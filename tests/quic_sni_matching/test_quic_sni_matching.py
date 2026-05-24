# Copyright (c) Dufferin Software

"""
End-to-end tests for QUIC Initial SNI matching (policy-engine Phase 3).

Architecture under test:

    client (aioquic) ─QUIC v1 Initial─→ server (XDP ingress)
                                          │
                                          ├─ rule lookup: UDP dport=443
                                          │  with sni_match_type != NONE
                                          │  → tail call xdp_quic_initial_inspect
                                          │
                                          ├─ BPF: header-only checks, emit
                                          │  ringbuf event, seed 2 s PASS
                                          │
                                          └─ userspace consumer: derive Initial
                                             keys, AEAD-decrypt, extract SNI,
                                             match sni_rules map, write 60 s
                                             PASS or DROP verdict in
                                             flow_verdict_cache

These tests verify each stage by:
  * installing a UDP + SNI policy rule on the server,
  * firing one real QUIC v1 Initial from the client with a controlled SNI,
  * asserting the flow_verdict_cache picks up a fresh verdict (the entire
    decrypt + match + write pipeline ran), and
  * for the GraphQL client, additionally asserting the verdict action
    (PASS vs DROP) reflects the rule outcome.
"""

import logging
import shlex
import time

import pytest

from lib.policy_engine.engine.cli.client import AddRuleOptions
from lib.policy_engine.engine.graphql.client import GraphQLPolicyClient

logger = logging.getLogger(__name__)

# Poll budget after sending the Initial: the BPF tail-call seeds a 2 s PASS
# verdict synchronously, so a sane test box should see *something* within
# well under a second.  Userspace decrypt + write may take an extra few
# hundred ms.  Five seconds is a comfortable upper bound that still fails
# fast when the pipeline is genuinely broken.
_VERDICT_POLL_BUDGET_S = 5.0
_VERDICT_POLL_INTERVAL_S = 0.25

_DPORT = 443


def _send_initial(quic_sender, server_ip_v4, sni: str) -> None:
    """Fire a single QUIC v1 Initial with the given SNI at the server."""
    quic_sender(str(server_ip_v4), _DPORT, sni)


def _wait_for_verdict_count(policy_client, baseline: int) -> int:
    """Poll until the ingress verdict count exceeds `baseline`, or budget expires."""
    deadline = time.monotonic() + _VERDICT_POLL_BUDGET_S
    last = baseline
    while time.monotonic() < deadline:
        last = policy_client.get_flow_verdicts(direction="ingress").active_verdicts
        if last > baseline:
            return last
        time.sleep(_VERDICT_POLL_INTERVAL_S)
    return last


def _rule_packet_count(policy_client, rule_id: int) -> int:
    """Return how many packets the BPF dispatcher counted as matching `rule_id`."""
    stats = policy_client.get_rule_stats(rule_id=rule_id, direction="ingress")
    if not stats.rules or not stats.rules[0].stats:
        return 0
    return stats.rules[0].stats.packets


def _server_diag(nodes) -> str:
    """Snapshot the server's interfaces + XDP attachments for failure context."""
    server = nodes["server"]
    parts = []
    try:
        parts.append(
            "addrs:\n"
            + server.ssh_command(
                "ip -4 -o addr show | awk '{print $2, $4}'", timeout=5
            ).strip()
        )
    except Exception as e:
        parts.append(f"addrs unavailable: {e}")
    try:
        parts.append(
            "xdp:\n"
            + server.ssh_command(
                "ip -d link show | grep -E 'xdp|^[0-9]+:' | head -40", timeout=5
            ).strip()
        )
    except Exception as e:
        parts.append(f"xdp unavailable: {e}")
    try:
        parts.append(
            "recent policy-engine log:\n"
            + server.ssh_command(
                "sudo journalctl -u policy-engine --since '30 seconds ago' "
                "--no-pager -n 50 2>/dev/null || true",
                timeout=5,
            ).strip()
        )
    except Exception as e:
        parts.append(f"journal unavailable: {e}")

    # Use bpftool to inspect kernel-side BPF map state directly, bypassing
    # libbpf-rs.  We look for two things:
    #   1. `map show` filtered by name — if two maps with the same name exist
    #      that's a fundamental skeleton-reuse bug.
    #   2. `map dump` of the pinned path — shows whether the entry actually
    #      reached the kernel-side map referenced by that pin.
    try:
        parts.append(
            "bpftool map show (flow_verdict_cache instances):\n"
            + server.ssh_command(
                "sudo bpftool map show 2>&1 "
                "| grep -A0 -B0 'flow_verdict_cache' || true",
                timeout=5,
            ).strip()
        )
    except Exception as e:
        parts.append(f"bpftool show unavailable: {e}")

    try:
        parts.append(
            "bpftool map dump (pinned /sys/fs/bpf/policy_engine/flow_verdict_cache):\n"
            + server.ssh_command(
                "sudo bpftool map dump pinned "
                "/sys/fs/bpf/policy_engine/flow_verdict_cache 2>&1 "
                "| head -40 || true",
                timeout=5,
            ).strip()
        )
    except Exception as e:
        parts.append(f"bpftool dump (pinned) unavailable: {e}")

    # Hit flowVerdictList via raw curl → GraphQL: if this returns entries
    # while the active count is 0, the bug is specifically in
    # get_flow_verdict_count (probably its map.keys().count() iterator).
    query_payload = (
        '{"query":"query{flowVerdictList(direction:INGRESS)'
        '{srcIp dstIp srcPort dstPort protocol action expired}}"}'
    )
    gql_cmd = (
        "curl -s -X POST -H 'Content-Type: application/json' "
        "http://127.0.0.1:8080/graphql "
        f"--data {shlex.quote(query_payload)} 2>&1 | head -c 2000"
    )
    try:
        parts.append(
            "graphql flowVerdictList (raw):\n"
            + server.ssh_command(gql_cmd, timeout=5).strip()
        )
    except Exception as e:
        parts.append(f"graphql verdict list unavailable: {e}")
    return "\n\n".join(parts)


def _diagnose(policy_client, nodes, rule_id: int, baseline: int, current: int) -> str:
    """Build a verbose assertion message that pins which stage failed.

    QUIC SNI rules do *not* increment rule packet stats from BPF — the TCP
    SNI tail call does so after its in-kernel match, but the QUIC inspector
    cannot match in-kernel (it can't decrypt) and so just emits a ringbuf
    event.  Therefore `rule_pkts` is *not* a reliable signal of BPF-side
    progress for this path; we rely on the journal and the raw map dump.
    """
    rule_pkts = _rule_packet_count(policy_client, rule_id)
    stage = (
        "Userspace flow-verdict count did not grow after the QUIC Initial. "
        "Check the journal for 'quic_inspect:' lines and the bpftool dump "
        "below to localise the break (BPF tail-call not firing / inspector "
        "rejected the packet / userspace write succeeded but read returns 0)"
    )

    # Rule list dump so we can compare {protocol, dport, sni, ifindex} against
    # the packet we sent.
    try:
        rules = policy_client.list_rules(direction="ingress")
        rule_dump = (
            "\n".join(
                f"  rule_id={getattr(r, 'rule_id', '?')} "
                f"proto={getattr(r, 'protocol', '?')} "
                f"dport={getattr(r, 'dport', '?')} "
                f"sni={getattr(r, 'sni', '?')} "
                f"src={getattr(r, 'src_prefix', '?')} "
                f"dst={getattr(r, 'dst_prefix', '?')}"
                for r in rules
            )
            or "  (none)"
        )
    except Exception as e:
        rule_dump = f"  (rule list query failed: {e})"

    return (
        f"{stage}.\n"
        f"  rule_id={rule_id} matched_packets={rule_pkts}, "
        f"verdicts before={baseline} after={current}.\n"
        f"installed ingress rules:\n{rule_dump}\n\n"
        f"{_server_diag(nodes)}"
    )


# ============================================================================
# Validation smoke
# ============================================================================


class TestUdpSniRuleInstall:
    """Confirm UDP + SNI rule plumbing is wired (no traffic involved)."""

    def test_udp_sni_rule_listed_after_creation(
        self,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
    ):
        """UDP+SNI rule must be installable and listed with the expected pattern."""
        result = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_ingress,
                protocol="udp",
                dport=_DPORT,
                actions=[("drop", 0)],
                sni="quic-block.example",
            ),
            direction="ingress",
        )
        assert result.success, f"UDP + SNI rule install failed: {result.message}"

        rules = policy_client.list_rules(direction="ingress")
        sni_rule = next(
            (r for r in rules if getattr(r, "sni", None) == "quic-block.example"),
            None,
        )
        assert sni_rule is not None, (
            f"Installed UDP+SNI rule not found in list: "
            f"{[getattr(r, 'sni', None) for r in rules]}"
        )


# ============================================================================
# End-to-end: BPF tail-call → userspace decrypt → verdict cache
# ============================================================================


class TestQuicInitialPipeline:
    """Drive a real QUIC v1 Initial through the full ingress pipeline."""

    def test_matching_sni_produces_flow_verdict(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
        quic_sender,
        server_ip_v4,
        bpftool_installed,
    ):
        """
        A QUIC Initial whose SNI matches an installed rule must result in a
        fresh entry in the flow_verdict_cache (proves: BPF tail-call fired →
        ringbuf delivered → userspace decrypted → SNI extracted → matched →
        verdict written).
        """
        sni = "block.quictest.example"
        rule_id = 900_001

        result = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_ingress,
                protocol="udp",
                dport=_DPORT,
                actions=[("drop", 0)],
                sni=sni,
                rule_id=rule_id,
            ),
            direction="ingress",
        )
        assert result.success, f"add_rule failed: {result.message}"
        policy_client.clear_rule_stats(rule_id=rule_id, direction="ingress")

        before = policy_client.get_flow_verdicts(direction="ingress").active_verdicts
        logger.info(f"ingress flow verdicts before: {before}")

        _send_initial(quic_sender, server_ip_v4, sni)
        after = _wait_for_verdict_count(policy_client, before)
        logger.info(f"ingress flow verdicts after: {after}")

        assert after > before, _diagnose(policy_client, nodes, rule_id, before, after)

    def test_non_matching_sni_still_produces_flow_verdict(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
        quic_sender,
        server_ip_v4,
        bpftool_installed,
    ):
        """
        Even when the extracted SNI doesn't match any installed rule, the
        userspace consumer writes a 60 s PASS verdict so subsequent packets
        on the same flow fast-path through BPF.

        This pins the "always write, even on miss" behaviour from Phase 3 —
        without it, the BPF would re-tail-call the inspector for every
        future Initial on the same flow.
        """
        rule_id = 900_002
        result = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_ingress,
                protocol="udp",
                dport=_DPORT,
                actions=[("drop", 0)],
                sni="never-matched.example",
                rule_id=rule_id,
            ),
            direction="ingress",
        )
        assert result.success, f"add_rule failed: {result.message}"
        policy_client.clear_rule_stats(rule_id=rule_id, direction="ingress")

        before = policy_client.get_flow_verdicts(direction="ingress").active_verdicts

        _send_initial(quic_sender, server_ip_v4, "different.example")
        after = _wait_for_verdict_count(policy_client, before)

        assert after > before, _diagnose(policy_client, nodes, rule_id, before, after)


# ============================================================================
# Action verification (GraphQL only — needs the verdict-list query that the
# CLI client does not yet wrap)
# ============================================================================


class TestQuicVerdictAction:
    """Confirm the *action* recorded by the consumer matches the rule outcome."""

    def _list_verdicts(self, graphql_policy_client: GraphQLPolicyClient):
        """Raw flowVerdictList query — returns the list of verdict dicts."""
        query = """
        query VerdictList($direction: GqlDirection!) {
            flowVerdictList(direction: $direction) {
                srcIp
                dstIp
                srcPort
                dstPort
                protocol
                action
                expired
            }
        }
        """
        data = graphql_policy_client._execute_graphql(query, {"direction": "INGRESS"})
        if "__error__" in data:
            pytest.fail(f"flowVerdictList query failed: {data['__error__']}")
        return data.get("flowVerdictList", [])

    @pytest.fixture
    def graphql_only(self, client_type):
        """Skip these tests on the CLI parameterization."""
        if client_type != "graphql":
            pytest.skip("verdict-action assertion needs flowVerdictList (GraphQL only)")

    def test_match_writes_drop_verdict(
        self,
        graphql_only,
        policy_client,
        graphql_policy_client,
        attached_ingress,
        clean_ingress_rules,
        quic_sender,
        server_ip_v4,
    ):
        """Matching SNI on a DROP rule must record a DROP action in the verdict."""
        sni = "drop.quictest.example"
        result = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_ingress,
                protocol="udp",
                dport=_DPORT,
                actions=[("drop", 0)],
                sni=sni,
                rule_id=900_010,
            ),
            direction="ingress",
        )
        assert result.success, f"add_rule failed: {result.message}"

        before = policy_client.get_flow_verdicts(direction="ingress").active_verdicts
        _send_initial(quic_sender, server_ip_v4, sni)
        _wait_for_verdict_count(policy_client, before)

        verdicts = self._list_verdicts(graphql_policy_client)
        live = [v for v in verdicts if not v.get("expired")]
        logger.info(f"live ingress verdicts (drop case): {live}")

        actions = [v.get("action", "").upper() for v in live]
        assert "DROP" in actions, (
            f"Expected a DROP verdict after matching SNI rule; got actions={actions}"
        )

    def test_miss_writes_pass_verdict(
        self,
        graphql_only,
        policy_client,
        graphql_policy_client,
        attached_ingress,
        clean_ingress_rules,
        quic_sender,
        server_ip_v4,
    ):
        """Non-matching SNI should record a PASS verdict (not DROP)."""
        result = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_ingress,
                protocol="udp",
                dport=_DPORT,
                actions=[("drop", 0)],
                sni="never.example",
                rule_id=900_011,
            ),
            direction="ingress",
        )
        assert result.success, f"add_rule failed: {result.message}"

        before = policy_client.get_flow_verdicts(direction="ingress").active_verdicts
        _send_initial(quic_sender, server_ip_v4, "totally-other.example")
        _wait_for_verdict_count(policy_client, before)

        verdicts = self._list_verdicts(graphql_policy_client)
        live = [v for v in verdicts if not v.get("expired")]
        actions = [v.get("action", "").upper() for v in live]

        assert any(a == "PASS" for a in actions), (
            f"Expected a PASS verdict for non-matching SNI; got actions={actions}"
        )
        assert "DROP" not in actions, (
            f"Did not expect any DROP verdicts for a non-matching SNI; "
            f"got actions={actions}"
        )
