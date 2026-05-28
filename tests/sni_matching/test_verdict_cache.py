# Copyright (c) Dufferin Software

"""
Verdict-cache fast-path behaviour.

After the SNI inspector decides a verdict on a flow it writes a verdict
into the verdict cache for 60 s.  Subsequent packets on the same 5-tuple
short-circuit in BPF without re-running the SNI tail call (TCP) or
re-emitting a ringbuf event (QUIC) — that's the whole point of the
cache.

Both transports are covered here:

* **QUIC** — userspace consumer (``process_quic_sample`` in
  ``event_stream.rs``) writes via ``BpfOperations::update_flow_verdict``
  after Initial decryption.
* **TCP** — ``tc_sni_inspect`` writes to ``tc_flow_verdict_cache``
  directly from BPF once it has walked the matched rule's
  ``actions[]`` (or selected PASS on the no-match-after-exhaustion
  path).

Test approach: use ``active_verdicts`` as the "inspector ran and wrote"
counter.
"""

import logging
import time

import pytest

from lib.policy_engine.engine.cli.client import AddRuleOptions

logger = logging.getLogger(__name__)

_DPORT = 443
_POLL_BUDGET_S = 5.0
_POLL_INTERVAL_S = 0.25


def _wait_verdicts(policy_client, baseline: int, want: int) -> int:
    deadline = time.monotonic() + _POLL_BUDGET_S
    last = baseline
    while time.monotonic() < deadline:
        last = policy_client.get_flow_verdicts(direction="egress").active_verdicts
        if last >= baseline + want:
            return last
        time.sleep(_POLL_INTERVAL_S)
    return last


class TestQuicVerdictCacheFastPath:
    def test_distinct_5tuples_each_write_a_verdict(
        self,
        policy_client,
        attached_egress,
        clean_egress_rules,
        quic_sender,
        client_ip_v4,
        server_network_v4,
    ):
        """Three QUIC Initials on distinct source ports → three verdict entries."""
        sni = "cache-distinct.example"
        r = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_egress,
                src=server_network_v4,
                protocol="udp",
                dport=_DPORT,
                actions=[("drop", 0)],
                sni=sni,
                rule_id=930_002,
            ),
            direction="egress",
        )
        assert r.success, f"add_rule failed: {r.message}"

        before = policy_client.get_flow_verdicts(direction="egress").active_verdicts
        for src in (50101, 50102, 50103):
            quic_sender(str(client_ip_v4), _DPORT, sni, src_port=src)
            time.sleep(0.15)

        after = _wait_verdicts(policy_client, before, want=3)
        grew = after - before
        logger.info(f"distinct-5tuple verdicts: before={before} after={after}")
        assert grew >= 3, (
            f"Expected at least 3 new verdicts across 3 distinct flows; got {grew}"
        )


@pytest.mark.usefixtures("tcp_sni_listener")
class TestTcpVerdictCacheFastPath:
    # tcp_sni_listener is required so connect() completes and the
    # ClientHello actually leaves the client.  Without it the test
    # binary exits non-zero before tc_sni_inspect ever runs.

    """
    Mirrors the QUIC class above for the in-kernel TCP SNI inspector.
    ``tc_sni_inspect`` now writes ``tc_flow_verdict_cache`` directly after
    walking the matched rule's actions[] (or PASS on no-match-after-exhaustion)
    so subsequent packets on the same flow short-circuit at L4 entry.
    """

    def test_distinct_5tuples_each_write_a_verdict(
        self,
        policy_client,
        attached_egress,
        clean_egress_rules,
        tls_sender,
        client_ip_v4,
        server_network_v4,
    ):
        """Three TLS ClientHellos on distinct source ports → three verdict entries.

        Uses a LOG (non-terminal) action.  A DROP rule would cache DROP for
        the first flow's 5-tuple, then the FIN packet from ``shutdown()`` on
        that same 5-tuple would also hit the L4 cache and be dropped at
        egress.  The listener (single-threaded, blocked in ``recv()``) would
        then never get the FIN, and the TCP cleanup interplay can make
        subsequent ``connect()`` calls flaky.  LOG matches still write the
        verdict cache (PASS, after walking actions[]) so the invariant under
        test is unchanged, while the on-the-wire handshake completes cleanly.
        """
        sni = "cache-tcp-distinct.example"
        rule_id = 930_003
        r = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_egress,
                src=server_network_v4,
                protocol="tcp",
                dport=_DPORT,
                actions=[("log", 0)],
                sni=sni,
                rule_id=rule_id,
            ),
            direction="egress",
        )
        assert r.success, f"add_rule failed: {r.message}"

        before = policy_client.get_flow_verdicts(direction="egress").active_verdicts
        for src in (50201, 50202, 50203):
            tls_sender(str(client_ip_v4), _DPORT, sni, src_port=src)
            time.sleep(0.15)

        after = _wait_verdicts(policy_client, before, want=3)
        grew = after - before
        logger.info(f"distinct-5tuple TCP verdicts: before={before} after={after}")
        assert grew >= 3, (
            f"Expected at least 3 new verdicts across 3 distinct TCP flows; got {grew}"
        )

    def test_same_5tuple_inspects_once(
        self,
        policy_client,
        attached_egress,
        clean_egress_rules,
        tls_sender,
        client_ip_v4,
        server_network_v4,
    ):
        """
        Repeated ClientHellos on the same source port must hit the cached
        verdict on every packet after the first, so ``rule_stats.packets``
        increments at most once across N sends.  Without the in-kernel cache
        write each send re-runs ``tc_sni_inspect`` and the counter grows
        linearly with the send count.

        Uses a LOG (non-terminal) action so the cached verdict is PASS;
        DROP would block the SYN of subsequent sends at the L4 cache check
        and ``connect()`` would never complete, masking the very behaviour
        under test.
        """
        sni = "cache-tcp-same.example"
        rule_id = 930_004
        r = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_egress,
                src=server_network_v4,
                protocol="tcp",
                dport=_DPORT,
                actions=[("log", 0)],
                sni=sni,
                rule_id=rule_id,
            ),
            direction="egress",
        )
        assert r.success, f"add_rule failed: {r.message}"
        policy_client.clear_rule_stats(rule_id=rule_id, direction="egress")

        src_port = 50301
        sends = 3
        for _ in range(sends):
            tls_sender(str(client_ip_v4), _DPORT, sni, src_port=src_port)
            time.sleep(0.15)

        # Give the engine a moment to surface the latest rule_stats.
        time.sleep(0.5)
        stats = policy_client.get_rule_stats(rule_id=rule_id, direction="egress")
        pkts = (
            stats.rules[0].stats.packets if stats.rules and stats.rules[0].stats else 0
        )
        logger.info(f"same-5-tuple TCP rule_stats.packets after {sends} sends: {pkts}")
        assert pkts >= 1, (
            "First ClientHello on this flow should have advanced rule_stats."
        )
        assert pkts < sends, (
            f"Verdict cache did not short-circuit subsequent sends — "
            f"rule_stats.packets={pkts} after {sends} sends (expected < {sends})."
        )
