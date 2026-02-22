# Copyright (c) Dufferin Software

"""
Snort rule ingress tests for policy-engine content inspection.

Tests that imported Snort rules correctly match traffic payloads
via the BPF content inspection tail-call program on ingress.

Traffic is sent FROM the client node TO the server node, where the
ingress XDP/TC program inspects incoming packet payloads against
the imported Snort content patterns.
"""

import logging
import time

import netaddr
import pytest

from tests.graphql_policy_client import GraphQLPolicyClient

logger = logging.getLogger(__name__)

# Port used for test traffic. Nothing should be listening here, so the server
# kernel will respond with TCP RST (allowing nping to confirm delivery) unless
# the BPF drop rule fires first.
TEST_PORT = 9999


# ============================================================================
# Helpers
# ============================================================================


def _nping_tcp_payload(
    node, target_ip: netaddr.IPAddress, port: int, payload: str, count: int = 3
) -> str:
    """Send TCP packets with a specific payload string using nping --data-string."""
    cmd = (
        f'sudo nping --tcp -p {port} -c {count} '
        f'--data-string "{payload}" {target_ip}'
    )
    try:
        return node.ssh_command(cmd, timeout=30)
    except Exception as e:
        logger.warning(f"nping returned non-zero (may be expected for drop tests): {e}")
        return str(e)


def _get_rule_ids(
    graphql_client: GraphQLPolicyClient, direction: str = "ingress"
) -> set:
    """Return the set of current rule IDs for the given direction."""
    rules = graphql_client.list_rules(direction=direction)
    return {r.rule_id for r in rules}


def _import_rules(
    graphql_client: GraphQLPolicyClient, rules_text: str, direction: str = "ingress"
) -> tuple:
    """
    Import Snort rules and return (import_result, set_of_new_rule_ids).

    Snapshots rule IDs before and after import so callers can identify
    which rules were created.
    """
    before_ids = _get_rule_ids(graphql_client, direction)
    result = graphql_client.import_snort_rules(rules_text, direction)
    after_ids = _get_rule_ids(graphql_client, direction)
    new_ids = after_ids - before_ids
    return result, new_ids


def _get_packet_count(
    graphql_client: GraphQLPolicyClient, rule_id: int, direction: str = "ingress"
) -> int:
    """Return the packet hit count for a specific rule, or 0 if not found."""
    stats_resp = graphql_client.get_rule_stats(rule_id=rule_id, direction=direction)
    for rws in stats_resp.rules:
        if rws.rule.rule_id == rule_id and rws.stats:
            return rws.stats.packets
    return 0


# ============================================================================
# Tests
# ============================================================================


class TestSnortIngress:
    """Tests for Snort rule matching on ingress traffic."""

    def test_snort_server_reports_support(self, graphql_client, snort_support):
        """Verify the server reports snortSupport=True via the GraphQL status query."""
        query = """
        query {
            status {
                snortSupport
            }
        }
        """
        data = graphql_client._execute_graphql(query)
        assert data.get("status", {}).get("snortSupport", False) is True, (
            "Server should report snortSupport=True when built with --features snort"
        )

    def test_snort_import_basic(
        self,
        nodes,
        graphql_client,
        snort_support,
        attached_ingress,
        clean_ingress_rules,
        server_ip_v4,
        nmap_installed,
    ):
        """
        Import a Snort alert rule with a content pattern and verify that ingress
        traffic containing the matching payload increments the rule hit counter.
        """
        client = nodes["client"]

        rules_text = (
            'alert tcp any any -> any any '
            '(msg:"test-basic"; content:"HELLO"; sid:1001;)'
        )
        import_result, new_rule_ids = _import_rules(
            graphql_client, rules_text, direction="ingress"
        )

        assert import_result.get("success", False), (
            f"Snort import failed: {import_result.get('errors', [])}"
        )
        assert import_result.get("rulesImported", 0) >= 1, (
            "Expected at least one rule to be imported"
        )
        assert len(new_rule_ids) >= 1, "Expected at least one new rule to appear in rule list"

        rule_id = next(iter(new_rule_ids))
        initial_packets = _get_packet_count(graphql_client, rule_id, direction="ingress")

        # Send TCP from client to server with matching payload
        _nping_tcp_payload(client, server_ip_v4, TEST_PORT, "HELLO", count=5)
        time.sleep(0.5)

        final_packets = _get_packet_count(graphql_client, rule_id, direction="ingress")
        assert final_packets > initial_packets, (
            f"Rule {rule_id} should have matched some packets "
            f"(initial={initial_packets}, final={final_packets})"
        )
        logger.info(f"Basic ingress rule matched {final_packets - initial_packets} packets")

    def test_snort_import_drop(
        self,
        nodes,
        graphql_client,
        snort_support,
        attached_ingress,
        clean_ingress_rules,
        server_ip_v4,
        nmap_installed,
    ):
        """
        Import a Snort drop rule and verify that packets with the matching
        payload are dropped, while packets with a non-matching payload pass.

        Matching is confirmed via the policy_drops global counter increasing
        for "BADPAYLOAD" traffic and remaining stable for "SAFE" traffic.
        """
        client = nodes["client"]

        rules_text = (
            'drop tcp any any -> any any '
            '(msg:"drop-bad"; content:"BADPAYLOAD"; sid:1002;)'
        )
        import_result, _ = _import_rules(
            graphql_client, rules_text, direction="ingress"
        )
        assert import_result.get("success", False), (
            f"Snort drop rule import failed: {import_result.get('errors', [])}"
        )

        # Capture baseline drop counter
        initial_stats = graphql_client.get_stats(attached_ingress, direction="ingress")
        initial_drops = initial_stats.global_stats.policy_drops

        # Send matching payload "BADPAYLOAD" — expect BPF drop
        _nping_tcp_payload(client, server_ip_v4, TEST_PORT, "BADPAYLOAD", count=5)
        time.sleep(0.3)

        after_bad_stats = graphql_client.get_stats(attached_ingress, direction="ingress")
        drops_after_bad = after_bad_stats.global_stats.policy_drops
        assert drops_after_bad > initial_drops, (
            "policy_drops should increase after sending matching payload "
            f"(before={initial_drops}, after={drops_after_bad})"
        )

        # Send non-matching payload "SAFE" — drops counter should stay the same
        baseline_for_safe = drops_after_bad
        _nping_tcp_payload(client, server_ip_v4, TEST_PORT, "SAFE", count=5)
        time.sleep(0.3)

        after_safe_stats = graphql_client.get_stats(attached_ingress, direction="ingress")
        drops_after_safe = after_safe_stats.global_stats.policy_drops
        assert drops_after_safe == baseline_for_safe, (
            "Non-matching payload should not increment policy_drops "
            f"(before={baseline_for_safe}, after={drops_after_safe})"
        )
        logger.info(
            f"Drop rule blocked {drops_after_bad - initial_drops} packets; "
            f"'SAFE' traffic was not dropped"
        )

    def test_snort_import_nocase(
        self,
        nodes,
        graphql_client,
        snort_support,
        attached_ingress,
        clean_ingress_rules,
        server_ip_v4,
        nmap_installed,
    ):
        """
        Import a Snort alert rule with the nocase modifier and verify it matches
        payload content regardless of case.

        The rule pattern is lowercase "hello" with nocase; traffic is sent with
        uppercase "HELLO" and should still be matched.
        """
        client = nodes["client"]

        rules_text = (
            'alert tcp any any -> any any '
            '(msg:"nocase-test"; content:"hello"; nocase; sid:1003;)'
        )
        import_result, new_rule_ids = _import_rules(
            graphql_client, rules_text, direction="ingress"
        )
        assert import_result.get("success", False), (
            f"Snort nocase rule import failed: {import_result.get('errors', [])}"
        )
        assert len(new_rule_ids) >= 1, "Expected at least one new rule to appear"

        rule_id = next(iter(new_rule_ids))
        initial_packets = _get_packet_count(graphql_client, rule_id, direction="ingress")

        # Send uppercase "HELLO" — should match case-insensitive pattern "hello"
        _nping_tcp_payload(client, server_ip_v4, TEST_PORT, "HELLO", count=5)
        time.sleep(0.5)

        final_packets = _get_packet_count(graphql_client, rule_id, direction="ingress")
        assert final_packets > initial_packets, (
            "Nocase rule should match uppercase 'HELLO' for pattern 'hello' "
            f"(initial={initial_packets}, final={final_packets})"
        )
        logger.info(f"Nocase rule matched {final_packets - initial_packets} packets")

    def test_snort_import_multiple_patterns(
        self,
        nodes,
        graphql_client,
        snort_support,
        attached_ingress,
        clean_ingress_rules,
        server_ip_v4,
        nmap_installed,
    ):
        """
        Import a Snort rule with two content patterns and verify AND semantics:
        - A packet containing only the first pattern should NOT match.
        - A packet containing both patterns should match.
        """
        client = nodes["client"]

        # Rule requires both "FOO" and "BAR" in the payload
        rules_text = (
            'alert tcp any any -> any any '
            '(msg:"multi-pattern"; content:"FOO"; content:"BAR"; sid:1004;)'
        )
        import_result, new_rule_ids = _import_rules(
            graphql_client, rules_text, direction="ingress"
        )
        assert import_result.get("success", False), (
            f"Snort multi-pattern import failed: {import_result.get('errors', [])}"
        )
        assert len(new_rule_ids) >= 1, "Expected at least one new rule to appear"

        rule_id = next(iter(new_rule_ids))

        # Send payload with only "FOO" — should NOT match (missing "BAR")
        before_partial = _get_packet_count(graphql_client, rule_id, direction="ingress")
        _nping_tcp_payload(client, server_ip_v4, TEST_PORT, "FOO only", count=5)
        time.sleep(0.5)
        after_partial = _get_packet_count(graphql_client, rule_id, direction="ingress")

        assert after_partial == before_partial, (
            "Rule should not match when only one content pattern is present "
            f"(before={before_partial}, after={after_partial})"
        )

        # Send payload with both "FOO" and "BAR" — should match
        before_full = _get_packet_count(graphql_client, rule_id, direction="ingress")
        _nping_tcp_payload(client, server_ip_v4, TEST_PORT, "FOO and BAR", count=5)
        time.sleep(0.5)
        after_full = _get_packet_count(graphql_client, rule_id, direction="ingress")

        assert after_full > before_full, (
            "Rule should match when both content patterns are present "
            f"(before={before_full}, after={after_full})"
        )
        logger.info(
            f"Multi-pattern: partial-only matched {after_partial - before_partial} packets, "
            f"full match={after_full - before_full} packets"
        )
