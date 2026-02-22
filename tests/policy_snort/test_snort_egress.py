# Copyright (c) Dufferin Software

"""
Snort rule egress tests for policy-engine content inspection.

Tests that imported Snort egress rules correctly match outbound traffic
payloads via the BPF content inspection tail-call program on egress.

Key difference from ingress tests:
- Egress rules match server→client traffic
- Traffic is sent FROM the server node TO the client node
- The TC egress program on the server's interface inspects outbound packets
"""

import logging
import time

import netaddr
import pytest

from tests.graphql_policy_client import GraphQLPolicyClient

logger = logging.getLogger(__name__)

# Port used for test traffic. Nothing should be listening on the client here,
# so the client kernel will respond with TCP RST (confirming delivery) unless
# the egress BPF drop rule fires first.
TEST_PORT = 9998


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
    graphql_client: GraphQLPolicyClient, direction: str = "egress"
) -> set:
    """Return the set of current rule IDs for the given direction."""
    rules = graphql_client.list_rules(direction=direction)
    return {r.rule_id for r in rules}


def _import_rules(
    graphql_client: GraphQLPolicyClient, rules_text: str, direction: str = "egress"
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
    graphql_client: GraphQLPolicyClient, rule_id: int, direction: str = "egress"
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


class TestSnortEgress:
    """Tests for Snort rule matching on egress traffic."""

    def test_snort_egress_content_match(
        self,
        nodes,
        graphql_client,
        snort_support,
        attached_egress,
        clean_egress_rules,
        client_ip_v4,
        nmap_installed_server,
    ):
        """
        Import a Snort egress alert rule and verify that outbound traffic from
        the server to the client with a matching payload increments the rule
        hit counter.
        """
        server = nodes["server"]

        rules_text = (
            'alert tcp any any -> any any '
            '(msg:"egress-test"; content:"EGRESS_TEST"; sid:2001;)'
        )
        import_result, new_rule_ids = _import_rules(
            graphql_client, rules_text, direction="egress"
        )

        assert import_result.get("success", False), (
            f"Snort egress rule import failed: {import_result.get('errors', [])}"
        )
        assert import_result.get("rulesImported", 0) >= 1, (
            "Expected at least one rule to be imported"
        )
        assert len(new_rule_ids) >= 1, "Expected at least one new rule to appear in rule list"

        rule_id = next(iter(new_rule_ids))
        initial_packets = _get_packet_count(graphql_client, rule_id, direction="egress")

        # Send from server to client with matching payload
        _nping_tcp_payload(server, client_ip_v4, TEST_PORT, "EGRESS_TEST", count=5)
        time.sleep(0.5)

        final_packets = _get_packet_count(graphql_client, rule_id, direction="egress")
        assert final_packets > initial_packets, (
            f"Egress rule {rule_id} should have matched some outbound packets "
            f"(initial={initial_packets}, final={final_packets})"
        )
        logger.info(
            f"Egress content rule matched {final_packets - initial_packets} packets"
        )

    def test_snort_egress_drop(
        self,
        nodes,
        graphql_client,
        snort_support,
        attached_egress,
        clean_egress_rules,
        client_ip_v4,
        nmap_installed_server,
    ):
        """
        Import a Snort egress drop rule and verify that outbound traffic with a
        matching payload is dropped by the TC egress program.

        Matching payload "EGRESS_DROP_ME" should increment policy_drops.
        Non-matching payload "SAFE_EGRESS" should not increment policy_drops.
        """
        server = nodes["server"]

        rules_text = (
            'drop tcp any any -> any any '
            '(msg:"egress-drop"; content:"EGRESS_DROP_ME"; sid:2002;)'
        )
        import_result, _ = _import_rules(
            graphql_client, rules_text, direction="egress"
        )
        assert import_result.get("success", False), (
            f"Snort egress drop rule import failed: {import_result.get('errors', [])}"
        )

        # Capture baseline drop counter
        initial_stats = graphql_client.get_stats(attached_egress, direction="egress")
        initial_drops = initial_stats.global_stats.policy_drops

        # Send from server to client with matching payload — expect BPF drop
        _nping_tcp_payload(server, client_ip_v4, TEST_PORT, "EGRESS_DROP_ME", count=5)
        time.sleep(0.3)

        after_drop_stats = graphql_client.get_stats(attached_egress, direction="egress")
        drops_after_match = after_drop_stats.global_stats.policy_drops
        assert drops_after_match > initial_drops, (
            "policy_drops should increase after sending matching egress payload "
            f"(before={initial_drops}, after={drops_after_match})"
        )

        # Send non-matching payload — drops counter should remain stable
        baseline_for_safe = drops_after_match
        _nping_tcp_payload(server, client_ip_v4, TEST_PORT, "SAFE_EGRESS", count=5)
        time.sleep(0.3)

        after_safe_stats = graphql_client.get_stats(attached_egress, direction="egress")
        drops_after_safe = after_safe_stats.global_stats.policy_drops
        assert drops_after_safe == baseline_for_safe, (
            "Non-matching egress payload should not increment policy_drops "
            f"(before={baseline_for_safe}, after={drops_after_safe})"
        )
        logger.info(
            f"Egress drop rule blocked {drops_after_match - initial_drops} packets; "
            f"'SAFE_EGRESS' traffic was not dropped"
        )
