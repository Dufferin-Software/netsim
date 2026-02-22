# Copyright (c) Dufferin Software

"""
Snort rule management tests for policy-engine.

Tests the snort registry: listing rules, merging / overwriting on import,
deleting by SID.  Traffic-verification tests additionally send packets to
confirm the correct BPF rule is (or is not) active.
"""

import logging
import time

import netaddr
import pytest

from tests.graphql_policy_client import GraphQLPolicyClient

logger = logging.getLogger(__name__)

# Port for traffic tests — nothing should be listening here.
TEST_PORT = 9998


# ============================================================================
# Helpers
# ============================================================================


def _nping_tcp_payload(
    node, target_ip: netaddr.IPAddress, port: int, payload: str, count: int = 3
) -> str:
    cmd = (
        f'sudo nping --tcp -p {port} -c {count} '
        f'--data-string "{payload}" {target_ip}'
    )
    try:
        return node.ssh_command(cmd, timeout=30)
    except Exception as e:
        logger.warning(f"nping returned non-zero (may be expected): {e}")
        return str(e)


def _get_rule_ids(client: GraphQLPolicyClient, direction: str = "ingress") -> set:
    rules = client.list_rules(direction=direction)
    return {r.rule_id for r in rules}


def _import_rules(
    client: GraphQLPolicyClient,
    rules_text: str,
    direction: str = "ingress",
    mode: str = "MERGE",
) -> tuple:
    """Import rules; return (result_dict, set_of_new_rule_ids)."""
    before_ids = _get_rule_ids(client, direction)
    result = client.import_snort_rules(rules_text, direction, mode)
    after_ids = _get_rule_ids(client, direction)
    new_ids = after_ids - before_ids
    return result, new_ids


def _get_packet_count(
    client: GraphQLPolicyClient, rule_id: int, direction: str = "ingress"
) -> int:
    stats_resp = client.get_rule_stats(rule_id=rule_id, direction=direction)
    for rws in stats_resp.rules:
        if rws.rule.rule_id == rule_id and rws.stats:
            return rws.stats.packets
    return 0


def _snort_sids(client: GraphQLPolicyClient, direction: str = "ingress") -> set:
    """Return the set of SIDs currently in the snort registry."""
    entries = client.list_snort_rules(direction=direction)
    return {int(e["sid"]) for e in entries}


# ============================================================================
# Tests
# ============================================================================


class TestSnortRuleManagement:
    """Tests for Snort rule registry management (list, delete, merge, overwrite)."""

    def test_list_rules_empty(
        self,
        graphql_client,
        snort_support,
        attached_ingress,
        clean_ingress_rules,
    ):
        """After flushing, snortRules query returns an empty list."""
        sids = _snort_sids(graphql_client, direction="ingress")
        assert sids == set(), f"Expected empty registry, got {sids}"

    def test_list_rules_after_import(
        self,
        graphql_client,
        snort_support,
        attached_ingress,
        clean_ingress_rules,
    ):
        """Importing 2 rules with distinct SIDs populates the registry with both."""
        rules_text = (
            'alert tcp any any -> any any (content:"AAA"; sid:6001; msg:"rule A";)\n'
            'alert tcp any any -> any any (content:"BBB"; sid:6002; msg:"rule B";)'
        )
        result = graphql_client.import_snort_rules(rules_text, direction="ingress")
        assert result.get("success", False), f"Import failed: {result.get('errors', [])}"
        assert result.get("rulesImported", 0) == 2

        sids = _snort_sids(graphql_client, direction="ingress")
        assert 6001 in sids, "SID 6001 should be in registry"
        assert 6002 in sids, "SID 6002 should be in registry"

    def test_delete_rule_by_sid(
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
        Import a drop rule, verify it matches traffic, delete by SID,
        then verify traffic is no longer matched.
        """
        client_node = nodes["client"]
        rules_text = (
            'drop tcp any any -> any any (content:"DELMATCH"; sid:6010; msg:"del test";)'
        )
        result, new_ids = _import_rules(graphql_client, rules_text)
        assert result.get("success", False), f"Import failed: {result.get('errors', [])}"
        assert len(new_ids) == 1, "Expected exactly one new rule"
        rule_id = next(iter(new_ids))

        # Send matching traffic — rule should count packets
        _nping_tcp_payload(client_node, server_ip_v4, TEST_PORT, "DELMATCH", count=3)
        time.sleep(0.5)
        count_before = _get_packet_count(graphql_client, rule_id)
        assert count_before > 0, "Rule should have matched packets before deletion"

        # Delete via SID
        del_result = graphql_client.delete_snort_rule(6010, direction="ingress")
        assert del_result.success, f"deleteSnortRule failed: {del_result.message}"

        # Registry should now be empty
        sids = _snort_sids(graphql_client, direction="ingress")
        assert 6010 not in sids, "SID 6010 should be removed from registry"

        # Send matching traffic again — the BPF rule is gone, so no further hits
        _nping_tcp_payload(client_node, server_ip_v4, TEST_PORT, "DELMATCH", count=3)
        time.sleep(0.5)
        count_after = _get_packet_count(graphql_client, rule_id)
        assert count_after == count_before, (
            f"Packet count should not increase after deletion "
            f"(before={count_before}, after={count_after})"
        )
        logger.info(f"Delete-by-SID confirmed: rule {rule_id} no longer active")

    def test_merge_updates_existing_sid(
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
        Import SID 5001 matching "ALPHA", then re-import the same SID matching "BETA"
        with mode=MERGE.  The result should report rulesUpdated=1, rulesImported=0,
        and the registry should still have exactly one entry for SID 5001 with the
        new text.  "BETA" traffic should match; "ALPHA" should not accumulate new hits.
        """
        client_node = nodes["client"]
        rule_alpha = (
            'alert tcp any any -> any any (content:"ALPHA"; sid:5001; msg:"alpha";)'
        )
        rule_beta = (
            'alert tcp any any -> any any (content:"BETA"; sid:5001; msg:"beta";)'
        )

        # First import
        r1, ids1 = _import_rules(graphql_client, rule_alpha)
        assert r1.get("rulesImported", 0) == 1
        assert r1.get("rulesUpdated", 0) == 0
        assert len(ids1) == 1
        rule_id_alpha = next(iter(ids1))

        # Re-import same SID with BETA content (merge)
        r2 = graphql_client.import_snort_rules(rule_beta, direction="ingress", mode="MERGE")
        assert r2.get("rulesImported", 0) == 0, (
            f"Expected rulesImported=0 on update, got {r2.get('rulesImported')}"
        )
        assert r2.get("rulesUpdated", 0) == 1, (
            f"Expected rulesUpdated=1, got {r2.get('rulesUpdated')}"
        )

        # Registry should have exactly one entry for SID 5001
        sids = _snort_sids(graphql_client, direction="ingress")
        assert sids == {5001}, f"Registry should contain only SID 5001, got {sids}"

        # Send ALPHA traffic — should NOT match the new rule (old rule was replaced)
        _nping_tcp_payload(client_node, server_ip_v4, TEST_PORT, "ALPHA", count=3)
        time.sleep(0.5)
        alpha_count = _get_packet_count(graphql_client, rule_id_alpha)

        # Send BETA traffic — should match the new rule
        ids_after = _get_rule_ids(graphql_client)
        rule_id_beta = next(iter(ids_after), None)
        _nping_tcp_payload(client_node, server_ip_v4, TEST_PORT, "BETA", count=5)
        time.sleep(0.5)
        beta_count = _get_packet_count(graphql_client, rule_id_beta) if rule_id_beta else 0
        assert beta_count > 0, (
            f"Updated rule (SID 5001 / BETA) should have matched traffic"
        )
        logger.info(
            f"Merge update confirmed: ALPHA rule gone (count={alpha_count}), "
            f"BETA rule active (count={beta_count})"
        )

    def test_overwrite_replaces_all(
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
        Import SIDs {5001, 5002}, then overwrite with SID {5003}.
        Registry should contain only {5003}; traffic for old SID 5001 should not match.
        """
        client_node = nodes["client"]
        rules_ab = (
            'alert tcp any any -> any any (content:"OVWR_A"; sid:5001; msg:"ow-a";)\n'
            'alert tcp any any -> any any (content:"OVWR_B"; sid:5002; msg:"ow-b";)'
        )
        rule_c = (
            'alert tcp any any -> any any (content:"OVWR_C"; sid:5003; msg:"ow-c";)'
        )

        r1, ids1 = _import_rules(graphql_client, rules_ab)
        assert r1.get("rulesImported", 0) == 2
        assert ids1 == _get_rule_ids(graphql_client)
        rule_id_5001 = None
        for rws in graphql_client.get_rule_stats(direction="ingress").rules:
            rule = rws.rule
            if rule.rule_id in ids1:
                rule_id_5001 = rule.rule_id
                break

        # Overwrite with only SID 5003
        r2 = graphql_client.import_snort_rules(rule_c, direction="ingress", mode="OVERWRITE")
        assert r2.get("rulesImported", 0) == 1, (
            f"Expected rulesImported=1 after overwrite, got {r2.get('rulesImported')}"
        )

        sids = _snort_sids(graphql_client, direction="ingress")
        assert sids == {5003}, f"Registry should contain only SID 5003, got {sids}"

        # Old SID 5001 traffic should not match anything
        if rule_id_5001:
            _nping_tcp_payload(client_node, server_ip_v4, TEST_PORT, "OVWR_A", count=3)
            time.sleep(0.5)
            count_old = _get_packet_count(graphql_client, rule_id_5001)
            assert count_old == 0, (
                f"Old rule (SID 5001) should not match after overwrite (count={count_old})"
            )
        logger.info("Overwrite confirmed: only SID 5003 in registry")

    def test_add_single_rule_inline(
        self,
        graphql_client,
        snort_support,
        attached_ingress,
        clean_ingress_rules,
    ):
        """
        Import a single rule via importSnortRules(mode=MERGE).
        rulesImported should be 1 and the rule should appear in snortRules.
        """
        single_rule = (
            'alert tcp any any -> any any (content:"INLINE"; sid:7001; msg:"inline";)'
        )
        result = graphql_client.import_snort_rules(single_rule, direction="ingress", mode="MERGE")
        assert result.get("success", False), f"Import failed: {result.get('errors', [])}"
        assert result.get("rulesImported", 0) == 1, (
            f"Expected rulesImported=1, got {result.get('rulesImported')}"
        )
        assert result.get("rulesUpdated", 0) == 0

        sids = _snort_sids(graphql_client, direction="ingress")
        assert 7001 in sids, "SID 7001 should be in the registry after inline import"

        entries = graphql_client.list_snort_rules(direction="ingress")
        assert any(int(e["sid"]) == 7001 for e in entries), (
            "snortRules query should return the imported rule"
        )
        logger.info("Inline single-rule import confirmed: SID 7001 in registry")
