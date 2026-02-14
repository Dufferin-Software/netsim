# Copyright (c) Dufferin Software

"""
SNI matching tests for policy-engine.

Tests:
- SNI rule creation succeeds with TCP protocol
- SNI rule creation is rejected with non-TCP protocols (UDP, ICMP, any)
- TCP traffic matching with an SNI rule (verifies the rule matches TCP traffic)
"""

import logging

from tests.nping_utils import send_tcp_syn
from tests.policy_client import AddRuleOptions

logger = logging.getLogger(__name__)


class TestSniRuleValidation:
    """Tests that SNI rules are only accepted with TCP protocol."""

    def test_add_rule_with_sni_tcp_succeeds(
        self,
        policy_client,
        attached_egress,
        clean_egress_rules,
    ):
        """Adding a rule with SNI and TCP protocol should succeed."""
        options = AddRuleOptions(
            protocol="tcp",
            dport=443,
            actions=[("drop", 0)],
            sni="example.com",
        )
        result = policy_client.add_rule(options, direction="egress")
        assert result.success, f"TCP rule with SNI should succeed: {result.message}"

    def test_add_rule_with_sni_wildcard_tcp_succeeds(
        self,
        policy_client,
        attached_egress,
        clean_egress_rules,
    ):
        """Adding a rule with wildcard SNI and TCP protocol should succeed."""
        options = AddRuleOptions(
            protocol="tcp",
            dport=443,
            actions=[("drop", 0)],
            sni="*.example.com",
        )
        result = policy_client.add_rule(options, direction="egress")
        assert result.success, (
            f"TCP rule with wildcard SNI should succeed: {result.message}"
        )

    def test_add_rule_with_sni_udp_rejected(
        self,
        policy_client,
        attached_egress,
        clean_egress_rules,
    ):
        """Adding a rule with SNI and UDP protocol should fail."""
        options = AddRuleOptions(
            protocol="udp",
            dport=443,
            actions=[("drop", 0)],
            sni="example.com",
        )
        result = policy_client.add_rule(options, direction="egress")
        assert not result.success, "UDP rule with SNI should be rejected"
        assert "tcp" in result.message.lower() or "sni" in result.message.lower(), (
            f"Error should mention TCP/SNI requirement: {result.message}"
        )

    def test_add_rule_with_sni_icmp_rejected(
        self,
        policy_client,
        attached_egress,
        clean_egress_rules,
    ):
        """Adding a rule with SNI and ICMP protocol should fail."""
        options = AddRuleOptions(
            protocol="icmp",
            actions=[("drop", 0)],
            sni="example.com",
        )
        result = policy_client.add_rule(options, direction="egress")
        assert not result.success, "ICMP rule with SNI should be rejected"
        assert "tcp" in result.message.lower() or "sni" in result.message.lower(), (
            f"Error should mention TCP/SNI requirement: {result.message}"
        )

    def test_add_rule_with_sni_any_protocol_rejected(
        self,
        policy_client,
        attached_egress,
        clean_egress_rules,
    ):
        """Adding a rule with SNI and 'any' protocol should fail."""
        options = AddRuleOptions(
            protocol="any",
            dport=443,
            actions=[("drop", 0)],
            sni="example.com",
        )
        result = policy_client.add_rule(options, direction="egress")
        assert not result.success, "Rule with 'any' protocol and SNI should be rejected"
        assert "tcp" in result.message.lower() or "sni" in result.message.lower(), (
            f"Error should mention TCP/SNI requirement: {result.message}"
        )

    def test_sni_rule_listed_after_creation(
        self,
        policy_client,
        attached_egress,
        clean_egress_rules,
    ):
        """SNI rule should appear in rule list with correct SNI pattern."""
        options = AddRuleOptions(
            protocol="tcp",
            dport=443,
            actions=[("drop", 0)],
            sni="example.com",
        )
        result = policy_client.add_rule(options, direction="egress")
        assert result.success, f"Failed to add SNI rule: {result.message}"

        rules = policy_client.list_rules(direction="egress")
        assert len(rules) > 0, "Should have at least one rule"

        sni_rule = next((r for r in rules if r.sni == "example.com"), None)
        assert sni_rule is not None, (
            f"Should find rule with SNI 'example.com', got: {[r.sni for r in rules]}"
        )


class TestSniRuleTrafficMatching:
    """Tests that SNI rules match TCP traffic correctly."""

    def test_sni_rule_matches_tcp_traffic(
        self,
        nodes,
        policy_client,
        attached_egress,
        clean_egress_rules,
        server_interface,
        server_network_v4,
        client_ip_v4,
        nmap_installed_server,
    ):
        """TCP drop rule with SNI should still match TCP traffic by port/protocol.

        Note: BPF-level SNI extraction is a future feature. This test verifies
        that the TCP/port matching works correctly when a rule also has an SNI
        pattern configured.
        """
        server = nodes["server"]

        rule_id = 88888
        options = AddRuleOptions(
            src=server_network_v4,
            protocol="tcp",
            dport=443,
            actions=[("drop", 0)],
            rule_id=rule_id,
            sni="example.com",
        )
        result = policy_client.add_rule(options, direction="egress")
        assert result.success, f"Failed to add SNI TCP drop rule: {result.message}"

        # Clear rule stats
        policy_client.clear_rule_stats(rule_id=rule_id, direction="egress")

        # Get baseline stats
        initial_stats = policy_client.get_stats(
            server_interface.if_name, direction="egress"
        )
        initial_drops = initial_stats.global_stats.policy_drops

        # Send TCP SYN to port 443 from server to client
        packets_to_send = 5
        send_tcp_syn(
            server,
            client_ip_v4,
            dest_port=443,
            count=packets_to_send,
            interface=server_interface.if_name,
        )

        # Verify drops occurred
        final_stats = policy_client.get_stats(
            server_interface.if_name, direction="egress"
        )
        drops_delta = final_stats.global_stats.policy_drops - initial_drops

        logger.info(
            f"SNI rule TCP 443 drops: sent={packets_to_send}, "
            f"policy_drops={drops_delta}"
        )
        assert drops_delta == packets_to_send, (
            f"Expected {packets_to_send} drops for TCP 443 with SNI rule, "
            f"got {drops_delta}"
        )
