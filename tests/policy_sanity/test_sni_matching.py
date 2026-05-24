# Copyright (c) Dufferin Software

"""
SNI matching tests for policy-engine.

Tests:
- SNI rule creation succeeds with TCP protocol (TLS handshake, parsed in-kernel)
- SNI rule creation succeeds with UDP protocol (QUIC Initial, parsed in userspace)
- SNI rule creation is rejected with ICMP / 'any' protocols
- TCP traffic matching with an SNI rule (verifies the rule matches TCP traffic)
"""

import logging
import time

import netaddr

from tests.nping_utils import send_tcp_packets, send_tcp_syn
from lib.policy_engine.engine.cli.client import AddRuleOptions

logger = logging.getLogger(__name__)


class TestSniRuleValidation:
    """Tests that SNI rules are accepted on TCP and UDP, rejected elsewhere."""

    def test_add_rule_with_sni_tcp_succeeds(
        self,
        policy_client,
        attached_egress,
        clean_egress_rules,
    ):
        """Adding a rule with SNI and TCP protocol should succeed."""
        options = AddRuleOptions(
            interface=attached_egress,
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
            interface=attached_egress,
            protocol="tcp",
            dport=443,
            actions=[("drop", 0)],
            sni="*.example.com",
        )
        result = policy_client.add_rule(options, direction="egress")
        assert result.success, (
            f"TCP rule with wildcard SNI should succeed: {result.message}"
        )

    def test_add_rule_with_sni_udp_succeeds(
        self,
        policy_client,
        attached_egress,
        clean_egress_rules,
    ):
        """UDP + SNI is the QUIC Initial inspection path and must be accepted."""
        options = AddRuleOptions(
            interface=attached_egress,
            protocol="udp",
            dport=443,
            actions=[("drop", 0)],
            sni="example.com",
        )
        result = policy_client.add_rule(options, direction="egress")
        assert result.success, f"UDP rule with SNI should succeed: {result.message}"

    def test_add_rule_with_sni_wildcard_udp_succeeds(
        self,
        policy_client,
        attached_egress,
        clean_egress_rules,
    ):
        """Wildcard SNI on UDP (QUIC) is accepted, same as the TCP path."""
        options = AddRuleOptions(
            interface=attached_egress,
            protocol="udp",
            dport=443,
            actions=[("drop", 0)],
            sni="*.example.com",
        )
        result = policy_client.add_rule(options, direction="egress")
        assert result.success, (
            f"UDP rule with wildcard SNI should succeed: {result.message}"
        )

    def test_add_rule_with_sni_icmp_rejected(
        self,
        policy_client,
        attached_egress,
        clean_egress_rules,
    ):
        """Adding a rule with SNI and ICMP protocol should fail."""
        options = AddRuleOptions(
            interface=attached_egress,
            protocol="icmp",
            actions=[("drop", 0)],
            sni="example.com",
        )
        result = policy_client.add_rule(options, direction="egress")
        assert not result.success, "ICMP rule with SNI should be rejected"
        msg = result.message.lower()
        assert "tcp" in msg or "udp" in msg or "sni" in msg, (
            f"Error should mention TCP/UDP/SNI requirement: {result.message}"
        )

    def test_add_rule_with_sni_any_protocol_rejected(
        self,
        policy_client,
        attached_egress,
        clean_egress_rules,
    ):
        """Adding a rule with SNI and 'any' protocol should fail."""
        options = AddRuleOptions(
            interface=attached_egress,
            protocol="any",
            dport=443,
            actions=[("drop", 0)],
            sni="example.com",
        )
        result = policy_client.add_rule(options, direction="egress")
        assert not result.success, "Rule with 'any' protocol and SNI should be rejected"
        msg = result.message.lower()
        assert "tcp" in msg or "udp" in msg or "sni" in msg, (
            f"Error should mention TCP/UDP/SNI requirement: {result.message}"
        )

    def test_sni_rule_listed_after_creation(
        self,
        policy_client,
        attached_egress,
        clean_egress_rules,
    ):
        """SNI rule should appear in rule list with correct SNI pattern."""
        options = AddRuleOptions(
            interface=attached_egress,
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
            interface=attached_egress,
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


class TestMultiSniRuleMatching:
    """Tests that multiple SNI rules in the same L4 rule slot all fire correctly.

    Key scenario being exercised: when two or more rules share the same
    src/dst prefix and port but differ only in SNI pattern, the XDP/TC
    dispatcher uses a tail call for the first matching SNI rule.  The tail
    call must not prevent subsequent rules from being evaluated.
    """

    def test_two_sni_rules_same_port_both_count(
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
        """Two SNI LOG rules on the same port must each accumulate stats.

        Both rules have src=server_network, dst=any, TCP dport=443 but
        different SNI patterns.  Because nping sends plain TCP SYNs (not TLS),
        the BPF SNI parser cannot extract an SNI and fails closed — meaning
        both rules should still fire and log the packet.

        This exposes the tail-call bug: if the dispatcher tail-calls into the
        SNI program for rule 1 and never returns to the L4 loop, rule 2 will
        never be reached and its counter will stay at zero.
        """
        server = nodes["server"]

        rule_id_1 = 55551
        rule_id_2 = 55552

        result = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_egress,
                src=server_network_v4,
                protocol="tcp",
                dport=443,
                actions=[("log", 0)],
                rule_id=rule_id_1,
                sni="alpha.example.com",
            ),
            direction="egress",
        )
        assert result.success, f"Failed to add first SNI rule: {result.message}"

        result = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_egress,
                src=server_network_v4,
                protocol="tcp",
                dport=443,
                actions=[("log", 0)],
                rule_id=rule_id_2,
                sni="beta.example.com",
            ),
            direction="egress",
        )
        assert result.success, f"Failed to add second SNI rule: {result.message}"

        policy_client.clear_rule_stats(rule_id=rule_id_1, direction="egress")
        policy_client.clear_rule_stats(rule_id=rule_id_2, direction="egress")

        packets_to_send = 5
        send_tcp_syn(
            server,
            client_ip_v4,
            dest_port=443,
            count=packets_to_send,
            interface=server_interface.if_name,
        )

        time.sleep(0.5)

        stats_1 = policy_client.get_rule_stats(rule_id=rule_id_1, direction="egress")
        stats_2 = policy_client.get_rule_stats(rule_id=rule_id_2, direction="egress")

        count_1 = (
            stats_1.rules[0].stats.packets
            if stats_1.rules and stats_1.rules[0].stats
            else 0
        )
        count_2 = (
            stats_2.rules[0].stats.packets
            if stats_2.rules and stats_2.rules[0].stats
            else 0
        )

        logger.info(
            f"SNI multi-rule (same port): rule {rule_id_1}={count_1} packets, "
            f"rule {rule_id_2}={count_2} packets (expected {packets_to_send} each)"
        )

        assert count_1 == packets_to_send, (
            f"Rule {rule_id_1} (alpha.example.com) expected {packets_to_send} packets, "
            f"got {count_1}"
        )
        assert count_2 == packets_to_send, (
            f"Rule {rule_id_2} (beta.example.com) expected {packets_to_send} packets, "
            f"got {count_2} — likely the tail-call prevents rule 2 from being evaluated"
        )

    def test_sni_rule_and_plain_rule_same_port_both_count(
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
        """An SNI LOG rule and a plain (no-SNI) LOG rule on the same port must both count.

        Tests that the SNI tail-call path doesn't swallow control before the
        plain rule in the same L4 slot is evaluated.
        """
        server = nodes["server"]

        sni_rule_id = 55561
        plain_rule_id = 55562

        result = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_egress,
                src=server_network_v4,
                protocol="tcp",
                dport=443,
                actions=[("log", 0)],
                rule_id=sni_rule_id,
                sni="example.com",
            ),
            direction="egress",
        )
        assert result.success, f"Failed to add SNI rule: {result.message}"

        result = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_egress,
                src=server_network_v4,
                protocol="tcp",
                dport=443,
                actions=[("log", 0)],
                rule_id=plain_rule_id,
            ),
            direction="egress",
        )
        assert result.success, f"Failed to add plain rule: {result.message}"

        policy_client.clear_rule_stats(rule_id=sni_rule_id, direction="egress")
        policy_client.clear_rule_stats(rule_id=plain_rule_id, direction="egress")

        packets_to_send = 5
        send_tcp_syn(
            server,
            client_ip_v4,
            dest_port=443,
            count=packets_to_send,
            interface=server_interface.if_name,
        )

        time.sleep(0.5)

        stats_sni = policy_client.get_rule_stats(
            rule_id=sni_rule_id, direction="egress"
        )
        stats_plain = policy_client.get_rule_stats(
            rule_id=plain_rule_id, direction="egress"
        )

        count_sni = (
            stats_sni.rules[0].stats.packets
            if stats_sni.rules and stats_sni.rules[0].stats
            else 0
        )
        count_plain = (
            stats_plain.rules[0].stats.packets
            if stats_plain.rules and stats_plain.rules[0].stats
            else 0
        )

        logger.info(
            f"SNI+plain rules (same port): SNI rule={count_sni} packets, "
            f"plain rule={count_plain} packets (expected {packets_to_send} each)"
        )

        assert count_sni == packets_to_send, (
            f"SNI rule {sni_rule_id} expected {packets_to_send} packets, got {count_sni}"
        )
        assert count_plain == packets_to_send, (
            f"Plain rule {plain_rule_id} expected {packets_to_send} packets, got {count_plain}"
        )

    def test_two_sni_rules_different_ports_isolated(
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
        """Two SNI rules on different ports should only count their own traffic.

        Rule 1: dport=443, SNI=alpha.example.com, LOG
        Rule 2: dport=8443, SNI=beta.example.com, LOG

        Send 5 packets to 443 and 7 to 8443; verify each rule counts only
        what it owns.
        """
        server = nodes["server"]

        rule_id_443 = 55571
        rule_id_8443 = 55572

        result = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_egress,
                src=server_network_v4,
                protocol="tcp",
                dport=443,
                actions=[("log", 0)],
                rule_id=rule_id_443,
                sni="alpha.example.com",
            ),
            direction="egress",
        )
        assert result.success, f"Failed to add port-443 SNI rule: {result.message}"

        result = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_egress,
                src=server_network_v4,
                protocol="tcp",
                dport=8443,
                actions=[("log", 0)],
                rule_id=rule_id_8443,
                sni="beta.example.com",
            ),
            direction="egress",
        )
        assert result.success, f"Failed to add port-8443 SNI rule: {result.message}"

        policy_client.clear_rule_stats(rule_id=rule_id_443, direction="egress")
        policy_client.clear_rule_stats(rule_id=rule_id_8443, direction="egress")

        packets_to_443 = 5
        packets_to_8443 = 7

        send_tcp_syn(
            server,
            client_ip_v4,
            dest_port=443,
            count=packets_to_443,
            interface=server_interface.if_name,
        )
        send_tcp_syn(
            server,
            client_ip_v4,
            dest_port=8443,
            count=packets_to_8443,
            interface=server_interface.if_name,
        )

        time.sleep(0.5)

        stats_443 = policy_client.get_rule_stats(
            rule_id=rule_id_443, direction="egress"
        )
        stats_8443 = policy_client.get_rule_stats(
            rule_id=rule_id_8443, direction="egress"
        )

        count_443 = (
            stats_443.rules[0].stats.packets
            if stats_443.rules and stats_443.rules[0].stats
            else 0
        )
        count_8443 = (
            stats_8443.rules[0].stats.packets
            if stats_8443.rules and stats_8443.rules[0].stats
            else 0
        )

        logger.info(
            f"SNI port isolation: port-443 rule={count_443} (expected {packets_to_443}), "
            f"port-8443 rule={count_8443} (expected {packets_to_8443})"
        )

        assert count_443 == packets_to_443, (
            f"Rule {rule_id_443} (port 443) expected {packets_to_443} packets, got {count_443}"
        )
        assert count_8443 == packets_to_8443, (
            f"Rule {rule_id_8443} (port 8443) expected {packets_to_8443} packets, got {count_8443}"
        )


class TestMultipleSniRules:
    """Tests that multiple SNI rules all match and accumulate statistics.

    These tests help identify issues where only the first SNI rule matches and
    subsequent rules are not evaluated.
    """

    def test_multiple_sni_rules_both_match(
        self,
        nodes,
        policy_client,
        attached_egress,
        clean_egress_rules,
        server_interface,
        server_network_v4,
        client_ip_v4,
    ):
        """Verify that when multiple SNI rules are configured on the same interface,
        both rules accumulate match statistics when traffic matches their criteria.

        Scenario:
        - Add two LOG rules both matching any src/dst on TCP port 443
        - Rule 1: SNI pattern = "bing.com"
        - Rule 2: SNI pattern = "google.com"
        - Send TCP SYN packets to port 443
        - Verify both rules' packet counters increment

        This test helps identify issues where only one SNI rule matches.
        """
        server = nodes["server"]

        rule_id_1 = 77771
        rule_id_2 = 77772

        options_1 = AddRuleOptions(
            interface=attached_egress,
            src=server_network_v4,
            protocol="tcp",
            dport=443,
            actions=[("log", 0)],
            rule_id=rule_id_1,
            sni="bing.com",
        )
        result_1 = policy_client.add_rule(options_1, direction="egress")
        assert result_1.success, (
            f"Failed to add first SNI rule (bing.com): {result_1.message}"
        )
        logger.info(f"Added SNI rule {rule_id_1} for bing.com with LOG action")

        options_2 = AddRuleOptions(
            interface=attached_egress,
            src=server_network_v4,
            protocol="tcp",
            dport=443,
            actions=[("log", 0)],
            rule_id=rule_id_2,
            sni="google.com",
        )
        result_2 = policy_client.add_rule(options_2, direction="egress")
        assert result_2.success, (
            f"Failed to add second SNI rule (google.com): {result_2.message}"
        )
        logger.info(f"Added SNI rule {rule_id_2} for google.com with LOG action")

        rules = policy_client.list_rules(direction="egress")
        rule_ids = [r.rule_id for r in rules]
        assert rule_id_1 in rule_ids, f"Rule {rule_id_1} not found in rules list"
        assert rule_id_2 in rule_ids, f"Rule {rule_id_2} not found in rules list"
        logger.info(f"Both SNI rules found in rule list: {rule_id_1}, {rule_id_2}")

        policy_client.clear_rule_stats(rule_id=rule_id_1, direction="egress")
        policy_client.clear_rule_stats(rule_id=rule_id_2, direction="egress")
        logger.info("Cleared rule statistics for both rules")

        packets_to_send = 5
        logger.info(f"Sending {packets_to_send} TCP SYN packets to {client_ip_v4}:443")
        send_tcp_packets(
            server,
            netaddr.IPAddress(client_ip_v4),
            dest_port=443,
            count=packets_to_send,
            interface=server_interface.if_name,
            flags="SYN",
        )

        time.sleep(0.5)

        stats_1 = policy_client.get_rule_stats(rule_id=rule_id_1, direction="egress")
        assert stats_1.program_attached, "Egress program should be attached"
        assert len(stats_1.rules) > 0, f"No stats found for rule {rule_id_1}"
        packets_rule_1 = stats_1.rules[0].stats.packets if stats_1.rules[0].stats else 0

        stats_2 = policy_client.get_rule_stats(rule_id=rule_id_2, direction="egress")
        assert stats_2.program_attached, "Egress program should be attached"
        assert len(stats_2.rules) > 0, f"No stats found for rule {rule_id_2}"
        packets_rule_2 = stats_2.rules[0].stats.packets if stats_2.rules[0].stats else 0

        logger.info(
            f"Rule {rule_id_1} (bing.com): {packets_rule_1} packets matched\n"
            f"Rule {rule_id_2} (google.com): {packets_rule_2} packets matched"
        )

        assert packets_rule_1 > 0, (
            f"Rule {rule_id_1} (bing.com SNI) should have matched packets, "
            f"but got {packets_rule_1} packets"
        )
        assert packets_rule_2 > 0, (
            f"Rule {rule_id_2} (google.com SNI) should have matched packets, "
            f"but got {packets_rule_2} packets. This indicates a potential issue "
            f"where only the first SNI rule is evaluated."
        )

        logger.info(
            f"Both SNI rules matched traffic successfully: "
            f"rule 1 (bing.com)={packets_rule_1} packets, "
            f"rule 2 (google.com)={packets_rule_2} packets"
        )

    def test_multiple_sni_rules_different_ports(
        self,
        nodes,
        policy_client,
        attached_egress,
        clean_egress_rules,
        server_interface,
        server_network_v4,
        client_ip_v4,
    ):
        """Verify that SNI rules on different ports both match independently.

        Scenario:
        - Rule 1: SNI = "bing.com", port 443, LOG action
        - Rule 2: SNI = "google.com", port 8443, LOG action
        - Send traffic to both ports
        - Verify each rule matches only its respective traffic
        """
        server = nodes["server"]

        rule_id_1 = 77781
        rule_id_2 = 77782

        options_1 = AddRuleOptions(
            interface=attached_egress,
            src=server_network_v4,
            protocol="tcp",
            dport=443,
            actions=[("log", 0)],
            rule_id=rule_id_1,
            sni="bing.com",
        )
        result_1 = policy_client.add_rule(options_1, direction="egress")
        assert result_1.success, (
            f"Failed to add rule for bing.com on port 443: {result_1.message}"
        )

        options_2 = AddRuleOptions(
            interface=attached_egress,
            src=server_network_v4,
            protocol="tcp",
            dport=8443,
            actions=[("log", 0)],
            rule_id=rule_id_2,
            sni="google.com",
        )
        result_2 = policy_client.add_rule(options_2, direction="egress")
        assert result_2.success, (
            f"Failed to add rule for google.com on port 8443: {result_2.message}"
        )

        logger.info(f"Added SNI rules: {rule_id_1} (port 443), {rule_id_2} (port 8443)")

        policy_client.clear_rule_stats(rule_id=rule_id_1, direction="egress")
        policy_client.clear_rule_stats(rule_id=rule_id_2, direction="egress")

        packets_port_443 = 3
        logger.info(f"Sending {packets_port_443} packets to port 443")
        send_tcp_packets(
            server,
            netaddr.IPAddress(client_ip_v4),
            dest_port=443,
            count=packets_port_443,
            interface=server_interface.if_name,
            flags="SYN",
        )

        packets_port_8443 = 4
        logger.info(f"Sending {packets_port_8443} packets to port 8443")
        send_tcp_packets(
            server,
            netaddr.IPAddress(client_ip_v4),
            dest_port=8443,
            count=packets_port_8443,
            interface=server_interface.if_name,
            flags="SYN",
        )

        time.sleep(0.5)

        stats_1 = policy_client.get_rule_stats(rule_id=rule_id_1, direction="egress")
        packets_rule_1 = (
            stats_1.rules[0].stats.packets
            if stats_1.rules and stats_1.rules[0].stats
            else 0
        )

        stats_2 = policy_client.get_rule_stats(rule_id=rule_id_2, direction="egress")
        packets_rule_2 = (
            stats_2.rules[0].stats.packets
            if stats_2.rules and stats_2.rules[0].stats
            else 0
        )

        logger.info(
            f"Rule {rule_id_1} (port 443): {packets_rule_1} packets\n"
            f"Rule {rule_id_2} (port 8443): {packets_rule_2} packets"
        )

        assert packets_rule_1 == packets_port_443, (
            f"Rule {rule_id_1} (port 443) should match {packets_port_443} packets, "
            f"got {packets_rule_1}"
        )
        assert packets_rule_2 == packets_port_8443, (
            f"Rule {rule_id_2} (port 8443) should match {packets_port_8443} packets, "
            f"got {packets_rule_2}"
        )

        logger.info(
            f"Port-specific SNI rules matched correctly: "
            f"port 443={packets_rule_1} packets (expected {packets_port_443}), "
            f"port 8443={packets_rule_2} packets (expected {packets_port_8443})"
        )
