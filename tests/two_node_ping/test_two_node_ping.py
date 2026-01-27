"""
Two-node ping connectivity tests.

This test suite validates basic ICMP connectivity between two nodes.
Includes both IPv4 and IPv6 tests.
Inherits standard validation tests from BaseTopologyTests.
"""

import pytest
from tests.conftest import BaseTopologyTests


class TestTwoNodePing(BaseTopologyTests):
    """Test connectivity between two nodes.

    Inherits standard tests from BaseTopologyTests.
    Add topology-specific tests here.
    """

    def test_two_nodes_exist(self, topology):
        """Verify topology has exactly two nodes."""
        assert len(topology.nodes) == 2, "Two-node topology should have exactly 2 nodes"
        assert topology.nodes[0].name == "node1"
        assert topology.nodes[1].name == "node2"

    def test_single_shared_network(self, topology):
        """Verify both nodes share exactly one network."""
        assert len(topology.networks) == 1, "Should have exactly one network"

        net1 = topology.get_network("net1")
        assert net1 is not None, "Network 'net1' should exist"
        assert net1.subnet == "10.0.1.0/24"
        assert hasattr(net1, "ipv6_subnet") and net1.ipv6_subnet == "2001:db8:1::/64", (
            "Network 'net1' should have IPv6 subnet 2001:db8:1::/64"
        )

        # Both nodes should be on net1
        for node in topology.nodes:
            assert "net1" in node.networks, f"{node.name} should be on net1"

    def test_ipv4_ping_connectivity(
        self, configure_node_interfaces, node_interfaces, ssh_command
    ):
        """Test IPv4 ping connectivity between nodes."""
        node1_iface = node_interfaces["node1"]["net1"]
        node2_iface = node_interfaces["node2"]["net1"]

        node1_ipv4 = node1_iface.get_ip().split("/")[0]
        node2_ipv4 = node2_iface.get_ip().split("/")[0]
        node2_ssh_port = node2_iface.ssh_port

        # Test ping from node2 to node1
        result = ssh_command(node2_ssh_port, f"ping -c 3 {node1_ipv4}", timeout=10)
        assert "3 received" in result or "100% packet loss" not in result, (
            "IPv4 ping from node2 to node1 failed"
        )
        print(f"✓ IPv4 Ping: node2 ({node2_ipv4}) → node1 ({node1_ipv4})")

    def test_ipv6_ping_connectivity(
        self, configure_node_interfaces, node_interfaces, ssh_command
    ):
        """Test IPv6 ping connectivity between nodes."""
        node1_iface = node_interfaces["node1"]["net1"]
        node2_iface = node_interfaces["node2"]["net1"]

        node1_ipv6 = node1_iface.get_ipv6().split("/")[0]
        node2_ipv6 = node2_iface.get_ipv6().split("/")[0]
        node2_ssh_port = node2_iface.ssh_port

        if not node1_ipv6:
            pytest.skip("IPv6 not configured on node1")

        # Test ping6 from node2 to node1
        result = ssh_command(node2_ssh_port, f"ping6 -c 3 {node1_ipv6}", timeout=10)
        assert "3 received" in result or "100% packet loss" not in result, (
            "IPv6 ping from node2 to node1 failed"
        )
        print(f"✓ IPv6 Ping: node2 ({node2_ipv6}) → node1 ({node1_ipv6})")
