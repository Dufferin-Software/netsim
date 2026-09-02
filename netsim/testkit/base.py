# Copyright (c) Peter Morrow

"""
Topology validation tests shared by every suite.

``BaseTopologyTests`` is a mixin: a suite inherits from it to get the
standard node/interface/connectivity assertions for whatever topology it
declares. The assertions are product-agnostic — they exercise the fixtures
in :mod:`netsim.testkit.plugin` and nothing else.
"""

from re import Match
import logging
import subprocess

import pytest
from tenacity import (
    retry,
    stop_after_attempt,
    wait_fixed,
    retry_if_exception_type,
    before_sleep_log,
)

from netsim.testkit.node import Node

logger: logging.Logger = logging.getLogger(__name__)


class BaseTopologyTests:
    """
    Base test class with common topology validation tests.

    All topology-specific test suites should inherit from this class
    to get standard validation tests that work with any topology.
    """

    @pytest.fixture(autouse=True)
    def ensure_topology_running(self, running_topology) -> None:
        """Ensure topology is started before any test in this class runs."""
        pass

    def test_nodes_configured(self, topology, node_allocations) -> None:
        """Verify nodes and interfaces are properly allocated."""
        # Check all topology nodes are present
        assert len(topology.nodes) > 0, "Topology should have at least one node"

        # Verify each node has allocations for its networks
        for node in topology.nodes:
            assert node.name in node_allocations, (
                f"Node {node.name} missing from allocations"
            )

            node_ifaces = node_allocations[node.name]
            assert len(node_ifaces) == len(node.networks), (
                f"Node {node.name} should have {len(node.networks)} interfaces, got {len(node_ifaces)}"
            )

            # Check each network has an IP allocation
            for net_name in node.networks:
                assert net_name in node_ifaces, (
                    f"Network {net_name} not found in allocations for {node.name}"
                )

                addrs = node_ifaces[net_name]
                assert "ipv4" in addrs and addrs["ipv4"], (
                    f"No IPv4 allocation for {node.name}:{net_name}"
                )

                # Verify IP is in the correct subnet
                network = topology.get_network(net_name)
                assert network, f"Network {net_name} not found in topology"
                ip_cidr = addrs["ipv4"]
                assert ip_cidr.startswith(
                    network.subnet.split("/")[0].rsplit(".", 1)[0]
                ), f"IP {ip_cidr} not in subnet {network.subnet}"

    def test_interface_discovery(self, node_interfaces, topology) -> None:
        """Test that interfaces are discovered correctly on all nodes."""
        # Check all nodes have interface discovery
        for node in topology.nodes:
            assert node.name in node_interfaces, (
                f"Node {node.name} missing from interface discovery"
            )

            node_ifaces = node_interfaces[node.name]

            # Check all networks are discovered
            for net_name in node.networks:
                assert net_name in node_ifaces, (
                    f"Network {net_name} not discovered on {node.name}"
                )

                iface = node_ifaces[net_name]
                assert iface.if_name is not None, (
                    f"Interface name not set for {node.name}:{net_name}"
                )
                assert iface.ssh_port > 0, (
                    f"SSH port not set for {node.name}:{net_name}"
                )

    def test_interface_configuration(
        self, configure_node_interfaces, node_interfaces, node_allocations
    ) -> None:
        """Test that interfaces are configured with correct IPs on all nodes."""
        for node_name, ifaces in node_interfaces.items():
            allocations = node_allocations[node_name]

            for net_name, node_iface in ifaces.items():
                # Interface should be up
                assert node_iface.is_up(), (
                    f"{node_name}:{net_name} interface should be up"
                )

                # Get expected IP from allocations
                assert net_name in allocations, (
                    f"No allocation found for {node_name}:{net_name}"
                )
                expected_ip = allocations[net_name]["ipv4"]
                assert expected_ip, f"No IPv4 allocation for {node_name}:{net_name}"

                # Check actual IP matches
                actual_ip = node_iface.get_ip()
                assert actual_ip == expected_ip, (
                    f"{node_name}:{net_name} should have IP {expected_ip}, got {actual_ip}"
                )

    @staticmethod
    def _ping_and_extract_rtt(
        node: Node,
        target_ip: str,
        count: int = 3,
        ipv6: bool = False,
        timeout: int = 10,
    ) -> tuple[bool, float | None, str]:
        """Execute ping and extract average RTT.

        Args:
            node: Node object to ping from
            target_ip: Target IP address to ping
            count: Number of pings to send
            ipv6: Whether to use ping6 instead of ping
            timeout: Command timeout in seconds

        Returns:
            tuple: (success: bool, avg_rtt: float or None, output: str)
        """
        import re

        cmd: str = f"ping6 -c {count}" if ipv6 else f"ping -c {count}"
        cmd += f" {target_ip}"

        try:
            result = node.ssh_command(cmd, timeout=timeout)

            # Extract average RTT from output
            # Format: rtt min/avg/max/mdev = 0.123/0.456/0.789/0.012 ms
            rtt_match: Match[str] | None = re.search(
                r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/[\d.]+/[\d.]+ ms", result
            )
            avg_rtt: float | None = float(rtt_match.group(1)) if rtt_match else None

            # Check for packet loss
            success: bool = "100% packet loss" not in result

            return success, avg_rtt, result
        except subprocess.CalledProcessError as e:
            return False, None, e.stderr if e.stderr else str(e)

    def test_ping_between_nodes(
        self, configure_node_interfaces, node_interfaces, topology, nodes
    ) -> None:
        """Test ICMP connectivity between nodes that share networks (IPv4 and IPv6)."""
        # Build a map of network -> [nodes]
        network_nodes: dict[str, list[str]] = {}
        for topo_node in topology.nodes:
            for net_name in topo_node.networks:
                if net_name not in network_nodes:
                    network_nodes[net_name] = []
                network_nodes[net_name].append(topo_node.name)

        # Test ping between nodes on each shared network
        tested_pairs = set()
        for net_name, node_names in network_nodes.items():
            if len(node_names) < 2:
                logger.info(f"Network {net_name} has only one node, skipping ping test")
                continue

            # Test ping from first node to all others on this network
            source_node_name = node_names[0]
            source_node = nodes[source_node_name]
            source_iface = node_interfaces[source_node_name][net_name]

            for target_node_name in node_names[1:]:
                pair = (source_node_name, target_node_name)
                if pair in tested_pairs:
                    continue
                tested_pairs.add(pair)

                target_iface = node_interfaces[target_node_name][net_name]
                target_ip = target_iface.get_ip_address()
                source_ip = source_iface.get_ip_address()

                # IPv4 Ping from source to target
                success, avg_rtt, output = self._ping_and_extract_rtt(
                    source_node,
                    str(target_ip),
                    count=1,
                    ipv6=False,
                )
                rtt_str: str = ""
                if success:
                    rtt_str = f" ({avg_rtt:.2f}ms)" if avg_rtt else ""
                    logger.info(
                        f"✓ IPv4 Ping {source_node_name} ({source_ip}) -> {target_node_name} ({target_ip}) on {net_name}{rtt_str}"
                    )
                else:
                    pytest.fail(
                        f"IPv4 Ping failed: {source_node_name} ({source_ip}) -> {target_node_name} ({target_ip}) on {net_name}\n"
                        f"Error: {output}"
                    )

                # IPv6 Ping from source to target (if available)
                target_ipv6 = target_iface.get_ipv6_address()
                source_ipv6 = source_iface.get_ipv6_address()

                if target_ipv6 and source_ipv6:

                    class IPv6PingFailed(Exception):
                        """Raised when IPv6 ping fails."""

                        def __init__(self, output: str) -> None:
                            self.output: str = output
                            super().__init__(output)

                    @retry(
                        stop=stop_after_attempt(3),
                        wait=wait_fixed(1.0),
                        retry=retry_if_exception_type(IPv6PingFailed),
                        before_sleep=before_sleep_log(logger, logging.DEBUG),
                        reraise=True,
                    )
                    def ping_ipv6() -> float | None:
                        success, avg_rtt, output = self._ping_and_extract_rtt(
                            source_node,
                            str(target_ipv6),
                            count=1,
                            ipv6=True,
                            timeout=15,  # IPv6 may need more time on first call
                        )
                        if not success:
                            raise IPv6PingFailed(output)
                        return avg_rtt

                    try:
                        avg_rtt = ping_ipv6()
                        rtt_str = f" ({avg_rtt:.2f}ms)" if avg_rtt else ""
                        logger.info(
                            f"✓ IPv6 Ping {source_node_name} ({source_ipv6}) -> {target_node_name} ({target_ipv6}) on {net_name}{rtt_str}"
                        )
                    except IPv6PingFailed as e:
                        pytest.fail(
                            f"IPv6 Ping failed: {source_node_name} ({source_ipv6}) -> {target_node_name} ({target_ipv6}) on {net_name}\n"
                            f"Error: {e.output}"
                        )
