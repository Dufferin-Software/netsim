# Copyright (c) Dufferin Software

"""
Two-node iperf3 performance tests.

This test suite validates network performance between two nodes using iperf3.
Tests both IPv4 and IPv6, with TCP and UDP throughput measurements.
"""

import subprocess
import json
import time
import logging
import pytest
from tests.conftest import BaseTopologyTests
from tests.process_helpers import kill_process

logger = logging.getLogger(__name__)


class TestTwoNodeIperf(BaseTopologyTests):
    """Test network performance between two nodes using iperf3.

    Inherits standard validation tests from BaseTopologyTests.
    """

    @pytest.fixture(scope="function")
    def install_iperf(self, install_packages, topology):
        """Install iperf3 on all nodes."""
        for node in topology.nodes:
            install_packages(node.name, ["iperf3"])

    def test_two_nodes_exist(self, topology):
        """Verify topology has exactly two nodes."""
        assert len(topology.nodes) == 2, "Iperf topology should have exactly 2 nodes"
        assert topology.nodes[0].name == "server"
        assert topology.nodes[1].name == "client"

    def test_tcp_throughput(
        self, install_iperf, configure_node_interfaces, node_interfaces, nodes
    ):
        """Test IPv4 TCP throughput between client and server."""
        server_iface = node_interfaces["server"]["net1"]
        client_iface = node_interfaces["client"]["net1"]

        server_ip = server_iface.get_ip_address()
        client_ip = client_iface.get_ip_address()
        server_node = nodes["server"]
        client_node = nodes["client"]

        # Pre-cleanup: kill any lingering iperf processes
        kill_process(server_node, "iperf3")
        time.sleep(1)

        # Start iperf3 server in background
        try:
            server_node.ssh_command("iperf3 -s -D", timeout=5)
            time.sleep(1)  # Give server time to start

            # Run iperf3 client (10 second test)
            result = client_node.ssh_command(
                f"iperf3 -c {str(server_ip)} -t 10 -J", timeout=20
            )

            # Parse JSON output to get throughput
            data = json.loads(result)

            # Get average throughput in bits/sec
            throughput_bps = data["end"]["sum_received"]["bits_per_second"]
            throughput_mbps = throughput_bps / 1_000_000

            # Log results
            logger.info(
                f"✓ IPv4 TCP: client ({client_ip}) → server ({server_ip}): {throughput_mbps:.2f} Mbps"
            )

            # Basic sanity check - should get at least 100 Mbps
            assert throughput_mbps > 100, (
                f"IPv4 TCP throughput too low: {throughput_mbps:.2f} Mbps (expected > 100 Mbps)"
            )

        except subprocess.CalledProcessError as e:
            pytest.fail(
                f"IPv4 TCP iperf test failed: {e.stderr if e.stderr else str(e)}"
            )
        finally:
            # Aggressive cleanup
            kill_process(server_node, "iperf3")
            time.sleep(0.5)

    def test_udp_throughput(
        self, install_iperf, configure_node_interfaces, node_interfaces, nodes
    ):
        """Test IPv4 UDP throughput and packet loss between client and server."""
        server_iface = node_interfaces["server"]["net1"]
        client_iface = node_interfaces["client"]["net1"]

        server_ip = server_iface.get_ip_address()
        client_ip = client_iface.get_ip_address()
        server_node = nodes["server"]
        client_node = nodes["client"]

        # Pre-cleanup: kill any lingering iperf processes
        kill_process(server_node, "iperf3")
        time.sleep(1)

        # Start iperf3 server in background
        try:
            server_node.ssh_command("iperf3 -s -D", timeout=5)
            time.sleep(1)  # Give server time to start

            # Run iperf3 client with UDP at 100 Mbps (10 second test)
            result = client_node.ssh_command(
                f"iperf3 -c {str(server_ip)} -u -b 100M -t 10 -J",
                timeout=20,
            )

            # Parse JSON output
            data = json.loads(result)

            # Get UDP stats
            throughput_bps = data["end"]["sum"]["bits_per_second"]
            throughput_mbps = throughput_bps / 1_000_000

            packets_sent = data["end"]["sum"]["packets"]
            packets_lost = data["end"]["sum"]["lost_packets"]
            loss_percent = data["end"]["sum"]["lost_percent"]

            # Log results
            logger.info(
                f"✓ IPv4 UDP: client ({client_ip}) → server ({server_ip}): {throughput_mbps:.2f} Mbps"
            )
            logger.info(
                f"  Packets: {packets_sent} sent, {packets_lost} lost ({loss_percent:.2f}%)"
            )

            # Validate - should have minimal packet loss for local VMs
            assert loss_percent < 5.0, (
                f"IPv4 UDP packet loss too high: {loss_percent:.2f}% (expected < 5%)"
            )

            # Should get reasonable throughput
            assert throughput_mbps > 50, (
                f"IPv4 UDP throughput too low: {throughput_mbps:.2f} Mbps (expected > 50 Mbps)"
            )

        except subprocess.CalledProcessError as e:
            pytest.fail(
                f"IPv4 UDP iperf test failed: {e.stderr if e.stderr else str(e)}"
            )
        finally:
            # Aggressive cleanup
            kill_process(server_node, "iperf3")
            time.sleep(0.5)

    def test_bidirectional_throughput(
        self, install_iperf, configure_node_interfaces, node_interfaces, nodes
    ):
        """Test IPv4 bidirectional (simultaneous send/receive) TCP throughput."""
        server_iface = node_interfaces["server"]["net1"]
        client_iface = node_interfaces["client"]["net1"]

        server_ip = server_iface.get_ip_address()
        client_ip = client_iface.get_ip_address()
        server_node = nodes["server"]
        client_node = nodes["client"]

        # Pre-cleanup: kill any lingering iperf processes
        kill_process(server_node, "iperf3")
        time.sleep(1)

        # Start iperf3 server in background
        try:
            server_node.ssh_command("iperf3 -s -D", timeout=5)
            time.sleep(1)  # Give server time to start

            # Run bidirectional test
            result = client_node.ssh_command(
                f"iperf3 -c {str(server_ip)} -t 10 --bidir -J", timeout=25
            )

            # Parse JSON output
            data = json.loads(result)

            # Get send and receive throughput
            send_bps = data["end"]["sum_sent"]["bits_per_second"]
            recv_bps = data["end"]["sum_received"]["bits_per_second"]

            send_mbps = send_bps / 1_000_000
            recv_mbps = recv_bps / 1_000_000

            # Log results
            logger.info(
                f"✓ IPv4 Bidirectional: client ({client_ip}) ↔ server ({server_ip}):"
            )
            logger.info(f"  Send: {send_mbps:.2f} Mbps")
            logger.info(f"  Recv: {recv_mbps:.2f} Mbps")

            # Both directions should have reasonable throughput
            assert send_mbps > 50, (
                f"IPv4 Send throughput too low: {send_mbps:.2f} Mbps (expected > 50 Mbps)"
            )
            assert recv_mbps > 50, (
                f"IPv4 Receive throughput too low: {recv_mbps:.2f} Mbps (expected > 50 Mbps)"
            )

        except subprocess.CalledProcessError as e:
            pytest.fail(
                f"IPv4 Bidirectional iperf test failed: {e.stderr if e.stderr else str(e)}"
            )
        finally:
            # Aggressive cleanup
            kill_process(server_node, "iperf3")
            time.sleep(0.5)

    def test_ipv6_tcp_throughput(
        self, install_iperf, configure_node_interfaces, node_interfaces, nodes
    ):
        """Test IPv6 TCP throughput between client and server."""
        server_iface = node_interfaces["server"]["net1"]
        client_iface = node_interfaces["client"]["net1"]

        server_ipv6 = server_iface.get_ipv6_address()
        client_ipv6 = client_iface.get_ipv6_address()
        server_node = nodes["server"]
        client_node = nodes["client"]

        if not server_ipv6:
            pytest.skip("IPv6 not configured on server")

        # Pre-cleanup: kill any lingering iperf processes
        kill_process(server_node, "iperf3")
        time.sleep(1)

        # Start iperf3 server in background
        try:
            server_node.ssh_command("iperf3 -s -D", timeout=5)
            time.sleep(1)  # Give server time to start

            # Run iperf3 client (10 second test) with IPv6
            result = client_node.ssh_command(
                f"iperf3 -c {str(server_ipv6)} -t 10 -J", timeout=20
            )

            # Parse JSON output to get throughput
            data = json.loads(result)

            # Get average throughput in bits/sec
            throughput_bps = data["end"]["sum_received"]["bits_per_second"]
            throughput_mbps = throughput_bps / 1_000_000

            # Log results
            logger.info(
                f"✓ IPv6 TCP: client ({client_ipv6}) → server ({server_ipv6}): {throughput_mbps:.2f} Mbps"
            )

            # Basic sanity check - should get at least 100 Mbps
            assert throughput_mbps > 100, (
                f"IPv6 TCP throughput too low: {throughput_mbps:.2f} Mbps (expected > 100 Mbps)"
            )

        except subprocess.CalledProcessError as e:
            pytest.fail(
                f"IPv6 TCP iperf test failed: {e.stderr if e.stderr else str(e)}"
            )
        finally:
            # Aggressive cleanup
            kill_process(server_node, "iperf3")
            time.sleep(0.5)

    def test_ipv6_udp_throughput(
        self, install_iperf, configure_node_interfaces, node_interfaces, nodes
    ):
        """Test IPv6 UDP throughput and packet loss between client and server."""
        server_iface = node_interfaces["server"]["net1"]
        client_iface = node_interfaces["client"]["net1"]

        server_ipv6 = server_iface.get_ipv6_address()
        client_ipv6 = client_iface.get_ipv6_address()
        server_node = nodes["server"]
        client_node = nodes["client"]

        if not server_ipv6:
            pytest.skip("IPv6 not configured on server")

        # Pre-cleanup: kill any lingering iperf processes
        kill_process(server_node, "iperf3")
        time.sleep(1)

        # Start iperf3 server in background
        try:
            server_node.ssh_command("iperf3 -s -D", timeout=5)
            time.sleep(1)  # Give server time to start

            # Run iperf3 client with UDP at 100 Mbps (10 second test)
            result = client_node.ssh_command(
                f"iperf3 -c {str(server_ipv6)} -u -b 100M -t 10 -J",
                timeout=20,
            )

            # Parse JSON output
            data = json.loads(result)

            # Get UDP stats
            throughput_bps = data["end"]["sum"]["bits_per_second"]
            throughput_mbps = throughput_bps / 1_000_000

            packets_sent = data["end"]["sum"]["packets"]
            packets_lost = data["end"]["sum"]["lost_packets"]
            loss_percent = data["end"]["sum"]["lost_percent"]

            # Log results
            logger.info(
                f"✓ IPv6 UDP: client ({client_ipv6}) → server ({server_ipv6}): {throughput_mbps:.2f} Mbps"
            )
            logger.info(
                f"  Packets: {packets_sent} sent, {packets_lost} lost ({loss_percent:.2f}%)"
            )

            # Validate - should have minimal packet loss for local VMs
            assert loss_percent < 5.0, (
                f"IPv6 UDP packet loss too high: {loss_percent:.2f}% (expected < 5%)"
            )

            # Should get reasonable throughput
            assert throughput_mbps > 50, (
                f"IPv6 UDP throughput too low: {throughput_mbps:.2f} Mbps (expected > 50 Mbps)"
            )

        except subprocess.CalledProcessError as e:
            pytest.fail(
                f"IPv6 UDP iperf test failed: {e.stderr if e.stderr else str(e)}"
            )
        finally:
            # Aggressive cleanup
            kill_process(server_node, "iperf3")
            time.sleep(0.5)

    def test_ipv6_bidirectional_throughput(
        self, install_iperf, configure_node_interfaces, node_interfaces, nodes
    ):
        """Test IPv6 bidirectional (simultaneous send/receive) TCP throughput."""
        server_iface = node_interfaces["server"]["net1"]
        client_iface = node_interfaces["client"]["net1"]

        server_ipv6 = server_iface.get_ipv6_address()
        client_ipv6 = client_iface.get_ipv6_address()
        server_node = nodes["server"]
        client_node = nodes["client"]

        if not server_ipv6:
            pytest.skip("IPv6 not configured on server")

        # Pre-cleanup: kill any lingering iperf processes
        kill_process(server_node, "iperf3")
        time.sleep(1)

        # Start iperf3 server in background
        try:
            server_node.ssh_command("iperf3 -s -D", timeout=5)
            time.sleep(1)  # Give server time to start

            # Run bidirectional test
            result = client_node.ssh_command(
                f"iperf3 -c {str(server_ipv6)} -t 10 --bidir -J",
                timeout=25,
            )

            # Parse JSON output
            data = json.loads(result)

            # Get send and receive throughput
            send_bps = data["end"]["sum_sent"]["bits_per_second"]
            recv_bps = data["end"]["sum_received"]["bits_per_second"]

            send_mbps = send_bps / 1_000_000
            recv_mbps = recv_bps / 1_000_000

            # Log results
            logger.info(
                f"✓ IPv6 Bidirectional: client ({client_ipv6}) ↔ server ({server_ipv6}):"
            )
            logger.info(f"  Send: {send_mbps:.2f} Mbps")
            logger.info(f"  Recv: {recv_mbps:.2f} Mbps")

            # Both directions should have reasonable throughput
            assert send_mbps > 50, (
                f"IPv6 Send throughput too low: {send_mbps:.2f} Mbps (expected > 50 Mbps)"
            )
            assert recv_mbps > 50, (
                f"IPv6 Receive throughput too low: {recv_mbps:.2f} Mbps (expected > 50 Mbps)"
            )

        except subprocess.CalledProcessError as e:
            pytest.fail(
                f"IPv6 Bidirectional iperf test failed: {e.stderr if e.stderr else str(e)}"
            )
        finally:
            # Aggressive cleanup
            kill_process(server_node, "iperf3")
            time.sleep(0.5)
