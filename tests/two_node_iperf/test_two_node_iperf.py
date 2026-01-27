"""
Two-node iperf3 performance tests.

This test suite validates network performance between two nodes using iperf3.
Tests both IPv4 and IPv6, with TCP and UDP throughput measurements.
"""

import subprocess
import json
import time
import pytest
from tests.conftest import BaseTopologyTests


class TestTwoNodeIperf(BaseTopologyTests):
    """Test network performance between two nodes using iperf3.

    Inherits standard validation tests from BaseTopologyTests.
    """

    @pytest.fixture(autouse=True, scope="class")
    def setup_iperf(self, install_packages, topology):
        """Install iperf3 on all nodes before running tests."""
        for node in topology.nodes:
            install_packages(node.name, ["iperf3"])

    @staticmethod
    def _kill_iperf(ssh_command, ssh_port, timeout=5):
        """Aggressively kill all iperf3 processes on a node."""
        try:
            # First try pkill with signal 15
            ssh_command(ssh_port, "pkill -15 iperf3 || true", timeout=timeout)
            time.sleep(0.5)
            # Then force kill any remaining
            ssh_command(ssh_port, "pkill -9 iperf3 || true", timeout=timeout)
            # Verify they're gone
            result = ssh_command(
                ssh_port, "pgrep iperf3 | wc -l", timeout=timeout
            ).strip()
            count = int(result) if result else 0
            if count > 0:
                ssh_command(ssh_port, f"killall -9 iperf3 || true", timeout=timeout)
        except Exception:
            pass  # Ignore errors in cleanup

    def test_two_nodes_exist(self, topology):
        """Verify topology has exactly two nodes."""
        assert len(topology.nodes) == 2, "Iperf topology should have exactly 2 nodes"
        assert topology.nodes[0].name == "server"
        assert topology.nodes[1].name == "client"

    def test_tcp_throughput(
        self, configure_node_interfaces, node_interfaces, ssh_command
    ):
        """Test IPv4 TCP throughput between client and server."""
        server_iface = node_interfaces["server"]["net1"]
        client_iface = node_interfaces["client"]["net1"]

        server_ip = server_iface.get_ip().split("/")[0]
        server_port = server_iface.ssh_port
        client_port = client_iface.ssh_port

        # Pre-cleanup: kill any lingering iperf processes
        self._kill_iperf(ssh_command, server_port)
        time.sleep(1)

        # Start iperf3 server in background
        try:
            ssh_command(server_port, "iperf3 -s -D", timeout=5)
            time.sleep(1)  # Give server time to start

            # Run iperf3 client (10 second test)
            result = ssh_command(
                client_port, f"iperf3 -c {server_ip} -t 10 -J", timeout=20
            )

            # Parse JSON output to get throughput
            data = json.loads(result)

            # Get average throughput in bits/sec
            throughput_bps = data["end"]["sum_received"]["bits_per_second"]
            throughput_mbps = throughput_bps / 1_000_000

            # Log results
            print(f"\n✓ IPv4 TCP Throughput: {throughput_mbps:.2f} Mbps")

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
            self._kill_iperf(ssh_command, server_port)
            time.sleep(0.5)

    def test_udp_throughput(
        self, configure_node_interfaces, node_interfaces, ssh_command
    ):
        """Test IPv4 UDP throughput and packet loss between client and server."""
        server_iface = node_interfaces["server"]["net1"]
        client_iface = node_interfaces["client"]["net1"]

        server_ip = server_iface.get_ip().split("/")[0]
        server_port = server_iface.ssh_port
        client_port = client_iface.ssh_port

        # Pre-cleanup: kill any lingering iperf processes
        self._kill_iperf(ssh_command, server_port)
        time.sleep(1)

        # Start iperf3 server in background
        try:
            ssh_command(server_port, "iperf3 -s -D", timeout=5)
            time.sleep(1)  # Give server time to start

            # Run iperf3 client with UDP at 100 Mbps (10 second test)
            result = ssh_command(
                client_port, f"iperf3 -c {server_ip} -u -b 100M -t 10 -J", timeout=20
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
            print(f"\n✓ IPv4 UDP Throughput: {throughput_mbps:.2f} Mbps")
            print(
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
            self._kill_iperf(ssh_command, server_port)
            time.sleep(0.5)

    def test_bidirectional_throughput(
        self, configure_node_interfaces, node_interfaces, ssh_command
    ):
        """Test IPv4 bidirectional (simultaneous send/receive) TCP throughput."""
        server_iface = node_interfaces["server"]["net1"]
        client_iface = node_interfaces["client"]["net1"]

        server_ip = server_iface.get_ip().split("/")[0]
        server_port = server_iface.ssh_port
        client_port = client_iface.ssh_port

        # Pre-cleanup: kill any lingering iperf processes
        self._kill_iperf(ssh_command, server_port)
        time.sleep(1)

        # Start iperf3 server in background
        try:
            ssh_command(server_port, "iperf3 -s -D", timeout=5)
            time.sleep(1)  # Give server time to start

            # Run bidirectional test
            result = ssh_command(
                client_port, f"iperf3 -c {server_ip} -t 10 --bidir -J", timeout=25
            )

            # Parse JSON output
            data = json.loads(result)

            # Get send and receive throughput
            send_bps = data["end"]["sum_sent"]["bits_per_second"]
            recv_bps = data["end"]["sum_received"]["bits_per_second"]

            send_mbps = send_bps / 1_000_000
            recv_mbps = recv_bps / 1_000_000

            # Log results
            print("\n✓ IPv4 Bidirectional Throughput:")
            print(f"  Send: {send_mbps:.2f} Mbps")
            print(f"  Recv: {recv_mbps:.2f} Mbps")

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
            self._kill_iperf(ssh_command, server_port)
            time.sleep(0.5)

    def test_ipv6_tcp_throughput(
        self, configure_node_interfaces, node_interfaces, ssh_command
    ):
        """Test IPv6 TCP throughput between client and server."""
        server_iface = node_interfaces["server"]["net1"]
        client_iface = node_interfaces["client"]["net1"]

        server_ipv6 = server_iface.get_ipv6().split("/")[0]
        server_port = server_iface.ssh_port
        client_port = client_iface.ssh_port

        if not server_ipv6:
            pytest.skip("IPv6 not configured on server")

        # Pre-cleanup: kill any lingering iperf processes
        self._kill_iperf(ssh_command, server_port)
        time.sleep(1)

        # Start iperf3 server in background
        try:
            ssh_command(server_port, "iperf3 -s -D", timeout=5)
            time.sleep(1)  # Give server time to start

            # Run iperf3 client (10 second test) with IPv6
            result = ssh_command(
                client_port, f"iperf3 -c {server_ipv6} -t 10 -J", timeout=20
            )

            # Parse JSON output to get throughput
            data = json.loads(result)

            # Get average throughput in bits/sec
            throughput_bps = data["end"]["sum_received"]["bits_per_second"]
            throughput_mbps = throughput_bps / 1_000_000

            # Log results
            print(f"\n✓ IPv6 TCP Throughput: {throughput_mbps:.2f} Mbps")

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
            self._kill_iperf(ssh_command, server_port)
            time.sleep(0.5)

    def test_ipv6_udp_throughput(
        self, configure_node_interfaces, node_interfaces, ssh_command
    ):
        """Test IPv6 UDP throughput and packet loss between client and server."""
        server_iface = node_interfaces["server"]["net1"]
        client_iface = node_interfaces["client"]["net1"]

        server_ipv6 = server_iface.get_ipv6().split("/")[0]
        server_port = server_iface.ssh_port
        client_port = client_iface.ssh_port

        if not server_ipv6:
            pytest.skip("IPv6 not configured on server")

        # Pre-cleanup: kill any lingering iperf processes
        self._kill_iperf(ssh_command, server_port)
        time.sleep(1)

        # Start iperf3 server in background
        try:
            ssh_command(server_port, "iperf3 -s -D", timeout=5)
            time.sleep(1)  # Give server time to start

            # Run iperf3 client with UDP at 100 Mbps (10 second test)
            result = ssh_command(
                client_port, f"iperf3 -c {server_ipv6} -u -b 100M -t 10 -J", timeout=20
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
            print(f"\n✓ IPv6 UDP Throughput: {throughput_mbps:.2f} Mbps")
            print(
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
            self._kill_iperf(ssh_command, server_port)
            time.sleep(0.5)

    def test_ipv6_bidirectional_throughput(
        self, configure_node_interfaces, node_interfaces, ssh_command
    ):
        """Test IPv6 bidirectional (simultaneous send/receive) TCP throughput."""
        server_iface = node_interfaces["server"]["net1"]
        client_iface = node_interfaces["client"]["net1"]

        server_ipv6 = server_iface.get_ipv6().split("/")[0]
        server_port = server_iface.ssh_port
        client_port = client_iface.ssh_port

        if not server_ipv6:
            pytest.skip("IPv6 not configured on server")

        # Pre-cleanup: kill any lingering iperf processes
        self._kill_iperf(ssh_command, server_port)
        time.sleep(1)

        # Start iperf3 server in background
        try:
            ssh_command(server_port, "iperf3 -s -D", timeout=5)
            time.sleep(1)  # Give server time to start

            # Run bidirectional test
            result = ssh_command(
                client_port, f"iperf3 -c {server_ipv6} -t 10 --bidir -J", timeout=25
            )

            # Parse JSON output
            data = json.loads(result)

            # Get send and receive throughput
            send_bps = data["end"]["sum_sent"]["bits_per_second"]
            recv_bps = data["end"]["sum_received"]["bits_per_second"]

            send_mbps = send_bps / 1_000_000
            recv_mbps = recv_bps / 1_000_000

            # Log results
            print("\n✓ IPv6 Bidirectional Throughput:")
            print(f"  Send: {send_mbps:.2f} Mbps")
            print(f"  Recv: {recv_mbps:.2f} Mbps")

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
            self._kill_iperf(ssh_command, server_port)
            time.sleep(0.5)
