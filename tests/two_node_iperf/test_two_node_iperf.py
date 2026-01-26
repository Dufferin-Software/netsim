"""
Two-node iperf3 performance tests.

This test suite validates network performance between two nodes using iperf3.
Tests both TCP and UDP throughput.
"""

import subprocess
import re
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

    def test_two_nodes_exist(self, topology):
        """Verify topology has exactly two nodes."""
        assert len(topology.nodes) == 2, "Iperf topology should have exactly 2 nodes"
        assert topology.nodes[0].name == "server"
        assert topology.nodes[1].name == "client"

    def test_tcp_throughput(self, configure_node_interfaces, node_interfaces, ssh_command):
        """Test TCP throughput between client and server."""
        server_iface = node_interfaces["server"]["net1"]
        client_iface = node_interfaces["client"]["net1"]
        
        server_ip = server_iface.get_ip().split('/')[0]
        server_port = server_iface.ssh_port
        client_port = client_iface.ssh_port
        
        # Start iperf3 server in background
        try:
            ssh_command(server_port, "pkill -9 iperf3 || true", timeout=5)
            ssh_command(server_port, "iperf3 -s -D", timeout=5)
            
            # Run iperf3 client (10 second test)
            result = ssh_command(client_port, f"iperf3 -c {server_ip} -t 10 -J", timeout=20)
            
            # Parse JSON output to get throughput
            import json
            data = json.loads(result)
            
            # Get average throughput in bits/sec
            throughput_bps = data["end"]["sum_received"]["bits_per_second"]
            throughput_mbps = throughput_bps / 1_000_000
            
            # Stop server
            ssh_command(server_port, "pkill -9 iperf3 || true", timeout=5)
            
            # Log results
            print(f"\n✓ TCP Throughput: {throughput_mbps:.2f} Mbps")
            
            # Basic sanity check - should get at least 100 Mbps
            assert throughput_mbps > 100, \
                f"TCP throughput too low: {throughput_mbps:.2f} Mbps (expected > 100 Mbps)"
                
        except subprocess.CalledProcessError as e:
            ssh_command(server_port, "pkill -9 iperf3 || true", timeout=5)
            pytest.fail(f"TCP iperf test failed: {e.stderr if e.stderr else str(e)}")

    def test_udp_throughput(self, configure_node_interfaces, node_interfaces, ssh_command):
        """Test UDP throughput and packet loss between client and server."""
        server_iface = node_interfaces["server"]["net1"]
        client_iface = node_interfaces["client"]["net1"]
        
        server_ip = server_iface.get_ip().split('/')[0]
        server_port = server_iface.ssh_port
        client_port = client_iface.ssh_port
        
        # Start iperf3 server in background
        try:
            ssh_command(server_port, "pkill -9 iperf3 || true", timeout=5)
            ssh_command(server_port, "iperf3 -s -D", timeout=5)
            
            # Run iperf3 client with UDP at 100 Mbps (10 second test)
            result = ssh_command(
                client_port, 
                f"iperf3 -c {server_ip} -u -b 100M -t 10 -J",
                timeout=20
            )
            
            # Parse JSON output
            import json
            data = json.loads(result)
            
            # Get UDP stats
            throughput_bps = data["end"]["sum"]["bits_per_second"]
            throughput_mbps = throughput_bps / 1_000_000
            
            packets_sent = data["end"]["sum"]["packets"]
            packets_lost = data["end"]["sum"]["lost_packets"]
            loss_percent = data["end"]["sum"]["lost_percent"]
            
            # Stop server
            ssh_command(server_port, "pkill -9 iperf3 || true", timeout=5)
            
            # Log results
            print(f"\n✓ UDP Throughput: {throughput_mbps:.2f} Mbps")
            print(f"  Packets: {packets_sent} sent, {packets_lost} lost ({loss_percent:.2f}%)")
            
            # Validate - should have minimal packet loss for local VMs
            assert loss_percent < 5.0, \
                f"UDP packet loss too high: {loss_percent:.2f}% (expected < 5%)"
            
            # Should get reasonable throughput
            assert throughput_mbps > 50, \
                f"UDP throughput too low: {throughput_mbps:.2f} Mbps (expected > 50 Mbps)"
                
        except subprocess.CalledProcessError as e:
            ssh_command(server_port, "pkill -9 iperf3 || true", timeout=5)
            pytest.fail(f"UDP iperf test failed: {e.stderr if e.stderr else str(e)}")

    def test_bidirectional_throughput(self, configure_node_interfaces, node_interfaces, ssh_command):
        """Test bidirectional (simultaneous send/receive) TCP throughput."""
        server_iface = node_interfaces["server"]["net1"]
        client_iface = node_interfaces["client"]["net1"]
        
        server_ip = server_iface.get_ip().split('/')[0]
        server_port = server_iface.ssh_port
        client_port = client_iface.ssh_port
        
        # Start iperf3 server in background
        try:
            ssh_command(server_port, "pkill -9 iperf3 || true", timeout=5)
            ssh_command(server_port, "iperf3 -s -D", timeout=5)
            
            # Run bidirectional test
            result = ssh_command(
                client_port,
                f"iperf3 -c {server_ip} -t 10 --bidir -J",
                timeout=25
            )
            
            # Parse JSON output
            import json
            data = json.loads(result)
            
            # Get send and receive throughput
            send_bps = data["end"]["sum_sent"]["bits_per_second"]
            recv_bps = data["end"]["sum_received"]["bits_per_second"]
            
            send_mbps = send_bps / 1_000_000
            recv_mbps = recv_bps / 1_000_000
            
            # Stop server
            ssh_command(server_port, "pkill -9 iperf3 || true", timeout=5)
            
            # Log results
            print(f"\n✓ Bidirectional Throughput:")
            print(f"  Send: {send_mbps:.2f} Mbps")
            print(f"  Recv: {recv_mbps:.2f} Mbps")
            
            # Both directions should have reasonable throughput
            assert send_mbps > 50, \
                f"Send throughput too low: {send_mbps:.2f} Mbps (expected > 50 Mbps)"
            assert recv_mbps > 50, \
                f"Receive throughput too low: {recv_mbps:.2f} Mbps (expected > 50 Mbps)"
                
        except subprocess.CalledProcessError as e:
            ssh_command(server_port, "pkill -9 iperf3 || true", timeout=5)
            pytest.fail(f"Bidirectional iperf test failed: {e.stderr if e.stderr else str(e)}")
