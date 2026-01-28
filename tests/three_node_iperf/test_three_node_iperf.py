"""
Three-node iperf3 performance tests with transit router.

This test suite validates network performance through a transit (router) node.
Tests both IPv4 and IPv6, with TCP and UDP throughput measurements.
Client and Server communicate through Transit node with static routing.
"""

import subprocess
import json
import time
import logging
import pytest
from tests.conftest import BaseTopologyTests
from tests.parallel_utils import run_parallel_simple

logger = logging.getLogger(__name__)


class TestThreeNodeIperf(BaseTopologyTests):
    """Test network performance with traffic routed through transit node.

    Inherits standard validation tests from BaseTopologyTests.
    """

    @pytest.fixture(autouse=True, scope="class")
    def setup_routing(
        self,
        configure_node_interfaces,
        node_interfaces,
        node_allocations,
        ssh_command,
        topology,
    ):
        """Configure static routing on all nodes via netplan (persistent across interface down/up)."""

        # Enable IP forwarding on transit node
        transit_iface = node_interfaces["transit"]["net1"]
        transit_port = transit_iface.ssh_port
        logger.info("Enabling IP forwarding on transit node...")
        ssh_command(transit_port, "sudo sysctl -w net.ipv4.ip_forward=1")
        ssh_command(transit_port, "sudo sysctl -w net.ipv6.conf.all.forwarding=1")

        # Get gateway addresses
        transit_net1_iface = node_interfaces["transit"]["net1"]
        transit_net1_ip = transit_net1_iface.get_ip().split("/")[0]
        transit_net1_ipv6 = transit_net1_iface.get_ipv6().split("/")[0]

        transit_net2_iface = node_interfaces["transit"]["net2"]
        transit_net2_ip = transit_net2_iface.get_ip().split("/")[0]
        transit_net2_ipv6 = transit_net2_iface.get_ipv6().split("/")[0]

        # Get networks
        server_net = topology.get_network("net2")
        client_net = topology.get_network("net1")

        # Configure client with routes via netplan
        client_iface = node_interfaces["client"]["net1"]
        client_port = client_iface.ssh_port
        client_routes = [{"to": server_net.subnet, "via": transit_net1_ip}]
        if (
            hasattr(server_net, "ipv6_subnet")
            and server_net.ipv6_subnet
            and transit_net1_ipv6
        ):
            client_routes.append(
                {"to": server_net.ipv6_subnet, "via": transit_net1_ipv6}
            )

        self._apply_routes_via_netplan(
            "client",
            client_iface.if_name,
            client_routes,
            node_allocations["client"]["net1"],
            client_port,
            ssh_command,
        )
        logger.info("  ✓ Client routes configured via netplan")

        # Configure server with routes via netplan
        server_iface = node_interfaces["server"]["net2"]
        server_port = server_iface.ssh_port
        server_routes = [{"to": client_net.subnet, "via": transit_net2_ip}]
        if (
            hasattr(client_net, "ipv6_subnet")
            and client_net.ipv6_subnet
            and transit_net2_ipv6
        ):
            server_routes.append(
                {"to": client_net.ipv6_subnet, "via": transit_net2_ipv6}
            )

        self._apply_routes_via_netplan(
            "server",
            server_iface.if_name,
            server_routes,
            node_allocations["server"]["net2"],
            server_port,
            ssh_command,
        )
        logger.info("  ✓ Server routes configured via netplan")

    @staticmethod
    def _apply_routes_via_netplan(
        node_name, if_name, routes, addresses, ssh_port, ssh_command
    ):
        """Apply routes to an interface via netplan."""
        import tempfile
        import subprocess
        import yaml
        from pathlib import Path

        # Build netplan config with routes
        ipv4_addr = addresses.get("ipv4")
        ipv6_addr = addresses.get("ipv6")
        addrs = [addr for addr in [ipv4_addr, ipv6_addr] if addr]

        netplan_config = {
            "network": {
                "version": 2,
                "ethernets": {
                    if_name: {
                        "dhcp4": False,
                        "dhcp6": False,
                        "addresses": addrs,
                        "routes": routes,
                    }
                },
            }
        }

        netplan_yaml = yaml.dump(netplan_config, default_flow_style=False)

        # Create temp file and copy to node
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(netplan_yaml)
            temp_path = f.name

        try:
            # Copy to node
            scp_cmd = [
                "scp",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-P",
                str(ssh_port),
                temp_path,
                "netsim@localhost:/tmp/netsim-routes.yaml",
            ]
            subprocess.run(scp_cmd, check=True, capture_output=True, timeout=10)

            # Apply via netplan
            ssh_command(
                ssh_port,
                f"sudo cp /tmp/netsim-routes.yaml /etc/netplan/50-{if_name}-routes.yaml",
            )
            ssh_command(
                ssh_port, f"sudo chmod 600 /etc/netplan/50-{if_name}-routes.yaml"
            )
            ssh_command(ssh_port, "sudo netplan apply 2>&1")

        finally:
            Path(temp_path).unlink()

    @pytest.fixture(scope="function")
    def install_iperf(self, install_packages, topology):
        """Install iperf3 on all nodes."""
        run_parallel_simple(
            install_packages, [(node.name, ["iperf3"]) for node in topology.nodes]
        )

    def test_three_nodes_exist(self, topology):
        """Verify topology has exactly three nodes."""
        assert len(topology.nodes) == 3, (
            "Three-node topology should have exactly 3 nodes"
        )
        assert topology.nodes[0].name == "client"
        assert topology.nodes[1].name == "transit"
        assert topology.nodes[2].name == "server"

    def test_networks_configured(self, topology):
        """Verify topology has two networks with correct nodes."""
        assert len(topology.networks) == 2, "Should have exactly two networks"

        net1 = topology.get_network("net1")
        net2 = topology.get_network("net2")
        assert net1 is not None and net2 is not None

        # Check net1 connectivity
        assert set(n.name for n in topology.nodes if "net1" in n.networks) == {
            "client",
            "transit",
        }
        # Check net2 connectivity
        assert set(n.name for n in topology.nodes if "net2" in n.networks) == {
            "transit",
            "server",
        }

    @staticmethod
    def _kill_iperf(ssh_command, ssh_port, timeout=5):
        """Aggressively kill all iperf3 processes on a node."""
        try:
            ssh_command(ssh_port, "pkill -15 iperf3 || true", timeout=timeout)
            time.sleep(0.5)
            ssh_command(ssh_port, "pkill -9 iperf3 || true", timeout=timeout)
            result = ssh_command(
                ssh_port, "pgrep iperf3 | wc -l", timeout=timeout
            ).strip()
            count = int(result) if result else 0
            if count > 0:
                ssh_command(ssh_port, "killall -9 iperf3 || true", timeout=timeout)
        except Exception:
            pass

    def test_ipv4_ping_client_to_server(
        self, configure_node_interfaces, node_interfaces, ssh_command
    ):
        """Test IPv4 ping from client to server via transit."""
        server_iface = node_interfaces["server"]["net2"]
        client_iface = node_interfaces["client"]["net1"]

        server_ip = server_iface.get_ip().split("/")[0]
        client_ip = client_iface.get_ip().split("/")[0]
        client_port = client_iface.ssh_port

        success, avg_rtt, output = self._ping_and_extract_rtt(
            ssh_command, client_port, server_ip, count=3, ipv6=False
        )
        if not success:
            pytest.fail(f"IPv4 ping from client to server failed: {output}")

        rtt_str = f" ({avg_rtt:.2f}ms)" if avg_rtt else ""
        logger.info(
            f"✓ IPv4 Ping: client ({client_ip}) → server ({server_ip}) via transit{rtt_str}"
        )

    def test_ipv6_ping_client_to_server(
        self, configure_node_interfaces, node_interfaces, ssh_command
    ):
        """Test IPv6 ping from client to server via transit."""
        server_iface = node_interfaces["server"]["net2"]
        client_iface = node_interfaces["client"]["net1"]

        server_ipv6 = server_iface.get_ipv6().split("/")[0]
        client_ipv6 = client_iface.get_ipv6().split("/")[0]
        client_port = client_iface.ssh_port

        if not server_ipv6:
            pytest.skip("IPv6 not configured on server")

        success, avg_rtt, output = self._ping_and_extract_rtt(
            ssh_command, client_port, server_ipv6, count=3, ipv6=True
        )
        if not success:
            pytest.fail(f"IPv6 ping from client to server failed: {output}")

        rtt_str = f" ({avg_rtt:.2f}ms)" if avg_rtt else ""
        logger.info(
            f"✓ IPv6 Ping: client ({client_ipv6}) → server ({server_ipv6}) via transit{rtt_str}"
        )

    def test_tcp_throughput(
        self, install_iperf, configure_node_interfaces, node_interfaces, ssh_command
    ):
        """Test IPv4 TCP throughput from client to server via transit."""
        server_iface = node_interfaces["server"]["net2"]
        client_iface = node_interfaces["client"]["net1"]

        server_ip = server_iface.get_ip().split("/")[0]
        client_ip = client_iface.get_ip().split("/")[0]
        server_port = server_iface.ssh_port
        client_port = client_iface.ssh_port

        # Pre-cleanup
        self._kill_iperf(ssh_command, server_port)
        time.sleep(1)

        try:
            ssh_command(server_port, "iperf3 -s -D", timeout=5)
            time.sleep(1)

            result = ssh_command(
                client_port, f"iperf3 -c {server_ip} -t 10 -J", timeout=20
            )

            data = json.loads(result)
            throughput_bps = data["end"]["sum_received"]["bits_per_second"]
            throughput_mbps = throughput_bps / 1_000_000

            logger.info(
                f"✓ IPv4 TCP: client ({client_ip}) → server ({server_ip}): {throughput_mbps:.2f} Mbps via transit"
            )

            assert throughput_mbps > 100, (
                f"IPv4 TCP throughput too low: {throughput_mbps:.2f} Mbps (expected > 100 Mbps)"
            )

        except subprocess.CalledProcessError as e:
            pytest.fail(
                f"IPv4 TCP iperf test failed: {e.stderr if e.stderr else str(e)}"
            )
        finally:
            self._kill_iperf(ssh_command, server_port)
            time.sleep(0.5)

    def test_udp_throughput(
        self, install_iperf, configure_node_interfaces, node_interfaces, ssh_command
    ):
        """Test IPv4 UDP throughput from client to server via transit."""
        server_iface = node_interfaces["server"]["net2"]
        client_iface = node_interfaces["client"]["net1"]

        server_ip = server_iface.get_ip().split("/")[0]
        client_ip = client_iface.get_ip().split("/")[0]
        server_port = server_iface.ssh_port
        client_port = client_iface.ssh_port

        # Pre-cleanup
        self._kill_iperf(ssh_command, server_port)
        time.sleep(1)

        try:
            ssh_command(server_port, "iperf3 -s -D", timeout=5)
            time.sleep(1)

            result = ssh_command(
                client_port, f"iperf3 -c {server_ip} -u -b 100M -t 10 -J", timeout=20
            )

            data = json.loads(result)
            throughput_bps = data["end"]["sum"]["bits_per_second"]
            throughput_mbps = throughput_bps / 1_000_000

            packets_sent = data["end"]["sum"]["packets"]
            packets_lost = data["end"]["sum"]["lost_packets"]
            loss_percent = data["end"]["sum"]["lost_percent"]

            logger.info(
                f"✓ IPv4 UDP: client ({client_ip}) → server ({server_ip}): {throughput_mbps:.2f} Mbps via transit"
            )
            logger.info(
                f"  Packets: {packets_sent} sent, {packets_lost} lost ({loss_percent:.2f}%)"
            )

            assert loss_percent < 5.0, (
                f"IPv4 UDP packet loss too high: {loss_percent:.2f}% (expected < 5%)"
            )

            assert throughput_mbps > 50, (
                f"IPv4 UDP throughput too low: {throughput_mbps:.2f} Mbps (expected > 50 Mbps)"
            )

        except subprocess.CalledProcessError as e:
            pytest.fail(
                f"IPv4 UDP iperf test failed: {e.stderr if e.stderr else str(e)}"
            )
        finally:
            self._kill_iperf(ssh_command, server_port)
            time.sleep(0.5)

    def test_bidirectional_throughput(
        self, install_iperf, configure_node_interfaces, node_interfaces, ssh_command
    ):
        """Test IPv4 bidirectional TCP throughput via transit."""
        server_iface = node_interfaces["server"]["net2"]
        client_iface = node_interfaces["client"]["net1"]

        server_ip = server_iface.get_ip().split("/")[0]
        client_ip = client_iface.get_ip().split("/")[0]
        server_port = server_iface.ssh_port
        client_port = client_iface.ssh_port

        # Pre-cleanup
        self._kill_iperf(ssh_command, server_port)
        time.sleep(1)

        try:
            ssh_command(server_port, "iperf3 -s -D", timeout=5)
            time.sleep(1)

            result = ssh_command(
                client_port, f"iperf3 -c {server_ip} -t 10 --bidir -J", timeout=25
            )

            data = json.loads(result)
            send_bps = data["end"]["sum_sent"]["bits_per_second"]
            recv_bps = data["end"]["sum_received"]["bits_per_second"]

            send_mbps = send_bps / 1_000_000
            recv_mbps = recv_bps / 1_000_000

            logger.info(
                f"✓ IPv4 Bidirectional: client ({client_ip}) ↔ server ({server_ip}): via transit"
            )
            logger.info(f"  Send: {send_mbps:.2f} Mbps")
            logger.info(f"  Recv: {recv_mbps:.2f} Mbps")

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
            self._kill_iperf(ssh_command, server_port)
            time.sleep(0.5)

    def test_ipv6_tcp_throughput(
        self, install_iperf, configure_node_interfaces, node_interfaces, ssh_command
    ):
        """Test IPv6 TCP throughput from client to server via transit."""
        server_iface = node_interfaces["server"]["net2"]
        client_iface = node_interfaces["client"]["net1"]

        server_ipv6 = server_iface.get_ipv6().split("/")[0]
        client_ipv6 = client_iface.get_ipv6().split("/")[0]
        server_port = server_iface.ssh_port
        client_port = client_iface.ssh_port

        if not server_ipv6:
            pytest.skip("IPv6 not configured on server")

        # Pre-cleanup
        self._kill_iperf(ssh_command, server_port)
        time.sleep(1)

        try:
            ssh_command(server_port, "iperf3 -s -D", timeout=5)
            time.sleep(1)

            result = ssh_command(
                client_port, f"iperf3 -c {server_ipv6} -t 10 -J", timeout=20
            )

            data = json.loads(result)
            throughput_bps = data["end"]["sum_received"]["bits_per_second"]
            throughput_mbps = throughput_bps / 1_000_000

            logger.info(
                f"✓ IPv6 TCP: client ({client_ipv6}) → server ({server_ipv6}): {throughput_mbps:.2f} Mbps via transit"
            )

            assert throughput_mbps > 100, (
                f"IPv6 TCP throughput too low: {throughput_mbps:.2f} Mbps (expected > 100 Mbps)"
            )

        except subprocess.CalledProcessError as e:
            pytest.fail(
                f"IPv6 TCP iperf test failed: {e.stderr if e.stderr else str(e)}"
            )
        finally:
            self._kill_iperf(ssh_command, server_port)
            time.sleep(0.5)

    def test_ipv6_udp_throughput(
        self, install_iperf, configure_node_interfaces, node_interfaces, ssh_command
    ):
        """Test IPv6 UDP throughput from client to server via transit."""
        server_iface = node_interfaces["server"]["net2"]
        client_iface = node_interfaces["client"]["net1"]

        server_ipv6 = server_iface.get_ipv6().split("/")[0]
        client_ipv6 = client_iface.get_ipv6().split("/")[0]
        server_port = server_iface.ssh_port
        client_port = client_iface.ssh_port

        if not server_ipv6:
            pytest.skip("IPv6 not configured on server")

        # Pre-cleanup
        self._kill_iperf(ssh_command, server_port)
        time.sleep(1)

        try:
            ssh_command(server_port, "iperf3 -s -D", timeout=5)
            time.sleep(1)

            result = ssh_command(
                client_port, f"iperf3 -c {server_ipv6} -u -b 100M -t 10 -J", timeout=20
            )

            data = json.loads(result)
            throughput_bps = data["end"]["sum"]["bits_per_second"]
            throughput_mbps = throughput_bps / 1_000_000

            packets_sent = data["end"]["sum"]["packets"]
            packets_lost = data["end"]["sum"]["lost_packets"]
            loss_percent = data["end"]["sum"]["lost_percent"]

            logger.info(
                f"✓ IPv6 UDP: client ({client_ipv6}) → server ({server_ipv6}): {throughput_mbps:.2f} Mbps via transit"
            )
            logger.info(
                f"  Packets: {packets_sent} sent, {packets_lost} lost ({loss_percent:.2f}%)"
            )

            assert loss_percent < 5.0, (
                f"IPv6 UDP packet loss too high: {loss_percent:.2f}% (expected < 5%)"
            )

            assert throughput_mbps > 50, (
                f"IPv6 UDP throughput too low: {throughput_mbps:.2f} Mbps (expected > 50 Mbps)"
            )

        except subprocess.CalledProcessError as e:
            pytest.fail(
                f"IPv6 UDP iperf test failed: {e.stderr if e.stderr else str(e)}"
            )
        finally:
            self._kill_iperf(ssh_command, server_port)
            time.sleep(0.5)

    def test_ipv6_bidirectional_throughput(
        self, install_iperf, configure_node_interfaces, node_interfaces, ssh_command
    ):
        """Test IPv6 bidirectional TCP throughput via transit."""
        server_iface = node_interfaces["server"]["net2"]
        client_iface = node_interfaces["client"]["net1"]

        server_ipv6 = server_iface.get_ipv6().split("/")[0]
        client_ipv6 = client_iface.get_ipv6().split("/")[0]
        server_port = server_iface.ssh_port
        client_port = client_iface.ssh_port

        if not server_ipv6:
            pytest.skip("IPv6 not configured on server")

        # Pre-cleanup
        self._kill_iperf(ssh_command, server_port)
        time.sleep(1)

        try:
            ssh_command(server_port, "iperf3 -s -D", timeout=5)
            time.sleep(1)

            result = ssh_command(
                client_port, f"iperf3 -c {server_ipv6} -t 10 --bidir -J", timeout=25
            )

            data = json.loads(result)
            send_bps = data["end"]["sum_sent"]["bits_per_second"]
            recv_bps = data["end"]["sum_received"]["bits_per_second"]

            send_mbps = send_bps / 1_000_000
            recv_mbps = recv_bps / 1_000_000

            logger.info(
                f"✓ IPv6 Bidirectional: client ({client_ipv6}) ↔ server ({server_ipv6}): via transit"
            )
            logger.info(f"  Send: {send_mbps:.2f} Mbps")
            logger.info(f"  Recv: {recv_mbps:.2f} Mbps")

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
            self._kill_iperf(ssh_command, server_port)
            time.sleep(0.5)
