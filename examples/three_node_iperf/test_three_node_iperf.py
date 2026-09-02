# Copyright (c) Peter Morrow

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
import netaddr
from netsim.testkit.base import BaseTopologyTests
from netsim.testkit.parallel_utils import run_parallel_simple
from netsim.testkit.network_helpers import enable_ip_forwarding, add_route
from netsim.testkit.process_helpers import kill_process

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
        topology,
        nodes,
    ):
        """Configure static routing on all nodes."""
        # Enable IP forwarding on transit node
        logger.info("Enabling IP forwarding on transit node...")
        enable_ip_forwarding(nodes["transit"], ipv4=True, ipv6=True)

        # Configure static routing on client
        client_iface = node_interfaces["client"]["net1"]
        transit_net1_iface = node_interfaces["transit"]["net1"]
        transit_net1_ip = transit_net1_iface.get_ip_address()
        transit_net1_ipv6 = transit_net1_iface.get_ipv6_address()

        logger.info(f"Configuring routing on client (via {transit_net1_ip})...")
        # IPv4 route: client needs to reach server's network via transit
        server_net = topology.get_network("net2")
        add_route(
            nodes["client"],
            netaddr.IPNetwork(server_net.subnet),
            netaddr.IPAddress(str(transit_net1_ip)),
            ipv6=False,
        )
        logger.info(f"  ✓ IPv4 route: {server_net.subnet} via {transit_net1_ip}")

        # IPv6 route: client needs to reach server's network via transit
        if (
            hasattr(server_net, "ipv6_subnet")
            and server_net.ipv6_subnet
            and transit_net1_ipv6
        ):
            add_route(
                nodes["client"],
                netaddr.IPNetwork(server_net.ipv6_subnet),
                netaddr.IPAddress(str(transit_net1_ipv6)),
                dev=client_iface.if_name,
                ipv6=True,
            )
            logger.info(
                f"  ✓ IPv6 route: {server_net.ipv6_subnet} via {transit_net1_ipv6} dev {client_iface.if_name}"
            )

            # Verify the route
            route_check = nodes["client"].ssh_command(
                f"ip -6 route show {server_net.ipv6_subnet}"
            )
            logger.debug(f"IPv6 route on client: {route_check.strip()}")

        # Configure static routing on server
        server_iface = node_interfaces["server"]["net2"]
        transit_net2_iface = node_interfaces["transit"]["net2"]
        transit_net2_ip = transit_net2_iface.get_ip_address()
        transit_net2_ipv6 = transit_net2_iface.get_ipv6_address()

        logger.info(f"Configuring routing on server (via {transit_net2_ip})...")
        # IPv4 route: server needs to reach client's network via transit
        client_net = topology.get_network("net1")
        add_route(
            nodes["server"],
            netaddr.IPNetwork(client_net.subnet),
            netaddr.IPAddress(str(transit_net2_ip)),
            ipv6=False,
        )
        logger.info(f"  ✓ IPv4 route: {client_net.subnet} via {transit_net2_ip}")

        # IPv6 route: server needs to reach client's network via transit
        if (
            hasattr(client_net, "ipv6_subnet")
            and client_net.ipv6_subnet
            and transit_net2_ipv6
        ):
            add_route(
                nodes["server"],
                netaddr.IPNetwork(client_net.ipv6_subnet),
                netaddr.IPAddress(str(transit_net2_ipv6)),
                dev=server_iface.if_name,
                ipv6=True,
            )
            logger.info(
                f"  ✓ IPv6 route: {client_net.ipv6_subnet} via {transit_net2_ipv6} dev {server_iface.if_name}"
            )

            # Verify the route
            route_check = nodes["server"].ssh_command(
                f"ip -6 route show {client_net.ipv6_subnet}"
            )
            logger.debug(f"IPv6 route on server: {route_check.strip()}")

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

    def test_ipv4_ping_client_to_server(
        self, configure_node_interfaces, node_interfaces, nodes
    ):
        """Test IPv4 ping from client to server via transit."""
        server_iface = node_interfaces["server"]["net2"]
        client_iface = node_interfaces["client"]["net1"]

        server_ip = server_iface.get_ip_address()
        client_ip = client_iface.get_ip_address()

        success, avg_rtt, output = self._ping_and_extract_rtt(
            nodes["client"], str(server_ip), count=3, ipv6=False
        )
        if not success:
            pytest.fail(f"IPv4 ping from client to server failed: {output}")

        rtt_str = f" ({avg_rtt:.2f}ms)" if avg_rtt else ""
        logger.info(
            f"✓ IPv4 Ping: client ({client_ip}) → server ({server_ip}) via transit{rtt_str}"
        )

    def test_ipv6_ping_client_to_server(
        self, configure_node_interfaces, node_interfaces, nodes
    ):
        """Test IPv6 ping from client to server via transit."""
        server_iface = node_interfaces["server"]["net2"]
        client_iface = node_interfaces["client"]["net1"]

        server_ipv6 = server_iface.get_ipv6_address()
        client_ipv6 = client_iface.get_ipv6_address()

        if not server_ipv6:
            pytest.skip("IPv6 not configured on server")

        if not client_ipv6:
            pytest.skip("IPv6 not configured on client")

        success, avg_rtt, output = self._ping_and_extract_rtt(
            nodes["client"], str(server_ipv6), count=3, ipv6=True
        )
        if not success:
            pytest.fail(f"IPv6 ping from client to server failed: {output}")

        rtt_str = f" ({avg_rtt:.2f}ms)" if avg_rtt else ""
        logger.info(
            f"✓ IPv6 Ping: client ({client_ipv6}) → server ({server_ipv6}) via transit{rtt_str}"
        )

    def test_tcp_throughput(
        self, install_iperf, configure_node_interfaces, node_interfaces, nodes
    ):
        """Test IPv4 TCP throughput from client to server via transit."""
        server_iface = node_interfaces["server"]["net2"]
        client_iface = node_interfaces["client"]["net1"]

        server_ip = server_iface.get_ip_address()
        client_ip = client_iface.get_ip_address()

        # Pre-cleanup
        kill_process(nodes["server"], "iperf3")
        time.sleep(1)

        try:
            nodes["server"].ssh_command("iperf3 -s -D", timeout=5)
            time.sleep(1)

            result = nodes["client"].ssh_command(
                f"iperf3 -c {str(server_ip)} -t 10 -J", timeout=20
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
            kill_process(nodes["server"], "iperf3")
            time.sleep(0.5)

    def test_udp_throughput(
        self, install_iperf, configure_node_interfaces, node_interfaces, nodes
    ):
        """Test IPv4 UDP throughput from client to server via transit."""
        server_iface = node_interfaces["server"]["net2"]
        client_iface = node_interfaces["client"]["net1"]

        server_ip = server_iface.get_ip_address()
        client_ip = client_iface.get_ip_address()

        # Pre-cleanup
        kill_process(nodes["server"], "iperf3")
        time.sleep(1)

        try:
            nodes["server"].ssh_command("iperf3 -s -D", timeout=5)
            time.sleep(1)

            result = nodes["client"].ssh_command(
                f"iperf3 -c {str(server_ip)} -u -b 100M -t 10 -J", timeout=20
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
            kill_process(nodes["server"], "iperf3")
            time.sleep(0.5)

    def test_bidirectional_throughput(
        self, install_iperf, configure_node_interfaces, node_interfaces, nodes
    ):
        """Test IPv4 bidirectional TCP throughput via transit."""
        server_iface = node_interfaces["server"]["net2"]
        client_iface = node_interfaces["client"]["net1"]

        server_ip = server_iface.get_ip_address()
        client_ip = client_iface.get_ip_address()

        # Pre-cleanup
        kill_process(nodes["server"], "iperf3")
        time.sleep(1)

        try:
            nodes["server"].ssh_command("iperf3 -s -D", timeout=5)
            time.sleep(1)

            result = nodes["client"].ssh_command(
                f"iperf3 -c {str(server_ip)} -t 10 --bidir -J", timeout=25
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
            kill_process(nodes["server"], "iperf3")
            time.sleep(0.5)

    def test_ipv6_tcp_throughput(
        self, install_iperf, configure_node_interfaces, node_interfaces, nodes
    ):
        """Test IPv6 TCP throughput from client to server via transit."""
        server_iface = node_interfaces["server"]["net2"]
        client_iface = node_interfaces["client"]["net1"]

        server_ipv6 = server_iface.get_ipv6_address()
        client_ipv6 = client_iface.get_ipv6_address()

        if not server_ipv6:
            pytest.skip("IPv6 not configured on server")

        # Pre-cleanup
        kill_process(nodes["server"], "iperf3")
        time.sleep(1)

        try:
            nodes["server"].ssh_command("iperf3 -s -D", timeout=5)
            time.sleep(1)

            result = nodes["client"].ssh_command(
                f"iperf3 -c {str(server_ipv6)} -t 10 -J", timeout=20
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
            kill_process(nodes["server"], "iperf3")
            time.sleep(0.5)

    def test_ipv6_udp_throughput(
        self, install_iperf, configure_node_interfaces, node_interfaces, nodes
    ):
        """Test IPv6 UDP throughput from client to server via transit."""
        server_iface = node_interfaces["server"]["net2"]
        client_iface = node_interfaces["client"]["net1"]

        server_ipv6 = server_iface.get_ipv6_address()
        client_ipv6 = client_iface.get_ipv6_address()

        if not server_ipv6:
            pytest.skip("IPv6 not configured on server")

        # Pre-cleanup
        kill_process(nodes["server"], "iperf3")
        time.sleep(1)

        try:
            nodes["server"].ssh_command("iperf3 -s -D", timeout=5)
            time.sleep(1)

            result = nodes["client"].ssh_command(
                f"iperf3 -c {str(server_ipv6)} -u -b 100M -t 10 -J", timeout=20
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
            kill_process(nodes["server"], "iperf3")
            time.sleep(0.5)

    def test_ipv6_bidirectional_throughput(
        self, install_iperf, configure_node_interfaces, node_interfaces, nodes
    ):
        """Test IPv6 bidirectional TCP throughput via transit."""
        server_iface = node_interfaces["server"]["net2"]
        client_iface = node_interfaces["client"]["net1"]

        server_ipv6 = server_iface.get_ipv6_address()
        client_ipv6 = client_iface.get_ipv6_address()

        if not server_ipv6:
            pytest.skip("IPv6 not configured on server")

        # Pre-cleanup
        kill_process(nodes["server"], "iperf3")
        time.sleep(1)

        try:
            nodes["server"].ssh_command("iperf3 -s -D", timeout=5)
            time.sleep(1)

            result = nodes["client"].ssh_command(
                f"iperf3 -c {str(server_ipv6)} -t 10 --bidir -J", timeout=25
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
            kill_process(nodes["server"], "iperf3")
            time.sleep(0.5)
