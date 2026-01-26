"""
Shared pytest fixtures for NetSim tests.

Provides:
- Topology loading
- SSH access to nodes
- Interface configuration with netplan
"""

import subprocess
import tempfile
import logging
from pathlib import Path
from typing import Dict, List, Tuple
import pytest
import yaml

from netsim.topology import TopologyParser
from netsim.simulator import TopologySimulator


logger = logging.getLogger(__name__)

# Session-level variable to store discovered topology path
_topology_path: Path = None


def pytest_collection_modifyitems(session, config, items):
    """After collection, set topology path based on collected test."""
    global _topology_path
    
    if items and not _topology_path:
        # Get directory of first test
        test_file = Path(items[0].fspath)
        test_dir = test_file.parent
        
        # Look for topology file
        topo_name = test_dir.name
        topo_path = test_dir / f"{topo_name}.yaml"
        
        if topo_path.exists():
            _topology_path = topo_path
            logger.info(f"Discovered topology: {_topology_path}")


@pytest.fixture(scope="session")
def topology_path() -> Path:
    """
    Get discovered topology path.
    
    Automatically discovered from test subdirectory name.
    Example: tests/two-node-topology/ -> tests/two-node-topology/two-node-topology.yaml
    """
    if not _topology_path:
        raise ValueError("No topology file discovered")
    return _topology_path


@pytest.fixture(scope="session")
def topology(topology_path: Path):
    """Load topology from YAML."""
    return TopologyParser.load(str(topology_path))


@pytest.fixture(scope="session")
def running_topology(topology):
    """
    Auto-start topology for entire test session, clean up after.
    
    This fixture ensures VMs are running before any tests execute.
    """
    import time
    
    logger.info(f"=" * 60)
    logger.info(f"Starting topology: {topology.name}")
    logger.info(f"=" * 60)
    
    with tempfile.TemporaryDirectory(prefix="netsim-test-") as runtime_dir:
        simulator = TopologySimulator(topology, runtime_dir=runtime_dir)
        
        try:
            logger.info(f"Setting up networks and VMs...")
            simulator.setup()
            logger.info(f"Setup complete. Starting VMs...")
            simulator.start()
            
            # Wait for VMs to be running
            timeout = 30
            start_time = time.time()
            while True:
                status = simulator.status()
                all_running = all(status.values())
                if all_running:
                    running_nodes = ", ".join(status.keys())
                    logger.info(f"✓ All domains started: {running_nodes}")
                    break
                if time.time() - start_time > timeout:
                    raise RuntimeError(f"VMs failed to start within {timeout}s")
                time.sleep(1)
            
            # Wait for SSH to be available on all nodes
            logger.info("Waiting for SSH to be available on all nodes...")
            for idx, node in enumerate(topology.nodes):
                ssh_port = 2200 + idx
                ssh_timeout = 60
                ssh_start = time.time()
                while True:
                    try:
                        result = subprocess.run(
                            ["ssh", "-o", "StrictHostKeyChecking=no", 
                             "-o", "UserKnownHostsFile=/dev/null",
                             "-o", "ConnectTimeout=2",
                             "-p", str(ssh_port), "netsim@localhost", "echo ready"],
                            capture_output=True,
                            timeout=5,
                            check=True
                        )
                        if "ready" in result.stdout.decode():
                            logger.info(f"{node.name}: SSH ready")
                            break
                    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                        if time.time() - ssh_start > ssh_timeout:
                            raise RuntimeError(f"{node.name}: SSH not available after {ssh_timeout}s")
                        time.sleep(2)
            
            logger.info(f"=" * 60)
            logger.info(f"✓ Topology ready - all tests can now run")
            logger.info(f"=" * 60)
            
            yield simulator
            
        finally:
            logger.info(f"=" * 60)
            logger.info(f"Tearing down topology")
            logger.info(f"=" * 60)
            try:
                simulator.destroy()
                logger.info(f"✓ Topology cleaned up")
            except Exception as e:
                logger.warning(f"Cleanup error: {e}")


@pytest.fixture(scope="session")
def node_allocations(topology) -> Dict[str, List[Tuple[str, str]]]:
    """
    Get auto-allocated IP addresses for each node.

    Returns:
        Dict mapping node_name -> [(network_name, ip_cidr), ...]
    """
    # Simulate the allocation process without running setup()
    allocations = {}
    net_allocators = {}
    
    for node in topology.nodes:
        node_ifaces = []
        
        for net_name in node.networks:
            # Initialize allocator if not present
            if net_name not in net_allocators:
                network = topology.get_network(net_name)
                if not network:
                    raise ValueError(f"Unknown network: {net_name}")
                
                import ipaddress
                net = ipaddress.IPv4Network(network.subnet, strict=False)
                # Start at index 9 to get .10 (since hosts[0] is .1, hosts[9] is .10)
                net_allocators[net_name] = {"net": net, "current": 9}
            else:
                net_allocators[net_name]["current"] += 1
            
            # Allocate IP
            import ipaddress
            net_obj = net_allocators[net_name]["net"]
            alloc_idx = net_allocators[net_name]["current"]
            
            hosts = list(net_obj.hosts())
            if alloc_idx >= len(hosts):
                raise ValueError(
                    f"IP pool exhausted for network {net_name}. Subnet too small."
                )
            
            ip_addr = hosts[alloc_idx]
            ip_cidr = f"{ip_addr}/{net_obj.prefixlen}"
            node_ifaces.append((net_name, ip_cidr))
        
        allocations[node.name] = node_ifaces
    
    return allocations


@pytest.fixture(scope="session")
def ssh_command() -> callable:
    """
    Fixture providing SSH command helper.

    Returns callable: ssh_command(port, cmd) -> output
    """
    def _ssh_run(port: int, cmd: str, timeout: int = 10) -> str:
        """
        SSH into a node and run a command.

        Args:
            port: SSH port (e.g., 2200)
            cmd: Shell command to run
            timeout: Command timeout in seconds

        Returns:
            Command output (stdout)

        Raises:
            subprocess.CalledProcessError: If command fails
        """
        full_cmd = [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=5",
            "-p", str(port),
            "netsim@localhost",
            cmd,
        ]
        
        result = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True,
        )
        return result.stdout.strip()
    
    return _ssh_run


@pytest.fixture
def configure_node_interfaces(node_interfaces, node_allocations, ssh_command):
    """
    Fixture that configures all node interfaces with netplan.

    Depends on node_interfaces (which depends on running_topology).
    
    Usage in tests:
        def test_example(configure_node_interfaces):
            # Interfaces are now configured
            pass
    """
    logger.info("=" * 60)
    logger.info("Configuring node interfaces with netplan")
    logger.info("=" * 60)
    
    for node_name, ifaces in node_interfaces.items():
        iface_configs = node_allocations[node_name]
        
        # Skip if no data interfaces
        if len(iface_configs) == 0:
            logger.info(f"{node_name}: no data interfaces to configure")
            continue
        
        logger.info(f"Configuring {len(iface_configs)} interface(s) for {node_name}")
        
        # Build netplan config for all interfaces
        interfaces = {}
        
        for net_name, node_iface in ifaces.items():
            # Find the IP for this network
            ip_cidr = next((ip for n, ip in iface_configs if n == net_name), None)
            if not ip_cidr:
                continue
            
            interfaces[node_iface.if_name] = {
                "dhcp4": False,
                "addresses": [ip_cidr],
            }
            
            logger.info(f"  {node_iface.if_name} ({net_name}): {ip_cidr}")
        
        # Create netplan config
        netplan_config = {
            "network": {
                "version": 2,
                "ethernets": interfaces,
            }
        }
        
        netplan_yaml = yaml.dump(netplan_config, default_flow_style=False)
        
        # Write to node via sudo tee
        try:
            # Create temporary file with config locally first
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
                f.write(netplan_yaml)
                temp_path = f.name
            
            # Get SSH port for this node
            ssh_port = list(ifaces.values())[0].ssh_port
            
            # Copy to node
            scp_cmd = [
                "scp",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-P", str(ssh_port),
                temp_path,
                f"netsim@localhost:/tmp/netsim.yaml",
            ]
            subprocess.run(scp_cmd, check=True, capture_output=True, timeout=10)
            
            # Ensure netplan directory exists and apply with sudo
            ssh_command(ssh_port, "sudo mkdir -p /etc/netplan")
            ssh_command(ssh_port, "sudo cp /tmp/netsim.yaml /etc/netplan/99-netsim.yaml")
            ssh_command(ssh_port, "sudo chmod 600 /etc/netplan/99-netsim.yaml")
            
            # Show what we're applying
            logger.debug(f"{node_name} netplan config:\n{netplan_yaml}")
            
            # Apply netplan
            result = ssh_command(ssh_port, "sudo netplan apply 2>&1")
            if result:
                logger.debug(f"{node_name} netplan output: {result}")
            
            logger.info(f"✓ {node_name}: netplan configuration applied")
            
            # Clean up temp file
            Path(temp_path).unlink()
            
        except subprocess.CalledProcessError as e:
            logger.error(f"✗ Failed to configure {node_name}")
            logger.error(f"  Command: {' '.join(e.cmd) if isinstance(e.cmd, list) else e.cmd}")
            logger.error(f"  Exit code: {e.returncode}")
            if e.stderr:
                logger.error(f"  Stderr: {e.stderr}")
            if e.stdout:
                logger.error(f"  Stdout: {e.stdout}")
            raise
        except Exception as e:
            logger.error(f"✗ Failed to configure {node_name}: {e}")
            raise
    
    logger.info("=" * 60)
    logger.info("✓ All interfaces configured")
    logger.info("=" * 60)


@pytest.fixture(scope="session")
def node_ssh_port(topology) -> callable:
    """
    Get SSH port for a node by name.

    Returns callable: node_ssh_port(node_name) -> port
    """
    def _get_port(node_name: str) -> int:
        for idx, node in enumerate(topology.nodes):
            if node.name == node_name:
                return 2200 + idx
        raise ValueError(f"Node {node_name} not found")
    
    return _get_port


class NodeInterface:
    """Helper class for interface management."""
    
    def __init__(self, node_name: str, if_name: str, network: str, ssh_port: int, ssh_cmd: callable):
        self.node_name = node_name
        self.if_name = if_name
        self.network = network
        self.ssh_port = ssh_port
        self._ssh = ssh_cmd
    
    def up(self):
        """Bring interface up."""
        self._ssh(self.ssh_port, f"sudo ip link set {self.if_name} up")
    
    def down(self):
        """Bring interface down."""
        self._ssh(self.ssh_port, f"sudo ip link set {self.if_name} down")
    
    def get_ip(self) -> str:
        """Get IP address."""
        output = self._ssh(self.ssh_port, f"ip -4 addr show {self.if_name} | grep 'inet ' | awk '{{print $2}}'")
        return output.strip()
    
    def is_up(self) -> bool:
        """Check if interface is up."""
        output = self._ssh(self.ssh_port, f"ip link show {self.if_name}")
        return "UP" in output


@pytest.fixture(scope="session")
def node_interfaces(running_topology, topology, node_allocations, ssh_command, node_ssh_port):
    """
    Discover interfaces on each node and map to networks.
    
    Note: VMs have management interface (user-mode NAT) as first interface,
    followed by data interfaces (tap devices). We skip the management interface.
    
    Returns:
        Dict[str, Dict[str, NodeInterface]] - node_name -> {network_name: NodeInterface}
    """
    interfaces = {}
    
    for idx, node in enumerate(topology.nodes):
        node_name = node.name
        ssh_port = node_ssh_port(node_name)
        node_ifaces = {}
        
        # Discover interface names (exclude loopback)
        output = ssh_command(ssh_port, "ip -o link show | grep -v ' lo:' | awk -F': ' '{print $2}'")
        all_if_names = [name.strip() for name in output.split('\n') if name.strip()]
        
        # Filter out @NONE suffixes
        if_names = [name.split('@')[0] for name in all_if_names if not name.startswith('lo')]
        
        logger.info(f"{node_name}: discovered interfaces: {if_names}")
        
        # Get allocation info for this node (list of (network_name, ip_cidr) tuples)
        # This only includes data networks, not the management interface
        iface_configs = node_allocations[node_name]
        
        # Map data networks to interfaces
        # if_names[0] = management interface (skip it)
        # if_names[1] = first data network
        # if_names[2] = second data network, etc.
        for config_idx, (net_name, ip_cidr) in enumerate(iface_configs):
            # Skip management interface (if_names[0]) by adding 1 to index
            if_idx = config_idx + 1
            if if_idx < len(if_names):
                if_name = if_names[if_idx]
                node_ifaces[net_name] = NodeInterface(
                    node_name, if_name, net_name, ssh_port, ssh_command
                )
                logger.info(f"{node_name}: {if_name} -> {net_name} ({ip_cidr})")
        
        interfaces[node_name] = node_ifaces
    
    return interfaces


class BaseTopologyTests:
    """
    Base test class with common topology validation tests.
    
    All topology-specific test suites should inherit from this class
    to get standard validation tests that work with any topology.
    """

    @pytest.fixture(autouse=True)
    def ensure_topology_running(self, running_topology):
        """Ensure topology is started before any test in this class runs."""
        pass

    def test_nodes_configured(self, topology, node_allocations):
        """Verify nodes and interfaces are properly allocated."""
        # Check all topology nodes are present
        assert len(topology.nodes) > 0, "Topology should have at least one node"
        
        # Verify each node has allocations for its networks
        for node in topology.nodes:
            assert node.name in node_allocations, f"Node {node.name} missing from allocations"
            
            node_ifaces = node_allocations[node.name]
            assert len(node_ifaces) == len(node.networks), \
                f"Node {node.name} should have {len(node.networks)} interfaces, got {len(node_ifaces)}"
            
            # Check each network has an IP allocation
            for idx, net_name in enumerate(node.networks):
                alloc_net_name, ip_cidr = node_ifaces[idx]
                assert alloc_net_name == net_name, \
                    f"Network mismatch: expected {net_name}, got {alloc_net_name}"
                
                # Verify IP is in the correct subnet
                network = topology.get_network(net_name)
                assert network, f"Network {net_name} not found in topology"
                assert ip_cidr.startswith(network.subnet.split('/')[0].rsplit('.', 1)[0]), \
                    f"IP {ip_cidr} not in subnet {network.subnet}"

    def test_interface_discovery(self, node_interfaces, topology):
        """Test that interfaces are discovered correctly on all nodes."""
        # Check all nodes have interface discovery
        for node in topology.nodes:
            assert node.name in node_interfaces, \
                f"Node {node.name} missing from interface discovery"
            
            node_ifaces = node_interfaces[node.name]
            
            # Check all networks are discovered
            for net_name in node.networks:
                assert net_name in node_ifaces, \
                    f"Network {net_name} not discovered on {node.name}"
                
                iface = node_ifaces[net_name]
                assert iface.if_name is not None, \
                    f"Interface name not set for {node.name}:{net_name}"
                assert iface.ssh_port > 0, \
                    f"SSH port not set for {node.name}:{net_name}"

    def test_interface_configuration(self, configure_node_interfaces, node_interfaces, node_allocations):
        """Test that interfaces are configured with correct IPs on all nodes."""
        for node_name, ifaces in node_interfaces.items():
            allocations = node_allocations[node_name]
            
            for net_name, node_iface in ifaces.items():
                # Interface should be up
                assert node_iface.is_up(), \
                    f"{node_name}:{net_name} interface should be up"
                
                # Get expected IP from allocations
                expected_ip = next((ip for n, ip in allocations if n == net_name), None)
                assert expected_ip, f"No allocation found for {node_name}:{net_name}"
                
                # Check actual IP matches
                actual_ip = node_iface.get_ip()
                assert actual_ip == expected_ip, \
                    f"{node_name}:{net_name} should have IP {expected_ip}, got {actual_ip}"

    def test_ping_between_nodes(self, configure_node_interfaces, node_interfaces, topology, ssh_command):
        """Test ICMP connectivity between nodes that share networks."""
        # Build a map of network -> [nodes]
        network_nodes = {}
        for node in topology.nodes:
            for net_name in node.networks:
                if net_name not in network_nodes:
                    network_nodes[net_name] = []
                network_nodes[net_name].append(node.name)
        
        # Test ping between nodes on each shared network
        tested_pairs = set()
        for net_name, node_names in network_nodes.items():
            if len(node_names) < 2:
                logger.info(f"Network {net_name} has only one node, skipping ping test")
                continue
            
            # Test ping from first node to all others on this network
            source_node = node_names[0]
            source_iface = node_interfaces[source_node][net_name]
            
            for target_node in node_names[1:]:
                pair = (source_node, target_node)
                if pair in tested_pairs:
                    continue
                tested_pairs.add(pair)
                
                target_iface = node_interfaces[target_node][net_name]
                target_ip = target_iface.get_ip().split('/')[0]
                
                # Ping from source to target
                try:
                    ssh_command(source_iface.ssh_port, f"ping -c 1 -W 2 {target_ip}", timeout=10)
                    logger.info(f"✓ Ping {source_node} -> {target_node} ({target_ip}) on {net_name}")
                except subprocess.CalledProcessError as e:
                    pytest.fail(
                        f"Ping failed: {source_node} -> {target_node} ({target_ip}) on {net_name}\n"
                        f"Error: {e.stderr if e.stderr else e}"
                    )

    def test_interface_control(self, configure_node_interfaces, node_interfaces, topology):
        """Test bringing interfaces up and down on first node."""
        # Just test the first node to verify interface control works
        if not topology.nodes:
            pytest.skip("No nodes in topology")
        
        first_node = topology.nodes[0]
        if first_node.name not in node_interfaces or not node_interfaces[first_node.name]:
            pytest.skip(f"No interfaces to test on {first_node.name}")
        
        # Get first interface
        net_name = list(node_interfaces[first_node.name].keys())[0]
        iface = node_interfaces[first_node.name][net_name]
        
        # Interface should start up
        assert iface.is_up(), f"{first_node.name}:{net_name} should be up initially"
        
        # Bring it down
        iface.down()
        assert not iface.is_up(), f"{first_node.name}:{net_name} should be down after calling down()"
        
        # Bring it back up
        iface.up()
        assert iface.is_up(), f"{first_node.name}:{net_name} should be up after calling up()"
