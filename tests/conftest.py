"""
Shared pytest fixtures for NetSim tests.

Provides:
- Topology loading
- SSH access to nodes
- Interface configuration with netplan
- Pause on failure for debugging
"""

from functools import lru_cache
import subprocess
import tempfile
import logging
import os
from pathlib import Path
from typing import Dict
import pytest
import yaml
import netaddr

from netsim.topology import TopologyParser
from netsim.simulator import TopologySimulator
from tests.parallel_utils import run_parallel_simple


logger = logging.getLogger(__name__)

# Log SSH commands to file (override with NETSIM_SSH_LOG)
SSH_LOG_PATH = Path(os.getenv("NETSIM_SSH_LOG", "ssh_commands.log")).resolve()

# Track if any test failed
_test_failed: bool = False


# Helper functions for running_topology
def _cleanup_leftover_vms(topology):
    """Clean up any leftover VMs from previous failed runs."""
    logger.info("Checking for leftover VMs from previous runs...")
    try:
        import libvirt

        conn = libvirt.open("qemu:///session")
        if conn:
            for node in topology.nodes:
                try:
                    dom = conn.lookupByName(node.name)
                    logger.warning(f"Found leftover VM: {node.name}, destroying it")
                    if dom.isActive():
                        dom.destroy()
                    dom.undefine()
                except libvirt.libvirtError:
                    pass  # VM doesn't exist, good
            conn.close()
    except Exception as e:
        logger.debug(f"Pre-cleanup check: {e}")


def _wait_for_vms_running(simulator, timeout=30):
    """Wait for all VMs to be running."""
    import time

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


def _wait_for_ssh_availability(topology, timeout_per_node=60):
    """Wait for SSH to be available on all nodes in parallel."""
    import time

    def _wait_for_node_ssh(node_name, ssh_port):
        """Wait for SSH on a single node."""
        ssh_start = time.time()
        while True:
            try:
                result = subprocess.run(
                    [
                        "ssh",
                        "-o",
                        "StrictHostKeyChecking=no",
                        "-o",
                        "UserKnownHostsFile=/dev/null",
                        "-o",
                        "ConnectTimeout=2",
                        "-p",
                        str(ssh_port),
                        "netsim@localhost",
                        "echo ready",
                    ],
                    capture_output=True,
                    timeout=5,
                    check=True,
                )
                if "ready" in result.stdout.decode():
                    logger.info(f"{node_name}: SSH ready")
                    return
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                if time.time() - ssh_start > timeout_per_node:
                    raise RuntimeError(
                        f"{node_name}: SSH not available after {timeout_per_node}s"
                    )
                time.sleep(2)

    logger.info("Waiting for SSH to be available on all nodes (in parallel)...")

    # Build list of (node_name, ssh_port) tuples
    node_ssh_info = [(node.name, 2200 + idx) for idx, node in enumerate(topology.nodes)]

    # Wait for all nodes in parallel
    run_parallel_simple(_wait_for_node_ssh, node_ssh_info)


def _pause_for_debugging(topology, request):
    """Pause for debugging if test failed and --pause-on-failure is set."""
    global _test_failed

    if not _test_failed:
        return

    pause_on_failure = request.config.getoption(
        "--pause-on-failure", False
    ) or os.environ.get("NETSIM_PAUSE_ON_FAILURE", "").lower() in ("1", "true", "yes")

    if not pause_on_failure:
        return

    logger.info("=" * 60)
    logger.info("⚠ TEST FAILURE DETECTED - PAUSING FOR DEBUGGING")
    logger.info("=" * 60)
    logger.info("Topology is still running. SSH access:")
    for idx, node in enumerate(topology.nodes):
        ssh_port = 2200 + idx
        logger.info(f"  {node.name}: ssh -p {ssh_port} netsim@localhost")
    logger.info("")
    logger.info("Press ENTER to tear down topology and continue...")
    logger.info("=" * 60)
    try:
        input()
    except (EOFError, KeyboardInterrupt):
        logger.info("Proceeding with teardown...")


def _log_vm_count(topology):
    """Log VM count for debugging."""
    try:
        import libvirt

        conn = libvirt.open("qemu:///session")
        if conn:
            all_domains = conn.listAllDomains()
            logger.info(f"Total VMs in libvirt session: {len(all_domains)}")
            if len(all_domains) > len(topology.nodes):
                logger.warning(
                    f"⚠ Expected {len(topology.nodes)} VMs, found {len(all_domains)}!"
                )
                for dom in all_domains:
                    logger.warning(f"  - {dom.name()}")
            conn.close()
    except Exception:
        pass


def pytest_addoption(parser):
    """Add custom command-line options."""
    parser.addoption(
        "--pause-on-failure",
        action="store_true",
        default=False,
        help="Keep topology running and pause for debugging when tests fail",
    )


def pytest_runtest_makereport(item, call):
    """Track test failures."""
    global _test_failed
    if call.when == "call" and call.excinfo is not None:
        _test_failed = True


@pytest.fixture(scope="module")
@lru_cache
def topology_path(request) -> Path:
    """
    Get discovered topology path for the current test module.

    Automatically discovered from test subdirectory name.
    Example: tests/two-node-topology/ -> tests/two-node-topology/two-node-topology.yaml
    """
    # Get the test file's directory
    test_file = Path(request.fspath)
    test_dir = test_file.parent

    # Look for topology file in the test directory
    topo_name = test_dir.name
    topo_path = test_dir / f"{topo_name}.yaml"

    if topo_path.exists():
        logger.info(f"Discovered topology for {test_file.name}: {topo_path}")
        return topo_path

    raise ValueError(f"No topology file found at {topo_path}")


@pytest.fixture(scope="module")
@lru_cache
def topology(topology_path: Path):
    """Load topology from YAML."""
    return TopologyParser.load(str(topology_path))


@pytest.fixture(scope="module", autouse=True)
def running_topology(topology, request):
    """
    Auto-start topology for test module, clean up after.

    Module-scoped with autouse=True to ensure topology runs for all tests in a module.
    Each test module (e.g., test_two_node_ping.py vs test_two_node_iperf.py) gets
    its own topology instance, preventing OOM from multiple topologies accumulating.

    The topology is started once per module and destroyed after that module's tests complete.
    Tests within the same module share the same running topology instance.
    """
    logger.info("=" * 60)
    logger.info(f"Starting topology for test module: {topology.name}")
    logger.info(f"Topology fixture ID: {id(topology)}")
    logger.info("=" * 60)

    with tempfile.TemporaryDirectory(prefix="netsim-test-") as runtime_dir:
        simulator = TopologySimulator(topology, runtime_dir=runtime_dir)

        try:
            # Pre-flight cleanup
            _cleanup_leftover_vms(topology)

            # Setup and start
            logger.info("Setting up networks and VMs...")
            simulator.setup()
            logger.info("Setup complete. Starting VMs...")
            simulator.start()

            # Wait for readiness
            _wait_for_vms_running(simulator)
            _wait_for_ssh_availability(topology)

            logger.info("=" * 60)
            logger.info("✓ Topology ready - all tests can now run")
            logger.info(f"Simulator instance ID: {id(simulator)}")
            logger.info("=" * 60)

            _log_vm_count(topology)

            yield simulator

        finally:
            # Check if we should pause before teardown
            _pause_for_debugging(topology, request)

            logger.info("=" * 60)
            logger.info("Tearing down topology")
            logger.info("=" * 60)
            try:
                simulator.destroy()
                logger.info("✓ Topology cleaned up")
            except Exception as e:
                logger.warning(f"Cleanup error: {e}")
            finally:
                # Explicitly clear all references
                simulator.vms.clear()
                simulator.bridges.clear()
                simulator.tap_devices.clear()
                simulator.node_interfaces.clear()
                del simulator

                # Force garbage collection to free VM memory
                import gc

                gc.collect()


@pytest.fixture(scope="module")
def node_allocations(topology) -> Dict[str, Dict[str, Dict[str, str]]]:
    """
    Get auto-allocated IPv4 and IPv6 addresses for each node.

    Returns:
        Dict mapping node_name -> {network_name: {"ipv4": "10.0.1.10/24", "ipv6": "2001:db8:1::10/64"}, ...}
    """
    # Simulate the allocation process without running setup()
    allocations = {}
    net_allocators = {}

    import ipaddress

    def _alloc_ip(net: ipaddress._BaseNetwork, idx: int) -> str:
        """Deterministically allocate the idx-th usable host in the network.

        Avoids materializing the full host list (which is impossible for /64 IPv6).
        idx=0 corresponds to the first usable host (network+1).
        """
        first_host = int(net.network_address) + 1  # skip network address
        # IPv4: exclude broadcast; IPv6: no broadcast, so allow all after network
        if isinstance(net, ipaddress.IPv4Network):
            last_host = int(net.broadcast_address) - 1
        else:
            last_host = int(net.network_address) + net.num_addresses - 1

        candidate = first_host + idx
        if candidate > last_host:
            raise ValueError(f"IP pool exhausted for network {net} (idx={idx})")

        return f"{ipaddress.ip_address(candidate)}/{net.prefixlen}"

    for node in topology.nodes:
        node_ifaces = {}

        for net_name in node.networks:
            # Initialize allocator if not present
            if net_name not in net_allocators:
                network = topology.get_network(net_name)
                if not network:
                    raise ValueError(f"Unknown network: {net_name}")

                ipv4_net = ipaddress.IPv4Network(network.subnet, strict=False)

                # Initialize IPv6 if present
                ipv6_net = None
                if hasattr(network, "ipv6_subnet") and network.ipv6_subnet:
                    ipv6_net = ipaddress.IPv6Network(network.ipv6_subnet, strict=False)

                # Start at index 9 to get .10 / ::10 (since hosts[0] is .1, hosts[9] is .10)
                net_allocators[net_name] = {
                    "ipv4": {"net": ipv4_net, "current": 9},
                    "ipv6": {"net": ipv6_net, "current": 9} if ipv6_net else None,
                }
            else:
                net_allocators[net_name]["ipv4"]["current"] += 1
                if net_allocators[net_name]["ipv6"]:
                    net_allocators[net_name]["ipv6"]["current"] += 1

            # Allocate IPv4 (without materializing host list)
            ipv4_obj = net_allocators[net_name]["ipv4"]["net"]
            ipv4_idx = net_allocators[net_name]["ipv4"]["current"]
            ipv4_cidr = _alloc_ip(ipv4_obj, ipv4_idx)

            # Allocate IPv6 if available
            ipv6_cidr = None
            if net_allocators[net_name]["ipv6"]:
                ipv6_obj = net_allocators[net_name]["ipv6"]["net"]
                ipv6_idx = net_allocators[net_name]["ipv6"]["current"]
                ipv6_cidr = _alloc_ip(ipv6_obj, ipv6_idx)

            node_ifaces[net_name] = {
                "ipv4": ipv4_cidr,
                "ipv6": ipv6_cidr,
            }

        allocations[node.name] = node_ifaces

    return allocations


@pytest.fixture(scope="module")
def ssh_command(topology) -> callable:
    """
    Fixture providing SSH command helper with per-node logging.

    Returns callable: ssh_command(port, cmd) -> output
    """

    # Configure file logger once per session
    if not any(
        isinstance(h, logging.FileHandler) and getattr(h, "_netsim_ssh_log", False)
        for h in logger.handlers
    ):
        SSH_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(SSH_LOG_PATH, mode="w")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        )
        file_handler._netsim_ssh_log = True  # marker to avoid duplicate handlers
        logger.addHandler(file_handler)
        logger.setLevel(logging.DEBUG)

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
        # Determine node name from port for logging
        node_name = f"port-{port}"
        for idx, node in enumerate(topology.nodes):
            if 2200 + idx == port:
                node_name = node.name
                break

        logger.debug(f"[{node_name}] $ {cmd}")

        full_cmd = [
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=5",
            "-p",
            str(port),
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

        output = result.stdout.strip()
        if output and len(output) < 200:  # Only log short outputs
            logger.debug(f"[{node_name}] → {output}")
        elif output:
            logger.debug(f"[{node_name}] → <{len(output)} bytes of output>")

        return output

    return _ssh_run


@pytest.fixture(scope="module")
def install_packages(ssh_command, node_ssh_port):
    """
    Fixture for installing packages on nodes.

    Returns a callable: install_packages(node_name, packages)

    Example:
        def test_example(install_packages):
            install_packages("node1", ["iperf3", "tcpdump"])
    """
    installed_cache = {}  # Track what's been installed to avoid duplicates

    def _install(node_name: str, packages: list[str]) -> None:
        """
        Install packages on a node using apt (Debian/Ubuntu).

        Args:
            node_name: Name of the node
            packages: List of package names to install
        """
        cache_key = (node_name, tuple(sorted(packages)))
        if cache_key in installed_cache:
            logger.debug(f"{node_name}: packages {packages} already installed")
            return

        ssh_port = node_ssh_port(node_name)
        package_list = " ".join(packages)

        logger.info(f"{node_name}: installing packages: {package_list}")

        try:
            # Update package list (increased timeout for parallel execution)
            ssh_command(ssh_port, "sudo apt-get update -qq", timeout=180)

            # Install packages (non-interactive, with dpkg lock avoidance)
            ssh_command(
                ssh_port,
                f"sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq {package_list}",
                timeout=180,
            )

            installed_cache[cache_key] = True
            logger.info(f"✓ {node_name}: packages installed: {package_list}")

        except subprocess.CalledProcessError as e:
            logger.error(f"✗ {node_name}: failed to install {package_list}")
            logger.error(f"  Stderr: {e.stderr if e.stderr else 'none'}")
            raise RuntimeError(f"Package installation failed on {node_name}: {e}")

    return _install


def _build_netplan_config(node_name, ifaces, node_allocations, mgmt_interface):
    """Build netplan YAML config for a node's interfaces."""
    iface_configs = node_allocations[node_name]
    interfaces = {}

    for net_name, node_iface in ifaces.items():
        addrs = iface_configs.get(net_name)
        if not addrs:
            continue

        ipv4_cidr = addrs.get("ipv4")
        ipv6_cidr = addrs.get("ipv6")

        # Build addresses list
        addresses = []
        if ipv4_cidr:
            addresses.append(ipv4_cidr)
        if ipv6_cidr:
            addresses.append(ipv6_cidr)

        if not addresses:
            continue

        interfaces[node_iface.if_name] = {
            "dhcp4": False,
            "dhcp6": False,
            "addresses": addresses,
        }

    # Disable IPv6 on management interface to prevent RA interference
    # The management interface will still get DHCPv4
    # link-local: [] prevents netplan from generating IPv6 link-local addresses
    interfaces[mgmt_interface] = {
        "dhcp4": True,
        "dhcp6": False,
        "link-local": [],  # Prevents IPv6 link-local address generation
    }

    return {
        "network": {
            "version": 2,
            "ethernets": interfaces,
        }
    }


def _apply_netplan_to_node(
    node_name, ifaces, netplan_yaml, ssh_command, mgmt_interface
):
    """Apply netplan configuration to a single node."""
    try:
        # Create temporary file with config locally
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(netplan_yaml)
            temp_path = f.name

        # Get SSH port for this node
        ssh_port = list(ifaces.values())[0].ssh_port

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
            "netsim@localhost:/tmp/netsim.yaml",
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
        logger.error(
            f"  Command: {' '.join(e.cmd) if isinstance(e.cmd, list) else e.cmd}"
        )
        logger.error(f"  Exit code: {e.returncode}")
        if e.stderr:
            logger.error(f"  Stderr: {e.stderr}")
        if e.stdout:
            logger.error(f"  Stdout: {e.stdout}")
        raise
    except Exception as e:
        logger.error(f"✗ Failed to configure {node_name}: {e}")
        raise


@pytest.fixture(scope="module")
def configure_node_interfaces(node_interfaces, node_allocations, ssh_command):
    """
    Fixture that configures all node interfaces with netplan in parallel.

    Depends on node_interfaces (which depends on running_topology).

    Usage in tests:
        def test_example(configure_node_interfaces):
            # Interfaces are now configured
            pass
    """
    logger.info("=" * 60)
    logger.info("Configuring node interfaces with netplan (in parallel)")
    logger.info("=" * 60)

    def _configure_node(node_name, ifaces):
        """Configure a single node's interfaces."""
        iface_configs = node_allocations[node_name]

        # Skip if no data interfaces
        if len(iface_configs) == 0:
            logger.info(f"{node_name}: no data interfaces to configure")
            return

        logger.info(f"Configuring {len(iface_configs)} interface(s) for {node_name}")

        # Discover management interface (first interface)
        ssh_port = list(ifaces.values())[0].ssh_port
        output = ssh_command(
            ssh_port,
            "ip -o link show | grep -v ' lo:' | awk -F': ' '{print $2}' | head -1",
        )
        mgmt_interface = output.strip().split("@")[0]  # Remove @NONE suffix if present
        logger.debug(f"{node_name}: management interface is {mgmt_interface}")

        # Build netplan config
        netplan_config = _build_netplan_config(
            node_name, ifaces, node_allocations, mgmt_interface
        )

        # Log interfaces for this node (grouped before parallel execution)
        for net_name, node_iface in ifaces.items():
            addrs = iface_configs.get(net_name)
            if addrs:
                ipv4 = addrs.get("ipv4", "")
                ipv6 = addrs.get("ipv6", "")
                addr_parts = [addr for addr in [ipv4, ipv6] if addr]
                addr_info = ", ".join(addr_parts)
                logger.info(
                    f"  [{node_name}] {node_iface.if_name} ({net_name}): {addr_info}"
                )

        netplan_yaml = yaml.dump(netplan_config, default_flow_style=False)
        _apply_netplan_to_node(
            node_name, ifaces, netplan_yaml, ssh_command, mgmt_interface
        )

    # Configure all nodes in parallel
    run_parallel_simple(
        _configure_node,
        [(node_name, ifaces) for node_name, ifaces in node_interfaces.items()],
    )

    logger.info("=" * 60)
    logger.info("✓ All interfaces configured")
    logger.info("=" * 60)


@pytest.fixture(scope="module")
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

    def __init__(
        self,
        node_name: str,
        if_name: str,
        network: str,
        ssh_port: int,
        ssh_cmd: callable,
        ipv4_addr: str = None,
        ipv6_addr: str = None,
    ):
        self.node_name = node_name
        self.if_name = if_name
        self.network = network
        self.ssh_port = ssh_port
        self._ssh = ssh_cmd
        self.ipv4_addr = ipv4_addr
        self.ipv6_addr = ipv6_addr

    def up(self):
        """Bring interface up."""
        self._ssh(self.ssh_port, f"sudo ip link set {self.if_name} up")

    def down(self):
        """Bring interface down."""
        self._ssh(self.ssh_port, f"sudo ip link set {self.if_name} down")

    def get_ip(self) -> str:
        """Get IPv4 address as CIDR string."""
        output = self._ssh(
            self.ssh_port,
            f"ip -4 addr show {self.if_name} | grep 'inet ' | awk '{{print $2}}'",
        )
        return output.strip()

    def get_ip_address(self) -> netaddr.IPAddress:
        """Get IPv4 address as netaddr.IPAddress object."""
        cidr_str = self.get_ip()
        if not cidr_str:
            return None
        return netaddr.IPAddress(cidr_str.split("/")[0])

    def get_ipv6(self) -> str:
        """Get IPv6 address as CIDR string."""
        output = self._ssh(
            self.ssh_port,
            f"ip -6 addr show {self.if_name} | grep 'inet6' | awk '{{print $2}}' | grep -v '^fe80'",
        )
        return output.strip()

    def get_ipv6_address(self) -> netaddr.IPAddress:
        """Get IPv6 address as netaddr.IPAddress object."""
        cidr_str = self.get_ipv6()
        if not cidr_str:
            return None
        return netaddr.IPAddress(cidr_str.split("/")[0])

    def is_up(self) -> bool:
        """Check if interface is up."""
        output = self._ssh(self.ssh_port, f"ip link show {self.if_name}")
        return "UP" in output


def _discover_interface_names(node_name, ssh_port, ssh_command):
    """Discover interface names on a node via SSH."""
    output = ssh_command(
        ssh_port, "ip -o link show | grep -v ' lo:' | awk -F': ' '{print $2}'"
    )
    all_if_names = [name.strip() for name in output.split("\n") if name.strip()]

    # Filter out @NONE suffixes
    if_names = [
        name.split("@")[0] for name in all_if_names if not name.startswith("lo")
    ]

    logger.info(f"{node_name}: discovered interfaces: {if_names}")
    return if_names


def _map_networks_to_interfaces(
    node_name, if_names, node_allocations, ssh_command, node_ssh_port
):
    """Map networks to discovered interfaces."""
    iface_configs = node_allocations[node_name]
    node_ifaces = {}

    # Map data networks to interfaces
    # if_names[0] = management interface (skip it)
    # if_names[1] = first data network
    # if_names[2] = second data network, etc.
    config_idx = 0
    for net_name, addrs in iface_configs.items():
        # Skip management interface (if_names[0]) by adding 1 to index
        if_idx = config_idx + 1
        if if_idx < len(if_names):
            if_name = if_names[if_idx]
            ipv4_addr = addrs.get("ipv4")
            ipv6_addr = addrs.get("ipv6")
            ssh_port = node_ssh_port(node_name)
            node_ifaces[net_name] = NodeInterface(
                node_name,
                if_name,
                net_name,
                ssh_port,
                ssh_command,
                ipv4_addr=ipv4_addr,
                ipv6_addr=ipv6_addr,
            )
            addr_info = ipv4_addr if ipv4_addr else ""
            if ipv6_addr:
                addr_info = f"{ipv4_addr}, {ipv6_addr}" if ipv4_addr else ipv6_addr
            logger.info(f"{node_name}: {if_name} -> {net_name} ({addr_info})")
        config_idx += 1

    return node_ifaces


@pytest.fixture(scope="module")
def node_interfaces(
    running_topology, topology, node_allocations, ssh_command, node_ssh_port
):
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

        # Discover interface names
        if_names = _discover_interface_names(node_name, ssh_port, ssh_command)

        # Map networks to interfaces
        node_ifaces = _map_networks_to_interfaces(
            node_name, if_names, node_allocations, ssh_command, node_ssh_port
        )

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

    def test_interface_discovery(self, node_interfaces, topology):
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
    ):
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
        ssh_command, ssh_port, target_ip, count=3, ipv6=False, timeout=10
    ):
        """Execute ping and extract average RTT.

        Args:
            ssh_command: SSH command function
            ssh_port: SSH port to connect to
            target_ip: Target IP address to ping
            count: Number of pings to send
            ipv6: Whether to use ping6 instead of ping
            timeout: Command timeout in seconds

        Returns:
            tuple: (success: bool, avg_rtt: float or None, output: str)
        """
        import re

        cmd = f"ping6 -c {count}" if ipv6 else f"ping -c {count}"
        cmd += f" {target_ip}"

        try:
            result = ssh_command(ssh_port, cmd, timeout=timeout)

            # Extract average RTT from output
            # Format: rtt min/avg/max/mdev = 0.123/0.456/0.789/0.012 ms
            rtt_match = re.search(
                r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/[\d.]+/[\d.]+ ms", result
            )
            avg_rtt = float(rtt_match.group(1)) if rtt_match else None

            # Check for packet loss
            success = "100% packet loss" not in result

            return success, avg_rtt, result
        except subprocess.CalledProcessError as e:
            return False, None, e.stderr if e.stderr else str(e)

    def test_ping_between_nodes(
        self, configure_node_interfaces, node_interfaces, topology, ssh_command
    ):
        """Test ICMP connectivity between nodes that share networks (IPv4 and IPv6)."""
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
                target_ip = target_iface.get_ip_address()
                source_ip = source_iface.get_ip_address()

                # IPv4 Ping from source to target
                success, avg_rtt, output = self._ping_and_extract_rtt(
                    ssh_command,
                    source_iface.ssh_port,
                    str(target_ip),
                    count=1,
                    ipv6=False,
                )
                if success:
                    rtt_str = f" ({avg_rtt:.2f}ms)" if avg_rtt else ""
                    logger.info(
                        f"✓ IPv4 Ping {source_node} ({source_ip}) -> {target_node} ({target_ip}) on {net_name}{rtt_str}"
                    )
                else:
                    pytest.fail(
                        f"IPv4 Ping failed: {source_node} ({source_ip}) -> {target_node} ({target_ip}) on {net_name}\n"
                        f"Error: {output}"
                    )

                # IPv6 Ping from source to target (if available)
                target_ipv6 = target_iface.get_ipv6_address()
                source_ipv6 = source_iface.get_ipv6_address()

                if target_ipv6 and source_ipv6:
                    success, avg_rtt, output = self._ping_and_extract_rtt(
                        ssh_command,
                        source_iface.ssh_port,
                        str(target_ipv6),
                        count=1,
                        ipv6=True,
                    )
                    if success:
                        rtt_str = f" ({avg_rtt:.2f}ms)" if avg_rtt else ""
                        logger.info(
                            f"✓ IPv6 Ping {source_node} ({source_ipv6}) -> {target_node} ({target_ipv6}) on {net_name}{rtt_str}"
                        )
                    else:
                        pytest.fail(
                            f"IPv6 Ping failed: {source_node} ({source_ipv6}) -> {target_node} ({target_ipv6}) on {net_name}\n"
                            f"Error: {output}"
                        )
