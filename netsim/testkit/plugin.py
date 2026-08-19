# Copyright (c) Dufferin Software

"""
Shared pytest fixtures for NetSim tests.

Provides:
- Topology loading
- SSH access to nodes
- Interface configuration with netplan
- Pause on failure for debugging
"""

import subprocess
import tempfile
import logging
import os
import time
from pathlib import Path
from typing import Callable, Any, Dict, Generator
import pytest
import yaml
from tenacity import (
    retry,
    stop_after_attempt,
    wait_fixed,
    retry_if_exception_type,
)

from netsim.topology import Topology, TopologyParser
from netsim.simulator import TopologySimulator
from netsim import libvirt_utils
from netsim.testkit.parallel_utils import run_parallel_simple
from netsim.testkit.node import Node, NodeInterface


logger: logging.Logger = logging.getLogger(__name__)

# Log SSH commands to file (override with NETSIM_SSH_LOG)
SSH_LOG_PATH: Path = Path(os.getenv("NETSIM_SSH_LOG", "ssh_commands.log")).resolve()

# Track if any test failed
_test_failed: bool = False

# Track current topology for PDB debugging
_current_topology = None


# Helper functions for running_topology
def _cleanup_leftover_vms(topology) -> None:
    """Clean up any leftover VMs and tap devices from previous failed runs."""
    libvirt_utils.cleanup_leftover_vms(topology)
    libvirt_utils.cleanup_leftover_taps()


def _wait_for_vms_running(simulator, timeout=30) -> None:
    """Wait for all VMs to be running."""

    start_time: float = time.time()
    while True:
        status = simulator.status()
        all_running: bool = all(status.values())
        if all_running:
            running_nodes: str = ", ".join(status.keys())
            logger.info(f"✓ All domains started: {running_nodes}")
            break
        if time.time() - start_time > timeout:
            raise RuntimeError(f"VMs failed to start within {timeout}s")
        time.sleep(1)


def _wait_for_ssh_availability(topology, timeout_per_node=60) -> None:
    """Wait for SSH to be available on all nodes in parallel."""

    def _wait_for_node_ssh(node_name, ssh_port) -> None:
        """Wait for SSH on a single node."""
        ssh_start: float = time.time()
        while True:
            try:
                result: subprocess.CompletedProcess[bytes] = subprocess.run(
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


def _pause_for_debugging(topology, request) -> None:
    """Pause for debugging if test failed and --pause-on-failure is set."""
    global _test_failed

    if not _test_failed:
        return

    # Skip pause if --pdb was used - user already had debugging opportunity
    if request.config.getoption("--pdb", False):
        logger.info("Skipping pause (--pdb was used for debugging)")
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
        ssh_port: int = 2200 + idx
        logger.info(f"  {node.name}: ssh -p {ssh_port} netsim@localhost")
    logger.info("")
    logger.info("Press ENTER to tear down topology and continue...")
    logger.info("=" * 60)
    try:
        # Check if stdin is available (not captured by pytest)
        import sys

        if sys.stdin.isatty():
            input()
        else:
            logger.warning("stdin not available (pytest capturing?), skipping pause")
    except (EOFError, KeyboardInterrupt, OSError):
        logger.info("Proceeding with teardown...")


def _log_vm_count(topology) -> None:
    """Log VM count for debugging."""
    libvirt_utils.log_vm_count(topology)


def pytest_addoption(parser) -> None:
    """Add custom command-line options."""
    parser.addoption(
        "--pause-on-failure",
        action="store_true",
        default=False,
        help="Keep topology running and pause for debugging when tests fail",
    )
    parser.addoption(
        "--package-dir",
        action="store",
        default=None,
        help="Directory containing the .deb packages referenced by the "
        "topology's per-node 'packages' lists (overrides the topology's "
        "'package_dir')",
    )
    parser.addoption(
        "--feature",
        action="store",
        default="vanilla",
        help="Engine feature set to install on nodes whose topology declares "
        "per-feature package sets ('packages: features: {...}'), e.g. "
        "vanilla, ips, ipfix, ips-ipfix. Nodes with a plain 'packages' "
        "list always install it, regardless of this flag (default: vanilla)",
    )
    parser.addoption(
        "--scale-nodes",
        action="store",
        type=int,
        default=10,
        help="Number of policy-engine + policy-node-agent container pairs to spin up in scale tests",
    )
    parser.addoption(
        "--engine-image",
        action="store",
        default="policy-engine:0.1.0",
        help="Docker image name for policy-engine (must exist in local daemon)",
    )
    parser.addoption(
        "--agent-image",
        action="store",
        default="policy-node-agent:0.1.0",
        help="Docker image name for policy-node-agent (must exist in local daemon)",
    )
    parser.addoption(
        "--tpm",
        action="store_true",
        default=True,
        dest="tpm",
        help="Attach an emulated TPM 2.0 (via swtpm) to each VM (default: enabled)",
    )
    parser.addoption(
        "--no-tpm",
        action="store_false",
        dest="tpm",
        help="Disable TPM emulation for all VMs",
    )


def pytest_configure(config) -> None:
    """Validate configuration before tests run (before VMs are started)."""
    # Configure logging to use UTC timestamps
    import time

    # Set all formatters to use UTC time
    logging.Formatter.converter = time.gmtime

    # Update existing handlers to use the UTC formatter
    for handler in logging.root.handlers:
        if handler.formatter:
            handler.formatter.converter = time.gmtime

    # Configure logging to ensure timestamps are in UTC
    for logger_name in [""]:  # root logger and all
        logger_obj = logging.getLogger(logger_name)
        logger_obj.propagate = True

    # Validate that every topology's per-node package globs resolve to real
    # .deb files before spinning up VMs. Discovery is best-effort (it mirrors
    # the topology_path fixture); anything missed here still fails cleanly in
    # the install_user_packages fixture.
    pkg_dir_override = config.getoption("--package-dir", default=None)
    feature = config.getoption("--feature", default="vanilla")
    errors = []
    for topo_path in _discover_topology_files(config):
        try:
            topo = TopologyParser.load(str(topo_path))
            _resolve_node_packages(topo, topo_path, pkg_dir_override, feature)
        except Exception as e:
            errors.append(str(e))

    if errors:
        raise pytest.UsageError("\n".join(errors))


def _discover_topology_files(config) -> list:
    """Find <suite>/<suite>.yaml topologies for the given test args."""
    found = []
    for arg in config.args:
        path = Path(str(arg).split("::")[0])
        test_dir = path if path.is_dir() else path.parent
        topo_path = (test_dir / f"{test_dir.resolve().name}.yaml").resolve()
        if topo_path.is_file() and topo_path not in found:
            found.append(topo_path)
    return found


def pytest_sessionstart(session) -> None:
    """Set up logging with UTC timestamps after pytest initialization."""
    import time
    import sys

    # Ensure all formatters use UTC time
    logging.Formatter.converter = time.gmtime

    # Remove ALL existing handlers to prevent duplicates
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[
        :
    ]:  # Copy the list to avoid modification issues
        root_logger.removeHandler(handler)

    # Add our own colored console handler with timestamps
    console_handler = logging.StreamHandler(sys.stderr)

    # Color mapping for log levels
    class ColoredFormatter(logging.Formatter):
        COLORS = {
            "DEBUG": "\033[36m",  # Cyan
            "INFO": "\033[32m",  # Green
            "WARNING": "\033[33m",  # Yellow
            "ERROR": "\033[31m",  # Red
            "CRITICAL": "\033[35m",  # Magenta
        }
        RESET = "\033[0m"

        def format(self, record):
            # Add color to level name
            levelname = record.levelname
            if levelname in self.COLORS:
                colored_level = f"{self.COLORS[levelname]}{levelname}{self.RESET}"
                record.levelname = colored_level

            # Use UTC time
            self.converter = time.gmtime
            return super().format(record)

    formatter = ColoredFormatter(
        fmt="%(asctime)s.%(msecs)03d %(levelname)-5s %(name)s:%(filename)s:%(lineno)d %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.INFO)

    # Add to root logger
    root_logger.addHandler(console_handler)
    root_logger.setLevel(logging.INFO)


def pytest_runtest_makereport(item, call) -> None:
    """Track test failures."""
    global _test_failed
    if call.when == "call" and call.excinfo is not None:
        _test_failed = True


def pytest_enter_pdb(config, pdb) -> None:
    """Called when entering PDB debugger - print connection info."""
    global _current_topology
    if _current_topology is not None:
        print("\n" + "=" * 60)
        print("⚠ ENTERING PDB - TOPOLOGY IS STILL RUNNING")
        print("=" * 60)
        print("SSH access to nodes:")
        for idx, node in enumerate(_current_topology.nodes):
            ssh_port: int = 2200 + idx
            print(f"  {node.name}: ssh -p {ssh_port} netsim@localhost")
        print("=" * 60 + "\n")


@pytest.fixture(scope="package")
def topology_path(request) -> Path:
    """
    Get discovered topology path for the current test module.

    Automatically discovered from test subdirectory name.
    Example: tests/two-node-topology/ -> tests/two-node-topology/two-node-topology.yaml
    """
    # Get the test file's directory
    test_file = Path(request.fspath)
    test_dir: Path = test_file.parent

    # Look for topology file in the test directory
    topo_name: str = test_dir.name
    topo_path: Path = test_dir / f"{topo_name}.yaml"

    if topo_path.exists():
        logger.info(f"Discovered topology for {test_file.name}: {topo_path}")
        return topo_path

    raise ValueError(f"No topology file found at {topo_path}")


@pytest.fixture(scope="package")
def topology(topology_path: Path) -> Topology:
    """Load topology from YAML."""
    return TopologyParser.load(str(topology_path))


@pytest.fixture(scope="package", autouse=True)
def running_topology(topology, request) -> Generator[TopologySimulator, Any, None]:
    """
    Auto-start topology for test module, clean up after.

    Package-scoped with autouse=True to ensure topology runs for all tests in a package.
    Each test package (directory with __init__.py) gets its own topology instance,
    preventing OOM from multiple topologies accumulating.

    The topology is started once per package and destroyed after that package's tests complete.
    Tests within the same package share the same running topology instance.
    """
    global _current_topology
    _current_topology = topology

    logger.info("=" * 60)
    logger.info(f"Starting topology for test package: {topology.name}")
    logger.info(f"Topology fixture ID: {id(topology)}")
    logger.info("=" * 60)

    with tempfile.TemporaryDirectory(prefix="netsim-test-") as runtime_dir:
        enable_tpm: bool = request.config.getoption("--tpm")
        simulator = TopologySimulator(
            topology, runtime_dir=runtime_dir, enable_tpm=enable_tpm
        )

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
                # Clear global topology reference
                _current_topology = None

                # Explicitly clear all references
                simulator.vms.clear()
                simulator.bridges.clear()
                simulator.tap_devices.clear()
                simulator.node_interfaces.clear()
                del simulator

                # Force garbage collection to free VM memory
                import gc

                gc.collect()


@pytest.fixture(scope="package")
def node_allocations(topology) -> Dict[str, Dict[str, Dict[str, str | None]]]:
    """
    Get auto-allocated IPv4 and IPv6 addresses for each node.

    Returns:
        Dict mapping node_name -> {network_name: {"ipv4": "10.0.1.10/24", "ipv6": "2001:db8:1::10/64" or None}, ...}
    """
    # Simulate the allocation process without running setup()
    allocations: Dict[str, Dict[str, Dict[str, str | None]]] = {}
    net_allocators: Dict[str, Dict[str, Dict[str, Any] | None]] = {}

    import ipaddress

    def _alloc_ip(net: ipaddress._BaseNetwork, idx: int) -> str:
        """Deterministically allocate the idx-th usable host in the network.

        Avoids materializing the full host list (which is impossible for /64 IPv6).
        idx=0 corresponds to the first usable host (network+1).
        """
        first_host: int = int(net.network_address) + 1  # skip network address
        # IPv4: exclude broadcast; IPv6: no broadcast, so allow all after network
        last_host: int
        if isinstance(net, ipaddress.IPv4Network):
            last_host = int(net.broadcast_address) - 1
        else:
            last_host = int(net.network_address) + net.num_addresses - 1

        candidate: int = first_host + idx
        if candidate > last_host:
            raise ValueError(f"IP pool exhausted for network {net} (idx={idx})")

        return f"{ipaddress.ip_address(candidate)}/{net.prefixlen}"

    for node in topology.nodes:
        node_ifaces: Dict[str, Dict[str, str | None]] = {}

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
                ipv4_alloc = net_allocators[net_name]["ipv4"]
                if isinstance(ipv4_alloc, dict):
                    ipv4_alloc["current"] += 1
                ipv6_alloc = net_allocators[net_name]["ipv6"]
                if ipv6_alloc and isinstance(ipv6_alloc, dict):
                    ipv6_alloc["current"] += 1

            # Allocate IPv4 (without materializing host list)
            ipv4_entry = net_allocators[net_name]["ipv4"]
            if isinstance(ipv4_entry, dict):
                ipv4_obj: ipaddress._BaseNetwork = ipv4_entry["net"]
                ipv4_idx: int = ipv4_entry["current"]
                ipv4_cidr: str = _alloc_ip(ipv4_obj, ipv4_idx)
            else:
                continue

            # Allocate IPv6 if available
            ipv6_cidr: str | None = None
            ipv6_entry = net_allocators[net_name]["ipv6"]
            if ipv6_entry and isinstance(ipv6_entry, dict):
                ipv6_obj: ipaddress._BaseNetwork = ipv6_entry["net"]
                ipv6_idx: int = ipv6_entry["current"]
                ipv6_cidr = _alloc_ip(ipv6_obj, ipv6_idx)

            node_ifaces[net_name] = {
                "ipv4": ipv4_cidr,
                "ipv6": ipv6_cidr,
            }

        allocations[node.name] = node_ifaces

    return allocations


@pytest.fixture(scope="package")
def install_packages(nodes, apt_updated) -> Callable[..., None]:
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
        cache_key: tuple[str, tuple[str, ...]] = (node_name, tuple(sorted(packages)))
        if cache_key in installed_cache:
            logger.debug(f"{node_name}: packages {packages} already installed")
            return

        node = nodes[node_name]
        package_list: str = " ".join(packages)

        logger.info(f"{node_name}: installing packages: {package_list}")

        try:
            # Install packages (non-interactive, with dpkg lock avoidance)
            node.ssh_command(
                f"sudo DEBIAN_FRONTEND=noninteractive apt install -y -qq {package_list}",
                timeout=180,
            )

            installed_cache[cache_key] = True
            logger.info(f"✓ {node_name}: packages installed: {package_list}")

        except subprocess.CalledProcessError as e:
            logger.error(f"✗ {node_name}: failed to install {package_list}")
            logger.error(f"  Stderr: {e.stderr if e.stderr else 'none'}")
            raise RuntimeError(f"Package installation failed on {node_name}: {e}")

    return _install


def _build_netplan_config(
    node_name: str,
    ifaces: dict[str, NodeInterface],
    node_allocations: dict[str, dict[str, dict[str, str | None]]],
    mgmt_interface: str,
) -> dict[str, Any]:
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
    node_name: str,
    ifaces: dict[str, NodeInterface],
    netplan_yaml: str,
    node: Node,
    mgmt_interface: str,
) -> None:
    """Apply netplan configuration to a single node."""
    try:
        # Create temporary file with config locally
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(netplan_yaml)
            temp_path: str = f.name

        # Copy to node
        scp_cmd: list[str] = [
            "scp",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-P",
            str(node.ssh_port),
            temp_path,
            "netsim@localhost:/tmp/netsim.yaml",
        ]
        subprocess.run(scp_cmd, check=True, capture_output=True, timeout=10)

        # Ensure netplan directory exists and apply with sudo
        node.ssh_command("sudo mkdir -p /etc/netplan")
        node.ssh_command("sudo cp /tmp/netsim.yaml /etc/netplan/99-netsim.yaml")
        node.ssh_command("sudo chmod 600 /etc/netplan/99-netsim.yaml")

        # Show what we're applying
        logger.debug(f"{node_name} netplan config:\n{netplan_yaml}")

        # Apply netplan
        result = node.ssh_command("sudo netplan apply 2>&1")
        if result:
            logger.debug(f"{node_name} netplan output: {result}")

        logger.info(f"✓ {node_name}: netplan configuration applied")

        # Wait for every interface to have its expected addresses.
        #
        # Three cases handled:
        #   1. Static IPv4 on data interfaces — should appear quickly but
        #      confirm rather than sleep-and-hope.
        #   2. Static IPv6 on data interfaces — DAD can take 1-2 seconds.
        #   3. DHCP IPv4 on the management interface — dhclient runs
        #      asynchronously after netplan apply returns.

        class AddressNotReady(Exception):
            pass

        def _wait_for_static_ipv4(if_name: str, expected_addr: str) -> None:
            addr: str = expected_addr.split("/")[0]

            @retry(
                stop=stop_after_attempt(15),
                wait=wait_fixed(1),
                retry=retry_if_exception_type(AddressNotReady),
                reraise=True,
            )
            def _check() -> None:
                out = node.ssh_command(
                    f"ip -4 addr show dev {if_name} 2>/dev/null"
                    f" | awk '/inet / {{print $2}}' | cut -d/ -f1",
                    timeout=5,
                ).strip()
                if addr in out.splitlines():
                    logger.debug(f"{node_name} {if_name}: IPv4 {addr} ready")
                    return
                raise AddressNotReady(f"{addr} not on {if_name} yet")

            try:
                _check()
            except AddressNotReady:
                logger.warning(
                    f"{node_name} {if_name}: IPv4 {addr} not ready after retries"
                )

        def _wait_for_static_ipv6(if_name: str, expected_addr: str) -> None:
            addr: str = expected_addr.split("/")[0]

            @retry(
                stop=stop_after_attempt(15),
                wait=wait_fixed(0.5),
                retry=retry_if_exception_type(AddressNotReady),
                reraise=True,
            )
            def _check() -> None:
                out = node.ssh_command(
                    f"ip -6 addr show dev {if_name} | grep 'inet6' | grep -v 'fe80'",
                    timeout=5,
                )
                if not out or addr not in out:
                    raise AddressNotReady(f"{addr} not on {if_name} yet")
                if "tentative" in out:
                    logger.debug(f"{node_name} {if_name}: IPv6 {addr} tentative (DAD)")
                    raise AddressNotReady(f"{addr} tentative on {if_name}")
                logger.debug(f"{node_name} {if_name}: IPv6 {addr} ready")

            try:
                _check()
            except AddressNotReady:
                logger.warning(
                    f"{node_name} {if_name}: IPv6 {addr} not ready after retries"
                )

        def _wait_for_dhcp_ipv4(if_name: str) -> None:
            @retry(
                stop=stop_after_attempt(15),
                wait=wait_fixed(2),
                retry=retry_if_exception_type(AddressNotReady),
                reraise=True,
            )
            def _check() -> None:
                out = node.ssh_command(
                    f"ip -4 addr show dev {if_name} 2>/dev/null"
                    f" | awk '/inet / {{print $2}}' | cut -d/ -f1",
                    timeout=5,
                ).strip()
                for addr_str in out.splitlines():
                    if addr_str and not addr_str.startswith("169.254."):
                        logger.debug(
                            f"{node_name} {if_name}: DHCP address {addr_str} ready"
                        )
                        return
                raise AddressNotReady(f"No DHCP address on {if_name} yet")

            try:
                _check()
            except AddressNotReady:
                logger.warning(
                    f"{node_name} {if_name}: DHCP address not ready after retries"
                )

        # Data interfaces: wait for static IPv4 and IPv6
        for net_name, iface in ifaces.items():
            if iface.ipv4_addr:
                _wait_for_static_ipv4(iface.if_name, iface.ipv4_addr)
            if iface.ipv6_addr:
                _wait_for_static_ipv6(iface.if_name, iface.ipv6_addr)

        # Management interface: wait for DHCP
        _wait_for_dhcp_ipv4(mgmt_interface)

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


@pytest.fixture(scope="package")
def configure_node_interfaces(
    node_interfaces, node_allocations, nodes, install_user_packages
) -> None:
    """
    Fixture that configures all node interfaces with netplan in parallel.

    Depends on node_interfaces (which depends on running_topology).
    Also depends on install_user_packages to ensure user packages are installed before configuration.

    Usage in tests:
        def test_example(configure_node_interfaces):
            # Interfaces are now configured
            pass
    """
    logger.info("=" * 60)
    logger.info("Configuring node interfaces with netplan (in parallel)")
    logger.info("=" * 60)

    def _configure_node(node_name: str, ifaces: dict[str, NodeInterface]) -> None:
        """Configure a single node's interfaces."""
        iface_configs = node_allocations[node_name]
        node = nodes[node_name]

        # Skip if no data interfaces
        if len(iface_configs) == 0:
            logger.info(f"{node_name}: no data interfaces to configure")
            return

        logger.info(f"Configuring {len(iface_configs)} interface(s) for {node_name}")

        # Discover management interface (first interface)
        output = node.ssh_command(
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
                addr_info: str = ", ".join(addr_parts)
                logger.info(
                    f"  [{node_name}] {node_iface.if_name} ({net_name}): {addr_info}"
                )

        netplan_yaml: str = yaml.dump(netplan_config, default_flow_style=False)
        _apply_netplan_to_node(node_name, ifaces, netplan_yaml, node, mgmt_interface)

    # Configure all nodes in parallel
    run_parallel_simple(
        _configure_node,
        [(node_name, ifaces) for node_name, ifaces in node_interfaces.items()],
    )

    # Brief settling time after parallel configuration to ensure all
    # interfaces are fully ready across all nodes (IPv6 DAD, neighbor discovery, etc.)

    time.sleep(2)

    logger.info("=" * 60)
    logger.info("✓ All interfaces configured")
    logger.info("=" * 60)


@pytest.fixture(scope="package")
def node_ssh_port(topology) -> Callable[[str], int]:
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


@pytest.fixture(scope="package")
def nodes(topology) -> Dict[str, Node]:
    """
    Get Node objects for all nodes in the topology.

    Returns:
        Dict mapping node_name -> Node object with SSH access
    """
    node_objects = {}
    for idx, topo_node in enumerate(topology.nodes):
        node = Node(
            name=topo_node.name,
            ssh_port=2200 + idx,
            topology=topology,
        )
        node_objects[topo_node.name] = node
    return node_objects


@pytest.fixture(scope="package")
def apt_updated(nodes) -> None:
    """
    Run 'apt-get update' once per node for the lifetime of the topology.

    All nodes are updated in parallel. Subsequent fixtures that install packages
    depend on this fixture to ensure the package index is current before any
    installation attempts.
    """

    def _update_node(node_name, node) -> None:
        logger.info(f"  [{node_name}] Running apt-get update...")
        node.ssh_command("sudo apt-get update -qq", timeout=600)
        logger.info(f"  [{node_name}] ✓ apt-get update complete")

    run_parallel_simple(
        _update_node,
        [(node_name, node) for node_name, node in nodes.items()],
    )


# Debug-symbol and -dev/-doc packages we never want pulled into a test VM,
# even if a package glob accidentally matches them.
_PKG_EXCLUDE_SUFFIXES = ("-dbgsym", "-dev", "-doc")


def _pkg_excluded(filename: str) -> bool:
    return filename.split("_")[0].endswith(_PKG_EXCLUDE_SUFFIXES)


def _resolve_node_packages(
    topology: Topology,
    topology_path,
    package_dir_override: str | None = None,
    feature: str = "vanilla",
) -> Dict[str, list[Path]]:
    """
    Resolve each node's package globs to concrete .deb paths.

    Globs come from the per-node 'packages' entry in the topology YAML —
    either a flat feature-agnostic list, or the per-feature nested form
    ('packages: features: {...}') from which the set named by --feature is
    selected. Globs are resolved against the package directory
    (--package-dir overrides the topology's 'package_dir'; a relative
    directory resolves against the YAML's location). dbgsym/dev/doc packages
    are never matched, and when several .debs match one glob (e.g. stale
    versions) the newest wins.

    Raises ValueError on a missing package directory, an unmatched glob, or
    a feature the node does not declare.
    """
    if not any(node.has_packages for node in topology.nodes):
        return {}

    if package_dir_override:
        # CLI-supplied: relative to the invocation directory
        pkg_dir = Path(package_dir_override).resolve()
    elif topology.package_dir:
        # From the YAML: relative to the YAML's directory
        pkg_dir = Path(topology.package_dir)
        if not pkg_dir.is_absolute():
            pkg_dir = (Path(topology_path).parent / pkg_dir).resolve()
    else:
        raise ValueError(
            f"{topology_path}: nodes declare 'packages' but no package "
            "directory is set (add 'package_dir' to the topology or pass "
            "--package-dir)"
        )
    if not pkg_dir.is_dir():
        raise ValueError(f"{topology_path}: package directory not found: {pkg_dir}")

    resolved: Dict[str, list[Path]] = {}
    for node in topology.nodes:
        try:
            node_globs = node.packages_for(feature)
        except ValueError as e:
            raise ValueError(f"{topology_path}: {e}") from e
        paths: list[Path] = []
        for pattern in node_globs:
            matches = [
                p
                for p in pkg_dir.glob(pattern)
                if p.name.endswith(".deb") and not _pkg_excluded(p.name)
            ]
            if not matches:
                raise ValueError(
                    f"{topology_path}: node '{node.name}': no .deb in "
                    f"{pkg_dir} matches '{pattern}'"
                )
            paths.append(max(matches, key=lambda p: p.stat().st_mtime))
        if paths:
            resolved[node.name] = paths
    return resolved


@pytest.fixture(scope="package")
def install_user_packages(topology, topology_path, nodes, apt_updated, request) -> None:
    """
    Install each node's debian packages as declared in the topology YAML.

    Per-node 'packages' globs are resolved against the topology's
    'package_dir' (or --package-dir) and installed with apt, which resolves
    any declared dependencies automatically. Nodes without a 'packages' list
    get nothing installed. Fails the test if any package installation fails.
    """
    feature = request.config.getoption("--feature")
    try:
        node_packages = _resolve_node_packages(
            topology,
            topology_path,
            request.config.getoption("--package-dir"),
            feature,
        )
    except ValueError as e:
        pytest.fail(str(e))

    if not node_packages:
        logger.debug("No packages declared in topology; nothing to install")
        return

    logger.info("=" * 60)
    logger.info(
        f"Installing packages (feature: {feature}): "
        + "; ".join(
            f"{name}: {', '.join(p.name for p in pkgs)}"
            for name, pkgs in node_packages.items()
        )
    )
    logger.info("=" * 60)

    def _install_packages_on_node(node_name, node) -> None:
        """Install this node's packages."""
        for pkg_path in node_packages[node_name]:
            pkg_name: str = pkg_path.name

            logger.info(f"  [{node_name}] Copying {pkg_name}...")

            # Copy package to node
            try:
                remote_path = node.copy_file(str(pkg_path))
            except FileNotFoundError as e:
                pytest.fail(str(e))
            except subprocess.CalledProcessError as e:
                error_msg: Any | str = e.stderr if e.stderr else "Unknown error"
                pytest.fail(f"Failed to copy {pkg_name} to {node_name}: {error_msg}")

            logger.info(f"  [{node_name}] Installing {pkg_name}...")

            # Diagnostics: show anything holding the dpkg lock and any
            # stale apt/dpkg processes left over from a previous run.
            try:
                lock_info = node.ssh_command(
                    "sudo lsof /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock "
                    "/var/cache/apt/archives/lock 2>/dev/null || true",
                    timeout=15,
                )
                if lock_info.strip():
                    logger.warning(f"  [{node_name}] dpkg locks held:\n{lock_info}")
                apt_procs = node.ssh_command(
                    "ps -eo pid,comm,args | grep -E '(apt|dpkg)' | grep -v grep || true",
                    timeout=15,
                )
                if apt_procs.strip():
                    logger.warning(
                        f"  [{node_name}] running apt/dpkg processes:\n{apt_procs}"
                    )
            except Exception as e:
                logger.debug(f"  [{node_name}] diagnostics failed: {e}")

            # Kill any stale apt/dpkg processes so they cannot hold the lock.
            # pkill takes a single ERE pattern; -x anchors it to the whole
            # process name.
            try:
                node.ssh_command(
                    "sudo pkill -9 -x 'apt|apt-get|dpkg' 2>/dev/null || true",
                    timeout=10,
                )
            except Exception:
                pass

            # Repair any interrupted dpkg state before installing.
            try:
                node.ssh_command(
                    "sudo DEBIAN_FRONTEND=noninteractive dpkg --configure -a 2>&1 || true",
                    timeout=120,
                )
            except Exception as e:
                logger.debug(f"  [{node_name}] dpkg --configure -a: {e}")

            install_output = node.ssh_command(
                f"sudo DEBIAN_FRONTEND=noninteractive apt install --fix-broken -y {remote_path} 2>&1",
                timeout=600,
            )
            logger.debug(f"  [{node_name}] apt output: {install_output}")

            logger.info(f"  [{node_name}] ✓ {pkg_name} installed successfully")

            # Clean up the package file
            node.ssh_command(f"rm -f {remote_path}")

    # Install packages on the declaring nodes in parallel
    run_parallel_simple(
        _install_packages_on_node,
        [(node_name, nodes[node_name]) for node_name in node_packages],
    )

    logger.info("=" * 60)
    logger.info("✓ All packages installed")
    logger.info("=" * 60)


def _discover_interface_names(node_name: str, node: Node) -> list[str]:
    """Discover interface names on a node via SSH."""
    output = node.ssh_command(
        "ip -o link show | grep -v ' lo:' | awk -F': ' '{print $2}'"
    )
    all_if_names = [name.strip() for name in output.split("\n") if name.strip()]

    # Filter out @NONE suffixes
    if_names = [
        name.split("@")[0] for name in all_if_names if not name.startswith("lo")
    ]

    logger.info(f"{node_name}: discovered interfaces: {if_names}")
    return if_names


def _map_networks_to_interfaces(
    node_name: str,
    if_names: list[str],
    node_allocations: dict[str, dict[str, dict[str, str | None]]],
    node: Node,
    topology=None,
) -> dict[str, NodeInterface]:
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
        if_idx: int = config_idx + 1
        if if_idx < len(if_names):
            if_name = if_names[if_idx]
            ipv4_addr = addrs.get("ipv4")
            ipv6_addr = addrs.get("ipv6")
            network_obj = topology.get_network(net_name) if topology else None
            iface = NodeInterface(
                node_name,
                if_name,
                net_name,
                node.ssh_port,
                node,
                ipv4_addr=ipv4_addr,
                ipv6_addr=ipv6_addr,
                network=network_obj,
            )
            node_ifaces[net_name] = iface
            node.add_interface(iface)
            addr_info = ipv4_addr if ipv4_addr else ""
            if ipv6_addr:
                addr_info = f"{ipv4_addr}, {ipv6_addr}" if ipv4_addr else ipv6_addr
            logger.info(f"{node_name}: {if_name} -> {net_name} ({addr_info})")
        config_idx += 1

    return node_ifaces


@pytest.fixture(scope="package")
def node_interfaces(running_topology, topology, node_allocations, nodes):
    """
    Discover interfaces on each node and map to networks.

    Note: VMs have management interface (user-mode NAT) as first interface,
    followed by data interfaces (tap devices). We skip the management interface.

    Returns:
        Dict[str, Dict[str, NodeInterface]] - node_name -> {network_name: NodeInterface}
    """
    interfaces = {}

    for idx, topo_node in enumerate(topology.nodes):
        node_name = topo_node.name
        node = nodes[node_name]

        # Discover interface names
        if_names = _discover_interface_names(node_name, node)

        # Map networks to interfaces
        node_ifaces = _map_networks_to_interfaces(
            node_name, if_names, node_allocations, node, topology
        )

        interfaces[node_name] = node_ifaces

    return interfaces


# ============================================================================
# Session-scoped setup and cleanup
# ============================================================================


@pytest.fixture(scope="session", autouse=True)
def libvirt_preflight() -> None:
    """Abort the test session early if the libvirt daemon is unresponsive.

    Without this gate, a wedged libvirtd makes later fixtures block forever
    inside ``libvirt.open()``. With it, pytest exits with an actionable
    message before any VMs are touched.
    """
    uri: str = os.environ.get("NETSIM_LIBVIRT_URI", "qemu:///system")
    libvirt_utils.preflight(uri)


@pytest.fixture(scope="session", autouse=True)
def cleanup_ssh_connections() -> Generator[None, Any, None]:
    """
    Cleanup SSH connections at the end of the test session.

    This fixture runs automatically and closes all persistent SSH
    connections created by the Node class using paramiko.
    """
    yield
    # Teardown: close all SSH connections
    logger.info("Closing all persistent SSH connections...")
    Node.close_all_connections()
    logger.info("✓ SSH connections closed")
