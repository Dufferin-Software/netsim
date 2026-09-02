# Copyright (c) Peter Morrow

"""
Main topology simulator orchestrating VMs and networks.
"""

import logging
import shutil
from subprocess import CompletedProcess
import yaml
import ipaddress
from typing import Dict, Optional, List, Tuple
from pathlib import Path

from netsim.topology import Network, Topology
from netsim.vm import LibvirtVM, VMConfig
from netsim.network import NetworkManager
from netsim.images import ImageManager

logger: logging.Logger = logging.getLogger(__name__)


class TopologySimulator:
    """Orchestrate a network topology of KVM/QEMU VMs via libvirt."""

    def __init__(
        self,
        topology: Topology,
        runtime_dir: str = "/tmp/netsim",
        image_cache_dir: Optional[str] = None,
        enable_tpm: bool = True,
    ) -> None:
        """
        Initialize simulator.

        Args:
            topology: Parsed topology definition
            runtime_dir: Directory for VM runtime data
            image_cache_dir: Directory for image caching. Defaults to ~/.netsim/images
            enable_tpm: Attach an emulated TPM 2.0 (via swtpm) to each VM
        """
        self.topology: Topology = topology
        self.runtime_dir: str = runtime_dir
        self.enable_tpm: bool = enable_tpm
        self.image_manager = ImageManager(cache_dir=image_cache_dir)
        self.vms: Dict[str, LibvirtVM] = {}
        self.tap_devices: Dict[
            Tuple[str, int], str
        ] = {}  # Maps (node_name, iface_idx) -> tap_name
        self.node_interfaces: Dict[
            str, List[Tuple[str, str]]
        ] = {}  # Maps node_name -> [(net_name, ip_cidr), ...]
        self.bridges: Dict[str, str] = {}  # Maps network_name -> bridge_name
        self.net_allocators: Dict[
            str, ipaddress.IPv4Network
        ] = {}  # Track IP allocation per network
        self.net_alloc_indices: Dict[
            str, int
        ] = {}  # Track current allocation index per network

    def setup(self) -> None:
        """Setup topology: create bridges, tap devices, configure VMs."""
        logger.info(f"Setting up topology: {self.topology.name}")

        try:
            # Step 1: Create bridges and taps for networks
            self._setup_networks()

            # Step 2: Create and configure VMs
            self._setup_vms()

        except Exception as e:
            logger.error(f"Setup failed: {e}")
            self.cleanup()
            raise

    def _setup_networks(self) -> None:
        """Create bridges and tap interfaces for each network."""
        logger.info("Setting up networks...")

        for network in self.topology.networks:
            bridge_name: str = f"br-{network.name}"
            logger.debug(f"Creating bridge: {bridge_name}")

            NetworkManager.create_bridge(bridge_name, mtu=network.mtu)
            self.bridges[network.name] = bridge_name

            # Extract gateway IP from subnet (first usable address)
            subnet_parts: List[str] = network.subnet.split("/")
            subnet_ip: str = subnet_parts[0]
            prefix: str = subnet_parts[1] if len(subnet_parts) > 1 else "24"

            # Set bridge IP to gateway (.1)
            gateway_cidr: str = self._get_gateway_cidr(subnet_ip, prefix)
            logger.debug(f"Setting bridge IP: {gateway_cidr}")
            NetworkManager.set_bridge_ip(bridge_name, gateway_cidr)

    def _setup_vms(self) -> None:
        """Create and configure VM instances."""
        logger.info("Setting up VMs...")

        for idx, node in enumerate(self.topology.nodes):
            logger.debug(f"Creating VM: {node.name}")

            # Auto-allocate tap interfaces and IPs based on node.networks
            tap_devices = []
            node_ifaces = []  # List of (network_name, ip_cidr)

            for net_idx, net_name in enumerate(node.networks):
                # Generate tap name (use index-based naming to keep it under 15 chars)
                if_name: str = f"eth{net_idx}"
                # Zero-pad indices so tap names remain unique even with >9
                # nodes or >9 networks per node. f"tap{idx}{net_idx}" was
                # ambiguous (e.g. idx=1/net_idx=10 collided with idx=11/net_idx=0).
                tap_name: str = f"tap{idx:02d}{net_idx:02d}"
                logger.debug(f"Creating tap interface: {tap_name} for {net_name}")

                NetworkManager.create_tap(tap_name)

                # Add to appropriate bridge
                bridge_name: str = self.bridges[net_name]
                NetworkManager.bridge_tap(bridge_name, tap_name)

                tap_devices.append(tap_name)
                self.tap_devices[(node.name, net_idx)] = tap_name

                # Auto-allocate IP from network
                ip_cidr: str = self._allocate_ip(net_name)
                node_ifaces.append((net_name, ip_cidr))
                logger.debug(f"Allocated {if_name}: {ip_cidr} on {net_name}")

            self.node_interfaces[node.name] = node_ifaces

            # Resolve image path (may download from cache)
            logger.debug(f"Resolving image for {node.name}: {node.image}")
            image_path: str = self.image_manager.resolve_image(node.image)
            logger.info(f"Image resolved for {node.name}: {image_path}")

            # Generate per-node cloud-init ISO with hostname
            cloudinit_iso: str = self._get_or_generate_cloudinit_iso(node.name)

            # Create VM configuration
            vm_config = VMConfig(
                name=node.name,
                image_path=image_path,
                memory_mb=node.memory,
                vcpus=node.vcpus,
                tap_devices=tap_devices,
                mgmt_ssh_port=2200 + idx,
                cloudinit_iso=cloudinit_iso,
                enable_tpm=self.enable_tpm,
            )

            # Create VM instance
            vm = LibvirtVM(vm_config, runtime_dir=self.runtime_dir)
            self.vms[node.name] = vm

    def _get_or_generate_cloudinit_iso(self, hostname: str) -> str:
        """Generate or retrieve cached cloud-init ISO with netsim user, SSH key, and hostname.

        Args:
            hostname: Hostname to configure for the node

        Returns:
            Path to the cloud-init ISO file.
        """
        iso_cache_dir: Path = Path.home() / ".netsim" / "cloud-init"
        iso_cache_dir.mkdir(parents=True, exist_ok=True)
        iso_path: Path = iso_cache_dir / f"cloud-init-{hostname}.iso"

        if iso_path.exists():
            logger.debug(f"Using cached cloud-init ISO for {hostname}: {iso_path}")
            return str(iso_path)

        logger.info(f"Generating cloud-init ISO for {hostname}: {iso_path}")

        try:
            import subprocess
            import tempfile

            # Read SSH public key
            ssh_key_path: Path = Path.home() / ".ssh" / "id_rsa.pub"
            if not ssh_key_path.exists():
                raise RuntimeError(f"SSH key not found at {ssh_key_path}")

            ssh_key: str = ssh_key_path.read_text().strip()
            logger.debug(f"Using SSH key from {ssh_key_path}")

            # Create cloud-config YAML with hostname
            cloud_config = {
                "hostname": hostname,
                "fqdn": f"{hostname}.local",
                "manage_etc_hosts": True,
                "users": [
                    {
                        "name": "netsim",
                        "groups": ["sudo"],
                        "shell": "/bin/bash",
                        "sudo": ["ALL=(ALL) NOPASSWD:ALL"],
                        "ssh_authorized_keys": [ssh_key],
                    }
                ],
            }

            cloud_config_yaml: str = yaml.dump(cloud_config, default_flow_style=False)
            user_data: str = f"#cloud-config\n{cloud_config_yaml}"

            with tempfile.TemporaryDirectory() as tmpdir:
                tmpdir_path = Path(tmpdir)

                # Write cloud-init files
                user_data_path: Path = tmpdir_path / "user-data"
                user_data_path.write_text(user_data)

                meta_data_path: Path = tmpdir_path / "meta-data"
                meta_data_path.write_text("instance-id: netsim\n")

                # Generate ISO using genisoimage or mkisofs
                iso_tmp: Path = tmpdir_path / "cloud-init.iso"
                cmd: List[str] | None = None

                # Try genisoimage first, fall back to mkisofs
                for tool in ["genisoimage", "mkisofs"]:
                    try:
                        subprocess.run(["which", tool], check=True, capture_output=True)
                        cmd = [
                            tool,
                            "-output",
                            str(iso_tmp),
                            "-volid",
                            "cidata",
                            "-joliet",
                            "-rock",
                            str(user_data_path),
                            str(meta_data_path),
                        ]
                        break
                    except subprocess.CalledProcessError:
                        continue

                if not cmd:
                    raise RuntimeError(
                        "Neither genisoimage nor mkisofs found. Install one of: apt install genisoimage"
                    )

                subprocess.run(cmd, check=True, capture_output=True)

                # Make readable and move to cache
                subprocess.run(
                    ["sudo", "cp", str(iso_tmp), str(iso_path)],
                    check=True,
                    capture_output=True,
                )
                subprocess.run(
                    ["sudo", "chmod", "a+r", str(iso_path)],
                    capture_output=True,
                    timeout=5,
                )

            logger.info(f"Cloud-init ISO created and cached for {hostname}: {iso_path}")
            return str(iso_path)
        except Exception as e:
            logger.error(f"Failed to generate cloud-init ISO: {e}")
            raise

    def start(self) -> None:
        """Start all VMs."""
        logger.info("Starting VMs...")

        for node_name, vm in self.vms.items():
            logger.info(f"Starting VM: {node_name}")
            try:
                vm.start()
            except Exception as e:
                logger.error(f"Failed to start VM {node_name}: {e}")
                raise

    def stop(self) -> None:
        """Suspend all VMs."""
        logger.info("Suspending VMs...")

        for node_name, vm in self.vms.items():
            logger.info(f"Suspending VM: {node_name}")
            try:
                vm.stop()
            except Exception as e:
                logger.error(f"Failed to suspend VM {node_name}: {e}")

    def cleanup(self) -> None:
        """Clean up all resources: VMs, taps, bridges."""
        logger.info("Cleaning up topology...")

        # Destroy all VMs (not just stop)
        for node_name, vm in self.vms.items():
            logger.debug(f"Destroying VM: {node_name}")
            try:
                vm.destroy()
            except Exception as e:
                logger.warning(f"Failed to destroy VM {node_name}: {e}")

        # Delete tap interfaces
        for tap_name in self.tap_devices.values():
            logger.debug(f"Deleting tap: {tap_name}")
            try:
                NetworkManager.delete_tap(tap_name)
            except Exception as e:
                logger.warning(f"Failed to delete tap {tap_name}: {e}")

        # Delete bridges
        for bridge_name in self.bridges.values():
            logger.debug(f"Deleting bridge: {bridge_name}")
            try:
                NetworkManager.delete_bridge(bridge_name)
            except Exception as e:
                logger.warning(f"Failed to delete bridge {bridge_name}: {e}")

        logger.info("Cleanup complete")

    def destroy(self) -> None:
        """Fully tear down topology resources and remove runtime directory."""
        # Seed expected resources so cleanup removes them even if setup was never called
        if not self.bridges:
            for network in self.topology.networks:
                self.bridges[network.name] = f"br-{network.name}"

        if not self.tap_devices:
            for idx, node in enumerate(self.topology.nodes):
                for iface_idx in range(len(node.networks)):
                    tap_name: str = f"tap{idx}{iface_idx}"
                    self.tap_devices[(node.name, iface_idx)] = tap_name

        if not self.vms:
            for idx, node in enumerate(self.topology.nodes):
                image_path: str = ""
                if isinstance(node.image, str):
                    image_path = node.image
                elif isinstance(node.image, dict):
                    image_path = node.image.get("name", "")

                config = VMConfig(
                    name=node.name,
                    image_path=image_path,
                    tap_devices=[],
                    mgmt_ssh_port=2200 + idx,
                )
                self.vms[node.name] = LibvirtVM(config, runtime_dir=self.runtime_dir)

        self.cleanup()

        try:
            runtime_path = Path(self.runtime_dir)
            if runtime_path.exists():
                shutil.rmtree(runtime_path, ignore_errors=True)
        except Exception:
            pass

    def status(self) -> Dict[str, bool]:
        """Get status of all VMs in this topology.

        First checks self.vms (VMs loaded in memory), then queries libvirt
        for any VMs matching this topology's nodes.
        """
        status = {}

        # First, check VMs we know about in memory
        for name, vm in self.vms.items():
            status[name] = vm.is_running()

        # If no VMs in memory, query libvirt for VMs matching topology nodes
        if not status and self.topology.nodes:
            logger.debug("No VMs loaded in memory, querying libvirt...")
            import subprocess

            try:
                result: CompletedProcess[str] = subprocess.run(
                    ["virsh", "list", "--all", "--name"],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                existing_vms = (
                    set(result.stdout.strip().split("\n"))
                    if result.stdout.strip()
                    else set()
                )

                # Check which topology nodes exist in libvirt
                for node in self.topology.nodes:
                    if node.name in existing_vms:
                        # Query if it's running
                        try:
                            state_result: CompletedProcess[str] = subprocess.run(
                                ["virsh", "domstate", node.name],
                                capture_output=True,
                                text=True,
                                check=True,
                            )
                            is_running: bool = "running" in state_result.stdout.lower()
                            status[node.name] = is_running
                        except subprocess.CalledProcessError:
                            status[node.name] = False
                    else:
                        # VM doesn't exist in libvirt
                        status[node.name] = False

            except subprocess.CalledProcessError as e:
                logger.warning(f"Failed to query libvirt: {e}")

        return status

    def _get_gateway_cidr(self, subnet_ip: str, prefix: str) -> str:
        """Convert subnet to gateway IP with CIDR.

        Uses the first usable host in the subnet, which is correct for any
        prefix length. The previous implementation hard-coded the last octet
        to "1", which produced addresses outside the subnet for non-/24
        aligned subnets (e.g. 192.168.1.128/25 -> 192.168.1.1/25).
        """
        net: ipaddress.IPv4Network = ipaddress.IPv4Network(
            f"{subnet_ip}/{prefix}", strict=False
        )
        gateway: ipaddress.IPv4Address = next(iter(net.hosts()))
        return f"{gateway}/{prefix}"

    def _allocate_ip(self, net_name: str) -> str:
        """Allocate next IP address from a network.

        Gateway (.1) is reserved, IPs start from .10

        Args:
            net_name: Name of network

        Returns:
            IP address in CIDR notation (e.g., "10.0.1.10/24")
        """
        # Initialize allocator if not present
        if net_name not in self.net_allocators:
            network: Network | None = self.topology.get_network(net_name)
            if not network:
                raise ValueError(f"Unknown network: {net_name}")

            net: ipaddress.IPv4Network = ipaddress.IPv4Network(
                network.subnet, strict=False
            )
            self.net_allocators[net_name] = net

            # Start allocation from .10 (index 9, since hosts[0] is .1)
            # Skip .1 which is gateway, .2-.9 reserved
            self.net_alloc_indices[net_name] = 9
        else:
            self.net_alloc_indices[net_name] += 1

        net = self.net_allocators[net_name]
        alloc_idx: int = self.net_alloc_indices[net_name]

        # Generate IP address
        hosts: List[ipaddress.IPv4Address] = list(net.hosts())
        if alloc_idx >= len(hosts):
            raise ValueError(
                f"IP pool exhausted for network {net_name}. Subnet too small."
            )

        ip_addr: ipaddress.IPv4Address = hosts[alloc_idx]
        return f"{ip_addr}/{net.prefixlen}"
