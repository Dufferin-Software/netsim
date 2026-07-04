# Copyright (c) Dufferin Software

"""
Topology definition and parsing from YAML.
"""

import yaml
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Union


@dataclass
class Network:
    """Represents a network segment connecting nodes."""

    name: str
    subnet: str  # e.g., "10.0.1.0/24"
    mtu: int = 1500
    ipv6_subnet: Optional[str] = None  # e.g., "2001:db8:1::/64"


@dataclass
class Node:
    """Represents a VM node in the topology."""

    name: str
    image: Union[
        str, Dict[str, Any]
    ]  # Either a path or {name, url, checksum} reference
    memory: int = 512  # MB
    vcpus: int = 1
    networks: List[str] = field(
        default_factory=list
    )  # List of network names; first is mgmt
    packages: List[str] = field(
        default_factory=list
    )  # Debian package globs (resolved against Topology.package_dir)


@dataclass
class Topology:
    """Complete network topology definition."""

    name: str
    version: str = "1.0"
    nodes: List[Node] = field(default_factory=list)
    networks: List[Network] = field(default_factory=list)
    # Directory containing the .deb packages referenced by Node.packages.
    # Relative paths are resolved against the topology YAML's directory.
    package_dir: Optional[str] = None

    def get_node(self, name: str) -> Optional[Node]:
        """Get a node by name."""
        return next((n for n in self.nodes if n.name == name), None)

    def get_network(self, name: str) -> Optional[Network]:
        """Get a network by name."""
        return next((n for n in self.networks if n.name == name), None)


class TopologyParser:
    """Parse and validate topology YAML files."""

    @staticmethod
    def load(yaml_path: str) -> Topology:
        """Load topology from YAML file."""
        with open(yaml_path, "r") as f:
            data = yaml.safe_load(f)

        if not data:
            raise ValueError("Empty topology file")

        return TopologyParser._parse(data)

    @staticmethod
    def _parse(data: Dict[str, Any]) -> Topology:
        """Parse topology dictionary."""
        # Parse networks
        networks: List[Network] = []
        for net_data in data.get("networks", []):
            networks.append(
                Network(
                    name=net_data["name"],
                    subnet=net_data["subnet"],
                    mtu=net_data.get("mtu", 1500),
                    ipv6_subnet=net_data.get("ipv6_subnet"),
                )
            )

        # Parse nodes
        nodes: List[Node] = []
        for node_data in data.get("nodes", []):
            # Get list of network names this node connects to
            node_networks: List[str] = node_data.get("networks", [])

            node_packages = node_data.get("packages", [])
            if not isinstance(node_packages, list) or not all(
                isinstance(p, str) for p in node_packages
            ):
                raise ValueError(
                    f"Node {node_data['name']}: 'packages' must be a list of "
                    "package filename globs"
                )

            nodes.append(
                Node(
                    name=node_data["name"],
                    image=node_data["image"],
                    memory=node_data.get("memory", 512),
                    vcpus=node_data.get("vcpus", 1),
                    networks=node_networks,
                    packages=node_packages,
                )
            )

        # Validate topology
        TopologyParser._validate(networks, nodes)

        return Topology(
            name=data.get("name", "default"),
            version=data.get("version", "1.0"),
            nodes=nodes,
            networks=networks,
            package_dir=data.get("package_dir"),
        )

    @staticmethod
    def _validate(networks: List[Network], nodes: List[Node]) -> None:
        """Validate topology consistency."""
        # Duplicate names cause silent collisions downstream (IPs, libvirt
        # domain names, bridges), so reject them up front.
        seen_networks: set[str] = set()
        for net in networks:
            if net.name in seen_networks:
                raise ValueError(f"Duplicate network name: {net.name}")
            seen_networks.add(net.name)

        seen_nodes: set[str] = set()
        for node in nodes:
            if node.name in seen_nodes:
                raise ValueError(f"Duplicate node name: {node.name}")
            seen_nodes.add(node.name)

        for node in nodes:
            for net_name in node.networks:
                if net_name not in seen_networks:
                    raise ValueError(
                        f"Node {node.name} references unknown network {net_name}"
                    )
