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


@dataclass
class Topology:
    """Complete network topology definition."""

    name: str
    version: str = "1.0"
    nodes: List[Node] = field(default_factory=list)
    networks: List[Network] = field(default_factory=list)

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
        networks = []
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
        nodes = []
        for node_data in data.get("nodes", []):
            # Get list of network names this node connects to
            node_networks = node_data.get("networks", [])

            nodes.append(
                Node(
                    name=node_data["name"],
                    image=node_data["image"],
                    memory=node_data.get("memory", 512),
                    vcpus=node_data.get("vcpus", 1),
                    networks=node_networks,
                )
            )

        # Validate topology
        TopologyParser._validate(networks, nodes)

        return Topology(
            name=data.get("name", "default"),
            version=data.get("version", "1.0"),
            nodes=nodes,
            networks=networks,
        )

    @staticmethod
    def _validate(networks: List[Network], nodes: List[Node]) -> None:
        """Validate topology consistency."""
        network_names = {n.name for n in networks}

        for node in nodes:
            for net_name in node.networks:
                if net_name not in network_names:
                    raise ValueError(
                        f"Node {node.name} references unknown network {net_name}"
                    )
