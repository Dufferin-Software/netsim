"""
Topology definition and parsing from YAML.
"""

import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Union


@dataclass
class Network:
    """Represents a network segment connecting nodes."""
    name: str
    subnet: str  # e.g., "10.0.1.0/24"
    mtu: int = 1500


@dataclass
class NodeInterface:
    """Network interface configuration for a node."""
    name: str
    network: str  # reference to network name
    ip: str  # IP address for this interface


@dataclass
class Node:
    """Represents a VM node in the topology."""
    name: str
    image: Union[str, Dict[str, Any]]  # Either a path or {name, url, checksum} reference
    memory: int = 512  # MB
    vcpus: int = 1
    interfaces: List[NodeInterface] = field(default_factory=list)


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
            networks.append(Network(
                name=net_data["name"],
                subnet=net_data["subnet"],
                mtu=net_data.get("mtu", 1500)
            ))

        # Parse nodes
        nodes = []
        for node_data in data.get("nodes", []):
            interfaces = []
            for iface_data in node_data.get("interfaces", []):
                interfaces.append(NodeInterface(
                    name=iface_data["name"],
                    network=iface_data["network"],
                    ip=iface_data["ip"]
                ))

            nodes.append(Node(
                name=node_data["name"],
                image=node_data["image"],
                memory=node_data.get("memory", 512),
                vcpus=node_data.get("vcpus", 1),
                interfaces=interfaces
            ))

        # Validate topology
        TopologyParser._validate(networks, nodes)

        return Topology(
            name=data.get("name", "default"),
            version=data.get("version", "1.0"),
            nodes=nodes,
            networks=networks
        )

    @staticmethod
    def _validate(networks: List[Network], nodes: List[Node]) -> None:
        """Validate topology consistency."""
        network_names = {n.name for n in networks}

        for node in nodes:
            for iface in node.interfaces:
                if iface.network not in network_names:
                    raise ValueError(
                        f"Node {node.name} references unknown network {iface.network}"
                    )
