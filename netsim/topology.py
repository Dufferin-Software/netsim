# Copyright (c) Peter Morrow

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
    )  # Feature-agnostic Debian package globs (resolved against
    # Topology.package_dir); installed regardless of the selected feature
    package_features: Dict[str, List[str]] = field(
        default_factory=dict
    )  # Feature name → package globs, from the nested
    # 'packages: features: {...}' form; exactly one of packages /
    # package_features is populated

    def packages_for(self, feature: str) -> List[str]:
        """
        Package globs to install for the given feature set.

        Nodes with a plain 'packages' list are feature-agnostic and return it
        unchanged.  Nodes with 'packages: features: {...}' must declare the
        requested feature explicitly — a missing entry is an error, not an
        empty install, so a typo'd --feature can't silently skip the engine.
        """
        if self.package_features:
            if feature not in self.package_features:
                available = ", ".join(sorted(self.package_features))
                raise ValueError(
                    f"Node {self.name}: no package set for feature "
                    f"'{feature}' (available: {available})"
                )
            return self.package_features[feature]
        return self.packages

    @property
    def has_packages(self) -> bool:
        """True if this node installs any packages (either form)."""
        return bool(self.packages or self.package_features)


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

            node_packages, node_package_features = TopologyParser._parse_packages(
                node_data["name"], node_data.get("packages", [])
            )

            nodes.append(
                Node(
                    name=node_data["name"],
                    image=node_data["image"],
                    memory=node_data.get("memory", 512),
                    vcpus=node_data.get("vcpus", 1),
                    networks=node_networks,
                    packages=node_packages,
                    package_features=node_package_features,
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
    def _parse_packages(
        node_name: str, raw: Any
    ) -> tuple[List[str], Dict[str, List[str]]]:
        """
        Parse a node's 'packages' entry, which takes one of two forms:

          packages:                      # flat: feature-agnostic
            - "myapp_*.deb"

          packages:                      # nested: per-feature package sets,
            features:                    # selected with pytest --feature
              vanilla:
                - "myapp_*.deb"
              tls:
                - "myapp-tls_*.deb"

        Returns (flat_globs, feature_globs); exactly one is non-empty.
        """

        def _check_globs(globs: Any, what: str) -> List[str]:
            if not isinstance(globs, list) or not all(
                isinstance(g, str) for g in globs
            ):
                raise ValueError(
                    f"Node {node_name}: {what} must be a list of package filename globs"
                )
            return globs

        if isinstance(raw, dict):
            unknown = set(raw) - {"features"}
            if unknown:
                raise ValueError(
                    f"Node {node_name}: unknown key(s) under 'packages': "
                    f"{', '.join(sorted(unknown))} (expected 'features')"
                )
            features = raw.get("features")
            if not isinstance(features, dict) or not features:
                raise ValueError(
                    f"Node {node_name}: 'packages.features' must be a "
                    "non-empty mapping of feature name to package list"
                )
            return [], {
                str(feat): _check_globs(globs, f"packages.features['{feat}']")
                for feat, globs in features.items()
            }

        return _check_globs(raw, "'packages'"), {}

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
