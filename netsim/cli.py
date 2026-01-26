"""
Command-line interface for the topology simulator.
"""

import argparse
import logging
import os
import sys
import subprocess
from pathlib import Path

from netsim.topology import TopologyParser
from netsim.simulator import TopologySimulator
from netsim.images import ImageManager


def get_default_runtime_dir(topology_file: str) -> str:
    """Generate default runtime directory with username, topology name, and timestamp."""
    username = os.getenv("USER", "user")
    topology_name = Path(topology_file).stem
    return f"/tmp/{username}/netsim/{topology_name}"


def setup_logging(verbose: bool = False):
    """Setup logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


def _show_connection_info(topology, simulator, target_node=None):
    """Show connection information for topology nodes."""

    print(f"\nConnection information for topology '{topology.name}':\n")

    nodes_to_show = []
    if target_node:
        # Show specific node
        nodes_to_show = (
            [target_node] if any(n.name == target_node for n in topology.nodes) else []
        )
        if not nodes_to_show:
            print(f"Error: Node '{target_node}' not found in topology")
            return
    else:
        # Show all nodes
        nodes_to_show = [n.name for n in topology.nodes]

    name_to_idx = {n.name: i for i, n in enumerate(topology.nodes)}

    for node_name in nodes_to_show:
        # Find the node in topology
        node = next((n for n in topology.nodes if n.name == node_name), None)
        if not node:
            continue

        # Check if VM is running
        try:
            result = subprocess.run(
                ["virsh", "domstate", node_name],
                capture_output=True,
                text=True,
                timeout=5,
            )
            is_running = result.returncode == 0 and "running" in result.stdout.lower()
        except Exception as _e:
            is_running = False

        status = "🟢 RUNNING" if is_running else "🔴 STOPPED"
        print(f"{node_name}: {status}")

        if is_running:
            # Show console access method
            print(f"  Console access: virsh console {node_name}")

            # Show auto-allocated interfaces
            if node_name in simulator.node_interfaces:
                print("  Network interfaces (auto-allocated):")
                for idx, (net_name, ip_cidr) in enumerate(simulator.node_interfaces[node_name]):
                    print(f"    - eth{idx}: {net_name} ({ip_cidr})")

            mgmt_port = 2200 + name_to_idx.get(node_name, 0)
            print(f"  SSH (management): ssh -p {mgmt_port} netsim@localhost")
            print("    (User-mode NAT with port forwarding; always available)")
            if len(node.networks) > 1:
                print("  Data interfaces:")
                print("    Use the configured IPs above for traffic tests")
        else:
            print(f"  Start the topology to connect: netsim start {topology.name}")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="NetSim - Network Topology Simulator for eBPF XDP Development"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Start command
    start_parser = subparsers.add_parser("start", help="Setup and start topology")
    start_parser.add_argument("topology", type=str, help="Path to topology YAML file")
    start_parser.add_argument(
        "--runtime-dir",
        type=str,
        help="Runtime directory for VM data (default: /tmp/{user}/netsim/{topology}_{timestamp})",
    )
    start_parser.add_argument(
        "--image-cache-dir",
        type=str,
        help="Image cache directory (default: ~/.netsim/images)",
    )

    # Stop command
    stop_parser = subparsers.add_parser("stop", help="Suspend topology")
    stop_parser.add_argument("topology", type=str, help="Path to topology YAML file")
    stop_parser.add_argument(
        "--runtime-dir",
        type=str,
        help="Runtime directory for VM data (default: /tmp/{user}/netsim/{topology}_{timestamp})",
    )

    # Status command
    status_parser = subparsers.add_parser("status", help="Show topology status")
    status_parser.add_argument("topology", type=str, help="Path to topology YAML file")
    status_parser.add_argument(
        "--runtime-dir",
        type=str,
        help="Runtime directory for VM data (default: /tmp/{user}/netsim/{topology}_{timestamp})",
    )

    # Connect command
    connect_parser = subparsers.add_parser(
        "connect", help="Show connection details for topology nodes"
    )
    connect_parser.add_argument("topology", type=str, help="Path to topology YAML file")
    connect_parser.add_argument(
        "node", nargs="?", type=str, help="Optional: specific node to connect to"
    )
    connect_parser.add_argument(
        "--runtime-dir",
        type=str,
        help="Runtime directory for VM data (default: /tmp/{user}/netsim/{topology}_{timestamp})",
    )

    # Destroy command
    destroy_parser = subparsers.add_parser(
        "destroy", help="Tear down VMs, bridges, taps, and remove runtime directory"
    )
    destroy_parser.add_argument("topology", type=str, help="Path to topology YAML file")
    destroy_parser.add_argument(
        "--runtime-dir",
        type=str,
        help="Runtime directory for VM data (default: /tmp/{user}/netsim/{topology}_{timestamp})",
    )

    # Image cache commands
    image_parser = subparsers.add_parser("image", help="Manage image cache")
    image_subparsers = image_parser.add_subparsers(
        dest="image_command", help="Image command"
    )

    # Image list command
    image_list_parser = image_subparsers.add_parser("list", help="List cached images")
    image_list_parser.add_argument(
        "--cache-dir", type=str, help="Image cache directory"
    )

    # Image download command
    image_download_parser = image_subparsers.add_parser(
        "download", help="Download image"
    )
    image_download_parser.add_argument("name", type=str, help="Image name")
    image_download_parser.add_argument("url", type=str, help="Image URL")
    image_download_parser.add_argument(
        "--checksum", type=str, help="SHA256 checksum for validation"
    )
    image_download_parser.add_argument(
        "--cache-dir", type=str, help="Image cache directory"
    )

    # Image remove command
    image_remove_parser = image_subparsers.add_parser(
        "remove", help="Remove cached image"
    )
    image_remove_parser.add_argument("name", type=str, help="Image name")
    image_remove_parser.add_argument(
        "--cache-dir", type=str, help="Image cache directory"
    )

    # Image clear command
    image_clear_parser = image_subparsers.add_parser(
        "clear", help="Clear all cached images"
    )
    image_clear_parser.add_argument(
        "--cache-dir", type=str, help="Image cache directory"
    )

    args = parser.parse_args()
    setup_logging(args.verbose)

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Handle image commands separately
    if args.command == "image":
        if not args.image_command:
            image_parser.print_help()
            sys.exit(1)

        image_manager = ImageManager(cache_dir=args.__dict__.get("cache_dir"))

        try:
            if args.image_command == "list":
                images = image_manager.list_cached_images()
                if not images:
                    print("No cached images")
                else:
                    print(f"Cached images ({len(images)}):")
                    total_size = 0
                    for name, info in images.items():
                        size_mb = info["size_mb"]
                        total_size += size_mb
                        print(
                            f"  {name}: {size_mb:.1f} MB (modified: {info['modified']})"
                        )
                    print(f"Total: {total_size:.1f} MB")

            elif args.image_command == "download":
                from netsim.images import ImageReference

                ref = ImageReference(
                    name=args.name, url=args.url, checksum=args.checksum
                )
                path = image_manager._resolve_image_reference(ref)
                print(f"Image downloaded: {path}")

            elif args.image_command == "remove":
                if image_manager.remove_cached_image(args.name):
                    print(f"Removed image: {args.name}")
                else:
                    print(f"Image not found: {args.name}")
                    sys.exit(1)

            elif args.image_command == "clear":
                count = image_manager.clear_cache()
                print(f"Cleared {count} images")

        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        return

    # Load topology for non-image commands
    try:
        topology = TopologyParser.load(args.topology)
    except Exception as e:
        print(f"Error loading topology: {e}", file=sys.stderr)
        sys.exit(1)

    # Generate default runtime_dir if not provided
    runtime_dir = args.__dict__.get("runtime_dir")
    if not runtime_dir:
        runtime_dir = get_default_runtime_dir(args.topology)

    # Create simulator
    simulator = TopologySimulator(
        topology,
        runtime_dir=runtime_dir,
        image_cache_dir=args.__dict__.get("image_cache_dir"),
    )

    try:
        if args.command == "start":
            simulator.setup()
            simulator.start()
            print(f"Topology '{topology.name}' started")

        elif args.command == "stop":
            simulator.stop()
            print(f"Topology '{topology.name}' suspended")

        elif args.command == "status":
            status = simulator.status()
            print(f"\nTopology '{topology.name}' status:")
            if not status:
                print("  No VMs found")
            else:
                for node, running in status.items():
                    state = "🟢 RUNNING" if running else "⚪ STOPPED"
                    print(f"  {node}: {state}")
            print()

        elif args.command == "connect":
            _show_connection_info(topology, simulator, args.__dict__.get("node"))

        elif args.command == "destroy":
            simulator.destroy()
            print(f"Topology '{topology.name}' destroyed")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
