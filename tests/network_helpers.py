# Copyright (c) Dufferin Software

"""
Network helper utilities for testing.

Provides abstracted routines for common network operations used in tests.
"""

import logging
from typing import Optional
import netaddr

logger = logging.getLogger(__name__)


def enable_ip_forwarding(
    node, ipv4: bool = True, ipv6: bool = True, timeout: int = 5
) -> None:
    """Enable IP forwarding on a node.

    Args:
        node: Node object with ssh_command method.
        ipv4: Enable IPv4 forwarding if True.
        ipv6: Enable IPv6 forwarding if True.
        timeout: SSH command timeout in seconds.
    """
    if ipv4:
        logger.debug(f"Enabling IPv4 forwarding on {node.name}...")
        node.ssh_command("sudo sysctl -w net.ipv4.ip_forward=1", timeout=timeout)

    if ipv6:
        logger.debug(f"Enabling IPv6 forwarding on {node.name}...")
        node.ssh_command(
            "sudo sysctl -w net.ipv6.conf.all.forwarding=1", timeout=timeout
        )


def add_route(
    node,
    destination: netaddr.IPNetwork,
    via: netaddr.IPAddress,
    dev: Optional[str] = None,
    ipv6: bool = False,
    timeout: int = 5,
) -> None:
    """Add a static route on a node.

    Args:
        node: Node object with ssh_command method.
        destination: Target network (e.g., netaddr.IPNetwork("10.0.2.0/24")).
        via: Gateway IP address (e.g., netaddr.IPAddress("192.168.1.1")).
        dev: Optional interface name (required for some IPv6 routes).
        ipv6: Use IPv6 route command if True, IPv4 otherwise.
        timeout: SSH command timeout in seconds.
    """
    ip_cmd = "ip -6" if ipv6 else "ip"
    dev_str = f" dev {dev}" if dev else ""

    cmd = f"sudo {ip_cmd} route add {destination} via {via}{dev_str}"
    logger.debug(f"Adding route on {node.name}: {destination} via {via}")
    node.ssh_command(cmd, timeout=timeout)
