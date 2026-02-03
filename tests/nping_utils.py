# Copyright (c) Dufferin Software

"""
Nping utility wrapper for test infrastructure.

Provides typed Python wrappers for sending TCP/UDP/ICMP traffic using nping.
Nping is part of the nmap package.
"""

import logging
import re
import subprocess
from dataclasses import dataclass
from enum import Enum
from typing import Optional

import netaddr

from tests.node import Node

logger = logging.getLogger(__name__)


# ============================================================================
# ICMP Constants
# ============================================================================

# ICMPv4 types
ICMP_V4_ECHO_REQUEST = 8
ICMP_V4_ECHO_REPLY = 0
ICMP_V4_DEST_UNREACHABLE = 3
ICMP_V4_REDIRECT = 5
ICMP_V4_TIME_EXCEEDED = 11
ICMP_V4_TIMESTAMP_REQUEST = 13
ICMP_V4_TIMESTAMP_REPLY = 14

# ICMPv6 types
ICMP_V6_ECHO_REQUEST = 128
ICMP_V6_ECHO_REPLY = 129
ICMP_V6_DEST_UNREACHABLE = 1
ICMP_V6_PACKET_TOO_BIG = 2
ICMP_V6_TIME_EXCEEDED = 3
ICMP_V6_PARAMETER_PROBLEM = 4


class NpingProtocol(str, Enum):
    """Protocol for nping."""

    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ARP = "arp"


@dataclass
class NpingResult:
    """Result from an nping execution."""

    success: bool
    packets_sent: int
    packets_received: int
    packets_lost: int
    loss_percent: float
    raw_output: str
    error_message: Optional[str] = None

    @property
    def all_received(self) -> bool:
        """Check if all packets were received."""
        return self.packets_sent > 0 and self.packets_lost == 0


@dataclass
class NpingOptions:
    """Options for nping command."""

    # Target (stored as string for command building, but validated as IPAddress)
    target: str

    # Protocol selection
    protocol: NpingProtocol = NpingProtocol.ICMP

    # Packet count and timing
    count: int = 5
    delay: str = "100ms"  # Delay between packets

    # TCP/UDP options
    dest_port: Optional[int] = None
    source_port: Optional[int] = None
    flags: Optional[str] = None  # TCP flags like "SYN", "ACK", "RST"

    # ICMP options
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None

    # Source options
    source_ip: Optional[str] = None
    interface: Optional[str] = None

    # MAC addresses (required for IPv6 with source_ip in nping)
    source_mac: Optional[str] = None
    dest_mac: Optional[str] = None

    # IPv6 - determined automatically from target address
    ipv6: bool = False

    # Data payload
    data_length: Optional[int] = None

    # TTL
    ttl: Optional[int] = None


def _parse_nping_output(output: str) -> NpingResult:
    """
    Parse nping output to extract statistics.

    Example output:
    SENT (0.0044s) ICMP [10.1.1.1 > 10.1.1.2 Echo request (type=8/code=0) id=12345 seq=1]
    RCVD (0.0046s) ICMP [10.1.1.2 > 10.1.1.1 Echo reply (type=0/code=0) id=12345 seq=1]
    ...
    Max rtt: 0.253ms | Min rtt: 0.186ms | Avg rtt: 0.213ms
    Raw packets sent: 5 (210B) | Rcvd: 5 (210B) | Lost: 0 (0.00%)
    Nping done: 1 IP address pinged in 0.41 seconds
    """
    packets_sent = 0
    packets_received = 0
    packets_lost = 0
    loss_percent = 0.0

    # Look for the stats line - format varies by protocol:
    # ICMP/TCP/Raw: "Raw packets sent: 5 (210B) | Rcvd: 5 (210B) | Lost: 0 (0.00%)"
    # UDP:          "UDP packets sent: 5 | Rcvd: 0 | Lost: 5 (100.00%)"
    stats_patterns = [
        # Raw/ICMP/TCP pattern (with byte counts)
        r"Raw packets sent:\s*(\d+).*Rcvd:\s*(\d+).*Lost:\s*(\d+)\s*\(([0-9.]+)%\)",
        # UDP pattern (without byte counts)
        r"UDP packets sent:\s*(\d+).*Rcvd:\s*(\d+).*Lost:\s*(\d+)\s*\(([0-9.]+)%\)",
    ]

    for pattern in stats_patterns:
        match = re.search(pattern, output)
        if match:
            packets_sent = int(match.group(1))
            packets_received = int(match.group(2))
            packets_lost = int(match.group(3))
            loss_percent = float(match.group(4))
            break

    success = packets_sent > 0 and packets_received > 0

    return NpingResult(
        success=success,
        packets_sent=packets_sent,
        packets_received=packets_received,
        packets_lost=packets_lost,
        loss_percent=loss_percent,
        raw_output=output,
    )


def _get_interface_mac(node: Node, interface: str) -> Optional[str]:
    """
    Get the MAC address of an interface.

    Args:
        node: Node to query
        interface: Interface name

    Returns:
        MAC address string or None if not found
    """
    try:
        output = node.ssh_command(
            f"ip link show {interface} | grep 'link/ether' | awk '{{print $2}}'",
            timeout=5,
        )
        mac = output.strip()
        if mac and ":" in mac:
            return mac
    except Exception as e:
        logger.warning(f"Failed to get MAC for {interface}: {e}")
    return None


def _get_neighbor_mac(node: Node, target_ip: str, interface: str) -> Optional[str]:
    """
    Get the MAC address for a target IP from the neighbor table.

    First pings the target to ensure neighbor entry exists, then queries.

    Args:
        node: Node to query
        target_ip: Target IP address
        interface: Interface to use

    Returns:
        MAC address string or None if not found
    """
    try:
        # First ping to populate neighbor cache (use ping6 for IPv6)
        node.ssh_command(
            f"ping -6 -c 1 -W 1 -I {interface} {target_ip} >/dev/null 2>&1 || true",
            timeout=5,
        )

        # Query neighbor table
        output = node.ssh_command(
            f"ip -6 neigh show {target_ip} | awk '{{print $5}}'",
            timeout=5,
        )
        mac = output.strip()
        if mac and ":" in mac:
            return mac
    except Exception as e:
        logger.warning(f"Failed to get neighbor MAC for {target_ip}: {e}")
    return None


def run_nping(node: Node, options: NpingOptions, timeout: int = 60) -> NpingResult:
    """
    Run nping on a node.

    Args:
        node: Node to run nping from
        options: Nping configuration options
        timeout: Command timeout in seconds

    Returns:
        NpingResult with statistics
    """
    # Build the nping command
    cmd_parts = ["sudo", "nping"]

    # Protocol selection
    if options.protocol == NpingProtocol.TCP:
        cmd_parts.append("--tcp")
    elif options.protocol == NpingProtocol.UDP:
        cmd_parts.append("--udp")
    elif options.protocol == NpingProtocol.ICMP:
        if options.ipv6:
            cmd_parts.append("--icmp")
            cmd_parts.append("-6")
        else:
            cmd_parts.append("--icmp")
    elif options.protocol == NpingProtocol.ARP:
        cmd_parts.append("--arp")

    # IPv6 flag (if not already added)
    if options.ipv6 and options.protocol != NpingProtocol.ICMP:
        cmd_parts.append("-6")

    # Packet count
    cmd_parts.extend(["-c", str(options.count)])

    # Delay between packets
    cmd_parts.extend(["--delay", options.delay])

    # Destination port (TCP/UDP)
    if options.dest_port is not None:
        cmd_parts.extend(["-p", str(options.dest_port)])

    # Source port (TCP/UDP)
    if options.source_port is not None:
        if options.protocol == NpingProtocol.TCP:
            cmd_parts.extend(["-g", str(options.source_port)])
        elif options.protocol == NpingProtocol.UDP:
            cmd_parts.extend(["--source-port", str(options.source_port)])

    # TCP flags
    if options.flags and options.protocol == NpingProtocol.TCP:
        cmd_parts.extend(["--flags", options.flags])

    # ICMP type and code
    if options.icmp_type is not None:
        cmd_parts.extend(["--icmp-type", str(options.icmp_type)])
    if options.icmp_code is not None:
        cmd_parts.extend(["--icmp-code", str(options.icmp_code)])

    # Source IP
    if options.source_ip:
        cmd_parts.extend(["-S", options.source_ip])

        # For IPv6 with source IP, nping requires MAC addresses
        if options.ipv6 and options.interface:
            # Get source MAC from interface
            source_mac = options.source_mac
            if not source_mac:
                source_mac = _get_interface_mac(node, options.interface)

            # Get destination MAC from neighbor table
            dest_mac = options.dest_mac
            if not dest_mac:
                dest_mac = _get_neighbor_mac(node, options.target, options.interface)

            if source_mac and dest_mac:
                cmd_parts.extend(["--source-mac", source_mac])
                cmd_parts.extend(["--dest-mac", dest_mac])
                logger.debug(f"Using MACs for IPv6: src={source_mac}, dst={dest_mac}")
            else:
                logger.warning(
                    f"Could not resolve MACs for IPv6 nping "
                    f"(src_mac={source_mac}, dst_mac={dest_mac})"
                )

    # Interface
    if options.interface:
        cmd_parts.extend(["-e", options.interface])

    # Data length
    if options.data_length is not None:
        cmd_parts.extend(["--data-length", str(options.data_length)])

    # TTL
    if options.ttl is not None:
        cmd_parts.extend(["--ttl", str(options.ttl)])

    # Target (must be last)
    cmd_parts.append(options.target)

    cmd = " ".join(cmd_parts)
    logger.info(f"[{node.name}] Running: {cmd}")

    try:
        output = node.ssh_command(cmd, timeout=timeout)
        result = _parse_nping_output(output)
        logger.info(
            f"[{node.name}] nping result: sent={result.packets_sent}, "
            f"received={result.packets_received}, lost={result.packets_lost}"
        )
        return result
    except subprocess.CalledProcessError as e:
        # nping might return non-zero on packet loss
        output = e.stdout if hasattr(e, "stdout") and e.stdout else ""
        if output:
            result = _parse_nping_output(output)
            result.error_message = str(e)
            return result
        return NpingResult(
            success=False,
            packets_sent=0,
            packets_received=0,
            packets_lost=0,
            loss_percent=100.0,
            raw_output="",
            error_message=str(e),
        )


# ============================================================================
# Convenience functions for common use cases
# ============================================================================


def send_ping(
    node: Node,
    target: netaddr.IPAddress,
    count: int = 5,
    interface: Optional[str] = None,
) -> NpingResult:
    """
    Send ICMP echo request packets (simple ping).

    For IPv4: uses nping --icmp
    For IPv6: uses ping -6 (nping has issues with ICMPv6)

    Automatically detects IPv4 vs IPv6 from target address.

    Args:
        node: Node to send from
        target: Target IP address (netaddr.IPAddress)
        count: Number of packets to send
        interface: Source interface

    Returns:
        NpingResult
    """
    ipv6 = target.version == 6

    if ipv6:
        # Use regular ping for IPv6 - nping has issues with ICMPv6
        return _run_ping6(node, target, count, interface)
    else:
        # Use nping for IPv4
        options = NpingOptions(
            target=str(target),
            protocol=NpingProtocol.ICMP,
            count=count,
            interface=interface,
            ipv6=False,
        )
        return run_nping(node, options)


def _run_ping6(
    node: Node,
    target: netaddr.IPAddress,
    count: int,
    interface: Optional[str],
) -> NpingResult:
    """
    Run ping -6 for IPv6 targets.

    Args:
        node: Node to run ping from
        target: Target IPv6 address
        count: Number of packets to send
        interface: Source interface (optional)

    Returns:
        NpingResult with statistics
    """
    cmd_parts = ["ping", "-6", "-c", str(count)]

    if interface:
        cmd_parts.extend(["-I", interface])

    cmd_parts.append(str(target))

    cmd = " ".join(cmd_parts)
    logger.info(f"[{node.name}] Running: {cmd}")

    try:
        output = node.ssh_command(cmd, timeout=60)
        return _parse_ping_output(output)
    except subprocess.CalledProcessError as e:
        output = e.stdout if hasattr(e, "stdout") and e.stdout else ""
        if output:
            result = _parse_ping_output(output)
            result.error_message = str(e)
            return result
        return NpingResult(
            success=False,
            packets_sent=0,
            packets_received=0,
            packets_lost=0,
            loss_percent=100.0,
            raw_output="",
            error_message=str(e),
        )


def _parse_ping_output(output: str) -> NpingResult:
    """
    Parse ping output to extract statistics.

    Example output:
    PING 2001:db8:1::a(2001:db8:1::a) 56 data bytes
    64 bytes from 2001:db8:1::a: icmp_seq=1 ttl=64 time=0.123 ms
    ...
    --- 2001:db8:1::a ping statistics ---
    5 packets transmitted, 5 received, 0% packet loss, time 4005ms
    rtt min/avg/max/mdev = 0.089/0.112/0.156/0.024 ms
    """
    packets_sent = 0
    packets_received = 0
    packets_lost = 0
    loss_percent = 0.0

    # Look for the stats line: "5 packets transmitted, 5 received, 0% packet loss"
    stats_pattern = (
        r"(\d+) packets transmitted, (\d+) received.*?(\d+(?:\.\d+)?)% packet loss"
    )
    match = re.search(stats_pattern, output)
    if match:
        packets_sent = int(match.group(1))
        packets_received = int(match.group(2))
        loss_percent = float(match.group(3))
        packets_lost = packets_sent - packets_received

    success = packets_sent > 0 and packets_received > 0

    return NpingResult(
        success=success,
        packets_sent=packets_sent,
        packets_received=packets_received,
        packets_lost=packets_lost,
        loss_percent=loss_percent,
        raw_output=output,
    )


def send_icmp(
    node: Node,
    target: netaddr.IPAddress,
    count: int = 5,
    interface: Optional[str] = None,
    icmp_type: Optional[int] = None,
    icmp_code: int = 0,
) -> NpingResult:
    """
    Send ICMP packets (ping or custom type).

    Automatically detects IPv4 vs IPv6 from target address and uses the
    appropriate ICMP type for echo requests:
    - IPv4: type 8 (Echo Request)
    - IPv6: type 128 (Echo Request)

    Args:
        node: Node to send from
        target: Target IP address (netaddr.IPAddress)
        count: Number of packets to send
        interface: Source interface
        icmp_type: ICMP type (default: echo request for the IP version)
        icmp_code: ICMP code (default 0)

    Returns:
        NpingResult
    """
    ipv6 = target.version == 6

    # Default ICMP type based on IP version
    if icmp_type is None:
        icmp_type = ICMP_V6_ECHO_REQUEST if ipv6 else ICMP_V4_ECHO_REQUEST

    options = NpingOptions(
        target=str(target),
        protocol=NpingProtocol.ICMP,
        count=count,
        interface=interface,
        ipv6=ipv6,
        icmp_type=icmp_type,
        icmp_code=icmp_code,
    )
    return run_nping(node, options)


def send_tcp_syn(
    node: Node,
    target: netaddr.IPAddress,
    dest_port: int,
    count: int = 5,
    source_port: Optional[int] = None,
    source_ip: Optional[str] = None,
    interface: Optional[str] = None,
) -> NpingResult:
    """
    Send TCP SYN packets.

    Automatically detects IPv4 vs IPv6 from target address.

    Args:
        node: Node to send from
        target: Target IP address (netaddr.IPAddress)
        dest_port: Destination port
        count: Number of packets to send
        source_port: Source port (optional)
        source_ip: Source IP address (required for IPv6 to work correctly with nping)
        interface: Source interface

    Returns:
        NpingResult
    """
    ipv6 = target.version == 6

    options = NpingOptions(
        target=str(target),
        protocol=NpingProtocol.TCP,
        count=count,
        dest_port=dest_port,
        source_port=source_port,
        source_ip=source_ip,
        interface=interface,
        ipv6=ipv6,
        flags="SYN",
    )
    return run_nping(node, options)


def send_tcp_packets(
    node: Node,
    target: netaddr.IPAddress,
    dest_port: int,
    count: int = 5,
    source_port: Optional[int] = None,
    source_ip: Optional[str] = None,
    flags: str = "SYN",
    interface: Optional[str] = None,
) -> NpingResult:
    """
    Send TCP packets with custom flags.

    Automatically detects IPv4 vs IPv6 from target address.

    Args:
        node: Node to send from
        target: Target IP address (netaddr.IPAddress)
        dest_port: Destination port
        count: Number of packets to send
        source_port: Source port (optional)
        source_ip: Source IP address (required for IPv6 to work correctly with nping)
        flags: TCP flags (e.g., "SYN", "ACK", "RST", "SYN,ACK")
        interface: Source interface

    Returns:
        NpingResult
    """
    ipv6 = target.version == 6

    options = NpingOptions(
        target=str(target),
        protocol=NpingProtocol.TCP,
        count=count,
        dest_port=dest_port,
        source_port=source_port,
        source_ip=source_ip,
        flags=flags,
        interface=interface,
        ipv6=ipv6,
    )
    return run_nping(node, options)


def send_udp_packets(
    node: Node,
    target: netaddr.IPAddress,
    dest_port: int,
    count: int = 5,
    source_port: Optional[int] = None,
    source_ip: Optional[str] = None,
    interface: Optional[str] = None,
    data_length: Optional[int] = None,
) -> NpingResult:
    """
    Send UDP packets.

    Automatically detects IPv4 vs IPv6 from target address.

    Args:
        node: Node to send from
        target: Target IP address (netaddr.IPAddress)
        dest_port: Destination port
        count: Number of packets to send
        source_port: Source port (optional)
        source_ip: Source IP address (required for IPv6 to work correctly with nping)
        interface: Source interface
        data_length: Payload size in bytes

    Returns:
        NpingResult
    """
    ipv6 = target.version == 6

    options = NpingOptions(
        target=str(target),
        protocol=NpingProtocol.UDP,
        count=count,
        dest_port=dest_port,
        source_port=source_port,
        source_ip=source_ip,
        interface=interface,
        ipv6=ipv6,
        data_length=data_length,
    )
    return run_nping(node, options)


def send_icmp_with_type(
    node: Node,
    target: netaddr.IPAddress,
    icmp_type: int,
    icmp_code: int = 0,
    count: int = 5,
    interface: Optional[str] = None,
) -> NpingResult:
    """
    Send ICMP packets with custom type and code.

    Automatically detects IPv4 vs IPv6 from target address.

    Common ICMPv4 types:
    - 0: Echo Reply
    - 3: Destination Unreachable
    - 5: Redirect
    - 8: Echo Request
    - 11: Time Exceeded
    - 13: Timestamp Request
    - 14: Timestamp Reply

    Common ICMPv6 types:
    - 1: Destination Unreachable
    - 2: Packet Too Big
    - 3: Time Exceeded
    - 4: Parameter Problem
    - 128: Echo Request
    - 129: Echo Reply

    Args:
        node: Node to send from
        target: Target IP address (netaddr.IPAddress)
        icmp_type: ICMP type
        icmp_code: ICMP code
        count: Number of packets to send
        interface: Source interface

    Returns:
        NpingResult
    """
    ipv6 = target.version == 6

    options = NpingOptions(
        target=str(target),
        protocol=NpingProtocol.ICMP,
        count=count,
        interface=interface,
        ipv6=ipv6,
        icmp_type=icmp_type,
        icmp_code=icmp_code,
    )
    return run_nping(node, options)
