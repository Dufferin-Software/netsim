# Copyright (c) Dufferin Software

"""
Network bridge and interface management.
"""

import logging
import subprocess
import re
import os
import getpass
import pwd
from typing import Any, List

logger: logging.Logger = logging.getLogger(__name__)


class NetworkManager:
    """Manage Linux bridges and tap interfaces for VMs."""

    @staticmethod
    def _run_cmd(
        cmd: List[str], sudo: bool = False, ignore_exists: bool = False
    ) -> None:
        """Run a command, automatically using sudo if permission denied.

        Args:
            cmd: Command to run (without sudo prefix)
            sudo: Whether sudo has been attempted (internal use)
            ignore_exists: If True, ignore "File exists" errors
        """
        cmd_to_run: List[str] = ["sudo"] + cmd if sudo else cmd

        try:
            subprocess.run(cmd_to_run, check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            if b"Operation not permitted" in e.stderr and not sudo:
                # Retry with sudo
                return NetworkManager._run_cmd(
                    cmd, sudo=True, ignore_exists=ignore_exists
                )
            elif ignore_exists and b"File exists" in e.stderr:
                # Resource already exists, that's ok
                return
            raise

    @staticmethod
    def _detect_tap_owner() -> str:
        """Decide which user should own tap devices.

        - User-session libvirt (qemu:///session): use the current user so QEMU can
          open the tap without extra capabilities.
        - System libvirt (qemu:///system): prefer the libvirt qemu user if present
          to keep permissions tight.
        - Allow override via NETSIM_TAP_USER for custom setups.
        """
        override: str | None = os.environ.get("NETSIM_TAP_USER")
        if override:
            return override

        try:
            uri_result: subprocess.CompletedProcess[str] = subprocess.run(
                ["virsh", "uri"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            uri: str = uri_result.stdout.strip()
        except Exception:
            uri = ""

        if "qemu:///system" in uri:
            for candidate in ("libvirt-qemu", "qemu"):
                try:
                    pwd.getpwnam(candidate)
                    return candidate
                except KeyError:
                    continue
            return "root"

        return getpass.getuser()

    @staticmethod
    def create_bridge(name: str, mtu: int = 1500) -> None:
        """Create a Linux bridge."""
        try:
            NetworkManager._run_cmd(
                ["ip", "link", "add", name, "type", "bridge"], ignore_exists=True
            )
            NetworkManager._run_cmd(
                ["ip", "link", "set", name, "up"], ignore_exists=True
            )
            NetworkManager._run_cmd(["ip", "link", "set", name, "mtu", str(mtu)])
            # If br_netfilter is active (loaded by Docker etc.), bridged IP traffic
            # passes through the iptables FORWARD chain which may have policy drop.
            # Insert ACCEPT rules so VM-to-VM traffic on this bridge is not blocked.
            NetworkManager._allow_bridge_forwarding(name)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to create bridge {name}: {e.stderr.decode()}")

    @staticmethod
    def _allow_bridge_forwarding(name: str) -> None:
        """Insert nftables ACCEPT rules for bridge forwarding if br_netfilter is active.

        When Docker (or anything that loads br_netfilter) is present, bridged
        IPv4/IPv6 traffic traverses the host's ip/ip6 filter FORWARD chain.
        Docker sets that chain's policy to drop, so VM-to-VM traffic on the
        netsim bridge is silently dropped without these accept rules.

        Idempotent: checks for pre-existing rules and skips insertion.
        """
        nft: str | None = next(
            (p for p in ["/usr/sbin/nft", "/sbin/nft", "nft"] if os.path.isfile(p)),
            None,
        )
        if nft is None:
            return

        # Each family has its own br_netfilter sysctl toggle and filter table.
        active_families: List[str] = []
        for family, sysctl in (
            ("ip", "bridge-nf-call-iptables"),
            ("ip6", "bridge-nf-call-ip6tables"),
        ):
            try:
                with open(f"/proc/sys/net/bridge/{sysctl}") as f:
                    if f.read().strip() == "1":
                        active_families.append(family)
            except OSError:
                continue

        if not active_families:
            return

        for family in active_families:
            list_res: subprocess.CompletedProcess[bytes] = subprocess.run(
                ["sudo", nft, "list", "chain", family, "filter", "FORWARD"],
                capture_output=True,
            )
            if list_res.returncode != 0:
                # Filter table / FORWARD chain not present in this family.
                continue

            existing: str = list_res.stdout.decode()
            for direction in ("iifname", "oifname"):
                # Match both quoted and unquoted forms that nft may emit.
                if re.search(rf'{direction}\s+"?{re.escape(name)}"?(\s|$)', existing):
                    continue
                insert_res: subprocess.CompletedProcess[bytes] = subprocess.run(
                    [
                        "sudo",
                        nft,
                        "insert",
                        "rule",
                        family,
                        "filter",
                        "FORWARD",
                        direction,
                        name,
                        "counter",
                        "accept",
                    ],
                    capture_output=True,
                )
                if insert_res.returncode != 0:
                    logger.warning(
                        "Failed to insert %s FORWARD %s accept rule for %s: %s",
                        family,
                        direction,
                        name,
                        insert_res.stderr.decode().strip(),
                    )

    @staticmethod
    def delete_bridge(name: str) -> None:
        """Delete a Linux bridge."""
        try:
            NetworkManager._run_cmd(["ip", "link", "set", name, "down"])
            NetworkManager._run_cmd(["ip", "link", "del", name])
        except subprocess.CalledProcessError:
            pass  # Bridge might already be deleted

    @staticmethod
    def create_tap(name: str) -> str:
        """Create a tap interface and return its name."""
        try:
            tap_owner: str = NetworkManager._detect_tap_owner()

            # Check if tap already exists
            result: subprocess.CompletedProcess[str] = subprocess.run(
                ["ip", "link", "show", name], capture_output=True, text=True
            )
            if result.returncode == 0:
                # Interface already exists; ensure ownership matches the expected tap owner
                detail: subprocess.CompletedProcess[str] = subprocess.run(
                    ["ip", "-d", "link", "show", name], capture_output=True, text=True
                )
                detail_out: str = detail.stdout + detail.stderr
                owner_match: re.Match[str] | None = re.search(r"user (\S+)", detail_out)
                current_owner: str | Any = owner_match.group(1) if owner_match else ""

                if current_owner and current_owner != tap_owner:
                    # Recreate with correct owner so QEMU can open it
                    NetworkManager._run_cmd(
                        ["ip", "tuntap", "del", name, "mode", "tap"], ignore_exists=True
                    )
                else:
                    NetworkManager._run_cmd(
                        ["ip", "link", "set", name, "up"], ignore_exists=True
                    )
                    return name

            # Create tap owned by libvirt-qemu so the hypervisor process can open it without extra caps
            NetworkManager._run_cmd(
                ["ip", "tuntap", "add", name, "mode", "tap", "user", tap_owner],
                ignore_exists=True,
            )
            NetworkManager._run_cmd(
                ["ip", "link", "set", name, "up"], ignore_exists=True
            )

            return name
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to create tap {name}: {e.stderr.decode()}")

    @staticmethod
    def delete_tap(name: str) -> None:
        """Delete a tap interface."""
        try:
            NetworkManager._run_cmd(["ip", "link", "set", name, "down"])
            NetworkManager._run_cmd(["ip", "tuntap", "del", name, "mode", "tap"])
        except subprocess.CalledProcessError:
            pass  # Interface might already be deleted

    @staticmethod
    def bridge_tap(bridge_name: str, tap_name: str) -> None:
        """Add a tap interface to a bridge."""
        try:
            NetworkManager._run_cmd(
                ["ip", "link", "set", tap_name, "master", bridge_name]
            )
        except subprocess.CalledProcessError as e:
            raise RuntimeError(
                f"Failed to bridge {tap_name} to {bridge_name}: {e.stderr.decode()}"
            )

    @staticmethod
    def set_bridge_ip(bridge_name: str, ip_cidr: str) -> None:
        """Assign IP address to bridge."""
        try:
            NetworkManager._run_cmd(["ip", "addr", "add", ip_cidr, "dev", bridge_name])
        except subprocess.CalledProcessError:
            pass  # Address might already be assigned

    @staticmethod
    def bridge_exists(name: str) -> bool:
        """Check if bridge exists."""
        try:
            result: subprocess.CompletedProcess[bytes] = subprocess.run(
                ["ip", "link", "show", name], check=True, capture_output=True
            )
            return "bridge" in result.stdout.decode()
        except subprocess.CalledProcessError:
            return False

    @staticmethod
    def get_existing_bridges() -> List[str]:
        """Get list of existing bridges."""
        try:
            result: subprocess.CompletedProcess[bytes] = subprocess.run(
                ["ip", "link", "show", "type", "bridge"],
                check=True,
                capture_output=True,
            )
            bridges = []
            for line in result.stdout.decode().split("\n"):
                # Lines like "2: br0: <BROADCAST,MULTICAST,UP,LOWER_UP>..."
                match: re.Match[str] | None = re.match(r"\d+:\s+(\w+):", line)
                if match:
                    bridges.append(match.group(1))
            return bridges
        except subprocess.CalledProcessError:
            return []
