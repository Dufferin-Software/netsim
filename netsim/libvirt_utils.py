# Copyright (c) Peter Morrow

"""Libvirt utilities for VM management."""

import logging
import os
import signal
import subprocess
from types import FrameType
from typing import Any, Optional

import libvirt  # type: ignore[import-untyped]

logger: logging.Logger = logging.getLogger(__name__)

# libvirt's Python binding has no connect timeout; a wedged daemon will hang
# callers forever. Every open() in this module is wrapped with SIGALRM.
_DEFAULT_OPEN_TIMEOUT_SECS: int = 10


class LibvirtOpenTimeout(Exception):
    """libvirt.open() did not complete within the allowed time."""


def open_with_timeout(
    uri: str, secs: int = _DEFAULT_OPEN_TIMEOUT_SECS
) -> "libvirt.virConnect":
    """Call libvirt.open(uri) with a hard timeout."""

    def _handler(_signum: int, _frame: Optional[FrameType]) -> None:
        raise LibvirtOpenTimeout(
            f"libvirt.open({uri!r}) did not respond within {secs}s — "
            "daemon is likely wedged"
        )

    old = signal.signal(signal.SIGALRM, _handler)
    signal.alarm(secs)
    try:
        conn: Optional["libvirt.virConnect"] = libvirt.open(uri)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)

    if conn is None:
        raise RuntimeError(f"libvirt.open({uri!r}) returned None")
    return conn


def _check_security_driver(conn: "libvirt.virConnect", uri: str) -> None:
    """Warn if AppArmor is the active security driver.

    AppArmor's virt-aa-helper profile explicitly denies access to hidden
    directories (paths starting with '.'), so ~/.netsim images will be blocked
    even if POSIX permissions are correct.  The fix is to set
    security_driver = "none" in /etc/libvirt/qemu.conf and restart libvirtd.
    """
    import xml.etree.ElementTree as ET

    try:
        caps_xml: str = conn.getCapabilities()
        root = ET.fromstring(caps_xml)
        active_models = [
            el.findtext("model") or "" for el in root.findall(".//secmodel")
        ]
        if "apparmor" in active_models:
            raise RuntimeError(
                f"libvirt on {uri!r} is using the AppArmor security driver.\n"
                "AppArmor blocks QEMU from accessing ~/.netsim images (hidden-dir rule).\n"
                "Fix: add 'security_driver = \"none\"' to /etc/libvirt/qemu.conf "
                "and run: sudo systemctl restart libvirtd"
            )
    except libvirt.libvirtError:
        pass


def preflight(uri: str = "qemu:///system", timeout: int = 10) -> None:
    """Fail fast if the libvirt daemon isn't responsive.

    Intended as a session-level gate so pytest aborts with an actionable
    error instead of hanging in a later fixture.
    """

    def _handler(_signum: int, _frame: Optional[FrameType]) -> None:
        raise LibvirtOpenTimeout(
            f"libvirt preflight timed out after {timeout}s on {uri!r} — "
            "daemon is likely wedged"
        )

    old = signal.signal(signal.SIGALRM, _handler)
    signal.alarm(timeout)
    try:
        try:
            conn = libvirt.open(uri)
        except libvirt.libvirtError as e:
            raise RuntimeError(
                f"libvirt pre-flight failed connecting to {uri!r}: {e}.\n"
                f"For qemu:///session: start the user daemon with 'libvirtd --daemon'\n"
                f"  or switch to the system daemon: "
                f"NETSIM_LIBVIRT_URI=qemu:///system pytest ...\n"
                f"For qemu:///system: sudo systemctl start libvirtd.socket"
            ) from e

        if conn is None:
            raise RuntimeError(f"libvirt.open({uri!r}) returned None")

        try:
            conn.listAllDomains()
            _check_security_driver(conn, uri)
        finally:
            try:
                conn.close()
            except Exception:
                pass
    except LibvirtOpenTimeout as e:
        raise RuntimeError(
            f"libvirt pre-flight failed: {e}.\n"
            f"Recovery: pkill -9 -x libvirtd && "
            f"systemctl --user restart libvirtd.socket"
        ) from e
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


def cleanup_leftover_taps() -> None:
    """Delete persistent tap devices left behind by killed VMs.

    Netsim names its taps ``tap<digits>`` (see simulator.py). Only devices
    matching that convention are touched.
    """
    try:
        out: subprocess.CompletedProcess[str] = subprocess.run(
            ["ip", "tuntap", "show"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        logger.debug(f"tap enumeration skipped: {e}")
        return

    if out.returncode != 0:
        return

    for line in out.stdout.splitlines():
        name: str = line.split(":", 1)[0].strip()
        if not name.startswith("tap") or not name[3:].isdigit():
            continue
        logger.info(f"Removing leftover tap device: {name}")
        subprocess.run(
            ["sudo", "-n", "ip", "tuntap", "del", "mode", "tap", "name", name],
            capture_output=True,
            timeout=5,
            check=False,
        )


def cleanup_leftover_vms(topology: Any) -> None:
    """Clean up any leftover VMs from previous failed runs.

    Args:
        topology: Topology object with nodes to clean
    """
    logger.info("Checking for leftover VMs from previous runs...")

    try:
        conn = open_with_timeout(os.environ.get("NETSIM_LIBVIRT_URI", "qemu:///system"))
    except LibvirtOpenTimeout as e:
        logger.warning(f"Skipping leftover-VM check: {e}")
        return
    except Exception as e:
        logger.debug(f"Pre-cleanup check: {e}")
        return

    try:
        for node in topology.nodes:
            try:
                dom = conn.lookupByName(node.name)
                logger.warning(f"Found leftover VM: {node.name}, destroying it")
                if dom.isActive():
                    dom.destroy()
                # Use flags to handle managed save images and snapshots
                undefine_flags: int = (
                    libvirt.VIR_DOMAIN_UNDEFINE_MANAGED_SAVE
                    | libvirt.VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA
                )
                try:
                    dom.undefineFlags(undefine_flags)
                except libvirt.libvirtError:
                    # Fallback to simple undefine if flags not supported
                    dom.undefine()
            except libvirt.libvirtError:
                pass  # VM doesn't exist, good
    finally:
        try:
            conn.close()
        except Exception:
            pass


def log_vm_count(topology: Any) -> None:
    """Log VM count for debugging.

    Args:
        topology: Topology object for comparison
    """
    try:
        conn = open_with_timeout(os.environ.get("NETSIM_LIBVIRT_URI", "qemu:///system"))
    except LibvirtOpenTimeout as e:
        logger.warning(f"Skipping VM count check: {e}")
        return
    except Exception:
        return

    try:
        all_domains = conn.listAllDomains()
        logger.info(f"Total VMs in libvirt session: {len(all_domains)}")
        if len(all_domains) > len(topology.nodes):
            logger.warning(
                f"⚠ Expected {len(topology.nodes)} VMs, found {len(all_domains)}!"
            )
            for dom in all_domains:
                logger.warning(f"  - {dom.name()}")
    finally:
        try:
            conn.close()
        except Exception:
            pass
