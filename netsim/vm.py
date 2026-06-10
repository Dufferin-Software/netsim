# Copyright (c) Dufferin Software

"""
Libvirt (KVM/QEMU) VM management.
"""

from logging import Logger
import xml.etree.ElementTree as ET
import os
import subprocess
import time
from pathlib import Path
from typing import Optional, List
from dataclasses import dataclass, field

import libvirt  # type: ignore[import-untyped]


@dataclass
class VMConfig:
    """Configuration for a KVM/QEMU VM managed by libvirt."""

    name: str
    image_path: str
    memory_mb: int = 512
    vcpus: int = 1
    tap_devices: List[str] = field(default_factory=list)  # List of tap interface names
    disk_size_gb: int = 10  # Size for COW overlay disk
    mgmt_ssh_port: Optional[int] = None  # Host port forwarded to guest ssh
    cloudinit_iso: Optional[str] = None  # Path to cloud-init ISO
    enable_tpm: bool = True  # Attach an emulated TPM 2.0 via swtpm

    def __post_init__(self) -> None:
        # Ensure tap_devices is always a list for mypy and runtime safety
        if self.tap_devices is None:
            self.tap_devices = []


class LibvirtVM:
    """Manager for a single KVM/QEMU VM via libvirt."""

    def __init__(self, config: VMConfig, runtime_dir: str = "/tmp/netsim") -> None:
        """
        Initialize libvirt VM.

        Args:
            config: VM configuration
            runtime_dir: Directory for VM runtime data
        """
        self.config: VMConfig = config
        self.runtime_dir = Path(runtime_dir)
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self.vm_dir: Path = self.runtime_dir / config.name
        self.vm_dir.mkdir(exist_ok=True)

    def _generate_domain_xml(self) -> str:
        """Generate libvirt domain XML configuration."""
        # Create disk image as copy-on-write layer
        disk_path: Path = self.vm_dir / f"{self.config.name}.qcow2"
        self._create_cow_disk(disk_path)

        # Build domain XML
        domain: ET.Element[str] = ET.Element("domain", type="kvm")

        # Name
        ET.SubElement(domain, "name").text = self.config.name

        # Memory (in MiB)
        ET.SubElement(domain, "memory", unit="MiB").text = str(self.config.memory_mb)
        ET.SubElement(domain, "currentMemory", unit="MiB").text = str(
            self.config.memory_mb
        )

        # vCPU
        vcpu_elem: ET.Element[str] = ET.SubElement(domain, "vcpu")
        vcpu_elem.set("placement", "static")
        vcpu_elem.text = str(self.config.vcpus)

        # CPU: pass through host CPU features so guests see the real instruction set
        # (e.g. SSE4.2, AVX) rather than a generic baseline model.
        ET.SubElement(domain, "cpu", mode="host-passthrough")

        # OS boot
        os_elem: ET.Element[str] = ET.SubElement(domain, "os")
        ET.SubElement(os_elem, "type", arch="x86_64", machine="q35").text = "hvm"
        ET.SubElement(os_elem, "boot", dev="hd")

        # Features: ACPI is required for the guest kernel to discover the TPM-TIS
        # device (via ACPI HID MSFT0101).  Without it libvirt starts QEMU with
        # acpi=off and /dev/tpm0 never appears in the guest.
        features: ET.Element[str] = ET.SubElement(domain, "features")
        ET.SubElement(features, "acpi")
        ET.SubElement(features, "apic")

        # Devices
        devices: ET.Element[str] = ET.SubElement(domain, "devices")

        # Emulator
        ET.SubElement(devices, "emulator").text = "/usr/bin/qemu-system-x86_64"

        # Disk — let libvirt auto-assign the PCIe address on q35.
        disk: ET.Element[str] = ET.SubElement(
            devices, "disk", type="file", device="disk"
        )
        ET.SubElement(disk, "driver", name="qemu", type="qcow2")
        ET.SubElement(disk, "source", file=str(disk_path))
        ET.SubElement(disk, "target", dev="vda", bus="virtio")

        # Cloud-init ISO (if provided)
        if self.config.cloudinit_iso:
            iso_disk: ET.Element[str] = ET.SubElement(
                devices, "disk", type="file", device="cdrom"
            )
            ET.SubElement(iso_disk, "driver", name="qemu", type="raw")
            ET.SubElement(iso_disk, "source", file=str(self.config.cloudinit_iso))
            ET.SubElement(iso_disk, "target", dev="sda", bus="sata")
            ET.SubElement(iso_disk, "readonly")

        # Serial console
        serial: ET.Element[str] = ET.SubElement(devices, "serial", type="pty")
        ET.SubElement(serial, "target", port="0")

        console: ET.Element[str] = ET.SubElement(devices, "console", type="pty")
        ET.SubElement(console, "target", type="serial", port="0")

        # Graphics (VNC)
        ET.SubElement(devices, "graphics", type="vnc", port="-1", autoport="yes")

        # Disable virtio balloon to avoid PCI slot collisions with manually placed NICs
        ET.SubElement(devices, "memballoon", model="none")

        # Management interface: user-mode SLIRP with SSH port forward.
        # libvirt has no declarative hostfwd support so this stays as a QEMU
        # command-line arg.  The data tap interfaces use native libvirt XML so
        # libvirt (root) opens /dev/net/tun and passes an fd to QEMU — QEMU
        # itself never opens /dev/net/tun (which is cgroup-restricted).
        if self.config.mgmt_ssh_port:
            domain.set("xmlns:qemu", "http://libvirt.org/schemas/domain/qemu/1.0")
            qemu_cmd: ET.Element[str] = ET.SubElement(
                domain, "{http://libvirt.org/schemas/domain/qemu/1.0}commandline"
            )
            ET.SubElement(
                qemu_cmd,
                "{http://libvirt.org/schemas/domain/qemu/1.0}arg",
                value="-netdev",
            )
            ET.SubElement(
                qemu_cmd,
                "{http://libvirt.org/schemas/domain/qemu/1.0}arg",
                value=f"user,id=mgmt,hostfwd=tcp::{self.config.mgmt_ssh_port}-:22",
            )
            ET.SubElement(
                qemu_cmd,
                "{http://libvirt.org/schemas/domain/qemu/1.0}arg",
                value="-device",
            )
            ET.SubElement(
                qemu_cmd,
                "{http://libvirt.org/schemas/domain/qemu/1.0}arg",
                value=f"virtio-net-pci,netdev=mgmt,mac={self._generate_mac(0)},bus=pcie.0,addr=0x10",
            )

        # Data interfaces: native libvirt ethernet interfaces backed by
        # pre-created tap devices.  managed='no' tells libvirt not to
        # create/destroy the tap; it still opens it (as root) and hands the fd
        # to QEMU, so QEMU never needs /dev/net/tun access directly.
        for idx, tap_dev in enumerate(self.config.tap_devices, start=1):
            iface: ET.Element[str] = ET.SubElement(
                devices, "interface", type="ethernet"
            )
            ET.SubElement(iface, "mac", address=self._generate_mac(idx))
            ET.SubElement(iface, "target", dev=tap_dev, managed="no")
            ET.SubElement(iface, "model", type="virtio")

        # Emulated TPM 2.0 — libvirt manages the swtpm process automatically.
        # Requires swtpm installed on the host.
        if self.config.enable_tpm:
            tpm: ET.Element = ET.SubElement(devices, "tpm", model="tpm-tis")
            ET.SubElement(tpm, "backend", type="emulator", version="2.0")

        # Convert to string
        return ET.tostring(domain, encoding="unicode")

    def _create_cow_disk(self, disk_path: Path) -> None:
        """Create a copy-on-write disk based on the image."""
        if disk_path.exists():
            return  # Disk already exists

        try:
            # Ensure base image exists and is readable
            base_image = Path(self.config.image_path)
            if not base_image.exists():
                raise RuntimeError(f"Base image not found at: {self.config.image_path}")

            import logging

            logger: Logger = logging.getLogger(__name__)
            logger.debug(f"Creating COW disk for {self.config.name}")
            logger.debug(f"  Base image: {base_image}")
            logger.debug(f"  COW disk: {disk_path}")

            # Ensure parent directory exists and is writable
            disk_path.parent.mkdir(parents=True, exist_ok=True)

            # Make the runtime and vm directories traversable by libvirt-qemu
            # (system libvirt runs QEMU as libvirt-qemu, which needs +rx on every
            # ancestor directory of the disk file)
            for directory in [disk_path.parent.parent, disk_path.parent]:
                subprocess.run(
                    ["sudo", "chmod", "a+rx", str(directory)],
                    capture_output=True,
                    timeout=5,
                )

            # Make base image readable by all (needed for libvirt-qemu user)
            subprocess.run(
                ["sudo", "chmod", "a+rx", str(base_image.parent)],
                capture_output=True,
                timeout=5,
            )
            subprocess.run(
                ["sudo", "chmod", "a+r", str(base_image)],
                capture_output=True,
                timeout=5,
            )

            # Create COW layer on top of base image
            subprocess.run(
                [
                    "qemu-img",
                    "create",
                    "-f",
                    "qcow2",
                    "-b",
                    str(self.config.image_path),
                    "-F",
                    "qcow2",
                    str(disk_path),
                    f"{self.config.disk_size_gb}G",
                ],
                check=True,
                capture_output=True,
            )

            # Make COW disk readable/writable by libvirt-qemu
            subprocess.run(
                ["sudo", "chmod", "a+rw", str(disk_path)],
                capture_output=True,
                timeout=5,
            )
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to create COW disk: {e.stderr.decode()}")

    def _generate_mac(self, interface_idx: int) -> str:
        """Generate deterministic MAC address."""
        # Use a stable MAC based on VM name and interface index
        hash_base: bytes = f"{self.config.name}{interface_idx}".encode()
        import hashlib

        h: bytes = hashlib.md5(hash_base).digest()
        # Format: 52:54:00:xx:xx:xx (QEMU OUI)
        return f"52:54:00:{h[0]:02x}:{h[1]:02x}:{h[2]:02x}"

    def start(self) -> None:
        """Create and start or resume the VM via libvirt."""
        # Generate domain XML (which creates the COW disk)
        try:
            xml: str = self._generate_domain_xml()
        except RuntimeError as e:
            raise RuntimeError(f"Failed to prepare VM disk: {e}")

        conn: libvirt.virConnect = self._get_conn()
        try:
            # If domain exists, handle existing state or redefine
            dom = None
            try:
                dom = conn.lookupByName(self.config.name)
            except libvirt.libvirtError:
                dom = None

            if dom is not None:
                state, _ = dom.state()
                if state == libvirt.VIR_DOMAIN_PAUSED:
                    dom.resume()
                    return
                if state == libvirt.VIR_DOMAIN_RUNNING:
                    return
                # Undefine to refresh XML for shutoff/crashed domains
                # Use flags to handle managed save images and snapshots
                undefine_flags: int = (
                    libvirt.VIR_DOMAIN_UNDEFINE_MANAGED_SAVE
                    | libvirt.VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA
                )
                try:
                    dom.undefineFlags(undefine_flags)
                except libvirt.libvirtError:
                    try:
                        dom.undefine()
                    except libvirt.libvirtError:
                        pass

            # Define and start
            dom = conn.defineXML(xml)
            if dom is None:
                raise RuntimeError(f"Failed to define domain {self.config.name}")

            try:
                dom.create()
            except libvirt.libvirtError as e:
                msg = str(e)
                if "Permission denied" in msg and "process exited" in msg:
                    raise RuntimeError(
                        f"{msg}\n"
                        "Hint: AppArmor may be blocking QEMU from reading ~/.netsim images.\n"
                        "Fix: set 'security_driver = \"none\"' in /etc/libvirt/qemu.conf "
                        "and restart libvirtd."
                    ) from e
                raise

            # Wait for VM to be running
            timeout = 10
            start_time: float = time.time()
            while True:
                state, _ = dom.state()
                if state == libvirt.VIR_DOMAIN_RUNNING:
                    return
                if time.time() - start_time > timeout:
                    raise RuntimeError(
                        f"VM {self.config.name} failed to start within {timeout}s"
                    )
                time.sleep(0.2)
        finally:
            conn.close()

    def stop(self) -> None:
        """Suspend the VM (keep memory for fast resume)."""
        try:
            conn: libvirt.virConnect = self._get_conn()
            try:
                dom: libvirt.virDomain[libvirt.virConnect] = conn.lookupByName(
                    self.config.name
                )
            except libvirt.libvirtError:
                return
            state, _ = dom.state()
            if state == libvirt.VIR_DOMAIN_RUNNING:
                dom.suspend()
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def destroy(self) -> None:
        """Permanently delete the VM and its data."""
        conn: libvirt.virConnect = self._get_conn()
        try:
            try:
                dom: libvirt.virDomain[libvirt.virConnect] = conn.lookupByName(
                    self.config.name
                )
            except libvirt.libvirtError:
                dom = None

            if dom is not None:
                state, _ = dom.state()
                if state == libvirt.VIR_DOMAIN_RUNNING:
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
                    try:
                        dom.undefine()
                    except libvirt.libvirtError:
                        pass

            # Remove runtime artifacts for this VM (COW disk, XML)
            try:
                if self.vm_dir.exists():
                    for child in self.vm_dir.iterdir():
                        try:
                            if child.is_file():
                                child.unlink()
                        except Exception:
                            pass
                    self.vm_dir.rmdir()
            except Exception:
                pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def is_running(self) -> bool:
        """Check if VM is running."""
        try:
            conn: libvirt.virConnect = self._get_conn()
            try:
                dom: libvirt.virDomain[libvirt.virConnect] = conn.lookupByName(
                    self.config.name
                )
            except libvirt.libvirtError:
                return False
            state, _ = dom.state()
            return state == libvirt.VIR_DOMAIN_RUNNING
        except Exception:
            return False
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _get_conn(self) -> libvirt.virConnect:
        """Open a libvirt connection."""
        from netsim.libvirt_utils import open_with_timeout

        uri: str = os.environ.get("NETSIM_LIBVIRT_URI", "qemu:///system")
        return open_with_timeout(uri)
