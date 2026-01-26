"""
Libvirt (KVM/QEMU) VM management.
"""

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

    def __post_init__(self):
        # Ensure tap_devices is always a list for mypy and runtime safety
        if self.tap_devices is None:
            self.tap_devices = []


class LibvirtVM:
    """Manager for a single KVM/QEMU VM via libvirt."""

    def __init__(self, config: VMConfig, runtime_dir: str = "/tmp/netsim"):
        """
        Initialize libvirt VM.

        Args:
            config: VM configuration
            runtime_dir: Directory for VM runtime data
        """
        self.config = config
        self.runtime_dir = Path(runtime_dir)
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self.vm_dir = self.runtime_dir / config.name
        self.vm_dir.mkdir(exist_ok=True)

    def _generate_domain_xml(self) -> str:
        """Generate libvirt domain XML configuration."""
        # Create disk image as copy-on-write layer
        disk_path = self.vm_dir / f"{self.config.name}.qcow2"
        self._create_cow_disk(disk_path)

        # Build domain XML
        domain = ET.Element("domain", type="kvm")

        # Name
        ET.SubElement(domain, "name").text = self.config.name

        # Memory (in MiB)
        ET.SubElement(domain, "memory", unit="MiB").text = str(self.config.memory_mb)
        ET.SubElement(domain, "currentMemory", unit="MiB").text = str(
            self.config.memory_mb
        )

        # vCPU
        vcpu_elem = ET.SubElement(domain, "vcpu")
        vcpu_elem.set("placement", "static")
        vcpu_elem.text = str(self.config.vcpus)

        # OS boot
        os_elem = ET.SubElement(domain, "os")
        ET.SubElement(os_elem, "type", arch="x86_64", machine="pc").text = "hvm"
        ET.SubElement(os_elem, "boot", dev="hd")

        # Devices
        devices = ET.SubElement(domain, "devices")

        # Emulator
        ET.SubElement(devices, "emulator").text = "/usr/bin/qemu-system-x86_64"

        # Controller for CD-ROM (SATA)
        controller = ET.SubElement(devices, "controller", type="sata", index="0")
        ET.SubElement(
            controller,
            "address",
            type="pci",
            domain="0x0000",
            bus="0x00",
            slot="0x04",
            function="0x0",
        )

        # Disk
        disk = ET.SubElement(devices, "disk", type="file", device="disk")
        ET.SubElement(disk, "driver", name="qemu", type="qcow2")
        ET.SubElement(disk, "source", file=str(disk_path))
        ET.SubElement(disk, "target", dev="vda", bus="virtio")
        ET.SubElement(
            disk,
            "address",
            type="pci",
            domain="0x0000",
            bus="0x00",
            slot="0x02",
            function="0x0",
        )

        # Cloud-init ISO (if provided)
        if self.config.cloudinit_iso:
            iso_disk = ET.SubElement(devices, "disk", type="file", device="cdrom")
            ET.SubElement(iso_disk, "driver", name="qemu", type="raw")
            ET.SubElement(iso_disk, "source", file=str(self.config.cloudinit_iso))
            ET.SubElement(iso_disk, "target", dev="sda", bus="sata")
            ET.SubElement(iso_disk, "readonly")

        # Serial console
        serial = ET.SubElement(devices, "serial", type="pty")
        ET.SubElement(serial, "target", port="0")

        console = ET.SubElement(devices, "console", type="pty")
        ET.SubElement(console, "target", type="serial", port="0")

        # Graphics (VNC)
        ET.SubElement(devices, "graphics", type="vnc", port="-1", autoport="yes")

        # Disable virtio balloon to avoid PCI slot collisions with manually placed NICs
        ET.SubElement(devices, "memballoon", model="none")

        # Add QEMU command-line arguments for networking with explicit PCI slots to avoid collisions
        domain.set("xmlns:qemu", "http://libvirt.org/schemas/domain/qemu/1.0")
        qemu_cmd = ET.SubElement(
            domain, "{http://libvirt.org/schemas/domain/qemu/1.0}commandline"
        )

        # Management interface: user-mode with hostfwd to guest ssh
        if self.config.mgmt_ssh_port:
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
                value=f"virtio-net-pci,netdev=mgmt,mac={self._generate_mac(0)},bus=pci.0,addr=0x5",
            )

        # Data interfaces: pre-created tap devices
        for idx, tap_dev in enumerate(self.config.tap_devices, start=1):
            ET.SubElement(
                qemu_cmd,
                "{http://libvirt.org/schemas/domain/qemu/1.0}arg",
                value="-netdev",
            )
            ET.SubElement(
                qemu_cmd,
                "{http://libvirt.org/schemas/domain/qemu/1.0}arg",
                value=f"tap,id=net{idx},ifname={tap_dev},script=no,downscript=no",
            )
            ET.SubElement(
                qemu_cmd,
                "{http://libvirt.org/schemas/domain/qemu/1.0}arg",
                value="-device",
            )
            # Offset addresses to avoid collision with disk (0x2) and mgmt NIC (0x5)
            pci_addr = hex(5 + idx)
            ET.SubElement(
                qemu_cmd,
                "{http://libvirt.org/schemas/domain/qemu/1.0}arg",
                value=f"virtio-net-pci,netdev=net{idx},mac={self._generate_mac(idx)},bus=pci.0,addr={pci_addr}",
            )

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

            logger = logging.getLogger(__name__)
            logger.debug(f"Creating COW disk for {self.config.name}")
            logger.debug(f"  Base image: {base_image}")
            logger.debug(f"  COW disk: {disk_path}")

            # Ensure parent directory exists and is writable
            disk_path.parent.mkdir(parents=True, exist_ok=True)

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
        hash_base = f"{self.config.name}{interface_idx}".encode()
        import hashlib

        h = hashlib.md5(hash_base).digest()
        # Format: 52:54:00:xx:xx:xx (QEMU OUI)
        return f"52:54:00:{h[0]:02x}:{h[1]:02x}:{h[2]:02x}"

    def start(self):
        """Create and start or resume the VM via libvirt."""
        # Generate domain XML (which creates the COW disk)
        try:
            xml = self._generate_domain_xml()
        except RuntimeError as e:
            raise RuntimeError(f"Failed to prepare VM disk: {e}")

        conn = self._get_conn()
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
                try:
                    dom.undefine()
                except libvirt.libvirtError:
                    pass

            # Define and start
            dom = conn.defineXML(xml)
            if dom is None:
                raise RuntimeError(f"Failed to define domain {self.config.name}")

            dom.create()

            # Wait for VM to be running
            timeout = 10
            start_time = time.time()
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

    def stop(self):
        """Suspend the VM (keep memory for fast resume)."""
        try:
            conn = self._get_conn()
            try:
                dom = conn.lookupByName(self.config.name)
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

    def destroy(self):
        """Permanently delete the VM and its data."""
        conn = self._get_conn()
        try:
            try:
                dom = conn.lookupByName(self.config.name)
            except libvirt.libvirtError:
                dom = None

            if dom is not None:
                state, _ = dom.state()
                if state == libvirt.VIR_DOMAIN_RUNNING:
                    dom.destroy()
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
            conn = self._get_conn()
            try:
                dom = conn.lookupByName(self.config.name)
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

    def get_info(self) -> dict:
        """Get VM information."""
        conn = self._get_conn()
        try:
            try:
                dom = conn.lookupByName(self.config.name)
            except libvirt.libvirtError:
                return {"state": "undefined"}

            info = dom.info()
            state = info[0]
            return {
                "name": self.config.name,
                "state": self._state_to_str(state),
                "memory_mb": int(info[2] / 1024),
                "max_memory_mb": int(info[1] / 1024),
                "vcpus": int(info[3]),
            }
        except Exception:
            return {"state": "error"}
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _get_conn(self) -> libvirt.virConnect:
        """Open a libvirt connection (session by default)."""
        uri = os.environ.get("NETSIM_LIBVIRT_URI", "qemu:///session")
        conn = libvirt.open(uri)
        if conn is None:
            raise RuntimeError(f"Failed to open libvirt connection to {uri}")
        return conn

    @staticmethod
    def _state_to_str(state: int) -> str:
        mapping = {
            libvirt.VIR_DOMAIN_NOSTATE: "nostate",
            libvirt.VIR_DOMAIN_RUNNING: "running",
            libvirt.VIR_DOMAIN_BLOCKED: "blocked",
            libvirt.VIR_DOMAIN_PAUSED: "paused",
            libvirt.VIR_DOMAIN_SHUTDOWN: "shutdown",
            libvirt.VIR_DOMAIN_SHUTOFF: "shutoff",
            libvirt.VIR_DOMAIN_CRASHED: "crashed",
            libvirt.VIR_DOMAIN_PMSUSPENDED: "pmsuspended",
        }
        return mapping.get(state, "unknown")
