# Copyright (c) Dufferin Software

"""Libvirt utilities for VM management."""

import logging

logger = logging.getLogger(__name__)


def cleanup_leftover_vms(topology):
    """Clean up any leftover VMs from previous failed runs.

    Args:
        topology: Topology object with nodes to clean
    """
    logger.info("Checking for leftover VMs from previous runs...")
    try:
        import libvirt

        conn = libvirt.open("qemu:///session")
        if conn:
            for node in topology.nodes:
                try:
                    dom = conn.lookupByName(node.name)
                    logger.warning(f"Found leftover VM: {node.name}, destroying it")
                    if dom.isActive():
                        dom.destroy()
                    dom.undefine()
                except libvirt.libvirtError:
                    pass  # VM doesn't exist, good
            conn.close()
    except Exception as e:
        logger.debug(f"Pre-cleanup check: {e}")


def log_vm_count(topology):
    """Log VM count for debugging.

    Args:
        topology: Topology object for comparison
    """
    try:
        import libvirt

        conn = libvirt.open("qemu:///session")
        if conn:
            all_domains = conn.listAllDomains()
            logger.info(f"Total VMs in libvirt session: {len(all_domains)}")
            if len(all_domains) > len(topology.nodes):
                logger.warning(
                    f"⚠ Expected {len(topology.nodes)} VMs, found {len(all_domains)}!"
                )
                for dom in all_domains:
                    logger.warning(f"  - {dom.name()}")
            conn.close()
    except Exception:
        pass
