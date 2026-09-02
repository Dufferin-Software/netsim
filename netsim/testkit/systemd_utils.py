# Copyright (c) Peter Morrow

"""Systemd service utilities for test infrastructure."""

import logging
import subprocess
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Dict, Optional

import pytest

from .node import Node

logger = logging.getLogger(__name__)


@dataclass
class ServiceStatus:
    """Status information for a systemd service."""

    name: str
    active: bool
    running: bool
    enabled: bool
    status_text: str  # e.g., "active (running)", "inactive (dead)"
    main_pid: Optional[int] = None

    @property
    def is_healthy(self) -> bool:
        """Check if service is active and running."""
        return self.active and self.running


def get_service_status(node: Node, service_name: str) -> ServiceStatus:
    """
    Get the status of a systemd service on a node.

    Args:
        node: Node to query
        service_name: Name of the service (with or without .service suffix)

    Returns:
        ServiceStatus with current state information
    """
    # Normalize service name
    if not service_name.endswith(".service"):
        service_name = f"{service_name}.service"

    # Get active state
    try:
        active_state = node.ssh_command(
            f"systemctl is-active {service_name} 2>/dev/null || true"
        ).strip()
    except subprocess.CalledProcessError:
        active_state = "unknown"

    # Get enabled state
    try:
        enabled_state = node.ssh_command(
            f"systemctl is-enabled {service_name} 2>/dev/null || true"
        ).strip()
    except subprocess.CalledProcessError:
        enabled_state = "unknown"

    # Get detailed status
    try:
        status_output = node.ssh_command(
            f"systemctl show {service_name} --property=ActiveState,SubState,MainPID --no-pager 2>/dev/null || true",
            timeout=15,
        )
        props = {}
        for line in status_output.strip().split("\n"):
            if "=" in line:
                key, value = line.split("=", 1)
                props[key] = value

        active_state = props.get("ActiveState", active_state)
        sub_state = props.get("SubState", "unknown")
        main_pid_str = props.get("MainPID", "0")
        main_pid = int(main_pid_str) if main_pid_str.isdigit() else None
        if main_pid == 0:
            main_pid = None
    except subprocess.CalledProcessError:
        sub_state = "unknown"
        main_pid = None

    status_text = f"{active_state} ({sub_state})"
    is_active = active_state == "active"
    is_running = sub_state == "running"
    is_enabled = enabled_state == "enabled"

    logger.debug(f"[{node.name}] {service_name}: {status_text}, PID={main_pid}")

    return ServiceStatus(
        name=service_name,
        active=is_active,
        running=is_running,
        enabled=is_enabled,
        status_text=status_text,
        main_pid=main_pid,
    )


def start_service(node: Node, service_name: str, timeout: int = 30) -> ServiceStatus:
    """
    Start a systemd service on a node.

    Args:
        node: Node to operate on
        service_name: Name of the service
        timeout: Timeout for the operation

    Returns:
        ServiceStatus after starting

    Raises:
        subprocess.CalledProcessError: If start fails
    """
    if not service_name.endswith(".service"):
        service_name = f"{service_name}.service"

    logger.info(f"[{node.name}] Starting {service_name}...")
    node.ssh_command(f"sudo systemctl start {service_name}", timeout=timeout)

    status = get_service_status(node, service_name)
    if status.is_healthy:
        logger.info(f"[{node.name}] ✓ {service_name} started (PID={status.main_pid})")
    else:
        logger.warning(
            f"[{node.name}] {service_name} start returned but status is {status.status_text}"
        )

    return status


def stop_service(node: Node, service_name: str, timeout: int = 30) -> ServiceStatus:
    """
    Stop a systemd service on a node.

    Args:
        node: Node to operate on
        service_name: Name of the service
        timeout: Timeout for the operation

    Returns:
        ServiceStatus after stopping

    Raises:
        subprocess.CalledProcessError: If stop fails
    """
    if not service_name.endswith(".service"):
        service_name = f"{service_name}.service"

    logger.info(f"[{node.name}] Stopping {service_name}...")
    node.ssh_command(f"sudo systemctl stop {service_name}", timeout=timeout)

    status = get_service_status(node, service_name)
    if not status.active:
        logger.info(f"[{node.name}] ✓ {service_name} stopped")
    else:
        logger.warning(
            f"[{node.name}] {service_name} stop returned but status is {status.status_text}"
        )

    return status


def restart_service(node: Node, service_name: str, timeout: int = 30) -> ServiceStatus:
    """
    Restart a systemd service on a node.

    Args:
        node: Node to operate on
        service_name: Name of the service
        timeout: Timeout for the operation

    Returns:
        ServiceStatus after restarting

    Raises:
        subprocess.CalledProcessError: If restart fails
    """
    if not service_name.endswith(".service"):
        service_name = f"{service_name}.service"

    logger.info(f"[{node.name}] Restarting {service_name}...")
    node.ssh_command(f"sudo systemctl restart {service_name}", timeout=timeout)

    status = get_service_status(node, service_name)
    if status.is_healthy:
        logger.info(f"[{node.name}] ✓ {service_name} restarted (PID={status.main_pid})")
    else:
        logger.warning(
            f"[{node.name}] {service_name} restart returned but status is {status.status_text}"
        )

    return status


def enable_service(node: Node, service_name: str) -> None:
    """
    Enable a systemd service on a node.

    Args:
        node: Node to operate on
        service_name: Name of the service
    """
    if not service_name.endswith(".service"):
        service_name = f"{service_name}.service"

    logger.info(f"[{node.name}] Enabling {service_name}...")
    node.ssh_command(f"sudo systemctl enable {service_name}")
    logger.info(f"[{node.name}] ✓ {service_name} enabled")


def disable_service(node: Node, service_name: str) -> None:
    """
    Disable a systemd service on a node.

    Args:
        node: Node to operate on
        service_name: Name of the service
    """
    if not service_name.endswith(".service"):
        service_name = f"{service_name}.service"

    logger.info(f"[{node.name}] Disabling {service_name}...")
    node.ssh_command(f"sudo systemctl disable {service_name}")
    logger.info(f"[{node.name}] ✓ {service_name} disabled")


# Pytest fixture for managing systemd services
@pytest.fixture(scope="function")
def systemd_service(nodes: Dict[str, Node]):
    """
    Fixture for managing systemd services on nodes.

    Returns a context manager that starts a service and stops it on cleanup.

    Usage:
        def test_example(systemd_service):
            with systemd_service("server", "nginx") as status:
                assert status.is_healthy
                # Service is running here
            # Service is automatically stopped after the with block

        # Or start on multiple nodes:
        def test_multi(systemd_service):
            with systemd_service("server", "my-service") as s1:
                with systemd_service("client", "my-service") as s2:
                    # Both services running
    """

    @contextmanager
    def _manage_service(node_name: str, service_name: str, timeout: int = 30):
        """
        Context manager to start a service and ensure cleanup.

        Args:
            node_name: Name of the node (must exist in nodes dict)
            service_name: Name of the systemd service
            timeout: Timeout for start/stop operations

        Yields:
            ServiceStatus after starting
        """
        if node_name not in nodes:
            raise ValueError(
                f"Unknown node: {node_name}. Available: {list(nodes.keys())}"
            )

        node = nodes[node_name]
        status = start_service(node, service_name, timeout=timeout)

        if not status.is_healthy:
            raise RuntimeError(
                f"Failed to start {service_name} on {node_name}: {status.status_text}"
            )

        try:
            yield status
        finally:
            # Always try to stop the service on cleanup
            try:
                stop_service(node, service_name, timeout=timeout)
            except Exception as e:
                logger.warning(f"Failed to stop {service_name} on {node_name}: {e}")

    return _manage_service
