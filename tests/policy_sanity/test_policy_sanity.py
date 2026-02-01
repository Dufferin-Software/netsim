# Copyright (c) Dufferin Software

"""
Two node policy engine sanity tests, tests basic features such as logging, dropping, and forwarding.
"""

import logging
import pytest
from tests.conftest import BaseTopologyTests
from tests.systemd_utils import (
    get_service_status,
    start_service,
    stop_service,
)

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def policy_engine_service(nodes, install_user_packages):
    """
    Module-level fixture that starts policy-engine on the server node.

    Starts the service once for all tests in this module and stops it after.
    Skips all tests if the service is not installed.
    """
    server = nodes["server"]

    # Check if the service unit exists (package was installed)
    check_result = server.ssh_command(
        "systemctl cat policy-engine.service >/dev/null 2>&1 && echo EXISTS || echo MISSING"
    )
    if "MISSING" in check_result:
        pytest.skip("policy-engine.service not installed (use --install-packages)")

    # Start the service
    status = start_service(server, "policy-engine")
    if not status.is_healthy:
        pytest.fail(f"Failed to start policy-engine: {status.status_text}")

    logger.info(f"policy-engine running with PID {status.main_pid}")

    yield status

    # Cleanup: stop the service
    logger.info("Stopping policy-engine service...")
    try:
        stop_service(server, "policy-engine")
    except Exception as e:
        logger.warning(f"Failed to stop policy-engine: {e}")


class TestTwoNodePolicy(BaseTopologyTests):
    """Test basic policy engine features between two nodes.

    Inherits standard validation tests from BaseTopologyTests.
    """

    def test_two_nodes_exist(self, topology):
        """Verify topology has exactly two nodes."""
        assert len(topology.nodes) == 2, "Policy topology should have exactly 2 nodes"
        assert topology.nodes[0].name == "server"
        assert topology.nodes[1].name == "client"

    def test_policy_engine_service_running(self, nodes, policy_engine_service):
        """Verify policy-engine service is running and healthy."""
        server = nodes["server"]

        # Verify it started correctly
        assert policy_engine_service.is_healthy, (
            f"Service should be healthy, got: {policy_engine_service.status_text}"
        )
        assert policy_engine_service.main_pid is not None, "Service should have a PID"

        # Double-check current status
        status = get_service_status(server, "policy-engine")
        assert status.is_healthy, (
            f"Service should still be healthy, got: {status.status_text}"
        )
        logger.info(f"policy-engine confirmed running with PID {status.main_pid}")
