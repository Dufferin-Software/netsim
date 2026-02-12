import logging
import pytest


logger = logging.getLogger(__name__)


@pytest.fixture(scope="function")
def attached_egress(policy_client, server_interface):
    """
    Fixture that attaches egress program before test and detaches after.

    Yields the interface name.
    """
    iface_name = server_interface.if_name

    # Attach egress
    result = policy_client.attach_egress(iface_name)
    if not result.success:
        pytest.fail(f"Failed to attach egress: {result.message}")

    logger.info(f"Egress attached to {iface_name}")
    yield iface_name

    # Detach egress
    try:
        policy_client.detach_egress(iface_name)
        logger.info(f"Egress detached from {iface_name}")
    except Exception as e:
        logger.warning(f"Failed to detach egress: {e}")


@pytest.fixture(scope="function")
def clean_egress_rules(policy_client):
    """Fixture to ensure egress rules are cleaned up before and after each test."""
    policy_client.flush_rules(direction="egress")
    yield
    policy_client.flush_rules(direction="egress")
