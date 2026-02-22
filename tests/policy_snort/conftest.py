import logging
from typing import Union

import netaddr
import pytest

from tests.systemd_utils import restart_service, stop_service
from tests.policy_client import PolicyClient
from tests.graphql_policy_client import GraphQLPolicyClient


logger = logging.getLogger(__name__)


AnyPolicyClient = Union[PolicyClient, GraphQLPolicyClient]


@pytest.fixture(scope="package")
def policy_engine_service(nodes, install_user_packages):
    """
    Package-level fixture that starts policy-engine on the server node.

    Starts the service once for all tests in this package and stops it after.
    Skips tests if the service unit is not installed.
    """
    server = nodes["server"]

    check_result = server.ssh_command(
        "systemctl cat policy-engine.service >/dev/null 2>&1 && echo EXISTS || echo MISSING"
    )
    if "MISSING" in check_result:
        pytest.skip("policy-engine.service not installed (use --install-packages)")

    status = restart_service(server, "policy-engine")
    if not status.is_healthy:
        pytest.fail(f"Failed to start policy-engine: {status.status_text}")

    logger.info(f"policy-engine running with PID {status.main_pid}")

    yield status

    logger.info("Stopping policy-engine service...")
    try:
        stop_service(server, "policy-engine")
    except Exception as e:
        logger.warning(f"Failed to stop policy-engine: {e}")


@pytest.fixture(scope="package")
def nmap_installed(nodes, install_packages):
    """Ensure nmap is installed on the client for nping."""
    nodes["client"]
    install_packages("client", ["nmap"])
    yield


@pytest.fixture(scope="package")
def nmap_installed_server(nodes, install_packages):
    """Ensure nmap is installed on the server for nping (egress traffic tests)."""
    nodes["server"]
    install_packages("server", ["nmap"])
    yield


@pytest.fixture(scope="module", params=["cli", "graphql"], ids=["cli", "graphql"])
def client_type(request):
    """Parameterized fixture for client type."""
    return request.param


@pytest.fixture(scope="package")
def cli_policy_client(nodes, policy_engine_service):
    """Create a CLI PolicyClient instance for the server."""
    server = nodes["server"]
    return PolicyClient(server)


@pytest.fixture(scope="package")
def graphql_policy_client(nodes, policy_engine_service):
    """Create a GraphQL PolicyClient instance for the server."""
    server = nodes["server"]
    return GraphQLPolicyClient(server)


@pytest.fixture(scope="module")
def policy_client(
    client_type, cli_policy_client, graphql_policy_client
) -> AnyPolicyClient:
    """
    Parameterized policy client fixture.

    Returns either the CLI client or GraphQL client based on client_type.
    Tests using this fixture will run twice: once with CLI, once with GraphQL.
    """
    if client_type == "cli":
        return cli_policy_client
    else:
        return graphql_policy_client


@pytest.fixture(scope="package")
def graphql_client(nodes, policy_engine_service):
    """GraphQL-only client fixture for Snort-specific tests."""
    server = nodes["server"]
    return GraphQLPolicyClient(server)


@pytest.fixture(scope="package")
def snort_support(graphql_client):
    """Assert that the server reports snortSupport=true, skip suite if not."""
    query = """
    query {
        status {
            snortSupport
        }
    }
    """
    data = graphql_client._execute_graphql(query)
    if "__error__" in data:
        pytest.fail(f"GraphQL error querying snortSupport: {data['__error__']}")
    snort_support_val = data.get("status", {}).get("snortSupport")
    if snort_support_val is None:
        pytest.fail(f"snortSupport field missing from status response: {data!r}")
    if not snort_support_val:
        pytest.skip("Server was not built with --features snort")
    yield True


@pytest.fixture(scope="package")
def server_interface(node_interfaces):
    """Get the server's interface on net1."""
    server_ifaces = node_interfaces["server"]
    return server_ifaces["net1"]


@pytest.fixture(scope="package")
def client_interface(node_interfaces):
    """Get the client's interface on net1."""
    client_ifaces = node_interfaces["client"]
    return client_ifaces["net1"]


@pytest.fixture(scope="package")
def server_ip_v4(server_interface) -> netaddr.IPAddress:
    ip = server_interface.get_ip_address()
    if ip is None:
        pytest.skip("No IPv4 address configured on server interface")
    return ip


@pytest.fixture(scope="package")
def client_ip_v4(client_interface) -> netaddr.IPAddress:
    ip = client_interface.get_ip_address()
    if ip is None:
        pytest.skip("No IPv4 address configured on client interface")
    return ip


@pytest.fixture(scope="package")
def server_network_v4(server_interface):
    network = server_interface.get_ipv4_network()
    if network is None:
        pytest.skip("No IPv4 address configured on server interface")
    return str(network)


@pytest.fixture(scope="package")
def client_network_v4(client_interface):
    network = client_interface.get_ipv4_network()
    if network is None:
        pytest.skip("No IPv4 address configured on client interface")
    return str(network)


@pytest.fixture(scope="function")
def attached_ingress(graphql_client, server_interface, configure_node_interfaces, snort_support):
    """Attach ingress program before test and detach after."""
    iface_name = server_interface.if_name

    result = graphql_client.attach_ingress(iface_name)
    if not result.success:
        pytest.fail(f"Failed to attach ingress: {result.message}")

    logger.info(f"Ingress attached to {iface_name}")
    yield iface_name

    try:
        graphql_client.detach_ingress(iface_name)
        logger.info(f"Ingress detached from {iface_name}")
    except Exception as e:
        logger.warning(f"Failed to detach ingress: {e}")


@pytest.fixture(scope="function")
def attached_egress(graphql_client, server_interface, configure_node_interfaces, snort_support):
    """Attach egress program before test and detach after."""
    iface_name = server_interface.if_name

    result = graphql_client.attach_egress(iface_name)
    if not result.success:
        pytest.fail(f"Failed to attach egress: {result.message}")

    logger.info(f"Egress attached to {iface_name}")
    yield iface_name

    try:
        graphql_client.detach_egress(iface_name)
        logger.info(f"Egress detached from {iface_name}")
    except Exception as e:
        logger.warning(f"Failed to detach egress: {e}")


@pytest.fixture(scope="function")
def clean_ingress_rules(graphql_client, snort_support):
    """Flush ingress rules before and after each test."""
    graphql_client.flush_rules(direction="ingress")
    yield
    graphql_client.flush_rules(direction="ingress")


@pytest.fixture(scope="function")
def clean_egress_rules(graphql_client, snort_support):
    """Flush egress rules before and after each test."""
    graphql_client.flush_rules(direction="egress")
    yield
    graphql_client.flush_rules(direction="egress")
