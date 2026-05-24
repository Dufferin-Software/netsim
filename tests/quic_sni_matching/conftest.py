# Copyright (c) Dufferin Software

"""
QUIC SNI matching test suite fixtures.

End-to-end exercise of the BPF tail-call → userspace QUIC Initial
decryption → ClientHello SNI extraction → flow_verdict_cache path
implemented by policy-engine Phase 3.

Tests are parameterized to run against both the CLI and GraphQL
clients, matching the convention used by the ips_ids suite.
"""

import logging
import time
from pathlib import Path
from typing import Union

import netaddr
import pytest

from tests.systemd_utils import restart_service, stop_service
from lib.policy_engine.engine.cli.client import PolicyClient, PolicyAction
from lib.policy_engine.engine.graphql.client import GraphQLPolicyClient

logger = logging.getLogger(__name__)

AnyPolicyClient = Union[PolicyClient, GraphQLPolicyClient]

_POLICY_ENGINE_URL = "http://127.0.0.1:8080/graphql"
_HTTP_READY_TIMEOUT = 30  # seconds
_HTTP_READY_INTERVAL = 0.5

# Local helper script that fires a single real QUIC v1 Initial with a
# chosen SNI.  Copied onto the client node by the quic_sender fixture.
_QUIC_SEND_SCRIPT_LOCAL = Path(__file__).parent / "quic_sni_send.py"
_QUIC_SEND_SCRIPT_REMOTE = "/usr/local/bin/quic_sni_send.py"


# ============================================================================
# Policy engine service
# ============================================================================


def _wait_for_policy_engine_http(server, timeout: int = _HTTP_READY_TIMEOUT) -> None:
    """Block until policy-engine's HTTP socket on :8080 is accepting connections."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            out = server.ssh_command(
                f"curl -s -o /dev/null -w '%{{http_code}}' "
                f"--max-time 2 {_POLICY_ENGINE_URL} 2>/dev/null || true",
                timeout=10,
            )
            if out.strip() and out.strip() != "000":
                logger.info("policy-engine HTTP server is ready")
                return
        except Exception:
            pass
        time.sleep(_HTTP_READY_INTERVAL)
    pytest.fail(f"policy-engine HTTP server did not become ready within {timeout}s")


@pytest.fixture(scope="package")
def policy_engine_service(nodes, install_user_packages):
    """Start policy-engine on the server node for the duration of the package."""
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
    _wait_for_policy_engine_http(server)

    yield status

    logger.info("Stopping policy-engine service...")
    try:
        stop_service(server, "policy-engine")
    except Exception as e:
        logger.warning(f"Failed to stop policy-engine: {e}")


# ============================================================================
# Client parameterization (cli / graphql)
# ============================================================================


@pytest.fixture(scope="module", params=["cli", "graphql"], ids=["cli", "graphql"])
def client_type(request):
    return request.param


@pytest.fixture(scope="package")
def cli_policy_client(nodes, policy_engine_service):
    return PolicyClient(nodes["server"])


@pytest.fixture(scope="package")
def graphql_policy_client(nodes, policy_engine_service):
    return GraphQLPolicyClient(nodes["server"])


@pytest.fixture(scope="module")
def policy_client(
    client_type, cli_policy_client, graphql_policy_client
) -> AnyPolicyClient:
    if client_type == "cli":
        return cli_policy_client
    return graphql_policy_client


# ============================================================================
# Interface + IP fixtures
# ============================================================================


@pytest.fixture(scope="package")
def server_interface(node_interfaces):
    return node_interfaces["server"]["net1"]


@pytest.fixture(scope="package")
def client_interface(node_interfaces):
    return node_interfaces["client"]["net1"]


@pytest.fixture(scope="package")
def server_ip_v4(server_interface) -> netaddr.IPAddress:
    ip = server_interface.get_ip_address()
    if ip is None:
        pytest.skip("No IPv4 address configured on server interface")
    return ip


@pytest.fixture(scope="package")
def client_network_v4(client_interface):
    network = client_interface.get_ipv4_network()
    if network is None:
        pytest.skip("No IPv4 address configured on client interface")
    return str(network)


# ============================================================================
# Attachment + rule cleanup
# ============================================================================


@pytest.fixture(scope="function")
def attached_ingress(policy_client, server_interface, configure_node_interfaces):
    """Attach XDP ingress on the server's net1 interface for the duration of one test."""
    iface_name = server_interface.if_name
    result = policy_client.attach_ingress(iface_name)
    if not result.success:
        pytest.fail(f"Failed to attach ingress: {result.message}")
    logger.info(f"Ingress attached to {iface_name}")
    yield iface_name
    try:
        policy_client.detach_ingress(iface_name)
    except Exception as e:
        logger.warning(f"Failed to detach ingress: {e}")


@pytest.fixture(scope="function")
def clean_ingress_rules(policy_client, server_interface):
    """Flush ingress rules + flow verdicts before and after each test."""
    iface = server_interface.if_name
    policy_client.flush_rules(direction="ingress")
    policy_client.clear_flow_verdicts(direction="ingress")
    policy_client.set_default_action(
        PolicyAction.PASS, direction="ingress", interface=iface
    )
    yield
    policy_client.flush_rules(direction="ingress")
    policy_client.clear_flow_verdicts(direction="ingress")
    policy_client.set_default_action(
        PolicyAction.PASS, direction="ingress", interface=iface
    )


# ============================================================================
# Tooling on the client: aioquic + sender script
# ============================================================================


@pytest.fixture(scope="package")
def aioquic_installed(nodes, install_packages):
    """Install python3-aioquic on the client so the helper script can run."""
    install_packages("client", ["python3-aioquic"])
    yield


@pytest.fixture(scope="package")
def bpftool_installed(nodes, install_packages):
    """Install bpftool on the server so test failure diagnostics can dump the
    flow_verdict_cache map directly, bypassing libbpf-rs."""
    install_packages("server", ["bpftool"])
    yield


@pytest.fixture(scope="package")
def quic_sender(nodes, aioquic_installed):
    """
    Copy the QUIC-Initial sender script onto the client node and return a
    callable that fires one Initial with the given target + SNI.
    """
    client = nodes["client"]
    payload = _QUIC_SEND_SCRIPT_LOCAL.read_text()
    # `client.write_file` would be cleaner if available; fall back to a
    # base64-piped install that doesn't depend on a richer fixture surface.
    import base64

    encoded = base64.b64encode(payload.encode()).decode()
    client.ssh_command(
        f"echo '{encoded}' | base64 -d | sudo tee {_QUIC_SEND_SCRIPT_REMOTE} >/dev/null && "
        f"sudo chmod +x {_QUIC_SEND_SCRIPT_REMOTE}"
    )

    def _send(server_ip, server_port: int, sni: str) -> str:
        cmd = f"python3 {_QUIC_SEND_SCRIPT_REMOTE} {server_ip} {server_port} {sni}"
        out = client.ssh_command(cmd, timeout=15)
        logger.info(f"quic_sni_send: {out.strip()}")
        return out

    yield _send
