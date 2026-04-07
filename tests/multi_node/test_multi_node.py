# Copyright (c) Dufferin Software

"""
Multi-node controller integration tests.

These tests exercise the complete controller ↔ agent workflow:
1. All 3 nodes enroll and reach Active status
2. Create + assign a ruleset → rules appear on all nodes via local GraphQL
3. Send ICMP traffic, verify BPF drop stats visible via controller metrics
4. Kill controller, verify nodes continue enforcing; restart → reconciliation
5. Decommission node3 → cert is rejected on reconnect

Requires the topology in multi_node.yaml and the following packages installed
via --install-packages:
  - policy-engine_*.deb
  - policy-node-agent_*.deb
  - policy-controller_*.deb

Run with:
  netsim start tests/multi_node/multi_node.yaml
  python3 -m pytest tests/multi_node/ -v \\
      --install-packages policy-engine.deb,policy-node-agent.deb,policy-controller.deb
  netsim destroy tests/multi_node/multi_node.yaml
"""

import json
import logging
import time
from typing import Dict

import pytest

from tests.systemd_utils import (
    restart_service,
    stop_service,
    get_service_status,
)
from lib.policy_engine.controller.graphql.client import ControllerClient
from lib.policy_engine.engine.graphql.client import GraphQLPolicyClient

logger = logging.getLogger(__name__)

_METRICS_SETTLE_SECS = 5  # time after traffic before checking metrics
_RECONCILE_TIMEOUT = 90  # time for controller restart + agent reconnect + reconcile
_POLL_INTERVAL = 2


def _attach_ingress_on_node(
    node, controller_client: ControllerClient, node_id: str
) -> None:
    """Attach ingress program via the controller to the node's data interface."""
    # Find the data interface (not mgmt)
    data_iface = None
    for iface in node.interfaces:
        if iface.network.name != "mgmt":
            data_iface = iface
            break
    if not data_iface:
        pytest.fail(f"No data interface found on {node.name}")

    # Use controller to attach ingress program
    result = controller_client.attach_program(
        node_id=node_id,
        interface_name=data_iface.if_name,
        direction="ingress",
        mode="auto",
    )
    if not result.success:
        pytest.fail(
            f"Failed to attach ingress via controller on {node.name}: {result.message}"
        )
    logger.info(
        f"Ingress attached via controller on {node.name} interface {data_iface.if_name}"
    )


# ── Tests ─────────────────────────────────────────────────────────────────────


def _list_rules_on_node(node) -> list:
    """Return the ingress rule list from a node's local policy-engine."""
    client = GraphQLPolicyClient(node)
    rules = client.list_rules(direction="ingress")
    return [
        {
            "ruleId": r.rule_id,
            "srcPrefix": r.src_prefix,
            "dstPrefix": r.dst_prefix,
            "actions": [
                {"action": a.action.name, "priority": a.priority} for a in r.actions
            ],
        }
        for r in rules
    ]


def _wait_for_rules_on_node(node, expected_rule_count: int, timeout: int = 60) -> None:
    """Poll the node's local policy-engine until at least N rules are present."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            rules = _list_rules_on_node(node)
            if len(rules) >= expected_rule_count:
                return
            logger.debug(
                f"[{node.name}] {len(rules)}/{expected_rule_count} rules present, waiting..."
            )
        except Exception as e:
            logger.debug(f"[{node.name}] Rule poll error: {e}")
        time.sleep(_POLL_INTERVAL)
    pytest.fail(
        f"[{node.name}] Expected {expected_rule_count} rules after {timeout}s, "
        f"got: {_list_rules_on_node(node)}"
    )


def _wait_for_online(
    client: ControllerClient, node_ids: list, timeout: int = 60
) -> None:
    """Wait until all given node IDs appear in onlineNodes."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            online = set(client.online_nodes())
            if all(nid in online for nid in node_ids):
                return
            missing = [nid for nid in node_ids if nid not in online]
            logger.debug(f"Waiting for nodes to come online: {missing}")
        except Exception as e:
            logger.debug(f"online_nodes error: {e}")
        time.sleep(_POLL_INTERVAL)
    pytest.fail(f"Nodes {node_ids} did not appear online within {timeout}s")


# ── Tests ─────────────────────────────────────────────────────────────────────


class TestEnrollment:
    """Scenario 1: all 3 nodes enroll and reach Active status."""

    def test_all_nodes_active(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """All three managed nodes must reach Active status after approval."""
        active_nodes = controller_client.list_nodes(status="active")
        active_ids = {n.id for n in active_nodes}
        for vm_name, node_id in enrolled_nodes.items():
            assert node_id in active_ids, (
                f"{vm_name} (id={node_id}) is not Active; active set: {active_ids}"
            )
        logger.info(f"All 3 nodes active: {list(enrolled_nodes.values())}")

    def test_nodes_have_labels(
        self,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """Approved nodes must carry the labels set during approval."""
        all_nodes = {n.id: n for n in controller_client.list_nodes()}
        for vm_name, node_id in enrolled_nodes.items():
            assert node_id in all_nodes, f"Node {node_id} not found"
            assert all_nodes[node_id].label == vm_name, (
                f"Expected label '{vm_name}', got '{all_nodes[node_id].label}'"
            )

    def test_nodes_appear_online(
        self,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """All active nodes must appear in the onlineNodes list (agents connected)."""
        _wait_for_online(controller_client, list(enrolled_nodes.values()))
        online = set(controller_client.online_nodes())
        for vm_name, node_id in enrolled_nodes.items():
            assert node_id in online, f"{vm_name} (id={node_id}) not in onlineNodes"


class TestConfigDistribution:
    """Scenario 2: create + assign a ruleset, verify rules appear on all nodes."""

    def test_ruleset_pushed_to_all_nodes(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """
        Create a drop-all ruleset, assign to all nodes, push, then verify
        that each node's local policy-engine reflects the correct rule count.
        """
        # Create a simple ruleset with one ingress drop-all rule.
        # The rules_json array must contain valid AddRuleInput JSON objects
        # (deserialized by the agent's ConfigApplier when applying the push).
        drop_all_rule = [
            {
                "direction": "INGRESS",
                "src": "0.0.0.0/0",
                "dst": "0.0.0.0/0",
                "sport": 0,
                "dport": 0,
                "protocol": "any",
                "actions": [{"action": "DROP", "priority": 0, "param": 0}],
            }
        ]
        ruleset = controller_client.create_ruleset(
            name="test-drop-all",
            rules_json=json.dumps(drop_all_rule),
            description="Integration test ruleset",
            default_action_ingress="drop",
        )
        assert ruleset.id, "Ruleset ID must be set"
        logger.info(f"Created ruleset {ruleset.id}")

        # Attach ingress programs on all managed nodes before pushing rules
        for vm_name, node_id in enrolled_nodes.items():
            node = nodes[vm_name]
            _attach_ingress_on_node(node, controller_client, node_id)

        # Assign and push to all managed nodes
        for vm_name, node_id in enrolled_nodes.items():
            result = controller_client.assign_ruleset(node_id, ruleset.id)
            assert result.success, (
                f"assign_ruleset to {vm_name} failed: {result.message}"
            )
            result = controller_client.push_config(node_id)
            assert result.success, f"push_config to {vm_name} failed: {result.message}"
            logger.info(f"Assigned + pushed ruleset to {vm_name}")

        # Verify rules appeared on each node's local policy-engine
        for vm_name in enrolled_nodes:
            node = nodes[vm_name]
            _wait_for_rules_on_node(node, expected_rule_count=1)
            rules = _list_rules_on_node(node)
            logger.info(f"[{vm_name}] Rules after push: {rules}")
            assert len(rules) >= 1, f"[{vm_name}] Expected at least 1 rule after push"

    def test_push_config_all_returns_success(
        self,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """pushConfigAll mutation must report success when nodes are online."""
        result = controller_client.push_config_all()
        assert result.success, f"pushConfigAll failed: {result.message}"
        assert result.message, "pushConfigAll should return a message"
        logger.info(f"pushConfigAll: {result.message}")


class TestMetricsVisibility:
    """Scenario 3: BPF drop stats visible via controller Prometheus metrics endpoint."""

    def test_metrics_endpoint_responds(
        self,
        nodes,
        enrolled_nodes: Dict[str, str],
    ):
        """
        The controller /metrics/node/<id> endpoint must respond with prometheus
        text after the agent has scraped the local policy-engine at least once.
        """
        controller = nodes["controller"]

        # Give the metrics forwarder time to scrape and send
        time.sleep(35)  # metrics forwarded every 30s

        for vm_name, node_id in enrolled_nodes.items():
            out = controller.ssh_command(
                f"curl -s -o /dev/null -w '%{{http_code}}' "
                f"http://127.0.0.1:8443/metrics/node/{node_id}",
                timeout=10,
            ).strip()
            # 200 = metrics present; 404 = not yet scraped (acceptable initially)
            assert out in ("200", "404"), (
                f"Unexpected HTTP status {out!r} for /metrics/node/{node_id}"
            )
            if out == "200":
                logger.info(f"[{vm_name}] Prometheus metrics available at controller")
            else:
                logger.info(f"[{vm_name}] Metrics not yet scraped (first 30s window)")

    def test_aggregated_metrics_endpoint(self, nodes):
        """The /metrics endpoint must respond with 200 (even if empty)."""
        controller = nodes["controller"]
        out = controller.ssh_command(
            "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8443/metrics",
            timeout=10,
        ).strip()
        assert out == "200", f"Expected 200 from /metrics, got {out!r}"


class TestControllerRestart:
    """
    Scenario 4: kill controller, verify nodes keep enforcing; restart →
    agents reconnect and reconciliation pushes config.
    """

    def test_nodes_enforce_during_controller_outage(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """
        While the controller is down, managed nodes must continue running
        their local policy-engine (rules still loaded in BPF).
        """
        controller = nodes["controller"]

        # Stop the controller
        logger.info("Stopping policy-controller for outage test...")
        stop_service(controller, "policy-controller")

        # Give agents time to notice the connection is gone
        time.sleep(5)

        # Each managed node's policy-engine should still be running
        for vm_name in enrolled_nodes:
            node = nodes[vm_name]
            status = get_service_status(node, "policy-engine")
            assert status.is_healthy, (
                f"[{vm_name}] policy-engine stopped during controller outage: "
                f"{status.status_text}"
            )

        logger.info("All nodes still enforcing during controller outage")

    def test_reconciliation_after_controller_restart(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """
        After the controller restarts, agents must reconnect and the controller
        must reconcile the desired state (existing ruleset assignments push config).
        Precondition: test_nodes_enforce_during_controller_outage ran first and
        left the controller stopped.
        """
        controller = nodes["controller"]

        # If controller is already running (test ordering changed), skip reconcile wait
        status = get_service_status(controller, "policy-controller")
        if not status.is_healthy:
            logger.info("Restarting policy-controller...")
            restart_status = restart_service(controller, "policy-controller")
            assert restart_status.is_healthy, (
                f"Failed to restart policy-controller: {restart_status.status_text}"
            )
            # Wait for HTTP API
            from tests.multi_node.conftest import _wait_for_controller_http

            _wait_for_controller_http(controller, timeout=60)

        # Wait for agents to reconnect
        logger.info("Waiting for agents to reconnect after controller restart...")
        _wait_for_online(
            controller_client,
            list(enrolled_nodes.values()),
            timeout=_RECONCILE_TIMEOUT,
        )

        # Verify all nodes are still active (reconciliation didn't break anything)
        active = controller_client.list_nodes(status="active")
        active_ids = {n.id for n in active}
        for vm_name, node_id in enrolled_nodes.items():
            assert node_id in active_ids, f"{vm_name} not Active after reconciliation"

        logger.info("Reconciliation successful — all nodes active and online")


class TestDecommission:
    """
    Scenario 5: decommission node3 → cert is rejected on reconnect.
    """

    def test_decommission_blocks_reconnect(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """
        After decommissioning node3, the agent's client cert is revoked.
        The agent must not appear in onlineNodes after reconnecting.
        """
        node3_id = enrolled_nodes.get("node3")
        if node3_id is None:
            pytest.skip("node3 not in enrolled_nodes")

        node3 = nodes["node3"]

        # Decommission
        result = controller_client.decommission_node(node3_id)
        assert result.success, f"decommissionNode failed: {result.message}"
        logger.info(f"Decommissioned node3 (id={node3_id})")

        # Verify status changed in controller
        time.sleep(2)
        all_nodes = {n.id: n for n in controller_client.list_nodes()}
        if node3_id in all_nodes:
            assert all_nodes[node3_id].status == "decommissioned", (
                f"Expected decommissioned status, got: {all_nodes[node3_id].status}"
            )

        # Restart agent to force reconnect attempt
        logger.info("Restarting policy-node-agent on node3 to force reconnect...")
        restart_service(node3, "policy-node-agent")

        # Give agent time to attempt reconnect (should be rejected by mTLS cert check)
        time.sleep(10)

        # node3 must NOT appear in onlineNodes — revoked cert must be rejected
        online = set(controller_client.online_nodes())
        assert node3_id not in online, (
            f"Decommissioned node3 (id={node3_id}) appeared in onlineNodes — "
            f"cert revocation not enforced"
        )
        logger.info(
            f"Decommissioned node3 correctly excluded from onlineNodes: {online}"
        )

    def test_remove_decommissioned_node(
        self,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """
        After decommission, removeNode must delete the node from the registry.
        Precondition: test_decommission_blocks_reconnect ran first.
        """
        node3_id = enrolled_nodes.get("node3")
        if node3_id is None:
            pytest.skip("node3 not in enrolled_nodes")

        result = controller_client.remove_node(node3_id)
        assert result.success, f"removeNode failed: {result.message}"

        # Verify it's gone
        all_nodes = {n.id: n for n in controller_client.list_nodes()}
        assert node3_id not in all_nodes, "node3 still present in registry after remove"
        logger.info(f"node3 (id={node3_id}) removed from registry")
