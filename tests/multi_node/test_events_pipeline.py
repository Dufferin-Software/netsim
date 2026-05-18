# Copyright (c) Dufferin Software

"""
Events pipeline + node-identity integration tests.

Covers the work that landed in docs/events-ui-todo.md:

  Phase 1 — DMI UUID populates on every enrolled node (agent runs with
            CAP_DAC_READ_SEARCH, controller COALESCEs the field).
  Phase 2 — every enrolled node has a non-empty hostname reported to the
            controller (the hostname column in the UI joins on this).
  Phase 4 — InterfaceReport carries ifindex; controller persists it on
            NodeInterface and on every forwarded flow event, so the UI
            can join (node_id, ifindex) → interface name without a per-
            node round trip.

Traffic test: install a log-only ingress rule on node1, ping from node2,
poll the controller's persisted-events store, and assert the events arrive
tagged with the right node_id and the ifindex of node1's data interface.

Run with:
  netsim start tests/multi_node/multi_node.yaml
  python3 -m pytest tests/multi_node/test_events_pipeline.py -v \\
      --install-packages policy-engine.deb,policy-node-agent.deb,policy-controller.deb
  netsim destroy tests/multi_node/multi_node.yaml
"""

import logging
import re
import time
from typing import Dict, List

import pytest

from lib.policy_engine.controller.graphql.client import (
    ControllerClient,
    PersistedEvent,
)

logger = logging.getLogger(__name__)

_SETTLE_SECS = 3
_POLL_INTERVAL = 1
_READY_TIMEOUT = 30
_EVENT_WAIT_TIMEOUT = 30  # controller flushes forwarded events in batches
_INTERFACE_REPORT_TIMEOUT = 60  # first InterfaceReport after enrollment


# ── Shared helpers ────────────────────────────────────────────────────────────


def _data_iface(node) -> str:
    for iface in node.interfaces.values():
        if iface.network.name != "mgmt":
            return iface.if_name
    pytest.fail(f"No data interface found on {node.name}")


def _get_data_ip(node) -> str:
    iface = _data_iface(node)
    out = node.ssh_command(
        f"ip -4 addr show {iface} | awk '/inet / {{print $2}}' | cut -d/ -f1",
        timeout=10,
    ).strip()
    for line in out.splitlines():
        addr = line.strip()
        if addr:
            return addr
    pytest.fail(f"Could not determine data IP for {node.name} on {iface}")


def _read_sysfs_ifindex(node, iface: str) -> int:
    """Read /sys/class/net/<iface>/ifindex on the node."""
    out = node.ssh_command(f"cat /sys/class/net/{iface}/ifindex", timeout=10).strip()
    try:
        return int(out)
    except ValueError:
        pytest.fail(
            f"[{node.name}] /sys/class/net/{iface}/ifindex returned non-int: {out!r}"
        )


def _send_icmp(node, target_ip: str, iface: str, count: int = 5) -> dict:
    out = node.ssh_command(
        f"ping -c {count} -I {iface} {target_ip} 2>&1 || true",
        timeout=30,
    )
    match = re.search(
        r"(\d+) packets transmitted, (\d+) received.*?(\d+(?:\.\d+)?)% packet loss",
        out,
    )
    if match:
        sent = int(match.group(1))
        received = int(match.group(2))
        return {
            "sent": sent,
            "received": received,
            "lost": sent - received,
            "output": out,
        }
    return {"sent": 0, "received": 0, "lost": 0, "output": out}


def _wait_for_node_ready(
    client: ControllerClient, node_id: str, timeout: int = _READY_TIMEOUT
) -> None:
    """Block until pendingGeneration is None — required before any gated mutation."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            pending = client.pending_generation(node_id)
            online = node_id in set(client.online_nodes())
            if pending is None and online:
                return
        except Exception as e:
            logger.debug(f"node_ready poll error: {e}")
        time.sleep(_POLL_INTERVAL)
    pytest.fail(f"Node {node_id} not ready (pending={pending!r}) after {timeout}s")


def _wait_for_interfaces_reported(
    client: ControllerClient,
    node_id: str,
    iface_name: str,
    timeout: int = _INTERFACE_REPORT_TIMEOUT,
) -> int:
    """Poll the controller until it has an ifindex>0 for (node_id, iface_name).

    First InterfaceReport lands shortly after enrollment but isn't synchronous
    with it. Returns the reported ifindex.
    """
    deadline = time.monotonic() + timeout
    last_seen: list = []
    while time.monotonic() < deadline:
        try:
            ifaces = client.node_interfaces(node_id)
            last_seen = ifaces
            for i in ifaces:
                if i.name == iface_name and i.ifindex > 0:
                    return i.ifindex
        except Exception as e:
            logger.debug(f"interfaces poll error: {e}")
        time.sleep(_POLL_INTERVAL)
    pytest.fail(
        f"Controller never reported ifindex>0 for ({node_id}, {iface_name}) "
        f"within {timeout}s; last_seen={[(i.name, i.ifindex) for i in last_seen]}"
    )


def _wait_for_events(
    client: ControllerClient,
    node_id: str,
    since_iso: str,
    min_count: int = 1,
    timeout: int = _EVENT_WAIT_TIMEOUT,
) -> List[PersistedEvent]:
    """Poll events() until at least `min_count` events arrive for node_id."""
    deadline = time.monotonic() + timeout
    last: List[PersistedEvent] = []
    while time.monotonic() < deadline:
        try:
            evs = client.events(node_id=node_id, since_iso=since_iso, limit=200)
            last = evs
            if len(evs) >= min_count:
                return evs
        except Exception as e:
            logger.debug(f"events poll error: {e}")
        time.sleep(_POLL_INTERVAL)
    pytest.fail(
        f"Expected ≥{min_count} events for node {node_id} since {since_iso}, "
        f"got {len(last)} after {timeout}s"
    )


def _flush_ingress_rules(node) -> None:
    """Best-effort cleanup of any leftover ingress rules on the node's local engine."""
    from lib.policy_engine.engine.graphql.client import GraphQLPolicyClient

    client = GraphQLPolicyClient(node)
    for r in client.list_rules(direction="ingress"):
        try:
            client.delete_rule(r.rule_id, direction="ingress")
        except Exception as e:
            logger.debug(f"[{node.name}] delete_rule({r.rule_id}) failed: {e}")


def _delete_controller_rules(
    client: ControllerClient, node_id: str, iface: str, direction: str
) -> None:
    for r in client.list_rules_for_node(
        node_id=node_id, interface_name=iface, direction=direction
    ):
        try:
            client.delete_rule(r["id"])
        except Exception as e:
            logger.debug(f"controller delete_rule({r.get('id')}) failed: {e}")


# ── Tests ─────────────────────────────────────────────────────────────────────


class TestNodeIdentity:
    """Phases 1 & 2: every enrolled node reports hostname and dmi_uuid."""

    def test_every_node_has_hostname(
        self,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ) -> None:
        by_id = {n.id: n for n in controller_client.list_nodes()}
        for vm_name, node_id in enrolled_nodes.items():
            n = by_id.get(node_id)
            assert n is not None, f"{vm_name} ({node_id}) missing from list_nodes"
            assert n.hostname, (
                f"{vm_name} ({node_id}) has empty hostname — the controller "
                f"never received it (check AgentHello) or COALESCE wiped it"
            )
            logger.info(f"{vm_name}: hostname={n.hostname!r}")

    def test_every_node_has_dmi_uuid(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ) -> None:
        """
        Regression test for the DynamicUser/DAC bug: the agent must be able
        to read /sys/class/dmi/id/product_uuid and the controller must
        persist it across AgentHello updates.

        Skips a node if the host kernel itself can't read product_uuid
        (uncommon, but possible in stripped-down VMs).
        """
        by_id = {n.id: n for n in controller_client.list_nodes()}
        for vm_name, node_id in enrolled_nodes.items():
            host_uuid = (
                nodes[vm_name]
                .ssh_command(
                    "sudo cat /sys/class/dmi/id/product_uuid 2>/dev/null || true",
                    timeout=10,
                )
                .strip()
            )
            if not host_uuid:
                pytest.skip(
                    f"{vm_name} has no product_uuid available even to root — "
                    f"nothing to compare against"
                )

            n = by_id.get(node_id)
            assert n is not None
            assert n.dmi_uuid, (
                f"{vm_name} ({node_id}) has empty dmi_uuid on the controller "
                f"but the host exposes {host_uuid!r} — agent likely lacks "
                f"CAP_DAC_READ_SEARCH or the controller is overwriting the "
                f"value with NULL on AgentHello"
            )
            assert n.dmi_uuid.lower() == host_uuid.lower(), (
                f"{vm_name}: controller dmi_uuid={n.dmi_uuid!r} != "
                f"host product_uuid={host_uuid!r}"
            )
            logger.info(f"{vm_name}: dmi_uuid={n.dmi_uuid}")


class TestInterfaceIfindex:
    """Phase 4 (server side): controller persists ifindex from InterfaceReport."""

    def test_data_interface_ifindex_matches_sysfs(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ) -> None:
        """For every managed node, the controller's NodeInterface.ifindex for
        the data NIC must match /sys/class/net/<iface>/ifindex on the host."""
        for vm_name, node_id in enrolled_nodes.items():
            node = nodes[vm_name]
            iface = _data_iface(node)
            sysfs_ifindex = _read_sysfs_ifindex(node, iface)
            controller_ifindex = _wait_for_interfaces_reported(
                controller_client, node_id, iface
            )
            assert controller_ifindex == sysfs_ifindex, (
                f"[{vm_name}] controller ifindex={controller_ifindex} for "
                f"{iface}, but sysfs reports {sysfs_ifindex}"
            )
            logger.info(
                f"{vm_name}: {iface} ifindex={sysfs_ifindex} (controller agrees)"
            )


class TestEventStreamPipeline:
    """
    Phase 4 (event side): events forwarded by the agent carry the right
    ifindex so the UI's (node_id, ifindex) → name join is correct.

    Plan:
      1. Attach ingress on node1, install a log-only ICMP rule.
      2. Capture a timestamp, ping node1 from node2.
      3. Poll the controller's persisted events store.
      4. Assert: events exist for node1; ifindex matches node1's data NIC;
         action is LOG; direction is INGRESS.
    """

    def test_log_events_tagged_with_correct_ifindex(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ) -> None:
        node1 = nodes["node1"]
        node2 = nodes["node2"]
        node1_id = enrolled_nodes["node1"]
        iface1 = _data_iface(node1)
        iface2 = _data_iface(node2)
        node1_ip = _get_data_ip(node1)

        expected_ifindex = _wait_for_interfaces_reported(
            controller_client, node1_id, iface1
        )

        _wait_for_node_ready(controller_client, node1_id)
        controller_client.attach_program(
            node_id=node1_id, interface_name=iface1, direction="ingress"
        )
        time.sleep(_SETTLE_SECS)
        _flush_ingress_rules(node1)
        _delete_controller_rules(controller_client, node1_id, iface1, "ingress")

        rule = controller_client.create_rule(
            node_id=node1_id,
            interface_name=iface1,
            direction="ingress",
            protocol="icmp",
            actions_json='[{"action":"log","priority":0}]',
        )
        assert rule.get("id"), f"createRule returned no id: {rule}"
        rule_id = rule["id"]
        logger.info(f"[node1] log-ICMP rule id={rule_id}")
        time.sleep(_SETTLE_SECS)

        # Pre-traffic high-water mark — only count events newer than this.
        # Controller stores DateTime in UTC; use a slightly-padded ISO string.
        from datetime import datetime, timedelta, timezone

        since_iso = (datetime.now(timezone.utc) - timedelta(seconds=2)).strftime(
            "%Y-%m-%dT%H:%M:%S.%f"
        ).rstrip("0").rstrip(".") + "Z"

        try:
            ping = _send_icmp(node2, node1_ip, iface2, count=5)
            logger.info(f"[log-rule] ping: sent={ping['sent']} recv={ping['received']}")
            assert ping["received"] > 0, (
                f"log-only rule must not drop traffic; got {ping}"
            )

            evs = _wait_for_events(controller_client, node1_id, since_iso, min_count=1)

            # Filter to ICMP-from-node2-to-node1 to ignore unrelated background
            # traffic the agent might also have logged.
            node2_ip = _get_data_ip(node2)
            relevant = [e for e in evs if e.src_ip == node2_ip and e.dst_ip == node1_ip]
            assert relevant, (
                f"No events matching {node2_ip} → {node1_ip} found; got "
                f"{[(e.src_ip, e.dst_ip, e.action, e.ifindex) for e in evs]}"
            )

            for e in relevant:
                assert e.node_id == node1_id, (
                    f"event.node_id={e.node_id} != node1_id={node1_id}"
                )
                assert e.ifindex == expected_ifindex, (
                    f"event.ifindex={e.ifindex} != expected {expected_ifindex} "
                    f"({iface1}); the agent's per-event ifindex tagging is wrong"
                )
                assert e.direction.lower() == "ingress", (
                    f"event.direction={e.direction!r}, expected INGRESS"
                )
                assert e.action.lower() == "log", (
                    f"event.action={e.action!r}, expected LOG"
                )
            logger.info(
                f"verified {len(relevant)} forwarded events carry ifindex={expected_ifindex}"
            )
        finally:
            _flush_ingress_rules(node1)
            _delete_controller_rules(controller_client, node1_id, iface1, "ingress")
            _wait_for_node_ready(controller_client, node1_id)
            try:
                controller_client.detach_program(
                    node_id=node1_id, interface_name=iface1, direction="ingress"
                )
            except Exception as e:
                logger.warning(f"detach_program cleanup failed: {e}")
