# Copyright (c) Dufferin Software

"""
Policy Controller GraphQL client for multi-node integration tests.

Executes GraphQL queries against the policy-controller HTTP API by running
curl commands on the controller VM via SSH — the same pattern used by
GraphQLPolicyClient for the policy-engine.
"""

import json
import logging
from dataclasses import dataclass
from typing import List, Optional

from tests.node import Node

logger = logging.getLogger(__name__)

_CONTROLLER_URL = "http://127.0.0.1:8443/graphql"


@dataclass
class ControlledNode:
    id: str
    status: str
    label: Optional[str] = None
    dmi_uuid: Optional[str] = None
    tpm_backed: bool = False
    agent_version: Optional[str] = None


@dataclass
class Ruleset:
    id: str
    name: str
    rules_json: str
    description: Optional[str] = None
    default_action_ingress: Optional[str] = None
    default_action_egress: Optional[str] = None


@dataclass
class OperationResult:
    success: bool
    message: Optional[str] = None


class ControllerClient:
    """
    GraphQL client for the policy-controller API.

    All requests are executed as curl commands on the controller VM via SSH,
    consistent with the netsim test infrastructure pattern.
    """

    def __init__(self, node: Node, url: str = _CONTROLLER_URL):
        self.node = node
        self.url = url

    def _execute(self, query: str, variables: Optional[dict] = None) -> dict:
        """Run a GraphQL query/mutation via curl on the controller VM."""
        payload = {"query": query}
        if variables:
            payload["variables"] = variables

        payload_json = json.dumps(payload)
        logger.debug(f"[controller] GraphQL: {query[:80]}...")

        if len(payload_json) > 10000:
            cmd = (
                f"curl -s -X POST -H 'Content-Type: application/json' -d @- {self.url}"
            )
            output = self.node.ssh_command_with_stdin(cmd, payload_json, timeout=30)
        else:
            payload_escaped = payload_json.replace("'", "'\\''")
            cmd = (
                f"curl -s -X POST -H 'Content-Type: application/json' "
                f"-d '{payload_escaped}' {self.url}"
            )
            output = self.node.ssh_command(cmd, timeout=30)

        try:
            response = json.loads(output)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse controller GraphQL response: {output!r}")
            raise ValueError(f"Invalid JSON from controller GraphQL: {e}") from e

        if "errors" in response and response["errors"]:
            error_msg = response["errors"][0].get("message", str(response["errors"]))
            raise RuntimeError(f"Controller GraphQL error: {error_msg}")

        return response.get("data", {})

    # ── Nodes ─────────────────────────────────────────────────────────────────

    def list_nodes(self, status: Optional[str] = None) -> List[ControlledNode]:
        """List all controlled nodes, optionally filtered by status string."""
        query = """
        query ListNodes($status: String) {
            nodes(status: $status) {
                id status label dmiUuid tpmBacked agentVersion
            }
        }
        """
        data = self._execute(query, {"status": status} if status else None)
        return [
            ControlledNode(
                id=n["id"],
                status=n["status"],
                label=n.get("label"),
                dmi_uuid=n.get("dmiUuid"),
                tpm_backed=n.get("tpmBacked", False),
                agent_version=n.get("agentVersion"),
            )
            for n in data.get("nodes", [])
        ]

    def pending_enrollments(self) -> List[ControlledNode]:
        """Return nodes in pending-enrollment state."""
        query = """
        query {
            pendingEnrollments { id status label dmiUuid tpmBacked agentVersion }
        }
        """
        data = self._execute(query)
        return [
            ControlledNode(
                id=n["id"],
                status=n["status"],
                label=n.get("label"),
                dmi_uuid=n.get("dmiUuid"),
                tpm_backed=n.get("tpmBacked", False),
                agent_version=n.get("agentVersion"),
            )
            for n in data.get("pendingEnrollments", [])
        ]

    def online_nodes(self) -> List[str]:
        """Return IDs of currently-connected agent nodes."""
        data = self._execute("query { onlineNodes }")
        return data.get("onlineNodes", [])

    def approve_enrollment(
        self, node_id: str, label: Optional[str] = None
    ) -> ControlledNode:
        """Approve a pending enrollment, optionally setting a label."""
        query = """
        mutation Approve($nodeId: ID!, $label: String) {
            approveEnrollment(nodeId: $nodeId, label: $label) {
                id status label
            }
        }
        """
        data = self._execute(query, {"nodeId": node_id, "label": label})
        n = data["approveEnrollment"]
        return ControlledNode(id=n["id"], status=n["status"], label=n.get("label"))

    def reject_enrollment(
        self, node_id: str, reason: Optional[str] = None
    ) -> OperationResult:
        """Reject a pending enrollment."""
        query = """
        mutation Reject($nodeId: ID!, $reason: String) {
            rejectEnrollment(nodeId: $nodeId, reason: $reason) { success message }
        }
        """
        data = self._execute(query, {"nodeId": node_id, "reason": reason})
        r = data["rejectEnrollment"]
        return OperationResult(success=r["success"], message=r.get("message"))

    def decommission_node(self, node_id: str) -> OperationResult:
        """Decommission a node (revokes cert, blocks reconnect)."""
        query = """
        mutation Decommission($nodeId: ID!) {
            decommissionNode(nodeId: $nodeId) { success message }
        }
        """
        data = self._execute(query, {"nodeId": node_id})
        r = data["decommissionNode"]
        return OperationResult(success=r["success"], message=r.get("message"))

    def remove_node(self, node_id: str) -> OperationResult:
        """Remove a decommissioned node from the registry."""
        query = """
        mutation Remove($nodeId: ID!) {
            removeNode(nodeId: $nodeId) { success message }
        }
        """
        data = self._execute(query, {"nodeId": node_id})
        r = data["removeNode"]
        return OperationResult(success=r["success"], message=r.get("message"))

    # ── Rulesets ──────────────────────────────────────────────────────────────

    def list_rulesets(self) -> List[Ruleset]:
        """Return all rulesets."""
        query = """
        query {
            rulesets {
                id name description rulesJson
                defaultActionIngress defaultActionEgress
            }
        }
        """
        data = self._execute(query)
        return [
            Ruleset(
                id=rs["id"],
                name=rs["name"],
                rules_json=rs["rulesJson"],
                description=rs.get("description"),
                default_action_ingress=rs.get("defaultActionIngress"),
                default_action_egress=rs.get("defaultActionEgress"),
            )
            for rs in data.get("rulesets", [])
        ]

    def create_ruleset(
        self,
        name: str,
        rules_json: str,
        description: Optional[str] = None,
        default_action_ingress: Optional[str] = None,
        default_action_egress: Optional[str] = None,
    ) -> Ruleset:
        """Create a new ruleset."""
        query = """
        mutation CreateRuleset(
            $name: String!
            $description: String
            $rulesJson: String!
            $defaultActionIngress: String
            $defaultActionEgress: String
        ) {
            createRuleset(
                name: $name
                description: $description
                rulesJson: $rulesJson
                defaultActionIngress: $defaultActionIngress
                defaultActionEgress: $defaultActionEgress
            ) { id name rulesJson defaultActionIngress defaultActionEgress }
        }
        """
        data = self._execute(
            query,
            {
                "name": name,
                "description": description,
                "rulesJson": rules_json,
                "defaultActionIngress": default_action_ingress,
                "defaultActionEgress": default_action_egress,
            },
        )
        rs = data["createRuleset"]
        return Ruleset(
            id=rs["id"],
            name=rs["name"],
            rules_json=rs["rulesJson"],
            default_action_ingress=rs.get("defaultActionIngress"),
            default_action_egress=rs.get("defaultActionEgress"),
        )

    def assign_ruleset(self, node_id: str, ruleset_id: str) -> OperationResult:
        """Assign a ruleset to a node."""
        query = """
        mutation Assign($nodeId: ID!, $rulesetId: ID!) {
            assignRuleset(nodeId: $nodeId, rulesetId: $rulesetId) { success message }
        }
        """
        data = self._execute(query, {"nodeId": node_id, "rulesetId": ruleset_id})
        r = data["assignRuleset"]
        return OperationResult(success=r["success"], message=r.get("message"))

    def push_config(self, node_id: str) -> OperationResult:
        """Force push the assigned ruleset to a specific node."""
        query = """
        mutation Push($nodeId: ID!) {
            pushConfig(nodeId: $nodeId) { success message }
        }
        """
        data = self._execute(query, {"nodeId": node_id})
        r = data["pushConfig"]
        return OperationResult(success=r["success"], message=r.get("message"))

    def push_config_all(self) -> OperationResult:
        """Push config to all currently-online nodes."""
        query = """
        mutation {
            pushConfigAll { success message }
        }
        """
        data = self._execute(query)
        r = data["pushConfigAll"]
        return OperationResult(success=r["success"], message=r.get("message"))

    def attach_program(
        self,
        node_id: str,
        interface_name: str,
        direction: str,
        mode: Optional[str] = None,
    ) -> OperationResult:
        """Attach a BPF program to an interface on a node."""
        query = """
        mutation AttachProgram(
            $nodeId: ID!
            $interfaceName: String!
            $direction: String!
            $mode: String
        ) {
            attachProgram(
                nodeId: $nodeId
                interfaceName: $interfaceName
                direction: $direction
                mode: $mode
            ) { success message }
        }
        """
        data = self._execute(
            query,
            {
                "nodeId": node_id,
                "interfaceName": interface_name,
                "direction": direction,
                "mode": mode,
            },
        )
        r = data["attachProgram"]
        return OperationResult(success=r["success"], message=r.get("message"))

    def detach_program(
        self, node_id: str, interface_name: str, direction: str
    ) -> OperationResult:
        """Detach a BPF program from an interface on a node."""
        query = """
        mutation DetachProgram(
            $nodeId: ID!
            $interfaceName: String!
            $direction: String!
        ) {
            detachProgram(
                nodeId: $nodeId
                interfaceName: $interfaceName
                direction: $direction
            ) { success message }
        }
        """
        data = self._execute(
            query,
            {
                "nodeId": node_id,
                "interfaceName": interface_name,
                "direction": direction,
            },
        )
        r = data["detachProgram"]
        return OperationResult(success=r["success"], message=r.get("message"))

    # ── CA cert ───────────────────────────────────────────────────────────────

    def ca_cert_pem(self) -> str:
        """Retrieve the controller CA certificate in PEM format."""
        data = self._execute("query { caCertPem }")
        return data["caCertPem"]

    # ── Health check ──────────────────────────────────────────────────────────

    def is_healthy(self) -> bool:
        """Return True if the controller HTTP API is responding."""
        try:
            out = self.node.ssh_command(
                "curl -s -o /dev/null -w '%{http_code}' "
                "--max-time 2 http://127.0.0.1:8443/health 2>/dev/null || true",
                timeout=10,
            )
            return out.strip() == "200"
        except Exception:
            return False
