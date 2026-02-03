# Copyright (c) Dufferin Software

"""
Policy Engine GraphQL client wrapper for test infrastructure.

Provides typed Python objects that mirror the policy-client JSON output,
but communicates directly with the GraphQL API instead of using the CLI.
"""

import json
import logging
from typing import List, Optional

from tests.node import Node
from tests.policy_client import (
    AddRuleOptions,
    EthertypeStats,
    GlobalStats,
    InterfaceAttachment,
    InterfaceStats,
    LpmRule,
    OperationResult,
    PolicyAction,
    Protocol,
    RuleAction,
    RuleStats,
    RuleStatsResponse,
    RuleWithStats,
    ServerStatus,
    XdpMode,
)

logger = logging.getLogger(__name__)


class GraphQLPolicyClient:
    """
    GraphQL-based wrapper for the policy-engine API.

    Makes direct HTTP requests to the GraphQL endpoint instead of using the CLI.
    Implements the same interface as PolicyClient for test compatibility.
    """

    def __init__(self, node: Node, server_url: str = "http://127.0.0.1:8080/graphql"):
        """
        Initialize the GraphQL policy client wrapper.

        Args:
            node: Node where policy-engine is running
            server_url: URL of the policy-engine GraphQL server
        """
        self.node = node
        self.server_url = server_url

    def _execute_graphql(self, query: str, variables: Optional[dict] = None) -> dict:
        """
        Execute a GraphQL query/mutation via HTTP from the remote node.

        Args:
            query: GraphQL query or mutation string
            variables: Optional variables for the query

        Returns:
            The 'data' portion of the GraphQL response

        Raises:
            ValueError: If GraphQL returns errors
        """
        payload = {"query": query}
        if variables:
            payload["variables"] = variables

        # Use curl via SSH to make the request from the node
        payload_json = json.dumps(payload).replace("'", "'\\''")  # Escape single quotes
        cmd = f"curl -s -X POST -H 'Content-Type: application/json' -d '{payload_json}' {self.server_url}"

        logger.debug(f"[{self.node.name}] GraphQL: {query[:100]}...")

        output = self.node.ssh_command(cmd, timeout=30)

        try:
            response = json.loads(output)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse GraphQL response: {output}")
            raise ValueError(f"Invalid JSON from GraphQL: {e}") from e

        if "errors" in response and response["errors"]:
            error_msg = response["errors"][0].get("message", str(response["errors"]))
            logger.debug(f"GraphQL error: {error_msg}")
            # Return as a failed OperationResult-like response
            return {"__error__": error_msg}

        return response.get("data", {})

    # ========================================================================
    # Status commands
    # ========================================================================

    def status(self) -> ServerStatus:
        """Get server status."""
        query = """
        query {
            status {
                running
                version
                uptimeSecs
                programAttached
            }
        }
        """
        data = self._execute_graphql(query)
        status_data = data.get("status", {})
        return ServerStatus(
            running=status_data.get("running", False),
            version=status_data.get("version", ""),
            uptime_secs=status_data.get("uptimeSecs", 0),
            program_attached=status_data.get("programAttached", False),
        )

    # ========================================================================
    # Attach/Detach commands
    # ========================================================================

    def attach_xdp(
        self, interface: str, mode: XdpMode = XdpMode.AUTO
    ) -> OperationResult:
        """
        Attach XDP program to an interface.

        Args:
            interface: Interface name
            mode: XDP attach mode

        Returns:
            OperationResult indicating success/failure
        """
        mutation = """
        mutation AttachXdp($input: AttachXdpInput!) {
            attachXdp(input: $input) {
                success
                message
            }
        }
        """
        variables = {
            "input": {
                "interface": interface,
                "mode": mode.value,
            }
        }
        data = self._execute_graphql(mutation, variables)

        if "__error__" in data:
            return OperationResult(success=False, message=data["__error__"])

        result = data.get("attachXdp", {})
        return OperationResult(
            success=result.get("success", False),
            message=result.get("message", ""),
        )

    def detach_xdp(self, interface: str) -> OperationResult:
        """
        Detach XDP program from an interface.

        Args:
            interface: Interface name

        Returns:
            OperationResult indicating success/failure
        """
        mutation = """
        mutation DetachXdp($input: DetachXdpInput!) {
            detachXdp(input: $input) {
                success
                message
            }
        }
        """
        variables = {"input": {"interface": interface}}
        data = self._execute_graphql(mutation, variables)

        if "__error__" in data:
            return OperationResult(success=False, message=data["__error__"])

        result = data.get("detachXdp", {})
        return OperationResult(
            success=result.get("success", False),
            message=result.get("message", ""),
        )

    def detach_all(self) -> OperationResult:
        """
        Detach all XDP programs.

        Returns:
            OperationResult indicating success/failure
        """
        mutation = """
        mutation {
            detachAll {
                success
                message
            }
        }
        """
        data = self._execute_graphql(mutation)

        if "__error__" in data:
            return OperationResult(success=False, message=data["__error__"])

        result = data.get("detachAll", {})
        return OperationResult(
            success=result.get("success", False),
            message=result.get("message", ""),
        )

    # ========================================================================
    # Rule commands
    # ========================================================================

    def add_rule(self, options: AddRuleOptions) -> OperationResult:
        """
        Add a policy rule.

        Args:
            options: Rule configuration options

        Returns:
            OperationResult indicating success/failure
        """
        mutation = """
        mutation AddRule($input: AddRuleInput!) {
            addRule(input: $input) {
                success
                message
            }
        }
        """

        # Convert actions to GraphQL format
        gql_actions = []
        for action, priority in options.actions:
            # Map action string to GraphQL enum value
            action_map = {
                "pass": "PASS",
                "drop": "DROP",
                "log": "LOG",
                "nat": "NAT",
            }
            gql_action = action_map.get(action.lower(), "PASS")
            gql_actions.append({"action": gql_action, "priority": priority})

        # Map protocol string to GraphQL string value (server expects lowercase)
        proto_map = {
            "any": "any",
            "tcp": "tcp",
            "udp": "udp",
            "icmp": "icmp",
            "icmpv6": "icmp",  # Server auto-converts to icmpv6 for IPv6 rules
        }
        gql_protocol = proto_map.get(options.protocol.lower(), "any")

        input_data = {
            "protocol": gql_protocol,
            "sport": options.sport,
            "dport": options.dport,
            "priority": options.priority,
            "actions": gql_actions,
        }

        if options.src:
            input_data["src"] = options.src
        if options.dst:
            input_data["dst"] = options.dst
        if options.rule_id is not None:
            input_data["id"] = options.rule_id

        variables = {"input": input_data}
        data = self._execute_graphql(mutation, variables)

        if "__error__" in data:
            return OperationResult(success=False, message=data["__error__"])

        result = data.get("addRule", {})
        return OperationResult(
            success=result.get("success", False),
            message=result.get("message", ""),
        )

    def delete_rule(
        self,
        rule_id: Optional[int] = None,
        src: Optional[str] = None,
        dst: Optional[str] = None,
        sport: Optional[int] = None,
        dport: Optional[int] = None,
        protocol: Optional[str] = None,
    ) -> OperationResult:
        """
        Delete a policy rule.

        Args:
            rule_id: Rule ID to delete
            src: Source prefix (alternative to id)
            dst: Destination prefix
            sport: Source port
            dport: Destination port
            protocol: Protocol

        Returns:
            OperationResult indicating success/failure
        """
        mutation = """
        mutation DeleteRule($input: DeleteRuleInput!) {
            deleteRule(input: $input) {
                success
                message
            }
        }
        """

        input_data = {}
        if rule_id is not None:
            input_data["id"] = rule_id
        if src:
            input_data["src"] = src
        if dst:
            input_data["dst"] = dst
        if sport is not None:
            input_data["sport"] = sport
        if dport is not None:
            input_data["dport"] = dport
        if protocol:
            proto_map = {
                "any": "any",
                "tcp": "tcp",
                "udp": "udp",
                "icmp": "icmp",
            }
            input_data["protocol"] = proto_map.get(protocol.lower(), "any")

        variables = {"input": input_data}
        data = self._execute_graphql(mutation, variables)

        if "__error__" in data:
            return OperationResult(success=False, message=data["__error__"])

        result = data.get("deleteRule", {})
        return OperationResult(
            success=result.get("success", False),
            message=result.get("message", ""),
        )

    def list_rules(self) -> List[LpmRule]:
        """
        List all policy rules.

        Returns:
            List of LpmRule objects
        """
        query = """
        query {
            rules {
                ruleId
                srcPrefix
                dstPrefix
                sport
                dport
                protocol
                priority
                actions {
                    action
                    priority
                }
            }
        }
        """
        data = self._execute_graphql(query)

        if "__error__" in data:
            return []

        rules_data = data.get("rules", [])
        rules = []
        for r in rules_data:
            # Convert GraphQL protocol enum to Protocol enum
            proto_str = r.get("protocol", "ANY")
            protocol = Protocol.from_string(proto_str)

            # Convert actions
            actions = []
            for a in r.get("actions", []):
                action_str = a.get("action", "Pass")
                actions.append(
                    RuleAction(
                        action=PolicyAction.from_string(action_str),
                        priority=a.get("priority", 0),
                    )
                )

            rules.append(
                LpmRule(
                    rule_id=r.get("ruleId", 0),
                    src_prefix=r.get("srcPrefix", "0.0.0.0/0"),
                    dst_prefix=r.get("dstPrefix", "0.0.0.0/0"),
                    sport=r.get("sport", 0),
                    dport=r.get("dport", 0),
                    protocol=protocol,
                    priority=r.get("priority", 1000),
                    actions=actions,
                )
            )
        return rules

    def flush_rules(self) -> OperationResult:
        """
        Flush all policy rules.

        Returns:
            OperationResult indicating success/failure
        """
        mutation = """
        mutation {
            flushRules {
                success
                message
            }
        }
        """
        data = self._execute_graphql(mutation)

        if "__error__" in data:
            return OperationResult(success=False, message=data["__error__"])

        result = data.get("flushRules", {})
        return OperationResult(
            success=result.get("success", False),
            message=result.get("message", ""),
        )

    # ========================================================================
    # Show commands
    # ========================================================================

    def list_interfaces(self) -> List[InterfaceAttachment]:
        """
        List attached interfaces.

        Returns:
            List of InterfaceAttachment objects
        """
        query = """
        query {
            interfaces {
                interface
                ifindex
                mode
            }
        }
        """
        data = self._execute_graphql(query)

        if "__error__" in data:
            return []

        ifaces_data = data.get("interfaces", [])
        return [
            InterfaceAttachment(
                interface=i.get("interface", ""),
                ifindex=i.get("ifindex", 0),
                mode=i.get("mode", ""),
            )
            for i in ifaces_data
        ]

    def get_stats(self, interface: str) -> InterfaceStats:
        """
        Get statistics for an interface.

        Args:
            interface: Interface name

        Returns:
            InterfaceStats object
        """
        query = """
        query GetStats($interface: String!) {
            stats(interface: $interface) {
                rxPackets
                rxBytes
                txPackets
                txBytes
                policyMatches
                policyDrops
                policyPass
                policyRedirects
                parseErrors
                tailCalls
                bumPackets
                nonIpUnicast
            }
            ethertypeStats(interface: $interface) {
                ethertype
                ethertypeHex
                name
                packets
            }
            status {
                programAttached
            }
        }
        """
        variables = {"interface": interface}
        data = self._execute_graphql(query, variables)

        if "__error__" in data:
            # Return empty stats on error
            return InterfaceStats(
                interface=interface,
                program_attached=False,
                global_stats=GlobalStats(
                    rx_packets=0,
                    rx_bytes=0,
                    tx_packets=0,
                    tx_bytes=0,
                    policy_matches=0,
                    policy_drops=0,
                    policy_pass=0,
                    policy_redirects=0,
                    parse_errors=0,
                    tail_calls=0,
                    bum_packets=0,
                    non_ip_unicast=0,
                ),
                ethertype_stats=[],
            )

        stats_data = data.get("stats", {})
        ethertype_data = data.get("ethertypeStats", [])
        status_data = data.get("status", {})

        global_stats = GlobalStats(
            rx_packets=stats_data.get("rxPackets", 0),
            rx_bytes=stats_data.get("rxBytes", 0),
            tx_packets=stats_data.get("txPackets", 0),
            tx_bytes=stats_data.get("txBytes", 0),
            policy_matches=stats_data.get("policyMatches", 0),
            policy_drops=stats_data.get("policyDrops", 0),
            policy_pass=stats_data.get("policyPass", 0),
            policy_redirects=stats_data.get("policyRedirects", 0),
            parse_errors=stats_data.get("parseErrors", 0),
            tail_calls=stats_data.get("tailCalls", 0),
            bum_packets=stats_data.get("bumPackets", 0),
            non_ip_unicast=stats_data.get("nonIpUnicast", 0),
        )

        ethertype_stats = [
            EthertypeStats(
                ethertype=e.get("ethertype", 0),
                ethertype_hex=e.get("ethertypeHex", ""),
                name=e.get("name", ""),
                packets=e.get("packets", 0),
            )
            for e in ethertype_data
        ]

        return InterfaceStats(
            interface=interface,
            program_attached=status_data.get("programAttached", False),
            global_stats=global_stats,
            ethertype_stats=ethertype_stats,
        )

    def get_rule_stats(self, rule_id: Optional[int] = None) -> RuleStatsResponse:
        """
        Get rule statistics.

        Args:
            rule_id: Optional rule ID (all rules if not specified)

        Returns:
            RuleStatsResponse object
        """
        if rule_id is not None:
            # Get stats for specific rule - note: ruleId is required (not optional)
            query = """
            query GetRuleStats($ruleId: Int!) {
                ruleStats(ruleId: $ruleId) {
                    packets
                    bytes
                    lastSeenNs
                }
                rules {
                    ruleId
                    srcPrefix
                    dstPrefix
                    sport
                    dport
                    protocol
                    priority
                    actions {
                        action
                        priority
                    }
                }
                status {
                    programAttached
                }
            }
            """
            variables = {"ruleId": rule_id}
        else:
            # Get all rules with their stats
            query = """
            query {
                rules {
                    ruleId
                    srcPrefix
                    dstPrefix
                    sport
                    dport
                    protocol
                    priority
                    actions {
                        action
                        priority
                    }
                }
                status {
                    programAttached
                }
            }
            """
            variables = None

        data = self._execute_graphql(query, variables)

        if "__error__" in data:
            return RuleStatsResponse(program_attached=False, rules=[])

        status_data = data.get("status", {})
        rules_data = data.get("rules", [])

        rules_with_stats = []
        for r in rules_data:
            # Convert rule data
            proto_str = r.get("protocol", "ANY")
            protocol = Protocol.from_string(proto_str)

            actions = []
            for a in r.get("actions", []):
                action_str = a.get("action", "Pass")
                actions.append(
                    RuleAction(
                        action=PolicyAction.from_string(action_str),
                        priority=a.get("priority", 0),
                    )
                )

            rule = LpmRule(
                rule_id=r.get("ruleId", 0),
                src_prefix=r.get("srcPrefix", "0.0.0.0/0"),
                dst_prefix=r.get("dstPrefix", "0.0.0.0/0"),
                sport=r.get("sport", 0),
                dport=r.get("dport", 0),
                protocol=protocol,
                priority=r.get("priority", 1000),
                actions=actions,
            )

            # Get stats for this rule if we queried for a specific one
            stats = None
            if rule_id is not None and r.get("ruleId") == rule_id:
                stats_data = data.get("ruleStats")
                if stats_data:
                    stats = RuleStats(
                        packets=stats_data.get("packets", 0),
                        bytes=stats_data.get("bytes", 0),
                        last_seen_ns=stats_data.get("lastSeenNs", 0),
                    )
            elif rule_id is None:
                # Query stats individually for each rule
                rule_stats_data = self._get_single_rule_stats(r.get("ruleId", 0))
                if rule_stats_data:
                    stats = RuleStats(
                        packets=rule_stats_data.get("packets", 0),
                        bytes=rule_stats_data.get("bytes", 0),
                        last_seen_ns=rule_stats_data.get("lastSeenNs", 0),
                    )

            rules_with_stats.append(RuleWithStats(rule=rule, stats=stats))

        return RuleStatsResponse(
            program_attached=status_data.get("programAttached", False),
            rules=rules_with_stats,
        )

    def _get_single_rule_stats(self, rule_id: int) -> Optional[dict]:
        """Get stats for a single rule."""
        query = """
        query GetRuleStats($ruleId: Int!) {
            ruleStats(ruleId: $ruleId) {
                packets
                bytes
                lastSeenNs
            }
        }
        """
        variables = {"ruleId": rule_id}
        data = self._execute_graphql(query, variables)
        return data.get("ruleStats")

    # ========================================================================
    # Config commands
    # ========================================================================

    def set_default_action(self, action: PolicyAction) -> OperationResult:
        """
        Set the default action for unmatched packets.

        Args:
            action: Default action

        Returns:
            OperationResult indicating success/failure
        """
        mutation = """
        mutation SetDefaultAction($input: DefaultActionInput!) {
            setDefaultAction(input: $input) {
                success
                message
            }
        }
        """
        # Map action to GraphQL enum
        action_map = {
            PolicyAction.PASS: "PASS",
            PolicyAction.DROP: "DROP",
            PolicyAction.LOG: "LOG",
            PolicyAction.NAT: "NAT",
        }
        gql_action = action_map.get(action, "PASS")

        variables = {"input": {"action": gql_action}}
        data = self._execute_graphql(mutation, variables)

        if "__error__" in data:
            return OperationResult(success=False, message=data["__error__"])

        result = data.get("setDefaultAction", {})
        return OperationResult(
            success=result.get("success", False),
            message=result.get("message", ""),
        )

    def register_tail_call(self, slot: int, program: str) -> OperationResult:
        """
        Register a tail call program.

        Args:
            slot: Slot number (0-63)
            program: Program name

        Returns:
            OperationResult indicating success/failure
        """
        mutation = """
        mutation RegisterTailCall($input: TailCallInput!) {
            registerTailCall(input: $input) {
                success
                message
            }
        }
        """
        variables = {"input": {"slot": slot, "program": program}}
        data = self._execute_graphql(mutation, variables)

        if "__error__" in data:
            return OperationResult(success=False, message=data["__error__"])

        result = data.get("registerTailCall", {})
        return OperationResult(
            success=result.get("success", False),
            message=result.get("message", ""),
        )

    # ========================================================================
    # Clear stats commands
    # ========================================================================

    def clear_global_stats(self, interface: str) -> OperationResult:
        """
        Clear global statistics for an interface.

        Args:
            interface: Interface name

        Returns:
            OperationResult indicating success/failure
        """
        mutation = """
        mutation ClearGlobalStats($interface: String!) {
            clearGlobalStats(interface: $interface) {
                success
                message
            }
        }
        """
        variables = {"interface": interface}
        data = self._execute_graphql(mutation, variables)

        if "__error__" in data:
            return OperationResult(success=False, message=data["__error__"])

        result = data.get("clearGlobalStats", {})
        return OperationResult(
            success=result.get("success", False),
            message=result.get("message", ""),
        )

    def clear_interface_stats(self, interface: str) -> OperationResult:
        """
        Clear all statistics for an interface (global + ethertype).

        Args:
            interface: Interface name

        Returns:
            OperationResult indicating success/failure
        """
        mutation = """
        mutation ClearInterfaceStats($interface: String!) {
            clearInterfaceStats(interface: $interface) {
                success
                message
            }
        }
        """
        variables = {"interface": interface}
        data = self._execute_graphql(mutation, variables)

        if "__error__" in data:
            return OperationResult(success=False, message=data["__error__"])

        result = data.get("clearInterfaceStats", {})
        return OperationResult(
            success=result.get("success", False),
            message=result.get("message", ""),
        )

    def clear_rule_stats(self, rule_id: Optional[int] = None) -> OperationResult:
        """
        Clear rule statistics.

        Args:
            rule_id: Optional rule ID (clears all rules if not specified)

        Returns:
            OperationResult indicating success/failure
        """
        if rule_id is not None:
            mutation = """
            mutation ClearRuleStats($ruleId: Int!) {
                clearRuleStats(ruleId: $ruleId) {
                    success
                    message
                }
            }
            """
            variables = {"ruleId": rule_id}
            data = self._execute_graphql(mutation, variables)

            if "__error__" in data:
                return OperationResult(success=False, message=data["__error__"])

            result = data.get("clearRuleStats", {})
        else:
            mutation = """
            mutation {
                clearAllRuleStats {
                    success
                    message
                }
            }
            """
            data = self._execute_graphql(mutation)

            if "__error__" in data:
                return OperationResult(success=False, message=data["__error__"])

            result = data.get("clearAllRuleStats", {})

        return OperationResult(
            success=result.get("success", False),
            message=result.get("message", ""),
        )

    def clear_ethertype_stats(self, interface: str) -> OperationResult:
        """
        Clear ethertype statistics for an interface.

        Args:
            interface: Interface name

        Returns:
            OperationResult indicating success/failure
        """
        mutation = """
        mutation ClearEthertypeStats($interface: String!) {
            clearEthertypeStats(interface: $interface) {
                success
                message
            }
        }
        """
        variables = {"interface": interface}
        data = self._execute_graphql(mutation, variables)

        if "__error__" in data:
            return OperationResult(success=False, message=data["__error__"])

        result = data.get("clearEthertypeStats", {})
        return OperationResult(
            success=result.get("success", False),
            message=result.get("message", ""),
        )

    def clear_all_stats(self) -> OperationResult:
        """
        Clear all statistics.

        Returns:
            OperationResult indicating success/failure
        """
        mutation = """
        mutation {
            clearAllStats {
                success
                message
            }
        }
        """
        data = self._execute_graphql(mutation)

        if "__error__" in data:
            return OperationResult(success=False, message=data["__error__"])

        result = data.get("clearAllStats", {})
        return OperationResult(
            success=result.get("success", False),
            message=result.get("message", ""),
        )


def create_graphql_policy_client(node: Node) -> GraphQLPolicyClient:
    """
    Create a GraphQLPolicyClient for a node.

    Args:
        node: Node where policy-engine is running

    Returns:
        GraphQLPolicyClient instance
    """
    return GraphQLPolicyClient(node)
