# Copyright (c) Dufferin Software

"""
Shared helpers for the SNI-matching tests.

These stat-polling helpers were previously copy-pasted across the individual
``test_*.py`` modules in this package; consolidated here so there is a single
implementation of each.
"""

import time

# Polling budget / cadence for wait_verdicts.
_POLL_BUDGET_S = 5.0
_POLL_INTERVAL_S = 0.25


def rule_packets(policy_client, rule_id: int) -> int:
    stats = policy_client.get_rule_stats(rule_id=rule_id, direction="egress")
    if not stats.rules or not stats.rules[0].stats:
        return 0
    return stats.rules[0].stats.packets


def policy_drops(policy_client, interface: str) -> int:
    return policy_client.get_stats(
        interface, direction="egress"
    ).global_stats.policy_drops


def wait_verdicts(policy_client, baseline: int, want: int) -> int:
    deadline = time.monotonic() + _POLL_BUDGET_S
    last = baseline
    while time.monotonic() < deadline:
        last = policy_client.get_flow_verdicts(direction="egress").active_verdicts
        if last >= baseline + want:
            return last
        time.sleep(_POLL_INTERVAL_S)
    return last
