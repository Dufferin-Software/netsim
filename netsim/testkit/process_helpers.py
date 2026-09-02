# Copyright (c) Peter Morrow

"""
Process management helper utilities for testing.

Provides abstracted routines for common process operations used in tests.
"""

import time
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def kill_process(
    node,
    process_name: str,
    timeout: int = 5,
    signal_sequence: Optional[list[int]] = None,
) -> int:
    """Kill processes by name on a node.

    Attempts to kill processes gracefully, then forcefully if needed.

    Args:
        node: Node object with ssh_command method.
        process_name: Name of process to kill (e.g., "iperf3").
        timeout: SSH command timeout in seconds.
        signal_sequence: Sequence of signals to try in order.
                        Defaults to [15, 9] (SIGTERM, SIGKILL).

    Returns:
        Number of processes that were killed.
    """
    if signal_sequence is None:
        signal_sequence = [15, 9]  # SIGTERM, SIGKILL

    killed_count = 0

    try:
        for signal in signal_sequence:
            try:
                node.ssh_command(
                    f"pkill -{signal} {process_name} || true", timeout=timeout
                )
                time.sleep(0.5)
            except Exception:
                pass

        # Verify processes are gone
        try:
            result = node.ssh_command(
                f"pgrep {process_name} | wc -l", timeout=timeout
            ).strip()
            killed_count = int(result) if result else 0
        except Exception:
            killed_count = 0

        # Last resort
        if killed_count > 0:
            try:
                node.ssh_command(f"killall -9 {process_name} || true", timeout=timeout)
            except Exception:
                pass

    except Exception as e:
        logger.warning(f"Error killing {process_name} on {node.name}: {e}")

    return killed_count
