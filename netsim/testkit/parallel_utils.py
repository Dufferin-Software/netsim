# Copyright (c) Peter Morrow

"""
Utility functions for running tasks in parallel using ThreadPoolExecutor.

These functions simplify concurrent execution of I/O-bound operations
like SSH commands and package installations across multiple nodes.
"""

from concurrent.futures import ThreadPoolExecutor


def run_parallel(tasks, max_workers=None):
    """
    Execute multiple tasks in parallel using ThreadPoolExecutor.

    Args:
        tasks: List of (func, args, kwargs) tuples or (func, args) tuples
        max_workers: Maximum number of parallel workers (default: number of tasks)

    Returns:
        List of results in the same order as tasks

    Example:
        results = run_parallel([
            (ssh_command, (port1, "cmd1"), {}),
            (ssh_command, (port2, "cmd2"), {}),
        ])
    """
    if max_workers is None:
        max_workers = len(tasks)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for task in tasks:
            if len(task) == 3:
                func, args, kwargs = task
            elif len(task) == 2:
                func, args = task
                kwargs = {}
            else:
                raise ValueError(
                    f"Task must be (func, args) or (func, args, kwargs), got {task}"
                )

            futures.append(executor.submit(func, *args, **kwargs))

        # Wait for all tasks and return results
        return [future.result() for future in futures]


def run_parallel_simple(func, items, max_workers=None):
    """
    Execute the same function on multiple items in parallel.

    Args:
        func: Function to execute
        items: List of argument tuples or single arguments to pass to func
        max_workers: Maximum number of parallel workers (default: number of items)

    Returns:
        List of results in the same order as items

    Example:
        # Single argument per item
        run_parallel_simple(install_packages, [("node1", ["pkg"]), ("node2", ["pkg"])])

        # Multiple arguments per item
        run_parallel_simple(ssh_command, [(port1, "cmd1"), (port2, "cmd2")])
    """
    if max_workers is None:
        max_workers = len(items)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for item in items:
            # If item is a tuple, unpack it as arguments
            if isinstance(item, tuple):
                futures.append(executor.submit(func, *item))
            else:
                futures.append(executor.submit(func, item))

        return [future.result() for future in futures]
