# Copyright (c) Peter Morrow

"""
Reusable pytest infrastructure for testing software on a netsim topology.

A consuming project opts in from its rootdir ``conftest.py``::

    pytest_plugins = ["netsim.testkit.plugin"]

and then gets the fixtures in :mod:`netsim.testkit.plugin` — ``topology``,
``nodes``, ``node_interfaces``, ``configure_node_interfaces``,
``install_user_packages`` and the rest — plus the CLI options they read
(``--package-dir``, ``--feature``, ``--pause-on-failure``, ``--tpm``).

The plugin discovers a suite's topology by convention: a test in
``<dir>/`` loads ``<dir>/<dir>.yaml``.

Note that :class:`netsim.testkit.node.Node` (a live SSH handle to a booted
VM) is a different thing from :class:`netsim.topology.Node` (a node as
declared in the topology YAML).
"""

from netsim.testkit.base import BaseTopologyTests
from netsim.testkit.node import Node, NodeInterface

__all__ = ["BaseTopologyTests", "Node", "NodeInterface"]
