"""
Example tests for two-node topology.

This test suite demonstrates:
- Inheriting from BaseTopologyTests for standard validation
- Adding topology-specific tests

The base tests automatically validate:
- Node and interface configuration
- Interface discovery
- IP assignment
- Connectivity between nodes
- Interface control (up/down)
"""

import subprocess
import pytest
from tests.conftest import BaseTopologyTests


class TestTwoNodeConnectivity(BaseTopologyTests):
    """Test connectivity between two nodes.
    
    Inherits standard tests from BaseTopologyTests.
    Add topology-specific tests here.
    """

    def test_two_nodes_exist(self, topology):
        """Verify topology has exactly two nodes."""
        assert len(topology.nodes) == 2, "Two-node topology should have exactly 2 nodes"
        assert topology.nodes[0].name == "node1"
        assert topology.nodes[1].name == "node2"

    def test_single_shared_network(self, topology):
        """Verify both nodes share exactly one network."""
        assert len(topology.networks) == 1, "Should have exactly one network"
        
        net1 = topology.get_network("net1")
        assert net1 is not None, "Network 'net1' should exist"
        assert net1.subnet == "10.0.1.0/24"
        
        # Both nodes should be on net1
        for node in topology.nodes:
            assert "net1" in node.networks, f"{node.name} should be on net1"

