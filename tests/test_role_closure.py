"""
Tests for compiler/role_closure.py (Step 4 of v2 migration).

Covers:
  - detect_hierarchy_cycle: detects cycles, passes for DAGs
  - compute_transitive_closure: correct reachability
  - get_ancestors: correct reverse reachability (used for building I_rbac)
"""

import pytest
from compiler.role_closure import (
    detect_hierarchy_cycle,
    compute_transitive_closure,
    get_ancestors,
)


# ---------------------------------------------------------------------------
# detect_hierarchy_cycle
# ---------------------------------------------------------------------------

class TestDetectCycle:
    def test_no_edges_no_cycle(self):
        detect_hierarchy_cycle({})  # should not raise

    def test_linear_chain_no_cycle(self):
        # A -> B -> C
        edges = {"A": ["B"], "B": ["C"]}
        detect_hierarchy_cycle(edges)

    def test_diamond_no_cycle(self):
        # A -> B, A -> C, B -> D, C -> D (diamond — acyclic)
        edges = {"A": ["B", "C"], "B": ["D"], "C": ["D"]}
        detect_hierarchy_cycle(edges)

    def test_self_loop_is_cycle(self):
        edges = {"A": ["A"]}
        with pytest.raises(ValueError, match="[Cc]ycle"):
            detect_hierarchy_cycle(edges)

    def test_simple_cycle(self):
        # A -> B -> A
        edges = {"A": ["B"], "B": ["A"]}
        with pytest.raises(ValueError, match="[Cc]ycle"):
            detect_hierarchy_cycle(edges)

    def test_longer_cycle(self):
        # A -> B -> C -> A
        edges = {"A": ["B"], "B": ["C"], "C": ["A"]}
        with pytest.raises(ValueError, match="[Cc]ycle"):
            detect_hierarchy_cycle(edges)

    def test_cycle_in_branch(self):
        # A -> B, B -> C, C -> B (cycle in the branch)
        edges = {"A": ["B"], "B": ["C"], "C": ["B"]}
        with pytest.raises(ValueError, match="[Cc]ycle"):
            detect_hierarchy_cycle(edges)

    def test_s7_hierarchy_no_cycle(self):
        """S7 hierarchy: senior-dev -> junior-dev -> intern (no cycle)."""
        edges = {
            "senior-dev": ["junior-dev"],
            "junior-dev": ["intern"],
        }
        detect_hierarchy_cycle(edges)


# ---------------------------------------------------------------------------
# compute_transitive_closure
# ---------------------------------------------------------------------------

class TestTransitiveClosure:
    def test_empty_hierarchy(self):
        closure = compute_transitive_closure({})
        assert closure == {}

    def test_single_edge(self):
        # A -> B
        closure = compute_transitive_closure({"A": ["B"]})
        assert closure["A"] == {"B"}
        assert closure["B"] == set()

    def test_two_hop_chain(self):
        # A -> B -> C
        closure = compute_transitive_closure({"A": ["B"], "B": ["C"]})
        assert closure["A"] == {"B", "C"}
        assert closure["B"] == {"C"}
        assert closure["C"] == set()

    def test_s7_three_hop(self):
        """S7: senior-dev -> junior-dev -> intern."""
        edges = {
            "senior-dev": ["junior-dev"],
            "junior-dev": ["intern"],
        }
        closure = compute_transitive_closure(edges)
        assert closure["senior-dev"] == {"junior-dev", "intern"}
        assert closure["junior-dev"] == {"intern"}
        assert closure["intern"] == set()

    def test_diamond(self):
        # A -> B, A -> C, B -> D, C -> D
        edges = {"A": ["B", "C"], "B": ["D"], "C": ["D"]}
        closure = compute_transitive_closure(edges)
        assert closure["A"] == {"B", "C", "D"}
        assert closure["B"] == {"D"}
        assert closure["C"] == {"D"}
        assert closure["D"] == set()

    def test_cycle_raises(self):
        with pytest.raises(ValueError, match="[Cc]ycle"):
            compute_transitive_closure({"A": ["B"], "B": ["A"]})

    def test_no_self_reference_in_closure(self):
        """A role should NOT appear in its own closure."""
        edges = {"A": ["B"]}
        closure = compute_transitive_closure(edges)
        assert "A" not in closure["A"]

    def test_multiple_children(self):
        # admin -> [editor, viewer]
        edges = {"admin": ["editor", "viewer"], "editor": ["viewer"]}
        closure = compute_transitive_closure(edges)
        assert closure["admin"] == {"editor", "viewer"}
        assert closure["editor"] == {"viewer"}


# ---------------------------------------------------------------------------
# get_ancestors
# ---------------------------------------------------------------------------

class TestGetAncestors:
    def test_no_ancestors(self):
        """Root role has no ancestors (nothing points to it)."""
        edges = {"senior-dev": ["junior-dev"], "junior-dev": ["intern"]}
        ancs = get_ancestors("senior-dev", edges)
        assert ancs == set()

    def test_one_ancestor(self):
        """junior-dev has one ancestor: senior-dev."""
        edges = {"senior-dev": ["junior-dev"], "junior-dev": ["intern"]}
        ancs = get_ancestors("junior-dev", edges)
        assert ancs == {"senior-dev"}

    def test_two_ancestors(self):
        """intern has two ancestors: junior-dev and senior-dev."""
        edges = {"senior-dev": ["junior-dev"], "junior-dev": ["intern"]}
        ancs = get_ancestors("intern", edges)
        assert ancs == {"junior-dev", "senior-dev"}

    def test_diamond_ancestors(self):
        # A -> B, A -> C, B -> D, C -> D
        # D is reached by both B and C, and transitively by A
        edges = {"A": ["B", "C"], "B": ["D"], "C": ["D"]}
        ancs = get_ancestors("D", edges)
        assert ancs == {"A", "B", "C"}

    def test_root_with_no_edges(self):
        ancs = get_ancestors("orphan", {})
        assert ancs == set()

    def test_s7_intern_ancestors(self):
        """S7: intern's ancestors are junior-dev and senior-dev.

        This is used to build I_rbac: if intern has 'get' permission,
        then both junior-dev and senior-dev should also be in I_rbac.
        """
        edges = {
            "senior-dev": ["junior-dev"],
            "junior-dev": ["intern"],
        }
        ancs = get_ancestors("intern", edges)
        assert "junior-dev" in ancs
        assert "senior-dev" in ancs
        assert len(ancs) == 2
