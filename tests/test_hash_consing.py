"""
Tests for the hash consing registry (Step 3).

Key correctness gate: the 4-policy example from Section 3.3 of the project
plan must produce EXACTLY 8 DAG nodes (not 11).

P1: a1 OR a2
P2: (a1 OR a2) AND (a2 AND a3)
P3: a2 AND a3
P4: (a2 AND a3) AND a4

Where:
  a1 = net == 'on-premise'
  a2 = time == 'business-hours'
  a3 = dept == 'engineering'
  a4 = clearance == 'top-secret'

Expected shared DAG structure (8 nodes):
  Layer 0 (leaves):  a1, a2, a3, a4                   <- 4 atoms
  Layer 1 (gates):   OR(a1,a2), AND(a2,a3)             <- 2 gates
  Layer 2 (gates):   AND(OR_12, AND_23), AND(AND_23,a4) <- 2 gates
  Total: 8 nodes
"""

import pytest

from dsl.parser import parse_predicate
from engine.hash_consing import HashConsingRegistry, build_shared_dag
from engine.gate_nodes import AtomicCheck, GateNode, ThresholdGate


# ---------------------------------------------------------------------------
# Helper: build a registry from a list of predicate strings
# ---------------------------------------------------------------------------

def build_dag_from_predicates(predicates: list[str]) -> tuple[HashConsingRegistry, list]:
    """Parse each predicate and build its shared DAG. Return (registry, roots)."""
    hc = HashConsingRegistry()
    roots = []
    for p in predicates:
        ast = parse_predicate(p)
        root = build_shared_dag(ast, hc)
        roots.append(root)
    return hc, roots


# ---------------------------------------------------------------------------
# Atoms
# ---------------------------------------------------------------------------

class TestAtomCreation:
    def test_same_atom_returns_same_object(self):
        hc = HashConsingRegistry()
        a = hc.get_or_create_atom("net", "==", "on-premise")
        b = hc.get_or_create_atom("net", "==", "on-premise")
        assert a is b

    def test_different_atoms_are_different_objects(self):
        hc = HashConsingRegistry()
        a = hc.get_or_create_atom("net", "==", "on-premise")
        b = hc.get_or_create_atom("time", "==", "business-hours")
        assert a is not b

    def test_node_count_increments_only_for_new_atoms(self):
        hc = HashConsingRegistry()
        hc.get_or_create_atom("net", "==", "on-premise")
        assert hc.node_count == 1
        hc.get_or_create_atom("net", "==", "on-premise")   # duplicate
        assert hc.node_count == 1
        hc.get_or_create_atom("time", "==", "business-hours")
        assert hc.node_count == 2

    def test_atom_inequality_operator(self):
        hc = HashConsingRegistry()
        eq = hc.get_or_create_atom("net", "==", "on-premise")
        ne = hc.get_or_create_atom("net", "!=", "on-premise")
        assert eq is not ne
        assert hc.node_count == 2

    def test_atom_in_operator(self):
        hc = HashConsingRegistry()
        a = hc.get_or_create_atom("role", "in", ["admin", "ops"])
        b = hc.get_or_create_atom("role", "in", ["admin", "ops"])
        assert a is b
        assert hc.node_count == 1


# ---------------------------------------------------------------------------
# Gates — commutativity
# ---------------------------------------------------------------------------

class TestGateCommutativity:
    def test_and_ab_equals_and_ba(self):
        hc = HashConsingRegistry()
        a = hc.get_or_create_atom("net", "==", "on-premise")
        b = hc.get_or_create_atom("time", "==", "business-hours")
        gate_ab = hc.get_or_create_gate("AND", [a, b])
        gate_ba = hc.get_or_create_gate("AND", [b, a])
        assert gate_ab is gate_ba
        # 2 atoms + 1 gate = 3 nodes
        assert hc.node_count == 3

    def test_or_ab_equals_or_ba(self):
        hc = HashConsingRegistry()
        a = hc.get_or_create_atom("net", "==", "on-premise")
        b = hc.get_or_create_atom("time", "==", "business-hours")
        gate_ab = hc.get_or_create_gate("OR", [a, b])
        gate_ba = hc.get_or_create_gate("OR", [b, a])
        assert gate_ab is gate_ba

    def test_and_not_same_as_or(self):
        hc = HashConsingRegistry()
        a = hc.get_or_create_atom("net", "==", "on-premise")
        b = hc.get_or_create_atom("time", "==", "business-hours")
        and_gate = hc.get_or_create_gate("AND", [a, b])
        or_gate = hc.get_or_create_gate("OR", [a, b])
        assert and_gate is not or_gate
        # 2 atoms + 2 gates = 4 nodes
        assert hc.node_count == 4

    def test_shared_child_across_gates(self):
        """AND(a,b) and OR(a,b) share the same atom objects."""
        hc = HashConsingRegistry()
        a = hc.get_or_create_atom("x", "==", "1")
        b = hc.get_or_create_atom("y", "==", "2")
        and_gate = hc.get_or_create_gate("AND", [a, b])
        or_gate = hc.get_or_create_gate("OR", [a, b])
        # The children of both gates ARE the same atom objects
        assert a in and_gate.children
        assert a in or_gate.children


# ---------------------------------------------------------------------------
# The critical 8-node test from Section 3.3
# ---------------------------------------------------------------------------

class TestFourPolicyExample:
    """
    This is the correctness GATE from the project plan.
    The 4-policy example must produce exactly 8 DAG nodes, not 11.
    """

    PREDICATES = [
        "a1 == 'on-premise' OR a2 == 'business-hours'",                          # P1: a1 OR a2
        "(a1 == 'on-premise' OR a2 == 'business-hours') AND (a2 == 'business-hours' AND a3 == 'engineering')",  # P2
        "a2 == 'business-hours' AND a3 == 'engineering'",                         # P3: a2 AND a3
        "(a2 == 'business-hours' AND a3 == 'engineering') AND a4 == 'top-secret'", # P4
    ]

    def test_exactly_8_nodes(self):
        hc, roots = build_dag_from_predicates(self.PREDICATES)
        assert hc.node_count == 8, (
            f"Expected 8 nodes in shared DAG but got {hc.node_count}. "
            "Check hash consing implementation for commutativity/sharing."
        )

    def test_p1_and_p2_share_or_node(self):
        hc, roots = build_dag_from_predicates(self.PREDICATES)
        p1_root, p2_root = roots[0], roots[1]
        # P1 root is OR(a1, a2)
        # P2 root is AND(OR(a1,a2), AND(a2,a3))
        # P2's first child should be the SAME object as P1's root
        assert isinstance(p2_root, GateNode)
        assert p2_root.operator == "AND"
        # One of P2's children is the OR gate, which is P1's root
        p2_children_ids = {id(c) for c in p2_root.children}
        assert id(p1_root) in p2_children_ids

    def test_p2_p3_p4_share_and_a2_a3(self):
        """AND(a2, a3) is shared between P2, P3, and P4."""
        hc, roots = build_dag_from_predicates(self.PREDICATES)
        p2_root, p3_root, p4_root = roots[1], roots[2], roots[3]

        # P3 root should be AND(a2, a3)
        assert isinstance(p3_root, GateNode)
        assert p3_root.operator == "AND"

        # P2's children include the same AND(a2,a3) as P3's root
        p2_children_ids = {id(c) for c in p2_root.children}
        assert id(p3_root) in p2_children_ids, "P2 and P3 should share AND(a2,a3)"

        # P4's children include the same AND(a2,a3) as P3's root
        assert isinstance(p4_root, GateNode)
        assert p4_root.operator == "AND"
        p4_children_ids = {id(c) for c in p4_root.children}
        assert id(p3_root) in p4_children_ids, "P4 and P3 should share AND(a2,a3)"

    def test_four_distinct_atoms(self):
        hc, roots = build_dag_from_predicates(self.PREDICATES)
        # Collect all atom nodes from the registry
        from engine.gate_nodes import AtomicCheck
        atoms = [v for v in hc._memo.values() if isinstance(v, AtomicCheck)]
        assert len(atoms) == 4


# ---------------------------------------------------------------------------
# ThresholdGate creation and sharing
# ---------------------------------------------------------------------------

class TestThresholdGate:
    def test_same_threshold_returns_same_object(self):
        hc = HashConsingRegistry()
        a = hc.get_or_create_atom("net", "==", "on-premise")
        b = hc.get_or_create_atom("time", "==", "business-hours")
        c = hc.get_or_create_atom("dept", "==", "engineering")
        t1 = hc.get_or_create_threshold(2, [a, b, c])
        t2 = hc.get_or_create_threshold(2, [a, b, c])
        assert t1 is t2

    def test_different_k_are_different_nodes(self):
        hc = HashConsingRegistry()
        a = hc.get_or_create_atom("net", "==", "on-premise")
        b = hc.get_or_create_atom("time", "==", "business-hours")
        c = hc.get_or_create_atom("dept", "==", "engineering")
        t1 = hc.get_or_create_threshold(1, [a, b, c])
        t2 = hc.get_or_create_threshold(2, [a, b, c])
        assert t1 is not t2

    def test_threshold_commutativity(self):
        """ATLEAST(2, a, b, c) == ATLEAST(2, c, b, a) — children sorted."""
        hc = HashConsingRegistry()
        a = hc.get_or_create_atom("x", "==", "1")
        b = hc.get_or_create_atom("y", "==", "2")
        c = hc.get_or_create_atom("z", "==", "3")
        t1 = hc.get_or_create_threshold(2, [a, b, c])
        t2 = hc.get_or_create_threshold(2, [c, b, a])
        assert t1 is t2


# ---------------------------------------------------------------------------
# build_shared_dag: end-to-end from parser output
# ---------------------------------------------------------------------------

class TestBuildSharedDag:
    def test_single_atom(self):
        hc = HashConsingRegistry()
        ast = parse_predicate("net == 'on-premise'")
        node = build_shared_dag(ast, hc)
        assert isinstance(node, AtomicCheck)
        assert node.attribute == "net"
        assert node.operator == "=="
        assert node.value == "on-premise"
        assert hc.node_count == 1

    def test_and_expression(self):
        hc = HashConsingRegistry()
        ast = parse_predicate("net == 'on-premise' AND time == 'business-hours'")
        node = build_shared_dag(ast, hc)
        assert isinstance(node, GateNode)
        assert node.operator == "AND"
        assert len(node.children) == 2
        # 2 atoms + 1 gate = 3
        assert hc.node_count == 3

    def test_shared_subexpr_across_two_predicates(self):
        """The same atom sub-expression is shared between two predicates."""
        hc = HashConsingRegistry()
        ast1 = parse_predicate("net == 'on-premise' AND time == 'business-hours'")
        ast2 = parse_predicate("dept == 'engineering' AND net == 'on-premise'")
        root1 = build_shared_dag(ast1, hc)
        root2 = build_shared_dag(ast2, hc)

        # net==on-premise atom should be the SAME object in both trees
        atom_net_in_p1 = next(c for c in root1.children
                              if isinstance(c, AtomicCheck) and c.attribute == "net")
        atom_net_in_p2 = next(c for c in root2.children
                              if isinstance(c, AtomicCheck) and c.attribute == "net")
        assert atom_net_in_p1 is atom_net_in_p2

    def test_atleast_predicate(self):
        hc = HashConsingRegistry()
        ast = parse_predicate(
            "ATLEAST(2, net == 'on-premise', time == 'business-hours', dept == 'engineering')"
        )
        node = build_shared_dag(ast, hc)
        assert isinstance(node, ThresholdGate)
        assert node.k == 2
        assert len(node.children) == 3
        # 3 atoms + 1 threshold = 4
        assert hc.node_count == 4

    def test_independent_predicates_no_sharing(self):
        """Predicates with no common sub-expressions have independent nodes."""
        hc = HashConsingRegistry()
        ast1 = parse_predicate("a == '1'")
        ast2 = parse_predicate("b == '2'")
        build_shared_dag(ast1, hc)
        build_shared_dag(ast2, hc)
        # Each is a distinct atom
        assert hc.node_count == 2
