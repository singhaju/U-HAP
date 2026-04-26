"""
Tests for Step 1: Core data models.
Verifies that all policy record types, graph node types, and gate node types
instantiate correctly and have the expected attributes.
"""
import pytest
from dsl.models import (
    RBACRecord, HierRecord, ABACRecord, ACLRecord, DenyRecord,
    ASTAtom, ASTBinary, ASTThreshold,
)
from graph.models import (
    RoleNode, ResourceNode, DenyTerminal, UserNode,
    HierEdge, PermEdge, GateEdge, ACLEdge, DenyEdge,
    PolicyGraph,
)
from engine.gate_nodes import AtomicCheck, GateNode, ThresholdGate, evaluate_dag


# ---------------------------------------------------------------------------
# DSL policy record types
# ---------------------------------------------------------------------------

class TestRBACRecord:
    def test_basic(self):
        r = RBACRecord(role="admin", resource="pods", namespace="prod", action="get")
        assert r.role == "admin"
        assert r.resource == "pods"
        assert r.namespace == "prod"
        assert r.action == "get"

    def test_frozen(self):
        r = RBACRecord(role="admin", resource="pods", namespace="prod", action="get")
        with pytest.raises((AttributeError, TypeError)):
            r.role = "other"

    def test_hashable(self):
        r1 = RBACRecord("admin", "pods", "prod", "get")
        r2 = RBACRecord("admin", "pods", "prod", "get")
        assert r1 == r2
        assert hash(r1) == hash(r2)


class TestHierRecord:
    def test_basic(self):
        h = HierRecord(parent_role="senior-dev", child_role="junior-dev", namespace="prod")
        assert h.parent_role == "senior-dev"
        assert h.child_role == "junior-dev"
        assert not h.is_wildcard if hasattr(h, "is_wildcard") else True


class TestABACRecord:
    def test_basic(self):
        a = ABACRecord(
            resource="pods", namespace="prod", action="get",
            predicate="net == 'on-premise'"
        )
        assert a.predicate == "net == 'on-premise'"


class TestACLRecord:
    def test_basic(self):
        a = ACLRecord(subject="charlie", resource="pods", namespace="dev", action="get")
        assert a.subject == "charlie"


class TestDenyRecord:
    def test_specific_user(self):
        d = DenyRecord(subject="eve", resource="secrets", namespace="prod", action="delete")
        assert not d.is_wildcard

    def test_wildcard(self):
        d = DenyRecord(subject="*", resource="secrets", namespace="prod", action="delete")
        assert d.is_wildcard


# ---------------------------------------------------------------------------
# Graph node types
# ---------------------------------------------------------------------------

class TestGraphNodes:
    def test_role_node_equality(self):
        r1 = RoleNode("admin")
        r2 = RoleNode("admin")
        assert r1 == r2
        assert hash(r1) == hash(r2)

    def test_resource_node_equality(self):
        n1 = ResourceNode("pods", "prod")
        n2 = ResourceNode("pods", "prod")
        assert n1 == n2

    def test_resource_node_inequality_namespace(self):
        n1 = ResourceNode("pods", "prod")
        n2 = ResourceNode("pods", "dev")
        assert n1 != n2

    def test_deny_terminal_singleton(self):
        d1 = DenyTerminal()
        d2 = DenyTerminal()
        assert d1 == d2

    def test_user_node(self):
        u = UserNode("alice")
        assert u.name == "alice"


class TestPolicyGraph:
    def test_add_deny_edge(self):
        g = PolicyGraph(namespace="prod", resource="pods")
        g.add_deny_edge("*", "delete")
        assert g.has_deny("alice", "delete")
        assert g.has_deny("bob", "delete")

    def test_add_acl_edge(self):
        g = PolicyGraph(namespace="dev", resource="pods")
        g.add_acl_edge("charlie", "get")
        assert g.has_acl("charlie", "get")
        assert not g.has_acl("dave", "get")

    def test_add_perm_edge(self):
        g = PolicyGraph(namespace="prod", resource="pods")
        g.add_perm_edge("viewer", "get")
        assert g.has_perm("viewer", "get")
        assert not g.has_perm("viewer", "delete")

    def test_add_hier_edge(self):
        g = PolicyGraph(namespace="prod", resource="pods")
        g.add_hier_edge("senior-dev", "junior-dev")
        g.add_hier_edge("junior-dev", "intern")
        assert g.get_children("senior-dev") == ["junior-dev"]
        assert g.get_children("junior-dev") == ["intern"]
        assert g.get_children("intern") == []

    def test_add_gate_edge(self):
        g = PolicyGraph(namespace="prod", resource="pods")
        atom = AtomicCheck("net", "==", "on-premise")
        g.add_gate_edge(atom, "get")
        gates = g.get_gate_edges("get")
        assert len(gates) == 1
        assert gates[0].gate_root is atom

    def test_specific_deny_vs_wildcard(self):
        g = PolicyGraph(namespace="prod", resource="pods")
        g.add_deny_edge("eve", "delete")
        assert g.has_deny("eve", "delete")
        # wildcard not added yet, other user should not be denied
        assert not g.has_deny("alice", "delete")
        # add wildcard
        g.add_deny_edge("*", "delete")
        assert g.has_deny("alice", "delete")


# ---------------------------------------------------------------------------
# Gate node types
# ---------------------------------------------------------------------------

class TestAtomicCheck:
    def test_equality_true(self):
        a = AtomicCheck("net", "==", "on-premise")
        assert a.evaluate({"net": "on-premise"}) is True

    def test_equality_false(self):
        a = AtomicCheck("net", "==", "on-premise")
        assert a.evaluate({"net": "remote"}) is False

    def test_inequality(self):
        a = AtomicCheck("time", "!=", "after-hours")
        assert a.evaluate({"time": "business-hours"}) is True
        assert a.evaluate({"time": "after-hours"}) is False

    def test_in_operator(self):
        a = AtomicCheck("role", "in", ["admin", "ops"])
        assert a.evaluate({"role": "admin"}) is True
        assert a.evaluate({"role": "viewer"}) is False

    def test_missing_attribute_returns_false(self):
        a = AtomicCheck("clearance", "==", "top-secret")
        assert a.evaluate({}) is False
        assert a.evaluate({"net": "on-premise"}) is False

    def test_canonical_key_stable(self):
        a = AtomicCheck("net", "==", "on-premise")
        k1 = a.canonical_key()
        k2 = a.canonical_key()
        assert k1 == k2
        assert k1 == ("atom", "net", "==", "on-premise")

    def test_frozen_hashable(self):
        a = AtomicCheck("net", "==", "on-premise")
        {a}  # must be hashable


class TestGateNode:
    def setup_method(self):
        self.a1 = AtomicCheck("net", "==", "on-premise")
        self.a2 = AtomicCheck("time", "==", "business-hours")
        self.a3 = AtomicCheck("dept", "==", "engineering")

    def test_and_all_true(self):
        g = GateNode("AND", [self.a1, self.a2])
        memo = {}
        ctx = {"net": "on-premise", "time": "business-hours"}
        assert evaluate_dag(g, ctx, memo) is True

    def test_and_one_false(self):
        g = GateNode("AND", [self.a1, self.a2])
        memo = {}
        ctx = {"net": "remote", "time": "business-hours"}
        assert evaluate_dag(g, ctx, memo) is False

    def test_or_one_true(self):
        g = GateNode("OR", [self.a1, self.a2])
        memo = {}
        ctx = {"net": "remote", "time": "business-hours"}
        assert evaluate_dag(g, ctx, memo) is True

    def test_or_all_false(self):
        g = GateNode("OR", [self.a1, self.a2])
        memo = {}
        ctx = {"net": "remote", "time": "after-hours"}
        assert evaluate_dag(g, ctx, memo) is False

    def test_canonical_key_commutative(self):
        g1 = GateNode("AND", [self.a2, self.a3])
        g2 = GateNode("AND", [self.a3, self.a2])
        # Keys must be equal regardless of child order
        assert g1.canonical_key() == g2.canonical_key()

    def test_memoization(self):
        """evaluate_dag must not evaluate the same node twice."""
        call_count = [0]
        original_evaluate = AtomicCheck.evaluate

        class CountingAtom(AtomicCheck):
            def evaluate(self, context):
                call_count[0] += 1
                return super().evaluate(context)

        a = CountingAtom("net", "==", "on-premise")
        # Build two gates sharing the same atom
        g1 = GateNode("AND", [a, self.a2])
        g2 = GateNode("OR", [a, self.a3])
        memo = {}
        ctx = {"net": "on-premise", "time": "business-hours", "dept": "finance"}
        evaluate_dag(g1, ctx, memo)
        evaluate_dag(g2, ctx, memo)
        # atom 'a' should have been evaluated exactly once
        assert call_count[0] == 1


class TestThresholdGate:
    def setup_method(self):
        self.a1 = AtomicCheck("net", "==", "on-premise")
        self.a2 = AtomicCheck("time", "==", "business-hours")
        self.a3 = AtomicCheck("dept", "==", "engineering")

    def test_threshold_met(self):
        t = ThresholdGate(k=2, children=[self.a1, self.a2, self.a3])
        ctx = {"net": "on-premise", "time": "business-hours", "dept": "finance"}
        assert evaluate_dag(t, ctx, {}) is True  # 2 of 3 true

    def test_threshold_not_met(self):
        t = ThresholdGate(k=2, children=[self.a1, self.a2, self.a3])
        ctx = {"net": "remote", "time": "after-hours", "dept": "engineering"}
        assert evaluate_dag(t, ctx, {}) is False  # 1 of 3 true

    def test_threshold_all(self):
        t = ThresholdGate(k=3, children=[self.a1, self.a2, self.a3])
        ctx = {"net": "on-premise", "time": "business-hours", "dept": "engineering"}
        assert evaluate_dag(t, ctx, {}) is True

    def test_canonical_key(self):
        t = ThresholdGate(k=2, children=[self.a1, self.a2, self.a3])
        key = t.canonical_key()
        assert key[0] == "THRESHOLD"
        assert key[1] == 2
