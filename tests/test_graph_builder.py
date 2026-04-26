"""
Tests for the graph builder (Step 4) — Phase 1: Algorithm 1.

Covers:
  - Correct edge creation for each policy record type
  - Hash consing integration (ABAC predicates produce shared DAG nodes)
  - DAG property: cycle detection for role hierarchies
  - Resource isolation: different resources get different graphs
  - Registry load and lookup
"""

import pytest

from dsl.models import RBACRecord, HierRecord, ABACRecord, ACLRecord, DenyRecord
from graph.builder import build_graph, detect_hierarchy_cycle
from graph.models import PolicyGraph, GateEdge
from graph.registry import GraphRegistry
from engine.gate_nodes import AtomicCheck, GateNode


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_records(**kwargs):
    """Build a minimal set of records for testing."""
    return kwargs


NAMESPACE = "prod"
RESOURCE  = "pods"


# ---------------------------------------------------------------------------
# Hierarchy edges
# ---------------------------------------------------------------------------

class TestHierarchyEdges:
    def test_hier_edge_added(self):
        records = [
            HierRecord(parent_role="admin", child_role="viewer", namespace=NAMESPACE),
        ]
        g = build_graph(records, NAMESPACE, RESOURCE)
        assert "viewer" in g.get_children("admin")

    def test_multi_hop_hierarchy(self):
        records = [
            HierRecord(parent_role="senior", child_role="junior", namespace=NAMESPACE),
            HierRecord(parent_role="junior", child_role="intern", namespace=NAMESPACE),
        ]
        g = build_graph(records, NAMESPACE, RESOURCE)
        assert "junior" in g.get_children("senior")
        assert "intern" in g.get_children("junior")

    def test_cycle_detection_direct(self):
        records = [
            HierRecord(parent_role="a", child_role="b", namespace=NAMESPACE),
            HierRecord(parent_role="b", child_role="a", namespace=NAMESPACE),
        ]
        with pytest.raises(ValueError, match="[Cc]ycle"):
            build_graph(records, NAMESPACE, RESOURCE)

    def test_cycle_detection_indirect(self):
        records = [
            HierRecord(parent_role="a", child_role="b", namespace=NAMESPACE),
            HierRecord(parent_role="b", child_role="c", namespace=NAMESPACE),
            HierRecord(parent_role="c", child_role="a", namespace=NAMESPACE),
        ]
        with pytest.raises(ValueError, match="[Cc]ycle"):
            build_graph(records, NAMESPACE, RESOURCE)

    def test_detect_hierarchy_cycle_standalone(self):
        hier = {"a": ["b"], "b": ["c"], "c": ["a"]}
        with pytest.raises(ValueError, match="[Cc]ycle"):
            detect_hierarchy_cycle(hier)

    def test_no_cycle_is_ok(self):
        hier = {"a": ["b", "c"], "b": ["d"], "c": ["d"]}
        detect_hierarchy_cycle(hier)   # should not raise


# ---------------------------------------------------------------------------
# RBAC permission edges
# ---------------------------------------------------------------------------

class TestRBACEdges:
    def test_perm_edge_added(self):
        records = [
            RBACRecord(role="viewer", resource=RESOURCE, namespace=NAMESPACE, action="get"),
        ]
        g = build_graph(records, NAMESPACE, RESOURCE)
        assert g.has_perm("viewer", "get")

    def test_multiple_actions(self):
        records = [
            RBACRecord(role="admin", resource=RESOURCE, namespace=NAMESPACE, action="get"),
            RBACRecord(role="admin", resource=RESOURCE, namespace=NAMESPACE, action="delete"),
        ]
        g = build_graph(records, NAMESPACE, RESOURCE)
        assert g.has_perm("admin", "get")
        assert g.has_perm("admin", "delete")

    def test_perm_edge_missing(self):
        records = [
            RBACRecord(role="viewer", resource=RESOURCE, namespace=NAMESPACE, action="get"),
        ]
        g = build_graph(records, NAMESPACE, RESOURCE)
        assert not g.has_perm("viewer", "delete")


# ---------------------------------------------------------------------------
# ABAC gate edges (with hash consing)
# ---------------------------------------------------------------------------

class TestABACEdges:
    def test_single_gate_edge(self):
        records = [
            ABACRecord(
                resource=RESOURCE, namespace=NAMESPACE, action="get",
                predicate="net == 'on-premise' AND time == 'business-hours'",
            ),
        ]
        g = build_graph(records, NAMESPACE, RESOURCE)
        gates = g.get_gate_edges("get")
        assert len(gates) == 1
        assert isinstance(gates[0].gate_root, GateNode)

    def test_multiple_abac_rules_same_action(self):
        records = [
            ABACRecord(
                resource=RESOURCE, namespace=NAMESPACE, action="get",
                predicate="net == 'on-premise'",
            ),
            ABACRecord(
                resource=RESOURCE, namespace=NAMESPACE, action="get",
                predicate="dept == 'engineering'",
            ),
        ]
        g = build_graph(records, NAMESPACE, RESOURCE)
        gates = g.get_gate_edges("get")
        assert len(gates) == 2

    def test_shared_subexpr_via_hash_consing(self):
        """Two predicates sharing a sub-expression produce shared DAG nodes."""
        records = [
            ABACRecord(
                resource=RESOURCE, namespace=NAMESPACE, action="get",
                predicate="net == 'on-premise' AND time == 'business-hours'",
            ),
            ABACRecord(
                resource=RESOURCE, namespace=NAMESPACE, action="get",
                predicate="dept == 'engineering' AND net == 'on-premise'",
            ),
        ]
        g = build_graph(records, NAMESPACE, RESOURCE)
        gates = g.get_gate_edges("get")
        root1, root2 = gates[0].gate_root, gates[1].gate_root

        # Both roots are AND gates
        assert isinstance(root1, GateNode)
        assert isinstance(root2, GateNode)

        # net == 'on-premise' atom is the same object in both trees
        def find_atom(node, attr):
            if isinstance(node, AtomicCheck) and node.attribute == attr:
                return node
            if isinstance(node, GateNode):
                for c in node.children:
                    found = find_atom(c, attr)
                    if found:
                        return found
            return None

        atom1 = find_atom(root1, "net")
        atom2 = find_atom(root2, "net")
        assert atom1 is atom2, "Shared atom should be the same object"

    def test_hash_consing_node_count(self):
        """Verify the 8-node property from Section 3.3 of the project plan."""
        records = [
            ABACRecord(
                resource=RESOURCE, namespace=NAMESPACE, action="get",
                predicate="a1 == 'on-premise' OR a2 == 'business-hours'",
            ),
            ABACRecord(
                resource=RESOURCE, namespace=NAMESPACE, action="get",
                predicate="(a1 == 'on-premise' OR a2 == 'business-hours') AND (a2 == 'business-hours' AND a3 == 'engineering')",
            ),
            ABACRecord(
                resource=RESOURCE, namespace=NAMESPACE, action="get",
                predicate="a2 == 'business-hours' AND a3 == 'engineering'",
            ),
            ABACRecord(
                resource=RESOURCE, namespace=NAMESPACE, action="get",
                predicate="(a2 == 'business-hours' AND a3 == 'engineering') AND a4 == 'top-secret'",
            ),
        ]
        g = build_graph(records, NAMESPACE, RESOURCE)
        assert g._hc_registry.node_count == 8

    def test_abac_atom_predicate(self):
        """A single-atom predicate creates one AtomicCheck gate root."""
        records = [
            ABACRecord(
                resource=RESOURCE, namespace=NAMESPACE, action="get",
                predicate="dept == 'engineering'",
            ),
        ]
        g = build_graph(records, NAMESPACE, RESOURCE)
        gates = g.get_gate_edges("get")
        assert len(gates) == 1
        assert isinstance(gates[0].gate_root, AtomicCheck)


# ---------------------------------------------------------------------------
# ACL edges
# ---------------------------------------------------------------------------

class TestACLEdges:
    def test_acl_edge_added(self):
        records = [
            ACLRecord(subject="charlie", resource=RESOURCE,
                      namespace=NAMESPACE, action="get"),
        ]
        g = build_graph(records, NAMESPACE, RESOURCE)
        assert g.has_acl("charlie", "get")

    def test_acl_edge_missing(self):
        records = [
            ACLRecord(subject="charlie", resource=RESOURCE,
                      namespace=NAMESPACE, action="get"),
        ]
        g = build_graph(records, NAMESPACE, RESOURCE)
        assert not g.has_acl("alice", "get")
        assert not g.has_acl("charlie", "delete")


# ---------------------------------------------------------------------------
# Deny edges
# ---------------------------------------------------------------------------

class TestDenyEdges:
    def test_specific_deny_edge(self):
        records = [
            DenyRecord(subject="mallory", resource=RESOURCE,
                       namespace=NAMESPACE, action="delete"),
        ]
        g = build_graph(records, NAMESPACE, RESOURCE)
        assert g.has_deny("mallory", "delete")

    def test_wildcard_deny_edge(self):
        records = [
            DenyRecord(subject="*", resource=RESOURCE,
                       namespace=NAMESPACE, action="delete"),
        ]
        g = build_graph(records, NAMESPACE, RESOURCE)
        # Wildcard should match any subject
        assert g.has_deny("alice", "delete")
        assert g.has_deny("bob", "delete")

    def test_deny_does_not_match_different_action(self):
        records = [
            DenyRecord(subject="*", resource=RESOURCE,
                       namespace=NAMESPACE, action="delete"),
        ]
        g = build_graph(records, NAMESPACE, RESOURCE)
        assert not g.has_deny("alice", "get")


# ---------------------------------------------------------------------------
# Resource isolation
# ---------------------------------------------------------------------------

class TestResourceIsolation:
    def test_different_resources_are_independent(self):
        """Graphs for different resources are completely independent."""
        registry = GraphRegistry()
        records = [
            RBACRecord(role="viewer", resource="pods",
                       namespace=NAMESPACE, action="get"),
            RBACRecord(role="admin", resource="secrets",
                       namespace=NAMESPACE, action="get"),
        ]
        registry.load(records)
        pods_graph = registry.get(NAMESPACE, "pods")
        secrets_graph = registry.get(NAMESPACE, "secrets")

        assert pods_graph is not None
        assert secrets_graph is not None
        assert pods_graph.has_perm("viewer", "get")
        assert not pods_graph.has_perm("admin", "get")
        assert secrets_graph.has_perm("admin", "get")
        assert not secrets_graph.has_perm("viewer", "get")

    def test_different_namespaces_are_independent(self):
        registry = GraphRegistry()
        records = [
            RBACRecord(role="viewer", resource="pods",
                       namespace="prod", action="get"),
            RBACRecord(role="viewer", resource="pods",
                       namespace="dev", action="list"),
        ]
        registry.load(records)
        prod = registry.get("prod", "pods")
        dev = registry.get("dev", "pods")
        assert prod.has_perm("viewer", "get")
        assert not prod.has_perm("viewer", "list")
        assert dev.has_perm("viewer", "list")
        assert not dev.has_perm("viewer", "get")


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class TestGraphRegistry:
    def test_get_missing_returns_none(self):
        registry = GraphRegistry()
        assert registry.get("nonexistent", "pods") is None

    def test_set_and_get(self):
        registry = GraphRegistry()
        g = build_graph([], "prod", "pods")
        registry.set("prod", "pods", g)
        assert registry.get("prod", "pods") is g

    def test_load_multiple_resources(self):
        registry = GraphRegistry()
        records = [
            RBACRecord(role="r1", resource="pods",
                       namespace="prod", action="get"),
            RBACRecord(role="r2", resource="secrets",
                       namespace="prod", action="get"),
            RBACRecord(role="r3", resource="pods",
                       namespace="dev", action="get"),
        ]
        registry.load(records)
        assert len(registry) == 3

    def test_clear(self):
        registry = GraphRegistry()
        registry.load([
            RBACRecord(role="r", resource="pods", namespace="prod", action="get"),
        ])
        assert len(registry) == 1
        registry.clear()
        assert len(registry) == 0

    def test_namespaces(self):
        registry = GraphRegistry()
        registry.load([
            RBACRecord(role="r", resource="pods", namespace="prod", action="get"),
            RBACRecord(role="r", resource="pods", namespace="dev", action="get"),
        ])
        ns = registry.namespaces()
        assert set(ns) == {"prod", "dev"}

    def test_resources(self):
        registry = GraphRegistry()
        registry.load([
            RBACRecord(role="r", resource="pods", namespace="prod", action="get"),
            RBACRecord(role="r", resource="secrets", namespace="prod", action="get"),
        ])
        res = registry.resources("prod")
        assert set(res) == {"pods", "secrets"}
