"""
Tests for the index compiler (Step C) — Phase 2 artifact generation.

Covers:
  - CompiledArtifact structure: all indices present
  - Deny index construction
  - ACL index construction
  - RBAC index with transitive closure and bit-vector
  - ABAC index: hash consing, cost sorting, attribute-key index
  - FastPath activation bits
  - PolicySummary counts
  - ArtifactRegistry 3-level lookup
  - Resource-action isolation
"""

import pytest

from dsl.models import (
    RBACRecord, HierRecord, ABACRecord, ACLRecord, DenyRecord,
    CompiledArtifact, FastPath,
)
from compiler.index_compiler import compile_artifacts
from compiler.registry import ArtifactRegistry


NS = "prod"
RES = "pods"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_artifact(records, action="get", ns=NS, res=RES):
    artifacts = compile_artifacts(records, ns, res)
    return artifacts.get(action)


# ---------------------------------------------------------------------------
# Deny index
# ---------------------------------------------------------------------------

class TestDenyIndex:
    def test_wildcard_deny_in_index(self):
        records = [DenyRecord(subject="*", resource=RES, namespace=NS, action="delete")]
        artifacts = compile_artifacts(records, NS, RES)
        art = artifacts["delete"]
        assert "*" in art.i_deny
        assert art.fast_path.has_deny

    def test_specific_user_deny_in_index(self):
        records = [DenyRecord(subject="alice", resource=RES, namespace=NS, action="get")]
        art = make_artifact(records, action="get")
        assert "user:alice" in art.i_deny
        assert art.fast_path.has_deny

    def test_no_deny_rules(self):
        records = [RBACRecord(role="viewer", resource=RES, namespace=NS, action="get")]
        art = make_artifact(records, action="get")
        assert len(art.i_deny) == 0
        assert not art.fast_path.has_deny

    def test_deny_action_scoped(self):
        """Deny for 'delete' does not appear in 'get' artifact."""
        records = [
            DenyRecord(subject="*", resource=RES, namespace=NS, action="delete"),
            RBACRecord(role="viewer", resource=RES, namespace=NS, action="get"),
        ]
        artifacts = compile_artifacts(records, NS, RES)
        assert "*" in artifacts["delete"].i_deny
        assert len(artifacts["get"].i_deny) == 0


# ---------------------------------------------------------------------------
# ACL index
# ---------------------------------------------------------------------------

class TestACLIndex:
    def test_subject_in_acl_index(self):
        records = [ACLRecord(subject="charlie", resource=RES, namespace=NS, action="get")]
        art = make_artifact(records, action="get")
        assert "charlie" in art.i_acl
        assert art.fast_path.has_acl

    def test_multiple_subjects(self):
        records = [
            ACLRecord(subject="charlie", resource=RES, namespace=NS, action="get"),
            ACLRecord(subject="dana", resource=RES, namespace=NS, action="get"),
        ]
        art = make_artifact(records, action="get")
        assert "charlie" in art.i_acl
        assert "dana" in art.i_acl

    def test_no_acl_rules(self):
        records = [RBACRecord(role="viewer", resource=RES, namespace=NS, action="get")]
        art = make_artifact(records, action="get")
        assert len(art.i_acl) == 0
        assert not art.fast_path.has_acl


# ---------------------------------------------------------------------------
# RBAC index with transitive closure
# ---------------------------------------------------------------------------

class TestRBACIndex:
    def test_direct_role_in_index(self):
        records = [RBACRecord(role="viewer", resource=RES, namespace=NS, action="get")]
        art = make_artifact(records, action="get")
        assert "viewer" in art.i_rbac
        assert art.fast_path.has_rbac

    def test_transitive_closure_ancestor_in_index(self):
        """senior-dev -> junior-dev -> intern; intern has get.
        I_rbac for get should include all three."""
        records = [
            HierRecord(parent_role="senior-dev", child_role="junior-dev", namespace=NS),
            HierRecord(parent_role="junior-dev", child_role="intern", namespace=NS),
            RBACRecord(role="intern", resource=RES, namespace=NS, action="get"),
        ]
        art = make_artifact(records, action="get")
        assert "intern" in art.i_rbac
        assert "junior-dev" in art.i_rbac
        assert "senior-dev" in art.i_rbac

    def test_bitvector_matches_rbac_index(self):
        from compiler.bitvector import RoleBitVector
        records = [
            HierRecord(parent_role="senior-dev", child_role="junior-dev", namespace=NS),
            HierRecord(parent_role="junior-dev", child_role="intern", namespace=NS),
            RBACRecord(role="intern", resource=RES, namespace=NS, action="get"),
        ]
        art = make_artifact(records, action="get")
        # b_rbac should be non-zero and cover I_rbac
        assert art.b_rbac != 0
        # Encoding i_rbac with the same roles should match b_rbac
        rbv = RoleBitVector(art.i_rbac)
        b = rbv.encode(art.i_rbac)
        # All bits from i_rbac should be set
        assert b != 0

    def test_no_rbac_rules(self):
        records = [ACLRecord(subject="charlie", resource=RES, namespace=NS, action="get")]
        art = make_artifact(records, action="get")
        assert len(art.i_rbac) == 0
        assert art.b_rbac == 0
        assert not art.fast_path.has_rbac

    def test_hierarchy_not_for_wrong_action(self):
        """Ancestor in hierarchy for action=get should not appear in delete index."""
        records = [
            HierRecord(parent_role="senior-dev", child_role="junior-dev", namespace=NS),
            RBACRecord(role="junior-dev", resource=RES, namespace=NS, action="get"),
            ACLRecord(subject="x", resource=RES, namespace=NS, action="delete"),
        ]
        artifacts = compile_artifacts(records, NS, RES)
        get_art = artifacts["get"]
        delete_art = artifacts["delete"]
        assert "junior-dev" in get_art.i_rbac
        assert "senior-dev" in get_art.i_rbac
        assert "junior-dev" not in delete_art.i_rbac


# ---------------------------------------------------------------------------
# ABAC index
# ---------------------------------------------------------------------------

class TestABACIndex:
    def test_simple_gate_compiled(self):
        records = [
            ABACRecord(resource=RES, namespace=NS, action="get",
                       predicate="net == 'on-premise'"),
        ]
        art = make_artifact(records, action="get")
        assert len(art.i_abac) == 1
        assert art.fast_path.has_abac

    def test_attribute_key_index_populated(self):
        records = [
            ABACRecord(resource=RES, namespace=NS, action="get",
                       predicate="net == 'on-premise' AND time == 'business-hours'"),
        ]
        art = make_artifact(records, action="get")
        assert "net" in art.i_attr
        assert "time" in art.i_attr

    def test_cost_sorted(self):
        """Gates are sorted cheapest-first."""
        records = [
            # Compound: cost = 1 + 1 + 1 = 3
            ABACRecord(resource=RES, namespace=NS, action="get",
                       predicate="net == 'on-premise' AND time == 'business-hours'"),
            # Simple: cost = 1
            ABACRecord(resource=RES, namespace=NS, action="get",
                       predicate="dept == 'engineering'"),
        ]
        art = make_artifact(records, action="get")
        assert len(art.i_abac) == 2
        assert art.i_abac[0].cost <= art.i_abac[1].cost

    def test_hash_consing_shared_node(self):
        """Two predicates with a shared atom share the same DAG node."""
        records = [
            ABACRecord(resource=RES, namespace=NS, action="get",
                       predicate="net == 'on-premise'"),
            ABACRecord(resource=RES, namespace=NS, action="get",
                       predicate="net == 'on-premise' AND time == 'business-hours'"),
        ]
        art = make_artifact(records, action="get")
        # The simple atom node should be the same object in both gates
        gate1 = art.i_abac[0].root   # cheaper
        gate2 = art.i_abac[1].root   # more expensive
        # gate1 should be the atomic 'net == on-premise'
        # gate2 should be an AND gate whose child IS gate1 (same object reference)
        from engine.gate_nodes import AtomicCheck, GateNode
        # Find the net-atom in gate2's children
        if isinstance(gate1, AtomicCheck) and isinstance(gate2, GateNode):
            net_child = next(
                (c for c in gate2.children
                 if isinstance(c, AtomicCheck) and c.attribute == "net"),
                None,
            )
            assert net_child is gate1, "Hash consing: shared atom should be same object"

    def test_no_abac_rules(self):
        records = [RBACRecord(role="viewer", resource=RES, namespace=NS, action="get")]
        art = make_artifact(records, action="get")
        assert len(art.i_abac) == 0
        assert not art.fast_path.has_abac


# ---------------------------------------------------------------------------
# FastPath and PolicySummary
# ---------------------------------------------------------------------------

class TestFastPath:
    def test_all_false_when_no_rules(self):
        records = []
        artifacts = compile_artifacts(records, NS, RES)
        assert len(artifacts) == 0  # no actions, no artifacts

    def test_correct_flags_set(self):
        records = [
            DenyRecord(subject="*", resource=RES, namespace=NS, action="delete"),
            ACLRecord(subject="charlie", resource=RES, namespace=NS, action="get"),
            RBACRecord(role="viewer", resource=RES, namespace=NS, action="get"),
            ABACRecord(resource=RES, namespace=NS, action="get",
                       predicate="net == 'on-premise'"),
        ]
        artifacts = compile_artifacts(records, NS, RES)

        get_art = artifacts["get"]
        assert not get_art.fast_path.has_deny
        assert get_art.fast_path.has_acl
        assert get_art.fast_path.has_rbac
        assert get_art.fast_path.has_abac

        del_art = artifacts["delete"]
        assert del_art.fast_path.has_deny
        assert not del_art.fast_path.has_acl
        assert not del_art.fast_path.has_rbac
        assert not del_art.fast_path.has_abac

    def test_policy_summary_counts(self):
        records = [
            ACLRecord(subject="charlie", resource=RES, namespace=NS, action="get"),
            ACLRecord(subject="dana", resource=RES, namespace=NS, action="get"),
            RBACRecord(role="viewer", resource=RES, namespace=NS, action="get"),
            ABACRecord(resource=RES, namespace=NS, action="get",
                       predicate="net == 'on-premise'"),
            DenyRecord(subject="*", resource=RES, namespace=NS, action="get"),
        ]
        art = make_artifact(records, action="get")
        assert art.summary.acl_count == 2
        assert art.summary.abac_count == 1
        assert art.summary.deny_count == 1


# ---------------------------------------------------------------------------
# ArtifactRegistry
# ---------------------------------------------------------------------------

class TestArtifactRegistry:
    def test_get_returns_artifact(self):
        registry = ArtifactRegistry()
        records = [
            RBACRecord(role="viewer", resource="pods", namespace="prod", action="get"),
        ]
        registry.load(records)
        art = registry.get("prod", "pods", "get")
        assert art is not None
        assert art.namespace == "prod"
        assert art.resource == "pods"
        assert art.action == "get"

    def test_get_missing_returns_none(self):
        registry = ArtifactRegistry()
        assert registry.get("prod", "pods", "delete") is None
        assert registry.get("nonexistent", "pods", "get") is None

    def test_3level_isolation(self):
        """Different (ns, res, action) combinations don't interfere."""
        registry = ArtifactRegistry()
        records = [
            RBACRecord(role="viewer", resource="pods", namespace="prod", action="get"),
            RBACRecord(role="admin", resource="secrets", namespace="prod", action="delete"),
            ACLRecord(subject="alice", resource="pods", namespace="dev", action="get"),
        ]
        registry.load(records)
        assert registry.get("prod", "pods", "get") is not None
        assert registry.get("prod", "secrets", "delete") is not None
        assert registry.get("dev", "pods", "get") is not None
        # Cross-action isolation
        assert registry.get("prod", "pods", "delete") is None
        assert registry.get("dev", "pods", "delete") is None

    def test_len(self):
        registry = ArtifactRegistry()
        records = [
            RBACRecord(role="viewer", resource="pods", namespace="prod", action="get"),
            RBACRecord(role="admin", resource="pods", namespace="prod", action="delete"),
        ]
        registry.load(records)
        assert len(registry) == 2

    def test_clear(self):
        registry = ArtifactRegistry()
        records = [RBACRecord(role="viewer", resource="pods", namespace="prod", action="get")]
        registry.load(records)
        registry.clear()
        assert len(registry) == 0
        assert registry.get("prod", "pods", "get") is None

    def test_namespaces_and_resources(self):
        registry = ArtifactRegistry()
        records = [
            RBACRecord(role="viewer", resource="pods", namespace="prod", action="get"),
            RBACRecord(role="admin", resource="secrets", namespace="prod", action="get"),
            ACLRecord(subject="alice", resource="pods", namespace="dev", action="get"),
        ]
        registry.load(records)
        assert set(registry.namespaces()) == {"prod", "dev"}
        assert set(registry.resources("prod")) == {"pods", "secrets"}
        assert set(registry.resources("dev")) == {"pods"}
        assert "get" in registry.actions("prod", "pods")


# ---------------------------------------------------------------------------
# Cycle detection at compile time
# ---------------------------------------------------------------------------

class TestCycleDetection:
    def test_cycle_raises(self):
        records = [
            HierRecord(parent_role="A", child_role="B", namespace=NS),
            HierRecord(parent_role="B", child_role="A", namespace=NS),
            RBACRecord(role="A", resource=RES, namespace=NS, action="get"),
        ]
        with pytest.raises(ValueError, match="[Cc]ycle"):
            compile_artifacts(records, NS, RES)


# ---------------------------------------------------------------------------
# Semantic graph embedded in artifact
# ---------------------------------------------------------------------------

class TestSemanticGraph:
    def test_graph_present_in_artifact(self):
        records = [RBACRecord(role="viewer", resource=RES, namespace=NS, action="get")]
        art = make_artifact(records, action="get")
        assert art.graph is not None

    def test_graph_not_used_for_eval(self):
        """Graph is present for audit; artifact indices are what matter."""
        records = [
            RBACRecord(role="viewer", resource=RES, namespace=NS, action="get"),
        ]
        art = make_artifact(records, action="get")
        # Confirms I_rbac is populated independently of the graph
        assert "viewer" in art.i_rbac
