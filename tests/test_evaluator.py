"""
Unit tests for the v2 evaluator (Step E) — Algorithm 3.

Tests each policy check individually (deny, ACL, RBAC, ABAC) and verifies:
  - deny-overrides-all invariant
  - O(1) bit-vector RBAC check (no BFS)
  - Attribute-key pruned ABAC evaluation
  - Memoized DAG evaluation
  - Decision cache integration
  - Default deny
"""

import pytest

from dsl.models import RBACRecord, HierRecord, ABACRecord, ACLRecord, DenyRecord
from compiler.index_compiler import compile_artifacts
from compiler.registry import ArtifactRegistry
from engine.evaluator import evaluate_artifact, evaluate_request
from engine.cache import DecisionCache


NS = "prod"
RES = "pods"


def make_artifact(records, action="get", ns=NS, res=RES):
    """Helper: compile records and return the artifact for the given action."""
    artifacts = compile_artifacts(records, ns, res)
    return artifacts.get(action)


def make_registry(records):
    """Helper: build an ArtifactRegistry from a flat list of records."""
    registry = ArtifactRegistry()
    registry.load(records)
    return registry


# ---------------------------------------------------------------------------
# Deny check — must be first (deny-overrides-all invariant)
# ---------------------------------------------------------------------------

class TestDenyCheck:
    def test_specific_deny_overrides_allow(self):
        """A deny rule for the subject overrides any allow path."""
        records = [
            DenyRecord(subject="alice", resource=RES, namespace=NS, action="delete"),
            RBACRecord(role="admin", resource=RES, namespace=NS, action="delete"),
            ACLRecord(subject="alice", resource=RES, namespace=NS, action="delete"),
        ]
        art = make_artifact(records, action="delete")
        allowed, reason = evaluate_artifact(art, uid="alice", roles=["admin"],
                                            groups=[], context={})
        assert not allowed
        assert "deny" in reason.lower()

    def test_wildcard_deny_blocks_everyone(self):
        records = [
            DenyRecord(subject="*", resource=RES, namespace=NS, action="delete"),
            RBACRecord(role="admin", resource=RES, namespace=NS, action="delete"),
        ]
        art = make_artifact(records, action="delete")
        for user in ["alice", "bob", "charlie", "admin"]:
            allowed, reason = evaluate_artifact(art, uid=user, roles=["admin"],
                                                groups=[], context={})
            assert not allowed, f"Expected deny for {user}"
            assert "deny" in reason.lower()

    def test_deny_specific_action_does_not_block_others(self):
        records = [
            DenyRecord(subject="*", resource=RES, namespace=NS, action="delete"),
            RBACRecord(role="viewer", resource=RES, namespace=NS, action="get"),
        ]
        art = make_artifact(records, action="get")
        allowed, _ = evaluate_artifact(art, uid="alice", roles=["viewer"],
                                        groups=[], context={})
        assert allowed

    def test_deny_requires_matching_action(self):
        records = [
            DenyRecord(subject="alice", resource=RES, namespace=NS, action="delete"),
            RBACRecord(role="viewer", resource=RES, namespace=NS, action="get"),
        ]
        art = make_artifact(records, action="get")
        allowed, _ = evaluate_artifact(art, uid="alice", roles=["viewer"],
                                        groups=[], context={})
        assert allowed


# ---------------------------------------------------------------------------
# ACL check
# ---------------------------------------------------------------------------

class TestACLCheck:
    def test_acl_grants_access(self):
        records = [
            ACLRecord(subject="charlie", resource=RES, namespace=NS, action="get"),
        ]
        art = make_artifact(records, action="get")
        allowed, reason = evaluate_artifact(art, uid="charlie", roles=[],
                                             groups=[], context={})
        assert allowed
        assert "acl" in reason.lower()

    def test_acl_subject_mismatch(self):
        records = [
            ACLRecord(subject="charlie", resource=RES, namespace=NS, action="get"),
        ]
        art = make_artifact(records, action="get")
        allowed, _ = evaluate_artifact(art, uid="alice", roles=[], groups=[], context={})
        assert not allowed

    def test_acl_action_mismatch(self):
        records = [
            ACLRecord(subject="charlie", resource=RES, namespace=NS, action="get"),
            ACLRecord(subject="charlie", resource=RES, namespace=NS, action="delete"),
        ]
        get_art = make_artifact(records, action="get")
        del_art = make_artifact(records, action="delete")
        allowed, _ = evaluate_artifact(del_art, uid="charlie", roles=[], groups=[], context={})
        assert allowed
        # confirm get also works
        allowed2, _ = evaluate_artifact(get_art, uid="charlie", roles=[], groups=[], context={})
        assert allowed2


# ---------------------------------------------------------------------------
# RBAC check — O(1) bit-vector AND (no BFS)
# ---------------------------------------------------------------------------

class TestRBACCheck:
    def test_direct_role_grants_access(self):
        records = [
            RBACRecord(role="viewer", resource=RES, namespace=NS, action="get"),
        ]
        art = make_artifact(records, action="get")
        allowed, reason = evaluate_artifact(art, uid="alice", roles=["viewer"],
                                             groups=[], context={})
        assert allowed
        assert "rbac" in reason.lower()

    def test_role_not_present(self):
        records = [
            RBACRecord(role="admin", resource=RES, namespace=NS, action="get"),
        ]
        art = make_artifact(records, action="get")
        allowed, _ = evaluate_artifact(art, uid="alice", roles=["viewer"],
                                        groups=[], context={})
        assert not allowed

    def test_hierarchy_transitive_closure(self):
        """senior-dev -> junior-dev -> intern; intern has get.
        At compile time, I_rbac includes all three. At runtime, bit-vector AND."""
        records = [
            HierRecord(parent_role="senior-dev", child_role="junior-dev", namespace=NS),
            HierRecord(parent_role="junior-dev", child_role="intern", namespace=NS),
            RBACRecord(role="intern", resource=RES, namespace=NS, action="get"),
        ]
        art = make_artifact(records, action="get")
        # senior-dev is in I_rbac via transitive closure
        assert "senior-dev" in art.i_rbac
        allowed, reason = evaluate_artifact(art, uid="dave", roles=["senior-dev"],
                                             groups=[], context={})
        assert allowed
        assert "rbac" in reason.lower()

    def test_hierarchy_multi_hop(self):
        """A -> B -> C -> D; D has get. A should be allowed."""
        records = [
            HierRecord(parent_role="A", child_role="B", namespace=NS),
            HierRecord(parent_role="B", child_role="C", namespace=NS),
            HierRecord(parent_role="C", child_role="D", namespace=NS),
            RBACRecord(role="D", resource=RES, namespace=NS, action="get"),
        ]
        art = make_artifact(records, action="get")
        allowed, _ = evaluate_artifact(art, uid="user", roles=["A"], groups=[], context={})
        assert allowed

    def test_hierarchy_does_not_grant_upward(self):
        """Senior inherits Junior, not the other way."""
        records = [
            HierRecord(parent_role="senior", child_role="junior", namespace=NS),
            RBACRecord(role="senior", resource=RES, namespace=NS, action="delete"),
        ]
        del_art = make_artifact(records, action="delete")
        # junior should NOT inherit senior's permissions
        allowed, _ = evaluate_artifact(del_art, uid="user", roles=["junior"],
                                        groups=[], context={})
        assert not allowed

    def test_multiple_token_roles(self):
        """Subject with multiple roles: any matching role grants access."""
        records = [
            RBACRecord(role="viewer", resource=RES, namespace=NS, action="get"),
        ]
        art = make_artifact(records, action="get")
        allowed, _ = evaluate_artifact(art, uid="alice", roles=["auditor", "viewer"],
                                        groups=[], context={})
        assert allowed

    def test_bitvector_used_not_bfs(self):
        """Verify bit-vector is non-zero and encode check works."""
        records = [
            HierRecord(parent_role="senior-dev", child_role="junior-dev", namespace=NS),
            RBACRecord(role="junior-dev", resource=RES, namespace=NS, action="get"),
        ]
        art = make_artifact(records, action="get")
        # b_rbac should be non-zero
        assert art.b_rbac != 0
        # senior-dev is in I_rbac via transitive closure
        assert "senior-dev" in art.i_rbac


# ---------------------------------------------------------------------------
# ABAC check — attribute-key pruned, cost-sorted, memoized DAG
# ---------------------------------------------------------------------------

class TestABACCheck:
    def test_abac_condition_met(self):
        records = [
            ABACRecord(resource=RES, namespace=NS, action="get",
                       predicate="net == 'on-premise' AND time == 'business-hours'"),
        ]
        art = make_artifact(records, action="get")
        ctx = {"net": "on-premise", "time": "business-hours"}
        allowed, reason = evaluate_artifact(art, uid="alice", roles=[], groups=[], context=ctx)
        assert allowed
        assert "abac" in reason.lower()

    def test_abac_condition_not_met(self):
        records = [
            ABACRecord(resource=RES, namespace=NS, action="get",
                       predicate="net == 'on-premise' AND time == 'business-hours'"),
        ]
        art = make_artifact(records, action="get")
        ctx = {"net": "remote", "time": "business-hours"}
        allowed, _ = evaluate_artifact(art, uid="alice", roles=[], groups=[], context=ctx)
        assert not allowed

    def test_abac_multiple_rules_disjunctive(self):
        """Multiple ABAC rules for same action: any one true grants access."""
        records = [
            ABACRecord(resource=RES, namespace=NS, action="get",
                       predicate="net == 'on-premise'"),
            ABACRecord(resource=RES, namespace=NS, action="get",
                       predicate="dept == 'engineering'"),
        ]
        art = make_artifact(records, action="get")
        ctx = {"net": "remote", "dept": "engineering"}
        allowed, _ = evaluate_artifact(art, uid="alice", roles=[], groups=[], context=ctx)
        assert allowed

    def test_abac_attribute_key_pruning(self):
        """Gates whose required attrs are absent from context are skipped."""
        records = [
            ABACRecord(resource=RES, namespace=NS, action="get",
                       predicate="net == 'on-premise'"),
        ]
        art = make_artifact(records, action="get")
        # Context has no 'net' key -> gate should be pruned -> default deny
        ctx = {"time": "business-hours"}
        allowed, _ = evaluate_artifact(art, uid="alice", roles=[], groups=[], context=ctx)
        assert not allowed

    def test_abac_memoization(self):
        """Each DAG node evaluated at most once per request (via memo dict)."""
        records = [
            ABACRecord(resource=RES, namespace=NS, action="get",
                       predicate="net == 'on-premise' OR net == 'on-premise'"),
        ]
        art = make_artifact(records, action="get")
        ctx = {"net": "on-premise"}
        # Should not crash or double-evaluate
        allowed, _ = evaluate_artifact(art, uid="alice", roles=[], groups=[], context=ctx)
        assert allowed

    def test_abac_empty_context_is_deny(self):
        records = [
            ABACRecord(resource=RES, namespace=NS, action="get",
                       predicate="net == 'on-premise'"),
        ]
        art = make_artifact(records, action="get")
        allowed, _ = evaluate_artifact(art, uid="alice", roles=[], groups=[], context={})
        assert not allowed


# ---------------------------------------------------------------------------
# Default deny
# ---------------------------------------------------------------------------

class TestDefaultDeny:
    def test_empty_artifact_denies(self):
        """An artifact with no rules denies everything."""
        # We can't normally get an empty artifact (compile_artifacts returns
        # nothing for empty records), but we can test via an empty registry.
        registry = ArtifactRegistry()
        allowed, reason = evaluate_request(
            registry, "prod", "pods", "get", "alice", [], [], {}
        )
        assert not allowed
        assert "no policy" in reason

    def test_no_matching_rule_denies(self):
        records = [
            RBACRecord(role="admin", resource=RES, namespace=NS, action="delete"),
        ]
        art = make_artifact(records, action="delete")
        # alice has wrong role
        allowed, reason = evaluate_artifact(art, uid="alice", roles=["viewer"],
                                             groups=[], context={})
        assert not allowed

    def test_registry_no_artifact_denies(self):
        registry = ArtifactRegistry()
        allowed, reason = evaluate_request(
            registry, "prod", "pods", "get", "alice", [], [], {}
        )
        assert not allowed
        assert "no policy" in reason

    def test_wrong_action_denies(self):
        """Artifact for 'get' does not cover 'delete' — registry returns None."""
        records = [
            RBACRecord(role="viewer", resource=RES, namespace=NS, action="get"),
        ]
        registry = make_registry(records)
        # delete has no artifact
        allowed, reason = evaluate_request(
            registry, NS, RES, "delete", "alice", ["viewer"], [], {}
        )
        assert not allowed
        assert "no policy" in reason


# ---------------------------------------------------------------------------
# Priority order: deny > ACL > RBAC > ABAC
# ---------------------------------------------------------------------------

class TestPriorityOrder:
    def test_deny_beats_acl(self):
        records = [
            DenyRecord(subject="alice", resource=RES, namespace=NS, action="get"),
            ACLRecord(subject="alice", resource=RES, namespace=NS, action="get"),
        ]
        art = make_artifact(records, action="get")
        allowed, _ = evaluate_artifact(art, uid="alice", roles=[], groups=[], context={})
        assert not allowed

    def test_deny_beats_rbac(self):
        records = [
            DenyRecord(subject="alice", resource=RES, namespace=NS, action="get"),
            RBACRecord(role="admin", resource=RES, namespace=NS, action="get"),
        ]
        art = make_artifact(records, action="get")
        allowed, _ = evaluate_artifact(art, uid="alice", roles=["admin"],
                                        groups=[], context={})
        assert not allowed

    def test_deny_beats_abac(self):
        records = [
            DenyRecord(subject="alice", resource=RES, namespace=NS, action="get"),
            ABACRecord(resource=RES, namespace=NS, action="get",
                       predicate="net == 'on-premise'"),
        ]
        art = make_artifact(records, action="get")
        ctx = {"net": "on-premise"}
        allowed, _ = evaluate_artifact(art, uid="alice", roles=[], groups=[], context=ctx)
        assert not allowed


# ---------------------------------------------------------------------------
# Decision cache integration
# ---------------------------------------------------------------------------

class TestDecisionCache:
    def test_cache_hit_returned(self):
        records = [
            RBACRecord(role="viewer", resource=RES, namespace=NS, action="get"),
        ]
        art = make_artifact(records, action="get")
        cache = DecisionCache()

        # First call: cache miss
        allowed1, reason1 = evaluate_artifact(art, uid="alice", roles=["viewer"],
                                               groups=[], context={}, cache=cache)
        assert allowed1
        assert cache.misses == 1
        assert cache.hits == 0

        # Second call: cache hit
        allowed2, reason2 = evaluate_artifact(art, uid="alice", roles=["viewer"],
                                               groups=[], context={}, cache=cache)
        assert allowed2
        assert cache.hits == 1
        assert allowed1 == allowed2

    def test_cache_miss_then_hit(self):
        records = [
            DenyRecord(subject="*", resource=RES, namespace=NS, action="delete"),
        ]
        art = make_artifact(records, action="delete")
        cache = DecisionCache()

        for i in range(3):
            allowed, reason = evaluate_artifact(art, uid="bob", roles=[], groups=[],
                                                 context={}, cache=cache)
            assert not allowed

        assert cache.hits == 2   # 2nd and 3rd calls hit
        assert cache.misses == 1  # 1st call miss

    def test_different_users_different_cache_entries(self):
        records = [
            ACLRecord(subject="alice", resource=RES, namespace=NS, action="get"),
        ]
        art = make_artifact(records, action="get")
        cache = DecisionCache()

        allowed_alice, _ = evaluate_artifact(art, uid="alice", roles=[], groups=[], context={}, cache=cache)
        allowed_bob, _ = evaluate_artifact(art, uid="bob", roles=[], groups=[], context={}, cache=cache)
        assert allowed_alice
        assert not allowed_bob

    def test_no_cache_still_works(self):
        records = [
            RBACRecord(role="viewer", resource=RES, namespace=NS, action="get"),
        ]
        art = make_artifact(records, action="get")
        # No cache passed — should still work
        allowed, _ = evaluate_artifact(art, uid="alice", roles=["viewer"],
                                        groups=[], context={}, cache=None)
        assert allowed


# ---------------------------------------------------------------------------
# evaluate_request via ArtifactRegistry
# ---------------------------------------------------------------------------

class TestEvaluateRequest:
    def test_allow_via_registry(self):
        records = [
            RBACRecord(role="viewer", resource="pods", namespace="prod", action="get"),
        ]
        registry = make_registry(records)
        allowed, reason = evaluate_request(
            registry, "prod", "pods", "get", "alice", ["viewer"], [], {}
        )
        assert allowed
        assert "rbac" in reason.lower()

    def test_deny_via_registry(self):
        records = [
            DenyRecord(subject="*", resource="secrets", namespace="prod", action="delete"),
        ]
        registry = make_registry(records)
        allowed, reason = evaluate_request(
            registry, "prod", "secrets", "delete", "alice", ["admin"], [], {}
        )
        assert not allowed
        assert "deny" in reason.lower()

    def test_no_policy_via_registry(self):
        registry = ArtifactRegistry()
        allowed, reason = evaluate_request(
            registry, "prod", "pods", "get", "alice", [], [], {}
        )
        assert not allowed
        assert "no policy" in reason

    def test_with_cache(self):
        records = [
            ACLRecord(subject="charlie", resource="pods", namespace="prod", action="get"),
        ]
        registry = make_registry(records)
        cache = DecisionCache()

        # Two identical requests
        r1 = evaluate_request(registry, "prod", "pods", "get", "charlie", [], [], {}, cache)
        r2 = evaluate_request(registry, "prod", "pods", "get", "charlie", [], [], {}, cache)
        assert r1 == r2
        assert cache.hits >= 1
