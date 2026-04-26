"""
Tests for deny rule semantics in U-HAP.

These tests verify the three deny scenarios described in the project plan:
  1. Wildcard deny (* -> d) blocks ALL subjects unconditionally.
  2. Specific deny (subject -> d) blocks only the named subject.
  3. Gate-blocked denial (ABAC gate evaluates to False) — not a deny rule;
     does NOT override an allow path from a different rule type.

Key invariant being tested: deny-overrides-all.
The deny check runs BEFORE ACL, RBAC, and ABAC checks.
"""

import pytest
from dsl.models import RBACRecord, ABACRecord, ACLRecord, DenyRecord, HierRecord
from compiler.registry import ArtifactRegistry
from engine.evaluator import evaluate_request


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_registry(extra_records=None):
    """Build a test ArtifactRegistry for namespace=prod, resource=pods.

    Standard allow paths:
      - alice has RBAC role 'viewer' -> can get
      - charlie has ACL entry -> can get
      - ABAC: net == 'on-premise' AND time == 'business-hours' -> can get
    """
    records = [
        RBACRecord(role="viewer", resource="pods", namespace="prod", action="get"),
        ACLRecord(subject="charlie", resource="pods", namespace="prod", action="get"),
        ABACRecord(
            resource="pods", namespace="prod", action="get",
            predicate="net == 'on-premise' AND time == 'business-hours'",
        ),
    ]
    if extra_records:
        records.extend(extra_records)
    registry = ArtifactRegistry()
    registry.load(records)
    return registry


def _eval(registry, uid, roles, action, context):
    """Convenience wrapper around evaluate_request for prod/pods."""
    return evaluate_request(registry, "prod", "pods", action, uid, roles, [], context)


# ---------------------------------------------------------------------------
# 1. Wildcard deny
# ---------------------------------------------------------------------------

class TestWildcardDeny:
    """Wildcard deny (*) blocks every subject regardless of allow paths."""

    def test_wildcard_blocks_rbac_user(self):
        registry = _make_registry([
            DenyRecord(subject="*", resource="pods", namespace="prod", action="get"),
        ])
        # alice has the 'viewer' role -> would normally ALLOW
        allowed, reason = _eval(registry, "alice", ["viewer"], "get", {})
        assert allowed is False
        assert "wildcard" in reason

    def test_wildcard_blocks_acl_user(self):
        registry = _make_registry([
            DenyRecord(subject="*", resource="pods", namespace="prod", action="get"),
        ])
        # charlie has ACL entry -> would normally ALLOW
        allowed, reason = _eval(registry, "charlie", [], "get", {})
        assert allowed is False
        assert "wildcard" in reason

    def test_wildcard_blocks_abac_user(self):
        registry = _make_registry([
            DenyRecord(subject="*", resource="pods", namespace="prod", action="get"),
        ])
        # on-premise + business-hours -> ABAC would allow, but deny wins
        ctx = {"net": "on-premise", "time": "business-hours"}
        allowed, reason = _eval(registry, "bob", [], "get", ctx)
        assert allowed is False
        assert "wildcard" in reason

    def test_wildcard_is_action_specific(self):
        """Wildcard deny for 'delete' does not block 'get'."""
        registry = _make_registry([
            DenyRecord(subject="*", resource="pods", namespace="prod", action="delete"),
        ])
        allowed, _ = _eval(registry, "alice", ["viewer"], "get", {})
        assert allowed is True

    def test_wildcard_blocks_unknown_user(self):
        """Even a user with no rules at all is blocked by wildcard deny."""
        registry = _make_registry([
            DenyRecord(subject="*", resource="pods", namespace="prod", action="get"),
        ])
        allowed, reason = _eval(registry, "nobody", [], "get", {})
        assert allowed is False
        assert "wildcard" in reason


# ---------------------------------------------------------------------------
# 2. Specific-user deny
# ---------------------------------------------------------------------------

class TestSpecificUserDeny:
    """Specific deny blocks only the named subject, not others."""

    def test_specific_deny_blocks_named_user(self):
        registry = _make_registry([
            DenyRecord(subject="mallory", resource="pods", namespace="prod", action="get"),
        ])
        allowed, reason = _eval(registry, "mallory", ["viewer"], "get", {})
        assert allowed is False
        assert "mallory" in reason

    def test_specific_deny_does_not_block_other_users(self):
        registry = _make_registry([
            DenyRecord(subject="mallory", resource="pods", namespace="prod", action="get"),
        ])
        # alice is not denied -> RBAC allow applies
        allowed, _ = _eval(registry, "alice", ["viewer"], "get", {})
        assert allowed is True

    def test_specific_deny_beats_acl(self):
        """Even if a user has an ACL entry, a deny for them wins."""
        registry = _make_registry([
            DenyRecord(subject="charlie", resource="pods", namespace="prod", action="get"),
        ])
        # charlie has ACL entry but also has a specific deny
        allowed, reason = _eval(registry, "charlie", [], "get", {})
        assert allowed is False
        assert "charlie" in reason

    def test_specific_deny_beats_rbac(self):
        """Specific deny overrides RBAC allow for the same user."""
        registry = _make_registry([
            DenyRecord(subject="alice", resource="pods", namespace="prod", action="get"),
        ])
        allowed, reason = _eval(registry, "alice", ["viewer"], "get", {})
        assert allowed is False
        assert "alice" in reason

    def test_specific_deny_beats_abac(self):
        """Specific deny overrides ABAC allow for the same user."""
        registry = _make_registry([
            DenyRecord(subject="eve", resource="pods", namespace="prod", action="get"),
        ])
        ctx = {"net": "on-premise", "time": "business-hours"}
        allowed, reason = _eval(registry, "eve", [], "get", ctx)
        assert allowed is False
        assert "eve" in reason


# ---------------------------------------------------------------------------
# 3. Gate-blocked denial (ABAC gate evaluates to False)
# ---------------------------------------------------------------------------

class TestGateBlockedDenial:
    """ABAC gate-blocked denial is NOT a deny rule — it does not override
    allow paths from other rule types."""

    def test_gate_false_with_no_other_allow_is_deny(self):
        """If ABAC gate is false and no other allow path exists -> DENY."""
        records = [
            ABACRecord(
                resource="pods", namespace="prod", action="get",
                predicate="net == 'on-premise' AND time == 'business-hours'",
            ),
        ]
        registry = ArtifactRegistry()
        registry.load(records)
        ctx = {"net": "remote", "time": "after-hours"}
        allowed, reason = evaluate_request(registry, "prod", "pods", "get", "alice", [], [], ctx)
        assert allowed is False
        # The denial is "no path" (default deny), not a deny rule
        assert reason == "no path"

    def test_gate_false_does_not_block_rbac(self):
        """If ABAC gate is false but RBAC allows -> ALLOW."""
        records = [
            ABACRecord(
                resource="pods", namespace="prod", action="get",
                predicate="net == 'on-premise' AND time == 'business-hours'",
            ),
            RBACRecord(role="viewer", resource="pods", namespace="prod", action="get"),
        ]
        registry = ArtifactRegistry()
        registry.load(records)
        ctx = {"net": "remote", "time": "after-hours"}  # ABAC false
        allowed, reason = evaluate_request(registry, "prod", "pods", "get", "alice", ["viewer"], [], ctx)
        # RBAC viewer role grants access
        assert allowed is True
        assert "rbac" in reason

    def test_gate_false_does_not_block_acl(self):
        """If ABAC gate is false but ACL allows -> ALLOW."""
        records = [
            ABACRecord(
                resource="pods", namespace="prod", action="get",
                predicate="net == 'on-premise'",
            ),
            ACLRecord(subject="charlie", resource="pods", namespace="prod", action="get"),
        ]
        registry = ArtifactRegistry()
        registry.load(records)
        ctx = {"net": "remote"}  # ABAC false
        allowed, reason = evaluate_request(registry, "prod", "pods", "get", "charlie", [], [], ctx)
        assert allowed is True
        assert "acl" in reason

    def test_deny_rule_blocks_even_when_gate_true(self):
        """Explicit deny rule beats ABAC gate even when gate is true."""
        records = [
            ABACRecord(
                resource="pods", namespace="prod", action="get",
                predicate="net == 'on-premise'",
            ),
            DenyRecord(subject="alice", resource="pods", namespace="prod", action="get"),
        ]
        registry = ArtifactRegistry()
        registry.load(records)
        ctx = {"net": "on-premise"}  # ABAC gate would return True
        allowed, reason = evaluate_request(registry, "prod", "pods", "get", "alice", [], [], ctx)
        # Deny rule runs first -> DENY
        assert allowed is False
        assert "alice" in reason


# ---------------------------------------------------------------------------
# 4. Multiple deny rules (both wildcard and specific)
# ---------------------------------------------------------------------------

class TestMultipleDenyRules:
    """Verify behavior when both wildcard and specific deny rules exist."""

    def test_wildcard_and_specific_both_deny(self):
        registry = _make_registry([
            DenyRecord(subject="*", resource="pods", namespace="prod", action="get"),
            DenyRecord(subject="alice", resource="pods", namespace="prod", action="get"),
        ])
        allowed, reason = _eval(registry, "alice", ["viewer"], "get", {})
        assert allowed is False

    def test_deny_different_actions_independent(self):
        """Deny on 'delete' does not affect 'get'."""
        registry = _make_registry([
            DenyRecord(subject="*", resource="pods", namespace="prod", action="delete"),
        ])
        ctx = {"net": "on-premise", "time": "business-hours"}
        get_result, _ = evaluate_request(registry, "prod", "pods", "get", "alice", ["viewer"], [], ctx)
        delete_result, _ = evaluate_request(registry, "prod", "pods", "delete", "alice", ["viewer"], [], ctx)
        assert get_result is True
        assert delete_result is False


# ---------------------------------------------------------------------------
# 5. Deny with role hierarchy
# ---------------------------------------------------------------------------

class TestDenyWithHierarchy:
    """Deny rules block access even when the user would reach a resource via
    role hierarchy traversal."""

    def test_deny_blocks_hierarchy_traversal(self):
        """Even if a user has a role that reaches the resource via hierarchy,
        a deny rule for that user wins."""
        records = [
            HierRecord(parent_role="admin", child_role="viewer", namespace="prod"),
            RBACRecord(role="viewer", resource="pods", namespace="prod", action="get"),
            DenyRecord(subject="mallory", resource="pods", namespace="prod", action="get"),
        ]
        registry = ArtifactRegistry()
        registry.load(records)
        # mallory has 'admin' role which reaches 'viewer' via hierarchy -> would ALLOW
        # but deny rule blocks mallory
        allowed, reason = evaluate_request(registry, "prod", "pods", "get", "mallory", ["admin"], [], {})
        assert allowed is False
        assert "mallory" in reason

    def test_other_user_with_same_role_still_allowed(self):
        """The deny on mallory does not affect alice with the same role."""
        records = [
            HierRecord(parent_role="admin", child_role="viewer", namespace="prod"),
            RBACRecord(role="viewer", resource="pods", namespace="prod", action="get"),
            DenyRecord(subject="mallory", resource="pods", namespace="prod", action="get"),
        ]
        registry = ArtifactRegistry()
        registry.load(records)
        allowed, _ = evaluate_request(registry, "prod", "pods", "get", "alice", ["admin"], [], {})
        assert allowed is True
