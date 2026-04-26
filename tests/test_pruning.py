"""
Tests for the two-level pruning module (Step D).

Level 1: Activation-bit pruning (FastPath) — tested via the evaluator.
Level 2: Token-driven pruning — tested here directly.
"""

import pytest

from engine.pruning import prune_deny, prune_acl, prune_rbac, prune_abac
from dsl.models import CompiledGate
from engine.gate_nodes import AtomicCheck


# ---------------------------------------------------------------------------
# Deny pruning
# ---------------------------------------------------------------------------

class TestPruneDeny:
    def test_wildcard_always_matches(self):
        i_deny = {"*"}
        result = prune_deny(i_deny, uid="alice", groups=[], roles=[])
        assert "*" in result

    def test_user_scope_matches_uid(self):
        i_deny = {"user:alice", "user:bob"}
        result = prune_deny(i_deny, uid="alice", groups=[], roles=[])
        assert "user:alice" in result
        assert "user:bob" not in result

    def test_group_scope_matches_group(self):
        i_deny = {"group:admins", "group:devs"}
        result = prune_deny(i_deny, uid="alice", groups=["admins"], roles=[])
        assert "group:admins" in result
        assert "group:devs" not in result

    def test_no_match_returns_empty(self):
        i_deny = {"user:bob", "group:admins"}
        result = prune_deny(i_deny, uid="alice", groups=["devs"], roles=[])
        assert len(result) == 0

    def test_multiple_matches(self):
        i_deny = {"*", "user:alice", "group:devs"}
        result = prune_deny(i_deny, uid="alice", groups=["devs"], roles=[])
        assert "*" in result
        assert "user:alice" in result
        assert "group:devs" in result

    def test_empty_index_returns_empty(self):
        result = prune_deny(set(), uid="alice", groups=["admins"], roles=[])
        assert len(result) == 0


# ---------------------------------------------------------------------------
# ACL pruning
# ---------------------------------------------------------------------------

class TestPruneACL:
    def test_uid_in_acl(self):
        i_acl = {"alice", "bob", "charlie"}
        result = prune_acl(i_acl, uid="alice", groups=[])
        assert "alice" in result
        assert "bob" not in result

    def test_group_in_acl(self):
        i_acl = {"admins", "devs"}
        result = prune_acl(i_acl, uid="alice", groups=["admins"])
        assert "admins" in result

    def test_no_match(self):
        i_acl = {"charlie", "dana"}
        result = prune_acl(i_acl, uid="alice", groups=["viewers"])
        assert len(result) == 0

    def test_empty_acl(self):
        result = prune_acl(set(), uid="alice", groups=["admins"])
        assert len(result) == 0


# ---------------------------------------------------------------------------
# RBAC pruning
# ---------------------------------------------------------------------------

class TestPruneRBAC:
    def test_matching_role(self):
        i_rbac = {"viewer", "editor", "admin"}
        b_rbac = 0b111  # all 3 roles set
        matching, bvec = prune_rbac(i_rbac, b_rbac, roles=["viewer"])
        assert "viewer" in matching
        assert bvec == b_rbac  # b_rbac unchanged

    def test_no_matching_role(self):
        i_rbac = {"admin", "editor"}
        b_rbac = 0b11
        matching, bvec = prune_rbac(i_rbac, b_rbac, roles=["viewer"])
        assert len(matching) == 0

    def test_multiple_roles(self):
        i_rbac = {"viewer", "editor"}
        b_rbac = 0b11
        matching, _ = prune_rbac(i_rbac, b_rbac, roles=["viewer", "editor", "unknown"])
        assert "viewer" in matching
        assert "editor" in matching
        assert "unknown" not in matching


# ---------------------------------------------------------------------------
# ABAC pruning
# ---------------------------------------------------------------------------

def _make_gate(attrs: set, cost: int = 1) -> CompiledGate:
    """Helper: create a CompiledGate with given required_attrs and cost."""
    # Use a simple AtomicCheck as the root (attr -> first attr in set)
    attr = next(iter(attrs)) if attrs else "dummy"
    root = AtomicCheck(attribute=attr, operator="==", value="x")
    return CompiledGate(root=root, required_attrs=set(attrs), cost=cost)


class TestPruneABAC:
    def test_matching_attr_included(self):
        gate = _make_gate({"net"})
        i_abac = [gate]
        i_attr = {"net": [gate]}
        result = prune_abac(i_abac, i_attr, attr_keys=["net"])
        assert gate in result

    def test_missing_attr_excluded(self):
        gate = _make_gate({"net"})
        i_abac = [gate]
        i_attr = {"net": [gate]}
        # User has "time" but not "net"
        result = prune_abac(i_abac, i_attr, attr_keys=["time"])
        assert gate not in result

    def test_partial_match_includes_gate(self):
        """Gate needs 'net' AND 'time'; user has 'net' — gate is still a candidate."""
        gate = _make_gate({"net", "time"})
        i_abac = [gate]
        i_attr = {"net": [gate], "time": [gate]}
        result = prune_abac(i_abac, i_attr, attr_keys=["net"])
        assert gate in result

    def test_empty_attr_keys(self):
        gate = _make_gate({"net"})
        i_abac = [gate]
        i_attr = {"net": [gate]}
        result = prune_abac(i_abac, i_attr, attr_keys=[])
        assert gate not in result

    def test_empty_i_attr_returns_all(self):
        """If no attribute-key index, all gates are candidates."""
        gate1 = _make_gate({"net"})
        gate2 = _make_gate({"time"})
        i_abac = [gate1, gate2]
        result = prune_abac(i_abac, {}, attr_keys=["net"])
        assert gate1 in result
        assert gate2 in result

    def test_cost_order_preserved(self):
        """Pruned result maintains cost-sorted order from I_abac."""
        gate_cheap = _make_gate({"net"}, cost=1)
        gate_expensive = _make_gate({"net"}, cost=5)
        i_abac = [gate_cheap, gate_expensive]  # already sorted
        i_attr = {"net": [gate_cheap, gate_expensive]}
        result = prune_abac(i_abac, i_attr, attr_keys=["net"])
        assert result.index(gate_cheap) < result.index(gate_expensive)

    def test_multiple_gates_multiple_attrs(self):
        gate1 = _make_gate({"net"}, cost=1)
        gate2 = _make_gate({"dept"}, cost=2)
        gate3 = _make_gate({"time"}, cost=3)
        i_abac = [gate1, gate2, gate3]
        i_attr = {"net": [gate1], "dept": [gate2], "time": [gate3]}
        # User has net and dept
        result = prune_abac(i_abac, i_attr, attr_keys=["net", "dept"])
        assert gate1 in result
        assert gate2 in result
        assert gate3 not in result
