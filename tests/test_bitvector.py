"""
Tests for compiler/bitvector.py (Step 4 of v2 migration).

Covers:
  - RoleBitVector initialization and registration
  - encode(): role set -> int
  - decode(): int -> role set
  - intersects(): bit-vector AND check
  - O(1) RBAC check pattern used in Phase 3
"""

import pytest
from compiler.bitvector import RoleBitVector


class TestRoleBitVectorInit:
    def test_empty_init(self):
        rbv = RoleBitVector()
        assert len(rbv) == 0

    def test_roles_from_iterable(self):
        rbv = RoleBitVector(["admin", "viewer", "editor"])
        assert len(rbv) == 3
        assert "admin" in rbv
        assert "viewer" in rbv
        assert "editor" in rbv

    def test_deduplicates_roles(self):
        rbv = RoleBitVector(["a", "a", "b"])
        assert len(rbv) == 2

    def test_deterministic_ordering(self):
        """Same input -> same bit assignments every time."""
        rbv1 = RoleBitVector(["c", "a", "b"])
        rbv2 = RoleBitVector(["a", "b", "c"])
        # Both should assign the same bit to each role (sorted order)
        assert rbv1.bit_for("a") == rbv2.bit_for("a")
        assert rbv1.bit_for("b") == rbv2.bit_for("b")
        assert rbv1.bit_for("c") == rbv2.bit_for("c")


class TestEncode:
    def test_empty_set_encodes_to_zero(self):
        rbv = RoleBitVector(["admin", "viewer"])
        assert rbv.encode([]) == 0

    def test_single_role(self):
        rbv = RoleBitVector(["admin", "viewer"])
        enc = rbv.encode(["admin"])
        assert enc != 0
        assert enc & rbv.encode(["viewer"]) == 0

    def test_multiple_roles(self):
        rbv = RoleBitVector(["admin", "viewer", "editor"])
        enc = rbv.encode(["admin", "viewer"])
        assert enc & rbv.encode(["admin"]) != 0
        assert enc & rbv.encode(["viewer"]) != 0
        assert enc & rbv.encode(["editor"]) == 0

    def test_unknown_role_ignored(self):
        rbv = RoleBitVector(["admin"])
        enc = rbv.encode(["admin", "unknown-role"])
        # unknown-role should not cause an error or affect the result
        assert enc == rbv.encode(["admin"])

    def test_encode_is_idempotent(self):
        rbv = RoleBitVector(["a", "b"])
        assert rbv.encode(["a", "a"]) == rbv.encode(["a"])


class TestDecode:
    def test_decode_empty(self):
        rbv = RoleBitVector(["admin"])
        assert rbv.decode(0) == set()

    def test_decode_single(self):
        rbv = RoleBitVector(["admin", "viewer"])
        enc = rbv.encode(["admin"])
        assert rbv.decode(enc) == {"admin"}

    def test_decode_multiple(self):
        rbv = RoleBitVector(["admin", "viewer", "editor"])
        enc = rbv.encode(["admin", "editor"])
        assert rbv.decode(enc) == {"admin", "editor"}

    def test_roundtrip(self):
        roles = ["x", "y", "z"]
        rbv = RoleBitVector(roles)
        for subset in [[], ["x"], ["y", "z"], ["x", "y", "z"]]:
            enc = rbv.encode(subset)
            assert rbv.decode(enc) == set(subset)


class TestIntersects:
    def test_no_overlap(self):
        rbv = RoleBitVector(["admin", "viewer"])
        b_admin = rbv.encode(["admin"])
        b_viewer = rbv.encode(["viewer"])
        assert not rbv.intersects(b_admin, b_viewer)

    def test_has_overlap(self):
        rbv = RoleBitVector(["admin", "viewer"])
        b1 = rbv.encode(["admin", "viewer"])
        b2 = rbv.encode(["admin"])
        assert rbv.intersects(b1, b2)

    def test_zero_never_intersects(self):
        rbv = RoleBitVector(["admin"])
        assert not rbv.intersects(0, rbv.encode(["admin"]))


class TestRBACCheckPattern:
    """Tests that mimic the O(1) RBAC check in Phase 3 (Step 6 of VERIFY)."""

    def test_s7_senior_dev_has_access(self):
        """S7: dave has role 'senior-dev'. I_rbac includes senior-dev via closure.

        b_user & b_rbac != 0 -> ALLOW
        """
        all_roles = ["intern", "junior-dev", "senior-dev"]
        rbv = RoleBitVector(all_roles)

        # I_rbac for (prod, pods, get) after transitive closure:
        # intern has direct permission; junior-dev and senior-dev inherit it
        i_rbac = {"intern", "junior-dev", "senior-dev"}
        b_rbac = rbv.encode(i_rbac)

        # dave's token roles
        b_user = rbv.encode(["senior-dev"])

        assert rbv.intersects(b_user, b_rbac), (
            "S7 FAILED: senior-dev should intersect I_rbac"
        )

    def test_unauthorized_role_denied(self):
        rbv = RoleBitVector(["intern", "junior-dev", "senior-dev", "outsider"])
        i_rbac = {"intern", "junior-dev", "senior-dev"}
        b_rbac = rbv.encode(i_rbac)
        b_user = rbv.encode(["outsider"])
        assert not rbv.intersects(b_user, b_rbac)

    def test_empty_token_roles_denied(self):
        rbv = RoleBitVector(["admin"])
        b_rbac = rbv.encode(["admin"])
        b_user = rbv.encode([])
        assert not rbv.intersects(b_user, b_rbac)

    def test_from_closure(self):
        from compiler.role_closure import compute_transitive_closure
        edges = {"senior-dev": ["junior-dev"], "junior-dev": ["intern"]}
        closure = compute_transitive_closure(edges)
        rbv = RoleBitVector.from_closure(closure)
        assert "senior-dev" in rbv
        assert "junior-dev" in rbv
        assert "intern" in rbv
