"""
Role bit-vector encoding for U-HAP's O(1) RBAC check.

A RoleBitVector maps a fixed set of role names to bit positions in a Python int.
This allows RBAC membership testing via a single bitwise AND:

    b_user & b_rbac != 0  ->  user has at least one authorized role

The bit-vector is built at compile time (Phase 2) and used at runtime (Phase 3).

Public API:
    RoleBitVector    -- bit-position mapping and encoding methods
"""

from typing import Collection, Dict, Iterable, Set


class RoleBitVector:
    """Maps role names to bit positions and encodes role sets as integers.

    Roles are assigned positions in the order they are registered.
    The same registry must be used for both the RBAC index b_rbac and the
    per-request user bit-vector b_user to ensure bit positions match.

    Usage (compile time):
        rbv = RoleBitVector(all_roles)
        b_rbac = rbv.encode(i_rbac_roles)   # set of authorized roles

    Usage (runtime):
        b_user = rbv.encode(token_roles)
        if b_user & b_rbac != 0:
            return ALLOW("rbac")
    """

    def __init__(self, roles: Iterable[str] = ()):
        """Initialize the bit-vector registry with a collection of role names.

        Args:
            roles: iterable of role name strings to register. Order is
                   deterministic (sorted) to ensure reproducibility.
        """
        # Sort roles for deterministic bit assignment
        sorted_roles = sorted(set(roles))
        self._role_to_bit: Dict[str, int] = {
            role: idx for idx, role in enumerate(sorted_roles)
        }
        self._bit_to_role: Dict[int, str] = {
            idx: role for role, idx in self._role_to_bit.items()
        }

    @classmethod
    def from_closure(cls, closure: Dict[str, Set[str]]) -> "RoleBitVector":
        """Build a RoleBitVector from a transitive closure dict.

        Registers all roles that appear as keys or values in the closure.
        """
        all_roles: Set[str] = set(closure.keys())
        for reachable in closure.values():
            all_roles.update(reachable)
        return cls(all_roles)

    def register(self, role: str) -> int:
        """Register a new role and return its bit position.

        If the role is already registered, return its existing position.
        New roles are appended in registration order (not sorted after init).
        """
        if role not in self._role_to_bit:
            idx = len(self._role_to_bit)
            self._role_to_bit[role] = idx
            self._bit_to_role[idx] = role
        return self._role_to_bit[role]

    def encode(self, roles: Iterable[str]) -> int:
        """Encode a set of role names as a bit-vector integer.

        Roles not registered in this instance are ignored (treated as not present).

        Args:
            roles: iterable of role name strings

        Returns:
            int with one bit set for each known role in `roles`
        """
        result = 0
        for role in roles:
            if role in self._role_to_bit:
                result |= (1 << self._role_to_bit[role])
        return result

    def decode(self, bitvec: int) -> Set[str]:
        """Decode a bit-vector integer back to a set of role names.

        Args:
            bitvec: integer bit-vector

        Returns:
            set of role names whose bits are set in bitvec
        """
        result: Set[str] = set()
        n = bitvec
        while n:
            bit = n & (-n)        # isolate lowest set bit
            pos = bit.bit_length() - 1
            if pos in self._bit_to_role:
                result.add(self._bit_to_role[pos])
            n &= n - 1            # clear lowest set bit
        return result

    def intersects(self, vec_a: int, vec_b: int) -> bool:
        """Return True if two bit-vectors share at least one set bit."""
        return (vec_a & vec_b) != 0

    def bit_for(self, role: str) -> int:
        """Return the bit position for a role, or -1 if not registered."""
        return self._role_to_bit.get(role, -1)

    def __len__(self) -> int:
        """Return the number of registered roles."""
        return len(self._role_to_bit)

    def __contains__(self, role: str) -> bool:
        return role in self._role_to_bit
