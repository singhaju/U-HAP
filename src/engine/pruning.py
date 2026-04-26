"""
Two-level pruning for U-HAP Phase 3 evaluation.

Level 1: Policy-type pruning — check FastPath activation bits; skip entire
         policy classes if the bit is False.

Level 2: Token-driven pruning — within an active class, reduce the candidate
         set to only rules relevant to this user's token.

This module provides pure functions that take a CompiledArtifact and token
components and return pruned candidate sets.

Public API:
  prune_deny(i_deny, uid, groups, roles) -> set[str]
  prune_acl(i_acl, uid, groups)          -> set[str]
  prune_rbac(i_rbac, b_rbac, roles)      -> (set[str], int)
  prune_abac(i_abac, i_attr, attr_keys)  -> list[CompiledGate]
"""

from typing import Dict, Iterable, List, Set, Tuple

from dsl.models import CompiledGate


def prune_deny(
    i_deny: Set[str],
    uid: str,
    groups: Iterable[str] = (),
    roles: Iterable[str] = (),
) -> Set[str]:
    """Level-2 prune: return deny candidates relevant to this token.

    A deny entry matches if:
      - It is a wildcard ("*")
      - It is a user-scoped entry matching the uid ("user:<uid>")
      - It is a group-scoped entry matching any of the user's groups ("group:<g>")

    The caller has already checked Ξ.has_deny (Level 1) before calling this.

    Args:
        i_deny:  Full deny index for this artifact.
        uid:     Authenticated user identity.
        groups:  User's group memberships.
        roles:   User's role names (not currently used for deny scope, included
                 for forward compatibility).

    Returns:
        Set of deny scope strings that are relevant to this token.
    """
    candidates: Set[str] = set()

    user_scope  = f"user:{uid}"
    group_scopes = {f"group:{g}" for g in groups}

    for entry in i_deny:
        if entry == "*":
            candidates.add(entry)
        elif entry == user_scope:
            candidates.add(entry)
        elif entry in group_scopes:
            candidates.add(entry)

    return candidates


def prune_acl(
    i_acl: Set[str],
    uid: str,
    groups: Iterable[str] = (),
) -> Set[str]:
    """Level-2 prune: return ACL entries that match uid or any of the groups.

    Args:
        i_acl:  Full ACL index (set of user IDs and group names).
        uid:    Authenticated user identity.
        groups: User's group memberships.

    Returns:
        Intersection of {uid} ∪ groups with I_acl.
    """
    token_ids = {uid} | set(groups)
    return token_ids & i_acl


def prune_rbac(
    i_rbac: Set[str],
    b_rbac: int,
    roles: Iterable[str],
) -> Tuple[Set[str], int]:
    """Level-2 prune: return role set and bit intersection for RBAC check.

    At runtime the actual check is: b_user & b_rbac != 0. This function
    returns the intersection set for diagnostics/audit as well.

    Note: The caller needs the role-to-bit mapping to compute b_user. Since
    that mapping is per-artifact, the evaluator computes b_user directly.
    This function only returns the set-intersection for logging.

    Args:
        i_rbac:  Full RBAC index (set of authorized role names).
        b_rbac:  RBAC bit-vector for the artifact.
        roles:   User's role names from the token.

    Returns:
        (matching_roles, b_rbac) where matching_roles = roles ∩ i_rbac.
        The evaluator computes b_user externally and does the bit-AND.
    """
    user_roles = set(roles)
    matching = user_roles & i_rbac
    return matching, b_rbac


def prune_abac(
    i_abac: List[CompiledGate],
    i_attr: Dict[str, List[CompiledGate]],
    attr_keys: Iterable[str],
) -> List[CompiledGate]:
    """Level-2 prune: return ABAC gates whose required attributes are present.

    Uses the attribute-key index to find only the gates that read at least one
    attribute present in the user's token. Gates not touched by any user
    attribute can never be satisfied.

    The returned list maintains the cost-sorted order from compilation (or
    re-sorts if needed).

    Args:
        i_abac:    Full ABAC gate list (cost-sorted at compile time).
        i_attr:    Attribute-key index: attr_key -> list[CompiledGate].
        attr_keys: Keys present in the user's attribute dict (A_u).

    Returns:
        List of CompiledGate that are candidates for evaluation, in cost order.
    """
    if not i_attr:
        # No attribute-key index means all gates are candidates
        return list(i_abac)

    # Collect all gates referenced by at least one present attribute key
    candidate_set: set = set()
    for key in attr_keys:
        for gate in i_attr.get(key, []):
            candidate_set.add(id(gate))

    if not candidate_set:
        return []

    # Maintain original cost-sorted order from I_abac
    return [g for g in i_abac if id(g) in candidate_set]
