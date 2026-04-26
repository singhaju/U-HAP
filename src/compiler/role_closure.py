"""
Transitive closure computation for role hierarchies in U-HAP.

Role hierarchy edges take the form:
    parent_role -> child_role

Meaning: parent inherits all permissions of child.

The transitive closure maps each role to the set of roles it transitively
inherits from (i.e., all roles it can "reach" by following hierarchy edges).

Cycle detection is performed during closure computation: any detected cycle
raises ValueError, since the DAG property is a hard invariant.

Public API:
    compute_transitive_closure(edges) -> dict[str, set[str]]
    detect_hierarchy_cycle(edges)     -> None (raises ValueError on cycle)
    get_ancestors(role, edges)        -> set[str]  (roles that inherit FROM role)
"""

from typing import Dict, List, Set


def detect_hierarchy_cycle(hier_edges: Dict[str, List[str]]) -> None:
    """Check the role hierarchy graph for cycles using iterative DFS.

    Args:
        hier_edges: dict mapping parent_role -> list of child_role names

    Raises:
        ValueError: if a cycle is detected in the role hierarchy
    """
    all_nodes: Set[str] = set(hier_edges.keys())
    for children in hier_edges.values():
        all_nodes.update(children)

    visited: Set[str] = set()    # fully explored
    in_stack: Set[str] = set()   # currently on the DFS stack

    def dfs(start: str) -> None:
        stack = [(start, False)]
        while stack:
            node, returning = stack.pop()
            if returning:
                in_stack.discard(node)
                visited.add(node)
                continue
            if node in visited:
                continue
            if node in in_stack:
                raise ValueError(
                    f"Cycle detected in role hierarchy at role '{node}'. "
                    "Role hierarchies must be acyclic (DAG property)."
                )
            in_stack.add(node)
            stack.append((node, True))  # push "return" marker
            for child in hier_edges.get(node, []):
                if child not in visited:
                    stack.append((child, False))

    for node in list(all_nodes):
        if node not in visited:
            dfs(node)


def compute_transitive_closure(
    hier_edges: Dict[str, List[str]],
) -> Dict[str, Set[str]]:
    """Compute the transitive closure of a role hierarchy.

    For each role, returns the set of roles it can reach by following
    parent->child edges (i.e., the roles whose permissions it inherits).

    Example:
        edges = {"senior-dev": ["junior-dev"], "junior-dev": ["intern"]}
        closure = {
            "senior-dev": {"junior-dev", "intern"},
            "junior-dev": {"intern"},
            "intern": set(),
        }

    Args:
        hier_edges: dict mapping parent_role -> list of child_role names.
                    Must be acyclic.

    Returns:
        dict mapping each role -> set of transitively reachable roles
        (not including the role itself)

    Raises:
        ValueError: if a cycle is detected
    """
    # First detect cycles — fail fast before any computation
    detect_hierarchy_cycle(hier_edges)

    # Collect all roles
    all_roles: Set[str] = set(hier_edges.keys())
    for children in hier_edges.values():
        all_roles.update(children)

    # Build closure via DFS for each role
    # closure[role] = set of roles reachable from role (not including self)
    closure: Dict[str, Set[str]] = {r: set() for r in all_roles}

    def _reachable(role: str, seen: Set[str]) -> Set[str]:
        """Return all roles reachable from `role` (recursive DFS with caching)."""
        result = set()
        for child in hier_edges.get(role, []):
            if child not in seen:
                seen.add(child)
                result.add(child)
                result.update(_reachable(child, seen))
        return result

    for role in all_roles:
        closure[role] = _reachable(role, {role})

    return closure


def get_ancestors(
    role: str,
    hier_edges: Dict[str, List[str]],
) -> Set[str]:
    """Return all roles that transitively inherit FROM the given role.

    This is the reverse direction: which roles have `role` reachable from them?
    Used when building I_rbac: if intern has get, then junior-dev and senior-dev
    should also be in I_rbac.

    Args:
        role:       The base role to find ancestors of.
        hier_edges: dict mapping parent_role -> list of child_role names.

    Returns:
        set of role names that can reach `role` via hierarchy edges
        (the "upstream" roles — those who inherit from `role`)
    """
    # Build reverse edges: child -> list of parents
    reverse: Dict[str, List[str]] = {}
    all_roles: Set[str] = set(hier_edges.keys())
    for children in hier_edges.values():
        all_roles.update(children)

    for parent, children in hier_edges.items():
        for child in children:
            if child not in reverse:
                reverse[child] = []
            reverse[child].append(parent)

    # BFS from role upward through reverse edges
    ancestors: Set[str] = set()
    queue = list(reverse.get(role, []))
    while queue:
        ancestor = queue.pop(0)
        if ancestor not in ancestors:
            ancestors.add(ancestor)
            queue.extend(reverse.get(ancestor, []))

    return ancestors
