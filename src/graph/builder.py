"""
Phase 1: Resource policy graph construction (Algorithm 1 from the U-HAP paper).

Modified Algorithm 1 — builds G_{n,r} from a set of policy records using
hash consing for ABAC predicates:

  1. Create a PolicyGraph for (namespace, resource) with resource node + deny terminal.
  2. Instantiate a HashConsingRegistry (shared across all ABAC rules for this resource).
  3. For each HierRecord: add hierarchy edge.
  4. For each RBACRecord: add perm edge.
  5. For each ABACRecord: parse predicate → build_shared_dag → add gate edge.
  6. For each ACLRecord: add ACL edge.
  7. For each DenyRecord: add deny edge.
  8. Store in registry.

Cycle detection for role hierarchies uses DFS. A cycle means the hierarchy
is invalid and will raise ValueError at load time.

Public API:
  build_graph(records, namespace, resource) -> PolicyGraph
  detect_hierarchy_cycle(hier_edges)        -> raises ValueError on cycle
"""

from collections import deque
from typing import List, Union

from dsl.models import RBACRecord, HierRecord, ABACRecord, ACLRecord, DenyRecord
from dsl.parser import parse_predicate
from engine.hash_consing import HashConsingRegistry, build_shared_dag
from graph.models import PolicyGraph


# Type alias for policy records
PolicyRecord = Union[RBACRecord, HierRecord, ABACRecord, ACLRecord, DenyRecord]


def detect_hierarchy_cycle(hier_edges: dict) -> None:
    """Check the role hierarchy graph for cycles using DFS.

    Args:
        hier_edges: dict mapping parent_role -> list of child_role names

    Raises:
        ValueError: if a cycle is detected in the role hierarchy
    """
    # Collect all nodes
    all_nodes = set(hier_edges.keys())
    for children in hier_edges.values():
        all_nodes.update(children)

    visited = set()      # fully explored
    in_stack = set()     # currently on the DFS stack

    def dfs(node: str) -> None:
        if node in visited:
            return
        if node in in_stack:
            raise ValueError(
                f"Cycle detected in role hierarchy at role '{node}'. "
                "Role hierarchies must be acyclic (DAG property)."
            )
        in_stack.add(node)
        for child in hier_edges.get(node, []):
            dfs(child)
        in_stack.discard(node)
        visited.add(node)

    for node in all_nodes:
        if node not in visited:
            dfs(node)


def build_graph(
    records: List[PolicyRecord],
    namespace: str,
    resource: str,
) -> PolicyGraph:
    """Build a PolicyGraph G_{n,r} from a list of policy records.

    This is the implementation of modified Algorithm 1 from the U-HAP paper.
    Records must all belong to (namespace, resource) — the caller is
    responsible for partitioning the global policy set first.

    Args:
        records:   list of policy records for this (namespace, resource)
        namespace: Kubernetes namespace string (e.g., "prod")
        resource:  resource name string (e.g., "pods")

    Returns:
        PolicyGraph: the constructed G_{n,r}

    Raises:
        ValueError: if role hierarchy has a cycle
        SyntaxError: if an ABAC predicate fails to parse
    """
    graph = PolicyGraph(namespace=namespace, resource=resource)
    hc = HashConsingRegistry()  # shared across all ABAC rules for this resource

    # Separate records by type for ordered processing
    hier_records = [r for r in records if isinstance(r, HierRecord)]
    rbac_records = [r for r in records if isinstance(r, RBACRecord)]
    abac_records = [r for r in records if isinstance(r, ABACRecord)]
    acl_records  = [r for r in records if isinstance(r, ACLRecord)]
    deny_records = [r for r in records if isinstance(r, DenyRecord)]

    # Step 3: Hierarchy edges
    for rec in hier_records:
        graph.add_hier_edge(parent=rec.parent_role, child=rec.child_role)

    # Validate: no cycles in the hierarchy
    detect_hierarchy_cycle(graph.hier_edges)

    # Step 4: RBAC permission edges
    for rec in rbac_records:
        graph.add_perm_edge(role=rec.role, action=rec.action)

    # Step 5: ABAC gate edges (with hash consing)
    for rec in abac_records:
        ast = parse_predicate(rec.predicate)
        gate_root = build_shared_dag(ast, hc)
        graph.add_gate_edge(gate_root=gate_root, action=rec.action)

    # Store the hash consing registry in the graph for introspection/benchmarks
    graph._hc_registry = hc  # type: ignore[attr-defined]

    # Step 6: ACL edges
    for rec in acl_records:
        graph.add_acl_edge(subject=rec.subject, action=rec.action)

    # Step 7: Deny edges
    for rec in deny_records:
        graph.add_deny_edge(subject=rec.subject, action=rec.action)

    return graph
