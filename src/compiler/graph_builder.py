"""
Semantic graph builder for U-HAP (Phase 2 — compiler module).

This module is functionally identical to src/graph/builder.py but lives in
the compiler package as the canonical Phase 2 entry point. The graph it
builds is used for audit/correctness proofs only — NOT for runtime evaluation.

Modified Algorithm 1:
  1. Create PolicyGraph for (namespace, resource) with resource node + deny terminal.
  2. Instantiate HashConsingRegistry (shared across all ABAC rules for this resource).
  3. HierRecords -> hierarchy edges.
  4. RBACRecords -> perm edges.
  5. ABACRecords -> parse predicate -> build_shared_dag -> gate edge.
  6. ACLRecords  -> ACL edges.
  7. DenyRecords -> deny edges.

The graph is stored inside CompiledArtifacts for audit access; the index
compiler derives the actual runtime indices (I_deny, I_acl, I_rbac, etc.)
from the same source records.

Public API:
  build_graph(records, namespace, resource) -> PolicyGraph
"""

from typing import List, Union

from compiler.role_closure import detect_hierarchy_cycle
from dsl.models import RBACRecord, HierRecord, ABACRecord, ACLRecord, DenyRecord
from dsl.parser import parse_predicate
from engine.hash_consing import HashConsingRegistry, build_shared_dag
from graph.models import PolicyGraph


PolicyRecord = Union[RBACRecord, HierRecord, ABACRecord, ACLRecord, DenyRecord]


def build_graph(
    records: List[PolicyRecord],
    namespace: str,
    resource: str,
) -> PolicyGraph:
    """Build a semantic PolicyGraph G_{n,r} from a list of policy records.

    Args:
        records:   list of policy records for this (namespace, resource)
        namespace: Kubernetes namespace string
        resource:  resource name string

    Returns:
        PolicyGraph: the constructed G_{n,r} (for audit/correctness only)

    Raises:
        ValueError: if role hierarchy has a cycle
        SyntaxError: if an ABAC predicate fails to parse
    """
    graph = PolicyGraph(namespace=namespace, resource=resource)
    hc = HashConsingRegistry()

    hier_records = [r for r in records if isinstance(r, HierRecord)]
    rbac_records = [r for r in records if isinstance(r, RBACRecord)]
    abac_records = [r for r in records if isinstance(r, ABACRecord)]
    acl_records  = [r for r in records if isinstance(r, ACLRecord)]
    deny_records = [r for r in records if isinstance(r, DenyRecord)]

    # Hierarchy edges
    for rec in hier_records:
        graph.add_hier_edge(parent=rec.parent_role, child=rec.child_role)

    detect_hierarchy_cycle(graph.hier_edges)

    # RBAC permission edges
    for rec in rbac_records:
        graph.add_perm_edge(role=rec.role, action=rec.action)

    # ABAC gate edges
    for rec in abac_records:
        ast = parse_predicate(rec.predicate)
        gate_root = build_shared_dag(ast, hc)
        graph.add_gate_edge(gate_root=gate_root, action=rec.action)

    # Store registry for introspection
    graph._hc_registry = hc  # type: ignore[attr-defined]

    # ACL edges
    for rec in acl_records:
        graph.add_acl_edge(subject=rec.subject, action=rec.action)

    # Deny edges
    for rec in deny_records:
        graph.add_deny_edge(subject=rec.subject, action=rec.action)

    return graph
