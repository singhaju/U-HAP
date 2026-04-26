"""
Index compiler for U-HAP — Phase 2 policy compilation.

Takes policy records for a (namespace, resource) partition and produces
CompiledArtifact objects C_{n,r,a} for each distinct action found in
those records.

The CompiledArtifact contains all pre-built indices used by Phase 3:
  - I_deny:   set of scope strings matched against user identity
  - I_acl:    set of subject IDs with direct permission
  - I_rbac:   set of role names authorized (after transitive closure)
  - b_rbac:   integer bit-vector for I_rbac
  - I_abac:   list of CompiledGate (cost-sorted)
  - I_attr:   dict[attr_key -> list[CompiledGate]] for attribute-key pruning
  - summary:  PolicySummary (counts per type)
  - fast_path: FastPath (activation bits)

The semantic graph G_{n,r} is also embedded in each artifact for audit.

Public API:
  compile_artifacts(records, namespace, resource) -> dict[action, CompiledArtifact]
"""

from collections import defaultdict
from typing import Dict, List, Union

from compiler.bitvector import RoleBitVector
from compiler.graph_builder import build_graph
from compiler.role_closure import compute_transitive_closure, get_ancestors
from dsl.models import (
    ABACRecord, ACLRecord, CompiledArtifact, CompiledGate,
    DenyRecord, FastPath, HierRecord, PolicySummary, RBACRecord,
)
from dsl.parser import parse_predicate
from engine.hash_consing import HashConsingRegistry, build_shared_dag, estimate_cost


PolicyRecord = Union[RBACRecord, HierRecord, ABACRecord, ACLRecord, DenyRecord]


def _extract_required_attrs(ast_node) -> set:
    """Recursively collect all attribute keys referenced in an AST node."""
    from dsl.models import ASTAtom, ASTBinary, ASTThreshold
    if isinstance(ast_node, ASTAtom):
        return {ast_node.attribute}
    if isinstance(ast_node, (ASTBinary, ASTThreshold)):
        attrs = set()
        for child in ast_node.children:
            attrs.update(_extract_required_attrs(child))
        return attrs
    return set()


def compile_artifacts(
    records: List[PolicyRecord],
    namespace: str,
    resource: str,
) -> Dict[str, CompiledArtifact]:
    """Compile policy records into C_{n,r,a} artifacts for each action.

    Args:
        records:   Policy records for this (namespace, resource) partition.
                   May include records of all 5 types.
        namespace: Kubernetes namespace string.
        resource:  Resource name string.

    Returns:
        dict mapping action_string -> CompiledArtifact.

    Raises:
        ValueError: if role hierarchy has a cycle or records are invalid.
        SyntaxError: if an ABAC predicate fails to parse.
    """
    # Separate records by type
    rbac_records  = [r for r in records if isinstance(r, RBACRecord)]
    hier_records  = [r for r in records if isinstance(r, HierRecord)]
    abac_records  = [r for r in records if isinstance(r, ABACRecord)]
    acl_records   = [r for r in records if isinstance(r, ACLRecord)]
    deny_records  = [r for r in records if isinstance(r, DenyRecord)]

    # ------------------------------------------------------------------
    # Build semantic graph G_{n,r} (for audit / correctness; not runtime)
    # ------------------------------------------------------------------
    graph = build_graph(records, namespace=namespace, resource=resource)

    # ------------------------------------------------------------------
    # Transitive closure of role hierarchy
    # ------------------------------------------------------------------
    hier_edges: Dict[str, List[str]] = {}
    for rec in hier_records:
        if rec.parent_role not in hier_edges:
            hier_edges[rec.parent_role] = []
        if rec.child_role not in hier_edges[rec.parent_role]:
            hier_edges[rec.parent_role].append(rec.child_role)

    # closure[role] = set of roles reachable from role (what role inherits)
    closure = compute_transitive_closure(hier_edges) if hier_edges else {}

    # Collect all roles across the entire namespace/resource
    all_roles: set = set()
    for rec in rbac_records:
        all_roles.add(rec.role)
    all_roles.update(hier_edges.keys())
    for children in hier_edges.values():
        all_roles.update(children)

    # Build bit-vector registry over all roles
    rbv = RoleBitVector(all_roles)

    # ------------------------------------------------------------------
    # Discover all actions
    # ------------------------------------------------------------------
    actions = set()
    for rec in rbac_records:
        actions.add(rec.action)
    for rec in abac_records:
        actions.add(rec.action)
    for rec in acl_records:
        actions.add(rec.action)
    for rec in deny_records:
        actions.add(rec.action)

    # Even if no rules exist we need at least the empty set of actions
    # (edge case: a deny for action X means X must have an artifact)

    # ------------------------------------------------------------------
    # Per-action compilation
    # ------------------------------------------------------------------
    # One HashConsingRegistry shared across all ABAC rules for this resource
    # (cross-action sharing within the same resource is valid)
    hc = HashConsingRegistry()

    artifacts: Dict[str, CompiledArtifact] = {}

    for action in actions:
        # --- Deny index ---
        i_deny: set = set()
        for rec in deny_records:
            if rec.action == action:
                if rec.subject == "*":
                    i_deny.add("*")
                else:
                    i_deny.add(f"user:{rec.subject}")

        # --- ACL index ---
        i_acl: set = set()
        for rec in acl_records:
            if rec.action == action:
                i_acl.add(rec.subject)

        # --- RBAC index with transitive closure ---
        # Direct roles that have a perm edge for this action
        direct_rbac_roles: set = set()
        for rec in rbac_records:
            if rec.action == action:
                direct_rbac_roles.add(rec.role)

        # Add all ancestor roles (roles whose closure includes a direct role)
        i_rbac: set = set(direct_rbac_roles)
        for direct_role in direct_rbac_roles:
            ancestors = get_ancestors(direct_role, hier_edges)
            i_rbac.update(ancestors)

        # Build bit-vector for I_rbac
        b_rbac = rbv.encode(i_rbac)

        # --- ABAC index with hash consing ---
        i_abac: List[CompiledGate] = []
        for rec in abac_records:
            if rec.action == action:
                ast = parse_predicate(rec.predicate)
                dag_root = build_shared_dag(ast, hc)
                required_attrs = _extract_required_attrs(ast)
                cost = estimate_cost(dag_root)
                i_abac.append(CompiledGate(
                    root=dag_root,
                    required_attrs=required_attrs,
                    cost=cost,
                ))

        # Cost-sort ABAC gates (cheapest first)
        i_abac.sort(key=lambda g: g.cost)

        # --- Attribute-key index ---
        i_attr: Dict[str, List[CompiledGate]] = defaultdict(list)
        for gate in i_abac:
            for attr_key in gate.required_attrs:
                i_attr[attr_key].append(gate)

        # --- Policy summary ---
        summary = PolicySummary(
            acl_count=sum(1 for r in acl_records if r.action == action),
            rbac_count=len(i_rbac),
            abac_count=len(i_abac),
            deny_count=sum(1 for r in deny_records if r.action == action),
        )

        # --- Fast-path descriptor ---
        fast_path = FastPath(
            has_deny=len(i_deny) > 0,
            has_acl=len(i_acl) > 0,
            has_rbac=len(i_rbac) > 0,
            has_abac=len(i_abac) > 0,
        )

        artifacts[action] = CompiledArtifact(
            namespace=namespace,
            resource=resource,
            action=action,
            graph=graph,
            i_deny=i_deny,
            i_acl=i_acl,
            i_rbac=i_rbac,
            role_universe=all_roles,
            b_rbac=b_rbac,
            rbv=rbv,
            i_abac=i_abac,
            i_attr=dict(i_attr),
            summary=summary,
            fast_path=fast_path,
        )

    return artifacts
