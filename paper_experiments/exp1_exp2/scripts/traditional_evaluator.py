"""
traditional_evaluator.py — Naive sequential authorization evaluator.

This module implements a fair, non-optimized sequential authorization evaluator
representing how a standard SSO system (LDAP, basic OAuth2, non-optimized
Kubernetes webhook) performs authorization.

Key properties (intentional NON-optimizations):
- No bit-vectors: RBAC checks loop through all role rules.
- No hash consing: ABAC predicates are evaluated per-rule without sharing.
- No memoization: sub-expressions re-evaluated even when identical across rules.
- No attribute-key pruning: all ABAC rules are evaluated.
- No 3-level index: rules stored as flat lists, scanned sequentially.
- Hierarchy traversal at request time (not pre-computed).

ABAC optimization: AST is cached at load time (parse once, evaluate many times).
This is a deliberate choice to focus the comparison on evaluation overhead,
not parsing overhead. Sub-expression RESULTS are never memoized.

Evaluation order (matches U-HAP for fairness):
    1. Namespace lookup (O(1) dict)
    2. Deny check (scan all deny_rules, filter resource+action)
    3. ACL check (scan all acl_rules, filter resource+action)
    4. RBAC check (scan all rbac_rules, compute hierarchy at runtime)
    5. ABAC check (scan all abac_rules, evaluate each predicate from scratch)
    6. Default deny
"""
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

_SCRIPTS_DIR = Path(__file__).resolve().parent
_ROOT = _SCRIPTS_DIR.parent.parent.parent
sys.path.insert(0, str(_ROOT / "src"))

from dsl.models import ASTAtom, ASTBinary, ASTThreshold
from dsl.parser import parse_predicate


# ---------------------------------------------------------------------------
# Rule data structures (no compilation, just plain lists)
# ---------------------------------------------------------------------------

@dataclass
class DenyRule:
    subject: str    # username or "*"
    resource: str
    action: str


@dataclass
class ACLRule:
    subject: str    # specific username
    resource: str
    action: str


@dataclass
class RBACRule:
    role: str
    resource: str
    action: str


@dataclass
class ABACRule:
    predicate_str: str     # raw predicate string
    resource: str
    action: str
    _ast: object = field(default=None, repr=False)  # cached AST (parsed once at load)

    def __post_init__(self):
        # Parse AST once at load time (but never memoize evaluation results)
        self._ast = parse_predicate(self.predicate_str)


@dataclass
class TraditionalPolicy:
    """A single namespace's complete policy set (no compilation).

    Rules stored as plain lists — no indexing by resource or action.
    The evaluator must scan all rules to find matching ones.
    """
    namespace: str
    # Rules stored as flat lists — no action-level indexing
    deny_rules: List[DenyRule] = field(default_factory=list)
    acl_rules: List[ACLRule] = field(default_factory=list)
    rbac_rules: List[RBACRule] = field(default_factory=list)
    abac_rules: List[ABACRule] = field(default_factory=list)
    # Hierarchy stored as raw edges — transitive closure computed at request time
    hierarchy_edges: Dict[str, List[str]] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Registry — indexed by namespace only (O(1) namespace lookup, O(k) rule scan)
# ---------------------------------------------------------------------------

class TraditionalRegistry:
    """Stores policies indexed by namespace only (no resource/action indexing).

    Lookup: registry[namespace] -> TraditionalPolicy
    Within a namespace, rules are scanned sequentially (no further indexing).
    """

    def __init__(self):
        self._store: Dict[str, TraditionalPolicy] = {}

    def get(self, namespace: str) -> Optional[TraditionalPolicy]:
        return self._store.get(namespace)

    def load(self, app_data_list: List[Dict]) -> None:
        """Load a list of app_data dicts into the registry.

        Groups rules by namespace and builds TraditionalPolicy objects.
        No compilation — just grouping into lists.

        Args:
            app_data_list: List of app_data dicts from generate_test_data.
        """
        for app_data in app_data_list:
            ns = app_data["namespace"]
            policy = self._store.get(ns)
            if policy is None:
                policy = TraditionalPolicy(namespace=ns)
                self._store[ns] = policy

            for r in app_data.get("deny_rules", []):
                policy.deny_rules.append(DenyRule(
                    subject=r["subject"],
                    resource=r["resource"],
                    action=r["action"],
                ))

            for r in app_data.get("acl_rules", []):
                policy.acl_rules.append(ACLRule(
                    subject=r["subject"],
                    resource=r["resource"],
                    action=r["action"],
                ))

            for r in app_data.get("rbac_rules", []):
                policy.rbac_rules.append(RBACRule(
                    role=r["role"],
                    resource=r["resource"],
                    action=r["action"],
                ))

            for r in app_data.get("abac_rules", []):
                policy.abac_rules.append(ABACRule(
                    predicate_str=r["predicate"],
                    resource=r["resource"],
                    action=r["action"],
                ))

            for parent, children in app_data.get("hierarchy_edges", {}).items():
                policy.hierarchy_edges.setdefault(parent, [])
                for child in children:
                    if child not in policy.hierarchy_edges[parent]:
                        policy.hierarchy_edges[parent].append(child)


# ---------------------------------------------------------------------------
# ABAC evaluation — no memoization, no sharing
# ---------------------------------------------------------------------------

def _eval_ast_node(node, context: dict) -> bool:
    """Recursively evaluate an AST node against context. No memoization.

    Each call evaluates the node from scratch. If the same sub-expression
    appears in multiple rules, it is evaluated multiple times (intentional).
    """
    if isinstance(node, ASTAtom):
        actual = context.get(node.attribute)
        if node.operator == "==":
            return actual == node.value
        elif node.operator == "!=":
            return actual != node.value
        elif node.operator == "in":
            return actual in node.value
        return False

    if isinstance(node, ASTBinary):
        if node.type == "AND":
            return all(_eval_ast_node(c, context) for c in node.children)
        elif node.type == "OR":
            return any(_eval_ast_node(c, context) for c in node.children)
        return False

    if isinstance(node, ASTThreshold):
        count = sum(1 for c in node.children if _eval_ast_node(c, context))
        return count >= node.k

    return False


def _eval_ast_node_counted(node, context: dict, counter: List[int]) -> bool:
    """Like _eval_ast_node but increments counter[0] for each atom evaluated.

    Used by exp3b to measure total atom evaluations.
    """
    if isinstance(node, ASTAtom):
        counter[0] += 1
        actual = context.get(node.attribute)
        if node.operator == "==":
            return actual == node.value
        elif node.operator == "!=":
            return actual != node.value
        elif node.operator == "in":
            return actual in node.value
        return False

    if isinstance(node, ASTBinary):
        if node.type == "AND":
            results = [_eval_ast_node_counted(c, context, counter) for c in node.children]
            return all(results)
        elif node.type == "OR":
            results = [_eval_ast_node_counted(c, context, counter) for c in node.children]
            return any(results)
        return False

    if isinstance(node, ASTThreshold):
        count = sum(1 for c in node.children if _eval_ast_node_counted(c, context, counter))
        return count >= node.k

    return False


# ---------------------------------------------------------------------------
# Hierarchy traversal — at request time (not pre-computed)
# ---------------------------------------------------------------------------

def _get_effective_roles(
    user_roles: List[str],
    hierarchy_edges: Dict[str, List[str]],
) -> Set[str]:
    """Compute effective roles by traversing hierarchy at request time.

    Unlike U-HAP (which pre-computes transitive closure + bit-vector at
    compile time), this computes it fresh for every request via BFS.

    For each user role, walk DOWN the hierarchy to find all inherited roles
    (children that the user transitively has permissions for).
    """
    effective = set(user_roles)
    queue = list(user_roles)
    while queue:
        role = queue.pop(0)
        for child in hierarchy_edges.get(role, []):
            if child not in effective:
                effective.add(child)
                queue.append(child)
    return effective


# ---------------------------------------------------------------------------
# Main evaluation function
# ---------------------------------------------------------------------------

def traditional_evaluate(
    registry: "TraditionalRegistry",
    namespace: str,
    resource: str,
    action: str,
    uid: str,
    roles: List[str],
    groups: List[str],
    context: dict,
) -> Tuple[bool, str]:
    """Evaluate authorization using sequential scanning.

    Order (same as U-HAP to be fair):
        1. Namespace lookup -> O(1) dict
        2. Deny check -> scan all deny_rules, filter by resource+action, O(k_deny)
        3. ACL check -> scan all acl_rules, filter by resource+action, O(k_acl)
        4. RBAC check -> scan all rbac_rules, filter by resource+action,
                         compute effective roles (hierarchy BFS), O(k_rbac * h)
        5. ABAC check -> scan all abac_rules, filter by resource+action,
                         evaluate each predicate AST. No memoization, no sharing.
                         O(k_abac * g)
        6. Default deny

    Args:
        registry:  TraditionalRegistry with loaded policies.
        namespace: Kubernetes namespace for the request.
        resource:  Resource being accessed (e.g., "pods").
        action:    Action being performed (e.g., "get").
        uid:       Authenticated user identity string.
        roles:     List of role names from the token.
        groups:    List of group names from the token.
        context:   Dict of attributes for ABAC evaluation.

    Returns:
        (allowed: bool, reason: str)
    """
    # 1. Namespace lookup (O(1))
    policy = registry.get(namespace)
    if policy is None:
        return False, "no policy"

    # 2. Deny check — scan all deny_rules, filter by resource+action
    for rule in policy.deny_rules:
        if rule.resource == resource and rule.action == action:
            if rule.subject == "*" or rule.subject == uid:
                return False, f"deny: {rule.subject}"

    # 3. ACL check — scan all acl_rules, filter by resource+action
    # Check uid directly AND groups (groups may contain role names that are also ACL entries)
    token_ids = {uid} | set(groups)
    for rule in policy.acl_rules:
        if rule.resource == resource and rule.action == action:
            if rule.subject in token_ids:
                return True, f"acl: {rule.subject}"

    # 4. RBAC check — compute effective roles via hierarchy BFS, then scan
    effective_roles = _get_effective_roles(roles, policy.hierarchy_edges)
    for rule in policy.rbac_rules:
        if rule.resource == resource and rule.action == action:
            if rule.role in effective_roles:
                return True, f"rbac: {rule.role}"

    # 5. ABAC check — evaluate each rule's predicate with NO memoization
    for rule in policy.abac_rules:
        if rule.resource == resource and rule.action == action:
            if _eval_ast_node(rule._ast, context):
                return True, f"abac: {rule.predicate_str[:40]}"

    # 6. Default deny
    return False, "no path"


def traditional_evaluate_counted(
    registry: "TraditionalRegistry",
    namespace: str,
    resource: str,
    action: str,
    uid: str,
    roles: List[str],
    groups: List[str],
    context: dict,
) -> Tuple[bool, str, int]:
    """Like traditional_evaluate but also returns total atom evaluation count.

    Used by exp3b to measure trad_total_evals.
    """
    policy = registry.get(namespace)
    if policy is None:
        return False, "no policy", 0

    for rule in policy.deny_rules:
        if rule.resource == resource and rule.action == action:
            if rule.subject == "*" or rule.subject == uid:
                return False, f"deny: {rule.subject}", 0

    token_ids = {uid} | set(groups)
    for rule in policy.acl_rules:
        if rule.resource == resource and rule.action == action:
            if rule.subject in token_ids:
                return True, f"acl: {rule.subject}", 0

    effective_roles = _get_effective_roles(roles, policy.hierarchy_edges)
    for rule in policy.rbac_rules:
        if rule.resource == resource and rule.action == action:
            if rule.role in effective_roles:
                return True, f"rbac: {rule.role}", 0

    counter = [0]
    for rule in policy.abac_rules:
        if rule.resource == resource and rule.action == action:
            if _eval_ast_node_counted(rule._ast, context, counter):
                return True, f"abac: {rule.predicate_str[:40]}", counter[0]

    return False, "no path", counter[0]


# ---------------------------------------------------------------------------
# Convenience loaders
# ---------------------------------------------------------------------------

def load_traditional_registry_from_app_data_list(
    apps_data: List[Dict],
) -> "TraditionalRegistry":
    """Convenience function to build a TraditionalRegistry from app_data dicts."""
    reg = TraditionalRegistry()
    reg.load(apps_data)
    return reg


def load_traditional_registry_from_exp2_data(
    data: Dict,
    model: str,
) -> "TraditionalRegistry":
    """Build a TraditionalRegistry from a single-model exp2 data dict.

    Args:
        data:  app_data dict from generate_rbac_only_data, generate_abac_only_data,
               or generate_acl_only_data.
        model: One of "rbac", "abac", "acl" (for labeling; not used functionally).

    Returns:
        TraditionalRegistry loaded with the single app's rules.
    """
    reg = TraditionalRegistry()
    reg.load([data])
    return reg
