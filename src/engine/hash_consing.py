"""
Hash consing registry for the U-HAP shared ABAC predicate DAG.

Hash consing ensures that structurally identical sub-expressions share
exactly one node in the DAG. This implements Common Subexpression
Elimination (CSE) as described in Section 3 of the U-HAP paper.

The key design choices:
  - AND/OR are commutative: children are sorted by canonical_key before
    computing the parent hash so AND(a,b) == AND(b,a).
  - ThresholdGate children are also sorted for the same reason.
  - The registry is per-resource (shared across all ABAC rules for one
    resource, not across resources).

Public API:
  HashConsingRegistry  -- the memo table
  build_shared_dag()   -- convert an AST node into a shared DAG node
"""

from typing import Any, Union

from dsl.models import ASTAtom, ASTBinary, ASTThreshold
from engine.gate_nodes import AtomicCheck, GateNode, ThresholdGate


class HashConsingRegistry:
    """
    Maintains the shared DAG of ABAC sub-expressions for a single resource.

    Maps canonical keys → node references. When two predicates produce
    structurally identical sub-expressions, they both point at the SAME
    node object in memory.

    Usage:
        hc = HashConsingRegistry()
        node = build_shared_dag(ast_root, hc)
        print(hc.node_count)   # number of unique structural nodes
    """

    def __init__(self):
        # canonical_key -> AtomicCheck | GateNode | ThresholdGate
        self._memo: dict = {}

    def get_or_create_atom(self, attribute: str, operator: str, value: Any) -> AtomicCheck:
        """Return an AtomicCheck for this (attribute, operator, value) triple.

        If an identical atom was already created, return the existing node
        (no new object is allocated).
        """
        node = AtomicCheck(attribute=attribute, operator=operator, value=value)
        key = node.canonical_key()
        if key in self._memo:
            return self._memo[key]
        self._memo[key] = node
        return node

    def get_or_create_gate(self, operator: str, children: list) -> GateNode:
        """Return a GateNode for this (operator, children) combination.

        Children are sorted by canonical key so AND(a, b) and AND(b, a)
        produce the same key (commutativity). If an identical gate already
        exists, return it unchanged.
        """
        sorted_children = sorted(children, key=lambda c: c.canonical_key())
        node = GateNode(operator=operator, children=sorted_children)
        key = node.canonical_key()
        if key in self._memo:
            return self._memo[key]
        self._memo[key] = node
        return node

    def get_or_create_threshold(self, k: int, children: list) -> ThresholdGate:
        """Return a ThresholdGate for this (k, children) combination.

        Children are sorted by canonical key for commutativity.
        """
        sorted_children = sorted(children, key=lambda c: c.canonical_key())
        node = ThresholdGate(k=k, children=sorted_children)
        key = node.canonical_key()
        if key in self._memo:
            return self._memo[key]
        self._memo[key] = node
        return node

    @property
    def node_count(self) -> int:
        """Number of unique structural nodes in the shared DAG."""
        return len(self._memo)


def estimate_cost(ast_node) -> int:
    """Estimate the evaluation cost of a predicate AST (or DAG node).

    Cost model:
      - AtomicCheck leaf: 1
      - ASTAtom leaf: 1
      - Binary/Gate (AND/OR): 1 + sum(child costs)
      - Threshold: 1 + sum(child costs)

    This is used to sort ABAC gates cheapest-first during compilation,
    so that at runtime the evaluator tries cheap gates before expensive ones.

    Args:
        ast_node: ASTAtom | ASTBinary | ASTThreshold
                  OR AtomicCheck | GateNode | ThresholdGate (DAG nodes)

    Returns:
        int cost estimate >= 1
    """
    # Handle DAG nodes (gate_nodes types)
    if isinstance(ast_node, AtomicCheck):
        return 1

    if isinstance(ast_node, (GateNode, ThresholdGate)):
        return 1 + sum(estimate_cost(c) for c in ast_node.children)

    # Handle AST nodes (parser output types)
    if isinstance(ast_node, ASTAtom):
        return 1

    if isinstance(ast_node, ASTBinary):
        return 1 + sum(estimate_cost(c) for c in ast_node.children)

    if isinstance(ast_node, ASTThreshold):
        return 1 + sum(estimate_cost(c) for c in ast_node.children)

    # Unknown node — return 1 as a safe default
    return 1


def build_shared_dag(
    ast_node,
    hc: HashConsingRegistry,
) -> Union[AtomicCheck, GateNode, ThresholdGate]:
    """Recursively convert an AST node into a shared DAG node using hash consing.

    For each sub-expression:
      - AtomicCheck atoms are looked up/created in the registry
      - AND/OR binary nodes are built bottom-up; children are sorted
      - THRESHOLD nodes are built similarly

    Two calls with structurally identical AST sub-trees will return the
    SAME node object from the registry (not just equal nodes — the same
    reference).

    Args:
        ast_node:  ASTAtom | ASTBinary | ASTThreshold  (from parser output)
        hc:        HashConsingRegistry shared across all ABAC rules for
                   one resource

    Returns:
        AtomicCheck | GateNode | ThresholdGate
    """
    if isinstance(ast_node, ASTAtom):
        return hc.get_or_create_atom(
            attribute=ast_node.attribute,
            operator=ast_node.operator,
            value=ast_node.value,
        )

    if isinstance(ast_node, ASTBinary):
        children = [build_shared_dag(child, hc) for child in ast_node.children]
        return hc.get_or_create_gate(operator=ast_node.type, children=children)

    if isinstance(ast_node, ASTThreshold):
        children = [build_shared_dag(child, hc) for child in ast_node.children]
        return hc.get_or_create_threshold(k=ast_node.k, children=children)

    raise ValueError(
        f"Unknown AST node type: {type(ast_node).__name__} ({ast_node!r})"
    )
