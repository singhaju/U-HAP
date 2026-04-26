"""
Gate node types for the U-HAP shared ABAC predicate DAG.

Three node types:
  AtomicCheck    - leaf: single attribute equality/inequality/in check
  GateNode       - internal: AND/OR gate over child nodes
  ThresholdGate  - internal: at-least-k-of-m gate over child nodes

These nodes form a shared DAG built during Phase 1 (graph construction)
using hash consing. During Phase 2 (evaluation), each node is evaluated
at most once per request using a memo dict.

evaluate_dag(node, context, memo) is the canonical evaluation entry point.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class AtomicCheck:
    """A single attribute equality/inequality/membership check.

    Examples:
        net == 'on-premise'      -> AtomicCheck("net", "==", "on-premise")
        time != 'after-hours'    -> AtomicCheck("time", "!=", "after-hours")
        role in ['admin', 'ops'] -> AtomicCheck("role", "in", ["admin", "ops"])
    """
    attribute: str
    operator: str    # "==" | "!=" | "in"
    value: Any

    # cost: estimated evaluation cost (leaves = 1, used for cost-ordered ABAC)
    cost: int = 1

    def evaluate(self, context: dict) -> bool:
        actual = context.get(self.attribute)
        if self.operator == "==":
            return actual == self.value
        elif self.operator == "!=":
            return actual != self.value
        elif self.operator == "in":
            return actual in self.value
        return False

    def canonical_key(self) -> tuple:
        # Use str(value) so lists become hashable in the key
        return ("atom", self.attribute, self.operator, str(self.value))

    def required_attributes(self) -> set:
        """Return the set of attribute keys read by this node."""
        return {self.attribute}


@dataclass
class GateNode:
    """An AND or OR gate composing child nodes.

    AND = all children must be true (short-circuits on first False)
    OR  = any child must be true  (short-circuits on first True)

    Children are stored sorted by canonical key so AND(a, b) == AND(b, a).
    The _key field caches the canonical key after first computation.
    """
    operator: str       # "AND" | "OR"
    children: list      # list of AtomicCheck | GateNode | ThresholdGate
    _key: tuple = field(default=None, compare=False, hash=False, repr=False)
    # cost: sum of children costs + 1 (for cost-ordered evaluation)
    cost: int = field(default=1, compare=False, hash=False)

    def canonical_key(self) -> tuple:
        if self._key is None:
            child_keys = sorted(c.canonical_key() for c in self.children)
            self._key = (self.operator, tuple(child_keys))
        return self._key

    def __hash__(self):
        return hash(self.canonical_key())

    def __eq__(self, other):
        if not isinstance(other, GateNode):
            return False
        return self.canonical_key() == other.canonical_key()

    def required_attributes(self) -> set:
        """Return the union of attribute keys read by all children."""
        attrs = set()
        for child in self.children:
            attrs.update(child.required_attributes())
        return attrs


@dataclass
class ThresholdGate:
    """At-least-k-of-m gate: at least k of the m children must be true.

    Note: AND is k=m (all), OR is k=1 (any).
    ThresholdGate is used only for explicit ATLEAST(k, ...) where 1 < k < m.
    """
    k: int
    children: list      # list of AtomicCheck | GateNode | ThresholdGate
    # cost: sum of children costs + 1
    cost: int = field(default=1)

    def canonical_key(self) -> tuple:
        child_keys = sorted(c.canonical_key() for c in self.children)
        return ("THRESHOLD", self.k, tuple(child_keys))

    def __hash__(self):
        return hash(self.canonical_key())

    def __eq__(self, other):
        if not isinstance(other, ThresholdGate):
            return False
        return self.canonical_key() == other.canonical_key()

    def required_attributes(self) -> set:
        """Return the union of attribute keys read by all children."""
        attrs = set()
        for child in self.children:
            attrs.update(child.required_attributes())
        return attrs


def evaluate_dag(node, context: dict, memo: dict) -> bool:
    """Evaluate a node in the shared ABAC DAG with memoization.

    Each node is evaluated at most once per request (memo prevents re-eval).
    Children are evaluated before their parents (recursive DFS).

    Args:
        node:    AtomicCheck, GateNode, or ThresholdGate
        context: dict of attribute name -> value (merged token + runtime context)
        memo:    dict of canonical_key -> bool (evaluation cache for this request)

    Returns:
        bool: True if this node evaluates to true for the given context
    """
    key = node.canonical_key()
    if key in memo:
        return memo[key]

    if isinstance(node, AtomicCheck):
        result = node.evaluate(context)

    elif isinstance(node, GateNode):
        if node.operator == "AND":
            # Short-circuit: stop on first False
            result = all(evaluate_dag(c, context, memo) for c in node.children)
        elif node.operator == "OR":
            # Short-circuit: stop on first True
            result = any(evaluate_dag(c, context, memo) for c in node.children)
        else:
            result = False

    elif isinstance(node, ThresholdGate):
        count = sum(1 for c in node.children if evaluate_dag(c, context, memo))
        result = count >= node.k

    else:
        result = False

    memo[key] = result
    return result
