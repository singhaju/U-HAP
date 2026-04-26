"""
In-memory graph registry for U-HAP.

Stores the constructed PolicyGraph objects indexed by (namespace, resource).
Access pattern: Registry[namespace][resource] -> PolicyGraph | None.

The registry is populated during Phase 1 (deployment time) and read-only
during Phase 2 (request time). It is NOT thread-safe for concurrent writes
(policies are loaded once at startup).

Public API:
  GraphRegistry          -- the registry class
  get_registry()         -- module-level singleton accessor
  load_graphs(records)   -- build and register all graphs from policy records
"""

from typing import Dict, Optional, List, Union

from dsl.models import RBACRecord, HierRecord, ABACRecord, ACLRecord, DenyRecord
from graph.builder import build_graph
from graph.models import PolicyGraph


PolicyRecord = Union[RBACRecord, HierRecord, ABACRecord, ACLRecord, DenyRecord]


class GraphRegistry:
    """In-memory store of policy graphs indexed by (namespace, resource).

    Usage:
        registry = GraphRegistry()
        registry.load(all_records)

        g = registry.get("prod", "pods")   # -> PolicyGraph or None
    """

    def __init__(self):
        # _store[namespace][resource] -> PolicyGraph
        self._store: Dict[str, Dict[str, PolicyGraph]] = {}

    def get(self, namespace: str, resource: str) -> Optional[PolicyGraph]:
        """Return the PolicyGraph for (namespace, resource), or None if absent."""
        return self._store.get(namespace, {}).get(resource)

    def set(self, namespace: str, resource: str, graph: PolicyGraph) -> None:
        """Store a PolicyGraph for (namespace, resource)."""
        if namespace not in self._store:
            self._store[namespace] = {}
        self._store[namespace][resource] = graph

    def load(self, records: List[PolicyRecord]) -> None:
        """Build and store PolicyGraphs for all (namespace, resource) pairs.

        Partitions the flat record list by (namespace, resource), then calls
        build_graph() for each partition.

        Args:
            records: flat list of all policy records (any types, any namespaces)

        Raises:
            ValueError: if a role hierarchy in any resource has a cycle
            SyntaxError: if an ABAC predicate fails to parse
        """
        # Partition by (namespace, resource)
        partitions: Dict[tuple, List[PolicyRecord]] = {}
        for rec in records:
            key = (rec.namespace, rec.resource)
            if key not in partitions:
                partitions[key] = []
            partitions[key].append(rec)

        # Build one graph per partition
        for (namespace, resource), partition in partitions.items():
            graph = build_graph(partition, namespace=namespace, resource=resource)
            self.set(namespace, resource, graph)

    def namespaces(self) -> List[str]:
        """Return all namespaces that have at least one registered graph."""
        return list(self._store.keys())

    def resources(self, namespace: str) -> List[str]:
        """Return all resources registered for a given namespace."""
        return list(self._store.get(namespace, {}).keys())

    def clear(self) -> None:
        """Remove all registered graphs (used in tests)."""
        self._store.clear()

    def __len__(self) -> int:
        return sum(len(ns_map) for ns_map in self._store.values())


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_registry: Optional[GraphRegistry] = None


def get_registry() -> GraphRegistry:
    """Return the module-level GraphRegistry singleton, creating it if needed."""
    global _registry
    if _registry is None:
        _registry = GraphRegistry()
    return _registry


def load_graphs(records: List[PolicyRecord]) -> GraphRegistry:
    """Convenience function: build graphs from records and store in singleton.

    Returns the populated registry.
    """
    reg = get_registry()
    reg.load(records)
    return reg
