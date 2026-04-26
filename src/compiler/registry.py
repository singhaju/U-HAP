"""
Compiled artifact registry for U-HAP v2.

Stores CompiledArtifact objects indexed by (namespace, resource, action).
Access pattern: registry[namespace][resource][action] -> CompiledArtifact | None.

This is the Phase 3 lookup table — populated once during Phase 2 compilation
and then read-only during request processing.

Public API:
  ArtifactRegistry   -- the 3-level registry class
"""

from collections import defaultdict
from typing import Dict, List, Optional, Union

from compiler.index_compiler import compile_artifacts
from dsl.models import (
    ABACRecord, ACLRecord, CompiledArtifact, DenyRecord, HierRecord, RBACRecord,
)


PolicyRecord = Union[RBACRecord, HierRecord, ABACRecord, ACLRecord, DenyRecord]


class ArtifactRegistry:
    """In-memory store of compiled artifacts indexed by (namespace, resource, action).

    Usage:
        registry = ArtifactRegistry()
        registry.load(all_records)

        artifact = registry.get("prod", "pods", "get")  # -> CompiledArtifact | None
    """

    def __init__(self):
        # _store[namespace][resource][action] -> CompiledArtifact
        self._store: Dict[str, Dict[str, Dict[str, CompiledArtifact]]] = {}

    def get(
        self,
        namespace: str,
        resource: str,
        action: str,
    ) -> Optional[CompiledArtifact]:
        """Return the CompiledArtifact for (namespace, resource, action), or None."""
        return (
            self._store
            .get(namespace, {})
            .get(resource, {})
            .get(action)
        )

    def set(
        self,
        namespace: str,
        resource: str,
        action: str,
        artifact: CompiledArtifact,
    ) -> None:
        """Store a CompiledArtifact for (namespace, resource, action)."""
        if namespace not in self._store:
            self._store[namespace] = {}
        if resource not in self._store[namespace]:
            self._store[namespace][resource] = {}
        self._store[namespace][resource][action] = artifact

    def load(self, records: List[PolicyRecord]) -> None:
        """Compile and store artifacts for all (namespace, resource) partitions.

        Groups records by (namespace, resource), compiles each partition into
        C_{n,r,a} artifacts via the index compiler, and stores them.

        HierRecord has namespace but no resource — it is included in every
        (namespace, resource) partition within its namespace so that transitive
        closure is available during RBAC index compilation.

        Args:
            records: flat list of all policy records (any types, any namespaces)

        Raises:
            ValueError: if a role hierarchy has a cycle
            SyntaxError: if an ABAC predicate fails to parse
        """
        # Separate HierRecords (namespace-scoped, no resource) from the rest
        hier_by_ns: Dict[str, List[PolicyRecord]] = defaultdict(list)
        resource_records: List[PolicyRecord] = []

        for rec in records:
            if isinstance(rec, HierRecord):
                hier_by_ns[rec.namespace].append(rec)
            else:
                resource_records.append(rec)

        # Partition resource-bearing records by (namespace, resource)
        partitions: Dict[tuple, List[PolicyRecord]] = defaultdict(list)
        for rec in resource_records:
            key = (rec.namespace, rec.resource)
            partitions[key].append(rec)

        # Also create empty partitions for namespaces that only have hier records
        for ns, hier_records in hier_by_ns.items():
            # If no resource records exist for this namespace, we still need to
            # register the hierarchy (but there's nothing to compile for it alone).
            # Only add partitions that already have resource records.
            pass

        # Compile each partition, including all HierRecords for the same namespace
        for (namespace, resource), partition in partitions.items():
            # Add hierarchy records from the same namespace
            full_partition = list(partition) + hier_by_ns.get(namespace, [])
            artifacts = compile_artifacts(full_partition, namespace=namespace, resource=resource)
            for action, artifact in artifacts.items():
                self.set(namespace, resource, action, artifact)

    def namespaces(self) -> List[str]:
        """Return all namespaces that have at least one artifact."""
        return list(self._store.keys())

    def resources(self, namespace: str) -> List[str]:
        """Return all resources registered for a given namespace."""
        return list(self._store.get(namespace, {}).keys())

    def actions(self, namespace: str, resource: str) -> List[str]:
        """Return all actions registered for a given (namespace, resource)."""
        return list(self._store.get(namespace, {}).get(resource, {}).keys())

    def clear(self) -> None:
        """Remove all stored artifacts (used in tests)."""
        self._store.clear()

    def __len__(self) -> int:
        """Return total number of stored artifacts."""
        total = 0
        for ns_map in self._store.values():
            for res_map in ns_map.values():
                total += len(res_map)
        return total
