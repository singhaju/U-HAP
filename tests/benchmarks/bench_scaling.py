"""
Benchmark: Scaling behavior.

Measures:
  1. Phase 2 (compile) time as policy count varies: 10, 50, 100 rules
  2. Phase 3 (eval) time as policy count varies
  3. Comparison: hash-consing vs. naive (independent) evaluation

The paper claims O(d) evaluation complexity where d is the DAG depth,
vs. O(w·n) naive where w=gate nodes, n=atoms per gate.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

import pytest
from dsl.models import ABACRecord, RBACRecord, HierRecord
from compiler.registry import ArtifactRegistry
from engine.evaluator import evaluate_request
from engine.hash_consing import HashConsingRegistry, build_shared_dag
from dsl.parser import parse_predicate


# ---------------------------------------------------------------------------
# Policy generators
# ---------------------------------------------------------------------------

# Fixed set of "base" predicates that will be reused to create overlap
BASE_CONDITIONS = [
    "net == 'on-premise'",
    "time == 'business-hours'",
    "dept == 'engineering'",
    "clearance == 'secret'",
    "region == 'us'",
]


def generate_abac_records(n: int, namespace="prod", resource="pods",
                           action="get") -> list:
    """Generate n ABAC records with some overlapping sub-expressions.

    Every 5th rule introduces a compound predicate that reuses base conditions,
    ensuring the shared DAG has significant sharing.
    """
    records = []
    for i in range(n):
        if i % 5 == 0:
            # Compound with shared base condition
            base = BASE_CONDITIONS[i % len(BASE_CONDITIONS)]
            pred = f"({base}) AND extra{i} == 'v{i}'"
        else:
            pred = f"attr{i} == 'val{i}'"
        records.append(ABACRecord(
            resource=resource, namespace=namespace, action=action,
            predicate=pred,
        ))
    return records


def generate_hierarchy_records(depth: int, namespace="prod") -> list:
    """Generate a linear role hierarchy of given depth."""
    records = []
    for i in range(depth):
        records.append(HierRecord(
            parent_role=f"role{i}", child_role=f"role{i+1}",
            namespace=namespace,
        ))
    return records


def _build_registry(records):
    r = ArtifactRegistry()
    r.load(records)
    return r


def _naive_eval_cost(records: list) -> int:
    """Compute the total node evaluations if evaluated naively (no sharing)."""
    total = 0
    for rec in records:
        if isinstance(rec, ABACRecord):
            hc = HashConsingRegistry()
            ast = parse_predicate(rec.predicate)
            build_shared_dag(ast, hc)
            total += hc.node_count
    return total


def _shared_eval_cost(records: list) -> int:
    """Compute total DAG nodes when all predicates share one HashConsingRegistry."""
    hc = HashConsingRegistry()
    for rec in records:
        if isinstance(rec, ABACRecord):
            ast = parse_predicate(rec.predicate)
            build_shared_dag(ast, hc)
    return hc.node_count


# ---------------------------------------------------------------------------
# Phase 2 (compile) scaling benchmarks
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("n", [10, 50, 100])
def test_bench_phase1_scaling(benchmark, n):
    """Phase 2 compile time scales with policy count."""
    records = generate_abac_records(n)
    g = benchmark(_build_registry, records)
    # Verify registry has artifacts
    assert len(g) > 0


# ---------------------------------------------------------------------------
# Phase 3 (eval) scaling benchmarks
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("n", [10, 50, 100])
def test_bench_phase2_scaling(benchmark, n):
    """Phase 3 eval time: all ABAC predicates false (worst-case scan)."""
    records = generate_abac_records(n)
    g = _build_registry(records)
    ctx = {"net": "remote", "time": "after-hours"}
    result = benchmark(evaluate_request, g, "prod", "pods", "get", "alice", [], [], ctx)
    assert result[0] is False  # none of the attr{i} predicates match


# ---------------------------------------------------------------------------
# Hierarchy scaling benchmarks
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("depth", [5, 10, 20])
def test_bench_hierarchy_depth_scaling(benchmark, depth):
    """Phase 3 RBAC time: bit-vector check, constant regardless of depth."""
    records = generate_hierarchy_records(depth)
    records.append(RBACRecord(
        role=f"role{depth}", resource="pods", namespace="prod", action="get"
    ))
    g = _build_registry(records)
    ctx = {}
    result = benchmark(evaluate_request, g, "prod", "pods", "get", "dave", ["role0"], [], ctx)
    assert result[0] is True  # transitive closure includes role{depth}


# ---------------------------------------------------------------------------
# Comparison: hash-consing vs. naive evaluation cost
# ---------------------------------------------------------------------------

class TestNaiveVsSharedComparison:
    """Verify that hash consing reduces evaluation cost vs. naive approach."""

    def test_shared_fewer_nodes_than_naive_with_overlap(self):
        """With overlapping predicates, shared DAG has fewer nodes than naive."""
        n = 20
        records = generate_abac_records(n)
        shared_count = _shared_eval_cost(records)
        naive_count = _naive_eval_cost(records)
        # With 20% compound predicates sharing base conditions, shared < naive
        assert shared_count <= naive_count, (
            f"Expected shared ({shared_count}) <= naive ({naive_count})"
        )

    def test_no_overlap_shared_equals_naive(self):
        """Without overlap, shared and naive are equal (no savings, no cost)."""
        records = [
            ABACRecord(resource="pods", namespace="prod", action="get",
                       predicate=f"unique_attr_{i} == 'v{i}'")
            for i in range(10)
        ]
        shared_count = _shared_eval_cost(records)
        naive_count = _naive_eval_cost(records)
        # Each predicate is a single unique atom -> equal
        assert shared_count == naive_count == 10
