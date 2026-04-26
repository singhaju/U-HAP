"""
Benchmark: Hash consing sharing ratio σ (sigma).

σ = Σ|φᵢ| / |V_dag|

Where:
  Σ|φᵢ| = total number of nodes if each predicate were evaluated independently
  |V_dag| = number of nodes in the shared DAG (with hash consing)

σ > 1 means sharing is happening. Higher σ = more redundancy eliminated.

The paper claims σ increases with policy overlap (more shared sub-expressions).
This benchmark measures σ for different policy configurations:
  - No overlap: all predicates use unique attributes
  - Low overlap: 20% shared sub-expressions
  - High overlap: 80% shared sub-expressions
  - Extreme overlap: all predicates share the same core condition
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

import pytest
from dsl.models import ABACRecord
from graph.builder import build_graph
from engine.hash_consing import HashConsingRegistry, build_shared_dag
from dsl.parser import parse_predicate
from engine.gate_nodes import AtomicCheck, GateNode, ThresholdGate


def _count_nodes_naive(predicate_strings: list) -> int:
    """Count total nodes if each predicate were evaluated independently.

    Each predicate gets its own fresh registry, so no sharing occurs.
    """
    total = 0
    for p in predicate_strings:
        hc = HashConsingRegistry()
        ast = parse_predicate(p)
        build_shared_dag(ast, hc)
        total += hc.node_count
    return total


def _count_nodes_shared(predicate_strings: list) -> int:
    """Count nodes with hash consing (shared DAG)."""
    hc = HashConsingRegistry()
    for p in predicate_strings:
        ast = parse_predicate(p)
        build_shared_dag(ast, hc)
    return hc.node_count


def sharing_ratio(predicate_strings: list) -> float:
    """Compute σ = naive_count / shared_count."""
    naive = _count_nodes_naive(predicate_strings)
    shared = _count_nodes_shared(predicate_strings)
    if shared == 0:
        return 1.0
    return naive / shared


# ---------------------------------------------------------------------------
# Policy sets for measurement
# ---------------------------------------------------------------------------

NO_OVERLAP_PREDICATES = [
    "a1 == 'v1'",
    "a2 == 'v2'",
    "a3 == 'v3'",
    "a4 == 'v4'",
    "a5 == 'v5'",
]

LOW_OVERLAP_PREDICATES = [
    "net == 'on-premise' AND a1 == 'v1'",
    "net == 'on-premise' AND a2 == 'v2'",
    "a3 == 'v3' AND a4 == 'v4'",
    "a5 == 'v5' AND a6 == 'v6'",
    "a7 == 'v7'",
]

HIGH_OVERLAP_PREDICATES = [
    "net == 'on-premise' AND time == 'business-hours'",
    "(net == 'on-premise' AND time == 'business-hours') AND dept == 'engineering'",
    "(net == 'on-premise' AND time == 'business-hours') AND clearance == 'secret'",
    "(net == 'on-premise' AND time == 'business-hours') AND region == 'us'",
    "net == 'on-premise' AND time == 'business-hours' AND dept == 'engineering'",
]

EXTREME_OVERLAP_PREDICATES = [
    "net == 'on-premise' AND time == 'business-hours'",
    "net == 'on-premise' AND time == 'business-hours'",
    "net == 'on-premise' AND time == 'business-hours'",
    "net == 'on-premise' AND time == 'business-hours'",
    "net == 'on-premise' AND time == 'business-hours'",
]

PAPER_EXAMPLE_PREDICATES = [
    "a1 == 'on-premise' OR a2 == 'business-hours'",
    "(a1 == 'on-premise' OR a2 == 'business-hours') AND (a2 == 'business-hours' AND a3 == 'engineering')",
    "a2 == 'business-hours' AND a3 == 'engineering'",
    "(a2 == 'business-hours' AND a3 == 'engineering') AND a4 == 'top-secret'",
]


# ---------------------------------------------------------------------------
# Tests: verify sharing ratios meet expected thresholds
# ---------------------------------------------------------------------------

class TestSharingRatio:
    def test_no_overlap_ratio_is_one(self):
        """No shared atoms -> σ = 1.0 (no improvement)."""
        sigma = sharing_ratio(NO_OVERLAP_PREDICATES)
        assert sigma == pytest.approx(1.0, abs=0.01), (
            f"Expected σ ≈ 1.0 for no-overlap policies, got {sigma:.3f}"
        )

    def test_high_overlap_ratio_greater_than_one(self):
        """High overlap -> σ > 1 (sharing saves evaluations)."""
        sigma = sharing_ratio(HIGH_OVERLAP_PREDICATES)
        assert sigma > 1.0, (
            f"Expected σ > 1.0 for high-overlap policies, got {sigma:.3f}"
        )

    def test_extreme_overlap_ratio(self):
        """Identical predicates -> maximum sharing; σ = n (n copies, 1 set of nodes)."""
        n = len(EXTREME_OVERLAP_PREDICATES)
        sigma = sharing_ratio(EXTREME_OVERLAP_PREDICATES)
        assert sigma == pytest.approx(n, abs=0.01), (
            f"Expected σ ≈ {n} for identical predicates, got {sigma:.3f}"
        )

    def test_paper_example_ratio(self):
        """The 4-policy paper example: shared DAG (8 nodes) < naive (17 nodes).

        The project plan's '11 total attribute checks' refers to atom-only
        evaluation counts (leaf nodes), not total DAG nodes including gates.
        Naive total (including gates): P1=3, P2=6, P3=3, P4=5 = 17.
        Shared total: 8 nodes.
        σ = 17/8 = 2.125.
        """
        naive = _count_nodes_naive(PAPER_EXAMPLE_PREDICATES)
        shared = _count_nodes_shared(PAPER_EXAMPLE_PREDICATES)
        assert shared == 8, "Expected 8 nodes in shared DAG (hash consing gate)"
        assert naive == 17, (
            "Expected 17 naive nodes (P1:3 + P2:6 + P3:3 + P4:5), got " + str(naive)
        )
        sigma = naive / shared
        assert sigma > 2.0, "Expected σ > 2.0 for the paper example"


# ---------------------------------------------------------------------------
# Benchmarks using pytest-benchmark
# ---------------------------------------------------------------------------

def test_bench_no_overlap_build(benchmark):
    """Phase 1 build time: 5 non-overlapping ABAC predicates."""
    records = [
        ABACRecord(resource="pods", namespace="prod", action="get",
                   predicate=p)
        for p in NO_OVERLAP_PREDICATES
    ]
    benchmark(build_graph, records, "prod", "pods")


def test_bench_high_overlap_build(benchmark):
    """Phase 1 build time: 5 high-overlap ABAC predicates."""
    records = [
        ABACRecord(resource="pods", namespace="prod", action="get",
                   predicate=p)
        for p in HIGH_OVERLAP_PREDICATES
    ]
    benchmark(build_graph, records, "prod", "pods")


def test_bench_paper_example_build(benchmark):
    """Phase 1 build time: paper's P1-P4 predicates."""
    records = [
        ABACRecord(resource="pods", namespace="prod", action="get",
                   predicate=p)
        for p in PAPER_EXAMPLE_PREDICATES
    ]
    benchmark(build_graph, records, "prod", "pods")
