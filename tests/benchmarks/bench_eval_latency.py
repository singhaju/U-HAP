"""
Benchmark: Per-request evaluation latency.

Target: < 1ms per request for typical policies (< 50 rules per resource).

Measures the time to call evaluate_request() on a pre-built ArtifactRegistry with:
  - A simple registry (5 rules)
  - A medium registry (20 rules, multiple ABAC predicates with shared sub-expressions)
  - A complex registry (50 rules, deep hierarchy)

Uses pytest-benchmark for statistical measurement.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

import pytest
from dsl.models import RBACRecord, HierRecord, ABACRecord, ACLRecord, DenyRecord
from compiler.registry import ArtifactRegistry
from engine.evaluator import evaluate_request


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_registry(records):
    r = ArtifactRegistry()
    r.load(records)
    return r


# ---------------------------------------------------------------------------
# Fixtures: build test registries
# ---------------------------------------------------------------------------

def _make_simple_registry():
    """5 rules: ABAC + RBAC + ACL + hierarchy + deny."""
    records = [
        ABACRecord(resource="pods", namespace="prod", action="get",
                   predicate="net == 'on-premise' AND time == 'business-hours'"),
        RBACRecord(role="viewer", resource="pods", namespace="prod", action="get"),
        ACLRecord(subject="charlie", resource="pods", namespace="prod", action="get"),
        HierRecord(parent_role="senior", child_role="junior", namespace="prod"),
        DenyRecord(subject="*", resource="pods", namespace="prod", action="delete"),
    ]
    return _build_registry(records)


def _make_medium_registry():
    """20 rules: multiple ABAC predicates with shared sub-expressions."""
    base_attrs = ["net", "time", "dept", "clearance", "region"]
    base_vals  = ["on-premise", "business-hours", "engineering", "secret", "us"]
    records = []
    for i, (attr, val) in enumerate(zip(base_attrs, base_vals)):
        records.append(ABACRecord(
            resource="pods", namespace="prod", action="get",
            predicate=f"{attr} == '{val}'",
        ))
    # Compound predicates sharing sub-expressions
    records.append(ABACRecord(
        resource="pods", namespace="prod", action="get",
        predicate="net == 'on-premise' AND time == 'business-hours'",
    ))
    records.append(ABACRecord(
        resource="pods", namespace="prod", action="get",
        predicate="(net == 'on-premise' AND time == 'business-hours') AND dept == 'engineering'",
    ))
    # Role hierarchy
    for i in range(5):
        records.append(HierRecord(
            parent_role=f"role-{i}", child_role=f"role-{i+1}", namespace="prod"
        ))
    records.append(RBACRecord(
        role="role-5", resource="pods", namespace="prod", action="get"
    ))
    return _build_registry(records)


def _make_complex_registry():
    """50 rules: deep hierarchy + many ABAC predicates."""
    records = []
    # Deep hierarchy: 10 levels
    for i in range(10):
        records.append(HierRecord(
            parent_role=f"l{i}", child_role=f"l{i+1}", namespace="prod"
        ))
    records.append(RBACRecord(
        role="l10", resource="pods", namespace="prod", action="get"
    ))
    # Many ABAC rules
    for i in range(30):
        records.append(ABACRecord(
            resource="pods", namespace="prod", action="get",
            predicate=f"attr{i} == 'val{i}'",
        ))
    # Some compound predicates
    records.append(ABACRecord(
        resource="pods", namespace="prod", action="get",
        predicate="net == 'on-premise' AND time == 'business-hours'",
    ))
    records.append(ABACRecord(
        resource="pods", namespace="prod", action="delete",
        predicate="dept == 'admin' AND clearance == 'top-secret'",
    ))
    return _build_registry(records)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def simple_registry():
    return _make_simple_registry()


@pytest.fixture(scope="module")
def medium_registry():
    return _make_medium_registry()


@pytest.fixture(scope="module")
def complex_registry():
    return _make_complex_registry()


# ---------------------------------------------------------------------------
# Benchmarks
# ---------------------------------------------------------------------------

def test_bench_simple_allow(benchmark, simple_registry):
    """Latency: simple registry, RBAC allow path."""
    ctx = {"net": "remote", "time": "after-hours"}
    result = benchmark(evaluate_request, simple_registry, "prod", "pods", "get", "alice", ["viewer"], [], ctx)
    assert result[0] is True  # should be allowed via RBAC


def test_bench_simple_abac_allow(benchmark, simple_registry):
    """Latency: simple registry, ABAC allow path."""
    ctx = {"net": "on-premise", "time": "business-hours"}
    result = benchmark(evaluate_request, simple_registry, "prod", "pods", "get", "alice", [], [], ctx)
    assert result[0] is True


def test_bench_simple_deny(benchmark, simple_registry):
    """Latency: simple registry, deny path (wildcard delete)."""
    ctx = {"net": "on-premise", "time": "business-hours"}
    result = benchmark(evaluate_request, simple_registry, "prod", "pods", "delete", "alice", ["viewer"], [], ctx)
    assert result[0] is False


def test_bench_medium_hierarchy(benchmark, medium_registry):
    """Latency: medium registry, RBAC via 5-level hierarchy bit-vector."""
    ctx = {"net": "remote", "time": "after-hours"}
    result = benchmark(evaluate_request, medium_registry, "prod", "pods", "get", "alice", ["role-0"], [], ctx)
    assert result[0] is True


def test_bench_medium_abac(benchmark, medium_registry):
    """Latency: medium registry, ABAC shared DAG evaluation."""
    ctx = {"net": "on-premise", "time": "business-hours", "dept": "engineering"}
    result = benchmark(evaluate_request, medium_registry, "prod", "pods", "get", "alice", [], [], ctx)
    assert result[0] is True


def test_bench_complex_hierarchy(benchmark, complex_registry):
    """Latency: complex registry, 10-level hierarchy via bit-vector."""
    ctx = {}
    result = benchmark(evaluate_request, complex_registry, "prod", "pods", "get", "alice", ["l0"], [], ctx)
    assert result[0] is True


def test_bench_complex_abac_miss(benchmark, complex_registry):
    """Latency: complex registry, all ABAC predicates false (worst-case scan)."""
    ctx = {"net": "remote", "time": "after-hours"}
    result = benchmark(evaluate_request, complex_registry, "prod", "pods", "get", "alice", [], [], ctx)
    # Should hit default deny (no hierarchy role, no matching ABAC)
    assert result[0] is False


def test_bench_complex_default_deny(benchmark, complex_registry):
    """Latency: complex registry, subject has no role and no context match."""
    ctx = {}
    result = benchmark(evaluate_request, complex_registry, "prod", "pods", "delete", "unknown-user", [], [], ctx)
    assert result[0] is False
