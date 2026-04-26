"""
run_exp1a.py — Experiment 1a: Fixed Workload Authorization, Growing System.

Goal: Show that U-HAP's O(1) artifact lookup means adding more apps to the
system does not slow down authorization of a fixed workload.

What varies: N = total applications in the system.
What is timed: Authorizing ONE test request against ONE fixed app (app_0).
Three lines: Traditional, U-HAP (cache OFF), U-HAP (cache ON / warm).

Expected result: All three lines approximately flat (both index by namespace).
U-HAP cache OFF < Traditional; U-HAP cache ON << both.
"""
import argparse
import random
import sys
import time
from pathlib import Path

import numpy as np

_SCRIPTS_DIR = Path(__file__).resolve().parent
_V3_DIR = _SCRIPTS_DIR.parent
_ROOT = _V3_DIR.parent.parent
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_SCRIPTS_DIR))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from utils import (
    RESULTS_DIR, PLOTS_DIR, RANDOM_SEED, WARMUP_ITERS, TIMING_ITERS,
    summarize, write_csv, load_csv, apply_plot_style, COLORS, MARKERS, LINESTYLES,
)
from generate_test_data import generate_app_data, app_data_to_uhap_yaml
from traditional_evaluator import (
    load_traditional_registry_from_app_data_list, traditional_evaluate,
)

from dsl.loader import load_yaml_string
from compiler.registry import ArtifactRegistry
from engine.evaluator import evaluate_request
from engine.context import build_context
from engine.cache import DecisionCache

N_VALUES = [10, 50, 100, 200, 300, 500, 750, 1000]


def _build_registries(n: int, rng: random.Random):
    """Generate N apps and load into both registries."""
    apps_data = [generate_app_data(i, rng) for i in range(n)]

    # U-HAP registry
    all_yaml_parts = [app_data_to_uhap_yaml(app) for app in apps_data]
    combined_yaml = "\n".join(all_yaml_parts)
    records = load_yaml_string(combined_yaml)
    uhap_registry = ArtifactRegistry()
    uhap_registry.load(records)

    # Traditional registry
    trad_registry = load_traditional_registry_from_app_data_list(apps_data)

    return uhap_registry, trad_registry, apps_data


def run_exp1a(rerun: bool = False):
    csv_path = RESULTS_DIR / "exp1a.csv"

    if not rerun and csv_path.exists():
        rows = load_csv(csv_path)
        print(f"[exp1a] Existing CSV found ({len(rows)} rows). Replotting only.")
        _plot_exp1a(rows)
        return

    print("[exp1a] Running Experiment 1a: Fixed Workload, Growing System")
    print(f"        N values: {N_VALUES}")
    print(f"        Warmup: {WARMUP_ITERS}, Timing: {TIMING_ITERS}")

    rows = []
    for n in N_VALUES:
        print(f"  N={n} ...", end=" ", flush=True)

        rng = random.Random(RANDOM_SEED)
        uhap_registry, trad_registry, apps_data = _build_registries(n, rng)

        # Test request is always for app_0
        tr = apps_data[0]["test_request"]
        context = build_context(
            source_ip="10.0.1.5",
            utc_hour=10,
            token_attrs=tr.get("context_attrs", {}),
        )
        ns = tr["namespace"]
        resource = tr["resource"]
        action = tr["verb"]
        uid = tr["user"]
        roles = tr.get("roles", [])
        groups = tr.get("groups", [])

        # Verify all return ALLOW
        u_result, _ = evaluate_request(
            uhap_registry, ns, resource, action, uid, roles, groups, context, cache=None
        )
        t_result, _ = traditional_evaluate(
            trad_registry, ns, resource, action, uid, roles, groups, context
        )
        if not u_result:
            print(f"\n  WARNING: U-HAP returned DENY for app_0")
        if not t_result:
            print(f"\n  WARNING: Traditional returned DENY for app_0")

        # --- Time U-HAP (cache OFF) ---
        def uhap_no_cache():
            evaluate_request(
                uhap_registry, ns, resource, action, uid, roles, groups, context,
                cache=None,
            )

        for _ in range(WARMUP_ITERS):
            uhap_no_cache()
        uhap_off_samples = []
        for _ in range(TIMING_ITERS):
            t0 = time.perf_counter_ns()
            uhap_no_cache()
            t1 = time.perf_counter_ns()
            uhap_off_samples.append((t1 - t0) / 1_000_000)

        # --- Time U-HAP (cache ON — warm hits) ---
        # Populate cache once, then all timing iterations are cache hits
        warm_cache = DecisionCache()
        evaluate_request(
            uhap_registry, ns, resource, action, uid, roles, groups, context,
            cache=warm_cache,
        )
        # Warmup cache-hit path
        for _ in range(WARMUP_ITERS):
            evaluate_request(
                uhap_registry, ns, resource, action, uid, roles, groups, context,
                cache=warm_cache,
            )
        uhap_on_samples = []
        for _ in range(TIMING_ITERS):
            t0 = time.perf_counter_ns()
            evaluate_request(
                uhap_registry, ns, resource, action, uid, roles, groups, context,
                cache=warm_cache,
            )
            t1 = time.perf_counter_ns()
            uhap_on_samples.append((t1 - t0) / 1_000_000)

        # --- Time Traditional ---
        def trad_fn():
            traditional_evaluate(
                trad_registry, ns, resource, action, uid, roles, groups, context
            )

        for _ in range(WARMUP_ITERS):
            trad_fn()
        trad_samples = []
        for _ in range(TIMING_ITERS):
            t0 = time.perf_counter_ns()
            trad_fn()
            t1 = time.perf_counter_ns()
            trad_samples.append((t1 - t0) / 1_000_000)

        u_off = summarize(np.array(uhap_off_samples))
        u_on = summarize(np.array(uhap_on_samples))
        t = summarize(np.array(trad_samples))

        sp_off = t["median"] / u_off["median"] if u_off["median"] > 0 else float("inf")
        sp_on = t["median"] / u_on["median"] if u_on["median"] > 0 else float("inf")

        print(f"U-HAP(off)={u_off['median']:.4f}ms, U-HAP(on)={u_on['median']:.4f}ms, "
              f"Trad={t['median']:.4f}ms, speedup(off)={sp_off:.1f}x, speedup(on)={sp_on:.1f}x")

        rows.append({
            "n": n,
            "uhap_off_median_ms": u_off["median"],
            "uhap_off_p95_ms": u_off["p95"],
            "uhap_off_mean_ms": u_off["mean"],
            "uhap_off_n": u_off["n"],
            "uhap_on_median_ms": u_on["median"],
            "uhap_on_p95_ms": u_on["p95"],
            "uhap_on_mean_ms": u_on["mean"],
            "uhap_on_n": u_on["n"],
            "trad_median_ms": t["median"],
            "trad_p95_ms": t["p95"],
            "trad_mean_ms": t["mean"],
            "trad_n": t["n"],
            "speedup_off": sp_off,
            "speedup_on": sp_on,
        })

    fieldnames = [
        "n",
        "uhap_off_median_ms", "uhap_off_p95_ms", "uhap_off_mean_ms", "uhap_off_n",
        "uhap_on_median_ms", "uhap_on_p95_ms", "uhap_on_mean_ms", "uhap_on_n",
        "trad_median_ms", "trad_p95_ms", "trad_mean_ms", "trad_n",
        "speedup_off", "speedup_on",
    ]
    write_csv(csv_path, rows, fieldnames)
    _plot_exp1a(rows)

    # Summary
    print("\n[exp1a] Summary:")
    print(f"  {'N':>6}  {'U-HAP off (ms)':>14}  {'U-HAP on (ms)':>14}  "
          f"{'Trad (ms)':>12}  {'Sp(off)':>8}  {'Sp(on)':>8}")
    for row in rows:
        print(f"  {int(row['n']):>6}  {float(row['uhap_off_median_ms']):>14.4f}  "
              f"{float(row['uhap_on_median_ms']):>14.4f}  "
              f"{float(row['trad_median_ms']):>12.4f}  "
              f"{float(row['speedup_off']):>8.1f}x  {float(row['speedup_on']):>8.1f}x")


def _plot_exp1a(rows):
    n_vals = [int(r["n"]) for r in rows]
    uhap_off = [float(r["uhap_off_median_ms"]) * 1000 for r in rows]  # ms → μs
    uhap_on = [float(r["uhap_on_median_ms"]) * 1000 for r in rows]
    trad_med = [float(r["trad_median_ms"]) * 1000 for r in rows]

    fig, ax = plt.subplots(figsize=(10, 6))

    ax.plot(n_vals, trad_med,
            color=COLORS["traditional"], marker="s",
            linestyle="--", linewidth=2, label="Traditional")
    ax.plot(n_vals, uhap_off,
            color=COLORS["uhap"], marker="o",
            linestyle="-", linewidth=2, label="U-HAP (cache OFF)")
    ax.plot(n_vals, uhap_on,
            color="#2ca02c", marker="^",
            linestyle="-.", linewidth=2, label="U-HAP (cache ON)")

    apply_plot_style(
        ax,
        title="Experiment 1a: Fixed Workload Authorization — Growing System",
        xlabel="Total Applications in System (N)",
        ylabel="Median Latency (μs)",
    )

    plot_path = PLOTS_DIR / "exp1a_fixed_workload.png"
    fig.savefig(plot_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"Plot saved -> {plot_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Experiment 1a: Fixed Workload, Growing System")
    parser.add_argument("--rerun", action="store_true", help="Force rerun even if CSV exists")
    args = parser.parse_args()
    run_exp1a(rerun=args.rerun)
