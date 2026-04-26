"""
run_exp2b.py — Experiment 2b: Rule Density — Isolated Per Model.

Goal: Show how each policy model scales independently.
Compare U-HAP's O(1) RBAC/ACL and hash-consed ABAC against traditional O(k) scanning.

What varies: k = rules of ONE model type.
What is timed: One authorization check per model.
Models: RBAC, ABAC, ACL (tested separately).
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
from generate_test_data import (
    app_data_to_uhap_yaml,
    generate_rbac_only_data,
    generate_abac_only_data,
    generate_acl_only_data,
)
from traditional_evaluator import (
    load_traditional_registry_from_exp2_data, traditional_evaluate,
)

from dsl.loader import load_yaml_string
from compiler.registry import ArtifactRegistry
from engine.evaluator import evaluate_request
from engine.context import build_context

K_VALUES = [5, 10, 20, 40, 80, 160, 320]
MODELS = ["rbac", "abac", "acl"]


def _load_uhap_registry(app_data: dict) -> ArtifactRegistry:
    yaml_str = app_data_to_uhap_yaml(app_data)
    records = load_yaml_string(yaml_str)
    registry = ArtifactRegistry()
    registry.load(records)
    return registry


def _time_pair(uhap_fn, trad_fn):
    """Time both systems and return (uhap_summary, trad_summary)."""
    for _ in range(WARMUP_ITERS):
        uhap_fn()
    uhap_samples = []
    for _ in range(TIMING_ITERS):
        t0 = time.perf_counter_ns()
        uhap_fn()
        t1 = time.perf_counter_ns()
        uhap_samples.append((t1 - t0) / 1_000_000)

    for _ in range(WARMUP_ITERS):
        trad_fn()
    trad_samples = []
    for _ in range(TIMING_ITERS):
        t0 = time.perf_counter_ns()
        trad_fn()
        t1 = time.perf_counter_ns()
        trad_samples.append((t1 - t0) / 1_000_000)

    return summarize(np.array(uhap_samples)), summarize(np.array(trad_samples))


def run_exp2b(rerun: bool = False):
    csv_path = RESULTS_DIR / "exp2b.csv"

    if not rerun and csv_path.exists():
        rows = load_csv(csv_path)
        print(f"[exp2b] Existing CSV found ({len(rows)} rows). Replotting only.")
        _plot_exp2b(rows)
        _plot_exp2b_subplots_logscale(rows)
        _plot_exp2b_combined(rows)
        _plot_exp2b_combined_bar_log(rows)
        return

    print("[exp2b] Running Experiment 2b: Per-Model Rule Density")
    print(f"        k values: {K_VALUES}, models: {MODELS}")

    rows = []
    for model in MODELS:
        for k in K_VALUES:
            print(f"  {model} k={k} ...", end=" ", flush=True)

            rng = random.Random(RANDOM_SEED)

            if model == "rbac":
                app_data = generate_rbac_only_data(k, rng)
            elif model == "abac":
                app_data = generate_abac_only_data(k, g=10, sharing_ratio=0.5, rng=rng)
            elif model == "acl":
                app_data = generate_acl_only_data(k, rng)
            else:
                raise ValueError(f"Unknown model: {model}")

            uhap_registry = _load_uhap_registry(app_data)
            trad_registry = load_traditional_registry_from_exp2_data(app_data, model)

            tr = app_data["test_request"]
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

            # Verify correctness
            u_result, u_reason = evaluate_request(
                uhap_registry, ns, resource, action, uid, roles, groups, context, cache=None
            )
            t_result, t_reason = traditional_evaluate(
                trad_registry, ns, resource, action, uid, roles, groups, context
            )
            if not u_result:
                print(f"\n  WARNING: U-HAP returned DENY ({model} k={k}): {u_reason}")
            if not t_result:
                print(f"\n  WARNING: Traditional returned DENY ({model} k={k}): {t_reason}")

            def uhap_fn():
                evaluate_request(
                    uhap_registry, ns, resource, action, uid, roles, groups, context, cache=None
                )

            def trad_fn():
                traditional_evaluate(
                    trad_registry, ns, resource, action, uid, roles, groups, context
                )

            u, t = _time_pair(uhap_fn, trad_fn)
            speedup = t["median"] / u["median"] if u["median"] > 0 else float("inf")
            print(f"U-HAP={u['median']:.4f}ms, Trad={t['median']:.4f}ms, speedup={speedup:.1f}x")

            rows.append({
                "model": model,
                "rule_count": k,
                "uhap_median_ms": u["median"],
                "uhap_p95_ms": u["p95"],
                "uhap_n": u["n"],
                "trad_median_ms": t["median"],
                "trad_p95_ms": t["p95"],
                "trad_n": t["n"],
                "speedup": speedup,
            })

    fieldnames = [
        "model", "rule_count",
        "uhap_median_ms", "uhap_p95_ms", "uhap_n",
        "trad_median_ms", "trad_p95_ms", "trad_n",
        "speedup",
    ]
    write_csv(csv_path, rows, fieldnames)
    _plot_exp2b(rows)
    _plot_exp2b_subplots_logscale(rows)
    _plot_exp2b_combined(rows)

    print("\n[exp2b] Summary:")
    print(f"  {'Model':>6}  {'k':>6}  {'U-HAP (ms)':>12}  {'Trad (ms)':>12}  {'Speedup':>8}")
    for row in rows:
        print(f"  {row['model']:>6}  {int(row['rule_count']):>6}  "
              f"{float(row['uhap_median_ms']):>12.4f}  {float(row['trad_median_ms']):>12.4f}  "
              f"{float(row['speedup']):>8.1f}x")


def _plot_exp2b(rows):
    """Grouped bar chart: 6 bars per k value (RBAC-U-HAP, RBAC-Trad, ABAC-U-HAP, ...)."""
    k_vals = sorted(set(int(r["rule_count"]) for r in rows))
    n_k = len(k_vals)
    k_idx = {k: i for i, k in enumerate(k_vals)}

    models = ["rbac", "abac", "acl"]
    model_colors = {
        "rbac": COLORS["rbac"],
        "abac": COLORS["abac"],
        "acl": COLORS["acl"],
    }

    # Organize data
    data = {model: {"uhap": [0.0] * n_k, "trad": [0.0] * n_k} for model in models}
    for row in rows:
        m = row["model"]
        ki = k_idx[int(row["rule_count"])]
        data[m]["uhap"][ki] = float(row["uhap_median_ms"])
        data[m]["trad"][ki] = float(row["trad_median_ms"])

    fig, ax = plt.subplots(figsize=(14, 6))

    n_groups = n_k
    n_bars = len(models) * 2  # RBAC-U-HAP, RBAC-Trad, ABAC-U-HAP, ABAC-Trad, ACL-U-HAP, ACL-Trad
    bar_width = 0.12
    group_width = n_bars * bar_width + 0.1

    x = np.arange(n_groups) * group_width

    bar_pos = 0
    legend_handles = []
    for model in models:
        color = model_colors[model]

        # U-HAP bar (solid)
        offset_uhap = (bar_pos - n_bars / 2 + 0.5) * bar_width
        bars_uhap = ax.bar(
            x + offset_uhap,
            data[model]["uhap"],
            bar_width,
            color=color,
            alpha=0.9,
            label=f"{model.upper()}-U-HAP",
        )
        legend_handles.append(bars_uhap)
        bar_pos += 1

        # Traditional bar (hatched)
        offset_trad = (bar_pos - n_bars / 2 + 0.5) * bar_width
        bars_trad = ax.bar(
            x + offset_trad,
            data[model]["trad"],
            bar_width,
            color=color,
            alpha=0.5,
            hatch="///",
            label=f"{model.upper()}-Traditional",
        )
        legend_handles.append(bars_trad)
        bar_pos += 1

    ax.set_xticks(x)
    ax.set_xticklabels([str(k) for k in k_vals])

    apply_plot_style(
        ax,
        title="Experiment 2b: Per-Model Rule Density — U-HAP vs Traditional",
        xlabel="Number of Rules (k)",
        ylabel="Median Latency (ms)",
    )

    plot_path = PLOTS_DIR / "exp2b_isolated_density.png"
    fig.savefig(plot_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"Plot saved -> {plot_path}")


def _plot_exp2b_combined(rows):
    """All 6 lines (3 models × 2 systems) on one log-scale graph.
    Same color per access-control model; U-HAP = solid line, Traditional = dotted line.
    Same marker per model; filled for U-HAP, open for Traditional.
    """
    k_vals = sorted(set(int(r["rule_count"]) for r in rows))

    # One color per model
    palette = {
        "rbac": "#c0392b",   # red
        "abac": "#1a5276",   # blue
        "acl":  "#1e8449",   # green
    }
    model_markers = {"rbac": "o", "abac": "s", "acl": "^"}
    model_labels = {"rbac": "RBAC", "abac": "ABAC", "acl": "ACL"}

    fig, ax = plt.subplots(figsize=(10, 6))

    for model in ["rbac", "abac", "acl"]:
        color = palette[model]
        marker = model_markers[model]
        uhap_vals, trad_vals = [], []
        for k in k_vals:
            row = next(r for r in rows if r["model"] == model and int(r["rule_count"]) == k)
            uhap_vals.append(float(row["uhap_median_ms"]) * 1000)
            trad_vals.append(float(row["trad_median_ms"]) * 1000)

        # Traditional: dotted line, open markers
        ax.plot(k_vals, trad_vals, color=color, marker=marker, linestyle=":",
                linewidth=2.0, markersize=8, markerfacecolor="white", markeredgecolor=color,
                markeredgewidth=1.5, label=f"{model_labels[model]} — Traditional")
        # U-HAP: solid line, filled markers
        ax.plot(k_vals, uhap_vals, color=color, marker=marker, linestyle="-",
                linewidth=2.0, markersize=8, label=f"{model_labels[model]} — U-HAP")

    ax.set_yscale("log")
    ax.set_xticks(k_vals)
    ax.set_xticklabels([str(k) for k in k_vals])
    ax.set_xlabel("Number of Rules (k)", fontsize=11)
    ax.set_ylabel("Median Latency (μs) — log scale", fontsize=11)
    ax.set_title(
        "Experiment 2b: Per-Model Authorization Latency\nU-HAP vs Traditional (Log Scale)",
        fontsize=13, fontweight="bold",
    )
    ax.legend(fontsize=9, ncol=2, loc="upper left")
    ax.grid(True, which="both", alpha=0.3)
    ax.set_axisbelow(True)

    fig.tight_layout()
    plot_path = PLOTS_DIR / "exp2b_combined_logscale.png"
    fig.savefig(plot_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"Plot saved -> {plot_path}")


def _plot_exp2b_combined_bar_log(rows):
    """Grouped bar chart, log scale, 6 colors (dark=Traditional, light=U-HAP per model)."""
    k_vals = sorted(set(int(r["rule_count"]) for r in rows))
    models = ["rbac", "abac", "acl"]
    model_labels = {"rbac": "RBAC", "abac": "ABAC", "acl": "ACL"}
    palette = {
        "rbac": ("#c0392b", "#f1948a"),
        "abac": ("#1a5276", "#5dade2"),
        "acl":  ("#1e8449", "#58d68d"),
    }

    n_k = len(k_vals)
    n_bars = len(models) * 2   # 6 bars per group
    bar_width = 0.12
    group_spacing = 0.10
    group_width = n_bars * bar_width + group_spacing
    x = np.arange(n_k) * group_width

    fig, ax = plt.subplots(figsize=(14, 6))

    offsets = [(i - n_bars / 2 + 0.5) * bar_width for i in range(n_bars)]
    bar_idx = 0
    for model in models:
        trad_color, uhap_color = palette[model]
        trad_vals, uhap_vals = [], []
        for k in k_vals:
            row = next(r for r in rows if r["model"] == model and int(r["rule_count"]) == k)
            trad_vals.append(float(row["trad_median_ms"]) * 1000)
            uhap_vals.append(float(row["uhap_median_ms"]) * 1000)

        ax.bar(x + offsets[bar_idx], trad_vals, bar_width,
               color=trad_color, label=f"{model_labels[model]} — Traditional")
        bar_idx += 1
        ax.bar(x + offsets[bar_idx], uhap_vals, bar_width,
               color=uhap_color, label=f"{model_labels[model]} — U-HAP")
        bar_idx += 1

    ax.set_yscale("log")
    ax.set_xticks(x)
    ax.set_xticklabels([str(k) for k in k_vals])
    ax.set_xlabel("Number of Rules (k)", fontsize=11)
    ax.set_ylabel("Median Latency (μs) — log scale", fontsize=11)
    ax.set_title(
        "Experiment 2b: Per-Model Authorization Latency (Bar, Log Scale)\n"
        "U-HAP vs Traditional Sequential Evaluator",
        fontsize=13, fontweight="bold",
    )
    ax.legend(fontsize=9, ncol=3, loc="upper left")
    ax.grid(True, which="both", axis="y", alpha=0.3)
    ax.set_axisbelow(True)

    fig.tight_layout()
    plot_path = PLOTS_DIR / "exp2b_combined_bar_logscale.png"
    fig.savefig(plot_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"Plot saved -> {plot_path}")


def _plot_exp2b_subplots_logscale(rows):
    """3-subplot log-scale line plot: one subplot per model (RBAC, ABAC, ACL).
    - Y-axis in microseconds (μs), log scale
    - Value annotations: no box, larger font, μs unit
    - Speedup annotation on each U-HAP point
    """
    k_vals = sorted(set(int(r["rule_count"]) for r in rows))
    models = ["rbac", "abac", "acl"]
    model_labels = {"rbac": "RBAC", "abac": "ABAC", "acl": "ACL"}
    model_colors = {
        "rbac": COLORS.get("rbac", "#e74c3c"),
        "abac": COLORS.get("abac", "#2980b9"),
        "acl": COLORS.get("acl", "#27ae60"),
    }

    # Organize data (convert ms → μs)
    data = {m: {"uhap": [], "trad": [], "speedup": []} for m in models}
    for m in models:
        for k in k_vals:
            row = next(r for r in rows if r["model"] == m and int(r["rule_count"]) == k)
            uhap_us = float(row["uhap_median_ms"]) * 1000
            trad_us = float(row["trad_median_ms"]) * 1000
            data[m]["uhap"].append(uhap_us)
            data[m]["trad"].append(trad_us)
            data[m]["speedup"].append(float(row["speedup"]))

    fig, axes = plt.subplots(1, 3, figsize=(16, 6))

    for ax, model in zip(axes, models):
        uhap_vals = data[model]["uhap"]
        trad_vals = data[model]["trad"]
        speedups = data[model]["speedup"]
        color = model_colors[model]

        ax.plot(
            k_vals, trad_vals,
            color=COLORS.get("traditional", "#c0392b"),
            marker="s", linestyle="--", linewidth=2.0, label="Traditional",
        )
        ax.plot(
            k_vals, uhap_vals,
            color=color,
            marker="o", linestyle="-", linewidth=2.0, label="U-HAP",
        )

        ax.set_yscale("log")

        # Annotate U-HAP points: latency + speedup, no box, bigger font
        for k, yu, sp in zip(k_vals, uhap_vals, speedups):
            if model == "rbac":
                # U-HAP is slower — show speedup as fraction
                label = f"{yu:.1f} μs\n({sp:.2f}×)"
            else:
                label = f"{yu:.1f} μs\n({sp:.1f}×)"
            ax.annotate(
                label,
                xy=(k, yu),
                xytext=(0, 14),
                textcoords="offset points",
                ha="center",
                fontsize=9,
                color=color,
                fontweight="bold",
            )

        # Annotate Traditional points: latency only, no box
        for k, yt in zip(k_vals, trad_vals):
            ax.annotate(
                f"{yt:.1f} μs",
                xy=(k, yt),
                xytext=(0, -18),
                textcoords="offset points",
                ha="center",
                fontsize=9,
                color=COLORS.get("traditional", "#c0392b"),
            )

        ax.set_title(f"{model_labels[model]}-Only Workload", fontsize=12, fontweight="bold")
        ax.set_xlabel("Number of Rules (k)", fontsize=10)
        ax.set_ylabel("Median Latency (μs) — log scale", fontsize=10)
        ax.set_xticks(k_vals)
        ax.legend(fontsize=9, loc="upper left")
        ax.grid(True, which="both", alpha=0.3)
        ax.set_axisbelow(True)

    fig.suptitle(
        "Experiment 2b: Per-Model Authorization Latency (Log Scale)\n"
        "U-HAP vs Traditional Sequential Evaluator",
        fontsize=13, fontweight="bold",
    )
    fig.tight_layout()

    plot_path = PLOTS_DIR / "exp2b_subplots_logscale.png"
    fig.savefig(plot_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"Plot saved -> {plot_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Experiment 2b: Per-Model Rule Density")
    parser.add_argument("--rerun", action="store_true", help="Force rerun even if CSV exists")
    parser.add_argument("--logscale", action="store_true", help="Generate logscale subplot plot only")
    args = parser.parse_args()

    if args.logscale:
        csv_path = RESULTS_DIR / "exp2b.csv"
        rows = load_csv(csv_path)
        _plot_exp2b_subplots_logscale(rows)
    else:
        run_exp2b(rerun=args.rerun)
