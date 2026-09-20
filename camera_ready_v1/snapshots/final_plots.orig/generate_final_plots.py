"""
Generate paper-ready plots for Deliverable 15.
Titles match IEEE figure captions (no experiment IDs like 1a/2b).
Output: final_plots/fig2_namespace_isolation.png, fig3_permodel_latency.png
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "experiments" / "v3_traditional" / "scripts"))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from utils import load_csv, COLORS

RESULTS_DIR = _ROOT / "experiments" / "v3_traditional" / "results"
OUT_DIR = Path(__file__).resolve().parent


def generate_fig2():
    """Fig 2: Namespace isolation — fixed workload, growing system."""
    rows = load_csv(RESULTS_DIR / "exp1a.csv")

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

    ax.set_title("Per-Request Authorization Latency vs. System Size",
                 fontsize=13, fontweight="bold")
    ax.set_xlabel("Total Applications in System (N)", fontsize=11)
    ax.set_ylabel("Median Latency (μs)", fontsize=11)
    ax.legend(fontsize=10)
    ax.grid(True, alpha=0.3)
    ax.set_axisbelow(True)

    fig.tight_layout()
    path = OUT_DIR / "fig2_namespace_isolation.png"
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved -> {path}")


def generate_fig3():
    """Fig 3: Per-model authorization latency (combined, log scale).
    Same color per model; U-HAP = solid line, Traditional = dotted line.
    """
    rows = load_csv(RESULTS_DIR / "exp2b.csv")
    k_vals = sorted(set(int(r["rule_count"]) for r in rows))

    palette = {
        "rbac": "#c0392b",  # red
        "abac": "#1a5276",  # blue
        "acl":  "#1e8449",  # green
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
            uhap_vals.append(float(row["uhap_median_ms"]) * 1000)  # ms → μs
            trad_vals.append(float(row["trad_median_ms"]) * 1000)

        # Traditional: dotted line, open markers
        ax.plot(k_vals, trad_vals, color=color, marker=marker, linestyle=":",
                linewidth=2.0, markersize=8, markerfacecolor="white",
                markeredgecolor=color, markeredgewidth=1.5,
                label=f"{model_labels[model]} — Traditional")
        # U-HAP: solid line, filled markers
        ax.plot(k_vals, uhap_vals, color=color, marker=marker, linestyle="-",
                linewidth=2.0, markersize=8,
                label=f"{model_labels[model]} — U-HAP")

    ax.set_yscale("log")
    ax.set_xticks(k_vals)
    ax.set_xticklabels([str(k) for k in k_vals])
    ax.set_xlabel("Number of Rules (k)", fontsize=11)
    ax.set_ylabel("Median Latency (μs) — log scale", fontsize=11)
    ax.set_title("Per-Model Authorization Latency: U-HAP vs Traditional",
                 fontsize=13, fontweight="bold")
    ax.legend(fontsize=9, ncol=2, loc="upper left")
    ax.grid(True, which="both", alpha=0.3)
    ax.set_axisbelow(True)

    fig.tight_layout()
    path = OUT_DIR / "fig3_permodel_latency.png"
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved -> {path}")


if __name__ == "__main__":
    generate_fig2()
    generate_fig3()
    print("Done — copy final_plots/*.png into your Overleaf figures/ folder.")
