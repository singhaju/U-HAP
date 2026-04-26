"""Regenerate fig2, fig3, fig4, and fig5 in full color."""
from __future__ import annotations

import csv
import statistics
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "figures"
OUT_DIR.mkdir(parents=True, exist_ok=True)

EXP_DIR = ROOT / "experiments" / "v3_traditional" / "results"
EXP5_CSV = Path(__file__).resolve().parent / "results" / "exp5_update_latency.csv"

plt.rcParams.update({
    "font.family":      "DejaVu Sans",
    "font.size":        13,
    "axes.titlesize":   16,
    "axes.titleweight": "bold",
    "axes.labelsize":   13,
    "axes.spines.top":   True,
    "axes.spines.right": True,
    "axes.edgecolor":   "#333",
    "axes.linewidth":   1.0,
    "axes.grid":        True,
    "grid.color":       "#dddddd",
    "grid.linestyle":   "-",
    "grid.linewidth":   0.6,
    "legend.frameon":   True,
    "legend.framealpha":0.9,
    "legend.edgecolor": "#aaaaaa",
    "legend.fontsize":  11,
    "lines.linewidth":  2.2,
    "lines.markersize": 8,
    "savefig.dpi":      200,
    "savefig.bbox":     "tight",
})

C_BLUE   = "#1f77b4"
C_ORANGE = "#ff7f0e"
C_GREEN  = "#2ca02c"
C_RED    = "#d62728"
C_PURPLE = "#9467bd"


def load_csv(path: Path) -> list[dict]:
    with path.open() as f:
        return list(csv.DictReader(f))


def fig2_namespace_isolation():
    rows = load_csv(EXP_DIR / "exp1a.csv")
    n_vals   = [int(r["n"])                            for r in rows]
    uhap_off = [float(r["uhap_off_median_ms"]) * 1000  for r in rows]
    uhap_on  = [float(r["uhap_on_median_ms"])  * 1000  for r in rows]
    trad     = [float(r["trad_median_ms"])     * 1000  for r in rows]

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.plot(n_vals, trad,
            color=C_RED,    marker="s", markerfacecolor="white",
            markeredgecolor=C_RED, markeredgewidth=1.8,
            linestyle="--", label="Traditional")
    ax.plot(n_vals, uhap_off,
            color=C_BLUE,   marker="o", linestyle="-",
            label="U-HAP (cache OFF)")
    ax.plot(n_vals, uhap_on,
            color=C_GREEN,  marker="^", linestyle="-.",
            label="U-HAP (cache ON)")

    ax.set_title("Per-Request Authorization Latency vs. System Size")
    ax.set_xlabel("Total Applications in System (N)")
    ax.set_ylabel("Median Latency (μs)")
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.14),
              ncol=3, frameon=True, framealpha=0.9,
              edgecolor="#aaaaaa", fontsize=10)
    ax.set_axisbelow(True)
    fig.tight_layout()

    out = OUT_DIR / "fig2_namespace_isolation.png"
    fig.savefig(out)
    print(f"wrote {out}")
    plt.close(fig)


def fig3_permodel_latency():
    rows   = load_csv(EXP_DIR / "exp2b.csv")
    k_vals = sorted({int(r["rule_count"]) for r in rows})

    style = {
        "rbac": dict(color=C_BLUE,   marker="o", label="RBAC"),
        "abac": dict(color=C_ORANGE, marker="s", label="ABAC"),
        "acl":  dict(color=C_GREEN,  marker="^", label="ACL"),
    }

    fig, ax = plt.subplots(figsize=(10, 6))

    for model, st in style.items():
        uhap_vals, trad_vals = [], []
        for k in k_vals:
            row = next(r for r in rows
                       if r["model"] == model and int(r["rule_count"]) == k)
            uhap_vals.append(float(row["uhap_median_ms"]) * 1000)
            trad_vals.append(float(row["trad_median_ms"]) * 1000)

        ax.plot(k_vals, trad_vals,
                color=st["color"], marker=st["marker"], linestyle=":",
                markerfacecolor="white", markeredgecolor=st["color"],
                markeredgewidth=1.8,
                label=f"{st['label']} — Traditional")
        ax.plot(k_vals, uhap_vals,
                color=st["color"], marker=st["marker"], linestyle="-",
                label=f"{st['label']} — U-HAP")

    ax.set_yscale("log")
    ax.set_xticks(k_vals)
    ax.set_xticklabels([str(k) for k in k_vals])
    ax.set_xlabel("Number of Rules (k)")
    ax.set_ylabel("Median Latency (μs) — log scale")
    ax.set_title("Per-Model Authorization Latency: U-HAP vs Traditional")
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.14),
              ncol=3, frameon=True, framealpha=0.9,
              edgecolor="#aaaaaa", fontsize=10)
    ax.set_axisbelow(True)
    fig.tight_layout()

    out = OUT_DIR / "fig3_permodel_latency.png"
    fig.savefig(out)
    print(f"wrote {out}")
    plt.close(fig)


def _exp5_rows():
    out = []
    for r in load_csv(EXP5_CSV):
        r["policy_count"] = int(r["policy_count"])
        for k in ("parse_ms", "compile_ms", "swap_ms",
                  "first_decision_ms", "post_parse_ms", "total_ms"):
            r[k] = float(r[k])
        out.append(r)
    return out


def _med(rows, system, n, field):
    xs = [r[field] for r in rows
          if r["system"] == system and r["policy_count"] == n]
    return statistics.median(xs) if xs else float("nan")


def fig5_update_latency():
    rows   = _exp5_rows()
    counts = sorted({r["policy_count"] for r in rows})

    uhap = [_med(rows, "uhap", n, "total_ms") for n in counts]
    opa  = [_med(rows, "opa",  n, "total_ms") for n in counts]

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.plot(counts, opa,
            color=C_RED,  marker="s", markerfacecolor="white",
            markeredgecolor=C_RED, markeredgewidth=1.8,
            linestyle="--", label="OPA (REST PUT)")
    ax.plot(counts, uhap,
            color=C_BLUE, marker="o", linestyle="-",
            label="U-HAP")

    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xticks(counts)
    ax.set_xticklabels([str(c) for c in counts])
    ax.set_xlabel("Number of Policies (n)")
    ax.set_ylabel("Update Latency (ms) — log scale")
    ax.set_title("End-to-End Policy Update Latency: U-HAP vs OPA")
    ax.legend(loc="upper left")
    ax.set_axisbelow(True)
    fig.tight_layout()

    out = OUT_DIR / "fig5_update_latency.png"
    fig.savefig(out)
    print(f"wrote {out}")
    plt.close(fig)


def fig5_breakdown():
    rows   = _exp5_rows()
    counts = sorted({r["policy_count"] for r in rows})

    series = [
        ([_med(rows, "uhap", n, "parse_ms")          for n in counts], "Parse",         C_BLUE),
        ([_med(rows, "uhap", n, "compile_ms")        for n in counts], "Compile",       C_ORANGE),
        ([_med(rows, "uhap", n, "swap_ms")           for n in counts], "Swap",          C_GREEN),
        ([_med(rows, "uhap", n, "first_decision_ms") for n in counts], "First Request", C_RED),
    ]

    fig, ax = plt.subplots(figsize=(10, 6))
    x      = list(range(len(counts)))
    bottom = [0.0] * len(counts)
    for vals, label, color in series:
        ax.bar(x, vals, bottom=bottom, label=label,
               color=color, edgecolor="white", linewidth=0.8, width=0.62)
        bottom = [b + v for b, v in zip(bottom, vals)]

    ax.set_xticks(x)
    ax.set_xticklabels([str(c) for c in counts])
    ax.set_xlabel("Number of Policies (n)")
    ax.set_ylabel("Time (ms)")
    ax.set_title("U-HAP Update-Latency Breakdown")
    ax.legend(loc="upper left", ncol=2)
    ax.grid(True, axis="y")
    ax.set_axisbelow(True)
    fig.tight_layout()

    out = OUT_DIR / "fig5_breakdown.png"
    fig.savefig(out)
    print(f"wrote {out}")
    plt.close(fig)


if __name__ == "__main__":
    fig2_namespace_isolation()
    fig3_permodel_latency()
    fig5_update_latency()
    fig5_breakdown()
