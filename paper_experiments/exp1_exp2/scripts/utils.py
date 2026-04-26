"""Shared utilities for V3 experiments (U-HAP vs Traditional)."""
import csv
import time
from pathlib import Path
from typing import Dict, List

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

_SCRIPTS_DIR = Path(__file__).resolve().parent
_V3_DIR      = _SCRIPTS_DIR.parent
RESULTS_DIR  = _V3_DIR / "results"
PLOTS_DIR    = _V3_DIR / "plots"
TEST_DATA_DIR = _V3_DIR / "test_data"

RESULTS_DIR.mkdir(parents=True, exist_ok=True)
PLOTS_DIR.mkdir(parents=True, exist_ok=True)
TEST_DATA_DIR.mkdir(parents=True, exist_ok=True)

COLORS = {
    "uhap":        "#1f77b4",
    "traditional": "#d62728",
    "rbac":        "#1f77b4",
    "abac":        "#ff7f0e",
    "acl":         "#2ca02c",
}
MARKERS = {"uhap": "o", "traditional": "s"}
LINESTYLES = {"uhap": "-", "traditional": "--"}

WARMUP_ITERS = 50
TIMING_ITERS = 1000
RANDOM_SEED  = 42
GATE_MIX     = {"AND": 0.5, "OR": 0.3, "ATLEAST": 0.2}


def summarize(samples: np.ndarray) -> Dict:
    return {
        "median": float(np.median(samples)),
        "mean":   float(np.mean(samples)),
        "p95":    float(np.percentile(samples, 95)),
        "std":    float(np.std(samples)),
        "n":      len(samples),
    }


def write_csv(path: Path, rows: List[Dict], fieldnames: List[str]) -> None:
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"CSV  saved -> {path}")


def load_csv(path: Path) -> List[Dict]:
    if not path.exists():
        return []
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def apply_plot_style(ax, title: str, xlabel: str, ylabel: str) -> None:
    ax.set_title(title, fontsize=12, fontweight="bold")
    ax.set_xlabel(xlabel, fontsize=10)
    ax.set_ylabel(ylabel, fontsize=10)
    ax.legend(fontsize=9)
    ax.grid(True, alpha=0.3)
    ax.set_axisbelow(True)


def time_fn(fn, warmup: int = WARMUP_ITERS, iters: int = TIMING_ITERS) -> np.ndarray:
    """Warmup then time fn() for iters iterations. Returns array of ms values."""
    for _ in range(warmup):
        fn()
    samples = []
    for _ in range(iters):
        t0 = time.perf_counter_ns()
        fn()
        t1 = time.perf_counter_ns()
        samples.append((t1 - t0) / 1_000_000)
    return np.array(samples)
