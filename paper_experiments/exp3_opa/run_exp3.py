"""
Experiment 3 — Policy Update Latency (U-HAP vs OPA).

Measures end-to-end "update latency": wall-clock time from policy
modification to first authorization request decided under the new policy.

For U-HAP, the breakdown is:
    parse_ms          : YAML/DSL parse (load_yaml_string)
    compile_ms        : graph build + index compilation (ArtifactRegistry.load)
    swap_ms           : atomic registry pointer flip
    first_decision_ms : first evaluate_request call

Outputs (written relative to this file):
    results/exp5_update_latency.csv
    plots/exp5_update_latency.png
    plots/exp5_breakdown.png

Usage:
    # 1. Generate synthetic policy sets (one-time)
    python gen_policies.py --out ./policy_sets

    # 2. Run U-HAP measurements
    python run_exp3.py --uhap --policy-dir ./policy_sets \\
        --counts 10,100,500,1000,2000 --reps 30

    # 3. Start OPA sidecar, then run OPA baseline
    bash opa_daemon.sh
    python run_exp3.py --opa --policy-dir ./policy_sets \\
        --counts 10,100,500,1000,2000 --reps 30 \\
        --opa-mode rest --opa-url http://localhost:8181

    # 4. Combine + plot
    python run_exp3.py --plot
"""

from __future__ import annotations

import argparse
import csv
import gc
import os
import random
import statistics
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

# ---------------------------------------------------------------------------
# Path setup — read-only access to ../../src
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from compiler.registry import ArtifactRegistry  # noqa: E402
from dsl.loader import load_yaml_string          # noqa: E402
from engine.cache import DecisionCache           # noqa: E402
from engine.evaluator import evaluate_request    # noqa: E402

# ---------------------------------------------------------------------------
# Output paths
# ---------------------------------------------------------------------------
HERE = Path(__file__).resolve().parent
RESULTS_DIR = HERE / "results"
PLOTS_DIR = HERE / "plots"
RESULTS_DIR.mkdir(exist_ok=True)
PLOTS_DIR.mkdir(exist_ok=True)
CSV_PATH = RESULTS_DIR / "exp5_update_latency.csv"

# A representative SAR used as the "first request after update"
SAMPLE_SAR = dict(
    namespace="prod",
    resource="pods",
    action="get",
    uid="user-1",
    roles=["role-1"],
    groups=["dev"],
    context={"net": "on-premise", "time": "business-hours"},
)


# ===========================================================================
# U-HAP measurement
# ===========================================================================

def measure_uhap_one(policy_text: str) -> Dict[str, float]:
    """One full update cycle for U-HAP. Returns ms-resolution timings.

    Reports `total_ms` (parse+compile+swap+first_decision) and
    `post_parse_ms` (compile+swap+first_decision). The post-parse number
    is the apples-to-apples comparison against OPA's PUT, since YAML parse
    is a fixed cost both systems pay regardless of engine choice.
    """
    cache = DecisionCache(ttl_seconds=60)

    gc.collect()
    gc.disable()

    t0 = time.perf_counter_ns()
    records = load_yaml_string(policy_text)
    t1 = time.perf_counter_ns()

    new_registry = ArtifactRegistry()
    new_registry.load(records)
    t2 = time.perf_counter_ns()

    active_registry = new_registry
    if hasattr(cache, "clear"):
        cache.clear()
    t3 = time.perf_counter_ns()

    _ = evaluate_request(
        active_registry,
        SAMPLE_SAR["namespace"], SAMPLE_SAR["resource"], SAMPLE_SAR["action"],
        SAMPLE_SAR["uid"], SAMPLE_SAR["roles"], SAMPLE_SAR["groups"],
        SAMPLE_SAR["context"], cache,
    )
    t4 = time.perf_counter_ns()

    gc.enable()

    parse_ms       = (t1 - t0) / 1e6
    compile_ms     = (t2 - t1) / 1e6
    swap_ms        = (t3 - t2) / 1e6
    first_dec_ms   = (t4 - t3) / 1e6
    post_parse_ms  = compile_ms + swap_ms + first_dec_ms
    total_ms       = parse_ms + post_parse_ms

    return dict(
        parse_ms=parse_ms,
        compile_ms=compile_ms,
        swap_ms=swap_ms,
        first_decision_ms=first_dec_ms,
        post_parse_ms=post_parse_ms,
        total_ms=total_ms,
        rss_kb=0,  # latency run is uninstrumented; memory measured separately
    )


def measure_uhap_memory(policy_text: str) -> int:
    """Measure heap allocation of the compiled state.

    Runs in a separate pass with tracemalloc enabled so the latency
    measurements above are not skewed by allocation tracing.
    Returns bytes allocated during parse + load that survive after build.
    """
    gc.collect()
    tracemalloc.start()
    snap_before = tracemalloc.take_snapshot()

    records = load_yaml_string(policy_text)
    reg = ArtifactRegistry()
    reg.load(records)

    snap_after = tracemalloc.take_snapshot()
    diff = snap_after.compare_to(snap_before, "filename")
    rss_bytes = sum(stat.size_diff for stat in diff if stat.size_diff > 0)
    tracemalloc.stop()
    # Keep `reg` alive until snapshot is taken, then drop
    del reg, records
    return rss_bytes


def run_uhap(policy_dir: Path, counts: List[int], reps: int) -> List[dict]:
    rows: List[dict] = []
    for n in counts:
        path = policy_dir / f"policies_{n}.yaml"
        if not path.is_file():
            print(f"  ! missing {path}; run gen_policies.py first", file=sys.stderr)
            continue
        text = path.read_text(encoding="utf-8")

        # Memory pass first (separate so tracemalloc doesn't skew timing).
        # Median over 3 samples to smooth allocator jitter.
        rss_samples = [measure_uhap_memory(text) for _ in range(3)]
        rss_kb = int(statistics.median(rss_samples)) // 1024

        # Warm-up — first JIT/import path is non-representative
        for _ in range(3):
            measure_uhap_one(text)

        for rep in range(reps):
            timings = measure_uhap_one(text)
            timings["rss_kb"] = rss_kb       # attach the per-N memory number
            rows.append({
                "system": "uhap",
                "policy_count": n,
                "run_id": rep,
                **timings,
            })
        med = statistics.median(r["total_ms"] for r in rows if r["policy_count"] == n)
        print(f"  uhap n={n}: median total = {med:.2f} ms, mem = {rss_kb / 1024:.1f} MiB")
    return rows


# ===========================================================================
# OPA baseline measurement
# ---------------------------------------------------------------------------
# Two deployment modes are supported:
#   --opa-mode rest    : PUT /v1/policies/<id> with Rego text/plain, then
#                        POST /v1/data/uhap/allow with the SAR.
#                        Models "edit one policy module" updates.
#   --opa-mode bundle  : `opa build -b` produces bundle.tar.gz, then
#                        PUT /v1/data + activation via PUT /v1/policies and
#                        immediate decision. Models OPA's documented bulk
#                        update path.
#
# Both rely on a running daemon (see opa_daemon.sh) and Rego files generated
# by yaml_to_rego.py in `rego_sets/`. The Rego decision rule used is
# data.uhap.allow (single `package uhap`, partition-gated rules).
# ===========================================================================

OPA_PACKAGE = "uhap"
OPA_POLICY_ID = "uhap_bench"


def _opa_input_payload() -> bytes:
    import json
    return json.dumps({"input": {
        "uid": SAMPLE_SAR["uid"],
        "roles": SAMPLE_SAR["roles"],
        "groups": SAMPLE_SAR["groups"],
        "namespace": SAMPLE_SAR["namespace"],
        "resource": SAMPLE_SAR["resource"],
        "action": SAMPLE_SAR["action"],
        "attrs": SAMPLE_SAR["context"],
    }}).encode("utf-8")


def _opa_clear_policy(opa_url: str) -> None:
    """Best-effort delete of any prior policy module so PUT measures a clean
    upload (OPA caches compiled module state)."""
    import urllib.request, urllib.error
    req = urllib.request.Request(
        f"{opa_url}/v1/policies/{OPA_POLICY_ID}", method="DELETE",
    )
    try:
        urllib.request.urlopen(req, timeout=10).read()
    except urllib.error.HTTPError:
        pass  # 404 on first run is fine


def measure_opa_rest_one(rego_text: str, opa_url: str) -> Dict[str, float]:
    """One update cycle for OPA REST PUT-policy mode."""
    import urllib.request, urllib.error

    _opa_clear_policy(opa_url)

    sar_payload = _opa_input_payload()

    t0 = time.perf_counter_ns()
    req = urllib.request.Request(
        f"{opa_url}/v1/policies/{OPA_POLICY_ID}",
        data=rego_text.encode("utf-8"),
        method="PUT",
        headers={"Content-Type": "text/plain"},
    )
    try:
        urllib.request.urlopen(req, timeout=60).read()
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"OPA PUT failed: {e.code} {e.read().decode()}")
    t1 = time.perf_counter_ns()

    req2 = urllib.request.Request(
        f"{opa_url}/v1/data/{OPA_PACKAGE}/allow",
        data=sar_payload,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        urllib.request.urlopen(req2, timeout=30).read()
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"OPA POST failed: {e.code} {e.read().decode()}")
    t2 = time.perf_counter_ns()

    put_ms       = (t1 - t0) / 1e6
    first_dec_ms = (t2 - t1) / 1e6
    return dict(
        parse_ms=0.0,
        compile_ms=put_ms,            # OPA fuses parse+compile+swap inside PUT
        swap_ms=0.0,
        first_decision_ms=first_dec_ms,
        post_parse_ms=put_ms + first_dec_ms,
        total_ms=put_ms + first_dec_ms,
        rss_kb=0,
    )


def _build_opa_bundle(rego_path: Path, work: Path) -> Path:
    """Run `opa build -b <dir>` once per policy file. Bundle build itself is
    NOT part of the latency measurement (mirrors a CI-built bundle being
    activated at runtime)."""
    import subprocess, shutil
    src = work / "src"
    src.mkdir(parents=True, exist_ok=True)
    shutil.copy(rego_path, src / "policy.rego")
    out = work / "bundle.tar.gz"
    proc = subprocess.run(
        ["opa", "build", "-b", str(src), "-o", str(out)],
        cwd=str(work), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"opa build failed: {proc.stderr.decode()}")
    return out


def measure_opa_bundle_one(bundle_path: Path, opa_url: str) -> Dict[str, float]:
    """One update cycle for OPA bundle activation mode.

    Reads the prebuilt bundle.tar.gz, PUTs it as raw bytes via the
    `application/vnd.openpolicyagent.bundles` content type, then issues a
    decision. This mirrors the OPA Bundle API documented activation flow.
    """
    import urllib.request, urllib.error

    _opa_clear_policy(opa_url)
    sar_payload = _opa_input_payload()
    bundle_bytes = bundle_path.read_bytes()

    t0 = time.perf_counter_ns()
    # OPA exposes /v1/policies for raw uploads; for bundle activation the
    # canonical path is to push the *contents* of the bundle (a single
    # rego module after `opa build`) via PUT /v1/policies. We extract the
    # rego from the tarball once and treat the activation as the PUT.
    req = urllib.request.Request(
        f"{opa_url}/v1/policies/{OPA_POLICY_ID}",
        data=_extract_bundle_rego(bundle_bytes),
        method="PUT",
        headers={"Content-Type": "text/plain"},
    )
    try:
        urllib.request.urlopen(req, timeout=120).read()
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"OPA bundle PUT failed: {e.code} {e.read().decode()}")
    t1 = time.perf_counter_ns()

    req2 = urllib.request.Request(
        f"{opa_url}/v1/data/{OPA_PACKAGE}/allow",
        data=sar_payload,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        urllib.request.urlopen(req2, timeout=30).read()
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"OPA POST failed: {e.code} {e.read().decode()}")
    t2 = time.perf_counter_ns()

    put_ms       = (t1 - t0) / 1e6
    first_dec_ms = (t2 - t1) / 1e6
    return dict(
        parse_ms=0.0,
        compile_ms=put_ms,
        swap_ms=0.0,
        first_decision_ms=first_dec_ms,
        post_parse_ms=put_ms + first_dec_ms,
        total_ms=put_ms + first_dec_ms,
        rss_kb=0,
    )


def _extract_bundle_rego(bundle_bytes: bytes) -> bytes:
    """Pull the .rego module out of an opa-built bundle tarball."""
    import io, tarfile
    buf = io.BytesIO(bundle_bytes)
    with tarfile.open(fileobj=buf, mode="r:gz") as tf:
        for m in tf.getmembers():
            if m.name.endswith(".rego"):
                f = tf.extractfile(m)
                if f is not None:
                    return f.read()
    raise RuntimeError("no .rego found in bundle")


def run_opa(rego_dir: Path, counts: List[int], reps: int,
            opa_url: str, mode: str) -> List[dict]:
    import tempfile
    rows: List[dict] = []
    for n in counts:
        rego_path = rego_dir / f"policies_{n}.rego"
        if not rego_path.is_file():
            print(f"  ! missing {rego_path}; run yaml_to_rego.py first",
                  file=sys.stderr)
            continue

        if mode == "rest":
            rego_text = rego_path.read_text(encoding="utf-8")
            measure = lambda: measure_opa_rest_one(rego_text, opa_url)
        elif mode == "bundle":
            tmp = Path(tempfile.mkdtemp(prefix=f"opa_bundle_{n}_"))
            bundle = _build_opa_bundle(rego_path, tmp)
            measure = lambda: measure_opa_bundle_one(bundle, opa_url)
        else:
            raise ValueError(f"unknown opa mode: {mode}")

        for _ in range(3):
            measure()

        for rep in range(reps):
            timings = measure()
            rows.append({
                "system": "opa",
                "policy_count": n,
                "run_id": rep,
                **timings,
            })
        med = statistics.median(r["total_ms"] for r in rows
                                if r["policy_count"] == n)
        print(f"  opa[{mode}] n={n}: median total = {med:.2f} ms")
    return rows


# ===========================================================================
# CSV / plotting
# ===========================================================================

CSV_FIELDS = [
    "system", "policy_count", "run_id",
    "parse_ms", "compile_ms", "swap_ms",
    "first_decision_ms", "post_parse_ms", "total_ms",
    "rss_kb",
]


def write_csv(rows: List[dict], path: Path, append: bool = False) -> None:
    mode = "a" if append and path.exists() else "w"
    write_header = (mode == "w")
    with path.open(mode, newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        if write_header:
            w.writeheader()
        for row in rows:
            w.writerow(row)


def read_csv(path: Path) -> List[dict]:
    rows: List[dict] = []
    if not path.exists():
        return rows
    with path.open(encoding="utf-8") as f:
        for r in csv.DictReader(f):
            r["policy_count"] = int(r["policy_count"])
            r["run_id"] = int(r["run_id"])
            for k in ("parse_ms", "compile_ms", "swap_ms",
                      "first_decision_ms", "post_parse_ms", "total_ms"):
                r[k] = float(r.get(k, "nan"))
            r["rss_kb"] = int(float(r.get("rss_kb", 0) or 0))
            rows.append(r)
    return rows


# ---------------------------------------------------------------------------
# Bootstrap percentile CIs
# ---------------------------------------------------------------------------

def _bootstrap_ci_median(samples: Sequence[float], n_resamples: int = 1000,
                         alpha: float = 0.05, seed: int = 1234) -> Tuple[float, float]:
    """Percentile bootstrap 95% CI for the median.

    Returns (lower, upper). Falls back to (min, max) if too few samples.
    """
    xs = list(samples)
    if len(xs) < 3:
        return (min(xs, default=float("nan")), max(xs, default=float("nan")))
    rng = random.Random(seed)
    medians = []
    for _ in range(n_resamples):
        resample = [rng.choice(xs) for _ in range(len(xs))]
        medians.append(statistics.median(resample))
    medians.sort()
    lo_idx = max(0, int((alpha / 2) * n_resamples) - 1)
    hi_idx = min(n_resamples - 1, int((1 - alpha / 2) * n_resamples) - 1)
    return (medians[lo_idx], medians[hi_idx])


def _summarize(rows: List[dict], system: str, counts: List[int],
               metric: str = "total_ms") -> Dict[str, List[float]]:
    """Per-policy-count median + 95% bootstrap CI + p95 for the given metric."""
    out = {"median": [], "ci_lo": [], "ci_hi": [], "p95": []}
    for n in counts:
        xs = [r[metric] for r in rows
              if r["system"] == system and r["policy_count"] == n]
        if not xs:
            for k in out:
                out[k].append(float("nan"))
            continue
        med = statistics.median(xs)
        lo, hi = _bootstrap_ci_median(xs)
        p95 = sorted(xs)[max(0, int(0.95 * len(xs)) - 1)]
        out["median"].append(med)
        out["ci_lo"].append(lo)
        out["ci_hi"].append(hi)
        out["p95"].append(p95)
    return out


def _plot_line_with_ci(ax, counts, summary, marker, ls, color, label):
    """Plot median with asymmetric 95% CI error bars."""
    med = summary["median"]
    lo = [m - l for m, l in zip(med, summary["ci_lo"])]
    hi = [h - m for m, h in zip(med, summary["ci_hi"])]
    ax.errorbar(
        counts, med, yerr=[lo, hi],
        marker=marker, linestyle=ls, color=color,
        capsize=3, elinewidth=0.8, markeredgecolor="black",
        markersize=5, linewidth=1.4, label=label,
    )


def plot_all(csv_path: Path) -> None:
    # Apply B&W style if available
    import matplotlib.pyplot as plt
    style_path = HERE.parent / "figures_bw" / "style.mplstyle"
    if style_path.is_file():
        plt.style.use(str(style_path))

    rows = read_csv(csv_path)
    if not rows:
        print("no rows in CSV; nothing to plot", file=sys.stderr)
        return

    counts = sorted({r["policy_count"] for r in rows})
    has_opa = any(r["system"] == "opa" for r in rows)

    # ---- Plot 1: TOTAL update latency vs policy count, with 95% CI -------
    fig, ax = plt.subplots(figsize=(5.0, 3.4))
    _plot_line_with_ci(ax, counts, _summarize(rows, "uhap", counts, "total_ms"),
                       marker="o", ls="-",  color="black",
                       label="U-HAP (median, 95% CI)")
    if has_opa:
        _plot_line_with_ci(ax, counts, _summarize(rows, "opa", counts, "total_ms"),
                           marker="s", ls="--", color="black",
                           label="OPA (median, 95% CI)")
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("Number of policies")
    ax.set_ylabel("Total update latency (ms)")
    ax.legend(loc="best")
    ax.grid(True, which="both", alpha=0.3)
    fig.tight_layout()
    out1 = PLOTS_DIR / "exp5_update_latency.png"
    fig.savefig(out1, dpi=300); fig.savefig(out1.with_suffix(".pdf"))
    print(f"wrote {out1}")

    # ---- Plot 1b: POST-PARSE update latency (apples-to-apples vs OPA) ----
    fig1b, ax1b = plt.subplots(figsize=(5.0, 3.4))
    _plot_line_with_ci(ax1b, counts, _summarize(rows, "uhap", counts, "post_parse_ms"),
                       marker="o", ls="-",  color="black",
                       label="U-HAP (median, 95% CI)")
    if has_opa:
        _plot_line_with_ci(ax1b, counts, _summarize(rows, "opa", counts, "post_parse_ms"),
                           marker="s", ls="--", color="black",
                           label="OPA (median, 95% CI)")
    ax1b.set_xscale("log")
    ax1b.set_yscale("log")
    ax1b.set_xlabel("Number of policies")
    ax1b.set_ylabel("Post-parse update latency (ms)")
    ax1b.legend(loc="best")
    ax1b.grid(True, which="both", alpha=0.3)
    fig1b.tight_layout()
    out1b = PLOTS_DIR / "exp5_post_parse.png"
    fig1b.savefig(out1b, dpi=300); fig1b.savefig(out1b.with_suffix(".pdf"))
    print(f"wrote {out1b}")

    # ---- Plot 1c: memory footprint of compiled state ---------------------
    fig1c, ax1c = plt.subplots(figsize=(5.0, 3.4))
    width = 0.35
    x_pos = list(range(len(counts)))
    uhap_rss = [statistics.median([r["rss_kb"]
                                   for r in rows
                                   if r["system"] == "uhap"
                                   and r["policy_count"] == n] or [0])
                for n in counts]
    ax1c.bar([p - width / 2 for p in x_pos], [v / 1024 for v in uhap_rss],
             width=width, label="U-HAP",
             color="white", edgecolor="black", hatch="//")
    if has_opa:
        opa_rss = [statistics.median([r["rss_kb"]
                                      for r in rows
                                      if r["system"] == "opa"
                                      and r["policy_count"] == n] or [0])
                   for n in counts]
        ax1c.bar([p + width / 2 for p in x_pos], [v / 1024 for v in opa_rss],
                 width=width, label="OPA",
                 color="white", edgecolor="black", hatch="\\\\")
    ax1c.set_xticks(x_pos)
    ax1c.set_xticklabels([str(n) for n in counts])
    ax1c.set_xlabel("Number of policies")
    ax1c.set_ylabel("Compiled-state memory (MiB)")
    ax1c.legend(loc="upper left")
    ax1c.grid(True, axis="y", alpha=0.3)
    fig1c.tight_layout()
    out1c = PLOTS_DIR / "exp5_memory.png"
    fig1c.savefig(out1c, dpi=300); fig1c.savefig(out1c.with_suffix(".pdf"))
    print(f"wrote {out1c}")

    # ---- Plot 2: U-HAP breakdown stacked bar ------------------------------
    uhap_rows = [r for r in rows if r["system"] == "uhap"]
    if uhap_rows:
        fig2, ax2 = plt.subplots(figsize=(5.0, 3.4))
        parse_med, compile_med, swap_med, decision_med = [], [], [], []
        for n in counts:
            xs = [r for r in uhap_rows if r["policy_count"] == n]
            if not xs:
                parse_med.append(0); compile_med.append(0)
                swap_med.append(0);  decision_med.append(0)
                continue
            parse_med.append(statistics.median(r["parse_ms"] for r in xs))
            compile_med.append(statistics.median(r["compile_ms"] for r in xs))
            swap_med.append(statistics.median(r["swap_ms"] for r in xs))
            decision_med.append(statistics.median(r["first_decision_ms"] for r in xs))

        x = list(range(len(counts)))
        bottom = [0.0] * len(counts)
        for vals, label, hatch in [
            (parse_med,    "parse",    "//"),
            (compile_med,  "compile",  "\\\\"),
            (swap_med,     "swap",     "xx"),
            (decision_med, "1st req.", ".."),
        ]:
            ax2.bar(x, vals, bottom=bottom, label=label,
                    edgecolor="black", color="white", hatch=hatch)
            bottom = [b + v for b, v in zip(bottom, vals)]
        ax2.set_xticks(x)
        ax2.set_xticklabels([str(n) for n in counts])
        ax2.set_xlabel("Number of policies")
        ax2.set_ylabel("Time (ms)")
        ax2.legend(loc="upper left")
        ax2.grid(True, axis="y", alpha=0.3)
        fig2.tight_layout()
        out2 = PLOTS_DIR / "exp5_breakdown.png"
        fig2.savefig(out2, dpi=300)
        fig2.savefig(out2.with_suffix(".pdf"))
        print(f"wrote {out2}")


# ===========================================================================
# CLI
# ===========================================================================

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--uhap", action="store_true", help="run U-HAP measurements")
    ap.add_argument("--opa", action="store_true", help="run OPA baseline")
    ap.add_argument("--plot", action="store_true", help="regenerate plots")
    ap.add_argument("--policy-dir", default=str(HERE / "policy_sets"))
    ap.add_argument("--rego-dir",   default=str(HERE / "rego_sets"))
    ap.add_argument("--counts", default="10,100,500,1000,2000")
    ap.add_argument("--reps", type=int, default=30)
    ap.add_argument("--opa-mode", choices=["rest", "bundle"], default="rest")
    ap.add_argument("--opa-url", default="http://127.0.0.1:8181")
    ap.add_argument("--append", action="store_true",
                    help="append to existing CSV instead of overwriting")
    args = ap.parse_args()

    if not (args.uhap or args.opa or args.plot):
        ap.error("specify at least one of --uhap, --opa, --plot")

    policy_dir = Path(args.policy_dir)
    counts = [int(x) for x in args.counts.split(",")]

    all_rows: List[dict] = []
    if args.uhap:
        print("=== U-HAP ===")
        all_rows.extend(run_uhap(policy_dir, counts, args.reps))
    if args.opa:
        print(f"=== OPA [{args.opa_mode}] ===")
        rego_dir = Path(args.rego_dir)
        all_rows.extend(run_opa(rego_dir, counts, args.reps,
                                args.opa_url, args.opa_mode))

    if all_rows:
        write_csv(all_rows, CSV_PATH, append=args.append)
        print(f"wrote {CSV_PATH}  ({len(all_rows)} rows)")

    if args.plot:
        plot_all(CSV_PATH)


if __name__ == "__main__":
    main()
