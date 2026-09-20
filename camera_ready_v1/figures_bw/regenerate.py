"""
Regenerate all paper figures with the B&W-safe matplotlib style applied.

Reads source plot scripts from the original repo (read-only) and re-runs them
with our style.mplstyle in effect. Output goes to camera_ready_v1/figures_bw/,
NOT back to the original figure paths — preserves rollback.

Targets:
  - experiments/run_experiments.py        (graph1, graph2a, graph2b, graph3)
  - experiments/run_final_graphs.py       (final paper plots)
  - final_plots/generate_final_plots.py   (Fig 2 namespace, Fig 3 latency)
  - camera_ready_v1/experiments/exp5_update_latency.py --plot

Usage:
    python regenerate.py --target final     # only the manuscript figures
    python regenerate.py --target all
    python regenerate.py --target exp5
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent              # U-HAP/
STYLE = HERE / "style.mplstyle"
OUT = HERE
OUT.mkdir(exist_ok=True)


def _run_with_style(script: Path, env_extra: dict | None = None,
                    cwd: Path | None = None) -> int:
    """Run a python script with MPLSTYLE_BW set so the script (or a small
    matplotlibrc shim) can pick it up. We also inject MPLBACKEND=Agg."""
    env = os.environ.copy()
    env["MPLBACKEND"] = "Agg"
    env["UHAP_BW_STYLE"] = str(STYLE)
    if env_extra:
        env.update(env_extra)

    # Inject style via PYTHONSTARTUP-like wrapper
    wrapper = f"""
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
plt.style.use(r'{STYLE}')
exec(open(r'{script}', encoding='utf-8').read(), {{'__name__': '__main__', '__file__': r'{script}'}})
"""
    return subprocess.call(
        [sys.executable, "-c", wrapper],
        env=env,
        cwd=str(cwd or script.parent),
    )


def regenerate_final_plots() -> None:
    """final_plots/generate_final_plots.py — Fig 2, Fig 3."""
    src = ROOT / "final_plots" / "generate_final_plots.py"
    if not src.is_file():
        print(f"  ! missing {src}", file=sys.stderr)
        return
    rc = _run_with_style(src)
    if rc != 0:
        print(f"  ! generate_final_plots.py exited {rc}", file=sys.stderr)
        return
    # Copy outputs from final_plots/ → figures_bw/
    src_dir = ROOT / "final_plots"
    for fname in ("fig2_namespace_isolation.png", "fig3_permodel_latency.png"):
        s = src_dir / fname
        if s.exists():
            d = OUT / f"bw_{fname}"
            shutil.copy2(s, d)
            print(f"  copied {fname} -> {d.name}")


def regenerate_experiments() -> None:
    """experiments/run_experiments.py + run_final_graphs.py."""
    for name in ("run_experiments.py", "run_final_graphs.py", "replot_final.py"):
        src = ROOT / "experiments" / name
        if not src.is_file():
            continue
        print(f"  running {name} with B&W style...")
        rc = _run_with_style(src)
        if rc != 0:
            print(f"  ! {name} exited {rc}", file=sys.stderr)
            continue
        # Copy any newly written experiments/plots/*.png to figures_bw/
        plots_dir = ROOT / "experiments" / "plots"
        if plots_dir.is_dir():
            for png in plots_dir.glob("*.png"):
                d = OUT / f"bw_{png.name}"
                shutil.copy2(png, d)


def regenerate_exp5() -> None:
    """camera_ready_v1/experiments/exp5_update_latency.py --plot."""
    src = HERE.parent / "experiments" / "exp5_update_latency.py"
    rc = _run_with_style(src, env_extra={}, cwd=src.parent)
    # exp5 already writes to camera_ready_v1/experiments/plots/, mirror to figures_bw/
    plots_dir = src.parent / "plots"
    for png in plots_dir.glob("exp5*.png"):
        d = OUT / f"bw_{png.name}"
        shutil.copy2(png, d)
    if rc != 0:
        print(f"  ! exp5 exited {rc}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", choices=["final", "experiments", "exp5", "all"],
                    default="all")
    args = ap.parse_args()

    print(f"Style file: {STYLE}")
    print(f"Output dir: {OUT}")

    if args.target in ("final", "all"):
        print("=== final_plots ===")
        regenerate_final_plots()
    if args.target in ("experiments", "all"):
        print("=== experiments ===")
        regenerate_experiments()
    if args.target in ("exp5", "all"):
        print("=== exp5 ===")
        regenerate_exp5()

    print("\nDone. Inspect figures in:", OUT)


if __name__ == "__main__":
    main()
