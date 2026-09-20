#!/usr/bin/env python3
"""
Experiment 2 figure, redesigned so it is OBVIOUS that U-HAP wins.

Professor feedback on the old fig3_permodel_latency.png:
  "hard to see that U-HAP is the winner -> change colors and circle the wins."

Fixes applied here:
  1. Colour by SYSTEM, not by model.
       U-HAP      = green  (the winner: stays low / flat)
       Traditional= red    (the loser: climbs with k)
     Model is shown only by marker shape (ABAC square, RBAC circle, ACL triangle).
  2. Shade the "U-HAP faster" zone (k beyond the crossover) in light green.
  3. Circle the k=320 win and label the speedup (16.9x / 5.6x / 5.0x).
  4. Second panel: speedup vs k with a 1x reference line, green above (U-HAP
     faster), red below (compilation cost not yet amortised), max wins circled.

Data source: experiments/v3_traditional/results/exp2b.csv
"""
import csv
import os
from collections import defaultdict

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Ellipse

HERE = os.path.dirname(os.path.abspath(__file__))
CSV = os.path.join(
    HERE, "..", "..", "experiments", "v3_traditional", "results", "exp2b.csv"
)
OUT = os.path.join(HERE, "fig3_exp2_uhap_wins.png")

# ---- load data ------------------------------------------------------------
rows = defaultdict(list)
with open(CSV) as f:
    for r in csv.DictReader(f):
        rows[r["model"]].append(
            (
                int(r["rule_count"]),
                float(r["uhap_median_ms"]) * 1000.0,  # ms -> us
                float(r["trad_median_ms"]) * 1000.0,
                float(r["speedup"]),
            )
        )
for m in rows:
    rows[m].sort()

# display order + marker per model
MODELS = [
    ("abac", "ABAC", "s"),
    ("rbac", "RBAC", "o"),
    ("acl", "ACL", "^"),
]

UHAP_C = "#00a14b"   # vivid green -> "win" zone shading
TRAD_C = "#e8000b"   # vivid red   -> "lose" zone shading

# Shared per-model palette used in BOTH panels (same tone everywhere):
#   ABAC = orange, RBAC = blue, ACL = purple
mcolors = {"abac": "#ff6f00", "rbac": "#005ce6", "acl": "#8e24aa"}

plt.rcParams.update({
    "font.size": 13,
    "axes.titlesize": 15,
    "axes.labelsize": 13,
    "legend.fontsize": 10.5,
})

fig, (axL, axR) = plt.subplots(1, 2, figsize=(13.5, 5.6))

# ===========================================================================
# LEFT PANEL: latency vs k  (log scale)
# ===========================================================================
ks = [k for k, *_ in rows["abac"]]

# win-zone shading (U-HAP faster once speedup >= 1 -> roughly k >= 20)
axL.axvspan(20, max(ks) * 1.15, color=UHAP_C, alpha=0.13, zorder=0)
axL.text(
    78, 5.0, "U-HAP faster region",
    color=UHAP_C, fontsize=11.5, fontweight="bold",
    ha="center", va="center",
)

for key, label, mk in MODELS:
    k = [x[0] for x in rows[key]]
    uh = [x[1] for x in rows[key]]
    tr = [x[2] for x in rows[key]]
    c = mcolors[key]
    # Traditional = dashed + open marker ; U-HAP = solid + filled marker
    axL.plot(k, tr, color=c, ls="--", lw=2.6, marker=mk,
             ms=9, mfc="white", mec=c, mew=2.0,
             label=f"{label} — Traditional", zorder=3)
    axL.plot(k, uh, color=c, ls="-", lw=3.4, marker=mk,
             ms=9, mfc=c, mec=c,
             label=f"{label} — U-HAP", zorder=4)

axL.set_xscale("log")
axL.set_yscale("log")
axL.set_xticks(ks)
axL.set_xticklabels([str(k) for k in ks])
axL.minorticks_off()
axL.set_xlabel("Rules per namespace  (k)")
axL.set_ylabel("Median latency  (µs) — log scale")
axL.set_title("Latency: U-HAP stays flat, Traditional climbs")
axL.grid(True, which="major", ls=":", alpha=0.4)

# ring the three U-HAP endpoints at k=320 (clean rings -> "these stay low")
last = {key: rows[key][-1] for key, *_ in MODELS}
for key in ("abac", "rbac", "acl"):
    _, uh, _, _ = last[key]
    axL.scatter([320], [uh], s=750, facecolors="none",
                edgecolors="#111111", linewidths=2.0, zorder=7)

# double-headed arrow showing the dramatic ABAC gap at k=320
_, uh_a, tr_a, _ = last["abac"]
axL.annotate("", xy=(320, tr_a), xytext=(320, uh_a),
             arrowprops=dict(arrowstyle="<->", color="#111111", lw=2.0),
             zorder=6)
axL.text(285, (uh_a * tr_a) ** 0.5, "16.9×\nfaster",
         fontsize=12, fontweight="bold", color="#111111",
         ha="right", va="center", zorder=8)
# small label for the flat RBAC/ACL wins
axL.annotate("RBAC 5.6× / ACL 5.0×\n(U-HAP stays flat)", xy=(320, last["rbac"][1]),
             xytext=(95, 0.40), fontsize=10, fontweight="bold",
             color=UHAP_C, ha="center", va="center",
             arrowprops=dict(arrowstyle="->", color=UHAP_C, lw=1.3), zorder=8)

axL.set_ylim(0.3, 700)
axL.legend(loc="upper left", ncol=2, framealpha=0.92, handlelength=2.4)

# ===========================================================================
# RIGHT PANEL: speedup vs k
# ===========================================================================
axR.axhspan(1, 30, color=UHAP_C, alpha=0.15, zorder=0)
axR.axhspan(0.3, 1, color=TRAD_C, alpha=0.13, zorder=0)
axR.axhline(1.0, color="#222222", lw=1.8, ls="-", zorder=2)
axR.text(330, 1.45, "U-HAP faster  ↑", color=UHAP_C,
         fontsize=10.5, fontweight="bold", ha="right", va="bottom")
axR.text(330, 0.72, "not yet amortised  ↓", color=TRAD_C,
         fontsize=10.5, fontweight="bold", ha="right", va="top")

lblpos = {"abac": (170, 17.5), "rbac": (150, 6.6), "acl": (150, 4.0)}
for key, label, mk in MODELS:
    k = [x[0] for x in rows[key]]
    sp = [x[3] for x in rows[key]]
    axR.plot(k, sp, color=mcolors[key], lw=3.2, marker=mk, ms=9,
             label=f"{label}", zorder=4)
    # clean ring around the max speedup at k=320
    axR.scatter([320], [sp[-1]], s=750, facecolors="none",
                edgecolors="#111111", linewidths=2.0, zorder=6)
    axR.annotate(f"{sp[-1]:.1f}×", xy=(320, sp[-1]),
                 xytext=lblpos[key], fontsize=11.5, fontweight="bold",
                 color=mcolors[key], ha="right", va="center", zorder=7)

axR.set_xscale("log")
axR.set_yscale("log")
axR.set_xticks(ks)
axR.set_xticklabels([str(k) for k in ks])
axR.set_yticks([0.5, 1, 2, 5, 10, 20])
axR.set_yticklabels(["0.5×", "1×", "2×", "5×", "10×", "20×"])
axR.minorticks_off()
axR.set_xlabel("Rules per namespace  (k)")
axR.set_ylabel("Speedup vs. Traditional baseline")
axR.set_title("Speedup grows with k  (everything above 1× = win)")
axR.grid(True, which="major", ls=":", alpha=0.4)
axR.legend(loc="upper left", framealpha=0.92)

fig.suptitle("Experiment 2 — U-HAP vs. Traditional under growing policy size",
             fontsize=16, fontweight="bold")
fig.tight_layout(rect=(0, 0, 1, 0.96))
fig.savefig(OUT, dpi=200, bbox_inches="tight")
print("wrote", OUT)
