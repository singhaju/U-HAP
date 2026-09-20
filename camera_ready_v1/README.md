# U-HAP Camera-Ready Workspace (JCSSE 2026)

All revision work for camera-ready (deadline May 15, 2026) lives here.
Original repo files are not modified until the explicit integration step.

## Layout

```
camera_ready_v1/
├── PLAN.md                      Full plan + workstreams + timeline + rollback
├── README.md                    This file (status quick-ref)
├── snapshots/                   Frozen baseline of accepted version (rollback target)
│   ├── pre_revision_paper.pdf
│   ├── section_iv_experimental.tex.orig
│   ├── figures.orig/
│   └── final_plots.orig/
├── experiments/                 Workstream A — Update Latency
│   ├── exp5_update_latency.py   U-HAP path implemented; OPA path stub
│   ├── gen_policies.py          Synthetic policy YAML generator
│   ├── policy_sets/             Generated YAML inputs
│   ├── results/
│   │   └── exp5_update_latency.csv
│   └── plots/
│       ├── exp5_update_latency.png/.pdf
│       └── exp5_breakdown.png/.pdf
├── figures_bw/                  Workstream B — B&W-safe figures
│   ├── style.mplstyle           Matplotlib style (B&W-safe)
│   └── regenerate.py            Re-run paper plot scripts with style
├── references/                  Workstreams C & D — refs
│   ├── candidates_2025.md       (TBD: 2025 papers to add)
│   ├── ieee_format_audit.md     IEEE format audit checklist
│   ├── refs_original.bib        (TBD: drop bib here)
│   └── new_2025_refs.bib        (TBD: add 2025 entries here)
├── manuscript/                  Workstream E — paper revisions
│   ├── revision_letter.md       Reviewer-comment → action map
│   ├── section_iv_v2.tex        (TBD: revised §IV after exp5 runs)
│   ├── related_work_patch.tex   (TBD: 2025 ref integration)
│   ├── abstract_v2.tex          (TBD)
│   └── conclusion_v2.tex        (TBD)
└── snapshots/                   See above
```

## Status snapshot

| Task | Status |
|------|--------|
| #1  Snapshot accepted-version baseline | ✅ |
| #2  Inspect src/ to ground exp5 imports | ✅ |
| #3  Scaffold exp5_update_latency.py | ✅ (smoke-tested, 1.7/14.7 ms median at 10/100 policies) |
| #4  Synthetic policy generator | ✅ |
| #5  B&W matplotlib style + regenerate.py | ✅ |
| #6  Find 2025 references for Related Work | ✅ (6 candidates, top-3 picked: KubeKeeper, KubeFence, Sissodiya formal) |
| #7  IEEE reference format audit | ✅ (framework — needs bib dropped in) |
| #8  Draft revision letter shell | ✅ |
| #9  OPA baseline harness for exp5 | ✅ (REST PUT + bundle activation, equivalence-gated) |
| #10 Run exp5 + generate plots (full sweep) | ✅ (n=10..2000, 30 reps; 2.73× total / 19.5× post-parse @ n=2000) |
| #11 Write §IV.E Update Latency text | ✅ (`manuscript/section_iv_E_update_latency.tex`) |
| #12 Integrate revisions into manuscript (F4) | ✅ (`U-HAP_deliverble_camera_ready.md` — 982 lines, +143 vs original; diff in `camera_ready_v1.diff`) |
| #13 EDAS upload + eCF + registration | pending — user-driven |
| #14 Bootstrap CIs + error bars in exp5 | ✅ |
| #15 Total vs post-parse split | ✅ |
| #16 Memory footprint (tracemalloc, separate pass) | ✅ |
| #17 Grayscale PDF verification script | ✅ (`figures_bw/grayscale_check.sh`) |
| #18 Reconcile PLAN.md with self-review | ✅ |

## Open decisions (waiting on user)

1. ~~**OPA deployment mode**~~ — Resolved. Both REST PUT and bundle activation are
   measured; numbers within ±4 % of each other across all sizes.
2. **Hardware** — exp5 ran on the same Ryzen 9 7945HX box as exp1–exp4. OK?
3. **Page budget** — pages remaining in the IEEE template? §IV.E adds ~3/4 column
   of prose + 1 table + 2 figures.
4. ~~**Rego translation**~~ — Resolved. `yaml_to_rego.py` produces Rego v1
   modules; equivalence test passes 100/100 at every $n$ (10..2000).
5. **Presenting author** for registration?
6. **Paper .tex source** — needed for the F4 integration step. The four
   ready-to-splice fragments live in `manuscript/`:
   `section_iv_E_update_latency.tex`, `abstract_update.tex`,
   `conclusion_update.tex`, `multi_replica_caveat.tex`. Once you drop the
   `.tex` source in `snapshots/` (or share it), I can do the splice and
   produce a unified diff.

## Rollback

Full: `rm -rf camera_ready_v1/`
Per-workstream: `rm -rf camera_ready_v1/<subfolder>/`

The original repository (`src/`, `experiments/`, `figures/`, `final_plots/`,
manuscript) is untouched until the explicit integration step (Workstream F4).
