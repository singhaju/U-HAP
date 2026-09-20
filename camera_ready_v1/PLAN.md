# U-HAP Camera-Ready Revision Plan (JCSSE 2026)

**Paper ID:** 1571271219
**Title:** U-HAP: Unified Authorization over Heterogeneous Policies with Efficient Multi-Resource Verification in Kubernetes
**Conference:** JCSSE 2026, Bangkok, June 24–27, 2026
**Camera-ready deadline:** May 15, 2026 (UTC-4 / EDT)
**Decision:** Accepted

---

## Isolation & Rollback Policy

All camera-ready work lives under `camera_ready_v1/`. The original repo state is **never modified in place** during this phase. Rollback = delete this folder.

```
U-HAP/
└── camera_ready_v1/                  ← ALL revision work here
    ├── PLAN.md                       ← this file
    ├── REVIEW_RESPONSE.md            ← reviewer comment → action map
    ├── experiments/
    │   ├── exp5_update_latency.py    ← new experiment
    │   ├── results/                  ← new CSVs (do not overwrite ../experiments/results)
    │   └── plots/                    ← new PNGs/PDFs
    ├── figures_bw/                   ← B&W-safe re-exports of all paper figures
    │   └── regenerate.py             ← script to rebuild from sources
    ├── references/
    │   ├── new_2025_refs.bib         ← 2–3 new 2025 sources
    │   └── ieee_format_audit.md      ← per-ref correction notes
    ├── manuscript/
    │   ├── section_iv_v2.tex         ← revised experimental section
    │   ├── related_work_patch.tex    ← Related Work additions
    │   └── revision_letter.md        ← cover letter for EDAS
    └── snapshots/
        └── pre_revision_paper.pdf    ← copy of accepted version (frozen baseline)
```

**Rules:**
1. No edits to `src/`, `experiments/run_experiments.py`, `final_plots/`, or `figures/` during this phase.
2. New code imports from `../src/` (read-only) — do not patch upstream modules.
3. Final integration into the paper repo is a separate, explicit step at the end (Workstream F).
4. To roll back at any point: `rm -rf camera_ready_v1/` — leaves the project in its accepted state.

---

## Workstreams Overview

| ID | Workstream | Effort | Priority | Blocks |
|----|------------|--------|----------|--------|
| A | Update Latency Experiment + OPA comparison | 3–5 d | **P0** (Best Paper hook) | E2, manuscript |
| B | Figures B&W legibility | 1–2 d | P0 (reviewer 1 explicit) | manuscript |
| C | Related Work — 2–3 new 2025 refs | 1 d | P0 (reviewer 1 explicit) | manuscript |
| D | IEEE reference-format pass | 1 d | P0 (reviewer 1 explicit) | manuscript |
| E | Manuscript revision pass | 2 d | P0 | F |
| F | EDAS submission + eCF + registration | 0.5 d | P0 hard deadline | — |

---

## Workstream A — Update Latency Experiment

### Rationale
Reviewer 1's strongest critique was the absence of update-latency data and a
sharper OPA comparison: *"If you refine the comparison with OPA and include
data regarding Update Latency, this paper will have a very high potential to
be selected as a Best Paper Candidate."* The primary goal here is **to address
that critique with statistically rigorous evidence**; Best Paper consideration
is a possible upside, not the success criterion.

### A1. Implement `camera_ready_v1/experiments/exp5_update_latency.py`

**Definition of "update latency":**
> Wall-clock time from the moment a policy artifact is modified on disk (or pushed to the policy API) until the **first authorization request** is decided under the new policy.

**Components measured (U-HAP):**
1. DSL parse time
2. Graph build time
3. Index compile time (Phase 2: `C_{n,r,a}` artifacts)
4. Registry hot-swap (atomic pointer flip)
5. First SAR served under new artifacts

**Components measured (OPA baseline):**
1. Bundle/policy upload (`PUT /v1/policies/{id}`)
2. OPA internal recompile + partial eval cache invalidation
3. First `POST /v1/data/...` decision under new policy

**Sweep (cold update, no concurrent load):**
- Policy counts: `[10, 100, 500, 1000, 2000]`
- Repetitions: ≥30 per `(policy_count, system)` cell
- Latency stats: median + 95% percentile bootstrap CI (1000 resamples) + p95
- Memory stats: median tracemalloc heap delta, separate measurement pass
  (uninstrumented timing run is the headline number)

**Two latency numbers reported, not one:**
- `total_ms`     — full update cycle (parse + compile + swap + first decision)
- `post_parse_ms` — apples-to-apples vs OPA: drops the YAML-parse cost both
                    systems pay, surfaces the actual engine-internal delta

**Outputs (CSV schema):**
`system, policy_count, run_id, parse_ms, compile_ms, swap_ms,
 first_decision_ms, post_parse_ms, total_ms, rss_kb`

**Plots:**
- `exp5_update_latency.png` — total update latency vs policy count (median + 95% CI error bars)
- `exp5_post_parse.png`     — post-parse-only, the headline U-HAP-vs-OPA delta
- `exp5_memory.png`         — compiled-state memory footprint (MiB), bar chart
- `exp5_breakdown.png`      — U-HAP stacked breakdown (parse/compile/swap/first-req)

**Pseudocode skeleton:**
```python
# camera_ready_v1/experiments/exp5_update_latency.py
import sys, time, csv, statistics
sys.path.insert(0, "../../")  # read-only access to src/
from src.dsl.loader import load_policies
from src.compiler.index_compiler import compile_indices
from src.compiler.registry import Registry
from src.engine.evaluator import evaluate_request

def measure_uhap_update(policy_set, sample_request):
    t0 = time.perf_counter_ns()
    parsed = load_policies(policy_set);             t1 = time.perf_counter_ns()
    graph  = build_graph(parsed);                   t2 = time.perf_counter_ns()
    idx    = compile_indices(graph);                t3 = time.perf_counter_ns()
    Registry.swap(idx);                             t4 = time.perf_counter_ns()
    _      = evaluate_request(sample_request);      t5 = time.perf_counter_ns()
    return dict(parse_ms=(t1-t0)/1e6, build_ms=(t2-t1)/1e6,
                compile_ms=(t3-t2)/1e6, swap_ms=(t4-t3)/1e6,
                first_decision_ms=(t5-t4)/1e6, total_ms=(t5-t0)/1e6)

def measure_opa_update(policy_bundle, sample_request, opa_url):
    # PUT bundle, then POST decision; measure both
    ...

POLICY_COUNTS = [10, 100, 500, 1000, 2000]
REPS = 30
for n in POLICY_COUNTS:
    for rep in range(REPS):
        ...
```

### A2. OPA baseline harness — TWO modes (both required for fair comparison)
**Mode 1: REST `PUT /v1/policies/<id>`** (apples-to-apples for raw-policy submission)
- OPA v0.70+ as a sidecar process on the same host
- Warm-up: 1000 requests before measurement
- Pin CPU governor to `performance`; isolate one core via `taskset`

**Mode 2: Bundle activation** (production-realistic OPA path)
- Pre-built signed OPA bundle, pushed via `PUT /v1/data/<bundle>`
- Reviewers will ask "did you compare against bundles?" — Mode 1 alone is
  not a defensible comparison

**Equivalence test (must pass before publishing numbers):**
- Property-based test: 100 random SARs evaluated against the same translated
  policy set in both U-HAP and OPA; decisions must match. Without this,
  comparison is invalid.

### A3. Extend OPA comparison table in §IV
Add **two** new columns, not one:
- "Update Latency (p50 / 95% CI)" — total
- "Update Latency post-parse (p50 / 95% CI)" — engine-internal only
Plus widen the existing memory column to include "compiled-state memory"
to address Reviewer 2's contribution concern with a second axis.

### A4. Manuscript text (~½ column)
- Setup: hardware, OPA version, policy translation note.
- Result: "U-HAP propagates a policy update in `X` ms (p50) at 1000 policies, vs OPA `Y` ms — `Z×` faster."
- Discussion: U-HAP's compile-once-then-swap vs OPA's per-request reasoning.

### A5. Decisions needed from user
- [ ] OPA version (recommend v0.70+) & deployment for Mode 1 (sidecar / REST)
- [ ] Bundle build pipeline for Mode 2 — do we reuse an existing bundle or build fresh?
- [ ] Hardware: reuse existing exp1–exp4 hardware, or re-run all on a new identical box?
- [ ] Is the Rego translation of U-HAP policies still valid post-v2 migration?
      If not, write a YAML→Rego translator inside `camera_ready_v1/experiments/yaml_to_rego.py`.

### A6. Multi-replica caveat (manuscript-only, no code change)
Add one paragraph to §IV.E or §V acknowledging that exp5 measures a single
webhook process. In a multi-replica deployment each replica hot-swaps
independently; eventual consistency window = max replica swap time. This
heads off a likely reviewer question without overclaiming.

---

## Workstream B — Figures (B&W legibility)

### B1. Inventory
Audit every figure currently used in the manuscript:
- `figures/architecture.png`
- `figures/namespace_isolation.png`
- `figures/permodel_latency.png`
- `final_plots/fig2_namespace_isolation.png`
- `final_plots/fig3_permodel_latency.png`
- `system diagram updated.png`
- All charts under `experiments/plots/`

### B2. Apply B&W-safe matplotlib style
Create `camera_ready_v1/figures_bw/style.mplstyle`:
```
axes.prop_cycle: cycler('color', ['000000', '404040', '808080', 'B0B0B0']) + cycler('linestyle', ['-', '--', '-.', ':']) + cycler('marker', ['o', 's', '^', 'D'])
figure.dpi: 300
savefig.dpi: 300
font.size: 9
```

### B3. Regeneration script
`camera_ready_v1/figures_bw/regenerate.py` that re-runs `final_plots/generate_final_plots.py` and the experiment plotters with the B&W style applied via `plt.style.use()`. Output to `camera_ready_v1/figures_bw/*.png` and `*.pdf` (vector).

### B4. Print test
Use `camera_ready_v1/figures_bw/grayscale_check.sh <paper.pdf>`:
- Renders each PDF page in color and grayscale at 200 DPI.
- Builds side-by-side `*_diff.png` files (ImageMagick) for visual review.
- Acceptance: every figure's text and line/marker styles remain
  distinguishable in the grayscale render. Fix any failure before submission.

---

## Workstream C — Related Work refresh

### C1. Target areas (2025 papers)
- Kubernetes admission/authorization advances
- OPA/Rego compilation or partial eval optimizations
- ABAC indexing / compilation
- Graph or DAG-based policy engines
- Zero-trust in cloud-native or service-mesh contexts

### C2. Source candidates
- IEEE Xplore (CNSM 2025, NOMS 2025, IM 2025, ICDCS 2025, EuroSys 2025)
- ACM DL (SoCC 2025, CCS 2025, EuroSys 2025)
- arXiv cs.CR / cs.DC 2025

### C3. Output
- `camera_ready_v1/references/new_2025_refs.bib` — 2–3 entries with full IEEE-format metadata.
- `camera_ready_v1/manuscript/related_work_patch.tex` — prose integration (≥1 sentence per ref positioning U-HAP).

### C4. Acceptance check
- Each new ref appears in Related Work prose, not just the bibliography.
- Each ref is from 2025.
- Each ref strengthens — not duplicates — existing comparisons.

---

## Workstream D — IEEE reference-format pass

### D1. Mechanical audit
For every entry in the bibliography:
- Author: `F. Last` (initials before surname)
- Title: sentence case in quotes
- Journal/conference: italicized, IEEE-standard abbreviation (look up in IEEE Reference Guide)
- `vol. X, no. Y, pp. A–B, Mon. YYYY`
- DOI: `doi: 10.xxxx/...` format
- En-dash for page ranges, not hyphen

### D2. In-text citation audit
- Style: `[N]` numeric, square brackets
- Sequential numbering by first appearance
- No orphan refs (cited but missing) or dead refs (in bib but not cited)

### D3. Output
- `camera_ready_v1/references/ieee_format_audit.md` — per-entry diff: original → corrected.
- Apply diff to manuscript only after all entries are audited.

---

## Workstream E — Manuscript revision pass

### E1. Revision letter (`camera_ready_v1/manuscript/revision_letter.md`)
Structure:
```
Dear PC and Reviewers,

We thank the reviewers for their constructive feedback. Below we map each
comment to the specific revisions made.

## Reviewer 1
- Comment: IEEE format compliance.
  Action: Audited every reference (Workstream D); see §VII bibliography.
- Comment: B&W figure legibility.
  Action: All figures regenerated with B&W-safe style; see Figs. 2–6.
- Comment: 2–3 additional 2025 references.
  Action: Added [X], [Y], [Z]; integrated in §II.B and §II.C.
- Comment: OPA comparison + Update Latency.
  Action: New §IV.E "Policy Update Latency"; added column in Table III;
  new Fig. 6 (exp5).

## Reviewer 2
- Acknowledgment of "limited contribution": addressed via expanded
  evaluation (Workstream A) demonstrating concrete advantage over OPA.
```

### E2. Strengthen Abstract + Conclusion
Both should now name-drop the update-latency result (concrete number + comparator).

### E3. Final proofread
- Typos, tense consistency
- IEEE conference template compliance (margins, font, columns)
- Page count vs. limit
- Figure/table numbering after insertions

### E4. Output
- `camera_ready_v1/manuscript/section_iv_v2.tex` (drop-in replacement for current §IV)
- `camera_ready_v1/manuscript/related_work_patch.tex` (additions to §II)
- `camera_ready_v1/manuscript/abstract_v2.tex`
- `camera_ready_v1/manuscript/conclusion_v2.tex`
- `camera_ready_v1/manuscript/revision_letter.md`

---

## Workstream F — Submission logistics

### F1. EDAS upload
- Upload final PDF compiled from integrated manuscript.
- Verify metadata (title, authors, affiliations) matches paper exactly.

### F2. IEEE eCF
- Sign and submit on EDAS by May 15, 2026.

### F3. Registration
- At least one author registers as presenting author at https://jcsse2026.org/services/payment/

### F4. Final integration step (only after E is done)
Copy from `camera_ready_v1/` into the working manuscript repo:
- `manuscript/section_iv_v2.tex` → replace §IV
- `manuscript/related_work_patch.tex` → merged into §II
- `references/new_2025_refs.bib` → appended to bibliography
- `figures_bw/*.pdf` → replace `figures/*` and `final_plots/*`

This is the **only** step that touches the existing paper. Tag the pre-integration commit so it's revertable.

---

## Timeline (working back from May 15, 2026)

| Dates | Workstream | Deliverable |
|-------|------------|-------------|
| Apr 25 – Apr 30 | A1, A2 | exp5 implemented + OPA harness running |
| May 1 – May 3   | A3, A4 | exp5 results, plots, draft text |
| May 4 – May 6   | B1–B4  | All figures B&W-safe + print-tested |
| May 4 – May 6   | C1–C4  | 2025 refs found + integrated (parallel with B) |
| May 7 – May 9   | D1–D3  | IEEE reference audit complete |
| May 10 – May 12 | E1–E4  | Revision letter + manuscript merge |
| May 13          | —      | Internal final read |
| May 14          | F1, F2 | Upload + eCF |
| May 15          | F3 + buffer | Registration + slack |

---

## Open Decisions Required From User

1. **OPA version & deployment** for exp5 (sidecar / REST / embedded Go)?
2. **Hardware** — reuse exp1–exp4 box or re-run everything on identical new hardware?
3. **Page budget** — how many pages remain in the IEEE template after current content?
4. **Rego translation** — is the existing OPA Rego policy still valid against current U-HAP semantics post-v2?
5. **Author for registration** — who is the presenting author?

---

## Acceptance Gates (camera-ready done = all true)

- [ ] exp5 CSV + plot exist and reproduce within ±5% on re-run
- [ ] exp5 reports both `total_ms` and `post_parse_ms`
- [ ] exp5 reports compiled-state memory (`rss_kb`)
- [ ] exp5 plot uses 95% bootstrap CI error bars (not just median)
- [ ] OPA equivalence test passes on 100 random SARs before publishing numbers
- [ ] OPA baseline run in **both** REST PUT mode and bundle activation mode
- [ ] §IV.E "Policy Update Latency" added to manuscript
- [ ] Table III has both "Update Latency" columns + memory column populated
- [ ] Multi-replica caveat paragraph added to §IV.E or §V
- [ ] grayscale_check.sh passes on the final PDF (manual visual review)
- [ ] ≥2 new 2025 references integrated in Related Work prose
- [ ] IEEE reference format audit applied (zero orphan/dead refs)
- [ ] Revision letter written, mapping every reviewer comment to a change
- [ ] Final PDF compiles without warnings, within page limit
- [ ] eCF signed on EDAS
- [ ] Final PDF uploaded on EDAS
- [ ] At least one author registered

---

## Rollback Procedure

If the camera-ready effort needs to be aborted or reset:

```bash
# Full rollback — discard all camera-ready work
rm -rf /home/singhaj/Documents/SIIT/U-HAP/camera_ready_v1/

# Partial rollback of one workstream (example: experiment A)
rm -rf /home/singhaj/Documents/SIIT/U-HAP/camera_ready_v1/experiments/

# Snapshot before integration (Workstream F4)
cp -r camera_ready_v1 camera_ready_v1.bak.$(date +%Y%m%d)
```

The original repository (`src/`, `experiments/run_experiments.py`, `figures/`, `final_plots/`, manuscript `.tex`) remains untouched until F4. After F4, the previous manuscript state is preserved by the git commit immediately before integration.
