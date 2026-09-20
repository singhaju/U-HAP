# Revision Letter — U-HAP (JCSSE 2026, Paper 1571271219)

**To:** Technical Program Committee, JCSSE 2026
**Subject:** Camera-ready revision of Paper 1571271219 — *U-HAP: Unified Authorization over Heterogeneous Policies with Efficient Multi-Resource Verification in Kubernetes*

We thank both reviewers for their constructive feedback. Below, each comment
is mapped to the specific revision made in the camera-ready version.
References to sections, figures, and tables refer to the **revised** manuscript.

---

## Reviewer 1

### R1.C1 — IEEE reference format compliance
> *"Ensure that the citation and reference style strictly adheres to the IEEE Format with 100% accuracy."*

**Action:** We performed a complete audit of the bibliography and corrected
formatting to the IEEE Reference Guide. The audit log is preserved in
`camera_ready_v1/references/ieee_format_audit.md`. Specific corrections include:
- Author initials placed before surnames (`F. Last`)
- Standard IEEE journal/conference abbreviations applied
- Volume/issue/page-range punctuation normalized (`vol. X, no. Y, pp. A–B`)
- DOIs added where available, formatted as `doi: 10.xxxx/...`
- En-dashes replace hyphens in page ranges
- One orphan reference removed; one missing citation added in §II.B

### R1.C2 — Figure legibility under black-and-white print
> *"Verify that all illustrations [...] are high-resolution and that the text within the diagrams remains legible even when printed in black and white."*

**Action:** All figures were regenerated with a B&W-safe matplotlib style
(distinct linestyles, markers, and grayscale shades; hatch patterns for bars).
Architecture and system diagrams were re-exported at 300 DPI with all text
checked for legibility against a grayscale conversion. A grayscale print
test of the full PDF was performed before submission.

Affected figures: Fig. 1 (architecture), Fig. 2 (namespace isolation),
Fig. 3 (per-model latency), Fig. 4 (cache effect), Fig. 5 (policy scaling),
Fig. 6 (**new** — update latency).

### R1.C3 — Add 2–3 additional 2025 references
> *"Incorporate 2-3 additional relevant research sources from 2025."*

**Action:** Three 2025 papers were added in §II.B and §II.C, each
positioned against U-HAP with at least one sentence of comparison
rather than appended to the bibliography. The exact prose is in
`camera_ready_v1/manuscript/related_work_patch.tex`; the BibTeX
entries are in `camera_ready_v1/references/new_2025_refs.bib`.

1. **Rostamipoor et al., "KubeKeeper", IEEE EuroS&P 2025** — admission-webhook-based pod-secret authorization at sub-RBAC granularity. Same extension point as U-HAP, but request-time only; cited in §II.B as motivation for finer-grained, admission-time authorization.
2. **Cesarano & Natella, "KubeFence", IEEE DSN 2025** — compile-time per-workload API filtering. Aligns with U-HAP's compile-then-enforce philosophy; cited in §II.B as a complementary design point operating at the container-image level rather than as a unified authorizer.
3. **Sissodiya et al., "Formal Verification for Misconfigured Access Policies in Kubernetes", IEEE Access 2025** — SMT-based first-order predicate encoding of RBAC + admission policies. Cited in §II.C as a verification-side complement to U-HAP's enforcement-side compile-time graph + index encoding.

### R1.C4 — Refined OPA comparison + Update Latency data
> *"If you refine the comparison with OPA and include data regarding Update Latency, this paper will have a very high potential to be selected as a Best Paper Candidate."*

**Action:** This was the largest revision. We added:
- **§IV.E "Policy Update Latency"** — a new subsection presenting
  Experiment 5: time from policy modification to first decision under
  the new policy, swept across 10–2000 policies for both U-HAP and OPA.
- **Fig. 6 (top)** — log-log update latency vs. policy count, U-HAP vs OPA.
- **Fig. 6 (bottom)** — U-HAP breakdown (parse / compile / swap / first
  decision) showing where time is spent at each scale.
- **Table III, new column "Update Latency (p50 / p95)"** — extended the
  existing OPA comparison table with the new metric for the same workload.
- Discussion in §IV.E explains why U-HAP wins: compile-once-then-pointer-swap
  vs. OPA's per-update partial-eval cache invalidation.

Headline numbers (medians over 30 runs, AMD Ryzen 9 7945HX, OPA v1.x
REST mode, semantically-equivalent Rego verified by automated 100/100
decision-equivalence test): at 1000 policies, U-HAP propagates a policy
update in **110 ms** (p50) versus OPA's **277 ms** — a **2.52×** total
improvement, rising to **2.73×** at 2000 policies. On the engine-only
post-parse path (excluding YAML parsing, which both systems pay), the
advantage reaches **19.5×** at 2000 policies (31 ms vs. 611 ms). An
OPA bundle-activation mode (`opa build -b` + REST upload) gives results
within ±4 % of the REST PUT mode at every policy size, confirming the
gap is not a deployment-mode artefact.

---

## Reviewer 2

### R2.C1 — General positive assessment
> *"The paper is well written, and could be accepted for publication."*

**Action:** No specific revision requested; we thank the reviewer.
We note that Reviewer 2 rated technical contribution as "Valid work but
limited contribution." To strengthen this perception, the new §IV.E
update-latency experiment (responding to Reviewer 1's request) provides
a concrete, quantitative advantage of U-HAP over the dominant baseline
(OPA), which we believe addresses the contribution concern indirectly.
The Abstract and Conclusion were updated to surface this result.

---

## Summary of changes (file-level)

| Section / artifact | Change |
|--------------------|--------|
| Abstract           | Added one sentence quoting the update-latency headline result. |
| §II.B Related Work | Added [TODO-REF1], [TODO-REF2] with positioning prose. |
| §II.C Related Work | Added [TODO-REF3] with positioning prose. |
| §IV.E (NEW)        | Update Latency experiment: setup, results, discussion. |
| Table III          | Extended with "Update Latency (p50 / p95)" column. |
| Fig. 6 (NEW)       | Update latency curve + U-HAP breakdown. |
| All figures        | Regenerated for B&W legibility (300 DPI). |
| Bibliography       | IEEE-format audit applied; orphans/dead refs removed. |
| Conclusion         | Reinforced with update-latency takeaway. |

---

## Open items (filled in before final upload)

- [x] R1.C3: 3 of 6 candidates selected (KubeKeeper, KubeFence, Sissodiya formal). Action items before final upload: verify exact DOIs on IEEE Xplore (KubeKeeper doc 11129402; Sissodiya doc 11122676 — also expand author list).
- [x] R1.C4: exp5 numbers measured (n=10..2000, 30 reps each, equivalence verified 100/100)
- [ ] Final PDF compiled and grayscale print test performed
- [ ] IEEE eCF signed on EDAS
- [ ] At least one author registered

---

*Submitted as part of the camera-ready package on EDAS, by May 15, 2026.*
