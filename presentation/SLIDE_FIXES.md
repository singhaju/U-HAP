# Slide Fixes — slides_uhap.tex / speaker_script.md

Source of truth: `Deliverble/final/๊U-HAP_semiFinal.tex` (paper, refs b1–b21) and `paper_experiments/.../exp2b.csv`.
Deliverable being shipped: **LaTeX deck** `slides_uhap.tex` → `slides_uhap.pdf`.

---

## A. References — was 18 refs, now 21 (slides_uhap.tex, References slide)

Added 3 missing references and renumbered the rest to match the paper:

| New # | Reference | Status |
|-------|-----------|--------|
| [11]  | M. Rostamipoor et al., "KubeKeeper: Protecting Kubernetes Secrets Against Excessive Permissions," IEEE EuroS&P, 2025 | **ADDED** |
| [13]  | C. Cesarano & R. Natella, "KubeFence: Security Hardening of the Kubernetes Attack Surface," IEEE/IFIP DSN, 2025 | **ADDED** |
| [21]  | Open Policy Agent, "OPA — Open Policy Agent," CNCF Graduated Project, 2024 | **ADDED** |

Renumbering of existing refs:

| Old # | New # | Author / title | Note |
|-------|-------|----------------|------|
| [11] Sissodiya | **[12]** | Formal Verification… | shifted |
| [12] Chandramouli | **[14]** | Zero Trust… | shifted |
| [13] "H. Nguyen" PerfSPEC | **[15]** | PerfSPEC… | **author corrected → H. Kermabon-Bobinnec** |
| [14] Kern | **[16]** | Optimization of Access Control… | shifted |
| [15] Liu | **[17]** | Fast/Scalable XACML… | shifted |
| [16] Ma | **[18]** | ABAC Knowledge Graph… | shifted |
| [17] Pang | **[19]** | Zanzibar… | shifted |
| [18] Davari | **[20]** | ABAC→RBAC conversion… | shifted |

Layout rebalanced: left column [1]–[10], right column [11]–[21].

## B. Related Work slide — citation markers updated for new numbering

- Box 1 (Hardening): added "[11] KubeKeeper protects secrets…"; "formal verification [11]" → **[12]**.
- Box 2 (RBAC/Zero Trust): added "[13] KubeFence…"; Zero Trust [12]→**[14]**, PerfSPEC [13]→**[15]**, optimization [14]→**[16]**.
- Box 3 (Graph-based): compiled-XACML [15]→**[17]**, graph AC [8,16]→**[8,18]**, Zanzibar [17]→**[19]**, ABAC→RBAC [18]→**[20]**.

## C. Experiment 3 slide — added OPA citation

Title: "Policy Update Latency vs. OPA" → "…vs. OPA **[21]**".

## D. Experiment 1 (Key Results) — speedup wording

"**14–15×** speedup over SSO" → "**~14×** speedup over SSO" (matches paper).

## E. Experiment 2 (Key Results) — crossover points corrected (paper + CSV)

| Model | Was | Now |
|-------|-----|-----|
| ABAC  | crossover k≈18 | **k≈20** (paper) |
| RBAC  | crossover k≈15 | **k≈20** (CSV: 1.01× at k=20) |
| ACL   | crossover k≈35 | **k≈30** (CSV: 0.85× @20 → 1.27× @40) |

## F. Hash-consing slide — clarified node counts

The drawing is a 2-policy toy (6 nodes → 5 nodes). Relabeling those to 11/8 would
contradict the actual figure, so instead:
- Header now reads "Naïve tree — 6 nodes *(2-policy illustration)*".
- The paper's canonical result elevated to the takeaway (bold teal):
  "Paper's full P1–P4 example: **11 nodes → 8 nodes**".

---

## Speaker script (speaker_script.md) — FIXED

- Slide 14: "Here are all **18** references" → "**21** references". ✅
- Slide 6: "**amber** dashed line … decision cache" — **left unchanged on purpose**:
  in the LaTeX deck the cache-hit arrow is amber (`uhapAmberBorder`), so the script
  already matches the slide. (It only looked "green" in the old Canva PDF export.)

---

## NOT changed / out of scope

- `slides_uhap.pptx` (Canva, 3.3 MB) and the old reviewed `slides_uhap.pdf` export —
  binary Canva design, not programmatically editable; it carried the **wrong title**
  ("Unified Heterogeneous Authorization Protocol") and IEEE logo. The LaTeX deck
  already has the correct title: "Unified Authorization over Heterogeneous Policies".
- `build_pptx.py` still contains the same content bugs (refs, crossover, 14–15×,
  wrong PerfSPEC author). Fix it too only if you intend to regenerate the editable PPTX
  (needs `python-pptx`, currently not installed).
