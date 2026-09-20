# IEEE Reference Format Audit — U-HAP Camera-Ready

**Purpose.** Verify that every entry in the U-HAP bibliography conforms to
the IEEE Reference Guide (latest revision). This file is the working
checklist; final corrections feed into the camera-ready manuscript.

**Source bibliography.** Drop the active `.bib` (or the inline `\bibitem`
list from the manuscript) into `camera_ready_v1/references/refs_original.bib`
before running the audit.

---

## IEEE format reminders (the things reviewers actually flag)

| Rule | Correct | Wrong |
|------|---------|-------|
| Author order | `F. Last` (initials first) | `Last, F.` |
| Multiple authors | `A. B. Cee, D. E. Eff, and G. H. Iee` | `Cee A.B., Eff D.E., Iee G.H.` |
| Title (paper) | `"Title in sentence case,"` (quoted, comma inside quotes) | Title Case With No Quotes |
| Journal/Conf name | *Italicized*, IEEE-standard abbreviation | Full unabbreviated name |
| Volume/issue | `vol. 12, no. 3,` | `Vol. 12, No. 3,` or `12(3)` |
| Pages | `pp. 100–112,` (en-dash, not hyphen) | `pp. 100-112,` |
| Date | `Mar. 2025.` | `March 2025.` or `2025-03.` |
| DOI | `doi: 10.1109/...` | URL of dx.doi.org |
| Conference proceedings | `in *Proc. of the XX Int. Conf. on YY*, City, Country, YYYY, pp. ...` | inconsistent ordering |
| URL refs | `[Online]. Available: https://...` then access date | bare URL |
| Et al. usage | `A. B. Cee et al.,` only when ≥6 authors | et al. with 3 authors |

**IEEE conference abbreviations** to check against the official list:
INFOCOM, NOMS, IM, CNSM, ICDCS, GLOBECOM, ICC, IPDPS, SoCC, CCS, USENIX
Security, NDSS — all have specific IEEE/ACM-approved abbreviations.

---

## Audit table — fill one row per bibliography entry

> Copy this table per reference. Mark **OK** or write the correction needed.

| Entry | Field | Current | Correction |
|-------|-------|---------|------------|
| [1] | Author order | TODO | TODO |
| [1] | Title format | TODO | TODO |
| [1] | Venue abbrev. | TODO | TODO |
| [1] | Vol/no/pages | TODO | TODO |
| [1] | Date format | TODO | TODO |
| [1] | DOI present? | TODO | TODO |
| [2] | … | … | … |

---

## Cross-citation audit

**Orphan refs** — bibliography entries with no `\cite{}` in the body:
- TODO: list

**Dead refs** — `\cite{key}` keys not in bibliography:
- TODO: list

**Duplicate refs** — same paper cited under two keys:
- TODO: list

---

## How to run the audit

1. Drop bibliography at `camera_ready_v1/references/refs_original.bib`.
2. For each entry, open the original venue page (DOI, ACM DL, IEEE Xplore,
   conference site) and copy the canonical IEEE-formatted citation from
   "Cite this" → IEEE.
3. Fill the audit table above with corrections.
4. After all entries audited, write `refs_corrected.bib` and a one-line
   diff per entry into `audit_diff.md`.
5. The corrected bib gets applied in Workstream F4 (manuscript integration).

---

## Acceptance gate

- [ ] Every entry has been compared field-by-field against IEEE format.
- [ ] No orphan refs.
- [ ] No dead refs.
- [ ] No duplicate refs.
- [ ] All DOIs present where the venue assigns them.
- [ ] All page ranges use en-dash.
- [ ] All venue names use IEEE-standard abbreviations.
- [ ] Reference numbering remains sequential after any insertions/deletions.
