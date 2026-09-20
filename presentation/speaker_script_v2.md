# U-HAP — Presentation Speaker Script (VERSION 2 — compact / shortest)
## JCSSE 2026 · Target runtime: 12 minutes

> **bold** = stress it · *italic* = slow down · `[PAUSE]` = let it land · `[CLICK]` = advance

---

## SLIDE 1 — Title · ⏱ 0:00–0:20

Good morning. I'm Krittapak, presenting **U-HAP** — Unified Authorization over Heterogeneous Policies in Kubernetes.
Joint work with Singha and Phisitphon, supervised by Asst. Prof. Dr. Somchart Fugkeaw at SIIT, Thammasat University.

---

## SLIDE 2 — Background · ⏱ 0:20–1:00

In Kubernetes, once a user is **authenticated**, every API call becomes a **SubjectAccessReview** sent to the authorization phase. U-HAP plugs in as a **webhook authorizer**.

Four models recur in this talk: **RBAC** (roles), **ABAC** (attributes), **ACL** (named lists), and **Deny** (always wins).

`[PAUSE]`
Many orgs add **SSO** — single sign-on. But *SSO solves authentication — who you are. Not authorization — what you may do.*
After SSO, every resource still enforces its own model. *That fragmentation is our problem.*

---

## SLIDE 3 — Related Work · ⏱ 1:00–1:50

Prior work falls in three groups.

**One — hardening and misconfiguration:** NSA/CISA guidance, EPScan, formal verification. They check *individual* policies, not unified authorization.

**Two — RBAC, Policy-as-Code, Zero Trust:** native RBAC, Zero Trust, compile-time optimization. All stay *within one model* — multi-layer setups still re-evaluate redundantly.

**Three — expressive and graph-based:** XACML is powerful but heavyweight; Zanzibar scales but needs runtime graph traversal; ABAC-to-RBAC tools only convert.

`[PAUSE]`
*The gap:* no one unifies RBAC, ABAC, ACL, and deny while staying fast. **That's U-HAP.**

---

## SLIDE 4 — Motivation · ⏱ 1:50–2:45

Kubernetes is the standard for production containers. A real cluster has dozens to hundreds of **namespaces** — different teams, different security needs.

The core issue: namespaces don't agree on *how* to express authorization.
`[PAUSE]`
A uses RBAC, B uses ABAC, C uses ACL. *They speak different languages about who gets access.*

That gives three problems: **semantic fragmentation**, **non-deterministic conflicts**, and **runtime inefficiency** from scanning every rule per request.
*SSO doesn't fix this — authorization stays fragmented, slow, inconsistent.*

---

## SLIDE 5 — Our Solution · ⏱ 2:45–3:45

U-HAP's idea is simple: *don't solve the hard problem at request time — solve it offline.*

`[PAUSE]`
Think compiler versus interpreter. A compiler does the work once, upfront. We do that for authorization.

U-HAP **compiles** RBAC, ABAC, and ACL into **indexed artifacts** — C subscript n-r-a — one tuned structure per namespace–resource–action.

At request time: one **O(1)** lookup, then evaluate. *No parsing, no graph traversal, no conflict logic — it's already baked in.*

Contributions: a **universal semantic graph**, **hash consing**, **two-level pruning**, and **deterministic deny-overrides-all**.

---

## SLIDE 6 — System Architecture · ⏱ 3:45–5:25

`[PAUSE — let them read the diagram]`

The **top pipeline is Phase 2 — compilation.** On a policy change: parse, validate, build a hash-consed DAG, compile artifacts, store in the registry. Runs *once per policy change* — not per request.

The **bottom pipeline is Phase 3 — every request.** A SubjectAccessReview arrives, O(1) lookup, two-level pruning, evaluate, return ALLOW or DENY with an audit log.
The amber dashed line is the **decision cache** — a hit skips everything.

`[PAUSE]`
Three phases:
**Phase 1 — Setup**, at deploy: load and validate policies. Zero request-time cost.
**Phase 2 — Compilation**, per policy change: hash-consed DAG plus four artifacts per triple.
**Phase 3 — Request-time**: lookup, prune, evaluate, decide.
*By the time a request arrives, the hard reasoning is done.*

---

## SLIDE 7 — Hash Consing · ⏱ 5:25–6:40

Hash consing is a core contribution.

Take the paper's four policies, P1–P4, over four atoms: *a1 on-premise, a2 business-hours, a3 engineering, a4 top-secret.*
They share sub-expressions: **(a1 OR a2)** is in P1 and P2; **(a2 AND a3)** is in P2, P3, and P4.

A naive tree rebuilds those — seven gate copies plus four atoms, **11 nodes** — and re-evaluates the same logic again and again.
`[PAUSE]`
**Hash consing**: before making a node, reuse an identical one if it exists. Seven gates collapse to four — **8 nodes**, each evaluated *once* and memoized.

`[PAUSE]`
Right side — four artifacts per triple: **I-deny** (token-pruned deny set), **I-acl** (O(1) hash set), **b-rbac** (bit-vector), **I-abac** (cost-sorted gate list).
Order: Cache → Deny → ACL → RBAC → ABAC → Default Deny. *The DAG is compile-time only.*

---

## SLIDE 8 — Two-Level Pruning · ⏱ 6:40–7:40

We don't evaluate all four models every time.

**Level 1 — policy-type pruning**, before touching any index:
No deny rules? Skip deny. No roles? Skip RBAC. No attributes? Skip ABAC. One O(1) check drops whole model classes.

**Level 2 — token-driven pruning**, inside each model:
`[PAUSE]`
ACL — one hash lookup.
RBAC — one **bitwise AND**: we precompute the transitive closure and encode roles as bits, so the check is `b_user AND b_rbac ≠ 0`. *One op, any number of roles.*
ABAC — an attribute-key index trims the gate list first.

And the invariant: **deny is always checked first** — enforced at compile time, can't be bypassed.

---

## SLIDE 9 — Evaluation Setup · ⏱ 7:40–8:20

Baseline: conventional **SSO-style** sequential scanning with runtime role resolution and hierarchy traversal.

**In-memory only** — no network. Median of **1,000 iterations**, 50 warm-ups. AMD Ryzen 9 7945HX, 32 GB.

Each namespace: 46 rules — 10 RBAC, 20 ABAC, 10 ACL, 1 deny, 5 hierarchy edges. ABAC uses AND/OR/ATLEAST gates with **~50% atom sharing** — where hash consing pays off.

---

## SLIDE 10 — Experiment 1: Scaling Namespaces · ⏱ 8:20–9:20

How does latency scale from 10 to 1,000 namespaces?

`[PAUSE]`
U-HAP is *flat* — the O(1) lookup goes straight to C_{n,r,a}.
The SSO baseline grows linearly — it scans and traverses every request.

Result: about **1.7× lower latency**, and with caching, **~14×** on repeated requests.
*990 extra namespaces have zero effect on the one you care about.*

---

## SLIDE 11 — Experiment 2: Policy Size · ⏱ 9:20–10:20

Now grow rules per namespace from k=5 to k=320.

**ABAC** — hash-consed DAG: **16.9×** at k=320, crossover at k≈20.
**RBAC** — bit-vector: **5.6×**, one AND regardless of count.
**ACL** — hash set: **5.0×**, near-constant.

`[PAUSE]`
The baseline scans ~k/2 rules — linear in k. Our indexes are effectively O(1), so the speedup grows with k.

---

## SLIDE 12 — Experiment 3: Updates vs. OPA · ⏱ 10:20–11:20

How fast is the update path? We compared edit-to-first-decision against **OPA**, the CNCF policy engine. Every policy was translated to Rego; a gate confirmed **100/100 identical decisions**.

`[PAUSE]`
At n=2,000: U-HAP **223 ms** vs OPA **611 ms** — **2.73×**.
Post-parse, engine only: **31 ms vs 611 ms — 19.5×**.
Footprint stays under **2.7 MB**.

*Offline compilation pays off twice — faster requests and faster updates.*

---

## SLIDE 13 — Conclusion · ⏱ 11:20–11:40

U-HAP is a **compilation-driven, index-based** Kubernetes webhook unifying RBAC, ABAC, and ACL under one semantic graph with **deterministic deny-override**.

Numbers: **≈1.7×** lower latency, flat to 1,000 namespaces · **14×** caching · **16.9×** ABAC at k=320 · **2.73×** faster updates than OPA · **19.5×** engine-only.

*Compile, don't scan. Share, don't repeat. Prune early, prune deep.*

---

## SLIDE 14 — References · ⏱ 11:40–11:50

All **21 references** are cited here; full details in the proceedings.

---

## SLIDE 15 — Thank You · ⏱ 11:50

*(Stand, invite questions.)*

---

## Q&A — Backup Slides Ready

- **B4 (RBAC bit-vector)** — "how does the RBAC speedup work?"
- **B7 (DSL example)** — "what does a policy file look like?"
- **B8 (Comparison table)** — "how vs. OPA/Keycloak?"
- **B2 (S1–S7)** — "how do you verify correctness?"
- **B9 (Limitations)** — "what are the limits?"

---

## Quick-Reference: Key Numbers

| Metric | Value |
|--------|-------|
| U-HAP vs SSO latency | **≈1.7×** lower (flat to N=1,000) |
| Caching speedup | **~14×** |
| ABAC speedup at k=320 | **16.9×** |
| RBAC speedup at k=320 | **5.6×** |
| ACL speedup at k=320 | **5.0×** |
| ABAC crossover | k≈20 |
| Update E2E n=2,000 (U-HAP / OPA) | **223 ms / 611 ms** |
| Update speedup E2E / engine-only | **2.73× / 19.5×** |
| Compiled footprint | **≤2.7 MiB** |
| Hash consing nodes (P1–P4) | **11 → 8** |
| Atom sharing in ABAC workload | **~50%** |

---

## Likely Q&A

**Q: Why Python? Wouldn't Go/Rust be faster?**
> Yes — that's future work. Current latency is dominated by Python/Gunicorn HTTP overhead (~0.68 ms), not the algorithm; the ABAC engine runs under 0.02 ms. Go/Rust would cut per-request overhead by ~10×.

**Q: How do you handle conflicts between models?**
> Deny always wins. I_deny is evaluated first, before any allow path — enforced at compile time. Any deny match → DENY.

**Q: What does a policy file look like?**
> [B7] Simple YAML: namespace and resource, then rules with a type — rbac, abac, acl, deny, or hierarchy. All five compile into the four artifacts.

**Q: Is the DAG traversed at runtime?**
> No — compile-time only. At runtime we hit hash sets, bit-vectors, and the ABAC gate list directly.

**Q: How do you ensure correctness?**
> [B2] Seven scenarios S1–S7 cover every model path and the deny invariant — all pass. Plus a hash-consing gate (the four-policy example must give exactly 8 nodes) and a role-closure suite.

**Q: Current limitations?**
> [B9] Single-namespace scope (no ClusterRoles), updates need a restart (no hot-reload), and authentication is out of scope.
