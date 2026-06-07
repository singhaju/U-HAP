# U-HAP — Presentation Speaker Script
## JCSSE 2026 · Target runtime: 12 minutes

> **How to read this script**
> - Text in **bold** = key terms to stress when speaking
> - Text in *italic* = slower delivery, let it land
> - `[PAUSE]` = stop briefly, let the audience catch up
> - `[CLICK]` = advance animation or next slide
> - Time targets are guides, not hard stops

---

## SLIDE 1 — Title
### ⏱ 0:00 – 0:20 (20 seconds)

Good morning, everyone.
My name is Krittapak, and today I will present our paper **U-HAP** — Unified Authorization over Heterogeneous Policies with Efficient Multi-Resource Verification in Kubernetes.

This is joint work with Singha and Phisitphon, under the supervision of Assistant Professor Dr. Somchart Fugkeaw at SIIT, Thammasat University.

---

## SLIDE 2 — Background: SSO and Access Control in Kubernetes
### ⏱ 0:20 – 1:00 (40 seconds)

Before diving into our work, let me set the context.

In Kubernetes, after a user is **authenticated**, every API call is packaged as a **SubjectAccessReview** and passed to an **authorization phase**. Kubernetes supports four built-in authorization modes — RBAC, ABAC, Node, and **Webhook** — and our system, U-HAP, plugs in as a webhook authorizer.

The four access-control models you will see throughout this talk are: **RBAC** — role-based, **ABAC** — attribute-based, **ACL** — explicit named list, and **Deny** — which always overrides any allow.

`[PAUSE]`
Now, many organizations also use **SSO** — Single Sign-On — which lets a user authenticate once with a single identity, for example via OIDC or Keycloak, and reuse it across services.
The key distinction: *SSO solves* ***authentication*** *— who you are. It does not solve* ***authorization*** *— what you may do.*
After SSO, each resource still enforces its own policy model independently.
*That fragmentation is the problem U-HAP addresses.*

---

## SLIDE 3 — Related Work and Its Limitations
### ⏱ 1:00 – 1:50 (50 seconds)

Let me briefly survey the related landscape and identify the gap we fill.

Existing work falls into three broad groups.

First, **hardening and misconfiguration** research — NSA/CISA guidance, empirical misconfiguration studies, tools like EPScan and formal verification approaches. These target the correctness of *individual* policies, not unified authorization across mixed models.

Second, **RBAC, Policy-as-Code, and Zero Trust** systems — Kubernetes native RBAC, Zero Trust architectures, compile-time optimization. These operate *within a single model*; multi-layer deployment still causes repeated, redundant evaluation.

Third, **expressive and graph-based models** — XACML is powerful but its heavyweight PDP is ill-suited to low-latency cloud-native. Zanzibar scales globally but requires runtime graph traversal. ABAC-to-RBAC conversion tools handle only interoperability, not unified evaluation.

`[PAUSE]`
*The gap*: no prior work offers a **unified** framework spanning RBAC, ABAC, ACL, and explicit deny that simultaneously eliminates redundant evaluation and guarantees scalable, low-latency multi-resource authorization.
**That is what U-HAP provides.**

---

## SLIDE 4 — Motivation: The Kubernetes Authorization Problem
### ⏱ 1:50 – 2:45 (55 seconds)

Let me now make this concrete.

Kubernetes has become the standard platform for running containerized applications in production.
In a real organization, a cluster might have dozens or even hundreds of **namespaces**, each owned by a different team, each with different security requirements.

Here is the core issue: those namespaces do not agree on *how* to express authorization.
`[PAUSE]`
Namespace A uses RBAC, Namespace B uses ABAC, Namespace C uses ACL — and these models are not just different in syntax.
*They speak completely different languages when deciding who gets access to what.*

This creates three serious problems: **semantic fragmentation** across models, **non-deterministic conflict behavior** when models disagree, and **runtime inefficiency** from full rule-scanning on every request.

*Even with SSO handling authentication, authorization remains fragmented, slow, and inconsistent.*

---

## SLIDE 5 — Our Solution: U-HAP
### ⏱ 2:45 – 3:45 (60 seconds)

Our answer is **U-HAP**, and the central idea is simple:
*do not solve the hard problem at request time — solve it offline.*

`[PAUSE]`
Think of the difference between a compiler and an interpreter.
A compiler processes the code once upfront and produces efficient machine instructions that run directly.
We do exactly the same thing for authorization.

U-HAP **compiles** all your policies — RBAC, ABAC, and ACL — into **indexed artifacts**, denoted C subscript n-r-a.
For every combination of namespace, resource, and action, the compiler produces a small, flat data structure tuned for exactly that query.

At request time, you look up the right artifact in one step — **O(1)** — and evaluate it directly.
No parsing. No graph traversal. No conflict resolution logic.
*All of that complexity is already baked into the artifact.*

The key contributions are: a **universal semantic graph**, **hash consing** to eliminate redundant sub-expression evaluation, **two-level pruning** to skip irrelevant models early, and a **deterministic deny-overrides-all rule** across every model.

---

## SLIDE 6 — System Architecture
### ⏱ 3:45 – 5:25 (100 seconds)

Here is the full system architecture.

`[PAUSE — let the audience look at the diagram]`

The **top pipeline** is Phase 2 — compilation.
When policies change, they move through the parser, get validated, are assembled into a hash-consed DAG, compiled into indexed artifacts C_{n,r,a}, and stored in the registry.
This pipeline runs *once per policy change* — not per request.

The **bottom pipeline** is Phase 3 — what happens at every request.
A Kubernetes SubjectAccessReview arrives, we do an O(1) registry lookup, apply two-level pruning, evaluate the relevant indexes, and return ALLOW or DENY with an audit log.

The amber dashed line at the bottom is the decision cache — a cache hit short-circuits the entire pipeline.

`[PAUSE]`
Let me walk through each phase.

**Phase 1 — Setup** happens once, at deploy time.
Load and validate the DSL policy files. Zero impact on request latency.

**Phase 2 — Compilation** builds a **hash-consed DAG** and compiles four artifact types per namespace-resource-action triple:
a deny candidate set, an ACL hash set, an RBAC bit-vector, and a sorted ABAC gate list.
Runs once per **policy change**.

**Phase 3 — Request-time** is deliberately simple.
Look up the artifact in O(1). Apply pruning. Evaluate. Return decision and write audit log.

*By the time a request arrives, all the hard reasoning is already done.*

---

## SLIDE 7 — Hash Consing and Indexed Artifacts
### ⏱ 5:25 – 6:40 (75 seconds)

Hash consing is one of our core contributions.

Consider four policies — P1, P2, P3, P4 — that all reference the same two conditions:
*"time is business hours"* and *"location is on-premise."*

In a naive tree, each policy builds its own copy of these conditions — **11 nodes** total.
At request time, you evaluate the same time check four times, even though the answer is identical.
`[PAUSE]`
**Hash consing** fixes this: before creating a new node, check if this exact sub-expression already exists. If yes, reuse it.
Result: **8 nodes** instead of 11 — and each node is evaluated *at most once*, with its result memoized.

`[PAUSE]`
The right side shows the four indexed artifacts produced per namespace-resource-action triple.
**I-deny** — deny candidate set, token-pruned to this caller.
**I-acl** — ACL hash set, O(1) membership test.
**b-rbac** — RBAC bit-vector.
**I-abac** — ABAC gate list, sorted by evaluation cost.

Runtime order: Cache → Deny → ACL → RBAC → ABAC → Default Deny.
*The DAG is compile-time only — no graph traversal at request time.*

---

## SLIDE 8 — Two-Level Pruning Strategy
### ⏱ 6:40 – 7:40 (60 seconds)

Even with compiled indexes, we do not want to evaluate all four models for every request.
That is what two-level pruning handles.

**Level 1 — Policy-type pruning** operates before any index is touched.
Does this triple even have deny rules? No → skip deny.
Does the caller carry role assignments? No → skip RBAC.
Does the request carry attributes? No → skip ABAC.
One O(1) check eliminates entire model classes.

**Level 2 — Token-driven pruning** operates within each model.
`[PAUSE]`
ACL: one hash lookup.
RBAC: one **bitwise AND** — at compile time we compute the full transitive closure and encode every role as a bit position. Checking RBAC is `b_user AND b_rbac ≠ 0`. *One operation, independent of role count.*
ABAC: attribute-key index narrows the candidate gate list before evaluation.

And the most important invariant: **deny is always checked first**, enforced at compile time and cannot be bypassed.

---

## SLIDE 9 — Evaluation Setup
### ⏱ 7:40 – 8:20 (40 seconds)

We benchmark against a conventional SSO-based baseline — sequential policy scanning with repeated role resolution and hierarchy traversal at runtime.

All measurements are **in-memory only** — no network, no HTTP overhead. Median of **1,000 iterations** after 50 warm-ups. Hardware: AMD Ryzen 9 7945HX, 32 GB RAM.

Each namespace carries 46 rules — 10 RBAC, 20 ABAC, 10 ACL, 1 deny, 5 hierarchy edges. ABAC predicates use AND/OR/ATLEAST gates with 50% atom sharing — exactly where hash consing pays off most.

---

## SLIDE 10 — Experiment 1: Policy Verification Efficiency
### ⏱ 8:20 – 9:20 (60 seconds)

Experiment 1 measures how latency scales as namespaces grow — from 10 to 1,000.

`[PAUSE]`
The key result: U-HAP's latency is *completely flat*. The O(1) artifact lookup goes directly to C_{n,r,a} — nothing else is touched.

The SSO baseline shows linear growth — full rule scanning including role hierarchy traversal for every request.

U-HAP achieves approximately **1.7× lower latency** through compiled evaluation.
With decision caching, an additional **~14× speedup** on repeated requests.

*Adding 990 background namespaces has zero effect on the namespace you actually care about.*

---

## SLIDE 11 — Experiment 2: Policy Size Impact
### ⏱ 9:20 – 10:20 (60 seconds)

Experiment 2: what happens as rules per namespace grow from k=5 to k=320?

For **ABAC** — hash-consed DAG with 50% atom sharing: **16.9× speedup** at k=320.
Crossover at k≈20 — below that, compilation overhead isn't amortized.

For **RBAC** — bit-vector gives **5.6× speedup** at k=320. One AND regardless of rule count.

For **ACL** — hash-set gives **5.0× speedup** at k=320. Near-constant.

`[PAUSE]`
The SSO baseline scans ~k/2 rules per request — linear with k. U-HAP's compiled indexes are effectively O(1), so speedup grows proportionally with k.

---

## SLIDE 12 — Experiment 3: Policy Update Latency vs. OPA
### ⏱ 10:20 – 11:20 (60 seconds)

The final experiment: how fast is the policy-update path?

We compared the full edit-to-first-decision cycle against **OPA** — Open Policy Agent, the CNCF graduated policy engine. Every U-HAP policy was translated to equivalent Rego and an automated gate verified 100 out of 100 identical decisions.

`[PAUSE]`
At n=2,000 policies: U-HAP **223 ms** vs OPA **611 ms** — **2.73× end-to-end speedup**.

Post-parse — measuring only the compilation and evaluation engine: **31 ms vs 611 ms — a 19.5× speedup**.

The compiled-state footprint stays under **2.7 megabytes** throughout.

*U-HAP's offline compilation pays off twice: faster at requests, and faster at propagating policy changes.*

---

## SLIDE 13 — Conclusion
### ⏱ 11:20 – 11:40 (20 seconds)

To summarize:
U-HAP is a **compilation-driven, index-based** Kubernetes authorization webhook that unifies RBAC, ABAC, and ACL under a single semantic graph with **deterministic deny-override** conflict resolution.

The results: **≈1.7×** lower latency, flat to 1,000 namespaces. **14×** caching speedup. **16.9×** ABAC speedup at k=320. **2.73×** faster policy updates than OPA. **19.5×** engine-only speedup.

*Compile, don't scan. Share, don't repeat. Prune early, prune deep.*

---

## SLIDE 14 — References
### ⏱ 11:40 – 11:50 (10 seconds)

Here are all 18 references cited in the paper.
You can find the full details in the conference proceedings.

---

## SLIDE 15 — Thank You
### ⏱ 11:50 (no time limit)

*(No script — just stand and invite questions.)*

---

## Q&A — Keep These Backup Slides Ready

- **B4 (RBAC bit-vector)** — "how does the RBAC speedup work exactly?"
- **B7 (DSL example)** — "what does a policy file look like?"
- **B8 (Comparison table)** — "how does this compare to OPA/Keycloak?"
- **B2 (S1–S7 scenarios)** — "how do you verify correctness?"
- **B9 (Limitations)** — "what are the limitations?"

---

## Quick-Reference: Key Numbers

| Metric | Value |
|--------|-------|
| U-HAP vs SSO baseline latency | **≈1.7×** lower (flat to N=1,000) |
| Caching speedup (repeated requests) | **~14×** |
| ABAC speedup at k=320 rules | **16.9×** |
| RBAC speedup at k=320 rules | **5.6×** |
| ACL speedup at k=320 rules | **5.0×** |
| ABAC crossover point | k≈20 rules |
| Policy update E2E at n=2,000 (U-HAP) | **223 ms** |
| Policy update E2E at n=2,000 (OPA) | **611 ms** |
| Update speedup E2E | **2.73×** |
| Update speedup engine-only | **19.5×** |
| Compiled footprint | **≤2.7 MiB** |
| Hash consing: naïve nodes (P1–P4) | **11** |
| Hash consing: DAG nodes (P1–P4) | **8** |
| Atom sharing in ABAC workload | **~50%** |

---

## Likely Q&A Questions and Key Answers

**Q: Why Python? Wouldn't Go or Rust be faster?**
> Yes, and that is our primary future work. The current latency is dominated by Python/Gunicorn HTTP overhead (~0.68 ms), not by the algorithm itself. The ABAC engine runs in under 0.02 ms natively. A Go or Rust implementation would reduce per-request overhead by roughly an order of magnitude.

**Q: How do you handle policy conflicts between models?**
> Deny always wins. The deny-overrides-all invariant is enforced at compile time: the deny index I_deny is always evaluated first, before any allow path in ACL, RBAC, or ABAC. If any deny candidate matches the request, the decision is DENY regardless of what any allow rule says.

**Q: What does a policy file look like?**
> [Show B7] It is a simple YAML file. You declare the namespace and resource at the top, then list rules, each with a type field — rbac, abac, acl, deny, or hierarchy. ABAC rules include a predicate string with attribute conditions. All five rule types compile into the four indexed artifacts.

**Q: Is the DAG traversed at runtime?**
> No. The DAG is a compile-time data structure only. At runtime, we evaluate the indexed artifacts directly — hash sets, bit-vectors, and the ABAC gate list. No graph traversal happens at request time.

**Q: How do you ensure correctness?**
> [Show B2] We have seven non-negotiable correctness scenarios, S1 through S7, that cover all model paths and the deny invariant. All seven pass in the implementation. We also have a hash consing gate that verifies the four-policy example produces exactly eight DAG nodes, and a role closure test suite.

**Q: What are the current limitations?**
> [Show B9] Three main ones: we only support single-namespace scope, so ClusterRoles are not supported. Policy updates require a restart — no hot-reload yet. And authentication is out of scope — U-HAP handles authorization only.
