# U-HAP — Presentation Speaker Script
## JCSSE 2026 · Target runtime: 10 minutes

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

## SLIDE 2 — Motivation
### ⏱ 0:20 – 1:20 (60 seconds)

Let me start with the problem we are trying to solve.

Kubernetes has become the standard platform for running containerized applications in production.
In a real organization, a cluster might have dozens or even hundreds of **namespaces**, each owned by a different team, each with different security requirements.

Here is the core issue: those namespaces do not agree on *how* to express authorization.
`[PAUSE]`
Namespace A might use **RBAC** — you grant access by assigning roles to users.
Namespace B might use **ABAC** — you grant access based on the attributes of the request, like time of day or network location.
Namespace C might use a simple **ACL** — an explicit list of who is allowed.

These three models are not just different in syntax — *they speak completely different languages when deciding who gets access to what*.

This creates three serious problems.
`[PAUSE]`
First, **semantic fragmentation**: each model evaluates rules independently, and there is no standard way to combine their decisions.

Second, **non-deterministic conflict behavior**: if an RBAC rule says "allow" and an ACL says "deny" for the same request, which one wins?
In most systems, the answer depends on evaluation order — and that inconsistency is a real security risk.

Third, **runtime inefficiency**: every request triggers a full scan through all rules, even rules that could never apply to this particular user or this particular resource.

*Even with SSO handling authentication, authorization across multiple resources remains fragmented, slow, and inconsistent.*

---

## SLIDE 3 — Our Solution: U-HAP
### ⏱ 1:20 – 2:20 (60 seconds)

Our answer is **U-HAP**, and the central idea is simple:
*do not solve the hard problem at request time — solve it offline.*

`[PAUSE]`
Think of the difference between a compiler and an interpreter.
An interpreter reads your code and executes it every time you run the program.
A compiler processes the code once upfront and produces efficient machine instructions that run directly.
We do exactly the same thing for authorization.

U-HAP **compiles** all your policies — RBAC, ABAC, and ACL — into what we call **indexed artifacts**, denoted C subscript n-r-a.
For every combination of namespace, resource, and action, the compiler produces a small, flat data structure tuned for exactly that query.

At request time, you look up the right artifact in one step — **O(1)** — and evaluate it directly.
No parsing. No graph traversal. No conflict resolution logic.
*All of that complexity is already baked into the artifact.*

The system has three phases:
**Phase 1** — setup at deploy time, one-time cost.
**Phase 2** — compilation, triggered whenever policies change.
**Phase 3** — evaluation, happening at every single authorization request.

The key contributions are: a **universal semantic graph** that captures all three models in one unified structure, **hash consing** to eliminate redundant sub-expression evaluation, **two-level pruning** to skip irrelevant models early, and a **deterministic deny-overrides-all rule** that holds across every model.

---

## SLIDE 4 — System Architecture
### ⏱ 2:20 – 4:00 (100 seconds)

Here is the full system architecture.

`[PAUSE — let the audience look at the diagram]`

The **top pipeline** is Phase 2 — compilation.
When policies change, they move through the parser, get validated, are assembled into a hash-consed DAG, compiled into indexed artifacts C_{n,r,a}, and stored in the registry.
This pipeline runs *once per policy change* — not per request.

The **bottom pipeline** is Phase 3 — what happens at every request.
A Kubernetes SubjectAccessReview arrives, we do an O(1) registry lookup, apply two-level pruning to skip inactive models, evaluate the relevant indexes, and return ALLOW or DENY with an audit log.

The dashed line shows the compiled artifacts flowing from the registry into each request lookup.
The amber dashed line at the bottom is the decision cache — a cache hit short-circuits the entire evaluation pipeline.

`[PAUSE]`
Let me walk through each phase in detail.

**Phase 1 — Setup** happens once, at deploy time.
We load and validate the DSL policy files and initialize the system.
This cost is paid once and has *zero* impact on request latency.

**Phase 2 — Compilation** is where the interesting engineering happens.
We parse the DSL, build a **hash-consed DAG** — I will explain hash consing in a moment — and then compile four types of indexed artifacts per namespace-resource-action triple:
a deny candidate set, an ACL hash set, an RBAC bit-vector, and a sorted ABAC gate list.
Everything gets stored in the registry.
This phase runs once per **policy change**, not per request.

**Phase 3 — Request-time** is what every request sees, and it is deliberately simple.
`[PAUSE]`
Look up the artifact in O(1).
Apply pruning to skip models that cannot produce a decision.
Evaluate using the appropriate index — hash set for ACL, one bitwise AND for RBAC, or gate evaluation for ABAC.
Return the decision and write the audit log.

*By the time a request arrives, all the hard reasoning is already done.*

---

## SLIDE 5 — Hash Consing and Indexed Artifacts
### ⏱ 4:00 – 5:15 (75 seconds)

Hash consing is one of our core contributions, and it is worth taking a minute to explain it properly.

Consider four policies — P1, P2, P3, P4 — that all reference the same two conditions:
*"time is business hours"* and *"location is on-premise".*

In a naive tree representation, each policy builds its own copy of these conditions.
So you end up with four separate "time" nodes and four separate "location" nodes — **11 nodes** in total.
At request time, you evaluate the same time check four times and the same location check four times, even though the answer is identical each time.
`[PAUSE]`
**Hash consing** fixes this by asking: before creating a new node, have we already seen this exact sub-expression?
If yes, we reuse the existing node instead of creating a new one.
So there is only *one* "time" node and *one* "location" node in the DAG, shared by all four policies.
The result: **8 nodes** instead of 11 — and at request time, each node is evaluated *at most once*, with its result memoized.
As policy sets grow and predicates are reused across rules, this savings compounds.

`[PAUSE]`
Now, the right side of this slide shows the four indexed artifacts that the compiler produces for each namespace-resource-action triple.
**I-deny** is the deny candidate set — token-pruned so only candidates relevant to this caller are kept.
**I-acl** is the ACL hash set — O(1) membership test.
**b-rbac** is the RBAC bit-vector — I will explain this in a moment.
**I-abac** is the ABAC gate list, sorted by evaluation cost so cheap predicates run first.

The runtime order is always: Cache → Deny → ACL → RBAC → ABAC → Default Deny.
*The DAG is a compile-time artifact only — there is no graph traversal at request time.*

---

## SLIDE 6 — Two-Level Pruning Strategy
### ⏱ 5:15 – 6:15 (60 seconds)

Even with compiled indexes, we do not want to evaluate all four models for every request.
That is what two-level pruning handles.

**Level 1 — Policy-type pruning** operates before any index is touched.
We ask: does this namespace-resource-action triple even have deny rules?
If not, skip the deny phase entirely.
Does the caller carry any role assignments?
If not, skip RBAC.
Does the request carry any attributes?
If not, skip ABAC.
This eliminates entire model classes in a single O(1) check per class.

**Level 2 — Token-driven pruning** operates within each model.
`[PAUSE]`
For ACL: is the caller's user ID in the ACL hash set? One hash lookup.
For RBAC: do the caller's roles overlap with the allowed roles? One **bitwise AND** between two integers.
Here is how that works: at compile time, we compute the full transitive closure of the role hierarchy and encode every role as a position in a bit-vector.
A user's effective bit-vector is the OR of all their roles.
Checking RBAC is then just `b_user AND b_rbac ≠ 0`.
*One operation. Independent of how many roles exist.*

For ABAC: we use an attribute-key index to narrow the candidate gate list before any gate is evaluated.

And the most important invariant: **deny is always checked first**.
If any deny candidate matches — regardless of what any allow rule says in any other model — *the decision is DENY*.
This invariant is enforced at compile time and cannot be bypassed.

---

## SLIDE 7 — Evaluation Setup
### ⏱ 6:15 – 6:55 (40 seconds)

For evaluation, we benchmark against a conventional SSO-based baseline — a system that verifies access rights by evaluating policies sequentially, including repeated role resolution and hierarchy traversal at runtime.

All measurements are **in-memory only** — no network, no HTTP overhead. We use the median of **1,000 iterations** after 50 warm-ups to isolate pure algorithm cost. This lets us clearly see the compilation gains without any framework noise.

The hardware is an AMD Ryzen 9 7945HX with 32 GB RAM. Each namespace carries 46 rules — 10 RBAC, 20 ABAC, 10 ACL, 1 deny, 5 hierarchy edges. ABAC predicates use AND/OR/ATLEAST gates with about 50% atom sharing across rules — which is exactly the workload where hash consing pays off most.

---

## SLIDE 8 — Experiment 1: Policy Verification Efficiency
### ⏱ 6:55 – 7:55 (60 seconds)

Experiment 1 measures how authorization latency scales as the number of namespaces grows — from 10 to 1,000.

`[PAUSE]`
The key result: U-HAP's latency is *completely flat*. Whether the system has 10 or 1,000 namespaces, the per-request latency stays near-constant. This is the O(1) property of the indexed artifact lookup — you go directly to C_{n,r,a} for the namespace you need, and nothing else is touched.

The SSO baseline shows linear growth — at N=1,000, its cost is roughly proportional to the namespace count, because it performs sequential policy scanning including role hierarchy traversal for every single request.

U-HAP achieves approximately **1.7× lower latency** than the baseline through compiled evaluation — shared ABAC DAG, hash-set ACL, and bit-vector RBAC.

And with decision caching enabled, there's an additional **~14× speedup** on repeated requests — the cache bypasses evaluation entirely. That's the combination of compilation and caching working together.

*Adding 990 background namespaces has zero effect on the latency of the namespace you actually care about.*

---

## SLIDE 9 — Experiment 2: Policy Size Impact
### ⏱ 7:55 – 8:55 (60 seconds)

Experiment 2 asks: what happens as you add more rules to the same namespace? We vary k from 5 to 320 rules per model type.

The results follow a clear pattern: speedup grows monotonically with k, and each model benefits from its specific compilation technique.

For **ABAC** — the most complex model — the hash-consed DAG with 50% atom sharing delivers a **16.9× speedup** at k=320 rules. There's a crossover at around k=20 rules: below that, the compilation overhead isn't fully amortized yet, so you see a minor 0.7× overhead at k=5. But beyond the crossover, gains are dramatic and growing.

For **RBAC** — the bit-vector technique gives a **5.6× speedup** at k=320. The user's bit-vector AND with the policy bit-vector is one operation regardless of rule count.

For **ACL** — hash-set lookup gives **5.0× speedup** at k=320. Also near-constant.

`[PAUSE]`
The important message is: the SSO baseline scales linearly because it scans approximately k/2 rules per request. U-HAP's compiled indexes are effectively O(1) — so the speedup grows proportionally with k.

---

## SLIDE 10 — Experiment 3: Policy Update Latency vs. OPA
### ⏱ 8:55 – 9:55 (60 seconds)

The final experiment asks: how fast is the policy-update path? When you change a policy, how long before the new policy takes effect for the first request?

We compared the full edit-to-first-decision cycle against **OPA** — Open Policy Agent, the CNCF graduated policy engine. Every U-HAP policy set was mechanically translated to equivalent Rego, and an automated gate verified 100 out of 100 identical decisions at every policy count tested.

`[PAUSE]`
Looking at the table: at n=2,000 policies, U-HAP completes in **223 ms** versus OPA's **611 ms** — a **2.73× end-to-end speedup**.

But the more striking number is post-parse — measuring only the compilation and evaluation engine, after YAML parsing (which both engines pay equally). At n=2,000: **31 ms for U-HAP versus 611 ms for OPA — a 19.5× speedup**.

The pattern starts at 1.63× for n=10 and grows steadily to 2.73× at n=2,000, because U-HAP's compile-time hash consing scales sub-linearly while OPA's per-update Rego compilation scales proportionally.

And throughout all of this, the compiled-state footprint stays under **2.7 megabytes**.

*U-HAP's offline compilation pays off twice: faster at requests, and faster at propagating policy changes.*

---

## SLIDE 11 — Conclusion
### ⏱ 9:55 – 10:15 (20 seconds)

To summarize:
U-HAP is a **compilation-driven, index-based** Kubernetes authorization webhook that unifies RBAC, ABAC, and ACL under a single semantic graph with **deterministic deny-override** conflict resolution.

The results: **≈1.7×** lower latency vs. SSO baseline, flat to 1,000 namespaces. **14× speedup** with decision caching. **16.9×** ABAC speedup at k=320 rules, RBAC **5.6×**, ACL **5.0×**. **2.73× faster** policy updates than OPA. **19.5×** engine-only speedup at n=2,000.

And the design philosophy in three lines:
*Compile, don't scan.
Share, don't repeat.
Prune early, prune deep.*

Thank you. I am happy to take questions.

---

## Q&A DIVIDER SLIDE

No script needed — just stand and wait.
Keep these backup slides ready:
- **B4 (RBAC bit-vector)** — if asked "how does the RBAC speedup work exactly?"
- **B7 (DSL example)** — if asked "what does a policy file look like?"
- **B8 (Comparison table)** — if asked "how does this compare to OPA/Keycloak?"
- **B2 (S1–S7 scenarios)** — if asked "how do you verify correctness?"
- **B9 (Limitations)** — if asked "what are the limitations?"

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
> No. The DAG is a compile-time data structure only. At runtime, we evaluate the indexed artifacts directly — hash sets, bit-vectors, and the ABAC gate list. The gate list is the hash-consed evaluation of the relevant DAG nodes, precomputed into a sorted list. No graph traversal happens at request time.

**Q: How do you ensure correctness?**
> [Show B2] We have seven non-negotiable correctness scenarios, S1 through S7, that cover all model paths and the deny invariant. All seven pass in the implementation. We also have a hash consing gate that verifies the four-policy example produces exactly eight DAG nodes, and a role closure test suite.

**Q: What are the current limitations?**
> [Show B9] Three main ones: we only support single-namespace scope, so ClusterRoles are not supported. Policy updates require a restart — no hot-reload yet. And authentication is out of scope — U-HAP handles authorization only.
