# U-HAP — Presentation Speaker Script (VERSION 4 — formal / spoken / recommended)
## JCSSE 2026 · Target runtime: 12 minutes

> **How to use this version**
> The register is formal — it represents the paper at a conference — but it is written
> to be *spoken*, not read silently. Sentences are short and built for the voice.
> **bold** = stress this word. *italic* = slow down. `[PAUSE]` = stop briefly and let it land.

---

## SLIDE 1 — Title · ⏱ 0:00 – 0:20

Good morning. My name is Krittapak. Today I will present our paper, **U-HAP** — Unified Authorization over Heterogeneous Policies with Efficient Multi-Resource Verification in Kubernetes.

This is joint work with Singha and Phisitphon, supervised by Assistant Professor Doctor Somchart Fugkeaw, at SIIT, Thammasat University.

---

## SLIDE 2 — Background · ⏱ 0:20 – 1:05

I will begin with the two concepts on which this work rests.

The first is how Kubernetes performs authorization. After a user is authenticated, every API request is expressed as a **SubjectAccessReview** and passed to an authorizer, which returns an allow or a deny decision. Kubernetes supports several authorizer modes, and one of them is a **webhook** mode that delegates the decision to an external service. U-HAP is deployed as that webhook authorizer.

The second concept is the set of access-control models. Four of them recur throughout this presentation. **RBAC** grants access according to roles. **ABAC** grants access according to attributes, such as the time of a request or its network origin. **ACL** is an explicit list of permitted subjects. And **deny** is an explicit prohibition that takes precedence over all others.

`[PAUSE]`
I would also like to address a common assumption. Many organizations adopt single sign-on, or **SSO**. However, SSO establishes only identity — that is, *authentication*. It does not determine permissions — that is, *authorization*. Therefore, even with SSO in place, each resource must still enforce its own model independently. *This fragmentation is the problem our work addresses.*

---

## SLIDE 3 — Related Work · ⏱ 1:05 – 1:50

Before presenting our approach, I will position it against existing work, which falls into three groups.

The **first** group concerns hardening and misconfiguration — for example, the NSA and CISA guidance, configuration scanners, and formal verification. These approaches verify the correctness of an *individual* policy. They do not unify authorization across multiple models.

The **second** group concerns RBAC, policy-as-code, and zero-trust architectures. These are effective, but each operates *within a single model*. When several are layered together, the system re-evaluates the same conditions redundantly.

The **third** group concerns expressive and graph-based models. XACML is highly expressive, but it relies on a heavy policy engine. Zanzibar scales globally, but it requires graph traversal at request time. And the ABAC-to-RBAC tools only translate between models.

`[PAUSE]`
The common gap is clear. *No existing framework unifies RBAC, ABAC, ACL, and deny while preserving low latency.* **That is the gap U-HAP fills.**

---

## SLIDE 4 — Motivation · ⏱ 1:50 – 2:35

Let me make the problem concrete.

A production Kubernetes cluster commonly contains dozens or hundreds of **namespaces**. Each is typically owned by a different team, with distinct security requirements. The fundamental difficulty is that these namespaces do not agree on *how* authorization should be expressed.

`[PAUSE]`
One namespace may use RBAC, another ABAC, and another ACL. These are not superficial differences in syntax. The models reason about access in fundamentally different ways.

This produces three problems. First, the authorization semantics are **fragmented** across models. Second, when two models disagree, the conflict behavior becomes **non-deterministic**. And third, the system incurs **runtime overhead**, because it scans every rule on each request. As I noted, SSO does not resolve any of these.

---

## SLIDE 5 — Our Solution · ⏱ 2:35 – 3:30

Our central idea is to move the difficult work off the request path and perform it in advance.

`[PAUSE]`
The principle is analogous to a **compiler** and an **interpreter**. An interpreter re-analyzes the program on every execution. A compiler performs that analysis once and produces an artifact that runs efficiently. U-HAP applies the compiler model to authorization.

U-HAP compiles the RBAC, ABAC, and ACL policies into **indexed artifacts**. For each combination of a namespace, a resource, and an action, the compiler produces one compact structure, tuned to that specific query. At request time, the system performs a single **constant-time lookup** and evaluates the artifact directly. There is no parsing, no graph traversal, and no conflict resolution on the request path, because all of that has been resolved during compilation.

This yields four contributions — a **universal semantic graph**, **hash consing**, **two-level pruning**, and **deterministic deny-overrides-all** conflict resolution.

---

## SLIDE 6 — System Architecture · ⏱ 3:30 – 4:45

The system is organized into **three phases**, and the design depends on *where* each phase executes.

`[PAUSE — allow the audience to read the diagram]`

**Phase one is setup.** It is performed once, at deployment. It loads and validates the policies, and it adds no cost to request processing.

**Phase two is compilation**, shown as the upper pipeline. It runs once per policy change. It parses and validates the policies, constructs a hash-consed graph, and compiles four artifacts for each triple — a deny candidate set, an ACL hash set, an RBAC bit-vector, and a cost-sorted ABAC gate list.

**Phase three is request-time evaluation**, shown as the lower pipeline. It executes on every request. The system performs the constant-time lookup, applies two-level pruning, evaluates the remaining indices, and returns the decision together with an audit record. The dashed path is the **decision cache**. On a repeated request, a cache hit bypasses the pipeline entirely.

`[PAUSE]`
The guiding principle is that, by the time a request arrives, the substantive reasoning has already been completed.

---

## SLIDE 7 — Hash Consing · ⏱ 4:45 – 5:50

Hash consing is the mechanism that eliminates redundant work, so I will explain it briefly.

In practice, policies share logic. Consider the four policies from the paper, defined over four atomic conditions. The expression *a1 or a2* appears in two of them, and the expression *a2 and a3* appears in three.

If these policies are represented as independent trees, each policy holds its own copy of the shared sub-expressions. This produces seven gate instances and four atoms — **eleven nodes** in total — and the shared logic is re-evaluated repeatedly at request time.

`[PAUSE]`
**Hash consing** applies a single rule. Before a node is created, an identical existing node is reused if one is present. The seven gate instances therefore reduce to four unique gates, so eleven nodes become **eight**. Because each node is unique, it is evaluated at most once per request, and the result is memoized.

I want to emphasize one point. *The graph exists only at compile time. It is never traversed during a request.* At runtime, the system consults the flat artifacts in a fixed order — cache, then deny, then ACL, then RBAC, then ABAC, and finally default deny.

---

## SLIDE 8 — Two-Level Pruning · ⏱ 5:50 – 6:45

Even after compilation, it is unnecessary to evaluate all four models on every request, so the system prunes at two levels.

The **first level** eliminates entire models before any index is consulted. If the triple has no deny rules, deny is skipped. If the subject holds no roles, RBAC is skipped. If the request carries no attributes, ABAC is skipped. Each test is a single constant-time check, and it can remove an entire class of models.

The **second level** prunes within each surviving model.
`[PAUSE]`
ACL requires one hash lookup. RBAC requires one bitwise AND, because the role hierarchy is flattened into its transitive closure at compile time, and each role is encoded as a single bit. The check is therefore one operation, regardless of the number of roles. ABAC uses an attribute-key index to reduce the candidate gates before evaluation.

Underlying all of this is the central guarantee. **Deny is always evaluated first.** That ordering is enforced at compile time, so it cannot be bypassed.

---

## SLIDE 9 — Evaluation Setup · ⏱ 6:45 – 7:20

A brief note on methodology.

The baseline is a conventional, SSO-style evaluator. It scans the policies sequentially, and it resolves roles and traverses the hierarchy at request time. All measurements are performed in memory, without network or HTTP overhead, in order to isolate the algorithm itself. Each value is the median of one thousand iterations, following fifty warm-up runs, on an AMD Ryzen 9 processor with 32 gigabytes of memory. Each namespace contains forty-six rules, and the ABAC predicates share approximately half of their atoms, which is precisely the condition under which hash consing is effective.

---

## SLIDE 10 — Experiment 1: Policy Verification Efficiency · ⏱ 7:20 – 8:15

The first experiment scales the number of namespaces from ten to one thousand.

`[PAUSE]`
The result is the key contrast. U-HAP stays **flat**, because the constant-time lookup goes straight to the right artifact, whereas the baseline grows **linearly**, scanning on every request. That is about **1.7 times** lower latency, and roughly **14 times** once caching is enabled.

The conceptual result is that adding 990 background namespaces has no measurable effect on the one namespace under evaluation.

---

## SLIDE 11 — Experiment 2: Policy Size Impact · ⏱ 8:15 – 9:10

The second experiment packs more rules into a single namespace, from five up to three hundred and twenty.

The headline is that **U-HAP wins across every access-control model**. The clearest case is **ABAC**, which reaches roughly **16.9 times** at high density through the hash-consed graph; RBAC and ACL improve in the same way through their own indices.

`[PAUSE]`
And the advantage *grows* with size, because the reason is structural. The baseline scans about half the rules, so it climbs with the rule count, while our compiled indices stay effectively constant-time.

---

## SLIDE 12 — Experiment 3: Policy Update Latency vs. OPA · ⏱ 9:10 – 10:15

The final experiment measures the update path — how fast a policy *change* takes effect.

We compare against **OPA**, the Open Policy Agent, the industry-standard, CNCF-graduated policy engine. The distinction is again compilation versus interpretation. OPA interprets at request time; we compile in advance. To keep it fair, we translated every policy into OPA's language, Rego, and confirmed all one hundred of one hundred decisions matched.

`[PAUSE]`
At two thousand policies, U-HAP is about **2.7 times** faster end to end — 223 milliseconds against 611 — and **19.5 times** faster on the engine alone, all in under **2.7 megabytes**.

So compilation pays off a benefit twice with faster requests, and faster policy rollout.

---

## SLIDE 13 — Conclusion and Future Work · ⏱ 10:15 – 11:05

To conclude. U-HAP is a **compilation-driven, index-based** webhook authorizer for Kubernetes. It unifies RBAC, ABAC, and ACL under a single semantic graph, with deny taking precedence, so that conflicts are resolved deterministically.

Three principles summarize the design. *Compile rather than scan*, which moves all cost offline. *Share rather than repeat*, through hash consing. And *prune early, and prune deeply*, through two-level pruning.

`[PAUSE]`
I will close with our future work. First, we plan to reimplement the webhook in **Go or Rust**, because the present latency is dominated by Python and HTTP overhead rather than the algorithm, so a native implementation should reduce it substantially. Second, we intend to support **cross-namespace policy composition**, extending beyond the current single-namespace scope. And third, we aim to enable **dynamic policy reloading**, without restarting the webhook.

---

## SLIDE 14 — References · ⏱ 11:05 – 11:15

These are the twenty-one references cited in the paper. The full bibliographic details are available in the proceedings.

---

## SLIDE 15 — Thank You · ⏱ 11:15

Thank you for your attention. I would be glad to answer any questions.

*(Stand, and invite questions.)*

---

## Q&A — Keep These Backup Slides Ready

- **B4 (RBAC bit-vector)** — how the RBAC speedup works.
- **B7 (DSL example)** — what a policy file looks like.
- **B8 (Comparison table)** — comparison with OPA or Keycloak.
- **B2 (S1–S7)** — how correctness is verified.
- **B9 (Limitations and Future Work)** — the limitations and the next steps.

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
| Update E2E n=2,000 (U-HAP / OPA) | **223 ms / 611 ms** → **2.73×** |
| Update speedup engine-only | **19.5×** |
| Compiled footprint | **≤2.7 MiB** |
| Hash consing nodes (P1–P4) | **11 → 8** |
| Atom sharing in ABAC workload | **~50%** |

---

## Likely Q&A — Spoken, but Measured

**Why Python? Would Go or Rust be faster?**
> Yes, and that is our primary future work. The latency we report is dominated by the Python and Gunicorn HTTP overhead, which is about 0.68 milliseconds, rather than the algorithm. The ABAC engine itself runs in under 0.02 milliseconds. A Go or Rust implementation would reduce the per-request overhead by roughly ten times.

**How do you handle conflicts between models?**
> Deny always takes precedence. The deny index is evaluated first, before any allow path, and that ordering is enforced at compile time. If any deny candidate matches, the decision is deny.

**What does a policy file look like?**
> I can show backup slide seven. It is a simple YAML file. You declare the namespace and the resource, and then you list the rules, each with a type — RBAC, ABAC, ACL, deny, or hierarchy. All five compile into the four artifacts.

**Is the DAG traversed at runtime?**
> No. The graph exists only at compile time. At runtime, the system consults the hash sets, the bit-vectors, and the ABAC gate list directly. There is no graph traversal on the request path.

**How do you ensure correctness?**
> I can show backup slide two. We define seven scenarios, S1 through S7, that cover every model path and the deny invariant, and all of them pass. In addition, a hash-consing gate confirms that the four-policy example produces exactly eight nodes, and we maintain a role-closure test suite.

**What are the current limitations?**
> There are three principal ones. The scope is a single namespace, so ClusterRoles are not yet supported. Policy updates require a restart, so there is no hot reload. And authentication is out of scope, because U-HAP performs authorization only. Each of these appears on our future-work list.

---

## Extended Q&A Bank — Anticipated Questions

> The six questions above are the most likely. The bank below is for deeper or
> unexpected questions. Each answer is written to be spoken — short, measured, and
> direct. Lead with the one-line answer, then justify if they want more.

### A. General and motivational

**What is the single most important contribution of this work?**
> The unification through compilation. Prior work either unifies models but stays slow, or stays fast but handles only one model. Our contribution is showing that you can do both — by compiling several heterogeneous models into one indexed form, the runtime cost of unification effectively disappears.

**Why is this problem important in practice?**
> Because Kubernetes is now the default platform for production workloads, and real clusters mix authorization models across teams. That mixture is where both inconsistency and latency come from. Solving it improves security and performance at the same time, which is unusual.

**Who would actually use U-HAP?**
> Platform and security teams that operate multi-tenant clusters, where different namespaces are governed by different models. They are the ones currently paying for that fragmentation, both in latency and in inconsistent conflict behavior.

**Isn't this just adding a cache in front of authorization?**
> No. Caching helps only on repeated, identical requests. Our main result, the near-constant scaling and the per-model speedups, holds on cache misses, because it comes from compilation and indexing. The cache is an additional optimization on top, not the source of the improvement.

**What was the hardest part of this work?**
> Designing a single semantic representation that is general enough to express RBAC, ABAC, and ACL together, yet still compiles down to simple, flat structures. Keeping the deny-overrides guarantee correct across all of those models, deterministically, was the most demanding part.

**How is your semantic graph different from Zanzibar's?**
> Zanzibar's graph is traversed at request time to resolve relationships. Ours is the opposite. Our graph exists only during compilation; at request time it has already been reduced to flat indices, so there is no traversal at all on the request path.

**Is this work specific to Kubernetes, or more general?**
> The webhook integration is Kubernetes-specific, but the core idea — compiling heterogeneous policies into per-query indexed artifacts — is general. It could apply to any system that evaluates mixed authorization models on a hot path.

**Has this been deployed in production?**
> Not yet. Our evaluation is a controlled, in-memory study designed to isolate the algorithm. Production deployment, and a native implementation to support it, are explicit future work.

### B. Architecture and design

**What exactly is a "triple", and why that granularity?**
> A triple is a namespace, a resource, and an action — for example, the default namespace, pods, and get. We compile one artifact per triple because that is the exact unit a SubjectAccessReview asks about, so the runtime lookup is a single, direct hit with no further filtering.

**Doesn't compiling per triple cause an explosion of artifacts?**
> In principle the space is large, but in practice it is sparse, because policies only reference the resources and actions that actually exist. Our measured footprint stays under 2.7 megabytes, so the sparsity holds for realistic policy sets.

**Walk me through a single request on a cache miss.**
> The SubjectAccessReview arrives. We perform a constant-time lookup for its triple. We apply first-level pruning to drop models that do not apply. Then, in fixed order, we check deny, then ACL, then RBAC, then ABAC. The first decisive match returns, otherwise we fall through to default deny, and we write an audit record.

**What are the four artifacts again, and why those four?**
> A deny candidate set, an ACL hash set, an RBAC bit-vector, and a cost-sorted ABAC gate list. Each is the structure that makes its own model's check cheapest — a hash test for membership, a bitwise operation for roles, and an ordered gate list for attributes.

**Why a bit-vector for RBAC specifically?**
> Because role membership is a set-intersection question, and intersection over a fixed role universe is exactly what a bitwise AND computes. We precompute the transitive closure once, encode each role as a bit, and then the entire role check becomes one machine operation.

**How do you compute the transitive closure, and what does it cost?**
> At compile time, we propagate role inheritance through the hierarchy until it is fully expanded, and we detect cycles while doing so. It is paid once per policy change, never on the request path, so its cost does not affect request latency.

**What if the role hierarchy contains a cycle?**
> We detect cycles at compile time and reject the policy. The hierarchy is required to be acyclic, and that invariant is enforced before any artifact is produced.

**What is the "cost-sorted ABAC gate list", and how do you estimate cost?**
> It is the list of attribute gates for a triple, ordered so the cheapest and most selective conditions are evaluated first. The ordering lets us short-circuit early. The cost estimate is based on the structure of each gate, computed during compilation.

**Where do the attributes for ABAC come from at request time?**
> From the request context, together with a context-enrichment step that derives additional attributes, such as the time window or the network origin, before evaluation. The ABAC gates are then evaluated against that enriched context.

**How is the decision cache invalidated?**
> On any policy change. Because a change triggers recompilation, the cache is cleared as part of that process, so it can never serve a decision based on a stale policy.

### C. Performance and evaluation

**Your baseline is your own SSO-style evaluator. Is that a fair comparison?**
> Yes, because it models how conventional, non-compiled authorization actually behaves — sequential scanning with runtime role resolution. For the update comparison we go further and benchmark against OPA, a real, widely used engine, and we verify identical decisions.

**1.7 times seems modest next to 16.9 times. Why the difference?**
> They measure different things. The 1.7 times is the overall request latency under a fixed, realistic workload. The 16.9 times is ABAC alone as rule density grows. The per-model speedups widen with scale, while the overall figure reflects a typical mixed namespace.

**Why is the ABAC speedup so much larger than RBAC or ACL?**
> Because ABAC is where the redundant work concentrates. Attribute predicates share sub-expressions, so hash consing removes the most duplication there. RBAC and ACL are already near-constant once indexed, so there is simply less left to gain.

**What about tail latency, the p95 or p99?**
> We report medians as the headline, but we also collect the 95th percentile, and the near-constant behavior holds in the tail, because the request path is a lookup plus a few bitwise and hash operations, with little variance.

**How long does compilation, Phase 2, actually take?**
> It is on the order of milliseconds for our policy sets, and it runs only on a policy change, not per request. In the OPA comparison, the end-to-end update at two thousand policies is about 223 milliseconds, which includes parsing and compilation.

**How does memory scale, and what is the 2.7 megabytes measured at?**
> It is the compiled footprint for our evaluation workload. Memory grows with the number of distinct triples and shared sub-expressions, but hash consing keeps it compact, because identical structures are stored once.

**How does U-HAP behave under concurrency?**
> The compiled artifacts are read-only at request time, so concurrent requests evaluate without contention. For batch evaluation we use a thread pool. We deliberately avoid multiprocessing, because the workload is in-memory and lock-free on the read path.

**What is the throughput, in requests per second?**
> Since the ABAC engine runs in under 0.02 milliseconds per evaluation in memory, the algorithm itself supports very high throughput. The practical ceiling is the HTTP transport, which is the overhead our future Go or Rust port is meant to remove.

### D. Correctness and security

**How do you know the compiled artifact is equivalent to the source policy?**
> Two ways. We verify decision equivalence against OPA, with all one hundred of one hundred cases matching, and we maintain scenario tests, S1 through S7, that exercise every model path and the deny invariant directly.

**Could hash consing itself introduce a correctness bug?**
> It should not, because it only shares structurally identical nodes; it never changes what a node means. We guard this with a dedicated gate that checks the four-policy example reduces to exactly eight nodes, so any regression in sharing is caught.

**Is one hundred test cases enough to claim equivalence with OPA?**
> It is evidence, not a proof. The cases are chosen to cover every model and the conflict rules. A formal proof of the deny-overrides invariant over all valid inputs is on our future-work list.

**What is in the audit log?**
> The decision, the request that produced it, and which model and rule were decisive. That makes each decision explainable after the fact, which matters for a security component.

**What is your threat model?**
> We assume the requester is authenticated but may attempt to obtain access they should not have. U-HAP's job is to enforce the policy correctly and deterministically. Authentication itself, and the integrity of the identity, are handled upstream and are out of scope.

**Could a crafted set of attributes bypass a deny rule?**
> No, because deny is evaluated first, before any allow path, and that ordering is enforced at compile time. No combination of attributes can reorder it or skip it.

**If the webhook is unavailable, does it fail open or closed?**
> The safe configuration is fail-closed, so that an unavailable authorizer denies rather than grants. That is consistent with our default-deny design.

### E. Comparison with alternatives

**Why not just use OPA, or Gatekeeper, or Kyverno?**
> Those are powerful, but they interpret policies at request time, and they are oriented around a single policy language. U-HAP compiles multiple models ahead of time, which is why our update path is several times faster while producing identical decisions.

**Why not Casbin, which also supports multiple models?**
> Casbin supports model templates, but it still evaluates at request time and does not compile across models into shared indexed artifacts. The compilation step, and the hash-consed sharing, are what give us the scaling behavior.

**How does this relate to Keycloak's authorization services?**
> Keycloak is primarily an identity and SSO provider. As I noted, that addresses authentication. U-HAP addresses the authorization decision itself, and it can sit behind an SSO provider rather than replacing it.

**Why not just extend native Kubernetes RBAC?**
> Because native RBAC is a single model. Extending it would not give you ABAC or ACL semantics, nor unified, deterministic conflict resolution across models. U-HAP provides that unification without modifying Kubernetes itself.

### F. Deployment and practicality

**How does an operator write or migrate policies?**
> Policies are written in a simple YAML DSL, where each rule carries a type — RBAC, ABAC, ACL, deny, or hierarchy. Existing role definitions map naturally onto the RBAC and hierarchy rule types, so migration is largely a translation exercise.

**How does U-HAP integrate with a real cluster?**
> It is registered as a webhook authorizer, so the API server forwards each SubjectAccessReview to it and uses the response. No change to application workloads is required.

**How do you run multiple replicas without the caches diverging?**
> Each replica compiles from the same policy source, so the artifacts are identical. The decision cache is per replica and is purely an optimization, so a miss on one replica simply recomputes the same correct answer. Recompilation on policy change keeps them consistent.

**What is the operational overhead of adopting it?**
> Registering the webhook and authoring the policy files. After that, the compiled state is small, and the request path is lightweight, so the steady-state overhead is low.

### G. Scope and future work

**Why is cross-namespace policy composition hard?**
> Because today each artifact is scoped to one namespace's triple, which is what keeps the lookup simple and isolated. Composing across namespaces means reasoning about interactions between policies, while preserving both determinism and the constant-time path. That is active future work.

**Why do policy updates require a restart instead of hot reload?**
> It was a deliberate scope decision to keep the compiled state simple and consistent. The future-work direction is incremental compilation, recompiling only the affected triples on an edit, which would enable reloading without a restart.

**Why don't you support conditional, attribute-based deny rules?**
> In the current design, deny matches on subject and action only, which keeps the deny check trivially fast and easy to prove correct. Adding attribute predicates inside deny rules is planned, but it must not compromise the deny-first guarantee.

**What is your top future-work priority?**
> The native Go or Rust implementation, because most of our remaining latency is transport overhead rather than the algorithm. After that, cross-namespace composition and incremental, hot-reloadable compilation.
