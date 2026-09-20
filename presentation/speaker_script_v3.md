# U-HAP — Presentation Speaker Script (VERSION 3 — spoken / recommended)
## JCSSE 2026 · Target runtime: 12 minutes

> **How to use this version**
> This script is written the way you actually talk, not the way papers are written.
> Read it out loud and it should sound natural. **bold** = lean on this word.
> *italic* = slow down a little. `[PAUSE]` = stop, breathe, let it land.

---

## SLIDE 1 — Title · ⏱ 0:00 – 0:20

Good morning everyone. My name is Krittapak, and today I'm going to walk you through our paper, **U-HAP**, which stands for Unified Authorization over Heterogeneous Policies with Efficient Multi-Resource Verification in Kubernetes.

This is joint work with Singha and Phisitphon, and it was supervised by Assistant Professor Doctor Somchart Fugkeaw, at SIIT, Thammasat University.

---

## SLIDE 2 — Background · ⏱ 0:20 – 1:00

Let me start by setting the scene a little.

In Kubernetes, once a user has been **authenticated**, every single API call they make gets wrapped up into something called a **SubjectAccessReview**, and that request is handed off to the authorization phase, which decides whether it's allowed or not. Now Kubernetes itself comes with four built-in ways of making that decision. There's RBAC, there's ABAC, there's the Node authorizer, and there's a **Webhook** mode. U-HAP slots in through that webhook mode, so Kubernetes simply asks us for the answer.

`[PAUSE]`
There are four access-control models that will keep coming back throughout this talk, so let me name them now while it's quiet. **RBAC** decides based on your role. **ABAC** decides based on your attributes, things like the time of day or where you're connecting from. **ACL** is just an explicit list of who is allowed. And **deny** is the special one, because deny always wins over everything else.

On top of all this, a lot of organizations add single sign-on, or **SSO**, often through something like OIDC or Keycloak. And here's the part I want you to remember. SSO only answers the question of *who you are*. It does not answer the question of *what you're actually allowed to do*. So even after you've logged in once with SSO, every resource still has to enforce its own policy, on its own. *And that fragmentation is exactly the problem we set out to solve.*

---

## SLIDE 3 — Related Work · ⏱ 1:00 – 1:50

Before I show you our solution, let me quickly place it against what already exists, because that's where you'll see the gap we're filling. The prior work really falls into three groups.

The **first** group is all about hardening and misconfiguration. So this is things like the NSA and CISA hardening guidance, empirical studies of misconfigured clusters, tools like EPScan, and formal verification approaches. These are all genuinely useful, but notice what they're doing. They're checking whether an *individual* policy is correct. They're not trying to unify authorization across different models.

The **second** group covers RBAC, policy-as-code, and zero trust. So that's native Kubernetes RBAC, zero trust architectures, and compile-time policy optimization. The limitation here is that they all stay inside a *single* model. So the moment you deploy several layers together, you're still re-evaluating the same things over and over.

The **third** group is the expressive and graph-based models. XACML is very powerful, but its policy engine is heavy, and it just doesn't fit low-latency cloud-native workloads. Zanzibar scales globally, but to do that it has to traverse a graph at runtime. And the ABAC-to-RBAC conversion tools only translate between models, they don't give you a unified runtime.

`[PAUSE]`
So when you put all of that together, the gap becomes really clear. *Nobody offers one unified framework that spans RBAC, ABAC, ACL, and deny, while still staying fast and avoiding redundant work.* **And that's exactly what U-HAP provides.**

---

## SLIDE 4 — Motivation · ⏱ 1:50 – 2:45

Let me make this concrete with a real situation.

Kubernetes has basically become the default platform for running containers in production. And in a real organization, a single cluster can easily have dozens, sometimes hundreds, of **namespaces**. Each one is usually owned by a different team, and each team has its own security requirements.

Now here's the heart of the problem. Those namespaces don't agree on *how* authorization should even be expressed.
`[PAUSE]`
One namespace might use RBAC, the next one uses ABAC, and another one uses ACL. And these aren't just small differences in syntax. They genuinely reason about access in completely different ways. *So when they decide who gets in, they're almost speaking different languages.*

And that leads to three serious problems. First, the meaning is **fragmented** across the models. Second, when two models disagree, the conflict behavior becomes **unpredictable**. And third, you get real **runtime inefficiency**, because the system ends up scanning through all of the rules on every single request. And I want to stress, even if your SSO is handling authentication perfectly, none of this goes away. Authorization is still fragmented, still slow, and still inconsistent.

---

## SLIDE 5 — Our Solution · ⏱ 2:45 – 3:45

So here's our answer, U-HAP, and the core idea behind it is actually very simple. *Instead of solving the hard problem at request time, when you're in a hurry, we solve it ahead of time, offline.*

`[PAUSE]`
The easiest way to picture it is the difference between a **compiler** and an **interpreter**. An interpreter re-reads your code and figures it out all over again, every single time it runs. A compiler does all of that thinking once, upfront, and hands you something that just runs fast. We're doing the compiler version of that, but for authorization.

So what U-HAP does is take all of your policies, the RBAC, the ABAC, and the ACL, and it **compiles** them into what we call **indexed artifacts**. We write those as C with the subscript n, r, a. And the idea is that for every combination of a namespace, a resource, and an action, the compiler produces one small, flat data structure that is tuned for exactly that question.

Then at request time, all we do is look up the right artifact in a single step, which is **O of one**, and evaluate it directly. There's no parsing, there's no walking through a graph, and there's no conflict-resolution logic at request time. *All of that complexity has already been baked into the artifact ahead of time.*

And that gives us our four main contributions. A **universal semantic graph**, **hash consing** to get rid of redundant work, **two-level pruning** to skip irrelevant models early, and a **deterministic deny-overrides-all** rule that behaves the same way across every model.

---

## SLIDE 6 — System Architecture · ⏱ 3:45 – 5:25

This slide shows you the whole system, end to end.

`[PAUSE — let them take in the diagram]`

Look at the **top pipeline** first. That's Phase 2, the compilation path. Whenever your policies change, they flow through here. We parse them, we validate them, we assemble them into a hash-consed DAG, we compile that into the indexed artifacts, and then we store everything in the registry. And the key thing to notice is that this whole pipeline only runs *once per policy change*. It does not run on every request.

Now the **bottom pipeline** is Phase 3, and that's what actually happens on every request. A SubjectAccessReview comes in, we do that single O-of-one lookup in the registry, we apply two-level pruning to throw away anything irrelevant, we evaluate the few indexes that are left, and we return allow or deny, along with an audit log entry.

And that amber dashed line you can see at the bottom is the **decision cache**. If we've already answered this exact request before, a cache hit just short-circuits the whole pipeline and hands back the answer immediately.

`[PAUSE]`
Let me put the same thing in terms of the three phases. **Phase one is setup**, and it happens just once, when you deploy. We load the policy files and validate them, and this has zero impact on request latency. **Phase two is compilation**, which runs once each time a policy changes. This is where we build the hash-consed DAG and compile the four artifact types, for every namespace, resource, action triple. And those four are a deny candidate set, an ACL hash set, an RBAC bit-vector, and a cost-sorted ABAC gate list. And then **phase three is request-time**, which we deliberately kept as simple as we possibly could. Look up, prune, evaluate, return the decision, write the log.

*So the whole philosophy here is that by the time a request actually arrives, all of the hard reasoning has already been done.*

---

## SLIDE 7 — Hash Consing · ⏱ 5:25 – 6:40

Hash consing is one of the core ideas, so let me spend a moment on it.

Take the four policies from the paper, P1 through P4. They're all built out of just four atomic conditions. **a1** is whether you're on the on-premise network. **a2** is whether it's business hours. **a3** is whether you're in the engineering department. And **a4** is whether you have top-secret clearance.

Now here's the interesting part. These policies share whole chunks of logic. The expression *a1 or a2* shows up in both P1 and P2. And the expression *a2 and a3* shows up in P2, P3, and P4.

If you build these as plain trees, every policy makes its own private copy of those shared chunks. So you end up with seven separate gate copies, plus the four atoms, which is **eleven nodes** in total. And it gets worse at request time, because you'd evaluate that same shared logic again and again, even though the answer never changes.

`[PAUSE]`
**Hash consing** fixes that. The rule is simple. Before you ever create a new node, you check whether an identical one already exists, and if it does, you just reuse it. So those seven gate copies collapse down into four unique gates. Eleven nodes become **eight**. And because each node now exists only once, it gets evaluated at most one time per request, and we remember the result.

`[PAUSE]`
Over on the right you can see the four indexed artifacts we produce for each triple. **I-deny** is the deny candidate set, already trimmed down to this specific caller. **I-acl** is the ACL hash set, which gives us an O-of-one membership test. **b-rbac** is the RBAC bit-vector. And **I-abac** is the ABAC gate list, sorted so that we evaluate the cheapest conditions first.

The runtime order is cache, then deny, then ACL, then RBAC, then ABAC, and finally default deny. And one last thing I really want to stress. *The DAG only exists at compile time. We never traverse it at request time.*

---

## SLIDE 8 — Two-Level Pruning · ⏱ 6:40 – 7:40

Even once everything is compiled, we still don't want to evaluate all four models on every request. And that's the job of two-level pruning.

The **first level** is policy-type pruning, and it happens before we even touch an index. We just ask a few very quick questions. Does this triple have any deny rules at all? If it doesn't, we skip deny entirely. Does this caller carry any role assignments? If not, we skip RBAC. Does the request carry any attributes? If not, we skip ABAC. Each of those is a single O-of-one check, and it can wipe out an entire class of models in one go.

The **second level** is token-driven pruning, and that happens inside each model that survived the first level.
`[PAUSE]`
For ACL, it's just one hash lookup. For RBAC, it's a single bitwise AND, and let me tell you why that works. At compile time, we've already worked out the full transitive closure of the role hierarchy, and we've encoded every role as one bit. So checking RBAC just becomes *b-user AND b-rbac*, and if that result isn't zero, you're in. *That's one operation, no matter how many roles exist.* And for ABAC, we use an attribute-key index to narrow down the candidate gates before we evaluate anything.

And underneath all of it sits the single most important guarantee. **Deny is always checked first.** That ordering is enforced at compile time, so there is no way to bypass it.

---

## SLIDE 9 — Evaluation Setup · ⏱ 7:40 – 8:20

Just a quick word on how we measured all of this.

Our baseline is a conventional, SSO-style approach, where the system scans the policies one by one, and resolves roles and walks the hierarchy at runtime. That's how a lot of real setups actually behave.

All of our measurements are purely in-memory. There's no network and no HTTP overhead in these numbers, because we wanted to isolate the algorithm itself. Each number is the median over a thousand iterations, after fifty warm-up runs. And the hardware is an AMD Ryzen 9 7945HX with 32 gigabytes of RAM.

For the workload, each namespace carries forty-six rules. That's ten RBAC, twenty ABAC, ten ACL, one deny, and five hierarchy edges. The ABAC predicates use and, or, and at-least gates, with about fifty percent of the atoms shared between them, which is exactly the situation where hash consing earns its keep.

---

## SLIDE 10 — Experiment 1: Policy Verification Efficiency · ⏱ 8:20 – 9:20

Experiment one looks at how the latency behaves as the number of namespaces grows, all the way from ten up to a thousand.

`[PAUSE]`
And the headline result is that U-HAP stays completely **flat**. Because that O-of-one lookup goes straight to the artifact we need, nothing else gets touched as the cluster grows. The SSO baseline, on the other hand, grows linearly, because it's scanning all the rules and traversing the role hierarchy on every single request.

In terms of the raw numbers, U-HAP gives you roughly **one-point-seven times** lower latency, just from compiled evaluation. And once you turn on decision caching, repeated requests get about a **fourteen times** speedup on top of that.

The way I'd sum it up is this. *You can add nine hundred and ninety background namespaces, and it has zero effect on the latency of the one namespace you actually care about.*

---

## SLIDE 11 — Experiment 2: Policy Size Impact · ⏱ 9:20 – 10:20

Experiment two asks a different question. What happens as we pack more and more rules into a *single* namespace, going from five rules all the way up to three hundred and twenty?

For **ABAC**, which uses the hash-consed DAG, we get a **sixteen-point-nine times** speedup at three hundred and twenty rules. There's a crossover point at around twenty rules, and below that U-HAP is actually a little slower, because at such small sizes the cost of compilation hasn't been paid back yet.

For **RBAC**, the bit-vector gives us about a **five-point-six times** speedup, and it's always just that one AND operation, no matter how many rules there are.

And for **ACL**, the hash set gives roughly a **five times** speedup, and it stays nearly constant.

`[PAUSE]`
The reason the gap keeps widening is simple. The baseline has to scan about half the rules on every request, so it grows linearly with the rule count. Our compiled indexes are effectively constant time, so the speedup just keeps growing as the rules pile up.

---

## SLIDE 12 — Experiment 3: Policy Update Latency vs. OPA · ⏱ 10:20 – 11:20

The last experiment is about the update path. So this isn't how fast we answer a request, it's how fast a policy *change* actually takes effect.

We compared the full cycle, from editing a policy to getting the first decision, against **OPA**, the Open Policy Agent, which is the CNCF's graduated policy engine. And to keep it fair, we translated every one of our policies into the equivalent Rego, and an automated check confirmed that all one hundred out of one hundred decisions matched exactly.

`[PAUSE]`
At two thousand policies, U-HAP takes **two hundred and twenty-three milliseconds**, while OPA takes **six hundred and eleven**. So that's about a **two-point-seven times** speedup, end to end. And if we measure only the post-parse part, just the compilation and evaluation engine, it's thirty-one milliseconds against six hundred and eleven, which is a **nineteen-and-a-half times** speedup. And through all of this, the compiled state stays under **two-point-seven megabytes**.

*So the offline compilation really pays off twice. It makes individual requests faster, and it also makes rolling out policy changes faster.*

---

## SLIDE 13 — Conclusion · ⏱ 11:20 – 11:40

So to wrap up. U-HAP is a **compilation-driven, index-based** authorization webhook for Kubernetes. It unifies RBAC, ABAC, and ACL under one semantic graph, and it resolves conflicts deterministically, because deny always overrides everything.

And the results back it up. Around one-point-seven times lower latency, staying flat all the way to a thousand namespaces. About fourteen times from caching. Sixteen-point-nine times for ABAC at high rule counts. And two-point-seven times faster policy updates than OPA, or nineteen-and-a-half times if you look at the engine alone.

If you remember just three things from this talk, let it be these. *Compile, don't scan. Share, don't repeat. And prune early, prune deep.*

---

## SLIDE 14 — References · ⏱ 11:40 – 11:50

These are the twenty-one references we cite in the paper, and you'll find the full details in the proceedings.

---

## SLIDE 15 — Thank You · ⏱ 11:50

*(Stand, smile, and invite questions.)*

---

## Q&A — Keep These Backup Slides Ready

- **B4 (RBAC bit-vector)** — if someone asks how the RBAC speedup actually works.
- **B7 (DSL example)** — if someone asks what a policy file looks like.
- **B8 (Comparison table)** — if someone asks how this compares to OPA or Keycloak.
- **B2 (S1–S7 scenarios)** — if someone asks how you verify correctness.
- **B9 (Limitations)** — if someone asks about the limitations.

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

## Likely Q&A — Say It Naturally

**If they ask: Why Python? Wouldn't Go or Rust be faster?**
> Yes, and honestly that's our main future work. The latency you're seeing is dominated by the Python and Gunicorn HTTP overhead, which is about zero-point-six-eight milliseconds, not by the algorithm itself. The ABAC engine actually runs in under zero-point-zero-two milliseconds. So a Go or Rust version would cut the per-request overhead by roughly ten times.

**If they ask: How do you handle conflicts between models?**
> Deny always wins. We enforce the deny-overrides-all rule at compile time, so the deny index is always evaluated first, before any allow path. If any deny candidate matches the request, the answer is deny, no matter what the allow rules say.

**If they ask: What does a policy file look like?**
> Let me show you backup slide seven. It's just a simple YAML file. You declare the namespace and the resource at the top, and then you list your rules, each one with a type, so rbac, abac, acl, deny, or hierarchy. And all five of those compile down into the four artifacts.

**If they ask: Is the DAG traversed at runtime?**
> No, it isn't. The DAG only exists at compile time. At runtime, we go straight to the artifacts, so the hash sets, the bit-vectors, and the ABAC gate list. There's no graph traversal on the request path at all.

**If they ask: How do you ensure correctness?**
> Let me show you backup slide two. We have seven scenarios, S1 through S7, that cover every model path and the deny invariant, and all seven pass. On top of that, we have a hash-consing gate that checks the four-policy example produces exactly eight nodes, plus a role-closure test suite.

**If they ask: What are the current limitations?**
> Three main ones. We only support single-namespace scope right now, so ClusterRoles aren't covered. Policy updates need a restart, so there's no hot-reload yet. And authentication is out of scope, because U-HAP handles authorization only.
