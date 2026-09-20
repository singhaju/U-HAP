# 2025 Related-Work Candidates for U-HAP (JCSSE 2026 Camera-Ready)

Prepared in response to Reviewer 1's request for 2-3 references published in **2025**.
Ranked 1–6 from most to least relevant to U-HAP's contributions.

---

## Candidate 1 (RANK 1) — `rostamipoor2025kubekeeper`

**Title:** KubeKeeper: Protecting Kubernetes Secrets Against Excessive Permissions

**Authors:** Maryam Rostamipoor, Aliakbar Sadeghi, Michalis Polychronakis

**Venue / Year:** 10th IEEE European Symposium on Security and Privacy (EuroS&P), Venice, Italy, 2025. Pages 322–338.

**Citation key:** `rostamipoor2025kubekeeper`

**Why it is relevant to U-HAP:**
KubeKeeper extends Kubernetes' dynamic admission control framework with fine-grained, pod-scoped access-control policies for Secrets, integrating transparently via admission webhooks without modifying application code — precisely the webhook-based authorization extension point that U-HAP exploits. The paper evaluates against 335 real-world Kubernetes applications and demonstrates that tight per-resource authorization can be enforced at admission time with negligible overhead, validating U-HAP's claim that O(1) index-based lookup enables practical request-time enforcement. Its contrast with RBAC's coarse-grained wildcard bindings provides a direct citation point for U-HAP's motivation section on RBAC insufficiency.

**Verification status:** Confirmed on IEEE Xplore (document 11129402), dblp EuroSP 2025, and author's institutional page.

---

## Candidate 2 (RANK 2) — `sissodiya2025formal`

**Title:** Formal Verification for Preventing Misconfigured Access Policies in Kubernetes Clusters

**Authors:** Aditya Sissodiya et al. (Luleå University of Technology, Sweden)

**Venue / Year:** IEEE Access, 2025. DOI: 10.1109/ACCESS.2025.3597504. Published online 11 August 2025.

**Citation key:** `sissodiya2025formal`

**Why it is relevant to U-HAP:**
This paper models Kubernetes RBAC and admission policies jointly as first-order logic predicates and uses an SMT solver to detect misconfiguration counter-examples before policies are deployed. U-HAP's compilation phase (Phase 2) likewise transforms heterogeneous DSL policies into a validated semantic graph, catching conflicts (including deny-overrides-allow violations) at compile time rather than request time. The paper's formalization of RBAC+admission policy interaction complements U-HAP's unified RBAC/ABAC/ACL model and can be cited when justifying compile-time correctness guarantees. It also motivates the need for a unified authorizer that reasons over multiple policy types simultaneously.

**Verification status:** Confirmed on IEEE Xplore (document 11122676) and LTU DiVA repository. DOI verified.

---

## Candidate 3 (RANK 3) — `cesarano2025kubefence`

**Title:** KubeFence: Security Hardening of the Kubernetes Attack Surface

**Authors:** Carmine Cesarano, Roberto Natella

**Venue / Year:** 55th Annual IEEE/IFIP International Conference on Dependable Systems and Networks (DSN), 2025. Pages 497–510. DOI: 10.1109/DSN64029.2025.00054.

**Citation key:** `cesarano2025kubefence`

**Why it is relevant to U-HAP:**
KubeFence addresses the gap that Kubernetes RBAC lacks the granularity to filter specific attributes within API requests (i.e., it operates only at resource-type/verb level). It proposes per-workload API filtering derived from Operator configuration files and demonstrates a 35% average reduction in attack surface over RBAC alone. This is directly analogous to U-HAP's motivation: RBAC is insufficient for fine-grained, attribute-sensitive authorization, and a compiled index approach (U-HAP's C_{n,r,a} artifacts) is needed. KubeFence can be cited as independent 2025 evidence that production Kubernetes deployments require authorization expressiveness beyond built-in RBAC.

**Verification status:** Confirmed on IEEE Xplore (document 11068711), arXiv 2504.11126, DSN 2025 accepted papers list.

---

## Candidate 4 (RANK 4) — `her2025ebpf`

**Title:** An In-Depth Analysis of eBPF-Based System Security Tools in Cloud-Native Environments

**Authors:** J. Her, J. Kim, J. Kim, S. Lee

**Venue / Year:** IEEE Access, 2025. DOI: 10.1109/ACCESS.2025.3605432.

**Citation key:** `her2025ebpf`

**Why it is relevant to U-HAP:**
This paper benchmarks four leading eBPF-based security enforcement tools (KubeArmor, Falco, Tetragon, Tracee) in Kubernetes, evaluating policy scope, matching strategies, and CPU/memory overhead. It represents the alternative "kernel-level enforcement" design point against which U-HAP's webhook/authorizer approach can be contrasted: eBPF-based tools enforce policy post-admission at the syscall layer, while U-HAP enforces authorization decisions pre-admission via a SubjectAccessReview webhook. This contrast is useful in the Related Work section to delineate U-HAP's authorization-plane focus from runtime anomaly detection. The performance data also provides reference overhead numbers for the broader cluster-security literature.

**Verification status:** Confirmed on IEEE Xplore (document 11146725). DOI verified via CoLab/IEEE Xplore metadata. Full author names partially abbreviated in search results ("Her J., Kim J., Kim J., Lee S.") — recommend verifying exact given names from IEEE Xplore before submission.

---

## Candidate 5 (RANK 5) — `sitharaman2025scalable`

**Title:** Scalable Privilege Analysis for Multi-Cloud Big Data Platforms: A Hypergraph Approach

**Authors:** Sai Sitharaman, Hassan Karim, Deepti Gupta, Mudit Tyagi

**Venue / Year:** arXiv preprint, arXiv:2511.15837, submitted 19 November 2025. (No venue publication confirmed as of April 2026.)

**Citation key:** `sitharaman2025scalable`

**Why it is relevant to U-HAP:**
This paper introduces a NIST NGAC + hypergraph framework that achieves sub-linear O(√n) privilege traversal, outperforming conventional ABAC (O(n^k)) and DAG-based NGAC in multi-cloud environments. U-HAP's bit-vector transitive closure for role hierarchies achieves an analogous O(1) per-request complexity by pre-computing the closure at compile time; citing this paper situates U-HAP within the broader "scalable authorization graph" research trend. The 3-Dimensional Privilege Analysis framework (Attack Surface, Attack Window, Attack Identity) also provides a conceptual vocabulary for discussing the breadth of U-HAP's three-level pruning (deny → ACL → RBAC → ABAC).

**Verification status:** arXiv preprint only; no peer-reviewed venue confirmed. Use with caveat "preprint under review."

---

## Candidate 6 (RANK 6) — `avirneni2025intent`

**Title:** Intent-Aware Authorization for Zero Trust CI/CD

**Authors:** Surya Teja Avirneni

**Venue / Year:** arXiv preprint, arXiv:2504.14777, submitted April 2025. (Third in a three-part series; no peer-reviewed venue confirmed.)

**Citation key:** `avirneni2025intent`

**Why it is relevant to U-HAP:**
This paper extends OPA/Cedar-based policy engines to evaluate not just identity but also justification, timing, and workload context in Zero Trust CI/CD pipelines. U-HAP's ABAC phase evaluates contextual attributes (location, time, environment) via predicate expressions — the same semantic category as "intent signals." The paper motivates the need to go beyond identity and role in authorization, supporting U-HAP's argument that a unified RBAC+ABAC authorizer is necessary. However, its single-author preprint status makes it less suitable as a flagship citation; use only if a third reference is required.

**Verification status:** Confirmed on arXiv (abs/2504.14777) and NASA ADS. Single author; arXiv-only.

---

## Recommendation Summary

| Rank | Citation Key | Venue Tier | Confidence | Notes |
|------|-------------|-----------|-----------|-------|
| 1 | `rostamipoor2025kubekeeper` | IEEE EuroS&P | High | Best fit; admission webhook + fine-grained AC |
| 2 | `sissodiya2025formal` | IEEE Access | High | Formal policy verification, RBAC+admission |
| 3 | `cesarano2025kubefence` | IEEE DSN | High | RBAC insufficiency, API-level filtering |
| 4 | `her2025ebpf` | IEEE Access | Medium | eBPF contrast; verify author given names |
| 5 | `sitharaman2025scalable` | arXiv only | Low-Med | Scalable AC graphs; no venue yet |
| 6 | `avirneni2025intent` | arXiv only | Low | Single-author preprint; use as last resort |

**Recommended top 3 for camera-ready:** candidates 1, 2, and 3.
