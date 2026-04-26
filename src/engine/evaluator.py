"""
Phase 3: Index-based authorization evaluation engine (U-HAP v2).

VERIFY(τ, n, r, a) — full Algorithm 3 from the v17 paper:

  1. ARTIFACT LOOKUP — O(1)
     C = registry[n][r][a]
     If C is None -> DENY("no policy")

  2. DECISION CACHE CHECK — O(1)
     κ = hash(uid, n, r, a, role_bitvec, group_sig, attr_sig)
     If κ in cache -> return cache[κ]

  3. CONTEXT ENRICHMENT
     Classify source_ip -> network zone
     Classify utc_hour  -> time period
     Merge into A_u

  4. DENY CHECK (if Ξ.has_deny) — O(|Γ_deny|)
     Γ_deny = token-pruned deny candidates
     If any candidate matches -> DENY("deny rule")

  5. ACL CHECK (if Ξ.has_acl) — O(1)
     If uid ∈ I_acl or groups ∩ I_acl ≠ ∅ -> ALLOW("acl")

  6. RBAC CHECK (if Ξ.has_rbac) — O(1)
     b_user = encode(token_roles)
     If b_user & b_rbac ≠ 0 -> ALLOW("rbac")

  7. ABAC CHECK (if Ξ.has_abac) — O(|Γ_abac|)
     Γ_abac = attr-key pruned, cost-sorted gates
     memo = {}
     For each gate: if evaluate_dag(root, A_u, memo) -> ALLOW("abac")

  8. DEFAULT DENY
     -> DENY("no path")

  9. CACHE UPDATE
     cache[κ] = decision (with TTL)

Key invariants:
  - Deny is step 4 — always before any allow path (deny-overrides-all)
  - No BFS at runtime — RBAC uses compile-time transitive closure + bit-vector AND
  - Each DAG node evaluated at most once per request (memo)
  - Resource-action isolation: only C_{n,r,a} is touched

Public API:
  evaluate_artifact(artifact, uid, roles, groups, context, cache) -> (bool, str)
  evaluate_request(registry, namespace, resource, action, uid, roles, groups, context, cache) -> (bool, str)
"""

from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Iterable, List, Optional, Set, Tuple

from compiler.bitvector import RoleBitVector
from dsl.models import CompiledArtifact
from engine.cache import DecisionCache, make_cache_key
from engine.gate_nodes import evaluate_dag
from engine.pruning import prune_abac, prune_acl, prune_deny


def evaluate_artifact(
    artifact: CompiledArtifact,
    uid: str,
    roles: List[str],
    groups: List[str],
    context: dict,
    cache: Optional[DecisionCache] = None,
) -> Tuple[bool, str]:
    """Evaluate an authorization request against a pre-compiled artifact.

    This is the core Phase 3 function. The artifact must already be compiled
    (Phase 2 complete). No graph traversal happens here.

    Args:
        artifact: CompiledArtifact C_{n,r,a} for this (namespace, resource, action).
        uid:      Authenticated user identity string.
        roles:    List of role names from the token (R_u).
        groups:   List of group names from the token (G_u).
        context:  Merged dict of user attributes + runtime context (A_u).
        cache:    Optional DecisionCache. If provided, cache is checked before
                  evaluation and updated after.

    Returns:
        (True, reason_string)  -> ALLOW
        (False, reason_string) -> DENY
    """
    fp = artifact.fast_path

    # ------------------------------------------------------------------
    # Step 2: Decision cache check
    # ------------------------------------------------------------------
    cache_key: Optional[int] = None
    if cache is not None:
        # Build role bit-vector for the cache key using the pre-built RoleBitVector
        rbv_key = artifact.rbv or RoleBitVector(artifact.role_universe or artifact.i_rbac)
        b_user_for_key = rbv_key.encode(roles)
        cache_key = make_cache_key(
            uid=uid,
            namespace=artifact.namespace,
            resource=artifact.resource,
            action=artifact.action,
            role_bitvec=b_user_for_key,
            groups=groups,
            attributes=context,
        )
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

    # ------------------------------------------------------------------
    # Step 4: DENY CHECK
    # ------------------------------------------------------------------
    if fp is None or fp.has_deny:
        deny_candidates = prune_deny(
            i_deny=artifact.i_deny,
            uid=uid,
            groups=groups,
            roles=roles,
        )
        if deny_candidates:
            # Distinguish wildcard vs specific for audit
            if "*" in deny_candidates:
                decision = (False, "deny rule: wildcard")
            else:
                decision = (False, f"deny rule: {uid}")
            if cache is not None and cache_key is not None:
                cache.put(cache_key, *decision)
            return decision

    # ------------------------------------------------------------------
    # Step 5: ACL CHECK
    # ------------------------------------------------------------------
    if fp is None or fp.has_acl:
        acl_candidates = prune_acl(
            i_acl=artifact.i_acl,
            uid=uid,
            groups=groups,
        )
        if acl_candidates:
            # Report the first matching subject for the audit trail
            matched = next(iter(acl_candidates))
            decision = (True, f"acl: {matched}")
            if cache is not None and cache_key is not None:
                cache.put(cache_key, *decision)
            return decision

    # ------------------------------------------------------------------
    # Step 6: RBAC CHECK — O(1) bit-vector AND
    # ------------------------------------------------------------------
    if fp is None or fp.has_rbac:
        if artifact.i_rbac and artifact.b_rbac != 0:
            rbv = artifact.rbv or RoleBitVector(artifact.role_universe or artifact.i_rbac)
            b_user = rbv.encode(roles)
            if b_user & artifact.b_rbac != 0:
                # Identify the matching role for the audit trail
                matching_roles = set(roles) & artifact.i_rbac
                matched_role = next(iter(matching_roles)) if matching_roles else "unknown"
                decision = (True, f"rbac: {matched_role}")
                if cache is not None and cache_key is not None:
                    cache.put(cache_key, *decision)
                return decision

    # ------------------------------------------------------------------
    # Step 7: ABAC CHECK — attribute-key pruned, cost-ordered, memoized
    # ------------------------------------------------------------------
    if fp is None or fp.has_abac:
        # Level-2 pruning: only gates whose required attrs are present
        attr_keys = list(context.keys())
        candidates = prune_abac(
            i_abac=artifact.i_abac,
            i_attr=artifact.i_attr,
            attr_keys=attr_keys,
        )
        # Per-request memoization (hash consing invariant: each DAG node ≤ 1 eval)
        memo: dict = {}
        for gate in candidates:
            if evaluate_dag(gate.root, context, memo):
                decision = (True, f"abac: {gate.root.canonical_key()}")
                if cache is not None and cache_key is not None:
                    cache.put(cache_key, *decision)
                return decision

    # ------------------------------------------------------------------
    # Step 8: DEFAULT DENY
    # ------------------------------------------------------------------
    decision = (False, "no path")
    if cache is not None and cache_key is not None:
        cache.put(cache_key, *decision)
    return decision


def evaluate_request(
    registry,
    namespace: str,
    resource: str,
    action: str,
    uid: str,
    roles: List[str],
    groups: List[str],
    context: dict,
    cache: Optional[DecisionCache] = None,
) -> Tuple[bool, str]:
    """Evaluate a full authorization request via the artifact registry.

    Top-level entry point for the webhook handler. Performs artifact lookup
    (Step 1) then delegates to evaluate_artifact().

    Args:
        registry:  ArtifactRegistry populated during Phase 2.
                   Accepts either ArtifactRegistry or GraphRegistry
                   (for backward-compatibility with v1 callers).
        namespace: Kubernetes namespace (e.g., "prod").
        resource:  Resource name (e.g., "pods").
        action:    Requested action verb (e.g., "get", "delete").
        uid:       Requesting user identity.
        roles:     Role names from authentication token.
        groups:    Group names from authentication token.
        context:   Runtime context dict (e.g., network classification, hour).
        cache:     Optional DecisionCache.

    Returns:
        (bool, str): (allow, reason)
    """
    # Step 1: Artifact lookup — O(1)
    # Support both ArtifactRegistry (3-level: [ns][res][action]) and
    # legacy GraphRegistry (2-level: [ns][res]).
    artifact = None

    # Try ArtifactRegistry protocol first (has .get(ns, res, action))
    try:
        artifact = registry.get(namespace, resource, action)
    except TypeError:
        # Fallback: old GraphRegistry.get(ns, res) — should not happen in v2
        pass

    if artifact is None:
        return False, "no policy"

    # Check if it's an old-style PolicyGraph (from v1 registry)
    from dsl.models import CompiledArtifact as CA
    if not isinstance(artifact, CA):
        return False, "no policy"

    return evaluate_artifact(
        artifact=artifact,
        uid=uid,
        roles=roles,
        groups=groups,
        context=context,
        cache=cache,
    )


def evaluate_batch_parallel(
    registry,
    requests: List[Tuple[str, str, str, str, List[str], List[str], dict]],
    workers: int = 4,
    cache: Optional[DecisionCache] = None,
) -> List[Tuple[bool, str]]:
    """Evaluate a batch of authorization requests concurrently.

    Each request in the list is evaluated independently by evaluate_request().
    Within each request the deny-first ordering is preserved exactly — only
    the *across-request* parallelism is exploited.

    Args:
        registry: ArtifactRegistry populated during Phase 2.
        requests: List of tuples, each:
                  (namespace, resource, action, uid, roles, groups, context)
        workers:  Number of ThreadPoolExecutor worker threads.
                  workers=1 uses the thread pool with a single worker, which
                  produces results identical to calling evaluate_request() in a
                  sequential loop.
        cache:    Optional shared DecisionCache (must be thread-safe for reads;
                  put() races are benign — worst case a key is written twice
                  with the same value).

    Returns:
        List of (bool, str) decisions in the same order as the input requests.
    """
    def _eval_one(req_tuple):
        namespace, resource, action, uid, roles, groups, context = req_tuple
        return evaluate_request(
            registry=registry,
            namespace=namespace,
            resource=resource,
            action=action,
            uid=uid,
            roles=roles,
            groups=groups,
            context=context,
            cache=cache,
        )

    with ThreadPoolExecutor(max_workers=workers) as executor:
        # executor.map preserves input order
        results = list(executor.map(_eval_one, requests))

    return results
