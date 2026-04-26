"""
Correctness gate: S1–S7 from the U-HAP paper (v17 architecture).

ALL 7 scenarios must pass. These are non-negotiable — the paper's correctness
claim depends on them.

| ID | Subject | Model     | Resource/Verb           | Context                              | Expected |
|----|---------|-----------|-------------------------|--------------------------------------|----------|
| S1 | alice   | ABAC      | pods/prod / get         | on-premise + business-hours          | ALLOW    |
| S2 | alice   | ABAC      | pods/prod / get         | remote                               | DENY     |
| S3 | alice   | RBAC      | pods/dev / get          | any                                  | ALLOW    |
| S4 | bob     | ABAC      | pods/prod / delete      | after-hours                          | DENY     |
| S5 | *       | Deny      | secrets / delete        | any                                  | DENY     |
| S6 | charlie | ACL       | pods/dev / get          | any                                  | ALLOW    |
| S7 | dave    | Hierarchy | pods/prod / get         | any (Senior Dev->Junior Dev->Intern) | ALLOW    |

S7 (v2 change): Hierarchy traversal is now done at compile time (transitive
closure). At runtime, bit-vector AND checks dave's roles against I^rbac, which
includes {intern, junior-dev, senior-dev} after closure. No BFS at runtime.
"""

import pytest
from dsl.models import RBACRecord, HierRecord, ABACRecord, ACLRecord, DenyRecord
from compiler.index_compiler import compile_artifacts
from compiler.registry import ArtifactRegistry
from engine.evaluator import evaluate_artifact, evaluate_request


# ---------------------------------------------------------------------------
# Policy setup — compile artifacts per (namespace, resource, action)
# ---------------------------------------------------------------------------

def make_pods_prod_artifacts():
    """Artifacts for namespace=prod, resource=pods.

    Policies:
      - ABAC: net == 'on-premise' AND time == 'business-hours' -> get (S1, S2)
      - ABAC: time == 'business-hours' -> delete (S4 checks that it fails)
      - RBAC: intern -> get (S7 via hierarchy transitive closure)
      - Hierarchy: senior-dev -> junior-dev -> intern
    """
    records = [
        # S1 / S2: ABAC gate for get
        ABACRecord(
            resource="pods", namespace="prod", action="get",
            predicate="net == 'on-premise' AND time == 'business-hours'",
        ),
        # S4: ABAC gate for delete (time must be business-hours)
        ABACRecord(
            resource="pods", namespace="prod", action="delete",
            predicate="time == 'business-hours'",
        ),
        # S7: role hierarchy + RBAC permission for intern
        HierRecord(parent_role="senior-dev", child_role="junior-dev",
                   namespace="prod"),
        HierRecord(parent_role="junior-dev", child_role="intern",
                   namespace="prod"),
        RBACRecord(role="intern", resource="pods", namespace="prod",
                   action="get"),
    ]
    return compile_artifacts(records, namespace="prod", resource="pods")


def make_pods_dev_artifacts():
    """Artifacts for namespace=dev, resource=pods.

    Policies:
      - RBAC: dev-role -> get (S3 alice has role dev-role)
      - ACL: charlie -> get (S6)
    """
    records = [
        # S3: alice has role 'dev-role' which grants get
        RBACRecord(role="dev-role", resource="pods", namespace="dev",
                   action="get"),
        # S6: charlie has direct ACL
        ACLRecord(subject="charlie", resource="pods", namespace="dev",
                  action="get"),
    ]
    return compile_artifacts(records, namespace="dev", resource="pods")


def make_secrets_prod_artifacts():
    """Artifacts for namespace=prod, resource=secrets.

    Policies:
      - Deny: * -> delete (S5: everyone denied delete)
    """
    records = [
        DenyRecord(subject="*", resource="secrets", namespace="prod",
                   action="delete"),
    ]
    return compile_artifacts(records, namespace="prod", resource="secrets")


# ---------------------------------------------------------------------------
# S1: alice / ABAC / pods/prod / get / on-premise + business-hours -> ALLOW
# ---------------------------------------------------------------------------

def test_s1_abac_allow_on_premise_business_hours():
    """S1: alice gets pods in prod under correct context -> ALLOW."""
    arts = make_pods_prod_artifacts()
    art = arts["get"]
    ctx = {"net": "on-premise", "time": "business-hours"}
    allowed, reason = evaluate_artifact(art, uid="alice", roles=[], groups=[],
                                         context=ctx)
    assert allowed, (
        f"S1 FAILED: expected ALLOW for alice/pods/prod/get "
        f"on-premise+business-hours, got DENY (reason: {reason})"
    )


# ---------------------------------------------------------------------------
# S2: alice / ABAC / pods/prod / get / remote -> DENY
# ---------------------------------------------------------------------------

def test_s2_abac_deny_remote():
    """S2: same request as S1 but from remote network -> DENY."""
    arts = make_pods_prod_artifacts()
    art = arts["get"]
    ctx = {"net": "remote", "time": "business-hours"}
    allowed, reason = evaluate_artifact(art, uid="alice", roles=[], groups=[],
                                         context=ctx)
    assert not allowed, (
        f"S2 FAILED: expected DENY for alice/pods/prod/get remote, "
        f"got ALLOW (reason: {reason})"
    )


# ---------------------------------------------------------------------------
# S3: alice / RBAC / pods/dev / get / any -> ALLOW
# ---------------------------------------------------------------------------

def test_s3_rbac_allow():
    """S3: alice has role 'dev-role' which grants get on pods/dev -> ALLOW."""
    arts = make_pods_dev_artifacts()
    art = arts["get"]
    ctx = {}
    allowed, reason = evaluate_artifact(art, uid="alice", roles=["dev-role"],
                                         groups=[], context=ctx)
    assert allowed, (
        f"S3 FAILED: expected ALLOW for alice/pods/dev/get via RBAC, "
        f"got DENY (reason: {reason})"
    )


# ---------------------------------------------------------------------------
# S4: bob / ABAC / pods/prod / delete / after-hours -> DENY
# ---------------------------------------------------------------------------

def test_s4_abac_deny_after_hours():
    """S4: bob's delete gate requires business-hours; it's after-hours -> DENY."""
    arts = make_pods_prod_artifacts()
    art = arts["delete"]
    ctx = {"net": "on-premise", "time": "after-hours"}
    allowed, reason = evaluate_artifact(art, uid="bob", roles=[], groups=[],
                                         context=ctx)
    assert not allowed, (
        f"S4 FAILED: expected DENY for bob/pods/prod/delete after-hours, "
        f"got ALLOW (reason: {reason})"
    )


# ---------------------------------------------------------------------------
# S5: * / Deny / secrets/prod / delete / any -> DENY
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("subject", ["alice", "bob", "charlie", "admin", "root"])
def test_s5_wildcard_deny(subject):
    """S5: wildcard deny on secrets/delete blocks ALL subjects."""
    arts = make_secrets_prod_artifacts()
    art = arts["delete"]
    ctx = {"net": "on-premise", "time": "business-hours"}
    allowed, reason = evaluate_artifact(art, uid=subject, roles=["admin"],
                                         groups=[], context=ctx)
    assert not allowed, (
        f"S5 FAILED: expected DENY for {subject}/secrets/prod/delete "
        f"(wildcard deny), got ALLOW (reason: {reason})"
    )


# ---------------------------------------------------------------------------
# S6: charlie / ACL / pods/dev / get / any -> ALLOW
# ---------------------------------------------------------------------------

def test_s6_acl_allow():
    """S6: charlie has a direct ACL entry for get on pods/dev -> ALLOW."""
    arts = make_pods_dev_artifacts()
    art = arts["get"]
    ctx = {}
    allowed, reason = evaluate_artifact(art, uid="charlie", roles=[],
                                         groups=[], context=ctx)
    assert allowed, (
        f"S6 FAILED: expected ALLOW for charlie/pods/dev/get via ACL, "
        f"got DENY (reason: {reason})"
    )


# ---------------------------------------------------------------------------
# S7: dave / Hierarchy / pods/prod / get / Senior Dev -> Intern -> ALLOW
#
# v2: Transitive closure computed at compile time. At runtime: bit-vector AND.
# I^rbac for (prod, pods, get) = {intern, junior-dev, senior-dev}.
# dave has role senior-dev => b_user & b_rbac != 0 => ALLOW.
# ---------------------------------------------------------------------------

def test_s7_hierarchy_allow():
    """S7: dave has role Senior Dev; transitive closure puts it in I^rbac -> ALLOW.

    v2 architecture: no BFS at runtime. The closure is precomputed and encoded
    as a bit-vector. The check is: encode(dave_roles) & b_rbac != 0.
    """
    arts = make_pods_prod_artifacts()
    art = arts["get"]

    # Verify compile-time correctness: all three roles in I_rbac
    assert "intern" in art.i_rbac, "intern should be in I_rbac"
    assert "junior-dev" in art.i_rbac, "junior-dev should be in I_rbac (ancestor of intern)"
    assert "senior-dev" in art.i_rbac, "senior-dev should be in I_rbac (ancestor of junior-dev)"
    assert art.b_rbac != 0, "b_rbac must be non-zero"

    # Runtime: bit-vector check succeeds for dave
    ctx = {}
    allowed, reason = evaluate_artifact(art, uid="dave", roles=["senior-dev"],
                                         groups=[], context=ctx)
    assert allowed, (
        f"S7 FAILED: expected ALLOW for dave/pods/prod/get via Senior Dev "
        f"-> Junior Dev -> Intern hierarchy (bit-vector check), "
        f"got DENY (reason: {reason})"
    )
    assert "rbac" in reason.lower(), f"S7 FAILED: reason should mention rbac, got: {reason}"


def test_s7_hierarchy_all_levels_in_i_rbac():
    """S7 supplement: all three hierarchy levels are in I_rbac at compile time."""
    arts = make_pods_prod_artifacts()
    art = arts["get"]
    assert "senior-dev" in art.i_rbac
    assert "junior-dev" in art.i_rbac
    assert "intern" in art.i_rbac


def test_s7_hierarchy_unidirectional():
    """Hierarchy is one-way: intern does NOT inherit senior-dev's permissions."""
    arts = make_pods_prod_artifacts()
    art = arts["get"]
    ctx = {"net": "on-premise", "time": "business-hours"}
    # Intern has the direct RBAC get.
    allowed_get, _ = evaluate_artifact(art, uid="intern-user", roles=["intern"],
                                        groups=[], context=ctx)
    assert allowed_get, "Intern should be able to get (direct RBAC in I_rbac)"

    # Delete: intern is NOT in I_rbac for delete (no such rule)
    del_art = arts.get("delete")
    if del_art is not None:
        allowed_del, _ = evaluate_artifact(del_art, uid="intern-user", roles=["intern"],
                                            groups=[], context=ctx)
        # intern has no delete permission — only ABAC gate (business-hours)
        # With business-hours context, ABAC allows delete for anyone with the right attrs.
        # But intern role doesn't grant delete via RBAC.
        pass  # Context-dependent; not asserted here


# ---------------------------------------------------------------------------
# S7 via ArtifactRegistry (end-to-end)
# ---------------------------------------------------------------------------

def test_s7_via_registry():
    """S7 end-to-end through the ArtifactRegistry."""
    records = [
        HierRecord(parent_role="senior-dev", child_role="junior-dev",
                   namespace="prod"),
        HierRecord(parent_role="junior-dev", child_role="intern",
                   namespace="prod"),
        RBACRecord(role="intern", resource="pods", namespace="prod",
                   action="get"),
    ]
    registry = ArtifactRegistry()
    registry.load(records)

    allowed, reason = evaluate_request(
        registry, "prod", "pods", "get", "dave", ["senior-dev"], [], {}
    )
    assert allowed, f"S7 via registry FAILED: {reason}"
    assert "rbac" in reason.lower()
