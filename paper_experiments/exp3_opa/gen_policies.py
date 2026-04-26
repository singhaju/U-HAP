"""
Synthetic policy generator for exp5_update_latency.

Produces YAML policy files of varying size (10/100/500/1000/2000 rules)
with a realistic mix of rule types. Each policy targets a single
(namespace, resource) partition so the U-HAP compiler exercises all
five rule paths (RBAC, hierarchy, ABAC, ACL, deny).

Usage:
    python gen_policies.py --out ./policy_sets --counts 10,100,500,1000,2000

Output:
    ./policy_sets/policies_<N>.yaml      single multi-document YAML per N
"""

from __future__ import annotations

import argparse
import os
import random
from typing import List


RULE_MIX = {
    "rbac":      0.40,
    "abac":      0.30,
    "acl":       0.15,
    "deny":      0.10,
    "hierarchy": 0.05,
}

RESOURCES = ["pods", "deployments", "services", "configmaps", "secrets",
             "ingresses", "jobs", "cronjobs"]
ACTIONS   = ["get", "list", "create", "update", "delete", "patch", "watch"]
NAMESPACES = ["prod", "staging", "dev", "test", "data", "ml"]
ROLES = [f"role-{i}" for i in range(50)]
SUBJECTS = [f"user-{i}" for i in range(200)]
NETS = ["on-premise", "remote", "vpn"]
TIMES = ["business-hours", "after-hours", "weekend"]


def _rule_rbac(rng: random.Random) -> dict:
    return {
        "type": "rbac",
        "role": rng.choice(ROLES),
        "action": rng.choice(ACTIONS),
    }


def _rule_abac(rng: random.Random) -> dict:
    nets = rng.sample(NETS, k=rng.randint(1, 2))
    times = rng.sample(TIMES, k=rng.randint(1, 2))
    net_pred = " OR ".join(f"net == '{n}'" for n in nets)
    time_pred = " OR ".join(f"time == '{t}'" for t in times)
    return {
        "type": "abac",
        "action": rng.choice(ACTIONS),
        "predicate": f"({net_pred}) AND ({time_pred})",
    }


def _rule_acl(rng: random.Random) -> dict:
    return {
        "type": "acl",
        "subject": rng.choice(SUBJECTS),
        "action": rng.choice(ACTIONS),
    }


def _rule_deny(rng: random.Random) -> dict:
    return {
        "type": "deny",
        "subject": rng.choice(SUBJECTS) if rng.random() < 0.7 else "*",
        "action": rng.choice(ACTIONS),
    }


def _rule_hier(rng: random.Random) -> dict:
    parent, child = rng.sample(ROLES, 2)
    return {"type": "hierarchy", "parent": parent, "child": child}


_GEN = {
    "rbac": _rule_rbac, "abac": _rule_abac, "acl": _rule_acl,
    "deny": _rule_deny, "hierarchy": _rule_hier,
}


def _pick_type(rng: random.Random) -> str:
    r = rng.random()
    cum = 0.0
    for t, w in RULE_MIX.items():
        cum += w
        if r <= cum:
            return t
    return "rbac"


def _yaml_serialize_doc(namespace: str, resource: str, rules: List[dict]) -> str:
    lines = [f"namespace: {namespace}", f"resource: {resource}", "rules:"]
    for rule in rules:
        first = True
        for k, v in rule.items():
            prefix = "  - " if first else "    "
            lines.append(f"{prefix}{k}: {_yaml_value(v)}")
            first = False
    return "\n".join(lines) + "\n"


def _yaml_value(v) -> str:
    if isinstance(v, str):
        # Quote anything that would confuse YAML: spaces, quotes, parens,
        # or alias/anchor/flow sigils that appear bare-token unsafe.
        if v == "" or any(c in v for c in " '\"()*&!|>%@`{}[],"):
            escaped = v.replace('"', '\\"')
            return f'"{escaped}"'
        return v
    return str(v)


def generate_policy_yaml(n_rules: int, seed: int = 42) -> str:
    rng = random.Random(seed)
    partitions: dict = {}
    cycle_guard: set = set()

    for _ in range(n_rules):
        ns = rng.choice(NAMESPACES)
        res = rng.choice(RESOURCES)
        rule_type = _pick_type(rng)
        rule = _GEN[rule_type](rng)

        # Avoid trivial hierarchy cycles (parent -> child -> parent)
        if rule_type == "hierarchy":
            edge = (rule["parent"], rule["child"])
            reverse = (rule["child"], rule["parent"])
            if reverse in cycle_guard:
                rule = _rule_rbac(rng)
                rule_type = "rbac"
            else:
                cycle_guard.add(edge)

        partitions.setdefault((ns, res), []).append(rule)

    docs = []
    for (ns, res), rules in sorted(partitions.items()):
        docs.append(_yaml_serialize_doc(ns, res, rules))
    return "\n---\n".join(docs)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--counts", default="10,100,500,1000,2000")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    counts = [int(x) for x in args.counts.split(",")]

    for n in counts:
        path = os.path.join(args.out, f"policies_{n}.yaml")
        text = generate_policy_yaml(n, seed=args.seed + n)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"wrote {path}  ({n} rules)")


if __name__ == "__main__":
    main()
