"""
U-HAP YAML → Rego v1 translator.

Produces a single Rego module per (namespace, resource) partition with
semantically equivalent rules to the U-HAP DSL. Targets OPA v1.x (Rego v1).

Decision contract:
    package uhap.<namespace>.<resource>

    default allow := false
    default deny  := false

    allow if { ... rules ... }
    deny  if { ... deny rules ... }

Caller does:
    decision := not deny and allow

Equivalent to U-HAP's deny-overrides-all + ACL/RBAC/ABAC ordering.

Usage:
    python yaml_to_rego.py --in policies_100.yaml --out policies_100.rego
    python yaml_to_rego.py --in policy_sets/ --out rego_sets/    # batch dir mode
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple

# read-only access to ../../src
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from compiler.role_closure import compute_transitive_closure            # noqa: E402
from dsl.loader import load_yaml_string                                 # noqa: E402
from dsl.models import (                                                # noqa: E402
    ABACRecord, ACLRecord, ASTAtom, ASTBinary, ASTThreshold,
    DenyRecord, HierRecord, RBACRecord,
)
from dsl.parser import parse_predicate                                  # noqa: E402


# ---------------------------------------------------------------------------
# Identifier sanitization (Rego package paths must be alphanumeric / _)
# ---------------------------------------------------------------------------

def _sanitize(s: str) -> str:
    out = re.sub(r"[^A-Za-z0-9_]", "_", s)
    if not out or out[0].isdigit():
        out = "p_" + out
    return out


def _rego_value(v: Any) -> str:
    if isinstance(v, str):
        escaped = v.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, list):
        return "[" + ", ".join(_rego_value(x) for x in v) + "]"
    raise TypeError(f"unsupported value type: {type(v).__name__}")


# ---------------------------------------------------------------------------
# AST → Rego expression
# ---------------------------------------------------------------------------

def _ast_to_rego(node) -> str:
    """Translate ABAC predicate AST into a single Rego boolean expression.

    Rego v1 uses `;` for conjunction inside a rule body, but inside a
    boolean *expression* we use `and`/`or` as keywords... actually Rego does
    NOT have boolean operators in expressions — conjunction is rule-body
    sequencing. So we emit a helper rule per ABAC predicate to express OR
    via multiple rule heads, and AND via sequential body lines.

    To keep the translator simple and self-contained, we emit a NESTED
    helper rule per OR/AND/THRESHOLD node and reference it from the parent.
    Each helper has form:

        h_<id>(input) if { <body> }

    Returns: (helper_name, list_of_helper_rule_strings)
    Caller appends helper rules to the module and uses helper_name in the
    rule body.
    """
    raise RuntimeError("use _emit_predicate")  # see below


class _PredicateEmitter:
    """Emits helper rules for a predicate AST.

    Each predicate becomes one top-level helper rule `pred_<id>` that is
    true exactly when the predicate is true under input.attrs.
    """

    def __init__(self, prefix: str):
        self.prefix = prefix
        self.helpers: List[str] = []
        self._counter = 0

    def _new_name(self) -> str:
        self._counter += 1
        return f"{self.prefix}_h{self._counter}"

    def emit(self, node) -> str:
        """Returns the helper-rule name that evaluates this AST."""
        if isinstance(node, ASTAtom):
            return self._emit_atom(node)
        if isinstance(node, ASTBinary):
            if node.type == "AND":
                return self._emit_and(node.children)
            if node.type == "OR":
                return self._emit_or(node.children)
            raise ValueError(f"unknown binary op: {node.type}")
        if isinstance(node, ASTThreshold):
            return self._emit_threshold(node.k, node.children)
        raise TypeError(f"unknown AST node: {type(node).__name__}")

    def _emit_atom(self, atom: ASTAtom) -> str:
        name = self._new_name()
        attr = atom.attribute
        op = atom.operator
        val = _rego_value(atom.value)
        # Rego access: input.attrs["key"]
        accessor = f'input.attrs["{attr}"]'
        if op == "==":
            body = f"{accessor} == {val}"
        elif op == "!=":
            body = f"{accessor} != {val}"
        elif op == "in":
            # value is a list; check membership
            body = f"{accessor} in {val}"
        else:
            raise ValueError(f"unknown atom operator: {op}")
        self.helpers.append(f"{name} if {{\n  {body}\n}}\n")
        return name

    def _emit_and(self, children: list) -> str:
        sub_names = [self.emit(c) for c in children]
        name = self._new_name()
        body = "\n  ".join(sub_names)
        self.helpers.append(f"{name} if {{\n  {body}\n}}\n")
        return name

    def _emit_or(self, children: list) -> str:
        # OR in Rego = multiple rule heads with the same name
        name = self._new_name()
        for c in children:
            sub = self.emit(c)
            self.helpers.append(f"{name} if {{ {sub} }}\n")
        return name

    def _emit_threshold(self, k: int, children: list) -> str:
        # ATLEAST(k, c1, c2, ...) — at least k of m children true.
        # We emit each child as a 0/1 helper, sum them, and compare.
        sub_names = [self.emit(c) for c in children]
        name = self._new_name()
        # Build:  count := sum([1 | sub_i])  is awkward; use comprehension:
        #   true_count := count([true | sub_i])
        elements = " | ".join(f"{s}" for s in sub_names)  # placeholder
        # We instead emit: sum := sum([1 | sub_1; sub_1]) -- but Rego
        # doesn't allow arbitrary comprehensions over rules in a body.
        # The cleanest way: enumerate subsets — for paper purposes,
        # threshold rules are rare; emit a brute "any k-subset is true" rule.
        # Generate all C(m, k) subsets.
        from itertools import combinations
        m = len(sub_names)
        for combo in combinations(range(m), k):
            body = "\n  ".join(sub_names[i] for i in combo)
            self.helpers.append(f"{name} if {{\n  {body}\n}}\n")
        return name


# ---------------------------------------------------------------------------
# Per-partition module emission
# ---------------------------------------------------------------------------

def _emit_partition_rules(namespace: str, resource: str,
                          records: List, hier_for_ns: List[HierRecord],
                          partition_idx: int) -> str:
    """Emit Rego rules for a single (namespace, resource) partition.

    All rules are gated on input.namespace and input.resource matching
    this partition. Helper rule names are partition-prefixed to avoid
    collisions with other partitions in the same module.

    Returns: rules text (no package declaration).
    """
    out: List[str] = []
    out.append(f"# ===== partition: {namespace}/{resource} =====\n")

    ns_lit = f'"{namespace}"'
    res_lit = f'"{resource}"'
    pidx = partition_idx
    gate = (
        f'  input.namespace == {ns_lit}\n'
        f'  input.resource == {res_lit}\n'
    )

    # ----- Role hierarchy: precompute closure, emit as facts ---------------
    # Avoids Rego recursion + unsafe-var issues. Equivalent to U-HAP's
    # I_rbac construction (direct role + ancestors of direct role).
    hier_edges: Dict[str, List[str]] = defaultdict(list)
    for h in hier_for_ns:
        if h.child_role not in hier_edges[h.parent_role]:
            hier_edges[h.parent_role].append(h.child_role)
    closure = compute_transitive_closure(dict(hier_edges)) if hier_edges else {}

    anc = f"ancestor_p{pidx}"
    # Reflexive: every role inherits itself.
    # We emit a fact per role mentioned in this partition's RBAC rules + the
    # universe seen in hierarchy. Plus a catch-all that matches any role the
    # user actually presents at request time.
    rbac_recs = [r for r in records if isinstance(r, RBACRecord)]
    universe = set()
    for r in rbac_recs:
        universe.add(r.role)
    for parent, children in hier_edges.items():
        universe.add(parent)
        for c in children:
            universe.add(c)
    # Emit transitive (ancestor, descendant) pairs from the closure
    for ancestor_role, descendants in closure.items():
        for desc in descendants:
            out.append(f'{anc}("{ancestor_role}", "{desc}")\n')
    # Reflexive: matches when user's presented role equals the required role
    out.append(
        f"{anc}(r, r) if {{\n"
        f'  r = input.roles[_]\n'
        f"}}\n"
    )

    # ----- ACL rules --------------------------------------------------------
    acls = [r for r in records if isinstance(r, ACLRecord)]
    for r in acls:
        out.append(
            f"allow if {{\n"
            f"{gate}"
            f'  input.action == "{r.action}"\n'
            f'  input.uid == "{r.subject}"\n'
            f"}}\n"
        )

    # ----- RBAC rules -------------------------------------------------------
    rbacs = [r for r in records if isinstance(r, RBACRecord)]
    for r in rbacs:
        out.append(
            f"allow if {{\n"
            f"{gate}"
            f'  input.action == "{r.action}"\n'
            f"  some user_role\n"
            f"  user_role = input.roles[_]\n"
            f'  {anc}(user_role, "{r.role}")\n'
            f"}}\n"
        )

    # ----- ABAC rules -------------------------------------------------------
    abacs = [r for r in records if isinstance(r, ABACRecord)]
    for i, r in enumerate(abacs):
        ast = parse_predicate(r.predicate)
        emitter = _PredicateEmitter(prefix=f"abac_p{pidx}_{i}")
        head_name = emitter.emit(ast)
        for h in emitter.helpers:
            out.append(h)
        out.append(
            f"allow if {{\n"
            f"{gate}"
            f'  input.action == "{r.action}"\n'
            f"  {head_name}\n"
            f"}}\n"
        )

    # ----- Deny rules -------------------------------------------------------
    denies = [r for r in records if isinstance(r, DenyRecord)]
    for r in denies:
        if r.subject == "*":
            out.append(
                f"deny if {{\n"
                f"{gate}"
                f'  input.action == "{r.action}"\n'
                f"}}\n"
            )
        else:
            out.append(
                f"deny if {{\n"
                f"{gate}"
                f'  input.action == "{r.action}"\n'
                f'  input.uid == "{r.subject}"\n'
                f"}}\n"
            )

    return "".join(out)


def yaml_to_rego(yaml_text: str, package: str = "uhap") -> str:
    """Convert U-HAP YAML to a single Rego module (one package, all partitions).

    The module is gated on input.namespace and input.resource so a single
    deployed module covers every partition. This matches U-HAP's single-call
    `ArtifactRegistry.load(records)` semantics for fair comparison.
    """
    records = load_yaml_string(yaml_text)

    hier_by_ns: Dict[str, List[HierRecord]] = defaultdict(list)
    for r in records:
        if isinstance(r, HierRecord):
            hier_by_ns[r.namespace].append(r)

    by_partition: Dict[Tuple[str, str], List] = defaultdict(list)
    for r in records:
        if isinstance(r, HierRecord):
            continue
        by_partition[(r.namespace, r.resource)].append(r)

    parts: List[str] = []
    parts.append(f"package {package}\n")
    parts.append("default allow := false\n")
    parts.append("default deny  := false\n")

    for idx, ((ns, res), recs) in enumerate(sorted(by_partition.items())):
        parts.append(_emit_partition_rules(
            ns, res, recs, hier_by_ns.get(ns, []), partition_idx=idx))

    parts.append(
        "default decision := false\n"
        "decision := true if {\n"
        "  not deny\n"
        "  allow\n"
        "}\n"
    )
    return "".join(parts)


def write_rego_single(rego_text: str, out_path: Path) -> None:
    """Write a single Rego module to disk."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(rego_text, encoding="utf-8")


def write_rego_bundle(rego_text: str, out_dir: Path) -> None:
    """Bundle layout: one .rego under out_dir/uhap.rego ready for `opa build -b`."""
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "uhap.rego").write_text(rego_text, encoding="utf-8")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True,
                    help="input YAML file or directory of *.yaml")
    ap.add_argument("--out", required=True,
                    help="output .rego file (single) or directory (bundle)")
    ap.add_argument("--bundle", action="store_true",
                    help="emit one .rego per (ns,res) under --out (bundle layout)")
    args = ap.parse_args()

    inp = Path(args.inp)
    out = Path(args.out)

    if inp.is_dir():
        yaml_files = sorted(inp.glob("*.yaml")) + sorted(inp.glob("*.yml"))
    else:
        yaml_files = [inp]

    combined_yaml = "\n---\n".join(f.read_text(encoding="utf-8") for f in yaml_files)
    rego_text = yaml_to_rego(combined_yaml)

    if args.bundle:
        write_rego_bundle(rego_text, out)
        print(f"wrote bundle layout under {out}/uhap.rego")
    else:
        write_rego_single(rego_text, out)
        print(f"wrote single Rego module -> {out}")


if __name__ == "__main__":
    main()
