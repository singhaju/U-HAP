"""
U-HAP ↔ OPA decision equivalence test.

For each policy set, generate N random SARs, evaluate them in both U-HAP
and OPA (via `opa eval`), and assert decisions match. Required gate before
publishing exp5 comparison numbers — without this, the comparison may be
secretly comparing different policies.

Usage:
    python equivalence_test.py --policy-dir ./policy_sets --rego-dir ./rego_sets
    python equivalence_test.py --policy-dir ./policy_sets --rego-dir ./rego_sets --sars 100 --counts 10,100

Exit codes:
    0 = all SARs match
    1 = at least one mismatch (prints offenders)
    2 = setup error (missing files / OPA not on PATH)
"""

from __future__ import annotations

import argparse
import json
import random
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from compiler.registry import ArtifactRegistry  # noqa: E402
from dsl.loader import load_yaml_string          # noqa: E402
from engine.evaluator import evaluate_request    # noqa: E402

HERE = Path(__file__).resolve().parent

NAMESPACES = ["prod", "staging", "dev", "test", "data", "ml"]
RESOURCES  = ["pods", "deployments", "services", "configmaps", "secrets",
              "ingresses", "jobs", "cronjobs"]
ACTIONS    = ["get", "list", "create", "update", "delete", "patch", "watch"]
ROLES      = [f"role-{i}" for i in range(50)]
SUBJECTS   = [f"user-{i}" for i in range(200)]
NETS       = ["on-premise", "remote", "vpn"]
TIMES      = ["business-hours", "after-hours", "weekend"]


def gen_sar(rng: random.Random) -> dict:
    return {
        "namespace": rng.choice(NAMESPACES),
        "resource":  rng.choice(RESOURCES),
        "action":    rng.choice(ACTIONS),
        "uid":       rng.choice(SUBJECTS),
        "roles":     rng.sample(ROLES, k=rng.randint(1, 3)),
        "groups":    [],
        "attrs": {
            "net":  rng.choice(NETS),
            "time": rng.choice(TIMES),
        },
    }


def uhap_decide(registry: ArtifactRegistry, sar: dict) -> bool:
    allow, _ = evaluate_request(
        registry, sar["namespace"], sar["resource"], sar["action"],
        sar["uid"], sar["roles"], sar["groups"], sar["attrs"],
        cache=None,
    )
    return bool(allow)


def opa_decide(rego_file: Path, sar: dict) -> bool:
    """Evaluate SAR via `opa eval` subprocess. Slow but correct."""
    proc = subprocess.run(
        ["opa", "eval",
         "--data", str(rego_file),
         "--stdin-input",
         "--format", "json",
         "data.uhap.decision"],
        input=json.dumps(sar).encode("utf-8"),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"opa eval failed: {proc.stderr.decode()}")
    out = json.loads(proc.stdout.decode())
    # Result shape: {"result":[{"expressions":[{"value": <bool>, ...}]}]}
    try:
        return bool(out["result"][0]["expressions"][0]["value"])
    except (KeyError, IndexError):
        return False


def run_one_set(yaml_path: Path, rego_path: Path, n_sars: int,
                seed: int) -> Tuple[int, int, List[Tuple[dict, bool, bool]]]:
    """Returns (matches, total, mismatches[(sar, uhap, opa), ...])."""
    records = load_yaml_string(yaml_path.read_text(encoding="utf-8"))
    registry = ArtifactRegistry()
    registry.load(records)

    rng = random.Random(seed)
    mismatches: List[Tuple[dict, bool, bool]] = []
    matches = 0
    for _ in range(n_sars):
        sar = gen_sar(rng)
        u = uhap_decide(registry, sar)
        o = opa_decide(rego_path, sar)
        if u == o:
            matches += 1
        else:
            mismatches.append((sar, u, o))
    return matches, n_sars, mismatches


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy-dir", default=str(HERE / "policy_sets"))
    ap.add_argument("--rego-dir",   default=str(HERE / "rego_sets"))
    ap.add_argument("--counts",     default="10,100")
    ap.add_argument("--sars",       type=int, default=100)
    ap.add_argument("--seed",       type=int, default=2026)
    args = ap.parse_args()

    if shutil.which("opa") is None:
        print("ERROR: opa binary not on PATH", file=sys.stderr)
        return 2

    policy_dir = Path(args.policy_dir)
    rego_dir = Path(args.rego_dir)
    counts = [int(x) for x in args.counts.split(",")]

    grand_match = 0
    grand_total = 0
    any_mismatch = False

    for n in counts:
        yaml_path = policy_dir / f"policies_{n}.yaml"
        rego_path = rego_dir / f"policies_{n}.rego"
        if not yaml_path.is_file():
            print(f"  ! missing {yaml_path}", file=sys.stderr); return 2
        if not rego_path.is_file():
            print(f"  ! missing {rego_path} (run yaml_to_rego.py)", file=sys.stderr); return 2

        m, t, miss = run_one_set(yaml_path, rego_path, args.sars, args.seed + n)
        grand_match += m; grand_total += t
        flag = "OK " if not miss else "FAIL"
        print(f"  [{flag}] n={n}: {m}/{t} matched")
        if miss:
            any_mismatch = True
            print(f"      first 5 mismatches:")
            for sar, u, o in miss[:5]:
                print(f"        uhap={u} opa={o}  sar={json.dumps(sar)}")

    print(f"\nGrand total: {grand_match}/{grand_total} matched "
          f"({100 * grand_match / grand_total:.1f}%)")
    return 0 if not any_mismatch else 1


if __name__ == "__main__":
    sys.exit(main())
