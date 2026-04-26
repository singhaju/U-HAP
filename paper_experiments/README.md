# Paper Experiments — U-HAP JCSSE 2026

Reproducible scripts and raw results for the three experiments reported in the paper.

## Requirements

```bash
pip install -r ../requirements.txt
# For Experiment 3 only: download the OPA binary
# https://www.openpolicyagent.org/docs/latest/#running-opa
```

## Experiment 1 — Policy Verification Efficiency (Fig. 2)

Per-request authorization latency as the number of namespaces N ∈ {10,50,100,200,300,500,750,1000} grows (46 rules per namespace, SSO-based baseline).

```bash
cd exp1_exp2/scripts
python run_exp1a.py          # writes ../results/exp1a.csv
```

**Key result:** U-HAP latency stays flat (~15 μs); the SSO baseline grows linearly. Caching adds ~14× speedup on warm requests.

## Experiment 2 — Per-Model Policy Size Impact (Fig. 3)

Per-model latency as rules per namespace k ∈ [5, 320] grows (RBAC / ABAC / ACL evaluated separately, caching disabled).

```bash
cd exp1_exp2/scripts
python run_exp2b.py          # writes ../results/exp2b.csv
```

**Key result:** ABAC reaches 16.9× speedup at k=320 via hash-consed DAG; ACL 5.0×, RBAC 5.6× via hash-set and bit-vector evaluation.

## Experiment 3 — Policy Update Latency vs OPA (Fig. 4)

End-to-end update latency (policy edit → first decision under new policy) compared against [OPA](https://www.openpolicyagent.org/) (CNCF graduated). Each U-HAP policy set is mechanically translated to equivalent Rego; 100/100 decision equivalence is verified before any timing.

```bash
cd exp3_opa

# Step 1 — generate synthetic policy sets
python gen_policies.py --out ./policy_sets

# Step 2 — run U-HAP
python run_exp3.py --uhap --policy-dir ./policy_sets \
    --counts 10,100,500,1000,2000 --reps 30

# Step 3 — start OPA sidecar, then run OPA baseline
bash opa_daemon.sh
python run_exp3.py --opa --policy-dir ./policy_sets \
    --counts 10,100,500,1000,2000 --reps 30 \
    --opa-mode rest --opa-url http://localhost:8181

# Step 4 — combine results and generate plots
python run_exp3.py --plot

# Optional: verify decision equivalence between U-HAP and OPA
python equivalence_test.py --policy-dir ./policy_sets --opa-url http://localhost:8181
```

**Key result:** U-HAP completes the full edit-to-first-decision cycle 2.73× faster than OPA at n=2000 (223 ms vs 611 ms). Post-parse advantage grows to 19.5× (31 ms vs 611 ms), demonstrating asymptotic benefit of compile-time hash consing over OPA's per-update Rego compilation.

| n    | U-HAP (ms) | OPA (ms) | Speedup | Post-parse U-HAP | Post-parse speedup |
|------|-----------|---------|---------|-------------------|--------------------|
| 10   | 1.75      | 2.85    | 1.63×   | 0.14              | 20.4×              |
| 100  | 14.76     | 26.60   | 1.80×   | 2.03              | 13.1×              |
| 500  | 57.35     | 119.40  | 2.08×   | 7.87              | 15.2×              |
| 1000 | 109.99    | 277.32  | 2.52×   | 16.27             | 17.0×              |
| 2000 | 223.41    | 610.54  | 2.73×   | 31.31             | 19.5×              |

Raw results are in `exp3_opa/results/exp5_update_latency.csv`.

## Regenerate figures

```bash
python regen_figures.py      # writes to ../figures/
```

Produces `fig2_namespace_isolation.png`, `fig3_permodel_latency.png`, `fig5_update_latency.png`.
