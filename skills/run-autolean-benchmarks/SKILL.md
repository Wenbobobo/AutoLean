---
name: run-autolean-benchmarks
description: Run, replay, compare, and audit AutoLean role benchmarks after model, prompt, tool, retrieval, evaluator, environment, or code changes. Use for Prover, statement-formalizer, fidelity-reviewer, cheating-supervisor, or task-allocator experiments and for producing repeatable benchmark evidence without leaking cases, oracles, outputs, or credentials.
---

# Run AutoLean Benchmarks

Operate from the AutoLean repository root. Read `AGENTS.md` and
`docs/role-benchmark-protocol.md` before changing a fixture or interpreting a result.

## Select the evidence level

1. Use `benchmarks/roles/fake-smoke.v1.json` only to test protocol plumbing.
2. Do not describe fake exact-output results as model quality, proof evidence, or semantic
   fidelity.
3. For an external model, first require an operator-owned executor that uses
   `ContextPack`, a current lease-bound `ModelExecutionAuthorizationV1`, and
   `ProviderRegistry.generate`. Refuse to call a provider adapter or endpoint directly.
4. Refuse an online run until that role has an evaluator with the required authority:
   independent Lean verification for Prover; human gold plus mutation and non-vacuity review for
   statement conversion; balanced attack-family labels for reviewers/supervisors; deterministic
   DAG simulation for allocation.
5. Never add or select Anthropic or Claude. Never accept an API key in a fixture, command, report,
   prompt, database, or chat message; use an operator-owned secret reference.

## Freeze the experiment

Before execution, verify that every matrix cell pins:

- role, case IDs and revisions;
- provider, model and model revision;
- generation parameters and provider-configuration hash;
- prompt revision and renderer;
- tool and retrieval artifact hashes;
- repetitions, token, timeout and cost budgets;
- code revision and role-environment hash.

Change one dimension per controlled comparison. Create a new matrix revision when any frozen
field changes. Use at least three repetitions for stochastic calls and preserve all failed trials.
Never merge scores across roles or FATE-M/H/X.

## Run the offline protocol smoke

Use a unique run ID and an absolute or repository-resolved SQLite path:

```powershell
uv run python scripts/role_benchmark.py run `
  --fixture benchmarks/roles/fake-smoke.v1.json `
  --database release-evidence/role-benchmarks/roles.sqlite3 `
  --run-id fake-smoke-v1 `
  --output release-evidence/role-benchmarks/fake-smoke-v1.report.json
```

Replay the report from SQLite and verify byte identity:

```powershell
uv run python scripts/role_benchmark.py report `
  --database release-evidence/role-benchmarks/roles.sqlite3 `
  --run-id fake-smoke-v1 `
  --output release-evidence/role-benchmarks/fake-smoke-v1.replay.json
```

Hash both reports with `Get-FileHash -Algorithm SHA256`; fail if they differ. Do not overwrite an
existing evidence path.

## Compare

Run `scripts/role_benchmark.py compare` with paired runs/cells. Accept causal wording only when
the result says `controlled_ablation` and lists exactly one changed dimension. Treat
`repeatability` as drift evidence and `confounded` as descriptive only.

Report pass rate with Wilson interval, instability, tokens, time, and cost. For Prover also report
pass@1, pass@4, success-at-budget, and cost-to-proof after independent verification. State model,
code, evaluator, prompt, tool, retrieval, environment, case-set, and budget revisions beside every
comparison.

## Close the run

Run the relevant evaluator tests plus `uv lock --check`, Ruff, Mypy, and Pytest. Retain canonical
reports and their SHA-256 values, but do not retain raw restricted case input, oracle values,
prompts, model outputs, secrets, or endpoint configuration. Record blockers as blockers; do not
turn missing API, Lean, OCI, evaluator, or signing evidence into a zero score.
