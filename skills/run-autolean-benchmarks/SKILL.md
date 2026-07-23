---
name: run-autolean-benchmarks
description: Preflight, run, replay, compare, and audit AutoLean role benchmarks after model, prompt, tool, retrieval, evaluator, environment, or code changes. Use for Prover, statement-formalizer, fidelity-reviewer, cheating-supervisor, or task-router/task-allocator experiments and for producing repeatable public reports plus separately controlled raw-output evidence without leaking cases, oracles, prompts, endpoints, or credentials.
---

# Run AutoLean Benchmarks

Operate from the AutoLean repository root. Read `AGENTS.md` and
`docs/role-benchmark-protocol.md` before changing a fixture or interpreting a result.

## Select the evidence level

1. Use `benchmarks/roles/fake-smoke.v3.json` only to test protocol plumbing. Treat the V1 file as
   a retirement tombstone, never as a fixture.
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
6. Treat `readiness.json` as capability evidence only. It must state
   `authority_granted: false`; it cannot replace a lease-bound execution authorization.
7. Require V3 fixture/readiness/run/report/raw-manifest schemas and a fresh V3 SQLite database.
   Refuse V1/V2 stores and wire records; never infer missing bindings.

## Freeze the experiment

Before execution, verify that every matrix cell pins:

- role, case IDs and revisions;
- provider, model and model revision;
- generation parameters and provider-configuration hash;
- prompt revision and renderer;
- tool and retrieval artifact hashes;
- required provider capabilities;
- canonical readiness-report hash;
- repetitions, token, timeout and cost budgets;
- code revision and role-environment hash.

Change one dimension per controlled comparison. Create a new matrix revision when any frozen
field changes. Use at least three repetitions for stochastic calls and preserve all failed trials.
Preserve each derived trial seed and trial work-item hash. Never merge scores across roles or
FATE-M/H/X.

Require every run cell's complete binding, every trial's full-result commitment, and the report's
aggregate public-result commitment. Cross-check the same aggregate and per-trial commitments in
the private manifest. Reject a report that changes verdict, score, accounting, model identity,
metrics, or receipt while retaining an old commitment.

## Run the offline protocol smoke

Use the bundled forward test rather than reconstructing a long command:

```powershell
uv run python scripts/role_benchmark.py forward-test --output-root .tmp-role-benchmark-v3-a
uv run python scripts/role_benchmark.py forward-test --output-root .tmp-role-benchmark-v3-b
```

Require byte-identical `readiness.json` and `report.json` across both roots, and an unchanged
private per-run manifest. The readiness report must mark `scripted_fake` ready and
`authorized_external` blocked. Raw JSON and its manifest live only under the fixed
operator-private state root, outside every Git checkout. Do not add caller-selected raw paths,
publish that state, or copy it into the output roots.

## Compare

Run `scripts/role_benchmark.py compare` with paired runs/cells. Accept causal wording only when
the result says `controlled_ablation` and lists exactly one changed dimension. Treat
`repeatability` as drift evidence and `confounded` as descriptive only. Require identical
case-revision, input-oracle, evaluator, and trial bindings. Report both `repeatable_bindings` and
byte-output repeatability; do not call a changed binding repeatable.

Report pass rate with Wilson interval, instability, tokens, time, and cost. For Prover also report
pass@1, pass@4, success-at-budget, and cost-to-proof after independent verification. State model,
code, evaluator, prompt, tool, retrieval, environment, case-set, and budget revisions beside every
comparison.

## Close the run

Run the relevant evaluator tests plus `uv lock --check`, Ruff, Mypy, and Pytest. Retain canonical
public reports and their SHA-256 values. Keep raw model JSON only in the separate private CAS with
an explicit access/retention policy; never put raw restricted case input, oracle values, prompts,
secrets, endpoint URLs, or endpoint configuration there. Record blockers as blockers; do not turn
missing API, Lean, OCI, evaluator, or signing evidence into a zero score.

If execution crashes after a trial is marked `started`, report the claim as indeterminate. Never
delete it or retry automatically; only a future executor with an external transactional
idempotency protocol may relax this at-most-once boundary.

Treat an expired unstarted claim differently: reclaim it only with a higher fencing token and
reject every operation made with the stale token.

Do not call a self-contained unsigned report authenticated. Its internal commitments prove only
consistency. Preserve the report/manifest hash independently or require a trusted signature before
using the result across a trust boundary.
