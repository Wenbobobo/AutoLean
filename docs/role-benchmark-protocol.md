# Role Benchmark Protocol

## Current status

The role benchmark harness is an offline architecture fixture, not a model leaderboard. It
currently executes only scripted fake responses and performs no network, provider, Lean, OCI, or
FATE operation. Its purpose is to freeze the experiment boundary before API credentials or paid
model runs are introduced.

The initial role vocabulary is:

| Role | Intended evidence |
| --- | --- |
| `prover` | Proof-search output under a frozen statement and verifier boundary |
| `statement_formalizer` | Candidate formal statement generation |
| `fidelity_reviewer` | Semantic mutation detection and false-positive control |
| `cheating_supervisor` | Statement replacement, axiom, import, and proof-boundary attack detection |
| `task_allocator` | Dependency-frontier, lease, and scheduling decisions |

Scores from different roles are never merged. In particular, an exact-output fake Prover score is
not proof evidence; a real Prover result must be joined to independent verifier evidence.

## Frozen experiment contract

[`benchmarks.role_benchmark`](../benchmarks/role_benchmark.py) defines versioned case, matrix,
run, result, report, and comparison records. Every matrix cell freezes:

- role and stable case IDs/revisions;
- provider, model, model revision, provider-configuration hash, and generation-parameter hash;
- prompt content/revision and canonical renderer version;
- content-addressed tool and retrieval scopes;
- repetitions, input/output token ceilings, timeout, and micro-USD ceiling;
- source-code revision hash and role environment hash; and
- stable SHA-256 case selection independent of source order, process RNG, and model identity.

The executor receives an answer-free `RoleBenchmarkWorkItem`. Oracle values remain in the
evaluator-owned case record. SQLite and public reports store only work/evaluator/output hashes,
pass/score fields, resource accounting, and the frozen run manifest. They do not store raw case
input, oracle values, prompts, or model outputs.

The SQLite store uses WAL plus append-only triggers. Replaying an identical run or trial is
idempotent; reusing the same coordinate for different content fails. A report is emitted only when
every selected case and repetition has one terminal result.

## Repetition and comparison

Each cell runs every selected case the configured number of times. The report includes:

- pass rate in integer parts per million and a Wilson 95% interval;
- mean score, token/cost/time totals;
- cases whose repeated outcomes disagree; and
- the corresponding instability rate.

Comparisons are paired by exact case ID and repetition. The comparison record enumerates changed
dimensions. Zero changes is a repeatability check, exactly one is a controlled ablation, and two
or more is labelled `confounded`; a confounded result must not be given a causal interpretation.
Wilson intervals are descriptive because repeated calls to a hosted model may not be independent.

## Offline commands

The checked-in fixture covers all five initial roles with three repetitions each:

```powershell
uv run python scripts/role_benchmark.py run `
  --fixture benchmarks/roles/fake-smoke.v1.json `
  --database .tmp-role-benchmark/roles.sqlite3 `
  --run-id fake-smoke-v1

uv run python scripts/role_benchmark.py report `
  --database .tmp-role-benchmark/roles.sqlite3 `
  --run-id fake-smoke-v1
```

The CLI has no endpoint, credential, or provider-selection option. Its `run` command validates
that every matrix cell uses the fake provider. This is deliberate.

To compare stored cells or repeated runs:

```powershell
uv run python scripts/role_benchmark.py compare `
  --database .tmp-role-benchmark/roles.sqlite3 `
  --baseline-run baseline-v1 `
  --baseline-cell fake.prover `
  --candidate-run candidate-v1 `
  --candidate-cell fake.prover
```

Use a script or short command file for repeated production runs rather than expanding this into a
long shell command.

## External-provider bridge

An online executor is future work and must be operator-owned. It must build a role-scoped
`ContextPack`, obtain a current lease-bound `ModelExecutionAuthorizationV1`, and call
`ProviderRegistry.generate`. It may not call a raw provider adapter or endpoint from this harness.
The resulting trial must retain provider usage and authorization/evidence identities without
persisting credentials or raw restricted context.

Before model ranking, each role needs a role-specific evaluator:

- Prover: independent Lean verification and cost-to-proof;
- statement formalizer: human gold statements, mutation tests, non-vacuity, and semantic review;
- fidelity reviewer and cheating supervisor: balanced positive/negative sets with precision,
  recall, false-positive rate, and attack-family slices; and
- task allocator: deterministic DAG simulations followed by project-level throughput and
  correctness measurements.

The current `exact_json_v1` scorer is sufficient only for protocol and fake-fixture tests. It
cannot establish semantic fidelity, proof validity, or production scheduling quality.
