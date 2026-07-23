# Role Benchmark Protocol

## Current status

The role benchmark harness is an offline architecture fixture, not a model leaderboard. It
currently executes only scripted fake responses and performs no network, Lean, OCI, or FATE
operation. Its purpose is to freeze the experiment boundary before API credentials or paid model
runs are introduced. Provider capability probing is a separate preflight; it never grants model
execution authority.

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

## Wire version

The current fixture, readiness, cell, matrix, run, trial-result, metrics, raw-manifest, report, and
comparison wire schemas are V3. This is an intentional pre-RC breaking migration: V3 binds the
full cell to every work hash, makes reports self-validating, and adds lease-fenced at-most-once
execution. V1/V2 fixtures and reports are rejected, not coerced. Populated V1/V2 SQLite stores
cannot supply the missing evidence and fail closed; use a new V3 database rather than migrating
one in place. `fake-smoke.v1.json` is an answer-free tombstone, not an executable compatibility
fixture.
`schema_version` is the wire authority; internal Python class suffixes are not accepted as a
substitute for it.

## Frozen experiment contract

[`benchmarks.role_benchmark`](../benchmarks/role_benchmark.py) defines versioned case, matrix,
run, result, report, and comparison records. Every matrix cell freezes:

- role and stable case IDs/revisions;
- provider, model, model revision, provider-configuration hash, and generation-parameter hash;
- prompt content/revision and canonical renderer version;
- content-addressed tool and retrieval scopes;
- required provider capabilities;
- repetitions, input/output token ceilings, timeout, and micro-USD ceiling;
- source-code revision hash and role environment hash; and
- stable SHA-256 case selection independent of source order, process RNG, and model identity.

Every selected case/repetition receives a domain-separated SHA-256 trial seed. The seed and its
trial-specific work-item hash are frozen in the run manifest and passed to the executor. This
provides a stable experiment coordinate; it does not imply that a hosted model is deterministic or
that every provider exposes a native sampling-seed parameter.

Each run cell also carries a recomputed binding over its complete answer-free projection:
provider/model target, prompt/tool/retrieval/capability/budget/code/environment hashes, selected
case contracts, evaluator identities, and trial schedule. A V3 `scripted_fake` run rejects any
cell whose `provider_id` is not exactly `fake`; coordinated model/metric/receipt edits cannot retain
the original run-cell binding.

The executor receives an answer-free `RoleBenchmarkWorkItem`. Oracle values remain in the
evaluator-owned case record. SQLite and public reports store only work/evaluator/output hashes,
pass/score fields, resource accounting, and the frozen run manifest. They do not store raw case
input, oracle values, prompts, or model outputs.

Raw JSON outputs are retained separately in a fixed operator-private content-addressed store.
The CLI derives this root from `AUTOLEAN_BENCHMARK_PRIVATE_ROOT` when explicitly configured,
otherwise from the platform's local state directory. The root must be absolute and outside every
Git checkout. A private per-run manifest binds each trial coordinate to the output hash recorded
in the aggregate report. It contains no prompt, input, oracle, credential, endpoint, or absolute
path. Public reports must never embed or publish the manifest or raw blobs, and the public-release
gate rejects their directory and filename patterns. Immediately before writing the manifest, the
CLI revalidates its fixed path against the operator-private root and rejects symlink, junction, and
other reparse-point traversal; a private manifest cannot be redirected into a checkout.

Every public trial has a commitment over the complete `RoleBenchmarkTrialResultV1`, including
verdict, score, elapsed/token/cost accounting, and execution receipt. The report recomputes one
aggregate public-result commitment from the frozen run plus all complete results. The private
manifest repeats that aggregate and each per-trial commitment; replay cross-checks its coordinates,
output hashes, receipt hashes, result commitments, and content hash against the report. Therefore a
coordinated verdict/metric/accounting rewrite that retains the original commitment fails.

These are integrity links, not authenticity. A self-contained unsigned report can be wholly
rewritten together with every embedded commitment. Tamper evidence across trust boundaries requires
an independently retained report/manifest hash or a trusted signature over that hash. Neither the
kernel nor this benchmark harness supplies that signature automatically.

The SQLite store validates its exact V3 schema fingerprint, metadata fingerprint, PRAGMA policy,
foreign keys, integrity check, and every existing run/result/claim/artifact row on open. It uses
WAL plus append-only triggers. Every trial is reserved and irreversibly marked `started` before
the executor call. Concurrent identical runs wait for or reuse one canonical terminal result.
After `started`, a crash leaves an indeterminate claim and automatic retry is forbidden; this
trades liveness for the only defensible at-most-once guarantee without an external transactional
idempotency protocol. An expired claim that never reached `started` may be reclaimed after reopen
with a higher fencing token; the stale token cannot start, abandon, or submit that trial. A report
is emitted only when every selected case and repetition has one terminal result.

## Readiness boundary

`provider_readiness.py` checks each exact provider/model/configuration target against the cell's
frozen required capabilities. Identity or configuration drift stops before the probe. Probe
exceptions are reduced to a credential-free blocker code, observed capability gaps fail closed,
and there is no fallback.

The canonical readiness report always states `authority_granted: false` and reports provider
targets separately from execution backends. The current `authorized_external` backend is
machine-readably blocked because the role harness has no authorization bridge or production role
evaluators. Its canonical content hash is frozen into the run manifest. A green scripted-fake
preflight is therefore not API readiness. Library execution accepts the complete canonical
readiness report, normalizes it, and reruns the fail-closed readiness check itself; callers cannot
substitute an unverified readiness hash.

## Repetition and comparison

Each cell runs every selected case the configured number of times. The report includes:

- pass rate in integer parts per million and a Wilson 95% interval;
- mean score, token/cost/time totals;
- cases whose repeated outcomes disagree; and
- the corresponding instability rate.

Comparisons require identical case revision, input-oracle contract hash, evaluator identity, and
trial schedule/seed bindings. The output records the paired case/trial binding hashes, matrix and
readiness hashes, changed dimensions, `repeatable_bindings`, and byte-output repeatability. Zero
experiment changes is a repeatability check, exactly one is a controlled ablation, and two or more
is labelled `confounded`; any binding change is machine-readably non-repeatable, while output drift
is reported separately even if pass/fail scores tie. Wilson intervals are descriptive because
repeated calls to a hosted model may not be independent.

## Offline commands

The checked-in fixture covers all five initial roles with three repetitions each:

```powershell
uv run python scripts/role_benchmark.py forward-test --output-root .tmp-role-benchmark-v3-a
uv run python scripts/role_benchmark.py forward-test --output-root .tmp-role-benchmark-v3-b
```

Each output root receives `readiness.json`, append-only `roles.sqlite3`, and the answer-free
`report.json`. Raw output CAS data and its per-run manifest remain under the fixed operator-private
root. Runs with the same fixture and run ID must reproduce byte-identical readiness, report, and
private manifest; an existing output path with different bytes is rejected rather than overwritten.
The granular `readiness`, `run`, `report`, and `compare` commands exist for automation. Neither
`run` nor `report` accepts a caller-selected raw artifact path.

The CLI has no endpoint, credential, or provider-selection option. This is deliberate.

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

FATE must enter only through its pinned source manifest and strict proof-slot adapter. A future
FATE Prover role run must join every accepted output to OCI/kernel verification and preserve the
M/H/X split. The fake forward test neither attempts nor scores a FATE theorem.
