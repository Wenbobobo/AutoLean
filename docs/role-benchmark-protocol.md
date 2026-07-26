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

The canonical V3 readiness report always states `authority_granted: false` and reports provider
targets separately from execution backends. The V3 `authorized_external` backend remains
machine-readably blocked because V3 has no production role evaluators and admits only the
scripted-fake execution receipt. Its canonical content hash is frozen into the run manifest. A
green scripted-fake preflight is therefore not API readiness. Library execution accepts the
complete canonical readiness report, normalizes it, and reruns the fail-closed readiness check
itself; callers cannot substitute an unverified readiness hash.

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

To compare one stored cell pair or repeated run:

```powershell
uv run python scripts/role_benchmark.py compare `
  --database .tmp-role-benchmark/roles.sqlite3 `
  --baseline-run baseline-v1 `
  --baseline-cell fake.prover `
  --candidate-run candidate-v1 `
  --candidate-cell fake.prover
```

To compare the checked-in V3 role-calibration suite, use its named preset rather than manually
merging per-role outputs:

```powershell
uv run python scripts/role_benchmark.py compare-suite `
  --database .tmp-role-benchmark/roles.sqlite3 `
  --baseline-run calibration-v1 `
  --candidate-run calibration-v1 `
  --preset calibration-pairs-v3
```

`calibration-pairs-v3` expands, in this fixed order, to the five oracle/mutant pairs for Prover,
statement formalizer, fidelity reviewer, cheating supervisor, and task allocator. A preset and
explicit `--cell-pair` values may be supplied together: the preset pairs are expanded first and
the explicit pairs are appended. They are never overridden or deduplicated. Every resulting pair
must stay within one role, and the suite rejects any second comparison for an already represented
role. Since `calibration-pairs-v3` already represents all five initial roles, an additional valid
pair necessarily fails as a duplicate role; an additional cross-role pair fails as a cross-role
comparison.

The suite output is only a deterministic bundle of pairwise comparisons. It does not compute a
global score across Prover, formalizer, reviewer, supervisor, and allocator roles.

Use a script or short command file for repeated production runs rather than expanding this into a
long shell command.

## External-provider bridge

`benchmarks.authorized_role_bridge` is a separate, non-promotable execution substrate; it does not
change or extend the V3 fake report. Its deterministic suite builder accepts a provider/model
target but derives all five role cells and ten cases from the checked-in
`calibration-pairs.v3.json` bytes. The loader pins SHA-256
`367b6cad7ca259798b20fd1710f29b06c64f2fbdbea58687588e450ab88761d8`, verifies the repository
Apache-2.0 license bytes at SHA-256
`5c9817c129b98e7bb966bca028c43c19107102ef8e03fe799bffb4354f4ef015`, and records each
answer-free outbound prompt as an explicit source span in private in-process planner state.
Before shared handoff it projects the complete local `SourceRecordV1` and `RightsRecordV1` into
prompt-free bindings containing only domain-separated typed digests, decisions, endpoint classes,
and optional offsets. Titles, locators, metadata, excerpts, attribution, restrictions, license
text, and reviewer text never enter `ModelWorkBundleV2` or the control-plane database. The builder
emits local trusted-work evidence binding the fixture and license hashes, exact matrix and suite
definition, source, rights, derived span set, provider target, and frozen generation policy. This
is explicitly non-cryptographic, non-promotable software-root evidence; it is not presented as a
production signer or KMS attestation. Every trial recomputes it before registration, lease
acquisition, capability issue, or provider I/O. Caller-supplied matrices, sources, rights, or
prepared work cannot replace the locked suite.

For every trial the bridge creates one rights-bound `ModelWorkBundleV2`, rather than fabricating a
theorem statement contract. The bundle binds the run, cell, case, repetition, role, work item,
role environment, exact egress span hash, answer-free context hash, request hash, and prompt-free
source and rights projections. Planner coordinates and upstream contract hashes are converted to
domain-separated typed digests; deterministic bundle and work-contract IDs use fixed namespaces.
V2 rejects prompt/source-excerpt bytes, free-text provenance, tools, and retrieval.

`AuthorizedRoleGenerationPolicyV1` is the complete supported per-request generation surface:
`reasoning_effort` and a positive timeout of at most 3600 seconds. Its canonical hash must equal
every target's `generation_parameters_hash`. The same policy determines each cell's `timeout_ms`,
the exact `ModelRequest.reasoning_effort` and `ModelRequest.timeout_seconds`, required capabilities,
request hash, and trusted-work evidence. A non-null reasoning effort requires the provider's
declared and probed `REASONING_EFFORT` capability. The request timeout is enforced inside the HTTP
or CLI adapter as `min(provider ceiling, request timeout)`; elapsed time remains reporting evidence,
not post-hoc timeout enforcement.

An independent caller must first supply a `MODEL_WORK_ADMISSION` attestation for every exact bundle
ID. The control plane verifies and persists that attestation before it registers the immutable
work, grants a fenced lease, and issues the existing
`ModelExecutionAuthorizationV1` wire capability. The bridge then invokes only
`ProviderRegistry.generate`, so provider approval, endpoint class, token/cost budget, circuit
breaker, settlement, and failure accounting remain on the same path used by Prover model calls.
For the fixed floor suite, all ten prepared bundles, caller-supplied admissions, exact one-attempt
budgets, approval snapshots, provider bindings, and effective provider timeouts are validated
without a database write, capability probe, or provider call. A bad sixth admission therefore
causes zero model calls and zero model-work registration state, and the corrected suite can start
cleanly. Only after that full gate passes does each trial register, claim, issue, preflight, and
generate in sequence. No later trial receives a capability before the preceding trial settles.
Authorization lifetime must cover the frozen request timeout plus a positive settlement margin
and remains subject to the configured and one-hour authorization caps. The lease must outlive that
authorization by a separate positive claim-to-issue margin; the margin is not counted against the
authorization cap.
Because the floor executes serially, admission `i` in stable trial order must retain at least
`sum(resolved_lease_ttl[0:i+1])` seconds at suite preflight. This cumulative bound prevents
a parent admission that is valid for one trial from expiring before its just-in-time authorization
can be minted and conservatively covers preceding provider/persistence slots plus the current
claim-to-issue and authorization windows. Runtime admission, lease, and fencing checks still run
again immediately before each provider call.
The complete normalized `ModelResponse` available at the registry boundary (text, response ID,
tool calls, and usage) is written first to an operator-private content-addressed store outside
the repository. The bridge does not claim to retain the transport's original HTTP response body.
A private manifest is stored only after all ten responses exist; only then can the public sidecar
be returned. Its true content digest and exact per-trial token/elapsed accounting remain private;
the V2 public suite sidecar exposes only a random opaque private handle, aggregate usage buckets,
and one coarse usage bucket set per trial. The V1 sidecar contracts remain unchanged and are not
accepted by the private evaluator. The evaluator recomputes all V2 trial buckets and the suite
aggregate from authenticated private manifest entries, then rechecks the same values against the
response artifact and reconciliation state. Missing or drifted buckets fail closed.
The private handle mapping is authenticated by a mandatory, non-serializable operator-private
authenticator over the handle, manifest hash, run ID, ten coordinates, and ten authorization
hashes. The key is neither persisted nor returned. Restart reconciliation therefore requires key
reinjection; substitution, truncation, or a wrong key fails closed. The repository HMAC
implementation is explicitly test-only; production operators must replace it with a KMS/HSM
implementation of the same boundary.
It omits each private response hash as well as the response, so low-entropy model output cannot be
tested against a public content digest. Local evaluation exposes only a keyed, domain-separated
commitment produced through the injected manifest authenticator. It is stable for the same
authenticated coordinate/entry/bundle but differs from both the private CAS digest and the former
enumerable unsalted construction. The private store also requires the reconciliation `bundle_id`
to equal the exact prepared work bundle on every response and commitment read. Before each
provider call the private store writes a conservative dispatch journal. If the process stops after
a provider response but before private CAS persistence, the state remains
`provider_outcome_ambiguous` and automatic replay is forbidden until an operator reconciles it.
The sidecar hard-codes
`production_evaluator: false`, `floor_claim_eligible: false`, and
`cross_role_aggregation_permitted: false`; it contains neither the evaluator oracle, a verdict,
score, prompt, nor raw model output.

The checked-in ten-case calibration fixture now has an offline authorization-bridge test across
all five roles. This proves the execution boundary and answer separation, not model quality.
Operator-authorized API runs may use the substrate, but their sidecars cannot enter the V3 report
or support a capability-floor claim until role-specific production evaluators exist.

The fixed-suite API is deliberately two-step:

Every bridge/evaluator `run_id` is one portable ASCII slug: it starts and ends
with an alphanumeric character, contains only alphanumerics plus `._-`, and
rejects `..`, path separators, colons, drive paths, and UNC paths. Invalid input
is replaced by a generic failure and is never reflected into an error or report.

```python
suite = build_locked_calibration_floor_suite(
    target,
    generation_policy=AuthorizedRoleGenerationPolicyV1(
        reasoning_effort="high",
        timeout_seconds=120,
    ),
    repetitions=1,
    max_cost_microusd_per_trial=bounded_cost,
)
trials = prepare_locked_floor_trials(suite, run_id=run_id)  # dry-run; no provider I/O
admissions_by_bundle_id = admission_authority.admit(trials)

sidecar = run_authorized_role_floor_suite(
    suite,
    run_id=run_id,
    authorization_service=authorization_service,
    admissions_by_bundle_id=admissions_by_bundle_id,
    registry=registry,
    approval=operator_registered_approval,
    budgets_by_cell=exact_one_attempt_budgets,
    raw_output_store=AuthorizedRoleRawOutputStore(
        operator_private_root,
        private_authenticator=operator_private_authenticator,
    ),
)
```

The caller constructs `target` from the already loaded operator profile and provider binding.
Its `generation_parameters_hash` must be the exact canonical policy hash shown above; the caller
must choose a timeout no greater than the provider profile when it intends that request bound to
be effective.
`authorization_service`, `registry`, and `approval` must be the same operator-controlled objects;
each budget must exactly equal its locked cell token and cost limits. `operator_private_root` must
be outside the repository and any Git checkout. The dry-run returns ten fully bound work bundles
and recomputes the locked work evidence without contacting the endpoint.

Bridge-local evidence lets the independent admission authority decide whether a trial really
comes from the locked fixture; it does not replace that authority. The generic service now rejects
unsigned work and revalidates the exact persisted admission at claim and issue. The checked-in
tests use a purpose-dedicated process-local HMAC outside the bridge, so they are architecture
evidence only. The optional
[`authorized_role_evaluation`](deepseek-role-operator.md#optional-local-exact-json-evaluation)
path now performs authenticated private exact-JSON scoring for the ten synthetic calibration
cases, but its authority is fixed to `local_exact_json_nonproduction` and role-floor admission is
forbidden. A DeepSeek role-floor CLI remains non-production until the signer is a separately
authenticated mTLS/KMS service and the role-specific evaluators below exist.

Before model ranking, each role needs a role-specific evaluator:

- Prover: independent Lean verification and cost-to-proof;
- statement formalizer: human gold statements, mutation tests, non-vacuity, and semantic review;
- fidelity reviewer and cheating supervisor: balanced positive/negative sets with precision,
  recall, false-positive rate, and attack-family slices; and
- task allocator: deterministic DAG simulations followed by project-level throughput and
  correctness measurements.

The current local exact-JSON scorer is sufficient only for protocol and locked synthetic-fixture
calibration. It cannot establish semantic fidelity, proof validity, cheating-detector quality, or
production scheduling quality.

FATE must enter only through its pinned source manifest and strict proof-slot adapter. A future
FATE Prover role run must join every accepted output to OCI/kernel verification and preserve the
M/H/X split. The fake forward test neither attempts nor scores a FATE theorem.
