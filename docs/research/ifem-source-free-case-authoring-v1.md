# iFEM source-free case authoring v1

Status: deterministic fake-first structural harness. It is neither textbook calibration nor a
model/provider experiment.

## Purpose

`autolean_builder.ifem_source_free_case_authoring` consumes only the canonical
`IFEMNextCalibrationCaseIntentsV1` queue. The queue is revalidated before use and the harness
accepts only its nine `P3/create_calibration_case` intents. The queue's P0, P1, and P2 routes are
not authoring inputs: they retain their existing deterministic/higher-capability or independent
review requirements.

For every P3 intent, the harness creates one in-memory project-synthetic finite signature. It
partitions all nine cases deterministically into `3 train / 3 dev / 3 private_heldout`, then
runs exactly three finite stages in this order:

1. `statement_formalizer` proposes one bounded candidate or abstains.
2. `fidelity_reviewer` sees only the parsed finite author projection.
3. `cheating_supervisor` sees only the two dispositions and a bounded change count.

The resulting plan declares 27 stages and one permitted attempt per stage. V1 supplies only a
deterministic local fake actor. It performs no endpoint I/O, reads no key, and does not create a
provider request.

## Boundary

The in-memory seed maps a stable case handle to a queue intent and contains a hidden finite oracle.
It exists only in memory during the fake run. Neither the public plan nor the public report renders
the node identifier, hidden oracle, finite candidate, source material, span, Lean surface, catalog
label, mutation label, raw agent output, endpoint data, request bytes, or private filesystem
location.

The synthetic finite grammar is intentionally not mathematics. Passing it means that the local
harness can preserve a narrow proposal-review-supervision protocol. It does not establish source
fidelity, theorem truth, Mathlib coverage, semantic equivalence, model capability, role
independence, a frozen statement, or a Prover handoff.

The public report binds the exact in-memory run hash. Report construction rejects even a
canonically rehashed run when its case/partition coordinates differ from the plan.

All authority fields are false. The plan and report expose only `freeze_statement()` and
`handoff_to_prover()` methods that always fail. Since the same fake agent fills all three roles,
the public aggregate records `machine_advisory_disposition=abstain`; it cannot enter the
machine-advisory positive route.

The case handle, partition, and finite seed are deterministically reproducible from the public
queue and this implementation. They are pseudonymous, not secret: a reader with the queue can
recompute a handle from its intent. This is a local structural split, not a blind or
contamination-resistant benchmark holdout. The contract therefore records
`case_linkage_publicly_replayable=true`, `partition_labels_topology_only=true`, and
`heldout_isolation_claimed=false`. In particular, `private_heldout` is an allocation label, not
an access-control claim. No V1 result may be used as held-out model evidence.

## Fake partition topology

V1 mirrors the important concepts from `private_pair_split` and
`private_pair_partition_store`: one scenario per component, deterministic 3/3/3 allocation, no
cross-partition component, and a replayable commitment in the public plan. It intentionally does not
instantiate their filesystem stores or HMAC authenticator. That would add a private root, key
material, and a second runtime to a fake-only harness. Therefore V1 does **not** claim filesystem,
OCI, HSM, or independent held-out isolation.

A future live implementation may reuse the existing private pair store only after it has an
operator-private HMAC implementation and disjoint worker mounts. It must create a new protocol
revision rather than treating a V1 aggregate as live evidence.

## Reproducible fake run

The intent queue must first be materialized by its own source-free tool. Then run:

```text
uv run --frozen python -m scripts.ifem_source_free_case_authoring \
  --intents <CANONICAL_INTENT_QUEUE_JSON> \
  --plan-out <WRITE_ONCE_PLAN_JSON> \
  --report-out <WRITE_ONCE_REPORT_JSON>
```

The plan and report are strict UTF-8 canonical JSON with self-hashes. Role response integers and
booleans are type-strict; JSON strings such as `"1"` and `"true"` are rejected rather than coerced.
Reusing an output path is
allowed only when every byte matches. A caller must use
`verify_source_free_case_authoring_plan_against_intents()` to prove that a loaded plan remains the
exact replay of its input queue; a valid self-hash alone is not provenance.

## Tests

```text
uv run --frozen pytest -q \
  Builder/tests/test_ifem_source_free_case_authoring.py \
  scripts/tests/test_ifem_source_free_case_authoring_script.py
uv run --frozen ruff check \
  Builder/src/autolean_builder/ifem_source_free_case_authoring.py \
  Builder/tests/test_ifem_source_free_case_authoring.py \
  scripts/ifem_source_free_case_authoring.py \
  scripts/tests/test_ifem_source_free_case_authoring_script.py
uv run --frozen ruff format --check \
  Builder/src/autolean_builder/ifem_source_free_case_authoring.py \
  Builder/tests/test_ifem_source_free_case_authoring.py \
  scripts/ifem_source_free_case_authoring.py \
  scripts/tests/test_ifem_source_free_case_authoring_script.py
uv run --frozen mypy --strict \
  Builder/src/autolean_builder/ifem_source_free_case_authoring.py \
  Builder/tests/test_ifem_source_free_case_authoring.py \
  scripts/ifem_source_free_case_authoring.py \
  scripts/tests/test_ifem_source_free_case_authoring_script.py
```

The focused suite covers P0/P1/P2 rejection, 3/3/3 fake partition topology with an explicit
no-isolation claim, exact 27-call counting, public rendering redaction,
duplicate-key/non-finite/free-text/type-coercion rejection, role-card projection isolation, exact
queue replay, rehashed run-coordinate tampering, deterministic fake reruns, write-once
materialization, same-agent abstention, and the absence of benchmark, Prover, HTTP, or
provider-runtime imports.

## Deferred work

No DeepSeek call belongs to V1. A later source-free external trial may send only an explicitly
rights-cleared AutoLean project-synthetic card through the normal `ModelWorkBundleV2`, control-plane
lease, completion receipt, and private output path. It must not reuse the D35 executor, which is a
narrow diagnostic adapter, and it must still report same-model multi-role results as advisory
abstention. Textbook/source-backed Builder calibration stays behind its separate rights and
semantic-fidelity gates.
