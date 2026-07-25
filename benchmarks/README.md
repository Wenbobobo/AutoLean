# Benchmarks

The default benchmark code is offline and answer-free. `fate.lock.json` pins FATE v4.28.0,
its three submodules, Lean, and mathlib. `fate.py` produces deterministic, separately reported
M/H/X splits. It never downloads tasks, starts a model, or opens a solution store.

FATE is a single-theorem benchmark. `project_dag/graph.json` is a separate 20-node fixture for
dependency-frontier, file-lease, API-propagation, and integration tests. A high FATE score does
not substitute for passing the project fixture.

`project_dag/real-lean-content-manifest.v1.json` is a separate, byte-bound T7 preflight fixture:
it maps twenty real Lean declarations across four modules to an explicit declaration content graph.
It does not alter `project_dag.v1` scheduler semantics or turn a local clean build into a T7
acceptance result. See the [T7 real Lean project-DAG preflight](../docs/t7-real-lean-project-dag-preflight.md).

`project_integration.py` binds that fixed graph to public control-plane registration, lease, and
append-only event APIs with synthetic test-only signatures. It records the cross-file topology as
formal-graph metadata and derives execution status from events; it does not put scheduling edges
in mathematical or execution graphs. It starts no Lean process, OCI worker, or model, so passing
the fixture is scheduling/control-plane evidence only, not compilation or proof evidence.

`benchmarks.reporting` is the answer-free reporting contract. It accepts only terminal,
verifier-bound attempt metadata and emits deterministic M/H/X-separated `pass@1`, `pass@4`,
`success@budget`, elapsed-time, token, and cost totals. It deliberately does not start a model or
Lean process; an OCI worker and the control-plane verification evidence remain prerequisites for
any recorded result.

`benchmarks.role_benchmark` adds a separate role-aware experiment contract for Prover, statement
formalizer, fidelity reviewer, cheating supervisor, and task allocator evaluations. It freezes
model/prompt/tool/retrieval/capability/budget/code/environment identities, derives a stable seed
for every repetition, performs stable case sampling, persists repeated answer-free results in
append-only SQLite WAL tables, and reports paired repeatability/ablation/confounding diagnostics.
Capability readiness is probed before execution and grants no authority. Raw JSON outputs live in
a separate operator-private content-addressed store. Run-cell, complete trial-result, and aggregate
public-result commitments bind its private manifest to the answer-free report. These hashes provide
integrity only when retained externally or signed; an unsigned self-contained report has no
independent authenticity. The checked-in CLI is fake-only and makes no external call. See the
[role benchmark protocol](../docs/role-benchmark-protocol.md).

The current role-benchmark wire format and store are V3. V1/V2 SQLite stores, fixtures, readiness
records, and reports are intentionally rejected because their missing bindings cannot be
reconstructed safely. The checked-in V1 file is an answer-free retirement tombstone only.

`tests/test_builder_prover_closed_loop.py` is the one-node offline evidence-closure fixture. It
persists canonical statement-fidelity evidence, freezes and bridges the reviewed revision, records
revision-bound failure feedback, requires a fresh Builder review for the next revision, and runs a
fake proof through independent synthetic acceptance. It executes neither Lean nor OCI; see the
[evidence boundary](../docs/builder-prover-evidence-closure.md).

The public FATE metadata does not provide a per-problem bibliographic source. Treat natural
language redistribution rights as unresolved even though the repositories are MIT licensed.

## Strict Source Adapter

`benchmarks.fate_adapter` does not use FATE-Eval.  An operator supplies a checkout containing the
fixed Git commits in `fate.lock.json`, then uses `uv run python scripts/build_fate_manifest.py
--checkout ... --output ...` to produce a content-addressed source manifest.  Lean task source is
read from the locked Git blobs, not the mutable working tree, so Windows line-ending conversion,
`assume-unchanged`, and working-tree edits cannot redefine a benchmark statement.  The separately
generated FATE metadata and Lake manifest are accepted only when their pinned SHA-256 values match.

The manifest records every original file's SHA-256, target declaration identity, and the byte
hashes on both sides of its single `sorry` token.  Its reported `manifest_sha256` must be stored in
the task bundle; `FateAdapter.from_manifest_file` requires that expected canonical hash before it
accepts a manifest.  It is the only authority for a FATE proof task.

`FateAdapter.materialize_proof` accepts a tactic body for that token, not an arbitrary Lean
file.  It rejects changed theorem declarations, `True` replacements, imports, namespaces,
axioms, `sorry`/`admit`, source drift, proof-slot ambiguity, and source-path traversal before
Lean is invoked.  Candidate files are written only outside the pinned checkout with exclusive,
non-link-following creation; Lean compilation belongs in the separate OCI execution harness.
