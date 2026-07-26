# T7 Real Lean Changed-Source Preflight

## Conclusion

This operator-local preflight exercises one fixed API-propagation case over the existing
four-module, twenty-declaration real-Lean fixture. It proves only this narrow sequence:

1. the committed baseline builds cleanly;
2. `Arithmetic.score` changes from `Nat` to `(bonus : Nat) → Nat` in a temporary snapshot;
3. the unchanged baseline `Relations.lean` fails against that new compiled API;
4. manifest-bound compatibility edits produce a successor that rebuilds Arithmetic, Relations,
   and Capstone; and
5. Foundations source and OLean bytes remain unchanged and are explicitly reused.

It remains **T7 preflight only**. It is not a task-contract, provider, lease, gateway, image-owned
verifier, semantic-review, or acceptance result.

## Committed change case

`benchmarks/project_dag/real-lean-change-case.v1.json` binds the baseline content-manifest hash,
the changed declaration ID, two expected elaborated-type hashes, every source replacement, every
successor source hash, and both reverse closures.

The loader parses one stable read of a regular, non-symlink manifest and captures that same byte
sequence's SHA-256 in the immutable case object. Execution and reporting use the captured digest;
they do not re-read a mutable path at the end of the run.

The baseline real-Lean fixture loader also computes its manifest SHA-256 from the exact byte
sequence passed to JSON parsing. The loaded graph and every derived rebuild bundle retain that
captured digest even if the original manifest path changes later.

Every replacement's old text must occur exactly once. Arithmetic changes:

```text
score : Nat
```

to:

```text
score (bonus : Nat) : Nat
```

The downstream successor passes `0`, preserving this fixture's original computed values while
adapting to the new public API. This is a deliberately chosen compatibility example, not a claim
that arbitrary API changes preserve semantics.

The two plans have different meanings:

| Plan | Bound result | Execution meaning |
| --- | --- | --- |
| Curated declaration invalidation | Exact eleven-node reverse closure from `arithmetic.score` | Review and scheduling hint derived from the committed content graph |
| Module reverse-import closure | Arithmetic, Relations, Capstone | Actual Lean recompilation units |

The runner does not claim that Lean recompiles individual declarations, and it does not infer a
general dependency graph from source or OLean files.

## Rebuild bundle boundary

`benchmarks.real_lean_project_dag_rebuild` now turns a **complete candidate source-hash
snapshot** plus explicit changed declaration IDs into an immutable, content-addressed rebuild
bundle. It refuses an incomplete snapshot, duplicate or unknown declaration IDs, and declarations
that do not belong to a changed source module. Its order is always the fixture's stable
topological order.

The bundle keeps the three meanings separate:

| Field | Meaning |
| --- | --- |
| `changed_declaration_ids` | Explicit semantic/API changes supplied by the reviewed change case |
| `declaration_invalidation_plan` | Exact formal/content-graph reverse closure from those explicit declaration IDs |
| `module_rebuild_plan` | Conservative Lean compilation closure: the changed module plus reverse importers |
| `module_reuse_plan` | Unchanged modules whose baseline OLean is eligible for byte-identity reuse |

For the committed case, the upstream `Arithmetic` source hash is the sole direct source change and
`arithmetic.score` is the sole explicit declaration change. The declaration closure remains the
curated eleven nodes, while the module plan conservatively schedules Arithmetic, Relations, and
Capstone and records Foundations as an explicit reuse. It is generated before downstream
compatibility edits are materialized, so it captures the causal planning boundary rather than
retroactively calling those edits independent root changes.

The planning bundle has `execution_status: refused_pending_control_plane_lease` and requires a
control-plane lease plus fencing token. The current runner remains an operator-local diagnostic.

`benchmarks.real_lean_project_dag_execution` now provides a deliberately narrow result-recording
skeleton. Before sealing anything, it reconstructs the complete source-hash snapshot from the
plan's source bindings, reruns the deterministic planner, and requires byte-for-byte equality with
the supplied plan. It then seals that plan and its declaration result graph in the immutable
artifact store and derives the lease job ID from the result-manifest hash. A recorder must use that
exact job ID and a live `LeaseStore` fencing token to append each terminal node result through
`EventStore.append_fenced`. The lease check and append occur in one SQLite transaction, so an
expired or superseded recorder cannot append a new `VERIFIED` record. An unchanged node can record
only `REUSED` with the exact baseline artifact reference frozen for that node; a planned rebuild
node can record only `VERIFIED` or `FAILED`; and a terminal `FAILED` node cannot later be
overwritten as `VERIFIED`.

The V1 result manifest by itself does not persist source bytes or bind a toolchain/image. Its
baseline-reference mapping remains an interface-level binding and its focused tests use opaque test
artifacts. It is not complete worker input and does not establish authoritative Lean-output reuse
or verification.

## Immutable worker contract and fake runner

`benchmarks.real_lean_project_dag_worker_contract` adds a separate boundary above that V1 store.
The legacy V1 schema remains available to its compatibility tests, while the typed adapter writes a
distinct synthetic V2 event stream:

1. `ChangedSourceWitnessV1` binds every module's baseline and candidate source artifact, the exact
   changed-module set, the claimed declaration IDs, and the reviewed successor-manifest artifact;
2. `reviewed_fixture_manifest_v1` currently accepts only the committed
   `real-lean-change-case.v1.json` SHA-256. A caller cannot mint a new reviewed manifest by setting a
   string field;
3. the witness takes `arithmetic.score` from that locked manifest. The typed planner has no free
   `changed_declaration_ids` parameter, so changing `Arithmetic.score` while claiming
   `arithmetic.sum-is-seven`, or supplying no changed declaration, fails closed;
4. candidate bytes must equal the manifest's exact reviewed replacements. Missing files, links,
   paths outside the snapshot root, artifact substitution/loss, and unreviewed source,
   import, or declaration-surface drift fail closed. This layer does not implement another Lean
   parser;
5. it binds a Lean version, full mathlib Git commit, OCI repository RepoDigest, and runner-policy
   SHA-256 identity; an image tag or image ID is not accepted in place of
   `repository@sha256:<digest>`, while the policy hash alone is not evidence that policy bytes were
   supplied or enforced;
6. before plan creation and on every status read, it revalidates the witness and derives the plan
   from its candidate artifacts and manifest-bound declaration IDs;
7. it recomputes the V1 execution graph from the fixture, derived plan, and exact baseline
   references rather than trusting a shape-valid frozen dataclass;
8. it seals the witness, source snapshot, environment artifact, V1 execution bundle, and plan hash
   into one immutable worker-input artifact; and
9. planned rebuilds can enter the new adapter only as a canonical
   `LeanNodeVerificationReceiptV1`.

The typed receipt is **synthetic declaration-node evidence** within a planned module rebuild. It
binds the worker input, V1 execution bundle, node, containing module, rebuild action, module source
artifact, exact dependency result artifacts, environment identity, lease job/holder/fencing token,
exit code, stdout, stderr, and result artifact. It is fixed to evidence class
`synthetic_fake_node_v1` and `promotion_eligible: false`. Attempts to remove or replace the evidence
class, or set promotion eligibility, are rejected during commit and status projection.

The receipt's internal V1-compatible `VERIFIED` outcome requires exit code zero and `FAILED`
requires a nonzero exit code. The typed path never publishes or returns that naked V1 status.
Its durable `t7_synthetic_node_v2` event binds the worker, witness, plan, execution, environment,
receipt, node-result artifacts, lease holder and fencing token. The event carries only a typed
`SYNTHETIC_COMPLETE`, `SYNTHETIC_FAILED`, or `SYNTHETIC_REUSED` outcome, with
`synthetic_fake_node_v1` and `promotion_eligible: false` in the payload itself. Commit returns a
`SyntheticNodeCommitResultV2`, not the underlying stored event. The lease job and node-stream
identity derive from the complete worker-input hash, so two environment bindings cannot collide
under one execution-bundle ID.

Aggregate status returns
`SYNTHETIC_PENDING`, `SYNTHETIC_FAILED`, or `SYNTHETIC_COMPLETE`, always paired with
`synthetic_fake_node_v1` and `promotion_eligible: false`. Status derivation revalidates the witness,
receipt, and every nested artifact, so later source, manifest, environment, output, or receipt
loss/corruption makes the status fail closed. None of these statuses says Lean or OCI ran.

The fixture contains four modules and twenty declaration nodes. Twenty node receipts must not be
read as twenty module compilations. The next layer is now specified in
`t7-oci-module-build-receipt.md`: one typed module receipt and one atomic, deterministic fanout over
the locked declaration query. Its tests remain synthetic and its operator preflight remains
non-executing; the T6 image still needs an image-owned module build/query wrapper before this can
record an operator-local OCI observation.

Reuse is intentionally not represented as a node-verification receipt. The adapter accepts only a
node ID and selects the exact baseline artifact already frozen in the V1 bundle. For rebuilds, the
adapter accepts a frozen typed receipt rather than a caller-selected result artifact. It checks
each declared dependency result against the durable upstream event: a rebuilt dependency
contributes the result artifact inside its synthetic-success receipt, while a reused dependency
contributes its exact baseline artifact.

The legacy `RealLeanRebuildExecutionStore.commit_node` remains available for V1 compatibility. A
worker composition that claims this new boundary must expose only
`RealLeanTypedWorkerReceiptStore`; directly handing the legacy store to a worker would bypass the
typed-receipt API and is outside this contract. A repository import-boundary test restricts raw
planner/store imports to tests, this adapter, and the locked changed-source preflight.

The focused tests use a deterministic fake node verifier. They prove contract validation, CAS
reverification, dependency binding, and lease fencing only. It does not invoke Lean, Docker, WSL,
or a subprocess, and its synthetic result bytes are not OLean evidence. The typed status is
mechanically non-promotable; it is not a module-build receipt, task-contract verification outcome,
semantic review, proof result, or acceptance signal.

## Causal checks

The runner creates fresh baseline, upstream-only, and complete-successor source snapshots. The
committed source tree is mounted nowhere directly and is never modified. All source mounts are
read-only. The exact source-v2 image is used with `--pull=never`, `--network none`, and a read-only
container root.

The incomplete-change failure is not accepted merely because a command returned nonzero:

- the baseline, including the old Relations module, must first compile;
- the changed Arithmetic module must compile;
- a fixed host-mounted Lean query must load each Arithmetic OLean and establish that the canonical
  elaborated types differ, with both type hashes bound by the change-case manifest;
- unchanged Relations must return Lean's semantic-error exit code and its diagnostic must identify
  `Arithmetic.score` as a `Nat → Nat` value where a `Nat` was expected; and
- the successor Relations source, whose exact edits and hash are bound by the manifest, must then
  compile against the same changed API.

The type query is source-hashed in the result, but it is host-mounted. Therefore it is diagnostic
preflight evidence only and must not be presented as an image-owned query or OCI-verifier result.

Foundations is copied byte-for-byte from the baseline output into the incomplete and successor
module trees because Lean resolves one module tree rather than merging namespace directories from
multiple search roots. The runner verifies the same source and OLean SHA-256 in all three phases
and never invokes Lean on `Foundations.lean` after the baseline. Each affected module must emit a
fresh OLean whose hash differs from its baseline OLean.

## Commands

Run the offline manifest and closure validation:

```text
uv run --frozen python -m scripts.real_lean_changed_source_preflight validate --json
```

Run the real pinned source-v2 canary on an operator machine with the image already present:

```text
uv run --frozen python -m scripts.real_lean_changed_source_preflight run
```

The normal unit tests do not invoke Docker. The real integration test is opt-in:

```text
AUTOLEAN_RUN_T7_CHANGED_SOURCE_PREFLIGHT=1 uv run --frozen pytest scripts/tests/test_real_lean_changed_source_preflight.py -q
```

On PowerShell, set the environment variable for the current process before running the same short
`uv` command.

Run the immutable worker-contract and fake-node-verifier tests without Docker:

```text
uv run --frozen pytest benchmarks/tests/test_real_lean_project_dag_worker_contract.py -q
```

Run the module-receipt, atomic-fanout, and operator-preflight contract tests:

```text
uv run --frozen pytest benchmarks/tests/test_real_lean_project_dag_module_build.py scripts/tests/test_real_lean_module_build_preflight.py -q
```

## Non-claims and next boundary

Passing this case does not validate arbitrary changed-source propagation, concurrent rebuilds,
agent patches, theorem fidelity, proof acceptance, or the target-free Library verifier path. The
worker contract is complete only for the bytes and identities it binds; it is not proof that those
bytes were executed by the named OCI image. Its allowlisted witness covers only the committed
Arithmetic successor, and it does not prove the eleven-node curated graph is complete for another
source or change manifest.

The module-level V1 contract now binds reviewed immutable artifacts to one receipt and atomic
declaration fanout, but every current evidence class remains explicitly ineligible for promotion
and kernel acceptance. The later T7 acceptance harness must obtain an image-owned module wrapper,
a trusted verifier/gateway attestation, and theorem-level kernel verification before consuming any
fanout as acceptance evidence. This fixture, fake runner, and operator capability preflight provide
deterministic failure/rebuild and contract cases for that later harness; they do not replace it.
