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

## Non-claims and next boundary

Passing this case does not validate arbitrary changed-source propagation, scheduler leases,
concurrent rebuilds, immutable task bundles, agent patches, theorem fidelity, proof acceptance, or
the target-free Library verifier path. It also does not prove the eleven-node curated graph is
complete for any source other than this committed fixture.

The later T7 acceptance harness must bind reviewed task contracts and immutable artifacts to the
execution graph, use the image-owned verifier/gateway path, and test changed-source propagation
under real scheduling and recovery. This preflight provides one deterministic Lean failure/rebuild
case for that later harness; it does not replace it.
