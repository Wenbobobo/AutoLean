# iFEM coarse local calibration plan v1

Status: M4.7a plan-only boundary. No calibration execution has been authorized or performed.

## Purpose

This protocol records which already indexed iFEM notebook cells would form the first coarse
local calibration input set after a separate rights decision. The record is public,
digest-only, read-only, and non-executable. The four cells are source containers, not selected
mathematical claim spans and not a frozen statement contract.

The protocol does not reuse the synthetic self-calibration corpus. It does not contain source
text, model input, a provider, an endpoint, a private path, a prompt, or an execution request.

## Exact bindings

The tracked canonical fixture is
`Builder/pilots/ifem-source-alignment/ifem-coarse-local-calibration-plan.v1.json`.

| Input | Bound identity |
| --- | --- |
| Source-lock receipt | `74eca6689fe69dcbf2f34ea524a99cacc2054c0a39cfecfb11887c29e13cf239` |
| Reference-manifest candidate | `4a5d859d77b606d6e485d98bd3e4afc41f6c566c6fb09f5e3dc2b2a539f18398` |
| Source revision | `a4ab841c4e5ec726e9b7742c9dcb352cb9645736` |
| Notebook index canonical SHA-256 | `3a0d39527481170a647cc8dc23917577e156f9ac42cb126f73759d784f8b03a7` |
| Notebook index rendered SHA-256 | `afc4ae97a9d5ac79a044195712e2a0591d93132d233bb1f6e2f8abb745dd7204` |
| Pending local-use request SHA-256 | `7fc6988f39d8b3233c2c836788f73b40ba82a839a79460aad7178d9d31356f33` |
| Discovery manifest SHA-256 | `40073963427d6c8917145619c6d1b75cd085b1c3b817d2650edd2305b3b0e70b` |
| Plan content SHA-256 | `17072812c03c38463aec3c3569cae15b046dfeb482577ba1f2185cc74df6fe1f` |

The plan binds opening notebook cells 0 through 3 by stable span ID, locked notebook-file
digest, cell-source digest, source-file index, cell index, cell type, and character count. It
deliberately omits the notebook path and all cell bodies.

## Authority boundary

The following values are schema invariants:

- `source_text_present=false`
- `model_input_present=false`
- `executable=false`
- `synthetic_self_calibration_reused=false`
- blockers are exactly `rights_decision_missing` and
  `local_model_processing_not_authorized`
- every rights, processing, execution, semantic-review, statement-contract, freeze,
  Prover-handoff, kernel-verification, promotion, and release authority flag is `false`
- Builder freeze and Prover handoff are `forbidden`

Calling the typed plan's execution assertion, freeze method, or handoff method always raises
`IFEMCoarseLocalCalibrationPlanError`. The plan cannot be adapted into a Builder-to-Prover
bridge.

## Replay and failure behavior

`build_current_ifem_coarse_local_calibration_plan` performs these read-only checks:

1. Read the fixed local source-lock and persisted notebook index as confined regular files.
2. Require the exact current byte digests and strict canonical JSON for the typed index.
3. Revalidate the existing digest-only notebook index as its strict typed contract and require
   its source-lock binding to match. The plan builder does not reopen notebook bodies.
4. Rebuild the pending `IFEMLocalUseRequestV1` from the tracked discovery manifest and require
   exact replay.
5. Resolve exactly the four pinned opening-cell identities and render a canonical plan with no
   payload-bearing fields.
6. Re-read the lock and index and reject if either changed during the operation.

Any missing input, digest drift, non-canonical JSON, duplicate key, non-unique cell selection,
source-lock binding mismatch, request drift, or forbidden rendered field rejects the plan. No
partial plan is emitted.

## Minimal CLI

The CLI has three positional actions and no path, provider, endpoint, output, or execution
options:

```text
uv run --frozen python scripts/ifem_coarse_local_calibration_plan.py materialize
uv run --frozen python scripts/ifem_coarse_local_calibration_plan.py render
uv run --frozen python scripts/ifem_coarse_local_calibration_plan.py verify
```

`materialize` performs write-once creation at the fixed tracked path: identical bytes are
idempotent and different existing bytes reject. `render` writes the canonical public plan to
standard output after live replay. `verify` loads the fixed tracked fixture, replays the same
local inputs, and emits the plan only when they are equal. Every action fails closed when the
fixed local cache is unavailable or inconsistent.

## What would change the decision

A future operator rights decision may authorize a separate local-model processing protocol.
That decision must create a new authority-bearing artifact and new tests; it cannot mutate or
reinterpret this plan. Even after rights approval, semantic review, Builder freeze, Prover
handoff, kernel verification, and promotion remain separate gates.
