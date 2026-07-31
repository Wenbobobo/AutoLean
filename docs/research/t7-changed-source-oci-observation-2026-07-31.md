# T7 changed-source OCI observation

Date: 2026-07-31

Status: operator-local real OCI/Lean observation; non-promotable

## Environment

- WSL distribution: `Ubuntu-24.04`
- Docker server: 29.1.3
- Lean: 4.28.0, commit `7e01a1bf5c70fc6167d49c345d3bf80596e9a79b`
- Worker image:
  `autolean/mathlib-worker@sha256:3237192cf627a05367c75d46e61ec9034fefe43a4fd0c06139e38c80358648d6`
- Network access by the container: false

The committed case was first validated with:

```text
uv run --frozen python -m scripts.real_lean_changed_source_preflight validate --json
```

The real OCI run used:

```text
uv run --frozen python -m scripts.real_lean_changed_source_preflight run --distribution Ubuntu-24.04 --timeout-seconds 300
```

Both commands returned success on 2026-07-31.

## Observation

- Change-case manifest SHA-256:
  `8e460eb423e48280ce2243e1a17342c2274b6e9230614f5ccfe7430cbfd6bfb8`
- Baseline fixture manifest SHA-256:
  `45dc2fe5dbff4fbc122c21aff1b653ccb941c08e1abc3d66843b0478b873cdf0`
- Changed declaration: `AutoLean.ProjectDagPreflight.Arithmetic.score`
- Baseline canonical type: `Nat`
- Baseline type SHA-256:
  `3d1917aa425fd7059394e1413a9cf36a1304374e10ea4b88200fd2d34ce749d4`
- Successor canonical type: `(bonus : Nat) -> Nat`
- Successor type SHA-256:
  `8cdc3fc38998265195d830dd7e0978f73e57d2b441a478bc377a2e80940f3e30`
- Type-query SHA-256:
  `400e5e228a16c231e1376ad29906d201384a493c40e7520e6a170feeb2db0311`

The unchanged old Relations source failed against the changed Arithmetic API with the expected
failure class `old_downstream_source_incompatible_with_new_upstream_api`. The successor run then
freshly recompiled Arithmetic, Relations, and Capstone. Foundations was not recompiled; its
baseline and reused OLean SHA-256 remained
`621082968bae7d36f8f5d230710bcd8d8dd1d0d759b25874ea3d7a4fcb826c95`.

This establishes the fixed fixture's real Lean type-change observation, expected downstream
breakage, reverse-import rebuild, and unchanged-module reuse on the pinned image. It is stronger
than the injected-runner tests but narrower than T7 acceptance.

## Separate refreshed substrate checks

The existing Library substrate image
`autolean/library-substrate@sha256:c28d05d12f8e5cbfba240a35987b33e1564c7cda72a2529ccf6255c28e5bf2a8`
also passed its image receipt verification, independent canary, V2 facade canary, and Builder-only
query canary in the same WSL/Docker environment. The Builder query remained
`proof_eligible=false`, and all declared negative cases were rejected.

## Authority boundary

The changed-source command explicitly reports `acceptance_result=false`. It created no frozen
contract evidence, control-plane lease, fencing history, trusted gateway attestation, independent
OCI verifier receipt, semantic review, or provider evidence. It therefore does not close
`AUTH-T7-01`, cannot support kernel acceptance, and cannot promote any Builder or Prover artifact.
