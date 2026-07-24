# AutoLean Library

`Library/` is a small, independent Lake project for AutoLean-owned formal
mathematical assets. It consumes the released mathlib API through a committed
Lake lock; it is not a fork, mirror, or patch queue for mathlib internals.

## Locked environment

- Lean toolchain: `leanprover/lean4:v4.28.0` in `lean-toolchain`.
- Direct mathlib input: `v4.28.0` in `lakefile.lean`.
- Resolved mathlib commit: `8f9d9cff6bd728b17a24e163c9402775d9e6a365` in
  `lake-manifest.json`.
- The manifest also fixes every transitive Lake package revision. Do not edit
  generated `.lake/` state or a package below it.

The baseline matches the pinned FATE/mathlib compatibility baseline already
audited in this repository. That compatibility fact is not proof that this
downstream project has built on a particular machine or in the authoritative
OCI verifier.

## Directory boundary

| Path | Owner and meaning | Import rule |
| --- | --- | --- |
| `AutoLeanLibrary/Promoted/` | Reviewed, kernel-checked assets that have passed promotion. | May import mathlib and other promoted assets. |
| `Staging/` | Builder-owned drafts and candidate proof work. | Never imported by `Promoted/` or the public root. |
| `Review/` | Immutable review packets and reviewer decisions. | Not a Lean import surface. |
| `records/` | References to source, contract, proof, and verification artifacts. | Not a Lean import surface. |
| `AutoLeanLibrary/Fixtures/` | Compile fixtures for project wiring only. | Never imported by `Promoted/` or the public root. |

The public root `AutoLeanLibrary.lean` stays intentionally empty until the
first promotion. A staged source can compile locally, but it is not an
AutoLean mathematical result, public API, or release artifact.

## Local commands

Use the small wrapper rather than copying platform-specific Lake commands into
reviews:

```text
uv run python Library/scripts/verify.py check
uv run python Library/scripts/verify.py build
```

`check` validates the committed lock structure and recomputes the tracked
model-theory compile receipt without fetching dependencies. `verify-receipt`
also dispatches to WSL and rehashes the exact current ext4 dependency cache. It
fails closed when that cache is absent or any recorded cache byte, path, link,
manifest, or identity differs.
`build` first validates that lock, then on Windows dispatches to WSL and copies
only the explicit authoritative build-input allowlist into a fresh ext4
worktree: the toolchain, Lake files, public root, and `AutoLeanLibrary/**/*.lean`.
Docs, records, receipts, and local evidence cannot affect the build-input hash.
Lake never builds this project on the NTFS checkout. The first build initializes
an ext4 dependency cache from the committed closure and obtains the matching
mathlib olean cache. It then records a canonical, UTF-8-byte-sorted manifest of
the complete linked package tree outside that tree. The manifest binds source
and generated `.lake/config` and `.lake/build` bytes, including every cached
olean, while excluding Git metadata. Cache reuse rehashes the tree before the
build and again after it. Subsequent builds reuse that byte-bound dependency
seed but always use a fresh Library worktree and local build directory. It
builds the public root, the three-node fixture DAG, and the non-promotable
model-theory semantic-boundary packet.

This detects cache pollution relative to the tracked receipt; it does not prove
that the first observed bytes came from a trusted clean build. The receipt is
local diagnostic evidence. Promotion still requires a separately attested,
digest-pinned mathlib-capable OCI verifier.

To record a replayable, public-safe result, request a new evidence filename:

```text
uv run python Library/scripts/verify.py build --evidence-out Library/evidence/<run-id>.json
```

The result records pins, input hashes, tool versions, targets, duration, and no
absolute paths or raw build output. It is local diagnostic evidence only;
promotion additionally needs the frozen AutoLean contract and the independent
verifier evidence described in `docs/mathlib-downstream.md`.

Lock movement is intentionally explicit:

```text
uv run python Library/scripts/verify.py update-lock --allow-lock-update
```

Run that only from an ext4 WSL checkout in a dedicated upstream-sync change
after its review plan exists. It rewrites `lake-manifest.json`; inspect every
resolved-revision change before accepting it. The wrapper intentionally refuses
to rewrite a Windows worktree.
