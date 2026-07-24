# Mathlib Downstream Workspace

## Decision

`Library/` is AutoLean's independent downstream Lake project and the main
formal-work record for mathematical assets. It consumes a pinned public mathlib
release; it is not a fork of mathlib, a place to edit `.lake/packages/mathlib`,
or an alternate verification environment for the existing pure-Lean OCI worker.

This keeps AutoLean-specific theorem curation reviewable without repeated
upstream pull requests. `Library/Staging/` is also the sole staging surface for
a later upstream proposal: it carries only reviewed, public-API-bound candidate
formal assets and their safe provenance links. A downstream result can evolve
through AutoLean's Builder--Prover protocol while its mathlib dependency remains
stable. A generic, well-scoped improvement may later be proposed upstream, but
that is a separate decision and must not block the local asset's provenance or
verification gates.

## Frozen environment

The initial baseline is deliberately aligned with the repository's audited FATE
compatibility baseline for interoperability. FATE is not the priority-setting
source for Library work or research direction:

| Input | Pinned value | Authority |
| --- | --- | --- |
| Lean toolchain | `leanprover/lean4:v4.28.0` | `Library/lean-toolchain` |
| mathlib requested release | `v4.28.0` | `Library/lakefile.lean` |
| mathlib resolved revision | `8f9d9cff6bd728b17a24e163c9402775d9e6a365` | `Library/lake-manifest.json` |
| transitive Lake packages | Full SHA-1 closure | `Library/lake-manifest.json` |

The lock is a dependency source identity, not byte evidence or an environment
attestation. The local build additionally records and rehashes a canonical
manifest of the complete linked package tree, including cached `.olean` and
other `.lake/build` outputs. That manifest detects drift relative to a tracked
receipt, but it does not prove the first observed bytes came from a trusted
clean build. A promoted
AutoLean contract must still bind its own `LeanEnvironmentV1` fields: exact Lean
version, mathlib revision, Lake-manifest hash, environment hash, axiom profile,
and verifier execution policy. The pure-Lean worker currently records no
mathlib; it cannot certify a mathlib-dependent result until a separately pinned
mathlib-capable verifier environment has been introduced and independently
attested.

## Ownership and flow

```text
rights-scoped source
  -> source-preparation record and source span
  -> Builder draft contract
  -> semantic review and frozen StatementContractV1
  -> registered task bundle and isolated proof attempt
  -> independent kernel/environment verification
  -> Library/AutoLeanLibrary/Promoted/ import and promoted record
```

The source, formal, and execution graphs remain different artifacts. A Lean
import says only that one formal declaration depends on another. It does not
establish that the source passage supports the theorem, that a task is approved,
or that a verifier ran in a clean environment.

### Staging, review, and promotion

| State | Writable by | Permitted content | Exit condition |
| --- | --- | --- | --- |
| `Library/Staging/` | Builder and assigned Prover | Draft references and candidate work linked to one contract revision | Freeze record and semantic-review decision |
| `Library/Review/` and `Library/records/reviewed/` | Reviewer process | Immutable public-safe review packet and artifact references | Contract, source, and proof boundary agree |
| `Library/AutoLeanLibrary/Promoted/` and `Library/records/promoted/` | Promotion change owner | Public Lean module plus immutable promoted record | Independent verification report, evidence artifact, and verifier attestation bind the frozen revision |

No promoted Lean module may import `Staging/` or a fixture. `sorry`, `admit`,
and local axioms are prohibited in a promoted module. A proof failure produces a
gap report or a contract-change request; it never changes a frozen declaration
or enters the public root as a placeholder.

## Provenance convention

`Library/records/` is an index over the existing versioned AutoLean contracts
and artifacts. It must not invent a parallel schema or copy restricted content.
Use the stable asset ID and contract revision in the record path, for example:

```text
Library/records/reviewed/<asset-id>/r0003/
Library/records/promoted/<asset-id>/r0003/<proof-source-hash>/
```

Every record contains only safe identifiers, revisions, SHA-256 digests, and
review decisions. The required chain is:

1. Source provenance: `source_preparation_id`, `source_preparation_hash`,
   source-span ID, source hash, rights decision, and the candidate contract ID.
   The source text and local cache location remain outside the record.
2. Contract provenance: `StatementContractV1` ID, revision, semantic hash,
   formal environment hash, freeze-evidence hash, and semantic-review decision.
   A changed statement starts a new contract revision.
3. Proof provenance: proof-source hash, proof-boundary hash, dependency-manifest
   hash, and the exact frozen environment hash. A candidate proof never changes
   the Builder-owned statement bytes.
4. Verification provenance: `VerificationReportV1` hash, verification-evidence
   artifact hash, verifier ID, and verifier-attestation identity. Only this
   final link may authorize a promotion.

Do not place prompts, credentials, raw source passages, source-cache paths,
mutable workspaces, raw Lean stdout/stderr, or model output in a record. When a
new proof targets the same frozen statement, add a new proof/verification record
under the existing revision. When the theorem semantics change, create a new
Builder contract revision and repeat review.

## Fixture boundary

`AutoLeanLibrary/Fixtures/Dag/` contains a three-module compile fixture:

```text
Foundation.lean -> Bridge.lean -> Certificate.lean
```

It verifies a multi-file Lake import path and proof dependency. It contains only
elementary natural-number normalization, has no source contract or promotion
record, and is never exported by `AutoLeanLibrary.lean`. Its successful build is
not a theorem acceptance, benchmark result, or OCI verification report.

## Review checklist

For a normal downstream asset change:

1. Verify the record points to a frozen contract and source-preparation pair;
   reject partial pairs, source-text copies, or a contract hash mismatch.
2. Check the Lean import graph: only mathlib public modules and promoted
   AutoLean modules may be dependencies. No `.lake` source patch, staging,
   fixture, or implementation-private mathlib import may cross the boundary.
3. Check the exact Lean toolchain, resolved mathlib commit, Lake-manifest hash,
   and environment hash against the task bundle. A local build with a different
   lock is diagnostic only.
4. Confirm that proof source fills the frozen proof boundary and that the
   independent verifier evidence records clean environment, build, dependency,
   kernel, and axiom observations. Local compilation cannot replace the
   verifier-attestation gate.
5. Confirm the reviewer has not accepted a weaker restatement. A failure must
   remain a gap or a request for a new Builder-owned revision.

The focused local checks are intentionally short:

```text
uv run python Library/scripts/verify.py check
uv run python Library/scripts/verify.py build
```

`check` is offline structural validation. `verify-receipt` requires the current
ext4 WSL dependency cache and rehashes its manifest-bound source/config/build
bytes. `build` uses the local pinned Lean environment and may hydrate the exact
lock if the Lake cache is empty. Record the host/WSL context and actual command
result in the review packet; neither a live cache match nor local compilation is
authoritative evidence without the required verifier artifact and signature. A
promotion requires a separately attested, digest-pinned mathlib-capable OCI
environment; the current local receipt cannot substitute for it.

## Upstream and lock synchronization

Most AutoLean assets should remain downstream. Consider upstream only when the
statement and API are broadly reusable, independent of AutoLean provenance, and
can satisfy mathlib's contribution and style expectations without carrying
AutoLean policy or research-specific metadata. Upstream acceptance does not
promote an AutoLean task; AutoLean still requires its own frozen contract and
verification evidence.

Treat lock movement as a dedicated, reviewable change rather than incidental
maintenance:

1. State why the toolchain or mathlib baseline must move and which frozen
   contracts can remain replayable versus require a new environment revision.
2. In a dedicated sync change, use the explicit wrapper command
   `uv run python Library/scripts/verify.py update-lock --allow-lock-update`.
   Do not edit generated package directories or hand-select a transitive commit.
3. Review the complete `lake-manifest.json` diff, toolchain diff, public import
   compatibility, and any changed proof/elaborated-type behavior. Recompute the
   Lake-manifest hash used by any new task bundle.
4. Build the fixture and affected promoted assets in the candidate environment,
   then obtain fresh independent verification evidence before promoting results
   under that environment. Old evidence remains bound to the old environment.
5. Keep the old lock available through Git history and immutable task artifacts.
   Never rewrite old contracts or reports to make them appear compatible with a
   new mathlib revision.

There is no requirement to open a mathlib pull request for a downstream asset,
and no permission to patch `Mathlib` locally. A temporary upstream workaround
belongs in an explicitly reviewed AutoLean namespace with a removal/upgrade
plan; it must still use public mathlib APIs and remain independent from
`.lake/packages` internals.
