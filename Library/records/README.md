# Asset Records

Records are a path-based index of immutable AutoLean artifacts, not a second
contract schema. Keep records under one of `staging/`, `reviewed/`, or
`promoted/`, with one directory per stable asset or preselection packet ID.

Every record must be public-safe. A mathematical-asset record contains
references and SHA-256 digests only. A `preselection_compile_spike` may also
contain concise candidate-boundary, gap, and non-claim summaries needed to
explain what was tested. No record may contain raw source text, source-cache
paths, prompts, credentials, raw Lean stdout/stderr, or a mutable workspace
path.

Required references for mathematical assets by state:

| State | Required references |
| --- | --- |
| `staging` | source-preparation ID/hash, source-span ID, candidate contract ID/revision, environment hash |
| `reviewed` | frozen `StatementContractV1` ID/revision/hash, freeze-evidence hash, semantic-review decision, proof-boundary hash |
| `promoted` | reviewed references plus proof-source hash, dependency-manifest hash, `VerificationReportV1` hash, verification-evidence artifact hash, and verifier attestation identity |

## Preselection compile spikes

A preselection spike is not a candidate mathematical asset. It lives under
`records/staging/<packet-id>/` and uses
`record_kind: preselection_compile_spike`. Its packet must contain:

- a stable packet ID, packet schema, `partial_passed_with_gap` state, and an
  explicit `not_selected` candidate-selection state;
- source-reference and source-artifact digests, source anchor IDs, model-egress
  policy, and pinned Lake/toolchain/mathlib environment;
- every tested candidate/module boundary, at least one still-open semantic
  gap, and explicit non-claims;
- a backlink to a tracked immutable compile receipt by repository-relative
  path and SHA-256 digest.

The matching receipt uses the same `record_kind` and binds the authoritative
build-input schema/hash, packet content hash, verifier-script hash, environment
pins, exact build targets, build exit state, and canonical public-safe build
report schema/digest. The packet content digest excludes only its receipt
backlink; this makes the receipt-to-packet binding one-way and avoids a hash
cycle.

A preselection spike must not invent or cite a candidate
`StatementContractV1`, freeze decision, proof acceptance, semantic-review
approval, or promotion evidence. If later review admits a candidate, create a
separate mathematical-asset staging record; do not reinterpret the spike as
that record.

Records never change in place after review. A new theorem statement creates a
new contract revision; a new proof for the same frozen statement creates a new
proof/verification record linked to that same contract revision.
