# Builder Reference Cache

## Decision

Reference books and notes are local, content-addressed inputs. Large source files never enter Git.
The tracked manifest is the only acquisition allowlist and records source, rights, artifact type,
derivation, retrieval time, byte count, media type, and digests.

The command-line entry point defaults to the current, explicitly bound revision:

- `Builder/references/manifest.v2.json`;
- `.cache/references/`; and
- manifest SHA-256
  `b947a08ef2455beb77d9481c4cbddc481ec6590f03746fd22affb03dd8b06f91`.

It accepts no manifest path, cache path, receipt path, or URL argument. The only revision selector
is the fixed `--manifest-version v1|v2` allowlist, each with its own bound digest. A new revision
therefore requires an intentional code change to both the allowlist and the bound digest.

Implementation:

- [`reference_cache.py`](../Builder/src/autolean_builder/reference_cache.py)
- [`manifest.v2.json`](../Builder/references/manifest.v2.json), with the historical
  [`manifest.v1.json`](../Builder/references/manifest.v1.json) retained byte-for-byte
- [`scripts/reference_cache.py`](../scripts/reference_cache.py)

## Commands

```text
uv run python scripts/reference_cache.py list
uv run python scripts/reference_cache.py operator-fetch REFERENCE_ID
uv run python scripts/reference_cache.py verify REFERENCE_ID
uv run python scripts/reference_cache.py verify-all
uv run python scripts/reference_cache.py verify-all --manifest-version v1
```

`operator-fetch` is deliberately named and manifest-marked as an operator-only acquisition
operation. Builder agents use `verify` or `verify-all`; they do not acquire source material.
`--refresh` is valid only with `operator-fetch`, `operator-import-local`, or `derive-pdf-text`.

## Manifest revisions

`manifest.v1.json` is historical provenance: it retains the original Open Logic derived-text
record produced by `pypdf 6.10.0` (625,143 bytes, SHA-256
`285655b3e8937e37215bb51b69eff6eb10cd9a5d64c54d8f1f4ddfb5175fc584`). It remains loadable and
verifiable through `--manifest-version v1`, but the current environment deliberately refuses to
re-derive it under a different extractor version.

`manifest.v2.json` contains every v1 entry plus a distinct derived-text record for the same locked
Open Logic PDF using `pypdf 6.14.2`: 437 pages, 622,790 UTF-8 bytes, SHA-256
`6184495568a4487848e747f25385cb4081be1cd87f77488c9de0046d600cfa6d`. The extraction method and
page-boundary serialization remain unchanged; the tool version is part of provenance, so the
changed bytes require a new record rather than a rewrite of v1.

After the locked parent PDF has been placed in the local cache through the operator import path,
the current derivation and a local candidate fingerprint are available as:

```text
uv run python scripts/reference_cache.py derive-pdf-text openlogic-sets-logic-computation-2026-07-12-text-pypdf-6.14.2
uv run python scripts/reference_cache.py fingerprint-pdf-text --input OPERATOR_LOCAL_PDF
```

The manifest digest is deliberately manifest-wide, not an entry digest. Consequently, verifying an
unchanged entry under v2 emits the v2 digest, while a historical contract or pilot that bound v1
must retain and verify its v1 receipt. Cache bytes are content-addressed and can be shared; receipt
or contract provenance cannot be silently upgraded. `fingerprint-pdf-text` is therefore restricted
to the current extractor-bound revision, while `v1` remains available for artifact verification.

Receipts are emitted to standard output and are not written by this script. They contain no host
path or source text. The `network_used` value comes from the actual acquisition observation; it is
not inferred from a prior file-existence check. Offline verification always reports `false`.

## Artifact types

The manifest distinguishes:

- `source_document`: the official parent PDF;
- `derived_text`: a UTF-8 text artifact with typed extraction provenance, exact parent reference
  ID and SHA-256, producer, method, disclosed tool metadata, and provenance URL.

The current repository text bitstream names its producer and method. `tool_name` and
`tool_version` are explicitly `null` because the repository does not disclose them; AutoLean does
not invent extraction metadata.

### Markdown byte-identity overlay

`repository_text_extraction` has two deliberately distinct cases. Historical repository-provided
PDF companion text remains an `operator_only` fetched artifact: its bytes need not match the PDF,
and it keeps its original repository provenance. The cache does not reinterpret it as a local
extraction.

The iFEM Markdown overlay is narrower. It accepts only a `text/markdown` `.md` source document
and creates a `text/plain` `.txt` object with the fixed
`utf8-markdown-byte-identity-v1` method. The parent and child must both be `local_only`, have
identical SHA-256 and byte count, keep `human_declared` parent-location authority, and declare no
tool name or version. Its child is `local_derivation_only`, has no download URL, and is rejected if
any Markdown parsing, normalization, conversion, size change, hash change, or egress widening is
claimed.

The local iFEM adapter is intentionally separate from the source-lock acquisition route:

```text
uv run --frozen python scripts/ifem_repository_text.py materialize
uv run --frozen python scripts/ifem_repository_text.py verify
```

It replays the canonical source-lock receipt and its fixed `intro.md` parent, writes a local
two-entry overlay manifest and receipt once below the ignored reference cache, and installs the
distinct `.txt` content-addressed object only after both byte identities verify. Standard output
contains hashes and negative authority flags, never source text, source paths, or cache paths.
This local alias neither approves model execution nor creates a statement contract, freeze, or
Prover handoff.

A derived text artifact must retain the parent source record, rights metadata, attribution, access
policy, and an egress policy no broader than its parent. A parent digest mismatch rejects the
entire manifest.

## Cache safety

Acquisition uses HTTPS and an exact redirect allowlist. Manifest URLs reject credentials, query
strings, fragments, explicit ports, local hostnames, legacy numeric shorthand or octal/hex host
forms, and literal loopback, private, link-local, reserved, multicast, or unspecified addresses.
This literal-address check is not DNS pinning or a DNS-rebinding defense. Acquisition therefore
remains an explicit operator operation; agent workers stay offline, and any future networked
acquisition service must validate every resolved A/AAAA address and redirect at its connection
boundary.

The cache is lexically confined beneath the repository root. The cache root, intermediate
directories, per-reference child directory, target, and temporary artifact reject symbolic links,
junctions, and other reparse points. Acquisition uses a unique temporary file, flushes and
`fsync`s it, verifies size and SHA-256, then installs the content-addressed target with a
no-clobber same-volume hard link. A target that appears concurrently is accepted only when its
regular-file type, size, and SHA-256 exactly match the manifest; different bytes are a conflict,
including under `--refresh`, and are never overwritten. Acquisition cleans failed temporaries and
serializes same-process work for one content-addressed target.

These checks materially reduce path substitution risk. They do not replace an OS sandbox or prove
cross-process exclusion against a hostile local administrator.

## Verified local reference

On 2026-07-23 the following official University College Cork artifacts were cached:

| Reference | Bytes | SHA-256 |
| --- | ---: | --- |
| McKay, *Lectures on Differential Geometry*, published parent PDF | 94,902,360 | `1cd1660be5e63bf2d5198e7a7f7e912d3179c9cf3b5f2d972db6283e0b483ea4` |
| Repository-provided derived text bitstream | 1,194,775 | `3fdfa27690ce473d8b84c322dbd12779ce5ba76aa12ef8d07608db768894bd25` |

The PDF also matched the repository-published MD5
`bc1e9988d0b47bab4ec336c3b4fb639a`. The repository describes the 643-page,
peer-reviewed published book as CC BY-SA 4.0:

- <https://cora.ucc.ie/items/274ec834-ca2e-4885-922f-e353d539ef18/full>

## Exact statement span

`SourceToStatementHarness.prepare_draft` accepts only a verified `text/plain` `derived_text`
artifact whose parent PDF is also cached and verified. Repository-provided text keeps a
`human_declared` parent-locator policy. Deterministic local PDF extraction instead keeps its
parent identity `manifest_bound`; the human chapter and page declarations remain separate on
every statement span. Every `ChapterSourceSpan` must provide:

- nonempty `start_offset` and `end_offset` byte offsets;
- `permitted_excerpt`;
- the derived artifact SHA-256;
- source analyst identity; and
- a human-declared chapter and parent-PDF page locator.

The Harness hashes the complete derived artifact, reads the declared byte range, and requires:

```text
cached_bytes[start_offset:end_offset] == permitted_excerpt.encode("utf-8")
```

No Unicode normalization, whitespace normalization, OCR repair, or substring search occurs.
Offsets that exceed the artifact and excerpts that differ by one byte are rejected. The public
contract span stores the derived-text byte range and excerpt hash, never the verbatim excerpt.
The private preparation packet and fidelity artifact retain the exact excerpt under the rights
policy. The PDF page locator is separately labeled
`human_declared`; it is review evidence, not a machine-verified PDF-to-text alignment.

The cache proves artifact and byte-span identity. It does not prove that the page declaration is
correct or that the normalized and Lean statements preserve the mathematics.

## Rights and freeze boundary

An open license does not make the manifest a legal reviewer. `RightsReview` is an explicit
operator decision and may only narrow the manifest egress ceiling. The McKay artifacts remain
`local_only`; external model access is blocked pending a new manifest revision and endpoint
review.

`SourceToStatementHarness.run_fidelity` delegates to `StatementFidelityHarness`.
Preparation writes one canonical record per `(contract_id, revision)` into
`SourcePreparationLedger`. The record commits the complete draft contract, rights, spans,
manifest, parent, and derived artifact. Replays must be byte-identical; a conflicting preparation
fails closed. Every fidelity, freeze, or signed bridge call reloads the record, then independently
rechecks source identity, license, attribution, endpoint classes, parent and derived bytes, and
every private excerpt. Coordinated changes to both a contract and its packet fields therefore
fail against the append-only record. The frozen contract stores the record's
`source_preparation_id` and typed `source_preparation_hash`; because the Builder handoff
attestation covers the frozen contract, the signed bundle also commits this exact preparation.

Raw freeze and bridge primitives are private implementation details rather than package exports.
The supported source-backed signed handoff is
`SourceToStatementHarness.revalidate_freeze_and_bridge`. This closes an accidental public bypass
and survives process restart, but it is still local structural evidence. The SQLite file must be
owned by a protected Builder service, `frozen_by` and reviewer strings are not authenticated, and
a caller holding the attestation key remains the ultimate authority. Production promotion is
blocked until a separate Builder signing gateway reopens the protected ledger, authenticates
human identities, and keeps its key in KMS/HSM custody.

The two source-preparation fields are additive for V1 parsing, but mandatory at the supported
bridge and control-plane admission gates. A legacy freeze without them is readable only for
audit/replay and cannot become a new Prover task.
