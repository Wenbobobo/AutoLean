# iFEM atomic source-span protocol v1

Status: M4.8 protocol mechanics only. No real iFEM text was atomized and no source-backed model
execution was authorized.

## Decision

The first atomic-span protocol is deliberately split from the real iFEM source route. The existing
M4.7 coarse plan identifies four opening Markdown cells, but those cells are containers rather than
mathematical claims. The M4.8 local-use artifact is now a non-authoritative candidate: it binds the
current plan, request, text-free source record, and an `unknown` rights claim, while every processing
and workflow authority remains false.

Consequently this revision validates atomic-span mechanics only on project-owned synthetic Unicode
text. It has no function that accepts the real notebook projection or the local-use candidate as
permission. A future source-backed successor requires a separately versioned, trusted rights
attestation and cannot reinterpret the candidate in place.

## Byte contract

Offsets are half-open UTF-8 byte intervals `[start_byte, end_byte)` over the exact logical cell
source. They are not Python character offsets and are not offsets into raw `.ipynb` JSON. The
reconciler performs no Unicode normalization, whitespace trimming, boundary expansion, merging, or
fuzzy alignment.

Each private observation binds:

- byte start and end;
- SHA-256 of the exact selected bytes;
- one span class;
- atomic, mixed, or uncertain status; and
- an explicit proof-entanglement flag.

Continuation-byte boundaries, empty or out-of-range spans, digest mismatch, overlap, mixed content,
proof entanglement, uncertainty, and unsupported classes all produce a typed Builder-local
abstention. They never become Prover `GapReportV1` values.

## Dual atomizer rule

Slots A and B receive the same immutable input binding and declare distinct method and failure-domain
labels. The labels are not proof of real independence, so `independence_verified` is always false in
V1. Precomputed outputs must already use canonical order; the protocol does not sort or normalize
them after the fact.

Success requires exact tuple equality across every observation field. Any difference in count,
order, byte boundary, digest, class, atomicity, or proof flag produces `abstain`. A successful private
locator is still only `machine_located_pending_semantic_review`. Its stable identity derives from
the parent cell identity, fixed locator method, and byte offsets, not the machine-assigned class.

## Private persistence and public projection

The private sidecar contains the two complete outputs, accepted locators or one typed gap, a private
32-byte nonce, and all-negative authority. It contains no source text; the exact text remains a
separate private input. The store requires an absolute `.private.json` path outside every Git
checkout, rejects link/junction/reparse ancestry, installs bytes write-once, synchronizes where the
platform supports it, and reads the canonical bytes back before returning a non-serializable,
process-local marker. The marker is a cooperative API-ordering guard, not an unforgeable capability
or persistence attestation; projection therefore revalidates the repository-external path and its
directory identity.

Only an API-returned marker can create the public projection in ordinary use. The public artifact
discloses:

- a domain-separated, nonce-hardened commitment;
- private byte size;
- coarse success/abstention state; and
- accepted/gap counts.

It does not disclose the nonce, fixture or parent identity, offsets, span digests, atomizer outputs,
source text, or private path. The public commitment is deliberately not the private file SHA-256 or
a private CAS locator. It is also not authenticated. Because the repository cannot independently
attest either in-process persistence provenance or nonce generation,
`private_persistence_provenance_verified`, `nonce_provenance_verified`, and
`commitment_non_enumerability_verified` remain false.

## Authority boundary

All rights, source-backed execution, model execution, semantic review, statement-contract, graph,
freeze, Prover handoff, kernel, promotion, and release authority fields are false. Calling execution,
freeze, or handoff methods raises. The protocol imports no provider, network client, Prover runtime,
`StatementContractV1`, `GapReportV1`, real iFEM projection, or local-use resolution type.

This milestone therefore proves only:

1. strict UTF-8 byte-range handling;
2. deterministic exact-consensus and abstention behavior;
3. private write-once/recovery order; and
4. coarse public redaction and commitment mechanics.

It does not prove atomizer quality, role independence, mathematical fidelity, source rights,
textbook calibration, a frozen statement, or any Lean result.

## Next gate

`AUTH-RIGHTS-01` must close through a new trusted rights-attestation successor before real iFEM text
can enter a local atomizer. That successor may authorize only local source processing; model-work
admission, semantic review, freeze, and Prover handoff remain later independent gates.
