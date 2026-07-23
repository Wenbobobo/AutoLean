# Builder--Prover Protocol V1

## Purpose

This protocol prevents the two engines from acquiring each other's authority. Builder may create
or supersede a statement contract; Prover may search for a proof of a frozen contract and report
evidence. Neither component reads the other's private mutable state as a protocol.

The current command implementation is
[ControlPlane](../packages/control_plane/src/autolean_control_plane/service.py#L87). This
document is normative for Phase 1; an implementation that needs a new semantic action must add a
versioned command and its tests rather than overload an existing payload.

## Preconditions for every Prover task

Before a worker can claim work, Builder must have created a
[FormalizationTaskBundleV1](../packages/contracts/src/autolean_contracts/models.py#L745) whose
contract is frozen and whose graph snapshot hash matches its three graphs. The control plane
records the bundle as a content-addressed artifact and binds its stable contract ID, revision,
contract hash, environment hash, axiom profile, allowlist, and graph-node projection.
For a production registration, the bundle also carries a typed
`FidelityEvidenceArtifactRefV1`. The control plane rehashes those canonical bytes, checks their
contract/revision/source/normalized-statement/Lean-statement binding, and roots the reference in
the same `task.registered` event.

It also requires an allowlisted Builder-freeze attestation over the exact bundle hash and freeze
evidence. A caller can construct a syntactically frozen contract, but cannot register it without
that authority decision. The corresponding verifier-attestation and evidence requirements are
normative in [Attestation Trust Root V1](attestation.md).

Registration atomically commits the event, attestation nonce, idempotency record, and an immutable
SQLite uniqueness projection. One `(contract_id, revision)` can bind only one bundle ID and
handoff hash. An exact delivery under a new idempotency key reuses the original registration event;
a different bundle ID or handoff hash fails closed. On an older database, initialization rebuilds
this projection from canonical registration events and refuses duplicate or conflicting history.

No command accepts a theorem name as an adequate identity. All results bind a stable ID, revision,
and contract hash; proof and verification results additionally bind the specified Lean
environment.

## Cross-Engine Public Commands

| Command | Caller | Input authority | Required checks | Allowed effect |
| --- | --- | --- | --- | --- |
| claim | Assigned worker | Registered bundle ID, worker identity, TTL, idempotency key | Bundle exists; SQLite lease claim produces a current fencing token | Records task claim; gives temporary authority to submit evidence for that bundle |
| submit_proof | Current lease holder | ProofSubmissionV1 | Current lease; stable ID/revision/contract/environment binding; no sorry, admit, or sorryAx | Stores a candidate proof artifact; it is not accepted yet |
| report_gap | Current lease holder | GapReportV1 | Current lease and frozen contract binding | Stores evidence of a missing lemma, API mismatch, ambiguity, version drift, or resource limit; never changes a theorem |
| request_contract_change | Current lease holder | ContractChangeRequestV1 | Current lease and old contract binding | Stores a request for Builder review; never applies it |
| verify_submission | Current lease holder acting through an independent verifier | VerificationReportV1 | Current lease; submitted proof exists; contract/environment/axiom-profile binding; typed verifier environment evidence; lease/fencing-bound gateway attestation; kernel/build/dependency/clean-environment/axiom gates | Emits accepted or rejected verification evidence |

The named methods are
[claim](../packages/control_plane/src/autolean_control_plane/service.py#L255),
[submit_proof](../packages/control_plane/src/autolean_control_plane/service.py#L295),
[report_gap](../packages/control_plane/src/autolean_control_plane/service.py#L356),
[request_contract_change](../packages/control_plane/src/autolean_control_plane/service.py#L410),
and [verify_submission](../packages/control_plane/src/autolean_control_plane/service.py#L467).

## Operator-Only Verifier Signing Gateway

`VerifierSigningGateway` is a separate authority seam, not a sixth Builder--Prover command.
Prover sends `VerificationSigningRequestV1`, containing only canonical digests plus the exact
lease holder, fencing token, expiry, bundle/contract/proof/environment/report/verifier context,
nonce, and idempotency key. The gateway rechecks the authoritative lease, proof event, task
binding, and content-addressed evidence artifact before signing. Request, nonce, idempotency key,
and canonical payload replays are durable across restart.

The resulting signature binds the lease as well as the verification context.
`verify_submission` independently reconstructs that payload from its current lease; an old fence
cannot be promoted under a replacement lease. Direct worker-local verifier signing is disabled by
default. The explicit `allow_test_only_direct_verifier_attestations` compatibility switch and HMAC
implementation are fixtures only.

`allow_test_only_unreviewed_bundles` similarly exists only for synthetic fixtures built before a
real Builder review. The production default rejects such a bundle even when it has a valid test
attestation.

This code defines the application boundary but does not deploy a signer service. Production still
requires authenticated mTLS/ACL ingress, non-exportable KMS/HSM sign/verify custody,
rotation/revocation, availability policy, and isolation preventing workers from reaching a raw
signing operation. V1 fixes HMAC-SHA256; an asymmetric authority requires a versioned V2 schema.

## Operator-Only Model Authorization

`ModelExecutionAuthorizationService` is an operator-controlled control-plane seam, not a
Builder--Prover public command. It issues or revokes a short-lived model capability only after a
registered bundle, approved provider snapshot, bounded budget, expiry, and idempotency key pass
its administrative checks. Builder and Prover task bundles cannot invoke it, and it must not add
an alternate semantic route around the five cross-engine commands above.

Model generation is an operator-gated side effect rather than a free-form Prover command.
`ModelExecutionAuthorizationService` signs a capability bound to the frozen bundle, provider/model
selection, approved endpoint class and credential-free configuration hash, rights egress policy,
aggregate attempt/token/micro-USD budget, current worker lease/fencing token, role-scoped
ContextPack hash, and full outbound-request hash. [ProviderRegistry](../Prover/src/autolean_prover/providers/registry.py#L68)
preflights that capability before a probe can contact an endpoint and accepts it rather than a
caller-supplied provider name. A stale worker, missing context hash, or substituted request is
rejected before endpoint I/O. It requires nonzero reported input usage to settle an authorized
call, so a missing usage field cannot silently become zero spend. Its control-plane SQLite ledger
appends reservation, settlement, abandonment, and revocation records under `BEGIN IMMEDIATE`; lost
workers therefore retain their consumed attempt slot and cannot reset a budget by restarting.
Prompts, endpoint URLs, credentials, and raw model output are absent from this capability and
ledger. V1 records provider-reported usage; a hard remote billing ceiling additionally requires an
operator-controlled egress proxy or provider-side account limit.

## Required state transitions

    Builder draft --semantic review--> frozen revision --bridge--> registered bundle
    registered bundle --claim--> leased attempt
    leased attempt --submit_proof--> candidate proof --verify_submission--> accepted | rejected
    leased attempt --report_gap--> blocked evidence
    leased attempt --request_contract_change--> Builder review queue
    Builder review --new draft revision--> repeat semantic review

There is intentionally no patch_statement, accept_model_claim, retry_with_weaker_goal, or
replace_declaration command. A proposed mathematical change must become a new Builder-owned
draft revision, preserving the old frozen revision and all evidence attached to it.

## Immutable artifacts and events

The control plane stores typed payloads in a SHA-256 content-addressed artifact store
([ArtifactStore](../packages/control_plane/src/autolean_control_plane/artifacts.py#L36)). Events
carry compact artifact references instead of raw source, prompts, proof text, or secret-bearing
configuration. The append-only event store uses SQLite WAL, per-entity compare-and-swap sequences,
idempotency records, and database triggers which reject event update or deletion
([EventStore](../packages/control_plane/src/autolean_control_plane/events.py#L69)).

Rules:

1. An artifact reference is content identity, not an authorization token.
2. JSON is an exchange encoding. The SQLite event log and artifact bytes are the local system of
   record; projections can be discarded and rebuilt.
3. Event payloads must contain only typed, JSON-safe summaries and references. Do not serialize
   source archives, model prompts, API credentials, raw logs, or unreviewed workspaces.
4. The dashboard receives a deliberately lossy projection. The current
   [DashboardProjection](../packages/control_plane/src/autolean_control_plane/projection.py#L16)
   omits artifact contents by design.
5. HMAC key bytes exist only in test fixtures. Production workers and control-plane protocol
   objects receive no signing key. Signatures, public key IDs, payload hashes, expiry, and
   evidence identity may be audited; secrets may not be serialized.

## Lease and fencing semantics

LeaseStore uses a transaction to assign a monotonically increasing fencing token. A worker may
retain a process after its TTL, but its old token cannot submit evidence once a newer lease has
been issued. Every evidence command calls the current-token check before recording its event.
An operator-issued model capability is also bound to this lease and is rechecked before a provider
probe, reservation, and settlement, so lease fencing applies to egress as well as eventual proof
submission. The implementation is in
[leases.py](../packages/control_plane/src/autolean_control_plane/leases.py#L31).

Idempotency applies to a command scope plus key and request hash. Reusing a key for different
payloads is an error; repeating the same request returns the recorded result. This prevents
network retries from manufacturing additional accepted results, subject to the chaos tests in the
acceptance plan.

## Proof and verifier boundary

The Prover is only allowed to fill a proof slot. The materializer writes a protected theorem
header and manifest, checks their hashes before and after proof work, and rejects patch paths
outside Proof.lean; see
[WorkspaceMaterializer](../Prover/src/autolean_prover/execution/workspace.py#L117).

The Lean-facing verifier compiles the candidate constructed from those protected statement bytes
and the submitted proof source. It records kernel/build/dependency/clean-environment observations
and checks sorryAx plus the selected axiom profile; see
[TrustedLeanVerifier](../Prover/src/autolean_prover/verification.py#L38). The control plane will
not accept a report whose environment, axiom profile, or contract hash differs from the frozen
bundle. It also requires verifier-owned evidence for the exact elaborated declaration type and
recomputes that type's digest against the frozen proof boundary; see the
[elaborated-type comparator contract](elaborated-type-comparator.md). This is a fail-closed
Python protocol gate, not evidence that the required pinned OCI Lean helper has already run; no
host or fixture result may be promoted as an authoritative elaborated-type check.

### Deliberate V1 limitation

The V1 bundle carries a versioned proof boundary, trusted statement bytes, solver manifest hash,
and elaborated-type comparator target. It is **not** equivalent to the full external
[lean-eval comparator](https://github.com/leanprover/lean-eval) boundary: production promotion
still requires a pinned OCI helper, clean-environment canaries, and any required external
environment/dependency comparison. The materializer's local manifest and pure-Python tests alone
are not a remote-worker or external-evaluation attestation.

## Compatibility rules

- A V1 reader must reject unknown fields in a contract model and reject mismatched schema versions.
- A breaking semantic or serialization change requires a new major contract version, a migration
  plan, fixtures, and replay tests. It must not be smuggled into a metadata map.
- An additive field is not automatically safe: it needs a default, hash/review impact analysis,
  serializer tests, and a decision about whether it belongs inside a frozen semantic hash.
- Contract revisions are data, not migrations. A new revision changes a particular theorem task;
  a schema version changes the language all tasks use.
