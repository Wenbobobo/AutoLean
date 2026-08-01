# Attestation Trust Root V1

## Scope

An immutable-looking JSON bundle is not proof that Builder performed the semantic freeze gate, and
a `VerificationReportV1` containing only `true` values is not proof that an independent verifier
ran Lean. Phase 1 therefore uses separate, versioned attestations for Builder freeze,
non-theorem model-work admission, model-execution capability issue, and independent verification.

This document describes the implemented protocol boundary. It does not claim that an OCI worker
or a public-key authority has already been deployed.

## Authority roles

| Authority | Signed payload | Control-plane effect |
| --- | --- | --- |
| Builder freeze | Bundle ID and hash, contract ID/revision/hash, proof-boundary and environment hashes, freeze-evidence hash, and typed fidelity-artifact reference | Allows `register_bundle` only after the signature and retained Builder artifact validate |
| Model-work admission | Complete immutable `ModelWorkBundleV2` public projection: fixed-namespace opaque references, domain-separated digests, permission/endpoint enums, bounded coordinates, and exact egress, context, request, role, and environment hashes | Allows `register_model_work` before any lease, capability, or provider I/O |
| Model execution | Exact bundle/contract/environment, lease, provider approval, egress policy, request, context, budget, and expiry | Allows one bounded provider capability to be consumed and settled |
| Independent verification | Exact lease holder/fencing token/expiry plus bundle, contract, proof, environment, report, dependency-manifest and evidence artifact/hash context | Allows `verify_submission` to record a terminal accepted or rejected verdict |

Each attestation includes a purpose, allowlisted `key_id`, issue/expiry timestamps, a
signer-generated nonce, evidence identity, canonical payload hash, and an authority signature.
Whether that nonce is consumed once or accepted only for an exact idempotent replay is defined by
the receiving workflow. Signature input is
domain-separated by both protocol version and purpose. Builder, model-work admission, model
execution, and verifier keys are separate. In particular, a model-execution key cannot admit its
own work. Builder, admission, and verifier keys are mechanically required to authorize only their
single purpose. Using one shared key defeats the authority split and is not acceptable.

The implemented public interfaces are
[attestation.py](../packages/contracts/src/autolean_contracts/attestation.py),
[model_work.py](../packages/contracts/src/autolean_contracts/model_work.py),
[verification_gateway.py](../packages/contracts/src/autolean_contracts/verification_gateway.py),
[FormalizationTaskBundleV1](../packages/contracts/src/autolean_contracts/models.py), and
[VerificationReportV1](../packages/contracts/src/autolean_contracts/models.py). They intentionally
separate signing and verification so remote KMS/HSM custody can replace the process-local test
HMAC without changing Builder--Prover semantics. `VerificationSigningRequestV1` self-validates the canonical
payload hash and contains no proof/report body, workspace path, endpoint configuration, or key.

`ModelExecutionAuthorizationService.register_model_work` accepts an `AttestationV1` separately
from the bundle. It rejects a missing verifier, wrong purpose/key/payload, future issue time,
expiry, revocation, a nonce outside the exact 48-character lowercase-hex shape, an evidence
identity other than `model-work-admission:<exact-payload-hash>`, and cross-bundle reuse. SQLite
stores the exact attestation and its canonical hash with the bundle. Registration and
ModelWork-capability issue derive their idempotency identities from their exact request digests;
the public methods accept no caller-chosen idempotency, authorization, or worker label. An exact
registration replay is accepted only while the same persisted admission remains valid.
`claim_model_work` and `issue_model_work` reload and revalidate the persisted signature on every
use, so expiry, post-registration revocation, substitution, and database inconsistency fail
closed. Registration and capability issue repeat that verification inside their write
transactions. Legacy unsigned or V1 rows are deliberately not promoted into V2 admitted work.

The complete admission payload means the complete immutable **public projection**, not a redacted
copy of a free-form record. A planner may use complete `SourceRecordV1` and `RightsRecordV1`
objects in its private/local decision process. `model_work_source_binding` and
`model_work_rights_binding` then produce V2 bindings containing only typed complete-record,
source-identity, source-byte, and span hashes; numeric offsets; permission decisions; and endpoint
enums. Run, cell, case, upstream-contract, and work-item coordinates are independently
domain-hashed. Bundle, contract, rights, authorization, and worker references use fixed system
namespaces or fixed opaque forms. Source licenses, original identifier namespaces, locators,
titles, excerpts, reviewer labels, restrictions, and caller operation labels have no V2 field and
therefore cannot accidentally enter the durable normal path.

This is an accident-prevention boundary, not an information-theoretic confidentiality claim. An
admission authority allowed to choose arbitrary digest bytes, or to override opaque signer fields
such as the nonce, can encode text into those bytes as a covert channel. Production therefore needs
an independent admission authority that reconstructs and audits every digest from the private
inputs, generates nonces internally without a caller override, and retains the signer behind its
authenticated boundary; schema validation alone cannot make a malicious authority safe.

The ModelWork helper preimages include their digest kind, so equal run, cell, case, and upstream
values do not produce linkable digest values across those domains. This domain separation prevents
accidental cross-domain substitution and equality leakage; it does not make a low-entropy planner
coordinate confidential. A party that can enumerate candidate coordinates can still build the same
unkeyed digest dictionary. If hiding those coordinates becomes a requirement, a future protocol
revision must add operator-keyed pseudonymization without placing the key in contracts or artifacts.

Every ModelWork execution authorization explicitly records its subject kind plus the exact parent
admission hash and expiry, and cannot outlive that parent. A requested TTL longer than the
remaining parent validity is rejected rather than silently shortened. Provider preflight checks
the persisted parent before capability probing or endpoint I/O. Attempt reservation repeats the exact
parent-bundle/hash/expiry/signature check inside `BEGIN IMMEDIATE`; a racing expiry or key
revocation therefore prevents generation. Theorem authorizations carry no parent admission and
remain independent of this ModelWork-only chain.

## Verification Evidence

An attested verification report must carry `VerificationEvidenceV1` with all of:

- immutable worker image digest;
- frozen OCI wrapper protocol and a stable command-policy hash;
- exact Lean version, mathlib revision, Lake manifest hash, and frozen environment hash;
- hash of the exact submitted dependency manifest;
- hash of the concrete verifier invocation; and
- a canonical `VerificationEvidenceArtifactV1` content-addressed artifact.

`LeanEnvironmentV1.verifier_execution_policy` freezes a digest-pinned worker image together with
the V1 wrapper, isolation, mount, and command-shape policy. The concrete OCI argv hash remains
separate because it includes per-attempt host mount paths and cannot safely be reused as a frozen
contract value. The Prover must show that both hashes agree before it stores evidence.

The control plane compares the environment, image, wrapper, command-policy, and
dependency-manifest fields against the registered bundle and submitted proof before accepting a
signature. It then reads the artifact bytes, rehashes them through the content-addressed store,
rejects duplicate/non-standard/non-canonical JSON, validates the exact artifact schema (V2 for
lease-bound gateway promotion), and
cross-binds the artifact to the report, frozen bundle, proof artifact, rendered candidate bytes,
trusted statement bytes, and solver manifest. A missing or arbitrary artifact, bad signature,
wrong purpose, unknown/revoked key, expiry, changed payload, or reused nonce fails closed.
`TrustedLeanVerifier` output without an external verifier attestation is therefore only a
transient observation; it cannot be promoted by `ControlPlane`.

`TrustedLeanVerifier.observe`,
[verification_attestation.py](../Prover/src/autolean_prover/verification_attestation.py), and
[verification_gateway.py](../Prover/src/autolean_prover/verification_gateway.py) implement the
Prover-side bridge. The adapter recomputes the byte hash of the verifier-rendered candidate
(including its fixed axiom-query suffix), checks OCI image/environment/statement/manifest bindings,
stores a JSON-safe artifact through an injected content-addressed sink, then sends only its digest
and the fenced verification context to a dedicated gateway. Lease-bound promotion requires the
canonical V2 artifact. The gateway rechecks the live SQLite lease, submitted-proof event,
registered task binding, and canonical V2 evidence artifact before invoking a mandatory
`IndependentExecutionVerifier`. That verifier receives the exact signing request and parsed,
canonical artifact, reruns the approved verifier path, and returns a hash-bound public receipt:
its ID, verifier ID, check timestamp, request hash, evidence-artifact/evidence digests, execution
claim hash, and receipt hash. The receipt must also carry an independent authentication envelope
over that hash. Gateway construction requires an `IndependentExecutionTrustPolicyV1`, which
allowlists verifier IDs and their authentication key IDs, verifies the envelope through an injected
authenticator, and mechanically requires its key ID to differ from the gateway signing key ID. A
malformed, mismatched, unauthenticated, untrusted, unavailable, or absent receipt is rejected
before the gateway reserves a signing request. The gateway rechecks the lease after the independent
run and both immediately before and after signing. Receipt time must be at or after request time
and no later than either the current gateway clock or lease expiry; exact replay revalidates this
persisted timestamp without rerunning Lean. It never receives or stores a prompt,
proof source, workspace path, raw Lean stdout/stderr, or credential reference. It may attest a
negative kernel result with valid execution evidence so that the control plane can record a
verified rejection; an observation without OCI evidence remains non-promotable.

`ControlPlane.verify_submission` reconstructs the same v2 gateway payload from the current lease
and report. A signature minted under an older holder, fencing token, or expiry therefore fails even
if its cryptographic nonce has not yet been consumed. The older
`attest_oci_observation(..., signer=...)` adapter and
`allow_test_only_direct_verifier_attestations=True` switch exist only for deterministic legacy
fixtures; the production default rejects that direct v1 payload.

## Replay and Idempotency

ModelWork registration and ModelWork capability issue do not expose caller-selected idempotency
keys. Their exact request digest is the internal key, so an exact retry returns the same durable
object and a changed attestation nonce is a different immutable registration attempt. The
signer-generated nonce is not itself a user-facing job or case label.

The SQLite event store has an `attestation_nonce_uses` table. It consumes
`(purpose, key_id, nonce)` in the same `BEGIN IMMEDIATE` transaction as the event append. A
network retry with the same idempotency request returns the original event before consuming a
nonce again. The command gateway performs that replay lookup before lease or attestation expiry
checks, so a durable retry of an already committed command remains replayable after restart. A
valid signature reused for a different transition is rejected, including after restart. The event
projection stores only a public summary (purpose, key ID, payload hash,
evidence identity, expiry); it stores no signing secret or raw evidence bytes.

The gateway additionally maintains `verifier_signing_requests`. Request ID, request nonce,
idempotency key, and canonical payload hash are unique. An exact idempotent retry returns the same
public attestation without rerunning the independent verifier, but only when the ledger retains a
complete public receipt binding. A different request cannot mint a second signature for the same
payload. Failed or interrupted signing attempts remain consumed and fail closed. The ledger retains
the receipt ID/hash, public authentication-envelope fields, and public binding fields alongside
digests, state, and the issued signature. A legacy issued row with no authenticated receipt fails
closed. The ledger never retains HMAC/KMS key material, candidate bytes, raw output, or exception
text from a verifier adapter.

## Operator Handling and Residual Risk

`HmacAttestationKeyV1`, `HmacAttestationSignerV1`, and `HmacAttestationVerifierV1` are test-only
runtime objects. No key bytes belong in YAML, JSON, task bundles, artifacts, worker workspaces,
logs, prompts, endpoint configuration, or the gateway request/ledger. Their presence demonstrates
protocol behavior, not independent authority.

The role and FATE harness tests use a dedicated process-local
`MODEL_WORK_ADMISSION` HMAC key labelled test-only/nonpromotable. Those tests establish payload
binding, persistence, and fail-closed state transitions only. Production admission still requires
an independently authenticated mTLS/ACL service and non-exportable KMS/HSM authority; a worker,
adapter, or model-execution service must not custody the admission signing key.

The implemented local gateway is test-only. It has no production KMS, network listener, or
unforgeable capability boundary: Python callers can construct their own protocols and wrappers.
Consequently every local `IndependentExecutionClassV1.PRODUCTION` construction and every attempted
production `issue` raises `ProductionAuthorityUnavailable`, regardless of the supplied authenticator,
allowlist, or verifier implementation. Production remains an interface placeholder until a separate
remote mTLS/KMS service client exists. The local HMAC and real-worker canary are explicit fixtures;
constructing a production trust policy additionally requires every receipt authenticator to expose
the exact enum marker `execution_class=PRODUCTION`; a missing, unknown, string-valued, or test-only
marker fails closed. That marker is necessary type evidence, not proof that remote authority exists.
The canary performs a second digest-pinned Docker-wrapper run but still runs under one operator
context. Every current `ControlPlane` verification event and reader is fixed to
`execution_authority_class=test-only-local` and `promotion_state=not_a_promotion`; a conflicting
promotion or production claim is rejected while proof evidence may still be locally accepted.
Production promotion still requires an operator-authenticated mTLS/ACL boundary, a KMS/HSM
sign/verify authority whose key material cannot be exported to workers or the control plane, key
rotation/revocation policy, a pinned OCI-image policy, and independently retained verifier
evidence. `AttestationV1` fixes HMAC-SHA256; adopting Ed25519/ECDSA or another asymmetric scheme
requires a versioned `AttestationV2`, not reinterpretation of the V1 signature field. Until that
deployment evidence exists, gateway tests prove only the software boundary and fail-closed
semantics.
