# Attestation Trust Root V1

## Scope

An immutable-looking JSON bundle is not proof that Builder performed the semantic freeze gate, and
a `VerificationReportV1` containing only `true` values is not proof that an independent verifier
ran Lean. Phase 1 therefore requires two separate, versioned attestations before the local control
plane registers a bundle or accepts any verification verdict.

This document describes the implemented protocol boundary. It does not claim that an OCI worker
or a public-key authority has already been deployed.

## Authority roles

| Authority | Signed payload | Control-plane effect |
| --- | --- | --- |
| Builder freeze | Bundle ID and hash, contract ID/revision/hash, proof-boundary and environment hashes, freeze-evidence hash, and typed fidelity-artifact reference | Allows `register_bundle` only after the signature and retained Builder artifact validate |
| Independent verification | Exact lease holder/fencing token/expiry plus bundle, contract, proof, environment, report, dependency-manifest and evidence artifact/hash context | Allows `verify_submission` to record a terminal accepted or rejected verdict |

Each attestation includes a purpose, allowlisted `key_id`, issue/expiry timestamps, one-time nonce,
evidence identity, canonical payload hash, and an authority signature. Signature input is
domain-separated by both protocol version and purpose. A Builder key must authorize only
`builder_freeze`; a verifier key must authorize only `verification`. Using one shared key defeats
the role split and is not an acceptable production configuration.

The implemented public interfaces are
[attestation.py](../packages/contracts/src/autolean_contracts/attestation.py),
[verification_gateway.py](../packages/contracts/src/autolean_contracts/verification_gateway.py),
[FormalizationTaskBundleV1](../packages/contracts/src/autolean_contracts/models.py), and
[VerificationReportV1](../packages/contracts/src/autolean_contracts/models.py). They intentionally
separate signing and verification so remote KMS/HSM custody can replace the process-local test
HMAC without changing Builder--Prover semantics. `VerificationSigningRequestV1` self-validates the canonical
payload hash and contains no proof/report body, workspace path, endpoint configuration, or key.

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
rejects duplicate/non-standard/non-canonical JSON, validates the exact V1 artifact schema, and
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
and the fenced verification context to a dedicated gateway. The gateway rechecks the live SQLite
lease, submitted-proof event, registered task binding, and canonical evidence artifact before its
authority signs. It never receives or stores a prompt,
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
public attestation; a different request cannot mint a second signature for the same payload.
Failed or interrupted signing attempts remain consumed and fail closed. The ledger retains public
digests, binding IDs, state, and the issued signature, never HMAC/KMS key material or exception
text from a signer adapter.

## Operator Handling and Residual Risk

`HmacAttestationKeyV1`, `HmacAttestationSignerV1`, and `HmacAttestationVerifierV1` are test-only
runtime objects. No key bytes belong in YAML, JSON, task bundles, artifacts, worker workspaces,
logs, prompts, endpoint configuration, or the gateway request/ledger. Their presence demonstrates
protocol behavior, not independent authority.

The implemented gateway is transport-neutral and has no production KMS or network listener.
It validates identity, content, and lease binding; it does not by itself prove that Lean or OCI
ran. A production ACL must admit only the isolated verifier workflow, and that workflow must
produce independently retained execution evidence. Giving an ordinary proof-search worker access
to a raw signing operation would invalidate the independence claim even though hashes still match.
Production promotion still requires an operator-authenticated mTLS/ACL boundary, a KMS/HSM
sign/verify authority whose key material cannot be exported to workers or the control plane, key
rotation/revocation policy, a pinned OCI-image policy, and independently retained verifier
evidence. `AttestationV1` fixes HMAC-SHA256; adopting Ed25519/ECDSA or another asymmetric scheme
requires a versioned `AttestationV2`, not reinterpretation of the V1 signature field. Until that
deployment evidence exists, gateway tests prove only the software boundary and fail-closed
semantics.
