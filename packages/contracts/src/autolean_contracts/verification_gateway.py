"""Public, secret-free contracts for the verifier signing gateway.

The gateway request is deliberately narrower than a verification report.  It carries only
content digests and immutable control-plane bindings.  Proof text, report details, workspace
paths, raw verifier output, endpoint configuration, and signing-key material are outside this
protocol.
"""

from __future__ import annotations

import hmac
import re
from datetime import datetime
from typing import Literal

from pydantic import Field, model_validator

from .attestation import AttestationPurposeV1, attestation_payload_hash
from .base import ContractModel
from .hashing import DigestV1, HashKindV1, StableIdentifierV1, digest_model, require_digest_kind

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_REQUEST_NONCE = re.compile(r"^[A-Za-z0-9._-]{16,256}$")


class VerificationSigningLeaseBindingV1(ContractModel):
    """The exact control-plane lease through which a verifier requests a signature."""

    schema_version: Literal["autolean.verification-signing-lease.v1"] = (
        "autolean.verification-signing-lease.v1"
    )
    bundle_id: StableIdentifierV1
    worker_id: str = Field(min_length=1, max_length=256)
    fencing_token: int = Field(gt=0)
    expires_at: datetime

    @model_validator(mode="after")
    def validate_lease(self) -> VerificationSigningLeaseBindingV1:
        if not _SAFE_ID.fullmatch(self.worker_id):
            raise ValueError("verification signing worker_id is not a safe identifier")
        if self.expires_at.tzinfo is None:
            raise ValueError("verification signing lease expiry must be timezone-aware")
        return self


class VerificationSigningContextV1(ContractModel):
    """Canonical public facts an isolated verifier authority is asked to attest."""

    schema_version: Literal["autolean.verification-signing-context.v1"] = (
        "autolean.verification-signing-context.v1"
    )
    bundle_id: StableIdentifierV1
    bundle_hash: DigestV1
    proof_id: StableIdentifierV1
    proof_submission_artifact_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    contract_id: StableIdentifierV1
    revision: int = Field(ge=1)
    contract_hash: DigestV1
    proof_boundary_hash: DigestV1
    environment_hash: DigestV1
    dependency_manifest_hash: DigestV1
    report_id: StableIdentifierV1
    verification_report_hash: DigestV1
    verifier_id: str = Field(min_length=1, max_length=256)
    evidence_identity: StableIdentifierV1
    verification_evidence_hash: DigestV1
    evidence_artifact_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_context(self) -> VerificationSigningContextV1:
        require_digest_kind(self.bundle_hash, HashKindV1.BUNDLE, "bundle_hash")
        require_digest_kind(self.contract_hash, HashKindV1.CONTRACT, "contract_hash")
        require_digest_kind(
            self.proof_boundary_hash,
            HashKindV1.PROOF_BOUNDARY,
            "proof_boundary_hash",
        )
        require_digest_kind(self.environment_hash, HashKindV1.ENVIRONMENT, "environment_hash")
        require_digest_kind(
            self.dependency_manifest_hash,
            HashKindV1.DEPENDENCY_MANIFEST,
            "dependency_manifest_hash",
        )
        require_digest_kind(
            self.verification_report_hash,
            HashKindV1.VERIFICATION_REPORT,
            "verification_report_hash",
        )
        require_digest_kind(
            self.verification_evidence_hash,
            HashKindV1.VERIFICATION_EVIDENCE,
            "verification_evidence_hash",
        )
        if not _SAFE_ID.fullmatch(self.verifier_id):
            raise ValueError("verification signing verifier_id is not a safe identifier")
        return self

    def context_hash(self) -> DigestV1:
        """Return a canonical digest suitable for audit and replay ledgers."""

        return digest_model(HashKindV1.ATTESTATION_PAYLOAD, self)


def verification_gateway_attestation_payload(
    *,
    lease: VerificationSigningLeaseBindingV1,
    context: VerificationSigningContextV1,
) -> dict[str, object]:
    """Build the v2 payload signed only by the isolated verifier gateway authority."""

    if lease.bundle_id != context.bundle_id:
        raise ValueError("verification signing lease and context name different bundles")
    return {
        "schema_version": "autolean.verification-gateway-attestation-payload.v1",
        "lease": lease.model_dump(mode="json"),
        "context": context.model_dump(mode="json"),
    }


class VerificationSigningRequestV1(ContractModel):
    """One replay-protected request to the verifier signing gateway.

    ``canonical_payload_hash`` is recomputed during validation, so a transport cannot substitute
    either the lease or verification context while preserving a worker-provided digest.
    """

    schema_version: Literal["autolean.verification-signing-request.v1"] = (
        "autolean.verification-signing-request.v1"
    )
    request_id: StableIdentifierV1
    request_nonce: str = Field(min_length=16, max_length=256)
    idempotency_key: str = Field(min_length=1, max_length=256)
    requested_at: datetime
    expires_at: datetime
    lease: VerificationSigningLeaseBindingV1
    context: VerificationSigningContextV1
    canonical_payload_hash: DigestV1

    @model_validator(mode="after")
    def validate_request(self) -> VerificationSigningRequestV1:
        if not _REQUEST_NONCE.fullmatch(self.request_nonce):
            raise ValueError("verification signing request nonce is not a safe V1 nonce")
        if not _SAFE_ID.fullmatch(self.idempotency_key):
            raise ValueError("verification signing idempotency key is not a safe identifier")
        if self.requested_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("verification signing request timestamps must be timezone-aware")
        if self.expires_at <= self.requested_at:
            raise ValueError("verification signing request expiry must be after request time")
        if self.expires_at > self.lease.expires_at:
            raise ValueError("verification signing request must not outlive its lease")
        require_digest_kind(
            self.canonical_payload_hash,
            HashKindV1.ATTESTATION_PAYLOAD,
            "canonical_payload_hash",
        )
        expected = attestation_payload_hash(
            AttestationPurposeV1.VERIFICATION,
            verification_gateway_attestation_payload(
                lease=self.lease,
                context=self.context,
            ),
        )
        if not hmac.compare_digest(self.canonical_payload_hash.value, expected.value):
            raise ValueError("verification signing request canonical payload hash does not match")
        return self

    def request_hash(self) -> DigestV1:
        """Bind every replay and idempotency field without exposing request contents."""

        return digest_model(HashKindV1.ATTESTATION_PAYLOAD, self)
