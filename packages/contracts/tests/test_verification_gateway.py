from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from autolean_contracts import (
    AttestationPurposeV1,
    HashKindV1,
    VerificationSigningContextV1,
    VerificationSigningLeaseBindingV1,
    VerificationSigningRequestV1,
    attestation_payload_hash,
    digest_text,
    stable_identifier,
    verification_gateway_attestation_payload,
)


def _request() -> VerificationSigningRequestV1:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    bundle_id = stable_identifier("bundle", "gateway-contract")
    lease = VerificationSigningLeaseBindingV1(
        bundle_id=bundle_id,
        worker_id="verifier-worker",
        fencing_token=7,
        expires_at=now + timedelta(minutes=2),
    )
    context = VerificationSigningContextV1(
        bundle_id=bundle_id,
        bundle_hash=digest_text(HashKindV1.BUNDLE, "bundle"),
        proof_id=stable_identifier("proof", "gateway-contract"),
        proof_submission_artifact_digest="a" * 64,
        contract_id=stable_identifier("statement-contract", "gateway-contract"),
        revision=3,
        contract_hash=digest_text(HashKindV1.CONTRACT, "contract"),
        proof_boundary_hash=digest_text(HashKindV1.PROOF_BOUNDARY, "boundary"),
        environment_hash=digest_text(HashKindV1.ENVIRONMENT, "environment"),
        dependency_manifest_hash=digest_text(
            HashKindV1.DEPENDENCY_MANIFEST,
            "dependencies",
        ),
        report_id=stable_identifier("verification-report", "gateway-contract"),
        verification_report_hash=digest_text(
            HashKindV1.VERIFICATION_REPORT,
            "report",
        ),
        verifier_id="independent-verifier",
        evidence_identity=stable_identifier("verification-evidence", "gateway-contract"),
        verification_evidence_hash=digest_text(
            HashKindV1.VERIFICATION_EVIDENCE,
            "evidence",
        ),
        evidence_artifact_digest="b" * 64,
    )
    payload = verification_gateway_attestation_payload(lease=lease, context=context)
    return VerificationSigningRequestV1(
        request_id=stable_identifier("verification-signing-request", "gateway-contract"),
        request_nonce="gateway-contract-nonce-0001",
        idempotency_key="gateway-contract-idempotency",
        requested_at=now,
        expires_at=now + timedelta(minutes=1),
        lease=lease,
        context=context,
        canonical_payload_hash=attestation_payload_hash(
            AttestationPurposeV1.VERIFICATION,
            payload,
        ),
    )


def test_gateway_request_hash_self_validates_and_contains_no_authority_material() -> None:
    request = _request()
    serialized = request.model_dump_json()

    assert "secret" not in serialized.lower()
    assert "signature" not in serialized.lower()
    assert "key_id" not in serialized.lower()
    assert "proof_source" not in serialized
    assert "workspace" not in serialized.lower()

    with pytest.raises(ValidationError, match="canonical payload hash"):
        request.model_copy(
            update={
                "canonical_payload_hash": digest_text(
                    HashKindV1.ATTESTATION_PAYLOAD,
                    "tampered",
                )
            }
        )


def test_gateway_request_rejects_cross_bundle_and_lease_expiry_mismatch() -> None:
    request = _request()
    other_lease = request.lease.model_copy(
        update={"bundle_id": stable_identifier("bundle", "other")}
    )
    with pytest.raises(ValueError, match="different bundles"):
        verification_gateway_attestation_payload(
            lease=other_lease,
            context=request.context,
        )

    with pytest.raises(ValidationError, match="must not outlive"):
        request.model_copy(update={"expires_at": request.lease.expires_at + timedelta(seconds=1)})
