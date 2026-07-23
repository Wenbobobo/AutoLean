"""Secret-free Prover client boundary for verifier signing authority."""

from __future__ import annotations

import hmac
import secrets
from datetime import UTC, datetime, timedelta
from typing import Protocol

from autolean_contracts import (
    AttestationPurposeV1,
    AttestationV1,
    FormalizationTaskBundleV1,
    ProofSubmissionV1,
    StableIdentifierV1,
    VerificationReportV1,
    VerificationSigningContextV1,
    VerificationSigningLeaseBindingV1,
    VerificationSigningRequestV1,
    attestation_payload_hash,
    proof_dependency_manifest_hash,
    stable_identifier,
    verification_gateway_attestation_payload,
)

from autolean_prover.errors import ValidationError
from autolean_prover.verification import VerificationObservation
from autolean_prover.verification_attestation import (
    EvidenceArtifactSink,
    prepare_oci_verification_evidence,
)


class VerificationSigningGatewayClient(Protocol):
    """Transport-neutral gateway client with no key or generic signing operation."""

    def issue(self, request: VerificationSigningRequestV1) -> AttestationV1: ...


def build_verification_signing_request(
    report: VerificationReportV1,
    *,
    bundle: FormalizationTaskBundleV1,
    submission: ProofSubmissionV1,
    proof_submission_artifact_digest: str,
    lease: VerificationSigningLeaseBindingV1,
    idempotency_key: str,
    ttl_seconds: float,
    request_id: StableIdentifierV1 | None = None,
    request_nonce: str | None = None,
    requested_at: datetime | None = None,
) -> VerificationSigningRequestV1:
    """Build a canonical request containing no proof, report detail, path, or credential."""

    if ttl_seconds <= 0:
        raise ValidationError(
            "verification_gateway_ttl",
            "verification gateway request TTL must be positive",
        )
    evidence = report.evidence
    if evidence is None or report.verifier_attestation is not None:
        raise ValidationError(
            "verification_gateway_report_state",
            "gateway signing requires an unsigned report with canonical verifier evidence",
        )
    now = requested_at or datetime.now(UTC)
    if now.tzinfo is None:
        raise ValidationError(
            "verification_gateway_clock",
            "verification gateway request time must be timezone-aware",
        )
    now = now.astimezone(UTC)
    expires_at = min(now + timedelta(seconds=ttl_seconds), lease.expires_at.astimezone(UTC))
    if expires_at <= now:
        raise ValidationError(
            "verification_gateway_lease_expired",
            "verification gateway request has no remaining lease authority",
        )
    context = VerificationSigningContextV1(
        bundle_id=bundle.bundle_id,
        bundle_hash=bundle.handoff_hash(),
        proof_id=submission.proof_id,
        proof_submission_artifact_digest=proof_submission_artifact_digest,
        contract_id=bundle.contract.contract_id,
        revision=bundle.contract.revision,
        contract_hash=report.contract_hash,
        proof_boundary_hash=report.proof_boundary_hash,
        environment_hash=report.environment_hash,
        dependency_manifest_hash=proof_dependency_manifest_hash(submission),
        report_id=report.report_id,
        verification_report_hash=report.report_hash(),
        verifier_id=report.verifier_id,
        evidence_identity=evidence.evidence_id,
        verification_evidence_hash=evidence.evidence_hash(),
        evidence_artifact_digest=evidence.evidence_artifact_digest,
    )
    payload = verification_gateway_attestation_payload(lease=lease, context=context)
    nonce = request_nonce or secrets.token_hex(24)
    actual_request_id = request_id or stable_identifier("verification-signing-request", nonce)
    return VerificationSigningRequestV1(
        request_id=actual_request_id,
        request_nonce=nonce,
        idempotency_key=idempotency_key,
        requested_at=now,
        expires_at=expires_at,
        lease=lease,
        context=context,
        canonical_payload_hash=attestation_payload_hash(
            AttestationPurposeV1.VERIFICATION,
            payload,
        ),
    )


def attest_oci_observation_via_gateway(
    observation: VerificationObservation,
    *,
    bundle: FormalizationTaskBundleV1,
    submission: ProofSubmissionV1,
    proof_submission_artifact_digest: str,
    artifact_sink: EvidenceArtifactSink,
    lease: VerificationSigningLeaseBindingV1,
    gateway_client: VerificationSigningGatewayClient,
    idempotency_key: str,
    ttl_seconds: float = 300,
    request_id: StableIdentifierV1 | None = None,
    request_nonce: str | None = None,
    requested_at: datetime | None = None,
    captured_at: datetime | None = None,
) -> VerificationReportV1:
    """Prepare verifier evidence and request a lease-bound gateway attestation."""

    unsigned = prepare_oci_verification_evidence(
        observation,
        bundle=bundle,
        submission=submission,
        proof_submission_artifact_digest=proof_submission_artifact_digest,
        artifact_sink=artifact_sink,
        captured_at=captured_at,
    )
    request = build_verification_signing_request(
        unsigned,
        bundle=bundle,
        submission=submission,
        proof_submission_artifact_digest=proof_submission_artifact_digest,
        lease=lease,
        idempotency_key=idempotency_key,
        ttl_seconds=ttl_seconds,
        request_id=request_id,
        request_nonce=request_nonce,
        requested_at=requested_at,
    )
    try:
        attestation = gateway_client.issue(request)
    except Exception as error:
        raise ValidationError(
            "verification_gateway_unavailable",
            "verifier signing gateway refused the request or is unavailable",
        ) from error
    _validate_gateway_response(request, attestation)
    return unsigned.model_copy(update={"verifier_attestation": attestation})


def _validate_gateway_response(
    request: VerificationSigningRequestV1,
    attestation: AttestationV1,
) -> None:
    if attestation.purpose is not AttestationPurposeV1.VERIFICATION:
        raise ValidationError(
            "verification_gateway_purpose",
            "verifier signing gateway returned a different authority purpose",
        )
    if attestation.evidence_identity != request.context.evidence_identity.value:
        raise ValidationError(
            "verification_gateway_evidence_identity",
            "verifier signing gateway returned a different evidence identity",
        )
    if not hmac.compare_digest(
        attestation.payload_hash.value,
        request.canonical_payload_hash.value,
    ):
        raise ValidationError(
            "verification_gateway_payload_hash",
            "verifier signing gateway returned a different canonical payload hash",
        )
    if attestation.issued_at < request.requested_at or attestation.expires_at > request.expires_at:
        raise ValidationError(
            "verification_gateway_expiry",
            "verifier signing gateway returned an attestation outside request authority",
        )
