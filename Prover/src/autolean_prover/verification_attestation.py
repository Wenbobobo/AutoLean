"""Promote a transient OCI verifier observation into an attested report.

This module is intentionally Prover-only: it has no dependency on the control plane or its
filesystem artifact implementation.  The caller supplies a narrow content-addressed artifact
sink and an operator-owned verifier signer.  That keeps Builder, Prover, and control-plane state
separate while preserving the exact payload that the control plane will later verify.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from datetime import datetime
from typing import Protocol

from autolean_contracts import (
    AttestationPurposeV1,
    AttestationSignerV1,
    DigestV1,
    FormalizationTaskBundleV1,
    HashKindV1,
    OciVerificationArtifactV1,
    ProofSubmissionV1,
    StableIdentifierV1,
    VerificationArtifactEnvironmentV1,
    VerificationEvidenceArtifactV1,
    VerificationEvidenceV1,
    VerificationReportV1,
    proof_dependency_manifest_hash,
    stable_identifier,
    verification_attestation_payload,
)

from autolean_prover.errors import ValidationError
from autolean_prover.execution import OciExecutionEvidence
from autolean_prover.verification import VerificationObservation

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class EvidenceArtifactSink(Protocol):
    """Store a JSON-safe evidence payload and return its SHA-256 digest.

    The sink must perform the content-addressed write itself.  It receives no proof source,
    prompt, workspace path, raw Lean output, or credential reference.
    """

    def __call__(self, payload: Mapping[str, object]) -> str: ...


def attest_oci_observation(
    observation: VerificationObservation,
    *,
    bundle: FormalizationTaskBundleV1,
    submission: ProofSubmissionV1,
    proof_submission_artifact_digest: str,
    artifact_sink: EvidenceArtifactSink,
    signer: AttestationSignerV1,
    ttl_seconds: float = 3600,
    captured_at: datetime | None = None,
) -> VerificationReportV1:
    """Attach OCI evidence and a test-only/local verifier signature to one observation.

    This compatibility adapter puts a signer in the caller's process and therefore is not an
    independent production authority boundary.  Production callers must use
    ``attest_oci_observation_via_gateway`` from ``verification_gateway``.
    """

    if ttl_seconds <= 0:
        raise ValidationError(
            "verification_attestation_ttl",
            "verification attestation TTL must be positive",
        )
    unsigned = prepare_oci_verification_evidence(
        observation,
        bundle=bundle,
        submission=submission,
        proof_submission_artifact_digest=proof_submission_artifact_digest,
        artifact_sink=artifact_sink,
        captured_at=captured_at,
    )
    evidence = unsigned.evidence
    if evidence is None:
        raise ValidationError(
            "verification_evidence_absent",
            "prepared verification report has no evidence",
        )
    try:
        attestation = signer.issue(
            purpose=AttestationPurposeV1.VERIFICATION,
            payload=verification_attestation_payload(
                bundle_id=bundle.bundle_id.value,
                bundle_hash=bundle.handoff_hash().value,
                proof_submission_artifact_digest=proof_submission_artifact_digest,
                contract_id=bundle.contract.contract_id.value,
                revision=bundle.contract.revision,
                contract_hash=unsigned.contract_hash,
                proof_boundary_hash=unsigned.proof_boundary_hash,
                environment_hash=unsigned.environment_hash,
                report=unsigned,
            ),
            evidence_identity=evidence.evidence_id.value,
            ttl_seconds=ttl_seconds,
        )
    except ValueError as error:
        raise ValidationError(
            "verification_attestation_issuance",
            "verification authority could not attest the report",
        ) from error
    return unsigned.model_copy(update={"verifier_attestation": attestation})


def prepare_oci_verification_evidence(
    observation: VerificationObservation,
    *,
    bundle: FormalizationTaskBundleV1,
    submission: ProofSubmissionV1,
    proof_submission_artifact_digest: str,
    artifact_sink: EvidenceArtifactSink,
    captured_at: datetime | None = None,
) -> VerificationReportV1:
    """Create the canonical unsigned report and evidence artifact sent to a gateway."""

    if not _SHA256.fullmatch(proof_submission_artifact_digest):
        raise ValidationError(
            "proof_submission_artifact_digest",
            "proof submission artifact digest must be a lowercase SHA-256 digest",
        )
    execution = observation.oci_execution_evidence
    if execution is None:
        raise ValidationError(
            "oci_execution_evidence_absent",
            "an OCI execution record is required before verifier attestation",
        )
    report = observation.report
    _validate_report_binding(bundle, submission, report)
    _validate_execution_binding(bundle, submission, execution)

    observation_hash = report.report_hash()
    evidence_id = stable_identifier(
        "verification-evidence",
        ":".join(
            (
                report.report_id.value,
                observation_hash.value,
                execution.command_hash,
                proof_submission_artifact_digest,
            )
        ),
    )
    artifact_payload = _evidence_artifact_payload(
        bundle=bundle,
        submission=submission,
        report=report,
        execution=execution,
        evidence_id=evidence_id,
        proof_submission_artifact_digest=proof_submission_artifact_digest,
        observation_hash=observation_hash,
    )
    try:
        artifact_digest = artifact_sink(artifact_payload)
    except Exception as error:
        raise ValidationError(
            "verification_evidence_artifact_unavailable",
            "verifier evidence artifact could not be stored",
        ) from error
    if not isinstance(artifact_digest, str) or not _SHA256.fullmatch(artifact_digest):
        raise ValidationError(
            "verification_evidence_artifact_digest",
            "verifier evidence artifact sink returned an invalid digest",
        )

    environment = bundle.contract.formal.environment
    evidence_kwargs: dict[str, object] = {
        "evidence_id": evidence_id,
        "environment_hash": environment.environment_hash,
        "worker_image_digest": execution.worker_image_digest,
        "wrapper_protocol": execution.wrapper_protocol,
        "lean_version": execution.lean_version,
        "mathlib_revision": execution.mathlib_revision,
        "lake_manifest_hash": environment.lake_manifest_hash,
        "dependency_manifest_hash": proof_dependency_manifest_hash(submission),
        "command_policy_hash": DigestV1(
            kind=HashKindV1.VERIFICATION_COMMAND,
            value=execution.command_policy_hash,
        ),
        "command_hash": DigestV1(
            kind=HashKindV1.VERIFICATION_COMMAND,
            value=execution.command_hash,
        ),
        "evidence_artifact_digest": artifact_digest,
    }
    if captured_at is not None:
        evidence_kwargs["captured_at"] = captured_at
    evidence = VerificationEvidenceV1.model_validate(evidence_kwargs)
    return report.model_copy(update={"evidence": evidence})


def _validate_report_binding(
    bundle: FormalizationTaskBundleV1,
    submission: ProofSubmissionV1,
    report: VerificationReportV1,
) -> None:
    contract = bundle.contract
    if report.evidence is not None or report.verifier_attestation is not None:
        raise ValidationError(
            "verification_report_already_attested",
            "verification report already carries authority material",
        )
    if (
        submission.contract_id != contract.contract_id
        or report.contract_hash != contract.semantic_hash()
    ):
        raise ValidationError(
            "verification_contract_binding",
            "verification observation does not bind the frozen contract",
        )
    if submission.revision != contract.revision or submission.contract_hash != report.contract_hash:
        raise ValidationError(
            "verification_revision_binding",
            "verification observation does not bind the submitted contract revision",
        )
    if report.proof_id != submission.proof_id:
        raise ValidationError(
            "verification_proof_binding",
            "verification observation does not bind the submitted proof",
        )
    if report.proof_boundary_hash != bundle.proof_boundary.boundary_hash:
        raise ValidationError(
            "verification_boundary_binding",
            "verification observation does not bind the frozen proof boundary",
        )
    if submission.proof_boundary_hash != report.proof_boundary_hash:
        raise ValidationError(
            "verification_submission_boundary",
            "submitted proof does not bind the observed proof boundary",
        )
    environment = contract.formal.environment
    if (
        submission.environment_hash != environment.environment_hash
        or report.environment_hash != environment.environment_hash
    ):
        raise ValidationError(
            "verification_environment_binding",
            "verification observation does not bind the frozen environment",
        )
    if report.axiom_profile is not contract.policy.axiom_profile:
        raise ValidationError(
            "verification_axiom_profile",
            "verification observation uses a different axiom policy",
        )


def _validate_execution_binding(
    bundle: FormalizationTaskBundleV1,
    submission: ProofSubmissionV1,
    execution: OciExecutionEvidence,
) -> None:
    environment = bundle.contract.formal.environment
    boundary = bundle.proof_boundary
    policy = environment.verifier_execution_policy
    if execution.worker_image_digest != policy.worker_image_digest:
        raise ValidationError(
            "oci_worker_image_policy_mismatch",
            "OCI execution record has a worker image outside the frozen verifier policy",
        )
    if execution.wrapper_protocol != policy.wrapper_protocol:
        raise ValidationError(
            "oci_wrapper_policy_mismatch",
            "OCI execution record has a wrapper protocol outside the frozen verifier policy",
        )
    if execution.command_policy_hash != policy.command_policy_hash().value:
        raise ValidationError(
            "oci_command_policy_mismatch",
            "OCI execution record has a command policy outside the frozen verifier policy",
        )
    if execution.environment_hash != environment.environment_hash.value:
        raise ValidationError(
            "oci_environment_hash_mismatch",
            "OCI execution record has a different environment hash",
        )
    if execution.lean_version != environment.lean_version:
        raise ValidationError(
            "oci_lean_version_mismatch",
            "OCI execution record has a different Lean version",
        )
    if execution.mathlib_revision != environment.mathlib_revision:
        raise ValidationError(
            "oci_mathlib_revision_mismatch",
            "OCI execution record has a different mathlib revision",
        )
    expected_lake_manifest = (
        None if environment.lake_manifest_hash is None else environment.lake_manifest_hash.value
    )
    if execution.lake_manifest_hash != expected_lake_manifest:
        raise ValidationError(
            "oci_lake_manifest_mismatch",
            "OCI execution record has a different Lake manifest",
        )
    if execution.trusted_statement_sha256 != boundary.trusted_statement_hash.value:
        raise ValidationError(
            "oci_trusted_statement_mismatch",
            "OCI execution record does not bind the frozen statement bytes",
        )
    if execution.bundle_manifest_sha256 != boundary.solver_manifest_hash.value:
        raise ValidationError(
            "oci_bundle_manifest_mismatch",
            "OCI execution record does not bind the frozen workspace manifest",
        )
    if execution.candidate_sha256 != _candidate_sha256(bundle, submission):
        raise ValidationError(
            "oci_candidate_mismatch",
            "OCI execution record does not bind the submitted proof source",
        )


def _candidate_sha256(bundle: FormalizationTaskBundleV1, submission: ProofSubmissionV1) -> str:
    """Reproduce the verifier-rendered candidate, including its fixed axiom query suffix."""

    boundary = bundle.proof_boundary
    candidate = (
        f"{boundary.trusted_statement_source} := {submission.proof_source.rstrip()}\n"
        f"\n#print axioms {boundary.expected_declaration}\n"
    )
    return hashlib.sha256(candidate.encode("utf-8")).hexdigest()


def _evidence_artifact_payload(
    *,
    bundle: FormalizationTaskBundleV1,
    submission: ProofSubmissionV1,
    report: VerificationReportV1,
    execution: OciExecutionEvidence,
    evidence_id: StableIdentifierV1,
    proof_submission_artifact_digest: str,
    observation_hash: DigestV1,
) -> dict[str, object]:
    """Serialize only non-secret execution facts that the signature later binds."""

    environment = bundle.contract.formal.environment
    artifact = VerificationEvidenceArtifactV1(
        evidence_id=evidence_id,
        bundle_id=bundle.bundle_id,
        bundle_hash=bundle.handoff_hash(),
        contract_id=bundle.contract.contract_id,
        revision=bundle.contract.revision,
        contract_hash=bundle.contract.semantic_hash(),
        proof_id=submission.proof_id,
        proof_boundary_hash=bundle.proof_boundary.boundary_hash,
        proof_submission_artifact_digest=proof_submission_artifact_digest,
        dependency_manifest_hash=proof_dependency_manifest_hash(submission),
        verification_report_id=report.report_id,
        verification_observation_hash=observation_hash,
        environment=VerificationArtifactEnvironmentV1(
            environment_hash=environment.environment_hash,
            lean_version=execution.lean_version,
            mathlib_revision=execution.mathlib_revision,
            lake_manifest_hash=environment.lake_manifest_hash,
        ),
        oci=OciVerificationArtifactV1(
            worker_image_digest=execution.worker_image_digest,
            wrapper_protocol=execution.wrapper_protocol,
            command_policy_hash=DigestV1(
                kind=HashKindV1.VERIFICATION_COMMAND,
                value=execution.command_policy_hash,
            ),
            command_hash=DigestV1(
                kind=HashKindV1.VERIFICATION_COMMAND,
                value=execution.command_hash,
            ),
            candidate_sha256=execution.candidate_sha256,
            trusted_statement_sha256=execution.trusted_statement_sha256,
            bundle_manifest_sha256=execution.bundle_manifest_sha256,
        ),
    )
    return artifact.model_dump(mode="json")
