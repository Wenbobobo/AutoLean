from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from autolean_contracts import (
    AttestationPurposeV1,
    HashKindV1,
    HmacAttestationKeyV1,
    HmacAttestationSignerV1,
    HmacAttestationVerifierV1,
    ProofSubmissionV1,
    VerificationSigningLeaseBindingV1,
    VerificationSigningRequestV1,
    attestation_payload_hash,
    builder_attestation_payload,
    digest_text,
    stable_identifier,
    verification_attestation_payload,
    verification_gateway_attestation_payload,
)
from autolean_control_plane import (
    ArtifactStore,
    ControlPlane,
    EventStore,
    LeaseStore,
    VerificationSigningGatewayRejected,
    VerificationSigningGatewayReplay,
    VerificationSigningGatewayUnavailable,
    VerifierSigningGateway,
)
from autolean_control_plane.errors import InvalidTransition
from autolean_prover.errors import ValidationError
from autolean_prover.execution import (
    ElaboratedTypeEvidence,
    LeanRunEvidence,
    OciExecutionEvidence,
    WorkspaceMaterializer,
)
from autolean_prover.verification import TrustedLeanVerifier, VerificationObservation
from autolean_prover.verification_attestation import (
    attest_oci_observation,
    prepare_oci_verification_evidence,
)
from autolean_prover.verification_gateway import (
    attest_oci_observation_via_gateway,
    build_verification_signing_request,
)

from .helpers import frozen_bundle, stable_id

_BUILDER_KEY = HmacAttestationKeyV1(
    key_id="builder-attestation-test-v1",
    secret=b"builder-attestation-test-secret-0123456789",
    allowed_purposes=frozenset({AttestationPurposeV1.BUILDER_FREEZE}),
)
_VERIFIER_KEY = HmacAttestationKeyV1(
    key_id="verifier-attestation-test-v1",
    secret=b"verifier-attestation-test-secret-012345678",
    allowed_purposes=frozenset({AttestationPurposeV1.VERIFICATION}),
)


def _submission(bundle) -> ProofSubmissionV1:
    proof = "by\n  rfl"
    return ProofSubmissionV1(
        proof_id=stable_id("attested-proof"),
        contract_id=bundle.contract.contract_id,
        revision=bundle.contract.revision,
        contract_hash=bundle.contract.semantic_hash(),
        proof_boundary_hash=bundle.proof_boundary.boundary_hash,
        proof_source=proof,
        proof_source_hash=digest_text(HashKindV1.PROOF_SOURCE, proof),
        environment_hash=bundle.contract.formal.environment.environment_hash,
    )


@dataclass(frozen=True)
class OciReportingRunner:
    """A fake runtime that returns an OCI-shaped observation without running Docker or Lean."""

    def run(self, candidate: Path, *, workspace) -> LeanRunEvidence:
        environment = workspace.bundle.contract.formal.environment
        canonical_type = workspace.bundle.contract.formal.elaborated_type
        assert canonical_type is not None
        evidence = OciExecutionEvidence(
            worker_image="registry.invalid/autolean-lean@sha256:" + "a" * 64,
            worker_image_digest="sha256:" + "a" * 64,
            environment_hash=environment.environment_hash.value,
            lean_version=environment.lean_version,
            mathlib_revision=environment.mathlib_revision,
            lake_manifest_hash=(
                None
                if environment.lake_manifest_hash is None
                else environment.lake_manifest_hash.value
            ),
            wrapper_protocol="autolean.oci-lean-wrapper.v1",
            command_policy_hash=(environment.verifier_execution_policy.command_policy_hash().value),
            command_hash="b" * 64,
            candidate_sha256=hashlib.sha256(candidate.read_bytes()).hexdigest(),
            trusted_statement_sha256=workspace.bundle.proof_boundary.trusted_statement_hash.value,
            bundle_manifest_sha256=workspace.bundle.proof_boundary.solver_manifest_hash.value,
        )
        return LeanRunEvidence(
            returncode=0,
            timed_out=False,
            stdout="axioms: []\n",
            stderr="",
            clean_environment=True,
            observed_axioms=(),
            elaborated_type_evidence=ElaboratedTypeEvidence(
                declaration=workspace.candidate_declaration(),
                canonical_type=canonical_type,
            ),
            oci_execution_evidence=evidence,
        )


def _observation(tmp_path: Path, bundle, submission: ProofSubmissionV1) -> VerificationObservation:
    workspace = WorkspaceMaterializer().materialize(bundle, tmp_path / "attempt")
    observation = TrustedLeanVerifier(
        runner=OciReportingRunner(),
        verifier_id="test-oci-verifier",
    ).observe(workspace, submission)
    assert observation.report.kernel_passed
    assert observation.oci_execution_evidence is not None
    return observation


def _artifact_sink(store: ArtifactStore):
    def store_payload(payload: Mapping[str, object]) -> str:
        return store.put_json(dict(payload)).digest

    return store_payload


def _signed_bundle():
    unsigned = frozen_bundle()
    attestation = HmacAttestationSignerV1(_BUILDER_KEY).issue(
        purpose=AttestationPurposeV1.BUILDER_FREEZE,
        payload=builder_attestation_payload(unsigned),
        evidence_identity="builder-freeze-fixture",
        ttl_seconds=3600,
    )
    return unsigned.model_copy(update={"builder_attestation": attestation})


def test_oci_observation_becomes_a_signed_sanitized_evidence_artifact(tmp_path: Path) -> None:
    bundle = frozen_bundle()
    submission = _submission(bundle)
    observation = _observation(tmp_path, bundle, submission)
    store = ArtifactStore(tmp_path / "artifacts")

    report = attest_oci_observation(
        observation,
        bundle=bundle,
        submission=submission,
        proof_submission_artifact_digest="c" * 64,
        artifact_sink=_artifact_sink(store),
        signer=HmacAttestationSignerV1(_VERIFIER_KEY),
    )

    assert report.evidence is not None
    assert report.verifier_attestation is not None
    assert report.evidence.worker_image_digest == "sha256:" + "a" * 64
    assert store.exists(report.evidence.evidence_artifact_digest)
    serialized = store.get_bytes(report.evidence.evidence_artifact_digest).decode("utf-8")
    payload = json.loads(serialized)
    assert payload["schema_version"] == "autolean.verification-evidence-artifact.v1"
    assert payload["oci"]["candidate_sha256"] == observation.oci_execution_evidence.candidate_sha256
    assert payload["oci"]["wrapper_protocol"] == "autolean.oci-lean-wrapper.v1"
    assert payload["oci"]["command_policy_hash"]["value"] == (
        bundle.contract.formal.environment.verifier_execution_policy.command_policy_hash().value
    )
    assert submission.proof_source not in serialized
    assert "proof_source" not in serialized
    assert "Candidate.lean" not in serialized

    HmacAttestationVerifierV1({_VERIFIER_KEY.key_id: _VERIFIER_KEY}).verify(
        report.verifier_attestation,
        expected_purpose=AttestationPurposeV1.VERIFICATION,
        payload=verification_attestation_payload(
            bundle_id=bundle.bundle_id.value,
            bundle_hash=bundle.handoff_hash().value,
            proof_submission_artifact_digest="c" * 64,
            contract_id=bundle.contract.contract_id.value,
            revision=bundle.contract.revision,
            contract_hash=report.contract_hash,
            proof_boundary_hash=report.proof_boundary_hash,
            environment_hash=report.environment_hash,
            report=report,
        ),
    )


def test_attestation_rejects_an_oci_record_for_a_different_candidate_before_storage(
    tmp_path: Path,
) -> None:
    bundle = frozen_bundle()
    submission = _submission(bundle)
    observation = _observation(tmp_path, bundle, submission)
    execution = observation.oci_execution_evidence
    assert execution is not None
    mismatched = replace(execution, candidate_sha256="0" * 64)
    called = False

    def should_not_store(_payload: Mapping[str, object]) -> str:
        nonlocal called
        called = True
        return "d" * 64

    with pytest.raises(ValidationError, match="oci_candidate_mismatch"):
        attest_oci_observation(
            replace(observation, oci_execution_evidence=mismatched),
            bundle=bundle,
            submission=submission,
            proof_submission_artifact_digest="c" * 64,
            artifact_sink=should_not_store,
            signer=HmacAttestationSignerV1(_VERIFIER_KEY),
        )
    assert not called


def test_attestation_rejects_oci_facts_outside_the_frozen_execution_policy(
    tmp_path: Path,
) -> None:
    bundle = frozen_bundle()
    submission = _submission(bundle)
    observation = _observation(tmp_path, bundle, submission)
    execution = observation.oci_execution_evidence
    assert execution is not None
    called = False

    def should_not_store(_payload: Mapping[str, object]) -> str:
        nonlocal called
        called = True
        return "d" * 64

    wrong_image = replace(
        execution,
        worker_image="registry.invalid/autolean-lean@sha256:" + ("f" * 64),
        worker_image_digest="sha256:" + ("f" * 64),
    )
    with pytest.raises(ValidationError, match="oci_worker_image_policy_mismatch"):
        attest_oci_observation(
            replace(observation, oci_execution_evidence=wrong_image),
            bundle=bundle,
            submission=submission,
            proof_submission_artifact_digest="c" * 64,
            artifact_sink=should_not_store,
            signer=HmacAttestationSignerV1(_VERIFIER_KEY),
        )

    wrong_wrapper = replace(
        execution,
        wrapper_protocol="autolean.oci-lean-wrapper.v0",
    )
    with pytest.raises(ValidationError, match="oci_wrapper_policy_mismatch"):
        attest_oci_observation(
            replace(observation, oci_execution_evidence=wrong_wrapper),
            bundle=bundle,
            submission=submission,
            proof_submission_artifact_digest="c" * 64,
            artifact_sink=should_not_store,
            signer=HmacAttestationSignerV1(_VERIFIER_KEY),
        )

    wrong_command = replace(execution, command_policy_hash="0" * 64)
    with pytest.raises(ValidationError, match="oci_command_policy_mismatch"):
        attest_oci_observation(
            replace(observation, oci_execution_evidence=wrong_command),
            bundle=bundle,
            submission=submission,
            proof_submission_artifact_digest="c" * 64,
            artifact_sink=should_not_store,
            signer=HmacAttestationSignerV1(_VERIFIER_KEY),
        )
    assert not called


def test_control_plane_accepts_a_report_from_the_prover_attestation_adapter(tmp_path: Path) -> None:
    bundle = _signed_bundle()
    database = tmp_path / "control.db"
    plane = ControlPlane(
        events=EventStore(database),
        leases=LeaseStore(database),
        artifacts=ArtifactStore(tmp_path / "control-artifacts"),
        attestation_verifier=HmacAttestationVerifierV1(
            {
                _BUILDER_KEY.key_id: _BUILDER_KEY,
                _VERIFIER_KEY.key_id: _VERIFIER_KEY,
            }
        ),
        allow_test_only_unreviewed_bundles=True,
    )
    plane.register_bundle(bundle, idempotency_key="register")
    receipt = plane.claim(
        bundle.bundle_id.value,
        worker_id="test-worker",
        ttl_seconds=60,
        idempotency_key="claim",
    )
    submission = _submission(bundle)
    proof_event = plane.submit_proof(
        bundle.bundle_id.value,
        lease=receipt.lease,
        submission=submission,
        idempotency_key="submit",
    )
    artifact_payload = proof_event.payload["proof_artifact"]
    assert isinstance(artifact_payload, dict)
    proof_artifact_digest = artifact_payload["digest"]
    assert isinstance(proof_artifact_digest, str)
    gateway = VerifierSigningGateway(
        control_plane=plane,
        signer=HmacAttestationSignerV1(_VERIFIER_KEY),
        verifier=HmacAttestationVerifierV1({_VERIFIER_KEY.key_id: _VERIFIER_KEY}),
    )
    report = attest_oci_observation_via_gateway(
        _observation(tmp_path / "observation", bundle, submission),
        bundle=bundle,
        submission=submission,
        proof_submission_artifact_digest=proof_artifact_digest,
        artifact_sink=_artifact_sink(plane.artifacts),
        lease=VerificationSigningLeaseBindingV1(
            bundle_id=bundle.bundle_id,
            worker_id=receipt.lease.holder_id,
            fencing_token=receipt.lease.fencing_token,
            expires_at=receipt.lease.expires_at,
        ),
        gateway_client=gateway,
        idempotency_key="gateway-verify",
        ttl_seconds=30,
    )

    outcome = plane.verify_submission(
        bundle.bundle_id.value,
        lease=receipt.lease,
        report=report,
        idempotency_key="verify",
    )

    assert outcome.accepted


def _gateway_fixture(tmp_path: Path):
    bundle = _signed_bundle()
    database = tmp_path / "control.db"
    verifier = HmacAttestationVerifierV1(
        {
            _BUILDER_KEY.key_id: _BUILDER_KEY,
            _VERIFIER_KEY.key_id: _VERIFIER_KEY,
        }
    )
    plane = ControlPlane(
        events=EventStore(database),
        leases=LeaseStore(database),
        artifacts=ArtifactStore(tmp_path / "artifacts"),
        attestation_verifier=verifier,
        allow_test_only_unreviewed_bundles=True,
    )
    plane.register_bundle(bundle, idempotency_key="register")
    receipt = plane.claim(
        bundle.bundle_id.value,
        worker_id="gateway-worker",
        ttl_seconds=60,
        idempotency_key="claim",
    )
    submission = _submission(bundle)
    proof_event = plane.submit_proof(
        bundle.bundle_id.value,
        lease=receipt.lease,
        submission=submission,
        idempotency_key="submit",
    )
    proof_artifact = proof_event.payload["proof_artifact"]
    assert isinstance(proof_artifact, dict)
    proof_digest = proof_artifact["digest"]
    assert isinstance(proof_digest, str)
    unsigned = prepare_oci_verification_evidence(
        _observation(tmp_path / "observation", bundle, submission),
        bundle=bundle,
        submission=submission,
        proof_submission_artifact_digest=proof_digest,
        artifact_sink=_artifact_sink(plane.artifacts),
    )
    lease_binding = VerificationSigningLeaseBindingV1(
        bundle_id=bundle.bundle_id,
        worker_id=receipt.lease.holder_id,
        fencing_token=receipt.lease.fencing_token,
        expires_at=receipt.lease.expires_at,
    )
    request = build_verification_signing_request(
        unsigned,
        bundle=bundle,
        submission=submission,
        proof_submission_artifact_digest=proof_digest,
        lease=lease_binding,
        idempotency_key="gateway-request",
        ttl_seconds=30,
        request_nonce="gateway-request-nonce-0001",
    )
    gateway = VerifierSigningGateway(
        control_plane=plane,
        signer=HmacAttestationSignerV1(_VERIFIER_KEY),
        verifier=verifier,
    )
    return plane, gateway, bundle, receipt, submission, proof_digest, unsigned, request


def test_gateway_request_and_ledger_never_serialize_signing_key_or_proof(
    tmp_path: Path,
) -> None:
    plane, gateway, _bundle, _receipt, submission, _proof_digest, _unsigned, request = (
        _gateway_fixture(tmp_path)
    )
    serialized = request.model_dump_json()
    assert submission.proof_source not in serialized
    assert "proof_source" not in serialized
    assert "Candidate.lean" not in serialized
    assert "secret" not in serialized.lower()

    gateway.issue(request)

    database_bytes = plane.events.path.read_bytes()
    assert _VERIFIER_KEY.secret not in database_bytes
    with sqlite3.connect(plane.events.path) as connection:
        row = connection.execute(
            """
            SELECT request_hash, canonical_payload_hash, evidence_artifact_digest, state
            FROM verifier_signing_requests
            """
        ).fetchone()
    assert row is not None
    assert row[3] == "issued"


def test_gateway_is_idempotent_for_exact_retry_and_rejects_payload_reissue(
    tmp_path: Path,
) -> None:
    plane, gateway, _bundle, _receipt, _submission, _digest, _unsigned, request = _gateway_fixture(
        tmp_path
    )
    first = gateway.issue(request)
    assert gateway.issue(request) == first
    restarted = VerifierSigningGateway(
        control_plane=plane,
        signer=HmacAttestationSignerV1(_VERIFIER_KEY),
        verifier=HmacAttestationVerifierV1({_VERIFIER_KEY.key_id: _VERIFIER_KEY}),
    )
    assert restarted.issue(request) == first

    replay = request.model_copy(
        update={
            "request_id": stable_identifier("verification-signing-request", "replay"),
            "request_nonce": "gateway-request-nonce-0002",
            "idempotency_key": "gateway-request-replay",
        }
    )
    with pytest.raises(VerificationSigningGatewayReplay):
        restarted.issue(replay)


def test_gateway_rejects_stale_fence_and_context_mismatch_before_signing(
    tmp_path: Path,
) -> None:
    plane, gateway, bundle, receipt, _submission, _digest, _unsigned, request = _gateway_fixture(
        tmp_path
    )
    plane.leases.release(receipt.lease)
    replacement = plane.leases.claim(bundle.bundle_id.value, "replacement-worker", ttl_seconds=60)
    assert replacement.fencing_token > receipt.lease.fencing_token
    with pytest.raises(VerificationSigningGatewayRejected, match="lease"):
        gateway.issue(request)

    replacement_lease = VerificationSigningLeaseBindingV1(
        bundle_id=bundle.bundle_id,
        worker_id=replacement.holder_id,
        fencing_token=replacement.fencing_token,
        expires_at=replacement.expires_at,
    )
    wrong_context = request.context.model_copy(
        update={"bundle_hash": digest_text(HashKindV1.BUNDLE, "different-bundle")}
    )
    wrong_payload = verification_gateway_attestation_payload(
        lease=replacement_lease,
        context=wrong_context,
    )
    mismatched = VerificationSigningRequestV1(
        request_id=stable_identifier("verification-signing-request", "mismatch"),
        request_nonce="gateway-request-nonce-0003",
        idempotency_key="gateway-request-mismatch",
        requested_at=datetime.now(UTC),
        expires_at=min(
            datetime.now(UTC) + timedelta(seconds=30),
            replacement.expires_at,
        ),
        lease=replacement_lease,
        context=wrong_context,
        canonical_payload_hash=attestation_payload_hash(
            AttestationPurposeV1.VERIFICATION,
            wrong_payload,
        ),
    )
    with pytest.raises(VerificationSigningGatewayRejected, match="bundle hash"):
        gateway.issue(mismatched)


def test_gateway_request_expiry_and_unavailable_client_fail_closed(tmp_path: Path) -> None:
    _plane, gateway, bundle, receipt, submission, digest, unsigned, request = _gateway_fixture(
        tmp_path
    )
    expired_at = datetime.now(UTC) - timedelta(minutes=2)
    expired = request.model_copy(
        update={
            "request_id": stable_identifier("verification-signing-request", "expired"),
            "request_nonce": "gateway-request-nonce-0004",
            "idempotency_key": "gateway-request-expired",
            "requested_at": expired_at,
            "expires_at": expired_at + timedelta(seconds=30),
        }
    )
    with pytest.raises(VerificationSigningGatewayRejected, match="expired"):
        gateway.issue(expired)

    class UnavailableClient:
        def issue(self, _request: VerificationSigningRequestV1):
            raise ConnectionError("gateway unavailable")

    lease_binding = VerificationSigningLeaseBindingV1(
        bundle_id=bundle.bundle_id,
        worker_id=receipt.lease.holder_id,
        fencing_token=receipt.lease.fencing_token,
        expires_at=receipt.lease.expires_at,
    )
    with pytest.raises(ValidationError, match="verification_gateway_unavailable"):
        attest_oci_observation_via_gateway(
            _observation(tmp_path / "second-observation", bundle, submission),
            bundle=bundle,
            submission=submission,
            proof_submission_artifact_digest=digest,
            artifact_sink=_artifact_sink(_plane.artifacts),
            lease=lease_binding,
            gateway_client=UnavailableClient(),
            idempotency_key="unavailable-client",
            ttl_seconds=30,
        )
    assert unsigned.verifier_attestation is None


def test_gateway_rejects_evidence_digest_substitution_and_signer_outage(
    tmp_path: Path,
) -> None:
    plane, _gateway, _bundle, _receipt, _submission, _digest, _unsigned, request = _gateway_fixture(
        tmp_path
    )
    wrong_context = request.context.model_copy(update={"evidence_artifact_digest": "f" * 64})
    wrong_payload = verification_gateway_attestation_payload(
        lease=request.lease,
        context=wrong_context,
    )
    substituted = request.model_copy(
        update={
            "request_id": stable_identifier("verification-signing-request", "bad-evidence"),
            "request_nonce": "gateway-request-nonce-0005",
            "idempotency_key": "gateway-request-bad-evidence",
            "context": wrong_context,
            "canonical_payload_hash": attestation_payload_hash(
                AttestationPurposeV1.VERIFICATION,
                wrong_payload,
            ),
        }
    )
    verifier = HmacAttestationVerifierV1({_VERIFIER_KEY.key_id: _VERIFIER_KEY})
    gateway = VerifierSigningGateway(
        control_plane=plane,
        signer=HmacAttestationSignerV1(_VERIFIER_KEY),
        verifier=verifier,
    )
    with pytest.raises(VerificationSigningGatewayRejected, match="unavailable or corrupt"):
        gateway.issue(substituted)

    class UnavailableSigner:
        def issue(self, **_kwargs):
            raise RuntimeError("sensitive remote signer detail")

    unavailable_gateway = VerifierSigningGateway(
        control_plane=plane,
        signer=UnavailableSigner(),
        verifier=verifier,
    )
    with pytest.raises(VerificationSigningGatewayUnavailable, match="unavailable"):
        unavailable_gateway.issue(request)
    with sqlite3.connect(plane.events.path) as connection:
        row = connection.execute(
            """
            SELECT state, failure_code, attestation_json
            FROM verifier_signing_requests
            WHERE request_id = ?
            """,
            (request.request_id.value,),
        ).fetchone()
    assert row == ("failed", "signer_unavailable", None)
    assert b"sensitive remote signer detail" not in plane.events.path.read_bytes()


def test_control_plane_rejects_direct_hmac_and_old_gateway_fence_by_default(
    tmp_path: Path,
) -> None:
    plane, gateway, bundle, receipt, _submission, digest, unsigned, request = _gateway_fixture(
        tmp_path
    )
    direct = unsigned.model_copy(
        update={
            "verifier_attestation": HmacAttestationSignerV1(_VERIFIER_KEY).issue(
                purpose=AttestationPurposeV1.VERIFICATION,
                payload=verification_attestation_payload(
                    bundle_id=bundle.bundle_id.value,
                    bundle_hash=bundle.handoff_hash().value,
                    proof_submission_artifact_digest=digest,
                    contract_id=bundle.contract.contract_id.value,
                    revision=bundle.contract.revision,
                    contract_hash=unsigned.contract_hash,
                    proof_boundary_hash=unsigned.proof_boundary_hash,
                    environment_hash=unsigned.environment_hash,
                    report=unsigned,
                ),
                evidence_identity=unsigned.evidence.evidence_id.value,
                ttl_seconds=30,
            )
        }
    )
    with pytest.raises(InvalidTransition, match="lease-bound"):
        plane.verify_submission(
            bundle.bundle_id.value,
            lease=receipt.lease,
            report=direct,
            idempotency_key="direct-hmac-rejected",
        )

    gateway_report = unsigned.model_copy(update={"verifier_attestation": gateway.issue(request)})
    plane.leases.release(receipt.lease)
    replacement = plane.leases.claim(bundle.bundle_id.value, "replacement-worker", ttl_seconds=60)
    with pytest.raises(InvalidTransition, match="lease-bound"):
        plane.verify_submission(
            bundle.bundle_id.value,
            lease=replacement,
            report=gateway_report,
            idempotency_key="old-fence-rejected",
        )
