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
    VerificationEvidenceArtifactV2,
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
    FixtureHmacIndependentExecutionReceiptAuthenticator,
    IndependentExecutionClassV1,
    IndependentExecutionReceiptAuthenticationV1,
    IndependentExecutionReceiptV1,
    IndependentExecutionTrustPolicyV1,
    IndependentExecutionVerifier,
    LeaseStore,
    ProductionAuthorityUnavailable,
    TrustedIndependentExecutionVerifierV1,
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
_WORKER_IMAGE_DIGEST = "sha256:" + "a" * 64
_WRAPPER_IDENTITY_HASH = "d" * 64
_FIXTURE_INDEPENDENT_VERIFIER_ID = "test-only-oci-reporting-verifier"
_INDEPENDENT_RECEIPT_AUTHENTICATOR = FixtureHmacIndependentExecutionReceiptAuthenticator(
    key_id="test-only-independent-execution-v1",
    secret=b"test-only-independent-execution-receipt-key-0123456789",
)


def _test_execution_trust_policy() -> IndependentExecutionTrustPolicyV1:
    return IndependentExecutionTrustPolicyV1(
        gateway_signing_key_id=_VERIFIER_KEY.key_id,
        execution_class=IndependentExecutionClassV1.TEST_ONLY,
        trusted_verifiers={
            _FIXTURE_INDEPENDENT_VERIFIER_ID: TrustedIndependentExecutionVerifierV1(
                verifier_id=_FIXTURE_INDEPENDENT_VERIFIER_ID,
                authentication_key_id=_INDEPENDENT_RECEIPT_AUTHENTICATOR.key_id,
                execution_class=IndependentExecutionClassV1.TEST_ONLY,
                authenticator=_INDEPENDENT_RECEIPT_AUTHENTICATOR,
            )
        },
    )


class FixtureOciReportingExecutionVerifier(IndependentExecutionVerifier):
    """Explicit allowlist bridge for the non-executing OciReportingRunner fixture only."""

    def __init__(self, allowed_verifier_ids: frozenset[str] | None = None) -> None:
        self.allowed_verifier_ids = allowed_verifier_ids or frozenset({"test-oci-verifier"})
        self.calls = 0

    def verify(
        self,
        *,
        request: VerificationSigningRequestV1,
        artifact: VerificationEvidenceArtifactV2,
    ) -> IndependentExecutionReceiptV1:
        self.calls += 1
        if request.context.verifier_id not in self.allowed_verifier_ids:
            raise RuntimeError("test-only verifier ID is not explicitly allowlisted")
        receipt = IndependentExecutionReceiptV1.create(
            receipt_id=f"test-only-receipt-{self.calls}",
            verifier_id=_FIXTURE_INDEPENDENT_VERIFIER_ID,
            checked_at=datetime.now(UTC),
            request_hash=request.request_hash().value,
            evidence_artifact_digest=request.context.evidence_artifact_digest,
            evidence_digest=request.context.verification_evidence_hash.value,
            execution_claim_hash=artifact.oci.execution_authority.execution_claim_hash,
        )
        return _INDEPENDENT_RECEIPT_AUTHENTICATOR.authenticate(receipt)


def _test_execution_verifier() -> FixtureOciReportingExecutionVerifier:
    return FixtureOciReportingExecutionVerifier()


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

    execution_lease: VerificationSigningLeaseBindingV1 | None = None

    def run(self, candidate: Path, *, workspace) -> LeanRunEvidence:
        environment = workspace.bundle.contract.formal.environment
        canonical_type = workspace.bundle.contract.formal.elaborated_type
        assert canonical_type is not None
        authority: dict[str, object] = {}
        if self.execution_lease is not None:
            authority = {
                "authority_status": "lease-bound-pending-gateway",
                "execution_claim_hash": "e" * 64,
                "lease_worker_id": self.execution_lease.worker_id,
                "lease_fencing_token": self.execution_lease.fencing_token,
                "lease_expires_at": self.execution_lease.expires_at,
                "wrapper_identity_hash": _WRAPPER_IDENTITY_HASH,
            }
        compile_command_hash = "c" * 64
        query_command_hash = "d" * 64
        sealed_candidate_sha256 = "f" * 64
        command_hash = hashlib.sha256(
            json.dumps(
                {
                    "schema_version": "autolean.oci-command-transcript.v2",
                    "handoff_protocol": "autolean.oci-compile-query-handoff.v1",
                    "compile_command_hash": compile_command_hash,
                    "query_command_hash": query_command_hash,
                    "sealed_candidate_sha256": sealed_candidate_sha256,
                },
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        evidence = OciExecutionEvidence(
            worker_image="registry.invalid/autolean-lean@" + _WORKER_IMAGE_DIGEST,
            worker_image_digest=_WORKER_IMAGE_DIGEST,
            environment_hash=environment.environment_hash.value,
            lean_version=environment.lean_version,
            mathlib_revision=environment.mathlib_revision,
            lake_manifest_hash=(
                None
                if environment.lake_manifest_hash is None
                else environment.lake_manifest_hash.value
            ),
            wrapper_protocol="autolean.oci-lean-wrapper.v2",
            command_policy_hash=(environment.verifier_execution_policy.command_policy_hash().value),
            command_hash=command_hash,
            compile_command_hash=compile_command_hash,
            query_command_hash=query_command_hash,
            sealed_candidate_sha256=sealed_candidate_sha256,
            candidate_sha256=hashlib.sha256(candidate.read_bytes()).hexdigest(),
            trusted_statement_sha256=workspace.bundle.proof_boundary.trusted_statement_hash.value,
            bundle_manifest_sha256=workspace.bundle.proof_boundary.solver_manifest_hash.value,
            **authority,
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


def _observation(
    tmp_path: Path,
    bundle,
    submission: ProofSubmissionV1,
    *,
    execution_lease: VerificationSigningLeaseBindingV1 | None = None,
) -> VerificationObservation:
    workspace = WorkspaceMaterializer().materialize(bundle, tmp_path / "attempt")
    observation = TrustedLeanVerifier(
        runner=OciReportingRunner(execution_lease=execution_lease),
        verifier_id="test-oci-verifier",
    ).observe(workspace, submission)
    assert observation.report.kernel_passed
    assert observation.oci_execution_evidence is not None
    return observation


def _artifact_sink(store: ArtifactStore):
    def store_payload(payload: Mapping[str, object]) -> str:
        return store.put_json(dict(payload)).digest

    return store_payload


def _identity_registry() -> dict[str, str]:
    return {_WORKER_IMAGE_DIGEST: _WRAPPER_IDENTITY_HASH}


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
    assert payload["oci"]["wrapper_protocol"] == "autolean.oci-lean-wrapper.v2"
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


def test_attestation_rejects_v1_policy_without_storing_evidence(tmp_path: Path) -> None:
    bundle = frozen_bundle(execution_policy_version="1.0")
    submission = _submission(bundle)
    observation = _observation(tmp_path, bundle, submission)
    called = False

    def should_not_store(_payload: Mapping[str, object]) -> str:
        nonlocal called
        called = True
        return "d" * 64

    with pytest.raises(ValidationError, match="oci_execution_policy_version_unsupported"):
        prepare_oci_verification_evidence(
            observation,
            bundle=bundle,
            submission=submission,
            proof_submission_artifact_digest="c" * 64,
            artifact_sink=should_not_store,
        )

    assert not called


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
        wrapper_protocol="autolean.oci-lean-wrapper.v1",
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

    wrong_transcript = replace(execution, command_hash="0" * 64)
    with pytest.raises(ValidationError, match="oci_command_transcript_mismatch"):
        attest_oci_observation(
            replace(observation, oci_execution_evidence=wrong_transcript),
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
        independent_execution_verifier=_test_execution_verifier(),
        independent_execution_trust_policy=_test_execution_trust_policy(),
        approved_image_identities=_identity_registry(),
    )
    lease_binding = VerificationSigningLeaseBindingV1(
        bundle_id=bundle.bundle_id,
        worker_id=receipt.lease.holder_id,
        fencing_token=receipt.lease.fencing_token,
        expires_at=receipt.lease.expires_at,
    )
    report = attest_oci_observation_via_gateway(
        _observation(
            tmp_path / "observation",
            bundle,
            submission,
            execution_lease=lease_binding,
        ),
        bundle=bundle,
        submission=submission,
        proof_submission_artifact_digest=proof_artifact_digest,
        artifact_sink=_artifact_sink(plane.artifacts),
        lease=lease_binding,
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
    assert outcome.promotion_state == "not_a_promotion"
    assert outcome.execution_authority_class == "test-only-local"
    assert outcome.event.payload["promotion_state"] == "not_a_promotion"
    with pytest.raises(InvalidTransition, match="promotion authority"):
        ControlPlane._verification_outcome_from_event(
            replace(
                outcome.event,
                payload={**outcome.event.payload, "promotion_state": "promotion-authorized"},
            )
        )
    assert report.evidence is not None
    artifact = json.loads(
        plane.artifacts.get_bytes(report.evidence.evidence_artifact_digest).decode("utf-8")
    )
    assert artifact["schema_version"] == "autolean.verification-evidence-artifact.v2"
    assert artifact["oci"]["execution_authority"]["fencing_token"] == receipt.lease.fencing_token
    assert artifact["oci"]["execution_authority"]["wrapper_identity_hash"] == _WRAPPER_IDENTITY_HASH


def test_gateway_adapter_rejects_non_authoritative_execution_before_storage(
    tmp_path: Path,
) -> None:
    bundle = frozen_bundle()
    submission = _submission(bundle)
    stored: list[Mapping[str, object]] = []

    class UnexpectedGateway:
        def issue(self, _request: VerificationSigningRequestV1):
            raise AssertionError("non-authoritative evidence reached the signing gateway")

    with pytest.raises(ValidationError, match="execution_authority"):
        attest_oci_observation_via_gateway(
            _observation(tmp_path / "observation", bundle, submission),
            bundle=bundle,
            submission=submission,
            proof_submission_artifact_digest="c" * 64,
            artifact_sink=lambda payload: stored.append(payload) or "f" * 64,
            lease=VerificationSigningLeaseBindingV1(
                bundle_id=bundle.bundle_id,
                worker_id="worker",
                fencing_token=1,
                expires_at=datetime.now(UTC) + timedelta(minutes=1),
            ),
            gateway_client=UnexpectedGateway(),
            idempotency_key="must-not-sign",
        )
    assert stored == []


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
    lease_binding = VerificationSigningLeaseBindingV1(
        bundle_id=bundle.bundle_id,
        worker_id=receipt.lease.holder_id,
        fencing_token=receipt.lease.fencing_token,
        expires_at=receipt.lease.expires_at,
    )
    unsigned = prepare_oci_verification_evidence(
        _observation(
            tmp_path / "observation",
            bundle,
            submission,
            execution_lease=lease_binding,
        ),
        bundle=bundle,
        submission=submission,
        proof_submission_artifact_digest=proof_digest,
        artifact_sink=_artifact_sink(plane.artifacts),
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
        independent_execution_verifier=_test_execution_verifier(),
        independent_execution_trust_policy=_test_execution_trust_policy(),
        approved_image_identities=_identity_registry(),
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
    assert _INDEPENDENT_RECEIPT_AUTHENTICATOR.secret not in database_bytes
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
        independent_execution_verifier=_test_execution_verifier(),
        independent_execution_trust_policy=_test_execution_trust_policy(),
        approved_image_identities=_identity_registry(),
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


def test_gateway_requires_an_explicit_independent_execution_verifier(tmp_path: Path) -> None:
    (
        plane,
        _gateway,
        _bundle,
        _receipt,
        _submission,
        _digest,
        _unsigned,
        _request,
    ) = _gateway_fixture(tmp_path)
    with pytest.raises(TypeError, match="independent_execution_verifier"):
        VerifierSigningGateway(  # type: ignore[call-arg]
            control_plane=plane,
            signer=HmacAttestationSignerV1(_VERIFIER_KEY),
            verifier=HmacAttestationVerifierV1({_VERIFIER_KEY.key_id: _VERIFIER_KEY}),
            approved_image_identities=_identity_registry(),
        )
    with pytest.raises(TypeError, match="independent_execution_trust_policy"):
        VerifierSigningGateway(  # type: ignore[call-arg]
            control_plane=plane,
            signer=HmacAttestationSignerV1(_VERIFIER_KEY),
            verifier=HmacAttestationVerifierV1({_VERIFIER_KEY.key_id: _VERIFIER_KEY}),
            independent_execution_verifier=_test_execution_verifier(),
            approved_image_identities=_identity_registry(),
        )


def test_gateway_persists_independent_receipt_and_never_reruns_exact_replay(
    tmp_path: Path,
) -> None:
    plane, gateway, _bundle, _receipt, _submission, _digest, _unsigned, request = _gateway_fixture(
        tmp_path
    )
    independent = gateway._independent_execution_verifier
    assert isinstance(independent, FixtureOciReportingExecutionVerifier)

    first = gateway.issue(request)
    assert independent.calls == 1
    assert gateway.issue(request) == first
    assert independent.calls == 1

    with sqlite3.connect(plane.events.path) as connection:
        row = connection.execute(
            """
            SELECT execution_receipt_id, execution_receipt_hash, execution_verifier_id,
                   execution_checked_at, execution_claim_hash,
                   execution_receipt_authentication_key_id,
                   execution_receipt_authentication_algorithm,
                   execution_receipt_authentication_signature
            FROM verifier_signing_requests
            """
        ).fetchone()
    assert row is not None
    assert all(isinstance(value, str) and value for value in row)

    restarted_verifier = _test_execution_verifier()
    restarted = VerifierSigningGateway(
        control_plane=plane,
        signer=HmacAttestationSignerV1(_VERIFIER_KEY),
        verifier=HmacAttestationVerifierV1({_VERIFIER_KEY.key_id: _VERIFIER_KEY}),
        independent_execution_verifier=restarted_verifier,
        independent_execution_trust_policy=_test_execution_trust_policy(),
        approved_image_identities=_identity_registry(),
    )
    assert restarted.issue(request) == first
    assert restarted_verifier.calls == 0

    with sqlite3.connect(plane.events.path) as connection:
        connection.execute(
            """
            UPDATE verifier_signing_requests
            SET execution_receipt_authentication_key_id = NULL,
                execution_receipt_authentication_algorithm = NULL,
                execution_receipt_authentication_signature = NULL
            """
        )
        connection.commit()
    with pytest.raises(VerificationSigningGatewayUnavailable, match="execution receipt"):
        restarted.issue(request)
    assert restarted_verifier.calls == 0


def test_gateway_rejects_forged_untrusted_or_tampered_receipt_authentication(
    tmp_path: Path,
) -> None:
    plane, _gateway, _bundle, _receipt, _submission, _digest, _unsigned, request = _gateway_fixture(
        tmp_path
    )

    class ForgedVerifier:
        def verify(
            self,
            *,
            request: VerificationSigningRequestV1,
            artifact: VerificationEvidenceArtifactV2,
        ) -> IndependentExecutionReceiptV1:
            receipt = IndependentExecutionReceiptV1.create(
                receipt_id="forged-receipt",
                verifier_id=_FIXTURE_INDEPENDENT_VERIFIER_ID,
                checked_at=datetime.now(UTC),
                request_hash=request.request_hash().value,
                evidence_artifact_digest=request.context.evidence_artifact_digest,
                evidence_digest=request.context.verification_evidence_hash.value,
                execution_claim_hash=artifact.oci.execution_authority.execution_claim_hash,
            )
            return replace(
                receipt,
                authentication=IndependentExecutionReceiptAuthenticationV1(
                    key_id=_INDEPENDENT_RECEIPT_AUTHENTICATOR.key_id,
                    algorithm="hmac-sha256-test-v1",
                    authenticated_receipt_hash=receipt.receipt_hash,
                    signature="0" * 64,
                ),
            )

    class UnknownIdentityVerifier:
        def verify(
            self,
            *,
            request: VerificationSigningRequestV1,
            artifact: VerificationEvidenceArtifactV2,
        ) -> IndependentExecutionReceiptV1:
            receipt = IndependentExecutionReceiptV1.create(
                receipt_id="unknown-identity-receipt",
                verifier_id="forged-independent-verifier",
                checked_at=datetime.now(UTC),
                request_hash=request.request_hash().value,
                evidence_artifact_digest=request.context.evidence_artifact_digest,
                evidence_digest=request.context.verification_evidence_hash.value,
                execution_claim_hash=artifact.oci.execution_authority.execution_claim_hash,
            )
            return _INDEPENDENT_RECEIPT_AUTHENTICATOR.authenticate(receipt)

    class TamperedReceiptVerifier:
        def verify(
            self,
            *,
            request: VerificationSigningRequestV1,
            artifact: VerificationEvidenceArtifactV2,
        ) -> IndependentExecutionReceiptV1:
            receipt = IndependentExecutionReceiptV1.create(
                receipt_id="tampered-receipt",
                verifier_id=_FIXTURE_INDEPENDENT_VERIFIER_ID,
                checked_at=datetime.now(UTC),
                request_hash=request.request_hash().value,
                evidence_artifact_digest=request.context.evidence_artifact_digest,
                evidence_digest=request.context.verification_evidence_hash.value,
                execution_claim_hash=artifact.oci.execution_authority.execution_claim_hash,
            )
            signed = _INDEPENDENT_RECEIPT_AUTHENTICATOR.authenticate(receipt)
            return replace(signed, execution_claim_hash="0" * 64)

    for verifier in (ForgedVerifier(), UnknownIdentityVerifier(), TamperedReceiptVerifier()):
        gateway = VerifierSigningGateway(
            control_plane=plane,
            signer=HmacAttestationSignerV1(_VERIFIER_KEY),
            verifier=HmacAttestationVerifierV1({_VERIFIER_KEY.key_id: _VERIFIER_KEY}),
            independent_execution_verifier=verifier,
            independent_execution_trust_policy=_test_execution_trust_policy(),
            approved_image_identities=_identity_registry(),
        )
        with pytest.raises(VerificationSigningGatewayRejected, match="receipt"):
            gateway.issue(request)
    with sqlite3.connect(plane.events.path) as connection:
        count = connection.execute("SELECT COUNT(*) FROM verifier_signing_requests").fetchone()
    assert count == (0,)


def test_gateway_rejects_receipt_before_request_or_after_current_time(tmp_path: Path) -> None:
    plane, _gateway, _bundle, _receipt, _submission, _digest, _unsigned, request = _gateway_fixture(
        tmp_path
    )

    class DatedVerifier:
        def __init__(self, checked_at: datetime) -> None:
            self.checked_at = checked_at

        def verify(
            self,
            *,
            request: VerificationSigningRequestV1,
            artifact: VerificationEvidenceArtifactV2,
        ) -> IndependentExecutionReceiptV1:
            receipt = IndependentExecutionReceiptV1.create(
                receipt_id="dated-receipt",
                verifier_id=_FIXTURE_INDEPENDENT_VERIFIER_ID,
                checked_at=self.checked_at,
                request_hash=request.request_hash().value,
                evidence_artifact_digest=request.context.evidence_artifact_digest,
                evidence_digest=request.context.verification_evidence_hash.value,
                execution_claim_hash=artifact.oci.execution_authority.execution_claim_hash,
            )
            return _INDEPENDENT_RECEIPT_AUTHENTICATOR.authenticate(receipt)

    dated_cases = (
        (datetime(2000, 1, 1, tzinfo=UTC), "predates"),
        (datetime.now(UTC) + timedelta(seconds=5), "future"),
    )
    for checked_at, message in dated_cases:
        gateway = VerifierSigningGateway(
            control_plane=plane,
            signer=HmacAttestationSignerV1(_VERIFIER_KEY),
            verifier=HmacAttestationVerifierV1({_VERIFIER_KEY.key_id: _VERIFIER_KEY}),
            independent_execution_verifier=DatedVerifier(checked_at),
            independent_execution_trust_policy=_test_execution_trust_policy(),
            approved_image_identities=_identity_registry(),
        )
        with pytest.raises(VerificationSigningGatewayRejected, match=message):
            gateway.issue(request)
    with sqlite3.connect(plane.events.path) as connection:
        count = connection.execute("SELECT COUNT(*) FROM verifier_signing_requests").fetchone()
    assert count == (0,)


def test_gateway_rejects_shared_key_and_every_local_production_composition(tmp_path: Path) -> None:
    same_key_authenticator = FixtureHmacIndependentExecutionReceiptAuthenticator(
        key_id=_VERIFIER_KEY.key_id,
        secret=b"different-fixture-independent-execution-key-0123456789",
    )
    with pytest.raises(ValueError, match="must differ"):
        IndependentExecutionTrustPolicyV1(
            gateway_signing_key_id=_VERIFIER_KEY.key_id,
            execution_class=IndependentExecutionClassV1.TEST_ONLY,
            trusted_verifiers={
                _FIXTURE_INDEPENDENT_VERIFIER_ID: TrustedIndependentExecutionVerifierV1(
                    verifier_id=_FIXTURE_INDEPENDENT_VERIFIER_ID,
                    authentication_key_id=same_key_authenticator.key_id,
                    execution_class=IndependentExecutionClassV1.TEST_ONLY,
                    authenticator=same_key_authenticator,
                )
            },
        )

    with pytest.raises(ValueError, match="production-class receipt key"):
        IndependentExecutionTrustPolicyV1(
            gateway_signing_key_id="production-gateway-key",
            execution_class=IndependentExecutionClassV1.PRODUCTION,
            trusted_verifiers={
                "production-independent-verifier": TrustedIndependentExecutionVerifierV1(
                    verifier_id="production-independent-verifier",
                    authentication_key_id=_INDEPENDENT_RECEIPT_AUTHENTICATOR.key_id,
                    execution_class=IndependentExecutionClassV1.PRODUCTION,
                    authenticator=_INDEPENDENT_RECEIPT_AUTHENTICATOR,
                )
            },
        )

    class ProductionAuthenticator:
        execution_class = IndependentExecutionClassV1.PRODUCTION

        def verify(self, receipt: IndependentExecutionReceiptV1) -> None:
            del receipt

    class UnmarkedAuthenticator:
        def verify(self, receipt: IndependentExecutionReceiptV1) -> None:
            del receipt

    class UnknownClassAuthenticator:
        execution_class = "production"

        def verify(self, receipt: IndependentExecutionReceiptV1) -> None:
            del receipt

    for authenticator in (UnmarkedAuthenticator(), UnknownClassAuthenticator()):
        with pytest.raises(ValueError, match="production-class receipt key"):
            IndependentExecutionTrustPolicyV1(
                gateway_signing_key_id="production-gateway-key",
                execution_class=IndependentExecutionClassV1.PRODUCTION,
                trusted_verifiers={
                    "production-independent-verifier": TrustedIndependentExecutionVerifierV1(
                        verifier_id="production-independent-verifier",
                        authentication_key_id="production-independent-key",
                        execution_class=IndependentExecutionClassV1.PRODUCTION,
                        authenticator=authenticator,
                    )
                },
            )

    class ForgedProductionVerifier:
        def verify(
            self,
            *,
            request: VerificationSigningRequestV1,
            artifact: VerificationEvidenceArtifactV2,
        ) -> IndependentExecutionReceiptV1:
            raise AssertionError(
                f"production verifier ran: {request.request_id} {artifact.evidence_id}"
            )

    production_policy = IndependentExecutionTrustPolicyV1(
        gateway_signing_key_id="production-gateway-key",
        execution_class=IndependentExecutionClassV1.PRODUCTION,
        trusted_verifiers={
            "production-independent-verifier": TrustedIndependentExecutionVerifierV1(
                verifier_id="production-independent-verifier",
                authentication_key_id="production-independent-key",
                execution_class=IndependentExecutionClassV1.PRODUCTION,
                authenticator=ProductionAuthenticator(),
            )
        },
    )
    (
        plane,
        _gateway,
        _bundle,
        _receipt,
        _submission,
        _digest,
        _unsigned,
        _request,
    ) = _gateway_fixture(tmp_path)
    with pytest.raises(ProductionAuthorityUnavailable, match="remote service"):
        VerifierSigningGateway(
            control_plane=plane,
            signer=HmacAttestationSignerV1(_VERIFIER_KEY),
            verifier=HmacAttestationVerifierV1({_VERIFIER_KEY.key_id: _VERIFIER_KEY}),
            independent_execution_verifier=ForgedProductionVerifier(),
            independent_execution_trust_policy=production_policy,
            approved_image_identities=_identity_registry(),
        )

    production_plane = ControlPlane(
        events=EventStore(tmp_path / "production.db"),
        leases=LeaseStore(tmp_path / "production.db"),
        artifacts=ArtifactStore(tmp_path / "production-artifacts"),
        attestation_verifier=HmacAttestationVerifierV1({_VERIFIER_KEY.key_id: _VERIFIER_KEY}),
    )
    with pytest.raises(ProductionAuthorityUnavailable, match="remote service"):
        VerifierSigningGateway(
            control_plane=production_plane,
            signer=HmacAttestationSignerV1(_VERIFIER_KEY),
            verifier=HmacAttestationVerifierV1({_VERIFIER_KEY.key_id: _VERIFIER_KEY}),
            independent_execution_verifier=ForgedProductionVerifier(),
            independent_execution_trust_policy=production_policy,
            approved_image_identities=_identity_registry(),
        )

    object.__setattr__(
        _gateway._independent_execution_trust_policy,
        "execution_class",
        IndependentExecutionClassV1.PRODUCTION,
    )
    with pytest.raises(ProductionAuthorityUnavailable, match="cannot issue production"):
        _gateway.issue(_request)


def test_gateway_rejects_missing_allowlist_bad_receipt_or_verifier_exception_before_reservation(
    tmp_path: Path,
) -> None:
    plane, _gateway, _bundle, _receipt, _submission, _digest, _unsigned, request = _gateway_fixture(
        tmp_path
    )

    class BadReceiptVerifier:
        def verify(
            self,
            *,
            request: VerificationSigningRequestV1,
            artifact: VerificationEvidenceArtifactV2,
        ) -> IndependentExecutionReceiptV1:
            valid = IndependentExecutionReceiptV1.create(
                receipt_id="bad-receipt",
                verifier_id="bad-receipt-verifier",
                checked_at=datetime.now(UTC),
                request_hash=request.request_hash().value,
                evidence_artifact_digest=request.context.evidence_artifact_digest,
                evidence_digest=request.context.verification_evidence_hash.value,
                execution_claim_hash=artifact.oci.execution_authority.execution_claim_hash,
            )
            return replace(valid, execution_claim_hash="0" * 64)

    class FailingVerifier:
        def verify(
            self,
            *,
            request: VerificationSigningRequestV1,
            artifact: VerificationEvidenceArtifactV2,
        ) -> IndependentExecutionReceiptV1:
            del request, artifact
            raise RuntimeError("independent runner endpoint detail")

    for verifier, exception, message in (
        (
            FixtureOciReportingExecutionVerifier(frozenset({"other-fixture"})),
            VerificationSigningGatewayUnavailable,
            "independent execution verifier",
        ),
        (BadReceiptVerifier(), VerificationSigningGatewayRejected, "receipt"),
        (
            FailingVerifier(),
            VerificationSigningGatewayUnavailable,
            "independent execution verifier",
        ),
    ):
        gateway = VerifierSigningGateway(
            control_plane=plane,
            signer=HmacAttestationSignerV1(_VERIFIER_KEY),
            verifier=HmacAttestationVerifierV1({_VERIFIER_KEY.key_id: _VERIFIER_KEY}),
            independent_execution_verifier=verifier,
            independent_execution_trust_policy=_test_execution_trust_policy(),
            approved_image_identities=_identity_registry(),
        )
        with pytest.raises(exception, match=message):
            gateway.issue(request)
        with sqlite3.connect(plane.events.path) as connection:
            count = connection.execute("SELECT COUNT(*) FROM verifier_signing_requests").fetchone()
        assert count == (0,)
    assert b"independent runner endpoint detail" not in plane.events.path.read_bytes()


def test_gateway_rechecks_lease_after_independent_run_and_after_signing(tmp_path: Path) -> None:
    (
        plane,
        _gateway,
        bundle,
        receipt,
        _submission,
        _digest,
        _unsigned,
        request,
    ) = _gateway_fixture(tmp_path)

    class LeaseReplacingVerifier(FixtureOciReportingExecutionVerifier):
        def verify(
            self,
            *,
            request: VerificationSigningRequestV1,
            artifact: VerificationEvidenceArtifactV2,
        ) -> IndependentExecutionReceiptV1:
            result = super().verify(request=request, artifact=artifact)
            plane.leases.release(receipt.lease)
            plane.leases.claim(bundle.bundle_id.value, "replacement-before-sign", ttl_seconds=60)
            return result

    replacement_gateway = VerifierSigningGateway(
        control_plane=plane,
        signer=HmacAttestationSignerV1(_VERIFIER_KEY),
        verifier=HmacAttestationVerifierV1({_VERIFIER_KEY.key_id: _VERIFIER_KEY}),
        independent_execution_verifier=LeaseReplacingVerifier(),
        independent_execution_trust_policy=_test_execution_trust_policy(),
        approved_image_identities=_identity_registry(),
    )
    with pytest.raises(VerificationSigningGatewayRejected, match="lease"):
        replacement_gateway.issue(request)
    with sqlite3.connect(plane.events.path) as connection:
        count = connection.execute("SELECT COUNT(*) FROM verifier_signing_requests").fetchone()
    assert count == (0,)

    (
        plane,
        _gateway,
        bundle,
        receipt,
        _submission,
        _digest,
        _unsigned,
        request,
    ) = _gateway_fixture(tmp_path / "after-signing")

    class LeaseReplacingSigner:
        def issue(self, **kwargs):
            attestation = HmacAttestationSignerV1(_VERIFIER_KEY).issue(**kwargs)
            plane.leases.release(receipt.lease)
            plane.leases.claim(bundle.bundle_id.value, "replacement-after-sign", ttl_seconds=60)
            return attestation

    post_sign_gateway = VerifierSigningGateway(
        control_plane=plane,
        signer=LeaseReplacingSigner(),
        verifier=HmacAttestationVerifierV1({_VERIFIER_KEY.key_id: _VERIFIER_KEY}),
        independent_execution_verifier=_test_execution_verifier(),
        independent_execution_trust_policy=_test_execution_trust_policy(),
        approved_image_identities=_identity_registry(),
    )
    with pytest.raises(VerificationSigningGatewayUnavailable, match="authority"):
        post_sign_gateway.issue(request)
    with sqlite3.connect(plane.events.path) as connection:
        assert connection.execute(
            "SELECT state FROM verifier_signing_requests WHERE request_id = ?",
            (request.request_id.value,),
        ).fetchone() == ("failed",)


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


def test_gateway_rejects_execution_lease_or_image_identity_substitution(
    tmp_path: Path,
) -> None:
    plane, _gateway, _bundle, _receipt, _submission, _digest, _unsigned, request = _gateway_fixture(
        tmp_path
    )
    artifact = json.loads(
        plane.artifacts.get_bytes(request.context.evidence_artifact_digest).decode("utf-8")
    )
    artifact["oci"]["execution_authority"]["fencing_token"] += 1
    changed = plane.artifacts.put_json(artifact)
    wrong_context = request.context.model_copy(update={"evidence_artifact_digest": changed.digest})
    wrong_payload = verification_gateway_attestation_payload(
        lease=request.lease,
        context=wrong_context,
    )
    wrong_fence = request.model_copy(
        update={
            "context": wrong_context,
            "canonical_payload_hash": attestation_payload_hash(
                AttestationPurposeV1.VERIFICATION,
                wrong_payload,
            ),
        }
    )
    gateway = VerifierSigningGateway(
        control_plane=plane,
        signer=HmacAttestationSignerV1(_VERIFIER_KEY),
        verifier=HmacAttestationVerifierV1({_VERIFIER_KEY.key_id: _VERIFIER_KEY}),
        independent_execution_verifier=_test_execution_verifier(),
        independent_execution_trust_policy=_test_execution_trust_policy(),
        approved_image_identities={_WORKER_IMAGE_DIGEST: "9" * 64},
    )
    with pytest.raises(VerificationSigningGatewayRejected, match="execution lease fence"):
        gateway.issue(wrong_fence)
    with pytest.raises(VerificationSigningGatewayRejected, match="image-owned verifier identity"):
        gateway.issue(request)


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
            _observation(
                tmp_path / "second-observation",
                bundle,
                submission,
                execution_lease=lease_binding,
            ),
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
        independent_execution_verifier=_test_execution_verifier(),
        independent_execution_trust_policy=_test_execution_trust_policy(),
        approved_image_identities=_identity_registry(),
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
        independent_execution_verifier=_test_execution_verifier(),
        independent_execution_trust_policy=_test_execution_trust_policy(),
        approved_image_identities=_identity_registry(),
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


def test_control_plane_rechecks_v2_execution_lease_even_with_a_valid_signature(
    tmp_path: Path,
) -> None:
    plane, _gateway, bundle, receipt, submission, digest, unsigned, request = _gateway_fixture(
        tmp_path
    )
    assert unsigned.evidence is not None
    artifact = json.loads(
        plane.artifacts.get_bytes(unsigned.evidence.evidence_artifact_digest).decode("utf-8")
    )
    artifact["oci"]["execution_authority"]["worker_id"] = "other-worker"
    changed = plane.artifacts.put_json(artifact)
    changed_evidence = unsigned.evidence.model_copy(
        update={"evidence_artifact_digest": changed.digest}
    )
    changed_report = unsigned.model_copy(update={"evidence": changed_evidence})
    signing_request = build_verification_signing_request(
        changed_report,
        bundle=bundle,
        submission=submission,
        proof_submission_artifact_digest=digest,
        lease=request.lease,
        idempotency_key="tampered-execution-lease",
        ttl_seconds=30,
    )
    attestation = HmacAttestationSignerV1(_VERIFIER_KEY).issue(
        purpose=AttestationPurposeV1.VERIFICATION,
        payload=verification_gateway_attestation_payload(
            lease=signing_request.lease,
            context=signing_request.context,
        ),
        evidence_identity=changed_evidence.evidence_id.value,
        ttl_seconds=20,
    )

    with pytest.raises(InvalidTransition, match="different execution lease"):
        plane.verify_submission(
            bundle.bundle_id.value,
            lease=receipt.lease,
            report=changed_report.model_copy(update={"verifier_attestation": attestation}),
            idempotency_key="control-plane-rechecks-execution-lease",
        )
