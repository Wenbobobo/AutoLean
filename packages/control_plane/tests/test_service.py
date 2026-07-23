from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier

import pytest
from autolean_contracts import (
    AlignmentTargetV1,
    AttestationPurposeV1,
    ExecutionGraphV1,
    FidelityRiskV1,
    FormalGraphV1,
    FormalizationTaskBundleV1,
    FormalSpecificationV1,
    FreezeRecordV1,
    HashKindV1,
    HmacAttestationKeyV1,
    HmacAttestationSignerV1,
    HmacAttestationVerifierV1,
    LeanEnvironmentV1,
    MathematicalGraphV1,
    MathematicalSpecificationV1,
    OciVerifierExecutionPolicyV1,
    PermissionDecisionV1,
    ProofSubmissionV1,
    ReleaseTierV1,
    RightsRecordV1,
    SourceRecordV1,
    SourceSpanV1,
    StableIdentifierV1,
    StatementContractV1,
    StatementStatusV1,
    TaskKindV1,
    TaskPolicyV1,
    VerificationEvidenceArtifactV1,
    VerificationEvidenceV1,
    VerificationReportV1,
    build_proof_boundary,
    builder_attestation_payload,
    digest_model,
    digest_text,
    proof_dependency_manifest_hash,
    stable_identifier,
    verification_attestation_payload,
)
from autolean_contracts.graphs import (
    GraphBundleV1,
    MathematicalNodeKindV1,
    MathematicalNodeV1,
)
from autolean_control_plane import (
    ArtifactStore,
    ControlPlane,
    DashboardProjection,
    EventStore,
    Lease,
    LeaseStore,
    VerificationOutcome,
    export_dashboard_projection,
)
from autolean_control_plane.errors import (
    IdempotencyConflict,
    InvalidTransition,
    ProjectionError,
    StaleFence,
)
from autolean_control_plane.events import StoredEvent


def _id(key: str) -> StableIdentifierV1:
    return stable_identifier("control-test", key)


_BUILDER_KEY = HmacAttestationKeyV1(
    key_id="builder-test-v1",
    secret=b"builder-test-secret-material-0123456789",
    allowed_purposes=frozenset({AttestationPurposeV1.BUILDER_FREEZE}),
)
_VERIFIER_KEY = HmacAttestationKeyV1(
    key_id="verifier-test-v1",
    secret=b"verifier-test-secret-material-012345678",
    allowed_purposes=frozenset({AttestationPurposeV1.VERIFICATION}),
)


def _builder_signer(
    clock: Callable[[], datetime] | None = None,
) -> HmacAttestationSignerV1:
    if clock is None:
        return HmacAttestationSignerV1(_BUILDER_KEY)
    return HmacAttestationSignerV1(_BUILDER_KEY, clock=clock)


def _verifier_signer(
    clock: Callable[[], datetime] | None = None,
) -> HmacAttestationSignerV1:
    if clock is None:
        return HmacAttestationSignerV1(_VERIFIER_KEY)
    return HmacAttestationSignerV1(_VERIFIER_KEY, clock=clock)


def _attestation_verifier(
    clock: Callable[[], datetime] | None = None,
) -> HmacAttestationVerifierV1:
    keys = {
        _BUILDER_KEY.key_id: _BUILDER_KEY,
        _VERIFIER_KEY.key_id: _VERIFIER_KEY,
    }
    if clock is None:
        return HmacAttestationVerifierV1(keys)
    return HmacAttestationVerifierV1(keys, clock=clock)


def _bundle(
    *,
    signer: HmacAttestationSignerV1 | None = None,
    nonce: str | None = None,
    bundle_key: str = "bundle",
) -> FormalizationTaskBundleV1:
    source_id = _id("source")
    span = SourceSpanV1(
        span_id=_id("span"),
        locator="source:1",
        content_hash=digest_text(HashKindV1.SOURCE_SPAN, "n equals n"),
        permitted_excerpt="n equals n",
    )
    source = SourceRecordV1(
        source_id=source_id,
        work_id="fixture",
        title="Fixture",
        version="1",
        locator="fixture://source",
        content_hash=digest_text(HashKindV1.SOURCE_BYTES, "fixture source"),
        spans=(span,),
    )
    rights = RightsRecordV1(
        rights_id=_id("rights"),
        source_id=source_id,
        source_license="CC0-1.0",
        overall_decision=PermissionDecisionV1.ALLOW,
        reviewed_by="reviewer",
        reviewed_at=datetime.now(UTC),
    )
    statement = "theorem fixture (n : Nat) : n = n"
    formal = FormalSpecificationV1(
        declaration_name="fixture",
        namespace="AutoLean.Test",
        lean_statement_source=statement,
        statement_source_hash=digest_text(HashKindV1.STATEMENT_SOURCE, statement),
        elaborated_type="forall (n : Nat), Eq n n",
        elaborated_type_hash=digest_text(HashKindV1.ELABORATED_TYPE, "forall (n : Nat), Eq n n"),
        environment=LeanEnvironmentV1(
            lean_version="v4.28.0",
            mathlib_revision="fixture-mathlib",
            verifier_execution_policy=OciVerifierExecutionPolicyV1(
                worker_image_digest="sha256:" + ("1" * 64),
            ),
            environment_hash=digest_text(HashKindV1.ENVIRONMENT, "fixture-environment"),
        ),
    )
    draft = StatementContractV1(
        contract_id=_id("contract"),
        revision=1,
        task_kind=TaskKindV1.KNOWN_THEOREM,
        source=source,
        rights=rights,
        mathematics=MathematicalSpecificationV1(
            informal_statement="n equals n",
            normalized_statement="For every n : Nat, n equals n.",
        ),
        formal=formal,
        alignments=(
            AlignmentTargetV1(
                source_span_id=span.span_id,
                formal_target="AutoLean.Test.fixture",
                relation="formalizes",
                confidence=1.0,
            ),
        ),
        policy=TaskPolicyV1(
            release_tier=ReleaseTierV1.CALIBRATION,
            fidelity_risk=FidelityRiskV1.L1_SIMPLE,
        ),
    )
    frozen_payload = draft.model_dump(mode="python", round_trip=True)
    frozen_payload.update(
        {
            "status": StatementStatusV1.FROZEN,
            "freeze": FreezeRecordV1(
                contract_hash=draft.semantic_hash(),
                source_hash=source.content_hash,
                source_preparation_id=stable_identifier(
                    "source-preparation", f"{bundle_key}:fixture"
                ),
                source_preparation_hash=digest_text(
                    HashKindV1.SOURCE_PREPARATION, f"{bundle_key}:fixture"
                ),
                statement_source_hash=formal.statement_source_hash,
                elaborated_type_hash=formal.elaborated_type_hash,
                frozen_by="fixture",
            ),
        }
    )
    frozen = StatementContractV1.model_validate(frozen_payload)
    graphs = GraphBundleV1(
        mathematical=MathematicalGraphV1(
            graph_id=_id("math"),
            revision=1,
            nodes=(
                MathematicalNodeV1(
                    node_id=_id("math-node"),
                    kind=MathematicalNodeKindV1.THEOREM,
                    label="fixture theorem",
                ),
            ),
        ),
        formal=FormalGraphV1(graph_id=_id("formal"), revision=1),
        execution=ExecutionGraphV1(graph_id=_id("execution"), revision=1),
    )
    unsigned = FormalizationTaskBundleV1(
        bundle_id=_id(bundle_key),
        contract=frozen,
        graphs=graphs,
        graph_snapshot_hash=digest_model(HashKindV1.GRAPH_SNAPSHOT, graphs),
        proof_boundary=build_proof_boundary(frozen),
    )
    attestation = (signer or _builder_signer()).issue(
        purpose=AttestationPurposeV1.BUILDER_FREEZE,
        payload=builder_attestation_payload(unsigned),
        evidence_identity="builder-fixture-freeze",
        ttl_seconds=3600,
        nonce=nonce,
    )
    return unsigned.model_copy(update={"builder_attestation": attestation})


def _rebundle(
    bundle: FormalizationTaskBundleV1,
    *,
    bundle_key: str | None = None,
    issued_at: datetime | None = None,
) -> FormalizationTaskBundleV1:
    updates: dict[str, object] = {"builder_attestation": None}
    if bundle_key is not None:
        updates["bundle_id"] = _id(bundle_key)
    if issued_at is not None:
        updates["issued_at"] = issued_at
    unsigned = bundle.model_copy(update=updates)
    attestation = _builder_signer().issue(
        purpose=AttestationPurposeV1.BUILDER_FREEZE,
        payload=builder_attestation_payload(unsigned),
        evidence_identity="builder-fixture-rebundle",
        ttl_seconds=3600,
    )
    return unsigned.model_copy(update={"builder_attestation": attestation})


def _plane(
    tmp_path: Path,
    *,
    clock: Callable[[], datetime] | None = None,
) -> ControlPlane:
    database = tmp_path / "control.db"
    return ControlPlane(
        events=EventStore(database, clock=clock),
        leases=LeaseStore(database, clock=clock),
        artifacts=ArtifactStore(tmp_path / "artifacts"),
        attestation_verifier=_attestation_verifier(clock),
        allow_test_only_direct_verifier_attestations=True,
        allow_test_only_unreviewed_bundles=True,
    )


def _submission(bundle: FormalizationTaskBundleV1) -> ProofSubmissionV1:
    source = "by\n  rfl"
    return ProofSubmissionV1(
        proof_id=_id("proof"),
        contract_id=bundle.contract.contract_id,
        revision=bundle.contract.revision,
        contract_hash=bundle.contract.semantic_hash(),
        proof_boundary_hash=bundle.proof_boundary.boundary_hash,
        proof_source=source,
        proof_source_hash=digest_text(HashKindV1.PROOF_SOURCE, source),
        environment_hash=bundle.contract.formal.environment.environment_hash,
    )


def test_control_plane_requires_events_and_leases_to_share_one_database(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="share one SQLite database"):
        ControlPlane(
            events=EventStore(tmp_path / "events.db"),
            leases=LeaseStore(tmp_path / "leases.db"),
            artifacts=ArtifactStore(tmp_path / "artifacts"),
            attestation_verifier=_attestation_verifier(),
        )


def test_control_plane_rejects_unreviewed_bundle_by_default(tmp_path: Path) -> None:
    database = tmp_path / "control.db"
    plane = ControlPlane(
        events=EventStore(database),
        leases=LeaseStore(database),
        artifacts=ArtifactStore(tmp_path / "artifacts"),
        attestation_verifier=_attestation_verifier(),
    )

    with pytest.raises(InvalidTransition, match="fidelity artifact is required"):
        plane.register_bundle(_bundle(), idempotency_key="unreviewed")


def test_control_plane_rejects_legacy_bundle_without_source_preparation(
    tmp_path: Path,
) -> None:
    bundle = _bundle()
    freeze = bundle.contract.freeze
    assert freeze is not None
    legacy_contract = bundle.contract.model_copy(
        update={
            "freeze": freeze.model_copy(
                update={
                    "source_preparation_id": None,
                    "source_preparation_hash": None,
                }
            )
        }
    )
    legacy_bundle = bundle.model_copy(update={"contract": legacy_contract})

    with pytest.raises(InvalidTransition, match="source-preparation evidence"):
        _plane(tmp_path).register_bundle(
            legacy_bundle,
            idempotency_key="legacy-source-preparation",
        )


def test_protocol_accepts_only_evidence_for_the_registered_frozen_contract(tmp_path: Path) -> None:
    plane = _plane(tmp_path)
    bundle = _bundle()
    binding = plane.register_bundle(bundle, idempotency_key="register")
    assert binding.contract_hash == bundle.contract.semantic_hash().value
    receipt = plane.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=60,
        idempotency_key="claim",
    )
    submission = _submission(bundle)
    plane.submit_proof(
        bundle.bundle_id.value,
        lease=receipt.lease,
        submission=submission,
        idempotency_key="proof",
    )
    report = _passing_report(plane, bundle, submission, report_key="accepted")
    outcome = plane.verify_submission(
        bundle.bundle_id.value,
        lease=receipt.lease,
        report=report,
        idempotency_key="verify",
    )
    assert outcome.accepted
    assert outcome.event.event_type == "verification.accepted"
    snapshot = DashboardProjection(plane.events.read_all()).snapshot()
    assert {node["status"] for node in snapshot["nodes"]} == {"verified"}
    assert snapshot["overview"]["active_runs"] == 0
    assert snapshot["overview"]["blocked_nodes"] == 0
    assert snapshot["runs"][0]["verification"] == "accepted"
    verification_event = next(
        item for item in snapshot["events"] if item["event_type"] == "verification.accepted"
    )
    assert verification_event["task_id"] == bundle.bundle_id.value


def test_verifier_records_but_never_accepts_sorry_axiom(tmp_path: Path) -> None:
    plane = _plane(tmp_path)
    bundle = _bundle()
    plane.register_bundle(bundle, idempotency_key="register")
    receipt = plane.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=60,
        idempotency_key="claim",
    )
    submission = _submission(bundle)
    plane.submit_proof(
        bundle.bundle_id.value,
        lease=receipt.lease,
        submission=submission,
        idempotency_key="proof",
    )
    outcome = plane.verify_submission(
        bundle.bundle_id.value,
        lease=receipt.lease,
        report=_passing_report(
            plane,
            bundle,
            submission,
            report_key="sorry-axiom",
            observed_axioms=("sorryAx",),
        ),
        idempotency_key="verify",
    )
    assert not outcome.accepted
    assert "sorryAx is prohibited" in outcome.reasons
    assert outcome.event.event_type == "verification.rejected"


def test_control_plane_rejects_a_nonindependent_verifier_report(tmp_path: Path) -> None:
    plane = _plane(tmp_path)
    bundle = _bundle()
    plane.register_bundle(bundle, idempotency_key="register")
    claim = plane.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=60,
        idempotency_key="claim",
    )
    submission = _submission(bundle)
    plane.submit_proof(
        bundle.bundle_id.value,
        lease=claim.lease,
        submission=submission,
        idempotency_key="proof",
    )
    report = _passing_report(
        plane,
        bundle,
        submission,
        report_key="not-independent",
        independent=False,
    )
    outcome = plane.verify_submission(
        bundle.bundle_id.value,
        lease=claim.lease,
        report=report,
        idempotency_key="verify",
    )
    assert not outcome.accepted
    assert "verification report is not independent" in outcome.reasons


def test_control_plane_rejects_a_submission_for_a_different_proof_boundary(tmp_path: Path) -> None:
    plane = _plane(tmp_path)
    bundle = _bundle()
    plane.register_bundle(bundle, idempotency_key="register")
    receipt = plane.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=60,
        idempotency_key="claim",
    )
    wrong_boundary = digest_text(HashKindV1.PROOF_BOUNDARY, "other-boundary")
    submission = _submission(bundle).model_copy(update={"proof_boundary_hash": wrong_boundary})
    with pytest.raises(InvalidTransition, match="proof boundary"):
        plane.submit_proof(
            bundle.bundle_id.value,
            lease=receipt.lease,
            submission=submission,
            idempotency_key="proof",
        )


def test_projection_exports_only_summaries_not_proof_or_source_text(tmp_path: Path) -> None:
    plane = _plane(tmp_path)
    bundle = _bundle()
    plane.register_bundle(bundle, idempotency_key="register")
    receipt = plane.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=60,
        idempotency_key="claim",
    )
    plane.submit_proof(
        bundle.bundle_id.value,
        lease=receipt.lease,
        submission=_submission(bundle),
        idempotency_key="proof",
    )
    snapshot = DashboardProjection(plane.events.read_all()).snapshot()
    text = json.dumps(snapshot)
    assert "by\\n  rfl" not in text
    node = snapshot["nodes"][0]
    run = snapshot["runs"][0]
    proof_event = next(
        item for item in snapshot["events"] if item["event_type"] == "proof.submitted"
    )
    assert node["source_node_id"] == bundle.graphs.mathematical.nodes[0].node_id.value
    assert node["task_id"] == run["task_id"] == proof_event["task_id"] == bundle.bundle_id.value
    assert node["id"] == (
        f"dashboard-node|{bundle.bundle_id.value}|mathematical|"
        f"{bundle.graphs.mathematical.nodes[0].node_id.value}"
    )
    assert "bundle_id" not in node
    claim_event = next(item for item in snapshot["events"] if item["event_type"] == "task.claimed")
    assert claim_event["task_id"] == bundle.bundle_id.value
    assert node["status"] == "running"
    assert snapshot["overview"]["active_runs"] == 1
    path = export_dashboard_projection(tmp_path / "projection.json", plane.events.read_all())
    assert json.loads(path.read_text(encoding="utf-8"))["runs"][0]["status"] == "candidate"


def test_projection_composite_node_ids_preserve_names_and_drop_tainted_fields(
    tmp_path: Path,
) -> None:
    def registered(
        *,
        position: int,
        bundle_id: str,
        graph_nodes: list[dict[str, object]],
    ) -> StoredEvent:
        return StoredEvent(
            global_position=position,
            event_id=f"event-{position}",
            entity_type="task",
            entity_id=bundle_id,
            entity_sequence=1,
            event_type="task.registered",
            payload={"bundle_id": bundle_id, "graph_nodes": graph_nodes},
            metadata={},
            recorded_at=f"2026-07-23T12:00:0{position}Z",
        )

    def graph_node(
        graph: str,
        *,
        node_id: str = "shared-node",
        dependencies: list[str] | None = None,
    ) -> dict[str, object]:
        return {
            "id": node_id,
            "bundle_id": "ignored-node-copy",
            "label": f"{graph} {node_id}",
            "graph": graph,
            "status": "frozen",
            "revision": 1,
            "kind": "statement",
            "dependencies": dependencies or [],
            "proof_source": "TAINTED-PROOF-SOURCE",
            "metadata": {"prompt": "TAINTED-MODEL-PROMPT"},
        }

    events = (
        registered(
            position=1,
            bundle_id="bundle-a",
            graph_nodes=[graph_node("mathematical"), graph_node("formal")],
        ),
        registered(
            position=2,
            bundle_id="bundle-b",
            graph_nodes=[
                graph_node("mathematical"),
                graph_node(
                    "mathematical",
                    node_id="child-node",
                    dependencies=["shared-node"],
                ),
            ],
        ),
    )
    snapshot = DashboardProjection(events).snapshot()
    nodes = snapshot["nodes"]

    assert len(nodes) == 4
    assert len({node["id"] for node in nodes}) == 4
    assert {(node["task_id"], node["graph"], node["source_node_id"]) for node in nodes} == {
        ("bundle-a", "mathematical", "shared-node"),
        ("bundle-a", "formal", "shared-node"),
        ("bundle-b", "mathematical", "shared-node"),
        ("bundle-b", "mathematical", "child-node"),
    }
    bundle_b_root = next(
        node
        for node in nodes
        if node["task_id"] == "bundle-b" and node["source_node_id"] == "shared-node"
    )
    bundle_b_child = next(
        node
        for node in nodes
        if node["task_id"] == "bundle-b" and node["source_node_id"] == "child-node"
    )
    assert bundle_b_child["dependencies"] == [bundle_b_root["id"]]
    assert all("bundle_id" not in node for node in nodes)
    assert all(
        set(node)
        == {
            "dependencies",
            "graph",
            "id",
            "kind",
            "label",
            "revision",
            "source_node_id",
            "status",
            "task_id",
            "updated_at",
        }
        for node in nodes
    )
    exported = export_dashboard_projection(tmp_path / "projection.json", events).read_text(
        encoding="utf-8"
    )
    assert "TAINTED-PROOF-SOURCE" not in exported
    assert "TAINTED-MODEL-PROMPT" not in exported
    assert '"proof_source"' not in exported
    assert '"metadata"' not in exported


def test_projection_rejected_verification_is_fail_closed() -> None:
    event = StoredEvent(
        global_position=1,
        event_id="verification-rejected",
        entity_type="verification",
        entity_id="proof-1",
        entity_sequence=1,
        event_type="verification.rejected",
        payload={
            "bundle_id": "bundle-a",
            "proof_id": "proof-1",
            "accepted": False,
            "reasons": ["kernel failure"],
        },
        metadata={},
        recorded_at="2026-07-23T12:00:00Z",
    )

    snapshot = DashboardProjection((event,)).snapshot()

    assert snapshot["overview"]["blocked_nodes"] == 1
    assert snapshot["events"][0]["task_id"] == "bundle-a"


@pytest.mark.parametrize(
    ("event_type", "accepted"),
    [
        ("verification.accepted", "false"),
        ("verification.accepted", False),
        ("verification.rejected", True),
        ("verification.unknown", False),
    ],
)
def test_projection_rejects_malformed_or_inconsistent_verification(
    event_type: str,
    accepted: object,
) -> None:
    event = StoredEvent(
        global_position=1,
        event_id="verification-malformed",
        entity_type="verification",
        entity_id="proof-1",
        entity_sequence=1,
        event_type=event_type,
        payload={
            "bundle_id": "bundle-a",
            "proof_id": "proof-1",
            "accepted": accepted,
            "reasons": [],
        },
        metadata={},
        recorded_at="2026-07-23T12:00:00Z",
    )

    with pytest.raises(ProjectionError, match="verification"):
        DashboardProjection((event,)).snapshot()


def _proof_submission_artifact_digest(
    plane: ControlPlane,
    submission: ProofSubmissionV1,
) -> str:
    event = plane.events.read_stream("proof", submission.proof_id.value)[0]
    artifact = event.payload["proof_artifact"]
    assert isinstance(artifact, dict)
    digest = artifact["digest"]
    assert isinstance(digest, str)
    return digest


def _unsigned_report(
    plane: ControlPlane,
    bundle: FormalizationTaskBundleV1,
    submission: ProofSubmissionV1,
    *,
    report_key: str,
    independent: bool = True,
    kernel_passed: bool = True,
    observed_axioms: tuple[str, ...] = (),
) -> VerificationReportV1:
    environment = bundle.contract.formal.environment
    policy = environment.verifier_execution_policy
    command_hash = digest_text(
        HashKindV1.VERIFICATION_COMMAND,
        "synthetic-control-plane-fixture-command-v1",
    )
    observation = VerificationReportV1(
        report_id=_id(f"verification-{report_key}"),
        proof_id=submission.proof_id,
        contract_hash=submission.contract_hash,
        proof_boundary_hash=submission.proof_boundary_hash,
        verifier_id="synthetic-control-plane-fixture-verifier",
        independent=independent,
        kernel_passed=kernel_passed,
        build_passed=True,
        dependency_check_passed=True,
        clean_environment=True,
        environment_hash=submission.environment_hash,
        axiom_profile=bundle.contract.policy.axiom_profile,
        observed_axioms=observed_axioms,
        details="Synthetic control-plane fixture record; no Lean or OCI execution occurred.",
    )
    candidate = (
        f"{bundle.proof_boundary.trusted_statement_source} := {submission.proof_source.rstrip()}\n"
        f"\n#print axioms {bundle.proof_boundary.expected_declaration}\n"
    )
    artifact = VerificationEvidenceArtifactV1(
        evidence_id=_id(f"evidence-{report_key}"),
        bundle_id=bundle.bundle_id,
        bundle_hash=bundle.handoff_hash(),
        contract_id=bundle.contract.contract_id,
        revision=bundle.contract.revision,
        contract_hash=bundle.contract.semantic_hash(),
        proof_id=submission.proof_id,
        proof_boundary_hash=bundle.proof_boundary.boundary_hash,
        proof_submission_artifact_digest=_proof_submission_artifact_digest(plane, submission),
        dependency_manifest_hash=proof_dependency_manifest_hash(submission),
        verification_report_id=observation.report_id,
        verification_observation_hash=observation.report_hash(),
        environment={
            "environment_hash": environment.environment_hash,
            "lean_version": environment.lean_version,
            "mathlib_revision": environment.mathlib_revision,
            "lake_manifest_hash": environment.lake_manifest_hash,
        },
        oci={
            "worker_image_digest": policy.worker_image_digest,
            "wrapper_protocol": policy.wrapper_protocol,
            "command_policy_hash": policy.command_policy_hash(),
            "command_hash": command_hash,
            "candidate_sha256": hashlib.sha256(candidate.encode("utf-8")).hexdigest(),
            "trusted_statement_sha256": bundle.proof_boundary.trusted_statement_hash.value,
            "bundle_manifest_sha256": bundle.proof_boundary.solver_manifest_hash.value,
        },
    )
    evidence_artifact = plane.artifacts.put_json(artifact.model_dump(mode="json"))
    evidence = VerificationEvidenceV1(
        evidence_id=artifact.evidence_id,
        environment_hash=submission.environment_hash,
        worker_image_digest=policy.worker_image_digest,
        wrapper_protocol=policy.wrapper_protocol,
        lean_version=environment.lean_version,
        mathlib_revision=environment.mathlib_revision,
        lake_manifest_hash=environment.lake_manifest_hash,
        dependency_manifest_hash=proof_dependency_manifest_hash(submission),
        command_policy_hash=policy.command_policy_hash(),
        command_hash=command_hash,
        evidence_artifact_digest=evidence_artifact.digest,
    )
    return observation.model_copy(update={"evidence": evidence})


def _passing_report(
    plane: ControlPlane,
    bundle: FormalizationTaskBundleV1,
    submission: ProofSubmissionV1,
    *,
    report_key: str,
    independent: bool = True,
    kernel_passed: bool = True,
    observed_axioms: tuple[str, ...] = (),
    signer: HmacAttestationSignerV1 | None = None,
    nonce: str | None = None,
) -> VerificationReportV1:
    return _attest_report(
        plane,
        bundle,
        submission,
        _unsigned_report(
            plane,
            bundle,
            submission,
            report_key=report_key,
            independent=independent,
            kernel_passed=kernel_passed,
            observed_axioms=observed_axioms,
        ),
        signer=signer,
        nonce=nonce,
    )


def _attest_report(
    plane: ControlPlane,
    bundle: FormalizationTaskBundleV1,
    submission: ProofSubmissionV1,
    report: VerificationReportV1,
    *,
    signer: HmacAttestationSignerV1 | None = None,
    nonce: str | None = None,
) -> VerificationReportV1:
    assert report.evidence is not None
    attestation = (signer or _verifier_signer()).issue(
        purpose=AttestationPurposeV1.VERIFICATION,
        payload=verification_attestation_payload(
            bundle_id=bundle.bundle_id.value,
            bundle_hash=bundle.handoff_hash().value,
            proof_submission_artifact_digest=_proof_submission_artifact_digest(plane, submission),
            contract_id=bundle.contract.contract_id.value,
            revision=bundle.contract.revision,
            contract_hash=report.contract_hash,
            proof_boundary_hash=report.proof_boundary_hash,
            environment_hash=report.environment_hash,
            report=report,
        ),
        evidence_identity=report.evidence.evidence_id.value,
        ttl_seconds=3600,
        nonce=nonce,
    )
    return report.model_copy(update={"verifier_attestation": attestation})


def _replace_evidence_artifact(
    plane: ControlPlane,
    report: VerificationReportV1,
    mutate: Callable[[dict[str, object]], None],
) -> VerificationReportV1:
    """Write a new canonical artifact for an adversarial binding test, then detach its signature."""

    assert report.evidence is not None
    payload = json.loads(
        plane.artifacts.get_bytes(report.evidence.evidence_artifact_digest).decode("utf-8")
    )
    assert isinstance(payload, dict)
    mutate(payload)
    replacement = plane.artifacts.put_json(payload)
    evidence = report.evidence.model_copy(update={"evidence_artifact_digest": replacement.digest})
    return report.model_copy(update={"evidence": evidence, "verifier_attestation": None})


def test_registration_rejects_unsigned_and_tampered_builder_bundles(tmp_path: Path) -> None:
    plane = _plane(tmp_path)
    signed = _bundle()
    unsigned = signed.model_copy(update={"builder_attestation": None})
    with pytest.raises(InvalidTransition, match="Builder attestation is required"):
        plane.register_bundle(unsigned, idempotency_key="unsigned")

    tampered = signed.model_copy(update={"issued_at": datetime(2026, 1, 2, tzinfo=UTC)})
    with pytest.raises(InvalidTransition, match="Builder attestation was rejected"):
        plane.register_bundle(tampered, idempotency_key="tampered")


def test_registration_rejects_expired_revoked_and_replayed_builder_authority(
    tmp_path: Path,
) -> None:
    clock_state = {"now": datetime(2026, 1, 1, tzinfo=UTC)}

    def clock() -> datetime:
        return clock_state["now"]

    expired = _bundle(signer=_builder_signer(clock))
    clock_state["now"] += timedelta(seconds=3601)
    with pytest.raises(InvalidTransition, match="Builder attestation was rejected"):
        _plane(tmp_path / "expired", clock=clock).register_bundle(
            expired,
            idempotency_key="expired",
        )

    revoked_builder = HmacAttestationKeyV1(
        key_id=_BUILDER_KEY.key_id,
        secret=_BUILDER_KEY.secret,
        allowed_purposes=_BUILDER_KEY.allowed_purposes,
        revoked=True,
    )
    revoked_plane = ControlPlane(
        events=EventStore(tmp_path / "revoked" / "control.db"),
        leases=LeaseStore(tmp_path / "revoked" / "control.db"),
        artifacts=ArtifactStore(tmp_path / "revoked" / "artifacts"),
        attestation_verifier=HmacAttestationVerifierV1(
            {
                revoked_builder.key_id: revoked_builder,
                _VERIFIER_KEY.key_id: _VERIFIER_KEY,
            }
        ),
    )
    with pytest.raises(InvalidTransition, match="Builder attestation was rejected"):
        revoked_plane.register_bundle(_bundle(), idempotency_key="revoked")

    replay_plane = _plane(tmp_path / "replay")
    nonce = "r" * 24
    replay_plane.register_bundle(_bundle(nonce=nonce), idempotency_key="first")
    with pytest.raises(InvalidTransition, match="nonce was replayed"):
        replay_plane.register_bundle(
            _bundle(nonce=nonce, bundle_key="bundle-replayed"),
            idempotency_key="second",
        )


def test_verification_requires_attested_environment_evidence_and_rejects_tampering(
    tmp_path: Path,
) -> None:
    plane = _plane(tmp_path)
    bundle = _bundle()
    plane.register_bundle(bundle, idempotency_key="register")
    claim = plane.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=60,
        idempotency_key="claim",
    )
    submission = _submission(bundle)
    plane.submit_proof(
        bundle.bundle_id.value,
        lease=claim.lease,
        submission=submission,
        idempotency_key="proof",
    )

    all_true_without_authority = _unsigned_report(
        plane,
        bundle,
        submission,
        report_key="unsigned-all-true",
    )
    with pytest.raises(InvalidTransition, match="independent verifier attestation is required"):
        plane.verify_submission(
            bundle.bundle_id.value,
            lease=claim.lease,
            report=all_true_without_authority,
            idempotency_key="unsigned",
        )

    missing_evidence = _passing_report(
        plane,
        bundle,
        submission,
        report_key="missing-evidence",
    ).model_copy(update={"evidence": None})
    with pytest.raises(InvalidTransition, match="environment evidence is required"):
        plane.verify_submission(
            bundle.bundle_id.value,
            lease=claim.lease,
            report=missing_evidence,
            idempotency_key="missing-evidence",
        )

    tampered = _passing_report(
        plane,
        bundle,
        submission,
        report_key="tampered-report",
    ).model_copy(update={"kernel_passed": False})
    with pytest.raises(InvalidTransition, match="verification attestation was rejected"):
        plane.verify_submission(
            bundle.bundle_id.value,
            lease=claim.lease,
            report=tampered,
            idempotency_key="tampered",
        )


def test_verification_rejects_oci_facts_outside_the_frozen_execution_policy(
    tmp_path: Path,
) -> None:
    plane = _plane(tmp_path)
    bundle = _bundle()
    plane.register_bundle(bundle, idempotency_key="register")
    claim = plane.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=60,
        idempotency_key="claim",
    )
    submission = _submission(bundle)
    plane.submit_proof(
        bundle.bundle_id.value,
        lease=claim.lease,
        submission=submission,
        idempotency_key="proof",
    )

    def mutate_image(payload: dict[str, object]) -> None:
        oci = payload["oci"]
        assert isinstance(oci, dict)
        oci["worker_image_digest"] = "sha256:" + ("f" * 64)

    base_image = _unsigned_report(plane, bundle, submission, report_key="wrong-image")
    assert base_image.evidence is not None
    wrong_image = _replace_evidence_artifact(
        plane,
        base_image.model_copy(
            update={
                "evidence": base_image.evidence.model_copy(
                    update={"worker_image_digest": "sha256:" + ("f" * 64)}
                )
            }
        ),
        mutate_image,
    )
    with pytest.raises(InvalidTransition, match="different worker image"):
        plane.verify_submission(
            bundle.bundle_id.value,
            lease=claim.lease,
            report=_attest_report(plane, bundle, submission, wrong_image),
            idempotency_key="wrong-image",
        )

    def mutate_wrapper(payload: dict[str, object]) -> None:
        oci = payload["oci"]
        assert isinstance(oci, dict)
        oci["wrapper_protocol"] = "autolean.oci-lean-wrapper.v0"

    base_wrapper = _unsigned_report(plane, bundle, submission, report_key="wrong-wrapper")
    assert base_wrapper.evidence is not None
    wrong_wrapper = _replace_evidence_artifact(
        plane,
        base_wrapper.model_copy(
            update={
                "evidence": base_wrapper.evidence.model_copy(
                    update={"wrapper_protocol": "autolean.oci-lean-wrapper.v0"}
                )
            }
        ),
        mutate_wrapper,
    )
    with pytest.raises(InvalidTransition, match="different wrapper protocol"):
        plane.verify_submission(
            bundle.bundle_id.value,
            lease=claim.lease,
            report=_attest_report(plane, bundle, submission, wrong_wrapper),
            idempotency_key="wrong-wrapper",
        )

    wrong_policy_hash = digest_text(HashKindV1.VERIFICATION_COMMAND, "wrong-policy")

    def mutate_policy(payload: dict[str, object]) -> None:
        oci = payload["oci"]
        assert isinstance(oci, dict)
        oci["command_policy_hash"] = wrong_policy_hash.model_dump(mode="json")

    base_policy = _unsigned_report(plane, bundle, submission, report_key="wrong-policy")
    assert base_policy.evidence is not None
    wrong_policy = _replace_evidence_artifact(
        plane,
        base_policy.model_copy(
            update={
                "evidence": base_policy.evidence.model_copy(
                    update={"command_policy_hash": wrong_policy_hash}
                )
            }
        ),
        mutate_policy,
    )
    with pytest.raises(InvalidTransition, match="different command policy"):
        plane.verify_submission(
            bundle.bundle_id.value,
            lease=claim.lease,
            report=_attest_report(plane, bundle, submission, wrong_policy),
            idempotency_key="wrong-policy",
        )


def test_verification_reads_only_canonical_typed_evidence_artifacts(tmp_path: Path) -> None:
    plane = _plane(tmp_path)
    bundle = _bundle()
    plane.register_bundle(bundle, idempotency_key="register")
    claim = plane.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=60,
        idempotency_key="claim",
    )
    submission = _submission(bundle)
    plane.submit_proof(
        bundle.bundle_id.value,
        lease=claim.lease,
        submission=submission,
        idempotency_key="proof",
    )

    malformed = _unsigned_report(plane, bundle, submission, report_key="malformed-blob")
    assert malformed.evidence is not None
    malformed_digest = plane.artifacts.put_bytes(b"not-json").digest
    malformed = malformed.model_copy(
        update={
            "evidence": malformed.evidence.model_copy(
                update={"evidence_artifact_digest": malformed_digest}
            )
        }
    )
    with pytest.raises(InvalidTransition, match="not strict JSON"):
        plane.verify_submission(
            bundle.bundle_id.value,
            lease=claim.lease,
            report=_attest_report(plane, bundle, submission, malformed),
            idempotency_key="malformed-blob",
        )

    arbitrary = _unsigned_report(plane, bundle, submission, report_key="arbitrary-blob")
    assert arbitrary.evidence is not None
    arbitrary_digest = plane.artifacts.put_json({"unrelated": "canonical but untyped"}).digest
    arbitrary = arbitrary.model_copy(
        update={
            "evidence": arbitrary.evidence.model_copy(
                update={"evidence_artifact_digest": arbitrary_digest}
            )
        }
    )
    with pytest.raises(InvalidTransition, match="invalid V1 schema"):
        plane.verify_submission(
            bundle.bundle_id.value,
            lease=claim.lease,
            report=_attest_report(plane, bundle, submission, arbitrary),
            idempotency_key="arbitrary-blob",
        )


def test_verification_cross_binds_evidence_artifact_to_report_bundle_and_proof(
    tmp_path: Path,
) -> None:
    plane = _plane(tmp_path)
    bundle = _bundle()
    plane.register_bundle(bundle, idempotency_key="register")
    claim = plane.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=60,
        idempotency_key="claim",
    )
    submission = _submission(bundle)
    plane.submit_proof(
        bundle.bundle_id.value,
        lease=claim.lease,
        submission=submission,
        idempotency_key="proof",
    )

    def mutate_report(payload: dict[str, object]) -> None:
        payload["verification_report_id"] = _id("different-verification-report").model_dump(
            mode="json"
        )

    def mutate_bundle(payload: dict[str, object]) -> None:
        bundle_hash = payload["bundle_hash"]
        assert isinstance(bundle_hash, dict)
        bundle_hash["value"] = "e" * 64

    def mutate_proof_artifact(payload: dict[str, object]) -> None:
        payload["proof_submission_artifact_digest"] = "d" * 64

    def mutate_candidate(payload: dict[str, object]) -> None:
        oci = payload["oci"]
        assert isinstance(oci, dict)
        oci["candidate_sha256"] = "0" * 64

    scenarios = (
        ("report", mutate_report, "different verification report"),
        ("bundle", mutate_bundle, "different bundle hash"),
        ("proof-artifact", mutate_proof_artifact, "different submitted proof artifact"),
        ("candidate", mutate_candidate, "does not bind the submitted proof bytes"),
    )
    for name, mutate, message in scenarios:
        report = _replace_evidence_artifact(
            plane,
            _unsigned_report(plane, bundle, submission, report_key=f"mismatch-{name}"),
            mutate,
        )
        with pytest.raises(InvalidTransition, match=message):
            plane.verify_submission(
                bundle.bundle_id.value,
                lease=claim.lease,
                report=_attest_report(plane, bundle, submission, report),
                idempotency_key=f"mismatch-{name}",
            )


def test_verification_attestation_nonce_cannot_be_reused_for_another_proof(
    tmp_path: Path,
) -> None:
    plane = _plane(tmp_path)
    bundle = _bundle()
    plane.register_bundle(bundle, idempotency_key="register")
    claim = plane.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=60,
        idempotency_key="claim",
    )
    first_submission = _submission(bundle)
    plane.submit_proof(
        bundle.bundle_id.value,
        lease=claim.lease,
        submission=first_submission,
        idempotency_key="proof-one",
    )
    nonce = "v" * 24
    plane.verify_submission(
        bundle.bundle_id.value,
        lease=claim.lease,
        report=_passing_report(
            plane,
            bundle,
            first_submission,
            report_key="nonce-one",
            nonce=nonce,
        ),
        idempotency_key="verify-one",
    )

    second_submission = first_submission.model_copy(update={"proof_id": _id("proof-two")})
    plane.submit_proof(
        bundle.bundle_id.value,
        lease=claim.lease,
        submission=second_submission,
        idempotency_key="proof-two",
    )
    with pytest.raises(InvalidTransition, match="attestation was replayed"):
        plane.verify_submission(
            bundle.bundle_id.value,
            lease=claim.lease,
            report=_passing_report(
                plane,
                bundle,
                second_submission,
                report_key="nonce-two",
                nonce=nonce,
            ),
            idempotency_key="verify-two",
        )


def test_repeated_delivery_replays_registered_claimed_and_submitted_events_after_restart(
    tmp_path: Path,
) -> None:
    bundle = _bundle()
    first = _plane(tmp_path)
    registered = first.register_bundle(bundle, idempotency_key="register")
    claim = first.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=60,
        idempotency_key="claim",
    )
    submission = _submission(bundle)
    submitted = first.submit_proof(
        bundle.bundle_id.value,
        lease=claim.lease,
        submission=submission,
        idempotency_key="proof",
    )

    restarted = _plane(tmp_path)
    repeated_registration = restarted.register_bundle(bundle, idempotency_key="register-replay")
    repeated_claim = restarted.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=60,
        idempotency_key="claim",
    )
    repeated_submission = restarted.submit_proof(
        bundle.bundle_id.value,
        lease=claim.lease,
        submission=submission,
        idempotency_key="proof",
    )

    assert repeated_registration == registered
    assert repeated_claim.lease == claim.lease
    assert repeated_claim.event.event_id == claim.event.event_id
    assert repeated_submission.event_id == submitted.event_id
    replayed = EventStore(tmp_path / "control.db").read_all()
    assert [event.global_position for event in replayed] == list(range(1, len(replayed) + 1))
    assert [event.event_type for event in replayed] == [
        "task.registered",
        "task.claimed",
        "proof.submitted",
    ]
    assert restarted.get_binding(bundle.bundle_id.value) == registered


def test_stale_fencing_token_cannot_submit_after_expiry_and_restart(tmp_path: Path) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)

    def clock() -> datetime:
        return now

    database = tmp_path / "control.db"
    first = ControlPlane(
        events=EventStore(database),
        leases=LeaseStore(database, clock=clock),
        artifacts=ArtifactStore(tmp_path / "artifacts"),
        attestation_verifier=_attestation_verifier(clock),
        allow_test_only_direct_verifier_attestations=True,
        allow_test_only_unreviewed_bundles=True,
    )
    bundle = _bundle(signer=_builder_signer(clock))
    first.register_bundle(bundle, idempotency_key="register")
    old_claim = first.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=5,
        idempotency_key="old-claim",
    )

    now += timedelta(seconds=6)
    restarted = ControlPlane(
        events=EventStore(database),
        leases=LeaseStore(database, clock=clock),
        artifacts=ArtifactStore(tmp_path / "artifacts"),
        attestation_verifier=_attestation_verifier(clock),
        allow_test_only_unreviewed_bundles=True,
    )
    replacement = restarted.claim(
        bundle.bundle_id.value,
        worker_id="worker-b",
        ttl_seconds=5,
        idempotency_key="replacement-claim",
    )
    assert replacement.lease.fencing_token > old_claim.lease.fencing_token
    with pytest.raises(StaleFence):
        restarted.submit_proof(
            bundle.bundle_id.value,
            lease=old_claim.lease,
            submission=_submission(bundle),
            idempotency_key="stale-proof",
        )


def test_verification_retry_after_restart_replays_one_terminal_verdict(tmp_path: Path) -> None:
    plane = _plane(tmp_path)
    bundle = _bundle()
    plane.register_bundle(bundle, idempotency_key="register")
    claim = plane.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=60,
        idempotency_key="claim",
    )
    submission = _submission(bundle)
    plane.submit_proof(
        bundle.bundle_id.value,
        lease=claim.lease,
        submission=submission,
        idempotency_key="proof",
    )
    report = _passing_report(plane, bundle, submission, report_key="retry")
    first = plane.verify_submission(
        bundle.bundle_id.value,
        lease=claim.lease,
        report=report,
        idempotency_key="verify",
    )

    restarted = _plane(tmp_path)
    repeated = restarted.verify_submission(
        bundle.bundle_id.value,
        lease=claim.lease,
        report=report,
        idempotency_key="verify",
    )
    assert repeated.accepted
    assert repeated.event.event_id == first.event.event_id
    assert restarted.events.count_events(entity_type="verification") == 1
    assert len(restarted.events.read_stream("verification", submission.proof_id.value)) == 1


def test_durable_replays_survive_expired_lease_and_attestations(tmp_path: Path) -> None:
    clock_state = {"now": datetime(2026, 1, 1, tzinfo=UTC)}

    def clock() -> datetime:
        return clock_state["now"]

    bundle = _bundle(signer=_builder_signer(clock))
    first = _plane(tmp_path, clock=clock)
    registered = first.register_bundle(bundle, idempotency_key="register")
    claim = first.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=1,
        idempotency_key="claim",
    )
    submission = _submission(bundle)
    submitted = first.submit_proof(
        bundle.bundle_id.value,
        lease=claim.lease,
        submission=submission,
        idempotency_key="proof",
    )
    report = _passing_report(
        first,
        bundle,
        submission,
        report_key="durable-replay",
        signer=_verifier_signer(clock),
    )
    verified = first.verify_submission(
        bundle.bundle_id.value,
        lease=claim.lease,
        report=report,
        idempotency_key="verify",
    )

    clock_state["now"] += timedelta(seconds=3601)
    restarted = _plane(tmp_path, clock=clock)
    assert restarted.register_bundle(bundle, idempotency_key="register") == registered
    replayed_claim = restarted.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=1,
        idempotency_key="claim",
    )
    assert replayed_claim == claim
    assert (
        restarted.submit_proof(
            bundle.bundle_id.value,
            lease=claim.lease,
            submission=submission,
            idempotency_key="proof",
        ).event_id
        == submitted.event_id
    )
    replayed_verification = restarted.verify_submission(
        bundle.bundle_id.value,
        lease=claim.lease,
        report=report,
        idempotency_key="verify",
    )
    assert replayed_verification == verified
    assert restarted.events.count_events() == first.events.count_events()

    changed_source = "by\n  exact rfl"
    changed_submission = submission.model_copy(
        update={
            "proof_source": changed_source,
            "proof_source_hash": digest_text(HashKindV1.PROOF_SOURCE, changed_source),
        }
    )
    with pytest.raises(IdempotencyConflict):
        restarted.submit_proof(
            bundle.bundle_id.value,
            lease=claim.lease,
            submission=changed_submission,
            idempotency_key="proof",
        )


def test_concurrent_verifiers_cannot_commit_two_terminal_verdicts_for_one_proof(
    tmp_path: Path,
) -> None:
    first = _plane(tmp_path)
    second = _plane(tmp_path)
    bundle = _bundle()
    first.register_bundle(bundle, idempotency_key="register")
    claim = first.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=60,
        idempotency_key="claim",
    )
    submission = _submission(bundle)
    first.submit_proof(
        bundle.bundle_id.value,
        lease=claim.lease,
        submission=submission,
        idempotency_key="proof",
    )
    reports = (
        _passing_report(first, bundle, submission, report_key="concurrent-a"),
        _passing_report(first, bundle, submission, report_key="concurrent-b"),
    )

    def verify(index: int) -> VerificationOutcome:
        plane = first if index == 0 else second
        return plane.verify_submission(
            bundle.bundle_id.value,
            lease=claim.lease,
            report=reports[index],
            idempotency_key=f"verify-{index}",
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(verify, index) for index in range(2)]

    outcomes: list[VerificationOutcome] = []
    failures: list[InvalidTransition] = []
    for future in futures:
        try:
            outcomes.append(future.result())
        except InvalidTransition as error:
            failures.append(error)

    assert len(outcomes) == 1
    assert outcomes[0].accepted
    assert len(failures) == 1
    assert "terminal verification verdict" in str(failures[0])
    replayed = EventStore(tmp_path / "control.db").read_stream(
        "verification", submission.proof_id.value
    )
    assert len(replayed) == 1
    assert replayed[0].payload["report_id"] in {report.report_id.value for report in reports}


def test_rejected_verdict_is_terminal_for_the_proof(tmp_path: Path) -> None:
    plane = _plane(tmp_path)
    bundle = _bundle()
    plane.register_bundle(bundle, idempotency_key="register")
    claim = plane.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=60,
        idempotency_key="claim",
    )
    submission = _submission(bundle)
    plane.submit_proof(
        bundle.bundle_id.value,
        lease=claim.lease,
        submission=submission,
        idempotency_key="proof",
    )
    rejected = _passing_report(
        plane,
        bundle,
        submission,
        report_key="rejected",
        kernel_passed=False,
    )
    outcome = plane.verify_submission(
        bundle.bundle_id.value,
        lease=claim.lease,
        report=rejected,
        idempotency_key="verify-rejected",
    )
    assert not outcome.accepted

    with pytest.raises(InvalidTransition, match="terminal verification verdict"):
        plane.verify_submission(
            bundle.bundle_id.value,
            lease=claim.lease,
            report=_passing_report(plane, bundle, submission, report_key="second"),
            idempotency_key="verify-second",
        )


def test_atomic_fence_rejects_proof_write_after_handover_between_check_and_append(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock_state: dict[str, datetime] = {"now": datetime(2026, 1, 1, tzinfo=UTC)}

    def clock() -> datetime:
        return clock_state["now"]

    database = tmp_path / "control.db"
    plane = ControlPlane(
        events=EventStore(database, clock=clock),
        leases=LeaseStore(database, clock=clock),
        artifacts=ArtifactStore(tmp_path / "artifacts"),
        attestation_verifier=_attestation_verifier(clock),
        allow_test_only_direct_verifier_attestations=True,
        allow_test_only_unreviewed_bundles=True,
    )
    bundle = _bundle(signer=_builder_signer(clock))
    plane.register_bundle(bundle, idempotency_key="register")
    old_claim = plane.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=5,
        idempotency_key="claim-a",
    )
    original_assert = plane._assert_lease

    def assert_then_handover(task_id: str, lease: Lease) -> None:
        original_assert(task_id, lease)
        clock_state["now"] += timedelta(seconds=6)
        replacement = plane.leases.claim(task_id, "worker-b", ttl_seconds=5)
        assert replacement.fencing_token > lease.fencing_token

    monkeypatch.setattr(plane, "_assert_lease", assert_then_handover)
    with pytest.raises(StaleFence):
        plane.submit_proof(
            bundle.bundle_id.value,
            lease=old_claim.lease,
            submission=_submission(bundle),
            idempotency_key="old-proof",
        )
    assert plane.events.count_events(entity_type="proof") == 0


def test_atomic_fence_rejects_verdict_after_expiry_between_check_and_append(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock_state: dict[str, datetime] = {"now": datetime(2026, 1, 1, tzinfo=UTC)}

    def clock() -> datetime:
        return clock_state["now"]

    database = tmp_path / "control.db"
    plane = ControlPlane(
        events=EventStore(database, clock=clock),
        leases=LeaseStore(database, clock=clock),
        artifacts=ArtifactStore(tmp_path / "artifacts"),
        attestation_verifier=_attestation_verifier(clock),
        allow_test_only_direct_verifier_attestations=True,
        allow_test_only_unreviewed_bundles=True,
    )
    bundle = _bundle(signer=_builder_signer(clock))
    plane.register_bundle(bundle, idempotency_key="register")
    old_claim = plane.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=5,
        idempotency_key="claim-a",
    )
    submission = _submission(bundle)
    plane.submit_proof(
        bundle.bundle_id.value,
        lease=old_claim.lease,
        submission=submission,
        idempotency_key="proof",
    )
    report = _passing_report(
        plane,
        bundle,
        submission,
        report_key="fenced-verdict",
        signer=_verifier_signer(clock),
    )
    original_assert = plane._assert_lease

    def assert_then_expire(task_id: str, lease: Lease) -> None:
        original_assert(task_id, lease)
        clock_state["now"] += timedelta(seconds=6)

    monkeypatch.setattr(plane, "_assert_lease", assert_then_expire)
    with pytest.raises(StaleFence):
        plane.verify_submission(
            bundle.bundle_id.value,
            lease=old_claim.lease,
            report=report,
            idempotency_key="old-verdict",
        )
    assert plane.events.count_events(entity_type="verification") == 0


def test_concurrent_exact_bundle_registration_reuses_one_atomic_binding(
    tmp_path: Path,
) -> None:
    first = _plane(tmp_path)
    second = _plane(tmp_path)
    bundle = _bundle()
    ready = Barrier(2)

    def register(plane: ControlPlane, key: str):
        ready.wait()
        return plane.register_bundle(bundle, idempotency_key=key)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = (
            executor.submit(register, first, "register-a"),
            executor.submit(register, second, "register-b"),
        )
        bindings = tuple(future.result() for future in futures)

    assert bindings[0] == bindings[1]
    database = tmp_path / "control.db"
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM contract_revision_bindings").fetchone() == (
            1,
        )
        assert connection.execute(
            """
            SELECT COUNT(*) FROM events
            WHERE entity_type = 'task' AND event_type = 'task.registered'
            """
        ).fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM attestation_nonce_uses").fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*) FROM idempotency_records WHERE scope = 'register_bundle'"
        ).fetchone() == (2,)


def test_concurrent_distinct_bundle_ids_cannot_bind_one_contract_revision(
    tmp_path: Path,
) -> None:
    first = _plane(tmp_path)
    second = _plane(tmp_path)
    bundle_a = _bundle(bundle_key="bundle-a")
    bundle_b = _rebundle(bundle_a, bundle_key="bundle-b")
    assert bundle_a.contract.semantic_hash() == bundle_b.contract.semantic_hash()
    assert bundle_a.handoff_hash() != bundle_b.handoff_hash()
    ready = Barrier(2)

    def register(plane: ControlPlane, bundle: FormalizationTaskBundleV1, key: str):
        ready.wait()
        return plane.register_bundle(bundle, idempotency_key=key)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = (
            executor.submit(register, first, bundle_a, "register-a"),
            executor.submit(register, second, bundle_b, "register-b"),
        )

    outcomes = []
    failures: list[InvalidTransition] = []
    for future in futures:
        try:
            outcomes.append(future.result())
        except InvalidTransition as error:
            failures.append(error)

    assert len(outcomes) == 1
    assert len(failures) == 1
    assert "contract revision" in str(failures[0])
    database = tmp_path / "control.db"
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            """
            SELECT bundle_id, bundle_hash, registration_event_id
            FROM contract_revision_bindings
            """
        ).fetchone()
        assert row is not None
        accepted = bundle_a if row[0] == bundle_a.bundle_id.value else bundle_b
        assert row[0] == accepted.bundle_id.value
        assert row[1] == accepted.handoff_hash().value
        assert connection.execute(
            """
            SELECT COUNT(*) FROM events
            WHERE entity_type = 'task' AND event_type = 'task.registered'
            """
        ).fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM attestation_nonce_uses").fetchone() == (1,)


def test_restart_replays_exact_binding_and_rejects_changed_handoff_hash(
    tmp_path: Path,
) -> None:
    bundle = _bundle()
    first = _plane(tmp_path)
    registered = first.register_bundle(bundle, idempotency_key="register")

    restarted = _plane(tmp_path)
    assert restarted.register_bundle(bundle, idempotency_key="register-after-restart") == registered
    changed = _rebundle(bundle, issued_at=bundle.issued_at + timedelta(seconds=1))
    assert changed.bundle_id == bundle.bundle_id
    assert changed.handoff_hash() != bundle.handoff_hash()
    with pytest.raises(InvalidTransition, match="already bound"):
        restarted.register_bundle(changed, idempotency_key="changed-handoff")

    with sqlite3.connect(tmp_path / "control.db") as connection:
        assert connection.execute("SELECT COUNT(*) FROM contract_revision_bindings").fetchone() == (
            1,
        )
        assert connection.execute(
            """
            SELECT COUNT(*) FROM events
            WHERE entity_type = 'task' AND event_type = 'task.registered'
            """
        ).fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM attestation_nonce_uses").fetchone() == (1,)
        assert connection.execute(
            """
            SELECT COUNT(*) FROM idempotency_records
            WHERE scope = 'register_bundle' AND key = 'changed-handoff'
            """
        ).fetchone() == (0,)


def test_contract_revision_projection_rejects_update_and_delete(tmp_path: Path) -> None:
    bundle = _bundle()
    _plane(tmp_path).register_bundle(bundle, idempotency_key="register")
    database = tmp_path / "control.db"

    with (
        sqlite3.connect(database) as connection,
        pytest.raises(sqlite3.IntegrityError, match="immutable"),
    ):
        connection.execute(
            "UPDATE contract_revision_bindings SET bundle_hash = ?",
            ("f" * 64,),
        )
    with (
        sqlite3.connect(database) as connection,
        pytest.raises(sqlite3.IntegrityError, match="immutable"),
    ):
        connection.execute("DELETE FROM contract_revision_bindings")


def test_legacy_registration_event_is_backfilled_and_verified_on_restart(
    tmp_path: Path,
) -> None:
    bundle = _bundle()
    plane = _plane(tmp_path)
    registered = plane.register_bundle(bundle, idempotency_key="register")
    database = tmp_path / "control.db"
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TABLE contract_revision_bindings")

    restarted_store = EventStore(database)
    with restarted_store.connection() as connection:
        row = connection.execute(
            """
            SELECT contract_id, revision, bundle_id, bundle_hash, contract_hash
            FROM contract_revision_bindings
            """
        ).fetchone()
    assert row is not None
    assert tuple(row) == (
        registered.contract_id,
        registered.revision,
        registered.bundle_id,
        registered.bundle_hash,
        registered.contract_hash,
    )

    restarted = _plane(tmp_path)
    assert restarted.register_bundle(bundle, idempotency_key="backfilled-replay") == registered


def test_legacy_conflicting_contract_revision_events_refuse_atomic_migration(
    tmp_path: Path,
) -> None:
    database = tmp_path / "control.db"
    EventStore(database)
    bundle_a = _bundle(bundle_key="legacy-a")
    bundle_b = _rebundle(bundle_a, bundle_key="legacy-b")
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("DROP TABLE contract_revision_bindings")
        for index, bundle in enumerate((bundle_a, bundle_b), start=1):
            payload = {
                "bundle_id": bundle.bundle_id.value,
                "bundle_hash": bundle.handoff_hash().value,
                "contract_id": bundle.contract.contract_id.value,
                "revision": bundle.contract.revision,
                "contract_hash": bundle.contract.semantic_hash().value,
            }
            connection.execute(
                """
                INSERT INTO events (
                    event_id, entity_type, entity_id, entity_sequence,
                    event_type, payload_json, metadata_json, recorded_at
                ) VALUES (?, 'task', ?, 1, 'task.registered', ?, '{}', ?)
                """,
                (
                    f"legacy-registration-{index}",
                    bundle.bundle_id.value,
                    json.dumps(payload, sort_keys=True, separators=(",", ":")),
                    datetime.now(UTC).isoformat(),
                ),
            )
            connection.execute(
                """
                INSERT INTO entity_versions (entity_type, entity_id, sequence)
                VALUES ('task', ?, 1)
                """,
                (bundle.bundle_id.value,),
            )

    with pytest.raises(ProjectionError, match="duplicate contract revision"):
        EventStore(database)

    with sqlite3.connect(database) as connection:
        assert (
            connection.execute(
                """
            SELECT name FROM sqlite_master
            WHERE type = 'table' AND name = 'contract_revision_bindings'
            """
            ).fetchone()
            is None
        )


@pytest.mark.parametrize("payload_encoding", ("noncanonical", "duplicate_key"))
def test_legacy_registration_projection_rejects_ambiguous_json(
    tmp_path: Path,
    payload_encoding: str,
) -> None:
    database = tmp_path / "control.db"
    EventStore(database)
    bundle = _bundle(bundle_key=f"legacy-{payload_encoding}")
    payload = {
        "bundle_id": bundle.bundle_id.value,
        "bundle_hash": bundle.handoff_hash().value,
        "contract_id": bundle.contract.contract_id.value,
        "revision": bundle.contract.revision,
        "contract_hash": bundle.contract.semantic_hash().value,
    }
    canonical_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    if payload_encoding == "noncanonical":
        payload_json = json.dumps(payload, sort_keys=True, indent=2)
    else:
        payload_json = canonical_payload.replace(
            '"bundle_id":',
            f'"bundle_id":"{bundle.bundle_id.value}","bundle_id":',
            1,
        )

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("DROP TABLE contract_revision_bindings")
        connection.execute(
            """
            INSERT INTO events (
                event_id, entity_type, entity_id, entity_sequence,
                event_type, payload_json, metadata_json, recorded_at
            ) VALUES ('ambiguous-registration', 'task', ?, 1, 'task.registered', ?, '{}', ?)
            """,
            (
                bundle.bundle_id.value,
                payload_json,
                datetime.now(UTC).isoformat(),
            ),
        )
        connection.execute(
            """
            INSERT INTO entity_versions (entity_type, entity_id, sequence)
            VALUES ('task', ?, 1)
            """,
            (bundle.bundle_id.value,),
        )

    with pytest.raises(ProjectionError, match="not canonical JSON"):
        EventStore(database)

    with sqlite3.connect(database) as connection:
        assert (
            connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type = 'table' AND name = 'contract_revision_bindings'
                """
            ).fetchone()
            is None
        )
