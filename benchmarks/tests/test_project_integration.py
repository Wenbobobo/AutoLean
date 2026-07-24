from __future__ import annotations

import hashlib
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
    FormalNodeKindV1,
    FormalNodeV1,
    FormalSpecificationV1,
    FreezeRecordV1,
    GraphBundleV1,
    HashKindV1,
    HmacAttestationKeyV1,
    HmacAttestationSignerV1,
    HmacAttestationVerifierV1,
    LeanEnvironmentV1,
    MathematicalGraphV1,
    MathematicalSpecificationV1,
    OciVerificationArtifactV1,
    OciVerifierExecutionPolicyV2,
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
    VerificationArtifactEnvironmentV1,
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
from autolean_control_plane import (
    ArtifactStore,
    ClaimReceipt,
    ControlPlane,
    DashboardProjection,
    EventStore,
    Lease,
    LeaseStore,
)
from autolean_control_plane.errors import LeaseUnavailable, StaleFence

from benchmarks.project_dag import ProjectNodeV1, load_default_project_dag
from benchmarks.project_integration import ProjectControlPlaneFixtureV1, ProjectIntegrationError


def _id(key: str) -> StableIdentifierV1:
    return stable_identifier("project-integration-test", key)


# These are fixed synthetic test keys.  They grant no runtime authority and are never read from
# host credentials, endpoint configuration, artifacts, or benchmark fixtures.
_BUILDER_KEY = HmacAttestationKeyV1(
    key_id="project-fixture-builder-test-v1",
    secret=b"project-fixture-builder-test-secret-0123456789",
    allowed_purposes=frozenset({AttestationPurposeV1.BUILDER_FREEZE}),
)
_VERIFIER_KEY = HmacAttestationKeyV1(
    key_id="project-fixture-verifier-test-v1",
    secret=b"project-fixture-verifier-test-secret-012345678",
    allowed_purposes=frozenset({AttestationPurposeV1.VERIFICATION}),
)


def _builder_signer(
    clock: Callable[[], datetime] | None = None,
) -> HmacAttestationSignerV1:
    return (
        HmacAttestationSignerV1(_BUILDER_KEY)
        if clock is None
        else HmacAttestationSignerV1(_BUILDER_KEY, clock=clock)
    )


def _verifier_signer(
    clock: Callable[[], datetime] | None = None,
) -> HmacAttestationSignerV1:
    return (
        HmacAttestationSignerV1(_VERIFIER_KEY)
        if clock is None
        else HmacAttestationSignerV1(_VERIFIER_KEY, clock=clock)
    )


def _attestation_verifier(
    clock: Callable[[], datetime] | None = None,
) -> HmacAttestationVerifierV1:
    keys = {
        _BUILDER_KEY.key_id: _BUILDER_KEY,
        _VERIFIER_KEY.key_id: _VERIFIER_KEY,
    }
    return (
        HmacAttestationVerifierV1(keys)
        if clock is None
        else HmacAttestationVerifierV1(
            keys,
            clock=clock,
        )
    )


def _safe_name(node_id: str) -> str:
    return node_id.replace(".", "_").replace("-", "_")


def _bundle(
    node: ProjectNodeV1,
    *,
    signer: HmacAttestationSignerV1,
) -> FormalizationTaskBundleV1:
    """Build a signed local bundle only; its cross-file topology stays in ProjectDagV1."""

    safe_name = _safe_name(node.node_id)
    source_text = f"synthetic scheduling fixture declaration {node.node_id}"
    source_id = _id(f"source:{node.node_id}")
    span = SourceSpanV1(
        span_id=_id(f"span:{node.node_id}"),
        locator=f"fixture:{node.source_file}:{node.node_id}",
        content_hash=digest_text(HashKindV1.SOURCE_SPAN, source_text),
        permitted_excerpt=source_text,
    )
    source = SourceRecordV1(
        source_id=source_id,
        work_id="autolean-project-integration-fixture",
        title="Synthetic 20-node scheduling fixture",
        version="1",
        locator=f"fixture://{node.source_file}/{node.node_id}",
        content_hash=digest_text(HashKindV1.SOURCE_BYTES, source_text),
        spans=(span,),
    )
    rights = RightsRecordV1(
        rights_id=_id(f"rights:{node.node_id}"),
        source_id=source_id,
        source_license="CC0-1.0",
        overall_decision=PermissionDecisionV1.ALLOW,
        reviewed_by="project-integration-test",
        reviewed_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    statement = f"theorem {safe_name} (n : Nat) : n = n"
    elaborated_type = "forall (n : Nat), Eq n n"
    formal = FormalSpecificationV1(
        declaration_name=safe_name,
        namespace="ProjectFixture",
        lean_statement_source=statement,
        statement_source_hash=digest_text(HashKindV1.STATEMENT_SOURCE, statement),
        elaborated_type=elaborated_type,
        elaborated_type_hash=digest_text(HashKindV1.ELABORATED_TYPE, elaborated_type),
        environment=LeanEnvironmentV1(
            lean_version="v4.28.0",
            mathlib_revision="project-fixture-mathlib",
            verifier_execution_policy=OciVerifierExecutionPolicyV2(
                worker_image_digest="sha256:" + ("2" * 64),
            ),
            environment_hash=digest_text(HashKindV1.ENVIRONMENT, "project-fixture-environment"),
        ),
    )
    draft = StatementContractV1(
        contract_id=_id(f"contract:{node.node_id}"),
        revision=1,
        task_kind=TaskKindV1.KNOWN_THEOREM,
        source=source,
        rights=rights,
        mathematics=MathematicalSpecificationV1(
            informal_statement=f"The synthetic declaration for {node.node_id} is reflexive.",
            normalized_statement=f"For every natural n, the fixture {node.node_id} has n = n.",
        ),
        formal=formal,
        alignments=(
            AlignmentTargetV1(
                source_span_id=span.span_id,
                formal_target=f"ProjectFixture.{safe_name}",
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
                    "source-preparation", f"project-integration:{node.node_id}"
                ),
                source_preparation_hash=digest_text(
                    HashKindV1.SOURCE_PREPARATION, f"project-integration:{node.node_id}"
                ),
                statement_source_hash=formal.statement_source_hash,
                elaborated_type_hash=formal.elaborated_type_hash,
                frozen_by="project-integration-test",
            ),
        }
    )
    frozen = StatementContractV1.model_validate(frozen_payload)

    # A project edge must not be represented as an execution edge or copied into another graph.
    # The sole local formal node carries the mapping back to the immutable ProjectDagV1 manifest.
    graphs = GraphBundleV1(
        mathematical=MathematicalGraphV1(
            graph_id=_id(f"math-graph:{node.node_id}"),
            revision=1,
        ),
        formal=FormalGraphV1(
            graph_id=_id(f"formal-graph:{node.node_id}"),
            revision=1,
            nodes=(
                FormalNodeV1(
                    node_id=_id(f"formal-node:{node.node_id}"),
                    kind=FormalNodeKindV1.THEOREM,
                    declaration_name=f"ProjectFixture.{safe_name}",
                    metadata={
                        "project_fixture_node_id": node.node_id,
                        "source_file": node.source_file,
                    },
                ),
            ),
        ),
        execution=ExecutionGraphV1(
            graph_id=_id(f"execution-graph:{node.node_id}"),
            revision=1,
        ),
    )
    unsigned = FormalizationTaskBundleV1(
        bundle_id=_id(f"bundle:{node.node_id}"),
        contract=frozen,
        graphs=graphs,
        graph_snapshot_hash=digest_model(HashKindV1.GRAPH_SNAPSHOT, graphs),
        proof_boundary=build_proof_boundary(frozen),
    )
    attestation = signer.issue(
        purpose=AttestationPurposeV1.BUILDER_FREEZE,
        payload=builder_attestation_payload(unsigned),
        evidence_identity=f"fixture-builder-{safe_name}",
        ttl_seconds=3600,
        nonce=f"fixture-builder-{safe_name}",
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


def _fixture(
    tmp_path: Path,
    *,
    clock: Callable[[], datetime] | None = None,
) -> ProjectControlPlaneFixtureV1:
    dag = load_default_project_dag()
    signer = _builder_signer(clock)
    return ProjectControlPlaneFixtureV1(
        dag=dag,
        plane=_plane(tmp_path, clock=clock),
        bundles={node.node_id: _bundle(node, signer=signer) for node in dag.nodes},
        run_id="integration-test-run",
    )


def _submission(
    bundle: FormalizationTaskBundleV1,
    node_id: str,
    *,
    suffix: str = "primary",
) -> ProofSubmissionV1:
    source = "by\n  rfl"
    return ProofSubmissionV1(
        proof_id=_id(f"proof:{node_id}:{suffix}"),
        contract_id=bundle.contract.contract_id,
        revision=bundle.contract.revision,
        contract_hash=bundle.contract.semantic_hash(),
        proof_boundary_hash=bundle.proof_boundary.boundary_hash,
        proof_source=source,
        proof_source_hash=digest_text(HashKindV1.PROOF_SOURCE, source),
        environment_hash=bundle.contract.formal.environment.environment_hash,
    )


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


def _synthetic_passing_report(
    plane: ControlPlane,
    bundle: FormalizationTaskBundleV1,
    submission: ProofSubmissionV1,
    *,
    report_key: str,
    signer: HmacAttestationSignerV1,
) -> VerificationReportV1:
    """Create test-only acceptance-shaped evidence; it deliberately does not run Lean."""

    environment = bundle.contract.formal.environment
    policy = environment.verifier_execution_policy
    command_hash = digest_text(
        HashKindV1.VERIFICATION_COMMAND,
        "synthetic-project-integration-fixture-command-v1",
    )
    observation = VerificationReportV1(
        report_id=_id(f"verification:{report_key}"),
        proof_id=submission.proof_id,
        contract_hash=submission.contract_hash,
        proof_boundary_hash=submission.proof_boundary_hash,
        verifier_id="synthetic-project-fixture-verifier",
        independent=True,
        kernel_passed=True,
        build_passed=True,
        dependency_check_passed=True,
        clean_environment=True,
        environment_hash=submission.environment_hash,
        axiom_profile=bundle.contract.policy.axiom_profile,
        details=(
            "Synthetic control-plane fixture acceptance shape; no Lean or OCI execution occurred."
        ),
    )
    candidate = (
        f"{bundle.proof_boundary.trusted_statement_source} := {submission.proof_source.rstrip()}\n"
        f"\n#print axioms {bundle.proof_boundary.expected_declaration}\n"
    )
    evidence_artifact = plane.artifacts.put_json(
        VerificationEvidenceArtifactV1(
            evidence_id=_id(f"evidence:{report_key}"),
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
            environment=VerificationArtifactEnvironmentV1(
                environment_hash=environment.environment_hash,
                lean_version=environment.lean_version,
                mathlib_revision=environment.mathlib_revision,
                lake_manifest_hash=environment.lake_manifest_hash,
            ),
            oci=OciVerificationArtifactV1(
                worker_image_digest=policy.worker_image_digest,
                wrapper_protocol=policy.wrapper_protocol,
                command_policy_hash=policy.command_policy_hash(),
                command_hash=command_hash,
                candidate_sha256=hashlib.sha256(candidate.encode("utf-8")).hexdigest(),
                trusted_statement_sha256=bundle.proof_boundary.trusted_statement_hash.value,
                bundle_manifest_sha256=bundle.proof_boundary.solver_manifest_hash.value,
            ),
        ).model_dump(mode="json")
    )
    evidence = VerificationEvidenceV1(
        evidence_id=_id(f"evidence:{report_key}"),
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
    report = observation.model_copy(update={"evidence": evidence})
    attestation = signer.issue(
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
        evidence_identity=evidence.evidence_id.value,
        ttl_seconds=3600,
        nonce=f"fixture-verifier-{report_key}",
    )
    return report.model_copy(update={"verifier_attestation": attestation})


def _accept_node(
    fixture: ProjectControlPlaneFixtureV1,
    node_id: str,
    *,
    worker_id: str,
) -> None:
    receipt = fixture.claim_frontier(node_id, worker_id=worker_id, ttl_seconds=60)
    bundle = fixture.bundles[node_id]
    submission = _submission(bundle, node_id)
    fixture.submit_proof(node_id, lease=receipt.lease, submission=submission)
    outcome = fixture.verify_submission(
        node_id,
        lease=receipt.lease,
        report=_synthetic_passing_report(
            fixture.plane,
            bundle,
            submission,
            report_key=f"{_safe_name(node_id)}-primary",
            signer=_verifier_signer(),
        ),
    )
    assert outcome.accepted


def test_formal_frontier_blocks_non_frontier_and_progresses_after_prerequisite(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    fixture.register_all()

    assert {node.node_id for node in fixture.formal_frontier()} == {"base.nat"}
    with pytest.raises(ProjectIntegrationError, match="formal dependency frontier"):
        fixture.claim_frontier("algebra.semiring", worker_id="out-of-order", ttl_seconds=60)

    _accept_node(fixture, "base.nat", worker_id="worker-base")

    assert {node.node_id for node in fixture.formal_frontier()} == {
        "base.add",
        "base.mul",
        "base.order",
    }
    snapshot = fixture.status_projection()
    assert snapshot.by_node_id["base.nat"].execution_status == "verified"
    assert snapshot.by_node_id["base.add"].execution_status == "ready"
    assert snapshot.lean_compilation_executed is False


def test_concurrent_workers_receive_one_lease_and_loser_cannot_submit(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    fixture.register_all()
    barrier = Barrier(2)

    def claim(worker_id: str) -> tuple[str, object]:
        barrier.wait()
        try:
            return (
                worker_id,
                fixture.claim_frontier("base.nat", worker_id=worker_id, ttl_seconds=60),
            )
        except LeaseUnavailable as error:
            return worker_id, error

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(claim, ("worker-a", "worker-b")))

    winners = [
        (worker_id, value) for worker_id, value in outcomes if not isinstance(value, Exception)
    ]
    losers = [(worker_id, value) for worker_id, value in outcomes if isinstance(value, Exception)]
    assert len(winners) == 1
    assert len(losers) == 1
    winner_id, receipt = winners[0]
    loser_id, error = losers[0]
    assert isinstance(receipt, ClaimReceipt)
    assert isinstance(error, LeaseUnavailable)

    # The losing worker has no receipt.  Even a forged lease with the winner's fence cannot write.
    winner_lease = receipt.lease
    forged_loser_lease = Lease(
        job_id=winner_lease.job_id,
        holder_id=loser_id,
        fencing_token=winner_lease.fencing_token,
        expires_at=winner_lease.expires_at,
    )
    loser_submission = _submission(fixture.bundles["base.nat"], "base.nat", suffix="loser")
    with pytest.raises(StaleFence):
        fixture.submit_proof("base.nat", lease=forged_loser_lease, submission=loser_submission)
    assert fixture.plane.events.count_events(entity_type="proof") == 0

    winner_submission = _submission(fixture.bundles["base.nat"], "base.nat", suffix=winner_id)
    fixture.submit_proof("base.nat", lease=winner_lease, submission=winner_submission)
    assert fixture.plane.events.count_events(entity_type="proof") == 1


def test_api_change_invalidates_exact_formal_reverse_closure_without_graph_mixing(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    fixture.register_all()
    _accept_node(fixture, "base.nat", worker_id="worker-nat")
    _accept_node(fixture, "base.add", worker_id="worker-add")
    _accept_node(fixture, "base.mul", worker_id="worker-mul")
    _accept_node(fixture, "algebra.semiring", worker_id="worker-semiring")

    formal_before = tuple((node.node_id, node.depends_on) for node in fixture.dag.nodes)
    event = fixture.replan_for_api_change(
        frozenset({"algebra.semiring"}),
        change_id="semiring-signature-v2",
    )
    expected = tuple(
        node.node_id for node in fixture.dag.affected_by(frozenset({"algebra.semiring"}))
    )
    assert event.payload["formal_reverse_closure_node_ids"] == list(expected)
    assert event.payload["execution_effect"] == "invalidate_and_replan"
    assert event.payload["lean_compilation_executed"] is False

    snapshot = fixture.status_projection()
    invalidated = {
        node_id
        for node_id, state in snapshot.by_node_id.items()
        if state.execution_status == "invalidated"
    }
    assert invalidated == set(expected)
    assert snapshot.by_node_id["base.add"].execution_status == "verified"
    assert tuple((node.node_id, node.depends_on) for node in fixture.dag.nodes) == formal_before
    assert all(not bundle.graphs.mathematical.nodes for bundle in fixture.bundles.values())
    assert all(not bundle.graphs.execution.nodes for bundle in fixture.bundles.values())

    frontier = {node.node_id for node in fixture.formal_frontier()}
    assert "algebra.semiring" in frontier
    assert "algebra.pow" not in frontier


def test_expired_fixture_lease_cannot_submit_after_replacement(tmp_path: Path) -> None:
    clock_state = {"now": datetime(2026, 1, 1, tzinfo=UTC)}

    def clock() -> datetime:
        return clock_state["now"]

    fixture = _fixture(tmp_path, clock=clock)
    fixture.register_all()
    old_claim = fixture.claim_frontier("base.nat", worker_id="worker-old", ttl_seconds=1)

    clock_state["now"] += timedelta(seconds=2)
    replacement = fixture.claim_frontier("base.nat", worker_id="worker-new", ttl_seconds=60)
    assert replacement.lease.fencing_token > old_claim.lease.fencing_token
    with pytest.raises(StaleFence):
        fixture.submit_proof(
            "base.nat",
            lease=old_claim.lease,
            submission=_submission(fixture.bundles["base.nat"], "base.nat", suffix="stale"),
        )
    assert fixture.plane.events.count_events(entity_type="proof") == 0


def test_twenty_nodes_multiple_files_are_visible_in_projection_and_events(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    first_bindings = fixture.register_all()
    event_count_before_retry = fixture.plane.events.count_events()
    assert fixture.register_all() == first_bindings
    assert fixture.plane.events.count_events() == event_count_before_retry

    snapshot = fixture.status_projection()
    assert len(snapshot.nodes) == 20
    assert {node.node_id for node in snapshot.nodes} == set(fixture.dag.by_id)
    assert {node.source_file for node in snapshot.nodes} == {
        "Base.lean",
        "Algebra.lean",
        "Structure.lean",
        "Lemmas.lean",
        "Target.lean",
    }
    assert all(
        snapshot.by_node_id[node.node_id].formal_dependencies == node.depends_on
        for node in fixture.dag.nodes
    )
    assert snapshot.by_node_id["base.nat"].execution_status == "ready"
    assert snapshot.relevant_event_count == 21
    assert snapshot.lean_compilation_executed is False

    dashboard = DashboardProjection(fixture.plane.events.read_all()).snapshot()
    dashboard_nodes = dashboard["nodes"]
    assert isinstance(dashboard_nodes, list)
    formal_nodes = [
        node for node in dashboard_nodes if isinstance(node, dict) and node.get("graph") == "formal"
    ]
    assert len(formal_nodes) == 20
    formal_labels = {
        label for node in formal_nodes if isinstance((label := node.get("label")), str)
    }
    assert len(formal_labels) == len(formal_nodes)
    assert formal_labels == {
        f"ProjectFixture.{_safe_name(node.node_id)}" for node in fixture.dag.nodes
    }
    assert fixture.plane.events.count_events(entity_type="task") == 20

    manifest = fixture.project_events()[0]
    assert manifest.event_type == "project.integration.registered"
    formal_manifest = manifest.payload["formal_graph_nodes"]
    assert isinstance(formal_manifest, list)
    assert len(formal_manifest) == 20
    assert manifest.payload["mathematical_graph"] == "not_modeled_by_project_fixture"
    assert manifest.payload["execution_graph"] == "derived_only_from_append_only_events"
