from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest
from autolean_builder import (
    BuilderError,
    CandidateFormalization,
    CandidateReviewVerdict,
    FidelityEvaluation,
    FreezeRejected,
    MutationReviewVerdict,
    ObligationReviewVerdict,
    SemanticObligation,
    SemanticObligationKind,
    SemanticReviewPacket,
    SemanticReviewVerdict,
    SourcePreparationRecordV1,
    StatementFidelityHarness,
    TranslationTask,
    create_next_revision,
)
from autolean_builder.workflow import (
    _bridge_frozen_contract as bridge_frozen_contract,
)
from autolean_builder.workflow import (
    _freeze_reviewed_contract as freeze_contract,
)
from autolean_contracts import (
    AlignmentTargetV1,
    AttestationPurposeV1,
    ContractChangeRequestV1,
    ContractChangeV1,
    DecisionV1,
    EndpointClassV1,
    ExecutionGraphV1,
    FidelityEvidenceArtifactRefV1,
    FidelityRiskV1,
    FormalGraphV1,
    FormalizationTaskBundleV1,
    FormalSpecificationV1,
    GapKindV1,
    GapReportV1,
    GraphBundleV1,
    HashKindV1,
    HmacAttestationKeyV1,
    HmacAttestationSignerV1,
    HmacAttestationVerifierV1,
    LeanEnvironmentV1,
    MathematicalGraphV1,
    MathematicalSpecificationV1,
    MutationKindV1,
    MutationProbeV1,
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
    digest_model,
    digest_text,
    proof_dependency_manifest_hash,
    stable_identifier,
    verification_attestation_payload,
)
from autolean_control_plane import (
    ArtifactRef,
    ArtifactStore,
    ControlPlane,
    EventStore,
    LeaseStore,
)
from autolean_control_plane.errors import InvalidTransition
from autolean_prover.context import ContextPackBuilder, SpecialistRole
from autolean_prover.providers import (
    Capability,
    FakeProvider,
    ModelRequest,
    ProviderCapabilities,
)


def _id(key: str) -> StableIdentifierV1:
    return stable_identifier("closed-loop-fixture", key)


# These are public deterministic fixture capabilities, never production keys.
_BUILDER_KEY = HmacAttestationKeyV1(
    key_id="closed-loop-builder-test-v1",
    secret=b"closed-loop-builder-public-fixture-key",
    allowed_purposes=frozenset({AttestationPurposeV1.BUILDER_FREEZE}),
)
_VERIFIER_KEY = HmacAttestationKeyV1(
    key_id="closed-loop-verifier-test-v1",
    secret=b"closed-loop-verifier-public-fixture-key",
    allowed_purposes=frozenset({AttestationPurposeV1.VERIFICATION}),
)


_STATEMENT_V1 = """theorem bounded_witness
    (a : Type) [Nonempty a] [Finite a]
    (Noetherian : Prop) (hNoetherian : Noetherian) :
    Nonempty a ∧ Finite a ∧ Noetherian ∧
      ∀ x : Nat, ∃ y : Nat, x < y ∧ x ≤ y"""

_STATEMENT_V2 = """theorem bounded_witness
    (a : Type) [Nonempty a] [Finite a]
    (Noetherian : Prop) (hNoetherian : Noetherian) :
    Nonempty a ∧ Finite a ∧ Noetherian ∧
      ∀ x : Nat, ∃ y : Nat, x < y ∧ x + 1 ≤ y"""


def _draft(*, revision: int) -> StatementContractV1:
    is_second_revision = revision == 2
    source_text = (
        "For every natural x there is y with x < y and x + 1 <= y."
        if is_second_revision
        else "For every natural x there is y with x < y and x <= y."
    )
    normalized = (
        "For all x : Nat, there exists y : Nat with x < y and x + 1 <= y."
        if is_second_revision
        else "For all x : Nat, there exists y : Nat with x < y and x <= y."
    )
    statement = _STATEMENT_V2 if is_second_revision else _STATEMENT_V1
    elaborated = (
        "forall (alpha : Type), Nonempty alpha -> Finite alpha -> "
        "forall (Noetherian : Prop), Noetherian -> Nonempty alpha /\\ "
        "Finite alpha /\\ Noetherian /\\ forall x : Nat, exists y : Nat, "
        + ("x < y /\\ x + 1 <= y" if is_second_revision else "x < y /\\ x <= y")
    )
    source_id = _id("source")
    span = SourceSpanV1(
        span_id=_id(f"source-span-r{revision}"),
        locator=f"fixture:closed-loop:source:r{revision}",
        content_hash=digest_text(HashKindV1.SOURCE_SPAN, source_text),
        permitted_excerpt=source_text,
    )
    source = SourceRecordV1(
        source_id=source_id,
        work_id="closed-loop-cc0-fixture",
        title="Synthetic Builder-Prover closure fixture",
        version=str(revision),
        locator=f"fixture://closed-loop/source/r{revision}",
        content_hash=digest_text(HashKindV1.SOURCE_BYTES, source_text),
        spans=(span,),
    )
    rights = RightsRecordV1(
        rights_id=_id("rights"),
        source_id=source_id,
        source_license="CC0-1.0",
        overall_decision=PermissionDecisionV1.ALLOW,
        redistribution=PermissionDecisionV1.ALLOW,
        model_egress=PermissionDecisionV1.ALLOW,
        allowed_endpoint_classes=(EndpointClassV1.LOCAL,),
        reviewed_by="closed-loop-rights-fixture",
        reviewed_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    formal = FormalSpecificationV1(
        declaration_name="bounded_witness",
        namespace="AutoLean.ClosedLoop",
        lean_statement_source=statement,
        statement_source_hash=digest_text(HashKindV1.STATEMENT_SOURCE, statement),
        elaborated_type=elaborated,
        elaborated_type_hash=digest_text(HashKindV1.ELABORATED_TYPE, elaborated),
        environment=LeanEnvironmentV1(
            lean_version="v4.28.0",
            mathlib_revision="closed-loop-fixture-mathlib",
            verifier_execution_policy=OciVerifierExecutionPolicyV2(
                worker_image_digest="sha256:" + ("c" * 64),
            ),
            environment_hash=digest_text(
                HashKindV1.ENVIRONMENT,
                "closed-loop-fixture-environment",
            ),
        ),
        imports_allowlist=("Mathlib",),
    )
    return StatementContractV1(
        contract_id=_id("contract"),
        revision=revision,
        task_kind=TaskKindV1.KNOWN_THEOREM,
        source=source,
        rights=rights,
        mathematics=MathematicalSpecificationV1(
            informal_statement=source_text,
            normalized_statement=normalized,
            assumptions=("Nonempty a", "Finite a", "Noetherian"),
            quantifier_order=("forall x : Nat", "exists y : Nat"),
        ),
        formal=formal,
        alignments=(
            AlignmentTargetV1(
                source_span_id=span.span_id,
                formal_target="AutoLean.ClosedLoop.bounded_witness",
                relation="formalizes",
                confidence=1.0,
                reviewer_id="closed-loop-semantic-reviewer",
            ),
        ),
        policy=TaskPolicyV1(
            release_tier=ReleaseTierV1.CALIBRATION,
            fidelity_risk=FidelityRiskV1.L1_SIMPLE,
        ),
    )


def _obligations(contract: StatementContractV1) -> tuple[SemanticObligation, ...]:
    source_span_id = contract.source.spans[0].span_id
    final_relation = "x + 1 <= y" if contract.revision == 2 else "x <= y"
    return (
        SemanticObligation(
            obligation_id="quantifier-order",
            kind=SemanticObligationKind.QUANTIFIER_ORDER,
            description="The universal x binder precedes the existential y binder.",
            source_span_ids=(source_span_id,),
            normalized_fragment="For all x : Nat, there exists y : Nat",
            lean_fragment="∀ x : Nat, ∃ y : Nat",
        ),
        SemanticObligation(
            obligation_id="assumptions",
            kind=SemanticObligationKind.ASSUMPTION,
            description="Nonempty, finite, and Noetherian conditions remain explicit.",
            source_span_ids=(source_span_id,),
            normalized_fragment="with x < y",
            lean_fragment="[Nonempty a] [Finite a]",
        ),
        SemanticObligation(
            obligation_id="conclusion",
            kind=SemanticObligationKind.CONCLUSION,
            description="Both requested order relations remain in the conclusion.",
            source_span_ids=(source_span_id,),
            normalized_fragment=final_relation,
            lean_fragment=final_relation.replace("<=", "≤"),
        ),
        SemanticObligation(
            obligation_id="non-vacuity",
            kind=SemanticObligationKind.NON_VACUITY,
            description="Unit and True provide a concrete satisfiable instance.",
            source_span_ids=(source_span_id,),
            normalized_fragment="there exists y : Nat",
            lean_fragment="∃ y : Nat",
        ),
    )


@dataclass(slots=True)
class _Translator:
    actor_id: str
    independence_group: str

    def translate(self, task: TranslationTask) -> CandidateFormalization:
        return CandidateFormalization(
            candidate_id=f"candidate-{self.actor_id}",
            actor_id=self.actor_id,
            independence_group=self.independence_group,
            contract_id=task.contract_id,
            revision=task.revision,
            draft_contract_hash=task.draft_contract_hash,
            source_hash=task.source_hash,
            normalized_statement_sha256=task.normalized_statement_sha256,
            lean_statement_source=task.selected_lean_statement,
            reverse_rendering=task.normalized_statement,
            covered_obligation_ids=tuple(item.obligation_id for item in task.obligations),
        )


@dataclass(slots=True)
class _MutationAgent:
    actor_id: str = "closed-loop-mutation-agent"

    def generate(
        self,
        task: TranslationTask,
        selected_candidate: CandidateFormalization,
    ) -> tuple[MutationProbeV1, ...]:
        del selected_candidate
        statement = task.selected_lean_statement
        changes = {
            MutationKindV1.DROP_ASSUMPTION: statement.replace(
                "(hNoetherian : Noetherian)",
                "",
            ),
            MutationKindV1.SWAP_QUANTIFIERS: statement.replace(
                "∀ x : Nat, ∃ y : Nat",
                "∃ y : Nat, ∀ x : Nat",
            ),
            MutationKindV1.WEAKEN_RELATION: statement.replace("x < y", "x ≤ y", 1),
            MutationKindV1.REMOVE_SIDE_CONDITION: statement.replace(
                " ∧ x + 1 ≤ y" if task.revision == 2 else " ∧ x ≤ y",
                "",
            ),
            MutationKindV1.DROP_NONEMPTY: statement.replace("[Nonempty a] ", ""),
            MutationKindV1.DROP_FINITE: statement.replace("[Finite a]", ""),
            MutationKindV1.DROP_NOETHERIAN: statement.replace(
                "(Noetherian : Prop) (hNoetherian : Noetherian)",
                "",
            ),
            MutationKindV1.REVERSE_PARAMETERS: statement.replace("x < y", "y < x", 1),
            MutationKindV1.VACUITY: statement.replace(
                "(Noetherian : Prop)",
                "(Noetherian : Prop) (impossible : False)",
            ),
        }
        return tuple(
            MutationProbeV1(
                probe_id=_id(f"mutation-r{task.revision}-{kind.value}"),
                kind=kind,
                target_path="/formal/lean_statement_source",
                expected_failure="independent semantic review rejects changed meaning",
                mutated_statement_source=mutated,
            )
            for kind, mutated in changes.items()
        )


@dataclass(slots=True)
class _SemanticReviewer:
    reviewer_id: str = "closed-loop-semantic-reviewer"

    def review(self, packet: SemanticReviewPacket) -> SemanticReviewVerdict:
        candidate_verdicts = tuple(
            CandidateReviewVerdict(
                candidate_id=candidate.candidate_id,
                candidate_hash=candidate.evidence_hash,
                decision=DecisionV1.ACCEPT,
                reverse_render_equivalent=True,
                obligation_verdicts=tuple(
                    ObligationReviewVerdict(
                        obligation_id=obligation.obligation_id,
                        decision=DecisionV1.ACCEPT,
                        rationale="the synthetic CC0 fixture preserves this obligation",
                    )
                    for obligation in packet.task.obligations
                ),
                rationale="candidate bytes and reverse rendering preserve the reviewed claim",
            )
            for candidate in packet.candidates
        )
        return SemanticReviewVerdict(
            review_id=f"closed-loop-review-r{packet.task.revision}",
            reviewer_id=self.reviewer_id,
            independent=True,
            decision=DecisionV1.ACCEPT,
            source_to_normalized_equivalent=True,
            source_to_normalized_evidence="the normalized fixture preserves both relations",
            candidate_verdicts=candidate_verdicts,
            mutation_verdicts=tuple(
                MutationReviewVerdict(
                    probe_id=probe.probe_id,
                    detected=True,
                    rationale=f"{probe.kind.value} changes a reviewed semantic obligation",
                )
                for probe in packet.mutation_probes
            ),
            positive_example_valid=True,
            positive_example_evidence="alpha=Unit, Noetherian=True, and y=x+1",
            negative_example_valid=True,
            negative_example_evidence="swapped quantifiers require one y larger than every x",
            non_vacuous=True,
            non_vacuity_evidence="Unit and True satisfy every premise",
            rationale="all fixture obligations and adversarial mutations were reviewed",
        )


def _evaluation(contract: StatementContractV1) -> FidelityEvaluation:
    return StatementFidelityHarness().run(
        contract,
        obligations=_obligations(contract),
        translators=(
            _Translator("translator-a", "independence-a"),
            _Translator("translator-b", "independence-b"),
        ),
        mutation_agent=_MutationAgent(),
        reviewer=_SemanticReviewer(),
    )


def _source_preparation(contract: StatementContractV1) -> SourcePreparationRecordV1:
    content_hash = contract.semantic_hash().value
    return SourcePreparationRecordV1(
        preparation_id=stable_identifier(
            "source-preparation",
            f"{contract.contract_id.value}:revision:{contract.revision}",
        ),
        contract_id=contract.contract_id,
        revision=contract.revision,
        packet_sha256=content_hash,
        contract_sha256=digest_model(HashKindV1.CONTRACT, contract).value,
        rights_sha256=content_hash,
        spans_sha256=content_hash,
        manifest_sha256=content_hash,
        artifact_sha256=contract.source.content_hash.value,
        parent_artifact_sha256=contract.source.content_hash.value,
    )


def _graphs(*, revision: int) -> GraphBundleV1:
    return GraphBundleV1(
        mathematical=MathematicalGraphV1(
            graph_id=_id("mathematical-graph"),
            revision=revision,
        ),
        formal=FormalGraphV1(
            graph_id=_id("formal-graph"),
            revision=revision,
        ),
        execution=ExecutionGraphV1(
            graph_id=_id("execution-graph"),
            revision=revision,
        ),
    )


def _plane(tmp_path: Path) -> ControlPlane:
    database = tmp_path / "control.db"
    return ControlPlane(
        events=EventStore(database),
        leases=LeaseStore(database),
        artifacts=ArtifactStore(tmp_path / "artifacts"),
        attestation_verifier=HmacAttestationVerifierV1(
            {
                _BUILDER_KEY.key_id: _BUILDER_KEY,
                _VERIFIER_KEY.key_id: _VERIFIER_KEY,
            }
        ),
        allow_test_only_direct_verifier_attestations=True,
    )


def _review_and_bridge(
    plane: ControlPlane,
    draft: StatementContractV1,
) -> tuple[
    FidelityEvaluation,
    ArtifactRef,
    StatementContractV1,
    FormalizationTaskBundleV1,
]:
    evaluation = _evaluation(draft)
    evidence_ref = plane.artifacts.put_bytes(evaluation.render_artifact())
    frozen = freeze_contract(
        draft,
        evaluation=evaluation,
        source_preparation=_source_preparation(draft),
        frozen_by="closed-loop-builder-fixture",
    )
    bundle = bridge_frozen_contract(
        frozen,
        _graphs(revision=draft.revision),
        bundle_key=f"closed-loop-r{draft.revision}",
        fidelity_evidence=FidelityEvidenceArtifactRefV1(
            digest=evaluation.evidence_hash,
            size=evidence_ref.size,
        ),
        attestor=HmacAttestationSignerV1(_BUILDER_KEY),
        evidence_identity=evidence_ref.uri,
    )
    return evaluation, evidence_ref, frozen, bundle


def _proof_artifact_digest(event_payload: Mapping[str, object]) -> str:
    artifact = event_payload["proof_artifact"]
    assert isinstance(artifact, dict)
    digest = artifact["digest"]
    assert isinstance(digest, str)
    return digest


def _synthetic_passing_report(
    plane: ControlPlane,
    *,
    bundle: FormalizationTaskBundleV1,
    submission: ProofSubmissionV1,
    proof_artifact_digest: str,
) -> VerificationReportV1:
    """Build acceptance-shaped test evidence without claiming a Lean or OCI execution."""

    environment = bundle.contract.formal.environment
    policy = environment.verifier_execution_policy
    command_hash = digest_text(
        HashKindV1.VERIFICATION_COMMAND,
        "closed-loop-synthetic-verifier-command-v1",
    )
    observation = VerificationReportV1(
        report_id=_id("verification-report"),
        proof_id=submission.proof_id,
        contract_hash=submission.contract_hash,
        proof_boundary_hash=submission.proof_boundary_hash,
        verifier_id="closed-loop-independent-verifier",
        independent=True,
        kernel_passed=True,
        build_passed=True,
        dependency_check_passed=True,
        clean_environment=True,
        environment_hash=submission.environment_hash,
        axiom_profile=bundle.contract.policy.axiom_profile,
        details="Synthetic architecture fixture only; no Lean or OCI execution occurred.",
    )
    candidate = (
        f"{bundle.proof_boundary.trusted_statement_source} := "
        f"{submission.proof_source.rstrip()}\n"
        f"\n#print axioms {bundle.proof_boundary.expected_declaration}\n"
    )
    evidence_artifact = VerificationEvidenceArtifactV1(
        evidence_id=_id("verification-evidence"),
        bundle_id=bundle.bundle_id,
        bundle_hash=bundle.handoff_hash(),
        contract_id=bundle.contract.contract_id,
        revision=bundle.contract.revision,
        contract_hash=bundle.contract.semantic_hash(),
        proof_id=submission.proof_id,
        proof_boundary_hash=bundle.proof_boundary.boundary_hash,
        proof_submission_artifact_digest=proof_artifact_digest,
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
    )
    evidence_ref = plane.artifacts.put_json(evidence_artifact.model_dump(mode="json"))
    evidence = VerificationEvidenceV1(
        evidence_id=evidence_artifact.evidence_id,
        environment_hash=environment.environment_hash,
        worker_image_digest=policy.worker_image_digest,
        wrapper_protocol=policy.wrapper_protocol,
        lean_version=environment.lean_version,
        mathlib_revision=environment.mathlib_revision,
        lake_manifest_hash=environment.lake_manifest_hash,
        dependency_manifest_hash=proof_dependency_manifest_hash(submission),
        command_policy_hash=policy.command_policy_hash(),
        command_hash=command_hash,
        evidence_artifact_digest=evidence_ref.digest,
    )
    report = observation.model_copy(update={"evidence": evidence})
    attestation = HmacAttestationSignerV1(_VERIFIER_KEY).issue(
        purpose=AttestationPurposeV1.VERIFICATION,
        payload=verification_attestation_payload(
            bundle_id=bundle.bundle_id.value,
            bundle_hash=bundle.handoff_hash().value,
            proof_submission_artifact_digest=proof_artifact_digest,
            contract_id=bundle.contract.contract_id.value,
            revision=bundle.contract.revision,
            contract_hash=report.contract_hash,
            proof_boundary_hash=report.proof_boundary_hash,
            environment_hash=report.environment_hash,
            report=report,
        ),
        evidence_identity=evidence.evidence_id.value,
        ttl_seconds=3600,
    )
    return report.model_copy(update={"verifier_attestation": attestation})


def test_registration_requires_the_referenced_fidelity_artifact(tmp_path: Path) -> None:
    builder_plane = _plane(tmp_path / "builder")
    _evaluation_result, _evidence_ref, _frozen, bundle = _review_and_bridge(
        builder_plane,
        _draft(revision=1),
    )
    empty_registration_plane = _plane(tmp_path / "registration")

    with pytest.raises(InvalidTransition, match="fidelity artifact is unavailable"):
        empty_registration_plane.register_bundle(bundle, idempotency_key="missing-fidelity")


def test_failure_feedback_is_immutable_and_a_new_revision_restarts_builder(
    tmp_path: Path,
) -> None:
    plane = _plane(tmp_path)
    evaluation, evidence_ref, frozen_v1, bundle_v1 = _review_and_bridge(
        plane,
        _draft(revision=1),
    )
    assert evidence_ref.digest == evaluation.evidence_hash.value
    assert plane.artifacts.get_bytes(evidence_ref) == evaluation.render_artifact()
    assert plane.artifacts.put_bytes(evaluation.render_artifact()) == evidence_ref

    binding = plane.register_bundle(bundle_v1, idempotency_key="register-r1")
    event_count = plane.events.count_events()
    assert plane.register_bundle(bundle_v1, idempotency_key="register-r1") == binding
    assert plane.events.count_events() == event_count
    claim = plane.claim(
        bundle_v1.bundle_id.value,
        worker_id="closed-loop-prover-worker",
        ttl_seconds=60,
        idempotency_key="claim-r1",
    )
    old_statement = frozen_v1.formal.lean_statement_source
    old_contract_hash = frozen_v1.semantic_hash()

    gap = GapReportV1(
        report_id=_id("gap-r1"),
        contract_id=frozen_v1.contract_id,
        revision=frozen_v1.revision,
        contract_hash=old_contract_hash,
        kind=GapKindV1.BAD_STATEMENT,
        evidence="The stronger source revision may require another conclusion conjunct.",
        suggested_action="Ask Builder to review a new source-backed revision.",
        reported_by="closed-loop-prover-worker",
    )
    gap_event = plane.report_gap(
        bundle_v1.bundle_id.value,
        lease=claim.lease,
        report=gap,
        idempotency_key="gap-r1",
    )
    request = ContractChangeRequestV1(
        request_id=_id("change-r1"),
        contract_id=frozen_v1.contract_id,
        old_revision=frozen_v1.revision,
        old_contract_hash=old_contract_hash,
        proposed_changes=(
            ContractChangeV1(
                path="/formal/lean_statement_source",
                operation="replace",
                before=_STATEMENT_V1,
                after=_STATEMENT_V2,
                semantic=True,
            ),
        ),
        semantic_impact="The proposed statement strengthens the final order conjunct.",
        evidence="A source revision was supplied; Builder must decide whether it is faithful.",
        requested_by="closed-loop-prover-worker",
    )
    change_event = plane.request_contract_change(
        bundle_v1.bundle_id.value,
        lease=claim.lease,
        request=request,
        idempotency_key="change-r1",
    )
    assert gap_event.payload["contract_hash"] == old_contract_hash.value
    assert change_event.payload["old_revision"] == 1
    assert plane.get_binding(bundle_v1.bundle_id.value).contract_hash == old_contract_hash.value
    assert bundle_v1.contract.formal.lean_statement_source == old_statement
    assert bundle_v1.contract.status is StatementStatusV1.FROZEN

    draft_v2 = create_next_revision(
        frozen_v1,
        _draft(revision=2),
        request=request,
    )
    assert draft_v2.status is StatementStatusV1.DRAFT
    with pytest.raises(BuilderError, match="only a frozen contract"):
        bridge_frozen_contract(
            draft_v2,
            _graphs(revision=2),
            bundle_key="closed-loop-r2",
            fidelity_evidence=FidelityEvidenceArtifactRefV1(
                digest=evaluation.evidence_hash,
                size=evidence_ref.size,
            ),
            attestor=HmacAttestationSignerV1(_BUILDER_KEY),
            evidence_identity="unreviewed-r2",
        )
    with pytest.raises(FreezeRejected, match="another contract revision"):
        freeze_contract(
            draft_v2,
            evaluation=evaluation,
            source_preparation=_source_preparation(draft_v2),
            frozen_by="closed-loop-builder-fixture",
        )

    evaluation_v2, evidence_ref_v2, frozen_v2, bundle_v2 = _review_and_bridge(
        plane,
        draft_v2,
    )
    assert evidence_ref_v2.digest == evaluation_v2.evidence_hash.value
    assert evidence_ref_v2 != evidence_ref
    plane.register_bundle(bundle_v2, idempotency_key="register-r2")
    assert plane.get_binding(bundle_v2.bundle_id.value).revision == 2
    assert frozen_v1.formal.lean_statement_source == old_statement
    assert frozen_v1.semantic_hash() == old_contract_hash

    wrong_revision_gap = gap.model_copy(
        update={
            "report_id": _id("gap-wrong-revision"),
            "revision": 2,
            "contract_hash": frozen_v2.semantic_hash(),
        }
    )
    with pytest.raises(InvalidTransition, match="different contract revision"):
        plane.report_gap(
            bundle_v1.bundle_id.value,
            lease=claim.lease,
            report=wrong_revision_gap,
            idempotency_key="gap-wrong-revision",
        )


def test_fake_prover_uses_only_the_bridge_and_independent_acceptance_is_bound(
    tmp_path: Path,
) -> None:
    plane = _plane(tmp_path)
    evaluation, _evidence_ref, _frozen, bundle = _review_and_bridge(
        plane,
        _draft(revision=1),
    )
    plane.register_bundle(bundle, idempotency_key="register-proof")
    claim = plane.claim(
        bundle.bundle_id.value,
        worker_id="closed-loop-proof-worker",
        ttl_seconds=60,
        idempotency_key="claim-proof",
    )

    context = ContextPackBuilder().build(
        bundle,
        role=SpecialistRole.TACTIC,
        endpoint_class=EndpointClassV1.LOCAL,
    )
    assert context.contract_hash == bundle.contract.semantic_hash().value
    assert context.proof_boundary_hash == bundle.proof_boundary.boundary_hash.value
    assert evaluation.review.rationale not in context.render()
    provider = FakeProvider(
        (
            "by\n"
            "  refine ⟨inferInstance, inferInstance, hNoetherian, ?_⟩\n"
            "  intro x\n"
            "  exact ⟨x + 1, Nat.lt_succ_self x, Nat.le_succ x⟩",
        ),
        capabilities=ProviderCapabilities.of(
            Capability.TEXT_GENERATION,
            Capability.USAGE_ACCOUNTING,
        ),
    )
    response = provider.generate(ModelRequest.from_context_pack(context))
    submission = ProofSubmissionV1(
        proof_id=_id("proof-r1"),
        contract_id=bundle.contract.contract_id,
        revision=bundle.contract.revision,
        contract_hash=bundle.contract.semantic_hash(),
        proof_boundary_hash=bundle.proof_boundary.boundary_hash,
        proof_source=response.text,
        proof_source_hash=digest_text(HashKindV1.PROOF_SOURCE, response.text),
        environment_hash=bundle.contract.formal.environment.environment_hash,
    )
    proof_event = plane.submit_proof(
        bundle.bundle_id.value,
        lease=claim.lease,
        submission=submission,
        idempotency_key="submit-proof-r1",
    )
    proof_artifact_digest = _proof_artifact_digest(proof_event.payload)
    report = _synthetic_passing_report(
        plane,
        bundle=bundle,
        submission=submission,
        proof_artifact_digest=proof_artifact_digest,
    )
    outcome = plane.verify_submission(
        bundle.bundle_id.value,
        lease=claim.lease,
        report=report,
        idempotency_key="verify-proof-r1",
    )
    assert outcome.accepted
    assert outcome.event.event_type == "verification.accepted"
    assert outcome.event.payload["contract_hash"] == bundle.contract.semantic_hash().value
    assert outcome.event.payload["proof_boundary_hash"] == (
        bundle.proof_boundary.boundary_hash.value
    )
    assert "no Lean or OCI execution occurred" in report.details
