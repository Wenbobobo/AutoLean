from __future__ import annotations

import json
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import TypedDict, cast

import pytest
from autolean_builder import (
    BuilderCase,
    BuilderError,
    BuilderStage,
    CandidateFormalization,
    CandidateReviewVerdict,
    EvidenceAuthority,
    FidelityHarnessError,
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
    AmbiguitySeverityV1,
    AmbiguityV1,
    AttestationPurposeV1,
    DecisionV1,
    ExecutionGraphV1,
    FidelityEvidenceArtifactRefV1,
    FormalGraphV1,
    FormalSpecificationV1,
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
    OciVerifierExecutionPolicyV1,
    PermissionDecisionV1,
    ReleaseTierV1,
    ReviewerRoleV1,
    ReviewerSignoffV1,
    RightsRecordV1,
    SourceRecordV1,
    SourceSpanV1,
    StatementContractV1,
    StatementStatusV1,
    TaskKindV1,
    TaskPolicyV1,
    builder_attestation_payload,
    digest_bytes,
    digest_model,
    digest_text,
    stable_identifier,
)


class ObligationFixture(TypedDict):
    obligation_id: str
    kind: str
    description: str
    normalized_fragment: str
    lean_fragment: str


class MutationFixture(TypedDict):
    kind: str
    target_path: str
    mutated_statement_source: str


class GoldenFixture(TypedDict):
    source_excerpt: str
    normalized_statement: str
    lean_statement: str
    reverse_rendering: str
    obligations: list[ObligationFixture]
    mutations: list[MutationFixture]


def _golden() -> GoldenFixture:
    path = Path(__file__).parent / "fixtures" / "statement_fidelity_golden.json"
    return cast(GoldenFixture, json.loads(path.read_text(encoding="utf-8")))


def _id(key: str):
    return stable_identifier("builder-test", key)


def _builder_key() -> HmacAttestationKeyV1:
    return HmacAttestationKeyV1(
        key_id="builder-test-v1",
        secret=b"builder-test-secret-material-0123456789",
        allowed_purposes=frozenset({AttestationPurposeV1.BUILDER_FREEZE}),
    )


def _contract() -> StatementContractV1:
    golden = _golden()
    source_id = _id("source")
    span = SourceSpanV1(
        span_id=_id("span"),
        locator="fixture:statement_fidelity_golden.json",
        content_hash=digest_text(HashKindV1.SOURCE_SPAN, golden["source_excerpt"]),
        permitted_excerpt=golden["source_excerpt"],
    )
    source = SourceRecordV1(
        source_id=source_id,
        work_id="builder-golden-fixture",
        title="Synthetic statement fidelity fixture",
        version="1",
        locator="fixture:statement_fidelity_golden.json",
        content_hash=digest_text(HashKindV1.SOURCE_BYTES, golden["source_excerpt"]),
        spans=(span,),
    )
    rights = RightsRecordV1(
        rights_id=_id("rights"),
        source_id=source_id,
        source_license="CC0-1.0",
        overall_decision=PermissionDecisionV1.ALLOW,
        redistribution=PermissionDecisionV1.ALLOW,
        model_egress=PermissionDecisionV1.ALLOW,
        allowed_endpoint_classes=("local", "approved_external"),
        reviewed_by="rights-reviewer",
        reviewed_at=datetime.now(UTC),
    )
    statement = golden["lean_statement"]
    elaborated = (
        "forall (alpha : Type), Nonempty alpha -> Finite alpha -> "
        "forall (Noetherian : Prop), Noetherian -> Nonempty alpha /\\ "
        "Finite alpha /\\ Noetherian /\\ forall x : Nat, exists y : Nat, "
        "x < y /\\ x <= y"
    )
    formal = FormalSpecificationV1(
        declaration_name="bounded_witness",
        namespace="AutoLean.BuilderFixture",
        lean_statement_source=statement,
        statement_source_hash=digest_text(HashKindV1.STATEMENT_SOURCE, statement),
        elaborated_type=elaborated,
        elaborated_type_hash=digest_text(HashKindV1.ELABORATED_TYPE, elaborated),
        environment=LeanEnvironmentV1(
            lean_version="v4.28.0",
            mathlib_revision="test-mathlib",
            verifier_execution_policy=OciVerifierExecutionPolicyV1(
                worker_image_digest="sha256:" + "b" * 64,
            ),
            environment_hash=digest_text(HashKindV1.ENVIRONMENT, "test-environment"),
        ),
        imports_allowlist=("Mathlib",),
    )
    return StatementContractV1(
        contract_id=_id("contract"),
        revision=1,
        task_kind=TaskKindV1.KNOWN_THEOREM,
        source=source,
        rights=rights,
        mathematics=MathematicalSpecificationV1(
            informal_statement=golden["source_excerpt"],
            normalized_statement=golden["normalized_statement"],
            assumptions=("Nonempty alpha", "Finite alpha", "Noetherian"),
            quantifier_order=("forall x : Nat", "exists y : Nat"),
            ambiguities=(
                AmbiguityV1(
                    ambiguity_id=_id("noetherian-name"),
                    description="Noetherian is a named synthetic proposition in this fixture.",
                    severity=AmbiguitySeverityV1.INFORMATIONAL,
                ),
            ),
        ),
        formal=formal,
        alignments=(
            AlignmentTargetV1(
                source_span_id=span.span_id,
                formal_target="AutoLean.BuilderFixture.bounded_witness",
                relation="formalizes",
                confidence=1.0,
                reviewer_id="semantic-reviewer",
            ),
        ),
        policy=TaskPolicyV1(
            release_tier=ReleaseTierV1.CALIBRATION,
            fidelity_risk="l1_simple",
        ),
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


def _obligations(contract: StatementContractV1) -> tuple[SemanticObligation, ...]:
    source_span = contract.source.spans[0].span_id
    return tuple(
        SemanticObligation(
            obligation_id=item["obligation_id"],
            kind=SemanticObligationKind(item["kind"]),
            description=item["description"],
            source_span_ids=(source_span,),
            normalized_fragment=item["normalized_fragment"],
            lean_fragment=item["lean_fragment"],
        )
        for item in _golden()["obligations"]
    )


@dataclass(frozen=True, slots=True)
class FakeTranslationAgent:
    actor_id: str
    independence_group: str
    candidate_id: str
    corrupt_normalized_binding: bool = False

    def translate(self, task: TranslationTask) -> CandidateFormalization:
        normalized_hash = (
            "0" * 64 if self.corrupt_normalized_binding else task.normalized_statement_sha256
        )
        return CandidateFormalization(
            candidate_id=self.candidate_id,
            actor_id=self.actor_id,
            independence_group=self.independence_group,
            contract_id=task.contract_id,
            revision=task.revision,
            draft_contract_hash=task.draft_contract_hash,
            source_hash=task.source_hash,
            normalized_statement_sha256=normalized_hash,
            lean_statement_source=task.selected_lean_statement,
            reverse_rendering=_golden()["reverse_rendering"],
            covered_obligation_ids=tuple(item.obligation_id for item in task.obligations),
        )


@dataclass(frozen=True, slots=True)
class FakeMutationSuiteAgent:
    actor_id: str = "mutation-suite-fixture"
    omit_kind: MutationKindV1 | None = None

    def generate(
        self,
        task: TranslationTask,
        selected_candidate: CandidateFormalization,
    ) -> tuple[MutationProbeV1, ...]:
        assert selected_candidate.statement_hash == task.selected_statement_hash
        return tuple(
            MutationProbeV1(
                probe_id=_id(f"mutation-{item['kind']}"),
                kind=MutationKindV1(item["kind"]),
                target_path=item["target_path"],
                expected_failure="independent semantic reviewer rejects the mutation",
                mutated_statement_source=item["mutated_statement_source"],
            )
            for item in _golden()["mutations"]
            if MutationKindV1(item["kind"]) is not self.omit_kind
        )


@dataclass(frozen=True, slots=True)
class FakeSemanticReviewer:
    reviewer_id: str = "independent-semantic-reviewer"
    false_negative_kind: MutationKindV1 | None = None
    independent: bool = True

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
                        rationale="golden source, normalized text, and Lean fragment agree",
                    )
                    for obligation in packet.task.obligations
                ),
                rationale="candidate preserves the reviewed mathematical claim",
            )
            for candidate in packet.candidates
        )
        mutation_verdicts = tuple(
            MutationReviewVerdict(
                probe_id=probe.probe_id,
                detected=probe.kind is not self.false_negative_kind,
                rationale=(
                    "mutation was not distinguished from the frozen claim"
                    if probe.kind is self.false_negative_kind
                    else "mutation changes a reviewed semantic obligation"
                ),
            )
            for probe in packet.mutation_probes
        )
        return SemanticReviewVerdict(
            review_id="golden-semantic-review-v1",
            reviewer_id=self.reviewer_id,
            independent=self.independent,
            decision=DecisionV1.ACCEPT,
            source_to_normalized_equivalent=True,
            source_to_normalized_evidence="the normalized text preserves every cited condition",
            candidate_verdicts=candidate_verdicts,
            mutation_verdicts=mutation_verdicts,
            positive_example_valid=True,
            positive_example_evidence="alpha=Unit, Noetherian=True, y=x+1",
            negative_example_valid=True,
            negative_example_evidence="the swapped quantifier claim has no finite global bound",
            non_vacuous=True,
            non_vacuity_evidence="Unit and True jointly witness all premises",
            rationale="the complete statement translation is accepted",
        )


def _translators() -> tuple[FakeTranslationAgent, ...]:
    return (
        FakeTranslationAgent("translator-a", "team-a", "candidate-a"),
        FakeTranslationAgent("translator-b", "team-b", "candidate-b"),
    )


def _evaluation(
    contract: StatementContractV1 | None = None,
    *,
    false_negative_kind: MutationKindV1 | None = None,
):
    active_contract = contract or _contract()
    return StatementFidelityHarness().run(
        active_contract,
        obligations=_obligations(active_contract),
        translators=_translators(),
        mutation_agent=FakeMutationSuiteAgent(),
        reviewer=FakeSemanticReviewer(false_negative_kind=false_negative_kind),
    )


def test_harness_freeze_and_bridge_preserve_the_reviewed_boundary() -> None:
    draft = _contract()
    evaluation = _evaluation(draft)
    preparation = _source_preparation(draft)
    frozen = freeze_contract(
        draft,
        evaluation=evaluation,
        source_preparation=preparation,
        frozen_by="builder-service",
    )
    assert draft.status is StatementStatusV1.DRAFT
    assert frozen.status is StatementStatusV1.FROZEN
    assert frozen.freeze is not None
    assert frozen.freeze.contract_hash == frozen.semantic_hash()
    assert frozen.freeze.source_preparation_id == preparation.preparation_id
    assert frozen.freeze.source_preparation_hash == preparation.artifact_digest()
    assert frozen.fidelity == evaluation.report
    assert all(
        item.authority is EvidenceAuthority.AUTOMATIC for item in evaluation.automatic_checks
    )
    assert (
        digest_bytes(HashKindV1.FREEZE_EVIDENCE, evaluation.render_artifact())
        == evaluation.evidence_hash
    )
    assert {item.reviewer_id for item in evaluation.report.checks} == {
        "independent-semantic-reviewer"
    }

    graphs = GraphBundleV1(
        mathematical=MathematicalGraphV1(graph_id=_id("math"), revision=1),
        formal=FormalGraphV1(graph_id=_id("formal"), revision=1),
        execution=ExecutionGraphV1(graph_id=_id("execution"), revision=1),
    )
    key = _builder_key()
    bundle = bridge_frozen_contract(
        frozen,
        graphs,
        bundle_key="test-bundle",
        fidelity_evidence=FidelityEvidenceArtifactRefV1(
            digest=evaluation.evidence_hash,
            size=len(evaluation.render_artifact()),
        ),
        attestor=HmacAttestationSignerV1(key),
        evidence_identity="builder-test-freeze-run",
    )
    assert bundle.fidelity_evidence is not None
    assert bundle.fidelity_evidence.digest == evaluation.evidence_hash
    assert bundle.contract.formal.lean_statement_source == draft.formal.lean_statement_source
    assert bundle.builder_attestation is not None
    HmacAttestationVerifierV1({key.key_id: key}).verify(
        bundle.builder_attestation,
        expected_purpose=AttestationPurposeV1.BUILDER_FREEZE,
        payload=builder_attestation_payload(bundle),
    )


def test_freeze_rejects_source_preparation_for_another_contract_state() -> None:
    draft = _contract()
    evaluation = _evaluation(draft)
    preparation = _source_preparation(draft)

    with pytest.raises(FreezeRejected, match="another contract ID"):
        freeze_contract(
            draft,
            evaluation=evaluation,
            source_preparation=replace(
                preparation,
                contract_id=_id("different-contract"),
            ),
            frozen_by="builder-service",
        )
    with pytest.raises(FreezeRejected, match="another contract revision"):
        freeze_contract(
            draft,
            evaluation=evaluation,
            source_preparation=replace(preparation, revision=draft.revision + 1),
            frozen_by="builder-service",
        )
    with pytest.raises(FreezeRejected, match="another contract hash"):
        freeze_contract(
            draft,
            evaluation=evaluation,
            source_preparation=replace(preparation, contract_sha256="0" * 64),
            frozen_by="builder-service",
        )


def test_bridge_rejects_legacy_freeze_without_source_preparation_commitment() -> None:
    draft = _contract()
    evaluation = _evaluation(draft)
    frozen = freeze_contract(
        draft,
        evaluation=evaluation,
        source_preparation=_source_preparation(draft),
        frozen_by="builder-service",
    )
    assert frozen.freeze is not None
    legacy = frozen.model_copy(
        update={
            "freeze": frozen.freeze.model_copy(
                update={
                    "source_preparation_id": None,
                    "source_preparation_hash": None,
                }
            )
        }
    )
    graphs = GraphBundleV1(
        mathematical=MathematicalGraphV1(graph_id=_id("legacy-math"), revision=1),
        formal=FormalGraphV1(graph_id=_id("legacy-formal"), revision=1),
        execution=ExecutionGraphV1(graph_id=_id("legacy-execution"), revision=1),
    )

    with pytest.raises(BuilderError, match="requires source-preparation evidence"):
        bridge_frozen_contract(
            legacy,
            graphs,
            bundle_key="legacy-source-preparation",
            fidelity_evidence=FidelityEvidenceArtifactRefV1(
                digest=evaluation.evidence_hash,
                size=len(evaluation.render_artifact()),
            ),
            attestor=HmacAttestationSignerV1(_builder_key()),
            evidence_identity="legacy-source-preparation",
        )


@pytest.mark.parametrize(
    "kind",
    tuple(MutationKindV1(item["kind"]) for item in _golden()["mutations"]),
)
def test_false_negative_mutation_golden_blocks_freeze(kind: MutationKindV1) -> None:
    draft = _contract()
    evaluation = _evaluation(draft, false_negative_kind=kind)
    result = next(item for item in evaluation.report.mutation_results if item.probe.kind is kind)
    assert not result.detected
    with pytest.raises(FreezeRejected, match=kind.value):
        freeze_contract(
            draft,
            evaluation=evaluation,
            source_preparation=_source_preparation(draft),
            frozen_by="builder-service",
        )


def test_harness_rejects_candidate_bound_to_another_normalized_statement() -> None:
    contract = _contract()
    translators = (
        FakeTranslationAgent(
            "translator-a",
            "team-a",
            "candidate-a",
            corrupt_normalized_binding=True,
        ),
        FakeTranslationAgent("translator-b", "team-b", "candidate-b"),
    )
    with pytest.raises(FidelityHarnessError, match="not bound"):
        StatementFidelityHarness().run(
            contract,
            obligations=_obligations(contract),
            translators=translators,
            mutation_agent=FakeMutationSuiteAgent(),
            reviewer=FakeSemanticReviewer(),
        )


def test_harness_rejects_an_incomplete_mutation_suite() -> None:
    contract = _contract()
    with pytest.raises(FidelityHarnessError, match="drop_noetherian"):
        StatementFidelityHarness().run(
            contract,
            obligations=_obligations(contract),
            translators=_translators(),
            mutation_agent=FakeMutationSuiteAgent(omit_kind=MutationKindV1.DROP_NOETHERIAN),
            reviewer=FakeSemanticReviewer(),
        )


def test_harness_requires_an_independent_semantic_reviewer() -> None:
    contract = _contract()
    with pytest.raises(FidelityHarnessError, match="independently authored"):
        StatementFidelityHarness().run(
            contract,
            obligations=_obligations(contract),
            translators=_translators(),
            mutation_agent=FakeMutationSuiteAgent(),
            reviewer=FakeSemanticReviewer(independent=False),
        )


@pytest.mark.parametrize("reviewer_id", ("translator-a", "mutation-suite-fixture"))
def test_harness_rejects_declared_reviewer_role_overlap(reviewer_id: str) -> None:
    contract = _contract()
    with pytest.raises(FidelityHarnessError, match="reviewer identity must differ"):
        StatementFidelityHarness().run(
            contract,
            obligations=_obligations(contract),
            translators=_translators(),
            mutation_agent=FakeMutationSuiteAgent(),
            reviewer=FakeSemanticReviewer(reviewer_id=reviewer_id),
        )


def test_harness_rejects_translation_and_mutation_actor_overlap() -> None:
    contract = _contract()
    with pytest.raises(FidelityHarnessError, match="mutation agent identity must differ"):
        StatementFidelityHarness().run(
            contract,
            obligations=_obligations(contract),
            translators=_translators(),
            mutation_agent=FakeMutationSuiteAgent(actor_id="translator-a"),
            reviewer=FakeSemanticReviewer(),
        )


def test_harness_rejects_one_identity_for_independent_review_roles() -> None:
    contract = _contract()
    duplicate_reviewer = ReviewerSignoffV1(
        signoff_id=_id("library-signoff"),
        reviewer_id="independent-semantic-reviewer",
        role=ReviewerRoleV1.LIBRARY_REVIEWER,
        decision=DecisionV1.ACCEPT,
        rationale="fixture library review",
    )
    with pytest.raises(FidelityHarnessError, match="distinct reviewer identities"):
        StatementFidelityHarness().run(
            contract,
            obligations=_obligations(contract),
            translators=_translators(),
            mutation_agent=FakeMutationSuiteAgent(),
            reviewer=FakeSemanticReviewer(),
            additional_signoffs=(duplicate_reviewer,),
        )


def test_freeze_rejects_a_tampered_harness_report() -> None:
    draft = _contract()
    evaluation = _evaluation(draft)
    first = evaluation.report.checks[0].model_copy(update={"evidence": "detached evidence"})
    detached_report = evaluation.report.model_copy(
        update={"checks": (first, *evaluation.report.checks[1:])}
    )
    with pytest.raises(FreezeRejected, match="differs from expert evidence"):
        freeze_contract(
            draft,
            evaluation=replace(evaluation, report=detached_report),
            source_preparation=_source_preparation(draft),
            frozen_by="builder-service",
        )


def test_freeze_revalidates_candidate_structure_instead_of_trusting_check_booleans() -> None:
    draft = _contract()
    evaluation = _evaluation(draft)
    impersonating = replace(
        evaluation.candidates[1],
        actor_id=evaluation.candidates[0].actor_id,
    )
    with pytest.raises(FreezeRejected, match="actor identities"):
        freeze_contract(
            draft,
            evaluation=replace(
                evaluation,
                candidates=(evaluation.candidates[0], impersonating),
            ),
            source_preparation=_source_preparation(draft),
            frozen_by="builder-service",
        )


def test_builder_case_attaches_a_complete_evaluation_in_order() -> None:
    contract = _contract()
    case = BuilderCase(contract)
    case = case.advance(BuilderStage.RIGHTS_REVIEWED)
    case = case.advance(BuilderStage.NORMALIZED)
    case = case.advance(BuilderStage.MATHLIB_MAPPED)
    reviewed = case.with_evaluation(_evaluation(contract))
    assert reviewed.stage is BuilderStage.FIDELITY_REVIEWED
    assert reviewed.fidelity is not None
    assert len(reviewed.candidates) == 2


def test_workflow_cannot_skip_fidelity_review() -> None:
    case = BuilderCase(_contract())
    with pytest.raises(BuilderError, match="invalid Builder transition"):
        case.advance(BuilderStage.FROZEN)


def test_new_revision_does_not_change_the_frozen_original() -> None:
    contract = _contract()
    original = freeze_contract(
        contract,
        evaluation=_evaluation(contract),
        source_preparation=_source_preparation(contract),
        frozen_by="builder-service",
    )
    replacement = _contract().model_copy(update={"revision": 2})
    next_revision = create_next_revision(original, replacement)
    assert original.status is StatementStatusV1.FROZEN
    assert next_revision.status is StatementStatusV1.DRAFT
    assert original.revision == 1
    assert next_revision.revision == 2
