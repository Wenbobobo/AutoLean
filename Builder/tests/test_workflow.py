from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import TypedDict, cast

import pytest
from autolean_builder import (
    BuilderCase,
    BuilderError,
    BuilderStage,
    CandidateGenerationTask,
    CandidateProposal,
    CandidateReviewVerdict,
    CanonicalTypeEnvironmentFacts,
    CanonicalTypeQueryAssurance,
    CanonicalTypeQueryFacts,
    CanonicalTypeQueryRequest,
    CanonicalTypeQueryResult,
    EvidenceAuthority,
    FidelityHarnessError,
    FreezeRejected,
    MutationReviewVerdict,
    ObligationReviewVerdict,
    SelectedStatementBaseline,
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
    OciVerifierExecutionPolicyV2,
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
            verifier_execution_policy=OciVerifierExecutionPolicyV2(
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


def test_semantic_obligation_rejects_duplicate_source_span_ids_at_construction() -> None:
    obligation = _obligations(_contract())[0]

    with pytest.raises(FidelityHarnessError, match="source span identifiers must be unique"):
        replace(
            obligation,
            source_span_ids=(obligation.source_span_ids[0], obligation.source_span_ids[0]),
        )


@dataclass(frozen=True, slots=True)
class FakeTranslationAgent:
    actor_id: str
    independence_group: str
    candidate_id: str
    oracle_lean_statement: str
    return_mismatched_statement: bool = False

    def translate(self, task: CandidateGenerationTask) -> CandidateProposal:
        lean_statement_source = (
            "theorem mismatched_fixture : True"
            if self.return_mismatched_statement
            else self.oracle_lean_statement
        )
        return CandidateProposal(
            candidate_id=self.candidate_id,
            lean_statement_source=lean_statement_source,
            reverse_rendering=_golden()["reverse_rendering"],
            covered_obligation_ids=tuple(item.obligation_id for item in task.obligations),
        )


@dataclass(slots=True)
class FakeCanonicalTypeQuery:
    contract: StatementContractV1
    canonical_types: dict[str, str] | None = None
    failures: dict[str, str] | None = None
    hash_mismatch_subjects: frozenset[str] = frozenset()
    environment_drift_subjects: frozenset[str] = frozenset()
    calls: list[str] | None = None

    def query(self, request: CanonicalTypeQueryRequest) -> CanonicalTypeQueryResult:
        if self.calls is None:
            self.calls = []
        self.calls.append(request.subject_id)
        if self.failures is not None and request.subject_id in self.failures:
            raise RuntimeError(self.failures[request.subject_id])
        formal = self.contract.formal
        assert formal.elaborated_type is not None
        canonical_type = (
            self.canonical_types.get(request.subject_id, formal.elaborated_type)
            if self.canonical_types is not None
            else formal.elaborated_type
        )
        worker_digest = formal.environment.verifier_execution_policy.worker_image_digest
        if request.subject_id in self.environment_drift_subjects:
            worker_digest = "sha256:" + "d" * 64
        lake_manifest = formal.environment.lake_manifest_hash
        return CanonicalTypeQueryResult(
            declaration=request.declaration,
            canonical_type=canonical_type,
            canonical_type_sha256=(
                "0" * 64
                if request.subject_id in self.hash_mismatch_subjects
                else hashlib.sha256(canonical_type.encode()).hexdigest()
            ),
            environment=CanonicalTypeEnvironmentFacts(
                assurance=CanonicalTypeQueryAssurance.SCRIPTED_FAKE,
                adapter_id="builder.tests.scripted-canonical-query",
                image=f"autolean/scripted-builder-query@{worker_digest}",
                worker_image_digest=worker_digest,
                lean_version=formal.environment.lean_version,
                mathlib_revision=formal.environment.mathlib_revision,
                lake_manifest_sha256=(None if lake_manifest is None else lake_manifest.value),
                type_format="autolean.lean-pp-expr.v1",
                query_schema_version="autolean.scripted-canonical-query.v1",
                query_protocol="autolean.scripted-canonical-query.v1",
                query_identity_sha256=_sha256("scripted-query-identity"),
                build_receipt_canonical_sha256=_sha256("scripted-build-receipt"),
                execution_policy_sha256=_sha256("scripted-execution-policy"),
                source_inputs_sha256=_sha256("scripted-source-inputs"),
                source_rendering_profile="autolean.scripted-header.v1",
            ),
            query=CanonicalTypeQueryFacts(
                query_output_sha256=_sha256(f"query:{request.subject_id}"),
                source_snapshot_sha256=hashlib.sha256(
                    request.statement_source.encode()
                ).hexdigest(),
                sealed_candidate_sha256=_sha256(f"sealed:{request.subject_id}"),
                candidate_direct_imports_sha256=_sha256("scripted-direct-imports"),
                module_import_closure_sha256=_sha256("scripted-import-closure"),
                observed_axioms=(),
                observed_axioms_sha256=hashlib.sha256(b"[]\n").hexdigest(),
            ),
        )


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _fidelity_harness(
    contract: StatementContractV1,
    *,
    query: FakeCanonicalTypeQuery | None = None,
    clock: Callable[[], datetime] | None = None,
) -> StatementFidelityHarness:
    return StatementFidelityHarness(
        canonical_type_query=query or FakeCanonicalTypeQuery(contract),
        **({} if clock is None else {"clock": clock}),
    )


@dataclass(frozen=True, slots=True)
class UnreachableMutationAgent:
    actor_id: str = "unreachable-mutation-agent"

    def generate(
        self,
        task: TranslationTask,
        baseline: SelectedStatementBaseline,
    ) -> tuple[MutationProbeV1, ...]:
        del task, baseline
        raise AssertionError("mutation callback must be unreachable")


@dataclass(frozen=True, slots=True)
class UnreachableReviewer:
    reviewer_id: str = "unreachable-reviewer"

    def review(self, packet: SemanticReviewPacket) -> SemanticReviewVerdict:
        del packet
        raise AssertionError("reviewer callback must be unreachable")


@dataclass(frozen=True, slots=True)
class FakeMutationSuiteAgent:
    actor_id: str = "mutation-suite-fixture"
    omit_kind: MutationKindV1 | None = None

    def generate(
        self,
        task: TranslationTask,
        baseline: SelectedStatementBaseline,
    ) -> tuple[MutationProbeV1, ...]:
        assert baseline.statement_source_hash == task.selected_statement_hash
        assert baseline.lean_statement_source == task.selected_lean_statement
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
    oracle_lean_statement = _golden()["lean_statement"]
    return (
        FakeTranslationAgent("translator-a", "team-a", "candidate-a", oracle_lean_statement),
        FakeTranslationAgent("translator-b", "team-b", "candidate-b", oracle_lean_statement),
    )


def _evaluation(
    contract: StatementContractV1 | None = None,
    *,
    false_negative_kind: MutationKindV1 | None = None,
):
    active_contract = contract or _contract()
    return _fidelity_harness(active_contract).run(
        active_contract,
        obligations=_obligations(active_contract),
        translators=_translators(),
        mutation_agent=FakeMutationSuiteAgent(),
        reviewer=FakeSemanticReviewer(false_negative_kind=false_negative_kind),
    )


def test_statement_fidelity_harness_rejects_naive_clock() -> None:
    contract = _contract()
    with pytest.raises(FidelityHarnessError, match=r"clock.*timezone-aware"):
        _fidelity_harness(
            contract,
            clock=lambda: datetime(2026, 7, 25, 12, 0),
        ).run(
            contract,
            obligations=_obligations(contract),
            translators=_translators(),
            mutation_agent=FakeMutationSuiteAgent(),
            reviewer=FakeSemanticReviewer(),
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


def test_harness_rejects_canonical_type_mismatch_before_reviewer_runs() -> None:
    contract = _contract()

    translators = (
        FakeTranslationAgent(
            "translator-a",
            "team-a",
            "candidate-a",
            _golden()["lean_statement"],
            return_mismatched_statement=True,
        ),
        FakeTranslationAgent("translator-b", "team-b", "candidate-b", _golden()["lean_statement"]),
    )
    query = FakeCanonicalTypeQuery(
        contract,
        canonical_types={"candidate-a": "True"},
    )
    with pytest.raises(FidelityHarnessError, match="canonical type differs"):
        _fidelity_harness(contract, query=query).run(
            contract,
            obligations=_obligations(contract),
            translators=translators,
            mutation_agent=UnreachableMutationAgent(),
            reviewer=UnreachableReviewer(),
        )


def test_harness_rejects_fresh_reference_drift_before_callbacks() -> None:
    contract = _contract()
    query = FakeCanonicalTypeQuery(
        contract,
        canonical_types={"contract-selected-reference": "True"},
    )

    with pytest.raises(FidelityHarnessError, match="reference canonical type drifted"):
        _fidelity_harness(contract, query=query).run(
            contract,
            obligations=_obligations(contract),
            translators=_translators(),
            mutation_agent=UnreachableMutationAgent(),
            reviewer=UnreachableReviewer(),
        )

    assert query.calls == ["contract-selected-reference"]


def test_harness_rejects_candidate_elaboration_failure_before_callbacks() -> None:
    contract = _contract()
    query = FakeCanonicalTypeQuery(
        contract,
        failures={"candidate-a": "fixture parse/elaboration failure"},
    )

    with pytest.raises(FidelityHarnessError, match="parse/elaboration failure"):
        _fidelity_harness(contract, query=query).run(
            contract,
            obligations=_obligations(contract),
            translators=_translators(),
            mutation_agent=UnreachableMutationAgent(),
            reviewer=UnreachableReviewer(),
        )

    assert query.calls == ["contract-selected-reference", "candidate-a"]


def test_harness_rejects_query_type_text_hash_mismatch_before_callbacks() -> None:
    contract = _contract()
    query = FakeCanonicalTypeQuery(
        contract,
        hash_mismatch_subjects=frozenset({"candidate-a"}),
    )

    with pytest.raises(FidelityHarnessError, match="type text/hash mismatch"):
        _fidelity_harness(contract, query=query).run(
            contract,
            obligations=_obligations(contract),
            translators=_translators(),
            mutation_agent=UnreachableMutationAgent(),
            reviewer=UnreachableReviewer(),
        )


def test_harness_rejects_candidate_query_environment_drift_before_callbacks() -> None:
    contract = _contract()
    query = FakeCanonicalTypeQuery(
        contract,
        environment_drift_subjects=frozenset({"candidate-a"}),
    )

    with pytest.raises(FidelityHarnessError, match="contract-bound environment"):
        _fidelity_harness(contract, query=query).run(
            contract,
            obligations=_obligations(contract),
            translators=_translators(),
            mutation_agent=UnreachableMutationAgent(),
            reviewer=UnreachableReviewer(),
        )


def test_mutation_baseline_is_selected_statement_not_first_candidate() -> None:
    contract = _contract()
    first_candidate_source = _golden()["lean_statement"].replace(
        "theorem bounded_witness",
        "lemma bounded_witness",
    )
    observed_baselines: list[SelectedStatementBaseline] = []

    @dataclass(frozen=True, slots=True)
    class BaselineSpy:
        actor_id: str = "baseline-spy"

        def generate(
            self,
            task: TranslationTask,
            baseline: SelectedStatementBaseline,
        ) -> tuple[MutationProbeV1, ...]:
            observed_baselines.append(baseline)
            return FakeMutationSuiteAgent().generate(task, baseline)

    evaluation = _fidelity_harness(contract).run(
        contract,
        obligations=_obligations(contract),
        translators=(
            FakeTranslationAgent(
                "translator-a",
                "team-a",
                "candidate-a",
                first_candidate_source,
            ),
            FakeTranslationAgent(
                "translator-b",
                "team-b",
                "candidate-b",
                _golden()["lean_statement"],
            ),
        ),
        mutation_agent=BaselineSpy(),
        reviewer=FakeSemanticReviewer(),
    )

    assert evaluation.candidates[0].lean_statement_source == first_candidate_source
    assert first_candidate_source != contract.formal.lean_statement_source
    assert observed_baselines == [SelectedStatementBaseline.from_task(evaluation.task)]
    assert observed_baselines[0].lean_statement_source == contract.formal.lean_statement_source
    frozen = freeze_contract(
        contract,
        evaluation=evaluation,
        source_preparation=_source_preparation(contract),
        frozen_by="canonical-type-liveness-fixture",
    )
    assert frozen.status is StatementStatusV1.FROZEN


def test_translation_agent_receives_selected_formal_field_blind_generation_payload() -> None:
    contract = _contract()
    base_obligations = _obligations(contract)
    obligations = (
        replace(
            base_obligations[0],
            description=contract.formal.lean_statement_source,
        ),
        *base_obligations[1:],
    )
    observed_tasks: list[CandidateGenerationTask] = []
    observed_payloads: list[dict[str, object]] = []

    @dataclass(frozen=True, slots=True)
    class SpyTranslator:
        actor_id: str
        independence_group: str
        candidate_id: str
        oracle_lean_statement: str

        def translate(self, task: CandidateGenerationTask) -> CandidateProposal:
            assert isinstance(task, CandidateGenerationTask)
            observed_tasks.append(task)
            observed_payloads.append(task.payload())
            return CandidateProposal(
                candidate_id=self.candidate_id,
                lean_statement_source=self.oracle_lean_statement,
                reverse_rendering=_golden()["reverse_rendering"],
                covered_obligation_ids=tuple(item.obligation_id for item in task.obligations),
            )

    evaluation = _fidelity_harness(contract).run(
        contract,
        obligations=obligations,
        translators=(
            SpyTranslator("spy-a", "team-a", "candidate-a", _golden()["lean_statement"]),
            SpyTranslator("spy-b", "team-b", "candidate-b", _golden()["lean_statement"]),
        ),
        mutation_agent=FakeMutationSuiteAgent(),
        reviewer=FakeSemanticReviewer(),
    )

    forbidden_keys = {
        "selected_lean_statement",
        "selected_statement_hash",
        "draft_contract_hash",
        "lean_fragment",
    }
    forbidden_values = {
        contract.formal.lean_statement_source,
        contract.formal.statement_source_hash.value,
        contract.semantic_hash().value,
        *(obligation.lean_fragment for obligation in obligations),
    }

    def assert_selected_formal_fields_absent(value: object) -> None:
        if isinstance(value, dict):
            assert not (set(value) & forbidden_keys)
            for nested in value.values():
                assert_selected_formal_fields_absent(nested)
        elif isinstance(value, (list, tuple)):
            for nested in value:
                assert_selected_formal_fields_absent(nested)
        elif isinstance(value, str):
            assert all(forbidden not in value for forbidden in forbidden_values)

    assert len(observed_tasks) == 2
    for task in observed_tasks:
        assert not hasattr(task, "selected_lean_statement")
        assert not hasattr(task, "selected_statement_hash")
        assert not hasattr(task, "draft_contract_hash")
        assert all(
            not hasattr(obligation, "lean_fragment") and not hasattr(obligation, "description")
            for obligation in task.obligations
        )
        assert task.mathematics == contract.mathematics
        assert task.formalization.task_kind is contract.task_kind
        assert task.formalization.declaration_name == contract.formal.declaration_name
        assert task.formalization.namespace == contract.formal.namespace
        assert task.formalization.lean_version == contract.formal.environment.lean_version
        assert task.formalization.mathlib_revision == contract.formal.environment.mathlib_revision
        assert task.formalization.imports_allowlist == contract.formal.imports_allowlist
        assert task.formalization.axioms_allowlist == contract.formal.axioms_allowlist
        assert task.formalization.rendering_profile == "autolean.full-declaration-canonical-type.v1"
    assert len(observed_payloads) == 2
    for payload in observed_payloads:
        assert_selected_formal_fields_absent(payload)
        projected_obligations = payload["obligations"]
        assert isinstance(projected_obligations, list)
        assert all(
            isinstance(obligation, dict) and "description" not in obligation
            for obligation in projected_obligations
        )
    assert all(candidate.contract_id == contract.contract_id for candidate in evaluation.candidates)
    assert all(candidate.revision == contract.revision for candidate in evaluation.candidates)
    assert all(
        candidate.draft_contract_hash == contract.semantic_hash()
        for candidate in evaluation.candidates
    )
    assert all(
        candidate.generation_task_hash == evaluation.generation_task.content_hash
        for candidate in evaluation.candidates
    )
    artifact = evaluation.artifact_payload()
    assert artifact["generation_task"] == evaluation.generation_task.payload()
    assert artifact["generation_task_hash"] == evaluation.generation_task.content_hash.model_dump(
        mode="json"
    )
    binding_check = next(
        item
        for item in evaluation.automatic_checks
        if item.check_name == "candidate_contract_bindings"
    )
    assert evaluation.generation_task.content_hash.value in binding_check.evidence
    canonical_check = next(
        item
        for item in evaluation.automatic_checks
        if item.check_name == "canonical_elaborated_type_identity"
    )
    canonical_envelope = json.loads(canonical_check.evidence)
    canonical_record = canonical_envelope["record"]
    assert canonical_envelope["record_hash"] == (
        evaluation.canonical_type_gate.record_hash.model_dump(mode="json")
    )
    assert canonical_record["contract_id"] == contract.contract_id.value
    assert canonical_record["source_hash"] == contract.source.content_hash.model_dump(mode="json")
    assert canonical_record["generation_task_hash"] == (
        evaluation.generation_task.content_hash.model_dump(mode="json")
    )
    assert canonical_record["environment"]["lean_version"] == (
        contract.formal.environment.lean_version
    )
    assert canonical_record["environment"]["mathlib_revision"] == (
        contract.formal.environment.mathlib_revision
    )
    assert canonical_record["environment"]["worker_image_digest"] == (
        contract.formal.environment.verifier_execution_policy.worker_image_digest
    )
    assert canonical_record["reference"]["canonical_type_hash"] == (
        contract.formal.elaborated_type_hash.model_dump(mode="json")
    )
    assert [item["subject_id"] for item in canonical_record["candidates"]] == [
        candidate.candidate_id for candidate in evaluation.candidates
    ]
    assert canonical_record["definitional_equivalence_claimed"] is False
    assert canonical_record["semantic_equivalence_claimed"] is False
    artifact_checks = cast(list[dict[str, object]], artifact["automatic_checks"])
    assert canonical_envelope in [
        json.loads(cast(str, item["evidence"]))
        for item in artifact_checks
        if item["check_name"] == "canonical_elaborated_type_identity"
    ]

    tampered_candidate = replace(
        evaluation.candidates[0],
        generation_task_hash=digest_text(HashKindV1.PROMPT, "detached-generation-task"),
    )
    tampered_evaluation = replace(
        evaluation,
        candidates=(tampered_candidate, *evaluation.candidates[1:]),
    )
    with pytest.raises(FidelityHarnessError, match="candidate is not bound"):
        tampered_evaluation.assert_binds(contract)

    tampered_reference = replace(
        evaluation.canonical_type_gate.reference,
        canonical_type="True",
    )
    with pytest.raises(FidelityHarnessError, match="observation is detached"):
        replace(
            evaluation,
            canonical_type_gate=replace(
                evaluation.canonical_type_gate,
                reference=tampered_reference,
            ),
        ).assert_binds(contract)


def test_harness_freezes_all_role_identities_before_untrusted_calls() -> None:
    contract = _contract()

    @dataclass(slots=True)
    class MutableMutationAgent:
        actor_id: str = "registered-mutation-agent"

        def generate(
            self,
            task: TranslationTask,
            baseline: SelectedStatementBaseline,
        ) -> tuple[MutationProbeV1, ...]:
            self.actor_id = "spoofed-mutation-agent"
            return FakeMutationSuiteAgent().generate(task, baseline)

    @dataclass(slots=True)
    class MutableReviewer:
        reviewer_id: str = "registered-semantic-reviewer"

        def review(self, packet: SemanticReviewPacket) -> SemanticReviewVerdict:
            self.reviewer_id = "spoofed-semantic-reviewer"
            return FakeSemanticReviewer(reviewer_id="registered-semantic-reviewer").review(packet)

    @dataclass(slots=True)
    class MutableTranslator:
        actor_id: str
        independence_group: str
        candidate_id: str
        oracle_lean_statement: str
        peer: MutableTranslator | None = None
        mutation_agent: MutableMutationAgent | None = None
        reviewer: MutableReviewer | None = None

        def translate(self, task: CandidateGenerationTask) -> CandidateProposal:
            self.actor_id = f"spoofed-{self.candidate_id}"
            self.independence_group = f"spoofed-group-{self.candidate_id}"
            if self.peer is not None:
                self.peer.actor_id = "spoofed-before-second-translate"
                self.peer.independence_group = "spoofed-before-second-group"
            if self.mutation_agent is not None:
                self.mutation_agent.actor_id = "spoofed-before-mutation"
            if self.reviewer is not None:
                self.reviewer.reviewer_id = "spoofed-before-review"
            return CandidateProposal(
                candidate_id=self.candidate_id,
                lean_statement_source=self.oracle_lean_statement,
                reverse_rendering=_golden()["reverse_rendering"],
                covered_obligation_ids=tuple(item.obligation_id for item in task.obligations),
            )

    mutation_agent = MutableMutationAgent()
    reviewer = MutableReviewer()
    second = MutableTranslator(
        "registered-translator-b",
        "registered-group-b",
        "candidate-b",
        _golden()["lean_statement"],
    )
    first = MutableTranslator(
        "registered-translator-a",
        "registered-group-a",
        "candidate-a",
        _golden()["lean_statement"],
        peer=second,
        mutation_agent=mutation_agent,
        reviewer=reviewer,
    )

    evaluation = _fidelity_harness(contract).run(
        contract,
        obligations=_obligations(contract),
        translators=(first, second),
        mutation_agent=mutation_agent,
        reviewer=reviewer,
    )

    assert tuple(candidate.actor_id for candidate in evaluation.candidates) == (
        "registered-translator-a",
        "registered-translator-b",
    )
    assert tuple(candidate.independence_group for candidate in evaluation.candidates) == (
        "registered-group-a",
        "registered-group-b",
    )
    assert evaluation.mutation_agent_id == "registered-mutation-agent"
    assert evaluation.review.reviewer_id == "registered-semantic-reviewer"
    assert first.actor_id == "spoofed-candidate-a"
    assert second.actor_id == "spoofed-candidate-b"
    assert mutation_agent.actor_id == "spoofed-mutation-agent"
    assert reviewer.reviewer_id == "spoofed-semantic-reviewer"


def test_harness_rejects_an_incomplete_mutation_suite() -> None:
    contract = _contract()
    with pytest.raises(FidelityHarnessError, match="drop_noetherian"):
        _fidelity_harness(contract).run(
            contract,
            obligations=_obligations(contract),
            translators=_translators(),
            mutation_agent=FakeMutationSuiteAgent(omit_kind=MutationKindV1.DROP_NOETHERIAN),
            reviewer=FakeSemanticReviewer(),
        )


def test_harness_requires_an_independent_semantic_reviewer() -> None:
    contract = _contract()
    with pytest.raises(FidelityHarnessError, match="independently authored"):
        _fidelity_harness(contract).run(
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
        _fidelity_harness(contract).run(
            contract,
            obligations=_obligations(contract),
            translators=_translators(),
            mutation_agent=FakeMutationSuiteAgent(),
            reviewer=FakeSemanticReviewer(reviewer_id=reviewer_id),
        )


def test_harness_rejects_translation_and_mutation_actor_overlap() -> None:
    contract = _contract()
    with pytest.raises(FidelityHarnessError, match="mutation agent identity must differ"):
        _fidelity_harness(contract).run(
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
        _fidelity_harness(contract).run(
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
