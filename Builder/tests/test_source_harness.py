from __future__ import annotations

import hashlib
import inspect
import json
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from threading import Barrier
from types import SimpleNamespace
from typing import BinaryIO, cast

import autolean_builder
import autolean_builder.source_harness as source_harness_module
import pytest
from autolean_builder import (
    CandidateGenerationTask,
    CandidateProposal,
    CandidateReviewVerdict,
    ChapterSourceSpan,
    DownloadObservation,
    FidelityEvaluation,
    FidelityHarnessError,
    MutationReviewVerdict,
    ObligationReviewVerdict,
    PilotManifestV1,
    ReferenceCache,
    ReferenceEntryV1,
    ReferenceManifestV1,
    RightsReview,
    SelectedStatementBaseline,
    SemanticObligation,
    SemanticObligationKind,
    SemanticReviewPacket,
    SemanticReviewVerdict,
    SourceClaimSpan,
    SourceHarnessError,
    SourcePreparationError,
    SourcePreparationLedger,
    SourceToStatementHarness,
    StatementDraftRequest,
    TranslationTask,
    load_pilot_manifest,
)
from autolean_builder.testing import ScriptedCanonicalTypeQuery
from autolean_contracts import (
    AttestationSignerV1,
    AxiomProfileV1,
    DecisionV1,
    EndpointClassV1,
    FidelityEvidenceArtifactRefV1,
    FidelityRiskV1,
    FormalSpecificationV1,
    GraphBundleV1,
    HashKindV1,
    LeanEnvironmentV1,
    MathematicalSpecificationV1,
    MutationKindV1,
    MutationProbeV1,
    OciVerifierExecutionPolicyV2,
    PermissionDecisionV1,
    ReleaseTierV1,
    ReviewerRoleV1,
    ReviewerSignoffV1,
    StatementStatusV1,
    TaskKindV1,
    TaskPolicyV1,
    digest_text,
    stable_identifier,
)

_PARENT_ID = "official-reference-pdf-v1"
_TEXT_ID = "official-reference-text-v1"
_PARENT_BYTES = b"%PDF-1.7\nparent source artifact\n"
_TEXT_BYTES = b"Introduction\nCurvature is alternating.\nConclusion\n"
_EXCERPT = "Curvature is alternating."
_EXCERPT_BYTES = b"Curvature is alternating."
_EXCERPT_START = _TEXT_BYTES.index(_EXCERPT_BYTES)
_EXCERPT_END = _EXCERPT_START + len(_EXCERPT_BYTES)
_PARENT_SHA256 = hashlib.sha256(_PARENT_BYTES).hexdigest()
_TEXT_SHA256 = hashlib.sha256(_TEXT_BYTES).hexdigest()
_ATTRIBUTION = "Official reference by Example Author, CC BY-SA 4.0."


def _entry_payload(
    *,
    reference_id: str,
    data: bytes,
    media_type: str,
    extension: str,
    artifact_kind: str,
    derivation: dict[str, object] | None,
) -> dict[str, object]:
    return {
        "reference_id": reference_id,
        "title": "Official reference",
        "authors": ["Example Author"],
        "version": "published-1",
        "citation": "Example Author, Official reference.",
        "source_record_url": "https://example.invalid/record",
        "download_url": f"https://example.invalid/{reference_id}{extension}",
        "allowed_redirect_urls": [],
        "media_type": media_type,
        "file_extension": extension,
        "size_bytes": len(data),
        "max_bytes": len(data) + 10,
        "sha256": hashlib.sha256(data).hexdigest(),
        "retrieved_at": "2026-07-23T12:00:00Z",
        "license": {
            "expression": "CC-BY-SA-4.0",
            "url": "https://creativecommons.org/licenses/by-sa/4.0/",
            "evidence_url": "https://example.invalid/record",
        },
        "access_policy": "public_open_access",
        "acquisition_policy": "operator_only",
        "model_egress_policy": "local_only",
        "artifact_kind": artifact_kind,
        "derivation": derivation,
        "attribution": _ATTRIBUTION,
    }


def _manifest(
    tmp_path: Path,
    *,
    local_pdf_derived_text: bool = False,
    parent_locator_authority: str | None = None,
) -> ReferenceManifestV1:
    derivation: dict[str, object] = {
        "kind": "repository_text_extraction",
        "parent_reference_id": _PARENT_ID,
        "parent_sha256": _PARENT_SHA256,
        "producer": "Official repository",
        "method": "repository_provided_text_bitstream",
        "tool_name": None,
        "tool_version": None,
        "provenance_url": "https://example.invalid/record",
        "parent_locator_authority": parent_locator_authority or "human_declared",
    }
    text_entry = _entry_payload(
        reference_id=_TEXT_ID,
        data=_TEXT_BYTES,
        media_type="text/plain",
        extension=".txt",
        artifact_kind="derived_text",
        derivation=derivation,
    )
    if local_pdf_derived_text:
        text_entry["download_url"] = None
        text_entry["acquisition_policy"] = "local_derivation_only"
        derivation.update(
            {
                "kind": "local_pdf_text_extraction",
                "producer": "AutoLean local reference cache",
                "method": "pypdf-pdfreader-extract-text-plain-form-feed-v1",
                "tool_name": "pypdf",
                "tool_version": "6.10.0",
                "parent_locator_authority": parent_locator_authority or "manifest_bound",
            }
        )
    payload = {
        "schema_version": "autolean.reference-manifest.v1",
        "entries": [
            _entry_payload(
                reference_id=_PARENT_ID,
                data=_PARENT_BYTES,
                media_type="application/pdf",
                extension=".pdf",
                artifact_kind="source_document",
                derivation=None,
            ),
            text_entry,
        ],
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return ReferenceManifestV1.load(path)


def _cache(tmp_path: Path, *, local_pdf_derived_text: bool = False) -> ReferenceCache:
    data_by_id = {_PARENT_ID: _PARENT_BYTES, _TEXT_ID: _TEXT_BYTES}

    def download(entry: ReferenceEntryV1, destination: BinaryIO) -> DownloadObservation:
        destination.write(data_by_id[entry.reference_id])
        return DownloadObservation(
            final_url=entry.download_url,
            media_type=entry.media_type,
            network_used=False,
        )

    cache = ReferenceCache(
        _manifest(tmp_path, local_pdf_derived_text=local_pdf_derived_text),
        tmp_path / "cache",
        confinement_root=tmp_path,
        downloader=download,
    )
    cache.operator_fetch(_PARENT_ID)
    if local_pdf_derived_text:
        extracted_text = tmp_path / "local-pypdf-extract.txt"
        extracted_text.write_bytes(_TEXT_BYTES)
        cache.operator_import_local(_TEXT_ID, extracted_text)
    else:
        cache.operator_fetch(_TEXT_ID)
    return cache


def _harness(
    tmp_path: Path,
    cache: ReferenceCache | None = None,
    pilot_manifest: PilotManifestV1 | None = None,
    clock: Callable[[], datetime] | None = None,
) -> SourceToStatementHarness:
    active_clock = clock or (lambda: datetime.now(UTC))
    formal = _formal()
    assert formal.elaborated_type is not None
    return SourceToStatementHarness(
        cache or _cache(tmp_path),
        preparation_ledger=SourcePreparationLedger(
            tmp_path / "source-preparations.db",
            confinement_root=tmp_path,
        ),
        canonical_type_query=ScriptedCanonicalTypeQuery(
            canonical_types_by_statement_sha256=(
                (formal.statement_source_hash.value, formal.elaborated_type),
            ),
            worker_image_digest=(formal.environment.verifier_execution_policy.worker_image_digest),
            lean_version=formal.environment.lean_version,
            mathlib_revision=formal.environment.mathlib_revision,
            lake_manifest_sha256=(
                None
                if formal.environment.lake_manifest_hash is None
                else formal.environment.lake_manifest_hash.value
            ),
            fixture_id="source-harness-tests",
        ),
        pilot_manifest=pilot_manifest,
        clock=active_clock,
        allow_test_only_non_authoritative_canonical_type_freeze=True,
    )


def _timestamp_only_evaluation(
    *,
    generated_at: datetime,
    reviewed_at: datetime,
) -> FidelityEvaluation:
    return cast(
        FidelityEvaluation,
        SimpleNamespace(
            report=SimpleNamespace(
                generated_at=generated_at,
                signoffs=(SimpleNamespace(reviewed_at=reviewed_at),),
            )
        ),
    )


def _formal() -> FormalSpecificationV1:
    statement = "theorem curvature_skew (u v : Nat) : u + v = v + u := by"
    elaborated = "forall (u v : Nat), u + v = v + u"
    return FormalSpecificationV1(
        declaration_name="curvature_skew",
        namespace="AutoLean.Geometry",
        lean_statement_source=statement,
        statement_source_hash=digest_text(HashKindV1.STATEMENT_SOURCE, statement),
        elaborated_type=elaborated,
        elaborated_type_hash=digest_text(HashKindV1.ELABORATED_TYPE, elaborated),
        environment=LeanEnvironmentV1(
            lean_version="v4.28.0",
            mathlib_revision="8f9d9cff6bd728b17a24e163c9402775d9e6a365",
            verifier_execution_policy=OciVerifierExecutionPolicyV2(
                worker_image_digest="sha256:" + "b" * 64,
            ),
            environment_hash=digest_text(HashKindV1.ENVIRONMENT, "source-harness-test"),
        ),
        imports_allowlist=("Mathlib",),
    )


def _rights(
    *,
    endpoint_classes: tuple[EndpointClassV1, ...] = (EndpointClassV1.LOCAL,),
) -> RightsReview:
    return RightsReview(
        review_key="official-reference-v1-review",
        source_license="CC-BY-SA-4.0",
        generated_code_license="Apache-2.0",
        overall_decision=PermissionDecisionV1.ALLOW,
        redistribution=PermissionDecisionV1.ALLOW,
        model_egress=PermissionDecisionV1.ALLOW,
        training=PermissionDecisionV1.RESTRICTED,
        embedding=PermissionDecisionV1.RESTRICTED,
        allowed_endpoint_classes=endpoint_classes,
        attribution=_ATTRIBUTION,
        restrictions=("Preserve attribution and share-alike terms for source-derived text.",),
        reviewed_by="rights-reviewer",
        reviewed_at=datetime(2026, 7, 23, 12, 0, tzinfo=UTC),
    )


def _request(
    *,
    rights: RightsReview | None = None,
    artifact_sha256: str = _TEXT_SHA256,
    excerpt: str = _EXCERPT,
    start_offset: int = _EXCERPT_START,
    end_offset: int = _EXCERPT_END,
    chapter_locator: str = "chapter:60",
    page_locator: str = "pdf:page:517",
) -> StatementDraftRequest:
    return StatementDraftRequest(
        contract_key="geometry.curvature-skew",
        revision=1,
        task_kind=TaskKindV1.KNOWN_THEOREM,
        spans=(
            ChapterSourceSpan(
                span_key="curvature-definition",
                human_declared_chapter_locator=chapter_locator,
                human_declared_page_locator=page_locator,
                permitted_excerpt=excerpt,
                source_analyst_id="source-analyst",
                verified_artifact_sha256=artifact_sha256,
                start_offset=start_offset,
                end_offset=end_offset,
            ),
        ),
        rights=rights or _rights(),
        mathematics=MathematicalSpecificationV1(
            informal_statement="Curvature is antisymmetric in its two tangent arguments.",
            normalized_statement=(
                "For every connection and tangent vectors u and v, R(u, v) = -R(v, u)."
            ),
            assumptions=("A covariant derivative on a smooth vector bundle is fixed.",),
            quantifier_order=("forall connection", "forall u", "forall v"),
            definitions=("R is the curvature endomorphism-valued two-form.",),
            edge_cases=("u = v gives zero curvature in the repeated direction.",),
        ),
        formal=_formal(),
        policy=TaskPolicyV1(
            release_tier=ReleaseTierV1.CALIBRATION,
            fidelity_risk=FidelityRiskV1.L2_REUSABLE_API,
            axiom_profile=AxiomProfileV1.MATHLIB,
        ),
        alignment_reviewer_id="mathlib-mapping-reviewer",
    )


def test_verified_text_byte_span_builds_only_a_parent_bound_draft(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    harness = _harness(tmp_path, cache)
    packet = harness.prepare_draft(_TEXT_ID, _request())

    assert packet.assert_binds(cache, harness.preparation_ledger).entry.sha256 == _TEXT_SHA256
    assert packet.contract.status is StatementStatusV1.DRAFT
    assert packet.contract.fidelity is None
    assert packet.contract.freeze is None
    assert packet.contract.source.content_hash.value == _TEXT_SHA256
    assert packet.contract.source.work_id == _PARENT_ID
    assert packet.parent_artifact_sha256 == _PARENT_SHA256
    assert packet.contract.source.spans[0].locator == (
        f"derived-text:bytes:{_EXCERPT_START}-{_EXCERPT_END}"
    )
    assert packet.contract.source.spans[0].start_offset == _EXCERPT_START
    assert packet.contract.source.spans[0].end_offset == _EXCERPT_END
    assert packet.contract.source.spans[0].permitted_excerpt is None
    assert _EXCERPT not in packet.contract.model_dump_json()
    assert packet.contract.source.metadata["human_parent_locators"] == (
        {
            "span_id": packet.contract.source.spans[0].span_id.value,
            "chapter_locator": "chapter:60",
            "page_locator": "pdf:page:517",
            "declared_by": "source-analyst",
            "authority": "human_declared",
        },
    )
    assert packet.contract.rights.allowed_endpoint_classes == (EndpointClassV1.LOCAL,)


def test_v1_packet_canonical_hash_uses_the_original_payload_shape(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    packet = _harness(tmp_path, cache).prepare_draft(_TEXT_ID, _request())
    expected_payload = {
        "schema_version": "autolean.statement-draft-packet.v1",
        "preparation_id": packet.preparation_id.model_dump(mode="json"),
        "contract": packet.contract.model_dump(mode="json", exclude_none=False),
        "reference_id": packet.reference_id,
        "manifest_sha256": packet.manifest_sha256,
        "artifact_sha256": packet.artifact_sha256,
        "parent_reference_id": packet.parent_reference_id,
        "parent_artifact_sha256": packet.parent_artifact_sha256,
        "rights_record": packet.rights_record.model_dump(mode="json", exclude_none=False),
        "spans": tuple(asdict(span) for span in packet.spans),
        "pilot_admission": None,
    }

    assert packet.preparation_record().packet_sha256 == source_harness_module._canonical_sha256(
        expected_payload
    )


def test_manifest_bound_local_pdf_text_enters_source_preparation(tmp_path: Path) -> None:
    cache = _cache(tmp_path, local_pdf_derived_text=True)
    harness = _harness(tmp_path, cache)

    packet = harness.prepare_draft(_TEXT_ID, _request())

    assert packet.assert_binds(cache, harness.preparation_ledger).entry.sha256 == _TEXT_SHA256
    assert packet.contract.source.metadata["derivation"]["kind"] == "local_pdf_text_extraction"
    assert packet.contract.source.metadata["derivation"]["parent_locator_authority"] == (
        "manifest_bound"
    )


@pytest.mark.parametrize(
    ("chapter_locator", "page_locator"),
    (("", "pdf:page:517"), ("chapter:60", "")),
)
def test_each_source_span_requires_human_declared_chapter_and_page_locator(
    chapter_locator: str,
    page_locator: str,
) -> None:
    with pytest.raises(SourceHarnessError, match="must be nonempty, trimmed text"):
        _request(chapter_locator=chapter_locator, page_locator=page_locator)


def test_repository_text_rejects_manifest_bound_parent_locator_authority(tmp_path: Path) -> None:
    data_by_id = {_PARENT_ID: _PARENT_BYTES, _TEXT_ID: _TEXT_BYTES}

    def download(entry: ReferenceEntryV1, destination: BinaryIO) -> DownloadObservation:
        destination.write(data_by_id[entry.reference_id])
        return DownloadObservation(
            final_url=entry.download_url,
            media_type=entry.media_type,
            network_used=False,
        )

    cache = ReferenceCache(
        _manifest(tmp_path, parent_locator_authority="manifest_bound"),
        tmp_path / "cache",
        confinement_root=tmp_path,
        downloader=download,
    )
    cache.operator_fetch(_PARENT_ID)
    cache.operator_fetch(_TEXT_ID)

    with pytest.raises(
        SourceHarnessError,
        match="repository-derived text requires a human-declared parent locator policy",
    ):
        _harness(tmp_path, cache).prepare_draft(_TEXT_ID, _request())


def test_private_source_claim_must_match_public_span_hash_and_locator(tmp_path: Path) -> None:
    packet = _harness(tmp_path).prepare_draft(_TEXT_ID, _request())
    public_span = packet.contract.source.spans[0]

    with pytest.raises(FidelityHarnessError, match="differs from its public span hash"):
        SourceClaimSpan(
            span_id=public_span.span_id,
            locator=public_span.locator,
            content_hash=public_span.content_hash,
            permitted_excerpt="A different source claim.",
        )
    with pytest.raises(FidelityHarnessError, match="public contract span binding"):
        TranslationTask.from_contract(
            packet.contract,
            (),
            source_claims=(
                SourceClaimSpan(
                    span_id=public_span.span_id,
                    locator="derived-text:bytes:0-1",
                    content_hash=public_span.content_hash,
                    permitted_excerpt=_EXCERPT,
                ),
            ),
        )


def test_real_source_harness_prepare_fidelity_and_freeze_path(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    harness = _harness(tmp_path, cache)
    packet = harness.prepare_draft(_TEXT_ID, _request())
    source_span_id = packet.contract.source.spans[0].span_id
    obligation_specs = (
        (
            "quantifier-order",
            SemanticObligationKind.QUANTIFIER_ORDER,
            "The universal variables retain their declared order.",
            "For every connection",
            "(u v : Nat)",
        ),
        (
            "assumption",
            SemanticObligationKind.ASSUMPTION,
            "The fixed connection assumption remains explicit.",
            "connection",
            "Nat",
        ),
        (
            "conclusion",
            SemanticObligationKind.CONCLUSION,
            "The antisymmetry conclusion is preserved.",
            "R(u, v) = -R(v, u)",
            "u + v = v + u",
        ),
        (
            "definition",
            SemanticObligationKind.DEFINITION,
            "The curvature symbol remains the selected operation.",
            "R",
            "curvature_skew",
        ),
        (
            "edge-case",
            SemanticObligationKind.EDGE_CASE,
            "The repeated-vector edge case remains reviewable.",
            "u and v",
            "u v",
        ),
        (
            "non-vacuity",
            SemanticObligationKind.NON_VACUITY,
            "The quantified inputs have an inhabited witness type.",
            "tangent vectors",
            ": Nat",
        ),
    )
    obligations = tuple(
        SemanticObligation(
            obligation_id=identifier,
            kind=kind,
            description=description,
            source_span_ids=(source_span_id,),
            normalized_fragment=normalized_fragment,
            lean_fragment=lean_fragment,
        )
        for identifier, kind, description, normalized_fragment, lean_fragment in obligation_specs
    )

    @dataclass(frozen=True, slots=True)
    class Translator:
        actor_id: str
        independence_group: str
        oracle_lean_statement: str

        def translate(self, task: CandidateGenerationTask) -> CandidateProposal:
            return CandidateProposal(
                candidate_id=f"{self.actor_id}-candidate",
                lean_statement_source=self.oracle_lean_statement,
                reverse_rendering=task.mathematics.normalized_statement,
                covered_obligation_ids=tuple(
                    obligation.obligation_id for obligation in task.obligations
                ),
            )

    @dataclass(frozen=True, slots=True)
    class MutationAgent:
        actor_id: str = "source-mutation-agent"

        def generate(
            self,
            task: TranslationTask,
            baseline: SelectedStatementBaseline,
        ) -> tuple[MutationProbeV1, ...]:
            assert baseline.statement_source_hash == task.selected_statement_hash
            return tuple(
                MutationProbeV1(
                    probe_id=stable_identifier("source-mutation", kind.value),
                    kind=kind,
                    target_path=f"formal.{kind.value}",
                    expected_failure="independent reviewer detects the changed statement",
                    mutated_statement_source=(
                        f"{task.selected_lean_statement}\n-- mutation: {kind.value}"
                    ),
                )
                for kind in MutationKindV1
            )

    @dataclass(frozen=True, slots=True)
    class Reviewer:
        reviewer_id: str = "source-semantic-reviewer"

        def review(self, review_packet: SemanticReviewPacket) -> SemanticReviewVerdict:
            return SemanticReviewVerdict(
                review_id="source-semantic-review-v1",
                reviewer_id=self.reviewer_id,
                independent=True,
                decision=DecisionV1.ACCEPT,
                source_to_normalized_equivalent=True,
                source_to_normalized_evidence="each cited condition remains explicit",
                candidate_verdicts=tuple(
                    CandidateReviewVerdict(
                        candidate_id=candidate.candidate_id,
                        candidate_hash=candidate.evidence_hash,
                        decision=DecisionV1.ACCEPT,
                        reverse_render_equivalent=True,
                        obligation_verdicts=tuple(
                            ObligationReviewVerdict(
                                obligation_id=obligation.obligation_id,
                                decision=DecisionV1.ACCEPT,
                                rationale="the source, normalized, and Lean fragments agree",
                            )
                            for obligation in review_packet.task.obligations
                        ),
                        rationale="the candidate preserves the reviewed statement",
                    )
                    for candidate in review_packet.candidates
                ),
                mutation_verdicts=tuple(
                    MutationReviewVerdict(
                        probe_id=probe.probe_id,
                        detected=True,
                        rationale="the mutation changes a reviewed semantic obligation",
                    )
                    for probe in review_packet.mutation_probes
                ),
                positive_example_valid=True,
                positive_example_evidence="zero and one instantiate the declared Nat inputs",
                negative_example_valid=True,
                negative_example_evidence="a noncommutative replacement changes the claim",
                non_vacuous=True,
                non_vacuity_evidence="Nat supplies witnesses for both quantified inputs",
                rationale="the complete source-backed translation is accepted",
            )

    library_signoff = ReviewerSignoffV1(
        signoff_id=stable_identifier("source-signoff", "library-review"),
        reviewer_id="source-library-reviewer",
        role=ReviewerRoleV1.LIBRARY_REVIEWER,
        decision=DecisionV1.ACCEPT,
        independent=True,
        rationale="the declaration is suitable as a reusable library boundary",
    )
    evaluation = harness.run_fidelity(
        packet,
        obligations=obligations,
        translators=(
            Translator(
                "source-translator-a",
                "source-team-a",
                packet.contract.formal.lean_statement_source,
            ),
            Translator(
                "source-translator-b",
                "source-team-b",
                packet.contract.formal.lean_statement_source,
            ),
        ),
        mutation_agent=MutationAgent(),
        reviewer=Reviewer(),
        additional_signoffs=(library_signoff,),
    )
    strict_harness = SourceToStatementHarness(
        harness.cache,
        preparation_ledger=harness.preparation_ledger,
        fidelity_harness=harness.fidelity_harness,
        pilot_manifest=harness.pilot_manifest,
    )
    with pytest.raises(SourceHarnessError, match="non-authoritative canonical type evidence"):
        strict_harness.revalidate_and_freeze(
            packet,
            evaluation=evaluation,
            frozen_by="source-harness-freezer",
        )
    frozen = harness.revalidate_and_freeze(
        packet,
        evaluation=evaluation,
        frozen_by="source-harness-freezer",
    )

    assert frozen.status is StatementStatusV1.FROZEN
    assert frozen.freeze is not None
    assert frozen.freeze.source_preparation_id == packet.preparation_id
    assert frozen.freeze.source_preparation_hash == packet.preparation_record().artifact_digest()
    assert frozen.fidelity == evaluation.report
    assert _EXCERPT not in frozen.model_dump_json()
    assert _EXCERPT in evaluation.render_artifact().decode("utf-8")


def test_raw_freeze_and_bridge_primitives_are_not_public_package_api() -> None:
    assert not hasattr(autolean_builder, "freeze_contract")
    assert not hasattr(autolean_builder, "bridge_frozen_contract")
    freeze_parameters = inspect.signature(SourceToStatementHarness.revalidate_and_freeze).parameters
    bridge_parameters = inspect.signature(
        SourceToStatementHarness.revalidate_freeze_and_bridge
    ).parameters
    assert "frozen_at" not in freeze_parameters
    assert "frozen_at" not in bridge_parameters
    assert "bundle_issued_at" not in bridge_parameters


def test_blocked_pilot_reference_cannot_bypass_the_supported_draft_entry(
    tmp_path: Path,
) -> None:
    manifest_path = (
        Path(__file__).parents[2]
        / "Builder"
        / "pilots"
        / "self-calibration"
        / "pilot-manifest.v1.json"
    )
    payload = load_pilot_manifest(manifest_path).model_dump(mode="python")
    payload["graphs"][0]["source"]["reference"]["reference_id"] = _TEXT_ID
    manifest = PilotManifestV1.model_validate(payload)

    with pytest.raises(SourceHarnessError, match="admission receipt is required"):
        _harness(tmp_path, pilot_manifest=manifest).prepare_draft(_TEXT_ID, _request())


def test_false_excerpt_is_rejected_against_exact_utf8_bytes(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    with pytest.raises(SourceHarnessError, match="differ from permitted_excerpt"):
        harness.prepare_draft(
            _TEXT_ID,
            _request(excerpt="Curvature is not alternating."),
        )


def test_excerpt_offsets_cannot_exceed_derived_text(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    with pytest.raises(SourceHarnessError, match="offsets exceed"):
        harness.prepare_draft(
            _TEXT_ID,
            _request(end_offset=len(_TEXT_BYTES) + 1),
        )


def test_pdf_cannot_directly_seed_a_statement_draft(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    with pytest.raises(SourceHarnessError, match="require derived text"):
        harness.prepare_draft(
            _PARENT_ID,
            _request(artifact_sha256=_PARENT_SHA256),
        )


def test_derived_text_cannot_draft_without_verified_parent_pdf(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    cache.path_for(_PARENT_ID).unlink()
    with pytest.raises(SourceHarnessError, match="absent from the local cache"):
        _harness(tmp_path, cache).prepare_draft(_TEXT_ID, _request())


def test_span_must_be_located_against_the_verified_text_artifact(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    with pytest.raises(SourceHarnessError, match="another artifact revision"):
        harness.prepare_draft(
            _TEXT_ID,
            _request(artifact_sha256="0" * 64),
        )


def test_manifest_local_only_policy_rejects_external_model_egress(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    with pytest.raises(SourceHarnessError, match="only local model processing"):
        harness.prepare_draft(
            _TEXT_ID,
            _request(
                rights=_rights(
                    endpoint_classes=(
                        EndpointClassV1.LOCAL,
                        EndpointClassV1.APPROVED_EXTERNAL,
                    )
                )
            ),
        )


@pytest.mark.parametrize(
    "update",
    (
        {"source_license": "MIT"},
        {"attribution": "Changed attribution"},
        {"reviewed_by": "different-reviewer"},
        {
            "allowed_endpoint_classes": (
                EndpointClassV1.LOCAL,
                EndpointClassV1.APPROVED_EXTERNAL,
            )
        },
        {"training": PermissionDecisionV1.ALLOW},
        {"embedding": PermissionDecisionV1.ALLOW},
        {"redistribution": PermissionDecisionV1.DENY},
        {"generated_code_license": "BSD-3-Clause"},
    ),
)
def test_packet_rejects_any_rights_change_after_source_preparation(
    tmp_path: Path,
    update: dict[str, object],
) -> None:
    cache = _cache(tmp_path)
    harness = _harness(tmp_path, cache)
    packet = harness.prepare_draft(_TEXT_ID, _request())
    changed_rights = packet.contract.rights.model_copy(update=update)
    changed_contract = packet.contract.model_copy(update={"rights": changed_rights})
    changed_packet = replace(packet, contract=changed_contract)

    with pytest.raises(SourceHarnessError, match="differs from the authority ledger"):
        changed_packet.assert_binds(cache, harness.preparation_ledger)


def test_manifest_ceiling_rejects_external_egress_even_if_packet_copy_is_rebound(
    tmp_path: Path,
) -> None:
    cache = _cache(tmp_path)
    harness = _harness(tmp_path, cache)
    packet = harness.prepare_draft(_TEXT_ID, _request())
    changed_rights = packet.contract.rights.model_copy(
        update={
            "allowed_endpoint_classes": (
                EndpointClassV1.LOCAL,
                EndpointClassV1.APPROVED_EXTERNAL,
            )
        }
    )
    changed_contract = packet.contract.model_copy(update={"rights": changed_rights})
    changed_packet = replace(
        packet,
        contract=changed_contract,
        rights_record=changed_rights,
    )

    with pytest.raises(SourceHarnessError, match="differs from the authority ledger"):
        changed_packet.assert_binds(cache, harness.preparation_ledger)


def test_authority_ledger_rejects_coordinated_rights_and_contract_rebinding(
    tmp_path: Path,
) -> None:
    cache = _cache(tmp_path)
    harness = _harness(tmp_path, cache)
    packet = harness.prepare_draft(_TEXT_ID, _request())
    changed_rights = packet.contract.rights.model_copy(
        update={
            "training": PermissionDecisionV1.ALLOW,
            "embedding": PermissionDecisionV1.ALLOW,
            "generated_code_license": "MIT",
            "reviewed_by": "attacker-controlled-identity",
            "restrictions": (),
        }
    )
    changed_contract = packet.contract.model_copy(update={"rights": changed_rights})
    changed_packet = replace(
        packet,
        contract=changed_contract,
        rights_record=changed_rights,
    )

    with pytest.raises(SourceHarnessError, match="differs from the authority ledger"):
        changed_packet.assert_binds(cache, harness.preparation_ledger)


def test_authority_ledger_rejects_coordinated_locator_and_analyst_rebinding(
    tmp_path: Path,
) -> None:
    cache = _cache(tmp_path)
    harness = _harness(tmp_path, cache)
    packet = harness.prepare_draft(_TEXT_ID, _request())
    changed_span = replace(
        packet.spans[0],
        human_declared_page_locator="pdf:page:1",
        source_analyst_id="attacker-controlled-identity",
    )
    changed_metadata = dict(packet.contract.source.metadata)
    changed_metadata["human_parent_locators"] = (
        {
            "span_id": packet.contract.source.spans[0].span_id.value,
            "chapter_locator": changed_span.human_declared_chapter_locator,
            "page_locator": changed_span.human_declared_page_locator,
            "declared_by": changed_span.source_analyst_id,
            "authority": "human_declared",
        },
    )
    changed_metadata["source_analyst_ids"] = (changed_span.source_analyst_id,)
    changed_source = packet.contract.source.model_copy(update={"metadata": changed_metadata})
    changed_contract = packet.contract.model_copy(update={"source": changed_source})
    changed_packet = replace(
        packet,
        contract=changed_contract,
        spans=(changed_span,),
    )

    with pytest.raises(SourceHarnessError, match="differs from the authority ledger"):
        changed_packet.assert_binds(cache, harness.preparation_ledger)


def test_source_preparation_record_survives_restart_and_conflicts_fail_closed(
    tmp_path: Path,
) -> None:
    cache = _cache(tmp_path)
    harness = _harness(tmp_path, cache)
    packet = harness.prepare_draft(_TEXT_ID, _request())
    restarted = _harness(tmp_path, cache)

    assert packet.assert_binds(cache, restarted.preparation_ledger).entry.sha256 == _TEXT_SHA256
    with pytest.raises(SourceHarnessError, match="append-only contract revision"):
        restarted.prepare_draft(
            _TEXT_ID,
            _request(
                rights=replace(
                    _rights(),
                    generated_code_license="MIT",
                )
            ),
        )


def test_source_preparation_ledger_serializes_conflicting_concurrent_writers(
    tmp_path: Path,
) -> None:
    cache = _cache(tmp_path)
    packet = _harness(tmp_path, cache).prepare_draft(_TEXT_ID, _request())
    root = tmp_path / "concurrent-authority"
    root.mkdir()
    database = root / "source-preparations.sqlite3"
    ledgers = (
        SourcePreparationLedger(database, confinement_root=root),
        SourcePreparationLedger(database, confinement_root=root),
    )
    canonical = packet.preparation_record()
    conflicting = replace(
        canonical,
        preparation_id=stable_identifier("source-preparation", "conflicting-writer"),
        rights_sha256="0" * 64,
    )
    barrier = Barrier(2)

    def write(index: int) -> str:
        barrier.wait()
        try:
            ledgers[index].record((canonical, conflicting)[index])
        except SourcePreparationError:
            return "rejected"
        return "committed"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = tuple(pool.map(write, range(2)))

    assert sorted(outcomes) == ["committed", "rejected"]


def test_packet_rejects_source_metadata_change_after_preparation(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    harness = _harness(tmp_path, cache)
    packet = harness.prepare_draft(_TEXT_ID, _request())
    changed_metadata = dict(packet.contract.source.metadata)
    changed_metadata["reference_model_egress_policy"] = "approved_external"
    changed_source = packet.contract.source.model_copy(update={"metadata": changed_metadata})
    changed_contract = packet.contract.model_copy(update={"source": changed_source})

    with pytest.raises(SourceHarnessError, match="differs from the authority ledger"):
        replace(packet, contract=changed_contract).assert_binds(
            cache,
            harness.preparation_ledger,
        )


def test_contract_binding_fails_after_cache_tampering(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    harness = _harness(tmp_path, cache)
    packet = harness.prepare_draft(_TEXT_ID, _request())
    cache.path_for(_TEXT_ID).write_bytes(b"tampered")
    with pytest.raises(SourceHarnessError, match="mismatch"):
        packet.assert_binds(cache, harness.preparation_ledger)


def test_freeze_wrapper_revalidates_source_before_using_evaluation(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    harness = _harness(tmp_path, cache)
    packet = harness.prepare_draft(_TEXT_ID, _request())
    cache.path_for(_TEXT_ID).write_bytes(b"tampered")

    with pytest.raises(SourceHarnessError, match="mismatch"):
        harness.revalidate_and_freeze(
            packet,
            evaluation=cast(FidelityEvaluation, object()),
            frozen_by="unauthenticated-test-identity",
        )


def test_freeze_wrapper_delegates_only_after_revalidation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    frozen_at = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)
    cache = _cache(tmp_path)
    harness = _harness(tmp_path, cache, clock=lambda: frozen_at)
    packet = harness.prepare_draft(_TEXT_ID, _request())
    evaluation = _timestamp_only_evaluation(
        generated_at=frozen_at,
        reviewed_at=frozen_at,
    )
    observed: dict[str, object] = {}

    def fake_freeze(
        contract,
        *,
        evaluation,
        source_preparation,
        frozen_by,
        gate,
        frozen_at,
    ):
        observed.update(
            {
                "contract": contract,
                "evaluation": evaluation,
                "source_preparation": source_preparation,
                "frozen_by": frozen_by,
                "gate": gate,
                "frozen_at": frozen_at,
            }
        )
        return contract

    monkeypatch.setattr(source_harness_module, "_freeze_reviewed_contract", fake_freeze)
    result = harness.revalidate_and_freeze(
        packet,
        evaluation=evaluation,
        frozen_by="local-structural-test",
    )

    assert result is packet.contract
    assert observed == {
        "contract": packet.contract,
        "evaluation": evaluation,
        "source_preparation": packet.preparation_record(),
        "frozen_by": "local-structural-test",
        "gate": None,
        "frozen_at": frozen_at,
    }


def test_freeze_rejects_naive_harness_clock(tmp_path: Path) -> None:
    naive = datetime(2026, 7, 25, 12, 0)
    cache = _cache(tmp_path)
    harness = _harness(tmp_path, cache, clock=lambda: naive)
    packet = harness.prepare_draft(_TEXT_ID, _request())
    evaluation = _timestamp_only_evaluation(
        generated_at=datetime(2026, 7, 25, 11, 59, tzinfo=UTC),
        reviewed_at=datetime(2026, 7, 25, 11, 59, tzinfo=UTC),
    )

    with pytest.raises(SourceHarnessError, match=r"freeze clock.*timezone-aware"):
        harness.revalidate_and_freeze(
            packet,
            evaluation=evaluation,
            frozen_by="local-structural-test",
        )


@pytest.mark.parametrize(
    ("generated_at", "reviewed_at", "message"),
    (
        (
            datetime(2026, 7, 25, 12, 0, 1, tzinfo=UTC),
            datetime(2026, 7, 25, 11, 59, tzinfo=UTC),
            "fidelity report timestamp is later",
        ),
        (
            datetime(2026, 7, 25, 11, 59, tzinfo=UTC),
            datetime(2026, 7, 25, 12, 0, 1, tzinfo=UTC),
            "fidelity signoff timestamp is later than fidelity report",
        ),
        (
            datetime(2026, 7, 25, 11, 59, tzinfo=UTC),
            datetime(2026, 7, 25, 11, 59, 30, tzinfo=UTC),
            "fidelity signoff timestamp is later than fidelity report",
        ),
    ),
)
def test_freeze_rejects_future_fidelity_evidence(
    tmp_path: Path,
    generated_at: datetime,
    reviewed_at: datetime,
    message: str,
) -> None:
    frozen_at = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)
    cache = _cache(tmp_path)
    harness = _harness(tmp_path, cache, clock=lambda: frozen_at)
    packet = harness.prepare_draft(_TEXT_ID, _request())

    with pytest.raises(SourceHarnessError, match=message):
        harness.revalidate_and_freeze(
            packet,
            evaluation=_timestamp_only_evaluation(
                generated_at=generated_at,
                reviewed_at=reviewed_at,
            ),
            frozen_by="local-structural-test",
        )


def test_bridge_rejects_issue_time_before_freeze(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    frozen_at = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)
    issued_at = datetime(2026, 7, 25, 11, 59, 59, tzinfo=UTC)
    times = iter((frozen_at, issued_at))
    cache = _cache(tmp_path)
    harness = _harness(tmp_path, cache, clock=lambda: next(times))
    packet = harness.prepare_draft(_TEXT_ID, _request())
    evaluation = _timestamp_only_evaluation(
        generated_at=frozen_at,
        reviewed_at=frozen_at,
    )

    def fake_freeze(
        contract,
        *,
        evaluation,
        source_preparation,
        frozen_by,
        gate,
        frozen_at,
    ):
        del contract, evaluation, source_preparation, frozen_by, gate
        return SimpleNamespace(freeze=SimpleNamespace(frozen_at=frozen_at))

    monkeypatch.setattr(source_harness_module, "_freeze_reviewed_contract", fake_freeze)
    with pytest.raises(SourceHarnessError, match="later than bundle issue"):
        harness.revalidate_freeze_and_bridge(
            packet,
            evaluation=evaluation,
            frozen_by="local-structural-test",
            graphs=cast(GraphBundleV1, object()),
            bundle_key="source-time-order-test",
            fidelity_evidence=cast(FidelityEvidenceArtifactRefV1, object()),
            attestor=cast(AttestationSignerV1, object()),
            evidence_identity="artifact:sha256:test-only",
        )
