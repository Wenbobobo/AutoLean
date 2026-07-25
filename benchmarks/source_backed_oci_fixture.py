"""Public source-backed fixture for the exact pure-Lean OCI verification path.

This module is architecture-test evidence only.  Its translator, mutation, and reviewer
actors are deterministic fixtures, not human semantic review and not promotion authority.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from autolean_builder import (
    CandidateFormalization,
    CandidateGenerationTask,
    CandidateProposal,
    CandidateReviewVerdict,
    ChapterSourceSpan,
    FidelityEvaluation,
    MutationReviewVerdict,
    ObligationReviewVerdict,
    ReferenceCache,
    ReferenceManifestV1,
    RightsReview,
    SemanticObligation,
    SemanticObligationKind,
    SemanticReviewPacket,
    SemanticReviewVerdict,
    SourcePreparationLedger,
    SourceToStatementHarness,
    StatementDraftPacket,
    StatementDraftRequest,
    TranslationTask,
)
from autolean_contracts import (
    AttestationSignerV1,
    DecisionV1,
    ExecutionGraphV1,
    FidelityEvidenceArtifactRefV1,
    FidelityRiskV1,
    FormalGraphV1,
    FormalizationTaskBundleV1,
    FormalSpecificationV1,
    GraphBundleV1,
    HashKindV1,
    LeanEnvironmentV1,
    MathematicalGraphV1,
    MathematicalSpecificationV1,
    MutationKindV1,
    MutationProbeV1,
    OciVerifierExecutionPolicyV2,
    PermissionDecisionV1,
    ReleaseTierV1,
    StableIdentifierV1,
    TaskKindV1,
    TaskPolicyV1,
    digest_text,
    stable_identifier,
)
from autolean_control_plane import ArtifactRef, ArtifactStore

PROTOCOL: Final[str] = "autolean.oci-lean-wrapper.v2"
TYPE_FORMAT: Final[str] = "autolean.lean-pp-expr.v1"
DECLARATION: Final[str] = "AutoLean.OCI.fixture"
STATEMENT: Final[str] = "theorem fixture (n : Nat) : n = n"
CANONICAL_TYPE: Final[str] = "∀ (n : Nat), @Eq.{1} Nat n n"
LEAN_VERSION: Final[str] = "v4.28.0"
MATHLIB_REVISION: Final[str] = "none-pure-lean-v4.28.0"

_FIXED_TIME: Final[datetime] = datetime(2026, 1, 1, tzinfo=UTC)
_SOURCE_TEXT: Final[str] = "Every natural number equals itself."
_NORMALIZED_STATEMENT: Final[str] = "For every natural number n, n equals itself."
_PARENT_REFERENCE_ID: Final[str] = "oci-source-backed-parent-v1"
_TEXT_REFERENCE_ID: Final[str] = "oci-source-backed-text-v1"
_PYPDF_VERSION: Final[str] = "6.14.2"


def _parent_pdf_bytes(text: str) -> bytes:
    """Render one deterministic, valid PDF page containing the exact source claim."""

    content = f"BT\n/F1 12 Tf\n72 720 Td\n({text}) Tj\nET\n".encode("ascii")
    objects = (
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"
        ),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        (
            b"<< /Length "
            + str(len(content)).encode("ascii")
            + b" >>\nstream\n"
            + content
            + b"endstream"
        ),
    )
    rendered = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: list[int] = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(rendered))
        rendered.extend(f"{number} 0 obj\n".encode("ascii"))
        rendered.extend(body)
        rendered.extend(b"\nendobj\n")
    xref_offset = len(rendered)
    rendered.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    rendered.extend(b"0000000000 65535 f \n")
    for offset in offsets:
        rendered.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    rendered.extend(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF\n"
        ).encode("ascii")
    )
    return bytes(rendered)


_PARENT_BYTES: Final[bytes] = _parent_pdf_bytes(_SOURCE_TEXT)
_TEXT_BYTES: Final[bytes] = _SOURCE_TEXT.encode("utf-8")
_PARENT_SHA256: Final[str] = hashlib.sha256(_PARENT_BYTES).hexdigest()
_TEXT_SHA256: Final[str] = hashlib.sha256(_TEXT_BYTES).hexdigest()
_ATTRIBUTION: Final[str] = "AutoLean public synthetic OCI architecture fixture."


@dataclass(frozen=True, slots=True)
class SourceBackedOciFixture:
    """One exact Builder handoff and the evidence that produced it."""

    packet: StatementDraftPacket
    evaluation: FidelityEvaluation
    fidelity_artifact: ArtifactRef
    bundle: FormalizationTaskBundleV1


def _id(key: str) -> StableIdentifierV1:
    return stable_identifier("source-backed-oci-fixture", key)


def _reference_entry(
    *,
    reference_id: str,
    payload: bytes,
    media_type: str,
    extension: str,
    artifact_kind: str,
    derivation: dict[str, object] | None,
) -> dict[str, object]:
    is_derived_text = artifact_kind == "derived_text"
    return {
        "reference_id": reference_id,
        "title": "AutoLean public OCI source-backed fixture",
        "authors": ["AutoLean contributors"],
        "version": "fixture-v1",
        "citation": "AutoLean public OCI source-backed fixture, fixture-v1.",
        "source_record_url": "https://example.invalid/autolean/oci-source-backed",
        "download_url": (
            None
            if is_derived_text
            else f"https://example.invalid/autolean/{reference_id}{extension}"
        ),
        "allowed_redirect_urls": [],
        "media_type": media_type,
        "file_extension": extension,
        "size_bytes": len(payload),
        "max_bytes": len(payload) + 64,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "retrieved_at": _FIXED_TIME.isoformat().replace("+00:00", "Z"),
        "license": {
            "expression": "CC0-1.0",
            "url": "https://creativecommons.org/publicdomain/zero/1.0/",
            "evidence_url": "https://example.invalid/autolean/oci-source-backed",
        },
        "access_policy": "public_open_access",
        "acquisition_policy": ("local_derivation_only" if is_derived_text else "operator_only"),
        "model_egress_policy": "local_only",
        "artifact_kind": artifact_kind,
        "derivation": derivation,
        "attribution": _ATTRIBUTION,
    }


def _source_harness(root: Path) -> SourceToStatementHarness:
    import pypdf

    if pypdf.__version__ != _PYPDF_VERSION:
        raise RuntimeError("source-backed fixture pypdf version differs from its provenance")

    root.mkdir(parents=True, exist_ok=True)
    manifest_payload = {
        "schema_version": "autolean.reference-manifest.v1",
        "entries": [
            _reference_entry(
                reference_id=_PARENT_REFERENCE_ID,
                payload=_PARENT_BYTES,
                media_type="application/pdf",
                extension=".pdf",
                artifact_kind="source_document",
                derivation=None,
            ),
            _reference_entry(
                reference_id=_TEXT_REFERENCE_ID,
                payload=_TEXT_BYTES,
                media_type="text/plain",
                extension=".txt",
                artifact_kind="derived_text",
                derivation={
                    "kind": "local_pdf_text_extraction",
                    "parent_reference_id": _PARENT_REFERENCE_ID,
                    "parent_sha256": _PARENT_SHA256,
                    "producer": "AutoLean deterministic pypdf fixture extraction",
                    "method": "pypdf-pdfreader-extract-text-plain-form-feed-v1",
                    "tool_name": "pypdf",
                    "tool_version": _PYPDF_VERSION,
                    "provenance_url": "https://example.invalid/autolean/oci-source-backed",
                    "parent_locator_authority": "manifest_bound",
                },
            ),
        ],
    }
    manifest_path = root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest_payload), encoding="utf-8")

    cache = ReferenceCache(
        ReferenceManifestV1.load(manifest_path),
        root / "cache",
        confinement_root=root,
    )
    with tempfile.TemporaryDirectory(prefix="source-input-", dir=root) as raw_inputs:
        input_root = Path(raw_inputs)
        parent_path = input_root / "synthetic-parent.pdf"
        parent_path.write_bytes(_PARENT_BYTES)
        parent = cache.operator_import_local(_PARENT_REFERENCE_ID, parent_path)

        reader = pypdf.PdfReader(parent.verified.cache_path)
        extracted = "\f".join(
            page.extract_text(extraction_mode="plain") or "" for page in reader.pages
        ).encode("utf-8")
        if extracted != _TEXT_BYTES:
            raise RuntimeError("source-backed fixture derived text differs from its parent PDF")
        extracted_path = input_root / "pypdf-6.14.2-extracted.txt"
        extracted_path.write_bytes(extracted)
        cache.operator_import_local(_TEXT_REFERENCE_ID, extracted_path)
    return SourceToStatementHarness(
        cache,
        preparation_ledger=SourcePreparationLedger(
            root / "source-preparations.db",
            confinement_root=root,
        ),
        clock=lambda: _FIXED_TIME,
    )


def _draft_request(image_digest: str) -> StatementDraftRequest:
    policy = OciVerifierExecutionPolicyV2(worker_image_digest=image_digest)
    environment = LeanEnvironmentV1(
        lean_version=LEAN_VERSION,
        mathlib_revision=MATHLIB_REVISION,
        verifier_execution_policy=policy,
        environment_hash=digest_text(
            HashKindV1.ENVIRONMENT,
            "pure-lean-4.28.0:"
            f"{image_digest}:{TYPE_FORMAT}:"
            f"{policy.schema_version}:{policy.command_policy_hash().value}",
        ),
    )
    formal = FormalSpecificationV1(
        declaration_name="fixture",
        namespace="AutoLean.OCI",
        lean_statement_source=STATEMENT,
        statement_source_hash=digest_text(HashKindV1.STATEMENT_SOURCE, STATEMENT),
        elaborated_type=CANONICAL_TYPE,
        elaborated_type_hash=digest_text(HashKindV1.ELABORATED_TYPE, CANONICAL_TYPE),
        environment=environment,
        imports_allowlist=(),
    )
    source_bytes = _SOURCE_TEXT.encode()
    start_offset = _TEXT_BYTES.index(source_bytes)
    return StatementDraftRequest(
        contract_key="oci-source-backed.fixture",
        revision=2,
        task_kind=TaskKindV1.KNOWN_THEOREM,
        spans=(
            ChapterSourceSpan(
                span_key="fixture-r2",
                human_declared_chapter_locator="synthetic:claim",
                human_declared_page_locator="synthetic:page:1",
                permitted_excerpt=_SOURCE_TEXT,
                source_analyst_id="oci-source-backed-source-analyst",
                verified_artifact_sha256=_TEXT_SHA256,
                start_offset=start_offset,
                end_offset=start_offset + len(source_bytes),
            ),
        ),
        rights=RightsReview(
            review_key="oci-source-backed-rights-v1",
            source_license="CC0-1.0",
            generated_code_license="Apache-2.0",
            overall_decision=PermissionDecisionV1.ALLOW,
            redistribution=PermissionDecisionV1.ALLOW,
            model_egress=PermissionDecisionV1.DENY,
            training=PermissionDecisionV1.RESTRICTED,
            embedding=PermissionDecisionV1.RESTRICTED,
            allowed_endpoint_classes=(),
            attribution=_ATTRIBUTION,
            restrictions=("test-only architecture fixture",),
            reviewed_by="oci-source-backed-rights-fixture",
            reviewed_at=_FIXED_TIME,
        ),
        mathematics=MathematicalSpecificationV1(
            informal_statement=_SOURCE_TEXT,
            normalized_statement=_NORMALIZED_STATEMENT,
            quantifier_order=("forall n : Nat",),
        ),
        formal=formal,
        policy=TaskPolicyV1(
            release_tier=ReleaseTierV1.CALIBRATION,
            fidelity_risk=FidelityRiskV1.L1_SIMPLE,
        ),
        alignment_reviewer_id="oci-source-backed-test-reviewer",
    )


def _obligations(packet: StatementDraftPacket) -> tuple[SemanticObligation, ...]:
    source_span_id = packet.contract.source.spans[0].span_id
    return (
        SemanticObligation(
            obligation_id="quantifier-order",
            kind=SemanticObligationKind.QUANTIFIER_ORDER,
            description="The claim quantifies over every natural number.",
            source_span_ids=(source_span_id,),
            normalized_fragment="For every natural number n",
            lean_fragment="(n : Nat)",
        ),
        SemanticObligation(
            obligation_id="conclusion",
            kind=SemanticObligationKind.CONCLUSION,
            description="The quantified number is equal to itself.",
            source_span_ids=(source_span_id,),
            normalized_fragment="n equals itself",
            lean_fragment="n = n",
        ),
        SemanticObligation(
            obligation_id="non-vacuity",
            kind=SemanticObligationKind.NON_VACUITY,
            description="Nat has concrete witnesses such as zero.",
            source_span_ids=(source_span_id,),
            normalized_fragment="natural number",
            lean_fragment="Nat",
        ),
    )


@dataclass(slots=True)
class _Translator:
    actor_id: str
    independence_group: str
    oracle_lean_statement: str

    def translate(self, task: CandidateGenerationTask) -> CandidateProposal:
        return CandidateProposal(
            candidate_id=f"candidate-{self.actor_id}",
            lean_statement_source=self.oracle_lean_statement,
            reverse_rendering=task.mathematics.normalized_statement,
            covered_obligation_ids=tuple(item.obligation_id for item in task.obligations),
        )


@dataclass(slots=True)
class _MutationAgent:
    actor_id: str = "oci-source-backed-test-mutation-agent"

    def generate(
        self,
        task: TranslationTask,
        selected_candidate: CandidateFormalization,
    ) -> tuple[MutationProbeV1, ...]:
        del task, selected_candidate
        changes = {
            MutationKindV1.DROP_ASSUMPTION: "theorem fixture : True",
            MutationKindV1.SWAP_QUANTIFIERS: ("theorem fixture : ∃ n : Nat, ∀ m : Nat, n = n"),
            MutationKindV1.WEAKEN_RELATION: ("theorem fixture (n : Nat) : Or (n = n) False"),
            MutationKindV1.REMOVE_SIDE_CONDITION: "theorem fixture (n : Nat) : True",
            MutationKindV1.DROP_NONEMPTY: ("theorem fixture (n : Nat) : n = n ∧ True"),
            MutationKindV1.DROP_FINITE: ("theorem fixture (n : Nat) : True ∧ n = n"),
            MutationKindV1.DROP_NOETHERIAN: ("theorem fixture (n : Nat) : n = n → True"),
            MutationKindV1.REVERSE_PARAMETERS: ("theorem fixture (m n : Nat) : n = m"),
            MutationKindV1.VACUITY: ("theorem fixture (n : Nat) (impossible : False) : n = n"),
        }
        return tuple(
            MutationProbeV1(
                probe_id=_id(f"mutation-{kind.value}"),
                kind=kind,
                target_path="/formal/lean_statement_source",
                expected_failure="the test reviewer rejects the changed statement bytes",
                mutated_statement_source=mutated,
            )
            for kind, mutated in changes.items()
        )


@dataclass(slots=True)
class _SemanticReviewer:
    reviewer_id: str = "oci-source-backed-test-reviewer"

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
                        rationale="the public synthetic claim preserves this exact L1 obligation",
                    )
                    for obligation in packet.task.obligations
                ),
                rationale="test-only candidate bytes equal the selected frozen statement",
            )
            for candidate in packet.candidates
        )
        return SemanticReviewVerdict(
            review_id="oci-source-backed-test-review-v1",
            reviewer_id=self.reviewer_id,
            independent=True,
            decision=DecisionV1.ACCEPT,
            source_to_normalized_equivalent=True,
            source_to_normalized_evidence="the normalized sentence preserves reflexive equality",
            candidate_verdicts=candidate_verdicts,
            mutation_verdicts=tuple(
                MutationReviewVerdict(
                    probe_id=probe.probe_id,
                    detected=True,
                    rationale=(
                        "the hostile statement is byte-distinct and no longer the exact "
                        "source-backed theorem; inapplicable premise categories are protocol "
                        "sentinels for this L1 fixture"
                    ),
                )
                for probe in packet.mutation_probes
            ),
            positive_example_valid=True,
            positive_example_evidence="n=0 gives the concrete proposition 0=0",
            negative_example_valid=True,
            negative_example_evidence="0 is not 1, detecting the reversed-parameter mutation",
            non_vacuous=True,
            non_vacuity_evidence="Nat is inhabited by zero without additional assumptions",
            rationale=(
                "deterministic architecture-test review only; this is not human expert "
                "promotion evidence"
            ),
        )


def _graphs() -> GraphBundleV1:
    return GraphBundleV1(
        mathematical=MathematicalGraphV1(graph_id=_id("mathematical-graph"), revision=2),
        formal=FormalGraphV1(graph_id=_id("formal-graph"), revision=2),
        execution=ExecutionGraphV1(graph_id=_id("execution-graph"), revision=2),
    )


def build_source_backed_oci_fixture(
    root: Path,
    *,
    artifact_store: ArtifactStore,
    image_digest: str,
    attestor: AttestationSignerV1,
) -> SourceBackedOciFixture:
    """Build exactly one reviewed handoff for CI or an operator-run OCI canary."""

    harness = _source_harness(root)
    packet = harness.prepare_draft(_TEXT_REFERENCE_ID, _draft_request(image_digest))
    evaluation = harness.run_fidelity(
        packet,
        obligations=_obligations(packet),
        translators=(
            _Translator(
                "oci-source-backed-translator-a",
                "independence-a",
                packet.contract.formal.lean_statement_source,
            ),
            _Translator(
                "oci-source-backed-translator-b",
                "independence-b",
                packet.contract.formal.lean_statement_source,
            ),
        ),
        mutation_agent=_MutationAgent(),
        reviewer=_SemanticReviewer(),
    )
    fidelity_artifact = artifact_store.put_bytes(evaluation.render_artifact())
    bundle = harness.revalidate_freeze_and_bridge(
        packet,
        evaluation=evaluation,
        frozen_by="oci-source-backed-test-freezer",
        graphs=_graphs(),
        bundle_key="oci-source-backed-r2",
        fidelity_evidence=FidelityEvidenceArtifactRefV1(
            digest=evaluation.evidence_hash,
            size=fidelity_artifact.size,
        ),
        attestor=attestor,
        evidence_identity=fidelity_artifact.uri,
    )
    return SourceBackedOciFixture(
        packet=packet,
        evaluation=evaluation,
        fidelity_artifact=fidelity_artifact,
        bundle=bundle,
    )
