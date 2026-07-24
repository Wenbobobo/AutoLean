"""Replay public-safe machine-located source spans without granting admission authority."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Collection, Mapping
from pathlib import Path
from typing import Literal

from autolean_contracts import ContractModel, canonical_json_bytes
from pydantic import Field, model_validator

from .pilot_harness import PilotBoundaryDecisionV2
from .reference_cache import (
    ReferenceArtifactKind,
    ReferenceDerivationKind,
    ReferenceManifestV1,
)


class FineSpanAttachmentError(ValueError):
    """A fine-span attachment or one of its bound artifacts did not replay."""


class FineSpanDecisionBindingV2(ContractModel):
    decision_path: Literal["Builder/pilots/model-theory-admission/decision.v2.json"] = (
        "Builder/pilots/model-theory-admission/decision.v2.json"
    )
    decision_canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,95}$")
    candidate_revision: str = Field(pattern=r"^[a-z0-9][a-z0-9.-]{2,95}$")
    t3_disposition: Literal["gap"] = "gap"
    selection: Literal["not_selected"] = "not_selected"
    statement_contract: Literal["not_frozen"] = "not_frozen"
    prover_handoff: Literal["forbidden"] = "forbidden"


class FineSpanRuleMatrixBindingV2(ContractModel):
    matrix_path: Literal["Builder/pilots/model-theory-admission/source-rule-matrix.v2.json"] = (
        "Builder/pilots/model-theory-admission/source-rule-matrix.v2.json"
    )
    matrix_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    required_fine_anchor_count: int = Field(ge=1)


class FineSpanReferenceBindingV2(ContractModel):
    manifest_path: Literal["Builder/references/manifest.v2.json"] = (
        "Builder/references/manifest.v2.json"
    )
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reference_id: str = Field(pattern=r"^[a-z0-9][a-z0-9.-]{2,127}$")
    source_artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_size_bytes: int = Field(gt=0)
    parent_reference_id: str = Field(pattern=r"^[a-z0-9][a-z0-9.-]{2,127}$")
    parent_artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    extraction_method: str = Field(min_length=1)
    extraction_tool_name: Literal["pypdf"] = "pypdf"
    extraction_tool_version: Literal["6.14.2"] = "6.14.2"
    contains_source_excerpt: Literal[False] = False
    contains_local_cache_path: Literal[False] = False


class FineSourceSpanV2(ContractModel):
    span_id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,127}$")
    requirement_id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,127}$")
    segment_id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,127}$")
    start_offset: int = Field(ge=0)
    end_offset: int = Field(gt=0)
    raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    location_state: Literal["machine_located_pending_review"] = "machine_located_pending_review"

    @model_validator(mode="after")
    def validate_range(self) -> FineSourceSpanV2:
        if self.end_offset <= self.start_offset:
            raise ValueError("fine source span byte range must be nonempty")
        return self


class FineSpanLocatorAmbiguityV2(ContractModel):
    ambiguity_id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,127}$")
    requirement_id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,127}$")
    segment_id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,127}$")
    matrix_locator_snapshot: str = Field(min_length=1)
    review_state: Literal["pending_visual_review"] = "pending_visual_review"
    note: str = Field(min_length=1)


class FineSpanAuthorityBoundaryV2(ContractModel):
    record_kind: Literal["machine_locator_output"] = "machine_locator_output"
    review_state: Literal["machine_located_pending_review"] = "machine_located_pending_review"
    human_visual_review_present: Literal[False] = False
    semantic_review_present: Literal[False] = False
    expert_review_present: Literal[False] = False
    builder_admission_authority_present: Literal[False] = False
    may_change_boundary_decision: Literal[False] = False
    may_issue_admission_receipt: Literal[False] = False
    may_freeze_statement: Literal[False] = False
    may_handoff_to_prover: Literal[False] = False


class FineSourceSpanAttachmentV2(ContractModel):
    """A digest-only T3 attachment whose evidence is explicitly non-authoritative."""

    schema_version: Literal["autolean.public-t3-fine-source-spans.v2"] = (
        "autolean.public-t3-fine-source-spans.v2"
    )
    artifact_kind: Literal["public_safe_t3_gap_attachment"] = "public_safe_t3_gap_attachment"
    decision_binding: FineSpanDecisionBindingV2
    rule_matrix_binding: FineSpanRuleMatrixBindingV2
    reference_binding: FineSpanReferenceBindingV2
    spans: tuple[FineSourceSpanV2, ...] = Field(min_length=1)
    locator_ambiguities: tuple[FineSpanLocatorAmbiguityV2, ...] = ()
    authority_boundary: FineSpanAuthorityBoundaryV2
    effect_on_t3: Literal["none_until_authorized_visual_and_semantic_review"] = (
        "none_until_authorized_visual_and_semantic_review"
    )

    @model_validator(mode="after")
    def validate_attachment(self) -> FineSourceSpanAttachmentV2:
        span_ids = [span.span_id for span in self.spans]
        segments = [(span.requirement_id, span.segment_id) for span in self.spans]
        if len(span_ids) != len(set(span_ids)):
            raise ValueError("fine source span identifiers must be unique")
        if len(segments) != len(set(segments)):
            raise ValueError("fine source span requirement segments must be unique")
        known_segments = set(segments)
        ambiguity_ids = [ambiguity.ambiguity_id for ambiguity in self.locator_ambiguities]
        if len(ambiguity_ids) != len(set(ambiguity_ids)):
            raise ValueError("fine source locator ambiguity identifiers must be unique")
        if any(
            (ambiguity.requirement_id, ambiguity.segment_id) not in known_segments
            for ambiguity in self.locator_ambiguities
        ):
            raise ValueError("fine source locator ambiguity references an unknown segment")
        return self

    def canonical_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self)).hexdigest()

    def assert_binds_decision(self, decision: PilotBoundaryDecisionV2) -> None:
        binding = self.decision_binding
        if (
            decision.canonical_sha256() != binding.decision_canonical_sha256
            or decision.candidate.candidate_id != binding.candidate_id
            or decision.candidate.revision != binding.candidate_revision
            or decision.disposition.value != binding.t3_disposition
        ):
            raise FineSpanAttachmentError("fine source spans bind another T3 decision")

    def assert_binds_reference_manifest(self, manifest: ReferenceManifestV1) -> None:
        binding = self.reference_binding
        try:
            source = manifest.require(binding.reference_id)
            parent = manifest.require(binding.parent_reference_id)
        except ValueError as error:
            raise FineSpanAttachmentError("fine source reference is not manifest-bound") from error
        derivation = source.derivation
        if (
            manifest.manifest_sha256 != binding.manifest_sha256
            or source.sha256 != binding.source_artifact_sha256
            or source.size_bytes != binding.source_size_bytes
            or source.artifact_kind is not ReferenceArtifactKind.DERIVED_TEXT
            or parent.sha256 != binding.parent_artifact_sha256
            or derivation is None
            or derivation.kind is not ReferenceDerivationKind.LOCAL_PDF_TEXT_EXTRACTION
            or derivation.parent_reference_id != binding.parent_reference_id
            or derivation.parent_sha256 != binding.parent_artifact_sha256
            or derivation.method != binding.extraction_method
            or derivation.tool_name != binding.extraction_tool_name
            or derivation.tool_version != binding.extraction_tool_version
        ):
            raise FineSpanAttachmentError("fine source manifest provenance changed")

    def assert_binds_rule_matrix(self, path: Path) -> None:
        try:
            raw = path.read_bytes()
        except OSError as error:
            raise FineSpanAttachmentError(
                f"cannot read bound source-rule matrix: {path}"
            ) from error
        if hashlib.sha256(raw).hexdigest() != self.rule_matrix_binding.matrix_sha256:
            raise FineSpanAttachmentError("fine source spans bind another source-rule matrix")
        payload = _load_json_object(raw, label="source-rule matrix")
        requirements = payload.get("required_fine_source_anchors")
        if not isinstance(requirements, list):
            raise FineSpanAttachmentError("source-rule matrix lacks fine anchor requirements")
        requirement_ids: list[str] = []
        for requirement in requirements:
            if not isinstance(requirement, Mapping):
                raise FineSpanAttachmentError("source-rule matrix fine anchor is not an object")
            requirement_id = requirement.get("requirement_id")
            if not isinstance(requirement_id, str):
                raise FineSpanAttachmentError("source-rule matrix fine anchor lacks an identifier")
            requirement_ids.append(requirement_id)
        if len(requirement_ids) != self.rule_matrix_binding.required_fine_anchor_count:
            raise FineSpanAttachmentError("source-rule matrix fine anchor count changed")
        self.assert_requirement_coverage(requirement_ids)

    def assert_requirement_coverage(self, requirement_ids: Collection[str]) -> None:
        expected = set(requirement_ids)
        actual = {span.requirement_id for span in self.spans}
        if len(expected) != len(requirement_ids) or actual != expected:
            raise FineSpanAttachmentError(
                "fine source spans do not cover exactly the matrix requirements"
            )

    def assert_matches_source_artifact(self, path: Path) -> None:
        try:
            raw = path.read_bytes()
        except OSError as error:
            raise FineSpanAttachmentError(f"cannot read fine source artifact: {path}") from error
        binding = self.reference_binding
        if (
            len(raw) != binding.source_size_bytes
            or hashlib.sha256(raw).hexdigest() != binding.source_artifact_sha256
        ):
            raise FineSpanAttachmentError("fine source artifact digest or size changed")
        for span in self.spans:
            if span.end_offset > len(raw):
                raise FineSpanAttachmentError(f"fine source span is out of bounds: {span.span_id}")
            if hashlib.sha256(raw[span.start_offset : span.end_offset]).hexdigest() != (
                span.raw_sha256
            ):
                raise FineSpanAttachmentError(f"fine source span no longer binds: {span.span_id}")


def load_fine_source_span_attachment(path: Path) -> FineSourceSpanAttachmentV2:
    """Load one strict public attachment while rejecting duplicate JSON keys."""

    try:
        raw = path.read_bytes()
    except OSError as error:
        raise FineSpanAttachmentError(f"cannot read fine source span attachment: {path}") from error
    payload = _load_json_object(raw, label="fine source span attachment")
    try:
        return FineSourceSpanAttachmentV2.model_validate(payload)
    except ValueError as error:
        raise FineSpanAttachmentError(f"fine source span attachment is invalid: {error}") from error


def _load_json_object(raw: bytes, *, label: str) -> dict[str, object]:
    try:
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except FineSpanAttachmentError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FineSpanAttachmentError(f"{label} is not valid UTF-8 JSON") from error
    if not isinstance(payload, dict):
        raise FineSpanAttachmentError(f"{label} root must be an object")
    return payload


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise FineSpanAttachmentError(f"duplicate JSON key in fine-span evidence: {key}")
        result[key] = value
    return result
