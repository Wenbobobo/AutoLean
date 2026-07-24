from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest
from autolean_builder.fine_span_attachment import (
    FineSourceSpanV2,
    FineSpanAttachmentError,
    load_fine_source_span_attachment,
)
from autolean_builder.pilot_harness import load_pilot_boundary_decision
from autolean_builder.reference_cache import ReferenceManifestV1

_ROOT = Path(__file__).parents[2]
_ADMISSION_ROOT = _ROOT / "Builder" / "pilots" / "model-theory-admission"
_ATTACHMENT_PATH = _ADMISSION_ROOT / "fine-source-spans.v2.json"
_DECISION_PATH = _ADMISSION_ROOT / "decision.v2.json"
_MATRIX_PATH = _ADMISSION_ROOT / "source-rule-matrix.v2.json"
_MANIFEST_PATH = _ROOT / "Builder" / "references" / "manifest.v2.json"
_REFERENCE_ID = "openlogic-sets-logic-computation-2026-07-12-text-pypdf-6.14.2"


def test_committed_fine_spans_bind_the_gap_decision_and_v2_reference() -> None:
    attachment = load_fine_source_span_attachment(_ATTACHMENT_PATH)
    decision = load_pilot_boundary_decision(_DECISION_PATH)
    manifest = ReferenceManifestV1.load(_MANIFEST_PATH)

    attachment.assert_binds_decision(decision)
    attachment.assert_binds_reference_manifest(manifest)
    attachment.assert_binds_rule_matrix(_MATRIX_PATH)

    assert attachment.schema_version == "autolean.public-t3-fine-source-spans.v2"
    assert attachment.decision_binding.t3_disposition == "gap"
    assert attachment.decision_binding.selection == "not_selected"
    assert attachment.decision_binding.statement_contract == "not_frozen"
    assert attachment.decision_binding.prover_handoff == "forbidden"
    assert attachment.reference_binding.reference_id == _REFERENCE_ID
    assert (
        attachment.reference_binding.manifest_sha256
        == hashlib.sha256(_MANIFEST_PATH.read_bytes()).hexdigest()
    )
    assert attachment.reference_binding.contains_source_excerpt is False
    assert attachment.reference_binding.contains_local_cache_path is False


def test_committed_fine_spans_cover_every_matrix_requirement_without_authority() -> None:
    attachment = load_fine_source_span_attachment(_ATTACHMENT_PATH)
    matrix = json.loads(_MATRIX_PATH.read_bytes())
    requirement_ids = {item["requirement_id"] for item in matrix["required_fine_source_anchors"]}

    assert len(requirement_ids) == 9
    assert len(attachment.spans) == 10
    assert {span.requirement_id for span in attachment.spans} == requirement_ids
    assert all(span.location_state == "machine_located_pending_review" for span in attachment.spans)
    assert all(
        0 <= span.start_offset < span.end_offset <= attachment.reference_binding.source_size_bytes
        for span in attachment.spans
    )
    assert all(len(span.raw_sha256) == 64 for span in attachment.spans)
    assert sum(span.requirement_id == "lk-validity-and-soundness" for span in attachment.spans) == 2

    ambiguity_ids = {item.ambiguity_id for item in attachment.locator_ambiguities}
    assert ambiguity_ids == {
        "section-7-5-page-pair-unreconciled",
        "universal-right-page-pair-unreconciled",
    }
    authority = attachment.authority_boundary
    assert authority.review_state == "machine_located_pending_review"
    assert authority.human_visual_review_present is False
    assert authority.semantic_review_present is False
    assert authority.expert_review_present is False
    assert authority.builder_admission_authority_present is False
    assert authority.may_change_boundary_decision is False
    assert authority.may_issue_admission_receipt is False
    assert authority.may_freeze_statement is False
    assert authority.may_handoff_to_prover is False
    assert attachment.effect_on_t3 == "none_until_authorized_visual_and_semantic_review"


def test_source_artifact_replay_checks_range_and_raw_digest(tmp_path: Path) -> None:
    attachment = load_fine_source_span_attachment(_ATTACHMENT_PATH)
    raw = b"prefix:bound-span:suffix"
    start_offset = raw.index(b"bound-span")
    end_offset = start_offset + len(b"bound-span")
    reference_binding = attachment.reference_binding.model_copy(
        update={
            "source_artifact_sha256": hashlib.sha256(raw).hexdigest(),
            "source_size_bytes": len(raw),
        }
    )
    span = FineSourceSpanV2(
        span_id="synthetic-span",
        requirement_id="synthetic-requirement",
        segment_id="synthetic-segment",
        start_offset=start_offset,
        end_offset=end_offset,
        raw_sha256=hashlib.sha256(raw[start_offset:end_offset]).hexdigest(),
    )
    replayable = attachment.model_copy(
        update={
            "reference_binding": reference_binding,
            "spans": (span,),
            "locator_ambiguities": (),
        }
    )
    source_path = tmp_path / "source.txt"
    source_path.write_bytes(raw)

    replayable.assert_matches_source_artifact(source_path)

    source_path.write_bytes(raw.replace(b"bound-span", b"bound-spun"))
    with pytest.raises(FineSpanAttachmentError, match="digest or size changed"):
        replayable.assert_matches_source_artifact(source_path)

    mutated = source_path.read_bytes()
    rebound_reference = reference_binding.model_copy(
        update={"source_artifact_sha256": hashlib.sha256(mutated).hexdigest()}
    )
    rebound = replayable.model_copy(update={"reference_binding": rebound_reference})
    with pytest.raises(FineSpanAttachmentError, match="span no longer binds"):
        rebound.assert_matches_source_artifact(source_path)


@pytest.mark.parametrize(
    ("raw", "message"),
    (
        (b"{", "not valid UTF-8 JSON"),
        (b"\xff", "not valid UTF-8 JSON"),
        (
            b'{"schema_version":"first","schema_version":"second"}',
            "duplicate JSON key",
        ),
        (b"[]", "root must be an object"),
    ),
)
def test_attachment_loader_rejects_ambiguous_or_invalid_json(
    tmp_path: Path,
    raw: bytes,
    message: str,
) -> None:
    attachment_path = tmp_path / "attachment.json"
    attachment_path.write_bytes(raw)

    with pytest.raises(FineSpanAttachmentError, match=message):
        load_fine_source_span_attachment(attachment_path)


def test_attachment_rejects_decision_manifest_and_matrix_drift(tmp_path: Path) -> None:
    attachment = load_fine_source_span_attachment(_ATTACHMENT_PATH)
    decision = load_pilot_boundary_decision(_DECISION_PATH)
    decision_drift = decision.model_copy(
        update={"blocker_ids": (*decision.blocker_ids, "test-only-drift")}
    )
    with pytest.raises(FineSpanAttachmentError, match="another T3 decision"):
        attachment.assert_binds_decision(decision_drift)

    manifest = ReferenceManifestV1.load(_MANIFEST_PATH)
    manifest_drift = replace(manifest, manifest_sha256="0" * 64)
    with pytest.raises(FineSpanAttachmentError, match="manifest provenance changed"):
        attachment.assert_binds_reference_manifest(manifest_drift)

    matrix_drift_path = tmp_path / "source-rule-matrix.v2.json"
    matrix_drift_path.write_bytes(_MATRIX_PATH.read_bytes() + b"\n")
    with pytest.raises(FineSpanAttachmentError, match="another source-rule matrix"):
        attachment.assert_binds_rule_matrix(matrix_drift_path)


def test_optional_local_v2_cache_replays_all_committed_span_hashes() -> None:
    attachment = load_fine_source_span_attachment(_ATTACHMENT_PATH)
    cache_path = (
        _ROOT
        / ".cache"
        / "references"
        / _REFERENCE_ID
        / f"{attachment.reference_binding.source_artifact_sha256}.txt"
    )
    if not cache_path.exists():
        pytest.skip("official local pypdf 6.14.2 source cache is intentionally absent")

    attachment.assert_matches_source_artifact(cache_path)
