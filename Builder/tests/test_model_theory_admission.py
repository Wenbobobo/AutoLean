from __future__ import annotations

import hashlib
import json
from pathlib import Path

from autolean_builder import (
    ReferenceCache,
    ReferenceManifestV1,
    load_pilot_manifest,
)
from autolean_builder.pilot_harness import (
    PilotBoundaryDispositionV2,
    PilotRuleCoverageStateV2,
    load_pilot_boundary_decision,
)
from autolean_contracts import canonical_json_bytes

_ROOT = Path(__file__).parents[2]
_ADMISSION_ROOT = _ROOT / "Builder" / "pilots" / "model-theory-admission"
_DECISION_PATH = _ADMISSION_ROOT / "decision.v2.json"
_REVIEW_PATH = _ADMISSION_ROOT / "review-evidence.v2.json"
_MATRIX_PATH = _ADMISSION_ROOT / "source-rule-matrix.v2.json"
_PILOT_MANIFEST_PATH = _ROOT / "Builder" / "pilots" / "self-calibration" / "pilot-manifest.v1.json"
_REFERENCE_MANIFEST_PATH = _ROOT / "Builder" / "references" / "manifest.v1.json"
_REFERENCE_CACHE_ROOT = _ROOT / ".cache" / "references"
_SOURCE_REFERENCE_ID = "openlogic-sets-logic-computation-2026-07-12-text"


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _load_json_object(path: Path) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    value = json.loads(path.read_bytes(), object_pairs_hook=reject_duplicates)
    assert isinstance(value, dict)
    return value


def test_committed_gap_decision_replays_manifest_and_workspace() -> None:
    decision = load_pilot_boundary_decision(_DECISION_PATH)
    manifest = load_pilot_manifest(_PILOT_MANIFEST_PATH)

    decision.assert_binds_manifest(manifest)
    decision.assert_matches_workspace(_ROOT)

    assert decision.disposition is PilotBoundaryDispositionV2.GAP
    assert decision.candidate.candidate_id == "model-theory-closed-level-indexed-fragment"
    assert decision.candidate.revision == "t3-boundary-v2"
    assert decision.candidate.predecessor_candidate_sha256 == (
        "dd5e6b59c6683eb8adc844cb783cc149a3f0d9a0afafd84c5e7942ef06d35181"
    )
    assert decision.formal_profile.imports_allowlist == ("Mathlib.ModelTheory.Semantics",)
    assert decision.formal_profile.axiom_profile.value == "strict"
    assert decision.formal_profile.axiom_evidence_sha256 is None
    assert decision.formal_profile.lean_build_identity == (
        "Lean (version 4.28.0, x86_64-unknown-linux-gnu, "
        "commit 7e01a1bf5c70fc6167d49c345d3bf80596e9a79b, Release)"
    )
    assert decision.formal_profile.allowed_write_paths == ("Proof.lean",)
    assert decision.formal_profile.worker_image_digest == (
        "sha256:83daaa542ee407c0fbb1ba93f2a0b40fde1621cc5ad2e689ab7d5392b76d03ff"
    )
    assert {anchor.anchor_id for anchor in decision.source.anchors} == {
        "mt-terms-formulas",
        "mt-satisfaction",
        "mt-sequent-calculus",
        "mt-sequent-soundness",
    }

    rows = {row.rule_id: row for row in decision.rule_matrix}
    for rule_id in (
        "existential-left",
        "existential-right",
        "structural-rules-and-cut",
        "other-connective-rules",
    ):
        assert rows[rule_id].coverage_state is PilotRuleCoverageStateV2.BLOCKING_GAP
        assert rows[rule_id].implementation_declarations == ()
    assert not (_ADMISSION_ROOT / "admission-receipt.v2.json").exists()


def test_review_evidence_recomputes_subobject_and_public_matrix_hashes() -> None:
    decision = load_pilot_boundary_decision(_DECISION_PATH)
    evidence = _load_json_object(_REVIEW_PATH)
    public_matrix_sha256 = hashlib.sha256(_MATRIX_PATH.read_bytes()).hexdigest()

    assert evidence["public_source_rule_matrix_sha256"] == public_matrix_sha256
    assert evidence["contains_source_excerpt"] is False
    assert evidence["contains_local_cache_path"] is False
    assert evidence["contains_prompt_or_raw_log"] is False
    assert "historical report digest may differ" in evidence["report_context_policy"]
    authority = evidence["authority_boundary"]
    assert isinstance(authority, dict)
    assert authority == {
        "human_review_present": False,
        "expert_review_present": False,
        "authenticated_independence_present": False,
        "operator_admission_authority_present": False,
        "may_issue_admission_receipt": False,
    }

    reports = evidence["reports"]
    assert isinstance(reports, list)
    assert {report["role"] for report in reports if isinstance(report, dict)} == {
        "source_interpreter",
        "adversarial_reviewer",
    }
    reports_by_role = {report["role"]: report for report in reports if isinstance(report, dict)}
    reviews_by_role = {review.role.value: review for review in decision.agent_reviews}
    assert reports_by_role.keys() == reviews_by_role.keys()

    for role, report in reports_by_role.items():
        review = reviews_by_role[role]
        context_pack = report["context_pack"]
        output = report["output"]
        run_receipt = report["execution_run_receipt"]
        assert isinstance(context_pack, dict)
        assert isinstance(output, dict)
        assert isinstance(run_receipt, dict)
        assert report["reviewer_id"] == review.reviewer_id
        assert report["reviewer_kind"] == review.reviewer_kind
        assert report["independence_group"] == review.independence_group
        assert report["review_state"] == review.review_state.value
        assert report["claims_human_or_expert_authority"] is False
        reviewed_matrix_sha256 = context_pack["public_source_rule_matrix_sha256"]
        assert isinstance(reviewed_matrix_sha256, str)
        assert len(reviewed_matrix_sha256) == 64
        int(reviewed_matrix_sha256, 16)
        assert review.context_pack_sha256 == _sha256(context_pack)
        assert review.output_sha256 == _sha256(output)
        assert review.execution_run_receipt_sha256 == _sha256(run_receipt)
        assert output["claims_human_or_expert_authority"] is False
        assert output["contains_source_excerpt"] is False
        assert run_receipt["network_used"] is False
        assert run_receipt["source_text_emitted"] is False
        assert run_receipt["raw_log_retained"] is False
        if "output_artifact_sha256" in run_receipt:
            assert run_receipt["output_artifact_sha256"] == reviewed_matrix_sha256


def test_public_rule_matrix_is_a_complete_projection_of_the_gap_decision() -> None:
    decision = load_pilot_boundary_decision(_DECISION_PATH)
    public = _load_json_object(_MATRIX_PATH)
    candidate = public["candidate"]
    source = public["source_binding"]
    disposition = public["disposition"]
    authority = public["authority_boundary"]
    assert isinstance(candidate, dict)
    assert isinstance(source, dict)
    assert isinstance(disposition, dict)
    assert isinstance(authority, dict)
    assert candidate["candidate_id"] == decision.candidate.candidate_id
    assert candidate["candidate_revision"] == decision.candidate.revision
    assert source["derived_text_reference_id"] == decision.source.reference_id
    assert source["derived_text_sha256"] == decision.source.source_artifact_sha256
    assert source["source_reference_id"] == decision.source.parent_reference_id
    assert source["source_pdf_sha256"] == decision.source.parent_artifact_sha256
    assert source["reference_manifest_sha256"] == decision.source.reference_manifest_sha256
    assert disposition == {
        "t3_admission": decision.disposition.value,
        "selection": "not_selected",
        "statement_contract": "not_frozen",
        "prover_handoff": "forbidden",
        "promotion": "forbidden",
        "open_problem_claim": "forbidden",
    }
    assert authority == {
        "record_kind": "automated_technical_cross_check",
        "human_review_present": False,
        "expert_review_present": False,
        "builder_admission_authority_present": False,
        "may_issue_admission_receipt": False,
    }

    public_anchors = public["coarse_source_anchors"]
    assert isinstance(public_anchors, list)
    public_anchors_by_id = {
        anchor["anchor_id"]: anchor for anchor in public_anchors if isinstance(anchor, dict)
    }
    assert public_anchors_by_id.keys() == {anchor.anchor_id for anchor in decision.source.anchors}
    for anchor in decision.source.anchors:
        public_anchor = public_anchors_by_id[anchor.anchor_id]
        assert public_anchor["start_offset"] == anchor.start_offset
        assert public_anchor["end_offset"] == anchor.end_offset
        assert public_anchor["raw_sha256"] == anchor.raw_sha256
        assert public_anchor["human_locator"] == anchor.human_locator

    public_rows = public["rule_matrix"]
    assert isinstance(public_rows, list)

    decision_by_id = {row.rule_id: row for row in decision.rule_matrix}
    public_by_id = {row["matrix_id"]: row for row in public_rows if isinstance(row, dict)}
    assert public_by_id.keys() == decision_by_id.keys()

    state_projection = {"blocking_gap": "missing"}
    for rule_id, decision_row in decision_by_id.items():
        public_row = public_by_id[rule_id]
        assert public_row["status"] == state_projection.get(
            decision_row.coverage_state.value,
            decision_row.coverage_state.value,
        )
        public_declarations = public_row["universal_lk_declarations"]
        assert isinstance(public_declarations, list)
        assert all(isinstance(item, str) for item in public_declarations)
        assert all(
            any(
                full == short or full.endswith(f".{short}")
                for full in decision_row.implementation_declarations
            )
            for short in public_declarations
        )
        assert all(
            any(full == short or full.endswith(f".{short}") for short in public_declarations)
            for full in decision_row.implementation_declarations
        )


def test_cached_source_anchors_replay_only_when_local_cache_exists() -> None:
    cached_text = _REFERENCE_CACHE_ROOT / _SOURCE_REFERENCE_ID
    if not cached_text.exists():
        return

    cache = ReferenceCache(
        ReferenceManifestV1.load(_REFERENCE_MANIFEST_PATH),
        _REFERENCE_CACHE_ROOT,
        confinement_root=_ROOT,
    )
    load_pilot_boundary_decision(_DECISION_PATH).assert_matches_reference_cache(cache)
