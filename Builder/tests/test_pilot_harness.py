from __future__ import annotations

from pathlib import Path

import pytest
from autolean_builder import (
    PilotAdmissionModeV1,
    PilotGraphV1,
    PilotHarnessError,
    PilotManifestV1,
    PilotReviewStateV1,
    PilotSourceStatusV1,
    ReferenceCache,
    ReferenceManifestV1,
    load_pilot_manifest,
    verify_cached_textbook_alignment,
)
from autolean_contracts import PermissionDecisionV1, RightsRecordV1, stable_identifier

_ROOT = Path(__file__).parents[2]
_MANIFEST_PATH = _ROOT / "Builder" / "pilots" / "self-calibration" / "pilot-manifest.v1.json"
_REFERENCE_MANIFEST = _ROOT / "Builder" / "references" / "manifest.v1.json"
_CACHE_ROOT = _ROOT / ".cache" / "references"


def _manifest() -> PilotManifestV1:
    return load_pilot_manifest(_MANIFEST_PATH)


def test_parallel_candidates_are_explicitly_blocked_until_calibrated() -> None:
    manifest = _manifest()

    assert manifest.prover_handoff == "forbidden"
    assert {graph.graph_id for graph in manifest.parallel_candidates()} == {
        "first-order-soundness-conditional",
        "abstract-galerkin-cea-conditional",
        "van-kampen-rights-restricted",
    }
    for graph in manifest.parallel_candidates():
        assert graph.admission_blocker_ids()
        assert all(
            requirement.review_state is PilotReviewStateV1.PENDING
            for requirement in graph.calibration_requirements
        )
        with pytest.raises(PilotHarnessError, match="cannot enter Builder statement drafting"):
            graph.assert_ready_for_statement_drafting()


def test_curvature_reference_graph_has_a_machine_checkable_overlap_blocker() -> None:
    graph = next(
        graph
        for graph in _manifest().graphs
        if graph.graph_id == "connection-curvature-overlap-reference"
    )

    assert graph.admission_mode is PilotAdmissionModeV1.OVERLAP_BLOCKED_REFERENCE
    assert "upstream-curvature-pr-36036" in graph.admission_blocker_ids()
    with pytest.raises(PilotHarnessError, match="only frozen StatementContractV1"):
        graph.assert_not_prover_handoffable()


def test_slc_local_copy_binds_source_spans_without_admitting_a_statement() -> None:
    graph = _manifest().graph("first-order-soundness-conditional")
    binding = graph.source.reference

    assert graph.source.status is PilotSourceStatusV1.VERIFIED_LOCAL_COPY
    assert binding is not None
    assert binding.reference_id == "openlogic-sets-logic-computation-2026-07-12-text"
    assert binding.source_scope.value == "declared_entry_boundary"
    assert binding.prior_dependency_review_state is PilotReviewStateV1.PENDING
    assert {anchor.anchor_id for anchor in binding.anchors} == {
        "mt-terms-formulas",
        "mt-satisfaction",
        "mt-sequent-calculus",
        "mt-sequent-soundness",
    }
    assert "source-provenance-pending" not in graph.admission_blocker_ids()
    assert "textbook-entry-dependencies-pending" in graph.admission_blocker_ids()
    with pytest.raises(PilotHarnessError, match="cannot enter Builder statement drafting"):
        graph.assert_ready_for_statement_drafting("mt-soundness-target")
    with pytest.raises(PilotHarnessError, match="only frozen StatementContractV1"):
        graph.assert_not_prover_handoffable()


def test_manifest_rejects_dependency_outside_its_graph() -> None:
    payload = _manifest().model_dump(mode="python")
    payload["graphs"][1]["nodes"][1]["depends_on"] = ("missing-node",)

    with pytest.raises(ValueError, match="dependency is absent"):
        PilotManifestV1.model_validate(payload)


def test_manifest_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.json"
    path.write_text(
        '{"schema_version":"autolean.builder-pilot-manifest.v1",'
        '"schema_version":"autolean.builder-pilot-manifest.v1"}',
        encoding="utf-8",
    )

    with pytest.raises(PilotHarnessError, match="duplicate JSON key"):
        load_pilot_manifest(path)


def test_verified_local_textbook_anchors_still_bind_when_cache_is_available() -> None:
    expected_text = _CACHE_ROOT / "mckay-lectures-differential-geometry-2022-text"
    if not expected_text.exists():
        pytest.skip("official local McKay cache is intentionally absent")
    cache = ReferenceCache(
        ReferenceManifestV1.load(_REFERENCE_MANIFEST),
        _CACHE_ROOT,
        confinement_root=_ROOT,
    )

    verified = verify_cached_textbook_alignment(_manifest(), cache)

    assert tuple(
        item for item in verified if item.startswith("connection-curvature-overlap-reference:")
    ) == (
        "connection-curvature-overlap-reference:connection-definition",
        "connection-curvature-overlap-reference:metric-compatibility",
        "connection-curvature-overlap-reference:curvature-form",
        "connection-curvature-overlap-reference:curvature-operator",
        "connection-curvature-overlap-reference:metric-curvature",
    )


def test_verified_slc_local_copy_anchors_still_bind_when_cache_is_available() -> None:
    expected_text = _CACHE_ROOT / "openlogic-sets-logic-computation-2026-07-12-text"
    if not expected_text.exists():
        pytest.skip("official local SLC cache is intentionally absent")
    cache = ReferenceCache(
        ReferenceManifestV1.load(_REFERENCE_MANIFEST),
        _CACHE_ROOT,
        confinement_root=_ROOT,
    )

    verified = verify_cached_textbook_alignment(_manifest(), cache)

    assert {item for item in verified if item.startswith("first-order-soundness-conditional:")} == {
        "first-order-soundness-conditional:mt-terms-formulas",
        "first-order-soundness-conditional:mt-satisfaction",
        "first-order-soundness-conditional:mt-sequent-calculus",
        "first-order-soundness-conditional:mt-sequent-soundness",
    }


def _accepted_curvature_graph() -> PilotGraphV1:
    graph = _manifest().graph("connection-curvature-overlap-reference")
    payload = graph.model_dump(mode="python")
    payload["admission_mode"] = "conditional_candidate"
    payload["blockers"] = ()
    payload["source"]["reference"]["prior_dependency_review_state"] = "accepted"
    payload["mathlib_census"].update(
        {
            "current_review_state": "accepted",
            "target_mathlib_revision": "8f9d9cff6bd728b17a24e163c9402775d9e6a365",
            "lake_manifest_sha256": "1" * 64,
            "search_protocol_sha256": "2" * 64,
            "result_artifact_sha256": "3" * 64,
        }
    )
    for requirement in payload["calibration_requirements"]:
        requirement["review_state"] = "accepted"
        requirement["reviews"] = tuple(
            {
                "reviewer_id": f"{requirement['role']}-reviewer-{index}",
                "independence_group": f"group-{index}",
                "evidence_sha256": f"{index + 4:x}" * 64,
                "review_state": "accepted",
            }
            for index in range(requirement["required_independence_groups"])
        )
    for node in payload["nodes"]:
        node["review_state"] = "accepted"
        node["review_evidence_sha256"] = "a" * 64
    for gate in payload["feedback_gates"]:
        gate["review_state"] = "accepted"
        gate["review_evidence_sha256"] = "b" * 64
    return PilotGraphV1.model_validate(payload)


def _rights() -> RightsRecordV1:
    return RightsRecordV1(
        rights_id=stable_identifier("rights", "pilot-admission"),
        source_id=stable_identifier("source", "pilot-admission"),
        overall_decision=PermissionDecisionV1.RESTRICTED,
    )


def test_admission_requires_reviewed_target_closure_feedback_and_independent_groups() -> None:
    graph = _accepted_curvature_graph()
    graph.assert_ready_for_statement_drafting("cc-curvature-operator")

    pending_gate = graph.model_dump(mode="python")
    pending_gate["feedback_gates"][0].update(
        {"review_state": "pending", "review_evidence_sha256": None}
    )
    blocked = PilotGraphV1.model_validate(pending_gate)
    assert "feedback-cc-opposite-symmetry-pending" in blocked.admission_blocker_ids(
        "cc-curvature-operator"
    )

    missing_groups = graph.model_dump(mode="python")
    missing_groups["calibration_requirements"][1]["reviews"] = ()
    with pytest.raises(ValueError, match="independent review groups"):
        PilotGraphV1.model_validate(missing_groups)


def test_admission_receipt_rebinds_manifest_target_and_rights() -> None:
    payload = _manifest().model_dump(mode="python")
    payload["graphs"] = (
        _accepted_curvature_graph().model_dump(mode="python"),
        *payload["graphs"][1:],
    )
    manifest = PilotManifestV1.model_validate(payload)
    receipt = manifest.issue_admission_receipt(
        graph_id="connection-curvature-overlap-reference",
        target_node_id="cc-curvature-operator",
        rights=_rights(),
    )

    manifest.validate_admission_receipt(receipt, rights=_rights())
    changed_rights = _rights().model_copy(update={"restrictions": ("different",)})
    with pytest.raises(PilotHarnessError, match="does not bind"):
        manifest.validate_admission_receipt(receipt, rights=changed_rights)
