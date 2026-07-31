from __future__ import annotations

import copy
import hashlib
import json
import shutil
from pathlib import Path

import pytest
from autolean_builder.discovery_manifest import load_discovery_lane_manifest
from autolean_builder.ifem_prerequisite_census import (
    DEFAULT_LANE_MANIFEST_PATH,
    DEFAULT_LIBRARY_ROOT,
    DEFAULT_PLAN_PATH,
    IFEMNodeClassificationEvidenceV1,
    IFEMPrerequisiteCensusError,
    IFEMPrerequisiteCensusPlanV1,
    IFEMPrerequisiteCensusResultV1,
    completed_unreviewed_result,
    load_ifem_prerequisite_census_plan,
    normalize_query_observation,
    not_run_result,
    render_lean_query,
    validate_local_library_dependencies,
    validate_plan_bindings,
    validate_result_against_plan,
)
from autolean_contracts import canonical_json_bytes

ROOT = Path(__file__).resolve().parents[2]
SHA = "a" * 64


def _plan() -> IFEMPrerequisiteCensusPlanV1:
    return load_ifem_prerequisite_census_plan(DEFAULT_PLAN_PATH)


def _rehashed_plan(payload: dict[str, object]) -> IFEMPrerequisiteCensusPlanV1:
    projection = copy.deepcopy(payload)
    projection.pop("content_sha256", None)
    payload["content_sha256"] = hashlib.sha256(canonical_json_bytes(projection)).hexdigest()
    return IFEMPrerequisiteCensusPlanV1.model_validate(payload)


def _raw_observation(plan: IFEMPrerequisiteCensusPlanV1) -> str:
    nodes: list[dict[str, object]] = []
    for query_index, query in enumerate(plan.queries):
        candidates: list[dict[str, object]] = []
        for candidate_index, declaration in enumerate(query.candidate_declarations):
            present = query_index == 0 and candidate_index == 0
            candidates.append(
                {
                    "canonical_type": "Type" if present else None,
                    "declaration": declaration,
                    "declaration_kind": "inductive" if present else None,
                    "observed_axioms": [],
                    "present": present,
                }
            )
        nodes.append({"candidates": candidates, "node_id": query.node_id})
    return json.dumps(
        {
            "direct_imports": list(plan.environment.direct_imports),
            "lake_manifest_sha256": plan.environment.lake_manifest_sha256,
            "lean_toolchain": plan.environment.lean_toolchain,
            "mathlib_revision": plan.environment.mathlib_revision,
            "nodes": nodes,
            "plan_content_sha256": plan.content_sha256,
            "protocol": plan.protocol,
            "schema_version": "autolean.ifem-prerequisite-query-raw.v1",
            "type_format": "autolean.lean-pp-expr.v1",
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def test_plan_binds_current_denominator_and_library_pins() -> None:
    plan = _plan()
    manifest = load_discovery_lane_manifest(DEFAULT_LANE_MANIFEST_PATH)
    lane = next(lane for lane in manifest.lanes if lane.lane_id == "ifem-coercive-galerkin")
    denominator = lane.prerequisite_denominator
    assert denominator is not None

    validate_plan_bindings(plan)
    assert plan.computed_content_sha256() == plan.content_sha256
    assert plan.denominator.frozen_node_count == 25
    assert plan.denominator.prerequisite_node_count == 21
    assert plan.denominator.denominator_revision == denominator.revision
    assert plan.denominator.denominator_content_sha256 == denominator.content_sha256
    assert tuple(query.node_id for query in plan.queries) == tuple(
        node.node_id for node in denominator.nodes if node.included_in_prerequisite_denominator
    )
    assert plan.graph_boundary.builder_freeze == "forbidden"
    assert plan.graph_boundary.prover_handoff == "forbidden"


def test_legacy_27_node_description_cannot_override_the_frozen_lane() -> None:
    payload = json.loads(DEFAULT_PLAN_PATH.read_text(encoding="utf-8"))
    payload["denominator"]["frozen_node_count"] = 27
    drifted = _rehashed_plan(payload)

    with pytest.raises(IFEMPrerequisiteCensusError, match="current frozen"):
        validate_plan_bindings(
            drifted,
            lane_manifest_path=DEFAULT_LANE_MANIFEST_PATH,
            library_root=DEFAULT_LIBRARY_ROOT,
        )


def test_rendered_lean_query_observes_metadata_without_classifying() -> None:
    source = render_lean_query(_plan())

    assert "import Mathlib.Analysis.InnerProductSpace.LaxMilgram" in source
    assert "import Mathlib.Analysis.Normed.Operator.Bilinear" in source
    assert "env.checked.get.find? declaration" in source
    assert '"canonical_type"' in source
    assert '"observed_axioms"' in source
    assert "thin_adapter" not in source
    assert '"classification"' not in source
    assert "StatementContractV1" not in source


def test_host_preflight_refuses_missing_local_packages_before_lake(tmp_path: Path) -> None:
    library = tmp_path / "Library"
    library.mkdir()
    shutil.copyfile(DEFAULT_LIBRARY_ROOT / "lean-toolchain", library / "lean-toolchain")
    shutil.copyfile(DEFAULT_LIBRARY_ROOT / "lake-manifest.json", library / "lake-manifest.json")

    with pytest.raises(IFEMPrerequisiteCensusError, match="local package directory"):
        validate_local_library_dependencies(_plan(), library_root=library)

    (library / ".lake" / "packages").mkdir(parents=True)
    with pytest.raises(IFEMPrerequisiteCensusError, match="Library package"):
        validate_local_library_dependencies(_plan(), library_root=library)


def test_not_run_result_is_content_addressed_and_all_unknown() -> None:
    plan = _plan()
    result = not_run_result(plan, plan_path=DEFAULT_PLAN_PATH, reason="wsl_unavailable")

    assert result.execution_state == "not_run"
    assert result.query_source_sha256 is None
    assert result.query_observation_sha256 is None
    assert len(result.node_results) == 21
    assert all(item.evidence.classification == "unknown" for item in result.node_results)
    assert all(
        item.evidence.explicit_unknown_reason == "wsl_unavailable" for item in result.node_results
    )
    assert result.resume_command == (
        "uv",
        "run",
        "--frozen",
        "python",
        "scripts/ifem_prerequisite_census.py",
        "--plan",
        "Builder/pilots/discovery/ifem-coercive-prerequisite-census-plan.v1.json",
        "run",
        "--out",
        "<result-json>",
        "--observation-out",
        "<observation-json>",
    )
    assert result.computed_content_sha256() == result.content_sha256
    assert result.coverage_claim == "not_authorized"


def test_not_run_result_records_host_query_timeout_without_claiming_execution() -> None:
    plan = _plan()
    result = not_run_result(
        plan,
        plan_path=DEFAULT_PLAN_PATH,
        reason="host_query_timeout",
    )

    assert result.execution_state == "not_run"
    assert result.query_source_sha256 is None
    assert result.query_observation_sha256 is None
    assert all(
        item.evidence.classification == "unknown"
        and item.evidence.explicit_unknown_reason == "host_query_timeout"
        for item in result.node_results
    )


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (
            {"classification": "direct", "mapped_declarations": ["Real"]},
            "direct classification lacks",
        ),
        (
            {
                "canonical_type_sha256s": [SHA],
                "classification": "thin_adapter",
                "mapped_declarations": ["Real"],
                "query_observation_sha256": SHA,
                "semantic_review_sha256": SHA,
            },
            "thin adapter classification lacks",
        ),
        (
            {
                "classification": "missing",
                "declaration_inventory_sha256": SHA,
                "negative_query_observation_sha256": SHA,
            },
            "missing classification lacks",
        ),
    ],
)
def test_non_unknown_classifications_require_explicit_evidence(
    payload: dict[str, object], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        IFEMNodeClassificationEvidenceV1.model_validate(payload)


def test_explicit_evidence_shapes_accept_each_reviewed_class() -> None:
    direct = IFEMNodeClassificationEvidenceV1(
        classification="direct",
        mapped_declarations=("Real",),
        canonical_type_sha256s=(SHA,),
        query_observation_sha256=SHA,
        semantic_review_sha256=SHA,
    )
    adapter = IFEMNodeClassificationEvidenceV1(
        classification="thin_adapter",
        mapped_declarations=("Real",),
        canonical_type_sha256s=(SHA,),
        query_observation_sha256=SHA,
        adapter_source_sha256=SHA,
        adapter_compile_receipt_sha256=SHA,
        semantic_review_sha256=SHA,
    )
    missing = IFEMNodeClassificationEvidenceV1(
        classification="missing",
        negative_query_observation_sha256=SHA,
        declaration_inventory_sha256=SHA,
        semantic_review_sha256=SHA,
    )

    assert (direct.classification, adapter.classification, missing.classification) == (
        "direct",
        "thin_adapter",
        "missing",
    )


def test_a_lean_name_hit_stays_unknown_without_builder_semantic_review() -> None:
    plan = _plan()
    source_sha256 = hashlib.sha256(render_lean_query(plan).encode("utf-8")).hexdigest()
    observation = normalize_query_observation(
        _raw_observation(plan), plan=plan, query_source_sha256=source_sha256
    )
    result = completed_unreviewed_result(plan, observation, plan_path=DEFAULT_PLAN_PATH)

    assert observation.nodes[0].candidates[0].present is True
    assert (
        observation.nodes[0].candidates[0].canonical_type_sha256
        == hashlib.sha256(b"Type").hexdigest()
    )
    assert result.execution_state == "completed"
    assert all(item.evidence.classification == "unknown" for item in result.node_results)
    assert all(
        item.evidence.explicit_unknown_reason == "builder_semantic_review_not_recorded"
        for item in result.node_results
    )
    assert result.coverage_claim == "not_authorized"


def test_reviewed_mapping_cannot_escape_the_content_addressed_query_plan() -> None:
    plan = _plan()
    source_sha256 = hashlib.sha256(render_lean_query(plan).encode("utf-8")).hexdigest()
    observation = normalize_query_observation(
        _raw_observation(plan), plan=plan, query_source_sha256=source_sha256
    )
    unreviewed = completed_unreviewed_result(plan, observation, plan_path=DEFAULT_PLAN_PATH)
    payload = unreviewed.model_dump(mode="json")
    payload["node_results"][0]["evidence"] = {
        "adapter_compile_receipt_sha256": None,
        "adapter_source_sha256": None,
        "canonical_type_sha256s": [SHA],
        "classification": "direct",
        "declaration_inventory_sha256": None,
        "explicit_unknown_reason": None,
        "mapped_declarations": ["Nat"],
        "negative_query_observation_sha256": None,
        "query_observation_sha256": observation.content_sha256,
        "semantic_review_sha256": SHA,
    }
    payload.pop("content_sha256")
    payload["content_sha256"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    escaped = IFEMPrerequisiteCensusResultV1.model_validate(payload)

    with pytest.raises(IFEMPrerequisiteCensusError, match="outside the content-addressed"):
        validate_result_against_plan(escaped, plan)
