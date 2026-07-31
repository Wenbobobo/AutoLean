"""Focused checks for source-free, unknown-only iFEM calibration intent queues."""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import shutil
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest
from autolean_builder import ifem_calibration_risk_routing as routing
from autolean_builder import ifem_classification_triage as triage
from autolean_builder import ifem_next_calibration_case_intents as intents
from autolean_contracts import canonical_json_bytes, stable_identifier

_RETAINED_QUEUE_PATH = (
    Path(__file__).resolve().parents[2]
    / "docs"
    / "research"
    / "ifem-next-calibration-case-intents-2026-07-31.json"
)
_RETAINED_QUEUE_FILE_SHA256 = "cb86f9d67faddda54c2fea8a3d0698dd2711df579d0275bfd0b2a52ae404dd38"
_RETAINED_QUEUE_CONTENT_SHA256 = "cd0101db7a0f5b99c9a8311ce01540a24faba3f97881bc31d9a652b2cb19cbc8"


@dataclass(frozen=True, slots=True)
class _Paths:
    report: Path
    graph: Path
    census_plan: Path
    census_result: Path
    profile_summary: Path
    structural_corpus: Path
    readiness_decision: Path


def _content_addressed(payload: dict[str, object]) -> dict[str, object]:
    normalized = copy.deepcopy(payload)
    normalized.pop("content_sha256", None)
    normalized["content_sha256"] = hashlib.sha256(canonical_json_bytes(normalized)).hexdigest()
    return normalized


def _read_object(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return cast(dict[str, object], payload)


def _write_object(path: Path, payload: dict[str, object]) -> None:
    path.write_bytes(canonical_json_bytes(_content_addressed(payload)) + b"\n")


def _copy_inputs(tmp_path: Path) -> _Paths:
    tmp_path.mkdir(parents=True, exist_ok=True)
    sources = {
        "report": routing.DEFAULT_D35_REPORT_PATH,
        "graph": triage.DEFAULT_GRAPH_PATH,
        "census_plan": triage.DEFAULT_CENSUS_PLAN_PATH,
        "census_result": triage.DEFAULT_CENSUS_RESULT_PATH,
        "profile_summary": triage.DEFAULT_PROFILE_SUMMARY_PATH,
        "structural_corpus": triage.DEFAULT_STRUCTURAL_CORPUS_PATH,
        "readiness_decision": triage.DEFAULT_READINESS_DECISION_PATH,
    }
    copied: dict[str, Path] = {}
    for name, source in sources.items():
        destination = tmp_path / f"{name}.json"
        shutil.copyfile(source, destination)
        copied[name] = destination
    return _Paths(**copied)


def _build(paths: _Paths) -> intents.IFEMNextCalibrationCaseIntentsV1:
    return intents.build_ifem_next_calibration_case_intents_from_paths(
        d35_report_path=paths.report,
        graph_path=paths.graph,
        census_plan_path=paths.census_plan,
        census_result_path=paths.census_result,
        profile_summary_path=paths.profile_summary,
        structural_corpus_path=paths.structural_corpus,
        readiness_decision_path=paths.readiness_decision,
    )


def _verify(value: intents.IFEMNextCalibrationCaseIntentsV1, paths: _Paths) -> None:
    intents.verify_ifem_next_calibration_case_intents_against_paths(
        value,
        d35_report_path=paths.report,
        graph_path=paths.graph,
        census_plan_path=paths.census_plan,
        census_result_path=paths.census_result,
        profile_summary_path=paths.profile_summary,
        structural_corpus_path=paths.structural_corpus,
        readiness_decision_path=paths.readiness_decision,
    )


def _materialize(
    output: Path,
    paths: _Paths,
) -> intents.IFEMNextCalibrationCaseIntentsV1:
    return intents.materialize_ifem_next_calibration_case_intents_from_paths_once(
        output,
        d35_report_path=paths.report,
        graph_path=paths.graph,
        census_plan_path=paths.census_plan,
        census_result_path=paths.census_result,
        profile_summary_path=paths.profile_summary,
        structural_corpus_path=paths.structural_corpus,
        readiness_decision_path=paths.readiness_decision,
    )


def test_default_projection_is_a_stable_priority_queue_of_un_authored_unknowns(
    tmp_path: Path,
) -> None:
    result = _build(_copy_inputs(tmp_path))

    assert len(result.intents) == result.denominator_node_count == 21
    distribution = Counter(str(intent.calibration_priority) for intent in result.intents)
    assert (
        distribution["p0_incorrect"],
        distribution["p1_invalid"],
        distribution["p2_independent_machine_review"],
        distribution["p3_create_calibration_case"],
    ) == (0, 10, 2, 9)
    assert tuple(
        (intents._PRIORITY_RANK[intent.calibration_priority], intent.source_order)
        for intent in result.intents
    ) == tuple(
        sorted(
            (intents._PRIORITY_RANK[intent.calibration_priority], intent.source_order)
            for intent in result.intents
        )
    )
    assert all(intent.semantic_classification == "unknown" for intent in result.intents)
    assert all(intent.materialization_state == "not_authored" for intent in result.intents)
    assert all(
        intent.required_next_calibration
        is intents._REQUIRED_ACTION_BY_PRIORITY[intent.calibration_priority]
        for intent in result.intents
    )
    assert all(
        intent.intent_id
        == stable_identifier(
            intents.CASE_INTENT_NAMESPACE,
            f"{intents.CASE_INTENT_LANE}:{intent.node_id}",
        )
        for intent in result.intents
    )
    assert all(
        intent.structural_risk_discovery_required
        is (
            intent.calibration_priority
            is routing.IFEMCalibrationPriorityV1.P3_CREATE_CALIBRATION_CASE
        )
        for intent in result.intents
    )
    assert result.authority.semantic_authority is False
    assert result.authority.case_authoring_authority is False
    assert result.authority.materialization_authority is False
    assert result.authority.freeze_authority is False
    assert result.authority.prover_handoff_authority is False
    assert result.authority.promotion_authority is False


def test_retained_queue_is_exactly_replayable_from_the_current_public_inputs() -> None:
    retained = intents.load_ifem_next_calibration_case_intents(_RETAINED_QUEUE_PATH)

    assert hashlib.sha256(_RETAINED_QUEUE_PATH.read_bytes()).hexdigest() == (
        _RETAINED_QUEUE_FILE_SHA256
    )
    assert retained.content_sha256 == _RETAINED_QUEUE_CONTENT_SHA256
    assert retained == intents.build_ifem_next_calibration_case_intents_from_paths()
    intents.verify_ifem_next_calibration_case_intents_against_paths(retained)


def test_synthetic_p0_route_is_first_but_never_changes_the_unknown_or_un_authored_boundary() -> (
    None
):
    routed = routing.build_ifem_calibration_risk_routing_from_paths()
    payload = routed.model_dump(mode="json")
    nodes = cast(list[dict[str, object]], payload["nodes"])
    risk_node = next(node for node in nodes if node["calibration_priority"] == "p1_invalid")
    risk_node["calibration_priority"] = "p0_incorrect"
    risk_node["required_next_calibration"] = "deterministic_or_higher_capability_calibration"
    synthetic_p0 = routing.IFEMCalibrationRiskRoutingV1.model_validate(_content_addressed(payload))

    result = intents.build_ifem_next_calibration_case_intents_from_routing(synthetic_p0)

    assert result.intents[0].calibration_priority is routing.IFEMCalibrationPriorityV1.P0_INCORRECT
    assert (
        result.intents[0].required_next_calibration
        is routing.IFEMRequiredNextCalibrationV1.DETERMINISTIC_OR_HIGHER_CAPABILITY_CALIBRATION
    )
    assert result.intents[0].structural_risk_discovery_required is False
    assert all(intent.semantic_classification == "unknown" for intent in result.intents)
    assert all(intent.materialization_state == "not_authored" for intent in result.intents)
    assert result.authority.freeze_authority is False
    assert result.authority.prover_handoff_authority is False


def test_rehashed_output_and_input_provenance_drift_are_refused(tmp_path: Path) -> None:
    paths = _copy_inputs(tmp_path)
    result = _build(paths)

    payload = result.model_dump(mode="json")
    queue = cast(list[dict[str, object]], payload["intents"])
    queue[-1]["source_order"] = 99
    rehashed = intents.IFEMNextCalibrationCaseIntentsV1.model_validate(_content_addressed(payload))
    with pytest.raises(
        intents.IFEMNextCalibrationCaseIntentError,
        match="differs from exact input replay",
    ):
        _verify(rehashed, paths)

    report = _read_object(paths.report)
    risk_aggregates = cast(list[dict[str, object]], report["risk_aggregates"])
    absolute_value = next(item for item in risk_aggregates if item["risk"] == "absolute_value")
    absolute_value["correct_count"] = 1
    absolute_value["invalid_count"] = 0
    role_aggregates = cast(list[dict[str, object]], report["role_aggregates"])
    supervisor = next(item for item in role_aggregates if item["role"] == "cheating_supervisor")
    supervisor["correct_count"] = 2
    supervisor["invalid_count"] = 0
    _write_object(paths.report, report)
    with pytest.raises(
        intents.IFEMNextCalibrationCaseIntentError,
        match="differs from exact input replay",
    ):
        _verify(result, paths)


def test_forbidden_actions_strict_loading_and_canonical_write_once_replay(tmp_path: Path) -> None:
    paths = _copy_inputs(tmp_path / "inputs")
    output = tmp_path / "intents.json"
    result = _materialize(output, paths)

    assert _materialize(output, paths) == result
    assert intents.load_ifem_next_calibration_case_intents(output) == result
    _verify(result, paths)
    with pytest.raises(intents.IFEMNextCalibrationCaseIntentError, match="cannot author"):
        result.assert_not_authoritative()
    with pytest.raises(intents.IFEMNextCalibrationCaseIntentError, match="cannot author"):
        result.freeze_statement()
    with pytest.raises(intents.IFEMNextCalibrationCaseIntentError, match="cannot author"):
        result.handoff_to_prover()

    output.write_bytes(b'{"schema_version":"first","schema_version":"second"}\n')
    with pytest.raises(intents.IFEMNextCalibrationCaseIntentError, match="duplicate JSON key"):
        intents.load_ifem_next_calibration_case_intents(output)

    output.write_bytes(b"different\n")
    with pytest.raises(intents.IFEMNextCalibrationCaseIntentError, match="already exists"):
        _materialize(output, paths)


def test_module_has_no_runtime_or_model_dependency_and_never_renders_forbidden_surfaces() -> None:
    module_path = Path(intents.__file__)
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    imports = {
        alias.name.split(".", 1)[0]
        for statement in ast.walk(tree)
        if isinstance(statement, ast.Import)
        for alias in statement.names
    }
    imports.update(
        statement.module.split(".", 1)[0]
        for statement in ast.walk(tree)
        if isinstance(statement, ast.ImportFrom) and statement.module is not None
    )

    assert not imports.intersection(
        {"benchmarks", "http", "httpx", "openai", "requests", "urllib", "Prover"}
    )
    rendered = intents.render_ifem_next_calibration_case_intents(
        intents.build_ifem_next_calibration_case_intents_from_paths()
    )
    for forbidden in (
        b'"catalog_case"',
        b'"canonical_type"',
        b'"formal_graph"',
        b'"lean_statement"',
        b'"oracle"',
        b'"provider"',
        b'"raw_output"',
        b'"source_text"',
        b'"statement_contract"',
    ):
        assert forbidden not in rendered
