"""Focused checks for the non-authoritative D35 iFEM calibration risk router."""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest
from autolean_builder import ifem_calibration_risk_routing as routing
from autolean_builder import ifem_classification_triage as triage
from autolean_contracts import canonical_json_bytes


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


def _build(paths: _Paths) -> routing.IFEMCalibrationRiskRoutingV1:
    return routing.build_ifem_calibration_risk_routing_from_paths(
        d35_report_path=paths.report,
        graph_path=paths.graph,
        census_plan_path=paths.census_plan,
        census_result_path=paths.census_result,
        profile_summary_path=paths.profile_summary,
        structural_corpus_path=paths.structural_corpus,
        readiness_decision_path=paths.readiness_decision,
    )


def _verify(value: routing.IFEMCalibrationRiskRoutingV1, paths: _Paths) -> None:
    routing.verify_ifem_calibration_risk_routing_against_paths(
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
) -> routing.IFEMCalibrationRiskRoutingV1:
    return routing.materialize_ifem_calibration_risk_routing_from_paths_once(
        output,
        d35_report_path=paths.report,
        graph_path=paths.graph,
        census_plan_path=paths.census_plan,
        census_result_path=paths.census_result,
        profile_summary_path=paths.profile_summary,
        structural_corpus_path=paths.structural_corpus,
        readiness_decision_path=paths.readiness_decision,
    )


def test_routing_preserves_every_unknown_node_and_uses_only_its_existing_risks(
    tmp_path: Path,
) -> None:
    paths = _copy_inputs(tmp_path)
    result = _build(paths)
    report = _read_object(paths.report)
    aggregates = {
        item["risk"]: item for item in cast(list[dict[str, object]], report["risk_aggregates"])
    }

    assert result.denominator_node_count == len(result.nodes) == 21
    assert all(node.semantic_classification.value == "unknown" for node in result.nodes)
    assert result.authority.semantic_classification_authorized is False
    assert result.authority.freeze_allowed is False
    assert result.authority.prover_handoff_allowed is False
    assert result.authority.promotion_allowed is False
    assert (
        result.evidence.d35_report_file_sha256
        == hashlib.sha256(paths.report.read_bytes()).hexdigest()
    )
    assert result.evidence.d35_case_count == 16
    assert result.evidence.d35_risk_family_count == 8

    for node in result.nodes:
        node_aggregates = [aggregates[str(risk)] for risk in node.structural_risk_families]
        if not node_aggregates:
            assert (
                node.calibration_priority
                is routing.IFEMCalibrationPriorityV1.P3_CREATE_CALIBRATION_CASE
            )
            assert (
                node.required_next_calibration
                is routing.IFEMRequiredNextCalibrationV1.CREATE_CALIBRATION_CASE
            )
        elif any(cast(int, item["incorrect_count"]) for item in node_aggregates):
            assert node.calibration_priority is routing.IFEMCalibrationPriorityV1.P0_INCORRECT
        elif any(cast(int, item["invalid_count"]) for item in node_aggregates):
            assert node.calibration_priority is routing.IFEMCalibrationPriorityV1.P1_INVALID
            expected_next = (
                routing.IFEMRequiredNextCalibrationV1.DETERMINISTIC_OR_HIGHER_CAPABILITY_CALIBRATION
            )
            assert node.required_next_calibration is expected_next
        else:
            assert (
                node.calibration_priority
                is routing.IFEMCalibrationPriorityV1.P2_INDEPENDENT_MACHINE_REVIEW
            )
            assert (
                node.required_next_calibration
                is routing.IFEMRequiredNextCalibrationV1.INDEPENDENT_MACHINE_REVIEW
            )


def test_d35_hash_schema_protocol_risk_and_authority_drift_are_rejected(tmp_path: Path) -> None:
    paths = _copy_inputs(tmp_path)
    raw = paths.report.read_bytes()
    payload = _read_object(paths.report)
    payload["fixture_content_sha256"] = "0" * 64
    paths.report.write_bytes(canonical_json_bytes(payload) + b"\n")
    with pytest.raises(routing.IFEMCalibrationRiskRoutingError, match="invalid"):
        _build(paths)

    paths.report.write_bytes(raw)
    payload = _read_object(paths.report)
    payload["fixture_content_sha256"] = "0" * 64
    _write_object(paths.report, payload)
    with pytest.raises(routing.IFEMCalibrationRiskRoutingError, match="invalid"):
        _build(paths)

    paths.report.write_bytes(raw)
    payload = _read_object(paths.report)
    binding = cast(dict[str, object], payload["protocol_binding"])
    binding["profile_content_sha256"] = "0" * 64
    _write_object(paths.report, payload)
    with pytest.raises(routing.IFEMCalibrationRiskRoutingError, match="invalid"):
        _build(paths)

    paths.report.write_bytes(raw)
    payload = _read_object(paths.report)
    payload["schema_version"] = "autolean.ifem-private-evaluator-public-report.v1"
    _write_object(paths.report, payload)
    with pytest.raises(routing.IFEMCalibrationRiskRoutingError, match="invalid"):
        _build(paths)

    paths.report.write_bytes(raw)
    payload = _read_object(paths.report)
    binding = cast(dict[str, object], payload["protocol_binding"])
    binding["protocol_id"] = "d34-v2"
    _write_object(paths.report, payload)
    with pytest.raises(routing.IFEMCalibrationRiskRoutingError, match="invalid"):
        _build(paths)

    paths.report.write_bytes(raw)
    payload = _read_object(paths.report)
    risks = cast(list[dict[str, object]], payload["risk_aggregates"])
    risks.pop()
    _write_object(paths.report, payload)
    with pytest.raises(routing.IFEMCalibrationRiskRoutingError, match="invalid"):
        _build(paths)

    paths.report.write_bytes(raw)
    payload = _read_object(paths.report)
    authority = cast(dict[str, object], payload["authority"])
    authority["promotion_allowed"] = True
    _write_object(paths.report, payload)
    with pytest.raises(routing.IFEMCalibrationRiskRoutingError, match="invalid"):
        _build(paths)


def test_incorrect_observation_is_p0_but_never_changes_unknown(tmp_path: Path) -> None:
    paths = _copy_inputs(tmp_path)
    payload = _read_object(paths.report)
    risks = cast(list[dict[str, object]], payload["risk_aggregates"])
    absolute_value = next(item for item in risks if item["risk"] == "absolute_value")
    absolute_value["incorrect_count"] = 1
    absolute_value["invalid_count"] = 0
    roles = cast(list[dict[str, object]], payload["role_aggregates"])
    statement_formalizer = next(item for item in roles if item["role"] == "statement_formalizer")
    statement_formalizer["incorrect_count"] = 1
    statement_formalizer["invalid_count"] = 2
    _write_object(paths.report, payload)

    result = _build(paths)
    affected = [node for node in result.nodes if "absolute_value" in node.structural_risk_families]

    assert affected
    assert all(
        node.calibration_priority is routing.IFEMCalibrationPriorityV1.P0_INCORRECT
        for node in affected
    )
    assert all(
        node.required_next_calibration
        is routing.IFEMRequiredNextCalibrationV1.DETERMINISTIC_OR_HIGHER_CAPABILITY_CALIBRATION
        for node in affected
    )
    assert all(node.semantic_classification.value == "unknown" for node in result.nodes)


def test_triage_drift_and_rehashed_output_provenance_are_rejected(tmp_path: Path) -> None:
    paths = _copy_inputs(tmp_path)
    result = _build(paths)
    payload = result.model_dump(mode="json")
    nodes = cast(list[dict[str, object]], payload["nodes"])
    risk_node = next(item for item in nodes if item["structural_risk_families"])
    risk_node["structural_risk_families"] = []
    risk_node["calibration_priority"] = "p3_create_calibration_case"
    risk_node["required_next_calibration"] = "create_calibration_case"
    forged_projection = routing.IFEMCalibrationRiskRoutingV1.model_validate(
        _content_addressed(payload)
    )
    with pytest.raises(
        routing.IFEMCalibrationRiskRoutingError, match="differs from exact input replay"
    ):
        _verify(forged_projection, paths)

    payload = result.model_dump(mode="json")
    evidence = cast(dict[str, object], payload["evidence"])
    evidence["triage_content_sha256"] = "0" * 64
    forged = routing.IFEMCalibrationRiskRoutingV1.model_validate(_content_addressed(payload))
    with pytest.raises(
        routing.IFEMCalibrationRiskRoutingError, match="differs from exact input replay"
    ):
        _verify(forged, paths)

    payload = result.model_dump(mode="json")
    nodes = cast(list[dict[str, object]], payload["nodes"])
    nodes[0]["semantic_classification"] = "direct"
    with pytest.raises(ValueError, match="literal_error"):
        routing.IFEMCalibrationRiskRoutingV1.model_validate(_content_addressed(payload))


def test_forbidden_methods_and_canonical_write_once_replay(tmp_path: Path) -> None:
    paths = _copy_inputs(tmp_path / "inputs")
    output = tmp_path / "routing.json"
    result = _materialize(output, paths)

    assert _materialize(output, paths) == result
    assert routing.load_ifem_calibration_risk_routing(output) == result
    _verify(result, paths)
    with pytest.raises(routing.IFEMCalibrationRiskRoutingError, match="cannot classify"):
        result.assert_not_routable()
    with pytest.raises(routing.IFEMCalibrationRiskRoutingError, match="cannot classify"):
        result.freeze_statement()
    with pytest.raises(routing.IFEMCalibrationRiskRoutingError, match="cannot classify"):
        result.handoff_to_prover()

    output.write_bytes(b"different\n")
    with pytest.raises(routing.IFEMCalibrationRiskRoutingError, match="already exists"):
        _materialize(output, paths)


def test_module_has_no_benchmarks_runtime_dependency_or_hidden_raw_fields() -> None:
    module_path = Path(routing.__file__)
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

    assert "benchmarks" not in imports
    result = routing.build_ifem_calibration_risk_routing_from_paths()
    rendered = routing.render_ifem_calibration_risk_routing(result)
    for forbidden in (b'"raw_output"', b'"source_text"', b'"canonical_type"'):
        assert forbidden not in rendered
