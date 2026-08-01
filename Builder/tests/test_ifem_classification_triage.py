"""Tests for the source-free, unknown-only iFEM classification triage."""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest
from autolean_builder import ifem_classification_triage as triage
from autolean_builder.ifem_prerequisite_census import (
    load_ifem_prerequisite_census_plan,
)
from autolean_contracts import canonical_json_bytes

ROOT = Path(__file__).resolve().parents[2]
_OLD_READINESS_PATH = ROOT / "docs" / "research" / "ifem-pilot-readiness-decision-2026-07-31.json"


@dataclass(frozen=True, slots=True)
class _Paths:
    graph: Path
    census_plan: Path
    census_result: Path
    profile_summary: Path
    structural_corpus: Path
    readiness_decision: Path


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _content_addressed(payload: dict[str, object]) -> dict[str, object]:
    normalized = copy.deepcopy(payload)
    normalized.pop("content_sha256", None)
    normalized["content_sha256"] = hashlib.sha256(canonical_json_bytes(normalized)).hexdigest()
    return normalized


def _read_object(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return cast(dict[str, object], value)


def _write_object(path: Path, payload: dict[str, object]) -> None:
    path.write_bytes(canonical_json_bytes(_content_addressed(payload)) + b"\n")


def _copy_inputs(tmp_path: Path, *, readiness_path: Path | None = None) -> _Paths:
    source_paths = {
        "graph": triage.DEFAULT_GRAPH_PATH,
        "census_plan": triage.DEFAULT_CENSUS_PLAN_PATH,
        "census_result": triage.DEFAULT_CENSUS_RESULT_PATH,
        "profile_summary": triage.DEFAULT_PROFILE_SUMMARY_PATH,
        "structural_corpus": triage.DEFAULT_STRUCTURAL_CORPUS_PATH,
        "readiness_decision": readiness_path or triage.DEFAULT_READINESS_DECISION_PATH,
    }
    copied: dict[str, Path] = {}
    for key, source in source_paths.items():
        destination = tmp_path / f"{key}.json"
        shutil.copyfile(source, destination)
        copied[key] = destination
    return _Paths(**copied)


def _build(paths: _Paths) -> triage.IFEMUnknownOnlyClassificationTriageV1:
    return triage.build_ifem_unknown_only_classification_triage_from_paths(
        graph_path=paths.graph,
        census_plan_path=paths.census_plan,
        census_result_path=paths.census_result,
        profile_summary_path=paths.profile_summary,
        structural_corpus_path=paths.structural_corpus,
        readiness_decision_path=paths.readiness_decision,
    )


def _verify(
    value: triage.IFEMUnknownOnlyClassificationTriageV1,
    paths: _Paths,
) -> None:
    triage.verify_ifem_unknown_only_classification_triage_against_paths(
        value,
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
) -> triage.IFEMUnknownOnlyClassificationTriageV1:
    return triage.materialize_ifem_unknown_only_classification_triage_from_paths_once(
        output,
        graph_path=paths.graph,
        census_plan_path=paths.census_plan,
        census_result_path=paths.census_result,
        profile_summary_path=paths.profile_summary,
        structural_corpus_path=paths.structural_corpus,
        readiness_decision_path=paths.readiness_decision,
    )


def test_consistent_source_free_snapshot_projects_exactly_21_unknown_nodes(tmp_path: Path) -> None:
    paths = _copy_inputs(tmp_path)
    output = tmp_path / "triage.json"
    result = _materialize(output, paths)
    rendered = output.read_bytes()
    _verify(result, paths)

    assert result.denominator_node_count == len(result.nodes) == 21
    assert all(node.semantic_classification.value == "unknown" for node in result.nodes)
    assert all(node.candidate_visibility_is_non_semantic for node in result.nodes)
    assert {node.node_id for node in result.nodes} == {
        item.node_id for item in load_ifem_prerequisite_census_plan(paths.census_plan).queries
    }
    assert result.evidence.candidate_graph_file_sha256 == _sha256(paths.graph.read_bytes())
    assert result.evidence.census_plan_file_sha256 == _sha256(paths.census_plan.read_bytes())
    assert result.evidence.census_result_file_sha256 == _sha256(paths.census_result.read_bytes())
    assert result.evidence.pinned_profile_public_summary_file_sha256 == _sha256(
        paths.profile_summary.read_bytes()
    )
    assert result.evidence.structural_probe_corpus_file_sha256 == _sha256(
        paths.structural_corpus.read_bytes()
    )
    assert result.evidence.readiness_decision_file_sha256 == _sha256(
        paths.readiness_decision.read_bytes()
    )
    candidate_names = {
        declaration
        for query in load_ifem_prerequisite_census_plan(paths.census_plan).queries
        for declaration in query.candidate_declarations
    }
    assert all(declaration.encode("utf-8") not in rendered for declaration in candidate_names)
    assert b'"canonical_type"' not in rendered
    assert b'"candidate_declarations"' not in rendered
    assert result.authority.semantic_classification_authorized is False
    assert result.builder_freeze == result.prover_handoff == "forbidden"


def test_current_d39_readiness_fork_is_a_hard_failure(tmp_path: Path) -> None:
    paths = _copy_inputs(tmp_path, readiness_path=_OLD_READINESS_PATH)

    with pytest.raises(
        triage.IFEMClassificationTriageError,
        match="does not bind the exact triage census",
    ):
        _build(paths)


def test_candidate_graph_node_drift_is_rejected_before_projection(tmp_path: Path) -> None:
    paths = _copy_inputs(tmp_path)
    payload = _read_object(paths.graph)
    nodes = cast(list[dict[str, object]], payload["candidate_nodes"])
    nodes[1]["candidate_node_kind"] = "prerequisite_theorem"
    _write_object(paths.graph, payload)

    with pytest.raises(triage.IFEMClassificationTriageError, match="structural corpus catalog"):
        _build(paths)


def test_census_candidate_set_drift_is_rejected(tmp_path: Path) -> None:
    paths = _copy_inputs(tmp_path)
    payload = _read_object(paths.census_plan)
    queries = cast(list[dict[str, object]], payload["queries"])
    queries[0]["candidate_declarations"] = ["A", "Real"]
    _write_object(paths.census_plan, payload)

    with pytest.raises(triage.IFEMClassificationTriageError):
        _build(paths)


def test_profile_plan_drift_is_rejected(tmp_path: Path) -> None:
    paths = _copy_inputs(tmp_path)
    payload = _read_object(paths.profile_summary)
    payload["plan_content_sha256"] = "0" * 64
    _write_object(paths.profile_summary, payload)

    with pytest.raises(triage.IFEMClassificationTriageError, match="replayed profile plan"):
        _build(paths)


def test_declared_profile_plan_file_hash_is_not_emitted_as_loaded_evidence(tmp_path: Path) -> None:
    paths = _copy_inputs(tmp_path)
    payload = _read_object(paths.profile_summary)
    payload["plan_file_sha256"] = "0" * 64
    _write_object(paths.profile_summary, payload)

    result = _build(paths)

    assert "pinned_profile_plan_file_sha256" not in result.evidence.model_dump(mode="json")
    assert result.evidence.pinned_profile_public_summary_file_sha256 == _sha256(
        paths.profile_summary.read_bytes()
    )


def test_structural_corpus_catalog_drift_is_rejected(tmp_path: Path) -> None:
    paths = _copy_inputs(tmp_path)
    payload = _read_object(paths.structural_corpus)
    payload["candidate_graph_content_sha256"] = "0" * 64
    _write_object(paths.structural_corpus, payload)

    with pytest.raises(
        triage.IFEMClassificationTriageError,
        match="structural probe corpus has an invalid",
    ):
        _build(paths)


def test_tampered_readiness_evidence_is_rejected_even_when_rehashed(tmp_path: Path) -> None:
    paths = _copy_inputs(tmp_path)
    payload = _read_object(paths.readiness_decision)
    evidence = cast(dict[str, object], payload["evidence"])
    evidence["census_result_content_sha256"] = "0" * 64
    _write_object(paths.readiness_decision, payload)

    with pytest.raises(
        triage.IFEMClassificationTriageError,
        match="does not bind the exact triage census",
    ):
        _build(paths)


def test_non_unknown_output_is_rejected_even_when_rehashed(tmp_path: Path) -> None:
    result = _build(_copy_inputs(tmp_path))
    payload = result.model_dump(mode="json")
    nodes = cast(list[dict[str, object]], payload["nodes"])
    nodes[0]["semantic_classification"] = "direct"
    payload = _content_addressed(payload)

    with pytest.raises(ValueError, match="literal_error"):
        triage.IFEMUnknownOnlyClassificationTriageV1.model_validate(payload)


def test_permuted_cli_input_arguments_have_deterministic_output(tmp_path: Path) -> None:
    paths = _copy_inputs(tmp_path)
    ordered_output = tmp_path / "ordered.json"
    permuted_output = tmp_path / "permuted.json"

    assert (
        triage.main(
            [
                "--graph",
                str(paths.graph),
                "--census-plan",
                str(paths.census_plan),
                "--census-result",
                str(paths.census_result),
                "--profile-summary",
                str(paths.profile_summary),
                "--structural-corpus",
                str(paths.structural_corpus),
                "--readiness-decision",
                str(paths.readiness_decision),
                "--out",
                str(ordered_output),
            ]
        )
        == 0
    )
    assert (
        triage.main(
            [
                "--out",
                str(permuted_output),
                "--readiness-decision",
                str(paths.readiness_decision),
                "--structural-corpus",
                str(paths.structural_corpus),
                "--profile-summary",
                str(paths.profile_summary),
                "--census-result",
                str(paths.census_result),
                "--census-plan",
                str(paths.census_plan),
                "--graph",
                str(paths.graph),
            ]
        )
        == 0
    )

    assert ordered_output.read_bytes() == permuted_output.read_bytes()


def test_only_the_path_replay_entry_point_is_public() -> None:
    assert "build_ifem_unknown_only_classification_triage" not in triage.__all__
    assert not hasattr(triage, "build_ifem_unknown_only_classification_triage")
    assert "render_ifem_unknown_only_classification_triage" not in triage.__all__
    assert "write_ifem_unknown_only_classification_triage_once" not in triage.__all__
    assert "materialize_ifem_unknown_only_classification_triage_from_paths_once" in triage.__all__
    assert "verify_ifem_unknown_only_classification_triage_against_paths" in triage.__all__


def test_freeze_and_handoff_are_unconditionally_rejected(tmp_path: Path) -> None:
    result = _build(_copy_inputs(tmp_path))

    with pytest.raises(triage.IFEMClassificationTriageError, match="cannot classify"):
        result.freeze_statement()
    with pytest.raises(triage.IFEMClassificationTriageError, match="cannot classify"):
        result.handoff_to_prover()


def test_materialize_reloads_exact_bytes_and_rejects_replacement(tmp_path: Path) -> None:
    paths = _copy_inputs(tmp_path)
    output = tmp_path / "triage.json"

    result = _materialize(output, paths)
    assert _materialize(output, paths) == result
    loaded = triage.load_ifem_unknown_only_classification_triage(output)
    assert loaded == result
    _verify(loaded, paths)

    replacement = tmp_path / "replacement.json"
    replacement.write_bytes(b"different bytes\n")
    with pytest.raises(triage.IFEMClassificationTriageError, match="already exists"):
        _materialize(replacement, paths)


def test_rehashed_file_provenance_is_rejected_by_exact_path_replay(tmp_path: Path) -> None:
    paths = _copy_inputs(tmp_path)
    payload = _build(paths).model_dump(mode="json")
    evidence = cast(dict[str, object], payload["evidence"])
    evidence["candidate_graph_file_sha256"] = "0" * 64
    forged = triage.IFEMUnknownOnlyClassificationTriageV1.model_validate(
        _content_addressed(payload)
    )
    output = tmp_path / "forged-triage.json"
    output.write_bytes(canonical_json_bytes(forged.model_dump(mode="json")) + b"\n")

    loaded = triage.load_ifem_unknown_only_classification_triage(output)
    assert loaded == forged
    with pytest.raises(
        triage.IFEMClassificationTriageError,
        match="differs from exact input replay",
    ):
        _verify(loaded, paths)
