"""Tests for the source-free iFEM structural calibration contract."""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path
from typing import cast

import pytest
from autolean_builder import ifem_candidate_dependency_graph as candidate_graph
from autolean_builder import ifem_structural_calibration as calibration
from autolean_contracts import canonical_json_bytes, stable_identifier


def _valid_graph() -> candidate_graph.IFEMCandidateDependencyGraphV1:
    source_binding = candidate_graph.IFEMCandidateGraphSourceBindingV1(
        source_lock_sha256="a" * 64,
        source_revision="b" * 40,
        source_file_count=1,
        staged_file_count=1,
        opening_markdown_index_sha256="c" * 64,
        opening_markdown_span_count=1,
        notebook_index_sha256="d" * 64,
        notebook_cell_count=1,
        staging_manifest_sha256="e" * 64,
        discovery_manifest_sha256="f" * 64,
        census_plan_content_sha256="0" * 64,
        census_result_sha256="1" * 64,
    )
    ambiguity_flags = tuple(sorted(candidate_graph.IFEMCandidateNodeAmbiguityFlagV1, key=str))
    gap_flags = tuple(sorted(candidate_graph.IFEMCandidateNodeGapFlagV1, key=str))
    nodes = tuple(
        candidate_graph.IFEMCandidateNodeV1(
            node_id=node_id,
            candidate_node_kind=(
                "terminal_target"
                if node_id is candidate_graph.IFEMCandidateNodeIdV1.CEA_QUASI_OPTIMALITY_INFINUM
                else "definition"
            ),
            source_order=index,
            included_in_prerequisite_denominator=False,
            source_anchor_id=stable_identifier(
                "ifem.markdown-source-span", f"project-synthetic-structural:{index}"
            ),
            source_anchor_kind="markdown_heading",
            census_query_present=False,
            candidate_declaration_count=0,
            candidate_declaration_set_sha256=None,
            ambiguity_flags=ambiguity_flags,
            gap_flags=gap_flags,
        )
        for index, node_id in enumerate(candidate_graph.IFEMCandidateNodeIdV1, start=1)
    )
    return _revalidated_graph_from_payload(
        {
            "schema_version": candidate_graph.IFEM_CANDIDATE_GRAPH_SCHEMA,
            "artifact_kind": candidate_graph.IFEM_CANDIDATE_GRAPH_ARTIFACT_KIND,
            "lane_id": candidate_graph.IFEM_LANE_ID,
            "source_binding": source_binding.model_dump(mode="json"),
            "census_execution_state": "not_run",
            "graph_layers": candidate_graph.IFEMCandidateGraphLayersV1().model_dump(mode="json"),
            "authority": candidate_graph.IFEMCandidateGraphAuthorityBoundaryV1().model_dump(
                mode="json"
            ),
            "contains_source_text": False,
            "contains_model_input": False,
            "candidate_nodes": [node.model_dump(mode="json") for node in nodes],
            "candidate_edges": [],
            "content_sha256": "0" * 64,
        }
    )


def _revalidated_graph_from_payload(
    payload: dict[str, object],
) -> candidate_graph.IFEMCandidateDependencyGraphV1:
    source_binding = candidate_graph.IFEMCandidateGraphSourceBindingV1.model_validate(
        cast(dict[str, object], payload["source_binding"])
    )
    graph_layers = candidate_graph.IFEMCandidateGraphLayersV1.model_validate(
        cast(dict[str, object], payload["graph_layers"])
    )
    authority = candidate_graph.IFEMCandidateGraphAuthorityBoundaryV1.model_validate(
        cast(dict[str, object], payload["authority"])
    )
    nodes = tuple(
        candidate_graph.IFEMCandidateNodeV1.model_validate(cast(dict[str, object], node))
        for node in cast(list[object], payload["candidate_nodes"])
    )
    edges = tuple(
        candidate_graph.IFEMCandidateDependencyEdgeV1.model_validate(cast(dict[str, object], edge))
        for edge in cast(list[object], payload["candidate_edges"])
    )
    unsafe = candidate_graph.IFEMCandidateDependencyGraphV1.model_construct(
        schema_version=payload["schema_version"],
        artifact_kind=payload["artifact_kind"],
        lane_id=payload["lane_id"],
        source_binding=source_binding,
        census_execution_state=payload["census_execution_state"],
        graph_layers=graph_layers,
        authority=authority,
        contains_source_text=payload["contains_source_text"],
        contains_model_input=payload["contains_model_input"],
        candidate_nodes=nodes,
        candidate_edges=edges,
        content_sha256="0" * 64,
    )
    validated_payload = unsafe.model_dump(mode="json")
    validated_payload["content_sha256"] = unsafe.computed_content_sha256()
    return candidate_graph.IFEMCandidateDependencyGraphV1.model_validate(validated_payload)


def test_catalog_is_deterministic_complete_and_non_authoritative() -> None:
    graph = _valid_graph()
    first = calibration.build_ifem_structural_calibration_catalog(graph)
    second = calibration.build_ifem_structural_calibration_catalog(graph)

    assert first == second
    assert first.content_sha256 == first.computed_content_sha256()
    assert first.source_binding.candidate_graph_content_sha256 == graph.content_sha256
    assert first.source_binding.candidate_graph_source_binding == graph.source_binding
    assert len(first.cases) == 16
    assert {case.risk for case in first.cases} == set(calibration.IFEMStructuralRiskV1)
    assert {case.mutation for case in first.cases} == set(calibration.IFEMStructuralMutationV1)
    assert {case.role for case in first.cases} == set(calibration.IFEMStructuralCalibrationRoleV1)
    graph_nodes = {node.node_id for node in graph.candidate_nodes}
    assert all(set(case.candidate_node_ids) <= graph_nodes for case in first.cases)
    assert not first.contains_source_text
    assert not first.contains_source_excerpt
    assert not first.contains_lean_statement
    assert not first.contains_model_input
    assert not first.authority.freeze_allowed
    assert not first.authority.prover_handoff_allowed
    rendered = calibration.render_ifem_structural_calibration_catalog(first)
    assert rendered == canonical_json_bytes(first.model_dump(mode="json")) + b"\n"
    with pytest.raises(calibration.IFEMStructuralCalibrationError, match="cannot create"):
        first.freeze_statement()
    with pytest.raises(calibration.IFEMStructuralCalibrationError, match="cannot create"):
        first.handoff_to_prover()


def test_build_revalidates_graph_and_requires_complete_node_set() -> None:
    graph = _valid_graph()
    unsafe_payload = graph.model_dump(mode="python")
    authority_payload = graph.authority.model_dump(mode="python")
    authority_payload["freeze_allowed"] = True
    unsafe_payload["authority"] = (
        candidate_graph.IFEMCandidateGraphAuthorityBoundaryV1.model_construct(**authority_payload)
    )
    unsafe = candidate_graph.IFEMCandidateDependencyGraphV1.model_construct(**unsafe_payload)
    with pytest.raises(calibration.IFEMStructuralCalibrationError, match="revalidated"):
        calibration.build_ifem_structural_calibration_catalog(unsafe)

    incomplete_payload = graph.model_dump(mode="python")
    nodes = list(cast(tuple[object, ...], incomplete_payload["candidate_nodes"]))
    nodes.pop()
    for index, node in enumerate(nodes, start=1):
        node_payload = cast(dict[str, object], node)
        node_payload["source_order"] = index
    incomplete_payload["candidate_nodes"] = nodes
    incomplete = _revalidated_graph_from_payload(incomplete_payload)
    with pytest.raises(calibration.IFEMStructuralCalibrationError, match="complete node set"):
        calibration.build_ifem_structural_calibration_catalog(incomplete)


def test_render_rejects_model_construct_injection_and_case_tampering() -> None:
    catalog = calibration.build_ifem_structural_calibration_catalog(_valid_graph())

    text_injection = catalog.model_dump(mode="python")
    text_injection["contains_source_text"] = True
    unsafe_text_catalog = calibration.IFEMStructuralCalibrationCatalogV1.model_construct(
        **text_injection
    )
    text_injection["content_sha256"] = unsafe_text_catalog.computed_content_sha256()
    unsafe_text_catalog = calibration.IFEMStructuralCalibrationCatalogV1.model_construct(
        **text_injection
    )
    with pytest.raises(calibration.IFEMStructuralCalibrationError, match="model-constructed"):
        calibration.render_ifem_structural_calibration_catalog(unsafe_text_catalog)

    case_payload = catalog.cases[0].model_dump(mode="python")
    case_payload["required_disposition"] = calibration.IFEMStructuralDispositionV1.REJECT_MUTATION
    unsafe_case = calibration.IFEMStructuralCalibrationCaseV1.model_construct(**case_payload)
    case_injection = catalog.model_dump(mode="python")
    cases = list(cast(tuple[object, ...], case_injection["cases"]))
    cases[0] = unsafe_case
    case_injection["cases"] = cases
    unsafe_case_catalog = calibration.IFEMStructuralCalibrationCatalogV1.model_construct(
        **case_injection
    )
    case_injection["content_sha256"] = unsafe_case_catalog.computed_content_sha256()
    unsafe_case_catalog = calibration.IFEMStructuralCalibrationCatalogV1.model_construct(
        **case_injection
    )
    with pytest.raises(calibration.IFEMStructuralCalibrationError, match="model-constructed"):
        calibration.render_ifem_structural_calibration_catalog(unsafe_case_catalog)


def test_consumer_verification_rejects_catalog_rebinding() -> None:
    graph = _valid_graph()
    catalog = calibration.build_ifem_structural_calibration_catalog(graph)
    assert (
        calibration.verify_ifem_structural_calibration_catalog_against_graph(catalog, graph)
        == catalog
    )

    rebound_payload = catalog.model_dump(mode="json")
    source_binding = catalog.source_binding.model_dump(mode="json")
    source_binding["candidate_graph_content_sha256"] = "9" * 64
    graph_source_binding = graph.source_binding.model_dump(mode="json")
    graph_source_binding["source_lock_sha256"] = "8" * 64
    source_binding["candidate_graph_source_binding"] = graph_source_binding
    rebound_payload["source_binding"] = source_binding
    rebound_payload["content_sha256"] = hashlib.sha256(
        canonical_json_bytes(
            {key: value for key, value in rebound_payload.items() if key != "content_sha256"}
        )
    ).hexdigest()
    rebound = calibration.IFEMStructuralCalibrationCatalogV1.model_validate(rebound_payload)

    assert calibration.render_ifem_structural_calibration_catalog(rebound)
    with pytest.raises(calibration.IFEMStructuralCalibrationError, match="does not bind"):
        calibration.verify_ifem_structural_calibration_catalog_against_graph(rebound, graph)

    alternate_graph_payload = graph.model_dump(mode="python")
    alternate_source_binding = graph.source_binding.model_dump(mode="python")
    alternate_source_binding["source_lock_sha256"] = "7" * 64
    alternate_graph_payload["source_binding"] = alternate_source_binding
    alternate_graph = _revalidated_graph_from_payload(alternate_graph_payload)
    with pytest.raises(calibration.IFEMStructuralCalibrationError, match="does not bind"):
        calibration.verify_ifem_structural_calibration_catalog_against_graph(
            catalog, alternate_graph
        )


def test_module_does_not_import_prover_or_control_plane() -> None:
    tree = ast.parse(Path(calibration.__file__).read_text(encoding="utf-8"))
    imported_modules = {
        alias.name
        for statement in ast.walk(tree)
        if isinstance(statement, ast.Import)
        for alias in statement.names
    }
    imported_modules.update(
        statement.module or ""
        for statement in ast.walk(tree)
        if isinstance(statement, ast.ImportFrom)
    )
    assert not any(name.startswith("autolean_prover") for name in imported_modules)
    assert not any(name.startswith("autolean_control_plane") for name in imported_modules)
