"""Tests for the independent public iFEM synthetic-role prompt fixture."""

from __future__ import annotations

import hashlib
from collections import Counter
from typing import Any, cast

import pytest
from autolean_builder import ifem_candidate_dependency_graph as candidate_graph
from autolean_builder import ifem_structural_calibration as calibration
from autolean_builder import ifem_structural_role_probes as probes
from autolean_contracts import canonical_json_bytes, stable_identifier

from benchmarks.ifem_synthetic_role_fixture import (
    IFEMSyntheticRoleFixtureError,
    IFEMSyntheticRoleOptionV1,
    build_ifem_synthetic_role_fixture,
    build_ifem_synthetic_role_oracle,
    ifem_synthetic_role_egress_bytes,
    render_ifem_synthetic_role_fixture,
)


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
                "ifem.markdown-source-span", f"synthetic-role-fixture:{index}"
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
    normalized = unsafe.model_dump(mode="json")
    normalized["content_sha256"] = unsafe.computed_content_sha256()
    return candidate_graph.IFEMCandidateDependencyGraphV1.model_validate(normalized)


def _corpus() -> probes.IFEMStructuralRoleProbeCorpusV1:
    graph = _valid_graph()
    catalog = calibration.build_ifem_structural_calibration_catalog(graph)
    return probes.build_ifem_structural_role_probe_corpus(catalog=catalog, graph=graph)


def test_public_fixture_is_exactly_16_neutral_rights_bound_cases() -> None:
    fixture = build_ifem_synthetic_role_fixture(_corpus(), operator_seed=b"operator-seed-a")

    assert len(fixture.cases) == 16
    assert fixture.case_count == 16
    assert fixture.content_sha256 == fixture.computed_content_sha256()
    assert Counter(case.role for case in fixture.cases) == Counter(
        {
            probes.IFEMStructuralProbeRoleV1.STATEMENT_FORMALIZER: 8,
            probes.IFEMStructuralProbeRoleV1.FIDELITY_REVIEWER: 4,
            probes.IFEMStructuralProbeRoleV1.CHEATING_SUPERVISOR: 4,
        }
    )
    for case in fixture.cases:
        assert case.source.source_id == case.rights.source_id
        assert case.source.spans[0].permitted_excerpt == case.prompt
        assert ifem_synthetic_role_egress_bytes(case) == case.prompt.encode("utf-8")
        assert not case.authority.freeze_allowed
        assert not case.authority.prover_handoff_allowed
        assert not case.authority.promotion_allowed
    assert not fixture.authority.model_egress_authorized
    assert not fixture.authority.freeze_allowed
    assert not fixture.authority.prover_handoff_allowed
    assert not fixture.authority.promotion_allowed

    rendered = render_ifem_synthetic_role_fixture(fixture)
    assert rendered == canonical_json_bytes(fixture.model_dump(mode="json")) + b"\n"


def test_seed_randomizes_public_order_without_exposing_preferred_side() -> None:
    corpus = _corpus()
    first = build_ifem_synthetic_role_fixture(corpus, operator_seed=b"seed-a")
    second = build_ifem_synthetic_role_fixture(corpus, operator_seed=b"seed-b")
    first_oracle = build_ifem_synthetic_role_oracle(corpus, operator_seed=b"seed-a")
    second_oracle = build_ifem_synthetic_role_oracle(corpus, operator_seed=b"seed-b")

    assert first.cases[0].case_id == second.cases[0].case_id
    assert any(a.prompt != b.prompt for a, b in zip(first.cases, second.cases, strict=True))
    assert first_oracle != second_oracle
    assert all(
        record.baseline_option in set(IFEMSyntheticRoleOptionV1) for record in first_oracle.records
    )
    public_json = render_ifem_synthetic_role_fixture(first).lower()
    assert b'"baseline_option"' not in public_json
    assert b'"baseline_mutant"' not in public_json


def test_private_oracle_is_independent_and_not_in_public_serializer() -> None:
    corpus = _corpus()
    fixture = build_ifem_synthetic_role_fixture(corpus, operator_seed="private-seed")
    oracle = build_ifem_synthetic_role_oracle(corpus, operator_seed="private-seed")

    assert not hasattr(fixture, "oracle")
    assert len(oracle.records) == len(fixture.cases) == 16
    assert oracle.authority.public_projection_allowed is False
    public_json = render_ifem_synthetic_role_fixture(fixture)
    assert b"private-oracle" not in public_json
    assert b'"private_evaluator_data"' not in public_json
    for pair in corpus.pairs:
        assert pair.pair_sha256.encode("ascii") not in public_json
        assert pair.witness.commitment_sha256.encode("ascii") not in public_json
        assert pair.mutation.value.encode("ascii") not in public_json
        assert pair.risk.value.encode("ascii") not in public_json
        assert pair.catalog_case_id.value.encode("ascii") not in public_json


def test_model_construct_and_span_rights_tamper_are_rejected() -> None:
    fixture = build_ifem_synthetic_role_fixture(_corpus(), operator_seed=b"tamper-seed")
    case_payload = fixture.cases[0].model_dump(mode="python", round_trip=True)
    source_payload = cast(dict[str, object], case_payload["source"])
    spans_payload = cast(list[object], source_payload["spans"])
    span_payload = cast(dict[str, object], spans_payload[0])
    span_payload["permitted_excerpt"] = "tampered prompt bytes"
    unsafe_case = cast(Any, type(fixture.cases[0])).model_construct(**case_payload)
    fixture_payload = fixture.model_dump(mode="python", round_trip=True)
    cases_payload = list(cast(tuple[object, ...], fixture_payload["cases"]))
    cases_payload[0] = unsafe_case
    fixture_payload["cases"] = tuple(cases_payload)
    unsafe_fixture = cast(Any, type(fixture)).model_construct(**fixture_payload)
    with pytest.raises(IFEMSyntheticRoleFixtureError, match="revalidated"):
        render_ifem_synthetic_role_fixture(unsafe_fixture)


def test_rehashed_provenance_tamper_is_rejected() -> None:
    fixture = build_ifem_synthetic_role_fixture(_corpus(), operator_seed=b"provenance-seed")
    payload = fixture.model_dump(mode="json")
    cases = list(cast(list[object], payload["cases"]))
    first = cast(dict[str, object], cases[0])
    first["role"] = probes.IFEMStructuralProbeRoleV1.FIDELITY_REVIEWER.value
    source = cast(dict[str, object], first["source"])
    source["locator"] = "file:///private/secret.txt"
    first["content_sha256"] = hashlib.sha256(
        canonical_json_bytes(
            {key: value for key, value in first.items() if key != "content_sha256"}
        )
    ).hexdigest()
    payload["cases"] = cases
    payload["content_sha256"] = hashlib.sha256(
        canonical_json_bytes(
            {key: value for key, value in payload.items() if key != "content_sha256"}
        )
    ).hexdigest()
    with pytest.raises(ValueError, match=r"fixed ordinal|fixed projection"):
        type(fixture).model_validate(payload)

    rights_payload = cast(dict[str, object], fixture.cases[0].rights.model_dump(mode="python"))
    rights_payload["source_id"] = stable_identifier("tampered", "rights").model_dump(mode="python")
    unsafe_rights = cast(Any, type(fixture.cases[0].rights)).model_construct(**rights_payload)
    tampered_case_payload = fixture.cases[0].model_dump(mode="python", round_trip=True)
    tampered_case_payload["rights"] = unsafe_rights
    unsafe_case = cast(Any, type(fixture.cases[0])).model_construct(**tampered_case_payload)
    fixture_payload = fixture.model_dump(mode="python", round_trip=True)
    cases_payload = list(cast(tuple[object, ...], fixture_payload["cases"]))
    cases_payload[0] = unsafe_case
    fixture_payload["cases"] = tuple(cases_payload)
    unsafe_fixture = cast(Any, type(fixture)).model_construct(**fixture_payload)
    with pytest.raises(IFEMSyntheticRoleFixtureError, match="revalidated"):
        render_ifem_synthetic_role_fixture(unsafe_fixture)


def test_non_exact_corpus_and_empty_seed_fail_closed() -> None:
    with pytest.raises(IFEMSyntheticRoleFixtureError, match="operator_seed"):
        build_ifem_synthetic_role_fixture(_corpus(), operator_seed=b"")

    corpus = _corpus()
    payload = corpus.model_dump(mode="python", round_trip=True)
    payload["contains_source_text"] = True
    unsafe = cast(Any, type(corpus)).model_construct(**payload)
    with pytest.raises(IFEMSyntheticRoleFixtureError, match="revalidated"):
        build_ifem_synthetic_role_fixture(unsafe, operator_seed=b"seed")
