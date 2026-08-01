"""Tests for project-synthetic iFEM witness validation."""

from __future__ import annotations

import ast
from fractions import Fraction
from pathlib import Path
from typing import cast

import pytest
from autolean_builder import ifem_candidate_dependency_graph as candidate_graph
from autolean_builder import ifem_structural_calibration as calibration
from autolean_builder import ifem_structural_role_probes as probes
from autolean_builder import ifem_structural_witness_validation as validation
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
                "ifem.markdown-source-span", f"project-synthetic-witness:{index}"
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
    payload: dict[str, object] = {
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
    return _revalidated_graph_from_payload(payload)


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


def _corpus() -> tuple[
    candidate_graph.IFEMCandidateDependencyGraphV1,
    probes.IFEMStructuralRoleProbeCorpusV1,
]:
    graph = _valid_graph()
    catalog = calibration.build_ifem_structural_calibration_catalog(graph)
    return graph, probes.build_ifem_structural_role_probe_corpus(catalog=catalog, graph=graph)


def _set_witness_specification_and_role_probe_golden(
    monkeypatch: pytest.MonkeyPatch,
    *,
    risk: calibration.IFEMStructuralRiskV1,
    specification: dict[str, object],
) -> None:
    monkeypatch.setitem(probes._WITNESS_SPECIFICATIONS, risk, specification)
    commitment = probes._sha256_json(
        {
            "schema_version": "autolean.ifem-structural-witness-specification.v1",
            "risk": risk,
            "witness_kind": probes._WITNESS_KIND_BY_RISK[risk],
            "specification": specification,
            "project_synthetic": True,
            "mathematical_validation_claimed": False,
        }
    )
    monkeypatch.setitem(probes._WITNESS_COMMITMENT_GOLDENS, risk, commitment)


_WITNESS_SPECIFICATION_FIELDS = tuple(
    (risk, field_name)
    for risk in sorted(probes._WITNESS_SPECIFICATIONS, key=str)
    for field_name in sorted(probes._WITNESS_SPECIFICATIONS[risk])
)


def test_all_risks_have_deterministic_distinguishing_witnesses() -> None:
    graph, corpus = _corpus()
    first = validation.validate_ifem_structural_witnesses(corpus=corpus, graph=graph)
    second = validation.validate_ifem_structural_witnesses(corpus=corpus, graph=graph)

    assert first == second
    assert first.validation_count == 8
    assert first.probe_corpus_content_sha256 == corpus.content_sha256
    assert first.candidate_graph_content_sha256 == graph.content_sha256
    assert {item.risk for item in first.validations} == set(calibration.IFEMStructuralRiskV1)
    assert all(
        item.baseline_dimension_value != item.mutant_dimension_value for item in first.validations
    )
    assert (
        len({pair_sha256 for item in first.validations for pair_sha256 in item.pair_sha256}) == 16
    )
    assert not first.private_witness_specifications_embedded
    assert not first.authority.lean_checked
    assert not first.authority.semantic_equivalence_claimed
    assert not first.authority.model_egress_allowed

    by_risk = {item.risk: item for item in first.validations}
    absolute_value = by_risk[calibration.IFEMStructuralRiskV1.ABSOLUTE_VALUE]
    assert (
        absolute_value.scope
        is validation.IFEMStructuralWitnessValidationScopeV1.EXACT_FINITE_COMPUTATION
    )
    vacuity = by_risk[calibration.IFEMStructuralRiskV1.VACUOUS_HYPOTHESIS]
    assert (
        vacuity.distinguishing_dimension
        is validation.IFEMStructuralDistinguishingDimensionV1.GUARD_SATISFIABILITY
    )
    assert vacuity.baseline_dimension_value
    assert not vacuity.mutant_dimension_value

    closed_subspace = by_risk[calibration.IFEMStructuralRiskV1.CLOSED_SUBSPACE]
    assert (
        closed_subspace.scope
        is validation.IFEMStructuralWitnessValidationScopeV1.SCHEMA_PLUS_STANDARD_LEMMA
    )
    assert closed_subspace.standard_lemma_dependencies

    rendered = validation.render_ifem_structural_witness_validation_report(
        first,
        corpus=corpus,
        graph=graph,
    )
    assert rendered == canonical_json_bytes(first.model_dump(mode="json")) + b"\n"
    for forbidden in (
        b'"specification"',
        b'"input_payload"',
        b'"expected_output"',
        b'"prompt"',
        b'"source_text"',
        b'"lean_statement"',
    ):
        assert forbidden not in rendered

    with pytest.raises(validation.IFEMStructuralWitnessValidationError, match="cannot create"):
        first.assert_not_routable()


def test_absolute_value_probe_rejects_a_sign_closed_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    original = probes._WITNESS_SPECIFICATIONS[calibration.IFEMStructuralRiskV1.ABSOLUTE_VALUE]
    unsafe = {
        **original,
        "evaluation_scope": "all_real_pairs",
        "scope_closed_under_sign_change": True,
    }
    _set_witness_specification_and_role_probe_golden(
        monkeypatch,
        risk=calibration.IFEMStructuralRiskV1.ABSOLUTE_VALUE,
        specification=unsafe,
    )
    evaluator_goldens = dict(validation._WITNESS_SPECIFICATION_SHA256_GOLDENS)
    evaluator_goldens[calibration.IFEMStructuralRiskV1.ABSOLUTE_VALUE] = validation._sha256_json(
        unsafe
    )
    monkeypatch.setattr(
        validation,
        "_WITNESS_SPECIFICATION_SHA256_GOLDENS",
        evaluator_goldens,
    )
    graph, corpus = _corpus()
    with pytest.raises(
        validation.IFEMStructuralWitnessValidationError,
        match="finite scope excludes sign closure",
    ):
        validation.validate_ifem_structural_witnesses(corpus=corpus, graph=graph)


def test_render_rejects_model_construct_and_graph_rebinding() -> None:
    graph, corpus = _corpus()
    report = validation.validate_ifem_structural_witnesses(corpus=corpus, graph=graph)

    payload = report.model_dump(mode="python")
    authority_payload = report.authority.model_dump(mode="python")
    authority_payload["model_egress_allowed"] = True
    payload["authority"] = validation.IFEMStructuralWitnessValidationAuthorityV1.model_construct(
        **authority_payload
    )
    unsafe = validation.IFEMStructuralWitnessValidationReportV1.model_construct(**payload)
    with pytest.raises(validation.IFEMStructuralWitnessValidationError, match="model-constructed"):
        validation.render_ifem_structural_witness_validation_report(
            unsafe,
            corpus=corpus,
            graph=graph,
        )

    changed_payload = graph.model_dump(mode="python")
    source_binding = cast(dict[str, object], changed_payload["source_binding"])
    source_binding["source_lock_sha256"] = "9" * 64
    unsafe_graph = candidate_graph.IFEMCandidateDependencyGraphV1.model_construct(**changed_payload)
    with pytest.raises(validation.IFEMStructuralWitnessValidationError, match="revalidated"):
        validation.validate_ifem_structural_witnesses(corpus=corpus, graph=unsafe_graph)


def test_validation_module_has_no_runtime_or_provider_dependency() -> None:
    module_path = Path(validation.__file__)
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    forbidden_roots = {
        "benchmarks",
        "autolean_control_plane",
        "autolean_prover",
        "autolean_dashboard",
    }
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imports.add(node.module.split(".", 1)[0])
    assert not imports & forbidden_roots


@pytest.mark.parametrize(("risk", "field_name"), _WITNESS_SPECIFICATION_FIELDS)
def test_every_witness_specification_field_is_bound_to_the_evaluator_golden(
    monkeypatch: pytest.MonkeyPatch,
    risk: calibration.IFEMStructuralRiskV1,
    field_name: str,
) -> None:
    unsafe = {**probes._WITNESS_SPECIFICATIONS[risk], field_name: "tampered"}
    _set_witness_specification_and_role_probe_golden(
        monkeypatch,
        risk=risk,
        specification=unsafe,
    )
    graph, corpus = _corpus()
    with pytest.raises(
        validation.IFEMStructuralWitnessValidationError,
        match="approved evaluator fixture",
    ):
        validation.validate_ifem_structural_witnesses(corpus=corpus, graph=graph)


@pytest.mark.parametrize("change", ["added", "removed"])
def test_witness_specification_shape_drift_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    risk = calibration.IFEMStructuralRiskV1.QUANTIFIER_ORDER
    unsafe = dict(probes._WITNESS_SPECIFICATIONS[risk])
    if change == "added":
        unsafe["unexpected"] = "field"
    else:
        del unsafe["relation"]
    _set_witness_specification_and_role_probe_golden(
        monkeypatch,
        risk=risk,
        specification=unsafe,
    )
    graph, corpus = _corpus()
    with pytest.raises(
        validation.IFEMStructuralWitnessValidationError,
        match="approved evaluator fixture",
    ):
        validation.validate_ifem_structural_witnesses(corpus=corpus, graph=graph)


def test_forged_self_hashed_report_cannot_be_rendered() -> None:
    graph, corpus = _corpus()
    report = validation.validate_ifem_structural_witnesses(corpus=corpus, graph=graph)
    payload = report.model_dump(mode="python")
    validations = cast(list[dict[str, object]], payload["validations"])
    validations[0]["machine_check_ids"] = ["fabricated-check"]
    validations[0]["baseline_dimension_value"] = not cast(
        bool, validations[0]["baseline_dimension_value"]
    )
    validations[0]["mutant_dimension_value"] = not cast(
        bool, validations[0]["mutant_dimension_value"]
    )
    validations[0]["validation_sha256"] = validation._sha256_json(
        {key: value for key, value in validations[0].items() if key != "validation_sha256"}
    )
    payload["content_sha256"] = validation._sha256_json(
        {key: value for key, value in payload.items() if key != "content_sha256"}
    )
    forged = validation.IFEMStructuralWitnessValidationReportV1.model_validate(payload)

    with pytest.raises(
        validation.IFEMStructuralWitnessValidationError,
        match="differs from exact evaluator recomputation",
    ):
        validation.render_ifem_structural_witness_validation_report(
            forged,
            corpus=corpus,
            graph=graph,
        )


def test_writer_persists_only_an_exact_recomputed_report(tmp_path: Path) -> None:
    graph, corpus = _corpus()
    report = validation.validate_ifem_structural_witnesses(corpus=corpus, graph=graph)
    output = tmp_path / validation.IFEM_STRUCTURAL_WITNESS_VALIDATION_REPORT_FILENAME
    validation.write_ifem_structural_witness_validation_report(
        cache_root=tmp_path,
        output_path=output,
        report=report,
        corpus=corpus,
        graph=graph,
    )
    expected = validation.render_ifem_structural_witness_validation_report(
        report,
        corpus=corpus,
        graph=graph,
    )
    assert output.read_bytes() == expected

    payload = report.model_dump(mode="python")
    validations = cast(list[dict[str, object]], payload["validations"])
    validations[0]["machine_check_ids"] = ["fabricated-write-check"]
    validations[0]["validation_sha256"] = validation._sha256_json(
        {key: value for key, value in validations[0].items() if key != "validation_sha256"}
    )
    payload["content_sha256"] = validation._sha256_json(
        {key: value for key, value in payload.items() if key != "content_sha256"}
    )
    forged = validation.IFEMStructuralWitnessValidationReportV1.model_validate(payload)
    with pytest.raises(
        validation.IFEMStructuralWitnessValidationError,
        match="differs from exact evaluator recomputation",
    ):
        validation.write_ifem_structural_witness_validation_report(
            cache_root=tmp_path,
            output_path=output,
            report=forged,
            corpus=corpus,
            graph=graph,
        )
    assert output.read_bytes() == expected


def test_absolute_value_probe_is_only_a_non_sign_closed_local_observation() -> None:
    sign_closed_values = (Fraction(-1), Fraction(1))
    bound = Fraction(1)
    one_sided = all(value <= bound for value in sign_closed_values)
    absolute = all(abs(value) <= bound for value in sign_closed_values)
    assert one_sided and absolute


@pytest.mark.parametrize(
    ("risk", "required_checks"),
    [
        (
            calibration.IFEMStructuralRiskV1.CLOSED_SUBSPACE,
            {
                "c00-finite-truncation-membership",
                "c00-infinite-support-limit",
                "exact-geometric-tail-identity",
            },
        ),
        (
            calibration.IFEMStructuralRiskV1.RESTRICTION_DOMAIN,
            {
                "r2-ambient-coefficient-mismatch",
                "r2-subspace-coefficient-equality",
                "r2-subspace-membership-and-outside-witness",
            },
        ),
        (
            calibration.IFEMStructuralRiskV1.INFIMUM_TO_ATTAINMENT,
            {
                "open-interval-halving-has-no-minimizer",
                "positive-lower-bound-candidate-refuters",
                "zero-is-lower-bound",
            },
        ),
        (
            calibration.IFEMStructuralRiskV1.PARAMETER_REVERSAL,
            {
                "nonsymmetric-parameter-order-values",
                "symmetric-part-sylvester-positive-definite",
            },
        ),
    ],
)
def test_strengthened_structural_witnesses_report_executed_invariants(
    risk: calibration.IFEMStructuralRiskV1,
    required_checks: set[str],
) -> None:
    graph, corpus = _corpus()
    report = validation.validate_ifem_structural_witnesses(corpus=corpus, graph=graph)
    result = next(item for item in report.validations if item.risk is risk)

    assert required_checks.issubset(result.machine_check_ids)
    assert result.baseline_dimension_value is True
    assert result.mutant_dimension_value is False
