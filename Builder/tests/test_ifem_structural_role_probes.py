"""Tests for the evaluator-side iFEM structural role probe corpus."""

from __future__ import annotations

import ast
import hashlib
from collections import Counter
from pathlib import Path
from typing import cast

import pytest
from autolean_builder import ifem_candidate_dependency_graph as candidate_graph
from autolean_builder import ifem_structural_calibration as calibration
from autolean_builder import ifem_structural_role_probes as probes
from autolean_contracts import canonical_json_bytes, stable_identifier

_ROOT = Path(__file__).resolve().parents[2]
_PUBLIC_CORPUS_PATH = (
    _ROOT / "Builder" / "pilots" / "discovery" / "ifem-structural-role-probe-corpus.v1.json"
)
_PUBLIC_CORPUS_FILE_SHA256 = "b0b232a7cd062b47bf5b07efb3158bd068d1988e5285cd0fd964a5855856f617"
_PUBLIC_CORPUS_CONTENT_SHA256 = "a449b48f3544dc7dfe748eb76abe423e0a6c66372dd1f58c5cdb7221b1d59fb8"


def _load_public_corpus(
    path: Path = _PUBLIC_CORPUS_PATH,
    *,
    expected_file_sha256: str = _PUBLIC_CORPUS_FILE_SHA256,
    expected_content_sha256: str = _PUBLIC_CORPUS_CONTENT_SHA256,
) -> probes.IFEMStructuralRoleProbeCorpusV1:
    return probes.load_ifem_structural_role_probe_corpus(
        path,
        expected_file_sha256=expected_file_sha256,
        expected_content_sha256=expected_content_sha256,
    )


def _write_public_corpus_copy(tmp_path: Path, content: bytes) -> Path:
    path = tmp_path / _PUBLIC_CORPUS_PATH.name
    path.write_bytes(content)
    return path


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
                "ifem.markdown-source-span", f"project-synthetic-role-probe:{index}"
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


def _corpus() -> tuple[
    candidate_graph.IFEMCandidateDependencyGraphV1,
    calibration.IFEMStructuralCalibrationCatalogV1,
    probes.IFEMStructuralRoleProbeCorpusV1,
]:
    graph = _valid_graph()
    catalog = calibration.build_ifem_structural_calibration_catalog(graph)
    corpus = probes.build_ifem_structural_role_probe_corpus(catalog=catalog, graph=graph)
    return graph, catalog, corpus


def test_probe_corpus_is_deterministic_complete_paired_and_non_authoritative() -> None:
    graph, catalog, first = _corpus()
    second = probes.build_ifem_structural_role_probe_corpus(catalog=catalog, graph=graph)

    assert first == second
    assert first.content_sha256 == first.computed_content_sha256()
    assert first.catalog == catalog
    assert first.candidate_graph_content_sha256 == graph.content_sha256
    assert len(first.pairs) == len(catalog.cases) == 16
    assert {pair.catalog_case_id for pair in first.pairs} == {
        case.case_id for case in catalog.cases
    }
    assert Counter(pair.risk for pair in first.pairs) == Counter(
        {risk: 2 for risk in calibration.IFEMStructuralRiskV1}
    )
    assert Counter(pair.probe_role for pair in first.pairs) == Counter(
        {
            probes.IFEMStructuralProbeRoleV1.STATEMENT_FORMALIZER: 8,
            probes.IFEMStructuralProbeRoleV1.FIDELITY_REVIEWER: 4,
            probes.IFEMStructuralProbeRoleV1.CHEATING_SUPERVISOR: 4,
        }
    )

    commitments_by_risk: dict[calibration.IFEMStructuralRiskV1, set[str]] = {
        risk: set() for risk in calibration.IFEMStructuralRiskV1
    }
    for pair in first.pairs:
        baseline = pair.baseline.model_dump(mode="json")
        mutant = pair.mutant.model_dump(mode="json")
        changed = tuple(key for key in baseline if baseline[key] != mutant[key])
        assert changed == (pair.changed_slot.value,)
        assert pair.baseline.content_sha256 != pair.mutant.content_sha256
        assert pair.pair_sha256 == pair.computed_pair_sha256()
        commitments_by_risk[pair.risk].add(pair.witness.commitment_sha256)
        assert not pair.witness.mathematical_validation_claimed
        assert not pair.authority.model_input_created
        assert not pair.authority.model_egress_allowed
    assert all(len(commitments) == 1 for commitments in commitments_by_risk.values())
    assert len({next(iter(values)) for values in commitments_by_risk.values()}) == 8

    assert not first.contains_source_text
    assert not first.contains_source_excerpt
    assert not first.contains_lean_statement
    assert not first.contains_model_input
    assert not first.contains_provider_request
    assert not first.contains_benchmark_matrix
    assert not first.authority.mathematical_witness_validated
    assert not first.authority.freeze_allowed
    assert not first.authority.prover_handoff_allowed
    rendered = probes.render_ifem_structural_role_probe_corpus(first)
    assert rendered == canonical_json_bytes(first.model_dump(mode="json")) + b"\n"
    for forbidden_key in (
        b'"input_payload"',
        b'"expected_output"',
        b'"oracle"',
        b'"prompt"',
        b'"provider_id"',
        b'"model_id"',
    ):
        assert forbidden_key not in rendered

    for operation in (
        first.create_model_input,
        first.authorize_model_egress,
        first.create_benchmark_matrix,
        first.freeze_statement,
        first.handoff_to_prover,
    ):
        with pytest.raises(probes.IFEMStructuralRoleProbeError, match="cannot directly create"):
            operation()


def test_builder_reconstructs_exact_catalog_from_supplied_graph() -> None:
    graph, catalog, _corpus_value = _corpus()
    changed_graph_payload = graph.model_dump(mode="python")
    source_binding = cast(dict[str, object], changed_graph_payload["source_binding"])
    source_binding["discovery_manifest_sha256"] = "2" * 64
    changed_graph = _revalidated_graph_from_payload(changed_graph_payload)

    with pytest.raises(probes.IFEMStructuralRoleProbeError, match="exact catalog rebuilt"):
        probes.build_ifem_structural_role_probe_corpus(
            catalog=catalog,
            graph=changed_graph,
        )

    catalog_payload = catalog.model_dump(mode="python")
    authority_payload = cast(dict[str, object], catalog_payload["authority"])
    authority_payload["external_model_egress_allowed"] = True
    catalog_payload["authority"] = calibration.IFEMStructuralCalibrationAuthorityV1.model_construct(
        **authority_payload
    )
    unsafe_catalog = calibration.IFEMStructuralCalibrationCatalogV1.model_construct(
        **catalog_payload
    )
    with pytest.raises(probes.IFEMStructuralRoleProbeError, match="revalidated structural"):
        probes.build_ifem_structural_role_probe_corpus(
            catalog=unsafe_catalog,
            graph=graph,
        )

    graph_payload = graph.model_dump(mode="python")
    graph_authority = cast(dict[str, object], graph_payload["authority"])
    graph_authority["source_egress_allowed"] = True
    graph_payload["authority"] = (
        candidate_graph.IFEMCandidateGraphAuthorityBoundaryV1.model_construct(**graph_authority)
    )
    unsafe_graph = candidate_graph.IFEMCandidateDependencyGraphV1.model_construct(**graph_payload)
    with pytest.raises(probes.IFEMStructuralRoleProbeError, match="revalidated candidate graph"):
        probes.build_ifem_structural_role_probe_corpus(
            catalog=catalog,
            graph=unsafe_graph,
        )


def test_render_rejects_pair_role_witness_and_authority_tampering() -> None:
    _graph, _catalog, corpus = _corpus()
    pair = corpus.pairs[0]

    pair_payload = pair.model_dump(mode="python")
    mutant_payload = pair.mutant.model_dump(mode="python")
    mutant_payload["antecedent_status"] = "contradictory"
    pair_payload["mutant"] = probes.IFEMStructuralProbeSignatureV1.model_validate(mutant_payload)
    unsafe_pair = probes.IFEMStructuralRoleProbePairV1.model_construct(**pair_payload)
    corpus_payload = corpus.model_dump(mode="python")
    pairs = list(cast(tuple[object, ...], corpus_payload["pairs"]))
    pairs[0] = unsafe_pair
    corpus_payload["pairs"] = tuple(pairs)
    unsafe_corpus = probes.IFEMStructuralRoleProbeCorpusV1.model_construct(**corpus_payload)
    with pytest.raises(probes.IFEMStructuralRoleProbeError, match="model-constructed"):
        probes.render_ifem_structural_role_probe_corpus(unsafe_corpus)

    mapping_payload = corpus.role_mappings[0].model_dump(mode="python")
    mapping_payload["probe_role"] = probes.IFEMStructuralProbeRoleV1.CHEATING_SUPERVISOR
    mappings = list(corpus.role_mappings)
    mappings[0] = probes.IFEMStructuralProbeRoleMappingV1.model_construct(**mapping_payload)
    role_payload = corpus.model_dump(mode="python")
    role_payload["role_mappings"] = tuple(mappings)
    unsafe_roles = probes.IFEMStructuralRoleProbeCorpusV1.model_construct(**role_payload)
    with pytest.raises(probes.IFEMStructuralRoleProbeError, match="model-constructed"):
        probes.render_ifem_structural_role_probe_corpus(unsafe_roles)

    witness_payload = pair.witness.model_dump(mode="python")
    witness_payload["commitment_sha256"] = "0" * 64
    witness_pair_payload = pair.model_dump(mode="python")
    witness_pair_payload["witness"] = probes.IFEMStructuralWitnessCommitmentV1.model_construct(
        **witness_payload
    )
    witness_pair = probes.IFEMStructuralRoleProbePairV1.model_construct(**witness_pair_payload)
    witness_corpus_payload = corpus.model_dump(mode="python")
    witness_pairs = list(cast(tuple[object, ...], witness_corpus_payload["pairs"]))
    witness_pairs[0] = witness_pair
    witness_corpus_payload["pairs"] = tuple(witness_pairs)
    unsafe_witness = probes.IFEMStructuralRoleProbeCorpusV1.model_construct(
        **witness_corpus_payload
    )
    with pytest.raises(probes.IFEMStructuralRoleProbeError, match="model-constructed"):
        probes.render_ifem_structural_role_probe_corpus(unsafe_witness)

    authority_payload = corpus.authority.model_dump(mode="python")
    authority_payload["benchmark_matrix_created"] = True
    authority_corpus_payload = corpus.model_dump(mode="python")
    authority_corpus_payload["authority"] = (
        probes.IFEMStructuralRoleProbeAuthorityV1.model_construct(**authority_payload)
    )
    unsafe_authority = probes.IFEMStructuralRoleProbeCorpusV1.model_construct(
        **authority_corpus_payload
    )
    with pytest.raises(probes.IFEMStructuralRoleProbeError, match="model-constructed"):
        probes.render_ifem_structural_role_probe_corpus(unsafe_authority)


def test_role_probe_module_has_no_runtime_or_provider_dependency() -> None:
    module_path = Path(cast(str, probes.__file__))
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


def test_public_corpus_loader_binds_the_exact_tracked_bytes_and_content() -> None:
    corpus = _load_public_corpus()
    file_sha256 = hashlib.sha256(_PUBLIC_CORPUS_PATH.read_bytes()).hexdigest()

    assert corpus.content_sha256 == _PUBLIC_CORPUS_CONTENT_SHA256
    assert corpus.computed_content_sha256() == _PUBLIC_CORPUS_CONTENT_SHA256
    assert file_sha256 == _PUBLIC_CORPUS_FILE_SHA256


def test_public_corpus_loader_rejects_file_hash_drift() -> None:
    with pytest.raises(probes.IFEMStructuralRoleProbeError, match="file hash drifted"):
        _load_public_corpus(expected_file_sha256="0" * 64)


def test_public_corpus_loader_rejects_content_hash_drift() -> None:
    with pytest.raises(probes.IFEMStructuralRoleProbeError, match="content hash drifted"):
        _load_public_corpus(expected_content_sha256="0" * 64)


def test_public_corpus_loader_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    raw = _PUBLIC_CORPUS_PATH.read_bytes()
    duplicate_key_bytes = (
        raw.removesuffix(b"\n")[:-1]
        + b',"schema_version":"autolean.ifem-structural-role-probe-corpus.v1"}'
    )
    path = _write_public_corpus_copy(tmp_path, duplicate_key_bytes)

    with pytest.raises(probes.IFEMStructuralRoleProbeError, match="duplicate corpus JSON key"):
        _load_public_corpus(
            path,
            expected_file_sha256=hashlib.sha256(duplicate_key_bytes).hexdigest(),
        )


def test_public_corpus_loader_rejects_noncanonical_bytes(tmp_path: Path) -> None:
    noncanonical_bytes = _PUBLIC_CORPUS_PATH.read_bytes() + b" "
    path = _write_public_corpus_copy(tmp_path, noncanonical_bytes)

    with pytest.raises(probes.IFEMStructuralRoleProbeError, match="not canonically rendered"):
        _load_public_corpus(
            path,
            expected_file_sha256=hashlib.sha256(noncanonical_bytes).hexdigest(),
        )


def test_public_corpus_loader_rejects_symlink_when_supported(tmp_path: Path) -> None:
    target = _write_public_corpus_copy(tmp_path, _PUBLIC_CORPUS_PATH.read_bytes())
    link = tmp_path / "public-corpus-link.json"
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symbolic links are unavailable on this host: {error}")

    with pytest.raises(probes.IFEMStructuralRoleProbeError, match="unlinked regular file"):
        _load_public_corpus(link)
