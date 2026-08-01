"""Tests for the local-only, digest-only iFEM candidate graph.

The fixtures intentionally contain only synthetic binary bytes and redacted
metadata.  They never reproduce iFEM prose, notebook cells, or source excerpts.
"""

from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

import pytest
from autolean_builder import ifem_candidate_dependency_graph as candidate_graph
from autolean_builder.ifem_prerequisite_census import (
    IFEMDenominatorBindingV1,
    IFEMEnvironmentBindingV1,
    IFEMNodeCensusResultV1,
    IFEMPrerequisiteCensusResultV1,
    IFEMQueryExecutionStateV1,
)
from autolean_contracts import canonical_json_bytes, stable_identifier

from scripts import ifem_candidate_dependency_graph as candidate_graph_script

ROOT = Path(__file__).resolve().parents[2]
_REVISION = "a" * 40
_PUBLIC_GRAPH_PATH = (
    ROOT / "Builder" / "pilots" / "discovery" / "ifem-candidate-dependency-graph.v1.json"
)
_PUBLIC_GRAPH_FILE_SHA256 = "e6442bfe1cc5305a3d26972c23c70a08029f8cde387dc1b58088d918632cd3af"
_PUBLIC_GRAPH_CONTENT_SHA256 = "ba9b246805a4b94ea9f0b02898a772114e495fc8dc12c783b7388b519470a71d"


@dataclass(frozen=True, slots=True)
class _FixturePaths:
    workspace: Path
    staging_root: Path
    staging_manifest: Path
    source_lock: Path
    opening_index: Path
    notebook_index: Path
    discovery_manifest: Path
    census_plan: Path
    census_result: Path
    cache_root: Path


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _git_blob_sha1(value: bytes) -> str:
    return hashlib.sha1(f"blob {len(value)}\0".encode("ascii") + value).hexdigest()


def _write_json(path: Path, payload: object) -> bytes:
    serialized = canonical_json_bytes(payload) + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(serialized)
    return serialized


def _load_json(path: Path) -> dict[str, object]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _install_fixture(tmp_path: Path) -> _FixturePaths:
    workspace = tmp_path / "workspace"
    cache_root = workspace / ".cache" / "references"
    staging_root = workspace / ".cache" / "iFEM-staging"
    staging_manifest = workspace / ".cache" / "iFEM-staging-manifest.v1.json"
    source_lock = cache_root / "ifem-lock" / "source-lock.v1.json"
    opening_index = cache_root / "ifem-lock" / "opening-markdown-source-span-index.v1.json"
    notebook_index = cache_root / "ifem-lock" / "notebook-source-span-index.v1.json"
    discovery_manifest = (
        workspace / "Builder" / "pilots" / "discovery" / "phase-2-active-lanes.v1.json"
    )
    census_plan = (
        workspace
        / "Builder"
        / "pilots"
        / "discovery"
        / "ifem-coercive-prerequisite-census-plan.v1.json"
    )
    census_result = workspace / ".cache" / "ifem-prerequisite-census-not-run.v1.json"

    source_paths = ["intro.md", "module/cells.ipynb"] + [
        f"data/source-{index:02d}.bin" for index in range(2, 13)
    ]
    source_files: list[dict[str, object]] = []
    staging_files: list[dict[str, object]] = []
    for index, relative_path in enumerate(source_paths, start=1):
        # Synthetic binary markers verify source-tree binding without fixture text.
        content = bytes((index, 255 - index))
        output = staging_root.joinpath(*relative_path.split("/"))
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(content)
        digest = _sha256(content)
        source_files.append(
            {
                "path": relative_path,
                "reference_id": f"ifem-fixture-{index:02d}",
                "sha256": digest,
                "size_bytes": len(content),
            }
        )
        staging_files.append(
            {
                "path": relative_path,
                "sha256": digest,
                "size_bytes": len(content),
                "git_blob_sha1": _git_blob_sha1(content),
            }
        )
    license_bytes = b"\x00\xff"
    (staging_root / "LICENSE").write_bytes(license_bytes)
    staging_files.append(
        {
            "path": "LICENSE",
            "sha256": _sha256(license_bytes),
            "size_bytes": len(license_bytes),
            "git_blob_sha1": _git_blob_sha1(license_bytes),
        }
    )
    lock_payload: dict[str, object] = {
        "schema_version": "autolean.ifem-source-lock.v1",
        "state": "acquired_local_only",
        "reference_manifest_state": "candidate_entries_not_yet_tracked",
        "reference_manifest_candidate_sha256": _sha256(b"fixture-manifest"),
        "source": {
            "license": {
                "evidence_url": "fixture-license-evidence",
                "expression": "fixture-license-expression",
                "license_blob_sha1": _git_blob_sha1(license_bytes),
                "license_sha256": _sha256(license_bytes),
                "url": "fixture-license-url",
            },
            "record_url": "fixture-record",
            "resolved_revision": _REVISION,
        },
        "policy": {
            "access_policy": "public_open_access",
            "contract_freeze": "not_authorized",
            "model_egress_policy": "local_only",
            "prover_handoff": "not_authorized",
        },
        "acquisition": {
            "retrieved_at": "2026-07-30T00:00:00+00:00",
            "source_file_count": len(source_files),
            "source_size_bytes": sum(int(item["size_bytes"]) for item in source_files),
        },
        "source_files": source_files,
    }
    lock_bytes = _write_json(source_lock, lock_payload)
    lock_sha256 = _sha256(lock_bytes)
    _write_json(
        staging_manifest,
        {
            "schema_version": "autolean.ifem-connector-staging.v1",
            "repository": "fixture-repository",
            "revision": _REVISION,
            "files": staging_files,
        },
    )
    opening_spans = []
    for index in range(3):
        opening_spans.append(
            {
                "span_id": stable_identifier(
                    "ifem.markdown-source-span", f"{_REVISION}:intro.md:heading:{index}"
                ).model_dump(mode="json"),
                "source_path": "intro.md",
                "source_reference_id": "ifem-fixture-01",
                "source_file_sha256": str(source_files[0]["sha256"]),
                "source_file_index": 0,
                "heading_index": index,
                "heading_level": 1,
                "start_line": index + 1,
                "end_line": index + 1,
                "heading_content_sha256": _sha256(bytes((20 + index,))),
                "heading_character_count": 1,
                "section_content_sha256": _sha256(bytes((30 + index,))),
                "section_character_count": 1,
            }
        )
    _write_json(
        opening_index,
        {
            "schema_version": "autolean.ifem-markdown-source-span-index.v1",
            "artifact_kind": "local_only_source_alignment_index",
            "source_lock": {
                "source_lock_sha256": lock_sha256,
                "source_lock_schema_version": "autolean.ifem-source-lock.v1",
                "source_revision": _REVISION,
                "source_retrieved_at": "2026-07-30T00:00:00+00:00",
                "source_file_count": len(source_files),
                "markdown_file_count": 1,
            },
            "model_egress_policy": "local_only",
            "semantic_review_state": "not_performed",
            "contract_freeze": "not_authorized",
            "prover_handoff": "not_authorized",
            "contains_source_text": False,
            "contains_model_input": False,
            "markdown_heading_count": len(opening_spans),
            "spans": opening_spans,
        },
    )
    notebook_spans = []
    for index in range(22):
        notebook_spans.append(
            {
                "span_id": stable_identifier(
                    "ifem.notebook-source-span", f"{_REVISION}:module/cells.ipynb:cell:{index}"
                ).model_dump(mode="json"),
                "source_path": "module/cells.ipynb",
                "source_reference_id": "ifem-fixture-02",
                "source_file_sha256": str(source_files[1]["sha256"]),
                "source_file_index": 1,
                "cell_index": index,
                "cell_type": "raw",
                "cell_content_sha256": _sha256(bytes((60 + index,))),
                "cell_character_count": 0,
            }
        )
    _write_json(
        notebook_index,
        {
            "schema_version": "autolean.ifem-notebook-source-span-index.v1",
            "artifact_kind": "local_only_source_alignment_index",
            "source_lock": {
                "source_lock_sha256": lock_sha256,
                "source_lock_schema_version": "autolean.ifem-source-lock.v1",
                "source_revision": _REVISION,
                "source_retrieved_at": "2026-07-30T00:00:00+00:00",
                "source_file_count": len(source_files),
                "notebook_file_count": 1,
            },
            "model_egress_policy": "local_only",
            "semantic_review_state": "not_performed",
            "contract_freeze": "not_authorized",
            "prover_handoff": "not_authorized",
            "contains_source_text": False,
            "contains_model_input": False,
            "notebook_cell_count": len(notebook_spans),
            "spans": notebook_spans,
        },
    )
    plan_payload = _load_json(
        ROOT / "Builder" / "pilots" / "discovery" / "ifem-coercive-prerequisite-census-plan.v1.json"
    )
    discovery_payload = _load_json(
        ROOT / "Builder" / "pilots" / "discovery" / "phase-2-active-lanes.v1.json"
    )
    lanes = discovery_payload["lanes"]
    assert isinstance(lanes, list)
    ifem_lane = next(lane for lane in lanes if lane["lane_id"] == "ifem-coercive-galerkin")
    assert isinstance(ifem_lane, dict)
    lane_source = ifem_lane["source"]
    assert isinstance(lane_source, dict)
    lane_source["resolved_revision"] = _REVISION
    lane_source["source_lock_receipt_sha256"] = lock_sha256
    _write_json(discovery_manifest, discovery_payload)
    _write_json(census_plan, plan_payload)
    queries = plan_payload["queries"]
    assert isinstance(queries, list)
    result_payload: dict[str, object] = {
        "schema_version": "autolean.ifem-prerequisite-census-result.v1",
        "protocol": "autolean.builder-ifem-prerequisite-census.v1",
        "execution_state": "not_run",
        "plan_content_sha256": plan_payload["content_sha256"],
        "denominator": plan_payload["denominator"],
        "environment": plan_payload["environment"],
        "query_source_sha256": None,
        "query_observation_sha256": None,
        "node_results": [
            {
                "node_id": query["node_id"],
                "evidence": {
                    "classification": "unknown",
                    "explicit_unknown_reason": "synthetic fixture has not run a query",
                },
            }
            for query in queries
        ],
        "resume_command": ["uv", "run", "python", "scripts/ifem_prerequisite_census.py"],
        "builder_freeze": "forbidden",
        "prover_handoff": "forbidden",
        "coverage_claim": "not_authorized",
    }
    result_for_hash = dict(result_payload)
    result_for_hash.update(
        {
            "execution_state": IFEMQueryExecutionStateV1.NOT_RUN,
            "denominator": IFEMDenominatorBindingV1.model_validate(result_payload["denominator"]),
            "environment": IFEMEnvironmentBindingV1.model_validate(result_payload["environment"]),
            "node_results": tuple(
                IFEMNodeCensusResultV1.model_validate(item)
                for item in result_payload["node_results"]
            ),
            "content_sha256": "0" * 64,
        }
    )
    result_model = IFEMPrerequisiteCensusResultV1.model_construct(**result_for_hash)
    result_payload["content_sha256"] = result_model.computed_content_sha256()
    _write_json(census_result, result_payload)
    return _FixturePaths(
        workspace=workspace,
        staging_root=staging_root,
        staging_manifest=staging_manifest,
        source_lock=source_lock,
        opening_index=opening_index,
        notebook_index=notebook_index,
        discovery_manifest=discovery_manifest,
        census_plan=census_plan,
        census_result=census_result,
        cache_root=cache_root,
    )


def _build(paths: _FixturePaths) -> candidate_graph.IFEMCandidateDependencyGraphV1:
    return candidate_graph.build_ifem_candidate_dependency_graph(
        workspace_root=paths.workspace,
        source_staging_root=paths.staging_root,
        staging_manifest_path=paths.staging_manifest,
        source_lock_path=paths.source_lock,
        opening_markdown_index_path=paths.opening_index,
        notebook_index_path=paths.notebook_index,
        discovery_manifest_path=paths.discovery_manifest,
        census_plan_path=paths.census_plan,
        census_result_path=paths.census_result,
    )


def test_build_is_deterministic_redacted_and_non_authoritative(tmp_path: Path) -> None:
    paths = _install_fixture(tmp_path)
    first = _build(paths)
    second = _build(paths)

    assert first == second
    assert first.content_sha256 == first.computed_content_sha256()
    assert len(first.candidate_nodes) == 25
    assert len(first.candidate_edges) == 49
    assert (
        sum(edge.edge_kind == "declared_candidate_dependency" for edge in first.candidate_edges)
        == 40
    )
    assert (
        sum(
            edge.edge_kind == "heuristic_candidate_declaration_overlap"
            for edge in first.candidate_edges
        )
        == 9
    )
    assert all(
        node.source_anchor_assignment.endswith("not_semantic_mapping")
        for node in first.candidate_nodes
    )
    assert all(not edge.semantic_dependency_claimed for edge in first.candidate_edges)
    assert not first.authority.freeze_allowed
    assert not first.authority.prover_handoff_allowed
    rendered = candidate_graph.render_ifem_candidate_dependency_graph(first)
    assert b"intro.md" not in rendered
    assert b"module/cells.ipynb" not in rendered
    with pytest.raises(candidate_graph.IFEMCandidateDependencyGraphError, match="cannot create"):
        first.freeze_statement()
    with pytest.raises(candidate_graph.IFEMCandidateDependencyGraphError, match="cannot create"):
        first.handoff_to_prover()


def test_rejects_tampered_index_and_staging_escape(tmp_path: Path) -> None:
    paths = _install_fixture(tmp_path)
    opening_payload = _load_json(paths.opening_index)
    source_lock = opening_payload["source_lock"]
    assert isinstance(source_lock, dict)
    source_lock["source_lock_sha256"] = "0" * 64
    _write_json(paths.opening_index, opening_payload)
    with pytest.raises(candidate_graph.IFEMCandidateDependencyGraphError, match="does not bind"):
        _build(paths)

    paths = _install_fixture(tmp_path / "escape")
    staging_payload = _load_json(paths.staging_manifest)
    records = staging_payload["files"]
    assert isinstance(records, list)
    assert isinstance(records[0], dict)
    records[0]["path"] = "../outside.bin"
    _write_json(paths.staging_manifest, staging_payload)
    with pytest.raises(candidate_graph.IFEMCandidateDependencyGraphError, match="invalid path"):
        _build(paths)


def test_discovery_manifest_hash_binds_the_parsed_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _install_fixture(tmp_path)
    expected_sha256 = _sha256(paths.discovery_manifest.read_bytes())
    original_loader = candidate_graph._load_discovery_manifest

    def mutate_after_parse(
        path: Path,
    ) -> tuple[candidate_graph.DiscoveryLaneManifestV1, bytes]:
        manifest, raw = original_loader(path)
        path.write_bytes(raw + b"\n")
        return manifest, raw

    monkeypatch.setattr(candidate_graph, "_load_discovery_manifest", mutate_after_parse)
    graph = _build(paths)

    assert graph.source_binding.discovery_manifest_sha256 == expected_sha256
    assert _sha256(paths.discovery_manifest.read_bytes()) != expected_sha256


def test_rejects_duplicate_json_out_of_workspace_and_model_construct_bypass(tmp_path: Path) -> None:
    paths = _install_fixture(tmp_path)
    paths.source_lock.write_text('{"schema_version":"x","schema_version":"x"}', encoding="utf-8")
    with pytest.raises(
        candidate_graph.IFEMCandidateDependencyGraphError, match="duplicate JSON key"
    ):
        _build(paths)

    paths = _install_fixture(tmp_path / "outside")
    with pytest.raises(candidate_graph.IFEMCandidateDependencyGraphError, match="workspace root"):
        candidate_graph.build_ifem_candidate_dependency_graph(
            workspace_root=paths.workspace,
            source_staging_root=paths.staging_root,
            staging_manifest_path=paths.staging_manifest,
            source_lock_path=Path(__file__),
            opening_markdown_index_path=paths.opening_index,
            notebook_index_path=paths.notebook_index,
            discovery_manifest_path=paths.discovery_manifest,
            census_plan_path=paths.census_plan,
            census_result_path=paths.census_result,
        )

    graph = _build(paths)
    unsafe_payload = graph.model_dump(mode="python")
    authority = unsafe_payload["authority"]
    assert isinstance(authority, dict)
    authority["freeze_allowed"] = True
    unsafe = candidate_graph.IFEMCandidateDependencyGraphV1.model_construct(**unsafe_payload)
    with pytest.raises(
        candidate_graph.IFEMCandidateDependencyGraphError, match="model-constructed"
    ):
        candidate_graph.render_ifem_candidate_dependency_graph(unsafe)

    nested_payload = graph.candidate_nodes[0].model_dump(mode="python")
    nested_payload["ambiguity_flags"] = ("FORGED_SOURCE_MARKER",)
    nested_node = candidate_graph.IFEMCandidateNodeV1.model_construct(**nested_payload)
    nested_graph_payload = graph.model_dump(mode="python")
    nested_graph_payload["candidate_nodes"] = (
        nested_node,
        *graph.candidate_nodes[1:],
    )
    nested_unsafe = candidate_graph.IFEMCandidateDependencyGraphV1.model_construct(
        **nested_graph_payload
    )
    with pytest.warns(UserWarning, match="Pydantic serializer"):
        nested_graph_payload["content_sha256"] = nested_unsafe.computed_content_sha256()
        nested_unsafe = candidate_graph.IFEMCandidateDependencyGraphV1.model_construct(
            **nested_graph_payload
        )
        with pytest.raises(
            candidate_graph.IFEMCandidateDependencyGraphError, match="model-constructed"
        ):
            candidate_graph.render_ifem_candidate_dependency_graph(nested_unsafe)
    with (
        pytest.warns(UserWarning, match="Pydantic serializer"),
        pytest.raises(candidate_graph.IFEMCandidateDependencyGraphError, match="model-constructed"),
    ):
        candidate_graph.write_ifem_candidate_dependency_graph(
            cache_root=paths.cache_root,
            output_path=(
                paths.cache_root / "ifem-lock" / "ifem-candidate-dependency-graph.v1.json"
            ),
            graph=nested_unsafe,
        )


def test_write_and_cli_keep_output_redacted(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    paths = _install_fixture(tmp_path)
    graph = _build(paths)
    output = paths.cache_root / "ifem-lock" / "ifem-candidate-dependency-graph.v1.json"
    candidate_graph.write_ifem_candidate_dependency_graph(
        cache_root=paths.cache_root,
        output_path=output,
        graph=graph,
    )
    assert output.read_bytes() == candidate_graph.render_ifem_candidate_dependency_graph(graph)
    with pytest.raises(candidate_graph.IFEMCandidateDependencyGraphError, match="cache root"):
        candidate_graph.write_ifem_candidate_dependency_graph(
            cache_root=paths.cache_root,
            output_path=tmp_path / "outside" / "ifem-candidate-dependency-graph.v1.json",
            graph=graph,
        )
    with pytest.raises(
        candidate_graph.IFEMCandidateDependencyGraphError, match="canonical artifact"
    ):
        candidate_graph.write_ifem_candidate_dependency_graph(
            cache_root=paths.cache_root,
            output_path=paths.cache_root / "ifem-lock" / "source-lock.v1.json",
            graph=graph,
        )

    exit_code = candidate_graph_script.main(
        [
            "--workspace-root",
            str(paths.workspace),
            "--source-staging-root",
            str(paths.staging_root),
            "--staging-manifest",
            str(paths.staging_manifest),
            "--source-lock",
            str(paths.source_lock),
            "--opening-markdown-index",
            str(paths.opening_index),
            "--notebook-index",
            str(paths.notebook_index),
            "--discovery-manifest",
            str(paths.discovery_manifest),
            "--census-plan",
            str(paths.census_plan),
            "--census-result",
            str(paths.census_result),
            "--cache-root",
            str(paths.cache_root),
            "--output",
            str(output),
        ]
    )
    assert exit_code == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["candidate_node_count"] == 25
    assert summary["candidate_edge_count"] == 49
    assert summary["contains_source_text"] is False
    assert summary["prover_handoff_allowed"] is False


def _load_public_graph(
    path: Path = _PUBLIC_GRAPH_PATH,
    *,
    expected_file_sha256: str = _PUBLIC_GRAPH_FILE_SHA256,
    expected_content_sha256: str = _PUBLIC_GRAPH_CONTENT_SHA256,
) -> candidate_graph.IFEMCandidateDependencyGraphV1:
    return candidate_graph.load_ifem_candidate_dependency_graph(
        path,
        expected_file_sha256=expected_file_sha256,
        expected_content_sha256=expected_content_sha256,
    )


def test_public_graph_loader_binds_exact_canonical_bytes() -> None:
    graph = _load_public_graph()

    assert hashlib.sha256(_PUBLIC_GRAPH_PATH.read_bytes()).hexdigest() == (
        _PUBLIC_GRAPH_FILE_SHA256
    )
    assert graph.content_sha256 == _PUBLIC_GRAPH_CONTENT_SHA256
    assert len(graph.candidate_nodes) == 25
    assert len(graph.candidate_edges) == 49
    assert not graph.contains_source_text
    assert not graph.contains_model_input
    assert not graph.authority.prover_handoff_allowed


def test_public_graph_loader_rejects_file_and_content_hash_drift() -> None:
    with pytest.raises(
        candidate_graph.IFEMCandidateDependencyGraphError, match="file hash drifted"
    ):
        _load_public_graph(expected_file_sha256="0" * 64)
    with pytest.raises(
        candidate_graph.IFEMCandidateDependencyGraphError,
        match="content hash drifted",
    ):
        _load_public_graph(expected_content_sha256="0" * 64)


def test_public_graph_loader_rejects_duplicate_keys_and_noncanonical_bytes(
    tmp_path: Path,
) -> None:
    raw = _PUBLIC_GRAPH_PATH.read_bytes()
    duplicate = (
        raw.removesuffix(b"\n")[:-1]
        + b',"schema_version":"autolean.ifem-candidate-dependency-graph.v1"}'
    )
    duplicate_path = tmp_path / "duplicate.json"
    duplicate_path.write_bytes(duplicate)
    with pytest.raises(candidate_graph.IFEMCandidateDependencyGraphError, match="duplicate JSON"):
        _load_public_graph(
            duplicate_path,
            expected_file_sha256=hashlib.sha256(duplicate).hexdigest(),
        )

    noncanonical = raw + b" "
    noncanonical_path = tmp_path / "noncanonical.json"
    noncanonical_path.write_bytes(noncanonical)
    with pytest.raises(
        candidate_graph.IFEMCandidateDependencyGraphError,
        match="not canonically rendered",
    ):
        _load_public_graph(
            noncanonical_path,
            expected_file_sha256=hashlib.sha256(noncanonical).hexdigest(),
        )


def test_public_graph_loader_rejects_symlink_when_supported(tmp_path: Path) -> None:
    link = tmp_path / "graph-link.json"
    try:
        link.symlink_to(_PUBLIC_GRAPH_PATH)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symbolic links are unavailable on this host: {error}")

    with pytest.raises(
        candidate_graph.IFEMCandidateDependencyGraphError,
        match="unlinked regular file",
    ):
        _load_public_graph(link)


def test_module_has_no_prover_or_control_plane_runtime_import() -> None:
    tree = ast.parse(Path(candidate_graph.__file__).read_text(encoding="utf-8"))
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
