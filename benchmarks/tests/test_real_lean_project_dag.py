from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from benchmarks.real_lean_project_dag import (
    RealLeanProjectDagError,
    load_default_real_lean_project_dag,
    load_real_lean_project_dag,
)


def _copied_fixture(tmp_path: Path) -> tuple[Path, dict[str, object]]:
    source = Path(__file__).parents[1] / "project_dag"
    destination = tmp_path / "project_dag"
    shutil.copytree(source, destination)
    manifest = destination / "real-lean-content-manifest.v1.json"
    return manifest, json.loads(manifest.read_text(encoding="utf-8"))


def _write_manifest(path: Path, document: dict[str, object]) -> None:
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def test_real_lean_content_fixture_binds_twenty_unique_declarations() -> None:
    graph = load_default_real_lean_project_dag()

    assert len(graph.modules) == 4
    assert len(graph.declarations) == 20
    assert [module.module for module in graph.module_topological_order()] == [
        "AutoLean.ProjectDagPreflight.Foundations",
        "AutoLean.ProjectDagPreflight.Arithmetic",
        "AutoLean.ProjectDagPreflight.Relations",
        "AutoLean.ProjectDagPreflight.Capstone",
    ]
    assert len({item.declaration for item in graph.declarations}) == 20


def test_loaded_manifest_hash_remains_bound_to_the_exact_parsed_bytes(tmp_path: Path) -> None:
    manifest, _ = _copied_fixture(tmp_path)
    parsed_bytes = manifest.read_bytes()
    fixture = load_real_lean_project_dag(manifest)
    captured = hashlib.sha256(parsed_bytes).hexdigest()

    manifest.write_bytes(parsed_bytes + b" ")

    assert fixture.manifest_sha256() == captured
    assert fixture.manifest_sha256() != hashlib.sha256(manifest.read_bytes()).hexdigest()


def test_real_lean_content_fixture_rejects_source_hash_drift(tmp_path: Path) -> None:
    manifest, _ = _copied_fixture(tmp_path)
    source = manifest.parent / "lean" / "AutoLean" / "ProjectDagPreflight" / "Foundations.lean"
    source.write_text(source.read_text(encoding="utf-8") + "\n-- drift\n", encoding="utf-8")

    with pytest.raises(RealLeanProjectDagError, match="source hash"):
        load_real_lean_project_dag(manifest)


def test_real_lean_content_fixture_rejects_import_mapping_drift(tmp_path: Path) -> None:
    manifest, document = _copied_fixture(tmp_path)
    source = manifest.parent / "lean" / "AutoLean" / "ProjectDagPreflight" / "Arithmetic.lean"
    source.write_text(
        source.read_text(encoding="utf-8").replace(
            "import AutoLean.ProjectDagPreflight.Foundations\n\n", ""
        ),
        encoding="utf-8",
    )
    modules = document["modules"]
    assert isinstance(modules, list)
    arithmetic = modules[1]
    assert isinstance(arithmetic, dict)
    arithmetic["source_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
    _write_manifest(manifest, document)

    with pytest.raises(RealLeanProjectDagError, match="source imports"):
        load_real_lean_project_dag(manifest)


def test_real_lean_content_fixture_rejects_duplicate_source_declaration(tmp_path: Path) -> None:
    manifest, document = _copied_fixture(tmp_path)
    source = manifest.parent / "lean" / "AutoLean" / "ProjectDagPreflight" / "Foundations.lean"
    source.write_text(
        source.read_text(encoding="utf-8").replace(
            "\nend AutoLean.ProjectDagPreflight.Foundations\n",
            "\ndef seed : Nat := 3\n\nend AutoLean.ProjectDagPreflight.Foundations\n",
        ),
        encoding="utf-8",
    )
    modules = document["modules"]
    assert isinstance(modules, list)
    foundations = modules[0]
    assert isinstance(foundations, dict)
    foundations["source_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
    _write_manifest(manifest, document)

    with pytest.raises(RealLeanProjectDagError, match="duplicate identity"):
        load_real_lean_project_dag(manifest)


def test_real_lean_content_dependency_and_reverse_closures_are_exact() -> None:
    graph = load_default_real_lean_project_dag()

    closure = {item.node_id for item in graph.dependency_closure(frozenset({"capstone.capstone"}))}
    assert {
        "foundations.seed",
        "arithmetic.score",
        "relations.score-certificate",
        "capstone.capstone",
    }.issubset(closure)
    assert "relations.seed-is-bounded" not in closure

    affected = {item.node_id for item in graph.affected_by(frozenset({"arithmetic.score"}))}
    assert {
        "arithmetic.score",
        "relations.exact-score",
        "relations.score-certificate",
        "capstone.capstone",
    }.issubset(affected)
    assert "foundations.next-seed" not in affected
