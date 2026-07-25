from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from benchmarks.real_lean_project_dag_change import (
    RealLeanChangeCaseError,
    load_default_real_lean_change_case,
    load_real_lean_change_case,
)


def _copied_case(tmp_path: Path) -> tuple[Path, dict[str, object]]:
    source = Path(__file__).parents[1] / "project_dag"
    destination = tmp_path / "project_dag"
    shutil.copytree(source, destination)
    manifest = destination / "real-lean-change-case.v1.json"
    return manifest, json.loads(manifest.read_text(encoding="utf-8"))


def _write_manifest(path: Path, document: dict[str, object]) -> None:
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def test_change_case_binds_exact_curated_and_module_reverse_closures() -> None:
    case = load_default_real_lean_change_case()

    assert case.changed_declaration_ids == ("arithmetic.score",)
    assert case.expected_declaration_reverse_closure == (
        "arithmetic.score",
        "capstone.target-nat",
        "relations.exact-score",
        "relations.positive-score",
        "relations.seed-is-bounded",
        "capstone.target-is-fifteen",
        "capstone.target-is-positive",
        "relations.score-certificate",
        "relations.score-is-nonzero",
        "capstone.final-certificate",
        "capstone.capstone",
    )
    assert case.expected_module_reverse_import_closure == (
        "AutoLean.ProjectDagPreflight.Arithmetic",
        "AutoLean.ProjectDagPreflight.Relations",
        "AutoLean.ProjectDagPreflight.Capstone",
    )
    assert case.failure_probe_module == "AutoLean.ProjectDagPreflight.Relations"
    assert (
        case.expected_baseline_canonical_type_sha256
        != case.expected_successor_canonical_type_sha256
    )


def test_change_case_replacements_are_unique_and_bind_successor_hashes() -> None:
    case = load_default_real_lean_change_case()

    for edit in case.edits:
        baseline = case.baseline.source_path(
            case.baseline.modules_by_name[edit.module]
        ).read_bytes()
        successor = edit.apply(baseline)

        assert all(
            baseline.decode("utf-8").count(replacement.old) == 1
            for replacement in edit.replacements
        )
        assert edit.successor_source_sha256 != edit.baseline_source_sha256
        assert successor != baseline


def test_loaded_case_hash_remains_bound_to_the_parsed_manifest_bytes(
    tmp_path: Path,
) -> None:
    manifest, _ = _copied_case(tmp_path)
    parsed_bytes = manifest.read_bytes()
    case = load_real_lean_change_case(manifest)
    captured = hashlib.sha256(parsed_bytes).hexdigest()

    manifest.write_bytes(parsed_bytes + b" ")

    assert case.manifest_sha256() == captured
    assert case.manifest_sha256() != hashlib.sha256(manifest.read_bytes()).hexdigest()


def test_change_case_rejects_declaration_reverse_closure_drift(tmp_path: Path) -> None:
    manifest, document = _copied_case(tmp_path)
    closure = document["expected_declaration_reverse_closure"]
    assert isinstance(closure, list)
    closure.pop()
    _write_manifest(manifest, document)

    with pytest.raises(RealLeanChangeCaseError, match="declaration reverse closure"):
        load_real_lean_change_case(manifest)


def test_change_case_rejects_module_reverse_import_closure_drift(tmp_path: Path) -> None:
    manifest, document = _copied_case(tmp_path)
    closure = document["expected_module_reverse_import_closure"]
    assert isinstance(closure, list)
    closure.reverse()
    _write_manifest(manifest, document)

    with pytest.raises(RealLeanChangeCaseError, match="module reverse-import closure"):
        load_real_lean_change_case(manifest)


def test_change_case_rejects_broad_multi_occurrence_replacement(tmp_path: Path) -> None:
    manifest, document = _copied_case(tmp_path)
    edits = document["edits"]
    assert isinstance(edits, list)
    relations = edits[1]
    assert isinstance(relations, dict)
    replacements = relations["replacements"]
    assert isinstance(replacements, list)
    replacement = replacements[0]
    assert isinstance(replacement, dict)
    replacement["expected_occurrences"] = 2
    _write_manifest(manifest, document)

    with pytest.raises(RealLeanChangeCaseError, match="exactly once"):
        load_real_lean_change_case(manifest)


def test_change_case_rejects_successor_source_hash_drift(tmp_path: Path) -> None:
    manifest, document = _copied_case(tmp_path)
    edits = document["edits"]
    assert isinstance(edits, list)
    arithmetic = edits[0]
    assert isinstance(arithmetic, dict)
    arithmetic["successor_source_sha256"] = "f" * 64
    _write_manifest(manifest, document)

    with pytest.raises(RealLeanChangeCaseError, match="successor hash"):
        load_real_lean_change_case(manifest)


def test_change_case_rejects_equal_elaborated_type_hashes(tmp_path: Path) -> None:
    manifest, document = _copied_case(tmp_path)
    document["expected_successor_canonical_type_sha256"] = document[
        "expected_baseline_canonical_type_sha256"
    ]
    _write_manifest(manifest, document)

    with pytest.raises(RealLeanChangeCaseError, match="distinct canonical type"):
        load_real_lean_change_case(manifest)
