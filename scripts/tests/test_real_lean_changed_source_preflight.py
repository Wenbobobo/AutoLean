from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
from typing import cast

import pytest

from benchmarks.real_lean_project_dag_change import load_default_real_lean_change_case
from scripts import real_lean_changed_source_preflight
from scripts.real_lean_project_dag_preflight import SOURCE_V2_IMAGE


def _write_olean(root: Path, module: str, content: bytes) -> None:
    path = root / PurePosixPath(*module.split(".")).with_suffix(".olean")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def test_changed_snapshots_apply_only_the_manifest_bound_phase(tmp_path: Path) -> None:
    case = load_default_real_lean_change_case()
    upstream = real_lean_changed_source_preflight._materialize_changed_snapshot(
        case, tmp_path / "upstream", successor=False
    )
    successor = real_lean_changed_source_preflight._materialize_changed_snapshot(
        case, tmp_path / "successor", successor=True
    )

    for module in case.baseline.module_topological_order():
        baseline_hash = module.source_sha256
        upstream_hash = upstream.source_hashes[module.module]
        successor_hash = successor.source_hashes[module.module]
        if module.module == case.changed_module:
            expected = case.edits_by_module[module.module].successor_source_sha256
            assert upstream_hash == expected
            assert successor_hash == expected
        elif module.module in case.edits_by_module:
            assert upstream_hash == baseline_hash
            assert successor_hash == case.edits_by_module[module.module].successor_source_sha256
        else:
            assert upstream_hash == baseline_hash
            assert successor_hash == baseline_hash


def test_compile_command_uses_pinned_offline_read_only_snapshots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = load_default_real_lean_change_case()
    snapshot = real_lean_changed_source_preflight._materialize_changed_snapshot(
        case, tmp_path / "successor", successor=True
    )
    reused = tmp_path / "reused"
    output = tmp_path / "output"
    reused.mkdir()
    output.mkdir()
    monkeypatch.setattr(
        real_lean_changed_source_preflight,
        "_container_path",
        lambda path, distribution: str(path.resolve()),
    )
    monkeypatch.setattr(
        real_lean_changed_source_preflight,
        "_docker_prefix",
        lambda distribution: ("docker",),
    )

    command = real_lean_changed_source_preflight.docker_compile_modules_command(
        case,
        snapshot,
        reused,
        output,
        case.expected_module_reverse_import_closure,
    )

    assert command[:3] == ("docker", "run", "--pull=never")
    assert command[4:6] == ("--network", "none")
    assert "--read-only" in command
    assert SOURCE_V2_IMAGE in command
    assert f"type=bind,src={snapshot.source_root.resolve()},dst=/input,readonly" in command
    assert f"type=bind,src={reused.resolve()},dst=/reuse,readonly" in command
    assert f"type=bind,src={output.resolve()},dst=/output" in command
    script = command[-1]
    assert "cp -R /reuse/. /output/" in script
    assert script.count("lean -R /input -o") == 3
    assert "Foundations.lean" not in script


def test_failure_probe_uses_old_relations_with_only_changed_compiled_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = load_default_real_lean_change_case()
    snapshot = real_lean_changed_source_preflight._materialize_changed_snapshot(
        case, tmp_path / "upstream", successor=False
    )
    changed = tmp_path / "changed"
    diagnostic = tmp_path / "diagnostic"
    changed.mkdir()
    diagnostic.mkdir()
    monkeypatch.setattr(
        real_lean_changed_source_preflight,
        "_container_path",
        lambda path, distribution: str(path.resolve()),
    )
    monkeypatch.setattr(
        real_lean_changed_source_preflight,
        "_docker_prefix",
        lambda distribution: ("docker",),
    )

    command = real_lean_changed_source_preflight.docker_expected_failure_command(
        case, snapshot, changed, diagnostic
    )

    assert f"type=bind,src={snapshot.source_root.resolve()},dst=/input,readonly" in command
    assert f"type=bind,src={changed.resolve()},dst=/changed,readonly" in command
    script = command[-1]
    assert "Relations.lean" in script
    assert "Arithmetic.lean" not in script
    assert 'test "$status" -ne 0' in script
    assert "test ! -e /diagnostic/AutoLean/ProjectDagPreflight/Relations.olean" in script


def test_failure_probe_rejects_unrelated_diagnostic(tmp_path: Path) -> None:
    case = load_default_real_lean_change_case()
    (tmp_path / "probe.status").write_text("1\n", encoding="ascii")
    (tmp_path / "probe.stdout").write_text("docker daemon unavailable\n", encoding="utf-8")
    (tmp_path / "probe.stderr").write_text("", encoding="utf-8")

    with pytest.raises(
        real_lean_changed_source_preflight.RealLeanChangedSourcePreflightError,
        match="not the expected old-API incompatibility",
    ):
        real_lean_changed_source_preflight._validate_expected_failure(tmp_path, case)


def test_failure_probe_rejects_a_different_arithmetic_score_type(tmp_path: Path) -> None:
    case = load_default_real_lean_change_case()
    (tmp_path / "probe.status").write_text("1\n", encoding="ascii")
    (tmp_path / "probe.stdout").write_text(
        "/input/AutoLean/ProjectDagPreflight/Relations.lean:21:6: error: "
        "Type mismatch\n  Arithmetic.score\nhas type\n  NatList\n"
        "but is expected to have type\n  Nat\n",
        encoding="utf-8",
    )
    (tmp_path / "probe.stderr").write_text("", encoding="utf-8")

    with pytest.raises(
        real_lean_changed_source_preflight.RealLeanChangedSourcePreflightError,
        match="not the expected old-API incompatibility",
    ):
        real_lean_changed_source_preflight._validate_expected_failure(tmp_path, case)


def test_preflight_records_declared_plan_separately_from_module_rebuild(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = load_default_real_lean_change_case()
    monkeypatch.setattr(
        real_lean_changed_source_preflight,
        "load_default_real_lean_change_case",
        lambda: case,
    )
    monkeypatch.setattr(
        real_lean_changed_source_preflight,
        "docker_clean_build_command",
        lambda fixture, output, distribution: ("baseline", str(output)),
    )
    monkeypatch.setattr(
        real_lean_changed_source_preflight,
        "docker_compile_modules_command",
        lambda case, snapshot, reused, output, modules, distribution: (
            "compile",
            output.name,
        ),
    )
    monkeypatch.setattr(
        real_lean_changed_source_preflight,
        "docker_expected_failure_command",
        lambda case, snapshot, changed, diagnostic, distribution: (
            "failure",
            str(diagnostic),
        ),
    )
    queried_outputs: list[str] = []

    def fake_query(
        query: Path,
        output: Path,
        *,
        distribution: str,
        timeout_seconds: int,
    ) -> str:
        queried_outputs.append(output.name)
        return "Nat" if output.name == "baseline-output" else "(bonus : Nat) → Nat"

    monkeypatch.setattr(real_lean_changed_source_preflight, "_query_canonical_type", fake_query)

    observed_workspace: list[Path] = []

    def fake_run(command: tuple[str, ...], *, timeout_seconds: int, label: str) -> bytes:
        output_root = Path(command[1]) if command[0] == "baseline" else None
        if label == "baseline clean build":
            assert output_root is not None
            observed_workspace.append(output_root.parent)
            for module in case.baseline.module_topological_order():
                _write_olean(output_root, module.module, f"baseline:{module.module}".encode())
        elif label == "upstream API-change build":
            assert command == ("compile", "upstream-output")
            output = observed_workspace[0] / "upstream-output"
            foundation = "AutoLean.ProjectDagPreflight.Foundations"
            _write_olean(output, foundation, f"baseline:{foundation}".encode())
            _write_olean(output, case.changed_module, b"changed:arithmetic")
        elif label == "unchanged downstream failure probe":
            diagnostic = Path(command[1])
            (diagnostic / "probe.status").write_text("1\n", encoding="ascii")
            (diagnostic / "probe.stdout").write_text(
                "/input/AutoLean/ProjectDagPreflight/Relations.lean:21:6: error: "
                "Type mismatch\n  Arithmetic.score\nhas type\n  Nat → Nat\n"
                "but is expected to have type\n  Nat\n",
                encoding="utf-8",
            )
            (diagnostic / "probe.stderr").write_text("", encoding="utf-8")
        elif label == "successor affected-module rebuild":
            assert command == ("compile", "successor-output")
            output = observed_workspace[0] / "successor-output"
            foundation = "AutoLean.ProjectDagPreflight.Foundations"
            _write_olean(output, foundation, f"baseline:{foundation}".encode())
            for module_name in case.expected_module_reverse_import_closure:
                _write_olean(output, module_name, f"successor:{module_name}".encode())
        else:
            raise AssertionError(label)
        return b""

    monkeypatch.setattr(real_lean_changed_source_preflight, "_run_required", fake_run)

    result = real_lean_changed_source_preflight.changed_source_preflight()
    curated = cast(list[str], result["curated_declaration_invalidation_plan"])
    module_plan = cast(list[str], result["module_granularity_rebuild_plan"])
    failure = cast(dict[str, object], result["incomplete_change_failure"])
    unaffected = cast(list[dict[str, object]], result["unaffected_modules"])

    assert queried_outputs == ["baseline-output", "upstream-output"]
    assert result["canonical_elaborated_type_changed"] is True
    assert len(curated) == 11
    assert len(module_plan) == 3
    assert failure["failure_class"] == ("old_downstream_source_incompatible_with_new_upstream_api")
    assert unaffected[0]["recompiled"] is False
    assert result["acceptance_result"] is False
    assert result["contract_evidence_created"] is False
    assert result["oci_verifier_evidence_created"] is False


@pytest.mark.integration
@pytest.mark.lean
@pytest.mark.skipif(
    os.environ.get("AUTOLEAN_RUN_T7_CHANGED_SOURCE_PREFLIGHT") != "1",
    reason="operator-local changed-source Docker preflight is disabled in cross-platform CI",
)
def test_operator_local_changed_source_preflight() -> None:
    case = load_default_real_lean_change_case()
    result = real_lean_changed_source_preflight.changed_source_preflight()
    curated = cast(list[str], result["curated_declaration_invalidation_plan"])
    module_plan = cast(list[str], result["module_granularity_rebuild_plan"])
    failure = cast(dict[str, object], result["incomplete_change_failure"])
    unaffected = cast(list[dict[str, object]], result["unaffected_modules"])
    affected = cast(list[dict[str, object]], result["affected_modules"])

    assert result["status"] == "passed"
    assert result["scope"] == "t7_changed_source_preflight_only"
    assert result["canonical_elaborated_type_changed"] is True
    assert result["baseline_canonical_type_sha256"] == case.expected_baseline_canonical_type_sha256
    assert (
        result["successor_canonical_type_sha256"] == case.expected_successor_canonical_type_sha256
    )
    assert result["change_case_manifest_sha256"] == case.manifest_sha256()
    assert len(curated) == 11
    assert len(module_plan) == 3
    assert failure["failure_class"] == ("old_downstream_source_incompatible_with_new_upstream_api")
    assert failure["lean_exit_code"] == 1
    assert len(unaffected) == 1
    foundation = unaffected[0]
    assert foundation["recompiled"] is False
    assert foundation["reused_from_baseline"] is True
    assert (
        foundation["baseline_olean_sha256"]
        == foundation["reused_olean_sha256"]
        == foundation["upstream_reused_olean_sha256"]
        == foundation["successor_reused_olean_sha256"]
    )
    assert len(affected) == 3
    assert {record["module"] for record in affected} == set(
        case.expected_module_reverse_import_closure
    )
    for record in affected:
        assert record["freshly_recompiled"] is True
        assert record["baseline_olean_sha256"] != record["successor_olean_sha256"]
    assert result["acceptance_result"] is False
