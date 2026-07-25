from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path, PurePosixPath

import pytest

from benchmarks.real_lean_project_dag import (
    RealLeanProjectDagV1,
    load_default_real_lean_project_dag,
    load_real_lean_project_dag,
)
from scripts import real_lean_project_dag_preflight


def _copied_fixture(tmp_path: Path) -> RealLeanProjectDagV1:
    source = Path(__file__).parents[2] / "benchmarks" / "project_dag"
    destination = tmp_path / "project_dag"
    shutil.copytree(source, destination)
    return load_real_lean_project_dag(destination / "real-lean-content-manifest.v1.json")


def test_source_v2_clean_build_command_mounts_only_a_revalidated_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(real_lean_project_dag_preflight, "_is_windows_host", lambda: False)
    live_fixture = load_default_real_lean_project_dag()
    snapshot = real_lean_project_dag_preflight._snapshot_fixture(
        live_fixture, tmp_path / "fixture-snapshot"
    )

    command = real_lean_project_dag_preflight.docker_clean_build_command(
        snapshot, tmp_path / "output"
    )

    assert command[:3] == ("docker", "run", "--pull=never")
    assert command[4:6] == ("--network", "none")
    assert "--read-only" in command
    assert real_lean_project_dag_preflight.SOURCE_V2_IMAGE in command
    snapshot_mount = (
        f"type=bind,src={(snapshot.root / snapshot.source_root).resolve()},dst=/input,readonly"
    )
    live_mount = (
        f"type=bind,src={(live_fixture.root / live_fixture.source_root).resolve()},"
        "dst=/input,readonly"
    )
    assert snapshot_mount in command
    assert live_mount not in command
    assert any("dst=/output" in value and "readonly" not in value for value in command)
    script = command[-1]
    assert "lean -R /input" in script
    assert "AutoLean/ProjectDagPreflight/Capstone.lean" in script
    copied_files = {
        path.relative_to(snapshot.root).as_posix()
        for path in snapshot.root.rglob("*")
        if path.is_file()
    }
    assert copied_files == {
        snapshot.manifest_path.relative_to(snapshot.root).as_posix(),
        *(module.file for module in snapshot.modules),
    }


def test_clean_build_hashes_and_compiles_the_snapshot_not_the_live_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live_fixture = _copied_fixture(tmp_path)
    expected_snapshot_hash = live_fixture.manifest_sha256()
    observed_snapshots: list[RealLeanProjectDagV1] = []
    observed_snapshot_hashes: list[str] = []

    def fake_command(
        fixture: RealLeanProjectDagV1,
        output_root: Path,
        *,
        distribution: str,
    ) -> tuple[str, ...]:
        assert distribution == real_lean_project_dag_preflight.DEFAULT_WSL_DISTRIBUTION
        observed_snapshots.append(fixture)
        observed_snapshot_hashes.append(fixture.manifest_sha256())
        for module in fixture.module_topological_order():
            output = output_root / PurePosixPath(*module.module.split(".")).with_suffix(".olean")
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(module.module.encode("utf-8"))
        live_fixture.manifest_path.write_bytes(live_fixture.manifest_path.read_bytes() + b" ")
        return ("docker", "run", "--pull=never")

    def successful_run(
        command: tuple[str, ...], *, timeout_seconds: int
    ) -> subprocess.CompletedProcess[bytes]:
        assert command == ("docker", "run", "--pull=never")
        assert timeout_seconds == 300
        return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(
        real_lean_project_dag_preflight,
        "load_default_real_lean_project_dag",
        lambda: live_fixture,
    )
    monkeypatch.setattr(real_lean_project_dag_preflight, "docker_clean_build_command", fake_command)
    monkeypatch.setattr(real_lean_project_dag_preflight, "_run", successful_run)

    result = real_lean_project_dag_preflight.clean_build()

    assert len(observed_snapshots) == 1
    assert observed_snapshots[0].root != live_fixture.root
    assert observed_snapshot_hashes == [expected_snapshot_hash]
    assert result["fixture_manifest_sha256"] == expected_snapshot_hash
    assert (
        result["fixture_manifest_sha256"]
        != hashlib.sha256(live_fixture.manifest_path.read_bytes()).hexdigest()
    )


@pytest.mark.integration
@pytest.mark.lean
@pytest.mark.skipif(
    os.environ.get("AUTOLEAN_RUN_T7_PREFLIGHT") != "1",
    reason="operator-local source-v2 Docker preflight is disabled in cross-platform CI",
)
def test_operator_local_source_v2_clean_build() -> None:
    result = real_lean_project_dag_preflight.clean_build()

    assert result["status"] == "passed"
    assert result["scope"] == "t7_preflight_only"
    assert result["acceptance_result"] is False
    assert result["declared_content_graph_reverse_closure_validated"] is True
    assert result["changed_source_recompiled"] is False
    assert result["oci_verifier_evidence_created"] is False
