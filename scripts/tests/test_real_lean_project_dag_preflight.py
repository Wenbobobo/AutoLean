from __future__ import annotations

import os
from pathlib import Path

import pytest

from benchmarks.real_lean_project_dag import load_default_real_lean_project_dag
from scripts import real_lean_project_dag_preflight


def test_source_v2_clean_build_command_is_pinned_and_has_separate_mounts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(real_lean_project_dag_preflight, "_is_windows_host", lambda: False)
    fixture = load_default_real_lean_project_dag()

    command = real_lean_project_dag_preflight.docker_clean_build_command(fixture, tmp_path)

    assert command[:3] == ("docker", "run", "--pull=never")
    assert command[4:6] == ("--network", "none")
    assert "--read-only" in command
    assert real_lean_project_dag_preflight.SOURCE_V2_IMAGE in command
    assert any("dst=/input,readonly" in value for value in command)
    assert any("dst=/output" in value and "readonly" not in value for value in command)
    script = command[-1]
    assert "lean -R /input" in script
    assert "AutoLean/ProjectDagPreflight/Capstone.lean" in script


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
    assert result["declaration_graph_reverse_closure_validated"] is True
    assert result["changed_source_recompiled"] is False
    assert result["oci_verifier_evidence_created"] is False
