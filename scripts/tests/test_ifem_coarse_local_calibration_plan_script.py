"""Direct-entry-point coverage for the fixed iFEM coarse calibration plan CLI."""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from autolean_builder import ifem_coarse_local_calibration_plan as coarse_plan

from scripts import ifem_coarse_local_calibration_plan as cli

ROOT = Path(__file__).resolve().parents[2]
PLAN_PATH = (
    ROOT
    / "Builder"
    / "pilots"
    / "ifem-source-alignment"
    / "ifem-coarse-local-calibration-plan.v1.json"
)


@pytest.mark.parametrize("action", ("materialize", "render", "verify"))
def test_cli_actions_emit_only_the_same_canonical_non_executable_plan(
    action: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    plan = coarse_plan.load_ifem_coarse_local_calibration_plan(PLAN_PATH)
    monkeypatch.setattr(
        cli,
        "materialize_ifem_coarse_local_calibration_plan_once",
        lambda *_args, **_kwargs: plan,
    )
    monkeypatch.setattr(
        cli,
        "build_current_ifem_coarse_local_calibration_plan",
        lambda **_kwargs: plan,
    )
    monkeypatch.setattr(
        cli,
        "load_ifem_coarse_local_calibration_plan",
        lambda _path: plan,
    )
    monkeypatch.setattr(
        cli,
        "verify_ifem_coarse_local_calibration_plan_against_current_inputs",
        lambda *_args, **_kwargs: None,
    )

    assert cli.main([action]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out.encode("utf-8") == PLAN_PATH.read_bytes()
    document = json.loads(captured.out)
    assert document["source_text_present"] is False
    assert document["model_input_present"] is False
    assert document["executable"] is False
    assert document["blockers"] == [
        "rights_decision_missing",
        "local_model_processing_not_authorized",
    ]


def test_cli_fails_closed_without_printing_source_or_local_paths(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def reject(**_kwargs: object) -> coarse_plan.IFEMCoarseLocalCalibrationPlanV1:
        raise coarse_plan.IFEMCoarseLocalCalibrationPlanError("current binding mismatch")

    monkeypatch.setattr(cli, "build_current_ifem_coarse_local_calibration_plan", reject)

    assert cli.main(["render"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "current binding mismatch" in captured.err
    assert "primal/" not in captured.err
    assert ".cache" not in captured.err
    assert "AppData" not in captured.err


@pytest.mark.parametrize(
    "arguments",
    (
        ["render", "--cache-root", "elsewhere"],
        ["render", "--out", "elsewhere.json"],
        ["render", "--provider-id", "model"],
        ["render", "--endpoint-url", "https://example.invalid"],
        ["verify", "--plan", "different.json"],
    ),
)
def test_cli_rejects_arbitrary_path_model_and_output_options(arguments: list[str]) -> None:
    with pytest.raises(SystemExit) as rejected:
        cli.main(arguments)
    assert rejected.value.code == 2


def test_direct_script_help_resolves_workspace_imports(tmp_path: Path) -> None:
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    completed = subprocess.run(
        (
            sys.executable,
            str(ROOT / "scripts" / "ifem_coarse_local_calibration_plan.py"),
            "--help",
        ),
        check=False,
        cwd=tmp_path,
        capture_output=True,
        env=environment,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert "{materialize,render,verify}" in completed.stdout
    assert "--cache-root" not in completed.stdout
    assert "--out" not in completed.stdout


def test_cli_is_offline_fixed_path_and_has_no_execution_dependency() -> None:
    assert cli.DEFAULT_PLAN_PATH == PLAN_PATH
    assert cli.DEFAULT_CACHE_ROOT == ROOT / ".cache" / "references"

    script_path = Path(cli.__file__)
    tree = ast.parse(script_path.read_text(encoding="utf-8"))
    imports = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imports.update(
        node.module.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    )
    assert imports.isdisjoint({"Prover", "http", "httpx", "openai", "requests", "socket", "urllib"})
