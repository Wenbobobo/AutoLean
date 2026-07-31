"""Regression coverage for documented direct-file script invocations."""

from __future__ import annotations

import os
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_SCRIPTS = (
    "authoritative_preflight.py",
    "fate_execution_preflight.py",
    "ifem_pilot_readiness.py",
    "ifem_structural_role_corpus.py",
    "real_lean_module_build_preflight.py",
)


def test_root_uv_project_installs_the_operator_workspace_closure() -> None:
    project = tomllib.loads((_REPOSITORY_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    dependencies = project["project"]["dependencies"]
    sources = project["tool"]["uv"]["sources"]

    assert "autolean-benchmarks>=0.1.0" in dependencies
    assert sources["autolean-benchmarks"] == {"workspace": True}

    lock = tomllib.loads((_REPOSITORY_ROOT / "uv.lock").read_text(encoding="utf-8"))
    workspace = next(
        package for package in lock["package"] if package["name"] == "autolean-workspace"
    )
    assert {dependency["name"] for dependency in workspace["dependencies"]} == {
        "autolean-benchmarks"
    }


@pytest.mark.parametrize("script_name", _SCRIPTS)
def test_documented_direct_script_help_resolves_workspace_imports(
    script_name: str,
    tmp_path: Path,
) -> None:
    """A direct script path must work without an inherited repository PYTHONPATH."""

    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    completed = subprocess.run(
        (sys.executable, str(_REPOSITORY_ROOT / "scripts" / script_name), "--help"),
        check=False,
        cwd=tmp_path,
        capture_output=True,
        env=environment,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert "usage:" in completed.stdout
