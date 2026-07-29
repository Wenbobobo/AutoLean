"""Regression coverage for documented direct-file script invocations."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_SCRIPTS = (
    "authoritative_preflight.py",
    "fate_execution_preflight.py",
    "real_lean_module_build_preflight.py",
)


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
