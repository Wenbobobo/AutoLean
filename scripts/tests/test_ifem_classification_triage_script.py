"""Direct-entry-point coverage for the iFEM unknown-only triage tool."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from autolean_builder import ifem_classification_triage as triage

from scripts import ifem_classification_triage as triage_script

ROOT = Path(__file__).resolve().parents[2]


def test_direct_script_help_resolves_workspace_imports(tmp_path: Path) -> None:
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    completed = subprocess.run(
        (sys.executable, str(ROOT / "scripts" / "ifem_classification_triage.py"), "--help"),
        check=False,
        cwd=tmp_path,
        capture_output=True,
        env=environment,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert "--readiness-decision" in completed.stdout


def test_script_main_writes_a_reusable_non_authoritative_artifact(tmp_path: Path) -> None:
    output = tmp_path / "ifem-triage.json"

    assert triage_script.main(["--out", str(output)]) == 0
    loaded = triage.load_ifem_unknown_only_classification_triage(output)

    assert len(loaded.nodes) == 21
    assert loaded.authority.prover_handoff_allowed is False
