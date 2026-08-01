"""Direct-entry-point coverage for the iFEM next calibration intent tool."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from autolean_builder import ifem_next_calibration_case_intents as intents

from scripts import ifem_next_calibration_case_intents as intent_script

ROOT = Path(__file__).resolve().parents[2]


def test_direct_script_help_resolves_workspace_imports(tmp_path: Path) -> None:
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    completed = subprocess.run(
        (sys.executable, str(ROOT / "scripts" / "ifem_next_calibration_case_intents.py"), "--help"),
        check=False,
        cwd=tmp_path,
        capture_output=True,
        env=environment,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert "--d35-report" in completed.stdout


def test_script_main_writes_a_replayable_un_authored_queue(tmp_path: Path) -> None:
    output = tmp_path / "ifem-next-calibration-case-intents.json"

    assert intent_script.main(["--out", str(output)]) == 0
    loaded = intents.load_ifem_next_calibration_case_intents(output)

    assert len(loaded.intents) == 21
    assert all(intent.materialization_state == "not_authored" for intent in loaded.intents)
    assert loaded.authority.prover_handoff_authority is False
