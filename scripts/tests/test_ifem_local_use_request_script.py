"""Direct-entry-point coverage for the pending iFEM local-use request tool."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from autolean_builder import ifem_local_use_request as local_use

from scripts import ifem_local_use_request as request_script

ROOT = Path(__file__).resolve().parents[2]


def test_direct_script_help_resolves_workspace_imports(tmp_path: Path) -> None:
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    completed = subprocess.run(
        (sys.executable, str(ROOT / "scripts" / "ifem_local_use_request.py"), "--help"),
        check=False,
        cwd=tmp_path,
        capture_output=True,
        env=environment,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert "--discovery-manifest" in completed.stdout
    assert "--out" in completed.stdout


def test_script_writes_a_replayable_pending_request(tmp_path: Path) -> None:
    output = tmp_path / "ifem-local-use-request.json"

    assert request_script.main(["--out", str(output)]) == 0
    loaded = local_use.load_ifem_local_use_request(output)
    local_use.verify_ifem_local_use_request_against_manifest(loaded)

    assert loaded.request_status == "pending_operator_rights_decision"
    assert loaded.authority.rights_decision_authorized is False
    assert loaded.builder_freeze == "forbidden"
    assert loaded.prover_handoff == "forbidden"
