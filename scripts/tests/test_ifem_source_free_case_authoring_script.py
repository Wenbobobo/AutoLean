"""Direct-entry-point coverage for source-free iFEM case authoring."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from autolean_builder import ifem_next_calibration_case_intents as intents
from autolean_builder import ifem_source_free_case_authoring as authoring

from scripts import ifem_source_free_case_authoring as authoring_script

ROOT = Path(__file__).resolve().parents[2]


def test_direct_script_help_resolves_workspace_imports(tmp_path: Path) -> None:
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    completed = subprocess.run(
        (sys.executable, str(ROOT / "scripts" / "ifem_source_free_case_authoring.py"), "--help"),
        check=False,
        cwd=tmp_path,
        capture_output=True,
        env=environment,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert "--intents" in completed.stdout
    assert "--plan-out" in completed.stdout
    assert "--report-out" in completed.stdout


def test_script_materializes_replayable_fake_first_plan_and_public_report(tmp_path: Path) -> None:
    queue = intents.build_ifem_next_calibration_case_intents_from_paths()
    intent_path = tmp_path / "intents.json"
    plan_path = tmp_path / "plan.json"
    report_path = tmp_path / "report.json"
    intent_path.write_bytes(intents.render_ifem_next_calibration_case_intents(queue))

    assert (
        authoring_script.main(
            [
                "--intents",
                str(intent_path),
                "--plan-out",
                str(plan_path),
                "--report-out",
                str(report_path),
            ]
        )
        == 0
    )
    plan = authoring.load_source_free_case_authoring_plan(plan_path)
    report = authoring.load_source_free_case_authoring_report(report_path)

    assert len(plan.case_coordinates) == 9
    assert report.case_count == 9
    assert report.stage_count == 27
    assert report.fake_only is True
    assert report.machine_advisory_disposition == "abstain"
