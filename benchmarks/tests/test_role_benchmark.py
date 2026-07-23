from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from benchmarks.role_benchmark import (
    BenchmarkRoleV1,
    FakeRoleBenchmarkFixtureV1,
    RoleBenchmarkError,
    RoleBenchmarkHarness,
    RoleBenchmarkReportV1,
    RoleBenchmarkStore,
    RoleBenchmarkStoreError,
    ScriptedFakeRoleExecutor,
    build_run_manifest,
    compare_reports,
    load_fake_fixture,
    stable_case_selection,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATH = PROJECT_ROOT / "benchmarks" / "roles" / "fake-smoke.v1.json"


def _fixture() -> FakeRoleBenchmarkFixtureV1:
    return load_fake_fixture(FIXTURE_PATH)


def _payload(fixture: FakeRoleBenchmarkFixtureV1) -> dict[str, object]:
    return fixture.model_dump(mode="json")


def _replace_response(
    fixture: FakeRoleBenchmarkFixtureV1,
    *,
    cell_id: str,
    outputs: list[object],
) -> FakeRoleBenchmarkFixtureV1:
    payload = _payload(fixture)
    responses = payload["responses"]
    assert isinstance(responses, list)
    for response in responses:
        assert isinstance(response, dict)
        if response["cell_id"] == cell_id:
            response["outputs"] = outputs
            break
    return FakeRoleBenchmarkFixtureV1.model_validate(payload)


def _replace_cell_model(
    fixture: FakeRoleBenchmarkFixtureV1,
    *,
    cell_id: str,
    model_id: str,
    change_prompt: bool = False,
) -> FakeRoleBenchmarkFixtureV1:
    payload = _payload(fixture)
    matrix = payload["matrix"]
    assert isinstance(matrix, dict)
    cells = matrix["cells"]
    assert isinstance(cells, list)
    for cell in cells:
        assert isinstance(cell, dict)
        if cell["cell_id"] != cell_id:
            continue
        model = cell["model"]
        assert isinstance(model, dict)
        model["model_id"] = model_id
        model["provider_configuration_hash"] = "d" * 64
        if change_prompt:
            prompt = cell["prompt"]
            assert isinstance(prompt, dict)
            prompt["revision"] = "2"
            prompt["instruction"] = f"{prompt['instruction']} Use the ablation prompt."
        break
    return FakeRoleBenchmarkFixtureV1.model_validate(payload)


def _run(
    fixture: FakeRoleBenchmarkFixtureV1,
    database: Path,
    *,
    run_id: str,
) -> RoleBenchmarkReportV1:
    with RoleBenchmarkStore(database) as store:
        return RoleBenchmarkHarness().run(
            fixture.matrix,
            executor=ScriptedFakeRoleExecutor(fixture),
            store=store,
            run_id=run_id,
        )


def test_fixture_covers_all_initial_roles_and_stable_selection() -> None:
    fixture = _fixture()
    assert {case.role for case in fixture.matrix.cases} == set(BenchmarkRoleV1)
    first = {
        cell.cell_id: stable_case_selection(fixture.matrix, cell) for cell in fixture.matrix.cells
    }
    second = {
        cell.cell_id: stable_case_selection(fixture.matrix, cell)
        for cell in reversed(fixture.matrix.cells)
    }
    assert first == second
    assert fixture.matrix.content_hash() == fixture.matrix.content_hash()


def test_fake_harness_persists_complete_answer_free_report(tmp_path: Path) -> None:
    report = _run(_fixture(), tmp_path / "roles.sqlite3", run_id="fake-smoke-run")

    assert len(report.results) == 15
    assert len(report.metrics) == 5
    assert all(metric.trials == 3 and metric.passed == 3 for metric in report.metrics)
    assert all(metric.pass_rate_ppm == 1_000_000 for metric in report.metrics)
    assert all(metric.unstable_cases == 0 for metric in report.metrics)

    text = report.canonical_json_bytes().decode("ascii")
    assert '"proof":"by' not in text
    assert "strictness_changed" not in text
    assert "source_claim" not in text
    assert "output_hash" in text
    assert "evaluator_hash" in text


def test_repetition_metrics_expose_output_fluctuation(tmp_path: Path) -> None:
    fixture = _replace_response(
        _fixture(),
        cell_id="fake.prover",
        outputs=[
            {"action": "submit_proof", "proof": "by\n  rfl"},
            {"action": "report_gap"},
            {"action": "submit_proof", "proof": "by\n  rfl"},
        ],
    )
    report = _run(fixture, tmp_path / "roles.sqlite3", run_id="fluctuation-run")
    metric = next(item for item in report.metrics if item.cell_id == "fake.prover")

    assert metric.passed == 2
    assert metric.pass_rate_ppm == 666_667
    assert metric.unstable_cases == 1
    assert metric.instability_rate_ppm == 1_000_000
    assert metric.pass_rate_wilson95_low_ppm < metric.pass_rate_ppm
    assert metric.pass_rate_wilson95_high_ppm > metric.pass_rate_ppm


def test_store_is_idempotent_but_rejects_conflicting_run_manifest(tmp_path: Path) -> None:
    fixture = _fixture()
    original = build_run_manifest(fixture.matrix, run_id="immutable-run")
    altered_fixture = _replace_cell_model(
        fixture,
        cell_id="fake.prover",
        model_id="fake-model-2",
    )
    conflicting = build_run_manifest(altered_fixture.matrix, run_id="immutable-run")

    with RoleBenchmarkStore(tmp_path / "roles.sqlite3") as store:
        store.create_run(original)
        store.create_run(original)
        with pytest.raises(RoleBenchmarkStoreError, match="conflicts"):
            store.create_run(conflicting)
        with pytest.raises(RoleBenchmarkError, match="missing terminal"):
            store.report("immutable-run")


def test_comparison_distinguishes_repeatability_control_and_confounding(
    tmp_path: Path,
) -> None:
    baseline_fixture = _fixture()
    candidate_outputs = _replace_response(
        baseline_fixture,
        cell_id="fake.prover",
        outputs=[
            {"action": "report_gap"},
            {"action": "submit_proof", "proof": "by\n  rfl"},
            {"action": "report_gap"},
        ],
    )
    baseline = _run(
        baseline_fixture,
        tmp_path / "baseline.sqlite3",
        run_id="baseline-run",
    )
    repeated = _run(
        candidate_outputs,
        tmp_path / "repeat.sqlite3",
        run_id="repeat-run",
    )
    repeatability = compare_reports(
        baseline,
        baseline_cell_id="fake.prover",
        candidate=repeated,
        candidate_cell_id="fake.prover",
    )
    assert repeatability.comparison_kind == "repeatability"
    assert repeatability.changed_dimensions == ()
    assert repeatability.candidate_losses == 2
    assert repeatability.discordant_trials == 2

    model_fixture = _replace_cell_model(
        candidate_outputs,
        cell_id="fake.prover",
        model_id="fake-model-2",
    )
    model_report = _run(
        model_fixture,
        tmp_path / "model.sqlite3",
        run_id="model-run",
    )
    controlled = compare_reports(
        baseline,
        baseline_cell_id="fake.prover",
        candidate=model_report,
        candidate_cell_id="fake.prover",
    )
    assert controlled.comparison_kind == "controlled_ablation"
    assert controlled.changed_dimensions == ("model_target",)

    confounded_fixture = _replace_cell_model(
        candidate_outputs,
        cell_id="fake.prover",
        model_id="fake-model-3",
        change_prompt=True,
    )
    confounded_report = _run(
        confounded_fixture,
        tmp_path / "confounded.sqlite3",
        run_id="confounded-run",
    )
    confounded = compare_reports(
        baseline,
        baseline_cell_id="fake.prover",
        candidate=confounded_report,
        candidate_cell_id="fake.prover",
    )
    assert confounded.comparison_kind == "confounded"
    assert confounded.changed_dimensions == ("model_target", "prompt")


def test_fake_fixture_refuses_non_fake_targets_and_incomplete_responses() -> None:
    payload = _payload(_fixture())
    matrix = payload["matrix"]
    assert isinstance(matrix, dict)
    cells = matrix["cells"]
    assert isinstance(cells, list)
    first_cell = cells[0]
    assert isinstance(first_cell, dict)
    model = first_cell["model"]
    assert isinstance(model, dict)
    model["provider_id"] = "external"
    with pytest.raises(ValidationError, match="provider_id 'fake'"):
        FakeRoleBenchmarkFixtureV1.model_validate(payload)

    payload = _payload(_fixture())
    responses = payload["responses"]
    assert isinstance(responses, list)
    responses.pop()
    with pytest.raises(ValidationError, match="coverage"):
        FakeRoleBenchmarkFixtureV1.model_validate(payload)


def test_checked_in_fixture_is_strict_json() -> None:
    raw = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    fixture = FakeRoleBenchmarkFixtureV1.model_validate(raw)
    assert fixture.schema_version == "autolean.role-fake-fixture.v1"


@pytest.mark.integration
def test_fake_only_cli_runs_and_replays_identical_report(tmp_path: Path) -> None:
    database = tmp_path / "roles.sqlite3"
    first = tmp_path / "first.json"
    replayed = tmp_path / "replayed.json"
    script = PROJECT_ROOT / "scripts" / "role_benchmark.py"
    subprocess.run(
        (
            sys.executable,
            str(script),
            "run",
            "--fixture",
            str(FIXTURE_PATH),
            "--database",
            str(database),
            "--run-id",
            "cli-fixture-run",
            "--output",
            str(first),
        ),
        cwd=PROJECT_ROOT,
        check=True,
    )
    subprocess.run(
        (
            sys.executable,
            str(script),
            "report",
            "--database",
            str(database),
            "--run-id",
            "cli-fixture-run",
            "--output",
            str(replayed),
        ),
        cwd=PROJECT_ROOT,
        check=True,
    )
    assert first.read_bytes() == replayed.read_bytes()
