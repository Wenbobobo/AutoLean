from __future__ import annotations

from pathlib import Path

from benchmarks.provider_readiness import build_scripted_fake_readiness
from benchmarks.role_benchmark import (
    BenchmarkRoleV1,
    FakeRoleBenchmarkFixtureV1,
    RoleBenchmarkHarness,
    RoleBenchmarkRawOutputStore,
    RoleBenchmarkReportV1,
    RoleBenchmarkStore,
    ScriptedFakeRoleExecutor,
    compare_reports,
    load_fake_fixture,
    stable_case_selection,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATH = PROJECT_ROOT / "benchmarks" / "roles" / "calibration-pairs.v3.json"


def _run_fixture(
    fixture: FakeRoleBenchmarkFixtureV1,
    root: Path,
) -> RoleBenchmarkReportV1:
    root.mkdir()
    with RoleBenchmarkStore(root / "roles.sqlite3") as store:
        return RoleBenchmarkHarness().run(
            fixture.matrix,
            executor=ScriptedFakeRoleExecutor(fixture),
            store=store,
            raw_output_store=RoleBenchmarkRawOutputStore(root / "raw-outputs"),
            readiness=build_scripted_fake_readiness(fixture.matrix),
            run_id="role-calibration-pairs-replay",
        )


def test_calibration_pairs_are_balanced_sensitive_controlled_and_replayable(
    tmp_path: Path,
) -> None:
    fixture = load_fake_fixture(FIXTURE_PATH)

    cases_by_role = {
        role: tuple(case for case in fixture.matrix.cases if case.role is role)
        for role in BenchmarkRoleV1
    }
    assert all(len(cases) == 2 for cases in cases_by_role.values())
    control_by_case: dict[str, str] = {}
    for cases in cases_by_role.values():
        assert all("calibration" in case.tags for case in cases)
        for case in cases:
            controls = tuple(tag for tag in case.tags if tag.startswith("control:"))
            assert len(controls) == 1
            control_by_case[case.case_id] = controls[0]
        assert {control_by_case[case.case_id] for case in cases} == {
            "control:negative",
            "control:positive",
        }

    cells_by_role = {
        role: tuple(cell for cell in fixture.matrix.cells if cell.role is role)
        for role in BenchmarkRoleV1
    }
    assert all(len(cells) == 2 for cells in cells_by_role.values())
    for role, cells in cells_by_role.items():
        oracle = next(cell for cell in cells if cell.cell_id.startswith("fake.oracle."))
        mutant = next(cell for cell in cells if cell.cell_id.startswith("fake.mutant."))
        assert set(stable_case_selection(fixture.matrix, oracle)) == {
            case.case_id for case in cases_by_role[role]
        }
        assert stable_case_selection(fixture.matrix, oracle) == stable_case_selection(
            fixture.matrix,
            mutant,
        )

        oracle_payload = oracle.model_dump(mode="json")
        mutant_payload = mutant.model_dump(mode="json")
        oracle_model = oracle_payload.pop("model")
        mutant_model = mutant_payload.pop("model")
        oracle_payload.pop("cell_id")
        mutant_payload.pop("cell_id")
        assert oracle_payload == mutant_payload
        assert isinstance(oracle_model, dict)
        assert isinstance(mutant_model, dict)
        assert oracle_model.pop("model_revision") == "oracle-v1"
        assert mutant_model.pop("model_revision") == "mutant-v1"
        assert oracle_model == mutant_model

    first = _run_fixture(fixture, tmp_path / "first")
    second = _run_fixture(fixture, tmp_path / "second")
    assert first.canonical_json_bytes() == second.canonical_json_bytes()
    assert first.run.authority_granted is False
    assert first.execution_class.value == "scripted_fake"
    assert first.evaluator_kinds == ("exact_json_v1",)
    assert len(first.results) == 60

    metrics = {metric.cell_id: metric for metric in first.metrics}
    for role, cells in cells_by_role.items():
        oracle = next(cell for cell in cells if cell.cell_id.startswith("fake.oracle."))
        mutant = next(cell for cell in cells if cell.cell_id.startswith("fake.mutant."))
        assert (metrics[oracle.cell_id].passed, metrics[oracle.cell_id].trials) == (6, 6)
        assert metrics[oracle.cell_id].pass_rate_ppm == 1_000_000
        assert (metrics[mutant.cell_id].passed, metrics[mutant.cell_id].trials) == (3, 6)
        assert metrics[mutant.cell_id].pass_rate_ppm == 500_000
        for case in cases_by_role[role]:
            oracle_results = tuple(
                result
                for result in first.results
                if result.cell_id == oracle.cell_id and result.case_id == case.case_id
            )
            mutant_results = tuple(
                result
                for result in first.results
                if result.cell_id == mutant.cell_id and result.case_id == case.case_id
            )
            assert len(oracle_results) == len(mutant_results) == 3
            assert sum(result.passed for result in oracle_results) == 3
            expected_mutant_passes = 3 if control_by_case[case.case_id] == "control:positive" else 0
            assert sum(result.passed for result in mutant_results) == expected_mutant_passes

        comparison = compare_reports(
            first,
            baseline_cell_id=oracle.cell_id,
            candidate=first,
            candidate_cell_id=mutant.cell_id,
        )
        assert comparison.comparison_kind == "controlled_ablation"
        assert comparison.changed_dimensions == ("model_target",)
        assert comparison.evidence_changes == ()
        assert comparison.non_repeatable_dimensions == ("experiment:model_target",)
        assert comparison.paired_trials == 6
        assert comparison.output_mismatched_trials == 3
        assert comparison.baseline_pass_rate_ppm == 1_000_000
        assert comparison.candidate_pass_rate_ppm == 500_000
        assert comparison.pass_rate_delta_ppm == -500_000
        assert comparison.candidate_wins == 0
        assert comparison.candidate_losses == 3
        assert comparison.ties == 3
