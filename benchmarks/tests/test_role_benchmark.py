from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import pytest
from autolean_contracts import canonical_json_bytes
from autolean_control_plane.errors import ArtifactCorruption
from autolean_prover.providers import Capability, FakeProvider, ProviderCapabilities
from pydantic import ValidationError

from benchmarks.provider_readiness import (
    build_scripted_fake_readiness,
    require_scripted_fake_ready,
)
from benchmarks.role_benchmark import (
    BenchmarkRoleV1,
    FakeRoleBenchmarkFixtureV1,
    RoleBenchmarkCellV1,
    RoleBenchmarkError,
    RoleBenchmarkExecutorDescriptorV1,
    RoleBenchmarkHarness,
    RoleBenchmarkPreflightBindingV1,
    RoleBenchmarkPrivateManifestStore,
    RoleBenchmarkPrivatePaths,
    RoleBenchmarkRawOutputStore,
    RoleBenchmarkReportV1,
    RoleBenchmarkStore,
    RoleBenchmarkStoreError,
    RoleBenchmarkTrialIndeterminate,
    RoleBenchmarkTrialReservation,
    RoleBenchmarkWorkItem,
    RoleExecutionOutcome,
    ScriptedFakeRoleExecutor,
    build_run_manifest,
    compare_reports,
    derive_trial_seed,
    load_fake_fixture,
    load_raw_artifact_manifest_json,
    load_report_json,
    operator_private_benchmark_paths,
    prepare_private_manifest_path,
    scripted_fake_executor_descriptor,
    stable_case_selection,
    validate_report_private_manifest,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATH = PROJECT_ROOT / "benchmarks" / "roles" / "fake-smoke.v3.json"


def _fixture() -> FakeRoleBenchmarkFixtureV1:
    return load_fake_fixture(FIXTURE_PATH)


def _private_paths(database: Path, run_id: str) -> RoleBenchmarkPrivatePaths:
    database_key = hashlib.sha256(str(database.resolve()).encode("utf-8")).hexdigest()[:16]
    return operator_private_benchmark_paths(
        run_id,
        environment={
            "AUTOLEAN_BENCHMARK_PRIVATE_ROOT": str(
                database.parent / f"{database_key}-{run_id}-private"
            )
        },
    )


class _CountingExecutor:
    def __init__(self, fixture: FakeRoleBenchmarkFixtureV1, *, delay_seconds: float = 0) -> None:
        self._delegate = ScriptedFakeRoleExecutor(fixture)
        self._delay_seconds = delay_seconds
        self._lock = threading.Lock()
        self.calls = 0

    @property
    def descriptor(self) -> RoleBenchmarkExecutorDescriptorV1:
        return self._delegate.descriptor

    def execute(
        self,
        *,
        cell: RoleBenchmarkCellV1,
        work_item: RoleBenchmarkWorkItem,
        repetition: int,
    ) -> RoleExecutionOutcome:
        with self._lock:
            self.calls += 1
        if self._delay_seconds:
            time.sleep(self._delay_seconds)
        return self._delegate.execute(
            cell=cell,
            work_item=work_item,
            repetition=repetition,
        )


def _preflight(fixture: FakeRoleBenchmarkFixtureV1) -> RoleBenchmarkPreflightBindingV1:
    descriptor = scripted_fake_executor_descriptor()
    return require_scripted_fake_ready(
        fixture.matrix,
        build_scripted_fake_readiness(fixture.matrix),
        executor_descriptor=descriptor,
    )


def _payload(fixture: FakeRoleBenchmarkFixtureV1) -> dict[str, object]:
    return fixture.model_dump(mode="json")


def _contract_hash(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _result_commitment(payload: dict[str, object]) -> str:
    body = dict(payload)
    body.pop("result_commitment_hash", None)
    return _contract_hash(
        {
            "schema_version": "autolean.role-trial-result-commitment.v3",
            "trial_result": body,
        }
    )


def _run_cell_binding(payload: dict[str, object]) -> str:
    body = dict(payload)
    body.pop("run_cell_binding_hash", None)
    return _contract_hash(
        {
            "schema_version": "autolean.role-run-cell-binding.v3",
            "run_cell": body,
        }
    )


def _public_result_commitment(
    run: dict[str, object],
    results: list[dict[str, object]],
) -> str:
    def result_key(item: dict[str, object]) -> tuple[str, str, int]:
        repetition = item["repetition"]
        assert isinstance(repetition, int)
        return (str(item["cell_id"]), str(item["case_id"]), repetition)

    ordered = sorted(results, key=result_key)
    return _contract_hash(
        {
            "schema_version": "autolean.role-public-result-commitment.v3",
            "run_manifest_hash": _contract_hash(run),
            "results": ordered,
        }
    )


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
        required = cell["required_capabilities"]
        assert isinstance(required, list)
        provider = FakeProvider(
            (),
            model_id=model_id,
            capabilities=ProviderCapabilities(frozenset(Capability(item) for item in required)),
        )
        model["provider_configuration_hash"] = provider.configuration_hash.value
        if change_prompt:
            prompt = cell["prompt"]
            assert isinstance(prompt, dict)
            prompt["revision"] = "2"
            prompt["instruction"] = f"{prompt['instruction']} Use the ablation prompt."
        break
    return FakeRoleBenchmarkFixtureV1.model_validate(payload)


def _replace_case_oracle(
    fixture: FakeRoleBenchmarkFixtureV1,
    *,
    case_id: str,
    expected_output: object,
) -> FakeRoleBenchmarkFixtureV1:
    payload = _payload(fixture)
    matrix = payload["matrix"]
    assert isinstance(matrix, dict)
    cases = matrix["cases"]
    assert isinstance(cases, list)
    for case in cases:
        assert isinstance(case, dict)
        if case["case_id"] == case_id:
            case["expected_output"] = expected_output
            break
    responses = payload["responses"]
    assert isinstance(responses, list)
    for response in responses:
        assert isinstance(response, dict)
        if response["case_id"] == case_id:
            response["outputs"] = [expected_output]
    return FakeRoleBenchmarkFixtureV1.model_validate(payload)


def _replace_case_input(
    fixture: FakeRoleBenchmarkFixtureV1,
    *,
    case_id: str,
    input_payload: object,
) -> FakeRoleBenchmarkFixtureV1:
    payload = _payload(fixture)
    matrix = payload["matrix"]
    assert isinstance(matrix, dict)
    cases = matrix["cases"]
    assert isinstance(cases, list)
    for case in cases:
        assert isinstance(case, dict)
        if case["case_id"] == case_id:
            case["input_payload"] = input_payload
            break
    return FakeRoleBenchmarkFixtureV1.model_validate(payload)


def _run(
    fixture: FakeRoleBenchmarkFixtureV1,
    database: Path,
    *,
    run_id: str,
) -> RoleBenchmarkReportV1:
    private_paths = _private_paths(database, run_id)
    raw_output_store = RoleBenchmarkRawOutputStore(private_paths.raw_output_root)
    private_manifest_store = RoleBenchmarkPrivateManifestStore(private_paths)
    with RoleBenchmarkStore(database) as store:
        return RoleBenchmarkHarness().run(
            fixture.matrix,
            executor=ScriptedFakeRoleExecutor(fixture),
            store=store,
            raw_output_store=raw_output_store,
            private_manifest_store=private_manifest_store,
            readiness=build_scripted_fake_readiness(fixture.matrix),
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


def test_repetition_seeds_and_work_hashes_are_explicit_and_stable() -> None:
    fixture = _fixture()
    first = build_run_manifest(
        fixture.matrix,
        run_id="seed-run-a",
        preflight=_preflight(fixture),
        executor_descriptor=scripted_fake_executor_descriptor(),
    )
    second = build_run_manifest(
        fixture.matrix,
        run_id="seed-run-b",
        preflight=_preflight(fixture),
        executor_descriptor=scripted_fake_executor_descriptor(),
    )
    first_trials = {
        (cell.cell_id, case.case_id, trial.repetition): (
            trial.trial_seed,
            trial.work_item_hash,
        )
        for cell in first.cells
        for case in cell.selected_cases
        for trial in case.trials
    }
    second_trials = {
        (cell.cell_id, case.case_id, trial.repetition): (
            trial.trial_seed,
            trial.work_item_hash,
        )
        for cell in second.cells
        for case in cell.selected_cases
        for trial in case.trials
    }

    assert first_trials == second_trials
    assert len(first_trials) == 15
    assert len({seed for seed, _work_hash in first_trials.values()}) == 15
    assert len({work_hash for _seed, work_hash in first_trials.values()}) == 15
    prover = next(cell for cell in fixture.matrix.cells if cell.cell_id == "fake.prover")
    assert (
        derive_trial_seed(
            fixture.matrix,
            prover,
            case_id="prover.reflexive",
            repetition=1,
        )
        == first_trials[("fake.prover", "prover.reflexive", 1)][0]
    )
    altered = _replace_cell_model(
        fixture,
        cell_id="fake.prover",
        model_id="fake-model-2",
    )
    altered_run = build_run_manifest(
        altered.matrix,
        run_id="seed-run-model-change",
        preflight=_preflight(altered),
        executor_descriptor=scripted_fake_executor_descriptor(),
    )
    altered_prover = next(cell for cell in altered_run.cells if cell.cell_id == "fake.prover")
    altered_trial = altered_prover.selected_cases[0].trials[0]
    original_seed, original_work = first_trials[
        ("fake.prover", altered_prover.selected_cases[0].case_id, 1)
    ]
    assert altered_trial.trial_seed == original_seed
    assert altered_trial.work_item_hash != original_work


def test_fake_harness_persists_complete_answer_free_report(tmp_path: Path) -> None:
    report = _run(_fixture(), tmp_path / "roles.sqlite3", run_id="fake-smoke-run")

    assert len(report.results) == 15
    assert len(report.metrics) == 5
    assert all(metric.trials == 3 and metric.passed == 3 for metric in report.metrics)
    assert all(metric.pass_rate_ppm == 1_000_000 for metric in report.metrics)
    assert all(metric.unstable_cases == 0 for metric in report.metrics)
    assert report.schema_version == "autolean.role-benchmark-report.v3"
    assert report.run.schema_version == "autolean.role-benchmark-run.v3"
    assert report.execution_class.value == "scripted_fake"
    assert report.evaluator_kinds == ("exact_json_v1",)
    assert all(
        result.schema_version == "autolean.role-trial-result.v3" for result in report.results
    )

    text = report.canonical_json_bytes().decode("ascii")
    assert '"proof":"by' not in text
    assert "strictness_changed" not in text
    assert "source_claim" not in text
    assert "output_hash" in text
    assert "evaluator_hash" in text
    assert "trial_seed" in text


def test_harness_revalidates_the_complete_readiness_report(tmp_path: Path) -> None:
    fixture = _fixture()
    private_paths = operator_private_benchmark_paths(
        "stale-readiness-run",
        environment={"AUTOLEAN_BENCHMARK_PRIVATE_ROOT": str(tmp_path / "operator-private")},
    )
    stale_readiness = build_scripted_fake_readiness(fixture.matrix).model_copy(
        update={"matrix_hash": "0" * 64}
    )
    with (
        RoleBenchmarkStore(tmp_path / "roles.sqlite3") as store,
        pytest.raises(RoleBenchmarkError, match="does not bind the benchmark matrix"),
    ):
        RoleBenchmarkHarness().run(
            fixture.matrix,
            executor=ScriptedFakeRoleExecutor(fixture),
            store=store,
            raw_output_store=RoleBenchmarkRawOutputStore(private_paths.raw_output_root),
            private_manifest_store=RoleBenchmarkPrivateManifestStore(private_paths),
            readiness=stale_readiness,
            run_id="stale-readiness-run",
        )


def test_raw_outputs_are_private_cas_artifacts_with_a_separate_manifest(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    private_paths = operator_private_benchmark_paths(
        "raw-artifact-run",
        environment={"AUTOLEAN_BENCHMARK_PRIVATE_ROOT": str(tmp_path / "operator-private")},
    )
    raw_store = RoleBenchmarkRawOutputStore(private_paths.raw_output_root)
    manifest_store = RoleBenchmarkPrivateManifestStore(private_paths)
    with RoleBenchmarkStore(tmp_path / "roles.sqlite3") as store:
        report = RoleBenchmarkHarness().run(
            fixture.matrix,
            executor=ScriptedFakeRoleExecutor(fixture),
            store=store,
            raw_output_store=raw_store,
            private_manifest_store=manifest_store,
            readiness=build_scripted_fake_readiness(fixture.matrix),
            run_id="raw-artifact-run",
        )
        replayed = store.report("raw-artifact-run")

    manifest = manifest_store.load()
    assert raw_store.build_manifest(replayed.run, replayed.results) == manifest
    assert manifest.schema_version == "autolean.role-raw-artifact-manifest.v3"
    assert all(
        item.schema_version == "autolean.role-raw-output-entry.v3" for item in manifest.outputs
    )
    assert manifest.storage_class == "operator-local-private"
    assert len(manifest.outputs) == 15
    assert manifest.run_manifest_hash
    assert manifest.content_hash() == report.raw_artifact_manifest_hash
    assert manifest.public_result_commitment_hash == report.public_result_commitment_hash
    assert {item.result_commitment_hash for item in manifest.outputs} == {
        item.result_commitment_hash for item in report.results
    }
    validate_report_private_manifest(report, manifest)
    assert {item.output_hash for item in manifest.outputs} == {
        item.output_hash for item in report.results
    }
    digest = manifest.outputs[0].output_hash
    blob = private_paths.raw_output_root / "sha256" / digest[:2] / digest[2:4] / digest
    blob.write_bytes(b"{}")
    with pytest.raises(ArtifactCorruption, match="failed integrity"):
        raw_store.build_manifest(report.run, report.results)


def test_private_manifest_cross_checks_complete_public_result_commitments(
    tmp_path: Path,
) -> None:
    database = tmp_path / "roles.sqlite3"
    report = _run(_fixture(), database, run_id="manifest-cross-check")
    manifest = RoleBenchmarkPrivateManifestStore(
        _private_paths(database, "manifest-cross-check")
    ).load()
    validate_report_private_manifest(report, manifest)

    payload = manifest.model_dump(mode="json")
    payload["public_result_commitment_hash"] = "0" * 64
    forged_manifest = type(manifest).model_validate(payload)
    report_payload = report.model_dump(mode="json")
    report_payload["raw_artifact_manifest_hash"] = forged_manifest.content_hash()
    forged_report = RoleBenchmarkReportV1.model_validate(report_payload)
    with pytest.raises(RoleBenchmarkError, match="complete public V3 results"):
        validate_report_private_manifest(forged_report, forged_manifest)

    payload = manifest.model_dump(mode="json")
    payload["outputs"][0]["result_commitment_hash"] = "1" * 64
    forged_entry_manifest = type(manifest).model_validate(payload)
    report_payload = report.model_dump(mode="json")
    report_payload["raw_artifact_manifest_hash"] = forged_entry_manifest.content_hash()
    forged_report = RoleBenchmarkReportV1.model_validate(report_payload)
    with pytest.raises(RoleBenchmarkError, match="complete public V3 results"):
        validate_report_private_manifest(forged_report, forged_entry_manifest)


def test_public_report_rejects_metric_identity_and_result_score_forgery(
    tmp_path: Path,
) -> None:
    report = _run(_fixture(), tmp_path / "roles.sqlite3", run_id="report-integrity")

    provider_forgery = report.model_dump(mode="json")
    provider_forgery["metrics"][0]["provider_id"] = "openai"
    provider_forgery["metrics"][0]["model_id"] = "gpt-real-looking"
    with pytest.raises(RoleBenchmarkError, match="invalid role benchmark report"):
        load_report_json(json.dumps(provider_forgery))

    metric_forgery = report.model_dump(mode="json")
    metric_forgery["metrics"][0]["passed"] = 0
    metric_forgery["metrics"][0]["pass_rate_ppm"] = 0
    metric_forgery["metrics"][0]["mean_score_micros"] = 0
    with pytest.raises(RoleBenchmarkError, match="invalid role benchmark report"):
        load_report_json(json.dumps(metric_forgery))

    score_forgery = report.model_dump(mode="json")
    score_forgery["results"][0]["passed"] = False
    with pytest.raises(RoleBenchmarkError, match="invalid role benchmark report"):
        load_report_json(json.dumps(score_forgery))


def test_coordinated_verdict_metric_and_accounting_rewrite_preserving_commitment_fails(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    changed_payload = _payload(fixture)
    responses = changed_payload["responses"]
    assert isinstance(responses, list)
    for response in responses:
        assert isinstance(response, dict)
        if response["cell_id"] == "fake.prover":
            response["outputs"] = [{"action": "report_gap"}]
            response["elapsed_ms"] = 9
            response["input_tokens"] = 2
            response["output_tokens"] = 3
            response["cost_microusd"] = 0
    changed_fixture = FakeRoleBenchmarkFixtureV1.model_validate(changed_payload)
    baseline = _run(
        fixture,
        tmp_path / "baseline.sqlite3",
        run_id="coordinated-rewrite",
    )
    changed = _run(
        changed_fixture,
        tmp_path / "changed.sqlite3",
        run_id="coordinated-rewrite",
    )
    assert changed.metrics != baseline.metrics
    assert any(
        result.input_tokens == 2 and not result.passed
        for result in changed.results
        if result.cell_id == "fake.prover"
    )

    forged = changed.model_dump(mode="json")
    baseline_commitments = {
        (result.cell_id, result.case_id, result.repetition): result.result_commitment_hash
        for result in baseline.results
    }
    for result in forged["results"]:
        coordinate = (result["cell_id"], result["case_id"], result["repetition"])
        result["result_commitment_hash"] = baseline_commitments[coordinate]
    forged["public_result_commitment_hash"] = baseline.public_result_commitment_hash
    forged["raw_artifact_manifest_hash"] = baseline.raw_artifact_manifest_hash

    with pytest.raises(ValidationError, match="trial result commitment"):
        RoleBenchmarkReportV1.model_validate(forged)


def test_public_report_requires_canonical_v3_and_complete_bindings(tmp_path: Path) -> None:
    report = _run(_fixture(), tmp_path / "roles.sqlite3", run_id="canonical-report")
    canonical = report.canonical_json_bytes().decode("ascii")
    assert load_report_json(canonical) == report

    with pytest.raises(RoleBenchmarkError, match="not canonical V3"):
        load_report_json(json.dumps(json.loads(canonical), indent=2))

    payload = json.loads(canonical)
    del payload["public_result_commitment_hash"]
    with pytest.raises(RoleBenchmarkError, match="invalid role benchmark report"):
        load_report_json(json.dumps(payload))

    for field in ("case_revision", "case_contract_hash", "evaluator_hash", "trials"):
        payload = json.loads(canonical)
        del payload["run"]["cells"][0]["selected_cases"][0][field]
        with pytest.raises(RoleBenchmarkError, match="invalid role benchmark report"):
            load_report_json(json.dumps(payload))


def test_scripted_fake_report_cannot_be_relabelled_as_external(tmp_path: Path) -> None:
    report = _run(_fixture(), tmp_path / "roles.sqlite3", run_id="execution-identity")
    payload = json.loads(report.canonical_json_bytes())
    payload["execution_class"] = "authorized_external"
    payload["run"]["execution_class"] = "authorized_external"
    for result in payload["results"]:
        result["execution_receipt"]["execution_class"] = "authorized_external"

    with pytest.raises(RoleBenchmarkError, match="invalid role benchmark report"):
        load_report_json(json.dumps(payload))

    fixture = _fixture()
    descriptor_payload = scripted_fake_executor_descriptor().model_dump(mode="python")
    descriptor_payload["execution_class"] = "authorized_external"
    forged_descriptor = RoleBenchmarkExecutorDescriptorV1.model_construct(**descriptor_payload)
    with pytest.raises(RoleBenchmarkError, match="not valid V3"):
        build_run_manifest(
            fixture.matrix,
            run_id="forged-executor-run",
            preflight=_preflight(fixture),
            executor_descriptor=forged_descriptor,
        )


def test_coordinated_model_metric_and_receipt_rewrite_preserving_cell_binding_fails(
    tmp_path: Path,
) -> None:
    report = _run(_fixture(), tmp_path / "roles.sqlite3", run_id="model-binding")
    payload = report.model_dump(mode="json")
    run = payload["run"]
    cells = run["cells"]
    target_cell = next(cell for cell in cells if cell["cell_id"] == "fake.prover")
    original_binding = target_cell["run_cell_binding_hash"]
    model = target_cell["model"]
    model["model_id"] = "fake-model-forged"
    model["provider_configuration_hash"] = "1" * 64
    metric = next(item for item in payload["metrics"] if item["cell_id"] == "fake.prover")
    metric["model_id"] = "fake-model-forged"
    provider_target_hash = _contract_hash(model)
    for result in payload["results"]:
        if result["cell_id"] != "fake.prover":
            continue
        result["execution_receipt"]["provider_target_hash"] = provider_target_hash
        result["result_commitment_hash"] = _result_commitment(result)
    payload["public_result_commitment_hash"] = _public_result_commitment(
        run,
        payload["results"],
    )
    assert target_cell["run_cell_binding_hash"] == original_binding

    with pytest.raises(ValidationError, match="run-cell binding hash"):
        RoleBenchmarkReportV1.model_validate(payload)


def test_scripted_fake_run_rejects_coordinated_non_fake_provider_rewrite(
    tmp_path: Path,
) -> None:
    report = _run(_fixture(), tmp_path / "roles.sqlite3", run_id="provider-binding")
    payload = report.model_dump(mode="json")
    run = payload["run"]
    cells = run["cells"]
    target_cell = next(cell for cell in cells if cell["cell_id"] == "fake.prover")
    model = target_cell["model"]
    model["provider_id"] = "openai"
    model["model_id"] = "gpt-forged"
    model["provider_configuration_hash"] = "2" * 64
    target_cell["run_cell_binding_hash"] = _run_cell_binding(target_cell)
    metric = next(item for item in payload["metrics"] if item["cell_id"] == "fake.prover")
    metric["provider_id"] = "openai"
    metric["model_id"] = "gpt-forged"
    provider_target_hash = _contract_hash(model)
    for result in payload["results"]:
        if result["cell_id"] != "fake.prover":
            continue
        result["execution_receipt"]["provider_target_hash"] = provider_target_hash
        result["result_commitment_hash"] = _result_commitment(result)
    payload["public_result_commitment_hash"] = _public_result_commitment(
        run,
        payload["results"],
    )

    with pytest.raises(ValidationError, match="provider_id 'fake'"):
        RoleBenchmarkReportV1.model_validate(payload)


def test_raw_output_store_rejects_repository_and_git_checkout_paths(
    tmp_path: Path,
) -> None:
    with pytest.raises(RoleBenchmarkError, match="outside the repository"):
        RoleBenchmarkRawOutputStore(PROJECT_ROOT / "raw-artifacts")

    checkout = tmp_path / "other-checkout"
    (checkout / ".git").mkdir(parents=True)
    with pytest.raises(RoleBenchmarkError, match="outside every Git checkout"):
        RoleBenchmarkRawOutputStore(checkout / "private" / "raw-artifacts")


def test_operator_private_paths_are_fixed_and_outside_checkout(tmp_path: Path) -> None:
    root = tmp_path / "operator-private"
    paths = operator_private_benchmark_paths(
        "fixed-private-run",
        environment={"AUTOLEAN_BENCHMARK_PRIVATE_ROOT": str(root)},
    )
    repeated = operator_private_benchmark_paths(
        "fixed-private-run",
        environment={"AUTOLEAN_BENCHMARK_PRIVATE_ROOT": str(root)},
    )

    assert paths == repeated
    assert paths.raw_output_root == root / "raw-outputs"
    assert paths.manifest_path.parent == root / "raw-artifact-manifests"
    assert paths.manifest_path.name.endswith(".json")
    with pytest.raises(RoleBenchmarkError, match="outside the repository"):
        operator_private_benchmark_paths(
            "unsafe-private-run",
            environment={"AUTOLEAN_BENCHMARK_PRIVATE_ROOT": str(PROJECT_ROOT / ".private")},
        )


def test_private_manifest_write_rejects_linked_parent(tmp_path: Path) -> None:
    root = tmp_path / "operator-private"
    root.mkdir()
    paths = operator_private_benchmark_paths(
        "linked-manifest-run",
        environment={"AUTOLEAN_BENCHMARK_PRIVATE_ROOT": str(root)},
    )
    linked_target = tmp_path / "linked-target"
    linked_target.mkdir()
    try:
        paths.manifest_path.parent.symlink_to(linked_target, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"directory symlinks are unavailable: {error}")

    with pytest.raises(RoleBenchmarkError, match="symlink, junction, or reparse point"):
        prepare_private_manifest_path(paths)
    assert not (linked_target / paths.manifest_path.name).exists()


def test_private_manifest_write_fails_fast_when_parent_is_not_writable(
    tmp_path: Path,
) -> None:
    paths = operator_private_benchmark_paths(
        "unwritable-manifest-run",
        environment={"AUTOLEAN_BENCHMARK_PRIVATE_ROOT": str(tmp_path / "operator-private")},
    )

    with (
        patch("benchmarks.role_benchmark.os.open", side_effect=PermissionError("denied")),
        pytest.raises(RoleBenchmarkError, match="parent is not writable"),
    ):
        prepare_private_manifest_path(paths)


def test_manifest_commit_failure_prevents_report_and_retry_is_idempotent(tmp_path: Path) -> None:
    fixture = _fixture()
    run_id = "manifest-commit-failure"
    database = tmp_path / "roles.sqlite3"
    private_paths = operator_private_benchmark_paths(
        run_id,
        environment={"AUTOLEAN_BENCHMARK_PRIVATE_ROOT": str(tmp_path / "operator-private")},
    )
    raw_store = RoleBenchmarkRawOutputStore(private_paths.raw_output_root)
    manifest_store = RoleBenchmarkPrivateManifestStore(private_paths)
    executor = _CountingExecutor(fixture)

    with RoleBenchmarkStore(database) as store:
        with (
            patch.object(
                RoleBenchmarkPrivateManifestStore,
                "commit",
                side_effect=RoleBenchmarkError("injected manifest commit failure"),
            ),
            pytest.raises(RoleBenchmarkError, match="injected manifest commit failure"),
        ):
            RoleBenchmarkHarness().run(
                fixture.matrix,
                executor=executor,
                store=store,
                raw_output_store=raw_store,
                private_manifest_store=manifest_store,
                readiness=build_scripted_fake_readiness(fixture.matrix),
                run_id=run_id,
            )
        assert len(store.load_results(run_id)) == 15
        with pytest.raises(RoleBenchmarkStoreError, match="no unique raw artifact manifest"):
            store.report(run_id)

    assert not private_paths.manifest_path.exists()
    assert executor.calls == 15
    with RoleBenchmarkStore(database) as store:
        report = RoleBenchmarkHarness().run(
            fixture.matrix,
            executor=executor,
            store=store,
            raw_output_store=raw_store,
            private_manifest_store=manifest_store,
            readiness=build_scripted_fake_readiness(fixture.matrix),
            run_id=run_id,
        )
    assert manifest_store.load().content_hash() == report.raw_artifact_manifest_hash
    assert executor.calls == 15


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
    original = build_run_manifest(
        fixture.matrix,
        run_id="immutable-run",
        preflight=_preflight(fixture),
        executor_descriptor=scripted_fake_executor_descriptor(),
    )
    altered_fixture = _replace_cell_model(
        fixture,
        cell_id="fake.prover",
        model_id="fake-model-2",
    )
    conflicting = build_run_manifest(
        altered_fixture.matrix,
        run_id="immutable-run",
        preflight=_preflight(altered_fixture),
        executor_descriptor=scripted_fake_executor_descriptor(),
    )

    with RoleBenchmarkStore(tmp_path / "roles.sqlite3") as store:
        store.create_run(original)
        store.create_run(original)
        with pytest.raises(RoleBenchmarkStoreError, match="conflicts"):
            store.create_run(conflicting)
        with pytest.raises(RoleBenchmarkError, match="missing terminal"):
            store.report("immutable-run")


def test_store_rejects_a_populated_legacy_v1_database_without_mutating_it(
    tmp_path: Path,
) -> None:
    database = tmp_path / "legacy-v1.sqlite3"
    connection = sqlite3.connect(database)
    connection.executescript(
        """
        CREATE TABLE role_benchmark_runs (
            run_id TEXT PRIMARY KEY,
            manifest_json TEXT NOT NULL
        );
        CREATE TABLE role_benchmark_trials (
            run_id TEXT NOT NULL,
            cell_id TEXT NOT NULL,
            case_id TEXT NOT NULL,
            repetition INTEGER NOT NULL,
            result_json TEXT NOT NULL,
            PRIMARY KEY (run_id, cell_id, case_id, repetition)
        );
        INSERT INTO role_benchmark_runs(run_id, manifest_json)
        VALUES ('legacy-v1', '{"schema_version":"autolean.role-benchmark-run.v1"}');
        """
    )
    connection.close()

    with pytest.raises(RoleBenchmarkStoreError, match="cannot be migrated in place"):
        RoleBenchmarkStore(database)

    connection = sqlite3.connect(database)
    metadata = connection.execute(
        """
        SELECT name FROM sqlite_master
        WHERE type = 'table' AND name = 'role_benchmark_store_metadata'
        """
    ).fetchall()
    journal_mode = connection.execute("PRAGMA journal_mode").fetchone()
    connection.close()
    assert metadata == []
    assert journal_mode is not None and journal_mode[0] == "delete"


@pytest.mark.parametrize("store_version", ["v1", "v2"])
def test_store_rejects_wrong_metadata_version(
    tmp_path: Path,
    store_version: str,
) -> None:
    database = tmp_path / f"wrong-version-{store_version}.sqlite3"
    connection = sqlite3.connect(database)
    connection.executescript(
        """
        CREATE TABLE role_benchmark_store_metadata (
            id INTEGER PRIMARY KEY,
            schema_version TEXT NOT NULL
        );
        """
    )
    connection.execute(
        """
        INSERT INTO role_benchmark_store_metadata(id, schema_version)
        VALUES (1, ?);
        """,
        (f"autolean.role-benchmark-store.{store_version}",),
    )
    connection.close()

    with pytest.raises(RoleBenchmarkStoreError, match=r"not an AutoLean.*V3"):
        RoleBenchmarkStore(database)


@pytest.mark.parametrize("wire_version", ["v1", "v2"])
def test_store_rejects_legacy_rows_even_if_metadata_was_stamped_v3(
    tmp_path: Path,
    wire_version: str,
) -> None:
    database = tmp_path / f"stamped-legacy-{wire_version}.sqlite3"
    with RoleBenchmarkStore(database):
        pass
    connection = sqlite3.connect(database)
    connection.execute(
        """
        INSERT INTO role_benchmark_runs(run_id, manifest_json)
        VALUES (?, ?)
        """,
        (
            "stamped-legacy",
            f'{{"schema_version":"autolean.role-benchmark-run.{wire_version}"}}',
        ),
    )
    connection.commit()
    connection.close()

    with pytest.raises(RoleBenchmarkStoreError, match="schema validation"):
        RoleBenchmarkStore(database)


def test_store_rejects_weak_v3_schema_before_duplicate_rows_can_enter(
    tmp_path: Path,
) -> None:
    database = tmp_path / "weak-v3.sqlite3"
    connection = sqlite3.connect(database)
    connection.executescript(
        """
        CREATE TABLE role_benchmark_store_metadata (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            schema_version TEXT NOT NULL
        );
        INSERT INTO role_benchmark_store_metadata(id, schema_version)
        VALUES (1, 'autolean.role-benchmark-store.v3');
        CREATE TABLE role_benchmark_runs (run_id TEXT, manifest_json TEXT);
        CREATE TABLE role_benchmark_trials (
            run_id TEXT, cell_id TEXT, case_id TEXT,
            repetition INTEGER, result_json TEXT
        );
        """
    )
    connection.close()

    with pytest.raises(
        RoleBenchmarkStoreError,
        match=r"(schema fingerprint|not an AutoLean.*V3)",
    ):
        RoleBenchmarkStore(database)


def test_store_rejects_partial_v3_tagged_payload_on_open(tmp_path: Path) -> None:
    database = tmp_path / "partial-v3.sqlite3"
    with RoleBenchmarkStore(database):
        pass
    connection = sqlite3.connect(database)
    connection.execute(
        """
        INSERT INTO role_benchmark_runs(run_id, manifest_json)
        VALUES (?, ?)
        """,
        (
            "partial-v3",
            '{"schema_version":"autolean.role-benchmark-run.v3"}',
        ),
    )
    connection.commit()
    connection.close()

    with pytest.raises(RoleBenchmarkStoreError, match="schema validation"):
        RoleBenchmarkStore(database)


def test_store_rejects_persistent_pragma_drift(tmp_path: Path) -> None:
    database = tmp_path / "pragma-drift.sqlite3"
    with RoleBenchmarkStore(database):
        pass
    connection = sqlite3.connect(database)
    observed = connection.execute("PRAGMA journal_mode=DELETE").fetchone()
    connection.close()
    assert observed is not None and observed[0] == "delete"

    with pytest.raises(RoleBenchmarkStoreError, match="journal mode"):
        RoleBenchmarkStore(database)


def test_store_rejects_terminal_trial_with_a_retained_claim(tmp_path: Path) -> None:
    database = tmp_path / "overlapping-claim.sqlite3"
    report = _run(_fixture(), database, run_id="overlap-run")
    result = report.results[0]
    connection = sqlite3.connect(database)
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute(
        """
        INSERT INTO role_benchmark_trial_claims(
            run_id, cell_id, case_id, repetition,
            owner_id, fencing_token, lease_expires_ns,
            execution_started, execution_started_ns
        ) VALUES (?, ?, ?, ?, 'forged-owner', 1, ?, 0, NULL)
        """,
        (
            result.run_id,
            result.cell_id,
            result.case_id,
            result.repetition,
            time.time_ns() + 1_000_000_000,
        ),
    )
    connection.commit()
    connection.close()

    with pytest.raises(RoleBenchmarkStoreError, match="cannot retain active claims"):
        RoleBenchmarkStore(database)


def test_started_trial_is_never_reclaimed_after_lease_expiry(tmp_path: Path) -> None:
    fixture = _fixture()
    manifest = build_run_manifest(
        fixture.matrix,
        run_id="indeterminate-run",
        preflight=_preflight(fixture),
        executor_descriptor=scripted_fake_executor_descriptor(),
    )
    first_cell = manifest.cells[0]
    first_case = first_cell.selected_cases[0]
    first_trial = first_case.trials[0]
    with RoleBenchmarkStore(tmp_path / "roles.sqlite3") as store:
        store.create_run(manifest)
        claim = store.claim_trial(
            manifest,
            cell_id=first_cell.cell_id,
            case_id=first_case.case_id,
            repetition=first_trial.repetition,
            owner_id="first-owner",
            ttl_ms=200,
        )
        assert isinstance(claim, RoleBenchmarkTrialReservation)
        started = store.mark_trial_execution_started(claim)
        with pytest.raises(RoleBenchmarkTrialIndeterminate, match="cannot be abandoned"):
            store.abandon_trial(started)
        time.sleep(0.25)
        with pytest.raises(RoleBenchmarkTrialIndeterminate, match="automatic retry"):
            store.claim_trial(
                manifest,
                cell_id=first_cell.cell_id,
                case_id=first_case.case_id,
                repetition=first_trial.repetition,
                owner_id="replacement-owner",
                ttl_ms=200,
            )


def test_expired_unstarted_claim_reopens_with_new_fence_and_rejects_stale_token(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    manifest = build_run_manifest(
        fixture.matrix,
        run_id="expired-unstarted-run",
        preflight=_preflight(fixture),
        executor_descriptor=scripted_fake_executor_descriptor(),
    )
    first_cell = manifest.cells[0]
    first_case = first_cell.selected_cases[0]
    first_trial = first_case.trials[0]
    database = tmp_path / "roles.sqlite3"
    with RoleBenchmarkStore(database) as store:
        store.create_run(manifest)
        stale = store.claim_trial(
            manifest,
            cell_id=first_cell.cell_id,
            case_id=first_case.case_id,
            repetition=first_trial.repetition,
            owner_id="expired-owner",
            ttl_ms=100,
        )
        assert isinstance(stale, RoleBenchmarkTrialReservation)
    time.sleep(0.15)

    with RoleBenchmarkStore(database) as store:
        replacement = store.claim_trial(
            manifest,
            cell_id=first_cell.cell_id,
            case_id=first_case.case_id,
            repetition=first_trial.repetition,
            owner_id="replacement-owner",
            ttl_ms=500,
        )
        assert isinstance(replacement, RoleBenchmarkTrialReservation)
        assert replacement.fencing_token == stale.fencing_token + 1
        with pytest.raises(RoleBenchmarkStoreError, match="stale, expired, or started"):
            store.mark_trial_execution_started(stale)
        with pytest.raises(RoleBenchmarkStoreError, match="cannot be safely abandoned"):
            store.abandon_trial(stale)
        store.abandon_trial(replacement)


def test_concurrent_and_repeated_same_run_never_duplicate_executor_calls(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    database = tmp_path / "roles.sqlite3"
    private_paths = operator_private_benchmark_paths(
        "concurrent-run",
        environment={"AUTOLEAN_BENCHMARK_PRIVATE_ROOT": str(tmp_path / "operator-private")},
    )
    executor = _CountingExecutor(fixture, delay_seconds=0.01)
    with RoleBenchmarkStore(database):
        pass

    def run_once() -> RoleBenchmarkReportV1:
        with RoleBenchmarkStore(database) as store:
            return RoleBenchmarkHarness().run(
                fixture.matrix,
                executor=executor,
                store=store,
                raw_output_store=RoleBenchmarkRawOutputStore(private_paths.raw_output_root),
                private_manifest_store=RoleBenchmarkPrivateManifestStore(private_paths),
                readiness=build_scripted_fake_readiness(fixture.matrix),
                run_id="concurrent-run",
            )

    with ThreadPoolExecutor(max_workers=2) as pool:
        reports = tuple(pool.map(lambda _index: run_once(), range(2)))

    assert reports[0] == reports[1]
    assert executor.calls == 15
    replayed = run_once()
    assert replayed == reports[0]
    assert executor.calls == 15


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
    assert repeatability.repeatable_bindings
    assert repeatability.non_repeatable_dimensions == ()
    assert not repeatability.repeatable_outputs
    assert repeatability.output_mismatched_trials == 2
    assert repeatability.case_binding_hash
    assert repeatability.trial_binding_hash
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
    assert not controlled.repeatable_bindings
    assert not controlled.repeatable_outputs
    assert set(controlled.non_repeatable_dimensions) == {
        "experiment:model_target",
        "evidence:matrix",
        "evidence:provider_readiness",
    }

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
    assert not confounded.repeatable_bindings


def test_comparison_rejects_case_revision_input_oracle_and_trial_binding_drift(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    baseline = _run(fixture, tmp_path / "baseline.sqlite3", run_id="binding-baseline")

    input_changed = _replace_case_input(
        fixture,
        case_id="prover.reflexive",
        input_payload={"goal": "the input changed"},
    )
    oracle_changed = _replace_case_oracle(
        fixture,
        case_id="prover.reflexive",
        expected_output={"action": "report_gap"},
    )
    revision_payload = _payload(fixture)
    matrix = revision_payload["matrix"]
    assert isinstance(matrix, dict)
    cases = matrix["cases"]
    assert isinstance(cases, list)
    for case in cases:
        assert isinstance(case, dict)
        if case["case_id"] == "prover.reflexive":
            case["case_revision"] = "2"
    revision_changed = FakeRoleBenchmarkFixtureV1.model_validate(revision_payload)

    for index, changed in enumerate((input_changed, oracle_changed, revision_changed), start=1):
        candidate = _run(
            changed,
            tmp_path / f"candidate-{index}.sqlite3",
            run_id=f"binding-candidate-{index}",
        )
        with pytest.raises(RoleBenchmarkError, match="case revision, input-oracle"):
            compare_reports(
                baseline,
                baseline_cell_id="fake.prover",
                candidate=candidate,
                candidate_cell_id="fake.prover",
            )

    trial_payload = baseline.model_dump(mode="json")
    trial_payload["run"]["cells"][0]["selected_cases"][0]["trials"][0]["trial_seed"] = "0" * 64
    with pytest.raises(ValidationError):
        RoleBenchmarkReportV1.model_validate(trial_payload)


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


def test_cell_freezes_capabilities_and_native_tools_require_tool_calling() -> None:
    payload = _payload(_fixture())
    matrix = payload["matrix"]
    assert isinstance(matrix, dict)
    cells = matrix["cells"]
    assert isinstance(cells, list)
    first_cell = cells[0]
    assert isinstance(first_cell, dict)
    first_cell["tools"] = [
        {
            "schema_version": "autolean.role-artifact-ref.v1",
            "artifact_id": "tool.synthetic",
            "revision": "1",
            "content_hash": "f" * 64,
        }
    ]

    with pytest.raises(ValidationError, match="tool_calling"):
        FakeRoleBenchmarkFixtureV1.model_validate(payload)


def test_checked_in_fixture_is_strict_json() -> None:
    raw = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    fixture = FakeRoleBenchmarkFixtureV1.model_validate(raw)
    assert fixture.schema_version == "autolean.role-fake-fixture.v3"
    assert fixture.matrix.matrix_revision == "3"


def test_checked_in_v1_tombstone_is_answer_free_and_not_executable() -> None:
    tombstone_path = PROJECT_ROOT / "benchmarks" / "roles" / "fake-smoke.v1.json"
    tombstone = json.loads(tombstone_path.read_text(encoding="ascii"))

    assert tombstone == {
        "schema_version": "autolean.role-fake-fixture.v1",
        "status": "retired_use_fake-smoke.v3.json",
    }
    with pytest.raises(RoleBenchmarkError, match="invalid role benchmark fixture"):
        load_fake_fixture(tombstone_path)


def test_legacy_v1_v2_fixture_and_report_are_not_misread_as_v3(tmp_path: Path) -> None:
    for version in ("v1", "v2"):
        fixture_payload = _payload(_fixture())
        fixture_payload["schema_version"] = f"autolean.role-fake-fixture.{version}"
        with pytest.raises(ValidationError, match=r"role-fake-fixture\.v3"):
            FakeRoleBenchmarkFixtureV1.model_validate(fixture_payload)

    report = _run(_fixture(), tmp_path / "v3.sqlite3", run_id="wire-v3")
    for version in ("v1", "v2"):
        report_payload = json.loads(report.canonical_json_bytes())
        report_payload["schema_version"] = f"autolean.role-benchmark-report.{version}"
        with pytest.raises(RoleBenchmarkError, match="invalid role benchmark report"):
            load_report_json(json.dumps(report_payload))


@pytest.mark.integration
def test_fake_only_cli_runs_and_replays_identical_report(tmp_path: Path) -> None:
    database = tmp_path / "roles.sqlite3"
    readiness = tmp_path / "readiness.json"
    private_root = tmp_path / "operator-private"
    environment = {
        **os.environ,
        "AUTOLEAN_BENCHMARK_PRIVATE_ROOT": str(private_root),
    }
    private_paths = operator_private_benchmark_paths(
        "cli-fixture-run",
        environment=environment,
    )
    first = tmp_path / "first.json"
    replayed = tmp_path / "replayed.json"
    script = PROJECT_ROOT / "scripts" / "role_benchmark.py"
    subprocess.run(
        (
            sys.executable,
            str(script),
            "readiness",
            "--fixture",
            str(FIXTURE_PATH),
            "--output",
            str(readiness),
        ),
        cwd=PROJECT_ROOT,
        check=True,
        env=environment,
    )
    subprocess.run(
        (
            sys.executable,
            str(script),
            "run",
            "--fixture",
            str(FIXTURE_PATH),
            "--readiness",
            str(readiness),
            "--database",
            str(database),
            "--run-id",
            "cli-fixture-run",
            "--output",
            str(first),
        ),
        cwd=PROJECT_ROOT,
        check=True,
        env=environment,
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
        env=environment,
    )
    assert first.read_bytes() == replayed.read_bytes()
    raw_manifest = load_raw_artifact_manifest_json(
        private_paths.manifest_path.read_text(encoding="ascii")
    )
    assert raw_manifest.run_id == "cli-fixture-run"
    assert len(raw_manifest.outputs) == 15
    assert private_paths.raw_output_root.is_dir()
    assert not (tmp_path / "raw-artifacts").exists()


@pytest.mark.integration
def test_forward_test_writes_separate_replayable_outputs(tmp_path: Path) -> None:
    output_roots = (tmp_path / "forward-a", tmp_path / "forward-b")
    private_root = tmp_path / "operator-private"
    environment = {
        **os.environ,
        "AUTOLEAN_BENCHMARK_PRIVATE_ROOT": str(private_root),
    }
    private_paths = operator_private_benchmark_paths(
        "fake-forward-v3",
        environment=environment,
    )
    script = PROJECT_ROOT / "scripts" / "role_benchmark.py"

    def command(output_root: Path) -> tuple[str, ...]:
        return (
            sys.executable,
            str(script),
            "forward-test",
            "--output-root",
            str(output_root),
        )

    first = subprocess.run(
        command(output_roots[0]),
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        env=environment,
    )
    private_manifest = private_paths.manifest_path.read_bytes()
    second = subprocess.run(
        command(output_roots[1]),
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        env=environment,
    )

    assert first.stdout == second.stdout
    for filename in ("readiness.json", "report.json"):
        assert (output_roots[0] / filename).read_bytes() == (
            output_roots[1] / filename
        ).read_bytes()
    assert private_paths.manifest_path.read_bytes() == private_manifest
    assert json.loads(first.stdout) == json.loads((output_roots[0] / "report.json").read_bytes())
    for output_root in output_roots:
        assert not (output_root / "raw-artifacts").exists()
        assert not (output_root / "raw-artifact-manifest.json").exists()

    (output_roots[0] / "report.json").write_text("{}", encoding="ascii")
    conflict = subprocess.run(
        command(output_roots[0]),
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        env=environment,
    )
    assert conflict.returncode != 0
    assert b"refusing to replace conflicting benchmark output" in conflict.stderr
