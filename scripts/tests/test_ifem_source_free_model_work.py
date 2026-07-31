"""No-network checks for the one-coordinate source-free DeepSeek operator runner."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

import pytest
from autolean_builder.ifem_source_free_case_authoring import SourceFreeAuthoringCardV1
from autolean_builder.ifem_source_free_stage_ledger import (
    LocalSourceFreeStageLedger,
    SourceFreeStageCoordinateV1,
)
from autolean_contracts import model_work_admission_evidence_identity

from benchmarks import ifem_source_free_model_work_sidecar as sidecar_module
from scripts import ifem_source_free_model_work as runner

_DEMO_CREDENTIAL = "source-free-deepseek-test-credential-0123456789"
_RAW_RESPONSE = "SOURCE_FREE_RAW_RESPONSE_MUST_NOT_REACH_STDOUT"
_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class SimulatedProcessCrash(BaseException):
    pass


class RecordingTransport:
    def __init__(self, *, response_text: str | None = None) -> None:
        self.calls: list[tuple[str, Mapping[str, str], bytes, float]] = []
        self.response_text = response_text

    def post_json_bytes(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        self.calls.append((url, dict(headers), body, timeout_seconds))
        return {
            "id": _RAW_RESPONSE,
            "model": "deepseek-v4-pro",
            "choices": [
                {
                    "message": {
                        "content": self.response_text
                        if self.response_text is not None
                        else json.dumps(
                            {
                                "schema_version": (
                                    "autolean.ifem-source-free-authoring-response.v1"
                                ),
                                "disposition": "abstain",
                                "selected_slot": None,
                                "candidate": None,
                            },
                            separators=(",", ":"),
                            sort_keys=True,
                        )
                    }
                }
            ],
            "usage": {
                "prompt_tokens": 12,
                "prompt_cache_hit_tokens": 0,
                "completion_tokens": 10,
            },
        }

    def post_json(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        payload: Mapping[str, object],
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        return self.post_json_bytes(
            url=url,
            headers=headers,
            body=json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"),
            timeout_seconds=timeout_seconds,
        )


class FailingTransport:
    def post_json_bytes(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        del url, headers, body, timeout_seconds
        raise AssertionError("a settled coordinate must not re-dispatch")

    def post_json(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        payload: Mapping[str, object],
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        del url, headers, payload, timeout_seconds
        raise AssertionError("a settled coordinate must not re-dispatch")


def _config(
    tmp_path: Path,
    mode: runner.OperatorMode,
    *,
    approved: bool = False,
) -> runner.SourceFreeDeepSeekOperatorConfig:
    operator_root = (tmp_path / "operator").resolve()
    operator_root.mkdir(exist_ok=True)
    return runner.SourceFreeDeepSeekOperatorConfig(
        mode=mode,
        state_root=operator_root / "state",
        private_root=operator_root / "private",
        run_label="source-free-deepseek-test",
        operator_approved=approved,
    )


def _environment() -> dict[str, str]:
    return {"AUTOLEAN_DEEPSEEK_API_KEY": _DEMO_CREDENTIAL}


def test_plan_and_preflight_do_not_create_roots_or_resolve_credentials(tmp_path: Path) -> None:
    plan = runner.execute_source_free_deepseek_operator(_config(tmp_path, "plan"), environment={})
    preflight = runner.execute_source_free_deepseek_operator(
        _config(tmp_path, "preflight"),
        environment={},
    )

    assert plan.status == "planned"
    assert preflight.status == "preflight_ready"
    built = runner.build_source_free_deepseek_plan()
    pricing = runner._approval(built).pricing
    assert built.policy.max_cost_microusd == 61_440
    assert pricing.reserve_cost(max_input_tokens=2048, max_output_tokens=4096) == 61_440
    assert not _config(tmp_path, "plan").state_root.exists()
    assert not _config(tmp_path, "plan").private_root.exists()


def test_plan_hash_binds_the_exact_system_prompt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = runner.build_source_free_deepseek_plan()
    original_prompt = sidecar_module._system_prompt
    monkeypatch.setattr(
        sidecar_module,
        "_system_prompt",
        lambda role: f"{original_prompt(role)} deterministic-drift",
    )

    changed = runner.build_source_free_deepseek_plan()

    assert original.prompt_contract_sha256 != changed.prompt_contract_sha256
    assert original.content_sha256 != changed.content_sha256


def test_plan_hash_binds_the_input_envelope_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = runner.build_source_free_deepseek_plan()
    monkeypatch.setattr(
        sidecar_module,
        "_STAGE_INPUT_SCHEMA_VERSION",
        "autolean.ifem-source-free-stage-input.test-drift",
    )

    changed = runner.build_source_free_deepseek_plan()

    assert original.prompt_contract_sha256 != changed.prompt_contract_sha256
    assert original.content_sha256 != changed.content_sha256


def test_plan_hash_binds_the_input_envelope_key_structure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = runner.build_source_free_deepseek_plan()
    monkeypatch.setattr(
        sidecar_module,
        "_STAGE_INPUT_TOP_LEVEL_KEYS",
        ("payload", "role", "schema_version"),
    )

    changed = runner.build_source_free_deepseek_plan()

    assert original.prompt_contract_sha256 != changed.prompt_contract_sha256
    assert original.content_sha256 != changed.content_sha256


def test_plan_hash_binds_the_formalizer_card_schema(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = runner.build_source_free_deepseek_plan()
    original_schema = SourceFreeAuthoringCardV1.model_json_schema

    def drifted_schema(**_kwargs: object) -> dict[str, object]:
        schema = original_schema(mode="validation")
        return {**schema, "autolean_test_drift": True}

    monkeypatch.setattr(
        SourceFreeAuthoringCardV1,
        "model_json_schema",
        staticmethod(drifted_schema),
    )

    changed = runner.build_source_free_deepseek_plan()

    assert original.prompt_contract_sha256 != changed.prompt_contract_sha256
    assert original.content_sha256 != changed.content_sha256


def test_run_dispatches_only_one_coordinate_and_a_second_run_does_not_redispatch(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path, "run", approved=True)
    first_transport = RecordingTransport()

    first = runner.execute_source_free_deepseek_operator(
        config,
        environment=_environment(),
        transport=first_transport,
    )
    second = runner.execute_source_free_deepseek_operator(
        config,
        environment=_environment(),
        transport=FailingTransport(),
    )

    assert first.status == second.status == "settled"
    assert len(first_transport.calls) == 1
    request_body = json.loads(first_transport.calls[0][2])
    messages = request_body["messages"]
    assert (
        'schema_version exactly to "autolean.ifem-source-free-authoring-response.v1"'
        in messages[0]["content"]
    )
    stage_input = json.loads(messages[1]["content"])
    assert sorted(stage_input) == ["card", "role", "schema_version"]
    assert stage_input["schema_version"] == "autolean.ifem-source-free-stage-input.v1"
    assert stage_input["role"] == "statement_formalizer"
    assert request_body["response_format"] == {"type": "json_object"}
    assert first.coordinate_count == 1
    assert first.maximum_authorized_provider_attempts == 1
    assert first.actual_provider_dispatch_count_claimed is False
    assert first.private_completion_verified is True
    assert first.private_stage_ledger_commitment_sha256 is not None
    assert first.private_attempt_binding_commitment_sha256 is not None
    assert first.private_completion_binding_commitment_sha256 is not None
    assert first.authority == runner.SourceFreeDeepSeekAuthorityV1()


@pytest.mark.parametrize(
    ("suffix", "file_sha256", "plan_sha256"),
    (
        (
            "d",
            "fcd19ff02662791847113f74c84cb058d6b172cf623184ac44dbeb73f5746449",
            "d1aabcf3e17c17e46d0bdffd5f598629ea1644cea73dff9253ff32260579f7a3",
        ),
        (
            "e",
            "f4b695da857b9a51839631236b3c2729017da4e31a0cdca194b97836112f31d0",
            "458228066bdbb24801d6d6947a4989994ba919a195140f460f2758c3da9452db",
        ),
    ),
)
def test_retained_recovery_reports_are_canonical_and_hash_bound(
    suffix: str,
    file_sha256: str,
    plan_sha256: str,
) -> None:
    path = (
        _REPOSITORY_ROOT
        / "docs"
        / "research"
        / f"ifem-source-free-deepseek-canary-2026-08-01-{suffix}.json"
    )
    raw = path.read_bytes()
    report = runner.SourceFreeDeepSeekPublicReportV1.model_validate_json(raw)

    assert hashlib.sha256(raw).hexdigest() == file_sha256
    assert runner.render_source_free_deepseek_public_report(report) == raw
    assert report.status == "recovered"
    assert report.plan_content_sha256 == plan_sha256
    assert report.private_completion_verified is True


def test_resume_recovers_a_settled_completion_without_api_key_or_provider_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path, "run", approved=True)
    transport = RecordingTransport()
    original_checkpoint = LocalSourceFreeStageLedger._checkpoint
    armed = True

    def crash_after_executor(
        ledger: LocalSourceFreeStageLedger,
        name: str,
        coordinate: SourceFreeStageCoordinateV1,
    ) -> None:
        nonlocal armed
        if armed and name == "executor_returned":
            armed = False
            raise SimulatedProcessCrash(coordinate.coordinate_sha256)
        original_checkpoint(ledger, name, coordinate)

    monkeypatch.setattr(
        LocalSourceFreeStageLedger,
        "_checkpoint",
        crash_after_executor,
    )
    with pytest.raises(SimulatedProcessCrash):
        runner.execute_source_free_deepseek_operator(
            config,
            environment=_environment(),
            transport=transport,
        )
    assert len(transport.calls) == 1

    monkeypatch.setattr(
        runner,
        "_required_api_key",
        lambda _environment: (_ for _ in ()).throw(
            AssertionError("resume must not resolve the DeepSeek API key")
        ),
    )
    resumed = runner.execute_source_free_deepseek_operator(
        _config(tmp_path, "resume"),
        environment={},
        transport=FailingTransport(),
    )

    assert resumed.status == "recovered"
    assert resumed.completion_settlement_observed is True
    assert resumed.private_completion_verified is True
    assert len(transport.calls) == 1


def test_settled_response_contract_failure_is_reported_without_redispatch(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path, "run", approved=True)
    transport = RecordingTransport(response_text='{"unexpected":true}')

    failed = runner.execute_source_free_deepseek_operator(
        config,
        environment=_environment(),
        transport=transport,
    )
    resumed = runner.execute_source_free_deepseek_operator(
        _config(tmp_path, "resume"),
        environment={},
        transport=FailingTransport(),
    )

    assert failed.status == resumed.status == "reconciliation_required"
    assert failed.failure_class == resumed.failure_class == "settled_completion_rejected"
    assert failed.attempt_binding_observed is True
    assert failed.completion_settlement_observed is True
    assert failed.private_completion_verified is False
    assert len(transport.calls) == 1


def test_subprocess_resume_rebuilds_keys_and_recovers_without_provider_or_api_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path, "run", approved=True)
    transport = RecordingTransport()
    original_checkpoint = LocalSourceFreeStageLedger._checkpoint
    armed = True

    def crash_after_executor(
        ledger: LocalSourceFreeStageLedger,
        name: str,
        coordinate: SourceFreeStageCoordinateV1,
    ) -> None:
        nonlocal armed
        if armed and name == "executor_returned":
            armed = False
            raise SimulatedProcessCrash(coordinate.coordinate_sha256)
        original_checkpoint(ledger, name, coordinate)

    monkeypatch.setattr(LocalSourceFreeStageLedger, "_checkpoint", crash_after_executor)
    with pytest.raises(SimulatedProcessCrash):
        runner.execute_source_free_deepseek_operator(
            config,
            environment=_environment(),
            transport=transport,
        )
    assert len(transport.calls) == 1

    child_environment = dict(os.environ)
    child_environment.pop("AUTOLEAN_DEEPSEEK_API_KEY", None)
    completed = subprocess.run(
        (
            sys.executable,
            str(_REPOSITORY_ROOT / "scripts" / "ifem_source_free_model_work.py"),
            "resume",
            "--state-root",
            str(config.state_root),
            "--private-root",
            str(config.private_root),
            "--run-label",
            config.run_label,
        ),
        cwd=_REPOSITORY_ROOT,
        env=child_environment,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert report["status"] == "recovered"
    assert report["private_completion_verified"] is True
    assert report["actual_provider_dispatch_count_claimed"] is False
    assert _RAW_RESPONSE not in completed.stdout
    assert _DEMO_CREDENTIAL not in completed.stdout


def test_admission_replays_the_same_persisted_attestation_for_one_work_bundle(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path, "run", approved=True)
    plan = runner.build_source_free_deepseek_plan()
    runtime = runner._prepare_runtime(
        config,
        plan,
        mode="run",
        environment=_environment(),
        transport=FailingTransport(),
    )
    prepared = runtime.sidecar.prepare(runtime.coordinate, runtime.seed_item)

    first = runtime.admission_resolver.admit_model_work(prepared.work_bundle)
    second = runtime.admission_resolver.admit_model_work(prepared.work_bundle)

    assert first == second
    assert first.evidence_identity == model_work_admission_evidence_identity(prepared.work_bundle)


def test_public_stdout_never_discloses_raw_response_api_key_or_operator_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = _config(tmp_path, "run", approved=True)
    monkeypatch.setenv("AUTOLEAN_DEEPSEEK_API_KEY", _DEMO_CREDENTIAL)
    transport = RecordingTransport()
    monkeypatch.setattr(runner, "HttpxResponsesTransport", lambda: transport)

    assert (
        runner.main(
            [
                "run",
                "--operator-approved",
                "--state-root",
                str(config.state_root),
                "--private-root",
                str(config.private_root),
                "--run-label",
                config.run_label,
            ]
        )
        == 0
    )
    rendered = capsys.readouterr().out.encode("ascii")

    assert _DEMO_CREDENTIAL.encode("ascii") not in rendered
    assert _RAW_RESPONSE.encode("ascii") not in rendered
    assert str(config.state_root).encode("utf-8") not in rendered
    assert str(config.private_root).encode("utf-8") not in rendered
    for forbidden in (
        b'"prompt"',
        b'"raw_response"',
        b'"secret"',
        b'"state_root"',
        b'"private_root"',
    ):
        assert forbidden not in rendered


def test_report_reads_only_redacted_state_summary(tmp_path: Path) -> None:
    config = _config(tmp_path, "run", approved=True)
    transport = RecordingTransport()
    settled = runner.execute_source_free_deepseek_operator(
        config,
        environment=_environment(),
        transport=transport,
    )
    database = config.state_root / "control-plane.sqlite3"
    before = hashlib.sha256(database.read_bytes()).hexdigest()

    report = runner.execute_source_free_deepseek_operator(
        _config(tmp_path, "report"),
        environment={},
        transport=FailingTransport(),
    )
    after = hashlib.sha256(database.read_bytes()).hexdigest()

    assert settled.status == "settled"
    assert report.status == "report_ready"
    assert report.attempt_binding_observed is True
    assert report.completion_settlement_observed is True
    assert report.private_completion_verified is False
    assert report.private_stage_ledger_commitment_sha256 is None
    assert len(transport.calls) == 1
    assert after == before
