from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

import pytest

from scripts import deepseek_output_budget_ablation as ablation

_API_SECRET = "api-secret-marker-" + ("a" * 40)
_MANIFEST_SECRET = "manifest-secret-marker-" + ("b" * 40)
_PRIVATE_RESPONSE_MARKER = "PRIVATE_ABLATION_RESPONSE"


def _clock() -> datetime:
    return datetime(2026, 7, 29, 12, 0, tzinfo=UTC)


class SaturatingTransport:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def post_json(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        payload: Mapping[str, object],
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        self.calls.append(
            {
                "url": url,
                "headers": dict(headers),
                "payload": dict(payload),
                "timeout_seconds": timeout_seconds,
            }
        )
        output_limit = payload["max_tokens"]
        assert isinstance(output_limit, int)
        return {
            "id": f"private-ablation-{len(self.calls)}",
            "model": "deepseek-v4-pro",
            "choices": [{"message": {"content": _PRIVATE_RESPONSE_MARKER + f"_{len(self.calls)}"}}],
            "usage": {
                "prompt_tokens": 20,
                "prompt_cache_hit_tokens": 2,
                "completion_tokens": output_limit,
            },
        }


class FailingTransport:
    def __init__(self) -> None:
        self.calls: list[int] = []

    def post_json(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        payload: Mapping[str, object],
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        del url, headers, payload, timeout_seconds
        self.calls.append(1)
        raise RuntimeError("do-not-publish-private-provider-error")


def _environment() -> dict[str, str]:
    return {
        "AUTOLEAN_DEEPSEEK_API_KEY": _API_SECRET,
        "AUTOLEAN_ROLE_MANIFEST_HMAC_KEY": _MANIFEST_SECRET,
    }


def _config(
    tmp_path: Path,
    mode: str,
    *,
    candidate_output_tokens: int = 512,
) -> ablation.DeepSeekOutputBudgetAblationConfig:
    state_parent = (tmp_path / f"{mode}-state-parent").resolve()
    private_parent = (tmp_path / f"{mode}-private-parent").resolve()
    state_parent.mkdir()
    private_parent.mkdir()
    return ablation.DeepSeekOutputBudgetAblationConfig(
        mode=mode,  # type: ignore[arg-type]
        run_id=f"ablation-{mode}-v1",
        state_parent=state_parent,
        private_parent=private_parent,
        max_cost_microusd_per_trial=100_000,
        candidate_output_tokens=candidate_output_tokens,  # type: ignore[arg-type]
        operator_approved=True,
    )


def test_operator_secret_reference_stays_in_process_memory(tmp_path: Path) -> None:
    secret_file = tmp_path / "llm.txt"
    secret_file.write_text(
        f"API_url=https://api.deepseek.com\nAPI_key={_API_SECRET}\n",
        encoding="utf-8",
    )

    environment = ablation._operator_environment_from_secret_file(secret_file)

    assert environment["AUTOLEAN_DEEPSEEK_API_KEY"] == _API_SECRET
    assert environment["AUTOLEAN_ROLE_MANIFEST_HMAC_KEY"] != _API_SECRET
    assert len(environment["AUTOLEAN_ROLE_MANIFEST_HMAC_KEY"]) >= 48
    assert str(secret_file) not in json.dumps(environment)


def test_plan_is_write_free_and_only_changes_the_frozen_output_limit(tmp_path: Path) -> None:
    config = _config(tmp_path, "plan", candidate_output_tokens=1024)

    report = ablation.execute_deepseek_output_budget_ablation(config, environment={})
    arms = ablation.build_deepseek_output_budget_ablation_plan(config)

    assert report.status == "planned"
    assert report.observed_provider_call_count == 0
    assert report.provider_call_ceiling == 20
    assert report.changed_dimensions == ("max_output_tokens",)
    assert [arm.output_token_limit for arm in report.arms] == [256, 1024]
    assert all(arm.status == "planned" for arm in report.arms)
    assert all(not arm.config.state_root.exists() for arm in arms)
    assert all(not arm.config.private_root.exists() for arm in arms)
    for baseline_cell, candidate_cell in zip(
        arms[0].plan.suite.matrix.cells,
        arms[1].plan.suite.matrix.cells,
        strict=True,
    ):
        baseline = baseline_cell.model_dump(mode="json")
        candidate = candidate_cell.model_dump(mode="json")
        assert baseline.pop("budget")["max_output_tokens"] == 256
        assert candidate.pop("budget")["max_output_tokens"] == 1024
        assert baseline == candidate


def test_run_is_twenty_calls_and_reports_saturation_without_scores_or_private_data(
    tmp_path: Path,
) -> None:
    transport = SaturatingTransport()
    config = _config(tmp_path, "run")

    report = ablation.execute_deepseek_output_budget_ablation(
        config,
        environment=_environment(),
        transport=transport,
        clock=_clock,
    )

    assert report.status == "settled"
    assert report.comparison_status == "budget_saturation_only"
    assert report.observed_provider_call_count == 20
    assert len(transport.calls) == 20
    output_limits: list[object] = []
    for call in transport.calls:
        payload = call["payload"]
        assert isinstance(payload, Mapping)
        output_limits.append(payload["max_tokens"])
    assert output_limits == ([256] * 10) + ([512] * 10)
    assert [arm.saturated_trial_count for arm in report.arms] == [10, 10]
    assert all(
        sum(item.saturated_trial_count for item in arm.role_saturations) == 10
        for arm in report.arms
    )
    assert report.comparison is not None
    assert report.comparison.candidate_minus_baseline_saturated_trials == 0

    public = json.dumps(report.model_dump(mode="json"), sort_keys=True)
    for forbidden in (
        _PRIVATE_RESPONSE_MARKER,
        _API_SECRET,
        _MANIFEST_SECRET,
        "api.deepseek.com",
        str(config.state_parent),
        str(config.private_parent),
        "private_manifest_handle",
        "score",
        "semantic_exact",
        "expected_output",
    ):
        assert forbidden not in public


def test_failed_control_skips_candidate_without_retry_or_provider_substitution(
    tmp_path: Path,
) -> None:
    transport = FailingTransport()
    config = _config(tmp_path, "run")

    report = ablation.execute_deepseek_output_budget_ablation(
        config,
        environment=_environment(),
        transport=transport,
        clock=_clock,
    )

    assert report.status == "reconciliation_required"
    assert report.observed_provider_call_count == 1
    assert len(transport.calls) == 1
    assert report.arms[0].status == "reconciliation_required"
    assert report.arms[1].status == "skipped"
    assert report.comparison is None
    assert report.automatic_retry_permitted is False


def test_checked_in_settled_evidence_is_bound_to_ledger_audit() -> None:
    repository = Path(__file__).resolve().parents[2]
    report_path = (
        repository
        / "docs"
        / "research"
        / "deepseek-output-budget-ablation-2026-07-30-settled-a.json"
    )
    ledger_path = report_path.with_name(
        "deepseek-output-budget-ablation-2026-07-30-settled-a-ledger-audit.json"
    )
    report_bytes = report_path.read_bytes()
    report = ablation.DeepSeekOutputBudgetAblationReportV1.model_validate_json(report_bytes)
    ledger = json.loads(ledger_path.read_text(encoding="ascii"))

    assert report.status == "settled"
    assert report.observed_provider_call_count == 20
    assert [arm.saturated_trial_count for arm in report.arms] == [4, 1]
    assert ledger["report_sha256"] == hashlib.sha256(report_bytes).hexdigest()
    assert ledger["experiment_binding_hash"] == report.experiment_binding_hash
    assert ledger["provider_call_count"] == report.observed_provider_call_count
    assert ledger["automatic_retry_observed"] is False
    assert all(
        arm["reserved_events"]
        == arm["settled_events"]
        == arm["completion_receipts"]
        == arm["completion_settlements"]
        == arm["unique_settled_reservations"]
        == 10
        for arm in ledger["arms"]
    )


def test_cli_refusal_exits_two_and_keeps_stdout_redacted_json(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state_parent = (tmp_path / "state-parent").resolve()
    private_parent = (tmp_path / "private-parent").resolve()
    state_parent.mkdir()
    private_parent.mkdir()
    unsafe_run_id = "ablation-../private"

    exit_code = ablation.main(
        [
            "plan",
            "--operator-approved",
            "--state-parent",
            str(state_parent),
            "--private-parent",
            str(private_parent),
            "--run-id",
            unsafe_run_id,
            "--candidate-output-tokens",
            "512",
            "--max-cost-microusd-per-trial",
            "10240",
        ]
    )

    public = capsys.readouterr().out
    report = json.loads(public)
    assert exit_code == 2
    assert report["status"] == "execution_refused"
    assert report["run_id"] == "unavailable"
    assert unsafe_run_id not in public
    assert str(state_parent) not in public
    assert str(private_parent) not in public


def test_cli_reconciliation_required_exits_two_and_keeps_stdout_redacted_json(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_parent = (tmp_path / "state-parent").resolve()
    private_parent = (tmp_path / "private-parent").resolve()
    state_parent.mkdir()
    private_parent.mkdir()
    run_id = "ablation-cli-reconciliation-v1"
    private_marker = "PRIVATE_RECONCILIATION_MARKER"

    def reconciliation_report(
        config: ablation.DeepSeekOutputBudgetAblationConfig,
        *,
        environment: Mapping[str, str] | None = None,
    ) -> ablation.DeepSeekOutputBudgetAblationReportV1:
        del environment
        return ablation.DeepSeekOutputBudgetAblationReportV1(
            mode="run",
            status="reconciliation_required",
            run_id=config.run_id,
            max_cost_microusd_per_trial=config.max_cost_microusd_per_trial,
            observed_provider_call_count=1,
            experiment_binding_hash="0" * 64,
            arms=(
                ablation.DeepSeekOutputBudgetAblationArmV1(
                    output_token_limit=256,
                    status="reconciliation_required",
                    plan_hash="1" * 64,
                    provider_call_count=1,
                    failure_class="network",
                ),
                ablation.DeepSeekOutputBudgetAblationArmV1(
                    output_token_limit=512,
                    status="skipped",
                    plan_hash="2" * 64,
                ),
            ),
            failure_class="network",
        )

    monkeypatch.setattr(ablation, "execute_deepseek_output_budget_ablation", reconciliation_report)
    exit_code = ablation.main(
        [
            "run",
            "--operator-approved",
            "--state-parent",
            str(state_parent),
            "--private-parent",
            str(private_parent),
            "--run-id",
            run_id,
            "--candidate-output-tokens",
            "512",
            "--max-cost-microusd-per-trial",
            "10240",
        ]
    )

    public = capsys.readouterr().out
    report = json.loads(public)
    assert exit_code == 2
    assert report["status"] == "reconciliation_required"
    assert report["failure_class"] == "network"
    assert report["observed_provider_call_count"] == 1
    assert private_marker not in public
    assert str(state_parent) not in public
    assert str(private_parent) not in public
