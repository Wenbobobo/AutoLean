from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path

import httpx
import pytest
from autolean_prover.providers.operator_profile import ChatCompletionsOperatorProfileV1

from scripts import deepseek_live_baseline as live
from scripts import deepseek_role_baseline as role_runner


def _profile() -> ChatCompletionsOperatorProfileV1:
    return ChatCompletionsOperatorProfileV1.from_json_file(live._PROFILE_PATH)


def _config(tmp_path: Path, *, maximum: int = 100_000) -> live.LiveBaselineConfig:
    return live.LiveBaselineConfig(
        state_root=(tmp_path / "state").resolve(),
        private_root=(tmp_path / "private").resolve(),
        run_id="deepseek-live-test-v1",
        max_total_authorized_cost_microusd=maximum,
        exercise_recovery=True,
    )


def _legacy_scored_role_observation() -> dict[str, object]:
    evidence_path = (
        live._REPOSITORY_ROOT
        / "docs"
        / "research"
        / "deepseek-role-json-contract-calibration-2026-07-29.json"
    )
    legacy = json.loads(evidence_path.read_text(encoding="utf-8"))["roles"]
    operator_keys = set(role_runner.DeepSeekRolePublicReportV2.model_fields)
    operator_report = role_runner.DeepSeekRolePublicReportV2.model_validate(
        {key: legacy[key] for key in operator_keys}
    )
    return live.DeepSeekRoleScoredObservationV1(
        operator_report=operator_report,
        provider_call_count=legacy["provider_call_count"],
        evaluation=legacy["evaluation"],
        failure_taxonomy=legacy["failure_taxonomy"],
        harness=live.DeepSeekRoleHarnessV1(),
        failure_partition=live.DeepSeekRoleFailurePartitionV1(
            schema_rejections=5,
            semantic_mismatches=4,
            passed=1,
        ),
    ).model_dump(mode="json")


def test_secret_reference_accepts_one_named_key_without_printing_it(tmp_path: Path) -> None:
    marker = "live-secret-marker-" + ("a" * 32)
    reference = tmp_path / "operator-secret.txt"
    reference.write_text(f"AUTOLEAN_DEEPSEEK_API_KEY={marker}\n", encoding="utf-8")

    assert live._required_secret(reference) == marker


def test_secret_reference_rejects_ambiguous_or_multiline_values(tmp_path: Path) -> None:
    reference = tmp_path / "operator-secret.txt"
    reference.write_text(
        "AUTOLEAN_DEEPSEEK_API_KEY=" + ("a" * 32) + "\nDEEPSEEK_API_KEY=" + ("b" * 32) + "\n",
        encoding="utf-8",
    )

    try:
        live._required_secret(reference)
    except live.OperatorSecretUnavailable:
        pass
    else:
        raise AssertionError("ambiguous key references must be rejected")

    reference.write_text(
        "AUTOLEAN_DEEPSEEK_API_KEY=" + ("a" * 32) + "\nUNRELATED_SECRET=" + ("b" * 32) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(live.OperatorSecretUnavailable):
        live._required_secret(reference)

    reference.write_text(
        "AUTOLEAN_DEEPSEEK_API_KEY=" + ("a" * 32) + "\nMODEL=deepseek-v4-pro\n",
        encoding="utf-8",
    )
    assert live._required_secret(reference) == "a" * 32


def test_catalog_probe_confirms_only_the_exact_profile_model() -> None:
    profile = _profile()
    seen_headers: dict[str, str] = {}

    def get(url: str, headers: Mapping[str, str], timeout_seconds: float) -> httpx.Response:
        assert url == "https://api.deepseek.com/models"
        assert timeout_seconds == 20.0
        seen_headers.update(headers)
        return httpx.Response(
            200,
            json={"object": "list", "data": [{"id": profile.model_id}]},
        )

    probe = live.probe_model_catalog(profile, api_key="x" * 32, get=get)

    assert probe.status == "target_model_listed"
    assert probe.target_model_listed is True
    assert seen_headers["Authorization"].startswith("Bearer ")
    assert probe.public_dict() == {
        "status": "target_model_listed",
        "target_model_listed": True,
        "evidence_class": "authenticated_model_catalog_identity_only",
        "capability_admission": "forbidden",
    }


def test_catalog_probe_stops_when_target_model_is_not_listed() -> None:
    profile = _profile()

    def get(_url: str, _headers: Mapping[str, str], _timeout_seconds: float) -> httpx.Response:
        return httpx.Response(200, json={"object": "list", "data": [{"id": "other-model"}]})

    probe = live.probe_model_catalog(profile, api_key="x" * 32, get=get)

    assert probe.status == "target_model_not_listed"
    assert probe.target_model_listed is False


def test_catalog_failure_is_redacted_and_prevents_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = "live-secret-marker-" + ("a" * 32)
    reference = tmp_path / "operator-secret.txt"
    reference.write_text(marker, encoding="utf-8")
    called = False

    def no_generation(**_kwargs: object) -> dict[str, object]:
        nonlocal called
        called = True
        raise AssertionError("generation must not start after catalog refusal")

    def get(_url: str, _headers: Mapping[str, str], _timeout_seconds: float) -> httpx.Response:
        return httpx.Response(401, json={"error": {"message": marker}})

    monkeypatch.setattr(live, "_run_canary", no_generation)
    report = live.execute_live_baseline(_config(tmp_path), secret_file=reference, catalog_get=get)
    public = json.dumps(report, sort_keys=True)

    assert report["status"] == "execution_refused"
    assert report["stage"] == "catalog"
    assert report["failure_class"] == "catalog_http_401"
    assert called is False
    assert marker not in public
    assert "api.deepseek.com" not in public


def test_budget_rejection_happens_before_secret_or_catalog_io(tmp_path: Path) -> None:
    calls = 0

    def get(_url: str, _headers: Mapping[str, str], _timeout_seconds: float) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"data": []})

    report = live.execute_live_baseline(
        _config(tmp_path, maximum=1),
        secret_file=tmp_path / "absent-secret.txt",
        catalog_get=get,
    )

    assert report == {
        "schema_version": "autolean.deepseek-live-baseline.v1",
        "status": "execution_refused",
        "stage": "preflight",
        "failure_class": "local_preflight_rejected",
        "authority_status": "non-promotable-operator-observation",
        "promotion_eligible": False,
        "role_floor_admission": "forbidden",
    }
    assert calls == 0


def test_512_output_budget_is_frozen_into_role_plan_and_static_cost(tmp_path: Path) -> None:
    profile = _profile()
    base = _config(tmp_path, maximum=102_400)
    config = live.LiveBaselineConfig(
        state_root=base.state_root,
        private_root=base.private_root,
        run_id=base.run_id,
        max_total_authorized_cost_microusd=102_400,
        exercise_recovery=False,
        max_output_tokens=512,
        run_canary=False,
    )

    role_config = live._validate_config(config, profile)
    plan = role_runner.build_deepseek_role_plan(role_config)

    assert role_config.max_output_tokens == 512
    assert role_config.max_cost_microusd_per_trial == 10_240
    assert live._role_static_cost(512) == 102_400
    assert {trial.cell.budget.max_output_tokens for trial in plan.trials} == {512}


def test_512_output_budget_rejects_the_256_default_cost_ceiling(tmp_path: Path) -> None:
    base = _config(tmp_path)
    config = live.LiveBaselineConfig(
        state_root=base.state_root,
        private_root=base.private_root,
        run_id=base.run_id,
        max_total_authorized_cost_microusd=100_000,
        exercise_recovery=False,
        max_output_tokens=512,
        run_canary=False,
    )

    with pytest.raises(live.LiveBaselineError, match="approved bound"):
        live._validate_config(config, _profile())


def test_role_only_calibration_skips_canary_and_caps_generation_at_ten(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = "live-secret-marker-" + ("a" * 32)
    reference = tmp_path / "operator-secret.txt"
    reference.write_text(marker, encoding="utf-8")
    config = _config(tmp_path)
    config = live.LiveBaselineConfig(
        state_root=config.state_root,
        private_root=config.private_root,
        run_id=config.run_id,
        max_total_authorized_cost_microusd=config.max_total_authorized_cost_microusd,
        exercise_recovery=False,
        run_canary=False,
    )

    def get(_url: str, _headers: Mapping[str, str], _timeout_seconds: float) -> httpx.Response:
        return httpx.Response(200, json={"data": [{"id": _profile().model_id}]})

    def forbidden_canary(**_kwargs: object) -> dict[str, object]:
        raise AssertionError("role-only calibration must not call the canary")

    monkeypatch.setattr(live, "_run_canary", forbidden_canary)
    monkeypatch.setattr(live, "_run_roles", lambda **_kwargs: _legacy_scored_role_observation())

    report = live.execute_live_baseline(config, secret_file=reference, catalog_get=get)

    assert report["status"] == "settled"
    assert report["schema_version"] == "autolean.deepseek-live-baseline.v2"
    assert (
        live.DeepSeekLiveBaselineSettledReportV2.model_validate(report).model_dump(mode="json")
        == report
    )
    assert report["canary"] == {
        "schema_version": "autolean.deepseek-live-canary-not-run.v1",
        "status": "not_run",
        "reason": "role_calibration_only",
    }
    budget = report["budget"]
    assert isinstance(budget, dict)
    assert budget["provider_generation_request_ceiling"] == 10


def test_public_report_writer_is_limited_to_research_json(tmp_path: Path) -> None:
    report = {"schema_version": "safe", "status": "execution_refused"}
    allowed = live._REPOSITORY_ROOT / "docs" / "research" / ".deepseek-live-test.json"
    try:
        live._write_public_report(allowed, report)
        assert json.loads(allowed.read_text(encoding="ascii")) == report
    finally:
        allowed.unlink(missing_ok=True)

    try:
        live._write_public_report(tmp_path / "outside.json", report)
    except live.LiveBaselineError:
        pass
    else:
        raise AssertionError("public evidence must remain under docs/research")


def test_checked_in_json_contract_evidence_is_redacted_and_budget_saturated() -> None:
    """Keep the dated public observation internally consistent without replaying an API call."""

    evidence_path = (
        live._REPOSITORY_ROOT
        / "docs"
        / "research"
        / "deepseek-role-json-contract-calibration-2026-07-29.json"
    )
    report = json.loads(evidence_path.read_text(encoding="utf-8"))
    roles = report["roles"]
    budget = roles["per_trial_budget"]
    taxonomy = roles["failure_taxonomy"]
    evaluation = roles["evaluation"]

    assert report["authority_status"] == "non-promotable-operator-observation"
    assert report["promotion_eligible"] is False
    assert report["role_floor_admission"] == "forbidden"
    assert roles["score_status"] == "not_computed"
    assert budget["max_output_tokens"] == 256
    assert all(item["usage"]["output_tokens"] == "256_1023" for item in roles["roles"])
    passed_by_role = {item["role"]: item["passed"] for item in evaluation["role_metrics"]}
    for metric in taxonomy["role_metrics"]:
        assert metric["passed"] == passed_by_role[metric["role"]]
        assert metric["passed"] + metric["schema_rejections"] + metric["semantic_mismatches"] == 2
    assert sum(item["passed"] for item in taxonomy["role_metrics"]) == 1
    assert sum(item["schema_rejections"] for item in taxonomy["role_metrics"]) == 5
    assert sum(item["semantic_mismatches"] for item in taxonomy["role_metrics"]) == 4
    public = json.dumps(report, sort_keys=True)
    for forbidden in (
        "https://",
        "private_manifest_handle",
        "completion-manifest-handles-v2",
        "completion-manifest-run-index-v2",
        "expected_output",
        "reasoning_content",
    ):
        assert forbidden not in public


def test_checked_in_512_evidence_is_bound_to_ledger_audit() -> None:
    report_path = (
        live._REPOSITORY_ROOT / "docs" / "research" / "deepseek-live-baseline-2026-07-30-512-a.json"
    )
    ledger_path = report_path.with_name("deepseek-live-baseline-2026-07-30-512-a-ledger-audit.json")
    report_bytes = report_path.read_bytes()
    report = json.loads(report_bytes)
    ledger = json.loads(ledger_path.read_text(encoding="ascii"))

    assert report["status"] == "settled"
    assert report["roles"]["per_trial_budget"]["max_output_tokens"] == 512
    assert report["roles"]["failure_partition"] == {
        "passed": 2,
        "schema_rejections": 1,
        "semantic_mismatches": 7,
        "transport_failures": 0,
    }
    assert ledger["report_sha256"] == hashlib.sha256(report_bytes).hexdigest()
    assert ledger["provider_call_count"] == report["roles"]["provider_call_count"] == 10
    assert ledger["reserved_events"] == ledger["settled_events"] == 10
    assert ledger["completion_receipts"] == ledger["completion_settlements"] == 10
    assert ledger["unique_settled_reservations"] == 10
    assert ledger["saturated_completion_count"] == 1
    assert ledger["automatic_retry_observed"] is False


def test_checked_in_512_v2_evidence_is_strict_and_ledger_bound() -> None:
    report_path = (
        live._REPOSITORY_ROOT
        / "docs"
        / "research"
        / "deepseek-live-baseline-2026-07-30-512-b-v2.json"
    )
    ledger_path = report_path.with_name(
        "deepseek-live-baseline-2026-07-30-512-b-v2-ledger-audit.json"
    )
    report_bytes = report_path.read_bytes()
    report = live.DeepSeekLiveBaselineSettledReportV2.model_validate_json(report_bytes)
    ledger = json.loads(ledger_path.read_text(encoding="ascii"))

    assert report.roles.operator_report.per_trial_budget is not None
    assert report.roles.operator_report.per_trial_budget.max_output_tokens == 512
    assert report.roles.failure_partition.model_dump(exclude={"schema_version"}) == {
        "passed": 2,
        "schema_rejections": 1,
        "semantic_mismatches": 7,
        "transport_failures": 0,
    }
    assert ledger["report_sha256"] == hashlib.sha256(report_bytes).hexdigest()
    assert ledger["provider_call_count"] == report.roles.provider_call_count == 10
    assert ledger["reserved_events"] == ledger["settled_events"] == 10
    assert ledger["completion_receipts"] == ledger["completion_settlements"] == 10
    assert ledger["unique_settled_reservations"] == 10
    assert ledger["saturated_completion_count"] == 1
    assert ledger["automatic_retry_observed"] is False


def test_v2_report_rejects_tampered_per_trial_static_cost() -> None:
    report_path = (
        live._REPOSITORY_ROOT
        / "docs"
        / "research"
        / "deepseek-live-baseline-2026-07-30-512-b-v2.json"
    )
    payload = json.loads(report_path.read_text(encoding="ascii"))
    payload["roles"]["operator_report"]["per_trial_budget"]["max_cost_microusd"] = 1

    with pytest.raises(ValueError, match="budget does not match"):
        live.DeepSeekLiveBaselineSettledReportV2.model_validate(payload)


def test_v2_report_rejects_evaluation_taxonomy_pass_disagreement() -> None:
    report_path = (
        live._REPOSITORY_ROOT
        / "docs"
        / "research"
        / "deepseek-live-baseline-2026-07-30-512-b-v2.json"
    )
    payload = json.loads(report_path.read_text(encoding="ascii"))
    evaluation = payload["roles"]["evaluation"]
    for trial in evaluation["trials"]:
        if trial["role"] == "task_allocator":
            trial["passed"] = False
            trial["score_micros"] = 0
    for metric in evaluation["role_metrics"]:
        if metric["role"] == "task_allocator":
            metric["passed"] = 0
            metric["pass_rate_ppm"] = 0
            metric["mean_score_micros"] = 0

    with pytest.raises(ValueError, match="role pass counts disagree"):
        live.DeepSeekLiveBaselineSettledReportV2.model_validate(payload)
