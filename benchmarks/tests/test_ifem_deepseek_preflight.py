"""Zero-network tests for the iFEM DeepSeek preflight adapter."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest
from autolean_contracts import (
    HashKindV1,
    canonical_json_bytes,
    digest_bytes,
    outbound_request_body_binding,
)
from autolean_prover.providers import Capability

from benchmarks.ifem_deepseek_preflight import (
    IFEMDeepSeekPreflightError,
    build_ifem_deepseek_preflight,
    render_ifem_deepseek_preflight_report,
)
from benchmarks.ifem_synthetic_role_bridge import execute
from benchmarks.ifem_synthetic_role_fixture import build_ifem_synthetic_role_fixture
from benchmarks.tests.test_ifem_synthetic_role_fixture import _corpus


def _fixture() -> Any:
    return build_ifem_synthetic_role_fixture(_corpus(), operator_seed=b"deepseek-preflight-seed")


def test_preflight_builds_sixteen_real_provider_bodies_without_network() -> None:
    fixture = _fixture()
    bundle = build_ifem_deepseek_preflight(fixture)

    assert bundle.report.case_count == 16
    assert bundle.report.role_counts == {
        "statement_formalizer": 8,
        "fidelity_reviewer": 4,
        "cheating_supervisor": 4,
    }
    assert bundle.adapter.network_call_count == 0
    assert bundle.report.authority.api_key_resolved is False
    assert bundle.report.authority.network_execution_authorized is False
    assert bundle.report.authority.network_call_performed is False
    for prepared in bundle.prepared:
        assert prepared.body_binding == outbound_request_body_binding(prepared.body)
        assert b'"model":"deepseek-v4-pro"' in prepared.body
        assert b'"thinking":{"type":"enabled"}' in prepared.body
        assert b'"max_tokens":256' in prepared.body
        assert b'"reasoning_effort":"high"' in prepared.body
        assert prepared.request.max_input_tokens == 2048
        assert Capability.USAGE_ACCOUNTING in prepared.request.required_capabilities
        assert b"AUTOLEAN_DEEPSEEK_API_KEY" not in prepared.body
        assert b"Authorization" not in prepared.body

    rendered = render_ifem_deepseek_preflight_report(bundle.report, fixture=fixture)
    assert b'"prompt":' not in rendered
    assert b"AutoLean project-authored calibration task" not in rendered
    assert b"api_key" in rendered
    assert b"sk-" not in rendered


def test_preflight_adapter_refuses_execution_before_transport() -> None:
    bundle = build_ifem_deepseek_preflight(_fixture())
    with pytest.raises(IFEMDeepSeekPreflightError, match="execution is disabled"):
        execute(bundle.prepared[0], bundle.adapter)
    assert bundle.adapter.network_call_count == 0


def test_preflight_report_rebuild_rejects_self_hashed_tamper() -> None:
    fixture = _fixture()
    bundle = build_ifem_deepseek_preflight(fixture)
    payload = bundle.report.model_dump(mode="json")
    payload["provider_id"] = "deepseek"
    cases = cast(list[object], payload["cases"])
    first = cast(dict[str, object], cases[0])
    binding = cast(dict[str, object], first["request_body_binding"])
    digest = cast(dict[str, object], binding["body_hash"])
    digest["value"] = "f" * 64
    payload["content_sha256"] = digest_bytes(
        HashKindV1.VERIFICATION_EVIDENCE,
        canonical_json_bytes(
            {key: value for key, value in payload.items() if key != "content_sha256"}
        ),
    ).value
    forged = cast(Any, type(bundle.report)).model_validate(payload)
    with pytest.raises(IFEMDeepSeekPreflightError, match="differs"):
        render_ifem_deepseek_preflight_report(forged, fixture=fixture)


def test_preflight_rejects_non_absolute_or_missing_profile(tmp_path: Path) -> None:
    fixture = _fixture()
    with pytest.raises(IFEMDeepSeekPreflightError, match="absolute"):
        build_ifem_deepseek_preflight(fixture, profile_path=Path("profile.json"))
    with pytest.raises(IFEMDeepSeekPreflightError, match="unavailable"):
        build_ifem_deepseek_preflight(
            fixture,
            profile_path=(tmp_path / "missing.json").resolve(),
        )


def test_public_report_is_canonical_and_contains_only_digest_cases() -> None:
    fixture = _fixture()
    report = build_ifem_deepseek_preflight(fixture).report
    rendered = render_ifem_deepseek_preflight_report(report, fixture=fixture)
    assert rendered == canonical_json_bytes(report.model_dump(mode="json")) + b"\n"
    assert all(case.request_body_binding.body_size_bytes > 0 for case in report.cases)
