from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from benchmarks.fate_execution import (
    FateExecutionError,
    selected_fate_problems,
    validate_operator_private_root,
)
from scripts.fate_execution_preflight import (
    FateExecutionPreflightError,
    build_preflight_summary,
    parse_wsl_audit,
)


def _audit() -> dict[str, object]:
    return {
        "schema_version": "autolean.fate-wsl-runtime-result.v1",
        "status": "verified",
        "runtime_state_sha256": "a" * 64,
        "audit_sha256": "b" * 64,
        "source_count": 350,
        "dependency_count": 42,
        "network_accessed": False,
        "contains_absolute_paths": False,
    }


def test_verified_wsl_audit_accepts_only_redacted_exact_schema() -> None:
    parsed = parse_wsl_audit(json.dumps(_audit(), sort_keys=True).encode("ascii"))

    assert parsed["source_count"] == 350
    assert parsed["network_accessed"] is False
    assert parsed["contains_absolute_paths"] is False


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("source_count", 349),
        ("dependency_count", 0),
        ("network_accessed", True),
        ("contains_absolute_paths", True),
        ("audit_sha256", "not-a-digest"),
    ),
)
def test_wsl_audit_rejects_unverified_or_leaking_records(
    field: str,
    value: object,
) -> None:
    audit = _audit()
    audit[field] = value

    with pytest.raises(FateExecutionPreflightError, match="wsl_audit_schema"):
        parse_wsl_audit(json.dumps(audit).encode("ascii"))


def test_preflight_is_always_non_executing_and_tier_separated() -> None:
    problems = selected_fate_problems("model-compare-90")

    summary = build_preflight_summary(
        suite="model-compare-90",
        problems=problems,
        fate_manifest_hash="c" * 64,
        split_manifest_hash="d" * 64,
        environment_hash="e" * 64,
        provider_profile_hash="f" * 64,
        provider_id="deepseek",
        model_id="deepseek-v4-pro",
        wsl_audit=_audit(),
        operator_approved=True,
    )

    assert summary["status"] == "blocked"
    assert summary["execution_authorized"] is False
    assert summary["live_execution_started"] is False
    assert summary["network_calls"] == 0
    assert summary["provider_calls"] == 0
    assert summary["verifier_calls"] == 0
    assert summary["tier_counts"] == {"M": 30, "H": 30, "X": 30}
    assert summary["blockers"] == [
        "model_work_admission_authority_required",
        "model_execution_authority_required",
        "production_verifier_authority_required",
        "wsl_oci_verifier_adapter_required",
    ]


def test_preflight_keeps_operator_approval_as_an_explicit_blocker() -> None:
    summary = build_preflight_summary(
        suite="regression-48",
        problems=selected_fate_problems("regression-48"),
        fate_manifest_hash="c" * 64,
        split_manifest_hash="d" * 64,
        environment_hash="e" * 64,
        provider_profile_hash="f" * 64,
        provider_id="deepseek",
        model_id="deepseek-v4-pro",
        wsl_audit=_audit(),
        operator_approved=False,
    )

    assert cast(list[str], summary["blockers"])[0] == "operator_approval_required"


def test_private_state_root_must_be_outside_repository(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()

    with pytest.raises(FateExecutionError, match="outside the repository"):
        validate_operator_private_root(
            repository / "private",
            repository_root=repository,
        )

    assert (
        validate_operator_private_root(
            tmp_path / "operator-private",
            repository_root=repository,
        )
        == (tmp_path / "operator-private").resolve()
    )
