"""Validate FATE live-execution inputs without model or verifier side effects.

This command deliberately cannot run a benchmark.  It reads only credential-free
configuration and audit records, emits one redacted JSON object, and remains blocked
until the caller injects the actual model capability, trusted work admission, remote
verifier authority, and WSL OCI adapter into ``FateExecutionEngineV1``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final, cast

from autolean_prover.providers.operator_profile import (
    ChatCompletionsOperatorProfileV1,
)

from benchmarks.fate import FateProblemId, Tier
from benchmarks.fate_adapter import FateAdapter
from benchmarks.fate_execution import (
    FateExecutionSuiteV1,
    selected_fate_problems,
    validate_operator_private_root,
    verified_split_manifest_hash,
)

_SCHEMA: Final = "autolean.fate-execution-preflight.v1"
_WSL_SCHEMA: Final = "autolean.fate-wsl-runtime-result.v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TIERS: Final[tuple[Tier, ...]] = ("M", "H", "X")
_LIVE_BLOCKERS: Final[tuple[str, ...]] = (
    "model_work_admission_authority_required",
    "model_execution_authority_required",
    "production_verifier_authority_required",
    "wsl_oci_verifier_adapter_required",
)


class FateExecutionPreflightError(RuntimeError):
    """A credential-free preflight input was absent, malformed, or inconsistent."""


def _strict_object(payload: bytes, *, label: str) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    try:
        loaded = json.loads(payload, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise FateExecutionPreflightError(f"{label}_invalid") from error
    if not isinstance(loaded, dict):
        raise FateExecutionPreflightError(f"{label}_invalid")
    return cast(dict[str, object], loaded)


def parse_wsl_audit(payload: bytes) -> dict[str, object]:
    """Accept exactly the redacted successful audit envelope."""

    audit = _strict_object(payload, label="wsl_audit")
    required = {
        "schema_version",
        "status",
        "runtime_state_sha256",
        "audit_sha256",
        "source_count",
        "dependency_count",
        "network_accessed",
        "contains_absolute_paths",
    }
    if set(audit) != required:
        raise FateExecutionPreflightError("wsl_audit_schema")
    if (
        audit["schema_version"] != _WSL_SCHEMA
        or audit["status"] != "verified"
        or audit["source_count"] != 350
        or isinstance(audit["dependency_count"], bool)
        or not isinstance(audit["dependency_count"], int)
        or audit["dependency_count"] <= 0
        or audit["network_accessed"] is not False
        or audit["contains_absolute_paths"] is not False
    ):
        raise FateExecutionPreflightError("wsl_audit_schema")
    for field in ("runtime_state_sha256", "audit_sha256"):
        value = audit[field]
        if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
            raise FateExecutionPreflightError("wsl_audit_schema")
    return audit


def build_preflight_summary(
    *,
    suite: FateExecutionSuiteV1,
    problems: tuple[FateProblemId, ...],
    fate_manifest_hash: str,
    split_manifest_hash: str,
    environment_hash: str,
    provider_profile_hash: str,
    provider_id: str,
    model_id: str,
    wsl_audit: Mapping[str, object],
    operator_approved: bool,
) -> dict[str, object]:
    """Build the only public preflight projection; it can never claim readiness."""

    for label, value in (
        ("fate_manifest_hash", fate_manifest_hash),
        ("split_manifest_hash", split_manifest_hash),
        ("environment_hash", environment_hash),
        ("provider_profile_hash", provider_profile_hash),
    ):
        if _SHA256.fullmatch(value) is None:
            raise FateExecutionPreflightError(f"{label}_invalid")
    expected = selected_fate_problems(suite)
    if problems != expected:
        raise FateExecutionPreflightError("suite_selection_drift")
    blockers = list(_LIVE_BLOCKERS)
    if operator_approved is not True:
        blockers.insert(0, "operator_approval_required")
    tier_counts = {tier: sum(problem.tier == tier for problem in problems) for tier in _TIERS}
    return {
        "blockers": blockers,
        "execution_authorized": False,
        "fate_manifest_hash": fate_manifest_hash,
        "input_validation": "passed",
        "live_execution_started": False,
        "model_id": model_id,
        "network_calls": 0,
        "phase1_claim_eligible": False,
        "private_artifacts_outside_repository": True,
        "provider_calls": 0,
        "provider_id": provider_id,
        "provider_profile_hash": provider_profile_hash,
        "schema_version": _SCHEMA,
        "split_manifest_hash": split_manifest_hash,
        "status": "blocked",
        "suite": suite,
        "tier_counts": tier_counts,
        "verifier_calls": 0,
        "wsl_audit_sha256": cast(str, wsl_audit["audit_sha256"]),
        "wsl_runtime_state_sha256": cast(
            str,
            wsl_audit["runtime_state_sha256"],
        ),
        "environment_hash": environment_hash,
    }


def inspect_preflight(
    *,
    repository_root: Path,
    checkout: Path,
    manifest: Path,
    expected_manifest_hash: str,
    split_manifest: Path,
    suite: FateExecutionSuiteV1,
    provider_profile: Path,
    environment_hash: str,
    private_state_root: Path,
    wsl_audit_path: Path,
    operator_approved: bool,
) -> dict[str, object]:
    """Read and validate every credential-free live input."""

    if not private_state_root.is_absolute():
        raise FateExecutionPreflightError("private_state_root_must_be_absolute")
    validate_operator_private_root(
        private_state_root,
        repository_root=repository_root,
    )
    if _SHA256.fullmatch(expected_manifest_hash) is None:
        raise FateExecutionPreflightError("fate_manifest_hash_invalid")
    if _SHA256.fullmatch(environment_hash) is None:
        raise FateExecutionPreflightError("environment_hash_invalid")
    adapter = FateAdapter.from_manifest_file(
        checkout,
        manifest,
        expected_manifest_content_hash=expected_manifest_hash,
    )
    problems = selected_fate_problems(suite)
    for problem in problems:
        adapter.task(problem)
    split_hash = verified_split_manifest_hash(split_manifest)
    profile = ChatCompletionsOperatorProfileV1.from_json_file(provider_profile)
    try:
        profile_bytes = provider_profile.read_bytes()
        wsl_bytes = wsl_audit_path.read_bytes()
    except OSError as error:
        raise FateExecutionPreflightError("preflight_input_unreadable") from error
    wsl_audit = parse_wsl_audit(wsl_bytes)
    return build_preflight_summary(
        suite=suite,
        problems=problems,
        fate_manifest_hash=adapter.manifest.content_hash,
        split_manifest_hash=split_hash,
        environment_hash=environment_hash,
        provider_profile_hash=hashlib.sha256(profile_bytes).hexdigest(),
        provider_id=profile.provider_id,
        model_id=profile.model_id,
        wsl_audit=wsl_audit,
        operator_approved=operator_approved,
    )


def _arguments(argv: Sequence[str] | None) -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument(
        "--split-manifest",
        type=Path,
        default=root / "benchmarks" / "fate-splits.v1.json",
    )
    parser.add_argument(
        "--suite",
        choices=("regression-48", "model-compare-90", "FATE-350"),
        default="regression-48",
    )
    parser.add_argument(
        "--provider-profile",
        type=Path,
        default=(
            root / "Prover" / "operator-profiles" / "deepseek-v4-pro.chat-completions.v1.json"
        ),
    )
    parser.add_argument("--environment-hash", required=True)
    parser.add_argument("--private-state-root", required=True, type=Path)
    parser.add_argument("--wsl-audit", required=True, type=Path)
    parser.add_argument("--operator-approved", action="store_true")
    return parser.parse_args(argv)


def _canonical(document: Mapping[str, object]) -> bytes:
    return (
        json.dumps(
            document,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("ascii")


def _blocked(code: str) -> dict[str, object]:
    return {
        "blockers": [code],
        "execution_authorized": False,
        "input_validation": "failed",
        "live_execution_started": False,
        "network_calls": 0,
        "phase1_claim_eligible": False,
        "provider_calls": 0,
        "schema_version": _SCHEMA,
        "status": "blocked",
        "verifier_calls": 0,
    }


def main(argv: Sequence[str] | None = None) -> int:
    args = _arguments(argv)
    root = Path(__file__).resolve().parents[1]
    try:
        summary = inspect_preflight(
            repository_root=root,
            checkout=args.checkout,
            manifest=args.manifest,
            expected_manifest_hash=args.expected_manifest_sha256,
            split_manifest=args.split_manifest,
            suite=cast(FateExecutionSuiteV1, args.suite),
            provider_profile=args.provider_profile,
            environment_hash=args.environment_hash,
            private_state_root=args.private_state_root,
            wsl_audit_path=args.wsl_audit,
            operator_approved=args.operator_approved,
        )
    except (FateExecutionPreflightError, OSError, ValueError):
        summary = _blocked("credential_free_input_validation_failed")
    sys.stdout.buffer.write(_canonical(summary))
    # This diagnostic intentionally never asserts that live authority exists.
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
