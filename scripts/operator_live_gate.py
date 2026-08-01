"""Run bounded, operator-local live gates and emit only a redacted summary.

This is intentionally a thin process wrapper, not a new authorization or worker
protocol.  It runs the existing DeepSeek bootstrap canary and/or the existing
T6 Library OCI preflight.  A successful result is operational evidence only:
it never establishes Phase 1 promotion eligibility.

The process inherits the operator environment unchanged.  In particular, the
DeepSeek child may obtain ``AUTOLEAN_DEEPSEEK_API_KEY`` from that environment;
this module never reads configuration files or prints child output.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, cast

SUMMARY_SCHEMA: Final = "autolean.operator-live-gate-summary.v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REPO_DIGEST = re.compile(r"^autolean/library-substrate@sha256:[0-9a-f]{64}$")
_DEEPSEEK_FAILURE_CLASSES: Final = frozenset(
    {
        "authorization",
        "capability",
        "configuration",
        "http_3xx",
        "http_400",
        "http_401",
        "http_402",
        "http_422",
        "http_429",
        "http_4xx_other",
        "http_5xx",
        "http_ok_response_invalid",
        "http_status_other",
        "invalid_json",
        "network",
        "policy",
        "provider_response_unclassified",
        "timeout",
        "transport_unclassified",
        "unexpected",
    }
)
_DEEPSEEK_REQUIRED_HASHES: Final = frozenset(
    {
        "authorization",
        "bundle",
        "context_pack",
        "contract",
        "outbound_request",
        "response_text_sha256",
    }
)
_DEEPSEEK_OPTIONAL_HASHES: Final = frozenset({"response_id_sha256"})
_DEEPSEEK_USAGE_FIELDS: Final = frozenset({"cached_input_tokens", "input_tokens", "output_tokens"})
_T6_ALL_FIELDS: Final = frozenset(
    {"build", "builder_query_canary", "canary", "schema_version", "v2_facade_canary"}
)
_T6_COMPONENT_SCHEMAS: Final = {
    "builder_query_canary": "autolean.library-substrate-builder-query-canary.v1",
    "canary": "autolean.library-substrate-independent-canary.v1",
    "v2_facade_canary": "autolean.library-substrate-v2-facade-canary.v2",
}
_MAX_CHILD_OUTPUT_BYTES: Final = 4 * 1024 * 1024
_DEFAULT_TIMEOUT_SECONDS: Final = 2_100
_GateName = Literal["deepseek", "t6_oci"]
_HostKind = Literal["Windows", "WSL", "Linux"]


class OperatorLiveGateError(RuntimeError):
    """The runner cannot safely execute or record a live gate."""


@dataclass(frozen=True, slots=True)
class ChildResult:
    """A bounded subprocess result with opaque stdout and stderr."""

    returncode: int
    stdout: bytes
    stderr: bytes


ChildRunner = Callable[[Sequence[str], Path, int], ChildResult]


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _host_kind(system: str | None = None, release: str | None = None) -> _HostKind:
    """Classify the only supported host forms without emitting host details."""

    observed_system = platform.system() if system is None else system
    if observed_system == "Windows":
        return "Windows"
    if observed_system == "Linux":
        observed_release = platform.release() if release is None else release
        if "microsoft" in observed_release.casefold():
            return "WSL"
        return "Linux"
    raise OperatorLiveGateError("unsupported_host")


def deepseek_argv() -> tuple[str, ...]:
    """Return the sole allowed DeepSeek child command."""

    return (
        "uv",
        "run",
        "--frozen",
        "python",
        "scripts/deepseek_authorized_canary.py",
        "--operator-approved",
    )


def t6_oci_argv(*, host_kind: _HostKind) -> tuple[str, ...]:
    """Return the existing T6 command for a supported host.

    The Library command owns the Windows-to-WSL delegation.  Calling it through
    ``uv`` on Windows therefore exercises its established WSL runtime helper;
    Linux and WSL run the same module natively.
    """

    if host_kind not in {"Windows", "WSL", "Linux"}:
        raise OperatorLiveGateError("unsupported_host")
    return (
        "uv",
        "run",
        "--frozen",
        "python",
        "-m",
        "Library.scripts.library_substrate_image",
        "all",
    )


def _subprocess_runner(argv: Sequence[str], cwd: Path, timeout_seconds: int) -> ChildResult:
    """Run an existing command while preserving opaque child diagnostics."""

    try:
        completed = subprocess.run(
            tuple(argv),
            check=False,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout_seconds,
            # Deliberately inherit, rather than reading/copying, operator credentials.
            env=None,
        )
    except subprocess.TimeoutExpired:
        raise OperatorLiveGateError("child_timed_out") from None
    except OSError:
        raise OperatorLiveGateError("child_unavailable") from None
    if len(completed.stdout) > _MAX_CHILD_OUTPUT_BYTES:
        raise OperatorLiveGateError("child_output_too_large")
    return ChildResult(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise OperatorLiveGateError("child_output_invalid")
        result[key] = value
    return result


def _parse_child_record(payload: bytes) -> dict[str, object]:
    """Accept exactly one JSON object, without exposing its opaque contents."""

    if not payload or len(payload) > _MAX_CHILD_OUTPUT_BYTES:
        raise OperatorLiveGateError("child_output_invalid")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        raise OperatorLiveGateError("child_output_invalid") from None
    lines = text.splitlines()
    if len(lines) != 1 or not lines[0]:
        raise OperatorLiveGateError("child_output_invalid")
    try:
        value = json.loads(
            lines[0],
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                OperatorLiveGateError("child_output_invalid")
            ),
        )
    except (json.JSONDecodeError, UnicodeError):
        raise OperatorLiveGateError("child_output_invalid") from None
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise OperatorLiveGateError("child_output_invalid")
    return cast(dict[str, object], value)


def _hashes(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise OperatorLiveGateError("child_output_schema")
    result: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not isinstance(item, str) or _SHA256.fullmatch(item) is None:
            raise OperatorLiveGateError("child_output_schema")
        result[key] = item
    return dict(sorted(result.items()))


def _deepseek_hashes(value: object) -> dict[str, str]:
    """Accept exactly the public hashes in the fixed canary response schema."""

    if not isinstance(value, Mapping):
        raise OperatorLiveGateError("child_output_schema")
    observed = set(value)
    if not _DEEPSEEK_REQUIRED_HASHES.issubset(observed) or not observed.issubset(
        _DEEPSEEK_REQUIRED_HASHES | _DEEPSEEK_OPTIONAL_HASHES
    ):
        raise OperatorLiveGateError("child_output_schema")
    required = {key: value[key] for key in _DEEPSEEK_REQUIRED_HASHES}
    hashes = _hashes(required)
    optional_response_id = value.get("response_id_sha256")
    if optional_response_id is None:
        return hashes
    if not isinstance(optional_response_id, str) or _SHA256.fullmatch(optional_response_id) is None:
        raise OperatorLiveGateError("child_output_schema")
    return dict(sorted({**hashes, "response_id_sha256": optional_response_id}.items()))


def _nonnegative_integer(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise OperatorLiveGateError("child_output_schema")
    return value


def _deepseek_summary(result: ChildResult) -> dict[str, object]:
    """Reduce the credential-free DeepSeek report to stable public evidence."""

    try:
        report = _parse_child_record(result.stdout)
    except OperatorLiveGateError as error:
        return _blocked_gate(error.args[0])

    status = report.get("status")
    if status == "settled" and result.returncode == 0:
        usage = report.get("usage")
        if not isinstance(usage, Mapping) or set(usage) != _DEEPSEEK_USAGE_FIELDS:
            return _blocked_gate("child_output_schema")
        try:
            return {
                "evidence_hashes": _deepseek_hashes(report.get("hashes")),
                "status": "passed",
                "usage": {
                    "cached_input_tokens": _nonnegative_integer(usage.get("cached_input_tokens")),
                    "input_tokens": _nonnegative_integer(usage.get("input_tokens")),
                    "output_tokens": _nonnegative_integer(usage.get("output_tokens")),
                },
            }
        except OperatorLiveGateError as error:
            return _blocked_gate(error.args[0])

    if status == "execution_refused":
        failure_class = report.get("failure_class")
        if isinstance(failure_class, str) and failure_class in _DEEPSEEK_FAILURE_CLASSES:
            return _blocked_gate(failure_class)
        return _blocked_gate("child_refused")
    if status == "operator_approval_required":
        return _blocked_gate("operator_approval_required")
    return _blocked_gate("child_failed")


def _t6_oci_summary(result: ChildResult) -> dict[str, object]:
    """Reduce a successful T6 image record to digest-bound evidence only."""

    if result.returncode != 0:
        return _blocked_gate("child_failed")
    try:
        report = _parse_child_record(result.stdout)
        if (
            set(report) != _T6_ALL_FIELDS
            or report.get("schema_version") != "autolean.library-substrate-image-all.v1"
        ):
            raise OperatorLiveGateError("child_output_schema")
        build = report.get("build")
        if not isinstance(build, Mapping):
            raise OperatorLiveGateError("child_output_schema")
        image = build.get("image")
        if not isinstance(image, str) or _REPO_DIGEST.fullmatch(image) is None:
            raise OperatorLiveGateError("child_output_schema")
        verification = build.get("verification")
        if not isinstance(verification, Mapping):
            raise OperatorLiveGateError("child_output_schema")
        for field, schema in _T6_COMPONENT_SCHEMAS.items():
            component = report.get(field)
            if (
                not isinstance(component, Mapping)
                or component.get("schema_version") != schema
                or component.get("image") != image
            ):
                raise OperatorLiveGateError("child_output_schema")
        evidence = {
            "build_input": build.get("build_input_sha256"),
            "context_inventory": build.get("context_inventory_sha256"),
            "image_receipt": verification.get("image_receipt_sha256"),
            "parent_receipt_canonical": verification.get("parent_receipt_canonical_sha256"),
        }
        return {
            "evidence_hashes": _hashes(evidence),
            "image_repo_digest": image,
            "status": "passed",
        }
    except OperatorLiveGateError as error:
        return _blocked_gate(error.args[0])


def _blocked_gate(blocker: str) -> dict[str, object]:
    """Return the sole failed state shape; no upstream diagnostic is retained."""

    return {"stable_blocker": blocker, "status": "blocked"}


def _gate_command(name: _GateName, host_kind: _HostKind) -> tuple[str, ...]:
    if name == "deepseek":
        return deepseek_argv()
    return t6_oci_argv(host_kind=host_kind)


def _run_gate(
    name: _GateName,
    *,
    root: Path,
    host_kind: _HostKind,
    timeout_seconds: int,
    runner: ChildRunner,
) -> dict[str, object]:
    try:
        result = runner(_gate_command(name, host_kind), root, timeout_seconds)
    except OperatorLiveGateError as error:
        return _blocked_gate(error.args[0])
    if name == "deepseek":
        return _deepseek_summary(result)
    return _t6_oci_summary(result)


def _canonical_summary(document: Mapping[str, object]) -> bytes:
    encoded = (
        json.dumps(document, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")
    if not encoded.isascii():
        raise AssertionError("summary escaped the ASCII-only boundary")
    return encoded


def _validate_output_path(output: Path, *, root: Path) -> Path:
    if not output.is_absolute():
        raise OperatorLiveGateError("output_must_be_absolute")
    candidate = output.resolve(strict=False)
    checkout = root.resolve(strict=True)
    if candidate == checkout or candidate.is_relative_to(checkout):
        raise OperatorLiveGateError("output_must_be_outside_checkout")
    if candidate.exists():
        raise OperatorLiveGateError("output_must_not_exist")
    if not candidate.parent.is_dir():
        raise OperatorLiveGateError("output_parent_unavailable")
    return candidate


def _write_exclusive(path: Path, payload: bytes) -> None:
    try:
        with path.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        raise OperatorLiveGateError("output_write_failed") from None


def run_live_gate(
    selection: Literal["deepseek", "t6-oci", "all"],
    *,
    root: Path | None = None,
    runner: ChildRunner = _subprocess_runner,
    host_system: str | None = None,
    host_release: str | None = None,
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, object]:
    """Run selected existing gates and return the non-promotional summary object."""

    if not 1 <= timeout_seconds <= 7_200:
        raise OperatorLiveGateError("timeout_out_of_range")
    resolved_root = (root or _repository_root()).resolve(strict=True)
    kind = _host_kind(host_system, host_release)
    requested: tuple[_GateName, ...]
    if selection == "deepseek":
        requested = ("deepseek",)
    elif selection == "t6-oci":
        requested = ("t6_oci",)
    else:
        requested = ("deepseek", "t6_oci")
    gates = {
        name: _run_gate(
            name,
            root=resolved_root,
            host_kind=kind,
            timeout_seconds=timeout_seconds,
            runner=runner,
        )
        for name in requested
    }
    passed = all(gate["status"] == "passed" for gate in gates.values())
    return {
        "gates": gates,
        # Connectivity and OCI preflight are not a contract/semantic/kernel release gate.
        "phase1_promotion_eligible": False,
        "schema_version": SUMMARY_SCHEMA,
        "status": "passed" if passed else "blocked",
    }


def _arguments(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("deepseek", "t6-oci", "all"))
    parser.add_argument(
        "--output",
        type=Path,
        help="absolute, non-existent path outside this checkout; omitted means stdout only",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=_DEFAULT_TIMEOUT_SECONDS,
        help="per-child bound (1-7200 seconds)",
    )
    return parser.parse_args(argv)


def _exit_for_summary(summary: Mapping[str, object]) -> int:
    return 0 if summary.get("status") == "passed" else 1


def _refusal_summary(blocker: str) -> dict[str, object]:
    return {
        "gates": {"runner": _blocked_gate(blocker)},
        "phase1_promotion_eligible": False,
        "schema_version": SUMMARY_SCHEMA,
        "status": "blocked",
    }


def main(argv: Sequence[str] | None = None) -> int:
    args = _arguments(argv)
    root = _repository_root()
    try:
        output = None if args.output is None else _validate_output_path(args.output, root=root)
        summary = run_live_gate(
            cast(Literal["deepseek", "t6-oci", "all"], args.command),
            root=root,
            timeout_seconds=args.timeout_seconds,
        )
    except OperatorLiveGateError as error:
        summary = _refusal_summary(error.args[0])
        output = None
    payload = _canonical_summary(summary)
    if output is not None:
        try:
            _write_exclusive(output, payload)
        except OperatorLiveGateError as error:
            payload = _canonical_summary(_refusal_summary(error.args[0]))
            sys.stdout.buffer.write(payload)
            return 2
    sys.stdout.buffer.write(payload)
    return _exit_for_summary(summary)


if __name__ == "__main__":
    raise SystemExit(main())
