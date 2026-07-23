"""Exercise bounded OS-process recovery for the synthetic local control plane.

The parent starts a purpose-built child worker, waits until it has durably registered synthetic
bundles and acquired SQLite leases, then terminates that child process. Separate recovery and
event-replay child processes reopen the same SQLite/WAL database and content-addressed artifact
store. They prove only the tested protocol facts: duplicate delivery is idempotent, expired leases
reject stale fencing tokens, and persisted events/artifacts replay consistently.

This is intentionally not an authoritative Lean, OCI, model-provider, network, power-loss, or
mid-transaction SQLite crash test. It never launches a general worker and never deletes a
user-supplied workspace; an omitted workspace is a private temporary run directory.

Run the small smoke campaign with the short project command:

    uv run python scripts/dev.py chaos-process

Run the bounded 1,000-job target explicitly:

    uv run python scripts/dev.py chaos-process --jobs 1000
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Literal, cast

_SCHEMA_VERSION = "autolean.control-plane-process-chaos.v1"
_REPORT_ENVELOPE_SCHEMA = "autolean.control-plane-process-chaos-report-envelope.v1"
_REPORT_HASH_DOMAIN = b"autolean.control-plane-process-chaos-report-envelope.v1\x00"
_SCENARIO_FILE = "scenario.json"
_READY_FILE = "crash-ready.json"
_RECOVERY_FILE = "recovery.json"
_REPLAY_FILE = "replay.json"
_MAX_JOBS = 1_000
_REPO_ROOT = Path(__file__).resolve().parents[1]
_REPORT_DIRECTORY = "release-evidence"
_DOES_NOT_EXERCISE = (
    "lean",
    "oci",
    "network",
    "model_provider",
    "real_attestation_authority",
    "power_loss",
    "mid_transaction_sqlite_kill",
)
_SUMMARY_FIELDS = frozenset(
    {
        "schema_version",
        "evidence_scope",
        "lean_or_oci_execution",
        "network_or_model_execution",
        "test_only_hmac_authority",
        "jobs_requested",
        "jobs_completed",
        "child_processes_started",
        "os_process_kill_exercised",
        "process_termination_target",
        "crash_phase",
        "restart_mode",
        "replacement_claims",
        "expired_leases",
        "stale_fence_rejections",
        "duplicate_delivery_replays",
        "terminal_verdicts",
        "per_proof_terminal_verdicts",
        "event_count",
        "expected_event_count",
        "event_positions_contiguous",
        "event_replay_consistent",
        "content_addressed_artifacts_verified",
        "task_loss_detected",
        "duplicate_terminal_verdict_detected",
        "does_not_exercise",
    }
)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("ascii")


def _canonical_object(value: object) -> dict[str, object]:
    """Create a JSON-only deep snapshot so later caller mutations cannot alter a report."""

    parsed = json.loads(_canonical_json(value))
    if not isinstance(parsed, dict):
        raise ValueError("process-chaos report data must be a JSON object")
    return cast(dict[str, object], parsed)


def _validate_summary(summary: dict[str, object]) -> None:
    """Reject arbitrary payloads: this writer retains only this harness's redacted V1 summary."""

    if set(summary) != _SUMMARY_FIELDS:
        raise ValueError("process-chaos report has unexpected or missing summary fields")
    literals: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "evidence_scope": "synthetic_control_plane_process_recovery_only",
        "process_termination_target": "purpose_built_prepare_worker",
        "crash_phase": "after_durable_registration_and_claim_before_proof_submission",
        "restart_mode": "new_os_processes_reopen_persisted_sqlite_wal_and_artifacts",
    }
    for field, expected in literals.items():
        if summary.get(field) != expected:
            raise ValueError(f"process-chaos report has an invalid {field}")
    if summary.get("does_not_exercise") != list(_DOES_NOT_EXERCISE):
        raise ValueError("process-chaos report has an invalid does_not_exercise boundary")
    boolean_fields: dict[str, bool] = {
        "lean_or_oci_execution": False,
        "network_or_model_execution": False,
        "test_only_hmac_authority": True,
        "os_process_kill_exercised": True,
        "event_positions_contiguous": True,
        "event_replay_consistent": True,
        "task_loss_detected": False,
        "duplicate_terminal_verdict_detected": False,
    }
    for field, expected in boolean_fields.items():
        if summary.get(field) is not expected:
            raise ValueError(f"process-chaos report has an invalid {field}")
    jobs = summary.get("jobs_requested")
    if type(jobs) is not int or not 1 <= jobs <= _MAX_JOBS:
        raise ValueError("process-chaos report has an invalid jobs_requested")
    expected_counts: dict[str, int] = {
        "jobs_completed": jobs,
        "child_processes_started": 3,
        "replacement_claims": jobs,
        "expired_leases": jobs,
        "stale_fence_rejections": jobs,
        "duplicate_delivery_replays": jobs * 4,
        "terminal_verdicts": jobs,
        "per_proof_terminal_verdicts": 1,
        "event_count": jobs * 5,
        "expected_event_count": jobs * 5,
        "content_addressed_artifacts_verified": jobs * 4,
    }
    for field, expected in expected_counts.items():
        if summary.get(field) != expected or type(summary.get(field)) is not int:
            raise ValueError(f"process-chaos report has an invalid {field}")


def _report_sha256(summary: dict[str, object]) -> str:
    return hashlib.sha256(_REPORT_HASH_DOMAIN + _canonical_json(summary)).hexdigest()


def report_envelope(summary: dict[str, object]) -> dict[str, object]:
    """Create an immutable, domain-separated envelope for the redacted V1 summary."""

    report = _canonical_object(summary)
    _validate_summary(report)
    return {
        "schema_version": _REPORT_ENVELOPE_SCHEMA,
        "report_sha256": _report_sha256(report),
        "report": report,
    }


def _is_link_or_reparse(path: Path) -> bool:
    metadata = path.lstat()
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _validate_envelope(envelope: dict[str, object]) -> dict[str, object]:
    normalized = _canonical_object(envelope)
    if set(normalized) != {"schema_version", "report_sha256", "report"}:
        raise ValueError("process-chaos report envelope has unexpected or missing fields")
    if normalized.get("schema_version") != _REPORT_ENVELOPE_SCHEMA:
        raise ValueError("process-chaos report envelope has an unsupported schema version")
    report = normalized.get("report")
    report_hash = normalized.get("report_sha256")
    if not isinstance(report, dict) or not isinstance(report_hash, str):
        raise ValueError("process-chaos report envelope has invalid report fields")
    canonical_report = cast(dict[str, object], report)
    _validate_summary(canonical_report)
    if not re.fullmatch(r"[0-9a-f]{64}", report_hash):
        raise ValueError("process-chaos report envelope has an invalid report hash")
    if report_hash != _report_sha256(canonical_report):
        raise ValueError("process-chaos report envelope hash does not match its report")
    return normalized


def _validated_output_path(output: Path, *, root: Path) -> Path:
    workspace = root.resolve()
    if not workspace.is_dir():
        raise ValueError("process-chaos workspace root must be an existing directory")
    if output.is_absolute():
        candidate = output.absolute()
    elif output.drive:
        raise ValueError("--output may not use a drive-relative path")
    else:
        candidate = (workspace / output).absolute()
    if candidate.suffix != ".json":
        raise ValueError("--output must have a .json filename")
    if candidate.exists() or candidate.is_symlink():
        raise ValueError("--output already exists; process-chaos evidence is immutable")
    parent = candidate.parent
    evidence_root = workspace / _REPORT_DIRECTORY
    if not evidence_root.is_dir():
        raise ValueError("--output requires an existing release-evidence directory")
    resolved_parent = parent.resolve()
    resolved_evidence_root = evidence_root.resolve()
    if not resolved_evidence_root.is_relative_to(workspace):
        raise ValueError("release-evidence must stay inside the workspace")
    if not resolved_parent.is_relative_to(resolved_evidence_root):
        raise ValueError("--output must stay inside release-evidence")
    if not parent.is_dir():
        raise ValueError("--output parent must be an existing directory")

    current = parent
    while True:
        if _is_link_or_reparse(current):
            raise ValueError("--output path may not traverse a link or junction")
        if current.resolve() == workspace:
            break
        if current.parent == current:
            raise ValueError("--output must stay inside the workspace")
        current = current.parent
    return candidate


def write_report_exclusive(
    output: Path,
    envelope: dict[str, object],
    *,
    root: Path = _REPO_ROOT,
) -> Path:
    """Write one report without following links or replacing prior evidence."""

    candidate = _validated_output_path(output, root=root)
    normalized_envelope = _validate_envelope(envelope)
    payload = _canonical_json(normalized_envelope) + b"\n"
    descriptor: int | None = None
    try:
        descriptor = os.open(
            candidate,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            descriptor = None
            raise ValueError("process-chaos report output must be a regular file")
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
        raise ValueError("process-chaos report write failed") from error
    return candidate


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _prepare_workspace(
    workspace: Path | None,
) -> tuple[Path, tempfile.TemporaryDirectory[str] | None]:
    if workspace is None:
        temporary = tempfile.TemporaryDirectory(prefix="autolean-control-plane-process-chaos-")
        return Path(temporary.name), temporary
    root = workspace.resolve()
    if root.exists() and any(root.iterdir()):
        raise ValueError("--workspace must be empty; this script never deletes existing data")
    root.mkdir(parents=True, exist_ok=True)
    return root, None


def _write_scenario(root: Path, jobs: int) -> None:
    payload = {
        "initial_time": "2026-01-01T00:00:00+00:00",
        "jobs": jobs,
        "schema_version": _SCHEMA_VERSION,
    }
    scenario = root / _SCENARIO_FILE
    with scenario.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
        handle.write("\n")


def _read_json_object(path: Path) -> dict[str, object]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AssertionError(f"process-chaos child did not produce valid {path.name}") from error
    if not isinstance(raw, dict):
        raise AssertionError(f"process-chaos child state {path.name} is not an object")
    return cast(dict[str, object], raw)


def _child_command(root: Path, phase: Literal["prepare", "recover", "replay"]) -> list[str]:
    return [
        sys.executable,
        "-m",
        "scripts.control_plane_process_worker",
        "--workspace",
        str(root),
        "--phase",
        phase,
    ]


def _timeout_seconds(jobs: int) -> float:
    """Bound a child run while still allowing the 1,000-job target on Windows CI."""

    return min(120.0, 15.0 + (jobs * 0.105))


def _start_child(
    root: Path,
    phase: Literal["prepare", "recover", "replay"],
) -> subprocess.Popen[str]:
    return subprocess.Popen(
        _child_command(root, phase),
        cwd=_REPO_ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _wait_for_ready(process: subprocess.Popen[str], ready_path: Path, *, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if ready_path.is_file():
            if process.poll() is not None:
                raise AssertionError("prepare child exited before its durable crash checkpoint")
            return
        if process.poll() is not None:
            raise AssertionError("prepare child exited before publishing its crash checkpoint")
        time.sleep(0.02)
    if process.poll() is None:
        process.terminate()
        try:
            process.communicate(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5.0)
    raise TimeoutError("prepare child did not reach its durable crash checkpoint in time")


def _terminate_prepare_child(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        raise AssertionError("prepare child exited before the requested OS-process termination")
    process.terminate()
    try:
        process.communicate(timeout=5.0)
    except subprocess.TimeoutExpired as error:
        process.kill()
        process.communicate(timeout=5.0)
        raise AssertionError(
            "prepare child did not terminate within the bounded timeout"
        ) from error
    _require(
        process.returncode is not None and process.returncode != 0,
        "prepare child was not killed",
    )


def _run_child(root: Path, phase: Literal["recover", "replay"], *, timeout: float) -> None:
    completed = subprocess.run(
        _child_command(root, phase),
        cwd=_REPO_ROOT,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if completed.returncode != 0:
        # Do not echo child stderr: a future implementation error could include artifact content.
        raise AssertionError(
            f"process-chaos {phase} child exited with status {completed.returncode}"
        )


def run_process_campaign(
    *,
    jobs: int = 3,
    workspace: Path | None = None,
) -> dict[str, object]:
    """Run a safe three-process synthetic recovery campaign.

    ``jobs`` is intentionally capped at 1,000. A caller that supplies ``workspace`` must supply
    an empty directory; it is retained for inspection and never deleted by this function.
    """

    if isinstance(jobs, bool) or not 1 <= jobs <= _MAX_JOBS:
        raise ValueError(f"jobs must be between 1 and {_MAX_JOBS}")
    root, temporary = _prepare_workspace(workspace)
    try:
        _write_scenario(root, jobs)
        timeout = _timeout_seconds(jobs)
        prepare = _start_child(root, "prepare")
        _wait_for_ready(prepare, root / _READY_FILE, timeout=timeout)
        _terminate_prepare_child(prepare)

        _run_child(root, "recover", timeout=timeout)
        _run_child(root, "replay", timeout=timeout)
        ready = _read_json_object(root / _READY_FILE)
        recovery = _read_json_object(root / _RECOVERY_FILE)
        replay = _read_json_object(root / _REPLAY_FILE)
        _require(ready.get("jobs_prepared") == jobs, "prepare child lost jobs before termination")
        _require(recovery.get("jobs_recovered") == jobs, "recovery child lost jobs")
        _require(replay.get("jobs_replayed") == jobs, "replay child lost jobs")
        _require(
            recovery.get("stale_fence_rejections") == jobs,
            "recovery child did not reject every stale fencing token",
        )
        _require(
            recovery.get("duplicate_delivery_replays") == jobs * 4,
            "duplicate delivery was not replayed for every job",
        )
        _require(replay.get("event_count") == jobs * 5, "unexpected process-chaos event count")
        _require(replay.get("terminal_verdicts") == jobs, "terminal verdict count is incorrect")
        _require(
            replay.get("content_addressed_artifacts_verified") == jobs * 4,
            "content-addressed artifact verification is incomplete",
        )

        return {
            "schema_version": _SCHEMA_VERSION,
            "evidence_scope": "synthetic_control_plane_process_recovery_only",
            "lean_or_oci_execution": False,
            "network_or_model_execution": False,
            "test_only_hmac_authority": True,
            "jobs_requested": jobs,
            "jobs_completed": jobs,
            "child_processes_started": 3,
            "os_process_kill_exercised": True,
            "process_termination_target": "purpose_built_prepare_worker",
            "crash_phase": ready["crash_phase"],
            "restart_mode": "new_os_processes_reopen_persisted_sqlite_wal_and_artifacts",
            "replacement_claims": recovery["replacement_claims"],
            "expired_leases": jobs,
            "stale_fence_rejections": recovery["stale_fence_rejections"],
            "duplicate_delivery_replays": recovery["duplicate_delivery_replays"],
            "terminal_verdicts": replay["terminal_verdicts"],
            "per_proof_terminal_verdicts": 1,
            "event_count": replay["event_count"],
            "expected_event_count": replay["expected_event_count"],
            "event_positions_contiguous": replay["event_positions_contiguous"],
            "event_replay_consistent": replay["event_replay_consistent"],
            "content_addressed_artifacts_verified": replay["content_addressed_artifacts_verified"],
            "task_loss_detected": False,
            "duplicate_terminal_verdict_detected": False,
            "does_not_exercise": _DOES_NOT_EXERCISE,
        }
    finally:
        if temporary is not None:
            temporary.cleanup()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--jobs",
        type=int,
        default=3,
        help="synthetic jobs to exercise; 3 is smoke coverage and 1000 is the bounded target",
    )
    parser.add_argument(
        "--workspace",
        type=Path,
        help="optional empty directory to retain only synthetic SQLite/artifact evidence",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="existing in-repository directory plus a new immutable report filename",
    )
    args = parser.parse_args()
    output = None if args.output is None else _validated_output_path(args.output, root=_REPO_ROOT)
    summary = run_process_campaign(jobs=args.jobs, workspace=args.workspace)
    envelope = report_envelope(summary)
    if output is not None:
        write_report_exclusive(output, envelope)
    print(json.dumps(summary, ensure_ascii=True, separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    main()
