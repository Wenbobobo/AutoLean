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
import platform
import re
import secrets
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Literal, cast

from autolean_contracts import (
    FormalizationTaskBundleV1,
    ProofSubmissionV1,
    VerificationEvidenceArtifactV1,
    VerificationReportV1,
    proof_dependency_manifest_hash,
)
from autolean_control_plane import ArtifactRef, ArtifactStore, DashboardProjection
from autolean_control_plane.errors import ArtifactCorruption, ArtifactNotFound
from autolean_control_plane.events import StoredEvent, canonical_json
from pydantic import BaseModel

_SCHEMA_VERSION = "autolean.control-plane-process-chaos.v1"
_REPORT_ENVELOPE_SCHEMA = "autolean.control-plane-process-chaos-report-envelope.v1"
_REPORT_HASH_DOMAIN = b"autolean.control-plane-process-chaos-report-envelope.v1\x00"
_PROVENANCE_RECEIPT_SCHEMA = "autolean.control-plane-process-chaos-provenance.v2"
_PROVENANCE_MANIFEST_SCHEMA = "autolean.control-plane-process-chaos-workspace-manifest.v2"
_PROVENANCE_RECEIPT_DOMAIN = b"autolean.control-plane-process-chaos-provenance.v2\x00"
_PROVENANCE_MANIFEST_DOMAIN = b"autolean.control-plane-process-chaos-workspace-manifest.v2\x00"
_SCENARIO_FILE = "scenario.json"
_READY_FILE = "crash-ready.json"
_RECOVERY_FILE = "recovery.json"
_REPLAY_FILE = "replay.json"
_STATE_FILES = (_SCENARIO_FILE, _READY_FILE, _RECOVERY_FILE, _REPLAY_FILE)
_DATABASE_FILE = "control-plane-process-chaos.sqlite3"
_SQLITE_FILE_NAMES = (
    _DATABASE_FILE,
    f"{_DATABASE_FILE}-shm",
    f"{_DATABASE_FILE}-wal",
)
_ARTIFACT_DIRECTORY = "artifacts"
_MAX_JOBS = 1_000
_CHILD_TIMEOUT_BASE_SECONDS = 30.0
_CHILD_TIMEOUT_PER_JOB_SECONDS = 0.27
_CHILD_TIMEOUT_MAX_SECONDS = 300.0
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
_PROVENANCE_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "receipt_sha256",
        "run_id",
        "source_candidate",
        "uv_lock",
        "runtime",
        "argv",
        "started_at",
        "ended_at",
        "duration_ms",
        "summary",
        "summary_report_sha256",
        "workspace_manifest",
    }
)
_WORKSPACE_MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "manifest_sha256",
        "state_files",
        "sqlite_files",
        "artifact_files",
    }
)
_MANIFEST_FILE_FIELDS = frozenset({"path", "sha256", "size_bytes"})
_SHA256 = re.compile(r"[0-9a-f]{64}")
_GIT_COMMIT = re.compile(r"[0-9a-f]{40}")
_RUN_ID = re.compile(r"[0-9a-f]{32}")
_SQLITE_TABLE_COLUMNS = {
    "events": (
        "global_position",
        "event_id",
        "entity_type",
        "entity_id",
        "entity_sequence",
        "event_type",
        "payload_json",
        "metadata_json",
        "recorded_at",
    ),
    "entity_versions": ("entity_type", "entity_id", "sequence"),
    "idempotency_records": (
        "scope",
        "key",
        "request_hash",
        "event_ids_json",
        "created_at",
    ),
    "attestation_nonce_uses": (
        "purpose",
        "key_id",
        "nonce",
        "payload_hash",
        "entity_type",
        "entity_id",
        "consumed_at",
    ),
    "contract_revision_bindings": (
        "contract_id",
        "revision",
        "bundle_id",
        "bundle_hash",
        "contract_hash",
        "registration_event_id",
    ),
    "worker_leases": (
        "job_id",
        "holder_id",
        "fencing_token",
        "expires_at_epoch",
        "updated_at_epoch",
    ),
    "lease_counters": ("job_id", "last_fencing_token"),
}
_SQLITE_TRIGGERS = frozenset(
    {
        "events_forbid_update",
        "events_forbid_delete",
        "attestation_nonce_uses_forbid_update",
        "attestation_nonce_uses_forbid_delete",
        "contract_revision_bindings_forbid_update",
        "contract_revision_bindings_forbid_delete",
    }
)
_SQLITE_INDEXES = frozenset({"events_entity_stream"})
_ARTIFACT_REFERENCE_FIELDS = frozenset({"digest", "kind", "media_type", "size", "uri"})


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


def _strict_json_object(data: bytes, *, label: str) -> dict[str, object]:
    """Load a JSON object without accepting duplicate keys or non-finite values."""

    def reject_constant(value: str) -> object:
        raise ValueError(f"{label} contains an invalid JSON constant: {value}")

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{label} contains a duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        decoded = data.decode("utf-8")
        value = json.loads(
            decoded,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"{label} is not strict UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain a JSON object")
    return cast(dict[str, object], value)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
                size += len(chunk)
    except OSError as error:
        raise ValueError(f"cannot read provenance file: {path.name}") from error
    return digest.hexdigest(), size


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


def _require_regular_file(path: Path, *, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValueError(f"{label} is missing") from error
    if _is_link_or_reparse(path) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"{label} must be a regular non-reparse file")


def _require_directory(path: Path, *, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValueError(f"{label} is missing") from error
    if _is_link_or_reparse(path) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"{label} must be a directory without links or junctions")


def _safe_relative_path(value: object, *, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError(f"{label} is not a canonical relative path")
    parsed = PurePosixPath(value)
    if (
        parsed.is_absolute()
        or not parsed.parts
        or any(part in {"", ".", ".."} or ":" in part for part in parsed.parts)
        or parsed.as_posix() != value
    ):
        raise ValueError(f"{label} is not a canonical relative path")
    return parsed


def _workspace_target(root: Path, relative: str, *, label: str) -> Path:
    parsed = _safe_relative_path(relative, label=label)
    _require_directory(root, label="provenance workspace")
    current = root
    for part in parsed.parts[:-1]:
        current = current / part
        _require_directory(current, label=label)
    return current / parsed.parts[-1]


def _manifest_file(root: Path, path: Path) -> dict[str, object]:
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError as error:
        raise ValueError("provenance file escaped the retained workspace") from error
    checked = _workspace_target(root, relative, label="provenance manifest path")
    _require_regular_file(checked, label="provenance manifest path")
    digest, size = _sha256_file(checked)
    return {"path": relative, "sha256": digest, "size_bytes": size}


def _walk_artifact_files(root: Path, directory: Path) -> list[dict[str, object]]:
    _require_directory(directory, label="provenance artifact directory")
    entries: list[dict[str, object]] = []
    for child in sorted(directory.iterdir(), key=lambda item: item.name):
        if _is_link_or_reparse(child):
            raise ValueError("provenance artifact tree contains a link or junction")
        metadata = child.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            entries.extend(_walk_artifact_files(root, child))
        elif stat.S_ISREG(metadata.st_mode):
            entries.append(_manifest_file(root, child))
        else:
            raise ValueError("provenance artifact tree contains a non-regular file")
    return entries


def _manifest_hash(payload: dict[str, object]) -> str:
    return _sha256_bytes(_PROVENANCE_MANIFEST_DOMAIN + _canonical_json(payload))


def workspace_manifest(workspace: Path) -> dict[str, object]:
    """Describe the exact retained synthetic workspace after the replay process has finished."""

    root = workspace.absolute()
    _require_directory(root, label="provenance workspace")
    children = {entry.name: entry for entry in root.iterdir()}
    allowed_names = {*_STATE_FILES, *_SQLITE_FILE_NAMES, _ARTIFACT_DIRECTORY}
    unexpected = sorted(set(children) - allowed_names)
    if unexpected:
        raise ValueError("provenance workspace contains unexpected root entries")
    if any(name not in children for name in _STATE_FILES):
        raise ValueError("provenance workspace is missing a required state file")
    if _DATABASE_FILE not in children:
        raise ValueError("provenance workspace is missing its SQLite database")
    if _ARTIFACT_DIRECTORY not in children:
        raise ValueError("provenance workspace is missing its artifact directory")

    state_files = [_manifest_file(root, children[name]) for name in _STATE_FILES]
    sqlite_files = [
        _manifest_file(root, children[name]) for name in _SQLITE_FILE_NAMES if name in children
    ]
    artifact_files = _walk_artifact_files(root, children[_ARTIFACT_DIRECTORY])
    artifact_files.sort(key=lambda entry: cast(str, entry["path"]))
    if not artifact_files:
        raise ValueError("provenance workspace contains no content-addressed artifacts")
    payload: dict[str, object] = {
        "schema_version": _PROVENANCE_MANIFEST_SCHEMA,
        "state_files": state_files,
        "sqlite_files": sqlite_files,
        "artifact_files": artifact_files,
    }
    return {"manifest_sha256": _manifest_hash(payload), **payload}


def _validate_manifest_file(entry: object, *, label: str) -> dict[str, object]:
    if not isinstance(entry, dict) or set(entry) != _MANIFEST_FILE_FIELDS:
        raise ValueError(f"{label} has invalid fields")
    path = entry.get("path")
    _safe_relative_path(path, label=label)
    digest = entry.get("sha256")
    size = entry.get("size_bytes")
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        raise ValueError(f"{label} has an invalid SHA-256")
    if type(size) is not int or size < 0:
        raise ValueError(f"{label} has an invalid size")
    return cast(dict[str, object], entry)


def _validate_workspace_manifest(manifest: object) -> dict[str, object]:
    if not isinstance(manifest, dict) or set(manifest) != _WORKSPACE_MANIFEST_FIELDS:
        raise ValueError("provenance receipt has invalid workspace manifest fields")
    if manifest.get("schema_version") != _PROVENANCE_MANIFEST_SCHEMA:
        raise ValueError("provenance receipt has an unsupported workspace manifest schema")
    groups = ("state_files", "sqlite_files", "artifact_files")
    normalized: dict[str, object] = {
        "schema_version": _PROVENANCE_MANIFEST_SCHEMA,
    }
    for group in groups:
        values = manifest.get(group)
        if not isinstance(values, list):
            raise ValueError(f"provenance receipt {group} must be a list")
        files = [
            _validate_manifest_file(item, label=f"provenance receipt {group}") for item in values
        ]
        paths = [cast(str, item["path"]) for item in files]
        if len(paths) != len(set(paths)):
            raise ValueError(f"provenance receipt {group} is not a unique sorted manifest")
        if group != "state_files" and paths != sorted(paths):
            raise ValueError(f"provenance receipt {group} is not a unique sorted manifest")
        normalized[group] = files
    state_paths = [
        cast(str, item["path"]) for item in cast(list[dict[str, object]], normalized["state_files"])
    ]
    if state_paths != list(_STATE_FILES):
        raise ValueError(
            "provenance receipt state manifest does not match the required state files"
        )
    sqlite_paths = [
        cast(str, item["path"])
        for item in cast(list[dict[str, object]], normalized["sqlite_files"])
    ]
    if sqlite_paths != [_DATABASE_FILE]:
        raise ValueError("provenance receipt SQLite manifest is invalid")
    artifact_paths = [
        cast(str, item["path"])
        for item in cast(list[dict[str, object]], normalized["artifact_files"])
    ]
    if not artifact_paths or any(
        not path.startswith(f"{_ARTIFACT_DIRECTORY}/") for path in artifact_paths
    ):
        raise ValueError("provenance receipt artifact manifest is invalid")
    payload = {
        "schema_version": normalized["schema_version"],
        "state_files": normalized["state_files"],
        "sqlite_files": normalized["sqlite_files"],
        "artifact_files": normalized["artifact_files"],
    }
    manifest_hash = manifest.get("manifest_sha256")
    if not isinstance(manifest_hash, str) or _SHA256.fullmatch(manifest_hash) is None:
        raise ValueError("provenance receipt workspace manifest hash is invalid")
    if manifest_hash != _manifest_hash(payload):
        raise ValueError("provenance receipt workspace manifest hash does not match")
    return {
        "manifest_sha256": manifest_hash,
        **payload,
    }


def _git_bytes(root: Path, *arguments: str) -> bytes:
    try:
        completed = subprocess.run(
            ("git", *arguments),
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError as error:
        raise ValueError("git is required for a provenance receipt") from error
    if completed.returncode != 0:
        raise ValueError("provenance receipt requires a valid Git checkout")
    return completed.stdout


def _bound_execution_root(root: Path) -> Path:
    """Bind provenance to the checkout that supplies the imported child worker bytes."""

    expected = _REPO_ROOT.resolve()
    candidate = root.resolve()
    if candidate != expected:
        raise ValueError(
            "process-chaos provenance root must match the repository worker source root"
        )
    return expected


def _candidate_directory_fingerprint(root: Path, directory: Path) -> tuple[str, int]:
    _require_directory(directory, label="dirty candidate directory")
    entries: list[dict[str, object]] = []
    total_size = 0
    for child in sorted(directory.rglob("*"), key=lambda item: item.as_posix()):
        if _is_link_or_reparse(child):
            try:
                link_bytes = os.readlink(child).encode("utf-8")
            except OSError as error:
                raise ValueError("dirty candidate link target is unreadable") from error
            entries.append(
                {
                    "kind": "link",
                    "path": child.relative_to(directory).as_posix(),
                    "sha256": _sha256_bytes(link_bytes),
                    "size_bytes": len(link_bytes),
                }
            )
            total_size += len(link_bytes)
            continue
        relative = child.relative_to(directory).as_posix()
        metadata = child.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            entries.append({"kind": "directory", "path": relative})
        elif stat.S_ISREG(metadata.st_mode):
            digest, size = _sha256_file(child)
            entries.append(
                {
                    "kind": "file",
                    "path": relative,
                    "sha256": digest,
                    "size_bytes": size,
                }
            )
            total_size += size
        else:
            raise ValueError("dirty candidate directory contains a non-regular entry")
    return _sha256_bytes(_canonical_json(entries)), total_size


def _candidate_path_manifest(root: Path, paths: list[str]) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for raw_relative in paths:
        is_directory = raw_relative.endswith("/")
        relative = raw_relative[:-1] if is_directory else raw_relative
        _safe_relative_path(relative, label="dirty candidate path")
        target = _workspace_target(root, relative, label="dirty candidate path")
        if _is_link_or_reparse(target):
            try:
                link_bytes = os.readlink(target).encode("utf-8")
            except OSError as error:
                raise ValueError("dirty candidate link target is unreadable") from error
            entries.append(
                {
                    "kind": "link",
                    "path": relative,
                    "sha256": _sha256_bytes(link_bytes),
                    "size_bytes": len(link_bytes),
                }
            )
        elif is_directory:
            digest, size = _candidate_directory_fingerprint(root, target)
            entries.append(
                {
                    "kind": "directory",
                    "path": relative,
                    "sha256": digest,
                    "size_bytes": size,
                }
            )
        else:
            _require_regular_file(target, label="dirty candidate path")
            digest, size = _sha256_file(target)
            entries.append(
                {
                    "kind": "file",
                    "path": relative,
                    "sha256": digest,
                    "size_bytes": size,
                }
            )
    return entries


def source_candidate(root: Path = _REPO_ROOT) -> dict[str, object]:
    """Return an exact commit identity or a reproducible dirty-worktree fingerprint."""

    checkout = root.resolve()
    _require_directory(checkout, label="source checkout")
    commit = _git_bytes(checkout, "rev-parse", "HEAD").decode("ascii", "strict").strip()
    if _GIT_COMMIT.fullmatch(commit) is None:
        raise ValueError("provenance checkout has an invalid HEAD commit")
    porcelain = _git_bytes(checkout, "status", "--porcelain=v1", "-z")
    if not porcelain:
        return {"kind": "git_commit", "git_commit": commit}
    diff = _git_bytes(checkout, "diff", "--no-ext-diff", "--binary", "HEAD", "--")
    untracked_raw = _git_bytes(checkout, "ls-files", "--others", "--exclude-standard", "-z")
    untracked = sorted(
        item.decode("utf-8", "strict") for item in untracked_raw.split(b"\0") if item
    )
    payload: dict[str, object] = {
        "schema_version": "autolean.dirty-candidate-fingerprint.v2",
        "git_commit": commit,
        "status_sha256": _sha256_bytes(porcelain),
        "diff_sha256": _sha256_bytes(diff),
        "untracked": _candidate_path_manifest(checkout, untracked),
    }
    return {
        "kind": "dirty_candidate",
        "git_commit": commit,
        "fingerprint": _sha256_bytes(_canonical_json(payload)),
    }


def _uv_lock(root: Path) -> dict[str, object]:
    path = root.resolve() / "uv.lock"
    _require_regular_file(path, label="uv.lock")
    digest, size = _sha256_file(path)
    return {"path": "uv.lock", "sha256": digest, "size_bytes": size}


def _tool_version(command: tuple[str, ...], *, label: str) -> str:
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
    except OSError as error:
        raise ValueError(f"{label} is required for a provenance receipt") from error
    value = completed.stdout.strip()
    if completed.returncode != 0 or not value or "\n" in value or "\r" in value:
        raise ValueError(f"{label} did not return a safe version string")
    return value


def runtime_facts() -> dict[str, object]:
    return {
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "python_cache_tag": sys.implementation.cache_tag or "",
        "uv_version": _tool_version(("uv", "--version"), label="uv"),
    }


def _canonical_provenance_argv(
    *,
    jobs: int,
    workspace: Path,
    provenance_output: Path,
) -> list[str]:
    return [
        "scripts/control_plane_process_chaos.py",
        "--jobs",
        str(jobs),
        "--workspace",
        workspace.resolve().as_posix(),
        "--provenance-output",
        provenance_output.resolve().as_posix(),
    ]


def _utc_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _validate_timestamp(value: object, *, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{label} is not a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(f"{value[:-1]}+00:00")
    except ValueError as error:
        raise ValueError(f"{label} is not a UTC timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ValueError(f"{label} is not a UTC timestamp")
    return parsed


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


def _provenance_payload(receipt: dict[str, object]) -> dict[str, object]:
    if set(receipt) != _PROVENANCE_RECEIPT_FIELDS:
        raise ValueError("provenance receipt has unexpected or missing fields")
    return {key: value for key, value in receipt.items() if key != "receipt_sha256"}


def _provenance_receipt_hash(payload: dict[str, object]) -> str:
    return _sha256_bytes(_PROVENANCE_RECEIPT_DOMAIN + _canonical_json(payload))


def _validate_source_candidate(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("provenance receipt source candidate is invalid")
    kind = value.get("kind")
    commit = value.get("git_commit")
    if not isinstance(commit, str) or _GIT_COMMIT.fullmatch(commit) is None:
        raise ValueError("provenance receipt source candidate has an invalid commit")
    if kind == "git_commit" and set(value) == {"kind", "git_commit"}:
        return cast(dict[str, object], value)
    fingerprint = value.get("fingerprint")
    if (
        kind != "dirty_candidate"
        or set(value) != {"kind", "git_commit", "fingerprint"}
        or not isinstance(fingerprint, str)
        or _SHA256.fullmatch(fingerprint) is None
    ):
        raise ValueError("provenance receipt source candidate is invalid")
    return cast(dict[str, object], value)


def _validate_uv_lock(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {"path", "sha256", "size_bytes"}:
        raise ValueError("provenance receipt uv.lock binding is invalid")
    if value.get("path") != "uv.lock":
        raise ValueError("provenance receipt uv.lock path is invalid")
    digest = value.get("sha256")
    size = value.get("size_bytes")
    if (
        not isinstance(digest, str)
        or _SHA256.fullmatch(digest) is None
        or type(size) is not int
        or size < 0
    ):
        raise ValueError("provenance receipt uv.lock binding is invalid")
    return cast(dict[str, object], value)


def _validate_runtime(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {
        "python_implementation",
        "python_version",
        "python_cache_tag",
        "uv_version",
    }:
        raise ValueError("provenance receipt runtime facts are invalid")
    if any(not isinstance(item, str) or not item for item in value.values()):
        raise ValueError("provenance receipt runtime facts are invalid")
    return cast(dict[str, object], value)


def _validate_provenance_argv(value: object) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ValueError("provenance receipt argv is invalid")
    if len(value) != 7 or value[0] != "scripts/control_plane_process_chaos.py":
        raise ValueError("provenance receipt argv is invalid")
    if value[1] != "--jobs" or value[3] != "--workspace" or value[5] != "--provenance-output":
        raise ValueError("provenance receipt argv is invalid")
    if not value[2].isdigit() or not 1 <= int(value[2]) <= _MAX_JOBS:
        raise ValueError("provenance receipt argv has an invalid job count")
    return cast(list[str], value)


def _validate_workspace_observations(workspace: Path, summary: dict[str, object]) -> None:
    """Re-read all child state files and cross-check their counts against the receipt summary."""

    root = workspace.resolve()
    states: dict[str, dict[str, object]] = {}
    for name in _STATE_FILES:
        path = _workspace_target(root, name, label="provenance state path")
        _require_regular_file(path, label="provenance state path")
        states[name] = _strict_json_object(
            path.read_bytes(),
            label=f"provenance state {name}",
        )
    scenario = states[_SCENARIO_FILE]
    ready = states[_READY_FILE]
    recovery = states[_RECOVERY_FILE]
    replay = states[_REPLAY_FILE]
    if set(scenario) != {"initial_time", "jobs", "schema_version"}:
        raise ValueError("provenance scenario fields are invalid")
    if (
        scenario.get("schema_version") != _SCHEMA_VERSION
        or scenario.get("initial_time") != "2026-01-01T00:00:00+00:00"
    ):
        raise ValueError("provenance scenario binding is invalid")
    jobs = scenario.get("jobs")
    if type(jobs) is not int or jobs != summary["jobs_requested"]:
        raise ValueError("provenance scenario job count differs from the receipt")
    expected_ready = {
        "schema_version": _SCHEMA_VERSION,
        "crash_phase": summary["crash_phase"],
        "jobs_prepared": jobs,
        "events_before_termination": jobs * 2,
    }
    expected_recovery = {
        "schema_version": _SCHEMA_VERSION,
        "jobs_recovered": jobs,
        "replacement_claims": summary["replacement_claims"],
        "stale_fence_rejections": summary["stale_fence_rejections"],
        "duplicate_delivery_replays": summary["duplicate_delivery_replays"],
    }
    expected_replay = {
        "schema_version": _SCHEMA_VERSION,
        "jobs_replayed": jobs,
        "event_count": summary["event_count"],
        "expected_event_count": summary["expected_event_count"],
        "terminal_verdicts": summary["terminal_verdicts"],
        "event_positions_contiguous": summary["event_positions_contiguous"],
        "event_replay_consistent": summary["event_replay_consistent"],
        "content_addressed_artifacts_verified": summary["content_addressed_artifacts_verified"],
    }
    if ready != expected_ready or recovery != expected_recovery or replay != expected_replay:
        raise ValueError("provenance child observations differ from the receipt summary")


def _evidence_require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _strict_canonical_sqlite_json(value: object, *, label: str) -> object:
    if not isinstance(value, str):
        raise ValueError(f"{label} is not canonical JSON text")

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError(f"{label} contains a duplicate JSON key")
            result[key] = item
        return result

    try:
        decoded = json.loads(
            value,
            object_pairs_hook=unique_object,
            parse_constant=lambda item: (_ for _ in ()).throw(
                ValueError(f"{label} contains an invalid JSON constant: {item}")
            ),
        )
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is not strict canonical JSON") from error
    if canonical_json(decoded) != value:
        raise ValueError(f"{label} is not canonical JSON")
    return decoded


def _sqlite_rows(connection: sqlite3.Connection, table: str) -> list[dict[str, object]]:
    return [dict(row) for row in connection.execute(f'SELECT * FROM "{table}"')]


def _read_retained_sqlite(
    workspace: Path,
) -> tuple[list[StoredEvent], dict[str, list[dict[str, object]]]]:
    database = _workspace_target(workspace, _DATABASE_FILE, label="provenance SQLite path")
    _require_regular_file(database, label="provenance SQLite database")
    uri = f"{database.resolve().as_uri()}?mode=ro&immutable=1"
    try:
        connection = sqlite3.connect(uri, uri=True, isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA query_only = ON")
            integrity = [str(row[0]) for row in connection.execute("PRAGMA integrity_check")]
            _evidence_require(
                integrity == ["ok"],
                "provenance SQLite integrity check failed",
            )
            _evidence_require(
                list(connection.execute("PRAGMA foreign_key_check")) == [],
                "provenance SQLite foreign-key check failed",
            )
            objects = list(
                connection.execute(
                    "SELECT type, name FROM sqlite_schema "
                    "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
                )
            )
            tables = {str(row["name"]) for row in objects if row["type"] == "table"}
            triggers = {str(row["name"]) for row in objects if row["type"] == "trigger"}
            indexes = {str(row["name"]) for row in objects if row["type"] == "index"}
            views = {str(row["name"]) for row in objects if row["type"] == "view"}
            _evidence_require(
                tables == set(_SQLITE_TABLE_COLUMNS),
                "provenance SQLite table schema is invalid",
            )
            _evidence_require(
                triggers == _SQLITE_TRIGGERS,
                "provenance SQLite trigger schema is invalid",
            )
            _evidence_require(
                indexes == _SQLITE_INDEXES and not views,
                "provenance SQLite index or view schema is invalid",
            )
            for table, expected_columns in _SQLITE_TABLE_COLUMNS.items():
                columns = tuple(
                    str(row["name"]) for row in connection.execute(f'PRAGMA table_info("{table}")')
                )
                _evidence_require(
                    columns == expected_columns,
                    f"provenance SQLite {table} columns are invalid",
                )
            rows = {table: _sqlite_rows(connection, table) for table in _SQLITE_TABLE_COLUMNS}
        finally:
            connection.close()
    except (OSError, sqlite3.Error, ValueError) as error:
        if isinstance(error, ValueError):
            raise
        raise ValueError("provenance SQLite database is invalid or unreadable") from error

    event_rows = sorted(rows["events"], key=lambda row: cast(int, row["global_position"]))
    events: list[StoredEvent] = []
    for row in event_rows:
        position = row.get("global_position")
        sequence = row.get("entity_sequence")
        event_id = row.get("event_id")
        entity_type = row.get("entity_type")
        entity_id = row.get("entity_id")
        event_type = row.get("event_type")
        recorded_at = row.get("recorded_at")
        if (
            type(position) is not int
            or type(sequence) is not int
            or sequence < 1
            or any(
                not isinstance(item, str) or not item
                for item in (event_id, entity_type, entity_id, event_type, recorded_at)
            )
        ):
            raise ValueError("provenance SQLite event row has invalid scalar fields")
        _validate_timestamp(recorded_at, label="provenance SQLite event timestamp")
        payload = _strict_canonical_sqlite_json(
            row.get("payload_json"),
            label="provenance SQLite event payload",
        )
        metadata = _strict_canonical_sqlite_json(
            row.get("metadata_json"),
            label="provenance SQLite event metadata",
        )
        if not isinstance(payload, dict) or metadata != {}:
            raise ValueError("provenance SQLite event JSON shape is invalid")
        event_id_text = cast(str, event_id)
        entity_type_text = cast(str, entity_type)
        entity_id_text = cast(str, entity_id)
        event_type_text = cast(str, event_type)
        recorded_at_text = cast(str, recorded_at)
        events.append(
            StoredEvent(
                global_position=position,
                event_id=event_id_text,
                entity_type=entity_type_text,
                entity_id=entity_id_text,
                entity_sequence=sequence,
                event_type=event_type_text,
                payload=payload,
                metadata={},
                recorded_at=recorded_at_text,
            )
        )
    return events, rows


def _manifest_artifact_references(manifest: dict[str, object]) -> dict[str, ArtifactRef]:
    values = manifest.get("artifact_files")
    if not isinstance(values, list):
        raise ValueError("provenance receipt artifact manifest is invalid")
    references: dict[str, ArtifactRef] = {}
    for value in values:
        if not isinstance(value, dict):
            raise ValueError("provenance receipt artifact manifest is invalid")
        path = value.get("path")
        digest = value.get("sha256")
        size = value.get("size_bytes")
        if not isinstance(path, str) or not isinstance(digest, str) or type(size) is not int:
            raise ValueError("provenance receipt artifact manifest is invalid")
        expected_path = f"{_ARTIFACT_DIRECTORY}/sha256/{digest[:2]}/{digest[2:4]}/{digest}"
        if path != expected_path or digest in references:
            raise ValueError("provenance receipt artifact manifest is not canonical CAS layout")
        references[digest] = ArtifactRef(digest=digest, size=size)
    return references


def _event_artifact_reference(
    payload: Mapping[str, object],
    field: str,
    *,
    expected_kind: str,
    manifest: dict[str, ArtifactRef],
) -> ArtifactRef:
    value = payload.get(field)
    if not isinstance(value, dict) or set(value) != _ARTIFACT_REFERENCE_FIELDS:
        raise ValueError(f"provenance event {field} reference is invalid")
    digest = value.get("digest")
    size = value.get("size")
    if (
        not isinstance(digest, str)
        or type(size) is not int
        or value.get("kind") != expected_kind
        or value.get("media_type") != "application/json"
        or value.get("uri") != f"sha256:{digest}"
    ):
        raise ValueError(f"provenance event {field} reference is invalid")
    reference = manifest.get(digest)
    if reference is None or reference.size != size:
        raise ValueError(f"provenance event {field} is absent from the CAS manifest")
    return reference


def _canonical_contract_artifact[ModelT: BaseModel](
    store: ArtifactStore,
    reference: ArtifactRef,
    model_type: type[ModelT],
    *,
    label: str,
) -> ModelT:
    try:
        raw = store.get_bytes(reference)
        model = model_type.model_validate_json(raw)
    except (ArtifactCorruption, ArtifactNotFound, OSError, TypeError, ValueError) as error:
        raise ValueError(f"provenance {label} artifact is invalid") from error
    if canonical_json(model.model_dump(mode="json")).encode("utf-8") != raw:
        raise ValueError(f"provenance {label} artifact is not canonical typed JSON")
    return model


def _payload_text(payload: dict[str, object], field: str, *, label: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value:
        raise ValueError(f"provenance {label} has an invalid {field}")
    return value


def _payload_int(payload: dict[str, object], field: str, *, label: str) -> int:
    value = payload.get(field)
    if type(value) is not int:
        raise ValueError(f"provenance {label} has an invalid {field}")
    return value


def _row_text(row: dict[str, object], field: str, *, label: str) -> str:
    value = row.get(field)
    if not isinstance(value, str) or not value:
        raise ValueError(f"provenance SQLite {label} has an invalid {field}")
    return value


def _row_int(row: dict[str, object], field: str, *, label: str) -> int:
    value = row.get(field)
    if type(value) is not int:
        raise ValueError(f"provenance SQLite {label} has an invalid {field}")
    return value


def _row_float(row: dict[str, object], field: str, *, label: str) -> float:
    value = row.get(field)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"provenance SQLite {label} has an invalid {field}")
    return float(value)


def _verify_sqlite_auxiliary_state(
    rows: dict[str, list[dict[str, object]]],
    *,
    expected_versions: set[tuple[str, str, int]],
    expected_bindings: set[tuple[str, int, str, str, str, str]],
    expected_leases: set[tuple[str, str, int, float, float]],
    expected_counters: set[tuple[str, int]],
    expected_idempotency: dict[tuple[str, str], tuple[str, str]],
    expected_nonces: set[tuple[str, str, str, str, str, str, str]],
) -> None:
    versions = {
        (
            _row_text(row, "entity_type", label="entity version"),
            _row_text(row, "entity_id", label="entity version"),
            _row_int(row, "sequence", label="entity version"),
        )
        for row in rows["entity_versions"]
    }
    _evidence_require(
        versions == expected_versions,
        "provenance SQLite entity-version projection is inconsistent",
    )
    bindings = {
        (
            _row_text(row, "contract_id", label="contract binding"),
            _row_int(row, "revision", label="contract binding"),
            _row_text(row, "bundle_id", label="contract binding"),
            _row_text(row, "bundle_hash", label="contract binding"),
            _row_text(row, "contract_hash", label="contract binding"),
            _row_text(row, "registration_event_id", label="contract binding"),
        )
        for row in rows["contract_revision_bindings"]
    }
    _evidence_require(
        bindings == expected_bindings,
        "provenance SQLite contract-revision projection is inconsistent",
    )
    leases = {
        (
            _row_text(row, "job_id", label="worker lease"),
            _row_text(row, "holder_id", label="worker lease"),
            _row_int(row, "fencing_token", label="worker lease"),
            _row_float(row, "expires_at_epoch", label="worker lease"),
            _row_float(row, "updated_at_epoch", label="worker lease"),
        )
        for row in rows["worker_leases"]
    }
    counters = {
        (
            _row_text(row, "job_id", label="lease counter"),
            _row_int(row, "last_fencing_token", label="lease counter"),
        )
        for row in rows["lease_counters"]
    }
    _evidence_require(
        leases == expected_leases and counters == expected_counters,
        "provenance SQLite lease/fencing state is inconsistent",
    )

    actual_idempotency: dict[tuple[str, str], tuple[str, str]] = {}
    for row in rows["idempotency_records"]:
        scope = _row_text(row, "scope", label="idempotency record")
        key = _row_text(row, "key", label="idempotency record")
        request_digest = _row_text(row, "request_hash", label="idempotency record")
        created_at = _row_text(row, "created_at", label="idempotency record")
        event_ids = _strict_canonical_sqlite_json(
            row["event_ids_json"],
            label="provenance SQLite idempotency event IDs",
        )
        if (
            _SHA256.fullmatch(request_digest) is None
            or not isinstance(event_ids, list)
            or len(event_ids) != 1
            or not isinstance(event_ids[0], str)
        ):
            raise ValueError("provenance SQLite idempotency record is invalid")
        identity = (scope, key)
        if identity in actual_idempotency:
            raise ValueError("provenance SQLite has duplicate idempotency identities")
        actual_idempotency[identity] = (event_ids[0], created_at)
    _evidence_require(
        actual_idempotency == expected_idempotency,
        "provenance SQLite idempotency projection is inconsistent",
    )
    nonces = {
        (
            _row_text(row, "purpose", label="attestation nonce"),
            _row_text(row, "key_id", label="attestation nonce"),
            _row_text(row, "nonce", label="attestation nonce"),
            _row_text(row, "payload_hash", label="attestation nonce"),
            _row_text(row, "entity_type", label="attestation nonce"),
            _row_text(row, "entity_id", label="attestation nonce"),
            _row_text(row, "consumed_at", label="attestation nonce"),
        )
        for row in rows["attestation_nonce_uses"]
    }
    _evidence_require(
        nonces == expected_nonces,
        "provenance SQLite attestation-nonce ledger is inconsistent",
    )


def _verify_projection_terminal_state(
    events: list[StoredEvent],
    *,
    jobs: int,
    proof_ids: set[str],
    event_artifact_digests: set[str],
) -> None:
    try:
        projection = DashboardProjection(events).snapshot()
    except (TypeError, ValueError) as error:
        raise ValueError("provenance Dashboard projection replay failed") from error
    runs = projection.get("runs")
    event_views = projection.get("events")
    artifacts = projection.get("artifacts")
    overview = projection.get("overview")
    if (
        not isinstance(runs, list)
        or not isinstance(event_views, list)
        or not isinstance(artifacts, list)
        or not isinstance(overview, dict)
    ):
        raise ValueError("provenance Dashboard projection has an invalid shape")
    run_ids: set[str] = set()
    for run in runs:
        if (
            not isinstance(run, dict)
            or run.get("status") != "succeeded"
            or run.get("verification") != "accepted"
            or not isinstance(run.get("id"), str)
        ):
            raise ValueError("provenance Dashboard projection has a non-terminal run")
        run_ids.add(cast(str, run["id"]))
    projected_artifacts = {
        cast(str, artifact["digest"])
        for artifact in artifacts
        if isinstance(artifact, dict) and isinstance(artifact.get("digest"), str)
    }
    _evidence_require(
        len(runs) == jobs
        and run_ids == proof_ids
        and len(event_views) == jobs * 5
        and projected_artifacts == event_artifact_digests
        and overview.get("active_runs") == 0
        and overview.get("blocked_nodes") == 0,
        "provenance Dashboard projection terminal state is inconsistent",
    )


def _verify_retained_semantics(
    workspace: Path,
    summary: dict[str, object],
    manifest: dict[str, object],
) -> None:
    jobs = cast(int, summary["jobs_requested"])
    events, rows = _read_retained_sqlite(workspace)
    _evidence_require(
        len(events) == jobs * 5
        and [event.global_position for event in events] == list(range(1, jobs * 5 + 1)),
        "provenance SQLite event positions or count are inconsistent",
    )
    registrations = [event for event in events if event.event_type == "task.registered"]
    _evidence_require(
        len(registrations) == jobs,
        "provenance SQLite registration count is inconsistent",
    )
    manifest_references = _manifest_artifact_references(manifest)
    try:
        store = ArtifactStore(workspace / _ARTIFACT_DIRECTORY)
    except (ArtifactCorruption, OSError, ValueError) as error:
        raise ValueError("provenance CAS store is invalid") from error

    referenced_artifacts: set[str] = set()
    projected_artifacts: set[str] = set()
    proof_ids: set[str] = set()
    expected_versions: set[tuple[str, str, int]] = set()
    expected_bindings: set[tuple[str, int, str, str, str, str]] = set()
    expected_leases: set[tuple[str, str, int, float, float]] = set()
    expected_counters: set[tuple[str, int]] = set()
    expected_idempotency: dict[tuple[str, str], tuple[str, str]] = {}
    expected_nonces: set[tuple[str, str, str, str, str, str, str]] = set()

    for index, registration in enumerate(registrations):
        key = f"job-{index:04d}"
        task_id = registration.entity_id
        task_events = [
            event for event in events if event.entity_type == "task" and event.entity_id == task_id
        ]
        _evidence_require(
            [event.event_type for event in task_events]
            == ["task.registered", "task.claimed", "task.claimed"]
            and [event.entity_sequence for event in task_events] == [1, 2, 3]
            and [event.global_position for event in task_events]
            == [index * 2 + 1, index * 2 + 2, jobs * 2 + index * 3 + 1],
            "provenance task event sequence is inconsistent",
        )
        registered_payload = registration.payload
        bundle_reference = _event_artifact_reference(
            registered_payload,
            "bundle_artifact",
            expected_kind="bundle",
            manifest=manifest_references,
        )
        bundle = _canonical_contract_artifact(
            store,
            bundle_reference,
            FormalizationTaskBundleV1,
            label="bundle",
        )
        referenced_artifacts.add(bundle_reference.digest)
        projected_artifacts.add(bundle_reference.digest)
        bundle_hash = bundle.handoff_hash().value
        contract_hash = bundle.contract.semantic_hash().value
        contract_id = bundle.contract.contract_id.value
        boundary_hash = bundle.proof_boundary.boundary_hash.value
        environment_hash = bundle.contract.formal.environment.environment_hash.value
        _evidence_require(
            bundle.bundle_id.value == task_id
            and registered_payload.get("bundle_id") == task_id
            and registered_payload.get("bundle_hash") == bundle_hash
            and registered_payload.get("contract_id") == contract_id
            and registered_payload.get("revision") == bundle.contract.revision
            and registered_payload.get("contract_hash") == contract_hash
            and registered_payload.get("proof_boundary_hash") == boundary_hash
            and registered_payload.get("environment_hash") == environment_hash
            and bundle.contract.source.locator == f"synthetic://control-plane-chaos/{key}",
            "provenance registered bundle binding is inconsistent",
        )
        builder_attestation = bundle.builder_attestation
        if (
            builder_attestation is None
            or builder_attestation.key_id != "test-only-chaos-builder-v1"
        ):
            raise ValueError("provenance bundle lacks the expected synthetic Builder attestation")

        crashed_claim = task_events[1]
        recovery_claim = task_events[2]
        for claim_event, worker, fence, expiry in (
            (crashed_claim, f"crashed-worker-{key}", 1, "2026-01-01T00:00:01+00:00"),
            (recovery_claim, f"recovery-worker-{key}", 2, "2026-01-01T00:00:03+00:00"),
        ):
            claim_payload = claim_event.payload
            claim_reference = _event_artifact_reference(
                claim_payload,
                "bundle_artifact",
                expected_kind="bundle",
                manifest=manifest_references,
            )
            _evidence_require(
                claim_reference == bundle_reference
                and claim_payload.get("bundle_id") == task_id
                and claim_payload.get("bundle_hash") == bundle_hash
                and claim_payload.get("worker_id") == worker
                and claim_payload.get("fencing_token") == fence
                and claim_payload.get("expires_at") == expiry,
                "provenance claim lease or bundle binding is inconsistent",
            )

        proof_events = [
            event
            for event in events
            if event.entity_type == "proof" and event.payload.get("bundle_id") == task_id
        ]
        _evidence_require(
            len(proof_events) == 1
            and proof_events[0].event_type == "proof.submitted"
            and proof_events[0].entity_sequence == 1
            and proof_events[0].global_position == jobs * 2 + index * 3 + 2,
            "provenance proof event sequence is inconsistent",
        )
        proof_event = proof_events[0]
        proof_reference = _event_artifact_reference(
            proof_event.payload,
            "proof_artifact",
            expected_kind="proof_submission",
            manifest=manifest_references,
        )
        proof = _canonical_contract_artifact(
            store,
            proof_reference,
            ProofSubmissionV1,
            label="proof submission",
        )
        referenced_artifacts.add(proof_reference.digest)
        projected_artifacts.add(proof_reference.digest)
        proof_id = proof.proof_id.value
        proof_ids.add(proof_id)
        dependency_hash = proof_dependency_manifest_hash(proof).value
        _evidence_require(
            proof_event.entity_id == proof_id
            and proof_event.payload.get("proof_id") == proof_id
            and proof_event.payload.get("fencing_token") == 2
            and proof_event.payload.get("contract_id") == contract_id
            and proof_event.payload.get("revision") == bundle.contract.revision
            and proof_event.payload.get("contract_hash") == contract_hash
            and proof_event.payload.get("proof_boundary_hash") == boundary_hash
            and proof_event.payload.get("environment_hash") == environment_hash
            and proof_event.payload.get("dependency_manifest_hash") == dependency_hash
            and proof.contract_id.value == contract_id
            and proof.revision == bundle.contract.revision
            and proof.contract_hash.value == contract_hash
            and proof.proof_boundary_hash.value == boundary_hash
            and proof.environment_hash.value == environment_hash
            and len(proof.provenance) == 1
            and proof.provenance[0].actor_kind.value == "tool"
            and proof.provenance[0].actor_id == "control-plane-chaos-worker",
            "provenance proof submission binding is inconsistent",
        )

        terminal_events = [
            event
            for event in events
            if event.entity_type == "verification" and event.entity_id == proof_id
        ]
        _evidence_require(
            len(terminal_events) == 1
            and terminal_events[0].event_type == "verification.accepted"
            and terminal_events[0].entity_sequence == 1
            and terminal_events[0].global_position == jobs * 2 + index * 3 + 3,
            "provenance verification event sequence is inconsistent",
        )
        terminal_event = terminal_events[0]
        report_reference = _event_artifact_reference(
            terminal_event.payload,
            "verification_artifact",
            expected_kind="verification_report",
            manifest=manifest_references,
        )
        report = _canonical_contract_artifact(
            store,
            report_reference,
            VerificationReportV1,
            label="verification report",
        )
        referenced_artifacts.add(report_reference.digest)
        projected_artifacts.add(report_reference.digest)
        evidence = report.evidence
        verifier_attestation = report.verifier_attestation
        if evidence is None or verifier_attestation is None:
            raise ValueError("provenance verification report lacks verifier evidence")
        _evidence_require(
            terminal_event.payload.get("accepted") is True
            and terminal_event.payload.get("promotion_state") == "not_a_promotion"
            and terminal_event.payload.get("execution_authority_class") == "test-only-local"
            and terminal_event.payload.get("bundle_id") == task_id
            and terminal_event.payload.get("proof_id") == proof_id
            and terminal_event.payload.get("fencing_token") == 2
            and terminal_event.payload.get("contract_hash") == contract_hash
            and terminal_event.payload.get("proof_boundary_hash") == boundary_hash
            and terminal_event.payload.get("report_id") == report.report_id.value
            and report.proof_id.value == proof_id
            and report.contract_hash.value == contract_hash
            and report.proof_boundary_hash.value == boundary_hash
            and report.environment_hash.value == environment_hash
            and report.independent
            and report.kernel_passed
            and report.build_passed
            and report.dependency_check_passed
            and report.clean_environment
            and not report.observed_axioms
            and verifier_attestation.key_id == "test-only-chaos-verifier-v1",
            "provenance verification report binding is inconsistent",
        )
        evidence_reference = manifest_references.get(evidence.evidence_artifact_digest)
        if evidence_reference is None:
            raise ValueError("provenance verifier evidence is absent from the CAS manifest")
        evidence_artifact = _canonical_contract_artifact(
            store,
            evidence_reference,
            VerificationEvidenceArtifactV1,
            label="verifier evidence",
        )
        referenced_artifacts.add(evidence_reference.digest)
        unsigned_observation = report.model_copy(
            update={"evidence": None, "verifier_attestation": None}
        )
        _evidence_require(
            evidence_artifact.evidence_id == evidence.evidence_id
            and evidence_artifact.bundle_id.value == task_id
            and evidence_artifact.bundle_hash.value == bundle_hash
            and evidence_artifact.contract_id.value == contract_id
            and evidence_artifact.revision == bundle.contract.revision
            and evidence_artifact.contract_hash.value == contract_hash
            and evidence_artifact.proof_id.value == proof_id
            and evidence_artifact.proof_boundary_hash.value == boundary_hash
            and evidence_artifact.proof_submission_artifact_digest == proof_reference.digest
            and evidence_artifact.dependency_manifest_hash.value == dependency_hash
            and evidence_artifact.verification_report_id == report.report_id
            and evidence_artifact.verification_observation_hash
            == unsigned_observation.report_hash()
            and evidence_artifact.environment.environment_hash.value == environment_hash
            and evidence.environment_hash.value == environment_hash
            and evidence.dependency_manifest_hash.value == dependency_hash
            and evidence.worker_image_digest == evidence_artifact.oci.worker_image_digest
            and evidence.wrapper_protocol == evidence_artifact.oci.wrapper_protocol
            and evidence.command_policy_hash == evidence_artifact.oci.command_policy_hash
            and evidence.command_hash == evidence_artifact.oci.command_hash,
            "provenance verifier evidence binding is inconsistent",
        )

        expected_versions.update(
            {
                ("task", task_id, 3),
                ("proof", proof_id, 1),
                ("verification", proof_id, 1),
            }
        )
        expected_bindings.add(
            (
                contract_id,
                bundle.contract.revision,
                task_id,
                bundle_hash,
                contract_hash,
                registration.event_id,
            )
        )
        expected_leases.add((task_id, f"recovery-worker-{key}", 2, 1767225603.0, 1767225602.0))
        expected_counters.add((task_id, 2))
        for scope, idempotency_key, event in (
            ("register_bundle", f"register-{key}", registration),
            ("claim", f"claim-{key}", crashed_claim),
            ("claim", f"replacement-claim-{key}", recovery_claim),
            ("submit_proof", f"submit-{key}", proof_event),
            ("verify_submission", f"verify-{key}", terminal_event),
        ):
            expected_idempotency[(scope, idempotency_key)] = (
                event.event_id,
                event.recorded_at,
            )
        expected_nonces.update(
            {
                (
                    builder_attestation.purpose.value,
                    builder_attestation.key_id,
                    builder_attestation.nonce,
                    builder_attestation.payload_hash.value,
                    "task",
                    task_id,
                    registration.recorded_at,
                ),
                (
                    verifier_attestation.purpose.value,
                    verifier_attestation.key_id,
                    verifier_attestation.nonce,
                    verifier_attestation.payload_hash.value,
                    "verification",
                    proof_id,
                    terminal_event.recorded_at,
                ),
            }
        )

    _evidence_require(
        len(proof_ids) == jobs and referenced_artifacts == set(manifest_references),
        "provenance CAS contains missing, unreferenced, or cross-job artifacts",
    )
    _verify_sqlite_auxiliary_state(
        rows,
        expected_versions=expected_versions,
        expected_bindings=expected_bindings,
        expected_leases=expected_leases,
        expected_counters=expected_counters,
        expected_idempotency=expected_idempotency,
        expected_nonces=expected_nonces,
    )
    _verify_projection_terminal_state(
        events,
        jobs=jobs,
        proof_ids=proof_ids,
        event_artifact_digests=projected_artifacts,
    )


def _validate_provenance_receipt(
    receipt: dict[str, object],
    *,
    workspace: Path,
    receipt_path: Path,
    root: Path,
) -> dict[str, object]:
    payload = _provenance_payload(receipt)
    if receipt.get("schema_version") != _PROVENANCE_RECEIPT_SCHEMA:
        raise ValueError("provenance receipt has an unsupported schema version")
    receipt_hash = receipt.get("receipt_sha256")
    if not isinstance(receipt_hash, str) or _SHA256.fullmatch(receipt_hash) is None:
        raise ValueError("provenance receipt hash is invalid")
    if receipt_hash != _provenance_receipt_hash(payload):
        raise ValueError("provenance receipt hash does not match")
    run_id = receipt.get("run_id")
    if not isinstance(run_id, str) or _RUN_ID.fullmatch(run_id) is None:
        raise ValueError("provenance receipt run_id is invalid")
    candidate = _validate_source_candidate(receipt.get("source_candidate"))
    lock = _validate_uv_lock(receipt.get("uv_lock"))
    runtime = _validate_runtime(receipt.get("runtime"))
    argv = _validate_provenance_argv(receipt.get("argv"))
    started_at = _validate_timestamp(receipt.get("started_at"), label="provenance receipt start")
    ended_at = _validate_timestamp(receipt.get("ended_at"), label="provenance receipt end")
    duration = receipt.get("duration_ms")
    if type(duration) is not int or duration < 0 or ended_at < started_at:
        raise ValueError("provenance receipt timing facts are invalid")
    summary = receipt.get("summary")
    if not isinstance(summary, dict):
        raise ValueError("provenance receipt summary is invalid")
    normalized_summary = cast(dict[str, object], summary)
    _validate_summary(normalized_summary)
    summary_hash = receipt.get("summary_report_sha256")
    if not isinstance(summary_hash, str) or summary_hash != _report_sha256(normalized_summary):
        raise ValueError("provenance receipt summary hash does not match")
    if argv[2] != str(normalized_summary["jobs_requested"]):
        raise ValueError("provenance receipt argv job count differs from its summary")
    expected_argv = _canonical_provenance_argv(
        jobs=cast(int, normalized_summary["jobs_requested"]),
        workspace=workspace,
        provenance_output=receipt_path,
    )
    if argv != expected_argv:
        raise ValueError("provenance receipt argv does not match the retained paths")
    manifest = _validate_workspace_manifest(receipt.get("workspace_manifest"))
    if candidate != source_candidate(root) or lock != _uv_lock(root) or runtime != runtime_facts():
        raise ValueError("provenance receipt source, lock, or runtime facts have drifted")
    _validate_workspace_observations(workspace, normalized_summary)
    actual_manifest = workspace_manifest(workspace)
    if manifest != actual_manifest:
        raise ValueError("provenance receipt workspace manifest differs from retained evidence")
    _verify_retained_semantics(workspace, normalized_summary, actual_manifest)
    return receipt


def _read_provenance_receipt(path: Path) -> dict[str, object]:
    _require_regular_file(path, label="provenance receipt")
    try:
        return _strict_json_object(path.read_bytes(), label="provenance receipt")
    except OSError as error:
        raise ValueError("cannot read provenance receipt") from error


def _receipt_path_under_root(receipt_path: Path, *, root: Path) -> Path:
    checkout = root.resolve()
    _require_directory(checkout, label="source checkout")
    candidate = receipt_path.absolute()
    try:
        relative = candidate.relative_to(checkout)
    except ValueError as error:
        raise ValueError("provenance receipt must stay inside the source checkout") from error
    if not relative.parts or relative.parts[0] != _REPORT_DIRECTORY:
        raise ValueError("provenance receipt must stay inside release-evidence")
    checked = _workspace_target(
        checkout,
        relative.as_posix(),
        label="provenance receipt path",
    )
    if _is_link_or_reparse(checked):
        raise ValueError("provenance receipt path may not traverse a link or junction")
    _require_regular_file(checked, label="provenance receipt")
    return checked


def verify_provenance_receipt(
    receipt_path: Path,
    *,
    workspace: Path,
    root: Path = _REPO_ROOT,
) -> dict[str, object]:
    """Independently verify a V2 receipt against its retained workspace and checkout facts."""

    checkout = _bound_execution_root(root)
    receipt_file = _receipt_path_under_root(receipt_path, root=checkout)
    evidence_root = workspace.absolute()
    _require_directory(evidence_root, label="provenance workspace")
    receipt = _read_provenance_receipt(receipt_file)
    return _validate_provenance_receipt(
        receipt,
        workspace=evidence_root,
        receipt_path=receipt_file,
        root=checkout,
    )


def write_provenance_receipt_exclusive(
    output: Path,
    receipt: dict[str, object],
    *,
    root: Path = _REPO_ROOT,
) -> Path:
    """Write a V2 receipt once after validating every provenance binding."""

    candidate = _validated_output_path(output, root=root)
    receipt_payload = _provenance_payload(receipt)
    receipt_hash = receipt.get("receipt_sha256")
    if not isinstance(receipt_hash, str) or receipt_hash != _provenance_receipt_hash(
        receipt_payload
    ):
        raise ValueError("provenance receipt hash does not match")
    payload = _canonical_json(receipt) + b"\n"
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
            raise ValueError("provenance receipt output must be a regular file")
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
        raise ValueError("provenance receipt write failed") from error
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
        raw = _strict_json_object(path.read_bytes(), label=f"process-chaos child state {path.name}")
    except (OSError, ValueError) as error:
        raise AssertionError(f"process-chaos child did not produce valid {path.name}") from error
    return raw


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

    if isinstance(jobs, bool) or not isinstance(jobs, int) or not 1 <= jobs <= _MAX_JOBS:
        raise ValueError(f"jobs must be an integer between 1 and {_MAX_JOBS}")
    return min(
        _CHILD_TIMEOUT_MAX_SECONDS,
        _CHILD_TIMEOUT_BASE_SECONDS + (jobs * _CHILD_TIMEOUT_PER_JOB_SECONDS),
    )


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

    if isinstance(jobs, bool) or not isinstance(jobs, int) or not 1 <= jobs <= _MAX_JOBS:
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


def run_process_campaign_with_provenance(
    *,
    jobs: int,
    workspace: Path,
    provenance_output: Path,
    root: Path = _REPO_ROOT,
) -> tuple[dict[str, object], dict[str, object]]:
    """Run a retained campaign and bind its resulting workspace to a V2 local provenance receipt."""

    checkout = _bound_execution_root(root)
    requested_workspace = workspace.absolute()
    if requested_workspace.exists() or requested_workspace.is_symlink():
        _require_directory(requested_workspace, label="provenance workspace")
    evidence_workspace = requested_workspace.resolve()
    output = _validated_output_path(provenance_output, root=checkout)
    candidate = source_candidate(checkout)
    lock = _uv_lock(checkout)
    runtime = runtime_facts()
    started_at = datetime.now(UTC)
    started_monotonic = time.monotonic_ns()
    summary = _canonical_object(run_process_campaign(jobs=jobs, workspace=evidence_workspace))
    ended_at = datetime.now(UTC)
    duration_ms = max(0, (time.monotonic_ns() - started_monotonic) // 1_000_000)
    _validate_summary(summary)
    receipt: dict[str, object] = {
        "schema_version": _PROVENANCE_RECEIPT_SCHEMA,
        "receipt_sha256": "",
        "run_id": secrets.token_hex(16),
        "source_candidate": candidate,
        "uv_lock": lock,
        "runtime": runtime,
        "argv": _canonical_provenance_argv(
            jobs=jobs,
            workspace=evidence_workspace,
            provenance_output=output,
        ),
        "started_at": _utc_timestamp(started_at),
        "ended_at": _utc_timestamp(ended_at),
        "duration_ms": duration_ms,
        "summary": summary,
        "summary_report_sha256": _report_sha256(summary),
        "workspace_manifest": workspace_manifest(evidence_workspace),
    }
    receipt["receipt_sha256"] = _provenance_receipt_hash(_provenance_payload(receipt))
    _validate_provenance_receipt(
        receipt,
        workspace=evidence_workspace,
        receipt_path=output,
        root=checkout,
    )
    written = write_provenance_receipt_exclusive(output, receipt, root=checkout)
    if written != output:
        raise AssertionError("provenance receipt write changed the requested output path")
    return summary, receipt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
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
    parser.add_argument(
        "--provenance-output",
        type=Path,
        help="new in-repository V2 receipt path; requires a retained --workspace",
    )
    parser.add_argument(
        "--verify-provenance",
        type=Path,
        help="verify an existing V2 receipt against its retained --workspace without running jobs",
    )
    args = parser.parse_args()
    if args.verify_provenance is not None:
        if args.workspace is None:
            parser.error("--verify-provenance requires --workspace")
        if args.output is not None or args.provenance_output is not None:
            parser.error("--verify-provenance cannot be combined with output options")
        verified = verify_provenance_receipt(args.verify_provenance, workspace=args.workspace)
        print(
            json.dumps(
                {
                    "receipt_sha256": verified["receipt_sha256"],
                    "status": "verified_local_synthetic_provenance",
                },
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return
    if args.output is not None and args.provenance_output is not None:
        parser.error("--output cannot be combined with --provenance-output")
    if args.provenance_output is not None:
        if args.workspace is None:
            parser.error("--provenance-output requires --workspace")
        summary, _receipt = run_process_campaign_with_provenance(
            jobs=args.jobs,
            workspace=args.workspace,
            provenance_output=args.provenance_output,
        )
        print(json.dumps(summary, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
        return
    output = None if args.output is None else _validated_output_path(args.output, root=_REPO_ROOT)
    summary = run_process_campaign(jobs=args.jobs, workspace=args.workspace)
    envelope = report_envelope(summary)
    if output is not None:
        write_report_exclusive(output, envelope)
    print(json.dumps(summary, ensure_ascii=True, separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    main()
