"""Purpose-built child worker for ``control_plane_process_chaos.py``.

This module is deliberately not a general worker launcher. Its only supported phases operate on
the synthetic, parent-created process-chaos workspace. The parent terminates the ``prepare`` phase
after it has durably registered synthetic bundles and acquired leases; later phases start in new
OS processes and recover only from that workspace's SQLite database and artifact store.
"""

from __future__ import annotations

import argparse
import json
import os
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, cast

from autolean_contracts import (
    FormalizationTaskBundleV1,
    HmacAttestationSignerV1,
    ProofSubmissionV1,
    VerificationReportV1,
)
from autolean_control_plane import ArtifactStore, DashboardProjection, EventStore
from autolean_control_plane.errors import StaleFence
from autolean_control_plane.events import StoredEvent

from scripts.control_plane_chaos import (
    _TEST_ONLY_BUILDER_KEY,
    _TEST_ONLY_VERIFIER_KEY,
    MutableClock,
    _bundle,
    _passing_report,
    _plane,
    _submission,
)

_SCENARIO_FILE = "scenario.json"
_READY_FILE = "crash-ready.json"
_RECOVERY_FILE = "recovery.json"
_REPLAY_FILE = "replay.json"
_DATABASE_FILE = "control-plane-process-chaos.sqlite3"
_ARTIFACT_DIRECTORY = "artifacts"
_SCHEMA_VERSION = "autolean.control-plane-process-chaos.v1"
_INITIAL_TIME = datetime(2026, 1, 1, tzinfo=UTC)
_PREPARE: Literal["prepare"] = "prepare"
_RECOVER: Literal["recover"] = "recover"
_REPLAY: Literal["replay"] = "replay"
_PHASES = (_PREPARE, _RECOVER, _REPLAY)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _workspace_path(value: Path) -> Path:
    root = value.resolve()
    if not root.is_dir():
        raise ValueError("process-chaos workspace must be an existing directory")
    if not (root / _SCENARIO_FILE).is_file():
        raise ValueError("process-chaos workspace is missing its parent-created scenario")
    return root


def _read_json_object(path: Path) -> dict[str, object]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid process-chaos state file: {path.name}") from error
    if not isinstance(raw, dict):
        raise ValueError(f"process-chaos state file must contain an object: {path.name}")
    return cast(dict[str, object], raw)


def _read_scenario(root: Path) -> int:
    payload = _read_json_object(root / _SCENARIO_FILE)
    if payload.get("schema_version") != _SCHEMA_VERSION:
        raise ValueError("process-chaos scenario has an unexpected schema version")
    if payload.get("initial_time") != _INITIAL_TIME.isoformat():
        raise ValueError("process-chaos scenario has an unexpected initial time")
    jobs = payload.get("jobs")
    if not isinstance(jobs, int) or isinstance(jobs, bool) or not 1 <= jobs <= 1_000:
        raise ValueError("process-chaos scenario has an invalid job count")
    return jobs


def _write_json_once(path: Path, payload: dict[str, object]) -> None:
    """Create one state file without deleting or replacing an existing file."""

    serialized = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    try:
        with path.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(serialized)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError as error:
        raise ValueError(f"process-chaos state file already exists: {path.name}") from error


def _fixture_bundle(key: str) -> FormalizationTaskBundleV1:
    fixture_clock = MutableClock(_INITIAL_TIME)
    builder = HmacAttestationSignerV1(_TEST_ONLY_BUILDER_KEY, clock=fixture_clock)
    return _bundle(
        key=key,
        signer=builder,
        clock=fixture_clock,
        nonce=f"builder-{key:0>24}",
    )


def _fixture_submission(bundle: FormalizationTaskBundleV1, key: str) -> ProofSubmissionV1:
    return _submission(bundle, key=key, clock=MutableClock(_INITIAL_TIME))


def _artifact_digest_from_event(event: StoredEvent, field: str) -> str:
    reference = event.payload.get(field)
    if not isinstance(reference, dict):
        raise AssertionError(f"event has no {field}")
    digest = reference.get("digest")
    if not isinstance(digest, str):
        raise AssertionError(f"event {field} has no digest")
    return digest


def _prepare(root: Path) -> None:
    jobs = _read_scenario(root)
    clock = MutableClock(_INITIAL_TIME)
    plane = _plane(root / _DATABASE_FILE, root / _ARTIFACT_DIRECTORY, clock)
    for job in range(jobs):
        key = f"job-{job:04d}"
        bundle = _fixture_bundle(key)
        plane.register_bundle(bundle, idempotency_key=f"register-{key}")
        plane.claim(
            bundle.bundle_id.value,
            worker_id=f"crashed-worker-{key}",
            ttl_seconds=1.0,
            idempotency_key=f"claim-{key}",
        )

    _write_json_once(
        root / _READY_FILE,
        {
            "crash_phase": "after_durable_registration_and_claim_before_proof_submission",
            "events_before_termination": jobs * 2,
            "jobs_prepared": jobs,
            "schema_version": _SCHEMA_VERSION,
        },
    )
    # The parent deliberately terminates this dedicated process. It starts no subprocesses and
    # performs no further writes after publishing the durable checkpoint.
    while True:
        time.sleep(60.0)


def _recover(root: Path) -> None:
    jobs = _read_scenario(root)
    clock = MutableClock(_INITIAL_TIME + timedelta(seconds=2.0))
    plane = _plane(root / _DATABASE_FILE, root / _ARTIFACT_DIRECTORY, clock)
    verifier = HmacAttestationSignerV1(_TEST_ONLY_VERIFIER_KEY, clock=clock)
    stale_fence_rejections = 0
    duplicate_replays = 0
    replacement_claims = 0

    for job in range(jobs):
        key = f"job-{job:04d}"
        bundle = _fixture_bundle(key)
        binding = plane.register_bundle(bundle, idempotency_key=f"register-{key}")
        _require(binding.bundle_id == bundle.bundle_id.value, "bundle replay returned another task")
        old_claim = plane.claim(
            bundle.bundle_id.value,
            worker_id=f"crashed-worker-{key}",
            ttl_seconds=1.0,
            idempotency_key=f"claim-{key}",
        )
        stale_submission = _fixture_submission(bundle, f"stale-{key}")
        try:
            plane.submit_proof(
                bundle.bundle_id.value,
                lease=old_claim.lease,
                submission=stale_submission,
                idempotency_key=f"stale-submit-{key}",
            )
        except StaleFence:
            stale_fence_rejections += 1
        else:
            raise AssertionError("an expired fencing token submitted a recovered proof")

        replacement = plane.claim(
            bundle.bundle_id.value,
            worker_id=f"recovery-worker-{key}",
            ttl_seconds=1.0,
            idempotency_key=f"replacement-claim-{key}",
        )
        _require(
            replacement.lease.fencing_token > old_claim.lease.fencing_token,
            "recovery claim did not advance the fencing token",
        )
        replacement_claims += 1
        submission = _fixture_submission(bundle, key)
        submitted = plane.submit_proof(
            bundle.bundle_id.value,
            lease=replacement.lease,
            submission=submission,
            idempotency_key=f"submit-{key}",
        )
        report = _passing_report(
            plane,
            bundle,
            submission,
            key=key,
            signer=verifier,
            clock=clock,
        )
        verified = plane.verify_submission(
            bundle.bundle_id.value,
            lease=replacement.lease,
            report=report,
            idempotency_key=f"verify-{key}",
        )
        _require(verified.accepted, "synthetic recovered verification was not accepted")

        # Network retries carry the same idempotency identity and must return the durable result.
        _require(
            plane.register_bundle(bundle, idempotency_key=f"register-{key}") == binding,
            "duplicate registration replay changed the task binding",
        )
        _require(
            plane.claim(
                bundle.bundle_id.value,
                worker_id=f"recovery-worker-{key}",
                ttl_seconds=1.0,
                idempotency_key=f"replacement-claim-{key}",
            )
            == replacement,
            "duplicate recovery claim replay changed the lease receipt",
        )
        _require(
            plane.submit_proof(
                bundle.bundle_id.value,
                lease=replacement.lease,
                submission=submission,
                idempotency_key=f"submit-{key}",
            )
            == submitted,
            "duplicate proof delivery created another proof event",
        )
        _require(
            plane.verify_submission(
                bundle.bundle_id.value,
                lease=replacement.lease,
                report=report,
                idempotency_key=f"verify-{key}",
            )
            == verified,
            "duplicate verification delivery created another terminal verdict",
        )
        duplicate_replays += 4

    _write_json_once(
        root / _RECOVERY_FILE,
        {
            "duplicate_delivery_replays": duplicate_replays,
            "jobs_recovered": jobs,
            "replacement_claims": replacement_claims,
            "schema_version": _SCHEMA_VERSION,
            "stale_fence_rejections": stale_fence_rejections,
        },
    )


def _replay(root: Path) -> None:
    jobs = _read_scenario(root)
    replay_clock = MutableClock(_INITIAL_TIME + timedelta(seconds=3.0))
    plane = _plane(root / _DATABASE_FILE, root / _ARTIFACT_DIRECTORY, replay_clock)
    events = plane.events.read_all()
    replayed_events = EventStore(root / _DATABASE_FILE, clock=replay_clock).read_all()
    _require(events == replayed_events, "fresh process event replay changed the persisted sequence")
    _require(
        [event.global_position for event in events] == list(range(1, len(events) + 1)),
        "event positions are not contiguous",
    )
    expected_event_count = jobs * 5
    _require(len(events) == expected_event_count, "unexpected persisted event count")
    _require(
        plane.events.count_events(entity_type="proof") == jobs,
        "a synthetic task lost or duplicated a proof event",
    )
    _require(
        plane.events.count_events(entity_type="verification") == jobs,
        "a recovered proof has more or fewer than one terminal verdict",
    )

    artifact_store = ArtifactStore(root / _ARTIFACT_DIRECTORY)
    verified_artifacts = 0
    for job in range(jobs):
        key = f"job-{job:04d}"
        bundle = _fixture_bundle(key)
        binding = plane.get_binding(bundle.bundle_id.value)
        artifact_store.verify(binding.bundle_artifact)
        verified_artifacts += 1
        submission = _fixture_submission(bundle, key)
        proof_events = plane.events.read_stream("proof", submission.proof_id.value)
        _require(len(proof_events) == 1, "recovered proof stream is not singular")
        artifact_store.get_bytes(_artifact_digest_from_event(proof_events[0], "proof_artifact"))
        verified_artifacts += 1
        terminal_events = plane.events.read_stream("verification", submission.proof_id.value)
        _require(len(terminal_events) == 1, "recovered proof has no singular terminal verdict")
        verification_bytes = artifact_store.get_bytes(
            _artifact_digest_from_event(terminal_events[0], "verification_artifact")
        )
        report = VerificationReportV1.model_validate_json(verification_bytes)
        evidence = report.evidence
        if evidence is None:
            raise AssertionError("verification report has no verifier evidence")
        artifact_store.get_bytes(evidence.evidence_artifact_digest)
        verified_artifacts += 2

    projection = DashboardProjection(events).snapshot()
    runs = projection.get("runs")
    _require(isinstance(runs, list) and len(runs) == jobs, "event projection lost runs")
    _write_json_once(
        root / _REPLAY_FILE,
        {
            "content_addressed_artifacts_verified": verified_artifacts,
            "event_count": len(events),
            "event_positions_contiguous": True,
            "event_replay_consistent": True,
            "expected_event_count": expected_event_count,
            "jobs_replayed": jobs,
            "schema_version": _SCHEMA_VERSION,
            "terminal_verdicts": jobs,
        },
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--phase", choices=_PHASES, required=True)
    args = parser.parse_args()
    root = _workspace_path(args.workspace)
    phase = cast(str, args.phase)
    if phase == _PREPARE:
        _prepare(root)
    elif phase == _RECOVER:
        _recover(root)
    elif phase == _REPLAY:
        _replay(root)
    else:  # argparse constrains this, but keep the child closed if this module is reused.
        raise AssertionError(f"unsupported process-chaos phase: {phase}")


if __name__ == "__main__":
    main()
