from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from scripts.control_plane_process_chaos import (
    report_envelope,
    run_process_campaign,
    write_report_exclusive,
)


def _valid_summary(jobs: int = 1_000) -> dict[str, object]:
    return {
        "schema_version": "autolean.control-plane-process-chaos.v1",
        "evidence_scope": "synthetic_control_plane_process_recovery_only",
        "lean_or_oci_execution": False,
        "network_or_model_execution": False,
        "test_only_hmac_authority": True,
        "jobs_requested": jobs,
        "jobs_completed": jobs,
        "child_processes_started": 3,
        "os_process_kill_exercised": True,
        "process_termination_target": "purpose_built_prepare_worker",
        "crash_phase": "after_durable_registration_and_claim_before_proof_submission",
        "restart_mode": "new_os_processes_reopen_persisted_sqlite_wal_and_artifacts",
        "replacement_claims": jobs,
        "expired_leases": jobs,
        "stale_fence_rejections": jobs,
        "duplicate_delivery_replays": jobs * 4,
        "terminal_verdicts": jobs,
        "per_proof_terminal_verdicts": 1,
        "event_count": jobs * 5,
        "expected_event_count": jobs * 5,
        "event_positions_contiguous": True,
        "event_replay_consistent": True,
        "content_addressed_artifacts_verified": jobs * 4,
        "task_loss_detected": False,
        "duplicate_terminal_verdict_detected": False,
        "does_not_exercise": (
            "lean",
            "oci",
            "network",
            "model_provider",
            "real_attestation_authority",
            "power_loss",
            "mid_transaction_sqlite_kill",
        ),
    }


@pytest.mark.integration
def test_small_process_chaos_campaign_kills_and_recovers_a_child(tmp_path: Path) -> None:
    workspace = tmp_path / "retained-process-chaos"
    summary = run_process_campaign(jobs=2, workspace=workspace)

    assert summary["evidence_scope"] == "synthetic_control_plane_process_recovery_only"
    assert summary["lean_or_oci_execution"] is False
    assert summary["network_or_model_execution"] is False
    assert summary["jobs_completed"] == 2
    assert summary["child_processes_started"] == 3
    assert summary["os_process_kill_exercised"] is True
    assert summary["restart_mode"] == "new_os_processes_reopen_persisted_sqlite_wal_and_artifacts"
    assert summary["replacement_claims"] == 2
    assert summary["expired_leases"] == 2
    assert summary["stale_fence_rejections"] == 2
    assert summary["duplicate_delivery_replays"] == 8
    assert summary["terminal_verdicts"] == 2
    assert summary["event_count"] == 10
    assert summary["expected_event_count"] == 10
    assert summary["content_addressed_artifacts_verified"] == 8
    assert summary["event_positions_contiguous"] is True
    assert summary["event_replay_consistent"] is True
    assert summary["task_loss_detected"] is False
    assert summary["duplicate_terminal_verdict_detected"] is False

    for name in ("scenario.json", "crash-ready.json", "recovery.json", "replay.json"):
        state = (workspace / name).read_text(encoding="utf-8")
        assert "proof_source" not in state
        assert "key-material" not in state

    rendered = json.dumps(summary, sort_keys=True)
    assert "by\\n" not in rendered
    assert "proof_source" not in rendered
    assert "key-material" not in rendered


def test_process_chaos_refuses_a_nonempty_retained_workspace(tmp_path: Path) -> None:
    workspace = tmp_path / "nonempty"
    workspace.mkdir()
    sentinel = workspace / "keep.txt"
    sentinel.write_text("do not remove", encoding="utf-8")

    with pytest.raises(ValueError, match="must be empty"):
        run_process_campaign(jobs=1, workspace=workspace)

    assert sentinel.read_text(encoding="utf-8") == "do not remove"


def test_report_envelope_is_deterministic_and_content_bound() -> None:
    summary = _valid_summary()

    first = report_envelope(summary)
    second = report_envelope(dict(reversed(tuple(summary.items()))))

    assert first == second
    assert first["schema_version"] == ("autolean.control-plane-process-chaos-report-envelope.v1")
    assert first["report_sha256"] == (
        "d80c2c0dbcbab22bfcbd0bea13f41e07c5f337a4a93d82203ef060e7765a2847"
    )
    assert isinstance(first["report"], dict)
    summary["jobs_completed"] = 999
    assert first["report"]["jobs_completed"] == 1_000

    changed = report_envelope(_valid_summary(999))
    assert changed["report_sha256"] != first["report_sha256"]
    with pytest.raises(ValueError, match="unexpected or missing"):
        report_envelope({**_valid_summary(), "prompt": "not a report field"})


def test_report_write_is_exclusive_and_confined(tmp_path: Path) -> None:
    report_root = tmp_path / "repository"
    evidence = report_root / "release-evidence"
    evidence.mkdir(parents=True)
    output = Path("release-evidence/process-chaos.v1.json")
    envelope = report_envelope(_valid_summary())

    written = write_report_exclusive(output, envelope, root=report_root)

    expected_output = evidence / "process-chaos.v1.json"
    assert written == expected_output
    assert json.loads(expected_output.read_text(encoding="ascii")) == envelope
    with pytest.raises(ValueError, match="already exists"):
        write_report_exclusive(output, envelope, root=report_root)
    with pytest.raises(ValueError, match="inside release-evidence"):
        write_report_exclusive(tmp_path / "outside.json", envelope, root=report_root)
    with pytest.raises(ValueError, match="inside release-evidence"):
        write_report_exclusive(Path("scripts/not-evidence.json"), envelope, root=report_root)
    with pytest.raises(ValueError, match=r"\.json"):
        write_report_exclusive(Path("release-evidence/not-json.txt"), envelope, root=report_root)

    tampered = report_envelope(_valid_summary())
    changed_report = report_envelope(_valid_summary(999))["report"]
    assert isinstance(changed_report, dict)
    tampered["report"] = changed_report
    with pytest.raises(ValueError, match="hash does not match"):
        write_report_exclusive(
            Path("release-evidence/tampered.v1.json"),
            tampered,
            root=report_root,
        )


def test_report_write_refuses_linked_parent(tmp_path: Path) -> None:
    report_root = tmp_path / "repository"
    evidence = report_root / "release-evidence"
    outside = evidence / "outside"
    outside.mkdir(parents=True)
    linked = evidence / "linked"
    try:
        os.symlink(outside, linked, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable")

    with pytest.raises(ValueError, match="link or junction"):
        write_report_exclusive(
            linked / "report.json",
            report_envelope(_valid_summary()),
            root=report_root,
        )


def test_report_write_refuses_an_existing_link_target(tmp_path: Path) -> None:
    report_root = tmp_path / "repository"
    evidence = report_root / "release-evidence"
    evidence.mkdir(parents=True)
    output = evidence / "report.v1.json"
    try:
        os.symlink(evidence / "missing-target.json", output)
    except OSError:
        pytest.skip("file symlinks are unavailable")

    with pytest.raises(ValueError, match="already exists"):
        write_report_exclusive(output, report_envelope(_valid_summary()), root=report_root)
