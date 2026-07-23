from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.control_plane_process_chaos import run_process_campaign


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
