from __future__ import annotations

import json
from pathlib import Path

from scripts.control_plane_chaos import run_campaign


def test_small_chaos_campaign_is_deterministic_and_non_sensitive(tmp_path: Path) -> None:
    first = run_campaign(jobs=3, restart_every=2, workspace=tmp_path / "first")
    second = run_campaign(jobs=3, restart_every=2, workspace=tmp_path / "second")

    assert first == second
    assert first["evidence_scope"] == "simulated_control_plane_only"
    assert first["lean_or_oci_execution"] is False
    assert first["jobs_completed"] == 3
    assert first["control_plane_restarts"] == 2
    assert first["restart_mode"] == "in_process_service_reconstruction"
    assert first["os_process_kill_exercised"] is False
    assert first["idempotent_replays"] == 12
    assert first["expired_attestation_replays"] == 6
    assert first["replacement_claims"] == 3
    assert first["stale_fence_rejections"] == 3
    assert first["nonce_replay_rejections"] == 1
    assert first["terminal_verdicts"] == 3
    assert first["event_count"] == 16
    assert first["expected_event_count"] == 16
    assert first["event_positions_contiguous"] is True
    assert first["event_replay_consistent"] is True
    assert first["task_loss_detected"] is False
    assert first["duplicate_terminal_verdict_detected"] is False

    summary = json.dumps(first, sort_keys=True)
    assert "by\\n" not in summary
    assert "proof_source" not in summary
    assert "prompt" not in summary
    assert "key-material" not in summary
