from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import uuid
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from itertools import pairwise
from pathlib import Path

import pytest

from scripts.control_plane_process_chaos import (
    _manifest_hash,
    _provenance_payload,
    _provenance_receipt_hash,
    _timeout_seconds,
    report_envelope,
    run_process_campaign,
    run_process_campaign_with_provenance,
    verify_provenance_receipt,
    workspace_manifest,
    write_report_exclusive,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]


def test_child_timeout_has_exact_bounded_endpoints_and_is_strictly_monotonic() -> None:
    budgets = [_timeout_seconds(jobs) for jobs in (1, 2, 999, 1_000)]

    assert budgets == pytest.approx([30.27, 30.54, 299.73, 300.0])
    assert all(left < right for left, right in pairwise(budgets))
    assert 240.0 <= budgets[-1] <= 300.0


@pytest.mark.parametrize("jobs", [True, False, 0, -1, 1_001, 1.0, "1"])
def test_child_timeout_rejects_boolean_non_integer_and_unbounded_job_counts(
    jobs: object,
) -> None:
    with pytest.raises(ValueError, match="integer between 1 and 1000"):
        _timeout_seconds(jobs)  # type: ignore[arg-type]


@pytest.mark.parametrize("jobs", [True, False, 0, 1_001, 1.0, "1"])
def test_campaign_rejects_invalid_job_counts_before_creating_a_workspace(
    tmp_path: Path,
    jobs: object,
) -> None:
    workspace = tmp_path / "must-not-create"

    with pytest.raises(ValueError, match="jobs must be between 1 and 1000"):
        run_process_campaign(jobs=jobs, workspace=workspace)  # type: ignore[arg-type]

    assert not workspace.exists()


def _test_receipt_path(label: str) -> Path:
    evidence = _REPO_ROOT / "release-evidence"
    evidence.mkdir(exist_ok=True)
    return evidence / f"pytest-{label}-{uuid.uuid4().hex}.json"


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


def _source_checkout(tmp_path: Path) -> Path:
    """Make a clean minimal Git root for stable provenance-binding tests."""

    root = tmp_path / "source-checkout"
    (root / "release-evidence").mkdir(parents=True)
    (root / ".gitignore").write_text("release-evidence/\n", encoding="utf-8")
    (root / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    for command in (
        ("git", "init"),
        ("git", "config", "user.email", "test@example.invalid"),
        ("git", "config", "user.name", "AutoLean test"),
        ("git", "add", "."),
        ("git", "commit", "-m", "provenance fixture"),
    ):
        subprocess.run(command, cwd=root, check=True, capture_output=True, text=True)
    return root


@contextmanager
def _run_small_provenance_campaign(
    tmp_path: Path,
    *,
    jobs: int = 2,
) -> Iterator[tuple[Path, Path, dict[str, object], Path]]:
    root = _REPO_ROOT
    (root / "release-evidence").mkdir(exist_ok=True)
    workspace = tmp_path / "retained-process-chaos"
    receipt_path = root / "release-evidence" / f"pytest-process-chaos-{uuid.uuid4().hex}.v2.json"
    try:
        _summary, receipt = run_process_campaign_with_provenance(
            jobs=jobs,
            workspace=workspace,
            provenance_output=receipt_path,
            root=root,
        )
        yield root, workspace, receipt, receipt_path
    finally:
        receipt_path.unlink(missing_ok=True)


def _rewrite_receipt(
    path: Path,
    mutate: Callable[[dict[str, object]], None],
) -> None:
    receipt = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(receipt, dict):
        raise AssertionError("test receipt must be an object")
    mutate(receipt)
    receipt["receipt_sha256"] = _provenance_receipt_hash(_provenance_payload(receipt))
    path.write_text(
        json.dumps(receipt, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n",
        encoding="ascii",
    )


def _rehash_manifest(receipt: dict[str, object]) -> None:
    manifest = receipt["workspace_manifest"]
    assert isinstance(manifest, dict)
    manifest["manifest_sha256"] = _manifest_hash(
        {
            "schema_version": manifest["schema_version"],
            "state_files": manifest["state_files"],
            "sqlite_files": manifest["sqlite_files"],
            "artifact_files": manifest["artifact_files"],
        }
    )


def _refresh_receipt_manifest(path: Path, workspace: Path) -> None:
    def refresh(receipt: dict[str, object]) -> None:
        receipt["workspace_manifest"] = workspace_manifest(workspace)

    _rewrite_receipt(path, refresh)


@pytest.mark.integration
def test_v2_provenance_receipt_replays_a_small_retained_campaign(tmp_path: Path) -> None:
    with _run_small_provenance_campaign(tmp_path) as (
        root,
        workspace,
        receipt,
        receipt_path,
    ):
        verified = verify_provenance_receipt(receipt_path, workspace=workspace, root=root)

        assert verified == receipt
        assert receipt["schema_version"] == "autolean.control-plane-process-chaos-provenance.v2"
        assert isinstance(receipt["run_id"], str)
        assert len(receipt["run_id"]) == 32
        assert receipt["argv"] == [
            "scripts/control_plane_process_chaos.py",
            "--jobs",
            "2",
            "--workspace",
            workspace.resolve().as_posix(),
            "--provenance-output",
            receipt_path.resolve().as_posix(),
        ]
        manifest = receipt["workspace_manifest"]
        assert isinstance(manifest, dict)
        assert [entry["path"] for entry in manifest["state_files"]] == [
            "scenario.json",
            "crash-ready.json",
            "recovery.json",
            "replay.json",
        ]
        assert len(manifest["artifact_files"]) == 8


def test_v2_verifier_rejects_a_handcrafted_v1_summary_substitution(tmp_path: Path) -> None:
    fake_v1 = _test_receipt_path("handcrafted-v1")
    workspace = tmp_path / "empty-workspace"
    workspace.mkdir()
    try:
        fake_v1.write_text(
            json.dumps(report_envelope(_valid_summary(2)), sort_keys=True) + "\n",
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="unexpected or missing fields"):
            verify_provenance_receipt(fake_v1, workspace=workspace, root=_REPO_ROOT)
    finally:
        fake_v1.unlink(missing_ok=True)


def test_v2_verifier_refuses_traversal_and_linked_receipt_paths(tmp_path: Path) -> None:
    outside = tmp_path / "outside.json"
    outside.write_text("{}\n", encoding="utf-8")
    linked = _test_receipt_path("linked")
    try:
        os.symlink(outside, linked)
    except OSError:
        pytest.skip("file symlinks are unavailable")
    try:
        with pytest.raises(ValueError, match="may not traverse a link or junction"):
            verify_provenance_receipt(
                linked,
                workspace=tmp_path / "absent-workspace",
                root=_REPO_ROOT,
            )
        with pytest.raises(ValueError, match="canonical relative path"):
            verify_provenance_receipt(
                _REPO_ROOT / "release-evidence" / ".." / "not-evidence.json",
                workspace=tmp_path / "absent-workspace",
                root=_REPO_ROOT,
            )
    finally:
        linked.unlink(missing_ok=True)


def test_v2_campaign_refuses_a_linked_workspace_root(tmp_path: Path) -> None:
    target = tmp_path / "workspace-target"
    target.mkdir()
    linked = tmp_path / "linked-workspace"
    try:
        os.symlink(target, linked, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable")

    with pytest.raises(ValueError, match="without links or junctions"):
        run_process_campaign_with_provenance(
            jobs=1,
            workspace=linked,
            provenance_output=_test_receipt_path("linked-workspace"),
            root=_REPO_ROOT,
        )


def test_v2_campaign_rejects_a_source_root_that_does_not_supply_the_worker(
    tmp_path: Path,
) -> None:
    alternate_root = _source_checkout(tmp_path)
    workspace = tmp_path / "must-not-start"
    output = alternate_root / "release-evidence" / "mismatched-root.v2.json"

    with pytest.raises(ValueError, match="must match the repository worker source root"):
        run_process_campaign_with_provenance(
            jobs=1,
            workspace=workspace,
            provenance_output=output,
            root=alternate_root,
        )

    assert not workspace.exists()
    assert not output.exists()


@pytest.mark.integration
def test_v2_verifier_rejects_receipt_binding_tampering(tmp_path: Path) -> None:
    with _run_small_provenance_campaign(tmp_path) as (
        root,
        workspace,
        _receipt,
        receipt_path,
    ):
        original = receipt_path.read_bytes()

        def wrong_commit(receipt: dict[str, object]) -> None:
            candidate = receipt["source_candidate"]
            assert isinstance(candidate, dict)
            candidate["git_commit"] = "0" * 40

        def wrong_lock(receipt: dict[str, object]) -> None:
            lock = receipt["uv_lock"]
            assert isinstance(lock, dict)
            lock["sha256"] = "0" * 64

        def wrong_argv(receipt: dict[str, object]) -> None:
            argv = receipt["argv"]
            assert isinstance(argv, list)
            argv[2] = "3"

        for mutate, message in (
            (wrong_commit, "source, lock, or runtime facts have drifted"),
            (wrong_lock, "source, lock, or runtime facts have drifted"),
            (wrong_argv, "argv job count differs from its summary"),
        ):
            receipt_path.write_bytes(original)
            _rewrite_receipt(receipt_path, mutate)
            with pytest.raises(ValueError, match=message):
                verify_provenance_receipt(receipt_path, workspace=workspace, root=root)


@pytest.mark.integration
def test_v2_verifier_rejects_missing_or_extra_manifest_entries_and_workspace_files(
    tmp_path: Path,
) -> None:
    with _run_small_provenance_campaign(tmp_path) as (
        root,
        workspace,
        _receipt,
        receipt_path,
    ):
        _assert_manifest_mutations_are_rejected(root, workspace, receipt_path)


def _assert_manifest_mutations_are_rejected(
    root: Path,
    workspace: Path,
    receipt_path: Path,
) -> None:
    original = receipt_path.read_bytes()

    def missing_manifest_file(receipt: dict[str, object]) -> None:
        manifest = receipt["workspace_manifest"]
        assert isinstance(manifest, dict)
        artifacts = manifest["artifact_files"]
        assert isinstance(artifacts, list)
        artifacts.pop()
        _rehash_manifest(receipt)

    def extra_manifest_file(receipt: dict[str, object]) -> None:
        manifest = receipt["workspace_manifest"]
        assert isinstance(manifest, dict)
        artifacts = manifest["artifact_files"]
        assert isinstance(artifacts, list)
        artifacts.append(
            {
                "path": "artifacts/zzzz-not-present",
                "sha256": "0" * 64,
                "size_bytes": 0,
            }
        )
        _rehash_manifest(receipt)

    def traversal_manifest_file(receipt: dict[str, object]) -> None:
        manifest = receipt["workspace_manifest"]
        assert isinstance(manifest, dict)
        artifacts = manifest["artifact_files"]
        assert isinstance(artifacts, list)
        entry = artifacts[0]
        assert isinstance(entry, dict)
        entry["path"] = "../not-an-artifact"
        _rehash_manifest(receipt)

    for mutate in (missing_manifest_file, extra_manifest_file):
        receipt_path.write_bytes(original)
        _rewrite_receipt(receipt_path, mutate)
        with pytest.raises(ValueError, match="workspace manifest differs from retained evidence"):
            verify_provenance_receipt(receipt_path, workspace=workspace, root=root)

    receipt_path.write_bytes(original)
    _rewrite_receipt(receipt_path, traversal_manifest_file)
    with pytest.raises(ValueError, match="canonical relative path"):
        verify_provenance_receipt(receipt_path, workspace=workspace, root=root)

    receipt_path.write_bytes(original)
    unexpected = workspace / "unexpected.txt"
    unexpected.write_text("not part of the retained run", encoding="utf-8")
    with pytest.raises(ValueError, match="unexpected root entries"):
        verify_provenance_receipt(receipt_path, workspace=workspace, root=root)
    unexpected.unlink()

    artifact = next(path for path in (workspace / "artifacts").rglob("*") if path.is_file())
    linked_artifact = workspace / "artifacts" / "linked-artifact"
    try:
        os.symlink(artifact, linked_artifact)
    except OSError:
        pytest.skip("file symlinks are unavailable")
    with pytest.raises(ValueError, match="artifact tree contains a link or junction"):
        verify_provenance_receipt(receipt_path, workspace=workspace, root=root)


@pytest.mark.integration
def test_v2_verifier_rejects_non_sqlite_bytes_with_arbitrary_cas_payload(
    tmp_path: Path,
) -> None:
    with _run_small_provenance_campaign(tmp_path, jobs=1) as (
        root,
        workspace,
        _receipt,
        receipt_path,
    ):
        (workspace / "control-plane-process-chaos.sqlite3").write_bytes(
            b"not a SQLite control-plane database"
        )
        arbitrary = b"arbitrary shape-compatible artifact bytes"
        digest = hashlib.sha256(arbitrary).hexdigest()
        target = workspace / "artifacts" / "sha256" / digest[:2] / digest[2:4] / digest
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(arbitrary)
        _refresh_receipt_manifest(receipt_path, workspace)

        with pytest.raises(ValueError, match="SQLite"):
            verify_provenance_receipt(receipt_path, workspace=workspace, root=root)


@pytest.mark.integration
def test_v2_verifier_rejects_semantically_tampered_lease_state(tmp_path: Path) -> None:
    with _run_small_provenance_campaign(tmp_path, jobs=1) as (
        root,
        workspace,
        _receipt,
        receipt_path,
    ):
        database = workspace / "control-plane-process-chaos.sqlite3"
        with closing(sqlite3.connect(database)) as connection, connection:
            connection.execute("UPDATE worker_leases SET fencing_token = 7")
        _refresh_receipt_manifest(receipt_path, workspace)

        with pytest.raises(ValueError, match="lease/fencing state is inconsistent"):
            verify_provenance_receipt(receipt_path, workspace=workspace, root=root)


@pytest.mark.integration
def test_v2_verifier_rejects_an_unreferenced_cas_artifact(tmp_path: Path) -> None:
    with _run_small_provenance_campaign(tmp_path, jobs=1) as (
        root,
        workspace,
        _receipt,
        receipt_path,
    ):
        orphan = b"canonical bytes but no event or verifier-evidence reference"
        digest = hashlib.sha256(orphan).hexdigest()
        target = workspace / "artifacts" / "sha256" / digest[:2] / digest[2:4] / digest
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(orphan)
        _refresh_receipt_manifest(receipt_path, workspace)

        with pytest.raises(ValueError, match="unreferenced"):
            verify_provenance_receipt(receipt_path, workspace=workspace, root=root)


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
