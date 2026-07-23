from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from scripts import oci_worker, oci_worker_canary


def test_worker_build_inputs_and_digests_are_frozen() -> None:
    assert oci_worker.WORKER_FILES == (
        "Dockerfile",
        "AutoleanLeanQuery.lean",
        "autolean-lean-wrapper",
    )
    assert (
        oci_worker.BASE_IMAGE_DIGEST
        == "sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90"
    )
    assert (
        oci_worker.LEAN_ARCHIVE_SHA256
        == "ceb3a3f844f7aebf63245e2b51c28d5b0ed38942c19f93cf3febd520302160bd"
    )


def test_wrong_cached_archive_is_preserved_and_rejected(tmp_path: Path) -> None:
    archive = tmp_path / oci_worker.LEAN_ARCHIVE
    archive.write_bytes(b"not the pinned Lean archive")

    with pytest.raises(RuntimeError, match="cached Lean archive digest mismatch"):
        oci_worker._archive(tmp_path)

    assert archive.read_bytes() == b"not the pinned Lean archive"


def test_archive_staging_copies_bytes_and_rechecks_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = tmp_path / "archive"
    staged = tmp_path / "different-filesystem-contract" / "archive"
    staged.parent.mkdir()
    archive.write_bytes(b"pinned archive fixture")
    monkeypatch.setattr(
        oci_worker,
        "LEAN_ARCHIVE_SHA256",
        hashlib.sha256(archive.read_bytes()).hexdigest(),
    )

    oci_worker._stage_archive(archive, staged)

    assert staged.read_bytes() == archive.read_bytes()


def test_direct_canary_command_freezes_the_oci_isolation_profile(tmp_path: Path) -> None:
    candidate = tmp_path / "Candidate.lean"
    candidate.write_text("theorem fixture : True := by trivial\n", encoding="utf-8")
    image = "autolean/lean-worker@sha256:" + "a" * 64

    command = oci_worker_canary._wrapper_command(image, candidate)

    assert command[:3] == ["docker", "run", "--rm"]
    assert command[3:5] == ["--network", "none"]
    assert "--read-only" in command
    assert command[command.index("--cap-drop") :][:2] == ["--cap-drop", "ALL"]
    assert command[command.index("--security-opt") :][:2] == [
        "--security-opt",
        "no-new-privileges",
    ]
    assert "/tmp:rw,noexec,nosuid,size=256m" in command
    assert image in command
    assert "/bin/sh" not in command
    assert "True" not in command


def test_real_canary_bundle_binds_image_type_and_pure_lean_boundary() -> None:
    digest = "sha256:" + "b" * 64
    bundle = oci_worker_canary._bundle(digest)
    replay = oci_worker_canary._bundle(digest)

    assert bundle.proof_boundary.expected_declaration == oci_worker_canary.DECLARATION
    assert bundle.contract.formal.elaborated_type == "\u2200 (n : Nat), @Eq.{1} Nat n n"
    assert bundle.contract.formal.imports_allowlist == ()
    assert bundle.contract.formal.environment.mathlib_revision == "none-pure-lean-v4.28.0"
    assert (
        bundle.contract.formal.environment.verifier_execution_policy.worker_image_digest == digest
    )
    assert replay.proof_boundary.solver_manifest_hash == bundle.proof_boundary.solver_manifest_hash
    assert replay.handoff_hash() == bundle.handoff_hash()


def test_worker_assets_enforce_archive_query_and_non_root_runtime() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    worker = repo_root / "Prover" / "worker"
    dockerfile = (worker / "Dockerfile").read_text(encoding="utf-8")
    helper = (worker / "AutoleanLeanQuery.lean").read_text(encoding="utf-8")
    wrapper = (worker / "autolean-lean-wrapper").read_text(encoding="utf-8")

    assert "sha256sum --check --strict" in dockerfile
    assert "USER 65532:65532" in dockerfile
    assert "apt-get" not in dockerfile
    assert "collectAxioms declaration" in helper
    assert "`pp.all true" in helper
    assert "`pp.notation false" in helper
    assert '>"$scratch/compiler.stdout"' in wrapper
    assert 'result_lines=$(wc -l <"$scratch/query.stdout")' in wrapper
