from __future__ import annotations

import hashlib
import os
import stat
import subprocess
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
    output = tmp_path / "output"
    output.mkdir()
    compiled = tmp_path / "Candidate.olean"
    compiled.write_bytes(b"compiled")
    image = "autolean/lean-worker@sha256:" + "a" * 64

    compile_command = oci_worker_canary._compile_command(
        image,
        candidate,
        output,
        "autolean-test-compile",
    )
    query_command = oci_worker_canary._query_command(
        image,
        compiled,
        "autolean-test-query",
    )

    for command in (compile_command, query_command):
        assert command[:3] == ["docker", "run", "--name"]
        assert command[command.index("--network") :][:2] == ["--network", "none"]
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
        assert not any("dst=/work" in argument for argument in command)
    assert any(
        "dst=/output" in argument and "readonly" not in argument for argument in compile_command
    )
    assert any(
        "dst=/compiled/Candidate.olean" in argument and "readonly" in argument
        for argument in query_command
    )


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits are authoritative on Linux")
def test_direct_canary_limits_cross_uid_output_access_to_compile_phase(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = tmp_path / "Candidate.lean"
    candidate.write_text("theorem fixture : True := by trivial\n", encoding="utf-8")
    observed: dict[str, int] = {}
    output_root: Path | None = None

    def fake_run_phase(
        command: list[str],
        container_name: str,
    ) -> subprocess.CompletedProcess[str]:
        del container_name
        nonlocal output_root
        phase = command[command.index("--phase") + 1]
        if phase == "compile":
            mount = next(value for value in command if "dst=/output" in value)
            source = next(
                field.removeprefix("src=") for field in mount.split(",") if field.startswith("src=")
            )
            output_root = Path(source)
            observed["parent"] = stat.S_IMODE(output_root.parent.stat().st_mode)
            observed["compile"] = stat.S_IMODE(output_root.stat().st_mode)
            (output_root / "Candidate.olean").write_bytes(b"canary-olean")
        else:
            assert output_root is not None
            observed["query"] = stat.S_IMODE(output_root.stat().st_mode)
        return subprocess.CompletedProcess(command, 0, "{}", "")

    monkeypatch.setattr(oci_worker_canary, "_run_phase", fake_run_phase)

    result = oci_worker_canary._direct(
        "autolean/lean-worker@sha256:" + ("a" * 64),
        candidate,
    )

    assert result.returncode == 0
    assert observed == {"parent": 0o700, "compile": 0o733, "query": 0o700}


def test_real_canary_bundle_binds_image_type_and_pure_lean_boundary() -> None:
    digest = "sha256:" + "b" * 64
    bundle = oci_worker_canary._bundle(digest)
    replay = oci_worker_canary._bundle(digest)

    assert bundle.proof_boundary.expected_declaration == oci_worker_canary.DECLARATION
    assert bundle.contract.formal.elaborated_type == "\u2200 (n : Nat), @Eq.{1} Nat n n"
    assert bundle.contract.formal.imports_allowlist == ()
    assert bundle.contract.formal.environment.mathlib_revision == "none-pure-lean-v4.28.0"
    assert bundle.contract.revision == 2
    assert bundle.graphs.mathematical.revision == 2
    assert bundle.graphs.formal.revision == 2
    assert bundle.graphs.execution.revision == 2
    assert bundle.contract.formal.environment.verifier_execution_policy.schema_version == "2.0"
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
