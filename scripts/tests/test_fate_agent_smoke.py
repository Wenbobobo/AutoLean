from __future__ import annotations

import hashlib
import os
import stat
import subprocess
from pathlib import Path
from typing import cast

import pytest

from benchmarks.fate import FateProblemId
from benchmarks.fate_adapter import FateFixtureTaskV1, FatePatchedSourceV1
from benchmarks.fate_smoke import FateSmokeError
from scripts import fate_agent_smoke


def _candidate() -> FatePatchedSourceV1:
    source = b"import Mathlib\n\ntheorem target : True := by\n  sorry\n"
    task = FateFixtureTaskV1.from_source(
        FateProblemId("M", 1),
        "FATE-M/FATEM/1.lean",
        source,
    )
    slot = task.proof_slot
    proof = b"aesop"
    candidate = source[: slot.byte_start] + proof + source[slot.byte_end :]
    return FatePatchedSourceV1(
        task=task,
        proof_body_sha256=hashlib.sha256(proof).hexdigest(),
        candidate_sha256=hashlib.sha256(candidate).hexdigest(),
        source=candidate,
    )


def _compiler(tmp_path: Path) -> fate_agent_smoke.OciMountedMathlibCompiler:
    packages = tmp_path / "packages"
    verifier = tmp_path / "verifier"
    packages.mkdir()
    verifier.mkdir()
    return fate_agent_smoke.OciMountedMathlibCompiler(
        cache_root=tmp_path / "cache",
        packages_root=packages,
        verifier_root=verifier,
        command_policy_sha256="a" * 64,
    )


def test_build_tree_commitment_is_deterministic_and_content_bound(tmp_path: Path) -> None:
    packages = tmp_path / "packages"
    for name in fate_agent_smoke.EXPECTED_DEPENDENCIES:
        if name in fate_agent_smoke.EXPECTED_ABSENT_BUILD_ROOTS:
            (packages / name).mkdir(parents=True)
            continue
        build = packages / name / ".lake" / "build" / "lib" / "lean"
        build.mkdir(parents=True)
        (build / f"{name}.olean").write_bytes(name.encode())

    first, count = fate_agent_smoke._build_tree_commitment(packages)
    second, second_count = fate_agent_smoke._build_tree_commitment(packages)
    target = packages / "mathlib" / ".lake" / "build" / "lib" / "lean" / "mathlib.olean"
    target.write_bytes(b"changed")
    changed, changed_count = fate_agent_smoke._build_tree_commitment(packages)

    assert first == second
    assert count == second_count == changed_count == 8
    assert changed != first


def test_runtime_state_accepts_only_canonical_bytes_or_one_lf() -> None:
    expected = b'{"state":"pinned"}'

    assert fate_agent_smoke._runtime_state_matches(expected, expected)
    assert fate_agent_smoke._runtime_state_matches(expected + b"\n", expected)
    assert not fate_agent_smoke._runtime_state_matches(expected + b"\r\n", expected)
    assert not fate_agent_smoke._runtime_state_matches(expected + b"\n\n", expected)


def test_build_tree_rejects_unexpected_dependency(tmp_path: Path) -> None:
    packages = tmp_path / "packages"
    packages.mkdir()
    (packages / "unexpected").mkdir()

    with pytest.raises(FateSmokeError, match="smoke_dependency_build_inventory_drift"):
        fate_agent_smoke._build_tree_commitment(packages)


def test_build_tree_rejects_missing_nonempty_dependency(tmp_path: Path) -> None:
    packages = tmp_path / "packages"
    for name in fate_agent_smoke.EXPECTED_DEPENDENCIES:
        (packages / name).mkdir(parents=True)

    with pytest.raises(FateSmokeError, match="smoke_dependency_build_tree_missing"):
        fate_agent_smoke._build_tree_commitment(packages)


def test_timeout_removes_only_the_unique_attempt_container(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_run(argv: tuple[str, ...], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        del kwargs
        calls.append(tuple(argv))
        if argv[1] == "run":
            raise subprocess.TimeoutExpired(argv, 20, output=b"partial", stderr=b"timed")
        assert argv[1:3] == ("rm", "--force")
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(
        "scripts.fate_agent_smoke.secrets.token_hex",
        lambda size: "1" * (size * 2),
    )
    monkeypatch.setattr("scripts.fate_agent_smoke.subprocess.run", fake_run)
    observation = _compiler(tmp_path).compile(_candidate(), timeout_seconds=20)

    assert observation.timed_out is True
    assert observation.returncode is None
    run = calls[0]
    assert (run[run.index("--network")], run[run.index("--network") + 1]) == ("--network", "none")
    assert "--read-only" in run
    assert (
        run[run.index("--cap-drop")],
        run[run.index("--cap-drop") + 1],
    ) == ("--cap-drop", "ALL")
    container_name = run[run.index("--name") + 1]
    assert calls[1] == ("/usr/bin/docker", "rm", "--force", container_name)


def test_timeout_cleanup_failure_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def fake_run(argv: tuple[str, ...], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        nonlocal calls
        del kwargs
        calls += 1
        if calls == 1:
            raise subprocess.TimeoutExpired(argv, 20)
        return subprocess.CompletedProcess(argv, 1, b"", b"cleanup failed")

    monkeypatch.setattr("scripts.fate_agent_smoke.subprocess.run", fake_run)

    with pytest.raises(FateSmokeError, match="smoke_timed_out_container_cleanup_failed"):
        _compiler(tmp_path).compile(_candidate(), timeout_seconds=20)


def test_image_inspection_requires_exact_repo_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wrong = (
        '[{"Id":"sha256:'
        + "0" * 64
        + '","RepoDigests":["autolean/lean-worker@sha256:'
        + "0" * 64
        + '"]}]'
    ).encode()

    monkeypatch.setattr(
        fate_agent_smoke,
        "_run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            cast(tuple[str, ...], args[0]),
            0,
            wrong,
            b"",
        ),
    )

    with pytest.raises(FateSmokeError, match="smoke_pinned_image_identity_mismatch"):
        fate_agent_smoke._inspect_image()


def test_command_policy_exposes_non_promotable_mount_boundary() -> None:
    policy = fate_agent_smoke._command_policy("a" * 64, "b" * 64)

    assert policy["network"] == "none"
    assert policy["root_filesystem"] == "read_only"
    assert policy["image"] == fate_agent_smoke.IMAGE_REPOSITORY_DIGEST
    assert cast(dict[str, str], policy["mounts"])["dependencies"] == "read_only"


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits are authoritative on Linux")
def test_fate_limits_cross_uid_output_access_to_compile_phase(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, int] = {}
    output_root: Path | None = None

    def fake_run_phase(
        _cls: type[fate_agent_smoke.OciMountedMathlibCompiler],
        argv: tuple[str, ...],
        *,
        container_name: str,
        timeout_seconds: int,
    ) -> tuple[subprocess.CompletedProcess[bytes], None]:
        del container_name, timeout_seconds
        nonlocal output_root
        phase = argv[argv.index("--phase") + 1]
        if phase == "compile":
            mount = next(value for value in argv if "dst=/output" in value)
            source = next(
                field.removeprefix("src=") for field in mount.split(",") if field.startswith("src=")
            )
            output_root = Path(source)
            observed["parent"] = stat.S_IMODE(output_root.parent.stat().st_mode)
            observed["compile"] = stat.S_IMODE(output_root.stat().st_mode)
            (output_root / "Candidate.olean").write_bytes(b"fate-olean")
        else:
            assert output_root is not None
            observed["query"] = stat.S_IMODE(output_root.stat().st_mode)
        return subprocess.CompletedProcess(argv, 0, b"{}", b""), None

    monkeypatch.setattr(
        fate_agent_smoke.OciMountedMathlibCompiler,
        "_run_container_phase",
        classmethod(fake_run_phase),
    )

    observation = _compiler(tmp_path).compile(_candidate(), timeout_seconds=20)

    assert observation.returncode == 0
    assert observed == {"parent": 0o700, "compile": 0o733, "query": 0o700}


def test_fate_handoff_rejects_non_regular_or_symlinked_olean(tmp_path: Path) -> None:
    compiler_output = tmp_path / "compiler-output"
    sealed = tmp_path / "sealed"
    compiler_output.mkdir()
    sealed.mkdir()
    compiled = compiler_output / "Candidate.olean"
    compiled.mkdir()

    with pytest.raises(
        FateSmokeError,
        match=r"smoke_compiled_candidate_(unavailable|not_regular)",
    ):
        fate_agent_smoke._seal_candidate_olean(compiler_output, sealed)

    compiled.rmdir()
    outside = tmp_path / "outside.olean"
    outside.write_bytes(b"outside")
    try:
        compiled.symlink_to(outside)
    except OSError:
        pytest.skip("symbolic links are unavailable on this Windows configuration")

    with pytest.raises(FateSmokeError, match="smoke_compiled_candidate_unavailable"):
        fate_agent_smoke._seal_candidate_olean(compiler_output, sealed)
