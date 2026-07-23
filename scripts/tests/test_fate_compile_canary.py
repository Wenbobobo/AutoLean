from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from pathlib import Path

import pytest

from benchmarks.fate import CANARY, Tier
from scripts.fate_compile_canary import (
    COMMAND_POLICY_ID,
    REPORT_ENVELOPE_SCHEMA,
    CanaryCase,
    CanaryRunError,
    CommandObservation,
    FixtureEvidence,
    LockedDependency,
    RuntimeEvidence,
    WslRuntime,
    execute_canaries,
    report_envelope,
    write_report_exclusive,
)

_TIERS: tuple[Tier, ...] = ("M", "H", "X")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class FakeRuntime:
    def __init__(self, *, failure: str | None = None) -> None:
        self.failure = failure
        self.calls: list[tuple[Tier, str, int]] = []

    def preflight(self, fixture: FixtureEvidence, checkout: Path) -> RuntimeEvidence:
        del fixture, checkout
        return RuntimeEvidence(
            execution_platform="WSL",
            distribution="Ubuntu-24.04",
            distribution_id="ubuntu",
            distribution_version="24.04",
            kernel_release="6.6.87.2-microsoft-standard-WSL2",
            lean_version="Lean (version 4.28.0, fake)",
            lake_version="Lake version 5.0.0-fake",
            dependency_graph_sha256={tier: "a" * 64 for tier in _TIERS},
            dependency_counts={tier: 1 for tier in _TIERS},
        )

    def compile(
        self,
        *,
        split: Tier,
        relative_source: str,
        timeout_seconds: int,
    ) -> CommandObservation:
        self.calls.append((split, relative_source, timeout_seconds))
        if self.failure == f"{split}/{relative_source}":
            return CommandObservation(
                returncode=1,
                stdout=b"diagnostic contains theorem source",
                stderr=b"secret-looking diagnostics",
                elapsed_seconds=0.25,
            )
        return CommandObservation(
            returncode=0,
            stdout=b"",
            stderr=b"warning: declaration uses sorry",
            elapsed_seconds=0.125,
        )


def _fixture(tmp_path: Path) -> tuple[FixtureEvidence, Path]:
    checkout = tmp_path / "FATE"
    cases: list[CanaryCase] = []
    for tier in _TIERS:
        for number in sorted(CANARY[tier]):
            payload = f"synthetic-{tier}-{number}-source".encode()
            source_path = f"FATE-{tier}/FATE{tier}/{number}.lean"
            destination = checkout.joinpath(*source_path.split("/"))
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(payload)
            cases.append(
                CanaryCase(
                    task_id=f"FATE-{tier}-{number}",
                    split=tier,
                    source_path=source_path,
                    source_sha256=_sha256(payload),
                    signature_sha256=_sha256(f"signature-{tier}-{number}".encode()),
                )
            )
    fixture = FixtureEvidence(
        manifest_sha256="1" * 64,
        root_commit="2" * 40,
        submodules={tier: str(index) * 40 for index, tier in enumerate(_TIERS, start=3)},
        toolchain="leanprover/lean4:v4.28.0",
        mathlib_commit="6" * 40,
        lake_manifest_sha256={tier: "7" * 64 for tier in _TIERS},
        dependencies={
            tier: (LockedDependency(name="mathlib", revision="6" * 40),) for tier in _TIERS
        },
        cases=tuple(cases),
    )
    return fixture, checkout


def test_fake_compile_report_is_separate_answer_free_and_hash_bound(tmp_path: Path) -> None:
    fixture, checkout = _fixture(tmp_path)
    runtime = FakeRuntime(failure="X/FATEX/72.lean")

    report = execute_canaries(
        fixture=fixture,
        checkout=checkout,
        runtime=runtime,
        timeout_seconds=20,
    )
    envelope = report_envelope(report)
    rendered = json.dumps(envelope, ensure_ascii=True, sort_keys=True)

    assert report["proof_search_executed"] is False
    assert report["original_sources_contain_sorry"] is True
    assert report["tiers_reported_separately"] is True
    tiers = report["tiers"]
    assert isinstance(tiers, dict)
    assert tiers["M"]["summary"] == {"compiled": 3, "failed": 0, "total": 3}
    assert tiers["H"]["summary"] == {"compiled": 3, "failed": 0, "total": 3}
    assert tiers["X"]["summary"] == {"compiled": 5, "failed": 1, "total": 6}
    assert len(runtime.calls) == 12
    command_policy = report["command_policy"]
    assert isinstance(command_policy, dict)
    assert command_policy["policy_id"] == COMMAND_POLICY_ID
    assert envelope["schema_version"] == REPORT_ENVELOPE_SCHEMA
    assert "diagnostic contains theorem source" not in rendered
    assert "secret-looking diagnostics" not in rendered
    assert "synthetic-M-3-source" not in rendered
    assert "warning: declaration uses sorry" not in rendered
    assert "HOME=" not in rendered


def test_source_drift_is_rejected_before_runtime_preflight(tmp_path: Path) -> None:
    fixture, checkout = _fixture(tmp_path)
    source = checkout / "FATE-M" / "FATEM" / "3.lean"
    source.write_bytes(b"changed")
    runtime = FakeRuntime()

    with pytest.raises(CanaryRunError, match="canary_worktree_source_drift"):
        execute_canaries(
            fixture=fixture,
            checkout=checkout,
            runtime=runtime,
            timeout_seconds=20,
        )

    assert runtime.calls == []


class FakeCommandRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[tuple[str, ...], str | None, int]] = []

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: str | None,
        timeout_seconds: int,
    ) -> CommandObservation:
        command = tuple(argv)
        self.calls.append((command, cwd, timeout_seconds))
        if command[-2:] == ("/bin/cat", "/proc/sys/kernel/osrelease"):
            output = b"6.6.87.2-microsoft-standard-WSL2\n"
        elif command[-2:] == ("/bin/cat", "/etc/os-release"):
            output = b'ID=ubuntu\nVERSION_ID="24.04"\n'
        elif "/usr/bin/wslpath" in command:
            output = b"/mnt/c/Projects/AutoLean/benchmarks/vendor/FATE\n"
        elif command[-2:] == ("/usr/bin/id", "-u"):
            output = b"1000\n"
        elif "/usr/bin/getent" in command:
            output = b"tester:x:1000:1000::/home/tester:/bin/bash\n"
        elif command[-4:] == ("lake", "env", "lean", "--version"):
            output = b"Lean (version 4.28.0, fake)\n"
        elif command[-2:] == ("lake", "--version"):
            output = b"Lake version 5.0.0-fake\n"
        elif "rev-parse" in command:
            output = b"6666666666666666666666666666666666666666\n"
        else:
            output = b""
        return CommandObservation(
            returncode=0,
            stdout=output,
            stderr=b"",
            elapsed_seconds=0.01,
        )


class MissingDependencyRunner(FakeCommandRunner):
    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: str | None,
        timeout_seconds: int,
    ) -> CommandObservation:
        command = tuple(argv)
        if "rev-parse" in command:
            self.calls.append((command, cwd, timeout_seconds))
            return CommandObservation(
                returncode=128,
                stdout=b"",
                stderr=b"untrusted dependency diagnostic",
                elapsed_seconds=0.01,
            )
        return super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)


def test_windows_orchestrator_uses_verified_wsl_and_empty_environment(tmp_path: Path) -> None:
    fixture, checkout = _fixture(tmp_path)
    runner = FakeCommandRunner()
    runtime = WslRuntime(
        distribution="Ubuntu-24.04",
        runner=runner,
        host_system="Windows",
    )

    evidence = runtime.preflight(fixture, checkout)
    observation = runtime.compile(
        split="M",
        relative_source="FATEM/3.lean",
        timeout_seconds=15,
    )

    assert evidence.execution_platform == "WSL"
    assert evidence.dependency_counts == {"M": 1, "H": 1, "X": 1}
    assert observation.returncode == 0
    compile_command = runner.calls[-1][0]
    assert compile_command[:4] == (
        "wsl.exe",
        "--distribution",
        "Ubuntu-24.04",
        "--cd",
    )
    assert "/usr/bin/env" in compile_command
    empty_index = compile_command.index("-i")
    assert compile_command[empty_index + 1].startswith("HOME=")
    assert compile_command[-4:] == ("lake", "env", "lean", "FATEM/3.lean")
    assert all("API_KEY" not in value for value in compile_command)


def test_missing_runtime_dependency_blocks_before_any_lean_source_compile(
    tmp_path: Path,
) -> None:
    fixture, checkout = _fixture(tmp_path)
    runner = MissingDependencyRunner()
    runtime = WslRuntime(
        distribution="Ubuntu-24.04",
        runner=runner,
        host_system="Windows",
    )

    with pytest.raises(CanaryRunError, match="runtime_dependency_missing_or_unreadable"):
        runtime.preflight(fixture, checkout)

    source_compile_calls = [
        command
        for command, _, _ in runner.calls
        if command[-4:-1] == ("lake", "env", "lean") and command[-1].endswith(".lean")
    ]
    assert source_compile_calls == []


def test_non_wsl_linux_and_report_overwrite_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(CanaryRunError, match="non_wsl_linux_refused"):
        WslRuntime(
            distribution="Ubuntu-24.04",
            runner=FakeCommandRunner(),
            host_system="Linux",
            native_wsl=False,
        )

    fixture, checkout = _fixture(tmp_path)
    report = execute_canaries(
        fixture=fixture,
        checkout=checkout,
        runtime=FakeRuntime(),
        timeout_seconds=20,
    )
    envelope = report_envelope(report)
    output = tmp_path / "report.json"
    write_report_exclusive(output, envelope, checkout)
    original = output.read_bytes()
    with pytest.raises(CanaryRunError, match="report_already_exists"):
        write_report_exclusive(output, envelope, checkout)
    assert output.read_bytes() == original
