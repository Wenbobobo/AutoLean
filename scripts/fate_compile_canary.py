"""Compile the fixed FATE canary sources with pinned Lean inside WSL.

This is a baseline source-compatibility check.  The original FATE files contain
``sorry``, so a successful run is not proof-search evidence and must never be
reported as a solved theorem.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Final, Literal, Protocol, cast

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from benchmarks.fate import CANARY, Tier  # noqa: E402
from benchmarks.fate_adapter import (  # noqa: E402
    FateAdapter,
    FateFixtureIntegrityError,
    FateFixtureLockV1,
)

REPORT_SCHEMA: Final = "autolean.fate-compile-canary-report.v1"
REPORT_ENVELOPE_SCHEMA: Final = "autolean.fate-compile-canary-envelope.v1"
SUITE: Final = "compile-canary-12"
EXPECTED_MANIFEST_SHA256: Final = "dc52f40fdede4c4e2290580d9dfdecb9e017b8cd3ed961e2ad13e9a0accb54a2"
EXPECTED_LEAN_VERSION: Final = "4.28.0"
EXPECTED_LAKE_VERSION: Final = "5.0.0"
DEFAULT_WSL_DISTRIBUTION: Final = "Ubuntu-24.04"
DEFAULT_TIMEOUT_SECONDS: Final = 300
COMMAND_POLICY_ID: Final = "autolean.wsl-lake-env-lean-original.v1"
_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_DISTRIBUTION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SAFE_PACKAGE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SAFE_VERSION_LINE = re.compile(r"^[\x20-\x7e]{1,300}$")
_TIERS: Final[tuple[Tier, ...]] = ("M", "H", "X")


class CanaryRunError(RuntimeError):
    """A fail-closed error whose code is safe to expose without subprocess output."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class LockedDependency:
    name: str
    revision: str


@dataclass(frozen=True, slots=True)
class CanaryCase:
    task_id: str
    split: Tier
    source_path: str
    source_sha256: str
    signature_sha256: str


@dataclass(frozen=True, slots=True)
class FixtureEvidence:
    manifest_sha256: str
    root_commit: str
    submodules: Mapping[Tier, str]
    toolchain: str
    mathlib_commit: str
    lake_manifest_sha256: Mapping[Tier, str]
    dependencies: Mapping[Tier, tuple[LockedDependency, ...]]
    cases: tuple[CanaryCase, ...]


@dataclass(frozen=True, slots=True)
class CommandObservation:
    returncode: int | None
    stdout: bytes
    stderr: bytes
    elapsed_seconds: float
    timed_out: bool = False


@dataclass(frozen=True, slots=True)
class RuntimeEvidence:
    execution_platform: Literal["WSL"]
    distribution: str
    distribution_id: str
    distribution_version: str
    kernel_release: str
    lean_version: str
    lake_version: str
    dependency_graph_sha256: Mapping[Tier, str]
    dependency_counts: Mapping[Tier, int]


class CommandRunner(Protocol):
    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: str | None,
        timeout_seconds: int,
    ) -> CommandObservation: ...


class CanaryRuntime(Protocol):
    def preflight(self, fixture: FixtureEvidence, checkout: Path) -> RuntimeEvidence: ...

    def compile(
        self,
        *,
        split: Tier,
        relative_source: str,
        timeout_seconds: int,
    ) -> CommandObservation: ...


class SubprocessCommandRunner:
    """Run bounded commands while retaining output only long enough to hash it."""

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: str | None,
        timeout_seconds: int,
    ) -> CommandObservation:
        started = time.monotonic()
        try:
            completed = subprocess.run(
                tuple(argv),
                check=False,
                cwd=cwd,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as error:
            return CommandObservation(
                returncode=None,
                stdout=_timeout_bytes(error.stdout),
                stderr=_timeout_bytes(error.stderr),
                elapsed_seconds=time.monotonic() - started,
                timed_out=True,
            )
        except OSError as error:
            raise CanaryRunError("command_unavailable") from error
        return CommandObservation(
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            elapsed_seconds=time.monotonic() - started,
        )


class WslRuntime:
    """A no-shell WSL command boundary with a minimal child environment."""

    def __init__(
        self,
        *,
        distribution: str,
        runner: CommandRunner,
        host_system: str | None = None,
        native_wsl: bool | None = None,
    ) -> None:
        if _SAFE_DISTRIBUTION.fullmatch(distribution) is None:
            raise CanaryRunError("unsafe_wsl_distribution")
        self._distribution = distribution
        self._runner = runner
        self._host_system = platform.system() if host_system is None else host_system
        if native_wsl is None:
            native_wsl = _host_is_wsl() if self._host_system == "Linux" else False
        self._native_wsl = native_wsl
        if self._host_system == "Linux" and not self._native_wsl:
            raise CanaryRunError("non_wsl_linux_refused")
        if self._host_system not in {"Windows", "Linux"}:
            raise CanaryRunError("unsupported_host_platform")
        self._checkout_wsl: PurePosixPath | None = None
        self._home: PurePosixPath | None = None
        self._minimal_path: str | None = None

    def _invoke(
        self,
        argv: Sequence[str],
        *,
        cwd: PurePosixPath | None = None,
        timeout_seconds: int = 30,
    ) -> CommandObservation:
        if self._host_system == "Windows":
            command = ["wsl.exe", "--distribution", self._distribution]
            if cwd is not None:
                command.extend(("--cd", cwd.as_posix()))
            command.append("--exec")
            command.extend(argv)
            return self._runner.run(command, cwd=None, timeout_seconds=timeout_seconds)
        return self._runner.run(
            argv,
            cwd=None if cwd is None else cwd.as_posix(),
            timeout_seconds=timeout_seconds,
        )

    def _required_output(
        self,
        argv: Sequence[str],
        *,
        cwd: PurePosixPath | None = None,
        code: str,
    ) -> bytes:
        observation = self._invoke(argv, cwd=cwd)
        if observation.timed_out or observation.returncode != 0:
            raise CanaryRunError(code)
        return observation.stdout

    def _map_checkout(self, checkout: Path) -> PurePosixPath:
        if self._host_system == "Windows":
            output = self._required_output(
                ("/usr/bin/wslpath", "-a", "-u", str(checkout.resolve())),
                code="wsl_path_mapping_failed",
            )
            return _safe_absolute_posix(_decode_line(output, "wsl_path_mapping_failed"))
        return _safe_absolute_posix(checkout.resolve().as_posix())

    def _minimal_environment(self) -> tuple[str, ...]:
        if self._home is None or self._minimal_path is None:
            raise CanaryRunError("runtime_not_preflighted")
        return (
            "/usr/bin/env",
            "-i",
            f"HOME={self._home.as_posix()}",
            f"PATH={self._minimal_path}",
            "LANG=C.UTF-8",
            "LC_ALL=C.UTF-8",
        )

    def _resolve_home(self) -> PurePosixPath:
        uid = _decode_line(
            self._required_output(("/usr/bin/id", "-u"), code="wsl_identity_probe_failed"),
            "wsl_identity_probe_failed",
        )
        if not uid.isdigit():
            raise CanaryRunError("wsl_identity_probe_failed")
        passwd = _decode_line(
            self._required_output(
                ("/usr/bin/getent", "passwd", uid),
                code="wsl_identity_probe_failed",
            ),
            "wsl_identity_probe_failed",
        )
        fields = passwd.split(":")
        if len(fields) != 7:
            raise CanaryRunError("wsl_identity_probe_failed")
        return _safe_absolute_posix(fields[5])

    def _verify_dependencies(
        self,
        fixture: FixtureEvidence,
        split_roots: Mapping[Tier, PurePosixPath],
    ) -> tuple[dict[Tier, str], dict[Tier, int]]:
        graph_hashes: dict[Tier, str] = {}
        counts: dict[Tier, int] = {}
        command_prefix = self._minimal_environment()
        for tier in _TIERS:
            dependencies = fixture.dependencies[tier]
            for dependency in dependencies:
                package = f".lake/packages/{dependency.name}"
                revision = _decode_line(
                    self._required_output(
                        (
                            *command_prefix,
                            "/usr/bin/git",
                            "-c",
                            "core.fsmonitor=false",
                            "-c",
                            "core.hooksPath=",
                            "-C",
                            package,
                            "rev-parse",
                            "--verify",
                            "HEAD^{commit}",
                        ),
                        cwd=split_roots[tier],
                        code="runtime_dependency_missing_or_unreadable",
                    ),
                    "runtime_dependency_missing_or_unreadable",
                )
                if revision != dependency.revision:
                    raise CanaryRunError("runtime_dependency_revision_drift")
                status = self._required_output(
                    (
                        *command_prefix,
                        "/usr/bin/git",
                        "-c",
                        "core.fsmonitor=false",
                        "-c",
                        "core.hooksPath=",
                        "-C",
                        package,
                        "status",
                        "--porcelain=v1",
                        "--untracked-files=no",
                    ),
                    cwd=split_roots[tier],
                    code="runtime_dependency_status_failed",
                )
                if status:
                    raise CanaryRunError("runtime_dependency_worktree_drift")
            graph_hashes[tier] = _sha256(
                _canonical_json(
                    [
                        {"name": dependency.name, "revision": dependency.revision}
                        for dependency in dependencies
                    ]
                )
            )
            counts[tier] = len(dependencies)
        return graph_hashes, counts

    def preflight(self, fixture: FixtureEvidence, checkout: Path) -> RuntimeEvidence:
        kernel_release = _decode_line(
            self._required_output(
                ("/bin/cat", "/proc/sys/kernel/osrelease"),
                code="wsl_kernel_probe_failed",
            ),
            "wsl_kernel_probe_failed",
        )
        if "microsoft" not in kernel_release.casefold():
            raise CanaryRunError("non_wsl_execution_refused")
        os_release = self._required_output(
            ("/bin/cat", "/etc/os-release"),
            code="wsl_distribution_probe_failed",
        )
        distribution_id, distribution_version = _parse_os_release(os_release)
        if distribution_id != "ubuntu" or distribution_version != "24.04":
            raise CanaryRunError("wsl_distribution_drift")

        self._checkout_wsl = self._map_checkout(checkout)
        self._home = self._resolve_home()
        self._minimal_path = (
            f"{self._home.as_posix()}/.elan/bin:"
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        )
        split_roots: dict[Tier, PurePosixPath] = {
            tier: self._checkout_wsl / f"FATE-{tier}" for tier in _TIERS
        }
        version_root = split_roots["M"]
        environment = self._minimal_environment()
        lean_version = _decode_version(
            self._required_output(
                (*environment, "lake", "env", "lean", "--version"),
                cwd=version_root,
                code="lean_version_probe_failed",
            ),
            "lean_version_probe_failed",
        )
        lake_version = _decode_version(
            self._required_output(
                (*environment, "lake", "--version"),
                cwd=version_root,
                code="lake_version_probe_failed",
            ),
            "lake_version_probe_failed",
        )
        if re.search(r"\bversion 4\.28\.0\b", lean_version) is None:
            raise CanaryRunError("lean_version_drift")
        if re.search(r"\bversion 5\.0\.0\b", lake_version, flags=re.IGNORECASE) is None:
            raise CanaryRunError("lake_version_drift")
        dependency_hashes, dependency_counts = self._verify_dependencies(fixture, split_roots)
        return RuntimeEvidence(
            execution_platform="WSL",
            distribution=self._distribution,
            distribution_id=distribution_id,
            distribution_version=distribution_version,
            kernel_release=kernel_release,
            lean_version=lean_version,
            lake_version=lake_version,
            dependency_graph_sha256=dependency_hashes,
            dependency_counts=dependency_counts,
        )

    def compile(
        self,
        *,
        split: Tier,
        relative_source: str,
        timeout_seconds: int,
    ) -> CommandObservation:
        if self._checkout_wsl is None:
            raise CanaryRunError("runtime_not_preflighted")
        source = _safe_relative_source(relative_source, split)
        return self._invoke(
            (*self._minimal_environment(), "lake", "env", "lean", source.as_posix()),
            cwd=self._checkout_wsl / f"FATE-{split}",
            timeout_seconds=timeout_seconds,
        )


def _timeout_bytes(value: bytes | str | None) -> bytes:
    if value is None:
        return b""
    return value if isinstance(value, bytes) else value.encode("utf-8", errors="replace")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _decode_line(value: bytes, code: str) -> str:
    try:
        decoded = value.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise CanaryRunError(code) from error
    if not decoded or "\n" in decoded or "\r" in decoded or "\x00" in decoded:
        raise CanaryRunError(code)
    return decoded


def _decode_version(value: bytes, code: str) -> str:
    decoded = _decode_line(value, code)
    if _SAFE_VERSION_LINE.fullmatch(decoded) is None:
        raise CanaryRunError(code)
    return decoded


def _safe_absolute_posix(value: str) -> PurePosixPath:
    candidate = PurePosixPath(value)
    if not candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        raise CanaryRunError("unsafe_wsl_path")
    return candidate


def _safe_relative_source(value: str, split: Tier) -> PurePosixPath:
    candidate = PurePosixPath(value)
    expected_prefix = f"FATE{split}"
    if (
        candidate.is_absolute()
        or len(candidate.parts) != 2
        or candidate.parts[0] != expected_prefix
        or candidate.suffix != ".lean"
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        raise CanaryRunError("unsafe_canary_source_path")
    return candidate


def _parse_os_release(payload: bytes) -> tuple[str, str]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CanaryRunError("wsl_distribution_probe_failed") from error
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if value[:1] in {"'", '"'} and value[-1:] == value[:1]:
            value = value[1:-1]
        values[key] = value
    distribution_id = values.get("ID", "")
    distribution_version = values.get("VERSION_ID", "")
    if not distribution_id or not distribution_version:
        raise CanaryRunError("wsl_distribution_probe_failed")
    return distribution_id, distribution_version


def _host_is_wsl() -> bool:
    try:
        release = Path("/proc/sys/kernel/osrelease").read_text(encoding="utf-8")
    except OSError:
        return False
    return "microsoft" in release.casefold()


def _safe_read_regular(path: Path, code: str) -> bytes:
    if path.is_symlink():
        raise CanaryRunError(code)
    try:
        metadata = path.stat()
        payload = path.read_bytes()
    except OSError as error:
        raise CanaryRunError(code) from error
    if not stat.S_ISREG(metadata.st_mode):
        raise CanaryRunError(code)
    return payload


def _git_environment() -> dict[str, str]:
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        }
    )
    return environment


def _require_clean_tracked_checkout(root: Path) -> None:
    try:
        completed = subprocess.run(
            (
                "git",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.hooksPath=",
                "-C",
                str(root),
                "status",
                "--porcelain=v1",
                "--untracked-files=no",
            ),
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=_git_environment(),
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CanaryRunError("checkout_status_failed") from error
    if completed.returncode != 0:
        raise CanaryRunError("checkout_status_failed")
    if completed.stdout:
        raise CanaryRunError("checkout_tracked_worktree_drift")


def _locked_dependencies(path: Path) -> tuple[LockedDependency, ...]:
    try:
        raw = json.loads(_safe_read_regular(path, "lake_manifest_unreadable"))
    except json.JSONDecodeError as error:
        raise CanaryRunError("lake_manifest_invalid") from error
    if not isinstance(raw, dict) or not isinstance(raw.get("packages"), list):
        raise CanaryRunError("lake_manifest_invalid")
    dependencies: list[LockedDependency] = []
    seen: set[str] = set()
    for value in raw["packages"]:
        if not isinstance(value, dict):
            raise CanaryRunError("lake_manifest_invalid")
        name = value.get("name")
        revision = value.get("rev")
        package_type = value.get("type")
        if (
            not isinstance(name, str)
            or _SAFE_PACKAGE_NAME.fullmatch(name) is None
            or name in seen
            or package_type != "git"
            or not isinstance(revision, str)
            or _SHA1.fullmatch(revision) is None
        ):
            raise CanaryRunError("lake_manifest_invalid")
        seen.add(name)
        dependencies.append(LockedDependency(name=name, revision=revision))
    if not dependencies:
        raise CanaryRunError("lake_manifest_invalid")
    return tuple(sorted(dependencies, key=lambda dependency: dependency.name))


def load_verified_fixture(checkout: Path, manifest_path: Path) -> FixtureEvidence:
    """Verify all repository locks and build the fixed answer-free canary view."""

    manifest_bytes = _safe_read_regular(manifest_path, "manifest_unreadable")
    if _sha256(manifest_bytes) != EXPECTED_MANIFEST_SHA256:
        raise CanaryRunError("manifest_byte_hash_drift")
    try:
        adapter = FateAdapter.from_manifest_file(
            checkout,
            manifest_path,
            expected_manifest_content_hash=EXPECTED_MANIFEST_SHA256,
        )
    except FateFixtureIntegrityError as error:
        raise CanaryRunError("fate_fixture_integrity_failed") from error
    lock = FateFixtureLockV1.load()
    _require_clean_tracked_checkout(checkout)
    for tier in _TIERS:
        _require_clean_tracked_checkout(checkout / f"FATE-{tier}")

    cases: list[CanaryCase] = []
    for tier in _TIERS:
        for number in sorted(CANARY[tier]):
            task = adapter.task(f"FATE-{tier}-{number}")
            source_path = checkout.joinpath(*PurePosixPath(task.source_path).parts)
            source = _safe_read_regular(source_path, "canary_source_unreadable")
            if _sha256(source) != task.source_sha256:
                raise CanaryRunError("canary_worktree_source_drift")
            cases.append(
                CanaryCase(
                    task_id=task.task_id,
                    split=tier,
                    source_path=task.source_path,
                    source_sha256=task.source_sha256,
                    signature_sha256=task.target.signature_sha256,
                )
            )
    if len(cases) != 12:
        raise CanaryRunError("canary_selection_drift")

    dependencies: dict[Tier, tuple[LockedDependency, ...]] = {}
    for tier in _TIERS:
        split_root = checkout / f"FATE-{tier}"
        toolchain = _safe_read_regular(split_root / "lean-toolchain", "toolchain_unreadable")
        try:
            toolchain_name = toolchain.decode("utf-8").strip()
        except UnicodeDecodeError as error:
            raise CanaryRunError("toolchain_invalid") from error
        if toolchain_name != lock.toolchain:
            raise CanaryRunError("toolchain_worktree_drift")
        dependencies[tier] = _locked_dependencies(split_root / "lake-manifest.json")
        mathlib = next(
            (dependency for dependency in dependencies[tier] if dependency.name == "mathlib"),
            None,
        )
        if mathlib is None or mathlib.revision != lock.mathlib_revision:
            raise CanaryRunError("mathlib_manifest_drift")

    return FixtureEvidence(
        manifest_sha256=adapter.manifest.content_hash,
        root_commit=lock.root_commit,
        submodules=dict(lock.submodules),
        toolchain=lock.toolchain,
        mathlib_commit=lock.mathlib_revision,
        lake_manifest_sha256=dict(lock.lake_manifest_sha256),
        dependencies=dependencies,
        cases=tuple(cases),
    )


def _source_on_host(checkout: Path, case: CanaryCase) -> Path:
    return checkout.joinpath(*PurePosixPath(case.source_path).parts)


def _case_report(case: CanaryCase, observation: CommandObservation) -> dict[str, object]:
    if observation.timed_out:
        result = "timeout"
    elif observation.returncode == 0:
        result = "compiled"
    else:
        result = "compile_failed"
    return {
        "task_id": case.task_id,
        "source_path": case.source_path,
        "source_sha256": case.source_sha256,
        "signature_sha256": case.signature_sha256,
        "command": ["lake", "env", "lean", case.source_path.split("/", 1)[1]],
        "elapsed_ms": round(observation.elapsed_seconds * 1000, 3),
        "exit_code": observation.returncode,
        "result": result,
        "stdout_bytes": len(observation.stdout),
        "stdout_sha256": _sha256(observation.stdout),
        "stderr_bytes": len(observation.stderr),
        "stderr_sha256": _sha256(observation.stderr),
    }


def execute_canaries(
    *,
    fixture: FixtureEvidence,
    checkout: Path,
    runtime: CanaryRuntime,
    timeout_seconds: int,
) -> dict[str, object]:
    """Compile exactly 12 immutable originals and return an answer-free report."""

    if not 1 <= timeout_seconds <= 3600:
        raise CanaryRunError("invalid_timeout")
    expected_ids = {f"FATE-{tier}-{number}" for tier in _TIERS for number in CANARY[tier]}
    if {case.task_id for case in fixture.cases} != expected_ids or len(fixture.cases) != 12:
        raise CanaryRunError("canary_selection_drift")
    for case in fixture.cases:
        payload = _safe_read_regular(
            _source_on_host(checkout, case),
            "canary_source_unreadable",
        )
        if _sha256(payload) != case.source_sha256:
            raise CanaryRunError("canary_worktree_source_drift")

    started_at = _utc_now()
    runtime_evidence = runtime.preflight(fixture, checkout)
    tiers: dict[str, object] = {}
    for tier in _TIERS:
        tier_reports: list[dict[str, object]] = []
        for case in (item for item in fixture.cases if item.split == tier):
            relative = case.source_path.split("/", 1)[1]
            observation = runtime.compile(
                split=tier,
                relative_source=relative,
                timeout_seconds=timeout_seconds,
            )
            after = _safe_read_regular(
                _source_on_host(checkout, case),
                "canary_source_unreadable",
            )
            if _sha256(after) != case.source_sha256:
                raise CanaryRunError("canary_source_changed_during_execution")
            tier_reports.append(_case_report(case, observation))
        compiled = sum(item["result"] == "compiled" for item in tier_reports)
        tiers[tier] = {
            "cases": tier_reports,
            "summary": {
                "compiled": compiled,
                "failed": len(tier_reports) - compiled,
                "total": len(tier_reports),
            },
        }

    policy = {
        "policy_id": COMMAND_POLICY_ID,
        "argv_template": ["lake", "env", "lean", "{manifest_relative_source_path}"],
        "environment": {
            "mode": "empty_then_allowlisted",
            "names": ["HOME", "PATH", "LANG", "LC_ALL"],
            "values_recorded": False,
        },
        "stdin": "null",
        "stdout": "sha256_and_byte_count_only",
        "stderr": "sha256_and_byte_count_only",
        "network_isolation": "not_enforced_by_this_runner",
        "timeout_seconds_per_case": timeout_seconds,
        "writes_requested": False,
    }
    return {
        "schema_version": REPORT_SCHEMA,
        "suite": SUITE,
        "evidence_scope": "pinned_original_source_baseline_compilation_only",
        "proof_search_executed": False,
        "original_sources_contain_sorry": True,
        "started_at": started_at,
        "finished_at": _utc_now(),
        "fixture": {
            "manifest_sha256": fixture.manifest_sha256,
            "root_commit": fixture.root_commit,
            "submodules": dict(sorted(fixture.submodules.items())),
            "toolchain": fixture.toolchain,
            "mathlib_commit": fixture.mathlib_commit,
            "lake_manifest_sha256": dict(sorted(fixture.lake_manifest_sha256.items())),
        },
        "runtime": {
            "execution_platform": runtime_evidence.execution_platform,
            "distribution": runtime_evidence.distribution,
            "distribution_id": runtime_evidence.distribution_id,
            "distribution_version": runtime_evidence.distribution_version,
            "kernel_release": runtime_evidence.kernel_release,
            "lean_version": runtime_evidence.lean_version,
            "lake_version": runtime_evidence.lake_version,
            "dependency_graph_sha256": dict(
                sorted(runtime_evidence.dependency_graph_sha256.items())
            ),
            "dependency_counts": dict(sorted(runtime_evidence.dependency_counts.items())),
        },
        "command_policy": policy,
        "command_policy_sha256": _sha256(_canonical_json(policy)),
        "tiers": tiers,
        "tiers_reported_separately": True,
        "contains_source_or_answer_text": False,
        "contains_environment_values": False,
    }


def report_envelope(report: Mapping[str, object]) -> dict[str, object]:
    report_dict = dict(report)
    return {
        "schema_version": REPORT_ENVELOPE_SCHEMA,
        "report_sha256": _sha256(_canonical_json(report_dict)),
        "report": report_dict,
    }


def write_report_exclusive(path: Path, envelope: Mapping[str, object], checkout: Path) -> Path:
    requested = path.absolute()
    if requested.exists():
        raise CanaryRunError("report_already_exists")
    destination = requested.resolve()
    checkout_root = checkout.resolve()
    if destination.is_relative_to(checkout_root):
        raise CanaryRunError("report_inside_fate_checkout_refused")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.parent.is_symlink():
        raise CanaryRunError("linked_report_directory_refused")
    payload = _canonical_json(dict(envelope))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor: int | None = None
    try:
        descriptor = os.open(destination, flags, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
        destination.unlink(missing_ok=True)
        raise CanaryRunError("report_write_failed") from error
    return destination


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--checkout",
        type=Path,
        default=PROJECT_ROOT / "benchmarks" / "vendor" / "FATE",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=PROJECT_ROOT / "benchmarks" / "results" / "fate-source-manifest.v1.json",
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--distribution", default=DEFAULT_WSL_DISTRIBUTION)
    parser.add_argument("--timeout-seconds", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    return parser.parse_args(argv)


def _tier_failures(report: Mapping[str, object]) -> int:
    tiers = cast(dict[str, object], report["tiers"])
    failures = 0
    for tier in _TIERS:
        tier_report = cast(dict[str, object], tiers[tier])
        summary = cast(dict[str, int], tier_report["summary"])
        failures += summary["failed"]
    return failures


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    checkout = cast(Path, args.checkout).resolve()
    output = cast(Path, args.output)
    try:
        fixture = load_verified_fixture(checkout, cast(Path, args.manifest).resolve())
        runtime = WslRuntime(
            distribution=cast(str, args.distribution),
            runner=SubprocessCommandRunner(),
        )
        report = execute_canaries(
            fixture=fixture,
            checkout=checkout,
            runtime=runtime,
            timeout_seconds=cast(int, args.timeout_seconds),
        )
        envelope = report_envelope(report)
        written = write_report_exclusive(output, envelope, checkout)
    except CanaryRunError as error:
        print(
            json.dumps(
                {
                    "schema_version": REPORT_ENVELOPE_SCHEMA,
                    "status": "blocked",
                    "error_code": error.code,
                },
                ensure_ascii=True,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    print(
        json.dumps(
            {
                "schema_version": REPORT_ENVELOPE_SCHEMA,
                "status": "completed",
                "report_sha256": envelope["report_sha256"],
                "output": str(written),
                "tier_failures": _tier_failures(report),
            },
            ensure_ascii=True,
            sort_keys=True,
        )
    )
    return 0 if _tier_failures(report) == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
