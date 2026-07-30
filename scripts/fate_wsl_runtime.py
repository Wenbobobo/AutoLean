"""Prepare, audit, and use an ext4 FATE runtime without network access.

The public commands run from Windows and dispatch this same file into the selected
WSL distribution.  Hidden ``_native-*`` commands are implementation details that
must execute under WSL on an ext4 cache root.
"""

# ruff: noqa: E402

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import platform
import re
import stat
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final, Literal, Protocol, cast

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from benchmarks.fate import CANARY, Tier
from benchmarks.fate_adapter import (
    FateAdapter,
    FateFixtureIntegrityError,
    FateFixtureLockV1,
)
from scripts.fate_compile_canary import (
    DEFAULT_TIMEOUT_SECONDS,
    DEFAULT_WSL_DISTRIBUTION,
    EXPECTED_MANIFEST_SHA256,
    CanaryCase,
    FixtureEvidence,
    LockedDependency,
)
from scripts.fate_compile_canary import (
    main as compile_canary_main,
)

RUNTIME_STATE_SCHEMA: Final = "autolean.fate-wsl-runtime-state.v1"
RUNTIME_AUDIT_SCHEMA: Final = "autolean.fate-wsl-runtime-audit.v1"
HOST_RESULT_SCHEMA: Final = "autolean.fate-wsl-runtime-result.v1"
# V2 changes the persisted runtime's text policy from the historical CRLF
# presentation to the canonical LF bytes pinned by the fixture lock.  A new
# namespace prevents a valid V1 state file from being reinterpreted in place.
LAYOUT_VERSION: Final = "fate-runtime-v2"
_TIERS: Final[tuple[Tier, ...]] = ("M", "H", "X")
_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_DISTRIBUTION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SAFE_PACKAGE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SAFE_VERSION = re.compile(r"^[A-Za-z0-9._+-]{1,100}$")
_EXT4_STAT_NAMES: Final = frozenset({"ext2/ext3", "ext2/ext3/ext4", "ext4"})
_MINIMAL_WSL_PATH: Final = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


class RuntimePreparationError(RuntimeError):
    """Fail-closed preparation error with a stable, non-sensitive code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class RuntimePaths:
    cache_root: Path
    packages_root: Path
    layout_root: Path
    object_db_root: Path
    runtime_root: Path
    control_root: Path
    state_path: Path


@dataclass(frozen=True, slots=True)
class RuntimeExpectation:
    fixture: FixtureEvidence
    metadata_json_sha256: Mapping[Tier, str]
    task_hashes: Mapping[str, str]
    shared_dependencies: tuple[LockedDependency, ...]
    state: Mapping[str, object]
    state_sha256: str


@dataclass(frozen=True, slots=True)
class ProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes


class ProcessRunner(Protocol):
    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        timeout_seconds: int = 120,
        env: Mapping[str, str] | None = None,
    ) -> ProcessResult: ...


class SubprocessRunner:
    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        timeout_seconds: int = 120,
        env: Mapping[str, str] | None = None,
    ) -> ProcessResult:
        try:
            completed = subprocess.run(
                tuple(argv),
                check=False,
                cwd=cwd,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=timeout_seconds,
                env=None if env is None else dict(env),
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RuntimePreparationError("subprocess_unavailable_or_timed_out") from error
        return ProcessResult(
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _safe_json_object(payload: bytes, code: str) -> dict[str, object]:
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimePreparationError(code) from error
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise RuntimePreparationError(code)
    return value


def _safe_line(payload: bytes, code: str) -> str:
    try:
        value = payload.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise RuntimePreparationError(code) from error
    if not value or "\x00" in value or "\n" in value or "\r" in value:
        raise RuntimePreparationError(code)
    return value


def _native_git_environment() -> dict[str, str]:
    return {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": _MINIMAL_WSL_PATH,
    }


def _native_git(
    runner: ProcessRunner,
    cwd: Path | None,
    *args: str,
    timeout_seconds: int = 120,
    code: str = "git_command_failed",
) -> bytes:
    command = (
        "/usr/bin/git",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=",
        "-c",
        "core.autocrlf=false",
        "-c",
        "core.eol=lf",
        *args,
    )
    result = runner.run(
        command,
        cwd=cwd,
        timeout_seconds=timeout_seconds,
        env=_native_git_environment(),
    )
    if result.returncode != 0:
        raise RuntimePreparationError(code)
    return result.stdout


def _require_native_wsl() -> None:
    if platform.system() != "Linux":
        raise RuntimePreparationError("native_wsl_required")
    try:
        kernel = Path("/proc/sys/kernel/osrelease").read_text(encoding="utf-8")
    except OSError as error:
        raise RuntimePreparationError("native_wsl_required") from error
    if "microsoft" not in kernel.casefold():
        raise RuntimePreparationError("native_wsl_required")


def _pure_absolute_posix(value: str, field: str) -> PurePosixPath:
    candidate = PurePosixPath(value)
    if (
        not candidate.is_absolute()
        or "\x00" in value
        or "\\" in value
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        raise RuntimePreparationError(f"unsafe_{field}")
    return candidate


def _path_from_posix(value: str, field: str) -> Path:
    return Path(_pure_absolute_posix(value, field).as_posix())


def _require_descendant(root: Path, candidate: Path, field: str) -> None:
    root_absolute = Path(os.path.abspath(root))
    candidate_absolute = Path(os.path.abspath(candidate))
    if candidate_absolute == root_absolute or not candidate_absolute.is_relative_to(root_absolute):
        raise RuntimePreparationError(f"{field}_outside_cache_root")


def _require_real_directory(path: Path, code: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise RuntimePreparationError(code) from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise RuntimePreparationError(code)


def _require_no_link_components(root: Path, candidate: Path, code: str) -> None:
    _require_descendant(root, candidate, code)
    relative = Path(os.path.abspath(candidate)).relative_to(Path(os.path.abspath(root)))
    current = root
    for component in relative.parts:
        current = current / component
        try:
            metadata = current.lstat()
        except OSError as error:
            raise RuntimePreparationError(code) from error
        if stat.S_ISLNK(metadata.st_mode):
            raise RuntimePreparationError(code)


def _require_ext4(cache_root: Path, runner: ProcessRunner) -> None:
    result = runner.run(
        ("/usr/bin/stat", "-f", "-c", "%T", "--", str(cache_root)),
        timeout_seconds=30,
        env={
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": _MINIMAL_WSL_PATH,
        },
    )
    if result.returncode != 0:
        raise RuntimePreparationError("cache_filesystem_probe_failed")
    filesystem = _safe_line(result.stdout, "cache_filesystem_probe_failed")
    if filesystem not in _EXT4_STAT_NAMES:
        raise RuntimePreparationError("cache_root_is_not_ext4")


def _dependencies_payload(dependencies: Sequence[LockedDependency]) -> list[dict[str, str]]:
    return [
        {"name": dependency.name, "revision": dependency.revision}
        for dependency in sorted(dependencies, key=lambda item: item.name)
    ]


def _shared_dependencies(fixture: FixtureEvidence) -> tuple[LockedDependency, ...]:
    reference = tuple(sorted(fixture.dependencies["M"], key=lambda item: item.name))
    for tier in ("H", "X"):
        candidate = tuple(sorted(fixture.dependencies[tier], key=lambda item: item.name))
        if candidate != reference:
            raise RuntimePreparationError("dependency_graph_not_shareable")
    return reference


def _load_locked_dependencies(path: Path) -> tuple[LockedDependency, ...]:
    try:
        metadata = path.lstat()
        raw = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimePreparationError("host_lake_manifest_invalid") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise RuntimePreparationError("host_lake_manifest_invalid")
    if not isinstance(raw, dict) or not isinstance(raw.get("packages"), list):
        raise RuntimePreparationError("host_lake_manifest_invalid")
    dependencies: list[LockedDependency] = []
    seen: set[str] = set()
    for item in raw["packages"]:
        if not isinstance(item, dict):
            raise RuntimePreparationError("host_lake_manifest_invalid")
        name = item.get("name")
        revision = item.get("rev")
        if (
            item.get("type") != "git"
            or not isinstance(name, str)
            or _SAFE_PACKAGE_NAME.fullmatch(name) is None
            or name in seen
            or not isinstance(revision, str)
            or _SHA1.fullmatch(revision) is None
        ):
            raise RuntimePreparationError("host_lake_manifest_invalid")
        seen.add(name)
        dependencies.append(LockedDependency(name=name, revision=revision))
    if not dependencies:
        raise RuntimePreparationError("host_lake_manifest_invalid")
    return tuple(sorted(dependencies, key=lambda dependency: dependency.name))


def build_runtime_expectation(checkout: Path, manifest_path: Path) -> RuntimeExpectation:
    """Load the host authority and derive a path-free deterministic runtime state."""

    try:
        manifest_metadata = manifest_path.lstat()
        manifest_bytes = manifest_path.read_bytes()
    except OSError as error:
        raise RuntimePreparationError("host_manifest_unreadable") from error
    if (
        not stat.S_ISREG(manifest_metadata.st_mode)
        or _sha256(manifest_bytes) != EXPECTED_MANIFEST_SHA256
    ):
        raise RuntimePreparationError("host_manifest_byte_hash_drift")
    try:
        adapter = FateAdapter.from_manifest_file(
            checkout,
            manifest_path,
            expected_manifest_content_hash=EXPECTED_MANIFEST_SHA256,
        )
        manifest = adapter.manifest
        manifest.validate_against_lock(FateFixtureLockV1.load())
    except FateFixtureIntegrityError as error:
        raise RuntimePreparationError("host_fixture_integrity_failed") from error
    lock = FateFixtureLockV1.load()
    dependency_sets = {
        tier: _load_locked_dependencies(checkout / f"FATE-{tier}" / "lake-manifest.json")
        for tier in _TIERS
    }
    cases = tuple(
        CanaryCase(
            task_id=task.task_id,
            split=tier,
            source_path=task.source_path,
            source_sha256=task.source_sha256,
            signature_sha256=task.target.signature_sha256,
        )
        for tier in _TIERS
        for number in sorted(CANARY[tier])
        for task in (manifest.task(f"FATE-{tier}-{number}"),)
    )
    fixture = FixtureEvidence(
        manifest_sha256=manifest.content_hash,
        root_commit=lock.root_commit,
        submodules=dict(lock.submodules),
        toolchain=lock.toolchain,
        mathlib_commit=lock.mathlib_revision,
        lake_manifest_sha256=dict(lock.lake_manifest_sha256),
        dependencies=dependency_sets,
        cases=cases,
    )
    dependencies = _shared_dependencies(fixture)
    task_hashes = {task.task_id: task.source_sha256 for task in manifest.tasks}
    if len(task_hashes) != 350:
        raise RuntimePreparationError("manifest_task_count_drift")
    source_set_sha256 = _sha256(
        _canonical_json(
            [
                {"source_sha256": task_hashes[task_id], "task_id": task_id}
                for task_id in sorted(task_hashes)
            ]
        )
    )
    dependency_graph_sha256 = _sha256(_canonical_json(_dependencies_payload(dependencies)))
    eol_policy = {
        tier: {
            "metadata_json": "git_blob_lf",
            "lake_manifest": "canonical_lf",
            "task_sources": "git_blob_lf",
        }
        for tier in _TIERS
    }
    state: dict[str, object] = {
        "schema_version": RUNTIME_STATE_SCHEMA,
        "layout_version": LAYOUT_VERSION,
        "fixture": {
            "manifest_sha256": fixture.manifest_sha256,
            "root_commit": fixture.root_commit,
            "submodules": dict(sorted(fixture.submodules.items())),
            "toolchain": fixture.toolchain,
            "mathlib_commit": fixture.mathlib_commit,
            "lake_manifest_sha256": dict(sorted(fixture.lake_manifest_sha256.items())),
            "metadata_json_sha256": dict(sorted(manifest.metadata_json_sha256.items())),
        },
        "source_set_sha256": source_set_sha256,
        "source_count": len(task_hashes),
        "dependency_graph_sha256": dependency_graph_sha256,
        "dependency_count": len(dependencies),
        "eol_policy": eol_policy,
        "shared_packages": True,
        "network_accessed": False,
        "contains_absolute_paths": False,
        "contains_source_or_answer_text": False,
    }
    return RuntimeExpectation(
        fixture=fixture,
        metadata_json_sha256=dict(manifest.metadata_json_sha256),
        task_hashes=task_hashes,
        shared_dependencies=dependencies,
        state=state,
        state_sha256=_sha256(_canonical_json(state)),
    )


def _runtime_paths(cache_root: Path, packages_root: Path, root_commit: str) -> RuntimePaths:
    layout_root = cache_root / f"{LAYOUT_VERSION}-{root_commit[:8]}"
    return RuntimePaths(
        cache_root=cache_root,
        packages_root=packages_root,
        layout_root=layout_root,
        object_db_root=layout_root / "object-db",
        runtime_root=layout_root / "runtime",
        control_root=layout_root / "control",
        state_path=layout_root / "control" / "state.json",
    )


def _validate_base_paths(paths: RuntimePaths, runner: ProcessRunner) -> None:
    _require_real_directory(paths.cache_root, "cache_root_missing_or_linked")
    _require_ext4(paths.cache_root, runner)
    _require_descendant(paths.cache_root, paths.packages_root, "packages_root")
    _require_real_directory(paths.packages_root, "packages_root_missing_or_linked")
    _require_no_link_components(
        paths.cache_root,
        paths.packages_root,
        "packages_root_contains_link_component",
    )
    if paths.packages_root.resolve() != paths.packages_root:
        raise RuntimePreparationError("packages_root_resolution_drift")
    _require_descendant(paths.cache_root, paths.layout_root, "layout_root")


def _write_exclusive(path: Path, payload: bytes, code: str) -> None:
    if path.exists() or path.is_symlink():
        raise RuntimePreparationError(code)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
        raise RuntimePreparationError(code) from error


def _clone_local_repository(
    runner: ProcessRunner,
    source: Path,
    destination: Path,
    expected_commit: str,
) -> None:
    if destination.exists() or destination.is_symlink():
        raise RuntimePreparationError("object_database_target_conflict")
    output = _native_git(
        runner,
        None,
        "clone",
        "--local",
        "--no-hardlinks",
        "--no-checkout",
        "--no-tags",
        "--no-recurse-submodules",
        "--",
        str(source),
        str(destination),
        timeout_seconds=300,
        code="local_object_database_clone_failed",
    )
    del output
    _native_git(
        runner,
        destination,
        "remote",
        "remove",
        "origin",
        code="local_object_database_remote_removal_failed",
    )
    if _native_git(runner, destination, "remote", code="object_database_has_remote"):
        raise RuntimePreparationError("object_database_has_remote")
    revision = _safe_line(
        _native_git(
            runner,
            destination,
            "rev-parse",
            "--verify",
            f"{expected_commit}^{{commit}}",
            code="object_database_commit_missing",
        ),
        "object_database_commit_missing",
    )
    if revision != expected_commit:
        raise RuntimePreparationError("object_database_commit_drift")


def _create_detached_worktree(
    runner: ProcessRunner,
    repository: Path,
    destination: Path,
    commit: str,
) -> None:
    if destination.exists():
        if destination.is_symlink() or not destination.is_dir():
            raise RuntimePreparationError("runtime_worktree_target_conflict")
        if any(destination.iterdir()):
            raise RuntimePreparationError("runtime_worktree_target_conflict")
    _native_git(
        runner,
        repository,
        "worktree",
        "add",
        "--detach",
        "--no-checkout",
        "--",
        str(destination),
        commit,
        code="detached_worktree_creation_failed",
    )
    _native_git(
        runner,
        destination,
        "reset",
        "--hard",
        commit,
        code="detached_worktree_checkout_failed",
    )


def _prepare_new_layout(
    paths: RuntimePaths,
    checkout: Path,
    expectation: RuntimeExpectation,
    runner: ProcessRunner,
) -> None:
    if paths.layout_root.exists() or paths.layout_root.is_symlink():
        raise RuntimePreparationError("runtime_layout_conflict_without_state")
    paths.layout_root.mkdir(mode=0o700)
    paths.object_db_root.mkdir(mode=0o700)
    paths.control_root.mkdir(mode=0o700)

    root_repository = paths.object_db_root / "root"
    split_repositories = {tier: paths.object_db_root / f"FATE-{tier}" for tier in _TIERS}
    _clone_local_repository(
        runner,
        checkout,
        root_repository,
        expectation.fixture.root_commit,
    )
    for tier in _TIERS:
        _clone_local_repository(
            runner,
            checkout / f"FATE-{tier}",
            split_repositories[tier],
            expectation.fixture.submodules[tier],
        )
    _create_detached_worktree(
        runner,
        root_repository,
        paths.runtime_root,
        expectation.fixture.root_commit,
    )
    for tier in _TIERS:
        split_root = paths.runtime_root / f"FATE-{tier}"
        _create_detached_worktree(
            runner,
            split_repositories[tier],
            split_root,
            expectation.fixture.submodules[tier],
        )
        lake_root = split_root / ".lake"
        if lake_root.exists() or lake_root.is_symlink():
            raise RuntimePreparationError("lake_runtime_target_conflict")
        lake_root.mkdir(mode=0o700)
        packages_link = lake_root / "packages"
        packages_link.symlink_to(paths.packages_root, target_is_directory=True)


def _git_revision(runner: ProcessRunner, repository: Path, code: str) -> str:
    revision = _safe_line(
        _native_git(
            runner,
            repository,
            "rev-parse",
            "--verify",
            "HEAD^{commit}",
            code=code,
        ),
        code,
    )
    if _SHA1.fullmatch(revision) is None:
        raise RuntimePreparationError(code)
    return revision


def _git_common_dir(runner: ProcessRunner, repository: Path, cache_root: Path) -> Path:
    value = _safe_line(
        _native_git(
            runner,
            repository,
            "rev-parse",
            "--path-format=absolute",
            "--git-common-dir",
            code="git_common_directory_probe_failed",
        ),
        "git_common_directory_probe_failed",
    )
    common = Path(value)
    if not common.is_absolute():
        raise RuntimePreparationError("git_common_directory_is_not_absolute")
    resolved = common.resolve()
    if not resolved.is_relative_to(cache_root.resolve()):
        raise RuntimePreparationError("git_common_directory_outside_cache_root")
    _require_real_directory(resolved, "git_common_directory_missing_or_linked")
    return resolved


def _require_clean_git_worktree(runner: ProcessRunner, repository: Path) -> None:
    status = _native_git(
        runner,
        repository,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        code="runtime_git_status_failed",
    )
    if status:
        raise RuntimePreparationError("runtime_git_worktree_drift")


def _require_regular_hash(path: Path, expected: str, code: str) -> None:
    try:
        metadata = path.lstat()
        payload = path.read_bytes()
    except OSError as error:
        raise RuntimePreparationError(code) from error
    if not stat.S_ISREG(metadata.st_mode) or _sha256(payload) != expected:
        raise RuntimePreparationError(code)


def _require_lf(path: Path, code: str) -> None:
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise RuntimePreparationError(code) from error
    if b"\r\n" in payload:
        raise RuntimePreparationError(code)


def _verify_runtime_links(paths: RuntimePaths) -> None:
    expected_links: set[Path] = set()
    for tier in _TIERS:
        lake_root = paths.runtime_root / f"FATE-{tier}" / ".lake"
        _require_real_directory(lake_root, "lake_runtime_directory_missing_or_linked")
        allowed = {"packages", "config"}
        try:
            entries = {entry.name for entry in lake_root.iterdir()}
        except OSError as error:
            raise RuntimePreparationError("lake_runtime_directory_unreadable") from error
        if not entries <= allowed or "packages" not in entries:
            raise RuntimePreparationError("lake_runtime_directory_has_unknown_entries")
        config = lake_root / "config"
        if config.exists():
            _require_real_directory(config, "lake_generated_config_is_linked")
            for directory, names, files in os.walk(config, followlinks=False):
                current = Path(directory)
                if any((current / name).is_symlink() for name in (*names, *files)):
                    raise RuntimePreparationError("lake_generated_config_contains_link")
        packages_link = lake_root / "packages"
        try:
            metadata = packages_link.lstat()
        except OSError as error:
            raise RuntimePreparationError("packages_link_missing") from error
        if not stat.S_ISLNK(metadata.st_mode):
            raise RuntimePreparationError("packages_link_is_not_symbolic")
        if packages_link.resolve() != paths.packages_root.resolve():
            raise RuntimePreparationError("packages_link_target_drift")
        if not packages_link.resolve().is_relative_to(paths.cache_root.resolve()):
            raise RuntimePreparationError("packages_link_escapes_cache_root")
        expected_links.add(packages_link)

    for directory, names, files in os.walk(paths.runtime_root, followlinks=False):
        current = Path(directory)
        for name in (*names, *files):
            candidate = current / name
            if candidate.is_symlink():
                if candidate not in expected_links:
                    raise RuntimePreparationError("runtime_contains_unapproved_symbolic_link")
                names[:] = [item for item in names if current / item != candidate]


def _verify_packages(
    paths: RuntimePaths,
    expectation: RuntimeExpectation,
    runner: ProcessRunner,
) -> None:
    expected = {
        dependency.name: dependency.revision for dependency in expectation.shared_dependencies
    }
    try:
        entries = {entry.name: entry for entry in paths.packages_root.iterdir()}
    except OSError as error:
        raise RuntimePreparationError("packages_root_unreadable") from error
    if set(entries) != set(expected):
        raise RuntimePreparationError("packages_root_inventory_drift")
    for name, revision in sorted(expected.items()):
        package = entries[name]
        _require_real_directory(package, "dependency_directory_missing_or_linked")
        if _git_revision(runner, package, "dependency_revision_probe_failed") != revision:
            raise RuntimePreparationError("dependency_revision_drift")
        _require_clean_git_worktree(runner, package)
    for directory, names, files in os.walk(paths.packages_root, followlinks=False):
        current = Path(directory)
        for name in (*names, *files):
            candidate = current / name
            if candidate.is_symlink():
                resolved = candidate.resolve()
                if not resolved.exists() or not resolved.is_relative_to(paths.cache_root.resolve()):
                    raise RuntimePreparationError("dependency_symbolic_link_escapes_cache_root")
                names[:] = [item for item in names if current / item != candidate]


def audit_runtime(
    *,
    checkout: Path,
    manifest_path: Path,
    paths: RuntimePaths,
    runner: ProcessRunner,
) -> dict[str, object]:
    """Read-only audit of a prepared or manually constructed runtime."""

    _validate_base_paths(paths, runner)
    expectation = build_runtime_expectation(checkout, manifest_path)
    _require_descendant(paths.cache_root, paths.runtime_root, "runtime_root")
    _require_real_directory(paths.runtime_root, "runtime_root_missing_or_linked")
    _require_no_link_components(
        paths.cache_root,
        paths.runtime_root,
        "runtime_root_contains_link_component",
    )

    if (
        _git_revision(runner, paths.runtime_root, "runtime_root_revision_probe_failed")
        != expectation.fixture.root_commit
    ):
        raise RuntimePreparationError("runtime_root_revision_drift")
    _git_common_dir(runner, paths.runtime_root, paths.cache_root)
    _require_clean_git_worktree(runner, paths.runtime_root)

    for tier in _TIERS:
        split_root = paths.runtime_root / f"FATE-{tier}"
        if (
            _git_revision(runner, split_root, "runtime_split_revision_probe_failed")
            != expectation.fixture.submodules[tier]
        ):
            raise RuntimePreparationError("runtime_split_revision_drift")
        _git_common_dir(runner, split_root, paths.cache_root)
        _require_clean_git_worktree(runner, split_root)
        _require_regular_hash(
            split_root / f"FATE-{tier}.json",
            expectation.metadata_json_sha256[tier],
            "runtime_metadata_hash_drift",
        )
        _require_regular_hash(
            split_root / "lake-manifest.json",
            expectation.fixture.lake_manifest_sha256[tier],
            "runtime_lake_manifest_hash_drift",
        )
        for text_path in (
            split_root / f"FATE-{tier}.json",
            split_root / "lake-manifest.json",
        ):
            _require_lf(text_path, "runtime_canonical_input_eol_drift")
        for text_path in (
            split_root / f"FATE{tier}.lean",
            split_root / "lakefile.lean",
            split_root / "lean-toolchain",
        ):
            _require_lf(text_path, "runtime_tracked_source_eol_drift")

    try:
        runtime_adapter = FateAdapter.from_manifest_file(
            paths.runtime_root,
            manifest_path,
            expected_manifest_content_hash=EXPECTED_MANIFEST_SHA256,
        )
    except FateFixtureIntegrityError as error:
        raise RuntimePreparationError("runtime_fixture_integrity_failed") from error
    for task_id, expected_hash in sorted(expectation.task_hashes.items()):
        task = runtime_adapter.task(task_id)
        task_path = paths.runtime_root.joinpath(*PurePosixPath(task.source_path).parts)
        _require_regular_hash(task_path, expected_hash, "runtime_task_source_hash_drift")
        _require_lf(task_path, "runtime_task_source_eol_drift")

    _verify_runtime_links(paths)
    _verify_packages(paths, expectation, runner)
    audit: dict[str, object] = {
        "schema_version": RUNTIME_AUDIT_SCHEMA,
        "runtime_state_sha256": expectation.state_sha256,
        "manifest_sha256": expectation.fixture.manifest_sha256,
        "root_commit": expectation.fixture.root_commit,
        "submodules": dict(sorted(expectation.fixture.submodules.items())),
        "source_count": len(expectation.task_hashes),
        "dependency_count": len(expectation.shared_dependencies),
        "all_task_hashes_match": True,
        "all_dependency_commits_match": True,
        "tracked_worktrees_clean": True,
        "eol_policy_verified": True,
        "links_confined_to_cache_root": True,
        "network_accessed": False,
        "contains_absolute_paths": False,
        "contains_source_or_answer_text": False,
    }
    audit["audit_sha256"] = _sha256(_canonical_json(audit))
    return audit


def prepare_runtime(
    *,
    checkout: Path,
    manifest_path: Path,
    cache_root: Path,
    packages_root: Path,
    runner: ProcessRunner,
) -> dict[str, object]:
    """Create once or verify an exact existing deterministic layout."""

    expectation = build_runtime_expectation(checkout, manifest_path)
    paths = _runtime_paths(
        cache_root,
        packages_root,
        expectation.fixture.root_commit,
    )
    _validate_base_paths(paths, runner)
    if paths.layout_root.exists() or paths.layout_root.is_symlink():
        if not paths.state_path.is_file() or paths.state_path.is_symlink():
            raise RuntimePreparationError("runtime_layout_conflict_without_state")
        state_bytes = paths.state_path.read_bytes()
        if state_bytes != _canonical_json(expectation.state):
            raise RuntimePreparationError("runtime_state_drift")
        mode: Literal["created", "reused"] = "reused"
    else:
        _prepare_new_layout(paths, checkout, expectation, runner)
        mode = "created"

    audit = audit_runtime(
        checkout=checkout,
        manifest_path=manifest_path,
        paths=paths,
        runner=runner,
    )
    if mode == "created":
        _write_exclusive(
            paths.state_path,
            _canonical_json(expectation.state),
            "runtime_state_write_failed",
        )
    return {
        "schema_version": HOST_RESULT_SCHEMA,
        "status": "prepared",
        "mode": mode,
        "runtime_path_relative_to_cache": paths.runtime_root.relative_to(
            paths.cache_root
        ).as_posix(),
        "runtime_state_sha256": expectation.state_sha256,
        "audit_sha256": audit["audit_sha256"],
        "source_count": audit["source_count"],
        "dependency_count": audit["dependency_count"],
        "network_accessed": False,
        "contains_absolute_paths": False,
    }


def _native_paths_from_args(
    args: argparse.Namespace,
    root_commit: str,
    *,
    explicit_runtime: bool,
) -> RuntimePaths:
    cache_root = _path_from_posix(cast(str, args.cache_root), "cache_root")
    packages_root = _path_from_posix(cast(str, args.packages_root), "packages_root")
    paths = _runtime_paths(cache_root, packages_root, root_commit)
    runtime_value = cast(str | None, getattr(args, "runtime_root", None))
    if explicit_runtime:
        if runtime_value is None:
            raise RuntimePreparationError("runtime_root_required")
        runtime_root = _path_from_posix(runtime_value, "runtime_root")
        paths = RuntimePaths(
            cache_root=paths.cache_root,
            packages_root=paths.packages_root,
            layout_root=runtime_root,
            object_db_root=runtime_root,
            runtime_root=runtime_root,
            control_root=runtime_root,
            state_path=runtime_root / "state.json",
        )
    return paths


def _native_audit(args: argparse.Namespace, runner: ProcessRunner) -> dict[str, object]:
    _require_native_wsl()
    checkout = _path_from_posix(cast(str, args.checkout), "checkout")
    manifest = _path_from_posix(cast(str, args.manifest), "manifest")
    expectation = build_runtime_expectation(checkout, manifest)
    paths = _native_paths_from_args(args, expectation.fixture.root_commit, explicit_runtime=True)
    audit = audit_runtime(
        checkout=checkout,
        manifest_path=manifest,
        paths=paths,
        runner=runner,
    )
    return {
        "schema_version": HOST_RESULT_SCHEMA,
        "status": "verified",
        "runtime_state_sha256": audit["runtime_state_sha256"],
        "audit_sha256": audit["audit_sha256"],
        "source_count": audit["source_count"],
        "dependency_count": audit["dependency_count"],
        "network_accessed": False,
        "contains_absolute_paths": False,
    }


def _native_prepare(args: argparse.Namespace, runner: ProcessRunner) -> dict[str, object]:
    _require_native_wsl()
    checkout = _path_from_posix(cast(str, args.checkout), "checkout")
    manifest = _path_from_posix(cast(str, args.manifest), "manifest")
    cache_root = _path_from_posix(cast(str, args.cache_root), "cache_root")
    packages_root = _path_from_posix(cast(str, args.packages_root), "packages_root")
    return prepare_runtime(
        checkout=checkout,
        manifest_path=manifest,
        cache_root=cache_root,
        packages_root=packages_root,
        runner=runner,
    )


def _native_run(args: argparse.Namespace, runner: ProcessRunner) -> tuple[dict[str, object], int]:
    audit_result = _native_audit(args, runner)
    output = _path_from_posix(cast(str, args.output), "output")
    checkout = _path_from_posix(cast(str, args.checkout), "checkout")
    manifest = _path_from_posix(cast(str, args.manifest), "manifest")
    expectation = build_runtime_expectation(checkout, manifest)
    paths = _native_paths_from_args(args, expectation.fixture.root_commit, explicit_runtime=True)
    captured_stdout = io.StringIO()
    captured_stderr = io.StringIO()
    with contextlib.redirect_stdout(captured_stdout), contextlib.redirect_stderr(captured_stderr):
        exit_code = compile_canary_main(
            (
                "--checkout",
                str(paths.runtime_root),
                "--manifest",
                str(manifest),
                "--output",
                str(output),
                "--distribution",
                cast(str, args.distribution),
                "--timeout-seconds",
                str(cast(int, args.timeout_seconds)),
            )
        )
    if exit_code == 2:
        blocked = _safe_json_object(
            captured_stderr.getvalue().encode("utf-8"),
            "canary_blocked_without_safe_result",
        )
        code = blocked.get("error_code")
        if not isinstance(code, str) or _SAFE_VERSION.fullmatch(code) is None:
            raise RuntimePreparationError("canary_blocked_without_safe_result")
        return (
            {
                "schema_version": HOST_RESULT_SCHEMA,
                "status": "blocked",
                "error_code": code,
                "runtime_state_sha256": audit_result["runtime_state_sha256"],
                "audit_sha256": audit_result["audit_sha256"],
                "contains_absolute_paths": False,
            },
            2,
        )
    try:
        envelope = _safe_json_object(output.read_bytes(), "canary_report_unreadable")
    except OSError as error:
        raise RuntimePreparationError("canary_report_unreadable") from error
    report_sha256 = envelope.get("report_sha256")
    if not isinstance(report_sha256, str) or _SHA256.fullmatch(report_sha256) is None:
        raise RuntimePreparationError("canary_report_hash_missing")
    child_result = _safe_json_object(
        captured_stdout.getvalue().encode("utf-8"),
        "canary_result_unreadable",
    )
    tier_failures = child_result.get("tier_failures")
    if not isinstance(tier_failures, int) or isinstance(tier_failures, bool):
        raise RuntimePreparationError("canary_result_unreadable")
    return (
        {
            "schema_version": HOST_RESULT_SCHEMA,
            "status": "completed",
            "runtime_state_sha256": audit_result["runtime_state_sha256"],
            "audit_sha256": audit_result["audit_sha256"],
            "report_sha256": report_sha256,
            "tier_failures": tier_failures,
            "contains_absolute_paths": False,
        },
        exit_code,
    )


def _host_minimal_environment_command(script_path: str) -> tuple[str, ...]:
    return (
        "/usr/bin/env",
        "-i",
        f"PATH={_MINIMAL_WSL_PATH}",
        "LANG=C.UTF-8",
        "LC_ALL=C.UTF-8",
        "PYTHONDONTWRITEBYTECODE=1",
        "/usr/bin/python3",
        script_path,
    )


def _host_wsl_call(
    runner: ProcessRunner,
    distribution: str,
    argv: Sequence[str],
    *,
    timeout_seconds: int,
) -> ProcessResult:
    if _SAFE_DISTRIBUTION.fullmatch(distribution) is None:
        raise RuntimePreparationError("unsafe_wsl_distribution")
    result = runner.run(
        ("wsl.exe", "--distribution", distribution, "--exec", *argv),
        timeout_seconds=timeout_seconds,
    )
    return result


def _host_map_path(runner: ProcessRunner, distribution: str, path: Path) -> str:
    result = _host_wsl_call(
        runner,
        distribution,
        ("/usr/bin/wslpath", "-a", "-u", str(path.resolve())),
        timeout_seconds=30,
    )
    if result.returncode != 0:
        raise RuntimePreparationError("wsl_path_mapping_failed")
    value = _safe_line(result.stdout, "wsl_path_mapping_failed")
    return _pure_absolute_posix(value, "mapped_path").as_posix()


def _host_dispatch(
    args: argparse.Namespace, runner: ProcessRunner
) -> tuple[dict[str, object], int]:
    if platform.system() != "Windows":
        raise RuntimePreparationError("windows_host_dispatch_required")
    distribution = cast(str, args.distribution)
    script_wsl = _host_map_path(runner, distribution, Path(__file__))
    checkout_wsl = _host_map_path(runner, distribution, cast(Path, args.checkout))
    manifest_wsl = _host_map_path(runner, distribution, cast(Path, args.manifest))
    command_name = cast(str, args.command)
    native_name = f"_native-{command_name}"
    native: list[str] = [
        *_host_minimal_environment_command(script_wsl),
        native_name,
        "--checkout",
        checkout_wsl,
        "--manifest",
        manifest_wsl,
        "--cache-root",
        _pure_absolute_posix(cast(str, args.cache_root), "cache_root").as_posix(),
        "--packages-root",
        _pure_absolute_posix(cast(str, args.packages_root), "packages_root").as_posix(),
        "--distribution",
        distribution,
    ]
    runtime_root = cast(str | None, getattr(args, "runtime_root", None))
    if runtime_root is not None:
        native.extend(
            (
                "--runtime-root",
                _pure_absolute_posix(runtime_root, "runtime_root").as_posix(),
            )
        )
    if command_name == "run":
        output_wsl = _host_map_path(runner, distribution, cast(Path, args.output))
        native.extend(
            (
                "--output",
                output_wsl,
                "--timeout-seconds",
                str(cast(int, args.timeout_seconds)),
            )
        )
    result = _host_wsl_call(
        runner,
        distribution,
        native,
        timeout_seconds=7200 if command_name == "run" else 1800,
    )
    if result.returncode not in {0, 1, 2}:
        raise RuntimePreparationError("native_wsl_runtime_command_failed")
    payload = result.stdout if result.stdout.strip() else result.stderr
    parsed = _safe_json_object(payload, "native_wsl_runtime_result_invalid")
    if parsed.get("schema_version") != HOST_RESULT_SCHEMA:
        raise RuntimePreparationError("native_wsl_runtime_result_invalid")
    rendered = _canonical_json(parsed)
    if b"/home/" in rendered or b"/mnt/" in rendered or b":\\" in rendered:
        raise RuntimePreparationError("native_wsl_runtime_result_leaked_path")
    return parsed, result.returncode


def _add_common_arguments(parser: argparse.ArgumentParser, *, native: bool) -> None:
    path_type: type[Path] | type[str] = str if native else Path
    parser.add_argument(
        "--checkout",
        type=path_type,
        default=(
            "/mnt/c/Projects/AutoLean/benchmarks/vendor/FATE"
            if native
            else PROJECT_ROOT / "benchmarks" / "vendor" / "FATE"
        ),
    )
    parser.add_argument(
        "--manifest",
        type=path_type,
        default=(
            "/mnt/c/Projects/AutoLean/benchmarks/results/fate-source-manifest.v1.json"
            if native
            else PROJECT_ROOT / "benchmarks" / "results" / "fate-source-manifest.v1.json"
        ),
    )
    parser.add_argument("--cache-root", required=True)
    parser.add_argument("--packages-root", required=True)
    parser.add_argument("--distribution", default=DEFAULT_WSL_DISTRIBUTION)


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("prepare", "audit", "run"):
        command = subparsers.add_parser(name)
        _add_common_arguments(command, native=False)
        if name in {"audit", "run"}:
            command.add_argument("--runtime-root", required=True)
        if name == "run":
            command.add_argument("--output", required=True, type=Path)
            command.add_argument(
                "--timeout-seconds",
                type=int,
                default=DEFAULT_TIMEOUT_SECONDS,
            )
    for name in ("_native-prepare", "_native-audit", "_native-run"):
        command = subparsers.add_parser(name, help=argparse.SUPPRESS)
        _add_common_arguments(command, native=True)
        if name in {"_native-audit", "_native-run"}:
            command.add_argument("--runtime-root", required=True)
        if name == "_native-run":
            command.add_argument("--output", required=True)
            command.add_argument(
                "--timeout-seconds",
                type=int,
                default=DEFAULT_TIMEOUT_SECONDS,
            )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    runner = SubprocessRunner()
    try:
        command = cast(str, args.command)
        if command == "_native-prepare":
            result = _native_prepare(args, runner)
            exit_code = 0
        elif command == "_native-audit":
            result = _native_audit(args, runner)
            exit_code = 0
        elif command == "_native-run":
            result, exit_code = _native_run(args, runner)
        else:
            result, exit_code = _host_dispatch(args, runner)
    except RuntimePreparationError as error:
        print(
            json.dumps(
                {
                    "schema_version": HOST_RESULT_SCHEMA,
                    "status": "blocked",
                    "error_code": error.code,
                },
                ensure_ascii=True,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
