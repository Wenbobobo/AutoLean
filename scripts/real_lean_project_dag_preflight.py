"""Run the isolated real-Lean project-DAG fixture against the pinned source-v2 image.

The command is an operator-local T7 *preflight*.  It validates a separately versioned
20-declaration fixture and asks the already-built source-v2 image to compile its four
Lean modules from a read-only source mount into a fresh output mount.  Its result is
diagnostic only: it is not a T7 acceptance result and does not create provider, OCI
verifier, lease, contract, or gateway evidence.
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
import tempfile
from collections.abc import Sequence
from pathlib import Path, PurePosixPath
from typing import Final

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.real_lean_project_dag import (  # noqa: I001
    RealLeanProjectDagV1,
    load_default_real_lean_project_dag,
    load_real_lean_project_dag,
)


SOURCE_V2_IMAGE: Final[str] = (
    "autolean/mathlib-worker@sha256:"
    "3237192cf627a05367c75d46e61ec9034fefe43a4fd0c06139e38c80358648d6"
)
RESULT_SCHEMA: Final[str] = "autolean.real-lean-project-dag-preflight-clean-build.v1"
DEFAULT_WSL_DISTRIBUTION: Final[str] = "Ubuntu-24.04"
_SAFE_DISTRIBUTION = re.compile(r"^[A-Za-z0-9_.-]+$")


class RealLeanProjectDagPreflightError(RuntimeError):
    """The local source-v2 preflight could not establish its limited result."""


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _snapshot_fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    fingerprint = (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
    )
    if os.name == "nt":
        return fingerprint
    return (*fingerprint, metadata.st_ctime_ns)


def _fixture_regular_file(source: Path, fixture_root: Path, *, label: str) -> Path:
    """Return one non-link fixture file that resolves inside the fixture root."""

    root = fixture_root.resolve()
    raw_source = source if source.is_absolute() else root / source
    try:
        raw_source.relative_to(root)
    except ValueError as error:
        raise RealLeanProjectDagPreflightError(f"{label} escapes the fixture root") from error
    try:
        metadata = raw_source.lstat()
    except OSError as error:
        raise RealLeanProjectDagPreflightError(f"{label} is unavailable") from error
    if raw_source.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise RealLeanProjectDagPreflightError(f"{label} must be a regular non-symlink file")
    resolved = raw_source.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise RealLeanProjectDagPreflightError(f"{label} escapes the fixture root") from error
    return resolved


def _snapshot_regular_file(source: Path, destination: Path, *, label: str) -> None:
    """Copy one stable regular file with exclusive creation into the fresh snapshot."""

    try:
        metadata = source.lstat()
    except OSError as error:
        raise RealLeanProjectDagPreflightError(f"{label} is unavailable") from error
    if source.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise RealLeanProjectDagPreflightError(f"{label} must be a regular non-symlink file")
    try:
        with source.open("rb") as source_stream:
            before = os.fstat(source_stream.fileno())
            if _snapshot_fingerprint(before) != _snapshot_fingerprint(metadata):
                raise RealLeanProjectDagPreflightError(f"{label} changed before snapshot")
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("xb") as destination_stream:
                while chunk := source_stream.read(1024 * 1024):
                    destination_stream.write(chunk)
                destination_stream.flush()
                os.fsync(destination_stream.fileno())
            after = os.fstat(source_stream.fileno())
    except OSError as error:
        raise RealLeanProjectDagPreflightError(f"{label} snapshot failed") from error
    if _snapshot_fingerprint(before) != _snapshot_fingerprint(after):
        raise RealLeanProjectDagPreflightError(f"{label} changed during snapshot")
    try:
        snapshot_metadata = destination.lstat()
    except OSError as error:
        raise RealLeanProjectDagPreflightError(f"{label} snapshot is unavailable") from error
    if destination.is_symlink() or not stat.S_ISREG(snapshot_metadata.st_mode):
        raise RealLeanProjectDagPreflightError(f"{label} snapshot is not a regular file")
    if snapshot_metadata.st_size != metadata.st_size:
        raise RealLeanProjectDagPreflightError(f"{label} snapshot size differs from source")
    destination.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)


def _snapshot_fixture(fixture: RealLeanProjectDagV1, snapshot_root: Path) -> RealLeanProjectDagV1:
    """Copy only the manifest and its bound sources, then revalidate that copy."""

    fixture_root = fixture.root.resolve()
    manifest = _fixture_regular_file(
        fixture.manifest_path, fixture_root, label="real Lean fixture manifest"
    )
    snapshot_root.mkdir(mode=0o700)
    snapshot_manifest = snapshot_root / manifest.relative_to(fixture_root)
    _snapshot_regular_file(manifest, snapshot_manifest, label="real Lean fixture manifest")
    for module in fixture.module_topological_order():
        source = _fixture_regular_file(
            fixture.source_path(module), fixture_root, label=f"Lean source {module.module}"
        )
        destination = snapshot_root / Path(*PurePosixPath(module.file).parts)
        _snapshot_regular_file(source, destination, label=f"Lean source {module.module}")
    return load_real_lean_project_dag(snapshot_manifest)


def _canonical_json(document: object) -> bytes:
    rendered = json.dumps(document, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return (rendered + "\n").encode("utf-8")


def _safe_wsl_distribution(value: str) -> str:
    if _SAFE_DISTRIBUTION.fullmatch(value) is None:
        raise RealLeanProjectDagPreflightError("WSL distribution name is invalid")
    return value


def _is_windows_host() -> bool:
    return platform.system() == "Windows"


def _run(command: Sequence[str], *, timeout_seconds: int) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            list(command),
            check=False,
            shell=False,
            capture_output=True,
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RealLeanProjectDagPreflightError("local source-v2 command could not run") from error


def _wsl_path(path: Path, distribution: str) -> str:
    result = _run(
        (
            "wsl.exe",
            "--distribution",
            _safe_wsl_distribution(distribution),
            "--exec",
            "/usr/bin/wslpath",
            "-a",
            "-u",
            str(path.resolve()),
        ),
        timeout_seconds=30,
    )
    if result.returncode != 0:
        raise RealLeanProjectDagPreflightError("Windows path could not be mapped into WSL")
    try:
        mapped = result.stdout.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise RealLeanProjectDagPreflightError("mapped WSL path is not UTF-8") from error
    pure = PurePosixPath(mapped)
    if not pure.is_absolute() or ".." in pure.parts or "\n" in mapped:
        raise RealLeanProjectDagPreflightError("mapped WSL path is invalid")
    return pure.as_posix()


def _docker_prefix(distribution: str) -> tuple[str, ...]:
    if _is_windows_host():
        return (
            "wsl.exe",
            "--distribution",
            _safe_wsl_distribution(distribution),
            "--exec",
            "/usr/bin/docker",
        )
    return ("docker",)


def _container_path(path: Path, distribution: str) -> str:
    if _is_windows_host():
        return _wsl_path(path, distribution)
    return str(path.resolve())


def _module_output_relative(module_name: str) -> PurePosixPath:
    return PurePosixPath(*module_name.split(".")).with_suffix(".olean")


def _compile_script(fixture: RealLeanProjectDagV1) -> str:
    commands = [
        "set -eu",
        'lean_path="$(cat /opt/autolean/environment/lean-path)"',
        'export LEAN_PATH="${lean_path}:/output"',
    ]
    for module in fixture.module_topological_order():
        source_relative = PurePosixPath(module.file).relative_to(fixture.source_root)
        output_relative = _module_output_relative(module.module)
        source = PurePosixPath("/input") / source_relative
        output = PurePosixPath("/output") / output_relative
        commands.extend(
            (
                f"mkdir -p {output.parent.as_posix()}",
                f"lean -R /input -o {output.as_posix()} {source.as_posix()}",
                f"test -s {output.as_posix()}",
            )
        )
    return "\n".join(commands)


def docker_clean_build_command(
    fixture: RealLeanProjectDagV1,
    output_root: Path,
    *,
    distribution: str = DEFAULT_WSL_DISTRIBUTION,
) -> tuple[str, ...]:
    """Build a fixed source-v2 command without granting the container source writes."""

    source_root = fixture.root / fixture.source_root
    source_mount = _container_path(source_root, distribution)
    output_mount = _container_path(output_root, distribution)
    return (
        *_docker_prefix(distribution),
        "run",
        "--pull=never",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=64m",
        "--mount",
        f"type=bind,src={source_mount},dst=/input,readonly",
        "--mount",
        f"type=bind,src={output_mount},dst=/output",
        SOURCE_V2_IMAGE,
        "/bin/sh",
        "-ceu",
        _compile_script(fixture),
    )


def clean_build(
    *,
    distribution: str = DEFAULT_WSL_DISTRIBUTION,
    timeout_seconds: int = 300,
) -> dict[str, object]:
    """Compile the fixture with source-v2; return a non-promotable local diagnostic."""

    if not 1 <= timeout_seconds <= 600:
        raise RealLeanProjectDagPreflightError("timeout must be between 1 and 600 seconds")
    live_fixture = load_default_real_lean_project_dag()
    with tempfile.TemporaryDirectory(prefix="autolean-t7-preflight-") as raw_workspace:
        workspace_root = Path(raw_workspace)
        fixture = _snapshot_fixture(live_fixture, workspace_root / "fixture-snapshot")
        fixture_manifest_sha256 = fixture.manifest_sha256()
        output_root = workspace_root / "output"
        output_root.mkdir(mode=0o700)
        output_root.chmod(stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
        command = docker_clean_build_command(fixture, output_root, distribution=distribution)
        result = _run(command, timeout_seconds=timeout_seconds)
        if result.returncode != 0:
            raise RealLeanProjectDagPreflightError("source-v2 Lean clean build failed")
        compiled_modules: list[dict[str, str]] = []
        for module in fixture.module_topological_order():
            output = output_root / _module_output_relative(module.module)
            if output.is_symlink() or not output.is_file() or output.stat().st_size == 0:
                raise RealLeanProjectDagPreflightError(
                    "source-v2 clean build did not emit a regular OLean"
                )
            compiled_modules.append({"module": module.module, "olean_sha256": _sha256(output)})
    payload: dict[str, object] = {
        "schema_version": RESULT_SCHEMA,
        "status": "passed",
        "scope": "t7_preflight_only",
        "acceptance_result": False,
        "image": SOURCE_V2_IMAGE,
        "fixture_manifest_sha256": fixture_manifest_sha256,
        "compiled_modules": compiled_modules,
        "declared_content_graph_reverse_closure_validated": True,
        "changed_source_recompiled": False,
        "network_accessed_by_container": False,
        "provider_evidence_created": False,
        "oci_verifier_evidence_created": False,
        "lease_evidence_created": False,
    }
    return payload


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate", help="validate the byte-bound real Lean fixture")
    validate.add_argument(
        "--json", action="store_true", help="render a canonical diagnostic record"
    )
    build = subparsers.add_parser(
        "clean-build",
        help="operator-local T7 preflight only; compile against the pinned source-v2 image",
    )
    build.add_argument("--distribution", default=DEFAULT_WSL_DISTRIBUTION)
    build.add_argument("--timeout-seconds", type=int, default=300)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        if args.command == "validate":
            fixture = load_default_real_lean_project_dag()
            result: dict[str, object] = {
                "schema_version": "autolean.real-lean-project-dag-preflight-validation.v1",
                "status": "passed",
                "scope": "t7_preflight_only",
                "acceptance_result": False,
                "fixture_manifest_sha256": fixture.manifest_sha256(),
                "module_count": len(fixture.modules),
                "declaration_count": len(fixture.declarations),
                "declared_content_graph_reverse_closure_validated": True,
                "changed_source_recompiled": False,
            }
            if args.json:
                print(_canonical_json(result).decode("utf-8"), end="")
            else:
                print("T7 preflight fixture is byte-bound and structurally valid.")
            return 0
        result = clean_build(
            distribution=args.distribution,
            timeout_seconds=args.timeout_seconds,
        )
    except RealLeanProjectDagPreflightError as error:
        print(f"real-lean-project-dag-preflight: {error}", file=sys.stderr)
        return 2
    print(_canonical_json(result).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
