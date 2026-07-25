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
    fixture = load_default_real_lean_project_dag()
    with tempfile.TemporaryDirectory(prefix="autolean-t7-preflight-") as raw_output:
        output_root = Path(raw_output)
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
        "fixture_manifest_sha256": fixture.manifest_sha256(),
        "compiled_modules": compiled_modules,
        "declaration_graph_reverse_closure_validated": True,
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
    validate = subparsers.add_parser(
        "validate", help="validate the byte-bound real Lean fixture"
    )
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
                "declaration_graph_reverse_closure_validated": True,
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
