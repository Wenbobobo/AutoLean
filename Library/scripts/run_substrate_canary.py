"""Compile and query the staged UniversalLK split in the pinned source-v2 worker.

The command deliberately builds an ext4 copy of the staging fixture inside
WSL, then mounts that copy into the existing digest-pinned source-v2 image.
It is an operator-local diagnostic: neither the copied source nor the
host-mounted query helper is part of an image-owned substrate receipt.

CI may invoke the explicit ``static`` command when Docker or the pinned image
is unavailable.  That fallback verifies the source/profile boundary and the
two candidate statements, but does *not* claim a Lean dependency observation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Final, NoReturn, TypedDict, cast

# A direct ``python Library/scripts/run_substrate_canary.py`` invocation gives
# Python only this script directory on ``sys.path``.  Keep that operator path
# working while using the repository-root namespace import that mypy can
# resolve under ``--explicit-package-bases``.
if __package__ in {None, ""}:
    repository_root = str(Path(__file__).resolve().parents[2])
    if repository_root not in sys.path:
        sys.path.insert(0, repository_root)

from Library.scripts.verify_substrate_fixture import (
    EXPECTED_CANDIDATES,
    FIXTURE_ROOT,
    MODULE_BY_NAME,
    SOUND_DECLARATION,
    SOURCE_V2_IMAGE,
    TARGET_DECLARATION,
    ValidatedProfileBoundary,
    check,
)

# Keep the distribution local to this script: the fixture checker is platform agnostic.
WSL_DISTRIBUTION: Final = "Ubuntu-24.04"
CANARY_SCHEMA: Final = "autolean.library-substrate-preflight-canary.v1"
HISTORICAL_TYPE_SHA256: Final = "66d1fe3cbd2a62831bf57b9761248bf3fa5d84b95879be25c7e591c48ebeef8a"
HISTORICAL_AXIOMS: Final = ("Classical.choice", "Quot.sound", "propext")


class CanaryError(RuntimeError):
    """The requested real diagnostic run could not complete."""


class DirectDependencyObservation(TypedDict):
    """Validated host-mounted query record used only by this local diagnostic."""

    authority: str
    candidate_owns_target: bool
    canonical_type: str
    declaration: str
    direct_proof_dependencies: tuple[str, ...]
    observed_axioms: tuple[str, ...]
    schema_version: str


def fail(message: str) -> NoReturn:
    raise CanaryError(message)


def _run(
    command: list[str], *, timeout: int, cwd: Path | None = None
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise CanaryError("subprocess failed") from error


def _sorted_unique_names(value: object, *, task_mode: str, field: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        fail(f"{task_mode} query {field} is invalid")
    names: list[str] = []
    for name in value:
        if not isinstance(name, str):
            fail(f"{task_mode} query {field} is invalid")
        names.append(name)
    if names != sorted(set(names)):
        fail(f"{task_mode} query {field} is not sorted and unique")
    return tuple(names)


def _parse_query(raw: str, *, task_mode: str) -> DirectDependencyObservation:
    lines = raw.splitlines()
    if len(lines) != 1:
        fail(f"{task_mode} query did not emit exactly one JSON record")
    try:
        raw_value: object = json.loads(lines[0])
    except json.JSONDecodeError as error:
        raise CanaryError(f"{task_mode} query did not emit JSON") from error
    if not isinstance(raw_value, dict) or any(not isinstance(key, str) for key in raw_value):
        fail(f"{task_mode} query output must be an object")
    value = cast(dict[str, object], raw_value)
    required = {
        "authority",
        "candidate_owns_target",
        "canonical_type",
        "declaration",
        "direct_proof_dependencies",
        "observed_axioms",
        "schema_version",
    }
    if set(value) != required:
        fail(f"{task_mode} query schema drifted")
    authority = value["authority"]
    if authority != "diagnostic-host-mounted-preflight-only":
        fail(f"{task_mode} query authority label drifted")
    schema_version = value["schema_version"]
    if schema_version != "autolean.library-substrate-direct-dependency-query.v2":
        fail(f"{task_mode} query protocol drifted")
    if value["candidate_owns_target"] is not True or value["declaration"] != TARGET_DECLARATION:
        fail(f"{task_mode} query did not establish Candidate ownership")
    canonical_type = value["canonical_type"]
    if not isinstance(canonical_type, str) or not canonical_type:
        fail(f"{task_mode} query canonical_type is invalid")
    direct_proof_dependencies = _sorted_unique_names(
        value["direct_proof_dependencies"],
        task_mode=task_mode,
        field="direct_proof_dependencies",
    )
    observed_axioms = _sorted_unique_names(
        value["observed_axioms"],
        task_mode=task_mode,
        field="observed_axioms",
    )
    return {
        "authority": authority,
        "candidate_owns_target": True,
        "canonical_type": canonical_type,
        "declaration": TARGET_DECLARATION,
        "direct_proof_dependencies": direct_proof_dependencies,
        "observed_axioms": observed_axioms,
        "schema_version": schema_version,
    }


def _validate_pair(
    observations: dict[str, DirectDependencyObservation],
) -> dict[str, object]:
    independent = observations["independent_reproof"]
    compositional = observations["compositional_bridge"]
    independent_direct = set(independent["direct_proof_dependencies"])
    compositional_direct = set(compositional["direct_proof_dependencies"])
    if SOUND_DECLARATION in independent_direct:
        fail("independent query directly depends on Deriv.sound")
    if SOUND_DECLARATION not in compositional_direct:
        fail("compositional query does not directly depend on Deriv.sound")
    independent_type = independent["canonical_type"]
    compositional_type = compositional["canonical_type"]
    if independent_type != compositional_type:
        fail("candidate queries do not have the same canonical target type")
    type_sha256 = hashlib.sha256(independent_type.encode("utf-8")).hexdigest()
    if type_sha256 != HISTORICAL_TYPE_SHA256:
        fail("split target canonical type differs from the retained T4 historical reference")
    independent_axioms = tuple(independent["observed_axioms"])
    compositional_axioms = tuple(compositional["observed_axioms"])
    if independent_axioms != compositional_axioms:
        fail("candidate queries do not have the same observed axiom set")
    if independent_axioms != HISTORICAL_AXIOMS:
        fail("split target observed axioms differ from the retained T4 historical reference")
    return {
        "canonical_type_sha256": type_sha256,
        "historical_reference": {
            "axioms_match": True,
            "source": "Builder/pilots/model-theory-admission/t4-declaration-query.v1.json",
            "type_match": True,
        },
    }


def _regular_tree_copy(source: Path, destination: Path) -> None:
    """Copy a regular-file tree without following or retaining links."""

    def copy_directory(current_source: Path, current_destination: Path) -> None:
        try:
            source_metadata = current_source.lstat()
        except OSError as error:
            raise CanaryError("staging fixture is unreadable") from error
        if stat.S_ISLNK(source_metadata.st_mode) or not stat.S_ISDIR(source_metadata.st_mode):
            fail("staging fixture root must be an unlinked directory")
        current_destination.mkdir()
        try:
            entries = tuple(os.scandir(current_source))
        except OSError as error:
            raise CanaryError("staging fixture directory is unreadable") from error
        for entry in entries:
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise CanaryError("staging fixture entry is unreadable") from error
            target = current_destination / entry.name
            if stat.S_ISLNK(metadata.st_mode):
                fail("staging fixture contains a symlink")
            if stat.S_ISDIR(metadata.st_mode):
                copy_directory(Path(entry.path), target)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                fail("staging fixture contains a non-regular entry")
            shutil.copy2(entry.path, target, follow_symlinks=False)
            if not stat.S_ISREG(target.lstat().st_mode):
                fail("staging fixture changed while creating the snapshot")

    copy_directory(source, destination)


def _require_ext4(path: Path) -> None:
    completed = _run(
        ["findmnt", "-n", "-o", "FSTYPE", "-T", str(path)],
        timeout=10,
    )
    if completed.stdout.strip() != "ext4":
        fail("real canary snapshot must reside on ext4")


def _module_source_relative(module: str) -> Path:
    return Path(MODULE_BY_NAME[module].path).relative_to("source")


def _materialize_runtime(
    snapshot_root: Path,
    workspace_root: Path,
    profile: ValidatedProfileBoundary,
) -> Path:
    """Create the profile-selected source view that is the only mounted tree."""

    runtime_root = workspace_root / "runtime" / profile.task_mode
    source_root = snapshot_root / "source"
    for module in profile.runtime_modules:
        source_relative = _module_source_relative(module)
        source = source_root / source_relative
        destination = runtime_root / source_relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    candidate = snapshot_root / profile.candidate_path
    shutil.copy2(candidate, runtime_root / "Candidate.lean")
    shutil.copy2(
        snapshot_root / "canary" / "DirectDependencyQuery.lean",
        runtime_root / "DirectDependencyQuery.lean",
    )
    return runtime_root


def _docker_base() -> list[str]:
    getuid = getattr(os, "getuid", None)
    getgid = getattr(os, "getgid", None)
    user = f"{getuid()}:{getgid()}" if callable(getuid) and callable(getgid) else "65532:65532"
    return [
        "docker",
        "run",
        "--rm",
        "--pull=never",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "128",
        "--memory",
        "2g",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=256m",
        "--tmpfs",
        "/work:rw,exec,nosuid,nodev,mode=1777,size=512m",
        "--user",
        user,
    ]


def _container_script(profile: ValidatedProfileBoundary) -> str:
    compile_lines = "\n".join(
        "lean -o /work/"
        f"{_module_source_relative(module).with_suffix('.olean').as_posix()} "
        f"/work/{_module_source_relative(module).as_posix()}"
        for module in profile.runtime_modules
    )
    reject_lines = "\n".join(
        line
        for module in profile.forbidden_modules
        for line in (
            f"printf 'import {module}\\n' > /work/ForbiddenImport.lean",
            "if lean /work/ForbiddenImport.lean >/dev/null 2>&1; then",
            f"  echo 'forbidden runtime module unexpectedly imported: {module}' >&2",
            "  exit 31",
            "fi",
        )
    )
    return "\n".join(
        (
            "set -eu",
            "cp -R /fixture/AutoLeanLibrary /work/",
            "cp /fixture/Candidate.lean /work/Candidate.lean",
            "cp /fixture/DirectDependencyQuery.lean /work/DirectDependencyQuery.lean",
            'export LEAN_PATH="/compiled:/work:$(cat /opt/autolean/environment/lean-path)"',
            compile_lines,
            reject_lines,
            "lean -o /compiled/Candidate.olean /work/Candidate.lean",
            "lean --run /work/DirectDependencyQuery.lean",
        )
    )


def _run_one_real(
    snapshot_root: Path,
    workspace_root: Path,
    profile: ValidatedProfileBoundary,
) -> DirectDependencyObservation:
    runtime_root = _materialize_runtime(snapshot_root, workspace_root, profile)
    compiled = workspace_root / "compiled" / profile.task_mode
    compiled.mkdir(parents=True, mode=0o777)
    command = [
        *_docker_base(),
        "--mount",
        f"type=bind,src={runtime_root},dst=/fixture,readonly",
        "--mount",
        f"type=bind,src={compiled},dst=/compiled",
        "--entrypoint",
        "/bin/sh",
        SOURCE_V2_IMAGE,
        "-eu",
        "-c",
        _container_script(profile),
    ]
    completed = _run(command, timeout=240)
    return _parse_query(completed.stdout, task_mode=profile.task_mode)


def _docker_available() -> tuple[bool, str]:
    if shutil.which("docker") is None:
        return False, "docker_unavailable"
    completed = subprocess.run(
        ["docker", "image", "inspect", SOURCE_V2_IMAGE],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    if completed.returncode == 0:
        return True, "available"
    message = (completed.stderr + completed.stdout).lower()
    if "no such image" in message or "not found" in message:
        return False, "pinned_image_unavailable"
    fail("docker is present but cannot inspect the pinned image")


def static_fallback(reason: str) -> dict[str, object]:
    check()
    return {
        "authority": "static-structural-preflight-only",
        "fallback_reason": reason,
        "image_inspected": False,
        "intended_parent_image": SOURCE_V2_IMAGE,
        "mode": "static_fallback",
        "non_claims": [
            "no_lean_compile_observation",
            "no_library_substrate_image",
            "no_proof_admission",
        ],
        "schema_version": CANARY_SCHEMA,
    }


def real_canary() -> dict[str, object]:
    available, reason = _docker_available()
    if not available:
        fail(f"real WSL/ext4 canary requires Docker and the pinned image ({reason})")
    with tempfile.TemporaryDirectory(prefix="autolean-library-substrate-", dir="/tmp") as temporary:
        temporary_root = Path(temporary)
        _require_ext4(temporary_root)
        snapshot_root = temporary_root / "fixture-snapshot"
        workspace_root = temporary_root / "workspace"
        _regular_tree_copy(FIXTURE_ROOT, snapshot_root)
        profiles = check(snapshot_root)
        observations = {
            mode: _run_one_real(snapshot_root, workspace_root, profiles[mode])
            for mode in EXPECTED_CANDIDATES
        }
    comparison = _validate_pair(observations)
    return {
        "authority": "operator-local-diagnostic-only",
        "image": SOURCE_V2_IMAGE,
        "mode": "real_wsl_ext4_lean",
        "non_claims": [
            "no_image_owned_substrate_receipt",
            "no_proof_admission",
            "no_transitive_dependency_or_type_collision_gate",
        ],
        "observations": observations,
        "pair_validation": comparison,
        "schema_version": CANARY_SCHEMA,
    }


def _wsl_path(path: Path) -> str:
    completed = _run(
        ["wsl.exe", "-d", WSL_DISTRIBUTION, "-e", "wslpath", "-a", str(path)],
        timeout=20,
    )
    translated = completed.stdout.strip()
    if not translated:
        fail("WSL path translation returned an empty path")
    return translated


def _delegate_to_wsl(arguments: argparse.Namespace) -> int:
    script = Path(__file__).resolve()
    command = [
        "wsl.exe",
        "-d",
        WSL_DISTRIBUTION,
        "--cd",
        _wsl_path(script.parents[2]),
        "--",
        "python3",
        _wsl_path(script),
        "canary",
        "--native",
    ]
    return subprocess.run(command, check=False).returncode


def parse_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    canary = subparsers.add_parser("canary", help="run the real WSL/ext4 Lean canary")
    canary.add_argument("--native", action="store_true", help=argparse.SUPPRESS)
    fallback = subparsers.add_parser("static", help="run only the CI-safe static fallback")
    fallback.add_argument("--reason", default="explicit_static_request")
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    parsed = parse_arguments(arguments)
    try:
        if parsed.command == "static":
            result = static_fallback(parsed.reason)
        elif os.name == "nt" and not parsed.native:
            return _delegate_to_wsl(parsed)
        else:
            result = real_canary()
        print(json.dumps(result, ensure_ascii=True, sort_keys=True))
        return 0
    except CanaryError as error:
        print(f"library-substrate-canary: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
