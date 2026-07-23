"""Run the answer-free FATE agent-smoke-8 static tactic probe in a locked-down OCI process.

This is a non-promotable Wave 1 bridge. It reuses the audited ext4 FATE/mathlib runtime as a
read-only dependency mount and the already pinned pure-Lean image as the execution base. The
report cannot be promoted because mathlib was not rebuilt inside that image and no signing
gateway request is made.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Final, cast

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from benchmarks.fate_smoke import (  # noqa: E402
    TYPE_FORMAT,
    WRAPPER_PROTOCOL,
    FateSmokeError,
    FateSmokeObservation,
    FateSmokeRuntimeEvidenceV1,
    execute_static_smoke,
    load_verified_smoke_fixture,
    report_envelope,
    write_report_exclusive,
)
from scripts.fate_wsl_runtime import (  # noqa: E402
    RuntimePreparationError,
    SubprocessRunner,
    _runtime_paths,
    audit_runtime,
    build_runtime_expectation,
)

WSL_DISTRIBUTION: Final = "Ubuntu-24.04"
IMAGE_REPOSITORY_DIGEST: Final = (
    "autolean/lean-worker@sha256:d69da80fa5c1b9f921cda33bb37376114e9e15e7238eff513d8b6a340e55bcc0"
)
IMAGE_DIGEST: Final = "sha256:d69da80fa5c1b9f921cda33bb37376114e9e15e7238eff513d8b6a340e55bcc0"
IMAGE_ID: Final = "sha256:d69da80fa5c1b9f921cda33bb37376114e9e15e7238eff513d8b6a340e55bcc0"
COMMAND_POLICY_ID: Final = "autolean.fate-readonly-mounted-mathlib-oci.v1"
MINIMAL_WSL_PATH: Final = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
EXPECTED_DEPENDENCIES: Final = (
    "Cli",
    "LeanSearchClient",
    "Qq",
    "aesop",
    "batteries",
    "importGraph",
    "mathlib",
    "plausible",
    "proofwidgets",
)
EXPECTED_ABSENT_BUILD_ROOTS: Final = frozenset({"Cli"})
_SAFE_DISTRIBUTION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SAFE_TASK = re.compile(r"^FATE-M-[1-9][0-9]*$")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _hash_file(path: Path, code: str) -> str:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            raise FateSmokeError(code)
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()
    except OSError as error:
        raise FateSmokeError(code) from error


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def _runtime_state_matches(observed: bytes, expected: bytes) -> bool:
    """Accept the managed runtime's legacy single trailing LF, and nothing else."""

    return observed == expected or observed == expected + b"\n"


def _build_tree_commitment(packages_root: Path) -> tuple[str, int]:
    """Commit every regular file Lean can resolve below the nine mounted build trees."""

    entries: list[dict[str, object]] = []
    try:
        inventory = {entry.name: entry for entry in packages_root.iterdir()}
    except OSError as error:
        raise FateSmokeError("smoke_dependency_build_tree_unreadable") from error
    if set(inventory) != set(EXPECTED_DEPENDENCIES):
        raise FateSmokeError("smoke_dependency_build_inventory_drift")
    for dependency in EXPECTED_DEPENDENCIES:
        build_root = inventory[dependency] / ".lake" / "build" / "lib" / "lean"
        try:
            metadata = build_root.lstat()
        except OSError as error:
            if dependency not in EXPECTED_ABSENT_BUILD_ROOTS:
                raise FateSmokeError("smoke_dependency_build_tree_missing") from error
            entries.append(
                {
                    "dependency": dependency,
                    "path": None,
                    "size": 0,
                    "sha256": None,
                }
            )
            continue
        if dependency in EXPECTED_ABSENT_BUILD_ROOTS:
            raise FateSmokeError("smoke_dependency_build_inventory_drift")
        if not stat.S_ISDIR(metadata.st_mode) or build_root.is_symlink():
            raise FateSmokeError("smoke_dependency_build_tree_missing")
        for directory, names, files in os.walk(build_root, followlinks=False):
            current = Path(directory)
            for name in names:
                if (current / name).is_symlink():
                    raise FateSmokeError("smoke_dependency_build_tree_contains_link")
            for name in files:
                candidate = current / name
                try:
                    file_metadata = candidate.lstat()
                except OSError as error:
                    raise FateSmokeError("smoke_dependency_build_tree_unreadable") from error
                if not stat.S_ISREG(file_metadata.st_mode) or candidate.is_symlink():
                    raise FateSmokeError("smoke_dependency_build_tree_contains_non_regular")
                relative = candidate.relative_to(build_root).as_posix()
                entries.append(
                    {
                        "dependency": dependency,
                        "path": relative,
                        "size": file_metadata.st_size,
                        "sha256": _hash_file(
                            candidate,
                            "smoke_dependency_build_tree_unreadable",
                        ),
                    }
                )
    entries.sort(key=lambda item: (cast(str, item["dependency"]), cast(str, item["path"])))
    if not entries:
        raise FateSmokeError("smoke_dependency_build_tree_empty")
    file_count = sum(item["path"] is not None for item in entries)
    return _sha256(_canonical_json(entries)), file_count


def _command_policy(wrapper_sha256: str, helper_sha256: str) -> dict[str, object]:
    return {
        "policy_id": COMMAND_POLICY_ID,
        "image": IMAGE_REPOSITORY_DIGEST,
        "entrypoint": ["/bin/sh", "/verifier/autolean-fate-wrapper"],
        "wrapper_protocol": WRAPPER_PROTOCOL,
        "type_format": TYPE_FORMAT,
        "network": "none",
        "root_filesystem": "read_only",
        "mounts": {
            "candidate": "read_only",
            "dependencies": "read_only",
            "verifier": "read_only",
        },
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges"],
        "user": "65532:65532",
        "pids_limit": 512,
        "memory_bytes": 12 * 1024 * 1024 * 1024,
        "cpus": 4,
        "tmpfs": "/tmp:rw,noexec,nosuid,nodev,size=256m",
        "stdin": "null",
        "stdout": "wrapper_json_hashed_then_redacted",
        "stderr": "sha256_and_byte_count_only",
        "wrapper_sha256": wrapper_sha256,
        "query_helper_sha256": helper_sha256,
    }


def _minimal_environment() -> dict[str, str]:
    return {
        "HOME": "/tmp",
        "PATH": MINIMAL_WSL_PATH,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }


def _run(
    argv: tuple[str, ...],
    *,
    timeout_seconds: int,
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            argv,
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout_seconds,
            env=_minimal_environment(),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise FateSmokeError("smoke_preflight_command_failed") from error


def _inspect_image() -> None:
    completed = _run(
        ("/usr/bin/docker", "image", "inspect", IMAGE_REPOSITORY_DIGEST),
        timeout_seconds=60,
    )
    if completed.returncode != 0:
        raise FateSmokeError("smoke_pinned_image_unavailable")
    try:
        raw = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FateSmokeError("smoke_pinned_image_inspect_invalid") from error
    if not isinstance(raw, list) or len(raw) != 1 or not isinstance(raw[0], dict):
        raise FateSmokeError("smoke_pinned_image_inspect_invalid")
    image = cast(dict[str, object], raw[0])
    repo_digests = image.get("RepoDigests")
    if image.get("Id") != IMAGE_ID or not isinstance(repo_digests, list):
        raise FateSmokeError("smoke_pinned_image_identity_mismatch")
    if IMAGE_REPOSITORY_DIGEST not in repo_digests:
        raise FateSmokeError("smoke_pinned_image_identity_mismatch")


class OciMountedMathlibCompiler:
    """Execute one hash-bound candidate with no network and no writable dependency path."""

    def __init__(
        self,
        *,
        cache_root: Path,
        packages_root: Path,
        verifier_root: Path,
        command_policy_sha256: str,
    ) -> None:
        self._workspace_root = cache_root / "fate-smoke-workspaces"
        self._workspace_root.mkdir(mode=0o755, parents=True, exist_ok=True)
        if self._workspace_root.is_symlink() or not self._workspace_root.is_dir():
            raise FateSmokeError("smoke_workspace_root_invalid")
        self._packages_root = packages_root
        self._verifier_root = verifier_root
        self._command_policy_sha256 = command_policy_sha256

    def compile(
        self,
        candidate: object,
        *,
        timeout_seconds: int,
    ) -> FateSmokeObservation:
        from benchmarks.fate_adapter import FatePatchedSourceV1

        if not isinstance(candidate, FatePatchedSourceV1):
            raise FateSmokeError("smoke_candidate_type_invalid")
        task_id = candidate.task.task_id
        if _SAFE_TASK.fullmatch(task_id) is None:
            raise FateSmokeError("smoke_candidate_task_invalid")
        container_name = f"autolean-smoke-{task_id.lower()}-{secrets.token_hex(8)}"
        command_commitment = _sha256(
            _canonical_json(
                {
                    "command_policy_sha256": self._command_policy_sha256,
                    "task_id": task_id,
                    "candidate_sha256": candidate.candidate_sha256,
                    "declaration": candidate.task.target.qualified_name,
                }
            )
        )
        with tempfile.TemporaryDirectory(
            prefix=f"{task_id}-",
            dir=self._workspace_root,
        ) as temporary:
            workspace = Path(temporary)
            workspace.chmod(0o755)
            source = workspace / "Candidate.lean"
            descriptor = os.open(
                source,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o444,
            )
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(candidate.source)
                    handle.flush()
                    os.fsync(handle.fileno())
            except OSError as error:
                source.unlink(missing_ok=True)
                raise FateSmokeError("smoke_candidate_write_failed") from error
            argv = (
                "/usr/bin/docker",
                "run",
                "--name",
                container_name,
                "--rm",
                "--network",
                "none",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                "512",
                "--memory",
                "12g",
                "--cpus",
                "4",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=256m",
                "--user",
                "65532:65532",
                "--mount",
                f"type=bind,src={source},dst=/input/Candidate.lean,readonly",
                "--mount",
                f"type=bind,src={self._packages_root},dst=/deps/packages,readonly",
                "--mount",
                f"type=bind,src={self._verifier_root},dst=/verifier,readonly",
                "--workdir",
                "/work",
                "--entrypoint",
                "/bin/sh",
                IMAGE_REPOSITORY_DIGEST,
                "/verifier/autolean-fate-wrapper",
                "--protocol",
                WRAPPER_PROTOCOL,
                "--candidate",
                "/input/Candidate.lean",
                "--declaration",
                candidate.task.target.qualified_name,
                "--type-format",
                TYPE_FORMAT,
            )
            started = time.monotonic()
            try:
                completed = subprocess.run(
                    argv,
                    check=False,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    timeout=timeout_seconds,
                    env=_minimal_environment(),
                )
            except subprocess.TimeoutExpired as error:
                elapsed = time.monotonic() - started
                cleanup = subprocess.run(
                    (
                        "/usr/bin/docker",
                        "rm",
                        "--force",
                        container_name,
                    ),
                    check=False,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    timeout=30,
                    env=_minimal_environment(),
                )
                if cleanup.returncode != 0:
                    raise FateSmokeError("smoke_timed_out_container_cleanup_failed") from error
                return FateSmokeObservation(
                    returncode=None,
                    stdout=error.stdout or b"",
                    stderr=error.stderr or b"",
                    elapsed_seconds=elapsed,
                    command_sha256=command_commitment,
                    timed_out=True,
                )
            except OSError as error:
                raise FateSmokeError("smoke_docker_command_unavailable") from error
            return FateSmokeObservation(
                returncode=completed.returncode,
                stdout=completed.stdout,
                stderr=completed.stderr,
                elapsed_seconds=time.monotonic() - started,
                command_sha256=command_commitment,
            )


def _require_native_wsl() -> None:
    if platform.system() != "Linux":
        raise FateSmokeError("smoke_native_linux_required")
    try:
        kernel = Path("/proc/sys/kernel/osrelease").read_text(encoding="ascii").lower()
    except (OSError, UnicodeDecodeError) as error:
        raise FateSmokeError("smoke_kernel_probe_failed") from error
    if "microsoft" not in kernel:
        raise FateSmokeError("smoke_native_wsl_required")


def _native_run(args: argparse.Namespace) -> dict[str, object]:
    _require_native_wsl()
    checkout = PROJECT_ROOT / "benchmarks" / "vendor" / "FATE"
    source_manifest = PROJECT_ROOT / "benchmarks" / "results" / "fate-source-manifest.v1.json"
    split_manifest = PROJECT_ROOT / "benchmarks" / "fate-splits.v1.json"
    verifier_root = PROJECT_ROOT / "Prover" / "worker" / "fate"
    if set(entry.name for entry in verifier_root.iterdir()) != {
        "AutoleanFateQuery.lean",
        "autolean-fate-wrapper",
    }:
        raise FateSmokeError("smoke_verifier_inventory_drift")
    cache_root = Path(cast(str, args.cache_root))
    packages_root = Path(cast(str, args.packages_root))
    runtime_root = Path(cast(str, args.runtime_root))
    output = Path(cast(str, args.output))

    expectation = build_runtime_expectation(checkout, source_manifest)
    expected_paths = _runtime_paths(
        cache_root,
        packages_root,
        expectation.fixture.root_commit,
    )
    if (
        expected_paths.runtime_root.resolve() != runtime_root.resolve()
        or expected_paths.packages_root.resolve() != packages_root.resolve()
    ):
        raise FateSmokeError("smoke_managed_runtime_path_drift")
    audit = audit_runtime(
        checkout=checkout,
        manifest_path=source_manifest,
        paths=expected_paths,
        runner=SubprocessRunner(),
    )
    expected_state = _canonical_json(expectation.state)
    try:
        state_bytes = expected_paths.state_path.read_bytes()
    except OSError as error:
        raise FateSmokeError("smoke_runtime_state_unreadable") from error
    if not _runtime_state_matches(state_bytes, expected_state):
        raise FateSmokeError("smoke_runtime_state_drift")

    _inspect_image()
    wrapper = verifier_root / "autolean-fate-wrapper"
    helper = verifier_root / "AutoleanFateQuery.lean"
    wrapper_sha256 = _hash_file(wrapper, "smoke_wrapper_unreadable")
    helper_sha256 = _hash_file(helper, "smoke_query_helper_unreadable")
    policy = _command_policy(wrapper_sha256, helper_sha256)
    policy_sha256 = _sha256(_canonical_json(policy))
    build_tree_sha256, build_file_count = _build_tree_commitment(packages_root)

    adapter, fixture = load_verified_smoke_fixture(
        runtime_root,
        source_manifest,
        split_manifest,
    )
    runtime_evidence = FateSmokeRuntimeEvidenceV1(
        image_digest=IMAGE_DIGEST,
        image_id=IMAGE_ID,
        runtime_state_sha256=expectation.state_sha256,
        runtime_audit_sha256=cast(str, audit["audit_sha256"]),
        dependency_graph_sha256=cast(str, expectation.state["dependency_graph_sha256"]),
        dependency_build_tree_sha256=build_tree_sha256,
        dependency_count=len(expectation.shared_dependencies),
        wrapper_sha256=wrapper_sha256,
        query_helper_sha256=helper_sha256,
        command_policy_id=COMMAND_POLICY_ID,
        command_policy_sha256=policy_sha256,
    )
    compiler = OciMountedMathlibCompiler(
        cache_root=cache_root,
        packages_root=packages_root,
        verifier_root=verifier_root,
        command_policy_sha256=policy_sha256,
    )
    report = execute_static_smoke(
        fixture=fixture,
        adapter=adapter,
        checkout=runtime_root,
        runtime_evidence=runtime_evidence,
        compiler=compiler,
        timeout_seconds=cast(int, args.timeout_seconds),
    )

    after_build_tree_sha256, after_file_count = _build_tree_commitment(packages_root)
    if (
        after_build_tree_sha256 != build_tree_sha256
        or after_file_count != build_file_count
        or _hash_file(wrapper, "smoke_wrapper_unreadable") != wrapper_sha256
        or _hash_file(helper, "smoke_query_helper_unreadable") != helper_sha256
    ):
        raise FateSmokeError("smoke_execution_inputs_changed_during_run")
    cast(dict[str, object], report["runtime"])["dependency_build_file_count"] = build_file_count
    envelope = report_envelope(report)
    written = write_report_exclusive(
        output,
        envelope,
        forbidden_root=runtime_root,
    )
    del written
    return {
        "schema_version": "autolean.fate-agent-smoke-result.v1",
        "status": "completed",
        "report_sha256": envelope["report_sha256"],
        "proof_search_executed": True,
        "model_or_agent_executed": False,
        "promotable": False,
        "tiers": {
            tier: cast(dict[str, object], cast(dict[str, object], report["tiers"])[tier])["summary"]
            for tier in ("M", "H", "X")
        },
    }


def _map_windows_path(distribution: str, path: Path) -> str:
    try:
        completed = subprocess.run(
            (
                "wsl.exe",
                "--distribution",
                distribution,
                "--exec",
                "/usr/bin/wslpath",
                "-a",
                "-u",
                str(path.resolve()),
            ),
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise FateSmokeError("smoke_wsl_path_mapping_failed") from error
    if completed.returncode != 0:
        raise FateSmokeError("smoke_wsl_path_mapping_failed")
    try:
        value = completed.stdout.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise FateSmokeError("smoke_wsl_path_mapping_failed") from error
    if not value.startswith("/") or "\x00" in value or "\n" in value:
        raise FateSmokeError("smoke_wsl_path_mapping_failed")
    return value


def _host_dispatch(args: argparse.Namespace) -> int:
    if platform.system() != "Windows":
        raise FateSmokeError("smoke_windows_dispatch_required")
    distribution = cast(str, args.distribution)
    if _SAFE_DISTRIBUTION.fullmatch(distribution) is None:
        raise FateSmokeError("smoke_wsl_distribution_invalid")
    script = _map_windows_path(distribution, Path(__file__))
    output = _map_windows_path(distribution, cast(Path, args.output))
    command = (
        "wsl.exe",
        "--distribution",
        distribution,
        "--exec",
        "/usr/bin/env",
        "-i",
        "HOME=/tmp",
        f"PATH={MINIMAL_WSL_PATH}",
        "LANG=C.UTF-8",
        "LC_ALL=C.UTF-8",
        "PYTHONDONTWRITEBYTECODE=1",
        "/usr/bin/python3",
        script,
        "--native",
        "--cache-root",
        cast(str, args.cache_root),
        "--packages-root",
        cast(str, args.packages_root),
        "--runtime-root",
        cast(str, args.runtime_root),
        "--output",
        output,
        "--timeout-seconds",
        str(cast(int, args.timeout_seconds)),
    )
    try:
        completed = subprocess.run(
            command,
            check=False,
            stdin=subprocess.DEVNULL,
            timeout=4 * 60 * 60,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise FateSmokeError("smoke_native_wsl_run_failed") from error
    return completed.returncode


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-root", required=True)
    parser.add_argument("--packages-root", required=True)
    parser.add_argument("--runtime-root", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--timeout-seconds", type=int, default=600)
    parser.add_argument("--distribution", default=WSL_DISTRIBUTION)
    parser.add_argument("--native", action="store_true", help=argparse.SUPPRESS)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    if not 1 <= args.timeout_seconds <= 1800:
        payload = {
            "schema_version": "autolean.fate-agent-smoke-result.v1",
            "status": "failed",
            "error": "smoke_timeout_invalid",
        }
        print(_canonical_json(payload).decode("ascii"))
        return 2
    if not args.native:
        try:
            return _host_dispatch(args)
        except FateSmokeError as error:
            payload = {
                "schema_version": "autolean.fate-agent-smoke-result.v1",
                "status": "failed",
                "error": error.code,
            }
            print(_canonical_json(payload).decode("ascii"))
            return 2
    try:
        result = _native_run(args)
    except (FateSmokeError, RuntimePreparationError) as error:
        code = error.code
        result = {
            "schema_version": "autolean.fate-agent-smoke-result.v1",
            "status": "failed",
            "error": code,
        }
        print(_canonical_json(result).decode("ascii"))
        return 2
    except Exception:
        result = {
            "schema_version": "autolean.fate-agent-smoke-result.v1",
            "status": "failed",
            "error": "smoke_unexpected_failure",
        }
        print(_canonical_json(result).decode("ascii"))
        return 2
    print(_canonical_json(result).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
