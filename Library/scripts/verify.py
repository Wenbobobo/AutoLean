"""Validate and build the independent AutoLean mathlib downstream project.

On Windows, ``build`` delegates to WSL and builds a fresh source snapshot below
an ext4 cache.  Lake never runs against the NTFS checkout.  The cache contains
only the pinned dependency closure; every invocation still starts from a new
copy of the Library inputs and a new local ``.lake/build`` directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Final, NoReturn

LIBRARY_ROOT: Final = Path(__file__).resolve().parents[1]
EXPECTED_TOOLCHAIN: Final = "leanprover/lean4:v4.28.0"
EXPECTED_MATHLIB_REV: Final = "8f9d9cff6bd728b17a24e163c9402775d9e6a365"
EXPECTED_PACKAGE_REVISIONS: Final = {
    "mathlib": EXPECTED_MATHLIB_REV,
    "plausible": "55c8532eb21ec9f6d565d51d96b8ca50bd1fbef3",
    "LeanSearchClient": "c5d5b8fe6e5158def25cd28eb94e4141ad97c843",
    "importGraph": "85b59af46828c029a9168f2f9c35119bd0721e6e",
    "proofwidgets": "be3b2e63b1bbf496c478cef98b86972a37c1417d",
    "aesop": "f642a64c76df8ba9cb53dba3b919425a0c2aeaf1",
    "Qq": "b8f98e9087e02c8553945a2c5abf07cec8e798c3",
    "batteries": "495c008c3e3f4fb4256ff5582ddb3abf3198026f",
    "Cli": "4f10f47646cb7d5748d6f423f4a07f98f7bbcc9e",
}
BUILD_EVIDENCE_SCHEMA: Final = "autolean.library-downstream-build.v2"
BUILD_TARGETS: Final = (
    "AutoLeanLibrary",
    "AutoLeanLibrary.Fixtures.Dag.Certificate",
    "AutoLeanLibrary.Fixtures.ModelTheory.Packet",
)
BUILD_INPUT_SCHEMA: Final = "autolean.library-build-input-tree.v2"
BUILD_INPUT_ROOT_FILES: Final = (
    "lean-toolchain",
    "lakefile.lean",
    "lake-manifest.json",
    "AutoLeanLibrary.lean",
)
BUILD_INPUT_MODULE_ROOT: Final = "AutoLeanLibrary"
COMPILE_RECEIPT_SCHEMA: Final = "autolean.library-compile-receipt.v2"
SPIKE_PACKET_SCHEMA: Final = "autolean.library-model-theory-compile-spike.v1"
SPIKE_PACKET_RELATIVE: Final = "records/staging/round-01-model-theory-compile-spike/packet.v1.json"
SPIKE_RECEIPT_RELATIVE: Final = (
    "records/staging/round-01-model-theory-compile-spike/compile-receipt.v2.json"
)
DEPENDENCY_CACHE_SCHEMA: Final = "autolean.library-dependency-cache.v3"
DEPENDENCY_TREE_SCHEMA: Final = "autolean.library-dependency-tree.v1"
DEPENDENCY_MANIFEST_FILENAME: Final = "dependency-manifest.v1.json"
DEPENDENCY_TREE_ROOT: Final = "packages"
DEPENDENCY_TREE_EXCLUSION: Final = "git-metadata-directories"
DEFAULT_WSL_DISTRIBUTION: Final = "Ubuntu-24.04"
SHA1: Final = re.compile(r"^[0-9a-f]{40}$")
SHA256: Final = re.compile(r"^[0-9a-f]{64}$")
SAFE_DISTRIBUTION: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
EXT4_FILESYSTEMS: Final = frozenset({"ext2/ext3", "ext2/ext3/ext4", "ext4"})


def fail(message: str) -> NoReturn:
    raise SystemExit(f"Library verification failed: {message}")


def read_manifest(root: Path = LIBRARY_ROOT) -> Mapping[str, object]:
    try:
        payload = json.loads((root / "lake-manifest.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"invalid lake-manifest.json ({error})")
    if not isinstance(payload, dict):
        fail("manifest root must be an object")
    return payload


def package_records(payload: Mapping[str, object]) -> Iterable[Mapping[str, object]]:
    packages = payload.get("packages")
    if not isinstance(packages, list):
        fail("manifest packages must be an array")
    for package in packages:
        if not isinstance(package, dict):
            fail("manifest package entry must be an object")
        yield package


def check_lock(root: Path = LIBRARY_ROOT) -> None:
    try:
        toolchain = (root / "lean-toolchain").read_text(encoding="utf-8").strip()
        lakefile = (root / "lakefile.lean").read_text(encoding="utf-8")
    except OSError as error:
        fail(f"required Lake input is unavailable ({error})")
    if toolchain != EXPECTED_TOOLCHAIN:
        fail(f"lean-toolchain must be {EXPECTED_TOOLCHAIN!r}")

    required_declaration = '"https://github.com/leanprover-community/mathlib4.git" @ "v4.28.0"'
    if required_declaration not in lakefile:
        fail("lakefile does not declare the pinned mathlib v4.28.0 input")

    payload = read_manifest(root)
    if payload.get("version") != "1.1.0" or payload.get("name") != "AutoLeanLibrary":
        fail("manifest identity or version changed")

    records: dict[str, Mapping[str, object]] = {}
    for package in package_records(payload):
        name = package.get("name")
        revision = package.get("rev")
        if not isinstance(name, str) or not isinstance(revision, str):
            fail("every manifest package needs a name and full SHA-1 revision")
        if SHA1.fullmatch(revision) is None:
            fail("every manifest package needs a name and full SHA-1 revision")
        if name in records:
            fail(f"duplicate package {name!r}")
        records[name] = package

    if set(records) != set(EXPECTED_PACKAGE_REVISIONS):
        fail("manifest package set differs from the reviewed dependency closure")
    for name, expected_revision in EXPECTED_PACKAGE_REVISIONS.items():
        if records[name].get("rev") != expected_revision:
            fail(f"package {name!r} has an unreviewed resolved revision")

    mathlib = records["mathlib"]
    if mathlib.get("inputRev") != "v4.28.0" or mathlib.get("inherited") is not False:
        fail("mathlib direct dependency shape changed")


def _path_from_posix(root: Path, relative: str) -> Path:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts or not pure.parts:
        fail("build input path is not a safe POSIX relative path")
    return root.joinpath(*pure.parts)


def _input_relative_paths(root: Path) -> list[str]:
    """Return the exact Lake build inputs in cross-platform byte order."""

    relative_paths: list[str] = []
    for relative in BUILD_INPUT_ROOT_FILES:
        candidate = _path_from_posix(root, relative)
        if candidate.is_symlink() or not candidate.is_file():
            fail(f"required build input is missing, linked, or not a file ({relative})")
        relative_paths.append(relative)

    module_root = root / BUILD_INPUT_MODULE_ROOT
    if module_root.is_symlink() or not module_root.is_dir():
        fail("AutoLeanLibrary module root is missing, linked, or not a directory")
    for candidate in module_root.rglob("*.lean"):
        relative = candidate.relative_to(root).as_posix()
        if candidate.is_symlink() or not candidate.is_file():
            fail(f"Lean build input is linked or not a file ({relative})")
        relative_paths.append(relative)

    if len(relative_paths) != len(set(relative_paths)):
        fail("build input allowlist contains a duplicate path")
    return sorted(relative_paths, key=lambda value: value.encode("utf-8"))


def _input_paths(root: Path) -> list[Path]:
    return [_path_from_posix(root, relative) for relative in _input_relative_paths(root)]


def input_tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    digest.update(BUILD_INPUT_SCHEMA.encode("ascii"))
    digest.update(b"\n")
    for relative in _input_relative_paths(root):
        candidate = _path_from_posix(root, relative)
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(candidate.read_bytes()).digest())
        digest.update(b"\n")
    return digest.hexdigest()


def _copy_input_tree(source: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=False)
    for relative in _input_relative_paths(source):
        candidate = _path_from_posix(source, relative)
        target = _path_from_posix(destination, relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(candidate, target)


def _canonical_json_bytes(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as error:
        fail(f"value is not canonical JSON ({error})")
    return encoded.encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _read_json_object(path: Path, label: str) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"{label} is invalid ({error})")
    if not isinstance(payload, dict):
        fail(f"{label} root must be an object")
    return payload


def packet_content_sha256(packet: Mapping[str, object]) -> str:
    """Hash packet content without its receipt backlink to avoid a hash cycle."""

    content = dict(packet)
    content.pop("compile_receipt", None)
    return _sha256_bytes(_canonical_json_bytes(content))


def _single_line(value: bytes, code: str) -> str:
    try:
        decoded = value.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        fail(f"{code} ({error})")
    if not decoded or "\n" in decoded or "\r" in decoded:
        fail(code)
    return decoded


def _run(
    command: Sequence[str],
    *,
    cwd: Path | None = None,
    environment: Mapping[str, str] | None = None,
    timeout_seconds: int = 900,
) -> subprocess.CompletedProcess[bytes]:
    try:
        completed = subprocess.run(
            tuple(command),
            cwd=cwd,
            env=None if environment is None else dict(environment),
            check=False,
            capture_output=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as error:
        fail(f"command timed out after {timeout_seconds} seconds ({error.cmd[0]})")
    except OSError as error:
        fail(f"subprocess unavailable ({error})")
    if completed.returncode:
        if completed.stdout:
            sys.stdout.buffer.write(completed.stdout)
        if completed.stderr:
            sys.stderr.buffer.write(completed.stderr)
        fail(f"command failed with exit code {completed.returncode}: {command[0]}")
    return completed


def _native_environment() -> dict[str, str]:
    home = os.environ.get("HOME")
    if not home:
        fail("WSL HOME is unavailable")
    environment = {
        "HOME": home,
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
    }
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


def _require_ext4(path: Path) -> None:
    filesystem = _single_line(
        _run(("/usr/bin/stat", "-f", "-c", "%T", "--", str(path))).stdout,
        "cache filesystem probe failed",
    )
    if filesystem not in EXT4_FILESYSTEMS:
        fail("cache root is not ext4")


def _manifest_sha256(root: Path) -> str:
    return hashlib.sha256((root / "lake-manifest.json").read_bytes()).hexdigest()


def _verification_script_sha256(root: Path) -> str:
    try:
        script = (root / "scripts" / "verify.py").read_bytes()
    except OSError as error:
        fail(f"Library verifier script is unavailable ({error})")
    return _sha256_bytes(script)


def _require_exact_keys(value: Mapping[str, object], expected: set[str], label: str) -> None:
    if set(value) != expected:
        fail(f"{label} fields differ from the reviewed schema")


def _require_object(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    return value


def _require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        fail(f"{label} must be a lowercase SHA-256 digest")
    return value


def _verify_build_report(
    report: Mapping[str, object],
    *,
    root: Path,
    source_tree_sha256: str,
) -> None:
    _require_exact_keys(
        report,
        {
            "schema_version",
            "status",
            "execution_platform",
            "build_root_filesystem",
            "toolchain",
            "lean_version",
            "lake_version",
            "lake_manifest_sha256",
            "mathlib_revision",
            "source_tree_schema",
            "source_tree_sha256",
            "targets",
            "dependency_cache_key",
            "dependency_tree",
            "dependency_cache_prepare_seconds",
            "local_build_seconds",
            "total_duration_seconds",
            "contains_absolute_paths",
            "contains_raw_build_output",
        },
        "compile receipt build report",
    )
    if report.get("schema_version") != BUILD_EVIDENCE_SCHEMA or report.get("status") != "passed":
        fail("compile receipt build report did not record a passed reviewed schema")
    if report.get("execution_platform") != "WSL" or report.get("build_root_filesystem") != "ext4":
        fail("compile receipt build report is not an ext4 WSL execution")
    if report.get("toolchain") != EXPECTED_TOOLCHAIN:
        fail("compile receipt build report toolchain drifted")
    if report.get("mathlib_revision") != EXPECTED_MATHLIB_REV:
        fail("compile receipt build report mathlib revision drifted")
    if report.get("lake_manifest_sha256") != _manifest_sha256(root):
        fail("compile receipt build report manifest drifted")
    if report.get("source_tree_schema") != BUILD_INPUT_SCHEMA:
        fail("compile receipt build input schema drifted")
    if report.get("source_tree_sha256") != source_tree_sha256:
        fail("compile receipt does not bind the current authoritative build inputs")
    if report.get("targets") != list(BUILD_TARGETS):
        fail("compile receipt build targets drifted")
    if report.get("dependency_cache_key") != _dependency_cache_key(root):
        fail("compile receipt dependency cache key drifted")
    _validate_dependency_tree_binding(report.get("dependency_tree"))
    if report.get("contains_absolute_paths") is not False:
        fail("compile receipt build report may contain absolute paths")
    if report.get("contains_raw_build_output") is not False:
        fail("compile receipt build report may contain raw build output")

    lean_version = report.get("lean_version")
    lake_version = report.get("lake_version")
    if not isinstance(lean_version, str) or not lean_version.startswith("Lean (version 4.28.0,"):
        fail("compile receipt Lean version is unexpected")
    if not isinstance(lake_version, str) or "Lean version 4.28.0" not in lake_version:
        fail("compile receipt Lake version is unexpected")
    for field in (
        "dependency_cache_prepare_seconds",
        "local_build_seconds",
        "total_duration_seconds",
    ):
        value = report.get(field)
        if isinstance(value, bool) or not isinstance(value, int | float) or value < 0:
            fail(f"compile receipt {field} must be a nonnegative duration")


def verify_compile_receipt(root: Path = LIBRARY_ROOT) -> None:
    check_lock(root)
    packet_path = _path_from_posix(root, SPIKE_PACKET_RELATIVE)
    receipt_path = _path_from_posix(root, SPIKE_RECEIPT_RELATIVE)
    packet = _read_json_object(packet_path, "model-theory spike packet")
    receipt_bytes: bytes
    try:
        receipt_bytes = receipt_path.read_bytes()
    except OSError as error:
        fail(f"model-theory compile receipt is unavailable ({error})")
    receipt = _read_json_object(receipt_path, "model-theory compile receipt")

    if packet.get("schema_version") != SPIKE_PACKET_SCHEMA:
        fail("model-theory spike packet schema drifted")
    if packet.get("record_kind") != "preselection_compile_spike":
        fail("model-theory spike packet record kind drifted")
    if packet.get("state") != "partial_passed_with_gap":
        fail("model-theory spike packet must retain its partial-with-gap state")
    if packet.get("candidate_selection_state") != "not_selected":
        fail("model-theory spike packet must not select a candidate")
    if packet.get("selected_candidate_id") is not None:
        fail("model-theory spike packet selected a candidate")
    gap = _require_object(packet.get("gap"), "model-theory spike gap")
    if gap.get("state") != "open":
        fail("model-theory spike freshness/quantifier gap must remain open")

    backlink = _require_object(packet.get("compile_receipt"), "compile receipt backlink")
    _require_exact_keys(backlink, {"path", "sha256"}, "compile receipt backlink")
    if backlink.get("path") != SPIKE_RECEIPT_RELATIVE:
        fail("compile receipt backlink path drifted")
    expected_receipt_sha256 = _require_sha256(
        backlink.get("sha256"),
        "compile receipt backlink digest",
    )
    if _sha256_bytes(receipt_bytes) != expected_receipt_sha256:
        fail("compile receipt file digest does not match the spike packet")

    _require_exact_keys(
        receipt,
        {
            "schema_version",
            "record_kind",
            "receipt_id",
            "packet_id",
            "receipt_state",
            "candidate_selection_state",
            "selected_candidate_id",
            "build_exit_code",
            "source_tree_schema",
            "source_tree_sha256",
            "packet_content_sha256",
            "verification_script_sha256",
            "environment",
            "targets",
            "build_report_schema",
            "build_report_sha256",
            "build_report",
            "contains_absolute_paths",
            "contains_raw_build_output",
        },
        "compile receipt",
    )
    if receipt.get("schema_version") != COMPILE_RECEIPT_SCHEMA:
        fail("compile receipt schema drifted")
    if receipt.get("record_kind") != "preselection_compile_spike":
        fail("compile receipt record kind drifted")
    if receipt.get("receipt_id") != "round-01-model-theory-compile-spike-wsl-v2":
        fail("compile receipt identity drifted")
    if receipt.get("packet_id") != packet.get("packet_id"):
        fail("compile receipt packet identity drifted")
    if receipt.get("receipt_state") != "partial_passed_with_gap":
        fail("compile receipt must retain the partial-with-gap state")
    if receipt.get("candidate_selection_state") != "not_selected":
        fail("compile receipt must not select a candidate")
    if receipt.get("selected_candidate_id") is not None:
        fail("compile receipt selected a candidate")
    if receipt.get("build_exit_code") != 0:
        fail("compile receipt did not record a successful build exit")
    if receipt.get("source_tree_schema") != BUILD_INPUT_SCHEMA:
        fail("compile receipt source-tree schema drifted")
    if receipt.get("contains_absolute_paths") is not False:
        fail("compile receipt may contain absolute paths")
    if receipt.get("contains_raw_build_output") is not False:
        fail("compile receipt may contain raw build output")

    source_tree_sha256 = input_tree_sha256(root)
    if receipt.get("source_tree_sha256") != source_tree_sha256:
        fail("compile receipt source-tree digest does not match current build inputs")
    expected_packet_sha256 = packet_content_sha256(packet)
    if receipt.get("packet_content_sha256") != expected_packet_sha256:
        fail("compile receipt packet-content digest drifted")
    if receipt.get("verification_script_sha256") != _verification_script_sha256(root):
        fail("compile receipt verifier-script digest drifted")

    environment = _require_object(receipt.get("environment"), "compile receipt environment")
    _require_exact_keys(
        environment,
        {
            "lean_toolchain",
            "mathlib_revision",
            "lake_manifest_sha256",
            "dependency_cache_key",
            "dependency_tree",
        },
        "compile receipt environment",
    )
    if environment.get("lean_toolchain") != EXPECTED_TOOLCHAIN:
        fail("compile receipt environment toolchain drifted")
    if environment.get("mathlib_revision") != EXPECTED_MATHLIB_REV:
        fail("compile receipt environment mathlib revision drifted")
    if environment.get("lake_manifest_sha256") != _manifest_sha256(root):
        fail("compile receipt environment manifest drifted")
    if environment.get("dependency_cache_key") != _dependency_cache_key(root):
        fail("compile receipt environment cache key drifted")
    environment_dependency_tree = _validate_dependency_tree_binding(
        environment.get("dependency_tree")
    )
    if receipt.get("targets") != list(BUILD_TARGETS):
        fail("compile receipt target list drifted")
    if receipt.get("build_report_schema") != BUILD_EVIDENCE_SCHEMA:
        fail("compile receipt report schema drifted")

    report = _require_object(receipt.get("build_report"), "compile receipt build report")
    report_sha256 = _require_sha256(
        receipt.get("build_report_sha256"),
        "compile receipt build report digest",
    )
    if _sha256_bytes(_canonical_json_bytes(report)) != report_sha256:
        fail("compile receipt build report digest drifted")
    _verify_build_report(report, root=root, source_tree_sha256=source_tree_sha256)
    if report.get("dependency_tree") != environment_dependency_tree:
        fail("compile receipt dependency tree differs between environment and report")


def _tracked_dependency_tree(root: Path) -> Mapping[str, object]:
    receipt_path = _path_from_posix(root, SPIKE_RECEIPT_RELATIVE)
    receipt = _read_json_object(receipt_path, "model-theory compile receipt")
    environment = _require_object(receipt.get("environment"), "compile receipt environment")
    return _validate_dependency_tree_binding(environment.get("dependency_tree"))


def _cache_root(value: str | None) -> Path:
    if value is None:
        return Path.home() / ".cache" / "autolean" / "library"
    pure = PurePosixPath(value)
    if not pure.is_absolute() or ".." in pure.parts:
        fail("cache root must be an absolute, traversal-free POSIX path")
    return Path(pure)


def _dependency_cache_key(root: Path) -> str:
    material = b"\0".join(
        (
            DEPENDENCY_CACHE_SCHEMA.encode("ascii"),
            DEPENDENCY_TREE_SCHEMA.encode("ascii"),
            (root / "lean-toolchain").read_bytes(),
            (root / "lake-manifest.json").read_bytes(),
            (root / "lakefile.lean").read_bytes(),
        )
    )
    return hashlib.sha256(material).hexdigest()


def _git_revision(package_root: Path) -> str:
    return _single_line(
        _run(("/usr/bin/git", "-C", str(package_root), "rev-parse", "HEAD")).stdout,
        "dependency revision probe failed",
    )


def _verify_package_directory(packages_root: Path) -> None:
    for name, expected_revision in EXPECTED_PACKAGE_REVISIONS.items():
        package_root = packages_root / name
        if not package_root.is_dir() or package_root.is_symlink():
            fail(f"dependency package {name!r} is missing or linked")
        if _git_revision(package_root) != expected_revision:
            fail(f"dependency package {name!r} revision drifted")
        status = _run(
            (
                "/usr/bin/git",
                "-C",
                str(package_root),
                "status",
                "--porcelain",
                "--untracked-files=no",
            )
        ).stdout
        if status:
            fail(f"dependency package {name!r} has tracked modifications")


def _safe_dependency_name(name: str) -> None:
    try:
        encoded = name.encode("utf-8")
    except UnicodeEncodeError as error:
        fail(f"dependency cache path is not UTF-8 encodable ({error})")
    if (
        not encoded
        or name in {".", ".."}
        or "\\" in name
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
    ):
        fail("dependency cache contains an unsafe path component")


def _normalize_dependency_symlink(parent: PurePosixPath, target: str) -> PurePosixPath:
    pure_target = PurePosixPath(target)
    if pure_target.is_absolute() or not pure_target.parts:
        fail("dependency cache contains an absolute or empty symlink")
    parts = list(parent.parts)
    for part in pure_target.parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not parts:
                fail("dependency cache symlink escapes the cache tree")
            parts.pop()
            continue
        _safe_dependency_name(part)
        parts.append(part)
    if not parts:
        fail("dependency cache symlink resolves outside the cache tree")
    if any(part.casefold() == ".git" for part in parts):
        fail("dependency cache symlink targets excluded Git metadata")
    return PurePosixPath(*parts)


def _is_junction(path: Path) -> bool:
    probe = getattr(path, "is_junction", None)
    return bool(callable(probe) and probe())


def _hash_dependency_file(path: Path) -> tuple[str, int]:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        fail(f"dependency cache file cannot be opened safely ({error})")
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            fail("dependency cache entry changed type while hashing")
        digest = hashlib.sha256()
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        path_after = path.stat(follow_symlinks=False)
    except OSError as error:
        fail(f"dependency cache file changed while hashing ({error})")
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    )
    identity_path = (
        path_after.st_dev,
        path_after.st_ino,
        path_after.st_size,
        path_after.st_mtime_ns,
    )
    if identity_before != identity_after or identity_after != identity_path:
        fail("dependency cache file changed while hashing")
    return digest.hexdigest(), before.st_size


def _dependency_tree_manifest(packages_root: Path) -> dict[str, object]:
    if packages_root.is_symlink() or _is_junction(packages_root) or not packages_root.is_dir():
        fail("dependency package tree is missing, linked, or not a directory")

    entries: list[dict[str, object]] = []

    def visit(directory: Path, parent: PurePosixPath) -> None:
        try:
            children = list(os.scandir(directory))
        except OSError as error:
            fail(f"dependency cache directory cannot be read ({error})")
        try:
            children.sort(key=lambda entry: entry.name.encode("utf-8"))
        except UnicodeEncodeError as error:
            fail(f"dependency cache path is not UTF-8 encodable ({error})")
        for child in children:
            _safe_dependency_name(child.name)
            child_path = Path(child.path)
            relative = parent / child.name
            relative_text = relative.as_posix()
            if _is_junction(child_path):
                fail(f"dependency cache contains a junction ({relative_text})")
            try:
                is_symlink = child.is_symlink()
                is_directory = child.is_dir(follow_symlinks=False)
                is_file = child.is_file(follow_symlinks=False)
            except OSError as error:
                fail(f"dependency cache entry cannot be inspected ({error})")

            if child.name == ".git":
                if is_symlink or not is_directory:
                    fail("dependency Git metadata boundary is linked or not a directory")
                continue
            if is_symlink:
                if "/.lake/build/" in f"/{relative_text}/" or "/.lake/config/" in (
                    f"/{relative_text}/"
                ):
                    fail(
                        "dependency generated build/config output must not be a symlink "
                        f"({relative_text})"
                    )
                try:
                    target = os.readlink(child_path)
                except OSError as error:
                    fail(f"dependency cache symlink cannot be read ({error})")
                normalized = _normalize_dependency_symlink(relative.parent, target)
                target_path = packages_root.joinpath(*normalized.parts)
                target_parent = packages_root
                for part in normalized.parts[:-1]:
                    target_parent /= part
                    if target_parent.is_symlink() or _is_junction(target_parent):
                        fail(f"dependency cache symlink traverses another link ({relative_text})")
                if (
                    target_path.is_symlink()
                    or _is_junction(target_path)
                    or not target_path.is_file()
                ):
                    fail(
                        "dependency cache contains a dangling, chained, or non-file symlink "
                        f"({relative_text})"
                    )
                entries.append(
                    {
                        "kind": "symlink",
                        "path": relative_text,
                        "target": target,
                    }
                )
                continue
            if is_directory:
                entries.append({"kind": "directory", "path": relative_text})
                visit(child_path, relative)
                continue
            if is_file:
                sha256, size = _hash_dependency_file(child_path)
                entries.append(
                    {
                        "kind": "file",
                        "path": relative_text,
                        "sha256": sha256,
                        "size": size,
                    }
                )
                continue
            fail(f"dependency cache contains an unsupported file type ({relative_text})")

    visit(packages_root, PurePosixPath())
    return {
        "schema_version": DEPENDENCY_TREE_SCHEMA,
        "root": DEPENDENCY_TREE_ROOT,
        "excluded": [DEPENDENCY_TREE_EXCLUSION],
        "entries": entries,
    }


def _dependency_tree_binding(
    manifest: Mapping[str, object],
    *,
    manifest_sha256: str,
) -> dict[str, object]:
    entries = manifest.get("entries")
    if not isinstance(entries, list):
        fail("dependency cache manifest entries must be an array")
    directory_count = 0
    regular_file_count = 0
    symlink_count = 0
    total_file_bytes = 0
    for entry in entries:
        if not isinstance(entry, dict):
            fail("dependency cache manifest entry must be an object")
        kind = entry.get("kind")
        if kind == "directory":
            directory_count += 1
        elif kind == "file":
            size = entry.get("size")
            if isinstance(size, bool) or not isinstance(size, int) or size < 0:
                fail("dependency cache manifest file size is invalid")
            regular_file_count += 1
            total_file_bytes += size
        elif kind == "symlink":
            symlink_count += 1
        else:
            fail("dependency cache manifest entry kind is invalid")
    return {
        "schema_version": DEPENDENCY_TREE_SCHEMA,
        "tree_sha256": _sha256_bytes(_canonical_json_bytes(manifest)),
        "manifest_sha256": manifest_sha256,
        "entry_count": len(entries),
        "directory_count": directory_count,
        "regular_file_count": regular_file_count,
        "symlink_count": symlink_count,
        "total_file_bytes": total_file_bytes,
    }


def _write_dependency_manifest(cache_entry: Path, packages_root: Path) -> dict[str, object]:
    manifest = _dependency_tree_manifest(packages_root)
    manifest_bytes = _canonical_json_bytes(manifest) + b"\n"
    manifest_path = cache_entry / DEPENDENCY_MANIFEST_FILENAME
    try:
        with manifest_path.open("xb") as output:
            output.write(manifest_bytes)
    except OSError as error:
        fail(f"dependency cache manifest cannot be written ({error})")
    return _dependency_tree_binding(
        manifest,
        manifest_sha256=_sha256_bytes(manifest_bytes),
    )


def _validate_dependency_tree_binding(value: object) -> Mapping[str, object]:
    binding = _require_object(value, "dependency tree binding")
    _require_exact_keys(
        binding,
        {
            "schema_version",
            "tree_sha256",
            "manifest_sha256",
            "entry_count",
            "directory_count",
            "regular_file_count",
            "symlink_count",
            "total_file_bytes",
        },
        "dependency tree binding",
    )
    if binding.get("schema_version") != DEPENDENCY_TREE_SCHEMA:
        fail("dependency tree binding schema drifted")
    _require_sha256(binding.get("tree_sha256"), "dependency tree digest")
    _require_sha256(binding.get("manifest_sha256"), "dependency manifest digest")
    counts: dict[str, int] = {}
    for field in (
        "entry_count",
        "directory_count",
        "regular_file_count",
        "symlink_count",
        "total_file_bytes",
    ):
        value_at_field = binding.get(field)
        if (
            isinstance(value_at_field, bool)
            or not isinstance(value_at_field, int)
            or value_at_field < 0
        ):
            fail(f"dependency tree binding {field} must be a nonnegative integer")
        counts[field] = value_at_field
    if counts["entry_count"] != (
        counts["directory_count"] + counts["regular_file_count"] + counts["symlink_count"]
    ):
        fail("dependency tree binding entry counts are inconsistent")
    return binding


def _cache_identity(
    root: Path,
    dependency_tree: Mapping[str, object],
) -> dict[str, object]:
    return {
        "schema_version": DEPENDENCY_CACHE_SCHEMA,
        "toolchain": (root / "lean-toolchain").read_text(encoding="utf-8").strip(),
        "lake_manifest_sha256": _manifest_sha256(root),
        "package_revisions": EXPECTED_PACKAGE_REVISIONS,
        "dependency_manifest": DEPENDENCY_MANIFEST_FILENAME,
        "dependency_tree": dict(dependency_tree),
    }


def _validate_dependency_cache(
    cache_entry: Path,
    root: Path,
) -> tuple[Path, Mapping[str, object]]:
    identity_path = cache_entry / "identity.json"
    try:
        identity = json.loads(identity_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"dependency cache identity is invalid ({error})")
    if not isinstance(identity, dict):
        fail("dependency cache identity root must be an object")
    _require_exact_keys(
        identity,
        {
            "schema_version",
            "toolchain",
            "lake_manifest_sha256",
            "package_revisions",
            "dependency_manifest",
            "dependency_tree",
        },
        "dependency cache identity",
    )
    if identity.get("schema_version") != DEPENDENCY_CACHE_SCHEMA:
        fail("dependency cache identity schema drifted")
    if identity.get("toolchain") != (root / "lean-toolchain").read_text(encoding="utf-8").strip():
        fail("dependency cache toolchain identity drifted")
    if identity.get("lake_manifest_sha256") != _manifest_sha256(root):
        fail("dependency cache Lake manifest identity drifted")
    if identity.get("package_revisions") != EXPECTED_PACKAGE_REVISIONS:
        fail("dependency cache package revision identity drifted")
    if identity.get("dependency_manifest") != DEPENDENCY_MANIFEST_FILENAME:
        fail("dependency cache manifest path drifted")
    stored_binding = _validate_dependency_tree_binding(identity.get("dependency_tree"))

    manifest_path = cache_entry / DEPENDENCY_MANIFEST_FILENAME
    try:
        manifest_bytes = manifest_path.read_bytes()
        manifest = json.loads(manifest_bytes)
    except (OSError, json.JSONDecodeError) as error:
        fail(f"dependency cache manifest is invalid ({error})")
    if not isinstance(manifest, dict):
        fail("dependency cache manifest root must be an object")
    if manifest_bytes != _canonical_json_bytes(manifest) + b"\n":
        fail("dependency cache manifest is not canonical JSON")
    if manifest.get("schema_version") != DEPENDENCY_TREE_SCHEMA:
        fail("dependency cache manifest schema drifted")
    if manifest.get("root") != DEPENDENCY_TREE_ROOT:
        fail("dependency cache manifest root drifted")
    if manifest.get("excluded") != [DEPENDENCY_TREE_EXCLUSION]:
        fail("dependency cache manifest exclusion boundary drifted")
    manifest_sha256 = _sha256_bytes(manifest_bytes)
    if stored_binding.get("manifest_sha256") != manifest_sha256:
        fail("dependency cache manifest file digest drifted")

    packages_root = cache_entry / "packages"
    _verify_package_directory(packages_root)
    current_manifest = _dependency_tree_manifest(packages_root)
    if current_manifest != manifest:
        fail("dependency cache bytes differ from the recorded manifest")
    current_binding = _dependency_tree_binding(
        current_manifest,
        manifest_sha256=manifest_sha256,
    )
    if current_binding != stored_binding:
        fail("dependency cache tree binding drifted")
    if identity != _cache_identity(root, current_binding):
        fail("dependency cache identity drifted")
    return packages_root, current_binding


def _ensure_dependency_cache(
    source: Path,
    cache_root: Path,
) -> tuple[Path, Mapping[str, object]]:
    key = _dependency_cache_key(source)
    cache_entry = cache_root / "dependencies" / key
    if cache_entry.exists():
        return _validate_dependency_cache(cache_entry, source)

    staging_root = cache_root / "staging"
    staging_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="dependency-", dir=staging_root) as temporary:
        temporary_root = Path(temporary)
        seed_source = temporary_root / "source"
        _copy_input_tree(source, seed_source)
        check_lock(seed_source)
        environment = _native_environment()
        _run(("lake", "update"), cwd=seed_source, environment=environment)
        check_lock(seed_source)
        packages = seed_source / ".lake" / "packages"
        _verify_package_directory(packages)
        _run(("lake", "exe", "cache", "get"), cwd=seed_source, environment=environment)
        _verify_package_directory(packages)
        for target in BUILD_TARGETS:
            _run(("lake", "build", target), cwd=seed_source, environment=environment)
        _verify_package_directory(packages)

        candidate = temporary_root / "cache-entry"
        candidate.mkdir()
        shutil.move(str(packages), str(candidate / "packages"))
        dependency_tree = _write_dependency_manifest(candidate, candidate / "packages")
        (candidate / "identity.json").write_text(
            json.dumps(
                _cache_identity(source, dependency_tree),
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        cache_entry.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.rename(candidate, cache_entry)
        except FileExistsError:
            return _validate_dependency_cache(cache_entry, source)
    return _validate_dependency_cache(cache_entry, source)


def _verify_live_dependency_cache(
    source: Path,
    cache_root: Path,
) -> Mapping[str, object]:
    cache_entry = cache_root / "dependencies" / _dependency_cache_key(source)
    if cache_entry.is_symlink() or _is_junction(cache_entry) or not cache_entry.is_dir():
        fail("tracked receipt dependency cache is missing, linked, or not a directory")
    _, current_dependency_tree = _validate_dependency_cache(cache_entry, source)
    expected_dependency_tree = _tracked_dependency_tree(source)
    if current_dependency_tree != expected_dependency_tree:
        fail("live dependency cache differs from the tracked receipt")
    return current_dependency_tree


def _native_verify_receipt(source_root: Path, cache_value: str | None) -> None:
    source = source_root.resolve()
    verify_compile_receipt(source)
    cache_root = _cache_root(cache_value)
    if not cache_root.is_dir():
        fail("tracked receipt dependency cache root is unavailable")
    _require_ext4(cache_root)
    _verify_live_dependency_cache(source, cache_root)


def _version(command: Sequence[str], cwd: Path, environment: Mapping[str, str]) -> str:
    completed = _run(command, cwd=cwd, environment=environment)
    return _single_line(completed.stdout, "version probe failed")


def _write_evidence(path: Path, source_root: Path, report: Mapping[str, object]) -> None:
    try:
        relative = path.resolve().relative_to(source_root.resolve())
    except ValueError:
        fail("evidence output must stay below the Library source root")
    if len(relative.parts) < 2 or relative.parts[0] != "evidence" or path.suffix != ".json":
        fail("evidence output must be a JSON file below Library/evidence")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8", newline="\n") as output:
            json.dump(report, output, ensure_ascii=True, indent=2, sort_keys=True)
            output.write("\n")
    except FileExistsError:
        fail("evidence output already exists; immutable evidence must use a new filename")


def _native_build(
    source_root: Path,
    cache_value: str | None,
    evidence_out: Path | None,
) -> dict[str, object]:
    source = source_root.resolve()
    if not source.is_dir():
        fail("Library source root is unavailable")
    check_lock(source)
    source_tree_sha256 = input_tree_sha256(source)
    overall_start = time.monotonic()
    cache_root = _cache_root(cache_value)
    cache_root.mkdir(parents=True, exist_ok=True)
    _require_ext4(cache_root)
    packages, dependency_tree = _ensure_dependency_cache(source, cache_root)
    dependency_cache_prepare_seconds = time.monotonic() - overall_start

    runs_root = cache_root / "runs"
    runs_root.mkdir(exist_ok=True)
    build_start = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="build-", dir=runs_root) as temporary:
        worktree = Path(temporary) / "source"
        _copy_input_tree(source, worktree)
        check_lock(worktree)
        local_lake = worktree / ".lake"
        local_lake.mkdir()
        os.symlink(packages, local_lake / "packages", target_is_directory=True)
        environment = _native_environment()
        lake_version = _version(("lake", "--version"), worktree, environment)
        lean_version = _version(("lake", "env", "lean", "--version"), worktree, environment)
        for target in BUILD_TARGETS:
            _run(("lake", "build", target), cwd=worktree, environment=environment)
        _, dependency_tree_after = _validate_dependency_cache(packages.parent, source)
        if dependency_tree_after != dependency_tree:
            fail("dependency cache changed during the Library build")

    report: dict[str, object] = {
        "schema_version": BUILD_EVIDENCE_SCHEMA,
        "status": "passed",
        "execution_platform": "WSL",
        "build_root_filesystem": "ext4",
        "toolchain": EXPECTED_TOOLCHAIN,
        "lean_version": lean_version,
        "lake_version": lake_version,
        "lake_manifest_sha256": _manifest_sha256(source),
        "mathlib_revision": EXPECTED_MATHLIB_REV,
        "source_tree_schema": BUILD_INPUT_SCHEMA,
        "source_tree_sha256": source_tree_sha256,
        "targets": list(BUILD_TARGETS),
        "dependency_cache_key": _dependency_cache_key(source),
        "dependency_tree": dict(dependency_tree),
        "dependency_cache_prepare_seconds": round(dependency_cache_prepare_seconds, 3),
        "local_build_seconds": round(time.monotonic() - build_start, 3),
        "total_duration_seconds": round(time.monotonic() - overall_start, 3),
        "contains_absolute_paths": False,
        "contains_raw_build_output": False,
    }
    if evidence_out is not None:
        _write_evidence(evidence_out, source, report)
    return report


def _wsl_path(distribution: str, path: Path) -> str:
    output = _run(
        (
            "wsl.exe",
            "--distribution",
            distribution,
            "--exec",
            "/usr/bin/wslpath",
            "-a",
            "-u",
            str(path.resolve()),
        )
    ).stdout
    mapped = _single_line(output, "Windows path could not be mapped into WSL")
    pure = PurePosixPath(mapped)
    if not pure.is_absolute() or ".." in pure.parts:
        fail("Windows path mapping is unsafe")
    return pure.as_posix()


def _host_build(
    cache_root: str | None,
    distribution: str,
    evidence_out: Path | None,
) -> dict[str, object]:
    if SAFE_DISTRIBUTION.fullmatch(distribution) is None:
        fail("WSL distribution name is unsafe")
    command = [
        "wsl.exe",
        "--distribution",
        distribution,
        "--exec",
        "/usr/bin/python3",
        _wsl_path(distribution, Path(__file__)),
        "_native-build",
        "--source-root",
        _wsl_path(distribution, LIBRARY_ROOT),
    ]
    if cache_root is not None:
        command.extend(("--cache-root", cache_root))
    if evidence_out is not None:
        command.extend(("--evidence-out", _wsl_path(distribution, evidence_out)))
    completed = _run(command)
    try:
        payload = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"WSL build result is not valid JSON ({error})")
    if not isinstance(payload, dict) or payload.get("schema_version") != BUILD_EVIDENCE_SCHEMA:
        fail("WSL build result has an unexpected schema")
    return payload


def _host_verify_receipt(cache_root: str | None, distribution: str) -> None:
    if SAFE_DISTRIBUTION.fullmatch(distribution) is None:
        fail("WSL distribution name is unsafe")
    command = [
        "wsl.exe",
        "--distribution",
        distribution,
        "--exec",
        "/usr/bin/python3",
        _wsl_path(distribution, Path(__file__)),
        "_native-verify-receipt",
        "--source-root",
        _wsl_path(distribution, LIBRARY_ROOT),
    ]
    if cache_root is not None:
        command.extend(("--cache-root", cache_root))
    _run(command)


def _native_update_lock() -> None:
    if platform.system() == "Windows":
        fail("update-lock requires an ext4 WSL checkout; it never updates a Windows worktree")
    _require_ext4(LIBRARY_ROOT)
    _run(("lake", "update"), cwd=LIBRARY_ROOT, environment=_native_environment())
    check_lock()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser(
        "check",
        help="validate the lock and tracked model-theory compile receipt",
    )
    verify_receipt = subparsers.add_parser(
        "verify-receipt",
        help="validate the tracked receipt and rehash its current ext4 dependency cache",
    )
    verify_receipt.add_argument("--cache-root", help="absolute ext4 cache root inside WSL")
    verify_receipt.add_argument("--distribution", default=DEFAULT_WSL_DISTRIBUTION)
    hash_input = subparsers.add_parser(
        "hash-input",
        help="report the canonical authoritative build-input hash",
    )
    hash_input.add_argument("--source-root", type=Path, default=LIBRARY_ROOT)
    build = subparsers.add_parser("build", help="build a fresh ext4 WSL source snapshot")
    build.add_argument("--cache-root", help="absolute ext4 cache root inside WSL")
    build.add_argument("--distribution", default=DEFAULT_WSL_DISTRIBUTION)
    build.add_argument("--evidence-out", type=Path, help="new JSON file below Library/evidence")
    update = subparsers.add_parser("update-lock", help="run Lake update in an ext4 WSL checkout")
    update.add_argument("--allow-lock-update", action="store_true")

    native = subparsers.add_parser("_native-build", help=argparse.SUPPRESS)
    native.add_argument("--source-root", type=Path, required=True)
    native.add_argument("--cache-root")
    native.add_argument("--evidence-out", type=Path)
    native_receipt = subparsers.add_parser("_native-verify-receipt", help=argparse.SUPPRESS)
    native_receipt.add_argument("--source-root", type=Path, required=True)
    native_receipt.add_argument("--cache-root")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.command == "check":
        verify_compile_receipt()
        print("Library lock and tracked compile receipt are internally consistent.")
        return
    if args.command == "verify-receipt":
        if platform.system() == "Windows":
            _host_verify_receipt(args.cache_root, args.distribution)
        else:
            _native_verify_receipt(LIBRARY_ROOT, args.cache_root)
        print("Tracked receipt matches current inputs and dependency-cache bytes.")
        return
    if args.command == "hash-input":
        source_root = args.source_root.resolve()
        check_lock(source_root)
        payload = {
            "schema_version": BUILD_INPUT_SCHEMA,
            "source_tree_sha256": input_tree_sha256(source_root),
            "input_paths": _input_relative_paths(source_root),
        }
        print(json.dumps(payload, ensure_ascii=True, sort_keys=True))
        return
    if args.command == "update-lock":
        if not args.allow_lock_update:
            fail("update-lock requires --allow-lock-update")
        _native_update_lock()
        return
    if args.command == "_native-build":
        report = _native_build(args.source_root, args.cache_root, args.evidence_out)
    elif args.command == "_native-verify-receipt":
        _native_verify_receipt(args.source_root, args.cache_root)
        return
    elif platform.system() == "Windows":
        report = _host_build(args.cache_root, args.distribution, args.evidence_out)
    else:
        report = _native_build(LIBRARY_ROOT, args.cache_root, args.evidence_out)
    print(json.dumps(report, ensure_ascii=True, sort_keys=True))


if __name__ == "__main__":
    main()
