"""Build and verify the offline source-built mathlib OCI worker profile.

The source and generated-JS caches are populated separately by
``mathlib_source_lock.py`` and ``mathlib_build_resources.py``. This driver
validates those bytes, stages an exact fresh Docker context, and runs every
Docker build step with networking disabled.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, cast

from scripts import mathlib_build_resources, mathlib_source_lock, oci_worker

WSL_DISTRIBUTION: Final[str] = "Ubuntu-24.04"
IMAGE_TAG: Final[str] = "autolean/mathlib-worker:4.28.0-model-theory-source-v2"
MATHLIB_REVISION: Final[str] = "8f9d9cff6bd728b17a24e163c9402775d9e6a365"
MATHLIB_TARGET: Final[str] = "Mathlib.ModelTheory.Semantics"
MATHLIB_BUILD_TARGET: Final[str] = "+Mathlib.ModelTheory.Semantics:olean"
PROOFWIDGETS_NAME: Final[str] = "proofwidgets"
BUILD_RECEIPT_SCHEMA: Final[str] = "autolean.mathlib-source-build-receipt.v2"
SOURCE_INPUTS_SCHEMA: Final[str] = "autolean.mathlib-source-build-inputs.v1"
BUILD_RECORD_SCHEMA: Final[str] = "autolean.mathlib-oci-worker-build.v1"
CANARY_SCHEMA: Final[str] = "autolean.mathlib-oci-worker-canary.v1"
DECLARATION_QUERY_SCHEMA: Final[str] = "autolean.mathlib-declaration-query.v1"
DECLARATION_QUERY_EVIDENCE_SCHEMA: Final[str] = "autolean.mathlib-declaration-query-evidence.v1"
DECLARATION_QUERY_PROTOCOL: Final[str] = "autolean.mathlib-declaration-query.v1"
DECLARATION_QUERY_EXECUTABLE: Final[str] = "/opt/autolean/bin/autolean-mathlib-declaration-query"
DECLARATION_QUERY_HELPER: Final[str] = "/opt/autolean/lib/AutoleanMathlibDeclarationQuery.lean"
DECLARATION_QUERY_MAX_DECLARATIONS: Final[int] = 128
DECLARATION_SOURCE_MAX_BYTES: Final[int] = 16 * 1024 * 1024
DECLARATION_EXECUTION_POLICY_SCHEMA: Final[str] = "autolean.mathlib-declaration-execution-policy.v1"
DECLARATION_QUERY_EVIDENCE_NAME: Final[str] = "mathlib-declarations.v1.json"
EXTERNAL_RUNTIME_PACKAGES: Final[tuple[str, ...]] = (
    "autolean-builder",
    "autolean-control-plane",
    "autolean-prover",
)
OCI_LEAN_WRAPPER_EXECUTABLE: Final[str] = "/opt/autolean/bin/autolean-lean-wrapper"
OCI_LEAN_WRAPPER_PROTOCOL: Final[str] = "autolean.oci-lean-wrapper.v2"
BUILD_ASSETS: Final[tuple[str, ...]] = (
    "Dockerfile.mathlib",
    "AutoleanMathlibQuery.lean",
    "AutoleanMathlibDeclarationQuery.lean",
    "autolean-mathlib-wrapper",
    "autolean-mathlib-declaration-query",
    "autolean-mathlib-build-receipt",
)
SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}")
IMAGE_DIGEST_RE: Final[re.Pattern[str]] = re.compile(r".+@sha256:[0-9a-f]{64}")
DECLARATION_NAME_RE: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+"
)

LABEL_SOURCE_LOCK: Final[str] = "org.autolean.mathlib.source-lock.sha256"
LABEL_SOURCE_INPUTS: Final[str] = "org.autolean.mathlib.source-inputs.sha256"
LABEL_LAKE_MANIFEST: Final[str] = "org.autolean.mathlib.lake-manifest.sha256"
LABEL_LOCAL_PATH_MANIFEST: Final[str] = "org.autolean.mathlib.local-path-manifest.sha256"
LABEL_BUILD_RESOURCE_LOCK: Final[str] = "org.autolean.mathlib.build-resource-lock.sha256"
LABEL_PROOFWIDGETS_ASSET: Final[str] = "org.autolean.mathlib.proofwidgets-release-asset.sha256"
LABEL_PROOFWIDGETS_JS_MANIFEST: Final[str] = "org.autolean.mathlib.proofwidgets-js-manifest.sha256"
LABEL_PROOFWIDGETS_JS_FILE_COUNT: Final[str] = "org.autolean.mathlib.proofwidgets-js-file-count"
LABEL_PROOFWIDGETS_RELEASE_TAG: Final[str] = "org.autolean.mathlib.proofwidgets-release-tag"
LABEL_PROOFWIDGETS_REVISION: Final[str] = "org.autolean.mathlib.proofwidgets-revision"
LABEL_MATHLIB_REVISION: Final[str] = "org.autolean.mathlib.revision"
LABEL_MATHLIB_TARGET: Final[str] = "org.autolean.mathlib.target"
LABEL_MATHLIB_BUILD_TARGET: Final[str] = "org.autolean.mathlib.build-target"
LABEL_DOCKERFILE: Final[str] = "org.autolean.build.dockerfile.sha256"
LABEL_HELPER: Final[str] = "org.autolean.verifier.helper-source.sha256"
LABEL_WRAPPER: Final[str] = "org.autolean.verifier.wrapper.sha256"
LABEL_DECLARATION_QUERY_HELPER: Final[str] = (
    "org.autolean.verifier.declaration-query-helper-source.sha256"
)
LABEL_DECLARATION_QUERY_WRAPPER: Final[str] = (
    "org.autolean.verifier.declaration-query-wrapper.sha256"
)


class MathlibWorkerError(RuntimeError):
    """A fail-closed build input, image receipt, or canary error."""


@dataclass(frozen=True, slots=True)
class PreparedInputs:
    source_inputs: dict[str, object]
    source_inputs_bytes: bytes
    source_archives_manifest: bytes
    source_layout: bytes
    local_path_manifest: bytes
    proofwidgets_js: mathlib_build_resources.PrunedResource
    archives: tuple[tuple[mathlib_source_lock.GitPackage, Path, str], ...]
    build_resource_lock_sha256: str
    source_lock_sha256: str
    source_inputs_sha256: str
    source_archives_manifest_sha256: str
    source_layout_sha256: str
    lake_manifest_sha256: str
    mathlib_source_manifest_sha256: str
    local_path_manifest_sha256: str
    proofwidgets_js_manifest_sha256: str


@dataclass(frozen=True, slots=True)
class CandidateSourceSnapshot:
    path: Path
    sha256: str


def _run(
    argv: list[str],
    *,
    cwd: Path | None = None,
    capture: bool = False,
    timeout: int | None = None,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=cwd,
        check=True,
        shell=False,
        text=True,
        capture_output=capture,
        timeout=timeout,
        env=environment,
    )


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _sha256(path: Path) -> str:
    return mathlib_source_lock.sha256_file(path)


def _canonical_json_bytes(document: object) -> bytes:
    return (
        json.dumps(document, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _unique_json(raw: str, *, label: str) -> dict[str, object]:
    def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise MathlibWorkerError(f"{label} contains a duplicate JSON key")
            result[key] = value
        return result

    try:
        document = json.loads(
            raw,
            object_pairs_hook=unique_pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(
                MathlibWorkerError(f"{label} contains non-standard JSON: {value}")
            ),
        )
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise MathlibWorkerError(f"{label} is not valid JSON") from exc
    if not isinstance(document, dict) or any(not isinstance(key, str) for key in document):
        raise MathlibWorkerError(f"{label} must be a JSON object")
    return cast(dict[str, object], document)


def _archive_member_bytes(
    archive_path: Path,
    package: mathlib_source_lock.GitPackage,
    relative_path: str,
    *,
    max_bytes: int = 2 * 1024 * 1024,
) -> bytes:
    expected = f"{package.repository}-{package.rev}/{relative_path}"
    try:
        with tarfile.open(archive_path, mode="r:*") as archive:
            matches = [member for member in archive if member.name == expected]
            if len(matches) != 1 or not matches[0].isfile() or matches[0].size > max_bytes:
                raise MathlibWorkerError(
                    f"locked {package.name} archive has no unique bounded {relative_path}"
                )
            handle = archive.extractfile(matches[0])
            if handle is None:
                raise MathlibWorkerError(f"locked {package.name} archive member could not be read")
            return handle.read()
    except (OSError, tarfile.TarError) as exc:
        raise MathlibWorkerError(f"locked {package.name} archive could not be inspected") from exc


def _mathlib_local_path_manifest(
    manifest_bytes: bytes,
    dependencies: tuple[mathlib_source_lock.GitPackage, ...],
    library_records: dict[str, dict[str, object]],
) -> bytes:
    try:
        document = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise MathlibWorkerError("mathlib source manifest is not readable JSON") from exc
    expected_top_keys = {"version", "packagesDir", "packages", "name", "lakeDir"}
    if (
        not isinstance(document, dict)
        or set(document) != expected_top_keys
        or document.get("version") != "1.1.0"
        or document.get("packagesDir") != ".lake/packages"
        or document.get("name") != "mathlib"
        or document.get("lakeDir") != ".lake"
        or not isinstance(document.get("packages"), list)
    ):
        raise MathlibWorkerError("mathlib source manifest has an unexpected shape")
    records = document["packages"]
    if len(records) != len(dependencies):
        raise MathlibWorkerError("mathlib source manifest dependency count differs from the lock")
    by_name: dict[str, dict[str, object]] = {}
    expected_record_keys = {
        "configFile",
        "inherited",
        "inputRev",
        "manifestFile",
        "name",
        "rev",
        "scope",
        "subDir",
        "type",
        "url",
    }
    for raw_record in records:
        if not isinstance(raw_record, dict) or set(raw_record) != expected_record_keys:
            raise MathlibWorkerError("mathlib source manifest dependency is not an object")
        record = cast(dict[str, object], raw_record)
        name = record.get("name")
        if not isinstance(name, str) or name in by_name:
            raise MathlibWorkerError("mathlib source manifest dependency name is invalid")
        by_name[name] = record
    overlay_records: list[dict[str, object]] = []
    for package in dependencies:
        dependency_record = by_name.get(package.name)
        library_record = library_records.get(package.name)
        if dependency_record is None or (
            dependency_record.get("type") != "git"
            or dependency_record.get("url") != package.url
            or dependency_record.get("rev") != package.rev
            or dependency_record.get("subDir") is not None
            or not isinstance(dependency_record.get("scope"), str)
            or dependency_record.get("manifestFile") != "lake-manifest.json"
            or dependency_record.get("configFile") not in {"lakefile.lean", "lakefile.toml"}
            or not isinstance(dependency_record.get("inherited"), bool)
            or library_record is None
            or any(
                dependency_record.get(field) != library_record.get(field)
                for field in ("configFile", "manifestFile", "scope", "subDir")
            )
        ):
            raise MathlibWorkerError(
                f"mathlib source manifest differs from locked dependency {package.name}"
            )
        overlay_records.append(
            {
                "configFile": dependency_record["configFile"],
                "dir": f".lake/packages/{package.name}",
                "inherited": dependency_record["inherited"],
                "manifestFile": dependency_record["manifestFile"],
                "name": package.name,
                "scope": dependency_record["scope"],
                "type": "path",
            }
        )
    overlay = {
        "lakeDir": ".lake",
        "name": "mathlib",
        "packages": overlay_records,
        "packagesDir": ".lake/packages",
        "version": "1.1.0",
    }
    return _canonical_json_bytes(overlay)


def _library_package_records(manifest_path: Path) -> dict[str, dict[str, object]]:
    try:
        document = _unique_json(
            manifest_path.read_text(encoding="utf-8"),
            label="Library Lake manifest",
        )
    except (OSError, UnicodeError) as exc:
        raise MathlibWorkerError("Library Lake manifest is unreadable") from exc
    raw_records = document.get("packages")
    if not isinstance(raw_records, list) or len(raw_records) != 9:
        raise MathlibWorkerError("Library Lake manifest package inventory is unexpected")
    records: dict[str, dict[str, object]] = {}
    for raw_record in raw_records:
        if not isinstance(raw_record, dict) or not isinstance(raw_record.get("name"), str):
            raise MathlibWorkerError("Library Lake manifest package record is malformed")
        record = cast(dict[str, object], raw_record)
        name = cast(str, record["name"])
        if name in records:
            raise MathlibWorkerError("Library Lake manifest package name is duplicated")
        records[name] = record
    return records


def prepare_inputs(
    repo_root: Path,
    source_cache: Path,
    build_resource_cache: Path = mathlib_build_resources.DEFAULT_CACHE,
) -> PreparedInputs:
    manifest_path = repo_root / "Library" / "lake-manifest.json"
    lock_path = repo_root / "Prover" / "worker" / "mathlib-source-lock.v1.json"
    build_resource_lock_path = (
        repo_root / "Prover" / "worker" / "mathlib-build-resource-lock.v1.json"
    )
    lake_manifest_sha256, packages = mathlib_source_lock.read_git_packages(manifest_path)
    library_records = _library_package_records(manifest_path)
    if not packages or packages[0].name != "mathlib" or packages[0].rev != MATHLIB_REVISION:
        raise MathlibWorkerError("the first locked package is not the expected mathlib revision")
    proofwidgets_packages = [package for package in packages if package.name == PROOFWIDGETS_NAME]
    if (
        len(proofwidgets_packages) != 1
        or proofwidgets_packages[0].rev != mathlib_build_resources.SOURCE_REVISION
    ):
        raise MathlibWorkerError(
            "the source lock has no unique resource-bound ProofWidgets revision"
        )
    try:
        lock_document = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MathlibWorkerError("tracked mathlib source lock is unreadable") from exc
    if not isinstance(lock_document, dict):
        raise MathlibWorkerError("tracked mathlib source lock is not an object")
    archive_hashes = mathlib_source_lock.validate_lock_document(
        cast(dict[str, object], lock_document),
        lake_manifest_sha256,
        packages,
    )

    staged_archives: list[tuple[mathlib_source_lock.GitPackage, Path, str]] = []
    package_records: list[dict[str, object]] = []
    archive_lines: list[str] = []
    layout_lines: list[str] = []
    for index, package in enumerate(packages):
        expected_hash = archive_hashes[package.name]
        if not isinstance(expected_hash, str):
            raise MathlibWorkerError(f"source lock has no archive hash for {package.name}")
        archive_path = mathlib_source_lock.cache_archive_path(source_cache, package)
        observed_hash = mathlib_source_lock.validate_source_archive(archive_path, package)
        if observed_hash != expected_hash:
            raise MathlibWorkerError(f"cached source archive differs for {package.name}")
        archive_name = f"{index:02d}-{package.name}.tar.gz"
        archive_root = f"{package.repository}-{package.rev}"
        role = "root" if index == 0 else "dependency"
        staged_archives.append((package, archive_path, archive_name))
        archive_lines.append(f"{expected_hash}  sources/{archive_name}\n")
        layout_lines.append(f"{package.name}\t{archive_name}\t{archive_root}\t{role}\n")
        package_records.append(
            {
                "archive_file": archive_name,
                "archive_root": archive_root,
                "archive_sha256": expected_hash,
                "name": package.name,
                "rev": package.rev,
                "role": role,
                "url": package.url,
            }
        )

    mathlib_manifest = _archive_member_bytes(
        staged_archives[0][1],
        packages[0],
        "lake-manifest.json",
    )
    try:
        proofwidgets_js = mathlib_build_resources.verify_cached_resource(
            manifest_path,
            build_resource_lock_path,
            build_resource_cache,
        )
    except mathlib_build_resources.BuildResourceError as exc:
        raise MathlibWorkerError(f"locked mathlib build resource is invalid: {exc}") from exc
    local_path_manifest = _mathlib_local_path_manifest(
        mathlib_manifest,
        packages[1:],
        library_records,
    )
    archives_manifest = "".join(archive_lines).encode("ascii")
    source_layout = "".join(layout_lines).encode("ascii")
    source_lock_sha256 = _sha256(lock_path)
    build_resource_lock_sha256 = _sha256(build_resource_lock_path)
    mathlib_source_manifest_sha256 = _sha256_bytes(mathlib_manifest)
    resource_spec = mathlib_build_resources.EXPECTED_RESOURCE
    source_inputs = {
        "build_resource_lock_sha256": build_resource_lock_sha256,
        "lake_manifest_sha256": lake_manifest_sha256,
        "lean_archive_sha256": oci_worker.LEAN_ARCHIVE_SHA256,
        "mathlib_build_target": MATHLIB_BUILD_TARGET,
        "mathlib_revision": MATHLIB_REVISION,
        "mathlib_local_path_manifest_sha256": _sha256_bytes(local_path_manifest),
        "mathlib_source_manifest_sha256": mathlib_source_manifest_sha256,
        "mathlib_target": MATHLIB_TARGET,
        "packages": package_records,
        "proofwidgets_release_asset_name": resource_spec.asset_name,
        "proofwidgets_release_asset_sha256": resource_spec.asset_sha256,
        "proofwidgets_release_asset_size": resource_spec.asset_size,
        "proofwidgets_release_tag": resource_spec.release_tag,
        "proofwidgets_revision": resource_spec.source_revision,
        "proofwidgets_js_file_count": proofwidgets_js.file_count,
        "proofwidgets_js_manifest_sha256": proofwidgets_js.manifest_sha256,
        "proofwidgets_js_unpacked_bytes": proofwidgets_js.unpacked_bytes,
        "schema_version": SOURCE_INPUTS_SCHEMA,
        "source_archives_manifest_sha256": _sha256_bytes(archives_manifest),
        "source_layout_sha256": _sha256_bytes(source_layout),
        "source_lock_sha256": source_lock_sha256,
    }
    source_inputs_bytes = _canonical_json_bytes(source_inputs)
    return PreparedInputs(
        source_inputs=source_inputs,
        source_inputs_bytes=source_inputs_bytes,
        source_archives_manifest=archives_manifest,
        source_layout=source_layout,
        local_path_manifest=local_path_manifest,
        proofwidgets_js=proofwidgets_js,
        archives=tuple(staged_archives),
        build_resource_lock_sha256=build_resource_lock_sha256,
        source_lock_sha256=source_lock_sha256,
        source_inputs_sha256=_sha256_bytes(source_inputs_bytes),
        source_archives_manifest_sha256=_sha256_bytes(archives_manifest),
        source_layout_sha256=_sha256_bytes(source_layout),
        lake_manifest_sha256=lake_manifest_sha256,
        mathlib_source_manifest_sha256=mathlib_source_manifest_sha256,
        local_path_manifest_sha256=_sha256_bytes(local_path_manifest),
        proofwidgets_js_manifest_sha256=proofwidgets_js.manifest_sha256,
    )


def _asset_hashes(worker_root: Path) -> dict[str, str]:
    return {name: _sha256(worker_root / name) for name in BUILD_ASSETS}


def _build_arguments(prepared: PreparedInputs, assets: dict[str, str]) -> dict[str, str]:
    return {
        "BUILD_RESOURCE_LOCK_SHA256": prepared.build_resource_lock_sha256,
        "BUILD_RECEIPT_TOOL_SHA256": assets["autolean-mathlib-build-receipt"],
        "DOCKERFILE_SHA256": assets["Dockerfile.mathlib"],
        "LAKE_MANIFEST_SHA256": prepared.lake_manifest_sha256,
        "LEAN_ARCHIVE_SHA256": oci_worker.LEAN_ARCHIVE_SHA256,
        "MATHLIB_REVISION": MATHLIB_REVISION,
        "MATHLIB_LOCAL_PATH_MANIFEST_SHA256": prepared.local_path_manifest_sha256,
        "MATHLIB_SOURCE_MANIFEST_SHA256": prepared.mathlib_source_manifest_sha256,
        "PROOFWIDGETS_ASSET_NAME": mathlib_build_resources.ASSET_NAME,
        "PROOFWIDGETS_ASSET_SHA256": mathlib_build_resources.ASSET_SHA256,
        "PROOFWIDGETS_ASSET_SIZE": str(mathlib_build_resources.ASSET_SIZE),
        "PROOFWIDGETS_JS_FILE_COUNT": str(prepared.proofwidgets_js.file_count),
        "PROOFWIDGETS_JS_MANIFEST_SHA256": (prepared.proofwidgets_js_manifest_sha256),
        "PROOFWIDGETS_JS_UNPACKED_BYTES": str(prepared.proofwidgets_js.unpacked_bytes),
        "PROOFWIDGETS_RELEASE_TAG": mathlib_build_resources.RELEASE_TAG,
        "PROOFWIDGETS_REVISION": mathlib_build_resources.SOURCE_REVISION,
        "DECLARATION_QUERY_HELPER_SOURCE_SHA256": assets["AutoleanMathlibDeclarationQuery.lean"],
        "DECLARATION_QUERY_WRAPPER_SHA256": assets["autolean-mathlib-declaration-query"],
        "QUERY_HELPER_SOURCE_SHA256": assets["AutoleanMathlibQuery.lean"],
        "SOURCE_ARCHIVES_MANIFEST_SHA256": prepared.source_archives_manifest_sha256,
        "SOURCE_INPUTS_SHA256": prepared.source_inputs_sha256,
        "SOURCE_LAYOUT_SHA256": prepared.source_layout_sha256,
        "SOURCE_LOCK_SHA256": prepared.source_lock_sha256,
        "WRAPPER_SHA256": assets["autolean-mathlib-wrapper"],
    }


def _normalized_build_policy(
    prepared: PreparedInputs,
    assets: dict[str, str],
) -> dict[str, object]:
    return {
        "build_args": dict(sorted(_build_arguments(prepared, assets).items())),
        "context": "fresh-exact-staging-directory",
        "dockerfile": "Dockerfile.mathlib",
        "flags": ["--no-cache", "--pull=false", "--network=none"],
        "image_tag": IMAGE_TAG,
        "runtime": "docker",
        "schema_version": "autolean.mathlib-oci-build-policy.v1",
    }


def _build_command(
    stage: Path,
    prepared: PreparedInputs,
    assets: dict[str, str],
) -> list[str]:
    command = [
        "docker",
        "build",
        "--no-cache",
        "--pull=false",
        "--network=none",
        "--file",
        "Dockerfile.mathlib",
        "--tag",
        IMAGE_TAG,
    ]
    for name, value in sorted(_build_arguments(prepared, assets).items()):
        command.extend(("--build-arg", f"{name}={value}"))
    command.append(str(stage))
    return command


def _stage_build_context(
    repo_root: Path,
    stage: Path,
    lean_archive: Path,
    prepared: PreparedInputs,
) -> dict[str, str]:
    worker_root = repo_root / "Prover" / "worker"
    stage.mkdir(parents=True, exist_ok=False)
    sources = stage / "sources"
    sources.mkdir()
    oci_worker._stage_archive(lean_archive, stage / oci_worker.LEAN_ARCHIVE)
    for name in BUILD_ASSETS:
        shutil.copy2(worker_root / name, stage / name)
    shutil.copy2(
        worker_root / "mathlib-source-lock.v1.json",
        stage / "mathlib-source-lock.v1.json",
    )
    shutil.copy2(
        worker_root / "mathlib-build-resource-lock.v1.json",
        stage / "mathlib-build-resource-lock.v1.json",
    )
    (stage / "mathlib-source-inputs.v1.json").write_bytes(prepared.source_inputs_bytes)
    (stage / "source-archives.sha256").write_bytes(prepared.source_archives_manifest)
    (stage / "source-layout.tsv").write_bytes(prepared.source_layout)
    (stage / "mathlib-local-path-manifest.v1.json").write_bytes(prepared.local_path_manifest)
    (stage / "proofwidgets-js.sha256").write_bytes(prepared.proofwidgets_js.manifest)
    try:
        staged_js = mathlib_build_resources.write_pruned_js(
            stage / "proofwidgets-release",
            prepared.proofwidgets_js,
        )
    except mathlib_build_resources.BuildResourceError as exc:
        raise MathlibWorkerError(f"ProofWidgets JS could not be staged: {exc}") from exc
    if staged_js != {selected.path: selected.sha256 for selected in prepared.proofwidgets_js.files}:
        raise MathlibWorkerError("staged ProofWidgets JS differs from the pruned resource")
    for package, source, archive_name in prepared.archives:
        destination = sources / archive_name
        shutil.copyfile(source, destination)
        raw_records = prepared.source_inputs["packages"]
        if not isinstance(raw_records, list):
            raise MathlibWorkerError("prepared source input package list is malformed")
        matching = [
            record
            for record in raw_records
            if isinstance(record, dict) and record.get("name") == package.name
        ]
        if len(matching) != 1 or not isinstance(matching[0].get("archive_sha256"), str):
            raise MathlibWorkerError(f"prepared archive binding is missing for {package.name}")
        expected = cast(str, matching[0]["archive_sha256"])
        if _sha256(destination) != expected:
            raise MathlibWorkerError(f"staged archive changed for {package.name}")

    inventory: dict[str, str] = {}
    for path in sorted(stage.rglob("*"), key=lambda item: item.relative_to(stage).as_posix()):
        if path.is_dir():
            continue
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise MathlibWorkerError("build context contains a non-regular file")
        relative = path.relative_to(stage).as_posix()
        if "/.lake/" in f"/{relative}/" or relative.startswith(".lake/"):
            raise MathlibWorkerError("host Lake state entered the fresh Docker build context")
        inventory[relative] = _sha256(path)
    expected_names = {
        oci_worker.LEAN_ARCHIVE,
        "mathlib-build-resource-lock.v1.json",
        "mathlib-source-lock.v1.json",
        "mathlib-source-inputs.v1.json",
        "source-archives.sha256",
        "source-layout.tsv",
        "mathlib-local-path-manifest.v1.json",
        "proofwidgets-js.sha256",
        *BUILD_ASSETS,
        *(f"proofwidgets-release/{selected.path}" for selected in prepared.proofwidgets_js.files),
        *(f"sources/{archive_name}" for _, _, archive_name in prepared.archives),
    }
    if set(inventory) != expected_names:
        raise MathlibWorkerError("fresh Docker build context inventory is not exact")
    return inventory


def _inspect(image: str) -> dict[str, object]:
    raw = _run(["docker", "image", "inspect", image], capture=True, timeout=60).stdout
    loaded = json.loads(raw)
    if not isinstance(loaded, list) or len(loaded) != 1 or not isinstance(loaded[0], dict):
        raise MathlibWorkerError("Docker returned an unexpected image inspection record")
    return cast(dict[str, object], loaded[0])


def _image_reference(inspected: dict[str, object]) -> str:
    repo_digests = inspected.get("RepoDigests")
    if not isinstance(repo_digests, list):
        raise MathlibWorkerError("built image has no repository digest list")
    matching = sorted(
        digest
        for digest in repo_digests
        if isinstance(digest, str)
        and digest.startswith("autolean/mathlib-worker@sha256:")
        and IMAGE_DIGEST_RE.fullmatch(digest)
    )
    if not matching:
        raise MathlibWorkerError("built mathlib worker has no digest-pinned repository identity")
    return matching[0]


def _receipt_command(image: str) -> list[str]:
    if not IMAGE_DIGEST_RE.fullmatch(image):
        raise MathlibWorkerError("receipt verification requires a digest-pinned image")
    return [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--user",
        "65532:65532",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=32m",
        image,
        "/opt/autolean/bin/autolean-mathlib-build-receipt",
    ]


def verify_image_receipt(
    repo_root: Path,
    image: str,
    prepared: PreparedInputs,
) -> tuple[dict[str, object], dict[str, object]]:
    inspected = _inspect(image)
    config = inspected.get("Config")
    if not isinstance(config, dict) or not isinstance(config.get("Labels"), dict):
        raise MathlibWorkerError("built image has no OCI label record")
    labels = cast(dict[str, object], config["Labels"])
    assets = _asset_hashes(repo_root / "Prover" / "worker")
    expected_labels = {
        LABEL_BUILD_RESOURCE_LOCK: prepared.build_resource_lock_sha256,
        LABEL_SOURCE_LOCK: prepared.source_lock_sha256,
        LABEL_SOURCE_INPUTS: prepared.source_inputs_sha256,
        LABEL_LAKE_MANIFEST: prepared.lake_manifest_sha256,
        LABEL_LOCAL_PATH_MANIFEST: prepared.local_path_manifest_sha256,
        LABEL_PROOFWIDGETS_ASSET: mathlib_build_resources.ASSET_SHA256,
        LABEL_PROOFWIDGETS_JS_MANIFEST: prepared.proofwidgets_js_manifest_sha256,
        LABEL_PROOFWIDGETS_JS_FILE_COUNT: str(prepared.proofwidgets_js.file_count),
        LABEL_PROOFWIDGETS_RELEASE_TAG: mathlib_build_resources.RELEASE_TAG,
        LABEL_PROOFWIDGETS_REVISION: mathlib_build_resources.SOURCE_REVISION,
        LABEL_MATHLIB_REVISION: MATHLIB_REVISION,
        LABEL_MATHLIB_TARGET: MATHLIB_TARGET,
        LABEL_MATHLIB_BUILD_TARGET: MATHLIB_BUILD_TARGET,
        LABEL_DOCKERFILE: assets["Dockerfile.mathlib"],
        LABEL_HELPER: assets["AutoleanMathlibQuery.lean"],
        LABEL_WRAPPER: assets["autolean-mathlib-wrapper"],
        LABEL_DECLARATION_QUERY_HELPER: assets["AutoleanMathlibDeclarationQuery.lean"],
        LABEL_DECLARATION_QUERY_WRAPPER: assets["autolean-mathlib-declaration-query"],
    }
    for label, expected in expected_labels.items():
        if labels.get(label) != expected:
            raise MathlibWorkerError(f"image label differs from the locked input: {label}")

    completed = _run(_receipt_command(image), capture=True, timeout=180)
    if len(completed.stdout.splitlines()) != 1:
        raise MathlibWorkerError("image build-receipt tool did not emit exactly one record")
    receipt = _unique_json(completed.stdout, label="image build receipt")
    expected_fields = {
        "build_resource_lock_sha256",
        "build_receipt_tool_sha256",
        "declaration_query_helper_olean_sha256",
        "declaration_query_helper_source_sha256",
        "declaration_query_wrapper_sha256",
        "dockerfile_sha256",
        "helper_olean_sha256",
        "helper_source_sha256",
        "lake_manifest_sha256",
        "lean_archive_sha256",
        "mathlib_build_target",
        "mathlib_import_closure_count",
        "mathlib_import_closure_sha256",
        "mathlib_revision",
        "mathlib_local_path_manifest_sha256",
        "mathlib_source_manifest_sha256",
        "mathlib_target",
        "mathlib_target_olean_sha256",
        "proofwidgets_js_file_count",
        "proofwidgets_js_manifest_sha256",
        "proofwidgets_js_unpacked_bytes",
        "proofwidgets_release_asset_name",
        "proofwidgets_release_asset_sha256",
        "proofwidgets_release_asset_size",
        "proofwidgets_release_tag",
        "proofwidgets_revision",
        "runtime_files_manifest_sha256",
        "schema_version",
        "source_inputs_sha256",
        "source_lock_sha256",
        "wrapper_sha256",
    }
    if set(receipt) != expected_fields:
        raise MathlibWorkerError("image build receipt has unexpected or missing fields")
    expected_receipt = {
        "build_resource_lock_sha256": prepared.build_resource_lock_sha256,
        "build_receipt_tool_sha256": assets["autolean-mathlib-build-receipt"],
        "declaration_query_helper_source_sha256": assets["AutoleanMathlibDeclarationQuery.lean"],
        "declaration_query_wrapper_sha256": assets["autolean-mathlib-declaration-query"],
        "dockerfile_sha256": assets["Dockerfile.mathlib"],
        "helper_source_sha256": assets["AutoleanMathlibQuery.lean"],
        "lake_manifest_sha256": prepared.lake_manifest_sha256,
        "lean_archive_sha256": oci_worker.LEAN_ARCHIVE_SHA256,
        "mathlib_build_target": MATHLIB_BUILD_TARGET,
        "mathlib_revision": MATHLIB_REVISION,
        "mathlib_local_path_manifest_sha256": prepared.local_path_manifest_sha256,
        "mathlib_source_manifest_sha256": prepared.mathlib_source_manifest_sha256,
        "mathlib_target": MATHLIB_TARGET,
        "proofwidgets_js_file_count": prepared.proofwidgets_js.file_count,
        "proofwidgets_js_manifest_sha256": prepared.proofwidgets_js_manifest_sha256,
        "proofwidgets_js_unpacked_bytes": prepared.proofwidgets_js.unpacked_bytes,
        "proofwidgets_release_asset_name": mathlib_build_resources.ASSET_NAME,
        "proofwidgets_release_asset_sha256": mathlib_build_resources.ASSET_SHA256,
        "proofwidgets_release_asset_size": mathlib_build_resources.ASSET_SIZE,
        "proofwidgets_release_tag": mathlib_build_resources.RELEASE_TAG,
        "proofwidgets_revision": mathlib_build_resources.SOURCE_REVISION,
        "schema_version": BUILD_RECEIPT_SCHEMA,
        "source_inputs_sha256": prepared.source_inputs_sha256,
        "source_lock_sha256": prepared.source_lock_sha256,
        "wrapper_sha256": assets["autolean-mathlib-wrapper"],
    }
    for field, expected_value in expected_receipt.items():
        if receipt.get(field) != expected_value:
            raise MathlibWorkerError(f"image build receipt differs at {field}")
    for field in (
        "declaration_query_helper_olean_sha256",
        "helper_olean_sha256",
        "mathlib_import_closure_sha256",
        "mathlib_target_olean_sha256",
        "runtime_files_manifest_sha256",
    ):
        value = receipt.get(field)
        if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
            raise MathlibWorkerError(f"image build receipt has an invalid {field}")
    closure_count = receipt.get("mathlib_import_closure_count")
    if not isinstance(closure_count, int) or closure_count < 2:
        raise MathlibWorkerError("image build receipt has no imported mathlib closure")
    return inspected, receipt


def _declaration_names(declarations: tuple[str, ...]) -> tuple[str, ...]:
    if not declarations:
        raise MathlibWorkerError("declaration query requires at least one declaration")
    if len(declarations) > DECLARATION_QUERY_MAX_DECLARATIONS:
        raise MathlibWorkerError("declaration query exceeds the frozen declaration limit")
    if declarations != tuple(sorted(declarations)):
        raise MathlibWorkerError("declaration query declarations must be sorted")
    if len(declarations) != len(set(declarations)):
        raise MathlibWorkerError("declaration query declarations must be unique")
    if any(DECLARATION_NAME_RE.fullmatch(name) is None for name in declarations):
        raise MathlibWorkerError("declaration query contains an invalid fully-qualified name")
    return declarations


def _source_metadata(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _snapshot_candidate(candidate: Path, snapshot_directory: Path) -> CandidateSourceSnapshot:
    """Copy one stable, non-link source file before it is exposed to a worker."""

    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise MathlibWorkerError("declaration query requires an O_NOFOLLOW execution environment")
    snapshot_directory.mkdir(mode=0o700)
    destination = snapshot_directory / "Candidate.lean"
    source_flags = os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0)
    source_flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        source_descriptor = os.open(candidate, source_flags)
    except OSError as error:
        raise MathlibWorkerError(
            "declaration query candidate could not be opened as a non-link file"
        ) from error

    digest = hashlib.sha256()
    try:
        before = os.fstat(source_descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size <= 0
            or before.st_size > DECLARATION_SOURCE_MAX_BYTES
        ):
            raise MathlibWorkerError("declaration query candidate is not a bounded regular file")
        try:
            snapshot_descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow | getattr(os, "O_CLOEXEC", 0),
                0o444,
            )
        except OSError as error:
            raise MathlibWorkerError("declaration query snapshot could not be created") from error
        copied = 0
        try:
            while True:
                block = os.read(source_descriptor, 1024 * 1024)
                if not block:
                    break
                copied += len(block)
                if copied > DECLARATION_SOURCE_MAX_BYTES:
                    raise MathlibWorkerError(
                        "declaration query candidate exceeds the source size limit"
                    )
                digest.update(block)
                view = memoryview(block)
                while view:
                    written = os.write(snapshot_descriptor, view)
                    if written <= 0:
                        raise OSError("short declaration query snapshot write")
                    view = view[written:]
            if copied != before.st_size:
                raise MathlibWorkerError("declaration query candidate changed during snapshot")
            os.fsync(snapshot_descriptor)
        finally:
            os.close(snapshot_descriptor)
        after = os.fstat(source_descriptor)
        if _source_metadata(before) != _source_metadata(after):
            raise MathlibWorkerError("declaration query candidate changed during snapshot")
    finally:
        os.close(source_descriptor)

    snapshot_metadata = destination.lstat()
    if destination.is_symlink() or not stat.S_ISREG(snapshot_metadata.st_mode):
        raise MathlibWorkerError("declaration query snapshot is not a regular file")
    if snapshot_metadata.st_size != copied or snapshot_metadata.st_mode & 0o222:
        raise MathlibWorkerError("declaration query snapshot is not sealed read-only")
    snapshot_sha256 = _sha256(destination)
    if snapshot_sha256 != digest.hexdigest():
        raise MathlibWorkerError("declaration query snapshot hash does not match copied source")
    return CandidateSourceSnapshot(path=destination, sha256=snapshot_sha256)


def _declaration_execution_policy(
    image: str,
    declarations: tuple[str, ...],
    sealed_candidate_max_bytes: int,
) -> dict[str, object]:
    return {
        "container_policy": {
            "capabilities_dropped": ["ALL"],
            "memory_limit": "2g",
            "network": "none",
            "pids_limit": 128,
            "read_only_rootfs": True,
            "security_options": ["no-new-privileges"],
            "tmpfs": "/tmp:rw,noexec,nosuid,size=256m",
            "user_policy": "host-non-root-or-65532",
        },
        "image": image,
        "phases": [
            {
                "entrypoint": OCI_LEAN_WRAPPER_EXECUTABLE,
                "mounts": [
                    {
                        "destination": "/input/Candidate.lean",
                        "read_only": True,
                        "role": "source_snapshot",
                    },
                    {
                        "destination": "/output",
                        "read_only": False,
                        "role": "compiler_output",
                    },
                ],
                "name": "compile",
                "protocol": OCI_LEAN_WRAPPER_PROTOCOL,
            },
            {
                "input_role": "compiler_output",
                "name": "seal",
                "output_role": "sealed_candidate",
                "sealed_candidate_max_bytes": sealed_candidate_max_bytes,
            },
            {
                "declarations": list(declarations),
                "entrypoint": DECLARATION_QUERY_EXECUTABLE,
                "mounts": [
                    {
                        "destination": "/compiled/Candidate.olean",
                        "read_only": True,
                        "role": "sealed_candidate",
                    }
                ],
                "name": "query",
                "protocol": DECLARATION_QUERY_PROTOCOL,
            },
        ],
        "schema_version": DECLARATION_EXECUTION_POLICY_SCHEMA,
    }


def _declaration_query_docker_base(image: str, container_name: str) -> list[str]:
    getuid = getattr(os, "getuid", None)
    getgid = getattr(os, "getgid", None)
    if os.name == "posix" and callable(getuid) and callable(getgid) and getuid() != 0:
        runtime_user = f"{getuid()}:{getgid()}"
    else:
        runtime_user = "65532:65532"
    return [
        "docker",
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
        "128",
        "--memory",
        "2g",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=256m",
        "--user",
        runtime_user,
    ]


def _name_list(value: object, *, label: str, require_nonempty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise MathlibWorkerError(f"declaration query {label} is not a string list")
    names = tuple(cast(list[str], value))
    if require_nonempty and not names:
        raise MathlibWorkerError(f"declaration query {label} is empty")
    if names != tuple(sorted(names)) or len(names) != len(set(names)):
        raise MathlibWorkerError(f"declaration query {label} must be sorted and unique")
    if any(not name or "\x00" in name or "\n" in name or "\r" in name for name in names):
        raise MathlibWorkerError(f"declaration query {label} contains an invalid name")
    return names


def _declaration_query_command(
    image: str,
    compiled_candidate: Path,
    container_name: str,
    declarations: tuple[str, ...],
) -> list[str]:
    return [
        *_declaration_query_docker_base(image, container_name),
        "--mount",
        f"type=bind,src={compiled_candidate.resolve()},dst=/compiled/Candidate.olean,readonly",
        image,
        DECLARATION_QUERY_EXECUTABLE,
        "--protocol",
        DECLARATION_QUERY_PROTOCOL,
        "--compiled",
        "/compiled/Candidate.olean",
        *(argument for declaration in declarations for argument in ("--declaration", declaration)),
    ]


def _declaration_query_record(
    raw: str,
    *,
    declarations: tuple[str, ...],
    prepared: PreparedInputs,
    assets: dict[str, str],
) -> dict[str, object]:
    record = _unique_json(raw, label="mathlib declaration query")
    expected_keys = {
        "candidate_direct_imports",
        "declarations",
        "image_identity",
        "lake_manifest_hash",
        "lean_version",
        "mathlib_revision",
        "module_import_closure",
        "schema_version",
        "type_format",
    }
    if set(record) != expected_keys:
        raise MathlibWorkerError("declaration query record has unexpected or missing fields")
    expected_identity = {
        "query_helper_path": DECLARATION_QUERY_HELPER,
        "query_helper_sha256": assets["AutoleanMathlibDeclarationQuery.lean"],
        "schema_version": "autolean.image-owned-declaration-query-identity.v1",
        "wrapper_path": DECLARATION_QUERY_EXECUTABLE,
        "wrapper_sha256": assets["autolean-mathlib-declaration-query"],
    }
    if (
        record.get("schema_version") != DECLARATION_QUERY_SCHEMA
        or record.get("type_format") != "autolean.lean-pp-expr.v1"
        or record.get("lean_version") != "v4.28.0"
        or record.get("mathlib_revision") != MATHLIB_REVISION
        or record.get("lake_manifest_hash") != prepared.lake_manifest_sha256
        or record.get("image_identity") != expected_identity
    ):
        raise MathlibWorkerError("declaration query record differs from the pinned image profile")

    direct_imports = _name_list(
        record.get("candidate_direct_imports"),
        label="candidate direct imports",
        require_nonempty=True,
    )
    import_closure = _name_list(
        record.get("module_import_closure"),
        label="module import closure",
        require_nonempty=True,
    )
    if not set(direct_imports) <= set(import_closure):
        raise MathlibWorkerError("declaration query closure omits a direct import")
    if "Candidate" not in import_closure:
        raise MathlibWorkerError("declaration query closure omits the compiled candidate")

    raw_declarations = record.get("declarations")
    if not isinstance(raw_declarations, list) or len(raw_declarations) != len(declarations):
        raise MathlibWorkerError("declaration query result count differs from the request")
    normalized_declarations: list[dict[str, object]] = []
    for expected_name, raw_declaration in zip(declarations, raw_declarations, strict=True):
        if not isinstance(raw_declaration, dict) or set(raw_declaration) != {
            "canonical_type",
            "declaration",
            "observed_axioms",
        }:
            raise MathlibWorkerError("declaration query result has unexpected or missing fields")
        name = raw_declaration.get("declaration")
        canonical_type = raw_declaration.get("canonical_type")
        if name != expected_name or not isinstance(canonical_type, str):
            raise MathlibWorkerError("declaration query result does not bind its requested name")
        if (
            not canonical_type
            or len(canonical_type) > 1_000_000
            or any(character in canonical_type for character in ("\x00", "\n", "\r"))
        ):
            raise MathlibWorkerError("declaration query result has an invalid canonical type")
        axioms = _name_list(raw_declaration.get("observed_axioms"), label="observed axioms")
        normalized_declarations.append(
            {
                "canonical_type": canonical_type,
                "canonical_type_sha256": _sha256_bytes(canonical_type.encode("utf-8")),
                "declaration": expected_name,
                "observed_axioms": list(axioms),
                "observed_axioms_sha256": _sha256_bytes(_canonical_json_bytes(axioms)),
            }
        )
    return {
        "candidate_direct_imports": list(direct_imports),
        "candidate_direct_imports_sha256": _sha256_bytes(_canonical_json_bytes(direct_imports)),
        "declarations": normalized_declarations,
        "image_identity": expected_identity,
        "module_import_closure": list(import_closure),
        "module_import_closure_sha256": _sha256_bytes(_canonical_json_bytes(import_closure)),
    }


def _oci_worker_canary() -> Any:
    """Load the shared compile-and-seal implementation only for the action path."""

    return importlib.import_module("scripts.oci_worker_canary")


def query_declarations(
    repo_root: Path,
    source_cache: Path,
    build_resource_cache: Path,
    image: str,
    candidate: Path,
    declarations: tuple[str, ...],
) -> dict[str, object]:
    """Compile one candidate once, then query its declarations in the pinned mathlib image."""

    oci_worker_canary = _oci_worker_canary()

    declarations = _declaration_names(declarations)
    prepared = prepare_inputs(repo_root, source_cache, build_resource_cache)
    _, receipt = verify_image_receipt(repo_root, image, prepared)
    assets = _asset_hashes(repo_root / "Prover" / "worker")
    execution_policy = _declaration_execution_policy(
        image,
        declarations,
        oci_worker_canary.SEALED_CANDIDATE_MAX_BYTES,
    )

    with tempfile.TemporaryDirectory(prefix="autolean-mathlib-declaration-query-") as raw_root:
        root = Path(raw_root)
        root.chmod(0o700)
        source_directory = root / "source-snapshot"
        compiler_output = root / "compiler-output"
        sealed_directory = root / "sealed"
        source_snapshot = _snapshot_candidate(candidate, source_directory)
        compiler_output.mkdir(mode=0o700)
        sealed_directory.mkdir(mode=0o700)
        invocation_id = secrets.token_hex(10)
        compile_name = f"autolean-mathlib-declaration-compile-{invocation_id}"
        compiler_output.chmod(0o733)
        try:
            compile_command = oci_worker_canary._compile_command(
                image,
                source_snapshot.path,
                compiler_output,
                compile_name,
            )
            compile_result = oci_worker_canary._run_phase(compile_command, compile_name)
        finally:
            compiler_output.chmod(0o700)
        if compile_result.returncode != 0:
            raise MathlibWorkerError(
                f"declaration query candidate failed to compile: {compile_result.stderr[:500]}"
            )
        sealed_candidate, sealed_candidate_sha256 = oci_worker_canary._seal_direct_olean(
            compiler_output,
            sealed_directory,
        )
        query_name = f"autolean-mathlib-declaration-inspect-{invocation_id}"
        query_command = _declaration_query_command(
            image,
            sealed_candidate,
            query_name,
            declarations,
        )
        query_result = oci_worker_canary._run_phase(query_command, query_name)
        if query_result.returncode != 0:
            raise MathlibWorkerError(
                f"image-owned declaration query failed: {query_result.stderr[:500]}"
            )
        observation = _declaration_query_record(
            query_result.stdout,
            declarations=declarations,
            prepared=prepared,
            assets=assets,
        )

    return {
        "build_receipt_canonical_sha256": _sha256_bytes(_canonical_json_bytes(receipt)),
        "execution_policy": execution_policy,
        "execution_policy_sha256": _sha256_bytes(_canonical_json_bytes(execution_policy)),
        "image": image,
        "observation": observation,
        "schema_version": DECLARATION_QUERY_EVIDENCE_SCHEMA,
        "sealed_candidate_sha256": sealed_candidate_sha256,
        "source_snapshot_sha256": source_snapshot.sha256,
        "source_inputs_sha256": prepared.source_inputs_sha256,
    }


def _write_evidence(repo_root: Path, name: str, document: dict[str, object]) -> str:
    evidence = repo_root / "release-evidence" / "oci-worker"
    evidence.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    output = evidence / name
    output.write_text(rendered, encoding="utf-8", newline="\n")
    return _sha256_bytes(rendered.encode("utf-8"))


def _record_declaration_query_evidence(
    repo_root: Path,
    document: dict[str, object],
) -> dict[str, object]:
    if "evidence_sha256" in document:
        raise MathlibWorkerError("declaration query evidence must not contain its own hash")
    evidence_sha256 = _write_evidence(
        repo_root,
        DECLARATION_QUERY_EVIDENCE_NAME,
        document,
    )
    result = dict(document)
    result["evidence_sha256"] = evidence_sha256
    return result


def build(
    repo_root: Path,
    source_cache: Path,
    build_resource_cache: Path,
) -> tuple[str, PreparedInputs, dict[str, object]]:
    prepared = prepare_inputs(repo_root, source_cache, build_resource_cache)
    worker_root = repo_root / "Prover" / "worker"
    assets = _asset_hashes(worker_root)
    lean_archive = oci_worker._archive(Path.home() / ".cache" / "autolean" / "oci-worker-sources")
    with tempfile.TemporaryDirectory(prefix="autolean-mathlib-oci-build-") as raw_parent:
        stage = Path(raw_parent) / "context"
        inventory = _stage_build_context(repo_root, stage, lean_archive, prepared)
        _run(_build_command(stage, prepared, assets), cwd=stage)

    inspected = _inspect(IMAGE_TAG)
    image = _image_reference(inspected)
    inspected, receipt = verify_image_receipt(repo_root, image, prepared)
    image_id = inspected.get("Id")
    if not isinstance(image_id, str) or not image_id.startswith("sha256:"):
        raise MathlibWorkerError("built image has no sha256 image ID")
    build_policy = _normalized_build_policy(prepared, assets)
    record: dict[str, object] = {
        "build_context_inventory": inventory,
        "build_policy": build_policy,
        "build_policy_sha256": _sha256_bytes(_canonical_json_bytes(build_policy)),
        "build_receipt": receipt,
        "host_lake_inputs_staged": False,
        "image": image,
        "image_id": image_id,
        "image_tag": IMAGE_TAG,
        "mathlib_exercised": True,
        "schema_version": BUILD_RECORD_SCHEMA,
        "source_inputs": prepared.source_inputs,
    }
    evidence_sha256 = _write_evidence(
        repo_root,
        "mathlib-build.v1.json",
        record,
    )
    record["evidence_sha256"] = evidence_sha256
    print(json.dumps(record, ensure_ascii=True, sort_keys=True))
    return image, prepared, record


def verify(
    repo_root: Path,
    source_cache: Path,
    build_resource_cache: Path,
    image: str,
) -> dict[str, object]:
    prepared = prepare_inputs(repo_root, source_cache, build_resource_cache)
    inspected, receipt = verify_image_receipt(repo_root, image, prepared)
    result = {
        "image": image,
        "image_id": inspected["Id"],
        "mathlib_exercised": True,
        "receipt": receipt,
        "schema_version": "autolean.mathlib-oci-worker-receipt-verification.v1",
        "source_inputs_sha256": prepared.source_inputs_sha256,
    }
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return result


def _compile_with_dependency_poison(
    image: str,
    candidate: Path,
    poison: Path,
) -> None:
    from scripts import oci_worker_canary

    with tempfile.TemporaryDirectory(prefix="autolean-mathlib-poison-") as raw_output:
        output = Path(raw_output)
        output.chmod(0o733)
        container_name = f"autolean-mathlib-poison-{os.getpid()}"
        command = oci_worker_canary._compile_command(
            image,
            candidate,
            output,
            container_name,
        )
        image_index = command.index(image)
        command[image_index:image_index] = [
            "--mount",
            f"type=bind,src={poison.resolve()},dst=/deps,readonly",
        ]
        try:
            completed = oci_worker_canary._run_phase(command, container_name)
        finally:
            output.chmod(0o700)
        if completed.returncode != 0:
            raise MathlibWorkerError(
                "runtime /deps poison influenced the image-owned mathlib import closure"
            )


def canary(
    repo_root: Path,
    source_cache: Path,
    build_resource_cache: Path,
    image: str,
) -> dict[str, object]:
    from scripts import oci_worker_canary

    prepared = prepare_inputs(repo_root, source_cache, build_resource_cache)
    _, receipt = verify_image_receipt(repo_root, image, prepared)
    worker_root = repo_root / "Prover" / "worker"
    identity = {
        "schema_version": "autolean.image-owned-verifier-identity.v2",
        "wrapper_path": "/opt/autolean/bin/autolean-lean-wrapper",
        "wrapper_sha256": _sha256(worker_root / "autolean-mathlib-wrapper"),
        "query_helper_path": "/opt/autolean/lib/AutoleanLeanQuery.lean",
        "query_helper_sha256": _sha256(worker_root / "AutoleanMathlibQuery.lean"),
    }
    with tempfile.TemporaryDirectory(prefix="autolean-mathlib-canary-") as raw_root:
        root = Path(raw_root)
        candidate = root / "Candidate.lean"
        candidate.write_text(
            "import Mathlib.ModelTheory.Semantics\n\n"
            "namespace AutoLean.OCI\n\n"
            "theorem fixture (n : Nat) : n = n := by\n"
            "  rfl\n\n"
            "end AutoLean.OCI\n",
            encoding="utf-8",
            newline="\n",
        )
        completed = oci_worker_canary._direct(image, candidate)
        if completed.returncode != 0:
            raise MathlibWorkerError(f"mathlib OCI wrapper canary failed: {completed.stderr}")
        record = _unique_json(completed.stdout, label="mathlib OCI wrapper record")
        expected = {
            "canonical_type": "\u2200 (n : Nat), @Eq.{1} Nat n n",
            "declaration": "AutoLean.OCI.fixture",
            "image_identity": identity,
            "lake_manifest_hash": prepared.lake_manifest_sha256,
            "lean_version": "v4.28.0",
            "mathlib_revision": MATHLIB_REVISION,
            "observed_axioms": [],
            "schema_version": "autolean.oci-lean-wrapper.v2",
        }
        if record != expected:
            raise MathlibWorkerError("mathlib OCI wrapper record differs from its pinned profile")

        poison = root / "deps-poison"
        (poison / "Mathlib" / "ModelTheory").mkdir(parents=True)
        (poison / "Mathlib" / "ModelTheory" / "Semantics.olean").write_bytes(
            b"not a Lean object file"
        )
        _compile_with_dependency_poison(image, candidate, poison)

    result: dict[str, object] = {
        "build_receipt_canonical_sha256": _sha256_bytes(_canonical_json_bytes(receipt)),
        "dependency_shadow_ignored": True,
        "host_lake_build_context_excluded": True,
        "image": image,
        "lake_manifest_sha256": prepared.lake_manifest_sha256,
        "mathlib_exercised": True,
        "mathlib_revision": MATHLIB_REVISION,
        "mathlib_build_target": MATHLIB_BUILD_TARGET,
        "mathlib_target": MATHLIB_TARGET,
        "observed_axioms": [],
        "promotion_attestation_created": False,
        "schema_version": CANARY_SCHEMA,
        "wrapper_protocol": "autolean.oci-lean-wrapper.v2",
    }
    evidence_sha256 = _write_evidence(
        repo_root,
        "mathlib-canary.v1.json",
        result,
    )
    result["evidence_sha256"] = evidence_sha256
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return result


def _wsl_path(path: Path) -> str:
    return _run(
        [
            "wsl.exe",
            "-d",
            WSL_DISTRIBUTION,
            "--",
            "wslpath",
            "-a",
            str(path).replace("\\", "/"),
        ],
        capture=True,
        timeout=30,
    ).stdout.strip()


def _delegate_to_wsl(
    arguments: list[str],
    repo_root: Path,
    source_cache: Path,
    build_resource_cache: Path,
) -> int:
    translated_root = _wsl_path(repo_root)
    forwarded = [
        "wsl.exe",
        "-d",
        WSL_DISTRIBUTION,
        "--cd",
        translated_root,
        "--",
        "python3",
        "-m",
        "scripts.oci_mathlib_worker",
        *arguments,
        "--source-cache",
        _wsl_path(source_cache),
        "--build-resource-cache",
        _wsl_path(build_resource_cache),
        "--native",
    ]
    return subprocess.run(forwarded, check=False, shell=False).returncode


def _external_canary(
    repo_root: Path,
    source_cache: Path,
    build_resource_cache: Path,
    image: str,
) -> None:
    environment = os.environ.copy()
    environment["UV_PROJECT_ENVIRONMENT"] = str(
        Path.home() / ".cache" / "autolean" / "oci-worker-python"
    )
    uv = shutil.which("uv")
    if uv is None:
        candidate = Path.home() / ".local" / "bin" / "uv"
        if not candidate.is_file():
            raise MathlibWorkerError("uv is unavailable in the WSL execution environment")
        uv = str(candidate)
    _run(
        [
            uv,
            "sync",
            "--frozen",
            *(
                argument
                for package in EXTERNAL_RUNTIME_PACKAGES
                for argument in ("--package", package)
            ),
            "--no-dev",
        ],
        cwd=repo_root,
        environment=environment,
    )
    _run(
        [
            uv,
            "run",
            "--frozen",
            "--no-sync",
            "python",
            "-m",
            "scripts.oci_mathlib_worker",
            "canary",
            "--image",
            image,
            "--source-cache",
            str(source_cache),
            "--build-resource-cache",
            str(build_resource_cache),
            "--native",
            "--external-python",
        ],
        cwd=repo_root,
        environment=environment,
    )


def _external_declaration_query(
    repo_root: Path,
    source_cache: Path,
    build_resource_cache: Path,
    image: str,
    candidate: Path,
    declarations: tuple[str, ...],
) -> None:
    environment = os.environ.copy()
    environment["UV_PROJECT_ENVIRONMENT"] = str(
        Path.home() / ".cache" / "autolean" / "oci-worker-python"
    )
    uv = shutil.which("uv")
    if uv is None:
        fallback = Path.home() / ".local" / "bin" / "uv"
        if not fallback.is_file():
            raise MathlibWorkerError("uv is unavailable in the WSL execution environment")
        uv = str(fallback)
    _run(
        [
            uv,
            "sync",
            "--frozen",
            *(
                argument
                for package in EXTERNAL_RUNTIME_PACKAGES
                for argument in ("--package", package)
            ),
            "--no-dev",
        ],
        cwd=repo_root,
        environment=environment,
    )
    query_command = [
        uv,
        "run",
        "--frozen",
        "--no-sync",
        "python",
        "-m",
        "scripts.oci_mathlib_worker",
        "query-declarations",
        "--image",
        image,
        "--candidate",
        str(candidate),
    ]
    for declaration in declarations:
        query_command.extend(("--declaration", declaration))
    query_command.extend(
        (
            "--source-cache",
            str(source_cache),
            "--build-resource-cache",
            str(build_resource_cache),
            "--native",
            "--external-python",
        )
    )
    _run(
        query_command,
        cwd=repo_root,
        environment=environment,
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=("build", "verify", "canary", "query-declarations", "all"),
    )
    parser.add_argument("--image", help="digest-pinned mathlib worker image")
    parser.add_argument(
        "--candidate",
        type=Path,
        help="Lean source compiled once before image-owned declaration inspection",
    )
    parser.add_argument(
        "--declaration",
        action="append",
        default=[],
        help="sorted fully-qualified declaration name; repeat for every declaration",
    )
    parser.add_argument(
        "--source-cache",
        type=Path,
        default=mathlib_source_lock.DEFAULT_CACHE,
        help="operator-owned cache populated by mathlib_source_lock.py",
    )
    parser.add_argument(
        "--build-resource-cache",
        type=Path,
        default=mathlib_build_resources.DEFAULT_CACHE,
        help="operator cache populated by mathlib_build_resources.py --update",
    )
    parser.add_argument("--native", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--external-python", action="store_true", help=argparse.SUPPRESS)
    arguments = parser.parse_args(argv)
    if arguments.action in {"verify", "canary", "query-declarations"} and arguments.image is None:
        parser.error(f"{arguments.action} requires --image")
    if arguments.action == "query-declarations":
        if arguments.candidate is None:
            parser.error("query-declarations requires --candidate")
        try:
            _declaration_names(tuple(arguments.declaration))
        except MathlibWorkerError as error:
            parser.error(str(error))
    elif arguments.candidate is not None or arguments.declaration:
        parser.error("--candidate and --declaration are only valid for query-declarations")
    return arguments


def main(argv: list[str] | None = None) -> None:
    arguments = parse_args(argv)
    repo_root = Path(__file__).resolve().parents[1]
    source_cache = arguments.source_cache.resolve()
    build_resource_cache = arguments.build_resource_cache.resolve()
    if os.name == "nt" and not arguments.native:
        forwarded = [arguments.action]
        if arguments.image is not None:
            forwarded.extend(("--image", arguments.image))
        if arguments.candidate is not None:
            forwarded.extend(("--candidate", _wsl_path(arguments.candidate.resolve())))
        for declaration in arguments.declaration:
            forwarded.extend(("--declaration", declaration))
        raise SystemExit(
            _delegate_to_wsl(
                forwarded,
                repo_root,
                source_cache,
                build_resource_cache,
            )
        )

    image = arguments.image
    if arguments.action in {"build", "all"}:
        image, _, _ = build(repo_root, source_cache, build_resource_cache)
    if arguments.action == "verify":
        assert image is not None
        verify(repo_root, source_cache, build_resource_cache, image)
    elif arguments.action == "canary":
        assert image is not None
        if arguments.external_python:
            canary(repo_root, source_cache, build_resource_cache, image)
        else:
            _external_canary(repo_root, source_cache, build_resource_cache, image)
    elif arguments.action == "query-declarations":
        assert image is not None
        assert arguments.candidate is not None
        if arguments.external_python:
            result = query_declarations(
                repo_root,
                source_cache,
                build_resource_cache,
                image,
                arguments.candidate.resolve(),
                tuple(arguments.declaration),
            )
            result = _record_declaration_query_evidence(repo_root, result)
            print(json.dumps(result, ensure_ascii=True, sort_keys=True))
        else:
            _external_declaration_query(
                repo_root,
                source_cache,
                build_resource_cache,
                image,
                arguments.candidate.resolve(),
                tuple(arguments.declaration),
            )
    elif arguments.action == "all":
        assert image is not None
        _external_canary(repo_root, source_cache, build_resource_cache, image)


if __name__ == "__main__":
    main()
