"""Lock, fetch, and prune non-source resources needed by the mathlib build.

The default operation validates only the tracked lock. ``--update`` is the
only operation that downloads an asset or replaces operator-cache bytes.
Build contexts receive the validated ProofWidgets ``js/**`` inventory, never
the original release archive or its compiled Lean/native payloads.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import tarfile
import urllib.error
import urllib.request
import uuid
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final, cast
from urllib.parse import unquote, urlsplit
from urllib.request import url2pathname

ROOT: Final[Path] = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST: Final[Path] = ROOT / "Library" / "lake-manifest.json"
DEFAULT_LOCK: Final[Path] = ROOT / "Prover" / "worker" / "mathlib-build-resource-lock.v1.json"
DEFAULT_CACHE: Final[Path] = Path.home() / ".cache" / "autolean" / "mathlib-build-resources"

SCHEMA_VERSION: Final[str] = "autolean.mathlib-build-resource-lock.v1"
RESOURCE_NAME: Final[str] = "proofwidgets-release-js"
PACKAGE_NAME: Final[str] = "proofwidgets"
SOURCE_REVISION: Final[str] = "be3b2e63b1bbf496c478cef98b86972a37c1417d"
SOURCE_URL: Final[str] = "https://github.com/leanprover-community/ProofWidgets4"
RELEASE_TAG: Final[str] = "v0.0.87"
ASSET_NAME: Final[str] = "ProofWidgets4.tar.gz"
ASSET_URL: Final[str] = (
    "https://github.com/leanprover-community/ProofWidgets4/"
    "releases/download/v0.0.87/ProofWidgets4.tar.gz"
)
ASSET_SIZE: Final[int] = 13_772_162
ASSET_SHA256: Final[str] = "ce3f6cd33c49b0b6e177cb2aba77be3a39988db0d6bec9dd6119413e260ac725"
ASSET_REGULAR_FILE_COUNT: Final[int] = 540
ASSET_DIRECTORY_COUNT: Final[int] = 23
JS_PREFIX: Final[str] = "js/"
JS_FILE_COUNT: Final[int] = 20
JS_UNPACKED_BYTES: Final[int] = 6_902_528
REQUIRED_JS_PATHS: Final[frozenset[str]] = frozenset({"js/interactiveExpr.js", "js/lake.trace"})

SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}")
CHUNK_SIZE: Final[int] = 1024 * 1024
MAX_ARCHIVE_MEMBERS: Final[int] = 10_000
MAX_UNPACKED_BYTES: Final[int] = 512 * 1024 * 1024
TRUSTED_RELEASE_HOSTS: Final[frozenset[str]] = frozenset(
    {
        "github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
        "github-releases.githubusercontent.com",
    }
)


class BuildResourceError(ValueError):
    """A fail-closed resource lock, cache, archive, or pruning error."""


@dataclass(frozen=True, slots=True)
class ResourceSpec:
    name: str = RESOURCE_NAME
    package: str = PACKAGE_NAME
    source_revision: str = SOURCE_REVISION
    release_tag: str = RELEASE_TAG
    asset_name: str = ASSET_NAME
    asset_url: str = ASSET_URL
    asset_size: int = ASSET_SIZE
    asset_sha256: str = ASSET_SHA256
    asset_regular_file_count: int = ASSET_REGULAR_FILE_COUNT
    asset_directory_count: int = ASSET_DIRECTORY_COUNT
    selection_prefix: str = JS_PREFIX
    js_file_count: int = JS_FILE_COUNT
    js_unpacked_bytes: int = JS_UNPACKED_BYTES


@dataclass(frozen=True, slots=True)
class ResourceFile:
    path: str
    content: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class PrunedResource:
    files: tuple[ResourceFile, ...]
    manifest: bytes
    manifest_sha256: str
    file_count: int
    unpacked_bytes: int


@dataclass(frozen=True, slots=True)
class LockedResource:
    spec: ResourceSpec
    js_manifest_sha256: str


EXPECTED_RESOURCE: Final[ResourceSpec] = ResourceSpec()


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_json_bytes(document: object) -> bytes:
    return (json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )


def _read_json(path: Path, *, label: str) -> dict[str, object]:
    def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise BuildResourceError(f"{label} contains a duplicate JSON key")
            result[key] = value
        return result

    try:
        document = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=unique_pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(
                BuildResourceError(f"{label} contains non-standard JSON: {value}")
            ),
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BuildResourceError(f"{label} is not readable JSON") from exc
    if not isinstance(document, dict) or any(not isinstance(key, str) for key in document):
        raise BuildResourceError(f"{label} must be a JSON object")
    return cast(dict[str, object], document)


def _expect_exact_keys(
    document: Mapping[str, object],
    expected: set[str],
    *,
    label: str,
) -> None:
    if set(document) != expected:
        raise BuildResourceError(f"{label} has unexpected or missing fields")


def _project_proofwidgets_binding(manifest_path: Path) -> tuple[str, str]:
    document = _read_json(manifest_path, label="Library Lake manifest")
    records = document.get("packages")
    if not isinstance(records, list):
        raise BuildResourceError("Library Lake manifest package inventory is malformed")
    matching = [
        record
        for record in records
        if isinstance(record, dict) and record.get("name") == PACKAGE_NAME
    ]
    if len(matching) != 1:
        raise BuildResourceError("Library Lake manifest has no unique ProofWidgets package")
    record = cast(dict[str, object], matching[0])
    revision = record.get("rev")
    tag = record.get("inputRev")
    if (
        revision != SOURCE_REVISION
        or tag != RELEASE_TAG
        or record.get("configFile") != "lakefile.lean"
        or record.get("type") != "git"
        or record.get("url") != SOURCE_URL
    ):
        raise BuildResourceError("ProofWidgets project binding differs from the resource lock")
    return revision, tag


def lock_document(
    spec: ResourceSpec,
    js_manifest_sha256: str | None,
) -> dict[str, object]:
    if js_manifest_sha256 is not None and not SHA256_RE.fullmatch(js_manifest_sha256):
        raise BuildResourceError("JS manifest SHA-256 is invalid")
    return {
        "resources": [
            {
                "asset_directory_count": spec.asset_directory_count,
                "asset_name": spec.asset_name,
                "asset_regular_file_count": spec.asset_regular_file_count,
                "asset_sha256": spec.asset_sha256,
                "asset_size": spec.asset_size,
                "asset_url": spec.asset_url,
                "js_file_count": spec.js_file_count,
                "js_manifest_sha256": js_manifest_sha256,
                "js_unpacked_bytes": spec.js_unpacked_bytes,
                "name": spec.name,
                "package": spec.package,
                "release_tag": spec.release_tag,
                "selection_prefix": spec.selection_prefix,
                "source_revision": spec.source_revision,
            }
        ],
        "schema_version": SCHEMA_VERSION,
        "state": "complete" if js_manifest_sha256 is not None else "incomplete",
    }


def validate_lock_document(
    document: Mapping[str, object],
    spec: ResourceSpec = EXPECTED_RESOURCE,
    *,
    require_complete: bool = True,
) -> str | None:
    _expect_exact_keys(
        document,
        {"resources", "schema_version", "state"},
        label="build-resource lock",
    )
    if document["schema_version"] != SCHEMA_VERSION:
        raise BuildResourceError("build-resource lock schema version is unsupported")
    raw_resources = document["resources"]
    if not isinstance(raw_resources, list) or len(raw_resources) != 1:
        raise BuildResourceError("build-resource lock must contain exactly one resource")
    raw_record = raw_resources[0]
    if not isinstance(raw_record, dict):
        raise BuildResourceError("build-resource lock record is not an object")
    record = cast(dict[str, object], raw_record)
    expected_keys = {
        "asset_directory_count",
        "asset_name",
        "asset_regular_file_count",
        "asset_sha256",
        "asset_size",
        "asset_url",
        "js_file_count",
        "js_manifest_sha256",
        "js_unpacked_bytes",
        "name",
        "package",
        "release_tag",
        "selection_prefix",
        "source_revision",
    }
    _expect_exact_keys(record, expected_keys, label="build-resource lock record")
    expected_values = {
        "asset_directory_count": spec.asset_directory_count,
        "asset_name": spec.asset_name,
        "asset_regular_file_count": spec.asset_regular_file_count,
        "asset_sha256": spec.asset_sha256,
        "asset_size": spec.asset_size,
        "asset_url": spec.asset_url,
        "js_file_count": spec.js_file_count,
        "js_unpacked_bytes": spec.js_unpacked_bytes,
        "name": spec.name,
        "package": spec.package,
        "release_tag": spec.release_tag,
        "selection_prefix": spec.selection_prefix,
        "source_revision": spec.source_revision,
    }
    if any(record.get(key) != value for key, value in expected_values.items()):
        raise BuildResourceError("build-resource lock record differs from the pinned resource")
    manifest_sha256 = record["js_manifest_sha256"]
    if manifest_sha256 is not None and (
        not isinstance(manifest_sha256, str) or not SHA256_RE.fullmatch(manifest_sha256)
    ):
        raise BuildResourceError("build-resource lock JS manifest SHA-256 is invalid")
    complete = manifest_sha256 is not None
    if document["state"] != ("complete" if complete else "incomplete"):
        raise BuildResourceError("build-resource lock state is inconsistent")
    if require_complete and not complete:
        raise BuildResourceError(
            "build-resource lock is incomplete; an explicit --update is required"
        )
    return manifest_sha256


def read_lock(
    manifest_path: Path = DEFAULT_MANIFEST,
    lock_path: Path = DEFAULT_LOCK,
    spec: ResourceSpec = EXPECTED_RESOURCE,
    *,
    require_complete: bool = True,
) -> LockedResource | None:
    _project_proofwidgets_binding(manifest_path)
    document = _read_json(lock_path, label="build-resource lock")
    manifest_sha256 = validate_lock_document(
        document,
        spec,
        require_complete=require_complete,
    )
    if manifest_sha256 is None:
        return None
    return LockedResource(spec=spec, js_manifest_sha256=manifest_sha256)


def _canonical_member_path(name: str) -> str:
    if not name or "\\" in name or "\x00" in name:
        raise BuildResourceError("release archive contains an invalid member path")
    if name in {".", "./"}:
        return "."
    raw = name[2:] if name.startswith("./") else name
    if (
        not raw
        or raw.startswith("/")
        or any(
            character.isspace() or ord(character) < 32 or ord(character) > 126 for character in raw
        )
    ):
        raise BuildResourceError("release archive contains an unsafe member path")
    path = PurePosixPath(raw)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise BuildResourceError("release archive contains an unsafe member path")
    if re.fullmatch(r"[A-Za-z]:", path.parts[0]) is not None:
        raise BuildResourceError("release archive contains an unsafe member path")
    return path.as_posix()


def validate_and_prune_asset(
    path: Path,
    spec: ResourceSpec = EXPECTED_RESOURCE,
    *,
    expected_js_manifest_sha256: str | None,
) -> PrunedResource:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise BuildResourceError("build-resource asset is unavailable") from exc
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise BuildResourceError("build-resource asset is not a regular file")
    if metadata.st_size != spec.asset_size:
        raise BuildResourceError("build-resource asset size differs from the lock")
    if sha256_file(path) != spec.asset_sha256:
        raise BuildResourceError("build-resource asset SHA-256 differs from the lock")

    selected: list[ResourceFile] = []
    selected_bytes = 0
    total_unpacked = 0
    regular_count = 0
    directory_count = 0
    seen_names: set[str] = set()
    seen_folded_names: set[str] = set()
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            for index, member in enumerate(archive, start=1):
                if index > MAX_ARCHIVE_MEMBERS:
                    raise BuildResourceError("build-resource archive has too many members")
                canonical = _canonical_member_path(member.name)
                folded = canonical.casefold()
                if canonical in seen_names or folded in seen_folded_names:
                    raise BuildResourceError(
                        "build-resource archive contains duplicate member paths"
                    )
                seen_names.add(canonical)
                seen_folded_names.add(folded)
                if member.isdir():
                    directory_count += 1
                    continue
                if not member.isfile():
                    raise BuildResourceError(
                        "build-resource archive contains a link or special file"
                    )
                if member.size < 0:
                    raise BuildResourceError("build-resource archive contains an invalid file size")
                regular_count += 1
                total_unpacked += member.size
                if total_unpacked > MAX_UNPACKED_BYTES:
                    raise BuildResourceError("build-resource archive expands beyond its limit")
                if not canonical.startswith(spec.selection_prefix):
                    continue
                handle = archive.extractfile(member)
                if handle is None:
                    raise BuildResourceError("selected build-resource file is unreadable")
                content = handle.read()
                if len(content) != member.size:
                    raise BuildResourceError("selected build-resource file is truncated")
                selected_bytes += len(content)
                selected.append(
                    ResourceFile(
                        path=canonical,
                        content=content,
                        sha256=_sha256_bytes(content),
                    )
                )
    except (OSError, tarfile.TarError) as exc:
        raise BuildResourceError("build-resource asset is not a valid tar archive") from exc

    if regular_count != spec.asset_regular_file_count:
        raise BuildResourceError("build-resource archive regular-file count differs")
    if directory_count != spec.asset_directory_count:
        raise BuildResourceError("build-resource archive directory count differs")
    selected.sort(key=lambda item: item.path)
    if len(selected) != spec.js_file_count:
        raise BuildResourceError("pruned JS file count differs from the lock")
    if selected_bytes != spec.js_unpacked_bytes:
        raise BuildResourceError("pruned JS byte count differs from the lock")
    selected_paths = {item.path for item in selected}
    if not REQUIRED_JS_PATHS.issubset(selected_paths):
        raise BuildResourceError("pruned JS inventory lacks a required runtime file")
    manifest = "".join(f"{item.sha256}  {item.path}\n" for item in selected).encode("ascii")
    manifest_sha256 = _sha256_bytes(manifest)
    if expected_js_manifest_sha256 is not None and manifest_sha256 != expected_js_manifest_sha256:
        raise BuildResourceError("pruned JS manifest SHA-256 differs from the lock")
    return PrunedResource(
        files=tuple(selected),
        manifest=manifest,
        manifest_sha256=manifest_sha256,
        file_count=len(selected),
        unpacked_bytes=selected_bytes,
    )


def cache_asset_path(
    cache_root: Path = DEFAULT_CACHE,
    spec: ResourceSpec = EXPECTED_RESOURCE,
) -> Path:
    return (
        cache_root
        / SCHEMA_VERSION
        / spec.package
        / spec.source_revision
        / spec.release_tag
        / spec.asset_name
    )


def _copy_download(
    source_url: str,
    output: Path,
    spec: ResourceSpec,
    *,
    allow_file_source: bool,
) -> None:
    parsed = urlsplit(source_url)
    if parsed.scheme == "file":
        if (
            not allow_file_source
            or parsed.query
            or parsed.fragment
            or parsed.hostname not in {None, "", "localhost"}
        ):
            raise BuildResourceError("local build-resource sources are disabled")
        source_path = Path(url2pathname(unquote(parsed.path)))
        try:
            with source_path.open("rb") as source, output.open("xb") as destination:
                shutil.copyfileobj(source, destination, length=CHUNK_SIZE)
                destination.flush()
                os.fsync(destination.fileno())
        except OSError as exc:
            raise BuildResourceError("local build-resource asset could not be copied") from exc
        return

    if source_url != spec.asset_url:
        raise BuildResourceError("production build-resource source override is not allowed")
    try:
        request = urllib.request.Request(
            source_url,
            headers={"User-Agent": "AutoLean-build-resource-lock/1"},
        )
        with (
            urllib.request.urlopen(request, timeout=120) as response,
            output.open("xb") as destination,
        ):
            final_url = urlsplit(response.geturl())
            if (
                final_url.scheme != "https"
                or final_url.hostname is None
                or final_url.hostname.casefold() not in TRUSTED_RELEASE_HOSTS
                or final_url.username is not None
                or final_url.password is not None
            ):
                raise BuildResourceError(
                    "build-resource download left trusted GitHub release origins"
                )
            copied = 0
            while chunk := response.read(CHUNK_SIZE):
                copied += len(chunk)
                if copied > spec.asset_size:
                    raise BuildResourceError("build-resource download exceeds locked size")
                destination.write(chunk)
            destination.flush()
            os.fsync(destination.fileno())
    except BuildResourceError:
        raise
    except (OSError, urllib.error.URLError) as exc:
        raise BuildResourceError("build-resource download failed") from exc


def _write_lock_atomic(path: Path, document: Mapping[str, object]) -> None:
    content = _canonical_json_bytes(document)
    path.parent.mkdir(parents=True, exist_ok=True)
    partial = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.part")
    try:
        with partial.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(partial, 0o644)
        os.replace(partial, path)
    finally:
        with suppress(OSError):
            partial.unlink(missing_ok=True)


def _cache_download(
    cache_root: Path,
    spec: ResourceSpec,
    *,
    source_url: str | None,
    allow_file_source: bool,
) -> Path:
    target = cache_asset_path(cache_root, spec)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if source_url is not None and not allow_file_source and source_url != spec.asset_url:
        raise BuildResourceError("production build-resource source override is not allowed")
    partial = target.with_name(f".{target.name}.{os.getpid()}.{uuid.uuid4().hex}.part")
    try:
        _copy_download(
            spec.asset_url if source_url is None else source_url,
            partial,
            spec,
            allow_file_source=allow_file_source,
        )
        validate_and_prune_asset(
            partial,
            spec,
            expected_js_manifest_sha256=None,
        )
        os.chmod(partial, 0o600)
        os.replace(partial, target)
        return target
    finally:
        with suppress(OSError):
            partial.unlink(missing_ok=True)


def update_resource_lock(
    manifest_path: Path = DEFAULT_MANIFEST,
    lock_path: Path = DEFAULT_LOCK,
    cache_root: Path = DEFAULT_CACHE,
    spec: ResourceSpec = EXPECTED_RESOURCE,
    *,
    source_url: str | None = None,
    allow_file_source: bool = False,
) -> LockedResource:
    _project_proofwidgets_binding(manifest_path)
    bound_manifest: str | None = None
    if lock_path.is_file():
        try:
            document = _read_json(lock_path, label="build-resource lock")
            bound_manifest = validate_lock_document(
                document,
                spec,
                require_complete=False,
            )
        except BuildResourceError:
            bound_manifest = None
    asset = cache_asset_path(cache_root, spec)
    if bound_manifest is not None:
        try:
            pruned = validate_and_prune_asset(
                asset,
                spec,
                expected_js_manifest_sha256=bound_manifest,
            )
        except BuildResourceError:
            bound_manifest = None
        else:
            return LockedResource(spec=spec, js_manifest_sha256=pruned.manifest_sha256)
    asset = _cache_download(
        cache_root,
        spec,
        source_url=source_url,
        allow_file_source=allow_file_source,
    )
    pruned = validate_and_prune_asset(
        asset,
        spec,
        expected_js_manifest_sha256=None,
    )
    document = lock_document(spec, pruned.manifest_sha256)
    validate_lock_document(document, spec)
    _write_lock_atomic(lock_path, document)
    return LockedResource(spec=spec, js_manifest_sha256=pruned.manifest_sha256)


def verify_cached_resource(
    manifest_path: Path = DEFAULT_MANIFEST,
    lock_path: Path = DEFAULT_LOCK,
    cache_root: Path = DEFAULT_CACHE,
    spec: ResourceSpec = EXPECTED_RESOURCE,
) -> PrunedResource:
    locked = read_lock(manifest_path, lock_path, spec)
    assert locked is not None
    return validate_and_prune_asset(
        cache_asset_path(cache_root, spec),
        spec,
        expected_js_manifest_sha256=locked.js_manifest_sha256,
    )


def write_pruned_js(output_root: Path, resource: PrunedResource) -> dict[str, str]:
    if output_root.exists():
        raise BuildResourceError("pruned JS output root already exists")
    output_root.mkdir(parents=True)
    inventory: dict[str, str] = {}
    for selected in resource.files:
        relative = PurePosixPath(selected.path)
        if not selected.path.startswith(JS_PREFIX) or relative.parts[0] != "js":
            raise BuildResourceError("pruned resource contains a non-JS path")
        destination = output_root.joinpath(*relative.parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as handle:
            handle.write(selected.content)
        os.chmod(destination, 0o444)
        if sha256_file(destination) != selected.sha256:
            raise BuildResourceError("written pruned JS file differs from its manifest")
        inventory[selected.path] = selected.sha256
    if len(inventory) != resource.file_count:
        raise BuildResourceError("written pruned JS inventory count differs")
    return inventory


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--update",
        action="store_true",
        help="explicitly fetch, validate, cache, and bind the pinned release asset",
    )
    parser.add_argument(
        "--verify-cache",
        action="store_true",
        help="also require and fully validate the operator-cached release asset",
    )
    arguments = parser.parse_args(argv)
    if arguments.update and arguments.verify_cache:
        parser.error("--update and --verify-cache are mutually exclusive")
    return arguments


def main(argv: Sequence[str] | None = None) -> None:
    arguments = parse_args(argv)
    try:
        if arguments.update:
            locked = update_resource_lock()
            print(f"mathlib build resource updated: {locked.spec.name} {locked.js_manifest_sha256}")
        elif arguments.verify_cache:
            resource = verify_cached_resource()
            print(f"mathlib build resource lock and cache valid: {resource.file_count} JS files")
        else:
            validated_lock = read_lock()
            assert validated_lock is not None
            print(f"mathlib build resource lock valid: {validated_lock.spec.name}")
    except BuildResourceError as exc:
        raise SystemExit(f"mathlib build resource failed: {exc}") from None


if __name__ == "__main__":
    main()
