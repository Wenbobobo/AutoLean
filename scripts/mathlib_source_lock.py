"""Pin and validate GitHub source archives for the Library Lake dependencies.

The default operation is read-only.  ``--update`` is the only operation that
downloads archives or changes the tracked lock.
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
from typing import cast
from urllib.parse import unquote, urlsplit
from urllib.request import url2pathname

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "Library" / "lake-manifest.json"
DEFAULT_LOCK = ROOT / "Prover" / "worker" / "mathlib-source-lock.v1.json"
DEFAULT_CACHE = Path.home() / ".cache" / "autolean" / "mathlib-sources"

SCHEMA_VERSION = "autolean.mathlib-source-lock.v1"
EXPECTED_GIT_PACKAGES = 9
SHA1_RE = re.compile(r"[0-9a-f]{40}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
SAFE_REPOSITORY_COMPONENT_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?")
SAFE_PACKAGE_NAME_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?")
CHUNK_SIZE = 1024 * 1024
MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 2_000_000
MAX_UNPACKED_BYTES = 20 * 1024 * 1024 * 1024


class SourceLockError(ValueError):
    """A fail-closed source manifest, lock, cache, or archive error."""


@dataclass(frozen=True)
class GitPackage:
    name: str
    url: str
    rev: str
    owner: str
    repository: str
    archive_url: str


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(path: Path, *, label: str) -> dict[str, object]:
    try:
        loaded = cast(object, json.loads(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SourceLockError(f"{label} is not readable canonical JSON") from exc
    if not isinstance(loaded, dict) or any(not isinstance(key, str) for key in loaded):
        raise SourceLockError(f"{label} must be a JSON object")
    return cast(dict[str, object], loaded)


def _github_coordinates(url: str) -> tuple[str, str]:
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port
        username = parsed.username
        password = parsed.password
    except ValueError as exc:
        raise SourceLockError("git package URL has an invalid HTTPS authority") from exc
    if (
        parsed.scheme != "https"
        or hostname is None
        or hostname.casefold() != "github.com"
        or port is not None
        or username is not None
        or password is not None
        or parsed.query
        or parsed.fragment
        or "%" in parsed.path
    ):
        raise SourceLockError("git package URL must be credential-free HTTPS github.com")
    parts = PurePosixPath(parsed.path).parts
    if len(parts) != 3 or parts[0] != "/":
        raise SourceLockError("git package URL must name one GitHub owner and repository")
    owner, repository = parts[1:]
    if repository.endswith(".git"):
        repository = repository[:-4]
    if (
        not SAFE_REPOSITORY_COMPONENT_RE.fullmatch(owner)
        or not SAFE_REPOSITORY_COMPONENT_RE.fullmatch(repository)
        or owner in {".", ".."}
        or repository in {".", ".."}
    ):
        raise SourceLockError("git package URL contains an invalid repository component")
    return owner, repository


def read_git_packages(manifest_path: Path = DEFAULT_MANIFEST) -> tuple[str, tuple[GitPackage, ...]]:
    document = _read_json(manifest_path, label="Lake manifest")
    raw_packages = document.get("packages")
    if not isinstance(raw_packages, list) or len(raw_packages) != EXPECTED_GIT_PACKAGES:
        raise SourceLockError(
            f"Lake manifest must contain exactly {EXPECTED_GIT_PACKAGES} git packages"
        )

    packages: list[GitPackage] = []
    seen_names: set[str] = set()
    for index, raw_package in enumerate(raw_packages):
        if not isinstance(raw_package, dict):
            raise SourceLockError(f"Lake package {index} must be a JSON object")
        package = cast(dict[object, object], raw_package)
        name = package.get("name")
        url = package.get("url")
        rev = package.get("rev")
        if package.get("type") != "git":
            raise SourceLockError(f"Lake package {index} is not a git dependency")
        if not isinstance(name, str) or not SAFE_PACKAGE_NAME_RE.fullmatch(name):
            raise SourceLockError(f"Lake package {index} has an invalid name")
        folded_name = name.casefold()
        if folded_name in seen_names:
            raise SourceLockError(f"Lake package name is not unique: {name}")
        seen_names.add(folded_name)
        if not isinstance(url, str):
            raise SourceLockError(f"Lake package {name} has no URL")
        if not isinstance(rev, str) or not SHA1_RE.fullmatch(rev):
            raise SourceLockError(f"Lake package {name} rev must be a lowercase 40-hex commit")
        owner, repository = _github_coordinates(url)
        archive_url = f"https://codeload.github.com/{owner}/{repository}/tar.gz/{rev}"
        packages.append(
            GitPackage(
                name=name,
                url=url,
                rev=rev,
                owner=owner,
                repository=repository,
                archive_url=archive_url,
            )
        )
    return sha256_file(manifest_path), tuple(packages)


def lock_document(
    manifest_sha256: str,
    packages: Sequence[GitPackage],
    archive_sha256_by_name: Mapping[str, str | None],
) -> dict[str, object]:
    records: list[dict[str, object]] = []
    complete = True
    for package in packages:
        archive_sha256 = archive_sha256_by_name.get(package.name)
        if archive_sha256 is None:
            complete = False
        elif not SHA256_RE.fullmatch(archive_sha256):
            raise SourceLockError(f"invalid archive SHA-256 for package {package.name}")
        records.append(
            {
                "archive_sha256": archive_sha256,
                "archive_url": package.archive_url,
                "name": package.name,
                "rev": package.rev,
                "url": package.url,
            }
        )
    return {
        "manifest_path": "Library/lake-manifest.json",
        "manifest_sha256": manifest_sha256,
        "packages": records,
        "schema_version": SCHEMA_VERSION,
        "state": "complete" if complete else "incomplete",
    }


def _expect_exact_keys(document: Mapping[str, object], expected: set[str], *, label: str) -> None:
    if set(document) != expected:
        raise SourceLockError(f"{label} has unexpected or missing fields")


def validate_lock_document(
    document: Mapping[str, object],
    manifest_sha256: str,
    packages: Sequence[GitPackage],
    *,
    require_complete: bool = True,
) -> dict[str, str | None]:
    _expect_exact_keys(
        document,
        {"manifest_path", "manifest_sha256", "packages", "schema_version", "state"},
        label="source lock",
    )
    if document["schema_version"] != SCHEMA_VERSION:
        raise SourceLockError("source lock schema version is unsupported")
    if document["manifest_path"] != "Library/lake-manifest.json":
        raise SourceLockError("source lock manifest path is not canonical")
    if document["manifest_sha256"] != manifest_sha256:
        raise SourceLockError("source lock manifest SHA-256 does not match")

    raw_records = document["packages"]
    if not isinstance(raw_records, list) or len(raw_records) != len(packages):
        raise SourceLockError("source lock package count does not match the Lake manifest")
    expected_record_keys = {"archive_sha256", "archive_url", "name", "rev", "url"}
    archive_hashes: dict[str, str | None] = {}
    for package, raw_record in zip(packages, raw_records, strict=True):
        if not isinstance(raw_record, dict):
            raise SourceLockError(f"source lock record for {package.name} is not an object")
        record = cast(dict[str, object], raw_record)
        _expect_exact_keys(record, expected_record_keys, label=f"source lock record {package.name}")
        expected_values = {
            "archive_url": package.archive_url,
            "name": package.name,
            "rev": package.rev,
            "url": package.url,
        }
        if any(record[key] != value for key, value in expected_values.items()):
            raise SourceLockError(f"source lock record does not match package {package.name}")
        archive_sha256 = record["archive_sha256"]
        if archive_sha256 is not None and (
            not isinstance(archive_sha256, str) or not SHA256_RE.fullmatch(archive_sha256)
        ):
            raise SourceLockError(f"source lock archive SHA-256 is invalid for {package.name}")
        archive_hashes[package.name] = archive_sha256

    complete = all(value is not None for value in archive_hashes.values())
    expected_state = "complete" if complete else "incomplete"
    if document["state"] != expected_state:
        raise SourceLockError("source lock state does not match its archive hashes")
    if require_complete and not complete:
        raise SourceLockError("source lock is incomplete; an explicit --update is required")
    return archive_hashes


def check_source_lock(
    manifest_path: Path = DEFAULT_MANIFEST,
    lock_path: Path = DEFAULT_LOCK,
    *,
    require_complete: bool = True,
) -> tuple[GitPackage, ...]:
    manifest_sha256, packages = read_git_packages(manifest_path)
    document = _read_json(lock_path, label="source lock")
    validate_lock_document(
        document,
        manifest_sha256,
        packages,
        require_complete=require_complete,
    )
    return packages


def _validate_archive_name(name: str, *, expected_root: str, label: str) -> PurePosixPath:
    if not name or "\\" in name or "\x00" in name:
        raise SourceLockError(f"{label} has an invalid path")
    path = PurePosixPath(name)
    if (
        path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or re.fullmatch(r"[A-Za-z]:", path.parts[0]) is not None
    ):
        raise SourceLockError(f"{label} has an unsafe path")
    if path.parts[0] != expected_root:
        raise SourceLockError(f"{label} is outside the canonical archive root")
    folded = tuple(part.casefold() for part in path.parts)
    if ".git" in folded:
        raise SourceLockError(f"{label} contains Git metadata")
    for index, component in enumerate(folded[:-1]):
        if component == ".lake" and folded[index + 1] in {"build", "config"}:
            raise SourceLockError(f"{label} contains generated Lake state")
    if folded[-1].endswith((".olean", ".ilean")):
        raise SourceLockError(f"{label} contains generated Lean output")
    return path


def _validate_symlink_target(
    linkname: str,
    *,
    member_path: PurePosixPath,
    expected_root: str,
    label: str,
) -> None:
    if not linkname or "\\" in linkname or "\x00" in linkname:
        raise SourceLockError(f"{label} has an invalid path")
    target = PurePosixPath(linkname)
    raw_parts = linkname.split("/")
    if target.is_absolute() or any(
        re.fullmatch(r"[A-Za-z]:", part) is not None for part in raw_parts
    ):
        raise SourceLockError(f"{label} has an unsafe path")

    normalized_parts = list(member_path.parent.parts)
    if not normalized_parts or normalized_parts[0] != expected_root:
        raise SourceLockError(f"{label} has an unsafe parent")
    for part in raw_parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if len(normalized_parts) == 1:
                raise SourceLockError(f"{label} escapes the canonical archive root")
            normalized_parts.pop()
            continue
        normalized_parts.append(part)

    _validate_archive_name(
        PurePosixPath(*normalized_parts).as_posix(),
        expected_root=expected_root,
        label=label,
    )


def validate_source_archive(path: Path, package: GitPackage) -> str:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise SourceLockError(f"source archive is unavailable for {package.name}") from exc
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise SourceLockError(f"source archive is not a regular file for {package.name}")
    if metadata.st_size <= 0 or metadata.st_size > MAX_ARCHIVE_BYTES:
        raise SourceLockError(f"source archive size is invalid for {package.name}")

    expected_root = f"{package.repository}-{package.rev}"
    seen_names: set[str] = set()
    member_count = 0
    unpacked_bytes = 0
    regular_files = 0
    try:
        with tarfile.open(path, mode="r:*") as archive:
            for member in archive:
                member_count += 1
                if member_count > MAX_ARCHIVE_MEMBERS:
                    raise SourceLockError(f"source archive has too many members for {package.name}")
                member_path = _validate_archive_name(
                    member.name,
                    expected_root=expected_root,
                    label=f"archive member for {package.name}",
                )
                canonical_name = member_path.as_posix()
                if canonical_name in seen_names:
                    raise SourceLockError(
                        f"source archive has duplicate members for {package.name}"
                    )
                seen_names.add(canonical_name)

                if member.isfile():
                    if member.size < 0:
                        raise SourceLockError(
                            f"source archive has an invalid file size for {package.name}"
                        )
                    regular_files += 1
                    unpacked_bytes += member.size
                    if unpacked_bytes > MAX_UNPACKED_BYTES:
                        raise SourceLockError(
                            f"source archive expands beyond its limit for {package.name}"
                        )
                elif member.isdir():
                    continue
                elif member.issym():
                    _validate_symlink_target(
                        member.linkname,
                        member_path=member_path,
                        expected_root=expected_root,
                        label=f"archive symlink target for {package.name}",
                    )
                elif member.islnk():
                    raise SourceLockError(f"source archive contains a hard link for {package.name}")
                else:
                    raise SourceLockError(
                        f"source archive contains a special file for {package.name}"
                    )
    except (tarfile.TarError, OSError) as exc:
        raise SourceLockError(f"source archive is not a valid tar file for {package.name}") from exc
    if regular_files == 0:
        raise SourceLockError(f"source archive has no source files for {package.name}")
    return sha256_file(path)


def cache_archive_path(cache_root: Path, package: GitPackage) -> Path:
    return (
        cache_root / SCHEMA_VERSION / package.owner / package.repository / f"{package.rev}.tar.gz"
    )


def _copy_download(source_url: str, output: Path, *, allow_file_source: bool) -> None:
    parsed = urlsplit(source_url)
    if parsed.scheme == "file":
        if (
            not allow_file_source
            or parsed.query
            or parsed.fragment
            or parsed.hostname not in {None, "", "localhost"}
        ):
            raise SourceLockError("local archive sources are disabled")
        source_path = Path(url2pathname(unquote(parsed.path)))
        try:
            with source_path.open("rb") as source, output.open("xb") as destination:
                shutil.copyfileobj(source, destination, length=CHUNK_SIZE)
                destination.flush()
                os.fsync(destination.fileno())
        except OSError as exc:
            raise SourceLockError("local source archive could not be copied") from exc
        return

    if parsed.scheme != "https" or parsed.hostname is None:
        raise SourceLockError("archive source must use HTTPS")
    try:
        request = urllib.request.Request(
            source_url, headers={"User-Agent": "AutoLean-source-lock/1"}
        )
        with (
            urllib.request.urlopen(request, timeout=120) as response,
            output.open("xb") as destination,
        ):
            final_url = urlsplit(response.geturl())
            if (
                final_url.scheme != "https"
                or final_url.hostname is None
                or final_url.hostname.casefold() != "codeload.github.com"
                or final_url.username is not None
                or final_url.password is not None
            ):
                raise SourceLockError("archive download left the trusted codeload origin")
            copied = 0
            while chunk := response.read(CHUNK_SIZE):
                copied += len(chunk)
                if copied > MAX_ARCHIVE_BYTES:
                    raise SourceLockError("source archive exceeds the download limit")
                destination.write(chunk)
            destination.flush()
            os.fsync(destination.fileno())
    except SourceLockError:
        raise
    except (OSError, urllib.error.URLError) as exc:
        raise SourceLockError("source archive download failed") from exc


def cache_source_archive(
    package: GitPackage,
    cache_root: Path = DEFAULT_CACHE,
    *,
    source_url: str | None = None,
    allow_file_source: bool = False,
) -> tuple[Path, str]:
    target = cache_archive_path(cache_root, package)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if source_url is not None and not allow_file_source and source_url != package.archive_url:
        raise SourceLockError("production source override is not allowed")

    partial = target.with_name(f".{target.name}.{os.getpid()}.{uuid.uuid4().hex}.part")
    try:
        _copy_download(
            package.archive_url if source_url is None else source_url,
            partial,
            allow_file_source=allow_file_source,
        )
        archive_sha256 = validate_source_archive(partial, package)
        os.chmod(partial, 0o600)
        os.replace(partial, target)
        return target, archive_sha256
    finally:
        with suppress(OSError):
            partial.unlink(missing_ok=True)


def _write_lock_atomic(path: Path, document: Mapping[str, object]) -> None:
    content = (json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
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


def _resume_archive_hashes(
    manifest_sha256: str,
    packages: Sequence[GitPackage],
    lock_path: Path,
    cache_root: Path,
) -> dict[str, str | None]:
    candidates: dict[str, str | None] = {package.name: None for package in packages}
    if lock_path.is_file():
        try:
            document = _read_json(lock_path, label="source lock")
            candidates = validate_lock_document(
                document,
                manifest_sha256,
                packages,
                require_complete=False,
            )
        except SourceLockError:
            candidates = {package.name: None for package in packages}

    verified: dict[str, str | None] = {}
    for package in packages:
        expected_hash = candidates[package.name]
        if expected_hash is None:
            verified[package.name] = None
            continue
        try:
            actual_hash = validate_source_archive(cache_archive_path(cache_root, package), package)
        except SourceLockError:
            verified[package.name] = None
            continue
        verified[package.name] = expected_hash if actual_hash == expected_hash else None
    return verified


def update_source_lock(
    manifest_path: Path = DEFAULT_MANIFEST,
    lock_path: Path = DEFAULT_LOCK,
    cache_root: Path = DEFAULT_CACHE,
    *,
    source_urls: Mapping[str, str] | None = None,
    allow_file_sources: bool = False,
) -> tuple[GitPackage, ...]:
    manifest_sha256, packages = read_git_packages(manifest_path)
    archive_hashes = _resume_archive_hashes(
        manifest_sha256,
        packages,
        lock_path,
        cache_root,
    )
    for package in packages:
        if archive_hashes[package.name] is not None:
            continue
        source_url = None if source_urls is None else source_urls.get(package.name)
        _, archive_hash = cache_source_archive(
            package,
            cache_root,
            source_url=source_url,
            allow_file_source=allow_file_sources,
        )
        archive_hashes[package.name] = archive_hash
        _write_lock_atomic(
            lock_path,
            lock_document(manifest_sha256, packages, archive_hashes),
        )
    document = lock_document(manifest_sha256, packages, archive_hashes)
    validate_lock_document(document, manifest_sha256, packages)
    _write_lock_atomic(lock_path, document)
    return packages


def verify_cached_archives(
    manifest_path: Path = DEFAULT_MANIFEST,
    lock_path: Path = DEFAULT_LOCK,
    cache_root: Path = DEFAULT_CACHE,
) -> tuple[GitPackage, ...]:
    manifest_sha256, packages = read_git_packages(manifest_path)
    document = _read_json(lock_path, label="source lock")
    archive_hashes = validate_lock_document(document, manifest_sha256, packages)
    for package in packages:
        expected_hash = archive_hashes[package.name]
        archive_path = cache_archive_path(cache_root, package)
        actual_hash = validate_source_archive(archive_path, package)
        if actual_hash != expected_hash:
            raise SourceLockError(f"cached source archive SHA-256 differs for {package.name}")
    return packages


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--update",
        action="store_true",
        help="explicitly download, validate, and atomically replace the tracked lock",
    )
    parser.add_argument(
        "--verify-cache",
        action="store_true",
        help="also require every locked archive in the operator cache",
    )
    args = parser.parse_args(argv)
    if args.update and args.verify_cache:
        parser.error("--update and --verify-cache are mutually exclusive")
    return args


def main(argv: Sequence[str] | None = None) -> None:
    args = parse_args(argv)
    try:
        if args.update:
            packages = update_source_lock()
            print(f"mathlib source lock updated: {len(packages)} packages")
        elif args.verify_cache:
            packages = verify_cached_archives()
            print(f"mathlib source lock and cache valid: {len(packages)} packages")
        else:
            packages = check_source_lock()
            print(f"mathlib source lock valid: {len(packages)} packages")
    except SourceLockError as exc:
        raise SystemExit(f"mathlib source lock failed: {exc}") from None


if __name__ == "__main__":
    main()
