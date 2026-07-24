from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path
from typing import Any

import pytest

from scripts import mathlib_source_lock as source_lock


def _manifest_document() -> dict[str, Any]:
    return {
        "version": "1.1.0",
        "packages": [
            {
                "name": f"package{index}",
                "rev": f"{index:040x}",
                "type": "git",
                "url": f"https://github.com/example/repository{index}"
                + (".git" if index == 1 else ""),
            }
            for index in range(1, source_lock.EXPECTED_GIT_PACKAGES + 1)
        ],
    }


def _write_manifest(path: Path, document: dict[str, Any] | None = None) -> None:
    path.write_text(
        json.dumps(_manifest_document() if document is None else document),
        encoding="utf-8",
    )


def _package(index: int = 1) -> source_lock.GitPackage:
    rev = f"{index:040x}"
    return source_lock.GitPackage(
        name=f"package{index}",
        url=f"https://github.com/example/repository{index}",
        rev=rev,
        owner="example",
        repository=f"repository{index}",
        archive_url=f"https://codeload.github.com/example/repository{index}/tar.gz/{rev}",
    )


def _add_bytes(archive: tarfile.TarFile, name: str, content: bytes = b"source\n") -> None:
    member = tarfile.TarInfo(name)
    member.size = len(content)
    archive.addfile(member, io.BytesIO(content))


def _write_valid_archive(path: Path, package: source_lock.GitPackage) -> None:
    root = f"{package.repository}-{package.rev}"
    with tarfile.open(path, mode="w:gz") as archive:
        directory = tarfile.TarInfo(root)
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        _add_bytes(archive, f"{root}/lakefile.toml")
        symlink = tarfile.TarInfo(f"{root}/lakefile-link.toml")
        symlink.type = tarfile.SYMTYPE
        symlink.linkname = "lakefile.toml"
        archive.addfile(symlink)


def _write_archive_with_member(
    path: Path,
    package: source_lock.GitPackage,
    member: tarfile.TarInfo,
) -> None:
    root = f"{package.repository}-{package.rev}"
    with tarfile.open(path, mode="w:gz") as archive:
        directory = tarfile.TarInfo(root)
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        archive.addfile(member, io.BytesIO(b"x") if member.isfile() else None)
        _add_bytes(archive, f"{root}/valid.lean")


def _write_symlink_archive(
    path: Path,
    package: source_lock.GitPackage,
    *,
    member_name: str,
    target: str,
) -> None:
    root = f"{package.repository}-{package.rev}"
    with tarfile.open(path, mode="w:gz") as archive:
        directory = tarfile.TarInfo(root)
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        _add_bytes(archive, f"{root}/target")
        symlink = tarfile.TarInfo(member_name)
        symlink.type = tarfile.SYMTYPE
        symlink.linkname = target
        archive.addfile(symlink)


def test_manifest_requires_nine_unique_pinned_https_github_dependencies(tmp_path: Path) -> None:
    manifest = tmp_path / "lake-manifest.json"
    _write_manifest(manifest)

    manifest_sha256, packages = source_lock.read_git_packages(manifest)

    assert len(manifest_sha256) == 64
    assert len(packages) == 9
    assert packages[0].url.endswith(".git")
    assert (
        packages[0].archive_url
        == f"https://codeload.github.com/example/repository1/tar.gz/{1:040x}"
    )


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("url", "http://github.com/example/repository1", "HTTPS github.com"),
        ("url", "https://operator:secret@github.com/example/repository1", "credential-free"),
        ("url", "https://example.com/example/repository1", "HTTPS github.com"),
        ("url", "https://github.com:not-a-port/example/repository1", "invalid HTTPS authority"),
        ("rev", "main", "40-hex"),
        ("type", "path", "not a git"),
    ],
)
def test_manifest_rejects_unpinned_or_untrusted_package(
    tmp_path: Path,
    field: str,
    value: str,
    match: str,
) -> None:
    document = _manifest_document()
    document["packages"][0][field] = value
    manifest = tmp_path / "lake-manifest.json"
    _write_manifest(manifest, document)

    with pytest.raises(source_lock.SourceLockError, match=match):
        source_lock.read_git_packages(manifest)


def test_manifest_rejects_case_insensitive_duplicate_names(tmp_path: Path) -> None:
    document = _manifest_document()
    document["packages"][1]["name"] = "PACKAGE1"
    manifest = tmp_path / "lake-manifest.json"
    _write_manifest(manifest, document)

    with pytest.raises(source_lock.SourceLockError, match="not unique"):
        source_lock.read_git_packages(manifest)


def test_tracked_source_lock_is_complete_and_default_check_passes() -> None:
    manifest_sha256, packages = source_lock.read_git_packages(source_lock.DEFAULT_MANIFEST)
    document = json.loads(source_lock.DEFAULT_LOCK.read_text(encoding="utf-8"))

    hashes = source_lock.validate_lock_document(document, manifest_sha256, packages)

    assert document["state"] == "complete"
    assert len(hashes) == 9
    assert all(
        isinstance(archive_hash, str) and len(archive_hash) == 64
        for archive_hash in hashes.values()
    )
    assert source_lock.check_source_lock() == packages


def test_synthetic_incomplete_lock_is_descriptive_but_not_release_ready() -> None:
    manifest_sha256, packages = source_lock.read_git_packages(source_lock.DEFAULT_MANIFEST)
    archive_hashes: dict[str, str | None] = {package.name: "a" * 64 for package in packages}
    archive_hashes[packages[0].name] = None
    document = source_lock.lock_document(manifest_sha256, packages, archive_hashes)

    validated_hashes = source_lock.validate_lock_document(
        document,
        manifest_sha256,
        packages,
        require_complete=False,
    )

    assert document["state"] == "incomplete"
    assert validated_hashes[packages[0].name] is None
    assert all(validated_hashes[package.name] is not None for package in packages[1:])
    with pytest.raises(source_lock.SourceLockError, match="explicit --update"):
        source_lock.validate_lock_document(document, manifest_sha256, packages)


def test_offline_update_uses_local_archives_and_atomically_completes_lock(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "lake-manifest.json"
    lock = tmp_path / "mathlib-source-lock.v1.json"
    cache = tmp_path / "operator-cache"
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    _write_manifest(manifest)
    _, packages = source_lock.read_git_packages(manifest)
    source_urls: dict[str, str] = {}
    for package in packages:
        archive = fixtures / f"{package.name}.tar.gz"
        _write_valid_archive(archive, package)
        source_urls[package.name] = archive.resolve().as_uri()

    updated = source_lock.update_source_lock(
        manifest,
        lock,
        cache,
        source_urls=source_urls,
        allow_file_sources=True,
    )

    assert updated == packages
    source_lock.check_source_lock(manifest, lock)
    source_lock.verify_cached_archives(manifest, lock, cache)
    document = json.loads(lock.read_text(encoding="utf-8"))
    assert document["state"] == "complete"
    assert all(record["archive_sha256"] for record in document["packages"])
    assert len(list(cache.rglob("*.tar.gz"))) == 9
    assert not list(cache.rglob("*.part"))


def test_file_source_is_never_enabled_by_default(tmp_path: Path) -> None:
    package = _package()
    archive = tmp_path / "fixture.tar.gz"
    _write_valid_archive(archive, package)

    with pytest.raises(source_lock.SourceLockError, match="not allowed"):
        source_lock.cache_source_archive(
            package,
            tmp_path / "cache",
            source_url=archive.resolve().as_uri(),
        )

    assert not list((tmp_path / "cache").rglob("*.part"))


def test_explicit_update_does_not_trust_an_unbound_existing_cache(tmp_path: Path) -> None:
    package = _package()
    cache = tmp_path / "cache"
    cached = source_lock.cache_archive_path(cache, package)
    cached.parent.mkdir(parents=True)
    _write_valid_archive(cached, package)
    previous_hash = source_lock.sha256_file(cached)
    source = tmp_path / "replacement.tar.gz"
    root = f"{package.repository}-{package.rev}"
    with tarfile.open(source, mode="w:gz") as archive:
        _add_bytes(archive, f"{root}/different.lean", b"different source bytes\n")

    _, updated_hash = source_lock.cache_source_archive(
        package,
        cache,
        source_url=source.resolve().as_uri(),
        allow_file_source=True,
    )

    assert updated_hash != previous_hash
    assert source_lock.sha256_file(cached) == updated_hash


def test_production_source_override_is_rejected_before_network_access(tmp_path: Path) -> None:
    with pytest.raises(source_lock.SourceLockError, match="override"):
        source_lock.cache_source_archive(
            _package(),
            tmp_path / "cache",
            source_url="https://codeload.github.com/example/other/tar.gz/" + "a" * 40,
        )


@pytest.mark.parametrize(
    "unsafe_name",
    [
        "/absolute.lean",
        "../escape.lean",
        "{root}/.git/config",
        "{root}/.GIT/config",
        "{root}/.lake/build/output.lean",
        "{root}/.lake/config/context.json",
        "{root}/compiled.olean",
        "{root}/compiled.ilean",
    ],
)
def test_archive_rejects_unsafe_or_generated_member(
    tmp_path: Path,
    unsafe_name: str,
) -> None:
    package = _package()
    root = f"{package.repository}-{package.rev}"
    member = tarfile.TarInfo(unsafe_name.format(root=root))
    member.size = 1
    archive_path = tmp_path / "unsafe.tar.gz"
    _write_archive_with_member(archive_path, package, member)

    with pytest.raises(source_lock.SourceLockError):
        source_lock.validate_source_archive(archive_path, package)


@pytest.mark.parametrize("kind", [tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE])
def test_archive_rejects_hard_links_and_special_files(
    tmp_path: Path,
    kind: bytes,
) -> None:
    package = _package()
    root = f"{package.repository}-{package.rev}"
    member = tarfile.TarInfo(f"{root}/unsafe")
    member.type = kind
    if kind == tarfile.LNKTYPE:
        member.linkname = f"{root}/valid.lean"
    if kind == tarfile.CHRTYPE:
        member.devmajor = 1
        member.devminor = 1
    archive_path = tmp_path / "unsafe.tar.gz"
    _write_archive_with_member(archive_path, package, member)

    with pytest.raises(source_lock.SourceLockError):
        source_lock.validate_source_archive(archive_path, package)


@pytest.mark.parametrize("target", ["/outside", "../outside", r"..\outside"])
def test_archive_rejects_unsafe_symlink_target(tmp_path: Path, target: str) -> None:
    package = _package()
    root = f"{package.repository}-{package.rev}"
    member = tarfile.TarInfo(f"{root}/link")
    member.type = tarfile.SYMTYPE
    member.linkname = target
    archive_path = tmp_path / "unsafe.tar.gz"
    _write_archive_with_member(archive_path, package, member)

    with pytest.raises(source_lock.SourceLockError, match="symlink target"):
        source_lock.validate_source_archive(archive_path, package)


def test_archive_accepts_symlink_parent_traversal_within_archive_root(tmp_path: Path) -> None:
    package = _package()
    root = f"{package.repository}-{package.rev}"
    archive_path = tmp_path / "safe-symlink.tar.gz"
    _write_symlink_archive(
        archive_path,
        package,
        member_name=f"{root}/subdir/link",
        target="../target",
    )

    assert len(source_lock.validate_source_archive(archive_path, package)) == 64


def test_archive_rejects_symlink_that_normalizes_above_archive_root(tmp_path: Path) -> None:
    package = _package()
    root = f"{package.repository}-{package.rev}"
    archive_path = tmp_path / "escaping-symlink.tar.gz"
    _write_symlink_archive(
        archive_path,
        package,
        member_name=f"{root}/subdir/link",
        target="../../outside",
    )

    with pytest.raises(source_lock.SourceLockError, match="escapes"):
        source_lock.validate_source_archive(archive_path, package)


@pytest.mark.parametrize("target", ["../.GIT/config", "../.lake/build/output"])
def test_archive_rejects_symlink_normalized_into_forbidden_tree(
    tmp_path: Path,
    target: str,
) -> None:
    package = _package()
    root = f"{package.repository}-{package.rev}"
    archive_path = tmp_path / "forbidden-symlink.tar.gz"
    _write_symlink_archive(
        archive_path,
        package,
        member_name=f"{root}/subdir/link",
        target=target,
    )

    with pytest.raises(source_lock.SourceLockError):
        source_lock.validate_source_archive(archive_path, package)


def test_failed_update_preserves_progress_and_resume_downloads_only_remaining(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = tmp_path / "lake-manifest.json"
    lock = tmp_path / "mathlib-source-lock.v1.json"
    cache = tmp_path / "operator-cache"
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    _write_manifest(manifest)
    _, packages = source_lock.read_git_packages(manifest)
    source_urls: dict[str, str] = {}
    for package in packages:
        archive = fixtures / f"{package.name}.tar.gz"
        _write_valid_archive(archive, package)
        source_urls[package.name] = archive.resolve().as_uri()
    failure_index = 3
    failed_package = packages[failure_index]
    malicious = fixtures / f"{failed_package.name}.tar.gz"
    root = f"{failed_package.repository}-{failed_package.rev}"
    bad_member = tarfile.TarInfo(f"{root}/proof.olean")
    bad_member.size = 1
    _write_archive_with_member(malicious, failed_package, bad_member)
    copied_sources: list[str] = []
    original_copy = source_lock._copy_download

    def record_copy(source_url: str, output: Path, *, allow_file_source: bool) -> None:
        copied_sources.append(source_url)
        original_copy(source_url, output, allow_file_source=allow_file_source)

    monkeypatch.setattr(source_lock, "_copy_download", record_copy)

    with pytest.raises(source_lock.SourceLockError):
        source_lock.update_source_lock(
            manifest,
            lock,
            cache,
            source_urls=source_urls,
            allow_file_sources=True,
        )

    partial_document = json.loads(lock.read_text(encoding="utf-8"))
    partial_hashes = [record["archive_sha256"] for record in partial_document["packages"]]
    assert partial_document["state"] == "incomplete"
    assert all(partial_hashes[index] is not None for index in range(failure_index))
    assert all(partial_hashes[index] is None for index in range(failure_index, len(packages)))
    assert copied_sources == [
        source_urls[package.name] for package in packages[: failure_index + 1]
    ]
    assert not list(cache.rglob("*.part"))

    _write_valid_archive(malicious, failed_package)
    copied_sources.clear()
    source_lock.update_source_lock(
        manifest,
        lock,
        cache,
        source_urls=source_urls,
        allow_file_sources=True,
    )

    assert copied_sources == [source_urls[package.name] for package in packages[failure_index:]]
    completed_document = json.loads(lock.read_text(encoding="utf-8"))
    assert completed_document["state"] == "complete"
    assert [
        record["archive_sha256"] for record in completed_document["packages"][:failure_index]
    ] == partial_hashes[:failure_index]
    assert not list(cache.rglob("*.part"))


def test_resume_does_not_reuse_cache_for_null_lock_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = tmp_path / "lake-manifest.json"
    lock = tmp_path / "mathlib-source-lock.v1.json"
    cache = tmp_path / "operator-cache"
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    _write_manifest(manifest)
    manifest_sha256, packages = source_lock.read_git_packages(manifest)
    source_urls: dict[str, str] = {}
    for package in packages:
        archive = fixtures / f"{package.name}.tar.gz"
        _write_valid_archive(archive, package)
        source_urls[package.name] = archive.resolve().as_uri()
    unbound_cache = source_lock.cache_archive_path(cache, packages[0])
    unbound_cache.parent.mkdir(parents=True)
    _write_valid_archive(unbound_cache, packages[0])
    lock.write_text(
        json.dumps(
            source_lock.lock_document(
                manifest_sha256,
                packages,
                {package.name: None for package in packages},
            )
        ),
        encoding="utf-8",
    )
    copied_sources: list[str] = []
    original_copy = source_lock._copy_download

    def record_copy(source_url: str, output: Path, *, allow_file_source: bool) -> None:
        copied_sources.append(source_url)
        original_copy(source_url, output, allow_file_source=allow_file_source)

    monkeypatch.setattr(source_lock, "_copy_download", record_copy)

    source_lock.update_source_lock(
        manifest,
        lock,
        cache,
        source_urls=source_urls,
        allow_file_sources=True,
    )

    assert copied_sources == [source_urls[package.name] for package in packages]


def test_resume_redownloads_only_bound_cache_with_wrong_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = tmp_path / "lake-manifest.json"
    lock = tmp_path / "mathlib-source-lock.v1.json"
    cache = tmp_path / "operator-cache"
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    _write_manifest(manifest)
    _, packages = source_lock.read_git_packages(manifest)
    source_urls: dict[str, str] = {}
    for package in packages:
        archive = fixtures / f"{package.name}.tar.gz"
        _write_valid_archive(archive, package)
        source_urls[package.name] = archive.resolve().as_uri()
    source_lock.update_source_lock(
        manifest,
        lock,
        cache,
        source_urls=source_urls,
        allow_file_sources=True,
    )
    damaged_package = packages[2]
    source_lock.cache_archive_path(cache, damaged_package).write_bytes(b"damaged")
    copied_sources: list[str] = []
    original_copy = source_lock._copy_download

    def record_copy(source_url: str, output: Path, *, allow_file_source: bool) -> None:
        copied_sources.append(source_url)
        original_copy(source_url, output, allow_file_source=allow_file_source)

    monkeypatch.setattr(source_lock, "_copy_download", record_copy)

    source_lock.update_source_lock(
        manifest,
        lock,
        cache,
        source_urls=source_urls,
        allow_file_sources=True,
    )

    assert copied_sources == [source_urls[damaged_package.name]]
    source_lock.verify_cached_archives(manifest, lock, cache)


def test_cached_archive_hash_mismatch_fails_closed(tmp_path: Path) -> None:
    manifest = tmp_path / "lake-manifest.json"
    lock = tmp_path / "mathlib-source-lock.v1.json"
    cache = tmp_path / "operator-cache"
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    _write_manifest(manifest)
    _, packages = source_lock.read_git_packages(manifest)
    source_urls: dict[str, str] = {}
    for package in packages:
        archive = fixtures / f"{package.name}.tar.gz"
        _write_valid_archive(archive, package)
        source_urls[package.name] = archive.resolve().as_uri()
    source_lock.update_source_lock(
        manifest,
        lock,
        cache,
        source_urls=source_urls,
        allow_file_sources=True,
    )
    cached = source_lock.cache_archive_path(cache, packages[0])
    cached.write_bytes(b"tampered")

    with pytest.raises(source_lock.SourceLockError):
        source_lock.verify_cached_archives(manifest, lock, cache)


def test_cli_defaults_to_check_and_requires_explicit_update() -> None:
    assert source_lock.parse_args([]).update is False
    assert source_lock.parse_args(["--update"]).update is True
