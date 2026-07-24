from __future__ import annotations

import io
import json
import tarfile
from dataclasses import replace
from pathlib import Path

import pytest

from scripts import mathlib_build_resources as resources


def _write_manifest(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "packages": [
                    {
                        "configFile": "lakefile.lean",
                        "inputRev": resources.RELEASE_TAG,
                        "name": resources.PACKAGE_NAME,
                        "rev": resources.SOURCE_REVISION,
                        "type": "git",
                        "url": resources.SOURCE_URL,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )


def _add_file(
    archive: tarfile.TarFile,
    name: str,
    content: bytes,
) -> None:
    member = tarfile.TarInfo(name)
    member.size = len(content)
    archive.addfile(member, io.BytesIO(content))


def _write_fixture_asset(path: Path) -> dict[str, bytes]:
    selected = {
        "js/interactiveExpr.js": b"export default function interactiveExpr() {}\n",
        "js/lake.trace": b'{"outputs":[]}\n',
    }
    with tarfile.open(path, mode="w:gz") as archive:
        for name in ("./", "./js/", "./lib/", "./ir/"):
            directory = tarfile.TarInfo(name)
            directory.type = tarfile.DIRTYPE
            archive.addfile(directory)
        for name, content in selected.items():
            _add_file(archive, f"./{name}", content)
        _add_file(archive, "./lib/lean/ProofWidgets.olean", b"compiled Lean")
        _add_file(archive, "./ir/ProofWidgets.c", b"generated C")
        _add_file(archive, "./native.so", b"native output")
    return selected


def _fixture_spec(path: Path, selected: dict[str, bytes]) -> resources.ResourceSpec:
    return replace(
        resources.EXPECTED_RESOURCE,
        asset_name=path.name,
        asset_url="https://github.com/example/releases/download/v1/fixture.tar.gz",
        asset_size=path.stat().st_size,
        asset_sha256=resources.sha256_file(path),
        asset_regular_file_count=5,
        asset_directory_count=4,
        js_file_count=len(selected),
        js_unpacked_bytes=sum(len(content) for content in selected.values()),
    )


def test_pruning_writes_only_bound_regular_js_inventory(tmp_path: Path) -> None:
    asset = tmp_path / "fixture.tar.gz"
    selected = _write_fixture_asset(asset)
    spec = _fixture_spec(asset, selected)

    pruned = resources.validate_and_prune_asset(
        asset,
        spec,
        expected_js_manifest_sha256=None,
    )
    inventory = resources.write_pruned_js(tmp_path / "context-resource", pruned)

    assert pruned.file_count == 2
    assert pruned.unpacked_bytes == sum(len(content) for content in selected.values())
    assert set(inventory) == set(selected)
    assert set((tmp_path / "context-resource").rglob("*")) == {
        tmp_path / "context-resource" / "js",
        tmp_path / "context-resource" / "js" / "interactiveExpr.js",
        tmp_path / "context-resource" / "js" / "lake.trace",
    }
    assert b"ProofWidgets.olean" not in pruned.manifest
    assert b"ProofWidgets.c" not in pruned.manifest
    assert b"native.so" not in pruned.manifest


def test_tracked_build_resource_lock_is_complete_and_project_bound() -> None:
    locked = resources.read_lock()

    assert locked is not None
    assert locked.spec.source_revision == resources.SOURCE_REVISION
    assert locked.spec.release_tag == resources.RELEASE_TAG
    assert locked.spec.asset_sha256 == resources.ASSET_SHA256
    assert locked.js_manifest_sha256 == (
        "f40d87505c4016791e7196c641ec7a20797439cf0146163562888d2a84550f7d"
    )


@pytest.mark.parametrize(
    ("member_name", "member_type"),
    [
        ("../escape.js", tarfile.REGTYPE),
        ("./js/../../escape.js", tarfile.REGTYPE),
        ("./js/link.js", tarfile.SYMTYPE),
        ("./js/hard.js", tarfile.LNKTYPE),
        ("./js/device", tarfile.CHRTYPE),
    ],
)
def test_release_archive_rejects_traversal_links_and_special_files(
    tmp_path: Path,
    member_name: str,
    member_type: bytes,
) -> None:
    asset = tmp_path / "unsafe.tar.gz"
    with tarfile.open(asset, mode="w:gz") as archive:
        member = tarfile.TarInfo(member_name)
        member.type = member_type
        if member_type == tarfile.REGTYPE:
            member.size = 1
            archive.addfile(member, io.BytesIO(b"x"))
        else:
            member.linkname = "interactiveExpr.js"
            archive.addfile(member)
    spec = replace(
        resources.EXPECTED_RESOURCE,
        asset_name=asset.name,
        asset_size=asset.stat().st_size,
        asset_sha256=resources.sha256_file(asset),
        asset_regular_file_count=1 if member_type == tarfile.REGTYPE else 0,
        asset_directory_count=0,
        js_file_count=0,
        js_unpacked_bytes=0,
    )

    with pytest.raises(resources.BuildResourceError):
        resources.validate_and_prune_asset(
            asset,
            spec,
            expected_js_manifest_sha256=None,
        )


def test_asset_hash_count_and_inventory_hash_are_independent_gates(
    tmp_path: Path,
) -> None:
    asset = tmp_path / "fixture.tar.gz"
    selected = _write_fixture_asset(asset)
    spec = _fixture_spec(asset, selected)
    pruned = resources.validate_and_prune_asset(
        asset,
        spec,
        expected_js_manifest_sha256=None,
    )

    with pytest.raises(resources.BuildResourceError, match="SHA-256"):
        resources.validate_and_prune_asset(
            asset,
            replace(spec, asset_sha256="0" * 64),
            expected_js_manifest_sha256=None,
        )
    with pytest.raises(resources.BuildResourceError, match="file count"):
        resources.validate_and_prune_asset(
            asset,
            replace(spec, js_file_count=3),
            expected_js_manifest_sha256=None,
        )
    with pytest.raises(resources.BuildResourceError, match="manifest SHA-256"):
        resources.validate_and_prune_asset(
            asset,
            spec,
            expected_js_manifest_sha256="0" * 64,
        )
    assert len(pruned.manifest_sha256) == 64


def test_lock_is_read_only_by_default_and_update_binds_operator_cache(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "lake-manifest.json"
    lock = tmp_path / "mathlib-build-resource-lock.v1.json"
    cache = tmp_path / "operator-cache"
    asset = tmp_path / "fixture.tar.gz"
    _write_manifest(manifest)
    selected = _write_fixture_asset(asset)
    spec = _fixture_spec(asset, selected)
    lock.write_bytes(resources._canonical_json_bytes(resources.lock_document(spec, None)))

    with pytest.raises(resources.BuildResourceError, match="explicit --update"):
        resources.read_lock(manifest, lock, spec)
    assert not cache.exists()

    locked = resources.update_resource_lock(
        manifest,
        lock,
        cache,
        spec,
        source_url=asset.resolve().as_uri(),
        allow_file_source=True,
    )
    cached = resources.cache_asset_path(cache, spec)

    assert cached.is_file()
    assert locked.js_manifest_sha256 == (
        resources.verify_cached_resource(manifest, lock, cache, spec).manifest_sha256
    )
    document = json.loads(lock.read_text(encoding="utf-8"))
    assert document["state"] == "complete"
    assert resources.read_lock(manifest, lock, spec) == locked

    cached.write_bytes(b"tampered")
    with pytest.raises(resources.BuildResourceError):
        resources.verify_cached_resource(manifest, lock, cache, spec)


def test_unbound_cache_is_not_reused_during_explicit_update(tmp_path: Path) -> None:
    manifest = tmp_path / "lake-manifest.json"
    lock = tmp_path / "mathlib-build-resource-lock.v1.json"
    cache = tmp_path / "operator-cache"
    asset = tmp_path / "fixture.tar.gz"
    _write_manifest(manifest)
    selected = _write_fixture_asset(asset)
    spec = _fixture_spec(asset, selected)
    cached = resources.cache_asset_path(cache, spec)
    cached.parent.mkdir(parents=True)
    cached.write_bytes(asset.read_bytes())
    lock.write_bytes(resources._canonical_json_bytes(resources.lock_document(spec, None)))
    cached.write_bytes(b"unbound bytes")

    resources.update_resource_lock(
        manifest,
        lock,
        cache,
        spec,
        source_url=asset.resolve().as_uri(),
        allow_file_source=True,
    )

    assert resources.sha256_file(cached) == spec.asset_sha256
    assert not list(cache.rglob("*.part"))


def test_file_source_and_update_are_never_enabled_by_default(tmp_path: Path) -> None:
    asset = tmp_path / "fixture.tar.gz"
    selected = _write_fixture_asset(asset)
    spec = _fixture_spec(asset, selected)

    with pytest.raises(resources.BuildResourceError, match=r"not allowed|disabled"):
        resources._cache_download(
            tmp_path / "cache",
            spec,
            source_url=asset.resolve().as_uri(),
            allow_file_source=False,
        )

    assert resources.parse_args([]).update is False
    assert resources.parse_args(["--update"]).update is True
