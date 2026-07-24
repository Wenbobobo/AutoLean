from __future__ import annotations

import hashlib
import json
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import BinaryIO

import pytest
from autolean_builder import (
    DownloadObservation,
    ReferenceCache,
    ReferenceCacheError,
    ReferenceEntryV1,
    ReferenceManifestV1,
)

from scripts import reference_cache as reference_cache_cli

_PARENT_ID = "official-reference-pdf-v1"
_TEXT_ID = "official-reference-text-v1"
_PARENT_BYTES = b"%PDF-1.7\nparent source artifact\n"
_TEXT_BYTES = b"Introduction\nCurvature is alternating.\nConclusion\n"
_ATTRIBUTION = "Official reference by Example Author, CC BY-SA 4.0."


def _entry_payload(
    *,
    reference_id: str,
    data: bytes,
    media_type: str,
    extension: str,
    artifact_kind: str,
    derivation: dict[str, object] | None,
) -> dict[str, object]:
    return {
        "reference_id": reference_id,
        "title": "Official reference",
        "authors": ["Example Author"],
        "version": "published-1",
        "citation": "Example Author, Official reference.",
        "source_record_url": "https://example.invalid/record",
        "download_url": f"https://example.invalid/{reference_id}{extension}",
        "allowed_redirect_urls": [],
        "media_type": media_type,
        "file_extension": extension,
        "size_bytes": len(data),
        "max_bytes": len(data) + 10,
        "sha256": hashlib.sha256(data).hexdigest(),
        "retrieved_at": "2026-07-23T12:00:00Z",
        "license": {
            "expression": "CC-BY-SA-4.0",
            "url": "https://creativecommons.org/licenses/by-sa/4.0/",
            "evidence_url": "https://example.invalid/record",
        },
        "access_policy": "public_open_access",
        "acquisition_policy": "operator_only",
        "model_egress_policy": "local_only",
        "artifact_kind": artifact_kind,
        "derivation": derivation,
        "attribution": _ATTRIBUTION,
    }


def _manifest_payload() -> dict[str, object]:
    return {
        "schema_version": "autolean.reference-manifest.v1",
        "entries": [
            _entry_payload(
                reference_id=_PARENT_ID,
                data=_PARENT_BYTES,
                media_type="application/pdf",
                extension=".pdf",
                artifact_kind="source_document",
                derivation=None,
            ),
            _entry_payload(
                reference_id=_TEXT_ID,
                data=_TEXT_BYTES,
                media_type="text/plain",
                extension=".txt",
                artifact_kind="derived_text",
                derivation={
                    "kind": "repository_text_extraction",
                    "parent_reference_id": _PARENT_ID,
                    "parent_sha256": hashlib.sha256(_PARENT_BYTES).hexdigest(),
                    "producer": "Official repository",
                    "method": "repository_provided_text_bitstream",
                    "tool_name": None,
                    "tool_version": None,
                    "provenance_url": "https://example.invalid/record",
                    "parent_locator_authority": "human_declared",
                },
            ),
        ],
    }


def _manifest(
    tmp_path: Path,
    *,
    payload: dict[str, object] | None = None,
) -> ReferenceManifestV1:
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(payload or _manifest_payload()), encoding="utf-8")
    return ReferenceManifestV1.load(path)


def _downloader(
    *,
    final_url: str | None = None,
    media_type: str | None = None,
    network_used: bool = True,
) -> Callable[[ReferenceEntryV1, BinaryIO], DownloadObservation]:
    data_by_id = {_PARENT_ID: _PARENT_BYTES, _TEXT_ID: _TEXT_BYTES}

    def download(entry: ReferenceEntryV1, destination: BinaryIO) -> DownloadObservation:
        destination.write(data_by_id[entry.reference_id])
        return DownloadObservation(
            final_url=final_url or entry.download_url,
            media_type=media_type or entry.media_type,
            network_used=network_used,
        )

    return download


def _cache(
    tmp_path: Path,
    *,
    downloader: Callable[[ReferenceEntryV1, BinaryIO], DownloadObservation] | None = None,
) -> ReferenceCache:
    return ReferenceCache(
        _manifest(tmp_path),
        tmp_path / "cache",
        confinement_root=tmp_path,
        downloader=downloader or _downloader(),
    )


def test_operator_fetch_uses_content_addressed_path_and_observed_network_flag(
    tmp_path: Path,
) -> None:
    cache = _cache(tmp_path)

    first = cache.operator_fetch(_PARENT_ID)
    expected = tmp_path / "cache" / _PARENT_ID / f"{hashlib.sha256(_PARENT_BYTES).hexdigest()}.pdf"
    assert first.verified.cache_path == expected
    assert first.verified.cache_path.read_bytes() == _PARENT_BYTES
    assert first.network_used is True

    offline_hit = ReferenceCache(
        cache.manifest,
        tmp_path / "cache",
        confinement_root=tmp_path,
        downloader=lambda _entry, _destination: pytest.fail("acquisition path was used"),
    ).operator_fetch(_PARENT_ID)
    assert offline_hit.network_used is False
    assert offline_hit.verified.cache_ref.startswith("reference-cache:sha256:")


def test_fetch_uses_downloader_observation_instead_of_assuming_network(
    tmp_path: Path,
) -> None:
    result = _cache(tmp_path, downloader=_downloader(network_used=False)).operator_fetch(_PARENT_ID)
    assert result.network_used is False
    receipt = json.loads(result.render_receipt(verified_at=result.verified.entry.retrieved_at))
    assert receipt["network_used"] is False


def test_unmanifested_reference_cannot_select_a_url(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    with pytest.raises(ReferenceCacheError, match="not manifest-allowlisted"):
        cache.operator_fetch("https://attacker.invalid/file")


def test_fetch_rejects_unallowlisted_final_url_and_removes_unique_partial(
    tmp_path: Path,
) -> None:
    cache = _cache(
        tmp_path,
        downloader=_downloader(final_url="https://mirror.invalid/reference.pdf"),
    )
    with pytest.raises(ReferenceCacheError, match="absent from the manifest"):
        cache.operator_fetch(_PARENT_ID)
    assert not list((tmp_path / "cache").rglob(".operator-download-*.part"))
    assert not cache.path_for(_PARENT_ID).exists()


def test_verify_rejects_tampered_cached_bytes(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    verified = cache.operator_fetch(_PARENT_ID).verified
    verified.cache_path.write_bytes(b"tampered!")
    with pytest.raises(ReferenceCacheError, match=r"size mismatch|hash mismatch"):
        cache.verify(_PARENT_ID)


def test_manifest_rejects_duplicate_keys_and_non_https_downloads(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"schema_version":"autolean.reference-manifest.v1",'
        '"schema_version":"autolean.reference-manifest.v1","entries":[]}',
        encoding="utf-8",
    )
    with pytest.raises(ReferenceCacheError, match="duplicate JSON key"):
        ReferenceManifestV1.load(duplicate)

    payload = _manifest_payload()
    entries = payload["entries"]
    assert isinstance(entries, list)
    parent = entries[0]
    assert isinstance(parent, dict)
    parent["download_url"] = "http://example.invalid/reference.pdf"
    with pytest.raises(ReferenceCacheError, match="must be an HTTPS URL"):
        _manifest(tmp_path, payload=payload)


@pytest.mark.parametrize(
    "url",
    (
        "https://127.0.0.1/reference.pdf",
        "https://127.1/reference.pdf",
        "https://127.0.1/reference.pdf",
        "https://0177.0.0.1/reference.pdf",
        "https://0x7f.1/reference.pdf",
        "https://2130706433/reference.pdf",
        "https://\uff11\uff12\uff17\uff0e\uff10\uff0e\uff10\uff0e\uff11/reference.pdf",
        "https://127\u30020\u30020\u30021/reference.pdf",
        "https://0177\uff0e0\uff0e0\uff0e1/reference.pdf",
        "https://10.0.0.1/reference.pdf",
        "https://169.254.169.254/reference.pdf",
        "https://192.0.2.1/reference.pdf",
        "https://224.0.0.1/reference.pdf",
        "https://[ff02::1]/reference.pdf",
        "https://[::1]/reference.pdf",
        "https://localhost/reference.pdf",
        "https://example.invalid:8443/reference.pdf",
    ),
)
def test_manifest_rejects_private_reserved_local_and_explicit_port_urls(
    tmp_path: Path,
    url: str,
) -> None:
    payload = _manifest_payload()
    entries = payload["entries"]
    assert isinstance(entries, list)
    parent = entries[0]
    assert isinstance(parent, dict)
    parent["download_url"] = url
    with pytest.raises(
        ReferenceCacheError,
        match=r"cannot target|cannot use|explicit ports|local hostname|ASCII characters",
    ):
        _manifest(tmp_path, payload=payload)


def test_manifest_rejects_acquisition_query_tokens(tmp_path: Path) -> None:
    payload = _manifest_payload()
    entries = payload["entries"]
    assert isinstance(entries, list)
    parent = entries[0]
    assert isinstance(parent, dict)
    parent["download_url"] = "https://example.invalid/reference.pdf?token=operator-secret"

    with pytest.raises(ReferenceCacheError, match="without credentials, queries"):
        _manifest(tmp_path, payload=payload)


def test_manifest_requires_typed_parent_digest_and_provenance(tmp_path: Path) -> None:
    payload = _manifest_payload()
    entries = payload["entries"]
    assert isinstance(entries, list)
    derived = entries[1]
    assert isinstance(derived, dict)
    derivation = derived["derivation"]
    assert isinstance(derivation, dict)
    derivation["parent_sha256"] = "0" * 64
    with pytest.raises(ReferenceCacheError, match="parent digest"):
        _manifest(tmp_path, payload=payload)


def test_manifest_requires_a_pinned_local_pdf_text_recipe(tmp_path: Path) -> None:
    payload = _manifest_payload()
    entries = payload["entries"]
    assert isinstance(entries, list)
    derived = entries[1]
    assert isinstance(derived, dict)
    derivation = derived["derivation"]
    assert isinstance(derivation, dict)
    derived.update(
        {
            "download_url": None,
            "acquisition_policy": "local_derivation_only",
        }
    )
    derivation.update(
        {
            "kind": "local_pdf_text_extraction",
            "method": "pypdf-pdfreader-extract-text-plain-form-feed-v1",
            "tool_name": "pypdf",
            "tool_version": "6.10.0",
            "parent_locator_authority": "manifest_bound",
        }
    )

    manifest = _manifest(tmp_path, payload=payload)
    assert manifest.require(_TEXT_ID).download_url is None

    derivation["tool_version"] = None
    with pytest.raises(ReferenceCacheError, match="pinned tool version"):
        _manifest(tmp_path, payload=payload)


def test_operator_import_local_requires_the_manifested_bytes(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    bootstrap = tmp_path / "bootstrap.pdf"
    bootstrap.write_bytes(_PARENT_BYTES)

    result = cache.operator_import_local(_PARENT_ID, bootstrap)

    assert result.network_used is False
    assert result.verified.cache_path.read_bytes() == _PARENT_BYTES
    bootstrap.write_bytes(b"tampered bootstrap")
    with pytest.raises(ReferenceCacheError, match=r"size mismatch|hash mismatch"):
        cache.operator_import_local(_PARENT_ID, bootstrap, refresh=True)


def test_verify_utf8_span_digest_binds_private_source_bytes(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    cache.operator_fetch(_TEXT_ID)
    start = _TEXT_BYTES.index(b"Curvature")
    end = start + len(b"Curvature is alternating.")

    verified = cache.verify_utf8_span_digest(
        _TEXT_ID,
        start_offset=start,
        end_offset=end,
        expected_sha256=hashlib.sha256(_TEXT_BYTES[start:end]).hexdigest(),
    )

    assert verified.entry.reference_id == _TEXT_ID
    with pytest.raises(ReferenceCacheError, match="declared digest"):
        cache.verify_utf8_span_digest(
            _TEXT_ID,
            start_offset=start,
            end_offset=end,
            expected_sha256="0" * 64,
        )


def test_cache_rejects_symlink_child_escape(tmp_path: Path) -> None:
    cache_root = tmp_path / "cache"
    cache_root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    child = cache_root / _PARENT_ID
    try:
        child.symlink_to(outside, target_is_directory=True)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"directory symlink unavailable: {error}")
    cache = ReferenceCache(
        _manifest(tmp_path),
        cache_root,
        confinement_root=tmp_path,
        downloader=_downloader(),
    )
    with pytest.raises(ReferenceCacheError, match="symlinks or junctions"):
        cache.operator_fetch(_PARENT_ID)
    assert not list(outside.iterdir())


def test_concurrent_operator_fetch_downloads_once_and_reports_actual_observation(
    tmp_path: Path,
) -> None:
    call_count = 0
    count_lock = threading.Lock()

    def slow_download(
        entry: ReferenceEntryV1,
        destination: BinaryIO,
    ) -> DownloadObservation:
        nonlocal call_count
        with count_lock:
            call_count += 1
        time.sleep(0.05)
        destination.write(_PARENT_BYTES)
        return DownloadObservation(
            final_url=entry.download_url,
            media_type=entry.media_type,
            network_used=True,
        )

    cache = _cache(tmp_path, downloader=slow_download)
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _index: cache.operator_fetch(_PARENT_ID), range(2)))

    assert call_count == 1
    assert sorted(result.network_used for result in results) == [False, True]
    assert {result.verified.entry.sha256 for result in results} == {
        hashlib.sha256(_PARENT_BYTES).hexdigest()
    }
    assert not list((tmp_path / "cache").rglob(".operator-download-*.part"))


@pytest.mark.parametrize("forbidden", ("--manifest", "--cache-root", "--receipt"))
def test_cli_does_not_accept_arbitrary_manifest_cache_or_receipt_paths(
    forbidden: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as raised:
        reference_cache_cli.main(["list", forbidden, "attacker-path"])
    assert raised.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err


def test_cli_manifest_sha_binding_matches_the_tracked_manifest() -> None:
    manifest = ReferenceManifestV1.load(
        reference_cache_cli._TRACKED_MANIFEST,
        expected_sha256=reference_cache_cli._EXPECTED_MANIFEST_SHA256,
    )
    assert manifest.manifest_sha256 == reference_cache_cli._EXPECTED_MANIFEST_SHA256


def test_pdf_text_serialization_uses_the_versioned_form_feed_boundary() -> None:
    assert reference_cache_cli._serialize_pdf_pages(("first\n", None, "third")) == (
        b"first\n\f\fthird"
    )
