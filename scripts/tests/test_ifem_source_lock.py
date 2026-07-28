from __future__ import annotations

import io
import json
from http.client import HTTPMessage
from pathlib import Path
from urllib.request import Request

import pytest
from autolean_builder import ReferenceManifestV1

from scripts import ifem_source_lock as lock

_LICENSE = b"""Creative Commons Attribution 4.0 International

This work is licensed under the Creative Commons Attribution 4.0 International License.
To view a copy of this license, visit http://creativecommons.org/licenses/by/4.0/
or send a letter to Creative Commons, PO Box 1866, Mountain View, CA 94042, USA.
"""


def _source_bytes(spec: lock.SourceFileSpec) -> bytes:
    if spec.extension == ".ipynb":
        return json.dumps(
            {
                "cells": [],
                "metadata": {"path": spec.path},
                "nbformat": 4,
                "nbformat_minor": 5,
            },
            sort_keys=True,
        ).encode("utf-8")
    return f"# iFEM source fixture: {spec.path}\n".encode()


def _materialize_receipt(tmp_path: Path) -> tuple[Path, dict[str, object]]:
    records: list[lock.SourceFileRecord] = []
    for spec in lock.SOURCE_FILES:
        source_bytes = _source_bytes(spec)
        record = lock._validate_source_bytes(spec, source_bytes)
        target = tmp_path / spec.reference_id / f"{record.sha256}{spec.extension}"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source_bytes)
        records.append(record)
    receipt_document = lock._receipt_payload(
        records,
        license_sha256=lock._validate_license_bytes(_LICENSE),
        retrieved_at="2026-07-28T01:02:03Z",
    )
    receipt_path = tmp_path / lock.RECEIPT_DIRECTORY / "source-lock.v1.json"
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.write_bytes(json.dumps(receipt_document, sort_keys=True).encode() + b"\n")
    return receipt_path, receipt_document


def test_selected_source_path_is_bounded_and_commit_pinned() -> None:
    assert lock.PINNED_REVISION == "a4ab841c4e5ec726e9b7742c9dcb352cb9645736"
    assert tuple(spec.path for spec in lock.SOURCE_FILES) == (
        "README.md",
        "_toc.yml",
        "intro.md",
        "primal/first_example.ipynb",
        "primal/boundary_conditions.ipynb",
        "primal/subdomains.ipynb",
        "primal/solvers.ipynb",
        "primal/elasticity3D.ipynb",
        "primal/exercises.ipynb",
        "abstracttheory/BasicProperties.ipynb",
        "abstracttheory/subspaceprojection.ipynb",
        "abstracttheory/RieszRepresentation.ipynb",
        "abstracttheory/Coercive.ipynb",
    )
    assert all(spec.download_url.startswith(lock.RAW_ROOT_URL) for spec in lock.SOURCE_FILES)
    assert lock._validate_license_bytes(_LICENSE) == lock.LICENSE_SHA256


def test_license_validation_binds_the_reviewed_git_blob() -> None:
    altered = _LICENSE.replace(b"Mountain View", b"Somewhere Else")

    with pytest.raises(lock.IFEMSourceLockError, match="reviewed Git blob"):
        lock._validate_license_bytes(altered)
    assert lock._git_blob_sha1(_LICENSE) == lock.LICENSE_BLOB_SHA1


def test_redirect_handler_refuses_before_following() -> None:
    handler = lock._RejectRedirectHandler()

    with pytest.raises(lock.IFEMSourceLockError, match="redirect was rejected"):
        handler.redirect_request(
            Request("https://raw.githubusercontent.com/source"),
            io.BytesIO(),
            302,
            "Found",
            HTTPMessage(),
            "https://example.invalid/redirected",
        )


def test_source_validation_rejects_non_notebook_json() -> None:
    notebook = next(spec for spec in lock.SOURCE_FILES if spec.extension == ".ipynb")

    with pytest.raises(lock.IFEMSourceLockError, match="not valid JSON"):
        lock._validate_source_bytes(notebook, b"not-json")
    with pytest.raises(lock.IFEMSourceLockError, match="no nbformat"):
        lock._validate_source_bytes(notebook, b"{}")


def test_receipt_replays_cached_files_and_rejects_policy_widening(tmp_path: Path) -> None:
    receipt_path, payload = _materialize_receipt(tmp_path)

    receipt, records = lock.inspect_receipt(tmp_path, receipt_path)
    assert receipt["state"] == "acquired_local_only"
    assert len(records) == len(lock.SOURCE_FILES)

    payload["policy"]["contract_freeze"] = "authorized"  # type: ignore[index]
    receipt_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(lock.IFEMSourceLockError, match="fixed local-only policy"):
        lock.inspect_receipt(tmp_path, receipt_path)


def test_receipt_rejects_license_or_manifest_projection_drift(tmp_path: Path) -> None:
    receipt_path, payload = _materialize_receipt(tmp_path)
    payload["source"]["license"]["license_sha256"] = "0" * 64  # type: ignore[index]
    receipt_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(lock.IFEMSourceLockError, match="license binding"):
        lock.inspect_receipt(tmp_path, receipt_path)

    _, payload = _materialize_receipt(tmp_path)
    payload["reference_manifest_candidate_sha256"] = "0" * 64
    receipt_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(lock.IFEMSourceLockError, match="manifest candidate binding"):
        lock.inspect_receipt(tmp_path, receipt_path)


def test_receipt_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    receipt_path, _ = _materialize_receipt(tmp_path)
    original = receipt_path.read_text(encoding="utf-8").rstrip()
    receipt_path.write_text(
        original[:-1] + ',"state":"acquired_local_only"}',
        encoding="utf-8",
    )

    with pytest.raises(lock.IFEMSourceLockError, match="duplicate JSON key"):
        lock.inspect_receipt(tmp_path, receipt_path)


def test_receipt_rejects_tampered_cached_source(tmp_path: Path) -> None:
    receipt_path, _ = _materialize_receipt(tmp_path)
    first_record = json.loads(receipt_path.read_text(encoding="utf-8"))["source_files"][0]
    first_spec = lock.SOURCE_FILES[0]
    cache_path = (
        tmp_path / first_spec.reference_id / f"{first_record['sha256']}{first_spec.extension}"
    )
    cache_path.write_bytes(b"tampered")

    with pytest.raises(lock.IFEMSourceLockError, match="cached iFEM source"):
        lock.inspect_receipt(tmp_path, receipt_path)


def test_manifest_entries_are_reference_manifest_compatible_and_redacted(tmp_path: Path) -> None:
    receipt_path, _ = _materialize_receipt(tmp_path)
    receipt, records = lock.inspect_receipt(tmp_path, receipt_path)
    retrieved_at = receipt["acquisition"]["retrieved_at"]  # type: ignore[index]
    entries = lock.manifest_entries(records, retrieved_at=retrieved_at)
    rendered = json.dumps(entries, ensure_ascii=True, sort_keys=True)

    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": "autolean.reference-manifest.v1",
                "entries": entries,
            }
        ),
        encoding="utf-8",
    )
    manifest = ReferenceManifestV1.load(manifest_path)

    assert len(manifest.entries) == len(lock.SOURCE_FILES)
    assert {entry.model_egress_policy.value for entry in manifest.entries} == {"local_only"}
    assert "nbformat_minor" not in rendered
    assert "iFEM source fixture" not in rendered


def test_acquire_uses_only_the_fixed_raw_urls_and_replays(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache_root = tmp_path / "references"
    calls: list[str] = []

    def fake_download(url: str, destination: Path) -> None:
        calls.append(url)
        if url == f"{lock.RAW_ROOT_URL}/LICENSE":
            destination.write_bytes(_LICENSE)
            return
        spec = next(item for item in lock.SOURCE_FILES if item.download_url == url)
        destination.write_bytes(_source_bytes(spec))

    monkeypatch.setattr(lock, "_download_to", fake_download)
    receipt_path, entries = lock.acquire(cache_root)
    lock.inspect_receipt(cache_root, receipt_path)

    assert calls == [f"{lock.RAW_ROOT_URL}/LICENSE", *[x.download_url for x in lock.SOURCE_FILES]]
    assert len(entries) == len(lock.SOURCE_FILES)

    def unexpected_download(url: str, destination: Path) -> None:
        raise AssertionError(f"second acquire attempted network I/O: {url} -> {destination}")

    monkeypatch.setattr(lock, "_download_to", unexpected_download)
    replayed_receipt, replayed_entries = lock.acquire(cache_root)
    assert replayed_receipt == receipt_path
    assert replayed_entries == entries
