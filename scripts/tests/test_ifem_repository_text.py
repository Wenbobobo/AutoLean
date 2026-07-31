"""Focused tests for the offline iFEM Markdown text-identity overlay."""

from __future__ import annotations

import ast
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from autolean_contracts import canonical_json_bytes

from scripts import ifem_repository_text as repository_text
from scripts import ifem_source_lock as source_lock

ROOT = Path(__file__).resolve().parents[2]
_LICENSE = b"""Creative Commons Attribution 4.0 International

This work is licensed under the Creative Commons Attribution 4.0 International License.
To view a copy of this license, visit http://creativecommons.org/licenses/by/4.0/
or send a letter to Creative Commons, PO Box 1866, Mountain View, CA 94042, USA.
"""


def _source_bytes(spec: source_lock.SourceFileSpec) -> bytes:
    if spec.path == repository_text.INTRO_MARKDOWN_PATH:
        return b"# iFEM opening\n\nA strictly local byte-identity fixture.\n"
    if spec.extension == ".ipynb":
        return canonical_json_bytes(
            {
                "cells": [],
                "metadata": {"fixture": spec.reference_id},
                "nbformat": 4,
                "nbformat_minor": 5,
            }
        )
    return f"# iFEM source fixture: {spec.reference_id}\n".encode()


def _materialize_source_lock(cache_root: Path) -> Path:
    records: list[source_lock.SourceFileRecord] = []
    for spec in source_lock.SOURCE_FILES:
        content = _source_bytes(spec)
        record = source_lock._validate_source_bytes(spec, content)
        target = cache_root / spec.reference_id / f"{record.sha256}{spec.extension}"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        records.append(record)
    receipt = source_lock._receipt_payload(
        records,
        license_sha256=source_lock._validate_license_bytes(_LICENSE),
        retrieved_at="2026-07-30T01:02:03Z",
    )
    receipt_path = cache_root / source_lock.RECEIPT_DIRECTORY / "source-lock.v1.json"
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.write_bytes(canonical_json_bytes(receipt) + b"\n")
    return receipt_path


def _materialized(tmp_path: Path) -> tuple[Path, Path, repository_text._OverlayPlan]:
    cache_root = tmp_path / "references"
    source_receipt = _materialize_source_lock(cache_root)
    plan = repository_text.materialize_ifem_repository_text_overlay(
        cache_root=cache_root,
        source_lock_path=source_receipt,
    )
    return cache_root, source_receipt, plan


def test_materializes_fixed_local_markdown_byte_identity_and_replays(tmp_path: Path) -> None:
    cache_root, source_receipt, plan = _materialized(tmp_path)

    assert plan.manifest_path.exists()
    assert plan.receipt_path.exists()
    replayed = repository_text.verify_ifem_repository_text_overlay(
        cache_root=cache_root,
        source_lock_path=source_receipt,
    )
    assert replayed == plan
    assert (
        repository_text.materialize_ifem_repository_text_overlay(
            cache_root=cache_root,
            source_lock_path=source_receipt,
        )
        == plan
    )

    manifest = json.loads(plan.manifest_path.read_text(encoding="utf-8"))
    entries = manifest["entries"]
    assert isinstance(entries, list)
    parent, derived = entries
    assert derived["derivation"]["method"] == "utf8-markdown-byte-identity-v1"
    assert derived["derivation"]["parent_locator_authority"] == "human_declared"
    assert derived["derivation"]["tool_name"] is None
    assert derived["derivation"]["tool_version"] is None
    assert parent["model_egress_policy"] == derived["model_egress_policy"] == "local_only"
    assert parent["sha256"] == derived["sha256"]
    assert parent["size_bytes"] == derived["size_bytes"]
    parent_bytes = (cache_root / parent["reference_id"] / f"{parent['sha256']}.md").read_bytes()
    derived_bytes = (cache_root / derived["reference_id"] / f"{derived['sha256']}.txt").read_bytes()
    assert parent_bytes == derived_bytes

    receipt = json.loads(plan.receipt_path.read_text(encoding="utf-8"))
    assert receipt["contains_source_text"] is False
    assert receipt["contains_source_path"] is False
    assert receipt["policy"] == {
        "contract_freeze_authorized": False,
        "model_egress_policy": "local_only",
        "prover_handoff_authorized": False,
    }


def test_cli_prints_only_redacted_authority_summary(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cache_root = tmp_path / "references"
    source_receipt = _materialize_source_lock(cache_root)

    assert (
        repository_text.main(
            [
                "materialize",
                "--cache-root",
                str(cache_root),
                "--source-lock",
                str(source_receipt),
            ]
        )
        == 0
    )
    rendered = capsys.readouterr().out.encode("utf-8")
    summary = json.loads(rendered)
    assert summary["contract_freeze_authorized"] is False
    assert summary["prover_handoff_authorized"] is False
    assert summary["model_egress_policy"] == "local_only"
    for forbidden in (
        b"intro.md",
        b"strictly local byte-identity fixture",
        str(cache_root).encode("utf-8"),
        b"source_path",
        b"source_text",
    ):
        assert forbidden not in rendered


def test_materialize_replays_local_lock_without_invoking_source_download(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache_root = tmp_path / "references"
    source_receipt = _materialize_source_lock(cache_root)

    def unexpected_download(*_arguments: object, **_keywords: object) -> None:
        raise AssertionError("repository text overlay attempted source acquisition")

    monkeypatch.setattr(source_lock, "_download_to", unexpected_download)
    plan = repository_text.materialize_ifem_repository_text_overlay(
        cache_root=cache_root,
        source_lock_path=source_receipt,
    )

    assert plan.receipt_path.exists()


def test_conflicting_write_once_receipt_is_rejected(tmp_path: Path) -> None:
    cache_root, source_receipt, plan = _materialized(tmp_path)
    plan.receipt_path.write_bytes(b"different\n")

    with pytest.raises(
        repository_text.IFEMRepositoryTextError,
        match="existing local overlay receipt",
    ):
        repository_text.materialize_ifem_repository_text_overlay(
            cache_root=cache_root,
            source_lock_path=source_receipt,
        )


def test_verify_rejects_manifest_or_cached_text_drift(tmp_path: Path) -> None:
    cache_root, source_receipt, plan = _materialized(tmp_path)
    plan.manifest_path.write_bytes(b"{}\n")

    with pytest.raises(repository_text.IFEMRepositoryTextError, match="overlay manifest differs"):
        repository_text.verify_ifem_repository_text_overlay(
            cache_root=cache_root,
            source_lock_path=source_receipt,
        )

    shutil.rmtree(plan.manifest_path.parent)
    plan = repository_text.materialize_ifem_repository_text_overlay(
        cache_root=cache_root,
        source_lock_path=source_receipt,
    )
    derived = cache_root / repository_text.DERIVED_TEXT_REFERENCE_ID / f"{plan.parent_sha256}.txt"
    derived.write_bytes(b"tampered")

    with pytest.raises(
        repository_text.IFEMRepositoryTextError,
        match="cache object did not verify",
    ):
        repository_text.verify_ifem_repository_text_overlay(
            cache_root=cache_root,
            source_lock_path=source_receipt,
        )


def test_rejects_noncanonical_source_lock_location(tmp_path: Path) -> None:
    cache_root = tmp_path / "references"
    source_receipt = _materialize_source_lock(cache_root)
    copied_receipt = tmp_path / "copied-source-lock.v1.json"
    shutil.copyfile(source_receipt, copied_receipt)

    with pytest.raises(repository_text.IFEMRepositoryTextError, match="canonical cache path"):
        repository_text.materialize_ifem_repository_text_overlay(
            cache_root=cache_root,
            source_lock_path=copied_receipt,
        )


def test_overlay_rejects_junction_or_reparse_output_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache_root = tmp_path / "references"
    source_receipt = _materialize_source_lock(cache_root)
    overlay_root = source_receipt.parent / repository_text.OVERLAY_DIRECTORY
    overlay_root.mkdir()
    monkeypatch.setattr(
        os.path,
        "isjunction",
        lambda path: Path(path) == overlay_root,
        raising=False,
    )

    with pytest.raises(
        repository_text.IFEMRepositoryTextError,
        match="link or reparse point",
    ):
        repository_text.materialize_ifem_repository_text_overlay(
            cache_root=cache_root,
            source_lock_path=source_receipt,
        )


def test_overlay_rejects_reparse_source_lock_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache_root = tmp_path / "references"
    source_receipt = _materialize_source_lock(cache_root)
    original = repository_text._is_link_or_reparse

    def forged_reparse(
        path: Path,
        metadata: os.stat_result | None = None,
    ) -> bool:
        return path == source_receipt.parent or original(path, metadata)

    monkeypatch.setattr(repository_text, "_is_link_or_reparse", forged_reparse)

    with pytest.raises(
        repository_text.IFEMRepositoryTextError,
        match="directory must not be a link or reparse point",
    ):
        repository_text.materialize_ifem_repository_text_overlay(
            cache_root=cache_root,
            source_lock_path=source_receipt,
        )


def test_overlay_rejects_reparse_source_lock_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache_root = tmp_path / "references"
    source_receipt = _materialize_source_lock(cache_root)
    original = repository_text._is_link_or_reparse

    def forged_reparse(
        path: Path,
        metadata: os.stat_result | None = None,
    ) -> bool:
        return path == source_receipt or original(path, metadata)

    monkeypatch.setattr(repository_text, "_is_link_or_reparse", forged_reparse)

    with pytest.raises(
        repository_text.IFEMRepositoryTextError,
        match="iFEM source lock must not be a link or reparse point",
    ):
        repository_text.materialize_ifem_repository_text_overlay(
            cache_root=cache_root,
            source_lock_path=source_receipt,
        )


def test_overlay_rejects_reparse_existing_receipt_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache_root, source_receipt, plan = _materialized(tmp_path)
    original = repository_text._is_link_or_reparse

    def forged_reparse(
        path: Path,
        metadata: os.stat_result | None = None,
    ) -> bool:
        return path == plan.receipt_path or original(path, metadata)

    monkeypatch.setattr(repository_text, "_is_link_or_reparse", forged_reparse)

    with pytest.raises(
        repository_text.IFEMRepositoryTextError,
        match="existing local overlay receipt must not be a link or reparse point",
    ):
        repository_text.materialize_ifem_repository_text_overlay(
            cache_root=cache_root,
            source_lock_path=source_receipt,
        )


def test_secure_reader_rejects_open_identity_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache_root = tmp_path / "references"
    cache_root.mkdir()
    target = cache_root / "input.txt"
    target.write_bytes(b"fixed")
    monkeypatch.setattr(os.path, "samestat", lambda _left, _right: False)

    with pytest.raises(
        repository_text.IFEMRepositoryTextError,
        match="input changed while opening",
    ):
        repository_text._read_regular_file(
            target,
            cache_root=cache_root,
            label="input",
        )


def test_module_has_no_direct_network_or_provider_imports() -> None:
    tree = ast.parse(Path(repository_text.__file__).read_text(encoding="utf-8"))
    imported_roots = {
        alias.name.split(".", 1)[0]
        for statement in ast.walk(tree)
        if isinstance(statement, ast.Import)
        for alias in statement.names
    }
    imported_roots.update(
        statement.module.split(".", 1)[0]
        for statement in ast.walk(tree)
        if isinstance(statement, ast.ImportFrom) and statement.module is not None
    )
    assert not imported_roots.intersection({"http", "httpx", "openai", "requests", "urllib"})


def test_direct_script_help_resolves_workspace_imports(tmp_path: Path) -> None:
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    completed = subprocess.run(
        (sys.executable, str(ROOT / "scripts" / "ifem_repository_text.py"), "--help"),
        check=False,
        cwd=tmp_path,
        capture_output=True,
        env=environment,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert "materialize" in completed.stdout
    assert "--source-lock" in completed.stdout
