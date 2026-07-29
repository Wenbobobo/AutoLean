from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from autolean_builder import ifem_notebook_source_span_index as span_index
from autolean_contracts import HashKindV1, canonical_json_bytes, stable_identifier

_REVISION = "a" * 40
_RETRIEVED_AT = "2026-07-29T11:47:23.423056Z"
_NOTEBOOK_REFERENCE_ID = "ifem-test-opening-notebook-source"
_README_REFERENCE_ID = "ifem-test-readme-source"
_NOTEBOOK_PATH = "primal/opening.ipynb"
_README_PATH = "README.md"
_PRIVATE_MARKDOWN = "Private notebook heading must never leave the cache."
_PRIVATE_CODE = "model_input = 'Private code must never leave the cache.'"


def _notebook_bytes(*, cells: list[object] | None = None) -> bytes:
    payload = {
        "cells": cells
        if cells is not None
        else [
            {"cell_type": "markdown", "metadata": {}, "source": [_PRIVATE_MARKDOWN, "\n"]},
            {
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "outputs": [{"text": "Notebook output is also never indexed."}],
                "source": _PRIVATE_CODE,
            },
            {"cell_type": "raw", "metadata": {}, "source": ""},
        ],
        "metadata": {"language_info": {"name": "python"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    return canonical_json_bytes(payload)


def _source_file(reference_id: str, source_path: str, raw: bytes) -> dict[str, object]:
    return {
        "path": source_path,
        "reference_id": reference_id,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
    }


def _install_lock(
    tmp_path: Path,
    *,
    notebook_bytes: bytes | None = None,
    lock_bytes: bytes | None = None,
) -> tuple[Path, Path, bytes]:
    cache_root = tmp_path / "cache" / "references"
    cache_root.mkdir(parents=True)
    raw_notebook = notebook_bytes or _notebook_bytes()
    raw_readme = b"Synthetic locked metadata only.\n"
    notebook_file = _source_file(_NOTEBOOK_REFERENCE_ID, _NOTEBOOK_PATH, raw_notebook)
    readme_file = _source_file(_README_REFERENCE_ID, _README_PATH, raw_readme)
    for record, raw in ((notebook_file, raw_notebook), (readme_file, raw_readme)):
        suffix = Path(str(record["path"])).suffix
        target = cache_root / str(record["reference_id"]) / f"{record['sha256']}{suffix}"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    source_lock_path = cache_root / "source-lock" / "source-lock.v1.json"
    source_lock_path.parent.mkdir(parents=True)
    if lock_bytes is None:
        lock_bytes = canonical_json_bytes(
            {
                "acquisition": {
                    "retrieved_at": _RETRIEVED_AT,
                    "source_file_count": 2,
                    "source_size_bytes": len(raw_notebook) + len(raw_readme),
                },
                "policy": {
                    "access_policy": "public_open_access",
                    "contract_freeze": "not_authorized",
                    "model_egress_policy": "local_only",
                    "prover_handoff": "not_authorized",
                },
                "reference_manifest_candidate_sha256": "b" * 64,
                "reference_manifest_state": "candidate_entries_not_yet_tracked",
                "schema_version": span_index.IFEM_SOURCE_LOCK_SCHEMA_VERSION,
                "source": {"resolved_revision": _REVISION},
                "source_files": [readme_file, notebook_file],
                "state": "acquired_local_only",
            }
        )
    source_lock_path.write_bytes(lock_bytes)
    return source_lock_path, cache_root, raw_notebook


def _build(tmp_path: Path, *, notebook_bytes: bytes | None = None):
    source_lock_path, cache_root, raw_notebook = _install_lock(
        tmp_path,
        notebook_bytes=notebook_bytes,
    )
    return (
        span_index.build_ifem_notebook_source_span_index(
            source_lock_path=source_lock_path,
            source_cache_root=cache_root,
        ),
        source_lock_path,
        cache_root,
        raw_notebook,
    )


def test_replays_json_notebooks_into_text_free_stable_cell_spans(tmp_path: Path) -> None:
    index, source_lock_path, _, raw_notebook = _build(tmp_path)

    assert (
        index.source_lock.source_lock_sha256
        == hashlib.sha256(source_lock_path.read_bytes()).hexdigest()
    )
    assert index.source_lock.source_file_count == 2
    assert index.source_lock.notebook_file_count == 1
    assert index.notebook_cell_count == 3
    assert index.model_egress_policy == "local_only"
    assert index.semantic_review_state == "not_performed"
    assert index.contract_freeze == "not_authorized"
    assert index.prover_handoff == "not_authorized"
    assert index.contains_source_text is False
    assert index.contains_model_input is False
    assert [span.cell_type for span in index.spans] == ["markdown", "code", "raw"]
    assert [span.cell_index for span in index.spans] == [0, 1, 2]
    assert [span.source_file_index for span in index.spans] == [1, 1, 1]
    assert (
        index.spans[0].cell_content_sha256
        == hashlib.sha256(f"{_PRIVATE_MARKDOWN}\n".encode()).hexdigest()
    )
    assert index.spans[1].span_id == stable_identifier(
        "ifem.notebook-source-span", f"{_REVISION}:{_NOTEBOOK_PATH}:cell:1"
    )
    assert index.spans[0].source_file_sha256 == hashlib.sha256(raw_notebook).hexdigest()

    records = index.source_records()
    assert len(records) == 1
    assert records[0].locator == _NOTEBOOK_PATH
    assert records[0].content_hash.kind is HashKindV1.SOURCE_BYTES
    assert [span.content_hash.kind for span in records[0].spans] == [HashKindV1.SOURCE_SPAN] * 3


def test_rendered_index_has_no_notebook_source_output_or_cache_path(tmp_path: Path) -> None:
    index, _, cache_root, _ = _build(tmp_path)
    rendered = span_index.render_ifem_notebook_source_span_index(index)

    assert _PRIVATE_MARKDOWN.encode("utf-8") not in rendered
    assert _PRIVATE_CODE.encode("utf-8") not in rendered
    assert b"Notebook output is also never indexed" not in rendered
    assert str(cache_root).encode("utf-8") not in rendered
    assert set(json.loads(rendered)) == {
        "artifact_kind",
        "contains_model_input",
        "contains_source_text",
        "contract_freeze",
        "model_egress_policy",
        "notebook_cell_count",
        "prover_handoff",
        "schema_version",
        "semantic_review_state",
        "source_lock",
        "spans",
    }
    assert set(json.loads(rendered)["spans"][0]) == {
        "cell_character_count",
        "cell_content_sha256",
        "cell_index",
        "cell_type",
        "source_file_sha256",
        "source_file_index",
        "source_path",
        "source_reference_id",
        "span_id",
    }


def test_rejects_cached_notebook_drift_before_parsing(tmp_path: Path) -> None:
    _, source_lock_path, cache_root, raw_notebook = _build(tmp_path)
    source_lock = json.loads(source_lock_path.read_text(encoding="utf-8"))
    notebook = next(item for item in source_lock["source_files"] if item["path"] == _NOTEBOOK_PATH)
    cached = cache_root / notebook["reference_id"] / f"{notebook['sha256']}.ipynb"
    cached.write_bytes(b"tampered")

    with pytest.raises(
        span_index.IFEMNotebookSourceSpanIndexError, match="does not match source lock"
    ):
        span_index.build_ifem_notebook_source_span_index(
            source_lock_path=source_lock_path,
            source_cache_root=cache_root,
        )
    assert raw_notebook != b"tampered"


def test_rejects_any_source_lock_egress_or_authority_widening(tmp_path: Path) -> None:
    _, source_lock_path, cache_root, _ = _build(tmp_path)
    payload = json.loads(source_lock_path.read_text(encoding="utf-8"))
    payload["policy"]["model_egress_policy"] = "approved_external"
    source_lock_path.write_bytes(canonical_json_bytes(payload))

    with pytest.raises(span_index.IFEMNotebookSourceSpanIndexError, match="widens the local-only"):
        span_index.build_ifem_notebook_source_span_index(
            source_lock_path=source_lock_path,
            source_cache_root=cache_root,
        )


def test_rejects_duplicate_notebook_json_keys(tmp_path: Path) -> None:
    duplicated = b'{"nbformat":4,"cells":[],"cells":[]}'
    source_lock_path, cache_root, _ = _install_lock(tmp_path, notebook_bytes=duplicated)

    with pytest.raises(span_index.IFEMNotebookSourceSpanIndexError, match="duplicate JSON key"):
        span_index.build_ifem_notebook_source_span_index(
            source_lock_path=source_lock_path,
            source_cache_root=cache_root,
        )


def test_rejects_invalid_cell_source_shape(tmp_path: Path) -> None:
    invalid_notebook = _notebook_bytes(
        cells=[{"cell_type": "markdown", "metadata": {}, "source": ["valid", 3]}]
    )
    source_lock_path, cache_root, _ = _install_lock(tmp_path, notebook_bytes=invalid_notebook)

    with pytest.raises(span_index.IFEMNotebookSourceSpanIndexError, match="invalid source"):
        span_index.build_ifem_notebook_source_span_index(
            source_lock_path=source_lock_path,
            source_cache_root=cache_root,
        )


def test_write_is_idempotent_and_confines_the_index_to_local_cache(tmp_path: Path) -> None:
    index, _, cache_root, _ = _build(tmp_path)
    output = cache_root / "source-lock" / "notebook-source-span-index.v1.json"

    span_index.write_ifem_notebook_source_span_index(
        cache_root=cache_root,
        output_path=output,
        index=index,
    )
    first = output.read_bytes()
    span_index.write_ifem_notebook_source_span_index(
        cache_root=cache_root,
        output_path=output,
        index=index,
    )
    assert output.read_bytes() == first
    with pytest.raises(span_index.IFEMNotebookSourceSpanIndexError, match="stay below"):
        span_index.write_ifem_notebook_source_span_index(
            cache_root=cache_root,
            output_path=tmp_path / "tracked-index.json",
            index=index,
        )
