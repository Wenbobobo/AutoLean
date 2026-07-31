from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

import pytest
from autolean_builder import ifem_notebook_markdown_cell_text_projection as projection
from autolean_builder.ifem_notebook_source_span_index import (
    build_ifem_notebook_source_span_index,
    render_ifem_notebook_source_span_index,
)
from autolean_contracts import canonical_json_bytes
from pydantic import ValidationError

from scripts import ifem_source_lock as source_lock

_LICENSE = b"""Creative Commons Attribution 4.0 International

This work is licensed under the Creative Commons Attribution 4.0 International License.
To view a copy of this license, visit http://creativecommons.org/licenses/by/4.0/
or send a letter to Creative Commons, PO Box 1866, Mountain View, CA 94042, USA.
"""
_SOURCE_PATH = "primal/first_example.ipynb"
_CELL_TEXT = "\n  Exact \u6570\u5b66 source\r\nwith trailing space.  \n"
_CODE_TEXT = "private_model_input = 'must not be projected'"


@dataclass(frozen=True, slots=True)
class _Fixture:
    cache_root: Path
    source_lock_path: Path
    index_path: Path
    source_path: str
    cell_text: str
    cell_sha256: str
    code_sha256: str
    source_lock_sha256: str
    manifest_candidate_sha256: str
    index_canonical_sha256: str

    def arguments(
        self,
        *,
        cell_index: int = 0,
        cell_sha256: str | None = None,
    ) -> dict[str, object]:
        return {
            "cache_root": self.cache_root,
            "source_path": self.source_path,
            "cell_index": cell_index,
            "expected_cell_sha256": cell_sha256 or self.cell_sha256,
            "expected_source_lock_sha256": self.source_lock_sha256,
            "expected_manifest_candidate_sha256": self.manifest_candidate_sha256,
            "expected_notebook_index_canonical_sha256": self.index_canonical_sha256,
            "expected_source_file_count": len(source_lock.SOURCE_FILES),
        }


def _source_bytes(
    spec: source_lock.SourceFileSpec,
    *,
    selected_cells: list[object] | None = None,
) -> bytes:
    if spec.path == _SOURCE_PATH:
        cells = selected_cells or [
            {
                "cell_type": "markdown",
                "metadata": {},
                "source": [
                    "\n  Exact \u6570\u5b66",
                    " source\r\n",
                    "with trailing space.  \n",
                ],
            },
            {
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "outputs": [{"text": "private notebook output"}],
                "source": _CODE_TEXT,
            },
            {"cell_type": "markdown", "metadata": {}, "source": ""},
        ]
        return canonical_json_bytes(
            {
                "cells": cells,
                "metadata": {"fixture": spec.reference_id},
                "nbformat": 4,
                "nbformat_minor": 5,
            }
        )
    if spec.extension == ".ipynb":
        return canonical_json_bytes(
            {
                "cells": [{"cell_type": "raw", "metadata": {}, "source": ""}],
                "metadata": {"fixture": spec.reference_id},
                "nbformat": 4,
                "nbformat_minor": 5,
            }
        )
    return f"# fixed source fixture: {spec.reference_id}\n".encode()


def _materialize_fixture(
    tmp_path: Path,
    *,
    selected_notebook_bytes: bytes | None = None,
) -> _Fixture:
    cache_root = tmp_path / "references"
    records: list[source_lock.SourceFileRecord] = []
    for spec in source_lock.SOURCE_FILES:
        content = (
            selected_notebook_bytes
            if spec.path == _SOURCE_PATH and selected_notebook_bytes is not None
            else _source_bytes(spec)
        )
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
    lock_root = cache_root / projection.IFEM_LOCK_DIRECTORY
    lock_root.mkdir(parents=True)
    source_lock_path = lock_root / projection.IFEM_SOURCE_LOCK_FILENAME
    source_lock_path.write_bytes(canonical_json_bytes(receipt) + b"\n")
    index = build_ifem_notebook_source_span_index(
        source_lock_path=source_lock_path,
        source_cache_root=cache_root,
    )
    index_path = lock_root / projection.IFEM_NOTEBOOK_SOURCE_SPAN_INDEX_FILENAME
    index_path.write_bytes(render_ifem_notebook_source_span_index(index))
    return _Fixture(
        cache_root=cache_root,
        source_lock_path=source_lock_path,
        index_path=index_path,
        source_path=_SOURCE_PATH,
        cell_text=_CELL_TEXT,
        cell_sha256=hashlib.sha256(_CELL_TEXT.encode()).hexdigest(),
        code_sha256=hashlib.sha256(_CODE_TEXT.encode()).hexdigest(),
        source_lock_sha256=hashlib.sha256(source_lock_path.read_bytes()).hexdigest(),
        manifest_candidate_sha256=str(receipt["reference_manifest_candidate_sha256"]),
        index_canonical_sha256=index.canonical_sha256(),
    )


def test_builds_one_exact_private_markdown_cell_projection(tmp_path: Path) -> None:
    fixture = _materialize_fixture(tmp_path)

    result = projection.build_ifem_notebook_markdown_cell_text_projection(**fixture.arguments())

    assert result.cell_text == fixture.cell_text
    assert result.cell_text.startswith("\n  ")
    assert result.cell_text.endswith("  \n")
    assert result.cell_utf8_byte_count == len(fixture.cell_text.encode("utf-8"))
    assert result.cell_span.cell_character_count == len(fixture.cell_text)
    assert result.cell_span.cell_content_sha256 == fixture.cell_sha256
    assert result.cell_locator == "notebook-cell:0:type:markdown"
    assert result.source_lock.source_file_count == 13
    assert result.source_lock.receipt_sha256 == fixture.source_lock_sha256
    assert result.notebook_index.canonical_sha256 == fixture.index_canonical_sha256
    assert result.contains_source_text is True
    assert result.contains_model_input is False
    assert result.model_egress_policy == "local_only"
    assert result.contract_freeze == result.prover_handoff == "not_authorized"


def test_materialize_and_verify_are_canonical_write_once_replays(tmp_path: Path) -> None:
    fixture = _materialize_fixture(tmp_path)

    first = projection.materialize_ifem_notebook_markdown_cell_text_projection(
        **fixture.arguments()
    )
    second = projection.materialize_ifem_notebook_markdown_cell_text_projection(
        **fixture.arguments()
    )
    verified = projection.verify_ifem_notebook_markdown_cell_text_projection(**fixture.arguments())

    expected = projection.render_ifem_notebook_markdown_cell_text_projection(first.projection)
    assert first.private_path == second.private_path == verified.private_path
    assert first.private_path.read_bytes() == expected
    assert second.projection == verified.projection == first.projection
    assert first.summary == second.summary == verified.summary
    assert first.summary.private_artifact_contains_source_text is True
    assert first.summary.summary_contains_source_text is False
    assert fixture.cell_text.encode("utf-8") not in (
        projection.render_ifem_notebook_markdown_cell_text_summary(first.summary)
    )

    first.private_path.write_bytes(b"conflicting private projection\n")
    with pytest.raises(
        projection.IFEMNotebookMarkdownCellTextProjectionError,
        match="conflicts with exact replay",
    ):
        projection.materialize_ifem_notebook_markdown_cell_text_projection(**fixture.arguments())
    assert first.private_path.read_bytes() == b"conflicting private projection\n"


def test_rejects_code_empty_and_digest_mismatched_cell_selection(tmp_path: Path) -> None:
    fixture = _materialize_fixture(tmp_path)

    with pytest.raises(
        projection.IFEMNotebookMarkdownCellTextProjectionError,
        match="not Markdown",
    ):
        projection.build_ifem_notebook_markdown_cell_text_projection(
            **fixture.arguments(cell_index=1, cell_sha256=fixture.code_sha256)
        )
    empty_sha256 = hashlib.sha256(b"").hexdigest()
    with pytest.raises(
        projection.IFEMNotebookMarkdownCellTextProjectionError,
        match="no logical source text",
    ):
        projection.build_ifem_notebook_markdown_cell_text_projection(
            **fixture.arguments(cell_index=2, cell_sha256=empty_sha256)
        )
    with pytest.raises(
        projection.IFEMNotebookMarkdownCellTextProjectionError,
        match="differs from the explicit selector",
    ):
        projection.build_ifem_notebook_markdown_cell_text_projection(
            **fixture.arguments(cell_sha256="0" * 64)
        )


@pytest.mark.parametrize(
    "raw, message",
    [
        (b'{"value":1,"value":2}', "duplicate JSON key"),
        (b'{"value":NaN}', "non-finite JSON number"),
        (b'{"value":"\xff"}', "not strict UTF-8 JSON"),
    ],
)
def test_strict_json_loader_rejects_duplicates_nan_and_invalid_utf8(
    raw: bytes,
    message: str,
) -> None:
    with pytest.raises(projection.IFEMNotebookMarkdownCellTextProjectionError, match=message):
        projection._load_json_object(raw, label="synthetic input")


def test_rejects_noncanonical_lock_index_and_private_projection(tmp_path: Path) -> None:
    fixture = _materialize_fixture(tmp_path)
    lock_payload = json.loads(fixture.source_lock_path.read_text(encoding="utf-8"))
    fixture.source_lock_path.write_text(json.dumps(lock_payload, indent=2), encoding="utf-8")
    with pytest.raises(
        projection.IFEMNotebookMarkdownCellTextProjectionError,
        match="source lock is not canonically rendered",
    ):
        projection.build_ifem_notebook_markdown_cell_text_projection(**fixture.arguments())

    fixture = _materialize_fixture(tmp_path / "index")
    index_payload = json.loads(fixture.index_path.read_text(encoding="utf-8"))
    fixture.index_path.write_text(json.dumps(index_payload, indent=2), encoding="utf-8")
    with pytest.raises(
        projection.IFEMNotebookMarkdownCellTextProjectionError,
        match="index is not canonically rendered",
    ):
        projection.build_ifem_notebook_markdown_cell_text_projection(**fixture.arguments())

    fixture = _materialize_fixture(tmp_path / "private")
    result = projection.materialize_ifem_notebook_markdown_cell_text_projection(
        **fixture.arguments()
    )
    private_payload = json.loads(result.private_path.read_text(encoding="utf-8"))
    result.private_path.write_text(json.dumps(private_payload, indent=2), encoding="utf-8")
    with pytest.raises(
        projection.IFEMNotebookMarkdownCellTextProjectionError,
        match="projection is not canonically rendered",
    ):
        projection.verify_ifem_notebook_markdown_cell_text_projection(**fixture.arguments())


def test_rejects_isolated_surrogate_in_logical_cell_source(tmp_path: Path) -> None:
    fixture = _materialize_fixture(tmp_path)
    valid = projection.build_ifem_notebook_markdown_cell_text_projection(**fixture.arguments())
    payload = valid.model_dump(mode="python", round_trip=True)
    payload["cell_text"] = "\ud800"
    payload["cell_utf8_byte_count"] = 1

    with pytest.raises(ValidationError, match=r"valid string|not strict UTF-8"):
        projection.IFEMNotebookMarkdownCellTextProjectionV1.model_validate(payload)


def test_rejects_link_or_reparse_parent_and_path_escape(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _materialize_fixture(tmp_path)
    notebook_parent = next(
        path.parent
        for path in fixture.cache_root.rglob("*.ipynb")
        if path.parent.name == source_lock.SOURCE_FILES[3].reference_id
    )
    original = projection._is_link_or_reparse

    def forged_reparse(path: Path, metadata: object) -> bool:
        if path == notebook_parent:
            return True
        return original(path, metadata)  # type: ignore[arg-type]

    monkeypatch.setattr(projection, "_is_link_or_reparse", forged_reparse)
    with pytest.raises(
        projection.IFEMNotebookMarkdownCellTextProjectionError,
        match="links, junctions, or reparse points",
    ):
        projection.build_ifem_notebook_markdown_cell_text_projection(**fixture.arguments())

    outside = tmp_path.parent / "outside-projection.json"
    outside.write_bytes(b"{}")
    with pytest.raises(
        projection.IFEMNotebookMarkdownCellTextProjectionError,
        match="escapes the source cache",
    ):
        projection._read_confined_regular_file(
            outside,
            root=fixture.cache_root,
            max_bytes=100,
            label="outside input",
        )


def test_secure_reader_stops_on_open_identity_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    target = root / "input.json"
    target.write_bytes(b"{}")
    monkeypatch.setattr(projection.os.path, "samestat", lambda _left, _right: False)

    with pytest.raises(
        projection.IFEMNotebookMarkdownCellTextProjectionError,
        match="changed while opening",
    ):
        projection._read_confined_regular_file(
            target,
            root=root,
            max_bytes=100,
            label="racing input",
        )


def test_authority_and_source_text_fields_cannot_be_widened(tmp_path: Path) -> None:
    fixture = _materialize_fixture(tmp_path)
    private = projection.build_ifem_notebook_markdown_cell_text_projection(**fixture.arguments())
    payload = private.model_dump(mode="json")

    for field, value in (
        ("contains_model_input", True),
        ("model_egress_policy", "approved_external"),
        ("semantic_review_state", "completed"),
        ("contract_freeze", "authorized"),
        ("prover_handoff", "authorized"),
    ):
        widened = {**payload, field: value}
        with pytest.raises(ValidationError):
            projection.IFEMNotebookMarkdownCellTextProjectionV1.model_validate(widened)


def test_real_file_symlink_is_rejected_when_available(tmp_path: Path) -> None:
    fixture = _materialize_fixture(tmp_path)
    external = tmp_path / "external-index.json"
    external.write_bytes(fixture.index_path.read_bytes())
    fixture.index_path.unlink()
    try:
        fixture.index_path.symlink_to(external)
    except OSError as error:
        pytest.skip(f"file symlink unavailable: {error}")

    with pytest.raises(
        projection.IFEMNotebookMarkdownCellTextProjectionError,
        match="link, junction, or reparse point",
    ):
        projection.build_ifem_notebook_markdown_cell_text_projection(**fixture.arguments())
