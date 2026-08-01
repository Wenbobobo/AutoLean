"""Project one locked iFEM notebook Markdown cell into a private local text artifact.

The digest-only notebook index remains the public-safe locator surface.  This module replays one
explicitly selected Markdown cell into an ignored local cache artifact so that later Builder work
can calibrate real source spans.  It performs no acquisition, model dispatch, semantic review,
statement freeze, or Prover handoff.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Final, Literal, Never, cast

from autolean_contracts import ContractModel, StableIdentifierV1, canonical_json_bytes
from pydantic import ConfigDict, Field, ValidationError, model_validator

from .ifem_notebook_source_span_index import (
    IFEM_NOTEBOOK_SOURCE_SPAN_INDEX_SCHEMA_VERSION,
    IFEM_SOURCE_LOCK_SCHEMA_VERSION,
    IFEMNotebookCellSourceSpanV1,
    IFEMNotebookSourceSpanIndexV1,
    render_ifem_notebook_source_span_index,
)

IFEM_LOCK_DIRECTORY: Final[str] = "ifem-interactive-fem-chapters-01-10-git-a4ab841-lock"
IFEM_SOURCE_LOCK_FILENAME: Final[str] = "source-lock.v1.json"
IFEM_NOTEBOOK_SOURCE_SPAN_INDEX_FILENAME: Final[str] = "notebook-source-span-index.v1.json"
IFEM_NOTEBOOK_MARKDOWN_CELL_TEXT_DIRECTORY: Final[str] = (
    "notebook-markdown-cell-text-projections.v1"
)
IFEM_NOTEBOOK_MARKDOWN_CELL_TEXT_PROJECTION_SCHEMA_VERSION: Final[
    Literal["autolean.ifem-notebook-markdown-cell-text-projection.v1"]
] = "autolean.ifem-notebook-markdown-cell-text-projection.v1"
IFEM_NOTEBOOK_MARKDOWN_CELL_TEXT_SUMMARY_SCHEMA_VERSION: Final[
    Literal["autolean.ifem-notebook-markdown-cell-text-summary.v1"]
] = "autolean.ifem-notebook-markdown-cell-text-summary.v1"
IFEM_NOTEBOOK_MARKDOWN_CELL_TEXT_PROJECTION_KIND: Final[
    Literal["local_only_private_notebook_markdown_cell_text_projection"]
] = "local_only_private_notebook_markdown_cell_text_projection"
IFEM_NOTEBOOK_MARKDOWN_CELL_TEXT_SUMMARY_KIND: Final[
    Literal["local_only_redacted_notebook_markdown_cell_text_summary"]
] = "local_only_redacted_notebook_markdown_cell_text_summary"
IFEM_NOTEBOOK_MARKDOWN_CELL_TEXT_METHOD: Final[Literal["jupyter-nbformat-v4-logical-source-v1"]] = (
    "jupyter-nbformat-v4-logical-source-v1"
)

_SHA256 = r"^[0-9a-f]{64}$"
_REVISION = r"^[0-9a-f]{40}$"
_PATH = r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\.ipynb$"
_CELL_LOCATOR = r"^notebook-cell:[0-9]+:type:markdown$"
_REPARSE_POINT = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
_MAX_SOURCE_LOCK_BYTES = 1024 * 1024
_MAX_NOTEBOOK_INDEX_BYTES = 16 * 1024 * 1024
_MAX_NOTEBOOK_BYTES = 256 * 1024 * 1024
_MAX_CELL_UTF8_BYTES = 4 * 1024 * 1024
_MAX_PRIVATE_PROJECTION_BYTES = 32 * 1024 * 1024
_CHUNK_BYTES = 1024 * 1024
_DirectoryIdentity = tuple[int, int, int, int]
_DirectorySnapshot = tuple[tuple[Path, _DirectoryIdentity], ...]


class IFEMNotebookMarkdownCellTextProjectionError(ValueError):
    """The locked source, digest-only index, or private text projection did not replay."""


@dataclass(frozen=True, slots=True)
class _LockedSourceFile:
    reference_id: str
    path: str
    sha256: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class _SourceLockReplay:
    raw: bytes
    sha256: str
    reference_manifest_candidate_sha256: str
    revision: str
    retrieved_at: datetime
    records: tuple[_LockedSourceFile, ...]


@dataclass(frozen=True, slots=True)
class IFEMNotebookMarkdownCellTextProjectionResult:
    projection: IFEMNotebookMarkdownCellTextProjectionV1
    summary: IFEMNotebookMarkdownCellTextSummaryV1
    private_path: Path


class IFEMNotebookMarkdownCellTextSourceLockBindingV1(ContractModel):
    receipt_sha256: str = Field(pattern=_SHA256)
    reference_manifest_candidate_sha256: str = Field(pattern=_SHA256)
    source_revision: str = Field(pattern=_REVISION)
    source_file_count: int = Field(gt=0)


class IFEMNotebookMarkdownCellTextIndexBindingV1(ContractModel):
    schema_version: Literal["autolean.ifem-notebook-source-span-index.v1"] = (
        IFEM_NOTEBOOK_SOURCE_SPAN_INDEX_SCHEMA_VERSION
    )
    canonical_sha256: str = Field(pattern=_SHA256)


class IFEMNotebookMarkdownCellTextProjectionV1(ContractModel):
    """One exact logical cell source retained only in the ignored local cache."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=False,
        validate_default=True,
    )

    schema_version: Literal["autolean.ifem-notebook-markdown-cell-text-projection.v1"] = (
        IFEM_NOTEBOOK_MARKDOWN_CELL_TEXT_PROJECTION_SCHEMA_VERSION
    )
    artifact_kind: Literal["local_only_private_notebook_markdown_cell_text_projection"] = (
        IFEM_NOTEBOOK_MARKDOWN_CELL_TEXT_PROJECTION_KIND
    )
    source_lock: IFEMNotebookMarkdownCellTextSourceLockBindingV1
    notebook_index: IFEMNotebookMarkdownCellTextIndexBindingV1
    cell_span: IFEMNotebookCellSourceSpanV1
    cell_locator: str = Field(pattern=_CELL_LOCATOR)
    projection_method: Literal["jupyter-nbformat-v4-logical-source-v1"] = (
        IFEM_NOTEBOOK_MARKDOWN_CELL_TEXT_METHOD
    )
    text_encoding: Literal["utf-8"] = "utf-8"
    cell_text: str = Field(min_length=1)
    cell_utf8_byte_count: int = Field(gt=0)
    contains_source_text: Literal[True] = True
    contains_model_input: Literal[False] = False
    model_egress_policy: Literal["local_only"] = "local_only"
    semantic_review_state: Literal["not_performed"] = "not_performed"
    contract_freeze: Literal["not_authorized"] = "not_authorized"
    prover_handoff: Literal["not_authorized"] = "not_authorized"

    @model_validator(mode="after")
    def validate_exact_cell_text(self) -> IFEMNotebookMarkdownCellTextProjectionV1:
        if self.cell_span.cell_type != "markdown":
            raise ValueError("private notebook text projection requires a Markdown cell")
        expected_locator = f"notebook-cell:{self.cell_span.cell_index}:type:markdown"
        if self.cell_locator != expected_locator:
            raise ValueError("private notebook text locator differs from its cell binding")
        try:
            encoded = self.cell_text.encode("utf-8", errors="strict")
        except UnicodeEncodeError as error:
            raise ValueError("private notebook cell text is not strict UTF-8") from error
        if len(encoded) != self.cell_utf8_byte_count:
            raise ValueError("private notebook cell UTF-8 byte count differs")
        if len(self.cell_text) != self.cell_span.cell_character_count:
            raise ValueError("private notebook cell character count differs from the index")
        if hashlib.sha256(encoded).hexdigest() != self.cell_span.cell_content_sha256:
            raise ValueError("private notebook cell text differs from the indexed digest")
        return self

    def canonical_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self)).hexdigest()


class IFEMNotebookMarkdownCellTextSummaryV1(ContractModel):
    """The complete stdout-safe surface; it cannot carry notebook text or local paths."""

    schema_version: Literal["autolean.ifem-notebook-markdown-cell-text-summary.v1"] = (
        IFEM_NOTEBOOK_MARKDOWN_CELL_TEXT_SUMMARY_SCHEMA_VERSION
    )
    artifact_kind: Literal["local_only_redacted_notebook_markdown_cell_text_summary"] = (
        IFEM_NOTEBOOK_MARKDOWN_CELL_TEXT_SUMMARY_KIND
    )
    source_lock_sha256: str = Field(pattern=_SHA256)
    notebook_index_canonical_sha256: str = Field(pattern=_SHA256)
    cell_span_id: StableIdentifierV1
    cell_locator: str = Field(pattern=_CELL_LOCATOR)
    cell_content_sha256: str = Field(pattern=_SHA256)
    private_projection_file_sha256: str = Field(pattern=_SHA256)
    private_artifact_contains_source_text: Literal[True] = True
    summary_contains_source_text: Literal[False] = False
    model_egress_policy: Literal["local_only"] = "local_only"
    semantic_review_state: Literal["not_performed"] = "not_performed"
    contract_freeze_authorized: Literal[False] = False
    prover_handoff_authorized: Literal[False] = False


def build_ifem_notebook_markdown_cell_text_projection(
    *,
    cache_root: Path,
    source_path: str,
    cell_index: int,
    expected_cell_sha256: str,
    expected_source_lock_sha256: str,
    expected_manifest_candidate_sha256: str,
    expected_notebook_index_canonical_sha256: str,
    expected_source_file_count: int,
) -> IFEMNotebookMarkdownCellTextProjectionV1:
    """Replay one explicit Markdown cell from the fixed local lock without writing an artifact."""

    _validate_selection(source_path, cell_index, expected_cell_sha256)
    _require_sha(expected_source_lock_sha256, label="expected source-lock SHA-256")
    _require_sha(
        expected_manifest_candidate_sha256,
        label="expected reference-manifest candidate SHA-256",
    )
    _require_sha(
        expected_notebook_index_canonical_sha256,
        label="expected notebook-index canonical SHA-256",
    )
    if (
        isinstance(expected_source_file_count, bool)
        or not isinstance(expected_source_file_count, int)
        or expected_source_file_count <= 0
    ):
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "expected source-file count must be a positive integer"
        )

    root = _require_cache_root(cache_root)
    source_lock_path = root / IFEM_LOCK_DIRECTORY / IFEM_SOURCE_LOCK_FILENAME
    index_path = root / IFEM_LOCK_DIRECTORY / IFEM_NOTEBOOK_SOURCE_SPAN_INDEX_FILENAME
    lock_raw = _read_confined_regular_file(
        source_lock_path,
        root=root,
        max_bytes=_MAX_SOURCE_LOCK_BYTES,
        label="iFEM source lock",
    )
    source_lock = _parse_source_lock(
        lock_raw,
        expected_sha256=expected_source_lock_sha256,
        expected_manifest_candidate_sha256=expected_manifest_candidate_sha256,
        expected_source_file_count=expected_source_file_count,
    )
    index_raw = _read_confined_regular_file(
        index_path,
        root=root,
        max_bytes=_MAX_NOTEBOOK_INDEX_BYTES,
        label="iFEM notebook source-span index",
    )
    notebook_index = _parse_notebook_index(
        index_raw,
        source_lock=source_lock,
        expected_canonical_sha256=expected_notebook_index_canonical_sha256,
    )
    matching = tuple(
        span
        for span in notebook_index.spans
        if span.source_path == source_path and span.cell_index == cell_index
    )
    if len(matching) != 1:
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "selected notebook cell does not resolve uniquely in the digest-only index"
        )
    span = matching[0]
    if span.cell_type != "markdown":
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "selected digest-only notebook cell is not Markdown"
        )
    if span.cell_content_sha256 != expected_cell_sha256:
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "selected notebook cell digest differs from the explicit selector"
        )
    if span.source_file_index >= len(source_lock.records):
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "selected notebook cell source-file index exceeds the source lock"
        )
    record = source_lock.records[span.source_file_index]
    if (
        record.path != span.source_path
        or record.reference_id != span.source_reference_id
        or record.sha256 != span.source_file_sha256
    ):
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "selected notebook cell binding differs from the source lock"
        )
    notebook_path = root / record.reference_id / f"{record.sha256}.ipynb"
    notebook_raw = _read_confined_regular_file(
        notebook_path,
        root=root,
        max_bytes=_MAX_NOTEBOOK_BYTES,
        label="selected iFEM notebook",
    )
    if len(notebook_raw) != record.size_bytes or _sha256(notebook_raw) != record.sha256:
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "selected iFEM notebook differs from the source lock"
        )
    cell_text = _extract_markdown_cell_text(
        notebook_raw,
        cell_index=cell_index,
    )
    try:
        encoded = cell_text.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "selected notebook cell is not strict UTF-8"
        ) from error
    if not encoded:
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "selected notebook Markdown cell has no logical source text"
        )
    if len(encoded) > _MAX_CELL_UTF8_BYTES:
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "selected notebook Markdown cell exceeds the local projection limit"
        )
    try:
        projection = IFEMNotebookMarkdownCellTextProjectionV1(
            source_lock=IFEMNotebookMarkdownCellTextSourceLockBindingV1(
                receipt_sha256=source_lock.sha256,
                reference_manifest_candidate_sha256=(
                    source_lock.reference_manifest_candidate_sha256
                ),
                source_revision=source_lock.revision,
                source_file_count=len(source_lock.records),
            ),
            notebook_index=IFEMNotebookMarkdownCellTextIndexBindingV1(
                canonical_sha256=notebook_index.canonical_sha256()
            ),
            cell_span=span,
            cell_locator=f"notebook-cell:{span.cell_index}:type:markdown",
            cell_text=cell_text,
            cell_utf8_byte_count=len(encoded),
        )
    except ValidationError as error:
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "selected notebook cell cannot form the private projection contract"
        ) from error

    _require_unchanged(
        source_lock_path,
        root=root,
        expected=lock_raw,
        max_bytes=_MAX_SOURCE_LOCK_BYTES,
        label="iFEM source lock",
    )
    _require_unchanged(
        index_path,
        root=root,
        expected=index_raw,
        max_bytes=_MAX_NOTEBOOK_INDEX_BYTES,
        label="iFEM notebook source-span index",
    )
    _require_unchanged(
        notebook_path,
        root=root,
        expected=notebook_raw,
        max_bytes=_MAX_NOTEBOOK_BYTES,
        label="selected iFEM notebook",
    )
    return projection


def materialize_ifem_notebook_markdown_cell_text_projection(
    *,
    cache_root: Path,
    source_path: str,
    cell_index: int,
    expected_cell_sha256: str,
    expected_source_lock_sha256: str,
    expected_manifest_candidate_sha256: str,
    expected_notebook_index_canonical_sha256: str,
    expected_source_file_count: int,
) -> IFEMNotebookMarkdownCellTextProjectionResult:
    projection = build_ifem_notebook_markdown_cell_text_projection(
        cache_root=cache_root,
        source_path=source_path,
        cell_index=cell_index,
        expected_cell_sha256=expected_cell_sha256,
        expected_source_lock_sha256=expected_source_lock_sha256,
        expected_manifest_candidate_sha256=expected_manifest_candidate_sha256,
        expected_notebook_index_canonical_sha256=(expected_notebook_index_canonical_sha256),
        expected_source_file_count=expected_source_file_count,
    )
    root = _require_cache_root(cache_root)
    private_path = _private_projection_path(root, projection)
    rendered = render_ifem_notebook_markdown_cell_text_projection(projection)
    if len(rendered) > _MAX_PRIVATE_PROJECTION_BYTES:
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "private notebook cell text projection exceeds the local size limit"
        )
    _write_once_confined(private_path, rendered, root=root)
    replayed = _load_private_projection(
        _read_confined_regular_file(
            private_path,
            root=root,
            max_bytes=_MAX_PRIVATE_PROJECTION_BYTES,
            label="private notebook cell text projection",
        )
    )
    if replayed != projection:
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "installed private notebook cell projection differs from replay"
        )
    summary = summarize_ifem_notebook_markdown_cell_text_projection(projection)
    return IFEMNotebookMarkdownCellTextProjectionResult(projection, summary, private_path)


def verify_ifem_notebook_markdown_cell_text_projection(
    *,
    cache_root: Path,
    source_path: str,
    cell_index: int,
    expected_cell_sha256: str,
    expected_source_lock_sha256: str,
    expected_manifest_candidate_sha256: str,
    expected_notebook_index_canonical_sha256: str,
    expected_source_file_count: int,
) -> IFEMNotebookMarkdownCellTextProjectionResult:
    projection = build_ifem_notebook_markdown_cell_text_projection(
        cache_root=cache_root,
        source_path=source_path,
        cell_index=cell_index,
        expected_cell_sha256=expected_cell_sha256,
        expected_source_lock_sha256=expected_source_lock_sha256,
        expected_manifest_candidate_sha256=expected_manifest_candidate_sha256,
        expected_notebook_index_canonical_sha256=(expected_notebook_index_canonical_sha256),
        expected_source_file_count=expected_source_file_count,
    )
    root = _require_cache_root(cache_root)
    private_path = _private_projection_path(root, projection)
    raw = _read_confined_regular_file(
        private_path,
        root=root,
        max_bytes=_MAX_PRIVATE_PROJECTION_BYTES,
        label="private notebook cell text projection",
    )
    replayed = _load_private_projection(raw)
    if replayed != projection or raw != render_ifem_notebook_markdown_cell_text_projection(
        projection
    ):
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "private notebook cell projection differs from exact source replay"
        )
    summary = summarize_ifem_notebook_markdown_cell_text_projection(projection)
    return IFEMNotebookMarkdownCellTextProjectionResult(projection, summary, private_path)


def summarize_ifem_notebook_markdown_cell_text_projection(
    projection: IFEMNotebookMarkdownCellTextProjectionV1,
) -> IFEMNotebookMarkdownCellTextSummaryV1:
    rendered = render_ifem_notebook_markdown_cell_text_projection(projection)
    return IFEMNotebookMarkdownCellTextSummaryV1(
        source_lock_sha256=projection.source_lock.receipt_sha256,
        notebook_index_canonical_sha256=projection.notebook_index.canonical_sha256,
        cell_span_id=projection.cell_span.span_id,
        cell_locator=projection.cell_locator,
        cell_content_sha256=projection.cell_span.cell_content_sha256,
        private_projection_file_sha256=_sha256(rendered),
    )


def render_ifem_notebook_markdown_cell_text_projection(
    projection: IFEMNotebookMarkdownCellTextProjectionV1,
) -> bytes:
    return canonical_json_bytes(projection) + b"\n"


def render_ifem_notebook_markdown_cell_text_summary(
    summary: IFEMNotebookMarkdownCellTextSummaryV1,
) -> bytes:
    return canonical_json_bytes(summary) + b"\n"


def _validate_selection(source_path: str, cell_index: int, expected_cell_sha256: str) -> None:
    if not isinstance(source_path, str) or not source_path:
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "notebook source path must be nonempty text"
        )
    pure_path = PurePosixPath(source_path)
    if (
        pure_path.is_absolute()
        or ".." in pure_path.parts
        or "\\" in source_path
        or re.fullmatch(_PATH, source_path) is None
    ):
        raise IFEMNotebookMarkdownCellTextProjectionError("notebook source path is unsafe")
    if isinstance(cell_index, bool) or not isinstance(cell_index, int) or cell_index < 0:
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "notebook cell index must be a nonnegative integer"
        )
    _require_sha(expected_cell_sha256, label="expected notebook cell SHA-256")


def _parse_source_lock(
    raw: bytes,
    *,
    expected_sha256: str,
    expected_manifest_candidate_sha256: str,
    expected_source_file_count: int,
) -> _SourceLockReplay:
    payload = _load_json_object(raw, label="iFEM source lock")
    if canonical_json_bytes(payload) + b"\n" != raw:
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "iFEM source lock is not canonically rendered"
        )
    actual_sha256 = _sha256(raw)
    if actual_sha256 != expected_sha256:
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "iFEM source-lock receipt SHA-256 differs from the fixed binding"
        )
    required = {
        "acquisition",
        "policy",
        "reference_manifest_candidate_sha256",
        "reference_manifest_state",
        "schema_version",
        "source",
        "source_files",
        "state",
    }
    if set(payload) != required or payload.get("schema_version") != IFEM_SOURCE_LOCK_SCHEMA_VERSION:
        raise IFEMNotebookMarkdownCellTextProjectionError("iFEM source-lock schema is invalid")
    if (
        payload.get("state") != "acquired_local_only"
        or payload.get("reference_manifest_state") != "candidate_entries_not_yet_tracked"
    ):
        raise IFEMNotebookMarkdownCellTextProjectionError("iFEM source-lock state is invalid")
    if payload.get("policy") != {
        "access_policy": "public_open_access",
        "contract_freeze": "not_authorized",
        "model_egress_policy": "local_only",
        "prover_handoff": "not_authorized",
    }:
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "iFEM source lock does not retain the fixed local-only policy"
        )
    candidate_sha256 = payload.get("reference_manifest_candidate_sha256")
    if candidate_sha256 != expected_manifest_candidate_sha256:
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "iFEM source-lock manifest-candidate SHA-256 differs from the fixed binding"
        )
    source = _expect_mapping(payload.get("source"), label="iFEM source-lock source")
    if set(source) != {"license", "record_url", "resolved_revision"}:
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "iFEM source-lock source record has unexpected fields"
        )
    _expect_mapping(source.get("license"), label="iFEM source-lock license")
    if not isinstance(source.get("record_url"), str) or not source.get("record_url"):
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "iFEM source-lock repository record is invalid"
        )
    revision = source.get("resolved_revision")
    if not isinstance(revision, str) or not _is_lower_hex(revision, 40):
        raise IFEMNotebookMarkdownCellTextProjectionError("iFEM source-lock revision is invalid")
    acquisition = _expect_mapping(payload.get("acquisition"), label="iFEM source-lock acquisition")
    if set(acquisition) != {"retrieved_at", "source_file_count", "source_size_bytes"}:
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "iFEM source-lock acquisition has unexpected fields"
        )
    retrieved_at = acquisition.get("retrieved_at")
    if not isinstance(retrieved_at, str):
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "iFEM source-lock retrieval time is invalid"
        )
    try:
        parsed_retrieved_at = datetime.fromisoformat(retrieved_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "iFEM source-lock retrieval time is invalid"
        ) from error
    if parsed_retrieved_at.tzinfo is None or parsed_retrieved_at.utcoffset() != UTC.utcoffset(
        parsed_retrieved_at
    ):
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "iFEM source-lock retrieval time must carry a UTC offset"
        )
    raw_records = payload.get("source_files")
    if not isinstance(raw_records, list) or len(raw_records) != expected_source_file_count:
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "iFEM source lock does not retain the fixed source-file count"
        )
    records = tuple(_parse_source_file(item) for item in raw_records)
    if len({record.path for record in records}) != len(records) or len(
        {record.reference_id for record in records}
    ) != len(records):
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "iFEM source lock repeats a source identity"
        )
    source_file_count = acquisition.get("source_file_count")
    source_size_bytes = acquisition.get("source_size_bytes")
    if (
        not isinstance(source_file_count, int)
        or isinstance(source_file_count, bool)
        or source_file_count != len(records)
        or not isinstance(source_size_bytes, int)
        or isinstance(source_size_bytes, bool)
        or source_size_bytes != sum(record.size_bytes for record in records)
    ):
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "iFEM source-lock aggregate values differ from its records"
        )
    return _SourceLockReplay(
        raw=raw,
        sha256=actual_sha256,
        reference_manifest_candidate_sha256=candidate_sha256,
        revision=revision,
        retrieved_at=parsed_retrieved_at,
        records=records,
    )


def _parse_source_file(value: object) -> _LockedSourceFile:
    item = _expect_mapping(value, label="iFEM source-lock source file")
    if set(item) != {"path", "reference_id", "sha256", "size_bytes"}:
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "iFEM source-lock source file has unexpected fields"
        )
    source_path = item.get("path")
    reference_id = item.get("reference_id")
    sha256 = item.get("sha256")
    size_bytes = item.get("size_bytes")
    if (
        not isinstance(source_path, str)
        or not isinstance(reference_id, str)
        or not _is_reference_id(reference_id)
        or not isinstance(sha256, str)
        or not _is_lower_hex(sha256, 64)
        or not isinstance(size_bytes, int)
        or isinstance(size_bytes, bool)
        or not 0 < size_bytes <= _MAX_NOTEBOOK_BYTES
    ):
        raise IFEMNotebookMarkdownCellTextProjectionError("iFEM source-lock source file is invalid")
    pure_path = PurePosixPath(source_path)
    if pure_path.is_absolute() or ".." in pure_path.parts or "\\" in source_path:
        raise IFEMNotebookMarkdownCellTextProjectionError("iFEM source-lock source path is unsafe")
    return _LockedSourceFile(reference_id, source_path, sha256, size_bytes)


def _parse_notebook_index(
    raw: bytes,
    *,
    source_lock: _SourceLockReplay,
    expected_canonical_sha256: str,
) -> IFEMNotebookSourceSpanIndexV1:
    payload = _load_json_object(raw, label="iFEM notebook source-span index")
    try:
        index = IFEMNotebookSourceSpanIndexV1.model_validate(payload)
    except ValidationError as error:
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "iFEM notebook source-span index schema is invalid"
        ) from error
    if render_ifem_notebook_source_span_index(index) != raw:
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "iFEM notebook source-span index is not canonically rendered"
        )
    if index.canonical_sha256() != expected_canonical_sha256:
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "iFEM notebook source-span index differs from the fixed canonical binding"
        )
    expected_notebook_count = sum(record.path.endswith(".ipynb") for record in source_lock.records)
    if (
        index.source_lock.source_lock_sha256 != source_lock.sha256
        or index.source_lock.source_lock_schema_version != IFEM_SOURCE_LOCK_SCHEMA_VERSION
        or index.source_lock.source_revision != source_lock.revision
        or index.source_lock.source_retrieved_at != source_lock.retrieved_at
        or index.source_lock.source_file_count != len(source_lock.records)
        or index.source_lock.notebook_file_count != expected_notebook_count
    ):
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "iFEM notebook source-span index is detached from the source lock"
        )
    return index


def _extract_markdown_cell_text(raw: bytes, *, cell_index: int) -> str:
    notebook = _load_json_object(raw, label="selected iFEM notebook")
    nbformat = notebook.get("nbformat")
    if isinstance(nbformat, bool) or nbformat != 4:
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "selected iFEM notebook is not Jupyter nbformat 4"
        )
    cells = notebook.get("cells")
    if not isinstance(cells, list) or cell_index >= len(cells):
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "selected notebook cell is absent from the locked notebook"
        )
    cell = _expect_mapping(cells[cell_index], label="selected iFEM notebook cell")
    if cell.get("cell_type") != "markdown":
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "selected locked notebook cell is not Markdown"
        )
    source = cell.get("source")
    if isinstance(source, str):
        return source
    if isinstance(source, list) and all(isinstance(item, str) for item in source):
        return "".join(cast(list[str], source))
    raise IFEMNotebookMarkdownCellTextProjectionError(
        "selected locked notebook cell has an invalid logical source"
    )


def _load_private_projection(raw: bytes) -> IFEMNotebookMarkdownCellTextProjectionV1:
    payload = _load_json_object(raw, label="private notebook cell text projection")
    try:
        projection = IFEMNotebookMarkdownCellTextProjectionV1.model_validate(payload)
    except ValidationError as error:
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "private notebook cell text projection schema is invalid"
        ) from error
    if render_ifem_notebook_markdown_cell_text_projection(projection) != raw:
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "private notebook cell text projection is not canonically rendered"
        )
    return projection


def _load_json_object(raw: bytes, *, label: str) -> dict[str, object]:
    try:
        text = raw.decode("utf-8", errors="strict")
        payload = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
        )
    except IFEMNotebookMarkdownCellTextProjectionError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IFEMNotebookMarkdownCellTextProjectionError(
            f"{label} is not strict UTF-8 JSON"
        ) from error
    if not isinstance(payload, dict):
        raise IFEMNotebookMarkdownCellTextProjectionError(f"{label} root must be an object")
    return cast(dict[str, object], payload)


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise IFEMNotebookMarkdownCellTextProjectionError(
                "duplicate JSON key in local notebook text projection input"
            )
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> Never:
    raise IFEMNotebookMarkdownCellTextProjectionError(
        "non-finite JSON number in local notebook text projection input"
    )


def _private_projection_path(
    cache_root: Path,
    projection: IFEMNotebookMarkdownCellTextProjectionV1,
) -> Path:
    span_token = projection.cell_span.span_id.value.rpartition(":")[2]
    filename = f"{span_token}.{projection.cell_span.cell_content_sha256}.private.json"
    return cache_root / IFEM_LOCK_DIRECTORY / IFEM_NOTEBOOK_MARKDOWN_CELL_TEXT_DIRECTORY / filename


def _write_once_confined(path: Path, content: bytes, *, root: Path) -> None:
    target = _absolute_lexical(path)
    confined_root = _absolute_lexical(root)
    _relative_parts(target, confined_root)
    _ensure_confined_directory(target.parent, root=confined_root)
    existing = _read_optional_confined_regular_file(
        target,
        root=confined_root,
        max_bytes=_MAX_PRIVATE_PROJECTION_BYTES,
        label="existing private notebook cell text projection",
    )
    if existing is not None:
        if existing != content:
            raise IFEMNotebookMarkdownCellTextProjectionError(
                "existing private notebook cell text projection conflicts with exact replay"
            )
        return
    snapshot = _snapshot_existing_directory(target.parent)
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".ifem-notebook-cell-text-",
            suffix=".tmp",
            dir=target.parent,
        )
    except OSError as error:
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "cannot create private notebook cell text projection temporary"
        ) from error
    temporary = Path(temporary_name)
    try:
        opened = os.fstat(descriptor)
        _require_regular_stat(temporary, opened, label="private projection temporary")
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            descriptor = -1
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        _assert_directory_snapshot(snapshot)
        try:
            os.link(temporary, target, follow_symlinks=False)
        except FileExistsError:
            existing = _read_confined_regular_file(
                target,
                root=confined_root,
                max_bytes=_MAX_PRIVATE_PROJECTION_BYTES,
                label="racing private notebook cell text projection",
            )
            if existing != content:
                raise IFEMNotebookMarkdownCellTextProjectionError(
                    "racing private notebook cell text projection conflicts with exact replay"
                ) from None
        except OSError as error:
            raise IFEMNotebookMarkdownCellTextProjectionError(
                "cannot install private notebook cell text projection"
            ) from error
        _assert_directory_snapshot(snapshot)
        installed = _read_confined_regular_file(
            target,
            root=confined_root,
            max_bytes=_MAX_PRIVATE_PROJECTION_BYTES,
            label="installed private notebook cell text projection",
        )
        if installed != content:
            raise IFEMNotebookMarkdownCellTextProjectionError(
                "installed private notebook cell text projection differs from exact bytes"
            )
        _fsync_directory_if_supported(target.parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        _unlink_confined_temporary(temporary, target.parent)


def _require_cache_root(path: Path) -> Path:
    root = _absolute_lexical(path)
    _reject_unc(root)
    _snapshot_existing_directory(root)
    return root


def _ensure_confined_directory(path: Path, *, root: Path) -> None:
    relative = _relative_parts(path, root)
    _snapshot_existing_directory(root)
    current = root
    for part in relative:
        parent_snapshot = _snapshot_existing_directory(current)
        current = current / part
        metadata = _lstat_optional(current)
        if metadata is None:
            try:
                os.mkdir(current)
            except FileExistsError:
                pass
            except OSError as error:
                raise IFEMNotebookMarkdownCellTextProjectionError(
                    "cannot create private notebook cell projection directory"
                ) from error
            metadata = _lstat_optional(current)
        if metadata is None:
            raise IFEMNotebookMarkdownCellTextProjectionError(
                "private notebook cell projection directory is absent"
            )
        _require_directory_stat(current, metadata)
        _assert_directory_snapshot(parent_snapshot)


def _read_optional_confined_regular_file(
    path: Path,
    *,
    root: Path,
    max_bytes: int,
    label: str,
) -> bytes | None:
    target = _absolute_lexical(path)
    _relative_parts(target, _absolute_lexical(root))
    if _lstat_optional(target) is None:
        return None
    return _read_confined_regular_file(
        target,
        root=root,
        max_bytes=max_bytes,
        label=label,
    )


def _read_confined_regular_file(
    path: Path,
    *,
    root: Path,
    max_bytes: int,
    label: str,
) -> bytes:
    target = _absolute_lexical(path)
    confined_root = _absolute_lexical(root)
    _relative_parts(target, confined_root)
    snapshot = _snapshot_existing_directory(target.parent)
    before = _lstat_optional(target)
    if before is None:
        raise IFEMNotebookMarkdownCellTextProjectionError(f"{label} is absent")
    _require_regular_stat(target, before, label=label)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags)
    except OSError as error:
        raise IFEMNotebookMarkdownCellTextProjectionError(f"cannot open {label}") from error
    try:
        opened = os.fstat(descriptor)
        _require_regular_stat(target, opened, label=label)
        if not os.path.samestat(before, opened):
            raise IFEMNotebookMarkdownCellTextProjectionError(f"{label} changed while opening")
        data = bytearray()
        with os.fdopen(descriptor, "rb", closefd=True) as source:
            descriptor = -1
            while chunk := source.read(_CHUNK_BYTES):
                data.extend(chunk)
                if len(data) > max_bytes:
                    raise IFEMNotebookMarkdownCellTextProjectionError(
                        f"{label} exceeds the local size limit"
                    )
            after_open = os.fstat(source.fileno())
        if not os.path.samestat(opened, after_open):
            raise IFEMNotebookMarkdownCellTextProjectionError(f"{label} changed while reading")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    after = _lstat_optional(target)
    if after is None or not os.path.samestat(before, after):
        raise IFEMNotebookMarkdownCellTextProjectionError(f"{label} changed during verification")
    _require_regular_stat(target, after, label=label)
    _assert_directory_snapshot(snapshot)
    return bytes(data)


def _require_unchanged(
    path: Path,
    *,
    root: Path,
    expected: bytes,
    max_bytes: int,
    label: str,
) -> None:
    if (
        _read_confined_regular_file(
            path,
            root=root,
            max_bytes=max_bytes,
            label=label,
        )
        != expected
    ):
        raise IFEMNotebookMarkdownCellTextProjectionError(f"{label} changed during replay")


def _snapshot_existing_directory(path: Path) -> _DirectorySnapshot:
    directory = _absolute_lexical(path)
    _reject_unc(directory)
    if not directory.is_absolute() or not directory.anchor:
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "local projection directory must be absolute"
        )
    current = Path(directory.anchor)
    chain: list[tuple[Path, _DirectoryIdentity]] = []
    for index, part in enumerate(directory.parts):
        if index:
            current /= part
        metadata = _lstat_optional(current)
        if metadata is None:
            raise IFEMNotebookMarkdownCellTextProjectionError(
                "local projection directory is absent"
            )
        _require_directory_stat(current, metadata)
        chain.append((current, _identity(metadata)))
    return tuple(chain)


def _assert_directory_snapshot(snapshot: _DirectorySnapshot) -> None:
    for path, expected in snapshot:
        metadata = _lstat_optional(path)
        if metadata is None:
            raise IFEMNotebookMarkdownCellTextProjectionError(
                "local projection directory changed during operation"
            )
        _require_directory_stat(path, metadata)
        if _identity(metadata) != expected:
            raise IFEMNotebookMarkdownCellTextProjectionError(
                "local projection directory identity changed during operation"
            )


def _identity(metadata: os.stat_result) -> _DirectoryIdentity:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(stat.S_IFMT(metadata.st_mode)),
        int(getattr(metadata, "st_file_attributes", 0)),
    )


def _lstat_optional(path: Path) -> os.stat_result | None:
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "cannot inspect local projection path"
        ) from error


def _is_link_or_reparse(path: Path, metadata: os.stat_result) -> bool:
    is_junction = getattr(os.path, "isjunction", None)
    path_is_junction = getattr(path, "is_junction", None)
    return (
        stat.S_ISLNK(metadata.st_mode)
        or bool(int(getattr(metadata, "st_file_attributes", 0)) & _REPARSE_POINT)
        or bool(is_junction is not None and is_junction(path))
        or bool(path_is_junction is not None and path_is_junction())
    )


def _require_directory_stat(path: Path, metadata: os.stat_result) -> None:
    if _is_link_or_reparse(path, metadata):
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "local projection directories cannot be links, junctions, or reparse points"
        )
    if not stat.S_ISDIR(metadata.st_mode):
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "local projection path component is not a directory"
        )


def _require_regular_stat(path: Path, metadata: os.stat_result, *, label: str) -> None:
    if _is_link_or_reparse(path, metadata):
        raise IFEMNotebookMarkdownCellTextProjectionError(
            f"{label} cannot be a link, junction, or reparse point"
        )
    if not stat.S_ISREG(metadata.st_mode):
        raise IFEMNotebookMarkdownCellTextProjectionError(f"{label} is not a regular file")


def _absolute_lexical(path: Path) -> Path:
    if any(part in {".", ".."} for part in path.parts):
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "local projection path contains an unsafe component"
        )
    return Path(os.path.abspath(os.fspath(path)))


def _relative_parts(path: Path, root: Path) -> tuple[str, ...]:
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "local notebook text projection path escapes the source cache"
        ) from error
    if any(part in {"", ".", ".."} for part in relative.parts):
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "local notebook text projection path contains an unsafe component"
        )
    return relative.parts


def _reject_unc(path: Path) -> None:
    anchor = path.anchor
    if anchor.startswith("\\\\") or anchor == "//":
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "local notebook text projection does not accept UNC paths"
        )


def _unlink_confined_temporary(path: Path, parent: Path) -> None:
    temporary = _absolute_lexical(path)
    expected_parent = _absolute_lexical(parent)
    if temporary.parent != expected_parent or not temporary.name.startswith(
        ".ifem-notebook-cell-text-"
    ):
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "refusing to clean an unconfined notebook text temporary"
        )
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        return
    except OSError as error:
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "cannot clean notebook text projection temporary"
        ) from error


def _fsync_directory_if_supported(path: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "cannot open notebook text projection directory for synchronization"
        ) from error
    try:
        os.fsync(descriptor)
    except OSError as error:
        raise IFEMNotebookMarkdownCellTextProjectionError(
            "cannot synchronize notebook text projection directory"
        ) from error
    finally:
        os.close(descriptor)


def _expect_mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise IFEMNotebookMarkdownCellTextProjectionError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def _require_sha(value: str, *, label: str) -> None:
    if not isinstance(value, str) or not _is_lower_hex(value, 64):
        raise IFEMNotebookMarkdownCellTextProjectionError(
            f"{label} must be a lowercase SHA-256 value"
        )


def _is_lower_hex(value: str, length: int) -> bool:
    return len(value) == length and all(character in "0123456789abcdef" for character in value)


def _is_reference_id(value: str) -> bool:
    return (
        3 <= len(value) <= 128
        and value[0] in "abcdefghijklmnopqrstuvwxyz0123456789"
        and all(character in "abcdefghijklmnopqrstuvwxyz0123456789.-" for character in value)
    )


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()
