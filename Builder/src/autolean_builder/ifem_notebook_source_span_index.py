"""Build a digest-only iFEM notebook-cell index from an already verified local lock.

The index is a source-alignment aid, not an extraction, semantic-review, freeze, or
Prover-handoff artifact.  It deliberately parses Jupyter notebooks as JSON and retains only
paths, content-addressed identities, cell positions/types, and hashes of logical cell sources.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Final, Literal, cast

from autolean_contracts import (
    ContractModel,
    DigestV1,
    HashKindV1,
    SourceRecordV1,
    SourceSpanV1,
    StableIdentifierV1,
    canonical_json_bytes,
    stable_identifier,
)
from pydantic import Field, model_validator

from .reference_cache import ReferenceEgressPolicy

IFEM_SOURCE_LOCK_SCHEMA_VERSION: Final[Literal["autolean.ifem-source-lock.v1"]] = (
    "autolean.ifem-source-lock.v1"
)
IFEM_NOTEBOOK_SOURCE_SPAN_INDEX_SCHEMA_VERSION: Final[
    Literal["autolean.ifem-notebook-source-span-index.v1"]
] = "autolean.ifem-notebook-source-span-index.v1"
IFEM_NOTEBOOK_SOURCE_SPAN_INDEX_KIND: Final[Literal["local_only_source_alignment_index"]] = (
    "local_only_source_alignment_index"
)
_SHA256 = r"^[0-9a-f]{64}$"
_PATH = r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\.ipynb$"
_REFERENCE_ID = r"^[a-z0-9][a-z0-9.-]{2,127}$"
_REVISION = r"^[0-9a-f]{40}$"
_CELL_TYPES = frozenset({"code", "markdown", "raw"})
_SPAN_NAMESPACE = "ifem.notebook-source-span"
_RECORD_NAMESPACE = "ifem.source-record"


class IFEMNotebookSourceSpanIndexError(ValueError):
    """The iFEM source lock, cached bytes, or digest-only projection did not replay."""


@dataclass(frozen=True, slots=True)
class _LockedSourceFile:
    reference_id: str
    path: str
    sha256: str
    size_bytes: int


class IFEMSourceLockBindingV1(ContractModel):
    """The replayed lock identity, without any notebook content or descriptive title."""

    source_lock_sha256: str = Field(pattern=_SHA256)
    source_lock_schema_version: Literal["autolean.ifem-source-lock.v1"] = (
        IFEM_SOURCE_LOCK_SCHEMA_VERSION
    )
    source_revision: str = Field(pattern=_REVISION)
    source_retrieved_at: datetime
    source_file_count: int = Field(gt=0)
    notebook_file_count: int = Field(gt=0)


class IFEMNotebookCellSourceSpanV1(ContractModel):
    """One text-free notebook-cell locator bound to a locked notebook byte stream."""

    span_id: StableIdentifierV1
    source_path: str = Field(pattern=_PATH)
    source_reference_id: str = Field(pattern=_REFERENCE_ID)
    source_file_sha256: str = Field(pattern=_SHA256)
    source_file_index: int = Field(ge=0)
    cell_index: int = Field(ge=0)
    cell_type: Literal["code", "markdown", "raw"]
    cell_content_sha256: str = Field(pattern=_SHA256)
    cell_character_count: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_span_namespace(self) -> IFEMNotebookCellSourceSpanV1:
        if self.span_id.namespace != _SPAN_NAMESPACE:
            raise ValueError("iFEM notebook span has the wrong stable-id namespace")
        return self

    def as_source_span(self) -> SourceSpanV1:
        """Project the redacted cell identity into the existing Builder span contract."""

        return SourceSpanV1(
            span_id=self.span_id,
            locator=f"notebook-cell:{self.cell_index}:type:{self.cell_type}",
            content_hash=DigestV1(kind=HashKindV1.SOURCE_SPAN, value=self.cell_content_sha256),
        )


class IFEMNotebookSourceSpanIndexV1(ContractModel):
    """The complete text-free local alignment index for the locked iFEM notebooks."""

    schema_version: Literal["autolean.ifem-notebook-source-span-index.v1"] = (
        IFEM_NOTEBOOK_SOURCE_SPAN_INDEX_SCHEMA_VERSION
    )
    artifact_kind: Literal["local_only_source_alignment_index"] = (
        IFEM_NOTEBOOK_SOURCE_SPAN_INDEX_KIND
    )
    source_lock: IFEMSourceLockBindingV1
    model_egress_policy: Literal["local_only"] = "local_only"
    semantic_review_state: Literal["not_performed"] = "not_performed"
    contract_freeze: Literal["not_authorized"] = "not_authorized"
    prover_handoff: Literal["not_authorized"] = "not_authorized"
    contains_source_text: Literal[False] = False
    contains_model_input: Literal[False] = False
    notebook_cell_count: int = Field(gt=0)
    spans: tuple[IFEMNotebookCellSourceSpanV1, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_index(self) -> IFEMNotebookSourceSpanIndexV1:
        if self.notebook_cell_count != len(self.spans):
            raise ValueError("notebook cell count differs from the span count")
        locations = [(span.source_path, span.cell_index) for span in self.spans]
        if len(locations) != len(set(locations)):
            raise ValueError("notebook cell locations must be unique")
        order = [(span.source_file_index, span.cell_index) for span in self.spans]
        if tuple(sorted(order)) != tuple(order):
            raise ValueError("notebook spans must retain source-lock and cell order")
        paths = {span.source_path for span in self.spans}
        if len(paths) != self.source_lock.notebook_file_count:
            raise ValueError("notebook file count differs from indexed source paths")
        for span in self.spans:
            pure_path = PurePosixPath(span.source_path)
            if ".." in pure_path.parts:
                raise ValueError("notebook span source path must stay relative")
            expected = _stable_span_id(
                self.source_lock.source_revision,
                span.source_path,
                span.cell_index,
            )
            if span.span_id != expected:
                raise ValueError("notebook span identifier does not bind its stable location")
        return self

    def canonical_sha256(self) -> str:
        """Return the content address of this text-free projection."""

        return hashlib.sha256(canonical_json_bytes(self)).hexdigest()

    def source_records(self) -> tuple[SourceRecordV1, ...]:
        """Return existing Builder source-record projections without serializing source content."""

        grouped: defaultdict[tuple[int, str, str, str], list[IFEMNotebookCellSourceSpanV1]] = (
            defaultdict(list)
        )
        for span in self.spans:
            grouped[
                (
                    span.source_file_index,
                    span.source_path,
                    span.source_reference_id,
                    span.source_file_sha256,
                )
            ].append(span)
        return tuple(
            SourceRecordV1(
                source_id=stable_identifier(
                    _RECORD_NAMESPACE,
                    f"{self.source_lock.source_revision}:{source_path}:{source_sha256}",
                ),
                work_id="ifem-interactive-fem-chapters-01-10",
                title="iFEM locked notebook source",
                version=f"git-{self.source_lock.source_revision}",
                locator=source_path,
                content_hash=DigestV1(kind=HashKindV1.SOURCE_BYTES, value=source_sha256),
                snapshot_ref=f"ifem-source-lock:sha256:{self.source_lock.source_lock_sha256}",
                retrieved_at=self.source_lock.source_retrieved_at,
                spans=tuple(item.as_source_span() for item in cells),
                metadata={
                    "model_egress_policy": self.model_egress_policy,
                    "source_alignment_only": True,
                    "semantic_review_state": self.semantic_review_state,
                },
            )
            for (_file_index, source_path, _reference_id, source_sha256), cells in sorted(
                grouped.items()
            )
        )


def build_ifem_notebook_source_span_index(
    *,
    source_lock_path: Path,
    source_cache_root: Path,
) -> IFEMNotebookSourceSpanIndexV1:
    """Replay one local source lock and project its notebook cells without retaining their text."""

    lock_bytes = _read_bytes(source_lock_path, label="iFEM source lock")
    lock = _load_json_object(lock_bytes, label="iFEM source lock")
    revision, retrieved_at, records = _parse_source_lock(lock)
    cache_root = _resolve_directory(source_cache_root, label="iFEM source cache root")
    spans: list[IFEMNotebookCellSourceSpanV1] = []
    notebook_records = tuple(
        (source_file_index, record)
        for source_file_index, record in enumerate(records)
        if record.path.endswith(".ipynb")
    )
    for source_file_index, record in notebook_records:
        raw = _read_cached_source(cache_root, record)
        notebook = _load_json_object(raw, label=f"iFEM notebook {record.path}")
        nbformat = notebook.get("nbformat")
        if not isinstance(nbformat, int) or isinstance(nbformat, bool):
            raise IFEMNotebookSourceSpanIndexError(
                f"iFEM notebook has no valid nbformat: {record.path}"
            )
        cells = notebook.get("cells")
        if not isinstance(cells, list):
            raise IFEMNotebookSourceSpanIndexError(
                f"iFEM notebook has no cell array: {record.path}"
            )
        for cell_index, cell in enumerate(cells):
            cell_type, source = _parse_notebook_cell(
                cell, source_path=record.path, cell_index=cell_index
            )
            spans.append(
                IFEMNotebookCellSourceSpanV1(
                    span_id=_stable_span_id(revision, record.path, cell_index),
                    source_path=record.path,
                    source_reference_id=record.reference_id,
                    source_file_sha256=record.sha256,
                    source_file_index=source_file_index,
                    cell_index=cell_index,
                    cell_type=cast(Literal["code", "markdown", "raw"], cell_type),
                    cell_content_sha256=hashlib.sha256(source.encode("utf-8")).hexdigest(),
                    cell_character_count=len(source),
                )
            )
    if not spans:
        raise IFEMNotebookSourceSpanIndexError("iFEM source lock contains no notebook cells")
    return IFEMNotebookSourceSpanIndexV1(
        source_lock=IFEMSourceLockBindingV1(
            source_lock_sha256=hashlib.sha256(lock_bytes).hexdigest(),
            source_revision=revision,
            source_retrieved_at=retrieved_at,
            source_file_count=len(records),
            notebook_file_count=len(notebook_records),
        ),
        notebook_cell_count=len(spans),
        spans=tuple(sorted(spans, key=lambda span: (span.source_file_index, span.cell_index))),
    )


def render_ifem_notebook_source_span_index(index: IFEMNotebookSourceSpanIndexV1) -> bytes:
    """Serialize exactly the schema-defined redacted projection."""

    return canonical_json_bytes(index) + b"\n"


def write_ifem_notebook_source_span_index(
    *,
    cache_root: Path,
    output_path: Path,
    index: IFEMNotebookSourceSpanIndexV1,
) -> None:
    """Atomically write a replayable index below the ignored local source cache."""

    root = _resolve_directory(cache_root, label="iFEM source cache root")
    destination = output_path.resolve(strict=False)
    if not _is_relative_to(destination, root):
        raise IFEMNotebookSourceSpanIndexError("iFEM span index must stay below the source cache")
    if output_path.exists() and output_path.is_symlink():
        raise IFEMNotebookSourceSpanIndexError("iFEM span index destination must not be a symlink")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    parent = _resolve_directory(output_path.parent, label="iFEM span index parent")
    if not _is_relative_to(parent, root):
        raise IFEMNotebookSourceSpanIndexError("iFEM span index parent escapes the source cache")
    rendered = render_ifem_notebook_source_span_index(index)
    if output_path.exists():
        if _read_bytes(output_path, label="existing iFEM span index") == rendered:
            return
        raise IFEMNotebookSourceSpanIndexError("existing iFEM span index conflicts with replay")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".ifem-span-index-", dir=parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(rendered)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, output_path)
    except OSError as error:
        raise IFEMNotebookSourceSpanIndexError("cannot write iFEM span index") from error
    finally:
        if temporary.exists():
            temporary.unlink()


def _parse_source_lock(
    payload: Mapping[str, object],
) -> tuple[str, datetime, tuple[_LockedSourceFile, ...]]:
    if payload.get("schema_version") != IFEM_SOURCE_LOCK_SCHEMA_VERSION:
        raise IFEMNotebookSourceSpanIndexError("unsupported iFEM source-lock schema")
    if payload.get("state") != "acquired_local_only":
        raise IFEMNotebookSourceSpanIndexError("iFEM source lock is not acquired local-only")
    policy = _expect_mapping(payload.get("policy"), label="iFEM source-lock policy")
    if (
        policy.get("model_egress_policy") != ReferenceEgressPolicy.LOCAL_ONLY.value
        or policy.get("contract_freeze") != "not_authorized"
        or policy.get("prover_handoff") != "not_authorized"
    ):
        raise IFEMNotebookSourceSpanIndexError("iFEM source lock widens the local-only policy")
    source = _expect_mapping(payload.get("source"), label="iFEM source-lock source")
    revision = source.get("resolved_revision")
    if not isinstance(revision, str) or not _is_sha(revision, length=40):
        raise IFEMNotebookSourceSpanIndexError("iFEM source lock revision is invalid")
    acquisition = _expect_mapping(payload.get("acquisition"), label="iFEM source-lock acquisition")
    retrieved_at = acquisition.get("retrieved_at")
    if not isinstance(retrieved_at, str):
        raise IFEMNotebookSourceSpanIndexError("iFEM source lock retrieval time is invalid")
    try:
        parsed_retrieved_at = datetime.fromisoformat(retrieved_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise IFEMNotebookSourceSpanIndexError(
            "iFEM source lock retrieval time is invalid"
        ) from error
    if parsed_retrieved_at.tzinfo is None:
        raise IFEMNotebookSourceSpanIndexError(
            "iFEM source lock retrieval time is not timezone-aware"
        )
    raw_files = payload.get("source_files")
    if not isinstance(raw_files, list) or not raw_files:
        raise IFEMNotebookSourceSpanIndexError("iFEM source lock source files are invalid")
    records = tuple(_parse_locked_source_file(item) for item in raw_files)
    if len({record.path for record in records}) != len(records):
        raise IFEMNotebookSourceSpanIndexError("iFEM source lock repeats a source path")
    declared_count = acquisition.get("source_file_count")
    if isinstance(declared_count, bool) or declared_count != len(records):
        raise IFEMNotebookSourceSpanIndexError("iFEM source lock source-file count differs")
    if not any(record.path.endswith(".ipynb") for record in records):
        raise IFEMNotebookSourceSpanIndexError("iFEM source lock contains no notebooks")
    return revision, parsed_retrieved_at, records


def _parse_locked_source_file(value: object) -> _LockedSourceFile:
    item = _expect_mapping(value, label="iFEM source-lock source file")
    if set(item) != {"path", "reference_id", "sha256", "size_bytes"}:
        raise IFEMNotebookSourceSpanIndexError("iFEM source-lock source file has unexpected fields")
    source_path = item.get("path")
    reference_id = item.get("reference_id")
    sha256 = item.get("sha256")
    size_bytes = item.get("size_bytes")
    if (
        not isinstance(source_path, str)
        or not isinstance(reference_id, str)
        or not _is_reference_id(reference_id)
        or not isinstance(sha256, str)
        or not _is_sha(sha256, length=64)
        or not isinstance(size_bytes, int)
        or isinstance(size_bytes, bool)
        or size_bytes <= 0
    ):
        raise IFEMNotebookSourceSpanIndexError("iFEM source-lock source file is invalid")
    pure_path = PurePosixPath(source_path)
    if pure_path.is_absolute() or ".." in pure_path.parts or "\\" in source_path:
        raise IFEMNotebookSourceSpanIndexError("iFEM source-lock source path is unsafe")
    return _LockedSourceFile(
        reference_id=reference_id, path=source_path, sha256=sha256, size_bytes=size_bytes
    )


def _read_cached_source(cache_root: Path, record: _LockedSourceFile) -> bytes:
    extension = PurePosixPath(record.path).suffix.casefold()
    if extension != ".ipynb":
        raise IFEMNotebookSourceSpanIndexError("only iFEM notebooks may be indexed")
    target = cache_root / record.reference_id / f"{record.sha256}{extension}"
    if target.is_symlink():
        raise IFEMNotebookSourceSpanIndexError("iFEM cached notebook must not be a symlink")
    resolved_target = target.resolve(strict=False)
    if not _is_relative_to(resolved_target, cache_root):
        raise IFEMNotebookSourceSpanIndexError("iFEM cached notebook escapes the source cache")
    raw = _read_bytes(target, label=f"iFEM cached notebook {record.path}")
    if len(raw) != record.size_bytes or hashlib.sha256(raw).hexdigest() != record.sha256:
        raise IFEMNotebookSourceSpanIndexError(
            f"iFEM cached notebook does not match source lock: {record.path}"
        )
    return raw


def _parse_notebook_cell(value: object, *, source_path: str, cell_index: int) -> tuple[str, str]:
    cell = _expect_mapping(value, label=f"iFEM notebook cell {source_path}:{cell_index}")
    cell_type = cell.get("cell_type")
    if not isinstance(cell_type, str) or cell_type not in _CELL_TYPES:
        raise IFEMNotebookSourceSpanIndexError(
            f"iFEM notebook cell has an unsupported type: {source_path}:{cell_index}"
        )
    source = cell.get("source")
    if isinstance(source, str):
        return cell_type, source
    if isinstance(source, list) and all(isinstance(item, str) for item in source):
        return cell_type, "".join(cast(list[str], source))
    raise IFEMNotebookSourceSpanIndexError(
        f"iFEM notebook cell has an invalid source: {source_path}:{cell_index}"
    )


def _stable_span_id(revision: str, source_path: str, cell_index: int) -> StableIdentifierV1:
    return stable_identifier(_SPAN_NAMESPACE, f"{revision}:{source_path}:cell:{cell_index}")


def _load_json_object(raw: bytes, *, label: str) -> dict[str, object]:
    try:
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
    except IFEMNotebookSourceSpanIndexError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IFEMNotebookSourceSpanIndexError(f"{label} is not valid UTF-8 JSON") from error
    if not isinstance(payload, dict):
        raise IFEMNotebookSourceSpanIndexError(f"{label} root must be an object")
    return cast(dict[str, object], payload)


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise IFEMNotebookSourceSpanIndexError("duplicate JSON key in iFEM source input")
        result[key] = value
    return result


def _read_bytes(path: Path, *, label: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as error:
        raise IFEMNotebookSourceSpanIndexError(f"cannot read {label}") from error


def _resolve_directory(path: Path, *, label: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise IFEMNotebookSourceSpanIndexError(f"{label} is absent or inaccessible") from error
    if not resolved.is_dir():
        raise IFEMNotebookSourceSpanIndexError(f"{label} is not a directory")
    return resolved


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _expect_mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise IFEMNotebookSourceSpanIndexError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def _is_sha(value: str, *, length: int) -> bool:
    return len(value) == length and all(character in "0123456789abcdef" for character in value)


def _is_reference_id(value: str) -> bool:
    return (
        3 <= len(value) <= 128
        and value[0] in "abcdefghijklmnopqrstuvwxyz0123456789"
        and all(character in "abcdefghijklmnopqrstuvwxyz0123456789.-" for character in value)
    )
