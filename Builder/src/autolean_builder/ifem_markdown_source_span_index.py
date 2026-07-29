"""Build a digest-only logical-heading index for the locked iFEM ``intro.md``.

This module is deliberately narrower than a Markdown extractor.  It replays one
already locked file, identifies its ATX-heading sections, and retains only
locators, digests, lengths, and source-lock provenance.  It does not serialize
source text, cache locations, model inputs, semantic decisions, freeze
authority, or Prover handoff authority.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
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
IFEM_MARKDOWN_SOURCE_SPAN_INDEX_SCHEMA_VERSION: Final[
    Literal["autolean.ifem-markdown-source-span-index.v1"]
] = "autolean.ifem-markdown-source-span-index.v1"
IFEM_MARKDOWN_SOURCE_SPAN_INDEX_KIND: Final[Literal["local_only_source_alignment_index"]] = (
    "local_only_source_alignment_index"
)
IFEM_OPENING_MARKDOWN_PATH: Final[Literal["intro.md"]] = "intro.md"
_SHA256 = r"^[0-9a-f]{64}$"
_REFERENCE_ID = r"^[a-z0-9][a-z0-9.-]{2,127}$"
_REVISION = r"^[0-9a-f]{40}$"
_SPAN_NAMESPACE = "ifem.markdown-source-span"
_RECORD_NAMESPACE = "ifem.source-record"
_ATX_HEADING = re.compile(r"^(?: {0,3})(#{1,6})[ \t]+(.*?)(?:[ \t]+#+[ \t]*)?$")
_FENCE = re.compile(r"^(?: {0,3})(`{3,}|~{3,}).*$")


class IFEMMarkdownSourceSpanIndexError(ValueError):
    """The iFEM source lock, cached Markdown, or redacted projection did not replay."""


@dataclass(frozen=True, slots=True)
class _LockedSourceFile:
    reference_id: str
    path: str
    sha256: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class _MarkdownHeading:
    index: int
    level: int
    line_index: int
    text: str


class IFEMMarkdownSourceLockBindingV1(ContractModel):
    """The replayed source-lock identity without a source path or cache location."""

    source_lock_sha256: str = Field(pattern=_SHA256)
    source_lock_schema_version: Literal["autolean.ifem-source-lock.v1"] = (
        IFEM_SOURCE_LOCK_SCHEMA_VERSION
    )
    source_revision: str = Field(pattern=_REVISION)
    source_retrieved_at: datetime
    source_file_count: int = Field(gt=0)
    markdown_file_count: Literal[1] = 1


class IFEMMarkdownHeadingSourceSpanV1(ContractModel):
    """One text-free ATX-heading section locator bound to locked Markdown bytes."""

    span_id: StableIdentifierV1
    source_path: Literal["intro.md"] = IFEM_OPENING_MARKDOWN_PATH
    source_reference_id: str = Field(pattern=_REFERENCE_ID)
    source_file_sha256: str = Field(pattern=_SHA256)
    source_file_index: int = Field(ge=0)
    heading_index: int = Field(ge=0)
    heading_level: int = Field(ge=1, le=6)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    heading_content_sha256: str = Field(pattern=_SHA256)
    heading_character_count: int = Field(gt=0)
    section_content_sha256: str = Field(pattern=_SHA256)
    section_character_count: int = Field(gt=0)

    @model_validator(mode="after")
    def validate_span(self) -> IFEMMarkdownHeadingSourceSpanV1:
        if self.span_id.namespace != _SPAN_NAMESPACE:
            raise ValueError("iFEM Markdown span has the wrong stable-id namespace")
        if self.end_line < self.start_line:
            raise ValueError("iFEM Markdown span ends before it starts")
        return self

    def as_source_span(self) -> SourceSpanV1:
        """Project this redacted locator into the existing Builder span contract."""

        return SourceSpanV1(
            span_id=self.span_id,
            locator=(
                "markdown-heading:"
                f"{self.heading_index}:level:{self.heading_level}:"
                f"lines:{self.start_line}-{self.end_line}"
            ),
            content_hash=DigestV1(kind=HashKindV1.SOURCE_SPAN, value=self.section_content_sha256),
        )


class IFEMMarkdownSourceSpanIndexV1(ContractModel):
    """The complete text-free logical-section index for the locked iFEM opening."""

    schema_version: Literal["autolean.ifem-markdown-source-span-index.v1"] = (
        IFEM_MARKDOWN_SOURCE_SPAN_INDEX_SCHEMA_VERSION
    )
    artifact_kind: Literal["local_only_source_alignment_index"] = (
        IFEM_MARKDOWN_SOURCE_SPAN_INDEX_KIND
    )
    source_lock: IFEMMarkdownSourceLockBindingV1
    model_egress_policy: Literal["local_only"] = "local_only"
    semantic_review_state: Literal["not_performed"] = "not_performed"
    contract_freeze: Literal["not_authorized"] = "not_authorized"
    prover_handoff: Literal["not_authorized"] = "not_authorized"
    contains_source_text: Literal[False] = False
    contains_model_input: Literal[False] = False
    markdown_heading_count: int = Field(gt=0)
    spans: tuple[IFEMMarkdownHeadingSourceSpanV1, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_index(self) -> IFEMMarkdownSourceSpanIndexV1:
        if self.markdown_heading_count != len(self.spans):
            raise ValueError("Markdown heading count differs from the span count")
        locations = [(span.source_path, span.heading_index) for span in self.spans]
        if len(locations) != len(set(locations)):
            raise ValueError("Markdown heading locations must be unique")
        order = [(span.source_file_index, span.heading_index) for span in self.spans]
        if tuple(sorted(order)) != tuple(order):
            raise ValueError("Markdown spans must retain source-lock and heading order")
        if {span.source_path for span in self.spans} != {IFEM_OPENING_MARKDOWN_PATH}:
            raise ValueError("Markdown index may only retain the locked opening path")
        source_file_indices = {span.source_file_index for span in self.spans}
        if (
            len(source_file_indices) != 1
            or min(source_file_indices) >= self.source_lock.source_file_count
        ):
            raise ValueError("Markdown source-file index is outside the source lock")
        source_identities = {
            (span.source_reference_id, span.source_file_sha256) for span in self.spans
        }
        if len(source_identities) != 1:
            raise ValueError("Markdown spans disagree about their locked source file")
        for span in self.spans:
            expected = _stable_span_id(
                self.source_lock.source_revision,
                span.source_path,
                span.heading_index,
            )
            if span.span_id != expected:
                raise ValueError("Markdown span identifier does not bind its stable location")
        return self

    def canonical_sha256(self) -> str:
        """Return the content address of this text-free projection."""

        return hashlib.sha256(canonical_json_bytes(self)).hexdigest()

    def source_records(self) -> tuple[SourceRecordV1, ...]:
        """Return a redacted SourceRecordV1 projection without source content or authority."""

        first = self.spans[0]
        return (
            SourceRecordV1(
                source_id=stable_identifier(
                    _RECORD_NAMESPACE,
                    f"{self.source_lock.source_revision}:{first.source_path}:{first.source_file_sha256}",
                ),
                work_id="ifem-interactive-fem-chapters-01-10",
                title="iFEM locked opening Markdown source",
                version=f"git-{self.source_lock.source_revision}",
                locator=first.source_path,
                content_hash=DigestV1(kind=HashKindV1.SOURCE_BYTES, value=first.source_file_sha256),
                snapshot_ref=f"ifem-source-lock:sha256:{self.source_lock.source_lock_sha256}",
                retrieved_at=self.source_lock.source_retrieved_at,
                spans=tuple(span.as_source_span() for span in self.spans),
                metadata={
                    "model_egress_policy": self.model_egress_policy,
                    "source_alignment_only": True,
                    "semantic_review_state": self.semantic_review_state,
                },
            ),
        )


def build_ifem_markdown_source_span_index(
    *,
    source_lock_path: Path,
    source_cache_root: Path,
) -> IFEMMarkdownSourceSpanIndexV1:
    """Replay locked ``intro.md`` and project its ATX-heading sections without text."""

    lock_bytes = _read_bytes(source_lock_path, label="iFEM source lock")
    lock = _load_json_object(lock_bytes, label="iFEM source lock")
    revision, retrieved_at, records = _parse_source_lock(lock)
    cache_root = _resolve_directory(source_cache_root, label="iFEM source cache root")
    source_file_index, record = _locked_opening_markdown(records)
    raw = _read_cached_markdown(cache_root, record)
    markdown = _canonical_logical_markdown(raw, source_path=record.path)
    lines = tuple(markdown.splitlines(keepends=True))
    headings = _parse_headings(lines, source_path=record.path)
    spans = tuple(
        _span_for_heading(
            heading=heading,
            headings=headings,
            lines=lines,
            revision=revision,
            record=record,
            source_file_index=source_file_index,
        )
        for heading in headings
    )
    return IFEMMarkdownSourceSpanIndexV1(
        source_lock=IFEMMarkdownSourceLockBindingV1(
            source_lock_sha256=hashlib.sha256(lock_bytes).hexdigest(),
            source_revision=revision,
            source_retrieved_at=retrieved_at,
            source_file_count=len(records),
        ),
        markdown_heading_count=len(spans),
        spans=spans,
    )


def render_ifem_markdown_source_span_index(index: IFEMMarkdownSourceSpanIndexV1) -> bytes:
    """Serialize exactly the schema-defined redacted projection."""

    return canonical_json_bytes(index) + b"\n"


def write_ifem_markdown_source_span_index(
    *,
    cache_root: Path,
    output_path: Path,
    index: IFEMMarkdownSourceSpanIndexV1,
) -> None:
    """Atomically write a replayable index below the ignored local source cache."""

    root = _resolve_directory(cache_root, label="iFEM source cache root")
    destination = output_path.resolve(strict=False)
    if not _is_relative_to(destination, root):
        raise IFEMMarkdownSourceSpanIndexError(
            "iFEM Markdown span index must stay below the source cache"
        )
    if destination.exists() and destination.is_symlink():
        raise IFEMMarkdownSourceSpanIndexError(
            "iFEM Markdown span index destination must not be a symlink"
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    parent = _resolve_directory(destination.parent, label="iFEM Markdown span index parent")
    if not _is_relative_to(parent, root):
        raise IFEMMarkdownSourceSpanIndexError(
            "iFEM Markdown span index parent escapes the source cache"
        )
    rendered = render_ifem_markdown_source_span_index(index)
    if destination.exists():
        if _read_bytes(destination, label="existing iFEM Markdown span index") == rendered:
            return
        raise IFEMMarkdownSourceSpanIndexError(
            "existing iFEM Markdown span index conflicts with replay"
        )
    descriptor, temporary_name = tempfile.mkstemp(prefix=".ifem-markdown-span-index-", dir=parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(rendered)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
    except OSError as error:
        raise IFEMMarkdownSourceSpanIndexError("cannot write iFEM Markdown span index") from error
    finally:
        if temporary.exists():
            temporary.unlink()


def _parse_source_lock(
    payload: Mapping[str, object],
) -> tuple[str, datetime, tuple[_LockedSourceFile, ...]]:
    if payload.get("schema_version") != IFEM_SOURCE_LOCK_SCHEMA_VERSION:
        raise IFEMMarkdownSourceSpanIndexError("unsupported iFEM source-lock schema")
    if payload.get("state") != "acquired_local_only":
        raise IFEMMarkdownSourceSpanIndexError("iFEM source lock is not acquired local-only")
    policy = _expect_mapping(payload.get("policy"), label="iFEM source-lock policy")
    if (
        policy.get("model_egress_policy") != ReferenceEgressPolicy.LOCAL_ONLY.value
        or policy.get("contract_freeze") != "not_authorized"
        or policy.get("prover_handoff") != "not_authorized"
    ):
        raise IFEMMarkdownSourceSpanIndexError(
            "iFEM source lock widens the local-only authority boundary"
        )
    source = _expect_mapping(payload.get("source"), label="iFEM source-lock source")
    revision = source.get("resolved_revision")
    if not isinstance(revision, str) or not _is_sha(revision, length=40):
        raise IFEMMarkdownSourceSpanIndexError("iFEM source lock revision is invalid")
    acquisition = _expect_mapping(payload.get("acquisition"), label="iFEM source-lock acquisition")
    retrieved_at = acquisition.get("retrieved_at")
    if not isinstance(retrieved_at, str):
        raise IFEMMarkdownSourceSpanIndexError("iFEM source lock retrieval time is invalid")
    try:
        parsed_retrieved_at = datetime.fromisoformat(retrieved_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise IFEMMarkdownSourceSpanIndexError(
            "iFEM source lock retrieval time is invalid"
        ) from error
    if parsed_retrieved_at.tzinfo is None:
        raise IFEMMarkdownSourceSpanIndexError(
            "iFEM source lock retrieval time is not timezone-aware"
        )
    raw_files = payload.get("source_files")
    if not isinstance(raw_files, list) or not raw_files:
        raise IFEMMarkdownSourceSpanIndexError("iFEM source lock source files are invalid")
    records = tuple(_parse_locked_source_file(item) for item in raw_files)
    if len({record.path for record in records}) != len(records):
        raise IFEMMarkdownSourceSpanIndexError("iFEM source lock repeats a source path")
    declared_count = acquisition.get("source_file_count")
    if isinstance(declared_count, bool) or declared_count != len(records):
        raise IFEMMarkdownSourceSpanIndexError("iFEM source lock source-file count differs")
    return revision, parsed_retrieved_at, records


def _parse_locked_source_file(value: object) -> _LockedSourceFile:
    item = _expect_mapping(value, label="iFEM source-lock source file")
    if set(item) != {"path", "reference_id", "sha256", "size_bytes"}:
        raise IFEMMarkdownSourceSpanIndexError("iFEM source-lock source file has unexpected fields")
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
        raise IFEMMarkdownSourceSpanIndexError("iFEM source-lock source file is invalid")
    pure_path = PurePosixPath(source_path)
    if pure_path.is_absolute() or ".." in pure_path.parts or "\\" in source_path:
        raise IFEMMarkdownSourceSpanIndexError("iFEM source-lock source path is unsafe")
    return _LockedSourceFile(
        reference_id=reference_id, path=source_path, sha256=sha256, size_bytes=size_bytes
    )


def _locked_opening_markdown(
    records: tuple[_LockedSourceFile, ...],
) -> tuple[int, _LockedSourceFile]:
    matched = tuple(
        (index, record)
        for index, record in enumerate(records)
        if record.path == IFEM_OPENING_MARKDOWN_PATH
    )
    if len(matched) != 1:
        raise IFEMMarkdownSourceSpanIndexError(
            "iFEM source lock must contain exactly one locked opening Markdown file"
        )
    return matched[0]


def _read_cached_markdown(cache_root: Path, record: _LockedSourceFile) -> bytes:
    if record.path != IFEM_OPENING_MARKDOWN_PATH:
        raise IFEMMarkdownSourceSpanIndexError("only the iFEM opening Markdown path may be indexed")
    target = cache_root / record.reference_id / f"{record.sha256}.md"
    if target.is_symlink():
        raise IFEMMarkdownSourceSpanIndexError("iFEM cached Markdown must not be a symlink")
    resolved_target = target.resolve(strict=False)
    if not _is_relative_to(resolved_target, cache_root):
        raise IFEMMarkdownSourceSpanIndexError("iFEM cached Markdown escapes the source cache")
    raw = _read_bytes(target, label=f"iFEM cached Markdown {record.path}")
    if len(raw) != record.size_bytes or hashlib.sha256(raw).hexdigest() != record.sha256:
        raise IFEMMarkdownSourceSpanIndexError(
            f"iFEM cached Markdown does not match source lock: {record.path}"
        )
    return raw


def _canonical_logical_markdown(raw: bytes, *, source_path: str) -> str:
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise IFEMMarkdownSourceSpanIndexError(
            f"iFEM Markdown is not valid UTF-8: {source_path}"
        ) from error
    canonical = decoded.replace("\r\n", "\n").replace("\r", "\n")
    if not canonical:
        raise IFEMMarkdownSourceSpanIndexError(f"iFEM Markdown is empty: {source_path}")
    return canonical


def _parse_headings(lines: tuple[str, ...], *, source_path: str) -> tuple[_MarkdownHeading, ...]:
    headings: list[_MarkdownHeading] = []
    active_fence: tuple[str, int] | None = None
    for line_index, line in enumerate(lines):
        logical_line = line.removesuffix("\n")
        fence = _fence_marker(logical_line)
        if active_fence is not None:
            if fence is not None and fence[0] == active_fence[0] and fence[1] >= active_fence[1]:
                active_fence = None
            continue
        if fence is not None:
            active_fence = fence
            continue
        match = _ATX_HEADING.fullmatch(logical_line)
        if match is None:
            continue
        heading_text = match.group(2).strip()
        if not heading_text:
            raise IFEMMarkdownSourceSpanIndexError(
                f"iFEM Markdown has an empty ATX heading: {source_path}:{line_index + 1}"
            )
        headings.append(
            _MarkdownHeading(
                index=len(headings),
                level=len(match.group(1)),
                line_index=line_index,
                text=heading_text,
            )
        )
    if active_fence is not None:
        raise IFEMMarkdownSourceSpanIndexError(
            f"iFEM Markdown has an unclosed fenced block: {source_path}"
        )
    if not headings:
        raise IFEMMarkdownSourceSpanIndexError(f"iFEM Markdown has no ATX headings: {source_path}")
    return tuple(headings)


def _span_for_heading(
    *,
    heading: _MarkdownHeading,
    headings: tuple[_MarkdownHeading, ...],
    lines: tuple[str, ...],
    revision: str,
    record: _LockedSourceFile,
    source_file_index: int,
) -> IFEMMarkdownHeadingSourceSpanV1:
    end_line_index = len(lines)
    for later in headings[heading.index + 1 :]:
        if later.level <= heading.level:
            end_line_index = later.line_index
            break
    section = "".join(lines[heading.line_index : end_line_index])
    if not section:
        raise IFEMMarkdownSourceSpanIndexError(
            f"iFEM Markdown has an empty heading section: {record.path}:{heading.line_index + 1}"
        )
    return IFEMMarkdownHeadingSourceSpanV1(
        span_id=_stable_span_id(revision, record.path, heading.index),
        source_reference_id=record.reference_id,
        source_file_sha256=record.sha256,
        source_file_index=source_file_index,
        heading_index=heading.index,
        heading_level=heading.level,
        start_line=heading.line_index + 1,
        end_line=end_line_index,
        heading_content_sha256=hashlib.sha256(heading.text.encode("utf-8")).hexdigest(),
        heading_character_count=len(heading.text),
        section_content_sha256=hashlib.sha256(section.encode("utf-8")).hexdigest(),
        section_character_count=len(section),
    )


def _stable_span_id(revision: str, source_path: str, heading_index: int) -> StableIdentifierV1:
    return stable_identifier(
        _SPAN_NAMESPACE,
        f"{revision}:{source_path}:heading:{heading_index}",
    )


def _fence_marker(line: str) -> tuple[str, int] | None:
    match = _FENCE.fullmatch(line)
    if match is None:
        return None
    marker = match.group(1)
    return marker[0], len(marker)


def _load_json_object(raw: bytes, *, label: str) -> dict[str, object]:
    try:
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
    except IFEMMarkdownSourceSpanIndexError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IFEMMarkdownSourceSpanIndexError(f"{label} is not valid UTF-8 JSON") from error
    if not isinstance(payload, dict):
        raise IFEMMarkdownSourceSpanIndexError(f"{label} root must be an object")
    return cast(dict[str, object], payload)


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise IFEMMarkdownSourceSpanIndexError("duplicate JSON key in iFEM source input")
        result[key] = value
    return result


def _read_bytes(path: Path, *, label: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as error:
        raise IFEMMarkdownSourceSpanIndexError(f"cannot read {label}") from error


def _resolve_directory(path: Path, *, label: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise IFEMMarkdownSourceSpanIndexError(f"{label} is absent or inaccessible") from error
    if not resolved.is_dir():
        raise IFEMMarkdownSourceSpanIndexError(f"{label} is not a directory")
    return resolved


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _expect_mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise IFEMMarkdownSourceSpanIndexError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def _is_sha(value: str, *, length: int) -> bool:
    return len(value) == length and all(character in "0123456789abcdef" for character in value)


def _is_reference_id(value: str) -> bool:
    return (
        3 <= len(value) <= 128
        and value[0] in "abcdefghijklmnopqrstuvwxyz0123456789"
        and all(character in "abcdefghijklmnopqrstuvwxyz0123456789.-" for character in value)
    )
