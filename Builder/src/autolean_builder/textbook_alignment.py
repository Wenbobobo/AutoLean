"""Local-only, non-freezing textbook alignment discovery.

This module intentionally stops before candidate extraction. It binds a small opening
sample to the verified derived-text artifact and its exact parent artifact, then emits a
private worksheet plus a text-free public summary. It has no model, contract-freeze, or
Prover dependency.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import Literal

from autolean_contracts import canonical_json_bytes
from autolean_contracts.base import ContractModel
from pydantic import ConfigDict, Field, model_validator

from .reference_cache import (
    ReferenceArtifactKind,
    ReferenceCache,
    ReferenceCacheError,
    ReferenceEgressPolicy,
    ReferenceManifestV1,
)

DISCOVERY_STATUS: Literal["textbook_alignment_discovery_nonfreeze"] = (
    "textbook_alignment_discovery_nonfreeze"
)
_CANDIDATE_HASH_DOMAIN = b"autolean:textbook-alignment-candidate:v1\x00"
_SHA256 = r"^[0-9a-f]{64}$"
_CANDIDATE_IDENTIFIER = r"^[a-z][a-z0-9-]{2,127}$"
_REFERENCE_IDENTIFIER = r"^[a-z0-9][a-z0-9.-]{2,127}$"
_LOCATOR = r"^form-feed-page:[0-9]{4}#utf8-bytes:[0-9]+-[0-9]+$"
_ASCII_WHITESPACE = frozenset(b" \t\r\n\v\f")
_MAX_PAGE_COUNT = 8
_MAX_EXCERPT_BYTES = 65_536
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_DirectoryIdentity = tuple[int, int, int, int]


class TextbookAlignmentError(ValueError):
    """The local discovery input or output violated its authority boundary."""


class TextbookAlignmentSourceSpanV1(ContractModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=False,
        validate_default=True,
    )

    page_number: int = Field(ge=1)
    locator: str = Field(pattern=_LOCATOR)
    global_byte_start: int = Field(ge=0)
    global_byte_end: int = Field(gt=0)
    span_sha256: str = Field(pattern=_SHA256)
    excerpt: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_exact_span(self) -> TextbookAlignmentSourceSpanV1:
        encoded = self.excerpt.encode("utf-8")
        if self.global_byte_end <= self.global_byte_start:
            raise ValueError("source span must be nonempty")
        if len(encoded) != self.global_byte_end - self.global_byte_start:
            raise ValueError("source span byte offsets do not match the UTF-8 excerpt")
        if hashlib.sha256(encoded).hexdigest() != self.span_sha256:
            raise ValueError("source span hash does not match the UTF-8 excerpt")
        expected_locator = (
            f"form-feed-page:{self.page_number:04d}"
            f"#utf8-bytes:{self.global_byte_start}-{self.global_byte_end}"
        )
        if self.locator != expected_locator:
            raise ValueError("source span locator does not match its page and byte offsets")
        return self


class TextbookAlignmentMutationWorksheetV1(ContractModel):
    mutation_kind: Literal["quantifier", "boundary"]
    review_prompt: str = Field(min_length=1)
    baseline_text: str | None = None
    mutated_text: str | None = None
    human_review: Literal["pending"] = "pending"

    @model_validator(mode="after")
    def validate_pair(self) -> TextbookAlignmentMutationWorksheetV1:
        if (self.baseline_text is None) != (self.mutated_text is None):
            raise ValueError("mutation baseline and mutated text must be filled together")
        if self.baseline_text is not None and self.baseline_text == self.mutated_text:
            raise ValueError("a filled mutation must change the baseline")
        return self


class TextbookAlignmentCandidateWorksheetV1(ContractModel):
    candidate_id: str = Field(pattern=_CANDIDATE_IDENTIFIER)
    source_span: TextbookAlignmentSourceSpanV1
    extraction_status: Literal["source_bound_pending_manual_extraction"] = (
        "source_bound_pending_manual_extraction"
    )
    normalized_candidate: str | None = None
    lean_like_draft: str | None = None
    ambiguities: tuple[str, ...] = ()
    positive_examples: tuple[str, ...] = ()
    negative_examples: tuple[str, ...] = ()
    quantifier_mutations: tuple[TextbookAlignmentMutationWorksheetV1, ...] = Field(min_length=1)
    boundary_mutations: tuple[TextbookAlignmentMutationWorksheetV1, ...] = Field(min_length=1)
    mathlib_mapping_status: Literal["pending"] = "pending"
    human_review: Literal["pending"] = "pending"
    semantic_review_claimed: Literal[False] = False

    @model_validator(mode="after")
    def validate_pending_discovery(self) -> TextbookAlignmentCandidateWorksheetV1:
        if any(item.mutation_kind != "quantifier" for item in self.quantifier_mutations):
            raise ValueError("quantifier worksheet contains a non-quantifier mutation")
        if any(item.mutation_kind != "boundary" for item in self.boundary_mutations):
            raise ValueError("boundary worksheet contains a non-boundary mutation")
        return self


class TextbookAlignmentPrivatePacketV1(ContractModel):
    schema_version: Literal["autolean.textbook-alignment-private-packet.v1"] = (
        "autolean.textbook-alignment-private-packet.v1"
    )
    status: Literal["textbook_alignment_discovery_nonfreeze"] = DISCOVERY_STATUS
    manifest_sha256: str = Field(pattern=_SHA256)
    reference_id: str = Field(pattern=_REFERENCE_IDENTIFIER)
    reference_sha256: str = Field(pattern=_SHA256)
    parent_reference_id: str = Field(pattern=_REFERENCE_IDENTIFIER)
    parent_sha256: str = Field(pattern=_SHA256)
    page_delimiter: Literal["form_feed"] = "form_feed"
    form_feed_delimiter_count: int = Field(ge=0)
    candidates: tuple[TextbookAlignmentCandidateWorksheetV1, ...] = Field(min_length=1)
    external_model_egress_allowed: Literal[False] = False
    contract_freeze_allowed: Literal[False] = False
    prover_handoff_allowed: Literal[False] = False
    semantic_review_claimed: Literal[False] = False

    @model_validator(mode="after")
    def validate_candidate_identity(self) -> TextbookAlignmentPrivatePacketV1:
        candidate_ids = [candidate.candidate_id for candidate in self.candidates]
        locators = [candidate.source_span.locator for candidate in self.candidates]
        if len(candidate_ids) != len(set(candidate_ids)):
            raise ValueError("candidate identifiers must be unique")
        if len(locators) != len(set(locators)):
            raise ValueError("candidate source locators must be unique")
        return self


class TextbookAlignmentPublicSummaryV1(ContractModel):
    """The complete public surface; no textbook or candidate text is allowed."""

    status: Literal["textbook_alignment_discovery_nonfreeze"] = DISCOVERY_STATUS
    reference_id: str = Field(pattern=_REFERENCE_IDENTIFIER)
    parent_sha256: str = Field(pattern=_SHA256)
    page_locators: tuple[str, ...] = Field(min_length=1)
    candidate_count: int = Field(gt=0)
    candidate_hashes: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_counts(self) -> TextbookAlignmentPublicSummaryV1:
        if self.candidate_count != len(self.page_locators):
            raise ValueError("candidate count differs from the page-locator count")
        if self.candidate_count != len(self.candidate_hashes):
            raise ValueError("candidate count differs from the candidate-hash count")
        if len(self.page_locators) != len(set(self.page_locators)):
            raise ValueError("public page locators must be unique")
        if len(self.candidate_hashes) != len(set(self.candidate_hashes)):
            raise ValueError("public candidate hashes must be unique")
        if any(
            len(value) != 64 or any(character not in "0123456789abcdef" for character in value)
            for value in self.candidate_hashes
        ):
            raise ValueError("candidate hashes must be lowercase SHA-256 values")
        return self


def candidate_worksheet_sha256(candidate: TextbookAlignmentCandidateWorksheetV1) -> str:
    """Hash one private candidate worksheet with an explicit protocol domain."""

    payload = canonical_json_bytes(candidate.model_dump(mode="json"))
    return hashlib.sha256(_CANDIDATE_HASH_DOMAIN + payload).hexdigest()


def summarize_textbook_alignment(
    packet: TextbookAlignmentPrivatePacketV1,
) -> TextbookAlignmentPublicSummaryV1:
    """Project the private packet onto the intentionally small public surface."""

    return TextbookAlignmentPublicSummaryV1(
        reference_id=packet.reference_id,
        parent_sha256=packet.parent_sha256,
        page_locators=tuple(candidate.source_span.locator for candidate in packet.candidates),
        candidate_count=len(packet.candidates),
        candidate_hashes=tuple(
            candidate_worksheet_sha256(candidate) for candidate in packet.candidates
        ),
    )


def render_textbook_alignment_private_packet(
    packet: TextbookAlignmentPrivatePacketV1,
) -> bytes:
    return canonical_json_bytes(packet.model_dump(mode="json")) + b"\n"


def render_textbook_alignment_public_summary(
    summary: TextbookAlignmentPublicSummaryV1,
) -> bytes:
    return canonical_json_bytes(summary.model_dump(mode="json")) + b"\n"


def build_textbook_alignment_discovery(
    *,
    manifest_path: Path,
    expected_manifest_sha256: str,
    cache_root: Path,
    reference_id: str,
    page_numbers: tuple[int, ...] = (1,),
    max_excerpt_bytes: int = 8192,
    confinement_root: Path | None = None,
) -> tuple[TextbookAlignmentPrivatePacketV1, TextbookAlignmentPublicSummaryV1]:
    """Build a pending worksheet from verified local bytes without invoking a model."""

    _validate_selection(page_numbers, max_excerpt_bytes)
    try:
        manifest = ReferenceManifestV1.load(
            manifest_path,
            expected_sha256=expected_manifest_sha256,
        )
        cache = ReferenceCache(
            manifest,
            cache_root,
            confinement_root=confinement_root,
        )
        child = cache.verify(reference_id)
        child_entry = child.entry
        if child_entry.artifact_kind is not ReferenceArtifactKind.DERIVED_TEXT:
            raise TextbookAlignmentError("alignment reference must be a derived-text artifact")
        if child_entry.media_type != "text/plain":
            raise TextbookAlignmentError("alignment reference must use text/plain")
        if child_entry.model_egress_policy not in {
            ReferenceEgressPolicy.NO_MODEL,
            ReferenceEgressPolicy.LOCAL_ONLY,
        }:
            raise TextbookAlignmentError(
                "alignment discovery requires a no-model or local-only reference policy"
            )
        derivation = child_entry.derivation
        if derivation is None:
            raise TextbookAlignmentError("alignment reference lacks a parent derivation")
        parent_entry = manifest.require(derivation.parent_reference_id)
        if parent_entry.artifact_kind is not ReferenceArtifactKind.SOURCE_DOCUMENT:
            raise TextbookAlignmentError("alignment parent must be a source document")
        if parent_entry.sha256 != derivation.parent_sha256:
            raise TextbookAlignmentError("derived-text parent SHA differs from the manifest parent")
        parent = cache.verify(parent_entry.reference_id)
        if parent.entry.sha256 != derivation.parent_sha256:
            raise TextbookAlignmentError("verified parent SHA differs from the declared parent SHA")
        raw_text = child.cache_path.read_bytes()
        if len(raw_text) != child_entry.size_bytes:
            raise TextbookAlignmentError("derived text changed while the sample was read")
        if hashlib.sha256(raw_text).hexdigest() != child_entry.sha256:
            raise TextbookAlignmentError("derived text hash changed while the sample was read")
        cache.verify(reference_id)
        cache.verify(parent_entry.reference_id)
    except ReferenceCacheError as error:
        raise TextbookAlignmentError(str(error)) from error
    try:
        raw_text.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise TextbookAlignmentError("derived text is not strict UTF-8") from error

    page_spans = _form_feed_page_spans(raw_text)
    candidates = tuple(
        _pending_candidate(
            raw_text,
            page_spans,
            page_number=page_number,
            max_excerpt_bytes=max_excerpt_bytes,
        )
        for page_number in page_numbers
    )
    packet = TextbookAlignmentPrivatePacketV1(
        manifest_sha256=manifest.manifest_sha256,
        reference_id=child_entry.reference_id,
        reference_sha256=child_entry.sha256,
        parent_reference_id=parent_entry.reference_id,
        parent_sha256=parent_entry.sha256,
        form_feed_delimiter_count=raw_text.count(b"\x0c"),
        candidates=candidates,
    )
    return packet, summarize_textbook_alignment(packet)


def write_textbook_alignment_discovery(
    *,
    checkout_root: Path,
    packet_path: Path,
    summary_path: Path,
    packet: TextbookAlignmentPrivatePacketV1,
    summary: TextbookAlignmentPublicSummaryV1,
) -> None:
    """Atomically install private and redacted records below checkout ``.cache``."""

    expected_summary = summarize_textbook_alignment(packet)
    if summary != expected_summary:
        raise TextbookAlignmentError("public summary does not match the private packet")
    packet_bytes = render_textbook_alignment_private_packet(packet)
    summary_bytes = render_textbook_alignment_public_summary(summary)
    _assert_public_summary_redacted(packet, summary_bytes)

    repository = _resolve_repository(checkout_root)
    packet_destination = _cache_destination(repository, packet_path)
    summary_destination = _cache_destination(repository, summary_path)
    if packet_destination == summary_destination:
        raise TextbookAlignmentError("private packet and public summary paths must differ")
    repository_identity = _directory_identity(repository, repository, "checkout root")
    cache_identity = _directory_identity(
        repository / ".cache",
        repository,
        "checkout cache",
    )
    packet_parent_identity = _directory_identity(
        packet_destination.parent,
        repository,
        "private packet parent",
    )
    summary_parent_identity = _directory_identity(
        summary_destination.parent,
        repository,
        "public summary parent",
    )
    packet_exists = _preflight_output(
        packet_destination,
        packet_bytes,
        repository=repository,
        repository_identity=repository_identity,
        cache_identity=cache_identity,
        parent_identity=packet_parent_identity,
    )
    summary_exists = _preflight_output(
        summary_destination,
        summary_bytes,
        repository=repository,
        repository_identity=repository_identity,
        cache_identity=cache_identity,
        parent_identity=summary_parent_identity,
    )
    if not packet_exists:
        _atomic_install(
            packet_destination,
            packet_bytes,
            repository=repository,
            repository_identity=repository_identity,
            cache_identity=cache_identity,
            parent_identity=packet_parent_identity,
        )
    if not summary_exists:
        _atomic_install(
            summary_destination,
            summary_bytes,
            repository=repository,
            repository_identity=repository_identity,
            cache_identity=cache_identity,
            parent_identity=summary_parent_identity,
        )


def _validate_selection(page_numbers: tuple[int, ...], max_excerpt_bytes: int) -> None:
    if not page_numbers:
        raise TextbookAlignmentError("at least one opening page must be selected")
    if len(page_numbers) > _MAX_PAGE_COUNT:
        raise TextbookAlignmentError("opening sample exceeds the page-count limit")
    if any(page_number < 1 for page_number in page_numbers):
        raise TextbookAlignmentError("page numbers are one-based")
    if tuple(sorted(page_numbers)) != page_numbers or len(set(page_numbers)) != len(page_numbers):
        raise TextbookAlignmentError("page numbers must be strictly increasing and unique")
    if not 1 <= max_excerpt_bytes <= _MAX_EXCERPT_BYTES:
        raise TextbookAlignmentError("excerpt byte limit is outside the bounded range")


def _form_feed_page_spans(raw_text: bytes) -> tuple[tuple[int, int], ...]:
    spans: list[tuple[int, int]] = []
    start = 0
    for index, value in enumerate(raw_text):
        if value == 0x0C:
            spans.append((start, index))
            start = index + 1
    spans.append((start, len(raw_text)))
    return tuple(spans)


def _pending_candidate(
    raw_text: bytes,
    page_spans: tuple[tuple[int, int], ...],
    *,
    page_number: int,
    max_excerpt_bytes: int,
) -> TextbookAlignmentCandidateWorksheetV1:
    if page_number > len(page_spans):
        raise TextbookAlignmentError(
            f"requested form-feed page {page_number} is outside the derived text"
        )
    page_start, page_end = page_spans[page_number - 1]
    while page_start < page_end and raw_text[page_start] in _ASCII_WHITESPACE:
        page_start += 1
    sample_end = min(page_end, page_start + max_excerpt_bytes)
    while sample_end > page_start:
        try:
            excerpt = raw_text[page_start:sample_end].decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            sample_end -= 1
            continue
        break
    else:
        raise TextbookAlignmentError(f"form-feed page {page_number} has no nonempty UTF-8 sample")
    if not excerpt.strip():
        raise TextbookAlignmentError(f"form-feed page {page_number} has no nonempty UTF-8 sample")
    excerpt_bytes = raw_text[page_start:sample_end]
    span_sha256 = hashlib.sha256(excerpt_bytes).hexdigest()
    locator = f"form-feed-page:{page_number:04d}#utf8-bytes:{page_start}-{sample_end}"
    candidate_id = f"opening-page-{page_number:04d}-{span_sha256[:16]}"
    return TextbookAlignmentCandidateWorksheetV1(
        candidate_id=candidate_id,
        source_span=TextbookAlignmentSourceSpanV1(
            page_number=page_number,
            locator=locator,
            global_byte_start=page_start,
            global_byte_end=sample_end,
            span_sha256=span_sha256,
            excerpt=excerpt,
        ),
        quantifier_mutations=(
            TextbookAlignmentMutationWorksheetV1(
                mutation_kind="quantifier",
                review_prompt=(
                    "Record every binder and test a quantifier-order or quantifier-kind change."
                ),
            ),
        ),
        boundary_mutations=(
            TextbookAlignmentMutationWorksheetV1(
                mutation_kind="boundary",
                review_prompt=(
                    "Record strictness and side conditions, then test one "
                    "boundary-condition change."
                ),
            ),
        ),
    )


def _sensitive_text_values(packet: TextbookAlignmentPrivatePacketV1) -> tuple[str, ...]:
    values: list[str] = []
    for candidate in packet.candidates:
        values.append(candidate.source_span.excerpt)
        values.extend(candidate.ambiguities)
        values.extend(candidate.positive_examples)
        values.extend(candidate.negative_examples)
        if candidate.normalized_candidate is not None:
            values.append(candidate.normalized_candidate)
        if candidate.lean_like_draft is not None:
            values.append(candidate.lean_like_draft)
        for mutation in (*candidate.quantifier_mutations, *candidate.boundary_mutations):
            values.append(mutation.review_prompt)
            if mutation.baseline_text is not None:
                values.append(mutation.baseline_text)
            if mutation.mutated_text is not None:
                values.append(mutation.mutated_text)
    return tuple(values)


def _assert_public_summary_redacted(
    packet: TextbookAlignmentPrivatePacketV1,
    summary_bytes: bytes,
) -> None:
    try:
        payload = json.loads(summary_bytes)
        TextbookAlignmentPublicSummaryV1.model_validate(payload)
    except (json.JSONDecodeError, ValueError) as error:
        raise TextbookAlignmentError("public summary is not the strict redacted schema") from error
    if set(payload) != {
        "status",
        "reference_id",
        "parent_sha256",
        "page_locators",
        "candidate_count",
        "candidate_hashes",
    }:
        raise TextbookAlignmentError("public summary contains a non-redacted field")
    for value in _sensitive_text_values(packet):
        if canonical_json_bytes(value) in summary_bytes:
            raise TextbookAlignmentError("private worksheet text leaked into the public summary")


def _absolute_lexical(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _resolve_directory(path: Path, label: str) -> Path:
    try:
        lexical = _absolute_lexical(path)
        resolved = lexical.resolve(strict=True)
        metadata = lexical.lstat()
    except OSError as error:
        raise TextbookAlignmentError(f"{label} is not an existing directory") from error
    if _is_link_or_reparse(lexical) or not stat.S_ISDIR(metadata.st_mode):
        raise TextbookAlignmentError(f"{label} must be a real directory")
    return resolved


def _resolve_repository(path: Path) -> Path:
    repository = _resolve_directory(path, "checkout root")
    marker = repository / ".git"
    try:
        marker_metadata = marker.lstat()
    except OSError as error:
        raise TextbookAlignmentError("checkout root is not a Git repository root") from error
    if _is_link_or_reparse(marker) or not (
        stat.S_ISDIR(marker_metadata.st_mode) or stat.S_ISREG(marker_metadata.st_mode)
    ):
        raise TextbookAlignmentError("checkout Git marker must be a real file or directory")

    ignore_path = repository / ".gitignore"
    try:
        ignore_metadata = ignore_path.lstat()
        ignore_text = ignore_path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError) as error:
        raise TextbookAlignmentError("checkout root lacks a readable UTF-8 .gitignore") from error
    if _is_link_or_reparse(ignore_path) or not stat.S_ISREG(ignore_metadata.st_mode):
        raise TextbookAlignmentError("checkout .gitignore must be a real regular file")
    active_patterns = tuple(
        line.strip()
        for line in ignore_text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )
    if "/.cache/" not in active_patterns or any(
        pattern.startswith(("!/.cache", "!.cache")) for pattern in active_patterns
    ):
        raise TextbookAlignmentError("checkout .gitignore must explicitly exclude /.cache/")
    return repository


def _cache_destination(repository: Path, path: Path) -> Path:
    lexical = _absolute_lexical(path if path.is_absolute() else repository / path)
    cache_root = repository / ".cache"
    try:
        relative = lexical.relative_to(cache_root)
    except ValueError as error:
        raise TextbookAlignmentError("alignment output must stay below checkout .cache") from error
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise TextbookAlignmentError("alignment output path is unsafe")
    return lexical


def _identity(metadata: os.stat_result) -> _DirectoryIdentity:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(stat.S_IFMT(metadata.st_mode)),
        int(getattr(metadata, "st_file_attributes", 0)),
    )


def _is_link_or_reparse(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    except OSError as error:
        raise TextbookAlignmentError(f"cannot inspect alignment output: {path.name}") from error
    is_junction = getattr(os.path, "isjunction", lambda _: False)
    return (
        path.is_symlink()
        or is_junction(path)
        or stat.S_ISLNK(metadata.st_mode)
        or bool(int(getattr(metadata, "st_file_attributes", 0)) & _REPARSE_POINT)
    )


def _directory_identity(
    path: Path,
    repository: Path,
    label: str,
) -> _DirectoryIdentity:
    try:
        relative = path.relative_to(repository)
    except ValueError as error:
        raise TextbookAlignmentError("alignment output escapes the checkout") from error
    current = repository
    for index, part in enumerate(("", *relative.parts)):
        if index:
            current /= part
        try:
            metadata = current.lstat()
            resolved = current.resolve(strict=True)
            resolved.relative_to(repository)
        except (OSError, ValueError) as error:
            raise TextbookAlignmentError(f"{label} is not a confined existing directory") from error
        if _is_link_or_reparse(current) or not stat.S_ISDIR(metadata.st_mode):
            raise TextbookAlignmentError(f"{label} must contain only real directories")
    return _identity(metadata)


def _assert_output_identities(
    path: Path,
    *,
    repository: Path,
    repository_identity: _DirectoryIdentity,
    cache_identity: _DirectoryIdentity,
    parent_identity: _DirectoryIdentity,
) -> None:
    observed = (
        _directory_identity(repository, repository, "checkout root"),
        _directory_identity(repository / ".cache", repository, "checkout cache"),
        _directory_identity(path.parent, repository, "alignment output parent"),
    )
    expected = (repository_identity, cache_identity, parent_identity)
    if observed != expected:
        raise TextbookAlignmentError("alignment output directory identity changed during write")


def _existing_output(path: Path) -> bytes | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise TextbookAlignmentError(f"cannot inspect alignment output: {path.name}") from error
    if _is_link_or_reparse(path) or not stat.S_ISREG(metadata.st_mode):
        raise TextbookAlignmentError("alignment output destination is not a real regular file")
    try:
        content = path.read_bytes()
        after = path.lstat()
    except OSError as error:
        raise TextbookAlignmentError(f"cannot read alignment output: {path.name}") from error
    if _identity(metadata) != _identity(after):
        raise TextbookAlignmentError("alignment output changed while it was inspected")
    return content


def _preflight_output(
    path: Path,
    content: bytes,
    *,
    repository: Path,
    repository_identity: _DirectoryIdentity,
    cache_identity: _DirectoryIdentity,
    parent_identity: _DirectoryIdentity,
) -> bool:
    _assert_output_identities(
        path,
        repository=repository,
        repository_identity=repository_identity,
        cache_identity=cache_identity,
        parent_identity=parent_identity,
    )
    existing = _existing_output(path)
    if existing is None:
        return False
    if existing != content:
        raise TextbookAlignmentError(f"alignment output conflicts with existing file: {path.name}")
    return True


def _atomic_install(
    path: Path,
    content: bytes,
    *,
    repository: Path,
    repository_identity: _DirectoryIdentity,
    cache_identity: _DirectoryIdentity,
    parent_identity: _DirectoryIdentity,
) -> None:
    if _preflight_output(
        path,
        content,
        repository=repository,
        repository_identity=repository_identity,
        cache_identity=cache_identity,
        parent_identity=parent_identity,
    ):
        return
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
        ) as handle:
            temporary_name = handle.name
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        _assert_output_identities(
            path,
            repository=repository,
            repository_identity=repository_identity,
            cache_identity=cache_identity,
            parent_identity=parent_identity,
        )
        existing = _existing_output(path)
        if existing is not None:
            if existing != content:
                raise TextbookAlignmentError(
                    f"alignment output conflicts with existing file: {path.name}"
                )
            return
        try:
            os.link(temporary_name, path)
        except FileExistsError:
            existing = _existing_output(path)
            if existing != content:
                raise TextbookAlignmentError(
                    f"alignment output conflicts with existing file: {path.name}"
                ) from None
        except OSError as error:
            raise TextbookAlignmentError(f"cannot install alignment output: {path.name}") from error
        _assert_output_identities(
            path,
            repository=repository,
            repository_identity=repository_identity,
            cache_identity=cache_identity,
            parent_identity=parent_identity,
        )
        if _existing_output(path) != content:
            raise TextbookAlignmentError(f"alignment output verification failed: {path.name}")
    except OSError as error:
        raise TextbookAlignmentError(f"cannot install alignment output: {path.name}") from error
    finally:
        if temporary_name is not None:
            try:
                _assert_output_identities(
                    path,
                    repository=repository,
                    repository_identity=repository_identity,
                    cache_identity=cache_identity,
                    parent_identity=parent_identity,
                )
            except TextbookAlignmentError:
                pass
            else:
                with suppress(FileNotFoundError):
                    Path(temporary_name).unlink()
