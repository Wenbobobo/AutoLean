"""Rights-aware, content-addressed cache for Builder reference material.

The tracked manifest is the acquisition allowlist. Reference acquisition is an operator-only
operation; automated Builder work may only verify already-cached artifacts. Cached bytes are
local artifacts and must be reverified before they can seed a statement contract.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import stat
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from http.client import HTTPMessage
from pathlib import Path
from typing import BinaryIO, Protocol, cast

from autolean_contracts import canonical_json_bytes

_REFERENCE_ID = re.compile(r"^[a-z0-9][a-z0-9.-]{2,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FILE_EXTENSION = re.compile(r"^\.[a-z0-9]{1,10}$")
_AMBIGUOUS_NUMERIC_HOST = re.compile(
    r"^(?:(?:0[xX][0-9a-fA-F]+|[0-9]+)\.)*(?:0[xX][0-9a-fA-F]+|[0-9]+)$"
)
_MAX_REFERENCE_BYTES = 2 * 1024 * 1024 * 1024
_CHUNK_BYTES = 1024 * 1024
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_TARGET_LOCKS_GUARD = threading.Lock()
_TARGET_LOCKS: dict[str, threading.Lock] = {}


class ReferenceCacheError(ValueError):
    """The manifest, acquisition, or cached artifact violated the reference policy."""


class ReferenceAccessPolicy(StrEnum):
    PUBLIC_OPEN_ACCESS = "public_open_access"


class ReferenceAcquisitionPolicy(StrEnum):
    OPERATOR_ONLY = "operator_only"
    LOCAL_DERIVATION_ONLY = "local_derivation_only"


class ReferenceEgressPolicy(StrEnum):
    NO_MODEL = "no_model"
    LOCAL_ONLY = "local_only"
    APPROVED_EXTERNAL = "approved_external"


class ReferenceArtifactKind(StrEnum):
    SOURCE_DOCUMENT = "source_document"
    DERIVED_TEXT = "derived_text"


class ReferenceDerivationKind(StrEnum):
    REPOSITORY_TEXT_EXTRACTION = "repository_text_extraction"
    LOCAL_PDF_TEXT_EXTRACTION = "local_pdf_text_extraction"


class ParentLocatorAuthority(StrEnum):
    HUMAN_DECLARED = "human_declared"
    MANIFEST_BOUND = "manifest_bound"


_LOCAL_PDF_TEXT_METHOD = "pypdf-pdfreader-extract-text-plain-form-feed-v1"
_LOCAL_PDF_TEXT_TOOL_NAME = "pypdf"


@dataclass(frozen=True, slots=True)
class ReferenceLicenseV1:
    expression: str
    url: str
    evidence_url: str


@dataclass(frozen=True, slots=True)
class ReferenceDerivationV1:
    kind: ReferenceDerivationKind
    parent_reference_id: str
    parent_sha256: str
    producer: str
    method: str
    tool_name: str | None
    tool_version: str | None
    provenance_url: str
    parent_locator_authority: ParentLocatorAuthority


@dataclass(frozen=True, slots=True)
class ReferenceEntryV1:
    reference_id: str
    title: str
    authors: tuple[str, ...]
    version: str
    citation: str
    source_record_url: str
    download_url: str | None
    allowed_redirect_urls: tuple[str, ...]
    media_type: str
    file_extension: str
    size_bytes: int
    max_bytes: int
    sha256: str
    retrieved_at: datetime
    license: ReferenceLicenseV1
    access_policy: ReferenceAccessPolicy
    acquisition_policy: ReferenceAcquisitionPolicy
    model_egress_policy: ReferenceEgressPolicy
    artifact_kind: ReferenceArtifactKind
    derivation: ReferenceDerivationV1 | None
    attribution: str

    @property
    def allowed_download_urls(self) -> frozenset[str]:
        return frozenset(
            (() if self.download_url is None else (self.download_url,)) + self.allowed_redirect_urls
        )

    def cache_relative_path(self) -> Path:
        return Path(self.reference_id) / f"{self.sha256}{self.file_extension}"


@dataclass(frozen=True, slots=True)
class ReferenceManifestV1:
    entries: tuple[ReferenceEntryV1, ...]
    manifest_sha256: str

    @classmethod
    def load(
        cls,
        path: Path,
        *,
        expected_sha256: str | None = None,
    ) -> ReferenceManifestV1:
        try:
            raw = path.read_bytes()
        except OSError as error:
            raise ReferenceCacheError(f"cannot read reference manifest: {path}") from error
        manifest_sha256 = hashlib.sha256(raw).hexdigest()
        if expected_sha256 is not None:
            if not _SHA256.fullmatch(expected_sha256):
                raise ReferenceCacheError("expected manifest SHA-256 is malformed")
            if manifest_sha256 != expected_sha256:
                raise ReferenceCacheError("tracked reference manifest differs from the bound SHA")
        try:
            payload = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ReferenceCacheError("reference manifest is not valid UTF-8 JSON") from error
        root = _expect_mapping(payload, "manifest")
        _expect_exact_keys(root, {"schema_version", "entries"}, "manifest")
        if root["schema_version"] != "autolean.reference-manifest.v1":
            raise ReferenceCacheError("unsupported reference manifest schema")
        raw_entries = root["entries"]
        if not isinstance(raw_entries, list) or not raw_entries:
            raise ReferenceCacheError("reference manifest entries must be a nonempty array")
        entries = tuple(_parse_entry(item, index) for index, item in enumerate(raw_entries))
        identifiers = [entry.reference_id for entry in entries]
        if len(identifiers) != len(set(identifiers)):
            raise ReferenceCacheError("reference identifiers must be unique")
        _validate_derivations(entries)
        return cls(entries=entries, manifest_sha256=manifest_sha256)

    def require(self, reference_id: str) -> ReferenceEntryV1:
        for entry in self.entries:
            if entry.reference_id == reference_id:
                return entry
        raise ReferenceCacheError(f"reference is not manifest-allowlisted: {reference_id}")


@dataclass(frozen=True, slots=True)
class VerifiedReference:
    entry: ReferenceEntryV1
    cache_path: Path
    manifest_sha256: str

    @property
    def cache_ref(self) -> str:
        return f"reference-cache:sha256:{self.entry.sha256}"

    def receipt_payload(self, *, verified_at: datetime) -> dict[str, object]:
        return _receipt_payload(self, verified_at=verified_at, network_used=False)

    def render_receipt(self, *, verified_at: datetime) -> bytes:
        return canonical_json_bytes(self.receipt_payload(verified_at=verified_at)) + b"\n"


@dataclass(frozen=True, slots=True)
class DownloadObservation:
    final_url: str
    media_type: str
    network_used: bool


@dataclass(frozen=True, slots=True)
class ReferenceFetchResult:
    verified: VerifiedReference
    observation: DownloadObservation | None

    @property
    def network_used(self) -> bool:
        return self.observation.network_used if self.observation is not None else False

    def receipt_payload(self, *, verified_at: datetime) -> dict[str, object]:
        return _receipt_payload(
            self.verified,
            verified_at=verified_at,
            network_used=self.network_used,
        )

    def render_receipt(self, *, verified_at: datetime) -> bytes:
        return canonical_json_bytes(self.receipt_payload(verified_at=verified_at)) + b"\n"


class ReferenceDownloader(Protocol):
    def __call__(self, entry: ReferenceEntryV1, destination: BinaryIO) -> DownloadObservation:
        """Write exactly one allowlisted entry to ``destination``."""


@dataclass(frozen=True, slots=True)
class _FileInspection:
    size: int
    sha256: str
    span_bytes: bytes | None


class ReferenceCache:
    """Verify references and perform explicit operator-only acquisition."""

    def __init__(
        self,
        manifest: ReferenceManifestV1,
        cache_root: Path,
        *,
        confinement_root: Path | None = None,
        downloader: ReferenceDownloader | None = None,
    ) -> None:
        self.manifest = manifest
        self.cache_root = _absolute_lexical(cache_root)
        self.confinement_root = _absolute_lexical(confinement_root or cache_root.parent)
        if not _is_relative_to(self.cache_root, self.confinement_root):
            raise ReferenceCacheError("reference cache root escapes its confinement root")
        self._downloader = downloader or _download_reference

    def path_for(self, reference_id: str) -> Path:
        entry = self.manifest.require(reference_id)
        target = self.cache_root / entry.cache_relative_path()
        if not _is_relative_to(target, self.cache_root):
            raise ReferenceCacheError("reference cache target escapes the cache root")
        return target

    def verify(self, reference_id: str) -> VerifiedReference:
        entry = self.manifest.require(reference_id)
        path = self.path_for(reference_id)
        self._require_existing_directory_tree(path.parent)
        inspection = _inspect_regular_file(path)
        self._validate_inspection(entry, inspection, cached=True)
        return VerifiedReference(
            entry=entry,
            cache_path=path,
            manifest_sha256=self.manifest.manifest_sha256,
        )

    def verify_all(self) -> tuple[VerifiedReference, ...]:
        return tuple(self.verify(entry.reference_id) for entry in self.manifest.entries)

    def verify_utf8_excerpt(
        self,
        reference_id: str,
        *,
        start_offset: int,
        end_offset: int,
        permitted_excerpt: str,
    ) -> VerifiedReference:
        entry = self.manifest.require(reference_id)
        if (
            entry.artifact_kind is not ReferenceArtifactKind.DERIVED_TEXT
            or entry.media_type != "text/plain"
            or entry.derivation is None
        ):
            raise ReferenceCacheError(
                "statement excerpts require a manifest-typed derived text artifact"
            )
        if (
            isinstance(start_offset, bool)
            or isinstance(end_offset, bool)
            or start_offset < 0
            or end_offset <= start_offset
        ):
            raise ReferenceCacheError("text excerpt byte offsets must form a nonempty range")
        path = self.path_for(reference_id)
        self._require_existing_directory_tree(path.parent)
        inspection = _inspect_regular_file(path, span=(start_offset, end_offset))
        self._validate_inspection(entry, inspection, cached=True)
        try:
            expected_bytes = permitted_excerpt.encode("utf-8")
        except UnicodeEncodeError as error:
            raise ReferenceCacheError("permitted_excerpt is not valid UTF-8 text") from error
        if inspection.span_bytes != expected_bytes:
            raise ReferenceCacheError(
                "cached UTF-8 bytes at the declared offsets differ from permitted_excerpt"
            )
        return VerifiedReference(
            entry=entry,
            cache_path=path,
            manifest_sha256=self.manifest.manifest_sha256,
        )

    def verify_utf8_span_digest(
        self,
        reference_id: str,
        *,
        start_offset: int,
        end_offset: int,
        expected_sha256: str,
    ) -> VerifiedReference:
        """Verify a private UTF-8 span without returning its text to the caller.

        A pilot manifest can commit to a source span's raw-byte digest without tracking an
        excerpt. Callers receive only the cache identity, not selected textbook text.
        """

        if not _SHA256.fullmatch(expected_sha256):
            raise ReferenceCacheError("expected UTF-8 span SHA-256 is malformed")
        if (
            isinstance(start_offset, bool)
            or isinstance(end_offset, bool)
            or start_offset < 0
            or end_offset <= start_offset
        ):
            raise ReferenceCacheError("UTF-8 span offsets must describe a nonempty byte range")
        entry = self.manifest.require(reference_id)
        if (
            entry.artifact_kind is not ReferenceArtifactKind.DERIVED_TEXT
            or entry.media_type != "text/plain"
            or entry.derivation is None
        ):
            raise ReferenceCacheError("UTF-8 span verification requires manifest-derived text")
        path = self.path_for(reference_id)
        self._require_existing_directory_tree(path.parent)
        inspection = _inspect_regular_file(path, span=(start_offset, end_offset))
        self._validate_inspection(entry, inspection, cached=True)
        span_bytes = inspection.span_bytes
        if span_bytes is None:
            raise ReferenceCacheError("UTF-8 span bytes were not captured")
        try:
            span_bytes.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ReferenceCacheError("UTF-8 span offsets split a character") from error
        if hashlib.sha256(span_bytes).hexdigest() != expected_sha256:
            raise ReferenceCacheError("cached UTF-8 span differs from its declared digest")
        return VerifiedReference(
            entry=entry,
            cache_path=path,
            manifest_sha256=self.manifest.manifest_sha256,
        )

    def operator_fetch(
        self,
        reference_id: str,
        *,
        refresh: bool = False,
    ) -> ReferenceFetchResult:
        entry = self.manifest.require(reference_id)
        if entry.acquisition_policy is not ReferenceAcquisitionPolicy.OPERATOR_ONLY:
            raise ReferenceCacheError("unsupported reference acquisition policy")
        if entry.download_url is None:
            raise ReferenceCacheError("operator-fetched reference has no download URL")
        target = self.path_for(reference_id)
        with _target_lock(target):
            return self._operator_fetch_locked(entry, target, refresh=refresh)

    def _operator_fetch_locked(
        self,
        entry: ReferenceEntryV1,
        target: Path,
        *,
        refresh: bool,
    ) -> ReferenceFetchResult:
        self._ensure_directory_tree(target.parent)
        target_stat = _lstat_optional(target)
        if target_stat is not None:
            _require_regular_stat(target, target_stat)
            if not refresh:
                return ReferenceFetchResult(
                    verified=self.verify(entry.reference_id),
                    observation=None,
                )

        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w+b",
                prefix=".operator-download-",
                suffix=".part",
                dir=target.parent,
                delete=False,
            ) as destination:
                temporary_path = Path(destination.name)
                observation = self._downloader(entry, cast(BinaryIO, destination))
                destination.flush()
                os.fsync(destination.fileno())
            self._validate_download_observation(entry, observation)
            inspection = _inspect_regular_file(temporary_path)
            self._validate_inspection(entry, inspection, cached=False)
            self._install_verified_temporary(entry, temporary_path, target)
            _fsync_directory_if_supported(target.parent)
            return ReferenceFetchResult(
                verified=self.verify(entry.reference_id),
                observation=observation,
            )
        finally:
            if temporary_path is not None:
                _unlink_confined_temporary(temporary_path, target.parent)

    def operator_import_local(
        self,
        reference_id: str,
        source_path: Path,
        *,
        refresh: bool = False,
    ) -> ReferenceFetchResult:
        """Import operator-supplied local bytes only after manifest verification.

        This is intentionally distinct from network acquisition.  It supports a verified
        bootstrap PDF and the deterministic text derived from it, while preserving the same
        content-addressed destination and atomic replacement guarantees as ``operator_fetch``.
        """

        entry = self.manifest.require(reference_id)
        if entry.acquisition_policy not in {
            ReferenceAcquisitionPolicy.OPERATOR_ONLY,
            ReferenceAcquisitionPolicy.LOCAL_DERIVATION_ONLY,
        }:
            raise ReferenceCacheError("unsupported local reference import policy")
        source = _absolute_lexical(source_path)
        source_stat = _lstat_optional(source)
        if source_stat is None:
            raise ReferenceCacheError("local reference import source is absent")
        _require_regular_stat(source, source_stat)
        target = self.path_for(reference_id)
        with _target_lock(target):
            return self._operator_import_local_locked(
                entry,
                target,
                source,
                refresh=refresh,
            )

    def _operator_import_local_locked(
        self,
        entry: ReferenceEntryV1,
        target: Path,
        source: Path,
        *,
        refresh: bool,
    ) -> ReferenceFetchResult:
        self._ensure_directory_tree(target.parent)
        target_stat = _lstat_optional(target)
        if target_stat is not None:
            _require_regular_stat(target, target_stat)
            if not refresh:
                return ReferenceFetchResult(
                    verified=self.verify(entry.reference_id),
                    observation=None,
                )

        temporary_path: Path | None = None
        try:
            with (
                source.open("rb") as input_file,
                tempfile.NamedTemporaryFile(
                    mode="w+b",
                    prefix=".operator-import-",
                    suffix=".part",
                    dir=target.parent,
                    delete=False,
                ) as destination,
            ):
                temporary_path = Path(destination.name)
                while chunk := input_file.read(_CHUNK_BYTES):
                    destination.write(chunk)
                destination.flush()
                os.fsync(destination.fileno())
            inspection = _inspect_regular_file(temporary_path)
            self._validate_inspection(entry, inspection, cached=False)
            self._install_verified_temporary(entry, temporary_path, target)
            _fsync_directory_if_supported(target.parent)
            return ReferenceFetchResult(
                verified=self.verify(entry.reference_id),
                observation=None,
            )
        finally:
            if temporary_path is not None:
                _unlink_confined_temporary(temporary_path, target.parent)

    def _ensure_directory_tree(self, path: Path) -> None:
        relative = _relative_parts(path, self.confinement_root)
        _require_directory(self.confinement_root)
        current = self.confinement_root
        for part in relative:
            current = current / part
            current_stat = _lstat_optional(current)
            if current_stat is None:
                with suppress(FileExistsError):
                    os.mkdir(current)
                current_stat = _lstat_optional(current)
            if current_stat is None:
                raise ReferenceCacheError(
                    f"cannot create reference cache directory: {current.name}"
                )
            _require_directory_stat(current, current_stat)

    def _require_existing_directory_tree(self, path: Path) -> None:
        relative = _relative_parts(path, self.confinement_root)
        _require_directory(self.confinement_root)
        current = self.confinement_root
        for part in relative:
            current = current / part
            _require_directory(current)

    def _install_verified_temporary(
        self,
        entry: ReferenceEntryV1,
        temporary_path: Path,
        target: Path,
    ) -> None:
        """Install one verified CAS object without replacing an existing target."""

        self._require_existing_directory_tree(target.parent)
        try:
            os.link(temporary_path, target)
        except FileExistsError:
            try:
                inspection = _inspect_regular_file(target)
                self._validate_inspection(entry, inspection, cached=True)
            except ReferenceCacheError as error:
                raise ReferenceCacheError(
                    f"content-addressed reference target conflicts with verified acquisition: "
                    f"{entry.reference_id}"
                ) from error
        except OSError as error:
            raise ReferenceCacheError(
                f"cannot install content-addressed reference: {entry.reference_id}"
            ) from error

    @staticmethod
    def _validate_download_observation(
        entry: ReferenceEntryV1,
        observation: DownloadObservation,
    ) -> None:
        if (
            not entry.allowed_download_urls
            or observation.final_url not in entry.allowed_download_urls
        ):
            raise ReferenceCacheError("download ended at a URL absent from the manifest")
        if observation.media_type != entry.media_type:
            raise ReferenceCacheError(
                "download media type differs from the manifest: "
                f"{observation.media_type} != {entry.media_type}"
            )

    @staticmethod
    def _validate_inspection(
        entry: ReferenceEntryV1,
        inspection: _FileInspection,
        *,
        cached: bool,
    ) -> None:
        label = "cached reference" if cached else "downloaded reference"
        if inspection.size != entry.size_bytes:
            raise ReferenceCacheError(
                f"{label} size mismatch for {entry.reference_id}: "
                f"{inspection.size} != {entry.size_bytes}"
            )
        if inspection.sha256 != entry.sha256:
            raise ReferenceCacheError(f"{label} hash mismatch for {entry.reference_id}")


class _AllowlistedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_urls: frozenset[str]) -> None:
        super().__init__()
        self._allowed_urls = allowed_urls

    def redirect_request(  # type: ignore[override]
        self,
        req: urllib.request.Request,
        fp: BinaryIO,
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> urllib.request.Request:
        resolved = urllib.parse.urljoin(req.full_url, newurl)
        if resolved not in self._allowed_urls:
            raise ReferenceCacheError("download redirect target is absent from the manifest")
        redirected = super().redirect_request(req, fp, code, msg, headers, resolved)
        if redirected is None:
            raise ReferenceCacheError("reference redirect was rejected")
        return redirected


def _download_reference(entry: ReferenceEntryV1, destination: BinaryIO) -> DownloadObservation:
    if entry.download_url is None:
        raise ReferenceCacheError("reference has no network download URL")
    opener = urllib.request.build_opener(_AllowlistedRedirectHandler(entry.allowed_download_urls))
    request = urllib.request.Request(
        entry.download_url,
        headers={
            "Accept": entry.media_type,
            "Accept-Encoding": "identity",
            "User-Agent": "AutoLean-ReferenceCache/1",
        },
        method="GET",
    )
    try:
        with opener.open(request, timeout=60) as response:
            final_url = response.geturl()
            if final_url not in entry.allowed_download_urls:
                raise ReferenceCacheError("download ended at a URL absent from the manifest")
            media_type = response.headers.get_content_type().lower()
            content_length = response.headers.get("Content-Length")
            if content_length is not None:
                try:
                    declared_size = int(content_length)
                except ValueError as error:
                    raise ReferenceCacheError(
                        "download returned an invalid Content-Length"
                    ) from error
                if declared_size > entry.max_bytes:
                    raise ReferenceCacheError("download exceeds the manifest byte limit")
            written = 0
            while chunk := response.read(_CHUNK_BYTES):
                written += len(chunk)
                if written > entry.max_bytes:
                    raise ReferenceCacheError("download exceeds the manifest byte limit")
                destination.write(chunk)
    except ReferenceCacheError:
        raise
    except (OSError, urllib.error.URLError) as error:
        raise ReferenceCacheError(f"reference download failed: {entry.reference_id}") from error
    return DownloadObservation(
        final_url=final_url,
        media_type=media_type,
        network_used=True,
    )


def _parse_entry(value: object, index: int) -> ReferenceEntryV1:
    item = _expect_mapping(value, f"entries[{index}]")
    expected = {
        "reference_id",
        "title",
        "authors",
        "version",
        "citation",
        "source_record_url",
        "download_url",
        "allowed_redirect_urls",
        "media_type",
        "file_extension",
        "size_bytes",
        "max_bytes",
        "sha256",
        "retrieved_at",
        "license",
        "access_policy",
        "acquisition_policy",
        "model_egress_policy",
        "artifact_kind",
        "derivation",
        "attribution",
    }
    _expect_exact_keys(item, expected, f"entries[{index}]")
    reference_id = _require_string(item, "reference_id")
    if not _REFERENCE_ID.fullmatch(reference_id):
        raise ReferenceCacheError(f"invalid reference identifier: {reference_id}")
    authors_value = item["authors"]
    if not isinstance(authors_value, list) or not authors_value:
        raise ReferenceCacheError(f"{reference_id}: authors must be a nonempty array")
    authors = tuple(_require_nonempty_text(author, "author") for author in authors_value)
    source_record_url = _validate_https_url(
        _require_string(item, "source_record_url"), "source_record_url"
    )
    raw_download_url = item["download_url"]
    if raw_download_url is None:
        download_url = None
    else:
        download_url = _validate_https_url(_require_string(item, "download_url"), "download_url")
    redirect_value = item["allowed_redirect_urls"]
    if not isinstance(redirect_value, list):
        raise ReferenceCacheError(f"{reference_id}: allowed_redirect_urls must be an array")
    redirects = tuple(
        _validate_https_url(_require_nonempty_text(url, "redirect URL"), "redirect URL")
        for url in redirect_value
    )
    if len(redirects) != len(set(redirects)):
        raise ReferenceCacheError(f"{reference_id}: redirect URLs must be unique")
    media_type = _require_string(item, "media_type").lower()
    if "/" not in media_type or any(character.isspace() for character in media_type):
        raise ReferenceCacheError(f"{reference_id}: invalid media type")
    extension = _require_string(item, "file_extension").lower()
    if not _FILE_EXTENSION.fullmatch(extension):
        raise ReferenceCacheError(f"{reference_id}: invalid file extension")
    size_bytes = _require_positive_int(item, "size_bytes")
    max_bytes = _require_positive_int(item, "max_bytes")
    if size_bytes > max_bytes or max_bytes > _MAX_REFERENCE_BYTES:
        raise ReferenceCacheError(f"{reference_id}: invalid reference byte limits")
    sha256 = _require_string(item, "sha256").lower()
    if not _SHA256.fullmatch(sha256):
        raise ReferenceCacheError(f"{reference_id}: invalid SHA-256")
    retrieved_at = _parse_utc(_require_string(item, "retrieved_at"))
    license_payload = _expect_mapping(item["license"], f"{reference_id}.license")
    _expect_exact_keys(
        license_payload,
        {"expression", "url", "evidence_url"},
        f"{reference_id}.license",
    )
    license_record = ReferenceLicenseV1(
        expression=_require_string(license_payload, "expression"),
        url=_validate_https_url(_require_string(license_payload, "url"), "license URL"),
        evidence_url=_validate_https_url(
            _require_string(license_payload, "evidence_url"), "license evidence URL"
        ),
    )
    try:
        access_policy = ReferenceAccessPolicy(_require_string(item, "access_policy"))
        acquisition_policy = ReferenceAcquisitionPolicy(_require_string(item, "acquisition_policy"))
        egress_policy = ReferenceEgressPolicy(_require_string(item, "model_egress_policy"))
        artifact_kind = ReferenceArtifactKind(_require_string(item, "artifact_kind"))
    except ValueError as error:
        raise ReferenceCacheError(f"{reference_id}: unsupported reference policy") from error
    derivation = _parse_derivation(item["derivation"], reference_id)
    if artifact_kind is ReferenceArtifactKind.SOURCE_DOCUMENT and derivation is not None:
        raise ReferenceCacheError(f"{reference_id}: source documents cannot declare a derivation")
    if artifact_kind is ReferenceArtifactKind.DERIVED_TEXT and derivation is None:
        raise ReferenceCacheError(f"{reference_id}: derived text requires derivation provenance")
    if acquisition_policy is ReferenceAcquisitionPolicy.OPERATOR_ONLY and download_url is None:
        raise ReferenceCacheError(
            f"{reference_id}: operator-fetched reference requires download URL"
        )
    if (
        acquisition_policy is ReferenceAcquisitionPolicy.LOCAL_DERIVATION_ONLY
        and download_url is not None
    ):
        raise ReferenceCacheError(
            f"{reference_id}: locally-derived reference cannot declare a download URL"
        )
    if download_url is None and redirects:
        raise ReferenceCacheError(
            f"{reference_id}: reference without a download URL cannot allow redirects"
        )
    return ReferenceEntryV1(
        reference_id=reference_id,
        title=_require_string(item, "title"),
        authors=authors,
        version=_require_string(item, "version"),
        citation=_require_string(item, "citation"),
        source_record_url=source_record_url,
        download_url=download_url,
        allowed_redirect_urls=redirects,
        media_type=media_type,
        file_extension=extension,
        size_bytes=size_bytes,
        max_bytes=max_bytes,
        sha256=sha256,
        retrieved_at=retrieved_at,
        license=license_record,
        access_policy=access_policy,
        acquisition_policy=acquisition_policy,
        model_egress_policy=egress_policy,
        artifact_kind=artifact_kind,
        derivation=derivation,
        attribution=_require_string(item, "attribution"),
    )


def _parse_derivation(value: object, reference_id: str) -> ReferenceDerivationV1 | None:
    if value is None:
        return None
    item = _expect_mapping(value, f"{reference_id}.derivation")
    expected = {
        "kind",
        "parent_reference_id",
        "parent_sha256",
        "producer",
        "method",
        "tool_name",
        "tool_version",
        "provenance_url",
        "parent_locator_authority",
    }
    _expect_exact_keys(item, expected, f"{reference_id}.derivation")
    parent_reference_id = _require_string(item, "parent_reference_id")
    if not _REFERENCE_ID.fullmatch(parent_reference_id):
        raise ReferenceCacheError(f"{reference_id}: invalid parent reference identifier")
    parent_sha256 = _require_string(item, "parent_sha256").lower()
    if not _SHA256.fullmatch(parent_sha256):
        raise ReferenceCacheError(f"{reference_id}: invalid parent SHA-256")
    try:
        kind = ReferenceDerivationKind(_require_string(item, "kind"))
        locator_authority = ParentLocatorAuthority(
            _require_string(item, "parent_locator_authority")
        )
    except ValueError as error:
        raise ReferenceCacheError(f"{reference_id}: unsupported derivation policy") from error
    return ReferenceDerivationV1(
        kind=kind,
        parent_reference_id=parent_reference_id,
        parent_sha256=parent_sha256,
        producer=_require_string(item, "producer"),
        method=_require_string(item, "method"),
        tool_name=_optional_trimmed_text(item["tool_name"], "tool_name"),
        tool_version=_optional_trimmed_text(item["tool_version"], "tool_version"),
        provenance_url=_validate_https_url(
            _require_string(item, "provenance_url"), "derivation provenance URL"
        ),
        parent_locator_authority=locator_authority,
    )


def _validate_derivations(entries: tuple[ReferenceEntryV1, ...]) -> None:
    by_id = {entry.reference_id: entry for entry in entries}
    egress_rank = {
        ReferenceEgressPolicy.NO_MODEL: 0,
        ReferenceEgressPolicy.LOCAL_ONLY: 1,
        ReferenceEgressPolicy.APPROVED_EXTERNAL: 2,
    }
    for entry in entries:
        if entry.artifact_kind is not ReferenceArtifactKind.DERIVED_TEXT:
            continue
        derivation = entry.derivation
        if derivation is None:
            raise ReferenceCacheError(f"{entry.reference_id}: missing derivation")
        parent = by_id.get(derivation.parent_reference_id)
        if parent is None:
            raise ReferenceCacheError(f"{entry.reference_id}: derivation parent is absent")
        if parent.artifact_kind is not ReferenceArtifactKind.SOURCE_DOCUMENT:
            raise ReferenceCacheError(f"{entry.reference_id}: derivation parent is not a source")
        if parent.media_type != "application/pdf":
            raise ReferenceCacheError(f"{entry.reference_id}: derivation parent must be a PDF")
        if derivation.parent_sha256 != parent.sha256:
            raise ReferenceCacheError(
                f"{entry.reference_id}: parent digest does not match manifest"
            )
        if entry.media_type != "text/plain" or entry.file_extension != ".txt":
            raise ReferenceCacheError(f"{entry.reference_id}: derived text must be text/plain .txt")
        if entry.source_record_url != parent.source_record_url:
            raise ReferenceCacheError(
                f"{entry.reference_id}: derived text must retain the parent source record"
            )
        if entry.license != parent.license or entry.attribution != parent.attribution:
            raise ReferenceCacheError(
                f"{entry.reference_id}: derived text must preserve parent rights metadata"
            )
        if entry.access_policy is not parent.access_policy:
            raise ReferenceCacheError(
                f"{entry.reference_id}: derived text access policy differs from parent"
            )
        if egress_rank[entry.model_egress_policy] > egress_rank[parent.model_egress_policy]:
            raise ReferenceCacheError(
                f"{entry.reference_id}: derived text egress exceeds its parent policy"
            )
        if derivation.kind is ReferenceDerivationKind.LOCAL_PDF_TEXT_EXTRACTION:
            if entry.acquisition_policy is not ReferenceAcquisitionPolicy.LOCAL_DERIVATION_ONLY:
                raise ReferenceCacheError(
                    f"{entry.reference_id}: local PDF extraction must be local-derivation-only"
                )
            if derivation.tool_name != _LOCAL_PDF_TEXT_TOOL_NAME:
                raise ReferenceCacheError(
                    f"{entry.reference_id}: local PDF extraction must name pypdf"
                )
            if derivation.tool_version is None:
                raise ReferenceCacheError(
                    f"{entry.reference_id}: local PDF extraction requires a pinned tool version"
                )
            if derivation.method != _LOCAL_PDF_TEXT_METHOD:
                raise ReferenceCacheError(
                    f"{entry.reference_id}: unsupported local PDF extraction method"
                )
            if derivation.parent_locator_authority is not ParentLocatorAuthority.MANIFEST_BOUND:
                raise ReferenceCacheError(
                    f"{entry.reference_id}: local PDF extraction parent must be manifest-bound"
                )
        elif entry.acquisition_policy is ReferenceAcquisitionPolicy.LOCAL_DERIVATION_ONLY:
            raise ReferenceCacheError(
                f"{entry.reference_id}: local-derivation-only requires local PDF extraction"
            )


def _validate_https_url(value: str, label: str) -> str:
    if any(character.isspace() or ord(character) < 0x20 for character in value):
        raise ReferenceCacheError(f"{label} contains whitespace or control characters")
    parsed = urllib.parse.urlsplit(value)
    try:
        port = parsed.port
    except ValueError as error:
        raise ReferenceCacheError(f"{label} contains an invalid port") from error
    hostname = parsed.hostname
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or port is not None
    ):
        raise ReferenceCacheError(
            f"{label} must be an HTTPS URL without credentials, queries, fragments, "
            "or explicit ports"
        )
    normalized_host = hostname.rstrip(".").lower()
    if not normalized_host.isascii():
        raise ReferenceCacheError(f"{label} hostname must contain ASCII characters only")
    if normalized_host == "localhost" or normalized_host.endswith(".localhost"):
        raise ReferenceCacheError(f"{label} cannot target a local hostname")
    try:
        address = ipaddress.ip_address(normalized_host)
    except ValueError:
        if _AMBIGUOUS_NUMERIC_HOST.fullmatch(normalized_host) is not None:
            raise ReferenceCacheError(f"{label} cannot use an ambiguous numeric hostname") from None
    else:
        if not address.is_global or address.is_multicast:
            raise ReferenceCacheError(
                f"{label} cannot target loopback, private, link-local, or reserved addresses"
            )
    return value


def _receipt_payload(
    verified: VerifiedReference,
    *,
    verified_at: datetime,
    network_used: bool,
) -> dict[str, object]:
    return {
        "schema_version": "autolean.reference-verification-receipt.v1",
        "reference_id": verified.entry.reference_id,
        "manifest_sha256": verified.manifest_sha256,
        "artifact_sha256": verified.entry.sha256,
        "size_bytes": verified.entry.size_bytes,
        "media_type": verified.entry.media_type,
        "cache_ref": verified.cache_ref,
        "verified_at": _render_utc(verified_at),
        "network_used": network_used,
    }


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ReferenceCacheError(f"duplicate JSON key in reference manifest: {key}")
        result[key] = value
    return result


def _expect_mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ReferenceCacheError(f"{label} must be a JSON object")
    return cast(dict[str, object], value)


def _expect_exact_keys(value: Mapping[str, object], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        raise ReferenceCacheError(f"{label} fields differ; missing={missing}, unknown={unknown}")


def _require_nonempty_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ReferenceCacheError(f"{label} must be nonempty, trimmed text")
    return value


def _optional_trimmed_text(value: object, label: str) -> str | None:
    if value is None:
        return None
    return _require_nonempty_text(value, label)


def _require_string(value: Mapping[str, object], key: str) -> str:
    return _require_nonempty_text(value[key], key)


def _require_positive_int(value: Mapping[str, object], key: str) -> int:
    result = value[key]
    if isinstance(result, bool) or not isinstance(result, int) or result <= 0:
        raise ReferenceCacheError(f"{key} must be a positive integer")
    return result


def _parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ReferenceCacheError("retrieved_at must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ReferenceCacheError("retrieved_at must carry a UTC offset")
    return parsed.astimezone(UTC)


def _render_utc(value: datetime) -> str:
    if value.tzinfo is None:
        raise ReferenceCacheError("verification timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _absolute_lexical(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _target_lock(path: Path) -> threading.Lock:
    key = os.path.normcase(os.fspath(_absolute_lexical(path)))
    with _TARGET_LOCKS_GUARD:
        return _TARGET_LOCKS.setdefault(key, threading.Lock())


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _relative_parts(path: Path, parent: Path) -> tuple[str, ...]:
    try:
        relative = path.relative_to(parent)
    except ValueError as error:
        raise ReferenceCacheError("reference cache path escapes its confinement root") from error
    if any(part in {"", ".", ".."} for part in relative.parts):
        raise ReferenceCacheError("reference cache path contains an unsafe component")
    return relative.parts


def _lstat_optional(path: Path) -> os.stat_result | None:
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise ReferenceCacheError(f"cannot inspect reference cache path: {path.name}") from error


def _is_link_or_reparse(value: os.stat_result) -> bool:
    attributes = int(getattr(value, "st_file_attributes", 0))
    return stat.S_ISLNK(value.st_mode) or bool(attributes & _REPARSE_POINT)


def _require_directory(path: Path) -> os.stat_result:
    value = _lstat_optional(path)
    if value is None:
        raise ReferenceCacheError(f"reference cache directory is absent: {path.name}")
    _require_directory_stat(path, value)
    return value


def _require_directory_stat(path: Path, value: os.stat_result) -> None:
    if _is_link_or_reparse(value):
        raise ReferenceCacheError(
            f"reference cache directories cannot be symlinks or junctions: {path.name}"
        )
    if not stat.S_ISDIR(value.st_mode):
        raise ReferenceCacheError(f"reference cache path is not a directory: {path.name}")


def _require_regular_stat(path: Path, value: os.stat_result) -> None:
    if _is_link_or_reparse(value):
        raise ReferenceCacheError(
            f"reference cache artifacts cannot be symlinks or reparse points: {path.name}"
        )
    if not stat.S_ISREG(value.st_mode):
        raise ReferenceCacheError(f"reference cache artifact is not a regular file: {path.name}")


def _inspect_regular_file(
    path: Path,
    *,
    span: tuple[int, int] | None = None,
) -> _FileInspection:
    before = _lstat_optional(path)
    if before is None:
        raise ReferenceCacheError(f"reference is absent from the local cache: {path.parent.name}")
    _require_regular_stat(path, before)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ReferenceCacheError(f"cannot open cached reference: {path.name}") from error
    try:
        opened = os.fstat(descriptor)
        _require_regular_stat(path, opened)
        if not os.path.samestat(before, opened):
            raise ReferenceCacheError("reference cache artifact changed while opening")
        hasher = hashlib.sha256()
        size = 0
        captured = bytearray()
        with os.fdopen(descriptor, "rb", closefd=True) as source:
            descriptor = -1
            while chunk := source.read(_CHUNK_BYTES):
                chunk_start = size
                chunk_end = chunk_start + len(chunk)
                if span is not None:
                    start, end = span
                    overlap_start = max(start, chunk_start)
                    overlap_end = min(end, chunk_end)
                    if overlap_start < overlap_end:
                        captured.extend(
                            chunk[overlap_start - chunk_start : overlap_end - chunk_start]
                        )
                size = chunk_end
                hasher.update(chunk)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    after = _lstat_optional(path)
    if after is None or not os.path.samestat(before, after):
        raise ReferenceCacheError("reference cache artifact changed during verification")
    _require_regular_stat(path, after)
    if span is not None and span[1] > size:
        raise ReferenceCacheError("text excerpt byte offsets exceed the cached artifact")
    return _FileInspection(
        size=size,
        sha256=hasher.hexdigest(),
        span_bytes=bytes(captured) if span is not None else None,
    )


def _unlink_confined_temporary(path: Path, parent: Path) -> None:
    absolute_path = _absolute_lexical(path)
    absolute_parent = _absolute_lexical(parent)
    permitted_prefixes = (".operator-download-", ".operator-import-")
    if absolute_path.parent != absolute_parent or not absolute_path.name.startswith(
        permitted_prefixes
    ):
        raise ReferenceCacheError("refusing to clean an unconfined acquisition temporary")
    try:
        os.unlink(absolute_path)
    except FileNotFoundError:
        return
    except OSError as error:
        raise ReferenceCacheError("cannot clean reference acquisition temporary") from error


def _fsync_directory_if_supported(path: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ReferenceCacheError("cannot open cache directory for synchronization") from error
    try:
        os.fsync(descriptor)
    except OSError as error:
        raise ReferenceCacheError("cannot synchronize cache directory") from error
    finally:
        os.close(descriptor)


def render_reference_index(manifest: ReferenceManifestV1) -> bytes:
    payload = {
        "schema_version": "autolean.reference-index.v1",
        "manifest_sha256": manifest.manifest_sha256,
        "references": [
            {
                "reference_id": entry.reference_id,
                "title": entry.title,
                "version": entry.version,
                "sha256": entry.sha256,
                "size_bytes": entry.size_bytes,
                "artifact_kind": entry.artifact_kind.value,
                "parent_reference_id": (
                    entry.derivation.parent_reference_id if entry.derivation is not None else None
                ),
                "access_policy": entry.access_policy.value,
                "acquisition_policy": entry.acquisition_policy.value,
                "model_egress_policy": entry.model_egress_policy.value,
            }
            for entry in manifest.entries
        ],
    }
    return canonical_json_bytes(payload) + b"\n"
