"""Prepare a local-only source lock for the selected iFEM Chapters 1--10 path.

The iFEM repository is large.  This adapter retrieves only the thirteen
selected source files at one immutable Git commit, plus the upstream LICENSE
needed to bind rights.  It delegates content-addressed cache installation and
replay to Builder's existing ``ReferenceCache``; it only owns the bounded
upstream route, notebook sanity checks, and the safe metadata receipt.

It never prints source text and does not authorize model egress, contract
freezing, or Prover handoff.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from http.client import HTTPMessage
from pathlib import Path
from typing import BinaryIO, cast

from autolean_builder import ReferenceCache, ReferenceCacheError, ReferenceManifestV1
from autolean_contracts import canonical_json_bytes

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CACHE_ROOT = ROOT / ".cache" / "references"

SCHEMA_VERSION = "autolean.ifem-source-lock.v1"
MANIFEST_CANDIDATE_SCHEMA_VERSION = "autolean.ifem-reference-manifest-candidate.v1"
REPOSITORY_URL = "https://github.com/JSchoeberl/iFEM"
PINNED_REVISION = "a4ab841c4e5ec726e9b7742c9dcb352cb9645736"
RAW_ROOT_URL = f"https://raw.githubusercontent.com/JSchoeberl/iFEM/{PINNED_REVISION}"
LICENSE_EVIDENCE_URL = f"{REPOSITORY_URL}/blob/{PINNED_REVISION}/LICENSE"
LICENSE_BLOB_SHA1 = "7aa2c7d055857957fc9464109c305df6916f3f30"
LICENSE_SHA256 = "91030ffc2d2f295670d43f67ac5c9f9ee7b9ace6609f5bcf6990fbd68f2665a0"
LICENSE_URL = "https://creativecommons.org/licenses/by/4.0/"
RECEIPT_DIRECTORY = "ifem-interactive-fem-chapters-01-10-git-a4ab841-lock"

MAX_SOURCE_FILE_BYTES = 256 * 1024 * 1024
MAX_TOTAL_SOURCE_BYTES = 2 * 1024 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024


class IFEMSourceLockError(ValueError):
    """The pinned source file, cache, or receipt violated the local source policy."""


@dataclass(frozen=True, slots=True)
class SourceFileSpec:
    reference_id: str
    path: str
    media_type: str
    extension: str

    @property
    def download_url(self) -> str:
        return f"{RAW_ROOT_URL}/{self.path}"


_SOURCE_PATHS = (
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


def _source_spec(path: str) -> SourceFileSpec:
    extension = Path(path).suffix.casefold()
    if extension == ".ipynb":
        media_type = "application/x-ipynb+json"
    elif extension == ".yml":
        media_type = "text/yaml"
    else:
        media_type = "text/markdown"
    identifier = path.replace("/", "-").replace("_", "-").replace(".", "-").casefold()
    return SourceFileSpec(f"ifem-a4ab841-{identifier}-source", path, media_type, extension)


SOURCE_FILES = tuple(_source_spec(path) for path in _SOURCE_PATHS)


@dataclass(frozen=True, slots=True)
class SourceFileRecord:
    reference_id: str
    path: str
    sha256: str
    size_bytes: int

    def as_json(self) -> dict[str, object]:
        return {
            "path": self.path,
            "reference_id": self.reference_id,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _git_blob_sha1(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data, usedforsecurity=False).hexdigest()


def _validate_source_bytes(spec: SourceFileSpec, data: bytes) -> SourceFileRecord:
    if not data or len(data) > MAX_SOURCE_FILE_BYTES:
        raise IFEMSourceLockError(f"source file has an invalid size: {spec.path}")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise IFEMSourceLockError(f"source file is not UTF-8: {spec.path}") from error
    if spec.extension == ".ipynb":
        try:
            notebook = json.loads(text)
        except json.JSONDecodeError as error:
            raise IFEMSourceLockError(f"source notebook is not valid JSON: {spec.path}") from error
        if not isinstance(notebook, dict) or not isinstance(notebook.get("nbformat"), int):
            raise IFEMSourceLockError(f"source notebook has no nbformat: {spec.path}")
    elif not text.strip():
        raise IFEMSourceLockError(f"source text is blank: {spec.path}")
    return SourceFileRecord(spec.reference_id, spec.path, _sha256(data), len(data))


def _validate_license_bytes(data: bytes) -> str:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise IFEMSourceLockError("pinned LICENSE is not UTF-8") from error
    if (
        "Creative Commons Attribution 4.0 International" not in text
        or "creativecommons.org/licenses/by/4.0" not in text
    ):
        raise IFEMSourceLockError("pinned LICENSE does not contain the CC BY 4.0 notice")
    sha256 = _sha256(data)
    if _git_blob_sha1(data) != LICENSE_BLOB_SHA1 or sha256 != LICENSE_SHA256:
        raise IFEMSourceLockError("pinned LICENSE differs from the reviewed Git blob")
    return sha256


class _RejectRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(  # type: ignore[override]
        self,
        req: urllib.request.Request,
        fp: BinaryIO,
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> urllib.request.Request:
        del req, fp, code, msg, headers, newurl
        raise IFEMSourceLockError("source endpoint redirect was rejected")


def _download_to(url: str, destination: Path) -> None:
    opener = urllib.request.build_opener(_RejectRedirectHandler())
    request = urllib.request.Request(url, headers={"User-Agent": "AutoLean-iFEM-source-lock/1"})
    try:
        with (
            opener.open(request, timeout=120) as response,
            destination.open("wb") as output,
        ):
            if response.geturl() != url:
                raise IFEMSourceLockError("source endpoint redirected away from the pinned URL")
            if response.headers.get_content_type().lower() not in {
                "application/json",
                "application/octet-stream",
                "text/plain",
            }:
                raise IFEMSourceLockError("source endpoint returned an unexpected media type")
            total = 0
            while chunk := response.read(CHUNK_BYTES):
                total += len(chunk)
                if total > MAX_SOURCE_FILE_BYTES:
                    raise IFEMSourceLockError("source file exceeds the local byte limit")
                output.write(chunk)
    except IFEMSourceLockError:
        raise
    except (OSError, urllib.error.URLError) as error:
        raise IFEMSourceLockError("iFEM source download failed") from error


def _receipt_path(cache_root: Path) -> Path:
    return cache_root / RECEIPT_DIRECTORY / "source-lock.v1.json"


def manifest_entries(
    records: Sequence[SourceFileRecord], *, retrieved_at: str
) -> list[dict[str, object]]:
    if tuple(record.reference_id for record in records) != tuple(
        spec.reference_id for spec in SOURCE_FILES
    ):
        raise IFEMSourceLockError("source records do not match the fixed chapter path")
    entries: list[dict[str, object]] = []
    for spec, record in zip(SOURCE_FILES, records, strict=True):
        entries.append(
            {
                "access_policy": "public_open_access",
                "acquisition_policy": "operator_only",
                "allowed_redirect_urls": [],
                "artifact_kind": "source_document",
                "attribution": (
                    "Joachim Schoberl and colleagues, An Interactive Introduction to the Finite "
                    "Element Method. TU Wien. CC BY 4.0."
                ),
                "authors": ["Joachim Schoberl and colleagues"],
                "citation": (
                    "Schoberl, Joachim et al. An Interactive Introduction to the Finite "
                    "Element Method."
                ),
                "derivation": None,
                "download_url": spec.download_url,
                "file_extension": spec.extension,
                "license": {
                    "evidence_url": LICENSE_EVIDENCE_URL,
                    "expression": "CC-BY-4.0",
                    "url": LICENSE_URL,
                },
                "max_bytes": MAX_SOURCE_FILE_BYTES,
                "media_type": spec.media_type,
                "model_egress_policy": "local_only",
                "reference_id": spec.reference_id,
                "retrieved_at": retrieved_at,
                "sha256": record.sha256,
                "size_bytes": record.size_bytes,
                "source_record_url": REPOSITORY_URL,
                "title": f"iFEM source: {spec.path}",
                "version": f"git-{PINNED_REVISION}",
            }
        )
    return entries


def _manifest_candidate_payload(
    entries: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    return {
        "entries": list(entries),
        "schema_version": MANIFEST_CANDIDATE_SCHEMA_VERSION,
    }


def _manifest_candidate_sha256(entries: Sequence[Mapping[str, object]]) -> str:
    return _sha256(canonical_json_bytes(_manifest_candidate_payload(entries)))


def _cache_for_entries(
    entries: Sequence[Mapping[str, object]], cache_root: Path, work_root: Path
) -> ReferenceCache:
    manifest_path = work_root / "reference-manifest.json"
    manifest_path.write_bytes(
        canonical_json_bytes(
            {"entries": list(entries), "schema_version": "autolean.reference-manifest.v1"}
        )
        + b"\n"
    )
    try:
        manifest = ReferenceManifestV1.load(manifest_path)
        return ReferenceCache(manifest, cache_root, confinement_root=cache_root.parent)
    except ReferenceCacheError as error:
        raise IFEMSourceLockError("generated iFEM reference manifest is invalid") from error


def _receipt_payload(
    records: Sequence[SourceFileRecord], *, license_sha256: str, retrieved_at: str
) -> dict[str, object]:
    entries = manifest_entries(records, retrieved_at=retrieved_at)
    return {
        "acquisition": {
            "retrieved_at": retrieved_at,
            "source_file_count": len(records),
            "source_size_bytes": sum(record.size_bytes for record in records),
        },
        "policy": {
            "access_policy": "public_open_access",
            "contract_freeze": "not_authorized",
            "model_egress_policy": "local_only",
            "prover_handoff": "not_authorized",
        },
        "reference_manifest_candidate_sha256": _manifest_candidate_sha256(entries),
        "reference_manifest_state": "candidate_entries_not_yet_tracked",
        "schema_version": SCHEMA_VERSION,
        "source": {
            "license": {
                "evidence_url": LICENSE_EVIDENCE_URL,
                "expression": "CC-BY-4.0",
                "license_blob_sha1": LICENSE_BLOB_SHA1,
                "license_sha256": license_sha256,
                "url": LICENSE_URL,
            },
            "record_url": REPOSITORY_URL,
            "resolved_revision": PINNED_REVISION,
        },
        "source_files": [record.as_json() for record in records],
        "state": "acquired_local_only",
    }


def _write_receipt_once(path: Path, payload: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = canonical_json_bytes(payload) + b"\n"
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        try:
            if path.read_bytes() != content:
                raise IFEMSourceLockError("existing source-lock receipt conflicts")
        except OSError as error:
            raise IFEMSourceLockError("cannot read existing source-lock receipt") from error
        return
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
    except OSError as error:
        raise IFEMSourceLockError("cannot write source-lock receipt") from error


def _parse_records(value: object) -> tuple[SourceFileRecord, ...]:
    if not isinstance(value, list) or len(value) != len(SOURCE_FILES):
        raise IFEMSourceLockError("source-lock receipt source-file count is invalid")
    records: list[SourceFileRecord] = []
    for item, spec in zip(value, SOURCE_FILES, strict=True):
        if not isinstance(item, dict) or set(item) != {
            "path",
            "reference_id",
            "sha256",
            "size_bytes",
        }:
            raise IFEMSourceLockError("source-lock receipt source-file record is invalid")
        record = cast(dict[str, object], item)
        reference_id = record.get("reference_id")
        path = record.get("path")
        sha256 = record.get("sha256")
        size_bytes = record.get("size_bytes")
        if (
            reference_id != spec.reference_id
            or path != spec.path
            or not isinstance(sha256, str)
            or len(sha256) != 64
            or any(character not in "0123456789abcdef" for character in sha256)
            or not isinstance(size_bytes, int)
            or isinstance(size_bytes, bool)
            or not 0 < size_bytes <= MAX_SOURCE_FILE_BYTES
        ):
            raise IFEMSourceLockError("source-lock receipt source-file identity drifted")
        records.append(SourceFileRecord(reference_id, path, sha256, size_bytes))
    return tuple(records)


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise IFEMSourceLockError(f"duplicate JSON key in source-lock receipt: {key}")
        result[key] = value
    return result


def inspect_receipt(
    cache_root: Path, receipt_path: Path
) -> tuple[dict[str, object], tuple[SourceFileRecord, ...]]:
    expected_receipt = _receipt_path(cache_root).resolve()
    try:
        actual_receipt = receipt_path.resolve(strict=True)
    except OSError as error:
        raise IFEMSourceLockError("source-lock receipt is absent or inaccessible") from error
    if actual_receipt != expected_receipt:
        raise IFEMSourceLockError("source-lock receipt is outside its canonical cache location")
    try:
        document = json.loads(
            receipt_path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IFEMSourceLockError("source-lock receipt is not valid UTF-8 JSON") from error
    if not isinstance(document, dict):
        raise IFEMSourceLockError("source-lock receipt must be an object")
    document = cast(dict[str, object], document)
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
    if set(document) != required or document.get("schema_version") != SCHEMA_VERSION:
        raise IFEMSourceLockError("source-lock receipt schema is invalid")
    if (
        document.get("state") != "acquired_local_only"
        or document.get("reference_manifest_state") != "candidate_entries_not_yet_tracked"
    ):
        raise IFEMSourceLockError("source-lock receipt state is invalid")
    policy = document.get("policy")
    source = document.get("source")
    acquisition = document.get("acquisition")
    expected_policy = {
        "access_policy": "public_open_access",
        "contract_freeze": "not_authorized",
        "model_egress_policy": "local_only",
        "prover_handoff": "not_authorized",
    }
    if policy != expected_policy:
        raise IFEMSourceLockError("source-lock receipt policy is not the fixed local-only policy")
    if (
        not isinstance(source, dict)
        or set(source) != {"license", "record_url", "resolved_revision"}
        or source.get("record_url") != REPOSITORY_URL
        or source.get("resolved_revision") != PINNED_REVISION
    ):
        raise IFEMSourceLockError("source-lock receipt source revision is invalid")
    license_record = source.get("license")
    expected_license = {
        "evidence_url": LICENSE_EVIDENCE_URL,
        "expression": "CC-BY-4.0",
        "license_blob_sha1": LICENSE_BLOB_SHA1,
        "license_sha256": LICENSE_SHA256,
        "url": LICENSE_URL,
    }
    if license_record != expected_license:
        raise IFEMSourceLockError("source-lock receipt license binding is invalid")
    retrieved_at = acquisition.get("retrieved_at") if isinstance(acquisition, dict) else None
    if (
        not isinstance(acquisition, dict)
        or set(acquisition) != {"retrieved_at", "source_file_count", "source_size_bytes"}
        or not isinstance(retrieved_at, str)
    ):
        raise IFEMSourceLockError("source-lock receipt acquisition record is invalid")
    try:
        parsed_retrieved_at = datetime.fromisoformat(retrieved_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise IFEMSourceLockError("source-lock receipt retrieval time is invalid") from error
    if parsed_retrieved_at.tzinfo is None or parsed_retrieved_at.utcoffset() is None:
        raise IFEMSourceLockError("source-lock receipt retrieval time has no UTC offset")
    records = _parse_records(document.get("source_files"))
    if acquisition.get("source_file_count") != len(records) or acquisition.get(
        "source_size_bytes"
    ) != sum(record.size_bytes for record in records):
        raise IFEMSourceLockError("source-lock receipt aggregate values drifted")
    entries = manifest_entries(records, retrieved_at=cast(str, acquisition["retrieved_at"]))
    if document.get("reference_manifest_candidate_sha256") != _manifest_candidate_sha256(entries):
        raise IFEMSourceLockError("source-lock receipt manifest candidate binding drifted")
    with tempfile.TemporaryDirectory(prefix="autolean-ifem-verify-", dir=cache_root.parent) as raw:
        try:
            cache = _cache_for_entries(entries, cache_root, Path(raw))
            verified = tuple(cache.verify(spec.reference_id) for spec in SOURCE_FILES)
        except ReferenceCacheError as error:
            raise IFEMSourceLockError("cached iFEM source does not match its receipt") from error
    if any(
        item.entry.sha256 != record.sha256 or item.entry.size_bytes != record.size_bytes
        for item, record in zip(verified, records, strict=True)
    ):
        raise IFEMSourceLockError("cached iFEM source verification drifted")
    return document, records


def acquire(
    cache_root: Path, *, now: datetime | None = None
) -> tuple[Path, list[dict[str, object]]]:
    """Retrieve the bounded pinned source path and install it through ReferenceCache."""

    cache_root.parent.mkdir(parents=True, exist_ok=True)
    receipt = _receipt_path(cache_root)
    if receipt.exists():
        document, existing_records = inspect_receipt(cache_root, receipt)
        retrieval = cast(dict[str, object], document["acquisition"])["retrieved_at"]
        return receipt, manifest_entries(existing_records, retrieved_at=cast(str, retrieval))
    retrieved_at = (now or datetime.now(UTC)).astimezone(UTC).isoformat().replace("+00:00", "Z")
    with tempfile.TemporaryDirectory(prefix="autolean-ifem-acquire-", dir=cache_root.parent) as raw:
        work_root = Path(raw)
        license_path = work_root / "LICENSE"
        _download_to(f"{RAW_ROOT_URL}/LICENSE", license_path)
        license_sha256 = _validate_license_bytes(license_path.read_bytes())
        source_records: list[SourceFileRecord] = []
        staged: dict[str, Path] = {}
        total = 0
        for index, spec in enumerate(SOURCE_FILES):
            source_path = work_root / f"source-{index}{spec.extension}"
            _download_to(spec.download_url, source_path)
            record = _validate_source_bytes(spec, source_path.read_bytes())
            total += record.size_bytes
            if total > MAX_TOTAL_SOURCE_BYTES:
                raise IFEMSourceLockError("selected iFEM source path exceeds the total byte limit")
            source_records.append(record)
            staged[spec.reference_id] = source_path
        entries = manifest_entries(source_records, retrieved_at=retrieved_at)
        try:
            cache = _cache_for_entries(entries, cache_root, work_root)
            for spec in SOURCE_FILES:
                cache.operator_import_local(spec.reference_id, staged[spec.reference_id])
        except ReferenceCacheError as error:
            raise IFEMSourceLockError("cannot install iFEM source into ReferenceCache") from error
    receipt_document = _receipt_payload(
        source_records,
        license_sha256=license_sha256,
        retrieved_at=retrieved_at,
    )
    _write_receipt_once(receipt, receipt_document)
    return receipt, entries


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("action", choices=("acquire", "verify", "manifest-entries"))
    parser.add_argument("--cache-root", type=Path, default=DEFAULT_CACHE_ROOT)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--operator-acquire", action="store_true")
    return parser


def _safe_summary(receipt_path: Path, entries: Sequence[Mapping[str, object]]) -> dict[str, object]:
    return {
        "manifest_entry_count": len(entries),
        "receipt_path": receipt_path.as_posix(),
        "selected_source_file_count": len(SOURCE_FILES),
        "state": "acquired_local_only",
    }


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.action == "acquire" and not args.operator_acquire:
        print("ifem-source-lock: acquire requires --operator-acquire", file=sys.stderr)
        return 2
    if args.action != "acquire" and args.operator_acquire:
        print("ifem-source-lock: --operator-acquire is valid only with acquire", file=sys.stderr)
        return 2
    if args.action == "acquire" and args.receipt is not None:
        print("ifem-source-lock: acquire does not accept --receipt", file=sys.stderr)
        return 2
    if args.action != "acquire" and args.receipt is None:
        print(f"ifem-source-lock: {args.action} requires --receipt", file=sys.stderr)
        return 2
    try:
        cache_root = args.cache_root.resolve()
        if args.action == "acquire":
            receipt_path, entries = acquire(cache_root)
            print(
                json.dumps(_safe_summary(receipt_path, entries), ensure_ascii=True, sort_keys=True)
            )
            return 0
        assert args.receipt is not None
        receipt_path = args.receipt.resolve()
        document, records = inspect_receipt(cache_root, receipt_path)
        retrieval = cast(dict[str, object], document["acquisition"])["retrieved_at"]
        entries = manifest_entries(records, retrieved_at=cast(str, retrieval))
        if args.action == "verify":
            print(
                json.dumps(_safe_summary(receipt_path, entries), ensure_ascii=True, sort_keys=True)
            )
        else:
            print(
                json.dumps(
                    _manifest_candidate_payload(entries),
                    ensure_ascii=True,
                    sort_keys=True,
                )
            )
        return 0
    except IFEMSourceLockError as error:
        print(f"ifem-source-lock: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
