"""Materialize a local byte-identical text overlay for locked iFEM Markdown.

The source-lock remains the authority for the thirteen source records.  This
adapter only replays its fixed ``intro.md`` record into a distinct, local-only
``text/plain`` cache object with the same bytes.  It never acquires network
data, prints source content or paths, authorizes model egress, freezes a
statement, or creates a Prover handoff.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast

from autolean_builder import ReferenceCache, ReferenceCacheError, ReferenceManifestV1
from autolean_builder.reference_cache import REPOSITORY_MARKDOWN_TEXT_IDENTITY_METHOD
from autolean_contracts import canonical_json_bytes

try:
    from scripts import ifem_source_lock
except ModuleNotFoundError:  # Direct execution keeps only this script directory on sys.path.
    import ifem_source_lock  # type: ignore[import-not-found, no-redef]

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CACHE_ROOT = ROOT / ".cache" / "references"
INTRO_MARKDOWN_PATH: Final[str] = "intro.md"
DERIVED_TEXT_REFERENCE_ID: Final[str] = "ifem-a4ab841-intro-md-local-text-v1"
OVERLAY_DIRECTORY: Final[str] = "repository-markdown-text-overlay-v1"
OVERLAY_MANIFEST_FILENAME: Final[str] = "reference-manifest.overlay.v1.json"
OVERLAY_RECEIPT_FILENAME: Final[str] = "repository-text-receipt.v1.json"
OVERLAY_MANIFEST_SCHEMA: Final[str] = "autolean.reference-manifest.v1"
OVERLAY_RECEIPT_SCHEMA: Final[str] = "autolean.ifem-repository-text-receipt.v1"
OVERLAY_ARTIFACT_KIND: Final[str] = "local_only_repository_markdown_text_overlay"
_SHA256_LENGTH = 64
_REPARSE_POINT = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


class IFEMRepositoryTextError(ValueError):
    """The source lock, local overlay, or authority boundary did not replay."""


def _is_link_or_reparse(path: Path, metadata: os.stat_result | None = None) -> bool:
    try:
        value = path.lstat() if metadata is None else metadata
    except OSError:
        return False
    is_junction = getattr(os.path, "isjunction", None)
    return (
        stat.S_ISLNK(value.st_mode)
        or bool(int(getattr(value, "st_file_attributes", 0)) & _REPARSE_POINT)
        or bool(is_junction is not None and is_junction(path))
        or bool(getattr(path, "is_junction", lambda: False)())
    )


@dataclass(frozen=True, slots=True)
class _OverlayPlan:
    cache_root: Path
    manifest_path: Path
    receipt_path: Path
    manifest_bytes: bytes
    receipt_bytes: bytes
    parent_reference_id: str
    derived_reference_id: str
    parent_sha256: str
    parent_size_bytes: int

    @property
    def manifest_sha256(self) -> str:
        return _sha256(self.manifest_bytes)

    @property
    def receipt_sha256(self) -> str:
        return _sha256(self.receipt_bytes)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _require_real_directory(path: Path, *, label: str) -> Path:
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise IFEMRepositoryTextError(f"{label} is absent or inaccessible") from error
    if _is_link_or_reparse(path, metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise IFEMRepositoryTextError(f"{label} must be a physical directory")
    return resolved


def _read_regular_file(path: Path, *, label: str) -> bytes:
    try:
        metadata = path.lstat()
        if _is_link_or_reparse(path, metadata) or not stat.S_ISREG(metadata.st_mode):
            raise IFEMRepositoryTextError(f"{label} must be a physical regular file")
        return path.read_bytes()
    except OSError as error:
        raise IFEMRepositoryTextError(f"cannot read {label}") from error


def _ensure_real_directory_tree(root: Path, destination_parent: Path) -> None:
    root = _require_real_directory(root, label="iFEM source cache root")
    target = destination_parent.resolve(strict=False)
    if not _is_relative_to(target, root):
        raise IFEMRepositoryTextError("local overlay output escapes the iFEM source cache")
    relative_parts = target.relative_to(root).parts
    current = root
    for part in relative_parts:
        current = current / part
        with suppress(FileExistsError):
            current.mkdir()
        try:
            metadata = current.lstat()
        except OSError as error:
            raise IFEMRepositoryTextError("cannot create local overlay directory") from error
        if _is_link_or_reparse(current, metadata) or not stat.S_ISDIR(metadata.st_mode):
            raise IFEMRepositoryTextError(
                "local overlay directory must not be a link or reparse point"
            )


def _write_once(path: Path, content: bytes, *, cache_root: Path, label: str) -> None:
    _ensure_real_directory_tree(cache_root, path.parent)
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        if _read_regular_file(path, label=f"existing {label}") != content:
            raise IFEMRepositoryTextError(
                f"existing {label} conflicts with this exact replay"
            ) from None
        return
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
    except OSError as error:
        raise IFEMRepositoryTextError(f"cannot write {label}") from error


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise IFEMRepositoryTextError(f"duplicate JSON key in local overlay: {key}")
        result[key] = value
    return result


def _require_mapping(value: object, *, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise IFEMRepositoryTextError(f"{label} must be an object")
    return cast(dict[str, object], value)


def _require_string(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise IFEMRepositoryTextError(f"{label} must be nonempty text")
    return value


def _require_positive_int(value: object, *, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise IFEMRepositoryTextError(f"{label} must be a positive integer")
    return value


def _canonical_source_lock_path(cache_root: Path) -> Path:
    return cache_root / ifem_source_lock.RECEIPT_DIRECTORY / "source-lock.v1.json"


def _overlay_paths(cache_root: Path, source_lock_path: Path) -> tuple[Path, Path]:
    expected_source_lock = _canonical_source_lock_path(cache_root)
    _require_real_directory(expected_source_lock.parent, label="iFEM source-lock directory")
    try:
        actual = source_lock_path.resolve(strict=True)
        expected = expected_source_lock.resolve(strict=True)
    except OSError as error:
        raise IFEMRepositoryTextError(
            "iFEM source-lock receipt is absent or inaccessible"
        ) from error
    if actual != expected:
        raise IFEMRepositoryTextError(
            "iFEM source-lock receipt is outside its canonical cache path"
        )
    overlay_root = expected.parent / OVERLAY_DIRECTORY
    return overlay_root / OVERLAY_MANIFEST_FILENAME, overlay_root / OVERLAY_RECEIPT_FILENAME


def _locked_intro_parent(
    cache_root: Path,
    source_lock_path: Path,
) -> tuple[dict[str, object], str]:
    try:
        receipt, records = ifem_source_lock.inspect_receipt(cache_root, source_lock_path)
    except ifem_source_lock.IFEMSourceLockError as error:
        raise IFEMRepositoryTextError("iFEM source lock did not verify") from error
    source_lock_sha256 = _sha256(_read_regular_file(source_lock_path, label="iFEM source lock"))
    acquisition = _require_mapping(receipt.get("acquisition"), label="source-lock acquisition")
    retrieved_at = _require_string(
        acquisition.get("retrieved_at"), label="source-lock retrieval time"
    )
    try:
        entries = ifem_source_lock.manifest_entries(records, retrieved_at=retrieved_at)
        source_spec_index, source_spec = next(
            (index, spec)
            for index, spec in enumerate(ifem_source_lock.SOURCE_FILES)
            if spec.path == INTRO_MARKDOWN_PATH
        )
    except (StopIteration, ifem_source_lock.IFEMSourceLockError) as error:
        raise IFEMRepositoryTextError("fixed iFEM Markdown parent is unavailable") from error
    parent = dict(entries[source_spec_index])
    if (
        parent.get("reference_id") != source_spec.reference_id
        or parent.get("media_type") != "text/markdown"
        or parent.get("file_extension") != ".md"
        or parent.get("artifact_kind") != "source_document"
        or parent.get("model_egress_policy") != "local_only"
    ):
        raise IFEMRepositoryTextError("fixed iFEM Markdown parent has unexpected metadata")
    return parent, source_lock_sha256


def _derived_entry(parent: Mapping[str, object]) -> dict[str, object]:
    reference_id = _require_string(parent.get("reference_id"), label="parent reference ID")
    parent_sha256 = _require_string(parent.get("sha256"), label="parent SHA-256")
    parent_size = _require_positive_int(parent.get("size_bytes"), label="parent size")
    if len(parent_sha256) != _SHA256_LENGTH or any(
        character not in "0123456789abcdef" for character in parent_sha256
    ):
        raise IFEMRepositoryTextError("parent SHA-256 is malformed")
    if parent.get("model_egress_policy") != "local_only":
        raise IFEMRepositoryTextError("fixed iFEM Markdown parent is not local-only")
    return {
        "access_policy": parent["access_policy"],
        "acquisition_policy": "local_derivation_only",
        "allowed_redirect_urls": [],
        "artifact_kind": "derived_text",
        "attribution": parent["attribution"],
        "authors": parent["authors"],
        "citation": "Byte-identical local text projection of a locked iFEM Markdown source.",
        "derivation": {
            "kind": "repository_text_extraction",
            "method": REPOSITORY_MARKDOWN_TEXT_IDENTITY_METHOD,
            "parent_locator_authority": "human_declared",
            "parent_reference_id": reference_id,
            "parent_sha256": parent_sha256,
            "producer": "AutoLean local repository text overlay",
            "provenance_url": parent["source_record_url"],
            "tool_name": None,
            "tool_version": None,
        },
        "download_url": None,
        "file_extension": ".txt",
        "license": parent["license"],
        "max_bytes": parent_size,
        "media_type": "text/plain",
        "model_egress_policy": "local_only",
        "reference_id": DERIVED_TEXT_REFERENCE_ID,
        "retrieved_at": parent["retrieved_at"],
        "sha256": parent_sha256,
        "size_bytes": parent_size,
        "source_record_url": parent["source_record_url"],
        "title": "iFEM locked Markdown local text identity",
        "version": f"{_require_string(parent.get('version'), label='parent version')}-text-v1",
    }


def _manifest_bytes(parent: Mapping[str, object], derived: Mapping[str, object]) -> bytes:
    return (
        canonical_json_bytes(
            {
                "entries": [dict(parent), dict(derived)],
                "schema_version": OVERLAY_MANIFEST_SCHEMA,
            }
        )
        + b"\n"
    )


def _receipt_bytes(
    *,
    source_lock_sha256: str,
    manifest_sha256: str,
    parent: Mapping[str, object],
    derived: Mapping[str, object],
) -> bytes:
    receipt = {
        "artifact_kind": OVERLAY_ARTIFACT_KIND,
        "contains_source_path": False,
        "contains_source_text": False,
        "derived_text": {
            "media_type": "text/plain",
            "reference_id": derived["reference_id"],
            "sha256": derived["sha256"],
            "size_bytes": derived["size_bytes"],
        },
        "overlay_manifest_sha256": manifest_sha256,
        "parent": {
            "reference_id": parent["reference_id"],
            "sha256": parent["sha256"],
            "size_bytes": parent["size_bytes"],
        },
        "policy": {
            "contract_freeze_authorized": False,
            "model_egress_policy": "local_only",
            "prover_handoff_authorized": False,
        },
        "schema_version": OVERLAY_RECEIPT_SCHEMA,
        "source_lock_receipt_sha256": source_lock_sha256,
        "state": "materialized_local_only",
    }
    return canonical_json_bytes(receipt) + b"\n"


def _plan(cache_root: Path, source_lock_path: Path) -> _OverlayPlan:
    resolved_cache_root = _require_real_directory(cache_root, label="iFEM source cache root")
    manifest_path, receipt_path = _overlay_paths(resolved_cache_root, source_lock_path)
    parent, source_lock_sha256 = _locked_intro_parent(resolved_cache_root, source_lock_path)
    derived = _derived_entry(parent)
    manifest_bytes = _manifest_bytes(parent, derived)
    receipt_bytes = _receipt_bytes(
        source_lock_sha256=source_lock_sha256,
        manifest_sha256=_sha256(manifest_bytes),
        parent=parent,
        derived=derived,
    )
    return _OverlayPlan(
        cache_root=resolved_cache_root,
        manifest_path=manifest_path,
        receipt_path=receipt_path,
        manifest_bytes=manifest_bytes,
        receipt_bytes=receipt_bytes,
        parent_reference_id=_require_string(
            parent.get("reference_id"), label="parent reference ID"
        ),
        derived_reference_id=DERIVED_TEXT_REFERENCE_ID,
        parent_sha256=_require_string(parent.get("sha256"), label="parent SHA-256"),
        parent_size_bytes=_require_positive_int(parent.get("size_bytes"), label="parent size"),
    )


def _load_exact_manifest(plan: _OverlayPlan) -> ReferenceManifestV1:
    manifest_bytes = _read_regular_file(plan.manifest_path, label="local overlay manifest")
    if manifest_bytes != plan.manifest_bytes:
        raise IFEMRepositoryTextError("local overlay manifest differs from the fixed source replay")
    try:
        return ReferenceManifestV1.load(
            plan.manifest_path,
            expected_sha256=plan.manifest_sha256,
        )
    except ReferenceCacheError as error:
        raise IFEMRepositoryTextError("local overlay manifest is invalid") from error


def _verify_cached_identity(plan: _OverlayPlan, manifest: ReferenceManifestV1) -> None:
    try:
        cache = ReferenceCache(
            manifest,
            plan.cache_root,
            confinement_root=plan.cache_root.parent,
        )
        parent = cache.verify(plan.parent_reference_id)
        derived = cache.verify(plan.derived_reference_id)
    except ReferenceCacheError as error:
        raise IFEMRepositoryTextError("local overlay cache object did not verify") from error
    parent_bytes = _read_regular_file(parent.cache_path, label="locked Markdown cache object")
    derived_bytes = _read_regular_file(derived.cache_path, label="derived text cache object")
    try:
        parent_bytes.decode("utf-8", errors="strict")
        derived_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise IFEMRepositoryTextError("local Markdown text identity is not strict UTF-8") from error
    if parent_bytes != derived_bytes:
        raise IFEMRepositoryTextError("local Markdown text identity differs from its parent bytes")


def _load_exact_receipt(plan: _OverlayPlan) -> None:
    raw = _read_regular_file(plan.receipt_path, label="local overlay receipt")
    try:
        parsed = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IFEMRepositoryTextError("local overlay receipt is not strict UTF-8 JSON") from error
    receipt = _require_mapping(parsed, label="local overlay receipt")
    if canonical_json_bytes(receipt) + b"\n" != raw:
        raise IFEMRepositoryTextError("local overlay receipt is not canonically rendered")
    if raw != plan.receipt_bytes:
        raise IFEMRepositoryTextError("local overlay receipt differs from the fixed source replay")


def materialize_ifem_repository_text_overlay(
    *,
    cache_root: Path = DEFAULT_CACHE_ROOT,
    source_lock_path: Path | None = None,
) -> _OverlayPlan:
    """Create the fixed local overlay and receipt, accepting exact replay only."""

    lock_path = source_lock_path or _canonical_source_lock_path(cache_root)
    plan = _plan(cache_root, lock_path)
    _write_once(
        plan.manifest_path,
        plan.manifest_bytes,
        cache_root=plan.cache_root,
        label="local overlay manifest",
    )
    manifest = _load_exact_manifest(plan)
    try:
        cache = ReferenceCache(
            manifest,
            plan.cache_root,
            confinement_root=plan.cache_root.parent,
        )
        parent = cache.verify(plan.parent_reference_id)
    except ReferenceCacheError as error:
        raise IFEMRepositoryTextError("locked Markdown parent did not verify") from error
    parent_bytes = _read_regular_file(parent.cache_path, label="locked Markdown cache object")
    try:
        parent_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise IFEMRepositoryTextError("locked Markdown parent is not strict UTF-8") from error
    try:
        cache.operator_import_local(plan.derived_reference_id, parent.cache_path)
    except ReferenceCacheError as error:
        raise IFEMRepositoryTextError("cannot materialize local Markdown text identity") from error
    _verify_cached_identity(plan, manifest)
    _write_once(
        plan.receipt_path,
        plan.receipt_bytes,
        cache_root=plan.cache_root,
        label="local overlay receipt",
    )
    _load_exact_receipt(plan)
    return plan


def verify_ifem_repository_text_overlay(
    *,
    cache_root: Path = DEFAULT_CACHE_ROOT,
    source_lock_path: Path | None = None,
) -> _OverlayPlan:
    """Replay all source, manifest, byte-identity, and receipt bindings offline."""

    lock_path = source_lock_path or _canonical_source_lock_path(cache_root)
    plan = _plan(cache_root, lock_path)
    manifest = _load_exact_manifest(plan)
    _verify_cached_identity(plan, manifest)
    _load_exact_receipt(plan)
    return plan


def _public_summary(plan: _OverlayPlan) -> dict[str, object]:
    """Return only metadata safe to print outside the local source cache."""

    return {
        "artifact_kind": OVERLAY_ARTIFACT_KIND,
        "contract_freeze_authorized": False,
        "derived_text_sha256": plan.parent_sha256,
        "derived_text_size_bytes": plan.parent_size_bytes,
        "model_egress_policy": "local_only",
        "overlay_manifest_sha256": plan.manifest_sha256,
        "overlay_receipt_sha256": plan.receipt_sha256,
        "prover_handoff_authorized": False,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("action", choices=("materialize", "verify"))
    parser.add_argument("--cache-root", type=Path, default=DEFAULT_CACHE_ROOT)
    parser.add_argument("--source-lock", type=Path)
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    namespace = _build_parser().parse_args(arguments)
    try:
        if namespace.action == "materialize":
            plan = materialize_ifem_repository_text_overlay(
                cache_root=namespace.cache_root,
                source_lock_path=namespace.source_lock,
            )
        else:
            plan = verify_ifem_repository_text_overlay(
                cache_root=namespace.cache_root,
                source_lock_path=namespace.source_lock,
            )
    except IFEMRepositoryTextError as error:
        print(f"ifem-repository-text: {error}", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_json_bytes(_public_summary(plan)) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
