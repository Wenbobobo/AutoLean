"""Verify the fixed local reference cache or perform operator-only acquisition."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from tempfile import NamedTemporaryFile

from autolean_builder import (
    ReferenceCache,
    ReferenceCacheError,
    ReferenceManifestV1,
    render_reference_index,
)

_ROOT = Path(__file__).resolve().parents[1]
_TRACKED_MANIFEST = _ROOT / "Builder" / "references" / "manifest.v1.json"
_IGNORED_CACHE = _ROOT / ".cache" / "references"
_EXPECTED_MANIFEST_SHA256 = "9f6fc30c5bac7d3625938d6b4dae166270ef0f34c21db603be12c86d5bfd42ab"
_LOCAL_PDF_TEXT_METHOD = "pypdf-pdfreader-extract-text-plain-form-feed-v1"
_PINNED_PYPDF_VERSION = "6.10.0"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=(
            "list",
            "operator-fetch",
            "operator-import-local",
            "derive-pdf-text",
            "fingerprint-pdf-text",
            "verify",
            "verify-all",
        ),
    )
    parser.add_argument("reference_id", nargs="?")
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="replace an existing cached artifact; valid only for materialization actions",
    )
    parser.add_argument(
        "--input",
        type=Path,
        help="operator-supplied local PDF or text file for a local materialization action",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)

    reference_actions = {"operator-fetch", "operator-import-local", "derive-pdf-text", "verify"}
    if args.action in reference_actions and not args.reference_id:
        parser.error(f"{args.action} requires reference_id")
    if args.action in {"list", "verify-all", "fingerprint-pdf-text"} and args.reference_id:
        parser.error(f"{args.action} does not accept reference_id")
    if args.refresh and args.action not in {
        "operator-fetch",
        "operator-import-local",
        "derive-pdf-text",
    }:
        parser.error("--refresh is only valid with a materialization action")
    if args.input is not None and args.action not in {
        "operator-import-local",
        "fingerprint-pdf-text",
    }:
        parser.error("--input is only valid with a local input action")
    if args.action in {"operator-import-local", "fingerprint-pdf-text"} and args.input is None:
        parser.error(f"{args.action} requires --input")

    try:
        manifest = ReferenceManifestV1.load(
            _TRACKED_MANIFEST,
            expected_sha256=_EXPECTED_MANIFEST_SHA256,
        )
        cache = ReferenceCache(
            manifest,
            _IGNORED_CACHE,
            confinement_root=_ROOT,
        )
        if args.action == "list":
            sys.stdout.buffer.write(render_reference_index(manifest))
            return
        if args.action == "verify-all":
            verified_items = cache.verify_all()
            print(
                json.dumps(
                    {
                        "schema_version": "autolean.reference-verification-summary.v1",
                        "manifest_sha256": manifest.manifest_sha256,
                        "verified": [item.entry.reference_id for item in verified_items],
                        "network_used": False,
                    },
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                )
            )
            return
        if args.action == "fingerprint-pdf-text":
            assert args.input is not None
            payload = _pdf_text_fingerprint(args.input)
            print(json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
            return
        assert args.reference_id is not None
        verified_at = datetime.now(UTC)
        if args.action == "operator-fetch":
            result = cache.operator_fetch(args.reference_id, refresh=args.refresh)
            receipt = result.render_receipt(verified_at=verified_at)
        elif args.action == "operator-import-local":
            assert args.input is not None
            result = cache.operator_import_local(
                args.reference_id,
                args.input,
                refresh=args.refresh,
            )
            receipt = result.render_receipt(verified_at=verified_at)
        elif args.action == "derive-pdf-text":
            receipt = _derive_pdf_text(
                cache,
                args.reference_id,
                refresh=args.refresh,
                verified_at=verified_at,
            )
        else:
            verified = cache.verify(args.reference_id)
            receipt = verified.render_receipt(verified_at=verified_at)
        sys.stdout.buffer.write(receipt)
    except ReferenceCacheError as error:
        parser.exit(2, f"reference-cache: {error}\n")


def _derive_pdf_text(
    cache: ReferenceCache,
    reference_id: str,
    *,
    refresh: bool,
    verified_at: datetime,
) -> bytes:
    entry = cache.manifest.require(reference_id)
    derivation = entry.derivation
    if (
        entry.artifact_kind.value != "derived_text"
        or derivation is None
        or derivation.kind.value != "local_pdf_text_extraction"
        or derivation.tool_name != "pypdf"
        or derivation.method != _LOCAL_PDF_TEXT_METHOD
        or derivation.tool_version != _PINNED_PYPDF_VERSION
    ):
        raise ReferenceCacheError(
            "derive-pdf-text requires a manifest-pinned local pypdf text derivation"
        )
    target = cache.path_for(reference_id)
    if target.exists() and not refresh:
        return cache.verify(reference_id).render_receipt(verified_at=verified_at)
    parent = cache.verify(derivation.parent_reference_id)
    text = _extract_pdf_text(parent.cache_path, expected_version=derivation.tool_version)
    temporary_path: Path | None = None
    try:
        with NamedTemporaryFile(
            prefix="autolean-reference-text-",
            suffix=".txt",
            delete=False,
        ) as file:
            temporary_path = Path(file.name)
            file.write(text)
            file.flush()
        result = cache.operator_import_local(reference_id, temporary_path, refresh=True)
        return result.render_receipt(verified_at=verified_at)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _pdf_text_fingerprint(pdf_path: Path) -> dict[str, object]:
    pdf_bytes = _read_regular_file(pdf_path)
    text = _extract_pdf_text(pdf_path, expected_version=_PINNED_PYPDF_VERSION)
    return {
        "schema_version": "autolean.reference-pdf-text-fingerprint.v1",
        "method": _LOCAL_PDF_TEXT_METHOD,
        "tool_name": "pypdf",
        "tool_version": _PINNED_PYPDF_VERSION,
        "source_size_bytes": len(pdf_bytes),
        "source_sha256": hashlib.sha256(pdf_bytes).hexdigest(),
        "derived_size_bytes": len(text),
        "derived_sha256": hashlib.sha256(text).hexdigest(),
    }


def _extract_pdf_text(pdf_path: Path, *, expected_version: str) -> bytes:
    try:
        import pypdf
        from pypdf.errors import PdfReadError
    except ImportError as error:
        raise ReferenceCacheError("pypdf is required for local PDF text derivation") from error
    if pypdf.__version__ != expected_version:
        raise ReferenceCacheError(
            f"pypdf version differs from the manifest: {pypdf.__version__} != {expected_version}"
        )
    try:
        reader = pypdf.PdfReader(pdf_path)
        pages = (page.extract_text(extraction_mode="plain") for page in reader.pages)
        return _serialize_pdf_pages(pages)
    except (OSError, PdfReadError) as error:
        raise ReferenceCacheError("cannot extract text from local PDF") from error


def _serialize_pdf_pages(pages: Iterable[str | None]) -> bytes:
    """Encode raw pypdf page strings with an explicit, versioned page boundary."""

    page_text: list[str] = []
    for text in pages:
        if text is None:
            page_text.append("")
        elif isinstance(text, str):
            page_text.append(text)
        else:
            raise ReferenceCacheError("pypdf returned a non-text page extraction")
    return "\f".join(page_text).encode("utf-8")


def _read_regular_file(path: Path) -> bytes:
    try:
        if not path.is_file() or path.is_symlink():
            raise ReferenceCacheError("local PDF input must be a regular file")
        return path.read_bytes()
    except OSError as error:
        raise ReferenceCacheError("cannot read local PDF input") from error


if __name__ == "__main__":
    main()
