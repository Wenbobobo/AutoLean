"""Create a local-only, non-freezing textbook opening-alignment worksheet."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from autolean_builder import (
    TextbookAlignmentError,
    build_textbook_alignment_discovery,
    render_textbook_alignment_public_summary,
    write_textbook_alignment_discovery,
)

_ROOT = Path(__file__).resolve().parents[1]
_MANIFEST = _ROOT / "Builder" / "references" / "manifest.v2.json"
_EXPECTED_MANIFEST_SHA256 = "b947a08ef2455beb77d9481c4cbddc481ec6590f03746fd22affb03dd8b06f91"
_REFERENCE_ID = "mckay-lectures-differential-geometry-2022-text"
_CACHE_ROOT = _ROOT / ".cache" / "references"
_OUTPUT_ROOT = _ROOT / ".cache" / "builder" / "textbook-alignment" / "mckay-opening"
_PRIVATE_PACKET = _OUTPUT_ROOT / "packet.private.json"
_PUBLIC_SUMMARY = _OUTPUT_ROOT / "summary.public.json"


def _pages(value: str) -> tuple[int, ...]:
    try:
        result = tuple(int(item) for item in value.split(","))
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "pages must be comma-separated positive integers"
        ) from error
    if not result or any(page < 1 for page in result):
        raise argparse.ArgumentTypeError("pages must be comma-separated positive integers")
    return result


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--manifest", type=Path, default=_MANIFEST)
    parser.add_argument(
        "--expected-manifest-sha256",
        default=_EXPECTED_MANIFEST_SHA256,
        help="exact SHA-256 binding for the selected reference manifest",
    )
    parser.add_argument("--cache-root", type=Path, default=_CACHE_ROOT)
    parser.add_argument("--reference-id", default=_REFERENCE_ID)
    parser.add_argument("--pages", type=_pages, default=(1,))
    parser.add_argument("--max-excerpt-bytes", type=int, default=8192)
    parser.add_argument("--checkout-root", type=Path, default=_ROOT)
    parser.add_argument("--private-packet", type=Path, default=_PRIVATE_PACKET)
    parser.add_argument("--public-summary", type=Path, default=_PUBLIC_SUMMARY)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _build_parser().parse_args(argv)
    try:
        packet, summary = build_textbook_alignment_discovery(
            manifest_path=arguments.manifest,
            expected_manifest_sha256=arguments.expected_manifest_sha256,
            cache_root=arguments.cache_root,
            reference_id=arguments.reference_id,
            page_numbers=arguments.pages,
            max_excerpt_bytes=arguments.max_excerpt_bytes,
            confinement_root=arguments.checkout_root,
        )
        write_textbook_alignment_discovery(
            checkout_root=arguments.checkout_root,
            packet_path=arguments.private_packet,
            summary_path=arguments.public_summary,
            packet=packet,
            summary=summary,
        )
    except TextbookAlignmentError as error:
        print(f"textbook alignment discovery failed: {error}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(render_textbook_alignment_public_summary(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
