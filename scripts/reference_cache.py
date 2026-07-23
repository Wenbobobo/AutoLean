"""Verify the fixed local reference cache or perform operator-only acquisition."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from autolean_builder import (
    ReferenceCache,
    ReferenceCacheError,
    ReferenceManifestV1,
    render_reference_index,
)

_ROOT = Path(__file__).resolve().parents[1]
_TRACKED_MANIFEST = _ROOT / "Builder" / "references" / "manifest.v1.json"
_IGNORED_CACHE = _ROOT / ".cache" / "references"
_EXPECTED_MANIFEST_SHA256 = "881d535d62661ad496f8385964151830688a78d10123b59ff8326cb8a3a5a907"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=("list", "operator-fetch", "verify", "verify-all"),
    )
    parser.add_argument("reference_id", nargs="?")
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="redownload an allowlisted artifact; valid only for operator-fetch",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.action in {"operator-fetch", "verify"} and not args.reference_id:
        parser.error(f"{args.action} requires reference_id")
    if args.action in {"list", "verify-all"} and args.reference_id:
        parser.error(f"{args.action} does not accept reference_id")
    if args.refresh and args.action != "operator-fetch":
        parser.error("--refresh is only valid with operator-fetch")

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
        assert args.reference_id is not None
        verified_at = datetime.now(UTC)
        if args.action == "operator-fetch":
            result = cache.operator_fetch(args.reference_id, refresh=args.refresh)
            receipt = result.render_receipt(verified_at=verified_at)
        else:
            verified = cache.verify(args.reference_id)
            receipt = verified.render_receipt(verified_at=verified_at)
        sys.stdout.buffer.write(receipt)
    except ReferenceCacheError as error:
        parser.exit(2, f"reference-cache: {error}\n")


if __name__ == "__main__":
    main()
