"""Materialize or verify one private local iFEM notebook Markdown-cell text projection.

The command accepts only an explicit digest-bound cell selector.  It has no network or model
interface, writes no public receipt, and cannot authorize semantic review, statement freeze, or
Prover handoff.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from autolean_builder import (
    IFEMNotebookMarkdownCellTextProjectionError,
    materialize_ifem_notebook_markdown_cell_text_projection,
    render_ifem_notebook_markdown_cell_text_summary,
    verify_ifem_notebook_markdown_cell_text_projection,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CACHE_ROOT = ROOT / ".cache" / "references"

EXPECTED_SOURCE_LOCK_SHA256 = "74eca6689fe69dcbf2f34ea524a99cacc2054c0a39cfecfb11887c29e13cf239"
EXPECTED_MANIFEST_CANDIDATE_SHA256 = (
    "4a5d859d77b606d6e485d98bd3e4afc41f6c566c6fb09f5e3dc2b2a539f18398"
)
EXPECTED_NOTEBOOK_INDEX_CANONICAL_SHA256 = (
    "3a0d39527481170a647cc8dc23917577e156f9ac42cb126f73759d784f8b03a7"
)
EXPECTED_SOURCE_FILE_COUNT = 13


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("action", choices=("materialize", "verify"))
    parser.add_argument("--source-path", required=True)
    parser.add_argument("--cell-index", type=int, required=True)
    parser.add_argument("--expected-cell-sha256", required=True)
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    namespace = _build_parser().parse_args(arguments)
    operation = (
        materialize_ifem_notebook_markdown_cell_text_projection
        if namespace.action == "materialize"
        else verify_ifem_notebook_markdown_cell_text_projection
    )
    try:
        result = operation(
            cache_root=DEFAULT_CACHE_ROOT,
            source_path=namespace.source_path,
            cell_index=namespace.cell_index,
            expected_cell_sha256=namespace.expected_cell_sha256,
            expected_source_lock_sha256=EXPECTED_SOURCE_LOCK_SHA256,
            expected_manifest_candidate_sha256=EXPECTED_MANIFEST_CANDIDATE_SHA256,
            expected_notebook_index_canonical_sha256=(EXPECTED_NOTEBOOK_INDEX_CANONICAL_SHA256),
            expected_source_file_count=EXPECTED_SOURCE_FILE_COUNT,
        )
    except IFEMNotebookMarkdownCellTextProjectionError as error:
        print(f"ifem-notebook-markdown-cell-text-projection: {error}", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(render_ifem_notebook_markdown_cell_text_summary(result.summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
