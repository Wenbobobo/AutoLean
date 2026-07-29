"""Render a local-only digest-only logical-heading index for locked iFEM ``intro.md``.

This command performs no acquisition and has no model interface.  Its output is
only a Builder source-alignment locator aid; it cannot authorize review, a
statement freeze, or Prover handoff.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from autolean_builder.ifem_markdown_source_span_index import (
    build_ifem_markdown_source_span_index,
    write_ifem_markdown_source_span_index,
)
from autolean_contracts import canonical_json_bytes

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CACHE_ROOT = ROOT / ".cache" / "references"
DEFAULT_SOURCE_LOCK = (
    DEFAULT_CACHE_ROOT
    / "ifem-interactive-fem-chapters-01-10-git-a4ab841-lock"
    / "source-lock.v1.json"
)
DEFAULT_OUTPUT = DEFAULT_SOURCE_LOCK.with_name("opening-markdown-source-span-index.v1.json")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-lock", type=Path, default=DEFAULT_SOURCE_LOCK)
    parser.add_argument("--source-cache-root", type=Path, default=DEFAULT_CACHE_ROOT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    arguments = parser.parse_args(argv)
    index = build_ifem_markdown_source_span_index(
        source_lock_path=arguments.source_lock,
        source_cache_root=arguments.source_cache_root,
    )
    write_ifem_markdown_source_span_index(
        cache_root=arguments.source_cache_root,
        output_path=arguments.output,
        index=index,
    )
    sys.stdout.buffer.write(
        canonical_json_bytes(
            {
                "artifact_kind": index.artifact_kind,
                "contains_model_input": index.contains_model_input,
                "contains_source_text": index.contains_source_text,
                "contract_freeze": index.contract_freeze,
                "index_canonical_sha256": index.canonical_sha256(),
                "markdown_heading_count": index.markdown_heading_count,
                "model_egress_policy": index.model_egress_policy,
                "prover_handoff": index.prover_handoff,
                "semantic_review_state": index.semantic_review_state,
                "source_file_count": index.source_lock.source_file_count,
            }
        )
        + b"\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
