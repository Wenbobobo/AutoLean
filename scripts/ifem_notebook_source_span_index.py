"""Render a local-only, digest-only cell index for an already locked iFEM source set.

This command performs no acquisition and has no model interface.  Its output is a locator aid
for Builder source alignment only; it cannot authorize semantic review, a statement freeze, or
Prover handoff.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from autolean_builder.ifem_notebook_source_span_index import (
    build_ifem_notebook_source_span_index,
    write_ifem_notebook_source_span_index,
)
from autolean_contracts import canonical_json_bytes

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CACHE_ROOT = ROOT / ".cache" / "references"
DEFAULT_SOURCE_LOCK = (
    DEFAULT_CACHE_ROOT
    / "ifem-interactive-fem-chapters-01-10-git-a4ab841-lock"
    / "source-lock.v1.json"
)
DEFAULT_OUTPUT = DEFAULT_SOURCE_LOCK.with_name("notebook-source-span-index.v1.json")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-lock", type=Path, default=DEFAULT_SOURCE_LOCK)
    parser.add_argument("--source-cache-root", type=Path, default=DEFAULT_CACHE_ROOT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    arguments = parser.parse_args(argv)
    index = build_ifem_notebook_source_span_index(
        source_lock_path=arguments.source_lock,
        source_cache_root=arguments.source_cache_root,
    )
    write_ifem_notebook_source_span_index(
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
                "index_canonical_sha256": index.canonical_sha256(),
                "model_egress_policy": index.model_egress_policy,
                "notebook_cell_count": index.notebook_cell_count,
                "notebook_file_count": index.source_lock.notebook_file_count,
                "semantic_review_state": index.semantic_review_state,
            }
        )
        + b"\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
