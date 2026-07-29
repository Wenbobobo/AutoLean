"""Render the local-only iFEM candidate dependency graph.

The command performs no download, model call, Lean query, semantic review,
statement freeze, or Prover handoff.  It verifies the supplied local source
tree only to bind existing digest-only discovery artifacts, then writes a
redacted candidate graph below ``.cache/references``.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from autolean_builder.ifem_candidate_dependency_graph import (
    IFEMCandidateDependencyGraphError,
    build_ifem_candidate_dependency_graph,
    write_ifem_candidate_dependency_graph,
)
from autolean_contracts import canonical_json_bytes

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CACHE_ROOT = ROOT / ".cache" / "references"
DEFAULT_LOCK_DIRECTORY = DEFAULT_CACHE_ROOT / "ifem-interactive-fem-chapters-01-10-git-a4ab841-lock"
DEFAULT_SOURCE_STAGING_ROOT = ROOT / ".cache" / "ifem-connector-staging-a4ab841-20260729-b"
DEFAULT_STAGING_MANIFEST = (
    ROOT / ".cache" / "ifem-connector-staging-manifest-a4ab841-20260729-b.json"
)
DEFAULT_SOURCE_LOCK = DEFAULT_LOCK_DIRECTORY / "source-lock.v1.json"
DEFAULT_OPENING_INDEX = DEFAULT_LOCK_DIRECTORY / "opening-markdown-source-span-index.v1.json"
DEFAULT_NOTEBOOK_INDEX = DEFAULT_LOCK_DIRECTORY / "notebook-source-span-index.v1.json"
DEFAULT_DISCOVERY_MANIFEST = (
    ROOT / "Builder" / "pilots" / "discovery" / "phase-2-active-lanes.v1.json"
)
DEFAULT_CENSUS_PLAN = (
    ROOT / "Builder" / "pilots" / "discovery" / "ifem-coercive-prerequisite-census-plan.v1.json"
)
DEFAULT_CENSUS_RESULT = ROOT / ".cache" / "ifem-prerequisite-census-not-run-main-r4.v1.json"
DEFAULT_OUTPUT = DEFAULT_LOCK_DIRECTORY / "ifem-candidate-dependency-graph.v1.json"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-root", type=Path, default=ROOT)
    parser.add_argument("--source-staging-root", type=Path, default=DEFAULT_SOURCE_STAGING_ROOT)
    parser.add_argument("--staging-manifest", type=Path, default=DEFAULT_STAGING_MANIFEST)
    parser.add_argument("--source-lock", type=Path, default=DEFAULT_SOURCE_LOCK)
    parser.add_argument("--opening-markdown-index", type=Path, default=DEFAULT_OPENING_INDEX)
    parser.add_argument("--notebook-index", type=Path, default=DEFAULT_NOTEBOOK_INDEX)
    parser.add_argument("--discovery-manifest", type=Path, default=DEFAULT_DISCOVERY_MANIFEST)
    parser.add_argument("--census-plan", type=Path, default=DEFAULT_CENSUS_PLAN)
    parser.add_argument("--census-result", type=Path, default=DEFAULT_CENSUS_RESULT)
    parser.add_argument("--cache-root", type=Path, default=DEFAULT_CACHE_ROOT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    arguments = parser.parse_args(argv)
    try:
        graph = build_ifem_candidate_dependency_graph(
            workspace_root=arguments.workspace_root,
            source_staging_root=arguments.source_staging_root,
            staging_manifest_path=arguments.staging_manifest,
            source_lock_path=arguments.source_lock,
            opening_markdown_index_path=arguments.opening_markdown_index,
            notebook_index_path=arguments.notebook_index,
            discovery_manifest_path=arguments.discovery_manifest,
            census_plan_path=arguments.census_plan,
            census_result_path=arguments.census_result,
        )
        write_ifem_candidate_dependency_graph(
            cache_root=arguments.cache_root,
            output_path=arguments.output,
            graph=graph,
        )
    except IFEMCandidateDependencyGraphError as error:
        print(f"ifem-candidate-dependency-graph: {error}", file=sys.stderr)
        return 2
    declared_count = sum(
        edge.edge_kind == "declared_candidate_dependency" for edge in graph.candidate_edges
    )
    heuristic_count = len(graph.candidate_edges) - declared_count
    sys.stdout.buffer.write(
        canonical_json_bytes(
            {
                "artifact_kind": graph.artifact_kind,
                "candidate_edge_count": len(graph.candidate_edges),
                "candidate_node_count": len(graph.candidate_nodes),
                "contains_model_input": graph.contains_model_input,
                "contains_source_text": graph.contains_source_text,
                "content_sha256": graph.content_sha256,
                "declared_candidate_edge_count": declared_count,
                "heuristic_candidate_edge_count": heuristic_count,
                "prover_handoff_allowed": graph.authority.prover_handoff_allowed,
                "semantic_review_completed": graph.authority.semantic_review_completed,
            }
        )
        + b"\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
