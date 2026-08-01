"""Materialize or verify the public source-text-free iFEM structural role corpus."""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from autolean_builder.ifem_candidate_dependency_graph import (  # noqa: E402
    build_ifem_candidate_dependency_graph,
    render_ifem_candidate_dependency_graph,
)
from autolean_builder.ifem_structural_calibration import (  # noqa: E402
    build_ifem_structural_calibration_catalog,
)
from autolean_builder.ifem_structural_role_probes import (  # noqa: E402
    IFEMStructuralRoleProbeCorpusV1,
    IFEMStructuralRoleProbeError,
    build_ifem_structural_role_probe_corpus,
    load_ifem_structural_role_probe_corpus,
    render_ifem_structural_role_probe_corpus,
)
from autolean_contracts import canonical_json_bytes  # noqa: E402

from scripts.ifem_candidate_dependency_graph import (  # noqa: E402
    DEFAULT_CENSUS_PLAN,
    DEFAULT_CENSUS_RESULT,
    DEFAULT_DISCOVERY_MANIFEST,
    DEFAULT_NOTEBOOK_INDEX,
    DEFAULT_OPENING_INDEX,
    DEFAULT_SOURCE_LOCK,
    DEFAULT_SOURCE_STAGING_ROOT,
    DEFAULT_STAGING_MANIFEST,
)

DEFAULT_OUTPUT = (
    ROOT / "Builder" / "pilots" / "discovery" / "ifem-structural-role-probe-corpus.v1.json"
)
TRACKED_FILE_SHA256 = "b0b232a7cd062b47bf5b07efb3158bd068d1988e5285cd0fd964a5855856f617"
TRACKED_CONTENT_SHA256 = "a449b48f3544dc7dfe748eb76abe423e0a6c66372dd1f58c5cdb7221b1d59fb8"
TRACKED_GRAPH_FILE_SHA256 = "e6442bfe1cc5305a3d26972c23c70a08029f8cde387dc1b58088d918632cd3af"
TRACKED_GRAPH_CONTENT_SHA256 = "ba9b246805a4b94ea9f0b02898a772114e495fc8dc12c783b7388b519470a71d"


def build_source_bound_corpus() -> IFEMStructuralRoleProbeCorpusV1:
    """Rebuild the redacted corpus from operator-local locked source metadata."""

    graph = build_ifem_candidate_dependency_graph(
        workspace_root=ROOT,
        source_staging_root=DEFAULT_SOURCE_STAGING_ROOT,
        staging_manifest_path=DEFAULT_STAGING_MANIFEST,
        source_lock_path=DEFAULT_SOURCE_LOCK,
        opening_markdown_index_path=DEFAULT_OPENING_INDEX,
        notebook_index_path=DEFAULT_NOTEBOOK_INDEX,
        discovery_manifest_path=DEFAULT_DISCOVERY_MANIFEST,
        census_plan_path=DEFAULT_CENSUS_PLAN,
        census_result_path=DEFAULT_CENSUS_RESULT,
    )
    graph_bytes = render_ifem_candidate_dependency_graph(graph)
    if (
        hashlib.sha256(graph_bytes).hexdigest() != TRACKED_GRAPH_FILE_SHA256
        or graph.content_sha256 != TRACKED_GRAPH_CONTENT_SHA256
    ):
        raise IFEMStructuralRoleProbeError(
            "rebuilt candidate graph differs from the tracked revision; define a successor"
        )
    catalog = build_ifem_structural_calibration_catalog(graph)
    return build_ifem_structural_role_probe_corpus(catalog=catalog, graph=graph)


def _unresolved_absolute_path(path: Path) -> Path:
    """Make a path absolute without dereferencing a final symlink or junction."""

    return Path(os.path.abspath(os.fspath(path)))


def _load_exact_corpus(
    path: Path,
    *,
    expected_file_sha256: str,
    expected_content_sha256: str,
) -> IFEMStructuralRoleProbeCorpusV1:
    return load_ifem_structural_role_probe_corpus(
        path,
        expected_file_sha256=expected_file_sha256,
        expected_content_sha256=expected_content_sha256,
    )


def _write_once(
    path: Path,
    content: bytes,
    *,
    expected_content_sha256: str,
) -> IFEMStructuralRoleProbeCorpusV1:
    """Atomically install exact bytes without replacing an existing pathname."""

    path.parent.mkdir(parents=True, exist_ok=True)
    expected_file_sha256 = hashlib.sha256(content).hexdigest()
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
        )
    except OSError as error:
        raise IFEMStructuralRoleProbeError(
            "structural role corpus temporary output could not be created"
        ) from error
    temporary_path = Path(temporary_name)
    try:
        try:
            output = os.fdopen(descriptor, "wb")
        except BaseException:
            os.close(descriptor)
            raise
        with output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary_path, path, follow_symlinks=False)
        except FileExistsError:
            pass
        except (NotImplementedError, OSError) as error:
            raise IFEMStructuralRoleProbeError(
                "structural role corpus could not be atomically installed"
            ) from error
        corpus = _load_exact_corpus(
            path,
            expected_file_sha256=expected_file_sha256,
            expected_content_sha256=expected_content_sha256,
        )
        if render_ifem_structural_role_probe_corpus(corpus) != content:
            raise IFEMStructuralRoleProbeError(
                "structural role corpus output already contains different bytes"
            )
        return corpus
    finally:
        temporary_path.unlink(missing_ok=True)


def parse_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    materialize = subparsers.add_parser(
        "materialize",
        help="rebuild the corpus from the operator-local locked source graph",
    )
    materialize.add_argument("--out", type=Path, default=DEFAULT_OUTPUT)
    inspect = subparsers.add_parser(
        "inspect",
        help="verify an existing corpus against independently supplied hashes",
    )
    inspect.add_argument("--path", type=Path, default=DEFAULT_OUTPUT)
    inspect.add_argument(
        "--expected-file-sha256",
        default=TRACKED_FILE_SHA256,
        help="expected SHA-256 of the exact canonical file bytes",
    )
    inspect.add_argument(
        "--expected-content-sha256",
        default=TRACKED_CONTENT_SHA256,
        help="expected canonical content SHA-256 embedded in the corpus",
    )
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    namespace = parse_arguments(arguments)
    if namespace.command == "materialize":
        corpus = build_source_bound_corpus()
        rendered = render_ifem_structural_role_probe_corpus(corpus)
        if (
            hashlib.sha256(rendered).hexdigest() != TRACKED_FILE_SHA256
            or corpus.content_sha256 != TRACKED_CONTENT_SHA256
        ):
            raise IFEMStructuralRoleProbeError(
                "rebuilt corpus differs from the tracked revision; define and pin a successor"
            )
        path = _unresolved_absolute_path(namespace.out)
        corpus = _write_once(
            path,
            rendered,
            expected_content_sha256=TRACKED_CONTENT_SHA256,
        )
    else:
        path = _unresolved_absolute_path(namespace.path)
        corpus = _load_exact_corpus(
            path,
            expected_file_sha256=namespace.expected_file_sha256,
            expected_content_sha256=namespace.expected_content_sha256,
        )
    rendered = render_ifem_structural_role_probe_corpus(corpus)
    payload = {
        "contains_source_text": corpus.contains_source_text,
        "content_sha256": corpus.content_sha256,
        "file_sha256": hashlib.sha256(rendered).hexdigest(),
        "graph_content_sha256": TRACKED_GRAPH_CONTENT_SHA256,
        "graph_file_sha256": TRACKED_GRAPH_FILE_SHA256,
        "path": path.name,
    }
    sys.stdout.buffer.write(canonical_json_bytes(payload) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
