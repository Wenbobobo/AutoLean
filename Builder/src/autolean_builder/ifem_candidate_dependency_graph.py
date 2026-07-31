"""Build a local-only, non-authoritative iFEM candidate dependency graph.

The graph is a source-alignment and planning artifact for the Phase-2 iFEM
discovery lane.  It binds the already locked local source tree, its two
digest-only indexes, and the existing discovery/census artifacts.  It keeps
only content hashes, stable source-span identifiers, node metadata, and
explicitly labelled candidate edges.

It is deliberately *not* a statement extractor.  In particular, it does not
create a ``StatementContractV1``, a FormalGraph, a Prover task, a semantic
approval, or a freeze decision.  The only two edge sources are the declared
discovery denominator and a low-confidence overlap heuristic over already
declared Lean-name candidates.  Neither source establishes a mathematical
dependency or a Mathlib mapping.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from collections.abc import Iterable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Final, Literal, Never, cast

from autolean_contracts import StableIdentifierV1, canonical_json_bytes
from autolean_contracts.base import ContractModel
from pydantic import Field, model_validator

from .discovery_manifest import (
    DiscoveryLaneManifestV1,
    DiscoveryLaneV1,
)
from .ifem_markdown_source_span_index import IFEMMarkdownSourceSpanIndexV1
from .ifem_notebook_source_span_index import IFEMNotebookSourceSpanIndexV1
from .ifem_prerequisite_census import (
    IFEMPrerequisiteCensusError,
    IFEMPrerequisiteCensusPlanV1,
    IFEMPrerequisiteCensusResultV1,
    IFEMQueryExecutionStateV1,
    validate_result_against_plan,
)

ROOT = Path(__file__).resolve().parents[3]
IFEM_LANE_ID: Final[Literal["ifem-coercive-galerkin"]] = "ifem-coercive-galerkin"
IFEM_SOURCE_LOCK_SCHEMA: Final[Literal["autolean.ifem-source-lock.v1"]] = (
    "autolean.ifem-source-lock.v1"
)
IFEM_STAGING_MANIFEST_SCHEMA: Final[Literal["autolean.ifem-connector-staging.v1"]] = (
    "autolean.ifem-connector-staging.v1"
)
IFEM_CANDIDATE_GRAPH_SCHEMA: Final[Literal["autolean.ifem-candidate-dependency-graph.v1"]] = (
    "autolean.ifem-candidate-dependency-graph.v1"
)
IFEM_CANDIDATE_GRAPH_ARTIFACT_KIND: Final[Literal["local_only_candidate_dependency_graph"]] = (
    "local_only_candidate_dependency_graph"
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SHA1 = re.compile(r"^[0-9a-f]{40}$")


class IFEMCandidateDependencyGraphError(ValueError):
    """A local iFEM graph input drifted or tried to cross an authority boundary."""


class IFEMCandidateNodeIdV1(StrEnum):
    """The intentional, source-locked node vocabulary for this v1 discovery graph."""

    REAL_SCALAR_FIELD = "ifem-real-scalar-field"
    NORMED_VECTOR_SPACE = "ifem-normed-vector-space"
    INNER_PRODUCT_SPACE = "ifem-inner-product-space"
    COMPLETE_INNER_PRODUCT_SPACE = "ifem-complete-inner-product-space"
    INDUCED_NORM = "ifem-induced-norm"
    CONTINUOUS_LINEAR_FUNCTIONAL = "ifem-continuous-linear-functional"
    DUAL_NORM = "ifem-dual-norm"
    CONTINUOUS_BILINEAR_FORM = "ifem-continuous-bilinear-form"
    CONTINUITY_BOUND = "ifem-continuity-bound"
    COERCIVITY_PREDICATE = "ifem-coercivity-predicate"
    INDUCED_DUAL_OPERATOR = "ifem-induced-dual-operator"
    OPERATOR_NORM_BOUND = "ifem-operator-norm-bound"
    SUBMODULE = "ifem-submodule"
    CLOSED_SUBSPACE = "ifem-closed-subspace"
    INHERITED_COMPLETE_STRUCTURE = "ifem-inherited-complete-structure"
    RESTRICTED_BILINEAR_FORM = "ifem-restricted-bilinear-form"
    RESTRICTED_FUNCTIONAL = "ifem-restricted-functional"
    RESTRICTED_CONTINUITY = "ifem-restricted-continuity"
    RESTRICTED_COERCIVITY = "ifem-restricted-coercivity"
    LAX_MILGRAM_SOLUTION_INTERFACE = "ifem-lax-milgram-solution-interface"
    GALERKIN_SOLUTION_INTERFACE = "ifem-galerkin-solution-interface"
    POISSON_GALERKIN_OPENING_EXAMPLE = "ifem-poisson-galerkin-opening-example"
    PROPER_SUBSPACE_EXAMPLE = "ifem-proper-subspace-example"
    ZERO_FORM_COUNTEREXAMPLE = "ifem-zero-form-counterexample"
    CEA_QUASI_OPTIMALITY_INFINUM = "ifem-cea-quasi-optimality-infimum"


class IFEMCandidateNodeAmbiguityFlagV1(StrEnum):
    """Closed non-semantic ambiguity vocabulary; arbitrary prose is not serializable."""

    ANCHOR_ASSIGNMENT_NOT_SEMANTIC_MAPPING = "anchor_assignment_not_semantic_mapping"
    MATHEMATICAL_DEPENDENCY_NOT_VERIFIED = "mathematical_dependency_not_verified"
    SOURCE_INTERPRETATION_NOT_PERFORMED = "source_interpretation_not_performed"


class IFEMCandidateNodeGapFlagV1(StrEnum):
    """Closed non-authoritative gap vocabulary for this graph revision."""

    SEMANTIC_REVIEW_NOT_PERFORMED = "semantic_review_not_performed"
    STATEMENT_CONTRACT_NOT_CREATED = "statement_contract_not_created"
    FORMAL_MAPPING_NOT_OBSERVED = "formal_mapping_not_observed"
    PROVER_HANDOFF_FORBIDDEN = "prover_handoff_forbidden"
    NOT_IN_PREREQUISITE_CENSUS_QUERY_PLAN = "not_in_prerequisite_census_query_plan"


@dataclass(frozen=True, slots=True)
class _LockedSourceFile:
    path: str
    reference_id: str
    sha256: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class _VerifiedSourceLock:
    sha256: str
    source_revision: str
    license_sha256: str
    license_blob_sha1: str
    source_files: tuple[_LockedSourceFile, ...]


class IFEMCandidateGraphSourceBindingV1(ContractModel):
    """Digest-only binding to every local input used by this graph."""

    source_lock_sha256: str = Field(pattern=_SHA256.pattern)
    source_revision: str = Field(pattern=_SHA1.pattern)
    source_file_count: int = Field(ge=1)
    staged_file_count: int = Field(ge=1)
    opening_markdown_index_sha256: str = Field(pattern=_SHA256.pattern)
    opening_markdown_span_count: int = Field(ge=1)
    notebook_index_sha256: str = Field(pattern=_SHA256.pattern)
    notebook_cell_count: int = Field(ge=1)
    staging_manifest_sha256: str = Field(pattern=_SHA256.pattern)
    discovery_manifest_sha256: str = Field(pattern=_SHA256.pattern)
    census_plan_content_sha256: str = Field(pattern=_SHA256.pattern)
    census_result_sha256: str = Field(pattern=_SHA256.pattern)


class IFEMCandidateGraphAuthorityBoundaryV1(ContractModel):
    """Every authority that this discovery artifact is forbidden to exercise."""

    source_egress_allowed: Literal[False] = False
    rights_adjudication_completed: Literal[False] = False
    semantic_review_completed: Literal[False] = False
    statement_contract_created: Literal[False] = False
    formal_graph_created: Literal[False] = False
    execution_graph_created: Literal[False] = False
    proof_task_created: Literal[False] = False
    freeze_allowed: Literal[False] = False
    prover_handoff_allowed: Literal[False] = False
    promotion_allowed: Literal[False] = False


class IFEMCandidateGraphLayersV1(ContractModel):
    """State the three graph boundaries without creating the other two graphs."""

    mathematical_graph: Literal["candidate_dependency_hypotheses_only"] = (
        "candidate_dependency_hypotheses_only"
    )
    formal_graph: Literal["not_created"] = "not_created"
    execution_graph: Literal["not_created"] = "not_created"


class IFEMCandidateNodeV1(ContractModel):
    """A discovery node with a deterministic, non-semantic source anchor."""

    node_id: IFEMCandidateNodeIdV1
    candidate_node_kind: Literal["definition", "prerequisite_theorem", "example", "terminal_target"]
    source_order: int = Field(ge=1)
    included_in_prerequisite_denominator: bool
    source_anchor_id: StableIdentifierV1
    source_anchor_kind: Literal["markdown_heading", "notebook_cell"]
    source_anchor_assignment: Literal["deterministic_index_position_not_semantic_mapping"] = (
        "deterministic_index_position_not_semantic_mapping"
    )
    census_query_present: bool
    candidate_declaration_count: int = Field(ge=0)
    candidate_declaration_set_sha256: str | None = Field(default=None, pattern=_SHA256.pattern)
    ambiguity_flags: tuple[IFEMCandidateNodeAmbiguityFlagV1, ...] = Field(min_length=1)
    gap_flags: tuple[IFEMCandidateNodeGapFlagV1, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_census_projection(self) -> IFEMCandidateNodeV1:
        if self.source_anchor_id.namespace not in {
            "ifem.markdown-source-span",
            "ifem.notebook-source-span",
        }:
            raise ValueError("candidate node source anchor has an unexpected namespace")
        expected_anchor_namespace = {
            "markdown_heading": "ifem.markdown-source-span",
            "notebook_cell": "ifem.notebook-source-span",
        }[self.source_anchor_kind]
        if self.source_anchor_id.namespace != expected_anchor_namespace:
            raise ValueError("candidate node source-anchor kind disagrees with its identifier")
        if self.census_query_present:
            if (
                self.candidate_declaration_count < 1
                or self.candidate_declaration_set_sha256 is None
            ):
                raise ValueError("a census query node lacks its redacted candidate binding")
        elif (
            self.candidate_declaration_count != 0
            or self.candidate_declaration_set_sha256 is not None
        ):
            raise ValueError("a non-query node carries a fabricated census candidate binding")
        expected_ambiguities = tuple(sorted(IFEMCandidateNodeAmbiguityFlagV1, key=str))
        if self.ambiguity_flags != expected_ambiguities:
            raise ValueError("candidate-node ambiguity flags differ from the closed vocabulary")
        expected_gaps = {
            IFEMCandidateNodeGapFlagV1.SEMANTIC_REVIEW_NOT_PERFORMED,
            IFEMCandidateNodeGapFlagV1.STATEMENT_CONTRACT_NOT_CREATED,
            IFEMCandidateNodeGapFlagV1.FORMAL_MAPPING_NOT_OBSERVED,
            IFEMCandidateNodeGapFlagV1.PROVER_HANDOFF_FORBIDDEN,
        }
        if not self.census_query_present:
            expected_gaps.add(IFEMCandidateNodeGapFlagV1.NOT_IN_PREREQUISITE_CENSUS_QUERY_PLAN)
        if self.gap_flags != tuple(sorted(expected_gaps, key=str)):
            raise ValueError("candidate-node gap flags differ from the closed vocabulary")
        return self


class IFEMCandidateDependencyEdgeV1(ContractModel):
    """One explicitly non-authoritative candidate-dependency relation."""

    source_node_id: IFEMCandidateNodeIdV1
    target_node_id: IFEMCandidateNodeIdV1
    edge_kind: Literal["declared_candidate_dependency", "heuristic_candidate_declaration_overlap"]
    provenance: Literal[
        "discovery_denominator_declared_unreviewed",
        "census_candidate_declaration_overlap_unreviewed",
    ]
    confidence: Literal["declared_unreviewed", "low"]
    shared_candidate_declaration_count: int = Field(ge=0)
    shared_candidate_declaration_set_sha256: str | None = Field(
        default=None, pattern=_SHA256.pattern
    )
    semantic_dependency_claimed: Literal[False] = False
    formal_mapping_claimed: Literal[False] = False

    @model_validator(mode="after")
    def validate_edge_evidence(self) -> IFEMCandidateDependencyEdgeV1:
        if self.source_node_id == self.target_node_id:
            raise ValueError("candidate dependency edges cannot be self-referential")
        declared = self.edge_kind == "declared_candidate_dependency"
        if declared:
            if (
                self.provenance != "discovery_denominator_declared_unreviewed"
                or self.confidence != "declared_unreviewed"
                or self.shared_candidate_declaration_count != 0
                or self.shared_candidate_declaration_set_sha256 is not None
            ):
                raise ValueError("declared edge carries heuristic-only evidence")
        elif (
            self.provenance != "census_candidate_declaration_overlap_unreviewed"
            or self.confidence != "low"
            or self.shared_candidate_declaration_count < 1
            or self.shared_candidate_declaration_set_sha256 is None
        ):
            raise ValueError("heuristic edge lacks its redacted overlap evidence")
        return self


class IFEMCandidateDependencyGraphV1(ContractModel):
    """A replayable discovery graph that is deliberately not a proof input."""

    schema_version: Literal["autolean.ifem-candidate-dependency-graph.v1"] = (
        IFEM_CANDIDATE_GRAPH_SCHEMA
    )
    artifact_kind: Literal["local_only_candidate_dependency_graph"] = (
        IFEM_CANDIDATE_GRAPH_ARTIFACT_KIND
    )
    lane_id: Literal["ifem-coercive-galerkin"] = IFEM_LANE_ID
    source_binding: IFEMCandidateGraphSourceBindingV1
    census_execution_state: Literal["not_run"] = "not_run"
    graph_layers: IFEMCandidateGraphLayersV1 = Field(default_factory=IFEMCandidateGraphLayersV1)
    authority: IFEMCandidateGraphAuthorityBoundaryV1 = Field(
        default_factory=IFEMCandidateGraphAuthorityBoundaryV1
    )
    contains_source_text: Literal[False] = False
    contains_model_input: Literal[False] = False
    candidate_nodes: tuple[IFEMCandidateNodeV1, ...] = Field(min_length=20, max_length=40)
    candidate_edges: tuple[IFEMCandidateDependencyEdgeV1, ...]
    content_sha256: str = Field(pattern=_SHA256.pattern)

    @model_validator(mode="after")
    def validate_graph(self) -> IFEMCandidateDependencyGraphV1:
        node_by_id = {node.node_id: node for node in self.candidate_nodes}
        if len(node_by_id) != len(self.candidate_nodes):
            raise ValueError("candidate graph node identifiers must be unique")
        source_orders = [node.source_order for node in self.candidate_nodes]
        if source_orders != list(range(1, len(self.candidate_nodes) + 1)):
            raise ValueError("candidate graph source order must remain contiguous")
        if len({node.source_anchor_id for node in self.candidate_nodes}) != len(
            self.candidate_nodes
        ):
            raise ValueError("candidate graph source anchors must be unique")
        edge_keys: list[tuple[str, str, str]] = []
        for edge in self.candidate_edges:
            if edge.source_node_id not in node_by_id or edge.target_node_id not in node_by_id:
                raise ValueError("candidate graph edge names an unknown node")
            if (
                node_by_id[edge.source_node_id].source_order
                >= node_by_id[edge.target_node_id].source_order
            ):
                raise ValueError("candidate graph edges must point forward in source order")
            edge_keys.append((edge.edge_kind, edge.source_node_id, edge.target_node_id))
        if len(edge_keys) != len(set(edge_keys)):
            raise ValueError("candidate graph edges must be unique by kind and endpoints")
        if edge_keys != sorted(edge_keys):
            raise ValueError("candidate graph edges must use canonical order")
        if self.content_sha256 != self.computed_content_sha256():
            raise ValueError("candidate graph content hash does not match its payload")
        return self

    def content_payload(self) -> dict[str, object]:
        payload = self.model_dump(mode="json", exclude={"content_sha256"})
        return cast(dict[str, object], payload)

    def computed_content_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.content_payload())).hexdigest()

    def assert_not_routable(self) -> Never:
        raise IFEMCandidateDependencyGraphError(
            "local-only iFEM candidate graphs cannot create a statement contract, "
            "freeze a statement, create a FormalGraph, or hand work to Prover"
        )

    def freeze_statement(self) -> Never:
        self.assert_not_routable()

    def handoff_to_prover(self) -> Never:
        self.assert_not_routable()


def build_ifem_candidate_dependency_graph(
    *,
    workspace_root: Path = ROOT,
    source_staging_root: Path,
    staging_manifest_path: Path,
    source_lock_path: Path,
    opening_markdown_index_path: Path,
    notebook_index_path: Path,
    discovery_manifest_path: Path,
    census_plan_path: Path,
    census_result_path: Path,
) -> IFEMCandidateDependencyGraphV1:
    """Replay local metadata and return a redacted candidate graph.

    Every input path must resolve below ``workspace_root``.  The function reads
    locked source bytes only to verify the source lock and staging manifest; no
    source bytes are returned, persisted, or supplied to a model.
    """

    root = _resolve_existing_directory(workspace_root, workspace_root, label="workspace root")
    staging_root = _resolve_existing_directory(
        source_staging_root, root, label="iFEM source staging root"
    )
    staging_manifest_file = _resolve_existing_file(
        staging_manifest_path, root, label="iFEM staging manifest"
    )
    source_lock_file = _resolve_existing_file(source_lock_path, root, label="iFEM source lock")
    markdown_index_file = _resolve_existing_file(
        opening_markdown_index_path, root, label="iFEM Markdown index"
    )
    notebook_index_file = _resolve_existing_file(
        notebook_index_path, root, label="iFEM notebook index"
    )
    discovery_manifest_file = _resolve_existing_file(
        discovery_manifest_path, root, label="iFEM discovery manifest"
    )
    census_plan_file = _resolve_existing_file(census_plan_path, root, label="iFEM census plan")
    census_result_file = _resolve_existing_file(
        census_result_path, root, label="iFEM census result"
    )

    lock_payload, lock_bytes = _load_json_object(source_lock_file, label="iFEM source lock")
    source_lock = _parse_source_lock(lock_payload, lock_bytes)
    staging_payload, staging_bytes = _load_json_object(
        staging_manifest_file, label="iFEM staging manifest"
    )
    staged_file_count = _verify_staging_tree(
        staging_root=staging_root,
        staging_payload=staging_payload,
        source_lock=source_lock,
    )
    markdown_payload, markdown_bytes = _load_json_object(
        markdown_index_file, label="iFEM Markdown index"
    )
    notebook_payload, notebook_bytes = _load_json_object(
        notebook_index_file, label="iFEM notebook index"
    )
    markdown_index = _validate_markdown_index(markdown_payload)
    notebook_index = _validate_notebook_index(notebook_payload)
    _validate_indexes_against_source_lock(
        source_lock=source_lock,
        markdown_index=markdown_index,
        notebook_index=notebook_index,
    )
    lane_manifest, discovery_manifest_bytes = _load_discovery_manifest(discovery_manifest_file)
    census_plan = _validate_census_plan(census_plan_file)
    census_result = _validate_census_result(census_result_file)
    lane = _validate_discovery_and_census(
        lane_manifest=lane_manifest,
        source_lock=source_lock,
        census_plan=census_plan,
        census_result=census_result,
    )
    source_binding = IFEMCandidateGraphSourceBindingV1(
        source_lock_sha256=source_lock.sha256,
        source_revision=source_lock.source_revision,
        source_file_count=len(source_lock.source_files),
        staged_file_count=staged_file_count,
        opening_markdown_index_sha256=_sha256(markdown_bytes),
        opening_markdown_span_count=markdown_index.markdown_heading_count,
        notebook_index_sha256=_sha256(notebook_bytes),
        notebook_cell_count=notebook_index.notebook_cell_count,
        staging_manifest_sha256=_sha256(staging_bytes),
        discovery_manifest_sha256=_sha256(discovery_manifest_bytes),
        census_plan_content_sha256=census_plan.content_sha256,
        census_result_sha256=census_result.content_sha256,
    )
    nodes = _build_candidate_nodes(
        lane=lane,
        census_plan=census_plan,
        markdown_index=markdown_index,
        notebook_index=notebook_index,
    )
    edges = _build_candidate_edges(lane=lane, census_plan=census_plan)
    payload: dict[str, object] = {
        "schema_version": IFEM_CANDIDATE_GRAPH_SCHEMA,
        "artifact_kind": IFEM_CANDIDATE_GRAPH_ARTIFACT_KIND,
        "lane_id": IFEM_LANE_ID,
        "source_binding": source_binding.model_dump(mode="json"),
        "census_execution_state": "not_run",
        "graph_layers": IFEMCandidateGraphLayersV1().model_dump(mode="json"),
        "authority": IFEMCandidateGraphAuthorityBoundaryV1().model_dump(mode="json"),
        "contains_source_text": False,
        "contains_model_input": False,
        "candidate_nodes": [node.model_dump(mode="json") for node in nodes],
        "candidate_edges": [edge.model_dump(mode="json") for edge in edges],
    }
    payload["content_sha256"] = _sha256(canonical_json_bytes(payload))
    try:
        return IFEMCandidateDependencyGraphV1.model_validate(payload)
    except ValueError as error:
        raise IFEMCandidateDependencyGraphError(
            f"iFEM candidate graph did not validate: {error}"
        ) from error


def render_ifem_candidate_dependency_graph(graph: IFEMCandidateDependencyGraphV1) -> bytes:
    """Serialize a revalidated graph, closing ``model_construct`` bypasses at output."""

    try:
        verified = IFEMCandidateDependencyGraphV1.model_validate(graph.model_dump(mode="json"))
    except ValueError as error:
        raise IFEMCandidateDependencyGraphError(
            "cannot render an invalid or model-constructed candidate graph"
        ) from error
    return canonical_json_bytes(verified) + b"\n"


def _is_link_or_reparse(path: Path, metadata: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    file_attributes = getattr(metadata, "st_file_attributes", 0)
    return (
        stat.S_ISLNK(metadata.st_mode) or bool(file_attributes & reparse_flag) or path.is_symlink()
    )


def _physical_parent_identities(path: Path) -> tuple[tuple[int, int], ...]:
    identities: list[tuple[int, int]] = []
    for parent in path.parents:
        metadata = parent.stat(follow_symlinks=False)
        if _is_link_or_reparse(parent, metadata) or not stat.S_ISDIR(metadata.st_mode):
            raise IFEMCandidateDependencyGraphError(
                "candidate graph parent chain must contain only physical directories"
            )
        identities.append((metadata.st_dev, metadata.st_ino))
    return tuple(identities)


def load_ifem_candidate_dependency_graph(
    path: Path,
    *,
    expected_file_sha256: str,
    expected_content_sha256: str,
) -> IFEMCandidateDependencyGraphV1:
    """Load one exact source-text-free graph projection without source replay."""

    if not isinstance(path, Path):
        raise IFEMCandidateDependencyGraphError("candidate graph path must be a Path")
    try:
        parents_before = _physical_parent_identities(path)
        before = path.lstat()
        if _is_link_or_reparse(path, before) or not stat.S_ISREG(before.st_mode):
            raise IFEMCandidateDependencyGraphError(
                "candidate graph must be an unlinked regular file"
            )
        raw = path.read_bytes()
        after = path.lstat()
        parents_after = _physical_parent_identities(path)
    except OSError as error:
        raise IFEMCandidateDependencyGraphError("candidate graph is unavailable") from error
    if (
        _is_link_or_reparse(path, after)
        or not stat.S_ISREG(after.st_mode)
        or (before.st_dev, before.st_ino, before.st_size)
        != (after.st_dev, after.st_ino, after.st_size)
        or parents_before != parents_after
    ):
        raise IFEMCandidateDependencyGraphError("candidate graph changed while loading")
    if hashlib.sha256(raw).hexdigest() != expected_file_sha256:
        raise IFEMCandidateDependencyGraphError("candidate graph file hash drifted")
    try:
        payload = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IFEMCandidateDependencyGraphError("candidate graph is not strict JSON") from error
    if not isinstance(payload, dict):
        raise IFEMCandidateDependencyGraphError("candidate graph must be a JSON object")
    try:
        graph = IFEMCandidateDependencyGraphV1.model_validate(payload)
    except ValueError as error:
        raise IFEMCandidateDependencyGraphError("candidate graph is invalid") from error
    if graph.content_sha256 != expected_content_sha256:
        raise IFEMCandidateDependencyGraphError("candidate graph content hash drifted")
    if render_ifem_candidate_dependency_graph(graph) != raw:
        raise IFEMCandidateDependencyGraphError("candidate graph is not canonically rendered")
    return graph


def write_ifem_candidate_dependency_graph(
    *,
    cache_root: Path,
    output_path: Path,
    graph: IFEMCandidateDependencyGraphV1,
) -> None:
    """Write the redacted graph atomically below the explicitly supplied cache root."""

    root = _resolve_existing_directory(cache_root, cache_root, label="candidate graph cache root")
    target = output_path.resolve(strict=False)
    try:
        target.relative_to(root)
    except ValueError as error:
        raise IFEMCandidateDependencyGraphError(
            "candidate graph output must stay below its cache root"
        ) from error
    if target.name != "ifem-candidate-dependency-graph.v1.json":
        raise IFEMCandidateDependencyGraphError(
            "candidate graph output must use the canonical artifact filename"
        )
    target.parent.mkdir(parents=True, exist_ok=True)
    serialized = render_ifem_candidate_dependency_graph(graph)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
    )
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(serialized)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_name, target)
    except OSError as error:
        with suppress(OSError):
            Path(temporary_name).unlink(missing_ok=True)
        raise IFEMCandidateDependencyGraphError("cannot write candidate graph artifact") from error


def _load_discovery_manifest(path: Path) -> tuple[DiscoveryLaneManifestV1, bytes]:
    payload, raw = _load_json_object(path, label="iFEM discovery manifest")
    try:
        return DiscoveryLaneManifestV1.model_validate(payload), raw
    except ValueError as error:
        raise IFEMCandidateDependencyGraphError(
            "cannot validate iFEM discovery manifest"
        ) from error


def _validate_census_plan(path: Path) -> IFEMPrerequisiteCensusPlanV1:
    payload, _ = _load_json_object(path, label="iFEM census plan")
    try:
        return IFEMPrerequisiteCensusPlanV1.model_validate(payload)
    except ValueError as error:
        raise IFEMCandidateDependencyGraphError("iFEM census plan is invalid") from error


def _validate_census_result(path: Path) -> IFEMPrerequisiteCensusResultV1:
    payload, _ = _load_json_object(path, label="iFEM census result")
    try:
        return IFEMPrerequisiteCensusResultV1.model_validate(payload)
    except ValueError as error:
        raise IFEMCandidateDependencyGraphError("iFEM census result is invalid") from error


def _validate_markdown_index(payload: Mapping[str, object]) -> IFEMMarkdownSourceSpanIndexV1:
    try:
        return IFEMMarkdownSourceSpanIndexV1.model_validate(payload)
    except ValueError as error:
        raise IFEMCandidateDependencyGraphError("iFEM Markdown index is invalid") from error


def _validate_notebook_index(payload: Mapping[str, object]) -> IFEMNotebookSourceSpanIndexV1:
    try:
        return IFEMNotebookSourceSpanIndexV1.model_validate(payload)
    except ValueError as error:
        raise IFEMCandidateDependencyGraphError("iFEM notebook index is invalid") from error


def _validate_discovery_and_census(
    *,
    lane_manifest: DiscoveryLaneManifestV1,
    source_lock: _VerifiedSourceLock,
    census_plan: IFEMPrerequisiteCensusPlanV1,
    census_result: IFEMPrerequisiteCensusResultV1,
) -> DiscoveryLaneV1:
    lane = next((item for item in lane_manifest.lanes if item.lane_id == IFEM_LANE_ID), None)
    if lane is None or lane.prerequisite_denominator is None or lane.precompile_census_plan is None:
        raise IFEMCandidateDependencyGraphError("iFEM discovery lane lacks its frozen denominator")
    if (
        lane.status != "discovery"
        or lane.source.source_bytes_state.value != "acquired_local_only"
        or lane.source.model_egress_ceiling != "local_only"
        or lane.source.external_model_source_text != "forbidden"
        or lane.source.source_lock_receipt_sha256 != source_lock.sha256
        or lane.source.resolved_revision != source_lock.source_revision
    ):
        raise IFEMCandidateDependencyGraphError(
            "iFEM discovery lane no longer binds the local-only source lock"
        )
    denominator = lane.prerequisite_denominator
    included_ids = tuple(
        node.node_id for node in denominator.nodes if node.included_in_prerequisite_denominator
    )
    if (
        census_plan.denominator.denominator_id != denominator.denominator_id
        or census_plan.denominator.denominator_revision != denominator.revision
        or census_plan.denominator.denominator_content_sha256 != denominator.content_sha256
        or census_plan.denominator.frozen_node_count != len(denominator.nodes)
        or census_plan.denominator.prerequisite_node_count != len(included_ids)
        or tuple(query.node_id for query in census_plan.queries) != included_ids
        or lane.precompile_census_plan.denominator_content_sha256 != denominator.content_sha256
        or lane.precompile_census_plan.mathlib_revision != census_plan.environment.mathlib_revision
    ):
        raise IFEMCandidateDependencyGraphError(
            "iFEM census plan no longer binds the discovery denominator"
        )
    try:
        validate_result_against_plan(census_result, census_plan)
    except IFEMPrerequisiteCensusError as error:
        raise IFEMCandidateDependencyGraphError(
            "iFEM census result does not bind its plan"
        ) from error
    if census_result.execution_state is not IFEMQueryExecutionStateV1.NOT_RUN:
        raise IFEMCandidateDependencyGraphError(
            "candidate graph requires the non-authoritative not-run census state"
        )
    return lane


def _build_candidate_nodes(
    *,
    lane: DiscoveryLaneV1,
    census_plan: IFEMPrerequisiteCensusPlanV1,
    markdown_index: IFEMMarkdownSourceSpanIndexV1,
    notebook_index: IFEMNotebookSourceSpanIndexV1,
) -> tuple[IFEMCandidateNodeV1, ...]:
    denominator = lane.prerequisite_denominator
    if denominator is None:
        raise IFEMCandidateDependencyGraphError("iFEM discovery lane lacks a denominator")
    discovery_nodes = denominator.nodes
    if not 20 <= len(discovery_nodes) <= 40:
        raise IFEMCandidateDependencyGraphError(
            "candidate graph requires between 20 and 40 discovery nodes"
        )
    anchors = _deterministic_anchors(
        node_count=len(discovery_nodes),
        markdown_index=markdown_index,
        notebook_index=notebook_index,
    )
    queries = {query.node_id: query for query in census_plan.queries}
    result: list[IFEMCandidateNodeV1] = []
    for discovery_node, (anchor_id, anchor_kind) in zip(discovery_nodes, anchors, strict=True):
        query = queries.get(discovery_node.node_id)
        ambiguity_flags = {
            IFEMCandidateNodeAmbiguityFlagV1.ANCHOR_ASSIGNMENT_NOT_SEMANTIC_MAPPING,
            IFEMCandidateNodeAmbiguityFlagV1.MATHEMATICAL_DEPENDENCY_NOT_VERIFIED,
            IFEMCandidateNodeAmbiguityFlagV1.SOURCE_INTERPRETATION_NOT_PERFORMED,
        }
        gap_flags = {
            IFEMCandidateNodeGapFlagV1.SEMANTIC_REVIEW_NOT_PERFORMED,
            IFEMCandidateNodeGapFlagV1.STATEMENT_CONTRACT_NOT_CREATED,
            IFEMCandidateNodeGapFlagV1.FORMAL_MAPPING_NOT_OBSERVED,
            IFEMCandidateNodeGapFlagV1.PROVER_HANDOFF_FORBIDDEN,
        }
        candidate_declaration_count = 0
        candidate_declaration_set_sha256: str | None = None
        if query is None:
            gap_flags.add(IFEMCandidateNodeGapFlagV1.NOT_IN_PREREQUISITE_CENSUS_QUERY_PLAN)
        else:
            candidate_declaration_count = len(query.candidate_declarations)
            candidate_declaration_set_sha256 = _sha256(
                canonical_json_bytes(query.candidate_declarations)
            )
        result.append(
            IFEMCandidateNodeV1(
                node_id=IFEMCandidateNodeIdV1(discovery_node.node_id),
                candidate_node_kind=discovery_node.kind.value,
                source_order=discovery_node.source_order,
                included_in_prerequisite_denominator=discovery_node.included_in_prerequisite_denominator,
                source_anchor_id=anchor_id,
                source_anchor_kind=anchor_kind,
                census_query_present=query is not None,
                candidate_declaration_count=candidate_declaration_count,
                candidate_declaration_set_sha256=candidate_declaration_set_sha256,
                ambiguity_flags=tuple(sorted(ambiguity_flags)),
                gap_flags=tuple(sorted(gap_flags)),
            )
        )
    return tuple(result)


def _deterministic_anchors(
    *,
    node_count: int,
    markdown_index: IFEMMarkdownSourceSpanIndexV1,
    notebook_index: IFEMNotebookSourceSpanIndexV1,
) -> tuple[tuple[StableIdentifierV1, Literal["markdown_heading", "notebook_cell"]], ...]:
    markdown_count = min(node_count, len(markdown_index.spans))
    anchors: list[tuple[StableIdentifierV1, Literal["markdown_heading", "notebook_cell"]]] = [
        (span.span_id, "markdown_heading") for span in markdown_index.spans[:markdown_count]
    ]
    remaining = node_count - markdown_count
    if remaining == 0:
        return tuple(anchors)
    if len(notebook_index.spans) < remaining:
        raise IFEMCandidateDependencyGraphError(
            "iFEM notebook index has too few cells for deterministic candidate anchors"
        )
    last_index = len(notebook_index.spans) - 1
    for position in range(remaining):
        index = 0 if remaining == 1 else position * last_index // (remaining - 1)
        anchors.append((notebook_index.spans[index].span_id, "notebook_cell"))
    if len({anchor_id for anchor_id, _kind in anchors}) != len(anchors):
        raise IFEMCandidateDependencyGraphError("deterministic source anchors are not unique")
    return tuple(anchors)


def _build_candidate_edges(
    *,
    lane: DiscoveryLaneV1,
    census_plan: IFEMPrerequisiteCensusPlanV1,
) -> tuple[IFEMCandidateDependencyEdgeV1, ...]:
    denominator = lane.prerequisite_denominator
    if denominator is None:
        raise IFEMCandidateDependencyGraphError("iFEM discovery lane lacks a denominator")
    node_order = {node.node_id: node.source_order for node in denominator.nodes}
    edges: list[IFEMCandidateDependencyEdgeV1] = []
    for node in denominator.nodes:
        for predecessor in node.depends_on:
            edges.append(
                IFEMCandidateDependencyEdgeV1(
                    source_node_id=IFEMCandidateNodeIdV1(predecessor),
                    target_node_id=IFEMCandidateNodeIdV1(node.node_id),
                    edge_kind="declared_candidate_dependency",
                    provenance="discovery_denominator_declared_unreviewed",
                    confidence="declared_unreviewed",
                    shared_candidate_declaration_count=0,
                )
            )
    queries = tuple(census_plan.queries)
    for left_index, left in enumerate(queries):
        left_candidates = set(left.candidate_declarations)
        for right in queries[left_index + 1 :]:
            shared = tuple(sorted(left_candidates.intersection(right.candidate_declarations)))
            if not shared:
                continue
            source, target = (left.node_id, right.node_id)
            if node_order[source] > node_order[target]:
                source, target = target, source
            edges.append(
                IFEMCandidateDependencyEdgeV1(
                    source_node_id=IFEMCandidateNodeIdV1(source),
                    target_node_id=IFEMCandidateNodeIdV1(target),
                    edge_kind="heuristic_candidate_declaration_overlap",
                    provenance="census_candidate_declaration_overlap_unreviewed",
                    confidence="low",
                    shared_candidate_declaration_count=len(shared),
                    shared_candidate_declaration_set_sha256=_sha256(canonical_json_bytes(shared)),
                )
            )
    return tuple(
        sorted(edges, key=lambda edge: (edge.edge_kind, edge.source_node_id, edge.target_node_id))
    )


def _validate_indexes_against_source_lock(
    *,
    source_lock: _VerifiedSourceLock,
    markdown_index: IFEMMarkdownSourceSpanIndexV1,
    notebook_index: IFEMNotebookSourceSpanIndexV1,
) -> None:
    for binding in (markdown_index.source_lock, notebook_index.source_lock):
        if (
            binding.source_lock_sha256 != source_lock.sha256
            or binding.source_revision != source_lock.source_revision
            or binding.source_file_count != len(source_lock.source_files)
        ):
            raise IFEMCandidateDependencyGraphError(
                "iFEM source-span index does not bind the supplied source lock"
            )
    if (
        markdown_index.model_egress_policy != "local_only"
        or notebook_index.model_egress_policy != "local_only"
        or markdown_index.semantic_review_state != "not_performed"
        or notebook_index.semantic_review_state != "not_performed"
        or markdown_index.contract_freeze != "not_authorized"
        or notebook_index.contract_freeze != "not_authorized"
        or markdown_index.prover_handoff != "not_authorized"
        or notebook_index.prover_handoff != "not_authorized"
        or markdown_index.contains_source_text
        or notebook_index.contains_source_text
        or markdown_index.contains_model_input
        or notebook_index.contains_model_input
    ):
        raise IFEMCandidateDependencyGraphError(
            "iFEM source-span index widens the local-only authority boundary"
        )
    by_position = {
        (index, record.path): record for index, record in enumerate(source_lock.source_files)
    }
    for span in markdown_index.spans:
        record = by_position.get((span.source_file_index, span.source_path))
        if record is None or (
            span.source_reference_id != record.reference_id
            or span.source_file_sha256 != record.sha256
        ):
            raise IFEMCandidateDependencyGraphError(
                "iFEM Markdown span does not bind a locked source file"
            )
    for cell_span in notebook_index.spans:
        record = by_position.get((cell_span.source_file_index, cell_span.source_path))
        if record is None or (
            cell_span.source_reference_id != record.reference_id
            or cell_span.source_file_sha256 != record.sha256
        ):
            raise IFEMCandidateDependencyGraphError(
                "iFEM notebook cell does not bind a locked source file"
            )


def _parse_source_lock(
    payload: Mapping[str, object], source_lock_bytes: bytes
) -> _VerifiedSourceLock:
    _expect_exact_keys(
        payload,
        {
            "acquisition",
            "policy",
            "reference_manifest_candidate_sha256",
            "reference_manifest_state",
            "schema_version",
            "source",
            "source_files",
            "state",
        },
        label="iFEM source lock",
    )
    if (
        payload.get("schema_version") != IFEM_SOURCE_LOCK_SCHEMA
        or payload.get("state") != "acquired_local_only"
        or payload.get("reference_manifest_state") != "candidate_entries_not_yet_tracked"
    ):
        raise IFEMCandidateDependencyGraphError("iFEM source lock has an unexpected state")
    _require_sha256(payload.get("reference_manifest_candidate_sha256"), label="reference manifest")
    source = _require_mapping(payload.get("source"), label="iFEM source lock source")
    _expect_exact_keys(source, {"license", "record_url", "resolved_revision"}, label="iFEM source")
    revision = source.get("resolved_revision")
    license_record = _require_mapping(source.get("license"), label="iFEM source license")
    _expect_exact_keys(
        license_record,
        {"evidence_url", "expression", "license_blob_sha1", "license_sha256", "url"},
        label="iFEM source license",
    )
    record_url = source.get("record_url")
    license_blob_sha1 = license_record.get("license_blob_sha1")
    license_sha256 = license_record.get("license_sha256")
    if (
        not isinstance(revision, str)
        or _SHA1.fullmatch(revision) is None
        or not isinstance(record_url, str)
        or not record_url.strip()
        or any(
            not isinstance(license_record.get(field), str)
            or not cast(str, license_record[field]).strip()
            for field in ("evidence_url", "expression", "url")
        )
        or not isinstance(license_blob_sha1, str)
        or not isinstance(license_sha256, str)
        or _SHA1.fullmatch(license_blob_sha1) is None
        or _SHA256.fullmatch(license_sha256) is None
    ):
        raise IFEMCandidateDependencyGraphError("iFEM source lock has an invalid revision")
    policy = _require_mapping(payload.get("policy"), label="iFEM source lock policy")
    if policy != {
        "access_policy": "public_open_access",
        "contract_freeze": "not_authorized",
        "model_egress_policy": "local_only",
        "prover_handoff": "not_authorized",
    }:
        raise IFEMCandidateDependencyGraphError("iFEM source lock widens its local-only policy")
    acquisition = _require_mapping(payload.get("acquisition"), label="iFEM source lock acquisition")
    _expect_exact_keys(
        acquisition,
        {"retrieved_at", "source_file_count", "source_size_bytes"},
        label="iFEM source lock acquisition",
    )
    raw_files = payload.get("source_files")
    if not isinstance(raw_files, list) or len(raw_files) != 13:
        raise IFEMCandidateDependencyGraphError(
            "iFEM source lock must retain exactly 13 source files"
        )
    files = tuple(
        _parse_locked_source_file(item, position=index) for index, item in enumerate(raw_files)
    )
    if len({item.path for item in files}) != len(files) or len(
        {item.reference_id for item in files}
    ) != len(files):
        raise IFEMCandidateDependencyGraphError("iFEM source lock has duplicate source identities")
    acquired_count = acquisition.get("source_file_count")
    acquired_size = acquisition.get("source_size_bytes")
    if (
        not _is_positive_int(acquired_count)
        or acquired_count != len(files)
        or not _is_positive_int(acquired_size)
        or acquired_size != sum(item.size_bytes for item in files)
    ):
        raise IFEMCandidateDependencyGraphError("iFEM source lock acquisition totals do not replay")
    return _VerifiedSourceLock(
        sha256=_sha256(source_lock_bytes),
        source_revision=revision,
        license_sha256=license_sha256,
        license_blob_sha1=license_blob_sha1,
        source_files=files,
    )


def _parse_locked_source_file(value: object, *, position: int) -> _LockedSourceFile:
    record = _require_mapping(value, label=f"iFEM source lock record {position}")
    _expect_exact_keys(
        record,
        {"path", "reference_id", "sha256", "size_bytes"},
        label=f"iFEM source lock record {position}",
    )
    path = record.get("path")
    reference_id = record.get("reference_id")
    size_bytes = record.get("size_bytes")
    if (
        not isinstance(path, str)
        or not _safe_relative_path(path)
        or not isinstance(reference_id, str)
        or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{2,127}", reference_id)
        or not _is_positive_int(size_bytes)
    ):
        raise IFEMCandidateDependencyGraphError("iFEM source lock record has invalid identity")
    sha256 = _require_sha256(record.get("sha256"), label=f"iFEM source lock hash {position}")
    return _LockedSourceFile(
        path=path, reference_id=reference_id, sha256=sha256, size_bytes=cast(int, size_bytes)
    )


def _verify_staging_tree(
    *,
    staging_root: Path,
    staging_payload: Mapping[str, object],
    source_lock: _VerifiedSourceLock,
) -> int:
    _expect_exact_keys(
        staging_payload,
        {"files", "repository", "revision", "schema_version"},
        label="iFEM staging manifest",
    )
    if (
        staging_payload.get("schema_version") != IFEM_STAGING_MANIFEST_SCHEMA
        or staging_payload.get("revision") != source_lock.source_revision
        or not isinstance(staging_payload.get("repository"), str)
    ):
        raise IFEMCandidateDependencyGraphError(
            "iFEM staging manifest does not bind the source lock"
        )
    raw_files = staging_payload.get("files")
    if not isinstance(raw_files, list) or len(raw_files) != 14:
        raise IFEMCandidateDependencyGraphError(
            "iFEM staging manifest must retain exactly 14 files"
        )
    staged: dict[str, tuple[str, int, str]] = {}
    for position, raw_record in enumerate(raw_files):
        record = _require_mapping(raw_record, label=f"iFEM staging record {position}")
        _expect_exact_keys(
            record,
            {"git_blob_sha1", "path", "sha256", "size_bytes"},
            label=f"iFEM staging record {position}",
        )
        path = record.get("path")
        size = record.get("size_bytes")
        if not isinstance(path, str) or not _safe_relative_path(path) or not _is_positive_int(size):
            raise IFEMCandidateDependencyGraphError("iFEM staging record has an invalid path")
        sha256 = _require_sha256(record.get("sha256"), label=f"iFEM staging hash {position}")
        blob_sha1 = record.get("git_blob_sha1")
        if not isinstance(blob_sha1, str) or _SHA1.fullmatch(blob_sha1) is None:
            raise IFEMCandidateDependencyGraphError(
                "iFEM staging record has an invalid Git blob hash"
            )
        if path in staged:
            raise IFEMCandidateDependencyGraphError("iFEM staging manifest has duplicate paths")
        staged[path] = (sha256, cast(int, size), blob_sha1)
    source_paths = {item.path for item in source_lock.source_files}
    if not source_paths <= set(staged):
        raise IFEMCandidateDependencyGraphError("iFEM staging manifest omits a locked source file")
    license_entry = staged.get("LICENSE")
    if (
        license_entry is None
        or license_entry[0] != source_lock.license_sha256
        or license_entry[2] != source_lock.license_blob_sha1
    ):
        raise IFEMCandidateDependencyGraphError(
            "iFEM staging manifest does not bind the locked license evidence"
        )
    for source_file in source_lock.source_files:
        staged_hash, staged_size, _staged_blob = staged[source_file.path]
        if staged_hash != source_file.sha256 or staged_size != source_file.size_bytes:
            raise IFEMCandidateDependencyGraphError(
                "iFEM staging manifest differs from a locked source file"
            )
    for path, (expected_hash, expected_size, expected_blob) in staged.items():
        staged_path = _resolve_staged_file(staging_root, path)
        try:
            content = staged_path.read_bytes()
        except OSError as error:
            raise IFEMCandidateDependencyGraphError(
                "cannot read a locked staged source file"
            ) from error
        if (
            len(content) != expected_size
            or _sha256(content) != expected_hash
            or _git_blob_sha1(content) != expected_blob
        ):
            raise IFEMCandidateDependencyGraphError("iFEM staged source bytes do not replay")
    return len(staged)


def _resolve_staged_file(staging_root: Path, relative_path: str) -> Path:
    pure = PurePosixPath(relative_path)
    candidate = staging_root.joinpath(*pure.parts)
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(staging_root)
    except (OSError, ValueError) as error:
        raise IFEMCandidateDependencyGraphError(
            "staged source path escapes its staging root"
        ) from error
    if not resolved.is_file():
        raise IFEMCandidateDependencyGraphError("staged source path is not a regular file")
    return resolved


def _load_json_object(path: Path, *, label: str) -> tuple[dict[str, object], bytes]:
    try:
        raw = path.read_bytes()
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IFEMCandidateDependencyGraphError(f"cannot read {label}") from error
    if not isinstance(payload, dict):
        raise IFEMCandidateDependencyGraphError(f"{label} must be a JSON object")
    return cast(dict[str, object], payload), raw


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    payload: dict[str, object] = {}
    for key, value in pairs:
        if key in payload:
            raise IFEMCandidateDependencyGraphError("duplicate JSON key in iFEM graph input")
        payload[key] = value
    return payload


def _resolve_existing_file(path: Path, root: Path, *, label: str) -> Path:
    resolved = _resolve_under_root(path, root, label=label)
    if not resolved.is_file():
        raise IFEMCandidateDependencyGraphError(f"{label} is not a file")
    return resolved


def _resolve_existing_directory(path: Path, root: Path, *, label: str) -> Path:
    resolved = _resolve_under_root(path, root, label=label)
    if not resolved.is_dir():
        raise IFEMCandidateDependencyGraphError(f"{label} is not a directory")
    return resolved


def _resolve_under_root(path: Path, root: Path, *, label: str) -> Path:
    try:
        root_resolved = root.resolve(strict=True)
        resolved = path.resolve(strict=True)
        resolved.relative_to(root_resolved)
    except (OSError, ValueError) as error:
        raise IFEMCandidateDependencyGraphError(
            f"{label} must resolve below the workspace root"
        ) from error
    return resolved


def _safe_relative_path(value: str) -> bool:
    if "\\" in value or not value or value.startswith("/"):
        return False
    pure = PurePosixPath(value)
    return pure.as_posix() == value and all(part not in {"", ".", ".."} for part in pure.parts)


def _expect_exact_keys(value: Mapping[str, object], expected: set[str], *, label: str) -> None:
    if set(value) != expected:
        raise IFEMCandidateDependencyGraphError(f"{label} has unexpected fields")


def _require_mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise IFEMCandidateDependencyGraphError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def _require_sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise IFEMCandidateDependencyGraphError(f"{label} has an invalid SHA-256")
    return value


def _is_positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _git_blob_sha1(value: bytes) -> str:
    header = f"blob {len(value)}\0".encode("ascii")
    return hashlib.sha1(header + value).hexdigest()


def iter_candidate_node_ids(graph: IFEMCandidateDependencyGraphV1) -> Iterable[str]:
    """Expose stable node identifiers without exposing source bytes or source paths."""

    verified = IFEMCandidateDependencyGraphV1.model_validate(graph.model_dump(mode="json"))
    return (node.node_id for node in verified.candidate_nodes)
