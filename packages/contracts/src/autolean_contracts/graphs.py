from __future__ import annotations

from collections import defaultdict, deque
from enum import StrEnum
from typing import Any, Literal

from pydantic import Field, model_validator

from .base import ContractModel
from .hashing import StableIdentifierV1


class MathematicalNodeKindV1(StrEnum):
    DEFINITION = "definition"
    THEOREM = "theorem"
    LEMMA = "lemma"
    EXAMPLE = "example"
    NOTATION = "notation"
    CONVENTION = "convention"


class MathematicalEdgeKindV1(StrEnum):
    USES = "uses"
    DEFINES = "defines"
    SPECIALIZES = "specializes"
    EQUIVALENT_TO = "equivalent_to"
    MOTIVATES = "motivates"


class FormalNodeKindV1(StrEnum):
    DEFINITION = "definition"
    THEOREM = "theorem"
    INSTANCE = "instance"
    NOTATION = "notation"
    IMPORT = "import"


class FormalEdgeKindV1(StrEnum):
    SIGNATURE_DEPENDS_ON = "signature_depends_on"
    BODY_DEPENDS_ON = "body_depends_on"
    IMPORTS = "imports"
    INSTANCE_DEPENDS_ON = "instance_depends_on"


class ExecutionNodeKindV1(StrEnum):
    INGEST = "ingest"
    RIGHTS_REVIEW = "rights_review"
    NORMALIZE = "normalize"
    FORMALIZE = "formalize"
    FIDELITY_REVIEW = "fidelity_review"
    PROVE = "prove"
    VERIFY = "verify"
    INTEGRATE = "integrate"


class ExecutionEdgeKindV1(StrEnum):
    BLOCKED_BY = "blocked_by"
    PRODUCES = "produces"
    RETRY_OF = "retry_of"
    SUPERSEDES = "supersedes"


class MathematicalNodeV1(ContractModel):
    node_id: StableIdentifierV1
    kind: MathematicalNodeKindV1
    label: str = Field(min_length=1)
    source_span_ids: tuple[StableIdentifierV1, ...] = ()
    metadata: dict[str, Any] = Field(default_factory=dict)


class MathematicalEdgeV1(ContractModel):
    edge_id: StableIdentifierV1
    source: StableIdentifierV1
    target: StableIdentifierV1
    kind: MathematicalEdgeKindV1


class FormalNodeV1(ContractModel):
    node_id: StableIdentifierV1
    kind: FormalNodeKindV1
    declaration_name: str = Field(min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)


class FormalEdgeV1(ContractModel):
    edge_id: StableIdentifierV1
    source: StableIdentifierV1
    target: StableIdentifierV1
    kind: FormalEdgeKindV1


class ExecutionNodeV1(ContractModel):
    node_id: StableIdentifierV1
    kind: ExecutionNodeKindV1
    label: str = Field(min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ExecutionEdgeV1(ContractModel):
    edge_id: StableIdentifierV1
    source: StableIdentifierV1
    target: StableIdentifierV1
    kind: ExecutionEdgeKindV1


def _validate_graph(nodes: tuple[Any, ...], edges: tuple[Any, ...], *, allow_cycles: bool) -> None:
    node_ids = [node.node_id.value for node in nodes]
    if len(node_ids) != len(set(node_ids)):
        raise ValueError("graph node identifiers must be unique")
    edge_ids = [edge.edge_id.value for edge in edges]
    if len(edge_ids) != len(set(edge_ids)):
        raise ValueError("graph edge identifiers must be unique")

    known = set(node_ids)
    adjacency: dict[str, list[str]] = defaultdict(list)
    indegree = dict.fromkeys(node_ids, 0)
    for edge in edges:
        source = edge.source.value
        target = edge.target.value
        if source not in known or target not in known:
            raise ValueError("every graph edge endpoint must reference a graph node")
        if source == target:
            raise ValueError("self-referential graph edges are not allowed")
        adjacency[source].append(target)
        indegree[target] += 1

    if allow_cycles:
        return
    queue = deque(node_id for node_id, degree in indegree.items() if degree == 0)
    visited = 0
    while queue:
        node_id = queue.popleft()
        visited += 1
        for target in adjacency[node_id]:
            indegree[target] -= 1
            if indegree[target] == 0:
                queue.append(target)
    if visited != len(node_ids):
        raise ValueError("dependency graph must be acyclic")


class MathematicalGraphV1(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    graph_id: StableIdentifierV1
    revision: int = Field(ge=1)
    nodes: tuple[MathematicalNodeV1, ...] = ()
    edges: tuple[MathematicalEdgeV1, ...] = ()

    @model_validator(mode="after")
    def validate_structure(self) -> MathematicalGraphV1:
        # Equivalence and motivation may be cyclic; mathematical prerequisites need not be.
        # Validate the full graph first so even non-dependency edges cannot smuggle in
        # duplicate IDs, dangling endpoints, or self-references.
        _validate_graph(self.nodes, self.edges, allow_cycles=True)
        dependency_edges = tuple(
            edge
            for edge in self.edges
            if edge.kind
            not in {MathematicalEdgeKindV1.EQUIVALENT_TO, MathematicalEdgeKindV1.MOTIVATES}
        )
        _validate_graph(self.nodes, dependency_edges, allow_cycles=False)
        return self


class FormalGraphV1(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    graph_id: StableIdentifierV1
    revision: int = Field(ge=1)
    nodes: tuple[FormalNodeV1, ...] = ()
    edges: tuple[FormalEdgeV1, ...] = ()

    @model_validator(mode="after")
    def validate_structure(self) -> FormalGraphV1:
        _validate_graph(self.nodes, self.edges, allow_cycles=False)
        return self


class ExecutionGraphV1(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    graph_id: StableIdentifierV1
    revision: int = Field(ge=1)
    nodes: tuple[ExecutionNodeV1, ...] = ()
    edges: tuple[ExecutionEdgeV1, ...] = ()

    @model_validator(mode="after")
    def validate_structure(self) -> ExecutionGraphV1:
        _validate_graph(self.nodes, self.edges, allow_cycles=False)
        return self


class AlignmentRelationV1(StrEnum):
    FORMALIZES = "formalizes"
    DEFINES = "defines"
    SUPPORTS = "supports"
    APPROXIMATES = "approximates"


class CrossGraphAlignmentV1(ContractModel):
    alignment_id: StableIdentifierV1
    mathematical_node_id: StableIdentifierV1
    formal_node_id: StableIdentifierV1
    relation: AlignmentRelationV1
    source_span_ids: tuple[StableIdentifierV1, ...] = ()
    confidence: float = Field(ge=0.0, le=1.0)
    reviewer_id: str | None = None


class GraphBundleV1(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    mathematical: MathematicalGraphV1
    formal: FormalGraphV1
    execution: ExecutionGraphV1
    alignments: tuple[CrossGraphAlignmentV1, ...] = ()

    @model_validator(mode="after")
    def validate_alignments(self) -> GraphBundleV1:
        mathematical_ids = {node.node_id.value for node in self.mathematical.nodes}
        formal_ids = {node.node_id.value for node in self.formal.nodes}
        alignment_ids = [alignment.alignment_id.value for alignment in self.alignments]
        if len(alignment_ids) != len(set(alignment_ids)):
            raise ValueError("alignment identifiers must be unique")
        for alignment in self.alignments:
            if alignment.mathematical_node_id.value not in mathematical_ids:
                raise ValueError("alignment references an unknown mathematical node")
            if alignment.formal_node_id.value not in formal_ids:
                raise ValueError("alignment references an unknown formal node")
        return self
