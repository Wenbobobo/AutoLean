"""Source-free, unknown-only triage for the iFEM prerequisite denominator.

This module is intentionally narrower than the prerequisite census.  It
replays a fixed set of already-versioned discovery artifacts and projects each
of the 21 prerequisite nodes as ``unknown``.  In particular, a declaration
being visible from a pinned singleton import is *not* a mathematical mapping.

The triage is therefore neither an input to the census nor a route to a frozen
statement.  It exists to make one internally-consistent discovery snapshot
easy to inspect while preserving the distinction between candidate visibility
and semantic classification.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from collections.abc import Sequence
from pathlib import Path
from typing import Final, Literal, Never, cast

from autolean_contracts import canonical_json_bytes
from autolean_contracts.base import ContractModel
from pydantic import Field, model_validator

from .ifem_candidate_dependency_graph import (
    IFEMCandidateDependencyGraphError,
    IFEMCandidateDependencyGraphV1,
    IFEMCandidateNodeIdV1,
    load_ifem_candidate_dependency_graph,
)
from .ifem_pilot_readiness import (
    IFEMPilotProfileEvidenceStateV2,
    IFEMPilotReadinessDecisionV2,
    IFEMPilotReadinessError,
    load_ifem_pilot_readiness_decision,
    verify_ifem_pilot_readiness_decision,
)
from .ifem_pinned_mathlib_profiles import (
    IFEMPinnedMathlibProfilePlanV1,
    IFEMPinnedMathlibProfilePublicSummaryV1,
    IFEMPinnedProfileError,
    build_ifem_pinned_mathlib_profile_plan,
    load_ifem_pinned_mathlib_profile_public_summary,
)
from .ifem_prerequisite_census import (
    DEFAULT_PLAN_PATH,
    IFEMPrerequisiteCensusError,
    IFEMPrerequisiteCensusPlanV1,
    IFEMPrerequisiteCensusResultV1,
    IFEMPrerequisiteClassificationV1,
    load_ifem_prerequisite_census_plan,
    validate_result_against_plan,
)
from .ifem_structural_calibration import (
    IFEMStructuralCalibrationError,
    IFEMStructuralCaseIdV1,
    IFEMStructuralRiskV1,
    verify_ifem_structural_calibration_catalog_against_graph,
)
from .ifem_structural_role_probes import (
    IFEMStructuralRoleProbeCorpusV1,
    IFEMStructuralRoleProbeError,
    build_ifem_structural_role_probe_corpus,
    load_ifem_structural_role_probe_corpus,
)

ROOT = Path(__file__).resolve().parents[3]

TRIAGE_SCHEMA: Final[Literal["autolean.ifem-classification-triage.v1"]] = (
    "autolean.ifem-classification-triage.v1"
)
TRIAGE_PROTOCOL: Final[Literal["autolean.builder-ifem-classification-triage.v1"]] = (
    "autolean.builder-ifem-classification-triage.v1"
)
TRIAGE_KIND: Final[Literal["source_free_unknown_only_classification_triage"]] = (
    "source_free_unknown_only_classification_triage"
)
_SHA256 = r"^[0-9a-f]{64}$"
_PROFILE_ID = r"^ifem-singleton-[a-z-]+$"

DEFAULT_GRAPH_PATH = (
    ROOT / "Builder" / "pilots" / "discovery" / "ifem-candidate-dependency-graph.v1.json"
)
DEFAULT_CENSUS_PLAN_PATH = DEFAULT_PLAN_PATH
DEFAULT_CENSUS_RESULT_PATH = (
    ROOT / "docs" / "research" / "ifem-prerequisite-census-not-run-2026-07-31-graph-chain.json"
)
DEFAULT_PROFILE_SUMMARY_PATH = (
    ROOT / "docs" / "research" / "ifem-pinned-mathlib-profile-public-summary-2026-07-31.json"
)
DEFAULT_STRUCTURAL_CORPUS_PATH = (
    ROOT / "Builder" / "pilots" / "discovery" / "ifem-structural-role-probe-corpus.v1.json"
)
DEFAULT_READINESS_DECISION_PATH = (
    ROOT
    / "docs"
    / "research"
    / "ifem-pilot-readiness-decision-2026-07-31-graph-chain-successor.json"
)


class IFEMClassificationTriageError(ValueError):
    """A proposed source-free triage crosses or drifts from a frozen boundary."""


class IFEMClassificationTriageAuthorityV1(ContractModel):
    """Every authority the triage is prohibited from exercising."""

    schema_version: Literal["autolean.ifem-classification-triage-authority.v1"] = (
        "autolean.ifem-classification-triage-authority.v1"
    )
    candidate_visibility_is_semantic_mapping: Literal[False] = False
    semantic_classification_authorized: Literal[False] = False
    source_text_present: Literal[False] = False
    lean_name_present: Literal[False] = False
    lean_type_present: Literal[False] = False
    model_input_created: Literal[False] = False
    statement_contract_created: Literal[False] = False
    formal_graph_created: Literal[False] = False
    execution_graph_created: Literal[False] = False
    freeze_allowed: Literal[False] = False
    prover_handoff_allowed: Literal[False] = False
    proof_submission_allowed: Literal[False] = False
    promotion_allowed: Literal[False] = False


class IFEMClassificationTriageEvidenceBindingV1(ContractModel):
    """Exact file and content hashes for the six supplied source artifacts.

    The structural calibration catalog is embedded in the public corpus rather
    than supplied as a seventh file.  Its independent content hash is retained
    to prevent the corpus from silently changing the catalog projection.
    """

    candidate_graph_file_sha256: str = Field(pattern=_SHA256)
    candidate_graph_content_sha256: str = Field(pattern=_SHA256)
    census_plan_file_sha256: str = Field(pattern=_SHA256)
    census_plan_content_sha256: str = Field(pattern=_SHA256)
    census_result_file_sha256: str = Field(pattern=_SHA256)
    census_result_content_sha256: str = Field(pattern=_SHA256)
    pinned_profile_public_summary_file_sha256: str = Field(pattern=_SHA256)
    pinned_profile_public_summary_content_sha256: str = Field(pattern=_SHA256)
    pinned_profile_plan_content_sha256: str = Field(pattern=_SHA256)
    structural_probe_corpus_file_sha256: str = Field(pattern=_SHA256)
    structural_probe_corpus_content_sha256: str = Field(pattern=_SHA256)
    structural_calibration_catalog_content_sha256: str = Field(pattern=_SHA256)
    readiness_decision_file_sha256: str = Field(pattern=_SHA256)
    readiness_decision_content_sha256: str = Field(pattern=_SHA256)


class IFEMClassificationTriageNodeV1(ContractModel):
    """One denominator node without candidate names or semantic evidence."""

    node_id: IFEMCandidateNodeIdV1
    source_order: int = Field(ge=1)
    candidate_node_kind: Literal["definition", "prerequisite_theorem", "example", "terminal_target"]
    semantic_classification: Literal[IFEMPrerequisiteClassificationV1.UNKNOWN] = (
        IFEMPrerequisiteClassificationV1.UNKNOWN
    )
    candidate_visibility_profile_ids: tuple[str, ...] = ()
    candidate_visibility_is_non_semantic: Literal[True] = True
    structural_case_ids: tuple[IFEMStructuralCaseIdV1, ...] = ()
    structural_risk_families: tuple[IFEMStructuralRiskV1, ...] = ()
    critical_restriction_node: bool

    @model_validator(mode="after")
    def validate_projection(self) -> IFEMClassificationTriageNodeV1:
        if self.candidate_visibility_profile_ids != tuple(
            sorted(set(self.candidate_visibility_profile_ids))
        ):
            raise ValueError("candidate visibility profile IDs must be sorted and unique")
        if any(
            re.fullmatch(_PROFILE_ID, identifier) is None
            for identifier in self.candidate_visibility_profile_ids
        ):
            raise ValueError("candidate visibility contains an invalid profile ID")
        if self.structural_case_ids != tuple(sorted(set(self.structural_case_ids), key=str)):
            raise ValueError("structural case IDs must be sorted and unique")
        if self.structural_risk_families != tuple(
            sorted(set(self.structural_risk_families), key=str)
        ):
            raise ValueError("structural risk families must be sorted and unique")
        return self


class IFEMUnknownOnlyClassificationTriageV1(ContractModel):
    """A deterministic, read-only projection of one coherent iFEM snapshot."""

    schema_version: Literal["autolean.ifem-classification-triage.v1"] = TRIAGE_SCHEMA
    protocol: Literal["autolean.builder-ifem-classification-triage.v1"] = TRIAGE_PROTOCOL
    artifact_kind: Literal["source_free_unknown_only_classification_triage"] = TRIAGE_KIND
    denominator_node_count: Literal[21] = 21
    candidate_visibility_interpretation: Literal[
        "candidate_name_intersection_only_not_semantic_mapping"
    ] = "candidate_name_intersection_only_not_semantic_mapping"
    evidence: IFEMClassificationTriageEvidenceBindingV1
    nodes: tuple[IFEMClassificationTriageNodeV1, ...] = Field(min_length=21, max_length=21)
    contains_source_text: Literal[False] = False
    contains_lean_names: Literal[False] = False
    contains_lean_types: Literal[False] = False
    contains_model_input: Literal[False] = False
    authority: IFEMClassificationTriageAuthorityV1 = IFEMClassificationTriageAuthorityV1()
    builder_freeze: Literal["forbidden"] = "forbidden"
    prover_handoff: Literal["forbidden"] = "forbidden"
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_triage(self) -> IFEMUnknownOnlyClassificationTriageV1:
        source_orders = tuple(node.source_order for node in self.nodes)
        if source_orders != tuple(sorted(source_orders)) or len(set(source_orders)) != 21:
            raise ValueError("triage nodes must retain a unique increasing source order")
        if len({node.node_id for node in self.nodes}) != self.denominator_node_count:
            raise ValueError("triage nodes must have unique identifiers")
        if any(
            node.semantic_classification is not IFEMPrerequisiteClassificationV1.UNKNOWN
            for node in self.nodes
        ):
            raise ValueError("unknown-only triage cannot emit a semantic classification")
        if self.authority != IFEMClassificationTriageAuthorityV1():
            raise ValueError("triage authority flags drifted")
        if self.content_sha256 != self.computed_content_sha256():
            raise ValueError("triage content hash does not match its payload")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(dict[str, object], self.model_dump(mode="json", exclude={"content_sha256"}))

    def computed_content_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.content_payload())).hexdigest()

    def assert_not_routable(self) -> Never:
        raise IFEMClassificationTriageError(
            "unknown-only iFEM classification triage cannot classify a proposition, create a "
            "statement contract, freeze a statement, or hand work to Prover"
        )

    def freeze_statement(self) -> Never:
        self.assert_not_routable()

    def handoff_to_prover(self) -> Never:
        self.assert_not_routable()


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise IFEMClassificationTriageError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


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
            raise IFEMClassificationTriageError(
                "triage input parent chain must contain only physical directories"
            )
        identities.append((metadata.st_dev, metadata.st_ino))
    return tuple(identities)


def _read_regular_file(path: Path, *, label: str) -> tuple[bytes, str]:
    if not isinstance(path, Path):
        raise IFEMClassificationTriageError(f"{label} path must be a Path")
    try:
        parents_before = _physical_parent_identities(path)
        before = path.lstat()
        if _is_link_or_reparse(path, before) or not stat.S_ISREG(before.st_mode):
            raise IFEMClassificationTriageError(f"{label} must be an unlinked regular file")
        raw = path.read_bytes()
        after = path.lstat()
        parents_after = _physical_parent_identities(path)
    except OSError as error:
        raise IFEMClassificationTriageError(f"cannot read {label}: {path}") from error
    if (
        _is_link_or_reparse(path, after)
        or not stat.S_ISREG(after.st_mode)
        or (before.st_dev, before.st_ino, before.st_size)
        != (after.st_dev, after.st_ino, after.st_size)
        or parents_before != parents_after
    ):
        raise IFEMClassificationTriageError(f"{label} changed while loading")
    return raw, hashlib.sha256(raw).hexdigest()


def _load_typed_model[ModelT: ContractModel](
    path: Path,
    model_type: type[ModelT],
    *,
    label: str,
    require_canonical_rendering: bool = False,
) -> tuple[ModelT, str]:
    raw, file_sha256 = _read_regular_file(path, label=label)
    try:
        payload = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IFEMClassificationTriageError(f"{label} is not strict UTF-8 JSON") from error
    if not isinstance(payload, dict):
        raise IFEMClassificationTriageError(f"{label} must be a JSON object")
    try:
        model = model_type.model_validate(payload)
    except ValueError as error:
        raise IFEMClassificationTriageError(f"{label} has an invalid typed model") from error
    if (
        require_canonical_rendering
        and canonical_json_bytes(model.model_dump(mode="json")) + b"\n" != raw
    ):
        raise IFEMClassificationTriageError(f"{label} is not canonically rendered")
    return model, file_sha256


def _revalidate_model[ModelT: ContractModel](
    value: ModelT,
    model_type: type[ModelT],
    *,
    label: str,
) -> ModelT:
    if type(value) is not model_type:
        raise IFEMClassificationTriageError(f"{label} must use its exact typed model")
    try:
        return model_type.model_validate(value.model_dump(mode="json"))
    except ValueError as error:
        raise IFEMClassificationTriageError(f"{label} failed typed self-revalidation") from error


def _validate_profile_summary(
    summary: IFEMPinnedMathlibProfilePublicSummaryV1,
    profile_plan: IFEMPinnedMathlibProfilePlanV1,
    census_plan: IFEMPrerequisiteCensusPlanV1,
) -> None:
    if (
        profile_plan.census_plan_content_sha256 != census_plan.content_sha256
        or profile_plan.denominator != census_plan.denominator
        or profile_plan.environment.lean_toolchain != census_plan.environment.lean_toolchain
        or profile_plan.environment.mathlib_revision != census_plan.environment.mathlib_revision
        or profile_plan.environment.lake_manifest_sha256
        != census_plan.environment.lake_manifest_sha256
    ):
        raise IFEMClassificationTriageError("replayed pinned profile plan does not bind the census")
    if summary.plan_content_sha256 != profile_plan.content_sha256:
        raise IFEMClassificationTriageError(
            "pinned profile public summary does not bind the replayed profile plan"
        )
    if (
        summary.environment.lean_toolchain != census_plan.environment.lean_toolchain
        or summary.environment.mathlib_revision != census_plan.environment.mathlib_revision
        or summary.environment.lake_manifest_sha256 != census_plan.environment.lake_manifest_sha256
    ):
        raise IFEMClassificationTriageError(
            "pinned profile public summary environment differs from the census plan"
        )
    expected_candidates = profile_plan.candidate_declarations
    for profile in summary.profiles:
        actual_candidates = tuple(item.declaration for item in profile.declarations)
        if actual_candidates != expected_candidates:
            raise IFEMClassificationTriageError(
                "pinned profile public summary candidate vocabulary differs from its replayed plan"
            )


def _validate_cross_bindings(
    *,
    graph: IFEMCandidateDependencyGraphV1,
    census_plan: IFEMPrerequisiteCensusPlanV1,
    census_result: IFEMPrerequisiteCensusResultV1,
    profile_summary: IFEMPinnedMathlibProfilePublicSummaryV1,
    replayed_profile_plan: IFEMPinnedMathlibProfilePlanV1,
    structural_corpus: IFEMStructuralRoleProbeCorpusV1,
    readiness_decision: IFEMPilotReadinessDecisionV2,
) -> None:
    try:
        validate_result_against_plan(census_result, census_plan)
    except IFEMPrerequisiteCensusError as error:
        raise IFEMClassificationTriageError(
            "census result does not bind the supplied census plan"
        ) from error
    if any(
        item.evidence.classification is not IFEMPrerequisiteClassificationV1.UNKNOWN
        for item in census_result.node_results
    ):
        raise IFEMClassificationTriageError(
            "unknown-only triage cannot consume non-unknown census classifications"
        )
    if (
        graph.source_binding.census_plan_content_sha256 != census_plan.content_sha256
        or graph.source_binding.census_result_sha256 != census_result.content_sha256
    ):
        raise IFEMClassificationTriageError(
            "candidate graph and census inputs are not one content-addressed snapshot"
        )
    if graph.census_execution_state != census_result.execution_state.value:
        raise IFEMClassificationTriageError(
            "candidate graph execution state differs from census result"
        )
    graph_queries = {
        node.node_id: node
        for node in graph.candidate_nodes
        if node.included_in_prerequisite_denominator
    }
    if tuple(graph_queries) != tuple(query.node_id for query in census_plan.queries):
        raise IFEMClassificationTriageError(
            "candidate graph denominator nodes drifted from census order"
        )
    for query in census_plan.queries:
        node = graph_queries[IFEMCandidateNodeIdV1(query.node_id)]
        expected_candidate_hash = hashlib.sha256(
            canonical_json_bytes(query.candidate_declarations)
        ).hexdigest()
        if (
            not node.census_query_present
            or node.candidate_declaration_count != len(query.candidate_declarations)
            or node.candidate_declaration_set_sha256 != expected_candidate_hash
        ):
            raise IFEMClassificationTriageError(
                "candidate graph declaration-set projection differs from census plan"
            )
    _validate_profile_summary(profile_summary, replayed_profile_plan, census_plan)
    try:
        verified_catalog = verify_ifem_structural_calibration_catalog_against_graph(
            structural_corpus.catalog,
            graph,
        )
        rebuilt_corpus = build_ifem_structural_role_probe_corpus(
            catalog=verified_catalog,
            graph=graph,
        )
    except (IFEMStructuralCalibrationError, IFEMStructuralRoleProbeError) as error:
        raise IFEMClassificationTriageError(
            "structural corpus catalog does not replay against the candidate graph"
        ) from error
    if structural_corpus != rebuilt_corpus:
        raise IFEMClassificationTriageError(
            "structural probe corpus differs from the exact catalog projection"
        )
    if (
        readiness_decision.evidence.census_plan_content_sha256 != census_plan.content_sha256
        or readiness_decision.evidence.census_result_content_sha256 != census_result.content_sha256
    ):
        raise IFEMClassificationTriageError(
            "readiness decision does not bind the exact triage census snapshot"
        )
    if (
        readiness_decision.profile_evidence_state
        is not IFEMPilotProfileEvidenceStateV2.NOT_SUPPLIED
    ):
        raise IFEMClassificationTriageError(
            "unknown-only triage cannot replay a readiness decision with omitted raw profile inputs"
        )
    try:
        verify_ifem_pilot_readiness_decision(readiness_decision, census_plan, census_result)
    except IFEMPilotReadinessError as error:
        raise IFEMClassificationTriageError(
            "readiness decision does not replay from the exact census inputs"
        ) from error
    if (
        readiness_decision.counts.denominator_node_count != 21
        or readiness_decision.counts.unknown_count != 21
        or readiness_decision.counts.direct_count
        or readiness_decision.counts.thin_adapter_count
        or readiness_decision.counts.missing_count
    ):
        raise IFEMClassificationTriageError(
            "unknown-only triage requires an all-unknown readiness decision"
        )
    if any(
        state.classification is not IFEMPrerequisiteClassificationV1.UNKNOWN
        or state.mapped_declarations
        or state.observed_under_exact_direct_import_profiles is not None
        for state in readiness_decision.critical_restriction_states
    ):
        raise IFEMClassificationTriageError(
            "unknown-only triage requires unknown critical restriction states"
        )


def _build_ifem_unknown_only_classification_triage(
    *,
    graph: IFEMCandidateDependencyGraphV1,
    census_plan: IFEMPrerequisiteCensusPlanV1,
    census_result: IFEMPrerequisiteCensusResultV1,
    profile_summary: IFEMPinnedMathlibProfilePublicSummaryV1,
    replayed_profile_plan: IFEMPinnedMathlibProfilePlanV1,
    structural_corpus: IFEMStructuralRoleProbeCorpusV1,
    readiness_decision: IFEMPilotReadinessDecisionV2,
    evidence: IFEMClassificationTriageEvidenceBindingV1,
) -> IFEMUnknownOnlyClassificationTriageV1:
    """Build the non-semantic projection after exact typed replay.

    ``replayed_profile_plan`` is an internal consistency witness regenerated
    from the supplied census-plan file by the path-based entry point.  The
    triage binds its content hash, but not a raw profile-plan file identity:
    that file is not supplied at this public boundary.
    """

    graph = _revalidate_model(graph, IFEMCandidateDependencyGraphV1, label="candidate graph")
    census_plan = _revalidate_model(
        census_plan,
        IFEMPrerequisiteCensusPlanV1,
        label="census plan",
    )
    census_result = _revalidate_model(
        census_result,
        IFEMPrerequisiteCensusResultV1,
        label="census result",
    )
    profile_summary = _revalidate_model(
        profile_summary,
        IFEMPinnedMathlibProfilePublicSummaryV1,
        label="pinned profile public summary",
    )
    replayed_profile_plan = _revalidate_model(
        replayed_profile_plan,
        IFEMPinnedMathlibProfilePlanV1,
        label="replayed pinned profile plan",
    )
    structural_corpus = _revalidate_model(
        structural_corpus,
        IFEMStructuralRoleProbeCorpusV1,
        label="structural probe corpus",
    )
    readiness_decision = _revalidate_model(
        readiness_decision,
        IFEMPilotReadinessDecisionV2,
        label="readiness decision",
    )
    evidence = _revalidate_model(
        evidence,
        IFEMClassificationTriageEvidenceBindingV1,
        label="triage evidence binding",
    )
    _validate_cross_bindings(
        graph=graph,
        census_plan=census_plan,
        census_result=census_result,
        profile_summary=profile_summary,
        replayed_profile_plan=replayed_profile_plan,
        structural_corpus=structural_corpus,
        readiness_decision=readiness_decision,
    )
    if (
        evidence.candidate_graph_content_sha256 != graph.content_sha256
        or evidence.census_plan_content_sha256 != census_plan.content_sha256
        or evidence.census_result_content_sha256 != census_result.content_sha256
        or evidence.pinned_profile_public_summary_content_sha256 != profile_summary.content_sha256
        or evidence.pinned_profile_plan_content_sha256 != replayed_profile_plan.content_sha256
        or evidence.structural_probe_corpus_content_sha256 != structural_corpus.content_sha256
        or evidence.structural_calibration_catalog_content_sha256
        != structural_corpus.catalog.content_sha256
        or evidence.readiness_decision_content_sha256 != readiness_decision.content_sha256
    ):
        raise IFEMClassificationTriageError("evidence content hashes do not bind supplied models")

    cases_by_node: dict[IFEMCandidateNodeIdV1, set[IFEMStructuralCaseIdV1]] = {}
    risks_by_node: dict[IFEMCandidateNodeIdV1, set[IFEMStructuralRiskV1]] = {}
    for pair in structural_corpus.pairs:
        for node_id in pair.candidate_node_ids:
            cases_by_node.setdefault(node_id, set()).add(pair.catalog_case_id)
            risks_by_node.setdefault(node_id, set()).add(pair.risk)
    critical_nodes = {
        IFEMCandidateNodeIdV1(item) for item in readiness_decision.policy.critical_restriction_nodes
    }
    summary_visibility = {
        profile.profile_id: {item.declaration for item in profile.declarations if item.present}
        for profile in profile_summary.profiles
    }
    graph_nodes = {
        node.node_id: node
        for node in graph.candidate_nodes
        if node.included_in_prerequisite_denominator
    }
    nodes: list[IFEMClassificationTriageNodeV1] = []
    for query in census_plan.queries:
        graph_node = graph_nodes[IFEMCandidateNodeIdV1(query.node_id)]
        candidate_set = set(query.candidate_declarations)
        visible_profiles = tuple(
            sorted(
                profile_id
                for profile_id, present_declarations in summary_visibility.items()
                if candidate_set.intersection(present_declarations)
            )
        )
        nodes.append(
            IFEMClassificationTriageNodeV1(
                node_id=graph_node.node_id,
                source_order=graph_node.source_order,
                candidate_node_kind=graph_node.candidate_node_kind,
                candidate_visibility_profile_ids=visible_profiles,
                structural_case_ids=tuple(
                    sorted(cases_by_node.get(graph_node.node_id, set()), key=str)
                ),
                structural_risk_families=tuple(
                    sorted(risks_by_node.get(graph_node.node_id, set()), key=str)
                ),
                critical_restriction_node=graph_node.node_id in critical_nodes,
            )
        )
    payload: dict[str, object] = {
        "schema_version": TRIAGE_SCHEMA,
        "protocol": TRIAGE_PROTOCOL,
        "artifact_kind": TRIAGE_KIND,
        "denominator_node_count": 21,
        "candidate_visibility_interpretation": (
            "candidate_name_intersection_only_not_semantic_mapping"
        ),
        "evidence": evidence.model_dump(mode="json"),
        "nodes": [node.model_dump(mode="json") for node in nodes],
        "contains_source_text": False,
        "contains_lean_names": False,
        "contains_lean_types": False,
        "contains_model_input": False,
        "authority": IFEMClassificationTriageAuthorityV1().model_dump(mode="json"),
        "builder_freeze": "forbidden",
        "prover_handoff": "forbidden",
    }
    payload["content_sha256"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    try:
        return IFEMUnknownOnlyClassificationTriageV1.model_validate(payload)
    except ValueError as error:
        raise IFEMClassificationTriageError("generated unknown-only triage is invalid") from error


def load_ifem_unknown_only_classification_triage(
    path: Path,
) -> IFEMUnknownOnlyClassificationTriageV1:
    """Load a canonically-rendered artifact and validate its self-hash.

    This validates the artifact's shape and its own content address only.  It
    does not establish that the embedded evidence hashes came from particular
    external files.  A consumer that needs that provenance claim must call
    :func:`verify_ifem_unknown_only_classification_triage_against_paths` with
    the exact input paths it relies on.
    """

    triage, _ = _load_typed_model(
        path,
        IFEMUnknownOnlyClassificationTriageV1,
        label="unknown-only iFEM classification triage",
        require_canonical_rendering=True,
    )
    return triage


def build_ifem_unknown_only_classification_triage_from_paths(
    *,
    graph_path: Path = DEFAULT_GRAPH_PATH,
    census_plan_path: Path = DEFAULT_CENSUS_PLAN_PATH,
    census_result_path: Path = DEFAULT_CENSUS_RESULT_PATH,
    profile_summary_path: Path = DEFAULT_PROFILE_SUMMARY_PATH,
    structural_corpus_path: Path = DEFAULT_STRUCTURAL_CORPUS_PATH,
    readiness_decision_path: Path = DEFAULT_READINESS_DECISION_PATH,
) -> IFEMUnknownOnlyClassificationTriageV1:
    """Load exact canonical inputs and build one projection.

    This is the public entry point.  It deliberately accepts a successor
    decision only if every supplied artifact refers to the same census snapshot.
    """

    graph, graph_file_sha256 = _load_typed_model(
        graph_path,
        IFEMCandidateDependencyGraphV1,
        label="candidate graph",
    )
    try:
        graph_from_existing_loader = load_ifem_candidate_dependency_graph(
            graph_path,
            expected_file_sha256=graph_file_sha256,
            expected_content_sha256=graph.content_sha256,
        )
    except IFEMCandidateDependencyGraphError as error:
        raise IFEMClassificationTriageError("candidate graph failed strict graph replay") from error
    if graph_from_existing_loader != graph:
        raise IFEMClassificationTriageError("candidate graph changed between exact replays")
    census_plan, census_plan_file_sha256 = _load_typed_model(
        census_plan_path,
        IFEMPrerequisiteCensusPlanV1,
        label="census plan",
    )
    try:
        census_plan_from_existing_loader = load_ifem_prerequisite_census_plan(census_plan_path)
    except IFEMPrerequisiteCensusError as error:
        raise IFEMClassificationTriageError("census plan failed typed replay") from error
    if census_plan_from_existing_loader != census_plan:
        raise IFEMClassificationTriageError("census plan changed between exact replays")
    census_result, census_result_file_sha256 = _load_typed_model(
        census_result_path,
        IFEMPrerequisiteCensusResultV1,
        label="census result",
    )
    profile_summary, profile_summary_file_sha256 = _load_typed_model(
        profile_summary_path,
        IFEMPinnedMathlibProfilePublicSummaryV1,
        label="pinned profile public summary",
    )
    try:
        profile_summary_from_existing_loader = load_ifem_pinned_mathlib_profile_public_summary(
            profile_summary_path
        )
    except IFEMPinnedProfileError as error:
        raise IFEMClassificationTriageError(
            "pinned profile public summary failed typed replay"
        ) from error
    if profile_summary_from_existing_loader != profile_summary:
        raise IFEMClassificationTriageError(
            "pinned profile public summary changed between exact replays"
        )
    structural_corpus, structural_corpus_file_sha256 = _load_typed_model(
        structural_corpus_path,
        IFEMStructuralRoleProbeCorpusV1,
        label="structural probe corpus",
    )
    try:
        corpus_from_existing_loader = load_ifem_structural_role_probe_corpus(
            structural_corpus_path,
            expected_file_sha256=structural_corpus_file_sha256,
            expected_content_sha256=structural_corpus.content_sha256,
        )
    except IFEMStructuralRoleProbeError as error:
        raise IFEMClassificationTriageError(
            "structural corpus failed strict corpus replay"
        ) from error
    if corpus_from_existing_loader != structural_corpus:
        raise IFEMClassificationTriageError("structural corpus changed between exact replays")
    readiness_decision, readiness_decision_file_sha256 = _load_typed_model(
        readiness_decision_path,
        IFEMPilotReadinessDecisionV2,
        label="readiness decision",
    )
    try:
        readiness_from_existing_loader = load_ifem_pilot_readiness_decision(readiness_decision_path)
    except IFEMPilotReadinessError as error:
        raise IFEMClassificationTriageError("readiness decision failed typed replay") from error
    if readiness_from_existing_loader != readiness_decision:
        raise IFEMClassificationTriageError("readiness decision changed between exact replays")
    try:
        replayed_profile_plan = build_ifem_pinned_mathlib_profile_plan(
            census_plan_path=census_plan_path,
        )
    except (IFEMPinnedProfileError, IFEMPrerequisiteCensusError) as error:
        raise IFEMClassificationTriageError("cannot replay the pinned profile plan") from error
    evidence = IFEMClassificationTriageEvidenceBindingV1(
        candidate_graph_file_sha256=graph_file_sha256,
        candidate_graph_content_sha256=graph.content_sha256,
        census_plan_file_sha256=census_plan_file_sha256,
        census_plan_content_sha256=census_plan.content_sha256,
        census_result_file_sha256=census_result_file_sha256,
        census_result_content_sha256=census_result.content_sha256,
        pinned_profile_public_summary_file_sha256=profile_summary_file_sha256,
        pinned_profile_public_summary_content_sha256=profile_summary.content_sha256,
        pinned_profile_plan_content_sha256=replayed_profile_plan.content_sha256,
        structural_probe_corpus_file_sha256=structural_corpus_file_sha256,
        structural_probe_corpus_content_sha256=structural_corpus.content_sha256,
        structural_calibration_catalog_content_sha256=structural_corpus.catalog.content_sha256,
        readiness_decision_file_sha256=readiness_decision_file_sha256,
        readiness_decision_content_sha256=readiness_decision.content_sha256,
    )
    return _build_ifem_unknown_only_classification_triage(
        graph=graph,
        census_plan=census_plan,
        census_result=census_result,
        profile_summary=profile_summary,
        replayed_profile_plan=replayed_profile_plan,
        structural_corpus=structural_corpus,
        readiness_decision=readiness_decision,
        evidence=evidence,
    )


def verify_ifem_unknown_only_classification_triage_against_paths(
    triage: IFEMUnknownOnlyClassificationTriageV1,
    *,
    graph_path: Path = DEFAULT_GRAPH_PATH,
    census_plan_path: Path = DEFAULT_CENSUS_PLAN_PATH,
    census_result_path: Path = DEFAULT_CENSUS_RESULT_PATH,
    profile_summary_path: Path = DEFAULT_PROFILE_SUMMARY_PATH,
    structural_corpus_path: Path = DEFAULT_STRUCTURAL_CORPUS_PATH,
    readiness_decision_path: Path = DEFAULT_READINESS_DECISION_PATH,
) -> None:
    """Prove an artifact is the exact projection of the supplied input paths.

    Loading an artifact can only validate its canonical format and self-hash.
    This function is the public provenance boundary: it independently replays
    the six inputs and rejects an artifact whose evidence, projection, or
    content address differs from that replay.
    """

    actual = _revalidate_model(
        triage,
        IFEMUnknownOnlyClassificationTriageV1,
        label="unknown-only iFEM classification triage",
    )
    expected = build_ifem_unknown_only_classification_triage_from_paths(
        graph_path=graph_path,
        census_plan_path=census_plan_path,
        census_result_path=census_result_path,
        profile_summary_path=profile_summary_path,
        structural_corpus_path=structural_corpus_path,
        readiness_decision_path=readiness_decision_path,
    )
    if actual != expected:
        raise IFEMClassificationTriageError("triage artifact differs from exact input replay")


def _render_ifem_unknown_only_classification_triage(
    triage: IFEMUnknownOnlyClassificationTriageV1,
) -> bytes:
    """Canonically serialize one revalidated source-free triage artifact."""

    verified = _revalidate_model(
        triage,
        IFEMUnknownOnlyClassificationTriageV1,
        label="unknown-only iFEM classification triage",
    )
    rendered = canonical_json_bytes(verified.model_dump(mode="json")) + b"\n"
    forbidden_fields = (
        b'"candidate_declarations"',
        b'"canonical_type"',
        b'"declaration"',
        b'"direct_import"',
        b'"source_hint"',
    )
    if any(field in rendered for field in forbidden_fields):
        raise IFEMClassificationTriageError(
            "triage rendering leaked a forbidden source or Lean field"
        )
    return rendered


def _write_once(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError:
        try:
            existing, _ = _read_regular_file(path, label="existing triage output")
        except IFEMClassificationTriageError as error:
            raise IFEMClassificationTriageError("cannot inspect existing triage output") from error
        if existing != content:
            raise IFEMClassificationTriageError(
                "triage output already exists with different bytes"
            ) from None


def _write_ifem_unknown_only_classification_triage_once(
    path: Path,
    triage: IFEMUnknownOnlyClassificationTriageV1,
) -> None:
    """Write one previously replayed triage artifact without replacement."""

    _write_once(path, _render_ifem_unknown_only_classification_triage(triage))


def materialize_ifem_unknown_only_classification_triage_from_paths_once(
    output_path: Path,
    *,
    graph_path: Path = DEFAULT_GRAPH_PATH,
    census_plan_path: Path = DEFAULT_CENSUS_PLAN_PATH,
    census_result_path: Path = DEFAULT_CENSUS_RESULT_PATH,
    profile_summary_path: Path = DEFAULT_PROFILE_SUMMARY_PATH,
    structural_corpus_path: Path = DEFAULT_STRUCTURAL_CORPUS_PATH,
    readiness_decision_path: Path = DEFAULT_READINESS_DECISION_PATH,
) -> IFEMUnknownOnlyClassificationTriageV1:
    """Replay exact inputs and write their immutable source-free projection."""

    triage = build_ifem_unknown_only_classification_triage_from_paths(
        graph_path=graph_path,
        census_plan_path=census_plan_path,
        census_result_path=census_result_path,
        profile_summary_path=profile_summary_path,
        structural_corpus_path=structural_corpus_path,
        readiness_decision_path=readiness_decision_path,
    )
    _write_ifem_unknown_only_classification_triage_once(output_path, triage)
    return triage


def parse_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graph", type=Path, default=DEFAULT_GRAPH_PATH)
    parser.add_argument("--census-plan", type=Path, default=DEFAULT_CENSUS_PLAN_PATH)
    parser.add_argument("--census-result", type=Path, default=DEFAULT_CENSUS_RESULT_PATH)
    parser.add_argument("--profile-summary", type=Path, default=DEFAULT_PROFILE_SUMMARY_PATH)
    parser.add_argument("--structural-corpus", type=Path, default=DEFAULT_STRUCTURAL_CORPUS_PATH)
    parser.add_argument("--readiness-decision", type=Path, default=DEFAULT_READINESS_DECISION_PATH)
    parser.add_argument("--out", type=Path, required=True)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    namespace = parse_arguments(arguments)
    triage = materialize_ifem_unknown_only_classification_triage_from_paths_once(
        namespace.out,
        graph_path=namespace.graph,
        census_plan_path=namespace.census_plan,
        census_result_path=namespace.census_result,
        profile_summary_path=namespace.profile_summary,
        structural_corpus_path=namespace.structural_corpus,
        readiness_decision_path=namespace.readiness_decision,
    )
    print(triage.content_sha256)
    return 0


__all__ = [
    "DEFAULT_CENSUS_PLAN_PATH",
    "DEFAULT_CENSUS_RESULT_PATH",
    "DEFAULT_GRAPH_PATH",
    "DEFAULT_PROFILE_SUMMARY_PATH",
    "DEFAULT_READINESS_DECISION_PATH",
    "DEFAULT_STRUCTURAL_CORPUS_PATH",
    "TRIAGE_KIND",
    "TRIAGE_PROTOCOL",
    "TRIAGE_SCHEMA",
    "IFEMClassificationTriageAuthorityV1",
    "IFEMClassificationTriageError",
    "IFEMClassificationTriageNodeV1",
    "IFEMUnknownOnlyClassificationTriageV1",
    "build_ifem_unknown_only_classification_triage_from_paths",
    "load_ifem_unknown_only_classification_triage",
    "main",
    "materialize_ifem_unknown_only_classification_triage_from_paths_once",
    "verify_ifem_unknown_only_classification_triage_against_paths",
]
