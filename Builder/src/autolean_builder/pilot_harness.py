"""Versioned, Builder-only contracts for textbook-aligned pilot selection.

Pilot graphs are calibration plans, not theorem contracts and not Builder-to-Prover handoffs.
They commit to source anchors, independent review roles, library-census gates, and adversarial
feedback without copying textbook text into the repository.
"""

from __future__ import annotations

import hashlib
import json
from collections import deque
from collections.abc import Iterable
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal

from autolean_contracts import PermissionDecisionV1, RightsRecordV1
from autolean_contracts.base import ContractModel, utc_now
from autolean_contracts.hashing import canonical_json_bytes
from pydantic import Field, model_validator

from .reference_cache import ReferenceCache, ReferenceCacheError


class PilotHarnessError(ValueError):
    """A pilot manifest cannot safely advance towards statement drafting."""


class PilotAdmissionModeV1(StrEnum):
    CONDITIONAL_CANDIDATE = "conditional_candidate"
    OVERLAP_BLOCKED_REFERENCE = "overlap_blocked_reference"


class PilotSourceStatusV1(StrEnum):
    VERIFIED = "verified"
    VERIFIED_LOCAL_COPY = "verified_local_copy"
    PENDING_ACQUISITION = "pending_acquisition"
    RIGHTS_RESTRICTED = "rights_restricted"


class PilotSourceScopeV1(StrEnum):
    WORK_BEGINNING = "work_beginning"
    DECLARED_ENTRY_BOUNDARY = "declared_entry_boundary"


class PilotReviewStateV1(StrEnum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"


class PilotNodeKindV1(StrEnum):
    TEXTBOOK_DEFINITION = "textbook_definition"
    DEPENDENCY_LEMMA = "dependency_lemma"
    TARGET_CLAIM = "target_claim"
    MATHLIB_MAPPING = "mathlib_mapping"


class FeedbackGateKindV1(StrEnum):
    COUNTEREXAMPLE = "counterexample"
    OPPOSITE_CONCLUSION = "opposite_conclusion"


class PilotBlockerKindV1(StrEnum):
    UPSTREAM_OVERLAP = "upstream_overlap"
    SOURCE_PROVENANCE = "source_provenance"
    RIGHTS = "rights"
    MATHLIB_CENSUS = "mathlib_census"
    HUMAN_REVIEW = "human_review"


class PilotBlockerStateV1(StrEnum):
    ACTIVE = "active"
    RESOLVED = "resolved"


class CalibrationRoleV1(StrEnum):
    SOURCE_ANALYST = "source_analyst"
    NORMALIZER = "normalizer"
    MATHLIB_MAPPER = "mathlib_mapper"
    CHALLENGE_AUTHOR = "challenge_author"
    SEMANTIC_REVIEWER = "semantic_reviewer"


class TextbookAnchorV1(ContractModel):
    anchor_id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,63}$")
    human_locator: str = Field(min_length=1)
    start_offset: int = Field(ge=0)
    end_offset: int = Field(ge=1)
    raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_range(self) -> TextbookAnchorV1:
        if self.end_offset <= self.start_offset:
            raise ValueError("textbook anchor must have a nonempty byte range")
        return self


class TextbookReferenceBindingV1(ContractModel):
    reference_id: str = Field(pattern=r"^[a-z0-9][a-z0-9.-]{2,127}$")
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    parent_reference_id: str = Field(pattern=r"^[a-z0-9][a-z0-9.-]{2,127}$")
    parent_artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    license_expression: str = Field(min_length=1)
    attribution: str = Field(min_length=1)
    model_egress_policy: Literal["local_only"] = "local_only"
    anchors: tuple[TextbookAnchorV1, ...] = Field(min_length=1)
    source_scope: PilotSourceScopeV1
    entry_boundary_locator: str | None = Field(default=None, min_length=1)
    prior_dependency_scope: tuple[str, ...] = ()
    prior_dependency_review_state: PilotReviewStateV1

    @model_validator(mode="after")
    def validate_unique_anchors(self) -> TextbookReferenceBindingV1:
        identifiers = [anchor.anchor_id for anchor in self.anchors]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("textbook anchor identifiers must be unique")
        if self.source_scope is PilotSourceScopeV1.WORK_BEGINNING:
            if self.entry_boundary_locator is not None or self.prior_dependency_scope:
                raise ValueError("work-beginning source cannot declare an earlier dependency scope")
        elif self.entry_boundary_locator is None or not self.prior_dependency_scope:
            raise ValueError(
                "declared textbook entry boundary requires a locator and prior dependency scope"
            )
        return self


class PilotSourceAdmissionV1(ContractModel):
    status: PilotSourceStatusV1
    rationale: str = Field(min_length=1)
    reference: TextbookReferenceBindingV1 | None = None
    proposed_work: str | None = Field(default=None, min_length=1)
    proposed_source_url: str | None = Field(default=None, min_length=1)
    proposed_license: str | None = Field(default=None, min_length=1)
    proposed_artifact_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    proposed_source_revision: str | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def validate_status_binding(self) -> PilotSourceAdmissionV1:
        if _is_verified_source_status(self.status):
            if self.reference is None:
                raise ValueError("verified pilot sources require a cache reference binding")
            if any(
                value is not None
                for value in (
                    self.proposed_work,
                    self.proposed_source_url,
                    self.proposed_license,
                    self.proposed_artifact_sha256,
                    self.proposed_source_revision,
                )
            ):
                raise ValueError("verified pilot sources cannot carry unresolved source proposals")
        elif self.reference is not None:
            raise ValueError("unverified pilot sources cannot carry a cache reference binding")
        elif not self.proposed_work:
            raise ValueError("unverified pilot sources must name the source work under review")
        return self


class MathlibCensusGateV1(ContractModel):
    observed_revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    observed_at: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    scope: str = Field(min_length=1)
    observation: str = Field(min_length=1)
    current_review_state: PilotReviewStateV1
    target_mathlib_revision: str | None = Field(default=None, pattern=r"^[0-9a-f]{40}$")
    lake_manifest_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    search_protocol_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    result_artifact_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_replay_evidence(self) -> MathlibCensusGateV1:
        replay_fields = (
            self.target_mathlib_revision,
            self.lake_manifest_sha256,
            self.search_protocol_sha256,
            self.result_artifact_sha256,
        )
        if self.current_review_state is PilotReviewStateV1.ACCEPTED and any(
            value is None for value in replay_fields
        ):
            raise ValueError("accepted mathlib census requires a replayable evidence closure")
        return self


class CalibrationReviewEvidenceV1(ContractModel):
    reviewer_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
    independence_group: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    review_state: PilotReviewStateV1


class CalibrationRequirementV1(ContractModel):
    role: CalibrationRoleV1
    required_independence_groups: int = Field(ge=1, le=4)
    review_state: PilotReviewStateV1
    reviews: tuple[CalibrationReviewEvidenceV1, ...] = ()

    @model_validator(mode="after")
    def validate_review_evidence(self) -> CalibrationRequirementV1:
        reviewers = [review.reviewer_id for review in self.reviews]
        if len(reviewers) != len(set(reviewers)):
            raise ValueError("calibration requirement reviewer IDs must be unique")
        accepted_groups = {
            review.independence_group
            for review in self.reviews
            if review.review_state is PilotReviewStateV1.ACCEPTED
        }
        if self.review_state is PilotReviewStateV1.ACCEPTED:
            if any(review.review_state is PilotReviewStateV1.REJECTED for review in self.reviews):
                raise ValueError("accepted calibration requirement cannot contain a rejection")
            if len(accepted_groups) < self.required_independence_groups:
                raise ValueError("accepted calibration requirement lacks independent review groups")
        return self


class PilotNodeV1(ContractModel):
    node_id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,63}$")
    kind: PilotNodeKindV1
    summary: str = Field(min_length=1)
    normalized_claim: str = Field(min_length=1)
    formalization_target: str = Field(min_length=1)
    source_anchor_ids: tuple[str, ...] = ()
    depends_on: tuple[str, ...] = ()
    review_state: PilotReviewStateV1
    review_evidence_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_review_evidence(self) -> PilotNodeV1:
        if self.review_state is PilotReviewStateV1.ACCEPTED and self.review_evidence_sha256 is None:
            raise ValueError("accepted pilot node requires review evidence")
        return self


class FeedbackGateV1(ContractModel):
    gate_id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,63}$")
    kind: FeedbackGateKindV1
    target_node_id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,63}$")
    challenged_conclusion: str = Field(min_length=1)
    concrete_witness: str = Field(min_length=1)
    expected_disposition: Literal["reject_challenged_conclusion"]
    review_state: PilotReviewStateV1
    review_evidence_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_review_evidence(self) -> FeedbackGateV1:
        if self.review_state is PilotReviewStateV1.ACCEPTED and self.review_evidence_sha256 is None:
            raise ValueError("accepted feedback gate requires review evidence")
        return self


class PilotAdmissionBlockerV1(ContractModel):
    blocker_id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,95}$")
    kind: PilotBlockerKindV1
    state: PilotBlockerStateV1
    evidence: str = Field(min_length=1)
    resolution_required: str = Field(min_length=1)


class PilotGraphV1(ContractModel):
    graph_id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,95}$")
    admission_mode: PilotAdmissionModeV1
    domain: str = Field(min_length=1)
    source: PilotSourceAdmissionV1
    mathlib_census: MathlibCensusGateV1
    calibration_requirements: tuple[CalibrationRequirementV1, ...] = Field(min_length=3)
    nodes: tuple[PilotNodeV1, ...] = Field(min_length=3)
    feedback_gates: tuple[FeedbackGateV1, ...] = Field(min_length=1)
    blockers: tuple[PilotAdmissionBlockerV1, ...] = ()

    @model_validator(mode="after")
    def validate_graph(self) -> PilotGraphV1:
        node_by_id = {node.node_id: node for node in self.nodes}
        if len(node_by_id) != len(self.nodes):
            raise ValueError("pilot node identifiers must be unique")
        requirement_roles = [requirement.role for requirement in self.calibration_requirements]
        if len(requirement_roles) != len(set(requirement_roles)):
            raise ValueError("pilot calibration roles must be unique")
        required_roles = {
            CalibrationRoleV1.NORMALIZER,
            CalibrationRoleV1.CHALLENGE_AUTHOR,
            CalibrationRoleV1.SEMANTIC_REVIEWER,
        }
        if not required_roles <= set(requirement_roles):
            raise ValueError("pilot graph lacks an independent calibration role")
        blocker_ids = [blocker.blocker_id for blocker in self.blockers]
        if len(blocker_ids) != len(set(blocker_ids)):
            raise ValueError("pilot admission blocker identifiers must be unique")
        anchor_ids = (
            {anchor.anchor_id for anchor in self.source.reference.anchors}
            if self.source.reference is not None
            else set()
        )
        roots: list[PilotNodeV1] = []
        for node in self.nodes:
            if len(node.depends_on) != len(set(node.depends_on)):
                raise ValueError("pilot node dependencies must be unique")
            if node.node_id in node.depends_on:
                raise ValueError("pilot node cannot depend on itself")
            if not set(node.depends_on) <= set(node_by_id):
                raise ValueError("pilot node dependency is absent from the graph")
            if _is_verified_source_status(self.source.status):
                if not node.source_anchor_ids or not set(node.source_anchor_ids) <= anchor_ids:
                    raise ValueError("verified pilot node must cite known textbook anchors")
            elif node.source_anchor_ids:
                raise ValueError("unverified pilot node cannot claim source anchors")
            if not node.depends_on:
                roots.append(node)
        if len(roots) != 1 or roots[0].kind is not PilotNodeKindV1.TEXTBOOK_DEFINITION:
            raise ValueError("pilot graph must start from exactly one textbook definition")
        _assert_acyclic(self.nodes)
        gate_ids = [gate.gate_id for gate in self.feedback_gates]
        if len(gate_ids) != len(set(gate_ids)):
            raise ValueError("feedback gate identifiers must be unique")
        if not {gate.target_node_id for gate in self.feedback_gates} <= set(node_by_id):
            raise ValueError("feedback gate targets an absent pilot node")
        if self.admission_mode is PilotAdmissionModeV1.OVERLAP_BLOCKED_REFERENCE and not any(
            blocker.kind is PilotBlockerKindV1.UPSTREAM_OVERLAP
            and blocker.state is PilotBlockerStateV1.ACTIVE
            for blocker in self.blockers
        ):
            raise ValueError("overlap-blocked reference graph needs an active overlap blocker")
        return self

    def target_closure(self, target_node_id: str) -> tuple[PilotNodeV1, ...]:
        node_by_id = {node.node_id: node for node in self.nodes}
        if target_node_id not in node_by_id:
            raise PilotHarnessError(f"pilot target node is absent: {target_node_id}")
        pending = [target_node_id]
        included: set[str] = set()
        while pending:
            node_id = pending.pop()
            if node_id in included:
                continue
            included.add(node_id)
            pending.extend(node_by_id[node_id].depends_on)
        return tuple(node for node in self.nodes if node.node_id in included)

    def admission_blocker_ids(self, target_node_id: str | None = None) -> frozenset[str]:
        """Return unresolved gates; only an empty set permits statement drafting."""

        blockers = {
            blocker.blocker_id
            for blocker in self.blockers
            if blocker.state is PilotBlockerStateV1.ACTIVE
        }
        if not _is_verified_source_status(self.source.status):
            blockers.add("source-provenance-pending")
        elif (
            self.source.reference is not None
            and self.source.reference.prior_dependency_review_state
            is not PilotReviewStateV1.ACCEPTED
        ):
            blockers.add("textbook-entry-dependencies-pending")
        if self.mathlib_census.current_review_state is not PilotReviewStateV1.ACCEPTED:
            blockers.add("current-mathlib-census-pending")
        for requirement in self.calibration_requirements:
            if requirement.review_state is not PilotReviewStateV1.ACCEPTED:
                blockers.add(f"review-{requirement.role.value}-pending")
        selected_nodes = (
            self.nodes if target_node_id is None else self.target_closure(target_node_id)
        )
        selected_node_ids = {node.node_id for node in selected_nodes}
        for node in selected_nodes:
            if node.review_state is not PilotReviewStateV1.ACCEPTED:
                blockers.add(f"node-{node.node_id}-review-pending")
        for gate in self.feedback_gates:
            if (
                gate.target_node_id in selected_node_ids
                and gate.review_state is not PilotReviewStateV1.ACCEPTED
            ):
                blockers.add(f"feedback-{gate.gate_id}-pending")
        if self.admission_mode is PilotAdmissionModeV1.OVERLAP_BLOCKED_REFERENCE:
            blockers.add("reference-only-overlap-blocked")
        return frozenset(blockers)

    def assert_ready_for_statement_drafting(self, target_node_id: str | None = None) -> None:
        blockers = self.admission_blocker_ids(target_node_id)
        if blockers:
            message = "pilot graph cannot enter Builder statement drafting: "
            raise PilotHarnessError(message + ", ".join(sorted(blockers)))

    def assert_not_prover_handoffable(self) -> None:
        raise PilotHarnessError(
            "pilot graphs are calibration artifacts; only frozen StatementContractV1 may cross "
            "to Prover"
        )


class PilotAdmissionReceiptV1(ContractModel):
    """A replayable binding from an accepted pilot target to one rights-reviewed draft."""

    schema_version: Literal["autolean.pilot-admission-receipt.v1"] = (
        "autolean.pilot-admission-receipt.v1"
    )
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    graph_id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,95}$")
    graph_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_node_id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,63}$")
    target_closure_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    rights_record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    issued_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def validate_time(self) -> PilotAdmissionReceiptV1:
        if self.issued_at.tzinfo is None:
            raise ValueError("pilot admission receipt timestamp must be timezone-aware")
        return self


class PilotManifestV1(ContractModel):
    schema_version: Literal["autolean.builder-pilot-manifest.v1"] = (
        "autolean.builder-pilot-manifest.v1"
    )
    protocol: Literal["autolean.builder-pilot.v1"] = "autolean.builder-pilot.v1"
    prover_handoff: Literal["forbidden"] = "forbidden"
    graphs: tuple[PilotGraphV1, ...] = Field(min_length=2)

    @model_validator(mode="after")
    def validate_manifest(self) -> PilotManifestV1:
        identifiers = [graph.graph_id for graph in self.graphs]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("pilot graph identifiers must be unique")
        if not self.parallel_candidates():
            raise ValueError("pilot manifest requires at least one conditional candidate")
        return self

    def parallel_candidates(self) -> tuple[PilotGraphV1, ...]:
        return tuple(
            graph
            for graph in self.graphs
            if graph.admission_mode is PilotAdmissionModeV1.CONDITIONAL_CANDIDATE
        )

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self) + b"\n"

    def graph(self, graph_id: str) -> PilotGraphV1:
        matching = tuple(graph for graph in self.graphs if graph.graph_id == graph_id)
        if len(matching) != 1:
            raise PilotHarnessError(f"pilot graph is absent or ambiguous: {graph_id}")
        return matching[0]

    def issue_admission_receipt(
        self,
        *,
        graph_id: str,
        target_node_id: str,
        rights: RightsRecordV1,
        issued_at: datetime | None = None,
    ) -> PilotAdmissionReceiptV1:
        graph = self.graph(graph_id)
        graph.assert_ready_for_statement_drafting(target_node_id)
        if rights.overall_decision not in {
            PermissionDecisionV1.ALLOW,
            PermissionDecisionV1.RESTRICTED,
        }:
            raise PilotHarnessError("pilot admission requires an allow or restricted rights review")
        closure = graph.target_closure(target_node_id)
        return PilotAdmissionReceiptV1(
            manifest_sha256=_sha256(self.canonical_bytes()),
            graph_id=graph.graph_id,
            graph_sha256=_sha256(canonical_json_bytes(graph)),
            target_node_id=target_node_id,
            target_closure_sha256=_sha256(
                canonical_json_bytes(tuple(node.model_dump(mode="json") for node in closure))
            ),
            rights_record_sha256=_sha256(canonical_json_bytes(rights)),
            issued_at=issued_at or utc_now(),
        )

    def validate_admission_receipt(
        self,
        receipt: PilotAdmissionReceiptV1,
        *,
        rights: RightsRecordV1,
    ) -> None:
        expected = self.issue_admission_receipt(
            graph_id=receipt.graph_id,
            target_node_id=receipt.target_node_id,
            rights=rights,
            issued_at=receipt.issued_at,
        )
        if receipt != expected:
            raise PilotHarnessError("pilot admission receipt does not bind the current manifest")


def load_pilot_manifest(path: Path) -> PilotManifestV1:
    """Load an immutable pilot contract while rejecting duplicate JSON keys."""

    try:
        raw = path.read_bytes()
    except OSError as error:
        raise PilotHarnessError(f"cannot read pilot manifest: {path}") from error
    try:
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except ValueError as error:
        raise PilotHarnessError(str(error)) from error
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PilotHarnessError("pilot manifest is not valid UTF-8 JSON") from error
    try:
        return PilotManifestV1.model_validate(payload)
    except ValueError as error:
        raise PilotHarnessError(f"pilot manifest is invalid: {error}") from error


def verify_cached_textbook_alignment(
    manifest: PilotManifestV1,
    cache: ReferenceCache,
) -> tuple[str, ...]:
    """Re-verify cached source bindings without exposing textbook excerpts."""

    verified_anchor_ids: list[str] = []
    for graph in manifest.graphs:
        binding = graph.source.reference
        if binding is None:
            continue
        try:
            derived = cache.verify(binding.reference_id)
            parent = cache.verify(binding.parent_reference_id)
        except ReferenceCacheError as error:
            raise PilotHarnessError(
                f"{graph.graph_id}: source cache verification failed"
            ) from error
        if (
            derived.manifest_sha256 != binding.manifest_sha256
            or derived.entry.sha256 != binding.artifact_sha256
            or derived.entry.model_egress_policy.value != binding.model_egress_policy
            or derived.entry.license.expression != binding.license_expression
            or derived.entry.attribution != binding.attribution
            or derived.entry.derivation is None
            or derived.entry.derivation.parent_reference_id != binding.parent_reference_id
            or derived.entry.derivation.parent_sha256 != binding.parent_artifact_sha256
            or parent.entry.sha256 != binding.parent_artifact_sha256
        ):
            raise PilotHarnessError(f"{graph.graph_id}: reference provenance binding changed")
        for anchor in binding.anchors:
            try:
                cache.verify_utf8_span_digest(
                    binding.reference_id,
                    start_offset=anchor.start_offset,
                    end_offset=anchor.end_offset,
                    expected_sha256=anchor.raw_sha256,
                )
            except ReferenceCacheError as error:
                raise PilotHarnessError(
                    f"{graph.graph_id}: textbook anchor {anchor.anchor_id} no longer binds"
                ) from error
            verified_anchor_ids.append(f"{graph.graph_id}:{anchor.anchor_id}")
    return tuple(verified_anchor_ids)


def _assert_acyclic(nodes: Iterable[PilotNodeV1]) -> None:
    node_tuple = tuple(nodes)
    indegree = {node.node_id: len(node.depends_on) for node in node_tuple}
    dependents: dict[str, list[str]] = {node.node_id: [] for node in node_tuple}
    for node in node_tuple:
        for dependency in node.depends_on:
            dependents[dependency].append(node.node_id)
    queue = deque(node_id for node_id, count in indegree.items() if count == 0)
    visited = 0
    while queue:
        node_id = queue.popleft()
        visited += 1
        for dependent in dependents[node_id]:
            indegree[dependent] -= 1
            if indegree[dependent] == 0:
                queue.append(dependent)
    if visited != len(node_tuple):
        raise ValueError("pilot dependency graph must be acyclic")


def _is_verified_source_status(status: PilotSourceStatusV1) -> bool:
    return status in {
        PilotSourceStatusV1.VERIFIED,
        PilotSourceStatusV1.VERIFIED_LOCAL_COPY,
    }


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key in pilot manifest: {key}")
        result[key] = value
    return result
