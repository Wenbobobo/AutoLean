"""Versioned, Builder-only contracts for textbook-aligned pilot selection.

Pilot graphs are calibration plans, not theorem contracts and not Builder-to-Prover handoffs.
They commit to source anchors, independent review roles, library-census gates, and adversarial
feedback without copying textbook text into the repository.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal

from autolean_contracts import AxiomProfileV1, PermissionDecisionV1, RightsRecordV1
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


class PilotBoundaryDispositionV2(StrEnum):
    GAP = "gap"
    BACKUP = "backup"


class PilotRuleCoverageStateV2(StrEnum):
    EXACT = "exact"
    DELIBERATE_SUBSET = "deliberate_subset"
    BLOCKING_GAP = "blocking_gap"
    MISMATCH = "mismatch"
    UNVERIFIED = "unverified"


class PilotAgentReviewRoleV2(StrEnum):
    SOURCE_INTERPRETER = "source_interpreter"
    FORMAL_ARCHITECT = "formal_architect"
    ADVERSARIAL_REVIEWER = "adversarial_reviewer"
    RESEARCH_ALIGNMENT = "research_alignment"
    LIBRARY_STEWARD = "library_steward"


class PilotNonClaimV2(StrEnum):
    NO_HUMAN_OR_EXPERT_REVIEW = "no_human_or_expert_review"
    NOT_FULL_LK = "not_full_lk"
    NO_COMPLETENESS_CLAIM = "no_completeness_claim"
    NOT_A_FROZEN_CONTRACT = "not_a_frozen_contract"
    NO_PROVER_HANDOFF = "no_prover_handoff"
    NO_PROMOTION = "no_promotion"
    NO_OPEN_PROBLEM_CLAIM = "no_open_problem_claim"
    NO_MODEL_EGRESS_AUTHORIZATION = "no_model_egress_authorization"


_V2_REQUIRED_NON_CLAIMS = frozenset(PilotNonClaimV2)
_LEAN_MODULE_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$")
_LEAN_BUILD_VERSION = re.compile(r"^Lean \(version ([0-9]+\.[0-9]+\.[0-9]+),")


def pilot_candidate_binding_sha256(
    *,
    candidate_id: str,
    revision: str,
    boundary_summary: str,
    required_mechanisms: tuple[str, ...],
    out_of_scope: tuple[str, ...],
) -> str:
    """Hash the complete inline candidate boundary, not an unattested identifier."""

    return _sha256(
        canonical_json_bytes(
            {
                "schema_version": "autolean.pilot-candidate-binding.v2",
                "candidate_id": candidate_id,
                "revision": revision,
                "boundary_summary": boundary_summary,
                "required_mechanisms": required_mechanisms,
                "out_of_scope": out_of_scope,
            }
        )
    )


def pilot_formal_environment_sha256(
    *,
    lean_toolchain: str,
    lean_version: str,
    lean_build_identity: str,
    mathlib_revision: str,
    lake_manifest_sha256: str,
    imports_allowlist: tuple[str, ...],
    axioms_allowlist: tuple[str, ...],
    axiom_profile: AxiomProfileV1,
    proof_slot_profile: str,
    allowed_write_paths: tuple[str, ...],
    worker_image_digest: str,
) -> str:
    """Hash every execution fact that must survive Builder-to-Prover handoff."""

    return _sha256(
        canonical_json_bytes(
            {
                "schema_version": "autolean.pilot-formal-environment.v2",
                "lean_toolchain": lean_toolchain,
                "lean_version": lean_version,
                "lean_build_identity": lean_build_identity,
                "mathlib_revision": mathlib_revision,
                "lake_manifest_sha256": lake_manifest_sha256,
                "imports_allowlist": imports_allowlist,
                "axioms_allowlist": axioms_allowlist,
                "axiom_profile": axiom_profile.value,
                "proof_slot_profile": proof_slot_profile,
                "allowed_write_paths": allowed_write_paths,
                "worker_image_digest": worker_image_digest,
            }
        )
    )


class PilotCandidateBindingV2(ContractModel):
    candidate_id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,95}$")
    revision: str = Field(min_length=1, max_length=128)
    boundary_summary: str = Field(min_length=1)
    required_mechanisms: tuple[str, ...] = Field(min_length=1)
    out_of_scope: tuple[str, ...] = Field(min_length=1)
    candidate_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    predecessor_revision: str = Field(min_length=1, max_length=128)
    predecessor_candidate_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_revision(self) -> PilotCandidateBindingV2:
        if self.revision == self.predecessor_revision:
            raise ValueError("V2 candidate revision must differ from its predecessor")
        for label, values in (
            ("required mechanisms", self.required_mechanisms),
            ("out-of-scope boundaries", self.out_of_scope),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"V2 candidate {label} must be unique")
            if any(not item.strip() or item != item.strip() for item in values):
                raise ValueError(f"V2 candidate {label} must be trimmed")
        expected = pilot_candidate_binding_sha256(
            candidate_id=self.candidate_id,
            revision=self.revision,
            boundary_summary=self.boundary_summary,
            required_mechanisms=self.required_mechanisms,
            out_of_scope=self.out_of_scope,
        )
        if self.candidate_sha256 != expected:
            raise ValueError("V2 candidate hash does not bind its inline boundary")
        return self


class PilotRuleAnchorBindingV2(ContractModel):
    anchor_id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,63}$")
    start_offset: int = Field(ge=0)
    end_offset: int = Field(ge=1)
    raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    human_locator: str | None = Field(default=None, min_length=1, max_length=512)

    @model_validator(mode="after")
    def validate_range(self) -> PilotRuleAnchorBindingV2:
        if self.end_offset <= self.start_offset:
            raise ValueError("V2 rule anchor must have a nonempty byte range")
        if self.human_locator is not None and self.human_locator != self.human_locator.strip():
            raise ValueError("V2 rule anchor human locator must be trimmed")
        return self


class PilotSourceBindingV2(ContractModel):
    reference_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reference_id: str = Field(pattern=r"^[a-z0-9][a-z0-9.-]{2,127}$")
    source_artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    parent_reference_id: str = Field(pattern=r"^[a-z0-9][a-z0-9.-]{2,127}$")
    parent_artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    anchors: tuple[PilotRuleAnchorBindingV2, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_anchors(self) -> PilotSourceBindingV2:
        anchor_ids = [anchor.anchor_id for anchor in self.anchors]
        if len(anchor_ids) != len(set(anchor_ids)):
            raise ValueError("V2 source anchor identifiers must be unique")
        return self


@dataclass(frozen=True, slots=True)
class _RetainedCompileEnvironmentV2:
    lean_toolchain: str
    lean_version: str
    mathlib_revision: str
    lake_manifest_sha256: str


class PilotImplementationEvidenceV2(ContractModel):
    module_name: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$")
    source_path: str = Field(pattern=r"^[A-Za-z0-9_.\-/]+\.lean$")
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    declarations: tuple[str, ...] = Field(min_length=1)
    compile_chain: tuple[str, ...] = Field(min_length=1)
    compile_packet_path: str = Field(pattern=r"^[A-Za-z0-9_.\-/]+\.json$")
    compile_packet_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    compile_packet_content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    compile_receipt_path: str = Field(pattern=r"^[A-Za-z0-9_.\-/]+\.json$")
    compile_receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    build_report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    library_input_tree_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_paths_and_declarations(self) -> PilotImplementationEvidenceV2:
        paths = {
            "source": self.source_path,
            "compile packet": self.compile_packet_path,
            "compile receipt": self.compile_receipt_path,
        }
        for label, raw_path in paths.items():
            path = Path(raw_path)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError(f"V2 implementation {label} path must be repository-relative")
        if len(set(paths.values())) != len(paths):
            raise ValueError("V2 implementation evidence paths must differ")
        if len(self.declarations) != len(set(self.declarations)):
            raise ValueError("V2 implementation declarations must be unique")
        if any(not item.strip() or item != item.strip() for item in self.declarations):
            raise ValueError("V2 implementation declarations must be trimmed")
        if len(self.compile_chain) != len(set(self.compile_chain)):
            raise ValueError("V2 implementation compile chain must be unique")
        if any(_LEAN_MODULE_NAME.fullmatch(item) is None for item in self.compile_chain):
            raise ValueError("V2 implementation compile chain contains an invalid module")
        if self.compile_chain[0] != self.module_name:
            raise ValueError("V2 implementation compile chain must begin at its source module")
        return self

    def assert_matches_workspace(self, root: Path) -> _RetainedCompileEnvironmentV2:
        """Recompute retained source, packet, receipt, and their internal backlinks."""

        source_raw = _read_workspace_file(root, self.source_path, label="V2 Lean source")
        if _sha256(source_raw) != self.source_sha256:
            raise PilotHarnessError("V2 implementation source digest differs from workspace")
        packet_raw = _read_workspace_file(root, self.compile_packet_path, label="V2 compile packet")
        if _sha256(packet_raw) != self.compile_packet_sha256:
            raise PilotHarnessError("V2 compile packet digest differs from workspace")
        receipt_raw = _read_workspace_file(
            root, self.compile_receipt_path, label="V2 compile receipt"
        )
        if _sha256(receipt_raw) != self.compile_receipt_sha256:
            raise PilotHarnessError("V2 compile receipt digest differs from workspace")

        packet = _decode_json_object(packet_raw, label="V2 compile packet")
        receipt = _decode_json_object(receipt_raw, label="V2 compile receipt")
        packet_without_backlink = dict(packet)
        backlink = _json_object(
            packet_without_backlink.pop("compile_receipt", None),
            label="V2 compile packet receipt backlink",
        )
        if (
            _sha256(canonical_json_bytes(packet_without_backlink))
            != self.compile_packet_content_sha256
        ):
            raise PilotHarnessError("V2 compile packet content digest differs")
        receipt_backlink_paths = {self.compile_receipt_path}
        receipt_path = Path(self.compile_receipt_path)
        if receipt_path.parts and receipt_path.parts[0] == "Library":
            receipt_backlink_paths.add(Path(*receipt_path.parts[1:]).as_posix())
        if (
            _json_string(backlink.get("path"), label="V2 compile receipt backlink path")
            not in receipt_backlink_paths
            or _json_string(backlink.get("sha256"), label="V2 compile receipt backlink digest")
            != self.compile_receipt_sha256
        ):
            raise PilotHarnessError("V2 compile packet receipt backlink differs")

        if (
            _json_string(
                receipt.get("packet_content_sha256"),
                label="V2 receipt packet content digest",
            )
            != self.compile_packet_content_sha256
            or _json_string(
                receipt.get("source_tree_sha256"),
                label="V2 receipt source tree digest",
            )
            != self.library_input_tree_sha256
            or _json_string(
                receipt.get("build_report_sha256"),
                label="V2 receipt build report digest",
            )
            != self.build_report_sha256
        ):
            raise PilotHarnessError("V2 compile receipt evidence bindings differ")

        packet_environment = _json_object(
            packet.get("environment"), label="V2 compile packet environment"
        )
        receipt_environment = _json_object(
            receipt.get("environment"), label="V2 compile receipt environment"
        )
        lean_toolchain = _json_string(
            receipt_environment.get("lean_toolchain"), label="V2 receipt Lean toolchain"
        )
        mathlib_revision = _json_string(
            receipt_environment.get("mathlib_revision"), label="V2 receipt mathlib revision"
        )
        lake_manifest_sha256 = _json_string(
            receipt_environment.get("lake_manifest_sha256"),
            label="V2 receipt lake manifest",
        )
        if (
            _json_string(packet_environment.get("lean_toolchain"), label="V2 packet Lean toolchain")
            != lean_toolchain
            or _json_string(
                packet_environment.get("mathlib_revision"),
                label="V2 packet mathlib revision",
            )
            != mathlib_revision
            or _json_string(
                packet_environment.get("lake_manifest_sha256"),
                label="V2 packet lake manifest",
            )
            != lake_manifest_sha256
        ):
            raise PilotHarnessError("V2 packet and receipt environments differ")

        build_report = _json_object(receipt.get("build_report"), label="V2 compile build report")
        if _sha256(canonical_json_bytes(build_report)) != self.build_report_sha256:
            raise PilotHarnessError("V2 compile build report digest differs")
        receipt_targets = _json_string_tuple(
            receipt.get("targets"), label="V2 compile receipt targets"
        )
        report_targets = _json_string_tuple(
            build_report.get("targets"), label="V2 build report targets"
        )
        if (
            self.compile_chain[-1] not in receipt_targets
            or report_targets != receipt_targets
            or _json_string(
                packet_environment.get("build_target"),
                label="V2 compile packet build target",
            )
            != self.compile_chain[-1]
        ):
            raise PilotHarnessError("V2 implementation compile chain differs")
        lean_version = _json_string(build_report.get("lean_version"), label="build Lean version")
        if (
            _json_string(build_report.get("source_tree_sha256"), label="build source tree")
            != self.library_input_tree_sha256
            or _json_string(build_report.get("mathlib_revision"), label="build mathlib revision")
            != mathlib_revision
            or _json_string(build_report.get("lake_manifest_sha256"), label="build lake manifest")
            != lake_manifest_sha256
            or _json_string(build_report.get("toolchain"), label="build toolchain")
            != lean_toolchain
            or build_report.get("status") != "passed"
            or receipt.get("build_exit_code") != 0
            or build_report.get("contains_absolute_paths") is not False
            or build_report.get("contains_raw_build_output") is not False
            or receipt.get("contains_absolute_paths") is not False
            or receipt.get("contains_raw_build_output") is not False
        ):
            raise PilotHarnessError("V2 compile build report is not an admissible clean build")
        fixtures = _json_object_tuple(packet.get("fixtures"), label="V2 compile packet fixtures")
        if not any(
            fixture.get("module") == self.module_name and fixture.get("result") == "compiled"
            for fixture in fixtures
        ):
            raise PilotHarnessError("V2 compile packet does not retain the implementation module")
        return _RetainedCompileEnvironmentV2(
            lean_toolchain=lean_toolchain,
            lean_version=lean_version,
            mathlib_revision=mathlib_revision,
            lake_manifest_sha256=lake_manifest_sha256,
        )


class PilotFormalProfileV2(ContractModel):
    lean_toolchain: str = Field(min_length=1)
    toolchain_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    lean_version: str = Field(pattern=r"^v[0-9]+\.[0-9]+\.[0-9]+$")
    lean_build_identity: str = Field(min_length=1)
    mathlib_revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    lake_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    environment_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    imports_allowlist: tuple[str, ...] = Field(min_length=1)
    axioms_allowlist: tuple[str, ...] = ()
    axiom_profile: AxiomProfileV1
    axiom_evidence_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    proof_slot_profile: Literal["lean-exact-declaration-boundary.v1"] = (
        "lean-exact-declaration-boundary.v1"
    )
    allowed_write_paths: tuple[Literal["Proof.lean"], ...] = ("Proof.lean",)
    worker_image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_profile(self) -> PilotFormalProfileV2:
        if _sha256(self.lean_toolchain.encode("utf-8")) != self.toolchain_sha256:
            raise ValueError("V2 toolchain hash does not bind lean_toolchain")
        for label, values in (
            ("imports", self.imports_allowlist),
            ("axioms", self.axioms_allowlist),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"V2 formal profile {label} must be unique")
            if any(not item.strip() or item != item.strip() for item in values):
                raise ValueError(f"V2 formal profile {label} must be trimmed")
        if self.allowed_write_paths != ("Proof.lean",):
            raise ValueError("V2 admission profile permits only the Proof.lean proof slot")
        expected_environment = pilot_formal_environment_sha256(
            lean_toolchain=self.lean_toolchain,
            lean_version=self.lean_version,
            lean_build_identity=self.lean_build_identity,
            mathlib_revision=self.mathlib_revision,
            lake_manifest_sha256=self.lake_manifest_sha256,
            imports_allowlist=self.imports_allowlist,
            axioms_allowlist=self.axioms_allowlist,
            axiom_profile=self.axiom_profile,
            proof_slot_profile=self.proof_slot_profile,
            allowed_write_paths=self.allowed_write_paths,
            worker_image_digest=self.worker_image_digest,
        )
        if self.environment_sha256 != expected_environment:
            raise ValueError("V2 environment hash does not bind its formal profile")
        return self


class PilotRuleMatrixEntryV2(ContractModel):
    rule_id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,95}$")
    source_anchor_ids: tuple[str, ...] = Field(min_length=1)
    implementation_declarations: tuple[str, ...] = ()
    coverage_state: PilotRuleCoverageStateV2
    rationale: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_references(self) -> PilotRuleMatrixEntryV2:
        if len(self.source_anchor_ids) != len(set(self.source_anchor_ids)):
            raise ValueError("V2 rule matrix source anchors must be unique")
        if len(self.implementation_declarations) != len(set(self.implementation_declarations)):
            raise ValueError("V2 rule matrix declarations must be unique")
        if (
            self.coverage_state is not PilotRuleCoverageStateV2.BLOCKING_GAP
            and not self.implementation_declarations
        ):
            raise ValueError("V2 non-gap rule coverage requires an implementation declaration")
        return self


class PilotAgentReviewEvidenceV2(ContractModel):
    role: PilotAgentReviewRoleV2
    reviewer_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
    reviewer_kind: Literal["automated_agent"] = "automated_agent"
    independence_group: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
    context_pack_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    output_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    execution_run_receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    review_state: PilotReviewStateV1
    claims_human_or_expert_authority: Literal[False] = False


class PilotBoundaryDecisionV2(ContractModel):
    """Replayable automated gap/backup evidence, never an admission capability."""

    schema_version: Literal["autolean.pilot-boundary-decision.v2"] = (
        "autolean.pilot-boundary-decision.v2"
    )
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    graph_id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,95}$")
    graph_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_node_id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,63}$")
    target_closure_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate: PilotCandidateBindingV2
    source: PilotSourceBindingV2
    implementation: PilotImplementationEvidenceV2
    formal_profile: PilotFormalProfileV2
    rule_matrix: tuple[PilotRuleMatrixEntryV2, ...] = Field(min_length=1)
    rule_matrix_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    agent_reviews: tuple[PilotAgentReviewEvidenceV2, ...] = Field(min_length=1)
    disposition: PilotBoundaryDispositionV2
    blocker_ids: tuple[str, ...] = ()
    non_claims: tuple[PilotNonClaimV2, ...] = Field(min_length=1)
    authority: Literal["automated_agent_evidence_only"] = "automated_agent_evidence_only"
    issued_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def validate_decision(self) -> PilotBoundaryDecisionV2:
        if self.issued_at.tzinfo is None or self.issued_at.utcoffset() is None:
            raise ValueError("V2 boundary decision timestamp must be timezone-aware")
        if self.rule_matrix_sha256 != _rule_matrix_sha256(self.rule_matrix):
            raise ValueError("V2 rule matrix hash does not bind its rows")
        rule_ids = [item.rule_id for item in self.rule_matrix]
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("V2 rule matrix identifiers must be unique")
        anchor_ids = {anchor.anchor_id for anchor in self.source.anchors}
        matrix_anchor_ids = {
            anchor_id for item in self.rule_matrix for anchor_id in item.source_anchor_ids
        }
        if matrix_anchor_ids != anchor_ids:
            raise ValueError("V2 rule matrix must cover exactly the bound source anchors")
        declarations = set(self.implementation.declarations)
        if any(
            not set(item.implementation_declarations) <= declarations for item in self.rule_matrix
        ):
            raise ValueError("V2 rule matrix references an unbound implementation declaration")
        reviewer_ids = [review.reviewer_id for review in self.agent_reviews]
        groups = [review.independence_group for review in self.agent_reviews]
        roles = [review.role for review in self.agent_reviews]
        if len(reviewer_ids) != len(set(reviewer_ids)):
            raise ValueError("V2 agent reviewer identities must be unique")
        if len(groups) != len(set(groups)):
            raise ValueError("V2 agent independence groups must be unique")
        if len(roles) != len(set(roles)):
            raise ValueError("V2 agent review roles must be unique")
        if len(self.blocker_ids) != len(set(self.blocker_ids)):
            raise ValueError("V2 boundary blocker identifiers must be unique")
        if any(not blocker.strip() or blocker != blocker.strip() for blocker in self.blocker_ids):
            raise ValueError("V2 boundary blockers must be trimmed")
        if set(self.non_claims) != _V2_REQUIRED_NON_CLAIMS:
            raise ValueError("V2 boundary decision lacks the required non-claims")
        if not self.blocker_ids:
            raise ValueError("V2 gap or backup decision requires machine-readable blockers")
        return self

    def canonical_sha256(self) -> str:
        return _sha256(canonical_json_bytes(self))

    def assert_binds_manifest(self, manifest: PilotManifestV1) -> None:
        if self.manifest_sha256 != _sha256(manifest.canonical_bytes()):
            raise PilotHarnessError("V2 boundary decision binds another pilot manifest")
        graph = manifest.graph(self.graph_id)
        if self.graph_sha256 != _sha256(canonical_json_bytes(graph)):
            raise PilotHarnessError("V2 boundary decision binds another pilot graph")
        closure = graph.target_closure(self.target_node_id)
        expected_closure_sha256 = _sha256(
            canonical_json_bytes(tuple(node.model_dump(mode="json") for node in closure))
        )
        if self.target_closure_sha256 != expected_closure_sha256:
            raise PilotHarnessError("V2 boundary decision target closure changed")
        reference = graph.source.reference
        if reference is None:
            raise PilotHarnessError("V2 boundary decision graph lacks a source binding")
        expected_anchor_ids = {
            anchor_id for node in closure for anchor_id in node.source_anchor_ids
        }
        bound_anchor_ids = {anchor.anchor_id for anchor in self.source.anchors}
        if (
            self.source.reference_manifest_sha256 != reference.manifest_sha256
            or self.source.reference_id != reference.reference_id
            or self.source.source_artifact_sha256 != reference.artifact_sha256
            or self.source.parent_reference_id != reference.parent_reference_id
            or self.source.parent_artifact_sha256 != reference.parent_artifact_sha256
            or not expected_anchor_ids <= bound_anchor_ids
        ):
            raise PilotHarnessError("V2 boundary decision source binding changed")
        graph_anchors = {anchor.anchor_id: anchor for anchor in reference.anchors}
        if any(
            anchor.anchor_id in graph_anchors
            and (
                anchor.start_offset != graph_anchors[anchor.anchor_id].start_offset
                or anchor.end_offset != graph_anchors[anchor.anchor_id].end_offset
                or anchor.raw_sha256 != graph_anchors[anchor.anchor_id].raw_sha256
            )
            for anchor in self.source.anchors
        ):
            raise PilotHarnessError("V2 boundary decision source anchors changed")
        if any(
            anchor.anchor_id not in graph_anchors and anchor.human_locator is None
            for anchor in self.source.anchors
        ):
            raise PilotHarnessError("V2 granular source anchors require a human locator")

    def assert_matches_reference_cache(self, cache: ReferenceCache) -> None:
        """Recheck all V2 spans by digest without returning source text."""

        try:
            derived = cache.verify(self.source.reference_id)
            parent = cache.verify(self.source.parent_reference_id)
        except ReferenceCacheError as error:
            raise PilotHarnessError("V2 source cache verification failed") from error
        derivation = derived.entry.derivation
        if (
            derived.manifest_sha256 != self.source.reference_manifest_sha256
            or derived.entry.sha256 != self.source.source_artifact_sha256
            or parent.entry.sha256 != self.source.parent_artifact_sha256
            or derivation is None
            or derivation.parent_reference_id != self.source.parent_reference_id
            or derivation.parent_sha256 != self.source.parent_artifact_sha256
        ):
            raise PilotHarnessError("V2 reference-cache provenance binding changed")
        for anchor in self.source.anchors:
            try:
                cache.verify_utf8_span_digest(
                    self.source.reference_id,
                    start_offset=anchor.start_offset,
                    end_offset=anchor.end_offset,
                    expected_sha256=anchor.raw_sha256,
                )
            except ReferenceCacheError as error:
                raise PilotHarnessError(
                    f"V2 source anchor no longer binds: {anchor.anchor_id}"
                ) from error

    def assert_matches_workspace(self, root: Path) -> None:
        environment = self.implementation.assert_matches_workspace(root)
        if (
            environment.lean_toolchain != self.formal_profile.lean_toolchain
            or environment.lean_version != self.formal_profile.lean_build_identity
            or _lean_release_version(environment.lean_version) != self.formal_profile.lean_version
            or environment.mathlib_revision != self.formal_profile.mathlib_revision
            or environment.lake_manifest_sha256 != self.formal_profile.lake_manifest_sha256
        ):
            raise PilotHarnessError("V2 compile evidence differs from its formal profile")


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


def load_pilot_boundary_decision(path: Path) -> PilotBoundaryDecisionV2:
    """Load a replayable V2 decision while rejecting ambiguous JSON."""

    try:
        raw = path.read_bytes()
    except OSError as error:
        raise PilotHarnessError(f"cannot read pilot boundary decision: {path}") from error
    try:
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_decision_keys)
    except ValueError as error:
        raise PilotHarnessError(str(error)) from error
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PilotHarnessError("pilot boundary decision is not valid UTF-8 JSON") from error
    try:
        return PilotBoundaryDecisionV2.model_validate(payload)
    except ValueError as error:
        raise PilotHarnessError(f"pilot boundary decision is invalid: {error}") from error


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


def _read_workspace_file(root: Path, relative_path: str, *, label: str) -> bytes:
    try:
        resolved_root = root.resolve(strict=True)
        unresolved = resolved_root / Path(relative_path)
        resolved = unresolved.resolve(strict=True)
    except OSError as error:
        raise PilotHarnessError(f"{label} is absent from workspace") from error
    if not resolved.is_relative_to(resolved_root) or resolved != unresolved:
        raise PilotHarnessError(f"{label} escapes or aliases the workspace")
    if not resolved.is_file() or resolved.is_symlink():
        raise PilotHarnessError(f"{label} must be a retained regular file")
    try:
        return resolved.read_bytes()
    except OSError as error:
        raise PilotHarnessError(f"cannot read {label}") from error


def _decode_json_object(raw: bytes, *, label: str) -> dict[str, object]:
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_evidence_keys)
    except ValueError as error:
        raise PilotHarnessError(f"{label} is ambiguous: {error}") from error
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PilotHarnessError(f"{label} is not valid UTF-8 JSON") from error
    return _json_object(value, label=label)


def _json_object(value: object, *, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise PilotHarnessError(f"{label} must be a JSON object")
    return value


def _json_object_tuple(value: object, *, label: str) -> tuple[dict[str, object], ...]:
    if not isinstance(value, (list, tuple)):
        raise PilotHarnessError(f"{label} must be a JSON array")
    return tuple(_json_object(item, label=f"{label} item") for item in value)


def _json_string(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise PilotHarnessError(f"{label} must be nonempty trimmed text")
    return value


def _json_string_tuple(value: object, *, label: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise PilotHarnessError(f"{label} must be a JSON string array")
    result = tuple(_json_string(item, label=f"{label} item") for item in value)
    if len(result) != len(set(result)):
        raise PilotHarnessError(f"{label} must contain unique values")
    return result


def _lean_release_version(observed: str) -> str:
    match = _LEAN_BUILD_VERSION.match(observed)
    if match is None:
        raise PilotHarnessError("V2 compile evidence has an unsupported Lean version string")
    return f"v{match.group(1)}"


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _rule_matrix_sha256(matrix: tuple[PilotRuleMatrixEntryV2, ...]) -> str:
    return _sha256(canonical_json_bytes(tuple(item.model_dump(mode="json") for item in matrix)))


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key in pilot manifest: {key}")
        result[key] = value
    return result


def _reject_duplicate_decision_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key in pilot boundary decision: {key}")
        result[key] = value
    return result


def _reject_duplicate_evidence_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON evidence key: {key}")
        result[key] = value
    return result
