"""Read-only discovery-lane manifests for Phase 2 source selection.

These manifests sit *before* the pilot-admission harness.  They bind public
metadata, rights ceilings, overlap-query status, and stop gates without
claiming a source span, a Mathlib coverage result, a frozen statement, or a
Prover handoff.  The iFEM denominator is content-addressed before its first
Mathlib query so a later result cannot be reused after adding easy nodes.
"""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from pathlib import Path
from typing import Literal, cast

from autolean_contracts import canonical_json_bytes
from autolean_contracts.base import ContractModel
from pydantic import Field, model_validator

_ID = r"^[a-z][a-z0-9-]{2,95}$"
_SHA256 = r"^[0-9a-f]{64}$"
_MATHLIB_REVISION = r"^[0-9a-f]{40}$"


class DiscoveryManifestError(ValueError):
    """A Phase 2 discovery artifact crosses an admission boundary or drifts."""


class DiscoverySourceByteStateV1(StrEnum):
    METADATA_ONLY = "metadata_only"
    ACQUIRED_LOCAL_ONLY = "acquired_local_only"


class DiscoveryRightsStateV1(StrEnum):
    METADATA_VERIFIED_EGRESS_PENDING = "metadata_verified_egress_pending"
    OPERATOR_LICENSE_REQUIRED = "operator_license_required"


class DiscoveryMathlibOverlapStateV1(StrEnum):
    NOT_QUERIED = "not_queried"


class DiscoveryNodeKindV1(StrEnum):
    DEFINITION = "definition"
    PREREQUISITE_THEOREM = "prerequisite_theorem"
    EXAMPLE = "example"
    TERMINAL_TARGET = "terminal_target"


class DiscoveryTextbookStageV1(StrEnum):
    OPENING = "opening"
    PREREQUISITE_CHAPTERS = "prerequisite_chapters"
    TERMINAL_CHAPTER = "terminal_chapter"


class DiscoverySourceIdentityV1(ContractModel):
    source_id: str = Field(pattern=_ID)
    official_record_url: str = Field(min_length=1)
    source_path: tuple[str, ...] = Field(min_length=1)
    resolved_revision: str | None = Field(default=None, min_length=1)
    source_bytes_state: DiscoverySourceByteStateV1 = DiscoverySourceByteStateV1.METADATA_ONLY
    source_lock_receipt_sha256: str | None = Field(default=None, pattern=_SHA256)
    reference_manifest_candidate_sha256: str | None = Field(default=None, pattern=_SHA256)
    rights_state: DiscoveryRightsStateV1
    license_expression: str = Field(min_length=1)
    license_evidence_url: str = Field(min_length=1)
    model_egress_ceiling: Literal["local_only"] = "local_only"
    external_model_source_text: Literal["forbidden"] = "forbidden"
    discovery_evidence_refs: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_source_byte_state(self) -> DiscoverySourceIdentityV1:
        bound_hashes = (
            self.source_lock_receipt_sha256,
            self.reference_manifest_candidate_sha256,
        )
        if self.source_bytes_state is DiscoverySourceByteStateV1.METADATA_ONLY:
            if any(value is not None for value in bound_hashes):
                raise ValueError("metadata-only discovery source cannot bind acquired bytes")
        elif (
            self.resolved_revision is None
            or any(value is None for value in bound_hashes)
            or self.model_egress_ceiling != "local_only"
        ):
            raise ValueError(
                "acquired local-only source requires revision, receipt, and manifest hashes"
            )
        return self


class DiscoveryMathlibOverlapV1(ContractModel):
    mathlib_revision: str = Field(pattern=_MATHLIB_REVISION)
    state: Literal[DiscoveryMathlibOverlapStateV1.NOT_QUERIED] = (
        DiscoveryMathlibOverlapStateV1.NOT_QUERIED
    )
    observed_coverage: Literal["not_observed"] = "not_observed"
    evidence_refs: tuple[str, ...] = Field(min_length=1)
    discovery_note: str = Field(min_length=1)


class DiscoveryStopGateV1(ContractModel):
    gate_id: str = Field(pattern=_ID)
    blocks: tuple[str, ...] = Field(min_length=1)
    resolution_required: str = Field(min_length=1)


class DiscoveryNodeV1(ContractModel):
    """A prospective mathematical node, never a source span or Lean declaration."""

    node_id: str = Field(pattern=_ID)
    kind: DiscoveryNodeKindV1
    textbook_stage: DiscoveryTextbookStageV1
    source_order: int = Field(ge=1)
    summary: str = Field(min_length=1)
    depends_on: tuple[str, ...] = ()
    included_in_prerequisite_denominator: bool

    @model_validator(mode="after")
    def validate_membership(self) -> DiscoveryNodeV1:
        included_kind = {
            DiscoveryNodeKindV1.DEFINITION,
            DiscoveryNodeKindV1.PREREQUISITE_THEOREM,
        }
        if self.included_in_prerequisite_denominator != (self.kind in included_kind):
            raise ValueError(
                "only definitions and prerequisite theorems may enter the prerequisite denominator"
            )
        return self


class FrozenPrerequisiteDenominatorV1(ContractModel):
    """A pre-query, content-addressed denominator for an honest overlap census."""

    denominator_id: str = Field(pattern=_ID)
    revision: str = Field(pattern=r"^[a-z][a-z0-9-]{2,95}-r(?:0[1-9]|[1-9][0-9]+)-[0-9a-f]{12}$")
    predecessor_content_sha256: str | None = Field(default=None, pattern=_SHA256)
    textbook_opening_path: tuple[str, ...] = Field(min_length=1)
    score_policy_percent: tuple[int, int]
    selected_terminal_node_id: str = Field(pattern=_ID)
    nodes: tuple[DiscoveryNodeV1, ...] = Field(min_length=4)
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_denominator(self) -> FrozenPrerequisiteDenominatorV1:
        if self.score_policy_percent != (70, 80):
            raise ValueError("the iFEM denominator keeps the fixed 70--80 percent policy band")
        node_by_id = {node.node_id: node for node in self.nodes}
        if len(node_by_id) != len(self.nodes):
            raise ValueError("denominator node IDs must be unique")
        if [node.source_order for node in self.nodes] != list(range(1, len(self.nodes) + 1)):
            raise ValueError("denominator source order must be a contiguous frozen sequence")
        first = self.nodes[0]
        if first.textbook_stage is not DiscoveryTextbookStageV1.OPENING:
            raise ValueError("the denominator must begin with a textbook-opening node")
        if not any(
            node.kind is DiscoveryNodeKindV1.DEFINITION
            and node.textbook_stage is DiscoveryTextbookStageV1.OPENING
            for node in self.nodes
        ):
            raise ValueError("the denominator must retain a textbook-opening definition")
        if not any(
            node.kind is DiscoveryNodeKindV1.EXAMPLE
            and node.textbook_stage is DiscoveryTextbookStageV1.OPENING
            for node in self.nodes
        ):
            raise ValueError("the denominator must retain a textbook-opening example")
        for node in self.nodes:
            if len(node.depends_on) != len(set(node.depends_on)):
                raise ValueError("denominator node dependencies must be unique")
            if node.node_id in node.depends_on or not set(node.depends_on) <= set(node_by_id):
                raise ValueError("denominator dependency is absent or self-referential")
            if any(
                node_by_id[parent].source_order >= node.source_order for parent in node.depends_on
            ):
                raise ValueError("denominator dependencies must precede their dependent node")
        target = node_by_id.get(self.selected_terminal_node_id)
        if target is None or target.kind is not DiscoveryNodeKindV1.TERMINAL_TARGET:
            raise ValueError("denominator must name one terminal target")
        if target.included_in_prerequisite_denominator:
            raise ValueError("terminal target cannot enter the prerequisite denominator")
        target_ancestors: set[str] = set()
        frontier = list(target.depends_on)
        while frontier:
            ancestor_id = frontier.pop()
            if ancestor_id in target_ancestors:
                continue
            target_ancestors.add(ancestor_id)
            frontier.extend(node_by_id[ancestor_id].depends_on)
        unrelated_prerequisites = {
            node.node_id
            for node in self.nodes
            if node.included_in_prerequisite_denominator and node.node_id not in target_ancestors
        }
        if unrelated_prerequisites:
            raise ValueError(
                "every prerequisite-denominator node must be in the selected terminal "
                "dependency closure"
            )
        if not any(node.kind is DiscoveryNodeKindV1.EXAMPLE for node in self.nodes):
            raise ValueError("denominator must retain an excluded textbook-alignment example")
        if not any(node.included_in_prerequisite_denominator for node in self.nodes):
            raise ValueError("denominator must contain prerequisites")
        if self.content_sha256 != self.computed_content_sha256():
            raise ValueError(
                "prerequisite denominator content hash does not match its frozen nodes"
            )
        if not self.revision.startswith(f"{self.denominator_id}-r") or not self.revision.endswith(
            f"-{self.content_sha256[:12]}"
        ):
            raise ValueError("denominator revision must commit to its content hash prefix")
        revision_counter = self.revision.removeprefix(f"{self.denominator_id}-r").split(
            "-", maxsplit=1
        )[0]
        if int(revision_counter) == 1 and self.predecessor_content_sha256 is not None:
            raise ValueError("the initial denominator revision cannot name a predecessor")
        if int(revision_counter) > 1 and self.predecessor_content_sha256 is None:
            raise ValueError("a successor denominator revision must bind its predecessor hash")
        return self

    def content_payload(self) -> dict[str, object]:
        """Return the immutable denominator projection, excluding its own digest."""

        payload = self.model_dump(mode="json", exclude={"content_sha256", "revision"})
        return cast(dict[str, object], payload)

    def computed_content_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.content_payload())).hexdigest()


class PrecompileCensusPlanV1(ContractModel):
    """The only permitted bridge from a frozen denominator to a future query."""

    denominator_id: str = Field(pattern=_ID)
    denominator_revision: str = Field(
        pattern=r"^[a-z][a-z0-9-]{2,95}-r(?:0[1-9]|[1-9][0-9]+)-[0-9a-f]{12}$"
    )
    denominator_content_sha256: str = Field(pattern=_SHA256)
    mathlib_revision: str = Field(pattern=_MATHLIB_REVISION)
    state: Literal["not_started"] = "not_started"
    result_artifact_sha256: None = None

    def assert_binds(self, denominator: FrozenPrerequisiteDenominatorV1) -> None:
        if (
            self.denominator_id != denominator.denominator_id
            or self.denominator_revision != denominator.revision
            or self.denominator_content_sha256 != denominator.content_sha256
        ):
            raise DiscoveryManifestError(
                "precompile census plan does not bind this frozen prerequisite denominator"
            )


class DiscoveryLaneV1(ContractModel):
    lane_id: str = Field(pattern=_ID)
    status: Literal["discovery"] = "discovery"
    source: DiscoverySourceIdentityV1
    mathlib_overlap: DiscoveryMathlibOverlapV1
    stop_gates: tuple[DiscoveryStopGateV1, ...] = Field(min_length=1)
    non_claims: tuple[str, ...] = Field(min_length=4)
    prerequisite_denominator: FrozenPrerequisiteDenominatorV1 | None = None
    precompile_census_plan: PrecompileCensusPlanV1 | None = None

    @model_validator(mode="after")
    def validate_lane(self) -> DiscoveryLaneV1:
        gate_ids = [gate.gate_id for gate in self.stop_gates]
        if len(gate_ids) != len(set(gate_ids)):
            raise ValueError("discovery stop-gate IDs must be unique")
        required_non_claims = {
            "builder_freeze_forbidden",
            "prover_handoff_forbidden",
            "mathlib_coverage_not_claimed",
            "production_pilot_not_selected",
        }
        if not required_non_claims <= set(self.non_claims):
            raise ValueError("discovery lane lacks a required non-claim")
        if (self.prerequisite_denominator is None) != (self.precompile_census_plan is None):
            raise ValueError("a precompile census plan and frozen denominator must appear together")
        if self.prerequisite_denominator is not None and self.precompile_census_plan is not None:
            self.precompile_census_plan.assert_binds(self.prerequisite_denominator)
            if (
                self.precompile_census_plan.mathlib_revision
                != self.mathlib_overlap.mathlib_revision
            ):
                raise ValueError(
                    "precompile census plan and overlap record pin different Mathlib revisions"
                )
        return self


class DiscoveryLaneManifestV1(ContractModel):
    """Public-metadata discovery only; it cannot issue admission or handoff authority."""

    schema_version: Literal["autolean.phase2-discovery-lane-manifest.v1"] = (
        "autolean.phase2-discovery-lane-manifest.v1"
    )
    protocol: Literal["autolean.builder-discovery.v1"] = "autolean.builder-discovery.v1"
    state: Literal["discovery"] = "discovery"
    builder_freeze: Literal["forbidden"] = "forbidden"
    prover_handoff: Literal["forbidden"] = "forbidden"
    lanes: tuple[DiscoveryLaneV1, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_manifest(self) -> DiscoveryLaneManifestV1:
        lane_ids = [lane.lane_id for lane in self.lanes]
        if len(lane_ids) != len(set(lane_ids)):
            raise ValueError("discovery lane IDs must be unique")
        return self

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self) + b"\n"

    def assert_not_prover_handoffable(self) -> None:
        raise DiscoveryManifestError(
            "discovery manifests are public-metadata planning artifacts; only frozen "
            "StatementContractV1 may cross to Prover"
        )


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise DiscoveryManifestError(f"duplicate JSON key in discovery manifest: {key}")
        document[key] = value
    return document


def load_discovery_lane_manifest(path: Path) -> DiscoveryLaneManifestV1:
    """Load a strict, duplicate-key-safe discovery manifest from a public artifact."""

    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as error:
        raise DiscoveryManifestError(f"cannot read discovery manifest: {path}") from error
    try:
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as error:
        raise DiscoveryManifestError("discovery manifest is not valid UTF-8 JSON") from error
    if not isinstance(payload, dict):
        raise DiscoveryManifestError("discovery manifest must be a JSON object")
    try:
        return DiscoveryLaneManifestV1.model_validate(payload)
    except ValueError as error:
        raise DiscoveryManifestError(f"discovery manifest is invalid: {error}") from error
