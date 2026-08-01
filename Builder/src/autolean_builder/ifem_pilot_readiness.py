"""Falsifiable iFEM discovery-readiness gate for the frozen prerequisite slice.

This module consumes content-addressed Builder census and singleton-direct-import
observations.  It does not discover mappings, decide semantic equivalence,
freeze a statement contract, or submit work to Prover.  Its only output is a
bounded readiness decision for the *current* 21-node iFEM discovery slice.

The v2 decision contract deliberately distinguishes an exact direct import from
the transitive module closure loaded by that import.  P2-07 records both facts,
but no closure-acceptance policy has yet been frozen.  Consequently v2 cannot
return ``go`` merely because the five direct imports match their plan.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections.abc import Sequence
from enum import StrEnum
from pathlib import Path
from typing import Literal, cast

from autolean_contracts import canonical_json_bytes
from autolean_contracts.base import ContractModel
from pydantic import Field, model_validator

from .ifem_pinned_mathlib_profiles import (
    DEFAULT_PLAN_PATH as DEFAULT_PROFILE_PLAN_PATH,
)
from .ifem_pinned_mathlib_profiles import (
    IFEMPinnedMathlibProfileBuildReceiptV1,
    IFEMPinnedMathlibProfileExecutionStateV1,
    IFEMPinnedMathlibProfileObservationsV1,
    IFEMPinnedMathlibProfilePlanV1,
    IFEMPinnedMathlibProfileResultV1,
)
from .ifem_prerequisite_census import (
    DEFAULT_PLAN_PATH as DEFAULT_CENSUS_PLAN_PATH,
)
from .ifem_prerequisite_census import (
    IFEMPrerequisiteCensusPlanV1,
    IFEMPrerequisiteCensusResultV1,
    IFEMPrerequisiteClassificationV1,
    IFEMQueryExecutionStateV1,
    load_ifem_prerequisite_census_plan,
    validate_result_against_plan,
)

ROOT = Path(__file__).resolve().parents[3]

DECISION_SCHEMA = "autolean.ifem-pilot-readiness-decision.v2"
PROTOCOL = "autolean.builder-ifem-pilot-readiness.v2"
_SHA256 = r"^[0-9a-f]{64}$"
_NODE_ID = r"^[a-z][a-z0-9-]{2,95}$"

_CRITICAL_RESTRICTION_NODES: tuple[str, ...] = (
    "ifem-restricted-bilinear-form",
    "ifem-restricted-coercivity",
    "ifem-restricted-continuity",
    "ifem-restricted-functional",
)
_MINIMUM_DIRECT_OR_THIN = 15
_MAXIMUM_DIRECT_OR_THIN = 16


class IFEMPilotReadinessError(ValueError):
    """The decision inputs are incomplete or do not share a frozen boundary."""


class IFEMPilotReadinessOutcomeV1(StrEnum):
    """A decision about this discovery slice, never an admission decision."""

    GO = "go"
    NO_GO = "no_go"
    INCOMPLETE = "incomplete"


class IFEMPilotProfileEvidenceStateV2(StrEnum):
    NOT_SUPPLIED = "not_supplied"
    NOT_COMPLETED = "not_completed"
    DIRECT_IMPORTS_BOUND_CLOSURE_UNREVIEWED = "direct_imports_bound_closure_unreviewed"
    WRONG_DIRECT_IMPORT = "wrong_direct_import"


class IFEMPilotReadinessReasonV2(StrEnum):
    CONDITIONS_SATISFIED = "all_frozen_readiness_conditions_satisfied"
    CENSUS_NOT_COMPLETED = "census_execution_not_completed"
    SEMANTIC_CLASSIFICATION_INCOMPLETE = "prerequisite_semantic_classification_incomplete"
    PROFILE_EVIDENCE_NOT_SUPPLIED = "singleton_import_evidence_not_supplied"
    PROFILE_EVIDENCE_NOT_COMPLETED = "singleton_import_evidence_not_completed"
    WRONG_DIRECT_IMPORT = "singleton_direct_import_is_not_the_frozen_profile"
    TRANSITIVE_CLOSURE_POLICY_UNRESOLVED = "transitive_import_closure_acceptance_policy_unresolved"
    RESTRICTION_API_MISSING = "critical_restriction_api_classified_missing"
    RESTRICTION_API_NOT_OBSERVED = (
        "critical_restriction_api_not_observed_under_exact_direct_import_profiles"
    )
    COVERAGE_BELOW_BAND = "reviewed_direct_or_thin_coverage_below_frozen_band"
    COVERAGE_ABOVE_BAND = "reviewed_direct_or_thin_coverage_above_frozen_band"


class IFEMPilotReadinessAuthorityV1(ContractModel):
    """The gate remains below semantic admission and every promotion boundary."""

    semantic_mapping_authorized: Literal[False] = False
    source_rights_authorized: Literal[False] = False
    local_calibration_authorized: Literal[False] = False
    builder_freeze_authorized: Literal[False] = False
    library_promotion_authorized: Literal[False] = False
    prover_handoff_authorized: Literal[False] = False
    proof_submission_authorized: Literal[False] = False


class IFEMPilotReadinessPolicyV2(ContractModel):
    """The precommitted threshold and critical API set for this one slice."""

    policy_id: Literal["ifem-coercive-galerkin-readiness-r02"] = (
        "ifem-coercive-galerkin-readiness-r02"
    )
    denominator_node_count: Literal[21] = 21
    minimum_direct_or_thin: Literal[15] = 15
    maximum_direct_or_thin: Literal[16] = 16
    critical_restriction_nodes: tuple[str, ...] = _CRITICAL_RESTRICTION_NODES
    transitive_closure_acceptance: Literal["unresolved"] = "unresolved"

    @model_validator(mode="after")
    def validate_policy(self) -> IFEMPilotReadinessPolicyV2:
        if self.critical_restriction_nodes != _CRITICAL_RESTRICTION_NODES:
            raise ValueError("critical iFEM restriction-node policy drifted")
        return self

    def content_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self)).hexdigest()


class IFEMPilotReadinessEvidenceBindingV1(ContractModel):
    """All referenced evidence is immutable and bound to one census plan."""

    census_plan_content_sha256: str = Field(pattern=_SHA256)
    census_result_content_sha256: str = Field(pattern=_SHA256)
    profile_plan_content_sha256: str | None = Field(default=None, pattern=_SHA256)
    profile_result_content_sha256: str | None = Field(default=None, pattern=_SHA256)
    profile_observation_content_sha256: str | None = Field(default=None, pattern=_SHA256)
    profile_build_receipt_content_sha256: str | None = Field(default=None, pattern=_SHA256)

    @model_validator(mode="after")
    def validate_profile_evidence_shape(self) -> IFEMPilotReadinessEvidenceBindingV1:
        profile_fields = (
            self.profile_plan_content_sha256,
            self.profile_result_content_sha256,
            self.profile_observation_content_sha256,
            self.profile_build_receipt_content_sha256,
        )
        if profile_fields[0] is None and any(value is not None for value in profile_fields[1:]):
            raise ValueError("profile evidence cannot omit its frozen profile plan")
        if profile_fields[0] is not None and profile_fields[1] is None:
            raise ValueError("profile plan evidence requires its result record")
        if (profile_fields[2] is None) != (profile_fields[3] is None):
            raise ValueError("profile observation and build receipt must appear together")
        return self


class IFEMPilotReadinessCountsV1(ContractModel):
    denominator_node_count: int = Field(ge=1)
    direct_count: int = Field(ge=0)
    thin_adapter_count: int = Field(ge=0)
    missing_count: int = Field(ge=0)
    unknown_count: int = Field(ge=0)
    direct_or_thin_count: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_counts(self) -> IFEMPilotReadinessCountsV1:
        if self.direct_or_thin_count != self.direct_count + self.thin_adapter_count:
            raise ValueError("direct-or-thin count does not equal its components")
        if (
            self.direct_count + self.thin_adapter_count + self.missing_count + self.unknown_count
            != self.denominator_node_count
        ):
            raise ValueError("classification counts do not exhaust the denominator")
        return self


class IFEMCriticalRestrictionStateV2(ContractModel):
    node_id: str = Field(pattern=_NODE_ID)
    classification: IFEMPrerequisiteClassificationV1
    mapped_declarations: tuple[str, ...] = ()
    observed_under_exact_direct_import_profiles: bool | None = None

    @model_validator(mode="after")
    def validate_state(self) -> IFEMCriticalRestrictionStateV2:
        if self.node_id not in _CRITICAL_RESTRICTION_NODES:
            raise ValueError("critical state contains a non-critical node")
        if self.mapped_declarations != tuple(sorted(set(self.mapped_declarations))):
            raise ValueError("critical mapped declarations must be sorted and unique")
        if self.classification in {
            IFEMPrerequisiteClassificationV1.DIRECT,
            IFEMPrerequisiteClassificationV1.THIN_ADAPTER,
        }:
            if not self.mapped_declarations:
                raise ValueError("mapped restriction state needs mapped declarations")
        elif self.mapped_declarations:
            raise ValueError("unmapped restriction state carries declarations")
        if (
            self.observed_under_exact_direct_import_profiles is not None
            and self.classification
            not in {
                IFEMPrerequisiteClassificationV1.DIRECT,
                IFEMPrerequisiteClassificationV1.THIN_ADAPTER,
            }
        ):
            raise ValueError("only mapped restriction states can have import observations")
        return self


class IFEMPilotReadinessDecisionV2(ContractModel):
    """One deterministic P2-08 decision with no promotion authority."""

    schema_version: Literal["autolean.ifem-pilot-readiness-decision.v2"] = (
        "autolean.ifem-pilot-readiness-decision.v2"
    )
    protocol: Literal["autolean.builder-ifem-pilot-readiness.v2"] = (
        "autolean.builder-ifem-pilot-readiness.v2"
    )
    outcome: IFEMPilotReadinessOutcomeV1
    census_execution_state: IFEMQueryExecutionStateV1
    reasons: tuple[IFEMPilotReadinessReasonV2, ...] = Field(min_length=1)
    policy: IFEMPilotReadinessPolicyV2
    policy_content_sha256: str = Field(pattern=_SHA256)
    evidence: IFEMPilotReadinessEvidenceBindingV1
    counts: IFEMPilotReadinessCountsV1
    profile_evidence_state: IFEMPilotProfileEvidenceStateV2
    direct_imports_verified: bool
    transitive_closure_policy_resolved: Literal[False] = False
    critical_restriction_states: tuple[IFEMCriticalRestrictionStateV2, ...] = Field(
        min_length=4,
        max_length=4,
    )
    authority: IFEMPilotReadinessAuthorityV1 = IFEMPilotReadinessAuthorityV1()
    builder_freeze: Literal["forbidden"] = "forbidden"
    prover_handoff: Literal["forbidden"] = "forbidden"
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_decision(self) -> IFEMPilotReadinessDecisionV2:
        if self.reasons != tuple(sorted(set(self.reasons), key=str)):
            raise ValueError("readiness reasons must be sorted and unique")
        if self.policy_content_sha256 != self.policy.content_sha256():
            raise ValueError("readiness policy hash does not match the frozen policy")
        if tuple(item.node_id for item in self.critical_restriction_states) != (
            _CRITICAL_RESTRICTION_NODES
        ):
            raise ValueError("critical restriction state order drifted")
        if self.authority != IFEMPilotReadinessAuthorityV1():
            raise ValueError("readiness decision authority flags drifted")
        expected_direct_imports_verified = (
            self.profile_evidence_state
            is IFEMPilotProfileEvidenceStateV2.DIRECT_IMPORTS_BOUND_CLOSURE_UNREVIEWED
        )
        if self.direct_imports_verified is not expected_direct_imports_verified:
            raise ValueError("direct-import verification flag contradicts profile evidence")
        expected_outcome, expected_reasons = _decision_reasons(
            census_execution_state=self.census_execution_state,
            counts=self.counts,
            profile_state=self.profile_evidence_state,
            critical_states=self.critical_restriction_states,
        )
        if self.outcome is not expected_outcome or self.reasons != expected_reasons:
            raise ValueError("readiness outcome or reasons do not follow from its evidence fields")
        if self.content_sha256 != self.computed_content_sha256():
            raise ValueError("readiness decision content hash does not match its payload")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(dict[str, object], self.model_dump(mode="json", exclude={"content_sha256"}))

    def computed_content_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.content_payload())).hexdigest()


def _exact_instance(value: object, expected_type: type[object], *, label: str) -> None:
    if type(value) is not expected_type:
        raise IFEMPilotReadinessError(f"{label} must use its exact model type")


def _classification_counts(result: IFEMPrerequisiteCensusResultV1) -> IFEMPilotReadinessCountsV1:
    counts = {classification: 0 for classification in IFEMPrerequisiteClassificationV1}
    for node in result.node_results:
        counts[node.evidence.classification] += 1
    return IFEMPilotReadinessCountsV1(
        denominator_node_count=result.denominator.prerequisite_node_count,
        direct_count=counts[IFEMPrerequisiteClassificationV1.DIRECT],
        thin_adapter_count=counts[IFEMPrerequisiteClassificationV1.THIN_ADAPTER],
        missing_count=counts[IFEMPrerequisiteClassificationV1.MISSING],
        unknown_count=counts[IFEMPrerequisiteClassificationV1.UNKNOWN],
        direct_or_thin_count=(
            counts[IFEMPrerequisiteClassificationV1.DIRECT]
            + counts[IFEMPrerequisiteClassificationV1.THIN_ADAPTER]
        ),
    )


def _profile_evidence_binding(
    *,
    census_plan: IFEMPrerequisiteCensusPlanV1,
    profile_plan: IFEMPinnedMathlibProfilePlanV1 | None,
    profile_result: IFEMPinnedMathlibProfileResultV1 | None,
    profile_observations: IFEMPinnedMathlibProfileObservationsV1 | None,
    profile_build_receipt: IFEMPinnedMathlibProfileBuildReceiptV1 | None,
) -> tuple[IFEMPilotProfileEvidenceStateV2, bool, set[str], IFEMPilotReadinessEvidenceBindingV1]:
    if profile_plan is None and profile_result is None:
        if profile_observations is not None or profile_build_receipt is not None:
            raise IFEMPilotReadinessError("profile observations require a profile plan and result")
        return (
            IFEMPilotProfileEvidenceStateV2.NOT_SUPPLIED,
            False,
            set(),
            IFEMPilotReadinessEvidenceBindingV1(
                census_plan_content_sha256=census_plan.content_sha256,
                census_result_content_sha256="0" * 64,
            ),
        )
    if profile_plan is None or profile_result is None:
        raise IFEMPilotReadinessError("profile plan and result must be supplied together")
    _exact_instance(profile_plan, IFEMPinnedMathlibProfilePlanV1, label="profile plan")
    _exact_instance(profile_result, IFEMPinnedMathlibProfileResultV1, label="profile result")
    try:
        profile_plan = IFEMPinnedMathlibProfilePlanV1.model_validate(
            profile_plan.model_dump(mode="json")
        )
        profile_result = IFEMPinnedMathlibProfileResultV1.model_validate(
            profile_result.model_dump(mode="json")
        )
    except ValueError as error:
        raise IFEMPilotReadinessError("profile plan or result failed self-revalidation") from error
    if profile_plan.census_plan_content_sha256 != census_plan.content_sha256:
        raise IFEMPilotReadinessError("profile plan does not bind the census plan")
    if profile_plan.denominator != census_plan.denominator:
        raise IFEMPilotReadinessError("profile plan denominator differs from the census plan")
    if (
        profile_plan.environment.lean_toolchain != census_plan.environment.lean_toolchain
        or profile_plan.environment.mathlib_revision != census_plan.environment.mathlib_revision
        or (
            profile_plan.environment.lake_manifest_sha256
            != census_plan.environment.lake_manifest_sha256
        )
    ):
        raise IFEMPilotReadinessError("profile plan environment differs from the census plan")
    if profile_result.plan_content_sha256 != profile_plan.content_sha256:
        raise IFEMPilotReadinessError("profile result does not bind the frozen profile plan")
    if profile_result.execution_state is IFEMPinnedMathlibProfileExecutionStateV1.NOT_RUN:
        if profile_observations is not None or profile_build_receipt is not None:
            raise IFEMPilotReadinessError("not-run profile result cannot carry observations")
        return (
            IFEMPilotProfileEvidenceStateV2.NOT_COMPLETED,
            False,
            set(),
            IFEMPilotReadinessEvidenceBindingV1(
                census_plan_content_sha256=census_plan.content_sha256,
                census_result_content_sha256="0" * 64,
                profile_plan_content_sha256=profile_plan.content_sha256,
                profile_result_content_sha256=profile_result.content_sha256,
            ),
        )
    if profile_observations is None or profile_build_receipt is None:
        raise IFEMPilotReadinessError(
            "completed profile result requires observation and build receipt"
        )
    _exact_instance(
        profile_observations,
        IFEMPinnedMathlibProfileObservationsV1,
        label="profile observations",
    )
    _exact_instance(
        profile_build_receipt,
        IFEMPinnedMathlibProfileBuildReceiptV1,
        label="profile build receipt",
    )
    try:
        profile_observations = IFEMPinnedMathlibProfileObservationsV1.model_validate(
            profile_observations.model_dump(mode="json")
        )
        profile_build_receipt = IFEMPinnedMathlibProfileBuildReceiptV1.model_validate(
            profile_build_receipt.model_dump(mode="json")
        )
    except ValueError as error:
        raise IFEMPilotReadinessError(
            "profile observations or build receipt failed self-revalidation"
        ) from error
    if profile_result.observation_content_sha256 != profile_observations.content_sha256:
        raise IFEMPilotReadinessError("profile result does not bind the observed profile records")
    if profile_observations.plan_content_sha256 != profile_plan.content_sha256:
        raise IFEMPilotReadinessError("profile observations do not bind the frozen profile plan")
    if (
        profile_observations.parent_image != profile_plan.environment.parent_image
        or profile_observations.lean_toolchain != profile_plan.environment.lean_toolchain
        or profile_observations.mathlib_revision != profile_plan.environment.mathlib_revision
        or (
            profile_observations.lake_manifest_sha256
            != profile_plan.environment.lake_manifest_sha256
        )
        or profile_observations.helper_sha256 != profile_plan.assets.helper_sha256
        or profile_observations.wrapper_sha256 != profile_plan.assets.wrapper_sha256
    ):
        raise IFEMPilotReadinessError("profile observations differ from the frozen profile plan")
    if (
        profile_build_receipt.plan_content_sha256 != profile_plan.content_sha256
        or profile_build_receipt.parent_image != profile_plan.environment.parent_image
        or profile_build_receipt.child_image != profile_observations.child_image
        or profile_build_receipt.dockerfile_sha256 != profile_plan.assets.dockerfile_sha256
        or profile_build_receipt.helper_sha256 != profile_plan.assets.helper_sha256
        or profile_build_receipt.wrapper_sha256 != profile_plan.assets.wrapper_sha256
    ):
        raise IFEMPilotReadinessError("profile build receipt differs from observed frozen inputs")
    expected_imports = {
        profile.profile_id: profile.direct_import for profile in profile_plan.profiles
    }
    observed_imports = {
        profile.profile_id: profile.direct_imports[0] for profile in profile_observations.profiles
    }
    for profile in profile_observations.profiles:
        declaration_inventory = tuple(item.declaration for item in profile.declarations)
        if declaration_inventory != profile_plan.candidate_declarations:
            raise IFEMPilotReadinessError(
                "profile observation declaration inventory differs from the frozen profile plan"
            )
    direct_imports_verified = observed_imports == expected_imports
    present_declarations = {
        declaration.declaration
        for profile in profile_observations.profiles
        for declaration in profile.declarations
        if declaration.present
    }
    state = (
        IFEMPilotProfileEvidenceStateV2.DIRECT_IMPORTS_BOUND_CLOSURE_UNREVIEWED
        if direct_imports_verified
        else IFEMPilotProfileEvidenceStateV2.WRONG_DIRECT_IMPORT
    )
    return (
        state,
        direct_imports_verified,
        present_declarations,
        IFEMPilotReadinessEvidenceBindingV1(
            census_plan_content_sha256=census_plan.content_sha256,
            census_result_content_sha256="0" * 64,
            profile_plan_content_sha256=profile_plan.content_sha256,
            profile_result_content_sha256=profile_result.content_sha256,
            profile_observation_content_sha256=profile_observations.content_sha256,
            profile_build_receipt_content_sha256=profile_build_receipt.content_sha256,
        ),
    )


def _critical_states(
    result: IFEMPrerequisiteCensusResultV1,
    *,
    present_declarations: set[str] | None,
) -> tuple[IFEMCriticalRestrictionStateV2, ...]:
    by_node = {item.node_id: item.evidence for item in result.node_results}
    states: list[IFEMCriticalRestrictionStateV2] = []
    for node_id in _CRITICAL_RESTRICTION_NODES:
        evidence = by_node.get(node_id)
        if evidence is None:
            raise IFEMPilotReadinessError("census result omits a frozen critical restriction node")
        mapped = evidence.mapped_declarations
        observed: bool | None = None
        if (
            evidence.classification
            in {
                IFEMPrerequisiteClassificationV1.DIRECT,
                IFEMPrerequisiteClassificationV1.THIN_ADAPTER,
            }
            and present_declarations is not None
        ):
            observed = set(mapped) <= present_declarations
        states.append(
            IFEMCriticalRestrictionStateV2(
                node_id=node_id,
                classification=evidence.classification,
                mapped_declarations=mapped,
                observed_under_exact_direct_import_profiles=observed,
            )
        )
    return tuple(states)


def _decision_reasons(
    *,
    census_execution_state: IFEMQueryExecutionStateV1,
    counts: IFEMPilotReadinessCountsV1,
    profile_state: IFEMPilotProfileEvidenceStateV2,
    critical_states: tuple[IFEMCriticalRestrictionStateV2, ...],
) -> tuple[IFEMPilotReadinessOutcomeV1, tuple[IFEMPilotReadinessReasonV2, ...]]:
    no_go_reasons: set[IFEMPilotReadinessReasonV2] = set()
    incomplete_reasons: set[IFEMPilotReadinessReasonV2] = {
        IFEMPilotReadinessReasonV2.TRANSITIVE_CLOSURE_POLICY_UNRESOLVED
    }
    if census_execution_state is not IFEMQueryExecutionStateV1.COMPLETED:
        incomplete_reasons.add(IFEMPilotReadinessReasonV2.CENSUS_NOT_COMPLETED)
    if any(
        state.classification is IFEMPrerequisiteClassificationV1.MISSING
        for state in critical_states
    ):
        no_go_reasons.add(IFEMPilotReadinessReasonV2.RESTRICTION_API_MISSING)
    if any(state.observed_under_exact_direct_import_profiles is False for state in critical_states):
        no_go_reasons.add(IFEMPilotReadinessReasonV2.RESTRICTION_API_NOT_OBSERVED)
    if profile_state is IFEMPilotProfileEvidenceStateV2.WRONG_DIRECT_IMPORT:
        no_go_reasons.add(IFEMPilotReadinessReasonV2.WRONG_DIRECT_IMPORT)
    if counts.unknown_count:
        incomplete_reasons.add(IFEMPilotReadinessReasonV2.SEMANTIC_CLASSIFICATION_INCOMPLETE)
    elif counts.direct_or_thin_count < _MINIMUM_DIRECT_OR_THIN:
        no_go_reasons.add(IFEMPilotReadinessReasonV2.COVERAGE_BELOW_BAND)
    elif counts.direct_or_thin_count > _MAXIMUM_DIRECT_OR_THIN:
        no_go_reasons.add(IFEMPilotReadinessReasonV2.COVERAGE_ABOVE_BAND)
    if profile_state is IFEMPilotProfileEvidenceStateV2.NOT_SUPPLIED:
        incomplete_reasons.add(IFEMPilotReadinessReasonV2.PROFILE_EVIDENCE_NOT_SUPPLIED)
    elif profile_state is IFEMPilotProfileEvidenceStateV2.NOT_COMPLETED:
        incomplete_reasons.add(IFEMPilotReadinessReasonV2.PROFILE_EVIDENCE_NOT_COMPLETED)
    if no_go_reasons:
        return IFEMPilotReadinessOutcomeV1.NO_GO, tuple(sorted(no_go_reasons, key=str))
    return (
        IFEMPilotReadinessOutcomeV1.INCOMPLETE,
        tuple(sorted(incomplete_reasons, key=str)),
    )


def evaluate_ifem_pilot_readiness(
    census_plan: IFEMPrerequisiteCensusPlanV1,
    census_result: IFEMPrerequisiteCensusResultV1,
    *,
    profile_plan: IFEMPinnedMathlibProfilePlanV1 | None = None,
    profile_result: IFEMPinnedMathlibProfileResultV1 | None = None,
    profile_observations: IFEMPinnedMathlibProfileObservationsV1 | None = None,
    profile_build_receipt: IFEMPinnedMathlibProfileBuildReceiptV1 | None = None,
) -> IFEMPilotReadinessDecisionV2:
    """Evaluate the immutable P2-08 rule without producing an admission verdict.

    ``incomplete`` is deliberately distinct from ``no_go``: it says that a
    bounded observation or semantic classification has not been supplied.  A
    reviewed missing critical restriction API and a wrong direct import are
    falsifying facts and therefore produce ``no_go`` when present.  Exact direct
    imports remain incomplete until a successor contract freezes and evaluates a
    transitive-closure acceptance policy.
    """

    _exact_instance(census_plan, IFEMPrerequisiteCensusPlanV1, label="census plan")
    _exact_instance(census_result, IFEMPrerequisiteCensusResultV1, label="census result")
    try:
        validate_result_against_plan(census_result, census_plan)
    except ValueError as error:
        raise IFEMPilotReadinessError("census result does not bind the frozen plan") from error
    if census_plan.denominator.prerequisite_node_count != _MINIMUM_DIRECT_OR_THIN + 6:
        raise IFEMPilotReadinessError("readiness policy denominator differs from the frozen census")
    (
        profile_state,
        direct_imports_verified,
        present_declarations,
        partial_evidence,
    ) = _profile_evidence_binding(
        census_plan=census_plan,
        profile_plan=profile_plan,
        profile_result=profile_result,
        profile_observations=profile_observations,
        profile_build_receipt=profile_build_receipt,
    )
    counts = _classification_counts(census_result)
    critical_states = _critical_states(
        census_result,
        present_declarations=(
            present_declarations
            if profile_state
            in {
                IFEMPilotProfileEvidenceStateV2.DIRECT_IMPORTS_BOUND_CLOSURE_UNREVIEWED,
                IFEMPilotProfileEvidenceStateV2.WRONG_DIRECT_IMPORT,
            }
            else None
        ),
    )
    outcome, reasons = _decision_reasons(
        census_execution_state=census_result.execution_state,
        counts=counts,
        profile_state=profile_state,
        critical_states=critical_states,
    )
    evidence_payload = partial_evidence.model_dump(mode="json")
    evidence_payload["census_result_content_sha256"] = census_result.content_sha256
    evidence = IFEMPilotReadinessEvidenceBindingV1.model_validate(evidence_payload)
    policy = IFEMPilotReadinessPolicyV2()
    payload: dict[str, object] = {
        "authority": IFEMPilotReadinessAuthorityV1().model_dump(mode="json"),
        "builder_freeze": "forbidden",
        "census_execution_state": census_result.execution_state.value,
        "content_sha256": "0" * 64,
        "counts": counts.model_dump(mode="json"),
        "critical_restriction_states": [state.model_dump(mode="json") for state in critical_states],
        "evidence": evidence.model_dump(mode="json"),
        "direct_imports_verified": direct_imports_verified,
        "outcome": outcome.value,
        "policy": policy.model_dump(mode="json"),
        "policy_content_sha256": policy.content_sha256(),
        "profile_evidence_state": profile_state.value,
        "protocol": PROTOCOL,
        "prover_handoff": "forbidden",
        "reasons": [reason.value for reason in reasons],
        "schema_version": DECISION_SCHEMA,
        "transitive_closure_policy_resolved": False,
    }
    payload.pop("content_sha256")
    payload["content_sha256"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    try:
        return IFEMPilotReadinessDecisionV2.model_validate(payload)
    except ValueError as error:
        raise IFEMPilotReadinessError("generated iFEM readiness decision is invalid") from error


def verify_ifem_pilot_readiness_decision(
    decision: IFEMPilotReadinessDecisionV2,
    census_plan: IFEMPrerequisiteCensusPlanV1,
    census_result: IFEMPrerequisiteCensusResultV1,
    *,
    profile_plan: IFEMPinnedMathlibProfilePlanV1 | None = None,
    profile_result: IFEMPinnedMathlibProfileResultV1 | None = None,
    profile_observations: IFEMPinnedMathlibProfileObservationsV1 | None = None,
    profile_build_receipt: IFEMPinnedMathlibProfileBuildReceiptV1 | None = None,
) -> None:
    """Recompute one decision from its source evidence before consuming it.

    A content hash only protects a decision's own bytes.  This verifier also
    proves that those bytes are the unique outcome of the referenced P2-07
    evidence supplied by the caller.
    """

    _exact_instance(decision, IFEMPilotReadinessDecisionV2, label="readiness decision")
    try:
        validated = IFEMPilotReadinessDecisionV2.model_validate(decision.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as error:
        raise IFEMPilotReadinessError("readiness decision failed self-revalidation") from error
    rebuilt = evaluate_ifem_pilot_readiness(
        census_plan,
        census_result,
        profile_plan=profile_plan,
        profile_result=profile_result,
        profile_observations=profile_observations,
        profile_build_receipt=profile_build_receipt,
    )
    if validated != rebuilt:
        raise IFEMPilotReadinessError(
            "readiness decision differs from the exact recomputation of its source evidence"
        )


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise IFEMPilotReadinessError(f"duplicate JSON key: {key}")
        document[key] = value
    return document


def _load_model[ModelType: ContractModel](
    path: Path,
    model_type: type[ModelType],
    *,
    label: str,
) -> ModelType:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as error:
        raise IFEMPilotReadinessError(f"cannot read {label}: {path}") from error
    try:
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as error:
        raise IFEMPilotReadinessError(f"{label} is not valid JSON") from error
    if not isinstance(payload, dict):
        raise IFEMPilotReadinessError(f"{label} must be a JSON object")
    try:
        return model_type.model_validate(payload)
    except ValueError as error:
        raise IFEMPilotReadinessError(f"{label} has an invalid v1 model") from error


def load_ifem_pilot_readiness_decision(path: Path) -> IFEMPilotReadinessDecisionV2:
    return _load_model(path, IFEMPilotReadinessDecisionV2, label="iFEM readiness decision")


def _write_once(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError:
        try:
            if path.read_bytes() != content:
                raise IFEMPilotReadinessError("output already exists with different bytes")
        except OSError as error:
            raise IFEMPilotReadinessError("cannot inspect an existing output") from error


def write_ifem_pilot_readiness_decision_once(
    path: Path,
    decision: IFEMPilotReadinessDecisionV2,
) -> None:
    _write_once(path, canonical_json_bytes(decision) + b"\n")


def parse_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--census-plan", type=Path, default=DEFAULT_CENSUS_PLAN_PATH)
    parser.add_argument("--census-result", type=Path, required=True)
    parser.add_argument("--profile-plan", type=Path)
    parser.add_argument("--profile-result", type=Path)
    parser.add_argument("--profile-observations", type=Path)
    parser.add_argument("--profile-build-receipt", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    namespace = parse_arguments(arguments)
    census_plan = load_ifem_prerequisite_census_plan(namespace.census_plan.resolve())
    census_result = _load_model(
        namespace.census_result.resolve(),
        IFEMPrerequisiteCensusResultV1,
        label="iFEM prerequisite census result",
    )
    profile_paths = (
        namespace.profile_plan,
        namespace.profile_result,
        namespace.profile_observations,
        namespace.profile_build_receipt,
    )
    profile_values: tuple[
        IFEMPinnedMathlibProfilePlanV1 | None,
        IFEMPinnedMathlibProfileResultV1 | None,
        IFEMPinnedMathlibProfileObservationsV1 | None,
        IFEMPinnedMathlibProfileBuildReceiptV1 | None,
    ]
    if all(path is None for path in profile_paths):
        profile_values = (None, None, None, None)
    else:
        if namespace.profile_plan is None or namespace.profile_result is None:
            raise IFEMPilotReadinessError("profile plan and profile result are required together")
        profile_values = (
            _load_model(
                namespace.profile_plan.resolve(),
                IFEMPinnedMathlibProfilePlanV1,
                label="iFEM profile plan",
            ),
            _load_model(
                namespace.profile_result.resolve(),
                IFEMPinnedMathlibProfileResultV1,
                label="iFEM profile result",
            ),
            (
                _load_model(
                    namespace.profile_observations.resolve(),
                    IFEMPinnedMathlibProfileObservationsV1,
                    label="iFEM profile observations",
                )
                if namespace.profile_observations is not None
                else None
            ),
            (
                _load_model(
                    namespace.profile_build_receipt.resolve(),
                    IFEMPinnedMathlibProfileBuildReceiptV1,
                    label="iFEM profile build receipt",
                )
                if namespace.profile_build_receipt is not None
                else None
            ),
        )
    decision = evaluate_ifem_pilot_readiness(
        census_plan,
        census_result,
        profile_plan=profile_values[0],
        profile_result=profile_values[1],
        profile_observations=profile_values[2],
        profile_build_receipt=profile_values[3],
    )
    write_ifem_pilot_readiness_decision_once(namespace.out, decision)
    print(decision.content_sha256)
    return 0


__all__ = [
    "DECISION_SCHEMA",
    "DEFAULT_CENSUS_PLAN_PATH",
    "DEFAULT_PROFILE_PLAN_PATH",
    "PROTOCOL",
    "IFEMCriticalRestrictionStateV2",
    "IFEMPilotProfileEvidenceStateV2",
    "IFEMPilotReadinessAuthorityV1",
    "IFEMPilotReadinessCountsV1",
    "IFEMPilotReadinessDecisionV2",
    "IFEMPilotReadinessError",
    "IFEMPilotReadinessOutcomeV1",
    "IFEMPilotReadinessPolicyV2",
    "IFEMPilotReadinessReasonV2",
    "evaluate_ifem_pilot_readiness",
    "load_ifem_pilot_readiness_decision",
    "main",
    "verify_ifem_pilot_readiness_decision",
    "write_ifem_pilot_readiness_decision_once",
]
