"""Fake-first source-free iFEM calibration-case authoring.

This module deliberately calibrates only a closed, project-synthetic structural
grammar.  It consumes the unknown-only next-calibration queue but never reads
source material, Lean surface, provider configuration, a private filesystem
root, or an external endpoint.  The private seed objects exist only in memory;
the renderable plan and report contain deterministic public-safe case handles
and commitments.  Those handles are deliberately not a secrecy boundary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections.abc import Sequence
from enum import StrEnum
from pathlib import Path
from typing import Final, Literal, Never, Self, cast

from autolean_contracts import (
    ModelWorkRoleV1,
    PairSplitPartitionV1,
    StableIdentifierV1,
    canonical_json_bytes,
    stable_identifier,
)
from autolean_contracts.base import ContractModel
from pydantic import Field, model_validator

from .ifem_calibration_risk_routing import (
    IFEMCalibrationPriorityV1,
    IFEMRequiredNextCalibrationV1,
)
from .ifem_next_calibration_case_intents import (
    IFEMNextCalibrationCaseIntentError,
    IFEMNextCalibrationCaseIntentsV1,
    IFEMNextCalibrationCaseIntentV1,
    load_ifem_next_calibration_case_intents,
)

SOURCE_FREE_CASE_AUTHORING_SCHEMA: Final[Literal["autolean.ifem-source-free-case-authoring.v1"]] = (
    "autolean.ifem-source-free-case-authoring.v1"
)
SOURCE_FREE_CASE_AUTHORING_PROTOCOL: Final[
    Literal["autolean.builder-ifem-source-free-case-authoring.v1"]
] = "autolean.builder-ifem-source-free-case-authoring.v1"
SOURCE_FREE_CASE_AUTHORING_KIND: Final[Literal["project_synthetic_source_free_case_authoring"]] = (
    "project_synthetic_source_free_case_authoring"
)
_CASE_NAMESPACE: Final[Literal["ifem-source-free-case-authoring-case"]] = (
    "ifem-source-free-case-authoring-case"
)
_SHA256 = r"^[0-9a-f]{64}$"
_ROLE_ORDER: Final[tuple[ModelWorkRoleV1, ...]] = (
    ModelWorkRoleV1.STATEMENT_FORMALIZER,
    ModelWorkRoleV1.FIDELITY_REVIEWER,
    ModelWorkRoleV1.CHEATING_SUPERVISOR,
)
_PARTITION_ORDER: Final[tuple[PairSplitPartitionV1, ...]] = (
    PairSplitPartitionV1.TRAIN,
    PairSplitPartitionV1.DEV,
    PairSplitPartitionV1.PRIVATE_HELDOUT,
)
_FORBIDDEN_PUBLIC_FIELDS: Final[tuple[bytes, ...]] = (
    b'"candidate"',
    b'"catalog"',
    b'"hidden_oracle"',
    b'"lean"',
    b'"mutation"',
    b'"node_id"',
    b'"oracle"',
    b'"private_root"',
    b'"provider"',
    b'"request"',
    b'"source_path"',
    b'"source_span"',
    b'"source_text"',
)


class SourceFreeCaseAuthoringError(ValueError):
    """A source-free calibration plan crossed its deliberately narrow boundary."""


class SourceFreeAuthoringDispositionV1(StrEnum):
    PROPOSE = "propose"
    ABSTAIN = "abstain"


class SourceFreeReviewDispositionV1(StrEnum):
    ACCEPT = "accept"
    REJECT = "reject"
    ABSTAIN = "abstain"


class SourceFreeSupervisorDispositionV1(StrEnum):
    ALLOW = "allow"
    REJECT = "reject"
    ABSTAIN = "abstain"


class SourceFreeStageStatusV1(StrEnum):
    CORRECT = "correct"
    INCORRECT = "incorrect"
    ABSTAIN = "abstain"


class SourceFreeCaseAuthoringAuthorityV1(ContractModel):
    """All semantic and execution authority is intentionally withheld."""

    schema_version: Literal["autolean.ifem-source-free-case-authoring-authority.v1"] = (
        "autolean.ifem-source-free-case-authoring-authority.v1"
    )
    semantic_classification_authorized: Literal[False] = False
    semantic_fidelity_claimed: Literal[False] = False
    statement_contract_created: Literal[False] = False
    formal_graph_created: Literal[False] = False
    execution_graph_created: Literal[False] = False
    model_egress_authorized: Literal[False] = False
    machine_advisory_authorized: Literal[False] = False
    heldout_isolation_claimed: Literal[False] = False
    freeze_allowed: Literal[False] = False
    prover_handoff_allowed: Literal[False] = False
    promotion_allowed: Literal[False] = False


class SourceFreeSignatureV1(ContractModel):
    """A bounded project-synthetic signature, not a mathematical proposition."""

    alpha: int = Field(ge=0, le=9, strict=True)
    beta: int = Field(ge=0, le=9, strict=True)
    gamma: int = Field(ge=0, le=9, strict=True)
    guard_enabled: bool = Field(strict=True)


class SourceFreeHiddenOracleV1(ContractModel):
    """Private evaluator data that no card or public renderer may expose."""

    selected_slot: int = Field(ge=0, le=2, strict=True)
    expected_candidate: SourceFreeSignatureV1


class PrivateSourceFreeCaseSeedV1(ContractModel):
    """In-memory seed binding one P3 intent to a finite project-synthetic case."""

    schema_version: Literal["autolean.ifem-source-free-case-seed.v1"] = (
        "autolean.ifem-source-free-case-seed.v1"
    )
    case_id: StableIdentifierV1
    intent_id: StableIdentifierV1
    node_id: str = Field(pattern=r"^ifem-[a-z0-9-]+$")
    partition: PairSplitPartitionV1
    baseline: SourceFreeSignatureV1
    selector: int = Field(ge=0, le=2, strict=True)
    increment: int = Field(ge=1, le=3, strict=True)
    hidden_oracle: SourceFreeHiddenOracleV1
    source_free: Literal[True] = True
    textbook_derived: Literal[False] = False
    lean_surface_present: Literal[False] = False
    authority: SourceFreeCaseAuthoringAuthorityV1 = Field(
        default_factory=SourceFreeCaseAuthoringAuthorityV1
    )
    seed_commitment_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_seed(self) -> Self:
        if self.case_id.namespace != _CASE_NAMESPACE:
            raise ValueError("source-free case seed uses the wrong case identifier namespace")
        if self.hidden_oracle.selected_slot != self.selector:
            raise ValueError("hidden oracle selector differs from its finite card selector")
        if self.hidden_oracle.expected_candidate != _expected_candidate_from_values(
            self.baseline,
            selector=self.selector,
            increment=self.increment,
        ):
            raise ValueError("hidden oracle does not bind the synthetic finite transform")
        if self.authority != SourceFreeCaseAuthoringAuthorityV1():
            raise ValueError("private source-free seed authority flags drifted")
        if self.seed_commitment_sha256 != self.computed_seed_commitment_sha256():
            raise ValueError("source-free case seed commitment does not match its payload")
        return self

    def seed_commitment_payload(self) -> dict[str, object]:
        return cast(
            dict[str, object],
            self.model_dump(mode="json", exclude={"seed_commitment_sha256"}),
        )

    def computed_seed_commitment_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.seed_commitment_payload())).hexdigest()


class SourceFreeCaseCoordinateV1(ContractModel):
    """Publicly replayable fake coordinate; it intentionally omits node identity.

    The case identifier is derived from the public queue, so this projection is
    pseudonymous rather than blind or secret.
    """

    case_id: StableIdentifierV1
    partition: PairSplitPartitionV1
    seed_commitment_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_coordinate(self) -> Self:
        if self.case_id.namespace != _CASE_NAMESPACE:
            raise ValueError("source-free case coordinate uses the wrong identifier namespace")
        return self


class SourceFreeCaseAuthoringPlanV1(ContractModel):
    """Renderable, write-once plan for exactly nine P3 project-synthetic cases."""

    schema_version: Literal["autolean.ifem-source-free-case-authoring.v1"] = (
        SOURCE_FREE_CASE_AUTHORING_SCHEMA
    )
    protocol: Literal["autolean.builder-ifem-source-free-case-authoring.v1"] = (
        SOURCE_FREE_CASE_AUTHORING_PROTOCOL
    )
    artifact_kind: Literal["project_synthetic_source_free_case_authoring"] = (
        SOURCE_FREE_CASE_AUTHORING_KIND
    )
    intent_queue_content_sha256: str = Field(pattern=_SHA256)
    case_coordinates: tuple[SourceFreeCaseCoordinateV1, ...] = Field(min_length=9, max_length=9)
    role_order: tuple[ModelWorkRoleV1, ...] = Field(min_length=3, max_length=3)
    train_case_count: Literal[3] = 3
    dev_case_count: Literal[3] = 3
    private_heldout_case_count: Literal[3] = 3
    stage_count: Literal[27] = 27
    max_attempts_per_stage: Literal[1] = 1
    seed_collection_commitment_sha256: str = Field(pattern=_SHA256)
    source_free: Literal[True] = True
    private_seed_embedded: Literal[False] = False
    raw_agent_output_embedded: Literal[False] = False
    case_linkage_publicly_replayable: Literal[True] = True
    partition_labels_topology_only: Literal[True] = True
    authority: SourceFreeCaseAuthoringAuthorityV1 = Field(
        default_factory=SourceFreeCaseAuthoringAuthorityV1
    )
    builder_freeze: Literal["forbidden"] = "forbidden"
    prover_handoff: Literal["forbidden"] = "forbidden"
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_plan(self) -> Self:
        if self.role_order != _ROLE_ORDER:
            raise ValueError("source-free case plan has an unexpected role sequence")
        case_ids = tuple(item.case_id.value for item in self.case_coordinates)
        if case_ids != tuple(sorted(case_ids)) or len(case_ids) != len(set(case_ids)):
            raise ValueError("source-free case plan coordinates must be sorted and unique")
        counts = {
            partition: sum(item.partition is partition for item in self.case_coordinates)
            for partition in _PARTITION_ORDER
        }
        if counts != {
            PairSplitPartitionV1.TRAIN: self.train_case_count,
            PairSplitPartitionV1.DEV: self.dev_case_count,
            PairSplitPartitionV1.PRIVATE_HELDOUT: self.private_heldout_case_count,
        }:
            raise ValueError("source-free case plan does not retain its 3/3/3 partition")
        if self.authority != SourceFreeCaseAuthoringAuthorityV1():
            raise ValueError("source-free case plan authority flags drifted")
        if self.content_sha256 != self.computed_content_sha256():
            raise ValueError("source-free case plan content hash does not match its payload")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(dict[str, object], self.model_dump(mode="json", exclude={"content_sha256"}))

    def computed_content_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.content_payload())).hexdigest()

    def assert_not_authoritative(self) -> Never:
        raise SourceFreeCaseAuthoringError(
            "source-free case authoring cannot classify a node, freeze a statement, or hand work "
            "to Prover"
        )

    def freeze_statement(self) -> Never:
        self.assert_not_authoritative()

    def handoff_to_prover(self) -> Never:
        self.assert_not_authoritative()


class SourceFreeAuthoringCardV1(ContractModel):
    """The statement-formalizer projection; node identity and oracle stay private."""

    case_id: StableIdentifierV1
    baseline: SourceFreeSignatureV1
    selector: int = Field(ge=0, le=2, strict=True)
    increment: int = Field(ge=1, le=3, strict=True)
    source_free: Literal[True] = True


class SourceFreeReviewerCardV1(ContractModel):
    """The reviewer receives parsed finite data, never raw author output or oracle."""

    case_id: StableIdentifierV1
    baseline: SourceFreeSignatureV1
    selector: int = Field(ge=0, le=2, strict=True)
    increment: int = Field(ge=1, le=3, strict=True)
    author_disposition: SourceFreeAuthoringDispositionV1
    author_selected_slot: int | None = Field(default=None, ge=0, le=2, strict=True)
    author_candidate: SourceFreeSignatureV1 | None = None
    source_free: Literal[True] = True

    @model_validator(mode="after")
    def validate_author_projection(self) -> Self:
        has_author_payload = (
            self.author_selected_slot is not None and self.author_candidate is not None
        )
        if (
            self.author_disposition is SourceFreeAuthoringDispositionV1.PROPOSE
        ) != has_author_payload:
            raise ValueError("reviewer card author projection is incomplete")
        return self


class SourceFreeSupervisorCardV1(ContractModel):
    """The supervisor gets only bounded dispositions and a finite change count."""

    case_id: StableIdentifierV1
    author_disposition: SourceFreeAuthoringDispositionV1
    reviewer_disposition: SourceFreeReviewDispositionV1
    observed_change_count: int = Field(ge=0, le=3, strict=True)
    source_free: Literal[True] = True


class SourceFreeAuthoringResponseV1(ContractModel):
    """Strict finite statement-formalizer response grammar."""

    schema_version: Literal["autolean.ifem-source-free-authoring-response.v1"] = (
        "autolean.ifem-source-free-authoring-response.v1"
    )
    disposition: SourceFreeAuthoringDispositionV1
    selected_slot: int | None = Field(default=None, ge=0, le=2, strict=True)
    candidate: SourceFreeSignatureV1 | None = None

    @model_validator(mode="after")
    def validate_response(self) -> Self:
        has_payload = self.selected_slot is not None and self.candidate is not None
        if (self.disposition is SourceFreeAuthoringDispositionV1.PROPOSE) != has_payload:
            raise ValueError(
                "authoring response must either propose a complete finite candidate or abstain"
            )
        return self


class SourceFreeReviewResponseV1(ContractModel):
    """Strict finite fidelity-review response grammar."""

    schema_version: Literal["autolean.ifem-source-free-review-response.v1"] = (
        "autolean.ifem-source-free-review-response.v1"
    )
    disposition: SourceFreeReviewDispositionV1
    observed_change_count: int = Field(ge=0, le=3, strict=True)


class SourceFreeSupervisorResponseV1(ContractModel):
    """Strict finite cheating-supervisor response grammar."""

    schema_version: Literal["autolean.ifem-source-free-supervisor-response.v1"] = (
        "autolean.ifem-source-free-supervisor-response.v1"
    )
    disposition: SourceFreeSupervisorDispositionV1
    violation_detected: bool = Field(strict=True)

    @model_validator(mode="after")
    def validate_response(self) -> Self:
        if (
            self.disposition is SourceFreeSupervisorDispositionV1.REJECT
        ) != self.violation_detected:
            raise ValueError("supervisor disposition must agree with its finite violation flag")
        return self


class PrivateSourceFreeCaseEvaluationV1(ContractModel):
    """Private, source-free outcome with no raw response or hidden evaluator data."""

    case_id: StableIdentifierV1
    partition: PairSplitPartitionV1
    authoring_status: SourceFreeStageStatusV1
    reviewer_status: SourceFreeStageStatusV1
    supervisor_status: SourceFreeStageStatusV1
    authority: SourceFreeCaseAuthoringAuthorityV1 = Field(
        default_factory=SourceFreeCaseAuthoringAuthorityV1
    )

    @model_validator(mode="after")
    def validate_evaluation(self) -> Self:
        if self.authority != SourceFreeCaseAuthoringAuthorityV1():
            raise ValueError("private source-free evaluation authority flags drifted")
        return self


class PrivateSourceFreeCaseAuthoringRunV1(ContractModel):
    """In-memory fake run; it is not a private store or a model-execution receipt."""

    schema_version: Literal["autolean.ifem-source-free-case-authoring-private-run.v1"] = (
        "autolean.ifem-source-free-case-authoring-private-run.v1"
    )
    plan_content_sha256: str = Field(pattern=_SHA256)
    evaluations: tuple[PrivateSourceFreeCaseEvaluationV1, ...] = Field(min_length=9, max_length=9)
    fake_only: Literal[True] = True
    raw_agent_output_retained: Literal[False] = False
    authority: SourceFreeCaseAuthoringAuthorityV1 = Field(
        default_factory=SourceFreeCaseAuthoringAuthorityV1
    )
    run_content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_run(self) -> Self:
        case_ids = tuple(item.case_id.value for item in self.evaluations)
        if case_ids != tuple(sorted(case_ids)) or len(case_ids) != len(set(case_ids)):
            raise ValueError("private source-free run evaluations must be sorted and unique")
        if self.authority != SourceFreeCaseAuthoringAuthorityV1():
            raise ValueError("private source-free run authority flags drifted")
        if self.run_content_sha256 != self.computed_run_content_sha256():
            raise ValueError("private source-free run hash does not match its payload")
        return self

    def run_content_payload(self) -> dict[str, object]:
        return cast(dict[str, object], self.model_dump(mode="json", exclude={"run_content_sha256"}))

    def computed_run_content_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.run_content_payload())).hexdigest()


class SourceFreeCaseAuthoringRoleAggregateV1(ContractModel):
    """One role-local count vector; cross-role score aggregation is intentionally absent."""

    role: ModelWorkRoleV1
    case_count: Literal[9] = 9
    correct_count: int = Field(ge=0, le=9)
    incorrect_count: int = Field(ge=0, le=9)
    abstain_count: int = Field(ge=0, le=9)

    @model_validator(mode="after")
    def validate_counts(self) -> Self:
        if self.correct_count + self.incorrect_count + self.abstain_count != self.case_count:
            raise ValueError("source-free role aggregate does not cover its cases")
        return self


class SourceFreeCaseAuthoringReportV1(ContractModel):
    """Sanitized public aggregate; no private seed or model-output material is embedded."""

    schema_version: Literal["autolean.ifem-source-free-case-authoring-report.v1"] = (
        "autolean.ifem-source-free-case-authoring-report.v1"
    )
    plan_content_sha256: str = Field(pattern=_SHA256)
    private_run_content_sha256: str = Field(pattern=_SHA256)
    case_count: Literal[9] = 9
    stage_count: Literal[27] = 27
    role_aggregates: tuple[SourceFreeCaseAuthoringRoleAggregateV1, ...] = Field(
        min_length=3, max_length=3
    )
    fake_only: Literal[True] = True
    same_agent_model_across_roles: Literal[True] = True
    machine_advisory_disposition: Literal["abstain"] = "abstain"
    semantic_fidelity_claimed: Literal[False] = False
    private_seed_embedded: Literal[False] = False
    raw_agent_output_embedded: Literal[False] = False
    case_linkage_publicly_replayable: Literal[True] = True
    partition_labels_topology_only: Literal[True] = True
    authority: SourceFreeCaseAuthoringAuthorityV1 = Field(
        default_factory=SourceFreeCaseAuthoringAuthorityV1
    )
    builder_freeze: Literal["forbidden"] = "forbidden"
    prover_handoff: Literal["forbidden"] = "forbidden"
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_report(self) -> Self:
        if tuple(item.role for item in self.role_aggregates) != _ROLE_ORDER:
            raise ValueError("source-free report role order drifted")
        if self.authority != SourceFreeCaseAuthoringAuthorityV1():
            raise ValueError("source-free report authority flags drifted")
        if self.content_sha256 != self.computed_content_sha256():
            raise ValueError("source-free report content hash does not match its payload")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(dict[str, object], self.model_dump(mode="json", exclude={"content_sha256"}))

    def computed_content_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.content_payload())).hexdigest()

    def assert_not_authoritative(self) -> Never:
        raise SourceFreeCaseAuthoringError(
            "source-free case authoring report cannot classify a node, freeze a statement, or "
            "hand work to Prover"
        )

    def freeze_statement(self) -> Never:
        self.assert_not_authoritative()

    def handoff_to_prover(self) -> Never:
        self.assert_not_authoritative()


class SourceFreeCaseAuthoringFakeAgent:
    """Deterministic local actor used only to exercise the three finite response grammars."""

    def author(self, card: SourceFreeAuthoringCardV1) -> str:
        candidate = _expected_candidate_from_values(
            card.baseline,
            selector=card.selector,
            increment=card.increment,
        )
        return _render_fake_response(
            {
                "schema_version": "autolean.ifem-source-free-authoring-response.v1",
                "disposition": SourceFreeAuthoringDispositionV1.PROPOSE.value,
                "selected_slot": card.selector,
                "candidate": candidate.model_dump(mode="json"),
            }
        )

    def review(self, card: SourceFreeReviewerCardV1) -> str:
        expected = _expected_candidate_from_values(
            card.baseline,
            selector=card.selector,
            increment=card.increment,
        )
        if card.author_disposition is SourceFreeAuthoringDispositionV1.ABSTAIN:
            disposition = SourceFreeReviewDispositionV1.ABSTAIN
            changes = 0
        else:
            changes = _changed_slot_count(card.baseline, card.author_candidate)
            disposition = (
                SourceFreeReviewDispositionV1.ACCEPT
                if card.author_selected_slot == card.selector
                and card.author_candidate == expected
                and changes == 1
                else SourceFreeReviewDispositionV1.REJECT
            )
        return _render_fake_response(
            {
                "schema_version": "autolean.ifem-source-free-review-response.v1",
                "disposition": disposition.value,
                "observed_change_count": changes,
            }
        )

    def supervise(self, card: SourceFreeSupervisorCardV1) -> str:
        if (
            card.author_disposition is SourceFreeAuthoringDispositionV1.ABSTAIN
            or card.reviewer_disposition is SourceFreeReviewDispositionV1.ABSTAIN
        ):
            disposition = SourceFreeSupervisorDispositionV1.ABSTAIN
            violation_detected = False
        elif (
            card.reviewer_disposition is SourceFreeReviewDispositionV1.ACCEPT
            and card.observed_change_count == 1
        ):
            disposition = SourceFreeSupervisorDispositionV1.ALLOW
            violation_detected = False
        else:
            disposition = SourceFreeSupervisorDispositionV1.REJECT
            violation_detected = True
        return _render_fake_response(
            {
                "schema_version": "autolean.ifem-source-free-supervisor-response.v1",
                "disposition": disposition.value,
                "violation_detected": violation_detected,
            }
        )


def _expected_candidate_from_values(
    baseline: SourceFreeSignatureV1,
    *,
    selector: int,
    increment: int,
) -> SourceFreeSignatureV1:
    values = [baseline.alpha, baseline.beta, baseline.gamma]
    values[selector] += increment
    return SourceFreeSignatureV1(
        alpha=values[0],
        beta=values[1],
        gamma=values[2],
        guard_enabled=baseline.guard_enabled,
    )


def _changed_slot_count(
    baseline: SourceFreeSignatureV1,
    candidate: SourceFreeSignatureV1 | None,
) -> int:
    if candidate is None:
        return 0
    return sum(
        before != after
        for before, after in zip(
            (baseline.alpha, baseline.beta, baseline.gamma),
            (candidate.alpha, candidate.beta, candidate.gamma),
            strict=True,
        )
    )


def _require_authorable_intent(intent: IFEMNextCalibrationCaseIntentV1) -> None:
    if type(intent) is not IFEMNextCalibrationCaseIntentV1:
        raise SourceFreeCaseAuthoringError("case authoring requires the exact intent model")
    if (
        intent.calibration_priority is not IFEMCalibrationPriorityV1.P3_CREATE_CALIBRATION_CASE
        or intent.required_next_calibration
        is not IFEMRequiredNextCalibrationV1.CREATE_CALIBRATION_CASE
        or not intent.structural_risk_discovery_required
        or intent.materialization_state != "not_authored"
        or intent.semantic_classification != "unknown"
    ):
        raise SourceFreeCaseAuthoringError(
            "only a P3 create-calibration-case unknown intent may enter source-free authoring"
        )


def _revalidate_intents(
    intents: IFEMNextCalibrationCaseIntentsV1,
) -> IFEMNextCalibrationCaseIntentsV1:
    if type(intents) is not IFEMNextCalibrationCaseIntentsV1:
        raise SourceFreeCaseAuthoringError("case authoring requires the exact intent queue type")
    try:
        value = IFEMNextCalibrationCaseIntentsV1.model_validate(intents.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as error:
        raise SourceFreeCaseAuthoringError(
            "source-free intent queue failed revalidation"
        ) from error
    if (
        not value.source_free
        or value.formalization_payload_present
        or value.model_payload_present
        or value.private_state_present
        or value.authority != type(value.authority)()
    ):
        raise SourceFreeCaseAuthoringError("source-free intent queue crossed its metadata boundary")
    return value


def _case_id(
    intents: IFEMNextCalibrationCaseIntentsV1,
    intent: IFEMNextCalibrationCaseIntentV1,
) -> StableIdentifierV1:
    return stable_identifier(
        _CASE_NAMESPACE,
        f"{intents.content_sha256}:{intent.intent_id.value}",
    )


def _ranking_key(
    intents: IFEMNextCalibrationCaseIntentsV1,
    intent: IFEMNextCalibrationCaseIntentV1,
) -> tuple[str, str]:
    digest = hashlib.sha256(
        canonical_json_bytes(
            {
                "schema_version": "autolean.ifem-source-free-case-rank.v1",
                "intent_queue_content_sha256": intents.content_sha256,
                "intent_id": intent.intent_id.model_dump(mode="json"),
            }
        )
    ).hexdigest()
    return digest, intent.intent_id.value


def _partition_for_rank(index: int) -> PairSplitPartitionV1:
    if index < 3:
        return PairSplitPartitionV1.TRAIN
    if index < 6:
        return PairSplitPartitionV1.DEV
    if index < 9:
        return PairSplitPartitionV1.PRIVATE_HELDOUT
    raise SourceFreeCaseAuthoringError("source-free case partition rank is outside nine cases")


def build_private_source_free_case_seed(
    intents: IFEMNextCalibrationCaseIntentsV1,
    intent: IFEMNextCalibrationCaseIntentV1,
    *,
    partition: PairSplitPartitionV1,
) -> PrivateSourceFreeCaseSeedV1:
    """Build one private finite seed; P0/P1/P2 inputs fail before any card is created."""

    queue = _revalidate_intents(intents)
    _require_authorable_intent(intent)
    if intent not in queue.intents:
        raise SourceFreeCaseAuthoringError("authoring intent is not a member of its exact queue")
    case_id = _case_id(queue, intent)
    digest = hashlib.sha256(
        canonical_json_bytes(
            {
                "schema_version": "autolean.ifem-source-free-case-seed-derivation.v1",
                "case_id": case_id.model_dump(mode="json"),
                "intent_queue_content_sha256": queue.content_sha256,
            }
        )
    ).digest()
    baseline = SourceFreeSignatureV1(
        alpha=digest[0] % 7,
        beta=digest[1] % 7,
        gamma=digest[2] % 7,
        guard_enabled=bool(digest[3] % 2),
    )
    selector = digest[4] % 3
    increment = 1 + digest[5] % 3
    expected_candidate = _expected_candidate_from_values(
        baseline,
        selector=selector,
        increment=increment,
    )
    payload: dict[str, object] = {
        "schema_version": "autolean.ifem-source-free-case-seed.v1",
        "case_id": case_id.model_dump(mode="json"),
        "intent_id": intent.intent_id.model_dump(mode="json"),
        "node_id": intent.node_id,
        "partition": partition.value,
        "baseline": baseline.model_dump(mode="json"),
        "selector": selector,
        "increment": increment,
        "hidden_oracle": SourceFreeHiddenOracleV1(
            selected_slot=selector,
            expected_candidate=expected_candidate,
        ).model_dump(mode="json"),
        "source_free": True,
        "textbook_derived": False,
        "lean_surface_present": False,
        "authority": SourceFreeCaseAuthoringAuthorityV1().model_dump(mode="json"),
    }
    payload["seed_commitment_sha256"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    try:
        return PrivateSourceFreeCaseSeedV1.model_validate(payload)
    except ValueError as error:
        raise SourceFreeCaseAuthoringError(
            "generated private source-free seed is invalid"
        ) from error


def build_private_source_free_case_seeds(
    intents: IFEMNextCalibrationCaseIntentsV1,
) -> tuple[PrivateSourceFreeCaseSeedV1, ...]:
    """Use every and only the nine P3 intents, partitioned deterministically 3/3/3."""

    queue = _revalidate_intents(intents)
    authorable = tuple(
        item
        for item in queue.intents
        if item.calibration_priority is IFEMCalibrationPriorityV1.P3_CREATE_CALIBRATION_CASE
    )
    if len(authorable) != 9:
        raise SourceFreeCaseAuthoringError(
            "source-free authoring requires exactly nine P3 create-calibration-case intents"
        )
    for intent in authorable:
        _require_authorable_intent(intent)
    ranked = tuple(sorted(authorable, key=lambda item: _ranking_key(queue, item)))
    seeds = tuple(
        build_private_source_free_case_seed(
            queue,
            intent,
            partition=_partition_for_rank(index),
        )
        for index, intent in enumerate(ranked)
    )
    return tuple(sorted(seeds, key=lambda item: item.case_id.value))


def _seed_collection_commitment(seeds: tuple[PrivateSourceFreeCaseSeedV1, ...]) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "schema_version": "autolean.ifem-source-free-case-seed-collection.v1",
                "seed_commitments": [item.seed_commitment_sha256 for item in seeds],
            }
        )
    ).hexdigest()


def build_source_free_case_authoring_plan(
    intents: IFEMNextCalibrationCaseIntentsV1,
) -> SourceFreeCaseAuthoringPlanV1:
    """Create the public digest-only plan from an exact source-free queue."""

    queue = _revalidate_intents(intents)
    seeds = build_private_source_free_case_seeds(queue)
    coordinates = tuple(
        sorted(
            (
                SourceFreeCaseCoordinateV1(
                    case_id=seed.case_id,
                    partition=seed.partition,
                    seed_commitment_sha256=seed.seed_commitment_sha256,
                )
                for seed in seeds
            ),
            key=lambda item: item.case_id.value,
        )
    )
    payload: dict[str, object] = {
        "schema_version": SOURCE_FREE_CASE_AUTHORING_SCHEMA,
        "protocol": SOURCE_FREE_CASE_AUTHORING_PROTOCOL,
        "artifact_kind": SOURCE_FREE_CASE_AUTHORING_KIND,
        "intent_queue_content_sha256": queue.content_sha256,
        "case_coordinates": [item.model_dump(mode="json") for item in coordinates],
        "role_order": [role.value for role in _ROLE_ORDER],
        "train_case_count": 3,
        "dev_case_count": 3,
        "private_heldout_case_count": 3,
        "stage_count": 27,
        "max_attempts_per_stage": 1,
        "seed_collection_commitment_sha256": _seed_collection_commitment(seeds),
        "source_free": True,
        "private_seed_embedded": False,
        "raw_agent_output_embedded": False,
        "case_linkage_publicly_replayable": True,
        "partition_labels_topology_only": True,
        "authority": SourceFreeCaseAuthoringAuthorityV1().model_dump(mode="json"),
        "builder_freeze": "forbidden",
        "prover_handoff": "forbidden",
    }
    payload["content_sha256"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    plan = SourceFreeCaseAuthoringPlanV1.model_validate(payload)
    if plan.seed_collection_commitment_sha256 != _seed_collection_commitment(seeds):
        raise SourceFreeCaseAuthoringError("private seed collection commitment drifted")
    return plan


def verify_source_free_case_authoring_plan_against_intents(
    plan: SourceFreeCaseAuthoringPlanV1,
    intents: IFEMNextCalibrationCaseIntentsV1,
) -> None:
    """Reject a self-hashed plan unless it is an exact replay of its source-free queue."""

    if type(plan) is not SourceFreeCaseAuthoringPlanV1:
        raise SourceFreeCaseAuthoringError("source-free plan must use its exact typed model")
    try:
        actual = SourceFreeCaseAuthoringPlanV1.model_validate(plan.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as error:
        raise SourceFreeCaseAuthoringError("source-free plan failed revalidation") from error
    expected = build_source_free_case_authoring_plan(intents)
    if actual != expected:
        raise SourceFreeCaseAuthoringError("source-free plan differs from exact intent replay")


def build_source_free_authoring_card(
    seed: PrivateSourceFreeCaseSeedV1,
) -> SourceFreeAuthoringCardV1:
    """Project only finite project-synthetic fields to the author role."""

    _revalidate_seed(seed)
    return SourceFreeAuthoringCardV1(
        case_id=seed.case_id,
        baseline=seed.baseline,
        selector=seed.selector,
        increment=seed.increment,
    )


def build_source_free_reviewer_card(
    seed: PrivateSourceFreeCaseSeedV1,
    authoring: SourceFreeAuthoringResponseV1,
) -> SourceFreeReviewerCardV1:
    """Pass only parsed finite authoring fields to the fidelity reviewer."""

    _revalidate_seed(seed)
    authoring = _revalidate_authoring_response(authoring)
    return SourceFreeReviewerCardV1(
        case_id=seed.case_id,
        baseline=seed.baseline,
        selector=seed.selector,
        increment=seed.increment,
        author_disposition=authoring.disposition,
        author_selected_slot=authoring.selected_slot,
        author_candidate=authoring.candidate,
    )


def build_source_free_supervisor_card(
    seed: PrivateSourceFreeCaseSeedV1,
    authoring: SourceFreeAuthoringResponseV1,
    review: SourceFreeReviewResponseV1,
) -> SourceFreeSupervisorCardV1:
    """Pass the smallest bounded projection to the cheating-supervisor role."""

    _revalidate_seed(seed)
    authoring = _revalidate_authoring_response(authoring)
    review = _revalidate_review_response(review)
    return SourceFreeSupervisorCardV1(
        case_id=seed.case_id,
        author_disposition=authoring.disposition,
        reviewer_disposition=review.disposition,
        observed_change_count=_changed_slot_count(seed.baseline, authoring.candidate),
    )


def _strict_json_object(raw: str | bytes, *, label: str) -> dict[str, object]:
    try:
        text = raw.decode("utf-8", errors="strict") if isinstance(raw, bytes) else raw
    except UnicodeDecodeError as error:
        raise SourceFreeCaseAuthoringError(f"{label} is not strict UTF-8") from error
    if not isinstance(text, str):
        raise SourceFreeCaseAuthoringError(f"{label} must be JSON text")

    def reject_constant(value: str) -> Never:
        raise SourceFreeCaseAuthoringError(f"{label} contains non-finite JSON constant: {value}")

    try:
        value: object = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=reject_constant,
        )
    except (json.JSONDecodeError, SourceFreeCaseAuthoringError) as error:
        raise SourceFreeCaseAuthoringError(f"{label} is not strict JSON") from error
    if not isinstance(value, dict):
        raise SourceFreeCaseAuthoringError(f"{label} must be a JSON object")
    return cast(dict[str, object], value)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise SourceFreeCaseAuthoringError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _require_exact_keys(
    payload: dict[str, object],
    *,
    expected: frozenset[str],
    label: str,
) -> None:
    actual = frozenset(payload)
    if actual != expected:
        raise SourceFreeCaseAuthoringError(
            f"{label} must contain exactly {sorted(expected)}, got {sorted(actual)}"
        )


def _require_json_string(value: object, *, label: str) -> None:
    if type(value) is not str:
        raise SourceFreeCaseAuthoringError(f"{label} must be a JSON string")


def _require_json_integer(value: object, *, label: str) -> None:
    if type(value) is not int:
        raise SourceFreeCaseAuthoringError(f"{label} must be a JSON integer")


def _require_json_boolean(value: object, *, label: str) -> None:
    if type(value) is not bool:
        raise SourceFreeCaseAuthoringError(f"{label} must be a JSON boolean")


def _validate_raw_signature_payload(value: object, *, label: str) -> None:
    if not isinstance(value, dict):
        raise SourceFreeCaseAuthoringError(f"{label} must be a JSON object")
    payload = cast(dict[str, object], value)
    _require_exact_keys(
        payload,
        expected=frozenset({"alpha", "beta", "gamma", "guard_enabled"}),
        label=label,
    )
    for field_name in ("alpha", "beta", "gamma"):
        _require_json_integer(payload[field_name], label=f"{label}.{field_name}")
    _require_json_boolean(payload["guard_enabled"], label=f"{label}.guard_enabled")


def _validate_raw_authoring_response_payload(payload: dict[str, object]) -> None:
    _require_exact_keys(
        payload,
        expected=frozenset({"schema_version", "disposition", "selected_slot", "candidate"}),
        label="authoring response",
    )
    _require_json_string(payload["schema_version"], label="authoring response.schema_version")
    _require_json_string(payload["disposition"], label="authoring response.disposition")
    selected_slot = payload["selected_slot"]
    if selected_slot is not None:
        _require_json_integer(selected_slot, label="authoring response.selected_slot")
    candidate = payload["candidate"]
    if candidate is not None:
        _validate_raw_signature_payload(candidate, label="authoring response.candidate")


def _validate_raw_review_response_payload(payload: dict[str, object]) -> None:
    _require_exact_keys(
        payload,
        expected=frozenset({"schema_version", "disposition", "observed_change_count"}),
        label="review response",
    )
    _require_json_string(payload["schema_version"], label="review response.schema_version")
    _require_json_string(payload["disposition"], label="review response.disposition")
    _require_json_integer(
        payload["observed_change_count"],
        label="review response.observed_change_count",
    )


def _validate_raw_supervisor_response_payload(payload: dict[str, object]) -> None:
    _require_exact_keys(
        payload,
        expected=frozenset({"schema_version", "disposition", "violation_detected"}),
        label="supervisor response",
    )
    _require_json_string(payload["schema_version"], label="supervisor response.schema_version")
    _require_json_string(payload["disposition"], label="supervisor response.disposition")
    _require_json_boolean(
        payload["violation_detected"],
        label="supervisor response.violation_detected",
    )


def _revalidate_authoring_response(
    response: SourceFreeAuthoringResponseV1,
) -> SourceFreeAuthoringResponseV1:
    if type(response) is not SourceFreeAuthoringResponseV1:
        raise SourceFreeCaseAuthoringError("authoring response must use its exact typed model")
    try:
        return SourceFreeAuthoringResponseV1.model_validate(response.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as error:
        raise SourceFreeCaseAuthoringError("authoring response failed revalidation") from error


def _revalidate_review_response(response: SourceFreeReviewResponseV1) -> SourceFreeReviewResponseV1:
    if type(response) is not SourceFreeReviewResponseV1:
        raise SourceFreeCaseAuthoringError("review response must use its exact typed model")
    try:
        return SourceFreeReviewResponseV1.model_validate(response.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as error:
        raise SourceFreeCaseAuthoringError("review response failed revalidation") from error


def _revalidate_supervisor_response(
    response: SourceFreeSupervisorResponseV1,
) -> SourceFreeSupervisorResponseV1:
    if type(response) is not SourceFreeSupervisorResponseV1:
        raise SourceFreeCaseAuthoringError("supervisor response must use its exact typed model")
    try:
        return SourceFreeSupervisorResponseV1.model_validate(response.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as error:
        raise SourceFreeCaseAuthoringError("supervisor response failed revalidation") from error


def _revalidate_seed(seed: PrivateSourceFreeCaseSeedV1) -> PrivateSourceFreeCaseSeedV1:
    if type(seed) is not PrivateSourceFreeCaseSeedV1:
        raise SourceFreeCaseAuthoringError(
            "private source-free seed must use its exact typed model"
        )
    try:
        return PrivateSourceFreeCaseSeedV1.model_validate(seed.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as error:
        raise SourceFreeCaseAuthoringError(
            "private source-free seed failed revalidation"
        ) from error


def parse_source_free_authoring_response(
    raw: str | bytes,
) -> SourceFreeAuthoringResponseV1:
    payload = _strict_json_object(raw, label="authoring response")
    _validate_raw_authoring_response_payload(payload)
    try:
        return SourceFreeAuthoringResponseV1.model_validate(payload)
    except ValueError as error:
        raise SourceFreeCaseAuthoringError(
            "authoring response violates the finite schema"
        ) from error


def parse_source_free_review_response(raw: str | bytes) -> SourceFreeReviewResponseV1:
    payload = _strict_json_object(raw, label="review response")
    _validate_raw_review_response_payload(payload)
    try:
        return SourceFreeReviewResponseV1.model_validate(payload)
    except ValueError as error:
        raise SourceFreeCaseAuthoringError("review response violates the finite schema") from error


def parse_source_free_supervisor_response(
    raw: str | bytes,
) -> SourceFreeSupervisorResponseV1:
    payload = _strict_json_object(raw, label="supervisor response")
    _validate_raw_supervisor_response_payload(payload)
    try:
        return SourceFreeSupervisorResponseV1.model_validate(payload)
    except ValueError as error:
        raise SourceFreeCaseAuthoringError(
            "supervisor response violates the finite schema"
        ) from error


def evaluate_private_source_free_case(
    seed: PrivateSourceFreeCaseSeedV1,
    authoring: SourceFreeAuthoringResponseV1,
    review: SourceFreeReviewResponseV1,
    supervisor: SourceFreeSupervisorResponseV1,
) -> PrivateSourceFreeCaseEvaluationV1:
    """Evaluate finite synthetic relations without asserting mathematical fidelity."""

    seed = _revalidate_seed(seed)
    authoring = _revalidate_authoring_response(authoring)
    review = _revalidate_review_response(review)
    supervisor = _revalidate_supervisor_response(supervisor)
    if authoring.disposition is SourceFreeAuthoringDispositionV1.ABSTAIN:
        author_status = SourceFreeStageStatusV1.ABSTAIN
    elif (
        authoring.selected_slot == seed.hidden_oracle.selected_slot
        and authoring.candidate == seed.hidden_oracle.expected_candidate
    ):
        author_status = SourceFreeStageStatusV1.CORRECT
    else:
        author_status = SourceFreeStageStatusV1.INCORRECT

    expected_changes = _changed_slot_count(seed.baseline, authoring.candidate)
    if author_status is SourceFreeStageStatusV1.ABSTAIN:
        reviewer_status = (
            SourceFreeStageStatusV1.CORRECT
            if review.disposition is SourceFreeReviewDispositionV1.ABSTAIN
            and review.observed_change_count == 0
            else SourceFreeStageStatusV1.INCORRECT
        )
    else:
        expected_review = (
            SourceFreeReviewDispositionV1.ACCEPT
            if author_status is SourceFreeStageStatusV1.CORRECT and expected_changes == 1
            else SourceFreeReviewDispositionV1.REJECT
        )
        reviewer_status = (
            SourceFreeStageStatusV1.CORRECT
            if review.disposition is expected_review
            and review.observed_change_count == expected_changes
            else SourceFreeStageStatusV1.INCORRECT
        )

    if (
        author_status is SourceFreeStageStatusV1.ABSTAIN
        and review.disposition is SourceFreeReviewDispositionV1.ABSTAIN
    ):
        supervisor_status = (
            SourceFreeStageStatusV1.CORRECT
            if supervisor.disposition is SourceFreeSupervisorDispositionV1.ABSTAIN
            and not supervisor.violation_detected
            else SourceFreeStageStatusV1.INCORRECT
        )
    else:
        allow = (
            author_status is SourceFreeStageStatusV1.CORRECT
            and reviewer_status is SourceFreeStageStatusV1.CORRECT
            and review.disposition is SourceFreeReviewDispositionV1.ACCEPT
            and expected_changes == 1
        )
        expected_disposition = (
            SourceFreeSupervisorDispositionV1.ALLOW
            if allow
            else SourceFreeSupervisorDispositionV1.REJECT
        )
        supervisor_status = (
            SourceFreeStageStatusV1.CORRECT
            if supervisor.disposition is expected_disposition
            and supervisor.violation_detected is (not allow)
            else SourceFreeStageStatusV1.INCORRECT
        )
    return PrivateSourceFreeCaseEvaluationV1(
        case_id=seed.case_id,
        partition=seed.partition,
        authoring_status=author_status,
        reviewer_status=reviewer_status,
        supervisor_status=supervisor_status,
    )


def run_source_free_case_authoring_fake(
    plan: SourceFreeCaseAuthoringPlanV1,
    intents: IFEMNextCalibrationCaseIntentsV1,
    *,
    agent: SourceFreeCaseAuthoringFakeAgent | None = None,
) -> PrivateSourceFreeCaseAuthoringRunV1:
    """Run all twenty-seven finite stages locally without provider, key, or network I/O."""

    verify_source_free_case_authoring_plan_against_intents(plan, intents)
    actual_plan = SourceFreeCaseAuthoringPlanV1.model_validate(plan.model_dump(mode="json"))
    seeds = build_private_source_free_case_seeds(intents)
    expected_coordinates = tuple(
        SourceFreeCaseCoordinateV1(
            case_id=seed.case_id,
            partition=seed.partition,
            seed_commitment_sha256=seed.seed_commitment_sha256,
        )
        for seed in seeds
    )
    if actual_plan.case_coordinates != expected_coordinates:
        raise SourceFreeCaseAuthoringError(
            "source-free plan is detached from its private seed replay"
        )
    fake_agent = agent if agent is not None else SourceFreeCaseAuthoringFakeAgent()
    if type(fake_agent) is not SourceFreeCaseAuthoringFakeAgent:
        raise SourceFreeCaseAuthoringError(
            "source-free fake run requires the exact local fake agent"
        )
    evaluations: list[PrivateSourceFreeCaseEvaluationV1] = []
    for seed in seeds:
        authoring = parse_source_free_authoring_response(
            fake_agent.author(build_source_free_authoring_card(seed))
        )
        review = parse_source_free_review_response(
            fake_agent.review(build_source_free_reviewer_card(seed, authoring))
        )
        supervisor = parse_source_free_supervisor_response(
            fake_agent.supervise(build_source_free_supervisor_card(seed, authoring, review))
        )
        evaluations.append(evaluate_private_source_free_case(seed, authoring, review, supervisor))
    ordered = tuple(sorted(evaluations, key=lambda item: item.case_id.value))
    payload: dict[str, object] = {
        "schema_version": "autolean.ifem-source-free-case-authoring-private-run.v1",
        "plan_content_sha256": actual_plan.content_sha256,
        "evaluations": [item.model_dump(mode="json") for item in ordered],
        "fake_only": True,
        "raw_agent_output_retained": False,
        "authority": SourceFreeCaseAuthoringAuthorityV1().model_dump(mode="json"),
    }
    payload["run_content_sha256"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    try:
        return PrivateSourceFreeCaseAuthoringRunV1.model_validate(payload)
    except ValueError as error:
        raise SourceFreeCaseAuthoringError("source-free fake run is invalid") from error


def summarize_source_free_case_authoring_run(
    plan: SourceFreeCaseAuthoringPlanV1,
    private_run: PrivateSourceFreeCaseAuthoringRunV1,
) -> SourceFreeCaseAuthoringReportV1:
    """Render role-local public counts from an exact in-memory fake run."""

    if type(private_run) is not PrivateSourceFreeCaseAuthoringRunV1:
        raise SourceFreeCaseAuthoringError("source-free report requires an exact private run")
    try:
        run = PrivateSourceFreeCaseAuthoringRunV1.model_validate(
            private_run.model_dump(mode="json")
        )
        actual_plan = SourceFreeCaseAuthoringPlanV1.model_validate(plan.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as error:
        raise SourceFreeCaseAuthoringError(
            "source-free report inputs failed revalidation"
        ) from error
    if run.plan_content_sha256 != actual_plan.content_sha256:
        raise SourceFreeCaseAuthoringError("source-free private run binds another plan")
    expected_coordinates = tuple(
        (item.case_id, item.partition) for item in actual_plan.case_coordinates
    )
    actual_coordinates = tuple((item.case_id, item.partition) for item in run.evaluations)
    if actual_coordinates != expected_coordinates:
        raise SourceFreeCaseAuthoringError(
            "source-free private run coordinates differ from its plan"
        )
    role_statuses: dict[ModelWorkRoleV1, tuple[SourceFreeStageStatusV1, ...]] = {
        ModelWorkRoleV1.STATEMENT_FORMALIZER: tuple(
            item.authoring_status for item in run.evaluations
        ),
        ModelWorkRoleV1.FIDELITY_REVIEWER: tuple(item.reviewer_status for item in run.evaluations),
        ModelWorkRoleV1.CHEATING_SUPERVISOR: tuple(
            item.supervisor_status for item in run.evaluations
        ),
    }
    aggregates = tuple(
        SourceFreeCaseAuthoringRoleAggregateV1(
            role=role,
            correct_count=statuses.count(SourceFreeStageStatusV1.CORRECT),
            incorrect_count=statuses.count(SourceFreeStageStatusV1.INCORRECT),
            abstain_count=statuses.count(SourceFreeStageStatusV1.ABSTAIN),
        )
        for role, statuses in ((role, role_statuses[role]) for role in _ROLE_ORDER)
    )
    payload: dict[str, object] = {
        "schema_version": "autolean.ifem-source-free-case-authoring-report.v1",
        "plan_content_sha256": actual_plan.content_sha256,
        "private_run_content_sha256": run.run_content_sha256,
        "case_count": 9,
        "stage_count": 27,
        "role_aggregates": [item.model_dump(mode="json") for item in aggregates],
        "fake_only": True,
        "same_agent_model_across_roles": True,
        "machine_advisory_disposition": "abstain",
        "semantic_fidelity_claimed": False,
        "private_seed_embedded": False,
        "raw_agent_output_embedded": False,
        "case_linkage_publicly_replayable": True,
        "partition_labels_topology_only": True,
        "authority": SourceFreeCaseAuthoringAuthorityV1().model_dump(mode="json"),
        "builder_freeze": "forbidden",
        "prover_handoff": "forbidden",
    }
    payload["content_sha256"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    try:
        return SourceFreeCaseAuthoringReportV1.model_validate(payload)
    except ValueError as error:
        raise SourceFreeCaseAuthoringError("source-free public report is invalid") from error


def render_source_free_case_authoring_plan(plan: SourceFreeCaseAuthoringPlanV1) -> bytes:
    """Canonical public plan rendering with an explicit forbidden-surface check."""

    if type(plan) is not SourceFreeCaseAuthoringPlanV1:
        raise SourceFreeCaseAuthoringError("source-free plan must use its exact typed model")
    try:
        verified = SourceFreeCaseAuthoringPlanV1.model_validate(plan.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as error:
        raise SourceFreeCaseAuthoringError("source-free plan failed revalidation") from error
    return _render_public(verified.model_dump(mode="json"), label="source-free plan")


def render_source_free_case_authoring_report(report: SourceFreeCaseAuthoringReportV1) -> bytes:
    """Canonical public report rendering with an explicit forbidden-surface check."""

    if type(report) is not SourceFreeCaseAuthoringReportV1:
        raise SourceFreeCaseAuthoringError("source-free report must use its exact typed model")
    try:
        verified = SourceFreeCaseAuthoringReportV1.model_validate(report.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as error:
        raise SourceFreeCaseAuthoringError("source-free report failed revalidation") from error
    return _render_public(verified.model_dump(mode="json"), label="source-free report")


def _render_public(payload: object, *, label: str) -> bytes:
    rendered = canonical_json_bytes(payload) + b"\n"
    if any(field in rendered for field in _FORBIDDEN_PUBLIC_FIELDS):
        raise SourceFreeCaseAuthoringError(f"{label} rendering leaked a forbidden surface")
    return rendered


def _load_canonical(path: Path, *, label: str) -> dict[str, object]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise SourceFreeCaseAuthoringError(f"cannot read {label}") from error
    payload = _strict_json_object(raw, label=label)
    return payload


def load_source_free_case_authoring_plan(path: Path) -> SourceFreeCaseAuthoringPlanV1:
    payload = _load_canonical(path, label="source-free plan")
    try:
        plan = SourceFreeCaseAuthoringPlanV1.model_validate(payload)
    except ValueError as error:
        raise SourceFreeCaseAuthoringError("source-free plan is invalid") from error
    if render_source_free_case_authoring_plan(plan) != path.read_bytes():
        raise SourceFreeCaseAuthoringError("source-free plan is not canonically rendered")
    return plan


def load_source_free_case_authoring_report(path: Path) -> SourceFreeCaseAuthoringReportV1:
    payload = _load_canonical(path, label="source-free report")
    try:
        report = SourceFreeCaseAuthoringReportV1.model_validate(payload)
    except ValueError as error:
        raise SourceFreeCaseAuthoringError("source-free report is invalid") from error
    if render_source_free_case_authoring_report(report) != path.read_bytes():
        raise SourceFreeCaseAuthoringError("source-free report is not canonically rendered")
    return report


def _write_once(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError:
        try:
            existing = path.read_bytes()
        except OSError as error:
            raise SourceFreeCaseAuthoringError("cannot read existing write-once output") from error
        if existing != content:
            raise SourceFreeCaseAuthoringError(
                "write-once output already exists with different bytes"
            ) from None


def materialize_source_free_case_authoring_plan_once(
    path: Path,
    intents: IFEMNextCalibrationCaseIntentsV1,
) -> SourceFreeCaseAuthoringPlanV1:
    plan = build_source_free_case_authoring_plan(intents)
    _write_once(path, render_source_free_case_authoring_plan(plan))
    return plan


def materialize_source_free_case_authoring_report_once(
    path: Path,
    plan: SourceFreeCaseAuthoringPlanV1,
    private_run: PrivateSourceFreeCaseAuthoringRunV1,
) -> SourceFreeCaseAuthoringReportV1:
    report = summarize_source_free_case_authoring_run(plan, private_run)
    _write_once(path, render_source_free_case_authoring_report(report))
    return report


def _render_fake_response(payload: dict[str, object]) -> str:
    return canonical_json_bytes(payload).decode("utf-8")


def parse_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--intents", type=Path, required=True)
    parser.add_argument("--plan-out", type=Path, required=True)
    parser.add_argument("--report-out", type=Path, required=True)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    namespace = parse_arguments(arguments)
    try:
        intents = load_ifem_next_calibration_case_intents(namespace.intents)
    except IFEMNextCalibrationCaseIntentError as error:
        raise SourceFreeCaseAuthoringError("cannot load the source-free intent queue") from error
    plan = materialize_source_free_case_authoring_plan_once(namespace.plan_out, intents)
    private_run = run_source_free_case_authoring_fake(plan, intents)
    report = materialize_source_free_case_authoring_report_once(
        namespace.report_out,
        plan,
        private_run,
    )
    print(report.content_sha256)
    return 0


__all__ = [
    "SOURCE_FREE_CASE_AUTHORING_KIND",
    "SOURCE_FREE_CASE_AUTHORING_PROTOCOL",
    "SOURCE_FREE_CASE_AUTHORING_SCHEMA",
    "PrivateSourceFreeCaseAuthoringRunV1",
    "PrivateSourceFreeCaseSeedV1",
    "SourceFreeAuthoringCardV1",
    "SourceFreeAuthoringDispositionV1",
    "SourceFreeAuthoringResponseV1",
    "SourceFreeCaseAuthoringAuthorityV1",
    "SourceFreeCaseAuthoringError",
    "SourceFreeCaseAuthoringFakeAgent",
    "SourceFreeCaseAuthoringPlanV1",
    "SourceFreeCaseAuthoringReportV1",
    "SourceFreeCaseCoordinateV1",
    "SourceFreeReviewDispositionV1",
    "SourceFreeReviewResponseV1",
    "SourceFreeReviewerCardV1",
    "SourceFreeSignatureV1",
    "SourceFreeStageStatusV1",
    "SourceFreeSupervisorCardV1",
    "SourceFreeSupervisorDispositionV1",
    "SourceFreeSupervisorResponseV1",
    "build_private_source_free_case_seed",
    "build_private_source_free_case_seeds",
    "build_source_free_authoring_card",
    "build_source_free_case_authoring_plan",
    "build_source_free_reviewer_card",
    "build_source_free_supervisor_card",
    "evaluate_private_source_free_case",
    "load_source_free_case_authoring_plan",
    "load_source_free_case_authoring_report",
    "main",
    "materialize_source_free_case_authoring_plan_once",
    "materialize_source_free_case_authoring_report_once",
    "parse_source_free_authoring_response",
    "parse_source_free_review_response",
    "parse_source_free_supervisor_response",
    "render_source_free_case_authoring_plan",
    "render_source_free_case_authoring_report",
    "run_source_free_case_authoring_fake",
    "summarize_source_free_case_authoring_run",
    "verify_source_free_case_authoring_plan_against_intents",
]
