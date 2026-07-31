"""Route verified machine quorum evidence without creating semantic authority.

The quorum report deliberately keeps execution and semantic authority unverified.  This module is
the narrow P2-13 sidecar: it adds explicit reviewer risk signals, execution lineage, and calibration
freshness, then chooses only between continued sandbox review and abstention.  It is not connected
to :class:`workflow.FreezeGate` and can never create a Prover handoff.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal, Never

from autolean_contracts import (
    DigestV1,
    HashKindV1,
    ModelExecutionProviderBindingV1,
    canonical_json_bytes,
    digest_bytes,
)

from .machine_semantic_quorum import (
    MachineQuorumReason,
    VerifiedMachineQuorumReport,
)

_CANONICAL_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_DECISION_TOKEN = object()
_AUTHORITY_LIMITATIONS = (
    "the decision is machine advisory and cannot establish mathematical fidelity",
    "lineage and calibration sidecars are structurally bound but not authority-attested",
    "continued review is not a pass, admission, statement freeze, or Prover handoff",
)


class MachineAdvisoryAdmissionError(ValueError):
    """A P2-13 sidecar or routing input failed structural validation."""


class MachineReviewerRiskKindV1(StrEnum):
    CRITICAL_DISSENT = "critical_dissent"
    COUNTEREXAMPLE_REPORTED = "counterexample_reported"


class MachineAdvisoryDispositionV1(StrEnum):
    CONTINUE_MACHINE_ADVISORY_REVIEW = "continue_machine_advisory_review"
    ABSTAIN = "abstain"


class MachineAdvisoryAdmissionReasonV1(StrEnum):
    QUORUM_EXECUTION_UNVERIFIED = "quorum_execution_unverified"
    CONTENT_BLINDING_UNVERIFIED = "content_blinding_unverified"
    QUORUM_ESCALATION_REQUIRED = "quorum_escalation_required"
    REVIEWER_DISAGREEMENT = "reviewer_disagreement"
    MUTATION_SURVIVED = "mutation_survived"
    CRITICAL_MUTATION_SURVIVED = "critical_mutation_survived"
    SEMANTIC_CONTROL_REJECTED = "semantic_control_rejected"
    SEMANTIC_CHECK_FAILED = "semantic_check_failed"
    CRITICAL_DISSENT = "critical_dissent"
    COUNTEREXAMPLE_REPORTED = "counterexample_reported"
    RISK_ASSESSMENT_MISSING = "risk_assessment_missing"
    LINEAGE_MISSING = "lineage_missing"
    LINEAGE_ENVIRONMENT_MISMATCH = "lineage_environment_mismatch"
    SHARED_DECLARED_FAILURE_DOMAIN = "shared_declared_failure_domain"
    SHARED_MODEL_LINEAGE = "shared_model_lineage"
    LINEAGE_EVIDENCE_UNVERIFIED = "lineage_evidence_unverified"
    CALIBRATION_MISSING = "calibration_missing"
    CALIBRATION_PROTOCOL_MISMATCH = "calibration_protocol_mismatch"
    CALIBRATION_SCOPE_MISMATCH = "calibration_scope_mismatch"
    CALIBRATION_LINEAGE_MISMATCH = "calibration_lineage_mismatch"
    CALIBRATION_FROM_FUTURE = "calibration_from_future"
    CALIBRATION_STALE = "calibration_stale"
    CALIBRATION_EVIDENCE_UNVERIFIED = "calibration_evidence_unverified"


def _canonical_identifier(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _CANONICAL_ID.fullmatch(value) is None:
        raise MachineAdvisoryAdmissionError(
            f"{label} must use canonical lower-case identifier form"
        )
    return value


def _require_digest(value: DigestV1, kind: HashKindV1, *, label: str) -> None:
    if not isinstance(value, DigestV1) or value.kind is not kind:
        raise MachineAdvisoryAdmissionError(f"{label} must use digest kind {kind.value}")


def _normalized_utc(value: datetime, *, label: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise MachineAdvisoryAdmissionError(f"{label} must be timezone-aware")
    return value.astimezone(UTC)


def _utc_text(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class MachineAdvisoryExecutionLineageV1:
    """Declared public execution identity for one reviewer, never an authorization."""

    reviewer_id: str
    provider: ModelExecutionProviderBindingV1
    role_environment_hash: DigestV1
    runtime_environment_hash: DigestV1
    model_failure_domain_fingerprint: DigestV1
    model_lineage_fingerprint: DigestV1 = field(init=False)
    execution_lineage_fingerprint: DigestV1 = field(init=False)
    authority: Literal["declared_unverified"] = field(default="declared_unverified", init=False)

    def __post_init__(self) -> None:
        _canonical_identifier(self.reviewer_id, label="lineage reviewer id")
        if not isinstance(self.provider, ModelExecutionProviderBindingV1):
            raise MachineAdvisoryAdmissionError(
                "lineage provider must use ModelExecutionProviderBindingV1"
            )
        _require_digest(
            self.role_environment_hash,
            HashKindV1.ENVIRONMENT,
            label="lineage role environment hash",
        )
        _require_digest(
            self.runtime_environment_hash,
            HashKindV1.ENVIRONMENT,
            label="lineage runtime environment hash",
        )
        _require_digest(
            self.model_failure_domain_fingerprint,
            HashKindV1.MODEL_WORK_ITEM,
            label="model failure-domain fingerprint",
        )
        model_lineage = digest_bytes(
            HashKindV1.MODEL_WORK_ITEM,
            canonical_json_bytes(
                {
                    "schema_version": "autolean.machine-model-lineage.v1",
                    "model_id": self.provider.model_id,
                    "model_revision": self.provider.model_revision,
                }
            ),
        )
        object.__setattr__(self, "model_lineage_fingerprint", model_lineage)
        object.__setattr__(
            self,
            "execution_lineage_fingerprint",
            digest_bytes(
                HashKindV1.MODEL_WORK_ITEM,
                canonical_json_bytes(self.payload(include_fingerprints=False)),
            ),
        )

    def payload(self, *, include_fingerprints: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema_version": "autolean.machine-advisory-execution-lineage.v1",
            "authority": self.authority,
            "reviewer_id": self.reviewer_id,
            "provider": self.provider.model_dump(mode="json"),
            "role_environment_hash": self.role_environment_hash.model_dump(mode="json"),
            "runtime_environment_hash": self.runtime_environment_hash.model_dump(mode="json"),
            "model_failure_domain_fingerprint": (
                self.model_failure_domain_fingerprint.model_dump(mode="json")
            ),
        }
        if include_fingerprints:
            payload["model_lineage_fingerprint"] = self.model_lineage_fingerprint.model_dump(
                mode="json"
            )
            payload["execution_lineage_fingerprint"] = (
                self.execution_lineage_fingerprint.model_dump(mode="json")
            )
        return payload


@dataclass(frozen=True, slots=True)
class MachineAdvisoryCalibrationBindingV1:
    """Time-bounded calibration declaration; V1 never treats it as verified evidence."""

    reviewer_id: str
    calibration_artifact_fingerprint: DigestV1
    calibration_input_fingerprint: DigestV1
    protocol_fingerprint: DigestV1
    scope_fingerprint: DigestV1
    execution_lineage_fingerprint: DigestV1
    calibrated_at: datetime
    valid_until: datetime
    binding_fingerprint: DigestV1 = field(init=False)
    authority: Literal["machine_advisory"] = field(default="machine_advisory", init=False)

    def __post_init__(self) -> None:
        _canonical_identifier(self.reviewer_id, label="calibration reviewer id")
        for label, value in (
            ("calibration artifact fingerprint", self.calibration_artifact_fingerprint),
            ("calibration input fingerprint", self.calibration_input_fingerprint),
            ("calibration protocol fingerprint", self.protocol_fingerprint),
            ("calibration scope fingerprint", self.scope_fingerprint),
            ("calibration execution lineage fingerprint", self.execution_lineage_fingerprint),
        ):
            _require_digest(value, HashKindV1.MODEL_WORK_ITEM, label=label)
        calibrated_at = _normalized_utc(self.calibrated_at, label="calibrated_at")
        valid_until = _normalized_utc(self.valid_until, label="valid_until")
        if valid_until <= calibrated_at:
            raise MachineAdvisoryAdmissionError("calibration validity must end after calibration")
        object.__setattr__(self, "calibrated_at", calibrated_at)
        object.__setattr__(self, "valid_until", valid_until)
        object.__setattr__(
            self,
            "binding_fingerprint",
            digest_bytes(
                HashKindV1.MODEL_WORK_ITEM,
                canonical_json_bytes(self.payload(include_fingerprint=False)),
            ),
        )

    def payload(self, *, include_fingerprint: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema_version": "autolean.machine-advisory-calibration-binding.v1",
            "authority": self.authority,
            "reviewer_id": self.reviewer_id,
            "calibration_artifact_fingerprint": (
                self.calibration_artifact_fingerprint.model_dump(mode="json")
            ),
            "calibration_input_fingerprint": self.calibration_input_fingerprint.model_dump(
                mode="json"
            ),
            "protocol_fingerprint": self.protocol_fingerprint.model_dump(mode="json"),
            "scope_fingerprint": self.scope_fingerprint.model_dump(mode="json"),
            "execution_lineage_fingerprint": self.execution_lineage_fingerprint.model_dump(
                mode="json"
            ),
            "calibrated_at": _utc_text(self.calibrated_at),
            "valid_until": _utc_text(self.valid_until),
        }
        if include_fingerprint:
            payload["binding_fingerprint"] = self.binding_fingerprint.model_dump(mode="json")
        return payload


@dataclass(frozen=True, slots=True)
class MachineReviewerRiskSignalV1:
    """Response-bound critical dissent or counterexample report without raw finding text."""

    reviewer_id: str
    kind: MachineReviewerRiskKindV1
    subject_fingerprint: DigestV1
    task_fingerprint: DigestV1
    verdict_fingerprint: DigestV1
    finding_fingerprint: DigestV1
    signal_fingerprint: DigestV1 = field(init=False)
    authority: Literal["machine_advisory"] = field(default="machine_advisory", init=False)

    def __post_init__(self) -> None:
        _canonical_identifier(self.reviewer_id, label="risk signal reviewer id")
        if not isinstance(self.kind, MachineReviewerRiskKindV1):
            raise MachineAdvisoryAdmissionError("risk signal kind is invalid")
        for label, value in (
            ("risk subject fingerprint", self.subject_fingerprint),
            ("risk task fingerprint", self.task_fingerprint),
            ("risk verdict fingerprint", self.verdict_fingerprint),
            ("risk finding fingerprint", self.finding_fingerprint),
        ):
            _require_digest(value, HashKindV1.MODEL_WORK_ITEM, label=label)
        object.__setattr__(
            self,
            "signal_fingerprint",
            digest_bytes(
                HashKindV1.MODEL_WORK_ITEM,
                canonical_json_bytes(self.payload(include_fingerprint=False)),
            ),
        )

    def payload(self, *, include_fingerprint: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema_version": "autolean.machine-reviewer-risk-signal.v1",
            "authority": self.authority,
            "reviewer_id": self.reviewer_id,
            "kind": self.kind.value,
            "subject_fingerprint": self.subject_fingerprint.model_dump(mode="json"),
            "task_fingerprint": self.task_fingerprint.model_dump(mode="json"),
            "verdict_fingerprint": self.verdict_fingerprint.model_dump(mode="json"),
            "finding_fingerprint": self.finding_fingerprint.model_dump(mode="json"),
        }
        if include_fingerprint:
            payload["signal_fingerprint"] = self.signal_fingerprint.model_dump(mode="json")
        return payload


@dataclass(frozen=True, slots=True)
class MachineReviewerRiskAssessmentV1:
    """Complete per-reviewer risk declaration bound to one exact verified verdict."""

    reviewer_id: str
    subject_fingerprint: DigestV1
    task_fingerprint: DigestV1
    verdict_fingerprint: DigestV1
    signals: tuple[MachineReviewerRiskSignalV1, ...] = ()
    assessment_fingerprint: DigestV1 = field(init=False)
    assessment_state: Literal["complete"] = field(default="complete", init=False)
    authority: Literal["machine_advisory"] = field(default="machine_advisory", init=False)

    def __post_init__(self) -> None:
        _canonical_identifier(self.reviewer_id, label="risk assessment reviewer id")
        for label, value in (
            ("risk assessment subject fingerprint", self.subject_fingerprint),
            ("risk assessment task fingerprint", self.task_fingerprint),
            ("risk assessment verdict fingerprint", self.verdict_fingerprint),
        ):
            _require_digest(value, HashKindV1.MODEL_WORK_ITEM, label=label)
        if any(type(item) is not MachineReviewerRiskSignalV1 for item in self.signals):
            raise MachineAdvisoryAdmissionError("risk assessment signal has the wrong type")
        ordered = tuple(
            sorted(
                self.signals,
                key=lambda item: (item.kind.value, item.signal_fingerprint.value),
            )
        )
        if self.signals != ordered or len({item.signal_fingerprint for item in ordered}) != len(
            ordered
        ):
            raise MachineAdvisoryAdmissionError(
                "risk assessment signals must be canonical and unique"
            )
        if any(
            signal.reviewer_id != self.reviewer_id
            or signal.subject_fingerprint != self.subject_fingerprint
            or signal.task_fingerprint != self.task_fingerprint
            or signal.verdict_fingerprint != self.verdict_fingerprint
            for signal in ordered
        ):
            raise MachineAdvisoryAdmissionError(
                "risk assessment signal is detached from its assessment"
            )
        object.__setattr__(
            self,
            "assessment_fingerprint",
            digest_bytes(
                HashKindV1.MODEL_WORK_ITEM,
                canonical_json_bytes(self.payload(include_fingerprint=False)),
            ),
        )

    def payload(self, *, include_fingerprint: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema_version": "autolean.machine-reviewer-risk-assessment.v1",
            "authority": self.authority,
            "assessment_state": self.assessment_state,
            "reviewer_id": self.reviewer_id,
            "subject_fingerprint": self.subject_fingerprint.model_dump(mode="json"),
            "task_fingerprint": self.task_fingerprint.model_dump(mode="json"),
            "verdict_fingerprint": self.verdict_fingerprint.model_dump(mode="json"),
            "signals": [item.payload() for item in self.signals],
        }
        if include_fingerprint:
            payload["assessment_fingerprint"] = self.assessment_fingerprint.model_dump(mode="json")
        return payload


@dataclass(frozen=True, slots=True, init=False)
class MachineAdvisoryAdmissionDecisionV1:
    """A replayable advisory route that can never become Builder or Prover authority."""

    _verified_quorum: VerifiedMachineQuorumReport = field(repr=False)
    lineages: tuple[MachineAdvisoryExecutionLineageV1, ...]
    calibrations: tuple[MachineAdvisoryCalibrationBindingV1, ...]
    risk_assessments: tuple[MachineReviewerRiskAssessmentV1, ...]
    expected_calibration_protocol_fingerprint: DigestV1
    expected_calibration_scope_fingerprint: DigestV1
    evaluated_at: datetime
    valid_until: datetime | None
    reasons: tuple[MachineAdvisoryAdmissionReasonV1, ...]
    disposition: MachineAdvisoryDispositionV1
    decision_fingerprint: DigestV1
    authority: Literal["machine_advisory"] = field(init=False)
    may_freeze: Literal[False] = field(init=False)
    prover_handoff: Literal["forbidden"] = field(init=False)
    freshness_revalidation_required: Literal[True] = field(init=False)
    authority_limitations: tuple[str, ...] = field(init=False)

    def __init__(
        self,
        verified_quorum: VerifiedMachineQuorumReport,
        *,
        lineages: tuple[MachineAdvisoryExecutionLineageV1, ...],
        calibrations: tuple[MachineAdvisoryCalibrationBindingV1, ...],
        risk_assessments: tuple[MachineReviewerRiskAssessmentV1, ...],
        expected_calibration_protocol_fingerprint: DigestV1,
        expected_calibration_scope_fingerprint: DigestV1,
        evaluated_at: datetime,
        valid_until: datetime | None,
        reasons: tuple[MachineAdvisoryAdmissionReasonV1, ...],
        _token: object,
    ) -> None:
        if _token is not _DECISION_TOKEN:
            raise TypeError(
                "MachineAdvisoryAdmissionDecisionV1 must be created by "
                "evaluate_machine_advisory_admission"
            )
        disposition = (
            MachineAdvisoryDispositionV1.ABSTAIN
            if reasons
            else MachineAdvisoryDispositionV1.CONTINUE_MACHINE_ADVISORY_REVIEW
        )
        object.__setattr__(self, "_verified_quorum", verified_quorum)
        object.__setattr__(self, "lineages", lineages)
        object.__setattr__(self, "calibrations", calibrations)
        object.__setattr__(self, "risk_assessments", risk_assessments)
        object.__setattr__(
            self,
            "expected_calibration_protocol_fingerprint",
            expected_calibration_protocol_fingerprint,
        )
        object.__setattr__(
            self,
            "expected_calibration_scope_fingerprint",
            expected_calibration_scope_fingerprint,
        )
        object.__setattr__(self, "evaluated_at", evaluated_at)
        object.__setattr__(self, "valid_until", valid_until)
        object.__setattr__(self, "reasons", reasons)
        object.__setattr__(self, "disposition", disposition)
        object.__setattr__(self, "authority", "machine_advisory")
        object.__setattr__(self, "may_freeze", False)
        object.__setattr__(self, "prover_handoff", "forbidden")
        object.__setattr__(self, "freshness_revalidation_required", True)
        object.__setattr__(self, "authority_limitations", _AUTHORITY_LIMITATIONS)
        object.__setattr__(
            self,
            "decision_fingerprint",
            digest_bytes(
                HashKindV1.MODEL_WORK_ITEM,
                canonical_json_bytes(self.payload(include_fingerprint=False)),
            ),
        )

    @property
    def verified_quorum(self) -> VerifiedMachineQuorumReport:
        return self._verified_quorum

    def can_continue_machine_advisory_review_at(self, consumed_at: datetime) -> bool:
        consumed_at = _normalized_utc(consumed_at, label="consumed_at")
        return (
            self.disposition is MachineAdvisoryDispositionV1.CONTINUE_MACHINE_ADVISORY_REVIEW
            and self.valid_until is not None
            and self.evaluated_at <= consumed_at < self.valid_until
        )

    def require_fresh_machine_advisory_review(self, consumed_at: datetime) -> None:
        if not self.can_continue_machine_advisory_review_at(consumed_at):
            raise MachineAdvisoryAdmissionError(
                "machine advisory decision is abstaining, not yet valid, or stale"
            )

    def payload(self, *, include_fingerprint: bool = True) -> dict[str, object]:
        report = self._verified_quorum.report
        payload: dict[str, object] = {
            "schema_version": "autolean.machine-advisory-admission-decision.v1",
            "authority": self.authority,
            "may_freeze": self.may_freeze,
            "prover_handoff": self.prover_handoff,
            "freshness_revalidation_required": self.freshness_revalidation_required,
            "disposition": self.disposition.value,
            "reasons": [item.value for item in self.reasons],
            "contract_id": report.contract_id.value,
            "revision": report.revision,
            "contract_hash": report.contract_hash.model_dump(mode="json"),
            "subject_fingerprint": report.subject_fingerprint.model_dump(mode="json"),
            "verified_quorum_fingerprint": (
                self._verified_quorum.verification_fingerprint.model_dump(mode="json")
            ),
            "quorum_report_fingerprint": report.report_fingerprint.model_dump(mode="json"),
            "semantic_all_checks_passed": self._verified_quorum.semantic_all_checks_passed,
            "expected_calibration_protocol_fingerprint": (
                self.expected_calibration_protocol_fingerprint.model_dump(mode="json")
            ),
            "expected_calibration_scope_fingerprint": (
                self.expected_calibration_scope_fingerprint.model_dump(mode="json")
            ),
            "evaluated_at": _utc_text(self.evaluated_at),
            "valid_until": None if self.valid_until is None else _utc_text(self.valid_until),
            "lineages": [item.payload() for item in self.lineages],
            "calibrations": [item.payload() for item in self.calibrations],
            "risk_assessments": [item.payload() for item in self.risk_assessments],
            "authority_limitations": list(self.authority_limitations),
        }
        if include_fingerprint:
            payload["decision_fingerprint"] = self.decision_fingerprint.model_dump(mode="json")
        return payload

    def render_artifact(self) -> bytes:
        return canonical_json_bytes(self.payload())

    def freeze_statement(self) -> Never:
        raise MachineAdvisoryAdmissionError("machine advisory admission cannot freeze a statement")

    def handoff_to_prover(self) -> Never:
        raise MachineAdvisoryAdmissionError("machine advisory admission cannot hand off to Prover")


def evaluate_machine_advisory_admission(
    verified_quorum: VerifiedMachineQuorumReport,
    *,
    lineages: tuple[MachineAdvisoryExecutionLineageV1, ...],
    calibrations: tuple[MachineAdvisoryCalibrationBindingV1, ...],
    risk_assessments: tuple[MachineReviewerRiskAssessmentV1, ...],
    expected_calibration_protocol_fingerprint: DigestV1,
    expected_calibration_scope_fingerprint: DigestV1,
    evaluated_at: datetime,
) -> MachineAdvisoryAdmissionDecisionV1:
    """Evaluate P2-13 blockers; current unverified inputs always abstain."""

    if not isinstance(verified_quorum, VerifiedMachineQuorumReport):
        raise MachineAdvisoryAdmissionError(
            "machine advisory admission requires a VerifiedMachineQuorumReport"
        )
    _require_digest(
        expected_calibration_protocol_fingerprint,
        HashKindV1.MODEL_WORK_ITEM,
        label="expected calibration protocol fingerprint",
    )
    _require_digest(
        expected_calibration_scope_fingerprint,
        HashKindV1.MODEL_WORK_ITEM,
        label="expected calibration scope fingerprint",
    )
    evaluated_at = _normalized_utc(evaluated_at, label="evaluated_at")
    report = verified_quorum.report
    tasks_by_reviewer = {item.reviewer_id: item for item in report.tasks}
    reviewer_ids = set(tasks_by_reviewer)
    evidence_by_task = {item.task_id: item for item in report.evidence}

    lineages_by_reviewer = _index_lineages(
        lineages,
        reviewer_ids=reviewer_ids,
    )
    calibrations_by_reviewer = _index_calibrations(
        calibrations,
        reviewer_ids=reviewer_ids,
    )

    risk_assessments_by_reviewer = _index_risk_assessments(
        risk_assessments,
        reviewer_ids=reviewer_ids,
    )
    ordered_assessments = tuple(sorted(risk_assessments, key=lambda item: item.reviewer_id))
    ordered_signals = tuple(
        signal for assessment in ordered_assessments for signal in assessment.signals
    )
    for assessment in ordered_assessments:
        task = tasks_by_reviewer[assessment.reviewer_id]
        evidence = evidence_by_task[task.task_id]
        if (
            assessment.subject_fingerprint != report.subject_fingerprint
            or assessment.task_fingerprint != task.task_fingerprint
            or assessment.verdict_fingerprint != evidence.verdict_fingerprint
        ):
            raise MachineAdvisoryAdmissionError(
                "risk assessment is detached from its verified reviewer evidence"
            )

    reasons: set[MachineAdvisoryAdmissionReasonV1] = set()
    quorum_reason_map = {
        MachineQuorumReason.UNVERIFIED_EXECUTION_EVIDENCE: (
            MachineAdvisoryAdmissionReasonV1.QUORUM_EXECUTION_UNVERIFIED
        ),
        MachineQuorumReason.DECLARED_FAILURE_DOMAIN_UNVERIFIED: (
            MachineAdvisoryAdmissionReasonV1.LINEAGE_EVIDENCE_UNVERIFIED
        ),
        MachineQuorumReason.CONTENT_BLINDING_UNVERIFIED: (
            MachineAdvisoryAdmissionReasonV1.CONTENT_BLINDING_UNVERIFIED
        ),
        MachineQuorumReason.REVIEWER_DISAGREEMENT: (
            MachineAdvisoryAdmissionReasonV1.REVIEWER_DISAGREEMENT
        ),
        MachineQuorumReason.MUTATION_SURVIVED: (MachineAdvisoryAdmissionReasonV1.MUTATION_SURVIVED),
        MachineQuorumReason.CRITICAL_MUTATION_SURVIVED: (
            MachineAdvisoryAdmissionReasonV1.CRITICAL_MUTATION_SURVIVED
        ),
        MachineQuorumReason.SEMANTIC_CONTROL_REJECTED: (
            MachineAdvisoryAdmissionReasonV1.SEMANTIC_CONTROL_REJECTED
        ),
        MachineQuorumReason.SEMANTIC_CHECK_FAILED: (
            MachineAdvisoryAdmissionReasonV1.SEMANTIC_CHECK_FAILED
        ),
    }
    reasons.update(quorum_reason_map[item] for item in report.reasons if item in quorum_reason_map)
    if verified_quorum.semantic_escalation_required and not reasons:
        reasons.add(MachineAdvisoryAdmissionReasonV1.QUORUM_ESCALATION_REQUIRED)
    declared_failure_domain_counts = Counter(
        item.declared_failure_domain_id for item in report.tasks
    )
    if any(count > 1 for count in declared_failure_domain_counts.values()):
        reasons.add(MachineAdvisoryAdmissionReasonV1.SHARED_DECLARED_FAILURE_DOMAIN)

    for signal in ordered_signals:
        reasons.add(
            MachineAdvisoryAdmissionReasonV1.CRITICAL_DISSENT
            if signal.kind is MachineReviewerRiskKindV1.CRITICAL_DISSENT
            else MachineAdvisoryAdmissionReasonV1.COUNTEREXAMPLE_REPORTED
        )

    if reviewer_ids - set(risk_assessments_by_reviewer):
        reasons.add(MachineAdvisoryAdmissionReasonV1.RISK_ASSESSMENT_MISSING)

    if reviewer_ids - set(lineages_by_reviewer):
        reasons.add(MachineAdvisoryAdmissionReasonV1.LINEAGE_MISSING)
    for reviewer_id, lineage in lineages_by_reviewer.items():
        expected_environment = tasks_by_reviewer[reviewer_id].reviewer_environment_fingerprint
        if lineage.role_environment_hash != expected_environment:
            reasons.add(MachineAdvisoryAdmissionReasonV1.LINEAGE_ENVIRONMENT_MISMATCH)
    model_lineage_counts = Counter(
        item.model_lineage_fingerprint.value for item in lineages_by_reviewer.values()
    )
    failure_domain_counts = Counter(
        item.model_failure_domain_fingerprint.value for item in lineages_by_reviewer.values()
    )
    if any(count > 1 for count in model_lineage_counts.values()) or any(
        count > 1 for count in failure_domain_counts.values()
    ):
        reasons.add(MachineAdvisoryAdmissionReasonV1.SHARED_MODEL_LINEAGE)
    if lineages_by_reviewer:
        reasons.add(MachineAdvisoryAdmissionReasonV1.LINEAGE_EVIDENCE_UNVERIFIED)

    if reviewer_ids - set(calibrations_by_reviewer):
        reasons.add(MachineAdvisoryAdmissionReasonV1.CALIBRATION_MISSING)
    for reviewer_id, calibration in calibrations_by_reviewer.items():
        calibration_lineage = lineages_by_reviewer.get(reviewer_id)
        if calibration.protocol_fingerprint != expected_calibration_protocol_fingerprint:
            reasons.add(MachineAdvisoryAdmissionReasonV1.CALIBRATION_PROTOCOL_MISMATCH)
        if calibration.scope_fingerprint != expected_calibration_scope_fingerprint:
            reasons.add(MachineAdvisoryAdmissionReasonV1.CALIBRATION_SCOPE_MISMATCH)
        if (
            calibration_lineage is None
            or calibration.execution_lineage_fingerprint
            != calibration_lineage.execution_lineage_fingerprint
        ):
            reasons.add(MachineAdvisoryAdmissionReasonV1.CALIBRATION_LINEAGE_MISMATCH)
        if calibration.calibrated_at > evaluated_at:
            reasons.add(MachineAdvisoryAdmissionReasonV1.CALIBRATION_FROM_FUTURE)
        if evaluated_at >= calibration.valid_until:
            reasons.add(MachineAdvisoryAdmissionReasonV1.CALIBRATION_STALE)
    if calibrations_by_reviewer:
        reasons.add(MachineAdvisoryAdmissionReasonV1.CALIBRATION_EVIDENCE_UNVERIFIED)

    ordered_lineages = tuple(sorted(lineages, key=lambda item: item.reviewer_id))
    ordered_calibrations = tuple(sorted(calibrations, key=lambda item: item.reviewer_id))
    ordered_reasons = tuple(sorted(reasons, key=lambda item: item.value))
    valid_until = (
        min(item.valid_until for item in ordered_calibrations)
        if len(ordered_calibrations) == len(reviewer_ids)
        else None
    )
    return MachineAdvisoryAdmissionDecisionV1(
        verified_quorum,
        lineages=ordered_lineages,
        calibrations=ordered_calibrations,
        risk_assessments=ordered_assessments,
        expected_calibration_protocol_fingerprint=expected_calibration_protocol_fingerprint,
        expected_calibration_scope_fingerprint=expected_calibration_scope_fingerprint,
        evaluated_at=evaluated_at,
        valid_until=valid_until,
        reasons=ordered_reasons,
        _token=_DECISION_TOKEN,
    )


def _index_lineages(
    values: tuple[MachineAdvisoryExecutionLineageV1, ...],
    *,
    reviewer_ids: set[str],
) -> dict[str, MachineAdvisoryExecutionLineageV1]:
    if any(type(item) is not MachineAdvisoryExecutionLineageV1 for item in values):
        raise MachineAdvisoryAdmissionError("execution lineage sidecar has the wrong type")
    indexed = {item.reviewer_id: item for item in values}
    if len(indexed) != len(values):
        raise MachineAdvisoryAdmissionError("execution lineage reviewer ids must be unique")
    if set(indexed) - reviewer_ids:
        raise MachineAdvisoryAdmissionError("execution lineage names an unknown reviewer")
    return indexed


def _index_calibrations(
    values: tuple[MachineAdvisoryCalibrationBindingV1, ...],
    *,
    reviewer_ids: set[str],
) -> dict[str, MachineAdvisoryCalibrationBindingV1]:
    if any(type(item) is not MachineAdvisoryCalibrationBindingV1 for item in values):
        raise MachineAdvisoryAdmissionError("calibration binding sidecar has the wrong type")
    indexed = {item.reviewer_id: item for item in values}
    if len(indexed) != len(values):
        raise MachineAdvisoryAdmissionError("calibration binding reviewer ids must be unique")
    if set(indexed) - reviewer_ids:
        raise MachineAdvisoryAdmissionError("calibration binding names an unknown reviewer")
    return indexed


def _index_risk_assessments(
    values: tuple[MachineReviewerRiskAssessmentV1, ...],
    *,
    reviewer_ids: set[str],
) -> dict[str, MachineReviewerRiskAssessmentV1]:
    if any(type(item) is not MachineReviewerRiskAssessmentV1 for item in values):
        raise MachineAdvisoryAdmissionError("risk assessment sidecar has the wrong type")
    indexed = {item.reviewer_id: item for item in values}
    if len(indexed) != len(values):
        raise MachineAdvisoryAdmissionError("risk assessment reviewer ids must be unique")
    if set(indexed) - reviewer_ids:
        raise MachineAdvisoryAdmissionError("risk assessment names an unknown reviewer")
    return indexed
