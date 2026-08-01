from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from autolean_builder import (
    MachineAdvisoryAdmissionError,
    MachineAdvisoryAdmissionReasonV1,
    MachineAdvisoryCalibrationBindingV1,
    MachineAdvisoryDispositionV1,
    MachineAdvisoryExecutionLineageV1,
    MachineReviewerRiskAssessmentV1,
    MachineReviewerRiskKindV1,
    MachineReviewerRiskSignalV1,
    evaluate_machine_advisory_admission,
    verify_machine_quorum_report,
)
from autolean_contracts import (
    EndpointClassV1,
    HashKindV1,
    ModelExecutionProviderBindingV1,
    digest_text,
)
from test_machine_semantic_quorum import (
    _SEED,
    _aggregate,
    _all_evidence,
    _evidence,
    _packet,
    _response_artifacts,
    _reviewers,
    _tasks,
    _verdict,
)

_NOW = datetime(2026, 7, 31, 12, tzinfo=UTC)
_PROTOCOL = digest_text(HashKindV1.MODEL_WORK_ITEM, "p2-13-calibration-protocol-v1")
_SCOPE = digest_text(HashKindV1.MODEL_WORK_ITEM, "p2-13-calibration-scope-v1")


def _verified_quorum(*, disagreement: bool = False, surviving_mutation: bool = False):
    contract, packet = _packet()
    tasks = _tasks(contract, packet)
    if disagreement:
        evidence = (
            _evidence(
                tasks[0],
                packet,
                verdict=_verdict(
                    tasks[0],
                    packet,
                    source_to_normalized_equivalent=False,
                ),
            ),
            *(_evidence(task, packet) for task in tasks[1:]),
        )
    elif surviving_mutation:
        mutation_source = packet.mutation_probes[0].mutated_statement_source
        evidence = _all_evidence(
            tasks,
            packet,
            source_overrides={mutation_source: True},
        )
    else:
        evidence = _all_evidence(tasks, packet)
    report = _aggregate(contract, packet, tasks, evidence)
    verified = verify_machine_quorum_report(
        contract,
        packet,
        _reviewers(),
        _SEED,
        report,
        response_artifacts=_response_artifacts(evidence),
    )
    return verified


def _lineages(
    verified,
    *,
    shared_model: bool = False,
    provider_aliases: bool = False,
    shared_failure_domain: bool = False,
):
    result = []
    for index, task in enumerate(verified.report.tasks):
        model_suffix = "shared" if shared_model else str(index)
        result.append(
            MachineAdvisoryExecutionLineageV1(
                reviewer_id=task.reviewer_id,
                provider=ModelExecutionProviderBindingV1(
                    registry_name="test-registry",
                    provider_id=f"fake-{index}" if provider_aliases else "fake",
                    model_id=f"advisory-model-{model_suffix}",
                    model_revision="revision-1",
                    endpoint_class=EndpointClassV1.LOCAL,
                    configuration_hash=digest_text(
                        HashKindV1.CONFIG,
                        f"configuration-{index}",
                    ),
                ),
                role_environment_hash=task.reviewer_environment_fingerprint,
                runtime_environment_hash=digest_text(
                    HashKindV1.ENVIRONMENT,
                    f"runtime-{index}",
                ),
                model_failure_domain_fingerprint=digest_text(
                    HashKindV1.MODEL_WORK_ITEM,
                    (
                        "failure-domain-shared"
                        if shared_failure_domain
                        else f"failure-domain-{index}"
                    ),
                ),
            )
        )
    return tuple(result)


def _calibrations(lineages):
    return tuple(
        MachineAdvisoryCalibrationBindingV1(
            reviewer_id=lineage.reviewer_id,
            calibration_artifact_fingerprint=digest_text(
                HashKindV1.MODEL_WORK_ITEM,
                f"artifact-{lineage.reviewer_id}",
            ),
            calibration_input_fingerprint=digest_text(
                HashKindV1.MODEL_WORK_ITEM,
                f"input-{lineage.reviewer_id}",
            ),
            protocol_fingerprint=_PROTOCOL,
            scope_fingerprint=_SCOPE,
            execution_lineage_fingerprint=lineage.execution_lineage_fingerprint,
            calibrated_at=_NOW - timedelta(days=1),
            valid_until=_NOW + timedelta(days=1),
        )
        for lineage in lineages
    )


def _risk_assessments(verified, signals=()):
    signals_by_reviewer = {}
    for signal in signals:
        signals_by_reviewer.setdefault(signal.reviewer_id, []).append(signal)
    assessments = []
    for task, evidence in zip(verified.report.tasks, verified.report.evidence, strict=True):
        reviewer_signals = tuple(
            sorted(
                signals_by_reviewer.get(task.reviewer_id, ()),
                key=lambda item: (item.kind.value, item.signal_fingerprint.value),
            )
        )
        assessments.append(
            MachineReviewerRiskAssessmentV1(
                reviewer_id=task.reviewer_id,
                subject_fingerprint=verified.report.subject_fingerprint,
                task_fingerprint=task.task_fingerprint,
                verdict_fingerprint=evidence.verdict_fingerprint,
                signals=reviewer_signals,
            )
        )
    return tuple(assessments)


def _evaluate(verified, *, lineages=None, calibrations=None, risk_assessments=None):
    active_lineages = _lineages(verified) if lineages is None else lineages
    active_calibrations = _calibrations(active_lineages) if calibrations is None else calibrations
    active_risk_assessments = (
        _risk_assessments(verified) if risk_assessments is None else risk_assessments
    )
    return evaluate_machine_advisory_admission(
        verified,
        lineages=active_lineages,
        calibrations=active_calibrations,
        risk_assessments=active_risk_assessments,
        expected_calibration_protocol_fingerprint=_PROTOCOL,
        expected_calibration_scope_fingerprint=_SCOPE,
        evaluated_at=_NOW,
    )


def _risk_signal(verified, kind: MachineReviewerRiskKindV1):
    task = verified.report.tasks[0]
    evidence = verified.report.evidence[0]
    return MachineReviewerRiskSignalV1(
        reviewer_id=task.reviewer_id,
        kind=kind,
        subject_fingerprint=verified.report.subject_fingerprint,
        task_fingerprint=task.task_fingerprint,
        verdict_fingerprint=evidence.verdict_fingerprint,
        finding_fingerprint=digest_text(
            HashKindV1.MODEL_WORK_ITEM,
            f"finding-{kind.value}",
        ),
    )


def test_current_unverified_route_abstains_and_never_becomes_authority() -> None:
    verified = _verified_quorum()
    before = verified.render_artifact()

    decision = _evaluate(verified)

    assert decision.disposition is MachineAdvisoryDispositionV1.ABSTAIN
    assert MachineAdvisoryAdmissionReasonV1.QUORUM_EXECUTION_UNVERIFIED in decision.reasons
    assert MachineAdvisoryAdmissionReasonV1.LINEAGE_EVIDENCE_UNVERIFIED in decision.reasons
    assert MachineAdvisoryAdmissionReasonV1.CALIBRATION_EVIDENCE_UNVERIFIED in decision.reasons
    assert decision.authority == "machine_advisory"
    assert decision.may_freeze is False
    assert decision.prover_handoff == "forbidden"
    assert decision.verified_quorum is verified
    assert decision.valid_until == _NOW + timedelta(days=1)
    assert not decision.can_continue_machine_advisory_review_at(_NOW)
    with pytest.raises(MachineAdvisoryAdmissionError, match="abstaining"):
        decision.require_fresh_machine_advisory_review(_NOW)
    assert verified.render_artifact() == before
    with pytest.raises(MachineAdvisoryAdmissionError, match="cannot freeze"):
        decision.freeze_statement()
    with pytest.raises(MachineAdvisoryAdmissionError, match="cannot hand off"):
        decision.handoff_to_prover()


def test_reviewer_disagreement_abstains_without_majority_vote() -> None:
    decision = _evaluate(_verified_quorum(disagreement=True))

    assert decision.disposition is MachineAdvisoryDispositionV1.ABSTAIN
    assert MachineAdvisoryAdmissionReasonV1.REVIEWER_DISAGREEMENT in decision.reasons
    assert MachineAdvisoryAdmissionReasonV1.SEMANTIC_CHECK_FAILED in decision.reasons


def test_any_surviving_mutation_abstains() -> None:
    decision = _evaluate(_verified_quorum(surviving_mutation=True))

    assert decision.disposition is MachineAdvisoryDispositionV1.ABSTAIN
    assert MachineAdvisoryAdmissionReasonV1.MUTATION_SURVIVED in decision.reasons


@pytest.mark.parametrize(
    ("kind", "reason"),
    (
        (
            MachineReviewerRiskKindV1.CRITICAL_DISSENT,
            MachineAdvisoryAdmissionReasonV1.CRITICAL_DISSENT,
        ),
        (
            MachineReviewerRiskKindV1.COUNTEREXAMPLE_REPORTED,
            MachineAdvisoryAdmissionReasonV1.COUNTEREXAMPLE_REPORTED,
        ),
    ),
)
def test_response_bound_risk_signal_abstains(kind, reason) -> None:
    verified = _verified_quorum()
    signal = _risk_signal(verified, kind)

    decision = _evaluate(
        verified,
        risk_assessments=_risk_assessments(verified, (signal,)),
    )

    assert decision.disposition is MachineAdvisoryDispositionV1.ABSTAIN
    assert reason in decision.reasons


def test_detached_risk_signal_is_rejected() -> None:
    verified = _verified_quorum()
    signal = replace(
        _risk_signal(verified, MachineReviewerRiskKindV1.CRITICAL_DISSENT),
        verdict_fingerprint=digest_text(HashKindV1.MODEL_WORK_ITEM, "other-verdict"),
    )
    task = verified.report.tasks[0]
    detached = MachineReviewerRiskAssessmentV1(
        reviewer_id=task.reviewer_id,
        subject_fingerprint=verified.report.subject_fingerprint,
        task_fingerprint=task.task_fingerprint,
        verdict_fingerprint=signal.verdict_fingerprint,
        signals=(signal,),
    )
    assessments = (detached, *_risk_assessments(verified)[1:])

    with pytest.raises(MachineAdvisoryAdmissionError, match="detached"):
        _evaluate(verified, risk_assessments=assessments)


def test_shared_model_lineage_abstains_even_with_distinct_role_configuration() -> None:
    verified = _verified_quorum()
    lineages = _lineages(verified, shared_model=True)

    decision = _evaluate(verified, lineages=lineages)

    assert decision.disposition is MachineAdvisoryDispositionV1.ABSTAIN
    assert MachineAdvisoryAdmissionReasonV1.SHARED_MODEL_LINEAGE in decision.reasons


def test_provider_aliases_do_not_hide_shared_model_lineage() -> None:
    verified = _verified_quorum()
    lineages = _lineages(verified, shared_model=True, provider_aliases=True)

    decision = _evaluate(verified, lineages=lineages)

    assert MachineAdvisoryAdmissionReasonV1.SHARED_MODEL_LINEAGE in decision.reasons


def test_verified_quorum_shared_failure_domain_cannot_be_erased_by_sidecar() -> None:
    verified = _verified_quorum()
    lineages = _lineages(verified)

    decision = _evaluate(verified, lineages=lineages)

    assert len({item.model_failure_domain_fingerprint for item in lineages}) == len(lineages)
    assert MachineAdvisoryAdmissionReasonV1.SHARED_DECLARED_FAILURE_DOMAIN in decision.reasons


def test_declared_shared_failure_domain_abstains_across_distinct_models() -> None:
    verified = _verified_quorum()
    lineages = _lineages(verified, shared_failure_domain=True)

    decision = _evaluate(verified, lineages=lineages)

    assert MachineAdvisoryAdmissionReasonV1.SHARED_MODEL_LINEAGE in decision.reasons


def test_missing_lineage_and_calibration_abstain() -> None:
    verified = _verified_quorum()
    lineages = _lineages(verified)
    calibrations = _calibrations(lineages)

    missing_lineage = _evaluate(
        verified,
        lineages=lineages[:-1],
        calibrations=calibrations[:-1],
    )
    missing_calibration = _evaluate(
        verified,
        lineages=lineages,
        calibrations=calibrations[:-1],
    )

    assert MachineAdvisoryAdmissionReasonV1.LINEAGE_MISSING in missing_lineage.reasons
    assert MachineAdvisoryAdmissionReasonV1.CALIBRATION_MISSING in missing_lineage.reasons
    assert MachineAdvisoryAdmissionReasonV1.CALIBRATION_MISSING in missing_calibration.reasons


def test_missing_complete_risk_assessment_abstains() -> None:
    verified = _verified_quorum()

    decision = _evaluate(
        verified,
        risk_assessments=_risk_assessments(verified)[:-1],
    )

    assert MachineAdvisoryAdmissionReasonV1.RISK_ASSESSMENT_MISSING in decision.reasons


@pytest.mark.parametrize(
    ("field_name", "replacement", "reason"),
    (
        (
            "protocol_fingerprint",
            digest_text(HashKindV1.MODEL_WORK_ITEM, "other-protocol"),
            MachineAdvisoryAdmissionReasonV1.CALIBRATION_PROTOCOL_MISMATCH,
        ),
        (
            "scope_fingerprint",
            digest_text(HashKindV1.MODEL_WORK_ITEM, "other-scope"),
            MachineAdvisoryAdmissionReasonV1.CALIBRATION_SCOPE_MISMATCH,
        ),
        (
            "execution_lineage_fingerprint",
            digest_text(HashKindV1.MODEL_WORK_ITEM, "other-lineage"),
            MachineAdvisoryAdmissionReasonV1.CALIBRATION_LINEAGE_MISMATCH,
        ),
        (
            "calibrated_at",
            _NOW + timedelta(seconds=1),
            MachineAdvisoryAdmissionReasonV1.CALIBRATION_FROM_FUTURE,
        ),
        (
            "valid_until",
            _NOW,
            MachineAdvisoryAdmissionReasonV1.CALIBRATION_STALE,
        ),
    ),
)
def test_calibration_mismatch_or_staleness_abstains(field_name, replacement, reason) -> None:
    verified = _verified_quorum()
    lineages = _lineages(verified)
    calibrations = _calibrations(lineages)
    changed = replace(calibrations[0], **{field_name: replacement})

    decision = _evaluate(
        verified,
        lineages=lineages,
        calibrations=(changed, *calibrations[1:]),
    )

    assert decision.disposition is MachineAdvisoryDispositionV1.ABSTAIN
    assert reason in decision.reasons


def test_arbitrary_calibration_digest_declarations_cannot_clear_gate() -> None:
    verified = _verified_quorum()
    lineages = _lineages(verified)
    calibrations = tuple(
        replace(
            item,
            calibration_artifact_fingerprint=digest_text(
                HashKindV1.MODEL_WORK_ITEM,
                f"arbitrary-non-report-{index}",
            ),
            calibration_input_fingerprint=digest_text(
                HashKindV1.MODEL_WORK_ITEM,
                f"arbitrary-non-input-{index}",
            ),
        )
        for index, item in enumerate(_calibrations(lineages))
    )

    decision = _evaluate(verified, lineages=lineages, calibrations=calibrations)

    assert decision.disposition is MachineAdvisoryDispositionV1.ABSTAIN
    assert MachineAdvisoryAdmissionReasonV1.CALIBRATION_EVIDENCE_UNVERIFIED in decision.reasons


def test_calibration_rejects_naive_or_inverted_timestamps() -> None:
    verified = _verified_quorum()
    lineage = _lineages(verified)[0]
    kwargs = {
        "reviewer_id": lineage.reviewer_id,
        "calibration_artifact_fingerprint": digest_text(
            HashKindV1.MODEL_WORK_ITEM,
            "artifact",
        ),
        "calibration_input_fingerprint": digest_text(HashKindV1.MODEL_WORK_ITEM, "input"),
        "protocol_fingerprint": _PROTOCOL,
        "scope_fingerprint": _SCOPE,
        "execution_lineage_fingerprint": lineage.execution_lineage_fingerprint,
    }

    with pytest.raises(MachineAdvisoryAdmissionError, match="timezone-aware"):
        MachineAdvisoryCalibrationBindingV1(
            **kwargs,
            calibrated_at=datetime(2026, 7, 30),
            valid_until=_NOW,
        )
    with pytest.raises(MachineAdvisoryAdmissionError, match="end after"):
        MachineAdvisoryCalibrationBindingV1(
            **kwargs,
            calibrated_at=_NOW,
            valid_until=_NOW,
        )


def test_input_permutation_renders_byte_identically() -> None:
    verified = _verified_quorum()
    lineages = _lineages(verified)
    calibrations = _calibrations(lineages)
    signals = (
        _risk_signal(verified, MachineReviewerRiskKindV1.CRITICAL_DISSENT),
        _risk_signal(verified, MachineReviewerRiskKindV1.COUNTEREXAMPLE_REPORTED),
    )
    assessments = _risk_assessments(verified, signals)

    forward = _evaluate(
        verified,
        lineages=lineages,
        calibrations=calibrations,
        risk_assessments=assessments,
    )
    reverse = _evaluate(
        verified,
        lineages=tuple(reversed(lineages)),
        calibrations=tuple(reversed(calibrations)),
        risk_assessments=tuple(reversed(assessments)),
    )

    assert forward.render_artifact() == reverse.render_artifact()
    assert forward.decision_fingerprint == reverse.decision_fingerprint
    assert forward.valid_until is not None
    assert not forward.can_continue_machine_advisory_review_at(forward.valid_until)
