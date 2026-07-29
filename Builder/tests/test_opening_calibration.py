from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path

import pytest
from autolean_builder.machine_semantic_quorum import (
    MachineReviewerSpec,
    MachineSemanticReviewRole,
)
from autolean_builder.opening_calibration import (
    OpeningCalibrationError,
    OpeningCalibrationOptionFindingV1,
    OpeningCalibrationReviewVerdictV1,
    OpeningCalibrationSampleV1,
    load_project_synthetic_opening_calibration_samples,
    prepare_opening_calibration,
    prepare_standard_bridge_bundle,
    score_opening_calibration,
    source_unavailable_opening_calibration_sample,
)
from autolean_contracts import HashKindV1, MutationKindV1, canonical_json_bytes, digest_bytes

_ROOT = Path(__file__).resolve().parents[2]
_CORPUS = (
    _ROOT / "Builder" / "pilots" / "local-calibration" / "project-synthetic-opening-corpus.v1.json"
)


def _samples():
    return load_project_synthetic_opening_calibration_samples(_CORPUS)


def _sample(sample_id: str):
    return next(item for item in _samples() if item.sample_id == sample_id)


def _reviewers() -> tuple[MachineReviewerSpec, ...]:
    return tuple(
        MachineReviewerSpec(
            reviewer_id=f"opening-reviewer-{index}",
            role=role,
            independence_group=f"opening-review-group-{index}",
            declared_failure_domain_id=f"opening-failure-domain-{index % 2}",
            role_environment_hash=digest_bytes(
                HashKindV1.ENVIRONMENT,
                f"opening-review-environment-{index}".encode(),
            ),
            run_id=f"opening-review-run-{index}",
        )
        for index, role in enumerate(MachineSemanticReviewRole)
    )


def _verdicts(prepared, *, let_first_mutation_survive: bool = False):
    verdicts = []
    changed = False
    expected_claims = {
        **{
            candidate.semantic_projection.normalized_claim: True
            for candidate in prepared.sample.candidates
        },
        **{mutation.mutated_claim: False for mutation in prepared.sample.mutations},
    }
    for task in prepared.tasks:
        findings = []
        for option in task.options:
            matches = [
                expected
                for claim, expected in expected_claims.items()
                if hashlib.sha256(
                    canonical_json_bytes(
                        {
                            "schema_version": (
                                "autolean.builder-opening-calibration-blind-option.v1"
                            ),
                            "option_id": option.option_id,
                            "candidate_claim": claim,
                        }
                    )
                ).hexdigest()
                == option.option_fingerprint_sha256
            ]
            assert len(matches) == 1
            preserves = matches[0]
            if let_first_mutation_survive and not changed and not preserves:
                preserves = True
                changed = True
            findings.append(
                OpeningCalibrationOptionFindingV1(
                    option_id=option.option_id,
                    option_fingerprint_sha256=option.option_fingerprint_sha256,
                    preserves_source_meaning=preserves,
                    rationale="scripted local advisory verdict for harness verification",
                )
            )
        verdicts.append(
            OpeningCalibrationReviewVerdictV1(
                task_id=task.task_id,
                task_fingerprint_sha256=task.task_fingerprint_sha256,
                reviewer_id=task.reviewer_id,
                source_to_candidate_equivalent=True,
                positive_examples_valid=True,
                negative_examples_valid=True,
                non_vacuous=True,
                option_findings=tuple(findings),
                rationale="scripted local advisory verdict for harness verification",
            )
        )
    return tuple(verdicts)


def test_derives_exact_project_synthetic_opening_samples_with_structured_conversion_fields() -> (
    None
):
    samples = _samples()

    assert len(samples) == 11
    assert all(item.authority.authority == "machine_advisory" for item in samples)
    assert all(item.authority.may_freeze is False for item in samples)
    assert all(item.source.exact_bytes_available for item in samples)
    assert all(item.source.source_record is not None for item in samples)
    assert all(item.source.rights_record is not None for item in samples)
    assert all(
        item.source.rights_record is not None
        and item.source.rights_record.model_egress.value == "deny"
        for item in samples
    )
    assert all(item.source.source_text is not None for item in samples)
    assert all(item.semantic_projection is not None for item in samples)
    assert all(len(item.candidates) >= 2 for item in samples)
    assert all(
        item.semantic_projection.reverse_rendering
        and item.semantic_projection.quantifier_order
        and item.semantic_projection.conclusion
        for item in samples
        if item.semantic_projection is not None
    )
    assert all(
        candidate.semantic_binding_claimed is False
        and candidate.lean_parsed is False
        and candidate.authority.external_model_egress_allowed is False
        for item in samples
        for candidate in item.candidates
    )
    with pytest.raises(OpeningCalibrationError, match="source text may not be serialized"):
        samples[0].serialize_for_external_model()
    with pytest.raises(OpeningCalibrationError, match="source text may not be serialized"):
        samples[0].source.serialize_for_external_model()
    with pytest.raises(OpeningCalibrationError, match="source text may not be serialized"):
        samples[0].candidates[0].serialize_for_external_model()


def test_unavailable_source_fixture_carries_no_invented_source_or_conversion() -> None:
    unavailable = source_unavailable_opening_calibration_sample(
        sample_id="mckay-opening-source-unavailable",
        reference_id="mckay-lectures-differential-geometry-2022-text",
        expected_source_sha256="3fdfa27690ce473d8b84c322dbd12779ce5ba76aa12ef8d07608db768894bd25",
    )

    assert unavailable.source.exact_bytes_available is False
    assert unavailable.source.source_text is None
    assert unavailable.source.source_record is None
    assert unavailable.source.rights_record is None
    assert unavailable.semantic_projection is None
    assert unavailable.candidates == ()
    assert unavailable.mutations == ()
    with pytest.raises(OpeningCalibrationError, match="source-unavailable"):
        prepare_opening_calibration(
            unavailable,
            reviewers=_reviewers(),
            randomization_seed=b"u" * 32,
        )


def test_blind_multi_candidate_multi_role_tasks_are_text_free_and_deny_egress() -> None:
    sample = _sample("mg-a-quantifier-order")
    prepared = prepare_opening_calibration(
        sample,
        reviewers=_reviewers(),
        randomization_seed=b"q" * 32,
    )

    assert len(prepared.tasks) == 3
    assert {item.role for item in prepared.tasks} == set(MachineSemanticReviewRole)
    assert all(item.authority.authority == "machine_advisory" for item in prepared.tasks)
    assert all(item.authority.may_freeze is False for item in prepared.tasks)
    assert all(item.authority.external_model_egress_allowed is False for item in prepared.tasks)
    assert all(len(item.options) == 4 for item in prepared.tasks)
    assert all(
        all(option.option_id.startswith("option-") for option in item.options)
        for item in prepared.tasks
    )
    for task in prepared.tasks:
        payload = task.model_dump(mode="json")
        assert task.local_text_material_present is False
        assert "candidate_claim" not in str(payload)
        assert "expected_preserves_source_meaning" not in str(payload)
        assert all(
            candidate.candidate_source not in str(payload) for candidate in sample.candidates
        )
        with pytest.raises(OpeningCalibrationError, match="no external-model egress capability"):
            task.authorize_external_model_egress()
        with pytest.raises(OpeningCalibrationError, match="source text may not be serialized"):
            task.serialize_for_external_model()
        with pytest.raises(OpeningCalibrationError, match="source text may not be serialized"):
            task.egress_guard.serialize_for_external_model()
    with pytest.raises(OpeningCalibrationError, match="no external-model egress capability"):
        prepared.authorize_external_model_egress()


def test_preparation_is_replayable_but_seed_changes_blind_option_aliases() -> None:
    sample = _sample("mg-a-quantifier-order")
    first = prepare_opening_calibration(
        sample,
        reviewers=_reviewers(),
        randomization_seed=b"a" * 32,
    )
    replay = prepare_opening_calibration(
        sample,
        reviewers=tuple(reversed(_reviewers())),
        randomization_seed=b"a" * 32,
    )
    changed = prepare_opening_calibration(
        sample,
        reviewers=_reviewers(),
        randomization_seed=b"b" * 32,
    )

    assert first.preparation_fingerprint_sha256 == replay.preparation_fingerprint_sha256
    assert [item.model_dump(mode="json") for item in first.tasks] == [
        item.model_dump(mode="json") for item in replay.tasks
    ]
    assert first.randomization_commitment_sha256 != changed.randomization_commitment_sha256
    assert [item.options for item in first.tasks] != [item.options for item in changed.tasks]


def test_reviewer_isolation_metadata_is_bound_into_preparation_and_report() -> None:
    sample = _sample("mg-a-quantifier-order")
    baseline_reviewers = _reviewers()
    changed_reviewers = (
        replace(
            baseline_reviewers[0],
            independence_group="opening-review-group-changed",
            declared_failure_domain_id="opening-failure-domain-changed",
            role_environment_hash=digest_bytes(HashKindV1.ENVIRONMENT, b"changed-environment"),
            run_id="opening-review-run-changed",
        ),
        *baseline_reviewers[1:],
    )
    baseline = prepare_opening_calibration(
        sample,
        reviewers=baseline_reviewers,
        randomization_seed=b"i" * 32,
    )
    changed = prepare_opening_calibration(
        sample,
        reviewers=changed_reviewers,
        randomization_seed=b"i" * 32,
    )

    assert baseline.preparation_fingerprint_sha256 != changed.preparation_fingerprint_sha256
    assert baseline.tasks[0].reviewer_binding_sha256 != changed.tasks[0].reviewer_binding_sha256
    assert baseline.tasks[0].task_fingerprint_sha256 != changed.tasks[0].task_fingerprint_sha256

    report = score_opening_calibration(baseline, _verdicts(baseline))
    assert report.reviewer_binding_sha256 == tuple(
        task.reviewer_binding_sha256 for task in baseline.tasks
    )


def test_scoring_correct_advisory_outputs_remains_nonfreezable_and_nonroutable() -> None:
    prepared = prepare_opening_calibration(
        _sample("mg-a-quantifier-order"),
        reviewers=_reviewers(),
        randomization_seed=b"s" * 32,
    )
    verdicts = _verdicts(prepared)
    report = score_opening_calibration(prepared, verdicts)
    bridge_preparation = prepare_standard_bridge_bundle(prepared, report)

    assert all(item.execution_state == "unverified_local_synthetic_response" for item in verdicts)
    assert report.observed_advisory_checks_passed is True
    assert report.mutation_coverage_complete is False
    assert report.unverified_advisory_checks_passed is False
    assert report.execution_evidence_verified is False
    assert report.authority.authority == "machine_advisory"
    assert report.authority.may_freeze is False
    assert MutationKindV1.SWAP_QUANTIFIERS in report.covered_mutation_kinds
    assert MutationKindV1.WEAKEN_RELATION in report.covered_mutation_kinds
    assert MutationKindV1.DROP_FINITE in report.missing_required_mutation_kinds
    assert MutationKindV1.DROP_NOETHERIAN in report.missing_required_mutation_kinds
    assert bridge_preparation.statement_contract_present is False
    assert bridge_preparation.formalization_task_bundle_present is False
    assert bridge_preparation.authority.may_freeze is False
    with pytest.raises(OpeningCalibrationError, match="cannot enter the standard bridge"):
        bridge_preparation.assert_not_routable()


def test_mutation_survival_is_exposed_as_an_advisory_failure_not_silently_accepted() -> None:
    prepared = prepare_opening_calibration(
        _sample("mg-a-quantifier-order"),
        reviewers=_reviewers(),
        randomization_seed=b"m" * 32,
    )
    report = score_opening_calibration(
        prepared,
        _verdicts(prepared, let_first_mutation_survive=True),
    )

    assert report.mutations_rejected is False
    assert report.unverified_advisory_checks_passed is False
    assert "MUTATION_SURVIVED" in report.blockers
    assert report.authority.may_freeze is False


def test_report_rejects_coverage_or_pass_state_forgery() -> None:
    prepared = prepare_opening_calibration(
        _sample("mg-a-quantifier-order"),
        reviewers=_reviewers(),
        randomization_seed=b"c" * 32,
    )
    report = score_opening_calibration(prepared, _verdicts(prepared))

    with pytest.raises(ValueError, match="coverage-complete flag"):
        report.model_copy(update={"mutation_coverage_complete": True})
    with pytest.raises(ValueError, match="cannot claim an unverified advisory pass"):
        report.model_copy(update={"unverified_advisory_checks_passed": True})


def test_full_opening_corpus_covers_every_required_mutation_kind() -> None:
    covered = frozenset(kind for sample in _samples() for kind in sample.available_mutation_kinds)

    assert MutationKindV1.DROP_FINITE in covered
    assert MutationKindV1.DROP_NOETHERIAN in covered
    assert MutationKindV1.SWAP_QUANTIFIERS in covered
    assert MutationKindV1.WEAKEN_RELATION in covered
    assert MutationKindV1.DROP_NONEMPTY in covered
    assert MutationKindV1.REVERSE_PARAMETERS in covered
    assert MutationKindV1.VACUITY in covered


def test_missing_declared_finite_mutation_keeps_an_advisory_run_incomplete() -> None:
    sample = _sample("mg-a-finite-noetherian-compactness")
    payload = sample.model_dump(mode="json")
    payload["mutations"] = [
        mutation.model_dump(mode="json")
        for mutation in sample.mutations
        if mutation.kind is not MutationKindV1.DROP_FINITE
    ]
    payload["sample_snapshot_sha256"] = hashlib.sha256(
        canonical_json_bytes(
            {key: value for key, value in payload.items() if key != "sample_snapshot_sha256"}
        )
    ).hexdigest()
    without_finite = OpeningCalibrationSampleV1.model_validate(payload)

    assert MutationKindV1.DROP_FINITE in sample.available_mutation_kinds
    assert MutationKindV1.DROP_FINITE not in without_finite.available_mutation_kinds
    assert MutationKindV1.DROP_FINITE in without_finite.missing_required_mutation_kinds
    corpus_without_finite = frozenset(
        mutation_kind
        for corpus_sample in _samples()
        for mutation_kind in (
            without_finite.available_mutation_kinds
            if corpus_sample.sample_id == without_finite.sample_id
            else corpus_sample.available_mutation_kinds
        )
    )
    assert MutationKindV1.DROP_FINITE not in corpus_without_finite
    assert MutationKindV1.DROP_NOETHERIAN in corpus_without_finite
    # Corpus coverage cannot turn an omitted source mutation into a passing source-level run.
    prepared = prepare_opening_calibration(
        without_finite,
        reviewers=_reviewers(),
        randomization_seed=b"f" * 32,
    )
    report = score_opening_calibration(prepared, _verdicts(prepared))
    assert report.mutation_coverage_complete is False
    assert report.unverified_advisory_checks_passed is False
    assert MutationKindV1.DROP_FINITE in report.missing_required_mutation_kinds
