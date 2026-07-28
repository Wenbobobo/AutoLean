from __future__ import annotations

import base64
from dataclasses import fields, replace

import autolean_builder
import autolean_builder.machine_semantic_quorum as quorum_module
import pytest
from autolean_builder import (
    BlindMachineReviewTask,
    BlindOptionFinding,
    MachineQuorumDisposition,
    MachineQuorumReason,
    MachineReviewerSpec,
    MachineReviewExecutionEvidence,
    MachineReviewVerdict,
    MachineSemanticQuorumError,
    MachineSemanticQuorumPolicy,
    MachineSemanticReviewRole,
    SemanticReviewPacket,
    VerifiedMachineQuorumReport,
    aggregate_machine_review_evidence,
    build_unverified_machine_review_evidence,
    prepare_machine_review_tasks,
    verify_machine_quorum_report,
)
from autolean_contracts import (
    HashKindV1,
    MutationKindV1,
    StatementContractV1,
    canonical_json_bytes,
    digest_bytes,
    digest_text,
    stable_identifier,
)
from test_workflow import _contract, _evaluation, _id

_SEED = b"machine-semantic-quorum-test-seed-v2"
_DEFAULT_CRITICAL_KINDS = frozenset(
    {
        MutationKindV1.DROP_ASSUMPTION,
        MutationKindV1.SWAP_QUANTIFIERS,
        MutationKindV1.WEAKEN_RELATION,
        MutationKindV1.REMOVE_SIDE_CONDITION,
        MutationKindV1.DROP_NONEMPTY,
        MutationKindV1.DROP_FINITE,
        MutationKindV1.DROP_NOETHERIAN,
        MutationKindV1.REVERSE_PARAMETERS,
        MutationKindV1.VACUITY,
    }
)


def _packet(
    contract: StatementContractV1 | None = None,
) -> tuple[StatementContractV1, SemanticReviewPacket]:
    active_contract = contract or _contract()
    evaluation = _evaluation(active_contract)
    return active_contract, SemanticReviewPacket(
        task=evaluation.task,
        candidates=evaluation.candidates,
        mutation_probes=evaluation.mutation_probes,
    )


def _reviewers() -> tuple[MachineReviewerSpec, ...]:
    return (
        MachineReviewerSpec(
            reviewer_id="reviewer-source",
            role=MachineSemanticReviewRole.SOURCE_FIDELITY,
            independence_group="review-group-source",
            declared_failure_domain_id="failure-domain-a",
            role_environment_hash=digest_text(HashKindV1.ENVIRONMENT, "source-env"),
            run_id="machine-review-run-source",
        ),
        MachineReviewerSpec(
            reviewer_id="reviewer-adversary",
            role=MachineSemanticReviewRole.FORMALIZATION_ADVERSARY,
            independence_group="review-group-adversary",
            declared_failure_domain_id="failure-domain-b",
            role_environment_hash=digest_text(
                HashKindV1.ENVIRONMENT,
                "adversary-env",
            ),
            run_id="machine-review-run-adversary",
        ),
        MachineReviewerSpec(
            reviewer_id="reviewer-mutation",
            role=MachineSemanticReviewRole.MUTATION_SENTINEL,
            independence_group="review-group-mutation",
            declared_failure_domain_id="failure-domain-a",
            role_environment_hash=digest_text(HashKindV1.ENVIRONMENT, "mutation-env"),
            run_id="machine-review-run-mutation",
        ),
    )


def _tasks(
    contract: StatementContractV1,
    packet: SemanticReviewPacket,
    *,
    reviewers: tuple[MachineReviewerSpec, ...] | None = None,
    policy: MachineSemanticQuorumPolicy | None = None,
    seed: bytes = _SEED,
) -> tuple[BlindMachineReviewTask, ...]:
    return prepare_machine_review_tasks(
        contract,
        packet,
        reviewers=reviewers or _reviewers(),
        randomization_seed=seed,
        policy=policy,
    )


def _expected_by_source(packet: SemanticReviewPacket) -> dict[str, bool]:
    controls = {item.lean_statement_source for item in packet.candidates}
    mutants = {item.mutated_statement_source for item in packet.mutation_probes}
    assert controls.isdisjoint(mutants)
    return {**dict.fromkeys(controls, True), **dict.fromkeys(mutants, False)}


def _verdict(
    task: BlindMachineReviewTask,
    packet: SemanticReviewPacket,
    *,
    source_overrides: dict[str, bool] | None = None,
    source_to_normalized_equivalent: bool = True,
) -> MachineReviewVerdict:
    expected = _expected_by_source(packet)
    expected.update(source_overrides or {})
    return MachineReviewVerdict(
        reviewer_id=task.reviewer_id,
        source_to_normalized_equivalent=source_to_normalized_equivalent,
        positive_example_valid=True,
        negative_example_valid=True,
        non_vacuous=True,
        option_findings=tuple(
            BlindOptionFinding(
                option_id=option.option_id,
                option_fingerprint=option.option_fingerprint,
                preserves_claim=expected[option.statement_source],
                rationale="independent semantic classification",
            )
            for option in task.options
        ),
        rationale="independent limited-blinding review completed",
    )


def _evidence(
    task: BlindMachineReviewTask,
    packet: SemanticReviewPacket,
    *,
    verdict: MachineReviewVerdict | None = None,
    artifact: bytes | None = None,
) -> MachineReviewExecutionEvidence:
    active_verdict = verdict or _verdict(task, packet)
    return build_unverified_machine_review_evidence(
        task,
        active_verdict,
        external_response_artifact=(
            canonical_json_bytes(active_verdict.payload()) if artifact is None else artifact
        ),
    )


def _all_evidence(
    tasks: tuple[BlindMachineReviewTask, ...],
    packet: SemanticReviewPacket,
    *,
    source_overrides: dict[str, bool] | None = None,
) -> tuple[MachineReviewExecutionEvidence, ...]:
    return tuple(
        _evidence(
            task,
            packet,
            verdict=_verdict(
                task,
                packet,
                source_overrides=source_overrides,
            ),
        )
        for task in tasks
    )


def _aggregate(
    contract: StatementContractV1,
    packet: SemanticReviewPacket,
    tasks: tuple[BlindMachineReviewTask, ...],
    evidence: tuple[MachineReviewExecutionEvidence, ...],
    *,
    reviewers: tuple[MachineReviewerSpec, ...] | None = None,
    policy: MachineSemanticQuorumPolicy | None = None,
    seed: bytes = _SEED,
):
    return aggregate_machine_review_evidence(
        contract,
        packet,
        tasks,
        evidence,
        reviewers=reviewers or _reviewers(),
        randomization_seed=seed,
        policy=policy,
    )


def _response_artifacts(
    evidence: tuple[MachineReviewExecutionEvidence, ...],
) -> dict[str, bytes]:
    return {item.task_id.value: item.external_response_artifact for item in evidence}


def _rehash_task(
    task: BlindMachineReviewTask,
    reviewer: MachineReviewerSpec,
    *,
    scoring_bindings: tuple[quorum_module._OptionScoringBinding, ...] | None = None,
) -> BlindMachineReviewTask:
    scoring_commitment = (
        task.scoring_commitment
        if scoring_bindings is None
        else quorum_module._scoring_commitment(scoring_bindings)
    )
    audit = quorum_module._task_audit_payload(
        reviewer,
        task.subject,
        task.packet_fingerprint,
        task.review_preparation_fingerprint,
        task.policy,
        scoring_commitment,
        task.randomization_commitment,
    )
    task_fingerprint = digest_bytes(
        HashKindV1.MODEL_WORK_ITEM,
        canonical_json_bytes(audit),
    )
    return replace(
        task,
        declared_failure_domain_id=reviewer.declared_failure_domain_id,
        scoring_commitment=scoring_commitment,
        task_fingerprint=task_fingerprint,
        task_id=stable_identifier(
            "machine-semantic-review-task",
            task_fingerprint.value,
        ),
    )


def _rebind_evidence(
    task: BlindMachineReviewTask,
    evidence: MachineReviewExecutionEvidence,
) -> MachineReviewExecutionEvidence:
    return build_unverified_machine_review_evidence(
        task,
        evidence.verdict,
        external_response_artifact=evidence.external_response_artifact,
    )


def _recursive_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {key for child in value.values() for key in _recursive_keys(child)}
    if isinstance(value, list):
        return {key for child in value for key in _recursive_keys(child)}
    return set()


def _noncritical_packet(
    packet: SemanticReviewPacket,
) -> tuple[SemanticReviewPacket, str]:
    source = packet.mutation_probes[0].mutated_statement_source.replace(
        "x < y /\\ x <= y",
        "x = y /\\ x <= y",
    )
    probe = packet.mutation_probes[0].model_copy(
        update={
            "probe_id": _id("mutation-change-equality"),
            "kind": MutationKindV1.CHANGE_EQUALITY_NOTION,
            "target_path": "/formal/conclusion/equality-notion",
            "mutated_statement_source": source,
        }
    )
    return replace(
        packet,
        mutation_probes=(*packet.mutation_probes, probe),
    ), source


def test_public_task_has_no_expected_labels_and_deduplicates_controls() -> None:
    contract, packet = _packet()
    tasks = _tasks(contract, packet)
    control_source = packet.candidates[0].lean_statement_source
    assert len({item.lean_statement_source for item in packet.candidates}) == 1

    for task in tasks:
        assert not hasattr(task, "_scoring_bindings")
        assert "_scoring_bindings" not in {item.name for item in fields(task)}
        assert sum(option.statement_source == control_source for option in task.options) == 1
        assert len(task.options) == len(packet.mutation_probes) + 1
        visible_keys = _recursive_keys(task.agent_payload())
        assert {
            "selected_lean_statement",
            "selected_statement_hash",
            "lean_fragment",
            "target_path",
            "expected_failure",
            "expected_preserves_claim",
            "mutation_kind",
            "critical",
            "origin_fingerprints",
            "declared_failure_domain_id",
        }.isdisjoint(visible_keys)
        assert task.content_blinding_assurance == "limited_text_screening_unverified"


def test_aggregation_rederives_preparation_and_rejects_rekeyed_task() -> None:
    contract, packet = _packet()
    reviewers = _reviewers()
    tasks = _tasks(contract, packet, reviewers=reviewers)
    task = tasks[0]
    fake_bindings = tuple(
        quorum_module._OptionScoringBinding(
            option_id=option.option_id,
            option_fingerprint=option.option_fingerprint,
            origin_group_fingerprint=option.option_fingerprint,
            origin_fingerprints=(option.option_fingerprint,),
            expected_preserves_claim=True,
            critical=False,
            mutation_kind=None,
        )
        for option in task.options
    )
    fake_commitment = quorum_module._scoring_commitment(fake_bindings)
    reviewer = next(item for item in reviewers if item.reviewer_id == task.reviewer_id)
    fake_audit = quorum_module._task_audit_payload(
        reviewer,
        task.subject,
        task.packet_fingerprint,
        task.review_preparation_fingerprint,
        task.policy,
        fake_commitment,
        task.randomization_commitment,
    )
    fake_fingerprint = digest_bytes(
        HashKindV1.MODEL_WORK_ITEM,
        canonical_json_bytes(fake_audit),
    )
    forged = replace(
        task,
        scoring_commitment=fake_commitment,
        task_fingerprint=fake_fingerprint,
        task_id=stable_identifier(
            "machine-semantic-review-task",
            fake_fingerprint.value,
        ),
    )

    with pytest.raises(MachineSemanticQuorumError, match="exact rederived"):
        _aggregate(
            contract,
            packet,
            (forged, *tasks[1:]),
            _all_evidence(tasks, packet),
            reviewers=reviewers,
        )


def test_exact_response_artifact_is_bounded_and_hashed_internally() -> None:
    contract, packet = _packet()
    task = _tasks(contract, packet)[0]
    verdict = _verdict(task, packet)
    artifact = canonical_json_bytes(verdict.payload())
    evidence = _evidence(task, packet, verdict=verdict, artifact=artifact)

    assert evidence.external_response_artifact == artifact
    assert evidence.external_response_artifact_size == len(artifact)
    assert base64.b64decode(evidence.payload()["external_response_artifact_base64"]) == artifact
    assert evidence.external_response_artifact_fingerprint == digest_bytes(
        HashKindV1.MODEL_WORK_ITEM,
        b"autolean.machine-review-response-artifact.v1\x00" + artifact,
    )
    with pytest.raises(MachineSemanticQuorumError, match="canonical verdict"):
        _evidence(task, packet, verdict=verdict, artifact=b"caller-declared-label")
    with pytest.raises(MachineSemanticQuorumError, match="bounded byte"):
        _evidence(task, packet, verdict=verdict, artifact=b"x" * 1_048_577)


def test_report_status_is_derived_and_findings_tampering_is_rejected() -> None:
    contract, packet = _packet()
    tasks = _tasks(contract, packet)
    report = _aggregate(contract, packet, tasks, _all_evidence(tasks, packet))

    assert report.observed_profile_equality
    assert report.untrusted_semantic_all_checks_passed
    assert not report.untrusted_semantic_escalation_required
    assert report.authority_verification_required
    with pytest.raises(ValueError, match="init=False"):
        replace(report, untrusted_semantic_all_checks_passed=False)
    with pytest.raises(ValueError, match="init=False"):
        replace(report, reasons=())
    with pytest.raises(ValueError, match="init=False"):
        replace(report, report_fingerprint=report.report_fingerprint)

    profile = report.findings.profiles[0]
    scored = profile.option_findings[0]
    changed_profile = replace(
        profile,
        option_findings=(
            replace(
                scored,
                observed_preserves_claim=not scored.observed_preserves_claim,
            ),
            *profile.option_findings[1:],
        ),
    )
    changed_findings = replace(
        report.findings,
        profiles=(changed_profile, *report.findings.profiles[1:]),
    )
    with pytest.raises(
        MachineSemanticQuorumError,
        match="changes an observed option verdict",
    ):
        replace(report, findings=changed_findings)


def test_report_and_scoring_dtos_are_explicitly_untrusted_and_not_exported() -> None:
    contract, packet = _packet()
    tasks = _tasks(contract, packet)
    report = _aggregate(contract, packet, tasks, _all_evidence(tasks, packet))

    assert report.trust_state == "untrusted_serialization"
    assert report.findings.trust_state == "untrusted_serialization"
    assert all(
        profile.trust_state == "untrusted_serialization"
        and all(
            finding.trust_state == "untrusted_serialization" for finding in profile.option_findings
        )
        for profile in report.findings.profiles
    )
    assert not hasattr(report, "semantic_all_checks_passed")
    for internal_name in (
        "MachineAggregateFindings",
        "MachineReviewerAggregateProfile",
        "MachineScoredOptionFinding",
    ):
        assert internal_name not in autolean_builder.__all__
        assert not hasattr(autolean_builder, internal_name)


def test_verified_wrapper_requires_full_reconstruction_and_is_only_route_status() -> None:
    contract, packet = _packet()
    reviewers = _reviewers()
    tasks = _tasks(contract, packet, reviewers=reviewers)
    evidence = _all_evidence(tasks, packet)
    report = _aggregate(
        contract,
        packet,
        tasks,
        evidence,
        reviewers=reviewers,
    )

    with pytest.raises(TypeError, match="must be created"):
        VerifiedMachineQuorumReport(report, _token=object())

    verified = verify_machine_quorum_report(
        contract,
        packet,
        reviewers,
        _SEED,
        report,
        response_artifacts=_response_artifacts(evidence),
    )

    assert isinstance(verified, VerifiedMachineQuorumReport)
    assert verified.report.render_artifact() == report.render_artifact()
    assert verified.semantic_all_checks_passed
    assert not verified.semantic_escalation_required
    assert verified.observed_profile_equality
    assert verified.authority == "machine_advisory"
    assert not verified.may_freeze
    assert verified.authority_verification_required


def test_direct_all_controls_and_single_failure_domain_reports_fail_sanity() -> None:
    contract, packet = _packet()
    reviewers = _reviewers()
    tasks = _tasks(contract, packet, reviewers=reviewers)
    evidence = _all_evidence(tasks, packet)
    report = _aggregate(
        contract,
        packet,
        tasks,
        evidence,
        reviewers=reviewers,
    )
    reviewers_by_id = {item.reviewer_id: item for item in reviewers}

    all_control_profiles = tuple(
        replace(
            profile,
            option_findings=tuple(
                replace(
                    finding,
                    expected_preserves_claim=True,
                    critical=False,
                    mutation_kind=None,
                )
                for finding in profile.option_findings
            ),
        )
        for profile in report.findings.profiles
    )
    all_control_findings = replace(
        report.findings,
        profiles=all_control_profiles,
    )
    all_control_tasks = tuple(
        _rehash_task(
            task,
            reviewers_by_id[task.reviewer_id],
            scoring_bindings=tuple(item.scoring_binding() for item in profile.option_findings),
        )
        for task, profile in zip(
            report.tasks,
            all_control_profiles,
            strict=True,
        )
    )
    all_control_evidence = tuple(
        _rebind_evidence(task, observed)
        for task, observed in zip(
            all_control_tasks,
            report.evidence,
            strict=True,
        )
    )
    with pytest.raises(
        MachineSemanticQuorumError,
        match="policy-critical mutation",
    ):
        quorum_module.MachineQuorumReport(
            tasks=all_control_tasks,
            evidence=all_control_evidence,
            findings=all_control_findings,
        )

    one_domain_reviewers = tuple(
        replace(item, declared_failure_domain_id="failure-domain-one") for item in reviewers
    )
    one_domain_tasks = tuple(
        _rehash_task(task, reviewer)
        for task, reviewer in zip(
            report.tasks,
            sorted(one_domain_reviewers, key=lambda item: item.reviewer_id),
            strict=True,
        )
    )
    one_domain_evidence = tuple(
        _rebind_evidence(task, observed)
        for task, observed in zip(
            one_domain_tasks,
            report.evidence,
            strict=True,
        )
    )
    with pytest.raises(
        MachineSemanticQuorumError,
        match="two declared failure domains",
    ):
        quorum_module.MachineQuorumReport(
            tasks=one_domain_tasks,
            evidence=one_domain_evidence,
            findings=report.findings,
        )


def test_verifier_rejects_structurally_valid_forgery_and_input_drift() -> None:
    contract, packet = _packet()
    reviewers = _reviewers()
    tasks = _tasks(contract, packet, reviewers=reviewers)
    evidence = _all_evidence(tasks, packet)
    report = _aggregate(
        contract,
        packet,
        tasks,
        evidence,
        reviewers=reviewers,
    )

    changed_reviewer = replace(
        next(item for item in reviewers if item.reviewer_id == report.tasks[0].reviewer_id),
        declared_failure_domain_id="failure-domain-forged",
    )
    forged_task = _rehash_task(report.tasks[0], changed_reviewer)
    forged_evidence = _rebind_evidence(forged_task, report.evidence[0])
    forged_report = quorum_module.MachineQuorumReport(
        tasks=(forged_task, *report.tasks[1:]),
        evidence=(forged_evidence, *report.evidence[1:]),
        findings=report.findings,
    )
    with pytest.raises(MachineSemanticQuorumError, match="exact rederived"):
        verify_machine_quorum_report(
            contract,
            packet,
            reviewers,
            _SEED,
            forged_report,
            response_artifacts=_response_artifacts(forged_report.evidence),
        )

    artifacts = _response_artifacts(evidence)
    changed_contract = contract.model_copy(update={"contract_id": _id("contract-drift")})
    packet_without_probe = replace(
        packet,
        mutation_probes=packet.mutation_probes[:-1],
    )
    drifted_artifacts = dict(artifacts)
    drifted_artifacts[next(iter(drifted_artifacts))] = b"response-artifact-drift"
    drift_cases = (
        (changed_contract, packet, _SEED, artifacts),
        (contract, packet_without_probe, _SEED, artifacts),
        (
            contract,
            packet,
            b"different-machine-semantic-quorum-seed",
            artifacts,
        ),
        (contract, packet, _SEED, drifted_artifacts),
    )
    for changed_contract_input, changed_packet, changed_seed, changed_artifacts in drift_cases:
        with pytest.raises(MachineSemanticQuorumError):
            verify_machine_quorum_report(
                changed_contract_input,
                changed_packet,
                reviewers,
                changed_seed,
                report,
                response_artifacts=changed_artifacts,
            )


def test_noncritical_mutation_survival_fails_semantic_checks() -> None:
    contract, packet = _packet()
    packet, noncritical_source = _noncritical_packet(packet)
    tasks = _tasks(contract, packet)
    evidence = _all_evidence(
        tasks,
        packet,
        source_overrides={noncritical_source: True},
    )

    report = _aggregate(contract, packet, tasks, evidence)

    assert MachineQuorumReason.MUTATION_SURVIVED in report.reasons
    assert MachineQuorumReason.CRITICAL_MUTATION_SURVIVED not in report.reasons
    assert not report.untrusted_semantic_all_checks_passed
    assert report.untrusted_semantic_escalation_required


def test_critical_mutation_survival_adds_critical_reason() -> None:
    contract, packet = _packet()
    critical_source = next(
        item.mutated_statement_source
        for item in packet.mutation_probes
        if item.kind is MutationKindV1.SWAP_QUANTIFIERS
    )
    tasks = _tasks(contract, packet)
    report = _aggregate(
        contract,
        packet,
        tasks,
        _all_evidence(
            tasks,
            packet,
            source_overrides={critical_source: True},
        ),
    )

    assert MachineQuorumReason.MUTATION_SURVIVED in report.reasons
    assert MachineQuorumReason.CRITICAL_MUTATION_SURVIVED in report.reasons
    assert not report.untrusted_semantic_all_checks_passed
    assert report.observed_profile_equality


def test_blinding_screen_rejects_namespace_and_origin_identifier_exploits() -> None:
    contract, packet = _packet()
    namespaced = replace(
        packet.candidates[0],
        lean_statement_source=packet.candidates[0].lean_statement_source.replace(
            "theorem bounded_witness",
            "theorem modela.bounded_witness",
        ),
    )
    with pytest.raises(MachineSemanticQuorumError, match="contract declaration name"):
        _tasks(
            contract,
            replace(packet, candidates=(namespaced, *packet.candidates[1:])),
        )

    labeled = replace(
        packet.candidates[0],
        lean_statement_source=packet.candidates[0].lean_statement_source.replace(
            "hFinite",
            "origin_model_a",
        ),
    )
    with pytest.raises(
        MachineSemanticQuorumError,
        match="origin-revealing identifier",
    ):
        _tasks(
            contract,
            replace(packet, candidates=(labeled, *packet.candidates[1:])),
        )


def test_duplicate_mutants_and_mutant_control_bytes_are_rejected() -> None:
    contract, packet = _packet()
    duplicate_mutant = packet.mutation_probes[1].model_copy(
        update={"mutated_statement_source": packet.mutation_probes[0].mutated_statement_source}
    )
    with pytest.raises(MachineSemanticQuorumError, match="byte-identical mutation"):
        _tasks(
            contract,
            replace(
                packet,
                mutation_probes=(
                    packet.mutation_probes[0],
                    duplicate_mutant,
                    *packet.mutation_probes[2:],
                ),
            ),
        )

    control_duplicate = packet.mutation_probes[0].model_copy(
        update={"mutated_statement_source": packet.candidates[0].lean_statement_source}
    )
    with pytest.raises(MachineSemanticQuorumError, match="duplicates a semantic control"):
        _tasks(
            contract,
            replace(
                packet,
                mutation_probes=(control_duplicate, *packet.mutation_probes[1:]),
            ),
        )


def test_report_opens_deduplicated_control_origins_after_response() -> None:
    contract, packet = _packet()
    tasks = _tasks(contract, packet)
    report = _aggregate(contract, packet, tasks, _all_evidence(tasks, packet))

    control_findings = [
        item
        for item in report.findings.profiles[0].option_findings
        if item.expected_preserves_claim
    ]
    assert len(control_findings) == 1
    assert len(control_findings[0].origin_fingerprints) == 2
    assert MachineQuorumReason.CONTENT_BLINDING_UNVERIFIED in report.reasons
    assert any("not Lean AST alpha-normalization" in item for item in report.authority_limitations)


def test_permutation_invariance_and_nonpromotable_authority() -> None:
    contract, packet = _packet()
    reviewers = _reviewers()
    tasks = _tasks(contract, packet, reviewers=reviewers)
    evidence = _all_evidence(tasks, packet)
    forward = _aggregate(
        contract,
        packet,
        tasks,
        evidence,
        reviewers=reviewers,
    )
    reverse = _aggregate(
        contract,
        packet,
        tuple(reversed(tasks)),
        tuple(reversed(evidence)),
        reviewers=tuple(reversed(reviewers)),
    )

    assert forward.render_artifact() == reverse.render_artifact()
    assert forward.report_fingerprint == reverse.report_fingerprint
    assert forward.disposition == MachineQuorumDisposition.UNVERIFIED_EXECUTION_EVIDENCE
    assert forward.authority == "machine_advisory"
    assert not forward.may_freeze
    assert forward.authority_verification_required
    with pytest.raises(ValueError, match="init=False"):
        replace(forward, may_freeze=True)
    with pytest.raises(ValueError, match="init=False"):
        replace(evidence[0], verification_state="verified")


def test_policy_and_declared_failure_domain_floors() -> None:
    contract, packet = _packet()
    policy = MachineSemanticQuorumPolicy(
        extra_critical_mutation_kinds=frozenset({MutationKindV1.CHANGE_EQUALITY_NOTION})
    )
    assert policy.critical_mutation_kinds > _DEFAULT_CRITICAL_KINDS
    with pytest.raises(MachineSemanticQuorumError, match="incomplete"):
        _tasks(contract, packet, policy=policy)

    one_domain = tuple(
        replace(item, declared_failure_domain_id="failure-domain-a") for item in _reviewers()
    )
    with pytest.raises(MachineSemanticQuorumError, match="failure domains"):
        _tasks(contract, packet, reviewers=one_domain)

    packet_without_default = replace(
        packet,
        mutation_probes=tuple(
            probe
            for probe in packet.mutation_probes
            if probe.kind is not MutationKindV1.DROP_NOETHERIAN
        ),
    )
    with pytest.raises(MachineSemanticQuorumError, match="drop_noetherian"):
        _tasks(contract, packet_without_default)


def test_contract_and_seed_replay_are_rejected_by_rederivation() -> None:
    contract_a, packet_a = _packet()
    tasks_a = _tasks(contract_a, packet_a)
    evidence_a = _all_evidence(tasks_a, packet_a)
    contract_b = contract_a.model_copy(update={"contract_id": _id("contract-b")})
    _, packet_b = _packet(contract_b)

    with pytest.raises(MachineSemanticQuorumError, match="exact rederived"):
        _aggregate(contract_b, packet_b, tasks_a, evidence_a)
    with pytest.raises(MachineSemanticQuorumError, match="exact rederived"):
        _aggregate(
            contract_a,
            packet_a,
            tasks_a,
            evidence_a,
            seed=b"different-machine-semantic-quorum-seed",
        )


def test_reviewer_disagreement_is_semantic_escalation_not_authority_claim() -> None:
    contract, packet = _packet()
    tasks = _tasks(contract, packet)
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
    report = _aggregate(contract, packet, tasks, evidence)

    assert MachineQuorumReason.REVIEWER_DISAGREEMENT in report.reasons
    assert MachineQuorumReason.SEMANTIC_CHECK_FAILED in report.reasons
    assert not report.observed_profile_equality
    assert report.untrusted_semantic_escalation_required
    assert report.authority_verification_required
