"""Focused checks for fake-first source-free iFEM case authoring."""

from __future__ import annotations

import ast
import copy
import hashlib
from collections import Counter
from pathlib import Path
from typing import cast

import pytest
from autolean_builder import ifem_next_calibration_case_intents as intents_module
from autolean_builder import ifem_source_free_case_authoring as authoring
from autolean_builder.ifem_calibration_risk_routing import (
    IFEMCalibrationPriorityV1,
    IFEMRequiredNextCalibrationV1,
)
from autolean_contracts import PairSplitPartitionV1, canonical_json_bytes


def _intents() -> intents_module.IFEMNextCalibrationCaseIntentsV1:
    return intents_module.build_ifem_next_calibration_case_intents_from_paths()


def _rehash_plan(payload: dict[str, object]) -> dict[str, object]:
    result = copy.deepcopy(payload)
    result.pop("content_sha256", None)
    result["content_sha256"] = hashlib.sha256(canonical_json_bytes(result)).hexdigest()
    return result


def _rehash_run(payload: dict[str, object]) -> dict[str, object]:
    result = copy.deepcopy(payload)
    result.pop("run_content_sha256", None)
    result["run_content_sha256"] = hashlib.sha256(canonical_json_bytes(result)).hexdigest()
    return result


def _non_p3_intent(
    queue: intents_module.IFEMNextCalibrationCaseIntentsV1,
    priority: IFEMCalibrationPriorityV1,
) -> intents_module.IFEMNextCalibrationCaseIntentV1:
    source = next(
        item
        for item in queue.intents
        if item.calibration_priority is IFEMCalibrationPriorityV1.P3_CREATE_CALIBRATION_CASE
    )
    payload = source.model_dump(mode="json")
    payload["calibration_priority"] = priority.value
    payload["required_next_calibration"] = (
        IFEMRequiredNextCalibrationV1.DETERMINISTIC_OR_HIGHER_CAPABILITY_CALIBRATION.value
        if priority
        in {
            IFEMCalibrationPriorityV1.P0_INCORRECT,
            IFEMCalibrationPriorityV1.P1_INVALID,
        }
        else IFEMRequiredNextCalibrationV1.INDEPENDENT_MACHINE_REVIEW.value
    )
    payload["structural_risk_discovery_required"] = False
    return intents_module.IFEMNextCalibrationCaseIntentV1.model_validate(payload)


def test_plan_uses_all_and_only_nine_p3_intents_with_a_3_3_3_partition() -> None:
    queue = _intents()
    seeds = authoring.build_private_source_free_case_seeds(queue)
    plan = authoring.build_source_free_case_authoring_plan(queue)

    assert len(seeds) == len(plan.case_coordinates) == 9
    assert Counter(seed.partition for seed in seeds) == {
        PairSplitPartitionV1.TRAIN: 3,
        PairSplitPartitionV1.DEV: 3,
        PairSplitPartitionV1.PRIVATE_HELDOUT: 3,
    }
    assert len({seed.intent_id.value for seed in seeds}) == 9
    assert all(seed.node_id in {item.node_id for item in queue.intents} for seed in seeds)
    assert all(
        plan.case_coordinates[index].case_id.value < plan.case_coordinates[index + 1].case_id.value
        for index in range(8)
    )
    assert plan.stage_count == 27
    assert plan.max_attempts_per_stage == 1


@pytest.mark.parametrize(
    "priority",
    (
        IFEMCalibrationPriorityV1.P0_INCORRECT,
        IFEMCalibrationPriorityV1.P1_INVALID,
        IFEMCalibrationPriorityV1.P2_INDEPENDENT_MACHINE_REVIEW,
    ),
)
def test_p0_p1_and_p2_are_rejected_before_private_seed_authoring(
    priority: IFEMCalibrationPriorityV1,
) -> None:
    queue = _intents()

    with pytest.raises(authoring.SourceFreeCaseAuthoringError, match="only a P3"):
        authoring.build_private_source_free_case_seed(
            queue,
            _non_p3_intent(queue, priority),
            partition=PairSplitPartitionV1.TRAIN,
        )


def test_private_oracle_and_node_identity_do_not_render_in_public_plan_or_report() -> None:
    queue = _intents()
    plan = authoring.build_source_free_case_authoring_plan(queue)
    private_run = authoring.run_source_free_case_authoring_fake(plan, queue)
    report = authoring.summarize_source_free_case_authoring_run(plan, private_run)

    rendered = authoring.render_source_free_case_authoring_plan(
        plan
    ) + authoring.render_source_free_case_authoring_report(report)
    for forbidden in (
        b'"hidden_oracle"',
        b'"node_id"',
        b'"source_text"',
        b'"source_span"',
        b'"lean"',
        b'"catalog"',
        b'"mutation"',
        b'"provider"',
        b'"request"',
        b'"private_root"',
    ):
        assert forbidden not in rendered
    assert report.private_seed_embedded is False
    assert report.raw_agent_output_embedded is False


def test_role_cards_are_strictly_projected_and_never_expose_hidden_oracle_or_node() -> None:
    queue = _intents()
    seed = authoring.build_private_source_free_case_seeds(queue)[0]
    author_card = authoring.build_source_free_authoring_card(seed)
    fake = authoring.SourceFreeCaseAuthoringFakeAgent()
    author_response = authoring.parse_source_free_authoring_response(fake.author(author_card))
    reviewer_card = authoring.build_source_free_reviewer_card(seed, author_response)
    reviewer_response = authoring.parse_source_free_review_response(fake.review(reviewer_card))
    supervisor_card = authoring.build_source_free_supervisor_card(
        seed,
        author_response,
        reviewer_response,
    )

    author_payload = author_card.model_dump(mode="json")
    reviewer_payload = reviewer_card.model_dump(mode="json")
    supervisor_payload = supervisor_card.model_dump(mode="json")
    assert "node_id" not in author_payload
    assert "hidden_oracle" not in author_payload
    assert "node_id" not in reviewer_payload
    assert "hidden_oracle" not in reviewer_payload
    assert "candidate" not in supervisor_payload
    assert "baseline" not in supervisor_payload
    assert "node_id" not in supervisor_payload
    assert "hidden_oracle" not in supervisor_payload


@pytest.mark.parametrize(
    "raw",
    (
        '{"schema_version":"autolean.ifem-source-free-authoring-response.v1","disposition":"abstain","selected_slot":null,"candidate":null,"candidate":null}',
        '{"schema_version":"autolean.ifem-source-free-authoring-response.v1","disposition":"abstain","selected_slot":NaN,"candidate":null}',
        (
            '{"schema_version":"autolean.ifem-source-free-authoring-response.v1",'
            '"disposition":"abstain","selected_slot":null,"candidate":null,'
            '"reason":"free text is forbidden"}'
        ),
    ),
)
def test_authoring_parser_rejects_duplicate_nonfinite_and_free_text(raw: str) -> None:
    with pytest.raises(authoring.SourceFreeCaseAuthoringError):
        authoring.parse_source_free_authoring_response(raw)


@pytest.mark.parametrize(
    "raw",
    (
        '{"schema_version":"autolean.ifem-source-free-authoring-response.v1","disposition":"propose","selected_slot":"1","candidate":{"alpha":1,"beta":2,"gamma":3,"guard_enabled":true}}',
        '{"schema_version":"autolean.ifem-source-free-authoring-response.v1","disposition":"propose","selected_slot":true,"candidate":{"alpha":1,"beta":2,"gamma":3,"guard_enabled":true}}',
        '{"schema_version":"autolean.ifem-source-free-authoring-response.v1","disposition":"propose","selected_slot":1.0,"candidate":{"alpha":1,"beta":2,"gamma":3,"guard_enabled":true}}',
        '{"schema_version":"autolean.ifem-source-free-authoring-response.v1","disposition":"propose","selected_slot":1,"candidate":{"alpha":"1","beta":2,"gamma":3,"guard_enabled":true}}',
        '{"schema_version":"autolean.ifem-source-free-authoring-response.v1","disposition":"propose","selected_slot":1,"candidate":{"alpha":true,"beta":2,"gamma":3,"guard_enabled":true}}',
        '{"schema_version":"autolean.ifem-source-free-authoring-response.v1","disposition":"propose","selected_slot":1,"candidate":{"alpha":1,"beta":2,"gamma":3,"guard_enabled":"true"}}',
    ),
)
def test_authoring_parser_rejects_scalar_type_coercion(raw: str) -> None:
    with pytest.raises(authoring.SourceFreeCaseAuthoringError):
        authoring.parse_source_free_authoring_response(raw)


def test_review_and_supervisor_parsers_reject_scalar_type_coercion() -> None:
    for raw in (
        '{"schema_version":"autolean.ifem-source-free-review-response.v1","disposition":"accept","observed_change_count":"1"}',
        '{"schema_version":"autolean.ifem-source-free-review-response.v1","disposition":"accept","observed_change_count":true}',
        '{"schema_version":"autolean.ifem-source-free-review-response.v1","disposition":"accept","observed_change_count":1.0}',
    ):
        with pytest.raises(authoring.SourceFreeCaseAuthoringError):
            authoring.parse_source_free_review_response(raw)
    for raw in (
        '{"schema_version":"autolean.ifem-source-free-supervisor-response.v1","disposition":"allow","violation_detected":"false"}',
        '{"schema_version":"autolean.ifem-source-free-supervisor-response.v1","disposition":"allow","violation_detected":0}',
        '{"schema_version":"autolean.ifem-source-free-supervisor-response.v1","disposition":"allow","violation_detected":1.0}',
    ):
        with pytest.raises(authoring.SourceFreeCaseAuthoringError):
            authoring.parse_source_free_supervisor_response(raw)


def test_review_and_supervisor_parsers_reject_extra_fields() -> None:
    with pytest.raises(authoring.SourceFreeCaseAuthoringError):
        authoring.parse_source_free_review_response(
            '{"schema_version":"autolean.ifem-source-free-review-response.v1","disposition":"accept","observed_change_count":1,"comment":"forbidden"}'
        )
    with pytest.raises(authoring.SourceFreeCaseAuthoringError):
        authoring.parse_source_free_supervisor_response(
            '{"schema_version":"autolean.ifem-source-free-supervisor-response.v1","disposition":"allow","violation_detected":false,"comment":"forbidden"}'
        )


def test_fake_run_is_deterministic_and_reports_same_agent_model_as_non_authoritative(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queue = _intents()
    plan = authoring.build_source_free_case_authoring_plan(queue)
    calls = {"author": 0, "review": 0, "supervise": 0}
    original_author = authoring.SourceFreeCaseAuthoringFakeAgent.author
    original_review = authoring.SourceFreeCaseAuthoringFakeAgent.review
    original_supervise = authoring.SourceFreeCaseAuthoringFakeAgent.supervise

    def counted_author(
        self: authoring.SourceFreeCaseAuthoringFakeAgent,
        card: authoring.SourceFreeAuthoringCardV1,
    ) -> str:
        calls["author"] += 1
        return original_author(self, card)

    def counted_review(
        self: authoring.SourceFreeCaseAuthoringFakeAgent,
        card: authoring.SourceFreeReviewerCardV1,
    ) -> str:
        calls["review"] += 1
        return original_review(self, card)

    def counted_supervise(
        self: authoring.SourceFreeCaseAuthoringFakeAgent,
        card: authoring.SourceFreeSupervisorCardV1,
    ) -> str:
        calls["supervise"] += 1
        return original_supervise(self, card)

    monkeypatch.setattr(authoring.SourceFreeCaseAuthoringFakeAgent, "author", counted_author)
    monkeypatch.setattr(authoring.SourceFreeCaseAuthoringFakeAgent, "review", counted_review)
    monkeypatch.setattr(
        authoring.SourceFreeCaseAuthoringFakeAgent,
        "supervise",
        counted_supervise,
    )
    first = authoring.run_source_free_case_authoring_fake(plan, queue)
    assert calls == {"author": 9, "review": 9, "supervise": 9}
    monkeypatch.undo()
    second = authoring.run_source_free_case_authoring_fake(plan, queue)
    report = authoring.summarize_source_free_case_authoring_run(plan, first)

    assert first == second
    assert all(
        aggregate.correct_count == 9
        and aggregate.incorrect_count == 0
        and aggregate.abstain_count == 0
        for aggregate in report.role_aggregates
    )
    assert report.same_agent_model_across_roles is True
    assert report.private_run_content_sha256 == first.run_content_sha256
    assert report.machine_advisory_disposition == "abstain"
    assert report.authority.machine_advisory_authorized is False
    assert report.authority.heldout_isolation_claimed is False
    assert report.case_linkage_publicly_replayable is True
    assert report.partition_labels_topology_only is True
    assert report.authority.freeze_allowed is False
    assert report.authority.prover_handoff_allowed is False
    with pytest.raises(authoring.SourceFreeCaseAuthoringError, match="cannot classify"):
        report.freeze_statement()
    with pytest.raises(authoring.SourceFreeCaseAuthoringError, match="cannot classify"):
        report.handoff_to_prover()


def test_fake_run_rejects_non_exact_actor_type() -> None:
    class OtherFake(authoring.SourceFreeCaseAuthoringFakeAgent):
        pass

    queue = _intents()
    plan = authoring.build_source_free_case_authoring_plan(queue)
    with pytest.raises(authoring.SourceFreeCaseAuthoringError, match="exact local fake"):
        authoring.run_source_free_case_authoring_fake(plan, queue, agent=OtherFake())


def test_rehashed_private_run_coordinate_tampering_is_rejected() -> None:
    queue = _intents()
    plan = authoring.build_source_free_case_authoring_plan(queue)
    private_run = authoring.run_source_free_case_authoring_fake(plan, queue)
    payload = private_run.model_dump(mode="json")
    evaluations = cast(list[dict[str, object]], payload["evaluations"])
    train = next(item for item in evaluations if item["partition"] == "train")
    dev = next(item for item in evaluations if item["partition"] == "dev")
    train["partition"], dev["partition"] = dev["partition"], train["partition"]
    tampered = authoring.PrivateSourceFreeCaseAuthoringRunV1.model_validate(_rehash_run(payload))

    with pytest.raises(authoring.SourceFreeCaseAuthoringError, match="coordinates differ"):
        authoring.summarize_source_free_case_authoring_run(plan, tampered)


def test_rehashed_partition_tampering_is_rejected_by_exact_queue_replay() -> None:
    queue = _intents()
    plan = authoring.build_source_free_case_authoring_plan(queue)
    payload = plan.model_dump(mode="json")
    coordinates = cast(list[dict[str, object]], payload["case_coordinates"])
    train = next(item for item in coordinates if item["partition"] == "train")
    dev = next(item for item in coordinates if item["partition"] == "dev")
    train["partition"], dev["partition"] = dev["partition"], train["partition"]
    tampered = authoring.SourceFreeCaseAuthoringPlanV1.model_validate(_rehash_plan(payload))

    with pytest.raises(
        authoring.SourceFreeCaseAuthoringError,
        match="differs from exact intent replay",
    ):
        authoring.verify_source_free_case_authoring_plan_against_intents(tampered, queue)


def test_canonical_write_once_loading_and_exact_replay(tmp_path: Path) -> None:
    queue = _intents()
    plan_path = tmp_path / "plan.json"
    report_path = tmp_path / "report.json"
    plan = authoring.materialize_source_free_case_authoring_plan_once(plan_path, queue)
    private_run = authoring.run_source_free_case_authoring_fake(plan, queue)
    report = authoring.materialize_source_free_case_authoring_report_once(
        report_path,
        plan,
        private_run,
    )

    assert authoring.materialize_source_free_case_authoring_plan_once(plan_path, queue) == plan
    assert (
        authoring.materialize_source_free_case_authoring_report_once(report_path, plan, private_run)
        == report
    )
    assert authoring.load_source_free_case_authoring_plan(plan_path) == plan
    assert authoring.load_source_free_case_authoring_report(report_path) == report
    authoring.verify_source_free_case_authoring_plan_against_intents(plan, queue)

    plan_path.write_bytes(b"different\n")
    with pytest.raises(authoring.SourceFreeCaseAuthoringError, match="already exists"):
        authoring.materialize_source_free_case_authoring_plan_once(plan_path, queue)


def test_module_has_no_benchmark_prover_http_or_provider_runtime_dependency() -> None:
    module_path = Path(authoring.__file__)
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    imported_roots = {
        alias.name.split(".", 1)[0]
        for statement in ast.walk(tree)
        if isinstance(statement, ast.Import)
        for alias in statement.names
    }
    imported_roots.update(
        statement.module.split(".", 1)[0]
        for statement in ast.walk(tree)
        if isinstance(statement, ast.ImportFrom) and statement.module is not None
    )

    assert not imported_roots.intersection({"benchmarks", "Prover", "http", "httpx", "provider"})
