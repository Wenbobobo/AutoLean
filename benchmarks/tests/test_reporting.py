from __future__ import annotations

import pytest

from benchmarks.fate import FateProblemId, Tier
from benchmarks.reporting import (
    FateEvaluationConfigV1,
    FateEvaluationReportV1,
    FateProblemResultV1,
    FateReportError,
    FateVerifiedAttemptV1,
)


def _config(*, budget: int = 4) -> FateEvaluationConfigV1:
    return FateEvaluationConfigV1(
        run_id="compare-fixture-v1",
        suite="compile-canary-12",
        fate_manifest_hash="a" * 64,
        environment_hash="b" * 64,
        provider_id="fake",
        model_id="fixture-model",
        model_revision="fixture-revision",
        prompt_hash="c" * 64,
        tools_hash="d" * 64,
        retrieval_scope_hash="e" * 64,
        attempt_budget=budget,
        timeout_seconds=30.0,
    )


def _attempt(
    problem: FateProblemId,
    number: int,
    *,
    accepted: bool,
) -> FateVerifiedAttemptV1:
    return FateVerifiedAttemptV1(
        problem_id=problem,
        attempt_number=number,
        verification_event_id=f"verification-{problem.tier}-{problem.number}-{number}",
        accepted=accepted,
        elapsed_ms=number * 10,
        input_tokens=number,
        output_tokens=number + 1,
        cost_microusd=number * 5,
    )


def _result(problem: FateProblemId, *, accepted_on: int | None) -> FateProblemResultV1:
    budget = 4
    attempts = tuple(
        _attempt(problem, number, accepted=number == accepted_on)
        for number in range(1, (accepted_on or budget) + 1)
    )
    return FateProblemResultV1(
        problem_id=problem,
        terminal_status="success" if accepted_on is not None else "budget_exhausted",
        attempts=attempts,
    )


def _canary_report() -> FateEvaluationReportV1:
    # M: one pass@1, one pass@4, one exhausted. H: one pass@4, two exhausted.
    # X: one pass@1, two pass@4, and three exhausted.
    accepted = {
        ("M", 3): 1,
        ("M", 15): 3,
        ("H", 31): 4,
        ("X", 11): 1,
        ("X", 15): 2,
        ("X", 62): 4,
    }
    targets: dict[Tier, tuple[int, ...]] = {
        "M": (3, 15, 134),
        "H": (31, 51, 93),
        "X": (11, 15, 62, 72, 77, 86),
    }
    return FateEvaluationReportV1(
        config=_config(),
        results=tuple(
            _result(
                FateProblemId(tier, number),
                accepted_on=accepted.get((tier, number)),
            )
            for tier, numbers in targets.items()
            for number in numbers
        ),
    )


def test_report_keeps_tiers_separate_and_calculates_budget_metrics() -> None:
    metrics = {item.tier: item for item in _canary_report().metrics()}
    assert (metrics["M"].pass_at_1, metrics["M"].pass_at_4) == (1, 2)
    assert metrics["M"].success_at_budget == 2
    assert metrics["H"].pass_at_1 == 0
    assert metrics["H"].pass_at_4 == 1
    assert metrics["X"].problems == 6
    assert metrics["X"].pass_at_1 == 1
    assert metrics["X"].pass_at_4 == 3
    assert metrics["X"].success_at_budget == 3


def test_report_json_is_deterministic_and_answer_free() -> None:
    report = _canary_report()
    first = report.canonical_json_bytes()
    assert first == report.canonical_json_bytes()
    text = first.decode("ascii")
    assert "proof_source" not in text
    assert "prove the frozen theorem" not in text
    assert "tiers" in text


def test_report_rejects_missing_selected_problem() -> None:
    report = _canary_report()
    with pytest.raises(FateReportError, match="exactly match"):
        FateEvaluationReportV1(config=report.config, results=report.results[:-1])


def test_report_rejects_nonterminal_failure_and_post_success_attempts() -> None:
    problem = FateProblemId("M", 3)
    with pytest.raises(FateReportError, match="exhaust"):
        FateProblemResultV1(
            problem_id=problem,
            terminal_status="budget_exhausted",
            attempts=(_attempt(problem, 1, accepted=False),),
        ).validate_for_budget(4)
    with pytest.raises(FateReportError, match="exactly one acceptance"):
        FateProblemResultV1(
            problem_id=problem,
            terminal_status="success",
            attempts=(
                _attempt(problem, 1, accepted=True),
                _attempt(problem, 2, accepted=True),
            ),
        ).validate_for_budget(4)
