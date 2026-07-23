"""Answer-free, deterministic aggregation for verified FATE attempts.

This module deliberately does not launch a model, run Lean, fetch FATE, or inspect proof text.
It turns already verified attempt metadata into separately reported M/H/X measurements.  A caller
must supply the pinned manifest and environment identities alongside the fixed comparison setup.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Final, Literal

from .fate import TIER_COUNTS, FateProblemId, Tier, benchmark_splits

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TIERS: Final[tuple[Tier, ...]] = ("M", "H", "X")
type TerminalStatus = Literal["success", "budget_exhausted"]


class FateReportError(ValueError):
    """A benchmark report would be incomplete, mixed, or not reproducible."""


def _require_sha256(value: str, *, label: str) -> None:
    if not _SHA256.fullmatch(value):
        raise FateReportError(f"{label} must be a lowercase SHA-256 digest")


def _require_identifier(value: str, *, label: str) -> None:
    if not value or value != value.strip() or len(value) > 512:
        raise FateReportError(f"{label} must be a trimmed, bounded identifier")
    if any(character.isspace() or ord(character) < 32 for character in value):
        raise FateReportError(f"{label} must not contain whitespace or control characters")


@dataclass(frozen=True, slots=True)
class FateEvaluationConfigV1:
    """The non-secret fixed setup that makes a model comparison meaningful."""

    run_id: str
    suite: str
    fate_manifest_hash: str
    environment_hash: str
    provider_id: str
    model_id: str
    model_revision: str
    prompt_hash: str
    tools_hash: str
    retrieval_scope_hash: str
    attempt_budget: int
    timeout_seconds: float

    def __post_init__(self) -> None:
        for label, value in (
            ("run_id", self.run_id),
            ("provider_id", self.provider_id),
            ("model_id", self.model_id),
            ("model_revision", self.model_revision),
        ):
            _require_identifier(value, label=label)
        if self.suite not in {*benchmark_splits(), "FATE-350"}:
            raise FateReportError("report suite is not a pinned FATE selection")
        for label, value in (
            ("fate_manifest_hash", self.fate_manifest_hash),
            ("environment_hash", self.environment_hash),
            ("prompt_hash", self.prompt_hash),
            ("tools_hash", self.tools_hash),
            ("retrieval_scope_hash", self.retrieval_scope_hash),
        ):
            _require_sha256(value, label=label)
        if self.attempt_budget < 1:
            raise FateReportError("attempt_budget must be positive")
        if self.timeout_seconds <= 0:
            raise FateReportError("timeout_seconds must be positive")

    def public_dict(self) -> dict[str, object]:
        return {
            "schema_version": "autolean.fate-evaluation-config.v1",
            "run_id": self.run_id,
            "suite": self.suite,
            "fate_manifest_hash": self.fate_manifest_hash,
            "environment_hash": self.environment_hash,
            "provider_id": self.provider_id,
            "model_id": self.model_id,
            "model_revision": self.model_revision,
            "prompt_hash": self.prompt_hash,
            "tools_hash": self.tools_hash,
            "retrieval_scope_hash": self.retrieval_scope_hash,
            "attempt_budget": self.attempt_budget,
            "timeout_seconds": self.timeout_seconds,
        }


@dataclass(frozen=True, slots=True)
class FateVerifiedAttemptV1:
    """One completed, verifier-bound attempt without proof, prompt, or source contents."""

    problem_id: FateProblemId
    attempt_number: int
    verification_event_id: str
    accepted: bool
    elapsed_ms: int
    input_tokens: int
    output_tokens: int
    cost_microusd: int

    def __post_init__(self) -> None:
        if self.attempt_number < 1:
            raise FateReportError("attempt_number must be positive")
        _require_identifier(self.verification_event_id, label="verification_event_id")
        for label, value in (
            ("elapsed_ms", self.elapsed_ms),
            ("input_tokens", self.input_tokens),
            ("output_tokens", self.output_tokens),
            ("cost_microusd", self.cost_microusd),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise FateReportError(f"{label} must be a non-negative integer")

    def public_dict(self) -> dict[str, object]:
        return {
            "problem_id": self.problem_id.canonical,
            "attempt_number": self.attempt_number,
            "verification_event_id": self.verification_event_id,
            "accepted": self.accepted,
            "elapsed_ms": self.elapsed_ms,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cost_microusd": self.cost_microusd,
        }


@dataclass(frozen=True, slots=True)
class FateProblemResultV1:
    """A terminal per-problem outcome under one fixed attempt budget."""

    problem_id: FateProblemId
    terminal_status: TerminalStatus
    attempts: tuple[FateVerifiedAttemptV1, ...]

    def validate_for_budget(self, attempt_budget: int) -> None:
        if not self.attempts:
            raise FateReportError("every selected FATE problem needs a terminal attempt record")
        if any(attempt.problem_id != self.problem_id for attempt in self.attempts):
            raise FateReportError("a problem result cannot contain another FATE problem's attempt")
        numbers = tuple(attempt.attempt_number for attempt in self.attempts)
        if numbers != tuple(range(1, len(numbers) + 1)):
            raise FateReportError("attempt numbers must be contiguous and begin at one")
        if len(self.attempts) > attempt_budget:
            raise FateReportError("problem result exceeds the configured attempt budget")
        accepted_positions = tuple(
            index for index, attempt in enumerate(self.attempts) if attempt.accepted
        )
        if self.terminal_status == "success":
            if len(accepted_positions) != 1:
                raise FateReportError("a successful problem result requires exactly one acceptance")
            if accepted_positions[0] != len(self.attempts) - 1:
                raise FateReportError("attempts after an accepted proof are not permitted")
        elif accepted_positions:
            raise FateReportError("a budget-exhausted problem result cannot contain acceptance")
        elif len(self.attempts) != attempt_budget:
            raise FateReportError("a failed problem must exhaust the configured attempt budget")

    def public_dict(self) -> dict[str, object]:
        return {
            "problem_id": self.problem_id.canonical,
            "terminal_status": self.terminal_status,
            "attempts": [attempt.public_dict() for attempt in self.attempts],
        }


@dataclass(frozen=True, slots=True)
class FateTierMetricsV1:
    """Counts and accounting for exactly one FATE tier, never a cross-tier aggregate."""

    tier: Tier
    problems: int
    pass_at_1: int
    pass_at_4: int
    success_at_budget: int
    attempts: int
    elapsed_ms: int
    input_tokens: int
    output_tokens: int
    cost_microusd: int

    def public_dict(self) -> dict[str, object]:
        return {
            "tier": self.tier,
            "problems": self.problems,
            "pass_at_1": self.pass_at_1,
            "pass_at_1_rate": self.pass_at_1 / self.problems,
            "pass_at_4": self.pass_at_4,
            "pass_at_4_rate": self.pass_at_4 / self.problems,
            "success_at_budget": self.success_at_budget,
            "success_at_budget_rate": self.success_at_budget / self.problems,
            "attempts": self.attempts,
            "elapsed_ms": self.elapsed_ms,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cost_microusd": self.cost_microusd,
        }


def _suite_targets(suite: str) -> dict[Tier, tuple[int, ...]]:
    if suite == "FATE-350":
        return {tier: tuple(range(1, TIER_COUNTS[tier] + 1)) for tier in _TIERS}
    return benchmark_splits()[suite]


@dataclass(frozen=True, slots=True)
class FateEvaluationReportV1:
    """A complete reproducible result set for one pinned FATE suite configuration."""

    config: FateEvaluationConfigV1
    results: tuple[FateProblemResultV1, ...]

    def __post_init__(self) -> None:
        targets = _suite_targets(self.config.suite)
        expected = {FateProblemId(tier, number) for tier in _TIERS for number in targets[tier]}
        observed = tuple(result.problem_id for result in self.results)
        if len(set(observed)) != len(observed):
            raise FateReportError("FATE report has duplicate problem results")
        if set(observed) != expected:
            missing = len(expected - set(observed))
            unexpected = len(set(observed) - expected)
            raise FateReportError(
                f"FATE report does not exactly match its pinned suite: {missing} missing, "
                f"{unexpected} unexpected"
            )
        for result in self.results:
            result.validate_for_budget(self.config.attempt_budget)

    def metrics(self) -> tuple[FateTierMetricsV1, ...]:
        by_tier: dict[Tier, list[FateProblemResultV1]] = {tier: [] for tier in _TIERS}
        for result in self.results:
            by_tier[result.problem_id.tier].append(result)
        return tuple(self._tier_metrics(tier, tuple(by_tier[tier])) for tier in _TIERS)

    @staticmethod
    def _tier_metrics(
        tier: Tier,
        results: tuple[FateProblemResultV1, ...],
    ) -> FateTierMetricsV1:
        attempts = tuple(attempt for result in results for attempt in result.attempts)
        return FateTierMetricsV1(
            tier=tier,
            problems=len(results),
            pass_at_1=sum(result.attempts[0].accepted for result in results),
            pass_at_4=sum(
                any(attempt.accepted for attempt in result.attempts[:4]) for result in results
            ),
            success_at_budget=sum(result.terminal_status == "success" for result in results),
            attempts=len(attempts),
            elapsed_ms=sum(attempt.elapsed_ms for attempt in attempts),
            input_tokens=sum(attempt.input_tokens for attempt in attempts),
            output_tokens=sum(attempt.output_tokens for attempt in attempts),
            cost_microusd=sum(attempt.cost_microusd for attempt in attempts),
        )

    def public_dict(self) -> dict[str, object]:
        return {
            "schema_version": "autolean.fate-evaluation-report.v1",
            "config": self.config.public_dict(),
            "tiers": [metric.public_dict() for metric in self.metrics()],
            "results": [
                result.public_dict()
                for result in sorted(
                    self.results,
                    key=lambda item: (item.problem_id.tier, item.problem_id.number),
                )
            ],
        }

    def canonical_json_bytes(self) -> bytes:
        """Render a stable, answer-free exchange record suitable for content addressing."""

        return (
            json.dumps(
                self.public_dict(),
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
