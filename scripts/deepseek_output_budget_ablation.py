"""Run one bounded DeepSeek output-budget ablation through the authorized role bridge.

The protocol compares a fresh 256-token control arm with one fresh larger-output arm.  It is an
operator observation of completion-budget saturation, never a capability, role-floor, proof, or
Builder-fidelity result.  Both arms use the existing DeepSeek-only authorized runner.  The fixed
control-first execution order remains a time/order confound, so the report is descriptive rather
than a causal estimate of the output ceiling.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import secrets
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal, Never, Protocol, Self

from autolean_contracts import ContractModel, ModelWorkRoleV1, canonical_json_bytes
from autolean_prover.providers.responses import HttpxResponsesTransport
from pydantic import ConfigDict, Field, model_validator

from benchmarks.authorized_role_bridge import (
    AuthorizedRoleCompletionEvidenceReaderV2,
    is_safe_authorized_role_run_id,
)
from benchmarks.authorized_role_evaluation import (
    evaluate_completed_authorized_role_suite_structural_json,
)
from scripts import deepseek_role_baseline as role_runner
from scripts.deepseek_live_baseline import _required_secret

_SCHEMA_VERSION = "autolean.deepseek-output-budget-ablation.v1"
_PROTOCOL_ID = "deepseek-role-output-budget-ablation-v1"
_BASELINE_OUTPUT_TOKENS: Final[Literal[256]] = 256
_CANDIDATE_OUTPUT_TOKENS: Final[frozenset[Literal[512, 1024]]] = frozenset({512, 1024})
_TRIALS_PER_ARM = 10
_ROLES = tuple(sorted(ModelWorkRoleV1, key=lambda role: role.value))
_SHA256 = r"^[0-9a-f]{64}$"
_SAFE_FAILURE = r"^[a-z][a-z0-9_]{0,63}$"
_PUBLIC_RUN_ID = r"^(unavailable|[a-z0-9][a-z0-9_.-]{0,47})$"
_RUN_ID = r"^[a-z0-9][a-z0-9_.-]{0,47}$"


class DeepSeekOutputBudgetAblationError(ValueError):
    """The output-budget ablation could not establish a bounded arm."""


class _RedactedArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        del message
        raise DeepSeekOutputBudgetAblationError("invalid CLI arguments")


class _Transport(Protocol):
    def post_json(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        payload: Mapping[str, object],
        timeout_seconds: float,
    ) -> Mapping[str, object]: ...


class CountingTransport:
    """Count provider dispatches without retaining any outbound or inbound content."""

    def __init__(self, delegate: _Transport) -> None:
        self._delegate = delegate
        self.calls = 0

    def post_json(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        payload: Mapping[str, object],
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        self.calls += 1
        return self._delegate.post_json(
            url=url,
            headers=headers,
            payload=payload,
            timeout_seconds=timeout_seconds,
        )


class DeepSeekOutputBudgetRoleSaturationV1(ContractModel):
    """One role-local saturation count, without a score or output-derived diagnosis."""

    schema_version: Literal["autolean.deepseek-output-budget-role-saturation.v1"] = (
        "autolean.deepseek-output-budget-role-saturation.v1"
    )
    role: ModelWorkRoleV1
    trial_count: Literal[2] = 2
    saturated_trial_count: int = Field(ge=0, le=2)


class DeepSeekOutputBudgetAblationArmV1(ContractModel):
    """Redacted public state for one fixed-budget ten-trial arm."""

    model_config = ConfigDict(hide_input_in_errors=True)

    schema_version: Literal["autolean.deepseek-output-budget-ablation-arm.v1"] = (
        "autolean.deepseek-output-budget-ablation-arm.v1"
    )
    output_token_limit: Literal[256, 512, 1024]
    status: Literal[
        "planned",
        "preflight_ready",
        "settled",
        "execution_refused",
        "reconciliation_required",
        "skipped",
    ]
    plan_hash: str = Field(pattern=_SHA256)
    provider_call_count: int = Field(default=0, ge=0, le=_TRIALS_PER_ARM)
    private_evidence_committed: bool = False
    structural_evaluator_hash: str | None = Field(default=None, pattern=_SHA256)
    saturated_trial_count: int | None = Field(default=None, ge=0, le=_TRIALS_PER_ARM)
    role_saturations: tuple[DeepSeekOutputBudgetRoleSaturationV1, ...] = ()
    failure_class: str | None = Field(default=None, pattern=_SAFE_FAILURE)

    @model_validator(mode="after")
    def validate_arm(self) -> Self:
        settled = self.status == "settled"
        has_saturation = self.saturated_trial_count is not None
        if settled:
            if (
                self.provider_call_count != _TRIALS_PER_ARM
                or not self.private_evidence_committed
                or not has_saturation
                or self.structural_evaluator_hash is None
                or len(self.role_saturations) != len(_ROLES)
                or tuple(item.role for item in self.role_saturations) != _ROLES
                or sum(item.saturated_trial_count for item in self.role_saturations)
                != self.saturated_trial_count
                or self.failure_class is not None
            ):
                raise ValueError("settled ablation arm lacks validated saturation evidence")
        elif (
            self.private_evidence_committed
            or has_saturation
            or self.structural_evaluator_hash is not None
            or self.role_saturations
        ):
            raise ValueError("unsettled ablation arm cannot expose partial private evidence")
        if self.status in {"planned", "preflight_ready", "skipped"} and (
            self.provider_call_count != 0 or self.failure_class is not None
        ):
            raise ValueError("non-executed ablation arm has dispatch or failure evidence")
        if self.status in {"execution_refused", "reconciliation_required"} and (
            self.failure_class is None
        ):
            raise ValueError("failed ablation arm requires one redacted failure class")
        return self


class DeepSeekOutputBudgetSaturationComparisonV1(ContractModel):
    """A descriptive ceiling comparison; it intentionally has no score or winner field."""

    schema_version: Literal["autolean.deepseek-output-budget-saturation-comparison.v1"] = (
        "autolean.deepseek-output-budget-saturation-comparison.v1"
    )
    baseline_output_token_limit: Literal[256] = 256
    candidate_output_token_limit: Literal[512, 1024]
    baseline_saturated_trial_count: int = Field(ge=0, le=_TRIALS_PER_ARM)
    candidate_saturated_trial_count: int = Field(ge=0, le=_TRIALS_PER_ARM)
    candidate_minus_baseline_saturated_trials: int = Field(ge=-_TRIALS_PER_ARM, le=_TRIALS_PER_ARM)

    @model_validator(mode="after")
    def validate_difference(self) -> Self:
        if self.candidate_minus_baseline_saturated_trials != (
            self.candidate_saturated_trial_count - self.baseline_saturated_trial_count
        ):
            raise ValueError("saturation comparison difference is inconsistent")
        return self


class DeepSeekOutputBudgetAblationReportV1(ContractModel):
    """The complete redacted public ablation report."""

    model_config = ConfigDict(hide_input_in_errors=True)

    schema_version: Literal["autolean.deepseek-output-budget-ablation.v1"] = (
        "autolean.deepseek-output-budget-ablation.v1"
    )
    protocol_id: Literal["deepseek-role-output-budget-ablation-v1"] = (
        "deepseek-role-output-budget-ablation-v1"
    )
    mode: Literal["plan", "preflight", "run"]
    status: Literal[
        "planned",
        "preflight_ready",
        "settled",
        "execution_refused",
        "reconciliation_required",
    ]
    run_id: str = Field(pattern=_PUBLIC_RUN_ID)
    provider_id: Literal["deepseek"] = "deepseek"
    model_id: Literal["deepseek-v4-pro"] = "deepseek-v4-pro"
    model_revision: Literal["deepseek-v4-pro-api-alias-unpinned"] = (
        "deepseek-v4-pro-api-alias-unpinned"
    )
    authority_status: Literal["non-promotable-ephemeral-local-hmac"] = (
        "non-promotable-ephemeral-local-hmac"
    )
    capability_evidence_class: Literal["static_declared_only"] = "static_declared_only"
    role_floor_admission: Literal["forbidden"] = "forbidden"
    promotion_eligible: Literal[False] = False
    production_authority: Literal[False] = False
    competence_claim: Literal["not_permitted"] = "not_permitted"
    automatic_retry_permitted: Literal[False] = False
    comparison_status: Literal["not_computed", "budget_saturation_only"] = "not_computed"
    changed_dimensions: tuple[Literal["max_output_tokens"], ...] = ("max_output_tokens",)
    max_cost_microusd_per_trial: int = Field(ge=0)
    provider_call_ceiling: Literal[20] = 20
    observed_provider_call_count: int = Field(ge=0, le=20)
    experiment_binding_hash: str = Field(pattern=_SHA256)
    arms: tuple[DeepSeekOutputBudgetAblationArmV1, ...] = ()
    comparison: DeepSeekOutputBudgetSaturationComparisonV1 | None = None
    failure_class: str | None = Field(default=None, pattern=_SAFE_FAILURE)

    @model_validator(mode="after")
    def validate_report(self) -> Self:
        arm_limits = tuple(arm.output_token_limit for arm in self.arms)
        expected_limits = (
            _BASELINE_OUTPUT_TOKENS,
            self._candidate_output_token_limit(),
        )
        terminal_success = self.status in {"planned", "preflight_ready", "settled"}
        if terminal_success and arm_limits != expected_limits:
            raise ValueError(
                "successful ablation report must contain one baseline and one candidate"
            )
        if sum(arm.provider_call_count for arm in self.arms) != self.observed_provider_call_count:
            raise ValueError("observed provider call count differs from arm counts")
        if self.status == "planned":
            if (
                self.mode != "plan"
                or any(arm.status != "planned" for arm in self.arms)
                or self.comparison is not None
                or self.failure_class is not None
            ):
                raise ValueError("planned report has execution evidence")
        elif self.status == "preflight_ready":
            if (
                self.mode != "preflight"
                or any(arm.status != "preflight_ready" for arm in self.arms)
                or self.comparison is not None
                or self.failure_class is not None
            ):
                raise ValueError("preflight report has execution evidence")
        elif self.status == "settled":
            if (
                self.mode != "run"
                or any(arm.status != "settled" for arm in self.arms)
                or self.observed_provider_call_count != self.provider_call_ceiling
                or self.comparison is None
                or self.comparison_status != "budget_saturation_only"
                or self.failure_class is not None
            ):
                raise ValueError("settled report lacks complete bounded comparison evidence")
        elif self.failure_class is None:
            raise ValueError("failed ablation report requires one redacted failure class")
        if self.comparison is not None and (
            self.comparison.candidate_output_token_limit != self._candidate_output_token_limit()
        ):
            raise ValueError("comparison candidate differs from the planned candidate")
        return self

    def _candidate_output_token_limit(self) -> Literal[512, 1024]:
        if len(self.arms) < 2:
            # This is reached only while validating a redacted construction failure.
            return 512
        candidate = self.arms[1].output_token_limit
        if candidate == 512:
            return 512
        if candidate == 1024:
            return 1024
        raise ValueError("ablation candidate output limit is invalid")


@dataclass(frozen=True, slots=True)
class DeepSeekOutputBudgetAblationConfig:
    mode: Literal["plan", "preflight", "run"]
    run_id: str
    state_parent: Path
    private_parent: Path
    max_cost_microusd_per_trial: int
    candidate_output_tokens: Literal[512, 1024]
    operator_approved: bool

    def __post_init__(self) -> None:
        if self.operator_approved is not True:
            raise DeepSeekOutputBudgetAblationError("explicit operator approval is required")
        if (
            not is_safe_authorized_role_run_id(self.run_id)
            or re.fullmatch(_RUN_ID, self.run_id) is None
        ):
            raise DeepSeekOutputBudgetAblationError("run_id is not a safe ablation identifier")
        if self.candidate_output_tokens not in _CANDIDATE_OUTPUT_TOKENS:
            raise DeepSeekOutputBudgetAblationError("candidate output limit is not approved")
        if (
            isinstance(self.max_cost_microusd_per_trial, bool)
            or not isinstance(self.max_cost_microusd_per_trial, int)
            or self.max_cost_microusd_per_trial < 0
        ):
            raise DeepSeekOutputBudgetAblationError("per-trial cost limit is invalid")
        required_cost = role_runner._PRICE_BOUND_MICROUSD_PER_TOKEN * (
            512 + self.candidate_output_tokens
        )
        if self.max_cost_microusd_per_trial < required_cost:
            raise DeepSeekOutputBudgetAblationError(
                "per-trial cost limit cannot cover the candidate"
            )


@dataclass(frozen=True, slots=True)
class _AblationArmPlan:
    output_token_limit: Literal[256, 512, 1024]
    config: role_runner.DeepSeekRoleOperatorConfig
    plan: role_runner.DeepSeekRolePlan


def _content_hash(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _arm_config(
    config: DeepSeekOutputBudgetAblationConfig,
    output_token_limit: Literal[256, 512, 1024],
) -> role_runner.DeepSeekRoleOperatorConfig:
    return role_runner.DeepSeekRoleOperatorConfig(
        mode=config.mode,
        run_id=f"{config.run_id}-b{output_token_limit}",
        state_root=config.state_parent / f"{config.run_id}-b{output_token_limit}",
        private_root=config.private_parent / f"{config.run_id}-b{output_token_limit}",
        max_cost_microusd_per_trial=config.max_cost_microusd_per_trial,
        max_output_tokens=output_token_limit,
        operator_approved=config.operator_approved,
    )


def _validate_controlled_dimension(arms: tuple[_AblationArmPlan, _AblationArmPlan]) -> None:
    """Check that represented plan fields differ only in the frozen output limit."""

    baseline, candidate = arms
    if (
        baseline.plan.profile != candidate.plan.profile
        or baseline.plan.generation_policy != candidate.plan.generation_policy
        or baseline.plan.suite.source != candidate.plan.suite.source
        or baseline.plan.suite.rights != candidate.plan.suite.rights
        or baseline.plan.suite.matrix.cases != candidate.plan.suite.matrix.cases
    ):
        raise DeepSeekOutputBudgetAblationError("ablation changed a non-budget binding")
    baseline_cells = {cell.cell_id: cell for cell in baseline.plan.suite.matrix.cells}
    candidate_cells = {cell.cell_id: cell for cell in candidate.plan.suite.matrix.cells}
    if set(baseline_cells) != set(candidate_cells):
        raise DeepSeekOutputBudgetAblationError("ablation changed the locked role cells")
    for cell_id in sorted(baseline_cells):
        baseline_cell = baseline_cells[cell_id].model_dump(mode="json")
        candidate_cell = candidate_cells[cell_id].model_dump(mode="json")
        baseline_budget = baseline_cell.pop("budget")
        candidate_budget = candidate_cell.pop("budget")
        if baseline_cell != candidate_cell:
            raise DeepSeekOutputBudgetAblationError("ablation changed role-cell content")
        if (
            baseline_budget["max_input_tokens"] != 512
            or candidate_budget["max_input_tokens"] != 512
            or baseline_budget["max_output_tokens"] != _BASELINE_OUTPUT_TOKENS
            or candidate_budget["max_output_tokens"] != candidate.output_token_limit
            or baseline_budget["max_cost_microusd"] != candidate_budget["max_cost_microusd"]
            or baseline_budget["timeout_ms"] != candidate_budget["timeout_ms"]
            or baseline_budget["repetitions"] != candidate_budget["repetitions"]
        ):
            raise DeepSeekOutputBudgetAblationError("ablation cell budget is not controlled")


def build_deepseek_output_budget_ablation_plan(
    config: DeepSeekOutputBudgetAblationConfig,
) -> tuple[_AblationArmPlan, _AblationArmPlan]:
    """Build both frozen arms without secrets, state writes, or provider I/O."""

    baseline_config = _arm_config(config, _BASELINE_OUTPUT_TOKENS)
    candidate_config = _arm_config(config, config.candidate_output_tokens)
    arms = (
        _AblationArmPlan(
            output_token_limit=_BASELINE_OUTPUT_TOKENS,
            config=baseline_config,
            plan=role_runner.build_deepseek_role_plan(baseline_config),
        ),
        _AblationArmPlan(
            output_token_limit=config.candidate_output_tokens,
            config=candidate_config,
            plan=role_runner.build_deepseek_role_plan(candidate_config),
        ),
    )
    _validate_controlled_dimension(arms)
    return arms


def _experiment_binding_hash(
    config: DeepSeekOutputBudgetAblationConfig,
    arms: Sequence[_AblationArmPlan],
) -> str:
    return _content_hash(
        {
            "schema_version": _SCHEMA_VERSION,
            "protocol_id": _PROTOCOL_ID,
            "run_id": config.run_id,
            "changed_dimensions": ["max_output_tokens"],
            "candidate_output_tokens": config.candidate_output_tokens,
            "max_cost_microusd_per_trial": config.max_cost_microusd_per_trial,
            "plan_hashes": [arm.plan.plan_hash for arm in arms],
            "provider_call_ceiling": 20,
            "automatic_retry_permitted": False,
        }
    )


def _unexecuted_arm(
    arm: _AblationArmPlan,
    *,
    status: Literal["planned", "preflight_ready", "skipped"],
) -> DeepSeekOutputBudgetAblationArmV1:
    return DeepSeekOutputBudgetAblationArmV1(
        output_token_limit=arm.output_token_limit,
        status=status,
        plan_hash=arm.plan.plan_hash,
    )


def _failed_arm(
    arm: _AblationArmPlan,
    *,
    status: Literal["execution_refused", "reconciliation_required"],
    provider_call_count: int,
    failure_class: str,
) -> DeepSeekOutputBudgetAblationArmV1:
    return DeepSeekOutputBudgetAblationArmV1(
        output_token_limit=arm.output_token_limit,
        status=status,
        plan_hash=arm.plan.plan_hash,
        provider_call_count=provider_call_count,
        failure_class=failure_class,
    )


def _failure_class(error: BaseException) -> str:
    return role_runner._failure_class(
        error,
        role_runner.RedactingDiagnosticTransport(role_runner._NoIoTransport()),
    )


def _arm_from_private_run(
    arm: _AblationArmPlan,
    *,
    prepared: role_runner.PreparedDeepSeekRoleOperator,
    private_run: role_runner.DeepSeekRolePrivateRun,
    provider_call_count: int,
) -> DeepSeekOutputBudgetAblationArmV1:
    if private_run.report.status != "settled" or private_run.suite_sidecar is None:
        status: Literal["execution_refused", "reconciliation_required"] = (
            "reconciliation_required"
            if private_run.report.status == "reconciliation_required"
            else "execution_refused"
        )
        return _failed_arm(
            arm,
            status=status,
            provider_call_count=provider_call_count,
            failure_class=private_run.report.failure_class or "internal_unclassified",
        )
    try:
        structural = evaluate_completed_authorized_role_suite_structural_json(
            prepared.plan.suite,
            private_run.suite_sidecar,
            evidence_reader=AuthorizedRoleCompletionEvidenceReaderV2(
                manifest_store=prepared.completion_manifest_store,
                output_store=prepared.output_store,
                completion_verifier=prepared.authorization_service,
            ),
        )
    except BaseException as error:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        return _failed_arm(
            arm,
            status="reconciliation_required",
            provider_call_count=provider_call_count,
            failure_class=_failure_class(error),
        )
    role_saturations = tuple(
        DeepSeekOutputBudgetRoleSaturationV1(
            role=metric.role,
            saturated_trial_count=metric.budget_saturations,
        )
        for metric in structural.role_metrics
    )
    return DeepSeekOutputBudgetAblationArmV1(
        output_token_limit=arm.output_token_limit,
        status="settled",
        plan_hash=arm.plan.plan_hash,
        provider_call_count=provider_call_count,
        private_evidence_committed=True,
        structural_evaluator_hash=structural.evaluator_hash,
        saturated_trial_count=sum(item.saturated_trial_count for item in role_saturations),
        role_saturations=role_saturations,
    )


def _run_one_arm(
    arm: _AblationArmPlan,
    *,
    environment: Mapping[str, str] | None,
    transport: _Transport | None,
    clock: Callable[[], datetime],
) -> DeepSeekOutputBudgetAblationArmV1:
    delegate: _Transport = HttpxResponsesTransport() if transport is None else transport
    counted = CountingTransport(delegate)
    try:
        prepared = role_runner.preflight_deepseek_role_operator(
            arm.config,
            environment=environment,
            transport=counted,
            clock=clock,
        )
        private_run = role_runner.run_preflighted_deepseek_role_operator_with_private_sidecar(
            prepared
        )
        return _arm_from_private_run(
            arm,
            prepared=prepared,
            private_run=private_run,
            provider_call_count=counted.calls,
        )
    except BaseException as error:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        return _failed_arm(
            arm,
            status="execution_refused",
            provider_call_count=counted.calls,
            failure_class=_failure_class(error),
        )


def _report(
    config: DeepSeekOutputBudgetAblationConfig,
    arms: Sequence[_AblationArmPlan],
    public_arms: tuple[DeepSeekOutputBudgetAblationArmV1, ...],
    *,
    status: Literal[
        "planned",
        "preflight_ready",
        "settled",
        "execution_refused",
        "reconciliation_required",
    ],
    failure_class: str | None = None,
) -> DeepSeekOutputBudgetAblationReportV1:
    comparison: DeepSeekOutputBudgetSaturationComparisonV1 | None = None
    comparison_status: Literal["not_computed", "budget_saturation_only"] = "not_computed"
    if status == "settled":
        baseline, candidate = public_arms
        assert baseline.saturated_trial_count is not None
        assert candidate.saturated_trial_count is not None
        if candidate.output_token_limit not in _CANDIDATE_OUTPUT_TOKENS:
            raise DeepSeekOutputBudgetAblationError("settled candidate output limit is invalid")
        comparison = DeepSeekOutputBudgetSaturationComparisonV1(
            candidate_output_token_limit=candidate.output_token_limit,
            baseline_saturated_trial_count=baseline.saturated_trial_count,
            candidate_saturated_trial_count=candidate.saturated_trial_count,
            candidate_minus_baseline_saturated_trials=(
                candidate.saturated_trial_count - baseline.saturated_trial_count
            ),
        )
        comparison_status = "budget_saturation_only"
    return DeepSeekOutputBudgetAblationReportV1(
        mode=config.mode,
        status=status,
        run_id=config.run_id,
        max_cost_microusd_per_trial=config.max_cost_microusd_per_trial,
        observed_provider_call_count=sum(arm.provider_call_count for arm in public_arms),
        experiment_binding_hash=_experiment_binding_hash(config, arms),
        arms=public_arms,
        comparison_status=comparison_status,
        comparison=comparison,
        failure_class=failure_class,
    )


def execute_deepseek_output_budget_ablation(
    config: DeepSeekOutputBudgetAblationConfig,
    *,
    environment: Mapping[str, str] | None = None,
    transport: _Transport | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> DeepSeekOutputBudgetAblationReportV1:
    """Execute a two-arm protocol with a hard twenty-call ceiling and no retry path."""

    try:
        arms = build_deepseek_output_budget_ablation_plan(config)
    except BaseException as error:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        return _report(
            config,
            (),
            (),
            status="execution_refused",
            failure_class=_failure_class(error),
        )
    if config.mode == "plan":
        return _report(
            config,
            arms,
            tuple(_unexecuted_arm(arm, status="planned") for arm in arms),
            status="planned",
        )
    if config.mode == "preflight":
        public_arms: list[DeepSeekOutputBudgetAblationArmV1] = []
        for arm in arms:
            try:
                role_runner.preflight_deepseek_role_operator(
                    arm.config,
                    environment=environment,
                    transport=transport,
                    clock=clock,
                )
            except BaseException as error:
                if isinstance(error, (KeyboardInterrupt, SystemExit)):
                    raise
                failed_arm = _failed_arm(
                    arm,
                    status="execution_refused",
                    provider_call_count=0,
                    failure_class=_failure_class(error),
                )
                public_arms.append(failed_arm)
                for skipped in arms[len(public_arms) :]:
                    public_arms.append(_unexecuted_arm(skipped, status="skipped"))
                return _report(
                    config,
                    arms,
                    tuple(public_arms),
                    status="execution_refused",
                    failure_class=failed_arm.failure_class,
                )
            public_arms.append(_unexecuted_arm(arm, status="preflight_ready"))
        return _report(config, arms, tuple(public_arms), status="preflight_ready")

    baseline = _run_one_arm(
        arms[0],
        environment=environment,
        transport=transport,
        clock=clock,
    )
    if baseline.status != "settled":
        candidate = _unexecuted_arm(arms[1], status="skipped")
        return _report(
            config,
            arms,
            (baseline, candidate),
            status=(
                "reconciliation_required"
                if baseline.status == "reconciliation_required"
                else "execution_refused"
            ),
            failure_class=baseline.failure_class,
        )
    candidate = _run_one_arm(
        arms[1],
        environment=environment,
        transport=transport,
        clock=clock,
    )
    if candidate.status != "settled":
        return _report(
            config,
            arms,
            (baseline, candidate),
            status=(
                "reconciliation_required"
                if candidate.status == "reconciliation_required"
                else "execution_refused"
            ),
            failure_class=candidate.failure_class,
        )
    return _report(config, arms, (baseline, candidate), status="settled")


def _parser() -> argparse.ArgumentParser:
    parser = _RedactedArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "preflight", "run"))
    parser.add_argument("--operator-approved", action="store_true")
    parser.add_argument("--state-parent", required=True, type=Path)
    parser.add_argument("--private-parent", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--candidate-output-tokens", choices=(512, 1024), required=True, type=int)
    parser.add_argument("--max-cost-microusd-per-trial", required=True, type=int)
    parser.add_argument("--secret-file", type=Path)
    return parser


def _operator_environment_from_secret_file(secret_file: Path) -> dict[str, str]:
    """Load one API-key reference and create an ephemeral manifest authenticator."""

    return {
        "AUTOLEAN_DEEPSEEK_API_KEY": _required_secret(secret_file),
        "AUTOLEAN_ROLE_MANIFEST_HMAC_KEY": secrets.token_urlsafe(48),
    }


def _bare_refusal(
    mode: Literal["plan", "preflight", "run"],
    *,
    run_id: str,
    failure_class: str,
) -> DeepSeekOutputBudgetAblationReportV1:
    safe_run_id = run_id if re.fullmatch(_PUBLIC_RUN_ID, run_id) is not None else "unavailable"
    return DeepSeekOutputBudgetAblationReportV1(
        mode=mode,
        status="execution_refused",
        run_id=safe_run_id,
        max_cost_microusd_per_trial=0,
        observed_provider_call_count=0,
        experiment_binding_hash="0" * 64,
        failure_class=failure_class,
    )


def main(argv: Sequence[str] | None = None) -> int:
    mode: Literal["plan", "preflight", "run"] = "plan"
    run_id = "unavailable"
    try:
        arguments = _parser().parse_args(argv)
        mode = arguments.mode
        config = DeepSeekOutputBudgetAblationConfig(
            mode=mode,
            run_id=arguments.run_id,
            state_parent=arguments.state_parent,
            private_parent=arguments.private_parent,
            max_cost_microusd_per_trial=arguments.max_cost_microusd_per_trial,
            candidate_output_tokens=arguments.candidate_output_tokens,
            operator_approved=arguments.operator_approved,
        )
        run_id = config.run_id
        environment = (
            None
            if arguments.secret_file is None or config.mode == "plan"
            else _operator_environment_from_secret_file(arguments.secret_file)
        )
        report = execute_deepseek_output_budget_ablation(config, environment=environment)
    except BaseException as error:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        report = _bare_refusal(mode, run_id=run_id, failure_class=_failure_class(error))
    print(json.dumps(report.model_dump(mode="json"), sort_keys=True, separators=(",", ":")))
    return 0 if report.status in {"planned", "preflight_ready", "settled"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
