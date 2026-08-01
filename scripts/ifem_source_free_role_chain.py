"""Operate one bounded source-free formalizer-reviewer-supervisor chain.

This runner extends the retained one-coordinate DeepSeek canary to exactly the first case in the
private nine-case seed.  It reuses the same control-plane authorization, private output CAS,
ModelWork sidecar, and 27-coordinate stage ledger.  Only coordinates one through three are in
scope; the remaining 24 coordinates must stay pending.

The public result is aggregate execution evidence.  It never discloses role responses, model
identity, operator paths, credentials, per-case outcomes, or a score, and it never grants Builder
semantic authority, statement freeze, promotion, or Prover handoff.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sqlite3
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, Never, Self, cast

# Keep direct-file invocation usable without a caller-managed PYTHONPATH.
_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(_REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPOSITORY_ROOT))

from autolean_builder.ifem_source_free_case_authoring import (  # noqa: E402
    SourceFreeAuthoringResponseV1,
    SourceFreeReviewResponseV1,
    SourceFreeSupervisorResponseV1,
)
from autolean_builder.ifem_source_free_private_seed import (  # noqa: E402
    PrivateSourceFreeSeedItemV2,
)
from autolean_builder.ifem_source_free_stage_ledger import (  # noqa: E402
    SourceFreeStageCompletionBindingV1,
    SourceFreeStageCoordinateV1,
    SourceFreeStageLedgerStateV1,
)
from autolean_contracts import ContractModel, ModelWorkRoleV1, canonical_json_bytes  # noqa: E402
from autolean_prover.providers.responses import ResponsesTransport  # noqa: E402
from pydantic import Field, model_validator  # noqa: E402

from benchmarks.ifem_source_free_model_work_sidecar import (  # noqa: E402
    SourceFreeModelWorkAuthorityV1,
    source_free_model_work_prompt_contract_sha256,
)
from scripts import ifem_source_free_model_work as single  # noqa: E402

type RoleChainMode = Literal["plan", "preflight", "run", "resume"]
type RoleChainStatus = Literal[
    "planned",
    "preflight_ready",
    "settled",
    "recovered",
    "execution_refused",
    "reconciliation_required",
]

_ROLE_ORDER: Final[tuple[ModelWorkRoleV1, ...]] = (
    ModelWorkRoleV1.STATEMENT_FORMALIZER,
    ModelWorkRoleV1.FIDELITY_REVIEWER,
    ModelWorkRoleV1.CHEATING_SUPERVISOR,
)
_SELECTED_COORDINATE_COUNT: Final = 3
_OUTSIDE_SCOPE_COORDINATE_COUNT: Final = 24
_PER_STAGE_COST_BOUND_MICROUSD: Final = 61_440
_AGGREGATE_COST_BOUND_MICROUSD: Final = _SELECTED_COORDINATE_COUNT * _PER_STAGE_COST_BOUND_MICROUSD
_SCOPE_SELECTION_RULE: Final = "first_case_in_canonical_27_coordinate_run_v1"
_SCOPE_BINDING_FILENAME: Final = "source-free-role-chain-scope-v1.json"
_SHA256 = r"^[0-9a-f]{64}$"
_SAFE_FAILURE = r"^[a-z][a-z0-9_]{0,63}$"
_FORBIDDEN_PUBLIC_FIELDS: Final[tuple[bytes, ...]] = (
    b'"api_key"',
    b'"case_id"',
    b'"model_id"',
    b'"path"',
    b'"private_root"',
    b'"prompt"',
    b'"raw_response"',
    b'"response"',
    b'"run_label"',
    b'"secret"',
    b'"state_root"',
)


class SourceFreeDeepSeekRoleChainError(ValueError):
    """The three-role source-free boundary was violated."""


class SourceFreeDeepSeekRoleChainScopeError(SourceFreeDeepSeekRoleChainError):
    """The retained private run scope is unavailable or inconsistent."""


class SourceFreeDeepSeekRolePromptBindingV1(ContractModel):
    """Digest of one exact role prompt and finite input envelope."""

    schema_version: Literal["autolean.ifem-source-free-role-prompt-binding.v1"] = (
        "autolean.ifem-source-free-role-prompt-binding.v1"
    )
    role: ModelWorkRoleV1
    prompt_contract_sha256: str = Field(pattern=_SHA256)
    response_schema_sha256: str = Field(pattern=_SHA256)


class SourceFreeDeepSeekRoleChainScopeBindingV1(ContractModel):
    """Operator-private binding from the public plan to one exact three-coordinate scope."""

    schema_version: Literal["autolean.ifem-source-free-role-chain-scope-binding.v1"] = (
        "autolean.ifem-source-free-role-chain-scope-binding.v1"
    )
    protocol: Literal["autolean.ifem-source-free-deepseek-role-chain.v1"] = (
        "autolean.ifem-source-free-deepseek-role-chain.v1"
    )
    artifact_kind: Literal["operator_private_source_free_role_chain_scope_binding"] = (
        "operator_private_source_free_role_chain_scope_binding"
    )
    plan_content_sha256: str = Field(pattern=_SHA256)
    private_seed_manifest_content_sha256: str = Field(pattern=_SHA256)
    private_stage_run_content_sha256: str = Field(pattern=_SHA256)
    selection_rule: Literal["first_case_in_canonical_27_coordinate_run_v1"] = (
        "first_case_in_canonical_27_coordinate_run_v1"
    )
    selected_coordinate_sha256s: tuple[str, ...] = Field(min_length=3, max_length=3)
    selected_coordinate_commitment_sha256: str = Field(pattern=_SHA256)
    selected_case_count: Literal[1] = 1
    selected_coordinate_count: Literal[3] = 3
    outside_scope_coordinate_count: Literal[24] = 24
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_scope_binding(self) -> Self:
        if len(set(self.selected_coordinate_sha256s)) != 3 or any(
            re.fullmatch(_SHA256, value) is None for value in self.selected_coordinate_sha256s
        ):
            raise ValueError("role-chain scope binding has invalid selected coordinates")
        if self.selected_coordinate_commitment_sha256 != _sha256_json(
            self.selected_coordinate_sha256s
        ):
            raise ValueError("role-chain selected-coordinate commitment drifted")
        if self.content_sha256 != _sha256_json(self.content_payload()):
            raise ValueError("role-chain scope-binding hash drifted")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(
            dict[str, object],
            self.model_dump(mode="json", exclude={"content_sha256"}),
        )

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.model_dump(mode="json"))


class SourceFreeDeepSeekRoleChainPlanV1(ContractModel):
    """Credential-free plan for one exact three-role chain."""

    schema_version: Literal["autolean.ifem-source-free-deepseek-role-chain-plan.v1"] = (
        "autolean.ifem-source-free-deepseek-role-chain-plan.v1"
    )
    protocol: Literal["autolean.ifem-source-free-deepseek-role-chain.v1"] = (
        "autolean.ifem-source-free-deepseek-role-chain.v1"
    )
    artifact_kind: Literal["source_free_first_case_role_chain_plan"] = (
        "source_free_first_case_role_chain_plan"
    )
    profile_content_sha256: str = Field(pattern=_SHA256)
    queue_content_sha256: str = Field(pattern=_SHA256)
    policy_content_sha256: str = Field(pattern=_SHA256)
    provider_configuration_sha256: str = Field(pattern=_SHA256)
    role_prompt_contracts: tuple[SourceFreeDeepSeekRolePromptBindingV1, ...] = Field(
        min_length=3,
        max_length=3,
    )
    selected_case_count: Literal[1] = 1
    selected_coordinate_count: Literal[3] = 3
    outside_scope_coordinate_count: Literal[24] = 24
    maximum_authorized_provider_attempts: Literal[3] = 3
    max_attempts_per_stage: Literal[1] = 1
    per_stage_cost_bound_microusd: Literal[61_440] = 61_440
    aggregate_cost_bound_microusd: Literal[184_320] = 184_320
    contains_source_text: Literal[False] = False
    contains_lean_statement: Literal[False] = False
    heldout_isolation_claimed: Literal[False] = False
    semantic_calibration_claimed: Literal[False] = False
    authority: SourceFreeModelWorkAuthorityV1 = Field(
        default_factory=SourceFreeModelWorkAuthorityV1
    )
    builder_freeze: Literal["forbidden"] = "forbidden"
    prover_handoff: Literal["forbidden"] = "forbidden"
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_plan(self) -> Self:
        if tuple(item.role for item in self.role_prompt_contracts) != _ROLE_ORDER:
            raise ValueError("source-free role-chain prompt order drifted")
        if len({item.role for item in self.role_prompt_contracts}) != 3:
            raise ValueError("source-free role-chain prompt bindings are not independent entries")
        if self.aggregate_cost_bound_microusd != (
            self.selected_coordinate_count * self.per_stage_cost_bound_microusd
        ):
            raise ValueError("source-free role-chain aggregate cost bound drifted")
        if self.authority != SourceFreeModelWorkAuthorityV1():
            raise ValueError("source-free role-chain plan authority drifted")
        if self.content_sha256 != _sha256_json(self.content_payload()):
            raise ValueError("source-free role-chain plan hash drifted")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(
            dict[str, object],
            self.model_dump(mode="json", exclude={"content_sha256"}),
        )

    def freeze_statement(self) -> Never:
        raise SourceFreeDeepSeekRoleChainError(
            "source-free role-chain planning cannot freeze a Builder statement"
        )

    def handoff_to_prover(self) -> Never:
        raise SourceFreeDeepSeekRoleChainError(
            "source-free role-chain planning cannot hand work to Prover"
        )


class SourceFreeDeepSeekRoleChainPublicReportV1(ContractModel):
    """Aggregate-only result for the selected three coordinates."""

    schema_version: Literal["autolean.ifem-source-free-deepseek-role-chain-report.v1"] = (
        "autolean.ifem-source-free-deepseek-role-chain-report.v1"
    )
    protocol: Literal["autolean.ifem-source-free-deepseek-role-chain.v1"] = (
        "autolean.ifem-source-free-deepseek-role-chain.v1"
    )
    artifact_kind: Literal["source_free_first_case_role_chain_execution"] = (
        "source_free_first_case_role_chain_execution"
    )
    mode: RoleChainMode
    status: RoleChainStatus
    plan_content_sha256: str | None = Field(default=None, pattern=_SHA256)
    selected_case_count: Literal[1] = 1
    selected_coordinate_count: Literal[3] = 3
    outside_scope_coordinate_count: Literal[24] = 24
    maximum_authorized_provider_attempts: Literal[3] = 3
    max_attempts_per_stage: Literal[1] = 1
    aggregate_cost_bound_microusd: Literal[184_320] = 184_320
    runtime_evidence_available: bool = Field(strict=True)
    selected_pending_count: int | None = Field(default=None, ge=0, le=3, strict=True)
    selected_claimed_count: int | None = Field(default=None, ge=0, le=3, strict=True)
    selected_dispatch_started_count: int | None = Field(
        default=None,
        ge=0,
        le=3,
        strict=True,
    )
    selected_completion_committed_count: int | None = Field(
        default=None,
        ge=0,
        le=3,
        strict=True,
    )
    selected_reconciliation_required_count: int | None = Field(
        default=None,
        ge=0,
        le=3,
        strict=True,
    )
    outside_scope_pending_count: int | None = Field(default=None, ge=0, le=24, strict=True)
    attempt_binding_count: int | None = Field(default=None, ge=0, le=3, strict=True)
    completion_settlement_count: int | None = Field(default=None, ge=0, le=3, strict=True)
    private_completion_verified_count: int | None = Field(
        default=None,
        ge=0,
        le=3,
        strict=True,
    )
    all_selected_completions_verified: bool | None = Field(default=None, strict=True)
    private_stage_ledger_commitment_sha256: str | None = Field(default=None, pattern=_SHA256)
    private_attempt_binding_commitment_sha256: str | None = Field(
        default=None,
        pattern=_SHA256,
    )
    private_completion_binding_commitment_sha256: str | None = Field(
        default=None,
        pattern=_SHA256,
    )
    run_scope_binding_sha256: str | None = Field(default=None, pattern=_SHA256)
    actual_provider_dispatch_count_claimed: Literal[False] = False
    raw_response_disclosed: Literal[False] = False
    per_role_result_disclosed: Literal[False] = False
    per_case_result_disclosed: Literal[False] = False
    combined_score_claimed: Literal[False] = False
    model_identity_disclosed: Literal[False] = False
    machine_advisory_disposition: Literal["abstain"] = "abstain"
    authority: SourceFreeModelWorkAuthorityV1 = Field(
        default_factory=SourceFreeModelWorkAuthorityV1
    )
    builder_freeze: Literal["forbidden"] = "forbidden"
    prover_handoff: Literal["forbidden"] = "forbidden"
    failure_class: str | None = Field(default=None, pattern=_SAFE_FAILURE)
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_report(self) -> Self:
        state_counts = (
            self.selected_pending_count,
            self.selected_claimed_count,
            self.selected_dispatch_started_count,
            self.selected_completion_committed_count,
            self.selected_reconciliation_required_count,
        )
        evidence_counts = (
            self.attempt_binding_count,
            self.completion_settlement_count,
            self.private_completion_verified_count,
        )
        state_counts_present = all(value is not None for value in state_counts)
        evidence_counts_present = all(value is not None for value in evidence_counts)
        if any(value is not None for value in state_counts) != state_counts_present:
            raise ValueError("role-chain selected state counts are only partially available")
        if any(value is not None for value in evidence_counts) != evidence_counts_present:
            raise ValueError("role-chain evidence counts are only partially available")

        complete: bool | None = None
        if self.runtime_evidence_available:
            if self.status not in {"settled", "recovered", "reconciliation_required"}:
                raise ValueError("role-chain status cannot carry runtime evidence")
            if (
                not state_counts_present
                or not evidence_counts_present
                or self.outside_scope_pending_count is None
                or self.all_selected_completions_verified is None
                or self.private_stage_ledger_commitment_sha256 is None
                or self.run_scope_binding_sha256 is None
            ):
                raise ValueError("available role-chain runtime evidence is incomplete")
            selected_total = sum(cast(int, value) for value in state_counts)
            if selected_total != self.selected_coordinate_count:
                raise ValueError(
                    "source-free role-chain report does not account for three coordinates"
                )
            attempts = cast(int, self.attempt_binding_count)
            settlements = cast(int, self.completion_settlement_count)
            verified = cast(int, self.private_completion_verified_count)
            committed = cast(int, self.selected_completion_committed_count)
            reconciliation = cast(int, self.selected_reconciliation_required_count)
            if not (verified <= settlements <= attempts <= self.selected_coordinate_count):
                raise ValueError("source-free role-chain evidence counts are inconsistent")
            if committed > verified:
                raise ValueError("committed role-chain completion lacks private verification")
            if self.outside_scope_pending_count != self.outside_scope_coordinate_count:
                raise ValueError("outside-scope role-chain state is not entirely pending")
            if (self.private_attempt_binding_commitment_sha256 is None) is not (attempts == 0):
                raise ValueError("role-chain attempt commitment presence is inconsistent")
            if (self.private_completion_binding_commitment_sha256 is None) is not (verified == 0):
                raise ValueError("role-chain completion commitment presence is inconsistent")
            complete = (
                committed == self.selected_coordinate_count
                and verified == self.selected_coordinate_count
                and reconciliation == 0
            )
            if self.all_selected_completions_verified is not complete:
                raise ValueError("role-chain all-completion flag is inconsistent")
        elif self.status == "execution_refused":
            unavailable = (
                *state_counts,
                *evidence_counts,
                self.outside_scope_pending_count,
                self.all_selected_completions_verified,
                self.private_stage_ledger_commitment_sha256,
                self.private_attempt_binding_commitment_sha256,
                self.private_completion_binding_commitment_sha256,
                self.run_scope_binding_sha256,
            )
            if any(value is not None for value in unavailable):
                raise ValueError(
                    "refused role-chain report fabricates unavailable runtime evidence"
                )
        elif self.status in {"planned", "preflight_ready"}:
            if (
                state_counts != (3, 0, 0, 0, 0)
                or evidence_counts != (0, 0, 0)
                or self.outside_scope_pending_count != 24
                or self.all_selected_completions_verified is not False
                or self.private_stage_ledger_commitment_sha256 is not None
                or self.private_attempt_binding_commitment_sha256 is not None
                or self.private_completion_binding_commitment_sha256 is not None
                or self.run_scope_binding_sha256 is not None
            ):
                raise ValueError("credential-free role-chain report contains runtime evidence")
        else:
            raise ValueError("terminal role-chain status lacks runtime evidence")

        successful = self.status in {"planned", "preflight_ready", "settled", "recovered"}
        if successful != (self.failure_class is None):
            raise ValueError("source-free role-chain status and failure class disagree")
        expected_mode = {
            "planned": "plan",
            "preflight_ready": "preflight",
            "settled": "run",
            "recovered": "resume",
        }.get(self.status)
        if expected_mode is not None and self.mode != expected_mode:
            raise ValueError("source-free role-chain mode and status disagree")
        if self.status == "reconciliation_required" and self.mode not in {"run", "resume"}:
            raise ValueError("role-chain reconciliation uses an impossible mode")
        if successful and self.plan_content_sha256 is None:
            raise ValueError("successful role-chain report lacks its exact plan hash")
        if self.runtime_evidence_available and self.plan_content_sha256 is None:
            raise ValueError("runtime role-chain report lacks its exact plan hash")
        if self.status in {"settled", "recovered"} and complete is not True:
            raise ValueError("successful role-chain report lacks three verified completions")
        if self.status == "reconciliation_required" and complete is not False:
            raise ValueError("role-chain reconciliation cannot claim a complete chain")
        if self.authority != SourceFreeModelWorkAuthorityV1():
            raise ValueError("source-free role-chain report authority drifted")
        if self.content_sha256 != _sha256_json(self.content_payload()):
            raise ValueError("source-free role-chain report hash drifted")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(
            dict[str, object],
            self.model_dump(mode="json", exclude={"content_sha256"}),
        )

    def freeze_statement(self) -> Never:
        raise SourceFreeDeepSeekRoleChainError(
            "source-free role-chain execution cannot freeze a Builder statement"
        )

    def handoff_to_prover(self) -> Never:
        raise SourceFreeDeepSeekRoleChainError(
            "source-free role-chain execution cannot hand work to Prover"
        )


@dataclass(frozen=True, slots=True)
class SourceFreeDeepSeekRoleChainConfig:
    mode: RoleChainMode
    state_root: Path
    private_root: Path
    run_label: str = "ifem-source-free-deepseek-role-chain-v1"
    operator_approved: bool = False

    def __post_init__(self) -> None:
        if self.mode not in {"plan", "preflight", "run", "resume"}:
            raise SourceFreeDeepSeekRoleChainError("source-free role-chain mode is invalid")
        checked = single.SourceFreeDeepSeekOperatorConfig(
            mode=self.mode,
            state_root=self.state_root,
            private_root=self.private_root,
            run_label=self.run_label,
            operator_approved=self.operator_approved,
        )
        object.__setattr__(self, "state_root", checked.state_root)
        object.__setattr__(self, "private_root", checked.private_root)

    def single_config(self) -> single.SourceFreeDeepSeekOperatorConfig:
        return single.SourceFreeDeepSeekOperatorConfig(
            mode=self.mode,
            state_root=self.state_root,
            private_root=self.private_root,
            run_label=self.run_label,
            operator_approved=self.operator_approved,
        )


@dataclass(frozen=True, slots=True)
class _PreparedRoleChainPlan:
    public: SourceFreeDeepSeekRoleChainPlanV1
    runtime: single.SourceFreeDeepSeekPlan


@dataclass(frozen=True, slots=True)
class _RoleChainEvidence:
    selected_pending_count: int
    selected_claimed_count: int
    selected_dispatch_started_count: int
    selected_completion_committed_count: int
    selected_reconciliation_required_count: int
    attempt_binding_count: int
    completion_settlement_count: int
    private_completion_verified_count: int
    private_stage_ledger_commitment_sha256: str
    private_attempt_binding_commitment_sha256: str | None
    private_completion_binding_commitment_sha256: str | None
    run_scope_binding_sha256: str

    @property
    def complete(self) -> bool:
        return (
            self.selected_completion_committed_count == 3
            and self.private_completion_verified_count == 3
            and self.selected_reconciliation_required_count == 0
        )


@dataclass(frozen=True, slots=True)
class _ControlPlaneBindings:
    authorization_ids: tuple[str, ...]
    settlement_authorization_ids: tuple[str, ...]
    receipt_authorization_ids: tuple[str, ...]


def _sha256_json(payload: object) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _response_schema_sha256(role: ModelWorkRoleV1) -> str:
    if role is ModelWorkRoleV1.STATEMENT_FORMALIZER:
        schema = SourceFreeAuthoringResponseV1.model_json_schema(mode="validation")
    elif role is ModelWorkRoleV1.FIDELITY_REVIEWER:
        schema = SourceFreeReviewResponseV1.model_json_schema(mode="validation")
    elif role is ModelWorkRoleV1.CHEATING_SUPERVISOR:
        schema = SourceFreeSupervisorResponseV1.model_json_schema(mode="validation")
    else:
        raise SourceFreeDeepSeekRoleChainError("unsupported role-chain response schema")
    return _sha256_json(schema)


def build_source_free_deepseek_role_chain_plan() -> _PreparedRoleChainPlan:
    """Build the exact three-role plan without credentials, state roots, or provider I/O."""

    base = single.build_source_free_deepseek_plan()
    role_prompt_contracts = tuple(
        SourceFreeDeepSeekRolePromptBindingV1(
            role=role,
            prompt_contract_sha256=source_free_model_work_prompt_contract_sha256(role),
            response_schema_sha256=_response_schema_sha256(role),
        )
        for role in _ROLE_ORDER
    )
    if base.policy.max_cost_microusd != _PER_STAGE_COST_BOUND_MICROUSD:
        raise SourceFreeDeepSeekRoleChainError("per-stage cost bound drifted")
    payload: dict[str, object] = {
        "schema_version": "autolean.ifem-source-free-deepseek-role-chain-plan.v1",
        "protocol": "autolean.ifem-source-free-deepseek-role-chain.v1",
        "artifact_kind": "source_free_first_case_role_chain_plan",
        "profile_content_sha256": hashlib.sha256(base.profile_bytes).hexdigest(),
        "queue_content_sha256": base.queue.content_sha256,
        "policy_content_sha256": base.policy.content_hash(),
        "provider_configuration_sha256": base.provider_configuration_sha256,
        "role_prompt_contracts": [item.model_dump(mode="json") for item in role_prompt_contracts],
        "selected_case_count": 1,
        "selected_coordinate_count": 3,
        "outside_scope_coordinate_count": 24,
        "maximum_authorized_provider_attempts": 3,
        "max_attempts_per_stage": 1,
        "per_stage_cost_bound_microusd": _PER_STAGE_COST_BOUND_MICROUSD,
        "aggregate_cost_bound_microusd": _AGGREGATE_COST_BOUND_MICROUSD,
        "contains_source_text": False,
        "contains_lean_statement": False,
        "heldout_isolation_claimed": False,
        "semantic_calibration_claimed": False,
        "authority": SourceFreeModelWorkAuthorityV1().model_dump(mode="json"),
        "builder_freeze": "forbidden",
        "prover_handoff": "forbidden",
    }
    payload["content_sha256"] = _sha256_json(payload)
    public = SourceFreeDeepSeekRoleChainPlanV1.model_validate(payload)
    aggregate_prompt_contract_sha256 = _sha256_json(
        {
            "schema_version": "autolean.ifem-source-free-role-prompt-set.v1",
            "bindings": [item.model_dump(mode="json") for item in role_prompt_contracts],
        }
    )
    runtime = single.SourceFreeDeepSeekPlan(
        profile=base.profile,
        profile_bytes=base.profile_bytes,
        queue=base.queue,
        policy=base.policy,
        provider_configuration_sha256=base.provider_configuration_sha256,
        prompt_contract_sha256=aggregate_prompt_contract_sha256,
        content_sha256=public.content_sha256,
    )
    return _PreparedRoleChainPlan(public=public, runtime=runtime)


def _role_chain_coordinates(
    runtime: single._PreparedRuntime,
) -> tuple[SourceFreeStageCoordinateV1, ...]:
    first_case_id = runtime.ledger.run.coordinates[0].case_id
    coordinates = tuple(
        item for item in runtime.ledger.run.coordinates if item.case_id == first_case_id
    )
    if (
        len(coordinates) != 3
        or tuple(item.ordinal for item in coordinates) != (1, 2, 3)
        or tuple(item.role for item in coordinates) != _ROLE_ORDER
        or len({item.case_id for item in coordinates}) != 1
        or runtime.coordinate != coordinates[0]
        or runtime.seed_item.case_id != coordinates[0].case_id
    ):
        raise SourceFreeDeepSeekRoleChainError("first-case role-chain coordinates drifted")
    return coordinates


def _build_role_chain_scope_binding(
    runtime: single._PreparedRuntime,
    plan: _PreparedRoleChainPlan,
) -> SourceFreeDeepSeekRoleChainScopeBindingV1:
    coordinates = _role_chain_coordinates(runtime)
    stage_run = runtime.ledger.run
    if (
        runtime.plan != plan.runtime
        or plan.runtime.content_sha256 != plan.public.content_sha256
        or stage_run.private_seed_manifest_content_sha256
        != coordinates[0].private_seed_manifest_content_sha256
    ):
        raise SourceFreeDeepSeekRoleChainError("role-chain runtime differs from its public plan")
    coordinate_hashes = tuple(item.coordinate_sha256 for item in coordinates)
    payload: dict[str, object] = {
        "schema_version": "autolean.ifem-source-free-role-chain-scope-binding.v1",
        "protocol": "autolean.ifem-source-free-deepseek-role-chain.v1",
        "artifact_kind": "operator_private_source_free_role_chain_scope_binding",
        "plan_content_sha256": plan.public.content_sha256,
        "private_seed_manifest_content_sha256": (stage_run.private_seed_manifest_content_sha256),
        "private_stage_run_content_sha256": stage_run.run_content_sha256,
        "selection_rule": _SCOPE_SELECTION_RULE,
        "selected_coordinate_sha256s": coordinate_hashes,
        "selected_coordinate_commitment_sha256": _sha256_json(coordinate_hashes),
        "selected_case_count": 1,
        "selected_coordinate_count": 3,
        "outside_scope_coordinate_count": 24,
    }
    payload["content_sha256"] = _sha256_json(payload)
    return SourceFreeDeepSeekRoleChainScopeBindingV1.model_validate(payload)


def _persist_role_chain_scope_binding(
    config: SourceFreeDeepSeekRoleChainConfig,
    runtime: single._PreparedRuntime,
    plan: _PreparedRoleChainPlan,
) -> SourceFreeDeepSeekRoleChainScopeBindingV1:
    expected = _build_role_chain_scope_binding(runtime, plan)
    retained = single._write_private_once(
        config.state_root / _SCOPE_BINDING_FILENAME,
        expected.canonical_bytes(),
    )
    try:
        persisted = SourceFreeDeepSeekRoleChainScopeBindingV1.model_validate_json(retained)
    except ValueError as error:
        raise SourceFreeDeepSeekRoleChainScopeError(
            "role-chain scope binding is invalid"
        ) from error
    if persisted.canonical_bytes() != retained or persisted != expected:
        raise SourceFreeDeepSeekRoleChainScopeError(
            "role-chain scope binding differs from the selected private run"
        )
    return persisted


def _load_role_chain_scope_binding(
    config: SourceFreeDeepSeekRoleChainConfig,
    runtime: single._PreparedRuntime,
    plan: _PreparedRoleChainPlan,
) -> SourceFreeDeepSeekRoleChainScopeBindingV1:
    path = config.state_root / _SCOPE_BINDING_FILENAME
    try:
        single._require_private_regular_file(path)
        retained = path.read_bytes()
        persisted = SourceFreeDeepSeekRoleChainScopeBindingV1.model_validate_json(retained)
    except (OSError, ValueError) as error:
        raise SourceFreeDeepSeekRoleChainScopeError(
            "role-chain scope binding is unavailable"
        ) from error
    if persisted.canonical_bytes() != retained or persisted != _build_role_chain_scope_binding(
        runtime, plan
    ):
        raise SourceFreeDeepSeekRoleChainScopeError(
            "role-chain scope binding differs from the selected private run"
        )
    return persisted


def _outside_scope_is_pending(runtime: single._PreparedRuntime) -> bool:
    selected = {item.coordinate_sha256 for item in _role_chain_coordinates(runtime)}
    outside = tuple(
        item for item in runtime.ledger.run.coordinates if item.coordinate_sha256 not in selected
    )
    return len(outside) == 24 and all(
        runtime.ledger.state_for(coordinate) is SourceFreeStageLedgerStateV1.PENDING
        and runtime.attempt_store.load(coordinate) is None
        for coordinate in outside
    )


def _read_control_plane_bindings(database: Path) -> _ControlPlaneBindings:
    single._require_private_regular_file(database)
    try:
        uri = f"{database.resolve(strict=True).as_uri()}?mode=ro"
        with sqlite3.connect(uri, uri=True) as connection:
            authorization_ids = tuple(
                str(row[0])
                for row in connection.execute(
                    "SELECT authorization_id FROM model_execution_authorizations "
                    "ORDER BY authorization_id"
                ).fetchall()
            )
            settlement_authorization_ids = tuple(
                str(row[0])
                for row in connection.execute(
                    "SELECT authorization_id FROM model_execution_completion_settlements "
                    "ORDER BY authorization_id"
                ).fetchall()
            )
            receipt_authorization_ids = tuple(
                str(row[0])
                for row in connection.execute(
                    "SELECT COALESCE(settlements.authorization_id, '') "
                    "FROM model_execution_completion_receipts AS receipts "
                    "LEFT JOIN model_execution_completion_settlements AS settlements "
                    "ON settlements.reservation_id = receipts.reservation_id "
                    "ORDER BY COALESCE(settlements.authorization_id, '')"
                ).fetchall()
            )
    except (OSError, sqlite3.Error, TypeError, IndexError) as error:
        raise SourceFreeDeepSeekRoleChainError(
            "role-chain control-plane bindings are unavailable"
        ) from error
    return _ControlPlaneBindings(
        authorization_ids=authorization_ids,
        settlement_authorization_ids=settlement_authorization_ids,
        receipt_authorization_ids=receipt_authorization_ids,
    )


def _collect_role_chain_evidence(
    runtime: single._PreparedRuntime,
    coordinates: tuple[SourceFreeStageCoordinateV1, ...],
    *,
    config: SourceFreeDeepSeekRoleChainConfig,
    database: Path,
    plan: _PreparedRoleChainPlan,
) -> _RoleChainEvidence:
    _load_role_chain_scope_binding(config, runtime, plan)
    if not _outside_scope_is_pending(runtime):
        raise SourceFreeDeepSeekRoleChainError(
            "source-free role-chain touched an outside-scope coordinate"
        )
    attempt_hashes: list[str] = []
    attempt_authorization_ids: list[str] = []
    settlement_authorization_ids: list[str] = []
    completion_hashes: dict[str, str] = {}
    for coordinate in coordinates:
        attempt = runtime.attempt_store.load(coordinate)
        if attempt is None:
            continue
        attempt_hashes.append(attempt.content_sha256)
        authorization_id = attempt.authorization.authorization_id.value
        attempt_authorization_ids.append(authorization_id)
        try:
            handle = runtime.authorization_service.completion_recovery_handle_for_authorization(
                attempt.authorization
            )
        except Exception:
            handle = None
        if handle is None:
            continue
        settlement_authorization_ids.append(authorization_id)
        try:
            completion = runtime.sidecar.recover(coordinate)
            runtime.ledger.reconcile_completion(coordinate, completion)
        except Exception:
            continue
        completion_hashes[coordinate.coordinate_sha256] = completion.binding_content_sha256

    if not _outside_scope_is_pending(runtime):
        raise SourceFreeDeepSeekRoleChainError(
            "source-free role-chain recovery touched an outside-scope coordinate"
        )
    states = tuple(runtime.ledger.state_for(coordinate) for coordinate in coordinates)
    counts = Counter(states)
    projection = runtime.ledger.public_projection()
    if projection.pending_count < _OUTSIDE_SCOPE_COORDINATE_COUNT:
        raise SourceFreeDeepSeekRoleChainError("role-chain ledger projection escaped its scope")
    control_plane = _read_control_plane_bindings(database)
    selected_authorizations = tuple(sorted(attempt_authorization_ids))
    selected_settlements = tuple(sorted(settlement_authorization_ids))
    if control_plane.authorization_ids != selected_authorizations:
        raise SourceFreeDeepSeekRoleChainError(
            "role-chain control plane contains an authorization outside selected attempts"
        )
    if control_plane.settlement_authorization_ids != selected_settlements:
        raise SourceFreeDeepSeekRoleChainError(
            "role-chain control plane contains a settlement outside selected attempts"
        )
    selected_authorization_set = set(selected_authorizations)
    if (
        len(control_plane.receipt_authorization_ids)
        > len(control_plane.settlement_authorization_ids)
        or not set(control_plane.receipt_authorization_ids).issubset(selected_authorization_set)
        or len(control_plane.receipt_authorization_ids) < len(completion_hashes)
    ):
        raise SourceFreeDeepSeekRoleChainError(
            "role-chain control plane contains an invalid completion-receipt binding"
        )
    scope_binding = _load_role_chain_scope_binding(config, runtime, plan)
    return _RoleChainEvidence(
        selected_pending_count=counts[SourceFreeStageLedgerStateV1.PENDING],
        selected_claimed_count=counts[SourceFreeStageLedgerStateV1.CLAIMED],
        selected_dispatch_started_count=counts[SourceFreeStageLedgerStateV1.DISPATCH_STARTED],
        selected_completion_committed_count=counts[
            SourceFreeStageLedgerStateV1.COMPLETION_COMMITTED
        ],
        selected_reconciliation_required_count=counts[
            SourceFreeStageLedgerStateV1.RECONCILIATION_REQUIRED
        ],
        attempt_binding_count=len(attempt_hashes),
        completion_settlement_count=len(settlement_authorization_ids),
        private_completion_verified_count=len(completion_hashes),
        private_stage_ledger_commitment_sha256=projection.private_ledger_commitment_sha256,
        private_attempt_binding_commitment_sha256=(
            _sha256_json(tuple(sorted(attempt_hashes))) if attempt_hashes else None
        ),
        private_completion_binding_commitment_sha256=(
            _sha256_json(tuple(sorted(completion_hashes.values()))) if completion_hashes else None
        ),
        run_scope_binding_sha256=scope_binding.content_sha256,
    )


def _report(
    mode: RoleChainMode,
    status: RoleChainStatus,
    *,
    plan: _PreparedRoleChainPlan | None,
    evidence: _RoleChainEvidence | None = None,
    failure_class: str | None = None,
) -> SourceFreeDeepSeekRoleChainPublicReportV1:
    planned_state = evidence is None and status in {"planned", "preflight_ready"}
    runtime_evidence_available = evidence is not None
    payload: dict[str, object] = {
        "schema_version": "autolean.ifem-source-free-deepseek-role-chain-report.v1",
        "protocol": "autolean.ifem-source-free-deepseek-role-chain.v1",
        "artifact_kind": "source_free_first_case_role_chain_execution",
        "mode": mode,
        "status": status,
        "plan_content_sha256": None if plan is None else plan.public.content_sha256,
        "selected_case_count": 1,
        "selected_coordinate_count": 3,
        "outside_scope_coordinate_count": 24,
        "maximum_authorized_provider_attempts": 3,
        "max_attempts_per_stage": 1,
        "aggregate_cost_bound_microusd": _AGGREGATE_COST_BOUND_MICROUSD,
        "runtime_evidence_available": runtime_evidence_available,
        "selected_pending_count": (
            evidence.selected_pending_count
            if evidence is not None
            else 3
            if planned_state
            else None
        ),
        "selected_claimed_count": (
            evidence.selected_claimed_count
            if evidence is not None
            else 0
            if planned_state
            else None
        ),
        "selected_dispatch_started_count": (
            evidence.selected_dispatch_started_count
            if evidence is not None
            else 0
            if planned_state
            else None
        ),
        "selected_completion_committed_count": (
            evidence.selected_completion_committed_count
            if evidence is not None
            else 0
            if planned_state
            else None
        ),
        "selected_reconciliation_required_count": (
            evidence.selected_reconciliation_required_count
            if evidence is not None
            else 0
            if planned_state
            else None
        ),
        "outside_scope_pending_count": (24 if evidence is not None or planned_state else None),
        "attempt_binding_count": (
            evidence.attempt_binding_count if evidence is not None else 0 if planned_state else None
        ),
        "completion_settlement_count": (
            evidence.completion_settlement_count
            if evidence is not None
            else 0
            if planned_state
            else None
        ),
        "private_completion_verified_count": (
            evidence.private_completion_verified_count
            if evidence is not None
            else 0
            if planned_state
            else None
        ),
        "all_selected_completions_verified": (
            evidence.complete if evidence is not None else False if planned_state else None
        ),
        "private_stage_ledger_commitment_sha256": (
            None if evidence is None else evidence.private_stage_ledger_commitment_sha256
        ),
        "private_attempt_binding_commitment_sha256": (
            None if evidence is None else evidence.private_attempt_binding_commitment_sha256
        ),
        "private_completion_binding_commitment_sha256": (
            None if evidence is None else evidence.private_completion_binding_commitment_sha256
        ),
        "run_scope_binding_sha256": (
            None if evidence is None else evidence.run_scope_binding_sha256
        ),
        "actual_provider_dispatch_count_claimed": False,
        "raw_response_disclosed": False,
        "per_role_result_disclosed": False,
        "per_case_result_disclosed": False,
        "combined_score_claimed": False,
        "model_identity_disclosed": False,
        "machine_advisory_disposition": "abstain",
        "authority": SourceFreeModelWorkAuthorityV1().model_dump(mode="json"),
        "builder_freeze": "forbidden",
        "prover_handoff": "forbidden",
        "failure_class": failure_class,
    }
    payload["content_sha256"] = _sha256_json(payload)
    return SourceFreeDeepSeekRoleChainPublicReportV1.model_validate(payload)


def _failure_for_evidence(
    runtime: single._PreparedRuntime,
    evidence: _RoleChainEvidence,
) -> str:
    if evidence.completion_settlement_count > evidence.private_completion_verified_count:
        return "settled_completion_rejected"
    diagnostic = runtime.diagnostic_transport
    if diagnostic is not None and diagnostic.failure_class not in {None, "http_ok"}:
        return cast(str, diagnostic.failure_class)
    return "private_reconciliation_required"


def _failure_class(error: BaseException) -> str:
    if isinstance(error, SourceFreeDeepSeekRoleChainScopeError):
        return "private_state_unavailable"
    return single._failure_class(error)


def _run_role_chain(
    config: SourceFreeDeepSeekRoleChainConfig,
    runtime: single._PreparedRuntime,
    plan: _PreparedRoleChainPlan,
    *,
    database: Path,
) -> SourceFreeDeepSeekRoleChainPublicReportV1:
    def execute_with_verified_scope(
        coordinate: SourceFreeStageCoordinateV1,
        item: PrivateSourceFreeSeedItemV2,
    ) -> SourceFreeStageCompletionBindingV1:
        _load_role_chain_scope_binding(config, runtime, plan)
        return runtime.sidecar.execute_once(coordinate, item)

    coordinates = _role_chain_coordinates(runtime)
    for coordinate in coordinates:
        runtime.ledger.execute_coordinate(coordinate, execute_with_verified_scope)
        if runtime.ledger.state_for(coordinate) is not (
            SourceFreeStageLedgerStateV1.COMPLETION_COMMITTED
        ):
            break
    evidence = _collect_role_chain_evidence(
        runtime,
        coordinates,
        config=config,
        database=database,
        plan=plan,
    )
    if evidence.complete:
        return _report("run", "settled", plan=plan, evidence=evidence)
    return _report(
        "run",
        "reconciliation_required",
        plan=plan,
        evidence=evidence,
        failure_class=_failure_for_evidence(runtime, evidence),
    )


def _resume_role_chain(
    config: SourceFreeDeepSeekRoleChainConfig,
    runtime: single._PreparedRuntime,
    plan: _PreparedRoleChainPlan,
    *,
    database: Path,
) -> SourceFreeDeepSeekRoleChainPublicReportV1:
    coordinates = _role_chain_coordinates(runtime)
    for coordinate in coordinates:
        state = runtime.ledger.state_for(coordinate)
        if state not in {
            SourceFreeStageLedgerStateV1.DISPATCH_STARTED,
            SourceFreeStageLedgerStateV1.RECONCILIATION_REQUIRED,
            SourceFreeStageLedgerStateV1.COMPLETION_COMMITTED,
        }:
            continue
        try:
            _load_role_chain_scope_binding(config, runtime, plan)
            completion = runtime.sidecar.recover(coordinate)
            runtime.ledger.reconcile_completion(coordinate, completion)
        except SourceFreeDeepSeekRoleChainScopeError:
            raise
        except Exception:
            continue
    evidence = _collect_role_chain_evidence(
        runtime,
        coordinates,
        config=config,
        database=database,
        plan=plan,
    )
    if evidence.complete:
        return _report("resume", "recovered", plan=plan, evidence=evidence)
    return _report(
        "resume",
        "reconciliation_required",
        plan=plan,
        evidence=evidence,
        failure_class=_failure_for_evidence(runtime, evidence),
    )


def execute_source_free_deepseek_role_chain(
    config: SourceFreeDeepSeekRoleChainConfig,
    *,
    environment: Mapping[str, str] | None = None,
    transport: ResponsesTransport | None = None,
) -> SourceFreeDeepSeekRoleChainPublicReportV1:
    """Execute one explicit mode; only ``run`` may resolve a provider credential."""

    if type(config) is not SourceFreeDeepSeekRoleChainConfig:
        raise SourceFreeDeepSeekRoleChainError("role-chain execution requires its exact config")
    if config.mode not in {"plan", "preflight", "run", "resume"}:
        raise SourceFreeDeepSeekRoleChainError("source-free role-chain mode is invalid")
    plan: _PreparedRoleChainPlan | None = None
    try:
        plan = build_source_free_deepseek_role_chain_plan()
        if config.mode == "plan":
            return _report("plan", "planned", plan=plan)
        if config.mode == "preflight":
            return _report("preflight", "preflight_ready", plan=plan)
        if config.mode == "run":
            if config.operator_approved is not True:
                raise single.OperatorApprovalRequired("explicit operator approval is required")
            runtime = single._prepare_runtime(
                config.single_config(),
                plan.runtime,
                mode="run",
                environment=os.environ if environment is None else environment,
                transport=transport,
            )
            _persist_role_chain_scope_binding(config, runtime, plan)
            return _run_role_chain(
                config,
                runtime,
                plan,
                database=config.state_root / "control-plane.sqlite3",
            )
        if config.mode == "resume":
            runtime = single._prepare_runtime(
                config.single_config(),
                plan.runtime,
                mode="resume",
                environment={},
                transport=None,
            )
            _load_role_chain_scope_binding(config, runtime, plan)
            return _resume_role_chain(
                config,
                runtime,
                plan,
                database=config.state_root / "control-plane.sqlite3",
            )
        raise SourceFreeDeepSeekRoleChainError("source-free role-chain mode is invalid")
    except Exception as error:
        return _report(
            config.mode,
            "execution_refused",
            plan=plan,
            failure_class=_failure_class(error),
        )


def render_source_free_deepseek_role_chain_report(
    report: SourceFreeDeepSeekRoleChainPublicReportV1,
) -> bytes:
    if type(report) is not SourceFreeDeepSeekRoleChainPublicReportV1:
        raise SourceFreeDeepSeekRoleChainError("role-chain report requires its exact type")
    value = SourceFreeDeepSeekRoleChainPublicReportV1.model_validate(report.model_dump(mode="json"))
    rendered = canonical_json_bytes(value.model_dump(mode="json")) + b"\n"
    if any(field in rendered for field in _FORBIDDEN_PUBLIC_FIELDS):
        raise SourceFreeDeepSeekRoleChainError("role-chain report leaked private operator data")
    return rendered


class _RedactedArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        del message
        raise SourceFreeDeepSeekRoleChainError("invalid CLI arguments")


def _parser() -> argparse.ArgumentParser:
    parser = _RedactedArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "preflight", "run", "resume"))
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--private-root", type=Path, required=True)
    parser.add_argument("--run-label", default="ifem-source-free-deepseek-role-chain-v1")
    parser.add_argument("--operator-approved", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    mode: RoleChainMode = "plan"
    try:
        arguments = _parser().parse_args(argv)
        mode = cast(RoleChainMode, arguments.mode)
        config = SourceFreeDeepSeekRoleChainConfig(
            mode=mode,
            state_root=arguments.state_root,
            private_root=arguments.private_root,
            run_label=arguments.run_label,
            operator_approved=arguments.operator_approved,
        )
        report = execute_source_free_deepseek_role_chain(config)
    except Exception as error:
        report = _report(
            mode,
            "execution_refused",
            plan=None,
            failure_class=single._failure_class(error),
        )
    print(render_source_free_deepseek_role_chain_report(report).decode("ascii"), end="")
    return 0 if report.status in {"planned", "preflight_ready", "settled", "recovered"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
