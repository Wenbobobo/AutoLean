"""Versioned, role-aware benchmark contracts and an offline execution harness.

The default harness deliberately knows only a scripted fake executor.  External model execution
must be supplied by a separate operator adapter that preserves the control-plane authorization,
lease, ContextPack, and provider-registry boundaries.  Benchmark reports contain hashes and
accounting metadata, never case inputs, oracle values, or raw model outputs.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sqlite3
import time
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Protocol, Self

from autolean_contracts import ContractModel, canonical_json_bytes
from autolean_control_plane import ArtifactStore
from autolean_prover.providers import Capability
from pydantic import Field, field_validator, model_validator

if TYPE_CHECKING:
    from benchmarks.provider_readiness import RoleBenchmarkReadinessReportV1

_IDENTIFIER_PATTERN = r"^[a-z0-9][a-z0-9_.:/-]{0,127}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_ONE_MILLION = 1_000_000
_STORE_SCHEMA_VERSION = "autolean.role-benchmark-store.v3"
_STORE_PRAGMA_POLICY = {
    "busy_timeout": 30_000,
    "foreign_keys": 1,
    "journal_mode": "wal",
    "synchronous": 2,
    "trusted_schema": 0,
}
_SCRIPTED_FAKE_EXECUTOR_ID: Literal["autolean.scripted-fake.v1"] = "autolean.scripted-fake.v1"
_SCRIPTED_FAKE_COMMITMENT_SCHEME: Literal["sha256-canonical-json-scripted-fake-v1"] = (
    "sha256-canonical-json-scripted-fake-v1"
)
_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_OPERATOR_PRIVATE_ROOT_ENV = "AUTOLEAN_BENCHMARK_PRIVATE_ROOT"


class RoleBenchmarkError(ValueError):
    """A benchmark contract, result, or comparison is invalid."""


class RoleBenchmarkStoreError(RuntimeError):
    """The append-only benchmark store is incomplete, corrupt, or conflicted."""


class RoleBenchmarkTrialBusy(RoleBenchmarkStoreError):
    """Another worker currently owns this trial coordinate."""


class RoleBenchmarkTrialIndeterminate(RoleBenchmarkStoreError):
    """A prior executor call may have started and cannot be retried safely."""


class BenchmarkRoleV1(StrEnum):
    """Initial roles whose behavior needs independent measurement."""

    PROVER = "prover"
    STATEMENT_FORMALIZER = "statement_formalizer"
    FIDELITY_REVIEWER = "fidelity_reviewer"
    CHEATING_SUPERVISOR = "cheating_supervisor"
    TASK_ALLOCATOR = "task_allocator"


class RoleExecutionClassV1(StrEnum):
    """Machine-readable execution provenance.

    V3 intentionally supports only the local scripted fixture. External execution remains
    unrepresentable until an authorization receipt and keyed raw-output commitment exist.
    """

    SCRIPTED_FAKE = "scripted_fake"


class RoleBenchmarkExecutorDescriptorV1(ContractModel):
    """Typed identity for the only executor admitted by the V3 harness."""

    schema_version: Literal["autolean.role-executor-descriptor.v1"] = (
        "autolean.role-executor-descriptor.v1"
    )
    execution_class: Literal[RoleExecutionClassV1.SCRIPTED_FAKE] = (
        RoleExecutionClassV1.SCRIPTED_FAKE
    )
    executor_id: Literal["autolean.scripted-fake.v1"] = _SCRIPTED_FAKE_EXECUTOR_ID
    raw_output_commitment_scheme: Literal["sha256-canonical-json-scripted-fake-v1"] = (
        _SCRIPTED_FAKE_COMMITMENT_SCHEME
    )
    authority_receipt_hash: None = None


class RoleBenchmarkPreflightBindingV1(ContractModel):
    """Capability evidence binding, explicitly not an execution authorization."""

    schema_version: Literal["autolean.role-preflight-binding.v1"] = (
        "autolean.role-preflight-binding.v1"
    )
    matrix_hash: str = Field(pattern=_SHA256_PATTERN)
    provider_readiness_hash: str = Field(pattern=_SHA256_PATTERN)
    executor_descriptor_hash: str = Field(pattern=_SHA256_PATTERN)
    execution_class: Literal[RoleExecutionClassV1.SCRIPTED_FAKE] = (
        RoleExecutionClassV1.SCRIPTED_FAKE
    )
    authority_granted: Literal[False] = False


class RoleArtifactRefV1(ContractModel):
    """A content-addressed tool or retrieval artifact, without embedding its contents."""

    schema_version: Literal["autolean.role-artifact-ref.v1"] = "autolean.role-artifact-ref.v1"
    artifact_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    revision: str = Field(min_length=1, max_length=128)
    content_hash: str = Field(pattern=_SHA256_PATTERN)


class RolePromptSpecV1(ContractModel):
    """A fixed prompt recipe; case input is appended through one canonical renderer."""

    schema_version: Literal["autolean.role-prompt.v1"] = "autolean.role-prompt.v1"
    prompt_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    revision: str = Field(min_length=1, max_length=128)
    system_prompt: str = Field(min_length=1, max_length=32_768)
    instruction: str = Field(min_length=1, max_length=65_536)
    renderer_version: Literal["canonical-json-v1"] = "canonical-json-v1"


class RoleModelTargetV1(ContractModel):
    """Credential-free model identity recorded by a benchmark cell."""

    schema_version: Literal["autolean.role-model-target.v1"] = "autolean.role-model-target.v1"
    provider_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    model_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    model_revision: str = Field(min_length=1, max_length=128)
    provider_configuration_hash: str = Field(pattern=_SHA256_PATTERN)
    generation_parameters_hash: str = Field(pattern=_SHA256_PATTERN)


class RoleBudgetV1(ContractModel):
    """Fixed per-trial and repetition limits."""

    schema_version: Literal["autolean.role-budget.v1"] = "autolean.role-budget.v1"
    repetitions: int = Field(ge=1, le=100)
    max_input_tokens: int = Field(ge=1, le=10_000_000)
    max_output_tokens: int = Field(ge=1, le=10_000_000)
    timeout_ms: int = Field(ge=1, le=86_400_000)
    max_cost_microusd: int = Field(ge=0)


class RoleBenchmarkCaseV1(ContractModel):
    """One role-specific case with an evaluator-owned exact JSON oracle."""

    schema_version: Literal["autolean.role-benchmark-case.v1"] = "autolean.role-benchmark-case.v1"
    case_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    role: BenchmarkRoleV1
    case_revision: str = Field(min_length=1, max_length=128)
    input_payload: object
    expected_output: object
    scorer: Literal["exact_json_v1"] = "exact_json_v1"
    tags: tuple[str, ...] = ()

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("case tags must be unique")
        if any(not item or item != item.strip() or len(item) > 64 for item in value):
            raise ValueError("case tags must be trimmed strings of at most 64 characters")
        return value

    @field_validator("input_payload", "expected_output")
    @classmethod
    def validate_json_fields(cls, value: object) -> object:
        return _validate_json_value(value, label="benchmark case payload")


class RoleBenchmarkCellV1(ContractModel):
    """One controlled role/model/protocol experiment cell."""

    schema_version: Literal["autolean.role-benchmark-cell.v3"] = "autolean.role-benchmark-cell.v3"
    cell_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    role: BenchmarkRoleV1
    model: RoleModelTargetV1
    prompt: RolePromptSpecV1
    tools: tuple[RoleArtifactRefV1, ...] = ()
    retrieval_scope: tuple[RoleArtifactRefV1, ...] = ()
    required_capabilities: tuple[Capability, ...] = (
        Capability.TEXT_GENERATION,
        Capability.USAGE_ACCOUNTING,
    )
    budget: RoleBudgetV1
    code_revision_hash: str = Field(pattern=_SHA256_PATTERN)
    environment_hash: str = Field(pattern=_SHA256_PATTERN)
    case_ids: tuple[str, ...]
    sample_size: int = Field(ge=1)

    @model_validator(mode="after")
    def validate_case_selection(self) -> Self:
        if not self.case_ids or len(set(self.case_ids)) != len(self.case_ids):
            raise ValueError("cell case_ids must be non-empty and unique")
        if self.sample_size > len(self.case_ids):
            raise ValueError("cell sample_size cannot exceed its eligible case count")
        for collection, label in (
            (self.tools, "tools"),
            (self.retrieval_scope, "retrieval_scope"),
        ):
            identities = tuple(item.artifact_id for item in collection)
            if len(set(identities)) != len(identities):
                raise ValueError(f"cell {label} artifact IDs must be unique")
        if (
            tuple(sorted(set(self.required_capabilities), key=str)) != self.required_capabilities
            or Capability.TEXT_GENERATION not in self.required_capabilities
            or Capability.USAGE_ACCOUNTING not in self.required_capabilities
        ):
            raise ValueError(
                "cell capabilities must be sorted, unique, and include text generation and "
                "usage accounting"
            )
        if self.tools and Capability.TOOL_CALLING not in self.required_capabilities:
            raise ValueError("a cell with native tools must require tool_calling")
        return self


class RoleBenchmarkMatrixV1(ContractModel):
    """A frozen set of cases and controlled experiment cells."""

    schema_version: Literal["autolean.role-benchmark-matrix.v3"] = (
        "autolean.role-benchmark-matrix.v3"
    )
    matrix_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    matrix_revision: str = Field(min_length=1, max_length=128)
    sampling_seed: str = Field(min_length=1, max_length=256)
    cases: tuple[RoleBenchmarkCaseV1, ...]
    cells: tuple[RoleBenchmarkCellV1, ...]

    @model_validator(mode="after")
    def validate_matrix_links(self) -> Self:
        case_by_id = {case.case_id: case for case in self.cases}
        if not case_by_id or len(case_by_id) != len(self.cases):
            raise ValueError("matrix case IDs must be non-empty and unique")
        if not self.cells or len({cell.cell_id for cell in self.cells}) != len(self.cells):
            raise ValueError("matrix cell IDs must be non-empty and unique")
        for cell in self.cells:
            for case_id in cell.case_ids:
                case = case_by_id.get(case_id)
                if case is None:
                    raise ValueError(f"cell references unknown case: {case_id}")
                if case.role is not cell.role:
                    raise ValueError("cell cannot include a case owned by another role")
        return self

    def content_hash(self) -> str:
        return _content_hash(self)


def _content_hash(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _run_cell_binding_hash(payload: Mapping[str, object]) -> str:
    body = dict(payload)
    body.pop("run_cell_binding_hash", None)
    return _content_hash(
        {
            "schema_version": "autolean.role-run-cell-binding.v3",
            "run_cell": body,
        }
    )


def _trial_result_commitment_hash(payload: Mapping[str, object]) -> str:
    body = dict(payload)
    body.pop("result_commitment_hash", None)
    return _content_hash(
        {
            "schema_version": "autolean.role-trial-result-commitment.v3",
            "trial_result": body,
        }
    )


def scripted_fake_executor_descriptor() -> RoleBenchmarkExecutorDescriptorV1:
    """Return the one execution descriptor admitted by the V3 harness."""

    return RoleBenchmarkExecutorDescriptorV1()


def _validate_json_value(value: object, *, label: str) -> object:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{label} cannot contain non-finite numbers")
        return value
    if isinstance(value, (list, tuple)):
        for item in value:
            _validate_json_value(item, label=label)
        return value
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise ValueError(f"{label} object keys must be strings")
        for item in value.values():
            _validate_json_value(item, label=label)
        return value
    raise ValueError(f"{label} must contain JSON values only")


def _canonical_text(value: object) -> str:
    return canonical_json_bytes(value).decode("ascii")


def _parse_canonical_model[ModelT: ContractModel](
    model_type: type[ModelT],
    payload: str,
) -> ModelT:
    try:
        model = model_type.model_validate_json(payload)
    except ValueError as error:
        raise RoleBenchmarkStoreError("stored benchmark JSON failed schema validation") from error
    if _canonical_text(model) != payload:
        raise RoleBenchmarkStoreError("stored benchmark JSON is not canonical")
    return model


def stable_case_selection(
    matrix: RoleBenchmarkMatrixV1,
    cell: RoleBenchmarkCellV1,
) -> tuple[str, ...]:
    """Select cases without source ordering, global RNG state, or cell/model identity."""

    def key(case_id: str) -> bytes:
        payload = (
            "autolean.role-benchmark-sampling.v1"
            f"\0{matrix.sampling_seed}\0{cell.role.value}\0{case_id}"
        ).encode()
        return hashlib.sha256(payload).digest()

    return tuple(sorted(sorted(cell.case_ids, key=key)[: cell.sample_size]))


def _refs_hash(values: tuple[RoleArtifactRefV1, ...], *, domain: str) -> str:
    return _content_hash(
        {
            "schema_version": domain,
            "artifacts": [item.model_dump(mode="json") for item in values],
        }
    )


def _render_prompt(
    case: RoleBenchmarkCaseV1,
    cell: RoleBenchmarkCellV1,
) -> tuple[str, str]:
    input_json = _canonical_text(
        {
            "schema_version": "autolean.role-work-input.v1",
            "role": case.role.value,
            "case_id": case.case_id,
            "case_revision": case.case_revision,
            "input": case.input_payload,
        }
    )
    prompt = f"{cell.prompt.instruction.rstrip()}\n\nINPUT_JSON\n{input_json}"
    return cell.prompt.system_prompt, prompt


class RoleBenchmarkTrialBindingV1(ContractModel):
    """One deterministic repetition coordinate derived from the matrix seed."""

    schema_version: Literal["autolean.role-trial-binding.v3"] = "autolean.role-trial-binding.v3"
    repetition: int = Field(ge=1, le=100)
    trial_seed: str = Field(pattern=_SHA256_PATTERN)
    work_item_hash: str = Field(pattern=_SHA256_PATTERN)


class RoleBenchmarkCaseBindingV1(ContractModel):
    """Answer-free case identity persisted in a run manifest."""

    schema_version: Literal["autolean.role-case-binding.v3"] = "autolean.role-case-binding.v3"
    case_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    case_revision: str = Field(min_length=1, max_length=128)
    case_contract_hash: str = Field(pattern=_SHA256_PATTERN)
    work_item_hash: str = Field(pattern=_SHA256_PATTERN)
    evaluator_kind: Literal["exact_json_v1"] = "exact_json_v1"
    evaluator_hash: str = Field(pattern=_SHA256_PATTERN)
    trials: tuple[RoleBenchmarkTrialBindingV1, ...]

    @model_validator(mode="after")
    def validate_trials(self) -> Self:
        repetitions = tuple(item.repetition for item in self.trials)
        if not repetitions or repetitions != tuple(range(1, len(repetitions) + 1)):
            raise ValueError("case trial bindings must be consecutive and start at one")
        return self


class RoleBenchmarkRunCellV1(ContractModel):
    """Exact immutable snapshot of one selected experiment cell."""

    schema_version: Literal["autolean.role-run-cell.v3"] = "autolean.role-run-cell.v3"
    run_cell_binding_hash: str = Field(pattern=_SHA256_PATTERN)
    cell_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    role: BenchmarkRoleV1
    cell_contract_hash: str = Field(pattern=_SHA256_PATTERN)
    model: RoleModelTargetV1
    prompt_hash: str = Field(pattern=_SHA256_PATTERN)
    tools_hash: str = Field(pattern=_SHA256_PATTERN)
    retrieval_scope_hash: str = Field(pattern=_SHA256_PATTERN)
    capabilities_hash: str = Field(pattern=_SHA256_PATTERN)
    budget_hash: str = Field(pattern=_SHA256_PATTERN)
    code_revision_hash: str = Field(pattern=_SHA256_PATTERN)
    environment_hash: str = Field(pattern=_SHA256_PATTERN)
    repetitions: int = Field(ge=1, le=100)
    selected_cases: tuple[RoleBenchmarkCaseBindingV1, ...]

    @model_validator(mode="after")
    def validate_selected_cases(self) -> Self:
        case_ids = tuple(case.case_id for case in self.selected_cases)
        if not case_ids or case_ids != tuple(sorted(set(case_ids))):
            raise ValueError("run-cell selected cases must be non-empty, unique, and sorted")
        if any(len(case.trials) != self.repetitions for case in self.selected_cases):
            raise ValueError("run-cell case trial schedules must match repetitions")
        if self.run_cell_binding_hash != _run_cell_binding_hash(self.model_dump(mode="json")):
            raise ValueError("run-cell binding hash does not match its complete V3 payload")
        return self


class RoleBenchmarkRunV1(ContractModel):
    """A repeatable run manifest containing no case input or oracle values."""

    schema_version: Literal["autolean.role-benchmark-run.v3"] = "autolean.role-benchmark-run.v3"
    run_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    matrix_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    matrix_revision: str = Field(min_length=1, max_length=128)
    matrix_hash: str = Field(pattern=_SHA256_PATTERN)
    sampling_seed_hash: str = Field(pattern=_SHA256_PATTERN)
    provider_readiness_hash: str = Field(pattern=_SHA256_PATTERN)
    execution_class: Literal[RoleExecutionClassV1.SCRIPTED_FAKE] = (
        RoleExecutionClassV1.SCRIPTED_FAKE
    )
    executor_descriptor_hash: str = Field(pattern=_SHA256_PATTERN)
    raw_output_commitment_scheme: Literal["sha256-canonical-json-scripted-fake-v1"] = (
        _SCRIPTED_FAKE_COMMITMENT_SCHEME
    )
    authority_granted: Literal[False] = False
    cells: tuple[RoleBenchmarkRunCellV1, ...]

    @model_validator(mode="after")
    def validate_unique_cells(self) -> Self:
        cell_ids = tuple(cell.cell_id for cell in self.cells)
        if not cell_ids or cell_ids != tuple(sorted(set(cell_ids))):
            raise ValueError("run cells must be non-empty, unique, and sorted")
        if any(cell.model.provider_id != "fake" for cell in self.cells):
            raise ValueError("scripted-fake V3 runs require provider_id 'fake' in every cell")
        return self


def derive_trial_seed(
    matrix: RoleBenchmarkMatrixV1,
    cell: RoleBenchmarkCellV1,
    *,
    case_id: str,
    repetition: int,
) -> str:
    """Derive one stable repetition seed without using process-global RNG state."""

    if case_id not in cell.case_ids:
        raise RoleBenchmarkError("trial seed case is not eligible for the cell")
    if repetition < 1 or repetition > cell.budget.repetitions:
        raise RoleBenchmarkError("trial seed repetition is outside the frozen budget")
    payload = (
        "autolean.role-benchmark-trial-seed.v1"
        f"\0{matrix.sampling_seed}\0{cell.role.value}\0{case_id}\0{repetition}"
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def _trial_work_item_hash(
    *,
    base_work_item_hash: str,
    repetition: int,
    trial_seed: str,
) -> str:
    return _content_hash(
        {
            "schema_version": "autolean.role-trial-work-item.v3",
            "base_work_item_hash": base_work_item_hash,
            "repetition": repetition,
            "trial_seed": trial_seed,
        }
    )


def build_run_manifest(
    matrix: RoleBenchmarkMatrixV1,
    *,
    run_id: str,
    preflight: RoleBenchmarkPreflightBindingV1,
    executor_descriptor: RoleBenchmarkExecutorDescriptorV1,
) -> RoleBenchmarkRunV1:
    try:
        matrix = RoleBenchmarkMatrixV1.model_validate(matrix.model_dump(mode="json"))
        preflight = RoleBenchmarkPreflightBindingV1.model_validate(
            preflight.model_dump(mode="json")
        )
        executor_descriptor = RoleBenchmarkExecutorDescriptorV1.model_validate(
            executor_descriptor.model_dump(mode="json")
        )
    except (AttributeError, ValueError) as error:
        raise RoleBenchmarkError("benchmark execution contracts are not valid V3 values") from error
    matrix_hash = matrix.content_hash()
    descriptor_hash = _content_hash(executor_descriptor)
    if (
        preflight.matrix_hash != matrix_hash
        or preflight.executor_descriptor_hash != descriptor_hash
        or preflight.execution_class is not executor_descriptor.execution_class
        or preflight.authority_granted
    ):
        raise RoleBenchmarkError("benchmark preflight does not bind the matrix and executor")
    if any(cell.model.provider_id != "fake" for cell in matrix.cells):
        raise RoleBenchmarkError("V3 role benchmark execution admits only scripted fake targets")

    cases = {case.case_id: case for case in matrix.cases}
    run_cells: list[RoleBenchmarkRunCellV1] = []
    for cell in sorted(matrix.cells, key=lambda item: item.cell_id):
        cell_contract_hash = _content_hash(cell)
        bindings: list[RoleBenchmarkCaseBindingV1] = []
        for case_id in stable_case_selection(matrix, cell):
            case = cases[case_id]
            system_prompt, prompt = _render_prompt(case, cell)
            work_item_hash = _content_hash(
                {
                    "schema_version": "autolean.role-work-item.v3",
                    "case_id": case.case_id,
                    "role": case.role.value,
                    "cell_contract_hash": cell_contract_hash,
                    "system_prompt": system_prompt,
                    "prompt": prompt,
                    "tools_hash": _refs_hash(
                        cell.tools,
                        domain="autolean.role-tools.v1",
                    ),
                    "retrieval_scope_hash": _refs_hash(
                        cell.retrieval_scope,
                        domain="autolean.role-retrieval.v1",
                    ),
                    "required_capabilities": sorted(
                        capability.value for capability in cell.required_capabilities
                    ),
                    "budget": cell.budget.model_dump(mode="json"),
                    "code_revision_hash": cell.code_revision_hash,
                    "environment_hash": cell.environment_hash,
                }
            )
            evaluator_hash = _content_hash(
                {
                    "schema_version": "autolean.role-evaluator.v1",
                    "scorer": case.scorer,
                    "expected_output": case.expected_output,
                }
            )
            trials: list[RoleBenchmarkTrialBindingV1] = []
            for repetition in range(1, cell.budget.repetitions + 1):
                trial_seed = derive_trial_seed(
                    matrix,
                    cell,
                    case_id=case.case_id,
                    repetition=repetition,
                )
                trials.append(
                    RoleBenchmarkTrialBindingV1(
                        repetition=repetition,
                        trial_seed=trial_seed,
                        work_item_hash=_trial_work_item_hash(
                            base_work_item_hash=work_item_hash,
                            repetition=repetition,
                            trial_seed=trial_seed,
                        ),
                    )
                )
            bindings.append(
                RoleBenchmarkCaseBindingV1(
                    case_id=case.case_id,
                    case_revision=case.case_revision,
                    case_contract_hash=_content_hash(case),
                    work_item_hash=work_item_hash,
                    evaluator_kind=case.scorer,
                    evaluator_hash=evaluator_hash,
                    trials=tuple(trials),
                )
            )
        run_cell_payload: dict[str, object] = {
            "schema_version": "autolean.role-run-cell.v3",
            "cell_id": cell.cell_id,
            "role": cell.role.value,
            "cell_contract_hash": cell_contract_hash,
            "model": cell.model.model_dump(mode="json"),
            "prompt_hash": _content_hash(cell.prompt),
            "tools_hash": _refs_hash(cell.tools, domain="autolean.role-tools.v1"),
            "retrieval_scope_hash": _refs_hash(
                cell.retrieval_scope,
                domain="autolean.role-retrieval.v1",
            ),
            "capabilities_hash": _content_hash(
                {
                    "schema_version": "autolean.role-capabilities.v1",
                    "required": sorted(
                        capability.value for capability in cell.required_capabilities
                    ),
                }
            ),
            "budget_hash": _content_hash(cell.budget),
            "code_revision_hash": cell.code_revision_hash,
            "environment_hash": cell.environment_hash,
            "repetitions": cell.budget.repetitions,
            "selected_cases": [item.model_dump(mode="json") for item in bindings],
        }
        run_cell_payload["run_cell_binding_hash"] = _run_cell_binding_hash(run_cell_payload)
        run_cells.append(RoleBenchmarkRunCellV1.model_validate(run_cell_payload))
    return RoleBenchmarkRunV1(
        run_id=run_id,
        matrix_id=matrix.matrix_id,
        matrix_revision=matrix.matrix_revision,
        matrix_hash=matrix_hash,
        sampling_seed_hash=hashlib.sha256(matrix.sampling_seed.encode()).hexdigest(),
        provider_readiness_hash=preflight.provider_readiness_hash,
        execution_class=executor_descriptor.execution_class,
        executor_descriptor_hash=descriptor_hash,
        raw_output_commitment_scheme=executor_descriptor.raw_output_commitment_scheme,
        cells=tuple(run_cells),
    )


@dataclass(frozen=True, slots=True)
class RoleBenchmarkWorkItem:
    """The executor-facing view. It intentionally contains no oracle."""

    case_id: str
    role: BenchmarkRoleV1
    system_prompt: str
    prompt: str
    tools: tuple[RoleArtifactRefV1, ...]
    retrieval_scope: tuple[RoleArtifactRefV1, ...]
    max_input_tokens: int
    max_output_tokens: int
    timeout_ms: int
    trial_seed: str
    work_item_hash: str


@dataclass(frozen=True, slots=True)
class RoleExecutionOutcome:
    """Raw executor output held only long enough for evaluation and hashing."""

    output: object
    elapsed_ms: int = 0
    input_tokens: int = 1
    output_tokens: int = 1
    cost_microusd: int = 0

    def __post_init__(self) -> None:
        _validate_json_value(self.output, label="execution output")
        for label, value in (
            ("elapsed_ms", self.elapsed_ms),
            ("input_tokens", self.input_tokens),
            ("output_tokens", self.output_tokens),
            ("cost_microusd", self.cost_microusd),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise RoleBenchmarkError(f"{label} must be a non-negative integer")


class RoleBenchmarkExecutor(Protocol):
    """Operator adapter seam; the built-in implementation is fake-only."""

    @property
    def descriptor(self) -> RoleBenchmarkExecutorDescriptorV1: ...

    def execute(
        self,
        *,
        cell: RoleBenchmarkCellV1,
        work_item: RoleBenchmarkWorkItem,
        repetition: int,
    ) -> RoleExecutionOutcome: ...


class FakeResponseSeriesV1(ContractModel):
    """Scripted output for one fake cell/case pair."""

    schema_version: Literal["autolean.role-fake-response.v1"] = "autolean.role-fake-response.v1"
    cell_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    case_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    outputs: tuple[object, ...]
    elapsed_ms: int = Field(default=0, ge=0)
    input_tokens: int = Field(default=1, ge=0)
    output_tokens: int = Field(default=1, ge=0)
    cost_microusd: int = Field(default=0, ge=0)

    @field_validator("outputs")
    @classmethod
    def require_outputs(cls, value: tuple[object, ...]) -> tuple[object, ...]:
        if not value:
            raise ValueError("fake response series must contain at least one output")
        for item in value:
            _validate_json_value(item, label="fake response output")
        return value


class FakeRoleBenchmarkFixtureV1(ContractModel):
    """Offline fixture that binds a matrix to scripted fake responses."""

    schema_version: Literal["autolean.role-fake-fixture.v3"] = "autolean.role-fake-fixture.v3"
    matrix: RoleBenchmarkMatrixV1
    responses: tuple[FakeResponseSeriesV1, ...]

    @model_validator(mode="after")
    def validate_response_coverage(self) -> Self:
        cells = {cell.cell_id: cell for cell in self.matrix.cells}
        expected: set[tuple[str, str]] = set()
        for cell in self.matrix.cells:
            if cell.model.provider_id != "fake":
                raise ValueError("the built-in benchmark fixture permits only provider_id 'fake'")
            expected.update(
                (cell.cell_id, case_id) for case_id in stable_case_selection(self.matrix, cell)
            )
        observed: set[tuple[str, str]] = set()
        for response in self.responses:
            key = (response.cell_id, response.case_id)
            if key in observed:
                raise ValueError("fake response cell/case pairs must be unique")
            observed.add(key)
            response_cell = cells.get(response.cell_id)
            if response_cell is None:
                raise ValueError("fake response references an unknown cell")
            if len(response.outputs) not in {1, response_cell.budget.repetitions}:
                raise ValueError("fake outputs must contain one or exactly repetitions entries")
        if observed != expected:
            raise ValueError("fake response coverage must exactly match stable case selection")
        return self


class ScriptedFakeRoleExecutor:
    """Deterministic, network-free executor used by the default CLI and tests."""

    def __init__(self, fixture: FakeRoleBenchmarkFixtureV1) -> None:
        self._responses = {(item.cell_id, item.case_id): item for item in fixture.responses}

    @property
    def descriptor(self) -> RoleBenchmarkExecutorDescriptorV1:
        return scripted_fake_executor_descriptor()

    def execute(
        self,
        *,
        cell: RoleBenchmarkCellV1,
        work_item: RoleBenchmarkWorkItem,
        repetition: int,
    ) -> RoleExecutionOutcome:
        if cell.model.provider_id != "fake":
            raise RoleBenchmarkError("scripted executor refuses non-fake providers")
        try:
            response = self._responses[(cell.cell_id, work_item.case_id)]
        except KeyError as error:
            raise RoleBenchmarkError("scripted fake response is missing") from error
        output_index = 0 if len(response.outputs) == 1 else repetition - 1
        try:
            output = response.outputs[output_index]
        except IndexError as error:
            raise RoleBenchmarkError("scripted fake repetition is missing") from error
        return RoleExecutionOutcome(
            output=output,
            elapsed_ms=response.elapsed_ms,
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
            cost_microusd=response.cost_microusd,
        )


class RoleBenchmarkExecutionReceiptV1(ContractModel):
    """Typed execution provenance bound to one synthetic trial output."""

    schema_version: Literal["autolean.role-execution-receipt.v1"] = (
        "autolean.role-execution-receipt.v1"
    )
    execution_class: Literal[RoleExecutionClassV1.SCRIPTED_FAKE] = (
        RoleExecutionClassV1.SCRIPTED_FAKE
    )
    executor_descriptor_hash: str = Field(pattern=_SHA256_PATTERN)
    provider_target_hash: str = Field(pattern=_SHA256_PATTERN)
    provider_readiness_hash: str = Field(pattern=_SHA256_PATTERN)
    work_item_hash: str = Field(pattern=_SHA256_PATTERN)
    output_hash: str = Field(pattern=_SHA256_PATTERN)
    authority_receipt_hash: None = None


class RoleBenchmarkTrialResultV1(ContractModel):
    """Answer-free terminal result for one cell/case/repetition."""

    schema_version: Literal["autolean.role-trial-result.v3"] = "autolean.role-trial-result.v3"
    run_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    cell_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    case_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    role: BenchmarkRoleV1
    repetition: int = Field(ge=1, le=100)
    trial_seed: str = Field(pattern=_SHA256_PATTERN)
    work_item_hash: str = Field(pattern=_SHA256_PATTERN)
    evaluator_hash: str = Field(pattern=_SHA256_PATTERN)
    output_hash: str = Field(pattern=_SHA256_PATTERN)
    passed: bool
    score_micros: int = Field(ge=0, le=_ONE_MILLION)
    elapsed_ms: int = Field(ge=0)
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    cost_microusd: int = Field(ge=0)
    execution_receipt: RoleBenchmarkExecutionReceiptV1
    result_commitment_hash: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_score_and_receipt(self) -> Self:
        expected_score = _ONE_MILLION if self.passed else 0
        if self.score_micros != expected_score:
            raise ValueError("exact_json_v1 score must be one million iff the trial passed")
        if (
            self.execution_receipt.work_item_hash != self.work_item_hash
            or self.execution_receipt.output_hash != self.output_hash
        ):
            raise ValueError("execution receipt does not bind the trial result")
        if self.result_commitment_hash != _trial_result_commitment_hash(
            self.model_dump(mode="json")
        ):
            raise ValueError("trial result commitment does not match its complete V3 payload")
        return self


def _public_result_commitment_hash(
    run: RoleBenchmarkRunV1,
    results: Iterable[RoleBenchmarkTrialResultV1],
) -> str:
    ordered = tuple(
        sorted(
            results,
            key=lambda item: (item.cell_id, item.case_id, item.repetition),
        )
    )
    return _content_hash(
        {
            "schema_version": "autolean.role-public-result-commitment.v3",
            "run_manifest_hash": _content_hash(run),
            "results": [item.model_dump(mode="json") for item in ordered],
        }
    )


def _wilson_interval_ppm(successes: int, trials: int) -> tuple[int, int]:
    if trials < 1:
        raise RoleBenchmarkError("Wilson interval requires at least one trial")
    z = 1.959963984540054
    rate = successes / trials
    denominator = 1 + (z * z / trials)
    center = (rate + z * z / (2 * trials)) / denominator
    margin = z * math.sqrt(rate * (1 - rate) / trials + z * z / (4 * trials * trials)) / denominator
    low = max(0.0, center - margin)
    high = min(1.0, center + margin)
    return round(low * _ONE_MILLION), round(high * _ONE_MILLION)


class RoleBenchmarkCellMetricsV1(ContractModel):
    """Aggregate for exactly one cell; roles are never merged."""

    schema_version: Literal["autolean.role-cell-metrics.v3"] = "autolean.role-cell-metrics.v3"
    cell_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    role: BenchmarkRoleV1
    provider_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    model_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    model_revision: str = Field(min_length=1, max_length=128)
    cases: int = Field(ge=1)
    repetitions: int = Field(ge=1)
    trials: int = Field(ge=1)
    passed: int = Field(ge=0)
    pass_rate_ppm: int = Field(ge=0, le=_ONE_MILLION)
    pass_rate_wilson95_low_ppm: int = Field(ge=0, le=_ONE_MILLION)
    pass_rate_wilson95_high_ppm: int = Field(ge=0, le=_ONE_MILLION)
    mean_score_micros: int = Field(ge=0, le=_ONE_MILLION)
    unstable_cases: int = Field(ge=0)
    instability_rate_ppm: int = Field(ge=0, le=_ONE_MILLION)
    elapsed_ms: int = Field(ge=0)
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    cost_microusd: int = Field(ge=0)


class RoleBenchmarkReportV1(ContractModel):
    """Complete report with an immutable run manifest and answer-free results."""

    schema_version: Literal["autolean.role-benchmark-report.v3"] = (
        "autolean.role-benchmark-report.v3"
    )
    execution_class: Literal[RoleExecutionClassV1.SCRIPTED_FAKE] = (
        RoleExecutionClassV1.SCRIPTED_FAKE
    )
    evaluator_kinds: tuple[Literal["exact_json_v1"], ...]
    raw_artifact_manifest_hash: str = Field(pattern=_SHA256_PATTERN)
    public_result_commitment_hash: str = Field(pattern=_SHA256_PATTERN)
    run: RoleBenchmarkRunV1
    metrics: tuple[RoleBenchmarkCellMetricsV1, ...]
    results: tuple[RoleBenchmarkTrialResultV1, ...]

    @model_validator(mode="after")
    def validate_report_integrity(self) -> Self:
        expected_evaluators = tuple(
            sorted({case.evaluator_kind for cell in self.run.cells for case in cell.selected_cases})
        )
        if (
            self.execution_class is not self.run.execution_class
            or self.evaluator_kinds != expected_evaluators
        ):
            raise ValueError("benchmark report execution or evaluator identity is inconsistent")
        canonical_results = tuple(
            sorted(
                self.results,
                key=lambda item: (item.cell_id, item.case_id, item.repetition),
            )
        )
        if self.results != canonical_results:
            raise ValueError("benchmark report trial results are not in canonical order")
        if self.public_result_commitment_hash != _public_result_commitment_hash(
            self.run,
            self.results,
        ):
            raise ValueError(
                "benchmark report public result commitment does not match run and results"
            )
        expected_metrics = _validated_report_metrics(self.run, self.results)
        if self.metrics != expected_metrics:
            raise ValueError("benchmark report metrics do not match its run and trial results")
        return self

    def canonical_json_bytes(self) -> bytes:
        return canonical_json_bytes(self) + b"\n"


class RoleBenchmarkRawOutputEntryV1(ContractModel):
    """One private content-addressed raw output referenced by a public trial hash."""

    schema_version: Literal["autolean.role-raw-output-entry.v3"] = (
        "autolean.role-raw-output-entry.v3"
    )
    cell_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    case_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    repetition: int = Field(ge=1, le=100)
    output_hash: str = Field(pattern=_SHA256_PATTERN)
    execution_receipt_hash: str = Field(pattern=_SHA256_PATTERN)
    result_commitment_hash: str = Field(pattern=_SHA256_PATTERN)
    size_bytes: int = Field(ge=1)


class RoleBenchmarkRawArtifactManifestV1(ContractModel):
    """Private index kept separately from the answer-free aggregate report."""

    schema_version: Literal["autolean.role-raw-artifact-manifest.v3"] = (
        "autolean.role-raw-artifact-manifest.v3"
    )
    run_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    run_manifest_hash: str = Field(pattern=_SHA256_PATTERN)
    execution_class: Literal[RoleExecutionClassV1.SCRIPTED_FAKE] = (
        RoleExecutionClassV1.SCRIPTED_FAKE
    )
    commitment_scheme: Literal["sha256-canonical-json-scripted-fake-v1"] = (
        _SCRIPTED_FAKE_COMMITMENT_SCHEME
    )
    storage_class: Literal["operator-local-private"] = "operator-local-private"
    public_result_commitment_hash: str = Field(pattern=_SHA256_PATTERN)
    outputs: tuple[RoleBenchmarkRawOutputEntryV1, ...]

    @model_validator(mode="after")
    def validate_output_index(self) -> Self:
        coordinates = tuple((item.cell_id, item.case_id, item.repetition) for item in self.outputs)
        if not coordinates or len(set(coordinates)) != len(coordinates):
            raise ValueError("raw output coordinates must be non-empty and unique")
        if coordinates != tuple(sorted(coordinates)):
            raise ValueError("raw output coordinates must use canonical order")
        commitments = tuple(item.result_commitment_hash for item in self.outputs)
        if len(set(commitments)) != len(commitments):
            raise ValueError("raw output result commitments must be unique")
        return self

    def canonical_json_bytes(self) -> bytes:
        return canonical_json_bytes(self) + b"\n"

    def content_hash(self) -> str:
        return _content_hash(self)


@dataclass(frozen=True, slots=True)
class RoleBenchmarkPrivatePaths:
    """Fixed operator-private paths for raw outputs and their manifest."""

    root: Path
    raw_output_root: Path
    manifest_path: Path


_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400


def _validated_private_artifact_root(root: Path) -> Path:
    if not root.is_absolute():
        raise RoleBenchmarkError("raw output artifact root must be absolute")
    resolved = root.resolve(strict=False)
    if resolved.is_relative_to(_REPOSITORY_ROOT.resolve()):
        raise RoleBenchmarkError("raw output artifact root must be outside the repository")
    for candidate in (resolved, *resolved.parents):
        if (candidate / ".git").exists():
            raise RoleBenchmarkError("raw output artifact root must be outside every Git checkout")
    return resolved


def operator_private_benchmark_paths(
    run_id: str,
    *,
    environment: Mapping[str, str] | None = None,
) -> RoleBenchmarkPrivatePaths:
    """Resolve the one operator-private benchmark location for this machine."""

    if re.fullmatch(_IDENTIFIER_PATTERN, run_id) is None:
        raise RoleBenchmarkError("run_id is not a valid benchmark identifier")
    selected_environment = os.environ if environment is None else environment
    configured = selected_environment.get(_OPERATOR_PRIVATE_ROOT_ENV)
    if configured:
        root = Path(configured)
        if not root.is_absolute():
            raise RoleBenchmarkError(
                f"{_OPERATOR_PRIVATE_ROOT_ENV} must be an absolute operator-private path"
            )
    elif os.name == "nt":
        local_app_data = selected_environment.get("LOCALAPPDATA")
        if local_app_data:
            root = Path(local_app_data) / "AutoLean" / "role-benchmarks"
        else:
            root = Path.home() / "AppData" / "Local" / "AutoLean" / "role-benchmarks"
    else:
        state_home = selected_environment.get("XDG_STATE_HOME")
        base = Path(state_home) if state_home else Path.home() / ".local" / "state"
        root = base / "autolean" / "role-benchmarks"
    root = root.resolve(strict=False)
    raw_output_root = _validated_private_artifact_root(root / "raw-outputs")
    run_key = hashlib.sha256(run_id.encode("utf-8")).hexdigest()
    return RoleBenchmarkPrivatePaths(
        root=root,
        raw_output_root=raw_output_root,
        manifest_path=root / "raw-artifact-manifests" / f"{run_key}.json",
    )


def _reject_reparse_point(path: Path, *, label: str) -> None:
    """Reject links and Windows reparse points before private-path use."""

    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if path.is_symlink() or (
        int(getattr(metadata, "st_file_attributes", 0)) & _FILE_ATTRIBUTE_REPARSE_POINT
    ):
        raise RoleBenchmarkError(f"{label} must not traverse a symlink, junction, or reparse point")


def prepare_private_manifest_path(paths: RoleBenchmarkPrivatePaths) -> Path:
    """Create and revalidate the fixed private manifest path immediately before writing."""

    root = _validated_private_artifact_root(paths.root)
    expected_raw_root = root / "raw-outputs"
    manifest_parent = root / "raw-artifact-manifests"
    if paths.raw_output_root != expected_raw_root or paths.manifest_path.parent != manifest_parent:
        raise RoleBenchmarkError("private benchmark paths do not use the fixed operator layout")

    for candidate, label in (
        (root, "private artifact root"),
        (manifest_parent, "manifest parent"),
    ):
        _reject_reparse_point(candidate, label=label)
    root.mkdir(parents=True, exist_ok=True)
    _reject_reparse_point(root, label="private artifact root")
    manifest_parent.mkdir(exist_ok=True)
    _reject_reparse_point(manifest_parent, label="manifest parent")

    resolved_root = _validated_private_artifact_root(root)
    resolved_parent = manifest_parent.resolve(strict=True)
    if not resolved_parent.is_relative_to(resolved_root):
        raise RoleBenchmarkError("private manifest path escapes the operator-private root")
    _validated_private_artifact_root(resolved_parent)
    _reject_reparse_point(paths.manifest_path, label="private manifest path")
    return paths.manifest_path


class RoleBenchmarkRawOutputStore:
    """Private CAS for raw model JSON; prompts, inputs, and evaluator oracles stay elsewhere."""

    def __init__(self, root: Path) -> None:
        self._artifacts = ArtifactStore(_validated_private_artifact_root(root))

    def put_output(self, output: object) -> str:
        _validate_json_value(output, label="raw benchmark output")
        payload = canonical_json_bytes(output)
        reference = self._artifacts.put_bytes(payload)
        expected = _content_hash(output)
        if reference.digest != expected:
            raise RoleBenchmarkStoreError("raw output artifact hash does not match output hash")
        return reference.digest

    def verify_output(self, output_hash: str) -> None:
        payload = self._artifacts.get_bytes(output_hash)
        try:
            output = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RoleBenchmarkStoreError("raw output artifact is not valid JSON") from error
        _validate_json_value(output, label="stored raw benchmark output")
        if canonical_json_bytes(output) != payload or _content_hash(output) != output_hash:
            raise RoleBenchmarkStoreError("raw output artifact is not canonical")

    def build_manifest(
        self,
        run: RoleBenchmarkRunV1,
        results: Iterable[RoleBenchmarkTrialResultV1],
    ) -> RoleBenchmarkRawArtifactManifestV1:
        ordered = tuple(
            sorted(
                results,
                key=lambda item: (item.cell_id, item.case_id, item.repetition),
            )
        )
        _validated_report_metrics(run, ordered)
        entries: list[RoleBenchmarkRawOutputEntryV1] = []
        for result in ordered:
            self.verify_output(result.output_hash)
            payload = self._artifacts.get_bytes(result.output_hash)
            entries.append(
                RoleBenchmarkRawOutputEntryV1(
                    cell_id=result.cell_id,
                    case_id=result.case_id,
                    repetition=result.repetition,
                    output_hash=result.output_hash,
                    execution_receipt_hash=_content_hash(result.execution_receipt),
                    result_commitment_hash=result.result_commitment_hash,
                    size_bytes=len(payload),
                )
            )
        return RoleBenchmarkRawArtifactManifestV1(
            run_id=run.run_id,
            run_manifest_hash=_content_hash(run),
            execution_class=run.execution_class,
            commitment_scheme=run.raw_output_commitment_scheme,
            public_result_commitment_hash=_public_result_commitment_hash(run, ordered),
            outputs=tuple(entries),
        )


def validate_report_private_manifest(
    report: RoleBenchmarkReportV1,
    manifest: RoleBenchmarkRawArtifactManifestV1,
) -> None:
    """Cross-check the public result commitment against the private evidence index."""

    expected_entries = {
        (result.cell_id, result.case_id, result.repetition): (
            result.output_hash,
            _content_hash(result.execution_receipt),
            result.result_commitment_hash,
        )
        for result in report.results
    }
    observed_entries = {
        (entry.cell_id, entry.case_id, entry.repetition): (
            entry.output_hash,
            entry.execution_receipt_hash,
            entry.result_commitment_hash,
        )
        for entry in manifest.outputs
    }
    if (
        manifest.run_id != report.run.run_id
        or manifest.run_manifest_hash != _content_hash(report.run)
        or manifest.execution_class is not report.execution_class
        or manifest.commitment_scheme != report.run.raw_output_commitment_scheme
        or manifest.public_result_commitment_hash != report.public_result_commitment_hash
        or report.public_result_commitment_hash
        != _public_result_commitment_hash(report.run, report.results)
        or manifest.content_hash() != report.raw_artifact_manifest_hash
        or observed_entries != expected_entries
    ):
        raise RoleBenchmarkError(
            "private raw artifact manifest does not bind the complete public V3 results"
        )


def _validated_report_metrics(
    run: RoleBenchmarkRunV1,
    results: Iterable[RoleBenchmarkTrialResultV1],
) -> tuple[RoleBenchmarkCellMetricsV1, ...]:
    try:
        run = RoleBenchmarkRunV1.model_validate(run.model_dump(mode="json"))
        validated_results = tuple(
            RoleBenchmarkTrialResultV1.model_validate(item.model_dump(mode="json"))
            for item in results
        )
    except (AttributeError, ValueError) as error:
        raise RoleBenchmarkError(
            "report run or trial results are not complete canonical V3 values"
        ) from error
    ordered = tuple(
        sorted(
            validated_results,
            key=lambda item: (item.cell_id, item.case_id, item.repetition),
        )
    )
    expected: dict[
        tuple[str, str, int],
        tuple[
            RoleBenchmarkRunCellV1,
            RoleBenchmarkCaseBindingV1,
            RoleBenchmarkTrialBindingV1,
        ],
    ] = {}
    for cell in run.cells:
        for case in cell.selected_cases:
            if len(case.trials) != cell.repetitions:
                raise RoleBenchmarkError("case trial schedule does not match cell repetitions")
            for trial in case.trials:
                expected[(cell.cell_id, case.case_id, trial.repetition)] = (cell, case, trial)
    observed: dict[tuple[str, str, int], RoleBenchmarkTrialResultV1] = {}
    for result in ordered:
        key = (result.cell_id, result.case_id, result.repetition)
        if key in observed:
            raise RoleBenchmarkError("report contains duplicate trial results")
        observed[key] = result
        expected_binding = expected.get(key)
        if expected_binding is None:
            raise RoleBenchmarkError("report contains an unexpected trial result")
        cell, case, trial = expected_binding
        if (
            result.run_id != run.run_id
            or result.role is not cell.role
            or result.trial_seed != trial.trial_seed
            or result.work_item_hash != trial.work_item_hash
            or result.evaluator_hash != case.evaluator_hash
            or result.execution_receipt.execution_class is not run.execution_class
            or result.execution_receipt.executor_descriptor_hash != run.executor_descriptor_hash
            or result.execution_receipt.provider_target_hash != _content_hash(cell.model)
            or result.execution_receipt.provider_readiness_hash != run.provider_readiness_hash
        ):
            raise RoleBenchmarkError("trial result does not match its frozen run binding")
    if observed.keys() != expected.keys():
        raise RoleBenchmarkError("report is missing terminal trial results")

    metrics: list[RoleBenchmarkCellMetricsV1] = []
    for cell in run.cells:
        cell_results = tuple(item for item in ordered if item.cell_id == cell.cell_id)
        passed = sum(item.passed for item in cell_results)
        trials = len(cell_results)
        low_ppm, high_ppm = _wilson_interval_ppm(passed, trials)
        unstable = 0
        for case in cell.selected_cases:
            outcomes = {item.passed for item in cell_results if item.case_id == case.case_id}
            unstable += len(outcomes) > 1
        cases = len(cell.selected_cases)
        metrics.append(
            RoleBenchmarkCellMetricsV1(
                cell_id=cell.cell_id,
                role=cell.role,
                provider_id=cell.model.provider_id,
                model_id=cell.model.model_id,
                model_revision=cell.model.model_revision,
                cases=cases,
                repetitions=cell.repetitions,
                trials=trials,
                passed=passed,
                pass_rate_ppm=round(passed * _ONE_MILLION / trials),
                pass_rate_wilson95_low_ppm=low_ppm,
                pass_rate_wilson95_high_ppm=high_ppm,
                mean_score_micros=round(sum(item.score_micros for item in cell_results) / trials),
                unstable_cases=unstable,
                instability_rate_ppm=round(unstable * _ONE_MILLION / cases),
                elapsed_ms=sum(item.elapsed_ms for item in cell_results),
                input_tokens=sum(item.input_tokens for item in cell_results),
                output_tokens=sum(item.output_tokens for item in cell_results),
                cost_microusd=sum(item.cost_microusd for item in cell_results),
            )
        )
    return tuple(metrics)


def build_report(
    run: RoleBenchmarkRunV1,
    results: Iterable[RoleBenchmarkTrialResultV1],
    *,
    raw_artifact_manifest_hash: str,
) -> RoleBenchmarkReportV1:
    ordered = tuple(
        sorted(
            results,
            key=lambda item: (item.cell_id, item.case_id, item.repetition),
        )
    )
    metrics = _validated_report_metrics(run, ordered)
    evaluator_kinds = tuple(
        sorted({case.evaluator_kind for cell in run.cells for case in cell.selected_cases})
    )
    return RoleBenchmarkReportV1(
        execution_class=run.execution_class,
        evaluator_kinds=evaluator_kinds,
        raw_artifact_manifest_hash=raw_artifact_manifest_hash,
        public_result_commitment_hash=_public_result_commitment_hash(run, ordered),
        run=run,
        metrics=metrics,
        results=ordered,
    )


class RoleBenchmarkComparisonV1(ContractModel):
    """Paired comparison with explicit confounding and repetition diagnostics."""

    schema_version: Literal["autolean.role-benchmark-comparison.v3"] = (
        "autolean.role-benchmark-comparison.v3"
    )
    baseline_run_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    baseline_cell_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    candidate_run_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    candidate_cell_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    baseline_matrix_hash: str = Field(pattern=_SHA256_PATTERN)
    candidate_matrix_hash: str = Field(pattern=_SHA256_PATTERN)
    baseline_provider_readiness_hash: str = Field(pattern=_SHA256_PATTERN)
    candidate_provider_readiness_hash: str = Field(pattern=_SHA256_PATTERN)
    baseline_raw_artifact_manifest_hash: str = Field(pattern=_SHA256_PATTERN)
    candidate_raw_artifact_manifest_hash: str = Field(pattern=_SHA256_PATTERN)
    role: BenchmarkRoleV1
    execution_class: Literal[RoleExecutionClassV1.SCRIPTED_FAKE] = (
        RoleExecutionClassV1.SCRIPTED_FAKE
    )
    comparison_kind: Literal["repeatability", "controlled_ablation", "confounded"]
    changed_dimensions: tuple[str, ...]
    evidence_changes: tuple[
        Literal["matrix", "provider_readiness", "raw_artifact_manifest"],
        ...,
    ]
    case_binding_hash: str = Field(pattern=_SHA256_PATTERN)
    trial_binding_hash: str = Field(pattern=_SHA256_PATTERN)
    repeatable_bindings: bool
    non_repeatable_dimensions: tuple[str, ...]
    repeatable_outputs: bool
    output_mismatched_trials: int = Field(ge=0)
    paired_trials: int = Field(ge=1)
    baseline_pass_rate_ppm: int = Field(ge=0, le=_ONE_MILLION)
    candidate_pass_rate_ppm: int = Field(ge=0, le=_ONE_MILLION)
    pass_rate_delta_ppm: int = Field(ge=-_ONE_MILLION, le=_ONE_MILLION)
    mean_score_delta_micros: int = Field(ge=-_ONE_MILLION, le=_ONE_MILLION)
    candidate_wins: int = Field(ge=0)
    candidate_losses: int = Field(ge=0)
    ties: int = Field(ge=0)
    discordant_trials: int = Field(ge=0)
    baseline_unstable_cases: int = Field(ge=0)
    candidate_unstable_cases: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_comparison_accounting(self) -> Self:
        for values, label in (
            (self.changed_dimensions, "changed dimensions"),
            (self.evidence_changes, "evidence changes"),
            (self.non_repeatable_dimensions, "non-repeatable dimensions"),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"comparison {label} must be unique")
        expected_kind = (
            "repeatability"
            if not self.changed_dimensions
            else "controlled_ablation"
            if len(self.changed_dimensions) == 1
            else "confounded"
        )
        if self.comparison_kind != expected_kind:
            raise ValueError("comparison kind does not match changed dimensions")
        if self.repeatable_bindings == bool(self.non_repeatable_dimensions):
            raise ValueError("comparison repeatability label is internally inconsistent")
        if self.output_mismatched_trials > self.paired_trials or self.repeatable_outputs != (
            self.output_mismatched_trials == 0
        ):
            raise ValueError("comparison output repeatability label is inconsistent")
        if (
            self.candidate_wins + self.candidate_losses + self.ties != self.paired_trials
            or self.discordant_trials != self.candidate_wins + self.candidate_losses
            or self.pass_rate_delta_ppm
            != self.candidate_pass_rate_ppm - self.baseline_pass_rate_ppm
        ):
            raise ValueError("comparison paired accounting is inconsistent")
        return self

    def canonical_json_bytes(self) -> bytes:
        return canonical_json_bytes(self) + b"\n"


def _run_cell(report: RoleBenchmarkReportV1, cell_id: str) -> RoleBenchmarkRunCellV1:
    matches = tuple(cell for cell in report.run.cells if cell.cell_id == cell_id)
    if len(matches) != 1:
        raise RoleBenchmarkError(f"report does not contain cell: {cell_id}")
    return matches[0]


def _metric(
    report: RoleBenchmarkReportV1,
    cell_id: str,
) -> RoleBenchmarkCellMetricsV1:
    matches = tuple(metric for metric in report.metrics if metric.cell_id == cell_id)
    if len(matches) != 1:
        raise RoleBenchmarkError(f"report does not contain metrics for cell: {cell_id}")
    return matches[0]


def compare_reports(
    baseline: RoleBenchmarkReportV1,
    *,
    baseline_cell_id: str,
    candidate: RoleBenchmarkReportV1,
    candidate_cell_id: str,
) -> RoleBenchmarkComparisonV1:
    """Pair exact case/repetition coordinates and identify every changed dimension."""

    baseline_cell = _run_cell(baseline, baseline_cell_id)
    candidate_cell = _run_cell(candidate, candidate_cell_id)
    if baseline_cell.role is not candidate_cell.role:
        raise RoleBenchmarkError("cross-role comparisons are not meaningful")
    if (
        baseline.execution_class is not candidate.execution_class
        or baseline.run.matrix_id != candidate.run.matrix_id
        or baseline.run.sampling_seed_hash != candidate.run.sampling_seed_hash
    ):
        raise RoleBenchmarkError("paired comparison requires one execution and sampling domain")
    if baseline_cell.repetitions != candidate_cell.repetitions:
        raise RoleBenchmarkError("paired comparison requires identical repetitions")

    def immutable_case_binding(
        case: RoleBenchmarkCaseBindingV1,
    ) -> tuple[object, ...]:
        return (
            case.case_id,
            case.case_revision,
            case.case_contract_hash,
            case.evaluator_kind,
            case.evaluator_hash,
        )

    baseline_cases = tuple(immutable_case_binding(case) for case in baseline_cell.selected_cases)
    candidate_cases = tuple(immutable_case_binding(case) for case in candidate_cell.selected_cases)
    if baseline_cases != candidate_cases:
        raise RoleBenchmarkError(
            "paired comparison requires identical case revision, input-oracle, and evaluator "
            "bindings"
        )
    baseline_trials = tuple(
        (
            case.case_id,
            tuple((trial.repetition, trial.trial_seed) for trial in case.trials),
        )
        for case in baseline_cell.selected_cases
    )
    candidate_trials = tuple(
        (
            case.case_id,
            tuple((trial.repetition, trial.trial_seed) for trial in case.trials),
        )
        for case in candidate_cell.selected_cases
    )
    if baseline_trials != candidate_trials:
        raise RoleBenchmarkError("paired comparison requires identical trial bindings")
    case_binding_hash = _content_hash(
        {
            "schema_version": "autolean.role-comparison-case-bindings.v3",
            "bindings": baseline_cases,
        }
    )
    trial_binding_hash = _content_hash(
        {
            "schema_version": "autolean.role-comparison-trial-bindings.v3",
            "bindings": baseline_trials,
        }
    )

    changed: list[str] = []
    if baseline_cell.model != candidate_cell.model:
        changed.append("model_target")
    for dimension in (
        "prompt_hash",
        "tools_hash",
        "retrieval_scope_hash",
        "capabilities_hash",
        "budget_hash",
        "code_revision_hash",
        "environment_hash",
    ):
        if getattr(baseline_cell, dimension) != getattr(candidate_cell, dimension):
            changed.append(dimension.removesuffix("_hash"))
    baseline_work = tuple(
        (
            case.work_item_hash,
            tuple(trial.work_item_hash for trial in case.trials),
        )
        for case in baseline_cell.selected_cases
    )
    candidate_work = tuple(
        (
            case.work_item_hash,
            tuple(trial.work_item_hash for trial in case.trials),
        )
        for case in candidate_cell.selected_cases
    )
    cell_dimensions_changed = bool(changed)
    if (baseline_work != candidate_work) != cell_dimensions_changed:
        raise RoleBenchmarkError("trial work hashes do not bind the declared cell changes")
    if not changed:
        comparison_kind: Literal["repeatability", "controlled_ablation", "confounded"] = (
            "repeatability"
        )
    elif len(changed) == 1:
        comparison_kind = "controlled_ablation"
    else:
        comparison_kind = "confounded"

    evidence_changes: list[Literal["matrix", "provider_readiness", "raw_artifact_manifest"]] = []
    if baseline.run.matrix_hash != candidate.run.matrix_hash:
        evidence_changes.append("matrix")
    if baseline.run.provider_readiness_hash != candidate.run.provider_readiness_hash:
        evidence_changes.append("provider_readiness")
    if baseline.raw_artifact_manifest_hash != candidate.raw_artifact_manifest_hash:
        evidence_changes.append("raw_artifact_manifest")
    non_repeatable_dimensions = tuple(
        dict.fromkeys(
            (
                *(f"experiment:{dimension}" for dimension in changed),
                *(
                    f"evidence:{dimension}"
                    for dimension in evidence_changes
                    if dimension != "raw_artifact_manifest"
                ),
            )
        )
    )

    def keyed(
        report: RoleBenchmarkReportV1,
        cell_id: str,
    ) -> Mapping[tuple[str, int], RoleBenchmarkTrialResultV1]:
        return {
            (item.case_id, item.repetition): item
            for item in report.results
            if item.cell_id == cell_id
        }

    baseline_results = keyed(baseline, baseline_cell_id)
    candidate_results = keyed(candidate, candidate_cell_id)
    if baseline_results.keys() != candidate_results.keys():
        raise RoleBenchmarkError("paired comparison result coordinates do not match")
    pairs = tuple(
        (baseline_results[key], candidate_results[key]) for key in sorted(baseline_results)
    )
    wins = sum(not old.passed and new.passed for old, new in pairs)
    losses = sum(old.passed and not new.passed for old, new in pairs)
    output_mismatches = sum(old.output_hash != new.output_hash for old, new in pairs)
    baseline_metric = _metric(baseline, baseline_cell_id)
    candidate_metric = _metric(candidate, candidate_cell_id)
    return RoleBenchmarkComparisonV1(
        baseline_run_id=baseline.run.run_id,
        baseline_cell_id=baseline_cell_id,
        candidate_run_id=candidate.run.run_id,
        candidate_cell_id=candidate_cell_id,
        baseline_matrix_hash=baseline.run.matrix_hash,
        candidate_matrix_hash=candidate.run.matrix_hash,
        baseline_provider_readiness_hash=baseline.run.provider_readiness_hash,
        candidate_provider_readiness_hash=candidate.run.provider_readiness_hash,
        baseline_raw_artifact_manifest_hash=baseline.raw_artifact_manifest_hash,
        candidate_raw_artifact_manifest_hash=candidate.raw_artifact_manifest_hash,
        role=baseline_cell.role,
        execution_class=baseline.execution_class,
        comparison_kind=comparison_kind,
        changed_dimensions=tuple(changed),
        evidence_changes=tuple(evidence_changes),
        case_binding_hash=case_binding_hash,
        trial_binding_hash=trial_binding_hash,
        repeatable_bindings=not non_repeatable_dimensions,
        non_repeatable_dimensions=non_repeatable_dimensions,
        repeatable_outputs=output_mismatches == 0,
        output_mismatched_trials=output_mismatches,
        paired_trials=len(pairs),
        baseline_pass_rate_ppm=baseline_metric.pass_rate_ppm,
        candidate_pass_rate_ppm=candidate_metric.pass_rate_ppm,
        pass_rate_delta_ppm=(candidate_metric.pass_rate_ppm - baseline_metric.pass_rate_ppm),
        mean_score_delta_micros=(
            candidate_metric.mean_score_micros - baseline_metric.mean_score_micros
        ),
        candidate_wins=wins,
        candidate_losses=losses,
        ties=len(pairs) - wins - losses,
        discordant_trials=wins + losses,
        baseline_unstable_cases=baseline_metric.unstable_cases,
        candidate_unstable_cases=candidate_metric.unstable_cases,
    )


@dataclass(frozen=True, slots=True)
class RoleBenchmarkTrialReservation:
    """One lease-fenced right to execute a not-yet-terminal trial."""

    run_id: str
    cell_id: str
    case_id: str
    repetition: int
    owner_id: str
    fencing_token: int
    lease_expires_ns: int
    execution_started: bool = False
    execution_started_ns: int | None = None


_ROLE_BENCHMARK_SCHEMA_SQL = """
CREATE TABLE role_benchmark_store_metadata (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    schema_version TEXT NOT NULL,
    schema_fingerprint TEXT NOT NULL,
    pragma_policy_hash TEXT NOT NULL
);
CREATE TABLE role_benchmark_runs (
    run_id TEXT PRIMARY KEY,
    manifest_json TEXT NOT NULL
);
CREATE TABLE role_benchmark_trials (
    run_id TEXT NOT NULL,
    cell_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    repetition INTEGER NOT NULL,
    result_json TEXT NOT NULL,
    PRIMARY KEY (run_id, cell_id, case_id, repetition),
    FOREIGN KEY (run_id) REFERENCES role_benchmark_runs(run_id)
);
CREATE TABLE role_benchmark_run_artifacts (
    run_id TEXT PRIMARY KEY,
    raw_artifact_manifest_hash TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES role_benchmark_runs(run_id)
);
CREATE TABLE role_benchmark_trial_claims (
    run_id TEXT NOT NULL,
    cell_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    repetition INTEGER NOT NULL,
    owner_id TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK (fencing_token >= 1),
    lease_expires_ns INTEGER NOT NULL CHECK (lease_expires_ns >= 1),
    execution_started INTEGER NOT NULL CHECK (execution_started IN (0, 1)),
    execution_started_ns INTEGER,
    CHECK (
        (execution_started = 0 AND execution_started_ns IS NULL)
        OR (execution_started = 1 AND execution_started_ns >= 1)
    ),
    PRIMARY KEY (run_id, cell_id, case_id, repetition),
    FOREIGN KEY (run_id) REFERENCES role_benchmark_runs(run_id)
);
CREATE TRIGGER role_benchmark_runs_no_update
BEFORE UPDATE ON role_benchmark_runs
BEGIN SELECT RAISE(ABORT, 'role benchmark runs are append-only'); END;
CREATE TRIGGER role_benchmark_runs_no_delete
BEFORE DELETE ON role_benchmark_runs
BEGIN SELECT RAISE(ABORT, 'role benchmark runs are append-only'); END;
CREATE TRIGGER role_benchmark_trials_no_update
BEFORE UPDATE ON role_benchmark_trials
BEGIN SELECT RAISE(ABORT, 'role benchmark trials are append-only'); END;
CREATE TRIGGER role_benchmark_trials_no_delete
BEFORE DELETE ON role_benchmark_trials
BEGIN SELECT RAISE(ABORT, 'role benchmark trials are append-only'); END;
CREATE TRIGGER role_benchmark_run_artifacts_no_update
BEFORE UPDATE ON role_benchmark_run_artifacts
BEGIN SELECT RAISE(ABORT, 'role benchmark artifact bindings are append-only'); END;
CREATE TRIGGER role_benchmark_run_artifacts_no_delete
BEFORE DELETE ON role_benchmark_run_artifacts
BEGIN SELECT RAISE(ABORT, 'role benchmark artifact bindings are append-only'); END;
CREATE TRIGGER role_benchmark_store_metadata_no_update
BEFORE UPDATE ON role_benchmark_store_metadata
BEGIN SELECT RAISE(ABORT, 'role benchmark metadata is append-only'); END;
CREATE TRIGGER role_benchmark_store_metadata_no_delete
BEFORE DELETE ON role_benchmark_store_metadata
BEGIN SELECT RAISE(ABORT, 'role benchmark metadata is append-only'); END;
"""


class RoleBenchmarkStore:
    """SQLite WAL V3 store with schema fingerprinting and lease-fenced trial writes."""

    def __init__(self, database: Path) -> None:
        if not database.is_absolute():
            raise RoleBenchmarkStoreError("benchmark database path must be absolute")
        database.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(database, timeout=30)
        try:
            self._connection.row_factory = sqlite3.Row
            self._preflight_existing_database()
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA foreign_keys=ON")
            self._connection.execute("PRAGMA synchronous=FULL")
            self._connection.execute("PRAGMA busy_timeout=30000")
            self._connection.execute("PRAGMA trusted_schema=OFF")
            self._initialize_schema()
        except Exception:
            self._connection.close()
            raise

    def _preflight_existing_database(self) -> None:
        """Reject legacy or damaged stores before any persistent PRAGMA can mutate them."""

        tables = {
            str(row["name"])
            for row in self._connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                """
            )
        }
        if not tables:
            return
        if "role_benchmark_store_metadata" not in tables:
            raise RoleBenchmarkStoreError(
                "legacy V1/V2 benchmark database cannot be migrated in place; "
                "use a new V3 database path"
            )
        self._validate_store_metadata()
        if self._schema_fingerprint(self._connection) != self._expected_schema_fingerprint():
            raise RoleBenchmarkStoreError("benchmark database V3 schema fingerprint is invalid")
        journal_mode = self._connection.execute("PRAGMA journal_mode").fetchone()
        if journal_mode is None or str(journal_mode[0]).casefold() != "wal":
            raise RoleBenchmarkStoreError("benchmark database V3 journal mode is invalid")

    @staticmethod
    def _schema_fingerprint(connection: sqlite3.Connection) -> str:
        table_names = tuple(
            sorted(
                str(row[0])
                for row in connection.execute(
                    """
                    SELECT name FROM sqlite_master
                    WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                    """
                )
            )
        )
        tables: list[dict[str, object]] = []
        for table in table_names:
            table_sql_row = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
                (table,),
            ).fetchone()
            tables.append(
                {
                    "name": table,
                    "sql": " ".join(str(table_sql_row[0]).split()),
                    "columns": [
                        (str(row[1]), str(row[2]), int(row[3]), int(row[5]))
                        for row in connection.execute(f"PRAGMA table_info({table})")
                    ],
                    "foreign_keys": [
                        tuple(row)
                        for row in connection.execute(f"PRAGMA foreign_key_list({table})")
                    ],
                    "indexes": [
                        (str(row[1]), int(row[2]), str(row[3]), int(row[4]))
                        for row in connection.execute(f"PRAGMA index_list({table})")
                    ],
                }
            )
        triggers = [
            {
                "name": str(row[0]),
                "table": str(row[1]),
                "sql": " ".join(str(row[2]).split()),
            }
            for row in connection.execute(
                """
                SELECT name, tbl_name, sql FROM sqlite_master
                WHERE type = 'trigger' ORDER BY name
                """
            )
        ]
        return _content_hash({"tables": tables, "triggers": triggers})

    @classmethod
    def _expected_schema_fingerprint(cls) -> str:
        connection = sqlite3.connect(":memory:")
        try:
            connection.executescript(_ROLE_BENCHMARK_SCHEMA_SQL)
            return cls._schema_fingerprint(connection)
        finally:
            connection.close()

    def _initialize_schema(self) -> None:
        tables = {
            str(row["name"])
            for row in self._connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                """
            )
        }
        if tables:
            if "role_benchmark_store_metadata" not in tables:
                raise RoleBenchmarkStoreError(
                    "legacy V1/V2 benchmark database cannot be migrated in place; "
                    "use a new V3 database path"
                )
            self._validate_store_metadata()
        else:
            self._connection.executescript(_ROLE_BENCHMARK_SCHEMA_SQL)
            expected_fingerprint = self._expected_schema_fingerprint()
            self._connection.execute(
                """
                INSERT INTO role_benchmark_store_metadata(
                    id, schema_version, schema_fingerprint, pragma_policy_hash
                ) VALUES (1, ?, ?, ?)
                """,
                (
                    _STORE_SCHEMA_VERSION,
                    expected_fingerprint,
                    _content_hash(_STORE_PRAGMA_POLICY),
                ),
            )
            self._connection.commit()

        self._validate_store_metadata()
        self._validate_pragmas()
        observed_fingerprint = self._schema_fingerprint(self._connection)
        if observed_fingerprint != self._expected_schema_fingerprint():
            raise RoleBenchmarkStoreError("benchmark database V3 schema fingerprint is invalid")
        integrity = self._connection.execute("PRAGMA integrity_check").fetchall()
        if len(integrity) != 1 or str(integrity[0][0]) != "ok":
            raise RoleBenchmarkStoreError("benchmark database integrity check failed")
        foreign_key_failures = self._connection.execute("PRAGMA foreign_key_check").fetchall()
        if foreign_key_failures:
            raise RoleBenchmarkStoreError("benchmark database contains foreign-key violations")
        self._validate_existing_rows()

    def _validate_store_metadata(self) -> None:
        try:
            rows = self._connection.execute(
                """
                SELECT id, schema_version, schema_fingerprint, pragma_policy_hash
                FROM role_benchmark_store_metadata ORDER BY id
                """
            ).fetchall()
        except sqlite3.DatabaseError as error:
            raise RoleBenchmarkStoreError(
                "benchmark database is not an AutoLean role benchmark V3 store"
            ) from error
        if (
            len(rows) != 1
            or int(rows[0]["id"]) != 1
            or str(rows[0]["schema_version"]) != _STORE_SCHEMA_VERSION
            or str(rows[0]["schema_fingerprint"]) != self._expected_schema_fingerprint()
            or str(rows[0]["pragma_policy_hash"]) != _content_hash(_STORE_PRAGMA_POLICY)
        ):
            raise RoleBenchmarkStoreError(
                "benchmark database is not an AutoLean role benchmark V3 store"
            )

    def _validate_pragmas(self) -> None:
        observed: dict[str, object] = {}
        for name in _STORE_PRAGMA_POLICY:
            row = self._connection.execute(f"PRAGMA {name}").fetchone()
            if row is None:
                raise RoleBenchmarkStoreError(f"benchmark database PRAGMA {name} is unavailable")
            value: object = row[0]
            if isinstance(_STORE_PRAGMA_POLICY[name], str):
                value = str(value).casefold()
            else:
                value = int(str(value))
            observed[name] = value
        if observed != _STORE_PRAGMA_POLICY:
            raise RoleBenchmarkStoreError("benchmark database V3 PRAGMA policy is invalid")

    @staticmethod
    def _trial_binding(
        run: RoleBenchmarkRunV1,
        *,
        cell_id: str,
        case_id: str,
        repetition: int,
    ) -> tuple[
        RoleBenchmarkRunCellV1,
        RoleBenchmarkCaseBindingV1,
        RoleBenchmarkTrialBindingV1,
    ]:
        for cell in run.cells:
            if cell.cell_id != cell_id:
                continue
            for case in cell.selected_cases:
                if case.case_id != case_id:
                    continue
                for trial in case.trials:
                    if trial.repetition == repetition:
                        return cell, case, trial
        raise RoleBenchmarkStoreError("trial coordinate is outside the frozen run manifest")

    @classmethod
    def _validate_result_binding(
        cls,
        run: RoleBenchmarkRunV1,
        result: RoleBenchmarkTrialResultV1,
    ) -> None:
        cell, case, trial = cls._trial_binding(
            run,
            cell_id=result.cell_id,
            case_id=result.case_id,
            repetition=result.repetition,
        )
        if (
            result.run_id != run.run_id
            or result.role is not cell.role
            or result.trial_seed != trial.trial_seed
            or result.work_item_hash != trial.work_item_hash
            or result.evaluator_hash != case.evaluator_hash
            or result.execution_receipt.execution_class is not run.execution_class
            or result.execution_receipt.executor_descriptor_hash != run.executor_descriptor_hash
            or result.execution_receipt.provider_target_hash != _content_hash(cell.model)
            or result.execution_receipt.provider_readiness_hash != run.provider_readiness_hash
        ):
            raise RoleBenchmarkStoreError("stored trial result does not bind its run manifest")

    def _validate_existing_rows(self) -> None:
        runs: dict[str, RoleBenchmarkRunV1] = {}
        results_by_run: dict[str, list[RoleBenchmarkTrialResultV1]] = {}
        for row in self._connection.execute(
            "SELECT run_id, manifest_json FROM role_benchmark_runs ORDER BY run_id"
        ):
            run = _parse_canonical_model(RoleBenchmarkRunV1, str(row["manifest_json"]))
            if str(row["run_id"]) != run.run_id:
                raise RoleBenchmarkStoreError("stored run column does not match its V3 payload")
            runs[run.run_id] = run

        for row in self._connection.execute(
            """
            SELECT run_id, cell_id, case_id, repetition, result_json
            FROM role_benchmark_trials
            ORDER BY run_id, cell_id, case_id, repetition
            """
        ):
            result = _parse_canonical_model(
                RoleBenchmarkTrialResultV1,
                str(row["result_json"]),
            )
            coordinates = (
                str(row["run_id"]),
                str(row["cell_id"]),
                str(row["case_id"]),
                int(row["repetition"]),
            )
            if coordinates != (
                result.run_id,
                result.cell_id,
                result.case_id,
                result.repetition,
            ):
                raise RoleBenchmarkStoreError("stored trial columns do not match their V3 payload")
            stored_run = runs.get(result.run_id)
            if stored_run is None:
                raise RoleBenchmarkStoreError("stored trial references an unknown run")
            self._validate_result_binding(stored_run, result)
            results_by_run.setdefault(result.run_id, []).append(result)

        for row in self._connection.execute(
            "SELECT run_id, raw_artifact_manifest_hash FROM role_benchmark_run_artifacts"
        ):
            run_id = str(row["run_id"])
            if (
                run_id not in runs
                or len(str(row["raw_artifact_manifest_hash"])) != 64
                or any(
                    character not in "0123456789abcdef"
                    for character in str(row["raw_artifact_manifest_hash"])
                )
            ):
                raise RoleBenchmarkStoreError("stored raw artifact binding is invalid")
            _validated_report_metrics(runs[run_id], results_by_run.get(run_id, ()))

        for row in self._connection.execute(
            """
            SELECT run_id, cell_id, case_id, repetition, owner_id,
                   fencing_token, lease_expires_ns,
                   execution_started, execution_started_ns
            FROM role_benchmark_trial_claims
            """
        ):
            stored_run = runs.get(str(row["run_id"]))
            owner_id = str(row["owner_id"])
            if (
                stored_run is None
                or not owner_id
                or len(owner_id) > 128
                or int(row["fencing_token"]) < 1
                or int(row["lease_expires_ns"]) < 1
                or int(row["execution_started"]) not in {0, 1}
                or (int(row["execution_started"]) == 0 and row["execution_started_ns"] is not None)
                or (
                    int(row["execution_started"]) == 1
                    and (
                        row["execution_started_ns"] is None or int(row["execution_started_ns"]) < 1
                    )
                )
            ):
                raise RoleBenchmarkStoreError("stored trial claim is invalid")
            self._trial_binding(
                stored_run,
                cell_id=str(row["cell_id"]),
                case_id=str(row["case_id"]),
                repetition=int(row["repetition"]),
            )
        overlapping = self._connection.execute(
            """
            SELECT 1
            FROM role_benchmark_trial_claims AS claims
            INNER JOIN role_benchmark_trials AS trials
              ON trials.run_id = claims.run_id
             AND trials.cell_id = claims.cell_id
             AND trials.case_id = claims.case_id
             AND trials.repetition = claims.repetition
            LIMIT 1
            """
        ).fetchone()
        if overlapping is not None:
            raise RoleBenchmarkStoreError("terminal trials cannot retain active claims")

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()

    def create_run(self, run: RoleBenchmarkRunV1) -> None:
        try:
            run = RoleBenchmarkRunV1.model_validate(run.model_dump(mode="json"))
        except (AttributeError, ValueError) as error:
            raise RoleBenchmarkStoreError("run is not a valid canonical V3 manifest") from error
        payload = _canonical_text(run)
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            row = self._connection.execute(
                "SELECT manifest_json FROM role_benchmark_runs WHERE run_id = ?",
                (run.run_id,),
            ).fetchone()
            if row is None:
                self._connection.execute(
                    "INSERT INTO role_benchmark_runs(run_id, manifest_json) VALUES (?, ?)",
                    (run.run_id, payload),
                )
            elif str(row["manifest_json"]) != payload:
                raise RoleBenchmarkStoreError("run_id conflicts with another manifest")
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise

    def claim_trial(
        self,
        run: RoleBenchmarkRunV1,
        *,
        cell_id: str,
        case_id: str,
        repetition: int,
        owner_id: str,
        ttl_ms: int,
    ) -> RoleBenchmarkTrialResultV1 | RoleBenchmarkTrialReservation:
        if ttl_ms < 1:
            raise RoleBenchmarkStoreError("trial claim TTL must be positive")
        if not owner_id or len(owner_id) > 128:
            raise RoleBenchmarkStoreError("trial claim owner_id is invalid")
        self._trial_binding(
            run,
            cell_id=cell_id,
            case_id=case_id,
            repetition=repetition,
        )
        if self.load_run(run.run_id) != run:
            raise RoleBenchmarkStoreError("trial claim run does not match stored manifest")
        now_ns = time.time_ns()
        expires_ns = now_ns + ttl_ms * 1_000_000
        coordinates = (run.run_id, cell_id, case_id, repetition)
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            terminal = self._connection.execute(
                """
                SELECT result_json FROM role_benchmark_trials
                WHERE run_id = ? AND cell_id = ? AND case_id = ? AND repetition = ?
                """,
                coordinates,
            ).fetchone()
            if terminal is not None:
                result = _parse_canonical_model(
                    RoleBenchmarkTrialResultV1,
                    str(terminal["result_json"]),
                )
                self._validate_result_binding(run, result)
                self._connection.commit()
                return result

            current = self._connection.execute(
                """
                SELECT owner_id, fencing_token, lease_expires_ns,
                       execution_started, execution_started_ns
                FROM role_benchmark_trial_claims
                WHERE run_id = ? AND cell_id = ? AND case_id = ? AND repetition = ?
                """,
                coordinates,
            ).fetchone()
            if current is None:
                token = 1
                self._connection.execute(
                    """
                    INSERT INTO role_benchmark_trial_claims(
                        run_id, cell_id, case_id, repetition,
                        owner_id, fencing_token, lease_expires_ns,
                        execution_started, execution_started_ns
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL)
                    """,
                    (*coordinates, owner_id, token, expires_ns),
                )
            else:
                if int(current["lease_expires_ns"]) > now_ns:
                    raise RoleBenchmarkTrialBusy("trial coordinate is actively claimed")
                if int(current["execution_started"]) == 1:
                    raise RoleBenchmarkTrialIndeterminate(
                        "expired trial may already have called its executor; automatic retry "
                        "is forbidden"
                    )
                token = int(current["fencing_token"]) + 1
                self._connection.execute(
                    """
                    UPDATE role_benchmark_trial_claims
                    SET owner_id = ?, fencing_token = ?, lease_expires_ns = ?,
                        execution_started = 0, execution_started_ns = NULL
                    WHERE run_id = ? AND cell_id = ? AND case_id = ? AND repetition = ?
                    """,
                    (owner_id, token, expires_ns, *coordinates),
                )
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise
        return RoleBenchmarkTrialReservation(
            run_id=run.run_id,
            cell_id=cell_id,
            case_id=case_id,
            repetition=repetition,
            owner_id=owner_id,
            fencing_token=token,
            lease_expires_ns=expires_ns,
        )

    def mark_trial_execution_started(
        self,
        reservation: RoleBenchmarkTrialReservation,
    ) -> RoleBenchmarkTrialReservation:
        """Irreversibly mark the at-most-once boundary immediately before executor call."""

        if reservation.execution_started:
            raise RoleBenchmarkStoreError("trial reservation is already marked started")
        started_ns = time.time_ns()
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            claim = self._connection.execute(
                """
                SELECT owner_id, fencing_token, lease_expires_ns, execution_started
                FROM role_benchmark_trial_claims
                WHERE run_id = ? AND cell_id = ? AND case_id = ? AND repetition = ?
                """,
                (
                    reservation.run_id,
                    reservation.cell_id,
                    reservation.case_id,
                    reservation.repetition,
                ),
            ).fetchone()
            if (
                claim is None
                or str(claim["owner_id"]) != reservation.owner_id
                or int(claim["fencing_token"]) != reservation.fencing_token
                or int(claim["lease_expires_ns"]) < started_ns
                or int(claim["execution_started"]) != 0
            ):
                raise RoleBenchmarkStoreError("trial reservation is stale, expired, or started")
            self._connection.execute(
                """
                UPDATE role_benchmark_trial_claims
                SET execution_started = 1, execution_started_ns = ?
                WHERE run_id = ? AND cell_id = ? AND case_id = ? AND repetition = ?
                  AND owner_id = ? AND fencing_token = ? AND execution_started = 0
                """,
                (
                    started_ns,
                    reservation.run_id,
                    reservation.cell_id,
                    reservation.case_id,
                    reservation.repetition,
                    reservation.owner_id,
                    reservation.fencing_token,
                ),
            )
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise
        return RoleBenchmarkTrialReservation(
            run_id=reservation.run_id,
            cell_id=reservation.cell_id,
            case_id=reservation.case_id,
            repetition=reservation.repetition,
            owner_id=reservation.owner_id,
            fencing_token=reservation.fencing_token,
            lease_expires_ns=reservation.lease_expires_ns,
            execution_started=True,
            execution_started_ns=started_ns,
        )

    def abandon_trial(self, reservation: RoleBenchmarkTrialReservation) -> None:
        if reservation.execution_started:
            raise RoleBenchmarkTrialIndeterminate(
                "a started executor call cannot be abandoned or made retryable"
            )
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            cursor = self._connection.execute(
                """
                DELETE FROM role_benchmark_trial_claims
                WHERE run_id = ? AND cell_id = ? AND case_id = ? AND repetition = ?
                  AND owner_id = ? AND fencing_token = ? AND execution_started = 0
                """,
                (
                    reservation.run_id,
                    reservation.cell_id,
                    reservation.case_id,
                    reservation.repetition,
                    reservation.owner_id,
                    reservation.fencing_token,
                ),
            )
            if cursor.rowcount != 1:
                raise RoleBenchmarkStoreError("trial reservation cannot be safely abandoned")
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise

    def record_claimed_trial(
        self,
        reservation: RoleBenchmarkTrialReservation,
        result: RoleBenchmarkTrialResultV1,
    ) -> None:
        if not reservation.execution_started or reservation.execution_started_ns is None:
            raise RoleBenchmarkStoreError("trial result requires a started reservation")
        try:
            result = RoleBenchmarkTrialResultV1.model_validate(result.model_dump(mode="json"))
        except (AttributeError, ValueError) as error:
            raise RoleBenchmarkStoreError(
                "trial result is not a valid canonical V3 value"
            ) from error
        if (
            reservation.run_id,
            reservation.cell_id,
            reservation.case_id,
            reservation.repetition,
        ) != (
            result.run_id,
            result.cell_id,
            result.case_id,
            result.repetition,
        ):
            raise RoleBenchmarkStoreError("trial reservation does not match result coordinates")
        run = self.load_run(result.run_id)
        self._validate_result_binding(run, result)
        payload = _canonical_text(result)
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            claim = self._connection.execute(
                """
                SELECT owner_id, fencing_token, lease_expires_ns,
                       execution_started, execution_started_ns
                FROM role_benchmark_trial_claims
                WHERE run_id = ? AND cell_id = ? AND case_id = ? AND repetition = ?
                """,
                (
                    reservation.run_id,
                    reservation.cell_id,
                    reservation.case_id,
                    reservation.repetition,
                ),
            ).fetchone()
            if (
                claim is None
                or str(claim["owner_id"]) != reservation.owner_id
                or int(claim["fencing_token"]) != reservation.fencing_token
                or int(claim["lease_expires_ns"]) < time.time_ns()
                or int(claim["execution_started"]) != 1
                or int(claim["execution_started_ns"]) != reservation.execution_started_ns
            ):
                raise RoleBenchmarkStoreError("trial reservation is stale or expired")
            existing = self._connection.execute(
                """
                SELECT result_json FROM role_benchmark_trials
                WHERE run_id = ? AND cell_id = ? AND case_id = ? AND repetition = ?
                """,
                (
                    result.run_id,
                    result.cell_id,
                    result.case_id,
                    result.repetition,
                ),
            ).fetchone()
            if existing is None:
                self._connection.execute(
                    """
                    INSERT INTO role_benchmark_trials(
                        run_id, cell_id, case_id, repetition, result_json
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        result.run_id,
                        result.cell_id,
                        result.case_id,
                        result.repetition,
                        payload,
                    ),
                )
            elif str(existing["result_json"]) != payload:
                raise RoleBenchmarkStoreError(
                    "trial coordinate conflicts with another terminal result"
                )
            self._connection.execute(
                """
                DELETE FROM role_benchmark_trial_claims
                WHERE run_id = ? AND cell_id = ? AND case_id = ? AND repetition = ?
                  AND owner_id = ? AND fencing_token = ?
                """,
                (
                    reservation.run_id,
                    reservation.cell_id,
                    reservation.case_id,
                    reservation.repetition,
                    reservation.owner_id,
                    reservation.fencing_token,
                ),
            )
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise

    def bind_raw_artifact_manifest(self, run_id: str, manifest_hash: str) -> None:
        if len(manifest_hash) != 64 or any(
            character not in "0123456789abcdef" for character in manifest_hash
        ):
            raise RoleBenchmarkStoreError("raw artifact manifest hash must be SHA-256")
        _validated_report_metrics(self.load_run(run_id), self.load_results(run_id))
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            row = self._connection.execute(
                """
                SELECT raw_artifact_manifest_hash
                FROM role_benchmark_run_artifacts WHERE run_id = ?
                """,
                (run_id,),
            ).fetchone()
            if row is None:
                self._connection.execute(
                    """
                    INSERT INTO role_benchmark_run_artifacts(
                        run_id, raw_artifact_manifest_hash
                    ) VALUES (?, ?)
                    """,
                    (run_id, manifest_hash),
                )
            elif str(row["raw_artifact_manifest_hash"]) != manifest_hash:
                raise RoleBenchmarkStoreError("run conflicts with another raw artifact manifest")
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise

    def load_run(self, run_id: str) -> RoleBenchmarkRunV1:
        rows = self._connection.execute(
            "SELECT manifest_json FROM role_benchmark_runs WHERE run_id = ?",
            (run_id,),
        ).fetchall()
        if len(rows) != 1:
            raise RoleBenchmarkStoreError(f"unknown or duplicate benchmark run: {run_id}")
        return _parse_canonical_model(RoleBenchmarkRunV1, str(rows[0]["manifest_json"]))

    def load_results(self, run_id: str) -> tuple[RoleBenchmarkTrialResultV1, ...]:
        run = self.load_run(run_id)
        rows = self._connection.execute(
            """
            SELECT run_id, cell_id, case_id, repetition, result_json
            FROM role_benchmark_trials
            WHERE run_id = ? ORDER BY cell_id, case_id, repetition
            """,
            (run_id,),
        ).fetchall()
        results: list[RoleBenchmarkTrialResultV1] = []
        for row in rows:
            result = _parse_canonical_model(
                RoleBenchmarkTrialResultV1,
                str(row["result_json"]),
            )
            if (
                str(row["run_id"]),
                str(row["cell_id"]),
                str(row["case_id"]),
                int(row["repetition"]),
            ) != (
                result.run_id,
                result.cell_id,
                result.case_id,
                result.repetition,
            ):
                raise RoleBenchmarkStoreError("stored trial columns do not match their payload")
            self._validate_result_binding(run, result)
            results.append(result)
        return tuple(results)

    def report(self, run_id: str) -> RoleBenchmarkReportV1:
        run = self.load_run(run_id)
        results = self.load_results(run_id)
        _validated_report_metrics(run, results)
        rows = self._connection.execute(
            """
            SELECT raw_artifact_manifest_hash
            FROM role_benchmark_run_artifacts WHERE run_id = ?
            """,
            (run_id,),
        ).fetchall()
        if len(rows) != 1:
            raise RoleBenchmarkStoreError(
                "benchmark run has no unique raw artifact manifest binding"
            )
        return build_report(
            run,
            results,
            raw_artifact_manifest_hash=str(rows[0]["raw_artifact_manifest_hash"]),
        )


class RoleBenchmarkHarness:
    """Execute the fake-only V3 protocol with trial-level leases and resumable writes."""

    def run(
        self,
        matrix: RoleBenchmarkMatrixV1,
        *,
        executor: RoleBenchmarkExecutor,
        store: RoleBenchmarkStore,
        raw_output_store: RoleBenchmarkRawOutputStore,
        readiness: RoleBenchmarkReadinessReportV1,
        run_id: str,
    ) -> RoleBenchmarkReportV1:
        from benchmarks.provider_readiness import (
            RoleBenchmarkReadinessReportV1,
            require_scripted_fake_ready,
        )

        try:
            descriptor = executor.descriptor
        except Exception as error:
            raise RoleBenchmarkError("executor has no valid typed descriptor") from error
        if not isinstance(descriptor, RoleBenchmarkExecutorDescriptorV1):
            raise RoleBenchmarkError("executor descriptor has an invalid type")
        try:
            readiness = RoleBenchmarkReadinessReportV1.model_validate(
                readiness.model_dump(mode="json")
            )
        except (AttributeError, ValueError) as error:
            raise RoleBenchmarkError(
                "benchmark readiness is not a valid canonical V3 report"
            ) from error
        preflight = require_scripted_fake_ready(
            matrix,
            readiness,
            executor_descriptor=descriptor,
        )
        manifest = build_run_manifest(
            matrix,
            run_id=run_id,
            preflight=preflight,
            executor_descriptor=descriptor,
        )
        store.create_run(manifest)
        cases = {case.case_id: case for case in matrix.cases}
        cells = {cell.cell_id: cell for cell in matrix.cells}
        owner_id = f"benchmark-{uuid.uuid4().hex}"
        for run_cell in manifest.cells:
            cell = cells[run_cell.cell_id]
            for binding in run_cell.selected_cases:
                case = cases[binding.case_id]
                system_prompt, prompt = _render_prompt(case, cell)
                for trial in binding.trials:
                    work_item = RoleBenchmarkWorkItem(
                        case_id=case.case_id,
                        role=case.role,
                        system_prompt=system_prompt,
                        prompt=prompt,
                        tools=cell.tools,
                        retrieval_scope=cell.retrieval_scope,
                        max_input_tokens=cell.budget.max_input_tokens,
                        max_output_tokens=cell.budget.max_output_tokens,
                        timeout_ms=cell.budget.timeout_ms,
                        trial_seed=trial.trial_seed,
                        work_item_hash=trial.work_item_hash,
                    )
                    while True:
                        try:
                            claim = store.claim_trial(
                                manifest,
                                cell_id=cell.cell_id,
                                case_id=case.case_id,
                                repetition=trial.repetition,
                                owner_id=owner_id,
                                ttl_ms=max(cell.budget.timeout_ms + 30_000, 60_000),
                            )
                            break
                        except RoleBenchmarkTrialBusy:
                            time.sleep(0.01)
                    if isinstance(claim, RoleBenchmarkTrialResultV1):
                        raw_output_store.verify_output(claim.output_hash)
                        continue
                    started_claim = store.mark_trial_execution_started(claim)
                    outcome = executor.execute(
                        cell=cell,
                        work_item=work_item,
                        repetition=trial.repetition,
                    )
                    if (
                        outcome.input_tokens > cell.budget.max_input_tokens
                        or outcome.output_tokens > cell.budget.max_output_tokens
                        or outcome.elapsed_ms > cell.budget.timeout_ms
                        or outcome.cost_microusd > cell.budget.max_cost_microusd
                    ):
                        raise RoleBenchmarkError(
                            "executor outcome exceeds the frozen benchmark budget"
                        )
                    output_hash = raw_output_store.put_output(outcome.output)
                    passed = canonical_json_bytes(outcome.output) == canonical_json_bytes(
                        case.expected_output
                    )
                    receipt = RoleBenchmarkExecutionReceiptV1(
                        execution_class=manifest.execution_class,
                        executor_descriptor_hash=manifest.executor_descriptor_hash,
                        provider_target_hash=_content_hash(cell.model),
                        provider_readiness_hash=manifest.provider_readiness_hash,
                        work_item_hash=trial.work_item_hash,
                        output_hash=output_hash,
                    )
                    result_payload: dict[str, object] = {
                        "schema_version": "autolean.role-trial-result.v3",
                        "run_id": run_id,
                        "cell_id": cell.cell_id,
                        "case_id": case.case_id,
                        "role": case.role.value,
                        "repetition": trial.repetition,
                        "trial_seed": trial.trial_seed,
                        "work_item_hash": trial.work_item_hash,
                        "evaluator_hash": binding.evaluator_hash,
                        "output_hash": output_hash,
                        "passed": passed,
                        "score_micros": _ONE_MILLION if passed else 0,
                        "elapsed_ms": outcome.elapsed_ms,
                        "input_tokens": outcome.input_tokens,
                        "output_tokens": outcome.output_tokens,
                        "cost_microusd": outcome.cost_microusd,
                        "execution_receipt": receipt.model_dump(mode="json"),
                    }
                    result_payload["result_commitment_hash"] = _trial_result_commitment_hash(
                        result_payload
                    )
                    result = RoleBenchmarkTrialResultV1.model_validate(result_payload)
                    store.record_claimed_trial(started_claim, result)

        results = store.load_results(run_id)
        _validated_report_metrics(manifest, results)
        raw_manifest = raw_output_store.build_manifest(manifest, results)
        store.bind_raw_artifact_manifest(run_id, raw_manifest.content_hash())
        report = store.report(run_id)
        validate_report_private_manifest(report, raw_manifest)
        return report


def load_fake_fixture(path: Path) -> FakeRoleBenchmarkFixtureV1:
    """Load one strict fake fixture; unknown fields and non-JSON values fail closed."""

    try:
        return FakeRoleBenchmarkFixtureV1.model_validate_json(path.read_bytes())
    except (OSError, ValueError) as error:
        raise RoleBenchmarkError(f"invalid role benchmark fixture: {path}") from error


def report_json(report: RoleBenchmarkReportV1) -> str:
    """Human/CLI helper with the same canonical exchange representation."""

    validated = RoleBenchmarkReportV1.model_validate(report.model_dump(mode="json"))
    return validated.canonical_json_bytes().decode("ascii")


def comparison_json(comparison: RoleBenchmarkComparisonV1) -> str:
    validated = RoleBenchmarkComparisonV1.model_validate(comparison.model_dump(mode="json"))
    return validated.canonical_json_bytes().decode("ascii")


def raw_artifact_manifest_json(manifest: RoleBenchmarkRawArtifactManifestV1) -> str:
    validated = RoleBenchmarkRawArtifactManifestV1.model_validate(manifest.model_dump(mode="json"))
    return validated.canonical_json_bytes().decode("ascii")


def load_report_json(payload: str) -> RoleBenchmarkReportV1:
    """Strict public report loader used by downstream comparison automation."""

    try:
        report = RoleBenchmarkReportV1.model_validate_json(payload)
    except ValueError as error:
        raise RoleBenchmarkError("invalid role benchmark report JSON") from error
    try:
        canonical = report.canonical_json_bytes().decode("ascii")
    except UnicodeError as error:
        raise RoleBenchmarkError("role benchmark report JSON is not canonical ASCII") from error
    if payload != canonical:
        raise RoleBenchmarkError("role benchmark report JSON is not canonical V3")
    return report


def load_raw_artifact_manifest_json(payload: str) -> RoleBenchmarkRawArtifactManifestV1:
    try:
        manifest = RoleBenchmarkRawArtifactManifestV1.model_validate_json(payload)
    except ValueError as error:
        raise RoleBenchmarkError("invalid raw artifact manifest JSON") from error
    if payload != manifest.canonical_json_bytes().decode("ascii"):
        raise RoleBenchmarkError("raw artifact manifest JSON is not canonical V3")
    return manifest
