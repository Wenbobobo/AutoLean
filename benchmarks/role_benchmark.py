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
import sqlite3
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Literal, Protocol, Self

from autolean_contracts import ContractModel, canonical_json_bytes
from pydantic import Field, field_validator, model_validator

_IDENTIFIER_PATTERN = r"^[a-z0-9][a-z0-9_.:/-]{0,127}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_ONE_MILLION = 1_000_000


class RoleBenchmarkError(ValueError):
    """A benchmark contract, result, or comparison is invalid."""


class RoleBenchmarkStoreError(RuntimeError):
    """The append-only benchmark store is incomplete, corrupt, or conflicted."""


class BenchmarkRoleV1(StrEnum):
    """Initial roles whose behavior needs independent measurement."""

    PROVER = "prover"
    STATEMENT_FORMALIZER = "statement_formalizer"
    FIDELITY_REVIEWER = "fidelity_reviewer"
    CHEATING_SUPERVISOR = "cheating_supervisor"
    TASK_ALLOCATOR = "task_allocator"


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

    schema_version: Literal["autolean.role-benchmark-cell.v1"] = "autolean.role-benchmark-cell.v1"
    cell_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    role: BenchmarkRoleV1
    model: RoleModelTargetV1
    prompt: RolePromptSpecV1
    tools: tuple[RoleArtifactRefV1, ...] = ()
    retrieval_scope: tuple[RoleArtifactRefV1, ...] = ()
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
        return self


class RoleBenchmarkMatrixV1(ContractModel):
    """A frozen set of cases and controlled experiment cells."""

    schema_version: Literal["autolean.role-benchmark-matrix.v1"] = (
        "autolean.role-benchmark-matrix.v1"
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


class RoleBenchmarkCaseBindingV1(ContractModel):
    """Answer-free case identity persisted in a run manifest."""

    schema_version: Literal["autolean.role-case-binding.v1"] = "autolean.role-case-binding.v1"
    case_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    case_revision: str = Field(min_length=1, max_length=128)
    work_item_hash: str = Field(pattern=_SHA256_PATTERN)
    evaluator_hash: str = Field(pattern=_SHA256_PATTERN)


class RoleBenchmarkRunCellV1(ContractModel):
    """Exact immutable snapshot of one selected experiment cell."""

    schema_version: Literal["autolean.role-run-cell.v1"] = "autolean.role-run-cell.v1"
    cell_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    role: BenchmarkRoleV1
    model: RoleModelTargetV1
    prompt_hash: str = Field(pattern=_SHA256_PATTERN)
    tools_hash: str = Field(pattern=_SHA256_PATTERN)
    retrieval_scope_hash: str = Field(pattern=_SHA256_PATTERN)
    budget_hash: str = Field(pattern=_SHA256_PATTERN)
    code_revision_hash: str = Field(pattern=_SHA256_PATTERN)
    environment_hash: str = Field(pattern=_SHA256_PATTERN)
    repetitions: int = Field(ge=1, le=100)
    selected_cases: tuple[RoleBenchmarkCaseBindingV1, ...]


class RoleBenchmarkRunV1(ContractModel):
    """A repeatable run manifest containing no case input or oracle values."""

    schema_version: Literal["autolean.role-benchmark-run.v1"] = "autolean.role-benchmark-run.v1"
    run_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    matrix_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    matrix_revision: str = Field(min_length=1, max_length=128)
    matrix_hash: str = Field(pattern=_SHA256_PATTERN)
    sampling_seed_hash: str = Field(pattern=_SHA256_PATTERN)
    cells: tuple[RoleBenchmarkRunCellV1, ...]

    @model_validator(mode="after")
    def validate_unique_cells(self) -> Self:
        if not self.cells or len({cell.cell_id for cell in self.cells}) != len(self.cells):
            raise ValueError("run cells must be non-empty and unique")
        return self


def build_run_manifest(matrix: RoleBenchmarkMatrixV1, *, run_id: str) -> RoleBenchmarkRunV1:
    cases = {case.case_id: case for case in matrix.cases}
    run_cells: list[RoleBenchmarkRunCellV1] = []
    for cell in sorted(matrix.cells, key=lambda item: item.cell_id):
        bindings: list[RoleBenchmarkCaseBindingV1] = []
        for case_id in stable_case_selection(matrix, cell):
            case = cases[case_id]
            system_prompt, prompt = _render_prompt(case, cell)
            work_item_hash = _content_hash(
                {
                    "schema_version": "autolean.role-work-item.v1",
                    "case_id": case.case_id,
                    "role": case.role.value,
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
            bindings.append(
                RoleBenchmarkCaseBindingV1(
                    case_id=case.case_id,
                    case_revision=case.case_revision,
                    work_item_hash=work_item_hash,
                    evaluator_hash=evaluator_hash,
                )
            )
        run_cells.append(
            RoleBenchmarkRunCellV1(
                cell_id=cell.cell_id,
                role=cell.role,
                model=cell.model,
                prompt_hash=_content_hash(cell.prompt),
                tools_hash=_refs_hash(cell.tools, domain="autolean.role-tools.v1"),
                retrieval_scope_hash=_refs_hash(
                    cell.retrieval_scope,
                    domain="autolean.role-retrieval.v1",
                ),
                budget_hash=_content_hash(cell.budget),
                code_revision_hash=cell.code_revision_hash,
                environment_hash=cell.environment_hash,
                repetitions=cell.budget.repetitions,
                selected_cases=tuple(bindings),
            )
        )
    return RoleBenchmarkRunV1(
        run_id=run_id,
        matrix_id=matrix.matrix_id,
        matrix_revision=matrix.matrix_revision,
        matrix_hash=matrix.content_hash(),
        sampling_seed_hash=hashlib.sha256(matrix.sampling_seed.encode()).hexdigest(),
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

    schema_version: Literal["autolean.role-fake-fixture.v1"] = "autolean.role-fake-fixture.v1"
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


class RoleBenchmarkTrialResultV1(ContractModel):
    """Answer-free terminal result for one cell/case/repetition."""

    schema_version: Literal["autolean.role-trial-result.v1"] = "autolean.role-trial-result.v1"
    run_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    cell_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    case_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    role: BenchmarkRoleV1
    repetition: int = Field(ge=1, le=100)
    work_item_hash: str = Field(pattern=_SHA256_PATTERN)
    evaluator_hash: str = Field(pattern=_SHA256_PATTERN)
    output_hash: str = Field(pattern=_SHA256_PATTERN)
    passed: bool
    score_micros: int = Field(ge=0, le=_ONE_MILLION)
    elapsed_ms: int = Field(ge=0)
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    cost_microusd: int = Field(ge=0)


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

    schema_version: Literal["autolean.role-cell-metrics.v1"] = "autolean.role-cell-metrics.v1"
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

    schema_version: Literal["autolean.role-benchmark-report.v1"] = (
        "autolean.role-benchmark-report.v1"
    )
    run: RoleBenchmarkRunV1
    metrics: tuple[RoleBenchmarkCellMetricsV1, ...]
    results: tuple[RoleBenchmarkTrialResultV1, ...]

    def canonical_json_bytes(self) -> bytes:
        return canonical_json_bytes(self) + b"\n"


def build_report(
    run: RoleBenchmarkRunV1,
    results: Iterable[RoleBenchmarkTrialResultV1],
) -> RoleBenchmarkReportV1:
    ordered = tuple(
        sorted(
            results,
            key=lambda item: (item.cell_id, item.case_id, item.repetition),
        )
    )
    expected: dict[
        tuple[str, str, int],
        tuple[RoleBenchmarkRunCellV1, RoleBenchmarkCaseBindingV1],
    ] = {}
    for cell in run.cells:
        for case in cell.selected_cases:
            for repetition in range(1, cell.repetitions + 1):
                expected[(cell.cell_id, case.case_id, repetition)] = (cell, case)
    observed: dict[tuple[str, str, int], RoleBenchmarkTrialResultV1] = {}
    for result in ordered:
        key = (result.cell_id, result.case_id, result.repetition)
        if key in observed:
            raise RoleBenchmarkError("report contains duplicate trial results")
        observed[key] = result
        expected_binding = expected.get(key)
        if expected_binding is None:
            raise RoleBenchmarkError("report contains an unexpected trial result")
        cell, case = expected_binding
        if (
            result.run_id != run.run_id
            or result.role is not cell.role
            or result.work_item_hash != case.work_item_hash
            or result.evaluator_hash != case.evaluator_hash
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
    return RoleBenchmarkReportV1(
        run=run,
        metrics=tuple(metrics),
        results=ordered,
    )


class RoleBenchmarkComparisonV1(ContractModel):
    """Paired comparison with explicit confounding and repetition diagnostics."""

    schema_version: Literal["autolean.role-benchmark-comparison.v1"] = (
        "autolean.role-benchmark-comparison.v1"
    )
    baseline_run_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    baseline_cell_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    candidate_run_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    candidate_cell_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    role: BenchmarkRoleV1
    comparison_kind: Literal["repeatability", "controlled_ablation", "confounded"]
    changed_dimensions: tuple[str, ...]
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
    baseline_cases = tuple(item.case_id for item in baseline_cell.selected_cases)
    candidate_cases = tuple(item.case_id for item in candidate_cell.selected_cases)
    if baseline_cases != candidate_cases or baseline_cell.repetitions != candidate_cell.repetitions:
        raise RoleBenchmarkError("paired comparison requires identical cases and repetitions")

    changed: list[str] = []
    if baseline_cell.model != candidate_cell.model:
        changed.append("model_target")
    for dimension in (
        "prompt_hash",
        "tools_hash",
        "retrieval_scope_hash",
        "budget_hash",
        "code_revision_hash",
        "environment_hash",
    ):
        if getattr(baseline_cell, dimension) != getattr(candidate_cell, dimension):
            changed.append(dimension.removesuffix("_hash"))
    if not changed:
        comparison_kind: Literal["repeatability", "controlled_ablation", "confounded"] = (
            "repeatability"
        )
    elif len(changed) == 1:
        comparison_kind = "controlled_ablation"
    else:
        comparison_kind = "confounded"

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
    baseline_metric = _metric(baseline, baseline_cell_id)
    candidate_metric = _metric(candidate, candidate_cell_id)
    return RoleBenchmarkComparisonV1(
        baseline_run_id=baseline.run.run_id,
        baseline_cell_id=baseline_cell_id,
        candidate_run_id=candidate.run.run_id,
        candidate_cell_id=candidate_cell_id,
        role=baseline_cell.role,
        comparison_kind=comparison_kind,
        changed_dimensions=tuple(changed),
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


class RoleBenchmarkStore:
    """SQLite WAL store with immutable, idempotent run and result insertion."""

    def __init__(self, database: Path) -> None:
        if not database.is_absolute():
            raise RoleBenchmarkStoreError("benchmark database path must be absolute")
        database.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(database)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS role_benchmark_runs (
                run_id TEXT PRIMARY KEY,
                manifest_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS role_benchmark_trials (
                run_id TEXT NOT NULL,
                cell_id TEXT NOT NULL,
                case_id TEXT NOT NULL,
                repetition INTEGER NOT NULL,
                result_json TEXT NOT NULL,
                PRIMARY KEY (run_id, cell_id, case_id, repetition),
                FOREIGN KEY (run_id) REFERENCES role_benchmark_runs(run_id)
            );
            CREATE TRIGGER IF NOT EXISTS role_benchmark_runs_no_update
            BEFORE UPDATE ON role_benchmark_runs
            BEGIN SELECT RAISE(ABORT, 'role benchmark runs are append-only'); END;
            CREATE TRIGGER IF NOT EXISTS role_benchmark_runs_no_delete
            BEFORE DELETE ON role_benchmark_runs
            BEGIN SELECT RAISE(ABORT, 'role benchmark runs are append-only'); END;
            CREATE TRIGGER IF NOT EXISTS role_benchmark_trials_no_update
            BEFORE UPDATE ON role_benchmark_trials
            BEGIN SELECT RAISE(ABORT, 'role benchmark trials are append-only'); END;
            CREATE TRIGGER IF NOT EXISTS role_benchmark_trials_no_delete
            BEFORE DELETE ON role_benchmark_trials
            BEGIN SELECT RAISE(ABORT, 'role benchmark trials are append-only'); END;
            """
        )
        self._connection.commit()

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()

    def create_run(self, run: RoleBenchmarkRunV1) -> None:
        payload = _canonical_text(run)
        try:
            self._connection.execute(
                "INSERT INTO role_benchmark_runs(run_id, manifest_json) VALUES (?, ?)",
                (run.run_id, payload),
            )
            self._connection.commit()
        except sqlite3.IntegrityError as error:
            row = self._connection.execute(
                "SELECT manifest_json FROM role_benchmark_runs WHERE run_id = ?",
                (run.run_id,),
            ).fetchone()
            if row is None or row["manifest_json"] != payload:
                raise RoleBenchmarkStoreError("run_id conflicts with another manifest") from error

    def record_trial(self, result: RoleBenchmarkTrialResultV1) -> None:
        payload = _canonical_text(result)
        try:
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
            self._connection.commit()
        except sqlite3.IntegrityError as error:
            row = self._connection.execute(
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
            if row is None or row["result_json"] != payload:
                raise RoleBenchmarkStoreError(
                    "trial coordinate conflicts with another result"
                ) from error

    def load_run(self, run_id: str) -> RoleBenchmarkRunV1:
        row = self._connection.execute(
            "SELECT manifest_json FROM role_benchmark_runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if row is None:
            raise RoleBenchmarkStoreError(f"unknown benchmark run: {run_id}")
        return _parse_canonical_model(RoleBenchmarkRunV1, str(row["manifest_json"]))

    def load_results(self, run_id: str) -> tuple[RoleBenchmarkTrialResultV1, ...]:
        rows = self._connection.execute(
            """
            SELECT result_json FROM role_benchmark_trials
            WHERE run_id = ? ORDER BY cell_id, case_id, repetition
            """,
            (run_id,),
        ).fetchall()
        return tuple(
            _parse_canonical_model(RoleBenchmarkTrialResultV1, str(row["result_json"]))
            for row in rows
        )

    def report(self, run_id: str) -> RoleBenchmarkReportV1:
        return build_report(self.load_run(run_id), self.load_results(run_id))


class RoleBenchmarkHarness:
    """Execute a frozen matrix through an explicitly supplied executor."""

    def run(
        self,
        matrix: RoleBenchmarkMatrixV1,
        *,
        executor: RoleBenchmarkExecutor,
        store: RoleBenchmarkStore,
        run_id: str,
    ) -> RoleBenchmarkReportV1:
        manifest = build_run_manifest(matrix, run_id=run_id)
        store.create_run(manifest)
        cases = {case.case_id: case for case in matrix.cases}
        cells = {cell.cell_id: cell for cell in matrix.cells}
        for run_cell in manifest.cells:
            cell = cells[run_cell.cell_id]
            for binding in run_cell.selected_cases:
                case = cases[binding.case_id]
                system_prompt, prompt = _render_prompt(case, cell)
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
                    work_item_hash=binding.work_item_hash,
                )
                for repetition in range(1, run_cell.repetitions + 1):
                    outcome = executor.execute(
                        cell=cell,
                        work_item=work_item,
                        repetition=repetition,
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
                    passed = canonical_json_bytes(outcome.output) == canonical_json_bytes(
                        case.expected_output
                    )
                    store.record_trial(
                        RoleBenchmarkTrialResultV1(
                            run_id=run_id,
                            cell_id=cell.cell_id,
                            case_id=case.case_id,
                            role=case.role,
                            repetition=repetition,
                            work_item_hash=binding.work_item_hash,
                            evaluator_hash=binding.evaluator_hash,
                            output_hash=_content_hash(outcome.output),
                            passed=passed,
                            score_micros=_ONE_MILLION if passed else 0,
                            elapsed_ms=outcome.elapsed_ms,
                            input_tokens=outcome.input_tokens,
                            output_tokens=outcome.output_tokens,
                            cost_microusd=outcome.cost_microusd,
                        )
                    )
        return store.report(run_id)


def load_fake_fixture(path: Path) -> FakeRoleBenchmarkFixtureV1:
    """Load one strict fake fixture; unknown fields and non-JSON values fail closed."""

    try:
        return FakeRoleBenchmarkFixtureV1.model_validate_json(path.read_bytes())
    except (OSError, ValueError) as error:
        raise RoleBenchmarkError(f"invalid role benchmark fixture: {path}") from error


def report_json(report: RoleBenchmarkReportV1) -> str:
    """Human/CLI helper with the same canonical exchange representation."""

    return report.canonical_json_bytes().decode("ascii")


def comparison_json(comparison: RoleBenchmarkComparisonV1) -> str:
    return comparison.canonical_json_bytes().decode("ascii")


def load_report_json(payload: str) -> RoleBenchmarkReportV1:
    """Strict public report loader used by downstream comparison automation."""

    try:
        report = RoleBenchmarkReportV1.model_validate_json(payload)
    except ValueError as error:
        raise RoleBenchmarkError("invalid role benchmark report JSON") from error
    if json.loads(payload) != report.model_dump(mode="json"):
        raise RoleBenchmarkError("role benchmark report JSON does not match its schema")
    return report
