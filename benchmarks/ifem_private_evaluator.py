"""Private D33 evaluation and non-promotional public projection for iFEM roles.

The sixteen model responses, expected option vector, operator seed, response-CAS
references, and witness specifications stay inside the evaluator boundary.  The
only serializable result is a complete-run aggregate by role and risk/mutation
family.  Its content hash is an integrity field, never its own authority: the
renderer and writer both rebuild every private input before accepting it.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Iterable
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final, Literal, Protocol, Self, cast, runtime_checkable

from autolean_builder.ifem_candidate_dependency_graph import IFEMCandidateDependencyGraphV1
from autolean_builder.ifem_structural_calibration import (
    IFEMStructuralMutationV1,
    IFEMStructuralRiskV1,
)
from autolean_builder.ifem_structural_role_probes import (
    IFEMStructuralProbeRoleV1,
    IFEMStructuralRoleProbeCorpusV1,
    build_ifem_structural_role_probe_corpus,
)
from autolean_builder.ifem_structural_witness_validation import (
    IFEMStructuralWitnessValidationReportV1,
    verify_ifem_structural_witness_validation_report,
)
from autolean_contracts import canonical_json_bytes
from autolean_contracts.base import ContractModel
from autolean_prover.providers import TokenUsage
from pydantic import Field, model_validator

from benchmarks.ifem_role_reconciliation import (
    IFEMRoleReconciliationError,
    build_ifem_role_reconciliation,
)
from benchmarks.ifem_synthetic_role_bridge import (
    IFEMSyntheticRoleExecutionV1,
    IFEMSyntheticRoleExecutor,
    IFEMSyntheticRolePredictionV1,
    IFEMSyntheticRolePreparedRequestV1,
    IFEMSyntheticRoleRequestPolicyV1,
    IFEMSyntheticRoleResponseContractV1,
    prepare,
)
from benchmarks.ifem_synthetic_role_fixture import (
    IFEMSyntheticRoleOptionV1,
    IFEMSyntheticRolePrivateOracleV1,
    IFEMSyntheticRolePublicFixtureV1,
    build_ifem_synthetic_role_fixture,
    build_ifem_synthetic_role_oracle,
)
from benchmarks.ifem_synthetic_role_private_ledger import (
    IFEMSyntheticRolePrivateManifestV1,
)

_SHA256 = r"^[0-9a-f]{64}$"
_CASE_COUNT: Final[int] = 16
IFEM_PRIVATE_EVALUATOR_PUBLIC_REPORT_FILENAME: Final[
    Literal["ifem-private-evaluator-public-report.v1.json"]
] = "ifem-private-evaluator-public-report.v1.json"
_ROLE_COUNTS: Final[dict[str, int]] = {
    IFEMStructuralProbeRoleV1.STATEMENT_FORMALIZER.value: 8,
    IFEMStructuralProbeRoleV1.FIDELITY_REVIEWER.value: 4,
    IFEMStructuralProbeRoleV1.CHEATING_SUPERVISOR.value: 4,
}
_FORBIDDEN_PUBLIC_MARKERS: Final[tuple[bytes, ...]] = (
    b'"baseline_option":',
    b'"expected_option":',
    b'"predicted_option":',
    b'"oracle":',
    b'"operator_seed":',
    b'"seed_commitment":',
    b'"response_id":',
    b'"artifact":',
    b'"commitment_nonce":',
    b'"output_commitment":',
    b'"pair_sha256":',
    b'"witness_commitment_sha256":',
    b"private-cas",
)


class IFEMPrivateEvaluatorError(ValueError):
    """The D33 evaluator could not establish its private input boundary."""


class IFEMPrivateEvaluationParseStatusV1(StrEnum):
    """Private classification for an exact response object, not a public prediction."""

    SELECTED_OPTION = "selected_option"
    ABSTAIN = "abstain"
    INVALID = "invalid"


class IFEMPrivateEvaluatorTokenBucketV1(StrEnum):
    """Coarse full-run token buckets that do not expose response-level usage."""

    ZERO = "zero"
    ONE_TO_255 = "1_to_255"
    TWO_HUNDRED_FIFTY_SIX_TO_1023 = "256_to_1023"
    ONE_THOUSAND_TWENTY_FOUR_TO_4095 = "1024_to_4095"
    FOUR_THOUSAND_NINETY_SIX_PLUS = "4096_plus"


class IFEMPrivateEvaluatorAuthorityV1(ContractModel):
    """Hard-negative authority boundary for the serializable D33 projection."""

    schema_version: Literal["autolean.ifem-private-evaluator-authority.v1"] = (
        "autolean.ifem-private-evaluator-authority.v1"
    )
    raw_output_embedded: Literal[False] = False
    private_oracle_embedded: Literal[False] = False
    operator_seed_embedded: Literal[False] = False
    private_cas_reference_embedded: Literal[False] = False
    response_identifier_embedded: Literal[False] = False
    enumerable_oracle_digest_embedded: Literal[False] = False
    enumerable_output_digest_embedded: Literal[False] = False
    semantic_equivalence_claimed: Literal[False] = False
    benchmark_authority: Literal[False] = False
    statement_contract_created: Literal[False] = False
    freeze_allowed: Literal[False] = False
    prover_handoff_allowed: Literal[False] = False
    promotion_allowed: Literal[False] = False


class IFEMPrivateEvaluatorRoleAggregateV1(ContractModel):
    """Public aggregate for one role, never a per-case scorecard."""

    schema_version: Literal["autolean.ifem-private-evaluator-role-aggregate.v1"] = (
        "autolean.ifem-private-evaluator-role-aggregate.v1"
    )
    role: IFEMStructuralProbeRoleV1
    case_count: int = Field(ge=1, le=_CASE_COUNT)
    correct_count: int = Field(ge=0, le=_CASE_COUNT)
    incorrect_count: int = Field(ge=0, le=_CASE_COUNT)
    abstention_count: int = Field(ge=0, le=_CASE_COUNT)
    invalid_count: int = Field(ge=0, le=_CASE_COUNT)

    @model_validator(mode="after")
    def validate_counts(self) -> Self:
        if self.case_count != _ROLE_COUNTS[self.role.value]:
            raise ValueError("role aggregate case count differs from the fixed fixture")
        if (
            self.correct_count + self.incorrect_count + self.abstention_count + self.invalid_count
            != self.case_count
        ):
            raise ValueError("role aggregate outcome counts do not cover its cases")
        return self


class IFEMPrivateEvaluatorRiskAggregateV1(ContractModel):
    """Public aggregate for one fixed risk/mutation family."""

    schema_version: Literal["autolean.ifem-private-evaluator-risk-aggregate.v1"] = (
        "autolean.ifem-private-evaluator-risk-aggregate.v1"
    )
    risk: IFEMStructuralRiskV1
    mutation: IFEMStructuralMutationV1
    case_count: Literal[2] = 2
    correct_count: int = Field(ge=0, le=2)
    incorrect_count: int = Field(ge=0, le=2)
    abstention_count: int = Field(ge=0, le=2)
    invalid_count: int = Field(ge=0, le=2)

    @model_validator(mode="after")
    def validate_counts(self) -> Self:
        if (
            self.correct_count + self.incorrect_count + self.abstention_count + self.invalid_count
            != self.case_count
        ):
            raise ValueError("risk aggregate outcome counts do not cover its cases")
        return self


class IFEMPrivateEvaluatorTokenUsageSummaryV1(ContractModel):
    """Full-run-only usage summary recovered from private response CAS records."""

    schema_version: Literal["autolean.ifem-private-evaluator-token-usage-summary.v1"] = (
        "autolean.ifem-private-evaluator-token-usage-summary.v1"
    )
    case_count: Literal[16] = 16
    input_tokens_total: int = Field(ge=0)
    cached_input_tokens_total: int = Field(ge=0)
    output_tokens_total: int = Field(ge=0)
    input_tokens_bucket: IFEMPrivateEvaluatorTokenBucketV1
    cached_input_tokens_bucket: IFEMPrivateEvaluatorTokenBucketV1
    output_tokens_bucket: IFEMPrivateEvaluatorTokenBucketV1

    @model_validator(mode="after")
    def validate_summary(self) -> Self:
        if self.cached_input_tokens_total > self.input_tokens_total:
            raise ValueError("cached token total cannot exceed the input token total")
        if self.input_tokens_bucket is not _token_bucket(self.input_tokens_total):
            raise ValueError("input token bucket does not match the total")
        if self.cached_input_tokens_bucket is not _token_bucket(self.cached_input_tokens_total):
            raise ValueError("cached token bucket does not match the total")
        if self.output_tokens_bucket is not _token_bucket(self.output_tokens_total):
            raise ValueError("output token bucket does not match the total")
        return self


class IFEMPrivateEvaluatorProtocolBindingV1(ContractModel):
    """Public revision binding for a D33 aggregate, without any operator material."""

    schema_version: Literal["autolean.ifem-private-evaluator-protocol-binding.v1"] = (
        "autolean.ifem-private-evaluator-protocol-binding.v1"
    )
    protocol_id: Literal["d32-v1", "d34-v2", "d35-v3"]
    profile_content_sha256: str = Field(pattern=_SHA256)
    request_policy_content_sha256: str = Field(pattern=_SHA256)
    response_contract: IFEMSyntheticRoleResponseContractV1


class IFEMPrivateEvaluatorPublicReportV1(ContractModel):
    """Public-safe D33 role/risk aggregate with an explicit non-promotion boundary."""

    schema_version: Literal[
        "autolean.ifem-private-evaluator-public-report.v1",
        "autolean.ifem-private-evaluator-public-report.v2",
    ] = "autolean.ifem-private-evaluator-public-report.v1"
    fixture_content_sha256: str = Field(pattern=_SHA256)
    case_count: Literal[16] = 16
    private_rebuild_verified: Literal[True] = True
    witness_validation_recomputed: Literal[True] = True
    private_manifest_recovered: Literal[True] = True
    role_aggregates: tuple[IFEMPrivateEvaluatorRoleAggregateV1, ...] = Field(
        min_length=3,
        max_length=3,
    )
    risk_aggregates: tuple[IFEMPrivateEvaluatorRiskAggregateV1, ...] = Field(
        min_length=8,
        max_length=8,
    )
    token_usage: IFEMPrivateEvaluatorTokenUsageSummaryV1
    authority: IFEMPrivateEvaluatorAuthorityV1 = Field(
        default_factory=IFEMPrivateEvaluatorAuthorityV1
    )
    protocol_binding: IFEMPrivateEvaluatorProtocolBindingV1 | None = None
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_report(self) -> Self:
        expected_roles = tuple(sorted(IFEMStructuralProbeRoleV1, key=str))
        if tuple(item.role for item in self.role_aggregates) != expected_roles:
            raise ValueError("role aggregates do not use canonical complete role order")
        expected_risks = tuple(sorted(IFEMStructuralRiskV1, key=str))
        if tuple(item.risk for item in self.risk_aggregates) != expected_risks:
            raise ValueError("risk aggregates do not use canonical complete risk order")
        for name in (
            "correct_count",
            "incorrect_count",
            "abstention_count",
            "invalid_count",
        ):
            role_total = sum(getattr(item, name) for item in self.role_aggregates)
            risk_total = sum(getattr(item, name) for item in self.risk_aggregates)
            if role_total != risk_total:
                raise ValueError("role and risk aggregate totals disagree")
        if sum(item.case_count for item in self.role_aggregates) != self.case_count:
            raise ValueError("role aggregates do not cover the complete fixture")
        if sum(cast(int, item.case_count) for item in self.risk_aggregates) != self.case_count:
            raise ValueError("risk aggregates do not cover the complete fixture")
        if self.authority != IFEMPrivateEvaluatorAuthorityV1():
            raise ValueError("private evaluator authority flags are not fixed")
        if (
            self.schema_version == "autolean.ifem-private-evaluator-public-report.v1"
            and self.protocol_binding is not None
        ):
            raise ValueError("legacy D33 report must not contain a protocol binding")
        if (
            self.schema_version == "autolean.ifem-private-evaluator-public-report.v2"
            and self.protocol_binding is None
        ):
            raise ValueError("revision-bound D33 report requires a protocol binding")
        if self.content_sha256 != self.computed_content_sha256():
            raise ValueError("private evaluator report content hash does not match its payload")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(
            dict[str, object],
            self.model_dump(mode="json", exclude={"content_sha256"}, exclude_none=True),
        )

    def computed_content_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.content_payload())).hexdigest()

    @property
    def is_promotable(self) -> Literal[False]:
        return False


@dataclass(frozen=True, slots=True)
class _PrivateCaseOutcome:
    """Private-only derived outcome; no raw output text is retained after parsing."""

    role: IFEMStructuralProbeRoleV1
    risk: IFEMStructuralRiskV1
    mutation: IFEMStructuralMutationV1
    status: IFEMPrivateEvaluationParseStatusV1
    correct: bool
    usage: TokenUsage


@runtime_checkable
class _IFEMPrivateEvaluatorLedger(Protocol):
    """The authenticated private-ledger read surface required by D33."""

    def read_manifest(
        self,
        fixture: IFEMSyntheticRolePublicFixtureV1,
        prepared_requests: Iterable[IFEMSyntheticRolePreparedRequestV1],
    ) -> IFEMSyntheticRolePrivateManifestV1: ...

    def recover_execution(
        self,
        prepared: IFEMSyntheticRolePreparedRequestV1,
    ) -> IFEMSyntheticRoleExecutionV1: ...


def build_ifem_private_evaluator_protocol_binding(
    *,
    protocol_id: str,
    profile_bytes: bytes,
    request_policy: IFEMSyntheticRoleRequestPolicyV1,
    response_contract: IFEMSyntheticRoleResponseContractV1,
) -> IFEMPrivateEvaluatorProtocolBindingV1:
    """Construct the public-safe revision binding used by a D33 operator report."""

    if not isinstance(profile_bytes, bytes) or not profile_bytes:
        raise IFEMPrivateEvaluatorError("D33 protocol profile bytes are unavailable")
    if protocol_id not in {"d32-v1", "d34-v2", "d35-v3"}:
        raise IFEMPrivateEvaluatorError("D33 protocol identifier is unsupported")
    if type(request_policy) is not IFEMSyntheticRoleRequestPolicyV1:
        raise IFEMPrivateEvaluatorError("D33 protocol request policy has an invalid type")
    if not isinstance(response_contract, IFEMSyntheticRoleResponseContractV1):
        raise IFEMPrivateEvaluatorError("D33 protocol response contract is invalid")
    return IFEMPrivateEvaluatorProtocolBindingV1(
        protocol_id=cast(Literal["d32-v1", "d34-v2", "d35-v3"], protocol_id),
        profile_content_sha256=hashlib.sha256(profile_bytes).hexdigest(),
        request_policy_content_sha256=_request_policy_content_sha256(request_policy),
        response_contract=response_contract,
    )


def _request_policy_content_sha256(policy: IFEMSyntheticRoleRequestPolicyV1) -> str:
    policy_payload = {
        "schema_version": "autolean.ifem-deepseek-role-request-policy.v1",
        "max_input_tokens": policy.max_input_tokens,
        "max_output_tokens": policy.max_output_tokens,
        "reasoning_effort": policy.reasoning_effort,
        "require_usage_accounting": policy.require_usage_accounting,
    }
    return hashlib.sha256(canonical_json_bytes(policy_payload)).hexdigest()


def _validate_protocol_binding(
    binding: IFEMPrivateEvaluatorProtocolBindingV1 | None,
    *,
    profile_bytes: bytes | None,
    request_policy: IFEMSyntheticRoleRequestPolicyV1,
    response_contract: IFEMSyntheticRoleResponseContractV1,
) -> IFEMPrivateEvaluatorProtocolBindingV1 | None:
    if binding is None:
        return None
    if type(binding) is not IFEMPrivateEvaluatorProtocolBindingV1:
        raise IFEMPrivateEvaluatorError("D33 protocol binding has an invalid type")
    try:
        verified = IFEMPrivateEvaluatorProtocolBindingV1.model_validate(
            binding.model_dump(mode="json")
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise IFEMPrivateEvaluatorError("D33 protocol binding failed revalidation") from error
    if profile_bytes is None:
        raise IFEMPrivateEvaluatorError("D33 protocol binding lacks exact profile bytes")
    expected = build_ifem_private_evaluator_protocol_binding(
        protocol_id=verified.protocol_id,
        profile_bytes=profile_bytes,
        request_policy=request_policy,
        response_contract=response_contract,
    )
    if verified != expected:
        raise IFEMPrivateEvaluatorError("D33 protocol binding differs from the rebuilt request")
    return verified


def evaluate_ifem_private_role_run(
    *,
    fixture: IFEMSyntheticRolePublicFixtureV1,
    oracle: IFEMSyntheticRolePrivateOracleV1,
    corpus: IFEMStructuralRoleProbeCorpusV1,
    graph: IFEMCandidateDependencyGraphV1,
    witness_report: IFEMStructuralWitnessValidationReportV1,
    operator_seed: bytes | str,
    ledger: _IFEMPrivateEvaluatorLedger,
    preparation_executor: IFEMSyntheticRoleExecutor,
    request_policy: IFEMSyntheticRoleRequestPolicyV1 | None = None,
    response_contract: IFEMSyntheticRoleResponseContractV1 = (
        IFEMSyntheticRoleResponseContractV1.SELECTED_OPTION_AND_REASON_V1
    ),
    profile_bytes: bytes | None = None,
    protocol_binding: IFEMPrivateEvaluatorProtocolBindingV1 | None = None,
) -> IFEMPrivateEvaluatorPublicReportV1:
    """Rebuild and evaluate one complete private 16-case run without public side labels."""

    if not isinstance(ledger, _IFEMPrivateEvaluatorLedger):
        raise IFEMPrivateEvaluatorError(
            "D33 requires an authenticated private ledger with manifest recovery"
        )
    if not isinstance(preparation_executor, IFEMSyntheticRoleExecutor):
        raise IFEMPrivateEvaluatorError("D33 requires an exact preparation executor")
    effective_policy = request_policy or IFEMSyntheticRoleRequestPolicyV1()
    if type(effective_policy) is not IFEMSyntheticRoleRequestPolicyV1:
        raise IFEMPrivateEvaluatorError("D33 request policy has an invalid type")
    if not isinstance(response_contract, IFEMSyntheticRoleResponseContractV1):
        raise IFEMPrivateEvaluatorError("D33 response contract is invalid")
    binding = _validate_protocol_binding(
        protocol_binding,
        profile_bytes=profile_bytes,
        request_policy=effective_policy,
        response_contract=response_contract,
    )

    expected_corpus = _rebuild_corpus(corpus=corpus, graph=graph)
    expected_fixture = build_ifem_synthetic_role_fixture(
        expected_corpus,
        operator_seed=operator_seed,
    )
    expected_oracle = build_ifem_synthetic_role_oracle(
        expected_corpus,
        operator_seed=operator_seed,
    )
    if _revalidate_fixture(fixture) != expected_fixture:
        raise IFEMPrivateEvaluatorError(
            "public fixture differs from the private corpus/seed rebuild"
        )
    if _revalidate_oracle(oracle) != expected_oracle:
        raise IFEMPrivateEvaluatorError("private oracle differs from the corpus/seed rebuild")
    try:
        verify_ifem_structural_witness_validation_report(
            witness_report,
            corpus=expected_corpus,
            graph=graph,
        )
        build_ifem_role_reconciliation(
            expected_fixture,
            expected_oracle,
            expected_corpus,
            operator_seed=operator_seed,
        )
    except (IFEMRoleReconciliationError, ValueError) as error:
        raise IFEMPrivateEvaluatorError(
            "D33 private inputs did not pass independent witness/reconciliation rebuild"
        ) from error

    prepared = tuple(
        prepare(
            expected_fixture,
            case.case_id,
            preparation_executor,
            request_policy=effective_policy,
            response_contract=response_contract,
        )
        for case in expected_fixture.cases
    )
    try:
        manifest = ledger.read_manifest(expected_fixture, prepared)
    except Exception as error:
        raise IFEMPrivateEvaluatorError("private iFEM manifest cannot be recovered") from error
    if (
        type(manifest) is not IFEMSyntheticRolePrivateManifestV1
        or manifest.fixture_content_sha256 != expected_fixture.content_sha256
        or len(manifest.entries) != _CASE_COUNT
    ):
        raise IFEMPrivateEvaluatorError("private iFEM manifest is not a complete rebuilt run")

    records_by_case = {record.public_case_id: record for record in expected_oracle.records}
    pairs_by_id = {pair.pair_id: pair for pair in expected_corpus.pairs}
    outcomes: list[_PrivateCaseOutcome] = []
    for request in prepared:
        try:
            execution = ledger.recover_execution(request)
            output = execution.output
        except Exception as error:
            raise IFEMPrivateEvaluatorError("private iFEM response cannot be recovered") from error
        record = records_by_case.get(request.case_id)
        if record is None:
            raise IFEMPrivateEvaluatorError("rebuilt private oracle is missing a prepared case")
        pair = pairs_by_id.get(record.source_pair_id)
        if (
            pair is None
            or pair.probe_role is not request.role
            or pair.probe_role is not record.role
            or pair.risk.value != record.risk
            or pair.mutation.value != record.mutation
            or pair.pair_sha256 != record.pair_sha256
        ):
            raise IFEMPrivateEvaluatorError(
                "private oracle is not bound to the rebuilt probe corpus"
            )
        if not isinstance(output.usage, TokenUsage):
            raise IFEMPrivateEvaluatorError("private response usage is invalid")
        status, selected_option = (
            (IFEMPrivateEvaluationParseStatusV1.INVALID, None)
            if output.tool_calls
            else _parse_strict_selected_option(output.text)
        )
        outcomes.append(
            _PrivateCaseOutcome(
                role=request.role,
                risk=pair.risk,
                mutation=pair.mutation,
                status=status,
                correct=(
                    status is IFEMPrivateEvaluationParseStatusV1.SELECTED_OPTION
                    and selected_option is record.baseline_option
                ),
                usage=output.usage,
            )
        )

    if len(outcomes) != _CASE_COUNT:
        raise IFEMPrivateEvaluatorError("private evaluator did not recover every fixture case")
    payload: dict[str, object] = {
        "schema_version": (
            "autolean.ifem-private-evaluator-public-report.v2"
            if binding is not None
            else "autolean.ifem-private-evaluator-public-report.v1"
        ),
        "fixture_content_sha256": expected_fixture.content_sha256,
        "case_count": _CASE_COUNT,
        "private_rebuild_verified": True,
        "witness_validation_recomputed": True,
        "private_manifest_recovered": True,
        "role_aggregates": [
            _role_aggregate(outcomes, role).model_dump(mode="json")
            for role in sorted(IFEMStructuralProbeRoleV1, key=str)
        ],
        "risk_aggregates": [
            _risk_aggregate(outcomes, risk).model_dump(mode="json")
            for risk in sorted(IFEMStructuralRiskV1, key=str)
        ],
        "token_usage": _usage_summary(outcomes).model_dump(mode="json"),
        "authority": IFEMPrivateEvaluatorAuthorityV1().model_dump(mode="json"),
    }
    if binding is not None:
        payload["protocol_binding"] = binding.model_dump(mode="json")
    payload["content_sha256"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    try:
        return IFEMPrivateEvaluatorPublicReportV1.model_validate(payload)
    except ValueError as error:
        raise IFEMPrivateEvaluatorError("D33 public report did not validate") from error


def render_ifem_private_evaluator_public_report(
    report: IFEMPrivateEvaluatorPublicReportV1,
    *,
    fixture: IFEMSyntheticRolePublicFixtureV1,
    oracle: IFEMSyntheticRolePrivateOracleV1,
    corpus: IFEMStructuralRoleProbeCorpusV1,
    graph: IFEMCandidateDependencyGraphV1,
    witness_report: IFEMStructuralWitnessValidationReportV1,
    operator_seed: bytes | str,
    ledger: _IFEMPrivateEvaluatorLedger,
    preparation_executor: IFEMSyntheticRoleExecutor,
    request_policy: IFEMSyntheticRoleRequestPolicyV1 | None = None,
    response_contract: IFEMSyntheticRoleResponseContractV1 = (
        IFEMSyntheticRoleResponseContractV1.SELECTED_OPTION_AND_REASON_V1
    ),
    profile_bytes: bytes | None = None,
    protocol_binding: IFEMPrivateEvaluatorProtocolBindingV1 | None = None,
) -> bytes:
    """Rebuild all private inputs before serializing a public D33 report."""

    if type(report) is not IFEMPrivateEvaluatorPublicReportV1:
        raise IFEMPrivateEvaluatorError("D33 report must use the exact public report type")
    try:
        verified = IFEMPrivateEvaluatorPublicReportV1.model_validate(report.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as error:
        raise IFEMPrivateEvaluatorError("D33 public report failed revalidation") from error
    expected = evaluate_ifem_private_role_run(
        fixture=fixture,
        oracle=oracle,
        corpus=corpus,
        graph=graph,
        witness_report=witness_report,
        operator_seed=operator_seed,
        ledger=ledger,
        preparation_executor=preparation_executor,
        request_policy=request_policy,
        response_contract=response_contract,
        profile_bytes=profile_bytes,
        protocol_binding=protocol_binding,
    )
    if verified != expected:
        raise IFEMPrivateEvaluatorError("D33 report differs from the private evaluator rebuild")
    rendered = canonical_json_bytes(verified.model_dump(mode="json", exclude_none=True)) + b"\n"
    if any(marker in rendered.lower() for marker in _FORBIDDEN_PUBLIC_MARKERS):
        raise IFEMPrivateEvaluatorError("D33 public report contains private material")
    return rendered


def write_ifem_private_evaluator_public_report(
    *,
    cache_root: Path,
    output_path: Path,
    report: IFEMPrivateEvaluatorPublicReportV1,
    fixture: IFEMSyntheticRolePublicFixtureV1,
    oracle: IFEMSyntheticRolePrivateOracleV1,
    corpus: IFEMStructuralRoleProbeCorpusV1,
    graph: IFEMCandidateDependencyGraphV1,
    witness_report: IFEMStructuralWitnessValidationReportV1,
    operator_seed: bytes | str,
    ledger: _IFEMPrivateEvaluatorLedger,
    preparation_executor: IFEMSyntheticRoleExecutor,
    request_policy: IFEMSyntheticRoleRequestPolicyV1 | None = None,
    response_contract: IFEMSyntheticRoleResponseContractV1 = (
        IFEMSyntheticRoleResponseContractV1.SELECTED_OPTION_AND_REASON_V1
    ),
    profile_bytes: bytes | None = None,
    protocol_binding: IFEMPrivateEvaluatorProtocolBindingV1 | None = None,
) -> None:
    """Atomically persist only the exact report rebuilt from private evidence."""

    serialized = render_ifem_private_evaluator_public_report(
        report,
        fixture=fixture,
        oracle=oracle,
        corpus=corpus,
        graph=graph,
        witness_report=witness_report,
        operator_seed=operator_seed,
        ledger=ledger,
        preparation_executor=preparation_executor,
        request_policy=request_policy,
        response_contract=response_contract,
        profile_bytes=profile_bytes,
        protocol_binding=protocol_binding,
    )
    try:
        root = cache_root.resolve(strict=True)
    except OSError as error:
        raise IFEMPrivateEvaluatorError("D33 cache root does not exist") from error
    if not root.is_dir():
        raise IFEMPrivateEvaluatorError("D33 cache root must be a directory")
    target = output_path.resolve(strict=False)
    try:
        target.relative_to(root)
    except ValueError as error:
        raise IFEMPrivateEvaluatorError(
            "D33 report output must stay below its cache root"
        ) from error
    if target.name != IFEM_PRIVATE_EVALUATOR_PUBLIC_REPORT_FILENAME:
        raise IFEMPrivateEvaluatorError(
            "D33 report output must use the canonical artifact filename"
        )

    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.",
        suffix=".tmp",
        dir=target.parent,
    )
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(serialized)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_name, target)
    except OSError as error:
        with suppress(OSError):
            Path(temporary_name).unlink(missing_ok=True)
        raise IFEMPrivateEvaluatorError("cannot write D33 public report") from error


def _rebuild_corpus(
    *,
    corpus: IFEMStructuralRoleProbeCorpusV1,
    graph: IFEMCandidateDependencyGraphV1,
) -> IFEMStructuralRoleProbeCorpusV1:
    if type(corpus) is not IFEMStructuralRoleProbeCorpusV1:
        raise IFEMPrivateEvaluatorError("D33 requires the exact private probe corpus type")
    try:
        verified = IFEMStructuralRoleProbeCorpusV1.model_validate(corpus.model_dump(mode="json"))
        expected = build_ifem_structural_role_probe_corpus(catalog=verified.catalog, graph=graph)
    except (AttributeError, TypeError, ValueError) as error:
        raise IFEMPrivateEvaluatorError(
            "private probe corpus failed graph-bound rebuild"
        ) from error
    if verified != expected:
        raise IFEMPrivateEvaluatorError("private probe corpus differs from the graph-bound rebuild")
    return expected


def _revalidate_fixture(
    fixture: IFEMSyntheticRolePublicFixtureV1,
) -> IFEMSyntheticRolePublicFixtureV1:
    if type(fixture) is not IFEMSyntheticRolePublicFixtureV1:
        raise IFEMPrivateEvaluatorError("D33 fixture must use the exact public fixture type")
    try:
        return IFEMSyntheticRolePublicFixtureV1.model_validate(fixture.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as error:
        raise IFEMPrivateEvaluatorError("D33 public fixture failed revalidation") from error


def _revalidate_oracle(
    oracle: IFEMSyntheticRolePrivateOracleV1,
) -> IFEMSyntheticRolePrivateOracleV1:
    if type(oracle) is not IFEMSyntheticRolePrivateOracleV1:
        raise IFEMPrivateEvaluatorError("D33 oracle must use the exact private oracle type")
    try:
        return IFEMSyntheticRolePrivateOracleV1.model_validate(oracle.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as error:
        raise IFEMPrivateEvaluatorError("D33 private oracle failed revalidation") from error


def _parse_strict_selected_option(
    text: str,
) -> tuple[IFEMPrivateEvaluationParseStatusV1, IFEMSyntheticRoleOptionV1 | None]:
    """Accept exactly one JSON selected_option field; no aliases or bare strings."""

    try:
        parsed = json.loads(text, object_pairs_hook=_reject_duplicate_json_object_keys)
    except (TypeError, ValueError):
        return IFEMPrivateEvaluationParseStatusV1.INVALID, None
    if not isinstance(parsed, dict) or set(parsed) != {"selected_option"}:
        return IFEMPrivateEvaluationParseStatusV1.INVALID, None
    selected = parsed["selected_option"]
    if selected == IFEMSyntheticRolePredictionV1.ABSTAIN.value:
        return IFEMPrivateEvaluationParseStatusV1.ABSTAIN, None
    if selected == IFEMSyntheticRoleOptionV1.A.value:
        return IFEMPrivateEvaluationParseStatusV1.SELECTED_OPTION, IFEMSyntheticRoleOptionV1.A
    if selected == IFEMSyntheticRoleOptionV1.B.value:
        return IFEMPrivateEvaluationParseStatusV1.SELECTED_OPTION, IFEMSyntheticRoleOptionV1.B
    return IFEMPrivateEvaluationParseStatusV1.INVALID, None


def _reject_duplicate_json_object_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _role_aggregate(
    outcomes: Iterable[_PrivateCaseOutcome],
    role: IFEMStructuralProbeRoleV1,
) -> IFEMPrivateEvaluatorRoleAggregateV1:
    selected = tuple(item for item in outcomes if item.role is role)
    return IFEMPrivateEvaluatorRoleAggregateV1(
        role=role,
        case_count=len(selected),
        correct_count=sum(item.correct for item in selected),
        incorrect_count=sum(
            item.status is IFEMPrivateEvaluationParseStatusV1.SELECTED_OPTION and not item.correct
            for item in selected
        ),
        abstention_count=sum(
            item.status is IFEMPrivateEvaluationParseStatusV1.ABSTAIN for item in selected
        ),
        invalid_count=sum(
            item.status is IFEMPrivateEvaluationParseStatusV1.INVALID for item in selected
        ),
    )


def _risk_aggregate(
    outcomes: Iterable[_PrivateCaseOutcome],
    risk: IFEMStructuralRiskV1,
) -> IFEMPrivateEvaluatorRiskAggregateV1:
    selected = tuple(item for item in outcomes if item.risk is risk)
    mutations = {item.mutation for item in selected}
    if len(selected) != 2 or len(mutations) != 1:
        raise IFEMPrivateEvaluatorError(
            "rebuilt risk family does not have two consistent mutations"
        )
    return IFEMPrivateEvaluatorRiskAggregateV1(
        risk=risk,
        mutation=next(iter(mutations)),
        correct_count=sum(item.correct for item in selected),
        incorrect_count=sum(
            item.status is IFEMPrivateEvaluationParseStatusV1.SELECTED_OPTION and not item.correct
            for item in selected
        ),
        abstention_count=sum(
            item.status is IFEMPrivateEvaluationParseStatusV1.ABSTAIN for item in selected
        ),
        invalid_count=sum(
            item.status is IFEMPrivateEvaluationParseStatusV1.INVALID for item in selected
        ),
    )


def _usage_summary(
    outcomes: Iterable[_PrivateCaseOutcome],
) -> IFEMPrivateEvaluatorTokenUsageSummaryV1:
    usages = tuple(item.usage for item in outcomes)
    if len(usages) != _CASE_COUNT:
        raise IFEMPrivateEvaluatorError("usage may be projected only for the complete 16-case run")
    input_total = sum(item.input_tokens for item in usages)
    cached_total = sum(item.cached_input_tokens for item in usages)
    output_total = sum(item.output_tokens for item in usages)
    return IFEMPrivateEvaluatorTokenUsageSummaryV1(
        input_tokens_total=input_total,
        cached_input_tokens_total=cached_total,
        output_tokens_total=output_total,
        input_tokens_bucket=_token_bucket(input_total),
        cached_input_tokens_bucket=_token_bucket(cached_total),
        output_tokens_bucket=_token_bucket(output_total),
    )


def _token_bucket(value: int) -> IFEMPrivateEvaluatorTokenBucketV1:
    if value == 0:
        return IFEMPrivateEvaluatorTokenBucketV1.ZERO
    if value <= 255:
        return IFEMPrivateEvaluatorTokenBucketV1.ONE_TO_255
    if value <= 1023:
        return IFEMPrivateEvaluatorTokenBucketV1.TWO_HUNDRED_FIFTY_SIX_TO_1023
    if value <= 4095:
        return IFEMPrivateEvaluatorTokenBucketV1.ONE_THOUSAND_TWENTY_FOUR_TO_4095
    return IFEMPrivateEvaluatorTokenBucketV1.FOUR_THOUSAND_NINETY_SIX_PLUS


__all__ = [
    "IFEM_PRIVATE_EVALUATOR_PUBLIC_REPORT_FILENAME",
    "IFEMPrivateEvaluationParseStatusV1",
    "IFEMPrivateEvaluatorAuthorityV1",
    "IFEMPrivateEvaluatorError",
    "IFEMPrivateEvaluatorProtocolBindingV1",
    "IFEMPrivateEvaluatorPublicReportV1",
    "IFEMPrivateEvaluatorRiskAggregateV1",
    "IFEMPrivateEvaluatorRoleAggregateV1",
    "IFEMPrivateEvaluatorTokenBucketV1",
    "IFEMPrivateEvaluatorTokenUsageSummaryV1",
    "build_ifem_private_evaluator_protocol_binding",
    "evaluate_ifem_private_role_run",
    "render_ifem_private_evaluator_public_report",
    "write_ifem_private_evaluator_public_report",
]
