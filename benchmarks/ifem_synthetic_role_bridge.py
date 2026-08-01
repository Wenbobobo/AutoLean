"""Provider-neutral bridge for the public iFEM synthetic-role fixture.

This module is intentionally independent of ``authorized_role_bridge``.  It exposes a
small request/execute/evaluate surface for the sixteen public synthetic prompts:

* ``prepare`` validates the public fixture and obtains one exact canonical body from an
  injected executor;
* ``execute`` hands that exact byte string to the executor and requires a matching body
  binding in its response acknowledgement;
* ``evaluate`` joins a private oracle only in evaluator memory; and
* ``receipt`` emits request-bound, non-promotable evidence.

The bridge is calibration plumbing, not a benchmark authority, statement freezer, or
Prover handoff.  Prompt bytes, model output, response identifiers, credentials, and
private oracle records are deliberately absent from the public receipt.  Until an
authenticated operator-private output sidecar exists, the receipt also omits hashes of
model output and response identifiers: those values are low entropy and a plain digest
would be reversible by enumeration.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Final, Literal, Protocol, cast, runtime_checkable

from autolean_builder.ifem_structural_role_probes import IFEMStructuralProbeRoleV1
from autolean_contracts import (
    DigestV1,
    HashKindV1,
    OutboundRequestBodyV1,
    StableIdentifierV1,
    canonical_json_bytes,
    digest_bytes,
    digest_model,
    digest_text,
)
from autolean_contracts.base import ContractModel
from autolean_contracts.hashing import require_digest_kind
from autolean_prover.providers import (
    CanonicalJsonRequestBody,
    Capability,
    ModelRequest,
    TokenUsage,
    ToolCall,
)
from pydantic import Field

from benchmarks.ifem_synthetic_role_fixture import (
    IFEMSyntheticRoleOptionV1,
    IFEMSyntheticRolePrivateOracleV1,
    IFEMSyntheticRolePublicCaseV1,
    IFEMSyntheticRolePublicFixtureV1,
    render_ifem_synthetic_role_fixture,
)

_SHA256 = r"^[0-9a-f]{64}$"
_IDENTIFIER = r"^[a-z][a-z0-9_.-]{0,127}$"
_MAX_OUTPUT_TOKENS = 65_536
_FORBIDDEN_BODY_MARKERS: Final[tuple[str, ...]] = (
    "authorization",
    "api_key",
    "credential",
    "private",
    "secret",
    "oracle",
    "baseline",
    "mutant",
    "witness",
)
_FORBIDDEN_RECEIPT_MARKERS: Final[tuple[bytes, ...]] = (
    b"private-oracle",
    b"secret-token",
    b"authorization:",
    b'"prompt":',
    b'"oracle":',
    b'"secret":',
    b'"output_digest":',
    b'"response_id_digest":',
    b"model_output_commitment",
)
_ROLE_SYSTEM_PROMPTS_V1: Final[Mapping[IFEMStructuralProbeRoleV1, str]] = MappingProxyType(
    {
        IFEMStructuralProbeRoleV1.STATEMENT_FORMALIZER: (
            "AutoLean synthetic-role calibration; act as the statement formalizer. "
            "Compare the two options literally and return JSON with selected_option and reason."
        ),
        IFEMStructuralProbeRoleV1.FIDELITY_REVIEWER: (
            "AutoLean synthetic-role calibration; act as the fidelity reviewer. "
            "Compare the two options literally and return JSON with selected_option and reason."
        ),
        IFEMStructuralProbeRoleV1.CHEATING_SUPERVISOR: (
            "AutoLean synthetic-role calibration; act as the cheating supervisor. "
            "Compare the two options literally and return JSON with selected_option and reason."
        ),
    }
)
_ROLE_SYSTEM_PROMPTS_V2: Final[Mapping[IFEMStructuralProbeRoleV1, str]] = MappingProxyType(
    {
        IFEMStructuralProbeRoleV1.STATEMENT_FORMALIZER: (
            "AutoLean synthetic-role calibration; act as the statement formalizer. "
            "Compare the two options literally. Return exactly one JSON object with exactly "
            "one selected_option field whose value is option_a, option_b, or abstain."
        ),
        IFEMStructuralProbeRoleV1.FIDELITY_REVIEWER: (
            "AutoLean synthetic-role calibration; act as the fidelity reviewer. "
            "Compare the two options literally. Return exactly one JSON object with exactly "
            "one selected_option field whose value is option_a, option_b, or abstain."
        ),
        IFEMStructuralProbeRoleV1.CHEATING_SUPERVISOR: (
            "AutoLean synthetic-role calibration; act as the cheating supervisor. "
            "Compare the two options literally. Return exactly one JSON object with exactly "
            "one selected_option field whose value is option_a, option_b, or abstain."
        ),
    }
)


class IFEMSyntheticRoleBridgeError(ValueError):
    """The synthetic role bridge crossed an input, egress, or authority boundary."""


class IFEMSyntheticRoleResponseContractV1(StrEnum):
    """Closed response syntax revisions for the iFEM synthetic-role prompt."""

    SELECTED_OPTION_AND_REASON_V1 = "selected_option_and_reason.v1"
    SELECTED_OPTION_ONLY_V2 = "selected_option_only.v2"


@dataclass(frozen=True, slots=True)
class IFEMSyntheticRoleRequestPolicyV1:
    """In-memory generation policy bound by the logical request and exact provider body."""

    max_input_tokens: int = 4096
    max_output_tokens: int = 1024
    reasoning_effort: str | None = None
    require_usage_accounting: bool = False

    def __post_init__(self) -> None:
        for label, value, upper_bound in (
            ("max_input_tokens", self.max_input_tokens, 65_536),
            ("max_output_tokens", self.max_output_tokens, _MAX_OUTPUT_TOKENS),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 1
                or value > upper_bound
            ):
                raise IFEMSyntheticRoleBridgeError(f"{label} is outside the supported bound")
        if self.reasoning_effort not in {None, "low", "medium", "high", "max"}:
            raise IFEMSyntheticRoleBridgeError("reasoning_effort is outside the supported policy")
        if not isinstance(self.require_usage_accounting, bool):
            raise IFEMSyntheticRoleBridgeError("require_usage_accounting must be a boolean")


class IFEMSyntheticRolePredictionV1(StrEnum):
    """Evaluator vocabulary; ``abstain`` is used for malformed or missing output."""

    OPTION_A = "option_a"
    OPTION_B = "option_b"
    ABSTAIN = "abstain"


class IFEMSyntheticRoleReceiptAuthorityV1(ContractModel):
    """Hard-negative authority boundary for synthetic calibration receipts."""

    schema_version: Literal["autolean.ifem-synthetic-role-receipt-authority.v1"] = (
        "autolean.ifem-synthetic-role-receipt-authority.v1"
    )
    model_egress_authorized: Literal[False] = False
    semantic_equivalence_claimed: Literal[False] = False
    benchmark_authority: Literal[False] = False
    statement_contract_created: Literal[False] = False
    freeze_allowed: Literal[False] = False
    prover_handoff_allowed: Literal[False] = False
    promotion_allowed: Literal[False] = False


class IFEMSyntheticRoleReceiptV1(ContractModel):
    """Public-safe request evidence with no output or private-oracle commitment."""

    schema_version: Literal["autolean.ifem-synthetic-role-receipt.v1"] = (
        "autolean.ifem-synthetic-role-receipt.v1"
    )
    fixture_content_sha256: str = Field(pattern=_SHA256)
    case_id: StableIdentifierV1
    role: IFEMStructuralProbeRoleV1
    prompt_digest: DigestV1
    logical_request_digest: DigestV1
    request_body_binding: OutboundRequestBodyV1
    provider_id: str = Field(pattern=_IDENTIFIER)
    model_id: str = Field(min_length=1, max_length=256)
    provider_configuration_digest: DigestV1
    authority: IFEMSyntheticRoleReceiptAuthorityV1 = Field(
        default_factory=IFEMSyntheticRoleReceiptAuthorityV1
    )
    content_sha256: str = Field(pattern=_SHA256)

    @classmethod
    def _validated_payload(cls, value: object) -> IFEMSyntheticRoleReceiptV1:
        if type(value) is not cls:
            raise IFEMSyntheticRoleBridgeError("receipt must use the exact receipt type")
        try:
            return cls.model_validate(value.model_dump(mode="json"))
        except (TypeError, ValueError) as error:
            raise IFEMSyntheticRoleBridgeError("receipt failed revalidation") from error

    @property
    def body_binding(self) -> OutboundRequestBodyV1:
        """Compatibility-friendly accessor for the exact prepared body binding."""

        return self.request_body_binding

    def content_payload(self) -> dict[str, object]:
        return cast(
            dict[str, object],
            self.model_dump(mode="json", exclude={"content_sha256"}),
        )

    def computed_content_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.content_payload())).hexdigest()

    @property
    def is_promotable(self) -> Literal[False]:
        return False

    @property
    def is_benchmark_authority(self) -> Literal[False]:
        return False

    @property
    def is_prover_handoff(self) -> Literal[False]:
        return False

    @property
    def is_freeze_authority(self) -> Literal[False]:
        return False

    @staticmethod
    def _validate_digest_kinds(value: IFEMSyntheticRoleReceiptV1) -> None:
        for raw_digest, expected, name in (
            (value.prompt_digest, HashKindV1.PROMPT, "prompt_digest"),
            (value.logical_request_digest, HashKindV1.PROMPT, "logical_request_digest"),
            (
                value.provider_configuration_digest,
                HashKindV1.CONFIG,
                "provider_configuration_digest",
            ),
        ):
            try:
                digest = DigestV1.model_validate(
                    raw_digest.model_dump(mode="json")
                    if isinstance(raw_digest, DigestV1)
                    else raw_digest
                )
                require_digest_kind(digest, expected, name)
            except (TypeError, ValueError, AttributeError) as error:
                raise IFEMSyntheticRoleBridgeError(str(error)) from error

    def model_post_init(self, __context: object) -> None:
        super().model_post_init(__context)
        self._validate_digest_kinds(self)
        if self.content_sha256 != self.computed_content_sha256():
            raise ValueError("synthetic role receipt content hash does not match its payload")


def ifem_synthetic_role_system_prompt(
    role: IFEMStructuralProbeRoleV1,
    *,
    response_contract: IFEMSyntheticRoleResponseContractV1 = (
        IFEMSyntheticRoleResponseContractV1.SELECTED_OPTION_AND_REASON_V1
    ),
) -> str:
    """Return the fixed, non-oracle system prompt for one closed role."""

    if not isinstance(response_contract, IFEMSyntheticRoleResponseContractV1):
        raise IFEMSyntheticRoleBridgeError("response contract is outside the fixed vocabulary")
    prompts = (
        _ROLE_SYSTEM_PROMPTS_V1
        if response_contract is IFEMSyntheticRoleResponseContractV1.SELECTED_OPTION_AND_REASON_V1
        else _ROLE_SYSTEM_PROMPTS_V2
    )
    try:
        return prompts[role]
    except (KeyError, TypeError) as error:
        raise IFEMSyntheticRoleBridgeError(
            "role is outside the fixed calibration vocabulary"
        ) from error


@dataclass(frozen=True, slots=True)
class IFEMSyntheticRoleModelOutputV1:
    """Transient executor output; never serialize this object as a public receipt."""

    text: str = field(repr=False)
    body_binding: OutboundRequestBodyV1
    provider_id: str
    model_id: str
    response_id: str | None = field(default=None, repr=False)
    usage: TokenUsage = field(default_factory=TokenUsage, repr=False)
    tool_calls: tuple[ToolCall, ...] = field(default_factory=tuple, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.text, str):
            raise IFEMSyntheticRoleBridgeError("executor output text must be a string")
        if not isinstance(self.body_binding, OutboundRequestBodyV1):
            raise IFEMSyntheticRoleBridgeError("executor output must acknowledge its body binding")
        if not self.provider_id or not self.model_id:
            raise IFEMSyntheticRoleBridgeError("executor output identity is required")
        if self.response_id is not None and not isinstance(self.response_id, str):
            raise IFEMSyntheticRoleBridgeError("executor response identifier must be a string")
        if not isinstance(self.usage, TokenUsage):
            raise IFEMSyntheticRoleBridgeError("executor usage must use TokenUsage")
        if not isinstance(self.tool_calls, tuple) or not all(
            isinstance(item, ToolCall) for item in self.tool_calls
        ):
            raise IFEMSyntheticRoleBridgeError("executor tool calls must use ToolCall values")


@runtime_checkable
class IFEMSyntheticRoleExecutor(Protocol):
    """Exact-byte executor implemented by a provider adapter or a test double.

    The protocol intentionally does not inherit ``ModelProvider``.  Existing provider
    contracts remain unchanged; an adapter must explicitly expose the exact bytes it
    sends and acknowledge the binding returned by ``prepare_request_body``.
    """

    @property
    def provider_id(self) -> str: ...

    @property
    def model_id(self) -> str: ...

    @property
    def configuration_hash(self) -> DigestV1: ...

    def prepare_request_body(self, request: ModelRequest) -> CanonicalJsonRequestBody: ...

    def execute_prepared(
        self,
        *,
        request: ModelRequest,
        body: bytes,
        binding: OutboundRequestBodyV1,
    ) -> IFEMSyntheticRoleModelOutputV1: ...


@dataclass(frozen=True, slots=True)
class IFEMSyntheticRolePreparedRequestV1:
    """Ephemeral request state; it contains prompt/body bytes and must stay in process memory."""

    fixture_content_sha256: str
    case_id: StableIdentifierV1
    role: IFEMStructuralProbeRoleV1
    request: ModelRequest
    body: bytes
    body_binding: OutboundRequestBodyV1
    prompt_digest: DigestV1
    logical_request_digest: DigestV1
    provider_id: str
    model_id: str
    provider_configuration_digest: DigestV1

    def __post_init__(self) -> None:
        if (
            not isinstance(self.fixture_content_sha256, str)
            or len(self.fixture_content_sha256) != 64
        ):
            raise IFEMSyntheticRoleBridgeError("prepared request fixture digest is malformed")
        if not isinstance(self.case_id, StableIdentifierV1):
            raise IFEMSyntheticRoleBridgeError("prepared request case id is malformed")
        if not isinstance(self.request, ModelRequest):
            raise IFEMSyntheticRoleBridgeError("prepared request must carry a ModelRequest")
        if not isinstance(self.body, bytes):
            raise IFEMSyntheticRoleBridgeError("prepared request body must be bytes")
        try:
            rebound = OutboundRequestBodyV1.model_validate(
                self.body_binding.model_dump(mode="json")
            )
            actual = digest_bytes(HashKindV1.OUTBOUND_REQUEST_BODY, self.body)
            if rebound.body_hash != actual or rebound.body_size_bytes != len(self.body):
                raise ValueError("body binding does not match body bytes")
        except (TypeError, ValueError) as error:
            raise IFEMSyntheticRoleBridgeError(
                "prepared request body binding is invalid"
            ) from error
        try:
            require_digest_kind(self.prompt_digest, HashKindV1.PROMPT, "prompt_digest")
            require_digest_kind(
                self.provider_configuration_digest,
                HashKindV1.CONFIG,
                "provider_configuration_digest",
            )
        except ValueError as error:
            raise IFEMSyntheticRoleBridgeError(str(error)) from error
        expected_prompt_digest = digest_text(HashKindV1.PROMPT, self.request.prompt)
        if self.prompt_digest != expected_prompt_digest:
            raise IFEMSyntheticRoleBridgeError(
                "prepared request prompt digest does not match prompt"
            )
        if self.logical_request_digest != self.request.outbound_request_hash():
            raise IFEMSyntheticRoleBridgeError(
                "prepared request logical digest does not match request"
            )
        if not self.provider_id or not self.model_id:
            raise IFEMSyntheticRoleBridgeError("prepared request provider identity is required")


@dataclass(frozen=True, slots=True)
class IFEMSyntheticRoleExecutionV1:
    """Transient output plus its prepared request; raw output stays evaluator-private."""

    prepared: IFEMSyntheticRolePreparedRequestV1
    output: IFEMSyntheticRoleModelOutputV1

    def __post_init__(self) -> None:
        if not isinstance(self.prepared, IFEMSyntheticRolePreparedRequestV1):
            raise IFEMSyntheticRoleBridgeError("execution has an invalid prepared request")
        if not isinstance(self.output, IFEMSyntheticRoleModelOutputV1):
            raise IFEMSyntheticRoleBridgeError("execution has an invalid model output")
        if self.output.body_binding != self.prepared.body_binding:
            raise IFEMSyntheticRoleBridgeError(
                "executor output does not acknowledge the exact prepared body binding"
            )
        if self.output.provider_id != self.prepared.provider_id:
            raise IFEMSyntheticRoleBridgeError("executor output provider differs from preparation")
        if self.output.model_id != self.prepared.model_id:
            raise IFEMSyntheticRoleBridgeError("executor output model differs from preparation")


@dataclass(frozen=True, slots=True)
class IFEMSyntheticRoleEvaluationV1:
    """Evaluator-side result; keep this object private when the expected side matters."""

    case_id: StableIdentifierV1
    role: IFEMStructuralProbeRoleV1
    predicted_option: IFEMSyntheticRolePredictionV1
    expected_option: IFEMSyntheticRoleOptionV1
    correct: bool
    parse_error: bool


def prepare(
    fixture: IFEMSyntheticRolePublicFixtureV1,
    case_id: object,
    executor: IFEMSyntheticRoleExecutor,
    *,
    system_prompt: str | None = None,
    request_policy: IFEMSyntheticRoleRequestPolicyV1 | None = None,
    response_contract: IFEMSyntheticRoleResponseContractV1 = (
        IFEMSyntheticRoleResponseContractV1.SELECTED_OPTION_AND_REASON_V1
    ),
    max_output_tokens: int | None = None,
    response_format: Literal["json_object"] | None = "json_object",
) -> IFEMSyntheticRolePreparedRequestV1:
    """Prepare one public case and bind the exact bytes an executor will receive."""

    verified_fixture = _revalidate_public_fixture(fixture)
    case = _find_case(verified_fixture, case_id)
    policy = request_policy or IFEMSyntheticRoleRequestPolicyV1()
    if type(policy) is not IFEMSyntheticRoleRequestPolicyV1:
        raise IFEMSyntheticRoleBridgeError("request policy must use the exact policy type")
    if max_output_tokens is not None:
        policy = IFEMSyntheticRoleRequestPolicyV1(
            max_input_tokens=policy.max_input_tokens,
            max_output_tokens=max_output_tokens,
            reasoning_effort=policy.reasoning_effort,
            require_usage_accounting=policy.require_usage_accounting,
        )
    if not isinstance(system_prompt, (str, type(None))):
        raise IFEMSyntheticRoleBridgeError("system_prompt must be a string or None")
    expected_system_prompt = ifem_synthetic_role_system_prompt(
        case.role,
        response_contract=response_contract,
    )
    if system_prompt is None:
        system_prompt = expected_system_prompt
    elif system_prompt != expected_system_prompt:
        raise IFEMSyntheticRoleBridgeError("system prompt differs from the fixed role policy")
    if response_format != "json_object":
        raise IFEMSyntheticRoleBridgeError("role calibration requires the JSON response format")
    try:
        request = ModelRequest(
            prompt=case.prompt,
            system_prompt=system_prompt,
            max_input_tokens=policy.max_input_tokens,
            max_output_tokens=policy.max_output_tokens,
            reasoning_effort=policy.reasoning_effort,
            response_format=response_format,
            required_capabilities=(
                frozenset({Capability.USAGE_ACCOUNTING})
                if policy.require_usage_accounting
                else frozenset()
            ),
        )
        prepared = executor.prepare_request_body(request)
    except Exception as error:
        if isinstance(error, IFEMSyntheticRoleBridgeError):
            raise
        raise IFEMSyntheticRoleBridgeError("executor could not prepare the request body") from None
    if not isinstance(prepared, CanonicalJsonRequestBody):
        raise IFEMSyntheticRoleBridgeError("executor returned an invalid canonical body")
    _reject_private_body_fields(prepared.body)
    try:
        binding = OutboundRequestBodyV1.model_validate(prepared.binding.model_dump(mode="json"))
        rebound = digest_bytes(HashKindV1.OUTBOUND_REQUEST_BODY, prepared.body)
        if binding.body_hash != rebound or binding.body_size_bytes != len(prepared.body):
            raise ValueError("binding does not match body")
    except (TypeError, ValueError) as error:
        raise IFEMSyntheticRoleBridgeError("executor body binding is not exact") from error
    try:
        configuration_digest = DigestV1.model_validate(
            executor.configuration_hash.model_dump(mode="json")
        )
        require_digest_kind(configuration_digest, HashKindV1.CONFIG, "configuration_hash")
    except (AttributeError, TypeError, ValueError) as error:
        raise IFEMSyntheticRoleBridgeError("executor configuration digest is invalid") from error
    try:
        case_id_payload = case.case_id
    except AttributeError as error:
        raise IFEMSyntheticRoleBridgeError("public case identifier is invalid") from error
    return IFEMSyntheticRolePreparedRequestV1(
        fixture_content_sha256=verified_fixture.content_sha256,
        case_id=case_id_payload,
        role=case.role,
        request=request,
        body=prepared.body,
        body_binding=binding,
        prompt_digest=digest_text(HashKindV1.PROMPT, request.prompt),
        logical_request_digest=request.outbound_request_hash(),
        provider_id=executor.provider_id,
        model_id=executor.model_id,
        provider_configuration_digest=configuration_digest,
    )


def execute(
    prepared: IFEMSyntheticRolePreparedRequestV1,
    executor: IFEMSyntheticRoleExecutor,
) -> IFEMSyntheticRoleExecutionV1:
    """Execute exactly the prepared bytes; this function grants no provider authority."""

    if not isinstance(prepared, IFEMSyntheticRolePreparedRequestV1):
        raise IFEMSyntheticRoleBridgeError("execute requires a prepared request")
    if executor.provider_id != prepared.provider_id or executor.model_id != prepared.model_id:
        raise IFEMSyntheticRoleBridgeError("executor identity differs from preparation")
    if executor.configuration_hash != prepared.provider_configuration_digest:
        raise IFEMSyntheticRoleBridgeError("executor configuration differs from preparation")
    try:
        output = executor.execute_prepared(
            request=prepared.request,
            body=prepared.body,
            binding=prepared.body_binding,
        )
    except IFEMSyntheticRoleBridgeError:
        raise
    except Exception:
        raise IFEMSyntheticRoleBridgeError(
            "executor failed without exposing provider details"
        ) from None
    return IFEMSyntheticRoleExecutionV1(prepared=prepared, output=output)


def evaluate(
    execution: IFEMSyntheticRoleExecutionV1,
    oracle: IFEMSyntheticRolePrivateOracleV1,
    *,
    fixture: IFEMSyntheticRolePublicFixtureV1 | None = None,
) -> IFEMSyntheticRoleEvaluationV1:
    """Evaluate one transient execution against a private oracle in evaluator memory.

    Supplying ``fixture`` is recommended: it rebinds the prepared fixture digest, case
    role, and prompt digest before the private oracle is consulted.  The optional form
    keeps the evaluator usable with a separately authenticated preparation record.
    """

    if not isinstance(execution, IFEMSyntheticRoleExecutionV1):
        raise IFEMSyntheticRoleBridgeError("evaluate requires a synthetic role execution")
    if fixture is not None:
        verified_fixture = _revalidate_public_fixture(fixture)
        if verified_fixture.content_sha256 != execution.prepared.fixture_content_sha256:
            raise IFEMSyntheticRoleBridgeError("evaluation fixture differs from preparation")
        fixture_case = _find_case(verified_fixture, execution.prepared.case_id)
        if fixture_case.role is not execution.prepared.role:
            raise IFEMSyntheticRoleBridgeError("evaluation fixture role differs from preparation")
        if digest_text(HashKindV1.PROMPT, fixture_case.prompt) != execution.prepared.prompt_digest:
            raise IFEMSyntheticRoleBridgeError("evaluation fixture prompt differs from preparation")
    verified_oracle = _revalidate_private_oracle(oracle)
    record = next(
        (
            item
            for item in verified_oracle.records
            if item.public_case_id.value == _case_value(execution.prepared.case_id)
        ),
        None,
    )
    if record is None:
        raise IFEMSyntheticRoleBridgeError("private oracle has no matching public case")
    if record.role is not execution.prepared.role:
        raise IFEMSyntheticRoleBridgeError("private oracle role differs from the public case")
    prediction, parse_error = _parse_prediction(execution.output.text)
    expected = record.baseline_option
    return IFEMSyntheticRoleEvaluationV1(
        case_id=execution.prepared.case_id,
        role=execution.prepared.role,
        predicted_option=prediction,
        expected_option=expected,
        correct=prediction.value == expected.value,
        parse_error=parse_error,
    )


def receipt(execution: IFEMSyntheticRoleExecutionV1) -> IFEMSyntheticRoleReceiptV1:
    """Create public request/body evidence without committing private model output."""

    if not isinstance(execution, IFEMSyntheticRoleExecutionV1):
        raise IFEMSyntheticRoleBridgeError("receipt requires a synthetic role execution")
    prepared = execution.prepared
    payload: dict[str, object] = {
        "schema_version": "autolean.ifem-synthetic-role-receipt.v1",
        "fixture_content_sha256": prepared.fixture_content_sha256,
        "case_id": prepared.case_id.model_dump(mode="json"),
        "role": prepared.role,
        "prompt_digest": prepared.prompt_digest.model_dump(mode="json"),
        "logical_request_digest": prepared.logical_request_digest.model_dump(mode="json"),
        "request_body_binding": prepared.body_binding.model_dump(mode="json"),
        "provider_id": prepared.provider_id,
        "model_id": prepared.model_id,
        "provider_configuration_digest": prepared.provider_configuration_digest.model_dump(
            mode="json"
        ),
        "authority": IFEMSyntheticRoleReceiptAuthorityV1().model_dump(mode="json"),
    }
    payload["content_sha256"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    try:
        return IFEMSyntheticRoleReceiptV1.model_validate(payload)
    except (TypeError, ValueError) as error:
        raise IFEMSyntheticRoleBridgeError("synthetic role receipt did not validate") from error


def render_receipt(receipt_value: IFEMSyntheticRoleReceiptV1) -> bytes:
    """Serialize only a revalidated request/body-only public receipt."""

    verified = IFEMSyntheticRoleReceiptV1._validated_payload(receipt_value)
    rendered = canonical_json_bytes(verified.model_dump(mode="json")) + b"\n"
    if any(marker in rendered.lower() for marker in _FORBIDDEN_RECEIPT_MARKERS):
        raise IFEMSyntheticRoleBridgeError("public receipt contains a private marker")
    return rendered


build_ifem_synthetic_role_receipt = receipt


class IFEMSyntheticRoleFakeExecutor:
    """Deterministic exact-byte executor for offline bridge tests and architecture checks."""

    def __init__(
        self,
        responses: Iterable[str],
        *,
        model_id: str = "synthetic-fake-model",
    ) -> None:
        self._responses = tuple(responses)
        if not self._responses:
            raise ValueError("fake executor requires at least one scripted response")
        if not model_id or len(model_id) > 256:
            raise ValueError("fake executor model_id is invalid")
        self._model_id = model_id
        self._next = 0
        self._lock = threading.Lock()
        self._bodies: list[bytes] = []

    @property
    def provider_id(self) -> str:
        return "synthetic-fake"

    @property
    def model_id(self) -> str:
        return self._model_id

    @property
    def configuration_hash(self) -> DigestV1:
        return digest_model(
            HashKindV1.CONFIG,
            {
                "schema_version": "autolean.ifem.synthetic-fake-executor.v1",
                "provider_id": self.provider_id,
                "model_id": self.model_id,
            },
        )

    @property
    def bodies(self) -> tuple[bytes, ...]:
        """Return captured exact bodies for offline re-verification."""

        with self._lock:
            return tuple(self._bodies)

    def prepare_request_body(self, request: ModelRequest) -> CanonicalJsonRequestBody:
        payload: dict[str, object] = {
            "schema_version": "autolean.ifem.synthetic-role-request.v1",
            "model": self.model_id,
            "prompt": request.prompt,
            "system_prompt": request.system_prompt,
            "max_output_tokens": request.max_output_tokens,
            "response_format": request.response_format,
        }
        body = canonical_json_bytes(payload)
        return CanonicalJsonRequestBody(
            body=body,
            binding=OutboundRequestBodyV1(
                body_hash=digest_bytes(HashKindV1.OUTBOUND_REQUEST_BODY, body),
                body_size_bytes=len(body),
            ),
        )

    def execute_prepared(
        self,
        *,
        request: ModelRequest,
        body: bytes,
        binding: OutboundRequestBodyV1,
    ) -> IFEMSyntheticRoleModelOutputV1:
        expected = self.prepare_request_body(request)
        if body != expected.body or binding != expected.binding:
            raise IFEMSyntheticRoleBridgeError(
                "fake executor observed a body different from preparation"
            )
        with self._lock:
            if self._next >= len(self._responses):
                raise IFEMSyntheticRoleBridgeError(
                    "fake executor has no scripted response remaining"
                )
            response = self._responses[self._next]
            self._next += 1
            self._bodies.append(body)
            response_id = f"synthetic-fake-response-{self._next}"
        return IFEMSyntheticRoleModelOutputV1(
            text=response,
            body_binding=binding,
            provider_id=self.provider_id,
            model_id=self.model_id,
            response_id=response_id,
        )


def _revalidate_public_fixture(
    fixture: IFEMSyntheticRolePublicFixtureV1,
) -> IFEMSyntheticRolePublicFixtureV1:
    if type(fixture) is not IFEMSyntheticRolePublicFixtureV1:
        raise IFEMSyntheticRoleBridgeError("fixture must be the exact public fixture type")
    try:
        rendered = render_ifem_synthetic_role_fixture(fixture)
        return IFEMSyntheticRolePublicFixtureV1.model_validate_json(rendered)
    except (AttributeError, TypeError, ValueError) as error:
        raise IFEMSyntheticRoleBridgeError("public fixture failed revalidation") from error


def _revalidate_private_oracle(
    oracle: IFEMSyntheticRolePrivateOracleV1,
) -> IFEMSyntheticRolePrivateOracleV1:
    if type(oracle) is not IFEMSyntheticRolePrivateOracleV1:
        raise IFEMSyntheticRoleBridgeError("oracle must be the exact private oracle type")
    try:
        return IFEMSyntheticRolePrivateOracleV1.model_validate(oracle.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as error:
        raise IFEMSyntheticRoleBridgeError("private oracle failed revalidation") from error


def _find_case(
    fixture: IFEMSyntheticRolePublicFixtureV1,
    case_id: object,
) -> IFEMSyntheticRolePublicCaseV1:
    value = _case_value(case_id)
    for case in fixture.cases:
        if case.case_id.value == value:
            return case
    raise IFEMSyntheticRoleBridgeError("public fixture has no matching case")


def _case_value(case_id: object) -> str:
    if isinstance(case_id, dict):
        value = case_id.get("value")
        if isinstance(value, str):
            return value
    value = getattr(case_id, "value", None)
    if isinstance(value, str):
        return value
    if isinstance(case_id, str):
        return case_id
    raise IFEMSyntheticRoleBridgeError("case_id must be a stable identifier or its value")


def _reject_private_body_fields(body: bytes) -> None:
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IFEMSyntheticRoleBridgeError("prepared body is not valid UTF-8 JSON") from error

    def walk(value: object) -> None:
        if isinstance(value, Mapping):
            for key, nested in value.items():
                if isinstance(key, str) and any(
                    marker in key.lower() for marker in _FORBIDDEN_BODY_MARKERS
                ):
                    raise IFEMSyntheticRoleBridgeError(
                        "prepared body contains a private or credential field"
                    )
                walk(nested)
        elif isinstance(value, list):
            for nested in value:
                walk(nested)
        elif isinstance(value, str):
            lowered = value.lower()
            if any(
                marker in lowered for marker in ("private-oracle", "secret-token", "authorization:")
            ):
                raise IFEMSyntheticRoleBridgeError(
                    "prepared body contains a credential or private marker"
                )

    walk(payload)


def _parse_prediction(text: str) -> tuple[IFEMSyntheticRolePredictionV1, bool]:
    stripped = text.strip()
    if stripped in {item.value for item in IFEMSyntheticRolePredictionV1}:
        prediction = IFEMSyntheticRolePredictionV1(stripped)
        return prediction, prediction is IFEMSyntheticRolePredictionV1.ABSTAIN
    try:
        parsed = json.loads(stripped)
    except (TypeError, ValueError, json.JSONDecodeError):
        return IFEMSyntheticRolePredictionV1.ABSTAIN, True
    if not isinstance(parsed, dict):
        return IFEMSyntheticRolePredictionV1.ABSTAIN, True
    candidate = parsed.get("selected_option", parsed.get("option"))
    if candidate in {IFEMSyntheticRoleOptionV1.A.value, IFEMSyntheticRoleOptionV1.B.value}:
        return IFEMSyntheticRolePredictionV1(cast(str, candidate)), False
    if candidate == IFEMSyntheticRolePredictionV1.ABSTAIN.value:
        return IFEMSyntheticRolePredictionV1.ABSTAIN, False
    return IFEMSyntheticRolePredictionV1.ABSTAIN, True


__all__ = [
    "IFEMSyntheticRoleBridgeError",
    "IFEMSyntheticRoleEvaluationV1",
    "IFEMSyntheticRoleExecutionV1",
    "IFEMSyntheticRoleExecutor",
    "IFEMSyntheticRoleFakeExecutor",
    "IFEMSyntheticRoleModelOutputV1",
    "IFEMSyntheticRolePredictionV1",
    "IFEMSyntheticRolePreparedRequestV1",
    "IFEMSyntheticRoleReceiptAuthorityV1",
    "IFEMSyntheticRoleReceiptV1",
    "IFEMSyntheticRoleRequestPolicyV1",
    "IFEMSyntheticRoleResponseContractV1",
    "build_ifem_synthetic_role_receipt",
    "evaluate",
    "execute",
    "ifem_synthetic_role_system_prompt",
    "prepare",
    "receipt",
    "render_receipt",
]
