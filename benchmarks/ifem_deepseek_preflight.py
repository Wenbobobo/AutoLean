"""Zero-network DeepSeek preflight for the iFEM synthetic-role bridge."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, Self, cast

from autolean_builder.ifem_structural_role_probes import IFEMStructuralProbeRoleV1
from autolean_contracts import (
    ContractModel,
    DigestV1,
    HashKindV1,
    OutboundRequestBodyV1,
    StableIdentifierV1,
    canonical_json_bytes,
    digest_bytes,
)
from autolean_contracts.hashing import require_digest_kind
from autolean_prover.errors import ProviderResponseError
from autolean_prover.providers import CanonicalJsonRequestBody, ModelRequest
from autolean_prover.providers.chat import ChatCompletionsProvider
from autolean_prover.providers.operator_profile import ChatCompletionsOperatorProfileV1
from pydantic import Field, model_validator

from benchmarks.ifem_synthetic_role_bridge import (
    IFEMSyntheticRoleBridgeError,
    IFEMSyntheticRoleModelOutputV1,
    IFEMSyntheticRolePreparedRequestV1,
    IFEMSyntheticRoleRequestPolicyV1,
    IFEMSyntheticRoleResponseContractV1,
    prepare,
)
from benchmarks.ifem_synthetic_role_fixture import (
    IFEMSyntheticRolePublicFixtureV1,
    render_ifem_synthetic_role_fixture,
)

_SHA256 = r"^[0-9a-f]{64}$"
_PROFILE_PATH = (
    Path(__file__).resolve().parents[1]
    / "Prover"
    / "operator-profiles"
    / "deepseek-v4-pro.chat-completions.v1.json"
)
_ROLE_COUNTS: Final[dict[str, int]] = {
    IFEMStructuralProbeRoleV1.STATEMENT_FORMALIZER.value: 8,
    IFEMStructuralProbeRoleV1.FIDELITY_REVIEWER.value: 4,
    IFEMStructuralProbeRoleV1.CHEATING_SUPERVISOR.value: 4,
}


class IFEMDeepSeekPreflightError(IFEMSyntheticRoleBridgeError):
    """The zero-network DeepSeek preflight crossed its execution boundary."""


class _RejectNetworkTransport:
    """Transport capability that records and rejects every attempted request."""

    def __init__(self) -> None:
        self._call_count = 0

    @property
    def call_count(self) -> int:
        return self._call_count

    def post_json_bytes(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        del url, headers, body, timeout_seconds
        self._call_count += 1
        raise ProviderResponseError("network is disabled for the iFEM DeepSeek preflight")

    def post_json(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        payload: Mapping[str, object],
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        del url, headers, payload, timeout_seconds
        self._call_count += 1
        raise ProviderResponseError("network is disabled for the iFEM DeepSeek preflight")


class IFEMDeepSeekPreflightAdapter:
    """Prepare real provider bodies while refusing every execution attempt."""

    def __init__(
        self,
        provider: ChatCompletionsProvider,
        transport: _RejectNetworkTransport,
    ) -> None:
        self._provider = provider
        self._transport = transport

    @property
    def provider_id(self) -> str:
        return self._provider.provider_id

    @property
    def model_id(self) -> str:
        return self._provider.model_id

    @property
    def configuration_hash(self) -> DigestV1:
        return self._provider.configuration_hash

    @property
    def network_call_count(self) -> int:
        return self._transport.call_count

    def prepare_request_body(self, request: ModelRequest) -> CanonicalJsonRequestBody:
        return self._provider.prepare_request_body(request)

    def execute_prepared(
        self,
        *,
        request: ModelRequest,
        body: bytes,
        binding: OutboundRequestBodyV1,
    ) -> IFEMSyntheticRoleModelOutputV1:
        del request, body, binding
        raise IFEMDeepSeekPreflightError("DeepSeek execution is disabled in preflight")


class IFEMDeepSeekPreflightAuthorityV1(ContractModel):
    schema_version: Literal["autolean.ifem-deepseek-preflight-authority.v1"] = (
        "autolean.ifem-deepseek-preflight-authority.v1"
    )
    api_key_resolved: Literal[False] = False
    network_execution_authorized: Literal[False] = False
    network_call_performed: Literal[False] = False
    model_result_observed: Literal[False] = False
    benchmark_authority: Literal[False] = False
    semantic_equivalence_claimed: Literal[False] = False
    statement_contract_created: Literal[False] = False
    freeze_allowed: Literal[False] = False
    prover_handoff_allowed: Literal[False] = False
    promotion_allowed: Literal[False] = False


class IFEMDeepSeekPreflightCaseV1(ContractModel):
    schema_version: Literal["autolean.ifem-deepseek-preflight-case.v1"] = (
        "autolean.ifem-deepseek-preflight-case.v1"
    )
    case_id: StableIdentifierV1
    role: IFEMStructuralProbeRoleV1
    prompt_digest: DigestV1
    logical_request_digest: DigestV1
    request_body_binding: OutboundRequestBodyV1

    @model_validator(mode="after")
    def validate_case(self) -> Self:
        if self.case_id.namespace != "ifem.synthetic-role-case":
            raise ValueError("DeepSeek preflight case uses an unexpected namespace")
        require_digest_kind(self.prompt_digest, HashKindV1.PROMPT, "prompt_digest")
        require_digest_kind(
            self.logical_request_digest,
            HashKindV1.PROMPT,
            "logical_request_digest",
        )
        return self


class IFEMDeepSeekPreflightReportV1(ContractModel):
    schema_version: Literal["autolean.ifem-deepseek-preflight.v1"] = (
        "autolean.ifem-deepseek-preflight.v1"
    )
    fixture_content_sha256: str = Field(pattern=_SHA256)
    profile_digest: DigestV1
    provider_configuration_digest: DigestV1
    provider_id: Literal["deepseek"] = "deepseek"
    model_id: Literal["deepseek-v4-pro"] = "deepseek-v4-pro"
    case_count: Literal[16] = 16
    role_counts: dict[str, int]
    cases: tuple[IFEMDeepSeekPreflightCaseV1, ...] = Field(min_length=16, max_length=16)
    authority: IFEMDeepSeekPreflightAuthorityV1 = Field(
        default_factory=IFEMDeepSeekPreflightAuthorityV1
    )
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_report(self) -> Self:
        require_digest_kind(self.profile_digest, HashKindV1.CONFIG, "profile_digest")
        require_digest_kind(
            self.provider_configuration_digest,
            HashKindV1.CONFIG,
            "provider_configuration_digest",
        )
        if self.role_counts != _ROLE_COUNTS:
            raise ValueError("DeepSeek preflight role counts differ from the fixed fixture")
        projected_role_counts = dict(Counter(item.role.value for item in self.cases))
        if self.role_counts != projected_role_counts:
            raise ValueError("DeepSeek preflight role counts do not match its cases")
        case_ids = tuple(item.case_id for item in self.cases)
        if len(set(case_ids)) != len(case_ids):
            raise ValueError("DeepSeek preflight cases must be unique")
        if self.authority != IFEMDeepSeekPreflightAuthorityV1():
            raise ValueError("DeepSeek preflight authority flags are not fixed")
        if self.content_sha256 != self.computed_content_sha256():
            raise ValueError("DeepSeek preflight report hash does not match its payload")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(dict[str, object], self.model_dump(mode="json", exclude={"content_sha256"}))

    def computed_content_sha256(self) -> str:
        return digest_bytes(
            HashKindV1.VERIFICATION_EVIDENCE, canonical_json_bytes(self.content_payload())
        ).value


@dataclass(frozen=True, slots=True)
class IFEMDeepSeekPreflightBundleV1:
    """Transient prepared bodies plus their digest-only public report."""

    report: IFEMDeepSeekPreflightReportV1
    prepared: tuple[IFEMSyntheticRolePreparedRequestV1, ...]
    adapter: IFEMDeepSeekPreflightAdapter


def build_ifem_deepseek_preflight(
    fixture: IFEMSyntheticRolePublicFixtureV1,
    *,
    profile_path: Path = _PROFILE_PATH,
    profile_bytes: bytes | None = None,
    request_policy: IFEMSyntheticRoleRequestPolicyV1 | None = None,
    response_contract: IFEMSyntheticRoleResponseContractV1 = (
        IFEMSyntheticRoleResponseContractV1.SELECTED_OPTION_AND_REASON_V1
    ),
) -> IFEMDeepSeekPreflightBundleV1:
    """Prepare all sixteen exact DeepSeek bodies without resolving a secret or using network."""

    verified_fixture = _revalidate_fixture(fixture)
    if profile_bytes is not None and not isinstance(profile_bytes, bytes):
        raise IFEMDeepSeekPreflightError("operator profile bytes must be bytes")
    if profile_bytes is None and (
        not isinstance(profile_path, Path) or not profile_path.is_absolute()
    ):
        raise IFEMDeepSeekPreflightError("operator profile path must be absolute")
    try:
        if profile_bytes is None:
            profile_bytes = profile_path.read_bytes()
        profile = ChatCompletionsOperatorProfileV1.from_json_bytes(profile_bytes)
    except (OSError, ValueError) as error:
        raise IFEMDeepSeekPreflightError("DeepSeek operator profile is unavailable") from error
    transport = _RejectNetworkTransport()
    provider = profile.create_provider(transport=transport, environment={})
    adapter = IFEMDeepSeekPreflightAdapter(provider, transport)
    policy = request_policy or IFEMSyntheticRoleRequestPolicyV1(
        max_input_tokens=profile.canary_max_input_tokens,
        max_output_tokens=profile.canary_max_output_tokens,
        reasoning_effort=profile.default_reasoning_effort,
        require_usage_accounting=True,
    )
    if type(policy) is not IFEMSyntheticRoleRequestPolicyV1:
        raise IFEMDeepSeekPreflightError("iFEM preflight request policy must use the exact type")
    if not isinstance(response_contract, IFEMSyntheticRoleResponseContractV1):
        raise IFEMDeepSeekPreflightError("iFEM preflight response contract is invalid")
    prepared = tuple(
        prepare(
            verified_fixture,
            case.case_id,
            adapter,
            request_policy=policy,
            response_contract=response_contract,
        )
        for case in verified_fixture.cases
    )
    if adapter.network_call_count != 0:
        raise IFEMDeepSeekPreflightError("DeepSeek preflight attempted a network call")
    case_payloads = tuple(
        IFEMDeepSeekPreflightCaseV1(
            case_id=item.case_id,
            role=item.role,
            prompt_digest=item.prompt_digest,
            logical_request_digest=item.logical_request_digest,
            request_body_binding=item.body_binding,
        )
        for item in prepared
    )
    payload: dict[str, object] = {
        "schema_version": "autolean.ifem-deepseek-preflight.v1",
        "fixture_content_sha256": verified_fixture.content_sha256,
        "profile_digest": digest_bytes(HashKindV1.CONFIG, profile_bytes).model_dump(mode="json"),
        "provider_configuration_digest": adapter.configuration_hash.model_dump(mode="json"),
        "provider_id": adapter.provider_id,
        "model_id": adapter.model_id,
        "case_count": len(case_payloads),
        "role_counts": dict(Counter(item.role.value for item in case_payloads)),
        "cases": [item.model_dump(mode="json") for item in case_payloads],
        "authority": IFEMDeepSeekPreflightAuthorityV1().model_dump(mode="json"),
    }
    payload["content_sha256"] = digest_bytes(
        HashKindV1.VERIFICATION_EVIDENCE, canonical_json_bytes(payload)
    ).value
    try:
        report = IFEMDeepSeekPreflightReportV1.model_validate(payload)
    except ValueError as error:
        raise IFEMDeepSeekPreflightError("DeepSeek preflight report did not validate") from error
    return IFEMDeepSeekPreflightBundleV1(
        report=report,
        prepared=prepared,
        adapter=adapter,
    )


def render_ifem_deepseek_preflight_report(
    report: IFEMDeepSeekPreflightReportV1,
    *,
    fixture: IFEMSyntheticRolePublicFixtureV1,
    profile_path: Path = _PROFILE_PATH,
    profile_bytes: bytes | None = None,
    request_policy: IFEMSyntheticRoleRequestPolicyV1 | None = None,
    response_contract: IFEMSyntheticRoleResponseContractV1 = (
        IFEMSyntheticRoleResponseContractV1.SELECTED_OPTION_AND_REASON_V1
    ),
) -> bytes:
    """Repeat the zero-network preflight before rendering its public projection."""

    if type(report) is not IFEMDeepSeekPreflightReportV1:
        raise IFEMDeepSeekPreflightError("report must be the exact preflight type")
    expected = build_ifem_deepseek_preflight(
        fixture,
        profile_path=profile_path,
        profile_bytes=profile_bytes,
        request_policy=request_policy,
        response_contract=response_contract,
    ).report
    try:
        verified = IFEMDeepSeekPreflightReportV1.model_validate(report.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as error:
        raise IFEMDeepSeekPreflightError("preflight report requires revalidation") from error
    if verified != expected:
        raise IFEMDeepSeekPreflightError("preflight report differs from the zero-network rebuild")
    return canonical_json_bytes(verified.model_dump(mode="json")) + b"\n"


def _revalidate_fixture(
    fixture: IFEMSyntheticRolePublicFixtureV1,
) -> IFEMSyntheticRolePublicFixtureV1:
    if type(fixture) is not IFEMSyntheticRolePublicFixtureV1:
        raise IFEMDeepSeekPreflightError("fixture must be the exact public fixture type")
    try:
        rendered = render_ifem_synthetic_role_fixture(fixture)
        return IFEMSyntheticRolePublicFixtureV1.model_validate_json(rendered)
    except (AttributeError, TypeError, ValueError) as error:
        raise IFEMDeepSeekPreflightError("fixture failed revalidation") from error


__all__ = [
    "IFEMDeepSeekPreflightAdapter",
    "IFEMDeepSeekPreflightAuthorityV1",
    "IFEMDeepSeekPreflightBundleV1",
    "IFEMDeepSeekPreflightCaseV1",
    "IFEMDeepSeekPreflightError",
    "IFEMDeepSeekPreflightReportV1",
    "build_ifem_deepseek_preflight",
    "render_ifem_deepseek_preflight_report",
]
