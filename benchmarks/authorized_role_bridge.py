"""Authorized external-model bridge for answer-free role calibration trials.

This module is intentionally separate from the scripted-fake V3 report.  It creates one
``ModelWorkBundleV2`` per trial, obtains the existing model-execution capability, and calls the
model only through ``ProviderRegistry.generate``.  The resulting sidecar is non-promotable and
contains neither the evaluator oracle nor raw model output.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import secrets
import time
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal, Never, Self, SupportsIndex

from autolean_contracts import (
    AttestationV1,
    ContractModel,
    DigestV1,
    EndpointClassV1,
    HashKindV1,
    ModelExecutionAuthorizationV1,
    ModelExecutionBudgetV1,
    ModelExecutionProviderApprovalV1,
    ModelExecutionProviderBindingV1,
    ModelWorkBundleV2,
    ModelWorkRoleV1,
    PermissionDecisionV1,
    RightsRecordV1,
    SourceRecordV1,
    SourceSpanV1,
    canonical_json_bytes,
    digest_bytes,
    digest_model,
    digest_text,
    model_work_bundle_id,
    model_work_case_contract_hash,
    model_work_case_hash,
    model_work_cell_contract_hash,
    model_work_cell_hash,
    model_work_contract_id,
    model_work_item_hash,
    model_work_rights_binding,
    model_work_run_hash,
    model_work_source_binding,
    stable_identifier,
)
from autolean_control_plane import ModelExecutionAuthorizationService
from autolean_prover.providers import (
    MAX_MODEL_REQUEST_TIMEOUT_SECONDS,
    Capability,
    ModelRequest,
    ModelResponse,
    ProviderRegistry,
    TokenUsage,
    ToolCall,
)
from pydantic import BeforeValidator, ConfigDict, Field, model_validator

from benchmarks.role_benchmark import (
    BenchmarkRoleV1,
    FakeRoleBenchmarkFixtureV1,
    RoleBenchmarkCaseV1,
    RoleBenchmarkCellV1,
    RoleBenchmarkMatrixV1,
    RoleBenchmarkRawOutputStore,
    RoleModelTargetV1,
    derive_trial_seed,
)

_IDENTIFIER_PATTERN = r"^[a-z0-9][a-z0-9_.:/-]{0,127}$"
_SAFE_RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$")
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_BASE_CAPABILITIES = frozenset(
    {
        Capability.TEXT_GENERATION,
        Capability.USAGE_ACCOUNTING,
    }
)
_PRIVATE_HANDLE_PATTERN = r"^private_[0-9a-f]{64}$"
_PRIVATE_AUTHENTICATION_TAG_PATTERN = r"^[A-Za-z0-9_-]{32,1024}$"
_TOKEN_BUCKET_PATTERN = r"^(zero|1_255|256_1023|1024_4095|4096_16383|16384_plus)$"
_ELAPSED_BUCKET_PATTERN = r"^(under_1s|1s_9s|10s_59s|60s_299s|300s_plus)$"
_ROLE_SETTLEMENT_MARGIN_SECONDS = 30.0
_ROLE_CLAIM_TO_ISSUE_MARGIN_SECONDS = 30.0
_ROLE_AUTHORIZATION_HARD_CAP_SECONDS = 60.0 * 60.0
_ROLE_LEASE_HARD_CAP_SECONDS = (
    _ROLE_AUTHORIZATION_HARD_CAP_SECONDS + _ROLE_CLAIM_TO_ISSUE_MARGIN_SECONDS
)
_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_CALIBRATION_FIXTURE_PATH = _REPOSITORY_ROOT / "benchmarks" / "roles" / "calibration-pairs.v3.json"
_CALIBRATION_FIXTURE_SHA256 = "367b6cad7ca259798b20fd1710f29b06c64f2fbdbea58687588e450ab88761d8"
_LICENSE_PATH = _REPOSITORY_ROOT / "LICENSE"
_LICENSE_SHA256 = "5c9817c129b98e7bb966bca028c43c19107102ef8e03fe799bffb4354f4ef015"
_CALIBRATION_TIMESTAMP = datetime(2026, 7, 26, tzinfo=UTC)


class AuthorizedRoleBridgeError(ValueError):
    """A role trial could not be bound to the external model authorization path."""


class AuthorizedRoleReconciliationRequired(AuthorizedRoleBridgeError):
    """A prior provider dispatch has ambiguous or private-only state and must not be replayed."""


def is_safe_authorized_role_run_id(value: object) -> bool:
    """Return whether a run ID is one portable, path-free ASCII slug."""

    return (
        isinstance(value, str)
        and _SAFE_RUN_ID_PATTERN.fullmatch(value) is not None
        and ".." not in value
    )


def validate_authorized_role_run_id(value: object) -> str:
    """Return a safe run ID without ever reflecting an invalid value in an error."""

    if not is_safe_authorized_role_run_id(value):
        raise AuthorizedRoleBridgeError("run_id is not a safe slug")
    assert isinstance(value, str)
    return value


type AuthorizedRoleRunIdV1 = Annotated[
    str,
    BeforeValidator(validate_authorized_role_run_id),
]


class _AuthorizedRoleRunIdContractModel(ContractModel):
    model_config = ConfigDict(hide_input_in_errors=True)


def _content_hash(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _canonical_text(value: object) -> str:
    return canonical_json_bytes(value).decode("ascii")


def _new_private_handle() -> str:
    return f"private_{secrets.token_hex(32)}"


def _validated_private_handle(value: str) -> str:
    if not isinstance(value, str) or re.fullmatch(_PRIVATE_HANDLE_PATTERN, value) is None:
        raise AuthorizedRoleReconciliationRequired("private handle has an invalid format")
    return value


def _write_private_exclusive(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def _replace_private_file(path: Path, payload: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(16)}.tmp")
    try:
        _write_private_exclusive(temporary, payload)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


class LockedRoleWorkEvidenceV1(ContractModel):
    """Local, non-cryptographic evidence emitted only by the pinned fixture builder."""

    schema_version: Literal["autolean.locked-role-work-evidence.v1"] = (
        "autolean.locked-role-work-evidence.v1"
    )
    authority_id: Literal["autolean.locked-role-fixture-builder.v1"] = (
        "autolean.locked-role-fixture-builder.v1"
    )
    evidence_class: Literal["local_software_root_of_trust_nonpromotable"] = (
        "local_software_root_of_trust_nonpromotable"
    )
    fixture_sha256: Literal["367b6cad7ca259798b20fd1710f29b06c64f2fbdbea58687588e450ab88761d8"] = (
        "367b6cad7ca259798b20fd1710f29b06c64f2fbdbea58687588e450ab88761d8"
    )
    license_sha256: Literal["5c9817c129b98e7bb966bca028c43c19107102ef8e03fe799bffb4354f4ef015"] = (
        "5c9817c129b98e7bb966bca028c43c19107102ef8e03fe799bffb4354f4ef015"
    )
    matrix_hash: str = Field(pattern=_SHA256_PATTERN)
    suite_definition_hash: str = Field(pattern=_SHA256_PATTERN)
    source_record_hash: str = Field(pattern=_SHA256_PATTERN)
    rights_record_hash: str = Field(pattern=_SHA256_PATTERN)
    egress_span_set_hash: str = Field(pattern=_SHA256_PATTERN)
    target_binding_hash: str = Field(pattern=_SHA256_PATTERN)
    generation_policy_hash: str = Field(pattern=_SHA256_PATTERN)
    production_trust_eligible: Literal[False] = False

    def content_hash(self) -> str:
        return _content_hash(self)


class AuthorizedRoleContextV1(_AuthorizedRoleRunIdContractModel):
    """The answer-free context sent to one role worker."""

    schema_version: Literal["autolean.authorized-role-context.v1"] = (
        "autolean.authorized-role-context.v1"
    )
    run_id: AuthorizedRoleRunIdV1
    cell_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    case_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    repetition: int = Field(ge=1, le=100)
    trial_seed: str = Field(pattern=_SHA256_PATTERN)
    role: ModelWorkRoleV1
    work_item_hash: str = Field(pattern=_SHA256_PATTERN)
    system_prompt: str = Field(min_length=1, max_length=32_768)
    prompt: str = Field(min_length=1, max_length=131_072)
    oracle_included: Literal[False] = False

    def content_hash(self) -> DigestV1:
        """Return the request ContextPack digest without exposing its text."""

        return digest_model(HashKindV1.PROMPT, self)


class AuthorizedRoleGenerationPolicyV1(ContractModel):
    """The complete per-request generation surface supported by this bridge."""

    schema_version: Literal["autolean.authorized-role-generation-policy.v1"] = (
        "autolean.authorized-role-generation-policy.v1"
    )
    reasoning_effort: str | None = Field(
        default=None,
        pattern=r"^[a-z][a-z0-9_-]{0,63}$",
    )
    timeout_seconds: int = Field(
        ge=1,
        le=int(MAX_MODEL_REQUEST_TIMEOUT_SECONDS),
    )

    def content_hash(self) -> str:
        return _content_hash(self)


def _required_generation_capabilities(
    policy: AuthorizedRoleGenerationPolicyV1,
) -> frozenset[Capability]:
    required = set(_BASE_CAPABILITIES)
    if policy.reasoning_effort is not None:
        required.add(Capability.REASONING_EFFORT)
    return frozenset(required)


class AuthorizedRoleTrialUsageSummaryV1(ContractModel):
    """Coarse public accounting for exactly one role trial."""

    schema_version: Literal["autolean.authorized-role-trial-usage.v1"] = (
        "autolean.authorized-role-trial-usage.v1"
    )
    trial_count: Literal[1] = 1
    input_tokens_bucket: str = Field(pattern=_TOKEN_BUCKET_PATTERN)
    cached_input_tokens_bucket: str = Field(pattern=_TOKEN_BUCKET_PATTERN)
    output_tokens_bucket: str = Field(pattern=_TOKEN_BUCKET_PATTERN)
    elapsed_ms_bucket: str = Field(pattern=_ELAPSED_BUCKET_PATTERN)


class _AuthorizedRoleTrialSidecarBase(_AuthorizedRoleRunIdContractModel):
    run_id: AuthorizedRoleRunIdV1
    cell_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    case_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    repetition: int = Field(ge=1, le=100)
    role: ModelWorkRoleV1
    work_item_hash: str = Field(pattern=_SHA256_PATTERN)
    model_work_bundle_hash: str = Field(pattern=_SHA256_PATTERN)
    authorization_hash: str = Field(pattern=_SHA256_PATTERN)
    provider_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    model_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    model_revision: str = Field(min_length=1, max_length=512)
    provider_configuration_hash: str = Field(pattern=_SHA256_PATTERN)
    context_pack_hash: str = Field(pattern=_SHA256_PATTERN)
    request_hash: str = Field(pattern=_SHA256_PATTERN)
    work_evidence_hash: str = Field(pattern=_SHA256_PATTERN)
    production_evaluator: Literal[False] = False
    floor_claim_eligible: Literal[False] = False
    oracle_visible_to_executor: Literal[False] = False
    cross_role_aggregation_permitted: Literal[False] = False


class AuthorizedRoleTrialSidecarV1(_AuthorizedRoleTrialSidecarBase):
    """Original answer-free trial evidence without public per-trial usage."""

    schema_version: Literal["autolean.authorized-role-trial-sidecar.v1"] = (
        "autolean.authorized-role-trial-sidecar.v1"
    )


class AuthorizedRoleTrialSidecarV2(_AuthorizedRoleTrialSidecarBase):
    """V2 trial evidence with authenticated, coarse public usage."""

    schema_version: Literal["autolean.authorized-role-trial-sidecar.v2"] = (
        "autolean.authorized-role-trial-sidecar.v2"
    )
    usage_summary: AuthorizedRoleTrialUsageSummaryV1


class AuthorizedRolePrivateOutputEntryV1(ContractModel):
    """Private-manifest index for one content-addressed normalized model response."""

    schema_version: Literal["autolean.authorized-role-private-output-entry.v1"] = (
        "autolean.authorized-role-private-output-entry.v1"
    )
    cell_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    case_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    repetition: int = Field(ge=1, le=100)
    private_reconciliation_handle: str = Field(pattern=_PRIVATE_HANDLE_PATTERN)
    output_hash: str = Field(pattern=_SHA256_PATTERN)
    authorization_hash: str = Field(pattern=_SHA256_PATTERN)
    elapsed_ms: int = Field(ge=0)
    input_tokens: int = Field(ge=1)
    cached_input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_usage(self) -> Self:
        if self.cached_input_tokens > self.input_tokens:
            raise ValueError("cached input tokens cannot exceed input tokens")
        return self


class AuthorizedRolePrivateReconciliationV1(ContractModel):
    """Operator-private dispatch state; an incomplete state forbids automatic replay."""

    schema_version: Literal["autolean.authorized-role-private-reconciliation.v1"] = (
        "autolean.authorized-role-private-reconciliation.v1"
    )
    private_handle: str = Field(pattern=_PRIVATE_HANDLE_PATTERN)
    bundle_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    authorization_hash: str = Field(pattern=_SHA256_PATTERN)
    state: Literal["provider_outcome_ambiguous", "response_persisted"]
    output_hash: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    elapsed_ms: int | None = Field(default=None, ge=0)
    input_tokens: int | None = Field(default=None, ge=1)
    cached_input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def validate_state(self) -> Self:
        private_values = (
            self.output_hash,
            self.elapsed_ms,
            self.input_tokens,
            self.cached_input_tokens,
            self.output_tokens,
        )
        if self.state == "provider_outcome_ambiguous":
            if any(value is not None for value in private_values):
                raise ValueError("ambiguous provider state cannot claim a persisted response")
        elif any(value is None for value in private_values):
            raise ValueError("persisted provider state requires complete private response metadata")
        if (
            self.input_tokens is not None
            and self.cached_input_tokens is not None
            and self.cached_input_tokens > self.input_tokens
        ):
            raise ValueError("cached input tokens cannot exceed input tokens")
        return self


class AuthorizedRolePrivateManifestV1(_AuthorizedRoleRunIdContractModel):
    """Operator-private coordinate index for raw response blobs."""

    schema_version: Literal["autolean.authorized-role-private-manifest.v1"] = (
        "autolean.authorized-role-private-manifest.v1"
    )
    run_id: AuthorizedRoleRunIdV1
    outputs: tuple[AuthorizedRolePrivateOutputEntryV1, ...]

    @model_validator(mode="after")
    def validate_outputs(self) -> Self:
        coordinates = tuple((item.cell_id, item.case_id, item.repetition) for item in self.outputs)
        if (
            not coordinates
            or coordinates != tuple(sorted(coordinates))
            or len(coordinates) != len(set(coordinates))
        ):
            raise ValueError("private output coordinates must be non-empty, unique, and sorted")
        return self

    def content_hash(self) -> str:
        return _content_hash(self)


class AuthorizedRolePrivateManifestCoordinateV1(ContractModel):
    """One authenticated suite coordinate, excluding raw-output metadata."""

    schema_version: Literal["autolean.authorized-role-private-coordinate.v1"] = (
        "autolean.authorized-role-private-coordinate.v1"
    )
    cell_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    case_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    repetition: int = Field(ge=1, le=100)
    authorization_hash: str = Field(pattern=_SHA256_PATTERN)


class AuthorizedRolePrivateManifestBindingV1(_AuthorizedRoleRunIdContractModel):
    """Authenticated handle-to-manifest binding retained only in operator-private storage."""

    schema_version: Literal["autolean.authorized-role-private-manifest-binding.v1"] = (
        "autolean.authorized-role-private-manifest-binding.v1"
    )
    private_handle: str = Field(pattern=_PRIVATE_HANDLE_PATTERN)
    manifest_hash: str = Field(pattern=_SHA256_PATTERN)
    run_id: AuthorizedRoleRunIdV1
    coordinates: tuple[AuthorizedRolePrivateManifestCoordinateV1, ...]

    @model_validator(mode="after")
    def validate_coordinates(self) -> Self:
        coordinates = tuple(
            (item.cell_id, item.case_id, item.repetition) for item in self.coordinates
        )
        if (
            len(coordinates) != 10
            or coordinates != tuple(sorted(coordinates))
            or len(coordinates) != len(set(coordinates))
        ):
            raise ValueError(
                "authenticated private manifest binding requires ten canonical coordinates"
            )
        return self


class AuthorizedRoleAuthenticatedManifestHandleV1(ContractModel):
    """Canonical authenticated mapping; its authentication key is never serialized."""

    model_config = ConfigDict(hide_input_in_errors=True)

    schema_version: Literal["autolean.authorized-role-authenticated-manifest-handle.v1"] = (
        "autolean.authorized-role-authenticated-manifest-handle.v1"
    )
    binding: AuthorizedRolePrivateManifestBindingV1
    authenticator_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    authentication_scheme: str = Field(pattern=_IDENTIFIER_PATTERN)
    authentication_tag: str = Field(pattern=_PRIVATE_AUTHENTICATION_TAG_PATTERN)


class AuthorizedRolePrivateRunIndexBindingV1(_AuthorizedRoleRunIdContractModel):
    """Authenticated run-to-manifest binding retained only in operator-private storage."""

    schema_version: Literal["autolean.authorized-role-private-run-index-binding.v1"] = (
        "autolean.authorized-role-private-run-index-binding.v1"
    )
    run_id: AuthorizedRoleRunIdV1
    private_handle: str = Field(pattern=_PRIVATE_HANDLE_PATTERN)
    manifest_hash: str = Field(pattern=_SHA256_PATTERN)


class AuthorizedRoleAuthenticatedRunIndexV1(ContractModel):
    """Canonical authenticated run index; its authentication key is never serialized."""

    model_config = ConfigDict(hide_input_in_errors=True)

    schema_version: Literal["autolean.authorized-role-authenticated-run-index.v1"] = (
        "autolean.authorized-role-authenticated-run-index.v1"
    )
    binding: AuthorizedRolePrivateRunIndexBindingV1
    authenticator_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    authentication_scheme: str = Field(pattern=_IDENTIFIER_PATTERN)
    authentication_tag: str = Field(pattern=_PRIVATE_AUTHENTICATION_TAG_PATTERN)


class _AuthorizedRoleRawToolCallV1(ContractModel):
    call_id: str
    name: str
    arguments_json: str


class _AuthorizedRoleRawUsageV1(ContractModel):
    input_tokens: int = Field(ge=0)
    cached_input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_cached_usage(self) -> Self:
        if self.cached_input_tokens > self.input_tokens:
            raise ValueError("cached input tokens cannot exceed input tokens")
        return self


class _AuthorizedRoleRawResponseV1(ContractModel):
    schema_version: Literal["autolean.authorized-role-raw-response.v1"]
    provider_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    model_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    response_id: str | None
    text: str
    tool_calls: tuple[_AuthorizedRoleRawToolCallV1, ...]
    usage: _AuthorizedRoleRawUsageV1

    def to_model_response(self) -> ModelResponse:
        return ModelResponse(
            provider_id=self.provider_id,
            model_id=self.model_id,
            response_id=self.response_id,
            text=self.text,
            tool_calls=tuple(
                ToolCall(
                    call_id=item.call_id,
                    name=item.name,
                    arguments_json=item.arguments_json,
                )
                for item in self.tool_calls
            ),
            usage=TokenUsage(
                input_tokens=self.usage.input_tokens,
                cached_input_tokens=self.usage.cached_input_tokens,
                output_tokens=self.usage.output_tokens,
            ),
        )


class OperatorPrivateManifestAuthenticator(ABC):
    """Injected operator-private MAC/signature boundary.

    Production deployments should implement this boundary with a non-exportable KMS/HSM key.
    Authenticator instances are deliberately not serializable and must be reinjected after a
    restart before an opaque manifest handle can be reconciled.
    """

    @property
    @abstractmethod
    def authenticator_id(self) -> str:
        """Return a non-secret operator key identifier."""

    @property
    @abstractmethod
    def authentication_scheme(self) -> str:
        """Return the algorithm/backend identifier persisted beside the tag."""

    @abstractmethod
    def authenticate(self, payload: bytes) -> str:
        """Authenticate canonical private binding bytes."""

    @abstractmethod
    def verify(self, payload: bytes, authentication_tag: str) -> bool:
        """Verify canonical private binding bytes without exposing key material."""

    def __getstate__(self) -> Never:
        raise TypeError("operator-private authenticator cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        del protocol
        raise TypeError("operator-private authenticator cannot be serialized")


class TestOnlyHmacPrivateManifestAuthenticator(OperatorPrivateManifestAuthenticator):
    """Non-production HMAC fixture used only by deterministic local tests."""

    __slots__ = ("_secret",)

    def __init__(self, secret: bytes) -> None:
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise AuthorizedRoleBridgeError(
                "test-only private manifest HMAC secret must contain at least 32 bytes"
            )
        self._secret = bytes(secret)

    @property
    def authenticator_id(self) -> str:
        return "test-only-private-manifest-hmac-v1"

    @property
    def authentication_scheme(self) -> str:
        return "test-only-hmac-sha256-nonproduction"

    def authenticate(self, payload: bytes) -> str:
        return hmac.new(self._secret, payload, hashlib.sha256).hexdigest()

    def verify(self, payload: bytes, authentication_tag: str) -> bool:
        return hmac.compare_digest(self.authenticate(payload), authentication_tag)


class AuthorizedRolePublicUsageSummaryV1(ContractModel):
    """Original coarse aggregate usage contract retained for V1 sidecars."""

    schema_version: Literal["autolean.authorized-role-public-usage.v1"] = (
        "autolean.authorized-role-public-usage.v1"
    )
    trial_count: Literal[10] = 10
    aggregate_input_tokens_bucket: str = Field(pattern=r"^[a-z0-9_-]{1,32}$")
    aggregate_cached_input_tokens_bucket: str = Field(pattern=r"^[a-z0-9_-]{1,32}$")
    aggregate_output_tokens_bucket: str = Field(pattern=r"^[a-z0-9_-]{1,32}$")
    aggregate_elapsed_ms_bucket: str = Field(pattern=r"^[a-z0-9_-]{1,32}$")


class AuthorizedRolePublicUsageSummaryV2(ContractModel):
    """Exact bucket vocabulary for V2 suite evidence."""

    schema_version: Literal["autolean.authorized-role-public-usage.v2"] = (
        "autolean.authorized-role-public-usage.v2"
    )
    trial_count: Literal[10] = 10
    aggregate_input_tokens_bucket: str = Field(pattern=_TOKEN_BUCKET_PATTERN)
    aggregate_cached_input_tokens_bucket: str = Field(pattern=_TOKEN_BUCKET_PATTERN)
    aggregate_output_tokens_bucket: str = Field(pattern=_TOKEN_BUCKET_PATTERN)
    aggregate_elapsed_ms_bucket: str = Field(pattern=_ELAPSED_BUCKET_PATTERN)


class _AuthorizedRoleSuiteSidecarBase(_AuthorizedRoleRunIdContractModel):
    run_id: AuthorizedRoleRunIdV1
    private_manifest_handle: str = Field(pattern=_PRIVATE_HANDLE_PATTERN)
    production_evaluator: Literal[False] = False
    floor_claim_eligible: Literal[False] = False
    cross_role_aggregation_permitted: Literal[False] = False

    def _validate_trial_set(
        self,
        trials: tuple[AuthorizedRoleTrialSidecarV1 | AuthorizedRoleTrialSidecarV2, ...],
    ) -> None:
        coordinates = tuple((item.cell_id, item.case_id, item.repetition) for item in trials)
        if (
            len(trials) != 10
            or coordinates != tuple(sorted(coordinates))
            or len(coordinates) != len(set(coordinates))
            or any(item.run_id != self.run_id for item in trials)
        ):
            raise ValueError("authorized role suite must contain ten canonical unique trials")
        role_counts = {role: 0 for role in ModelWorkRoleV1}
        for item in trials:
            role_counts[item.role] += 1
        if set(role_counts.values()) != {2}:
            raise ValueError("authorized role suite must keep exactly two trials per role")


class AuthorizedRoleSuiteSidecarV1(_AuthorizedRoleSuiteSidecarBase):
    """Original ten-case suite evidence without public per-trial usage."""

    schema_version: Literal["autolean.authorized-role-suite-sidecar.v1"] = (
        "autolean.authorized-role-suite-sidecar.v1"
    )
    usage_summary: AuthorizedRolePublicUsageSummaryV1
    trials: tuple[AuthorizedRoleTrialSidecarV1, ...]

    @model_validator(mode="after")
    def validate_trials(self) -> Self:
        self._validate_trial_set(self.trials)
        return self


class AuthorizedRoleSuiteSidecarV2(_AuthorizedRoleSuiteSidecarBase):
    """V2 suite evidence requiring authenticated coarse usage on every trial."""

    schema_version: Literal["autolean.authorized-role-suite-sidecar.v2"] = (
        "autolean.authorized-role-suite-sidecar.v2"
    )
    usage_summary: AuthorizedRolePublicUsageSummaryV2
    trials: tuple[AuthorizedRoleTrialSidecarV2, ...]

    @model_validator(mode="after")
    def validate_trials(self) -> Self:
        self._validate_trial_set(self.trials)
        return self


def _private_manifest_authentication_payload(
    binding: AuthorizedRolePrivateManifestBindingV1,
    *,
    authenticator_id: str,
    authentication_scheme: str,
) -> bytes:
    return canonical_json_bytes(
        {
            "schema_version": "autolean.authorized-role-private-manifest-authentication.v1",
            "binding": binding.model_dump(mode="json"),
            "authenticator_id": authenticator_id,
            "authentication_scheme": authentication_scheme,
        }
    )


def _private_run_index_authentication_payload(
    binding: AuthorizedRolePrivateRunIndexBindingV1,
    *,
    authenticator_id: str,
    authentication_scheme: str,
) -> bytes:
    return canonical_json_bytes(
        {
            "schema_version": "autolean.authorized-role-private-run-index-authentication.v1",
            "binding": binding.model_dump(mode="json"),
            "authenticator_id": authenticator_id,
            "authentication_scheme": authentication_scheme,
        }
    )


class AuthorizedRoleRawOutputStore:
    """Operator-private CAS and dispatch journal required before public evidence is returned."""

    def __init__(
        self,
        root: Path,
        *,
        private_authenticator: OperatorPrivateManifestAuthenticator,
    ) -> None:
        if not isinstance(private_authenticator, OperatorPrivateManifestAuthenticator):
            raise AuthorizedRoleBridgeError(
                "operator-private manifest authenticator must be injected explicitly"
            )
        for label, value in (
            ("authenticator_id", private_authenticator.authenticator_id),
            ("authentication_scheme", private_authenticator.authentication_scheme),
        ):
            if not isinstance(value, str) or re.fullmatch(_IDENTIFIER_PATTERN, value) is None:
                raise AuthorizedRoleBridgeError(f"private manifest {label} is invalid")
        self._store = RoleBenchmarkRawOutputStore(root)
        self._root = root.resolve(strict=False)
        self._reconciliation_root = self._root / "authorized-role-reconciliation"
        self._bundle_index_root = self._root / "authorized-role-bundle-index"
        self._manifest_handle_root = self._root / "authorized-role-manifest-handles"
        self._run_index_root = self._root / "authorized-role-run-index"
        self._private_authenticator = private_authenticator

    def put_response(self, response: ModelResponse) -> str:
        artifact = _raw_response_artifact(response)
        output_hash = self._store.put_output(artifact)
        self._store.verify_output(output_hash)
        return output_hash

    def begin_provider_call(
        self,
        *,
        bundle_id: str,
        authorization_hash: str,
    ) -> AuthorizedRolePrivateReconciliationV1:
        """Create conservative private dispatch state before entering provider code."""

        private_handle = _new_private_handle()
        index_path = self._bundle_index_path(bundle_id)
        index_payload = canonical_json_bytes(
            {
                "schema_version": "autolean.authorized-role-private-index.v1",
                "private_handle": private_handle,
                "bundle_id": bundle_id,
                "authorization_hash": authorization_hash,
            }
        )
        try:
            _write_private_exclusive(index_path, index_payload)
        except FileExistsError:
            state = self.reconciliation_for_bundle(bundle_id)
            status = "unknown" if state is None else state.state
            raise AuthorizedRoleReconciliationRequired(
                f"model work has existing private reconciliation state: {status}"
            ) from None
        state = AuthorizedRolePrivateReconciliationV1(
            private_handle=private_handle,
            bundle_id=bundle_id,
            authorization_hash=authorization_hash,
            state="provider_outcome_ambiguous",
        )
        try:
            _write_private_exclusive(
                self._reconciliation_path(private_handle),
                canonical_json_bytes(state.model_dump(mode="json")),
            )
        except Exception:
            # The durable bundle index intentionally remains.  A subsequent run sees an
            # ambiguous private state and cannot replay the provider call automatically.
            raise AuthorizedRoleReconciliationRequired(
                "private dispatch journal could not be initialized"
            ) from None
        return state

    def persist_provider_response(
        self,
        state: AuthorizedRolePrivateReconciliationV1,
        response: ModelResponse,
        *,
        elapsed_ms: int,
    ) -> AuthorizedRolePrivateReconciliationV1:
        """Persist raw output first, then atomically close the conservative dispatch state."""

        current = self._read_reconciliation(state.private_handle)
        if current != state or state.state != "provider_outcome_ambiguous":
            raise AuthorizedRoleReconciliationRequired(
                "private dispatch state changed before response persistence"
            )
        output_hash = self.put_response(response)
        persisted = AuthorizedRolePrivateReconciliationV1(
            private_handle=state.private_handle,
            bundle_id=state.bundle_id,
            authorization_hash=state.authorization_hash,
            state="response_persisted",
            output_hash=output_hash,
            elapsed_ms=elapsed_ms,
            input_tokens=response.usage.input_tokens,
            cached_input_tokens=response.usage.cached_input_tokens,
            output_tokens=response.usage.output_tokens,
        )
        _replace_private_file(
            self._reconciliation_path(state.private_handle),
            canonical_json_bytes(persisted.model_dump(mode="json")),
        )
        return persisted

    def reconciliation_for_bundle(
        self,
        bundle_id: str,
    ) -> AuthorizedRolePrivateReconciliationV1 | None:
        """Return private state for operator reconciliation; this is never a replay permit."""

        index_path = self._bundle_index_path(bundle_id)
        try:
            payload = index_path.read_bytes()
        except FileNotFoundError:
            return None
        try:
            raw: object = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise AuthorizedRoleReconciliationRequired(
                "private bundle index is unreadable and provider outcome is ambiguous"
            ) from None
        if (
            not isinstance(raw, dict)
            or raw.get("schema_version") != "autolean.authorized-role-private-index.v1"
            or raw.get("bundle_id") != bundle_id
            or not isinstance(raw.get("private_handle"), str)
            or not isinstance(raw.get("authorization_hash"), str)
            or canonical_json_bytes(raw) != payload
        ):
            raise AuthorizedRoleReconciliationRequired(
                "private bundle index is invalid and provider outcome is ambiguous"
            )
        private_handle = str(raw["private_handle"])
        try:
            return self._read_reconciliation(private_handle)
        except FileNotFoundError:
            return AuthorizedRolePrivateReconciliationV1(
                private_handle=private_handle,
                bundle_id=bundle_id,
                authorization_hash=str(raw["authorization_hash"]),
                state="provider_outcome_ambiguous",
            )

    def put_manifest(self, manifest: AuthorizedRolePrivateManifestV1) -> str:
        """Store the digest and an authenticated opaque mapping in private storage."""

        if self._run_index_path(manifest.run_id).exists():
            raise AuthorizedRoleReconciliationRequired("operator-private run index already exists")
        for item in manifest.outputs:
            self._store.verify_output(item.output_hash)
        manifest_hash = self._store.put_output(manifest.model_dump(mode="json"))
        self._store.verify_output(manifest_hash)
        if manifest_hash != manifest.content_hash():
            raise AuthorizedRoleBridgeError("private manifest CAS hash is inconsistent")
        private_handle = _new_private_handle()
        binding = AuthorizedRolePrivateManifestBindingV1(
            private_handle=private_handle,
            manifest_hash=manifest_hash,
            run_id=manifest.run_id,
            coordinates=tuple(
                AuthorizedRolePrivateManifestCoordinateV1(
                    cell_id=item.cell_id,
                    case_id=item.case_id,
                    repetition=item.repetition,
                    authorization_hash=item.authorization_hash,
                )
                for item in manifest.outputs
            ),
        )
        authenticator_id = self._private_authenticator.authenticator_id
        authentication_scheme = self._private_authenticator.authentication_scheme
        authentication_payload = _private_manifest_authentication_payload(
            binding,
            authenticator_id=authenticator_id,
            authentication_scheme=authentication_scheme,
        )
        authentication_tag = self._private_authenticator.authenticate(authentication_payload)
        if (
            not isinstance(authentication_tag, str)
            or re.fullmatch(_PRIVATE_AUTHENTICATION_TAG_PATTERN, authentication_tag) is None
            or not self._private_authenticator.verify(
                authentication_payload,
                authentication_tag,
            )
        ):
            raise AuthorizedRoleBridgeError(
                "operator-private manifest authenticator returned an invalid tag"
            )
        record = AuthorizedRoleAuthenticatedManifestHandleV1(
            binding=binding,
            authenticator_id=authenticator_id,
            authentication_scheme=authentication_scheme,
            authentication_tag=authentication_tag,
        )
        _write_private_exclusive(
            self._manifest_handle_root / f"{private_handle}.json",
            canonical_json_bytes(record.model_dump(mode="json")),
        )
        run_index_binding = AuthorizedRolePrivateRunIndexBindingV1(
            run_id=manifest.run_id,
            private_handle=private_handle,
            manifest_hash=manifest_hash,
        )
        run_index_payload = _private_run_index_authentication_payload(
            run_index_binding,
            authenticator_id=authenticator_id,
            authentication_scheme=authentication_scheme,
        )
        run_index_tag = self._private_authenticator.authenticate(run_index_payload)
        if (
            not isinstance(run_index_tag, str)
            or re.fullmatch(_PRIVATE_AUTHENTICATION_TAG_PATTERN, run_index_tag) is None
            or not self._private_authenticator.verify(run_index_payload, run_index_tag)
        ):
            raise AuthorizedRoleBridgeError(
                "operator-private run index authenticator returned an invalid tag"
            )
        run_index = AuthorizedRoleAuthenticatedRunIndexV1(
            binding=run_index_binding,
            authenticator_id=authenticator_id,
            authentication_scheme=authentication_scheme,
            authentication_tag=run_index_tag,
        )
        try:
            _write_private_exclusive(
                self._run_index_path(manifest.run_id),
                canonical_json_bytes(run_index.model_dump(mode="json")),
            )
        except FileExistsError:
            raise AuthorizedRoleReconciliationRequired(
                "operator-private run index already exists"
            ) from None
        return private_handle

    def resolve_run_manifest_handle(self, run_id: str) -> str:
        """Recover an authenticated manifest handle by run ID after process restart."""

        run_id = validate_authorized_role_run_id(run_id)
        try:
            payload = self._run_index_path(run_id).read_bytes()
            record = AuthorizedRoleAuthenticatedRunIndexV1.model_validate_json(payload)
        except (OSError, ValueError):
            raise AuthorizedRoleReconciliationRequired(
                "operator-private run index cannot be reconciled"
            ) from None
        if (
            record.binding.run_id != run_id
            or record.authenticator_id != self._private_authenticator.authenticator_id
            or record.authentication_scheme != self._private_authenticator.authentication_scheme
            or canonical_json_bytes(record.model_dump(mode="json")) != payload
        ):
            raise AuthorizedRoleReconciliationRequired("operator-private run index is invalid")
        authentication_payload = _private_run_index_authentication_payload(
            record.binding,
            authenticator_id=record.authenticator_id,
            authentication_scheme=record.authentication_scheme,
        )
        if not self._private_authenticator.verify(
            authentication_payload,
            record.authentication_tag,
        ):
            raise AuthorizedRoleReconciliationRequired(
                "operator-private run index authentication failed"
            )
        manifest_record = self._read_authenticated_manifest_record(record.binding.private_handle)
        if (
            manifest_record.binding.run_id != run_id
            or manifest_record.binding.manifest_hash != record.binding.manifest_hash
        ):
            raise AuthorizedRoleReconciliationRequired("operator-private run index is misbound")
        return record.binding.private_handle

    def resolve_manifest_handle(self, private_handle: str) -> str:
        """Resolve an opaque manifest handle inside the operator-private store only."""

        return self._read_authenticated_manifest_record(private_handle).binding.manifest_hash

    def read_authenticated_manifest(
        self,
        private_handle: str,
    ) -> AuthorizedRolePrivateManifestV1:
        """Return only the canonical manifest bound by an authenticated opaque handle."""

        record = self._read_authenticated_manifest_record(private_handle)
        manifest_hash = record.binding.manifest_hash
        try:
            payload = self._store._artifacts.get_bytes(manifest_hash)
            manifest = AuthorizedRolePrivateManifestV1.model_validate_json(payload)
        except Exception:
            raise AuthorizedRoleReconciliationRequired(
                "authenticated private manifest cannot be reconciled"
            ) from None
        expected_coordinates = tuple(
            AuthorizedRolePrivateManifestCoordinateV1(
                cell_id=item.cell_id,
                case_id=item.case_id,
                repetition=item.repetition,
                authorization_hash=item.authorization_hash,
            )
            for item in manifest.outputs
        )
        if (
            canonical_json_bytes(manifest.model_dump(mode="json")) != payload
            or manifest.content_hash() != manifest_hash
            or manifest.run_id != record.binding.run_id
            or expected_coordinates != record.binding.coordinates
        ):
            raise AuthorizedRoleReconciliationRequired(
                "authenticated private manifest binding is invalid"
            )
        return manifest

    def read_authenticated_response(
        self,
        private_handle: str,
        entry: AuthorizedRolePrivateOutputEntryV1,
        *,
        expected_bundle_id: str,
    ) -> ModelResponse:
        """Read one strongly typed response after rechecking its complete private binding."""

        self._read_authenticated_reconciliation_for_entry(
            private_handle,
            entry,
            expected_bundle_id=expected_bundle_id,
        )
        try:
            payload = self._store._artifacts.get_bytes(entry.output_hash)
            artifact = _AuthorizedRoleRawResponseV1.model_validate_json(payload)
        except Exception:
            raise AuthorizedRoleReconciliationRequired(
                "authenticated private response artifact is invalid"
            ) from None
        if (
            canonical_json_bytes(artifact.model_dump(mode="json")) != payload
            or artifact.usage.input_tokens != entry.input_tokens
            or artifact.usage.cached_input_tokens != entry.cached_input_tokens
            or artifact.usage.output_tokens != entry.output_tokens
        ):
            raise AuthorizedRoleReconciliationRequired(
                "authenticated private response artifact is misbound"
            )
        return artifact.to_model_response()

    def authenticated_output_commitment(
        self,
        private_handle: str,
        entry: AuthorizedRolePrivateOutputEntryV1,
        *,
        expected_bundle_id: str,
        coordinate_hash: str,
    ) -> str:
        """Return a keyed public commitment without exposing a private CAS locator."""

        self._read_authenticated_reconciliation_for_entry(
            private_handle,
            entry,
            expected_bundle_id=expected_bundle_id,
        )
        if (
            not isinstance(coordinate_hash, str)
            or re.fullmatch(_SHA256_PATTERN, coordinate_hash) is None
        ):
            raise AuthorizedRoleReconciliationRequired(
                "authenticated output commitment coordinate is invalid"
            )
        payload = canonical_json_bytes(
            {
                "schema_version": "autolean.authorized-role-private-output-commitment.v1",
                "coordinate_hash": coordinate_hash,
                "cell_id": entry.cell_id,
                "case_id": entry.case_id,
                "repetition": entry.repetition,
                "bundle_id": expected_bundle_id,
                "authorization_hash": entry.authorization_hash,
                "private_output_hash": entry.output_hash,
            }
        )
        try:
            authentication_tag = self._private_authenticator.authenticate(payload)
            valid_tag = (
                isinstance(authentication_tag, str)
                and re.fullmatch(_PRIVATE_AUTHENTICATION_TAG_PATTERN, authentication_tag)
                is not None
                and self._private_authenticator.verify(payload, authentication_tag)
            )
        except Exception:
            raise AuthorizedRoleReconciliationRequired(
                "authenticated output commitment could not be created"
            ) from None
        if not valid_tag:
            raise AuthorizedRoleReconciliationRequired("authenticated output commitment is invalid")
        try:
            return hashlib.sha256(
                canonical_json_bytes(
                    {
                        "schema_version": "autolean.authorized-role-public-output-commitment.v1",
                        "authenticator_id": self._private_authenticator.authenticator_id,
                        "authentication_scheme": self._private_authenticator.authentication_scheme,
                        "authentication_tag": authentication_tag,
                    }
                )
            ).hexdigest()
        except Exception:
            raise AuthorizedRoleReconciliationRequired(
                "authenticated output commitment could not be finalized"
            ) from None

    def _read_authenticated_reconciliation_for_entry(
        self,
        private_handle: str,
        entry: AuthorizedRolePrivateOutputEntryV1,
        *,
        expected_bundle_id: str,
    ) -> AuthorizedRolePrivateReconciliationV1:
        if not isinstance(entry, AuthorizedRolePrivateOutputEntryV1):
            raise AuthorizedRoleReconciliationRequired(
                "authenticated private response entry is invalid"
            )
        if (
            not isinstance(expected_bundle_id, str)
            or re.fullmatch(_IDENTIFIER_PATTERN, expected_bundle_id) is None
        ):
            raise AuthorizedRoleReconciliationRequired(
                "authenticated private response bundle is invalid"
            )
        manifest = self.read_authenticated_manifest(private_handle)
        if entry not in manifest.outputs:
            raise AuthorizedRoleReconciliationRequired(
                "authenticated private response is not an exact manifest member"
            )
        try:
            state = self._read_reconciliation(entry.private_reconciliation_handle)
        except Exception:
            raise AuthorizedRoleReconciliationRequired(
                "authenticated private response reconciliation is invalid"
            ) from None
        if (
            state.state != "response_persisted"
            or state.bundle_id != expected_bundle_id
            or state.authorization_hash != entry.authorization_hash
            or state.output_hash != entry.output_hash
            or state.elapsed_ms != entry.elapsed_ms
            or state.input_tokens != entry.input_tokens
            or state.cached_input_tokens != entry.cached_input_tokens
            or state.output_tokens != entry.output_tokens
        ):
            raise AuthorizedRoleReconciliationRequired(
                "authenticated private response reconciliation is misbound"
            )
        return state

    def _read_authenticated_manifest_record(
        self,
        private_handle: str,
    ) -> AuthorizedRoleAuthenticatedManifestHandleV1:
        private_handle = _validated_private_handle(private_handle)
        try:
            payload = (self._manifest_handle_root / f"{private_handle}.json").read_bytes()
            record = AuthorizedRoleAuthenticatedManifestHandleV1.model_validate_json(payload)
        except (OSError, ValueError):
            raise AuthorizedRoleReconciliationRequired(
                "private manifest handle cannot be reconciled"
            ) from None
        if (
            record.binding.private_handle != private_handle
            or record.authenticator_id != self._private_authenticator.authenticator_id
            or record.authentication_scheme != self._private_authenticator.authentication_scheme
            or canonical_json_bytes(record.model_dump(mode="json")) != payload
        ):
            raise AuthorizedRoleReconciliationRequired("private manifest handle is invalid")
        authentication_payload = _private_manifest_authentication_payload(
            record.binding,
            authenticator_id=record.authenticator_id,
            authentication_scheme=record.authentication_scheme,
        )
        if not self._private_authenticator.verify(
            authentication_payload,
            record.authentication_tag,
        ):
            raise AuthorizedRoleReconciliationRequired(
                "private manifest handle authentication failed"
            )
        try:
            self._store.verify_output(record.binding.manifest_hash)
        except Exception:
            raise AuthorizedRoleReconciliationRequired(
                "private manifest artifact cannot be reconciled"
            ) from None
        return record

    def verify(self, digest: str) -> None:
        self._store.verify_output(digest)

    def _bundle_index_path(self, bundle_id: str) -> Path:
        bundle_key = hashlib.sha256(bundle_id.encode("utf-8")).hexdigest()
        return self._bundle_index_root / f"{bundle_key}.json"

    def _run_index_path(self, run_id: str) -> Path:
        run_key = hashlib.sha256(
            validate_authorized_role_run_id(run_id).encode("utf-8")
        ).hexdigest()
        return self._run_index_root / f"{run_key}.json"

    def _reconciliation_path(self, private_handle: str) -> Path:
        return self._reconciliation_root / f"{_validated_private_handle(private_handle)}.json"

    def _read_reconciliation(
        self,
        private_handle: str,
    ) -> AuthorizedRolePrivateReconciliationV1:
        path = self._reconciliation_path(private_handle)
        payload = path.read_bytes()
        try:
            state = AuthorizedRolePrivateReconciliationV1.model_validate_json(payload)
        except ValueError:
            raise AuthorizedRoleReconciliationRequired(
                "private reconciliation state is invalid"
            ) from None
        if (
            state.private_handle != private_handle
            or canonical_json_bytes(state.model_dump(mode="json")) != payload
        ):
            raise AuthorizedRoleReconciliationRequired(
                "private reconciliation state is non-canonical or misbound"
            )
        return state


@dataclass(frozen=True, slots=True)
class AuthorizedRoleSuiteDefinition:
    """Fixed ten-case suite derived from the locked repository calibration fixture."""

    matrix: RoleBenchmarkMatrixV1
    source: SourceRecordV1
    rights: RightsRecordV1
    generation_policy: AuthorizedRoleGenerationPolicyV1
    work_evidence: LockedRoleWorkEvidenceV1


@dataclass(frozen=True, slots=True)
class PreparedAuthorizedRoleTrial:
    """In-memory trial input; only hashes are copied into its public sidecar."""

    context: AuthorizedRoleContextV1
    request: ModelRequest
    work_bundle: ModelWorkBundleV2
    cell: RoleBenchmarkCellV1
    generation_policy: AuthorizedRoleGenerationPolicyV1
    work_evidence: LockedRoleWorkEvidenceV1


@dataclass(frozen=True, slots=True)
class PreflightedAuthorizedRoleTrial:
    """A fully authorized trial that has not probed or called its provider."""

    prepared: PreparedAuthorizedRoleTrial
    authorization: ModelExecutionAuthorizationV1


@dataclass(frozen=True, slots=True)
class AuthorizedRoleTrialExecution:
    """A public sidecar returned only after its normalized response reached private CAS."""

    authorization: ModelExecutionAuthorizationV1
    sidecar: AuthorizedRoleTrialSidecarV2
    private_state: AuthorizedRolePrivateReconciliationV1


def build_locked_calibration_floor_suite(
    target: RoleModelTargetV1,
    *,
    generation_policy: AuthorizedRoleGenerationPolicyV1,
    repetitions: int = 1,
    max_cost_microusd_per_trial: int,
) -> AuthorizedRoleSuiteDefinition:
    """Build the one five-role matrix from pinned bytes and a frozen provider target."""

    if repetitions < 1 or repetitions > 100:
        raise AuthorizedRoleBridgeError("floor-suite repetitions must be between 1 and 100")
    if max_cost_microusd_per_trial < 0:
        raise AuthorizedRoleBridgeError("floor-suite cost budget must be non-negative")
    if target.generation_parameters_hash != generation_policy.content_hash():
        raise AuthorizedRoleBridgeError(
            "role target generation_parameters_hash must equal the frozen generation policy"
        )
    fixture_bytes = _CALIBRATION_FIXTURE_PATH.read_bytes()
    observed_hash = hashlib.sha256(fixture_bytes).hexdigest()
    if observed_hash != _CALIBRATION_FIXTURE_SHA256:
        raise AuthorizedRoleBridgeError("locked role calibration fixture bytes have drifted")
    license_bytes = _LICENSE_PATH.read_bytes()
    if hashlib.sha256(license_bytes).hexdigest() != _LICENSE_SHA256:
        raise AuthorizedRoleBridgeError("locked Apache-2.0 license bytes have drifted")
    try:
        fixture = FakeRoleBenchmarkFixtureV1.model_validate_json(fixture_bytes)
    except ValueError as error:
        raise AuthorizedRoleBridgeError("locked role calibration fixture is invalid") from error
    if fixture.matrix.matrix_id != "role-calibration-pairs" or len(fixture.matrix.cases) != 10:
        raise AuthorizedRoleBridgeError("locked role calibration fixture shape has drifted")

    cells: list[RoleBenchmarkCellV1] = []
    for role in BenchmarkRoleV1:
        templates = tuple(
            cell
            for cell in fixture.matrix.cells
            if cell.role is role and cell.cell_id.startswith("fake.oracle.")
        )
        if len(templates) != 1:
            raise AuthorizedRoleBridgeError(
                "locked role calibration fixture lacks one canonical role template"
            )
        template = templates[0]
        cells.append(
            RoleBenchmarkCellV1.model_validate(
                {
                    **template.model_dump(mode="json"),
                    "cell_id": f"authorized.{target.provider_id}.{role.value.replace('_', '-')}",
                    "model": target.model_dump(mode="json"),
                    "required_capabilities": tuple(
                        sorted(
                            _required_generation_capabilities(generation_policy),
                            key=str,
                        )
                    ),
                    "budget": {
                        **template.budget.model_dump(mode="json"),
                        "repetitions": repetitions,
                        "timeout_ms": generation_policy.timeout_seconds * 1000,
                        "max_cost_microusd": max_cost_microusd_per_trial,
                    },
                }
            )
        )
    matrix = RoleBenchmarkMatrixV1(
        matrix_id=f"authorized-floor-{target.provider_id}",
        matrix_revision="1",
        sampling_seed="autolean-authorized-role-floor-v1",
        cases=fixture.matrix.cases,
        cells=tuple(cells),
    )
    spans = tuple(
        sorted(
            (
                _egress_source_span(case, cell)
                for cell in matrix.cells
                for case in matrix.cases
                if case.case_id in cell.case_ids
            ),
            key=lambda item: item.locator,
        )
    )
    source = SourceRecordV1(
        source_id=stable_identifier(
            "authorized-role-source",
            f"calibration-pairs-v3:{_CALIBRATION_FIXTURE_SHA256}",
        ),
        work_id="role-calibration-pairs-v3",
        title="AutoLean synthetic role calibration pairs",
        version="3",
        locator="repo://benchmarks/roles/calibration-pairs.v3.json",
        content_hash=digest_bytes(HashKindV1.SOURCE_BYTES, fixture_bytes),
        retrieved_at=_CALIBRATION_TIMESTAMP,
        spans=spans,
        metadata={
            "locked_sha256": _CALIBRATION_FIXTURE_SHA256,
            "license_file": "repo://LICENSE",
            "license_sha256": _LICENSE_SHA256,
        },
    )
    rights = RightsRecordV1(
        rights_id=stable_identifier(
            "authorized-role-rights",
            f"calibration-pairs-v3:{_CALIBRATION_FIXTURE_SHA256}:apache-2.0",
        ),
        source_id=source.source_id,
        source_license="Apache-2.0",
        overall_decision=PermissionDecisionV1.ALLOW,
        redistribution=PermissionDecisionV1.ALLOW,
        model_egress=PermissionDecisionV1.ALLOW,
        allowed_endpoint_classes=(EndpointClassV1.APPROVED_EXTERNAL,),
        attribution="AutoLean calibration fixture; Apache-2.0",
        reviewed_by="autolean-locked-fixture-license-v1",
        reviewed_at=_CALIBRATION_TIMESTAMP,
    )
    work_evidence = _build_locked_work_evidence(
        target=target,
        matrix=matrix,
        source=source,
        rights=rights,
        generation_policy=generation_policy,
    )
    return AuthorizedRoleSuiteDefinition(
        matrix=matrix,
        source=source,
        rights=rights,
        generation_policy=generation_policy,
        work_evidence=work_evidence,
    )


def prepare_authorized_role_trial(
    suite: AuthorizedRoleSuiteDefinition,
    cell: RoleBenchmarkCellV1,
    *,
    case_id: str,
    repetition: int,
    run_id: str,
) -> PreparedAuthorizedRoleTrial:
    """Build one exact, tool-free trial without copying its oracle into model context."""

    run_id = validate_authorized_role_run_id(run_id)
    _assert_locked_suite(suite)
    matrix = suite.matrix
    matrix_cells = {item.cell_id: item for item in matrix.cells}
    matrix_cell = matrix_cells.get(cell.cell_id)
    if matrix_cell is None or matrix_cell != cell:
        raise AuthorizedRoleBridgeError("role cell is not an exact member of the matrix")
    cases = {item.case_id: item for item in matrix.cases}
    case = cases.get(case_id)
    if case is None or case_id not in cell.case_ids:
        raise AuthorizedRoleBridgeError("role case is not eligible for this cell")
    if case.role is not cell.role:
        raise AuthorizedRoleBridgeError("role case and cell roles differ")
    if cell.tools or cell.retrieval_scope:
        raise AuthorizedRoleBridgeError("ModelWorkBundleV2 forbids tools and retrieval")
    expected_capabilities = _required_generation_capabilities(suite.generation_policy)
    if frozenset(cell.required_capabilities) != expected_capabilities:
        raise AuthorizedRoleBridgeError(
            "role cell capabilities do not match the frozen generation policy"
        )
    if cell.budget.timeout_ms != suite.generation_policy.timeout_seconds * 1000:
        raise AuthorizedRoleBridgeError(
            "role cell timeout does not match the frozen generation policy"
        )
    if repetition < 1 or repetition > cell.budget.repetitions:
        raise AuthorizedRoleBridgeError("role trial repetition is outside the cell budget")

    trial_seed = derive_trial_seed(
        matrix,
        cell,
        case_id=case_id,
        repetition=repetition,
    )
    cell_contract_hash = _content_hash(cell)
    case_contract_hash = _content_hash(case)
    base_work_item_hash = _answer_free_work_item_hash(
        matrix=matrix,
        cell=cell,
        case=case,
        cell_contract_hash=cell_contract_hash,
        work_evidence_hash=suite.work_evidence.content_hash(),
    )
    work_item_hash = _content_hash(
        {
            "schema_version": "autolean.authorized-role-trial-work-item.v1",
            "base_work_item_hash": base_work_item_hash,
            "repetition": repetition,
            "trial_seed": trial_seed,
        }
    )
    prompt = _render_answer_free_prompt(case, cell)
    egress_content = _egress_content(cell.prompt.system_prompt, prompt)
    egress_content_hash = digest_text(HashKindV1.SOURCE_SPAN, egress_content)
    matching_spans = tuple(
        span for span in suite.source.spans if span.content_hash == egress_content_hash
    )
    if len(matching_spans) != 1 or matching_spans[0].permitted_excerpt != egress_content:
        raise AuthorizedRoleBridgeError(
            "answer-free egress is not an exact permitted span of the locked source"
        )
    role = ModelWorkRoleV1(cell.role.value)
    context = AuthorizedRoleContextV1(
        run_id=run_id,
        cell_id=cell.cell_id,
        case_id=case.case_id,
        repetition=repetition,
        trial_seed=trial_seed,
        role=role,
        work_item_hash=work_item_hash,
        system_prompt=cell.prompt.system_prompt,
        prompt=prompt,
    )
    request = ModelRequest(
        prompt=context.prompt,
        system_prompt=context.system_prompt,
        max_input_tokens=cell.budget.max_input_tokens,
        max_output_tokens=cell.budget.max_output_tokens,
        timeout_seconds=suite.generation_policy.timeout_seconds,
        reasoning_effort=suite.generation_policy.reasoning_effort,
        required_capabilities=expected_capabilities,
        context_pack_hash=context.content_hash(),
    )
    run_hash = model_work_run_hash(run_id)
    cell_hash = model_work_cell_hash(cell.cell_id)
    case_hash = model_work_case_hash(case.case_id)
    typed_cell_contract_hash = model_work_cell_contract_hash(cell_contract_hash)
    typed_case_contract_hash = model_work_case_contract_hash(case_contract_hash)
    typed_work_item_hash = model_work_item_hash(work_item_hash)
    work_bundle = ModelWorkBundleV2(
        bundle_id=model_work_bundle_id(
            run_hash=run_hash,
            cell_hash=cell_hash,
            case_hash=case_hash,
            repetition=repetition,
            role=role,
        ),
        work_contract_id=model_work_contract_id(
            cell_contract_hash=typed_cell_contract_hash,
            case_contract_hash=typed_case_contract_hash,
        ),
        run_hash=run_hash,
        cell_hash=cell_hash,
        case_hash=case_hash,
        repetition=repetition,
        role=role,
        cell_contract_hash=typed_cell_contract_hash,
        case_contract_hash=typed_case_contract_hash,
        work_item_hash=typed_work_item_hash,
        role_environment_hash=digest_model(
            HashKindV1.ENVIRONMENT,
            {
                "schema_version": "autolean.role-environment.v1",
                "environment_hash": cell.environment_hash,
                "code_revision_hash": cell.code_revision_hash,
            },
        ),
        egress_content_hash=egress_content_hash,
        context_pack_hash=context.content_hash(),
        request_hash=request.outbound_request_hash(),
        source=model_work_source_binding(suite.source),
        rights=model_work_rights_binding(suite.rights),
    )
    return PreparedAuthorizedRoleTrial(
        context=context,
        request=request,
        work_bundle=work_bundle,
        cell=cell,
        generation_policy=suite.generation_policy,
        work_evidence=suite.work_evidence,
    )


def execute_authorized_role_trial(
    prepared: PreparedAuthorizedRoleTrial,
    *,
    authorization_service: ModelExecutionAuthorizationService,
    admission: AttestationV1,
    registry: ProviderRegistry,
    approval: ModelExecutionProviderApprovalV1,
    budget: ModelExecutionBudgetV1,
    raw_output_store: AuthorizedRoleRawOutputStore,
    settlement_margin_seconds: float = _ROLE_SETTLEMENT_MARGIN_SECONDS,
    lease_ttl_seconds: float | None = None,
    authorization_ttl_seconds: float | None = None,
) -> AuthorizedRoleTrialExecution:
    """Run one trial through the existing signed authorization and registry path."""

    resolved_lease_ttl, resolved_authorization_ttl = _resolved_role_lifetimes(
        prepared,
        authorization_service=authorization_service,
        settlement_margin_seconds=settlement_margin_seconds,
        lease_ttl_seconds=lease_ttl_seconds,
        authorization_ttl_seconds=authorization_ttl_seconds,
    )
    _validate_authorized_role_trial(
        prepared,
        authorization_service=authorization_service,
        admission=admission,
        registry=registry,
        approval=approval,
        budget=budget,
        required_admission_validity_seconds=resolved_lease_ttl,
    )
    authorized = _authorize_role_trial_jit(
        prepared,
        authorization_service=authorization_service,
        admission=admission,
        registry=registry,
        approval=approval,
        budget=budget,
        lease_ttl_seconds=resolved_lease_ttl,
        authorization_ttl_seconds=resolved_authorization_ttl,
    )
    return _execute_preflighted_authorized_role_trial(
        authorized,
        registry=registry,
        raw_output_store=raw_output_store,
    )


def _validate_authorized_role_trial(
    prepared: PreparedAuthorizedRoleTrial,
    *,
    authorization_service: ModelExecutionAuthorizationService,
    admission: AttestationV1,
    registry: ProviderRegistry,
    approval: ModelExecutionProviderApprovalV1,
    budget: ModelExecutionBudgetV1,
    required_admission_validity_seconds: float,
) -> None:
    """Validate one exact trial without writes, probes, leases, or provider dispatch."""

    _assert_prepared_trial(prepared)
    _assert_role_trial_budget(prepared, budget)
    if not isinstance(admission, AttestationV1):
        raise AuthorizedRoleBridgeError("role trial admission must be an AttestationV1")
    bundle = prepared.work_bundle
    _assert_cell_model_binding(prepared.cell, approval.binding)
    try:
        effective_timeout = registry.effective_timeout_seconds(
            approval.binding,
            prepared.request,
        )
    except Exception:
        raise AuthorizedRoleBridgeError(
            "registered provider timeout policy rejected the frozen role request"
        ) from None
    if effective_timeout != float(prepared.generation_policy.timeout_seconds):
        raise AuthorizedRoleBridgeError(
            "provider effective timeout does not match the frozen role execution policy"
        )
    authorization_service.preflight_operator_approval(approval)
    authorization_service.preflight_model_work_registration(
        bundle,
        admission=admission,
        required_validity_seconds=required_admission_validity_seconds,
    )


def _authorize_role_trial_jit(
    prepared: PreparedAuthorizedRoleTrial,
    *,
    authorization_service: ModelExecutionAuthorizationService,
    admission: AttestationV1,
    registry: ProviderRegistry,
    approval: ModelExecutionProviderApprovalV1,
    budget: ModelExecutionBudgetV1,
    lease_ttl_seconds: float,
    authorization_ttl_seconds: float,
) -> PreflightedAuthorizedRoleTrial:
    """Register and mint one capability immediately before its only provider call."""

    bundle = prepared.work_bundle
    authorization_service.register_model_work(
        bundle,
        admission=admission,
    )
    lease = authorization_service.claim_model_work(
        bundle,
        ttl_seconds=lease_ttl_seconds,
    )
    authorization = authorization_service.issue_model_work(
        bundle,
        approval_id=approval.approval_id,
        budget=budget,
        lease=lease,
        ttl_seconds=authorization_ttl_seconds,
    )
    _assert_cell_model_binding(prepared.cell, authorization.provider)
    registry.preflight_generate(authorization, prepared.request)
    return PreflightedAuthorizedRoleTrial(
        prepared=prepared,
        authorization=authorization,
    )


def _resolved_role_lifetimes(
    prepared: PreparedAuthorizedRoleTrial,
    *,
    authorization_service: ModelExecutionAuthorizationService,
    settlement_margin_seconds: float,
    lease_ttl_seconds: float | None,
    authorization_ttl_seconds: float | None,
) -> tuple[float, float]:
    request_timeout = prepared.request.timeout_seconds
    if request_timeout is None:
        raise AuthorizedRoleBridgeError("role trial request must freeze an explicit timeout")
    if (
        isinstance(settlement_margin_seconds, bool)
        or not isinstance(settlement_margin_seconds, int | float)
        or not math.isfinite(settlement_margin_seconds)
        or settlement_margin_seconds <= 0
    ):
        raise AuthorizedRoleBridgeError("role settlement margin must be finite and positive")
    required_authorization = float(request_timeout) + float(settlement_margin_seconds)
    resolved_authorization = (
        required_authorization if authorization_ttl_seconds is None else authorization_ttl_seconds
    )
    if (
        isinstance(resolved_authorization, bool)
        or not isinstance(resolved_authorization, int | float)
        or not math.isfinite(resolved_authorization)
        or resolved_authorization < required_authorization
    ):
        raise AuthorizedRoleBridgeError(
            "role authorization TTL must cover request timeout plus settlement margin"
        )
    if resolved_authorization > _ROLE_AUTHORIZATION_HARD_CAP_SECONDS:
        raise AuthorizedRoleBridgeError(
            "role authorization TTL exceeds the one-hour authorization hard cap"
        )
    required_lease = float(resolved_authorization) + _ROLE_CLAIM_TO_ISSUE_MARGIN_SECONDS
    resolved_lease = required_lease if lease_ttl_seconds is None else lease_ttl_seconds
    if (
        isinstance(resolved_lease, bool)
        or not isinstance(resolved_lease, int | float)
        or not math.isfinite(resolved_lease)
        or resolved_lease < required_lease
    ):
        raise AuthorizedRoleBridgeError(
            "role lease TTL must outlive authorization TTL by the claim-to-issue margin"
        )
    if resolved_lease > _ROLE_LEASE_HARD_CAP_SECONDS:
        raise AuthorizedRoleBridgeError(
            "role lease TTL exceeds the authorization hard cap plus claim-to-issue margin"
        )
    authorization_service.preflight_authorization_ttl(float(resolved_authorization))
    return float(resolved_lease), float(resolved_authorization)


def _assert_role_trial_budget(
    prepared: PreparedAuthorizedRoleTrial,
    budget: ModelExecutionBudgetV1,
) -> None:
    if budget.max_attempts != 1:
        raise AuthorizedRoleBridgeError("a role trial budget must authorize exactly one attempt")
    expected_budget = ModelExecutionBudgetV1(
        max_attempts=1,
        max_input_tokens=prepared.cell.budget.max_input_tokens,
        max_output_tokens=prepared.cell.budget.max_output_tokens,
        max_total_tokens=(
            prepared.cell.budget.max_input_tokens + prepared.cell.budget.max_output_tokens
        ),
        max_cost_microusd=prepared.cell.budget.max_cost_microusd,
    )
    if budget != expected_budget:
        raise AuthorizedRoleBridgeError("role trial budget must exactly match the locked role cell")


def _execute_preflighted_authorized_role_trial(
    preflight: PreflightedAuthorizedRoleTrial,
    *,
    registry: ProviderRegistry,
    raw_output_store: AuthorizedRoleRawOutputStore,
) -> AuthorizedRoleTrialExecution:
    prepared = preflight.prepared
    authorization = preflight.authorization
    bundle = prepared.work_bundle
    dispatch_state = raw_output_store.begin_provider_call(
        bundle_id=bundle.bundle_id.value,
        authorization_hash=authorization.authorization_hash().value,
    )
    started_ns = time.monotonic_ns()
    response = registry.generate(authorization, prepared.request)
    elapsed_ms = max(0, (time.monotonic_ns() - started_ns) // 1_000_000)
    try:
        persisted_state = raw_output_store.persist_provider_response(
            dispatch_state,
            response,
            elapsed_ms=elapsed_ms,
        )
    except Exception:
        raise AuthorizedRoleReconciliationRequired(
            "provider response persistence requires private reconciliation"
        ) from None
    if response.tool_calls:
        raise AuthorizedRoleBridgeError(
            "tool-free role work returned a tool call; its raw response is private evidence only"
        )
    sidecar = AuthorizedRoleTrialSidecarV2(
        run_id=prepared.context.run_id,
        cell_id=prepared.context.cell_id,
        case_id=prepared.context.case_id,
        repetition=bundle.repetition,
        role=bundle.role,
        work_item_hash=prepared.context.work_item_hash,
        model_work_bundle_hash=bundle.handoff_hash().value,
        authorization_hash=authorization.authorization_hash().value,
        provider_id=authorization.provider.provider_id,
        model_id=authorization.provider.model_id,
        model_revision=authorization.provider.model_revision,
        provider_configuration_hash=authorization.provider.configuration_hash.value,
        context_pack_hash=bundle.context_pack_hash.value,
        request_hash=bundle.request_hash.value,
        work_evidence_hash=prepared.work_evidence.content_hash(),
        usage_summary=authorized_role_trial_usage_summary(
            input_tokens=_required_private_int(persisted_state.input_tokens),
            cached_input_tokens=_required_private_int(persisted_state.cached_input_tokens),
            output_tokens=_required_private_int(persisted_state.output_tokens),
            elapsed_ms=_required_private_int(persisted_state.elapsed_ms),
        ),
    )
    return AuthorizedRoleTrialExecution(
        authorization=authorization,
        sidecar=sidecar,
        private_state=persisted_state,
    )


def prepare_locked_floor_trials(
    suite: AuthorizedRoleSuiteDefinition,
    *,
    run_id: str,
    repetition: int = 1,
) -> tuple[PreparedAuthorizedRoleTrial, ...]:
    """Prepare the fixed two-case slice for each of the five roles."""

    run_id = validate_authorized_role_run_id(run_id)
    _assert_locked_suite(suite)
    prepared = tuple(
        prepare_authorized_role_trial(
            suite,
            cell,
            case_id=case_id,
            repetition=repetition,
            run_id=run_id,
        )
        for cell in suite.matrix.cells
        for case_id in cell.case_ids
    )
    if len(prepared) != 10:
        raise AuthorizedRoleBridgeError("locked floor suite must prepare exactly ten trials")
    return tuple(
        sorted(
            prepared,
            key=lambda item: (
                item.context.cell_id,
                item.context.case_id,
                item.work_bundle.repetition,
            ),
        )
    )


def run_authorized_role_floor_suite(
    suite: AuthorizedRoleSuiteDefinition,
    *,
    run_id: str,
    authorization_service: ModelExecutionAuthorizationService,
    admissions_by_bundle_id: Mapping[str, AttestationV1],
    registry: ProviderRegistry,
    approval: ModelExecutionProviderApprovalV1,
    budgets_by_cell: dict[str, ModelExecutionBudgetV1],
    raw_output_store: AuthorizedRoleRawOutputStore,
    settlement_margin_seconds: float = _ROLE_SETTLEMENT_MARGIN_SECONDS,
    lease_ttl_seconds: float | None = None,
    authorization_ttl_seconds: float | None = None,
) -> AuthorizedRoleSuiteSidecarV2:
    """Persist all normalized responses and a private CAS manifest before exposing sidecars."""

    run_id = validate_authorized_role_run_id(run_id)
    prepared_trials = prepare_locked_floor_trials(suite, run_id=run_id)
    expected_bundle_ids = {prepared.work_bundle.bundle_id.value for prepared in prepared_trials}
    if set(admissions_by_bundle_id) != expected_bundle_ids:
        raise AuthorizedRoleBridgeError(
            "suite admissions must cover each immutable model-work bundle exactly once"
        )
    if set(budgets_by_cell) != {cell.cell_id for cell in suite.matrix.cells}:
        raise AuthorizedRoleBridgeError("suite budgets must cover each role cell exactly once")
    resolved_lifetimes = tuple(
        _resolved_role_lifetimes(
            prepared,
            authorization_service=authorization_service,
            settlement_margin_seconds=settlement_margin_seconds,
            lease_ttl_seconds=lease_ttl_seconds,
            authorization_ttl_seconds=authorization_ttl_seconds,
        )
        for prepared in prepared_trials
    )
    cumulative_lease_window = 0.0
    for prepared, (resolved_lease_ttl, _) in zip(
        prepared_trials,
        resolved_lifetimes,
        strict=True,
    ):
        # Trial i may not mint authority until every preceding serial slot has elapsed. The
        # cumulative lease window conservatively covers those calls plus this trial's JIT issue
        # margin and complete authorization lifetime.
        cumulative_lease_window += resolved_lease_ttl
        _validate_authorized_role_trial(
            prepared,
            authorization_service=authorization_service,
            admission=admissions_by_bundle_id[prepared.work_bundle.bundle_id.value],
            registry=registry,
            approval=approval,
            budget=budgets_by_cell[prepared.cell.cell_id],
            required_admission_validity_seconds=cumulative_lease_window,
        )
    # Only after all ten immutable admissions, approvals, budgets, bindings and lifetimes pass
    # a side-effect-free gate may one trial register and mint its short-lived authority.  Each
    # capability is issued just in time and consumed before the next one exists.
    execution_list: list[AuthorizedRoleTrialExecution] = []
    for prepared, (resolved_lease_ttl, resolved_authorization_ttl) in zip(
        prepared_trials,
        resolved_lifetimes,
        strict=True,
    ):
        authorized = _authorize_role_trial_jit(
            prepared,
            authorization_service=authorization_service,
            admission=admissions_by_bundle_id[prepared.work_bundle.bundle_id.value],
            registry=registry,
            approval=approval,
            budget=budgets_by_cell[prepared.cell.cell_id],
            lease_ttl_seconds=resolved_lease_ttl,
            authorization_ttl_seconds=resolved_authorization_ttl,
        )
        execution_list.append(
            _execute_preflighted_authorized_role_trial(
                authorized,
                registry=registry,
                raw_output_store=raw_output_store,
            )
        )
    executions = tuple(execution_list)
    sidecars = tuple(
        sorted(
            (item.sidecar for item in executions),
            key=lambda item: (item.cell_id, item.case_id, item.repetition),
        )
    )
    manifest = AuthorizedRolePrivateManifestV1(
        run_id=run_id,
        outputs=tuple(
            AuthorizedRolePrivateOutputEntryV1(
                cell_id=execution.sidecar.cell_id,
                case_id=execution.sidecar.case_id,
                repetition=execution.sidecar.repetition,
                private_reconciliation_handle=execution.private_state.private_handle,
                output_hash=_required_private_output_hash(execution.private_state),
                authorization_hash=execution.sidecar.authorization_hash,
                elapsed_ms=_required_private_int(execution.private_state.elapsed_ms),
                input_tokens=_required_private_int(execution.private_state.input_tokens),
                cached_input_tokens=_required_private_int(
                    execution.private_state.cached_input_tokens
                ),
                output_tokens=_required_private_int(execution.private_state.output_tokens),
            )
            for execution in sorted(
                executions,
                key=lambda item: (
                    item.sidecar.cell_id,
                    item.sidecar.case_id,
                    item.sidecar.repetition,
                ),
            )
        ),
    )
    private_manifest_handle = raw_output_store.put_manifest(manifest)
    return AuthorizedRoleSuiteSidecarV2(
        run_id=run_id,
        private_manifest_handle=private_manifest_handle,
        usage_summary=_public_usage_summary(executions),
        trials=sidecars,
    )


def _required_private_output_hash(state: AuthorizedRolePrivateReconciliationV1) -> str:
    if state.state != "response_persisted" or state.output_hash is None:
        raise AuthorizedRoleReconciliationRequired(
            "private response state is incomplete and cannot enter a manifest"
        )
    return state.output_hash


def _required_private_int(value: int | None) -> int:
    if value is None:
        raise AuthorizedRoleReconciliationRequired(
            "private response accounting is incomplete and cannot enter a manifest"
        )
    return value


def authorized_role_token_bucket(value: int) -> str:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AuthorizedRoleBridgeError("token bucket input must be a non-negative integer")
    if value == 0:
        return "zero"
    if value <= 255:
        return "1_255"
    if value <= 1023:
        return "256_1023"
    if value <= 4095:
        return "1024_4095"
    if value <= 16_383:
        return "4096_16383"
    return "16384_plus"


def authorized_role_elapsed_bucket(value: int) -> str:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AuthorizedRoleBridgeError("elapsed bucket input must be a non-negative integer")
    if value < 1_000:
        return "under_1s"
    if value < 10_000:
        return "1s_9s"
    if value < 60_000:
        return "10s_59s"
    if value < 300_000:
        return "60s_299s"
    return "300s_plus"


def authorized_role_trial_usage_summary(
    *,
    input_tokens: int,
    cached_input_tokens: int,
    output_tokens: int,
    elapsed_ms: int,
) -> AuthorizedRoleTrialUsageSummaryV1:
    """Derive the only public per-trial accounting view from exact private values."""

    input_bucket = authorized_role_token_bucket(input_tokens)
    cached_input_bucket = authorized_role_token_bucket(cached_input_tokens)
    output_bucket = authorized_role_token_bucket(output_tokens)
    elapsed_bucket = authorized_role_elapsed_bucket(elapsed_ms)
    if cached_input_tokens > input_tokens:
        raise AuthorizedRoleBridgeError("cached input tokens cannot exceed input tokens")
    return AuthorizedRoleTrialUsageSummaryV1(
        input_tokens_bucket=input_bucket,
        cached_input_tokens_bucket=cached_input_bucket,
        output_tokens_bucket=output_bucket,
        elapsed_ms_bucket=elapsed_bucket,
    )


def authorized_role_suite_usage_summary(
    outputs: tuple[AuthorizedRolePrivateOutputEntryV1, ...],
) -> AuthorizedRolePublicUsageSummaryV2:
    """Derive aggregate public accounting from ten authenticated private entries."""

    if len(outputs) != 10:
        raise AuthorizedRoleBridgeError("public usage summary requires exactly ten trials")
    return AuthorizedRolePublicUsageSummaryV2(
        aggregate_input_tokens_bucket=authorized_role_token_bucket(
            sum(item.input_tokens for item in outputs)
        ),
        aggregate_cached_input_tokens_bucket=authorized_role_token_bucket(
            sum(item.cached_input_tokens for item in outputs)
        ),
        aggregate_output_tokens_bucket=authorized_role_token_bucket(
            sum(item.output_tokens for item in outputs)
        ),
        aggregate_elapsed_ms_bucket=authorized_role_elapsed_bucket(
            sum(item.elapsed_ms for item in outputs)
        ),
    )


def _public_usage_summary(
    executions: tuple[AuthorizedRoleTrialExecution, ...],
) -> AuthorizedRolePublicUsageSummaryV2:
    if len(executions) != 10:
        raise AuthorizedRoleBridgeError("public usage summary requires exactly ten trials")
    input_tokens = sum(
        _required_private_int(item.private_state.input_tokens) for item in executions
    )
    cached_input_tokens = sum(
        _required_private_int(item.private_state.cached_input_tokens) for item in executions
    )
    output_tokens = sum(
        _required_private_int(item.private_state.output_tokens) for item in executions
    )
    elapsed_ms = sum(_required_private_int(item.private_state.elapsed_ms) for item in executions)
    return AuthorizedRolePublicUsageSummaryV2(
        aggregate_input_tokens_bucket=authorized_role_token_bucket(input_tokens),
        aggregate_cached_input_tokens_bucket=authorized_role_token_bucket(cached_input_tokens),
        aggregate_output_tokens_bucket=authorized_role_token_bucket(output_tokens),
        aggregate_elapsed_ms_bucket=authorized_role_elapsed_bucket(elapsed_ms),
    )


def _answer_free_work_item_hash(
    *,
    matrix: RoleBenchmarkMatrixV1,
    cell: RoleBenchmarkCellV1,
    case: RoleBenchmarkCaseV1,
    cell_contract_hash: str,
    work_evidence_hash: str,
) -> str:
    return _content_hash(
        {
            "schema_version": "autolean.authorized-role-work-item.v1",
            "matrix_id": matrix.matrix_id,
            "matrix_revision": matrix.matrix_revision,
            "case_id": case.case_id,
            "case_revision": case.case_revision,
            "role": case.role.value,
            "input": case.input_payload,
            "cell_contract_hash": cell_contract_hash,
            "work_evidence_hash": work_evidence_hash,
            "prompt": cell.prompt.model_dump(mode="json"),
            "required_capabilities": sorted(
                capability.value for capability in cell.required_capabilities
            ),
            "budget": cell.budget.model_dump(mode="json"),
            "code_revision_hash": cell.code_revision_hash,
            "environment_hash": cell.environment_hash,
        }
    )


def _render_answer_free_prompt(
    case: RoleBenchmarkCaseV1,
    cell: RoleBenchmarkCellV1,
) -> str:
    input_json = _canonical_text(
        {
            "schema_version": "autolean.role-work-input.v1",
            "role": case.role.value,
            "case_id": case.case_id,
            "case_revision": case.case_revision,
            "input": case.input_payload,
        }
    )
    return f"{cell.prompt.instruction.rstrip()}\n\nINPUT_JSON\n{input_json}"


def _egress_content(system_prompt: str, prompt: str) -> str:
    return _canonical_text(
        {
            "schema_version": "autolean.authorized-role-egress-content.v1",
            "system_prompt": system_prompt,
            "prompt": prompt,
        }
    )


def _egress_source_span(
    case: RoleBenchmarkCaseV1,
    cell: RoleBenchmarkCellV1,
) -> SourceSpanV1:
    egress_content = _egress_content(
        cell.prompt.system_prompt,
        _render_answer_free_prompt(case, cell),
    )
    coordinate = f"{case.role.value}:{case.case_id}"
    return SourceSpanV1(
        span_id=stable_identifier(
            "authorized-role-egress-span",
            f"{_CALIBRATION_FIXTURE_SHA256}:{coordinate}",
        ),
        locator=f"answer-free-egress:{coordinate}",
        content_hash=digest_text(HashKindV1.SOURCE_SPAN, egress_content),
        permitted_excerpt=egress_content,
    )


def _assert_locked_suite(suite: AuthorizedRoleSuiteDefinition) -> None:
    if not suite.matrix.cells:
        raise AuthorizedRoleBridgeError("authorized role suite has no cells")
    first_cell = suite.matrix.cells[0]
    expected = build_locked_calibration_floor_suite(
        first_cell.model,
        generation_policy=suite.generation_policy,
        repetitions=first_cell.budget.repetitions,
        max_cost_microusd_per_trial=first_cell.budget.max_cost_microusd,
    )
    if suite != expected:
        raise AuthorizedRoleBridgeError(
            "authorized role suite is not the exact locked fixture-derived definition"
        )


def _build_locked_work_evidence(
    *,
    target: RoleModelTargetV1,
    matrix: RoleBenchmarkMatrixV1,
    source: SourceRecordV1,
    rights: RightsRecordV1,
    generation_policy: AuthorizedRoleGenerationPolicyV1,
) -> LockedRoleWorkEvidenceV1:
    matrix_hash = matrix.content_hash()
    source_record_hash = _content_hash(source)
    rights_record_hash = _content_hash(rights)
    egress_span_set_hash = _content_hash(
        tuple(
            span.model_dump(mode="json")
            for span in sorted(source.spans, key=lambda item: item.locator)
        )
    )
    target_binding_hash = _content_hash(target)
    generation_policy_hash = generation_policy.content_hash()
    suite_definition_hash = _content_hash(
        {
            "schema_version": "autolean.locked-role-suite-definition.v1",
            "fixture_sha256": _CALIBRATION_FIXTURE_SHA256,
            "license_sha256": _LICENSE_SHA256,
            "matrix_hash": matrix_hash,
            "source_record_hash": source_record_hash,
            "rights_record_hash": rights_record_hash,
            "egress_span_set_hash": egress_span_set_hash,
            "target_binding_hash": target_binding_hash,
            "generation_policy_hash": generation_policy_hash,
        }
    )
    return LockedRoleWorkEvidenceV1(
        matrix_hash=matrix_hash,
        suite_definition_hash=suite_definition_hash,
        source_record_hash=source_record_hash,
        rights_record_hash=rights_record_hash,
        egress_span_set_hash=egress_span_set_hash,
        target_binding_hash=target_binding_hash,
        generation_policy_hash=generation_policy_hash,
    )


def _assert_prepared_trial(prepared: PreparedAuthorizedRoleTrial) -> None:
    """Rebuild trusted work before any registration, lease, authorization, or provider I/O."""

    cell = prepared.cell
    expected_suite = build_locked_calibration_floor_suite(
        cell.model,
        generation_policy=prepared.generation_policy,
        repetitions=cell.budget.repetitions,
        max_cost_microusd_per_trial=cell.budget.max_cost_microusd,
    )
    expected_cells = {
        expected_cell.cell_id: expected_cell for expected_cell in expected_suite.matrix.cells
    }
    expected_cell = expected_cells.get(cell.cell_id)
    if expected_cell is None or expected_cell != cell:
        raise AuthorizedRoleBridgeError("prepared role work is not an exact locked trial")
    bundle = prepared.work_bundle
    expected = prepare_authorized_role_trial(
        expected_suite,
        expected_cell,
        case_id=prepared.context.case_id,
        repetition=bundle.repetition,
        run_id=prepared.context.run_id,
    )
    if prepared != expected:
        raise AuthorizedRoleBridgeError("prepared role work is not an exact locked trial")


def _raw_response_artifact(response: ModelResponse) -> dict[str, object]:
    return {
        "schema_version": "autolean.authorized-role-raw-response.v1",
        "provider_id": response.provider_id,
        "model_id": response.model_id,
        "response_id": response.response_id,
        "text": response.text,
        "tool_calls": [
            {
                "call_id": item.call_id,
                "name": item.name,
                "arguments_json": item.arguments_json,
            }
            for item in response.tool_calls
        ],
        "usage": {
            "input_tokens": response.usage.input_tokens,
            "cached_input_tokens": response.usage.cached_input_tokens,
            "output_tokens": response.usage.output_tokens,
        },
    }


def _assert_cell_model_binding(
    cell: RoleBenchmarkCellV1,
    provider: ModelExecutionProviderBindingV1,
) -> None:
    target = cell.model
    if (
        target.provider_id != provider.provider_id
        or target.model_id != provider.model_id
        or target.model_revision != provider.model_revision
        or target.provider_configuration_hash != provider.configuration_hash.value
    ):
        raise AuthorizedRoleBridgeError(
            "authorized provider binding does not match the frozen role cell"
        )
