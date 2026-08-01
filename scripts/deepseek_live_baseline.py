"""Run a bounded, non-promotable DeepSeek V4 Pro operator baseline.

This wrapper deliberately keeps credentials process-local.  It reads one operator-owned secret
reference, checks the official model catalog before any generation, then delegates a single
synthetic canary and the locked five-role/two-repetition suite to their existing authorization
paths.  It never changes the provider profile, enables web tools, retries a provider request, or
publishes a response, prompt, endpoint, private-store location, receipt body, or credential.

The optional recovery exercise injects one in-memory completion-signature interruption after the
provider response is stored.  Recovery uses the existing private output artifact and must not
perform a second provider call.  It is a protocol test, not model-quality or release evidence.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import stat
import tempfile
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Self, cast

import httpx
from autolean_contracts import (
    AttestationError,
    AttestationPurposeV1,
    AttestationSignerV1,
    AttestationV1,
    ContractModel,
    HmacAttestationSignerV1,
    ModelExecutionCompletionPublicV1,
)
from autolean_prover.errors import (
    CapabilityError,
    ConfigurationError,
    PolicyViolation,
    ProviderResponseError,
)
from autolean_prover.providers import (
    ModelExecutionCompletionRecoveryRequired,
    canonical_json_request_body,
)
from autolean_prover.providers.operator_profile import ChatCompletionsOperatorProfileV1
from autolean_prover.providers.responses import HttpxResponsesTransport, ResponsesTransport
from pydantic import Field, model_validator

from benchmarks.authorized_role_bridge import AuthorizedRoleCompletionEvidenceReaderV2
from benchmarks.authorized_role_evaluation import (
    AuthorizedRoleExactJsonEvaluationReportV1,
    AuthorizedRoleExactJsonFailureTaxonomyReportV1,
    diagnose_completed_authorized_role_suite_exact_json,
    evaluate_completed_authorized_role_suite_exact_json,
)
from scripts import deepseek_authorized_canary as canary
from scripts import deepseek_role_baseline as roles

_SCHEMA_VERSION = "autolean.deepseek-live-baseline.v1"
_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_PROFILE_PATH = (
    _REPOSITORY_ROOT / "Prover" / "operator-profiles" / "deepseek-v4-pro.chat-completions.v1.json"
)
_DEFAULT_SECRET_FILE = _REPOSITORY_ROOT / "llm.txt"
_DEFAULT_TOTAL_AUTHORIZED_COST_MICROUSD = 100_000
_HARD_TOTAL_AUTHORIZED_COST_MICROUSD = 10_000_000
_STATIC_PRICE_MICROUSD_PER_TOKEN = 10
_ROLE_TRIAL_COUNT = 10
_ROLE_MAX_INPUT_TOKENS = 512
_RoleMaxOutputTokens = Literal[256, 512, 1024]
_DEFAULT_ROLE_MAX_OUTPUT_TOKENS: _RoleMaxOutputTokens = 256
_APPROVED_ROLE_MAX_OUTPUT_TOKENS: tuple[_RoleMaxOutputTokens, ...] = (256, 512, 1024)
_SECRET_MAX_BYTES = 8_192
_SECRET_ASSIGNMENT = re.compile(
    r"^(?:export\s+)?(?:AUTOLEAN_DEEPSEEK_API_KEY|DEEPSEEK_API_KEY|API_KEY)"
    r"\s*(?:=|:)\s*(?P<value>.+?)\s*$",
    flags=re.IGNORECASE,
)
_SENSITIVE_REFERENCE = re.compile(
    r"(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret|password)",
    flags=re.IGNORECASE,
)
_SAFE_RUN_ID = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
_SHA256 = r"^[0-9a-f]{64}$"


class LiveBaselineError(ValueError):
    """A redacted, non-provider diagnostic for this operator wrapper."""


class OperatorSecretUnavailable(LiveBaselineError):
    """The operator-owned secret reference cannot be used safely."""


@dataclass(frozen=True, slots=True)
class ModelCatalogProbe:
    status: str
    target_model_listed: bool

    def public_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "target_model_listed": self.target_model_listed,
            "evidence_class": "authenticated_model_catalog_identity_only",
            "capability_admission": "forbidden",
        }


@dataclass(frozen=True, slots=True)
class LiveBaselineConfig:
    state_root: Path
    private_root: Path
    run_id: str
    max_total_authorized_cost_microusd: int
    exercise_recovery: bool
    max_output_tokens: _RoleMaxOutputTokens = _DEFAULT_ROLE_MAX_OUTPUT_TOKENS
    run_canary: bool = True


class DeepSeekCatalogEvidenceV1(ContractModel):
    """Authenticated catalog identity evidence without capability authority."""

    schema_version: Literal["autolean.deepseek-catalog-evidence.v1"] = (
        "autolean.deepseek-catalog-evidence.v1"
    )
    status: Literal["target_model_listed"] = "target_model_listed"
    target_model_listed: Literal[True] = True
    evidence_class: Literal["authenticated_model_catalog_identity_only"] = (
        "authenticated_model_catalog_identity_only"
    )
    capability_admission: Literal["forbidden"] = "forbidden"


class DeepSeekLiveCanaryNotRunV1(ContractModel):
    schema_version: Literal["autolean.deepseek-live-canary-not-run.v1"] = (
        "autolean.deepseek-live-canary-not-run.v1"
    )
    status: Literal["not_run"] = "not_run"
    reason: Literal["role_calibration_only"] = "role_calibration_only"


class DeepSeekLiveCanaryHashesV1(ContractModel):
    schema_version: Literal["autolean.deepseek-live-canary-hashes.v1"] = (
        "autolean.deepseek-live-canary-hashes.v1"
    )
    authorization: str = Field(pattern=_SHA256)
    bundle: str = Field(pattern=_SHA256)
    contract: str = Field(pattern=_SHA256)
    context_pack: str = Field(pattern=_SHA256)
    outbound_request: str = Field(pattern=_SHA256)


class DeepSeekAuthorizedCanaryPublicV2(ContractModel):
    schema_version: Literal["autolean.deepseek-authorized-canary.v2"] = (
        "autolean.deepseek-authorized-canary.v2"
    )
    status: Literal["settled"] = "settled"
    authority_status: Literal["non-promotable-ephemeral-test-authority"] = (
        "non-promotable-ephemeral-test-authority"
    )
    promotion_eligible: Literal[False] = False
    capability_evidence_class: Literal["static_declared_only"] = "static_declared_only"
    independent_capability_probe_status: Literal["not_independently_probed"] = (
        "not_independently_probed"
    )
    provider_approval_class: Literal["operator_declared_bootstrap_only"] = (
        "operator_declared_bootstrap_only"
    )
    role_floor_admission: Literal["forbidden"] = "forbidden"
    provider_id: Literal["deepseek"] = "deepseek"
    model_id: Literal["deepseek-v4-pro"] = "deepseek-v4-pro"
    hashes: DeepSeekLiveCanaryHashesV1
    completion: ModelExecutionCompletionPublicV1


class DeepSeekLiveCanarySettledV1(ContractModel):
    schema_version: Literal["autolean.deepseek-live-canary-settled.v1"] = (
        "autolean.deepseek-live-canary-settled.v1"
    )
    status: Literal["settled"] = "settled"
    provider_call_count: Literal[1] = 1
    recovery: Literal["not_exercised", "settled_without_provider_recall"]
    receipt: DeepSeekAuthorizedCanaryPublicV2


class DeepSeekRoleHarnessV1(ContractModel):
    schema_version: Literal["autolean.deepseek-role-harness.v1"] = (
        "autolean.deepseek-role-harness.v1"
    )
    response_format: Literal["json_object"] = "json_object"
    output_contract: Literal["role_json_v1"] = "role_json_v1"
    tool_schema: Literal["none"] = "none"
    structured_json_capability: Literal["static_declared_and_request_accepted"] = (
        "static_declared_and_request_accepted"
    )
    structured_json_admission: Literal["forbidden"] = "forbidden"


class DeepSeekRoleFailurePartitionV1(ContractModel):
    schema_version: Literal["autolean.deepseek-role-failure-partition.v1"] = (
        "autolean.deepseek-role-failure-partition.v1"
    )
    transport_failures: Literal[0] = 0
    schema_rejections: int = Field(ge=0, le=10)
    semantic_mismatches: int = Field(ge=0, le=10)
    passed: int = Field(ge=0, le=10)

    @model_validator(mode="after")
    def validate_partition(self) -> Self:
        if self.schema_rejections + self.semantic_mismatches + self.passed != 10:
            raise ValueError("role failure partition must cover ten settled trials")
        return self


class DeepSeekRoleScoredObservationV1(ContractModel):
    """Strict scored extension around, rather than inside, the base operator contract."""

    schema_version: Literal["autolean.deepseek-role-scored-observation.v1"] = (
        "autolean.deepseek-role-scored-observation.v1"
    )
    status: Literal["settled"] = "settled"
    operator_report: roles.DeepSeekRolePublicReportV2
    provider_call_count: Literal[10] = 10
    evaluation: AuthorizedRoleExactJsonEvaluationReportV1
    failure_taxonomy: AuthorizedRoleExactJsonFailureTaxonomyReportV1
    harness: DeepSeekRoleHarnessV1
    failure_partition: DeepSeekRoleFailurePartitionV1

    @model_validator(mode="after")
    def validate_scored_observation(self) -> Self:
        report = self.operator_report
        if report.status != "settled" or report.mode != "run" or report.failure_class is not None:
            raise ValueError("scored observation requires one settled base operator report")
        evaluation = self.evaluation
        taxonomy = self.failure_taxonomy
        common = (
            report.run_id,
            report.provider_id,
            report.model_id,
            report.model_revision,
        )
        if common != (
            evaluation.run_id,
            evaluation.provider_id,
            evaluation.model_id,
            evaluation.model_revision,
        ) or common != (
            taxonomy.run_id,
            taxonomy.provider_id,
            taxonomy.model_id,
            taxonomy.model_revision,
        ):
            raise ValueError("scored reports do not match the base operator identity")
        if (
            evaluation.provider_configuration_hash != taxonomy.provider_configuration_hash
            or evaluation.evaluator_hash != taxonomy.evaluator_hash
        ):
            raise ValueError("scored evaluator bindings disagree")
        evaluation_passes = {item.role: item.passed for item in evaluation.role_metrics}
        taxonomy_passes = {item.role: item.passed for item in taxonomy.role_metrics}
        if evaluation_passes != taxonomy_passes:
            raise ValueError("evaluation and failure taxonomy role pass counts disagree")
        expected = {
            "transport_failures": 0,
            "schema_rejections": sum(item.schema_rejections for item in taxonomy.role_metrics),
            "semantic_mismatches": sum(item.semantic_mismatches for item in taxonomy.role_metrics),
            "passed": sum(item.passed for item in taxonomy.role_metrics),
        }
        if self.failure_partition.model_dump(exclude={"schema_version"}) != expected:
            raise ValueError("failure partition does not match the role taxonomy")
        return self


class DeepSeekLiveBudgetV1(ContractModel):
    schema_version: Literal["autolean.deepseek-live-budget.v1"] = "autolean.deepseek-live-budget.v1"
    maximum_authorized_cost_microusd: int = Field(ge=0, le=_HARD_TOTAL_AUTHORIZED_COST_MICROUSD)
    canary_static_cost_microusd: int = Field(ge=0)
    roles_static_cost_microusd: int = Field(ge=0)
    provider_invoice_cost: Literal["not_available"] = "not_available"
    provider_generation_request_ceiling: Literal[10, 11]


class DeepSeekLiveBaselineSettledReportV2(ContractModel):
    """Strict public contract for one fully settled live baseline observation."""

    schema_version: Literal["autolean.deepseek-live-baseline.v2"] = (
        "autolean.deepseek-live-baseline.v2"
    )
    status: Literal["settled"] = "settled"
    authority_status: Literal["non-promotable-operator-observation"] = (
        "non-promotable-operator-observation"
    )
    promotion_eligible: Literal[False] = False
    role_floor_admission: Literal["forbidden"] = "forbidden"
    provider_id: Literal["deepseek"] = "deepseek"
    model_id: Literal["deepseek-v4-pro"] = "deepseek-v4-pro"
    catalog: DeepSeekCatalogEvidenceV1
    budget: DeepSeekLiveBudgetV1
    canary: DeepSeekLiveCanaryNotRunV1 | DeepSeekLiveCanarySettledV1
    roles: DeepSeekRoleScoredObservationV1

    @model_validator(mode="after")
    def validate_settled_report(self) -> Self:
        skipped_canary = isinstance(self.canary, DeepSeekLiveCanaryNotRunV1)
        expected_canary_cost = 0 if skipped_canary else 23_040
        expected_call_ceiling = 10 if skipped_canary else 11
        per_trial = self.roles.operator_report.per_trial_budget
        if per_trial is None:
            raise ValueError("settled scored report lacks a per-trial budget")
        expected_role_cost = (
            10
            * (_ROLE_MAX_INPUT_TOKENS + per_trial.max_output_tokens)
            * _STATIC_PRICE_MICROUSD_PER_TOKEN
        )
        expected_per_trial_cost = (
            _ROLE_MAX_INPUT_TOKENS + per_trial.max_output_tokens
        ) * _STATIC_PRICE_MICROUSD_PER_TOKEN
        if (
            per_trial.max_cost_microusd != expected_per_trial_cost
            or self.budget.canary_static_cost_microusd != expected_canary_cost
            or self.budget.provider_generation_request_ceiling != expected_call_ceiling
            or self.budget.roles_static_cost_microusd != expected_role_cost
            or self.budget.maximum_authorized_cost_microusd
            < expected_canary_cost + expected_role_cost
        ):
            raise ValueError("live baseline budget does not match the settled observation")
        return self


class _CountingTransport:
    """Count calls without retaining URLs, headers, prompts, or responses."""

    def __init__(self, delegate: ResponsesTransport) -> None:
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
        return self.post_json_bytes(
            url=url,
            headers=headers,
            body=canonical_json_request_body(payload).body,
            timeout_seconds=timeout_seconds,
        )

    def post_json_bytes(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        self.calls += 1
        return self._delegate.post_json_bytes(
            url=url,
            headers=headers,
            body=body,
            timeout_seconds=timeout_seconds,
        )


class _FailOnceCompletionSigner:
    """Fault only the first local completion signature; never the provider request."""

    def __init__(self, delegate: AttestationSignerV1) -> None:
        self._delegate = delegate
        self._calls = 0

    def issue(
        self,
        *,
        purpose: AttestationPurposeV1,
        payload: Mapping[str, object],
        evidence_identity: str,
        ttl_seconds: float,
        nonce: str | None = None,
    ) -> AttestationV1:
        self._calls += 1
        if self._calls == 1:
            raise AttestationError("injected completion signer interruption")
        return self._delegate.issue(
            purpose=purpose,
            payload=payload,
            evidence_identity=evidence_identity,
            ttl_seconds=ttl_seconds,
            nonce=nonce,
        )


CatalogGet = Callable[[str, Mapping[str, str], float], httpx.Response]


def _required_secret(path: Path) -> str:
    """Parse only a narrowly defined local API-key reference without emitting it."""

    try:
        original = path.expanduser()
        info = os.lstat(original)
        reparse = getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
        if original.is_symlink() or reparse or not stat.S_ISREG(info.st_mode):
            raise OSError("secret reference is not a regular file")
        if info.st_size <= 0 or info.st_size > _SECRET_MAX_BYTES:
            raise OSError("secret reference size is invalid")
        text = original.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError):
        raise OperatorSecretUnavailable("operator secret reference is unavailable") from None

    lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    candidates: list[str] = []
    recognized_lines: list[str] = []
    for line in lines:
        match = _SECRET_ASSIGNMENT.fullmatch(line)
        if match is not None:
            candidates.append(match.group("value"))
            recognized_lines.append(line)
    if not candidates and len(lines) == 1:
        candidates = [lines[0]]
        recognized_lines = [lines[0]]
    if len(candidates) != 1:
        raise OperatorSecretUnavailable("operator secret reference is ambiguous")
    if any(
        line not in recognized_lines and _SENSITIVE_REFERENCE.search(line) is not None
        for line in lines
    ):
        raise OperatorSecretUnavailable("operator secret reference contains another secret")

    candidate = candidates[0]
    if len(candidate) >= 2 and candidate[0] == candidate[-1] and candidate[0] in {"'", '"'}:
        candidate = candidate[1:-1]
    if (
        len(candidate) < 16
        or len(candidate) > 512
        or any(character.isspace() or ord(character) < 32 for character in candidate)
    ):
        raise OperatorSecretUnavailable("operator secret reference is invalid")
    return candidate


def _default_catalog_get(
    url: str,
    headers: Mapping[str, str],
    timeout_seconds: float,
) -> httpx.Response:
    with httpx.Client(timeout=timeout_seconds, follow_redirects=False) as client:
        return client.get(url, headers=dict(headers))


def _catalog_status_for_http(status_code: int) -> str:
    if status_code == 401:
        return "catalog_http_401"
    if status_code == 402:
        return "catalog_http_402"
    if status_code == 429:
        return "catalog_http_429"
    if status_code in {404, 405, 501}:
        return "catalog_unsupported"
    if 500 <= status_code <= 599:
        return "catalog_http_5xx"
    if 400 <= status_code <= 499:
        return "catalog_http_4xx_other"
    if 300 <= status_code <= 399:
        return "catalog_http_3xx"
    return "catalog_http_other"


def probe_model_catalog(
    profile: ChatCompletionsOperatorProfileV1,
    *,
    api_key: str,
    get: CatalogGet = _default_catalog_get,
) -> ModelCatalogProbe:
    """Perform the zero-generation official `/models` identity check.

    The result proves only that the exact profile model identifier was present in an authenticated
    catalog response.  It does not establish reasoning, usage, tool, quality, or release claims.
    """

    try:
        response = get(
            f"{profile.base_url.rstrip('/')}/models",
            {"Authorization": f"Bearer {api_key}"},
            min(profile.timeout_seconds, 20.0),
        )
    except httpx.TimeoutException:
        return ModelCatalogProbe(status="catalog_timeout", target_model_listed=False)
    except httpx.RequestError:
        return ModelCatalogProbe(status="catalog_network", target_model_listed=False)
    except Exception:
        return ModelCatalogProbe(status="catalog_unclassified", target_model_listed=False)

    if response.status_code != 200:
        return ModelCatalogProbe(
            status=_catalog_status_for_http(response.status_code),
            target_model_listed=False,
        )
    try:
        body = response.json()
    except (json.JSONDecodeError, UnicodeDecodeError):
        return ModelCatalogProbe(status="catalog_invalid_json", target_model_listed=False)
    if not isinstance(body, dict) or not isinstance(body.get("data"), list):
        return ModelCatalogProbe(status="catalog_invalid_payload", target_model_listed=False)
    identifiers = [
        item.get("id")
        for item in body["data"]
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    ]
    if profile.model_id not in identifiers:
        return ModelCatalogProbe(status="target_model_not_listed", target_model_listed=False)
    return ModelCatalogProbe(status="target_model_listed", target_model_listed=True)


def _canary_static_cost(profile: ChatCompletionsOperatorProfileV1) -> int:
    return (
        profile.canary_max_input_tokens + profile.canary_max_output_tokens
    ) * _STATIC_PRICE_MICROUSD_PER_TOKEN


def _role_static_cost(max_output_tokens: _RoleMaxOutputTokens) -> int:
    return (
        _ROLE_TRIAL_COUNT
        * (_ROLE_MAX_INPUT_TOKENS + max_output_tokens)
        * _STATIC_PRICE_MICROUSD_PER_TOKEN
    )


def _validate_config(
    config: LiveBaselineConfig,
    profile: ChatCompletionsOperatorProfileV1,
) -> roles.DeepSeekRoleOperatorConfig:
    if not _SAFE_RUN_ID.fullmatch(config.run_id):
        raise LiveBaselineError("run id is invalid")
    maximum = config.max_total_authorized_cost_microusd
    if isinstance(maximum, bool) or not isinstance(maximum, int):
        raise LiveBaselineError("maximum cost is invalid")
    if config.max_output_tokens not in _APPROVED_ROLE_MAX_OUTPUT_TOKENS:
        raise LiveBaselineError("role output limit is not approved")
    required = _role_static_cost(config.max_output_tokens) + (
        _canary_static_cost(profile) if config.run_canary else 0
    )
    if maximum < required or maximum > _HARD_TOTAL_AUTHORIZED_COST_MICROUSD:
        raise LiveBaselineError("maximum cost is outside the approved bound")
    return roles.DeepSeekRoleOperatorConfig(
        mode="run",
        run_id=config.run_id,
        state_root=config.state_root,
        private_root=config.private_root,
        max_cost_microusd_per_trial=(
            (_ROLE_MAX_INPUT_TOKENS + config.max_output_tokens) * _STATIC_PRICE_MICROUSD_PER_TOKEN
        ),
        operator_approved=True,
        max_output_tokens=config.max_output_tokens,
    )


def _canary_failure_class(
    error: BaseException,
    transport: canary.SafeDiagnosticTransport,
) -> str:
    if isinstance(error, ProviderResponseError):
        return transport.provider_response_failure_class
    if isinstance(error, (CapabilityError, ConfigurationError, PolicyViolation)):
        return "canary_policy_rejected"
    if isinstance(error, ModelExecutionCompletionRecoveryRequired):
        return "canary_recovery_unresolved"
    return "canary_unclassified"


def _run_canary(
    *,
    profile: ChatCompletionsOperatorProfileV1,
    environment: Mapping[str, str],
    exercise_recovery: bool,
) -> dict[str, object]:
    counter = _CountingTransport(HttpxResponsesTransport())
    transport = canary.SafeDiagnosticTransport(counter)
    with tempfile.TemporaryDirectory(prefix="autolean-deepseek-live-canary-") as temporary:
        factory: Callable[[HmacAttestationSignerV1], AttestationSignerV1] | None = None
        if exercise_recovery:
            factory = _FailOnceCompletionSigner
        try:
            prepared = canary.prepare_canary(
                state_root=Path(temporary),
                environment=environment,
                transport=transport,
                operator_approved=True,
                profile_path=_PROFILE_PATH,
                completion_signer_factory=factory,
            )
            authorization = canary.issue_canary_authorization(prepared)
            recovery = "not_exercised"
            try:
                report = canary.execute_prepared_canary(prepared, authorization)
            except ModelExecutionCompletionRecoveryRequired as interrupted:
                if not exercise_recovery:
                    raise
                report = canary.recover_prepared_canary(prepared, interrupted.recovery_handle)
                recovery = "settled_without_provider_recall"
        except BaseException as error:
            if isinstance(error, (KeyboardInterrupt, SystemExit)):
                raise
            return {
                "status": "execution_refused",
                "failure_class": _canary_failure_class(error, transport),
                "provider_call_count": counter.calls,
            }
    if counter.calls != 1:
        return {
            "status": "execution_refused",
            "failure_class": "provider_call_count_inconsistent",
            "provider_call_count": counter.calls,
        }
    return {
        "status": "settled",
        "provider_call_count": counter.calls,
        "recovery": recovery,
        "receipt": report,
    }


def _run_roles(
    *,
    role_config: roles.DeepSeekRoleOperatorConfig,
    environment: Mapping[str, str],
) -> dict[str, object]:
    counter = _CountingTransport(HttpxResponsesTransport())
    transport = roles.RedactingDiagnosticTransport(counter)
    try:
        prepared = roles.preflight_deepseek_role_operator(
            role_config,
            environment=environment,
            transport=transport,
        )
        settled = roles.run_preflighted_deepseek_role_operator_with_private_sidecar(prepared)
        report = settled.report
    except BaseException as error:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        return {
            "status": "execution_refused",
            "failure_class": "role_operator_unclassified",
            "provider_call_count": counter.calls,
        }
    if report.status == "settled" and counter.calls != _ROLE_TRIAL_COUNT:
        return {
            "status": "execution_refused",
            "failure_class": "role_provider_call_count_inconsistent",
            "provider_call_count": counter.calls,
        }
    if report.status == "settled":
        if settled.suite_sidecar is None:
            return {
                "status": "execution_refused",
                "failure_class": "role_private_sidecar_unavailable",
                "provider_call_count": counter.calls,
            }
        try:
            evaluation = evaluate_completed_authorized_role_suite_exact_json(
                prepared.plan.suite,
                settled.suite_sidecar,
                evidence_reader=AuthorizedRoleCompletionEvidenceReaderV2(
                    manifest_store=prepared.completion_manifest_store,
                    output_store=prepared.output_store,
                    completion_verifier=prepared.authorization_service,
                ),
            )
            taxonomy = diagnose_completed_authorized_role_suite_exact_json(
                prepared.plan.suite,
                settled.suite_sidecar,
                evidence_reader=AuthorizedRoleCompletionEvidenceReaderV2(
                    manifest_store=prepared.completion_manifest_store,
                    output_store=prepared.output_store,
                    completion_verifier=prepared.authorization_service,
                ),
            )
        except BaseException as error:
            if isinstance(error, (KeyboardInterrupt, SystemExit)):
                raise
            return {
                "status": "execution_refused",
                "failure_class": "role_local_evaluation_rejected",
                "provider_call_count": counter.calls,
            }
        scored = DeepSeekRoleScoredObservationV1(
            operator_report=report,
            provider_call_count=10,
            evaluation=evaluation,
            failure_taxonomy=taxonomy,
            harness=DeepSeekRoleHarnessV1(),
            failure_partition=DeepSeekRoleFailurePartitionV1(
                schema_rejections=sum(metric.schema_rejections for metric in taxonomy.role_metrics),
                semantic_mismatches=sum(
                    metric.semantic_mismatches for metric in taxonomy.role_metrics
                ),
                passed=sum(metric.passed for metric in taxonomy.role_metrics),
            ),
        )
        return cast(dict[str, object], scored.model_dump(mode="json"))
    return cast(dict[str, object], report.model_dump(mode="json"))


def _refusal(
    *,
    stage: Literal["preflight", "catalog", "canary", "roles"],
    failure_class: str,
    profile: ChatCompletionsOperatorProfileV1 | None = None,
) -> dict[str, object]:
    report: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "status": "execution_refused",
        "stage": stage,
        "failure_class": failure_class,
        "authority_status": "non-promotable-operator-observation",
        "promotion_eligible": False,
        "role_floor_admission": "forbidden",
    }
    if profile is not None:
        report["provider_id"] = profile.provider_id
        report["model_id"] = profile.model_id
    return report


def execute_live_baseline(
    config: LiveBaselineConfig,
    *,
    secret_file: Path = _DEFAULT_SECRET_FILE,
    catalog_get: CatalogGet = _default_catalog_get,
) -> dict[str, object]:
    """Run the catalog -> canary -> five-role sequence without exposing private evidence."""

    try:
        profile = ChatCompletionsOperatorProfileV1.from_json_file(_PROFILE_PATH)
        role_config = _validate_config(config, profile)
        # This plan is pure; its fixed cells prevent a caller from silently changing role counts
        # or token limits before the catalog check and any provider I/O.
        plan = roles.build_deepseek_role_plan(role_config)
        if len(plan.trials) != _ROLE_TRIAL_COUNT:
            raise LiveBaselineError("locked role trial count changed")
        api_key = _required_secret(secret_file)
    except BaseException as error:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        return _refusal(
            stage="preflight",
            failure_class=(
                "operator_secret_unavailable"
                if isinstance(error, OperatorSecretUnavailable)
                else "local_preflight_rejected"
            ),
        )

    catalog = probe_model_catalog(profile, api_key=api_key, get=catalog_get)
    if not catalog.target_model_listed:
        report = _refusal(
            stage="catalog",
            failure_class=catalog.status,
            profile=profile,
        )
        report["catalog"] = catalog.public_dict()
        return report

    environment = {
        profile.api_key_env: api_key,
        "AUTOLEAN_ROLE_MANIFEST_HMAC_KEY": secrets.token_urlsafe(48),
    }
    if config.run_canary:
        canary_report = _run_canary(
            profile=profile,
            environment=environment,
            exercise_recovery=config.exercise_recovery,
        )
    else:
        canary_report = {
            "status": "not_run",
            "reason": "role_calibration_only",
        }
    if config.run_canary and canary_report["status"] != "settled":
        report = _refusal(
            stage="canary",
            failure_class=str(canary_report["failure_class"]),
            profile=profile,
        )
        report.update(
            {
                "catalog": catalog.public_dict(),
                "canary": canary_report,
            }
        )
        return report

    role_report = _run_roles(role_config=role_config, environment=environment)
    if role_report["status"] != "settled":
        report = _refusal(
            stage="roles",
            failure_class=str(role_report.get("failure_class", "role_execution_refused")),
            profile=profile,
        )
        report.update(
            {
                "catalog": catalog.public_dict(),
                "canary": canary_report,
                "roles": role_report,
            }
        )
        return report

    settled_report = DeepSeekLiveBaselineSettledReportV2(
        catalog=DeepSeekCatalogEvidenceV1.model_validate(catalog.public_dict()),
        budget=DeepSeekLiveBudgetV1(
            maximum_authorized_cost_microusd=config.max_total_authorized_cost_microusd,
            canary_static_cost_microusd=(_canary_static_cost(profile) if config.run_canary else 0),
            roles_static_cost_microusd=_role_static_cost(config.max_output_tokens),
            provider_generation_request_ceiling=(11 if config.run_canary else 10),
        ),
        canary=(
            DeepSeekLiveCanarySettledV1.model_validate(canary_report)
            if config.run_canary
            else DeepSeekLiveCanaryNotRunV1.model_validate(canary_report)
        ),
        roles=DeepSeekRoleScoredObservationV1.model_validate(role_report),
    )
    return cast(dict[str, object], settled_report.model_dump(mode="json"))


def _write_public_report(path: Path, report: Mapping[str, object]) -> None:
    """Allow a durable redacted report only in the repository's research evidence area."""

    if report.get("status") == "settled":
        report = DeepSeekLiveBaselineSettledReportV2.model_validate(report).model_dump(mode="json")

    public_root = (_REPOSITORY_ROOT / "docs" / "research").resolve()
    candidate = path.resolve(strict=False)
    if public_root not in candidate.parents or candidate.suffix != ".json":
        raise LiveBaselineError("public report path is not permitted")
    candidate.parent.mkdir(parents=True, exist_ok=True)
    if candidate.exists() and (candidate.is_symlink() or not candidate.is_file()):
        raise LiveBaselineError("public report target is not a regular file")
    temporary = candidate.with_name(f".{candidate.name}.{secrets.token_hex(12)}.tmp")
    try:
        temporary.write_text(
            json.dumps(dict(report), sort_keys=True, separators=(",", ":"), ensure_ascii=True),
            encoding="ascii",
        )
        os.replace(temporary, candidate)
    finally:
        with suppress(FileNotFoundError):
            temporary.unlink()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operator-approved", action="store_true")
    parser.add_argument("--secret-file", type=Path, default=_DEFAULT_SECRET_FILE)
    parser.add_argument("--state-root", required=True, type=Path)
    parser.add_argument("--private-root", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument(
        "--max-total-authorized-cost-microusd",
        type=int,
        default=_DEFAULT_TOTAL_AUTHORIZED_COST_MICROUSD,
    )
    parser.add_argument("--exercise-recovery", action="store_true")
    parser.add_argument("--skip-canary", action="store_true")
    parser.add_argument(
        "--max-output-tokens",
        choices=_APPROVED_ROLE_MAX_OUTPUT_TOKENS,
        type=int,
        default=_DEFAULT_ROLE_MAX_OUTPUT_TOKENS,
    )
    parser.add_argument("--public-report", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not args.operator_approved:
        report = _refusal(stage="preflight", failure_class="operator_approval_required")
    else:
        report = execute_live_baseline(
            LiveBaselineConfig(
                state_root=args.state_root,
                private_root=args.private_root,
                run_id=args.run_id,
                max_total_authorized_cost_microusd=args.max_total_authorized_cost_microusd,
                exercise_recovery=args.exercise_recovery,
                max_output_tokens=cast(_RoleMaxOutputTokens, args.max_output_tokens),
                run_canary=not args.skip_canary,
            ),
            secret_file=args.secret_file,
        )
    try:
        if args.public_report is not None:
            _write_public_report(args.public_report, report)
    except BaseException:
        report = _refusal(stage="preflight", failure_class="public_report_write_rejected")
    print(json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
    return 0 if report["status"] == "settled" else 2


if __name__ == "__main__":
    raise SystemExit(main())
