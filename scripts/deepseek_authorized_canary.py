"""Run one authorization-complete DeepSeek V4 Pro bootstrap canary.

This is deliberately a non-promotable protocol canary. It uses a synthetic CC0 frozen bundle,
an operator-declared bootstrap approval, a fenced control-plane lease, exact context/request
hashes, a one-attempt budget, ``ProviderRegistry.generate``, and durable usage settlement.
The process-local HMAC authorities are ephemeral test fixtures and establish no release authority.
The static capability list is not an independent endpoint feature probe and cannot admit a model
to a role-floor benchmark.

The command emits one redacted JSON object. It never emits the prompt, response text, endpoint,
credential value, SQLite path, or attestation material.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import httpx
from autolean_contracts import (
    AlignmentTargetV1,
    AttestationPurposeV1,
    EndpointClassV1,
    ExecutionGraphV1,
    FidelityRiskV1,
    FormalGraphV1,
    FormalizationTaskBundleV1,
    FormalSpecificationV1,
    FreezeRecordV1,
    GraphBundleV1,
    HashKindV1,
    HmacAttestationKeyV1,
    HmacAttestationSignerV1,
    HmacAttestationVerifierV1,
    LeanEnvironmentV1,
    MathematicalGraphV1,
    MathematicalSpecificationV1,
    ModelExecutionAuthorizationError,
    ModelExecutionAuthorizationV1,
    ModelExecutionBudgetV1,
    ModelExecutionPricingV1,
    ModelExecutionProviderApprovalV1,
    ModelExecutionProviderBindingV1,
    OciVerifierExecutionPolicyV2,
    PermissionDecisionV1,
    ReleaseTierV1,
    RightsRecordV1,
    SourceRecordV1,
    SourceSpanV1,
    StableIdentifierV1,
    StatementContractV1,
    StatementStatusV1,
    TaskKindV1,
    TaskPolicyV1,
    build_proof_boundary,
    builder_attestation_payload,
    digest_model,
    digest_text,
    stable_identifier,
)
from autolean_control_plane import (
    ArtifactStore,
    ControlPlane,
    EventStore,
    Lease,
    LeaseStore,
    ModelExecutionAuthorizationService,
)
from autolean_prover.context import ContextPack, ContextPackBuilder, SpecialistRole
from autolean_prover.errors import (
    CapabilityError,
    ConfigurationError,
    PolicyViolation,
    ProviderResponseError,
)
from autolean_prover.providers import (
    Capability,
    ChatCompletionsOperatorProfileV1,
    ModelRequest,
    ProviderRegistry,
    StaticCapabilityProbe,
)
from autolean_prover.providers.responses import HttpxResponsesTransport, ResponsesTransport

_SCHEMA_VERSION = "autolean.deepseek-authorized-canary.v1"
_AUTHORITY_STATUS = "non-promotable-ephemeral-test-authority"
_CAPABILITY_EVIDENCE_CLASS = "static_declared_only"
_INDEPENDENT_CAPABILITY_PROBE_STATUS = "not_independently_probed"
_PROVIDER_APPROVAL_CLASS = "operator_declared_bootstrap_only"
_ROLE_FLOOR_ADMISSION = "forbidden"
_OPERATOR_APPROVED_BY = "operator-declared-bootstrap-canary"
_PROFILE_PATH = (
    Path(__file__).resolve().parents[1]
    / "Prover"
    / "operator-profiles"
    / "deepseek-v4-pro.chat-completions.v1.json"
)
_REGISTRY_NAME = "deepseek-v4-pro"
_MODEL_REVISION = "deepseek-v4-pro-api-alias-unpinned"
_SUPPORTED_EFFORTS = frozenset({"high", "max"})
_SYSTEM_PROMPT = "Submit only the proof body for the frozen Lean theorem."
_PRICE_UPPER_BOUND_MICROUSD_PER_TOKEN = 10
_HTTP_STATUS_FAILURE_CLASSES = {
    400: "http_400",
    401: "http_401",
    402: "http_402",
    422: "http_422",
    429: "http_429",
}


def _id(key: str) -> StableIdentifierV1:
    return stable_identifier("deepseek-authorized-canary", key)


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class PreparedCanary:
    """In-process state for one canary; it is never serialized as an artifact."""

    control_plane: ControlPlane
    authorization_service: ModelExecutionAuthorizationService
    registry: ProviderRegistry
    bundle: FormalizationTaskBundleV1
    context_pack: ContextPack
    request: ModelRequest
    approval: ModelExecutionProviderApprovalV1


class SafeDiagnosticTransport:
    """Retain only a stable provider-failure category across Registry sanitization."""

    def __init__(self, delegate: ResponsesTransport) -> None:
        self._delegate = delegate
        self._last_failure_class: str | None = None

    @property
    def provider_response_failure_class(self) -> str:
        return self._last_failure_class or "provider_response_unclassified"

    def post_json(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        payload: Mapping[str, object],
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        self._last_failure_class = None
        try:
            response = self._delegate.post_json(
                url=url,
                headers=headers,
                payload=payload,
                timeout_seconds=timeout_seconds,
            )
        except httpx.HTTPStatusError as error:
            self._last_failure_class = _http_failure_class(error.response.status_code)
            raise
        except httpx.TimeoutException:
            self._last_failure_class = "timeout"
            raise
        except httpx.RequestError:
            self._last_failure_class = "network"
            raise
        except (json.JSONDecodeError, UnicodeDecodeError, ProviderResponseError):
            self._last_failure_class = "invalid_json"
            raise
        except Exception:
            self._last_failure_class = "transport_unclassified"
            raise
        self._last_failure_class = "http_ok_response_invalid"
        return response


def _http_failure_class(status_code: int) -> str:
    exact = _HTTP_STATUS_FAILURE_CLASSES.get(status_code)
    if exact is not None:
        return exact
    if 500 <= status_code <= 599:
        return "http_5xx"
    if 400 <= status_code <= 499:
        return "http_4xx_other"
    if 300 <= status_code <= 399:
        return "http_3xx"
    return "http_status_other"


def _synthetic_bundle(
    *,
    signer: HmacAttestationSignerV1,
    clock: Callable[[], datetime],
    external_egress: bool,
) -> FormalizationTaskBundleV1:
    source_text = "For every natural number n, n equals n."
    span = SourceSpanV1(
        span_id=_id("source-span"),
        locator="synthetic://deepseek-authorized-canary/source#statement",
        content_hash=digest_text(HashKindV1.SOURCE_SPAN, source_text),
        permitted_excerpt=source_text,
    )
    source = SourceRecordV1(
        source_id=_id("source"),
        work_id="deepseek-authorized-canary",
        title="Synthetic DeepSeek authorization canary",
        version="1",
        locator="synthetic://deepseek-authorized-canary/source",
        content_hash=digest_text(HashKindV1.SOURCE_BYTES, source_text),
        retrieved_at=clock(),
        spans=(span,),
    )
    rights = RightsRecordV1(
        rights_id=_id("rights"),
        source_id=source.source_id,
        source_license="CC0-1.0",
        overall_decision=PermissionDecisionV1.ALLOW,
        model_egress=(PermissionDecisionV1.ALLOW if external_egress else PermissionDecisionV1.DENY),
        allowed_endpoint_classes=((EndpointClassV1.APPROVED_EXTERNAL,) if external_egress else ()),
        reviewed_by="synthetic-canary-rights-fixture",
        reviewed_at=clock(),
    )
    statement = "theorem deepseek_authorized_canary (n : Nat) : n = n"
    elaborated_type = "forall (n : Nat), Eq n n"
    formal = FormalSpecificationV1(
        declaration_name="deepseek_authorized_canary",
        namespace="AutoLean.Canary",
        lean_statement_source=statement,
        statement_source_hash=digest_text(HashKindV1.STATEMENT_SOURCE, statement),
        elaborated_type=elaborated_type,
        elaborated_type_hash=digest_text(HashKindV1.ELABORATED_TYPE, elaborated_type),
        environment=LeanEnvironmentV1(
            lean_version="synthetic-canary-no-lean-execution",
            mathlib_revision="synthetic-canary-no-mathlib-execution",
            verifier_execution_policy=OciVerifierExecutionPolicyV2(
                worker_image_digest="sha256:" + ("0" * 64)
            ),
            environment_hash=digest_text(
                HashKindV1.ENVIRONMENT,
                "deepseek-authorized-canary-synthetic-environment-v1",
            ),
        ),
        imports_allowlist=(),
    )
    draft = StatementContractV1(
        contract_id=_id("contract"),
        revision=1,
        task_kind=TaskKindV1.KNOWN_THEOREM,
        source=source,
        rights=rights,
        mathematics=MathematicalSpecificationV1(
            informal_statement=source_text,
            normalized_statement=source_text,
        ),
        formal=formal,
        alignments=(
            AlignmentTargetV1(
                source_span_id=span.span_id,
                formal_target="AutoLean.Canary.deepseek_authorized_canary",
                relation="formalizes",
                confidence=1.0,
            ),
        ),
        policy=TaskPolicyV1(
            release_tier=ReleaseTierV1.CALIBRATION,
            fidelity_risk=FidelityRiskV1.L1_SIMPLE,
        ),
    )
    frozen_payload: dict[str, Any] = draft.model_dump(mode="python", round_trip=True)
    frozen_payload.update(
        {
            "status": StatementStatusV1.FROZEN,
            "freeze": FreezeRecordV1(
                contract_hash=draft.semantic_hash(),
                source_hash=source.content_hash,
                source_preparation_id=stable_identifier(
                    "source-preparation",
                    "deepseek-authorized-canary",
                ),
                source_preparation_hash=digest_text(
                    HashKindV1.SOURCE_PREPARATION,
                    "deepseek-authorized-canary-source-preparation-v1",
                ),
                statement_source_hash=formal.statement_source_hash,
                elaborated_type_hash=formal.elaborated_type_hash,
                frozen_by="synthetic-canary-builder-fixture",
                frozen_at=clock(),
            ),
        }
    )
    frozen = StatementContractV1.model_validate(frozen_payload)
    graphs = GraphBundleV1(
        mathematical=MathematicalGraphV1(graph_id=_id("mathematical-graph"), revision=1),
        formal=FormalGraphV1(graph_id=_id("formal-graph"), revision=1),
        execution=ExecutionGraphV1(graph_id=_id("execution-graph"), revision=1),
    )
    unsigned = FormalizationTaskBundleV1(
        bundle_id=_id("bundle"),
        contract=frozen,
        graphs=graphs,
        graph_snapshot_hash=digest_model(HashKindV1.GRAPH_SNAPSHOT, graphs),
        proof_boundary=build_proof_boundary(frozen),
        issued_at=clock(),
    )
    attestation = signer.issue(
        purpose=AttestationPurposeV1.BUILDER_FREEZE,
        payload=builder_attestation_payload(unsigned),
        evidence_identity="non-promotable-synthetic-canary-builder-freeze",
        ttl_seconds=1800,
    )
    return unsigned.model_copy(update={"builder_attestation": attestation})


def prepare_canary(
    *,
    state_root: Path,
    environment: Mapping[str, str],
    transport: ResponsesTransport,
    operator_approved: bool,
    profile_path: Path = _PROFILE_PATH,
    reasoning_effort: Literal["high", "max"] = "high",
    external_egress: bool = True,
    clock: Callable[[], datetime] = _now,
) -> PreparedCanary:
    """Prepare every public authority input without contacting the provider endpoint."""

    if operator_approved is not True:
        raise PolicyViolation("DeepSeek canary requires explicit operator approval")
    if reasoning_effort not in _SUPPORTED_EFFORTS:
        raise ValueError("DeepSeek canary reasoning effort must be high or max")
    state_root.mkdir(parents=True, exist_ok=True)
    profile = ChatCompletionsOperatorProfileV1.from_json_file(profile_path)
    provider = profile.create_provider(transport=transport, environment=environment)

    builder_key = HmacAttestationKeyV1(
        key_id="deepseek-canary-ephemeral-builder-v1",
        secret=secrets.token_bytes(32),
        allowed_purposes=frozenset({AttestationPurposeV1.BUILDER_FREEZE}),
    )
    model_key = HmacAttestationKeyV1(
        key_id="deepseek-canary-ephemeral-model-v1",
        secret=secrets.token_bytes(32),
        allowed_purposes=frozenset({AttestationPurposeV1.MODEL_EXECUTION}),
    )
    verifier = HmacAttestationVerifierV1(
        {
            builder_key.key_id: builder_key,
            model_key.key_id: model_key,
        },
        clock=clock,
    )
    database = state_root / "control.db"
    control_plane = ControlPlane(
        events=EventStore(database, clock=clock),
        leases=LeaseStore(database, clock=clock),
        artifacts=ArtifactStore(state_root / "artifacts"),
        attestation_verifier=verifier,
        allow_test_only_unreviewed_bundles=True,
    )
    authorization_service = ModelExecutionAuthorizationService(
        control_plane=control_plane,
        signer=HmacAttestationSignerV1(model_key, clock=clock),
        verifier=verifier,
        clock=clock,
    )
    bundle = _synthetic_bundle(
        signer=HmacAttestationSignerV1(builder_key, clock=clock),
        clock=clock,
        external_egress=external_egress,
    )
    context_pack = ContextPackBuilder().build(
        bundle,
        role=SpecialistRole.TACTIC,
        endpoint_class=EndpointClassV1.APPROVED_EXTERNAL,
    )
    request = ModelRequest.from_context_pack(
        context_pack,
        system_prompt=_SYSTEM_PROMPT,
        max_input_tokens=profile.canary_max_input_tokens,
        max_output_tokens=profile.canary_max_output_tokens,
        reasoning_effort=reasoning_effort,
        required_capabilities=frozenset({Capability.USAGE_ACCOUNTING}),
    )
    control_plane.register_bundle(bundle, idempotency_key="register-synthetic-canary-bundle")

    approval = ModelExecutionProviderApprovalV1(
        approval_id=_id("operator-provider-approval"),
        binding=ModelExecutionProviderBindingV1(
            registry_name=_REGISTRY_NAME,
            provider_id=provider.provider_id,
            model_id=provider.model_id,
            model_revision=_MODEL_REVISION,
            endpoint_class=provider.endpoint_class,
            configuration_hash=provider.configuration_hash,
        ),
        pricing=ModelExecutionPricingV1(
            input_microusd_per_token=_PRICE_UPPER_BOUND_MICROUSD_PER_TOKEN,
            cached_input_microusd_per_token=_PRICE_UPPER_BOUND_MICROUSD_PER_TOKEN,
            output_microusd_per_token=_PRICE_UPPER_BOUND_MICROUSD_PER_TOKEN,
        ),
        approved_by=_OPERATOR_APPROVED_BY,
        approved_at=clock(),
    )
    authorization_service.register_operator_approval(
        approval,
        idempotency_key="register-deepseek-canary-operator-approval",
    )
    registry = ProviderRegistry(authorization_gate=authorization_service)
    registry.register(
        _REGISTRY_NAME,
        provider=provider,
        # Bootstrap wiring only: this replays the operator-declared list through the Registry's
        # required probe interface. It does not observe endpoint features independently.
        probe=StaticCapabilityProbe(profile.capabilities),
        endpoint_class=EndpointClassV1.APPROVED_EXTERNAL,
        model_revision=_MODEL_REVISION,
    )
    return PreparedCanary(
        control_plane=control_plane,
        authorization_service=authorization_service,
        registry=registry,
        bundle=bundle,
        context_pack=context_pack,
        request=request,
        approval=approval,
    )


def issue_canary_authorization(
    prepared: PreparedCanary,
    *,
    lease: Lease | None = None,
    budget: ModelExecutionBudgetV1 | None = None,
) -> ModelExecutionAuthorizationV1:
    """Issue the exact, one-attempt capability consumed by ``ProviderRegistry``."""

    active_lease = (
        lease
        or prepared.control_plane.claim(
            prepared.bundle.bundle_id.value,
            worker_id="deepseek-authorized-canary-worker",
            ttl_seconds=900,
            idempotency_key="claim-deepseek-authorized-canary",
        ).lease
    )
    selected_budget = budget or ModelExecutionBudgetV1(
        max_attempts=1,
        max_input_tokens=prepared.request.max_input_tokens,
        max_output_tokens=prepared.request.max_output_tokens,
        max_total_tokens=prepared.request.max_input_tokens + prepared.request.max_output_tokens,
        max_cost_microusd=(prepared.request.max_input_tokens + prepared.request.max_output_tokens)
        * _PRICE_UPPER_BOUND_MICROUSD_PER_TOKEN,
    )
    if prepared.request.context_pack_hash is None:
        raise AssertionError("canary request unexpectedly lacks its context hash")
    return prepared.authorization_service.issue(
        prepared.bundle,
        authorization_id=_id("model-execution-authorization"),
        approval_id=prepared.approval.approval_id,
        budget=selected_budget,
        lease=active_lease,
        context_pack_hash=prepared.request.context_pack_hash,
        outbound_request_hash=prepared.request.outbound_request_hash(),
        ttl_seconds=300,
        idempotency_key="issue-deepseek-authorized-canary",
    )


def execute_prepared_canary(
    prepared: PreparedCanary,
    authorization: ModelExecutionAuthorizationV1,
) -> dict[str, object]:
    """Execute via the registry and return a redacted, bootstrap-only report."""

    response = prepared.registry.generate(authorization, prepared.request)
    response_id_sha256 = (
        None
        if response.response_id is None
        else hashlib.sha256(response.response_id.encode("utf-8")).hexdigest()
    )
    return {
        "schema_version": _SCHEMA_VERSION,
        "status": "settled",
        "authority_status": _AUTHORITY_STATUS,
        "promotion_eligible": False,
        "capability_evidence_class": _CAPABILITY_EVIDENCE_CLASS,
        "independent_capability_probe_status": _INDEPENDENT_CAPABILITY_PROBE_STATUS,
        "provider_approval_class": _PROVIDER_APPROVAL_CLASS,
        "role_floor_admission": _ROLE_FLOOR_ADMISSION,
        "provider_id": response.provider_id,
        "model_id": response.model_id,
        "hashes": {
            "authorization": authorization.authorization_hash().value,
            "bundle": prepared.bundle.handoff_hash().value,
            "contract": prepared.bundle.contract.semantic_hash().value,
            "context_pack": authorization.context_pack_hash.value,
            "outbound_request": authorization.request_hash.value,
            "response_text_sha256": hashlib.sha256(response.text.encode("utf-8")).hexdigest(),
            "response_id_sha256": response_id_sha256,
        },
        "usage": {
            "input_tokens": response.usage.input_tokens,
            "cached_input_tokens": response.usage.cached_input_tokens,
            "output_tokens": response.usage.output_tokens,
        },
    }


def run_authorized_canary(
    *,
    environment: Mapping[str, str],
    transport: ResponsesTransport,
    operator_approved: bool,
    profile_path: Path = _PROFILE_PATH,
    reasoning_effort: Literal["high", "max"] = "high",
) -> dict[str, object]:
    """Run one transient canary from approval through settled provider usage."""

    with tempfile.TemporaryDirectory(prefix="autolean-deepseek-canary-") as temporary:
        prepared = prepare_canary(
            state_root=Path(temporary),
            environment=environment,
            transport=transport,
            operator_approved=operator_approved,
            profile_path=profile_path,
            reasoning_effort=reasoning_effort,
        )
        authorization = issue_canary_authorization(prepared)
        return execute_prepared_canary(prepared, authorization)


def _arguments(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--operator-approved",
        action="store_true",
        help="confirm this one synthetic approved_external request",
    )
    parser.add_argument(
        "--reasoning-effort",
        choices=sorted(_SUPPORTED_EFFORTS),
        default="high",
    )
    parser.add_argument("--profile", type=Path, default=_PROFILE_PATH)
    return parser.parse_args(argv)


def _refusal(status: str, *, failure_class: str | None = None) -> dict[str, object]:
    report: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "status": status,
        "authority_status": _AUTHORITY_STATUS,
        "promotion_eligible": False,
        "capability_evidence_class": _CAPABILITY_EVIDENCE_CLASS,
        "independent_capability_probe_status": _INDEPENDENT_CAPABILITY_PROBE_STATUS,
        "provider_approval_class": _PROVIDER_APPROVAL_CLASS,
        "role_floor_admission": _ROLE_FLOOR_ADMISSION,
    }
    if failure_class is not None:
        report["failure_class"] = failure_class
    return report


def main(argv: Sequence[str] | None = None) -> int:
    args = _arguments(argv)
    if not args.operator_approved:
        print(json.dumps(_refusal("operator_approval_required"), sort_keys=True))
        return 2
    diagnostic_transport = SafeDiagnosticTransport(HttpxResponsesTransport())
    try:
        report = run_authorized_canary(
            environment=os.environ,
            transport=diagnostic_transport,
            operator_approved=True,
            profile_path=args.profile,
            reasoning_effort=args.reasoning_effort,
        )
    except PolicyViolation:
        failure_class = "policy"
    except ConfigurationError:
        failure_class = "configuration"
    except CapabilityError:
        failure_class = "capability"
    except ModelExecutionAuthorizationError:
        failure_class = "authorization"
    except ProviderResponseError:
        failure_class = diagnostic_transport.provider_response_failure_class
    except Exception:
        failure_class = "unexpected"
    else:
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0
    # Never emit exception text: upstream HTTP errors can contain endpoint metadata.
    print(
        json.dumps(
            _refusal("execution_refused", failure_class=failure_class),
            sort_keys=True,
        )
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
