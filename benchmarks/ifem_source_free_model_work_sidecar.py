"""Minimal ModelWork sidecar for the private iFEM source-free calibration run.

The Builder stage ledger owns dispatch state.  The control plane owns leases,
authorizations, reservations, settlements, completion receipts, and private-output CAS.  This
module adds one write-once, fenced binding from a stage coordinate to the exact ModelWork
authorization used before provider I/O.  It deliberately does not create another 27-stage state
machine or persist model response text.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final, Literal, Never, Protocol, Self, cast

from autolean_builder.ifem_next_calibration_case_intents import (
    IFEMNextCalibrationCaseIntentsV1,
)
from autolean_builder.ifem_source_free_case_authoring import (
    SourceFreeAuthoringCardV1,
    SourceFreeAuthoringResponseV1,
    SourceFreeReviewerCardV1,
    SourceFreeReviewResponseV1,
    SourceFreeSupervisorCardV1,
    SourceFreeSupervisorResponseV1,
    parse_source_free_authoring_response,
    parse_source_free_review_response,
    parse_source_free_supervisor_response,
)
from autolean_builder.ifem_source_free_private_seed import (
    LocalSourceFreePrivateSeedStore,
    PrivateSourceFreeSeedItemV2,
    PrivateSourceFreeSeedManifestV2,
    SourceFreePrivateSeedError,
    verify_private_seed_manifest_against_queue,
)
from autolean_builder.ifem_source_free_stage_ledger import (
    LocalSourceFreeStageLedger,
    SourceFreeStageCompletionBindingV1,
    SourceFreeStageCoordinateV1,
    bind_verified_stage_completion,
)
from autolean_contracts import (
    AttestationV1,
    ContractModel,
    EndpointClassV1,
    HashKindV1,
    ModelExecutionAuthorizationV1,
    ModelExecutionBudgetV1,
    ModelExecutionProviderApprovalV1,
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
from autolean_control_plane import EventStore, Lease, NewEvent
from autolean_control_plane.errors import ConcurrencyError
from autolean_control_plane.events import JsonValue, StoredEvent
from autolean_control_plane.model_authorization import ModelExecutionAuthorizationService
from autolean_prover.providers import (
    Capability,
    ModelExecutionCompletionRecoveryRequired,
    ModelRequest,
    ModelResponse,
    PrivateModelOutputStore,
    ProviderRegistry,
)
from pydantic import Field, model_validator

SOURCE_FREE_MODEL_WORK_PROTOCOL: Final[
    Literal["autolean.ifem-source-free-model-work-sidecar.v1"]
] = "autolean.ifem-source-free-model-work-sidecar.v1"
_STAGE_INPUT_SCHEMA_VERSION: Final = "autolean.ifem-source-free-stage-input.v1"
_STAGE_INPUT_TOP_LEVEL_KEYS: Final = ("card", "role", "schema_version")
_STRUCTURED_RESPONSE_FORMAT: Final = "json_object"
_ATTEMPT_ENTITY_TYPE: Final = "ifem_source_free_model_work_attempt"
_ATTEMPT_EVENT_TYPE: Final = "ifem_source_free_model_work.authorization_bound.v1"
_ROLE_ORDER: Final[tuple[ModelWorkRoleV1, ...]] = (
    ModelWorkRoleV1.STATEMENT_FORMALIZER,
    ModelWorkRoleV1.FIDELITY_REVIEWER,
    ModelWorkRoleV1.CHEATING_SUPERVISOR,
)
_POLICY_REVIEWED_AT: Final = datetime(2026, 8, 1, tzinfo=UTC)
_SHA256 = r"^[0-9a-f]{64}$"
_FORBIDDEN_PUBLIC_FIELDS: Final[tuple[bytes, ...]] = (
    b'"authorization"',
    b'"bundle_id"',
    b'"case_id"',
    b'"completion_id"',
    b'"model_id"',
    b'"node_id"',
    b'"partition"',
    b'"prompt"',
    b'"provider_id"',
    b'"raw_output"',
    b'"role"',
    b'"run_id"',
)


class SourceFreeModelWorkError(ValueError):
    """The source-free ModelWork bridge violated its frozen boundary."""


class SourceFreeModelWorkReconciliationRequired(SourceFreeModelWorkError):
    """A provider request may have happened and must not be replayed."""


class SourceFreeModelWorkAdmissionResolver(Protocol):
    """Resolve an independently signed admission for one exact work bundle."""

    def admit_model_work(self, bundle: ModelWorkBundleV2) -> AttestationV1: ...


class SourceFreeModelWorkExecutionPolicyV1(ContractModel):
    """The complete bounded request and one-attempt authorization policy."""

    schema_version: Literal["autolean.ifem-source-free-model-work-policy.v1"] = (
        "autolean.ifem-source-free-model-work-policy.v1"
    )
    max_input_tokens: int = Field(default=2048, ge=1, le=32768, strict=True)
    max_output_tokens: int = Field(default=512, ge=1, le=4096, strict=True)
    request_timeout_seconds: int = Field(default=120, ge=1, le=3600, strict=True)
    authorization_ttl_seconds: int = Field(default=180, ge=61, le=3600, strict=True)
    lease_ttl_seconds: int = Field(default=210, ge=91, le=3630, strict=True)
    max_cost_microusd: int = Field(default=0, ge=0, strict=True)
    reasoning_effort: str | None = Field(
        default=None,
        pattern=r"^[a-z][a-z0-9_-]{0,63}$",
    )
    response_format: Literal["json_object"] = "json_object"
    max_attempts_per_stage: Literal[1] = 1

    @model_validator(mode="after")
    def validate_lifetimes(self) -> Self:
        if self.authorization_ttl_seconds < self.request_timeout_seconds + 30:
            raise ValueError("authorization TTL must cover request timeout plus settlement")
        if self.lease_ttl_seconds < self.authorization_ttl_seconds + 30:
            raise ValueError("lease TTL must outlive authorization TTL")
        return self

    def content_hash(self) -> str:
        return _sha256_json(self.model_dump(mode="json"))

    def budget(self) -> ModelExecutionBudgetV1:
        return ModelExecutionBudgetV1(
            max_attempts=1,
            max_input_tokens=self.max_input_tokens,
            max_output_tokens=self.max_output_tokens,
            max_total_tokens=self.max_input_tokens + self.max_output_tokens,
            max_cost_microusd=self.max_cost_microusd,
        )


class SourceFreeModelWorkAttemptBindingV1(ContractModel):
    """One private write-once authorization binding, recorded before provider I/O."""

    schema_version: Literal["autolean.ifem-source-free-model-work-attempt.v1"] = (
        "autolean.ifem-source-free-model-work-attempt.v1"
    )
    protocol: Literal["autolean.ifem-source-free-model-work-sidecar.v1"] = (
        SOURCE_FREE_MODEL_WORK_PROTOCOL
    )
    coordinate_sha256: str = Field(pattern=_SHA256)
    private_seed_manifest_content_sha256: str = Field(pattern=_SHA256)
    model_work_bundle: ModelWorkBundleV2
    authorization: ModelExecutionAuthorizationV1
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_binding(self) -> Self:
        bundle = self.model_work_bundle
        authorization = self.authorization
        if (
            authorization.bundle_id != bundle.bundle_id
            or authorization.bundle_hash != bundle.handoff_hash()
            or authorization.contract_id != bundle.work_contract_id
            or authorization.contract_hash != bundle.semantic_hash()
            or authorization.environment_hash != bundle.role_environment_hash
            or authorization.context_pack_hash != bundle.context_pack_hash
            or authorization.request_hash != bundle.request_hash
            or authorization.budget.max_attempts != 1
        ):
            raise ValueError("attempt authorization differs from its exact ModelWork bundle")
        if self.content_sha256 != _sha256_json(self.content_payload()):
            raise ValueError("attempt binding content hash drifted")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(
            dict[str, object],
            self.model_dump(mode="json", exclude={"content_sha256"}),
        )


class SourceFreeModelWorkAuthorityV1(ContractModel):
    semantic_classification_authorized: Literal[False] = False
    semantic_fidelity_claimed: Literal[False] = False
    statement_contract_created: Literal[False] = False
    formal_graph_created: Literal[False] = False
    builder_freeze_allowed: Literal[False] = False
    prover_handoff_allowed: Literal[False] = False
    promotion_allowed: Literal[False] = False
    heldout_isolation_claimed: Literal[False] = False
    cross_role_independence_claimed: Literal[False] = False


class SourceFreeModelWorkPublicReportV1(ContractModel):
    """Aggregate execution evidence; it contains no model identity or per-case result."""

    schema_version: Literal["autolean.ifem-source-free-model-work-public-report.v1"] = (
        "autolean.ifem-source-free-model-work-public-report.v1"
    )
    protocol: Literal["autolean.ifem-source-free-model-work-sidecar.v1"] = (
        SOURCE_FREE_MODEL_WORK_PROTOCOL
    )
    artifact_kind: Literal["source_free_model_work_execution_aggregate"] = (
        "source_free_model_work_execution_aggregate"
    )
    private_seed_manifest_content_sha256: str = Field(pattern=_SHA256)
    private_stage_ledger_commitment_sha256: str = Field(pattern=_SHA256)
    private_attempt_binding_commitment_sha256: str = Field(pattern=_SHA256)
    private_completion_binding_commitment_sha256: str = Field(pattern=_SHA256)
    case_count: Literal[9] = 9
    stage_count: Literal[27] = 27
    completion_receipt_count: Literal[27] = 27
    maximum_authorized_provider_attempts: Literal[27] = 27
    max_attempts_per_stage: Literal[1] = 1
    same_provider_binding_across_roles: bool = Field(strict=True)
    model_work_admission_observed: Literal[True] = True
    fenced_authorization_observed: Literal[True] = True
    private_cas_receipt_verification_observed: Literal[True] = True
    actual_provider_dispatch_count_claimed: Literal[False] = False
    raw_response_disclosed: Literal[False] = False
    per_case_result_disclosed: Literal[False] = False
    partition_result_disclosed: Literal[False] = False
    model_identity_disclosed: Literal[False] = False
    machine_advisory_disposition: Literal["abstain"] = "abstain"
    authority: SourceFreeModelWorkAuthorityV1 = Field(
        default_factory=SourceFreeModelWorkAuthorityV1
    )
    builder_freeze: Literal["forbidden"] = "forbidden"
    prover_handoff: Literal["forbidden"] = "forbidden"
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_report(self) -> Self:
        if self.authority != SourceFreeModelWorkAuthorityV1():
            raise ValueError("source-free execution public authority drifted")
        if self.content_sha256 != _sha256_json(self.content_payload()):
            raise ValueError("source-free execution public report hash drifted")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(
            dict[str, object],
            self.model_dump(mode="json", exclude={"content_sha256"}),
        )

    def assert_not_authoritative(self) -> Never:
        raise SourceFreeModelWorkError(
            "source-free ModelWork execution cannot classify, freeze, promote, or hand to Prover"
        )

    def freeze_statement(self) -> Never:
        self.assert_not_authoritative()

    def handoff_to_prover(self) -> Never:
        self.assert_not_authoritative()


class EventStoreSourceFreeModelWorkAttemptStore:
    """Persist exactly one fenced authorization binding per stage coordinate."""

    def __init__(self, events: EventStore) -> None:
        if type(events) is not EventStore:
            raise SourceFreeModelWorkError("attempt store requires the exact EventStore type")
        self._events = events

    def bind_once(
        self,
        coordinate: SourceFreeStageCoordinateV1,
        *,
        bundle: ModelWorkBundleV2,
        authorization: ModelExecutionAuthorizationV1,
        lease: Lease,
    ) -> SourceFreeModelWorkAttemptBindingV1:
        binding = _build_attempt_binding(coordinate, bundle, authorization)
        payload: dict[str, JsonValue] = {
            "bundle_id": bundle.bundle_id.value,
            "record": cast(JsonValue, binding.model_dump(mode="json")),
        }
        try:
            stored = self._events.append_fenced(
                _ATTEMPT_ENTITY_TYPE,
                coordinate.coordinate_sha256,
                task_id=bundle.bundle_id.value,
                lease=lease,
                expected_sequence=0,
                events=(NewEvent(_ATTEMPT_EVENT_TYPE, payload=payload),),
            )
        except ConcurrencyError as error:
            raise SourceFreeModelWorkReconciliationRequired(
                "this stage already has a durable provider-attempt binding"
            ) from error
        if len(stored) != 1:
            raise SourceFreeModelWorkReconciliationRequired(
                "provider-attempt binding did not commit exactly once"
            )
        return self._parse_event(stored[0], coordinate=coordinate)

    def load(
        self,
        coordinate: SourceFreeStageCoordinateV1,
    ) -> SourceFreeModelWorkAttemptBindingV1 | None:
        events = self._events.read_stream(
            _ATTEMPT_ENTITY_TYPE,
            coordinate.coordinate_sha256,
        )
        if not events:
            return None
        if len(events) != 1:
            raise SourceFreeModelWorkReconciliationRequired(
                "provider-attempt stream contains multiple immutable events"
            )
        return self._parse_event(events[0], coordinate=coordinate)

    @staticmethod
    def _parse_event(
        event: StoredEvent,
        *,
        coordinate: SourceFreeStageCoordinateV1,
    ) -> SourceFreeModelWorkAttemptBindingV1:
        if (
            event.entity_type != _ATTEMPT_ENTITY_TYPE
            or event.entity_id != coordinate.coordinate_sha256
            or event.entity_sequence != 1
            or event.event_type != _ATTEMPT_EVENT_TYPE
            or set(event.payload) != {"bundle_id", "record"}
        ):
            raise SourceFreeModelWorkReconciliationRequired(
                "provider-attempt event is structurally invalid"
            )
        try:
            binding = SourceFreeModelWorkAttemptBindingV1.model_validate(event.payload["record"])
        except (KeyError, TypeError, ValueError) as error:
            raise SourceFreeModelWorkReconciliationRequired(
                "provider-attempt event record is invalid"
            ) from error
        if (
            binding.coordinate_sha256 != coordinate.coordinate_sha256
            or event.payload["bundle_id"] != binding.model_work_bundle.bundle_id.value
        ):
            raise SourceFreeModelWorkReconciliationRequired(
                "provider-attempt event is bound to another coordinate or bundle"
            )
        return binding


type SourceFreeCardV1 = (
    SourceFreeAuthoringCardV1 | SourceFreeReviewerCardV1 | SourceFreeSupervisorCardV1
)
type SourceFreeParsedResponseV1 = (
    SourceFreeAuthoringResponseV1 | SourceFreeReviewResponseV1 | SourceFreeSupervisorResponseV1
)


@dataclass(frozen=True, slots=True)
class PreparedSourceFreeModelWorkStage:
    coordinate: SourceFreeStageCoordinateV1
    card: SourceFreeCardV1
    request: ModelRequest
    work_bundle: ModelWorkBundleV2


class SourceFreeModelWorkExecutionSidecar:
    """Prepare, execute once, and recover completion-backed source-free work."""

    def __init__(
        self,
        *,
        seed_store: LocalSourceFreePrivateSeedStore,
        intent_queue: IFEMNextCalibrationCaseIntentsV1,
        attempt_store: EventStoreSourceFreeModelWorkAttemptStore,
        authorization_service: ModelExecutionAuthorizationService,
        registry: ProviderRegistry,
        approval: ModelExecutionProviderApprovalV1,
        output_store: PrivateModelOutputStore,
        admission_resolver: SourceFreeModelWorkAdmissionResolver,
        policy: SourceFreeModelWorkExecutionPolicyV1 | None = None,
    ) -> None:
        if type(seed_store) is not LocalSourceFreePrivateSeedStore:
            raise SourceFreeModelWorkError(
                "sidecar requires the exact persisted private seed store"
            )
        if type(intent_queue) is not IFEMNextCalibrationCaseIntentsV1:
            raise SourceFreeModelWorkError("sidecar requires the exact calibration intent queue")
        if type(attempt_store) is not EventStoreSourceFreeModelWorkAttemptStore:
            raise SourceFreeModelWorkError("sidecar requires the exact attempt-store adapter")
        resolved_policy = SourceFreeModelWorkExecutionPolicyV1() if policy is None else policy
        if type(resolved_policy) is not SourceFreeModelWorkExecutionPolicyV1:
            raise SourceFreeModelWorkError("sidecar requires the exact frozen policy")
        if not isinstance(output_store, PrivateModelOutputStore):
            raise SourceFreeModelWorkError("sidecar requires a private model-output store")
        if not callable(getattr(admission_resolver, "admit_model_work", None)):
            raise SourceFreeModelWorkError("sidecar requires an independent admission resolver")
        try:
            manifest = seed_store.load()
            verify_private_seed_manifest_against_queue(manifest, intent_queue)
        except (SourceFreePrivateSeedError, TypeError, ValueError) as error:
            raise SourceFreeModelWorkError(
                "sidecar private seed is not persisted and replayable"
            ) from error
        self._manifest = PrivateSourceFreeSeedManifestV2.model_validate(
            manifest.model_dump(mode="json")
        )
        self._items = {item.case_id.value: item for item in self._manifest.items}
        self._attempt_store = attempt_store
        self._authorization_service = authorization_service
        self._registry = registry
        self._approval = ModelExecutionProviderApprovalV1.model_validate(
            approval.model_dump(mode="json")
        )
        if self._approval.binding.endpoint_class not in {
            EndpointClassV1.LOCAL,
            EndpointClassV1.APPROVED_EXTERNAL,
        }:
            raise SourceFreeModelWorkError(
                "source-free fixture forbids unapproved external endpoint classes"
            )
        self._output_store = output_store
        self._admission_resolver = admission_resolver
        self._policy = resolved_policy
        try:
            self._authorization_service.preflight_operator_approval(self._approval)
        except Exception as error:
            raise SourceFreeModelWorkError(
                "provider approval is not an exact registered snapshot"
            ) from error

    def prepare(
        self,
        coordinate: SourceFreeStageCoordinateV1,
        item: PrivateSourceFreeSeedItemV2,
    ) -> PreparedSourceFreeModelWorkStage:
        stage, seed_item = self._require_coordinate_item(coordinate, item)
        if stage.role is ModelWorkRoleV1.STATEMENT_FORMALIZER:
            card: SourceFreeCardV1 = _authoring_card(seed_item)
        elif stage.role is ModelWorkRoleV1.FIDELITY_REVIEWER:
            author = self._predecessor_response(
                stage,
                ModelWorkRoleV1.STATEMENT_FORMALIZER,
            )
            if type(author) is not SourceFreeAuthoringResponseV1:
                raise SourceFreeModelWorkReconciliationRequired(
                    "reviewer predecessor uses the wrong finite schema"
                )
            card = _reviewer_card(seed_item, author)
        else:
            author = self._predecessor_response(
                stage,
                ModelWorkRoleV1.STATEMENT_FORMALIZER,
            )
            review = self._predecessor_response(
                stage,
                ModelWorkRoleV1.FIDELITY_REVIEWER,
            )
            if (
                type(author) is not SourceFreeAuthoringResponseV1
                or type(review) is not SourceFreeReviewResponseV1
            ):
                raise SourceFreeModelWorkReconciliationRequired(
                    "supervisor predecessors use the wrong finite schemas"
                )
            card = _supervisor_card(seed_item, author, review)
        return _prepare_model_work(
            stage,
            seed_item,
            card,
            approval=self._approval,
            policy=self._policy,
        )

    def execute_once(
        self,
        coordinate: SourceFreeStageCoordinateV1,
        item: PrivateSourceFreeSeedItemV2,
    ) -> SourceFreeStageCompletionBindingV1:
        """Call the provider only after winning the unique fenced attempt event."""

        stage, seed_item = self._require_coordinate_item(coordinate, item)
        if self._attempt_store.load(stage) is not None:
            return self.recover(stage, seed_item)
        prepared = self.prepare(stage, seed_item)
        try:
            admission = self._admission_resolver.admit_model_work(prepared.work_bundle)
            if type(admission) is not AttestationV1:
                raise TypeError("admission resolver returned the wrong type")
            self._authorization_service.preflight_model_work_registration(
                prepared.work_bundle,
                admission=admission,
                required_validity_seconds=float(self._policy.lease_ttl_seconds),
            )
            self._authorization_service.register_model_work(
                prepared.work_bundle,
                admission=admission,
            )
            lease = self._authorization_service.claim_model_work(
                prepared.work_bundle,
                ttl_seconds=float(self._policy.lease_ttl_seconds),
            )
            authorization = self._authorization_service.issue_model_work(
                prepared.work_bundle,
                approval_id=self._approval.approval_id,
                budget=self._policy.budget(),
                lease=lease,
                ttl_seconds=float(self._policy.authorization_ttl_seconds),
            )
            effective_timeout = self._registry.effective_timeout_seconds(
                authorization.provider,
                prepared.request,
            )
            if effective_timeout != float(self._policy.request_timeout_seconds):
                raise SourceFreeModelWorkError(
                    "provider timeout differs from the frozen sidecar policy"
                )
            self._registry.preflight_generate(authorization, prepared.request)
            self._authorization_service.preflight_completion(authorization)
            bound = self._attempt_store.bind_once(
                stage,
                bundle=prepared.work_bundle,
                authorization=authorization,
                lease=lease,
            )
        except SourceFreeModelWorkReconciliationRequired:
            raise
        except SourceFreeModelWorkError:
            raise
        except Exception as error:
            raise SourceFreeModelWorkError(
                "source-free ModelWork admission or authorization failed"
            ) from error
        if bound.model_work_bundle != prepared.work_bundle:
            raise SourceFreeModelWorkReconciliationRequired(
                "durable attempt differs from the prepared ModelWork bundle"
            )
        self._checkpoint("authorization_bound", stage)
        try:
            completed = self._registry.generate_completed(
                authorization,
                prepared.request,
                output_store=self._output_store,
            )
        except ModelExecutionCompletionRecoveryRequired as pending:
            completed = self._registry.recover_completed(
                pending.recovery_handle,
                output_store=self._output_store,
            )
        self._checkpoint("completion_obtained", stage)
        _parse_response(stage.role, completed.response)
        return bind_verified_stage_completion(
            stage,
            work_bundle=prepared.work_bundle,
            receipt=completed.receipt,
            verifier=self._authorization_service,
        )

    def recover(
        self,
        coordinate: SourceFreeStageCoordinateV1,
        item: PrivateSourceFreeSeedItemV2 | None = None,
    ) -> SourceFreeStageCompletionBindingV1:
        """Recover one settled completion without provider probe or generation."""

        stage = self._require_coordinate(coordinate)
        seed_item = self._items[stage.case_id.value]
        if item is not None:
            _stage, seed_item = self._require_coordinate_item(stage, item)
        attempt = self._attempt_store.load(stage)
        if attempt is None:
            raise SourceFreeModelWorkReconciliationRequired(
                "stage has no durable provider-attempt binding"
            )
        prepared = self.prepare(stage, seed_item)
        if attempt.model_work_bundle != prepared.work_bundle:
            raise SourceFreeModelWorkReconciliationRequired(
                "reconstructed ModelWork differs from the durable attempt"
            )
        try:
            handle = self._authorization_service.completion_recovery_handle_for_authorization(
                attempt.authorization
            )
        except Exception as error:
            raise SourceFreeModelWorkReconciliationRequired(
                "completion settlement discovery failed"
            ) from error
        if handle is None:
            raise SourceFreeModelWorkReconciliationRequired(
                "provider-attempt binding has no durable completion settlement"
            )
        try:
            completed = self._registry.recover_completed(
                handle,
                output_store=self._output_store,
            )
        except Exception as error:
            raise SourceFreeModelWorkReconciliationRequired(
                "settled completion remains unavailable"
            ) from error
        _parse_response(stage.role, completed.response)
        return bind_verified_stage_completion(
            stage,
            work_bundle=prepared.work_bundle,
            receipt=completed.receipt,
            verifier=self._authorization_service,
        )

    def verify_binding(
        self,
        coordinate: SourceFreeStageCoordinateV1,
        binding: SourceFreeStageCompletionBindingV1,
    ) -> None:
        if self.recover(coordinate) != binding:
            raise SourceFreeModelWorkError(
                "stage binding differs from its exact recovered ModelWork completion"
            )

    def public_report(
        self,
        ledger: LocalSourceFreeStageLedger,
    ) -> SourceFreeModelWorkPublicReportV1:
        """Project only after every ledger coordinate and private completion verifies."""

        if type(ledger) is not LocalSourceFreeStageLedger:
            raise SourceFreeModelWorkError(
                "public report requires the exact persisted stage ledger"
            )
        projection = ledger.public_projection()
        if (
            ledger.run.coordinates != self._expected_coordinates()
            or not projection.complete
            or projection.completion_committed_count != 27
            or projection.reconciliation_required_count != 0
            or projection.private_seed_manifest_content_sha256
            != self._manifest.manifest_content_sha256
        ):
            raise SourceFreeModelWorkError("stage ledger is not an exact complete run")
        attempts: list[SourceFreeModelWorkAttemptBindingV1] = []
        completions: list[SourceFreeStageCompletionBindingV1] = []
        providers = set()
        for coordinate in self._expected_coordinates():
            attempt = self._attempt_store.load(coordinate)
            if attempt is None:
                raise SourceFreeModelWorkError("complete ledger lacks one private attempt")
            attempts.append(attempt)
            providers.add(attempt.authorization.provider)
            completions.append(self.recover(coordinate))
        payload: dict[str, object] = {
            "schema_version": "autolean.ifem-source-free-model-work-public-report.v1",
            "protocol": SOURCE_FREE_MODEL_WORK_PROTOCOL,
            "artifact_kind": "source_free_model_work_execution_aggregate",
            "private_seed_manifest_content_sha256": self._manifest.manifest_content_sha256,
            "private_stage_ledger_commitment_sha256": (projection.private_ledger_commitment_sha256),
            "private_attempt_binding_commitment_sha256": _sha256_json(
                tuple(sorted(item.content_sha256 for item in attempts))
            ),
            "private_completion_binding_commitment_sha256": _sha256_json(
                tuple(sorted(item.binding_content_sha256 for item in completions))
            ),
            "case_count": 9,
            "stage_count": 27,
            "completion_receipt_count": 27,
            "maximum_authorized_provider_attempts": 27,
            "max_attempts_per_stage": 1,
            "same_provider_binding_across_roles": len(providers) == 1,
            "model_work_admission_observed": True,
            "fenced_authorization_observed": True,
            "private_cas_receipt_verification_observed": True,
            "actual_provider_dispatch_count_claimed": False,
            "raw_response_disclosed": False,
            "per_case_result_disclosed": False,
            "partition_result_disclosed": False,
            "model_identity_disclosed": False,
            "machine_advisory_disposition": "abstain",
            "authority": SourceFreeModelWorkAuthorityV1().model_dump(mode="json"),
            "builder_freeze": "forbidden",
            "prover_handoff": "forbidden",
        }
        payload["content_sha256"] = _sha256_json(payload)
        return SourceFreeModelWorkPublicReportV1.model_validate(payload)

    def _predecessor_response(
        self,
        coordinate: SourceFreeStageCoordinateV1,
        role: ModelWorkRoleV1,
    ) -> SourceFreeParsedResponseV1:
        predecessor = next(
            item
            for item in self._expected_coordinates()
            if item.case_id == coordinate.case_id and item.role is role
        )
        attempt = self._attempt_store.load(predecessor)
        if attempt is None:
            raise SourceFreeModelWorkReconciliationRequired(
                "downstream stage has no durable predecessor attempt"
            )
        try:
            handle = self._authorization_service.completion_recovery_handle_for_authorization(
                attempt.authorization
            )
            if handle is None:
                raise SourceFreeModelWorkReconciliationRequired(
                    "downstream stage predecessor has no durable settlement"
                )
            completed = self._registry.recover_completed(
                handle,
                output_store=self._output_store,
            )
        except SourceFreeModelWorkReconciliationRequired:
            raise
        except Exception as error:
            raise SourceFreeModelWorkReconciliationRequired(
                "downstream predecessor completion is unavailable"
            ) from error
        return _parse_response(role, completed.response)

    def _require_coordinate(
        self,
        coordinate: SourceFreeStageCoordinateV1,
    ) -> SourceFreeStageCoordinateV1:
        if type(coordinate) is not SourceFreeStageCoordinateV1:
            raise SourceFreeModelWorkError("sidecar coordinate requires its exact type")
        stage = SourceFreeStageCoordinateV1.model_validate(coordinate.model_dump(mode="json"))
        expected = {value.coordinate_sha256: value for value in self._expected_coordinates()}.get(
            stage.coordinate_sha256
        )
        if expected != stage:
            raise SourceFreeModelWorkError("sidecar coordinate is not an exact run member")
        return stage

    def _require_coordinate_item(
        self,
        coordinate: SourceFreeStageCoordinateV1,
        item: PrivateSourceFreeSeedItemV2,
    ) -> tuple[SourceFreeStageCoordinateV1, PrivateSourceFreeSeedItemV2]:
        stage = self._require_coordinate(coordinate)
        if type(item) is not PrivateSourceFreeSeedItemV2:
            raise SourceFreeModelWorkError("sidecar seed item requires its exact type")
        seed_item = PrivateSourceFreeSeedItemV2.model_validate(item.model_dump(mode="json"))
        if self._items.get(stage.case_id.value) != seed_item:
            raise SourceFreeModelWorkError("sidecar seed item differs from its coordinate")
        return stage, seed_item

    def _expected_coordinates(self) -> tuple[SourceFreeStageCoordinateV1, ...]:
        values: list[SourceFreeStageCoordinateV1] = []
        ordinal = 0
        for item in self._manifest.items:
            for role in _ROLE_ORDER:
                ordinal += 1
                payload: dict[str, object] = {
                    "schema_version": "autolean.ifem-source-free-stage-coordinate.v1",
                    "run_id": self._manifest.run_id.model_dump(mode="json"),
                    "private_seed_manifest_content_sha256": (
                        self._manifest.manifest_content_sha256
                    ),
                    "case_id": item.case_id.model_dump(mode="json"),
                    "role": role.value,
                    "ordinal": ordinal,
                }
                payload["coordinate_sha256"] = _sha256_json(payload)
                values.append(SourceFreeStageCoordinateV1.model_validate(payload))
        return tuple(values)

    def _checkpoint(self, _name: str, _coordinate: SourceFreeStageCoordinateV1) -> None:
        """Test seam for simulating a process crash; production does nothing."""


def _prepare_model_work(
    coordinate: SourceFreeStageCoordinateV1,
    item: PrivateSourceFreeSeedItemV2,
    card: SourceFreeCardV1,
    *,
    approval: ModelExecutionProviderApprovalV1,
    policy: SourceFreeModelWorkExecutionPolicyV1,
) -> PreparedSourceFreeModelWorkStage:
    system_prompt = _system_prompt(coordinate.role)
    prompt = canonical_json_bytes(_stage_input_payload(coordinate.role, card)).decode("ascii")
    context_hash = digest_model(
        HashKindV1.PROMPT,
        {
            "schema_version": "autolean.ifem-source-free-stage-context.v1",
            "system_prompt": system_prompt,
            "prompt": prompt,
        },
    )
    capabilities = {
        Capability.TEXT_GENERATION,
        Capability.USAGE_ACCOUNTING,
        Capability.STRUCTURED_JSON,
    }
    if policy.reasoning_effort is not None:
        capabilities.add(Capability.REASONING_EFFORT)
    request = ModelRequest(
        prompt=prompt,
        system_prompt=system_prompt,
        max_input_tokens=policy.max_input_tokens,
        max_output_tokens=policy.max_output_tokens,
        timeout_seconds=float(policy.request_timeout_seconds),
        reasoning_effort=policy.reasoning_effort,
        response_format=_STRUCTURED_RESPONSE_FORMAT,
        required_capabilities=frozenset(capabilities),
        context_pack_hash=context_hash,
    )
    egress = canonical_json_bytes(
        {
            "schema_version": "autolean.ifem-source-free-egress.v1",
            "system_prompt": system_prompt,
            "prompt": prompt,
        }
    ).decode("ascii")
    egress_bytes = egress.encode("utf-8")
    egress_hash = digest_text(HashKindV1.SOURCE_SPAN, egress)
    source_identity = (
        f"{SOURCE_FREE_MODEL_WORK_PROTOCOL}:{coordinate.coordinate_sha256}:{egress_hash.value}"
    )
    source = SourceRecordV1(
        source_id=stable_identifier("ifem-source-free-model-work-source", source_identity),
        work_id="autolean-ifem-source-free-model-work-v1",
        title="AutoLean project-synthetic source-free role card",
        version="1",
        locator=f"project-synthetic://{coordinate.coordinate_sha256}",
        content_hash=digest_bytes(HashKindV1.SOURCE_BYTES, egress_bytes),
        retrieved_at=_POLICY_REVIEWED_AT,
        spans=(
            SourceSpanV1(
                span_id=stable_identifier(
                    "ifem-source-free-model-work-span",
                    source_identity,
                ),
                locator=f"project-synthetic-egress:{coordinate.coordinate_sha256}",
                content_hash=egress_hash,
                start_offset=0,
                end_offset=len(egress_bytes),
                permitted_excerpt=egress,
            ),
        ),
        metadata={
            "source_free": True,
            "project_synthetic": True,
            "textbook_derived": False,
        },
    )
    rights = RightsRecordV1(
        rights_id=stable_identifier(
            "ifem-source-free-model-work-rights",
            source_identity,
        ),
        source_id=source.source_id,
        source_license="Apache-2.0",
        overall_decision=PermissionDecisionV1.ALLOW,
        redistribution=PermissionDecisionV1.ALLOW,
        model_egress=PermissionDecisionV1.ALLOW,
        training=PermissionDecisionV1.DENY,
        embedding=PermissionDecisionV1.DENY,
        allowed_endpoint_classes=(approval.binding.endpoint_class,),
        attribution="AutoLean project-synthetic source-free calibration fixture",
        restrictions=(
            "project_synthetic_and_finite_predecessor_projection_only",
            "unapproved_external_endpoint_forbidden",
        ),
        reviewed_by="autolean-project-synthetic-rights-policy-v1",
        reviewed_at=_POLICY_REVIEWED_AT,
    )
    cell_contract_hash = _sha256_json(
        {
            "schema_version": "autolean.ifem-source-free-cell-contract.v1",
            "role": coordinate.role.value,
            "policy": policy.model_dump(mode="json"),
            "output_contract": _output_contract(coordinate.role),
        }
    )
    case_contract_hash = _sha256_json(
        {
            "schema_version": "autolean.ifem-source-free-case-contract.v1",
            "coordinate_sha256": coordinate.coordinate_sha256,
            "seed_item_content_sha256": item.item_content_sha256,
            "card_hash": _sha256_json(card.model_dump(mode="json")),
        }
    )
    work_item_hash = _sha256_json(
        {
            "schema_version": "autolean.ifem-source-free-work-item.v1",
            "coordinate_sha256": coordinate.coordinate_sha256,
            "context_hash": context_hash.model_dump(mode="json"),
            "request_hash": request.outbound_request_hash().model_dump(mode="json"),
        }
    )
    run_hash = model_work_run_hash(coordinate.run_id.value)
    cell_hash = model_work_cell_hash(f"ifem-source-free-model-work-v1:{coordinate.role.value}")
    case_hash = model_work_case_hash(coordinate.case_id.value)
    typed_cell_contract_hash = model_work_cell_contract_hash(cell_contract_hash)
    typed_case_contract_hash = model_work_case_contract_hash(case_contract_hash)
    role_environment_hash = digest_model(
        HashKindV1.ENVIRONMENT,
        {
            "schema_version": "autolean.ifem-source-free-role-environment.v1",
            "protocol": SOURCE_FREE_MODEL_WORK_PROTOCOL,
            "role": coordinate.role.value,
            "provider_binding": approval.binding.model_dump(mode="json"),
            "policy_hash": policy.content_hash(),
        },
    )
    bundle = ModelWorkBundleV2(
        bundle_id=model_work_bundle_id(
            run_hash=run_hash,
            cell_hash=cell_hash,
            case_hash=case_hash,
            repetition=1,
            role=coordinate.role,
        ),
        work_contract_id=model_work_contract_id(
            cell_contract_hash=typed_cell_contract_hash,
            case_contract_hash=typed_case_contract_hash,
        ),
        run_hash=run_hash,
        cell_hash=cell_hash,
        case_hash=case_hash,
        repetition=1,
        role=coordinate.role,
        cell_contract_hash=typed_cell_contract_hash,
        case_contract_hash=typed_case_contract_hash,
        work_item_hash=model_work_item_hash(work_item_hash),
        role_environment_hash=role_environment_hash,
        egress_content_hash=egress_hash,
        context_pack_hash=context_hash,
        request_hash=request.outbound_request_hash(),
        source=model_work_source_binding(source),
        rights=model_work_rights_binding(rights),
    )
    return PreparedSourceFreeModelWorkStage(
        coordinate=coordinate,
        card=card,
        request=request,
        work_bundle=bundle,
    )


def _system_prompt(role: ModelWorkRoleV1) -> str:
    labels = {
        ModelWorkRoleV1.STATEMENT_FORMALIZER: "statement formalizer",
        ModelWorkRoleV1.FIDELITY_REVIEWER: "fidelity reviewer",
        ModelWorkRoleV1.CHEATING_SUPERVISOR: "cheating supervisor",
    }
    label = labels.get(role)
    if label is None:
        raise SourceFreeModelWorkError("unsupported source-free ModelWork role")
    return (
        f"You are the AutoLean source-free {label}. "
        "Return exactly one JSON object and no markdown or extra keys. "
        f"{_output_contract(role)}"
    )


def _output_contract(role: ModelWorkRoleV1) -> str:
    if role is ModelWorkRoleV1.STATEMENT_FORMALIZER:
        return (
            "Set schema_version exactly to "
            '"autolean.ifem-source-free-authoring-response.v1". '
            "Do not copy the input schema_version. "
            "Use exactly the keys schema_version, disposition, selected_slot, candidate. "
            "Use disposition propose with selected_slot 0, 1, or 2 and a complete candidate "
            "containing integer alpha, beta, gamma each from 0 to 9 and boolean guard_enabled; "
            "or use "
            "disposition abstain with selected_slot and candidate both null."
        )
    if role is ModelWorkRoleV1.FIDELITY_REVIEWER:
        return (
            'Set schema_version exactly to "autolean.ifem-source-free-review-response.v1". '
            "Use exactly the keys schema_version, disposition, observed_change_count. "
            "Use disposition abstain with observed_change_count 0 when the author abstained; "
            "otherwise use disposition accept or reject. Use an integer observed_change_count "
            "from 0 to 3."
        )
    if role is ModelWorkRoleV1.CHEATING_SUPERVISOR:
        return (
            'Set schema_version exactly to "autolean.ifem-source-free-supervisor-response.v1". '
            "Use exactly the keys schema_version, disposition, violation_detected. "
            "Use disposition abstain with violation_detected false when an upstream role "
            "abstained; otherwise use disposition allow with violation_detected false, or "
            "disposition reject with violation_detected true."
        )
    raise SourceFreeModelWorkError("unsupported source-free ModelWork role")


def source_free_model_work_prompt_contract_sha256(role: ModelWorkRoleV1) -> str:
    """Bind the exact role prompt and wire envelope used before provider dispatch."""

    if type(role) is not ModelWorkRoleV1:
        raise SourceFreeModelWorkError("prompt contract role requires its exact enum type")
    return _sha256_json(
        {
            "schema_version": "autolean.ifem-source-free-model-work-prompt-contract.v2",
            "role": role.value,
            "input_envelope_contract": _stage_input_envelope_contract(role),
            "system_prompt": _system_prompt(role),
            "response_format": _STRUCTURED_RESPONSE_FORMAT,
        }
    )


def _stage_input_envelope_contract(role: ModelWorkRoleV1) -> dict[str, object]:
    if role is ModelWorkRoleV1.STATEMENT_FORMALIZER:
        card_schema = SourceFreeAuthoringCardV1.model_json_schema(mode="validation")
    elif role is ModelWorkRoleV1.FIDELITY_REVIEWER:
        card_schema = SourceFreeReviewerCardV1.model_json_schema(mode="validation")
    elif role is ModelWorkRoleV1.CHEATING_SUPERVISOR:
        card_schema = SourceFreeSupervisorCardV1.model_json_schema(mode="validation")
    else:
        raise SourceFreeModelWorkError("unsupported source-free ModelWork role")
    return {
        "schema_version": "autolean.ifem-source-free-stage-input-contract.v1",
        "top_level_keys": list(_STAGE_INPUT_TOP_LEVEL_KEYS),
        "schema_version_literal": _STAGE_INPUT_SCHEMA_VERSION,
        "role_literal": role.value,
        "card_json_schema_sha256": _sha256_json(card_schema),
    }


def _stage_input_payload(
    role: ModelWorkRoleV1,
    card: SourceFreeCardV1,
) -> dict[str, object]:
    if role is ModelWorkRoleV1.STATEMENT_FORMALIZER and type(card) is not SourceFreeAuthoringCardV1:
        raise SourceFreeModelWorkError("formalizer input requires its exact card type")
    if role is ModelWorkRoleV1.FIDELITY_REVIEWER and type(card) is not SourceFreeReviewerCardV1:
        raise SourceFreeModelWorkError("reviewer input requires its exact card type")
    if role is ModelWorkRoleV1.CHEATING_SUPERVISOR and type(card) is not SourceFreeSupervisorCardV1:
        raise SourceFreeModelWorkError("supervisor input requires its exact card type")
    if role not in _ROLE_ORDER:
        raise SourceFreeModelWorkError("unsupported source-free ModelWork role")
    payload: dict[str, object] = {
        "schema_version": _STAGE_INPUT_SCHEMA_VERSION,
        "role": role.value,
        "card": card.model_dump(mode="json"),
    }
    if tuple(sorted(payload)) != _STAGE_INPUT_TOP_LEVEL_KEYS:
        raise SourceFreeModelWorkError("source-free stage input envelope drifted")
    return payload


def _parse_response(
    role: ModelWorkRoleV1,
    response: ModelResponse,
) -> SourceFreeParsedResponseV1:
    if type(response) is not ModelResponse or response.tool_calls:
        raise SourceFreeModelWorkError("source-free response must be exact and tool-free")
    try:
        if role is ModelWorkRoleV1.STATEMENT_FORMALIZER:
            return parse_source_free_authoring_response(response.text)
        if role is ModelWorkRoleV1.FIDELITY_REVIEWER:
            return parse_source_free_review_response(response.text)
        if role is ModelWorkRoleV1.CHEATING_SUPERVISOR:
            return parse_source_free_supervisor_response(response.text)
    except ValueError as error:
        raise SourceFreeModelWorkError(
            "source-free response violates its strict finite JSON schema"
        ) from error
    raise SourceFreeModelWorkError("unsupported source-free ModelWork role")


def _authoring_card(item: PrivateSourceFreeSeedItemV2) -> SourceFreeAuthoringCardV1:
    """Project V2 directly without weakening the V1 seed exact-type boundary."""

    return SourceFreeAuthoringCardV1(
        case_id=item.case_id,
        baseline=item.baseline,
        selector=item.selector,
        increment=item.increment,
    )


def _reviewer_card(
    item: PrivateSourceFreeSeedItemV2,
    author: SourceFreeAuthoringResponseV1,
) -> SourceFreeReviewerCardV1:
    return SourceFreeReviewerCardV1(
        case_id=item.case_id,
        baseline=item.baseline,
        selector=item.selector,
        increment=item.increment,
        author_disposition=author.disposition,
        author_selected_slot=author.selected_slot,
        author_candidate=author.candidate,
    )


def _supervisor_card(
    item: PrivateSourceFreeSeedItemV2,
    author: SourceFreeAuthoringResponseV1,
    review: SourceFreeReviewResponseV1,
) -> SourceFreeSupervisorCardV1:
    candidate = author.candidate
    observed_change_count = 0
    if candidate is not None:
        observed_change_count = sum(
            left != right
            for left, right in zip(
                (item.baseline.alpha, item.baseline.beta, item.baseline.gamma),
                (candidate.alpha, candidate.beta, candidate.gamma),
                strict=True,
            )
        )
    return SourceFreeSupervisorCardV1(
        case_id=item.case_id,
        author_disposition=author.disposition,
        reviewer_disposition=review.disposition,
        observed_change_count=observed_change_count,
    )


def _build_attempt_binding(
    coordinate: SourceFreeStageCoordinateV1,
    bundle: ModelWorkBundleV2,
    authorization: ModelExecutionAuthorizationV1,
) -> SourceFreeModelWorkAttemptBindingV1:
    payload: dict[str, object] = {
        "schema_version": "autolean.ifem-source-free-model-work-attempt.v1",
        "protocol": SOURCE_FREE_MODEL_WORK_PROTOCOL,
        "coordinate_sha256": coordinate.coordinate_sha256,
        "private_seed_manifest_content_sha256": (coordinate.private_seed_manifest_content_sha256),
        "model_work_bundle": bundle.model_dump(mode="json"),
        "authorization": authorization.model_dump(mode="json"),
    }
    payload["content_sha256"] = _sha256_json(payload)
    return SourceFreeModelWorkAttemptBindingV1.model_validate(payload)


def render_source_free_model_work_public_report(
    report: SourceFreeModelWorkPublicReportV1,
) -> bytes:
    if type(report) is not SourceFreeModelWorkPublicReportV1:
        raise SourceFreeModelWorkError("public report requires its exact type")
    value = SourceFreeModelWorkPublicReportV1.model_validate(report.model_dump(mode="json"))
    rendered = canonical_json_bytes(value.model_dump(mode="json")) + b"\n"
    if any(field in rendered for field in _FORBIDDEN_PUBLIC_FIELDS):
        raise SourceFreeModelWorkError("public source-free execution report leaked private state")
    return rendered


def _sha256_json(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


__all__ = [
    "SOURCE_FREE_MODEL_WORK_PROTOCOL",
    "EventStoreSourceFreeModelWorkAttemptStore",
    "PreparedSourceFreeModelWorkStage",
    "SourceFreeModelWorkAdmissionResolver",
    "SourceFreeModelWorkAttemptBindingV1",
    "SourceFreeModelWorkAuthorityV1",
    "SourceFreeModelWorkError",
    "SourceFreeModelWorkExecutionPolicyV1",
    "SourceFreeModelWorkExecutionSidecar",
    "SourceFreeModelWorkPublicReportV1",
    "SourceFreeModelWorkReconciliationRequired",
    "render_source_free_model_work_public_report",
    "source_free_model_work_prompt_contract_sha256",
]
