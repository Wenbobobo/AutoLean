"""Durable control-plane authority for model execution capabilities.

This service deliberately stores only public routing/budget facts and signed capability metadata.
It never receives a prompt, an endpoint URL, an API key, or model response text.  Its SQLite
ledger is append-only so restart recovery cannot reset a model's attempt, token, or cost budget.
"""

from __future__ import annotations

import math
import re
import sqlite3
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal

from autolean_contracts import (
    AttestationError,
    AttestationPurposeV1,
    AttestationSignerV1,
    AttestationV1,
    AttestationVerifierV1,
    DigestV1,
    FormalizationTaskBundleV1,
    HashKindV1,
    ModelWorkBundleV2,
    StableIdentifierV1,
    digest_model,
    model_work_admission_evidence_identity,
    model_work_admission_payload,
    stable_identifier,
)
from autolean_contracts.authorization import (
    ModelEgressPolicyV1,
    ModelExecutionAuthorizationError,
    ModelExecutionAuthorizationV1,
    ModelExecutionBudgetV1,
    ModelExecutionLeaseBindingV1,
    ModelExecutionProviderApprovalV1,
    ModelExecutionProviderBindingV1,
    ModelExecutionReservationV1,
    ModelExecutionSubjectKindV1,
    model_execution_authorization_payload,
)

from .errors import StaleFence
from .events import canonical_json, request_hash
from .leases import Lease
from .service import ControlPlane, TaskBinding

_REVOCATION_CODE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_MODEL_WORK_NONCE = re.compile(r"^[0-9a-f]{48}$")
_PROVIDER_FAILURE_CODES = frozenset(
    {
        "probe_failed_v1",
        "probe_invalid_v1",
        "probe_capability_mismatch_v1",
        "generation_failed_v1",
        "response_invalid_v1",
        "settlement_rejected_v1",
        "local_policy_rejected_v1",
    }
)
_PROVIDER_HEALTH_FAILURE_CODES = frozenset(
    {
        "probe_failed_v1",
        "probe_invalid_v1",
        "generation_failed_v1",
        "response_invalid_v1",
    }
)


@dataclass(frozen=True, slots=True)
class _ReservationState:
    reservation_id: str
    attempt_number: int
    reserved_input_tokens: int
    reserved_output_tokens: int
    reserved_cost_microusd: int
    state: Literal["reserved", "settled", "abandoned"]
    actual_input_tokens: int | None = None
    actual_cached_input_tokens: int | None = None
    actual_output_tokens: int | None = None
    actual_cost_microusd: int | None = None
    failure_code: str | None = None


@dataclass(frozen=True, slots=True)
class _UsageTotals:
    attempts: int
    input_tokens: int
    output_tokens: int
    total_tokens: int
    cost_microusd: int


@dataclass(frozen=True, slots=True)
class _StoredModelWorkRegistration:
    bundle: ModelWorkBundleV2
    admission: AttestationV1
    admission_hash: str


@dataclass(frozen=True, slots=True)
class _AuthorizationSubject:
    """The fields carried unchanged by the existing authorization wire schema."""

    subject_kind: ModelExecutionSubjectKindV1
    bundle_id: StableIdentifierV1
    bundle_hash: DigestV1
    contract_id: StableIdentifierV1
    revision: int
    contract_hash: DigestV1
    environment_hash: DigestV1
    egress_policy: ModelEgressPolicyV1
    parent_admission_hash: DigestV1 | None = None
    parent_admission_expires_at: datetime | None = None


class ModelExecutionAuthorizationService:
    """Issue, revoke, reserve, and settle model authority against one ControlPlane database.

    The service implements the narrow protocol consumed by ``ProviderRegistry`` without making
    the Prover depend on the control-plane package.  All state-changing operations use the
    EventStore's ``BEGIN IMMEDIATE`` transaction, so concurrent workers cannot over-reserve a
    capability's budget.
    """

    _ISSUE_SCOPE = "issue_model_execution_authorization"
    _REVOKE_SCOPE = "revoke_model_execution_authorization"
    _DEFAULT_MAX_TTL_SECONDS = 60.0 * 60.0
    _HARD_MAX_TTL_SECONDS = 60.0 * 60.0
    _DEFAULT_PROVIDER_FAILURE_THRESHOLD = 3
    _HARD_MAX_PROVIDER_FAILURE_THRESHOLD = 100
    _DEFAULT_PROVIDER_FAILURE_COOLDOWN_SECONDS = 60.0
    _HARD_MAX_PROVIDER_FAILURE_COOLDOWN_SECONDS = 24.0 * 60.0 * 60.0

    def __init__(
        self,
        *,
        control_plane: ControlPlane,
        signer: AttestationSignerV1,
        verifier: AttestationVerifierV1,
        admission_verifier: AttestationVerifierV1 | None = None,
        clock: Callable[[], datetime] | None = None,
        max_ttl_seconds: float = _DEFAULT_MAX_TTL_SECONDS,
        provider_failure_threshold: int = _DEFAULT_PROVIDER_FAILURE_THRESHOLD,
        provider_failure_cooldown_seconds: float = (_DEFAULT_PROVIDER_FAILURE_COOLDOWN_SECONDS),
    ) -> None:
        self._control_plane = control_plane
        self._events = control_plane.events
        self._signer = signer
        self._verifier = verifier
        self._admission_verifier = admission_verifier
        self._clock = clock or (lambda: datetime.now(UTC))
        self._max_ttl_seconds = self._validate_max_ttl_seconds(max_ttl_seconds)
        self._provider_failure_threshold = self._validate_provider_failure_threshold(
            provider_failure_threshold
        )
        self._provider_failure_cooldown_seconds = self._validate_provider_failure_cooldown_seconds(
            provider_failure_cooldown_seconds
        )
        self._initialize()

    def register_operator_approval(
        self,
        approval: ModelExecutionProviderApprovalV1,
        *,
        idempotency_key: str,
    ) -> ModelExecutionProviderApprovalV1:
        """Persist one enabled provider approval through the operator-only control-plane path.

        This method deliberately is not an authorization primitive: it proves only that a process
        with access to this control-plane object registered the public record.  Deployment must
        keep this path out of Builder and worker processes with an operator ACL and protect the
        signing key with KMS/HSM or an equivalent authority boundary.
        """

        if not approval.enabled:
            raise ModelExecutionAuthorizationError(
                "operator provider approval registration requires an enabled approval"
            )
        if not idempotency_key.strip():
            raise ModelExecutionAuthorizationError(
                "provider approval registration idempotency key must not be empty"
            )
        approval_hash = approval.approval_hash().value
        registration_request = {
            "schema_version": "autolean.operator-provider-approval-registration-request.v1",
            "approval_id": approval.approval_id.value,
            "approval_hash": approval_hash,
        }
        request_digest = request_hash(registration_request)
        serialized = canonical_json(approval.model_dump(mode="json"))
        now = self._now()
        with self._events.write_transaction() as connection:
            replay = self._idempotent_provider_approval(
                connection,
                key=idempotency_key,
                request_digest=request_digest,
            )
            if replay is not None:
                return replay
            existing = connection.execute(
                """
                SELECT approval_hash
                FROM model_execution_provider_approvals
                WHERE approval_id = ?
                """,
                (approval.approval_id.value,),
            ).fetchone()
            if existing is not None:
                if str(existing["approval_hash"]) != approval_hash:
                    raise ModelExecutionAuthorizationError(
                        "provider approval ID is already bound to a different immutable record"
                    )
                stored = self._stored_provider_approval(connection, approval.approval_id.value)
                self._record_provider_approval_idempotency(
                    connection,
                    key=idempotency_key,
                    request_digest=request_digest,
                    approval_id=stored.approval_id.value,
                )
                return stored
            connection.execute(
                """
                INSERT INTO model_execution_provider_approvals (
                    approval_id, approval_hash, approval_json,
                    registration_request_hash, registered_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    approval.approval_id.value,
                    approval_hash,
                    serialized,
                    request_digest,
                    self._timestamp(now),
                ),
            )
            self._record_provider_approval_idempotency(
                connection,
                key=idempotency_key,
                request_digest=request_digest,
                approval_id=approval.approval_id.value,
            )
        return approval

    def preflight_operator_approval(
        self,
        approval: ModelExecutionProviderApprovalV1,
    ) -> None:
        """Read-only exact-snapshot check for orchestration-wide dry runs."""

        if not approval.enabled:
            raise ModelExecutionAuthorizationError("selected provider approval is disabled")
        with self._events.connection() as connection:
            stored = self._stored_provider_approval(connection, approval.approval_id.value)
        if canonical_json(stored.model_dump(mode="json")) != canonical_json(
            approval.model_dump(mode="json")
        ):
            raise ModelExecutionAuthorizationError(
                "provider approval differs from its immutable registered snapshot"
            )

    def preflight_model_work_registration(
        self,
        bundle: ModelWorkBundleV2,
        *,
        admission: AttestationV1,
        required_validity_seconds: float | None = None,
    ) -> None:
        """Validate a ModelWork registration with no database or lease mutation."""

        validated = self._validated_model_work(bundle)
        self._verify_model_work_admission(validated, admission)
        if required_validity_seconds is not None:
            if (
                isinstance(required_validity_seconds, bool)
                or not isinstance(required_validity_seconds, int | float)
                or not math.isfinite(required_validity_seconds)
                or required_validity_seconds <= 0
            ):
                raise ModelExecutionAuthorizationError(
                    "required parent-admission validity must be finite and positive"
                )
            remaining = (admission.expires_at - self._now()).total_seconds()
            if remaining < required_validity_seconds:
                raise ModelExecutionAuthorizationError(
                    "model work admission does not cover the required execution window"
                )
        admission_hash = self._model_work_admission_hash(admission)
        with self._events.connection() as connection:
            existing = connection.execute(
                """
                SELECT 1
                FROM model_execution_work_bundles
                WHERE bundle_id = ?
                """,
                (validated.bundle_id.value,),
            ).fetchone()
            if existing is not None:
                stored = self._stored_model_work(connection, validated.bundle_id.value)
                self._assert_exact_model_work_registration(
                    stored,
                    bundle=validated,
                    admission=admission,
                    admission_hash=admission_hash,
                )
                self._verify_model_work_admission(stored.bundle, stored.admission)

    def preflight_authorization_ttl(self, ttl_seconds: float) -> None:
        """Apply the configured authorization TTL policy without mutating state."""

        self._validate_ttl(ttl_seconds)

    def register_model_work(
        self,
        bundle: ModelWorkBundleV2,
        *,
        admission: AttestationV1,
    ) -> ModelWorkBundleV2:
        """Register independently admitted non-theorem work before it can obtain a lease."""

        bundle = self._validated_model_work(bundle)
        self._verify_model_work_admission(bundle, admission)
        bundle_hash = bundle.handoff_hash().value
        admission_hash = self._model_work_admission_hash(admission)
        registration_request = self._model_work_registration_request(
            bundle=bundle,
            admission_hash=admission_hash,
        )
        request_digest = request_hash(registration_request)
        serialized = canonical_json(bundle.model_dump(mode="json"))
        serialized_admission = canonical_json(admission.model_dump(mode="json"))
        with self._events.write_transaction() as connection:
            # The lock-time verification closes the expiry/revocation race between validation
            # and durable insertion. Exact replay is allowed only while this parent remains valid.
            self._verify_model_work_admission(bundle, admission)
            replay = self._idempotent_model_work(
                connection,
                key=request_digest,
                request_digest=request_digest,
            )
            if replay is not None:
                self._assert_exact_model_work_registration(
                    replay,
                    bundle=bundle,
                    admission=admission,
                    admission_hash=admission_hash,
                )
                self._verify_model_work_admission(replay.bundle, replay.admission)
                return replay.bundle
            existing = connection.execute(
                """
                SELECT bundle_hash, admission_attestation_hash
                FROM model_execution_work_bundles
                WHERE bundle_id = ?
                """,
                (bundle.bundle_id.value,),
            ).fetchone()
            if existing is not None:
                if (
                    str(existing["bundle_hash"]) != bundle_hash
                    or str(existing["admission_attestation_hash"]) != admission_hash
                ):
                    raise ModelExecutionAuthorizationError(
                        "model work bundle ID is already bound to different immutable work "
                        "or admission"
                    )
                stored = self._stored_model_work(connection, bundle.bundle_id.value)
                self._assert_exact_model_work_registration(
                    stored,
                    bundle=bundle,
                    admission=admission,
                    admission_hash=admission_hash,
                )
                self._verify_model_work_admission(stored.bundle, stored.admission)
                self._record_model_work_idempotency(
                    connection,
                    key=request_digest,
                    request_digest=request_digest,
                    bundle_id=stored.bundle.bundle_id.value,
                )
                return stored.bundle
            connection.execute(
                """
                INSERT INTO model_execution_work_bundles (
                    bundle_id, bundle_hash, bundle_json,
                    admission_attestation_hash, admission_attestation_json,
                    registration_request_hash, registered_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    bundle.bundle_id.value,
                    bundle_hash,
                    serialized,
                    admission_hash,
                    serialized_admission,
                    request_digest,
                    self._timestamp(self._now()),
                ),
            )
            self._record_model_work_idempotency(
                connection,
                key=request_digest,
                request_digest=request_digest,
                bundle_id=bundle.bundle_id.value,
            )
        return bundle

    def claim_model_work(
        self,
        bundle: ModelWorkBundleV2,
        *,
        ttl_seconds: float,
    ) -> Lease:
        """Claim the existing fenced lease primitive for registered non-theorem work."""

        validated = self._validated_model_work(bundle)
        self._assert_model_work_binding(validated)
        worker_id = self._model_work_worker_id(validated)
        try:
            return self._control_plane.leases.claim(
                validated.bundle_id.value,
                worker_id,
                ttl_seconds=ttl_seconds,
            )
        except ValueError as error:
            raise ModelExecutionAuthorizationError("model work lease claim is invalid") from error

    def issue(
        self,
        bundle: FormalizationTaskBundleV1,
        *,
        authorization_id: StableIdentifierV1,
        approval_id: StableIdentifierV1,
        budget: ModelExecutionBudgetV1,
        lease: Lease,
        context_pack_hash: DigestV1,
        outbound_request_hash: DigestV1,
        ttl_seconds: float,
        idempotency_key: str,
    ) -> ModelExecutionAuthorizationV1:
        """Mint a short-lived capability from a registered frozen bundle and approval ID only."""

        self._validate_ttl(ttl_seconds)
        if not idempotency_key.strip():
            raise ModelExecutionAuthorizationError(
                "authorization idempotency key must not be empty"
            )
        binding = self._assert_bundle_binding(bundle)
        self._assert_current_issue_lease(bundle, lease)
        self._validate_request_hashes(
            context_pack_hash=context_pack_hash,
            outbound_request_hash=outbound_request_hash,
        )
        egress_policy = ModelEgressPolicyV1(
            rights_id=bundle.contract.rights.rights_id,
            overall_decision=bundle.contract.rights.overall_decision,
            model_egress=bundle.contract.rights.model_egress,
            allowed_endpoint_classes=bundle.contract.rights.allowed_endpoint_classes,
        )
        return self._issue_bound(
            subject=_AuthorizationSubject(
                subject_kind=ModelExecutionSubjectKindV1.THEOREM,
                bundle_id=bundle.bundle_id,
                bundle_hash=bundle.handoff_hash(),
                contract_id=bundle.contract.contract_id,
                revision=bundle.contract.revision,
                contract_hash=bundle.contract.semantic_hash(),
                environment_hash=bundle.contract.formal.environment.environment_hash,
                egress_policy=egress_policy,
            ),
            registered_bundle_hash=binding.bundle_hash,
            authorization_id=authorization_id,
            approval_id=approval_id,
            budget=budget,
            lease=lease,
            context_pack_hash=context_pack_hash,
            outbound_request_hash=outbound_request_hash,
            ttl_seconds=ttl_seconds,
            idempotency_key=idempotency_key,
        )

    def issue_model_work(
        self,
        bundle: ModelWorkBundleV2,
        *,
        approval_id: StableIdentifierV1,
        budget: ModelExecutionBudgetV1,
        lease: Lease,
        ttl_seconds: float,
    ) -> ModelExecutionAuthorizationV1:
        """Issue the normal wire capability for one registered, rights-bound role trial."""

        self._validate_ttl(ttl_seconds)
        bundle = self._validated_model_work(bundle)
        registration = self._assert_model_work_binding(bundle)
        self._assert_current_model_work_lease(bundle, lease)
        self._validate_request_hashes(
            context_pack_hash=bundle.context_pack_hash,
            outbound_request_hash=bundle.request_hash,
        )
        egress_policy = ModelEgressPolicyV1(
            rights_id=stable_identifier(
                "model-work-rights",
                bundle.rights.rights_record_hash.value,
            ),
            overall_decision=bundle.rights.overall_decision,
            model_egress=bundle.rights.model_egress,
            allowed_endpoint_classes=bundle.rights.allowed_endpoint_classes,
        )
        return self._issue_bound(
            subject=_AuthorizationSubject(
                subject_kind=ModelExecutionSubjectKindV1.MODEL_WORK,
                bundle_id=bundle.bundle_id,
                bundle_hash=bundle.handoff_hash(),
                contract_id=bundle.work_contract_id,
                revision=bundle.revision,
                contract_hash=bundle.semantic_hash(),
                environment_hash=bundle.role_environment_hash,
                egress_policy=egress_policy,
                parent_admission_hash=DigestV1(
                    kind=HashKindV1.ATTESTATION,
                    value=registration.admission_hash,
                ),
                parent_admission_expires_at=registration.admission.expires_at,
            ),
            registered_bundle_hash=registration.bundle.handoff_hash().value,
            authorization_id=None,
            approval_id=approval_id,
            budget=budget,
            lease=lease,
            context_pack_hash=bundle.context_pack_hash,
            outbound_request_hash=bundle.request_hash,
            ttl_seconds=ttl_seconds,
            idempotency_key=None,
        )

    def _issue_bound(
        self,
        *,
        subject: _AuthorizationSubject,
        registered_bundle_hash: str,
        authorization_id: StableIdentifierV1 | None,
        approval_id: StableIdentifierV1,
        budget: ModelExecutionBudgetV1,
        lease: Lease,
        context_pack_hash: DigestV1,
        outbound_request_hash: DigestV1,
        ttl_seconds: float,
        idempotency_key: str | None,
    ) -> ModelExecutionAuthorizationV1:
        """Shared signed-capability path for theorem and non-theorem model work."""

        with self._events.connection() as connection:
            approval = self._stored_provider_approval(connection, approval_id.value)
        if not approval.enabled:
            raise ModelExecutionAuthorizationError("selected provider approval is disabled")
        if not subject.egress_policy.permits(approval.binding.endpoint_class):
            raise ModelExecutionAuthorizationError(
                "frozen source rights do not permit the selected model endpoint"
            )
        now = self._now()
        expires_at = now + timedelta(seconds=ttl_seconds)
        if subject.subject_kind is ModelExecutionSubjectKindV1.MODEL_WORK:
            if subject.parent_admission_hash is None or subject.parent_admission_expires_at is None:
                raise ModelExecutionAuthorizationError(
                    "model work authorization requires an exact parent admission"
                )
            if subject.parent_admission_expires_at <= now:
                raise ModelExecutionAuthorizationError("model work parent admission has expired")
            if expires_at > subject.parent_admission_expires_at:
                raise ModelExecutionAuthorizationError(
                    "requested model-work authorization TTL exceeds its parent admission"
                )
            if authorization_id is not None or idempotency_key is not None:
                raise ModelExecutionAuthorizationError(
                    "model work authorization identities are system-derived"
                )
            authorization_id = stable_identifier(
                "model-work-authorization",
                request_hash(
                    {
                        "schema_version": "autolean.model-work-authorization-identity.v1",
                        "bundle_hash": subject.bundle_hash.model_dump(mode="json"),
                        "parent_admission_hash": subject.parent_admission_hash.model_dump(
                            mode="json"
                        ),
                        "approval_hash": approval.approval_hash().model_dump(mode="json"),
                        "budget": budget.model_dump(mode="json"),
                        "lease": {
                            "worker_id": lease.holder_id,
                            "fencing_token": lease.fencing_token,
                            "expires_at": self._timestamp(lease.expires_at),
                        },
                        "context_pack_hash": context_pack_hash.model_dump(mode="json"),
                        "request_hash": outbound_request_hash.model_dump(mode="json"),
                        "ttl_seconds": ttl_seconds,
                    }
                ),
            )
        elif authorization_id is None or idempotency_key is None:
            raise ModelExecutionAuthorizationError(
                "theorem authorization requires caller-owned operation identities"
            )
        if expires_at > lease.expires_at:
            raise ModelExecutionAuthorizationError(
                "model execution authorization must expire no later than its current worker lease"
            )
        unsigned = ModelExecutionAuthorizationV1(
            subject_kind=subject.subject_kind,
            authorization_id=authorization_id,
            bundle_id=subject.bundle_id,
            bundle_hash=subject.bundle_hash,
            contract_id=subject.contract_id,
            revision=subject.revision,
            contract_hash=subject.contract_hash,
            environment_hash=subject.environment_hash,
            lease=ModelExecutionLeaseBindingV1(
                bundle_id=subject.bundle_id,
                worker_id=lease.holder_id,
                fencing_token=lease.fencing_token,
                expires_at=lease.expires_at,
            ),
            context_pack_hash=context_pack_hash,
            request_hash=outbound_request_hash,
            egress_policy=subject.egress_policy,
            approval_snapshot=approval,
            budget=budget,
            issued_at=now,
            expires_at=expires_at,
            parent_admission_hash=subject.parent_admission_hash,
            parent_admission_expires_at=subject.parent_admission_expires_at,
        )
        payload = model_execution_authorization_payload(unsigned)
        try:
            attestation = self._signer.issue(
                purpose=AttestationPurposeV1.MODEL_EXECUTION,
                payload=payload,
                evidence_identity=(
                    "model-execution-authorization:" + unsigned.authorization_hash().value
                ),
                ttl_seconds=(expires_at - now).total_seconds(),
            )
        except AttestationError as error:
            raise ModelExecutionAuthorizationError(
                "control-plane model authorization could not be attested"
            ) from error
        authorization = unsigned.model_copy(update={"attestation": attestation})
        self._verify_capability(authorization)
        issue_request = {
            "schema_version": "autolean.model-execution-issue-request.v2",
            "subject_kind": subject.subject_kind.value,
            "authorization_id": authorization_id.value,
            "bundle_hash": registered_bundle_hash,
            "approval_id": approval.approval_id.value,
            "approval_hash": approval.approval_hash().value,
            "budget": budget.model_dump(mode="json"),
            "lease": unsigned.lease.model_dump(mode="json"),
            "context_pack_hash": context_pack_hash.model_dump(mode="json"),
            "request_hash": outbound_request_hash.model_dump(mode="json"),
            "ttl_seconds": ttl_seconds,
            "parent_admission_hash": (
                None
                if subject.parent_admission_hash is None
                else subject.parent_admission_hash.model_dump(mode="json")
            ),
            "parent_admission_expires_at": (
                None
                if subject.parent_admission_expires_at is None
                else self._timestamp(subject.parent_admission_expires_at)
            ),
        }
        request_digest = request_hash(issue_request)
        effective_idempotency_key = (
            request_digest
            if subject.subject_kind is ModelExecutionSubjectKindV1.MODEL_WORK
            else idempotency_key
        )
        if effective_idempotency_key is None:
            raise ModelExecutionAuthorizationError("authorization idempotency identity is missing")
        serialized = canonical_json(authorization.model_dump(mode="json"))
        with self._events.write_transaction() as connection:
            if subject.subject_kind is ModelExecutionSubjectKindV1.MODEL_WORK:
                self._assert_parent_admission(connection, authorization)
            replay = self._idempotent_authorization(
                connection,
                scope=self._ISSUE_SCOPE,
                key=effective_idempotency_key,
                request_digest=request_digest,
            )
            if replay is not None:
                return replay
            existing = connection.execute(
                """
                SELECT issue_request_hash
                FROM model_execution_authorizations
                WHERE authorization_id = ?
                """,
                (authorization_id.value,),
            ).fetchone()
            if existing is not None:
                if str(existing["issue_request_hash"]) != request_digest:
                    raise ModelExecutionAuthorizationError(
                        "authorization ID is already bound to a different issue request"
                    )
                stored = self._stored_authorization(connection, authorization_id.value)
                self._record_idempotency(
                    connection,
                    scope=self._ISSUE_SCOPE,
                    key=effective_idempotency_key,
                    request_digest=request_digest,
                    authorization_id=stored.authorization_id.value,
                )
                return stored
            connection.execute(
                """
                INSERT INTO model_execution_authorizations (
                    authorization_id,
                    authorization_hash,
                    authorization_json,
                    issue_request_hash,
                    issued_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    authorization.authorization_id.value,
                    authorization.authorization_hash().value,
                    serialized,
                    request_digest,
                    self._timestamp(now),
                ),
            )
            self._record_idempotency(
                connection,
                scope=self._ISSUE_SCOPE,
                key=effective_idempotency_key,
                request_digest=request_digest,
                authorization_id=authorization.authorization_id.value,
            )
        return authorization

    def revoke(
        self,
        authorization_id: StableIdentifierV1,
        *,
        reason: str,
        idempotency_key: str,
    ) -> None:
        """Append a durable revocation; reservations can release but can never settle afterward."""

        self._validate_reason(reason)
        if not idempotency_key.strip():
            raise ModelExecutionAuthorizationError("revocation idempotency key must not be empty")
        request_digest = request_hash(
            {
                "schema_version": "autolean.model-execution-revocation-request.v1",
                "authorization_id": authorization_id.value,
                "reason": reason,
            }
        )
        with self._events.write_transaction() as connection:
            replay = self._idempotent_authorization(
                connection,
                scope=self._REVOKE_SCOPE,
                key=idempotency_key,
                request_digest=request_digest,
            )
            if replay is not None:
                return
            self._stored_authorization(connection, authorization_id.value)
            if not self._is_revoked(connection, authorization_id.value):
                self._append_ledger_event(
                    connection,
                    authorization_id=authorization_id.value,
                    reservation_id=None,
                    attempt_number=None,
                    event_type="revoked",
                    reason=reason,
                )
            self._record_idempotency(
                connection,
                scope=self._REVOKE_SCOPE,
                key=idempotency_key,
                request_digest=request_digest,
                authorization_id=authorization_id.value,
            )

    def preflight(
        self,
        authorization: ModelExecutionAuthorizationV1,
        *,
        provider: ModelExecutionProviderBindingV1,
        requested_input_tokens: int,
        requested_output_tokens: int,
        context_pack_hash: DigestV1 | None,
        outbound_request_hash: DigestV1,
    ) -> None:
        """Validate authority before a provider probe can perform endpoint I/O.

        This is intentionally non-reserving: a later ``reserve`` repeats the checks inside an
        immediate transaction, so a revocation racing with a probe still prevents generation.
        """

        self._verify_capability(authorization)
        self._validate_request_limits(
            authorization,
            provider=provider,
            requested_input_tokens=requested_input_tokens,
            requested_output_tokens=requested_output_tokens,
            context_pack_hash=context_pack_hash,
            outbound_request_hash=outbound_request_hash,
        )
        with self._events.connection() as connection:
            stored = self._stored_authorization(connection, authorization.authorization_id.value)
            self._assert_same_capability(stored, authorization)
            self._assert_active(connection, authorization)
            self._assert_parent_admission(connection, authorization)
            self._assert_provider_circuit_closed(connection, provider)

    def reserve(
        self,
        authorization: ModelExecutionAuthorizationV1,
        *,
        provider: ModelExecutionProviderBindingV1,
        requested_input_tokens: int,
        requested_output_tokens: int,
        context_pack_hash: DigestV1 | None,
        outbound_request_hash: DigestV1,
    ) -> ModelExecutionReservationV1:
        """Atomically reserve one attempt's worst-case token and cost budget."""

        self._verify_capability(authorization)
        self._validate_request_limits(
            authorization,
            provider=provider,
            requested_input_tokens=requested_input_tokens,
            requested_output_tokens=requested_output_tokens,
            context_pack_hash=context_pack_hash,
            outbound_request_hash=outbound_request_hash,
        )
        with self._events.write_transaction() as connection:
            stored = self._stored_authorization(connection, authorization.authorization_id.value)
            self._assert_same_capability(stored, authorization)
            self._assert_active(connection, authorization)
            self._assert_parent_admission(connection, authorization)
            self._assert_provider_circuit_closed(connection, provider)
            states = self._reservation_states(connection, authorization.authorization_id.value)
            totals = self._usage_totals(states)
            if totals.attempts >= authorization.budget.max_attempts:
                raise ModelExecutionAuthorizationError(
                    "model execution authorization attempt budget exhausted"
                )
            reservation_cost = authorization.pricing.reserve_cost(
                max_input_tokens=requested_input_tokens,
                max_output_tokens=requested_output_tokens,
            )
            next_input = totals.input_tokens + requested_input_tokens
            next_output = totals.output_tokens + requested_output_tokens
            next_total = totals.total_tokens + requested_input_tokens + requested_output_tokens
            next_cost = totals.cost_microusd + reservation_cost
            if next_input > authorization.budget.max_input_tokens:
                raise ModelExecutionAuthorizationError(
                    "model execution input-token budget exhausted"
                )
            if next_output > authorization.budget.max_output_tokens:
                raise ModelExecutionAuthorizationError(
                    "model execution output-token budget exhausted"
                )
            if next_total > authorization.budget.max_total_tokens:
                raise ModelExecutionAuthorizationError(
                    "model execution total-token budget exhausted"
                )
            if next_cost > authorization.budget.max_cost_microusd:
                raise ModelExecutionAuthorizationError("model execution cost budget exhausted")
            attempt_number = totals.attempts + 1
            now = self._now()
            reservation = ModelExecutionReservationV1(
                reservation_id=stable_identifier(
                    "model-execution-reservation",
                    f"{authorization.authorization_id.value}:{attempt_number}:{uuid.uuid4()}",
                ),
                authorization_id=authorization.authorization_id,
                attempt_number=attempt_number,
                reserved_input_tokens=requested_input_tokens,
                reserved_output_tokens=requested_output_tokens,
                reserved_cost_microusd=reservation_cost,
                reserved_at=now,
            )
            self._append_ledger_event(
                connection,
                authorization_id=authorization.authorization_id.value,
                reservation_id=reservation.reservation_id.value,
                attempt_number=attempt_number,
                event_type="reserved",
                reserved_input_tokens=reservation.reserved_input_tokens,
                reserved_output_tokens=reservation.reserved_output_tokens,
                reserved_cost_microusd=reservation.reserved_cost_microusd,
            )
        return reservation

    def settle(
        self,
        reservation: ModelExecutionReservationV1,
        *,
        input_tokens: int,
        cached_input_tokens: int,
        output_tokens: int,
    ) -> None:
        """Settle a reservation with observed usage; overages fail closed and are not accepted."""

        if min(input_tokens, cached_input_tokens, output_tokens) < 0:
            raise ModelExecutionAuthorizationError("model execution usage must be non-negative")
        if cached_input_tokens > input_tokens:
            raise ModelExecutionAuthorizationError("cached input tokens cannot exceed input tokens")
        with self._events.write_transaction() as connection:
            authorization = self._stored_authorization(
                connection,
                reservation.authorization_id.value,
            )
            self._verify_capability(authorization)
            self._assert_active(connection, authorization)
            states = self._reservation_states(connection, authorization.authorization_id.value)
            state = states.get(reservation.reservation_id.value)
            self._assert_reservation_matches(reservation, state)
            if state is not None and state.state == "settled":
                if (
                    state.actual_input_tokens,
                    state.actual_cached_input_tokens,
                    state.actual_output_tokens,
                ) != (input_tokens, cached_input_tokens, output_tokens):
                    raise ModelExecutionAuthorizationError(
                        "model execution settlement replay has different usage"
                    )
                return
            if state is None or state.state != "reserved":
                raise ModelExecutionAuthorizationError("model execution reservation is not active")
            actual_cost = authorization.pricing.cost_for_usage(
                input_tokens=input_tokens,
                cached_input_tokens=cached_input_tokens,
                output_tokens=output_tokens,
            )
            if (
                input_tokens > state.reserved_input_tokens
                or output_tokens > state.reserved_output_tokens
                or actual_cost > state.reserved_cost_microusd
            ):
                raise ModelExecutionAuthorizationError(
                    "provider usage exceeded the pre-authorized model execution reservation"
                )
            self._append_ledger_event(
                connection,
                authorization_id=authorization.authorization_id.value,
                reservation_id=reservation.reservation_id.value,
                attempt_number=reservation.attempt_number,
                event_type="settled",
                actual_input_tokens=input_tokens,
                actual_cached_input_tokens=cached_input_tokens,
                actual_output_tokens=output_tokens,
                actual_cost_microusd=actual_cost,
            )
            self._append_provider_health_event(
                connection,
                provider=authorization.provider,
                authorization_id=authorization.authorization_id.value,
                reservation_id=reservation.reservation_id.value,
                event_type="success",
            )

    def abandon(
        self,
        reservation: ModelExecutionReservationV1,
        *,
        failure_code: str,
    ) -> None:
        """Release a failed attempt and retain only its stable, credential-free failure code."""

        self._validate_provider_failure_code(failure_code)
        with self._events.write_transaction() as connection:
            authorization = self._stored_authorization(
                connection,
                reservation.authorization_id.value,
            )
            states = self._reservation_states(connection, authorization.authorization_id.value)
            state = states.get(reservation.reservation_id.value)
            self._assert_reservation_matches(reservation, state)
            if state is None or state.state == "settled":
                return
            if state.state == "abandoned":
                if state.failure_code is not None and state.failure_code != failure_code:
                    raise ModelExecutionAuthorizationError(
                        "model execution abandonment replay has a different failure code"
                    )
                return
            self._append_ledger_event(
                connection,
                authorization_id=authorization.authorization_id.value,
                reservation_id=reservation.reservation_id.value,
                attempt_number=reservation.attempt_number,
                event_type="abandoned",
                reason=failure_code,
            )
            if failure_code in _PROVIDER_HEALTH_FAILURE_CODES:
                self._append_provider_health_event(
                    connection,
                    provider=authorization.provider,
                    authorization_id=authorization.authorization_id.value,
                    reservation_id=reservation.reservation_id.value,
                    event_type="failure",
                    failure_code=failure_code,
                )

    def _initialize(self) -> None:
        with self._events.connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS model_execution_authorizations (
                    authorization_id TEXT PRIMARY KEY,
                    authorization_hash TEXT NOT NULL,
                    authorization_json TEXT NOT NULL,
                    issue_request_hash TEXT NOT NULL,
                    issued_at TEXT NOT NULL
                ) WITHOUT ROWID;

                CREATE TABLE IF NOT EXISTS model_execution_provider_approvals (
                    approval_id TEXT PRIMARY KEY,
                    approval_hash TEXT NOT NULL,
                    approval_json TEXT NOT NULL,
                    registration_request_hash TEXT NOT NULL,
                    registered_at TEXT NOT NULL
                ) WITHOUT ROWID;

                CREATE TABLE IF NOT EXISTS model_execution_provider_approval_idempotency (
                    key TEXT PRIMARY KEY,
                    request_hash TEXT NOT NULL,
                    approval_id TEXT NOT NULL
                ) WITHOUT ROWID;

                CREATE TABLE IF NOT EXISTS model_execution_work_bundles (
                    bundle_id TEXT PRIMARY KEY,
                    bundle_hash TEXT NOT NULL,
                    bundle_json TEXT NOT NULL,
                    admission_attestation_hash TEXT NOT NULL,
                    admission_attestation_json TEXT NOT NULL,
                    registration_request_hash TEXT NOT NULL,
                    registered_at TEXT NOT NULL
                ) WITHOUT ROWID;

                CREATE TABLE IF NOT EXISTS model_execution_work_idempotency (
                    key TEXT PRIMARY KEY,
                    request_hash TEXT NOT NULL,
                    bundle_id TEXT NOT NULL
                ) WITHOUT ROWID;

                CREATE TABLE IF NOT EXISTS model_execution_authorization_idempotency (
                    scope TEXT NOT NULL,
                    key TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    authorization_id TEXT NOT NULL,
                    PRIMARY KEY (scope, key)
                ) WITHOUT ROWID;

                CREATE TABLE IF NOT EXISTS model_execution_authorization_ledger (
                    event_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    authorization_id TEXT NOT NULL,
                    reservation_id TEXT,
                    attempt_number INTEGER,
                    event_type TEXT NOT NULL CHECK (
                        event_type IN ('reserved', 'settled', 'abandoned', 'revoked')
                    ),
                    reserved_input_tokens INTEGER,
                    reserved_output_tokens INTEGER,
                    reserved_cost_microusd INTEGER,
                    actual_input_tokens INTEGER,
                    actual_cached_input_tokens INTEGER,
                    actual_output_tokens INTEGER,
                    actual_cost_microusd INTEGER,
                    reason TEXT,
                    recorded_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS model_execution_authorization_ledger_auth
                    ON model_execution_authorization_ledger (authorization_id, event_sequence);

                CREATE TABLE IF NOT EXISTS model_execution_provider_health_ledger (
                    event_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    binding_hash TEXT NOT NULL,
                    binding_json TEXT NOT NULL,
                    authorization_id TEXT NOT NULL,
                    reservation_id TEXT NOT NULL,
                    event_type TEXT NOT NULL CHECK (event_type IN ('failure', 'success')),
                    failure_code TEXT,
                    recorded_at TEXT NOT NULL,
                    CHECK (
                        (event_type = 'failure' AND failure_code IS NOT NULL)
                        OR (event_type = 'success' AND failure_code IS NULL)
                    )
                );

                CREATE INDEX IF NOT EXISTS model_execution_provider_health_binding
                    ON model_execution_provider_health_ledger (
                        binding_hash, event_sequence DESC
                    );

                CREATE TRIGGER IF NOT EXISTS model_execution_authorizations_forbid_update
                BEFORE UPDATE ON model_execution_authorizations
                BEGIN
                    SELECT RAISE(ABORT, 'model execution authorizations are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS model_execution_authorizations_forbid_delete
                BEFORE DELETE ON model_execution_authorizations
                BEGIN
                    SELECT RAISE(ABORT, 'model execution authorizations are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS model_execution_provider_approvals_forbid_update
                BEFORE UPDATE ON model_execution_provider_approvals
                BEGIN
                    SELECT RAISE(ABORT, 'model execution provider approvals are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS model_execution_provider_approvals_forbid_delete
                BEFORE DELETE ON model_execution_provider_approvals
                BEGIN
                    SELECT RAISE(ABORT, 'model execution provider approvals are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS
                model_execution_provider_approval_idempotency_forbid_update
                BEFORE UPDATE ON model_execution_provider_approval_idempotency
                BEGIN
                    SELECT RAISE(ABORT, 'provider approval idempotency is immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS
                model_execution_provider_approval_idempotency_forbid_delete
                BEFORE DELETE ON model_execution_provider_approval_idempotency
                BEGIN
                    SELECT RAISE(ABORT, 'provider approval idempotency is immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS model_execution_work_bundles_forbid_update
                BEFORE UPDATE ON model_execution_work_bundles
                BEGIN
                    SELECT RAISE(ABORT, 'model work bundles are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS model_execution_work_bundles_forbid_delete
                BEFORE DELETE ON model_execution_work_bundles
                BEGIN
                    SELECT RAISE(ABORT, 'model work bundles are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS model_execution_work_idempotency_forbid_update
                BEFORE UPDATE ON model_execution_work_idempotency
                BEGIN
                    SELECT RAISE(ABORT, 'model work idempotency is immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS model_execution_work_idempotency_forbid_delete
                BEFORE DELETE ON model_execution_work_idempotency
                BEGIN
                    SELECT RAISE(ABORT, 'model work idempotency is immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS model_execution_authorization_idempotency_forbid_update
                BEFORE UPDATE ON model_execution_authorization_idempotency
                BEGIN
                    SELECT RAISE(ABORT, 'model execution authorization idempotency is immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS model_execution_authorization_idempotency_forbid_delete
                BEFORE DELETE ON model_execution_authorization_idempotency
                BEGIN
                    SELECT RAISE(ABORT, 'model execution authorization idempotency is immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS model_execution_authorization_ledger_forbid_update
                BEFORE UPDATE ON model_execution_authorization_ledger
                BEGIN
                    SELECT RAISE(ABORT, 'model execution ledger is append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS model_execution_authorization_ledger_forbid_delete
                BEFORE DELETE ON model_execution_authorization_ledger
                BEGIN
                    SELECT RAISE(ABORT, 'model execution ledger is append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS model_execution_provider_health_ledger_forbid_update
                BEFORE UPDATE ON model_execution_provider_health_ledger
                BEGIN
                    SELECT RAISE(ABORT, 'model execution provider health ledger is append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS model_execution_provider_health_ledger_forbid_delete
                BEFORE DELETE ON model_execution_provider_health_ledger
                BEGIN
                    SELECT RAISE(ABORT, 'model execution provider health ledger is append-only');
                END;
                """
            )
            self._ensure_model_work_admission_columns(connection)

    @staticmethod
    def _ensure_model_work_admission_columns(connection: sqlite3.Connection) -> None:
        """Migrate an older ledger without treating its unsigned rows as admitted work."""

        columns = {
            str(row["name"])
            for row in connection.execute(
                "PRAGMA table_info(model_execution_work_bundles)"
            ).fetchall()
        }
        if "admission_attestation_hash" not in columns:
            connection.execute(
                "ALTER TABLE model_execution_work_bundles "
                "ADD COLUMN admission_attestation_hash TEXT"
            )
        if "admission_attestation_json" not in columns:
            connection.execute(
                "ALTER TABLE model_execution_work_bundles "
                "ADD COLUMN admission_attestation_json TEXT"
            )

    def _assert_provider_circuit_closed(
        self,
        connection: sqlite3.Connection,
        provider: ModelExecutionProviderBindingV1,
    ) -> None:
        binding_hash, binding_json = self._provider_binding_record(provider)
        rows = connection.execute(
            """
            SELECT binding_json, event_type, failure_code, recorded_at
            FROM model_execution_provider_health_ledger
            WHERE binding_hash = ?
            ORDER BY event_sequence DESC
            LIMIT ?
            """,
            (binding_hash, self._provider_failure_threshold),
        ).fetchall()
        consecutive_failures = 0
        latest_failure_at: datetime | None = None
        for row in rows:
            if str(row["binding_json"]) != binding_json:
                raise ModelExecutionAuthorizationError(
                    "provider health ledger binding hash collision or corruption"
                )
            event_type = str(row["event_type"])
            if event_type == "success":
                if row["failure_code"] is not None:
                    raise ModelExecutionAuthorizationError(
                        "provider health success event contains a failure code"
                    )
                break
            if event_type != "failure":
                raise ModelExecutionAuthorizationError(
                    "provider health ledger contains an invalid event"
                )
            failure_code = row["failure_code"]
            if not isinstance(failure_code, str):
                raise ModelExecutionAuthorizationError(
                    "provider health failure event has no failure code"
                )
            self._validate_provider_failure_code(failure_code)
            if failure_code not in _PROVIDER_HEALTH_FAILURE_CODES:
                raise ModelExecutionAuthorizationError(
                    "provider health ledger contains a non-health failure code"
                )
            recorded_at = self._parse_provider_health_timestamp(row["recorded_at"])
            if latest_failure_at is None:
                latest_failure_at = recorded_at
            consecutive_failures += 1
        if (
            consecutive_failures >= self._provider_failure_threshold
            and latest_failure_at is not None
            and self._now()
            < latest_failure_at + timedelta(seconds=self._provider_failure_cooldown_seconds)
        ):
            raise ModelExecutionAuthorizationError(
                "provider circuit is open for the authorized provider binding"
            )

    def _append_provider_health_event(
        self,
        connection: sqlite3.Connection,
        *,
        provider: ModelExecutionProviderBindingV1,
        authorization_id: str,
        reservation_id: str,
        event_type: Literal["failure", "success"],
        failure_code: str | None = None,
    ) -> None:
        if event_type == "failure":
            if failure_code is None:
                raise ModelExecutionAuthorizationError(
                    "provider health failure requires a failure code"
                )
            self._validate_provider_failure_code(failure_code)
            if failure_code not in _PROVIDER_HEALTH_FAILURE_CODES:
                raise ModelExecutionAuthorizationError(
                    "non-health failure code cannot advance the provider circuit"
                )
        elif failure_code is not None:
            raise ModelExecutionAuthorizationError(
                "provider health success cannot contain a failure code"
            )
        binding_hash, binding_json = self._provider_binding_record(provider)
        connection.execute(
            """
            INSERT INTO model_execution_provider_health_ledger (
                event_id, binding_hash, binding_json, authorization_id, reservation_id,
                event_type, failure_code, recorded_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                binding_hash,
                binding_json,
                authorization_id,
                reservation_id,
                event_type,
                failure_code,
                self._timestamp(self._now()),
            ),
        )

    @staticmethod
    def _provider_binding_record(
        provider: ModelExecutionProviderBindingV1,
    ) -> tuple[str, str]:
        payload = {
            "schema_version": "autolean.provider-circuit-binding.v1",
            "provider": provider.model_dump(mode="json"),
        }
        return request_hash(payload), canonical_json(payload)

    def _parse_provider_health_timestamp(self, value: object) -> datetime:
        if not isinstance(value, str):
            raise ModelExecutionAuthorizationError(
                "provider health ledger contains an invalid timestamp"
            )
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as error:
            raise ModelExecutionAuthorizationError(
                "provider health ledger contains an invalid timestamp"
            ) from error
        if parsed.tzinfo is None or self._timestamp(parsed) != value:
            raise ModelExecutionAuthorizationError(
                "provider health ledger contains a non-canonical timestamp"
            )
        return parsed.astimezone(UTC)

    def _assert_bundle_binding(self, bundle: FormalizationTaskBundleV1) -> TaskBinding:
        binding = self._control_plane.get_binding(bundle.bundle_id.value)
        if (
            binding.bundle_hash != bundle.handoff_hash().value
            or binding.contract_id != bundle.contract.contract_id.value
            or binding.revision != bundle.contract.revision
            or binding.contract_hash != bundle.contract.semantic_hash().value
            or binding.environment_hash != bundle.contract.formal.environment.environment_hash.value
        ):
            raise ModelExecutionAuthorizationError(
                "model authorization bundle does not match the registered frozen task"
            )
        return binding

    @staticmethod
    def _validated_model_work(bundle: ModelWorkBundleV2) -> ModelWorkBundleV2:
        """Revalidate serialized fields so ``model_copy(update=...)`` cannot bypass V2."""

        try:
            return ModelWorkBundleV2.model_validate(bundle.model_dump(mode="json"))
        except Exception as error:
            raise ModelExecutionAuthorizationError(
                "model work bundle is not a valid V2 public projection"
            ) from error

    @staticmethod
    def _model_work_worker_id(bundle: ModelWorkBundleV2) -> str:
        return "model-work-worker-" + request_hash(
            {
                "schema_version": "autolean.model-work-worker-reference.v1",
                "bundle_hash": bundle.handoff_hash().value,
            }
        )

    def _assert_model_work_binding(
        self,
        bundle: ModelWorkBundleV2,
    ) -> _StoredModelWorkRegistration:
        with self._events.connection() as connection:
            registration = self._stored_model_work(connection, bundle.bundle_id.value)
        self._verify_model_work_admission(
            registration.bundle,
            registration.admission,
        )
        if canonical_json(registration.bundle.model_dump(mode="json")) != canonical_json(
            bundle.model_dump(mode="json")
        ):
            raise ModelExecutionAuthorizationError(
                "model work does not match its registered immutable bundle"
            )
        return registration

    def _verify_model_work_admission(
        self,
        bundle: ModelWorkBundleV2,
        admission: AttestationV1,
    ) -> None:
        if self._admission_verifier is None:
            raise ModelExecutionAuthorizationError(
                "model work registration requires a trusted admission verifier"
            )
        if _MODEL_WORK_NONCE.fullmatch(admission.nonce) is None:
            raise ModelExecutionAuthorizationError(
                "model work admission nonce must be a signer-generated 48-digit hex value"
            )
        if admission.evidence_identity != model_work_admission_evidence_identity(bundle):
            raise ModelExecutionAuthorizationError(
                "model work admission evidence identity does not bind the exact payload"
            )
        try:
            self._admission_verifier.verify(
                admission,
                expected_purpose=AttestationPurposeV1.MODEL_WORK_ADMISSION,
                payload=model_work_admission_payload(bundle),
            )
        except AttestationError as error:
            raise ModelExecutionAuthorizationError(
                "model work admission attestation was rejected"
            ) from error

    @staticmethod
    def _model_work_admission_hash(admission: AttestationV1) -> str:
        return digest_model(HashKindV1.ATTESTATION, admission).value

    @staticmethod
    def _model_work_registration_request(
        *,
        bundle: ModelWorkBundleV2,
        admission_hash: str,
    ) -> dict[str, object]:
        return {
            "schema_version": "autolean.model-work-registration-request.v3",
            "bundle_id": bundle.bundle_id.value,
            "bundle_hash": bundle.handoff_hash().value,
            "admission_attestation_hash": admission_hash,
        }

    @staticmethod
    def _assert_exact_model_work_registration(
        registration: _StoredModelWorkRegistration,
        *,
        bundle: ModelWorkBundleV2,
        admission: AttestationV1,
        admission_hash: str,
    ) -> None:
        if (
            registration.admission_hash != admission_hash
            or canonical_json(registration.bundle.model_dump(mode="json"))
            != canonical_json(bundle.model_dump(mode="json"))
            or canonical_json(registration.admission.model_dump(mode="json"))
            != canonical_json(admission.model_dump(mode="json"))
        ):
            raise ModelExecutionAuthorizationError(
                "model work registration differs from its immutable bundle or admission"
            )

    def _assert_current_issue_lease(
        self,
        bundle: FormalizationTaskBundleV1,
        lease: Lease,
    ) -> None:
        if lease.job_id != bundle.bundle_id.value:
            raise ModelExecutionAuthorizationError(
                "model execution lease belongs to a different frozen bundle"
            )
        try:
            self._control_plane.leases.assert_current(lease)
        except StaleFence as error:
            raise ModelExecutionAuthorizationError(
                "model execution lease is stale or expired"
            ) from error

    def _assert_current_model_work_lease(
        self,
        bundle: ModelWorkBundleV2,
        lease: Lease,
    ) -> None:
        if lease.job_id != bundle.bundle_id.value:
            raise ModelExecutionAuthorizationError(
                "model execution lease belongs to different registered model work"
            )
        if lease.holder_id != self._model_work_worker_id(bundle):
            raise ModelExecutionAuthorizationError(
                "model work lease holder is not its opaque system reference"
            )
        try:
            self._control_plane.leases.assert_current(lease)
        except StaleFence as error:
            raise ModelExecutionAuthorizationError(
                "model execution lease is stale or expired"
            ) from error

    def _assert_parent_admission(
        self,
        connection: sqlite3.Connection,
        authorization: ModelExecutionAuthorizationV1,
    ) -> None:
        if authorization.subject_kind is ModelExecutionSubjectKindV1.THEOREM:
            return
        registration = self._stored_model_work(connection, authorization.bundle_id.value)
        expected_hash = authorization.parent_admission_hash
        expected_expiry = authorization.parent_admission_expires_at
        if expected_hash is None or expected_expiry is None:
            raise ModelExecutionAuthorizationError(
                "model work authorization has no parent admission binding"
            )
        if (
            registration.admission_hash != expected_hash.value
            or registration.admission.expires_at != expected_expiry
            or registration.bundle.handoff_hash() != authorization.bundle_hash
            or registration.bundle.semantic_hash() != authorization.contract_hash
        ):
            raise ModelExecutionAuthorizationError(
                "model work authorization parent admission binding differs from storage"
            )
        self._verify_model_work_admission(registration.bundle, registration.admission)

    @staticmethod
    def _validate_request_hashes(
        *,
        context_pack_hash: DigestV1 | None,
        outbound_request_hash: DigestV1,
    ) -> None:
        if not isinstance(context_pack_hash, DigestV1) or context_pack_hash.kind.value != "prompt":
            raise ModelExecutionAuthorizationError(
                "model execution context_pack_hash must be a prompt digest"
            )
        if (
            not isinstance(outbound_request_hash, DigestV1)
            or outbound_request_hash.kind.value != "prompt"
        ):
            raise ModelExecutionAuthorizationError(
                "model execution request_hash must be a prompt digest"
            )

    def _verify_capability(self, authorization: ModelExecutionAuthorizationV1) -> None:
        attestation = authorization.attestation
        if attestation is None:
            raise ModelExecutionAuthorizationError(
                "model execution authorization is missing a control-plane attestation"
            )
        if attestation.expires_at < authorization.expires_at:
            raise ModelExecutionAuthorizationError(
                "model execution attestation expires before its authorization capability"
            )
        if authorization.expires_at <= self._now():
            raise ModelExecutionAuthorizationError("model execution authorization has expired")
        try:
            self._verifier.verify(
                attestation,
                expected_purpose=AttestationPurposeV1.MODEL_EXECUTION,
                payload=model_execution_authorization_payload(authorization),
            )
        except AttestationError as error:
            raise ModelExecutionAuthorizationError(
                "model execution authorization attestation was rejected"
            ) from error

    def _validate_request_limits(
        self,
        authorization: ModelExecutionAuthorizationV1,
        *,
        provider: ModelExecutionProviderBindingV1,
        requested_input_tokens: int,
        requested_output_tokens: int,
        context_pack_hash: DigestV1 | None,
        outbound_request_hash: DigestV1,
    ) -> None:
        if authorization.provider != provider:
            raise ModelExecutionAuthorizationError(
                "model execution authorization does not permit the selected provider binding"
            )
        self._validate_request_hashes(
            context_pack_hash=context_pack_hash,
            outbound_request_hash=outbound_request_hash,
        )
        if context_pack_hash != authorization.context_pack_hash:
            raise ModelExecutionAuthorizationError(
                "model execution authorization does not bind this ContextPack"
            )
        if outbound_request_hash != authorization.request_hash:
            raise ModelExecutionAuthorizationError(
                "model execution authorization does not bind this outbound request"
            )
        if (
            isinstance(requested_input_tokens, bool)
            or isinstance(requested_output_tokens, bool)
            or not isinstance(requested_input_tokens, int)
            or not isinstance(requested_output_tokens, int)
            or requested_input_tokens <= 0
            or requested_output_tokens <= 0
        ):
            raise ModelExecutionAuthorizationError(
                "requested token limits must be positive integers"
            )
        if requested_input_tokens > authorization.budget.max_input_tokens:
            raise ModelExecutionAuthorizationError(
                "requested input tokens exceed authorization budget"
            )
        if requested_output_tokens > authorization.budget.max_output_tokens:
            raise ModelExecutionAuthorizationError(
                "requested output tokens exceed authorization budget"
            )
        if requested_input_tokens + requested_output_tokens > authorization.budget.max_total_tokens:
            raise ModelExecutionAuthorizationError(
                "requested total tokens exceed authorization budget"
            )

    @classmethod
    def _validate_max_ttl_seconds(cls, max_ttl_seconds: float) -> float:
        if (
            isinstance(max_ttl_seconds, bool)
            or not isinstance(max_ttl_seconds, int | float)
            or not math.isfinite(max_ttl_seconds)
            or max_ttl_seconds <= 0
        ):
            raise ModelExecutionAuthorizationError(
                "model authorization max_ttl_seconds must be finite and positive"
            )
        if max_ttl_seconds > cls._HARD_MAX_TTL_SECONDS:
            raise ModelExecutionAuthorizationError(
                "model authorization max_ttl_seconds exceeds the one-hour hard cap"
            )
        return float(max_ttl_seconds)

    @classmethod
    def _validate_provider_failure_threshold(cls, value: int) -> int:
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or value < 1
            or value > cls._HARD_MAX_PROVIDER_FAILURE_THRESHOLD
        ):
            raise ModelExecutionAuthorizationError(
                "provider failure threshold must be an integer between 1 and 100"
            )
        return value

    @classmethod
    def _validate_provider_failure_cooldown_seconds(cls, value: float) -> float:
        if (
            isinstance(value, bool)
            or not isinstance(value, int | float)
            or not math.isfinite(value)
            or value < 1.0
            or value > cls._HARD_MAX_PROVIDER_FAILURE_COOLDOWN_SECONDS
        ):
            raise ModelExecutionAuthorizationError(
                "provider failure cooldown must be between 1 and 86400 seconds"
            )
        return float(value)

    @staticmethod
    def _validate_provider_failure_code(failure_code: str) -> None:
        if not isinstance(failure_code, str) or failure_code not in _PROVIDER_FAILURE_CODES:
            raise ModelExecutionAuthorizationError("provider failure code must be a stable V1 code")

    def _validate_ttl(self, ttl_seconds: float) -> None:
        if (
            isinstance(ttl_seconds, bool)
            or not isinstance(ttl_seconds, int | float)
            or not math.isfinite(ttl_seconds)
            or ttl_seconds <= 0
        ):
            raise ModelExecutionAuthorizationError(
                "authorization ttl_seconds must be finite and positive"
            )
        if ttl_seconds > self._max_ttl_seconds:
            raise ModelExecutionAuthorizationError(
                "authorization ttl_seconds exceeds the configured maximum of "
                f"{self._max_ttl_seconds:g} seconds"
            )

    @staticmethod
    def _validate_reason(reason: str) -> None:
        if not isinstance(reason, str) or not _REVOCATION_CODE.fullmatch(reason):
            raise ModelExecutionAuthorizationError("revocation reason must be a safe V1 code")

    def _stored_authorization(
        self,
        connection: sqlite3.Connection,
        authorization_id: str,
    ) -> ModelExecutionAuthorizationV1:
        row = connection.execute(
            """
            SELECT authorization_hash, authorization_json
            FROM model_execution_authorizations
            WHERE authorization_id = ?
            """,
            (authorization_id,),
        ).fetchone()
        if row is None:
            raise ModelExecutionAuthorizationError("model execution authorization is unknown")
        authorization = self._parse_authorization(str(row["authorization_json"]))
        if str(row["authorization_hash"]) != authorization.authorization_hash().value:
            raise ModelExecutionAuthorizationError(
                "stored model execution authorization hash is corrupt"
            )
        return authorization

    @staticmethod
    def _stored_provider_approval(
        connection: sqlite3.Connection,
        approval_id: str,
    ) -> ModelExecutionProviderApprovalV1:
        row = connection.execute(
            """
            SELECT approval_hash, approval_json
            FROM model_execution_provider_approvals
            WHERE approval_id = ?
            """,
            (approval_id,),
        ).fetchone()
        if row is None:
            raise ModelExecutionAuthorizationError(
                "model execution provider approval is not registered"
            )
        try:
            approval = ModelExecutionProviderApprovalV1.model_validate_json(
                str(row["approval_json"])
            )
        except Exception as error:
            raise ModelExecutionAuthorizationError(
                "stored model execution provider approval is corrupt"
            ) from error
        if (
            approval.approval_id.value != approval_id
            or str(row["approval_hash"]) != approval.approval_hash().value
        ):
            raise ModelExecutionAuthorizationError(
                "stored model execution provider approval hash is corrupt"
            )
        return approval

    def _stored_model_work(
        self,
        connection: sqlite3.Connection,
        bundle_id: str,
    ) -> _StoredModelWorkRegistration:
        row = connection.execute(
            """
            SELECT bundle_hash, bundle_json,
                   admission_attestation_hash, admission_attestation_json,
                   registration_request_hash
            FROM model_execution_work_bundles
            WHERE bundle_id = ?
            """,
            (bundle_id,),
        ).fetchone()
        if row is None:
            raise ModelExecutionAuthorizationError("model work bundle is not registered")
        try:
            bundle = ModelWorkBundleV2.model_validate_json(str(row["bundle_json"]))
            admission = AttestationV1.model_validate_json(str(row["admission_attestation_json"]))
        except Exception as error:
            raise ModelExecutionAuthorizationError(
                "stored model work bundle or admission is corrupt"
            ) from error
        admission_hash = self._model_work_admission_hash(admission)
        if (
            bundle.bundle_id.value != bundle_id
            or str(row["bundle_hash"]) != bundle.handoff_hash().value
            or str(row["admission_attestation_hash"]) != admission_hash
        ):
            raise ModelExecutionAuthorizationError(
                "stored model work bundle or admission hash is corrupt"
            )
        expected_registration_hash = request_hash(
            self._model_work_registration_request(
                bundle=bundle,
                admission_hash=admission_hash,
            )
        )
        if str(row["registration_request_hash"]) != expected_registration_hash:
            raise ModelExecutionAuthorizationError(
                "stored model work registration request hash is corrupt"
            )
        return _StoredModelWorkRegistration(
            bundle=bundle,
            admission=admission,
            admission_hash=admission_hash,
        )

    @staticmethod
    def _parse_authorization(serialized: str) -> ModelExecutionAuthorizationV1:
        try:
            return ModelExecutionAuthorizationV1.model_validate_json(serialized)
        except Exception as error:
            raise ModelExecutionAuthorizationError(
                "stored model execution authorization is corrupt"
            ) from error

    @staticmethod
    def _assert_same_capability(
        stored: ModelExecutionAuthorizationV1,
        supplied: ModelExecutionAuthorizationV1,
    ) -> None:
        if canonical_json(stored.model_dump(mode="json")) != canonical_json(
            supplied.model_dump(mode="json")
        ):
            raise ModelExecutionAuthorizationError(
                "supplied model execution authorization differs from the control-plane record"
            )

    def _assert_active(
        self,
        connection: sqlite3.Connection,
        authorization: ModelExecutionAuthorizationV1,
    ) -> None:
        if authorization.expires_at <= self._now():
            raise ModelExecutionAuthorizationError("model execution authorization has expired")
        if self._is_revoked(connection, authorization.authorization_id.value):
            raise ModelExecutionAuthorizationError("model execution authorization has been revoked")
        lease = authorization.lease
        try:
            self._control_plane.leases.assert_current(
                Lease(
                    job_id=lease.bundle_id.value,
                    holder_id=lease.worker_id,
                    fencing_token=lease.fencing_token,
                    expires_at=lease.expires_at,
                )
            )
        except StaleFence as error:
            raise ModelExecutionAuthorizationError(
                "model execution worker lease is stale or expired"
            ) from error

    @staticmethod
    def _assert_reservation_matches(
        reservation: ModelExecutionReservationV1,
        state: _ReservationState | None,
    ) -> None:
        if state is None:
            raise ModelExecutionAuthorizationError("model execution reservation is unknown")
        if (
            reservation.attempt_number != state.attempt_number
            or reservation.reserved_input_tokens != state.reserved_input_tokens
            or reservation.reserved_output_tokens != state.reserved_output_tokens
            or reservation.reserved_cost_microusd != state.reserved_cost_microusd
        ):
            raise ModelExecutionAuthorizationError(
                "model execution reservation differs from the control-plane ledger"
            )

    @staticmethod
    def _usage_totals(states: dict[str, _ReservationState]) -> _UsageTotals:
        input_tokens = 0
        output_tokens = 0
        cost_microusd = 0
        for state in states.values():
            if state.state == "abandoned":
                continue
            if state.state == "reserved":
                input_tokens += state.reserved_input_tokens
                output_tokens += state.reserved_output_tokens
                cost_microusd += state.reserved_cost_microusd
                continue
            if (
                state.actual_input_tokens is None
                or state.actual_output_tokens is None
                or state.actual_cost_microusd is None
            ):
                raise ModelExecutionAuthorizationError(
                    "settled authorization ledger row is corrupt"
                )
            input_tokens += state.actual_input_tokens
            output_tokens += state.actual_output_tokens
            cost_microusd += state.actual_cost_microusd
        return _UsageTotals(
            attempts=len(states),
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=input_tokens + output_tokens,
            cost_microusd=cost_microusd,
        )

    def _reservation_states(
        self,
        connection: sqlite3.Connection,
        authorization_id: str,
    ) -> dict[str, _ReservationState]:
        rows = connection.execute(
            """
            SELECT reservation_id, attempt_number, event_type,
                   reserved_input_tokens, reserved_output_tokens, reserved_cost_microusd,
                   actual_input_tokens, actual_cached_input_tokens,
                   actual_output_tokens, actual_cost_microusd, reason
            FROM model_execution_authorization_ledger
            WHERE authorization_id = ?
            ORDER BY event_sequence ASC
            """,
            (authorization_id,),
        ).fetchall()
        states: dict[str, _ReservationState] = {}
        for row in rows:
            event_type = str(row["event_type"])
            if event_type == "revoked":
                continue
            reservation_id = row["reservation_id"]
            if not isinstance(reservation_id, str) or not reservation_id:
                raise ModelExecutionAuthorizationError(
                    "authorization ledger has an invalid reservation"
                )
            if event_type == "reserved":
                if reservation_id in states:
                    raise ModelExecutionAuthorizationError("authorization ledger reserved twice")
                states[reservation_id] = _ReservationState(
                    reservation_id=reservation_id,
                    attempt_number=self._required_nonnegative_int(row, "attempt_number", minimum=1),
                    reserved_input_tokens=self._required_nonnegative_int(
                        row, "reserved_input_tokens", minimum=1
                    ),
                    reserved_output_tokens=self._required_nonnegative_int(
                        row, "reserved_output_tokens", minimum=1
                    ),
                    reserved_cost_microusd=self._required_nonnegative_int(
                        row, "reserved_cost_microusd"
                    ),
                    state="reserved",
                )
                continue
            state = states.get(reservation_id)
            if state is None or state.state != "reserved":
                raise ModelExecutionAuthorizationError("authorization ledger transition is invalid")
            if event_type == "abandoned":
                failure_code = row["reason"]
                if failure_code is not None:
                    if not isinstance(failure_code, str):
                        raise ModelExecutionAuthorizationError(
                            "authorization ledger has an invalid failure code"
                        )
                    self._validate_provider_failure_code(failure_code)
                states[reservation_id] = _ReservationState(
                    reservation_id=state.reservation_id,
                    attempt_number=state.attempt_number,
                    reserved_input_tokens=state.reserved_input_tokens,
                    reserved_output_tokens=state.reserved_output_tokens,
                    reserved_cost_microusd=state.reserved_cost_microusd,
                    state="abandoned",
                    failure_code=failure_code,
                )
                continue
            if event_type != "settled":
                raise ModelExecutionAuthorizationError("authorization ledger event is invalid")
            states[reservation_id] = _ReservationState(
                reservation_id=state.reservation_id,
                attempt_number=state.attempt_number,
                reserved_input_tokens=state.reserved_input_tokens,
                reserved_output_tokens=state.reserved_output_tokens,
                reserved_cost_microusd=state.reserved_cost_microusd,
                state="settled",
                actual_input_tokens=self._required_nonnegative_int(row, "actual_input_tokens"),
                actual_cached_input_tokens=self._required_nonnegative_int(
                    row, "actual_cached_input_tokens"
                ),
                actual_output_tokens=self._required_nonnegative_int(row, "actual_output_tokens"),
                actual_cost_microusd=self._required_nonnegative_int(row, "actual_cost_microusd"),
            )
        return states

    @staticmethod
    def _required_nonnegative_int(
        row: sqlite3.Row,
        key: str,
        *,
        minimum: int = 0,
    ) -> int:
        value = row[key]
        if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
            raise ModelExecutionAuthorizationError(f"authorization ledger has invalid {key}")
        return int(value)

    @staticmethod
    def _is_revoked(connection: sqlite3.Connection, authorization_id: str) -> bool:
        row = connection.execute(
            """
            SELECT 1
            FROM model_execution_authorization_ledger
            WHERE authorization_id = ? AND event_type = 'revoked'
            LIMIT 1
            """,
            (authorization_id,),
        ).fetchone()
        return row is not None

    def _append_ledger_event(
        self,
        connection: sqlite3.Connection,
        *,
        authorization_id: str,
        reservation_id: str | None,
        attempt_number: int | None,
        event_type: Literal["reserved", "settled", "abandoned", "revoked"],
        reserved_input_tokens: int | None = None,
        reserved_output_tokens: int | None = None,
        reserved_cost_microusd: int | None = None,
        actual_input_tokens: int | None = None,
        actual_cached_input_tokens: int | None = None,
        actual_output_tokens: int | None = None,
        actual_cost_microusd: int | None = None,
        reason: str | None = None,
    ) -> None:
        connection.execute(
            """
            INSERT INTO model_execution_authorization_ledger (
                event_id, authorization_id, reservation_id, attempt_number, event_type,
                reserved_input_tokens, reserved_output_tokens, reserved_cost_microusd,
                actual_input_tokens, actual_cached_input_tokens,
                actual_output_tokens, actual_cost_microusd, reason, recorded_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                authorization_id,
                reservation_id,
                attempt_number,
                event_type,
                reserved_input_tokens,
                reserved_output_tokens,
                reserved_cost_microusd,
                actual_input_tokens,
                actual_cached_input_tokens,
                actual_output_tokens,
                actual_cost_microusd,
                reason,
                self._timestamp(self._now()),
            ),
        )

    def _idempotent_authorization(
        self,
        connection: sqlite3.Connection,
        *,
        scope: str,
        key: str,
        request_digest: str,
    ) -> ModelExecutionAuthorizationV1 | None:
        row = connection.execute(
            """
            SELECT request_hash, authorization_id
            FROM model_execution_authorization_idempotency
            WHERE scope = ? AND key = ?
            """,
            (scope, key),
        ).fetchone()
        if row is None:
            return None
        if str(row["request_hash"]) != request_digest:
            raise ModelExecutionAuthorizationError(
                "model authorization idempotency key was reused for a different request"
            )
        return self._stored_authorization(connection, str(row["authorization_id"]))

    def _idempotent_provider_approval(
        self,
        connection: sqlite3.Connection,
        *,
        key: str,
        request_digest: str,
    ) -> ModelExecutionProviderApprovalV1 | None:
        row = connection.execute(
            """
            SELECT request_hash, approval_id
            FROM model_execution_provider_approval_idempotency
            WHERE key = ?
            """,
            (key,),
        ).fetchone()
        if row is None:
            return None
        if str(row["request_hash"]) != request_digest:
            raise ModelExecutionAuthorizationError(
                "provider approval idempotency key was reused for a different request"
            )
        return self._stored_provider_approval(connection, str(row["approval_id"]))

    def _idempotent_model_work(
        self,
        connection: sqlite3.Connection,
        *,
        key: str,
        request_digest: str,
    ) -> _StoredModelWorkRegistration | None:
        row = connection.execute(
            """
            SELECT request_hash, bundle_id
            FROM model_execution_work_idempotency
            WHERE key = ?
            """,
            (key,),
        ).fetchone()
        if row is None:
            return None
        if str(row["request_hash"]) != request_digest:
            raise ModelExecutionAuthorizationError(
                "model work idempotency key was reused for a different request"
            )
        return self._stored_model_work(connection, str(row["bundle_id"]))

    @staticmethod
    def _record_idempotency(
        connection: sqlite3.Connection,
        *,
        scope: str,
        key: str,
        request_digest: str,
        authorization_id: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO model_execution_authorization_idempotency (
                scope, key, request_hash, authorization_id
            ) VALUES (?, ?, ?, ?)
            """,
            (scope, key, request_digest, authorization_id),
        )

    @staticmethod
    def _record_provider_approval_idempotency(
        connection: sqlite3.Connection,
        *,
        key: str,
        request_digest: str,
        approval_id: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO model_execution_provider_approval_idempotency (
                key, request_hash, approval_id
            ) VALUES (?, ?, ?)
            """,
            (key, request_digest, approval_id),
        )

    @staticmethod
    def _record_model_work_idempotency(
        connection: sqlite3.Connection,
        *,
        key: str,
        request_digest: str,
        bundle_id: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO model_execution_work_idempotency (
                key, request_hash, bundle_id
            ) VALUES (?, ?, ?)
            """,
            (key, request_digest, bundle_id),
        )

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise ModelExecutionAuthorizationError(
                "model authorization clock returned a naive timestamp"
            )
        return value.astimezone(UTC)

    @staticmethod
    def _timestamp(value: datetime) -> str:
        return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
