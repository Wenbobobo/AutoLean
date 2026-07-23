"""Isolated authority boundary for verifier attestations.

This module is transport-neutral.  A production deployment must expose it behind an
operator-owned authenticated service and replace the test HMAC signer with KMS/HSM or an
equivalent non-exportable signing authority.  Neither the request contract nor this service's
durable ledger contains signing-key material.
"""

from __future__ import annotations

import hmac
import json
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime

from autolean_contracts import (
    AttestationError,
    AttestationPurposeV1,
    AttestationSignerV1,
    AttestationV1,
    AttestationVerifierV1,
    VerificationEvidenceArtifactV1,
    VerificationSigningContextV1,
    VerificationSigningRequestV1,
    verification_gateway_attestation_payload,
)

from .errors import (
    ArtifactCorruption,
    ArtifactNotFound,
    ControlPlaneError,
    StaleFence,
)
from .events import JsonObject, StoredEvent, canonical_json
from .service import ControlPlane, TaskBinding


class VerificationSigningGatewayError(ControlPlaneError):
    """Base class for a verifier signing request that did not produce authority."""


class VerificationSigningGatewayRejected(VerificationSigningGatewayError):
    """The request failed an immutable binding, expiry, or authority-policy check."""


class VerificationSigningGatewayReplay(VerificationSigningGatewayError):
    """A nonce, request, idempotency key, or canonical payload was reused inconsistently."""


class VerificationSigningGatewayUnavailable(VerificationSigningGatewayError):
    """The authority could not safely finish a request and therefore returned no signature."""


class VerifierSigningGateway:
    """Validate public verifier evidence bindings before invoking an isolated signer.

    The signer is reachable only from this authority object.  Prover code receives the
    ``issue`` method through a narrow client protocol and therefore never receives a key object.
    """

    _DEFAULT_MAX_TTL_SECONDS = 5.0 * 60.0
    _HARD_MAX_TTL_SECONDS = 15.0 * 60.0
    _SIGNING_EXPIRY_MARGIN_SECONDS = 1.0

    def __init__(
        self,
        *,
        control_plane: ControlPlane,
        signer: AttestationSignerV1,
        verifier: AttestationVerifierV1,
        clock: Callable[[], datetime] | None = None,
        max_ttl_seconds: float = _DEFAULT_MAX_TTL_SECONDS,
    ) -> None:
        if max_ttl_seconds <= 0 or max_ttl_seconds > self._HARD_MAX_TTL_SECONDS:
            raise ValueError("verifier gateway max TTL must be positive and at most 15 minutes")
        self._control_plane = control_plane
        self._events = control_plane.events
        self._signer = signer
        self._verifier = verifier
        self._clock = clock or (lambda: datetime.now(UTC))
        self._max_ttl_seconds = max_ttl_seconds
        self._initialize()

    def issue(self, request: VerificationSigningRequestV1) -> AttestationV1:
        """Return one lease-bound signature or fail closed without exposing authority material."""

        now = self._now()
        self._validate_request_time(request, now=now)
        self._assert_authoritative_binding(request)
        replay = self._reserve_request(request, now=now)
        if replay is not None:
            try:
                self._verifier.verify(
                    replay,
                    expected_purpose=AttestationPurposeV1.VERIFICATION,
                    payload=verification_gateway_attestation_payload(
                        lease=request.lease,
                        context=request.context,
                    ),
                )
            except AttestationError as error:
                raise VerificationSigningGatewayUnavailable(
                    "stored verification attestation no longer validates"
                ) from error
            self._validate_issued_attestation(request, replay)
            return replay

        payload = verification_gateway_attestation_payload(
            lease=request.lease,
            context=request.context,
        )
        ttl_seconds = (
            request.expires_at - now
        ).total_seconds() - self._SIGNING_EXPIRY_MARGIN_SECONDS
        if ttl_seconds <= 0:
            self._mark_failed(request, reason="insufficient_signing_ttl")
            raise VerificationSigningGatewayRejected(
                "verification signing request has insufficient remaining authority"
            )
        try:
            attestation = self._signer.issue(
                purpose=AttestationPurposeV1.VERIFICATION,
                payload=payload,
                evidence_identity=request.context.evidence_identity.value,
                ttl_seconds=ttl_seconds,
            )
            self._verifier.verify(
                attestation,
                expected_purpose=AttestationPurposeV1.VERIFICATION,
                payload=payload,
            )
            self._validate_issued_attestation(request, attestation)
            # A replacement lease racing with signing invalidates the response.
            self._assert_authoritative_binding(request)
        except (
            AttestationError,
            VerificationSigningGatewayError,
            StaleFence,
            ValueError,
        ) as error:
            self._mark_failed(request, reason="authority_unavailable_or_binding_changed")
            raise VerificationSigningGatewayUnavailable(
                "verifier signing authority did not issue a usable attestation"
            ) from error
        except Exception as error:
            # Transport/KMS adapters may raise implementation-specific exceptions.  Do not
            # persist their text because it can contain endpoint or credential metadata.
            self._mark_failed(request, reason="signer_unavailable")
            raise VerificationSigningGatewayUnavailable(
                "verifier signing authority is unavailable"
            ) from error

        self._record_issued(request, attestation)
        return attestation

    def _validate_request_time(
        self,
        request: VerificationSigningRequestV1,
        *,
        now: datetime,
    ) -> None:
        requested_at = request.requested_at.astimezone(UTC)
        expires_at = request.expires_at.astimezone(UTC)
        if requested_at > now:
            raise VerificationSigningGatewayRejected("verification signing request is from future")
        if expires_at <= now:
            raise VerificationSigningGatewayRejected("verification signing request has expired")
        if (expires_at - requested_at).total_seconds() > self._max_ttl_seconds:
            raise VerificationSigningGatewayRejected(
                "verification signing request exceeds the gateway TTL policy"
            )

    def _assert_authoritative_binding(self, request: VerificationSigningRequestV1) -> None:
        context = request.context
        lease_binding = request.lease
        if lease_binding.bundle_id != context.bundle_id:
            raise VerificationSigningGatewayRejected(
                "verification signing lease and context name different bundles"
            )
        current = self._control_plane.leases.current(context.bundle_id.value)
        if current is None:
            raise VerificationSigningGatewayRejected("verification signing lease is not current")
        if (
            current.holder_id != lease_binding.worker_id
            or current.fencing_token != lease_binding.fencing_token
            or current.expires_at.astimezone(UTC) != lease_binding.expires_at.astimezone(UTC)
        ):
            raise VerificationSigningGatewayRejected(
                "verification signing lease holder, fence, or expiry does not match"
            )
        if request.expires_at > current.expires_at:
            raise VerificationSigningGatewayRejected(
                "verification signing request outlives the authoritative lease"
            )
        binding = self._control_plane.get_binding(context.bundle_id.value)
        self._validate_task_binding(binding, context)
        proof_event = self._proof_event(context.proof_id.value)
        self._validate_proof_binding(context, proof_event.payload)
        artifact = self._read_evidence_artifact(context.evidence_artifact_digest)
        self._validate_evidence_binding(binding, context, artifact)

    @staticmethod
    def _validate_task_binding(
        binding: TaskBinding,
        context: VerificationSigningContextV1,
    ) -> None:
        checks = (
            (binding.bundle_id == context.bundle_id.value, "bundle ID"),
            (binding.bundle_hash == context.bundle_hash.value, "bundle hash"),
            (binding.contract_id == context.contract_id.value, "contract ID"),
            (binding.revision == context.revision, "contract revision"),
            (binding.contract_hash == context.contract_hash.value, "contract hash"),
            (
                binding.proof_boundary_hash == context.proof_boundary_hash.value,
                "proof boundary",
            ),
            (binding.environment_hash == context.environment_hash.value, "environment"),
        )
        for passed, label in checks:
            if not passed:
                raise VerificationSigningGatewayRejected(
                    f"verification signing context has a different {label}"
                )

    def _proof_event(self, proof_id: str) -> StoredEvent:
        events = self._control_plane.events.read_stream("proof", proof_id)
        event = next((item for item in events if item.event_type == "proof.submitted"), None)
        if event is None:
            raise VerificationSigningGatewayRejected(
                "verification signing proof has not been submitted"
            )
        return event

    @staticmethod
    def _validate_proof_binding(
        context: VerificationSigningContextV1,
        payload: JsonObject,
    ) -> None:
        proof_artifact = payload.get("proof_artifact")
        proof_digest = proof_artifact.get("digest") if isinstance(proof_artifact, dict) else None
        checks = (
            (payload.get("bundle_id") == context.bundle_id.value, "bundle ID"),
            (payload.get("proof_id") == context.proof_id.value, "proof ID"),
            (payload.get("contract_id") == context.contract_id.value, "contract ID"),
            (payload.get("revision") == context.revision, "contract revision"),
            (payload.get("contract_hash") == context.contract_hash.value, "contract hash"),
            (
                payload.get("proof_boundary_hash") == context.proof_boundary_hash.value,
                "proof boundary",
            ),
            (
                payload.get("environment_hash") == context.environment_hash.value,
                "environment",
            ),
            (
                payload.get("dependency_manifest_hash") == context.dependency_manifest_hash.value,
                "dependency manifest",
            ),
            (
                proof_digest == context.proof_submission_artifact_digest,
                "proof artifact digest",
            ),
        )
        for passed, label in checks:
            if not passed:
                raise VerificationSigningGatewayRejected(
                    f"verification signing proof has a different {label}"
                )

    def _read_evidence_artifact(self, digest: str) -> VerificationEvidenceArtifactV1:
        try:
            raw = self._control_plane.artifacts.get_bytes(digest)
        except (ArtifactCorruption, ArtifactNotFound) as error:
            raise VerificationSigningGatewayRejected(
                "verification signing evidence artifact is unavailable or corrupt"
            ) from error
        try:
            parsed = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=self._unique_json_object,
                parse_constant=self._reject_json_constant,
            )
            if not isinstance(parsed, dict):
                raise ValueError("evidence artifact is not an object")
            if canonical_json(parsed).encode("utf-8") != raw:
                raise ValueError("evidence artifact is not canonical JSON")
            artifact = VerificationEvidenceArtifactV1.model_validate(parsed)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise VerificationSigningGatewayRejected(
                "verification signing evidence artifact is not canonical V1 JSON"
            ) from error
        if canonical_json(artifact.model_dump(mode="json")).encode("utf-8") != raw:
            raise VerificationSigningGatewayRejected(
                "verification signing evidence artifact was normalized during validation"
            )
        return artifact

    @staticmethod
    def _validate_evidence_binding(
        binding: TaskBinding,
        context: VerificationSigningContextV1,
        artifact: VerificationEvidenceArtifactV1,
    ) -> None:
        checks = (
            (artifact.evidence_id == context.evidence_identity, "evidence identity"),
            (artifact.bundle_id == context.bundle_id, "bundle ID"),
            (artifact.bundle_hash == context.bundle_hash, "bundle hash"),
            (artifact.contract_id == context.contract_id, "contract ID"),
            (artifact.revision == context.revision, "contract revision"),
            (artifact.contract_hash == context.contract_hash, "contract hash"),
            (artifact.proof_id == context.proof_id, "proof ID"),
            (
                artifact.proof_boundary_hash == context.proof_boundary_hash,
                "proof boundary",
            ),
            (
                artifact.proof_submission_artifact_digest
                == context.proof_submission_artifact_digest,
                "proof artifact digest",
            ),
            (
                artifact.dependency_manifest_hash == context.dependency_manifest_hash,
                "dependency manifest",
            ),
            (artifact.verification_report_id == context.report_id, "report ID"),
            (
                artifact.environment.environment_hash == context.environment_hash,
                "environment",
            ),
            (
                artifact.oci.worker_image_digest == binding.worker_image_digest,
                "worker image",
            ),
            (
                artifact.oci.wrapper_protocol == binding.wrapper_protocol,
                "wrapper protocol",
            ),
            (
                artifact.oci.command_policy_hash.value == binding.command_policy_hash,
                "command policy",
            ),
        )
        for passed, label in checks:
            if not passed:
                raise VerificationSigningGatewayRejected(
                    f"verification signing evidence has a different {label}"
                )

    def _reserve_request(
        self,
        request: VerificationSigningRequestV1,
        *,
        now: datetime,
    ) -> AttestationV1 | None:
        request_hash = request.request_hash().value
        with self._events.write_transaction() as connection:
            existing = connection.execute(
                """
                SELECT request_hash, state, attestation_json
                FROM verifier_signing_requests
                WHERE idempotency_key = ?
                """,
                (request.idempotency_key,),
            ).fetchone()
            if existing is not None:
                if not hmac.compare_digest(str(existing["request_hash"]), request_hash):
                    raise VerificationSigningGatewayReplay(
                        "verification signing idempotency key was reused for another request"
                    )
                if str(existing["state"]) != "issued" or existing["attestation_json"] is None:
                    raise VerificationSigningGatewayUnavailable(
                        "verification signing request did not reach an issued state"
                    )
                try:
                    return AttestationV1.model_validate_json(str(existing["attestation_json"]))
                except ValueError as error:
                    raise VerificationSigningGatewayUnavailable(
                        "stored verification attestation is malformed"
                    ) from error
            try:
                connection.execute(
                    """
                    INSERT INTO verifier_signing_requests (
                        request_id, request_nonce, idempotency_key, request_hash,
                        canonical_payload_hash, bundle_id, proof_id, fencing_token,
                        evidence_artifact_digest, state, reserved_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
                    """,
                    (
                        request.request_id.value,
                        request.request_nonce,
                        request.idempotency_key,
                        request_hash,
                        request.canonical_payload_hash.value,
                        request.context.bundle_id.value,
                        request.context.proof_id.value,
                        request.lease.fencing_token,
                        request.context.evidence_artifact_digest,
                        self._timestamp(now),
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise VerificationSigningGatewayReplay(
                    "verification signing request, nonce, or canonical payload was replayed"
                ) from error
        return None

    def _record_issued(
        self,
        request: VerificationSigningRequestV1,
        attestation: AttestationV1,
    ) -> None:
        serialized = canonical_json(attestation.model_dump(mode="json"))
        with self._events.write_transaction() as connection:
            updated = connection.execute(
                """
                UPDATE verifier_signing_requests
                SET state = 'issued', attestation_json = ?, completed_at = ?
                WHERE request_id = ? AND state = 'pending'
                """,
                (
                    serialized,
                    self._timestamp(self._now()),
                    request.request_id.value,
                ),
            )
            if updated.rowcount != 1:
                raise VerificationSigningGatewayUnavailable(
                    "verification signing ledger changed before issuance completed"
                )

    def _mark_failed(self, request: VerificationSigningRequestV1, *, reason: str) -> None:
        with self._events.write_transaction() as connection:
            connection.execute(
                """
                UPDATE verifier_signing_requests
                SET state = 'failed', failure_code = ?, completed_at = ?
                WHERE request_id = ? AND state = 'pending'
                """,
                (
                    reason,
                    self._timestamp(self._now()),
                    request.request_id.value,
                ),
            )

    def _validate_issued_attestation(
        self,
        request: VerificationSigningRequestV1,
        attestation: AttestationV1,
    ) -> None:
        if attestation.purpose is not AttestationPurposeV1.VERIFICATION:
            raise VerificationSigningGatewayUnavailable(
                "verifier gateway returned a different attestation purpose"
            )
        if attestation.evidence_identity != request.context.evidence_identity.value:
            raise VerificationSigningGatewayUnavailable(
                "verifier gateway returned a different evidence identity"
            )
        if not hmac.compare_digest(
            attestation.payload_hash.value,
            request.canonical_payload_hash.value,
        ):
            raise VerificationSigningGatewayUnavailable(
                "verifier gateway returned a different canonical payload hash"
            )
        if attestation.expires_at > request.expires_at:
            raise VerificationSigningGatewayUnavailable(
                "verifier gateway attestation outlives its request or lease"
            )

    def _initialize(self) -> None:
        with self._events.connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS verifier_signing_requests (
                    request_id TEXT PRIMARY KEY,
                    request_nonce TEXT NOT NULL UNIQUE,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    request_hash TEXT NOT NULL,
                    canonical_payload_hash TEXT NOT NULL UNIQUE,
                    bundle_id TEXT NOT NULL,
                    proof_id TEXT NOT NULL,
                    fencing_token INTEGER NOT NULL CHECK (fencing_token > 0),
                    evidence_artifact_digest TEXT NOT NULL,
                    state TEXT NOT NULL CHECK (state IN ('pending', 'issued', 'failed')),
                    attestation_json TEXT,
                    failure_code TEXT,
                    reserved_at TEXT NOT NULL,
                    completed_at TEXT
                ) WITHOUT ROWID;
                """
            )

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise VerificationSigningGatewayUnavailable(
                "verifier signing gateway clock returned a naive timestamp"
            )
        return value.astimezone(UTC)

    @staticmethod
    def _timestamp(value: datetime) -> str:
        return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")

    @staticmethod
    def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    @staticmethod
    def _reject_json_constant(value: str) -> object:
        raise ValueError(f"non-standard JSON constant: {value}")
