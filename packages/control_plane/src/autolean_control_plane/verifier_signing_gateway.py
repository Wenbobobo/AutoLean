"""Isolated authority boundary for verifier attestations.

This module is transport-neutral.  A production deployment must expose it behind an
operator-owned authenticated service and replace the test HMAC signer with KMS/HSM or an
equivalent non-exportable signing authority.  Neither the request contract nor this service's
durable ledger contains signing-key material.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import sqlite3
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from dataclasses import replace as dataclass_replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import ClassVar, Protocol, runtime_checkable

from autolean_contracts import (
    AttestationError,
    AttestationPurposeV1,
    AttestationSignerV1,
    AttestationV1,
    AttestationVerifierV1,
    VerificationEvidenceArtifactV2,
    VerificationSigningContextV1,
    VerificationSigningLeaseBindingV1,
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


class ProductionAuthorityUnavailable(VerificationSigningGatewayUnavailable):
    """Local Python composition can never instantiate production verification authority."""


class IndependentExecutionClassV1(StrEnum):
    """Whether a verifier identity is an isolated production authority or a fixture."""

    PRODUCTION = "production"
    TEST_ONLY = "test-only"


@dataclass(frozen=True, slots=True)
class IndependentExecutionReceiptAuthenticationV1:
    """Non-secret authentication envelope over one independent execution receipt hash."""

    key_id: str
    algorithm: str
    authenticated_receipt_hash: str
    signature: str

    def validate(self) -> None:
        checks = (
            ("key ID", self.key_id, r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$"),
            ("algorithm", self.algorithm, r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"),
            ("receipt hash", self.authenticated_receipt_hash, r"^[0-9a-f]{64}$"),
            ("signature", self.signature, r"^[0-9a-f]{64,512}$"),
        )
        for label, value, pattern in checks:
            if re.fullmatch(pattern, value) is None:
                raise ValueError(f"independent execution receipt authentication {label} is invalid")


@dataclass(frozen=True, slots=True)
class IndependentExecutionReceiptV1:
    """Public, hash-bound record of a second verifier's execution check.

    This is deliberately not an attestation and does not introduce another signing purpose.
    The isolated verifier service is responsible for returning this receipt over its own
    authenticated boundary; the gateway stores only its public identity and binding hash.
    """

    receipt_id: str
    verifier_id: str
    checked_at: datetime
    request_hash: str
    evidence_artifact_digest: str
    evidence_digest: str
    execution_claim_hash: str
    receipt_hash: str
    authentication: IndependentExecutionReceiptAuthenticationV1 | None = None

    @classmethod
    def create(
        cls,
        *,
        receipt_id: str,
        verifier_id: str,
        checked_at: datetime,
        request_hash: str,
        evidence_artifact_digest: str,
        evidence_digest: str,
        execution_claim_hash: str,
    ) -> IndependentExecutionReceiptV1:
        timestamp = cls._timestamp(checked_at)
        payload = {
            "schema_version": "autolean.independent-execution-receipt.v1",
            "receipt_id": receipt_id,
            "verifier_id": verifier_id,
            "checked_at": timestamp,
            "request_hash": request_hash,
            "evidence_artifact_digest": evidence_artifact_digest,
            "evidence_digest": evidence_digest,
            "execution_claim_hash": execution_claim_hash,
        }
        return cls(
            receipt_id=receipt_id,
            verifier_id=verifier_id,
            checked_at=checked_at,
            request_hash=request_hash,
            evidence_artifact_digest=evidence_artifact_digest,
            evidence_digest=evidence_digest,
            execution_claim_hash=execution_claim_hash,
            receipt_hash=hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest(),
        )

    def validate(self) -> None:
        if self.checked_at.tzinfo is None:
            raise ValueError("independent execution receipt timestamp must be timezone-aware")
        for label, value, pattern in (
            ("receipt ID", self.receipt_id, r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$"),
            ("verifier ID", self.verifier_id, r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$"),
            ("request hash", self.request_hash, r"^[0-9a-f]{64}$"),
            ("evidence artifact digest", self.evidence_artifact_digest, r"^[0-9a-f]{64}$"),
            ("evidence digest", self.evidence_digest, r"^[0-9a-f]{64}$"),
            ("execution claim hash", self.execution_claim_hash, r"^[0-9a-f]{64}$"),
            ("receipt hash", self.receipt_hash, r"^[0-9a-f]{64}$"),
        ):
            if re.fullmatch(pattern, value) is None:
                raise ValueError(f"independent execution receipt {label} is invalid")
        expected = self.create(
            receipt_id=self.receipt_id,
            verifier_id=self.verifier_id,
            checked_at=self.checked_at,
            request_hash=self.request_hash,
            evidence_artifact_digest=self.evidence_artifact_digest,
            evidence_digest=self.evidence_digest,
            execution_claim_hash=self.execution_claim_hash,
        )
        if not hmac.compare_digest(self.receipt_hash, expected.receipt_hash):
            raise ValueError("independent execution receipt hash does not match its public fields")
        if self.authentication is not None:
            self.authentication.validate()
            if not hmac.compare_digest(
                self.authentication.authenticated_receipt_hash,
                self.receipt_hash,
            ):
                raise ValueError(
                    "independent execution receipt authentication binds another receipt hash"
                )

    @staticmethod
    def _timestamp(value: datetime) -> str:
        if value.tzinfo is None:
            raise ValueError("independent execution receipt timestamp must be timezone-aware")
        return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


@runtime_checkable
class IndependentExecutionReceiptAuthenticator(Protocol):
    """Verify a non-secret receipt envelope under one independently configured identity."""

    def verify(self, receipt: IndependentExecutionReceiptV1) -> None: ...


@dataclass(frozen=True, slots=True)
class FixtureHmacIndependentExecutionReceiptAuthenticator:
    """HMAC fixture adapter. Production deployments must provide a different authenticator."""

    key_id: str
    secret: bytes = field(repr=False, compare=False)

    _ALGORITHM = "hmac-sha256-test-v1"
    execution_class: ClassVar[IndependentExecutionClassV1] = IndependentExecutionClassV1.TEST_ONLY

    def __post_init__(self) -> None:
        if re.fullmatch(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$", self.key_id) is None:
            raise ValueError("independent receipt key ID is invalid")
        if len(self.secret) < 32:
            raise ValueError("independent receipt HMAC secret must contain at least 32 bytes")

    def authenticate(
        self,
        receipt: IndependentExecutionReceiptV1,
    ) -> IndependentExecutionReceiptV1:
        receipt.validate()
        envelope = IndependentExecutionReceiptAuthenticationV1(
            key_id=self.key_id,
            algorithm=self._ALGORITHM,
            authenticated_receipt_hash=receipt.receipt_hash,
            signature=self._signature(receipt),
        )
        return dataclass_replace(receipt, authentication=envelope)

    def verify(self, receipt: IndependentExecutionReceiptV1) -> None:
        receipt.validate()
        authentication = receipt.authentication
        if authentication is None:
            raise ValueError("independent execution receipt is unauthenticated")
        if (
            authentication.key_id != self.key_id
            or authentication.algorithm != self._ALGORITHM
            or not hmac.compare_digest(authentication.signature, self._signature(receipt))
        ):
            raise ValueError("independent execution receipt authentication does not verify")

    def _signature(self, receipt: IndependentExecutionReceiptV1) -> str:
        return hmac.digest(
            self.secret,
            canonical_json(
                {
                    "schema_version": "autolean.independent-execution-receipt-auth.v1",
                    "algorithm": self._ALGORITHM,
                    "key_id": self.key_id,
                    "verifier_id": receipt.verifier_id,
                    "receipt_hash": receipt.receipt_hash,
                }
            ).encode("utf-8"),
            "sha256",
        ).hex()


@dataclass(frozen=True, slots=True)
class TrustedIndependentExecutionVerifierV1:
    """One verifier identity and the key configured to authenticate its receipts."""

    verifier_id: str
    authentication_key_id: str
    execution_class: IndependentExecutionClassV1
    authenticator: IndependentExecutionReceiptAuthenticator

    def __post_init__(self) -> None:
        for label, value in (
            ("verifier ID", self.verifier_id),
            ("authentication key ID", self.authentication_key_id),
        ):
            if re.fullmatch(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$", value) is None:
                raise ValueError(f"trusted independent verifier {label} is invalid")
        if not isinstance(self.authenticator, IndependentExecutionReceiptAuthenticator):
            raise TypeError("trusted independent verifier requires a receipt authenticator")


@dataclass(frozen=True, slots=True)
class IndependentExecutionTrustPolicyV1:
    """Fail-closed verifier trust roots and explicit execution-class boundary."""

    gateway_signing_key_id: str
    execution_class: IndependentExecutionClassV1
    trusted_verifiers: Mapping[str, TrustedIndependentExecutionVerifierV1]

    def __post_init__(self) -> None:
        key_id_pattern = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$"
        if re.fullmatch(key_id_pattern, self.gateway_signing_key_id) is None:
            raise ValueError("gateway signing key ID is invalid")
        trusted = dict(self.trusted_verifiers)
        if not trusted:
            raise ValueError("independent execution trust policy requires a verifier allowlist")
        for verifier_id, identity in trusted.items():
            if verifier_id != identity.verifier_id:
                raise ValueError("independent verifier allowlist keys must match verifier IDs")
            if identity.authentication_key_id == self.gateway_signing_key_id:
                raise ValueError(
                    "independent verifier authentication key must differ from gateway signing key"
                )
            if (
                self.execution_class is IndependentExecutionClassV1.PRODUCTION
                and identity.execution_class is not IndependentExecutionClassV1.PRODUCTION
            ):
                raise ValueError("production authority cannot trust a test-only execution verifier")
            if (
                self.execution_class is IndependentExecutionClassV1.PRODUCTION
                and getattr(identity.authenticator, "execution_class", None)
                is not IndependentExecutionClassV1.PRODUCTION
            ):
                raise ValueError(
                    "production authority requires an explicitly production-class receipt key"
                )
        object.__setattr__(self, "trusted_verifiers", trusted)

    def authenticate(self, receipt: IndependentExecutionReceiptV1) -> None:
        authentication = receipt.authentication
        if authentication is None:
            raise ValueError("independent execution receipt is unauthenticated")
        identity = self.trusted_verifiers.get(receipt.verifier_id)
        if identity is None:
            raise ValueError("independent execution receipt verifier ID is not allowlisted")
        if authentication.key_id != identity.authentication_key_id:
            raise ValueError("independent execution receipt uses an untrusted authentication key")
        identity.authenticator.verify(receipt)


@runtime_checkable
class IndependentExecutionVerifier(Protocol):
    """Independently re-run and inspect one canonical V2 OCI verification artifact."""

    def verify(
        self,
        *,
        request: VerificationSigningRequestV1,
        artifact: VerificationEvidenceArtifactV2,
    ) -> IndependentExecutionReceiptV1: ...


@dataclass(frozen=True, slots=True)
class _IssuedRequestReplay:
    attestation: AttestationV1
    receipt: IndependentExecutionReceiptV1


class VerifierSigningGateway:
    """Validate public verifier evidence bindings before invoking an isolated signer.

    The signer is reachable only from this authority object.  Prover code receives the
    ``issue`` method through a narrow client protocol and therefore never receives a key object.
    """

    _DEFAULT_MAX_TTL_SECONDS = 5.0 * 60.0
    _HARD_MAX_TTL_SECONDS = 15.0 * 60.0
    _SIGNING_EXPIRY_MARGIN_SECONDS = 1.0
    _SHA256 = re.compile(r"^[0-9a-f]{64}$")

    def __init__(
        self,
        *,
        control_plane: ControlPlane,
        signer: AttestationSignerV1,
        verifier: AttestationVerifierV1,
        independent_execution_verifier: IndependentExecutionVerifier,
        independent_execution_trust_policy: IndependentExecutionTrustPolicyV1,
        approved_image_identities: Mapping[str, str],
        clock: Callable[[], datetime] | None = None,
        max_ttl_seconds: float = _DEFAULT_MAX_TTL_SECONDS,
    ) -> None:
        if max_ttl_seconds <= 0 or max_ttl_seconds > self._HARD_MAX_TTL_SECONDS:
            raise ValueError("verifier gateway max TTL must be positive and at most 15 minutes")
        self._control_plane = control_plane
        self._events = control_plane.events
        self._signer = signer
        self._verifier = verifier
        if not isinstance(independent_execution_verifier, IndependentExecutionVerifier):
            raise TypeError("verifier gateway requires an independent execution verifier")
        if not isinstance(independent_execution_trust_policy, IndependentExecutionTrustPolicyV1):
            raise TypeError("verifier gateway requires an independent execution trust policy")
        if (
            independent_execution_trust_policy.execution_class
            is IndependentExecutionClassV1.PRODUCTION
        ):
            raise ProductionAuthorityUnavailable(
                "production verifier authority requires a future independent remote service"
            )
        self._independent_execution_verifier = independent_execution_verifier
        self._independent_execution_trust_policy = independent_execution_trust_policy
        identities = dict(approved_image_identities)
        if not identities:
            raise ValueError("verifier gateway requires an approved image identity registry")
        for image_digest, identity_hash in identities.items():
            if re.fullmatch(r"^sha256:[0-9a-f]{64}$", image_digest) is None:
                raise ValueError("approved verifier image digest is invalid")
            if self._SHA256.fullmatch(identity_hash) is None:
                raise ValueError("approved verifier identity hash is invalid")
        self._approved_image_identities = identities
        self._clock = clock or (lambda: datetime.now(UTC))
        self._max_ttl_seconds = max_ttl_seconds
        self._initialize()

    def issue(self, request: VerificationSigningRequestV1) -> AttestationV1:
        """Return one lease-bound signature or fail closed without exposing authority material."""

        if (
            self._independent_execution_trust_policy.execution_class
            is IndependentExecutionClassV1.PRODUCTION
        ):
            raise ProductionAuthorityUnavailable(
                "local verifier signing gateway cannot issue production authority"
            )
        now = self._now()
        self._validate_request_time(request, now=now)
        artifact = self._assert_authoritative_binding(request)
        replay = self._load_issued_replay(request, artifact)
        if replay is not None:
            self._validate_issued_replay(request, artifact, replay)
            return replay.attestation

        execution_receipt = self._independently_verify_execution(request, artifact)
        # A lease replacement or artifact substitution while the second verifier was running
        # invalidates the result before it can reserve or sign anything.
        artifact = self._assert_authoritative_binding(request)
        self._validate_execution_receipt(request, artifact, execution_receipt)
        replay = self._reserve_request(request, receipt=execution_receipt, now=now)
        if replay is not None:
            self._validate_issued_replay(request, artifact, replay)
            return replay.attestation

        payload = verification_gateway_attestation_payload(
            lease=request.lease,
            context=request.context,
        )
        signing_now = self._now()
        try:
            self._validate_request_time(request, now=signing_now)
        except VerificationSigningGatewayRejected:
            self._mark_failed(request, reason="request_expired_before_signing")
            raise
        ttl_seconds = (
            request.expires_at - signing_now
        ).total_seconds() - self._SIGNING_EXPIRY_MARGIN_SECONDS
        if ttl_seconds <= 0:
            self._mark_failed(request, reason="insufficient_signing_ttl")
            raise VerificationSigningGatewayRejected(
                "verification signing request has insufficient remaining authority"
            )
        try:
            self._assert_authoritative_binding(request)
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

    def _assert_authoritative_binding(
        self,
        request: VerificationSigningRequestV1,
    ) -> VerificationEvidenceArtifactV2:
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
        self._validate_evidence_binding(binding, context, request.lease, artifact)
        return artifact

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

    def _read_evidence_artifact(self, digest: str) -> VerificationEvidenceArtifactV2:
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
            artifact = VerificationEvidenceArtifactV2.model_validate(parsed)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise VerificationSigningGatewayRejected(
                "verification signing evidence artifact is not canonical V2 JSON"
            ) from error
        if canonical_json(artifact.model_dump(mode="json")).encode("utf-8") != raw:
            raise VerificationSigningGatewayRejected(
                "verification signing evidence artifact was normalized during validation"
            )
        return artifact

    def _validate_evidence_binding(
        self,
        binding: TaskBinding,
        context: VerificationSigningContextV1,
        lease: VerificationSigningLeaseBindingV1,
        artifact: VerificationEvidenceArtifactV2,
    ) -> None:
        authority = artifact.oci.execution_authority
        approved_identity = self._approved_image_identities.get(binding.worker_image_digest)
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
            (authority.worker_id == lease.worker_id, "execution lease holder"),
            (authority.fencing_token == lease.fencing_token, "execution lease fence"),
            (
                authority.expires_at.astimezone(UTC) == lease.expires_at.astimezone(UTC),
                "execution lease expiry",
            ),
            (approved_identity is not None, "approved image identity"),
            (
                approved_identity is not None
                and hmac.compare_digest(authority.wrapper_identity_hash, approved_identity),
                "image-owned verifier identity",
            ),
        )
        for passed, label in checks:
            if not passed:
                raise VerificationSigningGatewayRejected(
                    f"verification signing evidence has a different {label}"
                )

    def _independently_verify_execution(
        self,
        request: VerificationSigningRequestV1,
        artifact: VerificationEvidenceArtifactV2,
    ) -> IndependentExecutionReceiptV1:
        """Ask the isolated execution verifier to re-run the exact canonical candidate."""

        try:
            receipt = self._independent_execution_verifier.verify(
                request=request,
                artifact=artifact,
            )
        except VerificationSigningGatewayError:
            raise
        except Exception as error:
            # The receipt service may be unavailable or its isolated runner may fail.  Its
            # implementation-specific exception text must never reach the durable ledger.
            raise VerificationSigningGatewayUnavailable(
                "independent execution verifier is unavailable"
            ) from error
        self._validate_execution_receipt(request, artifact, receipt)
        return receipt

    def _validate_execution_receipt(
        self,
        request: VerificationSigningRequestV1,
        artifact: VerificationEvidenceArtifactV2,
        receipt: IndependentExecutionReceiptV1,
    ) -> None:
        if not isinstance(receipt, IndependentExecutionReceiptV1):
            raise VerificationSigningGatewayRejected(
                "independent execution verifier returned an invalid receipt"
            )
        try:
            receipt.validate()
            self._independent_execution_trust_policy.authenticate(receipt)
        except ValueError as error:
            raise VerificationSigningGatewayRejected(
                "independent execution receipt is malformed, unauthenticated, or untrusted"
            ) from error
        checked_at = receipt.checked_at.astimezone(UTC)
        requested_at = request.requested_at.astimezone(UTC)
        current_time = self._now()
        if checked_at < requested_at:
            raise VerificationSigningGatewayRejected(
                "independent execution receipt predates its signing request"
            )
        if checked_at > request.lease.expires_at.astimezone(UTC):
            raise VerificationSigningGatewayRejected(
                "independent execution receipt outlives its execution lease"
            )
        if checked_at > current_time:
            raise VerificationSigningGatewayRejected(
                "independent execution receipt is from the future"
            )
        checks = (
            (
                hmac.compare_digest(receipt.request_hash, request.request_hash().value),
                "request hash",
            ),
            (
                hmac.compare_digest(
                    receipt.evidence_artifact_digest,
                    request.context.evidence_artifact_digest,
                ),
                "evidence artifact digest",
            ),
            (
                hmac.compare_digest(
                    receipt.evidence_digest,
                    request.context.verification_evidence_hash.value,
                ),
                "evidence digest",
            ),
            (
                hmac.compare_digest(
                    receipt.execution_claim_hash,
                    artifact.oci.execution_authority.execution_claim_hash,
                ),
                "execution claim hash",
            ),
        )
        for passed, label in checks:
            if not passed:
                raise VerificationSigningGatewayRejected(
                    f"independent execution receipt has a different {label}"
                )

    def _load_issued_replay(
        self,
        request: VerificationSigningRequestV1,
        artifact: VerificationEvidenceArtifactV2,
    ) -> _IssuedRequestReplay | None:
        request_hash = request.request_hash().value
        with self._events.connection() as connection:
            existing = connection.execute(
                """
                SELECT request_hash, state, attestation_json, evidence_artifact_digest,
                       execution_receipt_id, execution_receipt_hash, execution_verifier_id,
                       execution_checked_at, execution_claim_hash,
                       execution_receipt_authentication_key_id,
                       execution_receipt_authentication_algorithm,
                       execution_receipt_authentication_signature
                FROM verifier_signing_requests
                WHERE idempotency_key = ?
                """,
                (request.idempotency_key,),
            ).fetchone()
        if existing is None:
            return None
        if not hmac.compare_digest(str(existing["request_hash"]), request_hash):
            raise VerificationSigningGatewayReplay(
                "verification signing idempotency key was reused for another request"
            )
        if str(existing["state"]) != "issued" or existing["attestation_json"] is None:
            raise VerificationSigningGatewayUnavailable(
                "verification signing request did not reach an issued state"
            )
        try:
            attestation = AttestationV1.model_validate_json(str(existing["attestation_json"]))
            receipt = self._receipt_from_ledger(request, artifact, existing)
        except ValueError as error:
            raise VerificationSigningGatewayUnavailable(
                "stored verification attestation or execution receipt is malformed"
            ) from error
        return _IssuedRequestReplay(attestation=attestation, receipt=receipt)

    def _receipt_from_ledger(
        self,
        request: VerificationSigningRequestV1,
        artifact: VerificationEvidenceArtifactV2,
        row: sqlite3.Row,
    ) -> IndependentExecutionReceiptV1:
        values = (
            row["execution_receipt_id"],
            row["execution_receipt_hash"],
            row["execution_verifier_id"],
            row["execution_checked_at"],
            row["execution_claim_hash"],
            row["execution_receipt_authentication_key_id"],
            row["execution_receipt_authentication_algorithm"],
            row["execution_receipt_authentication_signature"],
        )
        if any(value is None for value in values):
            raise ValueError("issued verifier signing request has no persisted execution receipt")
        if not hmac.compare_digest(
            str(row["evidence_artifact_digest"]), request.context.evidence_artifact_digest
        ):
            raise ValueError("issued verifier signing request has another evidence artifact")
        checked_at = datetime.fromisoformat(str(row["execution_checked_at"]).replace("Z", "+00:00"))
        return IndependentExecutionReceiptV1(
            receipt_id=str(row["execution_receipt_id"]),
            verifier_id=str(row["execution_verifier_id"]),
            checked_at=checked_at,
            request_hash=request.request_hash().value,
            evidence_artifact_digest=request.context.evidence_artifact_digest,
            evidence_digest=request.context.verification_evidence_hash.value,
            execution_claim_hash=str(row["execution_claim_hash"]),
            receipt_hash=str(row["execution_receipt_hash"]),
            authentication=IndependentExecutionReceiptAuthenticationV1(
                key_id=str(row["execution_receipt_authentication_key_id"]),
                algorithm=str(row["execution_receipt_authentication_algorithm"]),
                authenticated_receipt_hash=str(row["execution_receipt_hash"]),
                signature=str(row["execution_receipt_authentication_signature"]),
            ),
        )

    def _validate_issued_replay(
        self,
        request: VerificationSigningRequestV1,
        artifact: VerificationEvidenceArtifactV2,
        replay: _IssuedRequestReplay,
    ) -> None:
        try:
            self._verifier.verify(
                replay.attestation,
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
        self._validate_issued_attestation(request, replay.attestation)
        self._validate_execution_receipt(request, artifact, replay.receipt)

    def _reserve_request(
        self,
        request: VerificationSigningRequestV1,
        *,
        receipt: IndependentExecutionReceiptV1,
        now: datetime,
    ) -> _IssuedRequestReplay | None:
        request_hash = request.request_hash().value
        with self._events.write_transaction() as connection:
            existing = connection.execute(
                """
                SELECT request_hash, state, attestation_json, evidence_artifact_digest,
                       execution_receipt_id, execution_receipt_hash, execution_verifier_id,
                       execution_checked_at, execution_claim_hash,
                       execution_receipt_authentication_key_id,
                       execution_receipt_authentication_algorithm,
                       execution_receipt_authentication_signature
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
                    attestation = AttestationV1.model_validate_json(
                        str(existing["attestation_json"])
                    )
                    stored_receipt = self._receipt_from_ledger_unchecked(request, existing)
                except ValueError as error:
                    raise VerificationSigningGatewayUnavailable(
                        "stored verification attestation or execution receipt is malformed"
                    ) from error
                return _IssuedRequestReplay(attestation=attestation, receipt=stored_receipt)
            try:
                connection.execute(
                    """
                    INSERT INTO verifier_signing_requests (
                        request_id, request_nonce, idempotency_key, request_hash,
                        canonical_payload_hash, bundle_id, proof_id, fencing_token,
                        evidence_artifact_digest, execution_receipt_id, execution_receipt_hash,
                        execution_verifier_id, execution_checked_at, execution_claim_hash,
                        execution_receipt_authentication_key_id,
                        execution_receipt_authentication_algorithm,
                        execution_receipt_authentication_signature,
                        state, reserved_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
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
                        receipt.receipt_id,
                        receipt.receipt_hash,
                        receipt.verifier_id,
                        self._timestamp(receipt.checked_at),
                        receipt.execution_claim_hash,
                        self._receipt_authentication_key_id(receipt),
                        self._receipt_authentication_algorithm(receipt),
                        self._receipt_authentication_signature(receipt),
                        self._timestamp(now),
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise VerificationSigningGatewayReplay(
                    "verification signing request, nonce, or canonical payload was replayed"
                ) from error
        return None

    def _receipt_from_ledger_unchecked(
        self,
        request: VerificationSigningRequestV1,
        row: sqlite3.Row,
    ) -> IndependentExecutionReceiptV1:
        if not hmac.compare_digest(
            str(row["evidence_artifact_digest"]), request.context.evidence_artifact_digest
        ):
            raise ValueError("issued verifier signing request has another evidence artifact")
        values = (
            row["execution_receipt_id"],
            row["execution_receipt_hash"],
            row["execution_verifier_id"],
            row["execution_checked_at"],
            row["execution_claim_hash"],
            row["execution_receipt_authentication_key_id"],
            row["execution_receipt_authentication_algorithm"],
            row["execution_receipt_authentication_signature"],
        )
        if any(value is None for value in values):
            raise ValueError("issued verifier signing request has no persisted execution receipt")
        checked_at = datetime.fromisoformat(str(row["execution_checked_at"]).replace("Z", "+00:00"))
        return IndependentExecutionReceiptV1(
            receipt_id=str(row["execution_receipt_id"]),
            verifier_id=str(row["execution_verifier_id"]),
            checked_at=checked_at,
            request_hash=request.request_hash().value,
            evidence_artifact_digest=request.context.evidence_artifact_digest,
            evidence_digest=request.context.verification_evidence_hash.value,
            execution_claim_hash=str(row["execution_claim_hash"]),
            receipt_hash=str(row["execution_receipt_hash"]),
            authentication=IndependentExecutionReceiptAuthenticationV1(
                key_id=str(row["execution_receipt_authentication_key_id"]),
                algorithm=str(row["execution_receipt_authentication_algorithm"]),
                authenticated_receipt_hash=str(row["execution_receipt_hash"]),
                signature=str(row["execution_receipt_authentication_signature"]),
            ),
        )

    @staticmethod
    def _receipt_authentication_key_id(receipt: IndependentExecutionReceiptV1) -> str:
        if receipt.authentication is None:
            raise ValueError("cannot reserve an unauthenticated execution receipt")
        return receipt.authentication.key_id

    @staticmethod
    def _receipt_authentication_algorithm(receipt: IndependentExecutionReceiptV1) -> str:
        if receipt.authentication is None:
            raise ValueError("cannot reserve an unauthenticated execution receipt")
        return receipt.authentication.algorithm

    @staticmethod
    def _receipt_authentication_signature(receipt: IndependentExecutionReceiptV1) -> str:
        if receipt.authentication is None:
            raise ValueError("cannot reserve an unauthenticated execution receipt")
        return receipt.authentication.signature

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
        if attestation.key_id != self._independent_execution_trust_policy.gateway_signing_key_id:
            raise VerificationSigningGatewayUnavailable(
                "verifier gateway returned an attestation from another signing key"
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
                    execution_receipt_id TEXT,
                    execution_receipt_hash TEXT,
                    execution_verifier_id TEXT,
                    execution_checked_at TEXT,
                    execution_claim_hash TEXT,
                    execution_receipt_authentication_key_id TEXT,
                    execution_receipt_authentication_algorithm TEXT,
                    execution_receipt_authentication_signature TEXT,
                    state TEXT NOT NULL CHECK (state IN ('pending', 'issued', 'failed')),
                    attestation_json TEXT,
                    failure_code TEXT,
                    reserved_at TEXT NOT NULL,
                    completed_at TEXT
                ) WITHOUT ROWID;
                """
            )
            existing_columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(verifier_signing_requests)")
            }
            migrations = {
                "execution_receipt_id": "TEXT",
                "execution_receipt_hash": "TEXT",
                "execution_verifier_id": "TEXT",
                "execution_checked_at": "TEXT",
                "execution_claim_hash": "TEXT",
                "execution_receipt_authentication_key_id": "TEXT",
                "execution_receipt_authentication_algorithm": "TEXT",
                "execution_receipt_authentication_signature": "TEXT",
            }
            for column, type_name in migrations.items():
                if column not in existing_columns:
                    connection.execute(
                        f"ALTER TABLE verifier_signing_requests ADD COLUMN {column} {type_name}"
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
