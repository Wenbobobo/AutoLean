"""Lease-bound, non-secret authority inputs for OCI verifier executions.

This module intentionally does not sign anything and does not import the control plane.  It
turns an immutable ``FormalizationTaskBundleV1`` into a narrow execution input, then binds that
input to the public projection of a fenced verifier lease.  A caller must supply a live lease
validator before such a claim may be used by ``OciLeanRunner``.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from autolean_contracts import FormalizationTaskBundleV1, VerificationSigningLeaseBindingV1

from autolean_prover.errors import ValidationError

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_IDENTITY_SCHEMA = "autolean.image-owned-verifier-identity.v2"
_CLAIM_SCHEMA = "autolean.oci-execution-claim.v2"
_WRAPPER_PATH = "/opt/autolean/bin/autolean-lean-wrapper"
_QUERY_HELPER_PATH = "/opt/autolean/lib/AutoleanLeanQuery.lean"


@dataclass(frozen=True, slots=True)
class FrozenTaskBundleInput:
    """A hash-bound projection of exactly one immutable Builder handoff.

    Keeping the original bundle lets the workspace retain its existing public API, while the
    captured hashes detect an unsafe in-memory substitution before the runner starts an OCI
    process.  No host path, proof text, or credential appears in this input.
    """

    bundle: FormalizationTaskBundleV1
    bundle_hash: str
    contract_hash: str
    proof_boundary_hash: str
    environment_hash: str

    @classmethod
    def from_bundle(cls, bundle: FormalizationTaskBundleV1) -> FrozenTaskBundleInput:
        return cls(
            bundle=bundle,
            bundle_hash=bundle.handoff_hash().value,
            contract_hash=bundle.contract.semantic_hash().value,
            proof_boundary_hash=bundle.proof_boundary.boundary_hash.value,
            environment_hash=bundle.contract.formal.environment.environment_hash.value,
        )

    def validate(self) -> None:
        if self.bundle.handoff_hash().value != self.bundle_hash:
            raise ValidationError(
                "oci_execution_bundle_mutated",
                "execution input bundle no longer matches its frozen handoff hash",
            )
        if self.bundle.contract.semantic_hash().value != self.contract_hash:
            raise ValidationError(
                "oci_execution_contract_mutated",
                "execution input contract no longer matches its frozen hash",
            )
        if self.bundle.proof_boundary.boundary_hash.value != self.proof_boundary_hash:
            raise ValidationError(
                "oci_execution_boundary_mutated",
                "execution input proof boundary no longer matches its frozen hash",
            )
        if self.bundle.contract.formal.environment.environment_hash.value != self.environment_hash:
            raise ValidationError(
                "oci_execution_environment_mutated",
                "execution input Lean environment no longer matches its frozen hash",
            )

    def binding_payload(self) -> dict[str, str]:
        """Return the stable public claim binding without serializing the full bundle."""

        return {
            "bundle_id": self.bundle.bundle_id.value,
            "bundle_hash": self.bundle_hash,
            "contract_hash": self.contract_hash,
            "proof_boundary_hash": self.proof_boundary_hash,
            "environment_hash": self.environment_hash,
        }


@dataclass(frozen=True, slots=True)
class ImageOwnedVerifierIdentity:
    """Digests which the image-owned wrapper must report after OCI execution starts.

    The configured values are expected to come from an image build/publish attestation.  The host
    never mounts these files into the container; it only compares the wrapper's self-measured
    values against the claim.  This is deliberately not a substitute for registry or runtime
    attestation, which remains a production deployment responsibility.
    """

    wrapper_sha256: str
    query_helper_sha256: str
    wrapper_path: str = _WRAPPER_PATH
    query_helper_path: str = _QUERY_HELPER_PATH
    schema_version: str = _IDENTITY_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != _IDENTITY_SCHEMA:
            raise ValueError("unsupported image-owned verifier identity schema")
        if self.wrapper_path != _WRAPPER_PATH or self.query_helper_path != _QUERY_HELPER_PATH:
            raise ValueError("image-owned verifier identity has an unsupported path")
        for label, value in (
            ("wrapper_sha256", self.wrapper_sha256),
            ("query_helper_sha256", self.query_helper_sha256),
        ):
            if not _SHA256.fullmatch(value):
                raise ValueError(f"image-owned verifier identity {label} must be a SHA-256 digest")

    def payload(self) -> dict[str, str]:
        return {
            "schema_version": self.schema_version,
            "wrapper_path": self.wrapper_path,
            "wrapper_sha256": self.wrapper_sha256,
            "query_helper_path": self.query_helper_path,
            "query_helper_sha256": self.query_helper_sha256,
        }

    def identity_hash(self) -> str:
        canonical = json.dumps(
            self.payload(), ensure_ascii=True, sort_keys=True, separators=(",", ":")
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @classmethod
    def from_wrapper_record(cls, value: object) -> ImageOwnedVerifierIdentity:
        if not isinstance(value, dict) or set(value) != {
            "schema_version",
            "wrapper_path",
            "wrapper_sha256",
            "query_helper_path",
            "query_helper_sha256",
        }:
            raise ValidationError(
                "oci_wrapper_identity_shape",
                "OCI Lean wrapper image identity has an unexpected shape",
            )
        try:
            return cls(
                schema_version=_required_text(value, "schema_version"),
                wrapper_path=_required_text(value, "wrapper_path"),
                wrapper_sha256=_required_text(value, "wrapper_sha256"),
                query_helper_path=_required_text(value, "query_helper_path"),
                query_helper_sha256=_required_text(value, "query_helper_sha256"),
            )
        except ValueError as error:
            raise ValidationError(
                "oci_wrapper_identity_invalid",
                "OCI Lean wrapper image identity is invalid",
            ) from error


class ExecutionClaimValidator(Protocol):
    """Control-plane adapter that proves a claim's fence is still current."""

    def assert_current(self, claim: OciExecutionClaim) -> None: ...


@dataclass(frozen=True, slots=True)
class OciExecutionClaim:
    """A lease-bound authorization to execute one frozen task in one verifier image.

    ``ExecutionClaimValidator`` is intentionally external: the Prover process has no authority
    to decide whether a worker lease is current.  The OCI runner checks it both before launch and
    after process completion, so a replacement worker cannot promote a stale result.
    """

    task_input: FrozenTaskBundleInput
    lease: VerificationSigningLeaseBindingV1
    image_identity: ImageOwnedVerifierIdentity
    claim_id: str
    issued_at: datetime
    schema_version: str = _CLAIM_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != _CLAIM_SCHEMA:
            raise ValueError("unsupported OCI execution claim schema")
        if not _SAFE_ID.fullmatch(self.claim_id):
            raise ValueError("OCI execution claim ID is not a safe identifier")
        if self.issued_at.tzinfo is None:
            raise ValueError("OCI execution claim issue time must be timezone-aware")
        self.task_input.validate()
        if self.lease.bundle_id != self.task_input.bundle.bundle_id:
            raise ValueError("OCI execution claim lease binds a different bundle")
        if self.lease.expires_at.astimezone(UTC) <= self.issued_at.astimezone(UTC):
            raise ValueError("OCI execution claim is already outside its lease")

    def claim_hash(self) -> str:
        return hashlib.sha256(
            json.dumps(
                {
                    "schema_version": self.schema_version,
                    "claim_id": self.claim_id,
                    "task": self.task_input.binding_payload(),
                    "lease": self.lease.model_dump(mode="json"),
                    "image_identity": self.image_identity.payload(),
                    "issued_at": self.issued_at.astimezone(UTC).isoformat(),
                },
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()

    def assert_authorizes(self, task_input: FrozenTaskBundleInput, *, now: datetime) -> None:
        if now.tzinfo is None:
            raise ValidationError(
                "oci_execution_claim_clock",
                "OCI execution claim validation requires a timezone-aware clock",
            )
        self.task_input.validate()
        task_input.validate()
        if self.task_input.binding_payload() != task_input.binding_payload():
            raise ValidationError(
                "oci_execution_claim_bundle_mismatch",
                "OCI execution claim does not authorize this frozen task bundle",
            )
        if self.lease.bundle_id != task_input.bundle.bundle_id:
            raise ValidationError(
                "oci_execution_claim_lease_bundle",
                "OCI execution claim lease does not bind the materialized bundle",
            )
        if now.astimezone(UTC) >= self.lease.expires_at.astimezone(UTC):
            raise ValidationError(
                "oci_execution_claim_expired",
                "OCI execution claim lease is expired",
            )


def _required_text(payload: dict[str, object], field: str) -> str:
    value = payload[field]
    if not isinstance(value, str):
        raise ValueError(f"{field} must be text")
    return value
