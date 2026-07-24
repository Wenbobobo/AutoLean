"""Typed evidence exchanged between a Lean runner and the frozen-boundary verifier.

These records deliberately live below ``verification`` so an OCI runner can produce them without
importing the verifier implementation.  They describe execution evidence; an operator still has to
store and attest that evidence before a result can be promoted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final, Literal, Protocol

if TYPE_CHECKING:
    from autolean_prover.execution.workspace import MaterializedWorkspace


CANONICAL_TYPE_FORMAT: Final[str] = "autolean.lean-pp-expr.v1"
OCI_EXECUTION_EVIDENCE_SCHEMA: Final[str] = "autolean.oci-execution-evidence.v2"
OCI_COMPILE_QUERY_HANDOFF: Final[str] = "autolean.oci-compile-query-handoff.v1"
OCI_EXECUTION_AUTHORITY_NON_PRODUCTION: Final[Literal["non-production"]] = "non-production"
OCI_EXECUTION_AUTHORITY_LEASE_UNOBSERVED: Final[Literal["lease-bound-unobserved"]] = (
    "lease-bound-unobserved"
)
OCI_EXECUTION_AUTHORITY_LEASE_PENDING_GATEWAY: Final[Literal["lease-bound-pending-gateway"]] = (
    "lease-bound-pending-gateway"
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_OCI_IMAGE = re.compile(r"^.+@(?P<digest>sha256:[0-9a-f]{64})$")
_MAX_CANONICAL_TYPE_CHARS: Final[int] = 1_000_000


@dataclass(frozen=True, slots=True)
class ElaboratedTypeEvidence:
    """A verifier-owned rendering of a declaration type from the pinned Lean image."""

    declaration: str
    canonical_type: str
    format_id: str = CANONICAL_TYPE_FORMAT

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if self.format_id != CANONICAL_TYPE_FORMAT:
            raise ValueError("unsupported elaborated-type evidence format")
        if not self.declaration or self.declaration != self.declaration.strip():
            raise ValueError("elaborated-type evidence declaration must be canonical")
        if "\x00" in self.declaration or "\n" in self.declaration or "\r" in self.declaration:
            raise ValueError("elaborated-type evidence declaration contains a control character")
        if not self.canonical_type or self.canonical_type != self.canonical_type.strip():
            raise ValueError("canonical elaborated type must be nonempty and trimmed")
        if (
            "\x00" in self.canonical_type
            or "\n" in self.canonical_type
            or "\r" in self.canonical_type
        ):
            raise ValueError("canonical elaborated type must be a single line")
        if len(self.canonical_type) > _MAX_CANONICAL_TYPE_CHARS:
            raise ValueError("canonical elaborated type exceeds the verifier limit")


@dataclass(frozen=True, slots=True)
class OciExecutionEvidence:
    """Immutable, non-secret facts observed around one OCI Lean invocation.

    The evidence intentionally has no host paths, model text, or credential references.  A later
    verifier service can turn these values plus captured wrapper output into a content-addressed
    ``VerificationEvidenceV1`` artifact.
    """

    worker_image: str
    worker_image_digest: str
    environment_hash: str
    lean_version: str
    mathlib_revision: str
    lake_manifest_hash: str | None
    wrapper_protocol: str
    command_policy_hash: str
    command_hash: str
    compile_command_hash: str
    query_command_hash: str | None
    sealed_candidate_sha256: str | None
    candidate_sha256: str
    trusted_statement_sha256: str
    bundle_manifest_sha256: str
    authority_status: Literal[
        "non-production", "lease-bound-unobserved", "lease-bound-pending-gateway"
    ] = "non-production"
    execution_claim_hash: str | None = None
    lease_worker_id: str | None = None
    lease_fencing_token: int | None = None
    lease_expires_at: datetime | None = None
    wrapper_identity_hash: str | None = None
    handoff_protocol: str = OCI_COMPILE_QUERY_HANDOFF
    schema_version: str = OCI_EXECUTION_EVIDENCE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != OCI_EXECUTION_EVIDENCE_SCHEMA:
            raise ValueError("unsupported OCI execution evidence schema")
        image = _OCI_IMAGE.fullmatch(self.worker_image)
        if image is None:
            raise ValueError("OCI execution evidence requires a digest-pinned worker image")
        if self.worker_image_digest != image.group("digest"):
            raise ValueError("OCI execution evidence image digest does not match worker image")
        if not _SHA256.fullmatch(self.environment_hash):
            raise ValueError("OCI execution evidence environment hash must be a SHA-256 hex digest")
        if not self.lean_version or not self.mathlib_revision:
            raise ValueError("OCI execution evidence environment fields must not be empty")
        if self.lake_manifest_hash is not None and not _SHA256.fullmatch(self.lake_manifest_hash):
            raise ValueError(
                "OCI execution evidence Lake manifest hash must be a SHA-256 hex digest"
            )
        if not self.wrapper_protocol:
            raise ValueError("OCI execution evidence wrapper protocol must not be empty")
        if self.handoff_protocol != OCI_COMPILE_QUERY_HANDOFF:
            raise ValueError("unsupported OCI compile/query handoff protocol")
        for label, value in (
            ("command_policy_hash", self.command_policy_hash),
            ("command_hash", self.command_hash),
            ("compile_command_hash", self.compile_command_hash),
            ("candidate_sha256", self.candidate_sha256),
            ("trusted_statement_sha256", self.trusted_statement_sha256),
            ("bundle_manifest_sha256", self.bundle_manifest_sha256),
        ):
            if not _SHA256.fullmatch(value):
                raise ValueError(f"OCI execution evidence {label} must be a SHA-256 hex digest")
        if (self.query_command_hash is None) != (self.sealed_candidate_sha256 is None):
            raise ValueError("OCI query command and sealed candidate hashes must appear together")
        for label, optional_value in (
            ("query_command_hash", self.query_command_hash),
            ("sealed_candidate_sha256", self.sealed_candidate_sha256),
        ):
            if optional_value is not None and not _SHA256.fullmatch(optional_value):
                raise ValueError(f"OCI execution evidence {label} must be a SHA-256 hex digest")
        claim_fields = (
            self.execution_claim_hash,
            self.lease_worker_id,
            self.lease_fencing_token,
            self.lease_expires_at,
            self.wrapper_identity_hash,
        )
        if self.authority_status == OCI_EXECUTION_AUTHORITY_NON_PRODUCTION:
            if any(value is not None for value in claim_fields):
                raise ValueError(
                    "non-production OCI execution evidence cannot carry an authority claim"
                )
        elif self.authority_status == OCI_EXECUTION_AUTHORITY_LEASE_UNOBSERVED:
            if (
                self.execution_claim_hash is None
                or self.lease_worker_id is None
                or self.lease_fencing_token is None
                or self.lease_expires_at is None
                or self.wrapper_identity_hash is not None
            ):
                raise ValueError("unobserved lease-bound OCI evidence lacks required claim fields")
        elif self.authority_status == OCI_EXECUTION_AUTHORITY_LEASE_PENDING_GATEWAY:
            if (
                any(value is None for value in claim_fields)
                or self.query_command_hash is None
                or self.sealed_candidate_sha256 is None
            ):
                raise ValueError("lease-bound OCI evidence lacks required authority fields")
        else:
            raise ValueError("unsupported OCI execution authority status")
        if self.execution_claim_hash is not None and not _SHA256.fullmatch(
            self.execution_claim_hash
        ):
            raise ValueError("OCI execution claim hash must be a SHA-256 hex digest")
        if self.wrapper_identity_hash is not None and not _SHA256.fullmatch(
            self.wrapper_identity_hash
        ):
            raise ValueError("OCI wrapper identity hash must be a SHA-256 hex digest")
        if self.lease_fencing_token is not None and self.lease_fencing_token <= 0:
            raise ValueError("OCI execution lease fencing token must be positive")
        if self.lease_worker_id is not None and (
            not self.lease_worker_id
            or self.lease_worker_id != self.lease_worker_id.strip()
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}", self.lease_worker_id) is None
        ):
            raise ValueError("OCI execution lease worker ID must be a safe identifier")
        if self.lease_expires_at is not None and self.lease_expires_at.tzinfo is None:
            raise ValueError("OCI execution lease expiry must be timezone-aware")

    def authority_payload(self) -> dict[str, object]:
        """Return the safe authority fields bound into verification evidence artifact V2.

        Current cross-component V1 evidence contracts do not have extension fields.  Callers can
        expose this structured payload without pretending that the existing V1 gateway artifact
        preserves fields it cannot validate.
        """

        return {
            "status": self.authority_status,
            "execution_claim_hash": self.execution_claim_hash,
            "lease_worker_id": self.lease_worker_id,
            "lease_fencing_token": self.lease_fencing_token,
            "lease_expires_at": (
                None if self.lease_expires_at is None else self.lease_expires_at.isoformat()
            ),
            "wrapper_identity_hash": self.wrapper_identity_hash,
        }


@dataclass(frozen=True, slots=True)
class LeanRunEvidence:
    returncode: int | None
    timed_out: bool
    stdout: str
    stderr: str
    clean_environment: bool
    observed_axioms: tuple[str, ...] | None = None
    elaborated_type_evidence: ElaboratedTypeEvidence | None = None
    oci_execution_evidence: OciExecutionEvidence | None = None


class LeanRunner(Protocol):
    def run(self, candidate: Path, *, workspace: MaterializedWorkspace) -> LeanRunEvidence: ...
