"""Typed evidence exchanged between a Lean runner and the frozen-boundary verifier.

These records deliberately live below ``verification`` so an OCI runner can produce them without
importing the verifier implementation.  They describe execution evidence; an operator still has to
store and attest that evidence before a result can be promoted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final, Protocol

if TYPE_CHECKING:
    from autolean_prover.execution.workspace import MaterializedWorkspace


CANONICAL_TYPE_FORMAT: Final[str] = "autolean.lean-pp-expr.v1"
OCI_EXECUTION_EVIDENCE_SCHEMA: Final[str] = "autolean.oci-execution-evidence.v1"
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
    candidate_sha256: str
    trusted_statement_sha256: str
    bundle_manifest_sha256: str
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
        for label, value in (
            ("command_policy_hash", self.command_policy_hash),
            ("command_hash", self.command_hash),
            ("candidate_sha256", self.candidate_sha256),
            ("trusted_statement_sha256", self.trusted_statement_sha256),
            ("bundle_manifest_sha256", self.bundle_manifest_sha256),
        ):
            if not _SHA256.fullmatch(value):
                raise ValueError(f"OCI execution evidence {label} must be a SHA-256 hex digest")


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
