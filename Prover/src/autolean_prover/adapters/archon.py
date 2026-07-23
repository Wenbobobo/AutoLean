"""A safe protocol bridge for Archon-style proof engines.

This module deliberately does not import, start, or vendor Archon's runtime.  The audited
runtime has incompatible host-environment, secret, and workspace semantics.  Instead, any
future Archon integration receives an immutable request and can return only a proof term; the
normal AutoLean verifier remains the sole acceptance authority.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from autolean_contracts import (
    AttemptMetricsV1,
    FormalizationTaskBundleV1,
    HashKindV1,
    ProofSubmissionV1,
    ProvenanceTraceV1,
    digest_text,
    stable_identifier,
)

from autolean_prover.context import ContextPack, SpecialistRole
from autolean_prover.errors import ValidationError
from autolean_prover.providers.policy import validate_provider_identity

_PLACEHOLDER_RE = re.compile(r"\b(?:sorry|admit)\b|sorryAx")


@dataclass(frozen=True, slots=True)
class ArchonProofRequest:
    """The complete protocol surface exposed to an external proof-search engine."""

    bundle_id: str
    contract_id: str
    revision: int
    contract_hash: str
    proof_boundary_hash: str
    trusted_statement_source: str
    proof_slot_path: str
    context: str


@dataclass(frozen=True, slots=True)
class ArchonCandidate:
    """A candidate proof term plus typed, non-secret execution attribution."""

    attempt_key: str
    proof_source: str
    provenance: ProvenanceTraceV1
    metrics: AttemptMetricsV1 = field(default_factory=AttemptMetricsV1)

    def __post_init__(self) -> None:
        if not self.attempt_key.strip():
            raise ValidationError("Archon candidate attempt_key must not be empty")
        if not self.proof_source.strip():
            raise ValidationError("Archon candidate proof source must not be empty")
        if _PLACEHOLDER_RE.search(self.proof_source):
            raise ValidationError("Archon candidate proof source contains a prohibited placeholder")
        if self.provenance.actor_kind.value != "model":
            raise ValidationError("Archon candidates require model provenance")
        if self.provenance.provider is None or self.provenance.model_name is None:
            raise ValidationError("Archon candidates require provider and model attribution")
        validate_provider_identity(self.provenance.provider, self.provenance.model_name)


class ArchonProofAdapter:
    """Translate a frozen AutoLean bundle to/from a proof-term-only Archon protocol."""

    def request(
        self,
        bundle: FormalizationTaskBundleV1,
        context: ContextPack,
    ) -> ArchonProofRequest:
        self._validate_context_binding(bundle, context)
        if context.role is not SpecialistRole.TACTIC:
            raise ValidationError("Archon proof requests require a tactic-specialist context pack")
        boundary = bundle.proof_boundary
        return ArchonProofRequest(
            bundle_id=bundle.bundle_id.value,
            contract_id=bundle.contract.contract_id.value,
            revision=bundle.contract.revision,
            contract_hash=bundle.contract.semantic_hash().value,
            proof_boundary_hash=boundary.boundary_hash.value,
            trusted_statement_source=boundary.trusted_statement_source,
            proof_slot_path=boundary.allowed_write_paths[0],
            context=context.render(),
        )

    def submission(
        self,
        bundle: FormalizationTaskBundleV1,
        candidate: ArchonCandidate,
    ) -> ProofSubmissionV1:
        """Return a normal Prover submission; this method does not verify or accept it."""

        return ProofSubmissionV1(
            proof_id=stable_identifier(
                "proof",
                f"archon:{bundle.bundle_id.value}:{candidate.attempt_key}",
            ),
            contract_id=bundle.contract.contract_id,
            revision=bundle.contract.revision,
            contract_hash=bundle.contract.semantic_hash(),
            proof_boundary_hash=bundle.proof_boundary.boundary_hash,
            proof_source=candidate.proof_source,
            proof_source_hash=digest_text(HashKindV1.PROOF_SOURCE, candidate.proof_source),
            environment_hash=bundle.contract.formal.environment.environment_hash,
            provenance=(candidate.provenance,),
            metrics=candidate.metrics,
        )

    @staticmethod
    def _validate_context_binding(
        bundle: FormalizationTaskBundleV1,
        context: ContextPack,
    ) -> None:
        contract = bundle.contract
        if context.contract_id != contract.contract_id.value:
            raise ValidationError("context pack binds a different contract ID")
        if context.revision != contract.revision:
            raise ValidationError("context pack binds a different contract revision")
        if context.contract_hash != contract.semantic_hash().value:
            raise ValidationError("context pack binds a different frozen contract hash")
        if context.proof_boundary_hash != bundle.proof_boundary.boundary_hash.value:
            raise ValidationError("context pack binds a different frozen proof boundary")
