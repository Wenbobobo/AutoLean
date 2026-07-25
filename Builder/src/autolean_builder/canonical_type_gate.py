"""Builder-owned exact canonical elaborated-type gate.

This module compares only the canonical type text emitted by one registered query boundary.  It
does not infer definitional, propositional, or mathematical equivalence.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal, Protocol

from autolean_contracts import (
    DigestV1,
    HashKindV1,
    canonical_json_bytes,
    digest_bytes,
    digest_text,
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_TYPE_FORMAT = "autolean.lean-pp-expr.v1"


class CanonicalTypeGateError(ValueError):
    """A query result cannot establish exact canonical type identity."""


class CanonicalTypeQueryAssurance(StrEnum):
    """The narrow execution assurance carried by one query adapter."""

    SCRIPTED_FAKE = "scripted_fake"
    LOCAL_OCI_PREFREEZE = "local_oci_prefreeze"


@dataclass(frozen=True, slots=True)
class CanonicalTypeQueryRequest:
    """One immutable source declaration submitted to the registered query boundary."""

    subject_id: str
    statement_source: str
    statement_source_hash: DigestV1
    declaration: str
    namespace: str
    imports_allowlist: tuple[str, ...]

    def __post_init__(self) -> None:
        for label, value in (
            ("subject_id", self.subject_id),
            ("statement_source", self.statement_source),
            ("declaration", self.declaration),
            ("namespace", self.namespace),
        ):
            if not value.strip() or value != value.strip():
                raise CanonicalTypeGateError(f"canonical query {label} must be trimmed text")
        if self.statement_source_hash != digest_text(
            HashKindV1.STATEMENT_SOURCE,
            self.statement_source,
        ):
            raise CanonicalTypeGateError(
                "canonical query statement source differs from its bound hash"
            )


@dataclass(frozen=True, slots=True)
class CanonicalTypeEnvironmentFacts:
    """Environment and image facts common to every result in one gate execution."""

    assurance: CanonicalTypeQueryAssurance
    adapter_id: str
    image: str
    worker_image_digest: str
    lean_version: str
    mathlib_revision: str
    lake_manifest_sha256: str | None
    type_format: str
    query_schema_version: str
    query_protocol: str
    query_identity_sha256: str
    build_receipt_canonical_sha256: str
    execution_policy_sha256: str
    source_inputs_sha256: str
    source_rendering_profile: str

    def validate(self) -> None:
        for label, value in (
            ("adapter_id", self.adapter_id),
            ("image", self.image),
            ("lean_version", self.lean_version),
            ("mathlib_revision", self.mathlib_revision),
            ("query_schema_version", self.query_schema_version),
            ("query_protocol", self.query_protocol),
            ("source_rendering_profile", self.source_rendering_profile),
        ):
            if not value.strip() or value != value.strip():
                raise CanonicalTypeGateError(
                    f"canonical query environment {label} must be trimmed text"
                )
        if not _IMAGE_DIGEST_RE.fullmatch(self.worker_image_digest):
            raise CanonicalTypeGateError(
                "canonical query environment has an invalid worker image digest"
            )
        if not self.image.endswith(f"@{self.worker_image_digest}"):
            raise CanonicalTypeGateError("canonical query image reference differs from its digest")
        if self.type_format != _TYPE_FORMAT:
            raise CanonicalTypeGateError("canonical query type format is unsupported")
        for label, value in (
            ("query_identity_sha256", self.query_identity_sha256),
            ("build_receipt_canonical_sha256", self.build_receipt_canonical_sha256),
            ("execution_policy_sha256", self.execution_policy_sha256),
            ("source_inputs_sha256", self.source_inputs_sha256),
        ):
            _require_sha256(value, label=label)
        if self.lake_manifest_sha256 is not None:
            _require_sha256(self.lake_manifest_sha256, label="lake_manifest_sha256")

    @property
    def content_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.payload())).hexdigest()

    def payload(self) -> dict[str, object]:
        return {
            "assurance": self.assurance.value,
            "adapter_id": self.adapter_id,
            "image": self.image,
            "worker_image_digest": self.worker_image_digest,
            "lean_version": self.lean_version,
            "mathlib_revision": self.mathlib_revision,
            "lake_manifest_sha256": self.lake_manifest_sha256,
            "type_format": self.type_format,
            "query_schema_version": self.query_schema_version,
            "query_protocol": self.query_protocol,
            "query_identity_sha256": self.query_identity_sha256,
            "build_receipt_canonical_sha256": self.build_receipt_canonical_sha256,
            "execution_policy_sha256": self.execution_policy_sha256,
            "source_inputs_sha256": self.source_inputs_sha256,
            "source_rendering_profile": self.source_rendering_profile,
        }


@dataclass(frozen=True, slots=True)
class CanonicalTypeQueryFacts:
    """Per-invocation facts returned after compile, seal, and image-owned query."""

    query_output_sha256: str
    source_snapshot_sha256: str
    sealed_candidate_sha256: str
    candidate_direct_imports_sha256: str
    module_import_closure_sha256: str
    observed_axioms: tuple[str, ...]
    observed_axioms_sha256: str

    def validate(self) -> None:
        for label, value in (
            ("query_output_sha256", self.query_output_sha256),
            ("source_snapshot_sha256", self.source_snapshot_sha256),
            ("sealed_candidate_sha256", self.sealed_candidate_sha256),
            ("candidate_direct_imports_sha256", self.candidate_direct_imports_sha256),
            ("module_import_closure_sha256", self.module_import_closure_sha256),
            ("observed_axioms_sha256", self.observed_axioms_sha256),
        ):
            _require_sha256(value, label=label)
        if (
            self.observed_axioms != tuple(sorted(self.observed_axioms))
            or len(self.observed_axioms) != len(set(self.observed_axioms))
            or any(not item or item != item.strip() for item in self.observed_axioms)
        ):
            raise CanonicalTypeGateError(
                "canonical query observed axioms must be sorted, unique, trimmed names"
            )
        expected_axioms_hash = hashlib.sha256(
            canonical_json_bytes(self.observed_axioms) + b"\n"
        ).hexdigest()
        if self.observed_axioms_sha256 != expected_axioms_hash:
            raise CanonicalTypeGateError(
                "canonical query observed axiom text differs from its hash"
            )

    def payload(self) -> dict[str, object]:
        return {
            "query_output_sha256": self.query_output_sha256,
            "source_snapshot_sha256": self.source_snapshot_sha256,
            "sealed_candidate_sha256": self.sealed_candidate_sha256,
            "candidate_direct_imports_sha256": self.candidate_direct_imports_sha256,
            "module_import_closure_sha256": self.module_import_closure_sha256,
            "observed_axioms": list(self.observed_axioms),
            "observed_axioms_sha256": self.observed_axioms_sha256,
        }


@dataclass(frozen=True, slots=True)
class CanonicalTypeQueryResult:
    """Typed output of a query adapter; validated by the gate, not trusted on construction."""

    declaration: str
    canonical_type: str
    canonical_type_sha256: str
    environment: CanonicalTypeEnvironmentFacts
    query: CanonicalTypeQueryFacts


class CanonicalTypeQuery(Protocol):
    def query(self, request: CanonicalTypeQueryRequest) -> CanonicalTypeQueryResult:
        """Freshly compile, seal, and query exactly one requested declaration."""


@dataclass(frozen=True, slots=True)
class CanonicalTypeGateBinding:
    """Contract-owned values that no query implementation may nominate."""

    contract_id: str
    revision: int
    draft_contract_hash: DigestV1
    source_hash: DigestV1
    generation_task_hash: DigestV1
    selected_statement_hash: DigestV1
    environment_hash: DigestV1
    declaration: str
    lean_version: str
    mathlib_revision: str
    lake_manifest_sha256: str | None
    worker_image_digest: str
    expected_elaborated_type: str
    expected_elaborated_type_hash: DigestV1


@dataclass(frozen=True, slots=True)
class CanonicalTypeObservation:
    subject_id: str
    statement_source_hash: DigestV1
    declaration: str
    canonical_type: str
    canonical_type_hash: DigestV1
    canonical_type_sha256: str
    environment_facts_sha256: str
    query: CanonicalTypeQueryFacts

    @classmethod
    def from_result(
        cls,
        request: CanonicalTypeQueryRequest,
        result: CanonicalTypeQueryResult,
    ) -> CanonicalTypeObservation:
        return cls(
            subject_id=request.subject_id,
            statement_source_hash=request.statement_source_hash,
            declaration=result.declaration,
            canonical_type=result.canonical_type,
            canonical_type_hash=digest_text(
                HashKindV1.ELABORATED_TYPE,
                result.canonical_type,
            ),
            canonical_type_sha256=result.canonical_type_sha256,
            environment_facts_sha256=result.environment.content_sha256,
            query=result.query,
        )

    def payload(self) -> dict[str, object]:
        return {
            "subject_id": self.subject_id,
            "statement_source_hash": self.statement_source_hash.model_dump(mode="json"),
            "declaration": self.declaration,
            "canonical_type": self.canonical_type,
            "canonical_type_hash": self.canonical_type_hash.model_dump(mode="json"),
            "canonical_type_sha256": self.canonical_type_sha256,
            "environment_facts_sha256": self.environment_facts_sha256,
            "query": self.query.payload(),
        }


@dataclass(frozen=True, slots=True)
class CanonicalTypeGateEvidence:
    """Builder-internal evidence for exact printer-text identity only."""

    contract_id: str
    revision: int
    draft_contract_hash: DigestV1
    source_hash: DigestV1
    generation_task_hash: DigestV1
    selected_statement_hash: DigestV1
    environment_hash: DigestV1
    expected_elaborated_type_hash: DigestV1
    environment: CanonicalTypeEnvironmentFacts
    reference: CanonicalTypeObservation
    candidates: tuple[CanonicalTypeObservation, ...]
    promotion_authority: Literal[False] = False

    def assert_binds(
        self,
        binding: CanonicalTypeGateBinding,
        reference: CanonicalTypeQueryRequest,
        candidates: tuple[CanonicalTypeQueryRequest, ...],
    ) -> None:
        if self.promotion_authority is not False:
            raise CanonicalTypeGateError("canonical type evidence cannot claim promotion authority")
        if (
            self.contract_id != binding.contract_id
            or self.revision != binding.revision
            or self.draft_contract_hash != binding.draft_contract_hash
            or self.source_hash != binding.source_hash
            or self.generation_task_hash != binding.generation_task_hash
            or self.selected_statement_hash != binding.selected_statement_hash
            or self.environment_hash != binding.environment_hash
            or self.expected_elaborated_type_hash != binding.expected_elaborated_type_hash
        ):
            raise CanonicalTypeGateError(
                "canonical type gate evidence is bound to another Builder task"
            )
        self.environment.validate()
        _assert_environment_matches_binding(self.environment, binding)
        if len(self.candidates) != len(candidates):
            raise CanonicalTypeGateError(
                "canonical type gate candidate evidence count differs from the task"
            )
        _assert_observation_binds_request(self.reference, reference, self.environment)
        if (
            self.reference.canonical_type != binding.expected_elaborated_type
            or self.reference.canonical_type_hash != binding.expected_elaborated_type_hash
        ):
            raise CanonicalTypeGateError(
                "fresh reference canonical type drifted from the contract-bound value"
            )
        for observation, request in zip(self.candidates, candidates, strict=True):
            _assert_observation_binds_request(observation, request, self.environment)
            if (
                observation.canonical_type != self.reference.canonical_type
                or observation.canonical_type_hash != self.reference.canonical_type_hash
                or observation.canonical_type_sha256 != self.reference.canonical_type_sha256
            ):
                raise CanonicalTypeGateError(
                    f"candidate {request.subject_id} canonical type differs from the reference"
                )

    def payload(self) -> dict[str, object]:
        return {
            "schema_version": "autolean.builder-canonical-type-gate.v1",
            "claim": "exact_canonical_printer_text_identity",
            "definitional_equivalence_claimed": False,
            "semantic_equivalence_claimed": False,
            "promotion_authority": self.promotion_authority,
            "contract_id": self.contract_id,
            "revision": self.revision,
            "draft_contract_hash": self.draft_contract_hash.model_dump(mode="json"),
            "source_hash": self.source_hash.model_dump(mode="json"),
            "generation_task_hash": self.generation_task_hash.model_dump(mode="json"),
            "selected_statement_hash": self.selected_statement_hash.model_dump(mode="json"),
            "environment_hash": self.environment_hash.model_dump(mode="json"),
            "expected_elaborated_type_hash": self.expected_elaborated_type_hash.model_dump(
                mode="json"
            ),
            "environment": self.environment.payload(),
            "reference": self.reference.payload(),
            "candidates": [item.payload() for item in self.candidates],
        }

    @property
    def record_hash(self) -> DigestV1:
        return digest_bytes(
            HashKindV1.FREEZE_EVIDENCE,
            canonical_json_bytes(self.payload()),
        )

    def automatic_evidence(self) -> str:
        return canonical_json_bytes(
            {
                "schema_version": "autolean.builder-canonical-type-check.v1",
                "record": self.payload(),
                "record_hash": self.record_hash.model_dump(mode="json"),
            }
        ).decode("ascii")


def run_canonical_type_gate(
    query: CanonicalTypeQuery,
    *,
    binding: CanonicalTypeGateBinding,
    reference: CanonicalTypeQueryRequest,
    candidates: tuple[CanonicalTypeQueryRequest, ...],
) -> CanonicalTypeGateEvidence:
    """Fresh-query the reference and every candidate before any semantic callback."""

    if len(candidates) < 2:
        raise CanonicalTypeGateError(
            "canonical type gate requires at least two independent candidates"
        )
    reference_result = _run_query(query, reference)
    _validate_query_result(reference_result, request=reference, binding=binding)
    if (
        reference_result.canonical_type != binding.expected_elaborated_type
        or digest_text(HashKindV1.ELABORATED_TYPE, reference_result.canonical_type)
        != binding.expected_elaborated_type_hash
    ):
        raise CanonicalTypeGateError(
            "fresh reference canonical type drifted from the contract-bound value"
        )

    candidate_observations: list[CanonicalTypeObservation] = []
    for request in candidates:
        result = _run_query(query, request)
        _validate_query_result(result, request=request, binding=binding)
        if result.environment != reference_result.environment:
            raise CanonicalTypeGateError(
                f"candidate {request.subject_id} query environment differs from the reference"
            )
        if (
            result.canonical_type != reference_result.canonical_type
            or result.canonical_type_sha256 != reference_result.canonical_type_sha256
        ):
            raise CanonicalTypeGateError(
                f"candidate {request.subject_id} canonical type differs from the reference"
            )
        candidate_observations.append(CanonicalTypeObservation.from_result(request, result))

    evidence = CanonicalTypeGateEvidence(
        contract_id=binding.contract_id,
        revision=binding.revision,
        draft_contract_hash=binding.draft_contract_hash,
        source_hash=binding.source_hash,
        generation_task_hash=binding.generation_task_hash,
        selected_statement_hash=binding.selected_statement_hash,
        environment_hash=binding.environment_hash,
        expected_elaborated_type_hash=binding.expected_elaborated_type_hash,
        environment=reference_result.environment,
        reference=CanonicalTypeObservation.from_result(reference, reference_result),
        candidates=tuple(candidate_observations),
    )
    evidence.assert_binds(binding, reference, candidates)
    return evidence


def _run_query(
    query: CanonicalTypeQuery,
    request: CanonicalTypeQueryRequest,
) -> CanonicalTypeQueryResult:
    try:
        result = query.query(request)
    except Exception as error:
        raise CanonicalTypeGateError(
            f"canonical type query failed for {request.subject_id}: {error}"
        ) from error
    if not isinstance(result, CanonicalTypeQueryResult):
        raise CanonicalTypeGateError(
            f"canonical type query returned an invalid result for {request.subject_id}"
        )
    return result


def _validate_query_result(
    result: CanonicalTypeQueryResult,
    *,
    request: CanonicalTypeQueryRequest,
    binding: CanonicalTypeGateBinding,
) -> None:
    result.environment.validate()
    result.query.validate()
    _assert_environment_matches_binding(result.environment, binding)
    if result.declaration != request.declaration:
        raise CanonicalTypeGateError(
            f"canonical query returned another declaration for {request.subject_id}"
        )
    if (
        not result.canonical_type
        or len(result.canonical_type) > 1_000_000
        or any(character in result.canonical_type for character in ("\x00", "\n", "\r"))
    ):
        raise CanonicalTypeGateError(
            f"canonical query returned invalid type text for {request.subject_id}"
        )
    expected_sha256 = hashlib.sha256(result.canonical_type.encode("utf-8")).hexdigest()
    if result.canonical_type_sha256 != expected_sha256:
        raise CanonicalTypeGateError(
            f"canonical query type text/hash mismatch for {request.subject_id}"
        )


def _assert_environment_matches_binding(
    environment: CanonicalTypeEnvironmentFacts,
    binding: CanonicalTypeGateBinding,
) -> None:
    if (
        environment.worker_image_digest != binding.worker_image_digest
        or environment.lean_version != binding.lean_version
        or environment.mathlib_revision != binding.mathlib_revision
        or (
            binding.lake_manifest_sha256 is not None
            and environment.lake_manifest_sha256 != binding.lake_manifest_sha256
        )
    ):
        raise CanonicalTypeGateError(
            "canonical query environment differs from the contract-bound environment"
        )


def _assert_observation_binds_request(
    observation: CanonicalTypeObservation,
    request: CanonicalTypeQueryRequest,
    environment: CanonicalTypeEnvironmentFacts,
) -> None:
    observation.query.validate()
    if (
        observation.subject_id != request.subject_id
        or observation.statement_source_hash != request.statement_source_hash
        or observation.declaration != request.declaration
        or observation.environment_facts_sha256 != environment.content_sha256
        or observation.canonical_type_hash
        != digest_text(HashKindV1.ELABORATED_TYPE, observation.canonical_type)
        or observation.canonical_type_sha256
        != hashlib.sha256(observation.canonical_type.encode("utf-8")).hexdigest()
    ):
        raise CanonicalTypeGateError(
            f"canonical type observation is detached from {request.subject_id}"
        )


def _require_sha256(value: str, *, label: str) -> None:
    if not _SHA256_RE.fullmatch(value):
        raise CanonicalTypeGateError(f"canonical query {label} is not a SHA-256 digest")


def query_payload_sha256(document: object) -> str:
    """Hash one normalized query document for adapter evidence."""

    return digest_bytes(HashKindV1.TOOL, canonical_json_bytes(document)).value
