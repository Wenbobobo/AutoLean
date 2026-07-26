"""Builder-owned exact canonical elaborated-type gate.

This module compares only the canonical type text emitted by one registered query boundary.  It
does not infer definitional, propositional, or mathematical equivalence.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal, Protocol, cast

from autolean_contracts import (
    DigestV1,
    HashKindV1,
    canonical_json_bytes,
    digest_bytes,
    digest_text,
)
from autolean_contracts.hashing import require_digest_kind

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_DECLARATION_HEADER_RE = re.compile(r"\A(?:theorem|lemma)\b")
_TYPE_FORMAT = "autolean.lean-pp-expr.v1"


class CanonicalTypeGateError(ValueError):
    """A query result cannot establish exact canonical type identity."""


class CanonicalTypeQueryAssurance(StrEnum):
    """The narrow execution assurance carried by one query adapter."""

    SCRIPTED_FAKE = "scripted_fake"
    LOCAL_OCI_PREFREEZE = "local_oci_prefreeze"


_ASSURANCE_PROFILES = {
    CanonicalTypeQueryAssurance.SCRIPTED_FAKE: (
        "autolean_builder.testing.ScriptedCanonicalTypeQuery",
        "autolean.scripted-canonical-query.v1",
        "autolean.scripted-canonical-query.v1",
        "autolean.scripted-header.v1",
    ),
    CanonicalTypeQueryAssurance.LOCAL_OCI_PREFREEZE: (
        "scripts.oci_mathlib_worker.query_declarations",
        "autolean.mathlib-declaration-query-evidence.v1",
        "autolean.mathlib-declaration-query.v1",
        "autolean.declaration-type-observation.v1",
    ),
}
_LOCAL_QUERY_OUTPUT_FIELDS = frozenset(
    {
        "build_receipt_canonical_sha256",
        "execution_policy",
        "execution_policy_sha256",
        "image",
        "observation",
        "schema_version",
        "sealed_candidate_sha256",
        "source_inputs_sha256",
        "source_snapshot_sha256",
    }
)
_LOCAL_OBSERVATION_FIELDS = frozenset(
    {
        "candidate_direct_imports",
        "candidate_direct_imports_sha256",
        "declarations",
        "image_identity",
        "module_import_closure",
        "module_import_closure_sha256",
    }
)
_LOCAL_DECLARATION_FIELDS = frozenset(
    {
        "canonical_type",
        "canonical_type_sha256",
        "declaration",
        "observed_axioms",
        "observed_axioms_sha256",
    }
)
_LOCAL_EXECUTION_POLICY_FIELDS = frozenset(
    {"container_policy", "image", "phases", "schema_version"}
)
_SCRIPTED_QUERY_OUTPUT_FIELDS = frozenset(
    {
        "canonical_type",
        "canonical_type_sha256",
        "declaration",
        "imports_allowlist",
        "observed_axioms",
        "observed_axioms_sha256",
        "schema_version",
        "source_snapshot_sha256",
        "statement_source_hash",
        "subject_id",
    }
)


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


def render_oci_type_query_source(request: CanonicalTypeQueryRequest) -> str:
    """Render the exact local-OCI source snapshot for one declaration-type observation."""

    statement = request.statement_source
    if ":=" in statement:
        carrier = statement
    else:
        match = _DECLARATION_HEADER_RE.match(statement)
        if match is None:
            raise CanonicalTypeGateError(
                "canonical type query requires a theorem or lemma declaration"
            )
        carrier = f"axiom{statement[match.end() :]}"
    imports = [f"import {name}" for name in request.imports_allowlist]
    lines = [*imports]
    if imports:
        lines.append("")
    lines.extend((f"namespace {request.namespace}", "", carrier, ""))
    return "\n".join(lines)


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
        observed_profile = (
            self.adapter_id,
            self.query_schema_version,
            self.query_protocol,
            self.source_rendering_profile,
        )
        if observed_profile != _ASSURANCE_PROFILES[self.assurance]:
            raise CanonicalTypeGateError(
                "canonical query assurance differs from its closed execution profile"
            )
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

    query_output_canonical_json: str
    query_output_sha256: str
    source_snapshot_sha256: str
    sealed_candidate_sha256: str
    candidate_direct_imports_sha256: str
    module_import_closure_sha256: str
    observed_axioms: tuple[str, ...]
    observed_axioms_sha256: str

    def validate(self) -> None:
        query_output = _parse_query_output(self.query_output_canonical_json)
        if (
            self.query_output_sha256
            != hashlib.sha256(canonical_json_bytes(query_output)).hexdigest()
        ):
            raise CanonicalTypeGateError("canonical query output text differs from its hash")
        for label, value in (
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
            "query_output_canonical_json": self.query_output_canonical_json,
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
        _assert_requests_bind_binding(binding, reference, candidates)
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


@dataclass(frozen=True, slots=True)
class BuilderStatementObservationEvidence:
    """Builder-owned bridge evidence for one frozen statement observation.

    This is deliberately not a proof carrier and must never be accepted by the Prover as a
    ProofSubmissionV1. Its only job is to bind the selected statement source, canonical type,
    and query receipt to the Builder handoff boundary before proof search starts.
    """

    contract_id: str
    revision: int
    contract_hash: DigestV1
    selected_statement_hash: DigestV1
    environment_hash: DigestV1
    declaration: str
    observation: CanonicalTypeObservation
    environment: CanonicalTypeEnvironmentFacts
    carrier_non_proof: Literal[True] = True
    promotion_authority: Literal[False] = False
    prover_submission_eligible: Literal[False] = False
    public_protocol_command: Literal["builder_statement_observation"] = (
        "builder_statement_observation"
    )

    @classmethod
    def from_gate_evidence(
        cls,
        evidence: CanonicalTypeGateEvidence,
        *,
        contract_hash: DigestV1,
    ) -> BuilderStatementObservationEvidence:
        """Project exact-type gate evidence into the standardized non-proof bridge record."""

        return cls(
            contract_id=evidence.contract_id,
            revision=evidence.revision,
            contract_hash=contract_hash,
            selected_statement_hash=evidence.selected_statement_hash,
            environment_hash=evidence.environment_hash,
            declaration=evidence.reference.declaration,
            observation=evidence.reference,
            environment=evidence.environment,
        )

    def assert_internal_only(self) -> None:
        """Fail closed if this evidence has been reshaped into a proof-like authority."""

        if (
            self.carrier_non_proof is not True
            or self.promotion_authority is not False
            or self.prover_submission_eligible is not False
            or self.public_protocol_command != "builder_statement_observation"
        ):
            raise CanonicalTypeGateError(
                "Builder statement observation cannot be promoted as proof evidence"
            )
        require_digest_kind(self.contract_hash, HashKindV1.CONTRACT, "contract_hash")
        require_digest_kind(
            self.selected_statement_hash,
            HashKindV1.STATEMENT_SOURCE,
            "selected_statement_hash",
        )
        require_digest_kind(self.environment_hash, HashKindV1.ENVIRONMENT, "environment_hash")
        self.environment.validate()
        _assert_observation_binds_requestless(self.observation, self.environment)
        if (
            self.observation.statement_source_hash != self.selected_statement_hash
            or self.observation.declaration != self.declaration
            or self.observation.environment_facts_sha256 != self.environment.content_sha256
        ):
            raise CanonicalTypeGateError(
                "Builder statement observation is detached from its frozen boundary"
            )

    def assert_binds_frozen_contract(
        self,
        *,
        contract_id: str,
        revision: int,
        contract_hash: DigestV1,
        selected_statement_hash: DigestV1,
        environment_hash: DigestV1,
        declaration: str,
        expected_elaborated_type_hash: DigestV1,
    ) -> None:
        """Validate this record against a frozen contract or Prover proof boundary.

        This is a Builder-side handoff check only. It establishes that the statement observation
        matches the frozen contract hashes the Prover will receive; it does not verify a proof.
        """

        self.assert_internal_only()
        require_digest_kind(
            expected_elaborated_type_hash,
            HashKindV1.ELABORATED_TYPE,
            "expected_elaborated_type_hash",
        )
        if (
            self.contract_id != contract_id
            or self.revision != revision
            or self.contract_hash != contract_hash
            or self.selected_statement_hash != selected_statement_hash
            or self.environment_hash != environment_hash
            or self.declaration != declaration
            or self.observation.canonical_type_hash != expected_elaborated_type_hash
        ):
            raise CanonicalTypeGateError(
                "Builder statement observation does not bind the frozen Prover boundary"
            )

    def payload(self) -> dict[str, object]:
        self.assert_internal_only()
        return {
            "schema_version": "autolean.builder-statement-observation-evidence.v1",
            "authority": "builder_internal_prefreeze_observation",
            "carrier_non_proof": self.carrier_non_proof,
            "promotion_authority": self.promotion_authority,
            "prover_submission_eligible": self.prover_submission_eligible,
            "public_protocol_command": self.public_protocol_command,
            "contract_id": self.contract_id,
            "revision": self.revision,
            "contract_hash": self.contract_hash.model_dump(mode="json"),
            "selected_statement_hash": self.selected_statement_hash.model_dump(mode="json"),
            "environment_hash": self.environment_hash.model_dump(mode="json"),
            "declaration": self.declaration,
            "canonical_type_hash": self.observation.canonical_type_hash.model_dump(mode="json"),
            "canonical_type_sha256": self.observation.canonical_type_sha256,
            "environment": self.environment.payload(),
            "observation": self.observation.payload(),
        }

    @property
    def record_hash(self) -> DigestV1:
        return digest_bytes(
            HashKindV1.FREEZE_EVIDENCE,
            canonical_json_bytes(self.payload()),
        )


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
    _assert_requests_bind_binding(binding, reference, candidates)
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
    _assert_raw_query_output_binds(
        CanonicalTypeObservation.from_result(request, result),
        result.environment,
        request,
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
    _assert_raw_query_output_binds(observation, environment, request)


def _assert_observation_binds_requestless(
    observation: CanonicalTypeObservation,
    environment: CanonicalTypeEnvironmentFacts,
) -> None:
    observation.query.validate()
    if (
        observation.environment_facts_sha256 != environment.content_sha256
        or observation.canonical_type_hash
        != digest_text(HashKindV1.ELABORATED_TYPE, observation.canonical_type)
        or observation.canonical_type_sha256
        != hashlib.sha256(observation.canonical_type.encode("utf-8")).hexdigest()
    ):
        raise CanonicalTypeGateError("Builder statement observation is internally detached")


def _parse_query_output(value: str) -> dict[str, object]:
    try:
        parsed = json.loads(value)
        canonical = canonical_json_bytes(parsed)
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        raise CanonicalTypeGateError(
            "canonical query output is not strict canonical JSON"
        ) from error
    if not isinstance(parsed, dict) or canonical.decode("ascii") != value:
        raise CanonicalTypeGateError("canonical query output is not strict canonical JSON")
    return cast(dict[str, object], parsed)


def _assert_raw_query_output_binds(
    observation: CanonicalTypeObservation,
    environment: CanonicalTypeEnvironmentFacts,
    request: CanonicalTypeQueryRequest,
) -> None:
    document = _parse_query_output(observation.query.query_output_canonical_json)
    if environment.assurance is CanonicalTypeQueryAssurance.SCRIPTED_FAKE:
        _assert_scripted_query_output_binds(document, observation, request)
        return
    _assert_local_oci_query_output_binds(document, observation, environment, request)


def _assert_scripted_query_output_binds(
    document: dict[str, object],
    observation: CanonicalTypeObservation,
    request: CanonicalTypeQueryRequest,
) -> None:
    _require_exact_query_fields(document, _SCRIPTED_QUERY_OUTPUT_FIELDS, label="scripted output")
    axioms = _query_names(document, "observed_axioms")
    if (
        _query_text(document, "schema_version") != "autolean.scripted-canonical-query-output.v1"
        or _query_text(document, "subject_id") != request.subject_id
        or _query_object(document, "statement_source_hash")
        != request.statement_source_hash.model_dump(mode="json")
        or _query_text(document, "declaration") != request.declaration
        or _query_text(document, "canonical_type") != observation.canonical_type
        or _query_sha256(document, "canonical_type_sha256") != observation.canonical_type_sha256
        or tuple(_query_names(document, "imports_allowlist")) != request.imports_allowlist
        or _query_sha256(document, "source_snapshot_sha256")
        != hashlib.sha256(request.statement_source.encode("utf-8")).hexdigest()
        or axioms != observation.query.observed_axioms
        or _query_sha256(document, "observed_axioms_sha256")
        != observation.query.observed_axioms_sha256
    ):
        raise CanonicalTypeGateError(
            f"scripted raw query output is detached from {request.subject_id}"
        )


def _assert_local_oci_query_output_binds(
    document: dict[str, object],
    observation: CanonicalTypeObservation,
    environment: CanonicalTypeEnvironmentFacts,
    request: CanonicalTypeQueryRequest,
) -> None:
    _require_exact_query_fields(document, _LOCAL_QUERY_OUTPUT_FIELDS, label="local OCI output")
    raw_observation = _query_object(document, "observation")
    _require_exact_query_fields(
        raw_observation,
        _LOCAL_OBSERVATION_FIELDS,
        label="local OCI observation",
    )
    declarations = _query_list(raw_observation, "declarations")
    if len(declarations) != 1 or not isinstance(declarations[0], dict):
        raise CanonicalTypeGateError(
            "local OCI raw query output must contain exactly one declaration"
        )
    declaration = cast(dict[str, object], declarations[0])
    _require_exact_query_fields(
        declaration,
        _LOCAL_DECLARATION_FIELDS,
        label="local OCI declaration",
    )
    execution_policy = _query_object(document, "execution_policy")
    _require_exact_query_fields(
        execution_policy,
        _LOCAL_EXECUTION_POLICY_FIELDS,
        label="local OCI execution policy",
    )
    phases = _query_list(execution_policy, "phases")
    query_phases = [
        phase for phase in phases if isinstance(phase, dict) and phase.get("name") == "query"
    ]
    if len(query_phases) != 1:
        raise CanonicalTypeGateError("local OCI execution policy has no unique query phase")
    query_phase = cast(dict[str, object], query_phases[0])
    image_identity = _query_object(raw_observation, "image_identity")
    _require_exact_query_fields(
        image_identity,
        frozenset(
            {
                "query_helper_path",
                "query_helper_sha256",
                "schema_version",
                "wrapper_path",
                "wrapper_sha256",
            }
        ),
        label="local OCI image identity",
    )
    direct_imports = _query_names(raw_observation, "candidate_direct_imports")
    import_closure = _query_names(raw_observation, "module_import_closure")
    axioms = _query_names(declaration, "observed_axioms")
    expected_snapshot = hashlib.sha256(
        render_oci_type_query_source(request).encode("utf-8")
    ).hexdigest()
    if (
        _query_text(document, "schema_version") != environment.query_schema_version
        or _query_text(document, "image") != environment.image
        or _query_sha256(document, "build_receipt_canonical_sha256")
        != environment.build_receipt_canonical_sha256
        or _query_sha256(document, "execution_policy_sha256") != environment.execution_policy_sha256
        or _worker_payload_sha256(execution_policy) != environment.execution_policy_sha256
        or _query_text(execution_policy, "image") != environment.image
        or _query_text(execution_policy, "schema_version")
        != "autolean.mathlib-declaration-execution-policy.v1"
        or query_phase.get("declarations") != [request.declaration]
        or query_phase.get("protocol") != environment.query_protocol
        or _query_sha256(document, "source_inputs_sha256") != environment.source_inputs_sha256
        or _query_sha256(document, "source_snapshot_sha256") != expected_snapshot
        or _query_sha256(document, "source_snapshot_sha256")
        != observation.query.source_snapshot_sha256
        or _query_sha256(document, "sealed_candidate_sha256")
        != observation.query.sealed_candidate_sha256
        or hashlib.sha256(canonical_json_bytes(image_identity)).hexdigest()
        != environment.query_identity_sha256
        or _query_text(image_identity, "schema_version")
        != "autolean.image-owned-declaration-query-identity.v1"
        or _query_text(image_identity, "query_helper_path")
        != "/opt/autolean/lib/AutoleanMathlibDeclarationQuery.lean"
        or _query_text(image_identity, "wrapper_path")
        != "/opt/autolean/bin/autolean-mathlib-declaration-query"
        or _worker_payload_sha256(direct_imports)
        != observation.query.candidate_direct_imports_sha256
        or _query_sha256(raw_observation, "candidate_direct_imports_sha256")
        != observation.query.candidate_direct_imports_sha256
        or _worker_payload_sha256(import_closure) != observation.query.module_import_closure_sha256
        or _query_sha256(raw_observation, "module_import_closure_sha256")
        != observation.query.module_import_closure_sha256
        or not set(direct_imports) <= set(import_closure)
        or "Candidate" not in import_closure
        or not set(request.imports_allowlist) <= set(direct_imports)
        or not set(direct_imports) <= {*request.imports_allowlist, "Init"}
        or _query_text(declaration, "declaration") != observation.declaration
        or _query_text(declaration, "canonical_type") != observation.canonical_type
        or _query_sha256(declaration, "canonical_type_sha256") != observation.canonical_type_sha256
        or axioms != observation.query.observed_axioms
        or _query_sha256(declaration, "observed_axioms_sha256")
        != observation.query.observed_axioms_sha256
    ):
        raise CanonicalTypeGateError(
            f"local OCI raw query output is detached from {request.subject_id}"
        )


def _require_exact_query_fields(
    value: dict[str, object],
    expected: frozenset[str],
    *,
    label: str,
) -> None:
    if set(value) != expected:
        raise CanonicalTypeGateError(f"canonical query {label} has unexpected fields")


def _query_object(value: dict[str, object], key: str) -> dict[str, object]:
    result = value.get(key)
    if not isinstance(result, dict):
        raise CanonicalTypeGateError(f"canonical query {key} is not an object")
    return cast(dict[str, object], result)


def _query_list(value: dict[str, object], key: str) -> list[object]:
    result = value.get(key)
    if not isinstance(result, list):
        raise CanonicalTypeGateError(f"canonical query {key} is not a list")
    return result


def _query_text(value: dict[str, object], key: str) -> str:
    result = value.get(key)
    if not isinstance(result, str) or not result:
        raise CanonicalTypeGateError(f"canonical query {key} is not text")
    return result


def _query_names(value: dict[str, object], key: str) -> tuple[str, ...]:
    result = _query_list(value, key)
    if not all(isinstance(item, str) and item for item in result):
        raise CanonicalTypeGateError(f"canonical query {key} is not a name list")
    names = tuple(cast(list[str], result))
    if names != tuple(sorted(set(names))) or any(item != item.strip() for item in names):
        raise CanonicalTypeGateError(f"canonical query {key} is not sorted and unique")
    return names


def _query_sha256(value: dict[str, object], key: str) -> str:
    result = _query_text(value, key)
    _require_sha256(result, label=key)
    return result


def _worker_payload_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value) + b"\n").hexdigest()


def _assert_requests_bind_binding(
    binding: CanonicalTypeGateBinding,
    reference: CanonicalTypeQueryRequest,
    candidates: tuple[CanonicalTypeQueryRequest, ...],
) -> None:
    if (
        reference.subject_id != "contract-selected-reference"
        or reference.statement_source_hash != binding.selected_statement_hash
        or reference.declaration != binding.declaration
        or any(request.declaration != binding.declaration for request in candidates)
    ):
        raise CanonicalTypeGateError(
            "canonical type query request differs from the contract binding"
        )


def _require_sha256(value: str, *, label: str) -> None:
    if not _SHA256_RE.fullmatch(value):
        raise CanonicalTypeGateError(f"canonical query {label} is not a SHA-256 digest")
