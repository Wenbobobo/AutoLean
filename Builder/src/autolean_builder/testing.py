"""Explicit scripted fixtures for tests; never use these records as promotion evidence."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from autolean_contracts import canonical_json_bytes

from .canonical_type_gate import (
    CanonicalTypeEnvironmentFacts,
    CanonicalTypeGateError,
    CanonicalTypeQueryAssurance,
    CanonicalTypeQueryFacts,
    CanonicalTypeQueryRequest,
    CanonicalTypeQueryResult,
)


@dataclass(frozen=True, slots=True)
class ScriptedCanonicalTypeQuery:
    """Deterministic fake implementing the canonical query protocol for unit fixtures."""

    canonical_types_by_statement_sha256: tuple[tuple[str, str], ...]
    worker_image_digest: str
    lean_version: str
    mathlib_revision: str
    lake_manifest_sha256: str | None = None
    fixture_id: str = "default"

    def query(self, request: CanonicalTypeQueryRequest) -> CanonicalTypeQueryResult:
        canonical_types = dict(self.canonical_types_by_statement_sha256)
        try:
            canonical_type = canonical_types[request.statement_source_hash.value]
        except KeyError as error:
            raise CanonicalTypeGateError(
                "scripted canonical query has no result for the statement hash"
            ) from error
        identity = f"{self.fixture_id}:{request.subject_id}"
        canonical_type_sha256 = _sha256(canonical_type)
        source_snapshot_sha256 = _sha256(request.statement_source)
        observed_axioms: tuple[str, ...] = ()
        observed_axioms_sha256 = _sha256("[]\n")
        query_output_canonical_json = canonical_json_bytes(
            {
                "canonical_type": canonical_type,
                "canonical_type_sha256": canonical_type_sha256,
                "declaration": request.declaration,
                "imports_allowlist": list(request.imports_allowlist),
                "observed_axioms": list(observed_axioms),
                "observed_axioms_sha256": observed_axioms_sha256,
                "schema_version": "autolean.scripted-canonical-query-output.v1",
                "source_snapshot_sha256": source_snapshot_sha256,
                "statement_source_hash": request.statement_source_hash.model_dump(mode="json"),
                "subject_id": request.subject_id,
            }
        ).decode("ascii")
        return CanonicalTypeQueryResult(
            declaration=request.declaration,
            canonical_type=canonical_type,
            canonical_type_sha256=canonical_type_sha256,
            environment=CanonicalTypeEnvironmentFacts(
                assurance=CanonicalTypeQueryAssurance.SCRIPTED_FAKE,
                adapter_id="autolean_builder.testing.ScriptedCanonicalTypeQuery",
                image=f"autolean/scripted-builder-query@{self.worker_image_digest}",
                worker_image_digest=self.worker_image_digest,
                lean_version=self.lean_version,
                mathlib_revision=self.mathlib_revision,
                lake_manifest_sha256=self.lake_manifest_sha256,
                type_format="autolean.lean-pp-expr.v1",
                query_schema_version="autolean.scripted-canonical-query.v1",
                query_protocol="autolean.scripted-canonical-query.v1",
                query_identity_sha256=_sha256(f"{self.fixture_id}:query-identity"),
                build_receipt_canonical_sha256=_sha256(f"{self.fixture_id}:build-receipt"),
                execution_policy_sha256=_sha256(f"{self.fixture_id}:execution-policy"),
                source_inputs_sha256=_sha256(f"{self.fixture_id}:source-inputs"),
                source_rendering_profile="autolean.scripted-header.v1",
            ),
            query=CanonicalTypeQueryFacts(
                query_output_canonical_json=query_output_canonical_json,
                query_output_sha256=_sha256(query_output_canonical_json),
                source_snapshot_sha256=source_snapshot_sha256,
                sealed_candidate_sha256=_sha256(f"{identity}:sealed-candidate"),
                candidate_direct_imports_sha256=_sha256(f"{self.fixture_id}:direct-imports"),
                module_import_closure_sha256=_sha256(f"{self.fixture_id}:import-closure"),
                observed_axioms=observed_axioms,
                observed_axioms_sha256=observed_axioms_sha256,
            ),
        )


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
