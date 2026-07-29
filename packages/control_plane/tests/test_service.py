from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier

import pytest
from autolean_contracts import (
    ActorKindV1,
    AlignmentTargetV1,
    AttestationPurposeV1,
    EditRegionV1,
    ExecutionGraphV1,
    FidelityEvidenceArtifactRefV1,
    FidelityReportV1,
    FidelityRiskV1,
    FormalGraphV1,
    FormalizationTaskBundleV1,
    FormalSpecificationV1,
    FreezeRecordV1,
    HashKindV1,
    HmacAttestationKeyV1,
    HmacAttestationSignerV1,
    HmacAttestationVerifierV1,
    LeanEnvironmentV1,
    MathematicalGraphV1,
    MathematicalSpecificationV1,
    OciVerifierExecutionPolicyV2,
    PermissionDecisionV1,
    ProofStatusV1,
    ProofSubmissionV1,
    ProvenanceTraceV1,
    ReleaseTierV1,
    RightsRecordV1,
    SourceRecordV1,
    SourceSpanV1,
    StableIdentifierV1,
    StatementContractV1,
    StatementStatusV1,
    TaskKindV1,
    TaskPolicyV1,
    VerificationEvidenceArtifactV1,
    VerificationEvidenceV1,
    VerificationReportV1,
    build_proof_boundary,
    builder_attestation_payload,
    canonical_json_bytes,
    digest_bytes,
    digest_model,
    digest_text,
    proof_dependency_manifest_hash,
    stable_identifier,
    verification_attestation_payload,
)
from autolean_contracts.graphs import (
    GraphBundleV1,
    MathematicalNodeKindV1,
    MathematicalNodeV1,
)
from autolean_control_plane import (
    ArtifactRef,
    ArtifactStore,
    ControlPlane,
    DashboardProjection,
    EventStore,
    Idempotency,
    Lease,
    LeaseStore,
    NewEvent,
    VerificationOutcome,
    export_dashboard_projection,
    request_hash,
)
from autolean_control_plane.errors import (
    IdempotencyConflict,
    InvalidTransition,
    ProjectionError,
    StaleFence,
)
from autolean_control_plane.events import StoredEvent


def _oci_type_query_source_hash(
    *,
    statement_source: str,
    namespace: str,
    imports_allowlist: tuple[str, ...],
) -> str:
    statement = statement_source
    if ":=" in statement:
        carrier = statement
    else:
        for prefix in ("theorem", "lemma"):
            if statement.startswith(prefix):
                carrier = f"axiom{statement[len(prefix) :]}"
                break
        else:  # pragma: no cover - fixture contracts always use theorem/lemma syntax.
            raise AssertionError("fixture statement must be a theorem or lemma")
    lines = [*(f"import {name}" for name in imports_allowlist)]
    if lines:
        lines.append("")
    lines.extend((f"namespace {namespace}", "", carrier, ""))
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def _scripted_query_output(
    *,
    observation: dict[str, object],
    statement_source: str,
    imports_allowlist: tuple[str, ...],
) -> str:
    query = observation["query"]
    assert isinstance(query, dict)
    observed_axioms = query["observed_axioms"]
    assert isinstance(observed_axioms, list)
    statement_source_hash = observation["statement_source_hash"]
    assert isinstance(statement_source_hash, dict)
    return canonical_json_bytes(
        {
            "canonical_type": observation["canonical_type"],
            "canonical_type_sha256": observation["canonical_type_sha256"],
            "declaration": observation["declaration"],
            "imports_allowlist": list(imports_allowlist),
            "observed_axioms": observed_axioms,
            "observed_axioms_sha256": query["observed_axioms_sha256"],
            "schema_version": "autolean.scripted-canonical-query-output.v1",
            "source_snapshot_sha256": hashlib.sha256(statement_source.encode("utf-8")).hexdigest(),
            "statement_source_hash": statement_source_hash,
            "subject_id": observation["subject_id"],
        }
    ).decode("ascii")


def _id(key: str) -> StableIdentifierV1:
    return stable_identifier("control-test", key)


_BUILDER_KEY = HmacAttestationKeyV1(
    key_id="builder-test-v1",
    secret=b"builder-test-secret-material-0123456789",
    allowed_purposes=frozenset({AttestationPurposeV1.BUILDER_FREEZE}),
)
_VERIFIER_KEY = HmacAttestationKeyV1(
    key_id="verifier-test-v1",
    secret=b"verifier-test-secret-material-012345678",
    allowed_purposes=frozenset({AttestationPurposeV1.VERIFICATION}),
)


def _builder_signer(
    clock: Callable[[], datetime] | None = None,
) -> HmacAttestationSignerV1:
    if clock is None:
        return HmacAttestationSignerV1(_BUILDER_KEY)
    return HmacAttestationSignerV1(_BUILDER_KEY, clock=clock)


def _verifier_signer(
    clock: Callable[[], datetime] | None = None,
) -> HmacAttestationSignerV1:
    if clock is None:
        return HmacAttestationSignerV1(_VERIFIER_KEY)
    return HmacAttestationSignerV1(_VERIFIER_KEY, clock=clock)


def _attestation_verifier(
    clock: Callable[[], datetime] | None = None,
) -> HmacAttestationVerifierV1:
    keys = {
        _BUILDER_KEY.key_id: _BUILDER_KEY,
        _VERIFIER_KEY.key_id: _VERIFIER_KEY,
    }
    if clock is None:
        return HmacAttestationVerifierV1(keys)
    return HmacAttestationVerifierV1(keys, clock=clock)


def _bundle(
    *,
    signer: HmacAttestationSignerV1 | None = None,
    nonce: str | None = None,
    bundle_key: str = "bundle",
    additional_source_spans: tuple[SourceSpanV1, ...] = (),
    allowed_edit_regions: tuple[EditRegionV1, ...] = (),
) -> FormalizationTaskBundleV1:
    source_id = _id("source")
    span = SourceSpanV1(
        span_id=_id("span"),
        locator="source:1",
        content_hash=digest_text(HashKindV1.SOURCE_SPAN, "n equals n"),
        permitted_excerpt="n equals n",
    )
    source = SourceRecordV1(
        source_id=source_id,
        work_id="fixture",
        title="Fixture",
        version="1",
        locator="fixture://source",
        content_hash=digest_text(HashKindV1.SOURCE_BYTES, "fixture source"),
        spans=(span, *additional_source_spans),
    )
    rights = RightsRecordV1(
        rights_id=_id("rights"),
        source_id=source_id,
        source_license="CC0-1.0",
        overall_decision=PermissionDecisionV1.ALLOW,
        reviewed_by="reviewer",
        reviewed_at=datetime.now(UTC),
    )
    statement = "theorem fixture (n : Nat) : n = n"
    formal = FormalSpecificationV1(
        declaration_name="fixture",
        namespace="AutoLean.Test",
        lean_statement_source=statement,
        statement_source_hash=digest_text(HashKindV1.STATEMENT_SOURCE, statement),
        elaborated_type="forall (n : Nat), Eq n n",
        elaborated_type_hash=digest_text(HashKindV1.ELABORATED_TYPE, "forall (n : Nat), Eq n n"),
        environment=LeanEnvironmentV1(
            lean_version="v4.28.0",
            mathlib_revision="fixture-mathlib",
            verifier_execution_policy=OciVerifierExecutionPolicyV2(
                worker_image_digest="sha256:" + ("1" * 64),
            ),
            environment_hash=digest_text(HashKindV1.ENVIRONMENT, "fixture-environment"),
        ),
    )
    draft = StatementContractV1(
        contract_id=_id("contract"),
        revision=1,
        task_kind=TaskKindV1.KNOWN_THEOREM,
        source=source,
        rights=rights,
        mathematics=MathematicalSpecificationV1(
            informal_statement="n equals n",
            normalized_statement="For every n : Nat, n equals n.",
        ),
        formal=formal,
        alignments=(
            AlignmentTargetV1(
                source_span_id=span.span_id,
                formal_target="AutoLean.Test.fixture",
                relation="formalizes",
                confidence=1.0,
            ),
        ),
        policy=TaskPolicyV1(
            release_tier=ReleaseTierV1.CALIBRATION,
            fidelity_risk=FidelityRiskV1.L1_SIMPLE,
            allowed_edit_regions=allowed_edit_regions,
        ),
    )
    frozen_payload = draft.model_dump(mode="python", round_trip=True)
    frozen_payload.update(
        {
            "status": StatementStatusV1.FROZEN,
            "freeze": FreezeRecordV1(
                contract_hash=draft.semantic_hash(),
                source_hash=source.content_hash,
                source_preparation_id=stable_identifier(
                    "source-preparation", f"{bundle_key}:fixture"
                ),
                source_preparation_hash=digest_text(
                    HashKindV1.SOURCE_PREPARATION, f"{bundle_key}:fixture"
                ),
                statement_source_hash=formal.statement_source_hash,
                elaborated_type_hash=formal.elaborated_type_hash,
                frozen_by="fixture",
            ),
        }
    )
    frozen = StatementContractV1.model_validate(frozen_payload)
    graphs = GraphBundleV1(
        mathematical=MathematicalGraphV1(
            graph_id=_id("math"),
            revision=1,
            nodes=(
                MathematicalNodeV1(
                    node_id=_id("math-node"),
                    kind=MathematicalNodeKindV1.THEOREM,
                    label="fixture theorem",
                ),
            ),
        ),
        formal=FormalGraphV1(graph_id=_id("formal"), revision=1),
        execution=ExecutionGraphV1(graph_id=_id("execution"), revision=1),
    )
    unsigned = FormalizationTaskBundleV1(
        bundle_id=_id(bundle_key),
        contract=frozen,
        graphs=graphs,
        graph_snapshot_hash=digest_model(HashKindV1.GRAPH_SNAPSHOT, graphs),
        proof_boundary=build_proof_boundary(frozen),
    )
    attestation = (signer or _builder_signer()).issue(
        purpose=AttestationPurposeV1.BUILDER_FREEZE,
        payload=builder_attestation_payload(unsigned),
        evidence_identity="builder-fixture-freeze",
        ttl_seconds=3600,
        nonce=nonce,
    )
    return unsigned.model_copy(update={"builder_attestation": attestation})


def _rebundle(
    bundle: FormalizationTaskBundleV1,
    *,
    bundle_key: str | None = None,
    issued_at: datetime | None = None,
) -> FormalizationTaskBundleV1:
    updates: dict[str, object] = {"builder_attestation": None}
    if bundle_key is not None:
        updates["bundle_id"] = _id(bundle_key)
    if issued_at is not None:
        updates["issued_at"] = issued_at
    unsigned = bundle.model_copy(update=updates)
    attestation = _builder_signer().issue(
        purpose=AttestationPurposeV1.BUILDER_FREEZE,
        payload=builder_attestation_payload(unsigned),
        evidence_identity="builder-fixture-rebundle",
        ttl_seconds=3600,
    )
    return unsigned.model_copy(update={"builder_attestation": attestation})


def _fidelity_payload(draft: StatementContractV1) -> dict[str, object]:
    source_span = draft.source.spans[0]
    source_claims = [
        {
            "span_id": span.span_id.value,
            "locator": span.locator,
            "content_hash": span.content_hash.model_dump(mode="json"),
            "permitted_excerpt": span.permitted_excerpt,
        }
        for span in draft.source.spans
    ]
    obligation = {
        "obligation_id": "conclusion",
        "kind": "conclusion",
        "source_span_ids": [source_span.span_id.value],
        "normalized_fragment": "n equals n",
    }
    task = {
        "contract_id": draft.contract_id.value,
        "revision": draft.revision,
        "draft_contract_hash": draft.semantic_hash().model_dump(mode="json"),
        "source_hash": draft.source.content_hash.model_dump(mode="json"),
        "source_spans": source_claims,
        "informal_statement": draft.mathematics.informal_statement,
        "normalized_statement": draft.mathematics.normalized_statement,
        "normalized_statement_sha256": hashlib.sha256(
            draft.mathematics.normalized_statement.encode("utf-8")
        ).hexdigest(),
        "selected_lean_statement": draft.formal.lean_statement_source,
        "selected_statement_hash": draft.formal.statement_source_hash.model_dump(mode="json"),
        "obligations": [
            {
                **obligation,
                "description": "The source states reflexive equality.",
                "lean_fragment": "n = n",
                "authority": "expert",
            }
        ],
    }
    generation_task = {
        "source_spans": source_claims,
        "mathematics": draft.mathematics.model_dump(mode="json"),
        "formalization": {
            "task_kind": draft.task_kind.value,
            "declaration_name": draft.formal.declaration_name,
            "namespace": draft.formal.namespace,
            "lean_version": draft.formal.environment.lean_version,
            "mathlib_revision": draft.formal.environment.mathlib_revision,
            "imports_allowlist": list(draft.formal.imports_allowlist),
            "axioms_allowlist": list(draft.formal.axioms_allowlist),
            "rendering_profile": "autolean.full-declaration-canonical-type.v1",
        },
        "obligations": [obligation],
    }
    generation_task_hash = digest_bytes(
        HashKindV1.PROMPT,
        canonical_json_bytes(generation_task),
    ).model_dump(mode="json")
    candidates = [
        {
            "candidate_id": f"candidate-{suffix}",
            "actor_id": f"translator-{suffix}",
            "independence_group": f"group-{suffix}",
            "contract_id": task["contract_id"],
            "revision": task["revision"],
            "draft_contract_hash": task["draft_contract_hash"],
            "source_hash": task["source_hash"],
            "normalized_statement_sha256": task["normalized_statement_sha256"],
            "generation_task_hash": generation_task_hash,
            "lean_statement_source": task["selected_lean_statement"],
            "reverse_rendering": task["normalized_statement"],
            "covered_obligation_ids": [obligation["obligation_id"]],
        }
        for suffix in ("a", "b")
    ]
    elaborated_type = draft.formal.elaborated_type
    elaborated_type_hash = draft.formal.elaborated_type_hash
    assert elaborated_type is not None
    assert elaborated_type_hash is not None
    declaration = f"{draft.formal.namespace}.{draft.formal.declaration_name}"
    imports_allowlist = tuple(draft.formal.imports_allowlist)
    worker_image_digest = draft.formal.environment.verifier_execution_policy.worker_image_digest
    image_identity = {
        "query_helper_path": "/opt/autolean/lib/AutoleanMathlibDeclarationQuery.lean",
        "query_helper_sha256": hashlib.sha256(b"query-helper").hexdigest(),
        "schema_version": "autolean.image-owned-declaration-query-identity.v1",
        "wrapper_path": "/opt/autolean/bin/autolean-mathlib-declaration-query",
        "wrapper_sha256": hashlib.sha256(b"query-wrapper").hexdigest(),
    }
    execution_policy = {
        "container_policy": {},
        "image": f"autolean/mathlib-worker@{worker_image_digest}",
        "phases": [
            {
                "name": "query",
                "declarations": [declaration],
                "protocol": "autolean.mathlib-declaration-query.v1",
            }
        ],
        "schema_version": "autolean.mathlib-declaration-execution-policy.v1",
    }
    execution_policy_sha256 = hashlib.sha256(
        canonical_json_bytes(execution_policy) + b"\n"
    ).hexdigest()
    source_inputs_sha256 = hashlib.sha256(b"source-inputs").hexdigest()
    environment = {
        "assurance": "local_oci_prefreeze",
        "adapter_id": "scripts.oci_mathlib_worker.query_declarations",
        "image": f"autolean/mathlib-worker@{worker_image_digest}",
        "worker_image_digest": worker_image_digest,
        "lean_version": draft.formal.environment.lean_version,
        "mathlib_revision": draft.formal.environment.mathlib_revision,
        "lake_manifest_sha256": None,
        "type_format": "autolean.lean-pp-expr.v1",
        "query_schema_version": "autolean.mathlib-declaration-query-evidence.v1",
        "query_protocol": "autolean.mathlib-declaration-query.v1",
        "query_identity_sha256": hashlib.sha256(canonical_json_bytes(image_identity)).hexdigest(),
        "build_receipt_canonical_sha256": hashlib.sha256(b"build-receipt").hexdigest(),
        "execution_policy_sha256": execution_policy_sha256,
        "source_inputs_sha256": source_inputs_sha256,
        "source_rendering_profile": "autolean.declaration-type-observation.v1",
    }
    environment_facts_sha256 = hashlib.sha256(canonical_json_bytes(environment)).hexdigest()
    observed_axioms: list[str] = []
    observed_axioms_sha256 = hashlib.sha256(
        canonical_json_bytes(observed_axioms) + b"\n"
    ).hexdigest()

    def observation(subject_id: str, statement_source: str) -> dict[str, object]:
        statement_source_hash = digest_text(
            HashKindV1.STATEMENT_SOURCE,
            statement_source,
        )
        source_snapshot_sha256 = _oci_type_query_source_hash(
            statement_source=statement_source,
            namespace=draft.formal.namespace,
            imports_allowlist=imports_allowlist,
        )
        sealed_candidate_sha256 = hashlib.sha256(
            f"{subject_id}:sealed-candidate".encode()
        ).hexdigest()
        direct_imports = tuple(sorted({*imports_allowlist, "Init"}))
        import_closure = tuple(sorted({*direct_imports, "Candidate"}))
        candidate_direct_imports_sha256 = hashlib.sha256(
            canonical_json_bytes(direct_imports) + b"\n"
        ).hexdigest()
        module_import_closure_sha256 = hashlib.sha256(
            canonical_json_bytes(import_closure) + b"\n"
        ).hexdigest()
        query_output = {
            "build_receipt_canonical_sha256": environment["build_receipt_canonical_sha256"],
            "execution_policy": execution_policy,
            "execution_policy_sha256": execution_policy_sha256,
            "image": environment["image"],
            "observation": {
                "candidate_direct_imports": list(direct_imports),
                "candidate_direct_imports_sha256": candidate_direct_imports_sha256,
                "declarations": [
                    {
                        "canonical_type": elaborated_type,
                        "canonical_type_sha256": hashlib.sha256(
                            elaborated_type.encode("utf-8")
                        ).hexdigest(),
                        "declaration": declaration,
                        "observed_axioms": observed_axioms,
                        "observed_axioms_sha256": observed_axioms_sha256,
                    }
                ],
                "image_identity": image_identity,
                "module_import_closure": list(import_closure),
                "module_import_closure_sha256": module_import_closure_sha256,
            },
            "schema_version": environment["query_schema_version"],
            "sealed_candidate_sha256": sealed_candidate_sha256,
            "source_inputs_sha256": source_inputs_sha256,
            "source_snapshot_sha256": source_snapshot_sha256,
        }
        query_output_canonical_json = canonical_json_bytes(query_output).decode("ascii")
        return {
            "subject_id": subject_id,
            "statement_source_hash": statement_source_hash.model_dump(mode="json"),
            "declaration": declaration,
            "canonical_type": elaborated_type,
            "canonical_type_hash": elaborated_type_hash.model_dump(mode="json"),
            "canonical_type_sha256": hashlib.sha256(elaborated_type.encode("utf-8")).hexdigest(),
            "environment_facts_sha256": environment_facts_sha256,
            "query": {
                "query_output_canonical_json": query_output_canonical_json,
                "query_output_sha256": hashlib.sha256(
                    query_output_canonical_json.encode("ascii")
                ).hexdigest(),
                "source_snapshot_sha256": source_snapshot_sha256,
                "sealed_candidate_sha256": sealed_candidate_sha256,
                "candidate_direct_imports_sha256": candidate_direct_imports_sha256,
                "module_import_closure_sha256": module_import_closure_sha256,
                "observed_axioms": observed_axioms,
                "observed_axioms_sha256": observed_axioms_sha256,
            },
        }

    canonical_evidence = {
        "schema_version": "autolean.builder-canonical-type-gate.v1",
        "claim": "exact_canonical_printer_text_identity",
        "definitional_equivalence_claimed": False,
        "semantic_equivalence_claimed": False,
        "promotion_authority": False,
        "contract_id": draft.contract_id.value,
        "revision": draft.revision,
        "draft_contract_hash": task["draft_contract_hash"],
        "source_hash": task["source_hash"],
        "generation_task_hash": generation_task_hash,
        "selected_statement_hash": task["selected_statement_hash"],
        "environment_hash": draft.formal.environment.environment_hash.model_dump(mode="json"),
        "expected_elaborated_type_hash": elaborated_type_hash.model_dump(mode="json"),
        "environment": environment,
        "reference": observation(
            "contract-selected-reference",
            draft.formal.lean_statement_source,
        ),
        "candidates": [
            observation(
                str(candidate["candidate_id"]),
                str(candidate["lean_statement_source"]),
            )
            for candidate in candidates
        ],
    }
    canonical_evidence_bytes = canonical_json_bytes(canonical_evidence)
    canonical_check_envelope = {
        "schema_version": "autolean.builder-canonical-type-check.v1",
        "record": canonical_evidence,
        "record_hash": digest_bytes(
            HashKindV1.FREEZE_EVIDENCE,
            canonical_evidence_bytes,
        ).model_dump(mode="json"),
    }
    return {
        "schema_version": "autolean.builder-fidelity-evidence.v1",
        "task": task,
        "generation_task": generation_task,
        "generation_task_hash": generation_task_hash,
        "candidates": candidates,
        "mutation_agent_id": "mutation-agent",
        "mutation_probes": [],
        "review": {"review_id": "fixture-review"},
        "automatic_checks": [
            {
                "check_name": "canonical_elaborated_type_identity",
                "authority": "automatic",
                "passed": True,
                "evidence": canonical_json_bytes(canonical_check_envelope).decode("ascii"),
            }
        ],
        "additional_signoffs": [],
    }


def _reviewed_bundle(
    artifact_store: ArtifactStore,
    *,
    fidelity_payload: dict[str, object] | None = None,
    base: FormalizationTaskBundleV1 | None = None,
) -> tuple[FormalizationTaskBundleV1, dict[str, object]]:
    base = _bundle() if base is None else base
    assert base.contract.freeze is not None
    draft = base.contract.model_copy(update={"status": StatementStatusV1.DRAFT, "freeze": None})
    payload = _fidelity_payload(draft) if fidelity_payload is None else fidelity_payload
    raw = canonical_json_bytes(payload)
    artifact = artifact_store.put_bytes(raw)
    evidence_hash = digest_bytes(HashKindV1.FREEZE_EVIDENCE, raw)
    reviewed_draft = draft.model_copy(
        update={
            "fidelity": FidelityReportV1(
                report_id=_id("fidelity-report"),
                evidence_hash=evidence_hash,
                risk_level=draft.policy.fidelity_risk,
            )
        }
    )
    frozen = reviewed_draft.model_copy(
        update={
            "status": StatementStatusV1.FROZEN,
            "freeze": FreezeRecordV1(
                contract_hash=reviewed_draft.semantic_hash(),
                source_hash=reviewed_draft.source.content_hash,
                source_preparation_id=base.contract.freeze.source_preparation_id,
                source_preparation_hash=base.contract.freeze.source_preparation_hash,
                statement_source_hash=reviewed_draft.formal.statement_source_hash,
                elaborated_type_hash=reviewed_draft.formal.elaborated_type_hash,
                frozen_by="fixture",
            ),
        }
    )
    unsigned = FormalizationTaskBundleV1(
        bundle_id=base.bundle_id,
        contract=frozen,
        graphs=base.graphs,
        graph_snapshot_hash=base.graph_snapshot_hash,
        proof_boundary=build_proof_boundary(frozen),
        fidelity_evidence=FidelityEvidenceArtifactRefV1(
            digest=evidence_hash,
            size=artifact.size,
        ),
    )
    attestation = _builder_signer().issue(
        purpose=AttestationPurposeV1.BUILDER_FREEZE,
        payload=builder_attestation_payload(unsigned),
        evidence_identity=artifact.uri,
        ttl_seconds=3600,
    )
    return unsigned.model_copy(update={"builder_attestation": attestation}), payload


def _refresh_generation_task_hash(payload: dict[str, object]) -> None:
    generation_task = payload["generation_task"]
    assert isinstance(generation_task, dict)
    generation_task_hash = digest_bytes(
        HashKindV1.PROMPT,
        canonical_json_bytes(generation_task),
    ).model_dump(mode="json")
    payload["generation_task_hash"] = generation_task_hash
    candidates = payload["candidates"]
    assert isinstance(candidates, list)
    for candidate in candidates:
        assert isinstance(candidate, dict)
        candidate["generation_task_hash"] = generation_task_hash
    canonical_evidence = _canonical_evidence_payload(payload)
    canonical_evidence["generation_task_hash"] = generation_task_hash
    _replace_canonical_evidence_payload(payload, canonical_evidence)


def _canonical_evidence_payload(payload: dict[str, object]) -> dict[str, object]:
    checks = payload["automatic_checks"]
    assert isinstance(checks, list)
    matches = [
        check
        for check in checks
        if isinstance(check, dict)
        and check.get("check_name") == "canonical_elaborated_type_identity"
    ]
    assert len(matches) == 1
    evidence_text = matches[0]["evidence"]
    assert isinstance(evidence_text, str)
    envelope = json.loads(evidence_text)
    assert isinstance(envelope, dict)
    evidence = envelope["record"]
    assert isinstance(evidence, dict)
    return evidence


def _replace_canonical_evidence_payload(
    payload: dict[str, object],
    evidence: dict[str, object],
) -> None:
    checks = payload["automatic_checks"]
    assert isinstance(checks, list)
    canonical_check = checks[0]
    assert isinstance(canonical_check, dict)
    evidence_bytes = canonical_json_bytes(evidence)
    canonical_check["evidence"] = canonical_json_bytes(
        {
            "schema_version": "autolean.builder-canonical-type-check.v1",
            "record": evidence,
            "record_hash": digest_bytes(
                HashKindV1.FREEZE_EVIDENCE,
                evidence_bytes,
            ).model_dump(mode="json"),
        }
    ).decode("ascii")


def _plane(
    tmp_path: Path,
    *,
    clock: Callable[[], datetime] | None = None,
    allow_test_only_unreviewed_bundles: bool = True,
    allow_test_only_non_authoritative_canonical_type_evidence: bool = True,
) -> ControlPlane:
    database = tmp_path / "control.db"
    return ControlPlane(
        events=EventStore(database, clock=clock),
        leases=LeaseStore(database, clock=clock),
        artifacts=ArtifactStore(tmp_path / "artifacts"),
        attestation_verifier=_attestation_verifier(clock),
        allow_test_only_direct_verifier_attestations=True,
        allow_test_only_unreviewed_bundles=allow_test_only_unreviewed_bundles,
        allow_test_only_non_authoritative_canonical_type_evidence=(
            allow_test_only_non_authoritative_canonical_type_evidence
        ),
    )


def _submission(bundle: FormalizationTaskBundleV1) -> ProofSubmissionV1:
    source = "by\n  rfl"
    return ProofSubmissionV1(
        proof_id=_id("proof"),
        contract_id=bundle.contract.contract_id,
        revision=bundle.contract.revision,
        contract_hash=bundle.contract.semantic_hash(),
        proof_boundary_hash=bundle.proof_boundary.boundary_hash,
        proof_source=source,
        proof_source_hash=digest_text(HashKindV1.PROOF_SOURCE, source),
        environment_hash=bundle.contract.formal.environment.environment_hash,
        provenance=(
            ProvenanceTraceV1(
                trace_id=_id("proof-provenance"),
                actor_id="control-plane-test-worker",
                actor_kind=ActorKindV1.TOOL,
            ),
        ),
    )


def test_control_plane_requires_events_and_leases_to_share_one_database(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="share one SQLite database"):
        ControlPlane(
            events=EventStore(tmp_path / "events.db"),
            leases=LeaseStore(tmp_path / "leases.db"),
            artifacts=ArtifactStore(tmp_path / "artifacts"),
            attestation_verifier=_attestation_verifier(),
        )


def test_fenced_events_persist_the_leased_task_bundle_binding_and_reject_cross_task_replays(
    tmp_path: Path,
) -> None:
    database = tmp_path / "control.db"
    store = EventStore(database)
    leases = LeaseStore(database)
    lease_a = leases.claim("bundle-a", "worker-a", ttl_seconds=60)
    idempotency = Idempotency(
        scope="fenced-test",
        key="one-command",
        request_hash=request_hash({"task_id": "bundle-a", "proof_id": "proof-a"}),
    )
    event = NewEvent("proof.submitted", payload={"bundle_id": "bundle-a"})

    committed = store.append_fenced(
        "proof",
        "proof-a",
        task_id="bundle-a",
        lease=lease_a,
        expected_sequence=0,
        events=(event,),
        idempotency=idempotency,
    )
    replayed = store.append_fenced(
        "proof",
        "proof-a",
        task_id="bundle-a",
        lease=lease_a,
        expected_sequence=0,
        events=(event,),
        idempotency=idempotency,
    )
    assert replayed == committed
    assert store.read_stream("proof", "proof-a")[0].payload["bundle_id"] == "bundle-a"

    with pytest.raises(ValueError, match="bundle_id must match task_id"):
        store.append_fenced(
            "proof",
            "proof-cross-payload",
            task_id="bundle-a",
            lease=lease_a,
            expected_sequence=0,
            events=(NewEvent("proof.submitted", payload={"bundle_id": "bundle-b"}),),
        )

    lease_b = leases.claim("bundle-b", "worker-b", ttl_seconds=60)
    with pytest.raises(IdempotencyConflict, match="requested fenced task"):
        store.append_fenced(
            "proof",
            "proof-cross-task",
            task_id="bundle-b",
            lease=lease_b,
            expected_sequence=0,
            events=(NewEvent("proof.submitted", payload={"bundle_id": "bundle-b"}),),
            idempotency=idempotency,
        )
    assert store.count_events(entity_type="proof") == 1


def test_control_plane_rejects_unreviewed_bundle_by_default(tmp_path: Path) -> None:
    database = tmp_path / "control.db"
    plane = ControlPlane(
        events=EventStore(database),
        leases=LeaseStore(database),
        artifacts=ArtifactStore(tmp_path / "artifacts"),
        attestation_verifier=_attestation_verifier(),
    )

    with pytest.raises(InvalidTransition, match="fidelity artifact is required"):
        plane.register_bundle(_bundle(), idempotency_key="unreviewed")


def test_control_plane_rejects_legacy_bundle_without_source_preparation(
    tmp_path: Path,
) -> None:
    bundle = _bundle()
    freeze = bundle.contract.freeze
    assert freeze is not None
    legacy_contract = bundle.contract.model_copy(
        update={
            "freeze": freeze.model_copy(
                update={
                    "source_preparation_id": None,
                    "source_preparation_hash": None,
                }
            )
        }
    )
    legacy_bundle = bundle.model_copy(update={"contract": legacy_contract})

    with pytest.raises(InvalidTransition, match="source-preparation evidence"):
        _plane(tmp_path).register_bundle(
            legacy_bundle,
            idempotency_key="legacy-source-preparation",
        )


def test_registration_accepts_a_complete_v1_fidelity_artifact(tmp_path: Path) -> None:
    plane = _plane(tmp_path)
    bundle, payload = _reviewed_bundle(plane.artifacts)

    expected_generation_hash = digest_bytes(
        HashKindV1.PROMPT,
        canonical_json_bytes(payload["generation_task"]),
    )
    assert not canonical_json_bytes(payload["generation_task"]).endswith(b"\n")
    assert payload["generation_task_hash"] == expected_generation_hash.model_dump(mode="json")

    binding = plane.register_bundle(bundle, idempotency_key="reviewed-v1")

    assert binding.fidelity_evidence_artifact is not None
    assert binding.fidelity_evidence_artifact.digest == bundle.fidelity_evidence.digest.value
    assert binding.canonical_type_assurance == "local_oci_prefreeze"
    assert binding.canonical_type_promotion_authority is False
    registered = plane.events.read_stream("task", bundle.bundle_id.value)[0]
    assert registered.payload["canonical_type_assurance"] == "local_oci_prefreeze"
    assert registered.payload["canonical_type_promotion_authority"] is False


def test_registration_rejects_local_prefreeze_evidence_without_test_only_mode(
    tmp_path: Path,
) -> None:
    plane = _plane(
        tmp_path,
        allow_test_only_non_authoritative_canonical_type_evidence=False,
    )
    bundle, _ = _reviewed_bundle(plane.artifacts)

    with pytest.raises(InvalidTransition, match="non-authoritative canonical type evidence"):
        plane.register_bundle(bundle, idempotency_key="local-prefreeze-default-reject")


def test_registration_rejects_fidelity_artifact_without_canonical_type_check(
    tmp_path: Path,
) -> None:
    plane = _plane(tmp_path)
    base, payload = _reviewed_bundle(plane.artifacts)
    missing_payload = json.loads(canonical_json_bytes(payload))
    assert isinstance(missing_payload, dict)
    missing_payload["automatic_checks"] = []
    missing, _ = _reviewed_bundle(
        plane.artifacts,
        fidelity_payload=missing_payload,
        base=base,
    )

    with pytest.raises(InvalidTransition, match="exactly one canonical type check"):
        plane.register_bundle(missing, idempotency_key="missing-canonical-type-check")


def test_registration_rejects_canonical_type_record_hash_drift(tmp_path: Path) -> None:
    plane = _plane(tmp_path)
    base, payload = _reviewed_bundle(plane.artifacts)
    tampered_payload = json.loads(canonical_json_bytes(payload))
    assert isinstance(tampered_payload, dict)
    checks = tampered_payload["automatic_checks"]
    assert isinstance(checks, list)
    check = checks[0]
    assert isinstance(check, dict)
    evidence_text = check["evidence"]
    assert isinstance(evidence_text, str)
    envelope = json.loads(evidence_text)
    assert isinstance(envelope, dict)
    record = envelope["record"]
    assert isinstance(record, dict)
    record["contract_id"] = _id("detached-canonical-record").value
    check["evidence"] = canonical_json_bytes(envelope).decode("ascii")
    tampered, _ = _reviewed_bundle(
        plane.artifacts,
        fidelity_payload=tampered_payload,
        base=base,
    )

    with pytest.raises(InvalidTransition, match="record hash is inconsistent"):
        plane.register_bundle(tampered, idempotency_key="canonical-record-hash-drift")


def test_registration_rejects_detached_candidate_canonical_type(
    tmp_path: Path,
) -> None:
    plane = _plane(tmp_path)
    base, payload = _reviewed_bundle(plane.artifacts)
    tampered_payload = json.loads(canonical_json_bytes(payload))
    assert isinstance(tampered_payload, dict)
    canonical_evidence = _canonical_evidence_payload(tampered_payload)
    observations = canonical_evidence["candidates"]
    assert isinstance(observations, list)
    first = observations[0]
    assert isinstance(first, dict)
    first["canonical_type"] = "True"
    _replace_canonical_evidence_payload(tampered_payload, canonical_evidence)
    tampered, _ = _reviewed_bundle(
        plane.artifacts,
        fidelity_payload=tampered_payload,
        base=base,
    )

    with pytest.raises(InvalidTransition, match="differs from its Builder inputs"):
        plane.register_bundle(tampered, idempotency_key="detached-canonical-candidate")


@pytest.mark.parametrize(
    ("field", "expected_error"),
    (
        ("query_output_sha256", "query output hash is inconsistent"),
        ("observed_axioms_sha256", "observed axiom hash is inconsistent"),
        ("environment_facts_sha256", "differs from its Builder inputs"),
        ("canonical_type_sha256", "differs from its Builder inputs"),
        ("canonical_type_hash", "differs from its Builder inputs"),
    ),
)
def test_registration_recomputes_canonical_evidence_derived_fields(
    tmp_path: Path,
    field: str,
    expected_error: str,
) -> None:
    plane = _plane(tmp_path)
    base, payload = _reviewed_bundle(plane.artifacts)
    tampered_payload = json.loads(canonical_json_bytes(payload))
    assert isinstance(tampered_payload, dict)
    canonical_evidence = _canonical_evidence_payload(tampered_payload)
    observations = canonical_evidence["candidates"]
    assert isinstance(observations, list)
    observation = observations[0]
    assert isinstance(observation, dict)
    if field in {"query_output_sha256", "observed_axioms_sha256"}:
        query = observation["query"]
        assert isinstance(query, dict)
        query[field] = "0" * 64
    elif field == "canonical_type_hash":
        canonical_type_hash = observation[field]
        assert isinstance(canonical_type_hash, dict)
        canonical_type_hash["value"] = "0" * 64
    else:
        observation[field] = "0" * 64
    _replace_canonical_evidence_payload(tampered_payload, canonical_evidence)
    tampered, _ = _reviewed_bundle(
        plane.artifacts,
        fidelity_payload=tampered_payload,
        base=base,
    )

    with pytest.raises(InvalidTransition, match=expected_error):
        plane.register_bundle(
            tampered,
            idempotency_key=f"tampered-canonical-derived-field-{field}",
        )


def test_registration_rejects_unrelated_raw_canonical_query_output(
    tmp_path: Path,
) -> None:
    plane = _plane(
        tmp_path,
        allow_test_only_non_authoritative_canonical_type_evidence=True,
    )
    base, payload = _reviewed_bundle(plane.artifacts)
    tampered_payload = json.loads(canonical_json_bytes(payload))
    assert isinstance(tampered_payload, dict)
    canonical_evidence = _canonical_evidence_payload(tampered_payload)
    observations = [canonical_evidence["reference"], *canonical_evidence["candidates"]]
    unrelated_raw = canonical_json_bytes({"unrelated": "valid canonical JSON"}).decode("ascii")
    for observation in observations:
        assert isinstance(observation, dict)
        query = observation["query"]
        assert isinstance(query, dict)
        query["query_output_canonical_json"] = unrelated_raw
        query["query_output_sha256"] = hashlib.sha256(unrelated_raw.encode("ascii")).hexdigest()
    _replace_canonical_evidence_payload(tampered_payload, canonical_evidence)
    tampered, _ = _reviewed_bundle(
        plane.artifacts,
        fidelity_payload=tampered_payload,
        base=base,
    )

    with pytest.raises(InvalidTransition, match="unexpected or missing fields"):
        plane.register_bundle(tampered, idempotency_key="unrelated-raw-canonical-query")


def test_registration_rejects_coupled_typed_axiom_and_environment_tamper(
    tmp_path: Path,
) -> None:
    plane = _plane(
        tmp_path,
        allow_test_only_non_authoritative_canonical_type_evidence=True,
    )
    base, payload = _reviewed_bundle(plane.artifacts)
    tampered_payload = json.loads(canonical_json_bytes(payload))
    assert isinstance(tampered_payload, dict)
    canonical_evidence = _canonical_evidence_payload(tampered_payload)
    environment = canonical_evidence["environment"]
    assert isinstance(environment, dict)
    environment["query_identity_sha256"] = "9" * 64
    environment_facts_sha256 = hashlib.sha256(canonical_json_bytes(environment)).hexdigest()
    observations = [canonical_evidence["reference"], *canonical_evidence["candidates"]]
    tampered_axioms = ["Injected.axiom"]
    tampered_axioms_sha256 = hashlib.sha256(
        canonical_json_bytes(tampered_axioms) + b"\n"
    ).hexdigest()
    for observation in observations:
        assert isinstance(observation, dict)
        observation["environment_facts_sha256"] = environment_facts_sha256
        query = observation["query"]
        assert isinstance(query, dict)
        query["observed_axioms"] = tampered_axioms
        query["observed_axioms_sha256"] = tampered_axioms_sha256
    _replace_canonical_evidence_payload(tampered_payload, canonical_evidence)
    tampered, _ = _reviewed_bundle(
        plane.artifacts,
        fidelity_payload=tampered_payload,
        base=base,
    )

    with pytest.raises(InvalidTransition, match="raw query output is detached"):
        plane.register_bundle(tampered, idempotency_key="coupled-canonical-tamper")


def test_scripted_canonical_type_evidence_requires_explicit_test_only_mode(
    tmp_path: Path,
) -> None:
    rejecting_plane = _plane(
        tmp_path / "rejecting",
        allow_test_only_non_authoritative_canonical_type_evidence=False,
    )
    base, payload = _reviewed_bundle(rejecting_plane.artifacts)
    scripted_payload = json.loads(canonical_json_bytes(payload))
    assert isinstance(scripted_payload, dict)
    canonical_evidence = _canonical_evidence_payload(scripted_payload)
    environment = canonical_evidence["environment"]
    assert isinstance(environment, dict)
    environment["assurance"] = "scripted_fake"
    observations = [canonical_evidence["reference"], *canonical_evidence["candidates"]]
    environment_facts_sha256 = hashlib.sha256(canonical_json_bytes(environment)).hexdigest()
    raw_candidates = scripted_payload["candidates"]
    assert isinstance(raw_candidates, list)
    statement_sources = [
        base.contract.formal.lean_statement_source,
        *[
            str(candidate["lean_statement_source"])
            for candidate in raw_candidates
            if isinstance(candidate, dict)
        ],
    ]
    for observation, statement_source in zip(observations, statement_sources, strict=True):
        assert isinstance(observation, dict)
        observation["environment_facts_sha256"] = environment_facts_sha256
        query = observation["query"]
        assert isinstance(query, dict)
        query_output_canonical_json = _scripted_query_output(
            observation=observation,
            statement_source=statement_source,
            imports_allowlist=tuple(base.contract.formal.imports_allowlist),
        )
        query["query_output_canonical_json"] = query_output_canonical_json
        query["query_output_sha256"] = hashlib.sha256(
            query_output_canonical_json.encode("ascii")
        ).hexdigest()
        query["source_snapshot_sha256"] = hashlib.sha256(
            statement_source.encode("utf-8")
        ).hexdigest()
    _replace_canonical_evidence_payload(scripted_payload, canonical_evidence)
    scripted, _ = _reviewed_bundle(
        rejecting_plane.artifacts,
        fidelity_payload=scripted_payload,
        base=base,
    )

    with pytest.raises(InvalidTransition, match="non-authoritative canonical type evidence"):
        rejecting_plane.register_bundle(scripted, idempotency_key="scripted-default-reject")

    relabeling_plane = _plane(
        tmp_path / "relabeling",
        allow_test_only_non_authoritative_canonical_type_evidence=True,
    )
    relabeled, _ = _reviewed_bundle(
        relabeling_plane.artifacts,
        fidelity_payload=scripted_payload,
    )
    with pytest.raises(InvalidTransition, match="closed execution profile"):
        relabeling_plane.register_bundle(relabeled, idempotency_key="scripted-relabel-reject")

    environment.update(
        {
            "adapter_id": "autolean_builder.testing.ScriptedCanonicalTypeQuery",
            "query_schema_version": "autolean.scripted-canonical-query.v1",
            "query_protocol": "autolean.scripted-canonical-query.v1",
            "source_rendering_profile": "autolean.scripted-header.v1",
        }
    )
    environment_facts_sha256 = hashlib.sha256(canonical_json_bytes(environment)).hexdigest()
    for observation in observations:
        assert isinstance(observation, dict)
        observation["environment_facts_sha256"] = environment_facts_sha256
    _replace_canonical_evidence_payload(scripted_payload, canonical_evidence)

    allowing_plane = _plane(
        tmp_path / "allowing",
        allow_test_only_non_authoritative_canonical_type_evidence=True,
    )
    allowed, _ = _reviewed_bundle(
        allowing_plane.artifacts,
        fidelity_payload=scripted_payload,
    )
    binding = allowing_plane.register_bundle(
        allowed,
        idempotency_key="scripted-explicit-test-mode",
    )
    assert binding.fidelity_evidence_artifact is not None


def test_registration_rejects_legacy_reviewed_v1_without_generation_task(
    tmp_path: Path,
) -> None:
    plane = _plane(tmp_path)
    base, payload = _reviewed_bundle(plane.artifacts)
    legacy_payload = json.loads(canonical_json_bytes(payload))
    assert isinstance(legacy_payload, dict)
    legacy_payload.pop("generation_task")
    legacy_payload.pop("generation_task_hash")
    legacy, _ = _reviewed_bundle(
        plane.artifacts,
        fidelity_payload=legacy_payload,
        base=base,
    )

    with pytest.raises(InvalidTransition, match="unexpected or missing fields"):
        plane.register_bundle(legacy, idempotency_key="legacy-reviewed-v1")


def test_registration_rejects_wrong_top_level_generation_task_hash(tmp_path: Path) -> None:
    plane = _plane(tmp_path)
    base, payload = _reviewed_bundle(plane.artifacts)
    tampered_payload = json.loads(canonical_json_bytes(payload))
    assert isinstance(tampered_payload, dict)
    top_hash = tampered_payload["generation_task_hash"]
    assert isinstance(top_hash, dict)
    top_hash["value"] = "0" * 64
    tampered, _ = _reviewed_bundle(
        plane.artifacts,
        fidelity_payload=tampered_payload,
        base=base,
    )

    with pytest.raises(InvalidTransition, match="does not match generation_task_hash"):
        plane.register_bundle(tampered, idempotency_key="wrong-top-level-generation-hash")


def test_registration_rejects_wrong_candidate_generation_task_hash(tmp_path: Path) -> None:
    plane = _plane(tmp_path)
    base, payload = _reviewed_bundle(plane.artifacts)
    tampered_payload = json.loads(canonical_json_bytes(payload))
    assert isinstance(tampered_payload, dict)
    candidates = tampered_payload["candidates"]
    assert isinstance(candidates, list)
    first_candidate = candidates[0]
    assert isinstance(first_candidate, dict)
    candidate_hash = first_candidate["generation_task_hash"]
    assert isinstance(candidate_hash, dict)
    candidate_hash["value"] = "1" * 64
    tampered, _ = _reviewed_bundle(
        plane.artifacts,
        fidelity_payload=tampered_payload,
        base=base,
    )

    with pytest.raises(InvalidTransition, match="candidate 0 has a different generation task hash"):
        plane.register_bundle(tampered, idempotency_key="wrong-candidate-generation-hash")


def test_registration_rejects_generation_projection_content_drift(tmp_path: Path) -> None:
    plane = _plane(tmp_path)
    base, payload = _reviewed_bundle(plane.artifacts)
    tampered_payload = json.loads(canonical_json_bytes(payload))
    assert isinstance(tampered_payload, dict)
    generation_task = tampered_payload["generation_task"]
    assert isinstance(generation_task, dict)
    formalization = generation_task["formalization"]
    assert isinstance(formalization, dict)
    formalization["declaration_name"] = "different_fixture"
    generation_task_hash = digest_bytes(
        HashKindV1.PROMPT,
        canonical_json_bytes(generation_task),
    ).model_dump(mode="json")
    tampered_payload["generation_task_hash"] = generation_task_hash
    candidates = tampered_payload["candidates"]
    assert isinstance(candidates, list)
    for candidate in candidates:
        assert isinstance(candidate, dict)
        candidate["generation_task_hash"] = generation_task_hash
    tampered, _ = _reviewed_bundle(
        plane.artifacts,
        fidelity_payload=tampered_payload,
        base=base,
    )

    with pytest.raises(InvalidTransition, match="differs from the Builder projection"):
        plane.register_bundle(tampered, idempotency_key="generation-projection-drift")


def test_registration_rejects_extra_generation_task_fields(tmp_path: Path) -> None:
    plane = _plane(tmp_path)
    base, payload = _reviewed_bundle(plane.artifacts)
    tampered_payload = json.loads(canonical_json_bytes(payload))
    assert isinstance(tampered_payload, dict)
    generation_task = tampered_payload["generation_task"]
    assert isinstance(generation_task, dict)
    generation_task["selected_formal_answer"] = "forbidden extra"
    tampered, _ = _reviewed_bundle(
        plane.artifacts,
        fidelity_payload=tampered_payload,
        base=base,
    )

    with pytest.raises(InvalidTransition, match="differs from the Builder projection"):
        plane.register_bundle(tampered, idempotency_key="extra-generation-field")


@pytest.mark.parametrize("allow_test_only_unreviewed_bundles", (False, True))
def test_registration_rejects_selected_lean_source_as_generation_fragment(
    tmp_path: Path,
    allow_test_only_unreviewed_bundles: bool,
) -> None:
    plane = _plane(
        tmp_path,
        allow_test_only_unreviewed_bundles=allow_test_only_unreviewed_bundles,
    )
    base, payload = _reviewed_bundle(plane.artifacts)
    tampered_payload = json.loads(canonical_json_bytes(payload))
    assert isinstance(tampered_payload, dict)
    task = tampered_payload["task"]
    generation_task = tampered_payload["generation_task"]
    assert isinstance(task, dict) and isinstance(generation_task, dict)
    task_obligations = task["obligations"]
    generation_obligations = generation_task["obligations"]
    assert isinstance(task_obligations, list) and isinstance(generation_obligations, list)
    assert isinstance(task_obligations[0], dict) and isinstance(generation_obligations[0], dict)
    task_obligations[0]["normalized_fragment"] = base.contract.formal.lean_statement_source
    generation_obligations[0]["normalized_fragment"] = base.contract.formal.lean_statement_source
    _refresh_generation_task_hash(tampered_payload)
    tampered, _ = _reviewed_bundle(
        plane.artifacts,
        fidelity_payload=tampered_payload,
        base=base,
    )

    with pytest.raises(InvalidTransition, match="fragment is absent"):
        plane.register_bundle(tampered, idempotency_key="selected-lean-fragment")


def test_registration_rejects_task_and_generation_source_span_drift(tmp_path: Path) -> None:
    plane = _plane(tmp_path)
    base, payload = _reviewed_bundle(plane.artifacts)
    tampered_payload = json.loads(canonical_json_bytes(payload))
    assert isinstance(tampered_payload, dict)
    task = tampered_payload["task"]
    generation_task = tampered_payload["generation_task"]
    assert isinstance(task, dict) and isinstance(generation_task, dict)
    task_spans = task["source_spans"]
    generation_spans = generation_task["source_spans"]
    assert isinstance(task_spans, list) and isinstance(generation_spans, list)
    assert isinstance(task_spans[0], dict) and isinstance(generation_spans[0], dict)
    task_spans[0]["locator"] = "attacker://different-source"
    generation_spans[0]["locator"] = "attacker://different-source"
    _refresh_generation_task_hash(tampered_payload)
    tampered, _ = _reviewed_bundle(
        plane.artifacts,
        fidelity_payload=tampered_payload,
        base=base,
    )

    with pytest.raises(InvalidTransition, match="source span locator differs"):
        plane.register_bundle(tampered, idempotency_key="source-span-drift")


def test_registration_accepts_valid_reordered_private_source_claims(tmp_path: Path) -> None:
    second_span = SourceSpanV1(
        span_id=_id("second-span"),
        locator="source:2",
        content_hash=digest_text(HashKindV1.SOURCE_SPAN, "m equals m"),
        permitted_excerpt="m equals m",
    )
    plane = _plane(tmp_path)
    base = _bundle(additional_source_spans=(second_span,))
    base, payload = _reviewed_bundle(plane.artifacts, base=base)
    reordered_payload = json.loads(canonical_json_bytes(payload))
    assert isinstance(reordered_payload, dict)
    task = reordered_payload["task"]
    generation_task = reordered_payload["generation_task"]
    assert isinstance(task, dict) and isinstance(generation_task, dict)
    task_spans = task["source_spans"]
    generation_spans = generation_task["source_spans"]
    assert isinstance(task_spans, list) and isinstance(generation_spans, list)
    task_spans.reverse()
    generation_spans.reverse()
    _refresh_generation_task_hash(reordered_payload)
    reordered, _ = _reviewed_bundle(
        plane.artifacts,
        fidelity_payload=reordered_payload,
        base=base,
    )

    binding = plane.register_bundle(reordered, idempotency_key="reordered-private-source-claims")

    assert binding.fidelity_evidence_artifact is not None


@pytest.mark.parametrize("mode", ("unknown", "duplicate"))
def test_registration_rejects_unknown_or_duplicate_task_source_span_ids(
    tmp_path: Path,
    mode: str,
) -> None:
    plane = _plane(tmp_path)
    base, payload = _reviewed_bundle(plane.artifacts)
    tampered_payload = json.loads(canonical_json_bytes(payload))
    assert isinstance(tampered_payload, dict)
    task = tampered_payload["task"]
    generation_task = tampered_payload["generation_task"]
    assert isinstance(task, dict) and isinstance(generation_task, dict)
    task_spans = task["source_spans"]
    generation_spans = generation_task["source_spans"]
    assert isinstance(task_spans, list) and isinstance(generation_spans, list)
    assert isinstance(task_spans[0], dict) and isinstance(generation_spans[0], dict)
    if mode == "unknown":
        task_spans[0]["span_id"] = _id("unknown-span").value
        generation_spans[0]["span_id"] = _id("unknown-span").value
    else:
        task_spans.append(dict(task_spans[0]))
        generation_spans.append(dict(generation_spans[0]))
    _refresh_generation_task_hash(tampered_payload)
    tampered, _ = _reviewed_bundle(
        plane.artifacts,
        fidelity_payload=tampered_payload,
        base=base,
    )

    with pytest.raises(InvalidTransition, match="source span"):
        plane.register_bundle(tampered, idempotency_key=f"{mode}-source-span")


def test_registration_rejects_fragment_absent_from_frozen_normalized_statement(
    tmp_path: Path,
) -> None:
    plane = _plane(tmp_path)
    base, payload = _reviewed_bundle(plane.artifacts)
    tampered_payload = json.loads(canonical_json_bytes(payload))
    assert isinstance(tampered_payload, dict)
    task = tampered_payload["task"]
    generation_task = tampered_payload["generation_task"]
    assert isinstance(task, dict) and isinstance(generation_task, dict)
    task_obligations = task["obligations"]
    generation_obligations = generation_task["obligations"]
    assert isinstance(task_obligations, list) and isinstance(generation_obligations, list)
    assert isinstance(task_obligations[0], dict) and isinstance(generation_obligations[0], dict)
    task_obligations[0]["normalized_fragment"] = "unbound normalized fragment"
    generation_obligations[0]["normalized_fragment"] = "unbound normalized fragment"
    _refresh_generation_task_hash(tampered_payload)
    tampered, _ = _reviewed_bundle(
        plane.artifacts,
        fidelity_payload=tampered_payload,
        base=base,
    )

    with pytest.raises(InvalidTransition, match="fragment is absent"):
        plane.register_bundle(tampered, idempotency_key="unbound-normalized-fragment")


def test_registration_rejects_duplicate_task_obligation_source_span_ids(tmp_path: Path) -> None:
    plane = _plane(tmp_path)
    base, payload = _reviewed_bundle(plane.artifacts)
    tampered_payload = json.loads(canonical_json_bytes(payload))
    assert isinstance(tampered_payload, dict)
    task = tampered_payload["task"]
    assert isinstance(task, dict)
    obligations = task["obligations"]
    assert isinstance(obligations, list) and isinstance(obligations[0], dict)
    source_span_ids = obligations[0]["source_span_ids"]
    assert isinstance(source_span_ids, list) and isinstance(source_span_ids[0], str)
    source_span_ids.append(source_span_ids[0])
    tampered, _ = _reviewed_bundle(
        plane.artifacts,
        fidelity_payload=tampered_payload,
        base=base,
    )

    with pytest.raises(InvalidTransition, match="source spans are invalid"):
        plane.register_bundle(tampered, idempotency_key="duplicate-obligation-source-span")


@pytest.mark.parametrize(
    "field",
    ("obligation_id", "description", "normalized_fragment", "lean_fragment"),
)
def test_registration_rejects_blank_task_obligation_text(tmp_path: Path, field: str) -> None:
    plane = _plane(tmp_path)
    base, payload = _reviewed_bundle(plane.artifacts)
    tampered_payload = json.loads(canonical_json_bytes(payload))
    assert isinstance(tampered_payload, dict)
    task = tampered_payload["task"]
    assert isinstance(task, dict)
    obligations = task["obligations"]
    assert isinstance(obligations, list) and isinstance(obligations[0], dict)
    obligations[0][field] = " "
    tampered, _ = _reviewed_bundle(
        plane.artifacts,
        fidelity_payload=tampered_payload,
        base=base,
    )

    with pytest.raises(InvalidTransition, match=f"{field} must not be blank"):
        plane.register_bundle(tampered, idempotency_key=f"blank-obligation-{field}")


@pytest.mark.parametrize("mode", ("extra", "missing"))
def test_registration_rejects_task_obligation_extra_or_missing_fields(
    tmp_path: Path,
    mode: str,
) -> None:
    plane = _plane(tmp_path)
    base, payload = _reviewed_bundle(plane.artifacts)
    tampered_payload = json.loads(canonical_json_bytes(payload))
    assert isinstance(tampered_payload, dict)
    task = tampered_payload["task"]
    assert isinstance(task, dict)
    obligations = task["obligations"]
    assert isinstance(obligations, list) and isinstance(obligations[0], dict)
    if mode == "extra":
        obligations[0]["selected_formal_answer"] = "forbidden"
    else:
        obligations[0].pop("description")
    tampered, _ = _reviewed_bundle(
        plane.artifacts,
        fidelity_payload=tampered_payload,
        base=base,
    )

    with pytest.raises(InvalidTransition, match="task obligation"):
        plane.register_bundle(tampered, idempotency_key=f"{mode}-obligation-field")


@pytest.mark.parametrize("mode", ("extra", "missing"))
def test_registration_rejects_generation_obligation_extra_or_missing_fields(
    tmp_path: Path,
    mode: str,
) -> None:
    plane = _plane(tmp_path)
    base, payload = _reviewed_bundle(plane.artifacts)
    tampered_payload = json.loads(canonical_json_bytes(payload))
    assert isinstance(tampered_payload, dict)
    generation_task = tampered_payload["generation_task"]
    assert isinstance(generation_task, dict)
    obligations = generation_task["obligations"]
    assert isinstance(obligations, list) and isinstance(obligations[0], dict)
    if mode == "extra":
        obligations[0]["lean_fragment"] = "forbidden"
    else:
        obligations[0].pop("normalized_fragment")
    _refresh_generation_task_hash(tampered_payload)
    tampered, _ = _reviewed_bundle(
        plane.artifacts,
        fidelity_payload=tampered_payload,
        base=base,
    )

    with pytest.raises(InvalidTransition, match="differs from the Builder projection"):
        plane.register_bundle(tampered, idempotency_key=f"{mode}-generation-obligation-field")


def test_protocol_accepts_only_evidence_for_the_registered_frozen_contract(tmp_path: Path) -> None:
    plane = _plane(tmp_path)
    bundle = _bundle()
    binding = plane.register_bundle(bundle, idempotency_key="register")
    assert binding.contract_hash == bundle.contract.semantic_hash().value
    receipt = plane.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=60,
        idempotency_key="claim",
    )
    submission = _submission(bundle)
    plane.submit_proof(
        bundle.bundle_id.value,
        lease=receipt.lease,
        submission=submission,
        idempotency_key="proof",
    )
    report = _passing_report(plane, bundle, submission, report_key="accepted")
    outcome = plane.verify_submission(
        bundle.bundle_id.value,
        lease=receipt.lease,
        report=report,
        idempotency_key="verify",
    )
    assert outcome.accepted
    assert outcome.event.event_type == "verification.accepted"
    snapshot = DashboardProjection(plane.events.read_all()).snapshot()
    assert {node["status"] for node in snapshot["nodes"]} == {"verified"}
    assert snapshot["overview"]["active_runs"] == 0
    assert snapshot["overview"]["blocked_nodes"] == 0
    assert snapshot["runs"][0]["verification"] == "accepted"
    verification_event = next(
        item for item in snapshot["events"] if item["event_type"] == "verification.accepted"
    )
    assert verification_event["task_id"] == bundle.bundle_id.value


def test_verifier_records_but_never_accepts_sorry_axiom(tmp_path: Path) -> None:
    plane = _plane(tmp_path)
    bundle = _bundle()
    plane.register_bundle(bundle, idempotency_key="register")
    receipt = plane.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=60,
        idempotency_key="claim",
    )
    submission = _submission(bundle)
    plane.submit_proof(
        bundle.bundle_id.value,
        lease=receipt.lease,
        submission=submission,
        idempotency_key="proof",
    )
    outcome = plane.verify_submission(
        bundle.bundle_id.value,
        lease=receipt.lease,
        report=_passing_report(
            plane,
            bundle,
            submission,
            report_key="sorry-axiom",
            observed_axioms=("sorryAx",),
        ),
        idempotency_key="verify",
    )
    assert not outcome.accepted
    assert "sorryAx is prohibited" in outcome.reasons
    assert outcome.event.event_type == "verification.rejected"


def test_control_plane_rejects_a_nonindependent_verifier_report(tmp_path: Path) -> None:
    plane = _plane(tmp_path)
    bundle = _bundle()
    plane.register_bundle(bundle, idempotency_key="register")
    claim = plane.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=60,
        idempotency_key="claim",
    )
    submission = _submission(bundle)
    plane.submit_proof(
        bundle.bundle_id.value,
        lease=claim.lease,
        submission=submission,
        idempotency_key="proof",
    )
    report = _passing_report(
        plane,
        bundle,
        submission,
        report_key="not-independent",
        independent=False,
    )
    outcome = plane.verify_submission(
        bundle.bundle_id.value,
        lease=claim.lease,
        report=report,
        idempotency_key="verify",
    )
    assert not outcome.accepted
    assert "verification report is not independent" in outcome.reasons


def test_control_plane_rejects_a_submission_for_a_different_proof_boundary(tmp_path: Path) -> None:
    plane = _plane(tmp_path)
    bundle = _bundle()
    plane.register_bundle(bundle, idempotency_key="register")
    receipt = plane.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=60,
        idempotency_key="claim",
    )
    wrong_boundary = digest_text(HashKindV1.PROOF_BOUNDARY, "other-boundary")
    submission = _submission(bundle).model_copy(update={"proof_boundary_hash": wrong_boundary})
    with pytest.raises(InvalidTransition, match="proof boundary"):
        plane.submit_proof(
            bundle.bundle_id.value,
            lease=receipt.lease,
            submission=submission,
            idempotency_key="proof",
        )


def test_projection_exports_only_summaries_not_proof_or_source_text(tmp_path: Path) -> None:
    plane = _plane(tmp_path)
    bundle = _bundle()
    plane.register_bundle(bundle, idempotency_key="register")
    receipt = plane.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=60,
        idempotency_key="claim",
    )
    plane.submit_proof(
        bundle.bundle_id.value,
        lease=receipt.lease,
        submission=_submission(bundle),
        idempotency_key="proof",
    )
    snapshot = DashboardProjection(plane.events.read_all()).snapshot()
    text = json.dumps(snapshot)
    assert "by\\n  rfl" not in text
    node = snapshot["nodes"][0]
    run = snapshot["runs"][0]
    proof_event = next(
        item for item in snapshot["events"] if item["event_type"] == "proof.submitted"
    )
    assert node["source_node_id"] == bundle.graphs.mathematical.nodes[0].node_id.value
    assert node["task_id"] == run["task_id"] == proof_event["task_id"] == bundle.bundle_id.value
    assert node["id"] == (
        f"dashboard-node|{bundle.bundle_id.value}|mathematical|"
        f"{bundle.graphs.mathematical.nodes[0].node_id.value}"
    )
    assert "bundle_id" not in node
    claim_event = next(item for item in snapshot["events"] if item["event_type"] == "task.claimed")
    assert claim_event["task_id"] == bundle.bundle_id.value
    assert node["status"] == "running"
    assert snapshot["overview"]["active_runs"] == 1
    phase_feedback = snapshot["phase_feedback"][0]
    assert (
        phase_feedback["builder_fidelity"]["contract_hash"] == bundle.contract.semantic_hash().value
    )
    assert phase_feedback["prover_verification"]["state"] == "candidate_pending_verification"
    assert phase_feedback["promotion_state"] == "not_a_promotion"
    path = export_dashboard_projection(tmp_path / "projection.json", plane.events.read_all())
    assert json.loads(path.read_text(encoding="utf-8"))["runs"][0]["status"] == "candidate"


def test_projection_composite_node_ids_preserve_names_and_drop_tainted_fields(
    tmp_path: Path,
) -> None:
    def registered(
        *,
        position: int,
        bundle_id: str,
        graph_nodes: list[dict[str, object]],
    ) -> StoredEvent:
        return StoredEvent(
            global_position=position,
            event_id=f"event-{position}",
            entity_type="task",
            entity_id=bundle_id,
            entity_sequence=1,
            event_type="task.registered",
            payload={"bundle_id": bundle_id, "graph_nodes": graph_nodes},
            metadata={},
            recorded_at=f"2026-07-23T12:00:0{position}Z",
        )

    def graph_node(
        graph: str,
        *,
        node_id: str = "shared-node",
        dependencies: list[str] | None = None,
    ) -> dict[str, object]:
        return {
            "id": node_id,
            "bundle_id": "ignored-node-copy",
            "label": f"{graph} {node_id}",
            "graph": graph,
            "status": "frozen",
            "revision": 1,
            "kind": "statement",
            "dependencies": dependencies or [],
            "proof_source": "TAINTED-PROOF-SOURCE",
            "metadata": {"prompt": "TAINTED-MODEL-PROMPT"},
        }

    events = (
        registered(
            position=1,
            bundle_id="bundle-a",
            graph_nodes=[graph_node("mathematical"), graph_node("formal")],
        ),
        registered(
            position=2,
            bundle_id="bundle-b",
            graph_nodes=[
                graph_node("mathematical"),
                graph_node(
                    "mathematical",
                    node_id="child-node",
                    dependencies=["shared-node"],
                ),
            ],
        ),
    )
    snapshot = DashboardProjection(events).snapshot()
    nodes = snapshot["nodes"]

    assert len(nodes) == 4
    assert len({node["id"] for node in nodes}) == 4
    assert {(node["task_id"], node["graph"], node["source_node_id"]) for node in nodes} == {
        ("bundle-a", "mathematical", "shared-node"),
        ("bundle-a", "formal", "shared-node"),
        ("bundle-b", "mathematical", "shared-node"),
        ("bundle-b", "mathematical", "child-node"),
    }
    bundle_b_root = next(
        node
        for node in nodes
        if node["task_id"] == "bundle-b" and node["source_node_id"] == "shared-node"
    )
    bundle_b_child = next(
        node
        for node in nodes
        if node["task_id"] == "bundle-b" and node["source_node_id"] == "child-node"
    )
    assert bundle_b_child["dependencies"] == [bundle_b_root["id"]]
    assert all("bundle_id" not in node for node in nodes)
    assert all(
        set(node)
        == {
            "dependencies",
            "graph",
            "id",
            "kind",
            "label",
            "revision",
            "source_node_id",
            "status",
            "task_id",
            "updated_at",
        }
        for node in nodes
    )
    exported = export_dashboard_projection(tmp_path / "projection.json", events).read_text(
        encoding="utf-8"
    )
    assert "TAINTED-PROOF-SOURCE" not in exported
    assert "TAINTED-MODEL-PROMPT" not in exported
    assert '"proof_source"' not in exported
    assert '"metadata"' not in exported


def test_projection_shows_t7_and_fate_public_event_families_without_private_fields(
    tmp_path: Path,
) -> None:
    t7_bundle_id = "t7-synthetic-worker-fixture-a"
    t7_raw_node_id = "T7-RAW-NODE-ID-SENTINEL"
    fate_bundle_id = "fate-public-attempt-a"
    forbidden = {
        t7_raw_node_id,
        "T7-PRIVATE-MODULE-NAME",
        "T7-PRIVATE-LEASE-HOLDER",
        "T7-RAW-PROMPT-SENTINEL",
        "T7-RAW-PROOF-SENTINEL",
        "T7-PRIVATE-CAS-DIGEST-SENTINEL",
        "FATE-PRIVATE-APPROVAL-SNAPSHOT",
        "FATE-PRIVATE-CANDIDATE",
    }
    events = (
        StoredEvent(
            global_position=1,
            event_id="t7-complete-a",
            entity_type="t7_synthetic_node_v2",
            entity_id=f"worker-input-hash-a:{t7_raw_node_id}",
            entity_sequence=1,
            event_type="t7_synthetic_node_v2.synthetic_complete",
            payload={
                "schema_version": "autolean.t7-synthetic-node-result.v2",
                "bundle_id": t7_bundle_id,
                "node_id": t7_raw_node_id,
                "module": "T7-PRIVATE-MODULE-NAME",
                "typed_outcome": "synthetic_complete",
                "evidence_class": "synthetic_fake_node_v1",
                "promotion_eligible": False,
                "lease_holder_id": "T7-PRIVATE-LEASE-HOLDER",
                "fencing_token": 7,
                "source_prompt": "T7-RAW-PROMPT-SENTINEL",
                "proof_candidate": "T7-RAW-PROOF-SENTINEL",
                "private_cas_digest": "T7-PRIVATE-CAS-DIGEST-SENTINEL",
            },
            metadata={},
            recorded_at="2026-07-27T12:00:01Z",
        ),
        StoredEvent(
            global_position=2,
            event_id="fate-start-a",
            entity_type="fate-attempt",
            entity_id=fate_bundle_id,
            entity_sequence=1,
            event_type="fate.attempt.started",
            payload={
                "schema_version": "autolean.fate-execution.v1",
                "bundle_id": fate_bundle_id,
                "run_id": "fate-run-a",
                "problem_id": "FATE-M-3",
                "attempt_number": 1,
                "raw_output_persisted": False,
                "approval_snapshot": "FATE-PRIVATE-APPROVAL-SNAPSHOT",
            },
            metadata={},
            recorded_at="2026-07-27T12:00:02Z",
        ),
        StoredEvent(
            global_position=3,
            event_id="fate-terminal-a",
            entity_type="fate-attempt",
            entity_id=fate_bundle_id,
            entity_sequence=2,
            event_type="fate.attempt.verified",
            payload={
                "schema_version": "autolean.fate-execution.v1",
                "bundle_id": fate_bundle_id,
                "run_id": "fate-run-a",
                "problem_id": "FATE-M-3",
                "attempt_number": 1,
                "accepted": True,
                "elapsed_ms": 246,
                "input_tokens": 100,
                "output_tokens": 20,
                "cost_microusd": 2_500,
                "contains_raw_output": False,
                "contains_candidate_source": False,
                "contains_private_digests": False,
                "private_artifacts_persisted": True,
                "candidate": "FATE-PRIVATE-CANDIDATE",
            },
            metadata={},
            recorded_at="2026-07-27T12:00:03Z",
        ),
        StoredEvent(
            global_position=4,
            event_id="future-event-a",
            entity_type="future-event",
            entity_id="future-entity-a",
            entity_sequence=1,
            event_type="future.event.v3",
            payload={"unrecognized": True},
            metadata={},
            recorded_at="2026-07-27T12:00:04Z",
        ),
    )

    snapshot = DashboardProjection(events).snapshot()
    public_ref = hashlib.sha256(
        b"autolean.dashboard.t7-public-node-ref.v1\x00"
        + json.dumps(
            {"bundle_id": t7_bundle_id, "node_id": t7_raw_node_id},
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()

    assert snapshot["nodes"] == [
        {
            "dependencies": [],
            "graph": "execution",
            "id": f"dashboard-node|{t7_bundle_id}|execution|t7-public:{public_ref}",
            "kind": "synthetic_execution",
            "label": f"T7 synthetic node {public_ref[:12]}",
            "revision": 1,
            "source_node_id": f"t7-public:{public_ref}",
            "status": "synthetic_complete",
            "task_id": t7_bundle_id,
            "updated_at": "2026-07-27T12:00:01Z",
        }
    ]
    assert snapshot["runs"] == [
        {
            "id": f"fate:{fate_bundle_id}",
            "task_id": fate_bundle_id,
            "provider": "fate-execution",
            "model": "redacted-by-public-sidecar",
            "started_at": "2026-07-27T12:00:02Z",
            "duration_ms": 246,
            "input_tokens": 100,
            "output_tokens": 20,
            "cost_usd": 0.0025,
            "status": "benchmark_verified",
            "verification": "benchmark_accepted",
        }
    ]
    assert [item["summary"] for item in snapshot["events"]] == [
        "T7 synthetic complete",
        "FATE benchmark attempt started",
        "FATE benchmark verifier accepted",
        "future event v3",
    ]
    exported = export_dashboard_projection(tmp_path / "projection.json", events).read_text(
        encoding="utf-8"
    )
    assert all(value not in exported for value in forbidden)


@pytest.mark.parametrize(
    ("event_type", "accepted"),
    [
        ("verification.accepted", True),
        ("verification.rejected", False),
    ],
)
def test_generic_verification_cannot_change_t7_synthetic_status(
    event_type: str,
    accepted: bool,
) -> None:
    bundle_id = "t7-cross-protocol-bundle"
    synthetic = StoredEvent(
        global_position=1,
        event_id="t7-cross-protocol-result",
        entity_type="t7_synthetic_node_v2",
        entity_id="private-worker-node-identity",
        entity_sequence=1,
        event_type="t7_synthetic_node_v2.synthetic_complete",
        payload={
            "schema_version": "autolean.t7-synthetic-node-result.v2",
            "bundle_id": bundle_id,
            "node_id": "private-node-id",
            "typed_outcome": "synthetic_complete",
            "evidence_class": "synthetic_fake_node_v1",
            "promotion_eligible": False,
        },
        metadata={},
        recorded_at="2026-07-27T12:00:00Z",
    )
    verification = StoredEvent(
        global_position=2,
        event_id="unrelated-proof-verification",
        entity_type="verification",
        entity_id="proof-from-another-protocol",
        entity_sequence=1,
        event_type=event_type,
        payload={
            "bundle_id": bundle_id,
            "proof_id": "proof-from-another-protocol",
            "accepted": accepted,
        },
        metadata={},
        recorded_at="2026-07-27T12:00:01Z",
    )

    snapshot = DashboardProjection((synthetic, verification)).snapshot()

    assert snapshot["nodes"][0]["kind"] == "synthetic_execution"
    assert snapshot["nodes"][0]["status"] == "synthetic_complete"
    assert snapshot["nodes"][0]["status"] not in {"verified", "blocked", "failed"}


@pytest.mark.parametrize(
    ("event_type", "payload", "message"),
    [
        (
            "t7_synthetic_node_v2.synthetic_complete",
            {
                "schema_version": "autolean.t7-synthetic-node-result.v2",
                "bundle_id": "t7-bundle-a",
                "node_id": "node-a",
                "typed_outcome": "synthetic_complete",
                "evidence_class": "synthetic_fake_node_v1",
                "promotion_eligible": True,
            },
            "T7 synthetic",
        ),
        (
            "fate.attempt.verified",
            {
                "schema_version": "autolean.fate-execution.v1",
                "bundle_id": "fate-bundle-a",
                "run_id": "fate-run-a",
                "problem_id": "FATE-M-3",
                "attempt_number": 1,
                "accepted": True,
                "elapsed_ms": 1,
                "input_tokens": 1,
                "output_tokens": 1,
                "cost_microusd": 1,
                "contains_raw_output": True,
                "contains_candidate_source": False,
                "contains_private_digests": False,
                "private_artifacts_persisted": True,
            },
            "FATE terminal",
        ),
    ],
)
def test_projection_rejects_known_public_execution_events_with_unsafe_boundaries(
    event_type: str,
    payload: dict[str, object],
    message: str,
) -> None:
    bundle_id = payload["bundle_id"]
    assert isinstance(bundle_id, str)
    event = StoredEvent(
        global_position=1,
        event_id="unsafe-public-execution-event",
        entity_type=("t7_synthetic_node_v2" if event_type.startswith("t7_") else "fate-attempt"),
        entity_id=("worker-input-hash-a:node-a" if event_type.startswith("t7_") else bundle_id),
        entity_sequence=(1 if event_type.startswith("t7_") else 2),
        event_type=event_type,
        payload=payload,
        metadata={},
        recorded_at="2026-07-27T12:00:00Z",
    )

    with pytest.raises(ProjectionError, match=message):
        DashboardProjection((event,)).snapshot()


def _fate_projection_test_event(
    position: int,
    event_type: str,
    *,
    bundle_id: str = "fate-replay-bundle",
    entity_id: str | None = None,
    include_attempt_seed: bool = True,
    overrides: dict[str, object] | None = None,
) -> StoredEvent:
    payload: dict[str, object] = {
        "schema_version": "autolean.fate-execution.v1",
        "bundle_id": bundle_id,
        "run_id": "fate-replay-run",
        "problem_id": "FATE-H-31",
        "attempt_number": 1,
        "attempt_seed": "a" * 64,
    }
    if not include_attempt_seed:
        payload.pop("attempt_seed")
    if event_type == "fate.attempt.started":
        payload["raw_output_persisted"] = False
    else:
        payload.update(
            {
                "accepted": True,
                "elapsed_ms": 25,
                "input_tokens": 10,
                "output_tokens": 5,
                "cost_microusd": 100,
                "contains_raw_output": False,
                "contains_candidate_source": False,
                "contains_private_digests": False,
                "private_artifacts_persisted": True,
            }
        )
    payload.update(overrides or {})
    return StoredEvent(
        global_position=position,
        event_id=f"fate-replay-event-{position}",
        entity_type="fate-attempt",
        entity_id=entity_id or bundle_id,
        entity_sequence=1 if event_type == "fate.attempt.started" else 2,
        event_type=event_type,
        payload=payload,
        metadata={},
        recorded_at=f"2026-07-27T12:00:0{position}Z",
    )


def test_fate_replay_is_ordered_by_event_position_and_requires_started_event() -> None:
    started = _fate_projection_test_event(1, "fate.attempt.started")
    terminal = _fate_projection_test_event(2, "fate.attempt.verified")

    snapshot = DashboardProjection((terminal, started)).snapshot()

    assert snapshot["runs"][0]["status"] == "benchmark_verified"
    assert snapshot["runs"][0]["started_at"] == started.recorded_at

    with pytest.raises(ProjectionError, match="no matching started event"):
        DashboardProjection((terminal,)).snapshot()


def test_fate_v2_events_match_current_public_producer_contract(tmp_path: Path) -> None:
    private_sentinel = "FATE-V2-PRIVATE-APPROVAL-SNAPSHOT"
    started = _fate_projection_test_event(
        1,
        "fate.attempt.started",
        overrides={
            "schema_version": "autolean.fate-execution.v2",
            "bundle_hash": "a" * 64,
            "authorization_hash": "b" * 64,
            "approval_hash": "c" * 64,
            "request_hash": "d" * 64,
            "context_pack_hash": "e" * 64,
            "execution_nonce": "fate-execution-nonce",
        },
    )
    terminal = _fate_projection_test_event(
        2,
        "fate.attempt.verified",
        overrides={
            "schema_version": "autolean.fate-execution.v2",
            "bundle_hash": "a" * 64,
            "authorization_hash": "b" * 64,
            "approval_hash": "c" * 64,
            "approval_snapshot": {"private": private_sentinel},
            "verification_event_id": "verification-event-v2",
            "verifier_id": "independent-verifier-v2",
        },
    )

    snapshot = DashboardProjection((started, terminal)).snapshot()

    assert snapshot["runs"][0]["status"] == "benchmark_verified"
    exported = export_dashboard_projection(tmp_path / "projection.json", (started, terminal))
    assert private_sentinel not in exported.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "event_type",
    [
        "fate.attempt.started",
        "fate.attempt.verified",
    ],
)
def test_fate_v2_event_requires_attempt_seed(event_type: str) -> None:
    event = _fate_projection_test_event(
        1,
        event_type,
        include_attempt_seed=False,
        overrides={"schema_version": "autolean.fate-execution.v2"},
    )

    with pytest.raises(ProjectionError, match="cannot be safely projected"):
        DashboardProjection((event,)).snapshot()


@pytest.mark.parametrize("attempt_seed", ["short", "A" * 64])
def test_fate_v2_attempt_seed_must_be_a_lowercase_sha256(attempt_seed: str) -> None:
    event = _fate_projection_test_event(
        1,
        "fate.attempt.started",
        overrides={
            "schema_version": "autolean.fate-execution.v2",
            "attempt_seed": attempt_seed,
        },
    )

    with pytest.raises(ProjectionError, match="cannot be safely projected"):
        DashboardProjection((event,)).snapshot()


@pytest.mark.parametrize(
    ("field", "different_value"),
    [
        ("run_id", "different-run"),
        ("problem_id", "FATE-X-11"),
        ("attempt_number", 2),
        ("attempt_seed", "b" * 64),
    ],
)
def test_fate_terminal_identity_must_match_started_event(
    field: str,
    different_value: object,
) -> None:
    started = _fate_projection_test_event(
        1,
        "fate.attempt.started",
        overrides={"schema_version": "autolean.fate-execution.v2"},
    )
    terminal = _fate_projection_test_event(
        2,
        "fate.attempt.verified",
        overrides={
            "schema_version": "autolean.fate-execution.v2",
            field: different_value,
        },
    )

    with pytest.raises(ProjectionError, match="identity differs"):
        DashboardProjection((started, terminal)).snapshot()


def test_fate_terminal_entity_must_match_started_event() -> None:
    started = _fate_projection_test_event(1, "fate.attempt.started")
    terminal = _fate_projection_test_event(
        2,
        "fate.attempt.verified",
        entity_id="different-fate-entity",
    )

    with pytest.raises(ProjectionError, match="cannot be safely projected"):
        DashboardProjection((started, terminal)).snapshot()


def test_fate_terminal_schema_must_match_started_event() -> None:
    started = _fate_projection_test_event(1, "fate.attempt.started")
    terminal = _fate_projection_test_event(
        2,
        "fate.attempt.verified",
        overrides={"schema_version": "autolean.fate-execution.v2"},
    )

    with pytest.raises(ProjectionError, match="identity differs"):
        DashboardProjection((started, terminal)).snapshot()


def test_fate_replay_rejects_duplicate_terminal_event() -> None:
    started = _fate_projection_test_event(1, "fate.attempt.started")
    terminal = _fate_projection_test_event(2, "fate.attempt.verified")
    conflicting_terminal = _fate_projection_test_event(
        3,
        "fate.attempt.verified",
        overrides={"accepted": False},
    )

    with pytest.raises(ProjectionError, match="duplicate FATE terminal"):
        DashboardProjection((started, terminal, conflicting_terminal)).snapshot()


@pytest.mark.parametrize(
    ("event_type", "accepted"),
    [
        ("verification.accepted", True),
        ("verification.rejected", False),
    ],
)
def test_generic_verification_cannot_terminalize_fate_attempt(
    event_type: str,
    accepted: bool,
) -> None:
    bundle_id = "fate-replay-bundle"
    started = _fate_projection_test_event(1, "fate.attempt.started", bundle_id=bundle_id)
    generic_verification = StoredEvent(
        global_position=2,
        event_id="generic-verification-targeting-fate-run",
        entity_type="verification",
        entity_id=f"fate:{bundle_id}",
        entity_sequence=1,
        event_type=event_type,
        payload={
            "bundle_id": bundle_id,
            "proof_id": f"fate:{bundle_id}",
            "accepted": accepted,
        },
        metadata={},
        recorded_at="2026-07-27T12:00:02Z",
    )

    with pytest.raises(ProjectionError, match="cannot target a FATE benchmark run"):
        DashboardProjection((started, generic_verification)).snapshot()


@pytest.mark.parametrize("fate_first", [True, False])
def test_proof_submission_cannot_replace_fate_run_identity(fate_first: bool) -> None:
    bundle_id = "fate-replay-bundle"
    started = _fate_projection_test_event(
        1 if fate_first else 2,
        "fate.attempt.started",
        bundle_id=bundle_id,
    )
    proof_submission = StoredEvent(
        global_position=2 if fate_first else 1,
        event_id="proof-submission-colliding-with-fate-run",
        entity_type="proof",
        entity_id=f"fate:{bundle_id}",
        entity_sequence=1,
        event_type="proof.submitted",
        payload={
            "bundle_id": bundle_id,
            "proof_id": f"fate:{bundle_id}",
            "provider": "fake",
            "model": "fake",
        },
        metadata={},
        recorded_at="2026-07-27T12:00:02Z",
    )

    with pytest.raises(ProjectionError, match="run identity"):
        DashboardProjection((started, proof_submission)).snapshot()


def test_projection_rejected_verification_is_fail_closed() -> None:
    event = StoredEvent(
        global_position=1,
        event_id="verification-rejected",
        entity_type="verification",
        entity_id="proof-1",
        entity_sequence=1,
        event_type="verification.rejected",
        payload={
            "bundle_id": "bundle-a",
            "proof_id": "proof-1",
            "accepted": False,
            "reasons": ["kernel failure"],
        },
        metadata={},
        recorded_at="2026-07-23T12:00:00Z",
    )

    snapshot = DashboardProjection((event,)).snapshot()

    assert snapshot["overview"]["blocked_nodes"] == 1
    assert snapshot["events"][0]["task_id"] == "bundle-a"


def test_phase_feedback_replays_evidence_without_scoring_or_auto_promotion() -> None:
    bundle_id = "bundle-phase"

    def event(
        position: int,
        event_type: str,
        payload: dict[str, object],
        *,
        entity_type: str = "task",
        entity_id: str | None = None,
    ) -> StoredEvent:
        return StoredEvent(
            global_position=position,
            event_id=f"event-{position}",
            entity_type=entity_type,
            entity_id=entity_id or bundle_id,
            entity_sequence=position,
            event_type=event_type,
            payload=payload,
            metadata={},
            recorded_at=f"2026-07-24T12:00:0{position}Z",
        )

    registered = event(
        1,
        "task.registered",
        {
            "bundle_id": bundle_id,
            "contract_id": "contract-phase",
            "revision": 2,
            "contract_hash": "a" * 64,
            "bundle_hash": "b" * 64,
            "builder_attestation": {
                "purpose": "builder-freeze",
                "key_id": "builder-key",
                "payload_hash": "2" * 64,
                "evidence_identity": "builder-evidence",
                "expires_at": "2026-07-25T12:00:00Z",
            },
            "fidelity_evidence_artifact": {"digest": "c" * 64},
            "graph_nodes": [
                {
                    "id": "math-root",
                    "label": "Root prerequisite",
                    "graph": "mathematical",
                    "status": "frozen",
                    "revision": 2,
                    "kind": "lemma",
                    "dependencies": [],
                },
                {
                    "id": "math-middle",
                    "label": "Middle consequence",
                    "graph": "mathematical",
                    "status": "frozen",
                    "revision": 2,
                    "kind": "theorem",
                    "dependencies": ["math-root"],
                },
                {
                    "id": "math-leaf",
                    "label": "Open-problem boundary",
                    "graph": "mathematical",
                    "status": "frozen",
                    "revision": 2,
                    "kind": "theorem",
                    "dependencies": ["math-middle"],
                },
            ],
        },
    )
    events = (
        registered,
        event(
            2,
            "proof.submitted",
            {
                "bundle_id": bundle_id,
                "proof_id": "proof-accepted",
                "proof_artifact": {"digest": "d" * 64},
            },
            entity_type="proof",
            entity_id="proof-accepted",
        ),
        event(
            3,
            "verification.accepted",
            {
                "bundle_id": bundle_id,
                "proof_id": "proof-accepted",
                "accepted": True,
                "verification_artifact": {"digest": "e" * 64},
            },
            entity_type="verification",
            entity_id="proof-accepted",
        ),
        event(
            4,
            "proof.submitted",
            {
                "bundle_id": bundle_id,
                "proof_id": "proof-pending",
                "proof_artifact": {"digest": "f" * 64},
            },
            entity_type="proof",
            entity_id="proof-pending",
        ),
        event(
            5,
            "gap.reported",
            {
                "bundle_id": bundle_id,
                "report_id": "gap-1",
                "gap_artifact": {"digest": "0" * 64},
            },
            entity_type="gap",
            entity_id="gap-1",
        ),
        event(
            6,
            "contract_change.requested",
            {
                "bundle_id": bundle_id,
                "request_id": "request-1",
                "request_artifact": {"digest": "1" * 64},
            },
            entity_type="contract_change_request",
            entity_id="request-1",
        ),
        event(
            7,
            "task.claimed",
            {},
            entity_id="bundle-other",
        ),
    )

    snapshot = DashboardProjection(events).snapshot()
    feedback = snapshot["phase_feedback"]

    assert len(feedback) == 1
    item = feedback[0]
    assert item["schema_version"] == "phase-feedback.v1"
    assert item["promotion_state"] == "not_a_promotion"
    assert item["builder_fidelity"]["state"] == "frozen_attested_with_evidence"
    assert item["builder_fidelity"]["evidence_digest"] == "c" * 64
    assert item["prover_verification"] == {
        "state": "mixed_candidates",
        "submitted_proof_ids": ["proof-accepted", "proof-pending"],
        "pending_proof_ids": ["proof-pending"],
        "accepted_proof_ids": ["proof-accepted"],
        "rejected_proof_ids": [],
    }
    assert [review["id"] for review in item["unresolved_human_review_assumptions"]] == [
        "gap-1",
        "request-1",
    ]
    assert all(
        review["state"] == "unresolved" for review in item["unresolved_human_review_assumptions"]
    )
    assert item["mathematical_dependency_node_count"] == 3
    assert item["dependency_leverage_exact_node_limit"] == 512
    assert item["dependency_leverage_mode"] == "exact_transitive"
    leverage = item["mathematical_dependency_leverage"]
    assert [node["source_node_id"] for node in leverage] == [
        "math-root",
        "math-middle",
        "math-leaf",
    ]
    assert [node["transitive_dependents"] for node in leverage] == [2, 1, 0]
    assert [milestone["phase"] for milestone in item["milestones"]] == [
        "builder_fidelity",
        "prover_candidate",
        "prover_verification",
        "prover_candidate",
        "human_review",
        "human_review",
    ]
    assert item["replay"] == {
        "first_relevant_event_sequence": 1,
        "last_relevant_event_sequence": 6,
        "last_relevant_event_id": "event-6",
        "last_relevant_event_recorded_at": "2026-07-24T12:00:06Z",
        "relevant_event_count": 6,
        "relevant_event_sequences": [1, 2, 3, 4, 5, 6],
        "replay_head_event_sequence": 7,
        "replay_head_event_id": "event-7",
        "replay_head_recorded_at": "2026-07-24T12:00:07Z",
        "events_observed_after_last_relevant": 1,
        "last_relevant_event_is_replay_head": False,
        "freshness_scope": "bounded_to_replayed_events",
    }
    serialized = json.dumps(item).lower()
    assert "score" not in serialized
    assert "fate" not in serialized


def test_phase_feedback_large_math_graph_uses_direct_only_leverage_without_transitive_walks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    node_count = 513
    bundle_id = "bundle-large-leverage"

    def unexpected_transitive_walk(*_args: object, **_kwargs: object) -> int:
        raise AssertionError("large graphs must not compute transitive dependency reach")

    monkeypatch.setattr(
        DashboardProjection,
        "_transitive_dependents",
        staticmethod(unexpected_transitive_walk),
    )
    graph_nodes = [
        {
            "id": f"math-{index:03d}",
            "label": f"Mathematical node {index}",
            "graph": "mathematical",
            "status": "frozen",
            "revision": 1,
            "kind": "lemma",
            "dependencies": [] if index == 0 else [f"math-{index - 1:03d}"],
        }
        for index in range(node_count)
    ]
    registered = StoredEvent(
        global_position=1,
        event_id="large-registration",
        entity_type="task",
        entity_id=bundle_id,
        entity_sequence=1,
        event_type="task.registered",
        payload={
            "bundle_id": bundle_id,
            "contract_id": "contract-large-leverage",
            "revision": 1,
            "contract_hash": "a" * 64,
            "bundle_hash": "b" * 64,
            "builder_attestation": {
                "purpose": "builder-freeze",
                "key_id": "builder-key",
                "payload_hash": "c" * 64,
                "evidence_identity": "builder-evidence",
                "expires_at": "2026-07-25T12:00:00Z",
            },
            "graph_nodes": graph_nodes,
        },
        metadata={},
        recorded_at="2026-07-24T12:00:00Z",
    )

    feedback = DashboardProjection((registered,)).snapshot()["phase_feedback"][0]
    leverage = feedback["mathematical_dependency_leverage"]

    assert feedback["mathematical_dependency_node_count"] == node_count
    assert feedback["dependency_leverage_exact_node_limit"] == 512
    assert feedback["dependency_leverage_mode"] == "direct_only_over_limit"
    assert len(leverage) == node_count
    assert all(item["transitive_dependents"] is None for item in leverage)
    assert all(item["direct_dependents"] == 1 for item in leverage[:-1])
    assert leverage[-1]["direct_dependents"] == 0


@pytest.mark.parametrize(
    ("event_type", "accepted"),
    [
        ("verification.accepted", "false"),
        ("verification.accepted", False),
        ("verification.rejected", True),
        ("verification.unknown", False),
    ],
)
def test_projection_rejects_malformed_or_inconsistent_verification(
    event_type: str,
    accepted: object,
) -> None:
    event = StoredEvent(
        global_position=1,
        event_id="verification-malformed",
        entity_type="verification",
        entity_id="proof-1",
        entity_sequence=1,
        event_type=event_type,
        payload={
            "bundle_id": "bundle-a",
            "proof_id": "proof-1",
            "accepted": accepted,
            "reasons": [],
        },
        metadata={},
        recorded_at="2026-07-23T12:00:00Z",
    )

    with pytest.raises(ProjectionError, match="verification"):
        DashboardProjection((event,)).snapshot()


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("promotion_state", "promotion-authorized", "promotion authority"),
        ("execution_authority_class", "production", "production authority"),
    ],
)
def test_projection_rejects_local_verification_claiming_promotion_authority(
    field: str,
    value: str,
    error: str,
) -> None:
    payload: dict[str, object] = {
        "bundle_id": "bundle-a",
        "proof_id": "proof-1",
        "accepted": True,
        "reasons": [],
        field: value,
    }
    event = StoredEvent(
        global_position=1,
        event_id="verification-forged-promotion",
        entity_type="verification",
        entity_id="proof-1",
        entity_sequence=1,
        event_type="verification.accepted",
        payload=payload,
        metadata={},
        recorded_at="2026-07-23T12:00:00Z",
    )

    with pytest.raises(ProjectionError, match=error):
        DashboardProjection((event,)).snapshot()


def _proof_submission_artifact_digest(
    plane: ControlPlane,
    submission: ProofSubmissionV1,
) -> str:
    event = plane.events.read_stream("proof", submission.proof_id.value)[0]
    artifact = event.payload["proof_artifact"]
    assert isinstance(artifact, dict)
    digest = artifact["digest"]
    assert isinstance(digest, str)
    return digest


def _unsigned_report(
    plane: ControlPlane,
    bundle: FormalizationTaskBundleV1,
    submission: ProofSubmissionV1,
    *,
    report_key: str,
    independent: bool = True,
    kernel_passed: bool = True,
    observed_axioms: tuple[str, ...] = (),
) -> VerificationReportV1:
    environment = bundle.contract.formal.environment
    policy = environment.verifier_execution_policy
    command_hash = digest_text(
        HashKindV1.VERIFICATION_COMMAND,
        "synthetic-control-plane-fixture-command-v1",
    )
    observation = VerificationReportV1(
        report_id=_id(f"verification-{report_key}"),
        proof_id=submission.proof_id,
        contract_hash=submission.contract_hash,
        proof_boundary_hash=submission.proof_boundary_hash,
        verifier_id="synthetic-control-plane-fixture-verifier",
        independent=independent,
        kernel_passed=kernel_passed,
        build_passed=True,
        dependency_check_passed=True,
        clean_environment=True,
        environment_hash=submission.environment_hash,
        axiom_profile=bundle.contract.policy.axiom_profile,
        observed_axioms=observed_axioms,
        details="Synthetic control-plane fixture record; no Lean or OCI execution occurred.",
    )
    candidate = (
        f"{bundle.proof_boundary.trusted_statement_source} := {submission.proof_source.rstrip()}\n"
        f"\n#print axioms {bundle.proof_boundary.expected_declaration}\n"
    )
    artifact = VerificationEvidenceArtifactV1(
        evidence_id=_id(f"evidence-{report_key}"),
        bundle_id=bundle.bundle_id,
        bundle_hash=bundle.handoff_hash(),
        contract_id=bundle.contract.contract_id,
        revision=bundle.contract.revision,
        contract_hash=bundle.contract.semantic_hash(),
        proof_id=submission.proof_id,
        proof_boundary_hash=bundle.proof_boundary.boundary_hash,
        proof_submission_artifact_digest=_proof_submission_artifact_digest(plane, submission),
        dependency_manifest_hash=proof_dependency_manifest_hash(submission),
        verification_report_id=observation.report_id,
        verification_observation_hash=observation.report_hash(),
        environment={
            "environment_hash": environment.environment_hash,
            "lean_version": environment.lean_version,
            "mathlib_revision": environment.mathlib_revision,
            "lake_manifest_hash": environment.lake_manifest_hash,
        },
        oci={
            "worker_image_digest": policy.worker_image_digest,
            "wrapper_protocol": policy.wrapper_protocol,
            "command_policy_hash": policy.command_policy_hash(),
            "command_hash": command_hash,
            "candidate_sha256": hashlib.sha256(candidate.encode("utf-8")).hexdigest(),
            "trusted_statement_sha256": bundle.proof_boundary.trusted_statement_hash.value,
            "bundle_manifest_sha256": bundle.proof_boundary.solver_manifest_hash.value,
        },
    )
    evidence_artifact = plane.artifacts.put_json(artifact.model_dump(mode="json"))
    evidence = VerificationEvidenceV1(
        evidence_id=artifact.evidence_id,
        environment_hash=submission.environment_hash,
        worker_image_digest=policy.worker_image_digest,
        wrapper_protocol=policy.wrapper_protocol,
        lean_version=environment.lean_version,
        mathlib_revision=environment.mathlib_revision,
        lake_manifest_hash=environment.lake_manifest_hash,
        dependency_manifest_hash=proof_dependency_manifest_hash(submission),
        command_policy_hash=policy.command_policy_hash(),
        command_hash=command_hash,
        evidence_artifact_digest=evidence_artifact.digest,
    )
    return observation.model_copy(update={"evidence": evidence})


def _passing_report(
    plane: ControlPlane,
    bundle: FormalizationTaskBundleV1,
    submission: ProofSubmissionV1,
    *,
    report_key: str,
    independent: bool = True,
    kernel_passed: bool = True,
    observed_axioms: tuple[str, ...] = (),
    signer: HmacAttestationSignerV1 | None = None,
    nonce: str | None = None,
) -> VerificationReportV1:
    return _attest_report(
        plane,
        bundle,
        submission,
        _unsigned_report(
            plane,
            bundle,
            submission,
            report_key=report_key,
            independent=independent,
            kernel_passed=kernel_passed,
            observed_axioms=observed_axioms,
        ),
        signer=signer,
        nonce=nonce,
    )


def _attest_report(
    plane: ControlPlane,
    bundle: FormalizationTaskBundleV1,
    submission: ProofSubmissionV1,
    report: VerificationReportV1,
    *,
    signer: HmacAttestationSignerV1 | None = None,
    nonce: str | None = None,
) -> VerificationReportV1:
    assert report.evidence is not None
    attestation = (signer or _verifier_signer()).issue(
        purpose=AttestationPurposeV1.VERIFICATION,
        payload=verification_attestation_payload(
            bundle_id=bundle.bundle_id.value,
            bundle_hash=bundle.handoff_hash().value,
            proof_submission_artifact_digest=_proof_submission_artifact_digest(plane, submission),
            contract_id=bundle.contract.contract_id.value,
            revision=bundle.contract.revision,
            contract_hash=report.contract_hash,
            proof_boundary_hash=report.proof_boundary_hash,
            environment_hash=report.environment_hash,
            report=report,
        ),
        evidence_identity=report.evidence.evidence_id.value,
        ttl_seconds=3600,
        nonce=nonce,
    )
    return report.model_copy(update={"verifier_attestation": attestation})


def _replace_evidence_artifact(
    plane: ControlPlane,
    report: VerificationReportV1,
    mutate: Callable[[dict[str, object]], None],
) -> VerificationReportV1:
    """Write a new canonical artifact for an adversarial binding test, then detach its signature."""

    assert report.evidence is not None
    payload = json.loads(
        plane.artifacts.get_bytes(report.evidence.evidence_artifact_digest).decode("utf-8")
    )
    assert isinstance(payload, dict)
    mutate(payload)
    replacement = plane.artifacts.put_json(payload)
    evidence = report.evidence.model_copy(update={"evidence_artifact_digest": replacement.digest})
    return report.model_copy(update={"evidence": evidence, "verifier_attestation": None})


def test_registration_rejects_unsigned_and_tampered_builder_bundles(tmp_path: Path) -> None:
    plane = _plane(tmp_path)
    signed = _bundle()
    unsigned = signed.model_copy(update={"builder_attestation": None})
    with pytest.raises(InvalidTransition, match="Builder attestation is required"):
        plane.register_bundle(unsigned, idempotency_key="unsigned")

    tampered = signed.model_copy(update={"issued_at": datetime(2026, 1, 2, tzinfo=UTC)})
    with pytest.raises(InvalidTransition, match="Builder attestation was rejected"):
        plane.register_bundle(tampered, idempotency_key="tampered")


def test_registration_rejects_expired_revoked_and_replayed_builder_authority(
    tmp_path: Path,
) -> None:
    clock_state = {"now": datetime(2026, 1, 1, tzinfo=UTC)}

    def clock() -> datetime:
        return clock_state["now"]

    expired = _bundle(signer=_builder_signer(clock))
    clock_state["now"] += timedelta(seconds=3601)
    with pytest.raises(InvalidTransition, match="Builder attestation was rejected"):
        _plane(tmp_path / "expired", clock=clock).register_bundle(
            expired,
            idempotency_key="expired",
        )

    revoked_builder = HmacAttestationKeyV1(
        key_id=_BUILDER_KEY.key_id,
        secret=_BUILDER_KEY.secret,
        allowed_purposes=_BUILDER_KEY.allowed_purposes,
        revoked=True,
    )
    revoked_plane = ControlPlane(
        events=EventStore(tmp_path / "revoked" / "control.db"),
        leases=LeaseStore(tmp_path / "revoked" / "control.db"),
        artifacts=ArtifactStore(tmp_path / "revoked" / "artifacts"),
        attestation_verifier=HmacAttestationVerifierV1(
            {
                revoked_builder.key_id: revoked_builder,
                _VERIFIER_KEY.key_id: _VERIFIER_KEY,
            }
        ),
    )
    with pytest.raises(InvalidTransition, match="Builder attestation was rejected"):
        revoked_plane.register_bundle(_bundle(), idempotency_key="revoked")

    replay_plane = _plane(tmp_path / "replay")
    nonce = "r" * 24
    replay_plane.register_bundle(_bundle(nonce=nonce), idempotency_key="first")
    with pytest.raises(InvalidTransition, match="nonce was replayed"):
        replay_plane.register_bundle(
            _bundle(nonce=nonce, bundle_key="bundle-replayed"),
            idempotency_key="second",
        )


def test_verification_requires_attested_environment_evidence_and_rejects_tampering(
    tmp_path: Path,
) -> None:
    plane = _plane(tmp_path)
    bundle = _bundle()
    plane.register_bundle(bundle, idempotency_key="register")
    claim = plane.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=60,
        idempotency_key="claim",
    )
    submission = _submission(bundle)
    plane.submit_proof(
        bundle.bundle_id.value,
        lease=claim.lease,
        submission=submission,
        idempotency_key="proof",
    )

    all_true_without_authority = _unsigned_report(
        plane,
        bundle,
        submission,
        report_key="unsigned-all-true",
    )
    with pytest.raises(InvalidTransition, match="independent verifier attestation is required"):
        plane.verify_submission(
            bundle.bundle_id.value,
            lease=claim.lease,
            report=all_true_without_authority,
            idempotency_key="unsigned",
        )

    missing_evidence = _passing_report(
        plane,
        bundle,
        submission,
        report_key="missing-evidence",
    ).model_copy(update={"evidence": None})
    with pytest.raises(InvalidTransition, match="environment evidence is required"):
        plane.verify_submission(
            bundle.bundle_id.value,
            lease=claim.lease,
            report=missing_evidence,
            idempotency_key="missing-evidence",
        )

    tampered = _passing_report(
        plane,
        bundle,
        submission,
        report_key="tampered-report",
    ).model_copy(update={"kernel_passed": False})
    with pytest.raises(InvalidTransition, match="verification attestation was rejected"):
        plane.verify_submission(
            bundle.bundle_id.value,
            lease=claim.lease,
            report=tampered,
            idempotency_key="tampered",
        )


def test_verification_rejects_oci_facts_outside_the_frozen_execution_policy(
    tmp_path: Path,
) -> None:
    plane = _plane(tmp_path)
    bundle = _bundle()
    plane.register_bundle(bundle, idempotency_key="register")
    claim = plane.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=60,
        idempotency_key="claim",
    )
    submission = _submission(bundle)
    plane.submit_proof(
        bundle.bundle_id.value,
        lease=claim.lease,
        submission=submission,
        idempotency_key="proof",
    )

    def mutate_image(payload: dict[str, object]) -> None:
        oci = payload["oci"]
        assert isinstance(oci, dict)
        oci["worker_image_digest"] = "sha256:" + ("f" * 64)

    base_image = _unsigned_report(plane, bundle, submission, report_key="wrong-image")
    assert base_image.evidence is not None
    wrong_image = _replace_evidence_artifact(
        plane,
        base_image.model_copy(
            update={
                "evidence": base_image.evidence.model_copy(
                    update={"worker_image_digest": "sha256:" + ("f" * 64)}
                )
            }
        ),
        mutate_image,
    )
    with pytest.raises(InvalidTransition, match="different worker image"):
        plane.verify_submission(
            bundle.bundle_id.value,
            lease=claim.lease,
            report=_attest_report(plane, bundle, submission, wrong_image),
            idempotency_key="wrong-image",
        )

    def mutate_wrapper(payload: dict[str, object]) -> None:
        oci = payload["oci"]
        assert isinstance(oci, dict)
        oci["wrapper_protocol"] = "autolean.oci-lean-wrapper.v0"

    base_wrapper = _unsigned_report(plane, bundle, submission, report_key="wrong-wrapper")
    assert base_wrapper.evidence is not None
    wrong_wrapper = _replace_evidence_artifact(
        plane,
        base_wrapper.model_copy(
            update={
                "evidence": base_wrapper.evidence.model_copy(
                    update={"wrapper_protocol": "autolean.oci-lean-wrapper.v0"}
                )
            }
        ),
        mutate_wrapper,
    )
    with pytest.raises(InvalidTransition, match="different wrapper protocol"):
        plane.verify_submission(
            bundle.bundle_id.value,
            lease=claim.lease,
            report=_attest_report(plane, bundle, submission, wrong_wrapper),
            idempotency_key="wrong-wrapper",
        )

    wrong_policy_hash = digest_text(HashKindV1.VERIFICATION_COMMAND, "wrong-policy")

    def mutate_policy(payload: dict[str, object]) -> None:
        oci = payload["oci"]
        assert isinstance(oci, dict)
        oci["command_policy_hash"] = wrong_policy_hash.model_dump(mode="json")

    base_policy = _unsigned_report(plane, bundle, submission, report_key="wrong-policy")
    assert base_policy.evidence is not None
    wrong_policy = _replace_evidence_artifact(
        plane,
        base_policy.model_copy(
            update={
                "evidence": base_policy.evidence.model_copy(
                    update={"command_policy_hash": wrong_policy_hash}
                )
            }
        ),
        mutate_policy,
    )
    with pytest.raises(InvalidTransition, match="different command policy"):
        plane.verify_submission(
            bundle.bundle_id.value,
            lease=claim.lease,
            report=_attest_report(plane, bundle, submission, wrong_policy),
            idempotency_key="wrong-policy",
        )


def test_verification_reads_only_canonical_typed_evidence_artifacts(tmp_path: Path) -> None:
    plane = _plane(tmp_path)
    bundle = _bundle()
    plane.register_bundle(bundle, idempotency_key="register")
    claim = plane.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=60,
        idempotency_key="claim",
    )
    submission = _submission(bundle)
    plane.submit_proof(
        bundle.bundle_id.value,
        lease=claim.lease,
        submission=submission,
        idempotency_key="proof",
    )

    malformed = _unsigned_report(plane, bundle, submission, report_key="malformed-blob")
    assert malformed.evidence is not None
    malformed_digest = plane.artifacts.put_bytes(b"not-json").digest
    malformed = malformed.model_copy(
        update={
            "evidence": malformed.evidence.model_copy(
                update={"evidence_artifact_digest": malformed_digest}
            )
        }
    )
    with pytest.raises(InvalidTransition, match="not strict JSON"):
        plane.verify_submission(
            bundle.bundle_id.value,
            lease=claim.lease,
            report=_attest_report(plane, bundle, submission, malformed),
            idempotency_key="malformed-blob",
        )

    arbitrary = _unsigned_report(plane, bundle, submission, report_key="arbitrary-blob")
    assert arbitrary.evidence is not None
    arbitrary_digest = plane.artifacts.put_json({"unrelated": "canonical but untyped"}).digest
    arbitrary = arbitrary.model_copy(
        update={
            "evidence": arbitrary.evidence.model_copy(
                update={"evidence_artifact_digest": arbitrary_digest}
            )
        }
    )
    with pytest.raises(InvalidTransition, match="unsupported schema"):
        plane.verify_submission(
            bundle.bundle_id.value,
            lease=claim.lease,
            report=_attest_report(plane, bundle, submission, arbitrary),
            idempotency_key="arbitrary-blob",
        )


def test_verification_cross_binds_evidence_artifact_to_report_bundle_and_proof(
    tmp_path: Path,
) -> None:
    plane = _plane(tmp_path)
    bundle = _bundle()
    plane.register_bundle(bundle, idempotency_key="register")
    claim = plane.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=60,
        idempotency_key="claim",
    )
    submission = _submission(bundle)
    plane.submit_proof(
        bundle.bundle_id.value,
        lease=claim.lease,
        submission=submission,
        idempotency_key="proof",
    )

    def mutate_report(payload: dict[str, object]) -> None:
        payload["verification_report_id"] = _id("different-verification-report").model_dump(
            mode="json"
        )

    def mutate_bundle(payload: dict[str, object]) -> None:
        bundle_hash = payload["bundle_hash"]
        assert isinstance(bundle_hash, dict)
        bundle_hash["value"] = "e" * 64

    def mutate_proof_artifact(payload: dict[str, object]) -> None:
        payload["proof_submission_artifact_digest"] = "d" * 64

    def mutate_candidate(payload: dict[str, object]) -> None:
        oci = payload["oci"]
        assert isinstance(oci, dict)
        oci["candidate_sha256"] = "0" * 64

    scenarios = (
        ("report", mutate_report, "different verification report"),
        ("bundle", mutate_bundle, "different bundle hash"),
        ("proof-artifact", mutate_proof_artifact, "different submitted proof artifact"),
        ("candidate", mutate_candidate, "does not bind the submitted proof bytes"),
    )
    for name, mutate, message in scenarios:
        report = _replace_evidence_artifact(
            plane,
            _unsigned_report(plane, bundle, submission, report_key=f"mismatch-{name}"),
            mutate,
        )
        with pytest.raises(InvalidTransition, match=message):
            plane.verify_submission(
                bundle.bundle_id.value,
                lease=claim.lease,
                report=_attest_report(plane, bundle, submission, report),
                idempotency_key=f"mismatch-{name}",
            )


def test_verification_attestation_nonce_cannot_be_reused_for_another_proof(
    tmp_path: Path,
) -> None:
    plane = _plane(tmp_path)
    bundle = _bundle()
    plane.register_bundle(bundle, idempotency_key="register")
    claim = plane.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=60,
        idempotency_key="claim",
    )
    first_submission = _submission(bundle)
    plane.submit_proof(
        bundle.bundle_id.value,
        lease=claim.lease,
        submission=first_submission,
        idempotency_key="proof-one",
    )
    nonce = "v" * 24
    plane.verify_submission(
        bundle.bundle_id.value,
        lease=claim.lease,
        report=_passing_report(
            plane,
            bundle,
            first_submission,
            report_key="nonce-one",
            nonce=nonce,
        ),
        idempotency_key="verify-one",
    )

    second_submission = first_submission.model_copy(update={"proof_id": _id("proof-two")})
    plane.submit_proof(
        bundle.bundle_id.value,
        lease=claim.lease,
        submission=second_submission,
        idempotency_key="proof-two",
    )
    with pytest.raises(InvalidTransition, match="attestation was replayed"):
        plane.verify_submission(
            bundle.bundle_id.value,
            lease=claim.lease,
            report=_passing_report(
                plane,
                bundle,
                second_submission,
                report_key="nonce-two",
                nonce=nonce,
            ),
            idempotency_key="verify-two",
        )


def test_repeated_delivery_replays_registered_claimed_and_submitted_events_after_restart(
    tmp_path: Path,
) -> None:
    bundle = _bundle()
    first = _plane(tmp_path)
    registered = first.register_bundle(bundle, idempotency_key="register")
    claim = first.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=60,
        idempotency_key="claim",
    )
    submission = _submission(bundle)
    submitted = first.submit_proof(
        bundle.bundle_id.value,
        lease=claim.lease,
        submission=submission,
        idempotency_key="proof",
    )

    restarted = _plane(tmp_path)
    repeated_registration = restarted.register_bundle(bundle, idempotency_key="register-replay")
    repeated_claim = restarted.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=60,
        idempotency_key="claim",
    )
    repeated_submission = restarted.submit_proof(
        bundle.bundle_id.value,
        lease=claim.lease,
        submission=submission,
        idempotency_key="proof",
    )

    assert repeated_registration == registered
    assert repeated_claim.lease == claim.lease
    assert repeated_claim.event.event_id == claim.event.event_id
    assert repeated_submission.event_id == submitted.event_id
    replayed = EventStore(tmp_path / "control.db").read_all()
    assert [event.global_position for event in replayed] == list(range(1, len(replayed) + 1))
    assert [event.event_type for event in replayed] == [
        "task.registered",
        "task.claimed",
        "proof.submitted",
    ]
    assert restarted.get_binding(bundle.bundle_id.value) == registered


def test_stale_fencing_token_cannot_submit_after_expiry_and_restart(tmp_path: Path) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)

    def clock() -> datetime:
        return now

    database = tmp_path / "control.db"
    first = ControlPlane(
        events=EventStore(database),
        leases=LeaseStore(database, clock=clock),
        artifacts=ArtifactStore(tmp_path / "artifacts"),
        attestation_verifier=_attestation_verifier(clock),
        allow_test_only_direct_verifier_attestations=True,
        allow_test_only_unreviewed_bundles=True,
    )
    bundle = _bundle(signer=_builder_signer(clock))
    first.register_bundle(bundle, idempotency_key="register")
    old_claim = first.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=5,
        idempotency_key="old-claim",
    )

    now += timedelta(seconds=6)
    restarted = ControlPlane(
        events=EventStore(database),
        leases=LeaseStore(database, clock=clock),
        artifacts=ArtifactStore(tmp_path / "artifacts"),
        attestation_verifier=_attestation_verifier(clock),
        allow_test_only_unreviewed_bundles=True,
    )
    replacement = restarted.claim(
        bundle.bundle_id.value,
        worker_id="worker-b",
        ttl_seconds=5,
        idempotency_key="replacement-claim",
    )
    assert replacement.lease.fencing_token > old_claim.lease.fencing_token
    with pytest.raises(StaleFence):
        restarted.submit_proof(
            bundle.bundle_id.value,
            lease=old_claim.lease,
            submission=_submission(bundle),
            idempotency_key="stale-proof",
        )


def test_verification_retry_after_restart_replays_one_terminal_verdict(tmp_path: Path) -> None:
    plane = _plane(tmp_path)
    bundle = _bundle()
    plane.register_bundle(bundle, idempotency_key="register")
    claim = plane.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=60,
        idempotency_key="claim",
    )
    submission = _submission(bundle)
    plane.submit_proof(
        bundle.bundle_id.value,
        lease=claim.lease,
        submission=submission,
        idempotency_key="proof",
    )
    report = _passing_report(plane, bundle, submission, report_key="retry")
    first = plane.verify_submission(
        bundle.bundle_id.value,
        lease=claim.lease,
        report=report,
        idempotency_key="verify",
    )

    restarted = _plane(tmp_path)
    repeated = restarted.verify_submission(
        bundle.bundle_id.value,
        lease=claim.lease,
        report=report,
        idempotency_key="verify",
    )
    assert repeated.accepted
    assert repeated.event.event_id == first.event.event_id
    assert restarted.events.count_events(entity_type="verification") == 1
    assert len(restarted.events.read_stream("verification", submission.proof_id.value)) == 1


def test_durable_replays_survive_expired_lease_and_attestations(tmp_path: Path) -> None:
    clock_state = {"now": datetime(2026, 1, 1, tzinfo=UTC)}

    def clock() -> datetime:
        return clock_state["now"]

    bundle = _bundle(signer=_builder_signer(clock))
    first = _plane(tmp_path, clock=clock)
    registered = first.register_bundle(bundle, idempotency_key="register")
    claim = first.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=1,
        idempotency_key="claim",
    )
    submission = _submission(bundle)
    submitted = first.submit_proof(
        bundle.bundle_id.value,
        lease=claim.lease,
        submission=submission,
        idempotency_key="proof",
    )
    report = _passing_report(
        first,
        bundle,
        submission,
        report_key="durable-replay",
        signer=_verifier_signer(clock),
    )
    verified = first.verify_submission(
        bundle.bundle_id.value,
        lease=claim.lease,
        report=report,
        idempotency_key="verify",
    )

    clock_state["now"] += timedelta(seconds=3601)
    restarted = _plane(tmp_path, clock=clock)
    assert restarted.register_bundle(bundle, idempotency_key="register") == registered
    replayed_claim = restarted.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=1,
        idempotency_key="claim",
    )
    assert replayed_claim == claim
    assert (
        restarted.submit_proof(
            bundle.bundle_id.value,
            lease=claim.lease,
            submission=submission,
            idempotency_key="proof",
        ).event_id
        == submitted.event_id
    )
    replayed_verification = restarted.verify_submission(
        bundle.bundle_id.value,
        lease=claim.lease,
        report=report,
        idempotency_key="verify",
    )
    assert replayed_verification == verified
    assert restarted.events.count_events() == first.events.count_events()

    changed_source = "by\n  exact rfl"
    changed_submission = submission.model_copy(
        update={
            "proof_source": changed_source,
            "proof_source_hash": digest_text(HashKindV1.PROOF_SOURCE, changed_source),
        }
    )
    with pytest.raises(IdempotencyConflict):
        restarted.submit_proof(
            bundle.bundle_id.value,
            lease=claim.lease,
            submission=changed_submission,
            idempotency_key="proof",
        )


def test_concurrent_verifiers_cannot_commit_two_terminal_verdicts_for_one_proof(
    tmp_path: Path,
) -> None:
    first = _plane(tmp_path)
    second = _plane(tmp_path)
    bundle = _bundle()
    first.register_bundle(bundle, idempotency_key="register")
    claim = first.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=60,
        idempotency_key="claim",
    )
    submission = _submission(bundle)
    first.submit_proof(
        bundle.bundle_id.value,
        lease=claim.lease,
        submission=submission,
        idempotency_key="proof",
    )
    reports = (
        _passing_report(first, bundle, submission, report_key="concurrent-a"),
        _passing_report(first, bundle, submission, report_key="concurrent-b"),
    )

    def verify(index: int) -> VerificationOutcome:
        plane = first if index == 0 else second
        return plane.verify_submission(
            bundle.bundle_id.value,
            lease=claim.lease,
            report=reports[index],
            idempotency_key=f"verify-{index}",
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(verify, index) for index in range(2)]

    outcomes: list[VerificationOutcome] = []
    failures: list[InvalidTransition] = []
    for future in futures:
        try:
            outcomes.append(future.result())
        except InvalidTransition as error:
            failures.append(error)

    assert len(outcomes) == 1
    assert outcomes[0].accepted
    assert len(failures) == 1
    assert "terminal verification verdict" in str(failures[0])
    replayed = EventStore(tmp_path / "control.db").read_stream(
        "verification", submission.proof_id.value
    )
    assert len(replayed) == 1
    assert replayed[0].payload["report_id"] in {report.report_id.value for report in reports}


def test_rejected_verdict_is_terminal_for_the_proof(tmp_path: Path) -> None:
    plane = _plane(tmp_path)
    bundle = _bundle()
    plane.register_bundle(bundle, idempotency_key="register")
    claim = plane.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=60,
        idempotency_key="claim",
    )
    submission = _submission(bundle)
    plane.submit_proof(
        bundle.bundle_id.value,
        lease=claim.lease,
        submission=submission,
        idempotency_key="proof",
    )
    rejected = _passing_report(
        plane,
        bundle,
        submission,
        report_key="rejected",
        kernel_passed=False,
    )
    outcome = plane.verify_submission(
        bundle.bundle_id.value,
        lease=claim.lease,
        report=rejected,
        idempotency_key="verify-rejected",
    )
    assert not outcome.accepted

    with pytest.raises(InvalidTransition, match="terminal verification verdict"):
        plane.verify_submission(
            bundle.bundle_id.value,
            lease=claim.lease,
            report=_passing_report(plane, bundle, submission, report_key="second"),
            idempotency_key="verify-second",
        )


def test_atomic_fence_rejects_proof_write_after_handover_between_check_and_append(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock_state: dict[str, datetime] = {"now": datetime(2026, 1, 1, tzinfo=UTC)}

    def clock() -> datetime:
        return clock_state["now"]

    database = tmp_path / "control.db"
    plane = ControlPlane(
        events=EventStore(database, clock=clock),
        leases=LeaseStore(database, clock=clock),
        artifacts=ArtifactStore(tmp_path / "artifacts"),
        attestation_verifier=_attestation_verifier(clock),
        allow_test_only_direct_verifier_attestations=True,
        allow_test_only_unreviewed_bundles=True,
    )
    bundle = _bundle(signer=_builder_signer(clock))
    plane.register_bundle(bundle, idempotency_key="register")
    old_claim = plane.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=5,
        idempotency_key="claim-a",
    )
    original_assert = plane._assert_lease

    def assert_then_handover(task_id: str, lease: Lease) -> None:
        original_assert(task_id, lease)
        clock_state["now"] += timedelta(seconds=6)
        replacement = plane.leases.claim(task_id, "worker-b", ttl_seconds=5)
        assert replacement.fencing_token > lease.fencing_token

    monkeypatch.setattr(plane, "_assert_lease", assert_then_handover)
    with pytest.raises(StaleFence):
        plane.submit_proof(
            bundle.bundle_id.value,
            lease=old_claim.lease,
            submission=_submission(bundle),
            idempotency_key="old-proof",
        )
    assert plane.events.count_events(entity_type="proof") == 0


def test_atomic_fence_rejects_verdict_after_expiry_between_check_and_append(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock_state: dict[str, datetime] = {"now": datetime(2026, 1, 1, tzinfo=UTC)}

    def clock() -> datetime:
        return clock_state["now"]

    database = tmp_path / "control.db"
    plane = ControlPlane(
        events=EventStore(database, clock=clock),
        leases=LeaseStore(database, clock=clock),
        artifacts=ArtifactStore(tmp_path / "artifacts"),
        attestation_verifier=_attestation_verifier(clock),
        allow_test_only_direct_verifier_attestations=True,
        allow_test_only_unreviewed_bundles=True,
    )
    bundle = _bundle(signer=_builder_signer(clock))
    plane.register_bundle(bundle, idempotency_key="register")
    old_claim = plane.claim(
        bundle.bundle_id.value,
        worker_id="worker-a",
        ttl_seconds=5,
        idempotency_key="claim-a",
    )
    submission = _submission(bundle)
    plane.submit_proof(
        bundle.bundle_id.value,
        lease=old_claim.lease,
        submission=submission,
        idempotency_key="proof",
    )
    report = _passing_report(
        plane,
        bundle,
        submission,
        report_key="fenced-verdict",
        signer=_verifier_signer(clock),
    )
    original_assert = plane._assert_lease

    def assert_then_expire(task_id: str, lease: Lease) -> None:
        original_assert(task_id, lease)
        clock_state["now"] += timedelta(seconds=6)

    monkeypatch.setattr(plane, "_assert_lease", assert_then_expire)
    with pytest.raises(StaleFence):
        plane.verify_submission(
            bundle.bundle_id.value,
            lease=old_claim.lease,
            report=report,
            idempotency_key="old-verdict",
        )
    assert plane.events.count_events(entity_type="verification") == 0


def test_concurrent_exact_bundle_registration_reuses_one_atomic_binding(
    tmp_path: Path,
) -> None:
    first = _plane(tmp_path)
    second = _plane(tmp_path)
    bundle = _bundle()
    ready = Barrier(2)

    def register(plane: ControlPlane, key: str):
        ready.wait()
        return plane.register_bundle(bundle, idempotency_key=key)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = (
            executor.submit(register, first, "register-a"),
            executor.submit(register, second, "register-b"),
        )
        bindings = tuple(future.result() for future in futures)

    assert bindings[0] == bindings[1]
    database = tmp_path / "control.db"
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM contract_revision_bindings").fetchone() == (
            1,
        )
        assert connection.execute(
            """
            SELECT COUNT(*) FROM events
            WHERE entity_type = 'task' AND event_type = 'task.registered'
            """
        ).fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM attestation_nonce_uses").fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*) FROM idempotency_records WHERE scope = 'register_bundle'"
        ).fetchone() == (2,)


def test_concurrent_distinct_bundle_ids_cannot_bind_one_contract_revision(
    tmp_path: Path,
) -> None:
    first = _plane(tmp_path)
    second = _plane(tmp_path)
    bundle_a = _bundle(bundle_key="bundle-a")
    bundle_b = _rebundle(bundle_a, bundle_key="bundle-b")
    assert bundle_a.contract.semantic_hash() == bundle_b.contract.semantic_hash()
    assert bundle_a.handoff_hash() != bundle_b.handoff_hash()
    ready = Barrier(2)

    def register(plane: ControlPlane, bundle: FormalizationTaskBundleV1, key: str):
        ready.wait()
        return plane.register_bundle(bundle, idempotency_key=key)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = (
            executor.submit(register, first, bundle_a, "register-a"),
            executor.submit(register, second, bundle_b, "register-b"),
        )

    outcomes = []
    failures: list[InvalidTransition] = []
    for future in futures:
        try:
            outcomes.append(future.result())
        except InvalidTransition as error:
            failures.append(error)

    assert len(outcomes) == 1
    assert len(failures) == 1
    assert "contract revision" in str(failures[0])
    database = tmp_path / "control.db"
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            """
            SELECT bundle_id, bundle_hash, registration_event_id
            FROM contract_revision_bindings
            """
        ).fetchone()
        assert row is not None
        accepted = bundle_a if row[0] == bundle_a.bundle_id.value else bundle_b
        assert row[0] == accepted.bundle_id.value
        assert row[1] == accepted.handoff_hash().value
        assert connection.execute(
            """
            SELECT COUNT(*) FROM events
            WHERE entity_type = 'task' AND event_type = 'task.registered'
            """
        ).fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM attestation_nonce_uses").fetchone() == (1,)


def test_restart_replays_exact_binding_and_rejects_changed_handoff_hash(
    tmp_path: Path,
) -> None:
    bundle = _bundle()
    first = _plane(tmp_path)
    registered = first.register_bundle(bundle, idempotency_key="register")

    restarted = _plane(tmp_path)
    assert restarted.register_bundle(bundle, idempotency_key="register-after-restart") == registered
    changed = _rebundle(bundle, issued_at=bundle.issued_at + timedelta(seconds=1))
    assert changed.bundle_id == bundle.bundle_id
    assert changed.handoff_hash() != bundle.handoff_hash()
    with pytest.raises(InvalidTransition, match="already bound"):
        restarted.register_bundle(changed, idempotency_key="changed-handoff")

    with sqlite3.connect(tmp_path / "control.db") as connection:
        assert connection.execute("SELECT COUNT(*) FROM contract_revision_bindings").fetchone() == (
            1,
        )
        assert connection.execute(
            """
            SELECT COUNT(*) FROM events
            WHERE entity_type = 'task' AND event_type = 'task.registered'
            """
        ).fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM attestation_nonce_uses").fetchone() == (1,)
        assert connection.execute(
            """
            SELECT COUNT(*) FROM idempotency_records
            WHERE scope = 'register_bundle' AND key = 'changed-handoff'
            """
        ).fetchone() == (0,)


def test_contract_revision_projection_rejects_update_and_delete(tmp_path: Path) -> None:
    bundle = _bundle()
    _plane(tmp_path).register_bundle(bundle, idempotency_key="register")
    database = tmp_path / "control.db"

    with (
        sqlite3.connect(database) as connection,
        pytest.raises(sqlite3.IntegrityError, match="immutable"),
    ):
        connection.execute(
            "UPDATE contract_revision_bindings SET bundle_hash = ?",
            ("f" * 64,),
        )
    with (
        sqlite3.connect(database) as connection,
        pytest.raises(sqlite3.IntegrityError, match="immutable"),
    ):
        connection.execute("DELETE FROM contract_revision_bindings")


def test_legacy_registration_event_is_backfilled_and_verified_on_restart(
    tmp_path: Path,
) -> None:
    bundle = _bundle()
    plane = _plane(tmp_path)
    registered = plane.register_bundle(bundle, idempotency_key="register")
    database = tmp_path / "control.db"
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TABLE contract_revision_bindings")

    restarted_store = EventStore(database)
    with restarted_store.connection() as connection:
        row = connection.execute(
            """
            SELECT contract_id, revision, bundle_id, bundle_hash, contract_hash
            FROM contract_revision_bindings
            """
        ).fetchone()
    assert row is not None
    assert tuple(row) == (
        registered.contract_id,
        registered.revision,
        registered.bundle_id,
        registered.bundle_hash,
        registered.contract_hash,
    )

    restarted = _plane(tmp_path)
    assert restarted.register_bundle(bundle, idempotency_key="backfilled-replay") == registered


def test_legacy_conflicting_contract_revision_events_refuse_atomic_migration(
    tmp_path: Path,
) -> None:
    database = tmp_path / "control.db"
    EventStore(database)
    bundle_a = _bundle(bundle_key="legacy-a")
    bundle_b = _rebundle(bundle_a, bundle_key="legacy-b")
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("DROP TABLE contract_revision_bindings")
        for index, bundle in enumerate((bundle_a, bundle_b), start=1):
            payload = {
                "bundle_id": bundle.bundle_id.value,
                "bundle_hash": bundle.handoff_hash().value,
                "contract_id": bundle.contract.contract_id.value,
                "revision": bundle.contract.revision,
                "contract_hash": bundle.contract.semantic_hash().value,
            }
            connection.execute(
                """
                INSERT INTO events (
                    event_id, entity_type, entity_id, entity_sequence,
                    event_type, payload_json, metadata_json, recorded_at
                ) VALUES (?, 'task', ?, 1, 'task.registered', ?, '{}', ?)
                """,
                (
                    f"legacy-registration-{index}",
                    bundle.bundle_id.value,
                    json.dumps(payload, sort_keys=True, separators=(",", ":")),
                    datetime.now(UTC).isoformat(),
                ),
            )
            connection.execute(
                """
                INSERT INTO entity_versions (entity_type, entity_id, sequence)
                VALUES ('task', ?, 1)
                """,
                (bundle.bundle_id.value,),
            )

    with pytest.raises(ProjectionError, match="duplicate contract revision"):
        EventStore(database)

    with sqlite3.connect(database) as connection:
        assert (
            connection.execute(
                """
            SELECT name FROM sqlite_master
            WHERE type = 'table' AND name = 'contract_revision_bindings'
            """
            ).fetchone()
            is None
        )


@pytest.mark.parametrize("payload_encoding", ("noncanonical", "duplicate_key"))
def test_legacy_registration_projection_rejects_ambiguous_json(
    tmp_path: Path,
    payload_encoding: str,
) -> None:
    database = tmp_path / "control.db"
    EventStore(database)
    bundle = _bundle(bundle_key=f"legacy-{payload_encoding}")
    payload = {
        "bundle_id": bundle.bundle_id.value,
        "bundle_hash": bundle.handoff_hash().value,
        "contract_id": bundle.contract.contract_id.value,
        "revision": bundle.contract.revision,
        "contract_hash": bundle.contract.semantic_hash().value,
    }
    canonical_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    if payload_encoding == "noncanonical":
        payload_json = json.dumps(payload, sort_keys=True, indent=2)
    else:
        payload_json = canonical_payload.replace(
            '"bundle_id":',
            f'"bundle_id":"{bundle.bundle_id.value}","bundle_id":',
            1,
        )

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("DROP TABLE contract_revision_bindings")
        connection.execute(
            """
            INSERT INTO events (
                event_id, entity_type, entity_id, entity_sequence,
                event_type, payload_json, metadata_json, recorded_at
            ) VALUES ('ambiguous-registration', 'task', ?, 1, 'task.registered', ?, '{}', ?)
            """,
            (
                bundle.bundle_id.value,
                payload_json,
                datetime.now(UTC).isoformat(),
            ),
        )
        connection.execute(
            """
            INSERT INTO entity_versions (entity_type, entity_id, sequence)
            VALUES ('task', ?, 1)
            """,
            (bundle.bundle_id.value,),
        )

    with pytest.raises(ProjectionError, match="not canonical JSON"):
        EventStore(database)

    with sqlite3.connect(database) as connection:
        assert (
            connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type = 'table' AND name = 'contract_revision_bindings'
                """
            ).fetchone()
            is None
        )


def test_claimed_bundle_can_be_fetched_after_restart_and_materialized(
    tmp_path: Path,
) -> None:
    bundle = _bundle(bundle_key="claimed-fetch")
    first = _plane(tmp_path)
    binding = first.register_bundle(bundle, idempotency_key="register-claimed-fetch")
    receipt = first.claim(
        bundle.bundle_id.value,
        worker_id="worker-claimed-fetch",
        ttl_seconds=60,
        idempotency_key="claim-claimed-fetch",
    )

    restarted = _plane(tmp_path)
    fetched = restarted.fetch_claimed_bundle(receipt)
    replayed = restarted.claim(
        bundle.bundle_id.value,
        worker_id="worker-claimed-fetch",
        ttl_seconds=60,
        idempotency_key="claim-claimed-fetch",
    )

    from autolean_prover.execution import WorkspaceMaterializer

    workspace = WorkspaceMaterializer().materialize(
        fetched,
        tmp_path / "claimed-fetch-workspace",
    )
    assert fetched == bundle
    assert receipt.bundle_id == binding.bundle_id
    assert receipt.bundle_hash == binding.bundle_hash
    assert receipt.bundle_artifact == binding.bundle_artifact
    assert replayed == receipt
    assert restarted.fetch_claimed_bundle(replayed) == bundle
    assert workspace.bundle == bundle
    assert workspace.proof_path.name == "Proof.lean"

    with pytest.raises(InvalidTransition, match="different bundle"):
        restarted.fetch_claimed_bundle(replace(receipt, bundle_id=_id("forged-bundle").value))
    with pytest.raises(InvalidTransition, match="persisted task claim"):
        restarted.fetch_claimed_bundle(replace(receipt, bundle_hash="f" * 64))
    with pytest.raises(InvalidTransition, match="persisted task claim"):
        restarted.fetch_claimed_bundle(
            replace(
                receipt,
                bundle_artifact=ArtifactRef(
                    digest="f" * 64,
                    size=receipt.bundle_artifact.size,
                ),
            )
        )


def test_fetch_claimed_bundle_rejects_stale_lease_and_corrupt_artifact(
    tmp_path: Path,
) -> None:
    now = [datetime.now(UTC)]

    def clock() -> datetime:
        return now[0]

    plane = _plane(tmp_path, clock=clock)
    bundle = _bundle(
        bundle_key="claimed-fetch-stale",
        signer=_builder_signer(clock),
        nonce="claimed-fetch-stale-builder",
    )
    plane.register_bundle(bundle, idempotency_key="register-claimed-fetch-stale")
    receipt = plane.claim(
        bundle.bundle_id.value,
        worker_id="worker-claimed-fetch-stale",
        ttl_seconds=1,
        idempotency_key="claim-claimed-fetch-stale",
    )

    artifact_path = plane.artifacts.path_for(receipt.bundle_artifact)
    artifact_path.write_bytes(b"corrupt")
    with pytest.raises(InvalidTransition, match="unavailable or corrupt"):
        plane.fetch_claimed_bundle(receipt)

    now[0] += timedelta(seconds=2)
    restarted = _plane(tmp_path, clock=clock)
    with pytest.raises(StaleFence):
        restarted.fetch_claimed_bundle(receipt)


def test_submit_proof_rejects_non_candidate_status_and_missing_provenance(
    tmp_path: Path,
) -> None:
    plane = _plane(tmp_path)
    bundle = _bundle(bundle_key="submission-gate")
    plane.register_bundle(bundle, idempotency_key="register-submission-gate")
    receipt = plane.claim(
        bundle.bundle_id.value,
        worker_id="submission-gate-worker",
        ttl_seconds=60,
        idempotency_key="claim-submission-gate",
    )
    submission = _submission(bundle)

    with pytest.raises(InvalidTransition, match="candidate proof status only"):
        plane.submit_proof(
            bundle.bundle_id.value,
            lease=receipt.lease,
            submission=submission.model_copy(update={"status": ProofStatusV1.KERNEL_VERIFIED}),
            idempotency_key="submit-non-candidate",
        )
    with pytest.raises(InvalidTransition, match="explicit provenance"):
        plane.submit_proof(
            bundle.bundle_id.value,
            lease=receipt.lease,
            submission=submission.model_copy(update={"provenance": ()}),
            idempotency_key="submit-without-provenance",
        )
    assert plane.events.read_stream("proof", submission.proof_id.value) == ()


def test_v1_bundle_keeps_line_ranged_edit_region_payload_compatible() -> None:
    region = EditRegionV1(
        artifact_ref="Proof.lean",
        start_line=1,
        end_line=1,
    )

    bundle = _bundle(
        bundle_key="line-ranged-edit-region",
        allowed_edit_regions=(region,),
    )

    assert bundle.contract.policy.allowed_edit_regions == (region,)


def test_registration_replay_rejects_an_invalid_mathlib_axiom_policy(
    tmp_path: Path,
) -> None:
    plane = _plane(tmp_path)
    bundle = _bundle(bundle_key="invalid-replayed-axiom-policy")
    plane.register_bundle(bundle, idempotency_key="register-valid-axiom-policy")
    event = plane.events.read_stream("task", bundle.bundle_id.value)[0]
    payload = dict(event.payload)
    payload["axiom_profile"] = "mathlib"
    payload["axioms_allowlist"] = ["Classical.choice", "AutoLean.UnsafeAxiom"]
    tampered = replace(event, payload=payload)

    with pytest.raises(InvalidTransition, match="invalid axiom policy"):
        plane._binding_from_event(tampered)
