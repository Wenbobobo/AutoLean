from __future__ import annotations

from datetime import UTC, datetime

from autolean_contracts import (
    AlignmentTargetV1,
    ExecutionGraphV1,
    FidelityRiskV1,
    FormalGraphV1,
    FormalizationTaskBundleV1,
    FormalSpecificationV1,
    FreezeRecordV1,
    GraphBundleV1,
    HashKindV1,
    LeanEnvironmentV1,
    MathematicalGraphV1,
    MathematicalSpecificationV1,
    OciVerifierExecutionPolicyV1,
    PermissionDecisionV1,
    ReleaseTierV1,
    RightsRecordV1,
    SourceRecordV1,
    SourceSpanV1,
    StatementContractV1,
    StatementStatusV1,
    TaskKindV1,
    TaskPolicyV1,
    build_proof_boundary,
    digest_model,
    digest_text,
    stable_identifier,
)


def stable_id(key: str):
    return stable_identifier("prover-test", key)


def frozen_bundle(*, external_egress: bool = False) -> FormalizationTaskBundleV1:
    source_id = stable_id("source")
    span = SourceSpanV1(
        span_id=stable_id("span"),
        locator="fixture:1",
        content_hash=digest_text(HashKindV1.SOURCE_SPAN, "n equals n"),
        permitted_excerpt="n equals n",
    )
    source = SourceRecordV1(
        source_id=source_id,
        work_id="fixture",
        title="Fixture source",
        version="1",
        locator="fixture://source",
        content_hash=digest_text(HashKindV1.SOURCE_BYTES, "source snapshot"),
        spans=(span,),
    )
    rights = RightsRecordV1(
        rights_id=stable_id("rights"),
        source_id=source_id,
        source_license="CC0-1.0",
        overall_decision=PermissionDecisionV1.ALLOW,
        model_egress=(
            PermissionDecisionV1.ALLOW if external_egress else PermissionDecisionV1.UNKNOWN
        ),
        allowed_endpoint_classes=("approved_external",) if external_egress else (),
        reviewed_by="rights-reviewer",
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
            verifier_execution_policy=OciVerifierExecutionPolicyV1(
                worker_image_digest="sha256:" + "a" * 64,
            ),
            environment_hash=digest_text(HashKindV1.ENVIRONMENT, "fixture-environment"),
        ),
        imports_allowlist=("Mathlib",),
    )
    draft = StatementContractV1(
        contract_id=stable_id("contract"),
        revision=1,
        task_kind=TaskKindV1.KNOWN_THEOREM,
        source=source,
        rights=rights,
        mathematics=MathematicalSpecificationV1(
            informal_statement="Every n equals itself.",
            normalized_statement="For every natural n, n equals n.",
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
        ),
    )
    frozen_payload = draft.model_dump(mode="python", round_trip=True)
    frozen_payload.update(
        {
            "status": StatementStatusV1.FROZEN,
            "freeze": FreezeRecordV1(
                contract_hash=draft.semantic_hash(),
                source_hash=source.content_hash,
                statement_source_hash=formal.statement_source_hash,
                elaborated_type_hash=formal.elaborated_type_hash,
                frozen_by="fixture",
            ),
        }
    )
    frozen = StatementContractV1.model_validate(frozen_payload)
    graphs = GraphBundleV1(
        mathematical=MathematicalGraphV1(graph_id=stable_id("math"), revision=1),
        formal=FormalGraphV1(graph_id=stable_id("formal"), revision=1),
        execution=ExecutionGraphV1(graph_id=stable_id("execution"), revision=1),
    )
    return FormalizationTaskBundleV1(
        bundle_id=stable_id("bundle"),
        contract=frozen,
        graphs=graphs,
        graph_snapshot_hash=digest_model(HashKindV1.GRAPH_SNAPSHOT, graphs),
        proof_boundary=build_proof_boundary(frozen),
    )
