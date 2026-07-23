from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from autolean_contracts import (
    ContractChangeV1,
    EventEnvelopeV1,
    FidelityRiskV1,
    FormalSpecificationV1,
    FreezeRecordV1,
    HashKindV1,
    LeanEnvironmentV1,
    MathematicalEdgeKindV1,
    MathematicalEdgeV1,
    MathematicalGraphV1,
    MathematicalNodeKindV1,
    MathematicalNodeV1,
    MathematicalSpecificationV1,
    OciVerifierExecutionPolicyV1,
    PermissionDecisionV1,
    ReleaseTierV1,
    RightsRecordV1,
    SourceRecordV1,
    StableIdentifierV1,
    StatementContractV1,
    StatementStatusV1,
    TaskKindV1,
    TaskPolicyV1,
    digest_model,
    digest_text,
    stable_identifier,
)


def _source() -> SourceRecordV1:
    return SourceRecordV1(
        source_id=stable_identifier("source", "nested-metadata"),
        work_id="work",
        title="A source",
        version="1",
        locator="https://example.invalid/source",
        content_hash=digest_text(HashKindV1.SOURCE_BYTES, "source bytes"),
        metadata={"nested": {"labels": ["alpha"]}},
    )


def _draft_contract() -> StatementContractV1:
    source = _source()
    environment = LeanEnvironmentV1(
        lean_version="v4.0.0",
        mathlib_revision="pinned-mathlib",
        verifier_execution_policy=OciVerifierExecutionPolicyV1(
            worker_image_digest="sha256:" + "c" * 64,
        ),
        environment_hash=digest_text(HashKindV1.ENVIRONMENT, "environment"),
    )
    statement = "theorem sample : True"
    return StatementContractV1(
        contract_id=stable_identifier("contract", "draft"),
        revision=1,
        task_kind=TaskKindV1.KNOWN_THEOREM,
        source=source,
        rights=RightsRecordV1(
            rights_id=stable_identifier("rights", "draft"),
            source_id=source.source_id,
            overall_decision=PermissionDecisionV1.RESTRICTED,
        ),
        mathematics=MathematicalSpecificationV1(
            informal_statement="The sample theorem holds.",
            normalized_statement="The sample theorem holds.",
        ),
        formal=FormalSpecificationV1(
            declaration_name="sample",
            namespace="AutoLean",
            lean_statement_source=statement,
            statement_source_hash=digest_text(HashKindV1.STATEMENT_SOURCE, statement),
            environment=environment,
        ),
        policy=TaskPolicyV1(
            release_tier=ReleaseTierV1.SANDBOX,
            fidelity_risk=FidelityRiskV1.L1_SIMPLE,
        ),
    )


def _event_with_payload(payload: dict[str, object]) -> EventEnvelopeV1:
    event_id = stable_identifier("event", "nested-payload")
    stream_id = stable_identifier("stream", "nested-payload")
    occurred_at = datetime(2026, 1, 1, tzinfo=UTC)
    # Event hashes include every field except themselves.  The timestamp uses the
    # canonical Pydantic JSON spelling for UTC, avoiding any validation bypass.
    preimage = {
        "schema_version": "1.0",
        "event_id": event_id.model_dump(mode="json"),
        "stream_id": stream_id.model_dump(mode="json"),
        "sequence": 0,
        "event_type": "task.created",
        "actor_id": "test",
        "occurred_at": "2026-01-01T00:00:00Z",
        "payload": payload,
        "previous_event_hash": None,
    }
    return EventEnvelopeV1(
        event_id=event_id,
        stream_id=stream_id,
        sequence=0,
        event_type="task.created",
        actor_id="test",
        occurred_at=occurred_at,
        payload=payload,
        event_hash=digest_model(HashKindV1.EVENT, preimage),
    )


def test_nested_contract_containers_are_recursively_immutable_and_json_safe() -> None:
    source = _source()
    assert source.metadata["nested"]["labels"] == ("alpha",)
    with pytest.raises(TypeError, match="immutable"):
        source.metadata["new"] = "value"
    with pytest.raises(TypeError, match="immutable"):
        source.metadata["nested"]["labels"] += ("beta",)
    assert source.model_dump(mode="json")["metadata"] == {"nested": {"labels": ["alpha"]}}

    change = ContractChangeV1(
        path="/mathematics/assumptions",
        operation="replace",
        before={"nested": [{"condition": "finite"}]},
    )
    assert change.before == {"nested": ({"condition": "finite"},)}
    with pytest.raises(TypeError, match="immutable"):
        assert isinstance(change.before, dict)
        change.before["new"] = "value"

    event = _event_with_payload({"run": {"attempts": [1, 2]}})
    assert event.payload["run"]["attempts"] == (1, 2)
    with pytest.raises(TypeError, match="immutable"):
        event.payload["run"]["attempts"] += (3,)


def test_model_copy_revalidates_cross_field_state_machine_and_field_invariants() -> None:
    draft = _draft_contract()
    replacement = draft.model_copy(update={"revision": 2})
    assert replacement.revision == 2
    assert replacement.status is StatementStatusV1.DRAFT

    with pytest.raises(ValidationError, match="frozen contracts require a freeze record"):
        draft.model_copy(update={"status": StatementStatusV1.FROZEN})

    policy = TaskPolicyV1(
        release_tier=ReleaseTierV1.SANDBOX,
        fidelity_risk=FidelityRiskV1.L1_SIMPLE,
        proof_budget={"attempts": 1},
    )
    updated_policy = policy.model_copy(update={"proof_budget": {"attempts": 2}})
    assert updated_policy.proof_budget == {"attempts": 2}
    with pytest.raises(TypeError, match="immutable"):
        updated_policy.proof_budget["attempts"] = 3
    with pytest.raises(ValidationError, match="proof budget values must be non-negative"):
        policy.model_copy(update={"proof_budget": {"attempts": -1}})
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        policy.model_copy(update={"unknown_field": True})


def test_freeze_record_requires_typed_source_preparation_commitment() -> None:
    draft = _draft_contract()
    common = {
        "contract_hash": draft.semantic_hash(),
        "source_hash": draft.source.content_hash,
        "statement_source_hash": draft.formal.statement_source_hash,
        "frozen_by": "fixture",
    }

    legacy = FreezeRecordV1.model_validate(common)
    assert legacy.source_preparation_id is None
    assert legacy.source_preparation_hash is None
    with pytest.raises(ValidationError, match="present together"):
        FreezeRecordV1(
            **common,
            source_preparation_id=stable_identifier("source-preparation", "source-preparation"),
        )
    with pytest.raises(ValidationError, match="source-preparation namespace"):
        FreezeRecordV1(
            **common,
            source_preparation_id=stable_identifier("fixture", "source-preparation"),
            source_preparation_hash=digest_text(
                HashKindV1.SOURCE_PREPARATION, "source-preparation"
            ),
        )
    with pytest.raises(ValidationError, match="source_preparation_hash must use digest kind"):
        FreezeRecordV1(
            **common,
            source_preparation_id=stable_identifier("source-preparation", "source-preparation"),
            source_preparation_hash=digest_text(HashKindV1.CONTRACT, "wrong-kind"),
        )


def test_stable_identifier_namespace_must_match_its_urn() -> None:
    with pytest.raises(ValidationError, match="namespace must match"):
        StableIdentifierV1(
            namespace="builder",
            value="urn:autolean:v1:prover:00000000-0000-0000-0000-000000000000",
        )
    with pytest.raises(ValidationError):
        StableIdentifierV1(
            namespace="Builder Team",
            value="urn:autolean:v1:builder-team:00000000-0000-0000-0000-000000000000",
        )

    identifier = stable_identifier("builder.team", "formalization")
    assert identifier.value.startswith("urn:autolean:v1:builder.team:")


@pytest.mark.parametrize(
    "kind",
    [MathematicalEdgeKindV1.EQUIVALENT_TO, MathematicalEdgeKindV1.MOTIVATES],
)
def test_mathematical_graph_rejects_self_edges_even_when_cycles_are_allowed(
    kind: MathematicalEdgeKindV1,
) -> None:
    node = MathematicalNodeV1(
        node_id=stable_identifier("math-node", "self"),
        kind=MathematicalNodeKindV1.THEOREM,
        label="Self reference",
    )
    with pytest.raises(ValidationError, match="self-referential"):
        MathematicalGraphV1(
            graph_id=stable_identifier("math-graph", kind.value),
            revision=1,
            nodes=(node,),
            edges=(
                MathematicalEdgeV1(
                    edge_id=stable_identifier("math-edge", kind.value),
                    source=node.node_id,
                    target=node.node_id,
                    kind=kind,
                ),
            ),
        )


def test_mathematical_graph_checks_duplicate_edge_ids_across_all_edge_kinds() -> None:
    left = MathematicalNodeV1(
        node_id=stable_identifier("math-node", "left"),
        kind=MathematicalNodeKindV1.DEFINITION,
        label="Left",
    )
    right = MathematicalNodeV1(
        node_id=stable_identifier("math-node", "right"),
        kind=MathematicalNodeKindV1.THEOREM,
        label="Right",
    )
    duplicate = stable_identifier("math-edge", "duplicate")
    with pytest.raises(ValidationError, match="edge identifiers must be unique"):
        MathematicalGraphV1(
            graph_id=stable_identifier("math-graph", "duplicates"),
            revision=1,
            nodes=(left, right),
            edges=(
                MathematicalEdgeV1(
                    edge_id=duplicate,
                    source=left.node_id,
                    target=right.node_id,
                    kind=MathematicalEdgeKindV1.EQUIVALENT_TO,
                ),
                MathematicalEdgeV1(
                    edge_id=duplicate,
                    source=right.node_id,
                    target=left.node_id,
                    kind=MathematicalEdgeKindV1.MOTIVATES,
                ),
            ),
        )
