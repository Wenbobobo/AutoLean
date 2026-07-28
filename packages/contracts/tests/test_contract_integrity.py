from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from autolean_contracts import (
    MATHLIB_AXIOMS_V1,
    AxiomProfileV1,
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
    OciVerifierExecutionPolicyV2,
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


def _contract_with_axiom_policy(
    profile: AxiomProfileV1,
    allowlist: tuple[str, ...],
) -> StatementContractV1:
    payload = _draft_contract().model_dump(mode="python", round_trip=True)
    formal = payload["formal"]
    policy = payload["policy"]
    assert isinstance(formal, dict)
    assert isinstance(policy, dict)
    formal["axioms_allowlist"] = allowlist
    policy["axiom_profile"] = profile
    return StatementContractV1.model_validate(payload)


def test_oci_v1_policy_round_trip_hash_and_argv_remain_frozen() -> None:
    expected_json = (
        '{"schema_version":"1.0","worker_image_digest":"sha256:'
        + ("c" * 64)
        + '","wrapper_protocol":"autolean.oci-lean-wrapper.v1",'
        '"wrapper_executable":"/opt/autolean/bin/autolean-lean-wrapper",'
        '"candidate_path":"/input/Candidate.lean",'
        '"type_format":"autolean.lean-pp-expr.v1","network_mode":"none",'
        '"read_only_root":true,"drop_all_capabilities":true,"no_new_privileges":true,'
        '"source_mount_path":"/source","dependencies_mount_path":"/deps",'
        '"source_mount_read_only":true,"dependencies_mount_read_only":true,'
        '"candidate_mount_read_only":true,"workdir":"/work"}'
    )
    policy = OciVerifierExecutionPolicyV1.model_validate_json(expected_json)

    assert policy.model_dump_json() == expected_json
    assert policy.command_policy_hash().value == (
        "409323e190d9cbd96e014de91bfa336ff5765cb3e1b5fafab238f8e43625bd2c"
    )
    assert policy.wrapper_argv("AutoLean.Test.fixture") == (
        "/opt/autolean/bin/autolean-lean-wrapper",
        "--protocol",
        "autolean.oci-lean-wrapper.v1",
        "--candidate",
        "/input/Candidate.lean",
        "--declaration",
        "AutoLean.Test.fixture",
        "--type-format",
        "autolean.lean-pp-expr.v1",
    )

    environment_payload = _draft_contract().formal.environment.model_dump(mode="json")
    environment_payload["verifier_execution_policy"] = policy.model_dump(mode="json")
    restored = LeanEnvironmentV1.model_validate(environment_payload)
    assert isinstance(restored.verifier_execution_policy, OciVerifierExecutionPolicyV1)
    assert restored.verifier_execution_policy.model_dump_json() == expected_json


def test_oci_v2_policy_has_distinct_hash_argv_and_requires_explicit_revision() -> None:
    draft = _draft_contract()
    old_hash = draft.semantic_hash()
    old_policy = draft.formal.environment.verifier_execution_policy
    assert isinstance(old_policy, OciVerifierExecutionPolicyV1)

    policy = OciVerifierExecutionPolicyV2(worker_image_digest="sha256:" + "c" * 64)
    assert policy.command_policy_hash().value == (
        "886f0e1a56f35e30b04da9655984d7c2857bac4a625558a5eb5312d57e9a9bf7"
    )
    assert policy.compile_wrapper_argv() == (
        "/opt/autolean/bin/autolean-lean-wrapper",
        "--protocol",
        "autolean.oci-lean-wrapper.v2",
        "--phase",
        "compile",
        "--candidate",
        "/input/Candidate.lean",
        "--output",
        "/output/Candidate.olean",
    )
    assert policy.wrapper_argv("AutoLean.Test.fixture") == (
        "/opt/autolean/bin/autolean-lean-wrapper",
        "--protocol",
        "autolean.oci-lean-wrapper.v2",
        "--phase",
        "query",
        "--compiled",
        "/compiled/Candidate.olean",
        "--declaration",
        "AutoLean.Test.fixture",
        "--type-format",
        "autolean.lean-pp-expr.v1",
    )

    revised_environment = draft.formal.environment.model_copy(
        update={"verifier_execution_policy": policy}
    )
    revised_formal = draft.formal.model_copy(update={"environment": revised_environment})
    revised = draft.model_copy(update={"revision": 2, "formal": revised_formal})

    assert revised.revision == 2
    assert isinstance(
        revised.formal.environment.verifier_execution_policy,
        OciVerifierExecutionPolicyV2,
    )
    assert revised.semantic_hash() != old_hash
    assert draft.revision == 1
    assert draft.formal.environment.verifier_execution_policy is old_policy


def test_lean_environment_discriminates_policy_versions_without_coercion() -> None:
    environment_payload = _draft_contract().formal.environment.model_dump(mode="json")
    legacy_policy = environment_payload["verifier_execution_policy"]
    assert isinstance(legacy_policy, dict)
    legacy_policy["runtime_user_mode"] = "host-non-root"

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        LeanEnvironmentV1.model_validate(environment_payload)

    legacy_policy["schema_version"] = "2.0"
    with pytest.raises(ValidationError):
        LeanEnvironmentV1.model_validate(environment_payload)


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


@pytest.mark.parametrize(
    "allowlist",
    [
        (),
        ("Classical.choice",),
        MATHLIB_AXIOMS_V1,
    ],
)
def test_mathlib_axiom_profile_accepts_only_baseline_subsets(
    allowlist: tuple[str, ...],
) -> None:
    contract = _contract_with_axiom_policy(AxiomProfileV1.MATHLIB, allowlist)

    assert contract.formal.axioms_allowlist == allowlist


def test_mathlib_axiom_profile_rejects_nonbaseline_axioms() -> None:
    with pytest.raises(ValidationError, match="non-baseline axioms: unsafeAxiom"):
        _contract_with_axiom_policy(
            AxiomProfileV1.MATHLIB,
            ("Classical.choice", "unsafeAxiom"),
        )


def test_strict_axiom_profile_requires_an_empty_allowlist() -> None:
    with pytest.raises(ValidationError, match="strict axiom profile requires an empty allowlist"):
        _contract_with_axiom_policy(
            AxiomProfileV1.STRICT,
            ("Classical.choice",),
        )


def test_explicit_axiom_profile_accepts_custom_axioms() -> None:
    contract = _contract_with_axiom_policy(
        AxiomProfileV1.EXPLICIT_ALLOWLIST,
        ("AutoLean.CustomAxiom",),
    )
    assert contract.formal.axioms_allowlist == ("AutoLean.CustomAxiom",)


@pytest.mark.parametrize("profile", tuple(AxiomProfileV1))
def test_every_axiom_profile_rejects_sorry_ax(profile: AxiomProfileV1) -> None:
    with pytest.raises(ValidationError, match="sorryAx is prohibited"):
        _contract_with_axiom_policy(
            profile,
            ("sorryAx",),
        )
