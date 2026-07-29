from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from autolean_contracts import (
    AttestationPurposeV1,
    HmacAttestationKeyV1,
    HmacAttestationVerifierV1,
)
from autolean_contracts.research_advisory import (
    ResearchAdvisoryEventKindV1,
    ResearchAdvisoryEventV1,
    ResearchAdvisoryProposalKindV1,
    ResearchAdvisoryProviderV1,
    ResearchAdvisorySourceRefV1,
)
from autolean_control_plane import (
    RESEARCH_ADVISORY_ENTITY_TYPE,
    ArtifactStore,
    ControlPlane,
    DashboardProjection,
    EventStore,
    LeaseStore,
    validate_research_advisory_event,
)
from autolean_control_plane.errors import InvalidTransition, ProjectionError

_KEY = HmacAttestationKeyV1(
    key_id="research-advisory-test-key",
    secret=b"research-advisory-test-secret-material-0123456789",
    allowed_purposes=frozenset({AttestationPurposeV1.BUILDER_FREEZE}),
)


def _plane(tmp_path: Path) -> ControlPlane:
    database = tmp_path / "control.db"
    return ControlPlane(
        events=EventStore(database),
        leases=LeaseStore(database),
        artifacts=ArtifactStore(tmp_path / "artifacts"),
        attestation_verifier=HmacAttestationVerifierV1({_KEY.key_id: _KEY}),
    )


def _advisory(
    *,
    proposal_kind: ResearchAdvisoryProposalKindV1 = ResearchAdvisoryProposalKindV1.LEMMA,
) -> ResearchAdvisoryEventV1:
    event_kind = (
        ResearchAdvisoryEventKindV1.OBSERVATION
        if proposal_kind
        in {
            ResearchAdvisoryProposalKindV1.COUNTEREXAMPLE,
            ResearchAdvisoryProposalKindV1.LITERATURE_LEAD,
        }
        else ResearchAdvisoryEventKindV1.HYPOTHESIS
    )
    return ResearchAdvisoryEventV1(
        proposal_id="a" * 64,
        event_kind=event_kind,
        proposal_kind=proposal_kind,
        request_id="request-fixture",
        context_pack_hash="b" * 64,
        output_sha256="a" * 64,
        response_cas_sha256="c" * 64,
        dependency_refs=("d" * 64,),
        source_refs=(
            ResearchAdvisorySourceRefV1(
                source_id="source-fixture",
                span_id="span-fixture",
                hash="e" * 64,
            ),
        ),
        provider=ResearchAdvisoryProviderV1(provider_id="fake", model_id="fake-model-v1"),
    )


def test_research_advisory_appends_once_replays_and_has_no_task_authority(tmp_path: Path) -> None:
    plane = _plane(tmp_path)
    advisory = _advisory()

    event = plane.record_research_advisory(advisory, idempotency_key="research-advisory")
    replayed = plane.record_research_advisory(advisory, idempotency_key="research-advisory")
    same_identity = plane.record_research_advisory(advisory, idempotency_key="new-delivery-key")

    assert event == replayed == same_identity
    assert event.entity_type == RESEARCH_ADVISORY_ENTITY_TYPE
    assert event.entity_id == advisory.proposal_id
    assert event.entity_sequence == 1
    assert event.event_type == "research_hypothesis"
    assert event.metadata == {}
    assert validate_research_advisory_event(event) == advisory
    assert plane.events.current_sequence("task", advisory.proposal_id) == 0
    assert set(event.payload) == set(advisory.model_dump(mode="json"))
    assert not {"bundle_id", "contract_id", "statement", "evidence", "promotion_state"} & set(
        event.payload
    )


def test_research_advisory_refuses_digest_rebinding(tmp_path: Path) -> None:
    plane = _plane(tmp_path)
    advisory = _advisory()
    plane.record_research_advisory(advisory, idempotency_key="first")

    with pytest.raises(InvalidTransition, match="already bound"):
        plane.record_research_advisory(
            advisory.model_copy(update={"context_pack_hash": "f" * 64}),
            idempotency_key="different-envelope",
        )


def test_research_advisory_revalidates_untrusted_in_memory_models_before_append(
    tmp_path: Path,
) -> None:
    plane = _plane(tmp_path)
    advisory = _advisory()
    bypassed = ResearchAdvisoryEventV1.model_construct(
        **{
            **advisory.model_dump(mode="python"),
            "event_kind": ResearchAdvisoryEventKindV1.OBSERVATION,
        }
    )

    with pytest.raises(InvalidTransition, match="violates the typed V1"):
        plane.record_research_advisory(bypassed, idempotency_key="bypassed-model")
    assert plane.events.read_all() == ()


def test_dashboard_projects_only_a_sanitized_advisory_timeline_entry(tmp_path: Path) -> None:
    plane = _plane(tmp_path)
    advisory = _advisory(proposal_kind=ResearchAdvisoryProposalKindV1.COUNTEREXAMPLE)
    event = plane.record_research_advisory(advisory, idempotency_key="counterexample")

    snapshot = DashboardProjection(plane.events.read_all()).snapshot()
    serialized = json.dumps(snapshot, sort_keys=True)

    assert snapshot["nodes"] == []
    assert snapshot["runs"] == []
    assert snapshot["artifacts"] == []
    assert snapshot["phase_feedback"] == []
    assert snapshot["events"] == [
        {
            "sequence": event.global_position,
            "event_type": "research_observation",
            "entity_id": advisory.proposal_id,
            "task_id": None,
            "occurred_at": event.recorded_at,
            "summary": "Research advisory observation: counterexample",
        }
    ]
    for private_value in (
        "PRIVATE-STATEMENT-SENTINEL",
        "PRIVATE-EVIDENCE-SENTINEL",
        "provider endpoint",
        "api_key=not-a-secret",
    ):
        assert private_value not in serialized
    assert "source_refs" not in serialized
    assert "dependency_refs" not in serialized


def test_dashboard_rejects_tainted_or_non_initial_research_advisory_events(tmp_path: Path) -> None:
    plane = _plane(tmp_path)
    event = plane.record_research_advisory(_advisory(), idempotency_key="first")
    tainted_payload = dict(event.payload)
    tainted_payload["statement"] = "PRIVATE-STATEMENT-SENTINEL"
    tainted = replace(event, payload=tainted_payload)

    with pytest.raises(ProjectionError, match="public schema"):
        DashboardProjection((tainted,)).snapshot()
    with pytest.raises(ProjectionError, match="append-only identity"):
        DashboardProjection((replace(event, entity_sequence=2),)).snapshot()
    with pytest.raises(ProjectionError, match="unknown event type"):
        DashboardProjection((replace(event, event_type="research_advisory.promoted"),)).snapshot()
