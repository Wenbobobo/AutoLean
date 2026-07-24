from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from autolean_dashboard.app import create_app
from autolean_dashboard.models import (
    ArtifactSummary,
    DashboardSnapshot,
    EventView,
    GraphNode,
    Overview,
    PhaseFeedback,
    RunSummary,
)
from autolean_dashboard.reader import JsonProjectionReader
from fastapi.testclient import TestClient


class FixedReader:
    def snapshot(self) -> DashboardSnapshot:
        now = datetime.now(UTC)
        return DashboardSnapshot(
            overview=Overview(mission="Test mission"),
            nodes=(
                GraphNode(
                    id="dashboard-node|task-1|formal|node-1",
                    source_node_id="node-1",
                    task_id="task-1",
                    label='<img src=x onerror="alert(1)">',
                    graph="formal",
                    status="frozen",
                    revision=3,
                ),
            ),
            runs=(
                RunSummary(
                    id="attempt-1",
                    task_id="task-1",
                    provider="codex-cli",
                    model="gpt-5",
                    status="candidate",
                ),
            ),
            artifacts=(
                ArtifactSummary(
                    digest="a" * 64,
                    media_type="application/json",
                    size=12,
                    kind="verification",
                ),
            ),
            events=(
                EventView(
                    sequence=1,
                    event_type="gap.reported",
                    entity_id="node-1",
                    task_id="task-1",
                    occurred_at=now,
                    summary="Gap reported",
                ),
                EventView(
                    sequence=2,
                    event_type="contract_change.requested",
                    entity_id="node-1",
                    task_id="task-1",
                    occurred_at=now,
                    summary="Contract change requested",
                ),
                EventView(
                    sequence=3,
                    event_type="verification.accepted",
                    entity_id="node-1",
                    task_id="task-1",
                    occurred_at=now,
                    summary="Verification accepted",
                ),
            ),
            phase_feedback=(
                PhaseFeedback.model_validate(
                    {
                        "task_id": "task-1",
                        "builder_fidelity": {
                            "state": "frozen_attested_with_evidence",
                            "contract_id": "contract-1",
                            "revision": 3,
                            "contract_hash": "b" * 64,
                            "bundle_hash": "c" * 64,
                            "registration_event_sequence": 1,
                            "registration_event_id": "event-1",
                            "registered_at": now,
                            "evidence_digest": "d" * 64,
                        },
                        "prover_verification": {
                            "state": "verified_candidate_available",
                            "submitted_proof_ids": ["proof-1"],
                            "accepted_proof_ids": ["proof-1"],
                        },
                        "mathematical_dependency_node_count": 1,
                        "dependency_leverage_exact_node_limit": 512,
                        "dependency_leverage_mode": "exact_transitive",
                        "mathematical_dependency_leverage": [
                            {
                                "node_id": "dashboard-node|task-1|mathematical|root",
                                "source_node_id": "root",
                                "label": "Root",
                                "direct_dependents": 1,
                                "transitive_dependents": 2,
                            }
                        ],
                        "milestones": [
                            {
                                "phase": "builder_fidelity",
                                "state": "recorded",
                                "source_event_sequence": 1,
                                "source_event_id": "event-1",
                                "occurred_at": now,
                                "evidence_digest": "d" * 64,
                            },
                            {
                                "phase": "prover_candidate",
                                "state": "pending",
                                "source_event_sequence": 2,
                                "source_event_id": "event-2",
                                "occurred_at": now,
                                "evidence_digest": "e" * 64,
                                "proof_id": "proof-1",
                            },
                            {
                                "phase": "prover_verification",
                                "state": "accepted",
                                "source_event_sequence": 3,
                                "source_event_id": "event-3",
                                "occurred_at": now,
                                "evidence_digest": "f" * 64,
                                "proof_id": "proof-1",
                            },
                        ],
                        "replay": {
                            "first_relevant_event_sequence": 1,
                            "last_relevant_event_sequence": 3,
                            "last_relevant_event_id": "event-3",
                            "last_relevant_event_recorded_at": now,
                            "relevant_event_count": 3,
                            "relevant_event_sequences": [1, 2, 3],
                            "replay_head_event_sequence": 3,
                            "replay_head_event_id": "event-3",
                            "replay_head_recorded_at": now,
                            "events_observed_after_last_relevant": 0,
                            "last_relevant_event_is_replay_head": True,
                        },
                    }
                ),
            ),
        )


class ManyFeedbackReader:
    def snapshot(self) -> DashboardSnapshot:
        snapshot = FixedReader().snapshot()
        first = snapshot.phase_feedback[0]
        second = first.model_copy(update={"task_id": "task-2"})
        return snapshot.model_copy(update={"phase_feedback": (first, second)})


def test_api_is_read_only_and_exposes_projection_metadata() -> None:
    client = TestClient(create_app(FixedReader()))

    health = client.get("/api/health")
    assert health.json()["mode"] == "read-only"
    assert health.headers["cache-control"] == "no-store"
    assert health.headers["x-content-type-options"] == "nosniff"
    assert "frame-ancestors 'none'" in health.headers["content-security-policy"]
    assert client.post("/api/runs").status_code == 405
    assert client.delete("/api/runs").status_code == 405

    snapshot = client.get("/api/snapshot")
    assert snapshot.headers["content-type"].startswith("application/json")
    assert snapshot.headers["x-content-type-options"] == "nosniff"

    node = client.get("/api/nodes").json()[0]
    assert node["label"].startswith("<img")
    assert node["task_id"] == "task-1"
    revision = client.get("/api/revisions").json()[0]
    assert revision["revision"] == 3
    assert revision["source_node_id"] == "node-1"
    assert revision["task_id"] == "task-1"
    assert [item["category"] for item in client.get("/api/work-records").json()] == [
        "gap",
        "contract_change",
        "verification",
    ]
    assert {item["task_id"] for item in client.get("/api/work-records").json()} == {"task-1"}
    phase_feedback = client.get("/api/phase-feedback")
    assert phase_feedback.status_code == 200
    assert phase_feedback.json()[0]["prover_verification"]["state"] == (
        "verified_candidate_available"
    )
    assert phase_feedback.json()[0]["promotion_state"] == "not_a_promotion"
    assert phase_feedback.json()[0]["dependency_leverage_mode"] == "exact_transitive"
    assert phase_feedback.json()[0]["replay"]["last_relevant_event_is_replay_head"] is True
    assert client.post("/api/phase-feedback").status_code == 405


def test_phase_feedback_api_filters_by_task_and_has_a_bounded_limit() -> None:
    client = TestClient(create_app(ManyFeedbackReader()))

    assert [item["task_id"] for item in client.get("/api/phase-feedback?limit=1").json()] == [
        "task-1"
    ]
    assert client.get("/api/phase-feedback?task_id=task-2&limit=1").json()[0]["task_id"] == "task-2"
    assert client.get("/api/phase-feedback?task_id=unknown").json() == []
    assert client.get("/api/phase-feedback?limit=0").status_code == 422
    assert client.get("/api/phase-feedback?limit=101").status_code == 422


def test_phase_feedback_model_rejects_an_optimistic_summary() -> None:
    with pytest.raises(ValueError, match="conflicts with candidate evidence"):
        PhaseFeedback.model_validate(
            {
                "task_id": "task-1",
                "builder_fidelity": {
                    "state": "frozen_attested_without_public_evidence",
                    "contract_id": "contract-1",
                    "revision": 1,
                    "contract_hash": "a" * 64,
                    "bundle_hash": "b" * 64,
                    "registration_event_sequence": 1,
                    "registration_event_id": "event-1",
                    "registered_at": datetime.now(UTC),
                },
                "prover_verification": {
                    "state": "verified_candidate_available",
                    "submitted_proof_ids": ["proof-1", "proof-2"],
                    "pending_proof_ids": ["proof-2"],
                    "accepted_proof_ids": ["proof-1"],
                },
                "mathematical_dependency_node_count": 0,
                "dependency_leverage_exact_node_limit": 512,
                "dependency_leverage_mode": "exact_transitive",
                "milestones": [],
                "replay": {
                    "first_relevant_event_sequence": 1,
                    "last_relevant_event_sequence": 1,
                    "last_relevant_event_id": "event-1",
                    "last_relevant_event_recorded_at": datetime.now(UTC),
                    "relevant_event_count": 1,
                    "relevant_event_sequences": [1],
                    "replay_head_event_sequence": 1,
                    "replay_head_event_id": "event-1",
                    "replay_head_recorded_at": datetime.now(UTC),
                    "events_observed_after_last_relevant": 0,
                    "last_relevant_event_is_replay_head": True,
                },
            }
        )


def _phase_feedback_payload() -> dict[str, object]:
    return FixedReader().snapshot().phase_feedback[0].model_dump(mode="json")


def test_phase_feedback_model_rejects_terminal_before_candidate() -> None:
    payload = _phase_feedback_payload()
    milestones = payload["milestones"]
    assert isinstance(milestones, list)
    candidate = milestones[1]
    terminal = milestones[2]
    assert isinstance(candidate, dict) and isinstance(terminal, dict)
    candidate["source_event_sequence"] = 3
    candidate["source_event_id"] = "event-3"
    terminal["source_event_sequence"] = 2
    terminal["source_event_id"] = "event-2"
    payload["milestones"] = [milestones[0], terminal, candidate]

    with pytest.raises(ValueError, match="precedes its candidate"):
        PhaseFeedback.model_validate(payload)


@pytest.mark.parametrize(
    ("second_terminal_state", "message"),
    [
        ("accepted", "duplicate terminal"),
        ("rejected", "conflicting accepted and rejected"),
    ],
)
def test_phase_feedback_model_rejects_duplicate_or_conflicting_terminals(
    second_terminal_state: str,
    message: str,
) -> None:
    payload = _phase_feedback_payload()
    milestones = payload["milestones"]
    replay = payload["replay"]
    assert isinstance(milestones, list) and isinstance(replay, dict)
    terminal = milestones[-1]
    assert isinstance(terminal, dict)
    second_terminal = {
        **terminal,
        "state": second_terminal_state,
        "source_event_sequence": 4,
        "source_event_id": "event-4",
    }
    payload["milestones"] = [*milestones, second_terminal]
    replay.update(
        {
            "last_relevant_event_sequence": 4,
            "last_relevant_event_id": "event-4",
            "relevant_event_count": 4,
            "relevant_event_sequences": [1, 2, 3, 4],
            "replay_head_event_sequence": 4,
            "replay_head_event_id": "event-4",
            "events_observed_after_last_relevant": 0,
            "last_relevant_event_is_replay_head": True,
        }
    )

    with pytest.raises(ValueError, match=message):
        PhaseFeedback.model_validate(payload)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        ("builder_revision", "3"),
        ("registration_sequence", True),
        ("replay_count", 3.0),
    ],
)
def test_phase_feedback_model_requires_strict_integer_linkage(path: str, value: object) -> None:
    payload = _phase_feedback_payload()
    builder = payload["builder_fidelity"]
    replay = payload["replay"]
    assert isinstance(builder, dict) and isinstance(replay, dict)
    if path == "builder_revision":
        builder["revision"] = value
    elif path == "registration_sequence":
        builder["registration_event_sequence"] = value
    else:
        replay["relevant_event_count"] = value

    with pytest.raises(ValueError):
        PhaseFeedback.model_validate(payload)


def test_phase_feedback_model_rejects_unranked_leverage_before_ui_truncation() -> None:
    payload = _phase_feedback_payload()
    payload["mathematical_dependency_node_count"] = 2
    payload["mathematical_dependency_leverage"] = [
        {
            "node_id": "node-low",
            "source_node_id": "low",
            "label": "Low reach",
            "direct_dependents": 0,
            "transitive_dependents": 0,
        },
        {
            "node_id": "node-high",
            "source_node_id": "high",
            "label": "High reach",
            "direct_dependents": 1,
            "transitive_dependents": 2,
        },
    ]

    with pytest.raises(ValueError, match="ranked by structural reach"):
        PhaseFeedback.model_validate(payload)


def test_phase_feedback_model_accepts_direct_only_leverage_over_the_exact_limit() -> None:
    payload = _phase_feedback_payload()
    payload["mathematical_dependency_node_count"] = 513
    payload["dependency_leverage_mode"] = "direct_only_over_limit"
    payload["mathematical_dependency_leverage"] = [
        {
            "node_id": f"node-{index:03d}",
            "source_node_id": f"source-{index:03d}",
            "label": f"Node {index}",
            "direct_dependents": 0,
            "transitive_dependents": None,
        }
        for index in range(513)
    ]

    feedback = PhaseFeedback.model_validate(payload)

    assert feedback.dependency_leverage_mode == "direct_only_over_limit"
    assert all(
        item.transitive_dependents is None for item in feedback.mathematical_dependency_leverage
    )


def test_untrusted_projection_strings_are_json_metadata_not_browser_markup() -> None:
    client = TestClient(create_app(FixedReader()))

    response = client.get("/api/nodes")

    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["content-security-policy"].startswith("default-src 'none'")
    assert response.json()[0]["label"] == '<img src=x onerror="alert(1)">'


def test_cors_does_not_allow_arbitrary_origins() -> None:
    client = TestClient(create_app(FixedReader()))
    response = client.options(
        "/api/overview",
        headers={
            "Origin": "https://attacker.invalid",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.headers.get("access-control-allow-origin") is None


def test_event_cursor() -> None:
    client = TestClient(create_app(FixedReader()))
    assert len(client.get("/api/events?after=0").json()) == 3
    assert [event["sequence"] for event in client.get("/api/events?after=1").json()] == [2, 3]


def test_remote_mode_requires_strong_token_and_hides_schema(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AUTOLEAN_DASHBOARD_REMOTE", "1")
    monkeypatch.setenv("AUTOLEAN_DASHBOARD_TOKEN", "x" * 31)
    try:
        create_app(FixedReader())
    except RuntimeError as error:
        assert "AUTOLEAN_DASHBOARD_TOKEN" in str(error)
    else:
        raise AssertionError("remote mode accepted a short token")

    token = "t" * 32
    monkeypatch.setenv("AUTOLEAN_DASHBOARD_TOKEN", token)
    client = TestClient(create_app(FixedReader()))
    assert client.get("/api/health").status_code == 401
    authenticated = client.get("/api/health", headers={"Authorization": f"Bearer {token}"})
    assert authenticated.status_code == 200
    assert client.get("/api/docs").status_code == 404


def test_invalid_projection_becomes_generic_service_unavailable(tmp_path: Path) -> None:
    projection = tmp_path / "projection.json"
    projection.write_text("{not json", encoding="utf-8")
    client = TestClient(create_app(JsonProjectionReader(projection)))

    response = client.get("/api/snapshot")
    assert response.status_code == 503
    assert response.json() == {"detail": "projection unavailable"}
    assert str(projection) not in response.text
