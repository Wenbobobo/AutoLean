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
        )


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
