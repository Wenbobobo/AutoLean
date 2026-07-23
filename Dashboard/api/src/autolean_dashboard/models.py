from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Metric(StrictModel):
    label: str
    value: int | float | str
    trend: float | None = None


class Overview(StrictModel):
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    mission: str = "Open problem portfolio"
    metrics: tuple[Metric, ...] = ()
    active_runs: int = 0
    blocked_nodes: int = 0


class GraphNode(StrictModel):
    id: str = Field(min_length=1, max_length=256)
    label: str = Field(min_length=1, max_length=512)
    graph: Literal["mathematical", "formal", "execution"]
    status: str = Field(min_length=1, max_length=64)
    revision: int = Field(default=1, ge=1)
    kind: str = Field(default="statement", min_length=1, max_length=64)
    dependencies: tuple[str, ...] = ()
    updated_at: datetime | None = None


class RunSummary(StrictModel):
    id: str = Field(min_length=1, max_length=256)
    task_id: str = Field(min_length=1, max_length=256)
    provider: str = Field(min_length=1, max_length=128)
    model: str = Field(min_length=1, max_length=256)
    status: str = Field(min_length=1, max_length=64)
    started_at: datetime | None = None
    duration_ms: int | None = Field(default=None, ge=0)
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    cost_usd: float = Field(default=0.0, ge=0.0)
    verification: str = Field(default="pending", min_length=1, max_length=64)


class ArtifactSummary(StrictModel):
    digest: str = Field(min_length=1, max_length=256)
    media_type: str = Field(min_length=1, max_length=128)
    size: int = Field(ge=0)
    kind: str = Field(min_length=1, max_length=64)
    created_at: datetime | None = None


class EventView(StrictModel):
    sequence: int = Field(ge=1)
    event_type: str = Field(min_length=1, max_length=128)
    entity_id: str = Field(min_length=1, max_length=256)
    occurred_at: datetime
    summary: str = Field(min_length=1, max_length=512)


class StatementRevision(StrictModel):
    """A public, revision-oriented view derived from graph nodes only."""

    id: str = Field(min_length=1, max_length=256)
    label: str = Field(min_length=1, max_length=512)
    graph: Literal["mathematical", "formal", "execution"]
    revision: int = Field(ge=1)
    status: str = Field(min_length=1, max_length=64)
    kind: str = Field(min_length=1, max_length=64)
    updated_at: datetime | None = None


WorkRecordCategory = Literal[
    "task",
    "attempt",
    "gap",
    "contract_change",
    "verification",
    "other",
]


class WorkRecord(StrictModel):
    """A safe event classification; no source, prompt, or artifact body is included."""

    sequence: int = Field(ge=1)
    category: WorkRecordCategory
    event_type: str = Field(min_length=1, max_length=128)
    entity_id: str = Field(min_length=1, max_length=256)
    occurred_at: datetime
    summary: str = Field(min_length=1, max_length=512)


class DashboardSnapshot(StrictModel):
    overview: Overview = Field(default_factory=Overview)
    nodes: tuple[GraphNode, ...] = ()
    runs: tuple[RunSummary, ...] = ()
    artifacts: tuple[ArtifactSummary, ...] = ()
    events: tuple[EventView, ...] = ()
