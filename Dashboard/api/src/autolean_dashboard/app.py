from __future__ import annotations

import asyncio
import hmac
import json
import os
from collections.abc import AsyncIterator
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

from .models import (
    ArtifactSummary,
    DashboardSnapshot,
    EventView,
    GraphNode,
    Overview,
    RunSummary,
    StatementRevision,
    WorkRecord,
    WorkRecordCategory,
)
from .reader import (
    EmptyProjectionReader,
    JsonProjectionReader,
    ProjectionReader,
    ProjectionUnavailable,
)


def _reader_from_environment() -> ProjectionReader:
    projection = os.environ.get("AUTOLEAN_DASHBOARD_PROJECTION")
    return JsonProjectionReader(Path(projection)) if projection else EmptyProjectionReader()


def _work_record(event: EventView) -> WorkRecord:
    category: WorkRecordCategory
    if event.event_type == "gap.reported":
        category = "gap"
    elif event.event_type == "contract_change.requested":
        category = "contract_change"
    elif event.event_type.startswith("verification."):
        category = "verification"
    elif event.event_type == "proof.submitted":
        category = "attempt"
    elif event.event_type.startswith("task."):
        category = "task"
    else:
        category = "other"
    return WorkRecord(
        sequence=event.sequence,
        category=category,
        event_type=event.event_type,
        entity_id=event.entity_id,
        task_id=event.task_id,
        occurred_at=event.occurred_at,
        summary=event.summary,
    )


def _event_cursor(value: str | None) -> int:
    if value is None:
        return 0
    try:
        return max(0, int(value))
    except ValueError:
        return 0


def create_app(reader: ProjectionReader | None = None) -> FastAPI:
    projection_reader = reader or _reader_from_environment()
    remote_mode = os.environ.get("AUTOLEAN_DASHBOARD_REMOTE") == "1"
    configured_token = os.environ.get("AUTOLEAN_DASHBOARD_TOKEN")
    if remote_mode and (
        configured_token is None
        or len(configured_token) < 32
        or configured_token.strip() != configured_token
        or any(character.isspace() for character in configured_token)
    ):
        raise RuntimeError(
            "remote dashboard mode requires a trimmed AUTOLEAN_DASHBOARD_TOKEN "
            "of at least 32 characters"
        )

    app = FastAPI(
        title="AutoLean Dashboard API",
        version="0.1.0",
        # The local API is useful to inspect during development. A remotely exposed
        # instance deliberately has no interactive schema endpoint to enumerate.
        docs_url=None if remote_mode else "/api/docs",
        openapi_url=None if remote_mode else "/api/openapi.json",
    )
    if not remote_mode:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
            allow_credentials=False,
            allow_methods=["GET"],
            allow_headers=["Authorization", "Last-Event-ID"],
        )

    async def authorize(authorization: str | None = Header(default=None)) -> None:
        if not remote_mode:
            return
        if configured_token is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="remote authentication is unavailable",
            )
        expected = f"Bearer {configured_token}"
        if authorization is None or not hmac.compare_digest(authorization, expected):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                headers={"WWW-Authenticate": "Bearer"},
            )

    def current_snapshot() -> DashboardSnapshot:
        try:
            return projection_reader.snapshot()
        except ProjectionUnavailable as error:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="projection unavailable",
            ) from error

    @app.middleware("http")
    async def enforce_read_only(request: Request, call_next):  # type: ignore[no-untyped-def]
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            response = JSONResponse(
                status_code=status.HTTP_405_METHOD_NOT_ALLOWED,
                content={"detail": "AutoLean Dashboard API is read-only"},
                headers={"Allow": "GET, HEAD, OPTIONS"},
            )
        else:
            response = await call_next(request)
        # The Dashboard is a metadata projection. Do not let a browser retain stale
        # task state or treat an API response as a document that can be embedded.
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Robots-Tag", "noindex, nofollow")
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(), geolocation=(), microphone=(), payment=(), usb=()",
        )
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        )
        return response

    @app.get("/api/health", dependencies=[Depends(authorize)])
    def health() -> dict[str, str]:
        return {"status": "ok", "mode": "read-only"}

    @app.get("/api/snapshot", response_model=DashboardSnapshot, dependencies=[Depends(authorize)])
    def snapshot() -> DashboardSnapshot:
        """Return one coherent, projection-only observation for the dashboard UI."""

        return current_snapshot()

    @app.get("/api/overview", response_model=Overview, dependencies=[Depends(authorize)])
    def overview() -> Overview:
        return current_snapshot().overview

    @app.get("/api/nodes", response_model=list[GraphNode], dependencies=[Depends(authorize)])
    def nodes(graph: str | None = Query(default=None)) -> list[GraphNode]:
        items = current_snapshot().nodes
        return [item for item in items if graph is None or item.graph == graph]

    @app.get(
        "/api/revisions",
        response_model=list[StatementRevision],
        dependencies=[Depends(authorize)],
    )
    def revisions() -> list[StatementRevision]:
        items = current_snapshot().nodes
        return [
            StatementRevision(
                id=item.id,
                source_node_id=item.source_node_id,
                task_id=item.task_id,
                label=item.label,
                graph=item.graph,
                revision=item.revision,
                status=item.status,
                kind=item.kind,
                updated_at=item.updated_at,
            )
            for item in items
            if item.kind != "mission"
        ]

    @app.get("/api/runs", response_model=list[RunSummary], dependencies=[Depends(authorize)])
    def runs(limit: int = Query(default=100, ge=1, le=1000)) -> list[RunSummary]:
        return list(current_snapshot().runs[-limit:])

    @app.get(
        "/api/artifacts",
        response_model=list[ArtifactSummary],
        dependencies=[Depends(authorize)],
    )
    def artifacts(limit: int = Query(default=100, ge=1, le=1000)) -> list[ArtifactSummary]:
        return list(current_snapshot().artifacts[-limit:])

    @app.get("/api/events", response_model=list[EventView], dependencies=[Depends(authorize)])
    def events(
        after: int = Query(default=0, ge=0), limit: int = Query(default=200, ge=1, le=1000)
    ) -> list[EventView]:
        return [item for item in current_snapshot().events if item.sequence > after][:limit]

    @app.get(
        "/api/work-records",
        response_model=list[WorkRecord],
        dependencies=[Depends(authorize)],
    )
    def work_records(
        after: int = Query(default=0, ge=0), limit: int = Query(default=200, ge=1, le=1000)
    ) -> list[WorkRecord]:
        return [_work_record(item) for item in current_snapshot().events if item.sequence > after][
            :limit
        ]

    async def event_stream(after: int, request: Request) -> AsyncIterator[str]:
        cursor = after
        while True:
            if await request.is_disconnected():
                return
            try:
                events = projection_reader.snapshot().events
            except ProjectionUnavailable:
                yield (
                    'event: projection-unavailable\ndata: {"detail":"projection unavailable"}\n\n'
                )
                await asyncio.sleep(2)
                continue
            batch = [event for event in events if event.sequence > cursor][:200]
            for event in batch:
                cursor = event.sequence
                payload = json.dumps(event.model_dump(mode="json"), separators=(",", ":"))
                yield f"id: {event.sequence}\nevent: autolean\ndata: {payload}\n\n"
            yield ": keepalive\n\n"
            await asyncio.sleep(2)

    @app.get("/api/stream", dependencies=[Depends(authorize)])
    def stream(
        request: Request,
        after: int = Query(default=0, ge=0),
        last_event_id: str | None = Header(default=None, alias="Last-Event-ID"),
    ) -> StreamingResponse:
        return StreamingResponse(
            event_stream(max(after, _event_cursor(last_event_id)), request),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-store"},
        )

    return app
