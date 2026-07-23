"""Read-only Dashboard projection rebuilt solely from append-only control-plane events."""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from .events import JsonObject, StoredEvent, canonical_json


class DashboardProjection:
    """A deliberately lossy projection: it never exposes proof/source artifact contents."""

    def __init__(self, events: Iterable[StoredEvent]) -> None:
        self._events = tuple(sorted(events, key=lambda item: item.global_position))

    def snapshot(self) -> JsonObject:
        nodes: dict[str, JsonObject] = {}
        runs: dict[str, JsonObject] = {}
        artifacts: dict[str, JsonObject] = {}
        event_views: list[JsonObject] = []
        active_bundles: set[str] = set()
        blocked_bundles: set[str] = set()

        for event in self._events:
            payload = event.payload
            bundle_id = self._optional_text(payload, "bundle_id")
            if event.event_type == "task.registered":
                for raw_node in self._optional_list(payload, "graph_nodes"):
                    if isinstance(raw_node, dict):
                        node = cast(JsonObject, raw_node).copy()
                        identifier = self._optional_text(node, "id")
                        if identifier:
                            nodes[identifier] = node
                self._capture_artifact(payload, "bundle_artifact", artifacts)
            elif event.event_type == "task.claimed" and bundle_id:
                active_bundles.add(bundle_id)
                self._set_task_status(nodes, bundle_id, "running")
            elif event.event_type == "proof.submitted":
                proof_id = self._optional_text(payload, "proof_id") or event.entity_id
                runs[proof_id] = self._run_from_submission(payload, proof_id)
                self._capture_artifact(payload, "proof_artifact", artifacts)
            elif event.event_type == "gap.reported" and bundle_id:
                blocked_bundles.add(bundle_id)
                active_bundles.discard(bundle_id)
                self._set_task_status(nodes, bundle_id, "blocked")
                self._capture_artifact(payload, "gap_artifact", artifacts)
            elif event.event_type == "contract_change.requested" and bundle_id:
                blocked_bundles.add(bundle_id)
                active_bundles.discard(bundle_id)
                self._set_task_status(nodes, bundle_id, "blocked")
                self._capture_artifact(payload, "request_artifact", artifacts)
            elif event.event_type.startswith("verification."):
                verified_proof_id = self._optional_text(payload, "proof_id")
                accepted = bool(payload.get("accepted"))
                if verified_proof_id and verified_proof_id in runs:
                    runs[verified_proof_id]["status"] = "succeeded" if accepted else "failed"
                    runs[verified_proof_id]["verification"] = "accepted" if accepted else "rejected"
                if bundle_id:
                    active_bundles.discard(bundle_id)
                    self._set_task_status(nodes, bundle_id, "verified" if accepted else "blocked")
                    if not accepted:
                        blocked_bundles.add(bundle_id)
                self._capture_artifact(payload, "verification_artifact", artifacts)

            event_views.append(self._event_view(event))

        return self._json_object(
            {
                "overview": {
                    "generated_at": datetime.now(UTC).isoformat(),
                    "mission": "Open problem portfolio",
                    "metrics": [
                        {"label": "events", "value": len(self._events)},
                        {"label": "artifacts", "value": len(artifacts)},
                    ],
                    "active_runs": len(active_bundles),
                    "blocked_nodes": len(blocked_bundles),
                },
                "nodes": [self._public_node(node) for node in nodes.values()],
                "runs": list(runs.values()),
                "artifacts": list(artifacts.values()),
                "events": event_views,
            }
        )

    @staticmethod
    def _set_task_status(nodes: dict[str, JsonObject], bundle_id: str, status: str) -> None:
        # Bundle IDs are not graph IDs. The event only affects nodes tied to that task's revision;
        # node state stays conservative when the graph had no nodes.
        for node in nodes.values():
            if node.get("bundle_id") == bundle_id:
                node["status"] = status

    @staticmethod
    def _public_node(node: JsonObject) -> JsonObject:
        return DashboardProjection._json_object(
            {key: value for key, value in node.items() if key != "bundle_id"}
        )

    @staticmethod
    def _run_from_submission(payload: JsonObject, proof_id: str) -> JsonObject:
        return DashboardProjection._json_object(
            {
                "id": proof_id,
                "task_id": DashboardProjection._optional_text(payload, "bundle_id") or "unknown",
                "provider": DashboardProjection._optional_text(payload, "provider")
                or "unattributed",
                "model": DashboardProjection._optional_text(payload, "model") or "unattributed",
                "status": "candidate",
                "verification": "pending",
                "duration_ms": DashboardProjection._optional_int(payload, "duration_ms"),
                "input_tokens": DashboardProjection._optional_int(payload, "input_tokens") or 0,
                "output_tokens": DashboardProjection._optional_int(payload, "output_tokens") or 0,
                "cost_usd": DashboardProjection._optional_float(payload, "cost_usd") or 0.0,
            }
        )

    @staticmethod
    def _capture_artifact(payload: JsonObject, key: str, target: dict[str, JsonObject]) -> None:
        value = payload.get(key)
        if not isinstance(value, dict):
            return
        artifact = value
        digest = DashboardProjection._optional_text(artifact, "digest")
        if not digest:
            return
        target[digest] = DashboardProjection._json_object(
            {
                "digest": digest,
                "media_type": DashboardProjection._optional_text(artifact, "media_type")
                or "application/octet-stream",
                "size": artifact.get("size", 0),
                "kind": DashboardProjection._optional_text(artifact, "kind") or "artifact",
            }
        )

    @staticmethod
    def _event_view(event: StoredEvent) -> JsonObject:
        bundle_id = DashboardProjection._optional_text(event.payload, "bundle_id")
        return DashboardProjection._json_object(
            {
                "sequence": event.global_position,
                "event_type": event.event_type,
                "entity_id": bundle_id or event.entity_id,
                "occurred_at": event.recorded_at,
                "summary": event.event_type.replace(".", " "),
            }
        )

    @staticmethod
    def _optional_text(payload: JsonObject, key: str) -> str | None:
        value = payload.get(key)
        return value if isinstance(value, str) and value else None

    @staticmethod
    def _optional_list(payload: JsonObject, key: str) -> list[object]:
        value = payload.get(key)
        items: list[object] = []
        if isinstance(value, list):
            items.extend(value)
        return items

    @staticmethod
    def _optional_int(payload: JsonObject, key: str) -> int | None:
        value = payload.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
        return None

    @staticmethod
    def _optional_float(payload: JsonObject, key: str) -> float | None:
        value = payload.get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
            return None
        return float(value)

    @staticmethod
    def _json_object(value: object) -> JsonObject:
        loaded = json.loads(canonical_json(value))
        if not isinstance(loaded, dict):
            raise TypeError("projection value must be a JSON object")
        return cast(JsonObject, loaded)


def export_dashboard_projection(path: str | Path, events: Iterable[StoredEvent]) -> Path:
    """Atomically export a JSON snapshot that a separate read-only Dashboard process can read."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_json(DashboardProjection(events).snapshot()).encode("utf-8")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=destination.parent, prefix=".projection-", delete=False
        ) as handle:
            temporary = Path(handle.name)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return destination
