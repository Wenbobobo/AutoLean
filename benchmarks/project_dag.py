"""Deterministic project-level DAG fixture utilities.

FATE tests one frozen Lean file at a time.  This module models the distinct scheduling
problem: a multi-file library has a mathematical/formal dependency frontier that workers must
respect, and an API change must invalidate exactly its reverse dependency closure.
"""

from __future__ import annotations

import json
import re
from collections import deque
from dataclasses import dataclass
from pathlib import Path


class ProjectDagError(ValueError):
    """The fixture is malformed or a scheduling request is invalid."""


_NODE_ID = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")
_FILE_PATH = re.compile(r"^[A-Za-z0-9_.-]+\.lean$")


@dataclass(frozen=True, slots=True)
class ProjectNodeV1:
    node_id: str
    source_file: str
    depends_on: tuple[str, ...]

    def __post_init__(self) -> None:
        if not _NODE_ID.fullmatch(self.node_id):
            raise ProjectDagError("project DAG node ID is invalid")
        if not _FILE_PATH.fullmatch(self.source_file):
            raise ProjectDagError("project DAG source file is invalid")
        if self.node_id in self.depends_on:
            raise ProjectDagError("project DAG nodes may not depend on themselves")
        if len(set(self.depends_on)) != len(self.depends_on):
            raise ProjectDagError("project DAG node dependencies must be unique")


@dataclass(frozen=True, slots=True)
class ProjectDagV1:
    name: str
    nodes: tuple[ProjectNodeV1, ...]

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ProjectDagError("project DAG name must not be empty")
        identifiers = tuple(node.node_id for node in self.nodes)
        if len(set(identifiers)) != len(identifiers):
            raise ProjectDagError("project DAG node IDs must be unique")
        known = set(identifiers)
        unknown = {
            dependency
            for node in self.nodes
            for dependency in node.depends_on
            if dependency not in known
        }
        if unknown:
            raise ProjectDagError("project DAG references an unknown dependency")
        self.topological_order()

    @property
    def by_id(self) -> dict[str, ProjectNodeV1]:
        return {node.node_id: node for node in self.nodes}

    def topological_order(self) -> tuple[str, ...]:
        """Return one stable topological order or reject cyclic work scheduling."""

        nodes = self.by_id
        reverse: dict[str, list[str]] = {node_id: [] for node_id in nodes}
        indegree = {node_id: len(node.depends_on) for node_id, node in nodes.items()}
        for node in nodes.values():
            for dependency in node.depends_on:
                reverse[dependency].append(node.node_id)
        ready = deque(sorted(node_id for node_id, degree in indegree.items() if degree == 0))
        ordered: list[str] = []
        while ready:
            node_id = ready.popleft()
            ordered.append(node_id)
            for dependent in sorted(reverse[node_id]):
                indegree[dependent] -= 1
                if indegree[dependent] == 0:
                    ready.append(dependent)
        if len(ordered) != len(nodes):
            raise ProjectDagError("project DAG must be acyclic")
        return tuple(ordered)

    def ready_frontier(self, completed: frozenset[str] = frozenset()) -> tuple[ProjectNodeV1, ...]:
        """Return currently executable nodes without treating scheduler state as mathematics."""

        unknown = completed - set(self.by_id)
        if unknown:
            raise ProjectDagError("completed set contains unknown project DAG nodes")
        return tuple(
            self.by_id[node_id]
            for node_id in self.topological_order()
            if node_id not in completed and set(self.by_id[node_id].depends_on).issubset(completed)
        )

    def affected_by(self, changed: frozenset[str]) -> tuple[ProjectNodeV1, ...]:
        """Return the changed API declarations plus every transitive dependent deterministically."""

        unknown = changed - set(self.by_id)
        if unknown:
            raise ProjectDagError("changed set contains unknown project DAG nodes")
        reverse: dict[str, set[str]] = {node.node_id: set() for node in self.nodes}
        for node in self.nodes:
            for dependency in node.depends_on:
                reverse[dependency].add(node.node_id)
        affected = set(changed)
        queue = deque(sorted(changed))
        while queue:
            current = queue.popleft()
            for dependent in sorted(reverse[current]):
                if dependent not in affected:
                    affected.add(dependent)
                    queue.append(dependent)
        return tuple(
            self.by_id[node_id] for node_id in self.topological_order() if node_id in affected
        )


def load_project_dag(path: str | Path) -> ProjectDagV1:
    """Load and validate a deliberately small JSON fixture without accepting extra fields."""

    source = Path(path)
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ProjectDagError("project DAG fixture could not be parsed") from error
    if not isinstance(raw, dict) or set(raw) != {"schema_version", "name", "nodes"}:
        raise ProjectDagError("project DAG root has unexpected fields")
    if raw["schema_version"] != "autolean.project-dag.v1":
        raise ProjectDagError("project DAG schema version is not supported")
    if not isinstance(raw["name"], str) or not isinstance(raw["nodes"], list):
        raise ProjectDagError("project DAG root fields have invalid types")
    nodes: list[ProjectNodeV1] = []
    for item in raw["nodes"]:
        if not isinstance(item, dict) or set(item) != {"id", "file", "depends_on"}:
            raise ProjectDagError("project DAG node has unexpected fields")
        node_id = item["id"]
        source_file = item["file"]
        dependencies = item["depends_on"]
        if (
            not isinstance(node_id, str)
            or not isinstance(source_file, str)
            or not isinstance(dependencies, list)
            or not all(isinstance(value, str) for value in dependencies)
        ):
            raise ProjectDagError("project DAG node fields have invalid types")
        nodes.append(ProjectNodeV1(node_id, source_file, tuple(dependencies)))
    return ProjectDagV1(name=raw["name"], nodes=tuple(nodes))


def load_default_project_dag() -> ProjectDagV1:
    return load_project_dag(Path(__file__).with_name("project_dag") / "graph.json")
