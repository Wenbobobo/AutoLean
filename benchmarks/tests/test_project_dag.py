from __future__ import annotations

import pytest

from benchmarks.project_dag import (
    ProjectDagError,
    ProjectDagV1,
    ProjectNodeV1,
    load_default_project_dag,
)


def test_twenty_node_fixture_has_a_deterministic_dependency_frontier() -> None:
    graph = load_default_project_dag()
    assert len(graph.nodes) == 20
    assert [node.node_id for node in graph.ready_frontier()] == ["base.nat"]
    frontier = graph.ready_frontier(frozenset({"base.nat"}))
    assert [node.node_id for node in frontier] == ["base.add", "base.mul", "base.order"]


def test_api_change_propagates_only_through_reverse_dependencies() -> None:
    graph = load_default_project_dag()
    affected = {node.node_id for node in graph.affected_by(frozenset({"algebra.semiring"}))}
    assert "algebra.semiring" in affected
    assert "target.capstone" in affected
    assert "base.order" not in affected
    assert "algebra.monotone" not in affected


def test_project_dag_rejects_cycles_and_unknown_completed_nodes() -> None:
    with pytest.raises(ProjectDagError, match="acyclic"):
        ProjectDagV1(
            name="cycle",
            nodes=(
                ProjectNodeV1("a", "A.lean", ("b",)),
                ProjectNodeV1("b", "B.lean", ("a",)),
            ),
        )

    graph = load_default_project_dag()
    with pytest.raises(ProjectDagError, match="unknown"):
        graph.ready_frontier(frozenset({"not-a-node"}))
