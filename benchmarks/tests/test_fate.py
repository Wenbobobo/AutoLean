from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks.fate import benchmark_splits, load_fate_json, split_manifest, stable_sample


def test_splits_have_expected_sizes_and_comparison_is_not_golden() -> None:
    splits = benchmark_splits()
    assert sum(map(len, splits["compile-canary-12"].values())) == 12
    assert sum(map(len, splits["agent-smoke-8"].values())) == 8
    assert sum(map(len, splits["regression-48"].values())) == 48
    assert sum(map(len, splits["model-compare-90"].values())) == 90
    for tier in ("M", "H", "X"):
        assert set(splits["regression-48"][tier]).isdisjoint(splits["model-compare-90"][tier])


def test_stable_sample_is_deterministic() -> None:
    assert stable_sample("M", 10) == stable_sample("M", 10)
    assert stable_sample("M", 10) != tuple(range(1, 11))


def test_manifest_never_claims_to_contain_solutions() -> None:
    manifest = split_manifest()
    assert manifest["contains_solutions"] is False
    assert manifest["report_tiers_separately"] is True


def test_checked_in_split_manifest_matches_the_stable_selection() -> None:
    path = Path(__file__).parents[1] / "fate-splits.v1.json"
    checked_in = json.loads(path.read_text(encoding="utf-8"))

    assert checked_in == json.loads(json.dumps(split_manifest()))


def test_loader_rejects_statement_without_exactly_one_hole(tmp_path: Path) -> None:
    path = tmp_path / "FATE-M.json"
    path.write_text(
        json.dumps(
            [
                {
                    "id": 1,
                    "source": "FATE-M",
                    "version": "v4.28.0",
                    "informal_statement": "A theorem.",
                    "formal_statement": "theorem changed : True := by trivial",
                }
            ]
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="exactly one proof hole"):
        load_fate_json(path, "M")


def test_project_fixture_is_acyclic_and_has_twenty_nodes() -> None:
    path = Path(__file__).parents[1] / "project_dag" / "graph.json"
    nodes = json.loads(path.read_text(encoding="utf-8"))["nodes"]
    known: set[str] = set()
    for node in nodes:
        assert set(node["depends_on"]) <= known
        known.add(node["id"])
    assert len(known) == 20
