from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from scripts.release_evidence import (
    INPUT_PATHS,
    SCHEMA_VERSION,
    _source_summary,
    build_inventory,
    inventory_bytes,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_release_inventory_is_deterministic_and_lock_bound() -> None:
    first = inventory_bytes(PROJECT_ROOT)
    second = inventory_bytes(PROJECT_ROOT)

    assert first == second
    inventory = json.loads(first)
    assert inventory["schema_version"] == SCHEMA_VERSION
    assert [record["path"] for record in inventory["inputs"]] == [
        path.as_posix() for path in INPUT_PATHS
    ]
    assert str(PROJECT_ROOT) not in first.decode("utf-8")
    assert "https://" not in first.decode("utf-8")


def test_release_inventory_covers_python_ui_and_fate_locks() -> None:
    inventory = cast(dict[str, Any], build_inventory(PROJECT_ROOT))

    python_packages = {package["name"] for package in inventory["python"]["packages"]}
    javascript_packages = {package["name"] for package in inventory["javascript"]["packages"]}
    fate_tiers = {tier["tier"] for tier in inventory["benchmark"]["tiers"]}

    assert "autolean-workspace" in python_packages
    assert "react" in javascript_packages
    assert fate_tiers == {"M", "H", "X"}
    assert inventory["benchmark"]["split_schema_version"] == "autolean.fate-splits.v1"
    assert inventory["benchmark"]["split_seed"] == "autolean-fate-split-v1"


def test_source_summary_does_not_export_raw_locators() -> None:
    assert _source_summary({"registry": "opaque-registry-value"}) == {"kind": "registry"}
