from __future__ import annotations

import hashlib

import pytest

from benchmarks.real_lean_project_dag import load_default_real_lean_project_dag
from benchmarks.real_lean_project_dag_rebuild import (
    RealLeanRebuildPlanError,
    plan_real_lean_rebuild,
)


def _baseline_hashes() -> dict[str, str]:
    fixture = load_default_real_lean_project_dag()
    return {module.module: module.source_sha256 for module in fixture.modules}


def _changed_hash(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def test_leaf_source_change_rebuilds_only_its_module_and_reuses_all_other_nodes() -> None:
    fixture = load_default_real_lean_project_dag()
    hashes = _baseline_hashes()
    leaf = "AutoLean.ProjectDagPreflight.Capstone"
    hashes[leaf] = _changed_hash("capstone leaf change")

    bundle = plan_real_lean_rebuild(
        fixture,
        hashes,
        changed_declaration_ids=("capstone.capstone",),
    )

    assert bundle.changed_modules == (leaf,)
    assert bundle.module_rebuild_plan == (leaf,)
    assert bundle.module_reuse_plan == tuple(
        module.module for module in fixture.module_topological_order() if module.module != leaf
    )
    assert {
        action.node_id for action in bundle.declaration_actions if action.action == "rebuild"
    } == {item.node_id for item in fixture.declarations if item.module == leaf}
    assert bundle.changed_declaration_ids == ("capstone.capstone",)
    assert bundle.declaration_invalidation_plan == ("capstone.capstone",)
    assert len(
        {action.node_id for action in bundle.declaration_actions if action.action == "rebuild"}
    ) > len(bundle.declaration_invalidation_plan)
    reasons = {action.module: action.reason for action in bundle.module_actions}
    assert reasons[leaf] == "changed_source"
    assert all(
        reason == "unchanged_source_reuse" for module, reason in reasons.items() if module != leaf
    )


def test_shared_upstream_source_change_rebuilds_the_deterministic_reverse_import_closure() -> None:
    fixture = load_default_real_lean_project_dag()
    hashes = _baseline_hashes()
    root = "AutoLean.ProjectDagPreflight.Foundations"
    hashes[root] = _changed_hash("shared foundations change")

    bundle = plan_real_lean_rebuild(
        fixture,
        hashes,
        changed_declaration_ids=("foundations.next-is-three",),
    )

    expected_modules = tuple(module.module for module in fixture.module_topological_order())
    assert bundle.changed_modules == (root,)
    assert bundle.module_rebuild_plan == expected_modules
    assert bundle.module_reuse_plan == ()
    reasons = {action.module: action.reason for action in bundle.module_actions}
    assert reasons[root] == "changed_source"
    assert all(
        reason == "reverse_import_closure" for module, reason in reasons.items() if module != root
    )
    assert bundle.declaration_invalidation_plan == ("foundations.next-is-three",)
    assert all(action.action == "rebuild" for action in bundle.declaration_actions)


def test_unchanged_snapshot_is_an_explicit_all_reuse_bundle_refused_without_a_lease() -> None:
    fixture = load_default_real_lean_project_dag()

    bundle = plan_real_lean_rebuild(
        fixture,
        _baseline_hashes(),
        changed_declaration_ids=(),
    )

    assert bundle.changed_modules == ()
    assert bundle.module_rebuild_plan == ()
    assert bundle.declaration_invalidation_plan == ()
    assert all(action.action == "reuse" for action in bundle.module_actions)
    assert all(action.action == "reuse" for action in bundle.declaration_actions)
    assert bundle.execution_status == "refused_pending_control_plane_lease"
    assert bundle.to_dict()["execution_precondition"] == (
        "control_plane_lease_and_fencing_token_required"
    )


def test_bundle_order_and_content_address_do_not_depend_on_snapshot_mapping_order() -> None:
    fixture = load_default_real_lean_project_dag()
    forward = _baseline_hashes()
    forward["AutoLean.ProjectDagPreflight.Arithmetic"] = _changed_hash("arithmetic change")
    reversed_mapping = dict(reversed(tuple(forward.items())))

    forward_bundle = plan_real_lean_rebuild(
        fixture,
        forward,
        changed_declaration_ids=("arithmetic.score", "arithmetic.sum-is-seven"),
    )
    reversed_bundle = plan_real_lean_rebuild(
        fixture,
        reversed_mapping,
        changed_declaration_ids=("arithmetic.sum-is-seven", "arithmetic.score"),
    )

    assert forward_bundle.module_rebuild_plan == (
        "AutoLean.ProjectDagPreflight.Arithmetic",
        "AutoLean.ProjectDagPreflight.Relations",
        "AutoLean.ProjectDagPreflight.Capstone",
    )
    assert forward_bundle.canonical_bytes() == reversed_bundle.canonical_bytes()
    assert forward_bundle.content_sha256 == reversed_bundle.content_sha256


def test_rebuild_planning_rejects_incomplete_unknown_and_invalid_source_hashes() -> None:
    fixture = load_default_real_lean_project_dag()
    missing = _baseline_hashes()
    missing.pop("AutoLean.ProjectDagPreflight.Capstone")

    with pytest.raises(RealLeanRebuildPlanError, match="exactly every fixture module"):
        plan_real_lean_rebuild(fixture, missing, changed_declaration_ids=())

    unknown = _baseline_hashes()
    unknown["AutoLean.ProjectDagPreflight.Unknown"] = _changed_hash("unknown")
    with pytest.raises(RealLeanRebuildPlanError, match="exactly every fixture module"):
        plan_real_lean_rebuild(fixture, unknown, changed_declaration_ids=())

    invalid = _baseline_hashes()
    invalid["AutoLean.ProjectDagPreflight.Arithmetic"] = "not-a-sha256"
    with pytest.raises(RealLeanRebuildPlanError, match="source snapshot hash"):
        plan_real_lean_rebuild(fixture, invalid, changed_declaration_ids=())


def test_rebuild_planning_validates_explicit_changed_declaration_ids() -> None:
    fixture = load_default_real_lean_project_dag()
    hashes = _baseline_hashes()
    hashes["AutoLean.ProjectDagPreflight.Arithmetic"] = _changed_hash("arithmetic API")

    with pytest.raises(RealLeanRebuildPlanError, match="changed declaration IDs"):
        plan_real_lean_rebuild(
            fixture,
            hashes,
            changed_declaration_ids=("arithmetic.score", "arithmetic.score"),
        )

    with pytest.raises(RealLeanRebuildPlanError, match="changed declaration IDs"):
        plan_real_lean_rebuild(
            fixture,
            hashes,
            changed_declaration_ids=("arithmetic.unknown",),
        )

    with pytest.raises(RealLeanRebuildPlanError, match="changed source module"):
        plan_real_lean_rebuild(
            fixture,
            hashes,
            changed_declaration_ids=("foundations.seed",),
        )
