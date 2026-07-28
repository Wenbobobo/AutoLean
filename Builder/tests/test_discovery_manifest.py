from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest
from autolean_builder.discovery_manifest import (
    DiscoveryManifestError,
    DiscoveryNodeKindV1,
    FrozenPrerequisiteDenominatorV1,
    load_discovery_lane_manifest,
)
from autolean_contracts import canonical_json_bytes

ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = ROOT / "Builder" / "pilots" / "discovery" / "phase-2-active-lanes.v1.json"


def _payload() -> dict[str, object]:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def _ifem_denominator_payload() -> dict[str, object]:
    payload = _payload()
    lanes = payload["lanes"]
    assert isinstance(lanes, list)
    lane = next(item for item in lanes if item["lane_id"] == "ifem-coercive-galerkin")
    denominator = lane["prerequisite_denominator"]
    assert isinstance(denominator, dict)
    return copy.deepcopy(denominator)


def _denominator_hash(payload: dict[str, object]) -> str:
    projection = copy.deepcopy(payload)
    projection.pop("content_sha256")
    projection.pop("revision")
    return hashlib.sha256(canonical_json_bytes(projection)).hexdigest()


def test_active_discovery_manifest_is_pre_admission_and_unscored() -> None:
    manifest = load_discovery_lane_manifest(MANIFEST_PATH)

    assert manifest.state == "discovery"
    assert manifest.builder_freeze == "forbidden"
    assert manifest.prover_handoff == "forbidden"
    assert {lane.lane_id for lane in manifest.lanes} == {
        "ifem-coercive-galerkin",
        "pde-a-classical-transport",
        "mg-a-intrinsic-distance",
    }
    for lane in manifest.lanes:
        assert lane.source.source_bytes_state == "metadata_only"
        assert lane.source.model_egress_ceiling == "local_only"
        assert lane.source.external_model_source_text == "forbidden"
        assert lane.mathlib_overlap.state == "not_queried"
        assert lane.mathlib_overlap.observed_coverage == "not_observed"
        assert lane.prerequisite_denominator is None or lane.lane_id == "ifem-coercive-galerkin"


def test_ifem_denominator_starts_at_opening_and_excludes_easy_nodes() -> None:
    manifest = load_discovery_lane_manifest(MANIFEST_PATH)
    lane = next(lane for lane in manifest.lanes if lane.lane_id == "ifem-coercive-galerkin")
    denominator = lane.prerequisite_denominator
    plan = lane.precompile_census_plan

    assert denominator is not None
    assert plan is not None
    assert denominator.computed_content_sha256() == denominator.content_sha256
    assert denominator.nodes[0].textbook_stage == "opening"
    assert any(
        node.kind is DiscoveryNodeKindV1.DEFINITION and node.textbook_stage == "opening"
        for node in denominator.nodes
    )
    assert any(
        node.kind is DiscoveryNodeKindV1.EXAMPLE and node.textbook_stage == "opening"
        for node in denominator.nodes
    )
    assert {node.kind for node in denominator.nodes} == set(DiscoveryNodeKindV1)
    assert all(
        not node.included_in_prerequisite_denominator
        for node in denominator.nodes
        if node.kind in {DiscoveryNodeKindV1.EXAMPLE, DiscoveryNodeKindV1.TERMINAL_TARGET}
    )
    plan.assert_binds(denominator)


def test_changed_denominator_needs_new_hash_revision_and_census_plan() -> None:
    payload = _ifem_denominator_payload()
    nodes = payload["nodes"]
    assert isinstance(nodes, list)
    first = nodes[0]
    assert isinstance(first, dict)
    first["summary"] = "Changed after a hypothetical census"

    payload["predecessor_content_sha256"] = _ifem_denominator_payload()["content_sha256"]
    changed_hash = _denominator_hash(payload)
    payload["content_sha256"] = changed_hash
    with pytest.raises(ValueError, match="revision must commit"):
        FrozenPrerequisiteDenominatorV1.model_validate(payload)

    payload["revision"] = f"ifem-coercive-prerequisites-r02-{changed_hash[:12]}"
    changed = FrozenPrerequisiteDenominatorV1.model_validate(payload)
    manifest = load_discovery_lane_manifest(MANIFEST_PATH)
    lane = next(lane for lane in manifest.lanes if lane.lane_id == "ifem-coercive-galerkin")
    assert lane.precompile_census_plan is not None
    with pytest.raises(DiscoveryManifestError, match="does not bind"):
        lane.precompile_census_plan.assert_binds(changed)


def test_unrelated_easy_node_cannot_inflate_the_denominator() -> None:
    payload = _ifem_denominator_payload()
    nodes = payload["nodes"]
    assert isinstance(nodes, list)
    lax_milgram = next(
        node for node in nodes if node["node_id"] == "ifem-lax-milgram-solution-interface"
    )
    assert isinstance(lax_milgram, dict)
    dependencies = lax_milgram["depends_on"]
    assert isinstance(dependencies, list)
    dependencies.remove("ifem-operator-norm-bound")
    changed_hash = _denominator_hash(payload)
    payload["content_sha256"] = changed_hash
    payload["revision"] = f"ifem-coercive-prerequisites-r01-{changed_hash[:12]}"

    with pytest.raises(ValueError, match="selected terminal dependency closure"):
        FrozenPrerequisiteDenominatorV1.model_validate(payload)


def test_revision_zero_cannot_bypass_predecessor_rules() -> None:
    payload = _ifem_denominator_payload()
    content_hash = payload["content_sha256"]
    assert isinstance(content_hash, str)
    payload["revision"] = f"ifem-coercive-prerequisites-r00-{content_hash[:12]}"

    with pytest.raises(ValueError, match="revision"):
        FrozenPrerequisiteDenominatorV1.model_validate(payload)


def test_discovery_manifest_cannot_cross_to_prover() -> None:
    manifest = load_discovery_lane_manifest(MANIFEST_PATH)

    with pytest.raises(DiscoveryManifestError, match="only frozen StatementContractV1"):
        manifest.assert_not_prover_handoffable()
