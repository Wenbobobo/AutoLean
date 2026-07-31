from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from autolean_builder.ifem_pilot_readiness import (
    IFEMPilotReadinessError,
    IFEMPilotReadinessOutcomeV1,
    IFEMPilotReadinessReasonV2,
    evaluate_ifem_pilot_readiness,
    load_ifem_pilot_readiness_decision,
    verify_ifem_pilot_readiness_decision,
    write_ifem_pilot_readiness_decision_once,
)
from autolean_builder.ifem_pinned_mathlib_profiles import (
    NEGATIVE_CONTROL,
    IFEMPinnedMathlibProfileBuildReceiptV1,
    IFEMPinnedMathlibProfileObservationsV1,
    IFEMPinnedMathlibProfilePlanV1,
    IFEMPinnedMathlibProfileResultV1,
)
from autolean_builder.ifem_prerequisite_census import (
    DEFAULT_PLAN_PATH,
    IFEMPrerequisiteCensusPlanV1,
    IFEMPrerequisiteCensusResultV1,
    load_ifem_prerequisite_census_plan,
    not_run_result,
)
from autolean_contracts import canonical_json_bytes

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64

_PROFILES = (
    ("ifem-singleton-defs", "Mathlib.Analysis.InnerProductSpace.Defs"),
    ("ifem-singleton-dual", "Mathlib.Analysis.InnerProductSpace.Dual"),
    ("ifem-singleton-lax-milgram", "Mathlib.Analysis.InnerProductSpace.LaxMilgram"),
    ("ifem-singleton-operator-basic", "Mathlib.Analysis.Normed.Operator.Basic"),
    ("ifem-singleton-operator-bilinear", "Mathlib.Analysis.Normed.Operator.Bilinear"),
)
_OLEAN_PATHS = (
    "/opt/mathlib/.lake/build/lib/lean/AutoLean/AutoleanIFEMPinnedProfileQuery.olean",
    "/opt/mathlib/.lake/build/lib/lean/Mathlib/Analysis/InnerProductSpace/Defs.olean",
    "/opt/mathlib/.lake/build/lib/lean/Mathlib/Analysis/InnerProductSpace/Dual.olean",
    "/opt/mathlib/.lake/build/lib/lean/Mathlib/Analysis/InnerProductSpace/LaxMilgram.olean",
    "/opt/mathlib/.lake/build/lib/lean/Mathlib/Analysis/Normed/Operator/Basic.olean",
    "/opt/mathlib/.lake/build/lib/lean/Mathlib/Analysis/Normed/Operator/Bilinear.olean",
)
_CRITICAL_NODES = {
    "ifem-restricted-bilinear-form",
    "ifem-restricted-coercivity",
    "ifem-restricted-continuity",
    "ifem-restricted-functional",
}


def _sha256(payload: object) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _content_addressed(payload: dict[str, object]) -> dict[str, object]:
    body = dict(payload)
    body.pop("content_sha256", None)
    body["content_sha256"] = _sha256(body)
    return body


def _plan() -> IFEMPrerequisiteCensusPlanV1:
    return load_ifem_prerequisite_census_plan(DEFAULT_PLAN_PATH)


def _candidate_declarations(plan: IFEMPrerequisiteCensusPlanV1) -> tuple[str, ...]:
    return tuple(sorted({name for query in plan.queries for name in query.candidate_declarations}))


def _reviewed_result(
    plan: IFEMPrerequisiteCensusPlanV1,
    *,
    missing_critical: bool = False,
) -> IFEMPrerequisiteCensusResultV1:
    critical = {query.node_id for query in plan.queries if query.node_id in _CRITICAL_NODES}
    direct_ids = set(critical)
    for query in plan.queries:
        if len(direct_ids) == 15:
            break
        if query.node_id not in direct_ids:
            direct_ids.add(query.node_id)
    if missing_critical:
        direct_ids.remove("ifem-restricted-coercivity")
    node_results: list[dict[str, object]] = []
    for query in plan.queries:
        if query.node_id in direct_ids:
            declaration = query.candidate_declarations[0]
            evidence = {
                "adapter_compile_receipt_sha256": None,
                "adapter_source_sha256": None,
                "canonical_type_sha256s": [SHA_A],
                "classification": "direct",
                "declaration_inventory_sha256": None,
                "explicit_unknown_reason": None,
                "mapped_declarations": [declaration],
                "negative_query_observation_sha256": None,
                "query_observation_sha256": SHA_B,
                "semantic_review_sha256": SHA_C,
            }
        else:
            evidence = {
                "adapter_compile_receipt_sha256": None,
                "adapter_source_sha256": None,
                "canonical_type_sha256s": [],
                "classification": "missing",
                "declaration_inventory_sha256": SHA_A,
                "explicit_unknown_reason": None,
                "mapped_declarations": [],
                "negative_query_observation_sha256": SHA_B,
                "query_observation_sha256": None,
                "semantic_review_sha256": SHA_C,
            }
        node_results.append({"node_id": query.node_id, "evidence": evidence})
    return IFEMPrerequisiteCensusResultV1.model_validate(
        _content_addressed(
            {
                "builder_freeze": "forbidden",
                "coverage_claim": "not_authorized",
                "denominator": plan.denominator.model_dump(mode="json"),
                "environment": plan.environment.model_dump(mode="json"),
                "execution_state": "completed",
                "node_results": node_results,
                "plan_content_sha256": plan.content_sha256,
                "protocol": "autolean.builder-ifem-prerequisite-census.v1",
                "prover_handoff": "forbidden",
                "query_observation_sha256": SHA_B,
                "query_source_sha256": SHA_A,
                "resume_command": ["uv", "run"],
                "schema_version": "autolean.ifem-prerequisite-census-result.v1",
            }
        )
    )


def _profile_plan(plan: IFEMPrerequisiteCensusPlanV1) -> IFEMPinnedMathlibProfilePlanV1:
    payload: dict[str, object] = {
        "assets": {
            "built_olean_manifest_path": (
                "/opt/autolean/attestations/ifem-pinned-profile-built-oleans.sha256"
            ),
            "dockerfile_path": "Prover/worker/Dockerfile.ifem-pinned-profile-query",
            "dockerfile_sha256": SHA_A,
            "helper_path": "Prover/worker/AutoleanIFEMPinnedProfileQuery.lean",
            "helper_sha256": SHA_B,
            "wrapper_path": "Prover/worker/autolean-ifem-pinned-profile-query",
            "wrapper_sha256": SHA_C,
        },
        "authority": {
            "builder_freeze_authorized": False,
            "coverage_claim_authorized": False,
            "mathematical_mapping_authorized": False,
            "proof_submission_authorized": False,
            "prover_handoff_authorized": False,
            "semantic_classification_authorized": False,
        },
        "candidate_declarations": list(_candidate_declarations(plan)),
        "census_plan_content_sha256": plan.content_sha256,
        "census_plan_path": (
            "Builder/pilots/discovery/ifem-coercive-prerequisite-census-plan.v1.json"
        ),
        "denominator": plan.denominator.model_dump(mode="json"),
        "environment": {
            "lake_manifest_sha256": plan.environment.lake_manifest_sha256,
            "lean_toolchain": plan.environment.lean_toolchain,
            "mathlib_revision": plan.environment.mathlib_revision,
            "parent_image": (
                "autolean/mathlib-worker@sha256:"
                "3237192cf627a05367c75d46e61ec9034fefe43a4fd0c06139e38c80358648d6"
            ),
        },
        "negative_control": NEGATIVE_CONTROL,
        "observation_contract": {
            "canonical_type": "required_if_present",
            "declaration_origin": "required_if_present",
            "loaded_module_closure": "required",
            "negative_control": "required_and_must_be_absent",
            "observed_axioms": "required_if_present",
        },
        "profiles": [
            {"profile_id": profile_id, "direct_import": direct_import}
            for profile_id, direct_import in _PROFILES
        ],
        "protocol": "autolean.ifem-pinned-profile-query.v1",
        "schema_version": "autolean.ifem-pinned-mathlib-profile-plan.v1",
        "state": "not_run",
    }
    return IFEMPinnedMathlibProfilePlanV1.model_validate(_content_addressed(payload))


def _profile_bundle(
    census_plan: IFEMPrerequisiteCensusPlanV1,
    *,
    broad_transitive_closure: bool = False,
) -> tuple[
    IFEMPinnedMathlibProfilePlanV1,
    IFEMPinnedMathlibProfileResultV1,
    IFEMPinnedMathlibProfileObservationsV1,
    IFEMPinnedMathlibProfileBuildReceiptV1,
]:
    plan = _profile_plan(census_plan)
    profiles: list[dict[str, object]] = []
    for profile_id, direct_import in _PROFILES:
        observed_import = direct_import
        declarations = [
            {
                "canonical_type": "Type",
                "canonical_type_sha256": hashlib.sha256(b"Type").hexdigest(),
                "declaration": declaration,
                "declaration_kind": "def",
                "observed_axioms": [],
                "origin_module": observed_import,
                "present": True,
            }
            for declaration in plan.candidate_declarations
        ]
        closure = [observed_import]
        if broad_transitive_closure:
            closure.append("Mathlib.Algebra.Group.Basic")
        closure = sorted(closure)
        profiles.append(
            {
                "declarations": declarations,
                "direct_imports": [observed_import],
                "loaded_module_closure": closure,
                "loaded_module_closure_sha256": _sha256(closure),
                "negative_control": {
                    "canonical_type": None,
                    "canonical_type_sha256": None,
                    "declaration": NEGATIVE_CONTROL,
                    "declaration_kind": None,
                    "observed_axioms": [],
                    "origin_module": None,
                    "present": False,
                },
                "profile_id": profile_id,
            }
        )
    observation_payload: dict[str, object] = {
        "authority": {
            "builder_freeze_authorized": False,
            "coverage_claim_authorized": False,
            "mathematical_mapping_authorized": False,
            "proof_submission_authorized": False,
            "prover_handoff_authorized": False,
            "semantic_classification_authorized": False,
        },
        "built_olean_hashes": [{"path": path, "sha256": SHA_D} for path in _OLEAN_PATHS],
        "built_olean_manifest_sha256": SHA_A,
        "child_image": f"sha256:{SHA_B}",
        "helper_sha256": plan.assets.helper_sha256,
        "lake_manifest_sha256": plan.environment.lake_manifest_sha256,
        "lean_toolchain": plan.environment.lean_toolchain,
        "mathlib_revision": plan.environment.mathlib_revision,
        "parent_image": plan.environment.parent_image,
        "plan_content_sha256": plan.content_sha256,
        "profiles": profiles,
        "protocol": "autolean.ifem-pinned-profile-query.v1",
        "schema_version": "autolean.ifem-pinned-mathlib-profile-observations.v1",
        "wrapper_sha256": plan.assets.wrapper_sha256,
    }
    observations = IFEMPinnedMathlibProfileObservationsV1.model_validate(
        _content_addressed(observation_payload)
    )
    result_payload: dict[str, object] = {
        "authority": observation_payload["authority"],
        "execution_state": "completed",
        "not_run_reason": None,
        "observation_content_sha256": observations.content_sha256,
        "plan_content_sha256": plan.content_sha256,
        "protocol": "autolean.ifem-pinned-profile-query.v1",
        "schema_version": "autolean.ifem-pinned-mathlib-profile-result.v1",
    }
    result = IFEMPinnedMathlibProfileResultV1.model_validate(_content_addressed(result_payload))
    receipt_payload: dict[str, object] = {
        "authority": observation_payload["authority"],
        "build_network": "none",
        "child_image": observations.child_image,
        "child_image_tag": f"autolean/ifem-pinned-profile-query:plan-{plan.content_sha256[:12]}",
        "dockerfile_sha256": plan.assets.dockerfile_sha256,
        "helper_sha256": plan.assets.helper_sha256,
        "parent_image": plan.environment.parent_image,
        "plan_content_sha256": plan.content_sha256,
        "protocol": "autolean.ifem-pinned-profile-query.v1",
        "schema_version": "autolean.ifem-pinned-mathlib-profile-build-receipt.v1",
        "staged_context_sha256": SHA_D,
        "wrapper_sha256": plan.assets.wrapper_sha256,
    }
    receipt = IFEMPinnedMathlibProfileBuildReceiptV1.model_validate(
        _content_addressed(receipt_payload)
    )
    return plan, result, observations, receipt


def test_not_run_census_is_incomplete_not_no_go() -> None:
    plan = _plan()
    decision = evaluate_ifem_pilot_readiness(
        plan,
        not_run_result(plan, plan_path=DEFAULT_PLAN_PATH, reason="operator_not_run"),
    )

    assert decision.outcome is IFEMPilotReadinessOutcomeV1.INCOMPLETE
    assert set(decision.reasons) == {
        IFEMPilotReadinessReasonV2.CENSUS_NOT_COMPLETED,
        IFEMPilotReadinessReasonV2.PROFILE_EVIDENCE_NOT_SUPPLIED,
        IFEMPilotReadinessReasonV2.SEMANTIC_CLASSIFICATION_INCOMPLETE,
        IFEMPilotReadinessReasonV2.TRANSITIVE_CLOSURE_POLICY_UNRESOLVED,
    }
    assert decision.builder_freeze == "forbidden"
    assert decision.prover_handoff == "forbidden"
    assert decision.authority == type(decision.authority)()


def test_self_rehashed_go_cannot_contradict_not_run_evidence() -> None:
    plan = _plan()
    decision = evaluate_ifem_pilot_readiness(
        plan,
        not_run_result(plan, plan_path=DEFAULT_PLAN_PATH, reason="operator_not_run"),
    )
    payload = decision.model_dump(mode="json")
    payload["outcome"] = "go"
    payload["reasons"] = ["all_frozen_readiness_conditions_satisfied"]
    forged = _content_addressed(payload)

    with pytest.raises(ValueError, match="outcome or reasons do not follow"):
        type(decision).model_validate(forged)


def test_v1_decision_cannot_be_relabelled_as_current_v2() -> None:
    plan = _plan()
    decision = evaluate_ifem_pilot_readiness(
        plan,
        not_run_result(plan, plan_path=DEFAULT_PLAN_PATH, reason="operator_not_run"),
    )
    payload = decision.model_dump(mode="json")
    payload["schema_version"] = "autolean.ifem-pilot-readiness-decision.v1"
    payload["protocol"] = "autolean.builder-ifem-pilot-readiness.v1"
    forged = _content_addressed(payload)

    with pytest.raises(ValueError, match="literal_error"):
        type(decision).model_validate(forged)


def test_direct_import_flag_cannot_be_forged_without_bound_profile_evidence() -> None:
    plan = _plan()
    decision = evaluate_ifem_pilot_readiness(
        plan,
        not_run_result(plan, plan_path=DEFAULT_PLAN_PATH, reason="operator_not_run"),
    )
    payload = decision.model_dump(mode="json")
    payload["direct_imports_verified"] = True
    forged = _content_addressed(payload)

    with pytest.raises(ValueError, match="direct-import verification flag contradicts"):
        type(decision).model_validate(forged)


def test_exact_replay_rejects_a_decision_bound_to_different_census_evidence() -> None:
    plan = _plan()
    operator_not_run = not_run_result(plan, plan_path=DEFAULT_PLAN_PATH, reason="operator_not_run")
    decision = evaluate_ifem_pilot_readiness(plan, operator_not_run)

    verify_ifem_pilot_readiness_decision(decision, plan, operator_not_run)

    with pytest.raises(IFEMPilotReadinessError, match="differs from the exact recomputation"):
        verify_ifem_pilot_readiness_decision(
            decision,
            plan,
            not_run_result(plan, plan_path=DEFAULT_PLAN_PATH, reason="pinned_runtime_unavailable"),
        )


def test_exact_15_of_21_and_observed_critical_apis_waits_for_closure_policy() -> None:
    census_plan = _plan()
    profile_plan, profile_result, observations, receipt = _profile_bundle(census_plan)
    decision = evaluate_ifem_pilot_readiness(
        census_plan,
        _reviewed_result(census_plan),
        profile_plan=profile_plan,
        profile_result=profile_result,
        profile_observations=observations,
        profile_build_receipt=receipt,
    )

    assert decision.outcome is IFEMPilotReadinessOutcomeV1.INCOMPLETE
    assert decision.reasons == (IFEMPilotReadinessReasonV2.TRANSITIVE_CLOSURE_POLICY_UNRESOLVED,)
    assert decision.counts.direct_or_thin_count == 15
    assert decision.counts.unknown_count == 0
    assert decision.direct_imports_verified is True
    assert decision.transitive_closure_policy_resolved is False
    assert all(
        state.observed_under_exact_direct_import_profiles is True
        for state in decision.critical_restriction_states
    )
    assert decision.authority.local_calibration_authorized is False


def test_broad_transitive_closure_is_not_misrepresented_as_narrow_or_go() -> None:
    census_plan = _plan()
    profile_plan, profile_result, observations, receipt = _profile_bundle(
        census_plan,
        broad_transitive_closure=True,
    )
    decision = evaluate_ifem_pilot_readiness(
        census_plan,
        _reviewed_result(census_plan),
        profile_plan=profile_plan,
        profile_result=profile_result,
        profile_observations=observations,
        profile_build_receipt=receipt,
    )

    assert decision.outcome is IFEMPilotReadinessOutcomeV1.INCOMPLETE
    assert decision.direct_imports_verified is True
    assert decision.transitive_closure_policy_resolved is False
    assert decision.profile_evidence_state.value == "direct_imports_bound_closure_unreviewed"
    assert decision.reasons == (IFEMPilotReadinessReasonV2.TRANSITIVE_CLOSURE_POLICY_UNRESOLVED,)


def test_reviewed_missing_critical_restriction_is_no_go_without_profile_wait() -> None:
    plan = _plan()
    decision = evaluate_ifem_pilot_readiness(
        plan,
        _reviewed_result(plan, missing_critical=True),
    )

    assert decision.outcome is IFEMPilotReadinessOutcomeV1.NO_GO
    assert IFEMPilotReadinessReasonV2.RESTRICTION_API_MISSING in decision.reasons
    assert IFEMPilotReadinessReasonV2.COVERAGE_BELOW_BAND in decision.reasons
    assert IFEMPilotReadinessReasonV2.PROFILE_EVIDENCE_NOT_SUPPLIED not in decision.reasons


def test_in_memory_wrong_direct_import_fails_self_revalidation() -> None:
    census_plan = _plan()
    profile_plan, profile_result, observations, receipt = _profile_bundle(census_plan)
    profiles = list(observations.profiles)
    wrong_imports = (_PROFILES[-1][1],)
    profile_payload = profiles[0].model_dump(mode="python")
    profile_payload.update(
        {
            "direct_imports": wrong_imports,
            "loaded_module_closure": wrong_imports,
            "loaded_module_closure_sha256": _sha256(list(wrong_imports)),
        }
    )
    profiles[0] = type(profiles[0]).model_construct(**profile_payload)
    observation_payload = dict(observations.__dict__)
    observation_payload["profiles"] = tuple(profiles)
    bypassed_observations = type(observations).model_construct(**observation_payload)

    with pytest.raises(IFEMPilotReadinessError, match="failed self-revalidation"):
        evaluate_ifem_pilot_readiness(
            census_plan,
            _reviewed_result(census_plan),
            profile_plan=profile_plan,
            profile_result=profile_result,
            profile_observations=bypassed_observations,
            profile_build_receipt=receipt,
        )


def test_completed_profile_result_requires_both_observation_and_receipt() -> None:
    census_plan = _plan()
    profile_plan, profile_result, _, _ = _profile_bundle(census_plan)

    with pytest.raises(IFEMPilotReadinessError, match="requires observation and build receipt"):
        evaluate_ifem_pilot_readiness(
            census_plan,
            _reviewed_result(census_plan),
            profile_plan=profile_plan,
            profile_result=profile_result,
        )


def test_decision_is_write_once_and_reloads(tmp_path: Path) -> None:
    plan = _plan()
    decision = evaluate_ifem_pilot_readiness(
        plan,
        not_run_result(plan, plan_path=DEFAULT_PLAN_PATH, reason="operator_not_run"),
    )
    path = tmp_path / "readiness.json"

    write_ifem_pilot_readiness_decision_once(path, decision)
    write_ifem_pilot_readiness_decision_once(path, decision)

    assert load_ifem_pilot_readiness_decision(path) == decision
    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert loaded["content_sha256"] == decision.content_sha256


def test_tracked_graph_chain_successor_replays_exact_af4_census() -> None:
    root = Path(__file__).resolve().parents[2]
    census_path = (
        root / "docs" / "research" / "ifem-prerequisite-census-not-run-2026-07-31-graph-chain.json"
    )
    decision_path = (
        root
        / "docs"
        / "research"
        / "ifem-pilot-readiness-decision-2026-07-31-graph-chain-successor.json"
    )
    graph_path = (
        root / "Builder" / "pilots" / "discovery" / "ifem-candidate-dependency-graph.v1.json"
    )

    plan = _plan()
    census_result = IFEMPrerequisiteCensusResultV1.model_validate_json(
        census_path.read_text(encoding="utf-8")
    )
    decision = load_ifem_pilot_readiness_decision(decision_path)
    graph = json.loads(graph_path.read_text(encoding="utf-8"))

    assert census_result.content_sha256 == (
        "af4ae42b2f7d983a98c30195348d4252edf88a0ccca9fa66cf1f4041947293da"
    )
    assert graph["source_binding"]["census_result_sha256"] == census_result.content_sha256
    assert decision.evidence.census_result_content_sha256 == census_result.content_sha256
    assert decision.content_sha256 == (
        "b145c82985c7b3fe1b3e3551fad1a6d71f6f369ad0231d18102ba66dfc705202"
    )
    assert decision.outcome is IFEMPilotReadinessOutcomeV1.INCOMPLETE
    assert decision.counts.unknown_count == 21
    assert decision.profile_evidence_state.value == "not_supplied"
    assert decision.builder_freeze == "forbidden"
    assert decision.prover_handoff == "forbidden"

    verify_ifem_pilot_readiness_decision(decision, plan, census_result)


def test_tracked_oci_successor_replays_completed_unknown_only_census() -> None:
    root = Path(__file__).resolve().parents[2]
    research = root / "docs" / "research"
    result_path = research / "ifem-prerequisite-census-oci-result-2026-07-31.json"
    decision_path = research / "ifem-pilot-readiness-decision-2026-07-31-oci-successor.json"
    observation_path = research / "ifem-prerequisite-census-oci-observation-2026-07-31.json"
    receipt_path = research / "ifem-prerequisite-census-oci-receipt-2026-07-31.json"
    execution_path = research / "ifem-prerequisite-census-oci-execution-2026-07-31.json"

    plan = _plan()
    result = IFEMPrerequisiteCensusResultV1.model_validate_json(
        result_path.read_text(encoding="utf-8")
    )
    decision = load_ifem_pilot_readiness_decision(decision_path)
    observation = json.loads(observation_path.read_text(encoding="utf-8"))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    execution = json.loads(execution_path.read_text(encoding="utf-8"))

    assert result.execution_state.value == "completed"
    assert result.content_sha256 == (
        "fbaf12b9f9979131f1ce2f7075808c0141e4a5933046b6a369a2f75818016165"
    )
    assert all(item.evidence.classification.value == "unknown" for item in result.node_results)
    assert result.query_observation_sha256 == observation["content_sha256"]
    assert execution["result_content_sha256"] == result.content_sha256
    assert execution["worker_receipt_content_sha256"] == receipt["content_sha256"]
    assert decision.evidence.census_result_content_sha256 == result.content_sha256
    assert decision.content_sha256 == (
        "07c2655e497d53082448bfc7a7a5997d5480eb6beffcc84f5770b10934fd3732"
    )
    assert decision.outcome is IFEMPilotReadinessOutcomeV1.INCOMPLETE
    assert decision.counts.unknown_count == 21
    assert decision.profile_evidence_state.value == "not_supplied"
    assert decision.builder_freeze == "forbidden"
    assert decision.prover_handoff == "forbidden"

    verify_ifem_pilot_readiness_decision(decision, plan, result)
