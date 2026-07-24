from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from autolean_builder import (
    PilotAdmissionModeV1,
    PilotGraphV1,
    PilotHarnessError,
    PilotManifestV1,
    PilotReviewStateV1,
    PilotSourceStatusV1,
    ReferenceCache,
    ReferenceManifestV1,
    load_pilot_manifest,
    verify_cached_textbook_alignment,
)
from autolean_builder.pilot_harness import (
    PilotAgentReviewRoleV2,
    PilotBoundaryDecisionV2,
    PilotNonClaimV2,
    PilotRuleCoverageStateV2,
    PilotRuleMatrixEntryV2,
    load_pilot_boundary_decision,
    pilot_candidate_binding_sha256,
    pilot_formal_environment_sha256,
)
from autolean_contracts import (
    AxiomProfileV1,
    PermissionDecisionV1,
    RightsRecordV1,
    stable_identifier,
)
from autolean_contracts.hashing import canonical_json_bytes

_ROOT = Path(__file__).parents[2]
_MANIFEST_PATH = _ROOT / "Builder" / "pilots" / "self-calibration" / "pilot-manifest.v1.json"
_REFERENCE_MANIFEST = _ROOT / "Builder" / "references" / "manifest.v1.json"
_CACHE_ROOT = _ROOT / ".cache" / "references"


def _manifest() -> PilotManifestV1:
    return load_pilot_manifest(_MANIFEST_PATH)


def test_parallel_candidates_are_explicitly_blocked_until_calibrated() -> None:
    manifest = _manifest()

    assert manifest.prover_handoff == "forbidden"
    assert {graph.graph_id for graph in manifest.parallel_candidates()} == {
        "first-order-soundness-conditional",
        "abstract-galerkin-cea-conditional",
        "van-kampen-rights-restricted",
    }
    for graph in manifest.parallel_candidates():
        assert graph.admission_blocker_ids()
        assert all(
            requirement.review_state is PilotReviewStateV1.PENDING
            for requirement in graph.calibration_requirements
        )
        with pytest.raises(PilotHarnessError, match="cannot enter Builder statement drafting"):
            graph.assert_ready_for_statement_drafting()


def test_curvature_reference_graph_has_a_machine_checkable_overlap_blocker() -> None:
    graph = next(
        graph
        for graph in _manifest().graphs
        if graph.graph_id == "connection-curvature-overlap-reference"
    )

    assert graph.admission_mode is PilotAdmissionModeV1.OVERLAP_BLOCKED_REFERENCE
    assert "upstream-curvature-pr-36036" in graph.admission_blocker_ids()
    with pytest.raises(PilotHarnessError, match="only frozen StatementContractV1"):
        graph.assert_not_prover_handoffable()


def test_slc_local_copy_binds_source_spans_without_admitting_a_statement() -> None:
    graph = _manifest().graph("first-order-soundness-conditional")
    binding = graph.source.reference

    assert graph.source.status is PilotSourceStatusV1.VERIFIED_LOCAL_COPY
    assert binding is not None
    assert binding.reference_id == "openlogic-sets-logic-computation-2026-07-12-text"
    assert binding.source_scope.value == "declared_entry_boundary"
    assert binding.prior_dependency_review_state is PilotReviewStateV1.PENDING
    assert {anchor.anchor_id for anchor in binding.anchors} == {
        "mt-terms-formulas",
        "mt-satisfaction",
        "mt-sequent-calculus",
        "mt-sequent-soundness",
    }
    assert "source-provenance-pending" not in graph.admission_blocker_ids()
    assert "textbook-entry-dependencies-pending" in graph.admission_blocker_ids()
    with pytest.raises(PilotHarnessError, match="cannot enter Builder statement drafting"):
        graph.assert_ready_for_statement_drafting("mt-soundness-target")
    with pytest.raises(PilotHarnessError, match="only frozen StatementContractV1"):
        graph.assert_not_prover_handoffable()


def test_manifest_rejects_dependency_outside_its_graph() -> None:
    payload = _manifest().model_dump(mode="python")
    payload["graphs"][1]["nodes"][1]["depends_on"] = ("missing-node",)

    with pytest.raises(ValueError, match="dependency is absent"):
        PilotManifestV1.model_validate(payload)


def test_manifest_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.json"
    path.write_text(
        '{"schema_version":"autolean.builder-pilot-manifest.v1",'
        '"schema_version":"autolean.builder-pilot-manifest.v1"}',
        encoding="utf-8",
    )

    with pytest.raises(PilotHarnessError, match="duplicate JSON key"):
        load_pilot_manifest(path)


def test_verified_local_textbook_anchors_still_bind_when_cache_is_available() -> None:
    expected_text = _CACHE_ROOT / "mckay-lectures-differential-geometry-2022-text"
    if not expected_text.exists():
        pytest.skip("official local McKay cache is intentionally absent")
    cache = ReferenceCache(
        ReferenceManifestV1.load(_REFERENCE_MANIFEST),
        _CACHE_ROOT,
        confinement_root=_ROOT,
    )

    verified = verify_cached_textbook_alignment(_manifest(), cache)

    assert tuple(
        item for item in verified if item.startswith("connection-curvature-overlap-reference:")
    ) == (
        "connection-curvature-overlap-reference:connection-definition",
        "connection-curvature-overlap-reference:metric-compatibility",
        "connection-curvature-overlap-reference:curvature-form",
        "connection-curvature-overlap-reference:curvature-operator",
        "connection-curvature-overlap-reference:metric-curvature",
    )


def test_verified_slc_local_copy_anchors_still_bind_when_cache_is_available() -> None:
    expected_text = _CACHE_ROOT / "openlogic-sets-logic-computation-2026-07-12-text"
    if not expected_text.exists():
        pytest.skip("official local SLC cache is intentionally absent")
    cache = ReferenceCache(
        ReferenceManifestV1.load(_REFERENCE_MANIFEST),
        _CACHE_ROOT,
        confinement_root=_ROOT,
    )

    verified = verify_cached_textbook_alignment(_manifest(), cache)

    assert {item for item in verified if item.startswith("first-order-soundness-conditional:")} == {
        "first-order-soundness-conditional:mt-terms-formulas",
        "first-order-soundness-conditional:mt-satisfaction",
        "first-order-soundness-conditional:mt-sequent-calculus",
        "first-order-soundness-conditional:mt-sequent-soundness",
    }


def _accepted_curvature_graph() -> PilotGraphV1:
    graph = _manifest().graph("connection-curvature-overlap-reference")
    payload = graph.model_dump(mode="python")
    payload["admission_mode"] = "conditional_candidate"
    payload["blockers"] = ()
    payload["source"]["reference"]["prior_dependency_review_state"] = "accepted"
    payload["mathlib_census"].update(
        {
            "current_review_state": "accepted",
            "target_mathlib_revision": "8f9d9cff6bd728b17a24e163c9402775d9e6a365",
            "lake_manifest_sha256": "1" * 64,
            "search_protocol_sha256": "2" * 64,
            "result_artifact_sha256": "3" * 64,
        }
    )
    for requirement in payload["calibration_requirements"]:
        requirement["review_state"] = "accepted"
        requirement["reviews"] = tuple(
            {
                "reviewer_id": f"{requirement['role']}-reviewer-{index}",
                "independence_group": f"group-{index}",
                "evidence_sha256": f"{index + 4:x}" * 64,
                "review_state": "accepted",
            }
            for index in range(requirement["required_independence_groups"])
        )
    for node in payload["nodes"]:
        node["review_state"] = "accepted"
        node["review_evidence_sha256"] = "a" * 64
    for gate in payload["feedback_gates"]:
        gate["review_state"] = "accepted"
        gate["review_evidence_sha256"] = "b" * 64
    return PilotGraphV1.model_validate(payload)


def _rights() -> RightsRecordV1:
    return RightsRecordV1(
        rights_id=stable_identifier("rights", "pilot-admission"),
        source_id=stable_identifier("source", "pilot-admission"),
        overall_decision=PermissionDecisionV1.RESTRICTED,
    )


def test_admission_requires_reviewed_target_closure_feedback_and_independent_groups() -> None:
    graph = _accepted_curvature_graph()
    graph.assert_ready_for_statement_drafting("cc-curvature-operator")

    pending_gate = graph.model_dump(mode="python")
    pending_gate["feedback_gates"][0].update(
        {"review_state": "pending", "review_evidence_sha256": None}
    )
    blocked = PilotGraphV1.model_validate(pending_gate)
    assert "feedback-cc-opposite-symmetry-pending" in blocked.admission_blocker_ids(
        "cc-curvature-operator"
    )

    missing_groups = graph.model_dump(mode="python")
    missing_groups["calibration_requirements"][1]["reviews"] = ()
    with pytest.raises(ValueError, match="independent review groups"):
        PilotGraphV1.model_validate(missing_groups)


def test_admission_receipt_rebinds_manifest_target_and_rights() -> None:
    payload = _manifest().model_dump(mode="python")
    payload["graphs"] = (
        _accepted_curvature_graph().model_dump(mode="python"),
        *payload["graphs"][1:],
    )
    manifest = PilotManifestV1.model_validate(payload)
    receipt = manifest.issue_admission_receipt(
        graph_id="connection-curvature-overlap-reference",
        target_node_id="cc-curvature-operator",
        rights=_rights(),
    )

    manifest.validate_admission_receipt(receipt, rights=_rights())
    changed_rights = _rights().model_copy(update={"restrictions": ("different",)})
    with pytest.raises(PilotHarnessError, match="does not bind"):
        manifest.validate_admission_receipt(receipt, rights=changed_rights)


def _accepted_model_theory_manifest() -> PilotManifestV1:
    manifest_payload = _manifest().model_dump(mode="python")
    graph_index = next(
        index
        for index, graph in enumerate(manifest_payload["graphs"])
        if graph["graph_id"] == "first-order-soundness-conditional"
    )
    graph = manifest_payload["graphs"][graph_index]
    graph["source"]["reference"]["prior_dependency_review_state"] = "accepted"
    graph["mathlib_census"].update(
        {
            "current_review_state": "accepted",
            "target_mathlib_revision": "8f9d9cff6bd728b17a24e163c9402775d9e6a365",
            "lake_manifest_sha256": "1" * 64,
            "search_protocol_sha256": "2" * 64,
            "result_artifact_sha256": "3" * 64,
        }
    )
    for requirement in graph["calibration_requirements"]:
        requirement["review_state"] = "accepted"
        requirement["reviews"] = tuple(
            {
                "reviewer_id": f"{requirement['role']}-reviewer-{index}",
                "independence_group": f"{requirement['role']}-group-{index}",
                "evidence_sha256": f"{index + 4:x}" * 64,
                "review_state": "accepted",
            }
            for index in range(requirement["required_independence_groups"])
        )
    for node in graph["nodes"]:
        node["review_state"] = "accepted"
        node["review_evidence_sha256"] = "a" * 64
    for gate in graph["feedback_gates"]:
        gate["review_state"] = "accepted"
        gate["review_evidence_sha256"] = "b" * 64
    return PilotManifestV1.model_validate(manifest_payload)


def _v2_rule_matrix_hash(rows: tuple[PilotRuleMatrixEntryV2, ...]) -> str:
    payload = tuple(row.model_dump(mode="json") for row in rows)
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _v2_decision_payload(
    *,
    disposition: str = "gap",
    manifest: PilotManifestV1 | None = None,
) -> tuple[PilotManifestV1, dict[str, object]]:
    manifest = manifest or _accepted_model_theory_manifest()
    graph = manifest.graph("first-order-soundness-conditional")
    closure = graph.target_closure("mt-soundness-target")
    reference = graph.source.reference
    assert reference is not None
    closure_anchor_ids = {anchor_id for node in closure for anchor_id in node.source_anchor_ids}
    anchors = tuple(
        {
            "anchor_id": anchor.anchor_id,
            "start_offset": anchor.start_offset,
            "end_offset": anchor.end_offset,
            "raw_sha256": anchor.raw_sha256,
            "human_locator": anchor.human_locator,
        }
        for anchor in reference.anchors
        if anchor.anchor_id in closure_anchor_ids
    )
    declaration = "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Deriv.closed_sound"
    matrix = tuple(
        PilotRuleMatrixEntryV2(
            rule_id=f"rule-{anchor['anchor_id']}",
            source_anchor_ids=(anchor["anchor_id"],),
            implementation_declarations=(declaration,),
            coverage_state=PilotRuleCoverageStateV2.EXACT,
            rationale="Synthetic V2 protocol fixture; no semantic authority.",
        )
        for anchor in anchors
    )
    reviews = tuple(
        {
            "role": role.value,
            "reviewer_id": f"agent:v2-{role.value}",
            "reviewer_kind": "automated_agent",
            "independence_group": f"v2-{role.value}-group",
            "context_pack_sha256": f"{index + 1:x}" * 64,
            "output_sha256": f"{index + 6:x}" * 64,
            "execution_run_receipt_sha256": f"{index + 11:x}" * 64,
            "review_state": "accepted",
            "claims_human_or_expert_authority": False,
        }
        for index, role in enumerate(PilotAgentReviewRoleV2)
    )
    blockers = ("v2-gap",)
    candidate_id = "model-theory-closed-external-open-internal"
    candidate_revision = "round-02-hybrid-v1"
    boundary_summary = "Closed external theorem with an open level-indexed internal calculus."
    required_mechanisms = (
        "fresh-eigenconstant discipline",
        "level-indexed open assignments",
    )
    out_of_scope = ("existential rules", "full LK completeness")
    lean_toolchain = "leanprover/lean4:v4.28.0"
    lean_version = "v4.28.0"
    lean_build_identity = (
        "Lean (version 4.28.0, x86_64-unknown-linux-gnu, "
        "commit 7e01a1bf5c70fc6167d49c345d3bf80596e9a79b, Release)"
    )
    mathlib_revision = "8f9d9cff6bd728b17a24e163c9402775d9e6a365"
    lake_manifest_sha256 = "5" * 64
    imports_allowlist = ("Mathlib.ModelTheory.Semantics",)
    axioms_allowlist: tuple[str, ...] = ()
    axiom_profile = AxiomProfileV1.STRICT
    proof_slot_profile = "lean-exact-declaration-boundary.v1"
    allowed_write_paths = ("Proof.lean",)
    worker_image_digest = "sha256:" + "a" * 64
    environment_sha256 = pilot_formal_environment_sha256(
        lean_toolchain=lean_toolchain,
        lean_version=lean_version,
        lean_build_identity=lean_build_identity,
        mathlib_revision=mathlib_revision,
        lake_manifest_sha256=lake_manifest_sha256,
        imports_allowlist=imports_allowlist,
        axioms_allowlist=axioms_allowlist,
        axiom_profile=axiom_profile,
        proof_slot_profile=proof_slot_profile,
        allowed_write_paths=allowed_write_paths,
        worker_image_digest=worker_image_digest,
    )
    payload: dict[str, object] = {
        "manifest_sha256": hashlib.sha256(manifest.canonical_bytes()).hexdigest(),
        "graph_id": graph.graph_id,
        "graph_sha256": hashlib.sha256(canonical_json_bytes(graph)).hexdigest(),
        "target_node_id": "mt-soundness-target",
        "target_closure_sha256": hashlib.sha256(
            canonical_json_bytes(tuple(node.model_dump(mode="json") for node in closure))
        ).hexdigest(),
        "candidate": {
            "candidate_id": candidate_id,
            "revision": candidate_revision,
            "boundary_summary": boundary_summary,
            "required_mechanisms": required_mechanisms,
            "out_of_scope": out_of_scope,
            "candidate_sha256": pilot_candidate_binding_sha256(
                candidate_id=candidate_id,
                revision=candidate_revision,
                boundary_summary=boundary_summary,
                required_mechanisms=required_mechanisms,
                out_of_scope=out_of_scope,
            ),
            "predecessor_revision": "round-01-structural-open-formula-v1",
            "predecessor_candidate_sha256": "d" * 64,
        },
        "source": {
            "reference_manifest_sha256": reference.manifest_sha256,
            "reference_id": reference.reference_id,
            "source_artifact_sha256": reference.artifact_sha256,
            "parent_reference_id": reference.parent_reference_id,
            "parent_artifact_sha256": reference.parent_artifact_sha256,
            "anchors": anchors,
        },
        "implementation": {
            "module_name": "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK",
            "source_path": ("Library/AutoLeanLibrary/Fixtures/ModelTheory/UniversalLK.lean"),
            "source_sha256": "e" * 64,
            "declarations": (declaration,),
            "compile_chain": (
                "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK",
                "AutoLeanLibrary.Fixtures.ModelTheory.Packet",
            ),
            "compile_packet_path": "Library/records/v2/packet.json",
            "compile_packet_sha256": "f" * 64,
            "compile_packet_content_sha256": "1" * 64,
            "compile_receipt_path": "Library/records/v2/receipt.json",
            "compile_receipt_sha256": "2" * 64,
            "build_report_sha256": "3" * 64,
            "library_input_tree_sha256": "4" * 64,
        },
        "formal_profile": {
            "lean_toolchain": lean_toolchain,
            "toolchain_sha256": hashlib.sha256(lean_toolchain.encode()).hexdigest(),
            "lean_version": lean_version,
            "lean_build_identity": lean_build_identity,
            "mathlib_revision": mathlib_revision,
            "lake_manifest_sha256": lake_manifest_sha256,
            "environment_sha256": environment_sha256,
            "imports_allowlist": imports_allowlist,
            "axioms_allowlist": axioms_allowlist,
            "axiom_profile": axiom_profile.value,
            "axiom_evidence_sha256": None,
            "proof_slot_profile": proof_slot_profile,
            "allowed_write_paths": allowed_write_paths,
            "worker_image_digest": worker_image_digest,
        },
        "rule_matrix": tuple(row.model_dump(mode="json") for row in matrix),
        "rule_matrix_sha256": _v2_rule_matrix_hash(matrix),
        "agent_reviews": reviews,
        "disposition": disposition,
        "blocker_ids": blockers,
        "non_claims": tuple(item.value for item in PilotNonClaimV2),
        "authority": "automated_agent_evidence_only",
        "issued_at": "2026-07-24T00:00:00Z",
    }
    return manifest, payload


def _v2_decision() -> tuple[PilotManifestV1, PilotBoundaryDecisionV2]:
    manifest, payload = _v2_decision_payload()
    return manifest, PilotBoundaryDecisionV2.model_validate(payload)


def _v2_workspace_decision(tmp_path: Path) -> PilotBoundaryDecisionV2:
    _, payload = _v2_decision_payload()
    implementation = payload["implementation"]
    profile = payload["formal_profile"]
    assert isinstance(implementation, dict)
    assert isinstance(profile, dict)
    source_raw = b"namespace AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK\n"
    source_path = tmp_path / implementation["source_path"]
    source_path.parent.mkdir(parents=True)
    source_path.write_bytes(source_raw)
    environment = {
        "lean_toolchain": profile["lean_toolchain"],
        "mathlib_revision": profile["mathlib_revision"],
        "lake_manifest_sha256": profile["lake_manifest_sha256"],
        "build_target": implementation["compile_chain"][-1],
    }
    targets = (implementation["compile_chain"][-1],)
    build_report = {
        "source_tree_sha256": implementation["library_input_tree_sha256"],
        "mathlib_revision": profile["mathlib_revision"],
        "lake_manifest_sha256": profile["lake_manifest_sha256"],
        "toolchain": profile["lean_toolchain"],
        "lean_version": profile["lean_build_identity"],
        "status": "passed",
        "targets": targets,
        "contains_absolute_paths": False,
        "contains_raw_build_output": False,
    }
    build_report_sha256 = hashlib.sha256(canonical_json_bytes(build_report)).hexdigest()
    packet_without_backlink = {
        "environment": environment,
        "fixtures": (
            {
                "module": implementation["module_name"],
                "result": "compiled",
            },
        ),
    }
    packet_content_sha256 = hashlib.sha256(
        canonical_json_bytes(packet_without_backlink)
    ).hexdigest()
    receipt = {
        "packet_content_sha256": packet_content_sha256,
        "source_tree_sha256": implementation["library_input_tree_sha256"],
        "build_report_sha256": build_report_sha256,
        "environment": {key: value for key, value in environment.items() if key != "build_target"},
        "targets": targets,
        "build_report": build_report,
        "build_exit_code": 0,
        "contains_absolute_paths": False,
        "contains_raw_build_output": False,
    }
    receipt_raw = canonical_json_bytes(receipt)
    receipt_sha256 = hashlib.sha256(receipt_raw).hexdigest()
    packet = {
        **packet_without_backlink,
        "compile_receipt": {
            "path": implementation["compile_receipt_path"],
            "sha256": receipt_sha256,
        },
    }
    packet_raw = canonical_json_bytes(packet)
    packet_path = tmp_path / implementation["compile_packet_path"]
    receipt_path = tmp_path / implementation["compile_receipt_path"]
    packet_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    packet_path.write_bytes(packet_raw)
    receipt_path.write_bytes(receipt_raw)
    implementation.update(
        {
            "source_sha256": hashlib.sha256(source_raw).hexdigest(),
            "compile_packet_sha256": hashlib.sha256(packet_raw).hexdigest(),
            "compile_packet_content_sha256": packet_content_sha256,
            "compile_receipt_sha256": receipt_sha256,
            "build_report_sha256": build_report_sha256,
        }
    )
    return PilotBoundaryDecisionV2.model_validate(payload)


def test_v2_gap_decision_binds_manifest_target_and_profile() -> None:
    manifest, decision = _v2_decision()
    decision.assert_binds_manifest(manifest)
    assert decision.disposition.value == "gap"
    assert decision.blocker_ids

    changed_worker = "sha256:" + "9" * 64
    changed_environment = pilot_formal_environment_sha256(
        lean_toolchain=decision.formal_profile.lean_toolchain,
        lean_version=decision.formal_profile.lean_version,
        lean_build_identity=decision.formal_profile.lean_build_identity,
        mathlib_revision=decision.formal_profile.mathlib_revision,
        lake_manifest_sha256=decision.formal_profile.lake_manifest_sha256,
        imports_allowlist=decision.formal_profile.imports_allowlist,
        axioms_allowlist=decision.formal_profile.axioms_allowlist,
        axiom_profile=decision.formal_profile.axiom_profile,
        proof_slot_profile=decision.formal_profile.proof_slot_profile,
        allowed_write_paths=decision.formal_profile.allowed_write_paths,
        worker_image_digest=changed_worker,
    )
    changed_profile = decision.formal_profile.model_copy(
        update={
            "worker_image_digest": changed_worker,
            "environment_sha256": changed_environment,
        }
    )
    changed_decision = decision.model_copy(
        update={
            "formal_profile": changed_profile,
        }
    )
    assert changed_decision.canonical_sha256() != decision.canonical_sha256()


def test_v2_decision_rejects_manifest_and_target_drift() -> None:
    manifest, decision = _v2_decision()
    changed_manifest_payload = manifest.model_dump(mode="python")
    changed_manifest_payload["graphs"][1]["domain"] = "changed model-theory graph"
    changed_manifest = PilotManifestV1.model_validate(changed_manifest_payload)

    with pytest.raises(PilotHarnessError, match="another pilot manifest"):
        decision.assert_binds_manifest(changed_manifest)

    changed_target = decision.model_copy(update={"target_node_id": "mt-syntax-definition"})
    with pytest.raises(PilotHarnessError, match="target closure changed"):
        changed_target.assert_binds_manifest(manifest)


@pytest.mark.parametrize("disposition", ("gap", "backup"))
def test_v2_boundary_records_are_non_admitting_gap_or_backup(disposition: str) -> None:
    _, payload = _v2_decision_payload(disposition=disposition)
    decision = PilotBoundaryDecisionV2.model_validate(payload)

    assert decision.disposition.value == disposition
    assert decision.blocker_ids


def test_v2_boundary_record_rejects_admission_disposition() -> None:
    _, payload = _v2_decision_payload()
    payload["disposition"] = "eligible_for_operator_admission"

    with pytest.raises(ValueError, match="disposition"):
        PilotBoundaryDecisionV2.model_validate(payload)


@pytest.mark.parametrize(
    "field",
    ("context_pack_sha256", "output_sha256", "execution_run_receipt_sha256"),
)
def test_v2_agent_review_requires_context_output_and_run_receipt(field: str) -> None:
    _, payload = _v2_decision_payload()
    del payload["agent_reviews"][0][field]

    with pytest.raises(ValueError, match=field):
        PilotBoundaryDecisionV2.model_validate(payload)


def test_v2_agent_review_cannot_claim_human_or_expert_authority() -> None:
    _, payload = _v2_decision_payload()
    payload["agent_reviews"][0]["reviewer_kind"] = "human"

    with pytest.raises(ValueError, match="automated_agent"):
        PilotBoundaryDecisionV2.model_validate(payload)

    _, payload = _v2_decision_payload()
    payload["agent_reviews"][0]["claims_human_or_expert_authority"] = True
    with pytest.raises(ValueError, match="False"):
        PilotBoundaryDecisionV2.model_validate(payload)


@pytest.mark.parametrize("field", ("reviewer_id", "independence_group"))
def test_v2_agent_reviews_require_distinct_identities_and_groups(field: str) -> None:
    _, payload = _v2_decision_payload()
    payload["agent_reviews"][1][field] = payload["agent_reviews"][0][field]

    with pytest.raises(ValueError, match=r"identities|independence groups"):
        PilotBoundaryDecisionV2.model_validate(payload)


def test_v2_gap_decision_requires_all_nonclaims() -> None:
    _, payload = _v2_decision_payload()
    payload["non_claims"] = payload["non_claims"][:-1]
    with pytest.raises(ValueError, match="required non-claims"):
        PilotBoundaryDecisionV2.model_validate(payload)


def test_v2_rule_matrix_hash_and_references_fail_closed() -> None:
    _, payload = _v2_decision_payload()
    payload["rule_matrix_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="hash does not bind"):
        PilotBoundaryDecisionV2.model_validate(payload)

    _, payload = _v2_decision_payload()
    payload["rule_matrix"][0]["implementation_declarations"] = ("Unbound.declaration",)
    rows = tuple(PilotRuleMatrixEntryV2.model_validate(row) for row in payload["rule_matrix"])
    payload["rule_matrix_sha256"] = _v2_rule_matrix_hash(rows)
    with pytest.raises(ValueError, match="unbound implementation declaration"):
        PilotBoundaryDecisionV2.model_validate(payload)


def test_v2_gap_rebinds_pending_v1_manifest_without_axiom_evidence() -> None:
    pending_manifest = _manifest()
    _, payload = _v2_decision_payload(disposition="gap", manifest=pending_manifest)
    decision = PilotBoundaryDecisionV2.model_validate(payload)

    decision.assert_binds_manifest(pending_manifest)
    assert decision.formal_profile.axiom_evidence_sha256 is None


def test_v2_candidate_and_environment_hashes_reject_inline_drift() -> None:
    _, payload = _v2_decision_payload()
    payload["candidate"]["boundary_summary"] = "Changed without recomputing the candidate hash."
    with pytest.raises(ValueError, match="candidate hash"):
        PilotBoundaryDecisionV2.model_validate(payload)

    _, payload = _v2_decision_payload()
    payload["formal_profile"]["lean_version"] = "v4.28.1"
    with pytest.raises(ValueError, match="environment hash"):
        PilotBoundaryDecisionV2.model_validate(payload)


def test_v2_manifest_binding_accepts_located_granular_anchors_only() -> None:
    manifest, payload = _v2_decision_payload()
    granular = {
        "anchor_id": "mt-forall-right-side-condition",
        "start_offset": 100,
        "end_offset": 120,
        "raw_sha256": "9" * 64,
        "human_locator": "SLC 2026-07-12, Definition 10.3, forall-right clause",
    }
    payload["source"]["anchors"] = (*payload["source"]["anchors"], granular)
    rows = (
        *(PilotRuleMatrixEntryV2.model_validate(row) for row in payload["rule_matrix"]),
        PilotRuleMatrixEntryV2(
            rule_id="rule-mt-forall-right-side-condition",
            source_anchor_ids=("mt-forall-right-side-condition",),
            implementation_declarations=(
                "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Deriv.closed_sound",
            ),
            coverage_state=PilotRuleCoverageStateV2.DELIBERATE_SUBSET,
            rationale="Synthetic granular-anchor fixture.",
        ),
    )
    payload["rule_matrix"] = tuple(row.model_dump(mode="json") for row in rows)
    payload["rule_matrix_sha256"] = _v2_rule_matrix_hash(rows)
    decision = PilotBoundaryDecisionV2.model_validate(payload)
    decision.assert_binds_manifest(manifest)

    payload["source"]["anchors"][-1]["human_locator"] = None
    unlocated = PilotBoundaryDecisionV2.model_validate(payload)
    with pytest.raises(PilotHarnessError, match="require a human locator"):
        unlocated.assert_binds_manifest(manifest)


def test_v2_rule_matrix_can_record_an_unimplemented_blocking_gap() -> None:
    PilotRuleMatrixEntryV2(
        rule_id="missing-exists-right",
        source_anchor_ids=("mt-exists-right",),
        implementation_declarations=(),
        coverage_state=PilotRuleCoverageStateV2.BLOCKING_GAP,
        rationale="No declaration implements this rule.",
    )
    with pytest.raises(ValueError, match="requires an implementation declaration"):
        PilotRuleMatrixEntryV2(
            rule_id="fake-exact",
            source_anchor_ids=("mt-exists-right",),
            implementation_declarations=(),
            coverage_state=PilotRuleCoverageStateV2.EXACT,
            rationale="An exact claim cannot omit its declaration.",
        )


def test_v2_workspace_evidence_recomputes_files_and_internal_receipt(tmp_path: Path) -> None:
    decision = _v2_workspace_decision(tmp_path)
    decision.assert_matches_workspace(tmp_path)

    wrong_hash = decision.implementation.model_copy(update={"source_sha256": "0" * 64})
    with pytest.raises(PilotHarnessError, match="source digest"):
        wrong_hash.assert_matches_workspace(tmp_path)

    missing_packet = decision.implementation.model_copy(
        update={"compile_packet_path": "Library/records/v2/missing.json"}
    )
    with pytest.raises(PilotHarnessError, match="absent from workspace"):
        missing_packet.assert_matches_workspace(tmp_path)


@pytest.mark.parametrize("raw", (b"{", b"\xff"))
def test_v2_workspace_evidence_classifies_invalid_utf8_json(tmp_path: Path, raw: bytes) -> None:
    decision = _v2_workspace_decision(tmp_path)
    packet_path = tmp_path / decision.implementation.compile_packet_path
    packet_path.write_bytes(raw)
    implementation = decision.implementation.model_copy(
        update={"compile_packet_sha256": hashlib.sha256(raw).hexdigest()}
    )

    with pytest.raises(PilotHarnessError, match="V2 compile packet is not valid UTF-8 JSON"):
        implementation.assert_matches_workspace(tmp_path)


def test_v2_workspace_evidence_keeps_duplicate_keys_ambiguous(tmp_path: Path) -> None:
    decision = _v2_workspace_decision(tmp_path)
    raw = b'{"duplicate":1,"duplicate":2}'
    packet_path = tmp_path / decision.implementation.compile_packet_path
    packet_path.write_bytes(raw)
    implementation = decision.implementation.model_copy(
        update={"compile_packet_sha256": hashlib.sha256(raw).hexdigest()}
    )

    with pytest.raises(
        PilotHarnessError,
        match="V2 compile packet is ambiguous: duplicate JSON evidence key",
    ):
        implementation.assert_matches_workspace(tmp_path)


def test_v2_replays_the_retained_t2_compile_evidence() -> None:
    _, payload = _v2_decision_payload(disposition="gap")
    lean_toolchain = "leanprover/lean4:v4.28.0"
    lean_version = "v4.28.0"
    lean_build_identity = (
        "Lean (version 4.28.0, x86_64-unknown-linux-gnu, "
        "commit 7e01a1bf5c70fc6167d49c345d3bf80596e9a79b, Release)"
    )
    mathlib_revision = "8f9d9cff6bd728b17a24e163c9402775d9e6a365"
    lake_manifest_sha256 = "e2a93c904f51195d6740cd9abfb35ab155dc0157e0e46642dce0d364b68a9a89"
    imports_allowlist = ("Mathlib.ModelTheory.Semantics",)
    axioms_allowlist: tuple[str, ...] = ()
    worker_image_digest = "sha256:83daaa542ee407c0fbb1ba93f2a0b40fde1621cc5ad2e689ab7d5392b76d03ff"
    environment_sha256 = pilot_formal_environment_sha256(
        lean_toolchain=lean_toolchain,
        lean_version=lean_version,
        lean_build_identity=lean_build_identity,
        mathlib_revision=mathlib_revision,
        lake_manifest_sha256=lake_manifest_sha256,
        imports_allowlist=imports_allowlist,
        axioms_allowlist=axioms_allowlist,
        axiom_profile=AxiomProfileV1.STRICT,
        proof_slot_profile="lean-exact-declaration-boundary.v1",
        allowed_write_paths=("Proof.lean",),
        worker_image_digest=worker_image_digest,
    )
    payload["implementation"] = {
        "module_name": "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK",
        "source_path": "Library/AutoLeanLibrary/Fixtures/ModelTheory/UniversalLK.lean",
        "source_sha256": "8788fafb3dde2ae0d2fa574b81984658e76adacf99770508000fd11cad500a3b",
        "declarations": ("AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Deriv.closed_sound",),
        "compile_chain": (
            "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK",
            "AutoLeanLibrary.Fixtures.ModelTheory.Packet",
        ),
        "compile_packet_path": (
            "Library/records/staging/round-01-model-theory-compile-spike/packet.v1.json"
        ),
        "compile_packet_sha256": (
            "d58b0d7964c031438e89f28e4c6f627463e72a6272ec115d6d27e3c54110b065"
        ),
        "compile_packet_content_sha256": (
            "c8cff937a896804f8fa2d48232200e3153f14d33174b2e00aee16a963c6ecb36"
        ),
        "compile_receipt_path": (
            "Library/records/staging/round-01-model-theory-compile-spike/compile-receipt.v2.json"
        ),
        "compile_receipt_sha256": (
            "5e2d0b9d119582f42dc4434eeedd067f19f5b82cac9f42f5ac17ccaed09312e3"
        ),
        "build_report_sha256": ("79325354563c19c5b32134f5102f964c11a738444a68746e85c8d03f5ab92c15"),
        "library_input_tree_sha256": (
            "87890952359a75d408505ed6f4462720cdb8a3f82cc80dd783f99d34585fac70"
        ),
    }
    payload["formal_profile"] = {
        "lean_toolchain": lean_toolchain,
        "toolchain_sha256": hashlib.sha256(lean_toolchain.encode()).hexdigest(),
        "lean_version": lean_version,
        "lean_build_identity": lean_build_identity,
        "mathlib_revision": mathlib_revision,
        "lake_manifest_sha256": lake_manifest_sha256,
        "environment_sha256": environment_sha256,
        "imports_allowlist": imports_allowlist,
        "axioms_allowlist": axioms_allowlist,
        "axiom_profile": AxiomProfileV1.STRICT.value,
        "axiom_evidence_sha256": None,
        "proof_slot_profile": "lean-exact-declaration-boundary.v1",
        "allowed_write_paths": ("Proof.lean",),
        "worker_image_digest": worker_image_digest,
    }
    decision = PilotBoundaryDecisionV2.model_validate(payload)

    decision.assert_matches_workspace(_ROOT)


def test_v2_decision_loader_rejects_duplicate_keys(tmp_path: Path) -> None:
    _, decision = _v2_decision()
    path = tmp_path / "decision.json"
    path.write_bytes(canonical_json_bytes(decision))
    assert load_pilot_boundary_decision(path) == decision

    path.write_text(
        '{"schema_version":"autolean.pilot-boundary-decision.v2",'
        '"schema_version":"autolean.pilot-boundary-decision.v2"}',
        encoding="utf-8",
    )
    with pytest.raises(PilotHarnessError, match="duplicate JSON key"):
        load_pilot_boundary_decision(path)


@pytest.mark.parametrize("raw", (b"{", b"\xff"))
def test_v2_decision_loader_classifies_invalid_utf8_json(tmp_path: Path, raw: bytes) -> None:
    path = tmp_path / "decision.json"
    path.write_bytes(raw)

    with pytest.raises(PilotHarnessError, match="not valid UTF-8 JSON"):
        load_pilot_boundary_decision(path)


def test_v2_granular_anchor_rechecks_exact_cached_bytes() -> None:
    expected_text = _CACHE_ROOT / "openlogic-sets-logic-computation-2026-07-12-text"
    if not expected_text.exists():
        pytest.skip("official local SLC cache is intentionally absent")
    cache = ReferenceCache(
        ReferenceManifestV1.load(_REFERENCE_MANIFEST),
        _CACHE_ROOT,
        confinement_root=_ROOT,
    )
    _, payload = _v2_decision_payload()
    first_anchor = dict(payload["source"]["anchors"][0])
    first_anchor.update(
        {
            "anchor_id": "mt-granular-cache-recheck",
            "human_locator": "SLC 2026-07-12, duplicated test span",
        }
    )
    payload["source"]["anchors"] = (*payload["source"]["anchors"], first_anchor)
    rows = (
        *(PilotRuleMatrixEntryV2.model_validate(row) for row in payload["rule_matrix"]),
        PilotRuleMatrixEntryV2(
            rule_id="rule-mt-granular-cache-recheck",
            source_anchor_ids=("mt-granular-cache-recheck",),
            implementation_declarations=(
                "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Deriv.closed_sound",
            ),
            coverage_state=PilotRuleCoverageStateV2.EXACT,
            rationale="Exercise V2-only span revalidation.",
        ),
    )
    payload["rule_matrix"] = tuple(row.model_dump(mode="json") for row in rows)
    payload["rule_matrix_sha256"] = _v2_rule_matrix_hash(rows)
    decision = PilotBoundaryDecisionV2.model_validate(payload)
    decision.assert_matches_reference_cache(cache)

    bad_anchor = decision.source.anchors[-1].model_copy(update={"raw_sha256": "0" * 64})
    bad_source = decision.source.model_copy(
        update={"anchors": (*decision.source.anchors[:-1], bad_anchor)}
    )
    bad_decision = decision.model_copy(update={"source": bad_source})
    with pytest.raises(PilotHarnessError, match="no longer binds"):
        bad_decision.assert_matches_reference_cache(cache)
