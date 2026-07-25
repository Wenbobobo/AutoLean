from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

import pytest
from autolean_builder import (
    ReferenceCache,
    ReferenceManifestV1,
    load_pilot_manifest,
)
from autolean_builder.pilot_harness import (
    PilotBoundaryDispositionV2,
    PilotRuleCoverageStateV2,
    load_pilot_boundary_decision,
)
from autolean_contracts import canonical_json_bytes

_ROOT = Path(__file__).parents[2]
_ADMISSION_ROOT = _ROOT / "Builder" / "pilots" / "model-theory-admission"
_DECISION_PATH = _ADMISSION_ROOT / "decision.v2.json"
_REVIEW_PATH = _ADMISSION_ROOT / "review-evidence.v2.json"
_MATRIX_PATH = _ADMISSION_ROOT / "source-rule-matrix.v2.json"
_T4_ATTACHMENT_PATH = _ADMISSION_ROOT / "t4-exact-image-attachment.v1.json"
_T4_QUERY_PATH = _ADMISSION_ROOT / "t4-declaration-query.v1.json"
_PILOT_MANIFEST_PATH = _ROOT / "Builder" / "pilots" / "self-calibration" / "pilot-manifest.v1.json"
_REFERENCE_MANIFEST_PATH = _ROOT / "Builder" / "references" / "manifest.v1.json"
_REFERENCE_CACHE_ROOT = _ROOT / ".cache" / "references"
_SOURCE_REFERENCE_ID = "openlogic-sets-logic-computation-2026-07-12-text"


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _oci_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value) + b"\n").hexdigest()


def _load_json_object(path: Path) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    value = json.loads(path.read_bytes(), object_pairs_hook=reject_duplicates)
    assert isinstance(value, dict)
    return value


def test_committed_gap_decision_replays_manifest_and_workspace() -> None:
    decision = load_pilot_boundary_decision(_DECISION_PATH)
    manifest = load_pilot_manifest(_PILOT_MANIFEST_PATH)

    decision.assert_binds_manifest(manifest)
    decision.assert_matches_workspace(_ROOT)

    assert decision.disposition is PilotBoundaryDispositionV2.GAP
    assert decision.candidate.candidate_id == "model-theory-closed-level-indexed-fragment"
    assert decision.candidate.revision == "t3-boundary-v2"
    assert decision.candidate.predecessor_candidate_sha256 == (
        "dd5e6b59c6683eb8adc844cb783cc149a3f0d9a0afafd84c5e7942ef06d35181"
    )
    assert decision.formal_profile.imports_allowlist == ("Mathlib.ModelTheory.Semantics",)
    assert decision.formal_profile.axiom_profile.value == "strict"
    assert decision.formal_profile.axiom_evidence_sha256 is None
    assert decision.formal_profile.lean_build_identity == (
        "Lean (version 4.28.0, x86_64-unknown-linux-gnu, "
        "commit 7e01a1bf5c70fc6167d49c345d3bf80596e9a79b, Release)"
    )
    assert decision.formal_profile.allowed_write_paths == ("Proof.lean",)
    assert decision.formal_profile.worker_image_digest == (
        "sha256:83daaa542ee407c0fbb1ba93f2a0b40fde1621cc5ad2e689ab7d5392b76d03ff"
    )
    assert {anchor.anchor_id for anchor in decision.source.anchors} == {
        "mt-terms-formulas",
        "mt-satisfaction",
        "mt-sequent-calculus",
        "mt-sequent-soundness",
    }

    rows = {row.rule_id: row for row in decision.rule_matrix}
    for rule_id in (
        "existential-left",
        "existential-right",
        "structural-rules-and-cut",
        "other-connective-rules",
    ):
        assert rows[rule_id].coverage_state is PilotRuleCoverageStateV2.BLOCKING_GAP
        assert rows[rule_id].implementation_declarations == ()
    assert not (_ADMISSION_ROOT / "admission-receipt.v2.json").exists()


def test_t4_exact_image_attachment_replays_query_and_keeps_gap_open() -> None:
    decision = load_pilot_boundary_decision(_DECISION_PATH)
    attachment = _load_json_object(_T4_ATTACHMENT_PATH)

    assert set(attachment) == {
        "artifact_kind",
        "authority_boundary",
        "compatibility",
        "decision_binding",
        "execution_binding",
        "observation_summary",
        "query_evidence_binding",
        "schema_version",
        "source_binding",
    }
    assert attachment["schema_version"] == "autolean.public-t4-exact-image-attachment.v1"
    assert attachment["artifact_kind"] == "public_safe_t4_gap_attachment"

    decision_binding = attachment["decision_binding"]
    assert isinstance(decision_binding, dict)
    assert decision_binding == {
        "decision_path": "Builder/pilots/model-theory-admission/decision.v2.json",
        "decision_canonical_sha256": decision.canonical_sha256(),
        "candidate_id": decision.candidate.candidate_id,
        "candidate_revision": decision.candidate.revision,
        "candidate_sha256": decision.candidate.candidate_sha256,
        "t3_disposition": "gap",
        "selection": "not_selected",
        "statement_contract": "not_frozen",
    }

    query_binding = attachment["query_evidence_binding"]
    assert isinstance(query_binding, dict)
    assert query_binding["path"] == (
        "Builder/pilots/model-theory-admission/t4-declaration-query.v1.json"
    )
    query_bytes = _T4_QUERY_PATH.read_bytes()
    assert len(query_bytes) == query_binding["size_bytes"] == 158805
    assert hashlib.sha256(query_bytes).hexdigest() == query_binding["sha256"]
    assert query_binding["sha256"] == (
        "167d7a1ede245bfa631c46651b5eb0502d758b8d966d6f4c494fdcb2d75df42a"
    )

    query = _load_json_object(_T4_QUERY_PATH)
    assert set(query) == {
        "build_receipt_canonical_sha256",
        "execution_policy",
        "execution_policy_sha256",
        "image",
        "observation",
        "schema_version",
        "sealed_candidate_sha256",
        "source_inputs_sha256",
        "source_snapshot_sha256",
    }
    assert query["schema_version"] == query_binding["schema_version"]
    assert query["schema_version"] == "autolean.mathlib-declaration-query-evidence.v1"
    assert query["execution_policy_sha256"] == _oci_sha256(query["execution_policy"])
    observation = query["observation"]
    assert isinstance(observation, dict)
    image_identity = observation["image_identity"]
    assert isinstance(image_identity, dict)

    source_binding = attachment["source_binding"]
    assert isinstance(source_binding, dict)
    assert source_binding == {
        "source_path": decision.implementation.source_path,
        "decision_source_sha256": decision.implementation.source_sha256,
        "query_source_snapshot_sha256": query["source_snapshot_sha256"],
        "source_snapshot_matches_decision": True,
        "source_inputs_sha256": query["source_inputs_sha256"],
    }
    source_path = _ROOT / decision.implementation.source_path
    assert hashlib.sha256(source_path.read_bytes()).hexdigest() == query["source_snapshot_sha256"]

    execution_binding = attachment["execution_binding"]
    assert isinstance(execution_binding, dict)
    assert execution_binding["worker_image"] == query["image"]
    assert execution_binding["worker_image_digest"] == str(query["image"]).split("@", 1)[1]
    assert (
        execution_binding["build_receipt_canonical_sha256"]
        == query["build_receipt_canonical_sha256"]
    )
    assert execution_binding["execution_policy_sha256"] == query["execution_policy_sha256"]
    assert execution_binding["image_owned_query_identity_sha256"] == _oci_sha256(image_identity)
    assert execution_binding["query_helper_source_sha256"] == image_identity["query_helper_sha256"]
    assert execution_binding["query_wrapper_sha256"] == image_identity["wrapper_sha256"]
    assert execution_binding["sealed_candidate_sha256"] == query["sealed_candidate_sha256"]
    assert execution_binding["operator_local_artifacts_committed"] is False
    for field in (
        "operator_local_build_evidence_sha256",
        "operator_local_canary_evidence_sha256",
    ):
        digest = execution_binding[field]
        assert isinstance(digest, str)
        assert len(digest) == 64
        int(digest, 16)

    local_evidence = {
        "operator_local_build_evidence_sha256": (
            _ROOT / "release-evidence" / "oci-worker" / "mathlib-build.v1.json"
        ),
        "operator_local_canary_evidence_sha256": (
            _ROOT / "release-evidence" / "oci-worker" / "mathlib-canary.v1.json"
        ),
    }
    for field, path in local_evidence.items():
        if path.exists():
            assert hashlib.sha256(path.read_bytes()).hexdigest() == execution_binding[field]

    assert set(observation) == {
        "candidate_direct_imports",
        "candidate_direct_imports_sha256",
        "declarations",
        "image_identity",
        "module_import_closure",
        "module_import_closure_sha256",
    }
    direct_imports = observation["candidate_direct_imports"]
    import_closure = observation["module_import_closure"]
    declarations = observation["declarations"]
    assert isinstance(direct_imports, list)
    assert isinstance(import_closure, list)
    assert isinstance(declarations, list)
    assert direct_imports == sorted(set(direct_imports))
    assert import_closure == sorted(set(import_closure))
    assert set(direct_imports) <= set(import_closure)
    assert "Candidate" in import_closure
    assert observation["candidate_direct_imports_sha256"] == _oci_sha256(direct_imports)
    assert observation["module_import_closure_sha256"] == _oci_sha256(import_closure)

    expected_declarations = sorted(decision.implementation.declarations)
    observed_declarations: list[str] = []
    axiom_distribution: Counter[tuple[str, ...]] = Counter()
    records_by_name: dict[str, dict[str, object]] = {}
    for raw_record in declarations:
        assert isinstance(raw_record, dict)
        assert set(raw_record) == {
            "canonical_type",
            "canonical_type_sha256",
            "declaration",
            "observed_axioms",
            "observed_axioms_sha256",
        }
        declaration = raw_record["declaration"]
        canonical_type = raw_record["canonical_type"]
        axioms = raw_record["observed_axioms"]
        assert isinstance(declaration, str)
        assert isinstance(canonical_type, str) and canonical_type
        assert isinstance(axioms, list)
        assert all(isinstance(axiom, str) for axiom in axioms)
        assert axioms == sorted(set(axioms))
        assert (
            hashlib.sha256(canonical_type.encode("utf-8")).hexdigest()
            == raw_record["canonical_type_sha256"]
        )
        assert _oci_sha256(axioms) == raw_record["observed_axioms_sha256"]
        observed_declarations.append(declaration)
        axiom_distribution[tuple(axioms)] += 1
        records_by_name[declaration] = raw_record

    assert observed_declarations == expected_declarations
    assert len(records_by_name) == len(observed_declarations) == 46
    assert axiom_distribution == Counter(
        {
            (): 5,
            ("propext",): 1,
            ("Quot.sound",): 6,
            ("Quot.sound", "propext"): 29,
            ("Classical.choice", "Quot.sound", "propext"): 5,
        }
    )

    summary = attachment["observation_summary"]
    assert isinstance(summary, dict)
    assert summary["declaration_count"] == len(observed_declarations)
    assert summary["declaration_names_sha256"] == _oci_sha256(observed_declarations)
    assert summary["declaration_records_sha256"] == _oci_sha256(declarations)
    assert summary["decision_declaration_set_match"] is True
    assert summary["canonical_types_and_axioms_retained_in_query_artifact"] is True
    assert summary["candidate_direct_imports"] == direct_imports
    assert (
        summary["candidate_direct_imports_sha256"] == observation["candidate_direct_imports_sha256"]
    )
    assert summary["module_import_closure_count"] == len(import_closure) == 2744
    assert summary["module_import_closure_sha256"] == observation["module_import_closure_sha256"]

    summary_distribution: Counter[tuple[str, ...]] = Counter()
    raw_summary_distribution = summary["axiom_distribution"]
    assert isinstance(raw_summary_distribution, list)
    for raw_row in raw_summary_distribution:
        assert isinstance(raw_row, dict)
        axioms = raw_row["observed_axioms"]
        count = raw_row["declaration_count"]
        assert isinstance(axioms, list)
        assert all(isinstance(axiom, str) for axiom in axioms)
        assert isinstance(count, int)
        summary_distribution[tuple(axioms)] = count
    assert summary_distribution == axiom_distribution

    closed_sound = summary["closed_sound_declaration"]
    assert isinstance(closed_sound, str)
    assert (
        records_by_name[closed_sound]["observed_axioms"] == summary["closed_sound_observed_axioms"]
    )

    compatibility = attachment["compatibility"]
    assert isinstance(compatibility, dict)
    assert compatibility == {
        "decision_worker_image_matches_observation": False,
        "decision_imports_allowlist_matches_direct_imports": False,
        "init_import_treatment_requires_explicit_resolution": True,
        "decision_strict_empty_axiom_profile_matches_observation": False,
        "observed_nonempty_axiom_declaration_count": 41,
        "declaration_specific_evidence_missing_closed": True,
        "effect_on_t3": "gap_remains_open",
    }
    assert decision.formal_profile.worker_image_digest != execution_binding["worker_image_digest"]
    assert list(decision.formal_profile.imports_allowlist) != direct_imports
    assert decision.formal_profile.axioms_allowlist == ()
    assert sum(count for axioms, count in axiom_distribution.items() if axioms) == 41

    authority = attachment["authority_boundary"]
    assert isinstance(authority, dict)
    assert set(authority) == {
        "authenticated_independence_present",
        "builder_admission_authority_present",
        "expert_review_present",
        "human_review_present",
        "may_change_boundary_decision",
        "may_claim_open_problem_progress",
        "may_freeze_statement",
        "may_handoff_to_prover",
        "may_issue_admission_receipt",
        "may_promote",
    }
    assert authority and all(value is False for value in authority.values())
    assert decision.disposition is PilotBoundaryDispositionV2.GAP
    assert not (_ADMISSION_ROOT / "admission-receipt.v2.json").exists()


def test_review_evidence_recomputes_subobject_and_public_matrix_hashes() -> None:
    decision = load_pilot_boundary_decision(_DECISION_PATH)
    evidence = _load_json_object(_REVIEW_PATH)
    public_matrix_sha256 = hashlib.sha256(_MATRIX_PATH.read_bytes()).hexdigest()

    assert evidence["public_source_rule_matrix_sha256"] == public_matrix_sha256
    assert evidence["contains_source_excerpt"] is False
    assert evidence["contains_local_cache_path"] is False
    assert evidence["contains_prompt_or_raw_log"] is False
    assert "historical report digest may differ" in evidence["report_context_policy"]
    authority = evidence["authority_boundary"]
    assert isinstance(authority, dict)
    assert authority == {
        "human_review_present": False,
        "expert_review_present": False,
        "authenticated_independence_present": False,
        "operator_admission_authority_present": False,
        "may_issue_admission_receipt": False,
    }

    reports = evidence["reports"]
    assert isinstance(reports, list)
    assert {report["role"] for report in reports if isinstance(report, dict)} == {
        "source_interpreter",
        "adversarial_reviewer",
    }
    reports_by_role = {report["role"]: report for report in reports if isinstance(report, dict)}
    reviews_by_role = {review.role.value: review for review in decision.agent_reviews}
    assert reports_by_role.keys() == reviews_by_role.keys()

    for role, report in reports_by_role.items():
        review = reviews_by_role[role]
        context_pack = report["context_pack"]
        output = report["output"]
        run_receipt = report["execution_run_receipt"]
        assert isinstance(context_pack, dict)
        assert isinstance(output, dict)
        assert isinstance(run_receipt, dict)
        assert report["reviewer_id"] == review.reviewer_id
        assert report["reviewer_kind"] == review.reviewer_kind
        assert report["independence_group"] == review.independence_group
        assert report["review_state"] == review.review_state.value
        assert report["claims_human_or_expert_authority"] is False
        reviewed_matrix_sha256 = context_pack["public_source_rule_matrix_sha256"]
        assert isinstance(reviewed_matrix_sha256, str)
        assert len(reviewed_matrix_sha256) == 64
        int(reviewed_matrix_sha256, 16)
        assert review.context_pack_sha256 == _sha256(context_pack)
        assert review.output_sha256 == _sha256(output)
        assert review.execution_run_receipt_sha256 == _sha256(run_receipt)
        assert output["claims_human_or_expert_authority"] is False
        assert output["contains_source_excerpt"] is False
        assert run_receipt["network_used"] is False
        assert run_receipt["source_text_emitted"] is False
        assert run_receipt["raw_log_retained"] is False
        if "output_artifact_sha256" in run_receipt:
            assert run_receipt["output_artifact_sha256"] == reviewed_matrix_sha256


def test_public_rule_matrix_is_a_complete_projection_of_the_gap_decision() -> None:
    decision = load_pilot_boundary_decision(_DECISION_PATH)
    public = _load_json_object(_MATRIX_PATH)
    candidate = public["candidate"]
    source = public["source_binding"]
    disposition = public["disposition"]
    authority = public["authority_boundary"]
    assert isinstance(candidate, dict)
    assert isinstance(source, dict)
    assert isinstance(disposition, dict)
    assert isinstance(authority, dict)
    assert candidate["candidate_id"] == decision.candidate.candidate_id
    assert candidate["candidate_revision"] == decision.candidate.revision
    assert source["derived_text_reference_id"] == decision.source.reference_id
    assert source["derived_text_sha256"] == decision.source.source_artifact_sha256
    assert source["source_reference_id"] == decision.source.parent_reference_id
    assert source["source_pdf_sha256"] == decision.source.parent_artifact_sha256
    assert source["reference_manifest_sha256"] == decision.source.reference_manifest_sha256
    assert disposition == {
        "t3_admission": decision.disposition.value,
        "selection": "not_selected",
        "statement_contract": "not_frozen",
        "prover_handoff": "forbidden",
        "promotion": "forbidden",
        "open_problem_claim": "forbidden",
    }
    assert authority == {
        "record_kind": "automated_technical_cross_check",
        "human_review_present": False,
        "expert_review_present": False,
        "builder_admission_authority_present": False,
        "may_issue_admission_receipt": False,
    }

    public_anchors = public["coarse_source_anchors"]
    assert isinstance(public_anchors, list)
    public_anchors_by_id = {
        anchor["anchor_id"]: anchor for anchor in public_anchors if isinstance(anchor, dict)
    }
    assert public_anchors_by_id.keys() == {anchor.anchor_id for anchor in decision.source.anchors}
    for anchor in decision.source.anchors:
        public_anchor = public_anchors_by_id[anchor.anchor_id]
        assert public_anchor["start_offset"] == anchor.start_offset
        assert public_anchor["end_offset"] == anchor.end_offset
        assert public_anchor["raw_sha256"] == anchor.raw_sha256
        assert public_anchor["human_locator"] == anchor.human_locator

    public_rows = public["rule_matrix"]
    assert isinstance(public_rows, list)

    decision_by_id = {row.rule_id: row for row in decision.rule_matrix}
    public_by_id = {row["matrix_id"]: row for row in public_rows if isinstance(row, dict)}
    assert public_by_id.keys() == decision_by_id.keys()

    state_projection = {"blocking_gap": "missing"}
    for rule_id, decision_row in decision_by_id.items():
        public_row = public_by_id[rule_id]
        assert public_row["status"] == state_projection.get(
            decision_row.coverage_state.value,
            decision_row.coverage_state.value,
        )
        public_declarations = public_row["universal_lk_declarations"]
        assert isinstance(public_declarations, list)
        assert all(isinstance(item, str) for item in public_declarations)
        assert all(
            any(
                full == short or full.endswith(f".{short}")
                for full in decision_row.implementation_declarations
            )
            for short in public_declarations
        )
        assert all(
            any(full == short or full.endswith(f".{short}") for short in public_declarations)
            for full in decision_row.implementation_declarations
        )


def test_cached_source_anchors_replay_only_when_local_cache_exists() -> None:
    cached_text = _REFERENCE_CACHE_ROOT / _SOURCE_REFERENCE_ID
    if not cached_text.exists():
        pytest.skip("official local SLC cache is intentionally absent")

    cache = ReferenceCache(
        ReferenceManifestV1.load(_REFERENCE_MANIFEST_PATH),
        _REFERENCE_CACHE_ROOT,
        confinement_root=_ROOT,
    )
    load_pilot_boundary_decision(_DECISION_PATH).assert_matches_reference_cache(cache)
