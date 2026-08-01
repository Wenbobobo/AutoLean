"""Build and verify the non-authoritative model-theory T3 machine review packet.

The packet is a deterministic cross-check of already retained public evidence.  It is not a
model execution, a machine quorum result, semantic admission, or a successor decision.  In
particular, it cannot change the immutable ``decision.v2.json`` gap boundary.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from autolean_contracts import canonical_json_bytes

from .machine_semantic_quorum import (
    MachineSemanticQuorumPolicy,
    MachineSemanticReviewRole,
)

SCHEMA_VERSION = "autolean.model-theory-t3-machine-review-packet.v1"
ARTIFACT_KIND = "public_safe_non_authoritative_machine_review_packet"
PACKET_RELATIVE_PATH = Path("Builder/pilots/model-theory-admission/machine-review/packet.v1.json")
DECISION_RELATIVE_PATH = Path("Builder/pilots/model-theory-admission/decision.v2.json")
SOURCE_MATRIX_RELATIVE_PATH = Path(
    "Builder/pilots/model-theory-admission/source-rule-matrix.v2.json"
)
FINE_SPANS_RELATIVE_PATH = Path("Builder/pilots/model-theory-admission/fine-source-spans.v2.json")
T4_ATTACHMENT_RELATIVE_PATH = Path(
    "Builder/pilots/model-theory-admission/t4-exact-image-attachment.v1.json"
)
T4_QUERY_RELATIVE_PATH = Path("Builder/pilots/model-theory-admission/t4-declaration-query.v1.json")
HUMAN_PACKET_RELATIVE_PATH = Path(
    "Builder/pilots/model-theory-admission/human-review/packet.v1.json"
)
PENDING_REVIEW_RELATIVE_PATH = Path("Builder/pilots/model-theory-admission/pending-review.md")
IMPLEMENTATION_RELATIVE_PATH = Path("Library/AutoLeanLibrary/Fixtures/ModelTheory/UniversalLK.lean")

_AUTHORITY_BOUNDARY = {
    "human_review_present": False,
    "expert_review_present": False,
    "authenticated_independence_present": False,
    "builder_admission_authority_present": False,
    "may_change_boundary_decision": False,
    "may_issue_admission_receipt": False,
    "may_freeze_statement": False,
    "may_handoff_to_prover": False,
    "may_promote": False,
    "may_claim_open_problem_progress": False,
}
_SOURCE_MATRIX_AUTHORITY_BOUNDARY = {
    "record_kind": "automated_technical_cross_check",
    "human_review_present": False,
    "expert_review_present": False,
    "builder_admission_authority_present": False,
    "may_issue_admission_receipt": False,
}
_FINE_SPAN_AUTHORITY_BOUNDARY = {
    "record_kind": "machine_locator_output",
    "review_state": "machine_located_pending_review",
    "human_visual_review_present": False,
    "semantic_review_present": False,
    "expert_review_present": False,
    "builder_admission_authority_present": False,
    "may_change_boundary_decision": False,
    "may_issue_admission_receipt": False,
    "may_freeze_statement": False,
    "may_handoff_to_prover": False,
}
_T4_AUTHORITY_BOUNDARY = dict(_AUTHORITY_BOUNDARY)
_HUMAN_PACKET_AUTHORITY_BOUNDARY = {
    "human_identity_authenticated": False,
    "expert_qualification_authenticated": False,
    "independence_authenticated": False,
    "builder_admission_authority_present": False,
    "may_change_boundary_decision": False,
    "may_issue_admission_receipt": False,
    "may_freeze_statement": False,
    "may_handoff_to_prover": False,
    "may_promote": False,
    "may_claim_open_problem_progress": False,
}
_EXPECTED_AMBIGUITY_IDS = frozenset(
    {
        "closed-boundary-translation-unadmitted",
        "formal-profile-successor-unselected",
        "fragment-scope-name-unselected",
        "implication-left-context-discipline-unverified",
        "rule-inventory-and-structural-policy-unverified",
        "section-7-5-page-pair-unreconciled",
        "universal-left-term-correspondence-unadmitted",
        "universal-right-freshness-correspondence-unadmitted",
        "universal-right-page-pair-unreconciled",
    }
)
_EXPECTED_MUTATION_IDS = frozenset(
    {
        "capture-avoiding-substitution-control",
        "existential-left-old-variable-reuse-control",
        "universal-right-old-variable-reuse-control",
    }
)
_EXPECTED_PROFILE_IDS = frozenset(
    {
        "full-candidate-observed-standard-axioms",
        "strict-empty-axiom-reproof",
        "target-only-observed-standard-axioms",
    }
)
_EXPECTED_DECISION_FILE_SHA256 = "ac0e66857405f0f948641d8579457ded2fab89b19fc5bd37409b95c3919eba57"
_EXPECTED_DECISION_CANONICAL_SHA256 = (
    "f55db634b51ef31871fdbd3e1002979d09c610bcf5dc7540ffef9d26c9f0f2a5"
)
_EXPECTED_CANDIDATE_ID = "model-theory-closed-level-indexed-fragment"
_EXPECTED_CANDIDATE_REVISION = "t3-boundary-v2"


class ModelTheoryMachineReviewError(ValueError):
    """A source binding or non-authority invariant failed closed."""


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _read_regular(path: Path, label: str) -> bytes:
    try:
        if not path.is_file() or path.is_symlink():
            raise ModelTheoryMachineReviewError(f"{label} must be a regular non-symlink file")
        return path.read_bytes()
    except OSError as error:
        raise ModelTheoryMachineReviewError(f"cannot read {label}") from error


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ModelTheoryMachineReviewError(f"{label} must be a string-keyed object")
    return cast(dict[str, object], value)


def _array(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise ModelTheoryMachineReviewError(f"{label} must be an array")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ModelTheoryMachineReviewError(f"{label} must be a nonempty string")
    return value


def _load_json(repo_root: Path, relative_path: Path, label: str) -> tuple[dict[str, object], bytes]:
    raw = _read_regular(repo_root / relative_path, label)
    try:
        value: object = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ModelTheoryMachineReviewError(f"{label} must be UTF-8 JSON") from error
    return _object(value, label), raw


def _json_binding(
    relative_path: Path, value: Mapping[str, object], raw: bytes
) -> dict[str, object]:
    return {
        "path": relative_path.as_posix(),
        "size_bytes": len(raw),
        "file_sha256": _sha256(raw),
        "canonical_sha256": _sha256(canonical_json_bytes(dict(value))),
        "schema_version": value.get("schema_version"),
    }


def _file_binding(repo_root: Path, relative_path: Path, label: str) -> dict[str, object]:
    raw = _read_regular(repo_root / relative_path, label)
    return {
        "path": relative_path.as_posix(),
        "size_bytes": len(raw),
        "file_sha256": _sha256(raw),
    }


def _require_false_authority(
    value: object,
    label: str,
    expected: Mapping[str, object],
) -> None:
    authority = _object(value, label)
    if authority != expected:
        raise ModelTheoryMachineReviewError(f"{label} contains authority")


def _verify_file_binding(
    repo_root: Path,
    binding: object,
    relative_path: Path,
    label: str,
    *,
    is_json: bool,
) -> None:
    observed = _object(binding, f"{label} binding")
    raw = _read_regular(repo_root / relative_path, label)
    if (
        observed.get("path") != relative_path.as_posix()
        or observed.get("size_bytes") != len(raw)
        or observed.get("file_sha256") != _sha256(raw)
    ):
        raise ModelTheoryMachineReviewError(f"{label} binding differs from its source")
    if is_json:
        try:
            value: object = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ModelTheoryMachineReviewError(f"{label} must be UTF-8 JSON") from error
        payload = _object(value, label)
        if observed.get("canonical_sha256") != _sha256(
            canonical_json_bytes(payload)
        ) or observed.get("schema_version") != payload.get("schema_version"):
            raise ModelTheoryMachineReviewError(f"{label} canonical binding differs from source")


def _row_by_id(rows: object, key: str, wanted: str, label: str) -> dict[str, object]:
    matches = [
        _object(row, label) for row in _array(rows, label) if _object(row, label).get(key) == wanted
    ]
    if len(matches) != 1:
        raise ModelTheoryMachineReviewError(f"{label} must contain exactly one {wanted!r} row")
    return matches[0]


def _declaration_observation(query: Mapping[str, object], declaration: str) -> dict[str, object]:
    observation = _object(query.get("observation"), "T4 query observation")
    record = _row_by_id(
        observation.get("declarations"),
        "declaration",
        declaration,
        "T4 declaration observations",
    )
    return {
        "declaration": declaration,
        "canonical_type_sha256": _string(
            record.get("canonical_type_sha256"), f"canonical type hash for {declaration}"
        ),
        "observed_axioms": sorted(
            _string(item, f"observed axiom for {declaration}")
            for item in _array(record.get("observed_axioms"), "observed axioms")
        ),
        "observed_axioms_sha256": _string(
            record.get("observed_axioms_sha256"), f"axiom hash for {declaration}"
        ),
    }


def _page_ambiguities(
    fine_spans: Mapping[str, object], human_packet: Mapping[str, object]
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for raw_ambiguity in _array(fine_spans.get("locator_ambiguities"), "locator ambiguities"):
        ambiguity = _object(raw_ambiguity, "locator ambiguity")
        ambiguity_id = _string(ambiguity.get("ambiguity_id"), "ambiguity ID")
        if ambiguity.get("review_state") != "pending_visual_review":
            raise ModelTheoryMachineReviewError("page ambiguity is no longer pending visual review")
        packet_row = _row_by_id(
            human_packet.get("page_ambiguity_reviews"),
            "ambiguity_id",
            ambiguity_id,
            "human packet page ambiguities",
        )
        span_id = _string(packet_row.get("span_id"), "page ambiguity span ID")
        span = _row_by_id(fine_spans.get("spans"), "span_id", span_id, "fine source spans")
        if span.get("location_state") != "machine_located_pending_review":
            raise ModelTheoryMachineReviewError("page ambiguity span is no longer pending review")
        rows.append(
            {
                "ambiguity_id": ambiguity_id,
                "ambiguity_kind": "pdf_printed_page_pair",
                "status": "unresolved_pending_visual_review",
                "source_requirement_id": ambiguity.get("requirement_id"),
                "source_span": {
                    key: span.get(key)
                    for key in ("span_id", "start_offset", "end_offset", "raw_sha256")
                },
                "claimed_pages": packet_row.get("claimed_pages"),
                "machine_finding": (
                    "The digest-only span does not determine which claimed PDF/printed-page "
                    "pair is visually correct."
                ),
                "required_next_evidence": (
                    "A page-render manifest and visual reconciliation bound to this span."
                ),
                "decision_effect": "none",
            }
        )
    return sorted(rows, key=lambda row: cast(str, row["ambiguity_id"]))


def _semantic_ambiguities(
    matrix: Mapping[str, object],
    decision: Mapping[str, object],
    t4_attachment: Mapping[str, object],
) -> list[dict[str, object]]:
    rows = matrix.get("rule_matrix")
    closed = _row_by_id(rows, "matrix_id", "closed-sequent-boundary", "source rule matrix")
    imp_left = _row_by_id(rows, "matrix_id", "implication-left", "source rule matrix")
    all_left = _row_by_id(rows, "matrix_id", "universal-left", "source rule matrix")
    all_right = _row_by_id(rows, "matrix_id", "universal-right", "source rule matrix")
    missing_ids = (
        "existential-left",
        "existential-right",
        "structural-rules-and-cut",
        "other-connective-rules",
    )
    missing = [_row_by_id(rows, "matrix_id", item, "source rule matrix") for item in missing_ids]
    candidate = _object(decision.get("candidate"), "decision candidate")
    compatibility = _object(t4_attachment.get("compatibility"), "T4 compatibility")
    common = {"status": "unresolved", "decision_effect": "none"}
    return [
        {
            **common,
            "ambiguity_id": "closed-boundary-translation-unadmitted",
            "ambiguity_kind": "source_to_formal_translation",
            "machine_finding": closed.get("reason"),
            "required_next_evidence": (
                "A source-bound rule translation showing that every selected closed sequent "
                "maps to the level-zero theorem boundary."
            ),
        },
        {
            **common,
            "ambiguity_id": "rule-inventory-and-structural-policy-unverified",
            "ambiguity_kind": "fragment_rule_inventory",
            "matrix_rows": [row.get("matrix_id") for row in missing],
            "matrix_statuses": [row.get("status") for row in missing],
            "machine_finding": (
                "Existential rules, structural rules, cut, and other connective rules are "
                "missing from the candidate; their source policy is not selected."
            ),
            "required_next_evidence": (
                "An explicit source-bound inventory classifying each rule as implemented, "
                "admissible, or excluded."
            ),
        },
        {
            **common,
            "ambiguity_id": "implication-left-context-discipline-unverified",
            "ambiguity_kind": "rule_variant",
            "matrix_status": imp_left.get("status"),
            "machine_finding": imp_left.get("reason"),
            "required_next_evidence": (
                "A source-bound equivalence or an explicit shared-context fragment exclusion."
            ),
        },
        {
            **common,
            "ambiguity_id": "universal-left-term-correspondence-unadmitted",
            "ambiguity_kind": "quantifier_representation",
            "matrix_status": all_left.get("status"),
            "machine_finding": all_left.get("reason"),
            "required_next_evidence": (
                "A fidelity argument relating source closed/free-for terms to Term (Fin n)."
            ),
        },
        {
            **common,
            "ambiguity_id": "universal-right-freshness-correspondence-unadmitted",
            "ambiguity_kind": "quantifier_representation",
            "matrix_status": all_right.get("status"),
            "machine_finding": all_right.get("reason"),
            "required_next_evidence": (
                "A fidelity argument relating a source fresh constant to the new Fin.last level."
            ),
        },
        {
            **common,
            "ambiguity_id": "fragment-scope-name-unselected",
            "ambiguity_kind": "candidate_scope",
            "candidate_id": candidate.get("candidate_id"),
            "out_of_scope": candidate.get("out_of_scope"),
            "machine_finding": (
                "The current identifier may be read more broadly than the implemented "
                "bottom/implication/universal fragment."
            ),
            "required_next_evidence": (
                "A successor candidate name and scope that cannot be mistaken for full LK."
            ),
        },
        {
            **common,
            "ambiguity_id": "formal-profile-successor-unselected",
            "ambiguity_kind": "execution_and_axiom_policy",
            "observed_incompatibilities": {
                key: compatibility.get(key)
                for key in (
                    "decision_worker_image_matches_observation",
                    "decision_imports_allowlist_matches_direct_imports",
                    "decision_strict_empty_axiom_profile_matches_observation",
                )
            },
            "machine_finding": (
                "The immutable decision profile does not match the exact-image import and axiom "
                "observations."
            ),
            "required_next_evidence": (
                "Choose and independently replay one successor profile; issue a new decision "
                "revision rather than editing decision.v2.json."
            ),
        },
    ]


def _mutation_results(query: Mapping[str, object]) -> list[dict[str, object]]:
    prefix = "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK."
    specifications = (
        (
            "capture-avoiding-substitution-control",
            "capture_avoidance",
            ("naive_capture_would_be_true", "inst0_capture_avoiding_control"),
            "The retained Bool witness distinguishes naive capture from the implemented "
            "capture-avoiding instance.",
            "This rejects one concrete capture mutation; it does not prove general source "
            "fidelity.",
        ),
        (
            "existential-left-old-variable-reuse-control",
            "eigenvariable_freshness",
            (
                "reused_old_variable_existsLeft_premise_valid",
                "reused_old_variable_existsLeft_is_unsound",
            ),
            "The retained Bool countermodel rejects reusing an old variable in the "
            "existential-left pattern.",
            "Existential-left is not a candidate constructor; this is only a rejection witness.",
        ),
        (
            "universal-right-old-variable-reuse-control",
            "eigenvariable_freshness",
            (
                "reused_old_variable_premise_valid",
                "reused_old_variable_allRight_is_unsound",
            ),
            "The retained Bool countermodel rejects reusing an old variable for universal-right.",
            "This rejects one concrete freshness mutation; it does not establish equivalence "
            "to the source fresh-symbol discipline.",
        ),
    )
    results: list[dict[str, object]] = []
    for mutation_id, family, declarations, finding, limitation in specifications:
        results.append(
            {
                "mutation_id": mutation_id,
                "mutation_family": family,
                "result": "mutant_rejected_by_retained_kernel_control",
                "mutant_rejected": True,
                "observation_assurance": "exact_image_declaration_query_bound",
                "declaration_observations": [
                    _declaration_observation(query, prefix + item) for item in declarations
                ],
                "machine_finding": finding,
                "limitation": limitation,
                "admission_effect": "none",
            }
        )
    return results


def _successor_profiles(
    decision: Mapping[str, object],
    query: Mapping[str, object],
    t4_attachment: Mapping[str, object],
) -> list[dict[str, object]]:
    current = _object(decision.get("formal_profile"), "decision formal profile")
    observation = _object(query.get("observation"), "T4 query observation")
    execution = _object(t4_attachment.get("execution_binding"), "T4 execution binding")
    direct_imports = sorted(
        _string(item, "candidate direct import")
        for item in _array(observation.get("candidate_direct_imports"), "direct imports")
    )
    observed_axioms = sorted(
        {
            _string(axiom, "observed axiom")
            for row in _array(observation.get("declarations"), "declaration observations")
            for axiom in _array(
                _object(row, "declaration observation").get("observed_axioms"),
                "observed axioms",
            )
        }
    )
    image = _string(execution.get("worker_image"), "exact worker image")
    common: dict[str, object] = {
        "lean_toolchain": current.get("lean_toolchain"),
        "mathlib_revision": current.get("mathlib_revision"),
        "worker_image": image,
        "imports_allowlist": direct_imports,
        "proof_slot_profile": current.get("proof_slot_profile"),
        "allowed_write_paths": current.get("allowed_write_paths"),
        "successor_revision_required": True,
        "selected": False,
        "admission_effect": "none",
    }
    return [
        {
            **common,
            "profile_id": "strict-empty-axiom-reproof",
            "axiom_profile": "strict",
            "axioms_allowlist": [],
            "declaration_scope": "full_candidate",
            "current_observation_compatibility": "incompatible",
            "required_next_evidence": (
                "Remove all observed axiom use, rebuild the exact image, and rerun every "
                "declaration query plus the complete Library input-tree receipt."
            ),
        },
        {
            **common,
            "profile_id": "full-candidate-observed-standard-axioms",
            "axiom_profile": "explicit_observed_allowlist",
            "axioms_allowlist": observed_axioms,
            "declaration_scope": "all_46_retained_declarations",
            "current_observation_compatibility": "matches_exact_image_observation",
            "required_next_evidence": (
                "Recompute the complete Library input tree, independently replay the exact "
                "image query, and obtain a new Builder decision revision."
            ),
        },
        {
            **common,
            "profile_id": "target-only-observed-standard-axioms",
            "axiom_profile": "explicit_target_allowlist",
            "axioms_allowlist": _declaration_observation(
                query,
                "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Deriv.closed_sound",
            )["observed_axioms"],
            "declaration_scope": "closed_sound_plus_exact_dependency_closure",
            "current_observation_compatibility": "target_observation_matches_but_closure_missing",
            "required_next_evidence": (
                "Retain an exact declaration dependency closure, query every dependency, "
                "recompute the Library input tree, and obtain a new Builder decision revision."
            ),
        },
    ]


def build_model_theory_machine_review_packet(repo_root: Path) -> dict[str, object]:
    """Construct the deterministic advisory packet from current tracked evidence."""

    decision, decision_raw = _load_json(repo_root, DECISION_RELATIVE_PATH, "T3 decision")
    matrix, matrix_raw = _load_json(repo_root, SOURCE_MATRIX_RELATIVE_PATH, "source rule matrix")
    fine, fine_raw = _load_json(repo_root, FINE_SPANS_RELATIVE_PATH, "fine source spans")
    t4_attachment, t4_attachment_raw = _load_json(
        repo_root, T4_ATTACHMENT_RELATIVE_PATH, "T4 exact-image attachment"
    )
    query, query_raw = _load_json(repo_root, T4_QUERY_RELATIVE_PATH, "T4 declaration query")
    human, human_raw = _load_json(repo_root, HUMAN_PACKET_RELATIVE_PATH, "human review packet")

    candidate = _object(decision.get("candidate"), "decision candidate")
    if (
        decision.get("schema_version") != "autolean.pilot-boundary-decision.v2"
        or matrix.get("schema_version") != "autolean.public-source-rule-matrix.v2"
        or fine.get("schema_version") != "autolean.public-t3-fine-source-spans.v2"
        or t4_attachment.get("schema_version") != "autolean.public-t4-exact-image-attachment.v1"
        or query.get("schema_version") != "autolean.mathlib-declaration-query-evidence.v1"
        or human.get("schema_version") != "autolean.model-theory-t3-human-review-packet.v1"
        or _sha256(decision_raw) != _EXPECTED_DECISION_FILE_SHA256
        or _sha256(canonical_json_bytes(decision)) != _EXPECTED_DECISION_CANONICAL_SHA256
        or candidate.get("candidate_id") != _EXPECTED_CANDIDATE_ID
        or candidate.get("revision") != _EXPECTED_CANDIDATE_REVISION
        or decision.get("disposition") != "gap"
        or decision.get("authority") != "automated_agent_evidence_only"
        or fine.get("effect_on_t3") != "none_until_authorized_visual_and_semantic_review"
    ):
        raise ModelTheoryMachineReviewError("the immutable T3 gap boundary changed")
    fine_decision = _object(fine.get("decision_binding"), "fine-span decision binding")
    matrix_disposition = _object(matrix.get("disposition"), "matrix disposition")
    t4_decision = _object(t4_attachment.get("decision_binding"), "T4 decision binding")
    human_decision = _object(human.get("decision_binding"), "human packet decision binding")
    fine_matrix = _object(fine.get("rule_matrix_binding"), "fine-span matrix binding")
    t4_query_binding = _object(t4_attachment.get("query_evidence_binding"), "T4 query binding")
    t4_source = _object(t4_attachment.get("source_binding"), "T4 source binding")
    t4_execution = _object(t4_attachment.get("execution_binding"), "T4 execution binding")
    t4_summary = _object(t4_attachment.get("observation_summary"), "T4 observation summary")
    t4_compatibility = _object(t4_attachment.get("compatibility"), "T4 compatibility")
    query_observation = _object(query.get("observation"), "T4 query observation")
    query_declarations = _array(
        query_observation.get("declarations"), "T4 declaration observations"
    )
    human_evidence = _object(human.get("evidence_bindings"), "human packet evidence")
    human_fine = _object(human_evidence.get("fine_source_spans"), "human fine binding")
    human_t4 = _object(human_evidence.get("t4_exact_image"), "human T4 binding")
    human_implementation = _object(
        human_evidence.get("implementation"), "human implementation binding"
    )
    implementation_sha256 = _sha256(
        _read_regular(repo_root / IMPLEMENTATION_RELATIVE_PATH, "T3 implementation")
    )
    if (
        fine_decision.get("t3_disposition") != "gap"
        or fine_decision.get("selection") != "not_selected"
        or fine_decision.get("statement_contract") != "not_frozen"
        or fine_decision.get("prover_handoff") != "forbidden"
        or matrix_disposition.get("t3_admission") != "gap"
        or matrix_disposition.get("prover_handoff") != "forbidden"
        or fine_decision.get("decision_canonical_sha256") != _EXPECTED_DECISION_CANONICAL_SHA256
        or t4_decision.get("decision_canonical_sha256") != _EXPECTED_DECISION_CANONICAL_SHA256
        or human_decision.get("canonical_sha256") != _EXPECTED_DECISION_CANONICAL_SHA256
        or human_decision.get("file_sha256") != _EXPECTED_DECISION_FILE_SHA256
        or fine_matrix.get("matrix_sha256") != _sha256(matrix_raw)
        or t4_query_binding.get("sha256") != _sha256(query_raw)
        or t4_source.get("source_snapshot_matches_decision") is not True
        or t4_source.get("decision_source_sha256") != implementation_sha256
        or query.get("source_snapshot_sha256") != implementation_sha256
        or query.get("image") != t4_execution.get("worker_image")
        or t4_summary.get("declaration_count") != len(query_declarations)
        or t4_compatibility.get("effect_on_t3") != "gap_remains_open"
        or human.get("review_effect") != "advisory_only"
        or human_fine.get("file_sha256") != _sha256(fine_raw)
        or human_t4.get("attachment_sha256") != _sha256(t4_attachment_raw)
        or human_t4.get("query_sha256") != _sha256(query_raw)
        or human_implementation.get("sha256") != implementation_sha256
    ):
        raise ModelTheoryMachineReviewError("a T3 attachment no longer preserves the gap")
    _require_false_authority(
        matrix.get("authority_boundary"),
        "source matrix authority",
        _SOURCE_MATRIX_AUTHORITY_BOUNDARY,
    )
    _require_false_authority(
        fine.get("authority_boundary"),
        "fine-span authority",
        _FINE_SPAN_AUTHORITY_BOUNDARY,
    )
    _require_false_authority(
        t4_attachment.get("authority_boundary"),
        "T4 authority",
        _T4_AUTHORITY_BOUNDARY,
    )
    _require_false_authority(
        human.get("authority_boundary"),
        "human packet authority",
        _HUMAN_PACKET_AUTHORITY_BOUNDARY,
    )

    ambiguities = [
        *_page_ambiguities(fine, human),
        *_semantic_ambiguities(matrix, decision, t4_attachment),
    ]
    mutations = _mutation_results(query)
    profiles = _successor_profiles(decision, query, t4_attachment)
    packet: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "artifact_kind": ARTIFACT_KIND,
        "packet_id": "model-theory-t3-machine-review-v1",
        "review_effect": "advisory_only",
        "decision_binding": {
            **_json_binding(DECISION_RELATIVE_PATH, decision, decision_raw),
            "candidate_id": candidate.get("candidate_id"),
            "candidate_revision": candidate.get("revision"),
            "candidate_sha256": candidate.get("candidate_sha256"),
            "disposition": "gap",
            "selection": "not_selected",
            "statement_contract": "not_frozen",
            "prover_handoff": "forbidden",
        },
        "evidence_bindings": {
            "source_rule_matrix": _json_binding(SOURCE_MATRIX_RELATIVE_PATH, matrix, matrix_raw),
            "fine_source_spans": _json_binding(FINE_SPANS_RELATIVE_PATH, fine, fine_raw),
            "t4_exact_image_attachment": _json_binding(
                T4_ATTACHMENT_RELATIVE_PATH, t4_attachment, t4_attachment_raw
            ),
            "t4_declaration_query": _json_binding(T4_QUERY_RELATIVE_PATH, query, query_raw),
            "human_review_packet": _json_binding(HUMAN_PACKET_RELATIVE_PATH, human, human_raw),
            "pending_review": _file_binding(
                repo_root, PENDING_REVIEW_RELATIVE_PATH, "pending T3 review"
            ),
            "implementation": _file_binding(
                repo_root, IMPLEMENTATION_RELATIVE_PATH, "T3 implementation"
            ),
        },
        "machine_quorum_compatibility": {
            "policy": MachineSemanticQuorumPolicy().payload(),
            "review_roles": sorted(role.value for role in MachineSemanticReviewRole),
            "compatibility_scope": "role_and_policy_shape_only",
            "execution_state": "not_executed",
            "machine_quorum_report_present": False,
            "provider_request_present": False,
            "control_plane_receipt_present": False,
            "declared_failure_domains_attested": False,
            "reason": (
                "This deterministic packet reuses the quorum role vocabulary but is not a "
                "BlindMachineReviewTask, provider request, or MachineQuorumReport."
            ),
        },
        "ambiguity_table": sorted(ambiguities, key=lambda row: cast(str, row["ambiguity_id"])),
        "mutation_results": sorted(mutations, key=lambda row: cast(str, row["mutation_id"])),
        "successor_formal_profile_alternatives": sorted(
            profiles, key=lambda row: cast(str, row["profile_id"])
        ),
        "machine_recommendation": {
            "recommendation": "prepare_successor_evidence_only",
            "preferred_profile_for_next_replay": "full-candidate-observed-standard-axioms",
            "reason": (
                "It is the only full-candidate option that matches the retained exact-image "
                "import and axiom observations without claiming that those policies are accepted."
            ),
            "selected": False,
            "admitted": False,
            "requires_new_decision_revision": True,
            "authority": "machine_advisory",
        },
        "residual_authority_gaps": [
            "machine findings are not human or expert semantic review",
            "reviewer identity and independence are not authenticated",
            "no Builder admission authority or admission receipt is present",
            "no successor formal profile has been selected or independently replayed",
            "no statement contract is frozen and Prover handoff remains forbidden",
        ],
        "public_safety": {
            "contains_source_excerpt": False,
            "contains_local_cache_path": False,
            "contains_prompt_or_raw_model_output": False,
            "contains_credentials": False,
        },
        "authority_boundary": dict(_AUTHORITY_BOUNDARY),
    }
    _verify_model_theory_machine_review_payload_structure(repo_root, packet)
    return packet


def _verify_model_theory_machine_review_payload_structure(
    repo_root: Path, packet: Mapping[str, object]
) -> None:
    """Verify exact replay plus the packet's permanent non-authority boundary."""

    if (
        packet.get("schema_version") != SCHEMA_VERSION
        or packet.get("artifact_kind") != ARTIFACT_KIND
    ):
        raise ModelTheoryMachineReviewError("unsupported machine review packet")
    if packet.get("review_effect") != "advisory_only":
        raise ModelTheoryMachineReviewError("machine review effect must remain advisory")
    if packet.get("authority_boundary") != _AUTHORITY_BOUNDARY:
        raise ModelTheoryMachineReviewError("machine review packet contains authority")
    decision = _object(packet.get("decision_binding"), "packet decision binding")
    _verify_file_binding(repo_root, decision, DECISION_RELATIVE_PATH, "T3 decision", is_json=True)
    if (
        decision.get("disposition") != "gap"
        or decision.get("selection") != "not_selected"
        or decision.get("statement_contract") != "not_frozen"
        or decision.get("prover_handoff") != "forbidden"
    ):
        raise ModelTheoryMachineReviewError("machine review packet changed the T3 boundary")
    protocol = _object(packet.get("machine_quorum_compatibility"), "quorum compatibility")
    if (
        protocol.get("policy") != MachineSemanticQuorumPolicy().payload()
        or protocol.get("review_roles") != sorted(role.value for role in MachineSemanticReviewRole)
        or protocol.get("execution_state") != "not_executed"
        or any(
            protocol.get(key) is not False
            for key in (
                "machine_quorum_report_present",
                "provider_request_present",
                "control_plane_receipt_present",
                "declared_failure_domains_attested",
            )
        )
    ):
        raise ModelTheoryMachineReviewError("machine quorum boundary is overstated")
    evidence = _object(packet.get("evidence_bindings"), "evidence bindings")
    for key, path, is_json in (
        ("source_rule_matrix", SOURCE_MATRIX_RELATIVE_PATH, True),
        ("fine_source_spans", FINE_SPANS_RELATIVE_PATH, True),
        ("t4_exact_image_attachment", T4_ATTACHMENT_RELATIVE_PATH, True),
        ("t4_declaration_query", T4_QUERY_RELATIVE_PATH, True),
        ("human_review_packet", HUMAN_PACKET_RELATIVE_PATH, True),
        ("pending_review", PENDING_REVIEW_RELATIVE_PATH, False),
        ("implementation", IMPLEMENTATION_RELATIVE_PATH, False),
    ):
        _verify_file_binding(
            repo_root, evidence.get(key), path, f"machine review {key}", is_json=is_json
        )
    ambiguity_rows = [
        _object(row, "ambiguity row")
        for row in _array(packet.get("ambiguity_table"), "ambiguity table")
    ]
    mutation_rows = [
        _object(row, "mutation row")
        for row in _array(packet.get("mutation_results"), "mutation results")
    ]
    ambiguity_ids = {_string(row.get("ambiguity_id"), "ambiguity ID") for row in ambiguity_rows}
    mutation_ids = {_string(row.get("mutation_id"), "mutation ID") for row in mutation_rows}
    profile_rows = [
        _object(row, "successor profile")
        for row in _array(packet.get("successor_formal_profile_alternatives"), "successor profiles")
    ]
    profile_ids = {_string(row.get("profile_id"), "successor profile ID") for row in profile_rows}
    if ambiguity_ids != _EXPECTED_AMBIGUITY_IDS:
        raise ModelTheoryMachineReviewError("machine ambiguity coverage is incomplete")
    if any(
        row.get("status") not in {"unresolved", "unresolved_pending_visual_review"}
        or row.get("decision_effect") != "none"
        for row in ambiguity_rows
    ):
        raise ModelTheoryMachineReviewError("machine ambiguity table resolved a boundary")
    if mutation_ids != _EXPECTED_MUTATION_IDS:
        raise ModelTheoryMachineReviewError("machine mutation coverage is incomplete")
    if profile_ids != _EXPECTED_PROFILE_IDS or any(
        row.get("selected") is not False or row.get("admission_effect") != "none"
        for row in profile_rows
    ):
        raise ModelTheoryMachineReviewError("successor profile alternatives crossed authority")
    if any(
        row.get("admission_effect") != "none"
        or row.get("mutant_rejected") is not True
        or row.get("result") != "mutant_rejected_by_retained_kernel_control"
        for row in mutation_rows
    ):
        raise ModelTheoryMachineReviewError("mutation evidence cannot admit the candidate")
    recommendation = _object(packet.get("machine_recommendation"), "machine recommendation")
    if (
        recommendation.get("authority") != "machine_advisory"
        or recommendation.get("selected") is not False
        or recommendation.get("admitted") is not False
        or recommendation.get("requires_new_decision_revision") is not True
    ):
        raise ModelTheoryMachineReviewError("machine recommendation impersonates admission")


def verify_model_theory_machine_review_payload(
    repo_root: Path, packet: Mapping[str, object]
) -> None:
    """Reject any packet that is not the exact deterministic source replay."""

    root = repo_root.resolve()
    _verify_model_theory_machine_review_payload_structure(root, packet)
    if dict(packet) != build_model_theory_machine_review_packet(root):
        raise ModelTheoryMachineReviewError(
            "machine review packet differs from deterministic source replay"
        )


def render_model_theory_machine_review_packet(
    repo_root: Path, packet: Mapping[str, object]
) -> bytes:
    verify_model_theory_machine_review_payload(repo_root, packet)
    return (json.dumps(dict(packet), indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def verify_tracked_model_theory_machine_review_packet(repo_root: Path) -> dict[str, object]:
    tracked, raw = _load_json(repo_root, PACKET_RELATIVE_PATH, "tracked machine review packet")
    verify_model_theory_machine_review_payload(repo_root, tracked)
    expected = build_model_theory_machine_review_packet(repo_root)
    expected_raw = render_model_theory_machine_review_packet(repo_root, expected)
    if tracked != expected or raw != expected_raw:
        raise ModelTheoryMachineReviewError(
            "tracked machine review packet differs from deterministic source replay"
        )
    return tracked


def write_model_theory_machine_review_packet(repo_root: Path) -> Path:
    root = repo_root.resolve()
    output = root / PACKET_RELATIVE_PATH
    output.parent.mkdir(parents=True, exist_ok=True)
    if (
        not output.parent.resolve().is_relative_to(root)
        or any(
            path.is_symlink() for path in (output.parent, *output.parent.parents) if path != root
        )
        or output.is_symlink()
        or (output.exists() and not output.is_file())
    ):
        raise ModelTheoryMachineReviewError("machine review output must remain a regular repo file")
    output.write_bytes(
        render_model_theory_machine_review_packet(
            root,
            build_model_theory_machine_review_packet(root),
        )
    )
    return output
