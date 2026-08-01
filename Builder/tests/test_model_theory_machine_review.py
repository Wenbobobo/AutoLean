from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import cast

import autolean_builder.model_theory_machine_review as machine_review
import pytest
from autolean_builder.model_theory_machine_review import (
    PACKET_RELATIVE_PATH,
    ModelTheoryMachineReviewError,
    build_model_theory_machine_review_packet,
    render_model_theory_machine_review_packet,
    verify_model_theory_machine_review_payload,
    verify_tracked_model_theory_machine_review_packet,
)

ROOT = Path(__file__).resolve().parents[2]


def _built() -> dict[str, object]:
    return build_model_theory_machine_review_packet(ROOT)


def test_tracked_packet_is_exact_deterministic_replay() -> None:
    tracked = verify_tracked_model_theory_machine_review_packet(ROOT)

    assert tracked == _built()
    assert (ROOT / PACKET_RELATIVE_PATH).read_bytes() == render_model_theory_machine_review_packet(
        ROOT, tracked
    )


def test_packet_preserves_immutable_gap_and_non_authority() -> None:
    packet = _built()
    decision = cast(dict[str, object], packet["decision_binding"])
    authority = cast(dict[str, object], packet["authority_boundary"])
    recommendation = cast(dict[str, object], packet["machine_recommendation"])

    assert decision["disposition"] == "gap"
    assert decision["selection"] == "not_selected"
    assert decision["statement_contract"] == "not_frozen"
    assert decision["prover_handoff"] == "forbidden"
    assert authority and not any(authority.values())
    assert recommendation["selected"] is False
    assert recommendation["admitted"] is False
    assert recommendation["requires_new_decision_revision"] is True


def test_packet_covers_ambiguities_mutations_and_profile_alternatives() -> None:
    packet = _built()

    ambiguities = cast(list[dict[str, object]], packet["ambiguity_table"])
    mutations = cast(list[dict[str, object]], packet["mutation_results"])
    profiles = cast(list[dict[str, object]], packet["successor_formal_profile_alternatives"])
    assert len(ambiguities) == 9
    assert len(mutations) == 3
    assert len(profiles) == 3
    assert all(row["decision_effect"] == "none" for row in ambiguities)
    assert all(row["mutant_rejected"] and row["admission_effect"] == "none" for row in mutations)
    assert all(not row["selected"] and row["admission_effect"] == "none" for row in profiles)


@pytest.mark.parametrize(
    ("section", "field", "value", "match"),
    (
        ("authority_boundary", "may_freeze_statement", True, "contains authority"),
        ("decision_binding", "selection", "selected", "changed the T3 boundary"),
        ("machine_quorum_compatibility", "execution_state", "verified", "overstated"),
        ("machine_recommendation", "admitted", True, "impersonates admission"),
    ),
)
def test_payload_rejects_authority_drift(
    section: str, field: str, value: object, match: str
) -> None:
    changed = copy.deepcopy(_built())
    cast(dict[str, object], changed[section])[field] = value

    with pytest.raises(ModelTheoryMachineReviewError, match=match):
        verify_model_theory_machine_review_payload(ROOT, changed)


def test_payload_rejects_dropped_ambiguity_mutation_or_profile() -> None:
    for section in (
        "ambiguity_table",
        "mutation_results",
        "successor_formal_profile_alternatives",
    ):
        changed = copy.deepcopy(_built())
        cast(list[object], changed[section]).pop()
        with pytest.raises(ModelTheoryMachineReviewError, match=r"coverage|alternatives"):
            verify_model_theory_machine_review_payload(ROOT, changed)


def test_payload_rejects_evidence_hash_drift() -> None:
    changed = copy.deepcopy(_built())
    evidence = cast(dict[str, object], changed["evidence_bindings"])
    query = cast(dict[str, object], evidence["t4_declaration_query"])
    query["file_sha256"] = "0" * 64

    with pytest.raises(ModelTheoryMachineReviewError, match="differs from its source"):
        verify_model_theory_machine_review_payload(ROOT, changed)


@pytest.mark.parametrize("mutation", ("extra_top_level", "changed_finding"))
def test_verifier_and_renderer_reject_noncanonical_packet_content(mutation: str) -> None:
    changed = copy.deepcopy(_built())
    if mutation == "extra_top_level":
        changed["private_note"] = "must not enter the public packet"
    else:
        ambiguity = cast(list[dict[str, object]], changed["ambiguity_table"])[0]
        ambiguity["machine_finding"] = "rewritten advisory content"

    with pytest.raises(ModelTheoryMachineReviewError, match="deterministic source replay"):
        verify_model_theory_machine_review_payload(ROOT, changed)
    with pytest.raises(ModelTheoryMachineReviewError, match="deterministic source replay"):
        render_model_theory_machine_review_packet(ROOT, changed)


@pytest.mark.parametrize(
    ("expected", "field"),
    (
        (machine_review._SOURCE_MATRIX_AUTHORITY_BOUNDARY, "freeze_allowed"),
        (machine_review._FINE_SPAN_AUTHORITY_BOUNDARY, "may_freeze_statement"),
        (machine_review._T4_AUTHORITY_BOUNDARY, "promotion_allowed"),
        (
            machine_review._HUMAN_PACKET_AUTHORITY_BOUNDARY,
            "human_identity_authenticated",
        ),
    ),
)
def test_source_authority_schemas_reject_known_or_unknown_true_fields(
    expected: dict[str, object], field: str
) -> None:
    changed = {**expected, field: True}

    with pytest.raises(ModelTheoryMachineReviewError, match="contains authority"):
        machine_review._require_false_authority(
            changed,
            "source authority",
            expected,
        )


def test_builder_rejects_immutable_decision_byte_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_read = machine_review._read_regular

    def changed_read(path: Path, label: str) -> bytes:
        raw = original_read(path, label)
        if path == ROOT / machine_review.DECISION_RELATIVE_PATH:
            return raw + b"\n"
        return raw

    monkeypatch.setattr(machine_review, "_read_regular", changed_read)

    with pytest.raises(ModelTheoryMachineReviewError, match="immutable T3 gap boundary"):
        build_model_theory_machine_review_packet(ROOT)


def test_packet_contains_no_source_excerpt_or_local_cache_path() -> None:
    packet = _built()
    rendered = render_model_theory_machine_review_packet(ROOT, packet)

    assert packet["public_safety"] == {
        "contains_source_excerpt": False,
        "contains_local_cache_path": False,
        "contains_prompt_or_raw_model_output": False,
        "contains_credentials": False,
    }
    assert b".cache" not in rendered
    assert b"C:/" not in rendered
    assert b"C:\\" not in rendered
    json.loads(rendered)
