from __future__ import annotations

import json
import os
import shutil
import subprocess
from copy import deepcopy
from pathlib import Path
from typing import cast

import pytest
from autolean_prover.proof_dependencies import (
    ProofDependencyEvidence,
    ProofDependencyEvidenceError,
    ProofDependencyPolicy,
    ProofDependencyRejected,
    evaluate_proof_dependency_policy,
)

from scripts import proof_dependency_gate

_FIXTURES = Path(__file__).parent / "fixtures" / "proof_dependencies"
_SOURCE_V2_IMAGE = (
    "autolean/mathlib-worker@"
    "sha256:3237192cf627a05367c75d46e61ec9034fefe43a4fd0c06139e38c80358648d6"
)


def _record(name: str) -> dict[str, object]:
    value = json.loads((_FIXTURES / name).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return cast(dict[str, object], value)


def test_exact_closure_allowlist_accepts_nonalias_fixture() -> None:
    evidence = ProofDependencyEvidence.from_mapping(_record("nonalias.evidence.json"))
    policy = ProofDependencyPolicy.from_mapping(_record("nonalias.policy.json"))

    decision = evaluate_proof_dependency_policy(evidence, policy)

    assert decision.accepted is True
    assert evidence.declaration == "AutoLean.ProofDependencyFixture.nonalias"
    assert decision.direct_dependency_count == 2
    assert decision.closure_dependency_count == 5
    assert len(decision.policy_sha256) == 64
    assert len(decision.evidence_sha256) == 64


def test_known_exact_type_alias_is_rejected_by_explicit_name_denial() -> None:
    evidence = ProofDependencyEvidence.from_mapping(_record("exact-type-alias.evidence.json"))
    policy = ProofDependencyPolicy.from_mapping(_record("exact-type-alias.policy.json"))

    assert evidence.direct_proof_dependencies == ("AutoLean.ProofDependencyFixture.nonalias",)
    with pytest.raises(ProofDependencyRejected, match="nonalias"):
        evaluate_proof_dependency_policy(evidence, policy)


def test_transitive_closure_rejects_allowed_wrapper_around_denied_theorem() -> None:
    evidence = ProofDependencyEvidence.from_mapping(_record("disguised.evidence.json"))
    policy = ProofDependencyPolicy.from_mapping(_record("disguised.policy.json"))

    assert evidence.direct_proof_dependencies == ("AutoLean.ProofDependencyFixture.allowedWrapper",)
    with pytest.raises(ProofDependencyRejected, match="forbiddenStrong"):
        evaluate_proof_dependency_policy(evidence, policy)


def test_unlisted_ordinary_declaration_fails_closed_without_a_matching_denial() -> None:
    evidence = ProofDependencyEvidence.from_mapping(_record("disguised.evidence.json"))
    policy_record = _record("disguised.policy.json")
    policy_record["denied_dependencies"] = ["AutoLean.ProofDependencyFixture.disguised"]
    policy = ProofDependencyPolicy.from_mapping(policy_record)

    with pytest.raises(ProofDependencyRejected, match=r"unapproved.*forbiddenStrong"):
        evaluate_proof_dependency_policy(evidence, policy)


def test_quotient_declaration_type_adds_quot_mk_to_transitive_closure() -> None:
    evidence = ProofDependencyEvidence.from_mapping(_record("quotient.evidence.json"))
    policy = ProofDependencyPolicy.from_mapping(_record("quotient.policy.json"))

    assert evidence.direct_proof_dependencies == ("Quot.ind",)
    assert "Quot.mk" not in evidence.direct_proof_dependencies
    assert "Quot.mk" in evidence.proof_dependency_closure
    with pytest.raises(ProofDependencyRejected, match=r"Quot\.mk"):
        evaluate_proof_dependency_policy(evidence, policy)


def test_candidate_module_intersection_is_diagnostic_not_an_ownership_policy() -> None:
    record = _record("nonalias.evidence.json")
    record["candidate_module_dependencies"] = []
    evidence = ProofDependencyEvidence.from_mapping(record)
    policy = ProofDependencyPolicy.from_mapping(_record("nonalias.policy.json"))

    decision = evaluate_proof_dependency_policy(evidence, policy)

    assert decision.accepted is True
    assert evidence.candidate_module_dependencies == ()


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("missing-field", "unexpected or missing"),
        ("unknown-field", "unexpected or missing"),
        ("wrong-schema", "unsupported schema"),
        ("wrong-traversal", "unsupported traversal"),
        ("boolean-count", "count is invalid"),
        ("unsorted-closure", "sorted and unique"),
        ("duplicate-direct", "sorted and unique"),
        ("missing-direct-from-closure", "omits a direct"),
        ("candidate-outside-closure", "outside"),
        ("self-reference", "own target"),
    ),
)
def test_evidence_shape_and_completeness_invariants_fail_closed(
    mutation: str,
    message: str,
) -> None:
    record = deepcopy(_record("disguised.evidence.json"))
    if mutation == "missing-field":
        del record["traversal"]
    elif mutation == "unknown-field":
        record["extra"] = True
    elif mutation == "wrong-schema":
        record["schema_version"] = "other"
    elif mutation == "wrong-traversal":
        record["traversal"] = "direct-only"
    elif mutation == "boolean-count":
        record["candidate_declaration_count"] = True
    elif mutation == "unsorted-closure":
        record["proof_dependency_closure"] = list(
            reversed(cast(list[object], record["proof_dependency_closure"]))
        )
    elif mutation == "duplicate-direct":
        direct = cast(list[object], record["direct_proof_dependencies"])
        record["direct_proof_dependencies"] = [*direct, *direct]
    elif mutation == "missing-direct-from-closure":
        record["proof_dependency_closure"] = ["AutoLean.ProofDependencyFixture.forbiddenStrong"]
    elif mutation == "candidate-outside-closure":
        record["candidate_module_dependencies"] = [
            "AutoLean.ProofDependencyFixture.allowedWrapper",
            "AutoLean.ProofDependencyFixture.forbiddenStrong",
            "AutoLean.ProofDependencyFixture.other",
        ]
    else:
        record["proof_dependency_closure"] = ["AutoLean.ProofDependencyFixture.disguised"]
        record["direct_proof_dependencies"] = ["AutoLean.ProofDependencyFixture.disguised"]
        record["candidate_module_dependencies"] = ["AutoLean.ProofDependencyFixture.disguised"]

    with pytest.raises(ProofDependencyEvidenceError, match=message):
        ProofDependencyEvidence.from_mapping(record)


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("missing-target-denial", "must include the target"),
        ("overlap", "overlap"),
        ("unsorted", "sorted and unique"),
        ("target-mismatch", "different target"),
    ),
)
def test_policy_and_target_binding_fail_closed(mutation: str, message: str) -> None:
    evidence = ProofDependencyEvidence.from_mapping(_record("nonalias.evidence.json"))
    record = deepcopy(_record("nonalias.policy.json"))
    if mutation == "missing-target-denial":
        record["denied_dependencies"] = ["AutoLean.ProofDependencyFixture.exactTypeAlias"]
    elif mutation == "overlap":
        record["allowed_dependencies"] = ["AutoLean.ProofDependencyFixture.exactTypeAlias"]
    elif mutation == "unsorted":
        record["denied_dependencies"] = list(
            reversed(cast(list[object], record["denied_dependencies"]))
        )
    else:
        record["target_declaration"] = "AutoLean.ProofDependencyFixture.other"
        record["denied_dependencies"] = ["AutoLean.ProofDependencyFixture.other"]

    if mutation == "target-mismatch":
        policy = ProofDependencyPolicy.from_mapping(record)
        with pytest.raises(ProofDependencyRejected, match=message):
            evaluate_proof_dependency_policy(evidence, policy)
    else:
        with pytest.raises(ProofDependencyEvidenceError, match=message):
            ProofDependencyPolicy.from_mapping(record)


def test_validation_cli_accepts_positive_and_rejects_disguised_fixture(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert (
        proof_dependency_gate.main(
            [
                "validate",
                "--policy",
                str(_FIXTURES / "nonalias.policy.json"),
                "--evidence",
                str(_FIXTURES / "nonalias.evidence.json"),
            ]
        )
        == 0
    )
    accepted = json.loads(capsys.readouterr().out)
    assert accepted["accepted"] is True

    assert (
        proof_dependency_gate.main(
            [
                "validate",
                "--policy",
                str(_FIXTURES / "disguised.policy.json"),
                "--evidence",
                str(_FIXTURES / "disguised.evidence.json"),
            ]
        )
        == 2
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "forbiddenStrong" in captured.err


@pytest.mark.integration
def test_source_v2_helper_replays_committed_query_fixtures() -> None:
    if os.name != "posix" or shutil.which("docker") is None:
        pytest.skip("requires Linux Docker and the operator-local source-v2 image")
    available = subprocess.run(
        ["docker", "image", "inspect", _SOURCE_V2_IMAGE],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if available.returncode != 0:
        pytest.skip("operator-local source-v2 image is unavailable")

    observations = proof_dependency_gate.replay_fixture_evidence(image=_SOURCE_V2_IMAGE)

    assert tuple(item["declaration"] for item in observations) == (
        "AutoLean.ProofDependencyFixture.nonalias",
        "AutoLean.ProofDependencyFixture.exactTypeAlias",
        "AutoLean.ProofDependencyFixture.disguised",
        "AutoLean.ProofDependencyFixture.quotientProbe",
    )
