from __future__ import annotations

import hashlib
import json
from pathlib import Path

import autolean_builder.self_calibration as self_calibration
import pytest
from autolean_builder import (
    ReferenceManifestV1,
    SelfCalibrationCompileSpikeStateV1,
    SelfCalibrationError,
    SelfCalibrationEvidenceAssuranceV1,
    SelfCalibrationLibraryBuildEvidenceV1,
    SelfCalibrationLibraryBuildStatusV1,
    SelfCalibrationLibraryCompileReceiptV1,
    SelfCalibrationReviewerKindV1,
    SelfCalibrationRoleV1,
    SelfCalibrationRoundV1,
    library_build_evidence_integrity_checksum_sha256,
    load_pilot_manifest,
    load_self_calibration_round,
)
from autolean_contracts import canonical_json_bytes

_ROOT = Path(__file__).parents[2]
_PILOT_MANIFEST_PATH = _ROOT / "Builder" / "pilots" / "self-calibration" / "pilot-manifest.v1.json"
_ROUND_PATH = _ROOT / "Builder" / "pilots" / "self-calibration" / "round-01.v1.json"
_REFERENCE_MANIFEST_PATH = _ROOT / "Builder" / "references" / "manifest.v1.json"


def _manifest():
    return load_pilot_manifest(_PILOT_MANIFEST_PATH)


def _reference_manifest() -> ReferenceManifestV1:
    return ReferenceManifestV1.load(_REFERENCE_MANIFEST_PATH)


def _round():
    return load_self_calibration_round(
        _ROUND_PATH,
        pilot_manifest=_manifest(),
        reference_manifest=_reference_manifest(),
        library_root=_ROOT / "Library",
    )


def _rehash_candidate(payload: dict[str, object]) -> None:
    payload["integrity_checksum_sha256"] = _checksum(
        {
            key: payload[key]
            for key in (
                "candidate_id",
                "revision",
                "kind",
                "boundary_summary",
                "required_mechanisms",
                "explicit_out_of_scope",
            )
        }
    )


def _rehash_report(payload: dict[str, object]) -> None:
    payload["integrity_checksum_sha256"] = _checksum(
        {
            key: payload[key]
            for key in (
                "report_id",
                "role",
                "candidate_id",
                "candidate_revision",
                "candidate_integrity_checksum_sha256",
                "reviewer_id",
                "reviewer_kind",
                "independence_group",
                "identity_binding",
                "evidence_sha256",
                "state",
                "finding",
                "authoring_mode",
            )
        }
    )


def _rehash_round(payload: dict[str, object]) -> None:
    content = dict(payload)
    content.pop("integrity_checksum_sha256")
    payload["integrity_checksum_sha256"] = _checksum(content)


def _rehash_compile_spike(packet: dict[str, object]) -> None:
    packet["integrity_checksum_sha256"] = _checksum(
        {
            key: packet[key]
            for key in ("packet_id", "candidate_ids", "state", "blocker_ids", "receipt")
        }
    )


def _rehash_library_evidence(evidence: dict[str, object]) -> None:
    evidence["integrity_checksum_sha256"] = _checksum(
        {
            key: evidence[key]
            for key in (
                "evidence_id",
                "status",
                "library_input_tree_sha256",
                "lake_manifest_sha256",
                "toolchain_sha256",
                "mathlib_revision",
                "dependency_tree_schema",
                "dependency_tree_sha256",
                "dependency_manifest_sha256",
                "dependency_entry_count",
                "dependency_directory_count",
                "dependency_regular_file_count",
                "dependency_symlink_count",
                "dependency_total_file_bytes",
                "target_modules",
                "exit_status",
                "build_report_sha256",
                "tracked_preselection_receipt",
            )
        }
    )


def _complete_payload() -> dict[str, object]:
    payload = _round().model_dump(mode="json")
    reports = payload["role_reports"]
    for report in reports:
        _mark_report_externally_verified(report)
    for candidate in payload["candidates"]:
        for role in ("source_interpreter", "research_alignment", "library_steward"):
            role_id = role.replace("_", "-")
            report = dict(reports[0])
            report.update(
                {
                    "report_id": f"test-{candidate['candidate_id']}-{role_id}",
                    "role": role,
                    "candidate_id": candidate["candidate_id"],
                    "candidate_revision": candidate["revision"],
                    "candidate_integrity_checksum_sha256": candidate["integrity_checksum_sha256"],
                    "reviewer_id": f"agent:test-{candidate['candidate_id']}-{role_id}",
                    "independence_group": f"test-{candidate['candidate_id']}-{role_id}-group",
                    "evidence_sha256": _checksum(
                        f"test-evidence:{candidate['candidate_id']}:{role}"
                    ),
                    "finding": "Structured test report; free text has no authority semantics.",
                }
            )
            _mark_report_externally_verified(report)
            reports.append(report)
    for blocker in payload["blockers"]:
        blocker["state"] = "resolved"
    receipt = _passed_library_receipt().model_dump(mode="json")
    receipt["assurance"] = "external_receipt_pending_verification"
    receipt["external_run_receipt"] = {
        "receipt_id": "test-external-library-run",
        "authority_id": "test-run-authority",
        "build_evidence_integrity_checksum_sha256": receipt["evidence"][
            "integrity_checksum_sha256"
        ],
        "external_signature": "x" * 32,
    }
    payload["compile_spike"].update(
        {
            "state": "passed",
            "blocker_ids": [],
            "receipt": receipt,
        }
    )
    _rehash_compile_spike(payload["compile_spike"])
    payload["state"] = "complete"
    payload["disposition"] = "continue"
    _rehash_round(payload)
    return payload


def _mark_report_externally_verified(report: dict[str, object]) -> None:
    report["state"] = "verified"
    report["identity_binding"] = {
        "assurance": "external_receipt_pending_verification",
        "external_receipt": {
            "receipt_id": f"test-{report['report_id']}-identity-receipt",
            "authority_id": "test-identity-authority",
            "report_evidence_sha256": report["evidence_sha256"],
            "reviewer_id": report["reviewer_id"],
            "independence_group": report["independence_group"],
            "execution_run_receipt_sha256": _checksum(f"test-run:{report['report_id']}"),
            "external_signature": "y" * 32,
        },
    }
    _rehash_report(report)


def _checksum(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def test_round_01_is_a_bound_incomplete_agent_record() -> None:
    round_record = _round()

    assert round_record.disposition.value == "gap"
    assert round_record.compile_spike.state.value == "partial_passed_with_gap"
    assert round_record.compile_spike.receipt is not None
    assert round_record.compile_spike.receipt.evidence.library_input_tree_sha256 == (
        "87890952359a75d408505ed6f4462720cdb8a3f82cc80dd783f99d34585fac70"
    )
    assert round_record.compile_spike.receipt.evidence.build_report_sha256 == (
        "79325354563c19c5b32134f5102f964c11a738444a68746e85c8d03f5ab92c15"
    )
    assert round_record.compile_spike.receipt.evidence.dependency_tree_sha256 == (
        "43f889366a4c5dc6daaed5b56cf3704e82e491ff90f2044602a187d7da2bfe62"
    )
    assert round_record.compile_spike.receipt.evidence.dependency_total_file_bytes == 6482481367
    tracked = round_record.compile_spike.receipt.evidence.tracked_preselection_receipt
    assert tracked is not None
    assert tracked.packet_sha256 == (
        "d58b0d7964c031438e89f28e4c6f627463e72a6272ec115d6d27e3c54110b065"
    )
    assert tracked.receipt_sha256 == (
        "5e2d0b9d119582f42dc4434eeedd067f19f5b82cac9f42f5ac17ccaed09312e3"
    )
    assert round_record.compile_spike.receipt.evidence.target_modules == (
        "AutoLeanLibrary",
        "AutoLeanLibrary.Fixtures.Dag.Certificate",
        "AutoLeanLibrary.Fixtures.ModelTheory.Packet",
    )
    assert {report.role for report in round_record.role_reports} == {
        SelfCalibrationRoleV1.FORMAL_ARCHITECT,
        SelfCalibrationRoleV1.ADVERSARIAL_REVIEWER,
    }
    assert all(
        report.reviewer_kind.value == "automated_agent" for report in round_record.role_reports
    )
    assert round_record.open_problem_alignment.non_claim == "no_open_problem_claim"
    assert round_record.open_problem_alignment.solves_open_problem is False
    assert round_record.open_problem_alignment.claims_novelty is False
    assert all(
        report.identity_binding.assurance
        is SelfCalibrationEvidenceAssuranceV1.UNTRUSTED_SELF_REPORTED
        for report in round_record.role_reports
    )
    assert {
        blocker.affected_role
        for blocker in round_record.blockers
        if blocker.affected_role is not None
    } == {
        SelfCalibrationRoleV1.SOURCE_INTERPRETER,
        SelfCalibrationRoleV1.RESEARCH_ALIGNMENT,
        SelfCalibrationRoleV1.LIBRARY_STEWARD,
    }


def test_tracked_preselection_receipt_requires_a_library_root_and_exact_digest(
    tmp_path: Path,
) -> None:
    with pytest.raises(SelfCalibrationError, match="requires a Library root"):
        load_self_calibration_round(
            _ROUND_PATH,
            pilot_manifest=_manifest(),
            reference_manifest=_reference_manifest(),
        )

    payload = _round().model_dump(mode="json")
    evidence = payload["compile_spike"]["receipt"]["evidence"]
    evidence["tracked_preselection_receipt"]["receipt_sha256"] = "0" * 64
    _rehash_library_evidence(evidence)
    _rehash_compile_spike(payload["compile_spike"])
    _rehash_round(payload)
    altered_round_path = tmp_path / "altered-round.v1.json"
    altered_round_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(SelfCalibrationError, match="receipt digest differs"):
        load_self_calibration_round(
            altered_round_path,
            pilot_manifest=_manifest(),
            reference_manifest=_reference_manifest(),
            library_root=_ROOT / "Library",
        )


def test_round_rebind_rejects_another_pilot_manifest() -> None:
    round_record = _round()
    payload = _manifest().model_dump(mode="python")
    payload["graphs"][1]["domain"] = "different but syntactically valid pilot graph"
    different_manifest = type(_manifest()).model_validate(payload)

    with pytest.raises(SelfCalibrationError, match="another pilot manifest"):
        round_record.assert_binds_manifest(different_manifest)


def test_round_rebind_rejects_forged_reference_rights_binding() -> None:
    payload = _round().model_dump(mode="json")
    payload["textbook"]["rights_binding_sha256"] = "0" * 64
    _rehash_round(payload)
    forged = SelfCalibrationRoundV1.model_validate(payload)

    with pytest.raises(SelfCalibrationError, match="rights binding differs"):
        forged.assert_binds_reference_manifest(_reference_manifest())


def test_candidate_hash_rejects_tampering() -> None:
    payload = _round().model_dump(mode="json")
    payload["candidates"][0]["boundary_summary"] = "weakened boundary after recording"

    with pytest.raises(ValueError, match="candidate integrity checksum"):
        SelfCalibrationRoundV1.model_validate(payload)


def test_round_hash_rejects_tampering_after_valid_inner_records() -> None:
    payload = _round().model_dump(mode="json")
    payload["open_problem_alignment"]["research_direction"] = "different research direction"

    with pytest.raises(ValueError, match="round integrity checksum"):
        SelfCalibrationRoundV1.model_validate(payload)


def test_incomplete_round_cannot_use_continue_or_resolve_every_blocker() -> None:
    payload = _round().model_dump(mode="json")
    payload["disposition"] = "continue"
    _rehash_round(payload)

    with pytest.raises(ValueError, match="partial compile spike requires a gap disposition"):
        SelfCalibrationRoundV1.model_validate(payload)

    payload = _round().model_dump(mode="json")
    for blocker in payload["blockers"]:
        blocker["state"] = "resolved"
    _rehash_round(payload)

    with pytest.raises(
        ValueError, match="blocked compile spike must reference only active blockers"
    ):
        SelfCalibrationRoundV1.model_validate(payload)


def test_complete_round_requires_every_verified_role_and_closed_blockers() -> None:
    payload = _round().model_dump(mode="json")
    payload["state"] = "complete"
    payload["disposition"] = "continue"
    for blocker in payload["blockers"]:
        blocker["state"] = "resolved"
    payload["compile_spike"]["state"] = SelfCalibrationCompileSpikeStateV1.PASSED.value
    payload["compile_spike"]["blocker_ids"] = []
    _rehash_round(payload)

    with pytest.raises(
        ValueError, match="passed compile spike requires a successful build receipt"
    ):
        SelfCalibrationRoundV1.model_validate(payload)

    payload = _round().model_dump(mode="json")
    payload["state"] = "complete"
    payload["disposition"] = "continue"
    for blocker in payload["blockers"]:
        blocker["state"] = "resolved"
    payload["compile_spike"].update(
        {
            "state": "passed",
            "blocker_ids": [],
            "receipt": _passed_library_receipt().model_dump(mode="json"),
        }
    )
    _rehash_compile_spike(payload["compile_spike"])
    _rehash_round(payload)

    with pytest.raises(ValueError, match="requires every role report"):
        SelfCalibrationRoundV1.model_validate(payload)


def test_complete_round_fails_closed_without_library_root_or_external_verifiers() -> None:
    round_record = SelfCalibrationRoundV1.model_validate(_complete_payload())

    with pytest.raises(SelfCalibrationError, match="requires a Library root"):
        round_record.assert_ready_for_completion(
            pilot_manifest=_manifest(),
            reference_manifest=_reference_manifest(),
            library_root=None,
            identity_receipt_verifier=None,
            library_receipt_verifier=None,
        )
    with pytest.raises(SelfCalibrationError, match="requires external receipt verifiers"):
        round_record.assert_ready_for_completion(
            pilot_manifest=_manifest(),
            reference_manifest=_reference_manifest(),
            library_root=_ROOT / "Library",
            identity_receipt_verifier=None,
            library_receipt_verifier=None,
        )


def test_forged_candidate_revision_cannot_reuse_role_reports() -> None:
    payload = _round().model_dump(mode="json")
    candidate = payload["candidates"][0]
    candidate["revision"] = "forged-revision"
    _rehash_candidate(candidate)

    with pytest.raises(ValueError, match="candidate revision and content"):
        SelfCalibrationRoundV1.model_validate(payload)


def test_same_independence_group_for_architect_and_adversary_is_rejected() -> None:
    payload = _round().model_dump(mode="json")
    adversarial = payload["role_reports"][1]
    adversarial["independence_group"] = payload["role_reports"][0]["independence_group"]
    _rehash_report(adversarial)

    with pytest.raises(ValueError, match="separate independence groups"):
        SelfCalibrationRoundV1.model_validate(payload)


def test_round_cannot_be_represented_as_human_or_expert_review() -> None:
    payload = _round().model_dump(mode="json")
    report = payload["role_reports"][0]
    report["reviewer_kind"] = SelfCalibrationReviewerKindV1.HUMAN
    _rehash_report(report)

    with pytest.raises(ValueError, match="cannot record human or expert review"):
        SelfCalibrationRoundV1.model_validate(payload)


def test_round_denies_all_authoritative_actions() -> None:
    round_record = _round()

    for action in (
        round_record.issue_admission_receipt,
        round_record.freeze_builder_statement,
        round_record.handoff_to_prover,
        round_record.authorize_model_egress,
        round_record.promote,
    ):
        with pytest.raises(SelfCalibrationError, match="non-authoritative"):
            action()


def test_library_compile_receipt_recomputes_local_input_bindings() -> None:
    evidence = SelfCalibrationLibraryBuildEvidenceV1.model_construct(
        evidence_id="test-library-build-evidence",
        status=SelfCalibrationLibraryBuildStatusV1.FAILED,
        library_input_tree_sha256="0" * 64,
        lake_manifest_sha256="1" * 64,
        toolchain_sha256="2" * 64,
        mathlib_revision="8f9d9cff6bd728b17a24e163c9402775d9e6a365",
        dependency_tree_schema="autolean.library-dependency-tree.v1",
        dependency_tree_sha256="4" * 64,
        dependency_manifest_sha256="5" * 64,
        dependency_entry_count=3,
        dependency_directory_count=1,
        dependency_regular_file_count=1,
        dependency_symlink_count=1,
        dependency_total_file_bytes=1,
        target_modules=("AutoLeanLibrary",),
        exit_status=1,
        build_report_sha256="3" * 64,
        integrity_checksum_sha256="0" * 64,
    )
    evidence = evidence.model_copy(
        update={
            "integrity_checksum_sha256": library_build_evidence_integrity_checksum_sha256(evidence)
        }
    )
    receipt = SelfCalibrationLibraryCompileReceiptV1(
        receipt_id="test-library-compile-receipt",
        evidence=evidence,
        assurance=SelfCalibrationEvidenceAssuranceV1.UNTRUSTED_SELF_REPORTED,
    )

    with pytest.raises(SelfCalibrationError, match="input tree differs"):
        receipt.assert_matches_library_root(_ROOT / "Library")


def test_library_compile_receipt_rejects_a_target_absent_from_the_bound_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = _passed_library_receipt()
    evidence_payload = receipt.evidence.model_dump(mode="python")
    evidence_payload["target_modules"] = ("AutoLeanLibrary.AbsentTarget",)
    provisional_evidence = SelfCalibrationLibraryBuildEvidenceV1.model_construct(**evidence_payload)
    evidence_payload["integrity_checksum_sha256"] = (
        library_build_evidence_integrity_checksum_sha256(provisional_evidence)
    )
    evidence = SelfCalibrationLibraryBuildEvidenceV1.model_validate(evidence_payload)
    receipt_payload = receipt.model_dump(mode="json")
    receipt_payload["evidence"] = evidence.model_dump(mode="json")
    receipt = SelfCalibrationLibraryCompileReceiptV1.model_validate(receipt_payload)
    monkeypatch.setattr(
        self_calibration,
        "_library_input_tree_sha256",
        lambda _root: evidence.library_input_tree_sha256,
    )
    monkeypatch.setattr(
        self_calibration,
        "_library_file_sha256",
        lambda _path: evidence.lake_manifest_sha256,
    )
    monkeypatch.setattr(
        self_calibration,
        "_library_toolchain_sha256",
        lambda _root: evidence.toolchain_sha256,
    )

    with pytest.raises(SelfCalibrationError, match="target module is absent"):
        receipt.assert_matches_library_root(_ROOT / "Library")


def _passed_library_receipt() -> SelfCalibrationLibraryCompileReceiptV1:
    evidence = SelfCalibrationLibraryBuildEvidenceV1.model_construct(
        evidence_id="test-library-passed-evidence",
        status=SelfCalibrationLibraryBuildStatusV1.PASSED,
        library_input_tree_sha256="4" * 64,
        lake_manifest_sha256=("e2a93c904f51195d6740cd9abfb35ab155dc0157e0e46642dce0d364b68a9a89"),
        toolchain_sha256=("26df5f74b79af0cd9e298b6583993699a54938d047ba1919428da80d3ae80c6e"),
        mathlib_revision="8f9d9cff6bd728b17a24e163c9402775d9e6a365",
        dependency_tree_schema="autolean.library-dependency-tree.v1",
        dependency_tree_sha256="5" * 64,
        dependency_manifest_sha256="6" * 64,
        dependency_entry_count=2,
        dependency_directory_count=1,
        dependency_regular_file_count=1,
        dependency_symlink_count=0,
        dependency_total_file_bytes=1,
        target_modules=("AutoLeanLibrary",),
        exit_status=0,
        build_report_sha256="7" * 64,
        integrity_checksum_sha256="0" * 64,
    )
    evidence = evidence.model_copy(
        update={
            "integrity_checksum_sha256": library_build_evidence_integrity_checksum_sha256(evidence)
        }
    )
    return SelfCalibrationLibraryCompileReceiptV1(
        receipt_id="test-library-passed-receipt",
        evidence=evidence,
        assurance=SelfCalibrationEvidenceAssuranceV1.UNTRUSTED_SELF_REPORTED,
    )
