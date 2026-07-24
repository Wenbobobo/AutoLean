"""Public-safe, non-authoritative records for Builder self-calibration.

These records make early multi-agent disagreements reproducible.  They deliberately do
not create a statement contract, rights decision, proof task, or promotion capability.
"""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Literal, Never, Protocol, cast

from autolean_contracts.base import ContractModel
from autolean_contracts.hashing import canonical_json_bytes
from pydantic import Field, model_validator

from .pilot_harness import PilotManifestV1
from .reference_cache import ReferenceEntryV1, ReferenceManifestV1

_IDENTIFIER = r"^[a-z][a-z0-9-]{2,95}$"
_SHA256 = r"^[0-9a-f]{64}$"


class SelfCalibrationError(ValueError):
    """A self-calibration record is malformed, stale, or asked to grant authority."""


class SelfCalibrationRoleV1(StrEnum):
    SOURCE_INTERPRETER = "source_interpreter"
    FORMAL_ARCHITECT = "formal_architect"
    ADVERSARIAL_REVIEWER = "adversarial_reviewer"
    RESEARCH_ALIGNMENT = "research_alignment"
    LIBRARY_STEWARD = "library_steward"


class SelfCalibrationReportStateV1(StrEnum):
    RECORDED = "recorded"
    INCOMPLETE = "incomplete"
    VERIFIED = "verified"


class SelfCalibrationRoundStateV1(StrEnum):
    INCOMPLETE = "incomplete"
    COMPLETE = "complete"


class SelfCalibrationDispositionV1(StrEnum):
    CONTINUE = "continue"
    COMPILE_SPIKE = "compile_spike"
    GAP = "gap"
    STOP = "stop"


class SelfCalibrationCandidateKindV1(StrEnum):
    CLOSED_ONLY = "closed_only"
    STRUCTURAL_OPEN_FORMULA = "structural_open_formula"


class SelfCalibrationReviewerKindV1(StrEnum):
    AUTOMATED_AGENT = "automated_agent"
    HUMAN = "human"
    DOMAIN_EXPERT = "domain_expert"


class SelfCalibrationBlockerKindV1(StrEnum):
    ROLE_REPORT_MISSING = "role_report_missing"
    INDEPENDENCE_INSUFFICIENT = "independence_insufficient"
    LIBRARY_COMPILE_SPIKE_NOT_RUN = "library_compile_spike_not_run"
    SOURCE_SCOPE_REVIEW_PENDING = "source_scope_review_pending"
    MATHLIB_CENSUS_PENDING = "mathlib_census_pending"
    HUMAN_OR_EXPERT_REVIEW_NOT_REQUESTED = "human_or_expert_review_not_requested"
    CANDIDATE_SCOPE_GAP = "candidate_scope_gap"


class SelfCalibrationBlockerStateV1(StrEnum):
    ACTIVE = "active"
    RESOLVED = "resolved"


class SelfCalibrationCompileSpikeStateV1(StrEnum):
    NOT_STARTED = "not_started"
    BLOCKED = "blocked"
    PARTIAL_PASSED_WITH_GAP = "partial_passed_with_gap"
    PASSED = "passed"
    FAILED = "failed"


class SelfCalibrationEvidenceAssuranceV1(StrEnum):
    """Whether a record has an external receipt still requiring verifier validation."""

    UNTRUSTED_SELF_REPORTED = "untrusted_self_reported"
    EXTERNAL_RECEIPT_PENDING_VERIFICATION = "external_receipt_pending_verification"


class SelfCalibrationLibraryBuildStatusV1(StrEnum):
    PASSED = "passed"
    PARTIAL_PASSED_WITH_GAP = "partial_passed_with_gap"
    FAILED = "failed"


class SelfCalibrationCandidateV1(ContractModel):
    """One immutable candidate boundary, represented without source excerpts."""

    candidate_id: str = Field(pattern=_IDENTIFIER)
    revision: str = Field(min_length=1, max_length=128)
    kind: SelfCalibrationCandidateKindV1
    boundary_summary: str = Field(min_length=1)
    required_mechanisms: tuple[str, ...] = Field(min_length=1)
    explicit_out_of_scope: tuple[str, ...] = Field(min_length=1)
    integrity_checksum_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_integrity_checksum(self) -> SelfCalibrationCandidateV1:
        if self.integrity_checksum_sha256 != candidate_integrity_checksum_sha256(self):
            raise ValueError(
                "self-calibration candidate integrity checksum does not bind its payload"
            )
        return self


class SelfCalibrationTextbookBindingV1(ContractModel):
    """A source/rights identifier binding; never a rights decision or egress grant."""

    reference_id: str = Field(pattern=r"^[a-z0-9][a-z0-9.-]{2,127}$")
    artifact_sha256: str = Field(pattern=_SHA256)
    parent_reference_id: str = Field(pattern=r"^[a-z0-9][a-z0-9.-]{2,127}$")
    parent_artifact_sha256: str = Field(pattern=_SHA256)
    anchor_ids: tuple[str, ...] = Field(min_length=1)
    reference_manifest_sha256: str = Field(pattern=_SHA256)
    rights_binding_sha256: str = Field(pattern=_SHA256)
    model_egress: Literal["forbidden"] = "forbidden"

    @model_validator(mode="after")
    def validate_anchor_ids(self) -> SelfCalibrationTextbookBindingV1:
        if len(self.anchor_ids) != len(set(self.anchor_ids)):
            raise ValueError("self-calibration textbook anchors must be unique")
        return self


class SelfCalibrationExternalIdentityReceiptV1(ContractModel):
    """A future external identity/run receipt, never verified by this data model alone."""

    receipt_id: str = Field(pattern=_IDENTIFIER)
    authority_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
    report_evidence_sha256: str = Field(pattern=_SHA256)
    reviewer_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
    independence_group: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
    execution_run_receipt_sha256: str = Field(pattern=_SHA256)
    external_signature: str = Field(min_length=32, max_length=4096)


class SelfCalibrationIdentityBindingV1(ContractModel):
    """Explicitly separates self-reported grouping from externally verified identity."""

    assurance: SelfCalibrationEvidenceAssuranceV1
    external_receipt: SelfCalibrationExternalIdentityReceiptV1 | None = None

    @model_validator(mode="after")
    def validate_assurance_shape(self) -> SelfCalibrationIdentityBindingV1:
        if self.assurance is SelfCalibrationEvidenceAssuranceV1.UNTRUSTED_SELF_REPORTED:
            if self.external_receipt is not None:
                raise ValueError("untrusted self-report cannot carry an external identity receipt")
        elif self.external_receipt is None:
            raise ValueError("external identity assurance requires an external receipt")
        return self


class SelfCalibrationIdentityReceiptVerifierV1(Protocol):
    """External authority interface required before identity evidence is trusted."""

    def verify(
        self,
        *,
        report: SelfCalibrationRoleReportV1,
        receipt: SelfCalibrationExternalIdentityReceiptV1,
    ) -> None: ...


class SelfCalibrationRoleReportV1(ContractModel):
    """A write-once role report bound to exactly one candidate revision."""

    report_id: str = Field(pattern=_IDENTIFIER)
    role: SelfCalibrationRoleV1
    candidate_id: str = Field(pattern=_IDENTIFIER)
    candidate_revision: str = Field(min_length=1, max_length=128)
    candidate_integrity_checksum_sha256: str = Field(pattern=_SHA256)
    reviewer_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
    reviewer_kind: SelfCalibrationReviewerKindV1
    independence_group: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
    identity_binding: SelfCalibrationIdentityBindingV1
    evidence_sha256: str = Field(pattern=_SHA256)
    state: SelfCalibrationReportStateV1
    finding: str = Field(min_length=1)
    authoring_mode: Literal["independent_write_once"] = "independent_write_once"
    integrity_checksum_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_integrity_checksum(self) -> SelfCalibrationRoleReportV1:
        if self.integrity_checksum_sha256 != role_report_integrity_checksum_sha256(self):
            raise ValueError(
                "self-calibration role report integrity checksum does not bind its payload"
            )
        return self


class SelfCalibrationBlockerV1(ContractModel):
    blocker_id: str = Field(pattern=_IDENTIFIER)
    kind: SelfCalibrationBlockerKindV1
    state: SelfCalibrationBlockerStateV1
    affected_role: SelfCalibrationRoleV1 | None = None
    affected_candidate_ids: tuple[str, ...] = ()
    evidence_sha256: str = Field(pattern=_SHA256)
    resolution_required: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_kind_scope(self) -> SelfCalibrationBlockerV1:
        if self.kind is SelfCalibrationBlockerKindV1.ROLE_REPORT_MISSING:
            if self.affected_role is None:
                raise ValueError("missing-role blocker must name the missing role")
        elif self.affected_role is not None:
            raise ValueError("only missing-role blockers may name an affected role")
        if len(self.affected_candidate_ids) != len(set(self.affected_candidate_ids)):
            raise ValueError("self-calibration blocker candidate identifiers must be unique")
        return self


class SelfCalibrationOpenProblemAlignmentV1(ContractModel):
    alignment_id: str = Field(pattern=_IDENTIFIER)
    research_direction: str = Field(min_length=1)
    dependency_rationale: str = Field(min_length=1)
    non_claim: Literal["no_open_problem_claim"] = "no_open_problem_claim"
    solves_open_problem: Literal[False] = False
    claims_novelty: Literal[False] = False


class SelfCalibrationLibraryLockV1(ContractModel):
    lock_id: str = Field(pattern=_IDENTIFIER)
    lean_toolchain: str = Field(min_length=1)
    toolchain_sha256: str = Field(pattern=_SHA256)
    mathlib_revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    lake_manifest_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_toolchain_checksum(self) -> SelfCalibrationLibraryLockV1:
        if self.toolchain_sha256 != _sha256(self.lean_toolchain.encode("utf-8")):
            raise ValueError("Library lock toolchain checksum does not bind its toolchain")
        return self


class SelfCalibrationTrackedPreselectionReceiptV1(ContractModel):
    """A content-addressed reference to a public-safe Library preselection receipt."""

    record_kind: Literal["preselection_compile_spike"] = "preselection_compile_spike"
    packet_id: str = Field(pattern=_IDENTIFIER)
    receipt_id: str = Field(pattern=_IDENTIFIER)
    packet_path: str = Field(min_length=1, max_length=255)
    packet_sha256: str = Field(pattern=_SHA256)
    packet_content_sha256: str = Field(pattern=_SHA256)
    receipt_path: str = Field(min_length=1, max_length=255)
    receipt_sha256: str = Field(pattern=_SHA256)
    receipt_schema: Literal["autolean.library-compile-receipt.v2"] = (
        "autolean.library-compile-receipt.v2"
    )
    source_tree_schema: Literal["autolean.library-build-input-tree.v2"] = (
        "autolean.library-build-input-tree.v2"
    )
    verification_script_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_paths(self) -> SelfCalibrationTrackedPreselectionReceiptV1:
        if not _is_safe_library_record_path(self.packet_path):
            raise ValueError("tracked preselection packet path is unsafe")
        if not _is_safe_library_record_path(self.receipt_path):
            raise ValueError("tracked preselection receipt path is unsafe")
        if self.packet_path == self.receipt_path:
            raise ValueError("tracked preselection packet and receipt paths must differ")
        return self

    def assert_matches_library_root(
        self,
        library_root: Path,
        *,
        evidence: SelfCalibrationLibraryBuildEvidenceV1,
        expected_candidate_ids: tuple[str, ...] | None = None,
        expected_source: SelfCalibrationTextbookBindingV1 | None = None,
    ) -> None:
        """Cross-check the receipt, packet, and copied build evidence without trusting prose."""

        packet_path = _resolve_library_record_path(library_root, self.packet_path)
        receipt_path = _resolve_library_record_path(library_root, self.receipt_path)
        if _library_file_sha256(packet_path) != self.packet_sha256:
            raise SelfCalibrationError("tracked preselection packet digest differs from Library")
        if _library_file_sha256(receipt_path) != self.receipt_sha256:
            raise SelfCalibrationError("tracked preselection receipt digest differs from Library")
        packet = _read_library_json_object(packet_path, label="tracked preselection packet")
        receipt = _read_library_json_object(receipt_path, label="tracked preselection receipt")
        _require_json_fields(
            packet,
            {
                "schema_version": "autolean.library-model-theory-compile-spike.v1",
                "record_kind": self.record_kind,
                "packet_id": self.packet_id,
                "record_state": "staging",
                "state": SelfCalibrationCompileSpikeStateV1.PARTIAL_PASSED_WITH_GAP.value,
                "candidate_selection_state": "not_selected",
                "selected_candidate_id": None,
                "contains_absolute_paths": False,
                "contains_source_text": False,
            },
            label="tracked preselection packet",
        )
        packet_without_backlink = dict(packet)
        packet_without_backlink.pop("compile_receipt", None)
        if _sha256(canonical_json_bytes(packet_without_backlink)) != self.packet_content_sha256:
            raise SelfCalibrationError(
                "tracked preselection packet canonical digest differs from Library"
            )
        _require_json_fields(
            receipt,
            {
                "schema_version": self.receipt_schema,
                "record_kind": self.record_kind,
                "receipt_id": self.receipt_id,
                "packet_id": self.packet_id,
                "receipt_state": SelfCalibrationCompileSpikeStateV1.PARTIAL_PASSED_WITH_GAP.value,
                "candidate_selection_state": "not_selected",
                "selected_candidate_id": None,
                "build_exit_code": evidence.exit_status,
                "source_tree_schema": self.source_tree_schema,
                "source_tree_sha256": evidence.library_input_tree_sha256,
                "packet_content_sha256": self.packet_content_sha256,
                "verification_script_sha256": self.verification_script_sha256,
                "build_report_sha256": evidence.build_report_sha256,
                "contains_absolute_paths": False,
                "contains_raw_build_output": False,
            },
            label="tracked preselection receipt",
        )
        packet_backlink = _json_object(
            packet.get("compile_receipt"), label="tracked preselection packet backlink"
        )
        _require_json_fields(
            packet_backlink,
            {"path": self.receipt_path, "sha256": self.receipt_sha256},
            label="tracked preselection packet backlink",
        )
        packet_environment = _json_object(packet.get("environment"), label="packet environment")
        receipt_environment = _json_object(receipt.get("environment"), label="receipt environment")
        expected_environment: dict[str, object] = {
            "lean_toolchain": _library_toolchain_text(library_root),
            "mathlib_revision": evidence.mathlib_revision,
            "lake_manifest_sha256": evidence.lake_manifest_sha256,
        }
        _require_json_fields(packet_environment, expected_environment, label="packet environment")
        _require_json_fields(receipt_environment, expected_environment, label="receipt environment")
        expected_dependency_tree = evidence.dependency_tree_binding()
        _require_json_fields(
            receipt_environment,
            {"dependency_tree": expected_dependency_tree},
            label="receipt environment dependency tree",
        )
        if (
            _json_string_tuple(receipt.get("targets"), label="receipt targets")
            != evidence.target_modules
        ):
            raise SelfCalibrationError("tracked preselection receipt targets differ from evidence")
        build_report = _json_object(receipt.get("build_report"), label="tracked build report")
        if _sha256(canonical_json_bytes(build_report)) != evidence.build_report_sha256:
            raise SelfCalibrationError("tracked preselection build report digest differs")
        _require_json_fields(
            build_report,
            {
                "schema_version": "autolean.library-downstream-build.v2",
                "source_tree_schema": self.source_tree_schema,
                "source_tree_sha256": evidence.library_input_tree_sha256,
                "mathlib_revision": evidence.mathlib_revision,
                "lake_manifest_sha256": evidence.lake_manifest_sha256,
                "toolchain": _library_toolchain_text(library_root),
                "status": "passed",
                "contains_absolute_paths": False,
                "contains_raw_build_output": False,
                "dependency_tree": expected_dependency_tree,
            },
            label="tracked build report",
        )
        if _json_string_tuple(build_report.get("targets"), label="build report targets") != (
            evidence.target_modules
        ):
            raise SelfCalibrationError("tracked build report targets differ from evidence")
        if expected_candidate_ids is not None:
            fixtures = _json_object_list(
                packet.get("fixtures"), label="tracked preselection fixtures"
            )
            fixture_candidate_ids = tuple(
                _json_string(fixture.get("candidate_id"), label="fixture candidate identifier")
                for fixture in fixtures
            )
            if fixture_candidate_ids != expected_candidate_ids:
                raise SelfCalibrationError(
                    "tracked preselection fixture candidates differ from compile spike"
                )
        if expected_source is not None:
            source_boundary = _json_object(
                packet.get("source_boundary"), label="tracked preselection source boundary"
            )
            _require_json_fields(
                source_boundary,
                {
                    "reference_id": expected_source.reference_id,
                    "source_artifact_sha256": expected_source.artifact_sha256,
                    "model_egress": expected_source.model_egress,
                },
                label="tracked preselection source boundary",
            )
            source_anchor_ids = _json_string_tuple(
                source_boundary.get("anchor_ids"), label="tracked preselection source anchors"
            )
            if not set(source_anchor_ids) <= set(expected_source.anchor_ids):
                raise SelfCalibrationError(
                    "tracked preselection source anchors exceed the calibration source boundary"
                )
        gap = _json_object(packet.get("gap"), label="tracked preselection gap")
        _require_json_fields(gap, {"state": "open"}, label="tracked preselection gap")


class SelfCalibrationLibraryBuildEvidenceV1(ContractModel):
    """Structured build result that can be compared with a local Library root."""

    evidence_id: str = Field(pattern=_IDENTIFIER)
    status: SelfCalibrationLibraryBuildStatusV1
    library_input_tree_sha256: str = Field(pattern=_SHA256)
    lake_manifest_sha256: str = Field(pattern=_SHA256)
    toolchain_sha256: str = Field(pattern=_SHA256)
    mathlib_revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    dependency_tree_schema: Literal["autolean.library-dependency-tree.v1"] = (
        "autolean.library-dependency-tree.v1"
    )
    dependency_tree_sha256: str = Field(pattern=_SHA256)
    dependency_manifest_sha256: str = Field(pattern=_SHA256)
    dependency_entry_count: int = Field(ge=0)
    dependency_directory_count: int = Field(ge=0)
    dependency_regular_file_count: int = Field(ge=0)
    dependency_symlink_count: int = Field(ge=0)
    dependency_total_file_bytes: int = Field(ge=0)
    target_modules: tuple[str, ...] = Field(min_length=1)
    exit_status: int = Field(ge=0, le=255)
    build_report_sha256: str = Field(pattern=_SHA256)
    tracked_preselection_receipt: SelfCalibrationTrackedPreselectionReceiptV1 | None = None
    integrity_checksum_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_evidence(self) -> SelfCalibrationLibraryBuildEvidenceV1:
        if self.dependency_entry_count != (
            self.dependency_directory_count
            + self.dependency_regular_file_count
            + self.dependency_symlink_count
        ):
            raise ValueError("Library dependency tree entry counts are inconsistent")
        if len(self.target_modules) != len(set(self.target_modules)):
            raise ValueError("Library build evidence target modules must be unique")
        if any(not _is_safe_module_name(module) for module in self.target_modules):
            raise ValueError("Library build evidence contains an unsafe target module")
        if (
            self.status
            in {
                SelfCalibrationLibraryBuildStatusV1.PASSED,
                SelfCalibrationLibraryBuildStatusV1.PARTIAL_PASSED_WITH_GAP,
            }
        ) != (self.exit_status == 0):
            raise ValueError("Library build status must agree with the process exit status")
        if (
            self.status is SelfCalibrationLibraryBuildStatusV1.PARTIAL_PASSED_WITH_GAP
            and self.tracked_preselection_receipt is None
        ):
            raise ValueError(
                "partial Library build evidence requires a tracked preselection receipt"
            )
        if (
            self.status is not SelfCalibrationLibraryBuildStatusV1.PARTIAL_PASSED_WITH_GAP
            and self.tracked_preselection_receipt is not None
        ):
            raise ValueError("tracked preselection receipts only support partial Library evidence")
        if self.integrity_checksum_sha256 != library_build_evidence_integrity_checksum_sha256(self):
            raise ValueError("Library build evidence integrity checksum does not bind its payload")
        return self

    def dependency_tree_binding(self) -> dict[str, object]:
        return {
            "schema_version": self.dependency_tree_schema,
            "tree_sha256": self.dependency_tree_sha256,
            "manifest_sha256": self.dependency_manifest_sha256,
            "entry_count": self.dependency_entry_count,
            "directory_count": self.dependency_directory_count,
            "regular_file_count": self.dependency_regular_file_count,
            "symlink_count": self.dependency_symlink_count,
            "total_file_bytes": self.dependency_total_file_bytes,
        }


class SelfCalibrationExternalRunReceiptV1(ContractModel):
    """An external run receipt pending verification by a dedicated authority."""

    receipt_id: str = Field(pattern=_IDENTIFIER)
    authority_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
    build_evidence_integrity_checksum_sha256: str = Field(pattern=_SHA256)
    external_signature: str = Field(min_length=32, max_length=4096)


class SelfCalibrationLibraryCompileReceiptV1(ContractModel):
    """A receipt binds structured build evidence; a verifier decides whether it is trusted."""

    receipt_id: str = Field(pattern=_IDENTIFIER)
    evidence: SelfCalibrationLibraryBuildEvidenceV1
    assurance: SelfCalibrationEvidenceAssuranceV1
    external_run_receipt: SelfCalibrationExternalRunReceiptV1 | None = None

    @model_validator(mode="after")
    def validate_receipt(self) -> SelfCalibrationLibraryCompileReceiptV1:
        if self.assurance is SelfCalibrationEvidenceAssuranceV1.UNTRUSTED_SELF_REPORTED:
            if self.external_run_receipt is not None:
                raise ValueError("untrusted Library receipt cannot carry an external run receipt")
        elif self.external_run_receipt is None:
            raise ValueError("external Library receipt assurance requires an external run receipt")
        elif (
            self.external_run_receipt.build_evidence_integrity_checksum_sha256
            != self.evidence.integrity_checksum_sha256
        ):
            raise ValueError("external run receipt does not bind the Library build evidence")
        return self

    def assert_matches_library_root(self, library_root: Path) -> None:
        """Recompute every local input binding before accepting a compile result."""

        if self.evidence.library_input_tree_sha256 != _library_input_tree_sha256(library_root):
            raise SelfCalibrationError(
                "Library compile receipt input tree differs from Library root"
            )
        if self.evidence.lake_manifest_sha256 != _library_file_sha256(
            library_root / "lake-manifest.json"
        ):
            raise SelfCalibrationError(
                "Library compile receipt lake manifest differs from Library root"
            )
        if self.evidence.toolchain_sha256 != _library_toolchain_sha256(library_root):
            raise SelfCalibrationError(
                "Library compile receipt toolchain differs from Library root"
            )
        for target_module in self.evidence.target_modules:
            target_path = library_root.joinpath(*target_module.split(".")).with_suffix(".lean")
            if not target_path.is_file() or target_path.is_symlink():
                raise SelfCalibrationError(
                    "Library compile receipt target module is absent from Library root: "
                    f"{target_module}"
                )
        if self.evidence.tracked_preselection_receipt is not None:
            self.evidence.tracked_preselection_receipt.assert_matches_library_root(
                library_root,
                evidence=self.evidence,
            )


class SelfCalibrationLibraryCompileReceiptVerifierV1(Protocol):
    """External authority interface required before a compile receipt is trusted."""

    def verify(self, *, receipt: SelfCalibrationLibraryCompileReceiptV1) -> None: ...


class SelfCalibrationCompileSpikePacketV1(ContractModel):
    """A bounded compile-spike plan/result, never Lean verification evidence."""

    packet_id: str = Field(pattern=_IDENTIFIER)
    candidate_ids: tuple[str, ...] = Field(min_length=1)
    state: SelfCalibrationCompileSpikeStateV1
    blocker_ids: tuple[str, ...] = ()
    receipt: SelfCalibrationLibraryCompileReceiptV1 | None = None
    integrity_checksum_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_packet(self) -> SelfCalibrationCompileSpikePacketV1:
        if len(self.candidate_ids) != len(set(self.candidate_ids)):
            raise ValueError("compile-spike candidate identifiers must be unique")
        if len(self.blocker_ids) != len(set(self.blocker_ids)):
            raise ValueError("compile-spike blocker identifiers must be unique")
        if self.state is SelfCalibrationCompileSpikeStateV1.NOT_STARTED:
            if self.receipt is not None:
                raise ValueError("unrun compile spike cannot contain a receipt")
            if not self.blocker_ids:
                raise ValueError("unrun compile spike requires machine-readable blockers")
        elif self.state is SelfCalibrationCompileSpikeStateV1.BLOCKED:
            if self.receipt is not None:
                raise ValueError("blocked compile spike cannot contain a completed receipt")
            if not self.blocker_ids:
                raise ValueError("blocked compile spike requires machine-readable blockers")
        elif (
            self.state
            in {
                SelfCalibrationCompileSpikeStateV1.PARTIAL_PASSED_WITH_GAP,
                SelfCalibrationCompileSpikeStateV1.PASSED,
                SelfCalibrationCompileSpikeStateV1.FAILED,
            }
            and self.receipt is None
        ):
            raise ValueError("completed compile spike requires a structured receipt")
        if self.state is SelfCalibrationCompileSpikeStateV1.PASSED and (
            self.receipt is None
            or self.receipt.evidence.status is not SelfCalibrationLibraryBuildStatusV1.PASSED
        ):
            raise ValueError("passed compile spike requires a successful build receipt")
        if self.state is SelfCalibrationCompileSpikeStateV1.PARTIAL_PASSED_WITH_GAP and (
            self.receipt is None
            or self.receipt.evidence.status
            is not SelfCalibrationLibraryBuildStatusV1.PARTIAL_PASSED_WITH_GAP
            or not self.blocker_ids
        ):
            raise ValueError(
                "partial compile spike requires a gap-bearing structured build receipt"
            )
        if self.state is SelfCalibrationCompileSpikeStateV1.FAILED and (
            self.receipt is None
            or self.receipt.evidence.status is not SelfCalibrationLibraryBuildStatusV1.FAILED
        ):
            raise ValueError("failed compile spike requires a failed build receipt")
        if self.integrity_checksum_sha256 != compile_spike_packet_integrity_checksum_sha256(self):
            raise ValueError("compile-spike packet integrity checksum does not bind its payload")
        return self

    def assert_matches_library_root(
        self,
        library_root: Path,
        *,
        expected_source: SelfCalibrationTextbookBindingV1 | None = None,
    ) -> None:
        """Revalidate an optional tracked preselection receipt with candidate bindings."""

        if self.receipt is None:
            return
        self.receipt.assert_matches_library_root(library_root)
        tracked_receipt = self.receipt.evidence.tracked_preselection_receipt
        if tracked_receipt is not None:
            tracked_receipt.assert_matches_library_root(
                library_root,
                evidence=self.receipt.evidence,
                expected_candidate_ids=self.candidate_ids,
                expected_source=expected_source,
            )


class SelfCalibrationAuthorityBoundaryV1(ContractModel):
    """The record's intentionally empty authority surface."""

    issue_admission_receipt: Literal["forbidden"] = "forbidden"
    builder_freeze: Literal["forbidden"] = "forbidden"
    prover_handoff: Literal["forbidden"] = "forbidden"
    model_egress: Literal["forbidden"] = "forbidden"
    promotion: Literal["forbidden"] = "forbidden"


class SelfCalibrationRoundV1(ContractModel):
    """A tamper-evident decision record for a non-authoritative calibration round."""

    schema_version: Literal["autolean.builder-self-calibration-round.v1"] = (
        "autolean.builder-self-calibration-round.v1"
    )
    round_id: str = Field(pattern=_IDENTIFIER)
    state: SelfCalibrationRoundStateV1
    pilot_manifest_sha256: str = Field(pattern=_SHA256)
    graph_id: str = Field(pattern=_IDENTIFIER)
    target_node_id: str = Field(pattern=_IDENTIFIER)
    textbook: SelfCalibrationTextbookBindingV1
    candidates: tuple[SelfCalibrationCandidateV1, ...] = Field(min_length=2)
    role_reports: tuple[SelfCalibrationRoleReportV1, ...] = Field(min_length=4)
    blockers: tuple[SelfCalibrationBlockerV1, ...] = Field(min_length=1)
    open_problem_alignment: SelfCalibrationOpenProblemAlignmentV1
    library_lock: SelfCalibrationLibraryLockV1
    compile_spike: SelfCalibrationCompileSpikePacketV1
    disposition: SelfCalibrationDispositionV1
    selected_candidate_id: Literal[None] = None
    authority_boundary: SelfCalibrationAuthorityBoundaryV1 = Field(
        default_factory=SelfCalibrationAuthorityBoundaryV1
    )
    integrity_checksum_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_round(self) -> SelfCalibrationRoundV1:
        candidates = {candidate.candidate_id: candidate for candidate in self.candidates}
        if len(candidates) != len(self.candidates):
            raise ValueError("self-calibration candidate identifiers must be unique")
        if len({candidate.integrity_checksum_sha256 for candidate in self.candidates}) != len(
            self.candidates
        ):
            raise ValueError("self-calibration candidates cannot reuse integrity checksums")
        report_ids = [report.report_id for report in self.role_reports]
        if len(report_ids) != len(set(report_ids)):
            raise ValueError("self-calibration role report identifiers must be unique")
        report_keys = [(report.candidate_id, report.role) for report in self.role_reports]
        if len(report_keys) != len(set(report_keys)):
            raise ValueError("each candidate may have only one report per calibration role")
        reviewer_ids = [report.reviewer_id for report in self.role_reports]
        if len(reviewer_ids) != len(set(reviewer_ids)):
            raise ValueError(
                "self-calibration reviewer identities must not author multiple reports"
            )
        for report in self.role_reports:
            candidate = candidates.get(report.candidate_id)
            if candidate is None:
                raise ValueError("role report targets an absent candidate")
            if (
                report.candidate_revision != candidate.revision
                or report.candidate_integrity_checksum_sha256 != candidate.integrity_checksum_sha256
            ):
                raise ValueError("role report does not bind its candidate revision and content")
            if report.reviewer_kind is not SelfCalibrationReviewerKindV1.AUTOMATED_AGENT:
                raise ValueError(
                    "self-calibration cannot record human or expert review; use the later review "
                    "workflow"
                )
        for candidate_id in candidates:
            candidate_reports = [
                report for report in self.role_reports if report.candidate_id == candidate_id
            ]
            roles = {report.role for report in candidate_reports}
            required = {
                SelfCalibrationRoleV1.FORMAL_ARCHITECT,
                SelfCalibrationRoleV1.ADVERSARIAL_REVIEWER,
            }
            if not required <= roles:
                raise ValueError(
                    "each candidate needs independent formal-architect and adversarial reports"
                )
            architect = next(
                report
                for report in candidate_reports
                if report.role is SelfCalibrationRoleV1.FORMAL_ARCHITECT
            )
            adversarial = next(
                report
                for report in candidate_reports
                if report.role is SelfCalibrationRoleV1.ADVERSARIAL_REVIEWER
            )
            if architect.independence_group == adversarial.independence_group:
                raise ValueError(
                    "formal architect and adversarial reviewer need separate independence groups"
                )
        blocker_ids = [blocker.blocker_id for blocker in self.blockers]
        if len(blocker_ids) != len(set(blocker_ids)):
            raise ValueError("self-calibration blocker identifiers must be unique")
        if not set(self.compile_spike.candidate_ids) <= set(candidates):
            raise ValueError("compile-spike packet targets an absent candidate")
        if not set(self.compile_spike.blocker_ids) <= set(blocker_ids):
            raise ValueError("compile-spike packet references an absent blocker")
        active_blocker_ids = {
            blocker.blocker_id
            for blocker in self.blockers
            if blocker.state is SelfCalibrationBlockerStateV1.ACTIVE
        }
        if (
            self.compile_spike.state
            in {
                SelfCalibrationCompileSpikeStateV1.NOT_STARTED,
                SelfCalibrationCompileSpikeStateV1.BLOCKED,
                SelfCalibrationCompileSpikeStateV1.PARTIAL_PASSED_WITH_GAP,
            }
            and not set(self.compile_spike.blocker_ids) <= active_blocker_ids
        ):
            raise ValueError("blocked compile spike must reference only active blockers")
        if (
            self.compile_spike.state
            in {
                SelfCalibrationCompileSpikeStateV1.PASSED,
                SelfCalibrationCompileSpikeStateV1.FAILED,
            }
            and self.compile_spike.blocker_ids
        ):
            raise ValueError("completed compile spike cannot retain blocker references")
        receipt = self.compile_spike.receipt
        if receipt is not None and (
            receipt.evidence.lake_manifest_sha256 != self.library_lock.lake_manifest_sha256
            or receipt.evidence.toolchain_sha256 != self.library_lock.toolchain_sha256
            or receipt.evidence.mathlib_revision != self.library_lock.mathlib_revision
        ):
            raise ValueError("compile-spike receipt differs from the round Library lock")
        if self.disposition is SelfCalibrationDispositionV1.COMPILE_SPIKE:
            if self.compile_spike.state is not SelfCalibrationCompileSpikeStateV1.NOT_STARTED:
                raise ValueError("compile-spike disposition requires an explicitly unrun spike")
            if not any(
                blocker.kind is SelfCalibrationBlockerKindV1.LIBRARY_COMPILE_SPIKE_NOT_RUN
                and blocker.state is SelfCalibrationBlockerStateV1.ACTIVE
                for blocker in self.blockers
            ):
                raise ValueError("compile-spike disposition requires an unrun-spike blocker")
        if self.compile_spike.state is SelfCalibrationCompileSpikeStateV1.PARTIAL_PASSED_WITH_GAP:
            if self.disposition is not SelfCalibrationDispositionV1.GAP:
                raise ValueError("partial compile spike requires a gap disposition")
            if not any(
                blocker.kind is SelfCalibrationBlockerKindV1.CANDIDATE_SCOPE_GAP
                and blocker.state is SelfCalibrationBlockerStateV1.ACTIVE
                and blocker.blocker_id in self.compile_spike.blocker_ids
                for blocker in self.blockers
            ):
                raise ValueError("partial compile spike requires an active scope-gap blocker")
        missing_roles = set(SelfCalibrationRoleV1) - {report.role for report in self.role_reports}
        blocked_roles = {
            blocker.affected_role
            for blocker in self.blockers
            if blocker.kind is SelfCalibrationBlockerKindV1.ROLE_REPORT_MISSING
        }
        if not missing_roles <= blocked_roles:
            raise ValueError(
                "every missing self-calibration role requires a machine-readable blocker"
            )
        if self.state is SelfCalibrationRoundStateV1.INCOMPLETE:
            if self.disposition is SelfCalibrationDispositionV1.CONTINUE:
                raise ValueError(
                    "incomplete self-calibration round cannot use continue disposition"
                )
            if not active_blocker_ids:
                raise ValueError("incomplete self-calibration rounds require active blockers")
        else:
            self._validate_complete_state(active_blocker_ids)
        if self.integrity_checksum_sha256 != self_calibration_round_integrity_checksum_sha256(self):
            raise ValueError("self-calibration round integrity checksum does not bind its payload")
        return self

    def _validate_complete_state(self, active_blocker_ids: set[str]) -> None:
        if self.disposition is not SelfCalibrationDispositionV1.CONTINUE:
            raise ValueError("complete self-calibration round requires continue disposition")
        if active_blocker_ids:
            raise ValueError("complete self-calibration round cannot retain active blockers")
        expected_report_keys = {
            (candidate.candidate_id, role)
            for candidate in self.candidates
            for role in SelfCalibrationRoleV1
        }
        actual_report_keys = {(report.candidate_id, report.role) for report in self.role_reports}
        if actual_report_keys != expected_report_keys:
            raise ValueError("complete self-calibration round requires every role report")
        if any(
            report.state is not SelfCalibrationReportStateV1.VERIFIED
            for report in self.role_reports
        ):
            raise ValueError("complete self-calibration round requires verified role reports")
        if any(
            report.identity_binding.assurance
            is not SelfCalibrationEvidenceAssuranceV1.EXTERNAL_RECEIPT_PENDING_VERIFICATION
            for report in self.role_reports
        ):
            raise ValueError(
                "complete self-calibration round requires externally receipted role identities"
            )
        if self.compile_spike.state is not SelfCalibrationCompileSpikeStateV1.PASSED:
            raise ValueError("complete self-calibration round requires a passed compile spike")
        receipt = self.compile_spike.receipt
        if (
            receipt is None
            or receipt.assurance
            is not SelfCalibrationEvidenceAssuranceV1.EXTERNAL_RECEIPT_PENDING_VERIFICATION
        ):
            raise ValueError(
                "complete self-calibration round requires an externally receipted compile spike"
            )

    def assert_binds_manifest(self, manifest: PilotManifestV1) -> None:
        """Rebind the record to the exact pilot graph before any read or reporting use."""

        expected_manifest_hash = _sha256(manifest.canonical_bytes())
        if self.pilot_manifest_sha256 != expected_manifest_hash:
            raise SelfCalibrationError("self-calibration round is bound to another pilot manifest")
        graph = manifest.graph(self.graph_id)
        closure = graph.target_closure(self.target_node_id)
        source = graph.source.reference
        if source is None:
            raise SelfCalibrationError("self-calibration graph has no verified source binding")
        if (
            self.textbook.reference_id != source.reference_id
            or self.textbook.artifact_sha256 != source.artifact_sha256
            or self.textbook.parent_reference_id != source.parent_reference_id
            or self.textbook.parent_artifact_sha256 != source.parent_artifact_sha256
        ):
            raise SelfCalibrationError(
                "self-calibration textbook binding differs from pilot source"
            )
        expected_anchor_ids = {
            anchor_id for node in closure for anchor_id in node.source_anchor_ids
        }
        if set(self.textbook.anchor_ids) != expected_anchor_ids:
            raise SelfCalibrationError(
                "self-calibration textbook anchors differ from target closure"
            )

    def assert_binds_reference_manifest(self, reference_manifest: ReferenceManifestV1) -> None:
        """Recheck source and rights metadata against the tracked reference allowlist."""

        if self.textbook.reference_manifest_sha256 != reference_manifest.manifest_sha256:
            raise SelfCalibrationError(
                "self-calibration textbook binding is tied to another reference manifest"
            )
        try:
            reference = reference_manifest.require(self.textbook.reference_id)
            parent = reference_manifest.require(self.textbook.parent_reference_id)
        except ValueError as error:
            raise SelfCalibrationError(
                "self-calibration textbook binding references an unallowlisted source"
            ) from error
        if (
            reference.sha256 != self.textbook.artifact_sha256
            or parent.sha256 != self.textbook.parent_artifact_sha256
            or reference.derivation is None
            or reference.derivation.parent_reference_id != parent.reference_id
            or reference.derivation.parent_sha256 != parent.sha256
        ):
            raise SelfCalibrationError(
                "self-calibration textbook binding differs from reference-manifest provenance"
            )
        expected_rights_binding = reference_rights_binding_sha256(
            reference_manifest,
            reference=reference,
            parent=parent,
        )
        if self.textbook.rights_binding_sha256 != expected_rights_binding:
            raise SelfCalibrationError(
                "self-calibration rights binding differs from reference-manifest metadata"
            )

    def assert_binds(
        self,
        *,
        pilot_manifest: PilotManifestV1,
        reference_manifest: ReferenceManifestV1,
    ) -> None:
        """Require both pilot-source and reference-rights revalidation before use."""

        self.assert_binds_manifest(pilot_manifest)
        self.assert_binds_reference_manifest(reference_manifest)
        graph = pilot_manifest.graph(self.graph_id)
        source = graph.source.reference
        if source is None:
            raise SelfCalibrationError("self-calibration graph has no verified source binding")
        reference = reference_manifest.require(self.textbook.reference_id)
        if (
            source.license_expression != reference.license.expression
            or source.attribution != reference.attribution
            or source.model_egress_policy != reference.model_egress_policy.value
        ):
            raise SelfCalibrationError(
                "pilot source rights metadata differs from the reference-manifest entry"
            )

    def assert_ready_for_completion(
        self,
        *,
        pilot_manifest: PilotManifestV1,
        reference_manifest: ReferenceManifestV1,
        library_root: Path | None,
        identity_receipt_verifier: SelfCalibrationIdentityReceiptVerifierV1 | None,
        library_receipt_verifier: SelfCalibrationLibraryCompileReceiptVerifierV1 | None,
    ) -> None:
        """Fail closed unless external authorities verify every completion-critical receipt."""

        self.assert_binds(
            pilot_manifest=pilot_manifest,
            reference_manifest=reference_manifest,
        )
        if self.state is not SelfCalibrationRoundStateV1.COMPLETE:
            raise SelfCalibrationError(
                "only complete self-calibration rounds can pass completion checks"
            )
        if library_root is None:
            raise SelfCalibrationError("complete self-calibration round requires a Library root")
        if identity_receipt_verifier is None or library_receipt_verifier is None:
            raise SelfCalibrationError(
                "complete self-calibration round requires external receipt verifiers"
            )
        for report in self.role_reports:
            identity_receipt = report.identity_binding.external_receipt
            if identity_receipt is None:
                raise SelfCalibrationError(
                    "complete role report lacks an external identity receipt"
                )
            if (
                identity_receipt.report_evidence_sha256 != report.evidence_sha256
                or identity_receipt.reviewer_id != report.reviewer_id
                or identity_receipt.independence_group != report.independence_group
            ):
                raise SelfCalibrationError(
                    "external identity receipt does not bind its self-calibration report"
                )
            identity_receipt_verifier.verify(report=report, receipt=identity_receipt)
        if self.compile_spike.receipt is None:
            raise SelfCalibrationError("complete self-calibration round lacks a compile receipt")
        self.compile_spike.assert_matches_library_root(library_root)
        library_receipt_verifier.verify(receipt=self.compile_spike.receipt)

    def assert_tracked_preselection_receipt(self, library_root: Path | None) -> None:
        """Require a readable Library root before relying on a tracked partial spike."""

        receipt = self.compile_spike.receipt
        if receipt is None or receipt.evidence.tracked_preselection_receipt is None:
            return
        if library_root is None:
            raise SelfCalibrationError(
                "tracked preselection compile receipt requires a Library root for revalidation"
            )
        self.compile_spike.assert_matches_library_root(
            library_root,
            expected_source=self.textbook,
        )

    def issue_admission_receipt(self) -> Never:
        self._deny("issue a pilot admission receipt")

    def freeze_builder_statement(self) -> Never:
        self._deny("freeze a Builder statement")

    def handoff_to_prover(self) -> Never:
        self._deny("handoff work to Prover")

    def authorize_model_egress(self) -> Never:
        self._deny("authorize model egress")

    def promote(self) -> Never:
        self._deny("promote a Library asset")

    @staticmethod
    def _deny(action: str) -> Never:
        raise SelfCalibrationError(
            f"self-calibration records are non-authoritative and cannot {action}"
        )


def candidate_integrity_checksum_sha256(candidate: SelfCalibrationCandidateV1) -> str:
    return _sha256(
        canonical_json_bytes(
            {
                "candidate_id": candidate.candidate_id,
                "revision": candidate.revision,
                "kind": candidate.kind.value,
                "boundary_summary": candidate.boundary_summary,
                "required_mechanisms": candidate.required_mechanisms,
                "explicit_out_of_scope": candidate.explicit_out_of_scope,
            }
        )
    )


def role_report_integrity_checksum_sha256(report: SelfCalibrationRoleReportV1) -> str:
    return _sha256(
        canonical_json_bytes(
            {
                "report_id": report.report_id,
                "role": report.role.value,
                "candidate_id": report.candidate_id,
                "candidate_revision": report.candidate_revision,
                "candidate_integrity_checksum_sha256": report.candidate_integrity_checksum_sha256,
                "reviewer_id": report.reviewer_id,
                "reviewer_kind": report.reviewer_kind.value,
                "independence_group": report.independence_group,
                "identity_binding": report.identity_binding.model_dump(mode="json"),
                "evidence_sha256": report.evidence_sha256,
                "state": report.state.value,
                "finding": report.finding,
                "authoring_mode": report.authoring_mode,
            }
        )
    )


def library_build_evidence_integrity_checksum_sha256(
    evidence: SelfCalibrationLibraryBuildEvidenceV1,
) -> str:
    return _sha256(
        canonical_json_bytes(
            {
                "evidence_id": evidence.evidence_id,
                "status": evidence.status.value,
                "library_input_tree_sha256": evidence.library_input_tree_sha256,
                "lake_manifest_sha256": evidence.lake_manifest_sha256,
                "toolchain_sha256": evidence.toolchain_sha256,
                "mathlib_revision": evidence.mathlib_revision,
                "dependency_tree_schema": evidence.dependency_tree_schema,
                "dependency_tree_sha256": evidence.dependency_tree_sha256,
                "dependency_manifest_sha256": evidence.dependency_manifest_sha256,
                "dependency_entry_count": evidence.dependency_entry_count,
                "dependency_directory_count": evidence.dependency_directory_count,
                "dependency_regular_file_count": evidence.dependency_regular_file_count,
                "dependency_symlink_count": evidence.dependency_symlink_count,
                "dependency_total_file_bytes": evidence.dependency_total_file_bytes,
                "target_modules": evidence.target_modules,
                "exit_status": evidence.exit_status,
                "build_report_sha256": evidence.build_report_sha256,
                "tracked_preselection_receipt": (
                    None
                    if evidence.tracked_preselection_receipt is None
                    else evidence.tracked_preselection_receipt.model_dump(mode="json")
                ),
            }
        )
    )


def compile_spike_packet_integrity_checksum_sha256(
    packet: SelfCalibrationCompileSpikePacketV1,
) -> str:
    return _sha256(
        canonical_json_bytes(
            {
                "packet_id": packet.packet_id,
                "candidate_ids": packet.candidate_ids,
                "state": packet.state.value,
                "blocker_ids": packet.blocker_ids,
                "receipt": (
                    None if packet.receipt is None else packet.receipt.model_dump(mode="json")
                ),
            }
        )
    )


def self_calibration_round_integrity_checksum_sha256(round_record: SelfCalibrationRoundV1) -> str:
    payload = round_record.model_dump(mode="json", exclude={"integrity_checksum_sha256"})
    return _sha256(canonical_json_bytes(payload))


def reference_rights_binding_sha256(
    reference_manifest: ReferenceManifestV1,
    *,
    reference: ReferenceEntryV1,
    parent: ReferenceEntryV1,
) -> str:
    """Hash only manifest-controlled source/rights metadata, never a caller-supplied string."""

    return _sha256(
        canonical_json_bytes(
            {
                "schema_version": "autolean.self-calibration-rights-binding.v1",
                "reference_manifest_sha256": reference_manifest.manifest_sha256,
                "reference": _reference_rights_payload(reference),
                "parent": _reference_rights_payload(parent),
            }
        )
    )


def load_self_calibration_round(
    path: Path,
    *,
    pilot_manifest: PilotManifestV1,
    reference_manifest: ReferenceManifestV1,
    library_root: Path | None = None,
    identity_receipt_verifier: SelfCalibrationIdentityReceiptVerifierV1 | None = None,
    library_receipt_verifier: SelfCalibrationLibraryCompileReceiptVerifierV1 | None = None,
) -> SelfCalibrationRoundV1:
    """Load a duplicate-key-safe round and fail closed on source or completion evidence."""

    try:
        raw = path.read_bytes()
    except OSError as error:
        raise SelfCalibrationError(f"cannot read self-calibration round: {path}") from error
    try:
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise SelfCalibrationError("self-calibration round is not valid UTF-8 JSON") from error
    try:
        round_record = SelfCalibrationRoundV1.model_validate(payload)
    except ValueError as error:
        raise SelfCalibrationError(f"self-calibration round is invalid: {error}") from error
    round_record.assert_binds(
        pilot_manifest=pilot_manifest,
        reference_manifest=reference_manifest,
    )
    round_record.assert_tracked_preselection_receipt(library_root)
    if round_record.state is SelfCalibrationRoundStateV1.COMPLETE:
        round_record.assert_ready_for_completion(
            pilot_manifest=pilot_manifest,
            reference_manifest=reference_manifest,
            library_root=library_root,
            identity_receipt_verifier=identity_receipt_verifier,
            library_receipt_verifier=library_receipt_verifier,
        )
    return round_record


def _reference_rights_payload(entry: ReferenceEntryV1) -> dict[str, object]:
    derivation = entry.derivation
    return {
        "reference_id": entry.reference_id,
        "sha256": entry.sha256,
        "source_record_url": entry.source_record_url,
        "license_expression": entry.license.expression,
        "license_url": entry.license.url,
        "license_evidence_url": entry.license.evidence_url,
        "access_policy": entry.access_policy.value,
        "acquisition_policy": entry.acquisition_policy.value,
        "model_egress_policy": entry.model_egress_policy.value,
        "attribution": entry.attribution,
        "derivation": (
            None
            if derivation is None
            else {
                "kind": derivation.kind.value,
                "parent_reference_id": derivation.parent_reference_id,
                "parent_sha256": derivation.parent_sha256,
                "producer": derivation.producer,
                "method": derivation.method,
                "tool_name": derivation.tool_name,
                "tool_version": derivation.tool_version,
                "provenance_url": derivation.provenance_url,
                "parent_locator_authority": derivation.parent_locator_authority.value,
            }
        ),
    }


def _library_file_sha256(path: Path) -> str:
    try:
        return _sha256(path.read_bytes())
    except OSError as error:
        raise SelfCalibrationError(f"Library input is unavailable: {path.name}") from error


def _library_toolchain_sha256(library_root: Path) -> str:
    return _sha256(_library_toolchain_text(library_root).encode("utf-8"))


def _library_toolchain_text(library_root: Path) -> str:
    try:
        toolchain = (library_root / "lean-toolchain").read_text(encoding="utf-8").strip()
    except OSError as error:
        raise SelfCalibrationError("Library input is unavailable: lean-toolchain") from error
    if not toolchain:
        raise SelfCalibrationError("Library toolchain is empty")
    return toolchain


def _library_input_tree_sha256(library_root: Path) -> str:
    """Match the Library v2 downstream build-input closure, not the whole checkout."""

    root_files = (
        "lean-toolchain",
        "lakefile.lean",
        "lake-manifest.json",
        "AutoLeanLibrary.lean",
    )
    try:
        relative_paths = list(root_files)
        module_root = library_root / "AutoLeanLibrary"
        if module_root.is_symlink() or not module_root.is_dir():
            raise SelfCalibrationError("Library AutoLeanLibrary module root is unavailable")
        for candidate in module_root.rglob("*.lean"):
            if candidate.is_symlink() or not candidate.is_file():
                raise SelfCalibrationError("Library build input is linked or unavailable")
            relative_paths.append(candidate.relative_to(library_root).as_posix())
    except OSError as error:
        raise SelfCalibrationError("Library root is unavailable") from error
    if len(relative_paths) != len(set(relative_paths)):
        raise SelfCalibrationError("Library build input closure contains duplicate paths")
    digest = hashlib.sha256()
    digest.update(b"autolean.library-build-input-tree.v2\n")
    for relative in sorted(relative_paths, key=lambda value: value.encode("utf-8")):
        candidate = library_root.joinpath(*PurePosixPath(relative).parts)
        if candidate.is_symlink() or not candidate.is_file():
            raise SelfCalibrationError("Library build input is linked or unavailable")
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(candidate.read_bytes()).digest())
        digest.update(b"\n")
    return digest.hexdigest()


def _is_safe_module_name(value: str) -> bool:
    parts = value.split(".")
    return bool(parts) and all(part.isidentifier() for part in parts)


def _is_safe_library_record_path(value: str) -> bool:
    if "\\" in value:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and len(path.parts) >= 2
        and path.parts[0] == "records"
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def _resolve_library_record_path(library_root: Path, relative_path: str) -> Path:
    if not _is_safe_library_record_path(relative_path):
        raise SelfCalibrationError("tracked preselection record path is unsafe")
    try:
        root = library_root.resolve(strict=True)
    except OSError as error:
        raise SelfCalibrationError("Library root is unavailable") from error
    path = root.joinpath(*PurePosixPath(relative_path).parts)
    if path.is_symlink() or not path.is_file():
        raise SelfCalibrationError("tracked preselection record is unavailable or symbolic")
    try:
        path.resolve(strict=True).relative_to(root)
    except (OSError, ValueError) as error:
        raise SelfCalibrationError("tracked preselection record escapes Library root") from error
    return path


def _read_library_json_object(path: Path, *, label: str) -> dict[str, object]:
    try:
        raw = path.read_bytes()
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise SelfCalibrationError(f"{label} is not valid UTF-8 JSON") from error
    return _json_object(payload, label=label)


def _json_object(value: object, *, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise SelfCalibrationError(f"{label} must be a JSON object")
    return cast(dict[str, object], value)


def _json_object_list(value: object, *, label: str) -> tuple[dict[str, object], ...]:
    if not isinstance(value, list):
        raise SelfCalibrationError(f"{label} must be a JSON array")
    return tuple(_json_object(item, label=label) for item in value)


def _json_string(value: object, *, label: str) -> str:
    if not isinstance(value, str):
        raise SelfCalibrationError(f"{label} must be a JSON string")
    return value


def _json_string_tuple(value: object, *, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise SelfCalibrationError(f"{label} must be a JSON string array")
    return tuple(cast(str, item) for item in value)


def _require_json_fields(
    value: dict[str, object], expected: dict[str, object], *, label: str
) -> None:
    for field, expected_value in expected.items():
        if value.get(field) != expected_value:
            raise SelfCalibrationError(f"{label} field differs: {field}")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key in self-calibration round")
        result[key] = value
    return result
