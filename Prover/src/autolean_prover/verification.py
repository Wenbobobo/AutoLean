"""Kernel-facing verification built around an immutable theorem header, not a theorem name."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from autolean_contracts import (
    AxiomProfileV1,
    HashKindV1,
    ProofBoundaryV1,
    ProofSubmissionV1,
    VerificationReportV1,
    digest_text,
    stable_identifier,
    validate_axiom_policy_v1,
)

from autolean_prover.errors import ValidationError
from autolean_prover.execution import MaterializedWorkspace
from autolean_prover.execution.lean_runner import (
    ElaboratedTypeEvidence,
    LeanRunEvidence,
    LeanRunner,
    OciExecutionEvidence,
)

_PLACEHOLDER_RE = re.compile(r"\b(?:sorry|admit)\b|sorryAx")
_AXIOMS_RE = re.compile(r"axioms:\s*\[(?P<items>[^\]]*)\]", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class VerificationObservation:
    """A transient verifier result plus safe OCI facts, before authority promotion.

    The observation deliberately omits raw Lean stdout/stderr and the candidate path.  The
    separate attestation adapter converts the OCI facts into a content-addressed evidence artifact
    and a signed ``VerificationReportV1`` before the control plane may accept either verdict.
    """

    report: VerificationReportV1
    oci_execution_evidence: OciExecutionEvidence | None


class ElaboratedTypeComparator:
    """Compare a Lean-rendered declaration type with the frozen proof boundary.

    The hash is deliberately recomputed from text returned by the authoritative runner. Accepting
    a runner-supplied hash, a declaration name, or the model's source would make this check
    vacuous.
    """

    @staticmethod
    def verify(
        boundary: ProofBoundaryV1,
        evidence: ElaboratedTypeEvidence | None,
    ) -> None:
        if evidence is None:
            raise ValidationError("Lean elaborated-type evidence was absent")
        try:
            evidence.validate()
        except ValueError as error:
            raise ValidationError("Lean elaborated-type evidence is malformed") from error
        if evidence.declaration != boundary.expected_declaration:
            raise ValidationError("Lean elaborated-type helper resolved a different declaration")
        observed_hash = digest_text(HashKindV1.ELABORATED_TYPE, evidence.canonical_type)
        if observed_hash != boundary.expected_elaborated_type_hash:
            raise ValidationError(
                "Lean elaborated-type hash differs from the frozen statement contract"
            )


class TrustedLeanVerifier:
    """Turn a clean Lean run into a typed verification report.

    The runner only ever compiles a file constructed by `MaterializedWorkspace`: its declaration
    header comes from the frozen contract, while the model can contribute only the proof slot.
    """

    def __init__(self, *, runner: LeanRunner, verifier_id: str, independent: bool = True) -> None:
        if not verifier_id.strip():
            raise ValueError("verifier_id must not be empty")
        self._runner = runner
        self._verifier_id = verifier_id
        self._independent = independent

    def verify(
        self,
        workspace: MaterializedWorkspace,
        submission: ProofSubmissionV1,
    ) -> VerificationReportV1:
        """Return the transient report for callers that do not need OCI evidence."""

        return self.observe(workspace, submission).report

    def observe(
        self,
        workspace: MaterializedWorkspace,
        submission: ProofSubmissionV1,
    ) -> VerificationObservation:
        """Return the local result and non-secret OCI evidence for later attestation.

        This does not sign or persist anything.  A report returned here is intentionally not
        promotable until a verifier authority attaches ``VerificationEvidenceV1`` and a
        verification-purpose attestation through ``verification_attestation``.
        """

        contract = workspace.bundle.contract
        self._validate_binding(workspace, submission)
        reasons: list[str] = []
        evidence: LeanRunEvidence | None = None
        observed_axioms: tuple[str, ...] = ()
        verification_evidence_valid = True
        try:
            if _PLACEHOLDER_RE.search(submission.proof_source):
                raise ValidationError("proof source contains a prohibited placeholder")
            workspace.write_proof(submission.proof_source)
            candidate = workspace.render_candidate()
            self._append_axiom_query(candidate, workspace.candidate_declaration())
            evidence = self._runner.run(candidate, workspace=workspace)
            workspace.validate_integrity()
            ElaboratedTypeComparator.verify(
                workspace.bundle.proof_boundary,
                evidence.elaborated_type_evidence,
            )
            parsed = self._observed_axioms(evidence)
            if parsed is None:
                raise ValidationError("Lean axiom query output was absent or malformed")
            else:
                observed_axioms = parsed
                reasons.extend(self._axiom_failures(workspace, parsed))
            if evidence.timed_out:
                reasons.append("Lean execution timed out")
            elif evidence.returncode != 0:
                reasons.append("Lean exited unsuccessfully")
        except ValidationError as exc:
            verification_evidence_valid = False
            reasons.append(str(exc))
        except Exception:
            verification_evidence_valid = False
            # Runner exceptions are not verification evidence and may contain host paths or secrets.
            reasons.append("Lean runner failed before producing verification evidence")

        kernel_passed = (
            verification_evidence_valid
            and evidence is not None
            and not evidence.timed_out
            and evidence.returncode == 0
        )
        dependency_check = kernel_passed and not any(
            reason.startswith("Lean axiom")
            or reason.startswith("unapproved axiom")
            or reason.startswith("strict axiom")
            or reason.startswith("sorryAx")
            for reason in reasons
        )
        clean_environment = evidence.clean_environment if evidence is not None else False
        details = self._details(evidence, reasons)
        report = VerificationReportV1(
            report_id=stable_identifier(
                "verification",
                f"{submission.proof_id.value}:{self._verifier_id}:{submission.proof_source_hash.value}",
            ),
            proof_id=submission.proof_id,
            contract_hash=submission.contract_hash,
            proof_boundary_hash=submission.proof_boundary_hash,
            verifier_id=self._verifier_id,
            independent=self._independent,
            kernel_passed=kernel_passed,
            build_passed=kernel_passed,
            dependency_check_passed=dependency_check,
            clean_environment=clean_environment,
            environment_hash=submission.environment_hash,
            axiom_profile=contract.policy.axiom_profile,
            observed_axioms=observed_axioms,
            details=details,
        )
        return VerificationObservation(
            report=report,
            oci_execution_evidence=(None if evidence is None else evidence.oci_execution_evidence),
        )

    @staticmethod
    def _validate_binding(workspace: MaterializedWorkspace, submission: ProofSubmissionV1) -> None:
        contract = workspace.bundle.contract
        if submission.contract_id != contract.contract_id:
            raise ValidationError("proof submission binds a different contract ID")
        if submission.revision != contract.revision:
            raise ValidationError("proof submission binds a different contract revision")
        if submission.contract_hash != contract.semantic_hash():
            raise ValidationError("proof submission binds a different frozen statement hash")
        if submission.proof_boundary_hash != workspace.bundle.proof_boundary.boundary_hash:
            raise ValidationError("proof submission binds a different frozen proof boundary")
        if submission.environment_hash != contract.formal.environment.environment_hash:
            raise ValidationError("proof submission uses a different Lean environment")

    @staticmethod
    def _append_axiom_query(candidate: Path, declaration: str) -> None:
        with candidate.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(f"\n#print axioms {declaration}\n")

    @staticmethod
    def _parse_axioms(stdout: str) -> tuple[str, ...] | None:
        matches = list(_AXIOMS_RE.finditer(stdout))
        if not matches:
            return None
        raw = matches[-1].group("items").strip()
        if not raw:
            return ()
        items = tuple(item.strip().strip("'\"") for item in raw.split(","))
        if not all(items):
            return None
        return tuple(sorted(set(items)))

    @staticmethod
    def _observed_axioms(evidence: LeanRunEvidence) -> tuple[str, ...] | None:
        """Prefer structured runner evidence; retain text parsing for legacy runners."""

        if evidence.observed_axioms is None:
            return TrustedLeanVerifier._parse_axioms(evidence.stdout)
        axioms = evidence.observed_axioms
        if len(set(axioms)) != len(axioms) or not all(
            isinstance(item, str)
            and item
            and item == item.strip()
            and "\x00" not in item
            and "\n" not in item
            and "\r" not in item
            for item in axioms
        ):
            return None
        return tuple(sorted(axioms))

    @staticmethod
    def _axiom_failures(workspace: MaterializedWorkspace, axioms: tuple[str, ...]) -> list[str]:
        contract = workspace.bundle.contract
        failures: list[str] = []
        try:
            validate_axiom_policy_v1(
                contract.policy.axiom_profile,
                contract.formal.axioms_allowlist,
            )
        except ValueError as error:
            failures.append(f"Lean axiom policy is invalid: {error}")
        observed = set(axioms)
        if "sorryAx" in observed:
            failures.append("sorryAx is prohibited")
        unapproved = observed - set(contract.formal.axioms_allowlist)
        if unapproved:
            failures.append("unapproved axiom(s): " + ", ".join(sorted(unapproved)))
        if contract.policy.axiom_profile is AxiomProfileV1.STRICT and observed:
            failures.append("strict axiom profile observed axioms")
        return failures

    @staticmethod
    def _details(evidence: LeanRunEvidence | None, reasons: list[str]) -> str:
        if evidence is None:
            return "verification did not start: " + "; ".join(reasons)
        state = "timed out" if evidence.timed_out else f"returned {evidence.returncode}"
        suffix = "; ".join(reasons) if reasons else "all local verifier gates passed"
        authority = (
            "non-OCI"
            if evidence.oci_execution_evidence is None
            else evidence.oci_execution_evidence.authority_status
        )
        return f"Lean worker {state}; OCI authority={authority}; {suffix}"
