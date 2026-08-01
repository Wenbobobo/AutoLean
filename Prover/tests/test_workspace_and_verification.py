from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest
from autolean_contracts import (
    MATHLIB_AXIOMS_V1,
    AxiomProfileV1,
    HashKindV1,
    ProofSubmissionV1,
    digest_text,
)
from autolean_prover.errors import ValidationError
from autolean_prover.execution import (
    MaterializedWorkspace,
    PatchBoundaryError,
    WorkspaceIntegrityError,
    WorkspaceMaterializer,
)
from autolean_prover.verification import (
    ElaboratedTypeComparator,
    ElaboratedTypeEvidence,
    LeanRunEvidence,
    TrustedLeanVerifier,
)

from .helpers import frozen_bundle, stable_id


@dataclass(frozen=True)
class SuccessfulRunner:
    def run(self, candidate: Path, *, workspace: MaterializedWorkspace) -> LeanRunEvidence:
        text = candidate.read_text(encoding="utf-8")
        assert "theorem fixture (n : Nat) : n = n := by" in text
        assert "theorem fixture (n : Nat) : True" not in text
        return LeanRunEvidence(
            returncode=0,
            timed_out=False,
            stdout="'AutoLean.Test.fixture' depends on axioms: []\n",
            stderr="",
            clean_environment=True,
            elaborated_type_evidence=_expected_type_evidence(workspace),
        )


@dataclass(frozen=True)
class TamperingRunner:
    def run(self, candidate: Path, *, workspace: MaterializedWorkspace) -> LeanRunEvidence:
        protected = workspace.root / workspace.bundle.proof_boundary.trusted_statement_path
        protected.chmod(0o644)
        protected.write_text("-- modified after compilation\n", encoding="utf-8")
        assert candidate.is_file()
        return LeanRunEvidence(
            returncode=0,
            timed_out=False,
            stdout="'AutoLean.Test.fixture' depends on axioms: []\n",
            stderr="",
            clean_environment=True,
        )


@dataclass(frozen=True)
class WrongTypeRunner:
    def run(self, candidate: Path, *, workspace: MaterializedWorkspace) -> LeanRunEvidence:
        assert candidate.is_file()
        return LeanRunEvidence(
            returncode=0,
            timed_out=False,
            stdout="'AutoLean.Test.fixture' depends on axioms: []\n",
            stderr="",
            clean_environment=True,
            elaborated_type_evidence=ElaboratedTypeEvidence(
                declaration=workspace.candidate_declaration(),
                canonical_type="True",
            ),
        )


@dataclass(frozen=True)
class MissingTypeEvidenceRunner:
    def run(self, candidate: Path, *, workspace: MaterializedWorkspace) -> LeanRunEvidence:
        assert candidate.is_file()
        return LeanRunEvidence(
            returncode=0,
            timed_out=False,
            stdout="'AutoLean.Test.fixture' depends on axioms: []\n",
            stderr="",
            clean_environment=True,
        )


def _expected_type_evidence(workspace: MaterializedWorkspace) -> ElaboratedTypeEvidence:
    canonical_type = workspace.bundle.contract.formal.elaborated_type
    assert canonical_type is not None
    return ElaboratedTypeEvidence(
        declaration=workspace.candidate_declaration(),
        canonical_type=canonical_type,
    )


def _submission(bundle, proof: str = "by\n  rfl") -> ProofSubmissionV1:
    return ProofSubmissionV1(
        proof_id=stable_id("proof"),
        contract_id=bundle.contract.contract_id,
        revision=bundle.contract.revision,
        contract_hash=bundle.contract.semantic_hash(),
        proof_boundary_hash=bundle.proof_boundary.boundary_hash,
        proof_source=proof,
        proof_source_hash=digest_text(HashKindV1.PROOF_SOURCE, proof),
        environment_hash=bundle.contract.formal.environment.environment_hash,
    )


def test_proof_slot_boundary_rejects_theorem_replacement(tmp_path) -> None:
    workspace = WorkspaceMaterializer().materialize(frozen_bundle(), tmp_path / "attempt")
    with pytest.raises(PatchBoundaryError, match="protected"):
        workspace.validate_patch(
            "diff --git a/TrustedStatement.lean b/TrustedStatement.lean\n"
            "--- a/TrustedStatement.lean\n+++ b/TrustedStatement.lean\n"
            "-theorem fixture (n : Nat) : n = n\n+theorem fixture (n : Nat) : True\n"
        )


def test_workspace_uses_the_hash_bound_header_and_solver_manifest(tmp_path) -> None:
    bundle = frozen_bundle()
    workspace = WorkspaceMaterializer().materialize(bundle, tmp_path / "attempt")
    boundary = bundle.proof_boundary
    assert (workspace.root / boundary.trusted_statement_path).read_text(
        encoding="utf-8"
    ) == boundary.trusted_statement_source
    manifest = (workspace.root / "bundle-manifest.json").read_text(encoding="utf-8")
    assert digest_text(HashKindV1.WORKSPACE_MANIFEST, manifest) == boundary.solver_manifest_hash
    assert workspace.allowed_write_paths == frozenset({"Proof.lean"})


def test_workspace_refuses_a_worker_created_proof_slot_symlink(tmp_path) -> None:
    workspace = WorkspaceMaterializer().materialize(frozen_bundle(), tmp_path / "attempt")
    outside = tmp_path / "outside.txt"
    outside.write_text("must remain unchanged", encoding="utf-8")
    workspace.proof_path.unlink()
    try:
        workspace.proof_path.symlink_to(outside)
    except OSError:
        pytest.skip("symbolic links are unavailable on this Windows configuration")

    with pytest.raises(WorkspaceIntegrityError, match="symbolic link"):
        workspace.write_proof("by\n  rfl")
    assert outside.read_text(encoding="utf-8") == "must remain unchanged"


def test_verifier_compiles_only_frozen_header_plus_proof_slot(tmp_path) -> None:
    bundle = frozen_bundle()
    workspace = WorkspaceMaterializer().materialize(bundle, tmp_path / "attempt")
    report = TrustedLeanVerifier(runner=SuccessfulRunner(), verifier_id="test-verifier").verify(
        workspace, _submission(bundle)
    )
    assert report.kernel_passed
    assert report.dependency_check_passed
    assert report.observed_axioms == ()


def test_verifier_rejects_placeholder_before_runner_execution(tmp_path) -> None:
    bundle = frozen_bundle()
    workspace = WorkspaceMaterializer().materialize(bundle, tmp_path / "attempt")
    report = TrustedLeanVerifier(runner=SuccessfulRunner(), verifier_id="test-verifier").verify(
        workspace, _submission(bundle, "by\n  sorry")
    )
    assert not report.kernel_passed
    assert "prohibited placeholder" in report.details


def test_verifier_rejects_a_compiled_candidate_with_a_different_elaborated_type(tmp_path) -> None:
    bundle = frozen_bundle()
    workspace = WorkspaceMaterializer().materialize(bundle, tmp_path / "attempt")
    report = TrustedLeanVerifier(runner=WrongTypeRunner(), verifier_id="test-verifier").verify(
        workspace, _submission(bundle)
    )
    assert not report.kernel_passed
    assert not report.build_passed
    assert not report.dependency_check_passed
    assert "elaborated-type hash differs" in report.details


def test_type_comparator_rejects_the_right_type_under_the_wrong_declaration() -> None:
    bundle = frozen_bundle()
    expected = bundle.contract.formal.elaborated_type
    assert expected is not None
    with pytest.raises(ValidationError, match="different declaration"):
        ElaboratedTypeComparator.verify(
            bundle.proof_boundary,
            ElaboratedTypeEvidence(
                declaration="AutoLean.Test.not_fixture",
                canonical_type=expected,
            ),
        )


def test_elaborated_type_evidence_rejects_an_unknown_printer_profile() -> None:
    with pytest.raises(ValueError, match="unsupported elaborated-type evidence format"):
        ElaboratedTypeEvidence(
            declaration="AutoLean.Test.fixture",
            canonical_type="forall (n : Nat), Eq n n",
            format_id="unknown-profile",
        )


def test_verifier_fails_closed_when_the_runner_omits_elaborated_type_evidence(tmp_path) -> None:
    bundle = frozen_bundle()
    workspace = WorkspaceMaterializer().materialize(bundle, tmp_path / "attempt")
    report = TrustedLeanVerifier(
        runner=MissingTypeEvidenceRunner(), verifier_id="test-verifier"
    ).verify(workspace, _submission(bundle))
    assert not report.kernel_passed
    assert "elaborated-type evidence was absent" in report.details


def test_verifier_fails_closed_when_runner_tampers_with_a_protected_file(tmp_path) -> None:
    bundle = frozen_bundle()
    workspace = WorkspaceMaterializer().materialize(bundle, tmp_path / "attempt")
    report = TrustedLeanVerifier(runner=TamperingRunner(), verifier_id="test-verifier").verify(
        workspace, _submission(bundle)
    )
    assert not report.kernel_passed
    assert not report.build_passed
    assert not report.dependency_check_passed
    assert "protected workspace file changed" in report.details


def test_verifier_rechecks_mathlib_axiom_policy_after_contract_validation(tmp_path) -> None:
    bundle = frozen_bundle(
        axiom_profile=AxiomProfileV1.MATHLIB,
        axioms_allowlist=MATHLIB_AXIOMS_V1,
    )
    workspace = WorkspaceMaterializer().materialize(bundle, tmp_path / "mathlib-attempt")
    assert TrustedLeanVerifier._axiom_failures(workspace, MATHLIB_AXIOMS_V1) == []
    assert "sorryAx is prohibited" in TrustedLeanVerifier._axiom_failures(
        workspace,
        ("sorryAx",),
    )

    object.__setattr__(
        bundle.contract.formal,
        "axioms_allowlist",
        (*MATHLIB_AXIOMS_V1, "AutoLean.UnsafeAxiom"),
    )
    failures = TrustedLeanVerifier._axiom_failures(
        workspace,
        (*MATHLIB_AXIOMS_V1, "AutoLean.UnsafeAxiom"),
    )
    assert any("axiom policy is invalid" in failure for failure in failures)
