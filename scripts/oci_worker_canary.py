"""Exercise the real pure-Lean worker and the repository OciLeanRunner boundary."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from autolean_contracts import (
    AlignmentTargetV1,
    ExecutionGraphV1,
    FidelityRiskV1,
    FormalGraphV1,
    FormalizationTaskBundleV1,
    FormalSpecificationV1,
    FreezeRecordV1,
    GraphBundleV1,
    HashKindV1,
    LeanEnvironmentV1,
    MathematicalGraphV1,
    MathematicalSpecificationV1,
    OciVerifierExecutionPolicyV1,
    PermissionDecisionV1,
    ProofSubmissionV1,
    ReleaseTierV1,
    RightsRecordV1,
    SourceRecordV1,
    SourceSpanV1,
    StableIdentifierV1,
    StatementContractV1,
    StatementStatusV1,
    TaskKindV1,
    TaskPolicyV1,
    build_proof_boundary,
    digest_model,
    digest_text,
    stable_identifier,
)
from autolean_prover.errors import ValidationError
from autolean_prover.execution import (
    CleanSubprocessHarness,
    MaterializedWorkspace,
    OciLeanRunner,
    OciWorkerHarness,
    OciWorkerSpec,
    WorkspaceMaterializer,
)
from autolean_prover.verification import TrustedLeanVerifier

PROTOCOL: Final[str] = "autolean.oci-lean-wrapper.v1"
TYPE_FORMAT: Final[str] = "autolean.lean-pp-expr.v1"
DECLARATION: Final[str] = "AutoLean.OCI.fixture"
CANONICAL_TYPE: Final[str] = "\u2200 (n : Nat), @Eq.{1} Nat n n"
LEAN_VERSION: Final[str] = "v4.28.0"
MATHLIB_REVISION: Final[str] = "none-pure-lean-v4.28.0"
_FIXED_TIME: Final[datetime] = datetime(2026, 1, 1, tzinfo=UTC)


def _stable_id(key: str) -> StableIdentifierV1:
    return stable_identifier("oci-real-canary", key)


def _bundle(image_digest: str) -> FormalizationTaskBundleV1:
    source_id = _stable_id("source")
    span = SourceSpanV1(
        span_id=_stable_id("span"),
        locator="oci-canary:1",
        content_hash=digest_text(HashKindV1.SOURCE_SPAN, "n equals n"),
        permitted_excerpt="n equals n",
    )
    source = SourceRecordV1(
        source_id=source_id,
        work_id="oci-real-canary",
        title="AutoLean OCI real-execution canary",
        version="1",
        locator="autolean://oci-real-canary",
        content_hash=digest_text(HashKindV1.SOURCE_BYTES, "oci-real-canary-source-v1"),
        retrieved_at=_FIXED_TIME,
        spans=(span,),
    )
    rights = RightsRecordV1(
        rights_id=_stable_id("rights"),
        source_id=source_id,
        source_license="CC0-1.0",
        overall_decision=PermissionDecisionV1.ALLOW,
        model_egress=PermissionDecisionV1.DENY,
        reviewed_by="oci-canary-rights-fixture",
        reviewed_at=_FIXED_TIME,
    )
    statement = "theorem fixture (n : Nat) : n = n"
    environment = LeanEnvironmentV1(
        lean_version=LEAN_VERSION,
        mathlib_revision=MATHLIB_REVISION,
        verifier_execution_policy=OciVerifierExecutionPolicyV1(
            worker_image_digest=image_digest,
        ),
        environment_hash=digest_text(
            HashKindV1.ENVIRONMENT,
            f"pure-lean-4.28.0:{image_digest}:{TYPE_FORMAT}",
        ),
    )
    formal = FormalSpecificationV1(
        declaration_name="fixture",
        namespace="AutoLean.OCI",
        lean_statement_source=statement,
        statement_source_hash=digest_text(HashKindV1.STATEMENT_SOURCE, statement),
        elaborated_type=CANONICAL_TYPE,
        elaborated_type_hash=digest_text(HashKindV1.ELABORATED_TYPE, CANONICAL_TYPE),
        environment=environment,
        imports_allowlist=(),
    )
    draft = StatementContractV1(
        contract_id=_stable_id("contract"),
        revision=1,
        task_kind=TaskKindV1.KNOWN_THEOREM,
        source=source,
        rights=rights,
        mathematics=MathematicalSpecificationV1(
            informal_statement="Every natural number equals itself.",
            normalized_statement="For every natural number n, n = n.",
        ),
        formal=formal,
        alignments=(
            AlignmentTargetV1(
                source_span_id=span.span_id,
                formal_target=DECLARATION,
                relation="formalizes",
                confidence=1.0,
            ),
        ),
        policy=TaskPolicyV1(
            release_tier=ReleaseTierV1.CALIBRATION,
            fidelity_risk=FidelityRiskV1.L1_SIMPLE,
        ),
    )
    frozen_payload = draft.model_dump(mode="python", round_trip=True)
    frozen_payload.update(
        {
            "status": StatementStatusV1.FROZEN,
            "freeze": FreezeRecordV1(
                contract_hash=draft.semantic_hash(),
                source_hash=source.content_hash,
                statement_source_hash=formal.statement_source_hash,
                elaborated_type_hash=formal.elaborated_type_hash,
                frozen_by="oci-real-canary",
                frozen_at=_FIXED_TIME,
            ),
        }
    )
    frozen = StatementContractV1.model_validate(frozen_payload)
    graphs = GraphBundleV1(
        mathematical=MathematicalGraphV1(graph_id=_stable_id("math"), revision=1),
        formal=FormalGraphV1(graph_id=_stable_id("formal"), revision=1),
        execution=ExecutionGraphV1(graph_id=_stable_id("execution"), revision=1),
    )
    return FormalizationTaskBundleV1(
        bundle_id=_stable_id("bundle"),
        contract=frozen,
        graphs=graphs,
        graph_snapshot_hash=digest_model(HashKindV1.GRAPH_SNAPSHOT, graphs),
        proof_boundary=build_proof_boundary(frozen),
        issued_at=_FIXED_TIME,
    )


def _submission(bundle: FormalizationTaskBundleV1, proof: str) -> ProofSubmissionV1:
    return ProofSubmissionV1(
        proof_id=_stable_id("proof"),
        contract_id=bundle.contract.contract_id,
        revision=bundle.contract.revision,
        contract_hash=bundle.contract.semantic_hash(),
        proof_boundary_hash=bundle.proof_boundary.boundary_hash,
        proof_source=proof,
        proof_source_hash=digest_text(HashKindV1.PROOF_SOURCE, proof),
        environment_hash=bundle.contract.formal.environment.environment_hash,
    )


def _wrapper_command(
    image: str,
    candidate: Path,
    *,
    declaration: str = DECLARATION,
    type_format: str = TYPE_FORMAT,
) -> list[str]:
    return [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "128",
        "--memory",
        "2g",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=256m",
        "--mount",
        f"type=bind,src={candidate.resolve()},dst=/input/Candidate.lean,readonly",
        image,
        "/opt/autolean/bin/autolean-lean-wrapper",
        "--protocol",
        PROTOCOL,
        "--candidate",
        "/input/Candidate.lean",
        "--declaration",
        declaration,
        "--type-format",
        type_format,
    ]


def _direct(
    image: str,
    candidate: Path,
    *,
    declaration: str = DECLARATION,
    type_format: str = TYPE_FORMAT,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        _wrapper_command(
            image,
            candidate,
            declaration=declaration,
            type_format=type_format,
        ),
        check=False,
        shell=False,
        text=True,
        capture_output=True,
        timeout=120,
    )


def _copy_frozen_source(workspace: MaterializedWorkspace, destination: Path) -> None:
    for protected in workspace.protected_files:
        target = destination / protected.path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((workspace.root / protected.path).read_bytes())


def _require_record(result: subprocess.CompletedProcess[str]) -> dict[str, object]:
    if result.returncode != 0:
        raise RuntimeError(f"wrapper failed with status {result.returncode}: {result.stderr[:500]}")
    payload = json.loads(result.stdout)
    if not isinstance(payload, dict):
        raise RuntimeError("wrapper record is not a JSON object")
    return payload


def _run_canaries(repo_root: Path, image: str) -> dict[str, object]:
    if "@sha256:" not in image:
        raise RuntimeError("canary image must use a repository sha256 digest")
    image_digest = image.rsplit("@", maxsplit=1)[1]
    fixtures = repo_root / "Prover" / "worker" / "tests" / "fixtures"

    normal = _require_record(_direct(image, fixtures / "Candidate.lean"))
    if normal != {
        "schema_version": PROTOCOL,
        "declaration": DECLARATION,
        "canonical_type": CANONICAL_TYPE,
        "lean_version": LEAN_VERSION,
        "mathlib_revision": MATHLIB_REVISION,
        "lake_manifest_hash": None,
        "observed_axioms": [],
    }:
        raise RuntimeError(f"unexpected authoritative wrapper record: {normal!r}")

    changed = _require_record(_direct(image, fixtures / "ChangedToTrue.lean"))
    if changed["canonical_type"] != "True":
        raise RuntimeError("changed-to-True canary did not observe the changed declaration type")
    if digest_text(HashKindV1.ELABORATED_TYPE, str(changed["canonical_type"])) == digest_text(
        HashKindV1.ELABORATED_TYPE, CANONICAL_TYPE
    ):
        raise RuntimeError("changed-to-True canary unexpectedly retained the frozen type hash")

    spoof = _direct(image, fixtures / "StdoutSpoof.lean")
    spoof_record = _require_record(spoof)
    if spoof_record != normal or spoof.stdout.count("\n") != 1:
        raise RuntimeError("candidate diagnostic output reached or forged the wrapper channel")

    wrong_declaration = _direct(
        image,
        fixtures / "Candidate.lean",
        declaration="AutoLean.OCI.missing",
    )
    if wrong_declaration.returncode == 0 or wrong_declaration.stdout:
        raise RuntimeError("wrong-declaration canary did not fail closed")

    wrong_profile = _direct(
        image,
        fixtures / "Candidate.lean",
        type_format="autolean.lean-pp-expr.unknown",
    )
    if wrong_profile.returncode == 0 or wrong_profile.stdout:
        raise RuntimeError("unknown helper profile did not fail closed")

    bundle = _bundle(image_digest)
    with tempfile.TemporaryDirectory(prefix="autolean-oci-canary-") as raw_root:
        root = Path(raw_root)
        workspace = WorkspaceMaterializer().materialize(bundle, root / "attempt")
        source = root / "source"
        dependencies = root / "dependencies"
        source.mkdir()
        dependencies.mkdir()
        _copy_frozen_source(workspace, source)
        harness = CleanSubprocessHarness(
            allowed_executables={"docker"},
            allowed_working_roots={root},
        )
        runner = OciLeanRunner(
            worker=OciWorkerHarness(
                harness=harness,
                spec=OciWorkerSpec(
                    runtime="docker",
                    image=image,
                    dependency_root=dependencies,
                    memory_limit="2g",
                    pids_limit=128,
                    timeout_seconds=120,
                ),
            ),
            immutable_source=source,
        )
        observation = TrustedLeanVerifier(
            runner=runner,
            verifier_id="oci-real-canary",
        ).observe(workspace, _submission(bundle, "by\n  rfl"))
        report = observation.report
        execution = observation.oci_execution_evidence
        if not (
            report.kernel_passed
            and report.build_passed
            and report.dependency_check_passed
            and report.clean_environment
            and report.observed_axioms == ()
            and execution is not None
            and execution.worker_image_digest == image_digest
        ):
            raise RuntimeError(f"OciLeanRunner canary did not pass: {report.model_dump_json()}")

        tampered = WorkspaceMaterializer().materialize(bundle, root / "tampered-attempt")
        tampered.write_proof("by\n  rfl")
        candidate = tampered.render_candidate()
        candidate.write_text(
            "namespace AutoLean.OCI\n\ntheorem fixture : True := by\n  trivial\n",
            encoding="utf-8",
            newline="\n",
        )
        try:
            runner.run(candidate, workspace=tampered)
        except ValidationError as error:
            if "oci_candidate_content_mismatch" not in str(error):
                raise
        else:
            raise RuntimeError("host runner accepted a changed-to-True candidate")

        result: dict[str, object] = {
            "schema_version": "autolean.oci-worker-canary.v1",
            "image": image,
            "image_digest": image_digest,
            "lean_version": LEAN_VERSION,
            "mathlib_revision": MATHLIB_REVISION,
            "mathlib_exercised": False,
            "declaration": DECLARATION,
            "canonical_type": CANONICAL_TYPE,
            "observed_axioms": [],
            "kernel_passed": report.kernel_passed,
            "build_passed": report.build_passed,
            "dependency_check_passed": report.dependency_check_passed,
            "clean_environment": report.clean_environment,
            "wrapper_stdout_spoof_rejected": True,
            "changed_to_true_detected": True,
            "wrong_declaration_rejected": True,
            "unknown_profile_rejected": True,
            "host_candidate_replacement_rejected": True,
            "command_policy_hash": execution.command_policy_hash,
            "command_hash": execution.command_hash,
            "candidate_sha256": execution.candidate_sha256,
            "trusted_statement_sha256": execution.trusted_statement_sha256,
            "bundle_manifest_sha256": execution.bundle_manifest_sha256,
            "promotion_attestation_created": False,
        }

    evidence = repo_root / "release-evidence" / "oci-worker"
    evidence.mkdir(parents=True, exist_ok=True)
    output = evidence / "canary.v1.json"
    rendered = json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    output.write_text(rendered, encoding="utf-8", newline="\n")
    result["evidence_sha256"] = hashlib.sha256(rendered.encode("utf-8")).hexdigest()
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    arguments = parser.parse_args()
    _run_canaries(Path(__file__).resolve().parents[1], arguments.image)


if __name__ == "__main__":
    main()
