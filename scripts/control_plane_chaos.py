"""Run a deterministic, test-only control-plane chaos campaign.

This script deliberately exercises only the local SQLite control-plane protocol.  It does not
invoke Lean, an OCI worker, a model provider, a network endpoint, or a real attestation
authority.  The HMAC material below is synthetic test data, never operator credentials.
Each reported restart reconstructs control-plane service objects in the same Python process from
the persisted SQLite and artifact state.  It is not an OS process-kill test.

Run the full campaign with the short workspace command:

    uv run python scripts/control_plane_chaos.py

The single JSON line on stdout is deterministic for a given argument set and intentionally
contains no proof source, prompt, artifact path, credential, or authority secret.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from autolean_contracts import (
    AlignmentTargetV1,
    AttestationPurposeV1,
    ExecutionGraphV1,
    FidelityRiskV1,
    FormalGraphV1,
    FormalizationTaskBundleV1,
    FormalSpecificationV1,
    FreezeRecordV1,
    GraphBundleV1,
    HashKindV1,
    HmacAttestationKeyV1,
    HmacAttestationSignerV1,
    HmacAttestationVerifierV1,
    LeanEnvironmentV1,
    MathematicalGraphV1,
    MathematicalSpecificationV1,
    OciVerificationArtifactV1,
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
    VerificationArtifactEnvironmentV1,
    VerificationEvidenceArtifactV1,
    VerificationEvidenceV1,
    VerificationReportV1,
    build_proof_boundary,
    builder_attestation_payload,
    digest_model,
    digest_text,
    proof_dependency_manifest_hash,
    stable_identifier,
    verification_attestation_payload,
)
from autolean_control_plane import (
    ArtifactStore,
    ControlPlane,
    DashboardProjection,
    EventStore,
    Lease,
    LeaseStore,
)
from autolean_control_plane.errors import InvalidTransition, StaleFence

_SCHEMA_VERSION = "autolean.control-plane-chaos.v1"
_INITIAL_TIME = datetime(2026, 1, 1, tzinfo=UTC)
_TEST_ONLY_BUILDER_KEY = HmacAttestationKeyV1(
    key_id="test-only-chaos-builder-v1",
    secret=b"autolean-chaos-builder-test-key-material-0001",
    allowed_purposes=frozenset({AttestationPurposeV1.BUILDER_FREEZE}),
)
_TEST_ONLY_VERIFIER_KEY = HmacAttestationKeyV1(
    key_id="test-only-chaos-verifier-v1",
    secret=b"autolean-chaos-verifier-test-key-material-0001",
    allowed_purposes=frozenset({AttestationPurposeV1.VERIFICATION}),
)


@dataclass(slots=True)
class MutableClock:
    """A deterministic clock shared by event, lease, and test-attestation components."""

    current: datetime

    def __call__(self) -> datetime:
        return self.current

    def advance(self, seconds: float) -> None:
        if seconds <= 0:
            raise ValueError("clock advances must be positive")
        self.current += timedelta(seconds=seconds)


def _id(key: str) -> StableIdentifierV1:
    return stable_identifier("control-plane-chaos", key)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _plane(database: Path, artifacts: Path, clock: MutableClock) -> ControlPlane:
    verifier = HmacAttestationVerifierV1(
        {
            _TEST_ONLY_BUILDER_KEY.key_id: _TEST_ONLY_BUILDER_KEY,
            _TEST_ONLY_VERIFIER_KEY.key_id: _TEST_ONLY_VERIFIER_KEY,
        },
        clock=clock,
    )
    return ControlPlane(
        events=EventStore(database, clock=clock),
        leases=LeaseStore(database, clock=clock),
        artifacts=ArtifactStore(artifacts),
        attestation_verifier=verifier,
        allow_test_only_direct_verifier_attestations=True,
        allow_test_only_unreviewed_bundles=True,
    )


def _bundle(
    *,
    key: str,
    signer: HmacAttestationSignerV1,
    clock: MutableClock,
    nonce: str,
) -> FormalizationTaskBundleV1:
    """Build one frozen synthetic bundle without reading a test helper or real source."""

    source_text = f"synthetic control-plane source {key}"
    span = SourceSpanV1(
        span_id=_id(f"span-{key}"),
        locator=f"synthetic://control-plane-chaos/{key}#statement",
        content_hash=digest_text(HashKindV1.SOURCE_SPAN, source_text),
        permitted_excerpt=source_text,
    )
    source = SourceRecordV1(
        source_id=_id(f"source-{key}"),
        work_id="control-plane-chaos",
        title="Synthetic control-plane chaos input",
        version="1",
        locator=f"synthetic://control-plane-chaos/{key}",
        content_hash=digest_text(HashKindV1.SOURCE_BYTES, source_text),
        retrieved_at=clock(),
        spans=(span,),
    )
    rights = RightsRecordV1(
        rights_id=_id(f"rights-{key}"),
        source_id=source.source_id,
        source_license="CC0-1.0",
        overall_decision=PermissionDecisionV1.ALLOW,
        reviewed_by="test-only-control-plane-authority",
        reviewed_at=clock(),
    )
    declaration_name = f"synthetic_{key.replace('-', '_')}"
    statement = f"theorem {declaration_name} (n : Nat) : n = n"
    elaborated_type = "forall (n : Nat), Eq n n"
    formal = FormalSpecificationV1(
        declaration_name=declaration_name,
        namespace="AutoLean.ControlPlaneChaos",
        lean_statement_source=statement,
        statement_source_hash=digest_text(HashKindV1.STATEMENT_SOURCE, statement),
        elaborated_type=elaborated_type,
        elaborated_type_hash=digest_text(HashKindV1.ELABORATED_TYPE, elaborated_type),
        environment=LeanEnvironmentV1(
            lean_version="simulated-lean-not-executed",
            mathlib_revision="simulated-mathlib-not-executed",
            verifier_execution_policy=OciVerifierExecutionPolicyV1(
                worker_image_digest="sha256:" + ("0" * 64),
            ),
            environment_hash=digest_text(
                HashKindV1.ENVIRONMENT,
                "control-plane-chaos-simulated-environment-v1",
            ),
        ),
    )
    draft = StatementContractV1(
        contract_id=_id(f"contract-{key}"),
        revision=1,
        task_kind=TaskKindV1.KNOWN_THEOREM,
        source=source,
        rights=rights,
        mathematics=MathematicalSpecificationV1(
            informal_statement="A synthetic reflexivity statement for control-plane testing.",
            normalized_statement="For every natural number n, n equals n.",
        ),
        formal=formal,
        alignments=(
            AlignmentTargetV1(
                source_span_id=span.span_id,
                formal_target=f"AutoLean.ControlPlaneChaos.{declaration_name}",
                relation="formalizes",
                confidence=1.0,
            ),
        ),
        policy=TaskPolicyV1(
            release_tier=ReleaseTierV1.CALIBRATION,
            fidelity_risk=FidelityRiskV1.L1_SIMPLE,
        ),
    )
    frozen_payload: dict[str, Any] = draft.model_dump(mode="python", round_trip=True)
    frozen_payload.update(
        {
            "status": StatementStatusV1.FROZEN,
            "freeze": FreezeRecordV1(
                contract_hash=draft.semantic_hash(),
                source_hash=source.content_hash,
                source_preparation_id=stable_identifier(
                    "source-preparation", f"control-plane-chaos:{key}"
                ),
                source_preparation_hash=digest_text(
                    HashKindV1.SOURCE_PREPARATION, f"control-plane-chaos:{key}"
                ),
                statement_source_hash=formal.statement_source_hash,
                elaborated_type_hash=formal.elaborated_type_hash,
                frozen_by="test-only-control-plane-authority",
                frozen_at=clock(),
            ),
        }
    )
    frozen = StatementContractV1.model_validate(frozen_payload)
    graphs = GraphBundleV1(
        mathematical=MathematicalGraphV1(graph_id=_id(f"mathematical-{key}"), revision=1),
        formal=FormalGraphV1(graph_id=_id(f"formal-{key}"), revision=1),
        execution=ExecutionGraphV1(graph_id=_id(f"execution-{key}"), revision=1),
    )
    unsigned = FormalizationTaskBundleV1(
        bundle_id=_id(f"bundle-{key}"),
        contract=frozen,
        graphs=graphs,
        graph_snapshot_hash=digest_model(HashKindV1.GRAPH_SNAPSHOT, graphs),
        proof_boundary=build_proof_boundary(frozen),
        issued_at=clock(),
    )
    attestation = signer.issue(
        purpose=AttestationPurposeV1.BUILDER_FREEZE,
        payload=builder_attestation_payload(unsigned),
        evidence_identity=f"test-only-builder-freeze-{key}",
        ttl_seconds=1.0,
        nonce=nonce,
    )
    return unsigned.model_copy(update={"builder_attestation": attestation})


def _submission(
    bundle: FormalizationTaskBundleV1,
    *,
    key: str,
    clock: MutableClock,
) -> ProofSubmissionV1:
    source = "by\n  rfl"
    return ProofSubmissionV1(
        proof_id=_id(f"proof-{key}"),
        contract_id=bundle.contract.contract_id,
        revision=bundle.contract.revision,
        contract_hash=bundle.contract.semantic_hash(),
        proof_boundary_hash=bundle.proof_boundary.boundary_hash,
        proof_source=source,
        proof_source_hash=digest_text(HashKindV1.PROOF_SOURCE, source),
        environment_hash=bundle.contract.formal.environment.environment_hash,
        submitted_at=clock(),
    )


def _proof_artifact_digest(plane: ControlPlane, submission: ProofSubmissionV1) -> str:
    events = plane.events.read_stream("proof", submission.proof_id.value)
    _require(len(events) == 1, "a submitted proof must have exactly one proof event")
    artifact = events[0].payload.get("proof_artifact")
    if not isinstance(artifact, dict):
        raise AssertionError("proof event must contain an artifact reference")
    digest = artifact.get("digest")
    if not isinstance(digest, str):
        raise AssertionError("proof event artifact must contain a digest")
    return digest


def _passing_report(
    plane: ControlPlane,
    bundle: FormalizationTaskBundleV1,
    submission: ProofSubmissionV1,
    *,
    key: str,
    signer: HmacAttestationSignerV1,
    clock: MutableClock,
) -> VerificationReportV1:
    """Create a synthetic verifier record solely to exercise control-plane validation."""

    environment = bundle.contract.formal.environment
    policy = environment.verifier_execution_policy
    command_hash = digest_text(
        HashKindV1.VERIFICATION_COMMAND,
        "test-only-simulated-control-plane-command-v1",
    )
    observation = VerificationReportV1(
        report_id=_id(f"verification-{key}"),
        proof_id=submission.proof_id,
        contract_hash=submission.contract_hash,
        proof_boundary_hash=submission.proof_boundary_hash,
        verifier_id="test-only-simulated-control-plane-verifier",
        independent=True,
        kernel_passed=True,
        build_passed=True,
        dependency_check_passed=True,
        clean_environment=True,
        environment_hash=submission.environment_hash,
        axiom_profile=bundle.contract.policy.axiom_profile,
        details="Synthetic control-plane record only; no Lean or OCI execution occurred.",
        verified_at=clock(),
    )
    candidate = (
        f"{bundle.proof_boundary.trusted_statement_source} := {submission.proof_source.rstrip()}\n"
        f"\n#print axioms {bundle.proof_boundary.expected_declaration}\n"
    )
    evidence_artifact = plane.artifacts.put_json(
        VerificationEvidenceArtifactV1(
            evidence_id=_id(f"evidence-{key}"),
            bundle_id=bundle.bundle_id,
            bundle_hash=bundle.handoff_hash(),
            contract_id=bundle.contract.contract_id,
            revision=bundle.contract.revision,
            contract_hash=bundle.contract.semantic_hash(),
            proof_id=submission.proof_id,
            proof_boundary_hash=bundle.proof_boundary.boundary_hash,
            proof_submission_artifact_digest=_proof_artifact_digest(plane, submission),
            dependency_manifest_hash=proof_dependency_manifest_hash(submission),
            verification_report_id=observation.report_id,
            verification_observation_hash=observation.report_hash(),
            environment=VerificationArtifactEnvironmentV1(
                environment_hash=environment.environment_hash,
                lean_version=environment.lean_version,
                mathlib_revision=environment.mathlib_revision,
                lake_manifest_hash=environment.lake_manifest_hash,
            ),
            oci=OciVerificationArtifactV1(
                worker_image_digest=policy.worker_image_digest,
                wrapper_protocol=policy.wrapper_protocol,
                command_policy_hash=policy.command_policy_hash(),
                command_hash=command_hash,
                candidate_sha256=hashlib.sha256(candidate.encode("utf-8")).hexdigest(),
                trusted_statement_sha256=bundle.proof_boundary.trusted_statement_hash.value,
                bundle_manifest_sha256=bundle.proof_boundary.solver_manifest_hash.value,
            ),
        ).model_dump(mode="json")
    )
    evidence = VerificationEvidenceV1(
        evidence_id=_id(f"evidence-{key}"),
        environment_hash=submission.environment_hash,
        worker_image_digest=policy.worker_image_digest,
        wrapper_protocol=policy.wrapper_protocol,
        lean_version=environment.lean_version,
        mathlib_revision=environment.mathlib_revision,
        lake_manifest_hash=environment.lake_manifest_hash,
        dependency_manifest_hash=proof_dependency_manifest_hash(submission),
        command_policy_hash=policy.command_policy_hash(),
        command_hash=command_hash,
        evidence_artifact_digest=evidence_artifact.digest,
        captured_at=clock(),
    )
    report = observation.model_copy(update={"evidence": evidence})
    attestation = signer.issue(
        purpose=AttestationPurposeV1.VERIFICATION,
        payload=verification_attestation_payload(
            bundle_id=bundle.bundle_id.value,
            bundle_hash=bundle.handoff_hash().value,
            proof_submission_artifact_digest=_proof_artifact_digest(plane, submission),
            contract_id=bundle.contract.contract_id.value,
            revision=bundle.contract.revision,
            contract_hash=report.contract_hash,
            proof_boundary_hash=report.proof_boundary_hash,
            environment_hash=report.environment_hash,
            report=report,
        ),
        evidence_identity=evidence.evidence_id.value,
        ttl_seconds=1.0,
        nonce=f"verifier-{key:0>24}",
    )
    return report.model_copy(update={"verifier_attestation": attestation})


def _assert_stale_token_is_rejected(
    plane: ControlPlane,
    bundle: FormalizationTaskBundleV1,
    old_lease: Lease,
    *,
    key: str,
    clock: MutableClock,
) -> None:
    """Check that a stale worker cannot create a second proof event."""

    stale_submission = _submission(bundle, key=f"stale-{key}", clock=clock)
    try:
        plane.submit_proof(
            bundle.bundle_id.value,
            lease=old_lease,
            submission=stale_submission,
            idempotency_key=f"stale-proof-{key}",
        )
    except StaleFence:
        pass
    else:
        raise AssertionError("a stale fencing token was allowed to submit a proof")
    _require(
        not plane.events.read_stream("proof", stale_submission.proof_id.value),
        "a stale fencing token created a proof event",
    )


def _prepare_workspace(
    workspace: Path | None,
) -> tuple[Path, tempfile.TemporaryDirectory[str] | None]:
    if workspace is None:
        temporary = tempfile.TemporaryDirectory(prefix="autolean-control-plane-chaos-")
        return Path(temporary.name), temporary
    root = workspace.resolve()
    if root.exists() and any(root.iterdir()):
        raise ValueError("--workspace must be empty; the chaos script never deletes existing data")
    root.mkdir(parents=True, exist_ok=True)
    return root, None


def run_campaign(
    *,
    jobs: int = 1_000,
    restart_every: int = 10,
    workspace: Path | None = None,
) -> dict[str, object]:
    """Run a reproducible crash/replay campaign and return non-sensitive evidence only."""

    if jobs <= 0:
        raise ValueError("jobs must be positive")
    if restart_every <= 0:
        raise ValueError("restart_every must be positive")

    root, temporary = _prepare_workspace(workspace)
    try:
        clock = MutableClock(_INITIAL_TIME)
        database = root / "control-plane-chaos.sqlite3"
        artifact_root = root / "artifacts"
        plane = _plane(database, artifact_root, clock)
        builder = HmacAttestationSignerV1(_TEST_ONLY_BUILDER_KEY, clock=clock)
        verifier = HmacAttestationSignerV1(_TEST_ONLY_VERIFIER_KEY, clock=clock)

        bundle_ids: list[str] = []
        proof_ids: list[str] = []
        restart_count = 0
        stale_fence_rejections = 0
        idempotent_replays = 0

        for job in range(jobs):
            key = f"job-{job:04d}"
            bundle = _bundle(
                key=key,
                signer=builder,
                clock=clock,
                nonce=f"builder-{key:0>24}",
            )
            binding = plane.register_bundle(bundle, idempotency_key=f"register-{key}")
            claim = plane.claim(
                bundle.bundle_id.value,
                worker_id=f"worker-{key}",
                ttl_seconds=1.0,
                idempotency_key=f"claim-{key}",
            )
            submission = _submission(bundle, key=key, clock=clock)
            submitted = plane.submit_proof(
                bundle.bundle_id.value,
                lease=claim.lease,
                submission=submission,
                idempotency_key=f"submit-{key}",
            )
            report = _passing_report(
                plane,
                bundle,
                submission,
                key=key,
                signer=verifier,
                clock=clock,
            )
            verified = plane.verify_submission(
                bundle.bundle_id.value,
                lease=claim.lease,
                report=report,
                idempotency_key=f"verify-{key}",
            )
            _require(verified.accepted, "the synthetic verification record was not accepted")

            bundle_ids.append(bundle.bundle_id.value)
            proof_ids.append(submission.proof_id.value)
            clock.advance(2.0)

            if job % restart_every == 0:
                plane = _plane(database, artifact_root, clock)
                restart_count += 1

            _require(
                plane.register_bundle(bundle, idempotency_key=f"register-{key}") == binding,
                "registered bundle replay did not return the original binding",
            )
            _require(
                plane.claim(
                    bundle.bundle_id.value,
                    worker_id=f"worker-{key}",
                    ttl_seconds=1.0,
                    idempotency_key=f"claim-{key}",
                )
                == claim,
                "claim replay did not return the original lease",
            )
            _require(
                plane.submit_proof(
                    bundle.bundle_id.value,
                    lease=claim.lease,
                    submission=submission,
                    idempotency_key=f"submit-{key}",
                )
                == submitted,
                "proof replay did not return the original event",
            )
            _require(
                plane.verify_submission(
                    bundle.bundle_id.value,
                    lease=claim.lease,
                    report=report,
                    idempotency_key=f"verify-{key}",
                )
                == verified,
                "verification replay did not return the original terminal verdict",
            )
            idempotent_replays += 4

            replacement = plane.claim(
                bundle.bundle_id.value,
                worker_id=f"replacement-{key}",
                ttl_seconds=1.0,
                idempotency_key=f"replacement-claim-{key}",
            )
            _require(
                replacement.lease.fencing_token > claim.lease.fencing_token,
                "replacement claim did not advance the fencing token",
            )
            _assert_stale_token_is_rejected(
                plane,
                bundle,
                claim.lease,
                key=key,
                clock=clock,
            )
            stale_fence_rejections += 1

        nonce = "builder-attestation-nonce-replay-probe"
        accepted_probe = _bundle(
            key="nonce-probe-accepted",
            signer=builder,
            clock=clock,
            nonce=nonce,
        )
        plane.register_bundle(accepted_probe, idempotency_key="nonce-probe-accepted")
        replay_probe = _bundle(
            key="nonce-probe-replayed",
            signer=builder,
            clock=clock,
            nonce=nonce,
        )
        try:
            plane.register_bundle(replay_probe, idempotency_key="nonce-probe-replayed")
        except InvalidTransition as error:
            _require("nonce" in str(error).lower(), "nonce replay failed for the wrong reason")
        else:
            raise AssertionError("reused Builder attestation nonce was accepted")
        _require(
            plane.get_binding(replay_probe.bundle_id.value, required=False) is None,
            "replayed Builder attestation registered a task",
        )

        final_plane = _plane(database, artifact_root, clock)
        events = final_plane.events.read_all()
        replayed_events = EventStore(database, clock=clock).read_all()
        _require(events == replayed_events, "event replay produced a different event sequence")
        _require(
            [event.global_position for event in events] == list(range(1, len(events) + 1)),
            "event positions are not contiguous",
        )
        expected_event_count = (jobs * 5) + 1
        _require(len(events) == expected_event_count, "unexpected number of persisted events")
        _require(
            final_plane.events.count_events(entity_type="proof") == jobs,
            "a logical job lost or duplicated its proof event",
        )
        _require(
            final_plane.events.count_events(entity_type="verification") == jobs,
            "a proof did not have exactly one terminal verdict",
        )
        for bundle_id in bundle_ids:
            _require(
                final_plane.get_binding(bundle_id, required=False) is not None,
                "task was lost",
            )
        for proof_id in proof_ids:
            terminal = final_plane.events.read_stream("verification", proof_id)
            _require(len(terminal) == 1, "proof has more or fewer than one terminal verdict")
            _require(
                terminal[0].event_type in {"verification.accepted", "verification.rejected"},
                "terminal verdict event type is invalid",
            )
        projection = DashboardProjection(events).snapshot()
        runs = projection.get("runs")
        _require(isinstance(runs, list) and len(runs) == jobs, "event replay projection lost runs")

        return {
            "schema_version": _SCHEMA_VERSION,
            "evidence_scope": "simulated_control_plane_only",
            "lean_or_oci_execution": False,
            "test_only_hmac_authority": True,
            "jobs_requested": jobs,
            "jobs_completed": jobs,
            "auxiliary_nonce_probe_tasks": 1,
            "control_plane_restarts": restart_count,
            "restart_mode": "in_process_service_reconstruction",
            "os_process_kill_exercised": False,
            "restart_interval": restart_every,
            "idempotent_replays": idempotent_replays,
            "expired_attestation_replays": jobs * 2,
            "replacement_claims": jobs,
            "stale_fence_rejections": stale_fence_rejections,
            "nonce_replay_rejections": 1,
            "proof_submissions": jobs,
            "terminal_verdicts": jobs,
            "per_proof_terminal_verdicts": 1,
            "event_count": len(events),
            "expected_event_count": expected_event_count,
            "event_positions_contiguous": True,
            "event_replay_consistent": True,
            "task_loss_detected": False,
            "duplicate_terminal_verdict_detected": False,
        }
    finally:
        if temporary is not None:
            temporary.cleanup()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jobs", type=int, default=1_000, help="logical jobs to simulate")
    parser.add_argument(
        "--restart-every",
        type=int,
        default=10,
        help="recreate the control-plane service after this many logical jobs",
    )
    parser.add_argument(
        "--workspace",
        type=Path,
        help="optional empty directory to retain only synthetic SQLite/artifact evidence",
    )
    args = parser.parse_args()
    summary = run_campaign(
        jobs=args.jobs,
        restart_every=args.restart_every,
        workspace=args.workspace,
    )
    print(json.dumps(summary, ensure_ascii=True, separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    main()
