"""The only command gateway shared by Builder-owned bundles and Prover-owned evidence."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, cast, overload

from autolean_contracts import (
    AttestationError,
    AttestationPurposeV1,
    AttestationV1,
    AttestationVerifierV1,
    AxiomProfileV1,
    ContractChangeRequestV1,
    DigestV1,
    FormalizationTaskBundleV1,
    GapReportV1,
    HashKindV1,
    ProofSubmissionV1,
    StableIdentifierV1,
    VerificationEvidenceArtifactV1,
    VerificationReportV1,
    VerificationSigningContextV1,
    VerificationSigningLeaseBindingV1,
    builder_attestation_payload,
    proof_dependency_manifest_hash,
    verification_attestation_payload,
    verification_gateway_attestation_payload,
)

from .artifacts import ArtifactRef, ArtifactStore
from .errors import (
    ArtifactCorruption,
    ArtifactNotFound,
    AttestationReplay,
    ConcurrencyError,
    ContractRevisionConflict,
    InvalidTransition,
    ProjectionError,
    TaskNotFound,
)
from .events import (
    AttestationNonce,
    ContractRevisionBinding,
    EventStore,
    Idempotency,
    JsonObject,
    NewEvent,
    StoredEvent,
    canonical_json,
    request_hash,
)
from .leases import Lease, LeaseStore

_PLACEHOLDER_RE = re.compile(r"\b(?:sorry|admit)\b|sorryAx")


@dataclass(frozen=True, slots=True)
class TaskBinding:
    bundle_id: str
    bundle_hash: str
    contract_id: str
    revision: int
    contract_hash: str
    proof_boundary_hash: str
    environment_hash: str
    lean_version: str
    mathlib_revision: str
    lake_manifest_hash: str | None
    worker_image_digest: str
    wrapper_protocol: str
    command_policy_hash: str
    axiom_profile: str
    axioms_allowlist: frozenset[str]
    bundle_artifact: ArtifactRef
    fidelity_evidence_artifact: ArtifactRef | None
    graph_nodes: tuple[JsonObject, ...]


@dataclass(frozen=True, slots=True)
class ClaimReceipt:
    lease: Lease
    event: StoredEvent


@dataclass(frozen=True, slots=True)
class VerificationOutcome:
    accepted: bool
    reasons: tuple[str, ...]
    event: StoredEvent


class ControlPlane:
    """Versioned command boundary with idempotency, leases, and immutable evidence.

    It never calls a model or applies a statement change.  A contract-change request is recorded
    as evidence for Builder review, and a proof result is only accepted after its independent
    verifier report passes every structural gate.
    """

    def __init__(
        self,
        *,
        events: EventStore,
        leases: LeaseStore,
        artifacts: ArtifactStore,
        attestation_verifier: AttestationVerifierV1,
        allow_test_only_direct_verifier_attestations: bool = False,
        allow_test_only_unreviewed_bundles: bool = False,
    ) -> None:
        if events.path.resolve() != leases.path.resolve():
            raise ValueError("events and leases must share one SQLite database for fenced writes")
        self.events = events
        self.leases = leases
        self.artifacts = artifacts
        self.attestation_verifier = attestation_verifier
        self.allow_test_only_direct_verifier_attestations = (
            allow_test_only_direct_verifier_attestations
        )
        self.allow_test_only_unreviewed_bundles = allow_test_only_unreviewed_bundles

    def _idempotency(
        self,
        *,
        scope: str,
        key: str,
        semantic_request: object,
    ) -> Idempotency:
        """Bind retries to stable command input, not leases, artifacts, or clock values."""

        return Idempotency(
            scope=scope,
            key=key,
            request_hash=request_hash(semantic_request),
        )

    def _replayed_event(self, idempotency: Idempotency) -> StoredEvent | None:
        events = self.events.lookup_idempotency(idempotency)
        if events is None:
            return None
        if len(events) != 1:
            raise InvalidTransition("corrupt idempotency record references multiple command events")
        return events[0]

    @staticmethod
    def _claim_receipt_from_event(bundle_id: str, event: StoredEvent) -> ClaimReceipt:
        payload = event.payload
        expires_at_text = ControlPlane._required_text(payload, "expires_at")
        try:
            expires_at = datetime.fromisoformat(expires_at_text.replace("Z", "+00:00"))
        except ValueError as error:
            raise InvalidTransition("corrupt claimed-task expiry timestamp") from error
        return ClaimReceipt(
            lease=Lease(
                job_id=bundle_id,
                holder_id=ControlPlane._required_text(payload, "worker_id"),
                fencing_token=ControlPlane._required_int(payload, "fencing_token"),
                expires_at=expires_at,
            ),
            event=event,
        )

    @staticmethod
    def _verification_outcome_from_event(event: StoredEvent) -> VerificationOutcome:
        accepted = event.payload.get("accepted")
        if not isinstance(accepted, bool):
            raise InvalidTransition("corrupt verification event acceptance flag")
        reasons = ControlPlane._required_texts(event.payload, "reasons")
        return VerificationOutcome(accepted=accepted, reasons=reasons, event=event)

    @staticmethod
    def _lease_identity(lease: Lease) -> dict[str, object]:
        """The fencing identity is durable command input; the volatile expiry is not."""

        return {
            "job_id": lease.job_id,
            "holder_id": lease.holder_id,
            "fencing_token": lease.fencing_token,
        }

    def register_bundle(
        self,
        bundle: FormalizationTaskBundleV1,
        *,
        idempotency_key: str,
    ) -> TaskBinding:
        """Register an immutable Builder handoff before any worker can claim it."""

        freeze = bundle.contract.freeze
        if (
            freeze is None
            or freeze.source_preparation_id is None
            or freeze.source_preparation_hash is None
        ):
            raise InvalidTransition(
                "Builder handoff requires committed source-preparation evidence"
            )
        bundle_id = bundle.bundle_id.value
        attestation_signature = (
            None if bundle.builder_attestation is None else bundle.builder_attestation.signature
        )
        idempotency = self._idempotency(
            scope="register_bundle",
            key=idempotency_key,
            semantic_request={
                "bundle_id": bundle_id,
                "bundle_hash": bundle.handoff_hash().value,
                "builder_attestation_signature": attestation_signature,
            },
        )
        replayed = self._replayed_event(idempotency)
        if replayed is not None:
            return self._binding_from_event(replayed)
        builder_attestation = self._verify_builder_attestation(bundle)
        fidelity_artifact = self._verify_builder_fidelity_artifact(bundle)
        desired = self._binding_from_bundle(bundle)
        artifact = self._put_model(bundle)
        binding = TaskBinding(
            bundle_id=desired.bundle_id,
            bundle_hash=desired.bundle_hash,
            contract_id=desired.contract_id,
            revision=desired.revision,
            contract_hash=desired.contract_hash,
            proof_boundary_hash=desired.proof_boundary_hash,
            environment_hash=desired.environment_hash,
            lean_version=desired.lean_version,
            mathlib_revision=desired.mathlib_revision,
            lake_manifest_hash=desired.lake_manifest_hash,
            worker_image_digest=desired.worker_image_digest,
            wrapper_protocol=desired.wrapper_protocol,
            command_policy_hash=desired.command_policy_hash,
            axiom_profile=desired.axiom_profile,
            axioms_allowlist=desired.axioms_allowlist,
            bundle_artifact=artifact,
            fidelity_evidence_artifact=fidelity_artifact,
            graph_nodes=desired.graph_nodes,
        )
        payload = self._json_object(
            {
                "bundle_id": binding.bundle_id,
                "bundle_hash": binding.bundle_hash,
                "contract_id": binding.contract_id,
                "revision": binding.revision,
                "contract_hash": binding.contract_hash,
                "proof_boundary_hash": binding.proof_boundary_hash,
                "environment_hash": binding.environment_hash,
                "lean_version": binding.lean_version,
                "mathlib_revision": binding.mathlib_revision,
                "lake_manifest_hash": binding.lake_manifest_hash,
                "worker_image_digest": binding.worker_image_digest,
                "wrapper_protocol": binding.wrapper_protocol,
                "command_policy_hash": binding.command_policy_hash,
                "axiom_profile": binding.axiom_profile,
                "axioms_allowlist": sorted(binding.axioms_allowlist),
                "bundle_artifact": self._artifact_payload(artifact, kind="bundle"),
                "fidelity_evidence_artifact": (
                    None
                    if fidelity_artifact is None
                    else self._artifact_payload(
                        fidelity_artifact,
                        kind="builder_fidelity_evidence",
                    )
                ),
                "builder_attestation": self._attestation_summary(builder_attestation),
                "graph_nodes": list(binding.graph_nodes),
            }
        )
        try:
            events = self.events.append_contract_revision_registration(
                ContractRevisionBinding(
                    contract_id=binding.contract_id,
                    revision=binding.revision,
                    bundle_id=binding.bundle_id,
                    bundle_hash=binding.bundle_hash,
                    contract_hash=binding.contract_hash,
                ),
                event=NewEvent("task.registered", payload=payload),
                idempotency=idempotency,
                attestation_nonce=self._attestation_nonce(builder_attestation),
            )
        except AttestationReplay as error:
            raise InvalidTransition("Builder attestation nonce was replayed") from error
        except ContractRevisionConflict as error:
            raise InvalidTransition(
                "contract revision or bundle ID is already bound to a different frozen bundle"
            ) from error
        stored = self._binding_from_event(events[0])
        if not self._same_logical_binding(stored, desired):
            raise ProjectionError(
                "canonical registration event disagrees with the requested immutable bundle"
            )
        return stored

    def claim(
        self,
        bundle_id: str,
        *,
        worker_id: str,
        ttl_seconds: float,
        idempotency_key: str,
    ) -> ClaimReceipt:
        """Acquire a fenced worker lease for a previously registered immutable bundle."""

        idempotency = self._idempotency(
            scope="claim",
            key=idempotency_key,
            semantic_request={
                "bundle_id": bundle_id,
                "worker_id": worker_id,
                "ttl_seconds": ttl_seconds,
            },
        )
        replayed = self._replayed_event(idempotency)
        if replayed is not None:
            return self._claim_receipt_from_event(bundle_id, replayed)
        self.get_binding(bundle_id)
        lease = self.leases.claim(bundle_id, worker_id, ttl_seconds=ttl_seconds)
        payload = self._json_object(
            {
                "worker_id": worker_id,
                "fencing_token": lease.fencing_token,
                "expires_at": lease.expires_at.isoformat(),
            }
        )
        events = self.events.append(
            "task",
            bundle_id,
            expected_sequence=self.events.current_sequence("task", bundle_id),
            events=(NewEvent("task.claimed", payload=payload),),
            idempotency=idempotency,
        )
        return ClaimReceipt(lease=lease, event=events[0])

    def submit_proof(
        self,
        bundle_id: str,
        *,
        lease: Lease,
        submission: ProofSubmissionV1,
        idempotency_key: str,
    ) -> StoredEvent:
        """Record a Prover candidate without granting it any verification status."""

        idempotency = self._idempotency(
            scope="submit_proof",
            key=idempotency_key,
            semantic_request={
                "bundle_id": bundle_id,
                "lease": self._lease_identity(lease),
                "submission": submission.model_dump(mode="json"),
            },
        )
        replayed = self._replayed_event(idempotency)
        if replayed is not None:
            return replayed
        binding = self.get_binding(bundle_id)
        self._assert_lease(bundle_id, lease)
        self._validate_proof_binding(binding, submission)
        if _PLACEHOLDER_RE.search(submission.proof_source):
            raise InvalidTransition("proof submissions may not contain sorry, admit, or sorryAx")
        artifact = self._put_model(submission)
        provider, model = self._model_attribution(submission)
        payload = self._json_object(
            {
                "bundle_id": bundle_id,
                "proof_id": submission.proof_id.value,
                "contract_id": submission.contract_id.value,
                "revision": submission.revision,
                "contract_hash": submission.contract_hash.value,
                "proof_boundary_hash": submission.proof_boundary_hash.value,
                "environment_hash": submission.environment_hash.value,
                "dependency_manifest_hash": proof_dependency_manifest_hash(submission).value,
                "provider": provider,
                "model": model,
                "input_tokens": submission.metrics.input_tokens,
                "output_tokens": submission.metrics.output_tokens,
                "cached_input_tokens": submission.metrics.cached_input_tokens,
                "cost_usd": submission.metrics.cost_usd,
                "duration_ms": submission.metrics.elapsed_ms,
                "proof_artifact": self._artifact_payload(artifact, kind="proof_submission"),
                "fencing_token": lease.fencing_token,
            }
        )
        events = self.events.append_fenced(
            "proof",
            submission.proof_id.value,
            task_id=bundle_id,
            lease=lease,
            expected_sequence=0,
            events=(NewEvent("proof.submitted", payload=payload),),
            idempotency=idempotency,
        )
        return events[0]

    def report_gap(
        self,
        bundle_id: str,
        *,
        lease: Lease,
        report: GapReportV1,
        idempotency_key: str,
    ) -> StoredEvent:
        """Persist evidence of a gap without changing the frozen statement."""

        idempotency = self._idempotency(
            scope="report_gap",
            key=idempotency_key,
            semantic_request={
                "bundle_id": bundle_id,
                "lease": self._lease_identity(lease),
                "report": report.model_dump(mode="json"),
            },
        )
        replayed = self._replayed_event(idempotency)
        if replayed is not None:
            return replayed
        binding = self.get_binding(bundle_id)
        self._assert_lease(bundle_id, lease)
        self._validate_report_binding(
            binding.contract_id,
            binding.revision,
            binding.contract_hash,
            report.contract_id.value,
            report.revision,
            report.contract_hash.value,
        )
        artifact = self._put_model(report)
        payload = self._json_object(
            {
                "bundle_id": bundle_id,
                "report_id": report.report_id.value,
                "kind": report.kind.value,
                "contract_hash": report.contract_hash.value,
                "gap_artifact": self._artifact_payload(artifact, kind="gap_report"),
                "fencing_token": lease.fencing_token,
            }
        )
        events = self.events.append_fenced(
            "gap",
            report.report_id.value,
            task_id=bundle_id,
            lease=lease,
            expected_sequence=0,
            events=(NewEvent("gap.reported", payload=payload),),
            idempotency=idempotency,
        )
        return events[0]

    def request_contract_change(
        self,
        bundle_id: str,
        *,
        lease: Lease,
        request: ContractChangeRequestV1,
        idempotency_key: str,
    ) -> StoredEvent:
        """Record a request for Builder review; this method cannot apply the request."""

        idempotency = self._idempotency(
            scope="request_contract_change",
            key=idempotency_key,
            semantic_request={
                "bundle_id": bundle_id,
                "lease": self._lease_identity(lease),
                "request": request.model_dump(mode="json"),
            },
        )
        replayed = self._replayed_event(idempotency)
        if replayed is not None:
            return replayed
        binding = self.get_binding(bundle_id)
        self._assert_lease(bundle_id, lease)
        self._validate_report_binding(
            binding.contract_id,
            binding.revision,
            binding.contract_hash,
            request.contract_id.value,
            request.old_revision,
            request.old_contract_hash.value,
        )
        artifact = self._put_model(request)
        payload = self._json_object(
            {
                "bundle_id": bundle_id,
                "request_id": request.request_id.value,
                "contract_id": request.contract_id.value,
                "old_revision": request.old_revision,
                "old_contract_hash": request.old_contract_hash.value,
                "request_artifact": self._artifact_payload(
                    artifact, kind="contract_change_request"
                ),
                "fencing_token": lease.fencing_token,
            }
        )
        events = self.events.append_fenced(
            "contract_change_request",
            request.request_id.value,
            task_id=bundle_id,
            lease=lease,
            expected_sequence=0,
            events=(NewEvent("contract_change.requested", payload=payload),),
            idempotency=idempotency,
        )
        return events[0]

    def verify_submission(
        self,
        bundle_id: str,
        *,
        lease: Lease,
        report: VerificationReportV1,
        idempotency_key: str,
    ) -> VerificationOutcome:
        """Record a verifier result and admit it only if every frozen-boundary check passes."""

        idempotency = self._idempotency(
            scope="verify_submission",
            key=idempotency_key,
            semantic_request={
                "bundle_id": bundle_id,
                "lease": self._lease_identity(lease),
                "report": report.model_dump(mode="json"),
            },
        )
        replayed = self._replayed_event(idempotency)
        if replayed is not None:
            return self._verification_outcome_from_event(replayed)
        binding = self.get_binding(bundle_id)
        self._assert_lease(bundle_id, lease)
        proof_event = self._proof_event(report.proof_id.value)
        self._validate_verification_binding(binding, report, proof_event)
        verifier_attestation = self._verify_verification_attestation(
            binding,
            report,
            proof_event,
            lease,
        )
        reasons = self._verification_failures(binding, report)
        artifact = self._put_model(report)
        payload = self._json_object(
            {
                "bundle_id": bundle_id,
                "report_id": report.report_id.value,
                "proof_id": report.proof_id.value,
                "contract_hash": report.contract_hash.value,
                "proof_boundary_hash": report.proof_boundary_hash.value,
                "accepted": not reasons,
                "reasons": list(reasons),
                "verifier_attestation": self._attestation_summary(verifier_attestation),
                "verification_artifact": self._artifact_payload(
                    artifact, kind="verification_report"
                ),
                "fencing_token": lease.fencing_token,
            }
        )
        try:
            events = self.events.append_fenced(
                "verification",
                report.proof_id.value,
                task_id=bundle_id,
                lease=lease,
                expected_sequence=0,
                events=(
                    NewEvent(
                        "verification.accepted" if not reasons else "verification.rejected",
                        payload=payload,
                    ),
                ),
                idempotency=idempotency,
                attestation_nonce=self._attestation_nonce(verifier_attestation),
            )
        except (AttestationReplay, ConcurrencyError) as error:
            raise InvalidTransition(
                "verification attestation was replayed or proof already has a terminal "
                "verification verdict"
            ) from error
        return VerificationOutcome(accepted=not reasons, reasons=tuple(reasons), event=events[0])

    @overload
    def get_binding(self, bundle_id: str, *, required: Literal[True] = True) -> TaskBinding: ...

    @overload
    def get_binding(self, bundle_id: str, *, required: Literal[False]) -> TaskBinding | None: ...

    def get_binding(self, bundle_id: str, *, required: bool = True) -> TaskBinding | None:
        events = self.events.read_stream("task", bundle_id)
        registered = next(
            (event for event in events if event.event_type == "task.registered"), None
        )
        if registered is None:
            if required:
                raise TaskNotFound(f"bundle {bundle_id!r} is not registered")
            return None
        return self._binding_from_event(registered)

    def _binding_from_bundle(self, bundle: FormalizationTaskBundleV1) -> TaskBinding:
        contract = bundle.contract
        verifier_policy = contract.formal.environment.verifier_execution_policy
        graph_nodes = self._graph_nodes(bundle)
        # Artifact is inserted later so this temporary reference is never returned.
        placeholder = ArtifactRef(digest="0" * 64, size=0)
        return TaskBinding(
            bundle_id=bundle.bundle_id.value,
            bundle_hash=bundle.handoff_hash().value,
            contract_id=contract.contract_id.value,
            revision=contract.revision,
            contract_hash=contract.semantic_hash().value,
            proof_boundary_hash=bundle.proof_boundary.boundary_hash.value,
            environment_hash=contract.formal.environment.environment_hash.value,
            lean_version=contract.formal.environment.lean_version,
            mathlib_revision=contract.formal.environment.mathlib_revision,
            lake_manifest_hash=(
                None
                if contract.formal.environment.lake_manifest_hash is None
                else contract.formal.environment.lake_manifest_hash.value
            ),
            worker_image_digest=verifier_policy.worker_image_digest,
            wrapper_protocol=verifier_policy.wrapper_protocol,
            command_policy_hash=verifier_policy.command_policy_hash().value,
            axiom_profile=contract.policy.axiom_profile.value,
            axioms_allowlist=frozenset(contract.formal.axioms_allowlist),
            bundle_artifact=placeholder,
            fidelity_evidence_artifact=(
                None
                if bundle.fidelity_evidence is None
                else ArtifactRef(
                    digest=bundle.fidelity_evidence.digest.value,
                    size=bundle.fidelity_evidence.size,
                )
            ),
            graph_nodes=graph_nodes,
        )

    def _binding_from_event(self, event: StoredEvent) -> TaskBinding:
        payload = event.payload
        artifact_payload = self._required_object(payload, "bundle_artifact")
        fidelity_payload = payload.get("fidelity_evidence_artifact")
        if fidelity_payload is not None and not isinstance(fidelity_payload, dict):
            raise InvalidTransition("corrupt control-plane payload: fidelity_evidence_artifact")
        graph_nodes = self._required_list(payload, "graph_nodes")
        return TaskBinding(
            bundle_id=self._required_text(payload, "bundle_id"),
            bundle_hash=self._required_text(payload, "bundle_hash"),
            contract_id=self._required_text(payload, "contract_id"),
            revision=self._required_int(payload, "revision"),
            contract_hash=self._required_text(payload, "contract_hash"),
            proof_boundary_hash=self._required_text(payload, "proof_boundary_hash"),
            environment_hash=self._required_text(payload, "environment_hash"),
            lean_version=self._required_text(payload, "lean_version"),
            mathlib_revision=self._required_text(payload, "mathlib_revision"),
            lake_manifest_hash=self._optional_text(payload, "lake_manifest_hash"),
            worker_image_digest=self._required_text(payload, "worker_image_digest"),
            wrapper_protocol=self._required_text(payload, "wrapper_protocol"),
            command_policy_hash=self._required_text(payload, "command_policy_hash"),
            axiom_profile=self._required_text(payload, "axiom_profile"),
            axioms_allowlist=frozenset(self._required_texts(payload, "axioms_allowlist")),
            bundle_artifact=ArtifactRef(
                digest=self._required_text(artifact_payload, "digest"),
                size=self._required_int(artifact_payload, "size"),
            ),
            fidelity_evidence_artifact=(
                None
                if fidelity_payload is None
                else ArtifactRef(
                    digest=self._required_text(fidelity_payload, "digest"),
                    size=self._required_int(fidelity_payload, "size"),
                )
            ),
            graph_nodes=tuple(self._json_object(item) for item in graph_nodes),
        )

    def _assert_lease(self, bundle_id: str, lease: Lease) -> None:
        if lease.job_id != bundle_id:
            raise InvalidTransition("lease belongs to a different bundle")
        self.leases.assert_current(lease)

    def _verify_builder_attestation(self, bundle: FormalizationTaskBundleV1) -> AttestationV1:
        attestation = bundle.builder_attestation
        if attestation is None:
            raise InvalidTransition("a trusted Builder attestation is required before registration")
        try:
            self.attestation_verifier.verify(
                attestation,
                expected_purpose=AttestationPurposeV1.BUILDER_FREEZE,
                payload=builder_attestation_payload(bundle),
            )
        except AttestationError as error:
            raise InvalidTransition("Builder attestation was rejected") from error
        return attestation

    def _verify_builder_fidelity_artifact(
        self,
        bundle: FormalizationTaskBundleV1,
    ) -> ArtifactRef | None:
        """Require the signed handoff to root one canonical Builder evidence artifact."""

        fidelity = bundle.contract.fidelity
        reference = bundle.fidelity_evidence
        if fidelity is None or reference is None:
            if self.allow_test_only_unreviewed_bundles:
                return None
            raise InvalidTransition(
                "a canonical Builder fidelity artifact is required before registration"
            )
        artifact = ArtifactRef(digest=reference.digest.value, size=reference.size)
        try:
            self.artifacts.verify(artifact)
        except (ArtifactCorruption, ArtifactNotFound) as error:
            raise InvalidTransition(
                "Builder fidelity artifact is unavailable or corrupt"
            ) from error
        payload = self._read_canonical_json_artifact(
            artifact.digest,
            label="Builder fidelity",
        )
        if payload.get("schema_version") != reference.artifact_schema:
            raise InvalidTransition("Builder fidelity artifact has an unexpected schema")
        task = self._required_object(payload, "task")
        source_hash = self._required_object(task, "source_hash")
        statement_hash = self._required_object(task, "selected_statement_hash")
        checks = (
            (
                self._required_text(task, "contract_id") == bundle.contract.contract_id.value,
                "contract ID",
            ),
            (
                self._required_int(task, "revision") == bundle.contract.revision,
                "contract revision",
            ),
            (
                self._required_text(source_hash, "value")
                == bundle.contract.source.content_hash.value,
                "source hash",
            ),
            (
                self._required_text(statement_hash, "value")
                == bundle.contract.formal.statement_source_hash.value,
                "statement hash",
            ),
            (
                self._required_text(task, "normalized_statement")
                == bundle.contract.mathematics.normalized_statement,
                "normalized statement",
            ),
            (
                self._required_text(task, "selected_lean_statement")
                == bundle.contract.formal.lean_statement_source,
                "Lean statement",
            ),
            (
                fidelity.evidence_hash == reference.digest,
                "fidelity evidence digest",
            ),
        )
        for valid, label in checks:
            if not valid:
                raise InvalidTransition(f"Builder fidelity artifact has a different {label}")
        return artifact

    def _verify_verification_attestation(
        self,
        binding: TaskBinding,
        report: VerificationReportV1,
        proof_event: StoredEvent,
        lease: Lease,
    ) -> AttestationV1:
        attestation = report.verifier_attestation
        evidence = report.evidence
        if attestation is None:
            raise InvalidTransition("an independent verifier attestation is required")
        if evidence is None:
            raise InvalidTransition("verifier-owned environment evidence is required")
        proof_payload = proof_event.payload
        proof_artifact = self._required_object(proof_payload, "proof_artifact")
        proof_artifact_digest = self._required_text(proof_artifact, "digest")
        expected_dependency_hash = self._required_text(
            proof_payload,
            "dependency_manifest_hash",
        )
        self._validate_verification_evidence(
            binding,
            report,
            expected_dependency_hash=expected_dependency_hash,
        )
        if attestation.evidence_identity != evidence.evidence_id.value:
            raise InvalidTransition("verifier attestation does not bind its evidence identity")
        gateway_context = VerificationSigningContextV1(
            bundle_id=self._stable_identifier(binding.bundle_id),
            bundle_hash=DigestV1(kind=HashKindV1.BUNDLE, value=binding.bundle_hash),
            proof_id=report.proof_id,
            proof_submission_artifact_digest=proof_artifact_digest,
            contract_id=self._stable_identifier(binding.contract_id),
            revision=binding.revision,
            contract_hash=report.contract_hash,
            proof_boundary_hash=report.proof_boundary_hash,
            environment_hash=report.environment_hash,
            dependency_manifest_hash=evidence.dependency_manifest_hash,
            report_id=report.report_id,
            verification_report_hash=report.report_hash(),
            verifier_id=report.verifier_id,
            evidence_identity=evidence.evidence_id,
            verification_evidence_hash=evidence.evidence_hash(),
            evidence_artifact_digest=evidence.evidence_artifact_digest,
        )
        gateway_lease = VerificationSigningLeaseBindingV1(
            bundle_id=gateway_context.bundle_id,
            worker_id=lease.holder_id,
            fencing_token=lease.fencing_token,
            expires_at=lease.expires_at,
        )
        try:
            self.attestation_verifier.verify(
                attestation,
                expected_purpose=AttestationPurposeV1.VERIFICATION,
                payload=verification_gateway_attestation_payload(
                    lease=gateway_lease,
                    context=gateway_context,
                ),
            )
        except AttestationError as error:
            if not self.allow_test_only_direct_verifier_attestations:
                raise InvalidTransition(
                    "lease-bound verifier gateway attestation was rejected"
                ) from error
            try:
                self.attestation_verifier.verify(
                    attestation,
                    expected_purpose=AttestationPurposeV1.VERIFICATION,
                    payload=verification_attestation_payload(
                        bundle_id=binding.bundle_id,
                        bundle_hash=binding.bundle_hash,
                        proof_submission_artifact_digest=proof_artifact_digest,
                        contract_id=binding.contract_id,
                        revision=binding.revision,
                        contract_hash=report.contract_hash,
                        proof_boundary_hash=report.proof_boundary_hash,
                        environment_hash=report.environment_hash,
                        report=report,
                    ),
                )
            except AttestationError as legacy_error:
                raise InvalidTransition("verification attestation was rejected") from legacy_error
        else:
            if attestation.expires_at > lease.expires_at:
                raise InvalidTransition("verifier gateway attestation outlives its fenced lease")
        artifact = self._read_verification_evidence_artifact(evidence.evidence_artifact_digest)
        self._validate_verification_evidence_artifact(
            binding,
            report,
            proof_submission_artifact_digest=proof_artifact_digest,
            expected_dependency_hash=expected_dependency_hash,
            artifact=artifact,
        )
        return attestation

    @staticmethod
    def _validate_verification_evidence(
        binding: TaskBinding,
        report: VerificationReportV1,
        *,
        expected_dependency_hash: str,
    ) -> None:
        evidence = report.evidence
        if evidence is None:
            raise InvalidTransition("verifier-owned environment evidence is required")
        if evidence.environment_hash.value != binding.environment_hash:
            raise InvalidTransition("verification evidence has a different environment hash")
        if evidence.environment_hash != report.environment_hash:
            raise InvalidTransition("verification evidence does not bind the reported environment")
        if evidence.lean_version != binding.lean_version:
            raise InvalidTransition("verification evidence has a different Lean version")
        if evidence.mathlib_revision != binding.mathlib_revision:
            raise InvalidTransition("verification evidence has a different mathlib revision")
        lake_manifest_hash = (
            None if evidence.lake_manifest_hash is None else evidence.lake_manifest_hash.value
        )
        if lake_manifest_hash != binding.lake_manifest_hash:
            raise InvalidTransition("verification evidence has a different Lake manifest")
        if evidence.dependency_manifest_hash.value != expected_dependency_hash:
            raise InvalidTransition("verification evidence has a different dependency manifest")
        if evidence.worker_image_digest != binding.worker_image_digest:
            raise InvalidTransition("verification evidence has a different worker image")
        if evidence.wrapper_protocol != binding.wrapper_protocol:
            raise InvalidTransition("verification evidence has a different wrapper protocol")
        if evidence.command_policy_hash.value != binding.command_policy_hash:
            raise InvalidTransition("verification evidence has a different command policy")

    def _read_verification_evidence_artifact(
        self,
        digest: str,
    ) -> VerificationEvidenceArtifactV1:
        """Load one canonical, content-addressed verifier evidence record.

        Artifact existence alone is insufficient: a signer must not be able to point at arbitrary
        JSON and have it treated as OCI evidence.  The strict decode rejects duplicate fields,
        non-standard JSON constants, non-canonical serialization, schema drift, and values that
        Pydantic would silently normalize.
        """

        raw = self._read_canonical_json_artifact(digest, label="verifier evidence")
        try:
            artifact = VerificationEvidenceArtifactV1.model_validate(raw)
        except ValueError as error:
            raise InvalidTransition(
                "verifier evidence artifact has an invalid V1 schema"
            ) from error
        serialized = canonical_json(artifact.model_dump(mode="json")).encode("utf-8")
        try:
            original = self.artifacts.get_bytes(digest)
        except (ArtifactCorruption, ArtifactNotFound) as error:
            raise InvalidTransition(
                "verifier evidence artifact is unavailable or corrupt"
            ) from error
        if serialized != original:
            raise InvalidTransition("verifier evidence artifact is not canonical V1 JSON")
        return artifact

    def _read_canonical_json_artifact(self, digest: str, *, label: str) -> JsonObject:
        try:
            raw = self.artifacts.get_bytes(digest)
        except (ArtifactCorruption, ArtifactNotFound) as error:
            raise InvalidTransition(f"{label} artifact is unavailable or corrupt") from error
        try:
            decoded = raw.decode("utf-8")
            parsed = json.loads(
                decoded,
                object_pairs_hook=self._unique_json_object,
                parse_constant=self._reject_nonstandard_json_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise InvalidTransition(f"{label} artifact is not strict JSON") from error
        if not isinstance(parsed, dict):
            raise InvalidTransition(f"{label} artifact must contain a JSON object")
        if canonical_json(parsed).encode("utf-8") != raw:
            raise InvalidTransition(f"{label} artifact is not canonically serialized")
        return self._json_object(parsed)

    @staticmethod
    def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    @staticmethod
    def _reject_nonstandard_json_constant(value: str) -> object:
        raise ValueError(f"non-standard JSON constant: {value}")

    def _validate_verification_evidence_artifact(
        self,
        binding: TaskBinding,
        report: VerificationReportV1,
        *,
        proof_submission_artifact_digest: str,
        expected_dependency_hash: str,
        artifact: VerificationEvidenceArtifactV1,
    ) -> None:
        """Cross-bind the canonical artifact to report, frozen bundle, and submitted proof."""

        evidence = report.evidence
        if evidence is None:
            raise InvalidTransition("verifier-owned environment evidence is required")
        checks = (
            (
                artifact.evidence_id == evidence.evidence_id,
                "verifier evidence artifact has a different evidence identity",
            ),
            (
                artifact.bundle_id.value == binding.bundle_id,
                "verifier evidence artifact has a different bundle ID",
            ),
            (
                artifact.bundle_hash.value == binding.bundle_hash,
                "verifier evidence artifact has a different bundle hash",
            ),
            (
                artifact.contract_id.value == binding.contract_id,
                "verifier evidence artifact has a different contract ID",
            ),
            (
                artifact.revision == binding.revision,
                "verifier evidence artifact has a different contract revision",
            ),
            (
                artifact.contract_hash.value == binding.contract_hash,
                "verifier evidence artifact has a different contract hash",
            ),
            (
                artifact.proof_id == report.proof_id,
                "verifier evidence artifact has a different proof ID",
            ),
            (
                artifact.proof_boundary_hash == report.proof_boundary_hash,
                "verifier evidence artifact has a different proof boundary",
            ),
            (
                artifact.proof_submission_artifact_digest == proof_submission_artifact_digest,
                "verifier evidence artifact has a different submitted proof artifact",
            ),
            (
                artifact.dependency_manifest_hash.value == expected_dependency_hash,
                "verifier evidence artifact has a different dependency manifest",
            ),
            (
                artifact.verification_report_id == report.report_id,
                "verifier evidence artifact has a different verification report",
            ),
            (
                artifact.environment.environment_hash == evidence.environment_hash,
                "verifier evidence artifact has a different environment hash",
            ),
            (
                artifact.environment.lean_version == evidence.lean_version,
                "verifier evidence artifact has a different Lean version",
            ),
            (
                artifact.environment.mathlib_revision == evidence.mathlib_revision,
                "verifier evidence artifact has a different mathlib revision",
            ),
            (
                artifact.environment.lake_manifest_hash == evidence.lake_manifest_hash,
                "verifier evidence artifact has a different Lake manifest",
            ),
            (
                artifact.oci.worker_image_digest == evidence.worker_image_digest,
                "verifier evidence artifact has a different worker image",
            ),
            (
                artifact.oci.wrapper_protocol == evidence.wrapper_protocol,
                "verifier evidence artifact has a different wrapper protocol",
            ),
            (
                artifact.oci.command_policy_hash == evidence.command_policy_hash,
                "verifier evidence artifact has a different command policy",
            ),
            (
                artifact.oci.command_hash == evidence.command_hash,
                "verifier evidence artifact has a different invocation command hash",
            ),
        )
        for passed, message in checks:
            if not passed:
                raise InvalidTransition(message)
        observation = report.model_copy(
            update={"evidence": None, "verifier_attestation": None}
        ).report_hash()
        if artifact.verification_observation_hash != observation:
            raise InvalidTransition(
                "verifier evidence artifact does not bind the unsigned verification observation"
            )
        if artifact.oci.worker_image_digest != binding.worker_image_digest:
            raise InvalidTransition("verifier evidence artifact has an unapproved worker image")
        if artifact.oci.wrapper_protocol != binding.wrapper_protocol:
            raise InvalidTransition("verifier evidence artifact has an unapproved wrapper protocol")
        if artifact.oci.command_policy_hash.value != binding.command_policy_hash:
            raise InvalidTransition("verifier evidence artifact has an unapproved command policy")

        bundle_payload = self._read_canonical_json_artifact(
            binding.bundle_artifact.digest,
            label="frozen bundle",
        )
        proof_payload = self._read_canonical_json_artifact(
            proof_submission_artifact_digest,
            label="submitted proof",
        )
        try:
            bundle = FormalizationTaskBundleV1.model_validate(bundle_payload)
            submission = ProofSubmissionV1.model_validate(proof_payload)
        except ValueError as error:
            raise InvalidTransition(
                "stored frozen bundle or submitted proof is malformed"
            ) from error
        if (
            bundle.bundle_id.value != binding.bundle_id
            or bundle.handoff_hash().value != binding.bundle_hash
            or bundle.contract.semantic_hash().value != binding.contract_hash
            or bundle.proof_boundary.boundary_hash.value != binding.proof_boundary_hash
        ):
            raise InvalidTransition("stored frozen bundle does not match its registered binding")
        if (
            submission.proof_id != report.proof_id
            or submission.contract_id.value != binding.contract_id
            or submission.revision != binding.revision
            or submission.contract_hash.value != binding.contract_hash
            or submission.proof_boundary_hash.value != binding.proof_boundary_hash
            or submission.environment_hash.value != binding.environment_hash
        ):
            raise InvalidTransition("stored submitted proof does not match its registered binding")
        boundary = bundle.proof_boundary
        candidate = (
            f"{boundary.trusted_statement_source} := {submission.proof_source.rstrip()}\n"
            f"\n#print axioms {boundary.expected_declaration}\n"
        )
        if artifact.oci.candidate_sha256 != hashlib.sha256(candidate.encode("utf-8")).hexdigest():
            raise InvalidTransition(
                "verifier evidence artifact does not bind the submitted proof bytes"
            )
        if artifact.oci.trusted_statement_sha256 != boundary.trusted_statement_hash.value:
            raise InvalidTransition(
                "verifier evidence artifact does not bind frozen statement bytes"
            )
        if artifact.oci.bundle_manifest_sha256 != boundary.solver_manifest_hash.value:
            raise InvalidTransition(
                "verifier evidence artifact does not bind frozen workspace manifest"
            )

    @staticmethod
    def _attestation_summary(attestation: AttestationV1) -> dict[str, object]:
        """Keep public audit metadata without serializing a signature or any key material."""

        return {
            "purpose": attestation.purpose.value,
            "key_id": attestation.key_id,
            "payload_hash": attestation.payload_hash.value,
            "evidence_identity": attestation.evidence_identity,
            "expires_at": attestation.expires_at.isoformat(),
        }

    @staticmethod
    def _attestation_nonce(attestation: AttestationV1) -> AttestationNonce:
        return AttestationNonce(
            purpose=attestation.purpose.value,
            key_id=attestation.key_id,
            nonce=attestation.nonce,
            payload_hash=attestation.payload_hash.value,
        )

    @staticmethod
    def _validate_proof_binding(binding: TaskBinding, submission: ProofSubmissionV1) -> None:
        ControlPlane._validate_report_binding(
            binding.contract_id,
            binding.revision,
            binding.contract_hash,
            submission.contract_id.value,
            submission.revision,
            submission.contract_hash.value,
        )
        if submission.environment_hash.value != binding.environment_hash:
            raise InvalidTransition("proof submission environment does not match the frozen bundle")
        if submission.proof_boundary_hash.value != binding.proof_boundary_hash:
            raise InvalidTransition("proof submission does not bind the frozen proof boundary")

    @staticmethod
    def _validate_report_binding(
        contract_id: str,
        revision: int,
        contract_hash: str,
        reported_contract_id: str,
        reported_revision: int,
        reported_contract_hash: str,
    ) -> None:
        if reported_contract_id != contract_id:
            raise InvalidTransition("report binds a different stable contract ID")
        if reported_revision != revision:
            raise InvalidTransition("report binds a different contract revision")
        if reported_contract_hash != contract_hash:
            raise InvalidTransition("report binds a different frozen contract hash")

    def _validate_verification_binding(
        self,
        binding: TaskBinding,
        report: VerificationReportV1,
        proof_event: StoredEvent,
    ) -> None:
        proof_payload = proof_event.payload
        if self._required_text(proof_payload, "contract_hash") != report.contract_hash.value:
            raise InvalidTransition(
                "verification report does not bind the submitted proof contract"
            )
        if (
            self._required_text(proof_payload, "proof_boundary_hash")
            != report.proof_boundary_hash.value
        ):
            raise InvalidTransition(
                "verification report does not bind the submitted proof boundary"
            )
        if report.contract_hash.value != binding.contract_hash:
            raise InvalidTransition("verification report does not bind the frozen bundle")
        if report.proof_boundary_hash.value != binding.proof_boundary_hash:
            raise InvalidTransition("verification report does not bind the frozen proof boundary")
        if report.environment_hash.value != binding.environment_hash:
            raise InvalidTransition("verification ran in a different environment")
        if report.axiom_profile.value != binding.axiom_profile:
            raise InvalidTransition("verification used a different axiom profile")

    def _verification_failures(
        self, binding: TaskBinding, report: VerificationReportV1
    ) -> list[str]:
        failures: list[str] = []
        if not report.independent:
            failures.append("verification report is not independent")
        if not report.kernel_passed:
            failures.append("Lean kernel verification failed")
        if not report.build_passed:
            failures.append("clean build failed")
        if not report.dependency_check_passed:
            failures.append("dependency boundary check failed")
        if not report.clean_environment:
            failures.append("verification did not use a clean environment")
        observed = set(report.observed_axioms)
        if "sorryAx" in observed:
            failures.append("sorryAx is prohibited")
        unapproved = observed - binding.axioms_allowlist
        if unapproved:
            failures.append("unapproved axioms: " + ", ".join(sorted(unapproved)))
        if binding.axiom_profile == AxiomProfileV1.STRICT.value and observed:
            failures.append("strict axiom profile permits no observed axioms")
        return failures

    def _proof_event(self, proof_id: str) -> StoredEvent:
        events = self.events.read_stream("proof", proof_id)
        event = next((item for item in events if item.event_type == "proof.submitted"), None)
        if event is None:
            raise TaskNotFound(f"proof {proof_id!r} has not been submitted")
        return event

    def _put_model(self, model: object) -> ArtifactRef:
        if not hasattr(model, "model_dump"):
            raise TypeError("control-plane artifacts must be typed contract models")
        dump = model.model_dump(mode="json")
        return self.artifacts.put_json(dump)

    @staticmethod
    def _model_attribution(submission: ProofSubmissionV1) -> tuple[str, str]:
        traces = tuple(
            item
            for item in submission.provenance
            if item.actor_kind.value == "model" and item.provider and item.model_name
        )
        if not traces:
            return "unattributed", "unattributed"
        selected = traces[-1]
        provider = selected.provider
        model_name = selected.model_name
        if provider is None or model_name is None:
            raise InvalidTransition("model provenance attribution is malformed")
        return provider, model_name

    @staticmethod
    def _artifact_payload(reference: ArtifactRef, *, kind: str) -> dict[str, object]:
        return {
            "digest": reference.digest,
            "size": reference.size,
            "uri": reference.uri,
            "kind": kind,
            "media_type": "application/json",
        }

    @staticmethod
    def _graph_nodes(bundle: FormalizationTaskBundleV1) -> tuple[JsonObject, ...]:
        result: list[JsonObject] = []
        for graph_name, graph, label_field in (
            ("mathematical", bundle.graphs.mathematical, "label"),
            ("formal", bundle.graphs.formal, "declaration_name"),
            ("execution", bundle.graphs.execution, "label"),
        ):
            dependencies: dict[str, list[str]] = {node.node_id.value: [] for node in graph.nodes}
            for edge in graph.edges:
                dependencies[edge.target.value].append(edge.source.value)
            for node in graph.nodes:
                label = getattr(node, label_field)
                result.append(
                    ControlPlane._json_object(
                        {
                            "id": node.node_id.value,
                            "bundle_id": bundle.bundle_id.value,
                            "label": label,
                            "graph": graph_name,
                            "status": "frozen",
                            "revision": bundle.contract.revision,
                            "kind": node.kind.value,
                            "dependencies": sorted(dependencies[node.node_id.value]),
                        }
                    )
                )
        return tuple(result)

    @staticmethod
    def _same_logical_binding(left: TaskBinding, right: TaskBinding) -> bool:
        return (
            left.bundle_id,
            left.bundle_hash,
            left.contract_id,
            left.revision,
            left.contract_hash,
            left.proof_boundary_hash,
            left.environment_hash,
            left.lean_version,
            left.mathlib_revision,
            left.lake_manifest_hash,
            left.worker_image_digest,
            left.wrapper_protocol,
            left.command_policy_hash,
            left.axiom_profile,
            left.axioms_allowlist,
            left.fidelity_evidence_artifact,
            left.graph_nodes,
        ) == (
            right.bundle_id,
            right.bundle_hash,
            right.contract_id,
            right.revision,
            right.contract_hash,
            right.proof_boundary_hash,
            right.environment_hash,
            right.lean_version,
            right.mathlib_revision,
            right.lake_manifest_hash,
            right.worker_image_digest,
            right.wrapper_protocol,
            right.command_policy_hash,
            right.axiom_profile,
            right.axioms_allowlist,
            right.fidelity_evidence_artifact,
            right.graph_nodes,
        )

    @staticmethod
    def _json_object(value: object) -> JsonObject:
        # Round-trip through the event encoder to reject non-JSON values before SQLite sees them.
        import json

        loaded = json.loads(canonical_json(value))
        if not isinstance(loaded, dict):
            raise TypeError("event payload must be a JSON object")
        return cast(JsonObject, loaded)

    @staticmethod
    def _required_text(payload: JsonObject, key: str) -> str:
        value = payload.get(key)
        if not isinstance(value, str) or not value:
            raise InvalidTransition(f"corrupt control-plane payload: {key}")
        return value

    @staticmethod
    def _optional_text(payload: JsonObject, key: str) -> str | None:
        value = payload.get(key)
        if value is None:
            return None
        if not isinstance(value, str) or not value:
            raise InvalidTransition(f"corrupt control-plane payload: {key}")
        return value

    @staticmethod
    def _required_int(payload: JsonObject, key: str) -> int:
        value = payload.get(key)
        if isinstance(value, bool) or not isinstance(value, int):
            raise InvalidTransition(f"corrupt control-plane payload: {key}")
        return value

    @staticmethod
    def _required_object(payload: JsonObject, key: str) -> JsonObject:
        value = payload.get(key)
        if not isinstance(value, dict):
            raise InvalidTransition(f"corrupt control-plane payload: {key}")
        return value

    @staticmethod
    def _required_list(payload: JsonObject, key: str) -> list[object]:
        value = payload.get(key)
        if not isinstance(value, list):
            raise InvalidTransition(f"corrupt control-plane payload: {key}")
        items: list[object] = []
        items.extend(value)
        return items

    @staticmethod
    def _required_texts(payload: JsonObject, key: str) -> tuple[str, ...]:
        values = ControlPlane._required_list(payload, key)
        if not all(isinstance(item, str) and item for item in values):
            raise InvalidTransition(f"corrupt control-plane payload: {key}")
        return tuple(cast(str, item) for item in values)

    @staticmethod
    def _stable_identifier(value: str) -> StableIdentifierV1:
        prefix = "urn:autolean:v1:"
        namespace, separator, _identifier = value.removeprefix(prefix).rpartition(":")
        if not separator or not namespace:
            raise InvalidTransition("stored task binding has an invalid stable identifier")
        try:
            return StableIdentifierV1(namespace=namespace, value=value)
        except ValueError as error:
            raise InvalidTransition(
                "stored task binding has an invalid stable identifier"
            ) from error
