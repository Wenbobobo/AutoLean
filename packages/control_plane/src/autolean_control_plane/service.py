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
    DependencyKindV1,
    DigestV1,
    FormalDependencySupplyV2,
    FormalizationTaskBundleV1,
    FormalizationTaskBundleV2,
    GapReportV1,
    HashKindV1,
    ProofStatusV1,
    ProofSubmissionV1,
    StableIdentifierV1,
    VerificationEvidenceArtifactV1,
    VerificationEvidenceArtifactV2,
    VerificationReportV1,
    VerificationSigningContextV1,
    VerificationSigningLeaseBindingV1,
    builder_attestation_payload,
    canonical_json_bytes,
    digest_bytes,
    digest_text,
    proof_dependency_manifest_hash,
    validate_axiom_policy_v1,
    validate_dependency_closure_ref,
    verification_attestation_payload,
    verification_gateway_attestation_payload,
)
from autolean_contracts.research_advisory import ResearchAdvisoryEventV1

from .artifacts import ArtifactRef, ArtifactStore
from .builder_fidelity import validate_canonical_type_check
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
from .research_advisory import (
    RESEARCH_ADVISORY_ENTITY_TYPE,
    validate_research_advisory_event,
)

_PLACEHOLDER_RE = re.compile(r"\b(?:sorry|admit)\b|sorryAx")

_FIDELITY_ARTIFACT_V1_FIELDS = frozenset(
    {
        "schema_version",
        "task",
        "generation_task",
        "generation_task_hash",
        "candidates",
        "mutation_agent_id",
        "mutation_probes",
        "review",
        "automatic_checks",
        "additional_signoffs",
    }
)
_DIGEST_V1_FIELDS = frozenset({"schema_version", "kind", "algorithm", "value"})
_SOURCE_CLAIM_SPAN_FIELDS = frozenset({"span_id", "locator", "content_hash", "permitted_excerpt"})
_SEMANTIC_OBLIGATION_FIELDS = frozenset(
    {
        "obligation_id",
        "kind",
        "description",
        "source_span_ids",
        "normalized_fragment",
        "lean_fragment",
        "authority",
    }
)
_SEMANTIC_OBLIGATION_KINDS = frozenset(
    {
        "quantifier_order",
        "assumption",
        "conclusion",
        "side_condition",
        "definition",
        "edge_case",
        "non_vacuity",
    }
)


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
    canonical_type_assurance: str | None
    canonical_type_promotion_authority: bool
    bundle_artifact: ArtifactRef
    fidelity_evidence_artifact: ArtifactRef | None
    graph_nodes: tuple[JsonObject, ...]
    bundle_schema_version: str = "1.0"
    dependency_closure_manifest: ArtifactRef | None = None
    dependency_closure_manifest_hash: str | None = None
    dependency_tree_hash: str | None = None
    dependency_artifacts: tuple[ArtifactRef, ...] = ()


@dataclass(frozen=True, slots=True)
class ClaimReceipt:
    bundle_id: str
    bundle_hash: str
    bundle_artifact: ArtifactRef
    lease: Lease
    event: StoredEvent
    dependency_closure_manifest: ArtifactRef | None = None
    dependency_closure_manifest_hash: str | None = None
    dependency_tree_hash: str | None = None


@dataclass(frozen=True, slots=True)
class VerificationOutcome:
    accepted: bool
    reasons: tuple[str, ...]
    event: StoredEvent
    promotion_state: Literal["not_a_promotion"] = "not_a_promotion"
    execution_authority_class: Literal["test-only-local"] = "test-only-local"


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
        allow_test_only_non_authoritative_canonical_type_evidence: bool = False,
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
        self.allow_test_only_non_authoritative_canonical_type_evidence = (
            allow_test_only_non_authoritative_canonical_type_evidence
        )

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

    def record_research_advisory(
        self,
        advisory: ResearchAdvisoryEventV1,
        *,
        idempotency_key: str,
    ) -> StoredEvent:
        """Append an advisory-only ResearchScout observation with no workflow authority.

        This command does not write an artifact, allocate a lease, register a task, or attach the
        advisory to a bundle/contract.  The stable proposal digest is both its entity identity and
        the only duplicate key.  A matching retry is safe; a different record for that digest is
        rejected rather than overwriting historical research evidence.
        """

        if not isinstance(advisory, ResearchAdvisoryEventV1):
            raise InvalidTransition("research advisory requires the typed V1 public envelope")
        try:
            # Pydantic's ``model_construct`` can manufacture an instance without validators.
            # Re-validate at the durable command boundary before any append so a malformed
            # in-memory object cannot leave a permanently malformed advisory event behind.
            advisory = ResearchAdvisoryEventV1.model_validate(advisory.model_dump(mode="json"))
        except ValueError as error:
            raise InvalidTransition(
                "research advisory violates the typed V1 public envelope"
            ) from error
        idempotency = self._idempotency(
            scope="record_research_advisory",
            key=idempotency_key,
            semantic_request=advisory.model_dump(mode="json"),
        )
        replayed = self._replayed_event(idempotency)
        if replayed is not None:
            self._assert_research_advisory_event(replayed, advisory)
            return replayed

        event = NewEvent(
            advisory.event_kind.value,
            payload=self._json_object(advisory.model_dump(mode="json")),
        )
        try:
            stored = self.events.append(
                RESEARCH_ADVISORY_ENTITY_TYPE,
                advisory.proposal_id,
                expected_sequence=0,
                events=(event,),
                idempotency=idempotency,
            )
        except ConcurrencyError as error:
            existing = self.events.read_stream(RESEARCH_ADVISORY_ENTITY_TYPE, advisory.proposal_id)
            if len(existing) == 1:
                self._assert_research_advisory_event(existing[0], advisory)
                return existing[0]
            raise InvalidTransition(
                "research advisory proposal ID is already bound to different immutable evidence"
            ) from error
        if len(stored) != 1:
            raise ProjectionError("research advisory append returned an unexpected event count")
        self._assert_research_advisory_event(stored[0], advisory)
        return stored[0]

    @staticmethod
    def _assert_research_advisory_event(
        event: StoredEvent,
        advisory: ResearchAdvisoryEventV1,
    ) -> None:
        try:
            stored = validate_research_advisory_event(event)
        except ProjectionError as error:
            raise InvalidTransition("stored research advisory event is malformed") from error
        if stored != advisory:
            raise InvalidTransition(
                "research advisory proposal ID is already bound to different immutable evidence"
            )

    @staticmethod
    def _claim_receipt_from_event(bundle_id: str, event: StoredEvent) -> ClaimReceipt:
        payload = event.payload
        event_bundle_id = ControlPlane._required_text(payload, "bundle_id")
        if (
            event.entity_type != "task"
            or event.entity_id != bundle_id
            or event.event_type != "task.claimed"
            or event_bundle_id != bundle_id
        ):
            raise InvalidTransition("corrupt claimed-task event binding")
        bundle_hash = ControlPlane._required_text(payload, "bundle_hash")
        if re.fullmatch(r"[0-9a-f]{64}", bundle_hash) is None:
            raise InvalidTransition("corrupt claimed-task bundle hash")
        artifact_payload = ControlPlane._required_object(payload, "bundle_artifact")
        try:
            bundle_artifact = ArtifactRef(
                digest=ControlPlane._required_text(artifact_payload, "digest"),
                size=ControlPlane._required_int(artifact_payload, "size"),
            )
        except ValueError as error:
            raise InvalidTransition("corrupt claimed-task bundle artifact") from error
        closure_payload = payload.get("dependency_closure_manifest")
        closure_manifest: ArtifactRef | None = None
        closure_manifest_hash: str | None = None
        dependency_tree_hash: str | None = None
        if closure_payload is not None:
            if not isinstance(closure_payload, dict):
                raise InvalidTransition("corrupt claimed-task dependency closure artifact")
            try:
                closure_manifest = ArtifactRef(
                    digest=ControlPlane._required_text(closure_payload, "digest"),
                    size=ControlPlane._required_int(closure_payload, "size"),
                )
                closure_manifest_hash = ControlPlane._required_text(
                    payload,
                    "dependency_closure_manifest_hash",
                )
                dependency_tree_hash = ControlPlane._required_text(
                    payload,
                    "dependency_tree_hash",
                )
            except (InvalidTransition, ValueError) as error:
                raise InvalidTransition(
                    "corrupt claimed-task dependency closure binding"
                ) from error
        expires_at_text = ControlPlane._required_text(payload, "expires_at")
        try:
            expires_at = datetime.fromisoformat(expires_at_text.replace("Z", "+00:00"))
        except ValueError as error:
            raise InvalidTransition("corrupt claimed-task expiry timestamp") from error
        return ClaimReceipt(
            bundle_id=event_bundle_id,
            bundle_hash=bundle_hash,
            bundle_artifact=bundle_artifact,
            lease=Lease(
                job_id=bundle_id,
                holder_id=ControlPlane._required_text(payload, "worker_id"),
                fencing_token=ControlPlane._required_int(payload, "fencing_token"),
                expires_at=expires_at,
            ),
            event=event,
            dependency_closure_manifest=closure_manifest,
            dependency_closure_manifest_hash=closure_manifest_hash,
            dependency_tree_hash=dependency_tree_hash,
        )

    @staticmethod
    def _verification_outcome_from_event(event: StoredEvent) -> VerificationOutcome:
        accepted = event.payload.get("accepted")
        if not isinstance(accepted, bool):
            raise InvalidTransition("corrupt verification event acceptance flag")
        reasons = ControlPlane._required_texts(event.payload, "reasons")
        promotion_state = event.payload.get("promotion_state", "not_a_promotion")
        if promotion_state != "not_a_promotion":
            raise InvalidTransition("local verification event claims promotion authority")
        authority_class = event.payload.get("execution_authority_class", "test-only-local")
        if authority_class != "test-only-local":
            raise InvalidTransition("local verification event claims a production authority")
        return VerificationOutcome(
            accepted=accepted,
            reasons=reasons,
            event=event,
            promotion_state="not_a_promotion",
            execution_authority_class="test-only-local",
        )

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
        bundle: FormalizationTaskBundleV1 | FormalizationTaskBundleV2,
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
        fidelity_artifact, canonical_type_assurance = self._verify_builder_fidelity_artifact(bundle)
        desired = self._binding_from_bundle(bundle)
        dependency_binding = self._dependency_binding_from_bundle(bundle)
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
            canonical_type_assurance=canonical_type_assurance,
            canonical_type_promotion_authority=False,
            bundle_artifact=artifact,
            fidelity_evidence_artifact=fidelity_artifact,
            graph_nodes=desired.graph_nodes,
            bundle_schema_version=desired.bundle_schema_version,
            dependency_closure_manifest=dependency_binding[0],
            dependency_closure_manifest_hash=dependency_binding[1],
            dependency_tree_hash=dependency_binding[2],
            dependency_artifacts=dependency_binding[3],
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
                "canonical_type_assurance": binding.canonical_type_assurance,
                "canonical_type_promotion_authority": (binding.canonical_type_promotion_authority),
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
                "bundle_schema_version": binding.bundle_schema_version,
                "dependency_closure_manifest": (
                    None
                    if binding.dependency_closure_manifest is None
                    else self._artifact_payload(
                        binding.dependency_closure_manifest,
                        kind="closure_manifest",
                    )
                ),
                "dependency_closure_manifest_hash": binding.dependency_closure_manifest_hash,
                "dependency_tree_hash": binding.dependency_tree_hash,
                "dependency_artifacts": [
                    self._artifact_payload(item, kind="closure_blob")
                    for item in binding.dependency_artifacts
                ],
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
        if not self._same_logical_binding(stored, binding):
            raise ProjectionError(
                "canonical registration event disagrees with the requested immutable bundle"
            )
        return stored

    def _dependency_binding_from_bundle(
        self,
        bundle: FormalizationTaskBundleV1 | FormalizationTaskBundleV2,
    ) -> tuple[ArtifactRef | None, str | None, str | None, tuple[ArtifactRef, ...]]:
        """Validate and index V2 closure blobs before the bundle can be claimed."""

        if not isinstance(bundle, FormalizationTaskBundleV2):
            return None, None, None, ()
        closure = bundle.dependency_closure
        manifest_ref = ArtifactRef(
            digest=closure.closure_manifest_ref.sha256,
            size=closure.closure_manifest_ref.size,
        )
        try:
            raw_manifest = self.artifacts.get_bytes(manifest_ref)
            manifest = validate_dependency_closure_ref(closure, raw_manifest)
        except (ArtifactCorruption, ArtifactNotFound, ValueError) as error:
            raise InvalidTransition(
                "V2 dependency closure manifest is unavailable, corrupt, or mismatched"
            ) from error
        expected_target = bundle.contract
        if (
            manifest.target_contract_id != expected_target.contract_id
            or manifest.target_revision != expected_target.revision
            or manifest.target_contract_hash != expected_target.semantic_hash()
            or manifest.target_declaration
            != f"{expected_target.formal.namespace}.{expected_target.formal.declaration_name}"
            or manifest.target_canonical_type_hash != expected_target.formal.elaborated_type_hash
        ):
            raise InvalidTransition("V2 dependency closure targets a different contract revision")

        # A closure reference binds only the accepted dependency IDs.  At admission, bind every
        # such ID back to the frozen graph node and declaration name as well.  Otherwise an
        # attacker can preserve an ID while substituting a different accepted declaration in the
        # manifest, leaving the contract's formal graph with a false provenance edge.
        closure_bindings = {
            item.dependency_id.value: item
            for item in expected_target.formal_dependency_bindings
            if item.supply is FormalDependencySupplyV2.CLOSURE
        }
        formal_body_dependencies = {
            item.dependency_id.value: item
            for item in expected_target.dependencies
            if item.kind is DependencyKindV1.FORMAL_BODY
        }
        manifest_dependency_ids = {
            item.dependency_id.value for item in manifest.accepted_dependencies
        }
        if manifest_dependency_ids != set(closure_bindings):
            raise InvalidTransition(
                "V2 dependency closure accepted dependencies differ from frozen closure bindings"
            )
        for accepted in manifest.accepted_dependencies:
            binding = closure_bindings[accepted.dependency_id.value]
            contract_dependency = formal_body_dependencies.get(accepted.dependency_id.value)
            if contract_dependency is None:
                raise InvalidTransition(
                    "V2 dependency closure accepted dependency is absent from the frozen contract"
                )
            if accepted.formal_node_id != binding.formal_node_id:
                raise InvalidTransition(
                    "V2 dependency closure accepted formal node differs from frozen binding"
                )
            if accepted.declaration_name != contract_dependency.target:
                raise InvalidTransition(
                    "V2 dependency closure accepted declaration differs from frozen dependency"
                )

        # ``verification.accepted`` currently proves an exact frozen theorem in an isolated
        # solver workspace.  It does not identify the exported Lean module containing that
        # theorem, nor bind the exported OLean blob later placed in this closure.  Consequently
        # the manifest's module/evidence fields are still Builder assertions even when they point
        # at an existing verification artifact.  Do not turn those assertions into dependency
        # admission authority.  A future verifier-gateway event must bind the verified contract,
        # declaration/type/axioms, exported module and closure blob before this gate can open.
        if manifest.accepted_dependencies:
            raise InvalidTransition(
                "V2 accepted dependencies require a durable module-bound dependency admission; "
                "verification.accepted does not bind an exported module or closure blob"
            )
        runtime_artifacts: list[ArtifactRef] = []
        try:
            for file_item in manifest.files:
                artifact = ArtifactRef(
                    digest=file_item.artifact.sha256,
                    size=file_item.artifact.size,
                )
                self.artifacts.verify(artifact)
                runtime_artifacts.append(artifact)
            for dependency in manifest.accepted_dependencies:
                evidence = ArtifactRef(
                    digest=dependency.verification_evidence.sha256,
                    size=dependency.verification_evidence.size,
                )
                self.artifacts.verify(evidence)
        except (ArtifactCorruption, ArtifactNotFound) as error:
            raise InvalidTransition(
                "V2 dependency closure references an unavailable CAS blob"
            ) from error
        return (
            manifest_ref,
            closure.closure_manifest_hash.value,
            closure.tree_hash.value,
            tuple(runtime_artifacts),
        )

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
        binding = self.get_binding(bundle_id)
        lease = self.leases.claim(bundle_id, worker_id, ttl_seconds=ttl_seconds)
        payload = self._json_object(
            {
                "bundle_id": binding.bundle_id,
                "bundle_hash": binding.bundle_hash,
                "bundle_artifact": self._artifact_payload(
                    binding.bundle_artifact,
                    kind="bundle",
                ),
                "worker_id": worker_id,
                "fencing_token": lease.fencing_token,
                "expires_at": lease.expires_at.isoformat(),
                "dependency_closure_manifest": (
                    None
                    if binding.dependency_closure_manifest is None
                    else self._artifact_payload(
                        binding.dependency_closure_manifest,
                        kind="closure_manifest",
                    )
                ),
                "dependency_closure_manifest_hash": binding.dependency_closure_manifest_hash,
                "dependency_tree_hash": binding.dependency_tree_hash,
            }
        )
        events = self.events.append(
            "task",
            bundle_id,
            expected_sequence=self.events.current_sequence("task", bundle_id),
            events=(NewEvent("task.claimed", payload=payload),),
            idempotency=idempotency,
        )
        return self._claim_receipt_from_event(bundle_id, events[0])

    def fetch_claimed_bundle(
        self,
        receipt: ClaimReceipt,
    ) -> FormalizationTaskBundleV1 | FormalizationTaskBundleV2:
        """Load the exact registered bundle for a still-current claimed-task receipt."""

        if receipt.bundle_id != receipt.lease.job_id:
            raise InvalidTransition("claim receipt lease belongs to a different bundle")
        self._assert_lease(receipt.bundle_id, receipt.lease)
        stored_event = next(
            (
                event
                for event in self.events.read_stream("task", receipt.bundle_id)
                if event.event_id == receipt.event.event_id
            ),
            None,
        )
        if stored_event is None or stored_event != receipt.event:
            raise InvalidTransition("claim receipt does not bind a persisted task claim")
        canonical_receipt = self._claim_receipt_from_event(receipt.bundle_id, stored_event)
        if canonical_receipt != receipt:
            raise InvalidTransition("claim receipt differs from its persisted task claim")

        binding = self.get_binding(receipt.bundle_id)
        if (
            receipt.bundle_hash != binding.bundle_hash
            or receipt.bundle_artifact != binding.bundle_artifact
        ):
            raise InvalidTransition("claim receipt does not match the registered bundle")
        try:
            raw = self.artifacts.get_bytes(receipt.bundle_artifact)
        except (ArtifactCorruption, ArtifactNotFound) as error:
            raise InvalidTransition("claimed bundle artifact is unavailable or corrupt") from error
        payload = self._decode_canonical_json_object(raw, label="claimed bundle")
        try:
            schema_version = payload.get("schema_version")
            if schema_version == "2.0":
                bundle: FormalizationTaskBundleV1 | FormalizationTaskBundleV2 = (
                    FormalizationTaskBundleV2.model_validate(payload)
                )
            elif schema_version == "1.0":
                bundle = FormalizationTaskBundleV1.model_validate(payload)
            else:
                raise ValueError("unsupported bundle schema")
        except ValueError as error:
            raise InvalidTransition("claimed bundle artifact is malformed") from error
        if canonical_json(bundle.model_dump(mode="json")).encode("utf-8") != raw:
            raise InvalidTransition("claimed bundle artifact is not canonical V1 JSON")
        if (
            bundle.bundle_id.value != receipt.bundle_id
            or bundle.handoff_hash().value != receipt.bundle_hash
            or bundle.contract.contract_id.value != binding.contract_id
            or bundle.contract.revision != binding.revision
            or bundle.contract.semantic_hash().value != binding.contract_hash
            or bundle.proof_boundary.boundary_hash.value != binding.proof_boundary_hash
        ):
            raise InvalidTransition("claimed bundle does not match its registered binding")
        if isinstance(bundle, FormalizationTaskBundleV2):
            if (
                binding.bundle_schema_version != "2.0"
                or binding.dependency_closure_manifest_hash
                != bundle.dependency_closure.closure_manifest_hash.value
                or binding.dependency_tree_hash != bundle.dependency_closure.tree_hash.value
            ):
                raise InvalidTransition("claimed V2 bundle does not match its closure binding")
        elif binding.bundle_schema_version != "1.0":
            raise InvalidTransition("claimed V1 bundle does not match its registered schema")
        self._assert_lease(receipt.bundle_id, receipt.lease)
        return bundle

    def read_claimed_dependency_artifact(
        self,
        receipt: ClaimReceipt,
        artifact: ArtifactRef,
    ) -> bytes:
        """Read one CAS blob reachable from a current V2 claim, and nothing else."""

        bundle = self.fetch_claimed_bundle(receipt)
        if not isinstance(bundle, FormalizationTaskBundleV2):
            raise InvalidTransition("claim-scoped dependency retrieval requires a V2 bundle")
        binding = self.get_binding(receipt.bundle_id)
        if (
            receipt.dependency_closure_manifest != binding.dependency_closure_manifest
            or receipt.dependency_closure_manifest_hash != binding.dependency_closure_manifest_hash
            or receipt.dependency_tree_hash != binding.dependency_tree_hash
        ):
            raise InvalidTransition("claim receipt does not bind the registered dependency closure")
        allowed = {
            *(
                ()
                if binding.dependency_closure_manifest is None
                else (binding.dependency_closure_manifest,)
            ),
            *binding.dependency_artifacts,
        }
        if artifact not in allowed:
            raise InvalidTransition("artifact is not reachable from the claimed dependency closure")
        try:
            return self.artifacts.get_bytes(artifact)
        except (ArtifactCorruption, ArtifactNotFound) as error:
            raise InvalidTransition(
                "claimed dependency artifact is unavailable or corrupt"
            ) from error

    def submit_proof(
        self,
        bundle_id: str,
        *,
        lease: Lease,
        submission: ProofSubmissionV1,
        idempotency_key: str,
    ) -> StoredEvent:
        """Record a Prover candidate without granting it any verification status."""

        if submission.status is not ProofStatusV1.CANDIDATE:
            raise InvalidTransition("submit_proof accepts candidate proof status only")
        if not submission.provenance:
            raise InvalidTransition("proof submissions require explicit provenance")
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
                "promotion_state": "not_a_promotion",
                "execution_authority_class": "test-only-local",
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
        return VerificationOutcome(
            accepted=not reasons,
            reasons=tuple(reasons),
            event=events[0],
            promotion_state="not_a_promotion",
            execution_authority_class="test-only-local",
        )

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

    def _binding_from_bundle(
        self,
        bundle: FormalizationTaskBundleV1 | FormalizationTaskBundleV2,
    ) -> TaskBinding:
        contract = bundle.contract
        verifier_policy = contract.formal.environment.verifier_execution_policy
        axiom_profile, axioms_allowlist = self._validated_axiom_policy(
            contract.policy.axiom_profile.value,
            contract.formal.axioms_allowlist,
            label="frozen bundle",
        )
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
            axiom_profile=axiom_profile,
            axioms_allowlist=axioms_allowlist,
            canonical_type_assurance=None,
            canonical_type_promotion_authority=False,
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
            bundle_schema_version=bundle.schema_version,
        )

    def _binding_from_event(self, event: StoredEvent) -> TaskBinding:
        payload = event.payload
        artifact_payload = self._required_object(payload, "bundle_artifact")
        fidelity_payload = payload.get("fidelity_evidence_artifact")
        if fidelity_payload is not None and not isinstance(fidelity_payload, dict):
            raise InvalidTransition("corrupt control-plane payload: fidelity_evidence_artifact")
        canonical_type_assurance = payload.get("canonical_type_assurance")
        if canonical_type_assurance is not None and (
            not isinstance(canonical_type_assurance, str)
            or canonical_type_assurance not in {"scripted_fake", "local_oci_prefreeze"}
        ):
            raise InvalidTransition("corrupt control-plane payload: canonical_type_assurance")
        canonical_type_promotion_authority = payload.get(
            "canonical_type_promotion_authority",
            False,
        )
        if canonical_type_promotion_authority is not False:
            raise InvalidTransition("canonical type registration event claims promotion authority")
        axiom_profile, axioms_allowlist = self._validated_axiom_policy(
            self._required_text(payload, "axiom_profile"),
            self._required_texts(payload, "axioms_allowlist"),
            label="task registration event",
        )
        graph_nodes = self._required_list(payload, "graph_nodes")
        closure_payload = payload.get("dependency_closure_manifest")
        if closure_payload is not None and not isinstance(closure_payload, dict):
            raise InvalidTransition("corrupt control-plane payload: dependency closure artifact")
        dependency_artifacts_payload = payload.get("dependency_artifacts", [])
        if not isinstance(dependency_artifacts_payload, list):
            raise InvalidTransition("corrupt control-plane payload: dependency artifacts")
        dependency_artifacts: list[ArtifactRef] = []
        for item in dependency_artifacts_payload:
            if not isinstance(item, dict):
                raise InvalidTransition("corrupt control-plane payload: dependency artifact")
            dependency_artifacts.append(
                ArtifactRef(
                    digest=self._required_text(item, "digest"),
                    size=self._required_int(item, "size"),
                )
            )
        bundle_schema_version = (
            self._required_text(payload, "bundle_schema_version")
            if "bundle_schema_version" in payload
            else "1.0"
        )
        if bundle_schema_version == "1.0" and (
            closure_payload is not None
            or payload.get("dependency_closure_manifest_hash") is not None
            or payload.get("dependency_tree_hash") is not None
            or dependency_artifacts
        ):
            raise InvalidTransition("V1 registration cannot claim dependency closure fields")
        if bundle_schema_version == "2.0" and (
            closure_payload is None
            or payload.get("dependency_closure_manifest_hash") is None
            or payload.get("dependency_tree_hash") is None
        ):
            raise InvalidTransition("V2 registration is missing its dependency closure binding")
        if bundle_schema_version not in {"1.0", "2.0"}:
            raise InvalidTransition("unsupported registered bundle schema version")
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
            axiom_profile=axiom_profile,
            axioms_allowlist=axioms_allowlist,
            canonical_type_assurance=canonical_type_assurance,
            canonical_type_promotion_authority=False,
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
            bundle_schema_version=bundle_schema_version,
            dependency_closure_manifest=(
                None
                if closure_payload is None
                else ArtifactRef(
                    digest=self._required_text(closure_payload, "digest"),
                    size=self._required_int(closure_payload, "size"),
                )
            ),
            dependency_closure_manifest_hash=(
                None
                if payload.get("dependency_closure_manifest_hash") is None
                else self._required_text(payload, "dependency_closure_manifest_hash")
            ),
            dependency_tree_hash=(
                None
                if payload.get("dependency_tree_hash") is None
                else self._required_text(payload, "dependency_tree_hash")
            ),
            dependency_artifacts=tuple(dependency_artifacts),
        )

    def _assert_lease(self, bundle_id: str, lease: Lease) -> None:
        if lease.job_id != bundle_id:
            raise InvalidTransition("lease belongs to a different bundle")
        self.leases.assert_current(lease)

    @staticmethod
    def _validated_axiom_policy(
        profile_text: str,
        axioms_allowlist: tuple[str, ...],
        *,
        label: str,
    ) -> tuple[str, frozenset[str]]:
        try:
            profile = AxiomProfileV1(profile_text)
            validate_axiom_policy_v1(profile, axioms_allowlist)
        except ValueError as error:
            raise InvalidTransition(f"{label} has an invalid axiom policy") from error
        return profile.value, frozenset(axioms_allowlist)

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
    ) -> tuple[ArtifactRef | None, str | None]:
        """Require the signed handoff to root one canonical Builder evidence artifact."""

        fidelity = bundle.contract.fidelity
        reference = bundle.fidelity_evidence
        if fidelity is None and reference is None:
            if self.allow_test_only_unreviewed_bundles:
                return None, None
            raise InvalidTransition(
                "a canonical Builder fidelity artifact is required before registration"
            )
        if fidelity is None or reference is None:
            raise InvalidTransition(
                "reviewed Builder handoffs require a canonical fidelity artifact reference"
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
        self._require_exact_object_keys(
            payload,
            _FIDELITY_ARTIFACT_V1_FIELDS,
            label="Builder fidelity artifact",
        )
        task = self._required_object(payload, "task")
        generation_task = self._required_object(payload, "generation_task")
        source_spans = self._source_claim_span_projection(bundle, task)
        expected_generation_task = self._generation_task_projection(bundle, task, source_spans)
        if generation_task != expected_generation_task:
            raise InvalidTransition(
                "Builder fidelity artifact generation task differs from the Builder projection"
            )
        generation_task_hash = digest_bytes(
            HashKindV1.PROMPT,
            canonical_json_bytes(generation_task),
        )
        declared_generation_task_hash = self._required_fidelity_digest(
            payload,
            "generation_task_hash",
            expected_kind=HashKindV1.PROMPT,
        )
        if declared_generation_task_hash != generation_task_hash:
            raise InvalidTransition(
                "Builder fidelity artifact generation task does not match generation_task_hash"
            )
        self._validate_candidate_generation_task_hashes(payload, generation_task_hash)
        canonical_type_admission = validate_canonical_type_check(
            bundle,
            payload,
            task=task,
            generation_task_hash=generation_task_hash,
            allow_test_only_non_authoritative=(
                self.allow_test_only_non_authoritative_canonical_type_evidence
            ),
        )
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
        return artifact, canonical_type_admission.assurance

    def _generation_task_projection(
        self,
        bundle: FormalizationTaskBundleV1,
        task: JsonObject,
        source_spans: list[JsonObject],
    ) -> JsonObject:
        obligations: list[JsonObject] = []
        frozen_span_ids = {span.span_id.value for span in bundle.contract.source.spans}
        obligation_ids: set[str] = set()
        for value in self._required_list(task, "obligations"):
            if not isinstance(value, dict):
                raise InvalidTransition("Builder fidelity artifact task obligations are invalid")
            full_obligation = self._json_object(value)
            self._require_exact_object_keys(
                full_obligation,
                _SEMANTIC_OBLIGATION_FIELDS,
                label="Builder fidelity artifact task obligation",
            )
            obligation_id = self._required_nonblank_fidelity_obligation_text(
                full_obligation,
                "obligation_id",
            )
            if obligation_id in obligation_ids:
                raise InvalidTransition(
                    "Builder fidelity artifact task obligation identifiers must be unique"
                )
            obligation_ids.add(obligation_id)
            kind = self._required_text(full_obligation, "kind")
            if kind not in _SEMANTIC_OBLIGATION_KINDS:
                raise InvalidTransition("Builder fidelity artifact task obligation kind is invalid")
            self._required_nonblank_fidelity_obligation_text(full_obligation, "description")
            source_span_ids = self._required_texts(full_obligation, "source_span_ids")
            if (
                not source_span_ids
                or len(set(source_span_ids)) != len(source_span_ids)
                or not set(source_span_ids) <= frozen_span_ids
            ):
                raise InvalidTransition(
                    "Builder fidelity artifact task obligation source spans are invalid"
                )
            normalized_fragment = self._required_nonblank_fidelity_obligation_text(
                full_obligation,
                "normalized_fragment",
            )
            if normalized_fragment not in bundle.contract.mathematics.normalized_statement:
                raise InvalidTransition(
                    "Builder fidelity artifact task obligation fragment is absent from the "
                    "normalized statement"
                )
            self._required_nonblank_fidelity_obligation_text(full_obligation, "lean_fragment")
            if self._required_text(full_obligation, "authority") != "expert":
                raise InvalidTransition(
                    "Builder fidelity artifact task obligation authority is invalid"
                )
            obligations.append(
                self._json_object(
                    {
                        "obligation_id": obligation_id,
                        "kind": kind,
                        "source_span_ids": list(source_span_ids),
                        "normalized_fragment": normalized_fragment,
                    }
                )
            )
        if not obligations:
            raise InvalidTransition("Builder fidelity artifact task requires semantic obligations")
        return self._json_object(
            {
                "source_spans": source_spans,
                "mathematics": bundle.contract.mathematics.model_dump(mode="json"),
                "formalization": {
                    "task_kind": bundle.contract.task_kind.value,
                    "declaration_name": bundle.contract.formal.declaration_name,
                    "namespace": bundle.contract.formal.namespace,
                    "lean_version": bundle.contract.formal.environment.lean_version,
                    "mathlib_revision": bundle.contract.formal.environment.mathlib_revision,
                    "imports_allowlist": list(bundle.contract.formal.imports_allowlist),
                    "axioms_allowlist": list(bundle.contract.formal.axioms_allowlist),
                    "rendering_profile": ("autolean.full-declaration-canonical-type.v1"),
                },
                "obligations": obligations,
            }
        )

    def _source_claim_span_projection(
        self,
        bundle: FormalizationTaskBundleV1,
        task: JsonObject,
    ) -> list[JsonObject]:
        """Rebuild private claim payloads from frozen public span bindings.

        The retained artifact supplies a private excerpt only.  Its span identifier, locator, and
        typed content hash must exactly reproduce the frozen contract, and the excerpt must hash
        to that contract hash before either task projection can include it.
        """

        claims = self._required_list(task, "source_spans")
        frozen_spans = bundle.contract.source.spans
        frozen_spans_by_id = {span.span_id.value: span for span in frozen_spans}
        claims_by_id: dict[str, JsonObject] = {}
        validated_claims: list[JsonObject] = []
        for value in claims:
            if not isinstance(value, dict):
                raise InvalidTransition("Builder fidelity artifact task source spans are invalid")
            claim = self._json_object(value)
            self._require_exact_object_keys(
                claim,
                _SOURCE_CLAIM_SPAN_FIELDS,
                label="Builder fidelity artifact task source span",
            )
            span_id = self._required_text(claim, "span_id")
            if span_id in claims_by_id:
                raise InvalidTransition(
                    "Builder fidelity artifact task source span identifiers must be unique"
                )
            claims_by_id[span_id] = claim
            validated_claims.append(claim)
        if not claims or set(claims_by_id) != set(frozen_spans_by_id):
            raise InvalidTransition(
                "Builder fidelity artifact task source spans differ from frozen spans"
            )

        projection: list[JsonObject] = []
        for frozen_claim in validated_claims:
            span_id = self._required_text(frozen_claim, "span_id")
            frozen_span = frozen_spans_by_id[span_id]
            if self._required_text(frozen_claim, "locator") != frozen_span.locator:
                raise InvalidTransition(
                    "Builder fidelity artifact task source span locator differs"
                )
            content_hash = self._required_fidelity_digest(
                frozen_claim,
                "content_hash",
                expected_kind=HashKindV1.SOURCE_SPAN,
            )
            if content_hash != frozen_span.content_hash:
                raise InvalidTransition("Builder fidelity artifact task source span hash differs")
            excerpt = self._required_text(frozen_claim, "permitted_excerpt")
            if not excerpt.strip() or digest_text(HashKindV1.SOURCE_SPAN, excerpt) != content_hash:
                raise InvalidTransition(
                    "Builder fidelity artifact task source excerpt differs from hash"
                )
            if (
                frozen_span.permitted_excerpt is not None
                and excerpt != frozen_span.permitted_excerpt
            ):
                raise InvalidTransition(
                    "Builder fidelity artifact task source excerpt differs from frozen span"
                )
            projection.append(
                self._json_object(
                    {
                        "span_id": frozen_span.span_id.value,
                        "locator": frozen_span.locator,
                        "content_hash": frozen_span.content_hash.model_dump(mode="json"),
                        "permitted_excerpt": excerpt,
                    }
                )
            )

        if validated_claims != projection:
            raise InvalidTransition(
                "Builder fidelity artifact task source spans differ from frozen spans"
            )
        return projection

    def _validate_candidate_generation_task_hashes(
        self,
        payload: JsonObject,
        generation_task_hash: DigestV1,
    ) -> None:
        candidates = self._required_list(payload, "candidates")
        if len(candidates) < 2:
            raise InvalidTransition("Builder fidelity artifact requires at least two candidates")
        for index, value in enumerate(candidates):
            if not isinstance(value, dict):
                raise InvalidTransition(
                    f"Builder fidelity artifact candidate {index} must be a JSON object"
                )
            candidate = self._json_object(value)
            if (
                self._required_fidelity_digest(
                    candidate,
                    "generation_task_hash",
                    expected_kind=HashKindV1.PROMPT,
                )
                != generation_task_hash
            ):
                raise InvalidTransition(
                    "Builder fidelity artifact candidate "
                    f"{index} has a different generation task hash"
                )

    @staticmethod
    def _require_exact_object_keys(
        payload: JsonObject,
        expected: frozenset[str],
        *,
        label: str,
    ) -> None:
        if set(payload) != expected:
            raise InvalidTransition(f"{label} has unexpected or missing fields")

    def _required_fidelity_digest(
        self,
        payload: JsonObject,
        key: str,
        *,
        expected_kind: HashKindV1,
    ) -> DigestV1:
        raw = self._required_object(payload, key)
        self._require_exact_object_keys(
            raw,
            _DIGEST_V1_FIELDS,
            label=f"Builder fidelity artifact {key}",
        )
        try:
            digest = DigestV1.model_validate(raw)
        except ValueError as error:
            raise InvalidTransition(
                f"Builder fidelity artifact {key} has an invalid digest"
            ) from error
        if digest.kind is not expected_kind:
            raise InvalidTransition(
                f"Builder fidelity artifact {key} has an unexpected digest kind"
            )
        return digest

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
        gateway_attested = False
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
            gateway_attested = True
            if attestation.expires_at > lease.expires_at:
                raise InvalidTransition("verifier gateway attestation outlives its fenced lease")
        artifact = self._read_verification_evidence_artifact(evidence.evidence_artifact_digest)
        self._validate_verification_evidence_artifact(
            binding,
            report,
            proof_submission_artifact_digest=proof_artifact_digest,
            expected_dependency_hash=expected_dependency_hash,
            lease=lease,
            require_authoritative=gateway_attested,
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
    ) -> VerificationEvidenceArtifactV1 | VerificationEvidenceArtifactV2:
        """Load one canonical, content-addressed verifier evidence record.

        Artifact existence alone is insufficient: a signer must not be able to point at arbitrary
        JSON and have it treated as OCI evidence.  The strict decode rejects duplicate fields,
        non-standard JSON constants, non-canonical serialization, schema drift, and values that
        Pydantic would silently normalize.
        """

        raw = self._read_canonical_json_artifact(digest, label="verifier evidence")
        schema_version = raw.get("schema_version")
        artifact_type = (
            VerificationEvidenceArtifactV1
            if schema_version == "autolean.verification-evidence-artifact.v1"
            else VerificationEvidenceArtifactV2
            if schema_version == "autolean.verification-evidence-artifact.v2"
            else None
        )
        if artifact_type is None:
            raise InvalidTransition("verifier evidence artifact has an unsupported schema")
        try:
            artifact = artifact_type.model_validate(raw)
        except ValueError as error:
            raise InvalidTransition("verifier evidence artifact has an invalid schema") from error
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
        return self._decode_canonical_json_object(raw, label=label)

    def _decode_canonical_json_object(self, raw: bytes, *, label: str) -> JsonObject:
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
        lease: Lease,
        require_authoritative: bool,
        artifact: VerificationEvidenceArtifactV1 | VerificationEvidenceArtifactV2,
    ) -> None:
        """Cross-bind the canonical artifact to report, frozen bundle, and submitted proof."""

        evidence = report.evidence
        if evidence is None:
            raise InvalidTransition("verifier-owned environment evidence is required")
        if require_authoritative and not isinstance(artifact, VerificationEvidenceArtifactV2):
            raise InvalidTransition(
                "gateway-attested verification requires lease-bound V2 execution evidence"
            )
        if isinstance(artifact, VerificationEvidenceArtifactV2):
            authority = artifact.oci.execution_authority
            if (
                authority.worker_id != lease.holder_id
                or authority.fencing_token != lease.fencing_token
                or authority.expires_at != lease.expires_at
            ):
                raise InvalidTransition(
                    "verifier evidence artifact has a different execution lease"
                )
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
            left.canonical_type_assurance,
            left.canonical_type_promotion_authority,
            left.fidelity_evidence_artifact,
            left.graph_nodes,
            left.bundle_schema_version,
            left.dependency_closure_manifest,
            left.dependency_closure_manifest_hash,
            left.dependency_tree_hash,
            left.dependency_artifacts,
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
            right.canonical_type_assurance,
            right.canonical_type_promotion_authority,
            right.fidelity_evidence_artifact,
            right.graph_nodes,
            right.bundle_schema_version,
            right.dependency_closure_manifest,
            right.dependency_closure_manifest_hash,
            right.dependency_tree_hash,
            right.dependency_artifacts,
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

    @classmethod
    def _required_nonblank_fidelity_obligation_text(cls, payload: JsonObject, key: str) -> str:
        value = cls._required_text(payload, key)
        if not value.strip():
            raise InvalidTransition(
                f"Builder fidelity artifact task obligation {key} must not be blank"
            )
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
