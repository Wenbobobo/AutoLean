"""Provenance-safe entry from a verified chapter span to statement-fidelity review."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from autolean_contracts import (
    AlignmentTargetV1,
    AttestationSignerV1,
    DependencyReferenceV1,
    DigestV1,
    EndpointClassV1,
    FidelityEvidenceArtifactRefV1,
    FormalizationTaskBundleV1,
    FormalSpecificationV1,
    GraphBundleV1,
    HashKindV1,
    MathematicalSpecificationV1,
    PermissionDecisionV1,
    ProvenanceTraceV1,
    ReviewerSignoffV1,
    RightsRecordV1,
    SourceRecordV1,
    SourceSpanV1,
    StableIdentifierV1,
    StatementContractV1,
    StatementStatusV1,
    TaskKindV1,
    TaskPolicyV1,
    canonical_json_bytes,
    digest_text,
    stable_identifier,
    utc_now,
)

from .fidelity_harness import (
    FidelityEvaluation,
    MutationSuiteAgent,
    SemanticObligation,
    SemanticReviewAgent,
    SourceClaimSpan,
    StatementFidelityHarness,
    TranslationAgent,
)
from .pilot_harness import (
    PilotAdmissionReceiptV1,
    PilotHarnessError,
    PilotManifestV1,
    load_pilot_manifest,
)
from .reference_cache import (
    ParentLocatorAuthority,
    ReferenceArtifactKind,
    ReferenceCache,
    ReferenceCacheError,
    ReferenceDerivationKind,
    ReferenceDerivationV1,
    ReferenceEgressPolicy,
    ReferenceEntryV1,
    VerifiedReference,
)
from .source_preparation import (
    SourcePreparationError,
    SourcePreparationLedger,
    SourcePreparationRecordV1,
)
from .workflow import FreezeGate, _bridge_frozen_contract, _freeze_reviewed_contract


class SourceHarnessError(ValueError):
    """A source packet cannot safely enter statement-fidelity review."""


@dataclass(frozen=True, slots=True)
class ChapterSourceSpan:
    """An exact UTF-8 byte span plus a human-declared locator in its parent PDF."""

    span_key: str
    human_declared_chapter_locator: str
    human_declared_page_locator: str
    permitted_excerpt: str
    source_analyst_id: str
    verified_artifact_sha256: str
    start_offset: int
    end_offset: int

    def __post_init__(self) -> None:
        for label, value in (
            ("span_key", self.span_key),
            ("human_declared_chapter_locator", self.human_declared_chapter_locator),
            ("human_declared_page_locator", self.human_declared_page_locator),
            ("permitted_excerpt", self.permitted_excerpt),
            ("source_analyst_id", self.source_analyst_id),
            ("verified_artifact_sha256", self.verified_artifact_sha256),
        ):
            if not value.strip() or value != value.strip():
                raise SourceHarnessError(f"{label} must be nonempty, trimmed text")
        if len(self.verified_artifact_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in self.verified_artifact_sha256
        ):
            raise SourceHarnessError("verified artifact SHA-256 must have 64 hexadecimal digits")
        if isinstance(self.start_offset, bool) or isinstance(self.end_offset, bool):
            raise SourceHarnessError("source span byte offsets must be integers")
        if self.start_offset < 0:
            raise SourceHarnessError("source span start offset must be non-negative")
        if self.end_offset <= self.start_offset:
            raise SourceHarnessError("source span byte range must be nonempty")

    @property
    def locator(self) -> str:
        return f"derived-text:bytes:{self.start_offset}-{self.end_offset}"

    @property
    def human_parent_locator(self) -> str:
        return f"{self.human_declared_chapter_locator}#{self.human_declared_page_locator}"


@dataclass(frozen=True, slots=True)
class RightsReview:
    """Explicit operator decision; the manifest never promotes itself to legal review."""

    review_key: str
    source_license: str
    generated_code_license: str | None
    overall_decision: PermissionDecisionV1
    redistribution: PermissionDecisionV1
    model_egress: PermissionDecisionV1
    training: PermissionDecisionV1
    embedding: PermissionDecisionV1
    allowed_endpoint_classes: tuple[EndpointClassV1, ...]
    attribution: str
    restrictions: tuple[str, ...]
    reviewed_by: str
    reviewed_at: datetime


@dataclass(frozen=True, slots=True)
class StatementDraftRequest:
    contract_key: str
    revision: int
    task_kind: TaskKindV1
    spans: tuple[ChapterSourceSpan, ...]
    rights: RightsReview
    mathematics: MathematicalSpecificationV1
    formal: FormalSpecificationV1
    policy: TaskPolicyV1
    alignment_reviewer_id: str
    alignment_relation: str = "formalizes"
    alignment_confidence: float = 1.0
    dependencies: tuple[DependencyReferenceV1, ...] = ()
    provenance: tuple[ProvenanceTraceV1, ...] = ()
    pilot_admission: PilotAdmissionReceiptV1 | None = None

    def __post_init__(self) -> None:
        for label, value in (
            ("contract_key", self.contract_key),
            ("alignment_reviewer_id", self.alignment_reviewer_id),
            ("alignment_relation", self.alignment_relation),
        ):
            if not value.strip() or value != value.strip():
                raise SourceHarnessError(f"{label} must be nonempty, trimmed text")
        if self.revision < 1:
            raise SourceHarnessError("statement contract revision must be positive")
        if not self.spans:
            raise SourceHarnessError("a statement draft requires at least one source span")
        span_keys = [span.span_key for span in self.spans]
        if len(span_keys) != len(set(span_keys)):
            raise SourceHarnessError("source span keys must be unique")
        if not 0.0 <= self.alignment_confidence <= 1.0:
            raise SourceHarnessError("alignment confidence must lie between zero and one")


@dataclass(frozen=True, slots=True)
class StatementDraftPacket:
    """A draft bound to exact derived-text bytes and a verified parent PDF."""

    contract: StatementContractV1
    preparation_id: StableIdentifierV1
    reference_id: str
    manifest_sha256: str
    artifact_sha256: str
    parent_reference_id: str
    parent_artifact_sha256: str
    rights_record: RightsRecordV1
    spans: tuple[ChapterSourceSpan, ...]
    pilot_admission: PilotAdmissionReceiptV1 | None = None

    def preparation_record(self) -> SourcePreparationRecordV1:
        contract_sha256 = _canonical_sha256(self.contract)
        rights_sha256 = _canonical_sha256(self.rights_record)
        spans_payload = tuple(asdict(span) for span in self.spans)
        spans_sha256 = _canonical_sha256(spans_payload)
        packet_sha256 = _canonical_sha256(
            {
                "schema_version": "autolean.statement-draft-packet.v1",
                "preparation_id": self.preparation_id.model_dump(mode="json"),
                "contract": self.contract.model_dump(mode="json", exclude_none=False),
                "reference_id": self.reference_id,
                "manifest_sha256": self.manifest_sha256,
                "artifact_sha256": self.artifact_sha256,
                "parent_reference_id": self.parent_reference_id,
                "parent_artifact_sha256": self.parent_artifact_sha256,
                "rights_record": self.rights_record.model_dump(mode="json", exclude_none=False),
                "spans": spans_payload,
                "pilot_admission": (
                    None
                    if self.pilot_admission is None
                    else self.pilot_admission.model_dump(mode="json")
                ),
            }
        )
        return SourcePreparationRecordV1(
            preparation_id=self.preparation_id,
            contract_id=self.contract.contract_id,
            revision=self.contract.revision,
            packet_sha256=packet_sha256,
            contract_sha256=contract_sha256,
            rights_sha256=rights_sha256,
            spans_sha256=spans_sha256,
            manifest_sha256=self.manifest_sha256,
            artifact_sha256=self.artifact_sha256,
            parent_artifact_sha256=self.parent_artifact_sha256,
        )

    def assert_binds(
        self,
        cache: ReferenceCache,
        preparation_ledger: SourcePreparationLedger,
    ) -> VerifiedReference:
        try:
            preparation_ledger.require(self.preparation_record())
        except SourcePreparationError as error:
            raise SourceHarnessError(str(error)) from error
        return self._assert_source_binds(cache)

    def _assert_source_binds(self, cache: ReferenceCache) -> VerifiedReference:
        try:
            verified = cache.verify(self.reference_id)
            parent = cache.verify(self.parent_reference_id)
        except ReferenceCacheError as error:
            raise SourceHarnessError(str(error)) from error
        if verified.manifest_sha256 != self.manifest_sha256:
            raise SourceHarnessError("reference manifest changed after statement drafting")
        if verified.entry.sha256 != self.artifact_sha256:
            raise SourceHarnessError("reference artifact changed after statement drafting")
        derivation = verified.entry.derivation
        if (
            verified.entry.artifact_kind is not ReferenceArtifactKind.DERIVED_TEXT
            or verified.entry.media_type != "text/plain"
            or derivation is None
        ):
            raise SourceHarnessError("statement packet is not bound to derived UTF-8 text")
        if (
            derivation.parent_reference_id != self.parent_reference_id
            or derivation.parent_sha256 != self.parent_artifact_sha256
            or parent.entry.sha256 != self.parent_artifact_sha256
        ):
            raise SourceHarnessError("statement packet parent reference binding changed")
        expected_source_hash = DigestV1(
            kind=HashKindV1.SOURCE_BYTES,
            value=self.artifact_sha256,
        )
        if self.contract.source.content_hash != expected_source_hash:
            raise SourceHarnessError("draft source hash differs from the verified reference")
        if self.contract.source.snapshot_ref != verified.cache_ref:
            raise SourceHarnessError("draft source snapshot reference is inconsistent")
        if (
            self.contract.source.source_id
            != stable_identifier("builder-source", parent.entry.reference_id)
            or self.contract.source.retrieved_at != verified.entry.retrieved_at
            or self.contract.source.source_id != self.contract.rights.source_id
            or self.contract.source.work_id != parent.entry.reference_id
            or self.contract.source.title != parent.entry.title
            or self.contract.source.version != parent.entry.version
            or self.contract.source.locator != parent.entry.source_record_url
        ):
            raise SourceHarnessError("draft parent source identity changed")
        if self.contract.rights != self.rights_record:
            raise SourceHarnessError("draft rights record changed after source preparation")
        _validate_manifest_rights_ceiling(
            verified.entry,
            parent.entry,
            self.contract.rights,
        )
        if self.contract.status is not StatementStatusV1.DRAFT:
            raise SourceHarnessError("the source harness only admits draft contracts")
        if self.contract.fidelity is not None or self.contract.freeze is not None:
            raise SourceHarnessError("source drafting cannot attach fidelity or freeze evidence")
        expected_spans = {
            stable_identifier(
                "source-span",
                f"{self.reference_id}:{span.span_key}",
            ): span
            for span in self.spans
        }
        contract_spans = {span.span_id: span for span in self.contract.source.spans}
        if set(contract_spans) != set(expected_spans):
            raise SourceHarnessError("draft source spans differ from the packet")
        for span_id, declared in expected_spans.items():
            contract_span = contract_spans[span_id]
            if (
                contract_span.locator != declared.locator
                or contract_span.start_offset != declared.start_offset
                or contract_span.end_offset != declared.end_offset
                or contract_span.permitted_excerpt is not None
                or contract_span.content_hash
                != digest_text(HashKindV1.SOURCE_SPAN, declared.permitted_excerpt)
            ):
                raise SourceHarnessError("draft source span binding changed")
            try:
                cache.verify_utf8_excerpt(
                    self.reference_id,
                    start_offset=declared.start_offset,
                    end_offset=declared.end_offset,
                    permitted_excerpt=declared.permitted_excerpt,
                )
            except ReferenceCacheError as error:
                raise SourceHarnessError(str(error)) from error
        expected_locators = _human_locator_records(self.reference_id, self.spans)
        if self.contract.source.metadata.get("human_parent_locators") != expected_locators:
            raise SourceHarnessError("human-declared parent locators changed")
        expected_derivation = _derivation_metadata(verified.entry)
        if self.contract.source.metadata.get("derivation") != expected_derivation:
            raise SourceHarnessError("source derivation metadata changed")
        expected_parent_metadata = {
            "parent_reference_id": parent.entry.reference_id,
            "parent_artifact_sha256": parent.entry.sha256,
            "parent_snapshot_ref": parent.cache_ref,
        }
        if any(
            self.contract.source.metadata.get(key) != value
            for key, value in expected_parent_metadata.items()
        ):
            raise SourceHarnessError("draft parent source metadata changed")
        expected_metadata = {
            "authors": parent.entry.authors,
            "citation": parent.entry.citation,
            "reference_manifest_sha256": verified.manifest_sha256,
            "derived_reference_id": verified.entry.reference_id,
            "derived_artifact_kind": verified.entry.artifact_kind.value,
            "reference_access_policy": verified.entry.access_policy.value,
            "reference_model_egress_policy": verified.entry.model_egress_policy.value,
            "license_expression": verified.entry.license.expression,
            "license_evidence_url": verified.entry.license.evidence_url,
            "parent_reference_id": parent.entry.reference_id,
            "parent_artifact_sha256": parent.entry.sha256,
            "parent_snapshot_ref": parent.cache_ref,
            "derivation": expected_derivation,
            "human_parent_locators": expected_locators,
            "source_analyst_ids": tuple(sorted({span.source_analyst_id for span in self.spans})),
        }
        if self.pilot_admission is not None:
            expected_metadata["pilot_admission"] = self.pilot_admission.model_dump(mode="json")
        if self.contract.source.metadata != expected_metadata:
            raise SourceHarnessError("draft source metadata changed")
        return verified


class SourceToStatementHarness:
    """Build drafts and route them into the sole statement-fidelity Harness."""

    def __init__(
        self,
        cache: ReferenceCache,
        *,
        preparation_ledger: SourcePreparationLedger,
        fidelity_harness: StatementFidelityHarness | None = None,
        pilot_manifest: PilotManifestV1 | None = None,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self.cache = cache
        self.preparation_ledger = preparation_ledger
        self._clock = clock
        self.fidelity_harness = fidelity_harness or StatementFidelityHarness(clock=clock)
        default_manifest = (
            Path(__file__).resolve().parents[2]
            / "pilots"
            / "self-calibration"
            / "pilot-manifest.v1.json"
        )
        self.pilot_manifest = (
            pilot_manifest
            if pilot_manifest is not None
            else load_pilot_manifest(default_manifest)
            if default_manifest.is_file()
            else None
        )

    def prepare_draft(
        self,
        reference_id: str,
        request: StatementDraftRequest,
    ) -> StatementDraftPacket:
        try:
            verified = self.cache.verify(reference_id)
        except ReferenceCacheError as error:
            raise SourceHarnessError(str(error)) from error
        entry = verified.entry
        derivation = self._require_derived_text(entry)
        try:
            parent = self.cache.verify(derivation.parent_reference_id)
        except ReferenceCacheError as error:
            raise SourceHarnessError(str(error)) from error
        self._validate_spans(entry, request.spans)
        rights = self._build_rights(
            entry,
            request.rights,
            source_reference_id=parent.entry.reference_id,
        )
        self._validate_pilot_admission(
            reference_id=entry.reference_id,
            receipt=request.pilot_admission,
            rights=rights,
        )
        source_id = rights.source_id
        spans = tuple(
            SourceSpanV1(
                span_id=stable_identifier(
                    "source-span",
                    f"{entry.reference_id}:{span.span_key}",
                ),
                locator=span.locator,
                content_hash=digest_text(HashKindV1.SOURCE_SPAN, span.permitted_excerpt),
                start_offset=span.start_offset,
                end_offset=span.end_offset,
                permitted_excerpt=None,
            )
            for span in request.spans
        )
        source_metadata: dict[str, object] = {
            "authors": list(parent.entry.authors),
            "citation": parent.entry.citation,
            "reference_manifest_sha256": verified.manifest_sha256,
            "derived_reference_id": entry.reference_id,
            "derived_artifact_kind": entry.artifact_kind.value,
            "reference_access_policy": entry.access_policy.value,
            "reference_model_egress_policy": entry.model_egress_policy.value,
            "license_expression": entry.license.expression,
            "license_evidence_url": entry.license.evidence_url,
            "parent_reference_id": parent.entry.reference_id,
            "parent_artifact_sha256": parent.entry.sha256,
            "parent_snapshot_ref": parent.cache_ref,
            "derivation": _derivation_metadata(entry),
            "human_parent_locators": _human_locator_records(
                entry.reference_id,
                request.spans,
            ),
            "source_analyst_ids": sorted({span.source_analyst_id for span in request.spans}),
        }
        if request.pilot_admission is not None:
            source_metadata["pilot_admission"] = request.pilot_admission.model_dump(mode="json")
        source = SourceRecordV1(
            source_id=source_id,
            work_id=parent.entry.reference_id,
            title=parent.entry.title,
            version=parent.entry.version,
            locator=parent.entry.source_record_url,
            content_hash=DigestV1(kind=HashKindV1.SOURCE_BYTES, value=entry.sha256),
            snapshot_ref=verified.cache_ref,
            retrieved_at=entry.retrieved_at,
            spans=spans,
            metadata=source_metadata,
        )
        formal_target = f"{request.formal.namespace}.{request.formal.declaration_name}"
        contract = StatementContractV1(
            contract_id=stable_identifier("statement-contract", request.contract_key),
            revision=request.revision,
            task_kind=request.task_kind,
            source=source,
            rights=rights,
            mathematics=request.mathematics,
            formal=request.formal,
            alignments=tuple(
                AlignmentTargetV1(
                    source_span_id=span.span_id,
                    formal_target=formal_target,
                    relation=request.alignment_relation,
                    confidence=request.alignment_confidence,
                    reviewer_id=request.alignment_reviewer_id,
                )
                for span in spans
            ),
            dependencies=request.dependencies,
            policy=request.policy,
            provenance=request.provenance,
            status=StatementStatusV1.DRAFT,
        )
        packet = StatementDraftPacket(
            contract=contract,
            preparation_id=stable_identifier(
                "source-preparation",
                f"{contract.contract_id.value}:revision:{contract.revision}",
            ),
            reference_id=entry.reference_id,
            manifest_sha256=verified.manifest_sha256,
            artifact_sha256=entry.sha256,
            parent_reference_id=parent.entry.reference_id,
            parent_artifact_sha256=parent.entry.sha256,
            rights_record=rights,
            spans=request.spans,
            pilot_admission=request.pilot_admission,
        )
        packet._assert_source_binds(self.cache)
        try:
            self.preparation_ledger.record(packet.preparation_record())
        except SourcePreparationError as error:
            raise SourceHarnessError(str(error)) from error
        self._assert_packet(packet)
        return packet

    def run_fidelity(
        self,
        packet: StatementDraftPacket,
        *,
        obligations: tuple[SemanticObligation, ...],
        translators: tuple[TranslationAgent, ...],
        mutation_agent: MutationSuiteAgent,
        reviewer: SemanticReviewAgent,
        additional_signoffs: tuple[ReviewerSignoffV1, ...] = (),
    ) -> FidelityEvaluation:
        self._assert_packet(packet)
        source_claims = tuple(
            SourceClaimSpan(
                span_id=stable_identifier(
                    "source-span",
                    f"{packet.reference_id}:{span.span_key}",
                ),
                locator=span.locator,
                content_hash=digest_text(
                    HashKindV1.SOURCE_SPAN,
                    span.permitted_excerpt,
                ),
                permitted_excerpt=span.permitted_excerpt,
            )
            for span in packet.spans
        )
        return self.fidelity_harness.run(
            packet.contract,
            obligations=obligations,
            source_claims=source_claims,
            translators=translators,
            mutation_agent=mutation_agent,
            reviewer=reviewer,
            additional_signoffs=additional_signoffs,
        )

    def revalidate_and_freeze(
        self,
        packet: StatementDraftPacket,
        *,
        evaluation: FidelityEvaluation,
        frozen_by: str,
        gate: FreezeGate | None = None,
    ) -> StatementContractV1:
        """Reverify source bytes immediately before the existing local freeze gate.

        This wrapper does not authenticate ``frozen_by``. Release authority remains blocked on the
        planned Builder signing gateway.
        """

        self._assert_packet(packet)
        frozen_at = self._now("freeze")
        self._validate_fidelity_before_freeze(evaluation, frozen_at)
        preparation = packet.preparation_record()
        return _freeze_reviewed_contract(
            packet.contract,
            evaluation=evaluation,
            source_preparation=preparation,
            frozen_by=frozen_by,
            gate=gate,
            frozen_at=frozen_at,
        )

    def revalidate_freeze_and_bridge(
        self,
        packet: StatementDraftPacket,
        *,
        evaluation: FidelityEvaluation,
        frozen_by: str,
        graphs: GraphBundleV1,
        bundle_key: str,
        fidelity_evidence: FidelityEvidenceArtifactRefV1,
        attestor: AttestationSignerV1,
        evidence_identity: str,
        gate: FreezeGate | None = None,
        attestation_ttl_seconds: float = 3600,
    ) -> FormalizationTaskBundleV1:
        """Revalidate the durable source record immediately before signed handoff."""

        frozen = self.revalidate_and_freeze(
            packet,
            evaluation=evaluation,
            frozen_by=frozen_by,
            gate=gate,
        )
        bundle_issued_at = self._now("bundle issue")
        if frozen.freeze is None:
            raise SourceHarnessError("freeze record is absent after Builder freeze")
        frozen_at = self._require_aware(frozen.freeze.frozen_at, "freeze record")
        if frozen_at > bundle_issued_at:
            raise SourceHarnessError("freeze timestamp is later than bundle issue timestamp")
        return _bridge_frozen_contract(
            frozen,
            graphs,
            bundle_key=bundle_key,
            fidelity_evidence=fidelity_evidence,
            attestor=attestor,
            evidence_identity=evidence_identity,
            attestation_ttl_seconds=attestation_ttl_seconds,
            bundle_issued_at=bundle_issued_at,
        )

    def _now(self, stage: str) -> datetime:
        return self._require_aware(self._clock(), f"{stage} clock")

    @staticmethod
    def _require_aware(value: object, label: str) -> datetime:
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise SourceHarnessError(f"{label} must be a timezone-aware datetime")
        return value.astimezone(UTC)

    @classmethod
    def _validate_fidelity_before_freeze(
        cls,
        evaluation: FidelityEvaluation,
        frozen_at: datetime,
    ) -> None:
        generated_at = cls._require_aware(
            evaluation.report.generated_at,
            "fidelity report timestamp",
        )
        if generated_at > frozen_at:
            raise SourceHarnessError("fidelity report timestamp is later than freeze timestamp")
        for signoff in evaluation.report.signoffs:
            reviewed_at = cls._require_aware(
                signoff.reviewed_at,
                "fidelity signoff timestamp",
            )
            if reviewed_at > generated_at:
                raise SourceHarnessError(
                    "fidelity signoff timestamp is later than fidelity report timestamp"
                )
            if reviewed_at > frozen_at:
                raise SourceHarnessError(
                    "fidelity signoff timestamp is later than freeze timestamp"
                )

    def _assert_packet(self, packet: StatementDraftPacket) -> None:
        packet.assert_binds(self.cache, self.preparation_ledger)
        self._validate_pilot_admission(
            reference_id=packet.reference_id,
            receipt=packet.pilot_admission,
            rights=packet.rights_record,
        )

    def _validate_pilot_admission(
        self,
        *,
        reference_id: str,
        receipt: PilotAdmissionReceiptV1 | None,
        rights: RightsRecordV1,
    ) -> None:
        if self.pilot_manifest is None:
            if receipt is not None:
                raise SourceHarnessError(
                    "pilot admission receipt cannot be checked without its manifest"
                )
            return
        matching = tuple(
            graph
            for graph in self.pilot_manifest.graphs
            if graph.source.reference is not None
            and graph.source.reference.reference_id == reference_id
        )
        if len(matching) > 1:
            raise SourceHarnessError("source reference belongs to multiple pilot graphs")
        if not matching:
            if receipt is not None:
                raise SourceHarnessError("pilot admission receipt names an unrelated source")
            return
        if receipt is None:
            raise SourceHarnessError(
                f"source belongs to blocked pilot graph {matching[0].graph_id}; "
                "an admission receipt is required"
            )
        if receipt.graph_id != matching[0].graph_id:
            raise SourceHarnessError("pilot admission receipt names a different source graph")
        try:
            self.pilot_manifest.validate_admission_receipt(receipt, rights=rights)
        except PilotHarnessError as error:
            raise SourceHarnessError(str(error)) from error

    def _validate_spans(
        self,
        entry: ReferenceEntryV1,
        spans: tuple[ChapterSourceSpan, ...],
    ) -> None:
        for span in spans:
            if span.verified_artifact_sha256 != entry.sha256:
                raise SourceHarnessError(
                    f"source span {span.span_key} was located against another artifact revision"
                )
            try:
                self.cache.verify_utf8_excerpt(
                    entry.reference_id,
                    start_offset=span.start_offset,
                    end_offset=span.end_offset,
                    permitted_excerpt=span.permitted_excerpt,
                )
            except ReferenceCacheError as error:
                raise SourceHarnessError(str(error)) from error

    @staticmethod
    def _require_derived_text(entry: ReferenceEntryV1) -> ReferenceDerivationV1:
        derivation = entry.derivation
        if (
            entry.artifact_kind is not ReferenceArtifactKind.DERIVED_TEXT
            or entry.media_type != "text/plain"
            or derivation is None
        ):
            raise SourceHarnessError(
                "statement drafts require derived text with manifest-typed provenance"
            )
        if derivation.kind is ReferenceDerivationKind.LOCAL_PDF_TEXT_EXTRACTION:
            if derivation.parent_locator_authority is not ParentLocatorAuthority.MANIFEST_BOUND:
                raise SourceHarnessError(
                    "local PDF derived text requires a manifest-bound parent locator policy"
                )
        elif derivation.parent_locator_authority is not ParentLocatorAuthority.HUMAN_DECLARED:
            raise SourceHarnessError(
                "repository-derived text requires a human-declared parent locator policy"
            )
        return derivation

    @staticmethod
    def _build_rights(
        entry: ReferenceEntryV1,
        review: RightsReview,
        *,
        source_reference_id: str,
    ) -> RightsRecordV1:
        for label, value in (
            ("review_key", review.review_key),
            ("source_license", review.source_license),
            ("attribution", review.attribution),
            ("reviewed_by", review.reviewed_by),
        ):
            if not value.strip() or value != value.strip():
                raise SourceHarnessError(f"{label} must be nonempty, trimmed text")
        if review.source_license != entry.license.expression:
            raise SourceHarnessError("rights review license differs from the reference manifest")
        if review.attribution != entry.attribution:
            raise SourceHarnessError("rights review must preserve the manifest attribution")
        if review.overall_decision in {
            PermissionDecisionV1.UNKNOWN,
            PermissionDecisionV1.DENY,
        }:
            raise SourceHarnessError("source rights must be affirmatively reviewed before drafting")
        if review.reviewed_at.tzinfo is None or review.reviewed_at.utcoffset() is None:
            raise SourceHarnessError("rights review timestamp must be timezone-aware")
        endpoint_classes = set(review.allowed_endpoint_classes)
        if len(endpoint_classes) != len(review.allowed_endpoint_classes):
            raise SourceHarnessError("rights review endpoint classes must be unique")
        if EndpointClassV1.NONE in endpoint_classes or EndpointClassV1.EXTERNAL in endpoint_classes:
            raise SourceHarnessError("raw external endpoint classes are never permitted")
        if review.model_egress is not PermissionDecisionV1.ALLOW and endpoint_classes:
            raise SourceHarnessError("non-allowed model egress cannot name endpoint classes")
        if entry.model_egress_policy is ReferenceEgressPolicy.NO_MODEL:
            if review.model_egress is PermissionDecisionV1.ALLOW:
                raise SourceHarnessError("the manifest prohibits all model use")
        elif entry.model_egress_policy is ReferenceEgressPolicy.LOCAL_ONLY:
            if endpoint_classes - {EndpointClassV1.LOCAL}:
                raise SourceHarnessError("the manifest permits only local model processing")
        elif endpoint_classes - {
            EndpointClassV1.LOCAL,
            EndpointClassV1.APPROVED_EXTERNAL,
        }:
            raise SourceHarnessError("rights review exceeds the manifest endpoint policy")
        source_id = stable_identifier("builder-source", source_reference_id)
        return RightsRecordV1(
            rights_id=stable_identifier("rights-review", review.review_key),
            source_id=source_id,
            source_license=review.source_license,
            generated_code_license=review.generated_code_license,
            overall_decision=review.overall_decision,
            redistribution=review.redistribution,
            model_egress=review.model_egress,
            training=review.training,
            embedding=review.embedding,
            allowed_endpoint_classes=review.allowed_endpoint_classes,
            attribution=review.attribution,
            restrictions=review.restrictions,
            reviewed_by=review.reviewed_by,
            reviewed_at=review.reviewed_at,
        )


def _validate_manifest_rights_ceiling(
    entry: ReferenceEntryV1,
    parent: ReferenceEntryV1,
    rights: RightsRecordV1,
) -> None:
    expected_source_id = stable_identifier("builder-source", parent.reference_id)
    if rights.source_id != expected_source_id:
        raise SourceHarnessError("draft rights source identity changed")
    if rights.source_license != entry.license.expression:
        raise SourceHarnessError("draft rights license differs from the reference manifest")
    if rights.attribution != entry.attribution:
        raise SourceHarnessError("draft rights attribution differs from the reference manifest")
    if rights.overall_decision in {
        PermissionDecisionV1.UNKNOWN,
        PermissionDecisionV1.DENY,
    }:
        raise SourceHarnessError("draft rights are no longer affirmatively reviewed")
    if not rights.reviewed_by or rights.reviewed_at is None:
        raise SourceHarnessError("draft rights require a reviewer and timestamp")

    endpoint_classes = set(rights.allowed_endpoint_classes)
    if len(endpoint_classes) != len(rights.allowed_endpoint_classes):
        raise SourceHarnessError("draft rights endpoint classes must be unique")
    if EndpointClassV1.NONE in endpoint_classes or EndpointClassV1.EXTERNAL in endpoint_classes:
        raise SourceHarnessError("draft rights contain an unsupported endpoint class")
    if rights.model_egress is not PermissionDecisionV1.ALLOW and endpoint_classes:
        raise SourceHarnessError("non-allowed model egress cannot name endpoint classes")
    if entry.model_egress_policy is ReferenceEgressPolicy.NO_MODEL:
        if rights.model_egress is PermissionDecisionV1.ALLOW or endpoint_classes:
            raise SourceHarnessError("the manifest prohibits all model use")
    elif entry.model_egress_policy is ReferenceEgressPolicy.LOCAL_ONLY:
        if endpoint_classes - {EndpointClassV1.LOCAL}:
            raise SourceHarnessError("the manifest permits only local model processing")
    elif endpoint_classes - {
        EndpointClassV1.LOCAL,
        EndpointClassV1.APPROVED_EXTERNAL,
    }:
        raise SourceHarnessError("draft rights exceed the manifest endpoint policy")


def _derivation_metadata(entry: ReferenceEntryV1) -> dict[str, object]:
    derivation = entry.derivation
    if derivation is None:
        raise SourceHarnessError("derived source is missing extraction provenance")
    return {
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


def _human_locator_records(
    reference_id: str,
    spans: tuple[ChapterSourceSpan, ...],
) -> tuple[dict[str, str], ...]:
    return tuple(
        {
            "span_id": stable_identifier(
                "source-span",
                f"{reference_id}:{span.span_key}",
            ).value,
            "chapter_locator": span.human_declared_chapter_locator,
            "page_locator": span.human_declared_page_locator,
            "declared_by": span.source_analyst_id,
            "authority": ParentLocatorAuthority.HUMAN_DECLARED.value,
        }
        for span in spans
    )


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()
