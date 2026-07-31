"""Project-synthetic protocol for private atomic source-span consensus.

This module proves byte-boundary, exact-consensus, persistence, and redaction mechanics only.
It deliberately has no source-backed iFEM entry point while the local-use rights candidate lacks
a trusted attestation.  A successful synthetic result remains pending semantic review and cannot
create a statement contract, graph node, model execution, freeze, or Prover handoff.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import stat
import tempfile
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Final, Literal, Never, Self, cast

from autolean_contracts import StableIdentifierV1, canonical_json_bytes, stable_identifier
from autolean_contracts.base import ContractModel
from pydantic import Field, model_validator

IFEM_ATOMIC_SPAN_PROTOCOL: Final[Literal["autolean.builder-ifem-atomic-source-span.v1"]] = (
    "autolean.builder-ifem-atomic-source-span.v1"
)
IFEM_ATOMIC_SPAN_METHOD: Final[Literal["dual-independent-exact-boundary-consensus-v1"]] = (
    "dual-independent-exact-boundary-consensus-v1"
)

_SHA256 = r"^[0-9a-f]{64}$"
_SAFE_LABEL = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_PRIVATE_COMMITMENT_DOMAIN = b"autolean.ifem-atomic-span.private-commitment.v1\0"
_SYNTHETIC_FIXTURE_NAMESPACE = "ifem.atomic-span-synthetic-fixture"
_SYNTHETIC_PARENT_NAMESPACE = "ifem.atomic-span-synthetic-parent"
_OUTPUT_NAMESPACE = "ifem.atomic-span-atomizer-output"
_LOCATOR_NAMESPACE = "ifem.atomic-span-private-locator"
_GAP_NAMESPACE = "ifem.atomic-span-gap"
_SIDECAR_NAMESPACE = "ifem.atomic-span-private-sidecar"
_MAX_PRIVATE_SIDECAR_BYTES = 16 * 1024 * 1024
_REPARSE_POINT = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
_HANDLE_TOKEN = object()


class IFEMAtomicSourceSpanError(ValueError):
    """The synthetic protocol input, consensus, persistence, or redaction is invalid."""


class IFEMAtomizerSlotV1(StrEnum):
    A = "atomizer_a"
    B = "atomizer_b"


class IFEMAtomizerDecisionV1(StrEnum):
    PROPOSE = "propose"
    ABSTAIN = "abstain"


class IFEMAtomicSpanClassV1(StrEnum):
    DEFINITION = "definition"
    MATHEMATICAL_CLAIM = "mathematical_claim"
    PROOF = "proof"
    MIXED = "mixed"
    OTHER = "other"


class IFEMAtomicityV1(StrEnum):
    ATOMIC = "atomic"
    MIXED = "mixed"
    UNCERTAIN = "uncertain"


class IFEMAtomicSpanOutcomeV1(StrEnum):
    MACHINE_LOCATED_PENDING_SEMANTIC_REVIEW = "machine_located_pending_semantic_review"
    ABSTAIN = "abstain"


class IFEMAtomicSpanGapReasonV1(StrEnum):
    AMBIGUOUS_BOUNDARY = "ambiguous_boundary"
    ATOMIZER_ABSTAINED = "atomizer_abstained"
    ATOMIZER_DISAGREEMENT = "atomizer_disagreement"
    DIGEST_MISMATCH = "digest_mismatch"
    INDEPENDENCE_NOT_ESTABLISHED = "independence_not_established"
    INVALID_UTF8_BOUNDARY = "invalid_utf8_boundary"
    MIXED_ATOM = "mixed_atom"
    NO_ATOMIC_CLAIM = "no_atomic_claim"
    OUT_OF_BOUNDS = "out_of_bounds"
    OVERLAPPING_SPANS = "overlapping_spans"
    PROOF_ENTANGLED = "proof_entangled"
    UNCERTAIN_ATOMICITY = "uncertain_atomicity"
    UNSUPPORTED_SPAN_CLASS = "unsupported_span_class"


class IFEMAtomicSpanAuthorityV1(ContractModel):
    """Synthetic mechanics never carry rights, semantic, proof, or release authority."""

    schema_version: Literal["autolean.ifem-atomic-span-authority.v1"] = (
        "autolean.ifem-atomic-span-authority.v1"
    )
    source_rights_authorized: Literal[False] = False
    source_backed_execution_authorized: Literal[False] = False
    model_execution_authorized: Literal[False] = False
    independence_verified: Literal[False] = False
    semantic_review_authorized: Literal[False] = False
    statement_contract_authorized: Literal[False] = False
    mathematical_graph_authorized: Literal[False] = False
    formal_graph_authorized: Literal[False] = False
    execution_graph_authorized: Literal[False] = False
    builder_freeze_authorized: Literal[False] = False
    prover_handoff_authorized: Literal[False] = False
    kernel_verification_authorized: Literal[False] = False
    promotion_authorized: Literal[False] = False
    release_authorized: Literal[False] = False


class IFEMAtomicSpanInputBindingV1(ContractModel):
    """Text-free identity of one project-owned synthetic UTF-8 protocol fixture."""

    schema_version: Literal["autolean.ifem-atomic-span-input-binding.v1"] = (
        "autolean.ifem-atomic-span-input-binding.v1"
    )
    protocol: Literal["autolean.builder-ifem-atomic-source-span.v1"] = IFEM_ATOMIC_SPAN_PROTOCOL
    fixture_id: StableIdentifierV1
    parent_cell_span_id: StableIdentifierV1
    input_scope: Literal["project_synthetic_protocol_fixture"] = (
        "project_synthetic_protocol_fixture"
    )
    projection_method: Literal["project-synthetic-logical-utf8-v1"] = (
        "project-synthetic-logical-utf8-v1"
    )
    cell_utf8_sha256: str = Field(pattern=_SHA256)
    cell_utf8_byte_count: int = Field(gt=0, strict=True)
    source_text_private: Literal[True] = True
    real_ifem_source_present: Literal[False] = False
    rights_attestation_present: Literal[False] = False
    source_backed_execution_authorized: Literal[False] = False
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_binding(self) -> Self:
        if self.fixture_id.namespace != _SYNTHETIC_FIXTURE_NAMESPACE:
            raise ValueError("atomic-span fixture uses the wrong stable-id namespace")
        if self.parent_cell_span_id.namespace != _SYNTHETIC_PARENT_NAMESPACE:
            raise ValueError("atomic-span parent uses the wrong stable-id namespace")
        if self.content_sha256 != _sha256_payload(self.content_payload()):
            raise ValueError("atomic-span input-binding hash drifted")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(dict[str, object], self.model_dump(mode="json", exclude={"content_sha256"}))


class IFEMAtomizerObservationV1(ContractModel):
    """One private byte-range proposal; it is not a contract source span."""

    start_byte: int = Field(ge=0, strict=True)
    end_byte: int = Field(gt=0, strict=True)
    span_content_sha256: str = Field(pattern=_SHA256)
    span_class: IFEMAtomicSpanClassV1
    atomicity: IFEMAtomicityV1
    proof_entangled: bool = Field(strict=True)

    @model_validator(mode="after")
    def validate_range(self) -> Self:
        if self.end_byte <= self.start_byte:
            raise ValueError("atomizer observation must use a nonempty half-open byte range")
        return self


class IFEMAtomizerOutputV1(ContractModel):
    """One blinded slot output with no text, peer output, provider, or execution authority."""

    schema_version: Literal["autolean.ifem-atomizer-output.v1"] = "autolean.ifem-atomizer-output.v1"
    protocol: Literal["autolean.builder-ifem-atomic-source-span.v1"] = IFEM_ATOMIC_SPAN_PROTOCOL
    output_id: StableIdentifierV1
    slot: IFEMAtomizerSlotV1
    method_id: str = Field(min_length=1, max_length=128)
    independence_group: str = Field(min_length=1, max_length=128)
    input_binding_sha256: str = Field(pattern=_SHA256)
    decision: IFEMAtomizerDecisionV1
    observations: tuple[IFEMAtomizerObservationV1, ...] = ()
    reason_codes: tuple[IFEMAtomicSpanGapReasonV1, ...] = ()
    peer_output_visible: Literal[False] = False
    contains_source_text: Literal[False] = False
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_output(self) -> Self:
        if _SAFE_LABEL.fullmatch(self.method_id) is None:
            raise ValueError("atomizer method id is not a safe identifier")
        if _SAFE_LABEL.fullmatch(self.independence_group) is None:
            raise ValueError("atomizer independence group is not a safe identifier")
        expected_id = _output_id(
            input_binding_sha256=self.input_binding_sha256,
            slot=self.slot,
            method_id=self.method_id,
            independence_group=self.independence_group,
        )
        if self.output_id != expected_id:
            raise ValueError("atomizer output id does not bind its task identity")
        if self.observations != tuple(
            sorted(
                self.observations,
                key=lambda item: (
                    item.start_byte,
                    item.end_byte,
                    item.span_class.value,
                    item.atomicity.value,
                    item.proof_entangled,
                ),
            )
        ):
            raise ValueError("atomizer observations must use canonical byte order")
        if len(set(self.reason_codes)) != len(self.reason_codes) or self.reason_codes != tuple(
            sorted(self.reason_codes, key=lambda reason: reason.value)
        ):
            raise ValueError("atomizer reason codes must be canonical and unique")
        if self.decision is IFEMAtomizerDecisionV1.PROPOSE:
            if not self.observations or self.reason_codes:
                raise ValueError("a proposing atomizer requires observations and no reason codes")
        elif self.observations or not self.reason_codes:
            raise ValueError("an abstaining atomizer requires reasons and no observations")
        if self.content_sha256 != _sha256_payload(self.content_payload()):
            raise ValueError("atomizer output hash drifted")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(dict[str, object], self.model_dump(mode="json", exclude={"content_sha256"}))


class IFEMMachineLocatedSpanV1(ContractModel):
    """A private machine locator, still awaiting semantic review."""

    schema_version: Literal["autolean.ifem-machine-located-span.v1"] = (
        "autolean.ifem-machine-located-span.v1"
    )
    locator_id: StableIdentifierV1
    parent_cell_span_id: StableIdentifierV1
    locator_method: Literal["dual-independent-exact-boundary-consensus-v1"] = (
        IFEM_ATOMIC_SPAN_METHOD
    )
    start_byte: int = Field(ge=0, strict=True)
    end_byte: int = Field(gt=0, strict=True)
    span_content_sha256: str = Field(pattern=_SHA256)
    span_class: IFEMAtomicSpanClassV1
    locator_state: Literal["machine_located_pending_semantic_review"] = (
        "machine_located_pending_semantic_review"
    )
    excerpt_present: Literal[False] = False

    @model_validator(mode="after")
    def validate_locator(self) -> Self:
        if self.end_byte <= self.start_byte:
            raise ValueError("machine locator must use a nonempty half-open byte range")
        if self.span_class not in {
            IFEMAtomicSpanClassV1.DEFINITION,
            IFEMAtomicSpanClassV1.MATHEMATICAL_CLAIM,
        }:
            raise ValueError("machine locator must contain a definition or mathematical claim")
        expected = _locator_id(
            parent_cell_span_id=self.parent_cell_span_id,
            start_byte=self.start_byte,
            end_byte=self.end_byte,
        )
        if self.locator_id != expected:
            raise ValueError("machine locator id does not bind parent, method, and offsets")
        return self


class IFEMAtomicSpanGapV1(ContractModel):
    """Builder-local abstention evidence; never a Prover GapReport."""

    schema_version: Literal["autolean.ifem-atomic-span-gap.v1"] = "autolean.ifem-atomic-span-gap.v1"
    gap_id: StableIdentifierV1
    input_binding_sha256: str = Field(pattern=_SHA256)
    outcome: Literal[IFEMAtomicSpanOutcomeV1.ABSTAIN] = IFEMAtomicSpanOutcomeV1.ABSTAIN
    reason_codes: tuple[IFEMAtomicSpanGapReasonV1, ...] = Field(min_length=1)
    source_text_included: Literal[False] = False
    offsets_included: Literal[False] = False
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_gap(self) -> Self:
        canonical = tuple(sorted(set(self.reason_codes), key=lambda reason: reason.value))
        if self.reason_codes != canonical:
            raise ValueError("atomic-span gap reasons must be canonical and unique")
        expected_id = _gap_id(self.input_binding_sha256, self.reason_codes)
        if self.gap_id != expected_id:
            raise ValueError("atomic-span gap id does not bind its input and reasons")
        if self.content_sha256 != _sha256_payload(self.content_payload()):
            raise ValueError("atomic-span gap hash drifted")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(dict[str, object], self.model_dump(mode="json", exclude={"content_sha256"}))


class IFEMAtomicSpanPrivateSidecarV1(ContractModel):
    """Private consensus record; source text remains in the separate projection/fixture."""

    schema_version: Literal["autolean.ifem-atomic-span-private-sidecar.v1"] = (
        "autolean.ifem-atomic-span-private-sidecar.v1"
    )
    protocol: Literal["autolean.builder-ifem-atomic-source-span.v1"] = IFEM_ATOMIC_SPAN_PROTOCOL
    artifact_kind: Literal["project_synthetic_private_atomic_span_sidecar"] = (
        "project_synthetic_private_atomic_span_sidecar"
    )
    sidecar_id: StableIdentifierV1
    input_binding: IFEMAtomicSpanInputBindingV1
    atomizer_a: IFEMAtomizerOutputV1
    atomizer_b: IFEMAtomizerOutputV1
    outcome: IFEMAtomicSpanOutcomeV1
    accepted_spans: tuple[IFEMMachineLocatedSpanV1, ...] = ()
    gaps: tuple[IFEMAtomicSpanGapV1, ...] = ()
    commitment_nonce: str = Field(pattern=_SHA256)
    commitment_nonce_source: Literal["os_csprng", "test_injected"]
    source_text_included: Literal[False] = False
    semantic_review_state: Literal["not_performed"] = "not_performed"
    statement_contract_present: Literal[False] = False
    graph_nodes_present: Literal[False] = False
    independence_verified: Literal[False] = False
    authority: IFEMAtomicSpanAuthorityV1 = Field(default_factory=IFEMAtomicSpanAuthorityV1)
    builder_freeze: Literal["forbidden"] = "forbidden"
    prover_handoff: Literal["forbidden"] = "forbidden"
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_sidecar(self) -> Self:
        if self.atomizer_a.slot is not IFEMAtomizerSlotV1.A:
            raise ValueError("atomic-span sidecar slot A is invalid")
        if self.atomizer_b.slot is not IFEMAtomizerSlotV1.B:
            raise ValueError("atomic-span sidecar slot B is invalid")
        if (
            self.atomizer_a.input_binding_sha256 != self.input_binding.content_sha256
            or self.atomizer_b.input_binding_sha256 != self.input_binding.content_sha256
        ):
            raise ValueError("atomic-span outputs do not bind the sidecar input")
        if self.authority != IFEMAtomicSpanAuthorityV1():
            raise ValueError("atomic-span sidecar authority flags drifted")
        expected_id = _sidecar_id(
            self.input_binding.content_sha256,
            self.atomizer_a.content_sha256,
            self.atomizer_b.content_sha256,
        )
        if self.sidecar_id != expected_id:
            raise ValueError("atomic-span sidecar id does not bind its exact outputs")
        if self.outcome is IFEMAtomicSpanOutcomeV1.MACHINE_LOCATED_PENDING_SEMANTIC_REVIEW:
            if not self.accepted_spans or self.gaps:
                raise ValueError("successful atomic-span sidecar must contain only located spans")
            if (
                self.atomizer_a.method_id == self.atomizer_b.method_id
                or self.atomizer_a.independence_group == self.atomizer_b.independence_group
            ):
                raise ValueError("successful atomic-span sidecar lacks distinct actor lineage")
            expected = tuple(
                _located_span(self.input_binding.parent_cell_span_id, observation)
                for observation in self.atomizer_a.observations
            )
            if self.atomizer_a.observations != self.atomizer_b.observations:
                raise ValueError("successful atomic-span sidecar lacks exact output consensus")
            if _nontext_success_rejection_reason(
                self.input_binding.cell_utf8_byte_count,
                self.atomizer_a.observations,
            ):
                raise ValueError("successful atomic-span sidecar contains an inadmissible locator")
            if self.accepted_spans != expected:
                raise ValueError("atomic-span sidecar locators differ from exact consensus")
        else:
            if self.accepted_spans or len(self.gaps) != 1:
                raise ValueError("abstaining atomic-span sidecar requires exactly one private gap")
            if self.gaps[0].input_binding_sha256 != self.input_binding.content_sha256:
                raise ValueError("abstaining atomic-span sidecar gap binds a different input")
        if self.content_sha256 != _sha256_payload(self.content_payload()):
            raise ValueError("atomic-span sidecar hash drifted")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(dict[str, object], self.model_dump(mode="json", exclude={"content_sha256"}))

    def assert_not_authoritative(self) -> Never:
        raise IFEMAtomicSourceSpanError(
            "synthetic atomic-span evidence cannot authorize source processing, semantic review, "
            "freeze, or Prover handoff"
        )

    def authorize_model_execution(self) -> Never:
        self.assert_not_authoritative()

    def freeze_statement(self) -> Never:
        self.assert_not_authoritative()

    def handoff_to_prover(self) -> Never:
        self.assert_not_authoritative()


class IFEMAtomicSpanPublicCommitmentV1(ContractModel):
    """Nonce-hardened public projection with no private locator or CAS handle."""

    schema_version: Literal["autolean.ifem-atomic-span-public-commitment.v1"] = (
        "autolean.ifem-atomic-span-public-commitment.v1"
    )
    protocol: Literal["autolean.builder-ifem-atomic-source-span.v1"] = IFEM_ATOMIC_SPAN_PROTOCOL
    artifact_kind: Literal["project_synthetic_atomic_span_public_commitment"] = (
        "project_synthetic_atomic_span_public_commitment"
    )
    commitment_scheme: Literal["sha256-domain-separated-private-nonce-v1"] = (
        "sha256-domain-separated-private-nonce-v1"
    )
    private_sidecar_commitment_sha256: str = Field(pattern=_SHA256)
    private_sidecar_size_bytes: int = Field(gt=0, le=_MAX_PRIVATE_SIDECAR_BYTES, strict=True)
    outcome: IFEMAtomicSpanOutcomeV1
    accepted_span_count: int = Field(ge=0, strict=True)
    gap_count: int = Field(ge=0, le=1, strict=True)
    nonce_disclosed: Literal[False] = False
    source_text_disclosed: Literal[False] = False
    offsets_disclosed: Literal[False] = False
    span_hashes_disclosed: Literal[False] = False
    atomizer_outputs_disclosed: Literal[False] = False
    private_path_disclosed: Literal[False] = False
    commitment_is_private_cas_locator: Literal[False] = False
    commitment_authenticated: Literal[False] = False
    private_persistence_provenance_verified: Literal[False] = False
    nonce_provenance_verified: Literal[False] = False
    commitment_non_enumerability_verified: Literal[False] = False
    independence_verified: Literal[False] = False
    semantic_review_state: Literal["not_performed"] = "not_performed"
    authority: IFEMAtomicSpanAuthorityV1 = Field(default_factory=IFEMAtomicSpanAuthorityV1)
    builder_freeze: Literal["forbidden"] = "forbidden"
    prover_handoff: Literal["forbidden"] = "forbidden"
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_public_commitment(self) -> Self:
        if self.outcome is IFEMAtomicSpanOutcomeV1.MACHINE_LOCATED_PENDING_SEMANTIC_REVIEW:
            if self.accepted_span_count <= 0 or self.gap_count != 0:
                raise ValueError("successful public commitment has inconsistent coarse counts")
        elif self.accepted_span_count != 0 or self.gap_count != 1:
            raise ValueError("abstaining public commitment has inconsistent coarse counts")
        if self.authority != IFEMAtomicSpanAuthorityV1():
            raise ValueError("atomic-span public authority flags drifted")
        if self.content_sha256 != _sha256_payload(self.content_payload()):
            raise ValueError("atomic-span public commitment hash drifted")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(dict[str, object], self.model_dump(mode="json", exclude={"content_sha256"}))

    def assert_not_authoritative(self) -> Never:
        raise IFEMAtomicSourceSpanError(
            "atomic-span public commitment is redacted protocol evidence, not semantic or proof "
            "authority"
        )

    def freeze_statement(self) -> Never:
        self.assert_not_authoritative()

    def handoff_to_prover(self) -> Never:
        self.assert_not_authoritative()


@dataclass(frozen=True, slots=True)
class PersistedIFEMAtomicSpanSidecar:
    """Cooperative marker that canonical private bytes were installed and read back."""

    sidecar: IFEMAtomicSpanPrivateSidecarV1
    canonical_bytes: bytes = field(repr=False)
    path: Path = field(repr=False)
    repository_root: Path = field(repr=False)
    directory_snapshot: tuple[tuple[Path, tuple[int, int, int, int]], ...] = field(repr=False)
    _token: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._token is not _HANDLE_TOKEN:
            raise IFEMAtomicSourceSpanError(
                "persisted sidecar handle is missing the process-local marker"
            )

    def __getstate__(self) -> Never:
        raise TypeError("persisted atomic-span handles cannot be serialized")

    def __reduce_ex__(self, protocol: object) -> Never:
        del protocol
        raise TypeError("persisted atomic-span handles cannot be serialized")


def build_project_synthetic_atomic_span_input(
    *,
    fixture_label: str,
    cell_text: str,
) -> IFEMAtomicSpanInputBindingV1:
    """Bind project-owned synthetic text without embedding it in the contract model."""

    if _SAFE_LABEL.fullmatch(fixture_label) is None:
        raise IFEMAtomicSourceSpanError("synthetic fixture label is not a safe identifier")
    encoded = _strict_nonempty_utf8(cell_text)
    fixture_id = stable_identifier(_SYNTHETIC_FIXTURE_NAMESPACE, fixture_label)
    payload: dict[str, object] = {
        "schema_version": "autolean.ifem-atomic-span-input-binding.v1",
        "protocol": IFEM_ATOMIC_SPAN_PROTOCOL,
        "fixture_id": fixture_id.model_dump(mode="json"),
        "parent_cell_span_id": stable_identifier(
            _SYNTHETIC_PARENT_NAMESPACE,
            fixture_id.value,
        ).model_dump(mode="json"),
        "input_scope": "project_synthetic_protocol_fixture",
        "projection_method": "project-synthetic-logical-utf8-v1",
        "cell_utf8_sha256": hashlib.sha256(encoded).hexdigest(),
        "cell_utf8_byte_count": len(encoded),
        "source_text_private": True,
        "real_ifem_source_present": False,
        "rights_attestation_present": False,
        "source_backed_execution_authorized": False,
    }
    payload["content_sha256"] = _sha256_payload(payload)
    return IFEMAtomicSpanInputBindingV1.model_validate(payload)


def build_ifem_atomizer_output(
    *,
    input_binding: IFEMAtomicSpanInputBindingV1,
    slot: IFEMAtomizerSlotV1,
    method_id: str,
    independence_group: str,
    decision: IFEMAtomizerDecisionV1,
    observations: tuple[IFEMAtomizerObservationV1, ...] = (),
    reason_codes: tuple[IFEMAtomicSpanGapReasonV1, ...] = (),
) -> IFEMAtomizerOutputV1:
    """Build one precomputed blind output; no provider or model is called here."""

    binding = _revalidate_input(input_binding)
    canonical_observations = observations
    canonical_reasons = reason_codes
    output_id = _output_id(
        input_binding_sha256=binding.content_sha256,
        slot=slot,
        method_id=method_id,
        independence_group=independence_group,
    )
    payload: dict[str, object] = {
        "schema_version": "autolean.ifem-atomizer-output.v1",
        "protocol": IFEM_ATOMIC_SPAN_PROTOCOL,
        "output_id": output_id.model_dump(mode="json"),
        "slot": slot.value,
        "method_id": method_id,
        "independence_group": independence_group,
        "input_binding_sha256": binding.content_sha256,
        "decision": decision.value,
        "observations": [item.model_dump(mode="json") for item in canonical_observations],
        "reason_codes": [reason.value for reason in canonical_reasons],
        "peer_output_visible": False,
        "contains_source_text": False,
    }
    payload["content_sha256"] = _sha256_payload(payload)
    try:
        return IFEMAtomizerOutputV1.model_validate(payload)
    except ValueError as error:
        raise IFEMAtomicSourceSpanError("atomizer output is invalid") from error


def reconcile_project_synthetic_atomic_spans(
    *,
    input_binding: IFEMAtomicSpanInputBindingV1,
    cell_text: str,
    atomizer_a: IFEMAtomizerOutputV1,
    atomizer_b: IFEMAtomizerOutputV1,
    commitment_nonce: str | None = None,
) -> IFEMAtomicSpanPrivateSidecarV1:
    """Reconcile exact precomputed outputs without normalizing, trimming, or calling a model."""

    binding = _revalidate_input(input_binding)
    encoded = _verify_bound_text(binding, cell_text)
    output_a = _revalidate_output(atomizer_a)
    output_b = _revalidate_output(atomizer_b)
    if output_a.slot is not IFEMAtomizerSlotV1.A or output_b.slot is not IFEMAtomizerSlotV1.B:
        raise IFEMAtomicSourceSpanError("atomic-span reconciliation requires slots A and B")
    if (
        output_a.input_binding_sha256 != binding.content_sha256
        or output_b.input_binding_sha256 != binding.content_sha256
    ):
        raise IFEMAtomicSourceSpanError("atomizer output is bound to a different input")

    reasons = _reconciliation_reasons(encoded, output_a, output_b)
    if reasons:
        outcome = IFEMAtomicSpanOutcomeV1.ABSTAIN
        accepted: tuple[IFEMMachineLocatedSpanV1, ...] = ()
        gaps: tuple[IFEMAtomicSpanGapV1, ...] = (_build_gap(binding.content_sha256, reasons),)
    else:
        outcome = IFEMAtomicSpanOutcomeV1.MACHINE_LOCATED_PENDING_SEMANTIC_REVIEW
        accepted = tuple(
            _located_span(binding.parent_cell_span_id, observation)
            for observation in output_a.observations
        )
        gaps = ()
    nonce = secrets.token_hex(32) if commitment_nonce is None else commitment_nonce
    nonce_source = "test_injected" if commitment_nonce is not None else "os_csprng"
    if not isinstance(nonce, str) or re.fullmatch(_SHA256, nonce) is None:
        raise IFEMAtomicSourceSpanError("private commitment nonce must be 32-byte lowercase hex")
    sidecar_id = _sidecar_id(
        binding.content_sha256,
        output_a.content_sha256,
        output_b.content_sha256,
    )
    payload: dict[str, object] = {
        "schema_version": "autolean.ifem-atomic-span-private-sidecar.v1",
        "protocol": IFEM_ATOMIC_SPAN_PROTOCOL,
        "artifact_kind": "project_synthetic_private_atomic_span_sidecar",
        "sidecar_id": sidecar_id.model_dump(mode="json"),
        "input_binding": binding.model_dump(mode="json"),
        "atomizer_a": output_a.model_dump(mode="json"),
        "atomizer_b": output_b.model_dump(mode="json"),
        "outcome": outcome.value,
        "accepted_spans": [item.model_dump(mode="json") for item in accepted],
        "gaps": [item.model_dump(mode="json") for item in gaps],
        "commitment_nonce": nonce,
        "commitment_nonce_source": nonce_source,
        "source_text_included": False,
        "semantic_review_state": "not_performed",
        "statement_contract_present": False,
        "graph_nodes_present": False,
        "independence_verified": False,
        "authority": IFEMAtomicSpanAuthorityV1().model_dump(mode="json"),
        "builder_freeze": "forbidden",
        "prover_handoff": "forbidden",
    }
    payload["content_sha256"] = _sha256_payload(payload)
    try:
        return IFEMAtomicSpanPrivateSidecarV1.model_validate(payload)
    except ValueError as error:
        raise IFEMAtomicSourceSpanError("atomic-span sidecar is invalid") from error


def verify_project_synthetic_atomic_span_sidecar(
    sidecar: IFEMAtomicSpanPrivateSidecarV1,
    *,
    cell_text: str,
) -> IFEMAtomicSpanPrivateSidecarV1:
    """Replay text-dependent checks that the serializable sidecar cannot perform alone."""

    verified = _revalidate_sidecar(sidecar)
    expected = reconcile_project_synthetic_atomic_spans(
        input_binding=verified.input_binding,
        cell_text=cell_text,
        atomizer_a=verified.atomizer_a,
        atomizer_b=verified.atomizer_b,
        commitment_nonce=verified.commitment_nonce,
    )
    if verified != expected:
        raise IFEMAtomicSourceSpanError("atomic-span sidecar differs from deterministic replay")
    return verified


def render_ifem_atomic_span_private_sidecar(
    sidecar: IFEMAtomicSpanPrivateSidecarV1,
) -> bytes:
    verified = _revalidate_sidecar(sidecar)
    return canonical_json_bytes(verified.model_dump(mode="json")) + b"\n"


def persist_ifem_atomic_span_private_sidecar_once(
    path: Path,
    sidecar: IFEMAtomicSpanPrivateSidecarV1,
    *,
    repository_root: Path,
    cell_text: str,
) -> PersistedIFEMAtomicSpanSidecar:
    """Install private bytes outside the checkout, read them back, and return a handle."""

    verified = verify_project_synthetic_atomic_span_sidecar(sidecar, cell_text=cell_text)
    raw = render_ifem_atomic_span_private_sidecar(verified)
    target, parent_snapshot = _validate_private_target(path, repository_root=repository_root)
    existing = _read_optional_regular(target)
    if existing is None:
        _install_write_once(target, raw, parent_snapshot=parent_snapshot)
    elif existing != raw:
        raise IFEMAtomicSourceSpanError("existing atomic-span private sidecar conflicts")
    _assert_directory_snapshot(parent_snapshot)
    persisted = _read_regular(target)
    if persisted != raw:
        raise IFEMAtomicSourceSpanError("persisted atomic-span sidecar differs after readback")
    loaded = _parse_private_sidecar(persisted)
    verify_project_synthetic_atomic_span_sidecar(loaded, cell_text=cell_text)
    return PersistedIFEMAtomicSpanSidecar(
        loaded,
        persisted,
        target,
        _validated_repository_root(repository_root),
        parent_snapshot,
        _HANDLE_TOKEN,
    )


def load_persisted_ifem_atomic_span_private_sidecar(
    path: Path,
    *,
    repository_root: Path,
    cell_text: str,
) -> PersistedIFEMAtomicSpanSidecar:
    """Recover a committed sidecar without rerunning either atomizer."""

    target, parent_snapshot = _validate_private_target(path, repository_root=repository_root)
    raw = _read_regular(target)
    _assert_directory_snapshot(parent_snapshot)
    sidecar = _parse_private_sidecar(raw)
    verify_project_synthetic_atomic_span_sidecar(sidecar, cell_text=cell_text)
    return PersistedIFEMAtomicSpanSidecar(
        sidecar,
        raw,
        target,
        _validated_repository_root(repository_root),
        parent_snapshot,
        _HANDLE_TOKEN,
    )


def project_ifem_atomic_span_public_commitment(
    persisted: PersistedIFEMAtomicSpanSidecar,
) -> IFEMAtomicSpanPublicCommitmentV1:
    """Project after API persistence and rechecking its cooperative process-local marker."""

    if (
        type(persisted) is not PersistedIFEMAtomicSpanSidecar
        or persisted._token is not _HANDLE_TOKEN
    ):
        raise IFEMAtomicSourceSpanError(
            "public projection requires the process-local persistence marker"
        )
    target, current_snapshot = _validate_private_target(
        persisted.path,
        repository_root=persisted.repository_root,
    )
    if target != persisted.path or current_snapshot != persisted.directory_snapshot:
        raise IFEMAtomicSourceSpanError("persisted sidecar storage identity changed")
    current = _read_regular(target)
    if current != persisted.canonical_bytes:
        raise IFEMAtomicSourceSpanError("private sidecar changed after persistence")
    if render_ifem_atomic_span_private_sidecar(persisted.sidecar) != current:
        raise IFEMAtomicSourceSpanError("persisted sidecar is no longer canonical")
    sidecar = persisted.sidecar
    commitment = hashlib.sha256(
        _PRIVATE_COMMITMENT_DOMAIN + bytes.fromhex(sidecar.commitment_nonce) + current
    ).hexdigest()
    payload: dict[str, object] = {
        "schema_version": "autolean.ifem-atomic-span-public-commitment.v1",
        "protocol": IFEM_ATOMIC_SPAN_PROTOCOL,
        "artifact_kind": "project_synthetic_atomic_span_public_commitment",
        "commitment_scheme": "sha256-domain-separated-private-nonce-v1",
        "private_sidecar_commitment_sha256": commitment,
        "private_sidecar_size_bytes": len(current),
        "outcome": sidecar.outcome.value,
        "accepted_span_count": len(sidecar.accepted_spans),
        "gap_count": len(sidecar.gaps),
        "nonce_disclosed": False,
        "source_text_disclosed": False,
        "offsets_disclosed": False,
        "span_hashes_disclosed": False,
        "atomizer_outputs_disclosed": False,
        "private_path_disclosed": False,
        "commitment_is_private_cas_locator": False,
        "commitment_authenticated": False,
        "private_persistence_provenance_verified": False,
        "nonce_provenance_verified": False,
        "commitment_non_enumerability_verified": False,
        "independence_verified": False,
        "semantic_review_state": "not_performed",
        "authority": IFEMAtomicSpanAuthorityV1().model_dump(mode="json"),
        "builder_freeze": "forbidden",
        "prover_handoff": "forbidden",
    }
    payload["content_sha256"] = _sha256_payload(payload)
    return IFEMAtomicSpanPublicCommitmentV1.model_validate(payload)


def verify_ifem_atomic_span_public_commitment(
    persisted: PersistedIFEMAtomicSpanSidecar,
    public: IFEMAtomicSpanPublicCommitmentV1,
) -> IFEMAtomicSpanPublicCommitmentV1:
    if type(public) is not IFEMAtomicSpanPublicCommitmentV1:
        raise IFEMAtomicSourceSpanError("public commitment must use its exact typed model")
    try:
        verified = IFEMAtomicSpanPublicCommitmentV1.model_validate(public.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as error:
        raise IFEMAtomicSourceSpanError("atomic-span public commitment is invalid") from error
    if verified != project_ifem_atomic_span_public_commitment(persisted):
        raise IFEMAtomicSourceSpanError("public commitment differs from the persisted sidecar")
    return verified


def render_ifem_atomic_span_public_commitment(
    public: IFEMAtomicSpanPublicCommitmentV1,
) -> bytes:
    if type(public) is not IFEMAtomicSpanPublicCommitmentV1:
        raise IFEMAtomicSourceSpanError("public commitment must use its exact typed model")
    try:
        verified = IFEMAtomicSpanPublicCommitmentV1.model_validate(public.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as error:
        raise IFEMAtomicSourceSpanError("atomic-span public commitment is invalid") from error
    rendered = canonical_json_bytes(verified.model_dump(mode="json")) + b"\n"
    forbidden = (
        b'"atomizer_a"',
        b'"atomizer_b"',
        b'"commitment_nonce"',
        b'"end_byte"',
        b'"fixture_id"',
        b'"parent_cell_span_id"',
        b'"private_path"',
        b'"span_content_sha256"',
        b'"start_byte"',
    )
    if any(item in rendered for item in forbidden):
        raise IFEMAtomicSourceSpanError("public commitment leaked a private atomic-span field")
    return rendered


def _reconciliation_reasons(
    encoded: bytes,
    output_a: IFEMAtomizerOutputV1,
    output_b: IFEMAtomizerOutputV1,
) -> tuple[IFEMAtomicSpanGapReasonV1, ...]:
    reasons: set[IFEMAtomicSpanGapReasonV1] = set()
    if (
        output_a.method_id == output_b.method_id
        or output_a.independence_group == output_b.independence_group
    ):
        reasons.add(IFEMAtomicSpanGapReasonV1.INDEPENDENCE_NOT_ESTABLISHED)
    for output in (output_a, output_b):
        if output.decision is IFEMAtomizerDecisionV1.ABSTAIN:
            reasons.add(IFEMAtomicSpanGapReasonV1.ATOMIZER_ABSTAINED)
            reasons.update(output.reason_codes)
            continue
        reasons.update(_observation_reasons(encoded, output.observations))
    if (
        output_a.decision is IFEMAtomizerDecisionV1.PROPOSE
        and output_b.decision is IFEMAtomizerDecisionV1.PROPOSE
        and output_a.observations != output_b.observations
    ):
        reasons.add(IFEMAtomicSpanGapReasonV1.ATOMIZER_DISAGREEMENT)
    return tuple(sorted(reasons, key=lambda reason: reason.value))


def _observation_reasons(
    encoded: bytes,
    observations: tuple[IFEMAtomizerObservationV1, ...],
) -> set[IFEMAtomicSpanGapReasonV1]:
    reasons: set[IFEMAtomicSpanGapReasonV1] = set()
    previous_end = -1
    for observation in observations:
        if observation.start_byte < previous_end:
            reasons.add(IFEMAtomicSpanGapReasonV1.OVERLAPPING_SPANS)
        previous_end = max(previous_end, observation.end_byte)
        if observation.end_byte > len(encoded):
            reasons.add(IFEMAtomicSpanGapReasonV1.OUT_OF_BOUNDS)
            continue
        selected = encoded[observation.start_byte : observation.end_byte]
        try:
            selected.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            reasons.add(IFEMAtomicSpanGapReasonV1.INVALID_UTF8_BOUNDARY)
        if hashlib.sha256(selected).hexdigest() != observation.span_content_sha256:
            reasons.add(IFEMAtomicSpanGapReasonV1.DIGEST_MISMATCH)
        if observation.span_class not in {
            IFEMAtomicSpanClassV1.DEFINITION,
            IFEMAtomicSpanClassV1.MATHEMATICAL_CLAIM,
        }:
            reasons.add(IFEMAtomicSpanGapReasonV1.UNSUPPORTED_SPAN_CLASS)
        if observation.span_class is IFEMAtomicSpanClassV1.MIXED:
            reasons.add(IFEMAtomicSpanGapReasonV1.MIXED_ATOM)
        if observation.span_class is IFEMAtomicSpanClassV1.PROOF or observation.proof_entangled:
            reasons.add(IFEMAtomicSpanGapReasonV1.PROOF_ENTANGLED)
        if observation.atomicity is IFEMAtomicityV1.MIXED:
            reasons.add(IFEMAtomicSpanGapReasonV1.MIXED_ATOM)
        elif observation.atomicity is IFEMAtomicityV1.UNCERTAIN:
            reasons.add(IFEMAtomicSpanGapReasonV1.UNCERTAIN_ATOMICITY)
    if not observations:
        reasons.add(IFEMAtomicSpanGapReasonV1.NO_ATOMIC_CLAIM)
    return reasons


def _nontext_success_rejection_reason(
    byte_count: int,
    observations: tuple[IFEMAtomizerObservationV1, ...],
) -> bool:
    previous_end = -1
    for observation in observations:
        if observation.start_byte < previous_end or observation.end_byte > byte_count:
            return True
        previous_end = observation.end_byte
        if (
            observation.span_class
            not in {
                IFEMAtomicSpanClassV1.DEFINITION,
                IFEMAtomicSpanClassV1.MATHEMATICAL_CLAIM,
            }
            or observation.atomicity is not IFEMAtomicityV1.ATOMIC
            or observation.proof_entangled
        ):
            return True
    return not observations


def _build_gap(
    input_binding_sha256: str,
    reasons: tuple[IFEMAtomicSpanGapReasonV1, ...],
) -> IFEMAtomicSpanGapV1:
    payload: dict[str, object] = {
        "schema_version": "autolean.ifem-atomic-span-gap.v1",
        "gap_id": _gap_id(input_binding_sha256, reasons).model_dump(mode="json"),
        "input_binding_sha256": input_binding_sha256,
        "outcome": IFEMAtomicSpanOutcomeV1.ABSTAIN.value,
        "reason_codes": [reason.value for reason in reasons],
        "source_text_included": False,
        "offsets_included": False,
    }
    payload["content_sha256"] = _sha256_payload(payload)
    return IFEMAtomicSpanGapV1.model_validate(payload)


def _located_span(
    parent_cell_span_id: StableIdentifierV1,
    observation: IFEMAtomizerObservationV1,
) -> IFEMMachineLocatedSpanV1:
    return IFEMMachineLocatedSpanV1(
        locator_id=_locator_id(
            parent_cell_span_id=parent_cell_span_id,
            start_byte=observation.start_byte,
            end_byte=observation.end_byte,
        ),
        parent_cell_span_id=parent_cell_span_id,
        start_byte=observation.start_byte,
        end_byte=observation.end_byte,
        span_content_sha256=observation.span_content_sha256,
        span_class=observation.span_class,
    )


def _output_id(
    *,
    input_binding_sha256: str,
    slot: IFEMAtomizerSlotV1,
    method_id: str,
    independence_group: str,
) -> StableIdentifierV1:
    return stable_identifier(
        _OUTPUT_NAMESPACE,
        f"{input_binding_sha256}:{slot.value}:{method_id}:{independence_group}",
    )


def _locator_id(
    *,
    parent_cell_span_id: StableIdentifierV1,
    start_byte: int,
    end_byte: int,
) -> StableIdentifierV1:
    return stable_identifier(
        _LOCATOR_NAMESPACE,
        f"{parent_cell_span_id.namespace}:{parent_cell_span_id.value}:"
        f"{IFEM_ATOMIC_SPAN_METHOD}:{start_byte}:{end_byte}",
    )


def _gap_id(
    input_binding_sha256: str,
    reasons: tuple[IFEMAtomicSpanGapReasonV1, ...],
) -> StableIdentifierV1:
    return stable_identifier(
        _GAP_NAMESPACE,
        f"{input_binding_sha256}:{','.join(reason.value for reason in reasons)}",
    )


def _sidecar_id(
    input_binding_sha256: str,
    atomizer_a_sha256: str,
    atomizer_b_sha256: str,
) -> StableIdentifierV1:
    return stable_identifier(
        _SIDECAR_NAMESPACE,
        f"{input_binding_sha256}:{atomizer_a_sha256}:{atomizer_b_sha256}",
    )


def _revalidate_input(value: IFEMAtomicSpanInputBindingV1) -> IFEMAtomicSpanInputBindingV1:
    if type(value) is not IFEMAtomicSpanInputBindingV1:
        raise IFEMAtomicSourceSpanError("atomic-span input must use its exact typed model")
    try:
        return IFEMAtomicSpanInputBindingV1.model_validate(value.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as error:
        raise IFEMAtomicSourceSpanError("atomic-span input failed revalidation") from error


def _revalidate_output(value: IFEMAtomizerOutputV1) -> IFEMAtomizerOutputV1:
    if type(value) is not IFEMAtomizerOutputV1:
        raise IFEMAtomicSourceSpanError("atomizer output must use its exact typed model")
    try:
        return IFEMAtomizerOutputV1.model_validate(value.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as error:
        raise IFEMAtomicSourceSpanError("atomizer output failed revalidation") from error


def _revalidate_sidecar(
    value: IFEMAtomicSpanPrivateSidecarV1,
) -> IFEMAtomicSpanPrivateSidecarV1:
    if type(value) is not IFEMAtomicSpanPrivateSidecarV1:
        raise IFEMAtomicSourceSpanError("atomic-span sidecar must use its exact typed model")
    try:
        return IFEMAtomicSpanPrivateSidecarV1.model_validate(value.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as error:
        raise IFEMAtomicSourceSpanError("atomic-span sidecar failed revalidation") from error


def _strict_nonempty_utf8(value: str) -> bytes:
    if not isinstance(value, str):
        raise IFEMAtomicSourceSpanError("synthetic cell text must be a string")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise IFEMAtomicSourceSpanError("synthetic cell text is not strict UTF-8") from error
    if not encoded:
        raise IFEMAtomicSourceSpanError("synthetic cell text must not be empty")
    return encoded


def _verify_bound_text(binding: IFEMAtomicSpanInputBindingV1, cell_text: str) -> bytes:
    encoded = _strict_nonempty_utf8(cell_text)
    if len(encoded) != binding.cell_utf8_byte_count:
        raise IFEMAtomicSourceSpanError("synthetic cell UTF-8 byte count differs from binding")
    if hashlib.sha256(encoded).hexdigest() != binding.cell_utf8_sha256:
        raise IFEMAtomicSourceSpanError("synthetic cell bytes differ from binding")
    return encoded


def _sha256_payload(payload: object) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _parse_private_sidecar(raw: bytes) -> IFEMAtomicSpanPrivateSidecarV1:
    try:
        sidecar = IFEMAtomicSpanPrivateSidecarV1.model_validate_json(raw)
    except ValueError as error:
        raise IFEMAtomicSourceSpanError("private atomic-span sidecar is invalid JSON") from error
    if render_ifem_atomic_span_private_sidecar(sidecar) != raw:
        raise IFEMAtomicSourceSpanError("private atomic-span sidecar is not canonical JSON")
    return sidecar


def _validate_private_target(
    path: Path,
    *,
    repository_root: Path,
) -> tuple[Path, tuple[tuple[Path, tuple[int, int, int, int]], ...]]:
    target = _absolute_lexical(path)
    repository = _validated_repository_root(repository_root)
    if not target.name.endswith(".private.json"):
        raise IFEMAtomicSourceSpanError("private sidecar path must end in .private.json")
    try:
        target.relative_to(repository)
    except ValueError:
        pass
    else:
        raise IFEMAtomicSourceSpanError("private atomic-span sidecar must stay outside the repo")
    for candidate in (target.parent, *target.parent.parents):
        if (candidate / ".git").exists():
            raise IFEMAtomicSourceSpanError(
                "private atomic-span sidecar must stay outside every Git checkout"
            )
    snapshot = _snapshot_existing_directory(target.parent)
    return target, snapshot


def _absolute_lexical(path: Path) -> Path:
    if not isinstance(path, Path) or any(part in {".", ".."} for part in path.parts):
        raise IFEMAtomicSourceSpanError("private sidecar path has an unsafe component")
    absolute = Path(os.path.abspath(os.fspath(path)))
    if not absolute.is_absolute() or not absolute.anchor:
        raise IFEMAtomicSourceSpanError("private sidecar path must be absolute")
    if absolute.anchor.startswith("\\\\") or absolute.anchor == "//":
        raise IFEMAtomicSourceSpanError("private sidecar path cannot use UNC storage")
    return absolute


def _validated_repository_root(path: Path) -> Path:
    repository = _absolute_lexical(path)
    if not (repository / ".git").exists():
        raise IFEMAtomicSourceSpanError("repository root must contain .git")
    _snapshot_existing_directory(repository)
    return repository


def _snapshot_existing_directory(
    directory: Path,
) -> tuple[tuple[Path, tuple[int, int, int, int]], ...]:
    current = Path(directory.anchor)
    result: list[tuple[Path, tuple[int, int, int, int]]] = []
    for index, part in enumerate(directory.parts):
        if index:
            current /= part
        try:
            metadata = os.lstat(current)
        except OSError as error:
            raise IFEMAtomicSourceSpanError("private sidecar directory is unavailable") from error
        _require_directory(current, metadata)
        result.append((current, _stat_identity(metadata)))
    return tuple(result)


def _assert_directory_snapshot(
    snapshot: tuple[tuple[Path, tuple[int, int, int, int]], ...],
) -> None:
    for path, expected in snapshot:
        try:
            metadata = os.lstat(path)
        except OSError as error:
            raise IFEMAtomicSourceSpanError("private sidecar directory changed") from error
        _require_directory(path, metadata)
        if _stat_identity(metadata) != expected:
            raise IFEMAtomicSourceSpanError("private sidecar directory identity changed")


def _is_link_or_reparse(path: Path, metadata: os.stat_result) -> bool:
    is_junction = getattr(os.path, "isjunction", None)
    path_is_junction = getattr(path, "is_junction", None)
    return (
        stat.S_ISLNK(metadata.st_mode)
        or bool(int(getattr(metadata, "st_file_attributes", 0)) & _REPARSE_POINT)
        or bool(is_junction is not None and is_junction(path))
        or bool(path_is_junction is not None and path_is_junction())
    )


def _require_directory(path: Path, metadata: os.stat_result) -> None:
    if _is_link_or_reparse(path, metadata):
        raise IFEMAtomicSourceSpanError(
            "private sidecar directories cannot be links, junctions, or reparse points"
        )
    if not stat.S_ISDIR(metadata.st_mode):
        raise IFEMAtomicSourceSpanError("private sidecar path component is not a directory")


def _require_regular(path: Path, metadata: os.stat_result) -> None:
    if _is_link_or_reparse(path, metadata):
        raise IFEMAtomicSourceSpanError(
            "private sidecar cannot be a link, junction, or reparse point"
        )
    if not stat.S_ISREG(metadata.st_mode):
        raise IFEMAtomicSourceSpanError("private sidecar is not a regular file")


def _stat_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(stat.S_IFMT(metadata.st_mode)),
        int(getattr(metadata, "st_file_attributes", 0)),
    )


def _read_optional_regular(path: Path) -> bytes | None:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise IFEMAtomicSourceSpanError("cannot inspect private atomic-span sidecar") from error
    return _read_regular(path)


def _read_regular(path: Path) -> bytes:
    try:
        before = os.lstat(path)
    except OSError as error:
        raise IFEMAtomicSourceSpanError("private atomic-span sidecar is unavailable") from error
    _require_regular(path, before)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise IFEMAtomicSourceSpanError("cannot open private atomic-span sidecar") from error
    try:
        opened = os.fstat(descriptor)
        _require_regular(path, opened)
        if not os.path.samestat(before, opened):
            raise IFEMAtomicSourceSpanError("private sidecar changed while opening")
        data = bytearray()
        with os.fdopen(descriptor, "rb", closefd=True) as source:
            descriptor = -1
            while chunk := source.read(1024 * 1024):
                data.extend(chunk)
                if len(data) > _MAX_PRIVATE_SIDECAR_BYTES:
                    raise IFEMAtomicSourceSpanError("private atomic-span sidecar is too large")
            after_open = os.fstat(source.fileno())
        if not os.path.samestat(opened, after_open):
            raise IFEMAtomicSourceSpanError("private sidecar changed while reading")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    after = os.lstat(path)
    _require_regular(path, after)
    if not os.path.samestat(before, after):
        raise IFEMAtomicSourceSpanError("private sidecar changed during readback")
    return bytes(data)


def _install_write_once(
    target: Path,
    raw: bytes,
    *,
    parent_snapshot: tuple[tuple[Path, tuple[int, int, int, int]], ...],
) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".ifem-atomic-span-",
        suffix=".tmp",
        dir=target.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            descriptor = -1
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        _assert_directory_snapshot(parent_snapshot)
        try:
            os.link(temporary, target, follow_symlinks=False)
        except FileExistsError:
            existing = _read_regular(target)
            if existing != raw:
                raise IFEMAtomicSourceSpanError("racing private sidecar conflicts") from None
        except OSError as error:
            raise IFEMAtomicSourceSpanError("cannot install private atomic-span sidecar") from error
        _assert_directory_snapshot(parent_snapshot)
        _fsync_directory_if_supported(target.parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        except OSError as error:
            raise IFEMAtomicSourceSpanError("cannot clean private sidecar temporary") from error


def _fsync_directory_if_supported(path: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise IFEMAtomicSourceSpanError("cannot open private sidecar directory for sync") from error
    try:
        os.fsync(descriptor)
    except OSError as error:
        raise IFEMAtomicSourceSpanError("cannot synchronize private sidecar directory") from error
    finally:
        os.close(descriptor)


__all__ = [
    "IFEM_ATOMIC_SPAN_METHOD",
    "IFEM_ATOMIC_SPAN_PROTOCOL",
    "IFEMAtomicSourceSpanError",
    "IFEMAtomicSpanAuthorityV1",
    "IFEMAtomicSpanClassV1",
    "IFEMAtomicSpanGapReasonV1",
    "IFEMAtomicSpanGapV1",
    "IFEMAtomicSpanInputBindingV1",
    "IFEMAtomicSpanOutcomeV1",
    "IFEMAtomicSpanPrivateSidecarV1",
    "IFEMAtomicSpanPublicCommitmentV1",
    "IFEMAtomicityV1",
    "IFEMAtomizerDecisionV1",
    "IFEMAtomizerObservationV1",
    "IFEMAtomizerOutputV1",
    "IFEMAtomizerSlotV1",
    "IFEMMachineLocatedSpanV1",
    "PersistedIFEMAtomicSpanSidecar",
    "build_ifem_atomizer_output",
    "build_project_synthetic_atomic_span_input",
    "load_persisted_ifem_atomic_span_private_sidecar",
    "persist_ifem_atomic_span_private_sidecar_once",
    "project_ifem_atomic_span_public_commitment",
    "reconcile_project_synthetic_atomic_spans",
    "render_ifem_atomic_span_private_sidecar",
    "render_ifem_atomic_span_public_commitment",
    "verify_ifem_atomic_span_public_commitment",
    "verify_project_synthetic_atomic_span_sidecar",
]
