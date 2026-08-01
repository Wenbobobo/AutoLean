"""Operator-private 27-stage execution journal for source-free iFEM cases.

The journal is deliberately narrower than a provider harness.  It derives one fixed
``statement_formalizer -> fidelity_reviewer -> cheating_supervisor`` sequence for each of the
nine cases in :class:`PrivateSourceFreeSeedManifestV2`, records at most one dispatch claim for
each coordinate, and stores only opaque identifiers and hashes shaped as a ModelWork completion
binding.

An interrupted ``dispatch_started`` is never replayed automatically. Reconciliation requires an
explicit operator quiescence confirmation and an externally recovered completion binding. Every
completion is checked by an injected operator-private binding verifier, while the public
projection deliberately makes no attestation claim about that verifier. The module never stores
model response text, tool calls, usage payloads, provider credentials, prompts, or source
material.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from collections import Counter
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final, Literal, Never, Protocol, Self, cast

from autolean_contracts import (
    DigestV1,
    ModelExecutionCompletionReceiptV1,
    ModelExecutionSubjectKindV1,
    ModelWorkBundleV2,
    ModelWorkRoleV1,
    StableIdentifierV1,
    canonical_json_bytes,
    model_execution_completion_public,
    model_work_case_hash,
    model_work_run_hash,
)
from autolean_contracts.base import ContractModel
from autolean_contracts.hashing import HashKindV1, require_digest_kind
from pydantic import Field, model_validator

from .ifem_next_calibration_case_intents import IFEMNextCalibrationCaseIntentsV1
from .ifem_source_free_case_authoring import SourceFreeCaseAuthoringAuthorityV1
from .ifem_source_free_private_seed import (
    LocalSourceFreePrivateSeedStore,
    PrivateSourceFreeSeedItemV2,
    PrivateSourceFreeSeedManifestV2,
    SourceFreePrivateSeedError,
    verify_private_seed_manifest_against_queue,
)

SOURCE_FREE_STAGE_LEDGER_SCHEMA: Final[Literal["autolean.ifem-source-free-stage-ledger.v1"]] = (
    "autolean.ifem-source-free-stage-ledger.v1"
)
SOURCE_FREE_STAGE_LEDGER_PROTOCOL: Final[
    Literal["autolean.builder-ifem-source-free-stage-ledger.v1"]
] = "autolean.builder-ifem-source-free-stage-ledger.v1"
_RUN_NAMESPACE: Final[Literal["ifem-source-free-private-seed-run"]] = (
    "ifem-source-free-private-seed-run"
)
_CASE_NAMESPACE: Final[Literal["ifem-source-free-private-seed-case"]] = (
    "ifem-source-free-private-seed-case"
)
_ROLE_ORDER: Final[tuple[ModelWorkRoleV1, ...]] = (
    ModelWorkRoleV1.STATEMENT_FORMALIZER,
    ModelWorkRoleV1.FIDELITY_REVIEWER,
    ModelWorkRoleV1.CHEATING_SUPERVISOR,
)
_SHA256 = r"^[0-9a-f]{64}$"
_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
_FORBIDDEN_PUBLIC_FIELDS: Final[tuple[bytes, ...]] = (
    b'"case_id"',
    b'"completion_id"',
    b'"coordinate"',
    b'"model_work_bundle_id"',
    b'"private_root"',
    b'"role"',
    b'"run_id"',
)


class SourceFreeStageLedgerError(ValueError):
    """The private stage journal or its public boundary was violated."""


class SourceFreeStageReconciliationRequired(SourceFreeStageLedgerError):
    """A dispatch may have reached an executor and therefore cannot be replayed."""


class SourceFreeStageLedgerStateV1(StrEnum):
    PENDING = "pending"
    CLAIMED = "claimed"
    DISPATCH_STARTED = "dispatch_started"
    COMPLETION_COMMITTED = "completion_committed"
    RECONCILIATION_REQUIRED = "reconciliation_required"


class CompletionReceiptVerifier(Protocol):
    """The existing completion-verifier surface used before storing a receipt reference."""

    def verify_completion(self, receipt: ModelExecutionCompletionReceiptV1) -> None: ...


class SourceFreeStageCompletionBindingVerifier(Protocol):
    """Resolve and verify an opaque binding against operator-private completion evidence.

    A production implementation must recover the exact ``ModelWorkBundleV2`` and
    ``ModelExecutionCompletionReceiptV1`` identified by the binding, invoke the existing
    completion verifier, and reproduce :func:`bind_verified_stage_completion`.  Keeping this
    resolver outside the journal prevents raw receipts and private output references from being
    copied into journal files.
    """

    def verify_binding(
        self,
        coordinate: SourceFreeStageCoordinateV1,
        binding: SourceFreeStageCompletionBindingV1,
    ) -> None: ...


class SourceFreeStageCoordinateV1(ContractModel):
    """One operator-private coordinate in the canonical nine-by-three schedule."""

    schema_version: Literal["autolean.ifem-source-free-stage-coordinate.v1"] = (
        "autolean.ifem-source-free-stage-coordinate.v1"
    )
    run_id: StableIdentifierV1
    private_seed_manifest_content_sha256: str = Field(pattern=_SHA256)
    case_id: StableIdentifierV1
    role: ModelWorkRoleV1
    ordinal: int = Field(ge=1, le=27, strict=True)
    coordinate_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_coordinate(self) -> Self:
        if self.run_id.namespace != _RUN_NAMESPACE:
            raise ValueError("source-free stage coordinate uses the wrong run namespace")
        if self.case_id.namespace != _CASE_NAMESPACE:
            raise ValueError("source-free stage coordinate uses the wrong case namespace")
        if self.role not in _ROLE_ORDER:
            raise ValueError("source-free stage coordinate uses an unsupported role")
        if self.coordinate_sha256 != _sha256_json(self.content_payload()):
            raise ValueError("source-free stage coordinate hash drifted")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(
            dict[str, object],
            self.model_dump(mode="json", exclude={"coordinate_sha256"}),
        )


class SourceFreeStageCompletionBindingV1(ContractModel):
    """Opaque ModelWork/completion references; raw provider output is never retained here."""

    schema_version: Literal["autolean.ifem-source-free-stage-completion-binding.v1"] = (
        "autolean.ifem-source-free-stage-completion-binding.v1"
    )
    coordinate_sha256: str = Field(pattern=_SHA256)
    model_work_bundle_id: StableIdentifierV1
    model_work_bundle_hash: DigestV1
    completion_id: StableIdentifierV1
    completion_receipt_hash: DigestV1
    public_output_commitment: DigestV1
    binding_content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_binding(self) -> Self:
        if self.model_work_bundle_id.namespace != "model-work-bundle":
            raise ValueError("stage completion uses the wrong ModelWork bundle namespace")
        if self.completion_id.namespace != "model-execution-completion":
            raise ValueError("stage completion uses the wrong completion namespace")
        require_digest_kind(
            self.model_work_bundle_hash,
            HashKindV1.BUNDLE,
            "model_work_bundle_hash",
        )
        require_digest_kind(
            self.completion_receipt_hash,
            HashKindV1.MODEL_EXECUTION_COMPLETION,
            "completion_receipt_hash",
        )
        require_digest_kind(
            self.public_output_commitment,
            HashKindV1.MODEL_OUTPUT_COMMITMENT,
            "public_output_commitment",
        )
        if self.binding_content_sha256 != _sha256_json(self.content_payload()):
            raise ValueError("source-free stage completion binding hash drifted")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(
            dict[str, object],
            self.model_dump(mode="json", exclude={"binding_content_sha256"}),
        )


def bind_verified_stage_completion(
    coordinate: SourceFreeStageCoordinateV1,
    *,
    work_bundle: ModelWorkBundleV2,
    receipt: ModelExecutionCompletionReceiptV1,
    verifier: CompletionReceiptVerifier,
) -> SourceFreeStageCompletionBindingV1:
    """Verify and reduce one existing completion to the journal's opaque reference set."""

    stage = _revalidate_coordinate(coordinate)
    if type(work_bundle) is not ModelWorkBundleV2:
        raise SourceFreeStageLedgerError("stage completion requires the exact ModelWork type")
    if type(receipt) is not ModelExecutionCompletionReceiptV1:
        raise SourceFreeStageLedgerError("stage completion requires the exact receipt type")
    try:
        bundle = ModelWorkBundleV2.model_validate(work_bundle.model_dump(mode="json"))
        completion = ModelExecutionCompletionReceiptV1.model_validate(
            receipt.model_dump(mode="json")
        )
        verifier.verify_completion(completion)
    except Exception as error:
        raise SourceFreeStageLedgerError(
            "stage completion receipt failed independent verification"
        ) from error

    if (
        bundle.run_hash != model_work_run_hash(stage.run_id.value)
        or bundle.case_hash != model_work_case_hash(stage.case_id.value)
        or bundle.role is not stage.role
        or bundle.repetition != 1
    ):
        raise SourceFreeStageLedgerError(
            "ModelWork bundle differs from the source-free stage coordinate"
        )
    authorization = completion.record.authorization
    if (
        authorization.subject_kind is not ModelExecutionSubjectKindV1.MODEL_WORK
        or authorization.bundle_id != bundle.bundle_id
        or authorization.bundle_hash != bundle.handoff_hash()
        or authorization.contract_id != bundle.work_contract_id
        or authorization.contract_hash != bundle.semantic_hash()
        or authorization.environment_hash != bundle.role_environment_hash
        or authorization.context_pack_hash != bundle.context_pack_hash
        or authorization.request_hash != bundle.request_hash
    ):
        raise SourceFreeStageLedgerError(
            "completion authorization differs from its exact ModelWork bundle"
        )
    public = model_execution_completion_public(completion)
    payload: dict[str, object] = {
        "schema_version": "autolean.ifem-source-free-stage-completion-binding.v1",
        "coordinate_sha256": stage.coordinate_sha256,
        "model_work_bundle_id": bundle.bundle_id.model_dump(mode="json"),
        "model_work_bundle_hash": bundle.handoff_hash().model_dump(mode="json"),
        "completion_id": public.completion_id.model_dump(mode="json"),
        "completion_receipt_hash": public.receipt_hash.model_dump(mode="json"),
        "public_output_commitment": public.public_output_commitment.model_dump(mode="json"),
    }
    payload["binding_content_sha256"] = _sha256_json(payload)
    return SourceFreeStageCompletionBindingV1.model_validate(payload)


class SourceFreeStageLedgerRunV1(ContractModel):
    """Private immutable descriptor for the exact 27-coordinate run."""

    schema_version: Literal["autolean.ifem-source-free-stage-ledger-run.v1"] = (
        "autolean.ifem-source-free-stage-ledger-run.v1"
    )
    protocol: Literal["autolean.builder-ifem-source-free-stage-ledger.v1"] = (
        SOURCE_FREE_STAGE_LEDGER_PROTOCOL
    )
    run_id: StableIdentifierV1
    private_seed_manifest_content_sha256: str = Field(pattern=_SHA256)
    coordinates: tuple[SourceFreeStageCoordinateV1, ...] = Field(
        min_length=27,
        max_length=27,
    )
    role_order: tuple[ModelWorkRoleV1, ...] = _ROLE_ORDER
    case_count: Literal[9] = 9
    coordinate_count: Literal[27] = 27
    run_content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_run(self) -> Self:
        if self.run_id.namespace != _RUN_NAMESPACE:
            raise ValueError("source-free stage run uses the wrong namespace")
        if self.role_order != _ROLE_ORDER:
            raise ValueError("source-free stage run role order drifted")
        if tuple(item.ordinal for item in self.coordinates) != tuple(range(1, 28)):
            raise ValueError("source-free stage ordinals must be canonical")
        cases = tuple(dict.fromkeys(item.case_id for item in self.coordinates))
        if len(cases) != 9:
            raise ValueError("source-free stage run requires exactly nine cases")
        expected = tuple((case_id, role) for case_id in cases for role in _ROLE_ORDER)
        actual = tuple((item.case_id, item.role) for item in self.coordinates)
        if actual != expected:
            raise ValueError("source-free stage coordinates must follow fixed role order")
        if any(
            item.run_id != self.run_id
            or item.private_seed_manifest_content_sha256
            != self.private_seed_manifest_content_sha256
            for item in self.coordinates
        ):
            raise ValueError("source-free stage coordinate differs from its run")
        if self.run_content_sha256 != _sha256_json(self.content_payload()):
            raise ValueError("source-free stage run hash drifted")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(
            dict[str, object],
            self.model_dump(mode="json", exclude={"run_content_sha256"}),
        )

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.model_dump(mode="json")) + b"\n"


class SourceFreeStageLedgerEventV1(ContractModel):
    """One immutable state transition for a private coordinate."""

    schema_version: Literal["autolean.ifem-source-free-stage-ledger-event.v1"] = (
        "autolean.ifem-source-free-stage-ledger-event.v1"
    )
    state: Literal[
        SourceFreeStageLedgerStateV1.CLAIMED,
        SourceFreeStageLedgerStateV1.DISPATCH_STARTED,
        SourceFreeStageLedgerStateV1.COMPLETION_COMMITTED,
        SourceFreeStageLedgerStateV1.RECONCILIATION_REQUIRED,
    ]
    coordinate: SourceFreeStageCoordinateV1
    completion: SourceFreeStageCompletionBindingV1 | None = None
    reconciliation_reason: (
        Literal[
            "incomplete_dispatch_observed",
            "executor_outcome_unknown",
            "completion_binding_invalid",
        ]
        | None
    ) = None
    event_content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_event(self) -> Self:
        if self.state is SourceFreeStageLedgerStateV1.COMPLETION_COMMITTED:
            if (
                self.completion is None
                or self.completion.coordinate_sha256 != self.coordinate.coordinate_sha256
                or self.reconciliation_reason is not None
            ):
                raise ValueError("completion event has an inconsistent binding")
        elif self.state is SourceFreeStageLedgerStateV1.RECONCILIATION_REQUIRED:
            if self.completion is not None or self.reconciliation_reason is None:
                raise ValueError("reconciliation event has inconsistent evidence")
        elif self.completion is not None or self.reconciliation_reason is not None:
            raise ValueError("pre-completion event contains terminal evidence")
        if self.event_content_sha256 != _sha256_json(self.content_payload()):
            raise ValueError("source-free stage ledger event hash drifted")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(
            dict[str, object],
            self.model_dump(mode="json", exclude={"event_content_sha256"}),
        )

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.model_dump(mode="json")) + b"\n"


class SourceFreeStageLedgerPublicProjectionV1(ContractModel):
    """Aggregate-only public view of the private 27-stage journal."""

    schema_version: Literal["autolean.ifem-source-free-stage-ledger-public-projection.v1"] = (
        "autolean.ifem-source-free-stage-ledger-public-projection.v1"
    )
    protocol: Literal["autolean.builder-ifem-source-free-stage-ledger.v1"] = (
        SOURCE_FREE_STAGE_LEDGER_PROTOCOL
    )
    artifact_kind: Literal["source_free_stage_ledger_aggregate"] = (
        "source_free_stage_ledger_aggregate"
    )
    private_seed_manifest_content_sha256: str = Field(pattern=_SHA256)
    private_run_content_sha256: str = Field(pattern=_SHA256)
    private_ledger_commitment_sha256: str = Field(pattern=_SHA256)
    coordinate_count: Literal[27] = 27
    pending_count: int = Field(ge=0, le=27, strict=True)
    claimed_count: int = Field(ge=0, le=27, strict=True)
    dispatch_started_count: int = Field(ge=0, le=27, strict=True)
    completion_committed_count: int = Field(ge=0, le=27, strict=True)
    reconciliation_required_count: int = Field(ge=0, le=27, strict=True)
    immutable_event_count: int = Field(ge=0, le=108, strict=True)
    executor_dispatch_count: int = Field(ge=0, le=27, strict=True)
    complete: bool = Field(strict=True)
    case_ids_disclosed: Literal[False] = False
    role_coordinates_disclosed: Literal[False] = False
    completion_ids_disclosed: Literal[False] = False
    raw_model_output_retained: Literal[False] = False
    automatic_dispatch_replay_allowed: Literal[False] = False
    provider_dispatch_performed_by_ledger: Literal[False] = False
    completion_verification_attested: Literal[False] = False
    live_model_eligible: Literal[False] = False
    heldout_worker_isolation_claimed: Literal[False] = False
    authority: SourceFreeCaseAuthoringAuthorityV1 = Field(
        default_factory=SourceFreeCaseAuthoringAuthorityV1
    )
    builder_freeze: Literal["forbidden"] = "forbidden"
    prover_handoff: Literal["forbidden"] = "forbidden"
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_projection(self) -> Self:
        total = (
            self.pending_count
            + self.claimed_count
            + self.dispatch_started_count
            + self.completion_committed_count
            + self.reconciliation_required_count
        )
        if total != 27:
            raise ValueError("source-free stage aggregate must account for 27 coordinates")
        if self.executor_dispatch_count != (
            self.dispatch_started_count
            + self.completion_committed_count
            + self.reconciliation_required_count
        ):
            raise ValueError("source-free stage dispatch aggregate is inconsistent")
        if self.complete is not (
            self.completion_committed_count == 27 and self.reconciliation_required_count == 0
        ):
            raise ValueError("source-free stage completion aggregate is inconsistent")
        if self.authority != SourceFreeCaseAuthoringAuthorityV1():
            raise ValueError("source-free stage aggregate authority drifted")
        if self.content_sha256 != _sha256_json(self.content_payload()):
            raise ValueError("source-free stage aggregate hash drifted")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(
            dict[str, object],
            self.model_dump(mode="json", exclude={"content_sha256"}),
        )

    def assert_not_authoritative(self) -> Never:
        raise SourceFreeStageLedgerError(
            "source-free stage ledger cannot classify, freeze, or hand work to Prover"
        )

    def freeze_statement(self) -> Never:
        self.assert_not_authoritative()

    def handoff_to_prover(self) -> Never:
        self.assert_not_authoritative()


@dataclass(frozen=True)
class _CoordinateState:
    state: SourceFreeStageLedgerStateV1
    events: tuple[SourceFreeStageLedgerEventV1, ...]


class LocalSourceFreeStageLedger:
    """Write-once local execution journal rooted outside every Git checkout."""

    def __init__(
        self,
        root: Path,
        *,
        repository_root: Path,
        seed_store: LocalSourceFreePrivateSeedStore,
        intent_queue: IFEMNextCalibrationCaseIntentsV1,
        completion_binding_verifier: SourceFreeStageCompletionBindingVerifier,
    ) -> None:
        if not callable(getattr(completion_binding_verifier, "verify_binding", None)):
            raise SourceFreeStageLedgerError(
                "stage ledger requires an operator-private completion binding verifier"
            )
        self._repository_root = _validated_repository_root(repository_root)
        self._root = _prepare_private_root(root, repository_root=self._repository_root)
        if type(seed_store) is not LocalSourceFreePrivateSeedStore:
            raise SourceFreeStageLedgerError(
                "stage ledger requires the exact persisted private seed store"
            )
        try:
            manifest = seed_store.load()
            verify_private_seed_manifest_against_queue(manifest, intent_queue)
        except (SourceFreePrivateSeedError, TypeError, ValueError) as error:
            raise SourceFreeStageLedgerError(
                "stage ledger private seed is not persisted and replayable"
            ) from error
        self._manifest = _revalidate_manifest(manifest)
        self._completion_binding_verifier = completion_binding_verifier
        self._run = _build_run(self._manifest)
        self._run_root = self._root / "runs" / self._manifest.manifest_content_sha256
        self._journal_root = self._run_root / "journal"
        _prepare_directory(self._run_root, root=self._root)
        _prepare_directory(self._journal_root, root=self._root)
        self._run_path = self._run_root / "run.json"
        _write_private_once(self._run_path, self._run.canonical_bytes(), root=self._root)
        self._read_run()

    @property
    def run(self) -> SourceFreeStageLedgerRunV1:
        return self._run

    @property
    def run_root(self) -> Path:
        return self._run_root

    def resume(
        self,
        executor: Callable[
            [SourceFreeStageCoordinateV1, PrivateSourceFreeSeedItemV2],
            SourceFreeStageCompletionBindingV1,
        ],
    ) -> SourceFreeStageLedgerPublicProjectionV1:
        """Advance safe coordinates once and leave existing dispatches untouched."""

        if not callable(executor):
            raise SourceFreeStageLedgerError("source-free stage executor must be callable")
        for coordinate in self._run.coordinates:
            self._advance_coordinate(coordinate, executor)
        return self.public_projection()

    def execute_coordinate(
        self,
        coordinate: SourceFreeStageCoordinateV1,
        executor: Callable[
            [SourceFreeStageCoordinateV1, PrivateSourceFreeSeedItemV2],
            SourceFreeStageCompletionBindingV1,
        ],
    ) -> SourceFreeStageLedgerPublicProjectionV1:
        """Advance exactly one ledger-owned coordinate through the normal dispatch protocol.

        This is the narrow canary entry point.  It deliberately does not scan, classify, or
        advance any other coordinate.  A blocked predecessor, a durable in-flight dispatch, or
        a reconciliation state remains untouched just as it would during :meth:`resume`.
        """

        if not callable(executor):
            raise SourceFreeStageLedgerError("source-free stage executor must be callable")
        self._advance_coordinate(self._require_coordinate(coordinate), executor)
        return self.public_projection()

    def _advance_coordinate(
        self,
        coordinate: SourceFreeStageCoordinateV1,
        executor: Callable[
            [SourceFreeStageCoordinateV1, PrivateSourceFreeSeedItemV2],
            SourceFreeStageCompletionBindingV1,
        ],
    ) -> None:
        """Apply the one-coordinate state machine shared by full resume and a canary."""

        stage = self._require_coordinate(coordinate)
        predecessor = self._predecessor_for(stage)
        if predecessor is not None and self._read_state(predecessor).state is not (
            SourceFreeStageLedgerStateV1.COMPLETION_COMMITTED
        ):
            return
        state = self._read_state(stage)
        if state.state in {
            SourceFreeStageLedgerStateV1.COMPLETION_COMMITTED,
            SourceFreeStageLedgerStateV1.RECONCILIATION_REQUIRED,
            SourceFreeStageLedgerStateV1.DISPATCH_STARTED,
        }:
            # A second process may be observing a live executor.  It must neither replay nor
            # reclassify its durable dispatch; explicit reconciliation remains the only path.
            return
        if state.state is SourceFreeStageLedgerStateV1.PENDING:
            self._append_event(
                stage,
                state=SourceFreeStageLedgerStateV1.CLAIMED,
            )
            self._checkpoint("claim_committed", stage)

        won_dispatch = self._append_event(
            stage,
            state=SourceFreeStageLedgerStateV1.DISPATCH_STARTED,
            require_new=True,
        )
        if not won_dispatch:
            # Another process won the durable transition and is the only one allowed to execute.
            return
        self._checkpoint("dispatch_committed", stage)
        item_by_case = {item.case_id: item for item in self._manifest.items}
        try:
            completion = executor(stage, item_by_case[stage.case_id])
        except Exception:
            self._append_event(
                stage,
                state=SourceFreeStageLedgerStateV1.RECONCILIATION_REQUIRED,
                reconciliation_reason="executor_outcome_unknown",
            )
            return
        try:
            validated_completion = self._verify_completion_binding(
                completion,
                coordinate=stage,
            )
        except SourceFreeStageLedgerError:
            self._append_event(
                stage,
                state=SourceFreeStageLedgerStateV1.RECONCILIATION_REQUIRED,
                reconciliation_reason="completion_binding_invalid",
            )
            return
        self._checkpoint("executor_returned", stage)
        self._append_event(
            stage,
            state=SourceFreeStageLedgerStateV1.COMPLETION_COMMITTED,
            completion=validated_completion,
        )
        self._checkpoint("completion_committed", stage)

    def mark_interrupted_dispatches_for_reconciliation(
        self,
        *,
        operator_confirmed_quiescent: Literal[True],
    ) -> SourceFreeStageLedgerPublicProjectionV1:
        """Persist unknown outcomes only after the operator confirms no executor is active."""

        if operator_confirmed_quiescent is not True:
            raise SourceFreeStageLedgerError(
                "reconciliation requires explicit operator quiescence confirmation"
            )
        for coordinate in self._run.coordinates:
            state = self._read_state(coordinate)
            if state.state is SourceFreeStageLedgerStateV1.DISPATCH_STARTED:
                self._append_event(
                    coordinate,
                    state=SourceFreeStageLedgerStateV1.RECONCILIATION_REQUIRED,
                    reconciliation_reason="incomplete_dispatch_observed",
                )
        return self.public_projection()

    def reconcile_completion(
        self,
        coordinate: SourceFreeStageCoordinateV1,
        completion: SourceFreeStageCompletionBindingV1,
    ) -> SourceFreeStageLedgerPublicProjectionV1:
        """Attach an externally recovered completion without invoking an executor."""

        stage = self._require_coordinate(coordinate)
        binding = self._verify_completion_binding(completion, coordinate=stage)
        state = self._read_state(stage)
        if state.state is SourceFreeStageLedgerStateV1.COMPLETION_COMMITTED:
            existing = next(
                event.completion
                for event in state.events
                if event.state is SourceFreeStageLedgerStateV1.COMPLETION_COMMITTED
            )
            if existing != binding:
                raise SourceFreeStageReconciliationRequired(
                    "completion reconciliation conflicts with the immutable terminal binding"
                )
            return self.public_projection()
        if state.state not in {
            SourceFreeStageLedgerStateV1.DISPATCH_STARTED,
            SourceFreeStageLedgerStateV1.RECONCILIATION_REQUIRED,
        }:
            raise SourceFreeStageReconciliationRequired(
                "completion cannot be reconciled before the single dispatch transition"
            )
        self._append_event(
            stage,
            state=SourceFreeStageLedgerStateV1.COMPLETION_COMMITTED,
            completion=binding,
        )
        return self.public_projection()

    def _verify_completion_binding(
        self,
        completion: SourceFreeStageCompletionBindingV1,
        *,
        coordinate: SourceFreeStageCoordinateV1,
    ) -> SourceFreeStageCompletionBindingV1:
        binding = _revalidate_completion(completion, coordinate=coordinate)
        try:
            self._completion_binding_verifier.verify_binding(coordinate, binding)
        except Exception as error:
            raise SourceFreeStageLedgerError(
                "stage completion binding failed operator-private verification"
            ) from error
        return binding

    def state_for(
        self,
        coordinate: SourceFreeStageCoordinateV1,
    ) -> SourceFreeStageLedgerStateV1:
        return self._read_state(self._require_coordinate(coordinate)).state

    def public_projection(self) -> SourceFreeStageLedgerPublicProjectionV1:
        """Return aggregate counts and one commitment after canonical private readback."""

        self._read_run()
        states = tuple(self._read_state(item) for item in self._run.coordinates)
        counts = Counter(item.state for item in states)
        event_hashes = tuple(
            event.event_content_sha256 for state in states for event in state.events
        )
        commitment = _sha256_json(
            {
                "schema_version": "autolean.ifem-source-free-stage-ledger-commitment.v1",
                "private_run_content_sha256": self._run.run_content_sha256,
                "event_content_sha256": event_hashes,
            }
        )
        dispatch_count = sum(
            1
            for state in states
            if state.state
            in {
                SourceFreeStageLedgerStateV1.DISPATCH_STARTED,
                SourceFreeStageLedgerStateV1.COMPLETION_COMMITTED,
                SourceFreeStageLedgerStateV1.RECONCILIATION_REQUIRED,
            }
        )
        completion_count = counts[SourceFreeStageLedgerStateV1.COMPLETION_COMMITTED]
        reconciliation_count = counts[SourceFreeStageLedgerStateV1.RECONCILIATION_REQUIRED]
        payload: dict[str, object] = {
            "schema_version": ("autolean.ifem-source-free-stage-ledger-public-projection.v1"),
            "protocol": SOURCE_FREE_STAGE_LEDGER_PROTOCOL,
            "artifact_kind": "source_free_stage_ledger_aggregate",
            "private_seed_manifest_content_sha256": (self._manifest.manifest_content_sha256),
            "private_run_content_sha256": self._run.run_content_sha256,
            "private_ledger_commitment_sha256": commitment,
            "coordinate_count": 27,
            "pending_count": counts[SourceFreeStageLedgerStateV1.PENDING],
            "claimed_count": counts[SourceFreeStageLedgerStateV1.CLAIMED],
            "dispatch_started_count": counts[SourceFreeStageLedgerStateV1.DISPATCH_STARTED],
            "completion_committed_count": completion_count,
            "reconciliation_required_count": reconciliation_count,
            "immutable_event_count": len(event_hashes),
            "executor_dispatch_count": dispatch_count,
            "complete": completion_count == 27 and reconciliation_count == 0,
            "case_ids_disclosed": False,
            "role_coordinates_disclosed": False,
            "completion_ids_disclosed": False,
            "raw_model_output_retained": False,
            "automatic_dispatch_replay_allowed": False,
            "provider_dispatch_performed_by_ledger": False,
            "completion_verification_attested": False,
            "live_model_eligible": False,
            "heldout_worker_isolation_claimed": False,
            "authority": SourceFreeCaseAuthoringAuthorityV1().model_dump(mode="json"),
            "builder_freeze": "forbidden",
            "prover_handoff": "forbidden",
        }
        payload["content_sha256"] = _sha256_json(payload)
        return SourceFreeStageLedgerPublicProjectionV1.model_validate(payload)

    def _checkpoint(self, _name: str, _coordinate: SourceFreeStageCoordinateV1) -> None:
        """Internal test seam for process-crash simulation; production does nothing."""

    def _append_event(
        self,
        coordinate: SourceFreeStageCoordinateV1,
        *,
        state: Literal[
            SourceFreeStageLedgerStateV1.CLAIMED,
            SourceFreeStageLedgerStateV1.DISPATCH_STARTED,
            SourceFreeStageLedgerStateV1.COMPLETION_COMMITTED,
            SourceFreeStageLedgerStateV1.RECONCILIATION_REQUIRED,
        ],
        completion: SourceFreeStageCompletionBindingV1 | None = None,
        reconciliation_reason: Literal[
            "incomplete_dispatch_observed",
            "executor_outcome_unknown",
            "completion_binding_invalid",
        ]
        | None = None,
        require_new: bool = False,
    ) -> bool:
        stage = self._require_coordinate(coordinate)
        payload: dict[str, object] = {
            "schema_version": "autolean.ifem-source-free-stage-ledger-event.v1",
            "state": state.value,
            "coordinate": stage.model_dump(mode="json"),
            "completion": (None if completion is None else completion.model_dump(mode="json")),
            "reconciliation_reason": reconciliation_reason,
        }
        payload["event_content_sha256"] = _sha256_json(payload)
        try:
            event = SourceFreeStageLedgerEventV1.model_validate(payload)
        except ValueError as error:
            raise SourceFreeStageLedgerError("source-free stage event is invalid") from error
        path = self._event_path(stage, state)
        created = _write_private_once(
            path,
            event.canonical_bytes(),
            root=self._root,
            require_new=require_new,
        )
        self._read_event(path, coordinate=stage, state=state)
        return created

    def _read_state(self, coordinate: SourceFreeStageCoordinateV1) -> _CoordinateState:
        stage = self._require_coordinate(coordinate)
        events: list[SourceFreeStageLedgerEventV1] = []
        by_state: dict[SourceFreeStageLedgerStateV1, SourceFreeStageLedgerEventV1] = {}
        for state in (
            SourceFreeStageLedgerStateV1.CLAIMED,
            SourceFreeStageLedgerStateV1.DISPATCH_STARTED,
            SourceFreeStageLedgerStateV1.RECONCILIATION_REQUIRED,
            SourceFreeStageLedgerStateV1.COMPLETION_COMMITTED,
        ):
            path = self._event_path(stage, state)
            if not path.exists():
                continue
            event = self._read_event(path, coordinate=stage, state=state)
            by_state[state] = event
            events.append(event)
        claimed = SourceFreeStageLedgerStateV1.CLAIMED in by_state
        dispatched = SourceFreeStageLedgerStateV1.DISPATCH_STARTED in by_state
        reconciled = SourceFreeStageLedgerStateV1.RECONCILIATION_REQUIRED in by_state
        completed = SourceFreeStageLedgerStateV1.COMPLETION_COMMITTED in by_state
        if not claimed and (dispatched or reconciled or completed):
            raise SourceFreeStageReconciliationRequired(
                "source-free stage transition history lacks its claim"
            )
        if not dispatched and (reconciled or completed):
            raise SourceFreeStageReconciliationRequired(
                "source-free stage terminal history lacks its dispatch"
            )
        effective = SourceFreeStageLedgerStateV1.PENDING
        if claimed:
            effective = SourceFreeStageLedgerStateV1.CLAIMED
        if dispatched:
            effective = SourceFreeStageLedgerStateV1.DISPATCH_STARTED
        if reconciled:
            effective = SourceFreeStageLedgerStateV1.RECONCILIATION_REQUIRED
        if completed:
            effective = SourceFreeStageLedgerStateV1.COMPLETION_COMMITTED
        return _CoordinateState(state=effective, events=tuple(events))

    def _read_event(
        self,
        path: Path,
        *,
        coordinate: SourceFreeStageCoordinateV1,
        state: SourceFreeStageLedgerStateV1,
    ) -> SourceFreeStageLedgerEventV1:
        _require_private_target(path, root=self._root)
        try:
            raw = path.read_bytes()
            event = SourceFreeStageLedgerEventV1.model_validate_json(raw)
        except (OSError, ValueError) as error:
            raise SourceFreeStageReconciliationRequired(
                "source-free stage event is unavailable or invalid"
            ) from error
        if (
            event.canonical_bytes() != raw
            or event.coordinate != coordinate
            or event.state is not state
        ):
            raise SourceFreeStageReconciliationRequired(
                "source-free stage event differs from its immutable coordinate"
            )
        return event

    def _read_run(self) -> SourceFreeStageLedgerRunV1:
        _require_private_target(self._run_path, root=self._root)
        try:
            raw = self._run_path.read_bytes()
            run = SourceFreeStageLedgerRunV1.model_validate_json(raw)
        except (OSError, ValueError) as error:
            raise SourceFreeStageReconciliationRequired(
                "source-free private run descriptor is unavailable or invalid"
            ) from error
        if run.canonical_bytes() != raw or run != self._run:
            raise SourceFreeStageReconciliationRequired(
                "source-free private run descriptor conflicts with the seed manifest"
            )
        return run

    def _event_path(
        self,
        coordinate: SourceFreeStageCoordinateV1,
        state: SourceFreeStageLedgerStateV1,
    ) -> Path:
        ordinal = {
            SourceFreeStageLedgerStateV1.CLAIMED: "01-claimed.json",
            SourceFreeStageLedgerStateV1.DISPATCH_STARTED: "02-dispatch-started.json",
            SourceFreeStageLedgerStateV1.RECONCILIATION_REQUIRED: (
                "03-reconciliation-required.json"
            ),
            SourceFreeStageLedgerStateV1.COMPLETION_COMMITTED: ("04-completion-committed.json"),
        }.get(state)
        if ordinal is None:
            raise SourceFreeStageLedgerError("pending has no persistent event file")
        coordinate_root = self._journal_root / coordinate.coordinate_sha256
        _prepare_directory(coordinate_root, root=self._root)
        return _require_private_target(coordinate_root / ordinal, root=self._root)

    def _require_coordinate(
        self,
        coordinate: SourceFreeStageCoordinateV1,
    ) -> SourceFreeStageCoordinateV1:
        stage = _revalidate_coordinate(coordinate)
        matching = tuple(
            item
            for item in self._run.coordinates
            if item.coordinate_sha256 == stage.coordinate_sha256
        )
        if len(matching) != 1 or matching[0] != stage:
            raise SourceFreeStageLedgerError(
                "source-free stage coordinate is not an exact member of this run"
            )
        return stage

    def _predecessor_for(
        self,
        coordinate: SourceFreeStageCoordinateV1,
    ) -> SourceFreeStageCoordinateV1 | None:
        stage = self._require_coordinate(coordinate)
        if stage.role is ModelWorkRoleV1.STATEMENT_FORMALIZER:
            return None
        predecessor = self._run.coordinates[stage.ordinal - 2]
        if predecessor.case_id != stage.case_id:
            raise SourceFreeStageLedgerError(
                "source-free stage predecessor crossed its private case boundary"
            )
        expected_role = (
            ModelWorkRoleV1.STATEMENT_FORMALIZER
            if stage.role is ModelWorkRoleV1.FIDELITY_REVIEWER
            else ModelWorkRoleV1.FIDELITY_REVIEWER
        )
        if predecessor.role is not expected_role:
            raise SourceFreeStageLedgerError("source-free stage predecessor role drifted")
        return predecessor


def render_stage_ledger_public_projection(
    projection: SourceFreeStageLedgerPublicProjectionV1,
) -> bytes:
    if type(projection) is not SourceFreeStageLedgerPublicProjectionV1:
        raise SourceFreeStageLedgerError("stage ledger projection requires its exact type")
    try:
        value = SourceFreeStageLedgerPublicProjectionV1.model_validate(
            projection.model_dump(mode="json")
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise SourceFreeStageLedgerError("stage ledger projection failed revalidation") from error
    rendered = canonical_json_bytes(value.model_dump(mode="json")) + b"\n"
    if any(field in rendered for field in _FORBIDDEN_PUBLIC_FIELDS):
        raise SourceFreeStageLedgerError("stage ledger projection leaked a private field")
    return rendered


def _build_run(manifest: PrivateSourceFreeSeedManifestV2) -> SourceFreeStageLedgerRunV1:
    coordinates: list[SourceFreeStageCoordinateV1] = []
    ordinal = 0
    for item in manifest.items:
        for role in _ROLE_ORDER:
            ordinal += 1
            coordinate_payload: dict[str, object] = {
                "schema_version": "autolean.ifem-source-free-stage-coordinate.v1",
                "run_id": manifest.run_id.model_dump(mode="json"),
                "private_seed_manifest_content_sha256": manifest.manifest_content_sha256,
                "case_id": item.case_id.model_dump(mode="json"),
                "role": role.value,
                "ordinal": ordinal,
            }
            coordinate_payload["coordinate_sha256"] = _sha256_json(coordinate_payload)
            coordinates.append(SourceFreeStageCoordinateV1.model_validate(coordinate_payload))
    payload: dict[str, object] = {
        "schema_version": "autolean.ifem-source-free-stage-ledger-run.v1",
        "protocol": SOURCE_FREE_STAGE_LEDGER_PROTOCOL,
        "run_id": manifest.run_id.model_dump(mode="json"),
        "private_seed_manifest_content_sha256": manifest.manifest_content_sha256,
        "coordinates": [item.model_dump(mode="json") for item in coordinates],
        "role_order": [role.value for role in _ROLE_ORDER],
        "case_count": 9,
        "coordinate_count": 27,
    }
    payload["run_content_sha256"] = _sha256_json(payload)
    return SourceFreeStageLedgerRunV1.model_validate(payload)


def _revalidate_manifest(
    manifest: PrivateSourceFreeSeedManifestV2,
) -> PrivateSourceFreeSeedManifestV2:
    if type(manifest) is not PrivateSourceFreeSeedManifestV2:
        raise SourceFreeStageLedgerError("stage ledger requires the exact private seed type")
    try:
        value = PrivateSourceFreeSeedManifestV2.model_validate(manifest.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as error:
        raise SourceFreeStageLedgerError("private seed manifest failed revalidation") from error
    if len(value.items) != 9 or value.model_work_created:
        raise SourceFreeStageLedgerError("private seed manifest crossed the stage-ledger boundary")
    return value


def _revalidate_coordinate(
    coordinate: SourceFreeStageCoordinateV1,
) -> SourceFreeStageCoordinateV1:
    if type(coordinate) is not SourceFreeStageCoordinateV1:
        raise SourceFreeStageLedgerError("stage coordinate requires its exact type")
    try:
        return SourceFreeStageCoordinateV1.model_validate(coordinate.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as error:
        raise SourceFreeStageLedgerError("stage coordinate failed revalidation") from error


def _revalidate_completion(
    completion: SourceFreeStageCompletionBindingV1,
    *,
    coordinate: SourceFreeStageCoordinateV1,
) -> SourceFreeStageCompletionBindingV1:
    if type(completion) is not SourceFreeStageCompletionBindingV1:
        raise SourceFreeStageLedgerError("stage completion requires its exact binding type")
    try:
        value = SourceFreeStageCompletionBindingV1.model_validate(
            completion.model_dump(mode="json")
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise SourceFreeStageLedgerError("stage completion binding failed revalidation") from error
    if value.coordinate_sha256 != coordinate.coordinate_sha256:
        raise SourceFreeStageLedgerError("stage completion belongs to a different coordinate")
    return value


def _sha256_json(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _validated_repository_root(root: Path) -> Path:
    if not isinstance(root, Path) or not root.is_absolute():
        raise SourceFreeStageLedgerError("repository root must be an absolute Path")
    resolved = root.resolve(strict=True)
    if not (resolved / ".git").exists():
        raise SourceFreeStageLedgerError("repository root must contain .git")
    return resolved


def _reject_link_or_reparse(path: Path, *, label: str) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if path.is_symlink() or (
        int(getattr(metadata, "st_file_attributes", 0)) & _FILE_ATTRIBUTE_REPARSE_POINT
    ):
        raise SourceFreeStageLedgerError(
            f"{label} must not be a symlink, junction, or reparse point"
        )


def _prepare_private_root(root: Path, *, repository_root: Path) -> Path:
    if not isinstance(root, Path) or not root.is_absolute():
        raise SourceFreeStageLedgerError("stage ledger root must be an absolute Path")
    unresolved = root.absolute()
    if unresolved == repository_root or repository_root in unresolved.parents:
        raise SourceFreeStageLedgerError("stage ledger root must be outside the repository")
    for candidate in (unresolved, *unresolved.parents):
        _reject_link_or_reparse(candidate, label="stage ledger root ancestry")
        if (candidate / ".git").exists():
            raise SourceFreeStageLedgerError("stage ledger root must be outside every Git checkout")
    root.mkdir(parents=True, exist_ok=True)
    _reject_link_or_reparse(root, label="stage ledger root")
    resolved = root.resolve(strict=True)
    if resolved == repository_root or repository_root in resolved.parents:
        raise SourceFreeStageLedgerError("stage ledger root resolved inside the repository")
    return resolved


def _prepare_directory(path: Path, *, root: Path) -> Path:
    if not isinstance(path, Path):
        raise SourceFreeStageLedgerError("stage ledger path must be a Path")
    unresolved = path.absolute()
    if unresolved != root and root not in unresolved.parents:
        raise SourceFreeStageLedgerError("stage ledger path escaped its private root")
    relative = unresolved.relative_to(root)
    current = root
    for part in relative.parts:
        current = current / part
        _reject_link_or_reparse(current, label="stage ledger directory")
        current.mkdir(exist_ok=True)
        _reject_link_or_reparse(current, label="stage ledger directory")
    resolved = path.resolve(strict=True)
    if resolved != root and root not in resolved.parents:
        raise SourceFreeStageLedgerError("stage ledger directory resolved outside its root")
    return resolved


def _require_private_target(path: Path, *, root: Path) -> Path:
    if not isinstance(path, Path):
        raise SourceFreeStageLedgerError("stage ledger target must be a Path")
    parent = _prepare_directory(path.parent, root=root)
    _reject_link_or_reparse(path, label="stage ledger private file")
    if parent != root and root not in parent.parents:
        raise SourceFreeStageLedgerError("stage ledger private file escaped its root")
    return path


def _write_private_once(
    path: Path,
    payload: bytes,
    *,
    root: Path,
    require_new: bool = False,
) -> bool:
    target = _require_private_target(path, root=root)
    temporary = target.parent / f".stage-ledger-{uuid.uuid4().hex}.tmp"
    descriptor: int | None = None
    created = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        descriptor = os.open(temporary, flags, 0o600)
        handle = os.fdopen(descriptor, "wb", closefd=True)
        descriptor = None
        with handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, target)
            created = True
        except FileExistsError:
            created = False
        except OSError as error:
            raise SourceFreeStageLedgerError(
                "could not atomically persist the source-free stage ledger"
            ) from error
        try:
            retained = target.read_bytes()
        except OSError as error:
            raise SourceFreeStageReconciliationRequired(
                "source-free stage ledger write cannot be read back"
            ) from error
        if retained != payload:
            raise SourceFreeStageReconciliationRequired(
                "source-free stage ledger write conflicts with retained bytes"
            )
        if require_new and not created:
            return False
        return created
    finally:
        if descriptor is not None:
            os.close(descriptor)
        with suppress(OSError):
            temporary.unlink()


__all__ = [
    "SOURCE_FREE_STAGE_LEDGER_PROTOCOL",
    "SOURCE_FREE_STAGE_LEDGER_SCHEMA",
    "CompletionReceiptVerifier",
    "LocalSourceFreeStageLedger",
    "SourceFreeStageCompletionBindingV1",
    "SourceFreeStageCompletionBindingVerifier",
    "SourceFreeStageCoordinateV1",
    "SourceFreeStageLedgerError",
    "SourceFreeStageLedgerPublicProjectionV1",
    "SourceFreeStageLedgerRunV1",
    "SourceFreeStageLedgerStateV1",
    "SourceFreeStageReconciliationRequired",
    "bind_verified_stage_completion",
    "render_stage_ledger_public_projection",
]
