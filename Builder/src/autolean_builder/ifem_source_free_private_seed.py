"""Operator-private seed manifest for source-free iFEM authoring.

This protocol is deliberately narrower than model execution.  It commits a
private, CSPRNG-derived 3/3/3 case manifest before exposing a redacted public
commitment.  It does not call a provider, create ModelWork, claim worker
isolation, classify mathematics, freeze a statement, or hand work to Prover.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import uuid
from collections import Counter
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import Final, Literal, Never, Self, cast

from autolean_contracts import (
    PairSplitPartitionV1,
    StableIdentifierV1,
    canonical_json_bytes,
    stable_identifier,
)
from autolean_contracts.base import ContractModel
from pydantic import Field, model_validator

from .ifem_calibration_risk_routing import (
    IFEMCalibrationPriorityV1,
    IFEMRequiredNextCalibrationV1,
)
from .ifem_next_calibration_case_intents import (
    IFEMNextCalibrationCaseIntentsV1,
)
from .ifem_source_free_case_authoring import (
    SourceFreeCaseAuthoringAuthorityV1,
    SourceFreeHiddenOracleV1,
    SourceFreeSignatureV1,
)

PRIVATE_SEED_SCHEMA: Final[Literal["autolean.ifem-source-free-private-seed.v2"]] = (
    "autolean.ifem-source-free-private-seed.v2"
)
PRIVATE_SEED_PROTOCOL: Final[Literal["autolean.builder-ifem-source-free-private-seed.v2"]] = (
    "autolean.builder-ifem-source-free-private-seed.v2"
)
_RUN_NAMESPACE: Final[Literal["ifem-source-free-private-seed-run"]] = (
    "ifem-source-free-private-seed-run"
)
_CASE_NAMESPACE: Final[Literal["ifem-source-free-private-seed-case"]] = (
    "ifem-source-free-private-seed-case"
)
_SHA256 = r"^[0-9a-f]{64}$"
_RUN_LABEL = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_NONCE_BYTES = 32
_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
_PARTITION_ORDER: Final[tuple[PairSplitPartitionV1, ...]] = (
    PairSplitPartitionV1.TRAIN,
    PairSplitPartitionV1.DEV,
    PairSplitPartitionV1.PRIVATE_HELDOUT,
)
_FORBIDDEN_PUBLIC_FIELDS: Final[tuple[bytes, ...]] = (
    b'"baseline"',
    b'"case_id"',
    b'"expected_candidate"',
    b'"hidden_oracle"',
    b'"increment"',
    b'"intent_id"',
    b'"node_id"',
    b'"partition"',
    b'"run_nonce_hex"',
    b'"selector"',
)


class SourceFreePrivateSeedError(ValueError):
    """The private seed protocol or storage boundary was violated."""


class PrivateSourceFreeSeedItemV2(ContractModel):
    """One private source-free case; never render this through a public API."""

    schema_version: Literal["autolean.ifem-source-free-private-seed-item.v2"] = (
        "autolean.ifem-source-free-private-seed-item.v2"
    )
    case_id: StableIdentifierV1
    intent_id: StableIdentifierV1
    node_id: str = Field(pattern=r"^ifem-[a-z0-9-]+$")
    partition: PairSplitPartitionV1
    baseline: SourceFreeSignatureV1
    selector: int = Field(ge=0, le=2, strict=True)
    increment: int = Field(ge=1, le=3, strict=True)
    hidden_oracle: SourceFreeHiddenOracleV1
    source_free: Literal[True] = True
    textbook_derived: Literal[False] = False
    authority: SourceFreeCaseAuthoringAuthorityV1 = Field(
        default_factory=SourceFreeCaseAuthoringAuthorityV1
    )
    item_content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_item(self) -> Self:
        if self.case_id.namespace != _CASE_NAMESPACE:
            raise ValueError("private source-free case uses the wrong identifier namespace")
        if self.hidden_oracle.selected_slot != self.selector:
            raise ValueError("private source-free oracle selector drifted")
        if self.hidden_oracle.expected_candidate != _expected_candidate(
            self.baseline,
            selector=self.selector,
            increment=self.increment,
        ):
            raise ValueError("private source-free oracle candidate drifted")
        if self.authority != SourceFreeCaseAuthoringAuthorityV1():
            raise ValueError("private source-free case authority drifted")
        if self.item_content_sha256 != _sha256_json(self.content_payload()):
            raise ValueError("private source-free case hash drifted")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(
            dict[str, object],
            self.model_dump(mode="json", exclude={"item_content_sha256"}),
        )


class PrivateSourceFreeSeedManifestV2(ContractModel):
    """Canonical operator-private manifest committed before public projection."""

    schema_version: Literal["autolean.ifem-source-free-private-seed.v2"] = PRIVATE_SEED_SCHEMA
    protocol: Literal["autolean.builder-ifem-source-free-private-seed.v2"] = PRIVATE_SEED_PROTOCOL
    artifact_kind: Literal["operator_private_source_free_seed_manifest"] = (
        "operator_private_source_free_seed_manifest"
    )
    run_id: StableIdentifierV1
    intent_queue_content_sha256: str = Field(pattern=_SHA256)
    run_nonce_hex: str = Field(pattern=_SHA256)
    entropy_path_label: Literal["default_store_csprng_path", "test_injected_path"]
    items: tuple[PrivateSourceFreeSeedItemV2, ...] = Field(min_length=9, max_length=9)
    train_case_count: Literal[3] = 3
    dev_case_count: Literal[3] = 3
    private_heldout_case_count: Literal[3] = 3
    source_free: Literal[True] = True
    model_work_created: Literal[False] = False
    authority: SourceFreeCaseAuthoringAuthorityV1 = Field(
        default_factory=SourceFreeCaseAuthoringAuthorityV1
    )
    manifest_content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        if self.run_id.namespace != _RUN_NAMESPACE:
            raise ValueError("private source-free run uses the wrong identifier namespace")
        case_ids = tuple(item.case_id.value for item in self.items)
        intent_ids = tuple(item.intent_id.value for item in self.items)
        if case_ids != tuple(sorted(case_ids)) or len(set(case_ids)) != 9:
            raise ValueError("private source-free case IDs must be canonical and unique")
        if len(set(intent_ids)) != 9:
            raise ValueError("private source-free intent IDs must be unique")
        counts = Counter(item.partition for item in self.items)
        if counts != Counter(
            {
                PairSplitPartitionV1.TRAIN: 3,
                PairSplitPartitionV1.DEV: 3,
                PairSplitPartitionV1.PRIVATE_HELDOUT: 3,
            }
        ):
            raise ValueError("private source-free manifest must retain a 3/3/3 split")
        if self.authority != SourceFreeCaseAuthoringAuthorityV1():
            raise ValueError("private source-free manifest authority drifted")
        if self.manifest_content_sha256 != _sha256_json(self.content_payload()):
            raise ValueError("private source-free manifest hash drifted")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(
            dict[str, object],
            self.model_dump(mode="json", exclude={"manifest_content_sha256"}),
        )

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.model_dump(mode="json")) + b"\n"


class SourceFreePrivateSeedCommitmentV2(ContractModel):
    """Public commitment with no case identity or split mapping."""

    schema_version: Literal["autolean.ifem-source-free-private-seed-commitment.v2"] = (
        "autolean.ifem-source-free-private-seed-commitment.v2"
    )
    protocol: Literal["autolean.builder-ifem-source-free-private-seed.v2"] = PRIVATE_SEED_PROTOCOL
    artifact_kind: Literal["source_free_private_seed_commitment"] = (
        "source_free_private_seed_commitment"
    )
    run_id: StableIdentifierV1
    intent_queue_content_sha256: str = Field(pattern=_SHA256)
    private_manifest_content_sha256: str = Field(pattern=_SHA256)
    private_manifest_size_bytes: int = Field(ge=2, le=1_048_576, strict=True)
    entropy_path_label: Literal["default_store_csprng_path", "test_injected_path"]
    default_csprng_path_claimed: bool = Field(strict=True)
    entropy_provenance_verified: Literal[False] = False
    unpredictability_verified: Literal[False] = False
    case_count: Literal[9] = 9
    train_case_count: Literal[3] = 3
    dev_case_count: Literal[3] = 3
    private_heldout_case_count: Literal[3] = 3
    store_persist_before_projection_observed: Literal[True] = True
    store_persistence_attested: Literal[False] = False
    case_ids_disclosed: Literal[False] = False
    partition_mapping_disclosed: Literal[False] = False
    nonce_disclosed: Literal[False] = False
    oracle_disclosed: Literal[False] = False
    same_process_materialization: Literal[True] = True
    heldout_worker_isolation_claimed: Literal[False] = False
    live_model_eligible: Literal[False] = False
    authority: SourceFreeCaseAuthoringAuthorityV1 = Field(
        default_factory=SourceFreeCaseAuthoringAuthorityV1
    )
    builder_freeze: Literal["forbidden"] = "forbidden"
    prover_handoff: Literal["forbidden"] = "forbidden"
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_commitment(self) -> Self:
        if self.run_id.namespace != _RUN_NAMESPACE:
            raise ValueError("private seed commitment uses the wrong run namespace")
        expected_claim = self.entropy_path_label == "default_store_csprng_path"
        if self.default_csprng_path_claimed is not expected_claim:
            raise ValueError("private seed CSPRNG path claim differs from its path label")
        if self.authority != SourceFreeCaseAuthoringAuthorityV1():
            raise ValueError("private seed commitment authority drifted")
        if self.content_sha256 != _sha256_json(self.content_payload()):
            raise ValueError("private seed commitment hash drifted")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(
            dict[str, object],
            self.model_dump(mode="json", exclude={"content_sha256"}),
        )

    def assert_not_authoritative(self) -> Never:
        raise SourceFreePrivateSeedError(
            "private source-free seed commitment cannot classify, freeze, or hand work to Prover"
        )

    def freeze_statement(self) -> Never:
        self.assert_not_authoritative()

    def handoff_to_prover(self) -> Never:
        self.assert_not_authoritative()


class LocalSourceFreePrivateSeedStore:
    """Atomic local manifest store rooted outside every Git checkout."""

    def __init__(self, root: Path, *, repository_root: Path, run_label: str) -> None:
        if _RUN_LABEL.fullmatch(run_label) is None:
            raise SourceFreePrivateSeedError("private seed run label is invalid")
        self._repository_root = _validated_repository_root(repository_root)
        self._root = _prepare_private_root(root, repository_root=self._repository_root)
        run_key = hashlib.sha256(run_label.encode("utf-8")).hexdigest()
        self._manifest_path = self._root / "manifests" / f"{run_key}.json"
        _prepare_manifest_parent(self._manifest_path, root=self._root)

    @property
    def manifest_path(self) -> Path:
        return self._manifest_path

    def load(self) -> PrivateSourceFreeSeedManifestV2:
        _reject_link_or_reparse(self._manifest_path, label="private seed manifest")
        try:
            raw = self._manifest_path.read_bytes()
            manifest = PrivateSourceFreeSeedManifestV2.model_validate_json(raw)
        except (OSError, ValueError) as error:
            raise SourceFreePrivateSeedError(
                "private source-free seed manifest is unavailable or invalid"
            ) from error
        if manifest.canonical_bytes() != raw:
            raise SourceFreePrivateSeedError("private source-free seed manifest is not canonical")
        return manifest

    def commit_for_queue(
        self,
        queue: IFEMNextCalibrationCaseIntentsV1,
        *,
        test_entropy: Callable[[int], bytes] | None = None,
    ) -> tuple[PrivateSourceFreeSeedManifestV2, SourceFreePrivateSeedCommitmentV2]:
        """Persist once, read back, then project; recovery never regenerates entropy."""

        validated_queue = _revalidate_queue(queue)
        if self._manifest_path.exists():
            persisted = self.load()
            verify_private_seed_manifest_against_queue(persisted, validated_queue)
            return persisted, _build_private_seed_commitment(persisted)

        entropy_path_label: Literal["default_store_csprng_path", "test_injected_path"]
        if test_entropy is None:
            nonce = secrets.token_bytes(_NONCE_BYTES)
            entropy_path_label = "default_store_csprng_path"
        else:
            nonce = test_entropy(_NONCE_BYTES)
            entropy_path_label = "test_injected_path"
        if type(nonce) is not bytes or len(nonce) != _NONCE_BYTES:
            raise SourceFreePrivateSeedError("private seed entropy must return exactly 32 bytes")
        candidate = _build_private_seed_manifest(
            validated_queue,
            run_nonce=nonce,
            entropy_path_label=entropy_path_label,
        )
        persisted = self._commit(candidate)
        verify_private_seed_manifest_against_queue(persisted, validated_queue)
        return persisted, _build_private_seed_commitment(persisted)

    def _commit(
        self,
        manifest: PrivateSourceFreeSeedManifestV2,
    ) -> PrivateSourceFreeSeedManifestV2:
        validated = _revalidate_manifest(manifest)
        _prepare_manifest_parent(self._manifest_path, root=self._root)
        payload = validated.canonical_bytes()
        temporary = self._manifest_path.parent / f".private-seed-{uuid.uuid4().hex}.tmp"
        descriptor: int | None = None
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
                os.link(temporary, self._manifest_path)
            except FileExistsError:
                pass
            except OSError as error:
                raise SourceFreePrivateSeedError(
                    "could not atomically persist the private seed manifest"
                ) from error
            persisted = self.load()
            if persisted != validated:
                raise SourceFreePrivateSeedError(
                    "private seed manifest conflicts with the retained run"
                )
            return persisted
        finally:
            if descriptor is not None:
                os.close(descriptor)
            with suppress(OSError):
                temporary.unlink()


def _build_private_seed_manifest(
    queue: IFEMNextCalibrationCaseIntentsV1,
    *,
    run_nonce: bytes,
    entropy_path_label: Literal["default_store_csprng_path", "test_injected_path"],
) -> PrivateSourceFreeSeedManifestV2:
    """Build exactly nine operator-private P3 cases in canonical order."""

    validated_queue = _revalidate_queue(queue)
    if type(run_nonce) is not bytes or len(run_nonce) != _NONCE_BYTES:
        raise SourceFreePrivateSeedError("private seed nonce must be exactly 32 bytes")
    intents = tuple(
        intent
        for intent in validated_queue.intents
        if intent.calibration_priority is IFEMCalibrationPriorityV1.P3_CREATE_CALIBRATION_CASE
    )
    if len(intents) != 9:
        raise SourceFreePrivateSeedError("private seed manifest requires exactly nine P3 intents")
    for intent in intents:
        if (
            intent.required_next_calibration
            is not IFEMRequiredNextCalibrationV1.CREATE_CALIBRATION_CASE
            or not intent.structural_risk_discovery_required
            or intent.materialization_state != "not_authored"
            or intent.semantic_classification != "unknown"
        ):
            raise SourceFreePrivateSeedError(
                "private seed manifest received a non-authorable intent"
            )

    run_digest = _hmac_json(
        run_nonce,
        {
            "schema_version": "autolean.ifem-source-free-private-run-id.v2",
            "intent_queue_content_sha256": validated_queue.content_sha256,
        },
    )
    run_id = stable_identifier(_RUN_NAMESPACE, run_digest.hex())
    ranked = tuple(
        sorted(
            intents,
            key=lambda intent: (
                _hmac_json(
                    run_nonce,
                    {
                        "schema_version": "autolean.ifem-source-free-private-rank.v2",
                        "intent_queue_content_sha256": validated_queue.content_sha256,
                        "intent_id": intent.intent_id.model_dump(mode="json"),
                    },
                ),
                intent.intent_id.value,
            ),
        )
    )
    items: list[PrivateSourceFreeSeedItemV2] = []
    for index, intent in enumerate(ranked):
        digest = _hmac_json(
            run_nonce,
            {
                "schema_version": "autolean.ifem-source-free-private-case.v2",
                "run_id": run_id.model_dump(mode="json"),
                "intent_id": intent.intent_id.model_dump(mode="json"),
            },
        )
        baseline = SourceFreeSignatureV1(
            alpha=digest[0] % 7,
            beta=digest[1] % 7,
            gamma=digest[2] % 7,
            guard_enabled=bool(digest[3] % 2),
        )
        selector = digest[4] % 3
        increment = 1 + digest[5] % 3
        payload: dict[str, object] = {
            "schema_version": "autolean.ifem-source-free-private-seed-item.v2",
            "case_id": stable_identifier(_CASE_NAMESPACE, digest.hex()).model_dump(mode="json"),
            "intent_id": intent.intent_id.model_dump(mode="json"),
            "node_id": intent.node_id,
            "partition": _partition_for_rank(index).value,
            "baseline": baseline.model_dump(mode="json"),
            "selector": selector,
            "increment": increment,
            "hidden_oracle": SourceFreeHiddenOracleV1(
                selected_slot=selector,
                expected_candidate=_expected_candidate(
                    baseline,
                    selector=selector,
                    increment=increment,
                ),
            ).model_dump(mode="json"),
            "source_free": True,
            "textbook_derived": False,
            "authority": SourceFreeCaseAuthoringAuthorityV1().model_dump(mode="json"),
        }
        payload["item_content_sha256"] = _sha256_json(payload)
        items.append(PrivateSourceFreeSeedItemV2.model_validate(payload))
    ordered = tuple(sorted(items, key=lambda item: item.case_id.value))
    payload = {
        "schema_version": PRIVATE_SEED_SCHEMA,
        "protocol": PRIVATE_SEED_PROTOCOL,
        "artifact_kind": "operator_private_source_free_seed_manifest",
        "run_id": run_id.model_dump(mode="json"),
        "intent_queue_content_sha256": validated_queue.content_sha256,
        "run_nonce_hex": run_nonce.hex(),
        "entropy_path_label": entropy_path_label,
        "items": [item.model_dump(mode="json") for item in ordered],
        "train_case_count": 3,
        "dev_case_count": 3,
        "private_heldout_case_count": 3,
        "source_free": True,
        "model_work_created": False,
        "authority": SourceFreeCaseAuthoringAuthorityV1().model_dump(mode="json"),
    }
    payload["manifest_content_sha256"] = _sha256_json(payload)
    try:
        return PrivateSourceFreeSeedManifestV2.model_validate(payload)
    except ValueError as error:
        raise SourceFreePrivateSeedError("generated private seed manifest is invalid") from error


def build_test_private_seed_manifest(
    queue: IFEMNextCalibrationCaseIntentsV1,
    *,
    run_nonce: bytes,
) -> PrivateSourceFreeSeedManifestV2:
    """Build a deterministic test manifest that can never claim CSPRNG provenance."""

    return _build_private_seed_manifest(
        queue,
        run_nonce=run_nonce,
        entropy_path_label="test_injected_path",
    )


def _build_private_seed_commitment(
    manifest: PrivateSourceFreeSeedManifestV2,
) -> SourceFreePrivateSeedCommitmentV2:
    """Project only aggregate counts and the persisted private-manifest commitment."""

    private = _revalidate_manifest(manifest)
    payload: dict[str, object] = {
        "schema_version": "autolean.ifem-source-free-private-seed-commitment.v2",
        "protocol": PRIVATE_SEED_PROTOCOL,
        "artifact_kind": "source_free_private_seed_commitment",
        "run_id": private.run_id.model_dump(mode="json"),
        "intent_queue_content_sha256": private.intent_queue_content_sha256,
        "private_manifest_content_sha256": private.manifest_content_sha256,
        "private_manifest_size_bytes": len(private.canonical_bytes()),
        "entropy_path_label": private.entropy_path_label,
        "default_csprng_path_claimed": (private.entropy_path_label == "default_store_csprng_path"),
        "entropy_provenance_verified": False,
        "unpredictability_verified": False,
        "case_count": 9,
        "train_case_count": 3,
        "dev_case_count": 3,
        "private_heldout_case_count": 3,
        "store_persist_before_projection_observed": True,
        "store_persistence_attested": False,
        "case_ids_disclosed": False,
        "partition_mapping_disclosed": False,
        "nonce_disclosed": False,
        "oracle_disclosed": False,
        "same_process_materialization": True,
        "heldout_worker_isolation_claimed": False,
        "live_model_eligible": False,
        "authority": SourceFreeCaseAuthoringAuthorityV1().model_dump(mode="json"),
        "builder_freeze": "forbidden",
        "prover_handoff": "forbidden",
    }
    payload["content_sha256"] = _sha256_json(payload)
    try:
        return SourceFreePrivateSeedCommitmentV2.model_validate(payload)
    except ValueError as error:
        raise SourceFreePrivateSeedError("private seed public commitment is invalid") from error


def verify_private_seed_manifest_against_queue(
    manifest: PrivateSourceFreeSeedManifestV2,
    queue: IFEMNextCalibrationCaseIntentsV1,
) -> None:
    """Reject a self-hashed manifest unless its private nonce replays the exact queue."""

    private = _revalidate_manifest(manifest)
    validated_queue = _revalidate_queue(queue)
    try:
        nonce = bytes.fromhex(private.run_nonce_hex)
    except ValueError as error:
        raise SourceFreePrivateSeedError("private seed nonce is invalid") from error
    expected = _build_private_seed_manifest(
        validated_queue,
        run_nonce=nonce,
        entropy_path_label=private.entropy_path_label,
    )
    if private != expected:
        raise SourceFreePrivateSeedError("private seed manifest differs from exact queue replay")


def verify_private_seed_commitment(
    commitment: SourceFreePrivateSeedCommitmentV2,
    manifest: PrivateSourceFreeSeedManifestV2,
) -> None:
    if type(commitment) is not SourceFreePrivateSeedCommitmentV2:
        raise SourceFreePrivateSeedError("private seed commitment requires its exact type")
    try:
        public = SourceFreePrivateSeedCommitmentV2.model_validate(
            commitment.model_dump(mode="json")
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise SourceFreePrivateSeedError("private seed commitment failed revalidation") from error
    if public != _build_private_seed_commitment(manifest):
        raise SourceFreePrivateSeedError("private seed commitment differs from its manifest")


def render_private_seed_commitment(commitment: SourceFreePrivateSeedCommitmentV2) -> bytes:
    if type(commitment) is not SourceFreePrivateSeedCommitmentV2:
        raise SourceFreePrivateSeedError("private seed commitment requires its exact type")
    try:
        public = SourceFreePrivateSeedCommitmentV2.model_validate(
            commitment.model_dump(mode="json")
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise SourceFreePrivateSeedError("private seed commitment failed revalidation") from error
    rendered = canonical_json_bytes(public.model_dump(mode="json")) + b"\n"
    if any(field in rendered for field in _FORBIDDEN_PUBLIC_FIELDS):
        raise SourceFreePrivateSeedError("private seed commitment leaked a private field")
    return rendered


def _revalidate_queue(
    queue: IFEMNextCalibrationCaseIntentsV1,
) -> IFEMNextCalibrationCaseIntentsV1:
    if type(queue) is not IFEMNextCalibrationCaseIntentsV1:
        raise SourceFreePrivateSeedError("private seed protocol requires the exact queue type")
    try:
        value = IFEMNextCalibrationCaseIntentsV1.model_validate(queue.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as error:
        raise SourceFreePrivateSeedError("private seed queue failed revalidation") from error
    if (
        not value.source_free
        or value.formalization_payload_present
        or value.model_payload_present
        or value.private_state_present
        or value.authority != type(value.authority)()
    ):
        raise SourceFreePrivateSeedError("private seed queue crossed its metadata boundary")
    return value


def _revalidate_manifest(
    manifest: PrivateSourceFreeSeedManifestV2,
) -> PrivateSourceFreeSeedManifestV2:
    if type(manifest) is not PrivateSourceFreeSeedManifestV2:
        raise SourceFreePrivateSeedError("private seed manifest requires its exact type")
    try:
        return PrivateSourceFreeSeedManifestV2.model_validate(manifest.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as error:
        raise SourceFreePrivateSeedError("private seed manifest failed revalidation") from error


def _partition_for_rank(index: int) -> PairSplitPartitionV1:
    if 0 <= index < 3:
        return PairSplitPartitionV1.TRAIN
    if 3 <= index < 6:
        return PairSplitPartitionV1.DEV
    if 6 <= index < 9:
        return PairSplitPartitionV1.PRIVATE_HELDOUT
    raise SourceFreePrivateSeedError("private seed rank is outside nine cases")


def _expected_candidate(
    baseline: SourceFreeSignatureV1,
    *,
    selector: int,
    increment: int,
) -> SourceFreeSignatureV1:
    values = [baseline.alpha, baseline.beta, baseline.gamma]
    values[selector] += increment
    return SourceFreeSignatureV1(
        alpha=values[0],
        beta=values[1],
        gamma=values[2],
        guard_enabled=baseline.guard_enabled,
    )


def _hmac_json(key: bytes, value: object) -> bytes:
    return hmac.new(key, canonical_json_bytes(value), hashlib.sha256).digest()


def _sha256_json(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _validated_repository_root(root: Path) -> Path:
    if not isinstance(root, Path) or not root.is_absolute():
        raise SourceFreePrivateSeedError("repository root must be an absolute Path")
    resolved = root.resolve(strict=True)
    if not (resolved / ".git").exists():
        raise SourceFreePrivateSeedError("repository root must contain .git")
    return resolved


def _reject_link_or_reparse(path: Path, *, label: str) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if path.is_symlink() or (
        int(getattr(metadata, "st_file_attributes", 0)) & _FILE_ATTRIBUTE_REPARSE_POINT
    ):
        raise SourceFreePrivateSeedError(
            f"{label} must not be a symlink, junction, or reparse point"
        )


def _prepare_private_root(root: Path, *, repository_root: Path) -> Path:
    if not isinstance(root, Path) or not root.is_absolute():
        raise SourceFreePrivateSeedError("private seed root must be an absolute Path")
    unresolved = root.absolute()
    if unresolved == repository_root or repository_root in unresolved.parents:
        raise SourceFreePrivateSeedError("private seed root must be outside the repository")
    for candidate in (unresolved, *unresolved.parents):
        _reject_link_or_reparse(candidate, label="private seed root ancestry")
        if (candidate / ".git").exists():
            raise SourceFreePrivateSeedError("private seed root must be outside every Git checkout")
    root.mkdir(parents=True, exist_ok=True)
    _reject_link_or_reparse(root, label="private seed root")
    resolved = root.resolve(strict=True)
    if resolved == repository_root or repository_root in resolved.parents:
        raise SourceFreePrivateSeedError("private seed root resolved inside the repository")
    return resolved


def _prepare_manifest_parent(path: Path, *, root: Path) -> None:
    parent = path.parent
    _reject_link_or_reparse(parent, label="private seed manifest parent")
    parent.mkdir(parents=True, exist_ok=True)
    _reject_link_or_reparse(parent, label="private seed manifest parent")
    resolved = parent.resolve(strict=True)
    if root not in resolved.parents:
        raise SourceFreePrivateSeedError("private seed manifest path escaped its root")
    _reject_link_or_reparse(path, label="private seed manifest")


__all__ = [
    "PRIVATE_SEED_PROTOCOL",
    "PRIVATE_SEED_SCHEMA",
    "LocalSourceFreePrivateSeedStore",
    "PrivateSourceFreeSeedItemV2",
    "PrivateSourceFreeSeedManifestV2",
    "SourceFreePrivateSeedCommitmentV2",
    "SourceFreePrivateSeedError",
    "build_test_private_seed_manifest",
    "render_private_seed_commitment",
    "verify_private_seed_commitment",
    "verify_private_seed_manifest_against_queue",
]
