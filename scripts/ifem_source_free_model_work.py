"""Operate one recoverable, source-free iFEM formalizer canary through DeepSeek.

This is intentionally a bounded operator experiment, not Builder fidelity evidence or a Prover
input.  The Builder-owned stage ledger dispatches exactly one first-stage coordinate.  The
control plane owns its authorization and completion receipt, while raw output stays in an
operator-private CAS.  ``resume`` never constructs or invokes a provider.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
import sys
import uuid
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal, Never, Self, cast

import httpx

# Keep direct-file invocation usable without a caller-managed PYTHONPATH.
_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(_REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPOSITORY_ROOT))

from autolean_builder.ifem_next_calibration_case_intents import (  # noqa: E402
    IFEMNextCalibrationCaseIntentsV1,
    build_ifem_next_calibration_case_intents_from_paths,
)
from autolean_builder.ifem_source_free_private_seed import (  # noqa: E402
    LocalSourceFreePrivateSeedStore,
    PrivateSourceFreeSeedItemV2,
    SourceFreePrivateSeedError,
)
from autolean_builder.ifem_source_free_stage_ledger import (  # noqa: E402
    LocalSourceFreeStageLedger,
    SourceFreeStageCoordinateV1,
    SourceFreeStageLedgerError,
    SourceFreeStageLedgerStateV1,
)
from autolean_contracts import (  # noqa: E402
    AttestationPurposeV1,
    AttestationV1,
    ContractModel,
    EndpointClassV1,
    HmacAttestationKeyV1,
    HmacAttestationSignerV1,
    HmacAttestationVerifierV1,
    ModelExecutionPricingV1,
    ModelExecutionProviderApprovalV1,
    ModelExecutionProviderBindingV1,
    ModelWorkBundleV2,
    ModelWorkRoleV1,
    canonical_json_bytes,
    model_work_admission_evidence_identity,
    model_work_admission_payload,
    stable_identifier,
)
from autolean_control_plane import (  # noqa: E402
    ArtifactStore,
    ControlPlane,
    EventStore,
    LeaseStore,
    ModelExecutionAuthorizationService,
)
from autolean_prover.errors import ProviderResponseError  # noqa: E402
from autolean_prover.providers import (  # noqa: E402
    ChatCompletionsOperatorProfileV1,
    LocalPrivateModelOutputStore,
    ProviderRegistry,
    StaticCapabilityProbe,
)
from autolean_prover.providers.responses import (  # noqa: E402
    HttpxResponsesTransport,
    ResponsesTransport,
)
from pydantic import Field, model_validator  # noqa: E402

from benchmarks.ifem_source_free_model_work_sidecar import (  # noqa: E402
    EventStoreSourceFreeModelWorkAttemptStore,
    SourceFreeModelWorkError,
    SourceFreeModelWorkExecutionPolicyV1,
    SourceFreeModelWorkExecutionSidecar,
    SourceFreeModelWorkReconciliationRequired,
    source_free_model_work_prompt_contract_sha256,
)

type OperatorMode = Literal["plan", "preflight", "run", "resume", "report"]
type OperatorStatus = Literal[
    "planned",
    "preflight_ready",
    "settled",
    "recovered",
    "report_ready",
    "execution_refused",
    "reconciliation_required",
]

_PROFILE_PATH = (
    _REPOSITORY_ROOT
    / "Prover"
    / "operator-profiles"
    / "deepseek-v4-pro.ifem-role-calibration.v4.json"
)
_PROFILE_SHA256: Final = "5faba1964bdbda24f03b9a290e4fd18c92b9dac70418d711cf7296643b4fafe3"
_API_KEY_ENV: Final = "AUTOLEAN_DEEPSEEK_API_KEY"
_REGISTRY_NAME: Final = "ifem-source-free-deepseek-v1"
_MODEL_REVISION: Final = "deepseek-v4-pro-api-alias-unpinned"
_PRICE_BOUND_MICROUSD_PER_TOKEN: Final = 10
_RUN_LABEL = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_SHA256 = r"^[0-9a-f]{64}$"
_SAFE_FAILURE = r"^[a-z][a-z0-9_]{0,63}$"
_ATTESTATION_MATERIAL_BYTES: Final = 48 * 3
_OPERATOR_APPROVED_AT: Final = datetime(2026, 8, 1, tzinfo=UTC)
_FORBIDDEN_PUBLIC_FIELDS: Final[tuple[bytes, ...]] = (
    b'"api_key"',
    b'"model_id"',
    b'"path"',
    b'"private_root"',
    b'"prompt"',
    b'"raw_response"',
    b'"response"',
    b'"run_label"',
    b'"secret"',
    b'"state_root"',
)


class SourceFreeDeepSeekOperatorError(ValueError):
    """The bounded source-free operator boundary was violated."""


class OperatorApprovalRequired(SourceFreeDeepSeekOperatorError):
    """The caller did not explicitly allow the only network-capable mode."""


class OperatorRootRejected(SourceFreeDeepSeekOperatorError):
    """State or private storage does not meet the external-root policy."""


class OperatorSecretUnavailable(SourceFreeDeepSeekOperatorError):
    """The named process environment API-key reference cannot be used."""


class OperatorPrivateStateUnavailable(SourceFreeDeepSeekOperatorError):
    """An immutable operator-private state item is missing or malformed."""


class SourceFreeDeepSeekAuthorityV1(ContractModel):
    """Every result from this local-HMAC experiment remains advisory only."""

    semantic_classification_authorized: Literal[False] = False
    semantic_fidelity_claimed: Literal[False] = False
    statement_contract_created: Literal[False] = False
    formal_graph_created: Literal[False] = False
    builder_freeze_allowed: Literal[False] = False
    prover_handoff_allowed: Literal[False] = False
    promotion_allowed: Literal[False] = False
    production_signing_authority: Literal[False] = False


class SourceFreeDeepSeekPublicReportV1(ContractModel):
    """Redacted stdout result for one formalizer coordinate, never a proof or score."""

    schema_version: Literal["autolean.ifem-source-free-deepseek-operator.v1"] = (
        "autolean.ifem-source-free-deepseek-operator.v1"
    )
    mode: OperatorMode
    status: OperatorStatus
    plan_content_sha256: str | None = Field(default=None, pattern=_SHA256)
    stage_role: Literal["statement_formalizer"] = "statement_formalizer"
    coordinate_count: Literal[1] = 1
    maximum_authorized_provider_attempts: Literal[1] = 1
    max_attempts_per_stage: Literal[1] = 1
    attempt_binding_observed: bool = False
    completion_settlement_observed: bool = False
    private_stage_ledger_commitment_sha256: str | None = Field(default=None, pattern=_SHA256)
    private_attempt_binding_commitment_sha256: str | None = Field(default=None, pattern=_SHA256)
    private_completion_binding_commitment_sha256: str | None = Field(
        default=None,
        pattern=_SHA256,
    )
    private_completion_verified: bool = False
    actual_provider_dispatch_count_claimed: Literal[False] = False
    raw_response_disclosed: Literal[False] = False
    model_identity_disclosed: Literal[False] = False
    machine_advisory_disposition: Literal["abstain"] = "abstain"
    authority: SourceFreeDeepSeekAuthorityV1 = Field(default_factory=SourceFreeDeepSeekAuthorityV1)
    builder_freeze: Literal["forbidden"] = "forbidden"
    prover_handoff: Literal["forbidden"] = "forbidden"
    failure_class: str | None = Field(default=None, pattern=_SAFE_FAILURE)
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_public_boundary(self) -> Self:
        successful = self.status in {
            "planned",
            "preflight_ready",
            "settled",
            "recovered",
            "report_ready",
        }
        if successful != (self.failure_class is None):
            raise ValueError("source-free public status and failure class disagree")
        commitments = (
            self.private_stage_ledger_commitment_sha256,
            self.private_attempt_binding_commitment_sha256,
            self.private_completion_binding_commitment_sha256,
        )
        complete_commitments = all(value is not None for value in commitments)
        if any(value is not None for value in commitments) != complete_commitments:
            raise ValueError("source-free public evidence commitments are incomplete")
        if self.private_completion_verified != complete_commitments:
            raise ValueError("source-free completion verification and commitments disagree")
        if self.status in {"settled", "recovered"} and not (
            self.attempt_binding_observed
            and self.completion_settlement_observed
            and self.private_completion_verified
        ):
            raise ValueError("settled source-free report lacks private completion evidence")
        if self.authority != SourceFreeDeepSeekAuthorityV1():
            raise ValueError("source-free public authority drifted")
        if self.content_sha256 != _sha256_json(self.content_payload()):
            raise ValueError("source-free public report hash drifted")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(
            dict[str, object],
            self.model_dump(mode="json", exclude={"content_sha256"}),
        )


class _RunMarkerV1(ContractModel):
    """Private-root-independent state binding for one operator run label and exact plan."""

    schema_version: Literal["autolean.ifem-source-free-deepseek-run-marker.v1"] = (
        "autolean.ifem-source-free-deepseek-run-marker.v1"
    )
    run_label_sha256: str = Field(pattern=_SHA256)
    plan_content_sha256: str = Field(pattern=_SHA256)
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_marker(self) -> Self:
        if self.content_sha256 != _sha256_json(self.content_payload()):
            raise ValueError("source-free run marker hash drifted")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(
            dict[str, object],
            self.model_dump(mode="json", exclude={"content_sha256"}),
        )


class _PrivateAttestationMaterialV1(ContractModel):
    """Three local-only HMAC keys for restartable test authority, retained outside Git."""

    schema_version: Literal["autolean.ifem-source-free-local-hmac-material.v1"] = (
        "autolean.ifem-source-free-local-hmac-material.v1"
    )
    encoded_material: str = Field(min_length=1)
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_material(self) -> Self:
        try:
            material = base64.b64decode(self.encoded_material.encode("ascii"), validate=True)
        except (UnicodeEncodeError, ValueError) as error:
            raise ValueError("local HMAC material is invalid") from error
        if len(material) != _ATTESTATION_MATERIAL_BYTES:
            raise ValueError("local HMAC material has an unexpected length")
        if self.content_sha256 != _sha256_json(self.content_payload()):
            raise ValueError("local HMAC material hash drifted")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(
            dict[str, object],
            self.model_dump(mode="json", exclude={"content_sha256"}),
        )

    def key_bytes(self) -> tuple[bytes, bytes, bytes]:
        material = base64.b64decode(self.encoded_material.encode("ascii"), validate=True)
        return material[:48], material[48:96], material[96:]


@dataclass(frozen=True, slots=True)
class SourceFreeDeepSeekOperatorConfig:
    mode: OperatorMode
    state_root: Path
    private_root: Path
    run_label: str = "ifem-source-free-deepseek-v1"
    operator_approved: bool = False

    def __post_init__(self) -> None:
        if _RUN_LABEL.fullmatch(self.run_label) is None:
            raise SourceFreeDeepSeekOperatorError("source-free run label is invalid")
        state_root = _validated_operator_root(self.state_root, label="state")
        private_root = _validated_operator_root(self.private_root, label="private")
        if (
            state_root == private_root
            or _is_relative_to(state_root, private_root)
            or _is_relative_to(private_root, state_root)
        ):
            raise OperatorRootRejected("state and private roots must be disjoint")
        object.__setattr__(self, "state_root", state_root)
        object.__setattr__(self, "private_root", private_root)


@dataclass(frozen=True, slots=True)
class SourceFreeDeepSeekPlan:
    profile: ChatCompletionsOperatorProfileV1
    profile_bytes: bytes
    queue: IFEMNextCalibrationCaseIntentsV1
    policy: SourceFreeModelWorkExecutionPolicyV1
    provider_configuration_sha256: str
    prompt_contract_sha256: str
    content_sha256: str


@dataclass(slots=True)
class _PreparedRuntime:
    plan: SourceFreeDeepSeekPlan
    ledger: LocalSourceFreeStageLedger
    coordinate: SourceFreeStageCoordinateV1
    seed_item: PrivateSourceFreeSeedItemV2
    attempt_store: EventStoreSourceFreeModelWorkAttemptStore
    authorization_service: ModelExecutionAuthorizationService
    sidecar: SourceFreeModelWorkExecutionSidecar
    admission_resolver: _PersistentAdmissionResolver
    diagnostic_transport: _RedactingTransport | None


class _NoIoTransport:
    """A plan-only adapter that makes accidental egress fail deterministically."""

    def post_json_bytes(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        del url, headers, body, timeout_seconds
        raise AssertionError("source-free plan construction must not perform provider I/O")

    def post_json(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        payload: Mapping[str, object],
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        del url, headers, payload, timeout_seconds
        raise AssertionError("source-free plan construction must not perform provider I/O")


class _RedactingTransport:
    """Preserve a small error class while never retaining request or response contents."""

    def __init__(self, delegate: ResponsesTransport) -> None:
        self._delegate = delegate
        self.failure_class: str | None = None

    def post_json_bytes(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        self.failure_class = None
        try:
            response = self._delegate.post_json_bytes(
                url=url,
                headers=headers,
                body=body,
                timeout_seconds=timeout_seconds,
            )
        except httpx.HTTPStatusError as error:
            self.failure_class = _http_failure_class(error.response.status_code)
            raise
        except httpx.TimeoutException:
            self.failure_class = "timeout"
            raise
        except httpx.RequestError:
            self.failure_class = "network"
            raise
        except (json.JSONDecodeError, UnicodeDecodeError, ProviderResponseError):
            self.failure_class = "provider_response_rejected"
            raise
        except Exception:
            self.failure_class = "transport_unclassified"
            raise
        self.failure_class = "http_ok"
        return response

    def post_json(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        payload: Mapping[str, object],
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        return self.post_json_bytes(
            url=url,
            headers=headers,
            body=canonical_json_bytes(payload),
            timeout_seconds=timeout_seconds,
        )


class _PersistentAdmissionResolver:
    """Persist exactly one signed admission per evidence identity before registration."""

    def __init__(
        self,
        root: Path,
        *,
        signer: HmacAttestationSignerV1,
        verifier: HmacAttestationVerifierV1,
    ) -> None:
        self._root = _prepare_private_child(root, "model-work-admissions-v1")
        self._signer = signer
        self._verifier = verifier

    def admit_model_work(self, bundle: ModelWorkBundleV2) -> AttestationV1:
        evidence_identity = model_work_admission_evidence_identity(bundle)
        path = self._root / f"{hashlib.sha256(evidence_identity.encode('utf-8')).hexdigest()}.json"
        if path.exists():
            return self._load(path, bundle)
        nonce = hashlib.sha256(
            f"autolean-source-free-admission-v1:{evidence_identity}".encode()
        ).hexdigest()[:48]
        candidate = self._signer.issue(
            purpose=AttestationPurposeV1.MODEL_WORK_ADMISSION,
            payload=model_work_admission_payload(bundle),
            evidence_identity=evidence_identity,
            ttl_seconds=3600,
            nonce=nonce,
        )
        retained = _write_private_once(
            path,
            canonical_json_bytes(candidate.model_dump(mode="json")),
        )
        try:
            persisted = AttestationV1.model_validate_json(retained)
        except ValueError as error:
            raise OperatorPrivateStateUnavailable("persisted admission is invalid") from error
        self._verify(persisted, bundle)
        return persisted

    def _load(self, path: Path, bundle: ModelWorkBundleV2) -> AttestationV1:
        _require_private_regular_file(path)
        try:
            persisted = AttestationV1.model_validate_json(path.read_bytes())
        except (OSError, ValueError) as error:
            raise OperatorPrivateStateUnavailable("persisted admission is unavailable") from error
        self._verify(persisted, bundle)
        return persisted

    def _verify(self, attestation: AttestationV1, bundle: ModelWorkBundleV2) -> None:
        try:
            self._verifier.verify(
                attestation,
                expected_purpose=AttestationPurposeV1.MODEL_WORK_ADMISSION,
                payload=model_work_admission_payload(bundle),
            )
        except Exception as error:
            raise OperatorPrivateStateUnavailable("persisted admission is not current") from error
        if attestation.evidence_identity != model_work_admission_evidence_identity(bundle):
            raise OperatorPrivateStateUnavailable(
                "persisted admission is bound to another work item"
            )


def _now() -> datetime:
    return datetime.now(UTC)


def _sha256_json(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _is_link_or_reparse_point(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    return stat.S_ISLNK(metadata.st_mode) or bool(
        attributes & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    )


def _validated_operator_root(path: Path, *, label: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise OperatorRootRejected(f"{label} root must be an absolute path")
    unresolved = path.absolute()
    if not unresolved.parent.is_dir():
        raise OperatorRootRejected(f"{label} root parent must already exist")
    for parent in unresolved.parents:
        if _is_link_or_reparse_point(parent):
            raise OperatorRootRejected(f"{label} root parent chain contains a link")
        if (parent / ".git").exists():
            raise OperatorRootRejected(f"{label} root must be outside every Git checkout")
    resolved_parent = unresolved.parent.resolve(strict=True)
    resolved = resolved_parent / unresolved.name
    repository = _REPOSITORY_ROOT.resolve(strict=True)
    if resolved == Path(resolved.anchor) or _is_relative_to(resolved, repository):
        raise OperatorRootRejected(f"{label} root must be outside the source checkout")
    if resolved.exists() and (_is_link_or_reparse_point(resolved) or not resolved.is_dir()):
        raise OperatorRootRejected(f"{label} root must be a physical directory")
    return resolved


def _ensure_operator_root(path: Path) -> None:
    if path.exists():
        if _is_link_or_reparse_point(path) or not path.is_dir():
            raise OperatorRootRejected("operator root changed before initialization")
        return
    try:
        path.mkdir()
    except FileExistsError:
        if _is_link_or_reparse_point(path) or not path.is_dir():
            raise OperatorRootRejected("operator root was concurrently replaced") from None


def _require_existing_operator_root(path: Path) -> Path:
    if not path.exists() or _is_link_or_reparse_point(path) or not path.is_dir():
        raise OperatorPrivateStateUnavailable("source-free run root is unavailable")
    resolved = path.resolve(strict=True)
    if resolved != path:
        raise OperatorPrivateStateUnavailable("source-free run root is no longer physical")
    return resolved


def _prepare_private_child(root: Path, name: str) -> Path:
    if _is_link_or_reparse_point(root) or not root.is_dir():
        raise OperatorPrivateStateUnavailable("operator-private root is unavailable")
    candidate = root / name
    if _is_link_or_reparse_point(candidate):
        raise OperatorPrivateStateUnavailable("operator-private child is linked")
    candidate.mkdir(exist_ok=True)
    if _is_link_or_reparse_point(candidate) or not candidate.is_dir():
        raise OperatorPrivateStateUnavailable("operator-private child is unavailable")
    resolved_root = root.resolve(strict=True)
    resolved = candidate.resolve(strict=True)
    if resolved_root not in resolved.parents:
        raise OperatorPrivateStateUnavailable("operator-private child escaped its root")
    return resolved


def _require_private_regular_file(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise OperatorPrivateStateUnavailable("operator-private file is unavailable") from error
    if _is_link_or_reparse_point(path) or not stat.S_ISREG(metadata.st_mode):
        raise OperatorPrivateStateUnavailable("operator-private file is not regular")


def _write_private_once(path: Path, payload: bytes) -> bytes:
    if _is_link_or_reparse_point(path.parent) or not path.parent.is_dir():
        raise OperatorPrivateStateUnavailable("operator-private file parent is unavailable")
    if path.exists():
        _require_private_regular_file(path)
        return path.read_bytes()
    temporary = path.parent / f".autolean-source-free-{uuid.uuid4().hex}.tmp"
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = None
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        with suppress(FileExistsError):
            os.link(temporary, path)
        return path.read_bytes()
    except OSError as error:
        raise OperatorPrivateStateUnavailable(
            "operator-private state could not be persisted"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        with suppress(FileNotFoundError):
            temporary.unlink()


def _run_marker(
    config: SourceFreeDeepSeekOperatorConfig,
    plan: SourceFreeDeepSeekPlan,
) -> _RunMarkerV1:
    payload: dict[str, object] = {
        "schema_version": "autolean.ifem-source-free-deepseek-run-marker.v1",
        "run_label_sha256": hashlib.sha256(config.run_label.encode("utf-8")).hexdigest(),
        "plan_content_sha256": plan.content_sha256,
    }
    payload["content_sha256"] = _sha256_json(payload)
    return _RunMarkerV1.model_validate(payload)


def _state_marker_path(config: SourceFreeDeepSeekOperatorConfig) -> Path:
    return config.state_root / "source-free-run-marker-v1.json"


def _write_or_verify_run_marker(
    config: SourceFreeDeepSeekOperatorConfig,
    plan: SourceFreeDeepSeekPlan,
) -> None:
    marker = _run_marker(config, plan)
    retained = _write_private_once(
        _state_marker_path(config),
        canonical_json_bytes(marker.model_dump(mode="json")),
    )
    try:
        persisted = _RunMarkerV1.model_validate_json(retained)
    except ValueError as error:
        raise OperatorPrivateStateUnavailable("source-free run marker is invalid") from error
    if persisted != marker:
        raise OperatorPrivateStateUnavailable("state root belongs to another source-free run")


def _load_and_verify_run_marker(
    config: SourceFreeDeepSeekOperatorConfig,
    plan: SourceFreeDeepSeekPlan,
) -> None:
    path = _state_marker_path(config)
    _require_private_regular_file(path)
    try:
        persisted = _RunMarkerV1.model_validate_json(path.read_bytes())
    except (OSError, ValueError) as error:
        raise OperatorPrivateStateUnavailable("source-free run marker is unavailable") from error
    if persisted != _run_marker(config, plan):
        raise OperatorPrivateStateUnavailable("state root differs from the requested run")


def _load_or_create_material(
    config: SourceFreeDeepSeekOperatorConfig,
) -> _PrivateAttestationMaterialV1:
    root = _prepare_private_child(config.private_root, "local-attestation-v1")
    path = root / "material.json"
    if path.exists():
        return _load_material(path)
    payload: dict[str, object] = {
        "schema_version": "autolean.ifem-source-free-local-hmac-material.v1",
        "encoded_material": base64.b64encode(
            secrets.token_bytes(_ATTESTATION_MATERIAL_BYTES)
        ).decode("ascii"),
    }
    payload["content_sha256"] = _sha256_json(payload)
    retained = _write_private_once(path, canonical_json_bytes(payload))
    try:
        material = _PrivateAttestationMaterialV1.model_validate_json(retained)
    except ValueError as error:
        raise OperatorPrivateStateUnavailable("local HMAC material is invalid") from error
    return material


def _load_material(path: Path) -> _PrivateAttestationMaterialV1:
    _require_private_regular_file(path)
    try:
        return _PrivateAttestationMaterialV1.model_validate_json(path.read_bytes())
    except (OSError, ValueError) as error:
        raise OperatorPrivateStateUnavailable("local HMAC material is unavailable") from error


def _attestation_keys(
    material: _PrivateAttestationMaterialV1,
) -> tuple[HmacAttestationKeyV1, HmacAttestationKeyV1, HmacAttestationKeyV1]:
    model_secret, admission_secret, completion_secret = material.key_bytes()
    return (
        HmacAttestationKeyV1(
            key_id="ifem-source-free-local-model-v1",
            secret=model_secret,
            allowed_purposes=frozenset({AttestationPurposeV1.MODEL_EXECUTION}),
        ),
        HmacAttestationKeyV1(
            key_id="ifem-source-free-local-admission-v1",
            secret=admission_secret,
            allowed_purposes=frozenset({AttestationPurposeV1.MODEL_WORK_ADMISSION}),
        ),
        HmacAttestationKeyV1(
            key_id="ifem-source-free-local-completion-v1",
            secret=completion_secret,
            allowed_purposes=frozenset({AttestationPurposeV1.MODEL_EXECUTION_COMPLETION}),
        ),
    )


def _load_profile() -> tuple[ChatCompletionsOperatorProfileV1, bytes]:
    try:
        payload = _PROFILE_PATH.read_bytes()
        profile = ChatCompletionsOperatorProfileV1.from_json_bytes(payload)
    except (OSError, ValueError) as error:
        raise SourceFreeDeepSeekOperatorError("fixed DeepSeek profile is unavailable") from error
    if (
        hashlib.sha256(payload).hexdigest() != _PROFILE_SHA256
        or profile.profile_id != "deepseek-v4-pro-ifem-role-d36"
        or profile.provider_id != "deepseek"
        or profile.model_id != "deepseek-v4-pro"
        or profile.api_key_env != _API_KEY_ENV
        or profile.endpoint_class is not EndpointClassV1.APPROVED_EXTERNAL
        or profile.timeout_seconds != 120.0
        or profile.canary_max_input_tokens != 2048
        or profile.canary_max_output_tokens != 4096
        or profile.default_reasoning_effort != "high"
    ):
        raise SourceFreeDeepSeekOperatorError("fixed DeepSeek profile has drifted")
    return profile, payload


def build_source_free_deepseek_plan() -> SourceFreeDeepSeekPlan:
    """Build one credential-free source-free formalizer plan with no state or provider I/O."""

    profile, profile_bytes = _load_profile()
    queue = build_ifem_next_calibration_case_intents_from_paths()
    policy = SourceFreeModelWorkExecutionPolicyV1(
        max_input_tokens=profile.canary_max_input_tokens,
        max_output_tokens=profile.canary_max_output_tokens,
        request_timeout_seconds=int(profile.timeout_seconds),
        authorization_ttl_seconds=150,
        lease_ttl_seconds=180,
        max_cost_microusd=_PRICE_BOUND_MICROUSD_PER_TOKEN
        * (profile.canary_max_input_tokens + profile.canary_max_output_tokens),
        reasoning_effort=profile.default_reasoning_effort,
    )
    provider = profile.create_provider(transport=_NoIoTransport(), environment={})
    prompt_contract_sha256 = source_free_model_work_prompt_contract_sha256(
        ModelWorkRoleV1.STATEMENT_FORMALIZER
    )
    payload: dict[str, object] = {
        "schema_version": "autolean.ifem-source-free-deepseek-plan.v2",
        "profile_content_sha256": hashlib.sha256(profile_bytes).hexdigest(),
        "queue_content_sha256": queue.content_sha256,
        "policy_content_sha256": policy.content_hash(),
        "provider_configuration_sha256": provider.configuration_hash.value,
        "prompt_contract_sha256": prompt_contract_sha256,
        "stage_role": ModelWorkRoleV1.STATEMENT_FORMALIZER.value,
        "coordinate_count": 1,
    }
    content_sha256 = _sha256_json(payload)
    return SourceFreeDeepSeekPlan(
        profile=profile,
        profile_bytes=profile_bytes,
        queue=queue,
        policy=policy,
        provider_configuration_sha256=provider.configuration_hash.value,
        prompt_contract_sha256=prompt_contract_sha256,
        content_sha256=content_sha256,
    )


def _required_api_key(environment: Mapping[str, str]) -> str:
    value = environment.get(_API_KEY_ENV)
    if (
        not isinstance(value, str)
        or not 16 <= len(value) <= 512
        or any(character.isspace() or ord(character) < 32 for character in value)
    ):
        raise OperatorSecretUnavailable("DeepSeek API-key environment reference is unavailable")
    return value


def _approval(plan: SourceFreeDeepSeekPlan) -> ModelExecutionProviderApprovalV1:
    return ModelExecutionProviderApprovalV1(
        approval_id=stable_identifier(
            "ifem-source-free-deepseek-provider",
            plan.provider_configuration_sha256,
        ),
        binding=ModelExecutionProviderBindingV1(
            registry_name=_REGISTRY_NAME,
            provider_id="deepseek",
            model_id="deepseek-v4-pro",
            model_revision=_MODEL_REVISION,
            endpoint_class=EndpointClassV1.APPROVED_EXTERNAL,
            configuration_hash=plan.profile.create_provider(
                transport=_NoIoTransport(),
                environment={},
            ).configuration_hash,
        ),
        pricing=ModelExecutionPricingV1(
            input_microusd_per_token=_PRICE_BOUND_MICROUSD_PER_TOKEN,
            cached_input_microusd_per_token=_PRICE_BOUND_MICROUSD_PER_TOKEN,
            output_microusd_per_token=_PRICE_BOUND_MICROUSD_PER_TOKEN,
        ),
        approved_by="autolean-source-free-local-hmac-v1",
        approved_at=_OPERATOR_APPROVED_AT,
    )


def _prepare_runtime(
    config: SourceFreeDeepSeekOperatorConfig,
    plan: SourceFreeDeepSeekPlan,
    *,
    mode: Literal["run", "resume"],
    environment: Mapping[str, str],
    transport: ResponsesTransport | None,
) -> _PreparedRuntime:
    if mode == "run":
        _ensure_operator_root(config.state_root)
        _ensure_operator_root(config.private_root)
        _write_or_verify_run_marker(config, plan)
        material = _load_or_create_material(config)
        seed_store = LocalSourceFreePrivateSeedStore(
            (config.private_root / "private-seed-v2").resolve(),
            repository_root=_REPOSITORY_ROOT,
            run_label=config.run_label,
        )
        manifest, _commitment = seed_store.commit_for_queue(plan.queue)
        api_key = _required_api_key(environment)
    else:
        _require_existing_operator_root(config.state_root)
        _require_existing_operator_root(config.private_root)
        _load_and_verify_run_marker(config, plan)
        material = _load_material(
            _prepare_private_child(config.private_root, "local-attestation-v1") / "material.json"
        )
        seed_store = LocalSourceFreePrivateSeedStore(
            (config.private_root / "private-seed-v2").resolve(),
            repository_root=_REPOSITORY_ROOT,
            run_label=config.run_label,
        )
        manifest = seed_store.load()
        api_key = None

    model_key, admission_key, completion_key = _attestation_keys(material)
    model_verifier = HmacAttestationVerifierV1({model_key.key_id: model_key})
    admission_verifier = HmacAttestationVerifierV1({admission_key.key_id: admission_key})
    completion_verifier = HmacAttestationVerifierV1({completion_key.key_id: completion_key})
    database = config.state_root / "control-plane.sqlite3"
    events = EventStore(database)
    control_plane = ControlPlane(
        events=events,
        leases=LeaseStore(database),
        artifacts=ArtifactStore(config.state_root / "artifact-staging-v1"),
        attestation_verifier=model_verifier,
    )
    output_store = LocalPrivateModelOutputStore(
        _prepare_private_child(config.private_root, "model-output-cas-v1")
    )
    service = ModelExecutionAuthorizationService(
        control_plane=control_plane,
        signer=HmacAttestationSignerV1(model_key),
        verifier=model_verifier,
        admission_verifier=admission_verifier,
        completion_signer=HmacAttestationSignerV1(completion_key),
        completion_verifier=completion_verifier,
        private_output_verifier=output_store,
    )
    approval = _approval(plan)
    diagnostic_transport: _RedactingTransport | None = None
    registry = ProviderRegistry(authorization_gate=service)
    if mode == "run":
        if api_key is None:
            raise AssertionError("run mode must resolve an API key")
        diagnostic_transport = _RedactingTransport(
            HttpxResponsesTransport() if transport is None else transport
        )
        provider = plan.profile.create_provider(
            transport=diagnostic_transport,
            environment={_API_KEY_ENV: api_key},
        )
        service.register_operator_approval(
            approval,
            idempotency_key=(
                "register-ifem-source-free-deepseek-"
                f"{hashlib.sha256(plan.content_sha256.encode('ascii')).hexdigest()[:24]}"
            ),
        )
        registry.register(
            _REGISTRY_NAME,
            provider=provider,
            probe=StaticCapabilityProbe(provider.capabilities),
            endpoint_class=EndpointClassV1.APPROVED_EXTERNAL,
            model_revision=_MODEL_REVISION,
        )
    else:
        service.preflight_operator_approval(approval)

    admissions = _PersistentAdmissionResolver(
        config.private_root,
        signer=HmacAttestationSignerV1(admission_key),
        verifier=admission_verifier,
    )
    attempt_store = EventStoreSourceFreeModelWorkAttemptStore(events)
    sidecar = SourceFreeModelWorkExecutionSidecar(
        seed_store=seed_store,
        intent_queue=plan.queue,
        attempt_store=attempt_store,
        authorization_service=service,
        registry=registry,
        approval=approval,
        output_store=output_store,
        admission_resolver=admissions,
        policy=plan.policy,
    )
    ledger = LocalSourceFreeStageLedger(
        (config.private_root / "stage-ledger-v1").resolve(),
        repository_root=_REPOSITORY_ROOT,
        seed_store=seed_store,
        intent_queue=plan.queue,
        completion_binding_verifier=sidecar,
    )
    coordinate = ledger.run.coordinates[0]
    if coordinate.role is not ModelWorkRoleV1.STATEMENT_FORMALIZER or coordinate.ordinal != 1:
        raise SourceFreeDeepSeekOperatorError("source-free canary coordinate has drifted")
    if manifest.items[0].case_id != coordinate.case_id:
        raise SourceFreeDeepSeekOperatorError("source-free canary seed coordinate has drifted")
    return _PreparedRuntime(
        plan=plan,
        ledger=ledger,
        coordinate=coordinate,
        seed_item=manifest.items[0],
        attempt_store=attempt_store,
        authorization_service=service,
        sidecar=sidecar,
        admission_resolver=admissions,
        diagnostic_transport=diagnostic_transport,
    )


def _report(
    mode: OperatorMode,
    status: OperatorStatus,
    *,
    plan: SourceFreeDeepSeekPlan | None,
    attempt_binding_observed: bool = False,
    completion_settlement_observed: bool = False,
    private_stage_ledger_commitment_sha256: str | None = None,
    private_attempt_binding_commitment_sha256: str | None = None,
    private_completion_binding_commitment_sha256: str | None = None,
    private_completion_verified: bool = False,
    failure_class: str | None = None,
) -> SourceFreeDeepSeekPublicReportV1:
    payload: dict[str, object] = {
        "schema_version": "autolean.ifem-source-free-deepseek-operator.v1",
        "mode": mode,
        "status": status,
        "plan_content_sha256": None if plan is None else plan.content_sha256,
        "stage_role": "statement_formalizer",
        "coordinate_count": 1,
        "maximum_authorized_provider_attempts": 1,
        "max_attempts_per_stage": 1,
        "attempt_binding_observed": attempt_binding_observed,
        "completion_settlement_observed": completion_settlement_observed,
        "private_stage_ledger_commitment_sha256": (private_stage_ledger_commitment_sha256),
        "private_attempt_binding_commitment_sha256": (private_attempt_binding_commitment_sha256),
        "private_completion_binding_commitment_sha256": (
            private_completion_binding_commitment_sha256
        ),
        "private_completion_verified": private_completion_verified,
        "actual_provider_dispatch_count_claimed": False,
        "raw_response_disclosed": False,
        "model_identity_disclosed": False,
        "machine_advisory_disposition": "abstain",
        "authority": SourceFreeDeepSeekAuthorityV1().model_dump(mode="json"),
        "builder_freeze": "forbidden",
        "prover_handoff": "forbidden",
        "failure_class": failure_class,
    }
    payload["content_sha256"] = _sha256_json(payload)
    return SourceFreeDeepSeekPublicReportV1.model_validate(payload)


def _failure_class(error: BaseException, transport: _RedactingTransport | None = None) -> str:
    if transport is not None:
        transport_failure = transport.failure_class
        if transport_failure is not None and transport_failure != "http_ok":
            return transport_failure
    if isinstance(error, OperatorApprovalRequired):
        return "operator_approval_required"
    if isinstance(error, OperatorSecretUnavailable):
        return "secret_reference_unavailable"
    if isinstance(error, OperatorRootRejected):
        return "root_policy_rejected"
    if isinstance(error, (SourceFreeModelWorkReconciliationRequired, SourceFreeStageLedgerError)):
        return "private_reconciliation_required"
    if isinstance(error, OperatorPrivateStateUnavailable):
        return "private_state_unavailable"
    if isinstance(error, (SourceFreeModelWorkError, SourceFreePrivateSeedError)):
        return "operator_policy_rejected"
    if isinstance(error, ProviderResponseError):
        return "provider_response_rejected"
    return "internal_unclassified"


def _http_failure_class(status_code: int) -> str:
    if status_code == 429:
        return "http_429"
    if 500 <= status_code <= 599:
        return "http_5xx"
    if 400 <= status_code <= 499:
        return "http_4xx"
    return "http_status_other"


@dataclass(frozen=True, slots=True)
class _VerifiedCanaryCommitments:
    stage_ledger: str
    attempt_binding: str
    completion_binding: str


def _attempt_and_settlement_observed(runtime: _PreparedRuntime) -> tuple[bool, bool]:
    """Read durable attempt/settlement presence without parsing or exposing the response."""

    attempt = runtime.attempt_store.load(runtime.coordinate)
    if attempt is None:
        return False, False
    try:
        handle = runtime.authorization_service.completion_recovery_handle_for_authorization(
            attempt.authorization
        )
    except Exception:
        return True, False
    return True, handle is not None


def _verified_canary_commitments(
    runtime: _PreparedRuntime,
) -> _VerifiedCanaryCommitments:
    """Bind a successful public result to exact private readback without provider I/O."""

    if runtime.ledger.state_for(runtime.coordinate) is not (
        SourceFreeStageLedgerStateV1.COMPLETION_COMMITTED
    ):
        raise SourceFreeModelWorkReconciliationRequired(
            "source-free canary ledger has no committed completion"
        )
    attempt = runtime.attempt_store.load(runtime.coordinate)
    if attempt is None:
        raise SourceFreeModelWorkReconciliationRequired(
            "source-free canary ledger lacks its durable attempt"
        )
    completion = runtime.sidecar.recover(runtime.coordinate)
    before = runtime.ledger.public_projection()
    after = runtime.ledger.reconcile_completion(runtime.coordinate, completion)
    if (
        before != after
        or after.completion_committed_count != 1
        or after.pending_count != 26
        or after.reconciliation_required_count != 0
    ):
        raise SourceFreeModelWorkReconciliationRequired(
            "source-free canary private evidence does not form one exact completion"
        )
    return _VerifiedCanaryCommitments(
        stage_ledger=after.private_ledger_commitment_sha256,
        attempt_binding=attempt.content_sha256,
        completion_binding=completion.binding_content_sha256,
    )


def _run_single_coordinate(
    runtime: _PreparedRuntime,
) -> SourceFreeDeepSeekPublicReportV1:
    runtime.ledger.execute_coordinate(
        runtime.coordinate,
        runtime.sidecar.execute_once,
    )
    state = runtime.ledger.state_for(runtime.coordinate)
    if state is SourceFreeStageLedgerStateV1.COMPLETION_COMMITTED:
        try:
            commitments = _verified_canary_commitments(runtime)
        except Exception as error:
            return _report(
                "run",
                "reconciliation_required",
                plan=runtime.plan,
                attempt_binding_observed=True,
                completion_settlement_observed=True,
                failure_class=_failure_class(error, runtime.diagnostic_transport),
            )
        return _report(
            "run",
            "settled",
            plan=runtime.plan,
            attempt_binding_observed=True,
            completion_settlement_observed=True,
            private_stage_ledger_commitment_sha256=commitments.stage_ledger,
            private_attempt_binding_commitment_sha256=commitments.attempt_binding,
            private_completion_binding_commitment_sha256=commitments.completion_binding,
            private_completion_verified=True,
        )
    if state is SourceFreeStageLedgerStateV1.RECONCILIATION_REQUIRED:
        attempt_observed, settlement_observed = _attempt_and_settlement_observed(runtime)
        return _report(
            "run",
            "reconciliation_required",
            plan=runtime.plan,
            attempt_binding_observed=attempt_observed,
            completion_settlement_observed=settlement_observed,
            failure_class=(
                "settled_completion_rejected"
                if settlement_observed
                else "private_reconciliation_required"
            ),
        )
    return _report(
        "run",
        "reconciliation_required",
        plan=runtime.plan,
        failure_class="private_reconciliation_required",
    )


def _resume_single_coordinate(runtime: _PreparedRuntime) -> SourceFreeDeepSeekPublicReportV1:
    state = runtime.ledger.state_for(runtime.coordinate)
    if state in {
        SourceFreeStageLedgerStateV1.DISPATCH_STARTED,
        SourceFreeStageLedgerStateV1.RECONCILIATION_REQUIRED,
        SourceFreeStageLedgerStateV1.COMPLETION_COMMITTED,
    }:
        try:
            completion = runtime.sidecar.recover(runtime.coordinate)
            runtime.ledger.reconcile_completion(runtime.coordinate, completion)
            commitments = _verified_canary_commitments(runtime)
        except Exception as error:
            attempt_observed, settlement_observed = _attempt_and_settlement_observed(runtime)
            return _report(
                "resume",
                "reconciliation_required",
                plan=runtime.plan,
                attempt_binding_observed=attempt_observed,
                completion_settlement_observed=settlement_observed,
                failure_class=(
                    "settled_completion_rejected" if settlement_observed else _failure_class(error)
                ),
            )
        return _report(
            "resume",
            "recovered",
            plan=runtime.plan,
            attempt_binding_observed=True,
            completion_settlement_observed=True,
            private_stage_ledger_commitment_sha256=commitments.stage_ledger,
            private_attempt_binding_commitment_sha256=commitments.attempt_binding,
            private_completion_binding_commitment_sha256=commitments.completion_binding,
            private_completion_verified=True,
        )
    return _report(
        "resume",
        "reconciliation_required",
        plan=runtime.plan,
        failure_class="private_reconciliation_required",
    )


def _read_existing_report(
    config: SourceFreeDeepSeekOperatorConfig,
    plan: SourceFreeDeepSeekPlan,
) -> SourceFreeDeepSeekPublicReportV1:
    _require_existing_operator_root(config.state_root)
    _load_and_verify_run_marker(config, plan)
    database = config.state_root / "control-plane.sqlite3"
    _require_private_regular_file(database)
    try:
        database_uri = f"{database.resolve(strict=True).as_uri()}?mode=ro"
        with sqlite3.connect(database_uri, uri=True) as connection:
            attempts = int(
                connection.execute(
                    "SELECT COUNT(*) FROM events WHERE entity_type = ?",
                    ("ifem_source_free_model_work_attempt",),
                ).fetchone()[0]
            )
            settlement_row = connection.execute(
                "SELECT COUNT(*) FROM model_execution_completion_settlements"
            ).fetchone()
            settlements = int(settlement_row[0])
    except (sqlite3.Error, TypeError, IndexError) as error:
        raise OperatorPrivateStateUnavailable(
            "source-free state database is unavailable"
        ) from error
    return _report(
        "report",
        "report_ready",
        plan=plan,
        attempt_binding_observed=attempts == 1,
        completion_settlement_observed=settlements == 1,
        private_completion_verified=False,
    )


def execute_source_free_deepseek_operator(
    config: SourceFreeDeepSeekOperatorConfig,
    *,
    environment: Mapping[str, str] | None = None,
    transport: ResponsesTransport | None = None,
) -> SourceFreeDeepSeekPublicReportV1:
    """Run one explicit mode; only ``run`` resolves the named API-key environment variable."""

    plan: SourceFreeDeepSeekPlan | None = None
    try:
        plan = build_source_free_deepseek_plan()
        if config.mode == "plan":
            return _report("plan", "planned", plan=plan)
        if config.mode == "preflight":
            return _report("preflight", "preflight_ready", plan=plan)
        if config.mode == "report":
            return _read_existing_report(config, plan)
        source_environment = os.environ if environment is None else environment
        if config.mode == "run":
            if config.operator_approved is not True:
                raise OperatorApprovalRequired("explicit operator approval is required")
            runtime = _prepare_runtime(
                config,
                plan,
                mode="run",
                environment=source_environment,
                transport=transport,
            )
            return _run_single_coordinate(runtime)
        runtime = _prepare_runtime(
            config,
            plan,
            mode="resume",
            environment={},
            transport=None,
        )
        return _resume_single_coordinate(runtime)
    except Exception as error:
        return _report(
            config.mode,
            "execution_refused",
            plan=plan,
            failure_class=_failure_class(error),
        )


def render_source_free_deepseek_public_report(report: SourceFreeDeepSeekPublicReportV1) -> bytes:
    if type(report) is not SourceFreeDeepSeekPublicReportV1:
        raise SourceFreeDeepSeekOperatorError("public report requires its exact type")
    value = SourceFreeDeepSeekPublicReportV1.model_validate(report.model_dump(mode="json"))
    rendered = canonical_json_bytes(value.model_dump(mode="json")) + b"\n"
    if any(field in rendered for field in _FORBIDDEN_PUBLIC_FIELDS):
        raise SourceFreeDeepSeekOperatorError("public report leaked private operator data")
    return rendered


class _RedactedArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        del message
        raise SourceFreeDeepSeekOperatorError("invalid CLI arguments")


def _parser() -> argparse.ArgumentParser:
    parser = _RedactedArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "preflight", "run", "resume", "report"))
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--private-root", type=Path, required=True)
    parser.add_argument("--run-label", default="ifem-source-free-deepseek-v1")
    parser.add_argument("--operator-approved", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    mode: OperatorMode = "plan"
    try:
        arguments = _parser().parse_args(argv)
        mode = cast(OperatorMode, arguments.mode)
        config = SourceFreeDeepSeekOperatorConfig(
            mode=mode,
            state_root=arguments.state_root,
            private_root=arguments.private_root,
            run_label=arguments.run_label,
            operator_approved=arguments.operator_approved,
        )
        report = execute_source_free_deepseek_operator(config)
    except Exception as error:
        report = _report(
            mode,
            "execution_refused",
            plan=None,
            failure_class=_failure_class(error),
        )
    print(render_source_free_deepseek_public_report(report).decode("ascii"), end="")
    successful_statuses = {
        "planned",
        "preflight_ready",
        "settled",
        "recovered",
        "report_ready",
    }
    return 0 if report.status in successful_statuses else 2


if __name__ == "__main__":
    raise SystemExit(main())
