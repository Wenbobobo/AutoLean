"""Run the locked five-role suite through the authorized DeepSeek operator path.

This is an operator experiment, not a score, a role-floor admission, or production
authority.  Ten answer-free trials are preflighted as one immutable set before the
existing bridge mints any just-in-time ModelWork capability.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import stat
import sys
from collections.abc import Callable, Mapping, Sequence
from contextlib import closing
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Never, Self

import httpx
from autolean_contracts import (
    AttestationPurposeV1,
    AttestationV1,
    ContractModel,
    EndpointClassV1,
    HmacAttestationKeyV1,
    HmacAttestationSignerV1,
    HmacAttestationVerifierV1,
    ModelExecutionBudgetV1,
    ModelExecutionPricingV1,
    ModelExecutionProviderApprovalV1,
    ModelExecutionProviderBindingV1,
    ModelWorkRoleV1,
    canonical_json_bytes,
    model_work_admission_evidence_identity,
    model_work_admission_payload,
    stable_identifier,
)
from autolean_control_plane import (
    ArtifactStore,
    ControlPlane,
    EventStore,
    LeaseStore,
    ModelExecutionAuthorizationService,
)
from autolean_prover.errors import (
    CapabilityError,
    ConfigurationError,
    PolicyViolation,
    ProviderResponseError,
)
from autolean_prover.providers import (
    Capability,
    ChatCompletionsOperatorProfileV1,
    LocalPrivateModelOutputStore,
    ModelExecutionCompletionRecoveryRequired,
    ModelProvider,
    ProviderRegistry,
    StaticCapabilityProbe,
)
from autolean_prover.providers.responses import HttpxResponsesTransport, ResponsesTransport
from pydantic import Field, model_validator

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(_REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPOSITORY_ROOT))

from benchmarks.authorized_role_bridge import (  # noqa: E402
    AuthorizedRoleBridgeError,
    AuthorizedRoleCompletionManifestStoreV2,
    AuthorizedRoleGenerationPolicyV1,
    AuthorizedRoleReconciliationRequired,
    AuthorizedRoleSuiteDefinition,
    AuthorizedRoleSuiteSidecarV3,
    PreparedAuthorizedRoleTrial,
    TestOnlyHmacPrivateManifestAuthenticator,
    authorized_role_elapsed_bucket,
    authorized_role_token_bucket,
    build_locked_calibration_floor_suite,
    is_safe_authorized_role_run_id,
    prepare_locked_floor_trials,
    run_completed_authorized_role_floor_suite,
)
from benchmarks.role_benchmark import RoleModelTargetV1  # noqa: E402

_SCHEMA_VERSION = "autolean.deepseek-role-operator.v1"
_PROFILE_PATH = (
    Path(__file__).resolve().parents[1]
    / "Prover"
    / "operator-profiles"
    / "deepseek-v4-pro.chat-completions.v1.json"
)
_REGISTRY_NAME = "deepseek-v4-pro"
_MODEL_REVISION = "deepseek-v4-pro-api-alias-unpinned"
_API_KEY_ENV = "AUTOLEAN_DEEPSEEK_API_KEY"
_MANIFEST_KEY_ENV = "AUTOLEAN_ROLE_MANIFEST_HMAC_KEY"
_AUTHORITY_STATUS = "non-promotable-ephemeral-local-hmac"
_CAPABILITY_EVIDENCE_CLASS = "static_declared_only"
_ROLE_FLOOR_ADMISSION = "forbidden"
_SCORE_STATUS = "not_computed"
_SETTLEMENT_MARGIN_SECONDS = 30
_AUTHORIZATION_TTL_SECONDS = 150
_LEASE_TTL_SECONDS = 180
_ADMISSION_TTL_SECONDS = 3600
_PRICE_BOUND_MICROUSD_PER_TOKEN = 10
_RUN_ID = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
_PUBLIC_RUN_ID = r"^(unavailable|[a-z0-9][a-z0-9_.-]{0,63})$"
_SHA256 = r"^[0-9a-f]{64}$"
_SAFE_FAILURE = r"^[a-z][a-z0-9_]{0,63}$"
_TOKEN_BUCKET = r"^(not_available|zero|1_255|256_1023|1024_4095|4096_16383|16384_plus)$"
_ELAPSED_BUCKET = r"^(not_available|under_1s|1s_9s|10s_59s|60s_299s|300s_plus)$"
_ROOT_INITIALIZING_MARKER = ".autolean-root-initializing-v1"
_ROOT_READY_MARKER = ".autolean-root-ready-v1"
_MODEL_WORK_STATE_TABLES = (
    "model_execution_authorizations",
    "model_execution_work_bundles",
    "model_execution_work_idempotency",
    "model_execution_authorization_idempotency",
    "model_execution_authorization_ledger",
    "model_execution_provider_health_ledger",
    "model_execution_completion_settlements",
    "model_execution_completion_receipts",
    "worker_leases",
)
_HTTP_FAILURE_CLASSES = {
    400: "http_400",
    401: "http_401",
    402: "http_402",
    403: "http_403",
    404: "http_404",
    409: "http_409",
    422: "http_422",
    429: "http_429",
}


class DeepSeekRoleOperatorError(ValueError):
    """The operator request failed before any provider result could be published."""


class OperatorApprovalRequired(DeepSeekRoleOperatorError):
    """The explicit human approval switch was absent."""


class OperatorRootRejected(DeepSeekRoleOperatorError):
    """An operator root was unsafe or inside the source checkout."""


class OperatorSecretUnavailable(DeepSeekRoleOperatorError):
    """One of the two named operator secret references was unavailable."""


class OperatorStateNotClean(DeepSeekRoleOperatorError):
    """The dedicated state root already contains model-execution state."""


class ProviderTimeoutPolicyRejected(DeepSeekRoleOperatorError):
    """The registered provider cannot enforce the frozen role timeout."""


class OperatorInitializationQuarantined(DeepSeekRoleOperatorError):
    """Initialization roots were moved aside for explicit operator review."""


class OperatorInitializationQuarantineFailed(DeepSeekRoleOperatorError):
    """Initialization state could not be safely quarantined and needs manual review."""


class DeepSeekRolePerTrialBudgetV1(ContractModel):
    schema_version: Literal["autolean.deepseek-role-per-trial-budget.v1"] = (
        "autolean.deepseek-role-per-trial-budget.v1"
    )
    max_attempts: Literal[1] = 1
    max_input_tokens: Literal[512] = 512
    max_output_tokens: Literal[256, 512, 1024] = 256
    model_timeout_seconds: Literal[120] = 120
    settlement_margin_seconds: Literal[30] = 30
    authorization_ttl_seconds: Literal[150] = 150
    lease_ttl_seconds: Literal[180] = 180
    max_cost_microusd: int = Field(ge=0)


class DeepSeekRoleUsageBucketsV1(ContractModel):
    schema_version: Literal["autolean.deepseek-role-usage-buckets.v1"] = (
        "autolean.deepseek-role-usage-buckets.v1"
    )
    input_tokens: str = Field(pattern=_TOKEN_BUCKET)
    cached_input_tokens: str = Field(pattern=_TOKEN_BUCKET)
    output_tokens: str = Field(pattern=_TOKEN_BUCKET)
    elapsed_ms: str = Field(pattern=_ELAPSED_BUCKET)


class DeepSeekRoleSeparatedSidecarV1(ContractModel):
    schema_version: Literal["autolean.deepseek-role-separated-sidecar.v1"] = (
        "autolean.deepseek-role-separated-sidecar.v1"
    )
    role: ModelWorkRoleV1
    trial_count: Literal[2] = 2
    role_plan_hash: str = Field(pattern=_SHA256)
    trial_sidecar_hashes: tuple[str, ...] = ()
    usage: DeepSeekRoleUsageBucketsV1

    @model_validator(mode="after")
    def validate_trial_state(self) -> Self:
        hashes = self.trial_sidecar_hashes
        if hashes:
            if (
                len(hashes) != 2
                or hashes != tuple(sorted(hashes))
                or len(set(hashes)) != 2
                or any(re.fullmatch(_SHA256, item) is None for item in hashes)
                or "not_available" in self.usage.model_dump().values()
            ):
                raise ValueError("settled role sidecar requires two hashes and usage")
        elif set(self.usage.model_dump().values()) != {
            "autolean.deepseek-role-usage-buckets.v1",
            "not_available",
        }:
            raise ValueError("unsettled role sidecar cannot expose usage")
        return self


class DeepSeekRolePublicReportV2(ContractModel):
    """Answer-free stdout contract; exact outputs and accounting remain private."""

    schema_version: Literal["autolean.deepseek-role-operator.v2"] = (
        "autolean.deepseek-role-operator.v2"
    )
    mode: Literal["plan", "preflight", "run"]
    status: Literal[
        "planned",
        "preflight_ready",
        "settled",
        "execution_refused",
        "reconciliation_required",
    ]
    run_id: str = Field(pattern=_PUBLIC_RUN_ID)
    provider_id: Literal["deepseek"] = "deepseek"
    model_id: Literal["deepseek-v4-pro"] = "deepseek-v4-pro"
    model_revision: Literal["deepseek-v4-pro-api-alias-unpinned"] = (
        "deepseek-v4-pro-api-alias-unpinned"
    )
    endpoint_class: Literal["approved_external"] = "approved_external"
    authority_status: Literal["non-promotable-ephemeral-local-hmac"] = (
        "non-promotable-ephemeral-local-hmac"
    )
    capability_evidence_class: Literal["static_declared_only"] = "static_declared_only"
    role_floor_admission: Literal["forbidden"] = "forbidden"
    score_status: Literal["not_computed"] = "not_computed"
    promotion_eligible: Literal[False] = False
    floor_claim_eligible: Literal[False] = False
    production_authority: Literal[False] = False
    automatic_retry_permitted: Literal[False] = False
    trial_count: Literal[10] = 10
    plan_hash: str | None = Field(default=None, pattern=_SHA256)
    per_trial_budget: DeepSeekRolePerTrialBudgetV1 | None = None
    roles: tuple[DeepSeekRoleSeparatedSidecarV1, ...] = ()
    private_evidence_committed: bool = False
    failure_class: str | None = Field(default=None, pattern=_SAFE_FAILURE)

    @model_validator(mode="after")
    def validate_status_boundary(self) -> Self:
        role_values = tuple(item.role.value for item in self.roles)
        if self.roles and (
            len(self.roles) != 5
            or role_values != tuple(sorted(role_values))
            or len(set(role_values)) != 5
        ):
            raise ValueError("public role sidecars must cover five sorted roles")
        successful = self.status in {"planned", "preflight_ready", "settled"}
        if successful != (self.failure_class is None):
            raise ValueError("public status and failure_class are inconsistent")
        if self.status == "settled":
            if (
                self.mode != "run"
                or not self.private_evidence_committed
                or len(self.roles) != 5
                or any(len(item.trial_sidecar_hashes) != 2 for item in self.roles)
            ):
                raise ValueError("settled report lacks complete private and role evidence")
        elif self.private_evidence_committed:
            raise ValueError("unsettled report cannot claim committed private evidence")
        if self.status == "planned" and self.mode != "plan":
            raise ValueError("planned status requires plan mode")
        if self.status == "preflight_ready" and self.mode != "preflight":
            raise ValueError("preflight_ready status requires preflight mode")
        return self


@dataclass(frozen=True, slots=True)
class _OperatorParentSnapshot:
    path: Path
    device: int
    inode: int


@dataclass(frozen=True, slots=True)
class DeepSeekRoleOperatorConfig:
    mode: Literal["plan", "preflight", "run"]
    run_id: str
    state_root: Path
    private_root: Path
    max_cost_microusd_per_trial: int
    operator_approved: bool
    max_output_tokens: Literal[256, 512, 1024] = 256
    state_parent: _OperatorParentSnapshot = field(init=False, repr=False)
    private_parent: _OperatorParentSnapshot = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.operator_approved is not True:
            raise OperatorApprovalRequired("explicit operator approval is required")
        if not _is_safe_run_id(self.run_id):
            raise DeepSeekRoleOperatorError("run_id is not a safe identifier")
        if (
            isinstance(self.max_cost_microusd_per_trial, bool)
            or not isinstance(self.max_cost_microusd_per_trial, int)
            or self.max_cost_microusd_per_trial < 0
        ):
            raise DeepSeekRoleOperatorError(
                "max_cost_microusd_per_trial must be a non-negative integer"
            )
        if self.max_output_tokens not in (256, 512, 1024):
            raise DeepSeekRoleOperatorError("max_output_tokens is not an approved ablation value")
        state_root, state_parent = _validated_operator_root(self.state_root, label="state")
        private_root, private_parent = _validated_operator_root(self.private_root, label="private")
        if (
            state_root == private_root
            or _is_relative_to(state_root, private_root)
            or _is_relative_to(private_root, state_root)
        ):
            raise OperatorRootRejected("state and private roots must be disjoint")
        object.__setattr__(self, "state_root", state_root)
        object.__setattr__(self, "private_root", private_root)
        object.__setattr__(self, "state_parent", state_parent)
        object.__setattr__(self, "private_parent", private_parent)


@dataclass(frozen=True, slots=True)
class DeepSeekRolePlan:
    config: DeepSeekRoleOperatorConfig
    profile: ChatCompletionsOperatorProfileV1
    generation_policy: AuthorizedRoleGenerationPolicyV1
    suite: AuthorizedRoleSuiteDefinition
    trials: tuple[PreparedAuthorizedRoleTrial, ...]
    budgets_by_cell: dict[str, ModelExecutionBudgetV1]
    role_plan_hashes: dict[ModelWorkRoleV1, str]
    plan_hash: str
    provider_timeout_override_seconds: float | None


@dataclass(slots=True)
class PreparedDeepSeekRoleOperator:
    plan: DeepSeekRolePlan
    authorization_service: ModelExecutionAuthorizationService
    registry: ProviderRegistry
    approval: ModelExecutionProviderApprovalV1
    admissions_by_bundle_id: dict[str, AttestationV1]
    output_store: LocalPrivateModelOutputStore
    completion_manifest_store: AuthorizedRoleCompletionManifestStoreV2
    diagnostic_transport: RedactingDiagnosticTransport
    state_database: Path


@dataclass(frozen=True, slots=True)
class DeepSeekRolePrivateRun:
    """A public report plus a same-process-only suite sidecar for trusted local evaluation.

    ``suite_sidecar`` carries an opaque private manifest handle.  It must never reach CLI stdout,
    a public artifact, or a restart boundary.  The optional exact evaluator uses it only while the
    matching private authenticator and output store still live in this process.
    """

    report: DeepSeekRolePublicReportV2
    suite_sidecar: AuthorizedRoleSuiteSidecarV3 | None


@dataclass(frozen=True, slots=True)
class _OwnedOperatorRoot:
    path: Path
    device: int
    inode: int
    token: bytes
    parent: _OperatorParentSnapshot

    @property
    def initializing_marker(self) -> Path:
        return self.path / _ROOT_INITIALIZING_MARKER

    @property
    def ready_marker(self) -> Path:
        return self.path / _ROOT_READY_MARKER


class _NoIoTransport:
    def post_json(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        payload: Mapping[str, object],
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        del url, headers, payload, timeout_seconds
        raise AssertionError("plan construction must not perform provider I/O")


class RedactingDiagnosticTransport:
    """Retain only a stable failure category, never an exception message."""

    def __init__(self, delegate: ResponsesTransport) -> None:
        self._delegate = delegate
        self._failure_class: str | None = None

    @property
    def failure_class(self) -> str:
        return self._failure_class or "provider_response_unclassified"

    def reset_failure(self) -> None:
        self._failure_class = None

    def post_json(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        payload: Mapping[str, object],
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        self._failure_class = None
        try:
            response = self._delegate.post_json(
                url=url,
                headers=headers,
                payload=payload,
                timeout_seconds=timeout_seconds,
            )
        except httpx.HTTPStatusError as error:
            self._failure_class = _http_failure_class(error.response.status_code)
            raise
        except httpx.TimeoutException:
            self._failure_class = "timeout"
            raise
        except httpx.RequestError:
            self._failure_class = "network"
            raise
        except (json.JSONDecodeError, UnicodeDecodeError, ProviderResponseError):
            self._failure_class = "invalid_json"
            raise
        except Exception:
            self._failure_class = "transport_unclassified"
            raise
        self._failure_class = "http_ok"
        return response


def _now() -> datetime:
    return datetime.now(UTC)


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _is_safe_run_id(value: object) -> bool:
    return (
        is_safe_authorized_role_run_id(value)
        and isinstance(value, str)
        and _RUN_ID.fullmatch(value) is not None
    )


def _is_link_or_reparse_point(path: Path) -> bool:
    metadata = os.lstat(path)
    if stat.S_ISLNK(metadata.st_mode):
        return True
    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction) and is_junction():
        return True
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    return bool(attributes & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)))


def _physical_directory_identity(path: Path) -> tuple[int, int]:
    metadata = os.stat(path, follow_symlinks=False)
    if not stat.S_ISDIR(metadata.st_mode) or _is_link_or_reparse_point(path):
        raise OperatorRootRejected("operator path is not a physical directory")
    return metadata.st_dev, metadata.st_ino


def _assert_physical_parent_chain(path: Path) -> None:
    current = path
    while True:
        if _is_link_or_reparse_point(current):
            raise OperatorRootRejected("operator root parent chain contains a link")
        if current == Path(current.anchor):
            return
        current = current.parent


def _validated_operator_root(
    path: Path,
    *,
    label: str,
) -> tuple[Path, _OperatorParentSnapshot]:
    if not isinstance(path, Path) or not path.is_absolute():
        raise OperatorRootRejected(f"{label} root must be absolute")
    unresolved = path.absolute()
    if not unresolved.parent.is_dir():
        raise OperatorRootRejected(f"{label} root parent must already exist")
    _assert_physical_parent_chain(unresolved.parent)
    resolved_parent = unresolved.parent.resolve(strict=True)
    _assert_physical_parent_chain(resolved_parent)
    parent_identity = _physical_directory_identity(resolved_parent)
    resolved = resolved_parent / unresolved.name
    repository = _REPOSITORY_ROOT.resolve(strict=True)
    if resolved == Path(resolved.anchor) or _is_relative_to(resolved, repository):
        raise OperatorRootRejected(f"{label} root must be outside the source checkout")
    if resolved.exists() and (_is_link_or_reparse_point(resolved) or not resolved.is_dir()):
        raise OperatorRootRejected(f"{label} root must identify a physical directory")
    return resolved, _OperatorParentSnapshot(
        path=resolved_parent,
        device=parent_identity[0],
        inode=parent_identity[1],
    )


def _parent_snapshot_matches(snapshot: _OperatorParentSnapshot) -> bool:
    try:
        if snapshot.path.resolve(strict=True) != snapshot.path:
            return False
        _assert_physical_parent_chain(snapshot.path)
        return _physical_directory_identity(snapshot.path) == (
            snapshot.device,
            snapshot.inode,
        )
    except (OSError, OperatorRootRejected):
        return False


def _assert_parent_snapshot(snapshot: _OperatorParentSnapshot) -> None:
    if not _parent_snapshot_matches(snapshot):
        raise OperatorRootRejected("operator root parent identity changed")


def _assert_fresh_operator_roots(config: DeepSeekRoleOperatorConfig) -> None:
    """Require roots that this invocation can exclusively create and own."""

    for root, parent in (
        (config.state_root, config.state_parent),
        (config.private_root, config.private_parent),
    ):
        _assert_parent_snapshot(parent)
        if root.exists():
            raise OperatorStateNotClean("operator roots must not already exist")


def _root_identity(path: Path) -> tuple[int, int]:
    return _physical_directory_identity(path)


def _claim_operator_root(
    path: Path,
    *,
    parent: _OperatorParentSnapshot,
) -> _OwnedOperatorRoot:
    """Create one root while continuously binding it to the snapshotted physical parent."""

    _assert_parent_snapshot(parent)
    try:
        path.mkdir()
    except FileExistsError:
        raise OperatorStateNotClean("operator root was concurrently created") from None
    try:
        _assert_parent_snapshot(parent)
        if path.parent != parent.path or path.resolve(strict=False).parent != parent.path:
            raise OperatorRootRejected("operator root parent changed during claim")
        identity = _root_identity(path)
        token = secrets.token_bytes(32)
        owned = _OwnedOperatorRoot(
            path=path,
            device=identity[0],
            inode=identity[1],
            token=token,
            parent=parent,
        )
        _assert_parent_snapshot(parent)
        with owned.initializing_marker.open("xb") as handle:
            handle.write(token)
            handle.flush()
            os.fsync(handle.fileno())
        _assert_parent_snapshot(parent)
    except BaseException:
        raise OperatorInitializationQuarantineFailed(
            "operator root claim requires manual review"
        ) from None
    return owned


def _owned_root_matches_at(owned: _OwnedOperatorRoot, path: Path) -> bool:
    try:
        if (
            not _parent_snapshot_matches(owned.parent)
            or path.parent != owned.parent.path
            or path.resolve(strict=False).parent != owned.parent.path
        ):
            return False
        if _root_identity(path) != (owned.device, owned.inode):
            return False
        markers = tuple(
            marker
            for marker in (
                path / _ROOT_INITIALIZING_MARKER,
                path / _ROOT_READY_MARKER,
            )
            if marker.is_file()
        )
        return len(markers) == 1 and hmac.compare_digest(markers[0].read_bytes(), owned.token)
    except OSError:
        return False


def _owned_root_matches(owned: _OwnedOperatorRoot) -> bool:
    return _owned_root_matches_at(owned, owned.path)


def _quarantine_owned_roots(roots: Sequence[_OwnedOperatorRoot]) -> tuple[Path, ...] | None:
    """Move owned roots aside atomically; runtime never deletes quarantine contents."""

    owned_roots = tuple(roots)
    if not all(_owned_root_matches(owned) for owned in owned_roots):
        return None
    quarantined: list[Path] = []
    for owned in reversed(owned_roots):
        if not _parent_snapshot_matches(owned.parent):
            return None
        quarantine = owned.path.with_name(
            f".{owned.path.name}.autolean-quarantine-{secrets.token_hex(16)}"
        )
        if quarantine.exists():
            return None
        try:
            owned.path.rename(quarantine)
        except OSError:
            return None
        if not _owned_root_matches_at(owned, quarantine):
            return None
        quarantined.append(quarantine)
    return tuple(quarantined)


def _publish_owned_root(owned: _OwnedOperatorRoot) -> None:
    if (
        not _parent_snapshot_matches(owned.parent)
        or not _owned_root_matches(owned)
        or owned.ready_marker.exists()
    ):
        raise OperatorStateNotClean("operator root ownership changed before publication")
    owned.initializing_marker.rename(owned.ready_marker)
    if not _parent_snapshot_matches(owned.parent) or not _owned_root_matches(owned):
        raise OperatorStateNotClean("operator root publication could not be verified")


def _publish_initialized_roots(roots: Sequence[_OwnedOperatorRoot]) -> None:
    """Publish lifecycle markers only after both roots are completely initialized."""

    if not all(_owned_root_matches(owned) for owned in roots):
        raise OperatorStateNotClean("operator root ownership changed during initialization")
    for owned in roots:
        _publish_owned_root(owned)


def _required_secret(
    environment: Mapping[str, str],
    name: str,
    *,
    min_bytes: int,
) -> bytes:
    value = environment.get(name)
    if not isinstance(value, str) or not value or "\r" in value or "\n" in value or "\x00" in value:
        raise OperatorSecretUnavailable("an operator secret reference is unavailable")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        raise OperatorSecretUnavailable("an operator secret reference is not valid UTF-8") from None
    if len(encoded) < min_bytes:
        raise OperatorSecretUnavailable("an operator secret reference is too short")
    return encoded


def _profile() -> ChatCompletionsOperatorProfileV1:
    profile = ChatCompletionsOperatorProfileV1.from_json_file(_PROFILE_PATH)
    if (
        profile.profile_id != "deepseek-v4-pro-canary"
        or profile.provider_id != "deepseek"
        or profile.model_id != "deepseek-v4-pro"
        or profile.endpoint_class is not EndpointClassV1.APPROVED_EXTERNAL
        or profile.api_key_env != _API_KEY_ENV
        or profile.timeout_seconds != 120
    ):
        raise DeepSeekRoleOperatorError("the fixed DeepSeek operator profile has drifted")
    return profile


def _provider_profile(
    profile: ChatCompletionsOperatorProfileV1,
    timeout_override_seconds: float | None,
) -> ChatCompletionsOperatorProfileV1:
    if timeout_override_seconds is None:
        return profile
    return replace(profile, timeout_seconds=timeout_override_seconds)


def _content_hash(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _budget_sidecar(
    max_cost_microusd: int,
    max_output_tokens: Literal[256, 512, 1024] = 256,
) -> DeepSeekRolePerTrialBudgetV1:
    return DeepSeekRolePerTrialBudgetV1(
        max_cost_microusd=max_cost_microusd,
        max_output_tokens=max_output_tokens,
    )


def _unavailable_usage() -> DeepSeekRoleUsageBucketsV1:
    return DeepSeekRoleUsageBucketsV1(
        input_tokens="not_available",
        cached_input_tokens="not_available",
        output_tokens="not_available",
        elapsed_ms="not_available",
    )


def build_deepseek_role_plan(
    config: DeepSeekRoleOperatorConfig,
    *,
    _provider_timeout_override_seconds: float | None = None,
) -> DeepSeekRolePlan:
    """Build the locked answer-free plan without secrets, state writes, or provider I/O."""

    profile = _profile()
    provider_profile = _provider_profile(profile, _provider_timeout_override_seconds)
    provider = provider_profile.create_provider(transport=_NoIoTransport(), environment={})
    generation_policy = AuthorizedRoleGenerationPolicyV1(
        reasoning_effort=profile.default_reasoning_effort,
        response_format="json_object",
        output_contract="role_json_v1",
        timeout_seconds=int(profile.timeout_seconds),
    )
    target = RoleModelTargetV1(
        provider_id=profile.provider_id,
        model_id=profile.model_id,
        model_revision=_MODEL_REVISION,
        provider_configuration_hash=provider.configuration_hash.value,
        generation_parameters_hash=generation_policy.content_hash(),
    )
    suite = build_locked_calibration_floor_suite(
        target,
        generation_policy=generation_policy,
        repetitions=1,
        max_cost_microusd_per_trial=config.max_cost_microusd_per_trial,
        max_output_tokens=config.max_output_tokens,
    )
    trials = prepare_locked_floor_trials(suite, run_id=config.run_id)
    budgets_by_cell = {
        cell.cell_id: ModelExecutionBudgetV1(
            max_attempts=1,
            max_input_tokens=cell.budget.max_input_tokens,
            max_output_tokens=cell.budget.max_output_tokens,
            max_total_tokens=cell.budget.max_input_tokens + cell.budget.max_output_tokens,
            max_cost_microusd=cell.budget.max_cost_microusd,
        )
        for cell in suite.matrix.cells
    }
    role_plan_hashes = {
        role: _content_hash(
            {
                "schema_version": "autolean.deepseek-role-plan-sidecar.v1",
                "role": role.value,
                "bundle_hashes": sorted(
                    trial.work_bundle.handoff_hash().value
                    for trial in trials
                    if trial.work_bundle.role is role
                ),
                "generation_policy_hash": generation_policy.content_hash(),
            }
        )
        for role in ModelWorkRoleV1
    }
    plan_hash = _content_hash(
        {
            "schema_version": "autolean.deepseek-role-plan.v1",
            "run_id": config.run_id,
            "provider_configuration_hash": provider.configuration_hash.value,
            "model_revision": _MODEL_REVISION,
            "suite_definition_hash": suite.work_evidence.suite_definition_hash,
            "generation_policy_hash": generation_policy.content_hash(),
            "per_trial_budget": _budget_sidecar(
                config.max_cost_microusd_per_trial,
                config.max_output_tokens,
            ).model_dump(mode="json"),
            "role_plan_hashes": {
                role.value: digest
                for role, digest in sorted(
                    role_plan_hashes.items(),
                    key=lambda item: item[0].value,
                )
            },
        }
    )
    return DeepSeekRolePlan(
        config=config,
        profile=profile,
        generation_policy=generation_policy,
        suite=suite,
        trials=trials,
        budgets_by_cell=budgets_by_cell,
        role_plan_hashes=role_plan_hashes,
        plan_hash=plan_hash,
        provider_timeout_override_seconds=_provider_timeout_override_seconds,
    )


def _base_role_sidecars(plan: DeepSeekRolePlan) -> tuple[DeepSeekRoleSeparatedSidecarV1, ...]:
    return tuple(
        DeepSeekRoleSeparatedSidecarV1(
            role=role,
            role_plan_hash=plan.role_plan_hashes[role],
            usage=_unavailable_usage(),
        )
        for role in sorted(ModelWorkRoleV1, key=lambda item: item.value)
    )


def _report_from_plan(
    plan: DeepSeekRolePlan,
    *,
    status: Literal[
        "planned",
        "preflight_ready",
        "execution_refused",
        "reconciliation_required",
    ],
    failure_class: str | None = None,
) -> DeepSeekRolePublicReportV2:
    return DeepSeekRolePublicReportV2(
        mode=plan.config.mode,
        status=status,
        run_id=plan.config.run_id,
        plan_hash=plan.plan_hash,
        per_trial_budget=_budget_sidecar(
            plan.config.max_cost_microusd_per_trial,
            plan.config.max_output_tokens,
        ),
        roles=_base_role_sidecars(plan),
        failure_class=failure_class,
    )


def _model_work_state_counts(database: Path) -> tuple[int, ...]:
    with closing(sqlite3.connect(database)) as connection:
        return tuple(
            int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in _MODEL_WORK_STATE_TABLES
        )


def _assert_clean_model_work_state(database: Path) -> None:
    if any(_model_work_state_counts(database)):
        raise OperatorStateNotClean("the dedicated state root already contains model work")


def _ephemeral_key(
    *,
    purpose: AttestationPurposeV1,
    label: str,
) -> HmacAttestationKeyV1:
    return HmacAttestationKeyV1(
        key_id=f"deepseek-role-ephemeral-{label}-{secrets.token_hex(8)}",
        secret=secrets.token_bytes(48),
        allowed_purposes=frozenset({purpose}),
    )


def _assert_budget_binding(plan: DeepSeekRolePlan, trial: PreparedAuthorizedRoleTrial) -> None:
    budget = plan.budgets_by_cell[trial.cell.cell_id]
    expected = ModelExecutionBudgetV1(
        max_attempts=1,
        max_input_tokens=trial.cell.budget.max_input_tokens,
        max_output_tokens=trial.cell.budget.max_output_tokens,
        max_total_tokens=trial.cell.budget.max_input_tokens + trial.cell.budget.max_output_tokens,
        max_cost_microusd=trial.cell.budget.max_cost_microusd,
    )
    if budget != expected:
        raise DeepSeekRoleOperatorError("per-trial budget differs from the locked role cell")


def _assert_model_binding(
    trial: PreparedAuthorizedRoleTrial,
    approval: ModelExecutionProviderApprovalV1,
) -> None:
    target = trial.cell.model
    binding = approval.binding
    if (
        target.provider_id != binding.provider_id
        or target.model_id != binding.model_id
        or target.model_revision != binding.model_revision
        or target.provider_configuration_hash != binding.configuration_hash.value
        or target.generation_parameters_hash != trial.generation_policy.content_hash()
    ):
        raise DeepSeekRoleOperatorError("role target differs from the approved provider binding")


def _pure_suite_preflight(
    plan: DeepSeekRolePlan,
    *,
    registry: ProviderRegistry,
    provider: ModelProvider,
    approval: ModelExecutionProviderApprovalV1,
    admissions_by_bundle_id: Mapping[str, AttestationV1],
    admission_verifier: HmacAttestationVerifierV1,
    clock: Callable[[], datetime],
) -> None:
    """Validate all ten trials before any control-plane or artifact state exists."""

    if len(plan.trials) != 10:
        raise DeepSeekRoleOperatorError("locked role plan must contain ten trials")
    expected_bundle_ids = {trial.work_bundle.bundle_id.value for trial in plan.trials}
    if set(admissions_by_bundle_id) != expected_bundle_ids:
        raise DeepSeekRoleOperatorError("admissions do not exactly cover the locked role plan")
    if set(plan.budgets_by_cell) != {cell.cell_id for cell in plan.suite.matrix.cells}:
        raise DeepSeekRoleOperatorError("budgets do not exactly cover the locked role cells")
    if not approval.enabled:
        raise DeepSeekRoleOperatorError("provider approval is disabled")
    if (
        plan.generation_policy.timeout_seconds + _SETTLEMENT_MARGIN_SECONDS
        > _AUTHORIZATION_TTL_SECONDS
        or _AUTHORIZATION_TTL_SECONDS > 3600
        or _LEASE_TTL_SECONDS < _AUTHORIZATION_TTL_SECONDS + 30
    ):
        raise DeepSeekRoleOperatorError("fixed role execution lifetimes are inconsistent")
    cumulative_validity = 0.0
    for trial in plan.trials:
        _assert_budget_binding(plan, trial)
        _assert_model_binding(trial, approval)
        effective_timeout = registry.effective_timeout_seconds(
            approval.binding,
            trial.request,
        )
        if effective_timeout != float(plan.generation_policy.timeout_seconds):
            raise ProviderTimeoutPolicyRejected(
                "provider effective timeout differs from the frozen role policy"
            )
        provider.capabilities.require(
            trial.request.inferred_capabilities() | {Capability.USAGE_ACCOUNTING},
            provider_id=provider.provider_id,
        )
        cumulative_validity += _LEASE_TTL_SECONDS
        admission = admissions_by_bundle_id[trial.work_bundle.bundle_id.value]
        if admission.evidence_identity != model_work_admission_evidence_identity(trial.work_bundle):
            raise DeepSeekRoleOperatorError("role admission does not bind the exact bundle")
        admission_verifier.verify(
            admission,
            expected_purpose=AttestationPurposeV1.MODEL_WORK_ADMISSION,
            payload=model_work_admission_payload(trial.work_bundle),
        )
        if (admission.expires_at - clock()).total_seconds() < cumulative_validity:
            raise DeepSeekRoleOperatorError(
                "role admission does not cover the cumulative execution window"
            )


def preflight_deepseek_role_operator(
    config: DeepSeekRoleOperatorConfig,
    *,
    environment: Mapping[str, str] | None = None,
    transport: ResponsesTransport | None = None,
    clock: Callable[[], datetime] = _now,
    _provider_timeout_override_seconds: float | None = None,
) -> PreparedDeepSeekRoleOperator:
    """Prepare all ten trials with zero provider I/O and zero ModelWork state."""

    plan = build_deepseek_role_plan(
        config,
        _provider_timeout_override_seconds=_provider_timeout_override_seconds,
    )
    source_environment = os.environ if environment is None else environment
    api_secret = _required_secret(source_environment, _API_KEY_ENV, min_bytes=1)
    manifest_secret = _required_secret(source_environment, _MANIFEST_KEY_ENV, min_bytes=32)
    if hmac.compare_digest(api_secret, manifest_secret):
        raise OperatorSecretUnavailable("operator API and manifest keys must be independent")
    filtered_environment = {_API_KEY_ENV: api_secret.decode("utf-8")}

    _assert_fresh_operator_roots(config)
    diagnostic_transport = RedactingDiagnosticTransport(
        HttpxResponsesTransport() if transport is None else transport
    )
    provider_profile = _provider_profile(
        plan.profile,
        plan.provider_timeout_override_seconds,
    )
    provider = provider_profile.create_provider(
        transport=diagnostic_transport,
        environment=filtered_environment,
    )

    model_key = _ephemeral_key(
        purpose=AttestationPurposeV1.MODEL_EXECUTION,
        label="model",
    )
    admission_key = _ephemeral_key(
        purpose=AttestationPurposeV1.MODEL_WORK_ADMISSION,
        label="admission",
    )
    completion_key = _ephemeral_key(
        purpose=AttestationPurposeV1.MODEL_EXECUTION_COMPLETION,
        label="completion",
    )
    model_verifier = HmacAttestationVerifierV1(
        {model_key.key_id: model_key},
        clock=clock,
    )
    admission_verifier = HmacAttestationVerifierV1(
        {admission_key.key_id: admission_key},
        clock=clock,
    )
    completion_verifier = HmacAttestationVerifierV1(
        {completion_key.key_id: completion_key},
        clock=clock,
    )
    approval = ModelExecutionProviderApprovalV1(
        approval_id=stable_identifier(
            "deepseek-role-provider",
            f"{config.run_id}:{provider.configuration_hash.value}",
        ),
        binding=ModelExecutionProviderBindingV1(
            registry_name=_REGISTRY_NAME,
            provider_id=provider.provider_id,
            model_id=provider.model_id,
            model_revision=_MODEL_REVISION,
            endpoint_class=EndpointClassV1.APPROVED_EXTERNAL,
            configuration_hash=provider.configuration_hash,
        ),
        pricing=ModelExecutionPricingV1(
            input_microusd_per_token=_PRICE_BOUND_MICROUSD_PER_TOKEN,
            cached_input_microusd_per_token=_PRICE_BOUND_MICROUSD_PER_TOKEN,
            output_microusd_per_token=_PRICE_BOUND_MICROUSD_PER_TOKEN,
        ),
        approved_by="operator-declared-role-candidate",
        approved_at=clock(),
    )
    pure_registry = ProviderRegistry()
    pure_registry.register(
        _REGISTRY_NAME,
        provider=provider,
        probe=StaticCapabilityProbe(provider.capabilities),
        endpoint_class=EndpointClassV1.APPROVED_EXTERNAL,
        model_revision=_MODEL_REVISION,
    )
    admission_signer = HmacAttestationSignerV1(admission_key, clock=clock)
    admissions_by_bundle_id = {
        trial.work_bundle.bundle_id.value: admission_signer.issue(
            purpose=AttestationPurposeV1.MODEL_WORK_ADMISSION,
            payload=model_work_admission_payload(trial.work_bundle),
            evidence_identity=model_work_admission_evidence_identity(trial.work_bundle),
            ttl_seconds=_ADMISSION_TTL_SECONDS,
        )
        for trial in plan.trials
    }
    _pure_suite_preflight(
        plan,
        registry=pure_registry,
        provider=provider,
        approval=approval,
        admissions_by_bundle_id=admissions_by_bundle_id,
        admission_verifier=admission_verifier,
        clock=clock,
    )
    _assert_fresh_operator_roots(config)

    owned_roots: list[_OwnedOperatorRoot] = []
    prepared: PreparedDeepSeekRoleOperator | None = None
    initialization_error: BaseException | None = None
    try:
        owned_roots.append(
            _claim_operator_root(
                config.state_root,
                parent=config.state_parent,
            )
        )
        owned_roots.append(
            _claim_operator_root(
                config.private_root,
                parent=config.private_parent,
            )
        )
        state_database = config.state_root / "control.db"
        control_plane = ControlPlane(
            events=EventStore(state_database, clock=clock),
            leases=LeaseStore(state_database, clock=clock),
            artifacts=ArtifactStore(config.state_root / "public-artifacts"),
            attestation_verifier=model_verifier,
        )
        output_store = LocalPrivateModelOutputStore(
            (config.private_root / "model-output-cas-v1").resolve()
        )
        authorization_service = ModelExecutionAuthorizationService(
            control_plane=control_plane,
            signer=HmacAttestationSignerV1(model_key, clock=clock),
            verifier=model_verifier,
            admission_verifier=admission_verifier,
            completion_signer=HmacAttestationSignerV1(completion_key, clock=clock),
            completion_verifier=completion_verifier,
            private_output_verifier=output_store,
            clock=clock,
            max_ttl_seconds=3600,
        )
        _assert_clean_model_work_state(state_database)
        authorization_service.register_operator_approval(
            approval,
            idempotency_key=(
                f"register-deepseek-role-{hashlib.sha256(config.run_id.encode()).hexdigest()[:24]}"
            ),
        )
        registry = ProviderRegistry(authorization_gate=authorization_service)
        registry.register(
            _REGISTRY_NAME,
            provider=provider,
            probe=StaticCapabilityProbe(provider.capabilities),
            endpoint_class=EndpointClassV1.APPROVED_EXTERNAL,
            model_revision=_MODEL_REVISION,
        )
        completion_manifest_store = AuthorizedRoleCompletionManifestStoreV2(
            config.private_root,
            private_authenticator=TestOnlyHmacPrivateManifestAuthenticator(manifest_secret),
        )
        prepared = PreparedDeepSeekRoleOperator(
            plan=plan,
            authorization_service=authorization_service,
            registry=registry,
            approval=approval,
            admissions_by_bundle_id=admissions_by_bundle_id,
            output_store=output_store,
            completion_manifest_store=completion_manifest_store,
            diagnostic_transport=diagnostic_transport,
            state_database=state_database,
        )
        if any(_model_work_state_counts(state_database)):
            raise DeepSeekRoleOperatorError("role preflight mutated ModelWork state")
        _publish_initialized_roots(owned_roots)
    except BaseException as error:
        initialization_error = error.with_traceback(None)
        initialization_error.__context__ = None
        initialization_error.__cause__ = None
    if initialization_error is not None:
        if owned_roots:
            quarantined = _quarantine_owned_roots(owned_roots)
            if quarantined is None:
                raise OperatorInitializationQuarantineFailed(
                    "operator initialization requires manual root reconciliation"
                ) from None
            raise OperatorInitializationQuarantined(
                "operator initialization was quarantined for manual review"
            ) from None
        raise initialization_error from None
    if prepared is None:
        raise DeepSeekRoleOperatorError("operator initialization produced no prepared run")
    return prepared


def _settled_role_sidecars(
    prepared: PreparedDeepSeekRoleOperator,
    suite_sidecar: AuthorizedRoleSuiteSidecarV3,
) -> tuple[DeepSeekRoleSeparatedSidecarV1, ...]:
    manifest = prepared.completion_manifest_store.read_manifest(
        suite_sidecar.private_manifest_handle
    )
    private_by_coordinate = {
        (entry.cell_id, entry.case_id, entry.repetition): entry for entry in manifest.outputs
    }
    sidecars: list[DeepSeekRoleSeparatedSidecarV1] = []
    for role in sorted(ModelWorkRoleV1, key=lambda item: item.value):
        role_trials = tuple(
            trial for trial in prepared.plan.trials if trial.work_bundle.role is role
        )
        public_trials = tuple(trial for trial in suite_sidecar.trials if trial.role is role)
        if len(role_trials) != 2 or len(public_trials) != 2:
            raise AuthorizedRoleReconciliationRequired(
                "settled role output does not contain two canonical trials"
            )
        entries = []
        for trial in role_trials:
            coordinate = (
                trial.context.cell_id,
                trial.context.case_id,
                trial.work_bundle.repetition,
            )
            entry = private_by_coordinate.get(coordinate)
            if entry is None:
                raise AuthorizedRoleReconciliationRequired(
                    "settled role output lacks a completion receipt"
                )
            receipt_authorization = entry.receipt.record.authorization
            if (
                receipt_authorization.bundle_id != trial.work_bundle.bundle_id
                or receipt_authorization.bundle_hash != trial.work_bundle.handoff_hash()
            ):
                raise AuthorizedRoleReconciliationRequired(
                    "settled role receipt is not bound to its immutable model work"
                )
            entries.append(entry)
        input_tokens = sum(entry.receipt.record.actual_usage.input_tokens for entry in entries)
        cached_tokens = sum(
            entry.receipt.record.actual_usage.cached_input_tokens for entry in entries
        )
        output_tokens = sum(entry.receipt.record.actual_usage.output_tokens for entry in entries)
        elapsed_ms = sum(entry.elapsed_ms for entry in entries)
        sidecars.append(
            DeepSeekRoleSeparatedSidecarV1(
                role=role,
                role_plan_hash=prepared.plan.role_plan_hashes[role],
                trial_sidecar_hashes=tuple(
                    sorted(_content_hash(trial.model_dump(mode="json")) for trial in public_trials)
                ),
                usage=DeepSeekRoleUsageBucketsV1(
                    input_tokens=authorized_role_token_bucket(input_tokens),
                    cached_input_tokens=authorized_role_token_bucket(cached_tokens),
                    output_tokens=authorized_role_token_bucket(output_tokens),
                    elapsed_ms=authorized_role_elapsed_bucket(elapsed_ms),
                ),
            )
        )
    return tuple(sidecars)


def _has_private_reconciliation(prepared: PreparedDeepSeekRoleOperator) -> bool:
    try:
        return any(_model_work_state_counts(prepared.state_database))
    except Exception:
        return True


def _failure_class(error: BaseException, diagnostic: RedactingDiagnosticTransport) -> str:
    transport_failure = diagnostic.failure_class
    if transport_failure not in {"provider_response_unclassified", "http_ok"}:
        return transport_failure
    if isinstance(error, ModelExecutionCompletionRecoveryRequired):
        return "completion_recovery_required"
    if isinstance(error, AuthorizedRoleReconciliationRequired):
        return "private_reconciliation_required"
    if isinstance(error, OperatorInitializationQuarantined):
        return "operator_initialization_quarantined"
    if isinstance(error, OperatorInitializationQuarantineFailed):
        return "operator_initialization_manual_review"
    if isinstance(error, OperatorStateNotClean):
        return "operator_state_not_clean"
    if isinstance(error, OperatorSecretUnavailable):
        return "secret_reference_unavailable"
    if isinstance(error, OperatorRootRejected):
        return "root_policy_rejected"
    if isinstance(error, OperatorApprovalRequired):
        return "operator_approval_required"
    if isinstance(error, ProviderTimeoutPolicyRejected):
        return "provider_timeout_policy_rejected"
    if isinstance(error, CapabilityError):
        return "capability_rejected"
    if isinstance(error, PolicyViolation):
        return "policy_rejected"
    if isinstance(error, ProviderResponseError):
        return "provider_response_rejected"
    if isinstance(error, ConfigurationError):
        return "configuration_rejected"
    if isinstance(error, AuthorizedRoleBridgeError):
        return "role_policy_rejected"
    if isinstance(error, DeepSeekRoleOperatorError):
        return "operator_policy_rejected"
    return "internal_unclassified"


def run_preflighted_deepseek_role_operator(
    prepared: PreparedDeepSeekRoleOperator,
) -> DeepSeekRolePublicReportV2:
    """Execute exactly once and return only the redacted public report."""

    return run_preflighted_deepseek_role_operator_with_private_sidecar(prepared).report


def run_preflighted_deepseek_role_operator_with_private_sidecar(
    prepared: PreparedDeepSeekRoleOperator,
) -> DeepSeekRolePrivateRun:
    """Execute once; retain the V3 sidecar only for a same-process trusted evaluator."""

    if _has_private_reconciliation(prepared):
        return DeepSeekRolePrivateRun(
            report=_report_from_plan(
                prepared.plan,
                status="reconciliation_required",
                failure_class="private_reconciliation_required",
            ),
            suite_sidecar=None,
        )
    prepared.diagnostic_transport.reset_failure()
    try:
        suite_sidecar = run_completed_authorized_role_floor_suite(
            prepared.plan.suite,
            run_id=prepared.plan.config.run_id,
            authorization_service=prepared.authorization_service,
            admissions_by_bundle_id=prepared.admissions_by_bundle_id,
            registry=prepared.registry,
            approval=prepared.approval,
            budgets_by_cell=prepared.plan.budgets_by_cell,
            output_store=prepared.output_store,
            completion_manifest_store=prepared.completion_manifest_store,
            settlement_margin_seconds=_SETTLEMENT_MARGIN_SECONDS,
            lease_ttl_seconds=_LEASE_TTL_SECONDS,
            authorization_ttl_seconds=_AUTHORIZATION_TTL_SECONDS,
        )
        prepared.completion_manifest_store.read_manifest(suite_sidecar.private_manifest_handle)
        role_sidecars = _settled_role_sidecars(prepared, suite_sidecar)
    except BaseException as error:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        reconciliation = _has_private_reconciliation(prepared)
        return DeepSeekRolePrivateRun(
            report=_report_from_plan(
                prepared.plan,
                status=("reconciliation_required" if reconciliation else "execution_refused"),
                failure_class=_failure_class(error, prepared.diagnostic_transport),
            ),
            suite_sidecar=None,
        )
    return DeepSeekRolePrivateRun(
        report=DeepSeekRolePublicReportV2(
            mode="run",
            status="settled",
            run_id=prepared.plan.config.run_id,
            plan_hash=prepared.plan.plan_hash,
            per_trial_budget=_budget_sidecar(
                prepared.plan.config.max_cost_microusd_per_trial,
                prepared.plan.config.max_output_tokens,
            ),
            roles=role_sidecars,
            private_evidence_committed=True,
        ),
        suite_sidecar=suite_sidecar,
    )


def _bare_refusal(
    mode: Literal["plan", "preflight", "run"],
    *,
    run_id: str,
    failure_class: str,
) -> DeepSeekRolePublicReportV2:
    safe_run_id = run_id if _is_safe_run_id(run_id) else "unavailable"
    return DeepSeekRolePublicReportV2(
        mode=mode,
        status="execution_refused",
        run_id=safe_run_id,
        failure_class=failure_class,
    )


def execute_operator_mode(
    config: DeepSeekRoleOperatorConfig,
    *,
    environment: Mapping[str, str] | None = None,
    transport: ResponsesTransport | None = None,
    clock: Callable[[], datetime] = _now,
    _provider_timeout_override_seconds: float | None = None,
) -> DeepSeekRolePublicReportV2:
    """Execute plan/preflight/run while returning only redacted public contracts."""

    try:
        plan = build_deepseek_role_plan(
            config,
            _provider_timeout_override_seconds=_provider_timeout_override_seconds,
        )
    except BaseException as error:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        return _bare_refusal(
            config.mode,
            run_id=config.run_id,
            failure_class=_failure_class(
                error,
                RedactingDiagnosticTransport(_NoIoTransport()),
            ),
        )
    if config.mode == "plan":
        return _report_from_plan(plan, status="planned")
    try:
        prepared = preflight_deepseek_role_operator(
            config,
            environment=environment,
            transport=transport,
            clock=clock,
            _provider_timeout_override_seconds=_provider_timeout_override_seconds,
        )
    except BaseException as error:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        return _report_from_plan(
            plan,
            status="execution_refused",
            failure_class=_failure_class(
                error,
                RedactingDiagnosticTransport(_NoIoTransport()),
            ),
        )
    if config.mode == "preflight":
        return _report_from_plan(prepared.plan, status="preflight_ready")
    return run_preflighted_deepseek_role_operator(prepared)


def _http_failure_class(status_code: int) -> str:
    exact = _HTTP_FAILURE_CLASSES.get(status_code)
    if exact is not None:
        return exact
    if 500 <= status_code <= 599:
        return "http_5xx"
    if 400 <= status_code <= 499:
        return "http_4xx_other"
    if 300 <= status_code <= 399:
        return "http_3xx"
    return "http_status_other"


class _RedactedArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        del message
        raise DeepSeekRoleOperatorError("invalid CLI arguments")


def _parser() -> argparse.ArgumentParser:
    parser = _RedactedArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "preflight", "run"))
    parser.add_argument("--operator-approved", action="store_true")
    parser.add_argument("--state-root", required=True, type=Path)
    parser.add_argument("--private-root", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--max-cost-microusd-per-trial", required=True, type=int)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    mode: Literal["plan", "preflight", "run"] = "plan"
    run_id = "unavailable"
    try:
        arguments = _parser().parse_args(argv)
        mode = arguments.mode
        config = DeepSeekRoleOperatorConfig(
            mode=mode,
            run_id=arguments.run_id,
            state_root=arguments.state_root,
            private_root=arguments.private_root,
            max_cost_microusd_per_trial=arguments.max_cost_microusd_per_trial,
            operator_approved=arguments.operator_approved,
        )
        run_id = config.run_id
        report = execute_operator_mode(config)
    except BaseException as error:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        report = _bare_refusal(
            mode,
            run_id=run_id,
            failure_class=_failure_class(
                error,
                RedactingDiagnosticTransport(_NoIoTransport()),
            ),
        )
    print(canonical_json_bytes(report.model_dump(mode="json")).decode("ascii"))
    return 0 if report.status in {"planned", "preflight_ready", "settled"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
