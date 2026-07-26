"""Authorized, answer-free FATE execution with restart-safe public evidence.

The engine has two deliberately different storage boundaries:

* the model-visible prompt exists only in the in-memory request; model responses,
  candidate Lean sources, and private verifier digests live in an
  ``OperatorPrivateArtifactStore``;
* the append-only public event stream contains redacted work/authorization
  identities, usage, and verifier verdicts only.

Every provider call is bound to a ``ModelWorkBundleV2`` and can only pass
through ``ModelExecutionAuthorizationService`` plus ``ProviderRegistry``.
There is no synthetic ``StatementContractV1`` for benchmark work.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal, Protocol, cast

from autolean_contracts import (
    AttestationV1,
    EndpointClassV1,
    HashKindV1,
    ModelExecutionAuthorizationV1,
    ModelExecutionBudgetV1,
    ModelExecutionProviderApprovalV1,
    ModelWorkBundleV2,
    ModelWorkRoleV1,
    PermissionDecisionV1,
    RightsRecordV1,
    SourceRecordV1,
    SourceSpanV1,
    StableIdentifierV1,
    canonical_json_bytes,
    digest_bytes,
    digest_model,
    digest_text,
    model_work_bundle_id,
    model_work_case_contract_hash,
    model_work_case_hash,
    model_work_cell_contract_hash,
    model_work_cell_hash,
    model_work_contract_id,
    model_work_item_hash,
    model_work_rights_binding,
    model_work_run_hash,
    model_work_source_binding,
    stable_identifier,
)
from autolean_control_plane import (
    ArtifactRef,
    ArtifactStore,
    EventStore,
    Idempotency,
    IndependentExecutionClassV1,
    IndependentExecutionReceiptAuthenticationV1,
    IndependentExecutionReceiptV1,
    IndependentExecutionTrustPolicyV1,
    ModelExecutionAuthorizationService,
    NewEvent,
    request_hash,
)
from autolean_control_plane.events import JsonObject, JsonValue, StoredEvent
from autolean_prover.providers import (
    Capability,
    ModelRequest,
    ModelResponse,
    ProviderRegistry,
)

from .fate import TIER_COUNTS, FateProblemId, Tier, benchmark_splits, split_manifest
from .fate_adapter import (
    FateAdapter,
    FateFixtureLockV1,
    FateFixtureManifestV1,
    FatePatchedSourceV1,
    FatePatchRejected,
)
from .fate_smoke import (
    ALLOWED_AXIOMS,
    FateSmokeCompiler,
    FateSmokeError,
    _parse_wrapper_record,
)
from .reporting import (
    FateEvaluationConfigV1,
    FateEvaluationReportV1,
    FateProblemResultV1,
    FateVerifiedAttemptV1,
)

type FateExecutionSuiteV1 = Literal["regression-48", "model-compare-90", "FATE-350"]
type FateBoundaryFailureV1 = Literal["proof_boundary_rejected"]

_SCHEMA_VERSION: Final = "autolean.fate-execution.v2"
_EVENT_ENTITY_TYPE: Final = "fate-attempt"
_STARTED_EVENT: Final = "fate.attempt.started"
_VERIFIED_EVENT: Final = "fate.attempt.verified"
_SUPPORTED_SUITES: Final[frozenset[str]] = frozenset(
    {"regression-48", "model-compare-90", "FATE-350"}
)
_TIERS: Final[tuple[Tier, ...]] = ("M", "H", "X")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9_.:/-]{0,127}$")
_PUBLIC_EVENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_AUTHORITY_SETUP_MARGIN_SECONDS: Final = 1.0
_BASE_CAPABILITIES: Final = frozenset(
    {
        Capability.TEXT_GENERATION,
        Capability.USAGE_ACCOUNTING,
    }
)
_SYSTEM_PROMPT: Final = (
    "Prove the frozen Lean declaration. Return only the exact text that replaces the existing "
    "sorry token. Do not return Markdown fences, imports, declarations, or commentary."
)
_PROMPT_POLICY: Final[dict[str, JsonValue]] = {
    "schema_version": "autolean.fate-prover-prompt-policy.v1",
    "system_prompt": _SYSTEM_PROMPT,
    "response_format": "exact-proof-slot-fragment",
    "native_tools_enabled": False,
    "retrieval_enabled": False,
    "previous_attempts_visible": False,
    "solutions_visible": False,
}
DISABLED_TOOLS_HASH: Final = hashlib.sha256(
    canonical_json_bytes(
        {
            "schema_version": "autolean.fate-tools.v1",
            "enabled": False,
            "tools": [],
        }
    )
).hexdigest()
DISABLED_RETRIEVAL_HASH: Final = hashlib.sha256(
    canonical_json_bytes(
        {
            "schema_version": "autolean.fate-retrieval.v1",
            "enabled": False,
            "scope": [],
        }
    )
).hexdigest()


class FateExecutionError(RuntimeError):
    """A stable FATE execution invariant failed."""


class FateAttemptAmbiguous(FateExecutionError):
    """A provider call may have happened, so an automatic retry is forbidden."""


class FateLiveExecutionBlocked(FateExecutionError):
    """Required operator or authoritative verifier wiring is absent."""


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _require_sha256(value: str, *, label: str) -> None:
    if _SHA256.fullmatch(value) is None:
        raise FateExecutionError(f"{label} must be a lowercase SHA-256 digest")


def _require_safe_id(value: str, *, label: str) -> None:
    if _SAFE_ID.fullmatch(value) is None:
        raise FateExecutionError(f"{label} must use the bounded lower-case identifier format")


def _json_object(payload: bytes, *, label: str) -> dict[str, object]:
    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    try:
        value = json.loads(payload, object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise FateExecutionError(f"{label} is not strict JSON") from error
    if not isinstance(value, dict):
        raise FateExecutionError(f"{label} must be a JSON object")
    return cast(dict[str, object], value)


def selected_fate_problems(suite: FateExecutionSuiteV1) -> tuple[FateProblemId, ...]:
    """Return one deterministic suite selection ordered M, H, X."""

    if suite not in _SUPPORTED_SUITES:
        raise FateExecutionError("unsupported FATE execution suite")
    if suite == "FATE-350":
        targets = {tier: tuple(range(1, TIER_COUNTS[tier] + 1)) for tier in _TIERS}
    else:
        targets = benchmark_splits()[suite]
    return tuple(FateProblemId(tier, number) for tier in _TIERS for number in targets[tier])


def verified_split_manifest_hash(path: str | Path) -> str:
    """Verify the answer-free split file against code and return its byte hash."""

    candidate = Path(path)
    try:
        payload = candidate.read_bytes()
    except OSError as error:
        raise FateExecutionError("FATE split manifest is unreadable") from error
    loaded = _json_object(payload, label="FATE split manifest")
    if canonical_json_bytes(loaded) != canonical_json_bytes(split_manifest()):
        raise FateExecutionError("FATE split manifest differs from the deterministic selection")
    return _sha256(payload)


@dataclass(frozen=True, slots=True)
class FateRunPlanV1:
    """One fixed provider-independent FATE run plan."""

    run_id: str
    suite: FateExecutionSuiteV1
    fate_manifest_hash: str
    split_manifest_hash: str
    environment_hash: str
    attempt_budget: int
    model_request_timeout_seconds: int
    verifier_timeout_seconds: int
    settlement_margin_seconds: int
    max_input_tokens: int
    max_output_tokens: int
    max_cost_microusd_per_attempt: int
    reasoning_effort: str | None = None

    def __post_init__(self) -> None:
        _require_safe_id(self.run_id, label="run_id")
        if self.suite not in _SUPPORTED_SUITES:
            raise FateExecutionError("unsupported FATE execution suite")
        for label, value in (
            ("fate_manifest_hash", self.fate_manifest_hash),
            ("split_manifest_hash", self.split_manifest_hash),
            ("environment_hash", self.environment_hash),
        ):
            _require_sha256(value, label=label)
        if not 1 <= self.attempt_budget <= 100:
            raise FateExecutionError("attempt_budget must be between 1 and 100")
        if not 1 <= self.model_request_timeout_seconds <= 3600:
            raise FateExecutionError("model_request_timeout_seconds must be between 1 and 3600")
        if not 1 <= self.verifier_timeout_seconds <= 1800:
            raise FateExecutionError("verifier_timeout_seconds must be between 1 and 1800")
        if not 1 <= self.settlement_margin_seconds <= 600:
            raise FateExecutionError("settlement_margin_seconds must be between 1 and 600")
        if self.model_authorization_window_seconds > 3600:
            raise FateExecutionError(
                "model timeout plus settlement margin exceeds the authorization hard cap"
            )
        if self.max_input_tokens <= 0 or self.max_output_tokens <= 0:
            raise FateExecutionError("model token limits must be positive")
        if self.max_cost_microusd_per_attempt < 0:
            raise FateExecutionError("per-attempt cost budget must be non-negative")
        if self.reasoning_effort is not None and self.reasoning_effort not in {
            "low",
            "medium",
            "high",
            "max",
        }:
            raise FateExecutionError("reasoning_effort is unsupported")

    @property
    def prompt_policy_hash(self) -> str:
        return _sha256(
            canonical_json_bytes(
                {
                    **_PROMPT_POLICY,
                    "reasoning_effort": self.reasoning_effort,
                    "max_input_tokens": self.max_input_tokens,
                    "max_output_tokens": self.max_output_tokens,
                    "model_request_timeout_seconds": self.model_request_timeout_seconds,
                    "settlement_margin_seconds": self.settlement_margin_seconds,
                }
            )
        )

    @property
    def model_authorization_window_seconds(self) -> int:
        """Minimum capability window through provider response settlement."""

        return self.model_request_timeout_seconds + self.settlement_margin_seconds

    @property
    def attempt_lease_window_seconds(self) -> int:
        """Minimum fence window through model, verifier, and terminal commit."""

        return (
            self.model_request_timeout_seconds
            + self.verifier_timeout_seconds
            + self.settlement_margin_seconds
        )

    def reporting_config(
        self,
        approval: ModelExecutionProviderApprovalV1,
        *,
        effective_model_timeout_seconds: float,
    ) -> FateEvaluationConfigV1:
        """Build the report config with the exact request-bound model timeout."""

        if effective_model_timeout_seconds != float(self.model_request_timeout_seconds):
            raise FateExecutionError(
                "reported model timeout differs from the frozen effective timeout"
            )
        binding = approval.binding
        return FateEvaluationConfigV1(
            run_id=self.run_id,
            suite=self.suite,
            fate_manifest_hash=self.fate_manifest_hash,
            environment_hash=self.environment_hash,
            provider_id=binding.provider_id,
            model_id=binding.model_id,
            model_revision=binding.model_revision,
            prompt_hash=self.prompt_policy_hash,
            tools_hash=DISABLED_TOOLS_HASH,
            retrieval_scope_hash=DISABLED_RETRIEVAL_HASH,
            attempt_budget=self.attempt_budget,
            timeout_seconds=effective_model_timeout_seconds,
        )


@dataclass(frozen=True, slots=True)
class FateModelWorkAuthorityV1:
    """Repository-lock-derived source and rights records for FATE model egress."""

    source: SourceRecordV1
    rights: RightsRecordV1
    lock_sha256: str

    def __post_init__(self) -> None:
        _require_sha256(self.lock_sha256, label="lock_sha256")
        if self.rights.source_id != self.source.source_id:
            raise FateExecutionError("FATE rights must reference the FATE source record")


def build_fate_model_work_authority(
    manifest: FateFixtureManifestV1,
    *,
    endpoint_class: EndpointClassV1,
    reviewed_by: str,
    reviewed_at: datetime,
    lock_path: str | Path | None = None,
) -> FateModelWorkAuthorityV1:
    """Derive FATE source rights from the checked-in MIT lock, without answer data."""

    if endpoint_class not in {EndpointClassV1.LOCAL, EndpointClassV1.APPROVED_EXTERNAL}:
        raise FateExecutionError(
            "FATE execution requires local or approved_external provider routing"
        )
    if not reviewed_by.strip() or reviewed_at.tzinfo is None:
        raise FateExecutionError("FATE rights review requires an identified reviewer and timezone")
    selected_lock_path = (
        Path(lock_path) if lock_path is not None else Path(__file__).with_name("fate.lock.json")
    )
    try:
        lock_bytes = selected_lock_path.read_bytes()
    except OSError as error:
        raise FateExecutionError("FATE lock is unreadable") from error
    raw_lock = _json_object(lock_bytes, label="FATE lock")
    if (
        raw_lock.get("schema_version") != "autolean.fate-lock.v1"
        or raw_lock.get("suite") != "FATE"
        or raw_lock.get("license") != "MIT"
        or raw_lock.get("repository") != "https://github.com/frenzymath/FATE"
    ):
        raise FateExecutionError(
            "FATE lock does not bind the expected suite, repository, and MIT license"
        )
    lock = FateFixtureLockV1.load(selected_lock_path)
    manifest.validate_against_lock(lock)
    manifest_bytes = manifest.to_json().encode("utf-8")
    source = SourceRecordV1(
        source_id=stable_identifier("fate-source", manifest.content_hash),
        work_id="frenzymath/FATE",
        title="FATE Lean benchmark source manifest",
        version="v4.28.0",
        locator="https://github.com/frenzymath/FATE",
        content_hash=digest_bytes(HashKindV1.SOURCE_BYTES, manifest_bytes),
        retrieved_at=reviewed_at,
        metadata={
            "contains_solutions": False,
            "fate_manifest_sha256": manifest.content_hash,
            "fate_lock_sha256": _sha256(lock_bytes),
            "license": "MIT",
            "root_commit": lock.root_commit,
            "submodules": dict(sorted(lock.submodules.items())),
        },
    )
    external = endpoint_class is EndpointClassV1.APPROVED_EXTERNAL
    rights = RightsRecordV1(
        rights_id=stable_identifier(
            "fate-rights",
            f"{manifest.content_hash}:{endpoint_class.value}",
        ),
        source_id=source.source_id,
        source_license="MIT",
        overall_decision=PermissionDecisionV1.ALLOW,
        redistribution=PermissionDecisionV1.ALLOW,
        model_egress=(PermissionDecisionV1.ALLOW if external else PermissionDecisionV1.DENY),
        allowed_endpoint_classes=((EndpointClassV1.APPROVED_EXTERNAL,) if external else ()),
        attribution="FATE, frenzymath, MIT license",
        reviewed_by=reviewed_by,
        reviewed_at=reviewed_at,
    )
    return FateModelWorkAuthorityV1(
        source=source,
        rights=rights,
        lock_sha256=_sha256(lock_bytes),
    )


@dataclass(frozen=True, slots=True)
class FatePrivateAttemptRecordV1:
    """Operator-private coordinate index for one response and candidate.

    None of these content digests are copied into the public event stream.  In
    particular, a short proof body must not become enumerable through a public
    unkeyed SHA-256 commitment.
    """

    run_id: str
    problem_id: FateProblemId
    attempt_number: int
    raw_output_sha256: str
    candidate_sha256: str | None
    verifier_evidence_sha256: str
    independent_execution_receipt_hash: str
    verifier_receipt_artifact_sha256: str

    def __post_init__(self) -> None:
        _require_safe_id(self.run_id, label="run_id")
        if self.attempt_number < 1:
            raise FateExecutionError("private attempt number must be positive")
        for label, value in (
            ("raw_output_sha256", self.raw_output_sha256),
            ("verifier_evidence_sha256", self.verifier_evidence_sha256),
            (
                "independent_execution_receipt_hash",
                self.independent_execution_receipt_hash,
            ),
            (
                "verifier_receipt_artifact_sha256",
                self.verifier_receipt_artifact_sha256,
            ),
        ):
            _require_sha256(value, label=label)
        if self.candidate_sha256 is not None:
            _require_sha256(self.candidate_sha256, label="candidate_sha256")

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "schema_version": "autolean.fate-private-attempt-record.v1",
            "run_id": self.run_id,
            "problem_id": self.problem_id.canonical,
            "attempt_number": self.attempt_number,
            "raw_output_sha256": self.raw_output_sha256,
            "candidate_sha256": self.candidate_sha256,
            "verifier_evidence_sha256": self.verifier_evidence_sha256,
            "independent_execution_receipt_hash": (self.independent_execution_receipt_hash),
            "verifier_receipt_artifact_sha256": (self.verifier_receipt_artifact_sha256),
        }

    @classmethod
    def from_bytes(cls, payload: bytes) -> FatePrivateAttemptRecordV1:
        raw = _json_object(payload, label="private FATE attempt record")
        if (
            set(raw)
            != {
                "schema_version",
                "run_id",
                "problem_id",
                "attempt_number",
                "raw_output_sha256",
                "candidate_sha256",
                "verifier_evidence_sha256",
                "independent_execution_receipt_hash",
                "verifier_receipt_artifact_sha256",
            }
            or raw["schema_version"] != "autolean.fate-private-attempt-record.v1"
        ):
            raise FateExecutionError("private FATE attempt record schema differs")
        run_id = raw["run_id"]
        problem_id = raw["problem_id"]
        attempt_number = raw["attempt_number"]
        raw_output = raw["raw_output_sha256"]
        candidate = raw["candidate_sha256"]
        evidence = raw["verifier_evidence_sha256"]
        execution_receipt = raw["independent_execution_receipt_hash"]
        verifier_receipt_artifact = raw["verifier_receipt_artifact_sha256"]
        if (
            not isinstance(run_id, str)
            or not isinstance(problem_id, str)
            or isinstance(attempt_number, bool)
            or not isinstance(attempt_number, int)
            or not isinstance(raw_output, str)
            or (candidate is not None and not isinstance(candidate, str))
            or not isinstance(evidence, str)
            or not isinstance(execution_receipt, str)
            or not isinstance(verifier_receipt_artifact, str)
        ):
            raise FateExecutionError("private FATE attempt record fields are invalid")
        problem_match = re.fullmatch(r"FATE-([MHX])-([1-9][0-9]*)", problem_id)
        if problem_match is None:
            raise FateExecutionError("private FATE attempt record problem ID is invalid")
        try:
            parsed_problem = FateProblemId(
                cast(Tier, problem_match.group(1)),
                int(problem_match.group(2)),
            )
        except ValueError as error:
            raise FateExecutionError("private FATE attempt record problem ID is invalid") from error
        return cls(
            run_id=run_id,
            problem_id=parsed_problem,
            attempt_number=attempt_number,
            raw_output_sha256=raw_output,
            candidate_sha256=candidate,
            verifier_evidence_sha256=evidence,
            independent_execution_receipt_hash=execution_receipt,
            verifier_receipt_artifact_sha256=verifier_receipt_artifact,
        )


def validate_operator_private_root(
    root: str | Path,
    *,
    repository_root: str | Path,
) -> Path:
    """Return a normalized private root only when it is outside the checkout."""

    private_root = Path(root).resolve()
    public_root = Path(repository_root).resolve()
    if private_root == public_root or private_root.is_relative_to(public_root):
        raise FateExecutionError("operator-private FATE artifacts must be outside the repository")
    return private_root


class OperatorPrivateArtifactStore:
    """Repository-external private CAS plus a durable coordinate index."""

    def __init__(
        self,
        root: str | Path,
        *,
        repository_root: str | Path,
    ) -> None:
        public_root = Path(repository_root).resolve()
        private_root = validate_operator_private_root(
            root,
            repository_root=public_root,
        )
        self._repository_root = public_root
        self._store = ArtifactStore(private_root)
        self._index_root = private_root / "attempt-index"

    @property
    def root(self) -> Path:
        return self._store.root

    @property
    def repository_root(self) -> Path:
        return self._repository_root

    def put_bytes(self, payload: bytes) -> ArtifactRef:
        return self._store.put_bytes(payload)

    def get_bytes(self, reference: ArtifactRef | str) -> bytes:
        return self._store.get_bytes(reference)

    def put_attempt_record(self, record: FatePrivateAttemptRecordV1) -> None:
        payload = canonical_json_bytes(record.to_dict())
        reference = self._store.put_bytes(payload)
        index_path = self._attempt_index_path(
            record.run_id,
            record.problem_id,
            record.attempt_number,
        )
        index_payload = canonical_json_bytes(
            {
                "schema_version": "autolean.fate-private-attempt-index.v1",
                "record_sha256": reference.digest,
            }
        )
        index_path.parent.mkdir(parents=True, exist_ok=True)
        if index_path.exists():
            existing = _json_object(
                index_path.read_bytes(),
                label="private FATE attempt index",
            )
            if existing != {
                "schema_version": "autolean.fate-private-attempt-index.v1",
                "record_sha256": reference.digest,
            }:
                raise FateExecutionError(
                    "private FATE attempt coordinate already binds different artifacts"
                )
            return
        temporary = index_path.with_name(f".{index_path.name}.{uuid.uuid4().hex}.pending")
        try:
            temporary.write_bytes(index_payload)
            os.replace(temporary, index_path)
        finally:
            temporary.unlink(missing_ok=True)

    def get_attempt_record(
        self,
        run_id: str,
        problem_id: FateProblemId,
        attempt_number: int,
    ) -> FatePrivateAttemptRecordV1:
        index_path = self._attempt_index_path(run_id, problem_id, attempt_number)
        try:
            raw_index = _json_object(
                index_path.read_bytes(),
                label="private FATE attempt index",
            )
        except OSError as error:
            raise FateExecutionError("private FATE attempt index is missing") from error
        if (
            set(raw_index) != {"schema_version", "record_sha256"}
            or raw_index.get("schema_version") != "autolean.fate-private-attempt-index.v1"
        ):
            raise FateExecutionError("private FATE attempt index schema differs")
        record_digest = raw_index["record_sha256"]
        if not isinstance(record_digest, str):
            raise FateExecutionError("private FATE attempt index digest is invalid")
        _require_sha256(record_digest, label="private record digest")
        record = FatePrivateAttemptRecordV1.from_bytes(self._store.get_bytes(record_digest))
        if (
            record.run_id != run_id
            or record.problem_id != problem_id
            or record.attempt_number != attempt_number
        ):
            raise FateExecutionError("private FATE attempt index binding differs")
        return record

    def _attempt_index_path(
        self,
        run_id: str,
        problem_id: FateProblemId,
        attempt_number: int,
    ) -> Path:
        _require_safe_id(run_id, label="run_id")
        if attempt_number < 1:
            raise FateExecutionError("attempt_number must be positive")
        return self._index_root / run_id / problem_id.canonical.lower() / f"{attempt_number}.json"


@dataclass(frozen=True, slots=True)
class FateVerificationRequestV1:
    """In-process request to an independent candidate verifier."""

    run_id: str
    problem_id: FateProblemId
    attempt_number: int
    task_source_sha256: str
    signature_sha256: str
    raw_output_sha256: str
    candidate: FatePatchedSourceV1 | None
    boundary_failure: FateBoundaryFailureV1 | None
    environment_hash: str
    timeout_seconds: int

    def __post_init__(self) -> None:
        _require_safe_id(self.run_id, label="run_id")
        if self.attempt_number < 1:
            raise FateExecutionError("attempt_number must be positive")
        for label, value in (
            ("task_source_sha256", self.task_source_sha256),
            ("signature_sha256", self.signature_sha256),
            ("raw_output_sha256", self.raw_output_sha256),
            ("environment_hash", self.environment_hash),
        ):
            _require_sha256(value, label=label)
        if (self.candidate is None) != (self.boundary_failure is not None):
            raise FateExecutionError(
                "a missing candidate requires exactly one proof-boundary failure"
            )
        if self.candidate is not None:
            if self.candidate.task.task_id != self.problem_id.canonical:
                raise FateExecutionError("verifier candidate problem binding differs")
            if self.candidate.task.source_sha256 != self.task_source_sha256:
                raise FateExecutionError("verifier candidate source binding differs")
            if self.candidate.task.target.signature_sha256 != self.signature_sha256:
                raise FateExecutionError("verifier candidate signature binding differs")
        if not 1 <= self.timeout_seconds <= 1800:
            raise FateExecutionError("verifier timeout is outside the supported range")

    def request_hash(self) -> str:
        """Bind every verifier-visible fact without publishing its private digests."""

        return _verification_request_hash(
            run_id=self.run_id,
            problem_id=self.problem_id,
            attempt_number=self.attempt_number,
            task_source_sha256=self.task_source_sha256,
            signature_sha256=self.signature_sha256,
            raw_output_sha256=self.raw_output_sha256,
            candidate_sha256=(None if self.candidate is None else self.candidate.candidate_sha256),
            boundary_failure=self.boundary_failure,
            environment_hash=self.environment_hash,
            timeout_seconds=self.timeout_seconds,
        )


def _verification_request_hash(
    *,
    run_id: str,
    problem_id: FateProblemId,
    attempt_number: int,
    task_source_sha256: str,
    signature_sha256: str,
    raw_output_sha256: str,
    candidate_sha256: str | None,
    boundary_failure: FateBoundaryFailureV1 | None,
    environment_hash: str,
    timeout_seconds: int,
) -> str:
    return _sha256(
        canonical_json_bytes(
            {
                "schema_version": "autolean.fate-verification-request.v1",
                "run_id": run_id,
                "problem_id": problem_id.canonical,
                "attempt_number": attempt_number,
                "task_source_sha256": task_source_sha256,
                "signature_sha256": signature_sha256,
                "raw_output_sha256": raw_output_sha256,
                "candidate_sha256": candidate_sha256,
                "boundary_failure": boundary_failure,
                "environment_hash": environment_hash,
                "timeout_seconds": timeout_seconds,
            }
        )
    )


@dataclass(frozen=True, slots=True)
class FateVerificationReceiptV1:
    """Verifier verdict plus an authenticated independent-execution receipt."""

    verification_event_id: str
    problem_id: FateProblemId
    attempt_number: int
    accepted: bool
    candidate_sha256: str | None
    task_source_sha256: str
    signature_sha256: str
    environment_hash: str
    verifier_id: str
    evidence_sha256: str
    verifier_elapsed_ms: int
    failure_code: str | None
    independent_execution_receipt: IndependentExecutionReceiptV1

    def __post_init__(self) -> None:
        if _PUBLIC_EVENT_ID.fullmatch(self.verification_event_id) is None:
            raise FateExecutionError("verification_event_id has an unsafe format")
        if _PUBLIC_EVENT_ID.fullmatch(self.verifier_id) is None:
            raise FateExecutionError("verifier_id has an unsafe format")
        if self.attempt_number < 1:
            raise FateExecutionError("verifier attempt_number must be positive")
        for label, value in (
            ("task_source_sha256", self.task_source_sha256),
            ("signature_sha256", self.signature_sha256),
            ("environment_hash", self.environment_hash),
            ("evidence_sha256", self.evidence_sha256),
        ):
            _require_sha256(value, label=label)
        if self.candidate_sha256 is not None:
            _require_sha256(self.candidate_sha256, label="candidate_sha256")
        if self.accepted and (self.candidate_sha256 is None or self.failure_code is not None):
            raise FateExecutionError(
                "an accepted verifier receipt requires a candidate and no failure"
            )
        if not self.accepted and not self.failure_code:
            raise FateExecutionError("a rejected verifier receipt requires a stable failure code")
        if self.verifier_elapsed_ms < 0:
            raise FateExecutionError("verifier_elapsed_ms must be non-negative")
        try:
            self.independent_execution_receipt.validate()
        except ValueError as error:
            raise FateExecutionError("independent execution receipt is malformed") from error

    def verification_claim_hash(self) -> str:
        return _verification_claim_hash(
            verification_event_id=self.verification_event_id,
            problem_id=self.problem_id,
            attempt_number=self.attempt_number,
            accepted=self.accepted,
            candidate_sha256=self.candidate_sha256,
            task_source_sha256=self.task_source_sha256,
            signature_sha256=self.signature_sha256,
            environment_hash=self.environment_hash,
            verifier_id=self.verifier_id,
            evidence_sha256=self.evidence_sha256,
            verifier_elapsed_ms=self.verifier_elapsed_ms,
            failure_code=self.failure_code,
        )

    def private_bytes(self) -> bytes:
        independent = self.independent_execution_receipt
        authentication = independent.authentication
        return canonical_json_bytes(
            {
                "schema_version": "autolean.fate-private-verification-receipt.v1",
                "verification_event_id": self.verification_event_id,
                "problem_id": self.problem_id.canonical,
                "attempt_number": self.attempt_number,
                "accepted": self.accepted,
                "candidate_sha256": self.candidate_sha256,
                "task_source_sha256": self.task_source_sha256,
                "signature_sha256": self.signature_sha256,
                "environment_hash": self.environment_hash,
                "verifier_id": self.verifier_id,
                "evidence_sha256": self.evidence_sha256,
                "verifier_elapsed_ms": self.verifier_elapsed_ms,
                "failure_code": self.failure_code,
                "independent_execution_receipt": {
                    "receipt_id": independent.receipt_id,
                    "verifier_id": independent.verifier_id,
                    "checked_at": independent.checked_at.astimezone(UTC)
                    .isoformat(timespec="microseconds")
                    .replace("+00:00", "Z"),
                    "request_hash": independent.request_hash,
                    "evidence_artifact_digest": (independent.evidence_artifact_digest),
                    "evidence_digest": independent.evidence_digest,
                    "execution_claim_hash": independent.execution_claim_hash,
                    "receipt_hash": independent.receipt_hash,
                    "authentication": (
                        None
                        if authentication is None
                        else {
                            "key_id": authentication.key_id,
                            "algorithm": authentication.algorithm,
                            "authenticated_receipt_hash": (
                                authentication.authenticated_receipt_hash
                            ),
                            "signature": authentication.signature,
                        }
                    ),
                },
            }
        )

    @classmethod
    def from_private_bytes(cls, payload: bytes) -> FateVerificationReceiptV1:
        raw = _json_object(payload, label="private FATE verification receipt")
        required = {
            "schema_version",
            "verification_event_id",
            "problem_id",
            "attempt_number",
            "accepted",
            "candidate_sha256",
            "task_source_sha256",
            "signature_sha256",
            "environment_hash",
            "verifier_id",
            "evidence_sha256",
            "verifier_elapsed_ms",
            "failure_code",
            "independent_execution_receipt",
        }
        if set(raw) != required or raw["schema_version"] != (
            "autolean.fate-private-verification-receipt.v1"
        ):
            raise FateExecutionError("private FATE verification receipt schema differs")
        problem_value = raw["problem_id"]
        independent_raw = raw["independent_execution_receipt"]
        if not isinstance(problem_value, str) or not isinstance(independent_raw, dict):
            raise FateExecutionError("private FATE verification receipt fields are invalid")
        if (
            not isinstance(raw["verification_event_id"], str)
            or isinstance(raw["attempt_number"], bool)
            or not isinstance(raw["attempt_number"], int)
            or not isinstance(raw["accepted"], bool)
            or (
                raw["candidate_sha256"] is not None and not isinstance(raw["candidate_sha256"], str)
            )
            or not isinstance(raw["task_source_sha256"], str)
            or not isinstance(raw["signature_sha256"], str)
            or not isinstance(raw["environment_hash"], str)
            or not isinstance(raw["verifier_id"], str)
            or not isinstance(raw["evidence_sha256"], str)
            or isinstance(raw["verifier_elapsed_ms"], bool)
            or not isinstance(raw["verifier_elapsed_ms"], int)
            or (raw["failure_code"] is not None and not isinstance(raw["failure_code"], str))
        ):
            raise FateExecutionError("private FATE verification receipt fields are invalid")
        problem_match = re.fullmatch(
            r"FATE-([MHX])-([1-9][0-9]*)",
            problem_value,
        )
        if problem_match is None:
            raise FateExecutionError("private FATE verification receipt problem ID is invalid")
        try:
            problem = FateProblemId(
                cast(Tier, problem_match.group(1)),
                int(problem_match.group(2)),
            )
            independent = _independent_receipt_from_dict(independent_raw)
            return cls(
                verification_event_id=raw["verification_event_id"],
                problem_id=problem,
                attempt_number=raw["attempt_number"],
                accepted=raw["accepted"],
                candidate_sha256=raw["candidate_sha256"],
                task_source_sha256=raw["task_source_sha256"],
                signature_sha256=raw["signature_sha256"],
                environment_hash=raw["environment_hash"],
                verifier_id=raw["verifier_id"],
                evidence_sha256=raw["evidence_sha256"],
                verifier_elapsed_ms=raw["verifier_elapsed_ms"],
                failure_code=raw["failure_code"],
                independent_execution_receipt=independent,
            )
        except (TypeError, ValueError) as error:
            raise FateExecutionError(
                "private FATE verification receipt fields are invalid"
            ) from error


def _independent_receipt_from_dict(
    raw: Mapping[str, object],
) -> IndependentExecutionReceiptV1:
    required = {
        "receipt_id",
        "verifier_id",
        "checked_at",
        "request_hash",
        "evidence_artifact_digest",
        "evidence_digest",
        "execution_claim_hash",
        "receipt_hash",
        "authentication",
    }
    if set(raw) != required:
        raise ValueError("independent execution receipt schema differs")
    checked_at_value = raw["checked_at"]
    if not isinstance(checked_at_value, str) or not checked_at_value.endswith("Z"):
        raise ValueError("independent execution receipt timestamp is invalid")
    checked_at = datetime.fromisoformat(checked_at_value.removesuffix("Z") + "+00:00")
    authentication_raw = raw["authentication"]
    authentication: IndependentExecutionReceiptAuthenticationV1 | None
    if authentication_raw is None:
        authentication = None
    elif isinstance(authentication_raw, dict) and set(authentication_raw) == {
        "key_id",
        "algorithm",
        "authenticated_receipt_hash",
        "signature",
    }:
        authentication = IndependentExecutionReceiptAuthenticationV1(
            key_id=cast(str, authentication_raw["key_id"]),
            algorithm=cast(str, authentication_raw["algorithm"]),
            authenticated_receipt_hash=cast(
                str,
                authentication_raw["authenticated_receipt_hash"],
            ),
            signature=cast(str, authentication_raw["signature"]),
        )
    else:
        raise ValueError("independent execution receipt authentication is invalid")
    return IndependentExecutionReceiptV1(
        receipt_id=cast(str, raw["receipt_id"]),
        verifier_id=cast(str, raw["verifier_id"]),
        checked_at=checked_at,
        request_hash=cast(str, raw["request_hash"]),
        evidence_artifact_digest=cast(str, raw["evidence_artifact_digest"]),
        evidence_digest=cast(str, raw["evidence_digest"]),
        execution_claim_hash=cast(str, raw["execution_claim_hash"]),
        receipt_hash=cast(str, raw["receipt_hash"]),
        authentication=authentication,
    )


class FateExecutionReceiptIssuer(Protocol):
    """Isolated verifier-side issuer; production implementations keep keys remote."""

    def authenticate(
        self,
        receipt: IndependentExecutionReceiptV1,
    ) -> IndependentExecutionReceiptV1: ...


def _verification_claim_hash(
    *,
    verification_event_id: str,
    problem_id: FateProblemId,
    attempt_number: int,
    accepted: bool,
    candidate_sha256: str | None,
    task_source_sha256: str,
    signature_sha256: str,
    environment_hash: str,
    verifier_id: str,
    evidence_sha256: str,
    verifier_elapsed_ms: int,
    failure_code: str | None,
) -> str:
    return _sha256(
        canonical_json_bytes(
            {
                "schema_version": "autolean.fate-verification-claim.v1",
                "verification_event_id": verification_event_id,
                "problem_id": problem_id.canonical,
                "attempt_number": attempt_number,
                "accepted": accepted,
                "candidate_sha256": candidate_sha256,
                "task_source_sha256": task_source_sha256,
                "signature_sha256": signature_sha256,
                "environment_hash": environment_hash,
                "verifier_id": verifier_id,
                "evidence_sha256": evidence_sha256,
                "verifier_elapsed_ms": verifier_elapsed_ms,
                "failure_code": failure_code,
            }
        )
    )


def _verification_event_id(
    request: FateVerificationRequestV1,
    *,
    verifier_id: str,
) -> str:
    coordinate_hash = _sha256(
        canonical_json_bytes(
            {
                "schema_version": "autolean.fate-verification-coordinate.v1",
                "run_id": request.run_id,
                "problem_id": request.problem_id.canonical,
                "attempt_number": request.attempt_number,
                "environment_hash": request.environment_hash,
                "verifier_id": verifier_id,
            }
        )
    )
    return f"fate-verification-{coordinate_hash[:32]}"


def _build_verification_receipt(
    request: FateVerificationRequestV1,
    *,
    receipt_issuer: FateExecutionReceiptIssuer,
    checked_at: datetime,
    verifier_id: str,
    accepted: bool,
    candidate_sha256: str | None,
    evidence_sha256: str,
    verifier_elapsed_ms: int,
    failure_code: str | None,
) -> FateVerificationReceiptV1:
    verification_event_id = _verification_event_id(
        request,
        verifier_id=verifier_id,
    )
    claim_hash = _verification_claim_hash(
        verification_event_id=verification_event_id,
        problem_id=request.problem_id,
        attempt_number=request.attempt_number,
        accepted=accepted,
        candidate_sha256=candidate_sha256,
        task_source_sha256=request.task_source_sha256,
        signature_sha256=request.signature_sha256,
        environment_hash=request.environment_hash,
        verifier_id=verifier_id,
        evidence_sha256=evidence_sha256,
        verifier_elapsed_ms=verifier_elapsed_ms,
        failure_code=failure_code,
    )
    independent = IndependentExecutionReceiptV1.create(
        receipt_id=f"fate-execution-{verification_event_id.removeprefix('fate-verification-')}",
        verifier_id=verifier_id,
        checked_at=checked_at,
        request_hash=request.request_hash(),
        evidence_artifact_digest=evidence_sha256,
        evidence_digest=evidence_sha256,
        execution_claim_hash=claim_hash,
    )
    authenticated = receipt_issuer.authenticate(independent)
    return FateVerificationReceiptV1(
        verification_event_id=verification_event_id,
        problem_id=request.problem_id,
        attempt_number=request.attempt_number,
        accepted=accepted,
        candidate_sha256=candidate_sha256,
        task_source_sha256=request.task_source_sha256,
        signature_sha256=request.signature_sha256,
        environment_hash=request.environment_hash,
        verifier_id=verifier_id,
        evidence_sha256=evidence_sha256,
        verifier_elapsed_ms=verifier_elapsed_ms,
        failure_code=failure_code,
        independent_execution_receipt=authenticated,
    )


class FateCandidateVerifier(Protocol):
    """Independent verifier interface; only it may return ``accepted=True``."""

    @property
    def execution_class(self) -> IndependentExecutionClassV1: ...

    def verify(self, request: FateVerificationRequestV1) -> FateVerificationReceiptV1: ...


class DeterministicFakeFateVerifier:
    """Offline verifier fixture. It is never production evidence."""

    execution_class: Final = IndependentExecutionClassV1.TEST_ONLY

    def __init__(
        self,
        *,
        receipt_issuer: FateExecutionReceiptIssuer,
        accepted_proof_body_hashes: frozenset[str] | None = None,
        accept_all_candidates: bool = False,
        verifier_id: str = "fake-fate-verifier-v1",
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if accepted_proof_body_hashes is not None:
            for digest in accepted_proof_body_hashes:
                _require_sha256(digest, label="accepted proof hash")
        if accepted_proof_body_hashes is not None and accept_all_candidates:
            raise FateExecutionError("fake verifier acceptance modes are mutually exclusive")
        if _PUBLIC_EVENT_ID.fullmatch(verifier_id) is None:
            raise FateExecutionError("fake verifier_id has an unsafe format")
        self._accepted_hashes = accepted_proof_body_hashes or frozenset()
        self._accept_all = accept_all_candidates
        self._verifier_id = verifier_id
        self._receipt_issuer = receipt_issuer
        self._clock = clock or (lambda: datetime.now(UTC))
        self.requests: list[FateVerificationRequestV1] = []

    def verify(self, request: FateVerificationRequestV1) -> FateVerificationReceiptV1:
        self.requests.append(request)
        candidate = request.candidate
        accepted = candidate is not None and (
            self._accept_all or candidate.proof_body_sha256 in self._accepted_hashes
        )
        if candidate is None:
            failure_code = cast(str, request.boundary_failure)
        elif accepted:
            failure_code = None
        else:
            failure_code = "kernel_rejected"
        evidence = {
            "schema_version": "autolean.fake-fate-verifier-evidence.v1",
            "problem_id": request.problem_id.canonical,
            "attempt_number": request.attempt_number,
            "candidate_sha256": (None if candidate is None else candidate.candidate_sha256),
            "accepted": accepted,
            "failure_code": failure_code,
            "environment_hash": request.environment_hash,
        }
        evidence_sha256 = _sha256(canonical_json_bytes(evidence))
        return _build_verification_receipt(
            request,
            receipt_issuer=self._receipt_issuer,
            checked_at=self._clock(),
            verifier_id=self._verifier_id,
            accepted=accepted,
            candidate_sha256=(None if candidate is None else candidate.candidate_sha256),
            evidence_sha256=evidence_sha256,
            verifier_elapsed_ms=0,
            failure_code=failure_code,
        )


class FateSmokeCompilerVerifier:
    """Test-only local OCI adapter; production requires an independent remote verifier."""

    execution_class: Final = IndependentExecutionClassV1.TEST_ONLY

    def __init__(
        self,
        compiler: FateSmokeCompiler,
        *,
        receipt_issuer: FateExecutionReceiptIssuer,
        verifier_id: str,
        environment_hash: str,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if _PUBLIC_EVENT_ID.fullmatch(verifier_id) is None:
            raise FateExecutionError("verifier_id has an unsafe format")
        _require_sha256(environment_hash, label="environment_hash")
        self._compiler = compiler
        self._receipt_issuer = receipt_issuer
        self._verifier_id = verifier_id
        self._environment_hash = environment_hash
        self._clock = clock or (lambda: datetime.now(UTC))

    def verify(self, request: FateVerificationRequestV1) -> FateVerificationReceiptV1:
        if request.environment_hash != self._environment_hash:
            raise FateExecutionError("verifier environment differs from the frozen run plan")
        candidate = request.candidate
        if candidate is None:
            return self._receipt(
                request,
                candidate_sha256=None,
                accepted=False,
                failure_code=cast(str, request.boundary_failure),
                elapsed_ms=0,
                evidence={
                    "schema_version": "autolean.fate-oci-verifier-evidence.v1",
                    "boundary_failure": request.boundary_failure,
                },
            )

        observation = self._compiler.compile(
            candidate,
            timeout_seconds=request.timeout_seconds,
        )
        failure_code: str | None
        wrapper_record_sha256: str | None = None
        observed_axioms: tuple[str, ...] = ()
        if observation.timed_out:
            failure_code = "verifier_timeout"
        elif observation.returncode != 0:
            failure_code = "compile_or_query_failed"
        else:
            try:
                record = _parse_wrapper_record(
                    observation.stdout,
                    candidate.task.target.qualified_name,
                )
            except FateSmokeError:
                failure_code = "verifier_protocol_failed"
            else:
                wrapper_record_sha256 = record.record_sha256
                observed_axioms = record.observed_axioms
                failure_code = (
                    None
                    if set(observed_axioms).issubset(ALLOWED_AXIOMS)
                    else "axiom_policy_rejected"
                )
        evidence = {
            "schema_version": "autolean.fate-oci-verifier-evidence.v1",
            "candidate_sha256": candidate.candidate_sha256,
            "command_sha256": observation.command_sha256,
            "returncode": observation.returncode,
            "timed_out": observation.timed_out,
            "stdout_sha256": _sha256(observation.stdout),
            "stderr_sha256": _sha256(observation.stderr),
            "wrapper_record_sha256": wrapper_record_sha256,
            "observed_axioms": list(observed_axioms),
            "failure_code": failure_code,
        }
        return self._receipt(
            request,
            candidate_sha256=candidate.candidate_sha256,
            accepted=failure_code is None,
            failure_code=failure_code,
            elapsed_ms=max(0, round(observation.elapsed_seconds * 1000)),
            evidence=evidence,
        )

    def _receipt(
        self,
        request: FateVerificationRequestV1,
        *,
        candidate_sha256: str | None,
        accepted: bool,
        failure_code: str | None,
        elapsed_ms: int,
        evidence: Mapping[str, object],
    ) -> FateVerificationReceiptV1:
        evidence_sha256 = _sha256(canonical_json_bytes(evidence))
        return _build_verification_receipt(
            request,
            receipt_issuer=self._receipt_issuer,
            checked_at=self._clock(),
            verifier_id=self._verifier_id,
            accepted=accepted,
            candidate_sha256=candidate_sha256,
            evidence_sha256=evidence_sha256,
            verifier_elapsed_ms=elapsed_ms,
            failure_code=failure_code,
        )


@dataclass(frozen=True, slots=True)
class PreparedFateAttemptV1:
    """One answer-free model request and its exact immutable work bundle."""

    problem_id: FateProblemId
    attempt_number: int
    attempt_seed: str
    request: ModelRequest
    work_bundle: ModelWorkBundleV2


@dataclass(frozen=True, slots=True)
class FateTestOnlyAttemptV1:
    """Explicit wrapper preventing fixture verdicts from looking authoritative."""

    attempt: FateVerifiedAttemptV1
    production_evidence: Literal[False] = False


@dataclass(frozen=True, slots=True)
class FateTestOnlyEvaluationV1:
    """A complete pipeline exercise that is ineligible for model claims."""

    report: FateEvaluationReportV1
    production_evidence: Literal[False] = False


def _fate_egress_packet(request: ModelRequest) -> str:
    """Canonical text covering every model-visible string in a tool-free FATE request."""

    return canonical_json_bytes(
        {
            "schema_version": "autolean.fate-derived-egress-packet.v1",
            "content_class": "autolean-derived-model-egress",
            "source_provenance": "pinned-fate-task-plus-autolean-instructions",
            "system_prompt": request.system_prompt,
            "prompt": request.prompt,
        }
    ).decode("ascii")


def validate_fate_egress_binding(
    prepared: PreparedFateAttemptV1,
    *,
    expected_source_bytes: bytes,
) -> None:
    """Recompute source, prompt, and request bindings immediately before provider I/O."""

    bundle = prepared.work_bundle
    request = prepared.request
    if (
        digest_bytes(HashKindV1.SOURCE_BYTES, expected_source_bytes)
        != bundle.source.source_content_hash
    ):
        raise FateExecutionError("FATE model work source bytes differ from the pinned task")
    if bundle.rights.source_identity_hash != bundle.source.source_identity_hash:
        raise FateExecutionError("FATE model work rights do not bind its exact source")
    if request.tools or request.working_directory is not None:
        raise FateExecutionError("FATE model work forbids tools and working-directory access")
    if request.context_pack_hash != bundle.context_pack_hash:
        raise FateExecutionError("FATE request context hash differs from its work bundle")
    if request.outbound_request_hash() != bundle.request_hash:
        raise FateExecutionError("FATE outbound request differs from its work bundle")
    egress_packet = _fate_egress_packet(request)
    expected_egress_hash = digest_text(HashKindV1.SOURCE_SPAN, egress_packet)
    if expected_egress_hash != bundle.egress_content_hash:
        raise FateExecutionError("FATE derived egress packet differs from its work bundle")
    matching = tuple(
        span for span in bundle.source.spans if span.content_hash == bundle.egress_content_hash
    )
    if len(matching) != 1:
        raise FateExecutionError("FATE derived egress packet lacks one prompt-free exact-hash span")


def prepare_fate_attempt(
    *,
    adapter: FateAdapter,
    source_bytes: bytes,
    problem_id: FateProblemId,
    attempt_number: int,
    plan: FateRunPlanV1,
    authority: FateModelWorkAuthorityV1,
) -> PreparedFateAttemptV1:
    """Prepare one proof-slot-only request without any answer, tool, or retrieval data."""

    if not 1 <= attempt_number <= plan.attempt_budget:
        raise FateExecutionError("attempt_number is outside the frozen run budget")
    if adapter.manifest.content_hash != plan.fate_manifest_hash:
        raise FateExecutionError("FATE adapter manifest differs from the frozen run plan")
    task = adapter.task(problem_id)
    task.validate_source(source_bytes)
    try:
        source_text = source_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise FateExecutionError("FATE source is not UTF-8") from error
    # ContractModel trims string fields. The exact file remains byte-hashed below; only
    # boundary whitespace is removed from the model-visible source rendering.
    egress_source_text = source_text.strip()
    if not egress_source_text:
        raise FateExecutionError("FATE source is empty after prompt normalization")
    attempt_seed = _sha256(
        canonical_json_bytes(
            {
                "schema_version": "autolean.fate-attempt-seed.v1",
                "run_id": plan.run_id,
                "problem_id": problem_id.canonical,
                "attempt_number": attempt_number,
            }
        )
    )
    prompt = (
        "FATE_TASK_JSON\n"
        + canonical_json_bytes(
            {
                "schema_version": "autolean.fate-prover-input.v1",
                "benchmark": "FATE",
                "release": "v4.28.0",
                "problem_id": problem_id.canonical,
                "attempt_number": attempt_number,
                "attempt_seed": attempt_seed,
                "target_declaration": task.target.qualified_name,
                "source_sha256": task.source_sha256,
                "signature_sha256": task.target.signature_sha256,
                "proof_slot_mode": task.proof_slot.mode,
                "proof_slot_original_token": "sorry",
                "answers_included": False,
                "tools_enabled": False,
                "retrieval_enabled": False,
            }
        ).decode("ascii")
        + "LEAN_SOURCE\n"
        + egress_source_text
    )
    context_hash = digest_model(
        HashKindV1.PROMPT,
        {
            "schema_version": "autolean.fate-prover-context.v1",
            "system_prompt": _SYSTEM_PROMPT,
            "prompt": prompt,
        },
    )
    request = ModelRequest(
        prompt=prompt,
        system_prompt=_SYSTEM_PROMPT,
        timeout_seconds=float(plan.model_request_timeout_seconds),
        max_input_tokens=plan.max_input_tokens,
        max_output_tokens=plan.max_output_tokens,
        reasoning_effort=plan.reasoning_effort,
        required_capabilities=_BASE_CAPABILITIES,
        context_pack_hash=context_hash,
    )
    egress_packet = _fate_egress_packet(request)
    egress_span = SourceSpanV1(
        span_id=stable_identifier(
            "fate-derived-egress-span",
            f"{plan.run_id}:{task.task_id}:{attempt_number}:{request.outbound_request_hash().value}",
        ),
        locator=(
            "derived://autolean/fate-prover-egress/"
            f"{plan.run_id}/{task.task_id.lower()}/{attempt_number}"
        ),
        content_hash=digest_text(HashKindV1.SOURCE_SPAN, egress_packet),
        permitted_excerpt=None,
    )
    task_source = SourceRecordV1(
        source_id=stable_identifier(
            "fate-task-source",
            f"{plan.fate_manifest_hash}:{task.task_id}:{task.source_sha256}",
        ),
        work_id="frenzymath/FATE",
        title=f"FATE v4.28.0 task {task.task_id}",
        version="v4.28.0",
        locator=(
            "https://github.com/frenzymath/FATE/blob/"
            f"{adapter.manifest.root_commit}/{task.source_path}"
        ),
        content_hash=digest_bytes(HashKindV1.SOURCE_BYTES, source_bytes),
        snapshot_ref=f"sha256:{task.source_sha256}",
        retrieved_at=authority.source.retrieved_at,
        spans=(egress_span,),
        metadata={
            "contains_solutions": False,
            "derived_span_contains_autolean_instructions": True,
            "fate_manifest_sha256": plan.fate_manifest_hash,
            "fate_lock_sha256": authority.lock_sha256,
            "source_path": task.source_path,
            "source_sha256": task.source_sha256,
            "signature_sha256": task.target.signature_sha256,
        },
    )
    task_rights = authority.rights.model_copy(
        update={
            "rights_id": stable_identifier(
                "fate-task-rights",
                f"{task_source.source_id.value}:{authority.rights.rights_id.value}",
            ),
            "source_id": task_source.source_id,
        }
    )
    cell_contract_hash = _sha256(
        canonical_json_bytes(
            {
                "schema_version": "autolean.fate-prover-cell.v1",
                "suite": plan.suite,
                "prompt_policy_hash": plan.prompt_policy_hash,
                "split_manifest_hash": plan.split_manifest_hash,
                "attempt_budget": plan.attempt_budget,
                "model_request_timeout_seconds": plan.model_request_timeout_seconds,
                "verifier_timeout_seconds": plan.verifier_timeout_seconds,
                "settlement_margin_seconds": plan.settlement_margin_seconds,
                "max_cost_microusd_per_attempt": plan.max_cost_microusd_per_attempt,
                "tools_hash": DISABLED_TOOLS_HASH,
                "retrieval_scope_hash": DISABLED_RETRIEVAL_HASH,
            }
        )
    )
    case_contract_hash = _sha256(canonical_json_bytes(task.to_dict()))
    work_item_hash = _sha256(
        canonical_json_bytes(
            {
                "schema_version": "autolean.fate-prover-work-item.v1",
                "problem_id": problem_id.canonical,
                "attempt_number": attempt_number,
                "attempt_seed": attempt_seed,
                "case_contract_hash": case_contract_hash,
                "context_pack_hash": context_hash.value,
            }
        )
    )
    run_hash = model_work_run_hash(plan.run_id)
    cell_hash = model_work_cell_hash("fate-prover")
    case_hash = model_work_case_hash(problem_id.canonical.lower())
    typed_cell_contract_hash = model_work_cell_contract_hash(cell_contract_hash)
    typed_case_contract_hash = model_work_case_contract_hash(case_contract_hash)
    typed_work_item_hash = model_work_item_hash(work_item_hash)
    work_bundle = ModelWorkBundleV2(
        bundle_id=model_work_bundle_id(
            run_hash=run_hash,
            cell_hash=cell_hash,
            case_hash=case_hash,
            repetition=attempt_number,
            role=ModelWorkRoleV1.PROVER,
        ),
        work_contract_id=model_work_contract_id(
            cell_contract_hash=typed_cell_contract_hash,
            case_contract_hash=typed_case_contract_hash,
        ),
        run_hash=run_hash,
        cell_hash=cell_hash,
        case_hash=case_hash,
        repetition=attempt_number,
        role=ModelWorkRoleV1.PROVER,
        cell_contract_hash=typed_cell_contract_hash,
        case_contract_hash=typed_case_contract_hash,
        work_item_hash=typed_work_item_hash,
        role_environment_hash=digest_model(
            HashKindV1.ENVIRONMENT,
            {
                "schema_version": "autolean.fate-prover-environment.v1",
                "environment_hash": plan.environment_hash,
                "fate_manifest_hash": plan.fate_manifest_hash,
                "fate_lock_hash": authority.lock_sha256,
            },
        ),
        egress_content_hash=egress_span.content_hash,
        context_pack_hash=context_hash,
        request_hash=request.outbound_request_hash(),
        source=model_work_source_binding(task_source),
        rights=model_work_rights_binding(task_rights),
    )
    prepared = PreparedFateAttemptV1(
        problem_id=problem_id,
        attempt_number=attempt_number,
        attempt_seed=attempt_seed,
        request=request,
        work_bundle=work_bundle,
    )
    validate_fate_egress_binding(prepared, expected_source_bytes=source_bytes)
    return prepared


class FateExecutionEngineV1:
    """Run or resume one fixed FATE suite through the authorized provider path."""

    def __init__(
        self,
        *,
        plan: FateRunPlanV1,
        adapter: FateAdapter,
        prompt_sources: Mapping[str, bytes],
        authority: FateModelWorkAuthorityV1,
        approval_id: StableIdentifierV1,
        authorization_service: ModelExecutionAuthorizationService,
        registry: ProviderRegistry,
        events: EventStore,
        private_artifacts: OperatorPrivateArtifactStore,
        verifier: FateCandidateVerifier,
        verifier_trust_policy: IndependentExecutionTrustPolicyV1,
        execution_nonce: str,
        work_admissions: Mapping[str, AttestationV1],
        monotonic: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], datetime] | None = None,
        lease_ttl_seconds: float = 900,
        authorization_ttl_seconds: float = 600,
    ) -> None:
        _require_safe_id(execution_nonce, label="execution_nonce")
        if lease_ttl_seconds <= 0 or authorization_ttl_seconds <= 0:
            raise FateExecutionError("lease and authorization TTLs must be positive")
        if authorization_ttl_seconds < plan.model_authorization_window_seconds:
            raise FateExecutionError(
                "authorization TTL cannot cover the model timeout and settlement margin"
            )
        if lease_ttl_seconds < plan.attempt_lease_window_seconds:
            raise FateExecutionError(
                "lease TTL cannot cover the model, verifier, and terminal settlement window"
            )
        if authorization_ttl_seconds + 1.0 > lease_ttl_seconds:
            raise FateExecutionError(
                "worker lease TTL must outlive authorization TTL by at least one second"
            )
        if plan.fate_manifest_hash != adapter.manifest.content_hash:
            raise FateExecutionError("FATE run plan does not match the adapter manifest")
        expected_source_hash = digest_bytes(
            HashKindV1.SOURCE_BYTES,
            adapter.manifest.to_json().encode("utf-8"),
        )
        if authority.source.content_hash != expected_source_hash:
            raise FateExecutionError("FATE authority source does not hash the adapter manifest")
        if authority.rights.source_id != authority.source.source_id:
            raise FateExecutionError("FATE authority rights and source differ")
        if not isinstance(verifier_trust_policy, IndependentExecutionTrustPolicyV1):
            raise FateExecutionError("FATE verifier trust policy is required")
        if verifier.execution_class is not verifier_trust_policy.execution_class:
            raise FateExecutionError("FATE verifier execution class differs from its trust policy")
        admission_snapshot = dict(work_admissions)
        if not admission_snapshot:
            raise FateExecutionError("FATE model work admissions are required")
        selected = selected_fate_problems(plan.suite)
        source_snapshot = dict(prompt_sources)
        expected_ids = {problem.canonical for problem in selected}
        if set(source_snapshot) != expected_ids:
            raise FateExecutionError("prompt source snapshot must cover exactly the selected suite")
        for problem in selected:
            adapter.task(problem).validate_source(source_snapshot[problem.canonical])
        self._plan = plan
        self._adapter = adapter
        self._prompt_sources = source_snapshot
        self._authority = authority
        self._approval_id = approval_id
        self._authorization_service = authorization_service
        self._registry = registry
        self._events = events
        self._private_artifacts = private_artifacts
        self._verifier = verifier
        self._verifier_trust_policy = verifier_trust_policy
        self._work_admissions = admission_snapshot
        self._execution_nonce = execution_nonce
        self._monotonic = monotonic
        self._wall_clock = wall_clock or (lambda: datetime.now(UTC))
        self._lease_ttl_seconds = lease_ttl_seconds
        self._authorization_ttl_seconds = authorization_ttl_seconds
        self._observed_approval: ModelExecutionProviderApprovalV1 | None = None
        self._observed_effective_model_timeout_seconds: float | None = None

    def run(self) -> FateEvaluationReportV1:
        if (
            self._verifier_trust_policy.execution_class
            is not IndependentExecutionClassV1.PRODUCTION
        ):
            raise FateLiveExecutionBlocked("production_verifier_authority_required")
        return self._run()

    def run_test_only(self) -> FateTestOnlyEvaluationV1:
        if self._verifier_trust_policy.execution_class is not IndependentExecutionClassV1.TEST_ONLY:
            raise FateExecutionError(
                "production verifier results cannot enter the test-only report path"
            )
        return FateTestOnlyEvaluationV1(report=self._run())

    def _run(self) -> FateEvaluationReportV1:
        results: list[FateProblemResultV1] = []
        for problem in selected_fate_problems(self._plan.suite):
            attempts: list[FateVerifiedAttemptV1] = []
            for attempt_number in range(1, self._plan.attempt_budget + 1):
                attempt = self._execute_attempt(problem, attempt_number)
                attempts.append(attempt)
                if attempt.accepted:
                    break
            terminal_status: Literal["success", "budget_exhausted"] = (
                "success" if attempts[-1].accepted else "budget_exhausted"
            )
            results.append(
                FateProblemResultV1(
                    problem_id=problem,
                    terminal_status=terminal_status,
                    attempts=tuple(attempts),
                )
            )
        approval = self._observed_approval
        if approval is None:
            raise FateExecutionError("complete FATE report lacks an issued approval snapshot")
        effective_model_timeout = self._observed_effective_model_timeout_seconds
        if effective_model_timeout is None:
            raise FateExecutionError("complete FATE report lacks an effective model timeout")
        return FateEvaluationReportV1(
            config=self._plan.reporting_config(
                approval,
                effective_model_timeout_seconds=effective_model_timeout,
            ),
            results=tuple(results),
        )

    def execute_attempt(
        self,
        problem_id: FateProblemId,
        attempt_number: int,
    ) -> FateVerifiedAttemptV1:
        if (
            self._verifier_trust_policy.execution_class
            is not IndependentExecutionClassV1.PRODUCTION
        ):
            raise FateLiveExecutionBlocked("production_verifier_authority_required")
        return self._execute_attempt(problem_id, attempt_number)

    def execute_test_only_attempt(
        self,
        problem_id: FateProblemId,
        attempt_number: int,
    ) -> FateTestOnlyAttemptV1:
        if self._verifier_trust_policy.execution_class is not IndependentExecutionClassV1.TEST_ONLY:
            raise FateExecutionError(
                "production verifier results cannot enter the test-only attempt path"
            )
        return FateTestOnlyAttemptV1(attempt=self._execute_attempt(problem_id, attempt_number))

    def _execute_attempt(
        self,
        problem_id: FateProblemId,
        attempt_number: int,
    ) -> FateVerifiedAttemptV1:
        prepared = prepare_fate_attempt(
            adapter=self._adapter,
            source_bytes=self._prompt_sources[problem_id.canonical],
            problem_id=problem_id,
            attempt_number=attempt_number,
            plan=self._plan,
            authority=self._authority,
        )
        bundle = prepared.work_bundle
        existing = self._events.read_stream(
            _EVENT_ENTITY_TYPE,
            bundle.bundle_id.value,
        )
        if existing:
            return self._resume_attempt(prepared, existing)

        started_at = self._monotonic()
        admission = self._work_admissions.get(bundle.bundle_id.value)
        if admission is None:
            raise FateLiveExecutionBlocked("model_work_admission_required")
        now = self._wall_clock()
        if now.tzinfo is None:
            raise FateExecutionError("FATE wall clock must be timezone-aware")
        admission_remaining_seconds = (admission.expires_at - now.astimezone(UTC)).total_seconds()
        if (
            admission_remaining_seconds
            < self._authorization_ttl_seconds + _AUTHORITY_SETUP_MARGIN_SECONDS
        ):
            raise FateLiveExecutionBlocked("model_work_admission_deadline_insufficient")
        self._authorization_service.preflight_authorization_ttl(self._authorization_ttl_seconds)
        self._authorization_service.preflight_model_work_registration(
            bundle,
            admission=admission,
            required_validity_seconds=(
                self._authorization_ttl_seconds + _AUTHORITY_SETUP_MARGIN_SECONDS
            ),
        )
        self._authorization_service.register_model_work(
            bundle,
            admission=admission,
        )
        lease = self._authorization_service.claim_model_work(
            bundle,
            ttl_seconds=self._lease_ttl_seconds,
        )
        budget = ModelExecutionBudgetV1(
            max_attempts=1,
            max_input_tokens=prepared.request.max_input_tokens,
            max_output_tokens=prepared.request.max_output_tokens,
            max_total_tokens=(
                prepared.request.max_input_tokens + prepared.request.max_output_tokens
            ),
            max_cost_microusd=self._plan.max_cost_microusd_per_attempt,
        )
        authorization = self._authorization_service.issue_model_work(
            bundle,
            approval_id=self._approval_id,
            budget=budget,
            lease=lease,
            ttl_seconds=self._authorization_ttl_seconds,
        )
        self._remember_approval(authorization.approval_snapshot)
        effective_model_timeout = self._registry.effective_timeout_seconds(
            authorization.provider,
            prepared.request,
        )
        if effective_model_timeout != float(self._plan.model_request_timeout_seconds):
            raise FateLiveExecutionBlocked("provider_timeout_ceiling_below_frozen_plan")
        self._registry.preflight_generate(authorization, prepared.request)
        self._assert_attempt_authority_windows(
            authorization,
            effective_model_timeout_seconds=effective_model_timeout,
        )
        self._remember_effective_model_timeout(effective_model_timeout)
        if (
            self._verifier_trust_policy.execution_class is IndependentExecutionClassV1.TEST_ONLY
            and authorization.provider.endpoint_class is not EndpointClassV1.LOCAL
        ):
            raise FateLiveExecutionBlocked("test_only_fate_execution_requires_local_provider")
        start_payload: dict[str, JsonValue] = {
            "schema_version": _SCHEMA_VERSION,
            "bundle_id": bundle.bundle_id.value,
            "bundle_hash": bundle.handoff_hash().value,
            "authorization_hash": authorization.authorization_hash().value,
            "approval_hash": authorization.approval_hash().value,
            "run_id": self._plan.run_id,
            "problem_id": problem_id.canonical,
            "attempt_number": attempt_number,
            "attempt_seed": prepared.attempt_seed,
            "request_hash": bundle.request_hash.value,
            "context_pack_hash": bundle.context_pack_hash.value,
            "effective_model_timeout_seconds": effective_model_timeout,
            "execution_nonce": self._execution_nonce,
            "raw_output_persisted": False,
        }
        started_events = self._events.append_fenced(
            _EVENT_ENTITY_TYPE,
            bundle.bundle_id.value,
            task_id=bundle.bundle_id.value,
            lease=lease,
            expected_sequence=0,
            events=(NewEvent(event_type=_STARTED_EVENT, payload=start_payload),),
        )
        if len(started_events) != 1 or started_events[0].payload != start_payload:
            raise FateAttemptAmbiguous("FATE attempt start could not be uniquely committed")

        try:
            validate_fate_egress_binding(
                prepared,
                expected_source_bytes=self._prompt_sources[problem_id.canonical],
            )
            response = self._registry.generate(authorization, prepared.request)
            raw_output = response.text.encode("utf-8")
            raw_ref = self._private_artifacts.put_bytes(raw_output)
            candidate: FatePatchedSourceV1 | None
            boundary_failure: FateBoundaryFailureV1 | None
            try:
                candidate = self._adapter.materialize_proof(
                    problem_id,
                    response.text,
                )
            except FatePatchRejected:
                candidate = None
                boundary_failure = "proof_boundary_rejected"
            else:
                boundary_failure = None
                candidate_ref = self._private_artifacts.put_bytes(candidate.source)
                if candidate_ref.digest != candidate.candidate_sha256:
                    raise FateExecutionError("private candidate CAS hash differs")
            task = self._adapter.task(problem_id)
            verification_request = FateVerificationRequestV1(
                run_id=self._plan.run_id,
                problem_id=problem_id,
                attempt_number=attempt_number,
                task_source_sha256=task.source_sha256,
                signature_sha256=task.target.signature_sha256,
                raw_output_sha256=raw_ref.digest,
                candidate=candidate,
                boundary_failure=boundary_failure,
                environment_hash=self._plan.environment_hash,
                timeout_seconds=self._plan.verifier_timeout_seconds,
            )
            receipt = self._verifier.verify(verification_request)
            self._validate_receipt(
                receipt,
                request=verification_request,
                candidate=candidate,
            )
            elapsed_ms = max(0, round((self._monotonic() - started_at) * 1000))
            cost_microusd = authorization.pricing.cost_for_usage(
                input_tokens=response.usage.input_tokens,
                cached_input_tokens=response.usage.cached_input_tokens,
                output_tokens=response.usage.output_tokens,
            )
            private_receipt_ref = self._private_artifacts.put_bytes(receipt.private_bytes())
            self._private_artifacts.put_attempt_record(
                FatePrivateAttemptRecordV1(
                    run_id=self._plan.run_id,
                    problem_id=problem_id,
                    attempt_number=attempt_number,
                    raw_output_sha256=raw_ref.digest,
                    candidate_sha256=receipt.candidate_sha256,
                    verifier_evidence_sha256=receipt.evidence_sha256,
                    independent_execution_receipt_hash=(
                        receipt.independent_execution_receipt.receipt_hash
                    ),
                    verifier_receipt_artifact_sha256=private_receipt_ref.digest,
                )
            )
            terminal_payload = self._terminal_payload(
                prepared=prepared,
                authorization=authorization,
                response=response,
                receipt=receipt,
                effective_model_timeout_seconds=effective_model_timeout,
                elapsed_ms=elapsed_ms,
                cost_microusd=cost_microusd,
            )
            terminal = self._events.append_fenced(
                _EVENT_ENTITY_TYPE,
                bundle.bundle_id.value,
                task_id=bundle.bundle_id.value,
                lease=lease,
                expected_sequence=1,
                events=(
                    NewEvent(
                        event_type=_VERIFIED_EVENT,
                        payload=terminal_payload,
                    ),
                ),
                idempotency=Idempotency(
                    scope="fate-attempt-terminal",
                    key=bundle.bundle_id.value,
                    request_hash=request_hash(terminal_payload),
                ),
            )
        except BaseException as error:
            if isinstance(error, (KeyboardInterrupt, SystemExit)):
                raise
            raise FateAttemptAmbiguous(
                "FATE attempt started; automatic provider replay is forbidden"
            ) from None
        if len(terminal) != 1:
            raise FateAttemptAmbiguous("FATE verifier result was not committed exactly once")
        return self._attempt_from_terminal(prepared, terminal[0])

    def _resume_attempt(
        self,
        prepared: PreparedFateAttemptV1,
        events: tuple[StoredEvent, ...],
    ) -> FateVerifiedAttemptV1:
        if len(events) == 1 and events[0].event_type == _STARTED_EVENT:
            raise FateAttemptAmbiguous(
                "FATE attempt has a durable start without a terminal verifier event"
            )
        if (
            len(events) != 2
            or events[0].event_type != _STARTED_EVENT
            or events[1].event_type != _VERIFIED_EVENT
        ):
            raise FateExecutionError("FATE attempt event stream has an invalid shape")
        self._validate_started_payload(prepared, events[0].payload)
        for field in (
            "bundle_id",
            "run_id",
            "problem_id",
            "attempt_number",
            "attempt_seed",
        ):
            if events[0].payload[field] != events[1].payload.get(field):
                raise FateExecutionError("FATE terminal identity differs from its started event")
        return self._attempt_from_terminal(prepared, events[1])

    def _remember_approval(
        self,
        approval: ModelExecutionProviderApprovalV1,
    ) -> None:
        if approval.approval_id != self._approval_id:
            raise FateExecutionError("issued model authorization used another provider approval")
        if self._observed_approval is None:
            self._observed_approval = approval
        elif self._observed_approval != approval:
            raise FateExecutionError("one FATE run cannot mix provider approval snapshots")

    def _remember_effective_model_timeout(self, timeout_seconds: float) -> None:
        if timeout_seconds != float(self._plan.model_request_timeout_seconds):
            raise FateExecutionError("effective model timeout differs from the frozen run plan")
        if self._observed_effective_model_timeout_seconds is None:
            self._observed_effective_model_timeout_seconds = timeout_seconds
        elif self._observed_effective_model_timeout_seconds != timeout_seconds:
            raise FateExecutionError("one FATE run cannot mix effective model timeouts")

    def _assert_attempt_authority_windows(
        self,
        authorization: ModelExecutionAuthorizationV1,
        *,
        effective_model_timeout_seconds: float,
    ) -> None:
        now = self._wall_clock()
        if now.tzinfo is None:
            raise FateExecutionError("FATE wall clock must be timezone-aware")
        now_utc = now.astimezone(UTC)
        authorization_window = (authorization.expires_at - now_utc).total_seconds()
        lease_window = (authorization.lease.expires_at - now_utc).total_seconds()
        required_authorization_window = (
            effective_model_timeout_seconds + self._plan.settlement_margin_seconds
        )
        required_lease_window = (
            effective_model_timeout_seconds
            + self._plan.verifier_timeout_seconds
            + self._plan.settlement_margin_seconds
        )
        if authorization_window < required_authorization_window:
            raise FateLiveExecutionBlocked("model_authorization_deadline_insufficient")
        if lease_window < required_lease_window:
            raise FateLiveExecutionBlocked("attempt_lease_deadline_insufficient")

    def _validate_receipt(
        self,
        receipt: FateVerificationReceiptV1,
        *,
        request: FateVerificationRequestV1,
        candidate: FatePatchedSourceV1 | None,
    ) -> None:
        task = self._adapter.task(request.problem_id)
        expected_candidate = None if candidate is None else candidate.candidate_sha256
        if (
            receipt.problem_id != request.problem_id
            or receipt.attempt_number != request.attempt_number
            or receipt.candidate_sha256 != expected_candidate
            or receipt.task_source_sha256 != task.source_sha256
            or receipt.signature_sha256 != task.target.signature_sha256
            or receipt.environment_hash != self._plan.environment_hash
        ):
            raise FateExecutionError("independent verifier receipt binding differs")
        if receipt.accepted and candidate is None:
            raise FateExecutionError("verifier accepted an absent candidate")
        independent = receipt.independent_execution_receipt
        if (
            independent.verifier_id != receipt.verifier_id
            or independent.request_hash != request.request_hash()
            or independent.evidence_artifact_digest != receipt.evidence_sha256
            or independent.evidence_digest != receipt.evidence_sha256
            or independent.execution_claim_hash != receipt.verification_claim_hash()
        ):
            raise FateExecutionError("authenticated independent execution receipt binding differs")
        try:
            self._verifier_trust_policy.authenticate(independent)
        except ValueError as error:
            raise FateExecutionError("independent verifier receipt is not trusted") from error

    def _terminal_payload(
        self,
        *,
        prepared: PreparedFateAttemptV1,
        authorization: ModelExecutionAuthorizationV1,
        response: ModelResponse,
        receipt: FateVerificationReceiptV1,
        effective_model_timeout_seconds: float,
        elapsed_ms: int,
        cost_microusd: int,
    ) -> dict[str, JsonValue]:
        bundle = prepared.work_bundle
        authentication = receipt.independent_execution_receipt.authentication
        if authentication is None:
            raise FateExecutionError("independent verifier receipt lacks authentication")
        return {
            "schema_version": _SCHEMA_VERSION,
            "bundle_id": bundle.bundle_id.value,
            "bundle_hash": bundle.handoff_hash().value,
            "authorization_hash": authorization.authorization_hash().value,
            "approval_hash": authorization.approval_hash().value,
            "approval_snapshot": authorization.approval_snapshot.model_dump(mode="json"),
            "run_id": self._plan.run_id,
            "problem_id": prepared.problem_id.canonical,
            "attempt_number": prepared.attempt_number,
            "attempt_seed": prepared.attempt_seed,
            "verification_event_id": receipt.verification_event_id,
            "verifier_id": receipt.verifier_id,
            "verification_authority_key_id": authentication.key_id,
            "execution_class": self._verifier_trust_policy.execution_class.value,
            "effective_model_timeout_seconds": effective_model_timeout_seconds,
            "verifier_failure_code": receipt.failure_code,
            "accepted": receipt.accepted,
            "elapsed_ms": elapsed_ms,
            "verifier_elapsed_ms": receipt.verifier_elapsed_ms,
            "input_tokens": response.usage.input_tokens,
            "cached_input_tokens": response.usage.cached_input_tokens,
            "output_tokens": response.usage.output_tokens,
            "cost_microusd": cost_microusd,
            "contains_raw_output": False,
            "contains_candidate_source": False,
            "contains_private_digests": False,
            "private_artifacts_persisted": True,
        }

    def _attempt_from_terminal(
        self,
        prepared: PreparedFateAttemptV1,
        event: StoredEvent,
    ) -> FateVerifiedAttemptV1:
        payload = event.payload
        self._validate_terminal_payload(prepared, payload)
        private_record = self._private_artifacts.get_attempt_record(
            self._plan.run_id,
            prepared.problem_id,
            prepared.attempt_number,
        )
        self._private_artifacts.get_bytes(private_record.raw_output_sha256)
        if private_record.candidate_sha256 is not None:
            self._private_artifacts.get_bytes(private_record.candidate_sha256)
        private_receipt = FateVerificationReceiptV1.from_private_bytes(
            self._private_artifacts.get_bytes(private_record.verifier_receipt_artifact_sha256)
        )
        self._validate_private_terminal_receipt(
            prepared,
            payload=payload,
            private_record=private_record,
            receipt=private_receipt,
        )
        if payload["accepted"] is True and private_record.candidate_sha256 is None:
            raise FateExecutionError(
                "accepted FATE terminal event lacks its private candidate artifact"
            )
        return FateVerifiedAttemptV1(
            problem_id=prepared.problem_id,
            attempt_number=prepared.attempt_number,
            verification_event_id=cast(str, payload["verification_event_id"]),
            accepted=cast(bool, payload["accepted"]),
            elapsed_ms=cast(int, payload["elapsed_ms"]),
            input_tokens=cast(int, payload["input_tokens"]),
            output_tokens=cast(int, payload["output_tokens"]),
            cost_microusd=cast(int, payload["cost_microusd"]),
        )

    def _validate_private_terminal_receipt(
        self,
        prepared: PreparedFateAttemptV1,
        *,
        payload: JsonObject,
        private_record: FatePrivateAttemptRecordV1,
        receipt: FateVerificationReceiptV1,
    ) -> None:
        task = self._adapter.task(prepared.problem_id)
        boundary_failure: FateBoundaryFailureV1 | None = (
            "proof_boundary_rejected" if private_record.candidate_sha256 is None else None
        )
        expected_request_hash = _verification_request_hash(
            run_id=self._plan.run_id,
            problem_id=prepared.problem_id,
            attempt_number=prepared.attempt_number,
            task_source_sha256=task.source_sha256,
            signature_sha256=task.target.signature_sha256,
            raw_output_sha256=private_record.raw_output_sha256,
            candidate_sha256=private_record.candidate_sha256,
            boundary_failure=boundary_failure,
            environment_hash=self._plan.environment_hash,
            timeout_seconds=self._plan.verifier_timeout_seconds,
        )
        independent = receipt.independent_execution_receipt
        authentication = independent.authentication
        if (
            receipt.problem_id != prepared.problem_id
            or receipt.attempt_number != prepared.attempt_number
            or receipt.candidate_sha256 != private_record.candidate_sha256
            or receipt.task_source_sha256 != task.source_sha256
            or receipt.signature_sha256 != task.target.signature_sha256
            or receipt.environment_hash != self._plan.environment_hash
            or receipt.verification_event_id != payload["verification_event_id"]
            or receipt.verifier_id != payload["verifier_id"]
            or receipt.accepted != payload["accepted"]
            or receipt.failure_code != payload["verifier_failure_code"]
            or receipt.verifier_elapsed_ms != payload["verifier_elapsed_ms"]
            or receipt.evidence_sha256 != private_record.verifier_evidence_sha256
            or independent.receipt_hash != private_record.independent_execution_receipt_hash
            or independent.verifier_id != receipt.verifier_id
            or independent.request_hash != expected_request_hash
            or independent.evidence_artifact_digest != receipt.evidence_sha256
            or independent.evidence_digest != receipt.evidence_sha256
            or independent.execution_claim_hash != receipt.verification_claim_hash()
            or authentication is None
            or authentication.key_id != payload["verification_authority_key_id"]
        ):
            raise FateExecutionError("private verifier receipt differs from the terminal event")
        try:
            self._verifier_trust_policy.authenticate(independent)
        except ValueError as error:
            raise FateExecutionError(
                "stored independent verifier receipt is not trusted"
            ) from error

    def _validate_started_payload(
        self,
        prepared: PreparedFateAttemptV1,
        payload: JsonObject,
    ) -> None:
        required = {
            "schema_version",
            "bundle_id",
            "bundle_hash",
            "authorization_hash",
            "approval_hash",
            "run_id",
            "problem_id",
            "attempt_number",
            "attempt_seed",
            "request_hash",
            "context_pack_hash",
            "effective_model_timeout_seconds",
            "execution_nonce",
            "raw_output_persisted",
        }
        if set(payload) != required:
            raise FateExecutionError("FATE started event has an unsupported schema")
        bundle = prepared.work_bundle
        if (
            payload["schema_version"] != _SCHEMA_VERSION
            or payload["bundle_id"] != bundle.bundle_id.value
            or payload["bundle_hash"] != bundle.handoff_hash().value
            or payload["run_id"] != self._plan.run_id
            or payload["problem_id"] != prepared.problem_id.canonical
            or payload["attempt_number"] != prepared.attempt_number
            or payload["attempt_seed"] != prepared.attempt_seed
            or payload["request_hash"] != bundle.request_hash.value
            or payload["context_pack_hash"] != bundle.context_pack_hash.value
            or payload["raw_output_persisted"] is not False
        ):
            raise FateExecutionError("FATE started event binding differs")
        effective_model_timeout = payload["effective_model_timeout_seconds"]
        if (
            isinstance(effective_model_timeout, bool)
            or not isinstance(effective_model_timeout, int | float)
            or float(effective_model_timeout) != float(self._plan.model_request_timeout_seconds)
        ):
            raise FateExecutionError("FATE started effective model timeout differs")
        execution_nonce = payload["execution_nonce"]
        if not isinstance(execution_nonce, str) or not execution_nonce:
            raise FateExecutionError("FATE started execution nonce is invalid")
        for label in ("authorization_hash", "approval_hash"):
            value = payload[label]
            if not isinstance(value, str):
                raise FateExecutionError(f"{label} must be a SHA-256 digest")
            _require_sha256(value, label=label)

    def _validate_terminal_payload(
        self,
        prepared: PreparedFateAttemptV1,
        payload: JsonObject,
    ) -> None:
        required = {
            "schema_version",
            "bundle_id",
            "bundle_hash",
            "authorization_hash",
            "approval_hash",
            "approval_snapshot",
            "run_id",
            "problem_id",
            "attempt_number",
            "attempt_seed",
            "verification_event_id",
            "verifier_id",
            "verification_authority_key_id",
            "execution_class",
            "effective_model_timeout_seconds",
            "verifier_failure_code",
            "accepted",
            "elapsed_ms",
            "verifier_elapsed_ms",
            "input_tokens",
            "cached_input_tokens",
            "output_tokens",
            "cost_microusd",
            "contains_raw_output",
            "contains_candidate_source",
            "contains_private_digests",
            "private_artifacts_persisted",
        }
        if set(payload) != required:
            raise FateExecutionError("FATE terminal event has an unsupported schema")
        bundle = prepared.work_bundle
        if (
            payload["schema_version"] != _SCHEMA_VERSION
            or payload["bundle_id"] != bundle.bundle_id.value
            or payload["bundle_hash"] != bundle.handoff_hash().value
            or payload["run_id"] != self._plan.run_id
            or payload["problem_id"] != prepared.problem_id.canonical
            or payload["attempt_number"] != prepared.attempt_number
            or payload["attempt_seed"] != prepared.attempt_seed
            or payload["contains_raw_output"] is not False
            or payload["contains_candidate_source"] is not False
            or payload["contains_private_digests"] is not False
            or payload["private_artifacts_persisted"] is not True
            or payload["execution_class"] != self._verifier_trust_policy.execution_class.value
        ):
            raise FateExecutionError("FATE terminal event binding differs")
        effective_model_timeout = payload["effective_model_timeout_seconds"]
        if (
            isinstance(effective_model_timeout, bool)
            or not isinstance(effective_model_timeout, int | float)
            or float(effective_model_timeout) != float(self._plan.model_request_timeout_seconds)
        ):
            raise FateExecutionError("FATE terminal effective model timeout differs")
        self._remember_effective_model_timeout(float(effective_model_timeout))
        for label in ("authorization_hash", "approval_hash"):
            value = payload[label]
            if not isinstance(value, str):
                raise FateExecutionError(f"{label} must be a SHA-256 digest")
            _require_sha256(value, label=label)
        raw_approval = payload["approval_snapshot"]
        if not isinstance(raw_approval, dict):
            raise FateExecutionError("FATE terminal approval snapshot is invalid")
        try:
            approval = ModelExecutionProviderApprovalV1.model_validate(raw_approval)
        except ValueError as error:
            raise FateExecutionError("FATE terminal approval snapshot is malformed") from error
        if approval.approval_hash().value != payload["approval_hash"]:
            raise FateExecutionError("FATE terminal approval hash differs")
        self._remember_approval(approval)
        event_id = payload["verification_event_id"]
        verifier_id = payload["verifier_id"]
        authority_key_id = payload["verification_authority_key_id"]
        if (
            not isinstance(event_id, str)
            or _PUBLIC_EVENT_ID.fullmatch(event_id) is None
            or not isinstance(verifier_id, str)
            or _PUBLIC_EVENT_ID.fullmatch(verifier_id) is None
            or not isinstance(authority_key_id, str)
            or _PUBLIC_EVENT_ID.fullmatch(authority_key_id) is None
        ):
            raise FateExecutionError("FATE terminal verifier identity is invalid")
        trusted_identity = self._verifier_trust_policy.trusted_verifiers.get(verifier_id)
        if trusted_identity is None or trusted_identity.authentication_key_id != authority_key_id:
            raise FateExecutionError("FATE terminal verifier authority is not allowlisted")
        accepted = payload["accepted"]
        failure_code = payload["verifier_failure_code"]
        if not isinstance(accepted, bool):
            raise FateExecutionError("FATE terminal accepted flag must be boolean")
        if accepted:
            if failure_code is not None:
                raise FateExecutionError("accepted FATE event lacks a clean verdict")
        elif not isinstance(failure_code, str) or not failure_code:
            raise FateExecutionError("rejected FATE event lacks a failure code")
        for label in (
            "elapsed_ms",
            "verifier_elapsed_ms",
            "input_tokens",
            "cached_input_tokens",
            "output_tokens",
            "cost_microusd",
        ):
            value = payload[label]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise FateExecutionError(f"{label} must be a non-negative integer")
        if cast(int, payload["cached_input_tokens"]) > cast(int, payload["input_tokens"]):
            raise FateExecutionError("cached input tokens exceed total input tokens")
        expected_cost = approval.pricing.cost_for_usage(
            input_tokens=cast(int, payload["input_tokens"]),
            cached_input_tokens=cast(int, payload["cached_input_tokens"]),
            output_tokens=cast(int, payload["output_tokens"]),
        )
        if payload["cost_microusd"] != expected_cost:
            raise FateExecutionError("FATE terminal cost differs from the signed approval pricing")


def require_live_fate_dependencies(
    *,
    operator_approved: bool,
    provider_authority_injected: bool,
    wsl_verifier_injected: bool,
    production_verifier_authority_injected: bool,
    work_admission_authority_injected: bool,
) -> None:
    """Fail closed until every live FATE authority boundary is present."""

    if operator_approved is not True:
        raise FateLiveExecutionBlocked("operator_approval_required")
    if provider_authority_injected is not True:
        raise FateLiveExecutionBlocked("model_execution_authority_required")
    if wsl_verifier_injected is not True:
        raise FateLiveExecutionBlocked("wsl_oci_verifier_required")
    if production_verifier_authority_injected is not True:
        raise FateLiveExecutionBlocked("production_verifier_authority_required")
    if work_admission_authority_injected is not True:
        raise FateLiveExecutionBlocked("model_work_admission_authority_required")
