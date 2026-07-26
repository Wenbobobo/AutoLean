"""Immutable worker input and typed fake-runner receipts for the T7 Lean DAG.

This module is deliberately one layer above the V1 result-recording store.  It
does not launch Lean or Docker.  It seals exact candidate source bytes, an exact
toolchain/image identity, and typed node-verification receipts before adapting them to the
existing lease-fenced event store.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final, Literal, cast

from autolean_control_plane import (
    ArtifactRef,
    ArtifactStore,
    Idempotency,
    Lease,
    NewEvent,
    StoredEvent,
    request_hash,
)
from autolean_control_plane.events import JsonObject

from benchmarks.real_lean_project_dag import RealLeanProjectDagV1
from benchmarks.real_lean_project_dag_change import RealLeanChangeCaseV1
from benchmarks.real_lean_project_dag_execution import (
    FrozenRealLeanRebuildExecutionBundleV1,
    RealLeanRebuildExecutionError,
    RealLeanRebuildExecutionStore,
    RebuildExecutionNodeV1,
    freeze_real_lean_rebuild_execution_bundle,
)
from benchmarks.real_lean_project_dag_rebuild import (
    RealLeanRebuildBundleV1,
    plan_real_lean_rebuild,
)

CHANGED_SOURCE_WITNESS_SCHEMA: Final[str] = "autolean.changed-source-witness.v1"
WORKER_ENVIRONMENT_SCHEMA: Final[str] = "autolean.real-lean-worker-environment.v1"
WORKER_INPUT_SCHEMA: Final[str] = "autolean.real-lean-immutable-worker-input.v1"
LEAN_NODE_VERIFICATION_RECEIPT_SCHEMA: Final[str] = "autolean.lean-node-verification-receipt.v1"
TYPED_WORKER_STATUS_SCHEMA: Final[str] = "autolean.typed-worker-execution-status.v1"
SYNTHETIC_NODE_EVENT_SCHEMA: Final[str] = "autolean.t7-synthetic-node-result.v2"
SYNTHETIC_NODE_COMMIT_SCHEMA: Final[str] = "autolean.t7-synthetic-node-commit.v2"
SYNTHETIC_NODE_EVENT_ENTITY_TYPE: Final[str] = "t7_synthetic_node_v2"
REVIEWED_FIXTURE_WITNESS_CLASS: Final[str] = "reviewed_fixture_manifest_v1"
SYNTHETIC_FAKE_NODE_EVIDENCE_CLASS: Final[str] = "synthetic_fake_node_v1"
REVIEWED_FIXTURE_MANIFEST_SHA256: Final[str] = (
    "8e460eb423e48280ce2243e1a17342c2274b6e9230614f5ccfe7430cbfd6bfb8"
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}$")
_OCI_PATH_COMPONENT = re.compile(r"^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$")
_OCI_REGISTRY_HOST = re.compile(r"^[a-z0-9]+(?:[.-][a-z0-9]+)*$")
_REBUILD = "rebuild"
_REUSE = "reuse"
_VERIFIED = "VERIFIED"
_FAILED = "FAILED"
_REUSED = "REUSED"
_SYNTHETIC_COMPLETE: Final[Literal["SYNTHETIC_COMPLETE"]] = "SYNTHETIC_COMPLETE"
_SYNTHETIC_FAILED: Final[Literal["SYNTHETIC_FAILED"]] = "SYNTHETIC_FAILED"
_SYNTHETIC_REUSED: Final[Literal["SYNTHETIC_REUSED"]] = "SYNTHETIC_REUSED"
_SYNTHETIC_EVENT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "bundle_id",
        "fixture_manifest_sha256",
        "changed_source_witness_sha256",
        "changed_source_witness_artifact",
        "rebuild_plan_sha256",
        "execution_bundle_sha256",
        "execution_bundle_artifact",
        "worker_input_sha256",
        "worker_input_artifact",
        "environment_sha256",
        "environment_artifact",
        "node_id",
        "module",
        "planned_action",
        "typed_outcome",
        "receipt_sha256",
        "receipt_artifact",
        "node_result_artifact",
        "evidence_class",
        "promotion_eligible",
        "lease_holder_id",
        "fencing_token",
    }
)
type NodeVerificationOutcome = Literal["VERIFIED", "FAILED"]
type SyntheticNodeOutcome = Literal[
    "SYNTHETIC_COMPLETE",
    "SYNTHETIC_FAILED",
    "SYNTHETIC_REUSED",
]
type TypedWorkerState = Literal[
    "SYNTHETIC_PENDING",
    "SYNTHETIC_FAILED",
    "SYNTHETIC_COMPLETE",
]


class RealLeanWorkerContractError(RuntimeError):
    """A worker input or typed receipt is incomplete, stale, or inconsistent."""


@dataclass(frozen=True, slots=True)
class ChangedSourceArtifactPairV1:
    """Exact baseline and reviewed candidate source artifacts for one module."""

    module: str
    file: str
    baseline_source_artifact: ArtifactRef
    candidate_source_artifact: ArtifactRef

    def __post_init__(self) -> None:
        if not self.module or not _safe_relative_file(self.file):
            raise RealLeanWorkerContractError("changed-source artifact pair is invalid")

    @property
    def source_changed(self) -> bool:
        return self.baseline_source_artifact != self.candidate_source_artifact


@dataclass(frozen=True, slots=True)
class ChangedSourceWitnessV1:
    """CAS-bound fixture witness replacing free changed-declaration claims."""

    baseline_fixture_manifest_sha256: str
    reviewed_successor_manifest_sha256: str
    reviewed_successor_manifest_artifact: ArtifactRef
    source_artifacts: tuple[ChangedSourceArtifactPairV1, ...]
    changed_module_ids: tuple[str, ...]
    claimed_declaration_ids: tuple[str, ...]
    witness_class: str = REVIEWED_FIXTURE_WITNESS_CLASS
    promotion_eligible: bool = False

    def __post_init__(self) -> None:
        modules = tuple(item.module for item in self.source_artifacts)
        files = tuple(item.file for item in self.source_artifacts)
        if (
            _SHA256.fullmatch(self.baseline_fixture_manifest_sha256) is None
            or self.reviewed_successor_manifest_sha256 != REVIEWED_FIXTURE_MANIFEST_SHA256
            or self.reviewed_successor_manifest_artifact.digest
            != self.reviewed_successor_manifest_sha256
            or not modules
            or len(set(modules)) != len(modules)
            or len(set(files)) != len(files)
            or not self.changed_module_ids
            or len(set(self.changed_module_ids)) != len(self.changed_module_ids)
            or set(self.changed_module_ids) - set(modules)
            or not self.claimed_declaration_ids
            or len(set(self.claimed_declaration_ids)) != len(self.claimed_declaration_ids)
            or self.witness_class != REVIEWED_FIXTURE_WITNESS_CLASS
            or type(self.promotion_eligible) is not bool
            or self.promotion_eligible
        ):
            raise RealLeanWorkerContractError("changed-source witness is invalid")

    def _content_document(self) -> dict[str, object]:
        return {
            "schema_version": CHANGED_SOURCE_WITNESS_SCHEMA,
            "baseline_fixture_manifest_sha256": self.baseline_fixture_manifest_sha256,
            "reviewed_successor_manifest_sha256": (self.reviewed_successor_manifest_sha256),
            "reviewed_successor_manifest_artifact": _artifact_document(
                self.reviewed_successor_manifest_artifact
            ),
            "source_artifacts": [
                {
                    "module": item.module,
                    "file": item.file,
                    "baseline_source_artifact": _artifact_document(item.baseline_source_artifact),
                    "candidate_source_artifact": _artifact_document(item.candidate_source_artifact),
                    "source_changed": item.source_changed,
                }
                for item in self.source_artifacts
            ],
            "changed_module_ids": list(self.changed_module_ids),
            "claimed_declaration_ids": list(self.claimed_declaration_ids),
            "witness_class": self.witness_class,
            "promotion_eligible": self.promotion_eligible,
        }

    def canonical_bytes(self) -> bytes:
        return _canonical_bytes(self._content_document())

    @property
    def content_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


@dataclass(frozen=True, slots=True)
class FrozenChangedSourceWitnessV1:
    """Witness plus its allowlisted review case for status-time revalidation."""

    witness: ChangedSourceWitnessV1
    artifact: ArtifactRef
    reviewed_successor: RealLeanChangeCaseV1
    fixture: RealLeanProjectDagV1

    def __post_init__(self) -> None:
        if (
            self.artifact.digest != self.witness.content_sha256
            or self.artifact.size != len(self.witness.canonical_bytes())
            or self.witness.baseline_fixture_manifest_sha256 != self.fixture.manifest_sha256()
            or self.witness.reviewed_successor_manifest_sha256
            != self.reviewed_successor.manifest_sha256()
        ):
            raise RealLeanWorkerContractError("frozen changed-source witness binding is invalid")


@dataclass(frozen=True, slots=True)
class LeanWorkerEnvironmentV1:
    """Exact non-secret environment identity required by one immutable worker.

    ``runner_policy_sha256`` names a policy revision.  This contract does not
    carry the policy bytes or prove that a runner enforced them.
    """

    lean_version: str
    mathlib_revision: str
    oci_repo_digest: str
    runner_policy_sha256: str

    def __post_init__(self) -> None:
        if _SAFE_VERSION.fullmatch(self.lean_version) is None:
            raise RealLeanWorkerContractError("Lean version is invalid")
        if _GIT_COMMIT.fullmatch(self.mathlib_revision) is None:
            raise RealLeanWorkerContractError("mathlib revision must be a full Git commit")
        if not _is_oci_repo_digest(self.oci_repo_digest):
            raise RealLeanWorkerContractError("OCI image must be an exact repository RepoDigest")
        if _SHA256.fullmatch(self.runner_policy_sha256) is None:
            raise RealLeanWorkerContractError("runner policy hash is invalid")

    def _content_document(self) -> dict[str, object]:
        return {
            "schema_version": WORKER_ENVIRONMENT_SCHEMA,
            "lean_version": self.lean_version,
            "mathlib_revision": self.mathlib_revision,
            "oci_repo_digest": self.oci_repo_digest,
            "runner_policy_sha256": self.runner_policy_sha256,
        }

    def canonical_bytes(self) -> bytes:
        return _canonical_bytes(self._content_document())

    @property
    def content_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


@dataclass(frozen=True, slots=True)
class LeanWorkerSourceV1:
    """One exact source blob, named by the fixture module and relative path."""

    module: str
    file: str
    artifact: ArtifactRef

    def __post_init__(self) -> None:
        if not self.module or not _safe_relative_file(self.file):
            raise RealLeanWorkerContractError("worker source binding is invalid")


@dataclass(frozen=True, slots=True)
class RealLeanImmutableWorkerInputV1:
    """Content-addressed source and environment input for the V1 execution graph."""

    fixture_manifest_sha256: str
    changed_source_witness_sha256: str
    changed_source_witness_artifact: ArtifactRef
    rebuild_plan_sha256: str
    execution_bundle_sha256: str
    execution_bundle_artifact: ArtifactRef
    environment_sha256: str
    environment_artifact: ArtifactRef
    sources: tuple[LeanWorkerSourceV1, ...]

    def __post_init__(self) -> None:
        if (
            _SHA256.fullmatch(self.fixture_manifest_sha256) is None
            or _SHA256.fullmatch(self.changed_source_witness_sha256) is None
            or self.changed_source_witness_artifact.digest != self.changed_source_witness_sha256
            or _SHA256.fullmatch(self.rebuild_plan_sha256) is None
            or _SHA256.fullmatch(self.execution_bundle_sha256) is None
            or self.execution_bundle_artifact.digest != self.execution_bundle_sha256
            or _SHA256.fullmatch(self.environment_sha256) is None
            or self.environment_artifact.digest != self.environment_sha256
        ):
            raise RealLeanWorkerContractError("worker input identity is invalid")
        modules = tuple(source.module for source in self.sources)
        files = tuple(source.file for source in self.sources)
        if not modules or len(set(modules)) != len(modules) or len(set(files)) != len(files):
            raise RealLeanWorkerContractError("worker source snapshot is incomplete")

    @property
    def sources_by_module(self) -> dict[str, LeanWorkerSourceV1]:
        return {source.module: source for source in self.sources}

    def _content_document(self) -> dict[str, object]:
        return {
            "schema_version": WORKER_INPUT_SCHEMA,
            "fixture_manifest_sha256": self.fixture_manifest_sha256,
            "changed_source_witness_sha256": self.changed_source_witness_sha256,
            "changed_source_witness_artifact": _artifact_document(
                self.changed_source_witness_artifact
            ),
            "rebuild_plan_sha256": self.rebuild_plan_sha256,
            "execution_bundle_sha256": self.execution_bundle_sha256,
            "execution_bundle_artifact": _artifact_document(self.execution_bundle_artifact),
            "environment_sha256": self.environment_sha256,
            "environment_artifact": _artifact_document(self.environment_artifact),
            "sources": [
                {
                    "module": source.module,
                    "file": source.file,
                    "artifact": _artifact_document(source.artifact),
                }
                for source in self.sources
            ],
        }

    def canonical_bytes(self) -> bytes:
        return _canonical_bytes(self._content_document())

    @property
    def content_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    @property
    def job_id(self) -> str:
        """Lease and event identity derived from the complete immutable worker input."""

        return f"t7-synthetic-worker:{self.content_sha256}"


@dataclass(frozen=True, slots=True)
class FrozenRealLeanImmutableWorkerInputV1:
    """Worker input plus every object needed to revalidate its nested bindings."""

    bundle: RealLeanImmutableWorkerInputV1
    artifact: ArtifactRef
    environment: LeanWorkerEnvironmentV1
    changed_source_witness: FrozenChangedSourceWitnessV1
    rebuild_plan: RealLeanRebuildBundleV1
    execution: FrozenRealLeanRebuildExecutionBundleV1
    fixture: RealLeanProjectDagV1

    def __post_init__(self) -> None:
        if (
            self.artifact.digest != self.bundle.content_sha256
            or self.artifact.size != len(self.bundle.canonical_bytes())
            or self.bundle.environment_sha256 != self.environment.content_sha256
            or self.bundle.changed_source_witness_sha256
            != self.changed_source_witness.witness.content_sha256
            or self.bundle.changed_source_witness_artifact != self.changed_source_witness.artifact
            or self.changed_source_witness.fixture.manifest_sha256()
            != self.fixture.manifest_sha256()
            or self.bundle.rebuild_plan_sha256 != self.rebuild_plan.content_sha256
            or self.bundle.fixture_manifest_sha256 != self.rebuild_plan.fixture_manifest_sha256
            or self.bundle.fixture_manifest_sha256 != self.execution.bundle.fixture_manifest_sha256
            or self.bundle.fixture_manifest_sha256 != self.fixture.manifest_sha256()
            or self.execution.bundle.rebuild_plan_sha256 != self.rebuild_plan.content_sha256
            or self.bundle.execution_bundle_sha256 != self.execution.bundle.content_sha256
            or self.bundle.execution_bundle_artifact != self.execution.artifact
        ):
            raise RealLeanWorkerContractError("frozen worker input binding is invalid")


@dataclass(frozen=True, slots=True)
class LeanDependencyArtifactV1:
    """The exact result artifact consumed from one completed dependency node."""

    node_id: str
    result_artifact: ArtifactRef

    def __post_init__(self) -> None:
        if not self.node_id:
            raise RealLeanWorkerContractError("dependency artifact node is invalid")


@dataclass(frozen=True, slots=True)
class LeanNodeVerificationReceiptV1:
    """Typed evidence for one declaration node in a planned module rebuild.

    This receipt does not claim that a module was compiled once per declaration.
    Reuse is not a verification attempt and therefore has no receipt; the
    adapter records it directly from the immutable baseline reference.
    """

    worker_input_sha256: str
    worker_input_artifact: ArtifactRef
    execution_bundle_sha256: str
    execution_bundle_artifact: ArtifactRef
    environment_sha256: str
    environment_artifact: ArtifactRef
    node_id: str
    module: str
    action: str
    source_artifact: ArtifactRef
    dependency_artifacts: tuple[LeanDependencyArtifactV1, ...]
    lease_job_id: str
    lease_holder_id: str
    fencing_token: int
    outcome: NodeVerificationOutcome
    exit_code: int
    stdout_artifact: ArtifactRef
    stderr_artifact: ArtifactRef
    result_artifact: ArtifactRef
    evidence_class: str = SYNTHETIC_FAKE_NODE_EVIDENCE_CLASS
    promotion_eligible: bool = False

    def __post_init__(self) -> None:
        if (
            _SHA256.fullmatch(self.worker_input_sha256) is None
            or self.worker_input_artifact.digest != self.worker_input_sha256
            or _SHA256.fullmatch(self.execution_bundle_sha256) is None
            or self.execution_bundle_artifact.digest != self.execution_bundle_sha256
            or _SHA256.fullmatch(self.environment_sha256) is None
            or self.environment_artifact.digest != self.environment_sha256
            or not self.node_id
            or not self.module
            or self.action != _REBUILD
            or not self.lease_job_id
            or not self.lease_holder_id
            or type(self.fencing_token) is not int
            or self.fencing_token <= 0
            or type(self.exit_code) is not int
            or not 0 <= self.exit_code <= 255
            or self.evidence_class != SYNTHETIC_FAKE_NODE_EVIDENCE_CLASS
            or type(self.promotion_eligible) is not bool
            or self.promotion_eligible
        ):
            raise RealLeanWorkerContractError("Lean node receipt identity is invalid")
        dependency_ids = tuple(item.node_id for item in self.dependency_artifacts)
        if len(set(dependency_ids)) != len(dependency_ids):
            raise RealLeanWorkerContractError("Lean node receipt dependencies are invalid")
        if self.outcome == _VERIFIED and self.exit_code != 0:
            raise RealLeanWorkerContractError("VERIFIED receipt must have exit code zero")
        if self.outcome == _FAILED and self.exit_code == 0:
            raise RealLeanWorkerContractError("FAILED receipt must have a nonzero exit code")
        if self.outcome not in {_VERIFIED, _FAILED}:
            raise RealLeanWorkerContractError("Lean node receipt outcome is invalid")

    def _content_document(self) -> dict[str, object]:
        return {
            "schema_version": LEAN_NODE_VERIFICATION_RECEIPT_SCHEMA,
            "worker_input_sha256": self.worker_input_sha256,
            "worker_input_artifact": _artifact_document(self.worker_input_artifact),
            "execution_bundle_sha256": self.execution_bundle_sha256,
            "execution_bundle_artifact": _artifact_document(self.execution_bundle_artifact),
            "environment_sha256": self.environment_sha256,
            "environment_artifact": _artifact_document(self.environment_artifact),
            "node_id": self.node_id,
            "module": self.module,
            "action": self.action,
            "source_artifact": _artifact_document(self.source_artifact),
            "dependency_artifacts": [
                {
                    "node_id": dependency.node_id,
                    "result_artifact": _artifact_document(dependency.result_artifact),
                }
                for dependency in self.dependency_artifacts
            ],
            "lease_job_id": self.lease_job_id,
            "lease_holder_id": self.lease_holder_id,
            "fencing_token": self.fencing_token,
            "outcome": self.outcome,
            "exit_code": self.exit_code,
            "stdout_artifact": _artifact_document(self.stdout_artifact),
            "stderr_artifact": _artifact_document(self.stderr_artifact),
            "result_artifact": _artifact_document(self.result_artifact),
            "evidence_class": self.evidence_class,
            "promotion_eligible": self.promotion_eligible,
        }

    def canonical_bytes(self) -> bytes:
        return _canonical_bytes(self._content_document())

    @property
    def content_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


@dataclass(frozen=True, slots=True)
class FrozenLeanNodeVerificationReceiptV1:
    """A typed receipt paired with the exact bytes committed as node evidence."""

    receipt: LeanNodeVerificationReceiptV1
    artifact: ArtifactRef

    def __post_init__(self) -> None:
        if self.artifact.digest != self.receipt.content_sha256 or self.artifact.size != len(
            self.receipt.canonical_bytes()
        ):
            raise RealLeanWorkerContractError("frozen node receipt binding is invalid")


@dataclass(frozen=True, slots=True)
class TypedWorkerExecutionStatusV1:
    """Mechanically non-promotable status derived from synthetic node evidence."""

    state: TypedWorkerState
    evidence_class: str = SYNTHETIC_FAKE_NODE_EVIDENCE_CLASS
    promotion_eligible: bool = False
    schema_version: str = TYPED_WORKER_STATUS_SCHEMA

    def __post_init__(self) -> None:
        if (
            self.state
            not in {
                "SYNTHETIC_PENDING",
                "SYNTHETIC_FAILED",
                "SYNTHETIC_COMPLETE",
            }
            or self.evidence_class != SYNTHETIC_FAKE_NODE_EVIDENCE_CLASS
            or type(self.promotion_eligible) is not bool
            or self.promotion_eligible
            or self.schema_version != TYPED_WORKER_STATUS_SCHEMA
        ):
            raise RealLeanWorkerContractError("typed worker status is invalid")


@dataclass(frozen=True, slots=True)
class SyntheticNodeCommitResultV2:
    """Typed acknowledgement for one durable, non-promotable synthetic event."""

    event_id: str
    node_id: str
    planned_action: str
    typed_outcome: SyntheticNodeOutcome
    receipt_artifact: ArtifactRef | None
    node_result_artifact: ArtifactRef
    evidence_class: str = SYNTHETIC_FAKE_NODE_EVIDENCE_CLASS
    promotion_eligible: bool = False
    schema_version: str = SYNTHETIC_NODE_COMMIT_SCHEMA

    def __post_init__(self) -> None:
        receipt_required = self.typed_outcome in {
            _SYNTHETIC_COMPLETE,
            _SYNTHETIC_FAILED,
        }
        if (
            not self.event_id
            or not self.node_id
            or self.planned_action not in {_REBUILD, _REUSE}
            or self.typed_outcome
            not in {
                _SYNTHETIC_COMPLETE,
                _SYNTHETIC_FAILED,
                _SYNTHETIC_REUSED,
            }
            or receipt_required != (self.receipt_artifact is not None)
            or (self.planned_action == _REUSE) != (self.typed_outcome == _SYNTHETIC_REUSED)
            or self.evidence_class != SYNTHETIC_FAKE_NODE_EVIDENCE_CLASS
            or type(self.promotion_eligible) is not bool
            or self.promotion_eligible
            or self.schema_version != SYNTHETIC_NODE_COMMIT_SCHEMA
        ):
            raise RealLeanWorkerContractError("synthetic node commit result is invalid")


@dataclass(frozen=True, slots=True)
class _ValidatedSyntheticNodeEventV2:
    """Internal parsed event plus the artifact consumed by downstream nodes."""

    commit: SyntheticNodeCommitResultV2
    frozen_receipt: FrozenLeanNodeVerificationReceiptV1 | None


def freeze_changed_source_witness(
    fixture: RealLeanProjectDagV1,
    reviewed_successor: RealLeanChangeCaseV1,
    artifacts: ArtifactStore,
    *,
    source_snapshot_root: str | Path,
) -> FrozenChangedSourceWitnessV1:
    """Seal the allowlisted reviewed successor and both source endpoints.

    ``source_snapshot_root`` must reproduce the fixture-relative source paths.
    Candidate bytes must equal the exact replacements in the reviewed fixture
    manifest; free declaration claims are not accepted.
    """

    if (
        reviewed_successor.manifest_sha256() != REVIEWED_FIXTURE_MANIFEST_SHA256
        or reviewed_successor.baseline.manifest_sha256() != fixture.manifest_sha256()
    ):
        raise RealLeanWorkerContractError(
            "reviewed successor is not the allowlisted fixture manifest"
        )

    manifest_path = reviewed_successor.manifest_path
    if _path_is_link(manifest_path) or not manifest_path.is_file():
        raise RealLeanWorkerContractError("reviewed successor manifest is unavailable or linked")
    try:
        reviewed_manifest_bytes = manifest_path.read_bytes()
    except OSError as error:
        raise RealLeanWorkerContractError(
            "reviewed successor manifest could not be read"
        ) from error
    reviewed_manifest_artifact = artifacts.put_bytes(reviewed_manifest_bytes)
    if reviewed_manifest_artifact.digest != reviewed_successor.manifest_sha256():
        raise RealLeanWorkerContractError("reviewed successor manifest changed after validation")

    source_root = Path(source_snapshot_root)
    if _path_is_link(source_root) or not source_root.is_dir():
        raise RealLeanWorkerContractError("worker source snapshot root is unavailable or linked")
    resolved_root = source_root.resolve()
    source_artifacts: list[ChangedSourceArtifactPairV1] = []
    for module in fixture.module_topological_order():
        baseline_bytes = fixture.source_path(module).read_bytes()
        expected_candidate_bytes = reviewed_successor.apply_to_module(module.module, successor=True)
        source_path = _source_snapshot_path(resolved_root, module.file)
        try:
            candidate_bytes = source_path.read_bytes()
        except OSError as error:
            raise RealLeanWorkerContractError("worker source snapshot is incomplete") from error
        if candidate_bytes != expected_candidate_bytes:
            raise RealLeanWorkerContractError(
                "candidate source is not the exact reviewed successor"
            )
        source_artifacts.append(
            ChangedSourceArtifactPairV1(
                module=module.module,
                file=module.file,
                baseline_source_artifact=artifacts.put_bytes(baseline_bytes),
                candidate_source_artifact=artifacts.put_bytes(candidate_bytes),
            )
        )
    changed_modules = tuple(item.module for item in source_artifacts if item.source_changed)
    witness = ChangedSourceWitnessV1(
        baseline_fixture_manifest_sha256=fixture.manifest_sha256(),
        reviewed_successor_manifest_sha256=reviewed_successor.manifest_sha256(),
        reviewed_successor_manifest_artifact=reviewed_manifest_artifact,
        source_artifacts=tuple(source_artifacts),
        changed_module_ids=changed_modules,
        claimed_declaration_ids=reviewed_successor.changed_declaration_ids,
    )
    artifact = artifacts.put_bytes(witness.canonical_bytes())
    frozen = FrozenChangedSourceWitnessV1(
        witness=witness,
        artifact=artifact,
        reviewed_successor=reviewed_successor,
        fixture=fixture,
    )
    _verify_changed_source_witness(frozen, artifacts)
    return frozen


def plan_real_lean_rebuild_from_witness(
    fixture: RealLeanProjectDagV1,
    changed_source_witness: FrozenChangedSourceWitnessV1,
    artifacts: ArtifactStore,
) -> RealLeanRebuildBundleV1:
    """Derive the typed rebuild plan only from the revalidated witness."""

    _verify_changed_source_witness(changed_source_witness, artifacts)
    source_snapshot_sha256 = {
        item.module: item.candidate_source_artifact.digest
        for item in changed_source_witness.witness.source_artifacts
    }
    return plan_real_lean_rebuild(
        fixture,
        source_snapshot_sha256,
        changed_declaration_ids=(changed_source_witness.witness.claimed_declaration_ids),
    )


def freeze_real_lean_immutable_worker_input(
    fixture: RealLeanProjectDagV1,
    changed_source_witness: FrozenChangedSourceWitnessV1,
    execution: FrozenRealLeanRebuildExecutionBundleV1,
    environment: LeanWorkerEnvironmentV1,
    artifacts: ArtifactStore,
) -> FrozenRealLeanImmutableWorkerInputV1:
    """Seal worker input after witness-driven plan and execution recomputation."""

    _verify_changed_source_witness(changed_source_witness, artifacts)
    rebuild_plan = plan_real_lean_rebuild_from_witness(fixture, changed_source_witness, artifacts)
    _verify_execution(execution, artifacts)
    _verify_recomputed_execution(fixture, rebuild_plan, execution, artifacts)
    if (
        execution.bundle.fixture_manifest_sha256 != fixture.manifest_sha256()
        or execution.bundle.rebuild_plan_sha256 != rebuild_plan.content_sha256
        or execution.bundle.rebuild_plan_artifact.digest != rebuild_plan.content_sha256
    ):
        raise RealLeanWorkerContractError("worker plan and execution binding is invalid")
    artifacts.verify(execution.bundle.rebuild_plan_artifact)
    if (
        artifacts.get_bytes(execution.bundle.rebuild_plan_artifact)
        != rebuild_plan.canonical_bytes()
    ):
        raise RealLeanWorkerContractError("worker rebuild plan artifact content changed")

    source_pairs = changed_source_witness.witness.source_artifacts
    sources = tuple(
        LeanWorkerSourceV1(
            module=item.module,
            file=item.file,
            artifact=item.candidate_source_artifact,
        )
        for item in source_pairs
    )

    environment_artifact = artifacts.put_bytes(environment.canonical_bytes())
    bundle = RealLeanImmutableWorkerInputV1(
        fixture_manifest_sha256=fixture.manifest_sha256(),
        changed_source_witness_sha256=changed_source_witness.witness.content_sha256,
        changed_source_witness_artifact=changed_source_witness.artifact,
        rebuild_plan_sha256=rebuild_plan.content_sha256,
        execution_bundle_sha256=execution.bundle.content_sha256,
        execution_bundle_artifact=execution.artifact,
        environment_sha256=environment.content_sha256,
        environment_artifact=environment_artifact,
        sources=tuple(sources),
    )
    artifact = artifacts.put_bytes(bundle.canonical_bytes())
    return FrozenRealLeanImmutableWorkerInputV1(
        bundle=bundle,
        artifact=artifact,
        environment=environment,
        changed_source_witness=changed_source_witness,
        rebuild_plan=rebuild_plan,
        execution=execution,
        fixture=fixture,
    )


def freeze_lean_node_verification_receipt(
    worker: FrozenRealLeanImmutableWorkerInputV1,
    artifacts: ArtifactStore,
    *,
    lease: Lease,
    node_id: str,
    outcome: NodeVerificationOutcome,
    exit_code: int,
    dependency_artifacts: Mapping[str, ArtifactRef],
    stdout_artifact: ArtifactRef,
    stderr_artifact: ArtifactRef,
    result_artifact: ArtifactRef,
) -> FrozenLeanNodeVerificationReceiptV1:
    """Seal one rebuild attempt; durable dependency truth is checked on commit."""

    _verify_worker(worker, artifacts)
    node = worker.execution.bundle.nodes_by_id.get(node_id)
    if node is None or node.action != _REBUILD:
        raise RealLeanWorkerContractError("node receipt must target a planned rebuild node")
    if lease.job_id != worker.bundle.job_id:
        raise RealLeanWorkerContractError("node receipt lease belongs to another worker")
    if set(dependency_artifacts) != set(node.depends_on):
        raise RealLeanWorkerContractError(
            "node receipt must bind exactly every dependency artifact"
        )
    for reference in (
        *dependency_artifacts.values(),
        stdout_artifact,
        stderr_artifact,
        result_artifact,
    ):
        artifacts.verify(reference)
    receipt = LeanNodeVerificationReceiptV1(
        worker_input_sha256=worker.bundle.content_sha256,
        worker_input_artifact=worker.artifact,
        execution_bundle_sha256=worker.execution.bundle.content_sha256,
        execution_bundle_artifact=worker.execution.artifact,
        environment_sha256=worker.environment.content_sha256,
        environment_artifact=worker.bundle.environment_artifact,
        node_id=node.node_id,
        module=node.module,
        action=node.action,
        source_artifact=worker.bundle.sources_by_module[node.module].artifact,
        dependency_artifacts=tuple(
            LeanDependencyArtifactV1(
                node_id=dependency_id,
                result_artifact=dependency_artifacts[dependency_id],
            )
            for dependency_id in node.depends_on
        ),
        lease_job_id=lease.job_id,
        lease_holder_id=lease.holder_id,
        fencing_token=lease.fencing_token,
        outcome=outcome,
        exit_code=exit_code,
        stdout_artifact=stdout_artifact,
        stderr_artifact=stderr_artifact,
        result_artifact=result_artifact,
    )
    artifact = artifacts.put_bytes(receipt.canonical_bytes())
    return FrozenLeanNodeVerificationReceiptV1(receipt=receipt, artifact=artifact)


class RealLeanTypedWorkerReceiptStore:
    """Receipt-only adapter over :class:`RealLeanRebuildExecutionStore`.

    The wrapped V1 store remains unchanged.  New callers submit rebuilds only
    through a frozen typed receipt and submit reuse without any artifact
    parameter; the exact frozen baseline is selected by this adapter.
    """

    def __init__(self, store: RealLeanRebuildExecutionStore) -> None:
        self._store = store
        self.artifacts = store.artifacts

    def claim(
        self,
        worker: FrozenRealLeanImmutableWorkerInputV1,
        *,
        worker_id: str,
        ttl_seconds: float,
    ) -> Lease:
        _verify_worker(worker, self.artifacts)
        return self._store.leases.claim(
            worker.bundle.job_id,
            worker_id,
            ttl_seconds=ttl_seconds,
        )

    def commit_reuse(
        self,
        worker: FrozenRealLeanImmutableWorkerInputV1,
        *,
        lease: Lease,
        node_id: str,
        idempotency_key: str,
    ) -> SyntheticNodeCommitResultV2:
        """Record reuse using only the baseline reference frozen in worker input."""

        _verify_worker(worker, self.artifacts)
        node = worker.execution.bundle.nodes_by_id.get(node_id)
        if node is None or node.action != _REUSE or node.baseline_artifact is None:
            raise RealLeanWorkerContractError("reuse must target a planned baseline node")
        self._completed_dependency_results(worker, node.depends_on)
        return self._commit_synthetic_event(
            worker,
            lease=lease,
            node=node,
            typed_outcome=_SYNTHETIC_REUSED,
            frozen_receipt=None,
            node_result_artifact=node.baseline_artifact,
            idempotency_key=idempotency_key,
        )

    def commit_receipt(
        self,
        worker: FrozenRealLeanImmutableWorkerInputV1,
        *,
        lease: Lease,
        frozen_receipt: FrozenLeanNodeVerificationReceiptV1,
        idempotency_key: str,
    ) -> SyntheticNodeCommitResultV2:
        """Validate and commit typed rebuild evidence to the synthetic V2 stream."""

        _verify_worker(worker, self.artifacts)
        _verify_frozen_receipt(frozen_receipt, self.artifacts)
        receipt = frozen_receipt.receipt
        node = self._verify_receipt_identity(worker, receipt)
        if (
            receipt.lease_job_id != lease.job_id
            or receipt.lease_holder_id != lease.holder_id
            or receipt.fencing_token != lease.fencing_token
        ):
            raise RealLeanWorkerContractError("node receipt lease identity changed")
        expected_dependencies = self._completed_dependency_results(worker, node.depends_on)
        if receipt.dependency_artifacts != tuple(
            LeanDependencyArtifactV1(node_id=node_id, result_artifact=artifact)
            for node_id, artifact in expected_dependencies
        ):
            raise RealLeanWorkerContractError(
                "node receipt dependency artifacts drifted from durable results"
            )
        typed_outcome: SyntheticNodeOutcome = (
            _SYNTHETIC_COMPLETE if receipt.outcome == _VERIFIED else _SYNTHETIC_FAILED
        )
        return self._commit_synthetic_event(
            worker,
            lease=lease,
            node=node,
            typed_outcome=typed_outcome,
            frozen_receipt=frozen_receipt,
            node_result_artifact=receipt.result_artifact,
            idempotency_key=idempotency_key,
        )

    def execution_status(
        self, worker: FrozenRealLeanImmutableWorkerInputV1
    ) -> TypedWorkerExecutionStatusV1:
        """Return a synthetic, mechanically non-promotable typed status."""

        _verify_worker(worker, self.artifacts)
        completed_results: dict[str, ArtifactRef] = {}
        observed_outcomes: dict[str, SyntheticNodeOutcome] = {}
        for node in worker.execution.bundle.nodes:
            events = self._node_events(worker, node.node_id)
            if not events:
                continue
            if len(events) != 1:
                raise RealLeanWorkerContractError("worker node stream is not terminal")
            validated = self._validate_synthetic_event(worker, node, events[0])
            observed_outcomes[node.node_id] = validated.commit.typed_outcome
            expected_dependencies = tuple(
                LeanDependencyArtifactV1(
                    node_id=dependency_id,
                    result_artifact=completed_results[dependency_id],
                )
                for dependency_id in node.depends_on
                if dependency_id in completed_results
            )
            if len(expected_dependencies) != len(node.depends_on):
                raise RealLeanWorkerContractError(
                    "stored receipt dependency artifacts are inconsistent"
                )
            frozen_receipt = validated.frozen_receipt
            if frozen_receipt is not None:
                receipt = frozen_receipt.receipt
                if receipt.dependency_artifacts != expected_dependencies:
                    raise RealLeanWorkerContractError(
                        "stored receipt dependency artifacts are inconsistent"
                    )
            if validated.commit.typed_outcome in {
                _SYNTHETIC_COMPLETE,
                _SYNTHETIC_REUSED,
            }:
                completed_results[node.node_id] = validated.commit.node_result_artifact
        if _SYNTHETIC_FAILED in observed_outcomes.values():
            return TypedWorkerExecutionStatusV1(state="SYNTHETIC_FAILED")
        if len(observed_outcomes) != len(worker.execution.bundle.nodes):
            return TypedWorkerExecutionStatusV1(state="SYNTHETIC_PENDING")
        expected_outcomes = {
            node.node_id: (_SYNTHETIC_COMPLETE if node.action == _REBUILD else _SYNTHETIC_REUSED)
            for node in worker.execution.bundle.nodes
        }
        if observed_outcomes != expected_outcomes:
            raise RealLeanWorkerContractError("synthetic execution outcomes are inconsistent")
        return TypedWorkerExecutionStatusV1(state="SYNTHETIC_COMPLETE")

    def _completed_dependency_results(
        self,
        worker: FrozenRealLeanImmutableWorkerInputV1,
        dependency_ids: tuple[str, ...],
    ) -> tuple[tuple[str, ArtifactRef], ...]:
        results: list[tuple[str, ArtifactRef]] = []
        nodes = worker.execution.bundle.nodes_by_id
        for dependency_id in dependency_ids:
            dependency = nodes[dependency_id]
            events = self._node_events(worker, dependency_id)
            if len(events) != 1:
                raise RealLeanWorkerContractError("node receipt dependency is not complete")
            validated = self._validate_synthetic_event(worker, dependency, events[0])
            if validated.commit.typed_outcome not in {
                _SYNTHETIC_COMPLETE,
                _SYNTHETIC_REUSED,
            }:
                raise RealLeanWorkerContractError("synthetic dependency is not complete")
            results.append((dependency_id, validated.commit.node_result_artifact))
        return tuple(results)

    def _commit_synthetic_event(
        self,
        worker: FrozenRealLeanImmutableWorkerInputV1,
        *,
        lease: Lease,
        node: RebuildExecutionNodeV1,
        typed_outcome: SyntheticNodeOutcome,
        frozen_receipt: FrozenLeanNodeVerificationReceiptV1 | None,
        node_result_artifact: ArtifactRef,
        idempotency_key: str,
    ) -> SyntheticNodeCommitResultV2:
        self.artifacts.verify(node_result_artifact)
        if frozen_receipt is not None:
            _verify_frozen_receipt(frozen_receipt, self.artifacts)
        payload = self._synthetic_event_payload(
            worker,
            lease=lease,
            node=node,
            typed_outcome=typed_outcome,
            frozen_receipt=frozen_receipt,
            node_result_artifact=node_result_artifact,
        )
        event_type = self._synthetic_event_type(typed_outcome)
        idempotency = Idempotency(
            scope="t7_synthetic_node_commit_v2",
            key=idempotency_key,
            request_hash=request_hash(
                {
                    "entity_type": SYNTHETIC_NODE_EVENT_ENTITY_TYPE,
                    "entity_id": self._synthetic_entity_id(worker, node.node_id),
                    "event_type": event_type,
                    "payload": payload,
                }
            ),
        )
        stored = self._store.events.append_fenced(
            SYNTHETIC_NODE_EVENT_ENTITY_TYPE,
            self._synthetic_entity_id(worker, node.node_id),
            task_id=worker.bundle.job_id,
            lease=lease,
            expected_sequence=0,
            events=(NewEvent(event_type, payload=payload),),
            idempotency=idempotency,
        )[0]
        return self._validate_synthetic_event(worker, node, stored).commit

    def _synthetic_event_payload(
        self,
        worker: FrozenRealLeanImmutableWorkerInputV1,
        *,
        lease: Lease,
        node: RebuildExecutionNodeV1,
        typed_outcome: SyntheticNodeOutcome,
        frozen_receipt: FrozenLeanNodeVerificationReceiptV1 | None,
        node_result_artifact: ArtifactRef,
    ) -> JsonObject:
        receipt_artifact = None if frozen_receipt is None else frozen_receipt.artifact
        return {
            "schema_version": SYNTHETIC_NODE_EVENT_SCHEMA,
            "bundle_id": worker.bundle.job_id,
            "fixture_manifest_sha256": worker.bundle.fixture_manifest_sha256,
            "changed_source_witness_sha256": worker.bundle.changed_source_witness_sha256,
            "changed_source_witness_artifact": _artifact_document(
                worker.bundle.changed_source_witness_artifact
            ),
            "rebuild_plan_sha256": worker.bundle.rebuild_plan_sha256,
            "execution_bundle_sha256": worker.bundle.execution_bundle_sha256,
            "execution_bundle_artifact": _artifact_document(
                worker.bundle.execution_bundle_artifact
            ),
            "worker_input_sha256": worker.bundle.content_sha256,
            "worker_input_artifact": _artifact_document(worker.artifact),
            "environment_sha256": worker.bundle.environment_sha256,
            "environment_artifact": _artifact_document(worker.bundle.environment_artifact),
            "node_id": node.node_id,
            "module": node.module,
            "planned_action": node.action,
            "typed_outcome": typed_outcome,
            "receipt_sha256": None if receipt_artifact is None else receipt_artifact.digest,
            "receipt_artifact": (
                None if receipt_artifact is None else _artifact_document(receipt_artifact)
            ),
            "node_result_artifact": _artifact_document(node_result_artifact),
            "evidence_class": SYNTHETIC_FAKE_NODE_EVIDENCE_CLASS,
            "promotion_eligible": False,
            "lease_holder_id": lease.holder_id,
            "fencing_token": lease.fencing_token,
        }

    def _validate_synthetic_event(
        self,
        worker: FrozenRealLeanImmutableWorkerInputV1,
        node: RebuildExecutionNodeV1,
        event: StoredEvent,
    ) -> _ValidatedSyntheticNodeEventV2:
        payload = event.payload
        expected_entity_id = self._synthetic_entity_id(worker, node.node_id)
        if (
            event.entity_type != SYNTHETIC_NODE_EVENT_ENTITY_TYPE
            or event.entity_id != expected_entity_id
            or event.entity_sequence != 1
            or event.metadata
            or set(payload) != _SYNTHETIC_EVENT_FIELDS
        ):
            raise RealLeanWorkerContractError("synthetic node event shape is invalid")
        typed_outcome_value = payload.get("typed_outcome")
        if not isinstance(typed_outcome_value, str) or typed_outcome_value not in {
            _SYNTHETIC_COMPLETE,
            _SYNTHETIC_FAILED,
            _SYNTHETIC_REUSED,
        }:
            raise RealLeanWorkerContractError("synthetic node event outcome is invalid")
        typed_outcome = cast(SyntheticNodeOutcome, typed_outcome_value)
        if event.event_type != self._synthetic_event_type(typed_outcome):
            raise RealLeanWorkerContractError("synthetic node event type is inconsistent")
        fencing_token = payload.get("fencing_token")
        lease_holder_id = payload.get("lease_holder_id")
        if (
            not isinstance(lease_holder_id, str)
            or not lease_holder_id
            or type(fencing_token) is not int
            or fencing_token <= 0
        ):
            raise RealLeanWorkerContractError("synthetic node event fencing token is invalid")
        if (
            payload.get("schema_version") != SYNTHETIC_NODE_EVENT_SCHEMA
            or payload.get("bundle_id") != worker.bundle.job_id
            or payload.get("fixture_manifest_sha256") != worker.bundle.fixture_manifest_sha256
            or payload.get("changed_source_witness_sha256")
            != worker.bundle.changed_source_witness_sha256
            or payload.get("rebuild_plan_sha256") != worker.bundle.rebuild_plan_sha256
            or payload.get("execution_bundle_sha256") != worker.bundle.execution_bundle_sha256
            or payload.get("worker_input_sha256") != worker.bundle.content_sha256
            or payload.get("environment_sha256") != worker.bundle.environment_sha256
            or payload.get("node_id") != node.node_id
            or payload.get("module") != node.module
            or payload.get("planned_action") != node.action
            or payload.get("evidence_class") != SYNTHETIC_FAKE_NODE_EVIDENCE_CLASS
            or type(payload.get("promotion_eligible")) is not bool
            or payload.get("promotion_eligible")
        ):
            raise RealLeanWorkerContractError("synthetic node event identity is inconsistent")

        witness_artifact = _artifact_reference(
            payload.get("changed_source_witness_artifact"),
            label="changed-source witness",
        )
        execution_artifact = _artifact_reference(
            payload.get("execution_bundle_artifact"),
            label="execution bundle",
        )
        worker_artifact = _artifact_reference(
            payload.get("worker_input_artifact"),
            label="worker input",
        )
        environment_artifact = _artifact_reference(
            payload.get("environment_artifact"),
            label="worker environment",
        )
        node_result_artifact = _artifact_reference(
            payload.get("node_result_artifact"),
            label="synthetic node result",
        )
        if (
            witness_artifact != worker.bundle.changed_source_witness_artifact
            or execution_artifact != worker.bundle.execution_bundle_artifact
            or worker_artifact != worker.artifact
            or environment_artifact != worker.bundle.environment_artifact
        ):
            raise RealLeanWorkerContractError("synthetic node event artifact binding changed")
        for reference in (
            witness_artifact,
            execution_artifact,
            worker_artifact,
            environment_artifact,
            node_result_artifact,
        ):
            self.artifacts.verify(reference)

        receipt_sha256 = payload.get("receipt_sha256")
        receipt_artifact_value = payload.get("receipt_artifact")
        frozen_receipt: FrozenLeanNodeVerificationReceiptV1 | None = None
        if typed_outcome == _SYNTHETIC_REUSED:
            if (
                node.action != _REUSE
                or node.baseline_artifact is None
                or receipt_sha256 is not None
                or receipt_artifact_value is not None
                or node_result_artifact != node.baseline_artifact
            ):
                raise RealLeanWorkerContractError("synthetic reuse event is inconsistent")
        else:
            if node.action != _REBUILD or not isinstance(receipt_sha256, str):
                raise RealLeanWorkerContractError("synthetic receipt event is inconsistent")
            receipt_artifact = _artifact_reference(
                receipt_artifact_value,
                label="synthetic node receipt",
            )
            if receipt_sha256 != receipt_artifact.digest:
                raise RealLeanWorkerContractError("synthetic receipt hash is inconsistent")
            frozen_receipt = _load_frozen_receipt(receipt_artifact, self.artifacts)
            receipt = frozen_receipt.receipt
            self._verify_receipt_identity(worker, receipt)
            expected_outcome = (
                _SYNTHETIC_COMPLETE if receipt.outcome == _VERIFIED else _SYNTHETIC_FAILED
            )
            if (
                typed_outcome != expected_outcome
                or receipt.node_id != node.node_id
                or receipt.lease_holder_id != lease_holder_id
                or receipt.fencing_token != fencing_token
                or receipt.result_artifact != node_result_artifact
            ):
                raise RealLeanWorkerContractError("synthetic receipt event is inconsistent")

        commit = SyntheticNodeCommitResultV2(
            event_id=event.event_id,
            node_id=node.node_id,
            planned_action=node.action,
            typed_outcome=typed_outcome,
            receipt_artifact=None if frozen_receipt is None else frozen_receipt.artifact,
            node_result_artifact=node_result_artifact,
        )
        return _ValidatedSyntheticNodeEventV2(
            commit=commit,
            frozen_receipt=frozen_receipt,
        )

    @staticmethod
    def _synthetic_event_type(typed_outcome: SyntheticNodeOutcome) -> str:
        return {
            _SYNTHETIC_COMPLETE: "t7_synthetic_node_v2.synthetic_complete",
            _SYNTHETIC_FAILED: "t7_synthetic_node_v2.synthetic_failed",
            _SYNTHETIC_REUSED: "t7_synthetic_node_v2.synthetic_reused",
        }[typed_outcome]

    def _verify_receipt_identity(
        self,
        worker: FrozenRealLeanImmutableWorkerInputV1,
        receipt: LeanNodeVerificationReceiptV1,
    ) -> RebuildExecutionNodeV1:
        node = worker.execution.bundle.nodes_by_id.get(receipt.node_id)
        source = worker.bundle.sources_by_module.get(receipt.module)
        if (
            node is None
            or node.action != _REBUILD
            or node.module != receipt.module
            or receipt.action != node.action
            or source is None
            or receipt.source_artifact != source.artifact
            or receipt.worker_input_sha256 != worker.bundle.content_sha256
            or receipt.worker_input_artifact != worker.artifact
            or receipt.execution_bundle_sha256 != worker.execution.bundle.content_sha256
            or receipt.execution_bundle_artifact != worker.execution.artifact
            or receipt.environment_sha256 != worker.environment.content_sha256
            or receipt.environment_artifact != worker.bundle.environment_artifact
            or receipt.lease_job_id != worker.bundle.job_id
            or receipt.evidence_class != SYNTHETIC_FAKE_NODE_EVIDENCE_CLASS
            or receipt.promotion_eligible
            or tuple(item.node_id for item in receipt.dependency_artifacts) != node.depends_on
        ):
            raise RealLeanWorkerContractError("node receipt does not bind this worker node")
        for reference in (
            receipt.source_artifact,
            receipt.stdout_artifact,
            receipt.stderr_artifact,
            receipt.result_artifact,
            *(item.result_artifact for item in receipt.dependency_artifacts),
        ):
            self.artifacts.verify(reference)
        return node

    def _node_events(
        self, worker: FrozenRealLeanImmutableWorkerInputV1, node_id: str
    ) -> tuple[StoredEvent, ...]:
        return self._store.events.read_stream(
            SYNTHETIC_NODE_EVENT_ENTITY_TYPE,
            self._synthetic_entity_id(worker, node_id),
        )

    @staticmethod
    def _synthetic_entity_id(worker: FrozenRealLeanImmutableWorkerInputV1, node_id: str) -> str:
        return f"{worker.bundle.content_sha256}:{node_id}"


def _verify_execution(
    execution: FrozenRealLeanRebuildExecutionBundleV1, artifacts: ArtifactStore
) -> None:
    for reference in (
        execution.bundle.rebuild_plan_artifact,
        execution.artifact,
        *(
            node.baseline_artifact
            for node in execution.bundle.nodes
            if node.baseline_artifact is not None
        ),
    ):
        artifacts.verify(reference)
    if artifacts.get_bytes(execution.artifact) != execution.bundle.canonical_bytes():
        raise RealLeanWorkerContractError("execution bundle artifact content changed")


def _verify_changed_source_witness(
    frozen: FrozenChangedSourceWitnessV1,
    artifacts: ArtifactStore,
) -> None:
    witness = frozen.witness
    reviewed_successor = frozen.reviewed_successor
    fixture = frozen.fixture
    artifacts.verify(frozen.artifact)
    artifacts.verify(witness.reviewed_successor_manifest_artifact)
    if artifacts.get_bytes(frozen.artifact) != witness.canonical_bytes():
        raise RealLeanWorkerContractError("changed-source witness artifact content changed")
    reviewed_manifest_bytes = artifacts.get_bytes(witness.reviewed_successor_manifest_artifact)
    reviewed_document = _load_unique_json_object(
        reviewed_manifest_bytes,
        label="reviewed successor manifest",
    )
    if (
        witness.witness_class != REVIEWED_FIXTURE_WITNESS_CLASS
        or witness.promotion_eligible
        or witness.reviewed_successor_manifest_sha256 != REVIEWED_FIXTURE_MANIFEST_SHA256
        or reviewed_successor.manifest_sha256() != REVIEWED_FIXTURE_MANIFEST_SHA256
        or reviewed_document != _reviewed_successor_document(reviewed_successor)
        or witness.baseline_fixture_manifest_sha256 != fixture.manifest_sha256()
        or reviewed_successor.baseline.manifest_sha256() != fixture.manifest_sha256()
        or witness.claimed_declaration_ids != reviewed_successor.changed_declaration_ids
    ):
        raise RealLeanWorkerContractError("changed-source witness review binding is inconsistent")

    ordered_modules = fixture.module_topological_order()
    if tuple(item.module for item in witness.source_artifacts) != tuple(
        module.module for module in ordered_modules
    ) or tuple(item.file for item in witness.source_artifacts) != tuple(
        module.file for module in ordered_modules
    ):
        raise RealLeanWorkerContractError("changed-source witness module snapshot is incomplete")
    observed_changed_modules: list[str] = []
    for module, pair in zip(ordered_modules, witness.source_artifacts, strict=True):
        for reference in (
            pair.baseline_source_artifact,
            pair.candidate_source_artifact,
        ):
            artifacts.verify(reference)
        baseline_bytes = fixture.source_path(module).read_bytes()
        candidate_bytes = reviewed_successor.apply_to_module(module.module, successor=True)
        if (
            artifacts.get_bytes(pair.baseline_source_artifact) != baseline_bytes
            or pair.baseline_source_artifact.digest != module.source_sha256
            or artifacts.get_bytes(pair.candidate_source_artifact) != candidate_bytes
        ):
            raise RealLeanWorkerContractError(
                "changed-source witness source artifact is inconsistent"
            )
        if pair.source_changed:
            observed_changed_modules.append(pair.module)
    expected_changed_modules = tuple(
        module.module
        for module in ordered_modules
        if module.module in reviewed_successor.edits_by_module
    )
    if (
        witness.changed_module_ids != tuple(observed_changed_modules)
        or witness.changed_module_ids != expected_changed_modules
    ):
        raise RealLeanWorkerContractError("changed-source witness changed modules are inconsistent")


def _verify_worker(worker: FrozenRealLeanImmutableWorkerInputV1, artifacts: ArtifactStore) -> None:
    _verify_changed_source_witness(worker.changed_source_witness, artifacts)
    expected_plan = plan_real_lean_rebuild_from_witness(
        worker.fixture,
        worker.changed_source_witness,
        artifacts,
    )
    if expected_plan.canonical_bytes() != worker.rebuild_plan.canonical_bytes():
        raise RealLeanWorkerContractError("worker rebuild plan differs from changed-source witness")
    _verify_execution(worker.execution, artifacts)
    _verify_recomputed_execution(
        worker.fixture,
        worker.rebuild_plan,
        worker.execution,
        artifacts,
    )
    artifacts.verify(worker.execution.bundle.rebuild_plan_artifact)
    artifacts.verify(worker.bundle.changed_source_witness_artifact)
    artifacts.verify(worker.bundle.environment_artifact)
    artifacts.verify(worker.artifact)
    for source in worker.bundle.sources:
        artifacts.verify(source.artifact)
    if (
        worker.bundle.fixture_manifest_sha256 != worker.rebuild_plan.fixture_manifest_sha256
        or worker.bundle.changed_source_witness_sha256
        != worker.changed_source_witness.witness.content_sha256
        or worker.bundle.changed_source_witness_artifact != worker.changed_source_witness.artifact
        or worker.bundle.fixture_manifest_sha256 != worker.execution.bundle.fixture_manifest_sha256
        or worker.bundle.fixture_manifest_sha256 != worker.fixture.manifest_sha256()
        or worker.bundle.rebuild_plan_sha256 != worker.rebuild_plan.content_sha256
        or worker.execution.bundle.rebuild_plan_sha256 != worker.rebuild_plan.content_sha256
        or worker.bundle.execution_bundle_sha256 != worker.execution.bundle.content_sha256
        or worker.bundle.execution_bundle_artifact != worker.execution.artifact
        or worker.bundle.environment_sha256 != worker.environment.content_sha256
        or worker.bundle.environment_artifact.digest != worker.environment.content_sha256
        or artifacts.get_bytes(worker.execution.bundle.rebuild_plan_artifact)
        != worker.rebuild_plan.canonical_bytes()
        or artifacts.get_bytes(worker.bundle.environment_artifact)
        != worker.environment.canonical_bytes()
        or artifacts.get_bytes(worker.artifact) != worker.bundle.canonical_bytes()
    ):
        raise RealLeanWorkerContractError("worker input artifact content changed")
    plan_bindings = worker.rebuild_plan.source_bindings
    witness_sources = worker.changed_source_witness.witness.source_artifacts
    if (
        tuple(source.module for source in worker.bundle.sources)
        != tuple(binding.module for binding in plan_bindings)
        or tuple(source.file for source in worker.bundle.sources)
        != tuple(binding.file for binding in plan_bindings)
        or tuple(source.artifact.digest for source in worker.bundle.sources)
        != tuple(binding.snapshot_source_sha256 for binding in plan_bindings)
        or tuple(source.artifact for source in worker.bundle.sources)
        != tuple(item.candidate_source_artifact for item in witness_sources)
    ):
        raise RealLeanWorkerContractError("worker source artifacts differ from rebuild plan")


def verify_frozen_real_lean_worker(
    worker: FrozenRealLeanImmutableWorkerInputV1,
    artifacts: ArtifactStore,
) -> None:
    """Public read-only verifier for higher T7 receipt layers."""

    _verify_worker(worker, artifacts)


def _verify_recomputed_execution(
    fixture: RealLeanProjectDagV1,
    rebuild_plan: RealLeanRebuildBundleV1,
    execution: FrozenRealLeanRebuildExecutionBundleV1,
    artifacts: ArtifactStore,
) -> None:
    baselines: dict[str, ArtifactRef] = {}
    for node in execution.bundle.nodes:
        if node.action == _REUSE:
            if node.baseline_artifact is None:
                raise RealLeanWorkerContractError("execution reuse node has no baseline artifact")
            baselines[node.node_id] = node.baseline_artifact
    try:
        expected = freeze_real_lean_rebuild_execution_bundle(
            fixture,
            rebuild_plan,
            artifacts,
            reuse_baseline_artifacts=baselines,
        )
    except RealLeanRebuildExecutionError as error:
        raise RealLeanWorkerContractError(
            "execution bundle cannot be recomputed from fixture and plan"
        ) from error
    if (
        expected.bundle.canonical_bytes() != execution.bundle.canonical_bytes()
        or expected.artifact != execution.artifact
    ):
        raise RealLeanWorkerContractError(
            "execution bundle differs from recomputed fixture and plan"
        )


def _verify_frozen_receipt(
    frozen: FrozenLeanNodeVerificationReceiptV1, artifacts: ArtifactStore
) -> None:
    artifacts.verify(frozen.artifact)
    if artifacts.get_bytes(frozen.artifact) != frozen.receipt.canonical_bytes():
        raise RealLeanWorkerContractError("node receipt artifact content changed")


def _load_frozen_receipt(
    reference: ArtifactRef, artifacts: ArtifactStore
) -> FrozenLeanNodeVerificationReceiptV1:
    artifacts.verify(reference)
    raw_bytes = artifacts.get_bytes(reference)
    try:
        raw = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RealLeanWorkerContractError("node receipt artifact is not valid JSON") from error
    expected_fields = {
        "schema_version",
        "worker_input_sha256",
        "worker_input_artifact",
        "execution_bundle_sha256",
        "execution_bundle_artifact",
        "environment_sha256",
        "environment_artifact",
        "node_id",
        "module",
        "action",
        "source_artifact",
        "dependency_artifacts",
        "lease_job_id",
        "lease_holder_id",
        "fencing_token",
        "outcome",
        "exit_code",
        "stdout_artifact",
        "stderr_artifact",
        "result_artifact",
        "evidence_class",
        "promotion_eligible",
    }
    if not isinstance(raw, dict) or set(raw) != expected_fields:
        raise RealLeanWorkerContractError("node receipt artifact shape is invalid")
    if raw["schema_version"] != LEAN_NODE_VERIFICATION_RECEIPT_SCHEMA:
        raise RealLeanWorkerContractError("node receipt schema is unsupported")
    dependencies_raw = raw["dependency_artifacts"]
    if not isinstance(dependencies_raw, list):
        raise RealLeanWorkerContractError("node receipt dependencies are invalid")
    dependencies: list[LeanDependencyArtifactV1] = []
    for item in dependencies_raw:
        if not isinstance(item, dict) or set(item) != {"node_id", "result_artifact"}:
            raise RealLeanWorkerContractError("node receipt dependency shape is invalid")
        dependencies.append(
            LeanDependencyArtifactV1(
                node_id=_required_string(item["node_id"], "dependency node"),
                result_artifact=_artifact_reference(
                    item["result_artifact"], label="dependency result"
                ),
            )
        )
    outcome_value = _required_string(raw["outcome"], "build outcome")
    if outcome_value not in {_VERIFIED, _FAILED}:
        raise RealLeanWorkerContractError("node receipt outcome is invalid")
    receipt = LeanNodeVerificationReceiptV1(
        worker_input_sha256=_required_string(raw["worker_input_sha256"], "worker input hash"),
        worker_input_artifact=_artifact_reference(
            raw["worker_input_artifact"], label="worker input"
        ),
        execution_bundle_sha256=_required_string(
            raw["execution_bundle_sha256"], "execution bundle hash"
        ),
        execution_bundle_artifact=_artifact_reference(
            raw["execution_bundle_artifact"], label="execution bundle"
        ),
        environment_sha256=_required_string(raw["environment_sha256"], "environment hash"),
        environment_artifact=_artifact_reference(raw["environment_artifact"], label="environment"),
        node_id=_required_string(raw["node_id"], "receipt node"),
        module=_required_string(raw["module"], "receipt module"),
        action=_required_string(raw["action"], "receipt action"),
        source_artifact=_artifact_reference(raw["source_artifact"], label="source"),
        dependency_artifacts=tuple(dependencies),
        lease_job_id=_required_string(raw["lease_job_id"], "lease job"),
        lease_holder_id=_required_string(raw["lease_holder_id"], "lease holder"),
        fencing_token=_required_int(raw["fencing_token"], "fencing token"),
        outcome=cast(NodeVerificationOutcome, outcome_value),
        exit_code=_required_int(raw["exit_code"], "exit code"),
        stdout_artifact=_artifact_reference(raw["stdout_artifact"], label="stdout"),
        stderr_artifact=_artifact_reference(raw["stderr_artifact"], label="stderr"),
        result_artifact=_artifact_reference(raw["result_artifact"], label="result"),
        evidence_class=_required_string(raw["evidence_class"], "evidence class"),
        promotion_eligible=_required_bool(raw["promotion_eligible"], "promotion eligibility"),
    )
    if receipt.canonical_bytes() != raw_bytes:
        raise RealLeanWorkerContractError("node receipt bytes are not canonical")
    return FrozenLeanNodeVerificationReceiptV1(receipt=receipt, artifact=reference)


def _reviewed_successor_document(
    reviewed_successor: RealLeanChangeCaseV1,
) -> dict[str, object]:
    return {
        "schema_version": "autolean.real-lean-project-dag-change-case.v1",
        "name": reviewed_successor.name,
        "baseline_manifest_file": reviewed_successor.baseline_manifest_file,
        "baseline_manifest_sha256": reviewed_successor.baseline_manifest_sha256,
        "changed_declaration_ids": list(reviewed_successor.changed_declaration_ids),
        "expected_declaration_reverse_closure": list(
            reviewed_successor.expected_declaration_reverse_closure
        ),
        "expected_module_reverse_import_closure": list(
            reviewed_successor.expected_module_reverse_import_closure
        ),
        "failure_probe_module": reviewed_successor.failure_probe_module,
        "expected_baseline_canonical_type_sha256": (
            reviewed_successor.expected_baseline_canonical_type_sha256
        ),
        "expected_successor_canonical_type_sha256": (
            reviewed_successor.expected_successor_canonical_type_sha256
        ),
        "edits": [
            {
                "kind": edit.kind,
                "module": edit.module,
                "file": edit.file,
                "baseline_source_sha256": edit.baseline_source_sha256,
                "successor_source_sha256": edit.successor_source_sha256,
                "replacements": [
                    {
                        "old": replacement.old,
                        "new": replacement.new,
                        "expected_occurrences": replacement.expected_occurrences,
                    }
                    for replacement in edit.replacements
                ],
            }
            for edit in reviewed_successor.edits
        ],
    }


def _load_unique_json_object(data: bytes, *, label: str) -> dict[str, object]:
    def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        document: dict[str, object] = {}
        for key, value in pairs:
            if key in document:
                raise RealLeanWorkerContractError(f"{label} contains a duplicate key")
            document[key] = value
        return document

    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=unique_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RealLeanWorkerContractError(f"{label} is not valid JSON") from error
    if not isinstance(value, dict):
        raise RealLeanWorkerContractError(f"{label} must be an object")
    return value


def _canonical_bytes(value: object) -> bytes:
    rendered = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return (rendered + "\n").encode("utf-8")


def _artifact_document(reference: ArtifactRef) -> JsonObject:
    return {
        "algorithm": reference.algorithm,
        "digest": reference.digest,
        "size": reference.size,
    }


def _artifact_reference(value: object, *, label: str) -> ArtifactRef:
    if not isinstance(value, dict) or set(value) != {"algorithm", "digest", "size"}:
        raise RealLeanWorkerContractError(f"{label} artifact reference is invalid")
    algorithm = value.get("algorithm")
    digest = value.get("digest")
    size = value.get("size")
    if not isinstance(algorithm, str) or not isinstance(digest, str) or type(size) is not int:
        raise RealLeanWorkerContractError(f"{label} artifact reference is invalid")
    try:
        return ArtifactRef(algorithm=algorithm, digest=digest, size=size)
    except ValueError as error:
        raise RealLeanWorkerContractError(f"{label} artifact reference is invalid") from error


def _required_string(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise RealLeanWorkerContractError(f"{label} is invalid")
    return value


def _required_int(value: object, label: str) -> int:
    if type(value) is not int:
        raise RealLeanWorkerContractError(f"{label} is invalid")
    return value


def _required_bool(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise RealLeanWorkerContractError(f"{label} is invalid")
    return value


def _safe_relative_file(value: str) -> bool:
    path = PurePosixPath(value)
    return (
        bool(value)
        and not path.is_absolute()
        and ".." not in path.parts
        and "." not in path.parts
        and path.suffix == ".lean"
    )


def _path_is_link(path: Path) -> bool:
    is_junction = getattr(path, "is_junction", None)
    return path.is_symlink() or bool(is_junction is not None and is_junction())


def _source_snapshot_path(root: Path, relative_file: str) -> Path:
    if not _safe_relative_file(relative_file):
        raise RealLeanWorkerContractError("worker source path is invalid")
    current = root
    if _path_is_link(current):
        raise RealLeanWorkerContractError("worker source path is linked")
    for part in PurePosixPath(relative_file).parts:
        current /= part
        if _path_is_link(current):
            raise RealLeanWorkerContractError("worker source path is linked")
    if not current.is_file():
        raise RealLeanWorkerContractError("worker source snapshot is incomplete")
    resolved = current.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise RealLeanWorkerContractError("worker source path escapes snapshot root") from error
    return resolved


def _is_oci_repo_digest(value: str) -> bool:
    if value.count("@sha256:") != 1 or any(character.isspace() for character in value):
        return False
    repository, digest = value.split("@sha256:", maxsplit=1)
    if not repository or repository != repository.lower() or _SHA256.fullmatch(digest) is None:
        return False
    components = repository.split("/")
    if any(not component for component in components):
        return False
    first = components[0]
    if ":" in first:
        if first.count(":") != 1:
            return False
        host, port = first.split(":", maxsplit=1)
        if _OCI_REGISTRY_HOST.fullmatch(host) is None or not port.isdigit():
            return False
        components = components[1:]
        if not components:
            return False
    return all(
        ":" not in component and _OCI_PATH_COMPONENT.fullmatch(component) is not None
        for component in components
    )
