"""One-process Lean module evidence and deterministic declaration fanout for T7.

This layer deliberately does not promote local execution into proof acceptance.  It
binds one immutable module request to one observed process, commits that receipt and
all declaration projections atomically under the same lease fence, and keeps fake and
operator-local evidence mechanically non-promotable.  A future trusted gateway must
use a new verifier path rather than changing these receipt semantics.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from abc import ABC, abstractmethod
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Final, Literal, cast

from autolean_control_plane import (
    ArtifactRef,
    ArtifactStore,
    EventStore,
    Idempotency,
    Lease,
    LeaseStore,
    NewEvent,
    StoredEvent,
    request_hash,
)
from autolean_control_plane.errors import StaleFence
from autolean_control_plane.events import JsonObject

from benchmarks.real_lean_project_dag import RealLeanProjectDagV1
from benchmarks.real_lean_project_dag_worker_contract import (
    FrozenRealLeanImmutableWorkerInputV1,
    verify_frozen_real_lean_worker,
)

MODULE_SOURCE_TREE_SCHEMA: Final[str] = "autolean.lean-module-source-tree.v1"
DECLARATION_QUERY_SCHEMA: Final[str] = "autolean.lean-declaration-query-manifest.v1"
MODULE_IMAGE_BINDING_SCHEMA: Final[str] = "autolean.lean-module-image-binding.v1"
MODULE_BUILD_SPEC_SCHEMA: Final[str] = "autolean.lean-module-build-spec.v1"
MODULE_BUILD_REQUEST_SCHEMA: Final[str] = "autolean.lean-module-build-request.v1"
MODULE_RUNTIME_OBSERVATION_SCHEMA: Final[str] = "autolean.lean-module-runtime-observation.v1"
MODULE_BUILD_RECEIPT_SCHEMA: Final[str] = "autolean.lean-module-build-receipt.v1"
DECLARATION_FANOUT_SCHEMA: Final[str] = "autolean.lean-declaration-fanout.v1"
MODULE_EVENT_SCHEMA: Final[str] = "autolean.t7-module-execution-event.v1"
MODULE_FANOUT_EVENT_SCHEMA: Final[str] = "autolean.t7-module-fanout-event.v1"
MODULE_EVENT_ENTITY_TYPE: Final[str] = "t7_lean_module_execution_v1"
OPERATOR_PREFLIGHT_SCHEMA: Final[str] = "autolean.t7-operator-module-preflight.v1"

SYNTHETIC_MODULE_EVIDENCE_CLASS: Final[str] = "synthetic_fake_module_v1"
OPERATOR_LOCAL_MODULE_EVIDENCE_CLASS: Final[str] = "operator_local_oci_without_trusted_gateway_v1"
NO_TRUSTED_GATEWAY_ATTESTATION: Final[str] = "none"

_BUILD = "build"
_REUSE = "reuse"
_PROCESS_SUCCEEDED = "PROCESS_SUCCEEDED"
_PROCESS_FAILED = "PROCESS_FAILED"
_PROCESS_TIMED_OUT = "PROCESS_TIMED_OUT"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,255}$")
_OCI_COMPONENT = re.compile(r"^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$")
_OCI_HOST = re.compile(r"^[a-z0-9]+(?:[.-][a-z0-9]+)*$")
_EVENT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "bundle_id",
        "request_sha256",
        "request_artifact",
        "spec_sha256",
        "module",
        "action",
        "outcome",
        "receipt_sha256",
        "receipt_artifact",
        "evidence_class",
        "promotion_eligible",
        "kernel_acceptance_eligible",
        "fanout_count",
        "lease_holder_id",
        "fencing_token",
    }
)
_FANOUT_EVENT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "bundle_id",
        "request_sha256",
        "request_artifact",
        "module_receipt_sha256",
        "module_receipt_artifact",
        "node_id",
        "fanout_record_sha256",
        "fanout_record_artifact",
        "evidence_class",
        "promotion_eligible",
        "kernel_acceptance_eligible",
        "lease_holder_id",
        "fencing_token",
    }
)
_OPERATOR_PREFLIGHT_MARKER = object()

type ModuleAction = Literal["build", "reuse"]
type ModuleProcessOutcome = Literal["PROCESS_SUCCEEDED", "PROCESS_FAILED", "PROCESS_TIMED_OUT"]
type ModuleEvidenceClass = Literal[
    "synthetic_fake_module_v1",
    "operator_local_oci_without_trusted_gateway_v1",
]
type ModuleExecutionState = Literal[
    "MODULE_PENDING",
    "MODULE_BUILD_SUCCEEDED_NONPROMOTABLE",
    "MODULE_BUILD_FAILED_NONPROMOTABLE",
    "MODULE_REUSED_NONPROMOTABLE",
]
type CommandRunner = Callable[[Sequence[str], float], subprocess.CompletedProcess[bytes]]


class LeanModuleBuildError(RuntimeError):
    """A module request, process receipt, or declaration fanout is inconsistent."""


@dataclass(frozen=True, slots=True)
class OciPlatformV1:
    os: str
    architecture: str
    variant: str | None = None

    def __post_init__(self) -> None:
        if (
            self.os != "linux"
            or _SAFE_NAME.fullmatch(self.architecture) is None
            or (self.variant is not None and _SAFE_NAME.fullmatch(self.variant) is None)
        ):
            raise LeanModuleBuildError("OCI platform must be an exact Linux platform")

    def document(self) -> JsonObject:
        return {
            "os": self.os,
            "architecture": self.architecture,
            "variant": self.variant,
        }


@dataclass(frozen=True, slots=True)
class LeanModuleSourceEntryV1:
    module: str
    file: str
    imports: tuple[str, ...]
    source_artifact: ArtifactRef

    def __post_init__(self) -> None:
        if (
            not self.module
            or not _safe_relative_file(self.file)
            or len(set(self.imports)) != len(self.imports)
            or any(not item for item in self.imports)
        ):
            raise LeanModuleBuildError("module source-tree entry is invalid")

    def document(self) -> JsonObject:
        return {
            "module": self.module,
            "file": self.file,
            "imports": list(self.imports),
            "source_artifact": _artifact_document(self.source_artifact),
        }


@dataclass(frozen=True, slots=True)
class LeanModuleSourceTreeV1:
    target_module: str
    entries: tuple[LeanModuleSourceEntryV1, ...]

    def __post_init__(self) -> None:
        modules = tuple(item.module for item in self.entries)
        files = tuple(item.file for item in self.entries)
        if (
            not self.target_module
            or not modules
            or modules[-1] != self.target_module
            or len(set(modules)) != len(modules)
            or len(set(files)) != len(files)
        ):
            raise LeanModuleBuildError("module source tree is incomplete")
        seen: set[str] = set()
        for entry in self.entries:
            if set(entry.imports) - seen:
                raise LeanModuleBuildError("module source tree is not in import-topological order")
            seen.add(entry.module)

    @property
    def entries_by_module(self) -> dict[str, LeanModuleSourceEntryV1]:
        return {item.module: item for item in self.entries}

    def canonical_bytes(self) -> bytes:
        return _canonical_bytes(
            {
                "schema_version": MODULE_SOURCE_TREE_SCHEMA,
                "target_module": self.target_module,
                "entries": [item.document() for item in self.entries],
            }
        )

    @property
    def content_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


@dataclass(frozen=True, slots=True)
class FrozenLeanModuleSourceTreeV1:
    tree: LeanModuleSourceTreeV1
    artifact: ArtifactRef

    def __post_init__(self) -> None:
        _check_frozen(self.artifact, self.tree.canonical_bytes(), "module source tree")


@dataclass(frozen=True, slots=True)
class LeanDeclarationQueryRecordV1:
    node_id: str
    declaration: str
    elaborated_type_sha256: str
    axioms: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            not self.node_id
            or not self.declaration
            or _SHA256.fullmatch(self.elaborated_type_sha256) is None
            or tuple(sorted(set(self.axioms))) != self.axioms
            or any(not item for item in self.axioms)
        ):
            raise LeanModuleBuildError("declaration query record is invalid")

    def document(self) -> JsonObject:
        return {
            "node_id": self.node_id,
            "declaration": self.declaration,
            "elaborated_type_sha256": self.elaborated_type_sha256,
            "axioms": list(self.axioms),
        }


@dataclass(frozen=True, slots=True)
class LeanDeclarationQueryManifestV1:
    module: str
    records: tuple[LeanDeclarationQueryRecordV1, ...]

    def __post_init__(self) -> None:
        node_ids = tuple(item.node_id for item in self.records)
        declarations = tuple(item.declaration for item in self.records)
        if (
            not self.module
            or not node_ids
            or len(set(node_ids)) != len(node_ids)
            or len(set(declarations)) != len(declarations)
        ):
            raise LeanModuleBuildError("declaration query manifest is incomplete")

    @property
    def records_by_node(self) -> dict[str, LeanDeclarationQueryRecordV1]:
        return {item.node_id: item for item in self.records}

    def canonical_bytes(self) -> bytes:
        return _canonical_bytes(
            {
                "schema_version": DECLARATION_QUERY_SCHEMA,
                "module": self.module,
                "records": [item.document() for item in self.records],
            }
        )

    @property
    def content_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


@dataclass(frozen=True, slots=True)
class FrozenLeanDeclarationQueryManifestV1:
    manifest: LeanDeclarationQueryManifestV1
    artifact: ArtifactRef

    def __post_init__(self) -> None:
        _check_frozen(
            self.artifact,
            self.manifest.canonical_bytes(),
            "declaration query manifest",
        )


@dataclass(frozen=True, slots=True)
class LeanModuleImageBindingV1:
    oci_repo_digest: str
    oci_config_digest: str
    platform: OciPlatformV1
    runner_policy_image_path: str
    runner_policy_sha256: str
    runner_policy_artifact: ArtifactRef
    image_verification_artifact: ArtifactRef

    def __post_init__(self) -> None:
        if (
            not _is_oci_repo_digest(self.oci_repo_digest)
            or _DIGEST.fullmatch(self.oci_config_digest) is None
            or not _safe_absolute_posix_path(self.runner_policy_image_path)
            or _SHA256.fullmatch(self.runner_policy_sha256) is None
            or self.runner_policy_artifact.digest != self.runner_policy_sha256
        ):
            raise LeanModuleBuildError("module image binding is invalid")

    def canonical_bytes(self) -> bytes:
        return _canonical_bytes(
            {
                "schema_version": MODULE_IMAGE_BINDING_SCHEMA,
                "oci_repo_digest": self.oci_repo_digest,
                "oci_config_digest": self.oci_config_digest,
                "platform": self.platform.document(),
                "runner_policy_image_path": self.runner_policy_image_path,
                "runner_policy_sha256": self.runner_policy_sha256,
                "runner_policy_artifact": _artifact_document(self.runner_policy_artifact),
                "image_verification_artifact": _artifact_document(self.image_verification_artifact),
            }
        )

    @property
    def content_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


@dataclass(frozen=True, slots=True)
class LeanDependencyModuleReceiptV1:
    module: str
    request_sha256: str
    request_artifact: ArtifactRef
    receipt_sha256: str
    receipt_artifact: ArtifactRef
    output_olean_artifact: ArtifactRef

    def __post_init__(self) -> None:
        if (
            not self.module
            or _SHA256.fullmatch(self.request_sha256) is None
            or self.request_artifact.digest != self.request_sha256
            or _SHA256.fullmatch(self.receipt_sha256) is None
            or self.receipt_artifact.digest != self.receipt_sha256
        ):
            raise LeanModuleBuildError("dependency module receipt binding is invalid")

    def document(self) -> JsonObject:
        return {
            "module": self.module,
            "request_sha256": self.request_sha256,
            "request_artifact": _artifact_document(self.request_artifact),
            "receipt_sha256": self.receipt_sha256,
            "receipt_artifact": _artifact_document(self.receipt_artifact),
            "output_olean_artifact": _artifact_document(self.output_olean_artifact),
        }


@dataclass(frozen=True, slots=True)
class LeanModuleBuildSpecV1:
    action: ModuleAction
    module: str
    worker_input_sha256: str
    worker_input_artifact: ArtifactRef
    execution_bundle_sha256: str
    execution_bundle_artifact: ArtifactRef
    changed_source_witness_sha256: str
    changed_source_witness_artifact: ArtifactRef
    rebuild_plan_sha256: str
    rebuild_plan_artifact: ArtifactRef
    source_tree_sha256: str
    source_tree_artifact: ArtifactRef
    dependency_receipts: tuple[LeanDependencyModuleReceiptV1, ...]
    lean_version: str
    mathlib_revision: str
    lake_manifest_sha256: str
    lake_manifest_artifact: ArtifactRef
    image_binding_sha256: str
    image_binding_artifact: ArtifactRef
    expected_query_sha256: str
    expected_query_artifact: ArtifactRef
    command_argv: tuple[str, ...]
    working_directory: str
    output_olean_path: str
    declaration_query_path: str
    baseline_receipt_sha256: str | None
    baseline_receipt_artifact: ArtifactRef | None

    def __post_init__(self) -> None:
        if (
            self.action not in {_BUILD, _REUSE}
            or not self.module
            or _SHA256.fullmatch(self.worker_input_sha256) is None
            or self.worker_input_artifact.digest != self.worker_input_sha256
            or _SHA256.fullmatch(self.execution_bundle_sha256) is None
            or self.execution_bundle_artifact.digest != self.execution_bundle_sha256
            or _SHA256.fullmatch(self.changed_source_witness_sha256) is None
            or self.changed_source_witness_artifact.digest != self.changed_source_witness_sha256
            or _SHA256.fullmatch(self.rebuild_plan_sha256) is None
            or self.rebuild_plan_artifact.digest != self.rebuild_plan_sha256
            or _SHA256.fullmatch(self.source_tree_sha256) is None
            or self.source_tree_artifact.digest != self.source_tree_sha256
            or _SAFE_NAME.fullmatch(self.lean_version) is None
            or _GIT_COMMIT.fullmatch(self.mathlib_revision) is None
            or _SHA256.fullmatch(self.lake_manifest_sha256) is None
            or self.lake_manifest_artifact.digest != self.lake_manifest_sha256
            or _SHA256.fullmatch(self.image_binding_sha256) is None
            or self.image_binding_artifact.digest != self.image_binding_sha256
            or _SHA256.fullmatch(self.expected_query_sha256) is None
            or self.expected_query_artifact.digest != self.expected_query_sha256
            or not _safe_argv(self.command_argv)
            or not _safe_absolute_posix_path(self.working_directory)
            or not _safe_relative_file(self.output_olean_path)
            or not self.output_olean_path.endswith(".olean")
            or not _safe_relative_file(self.declaration_query_path)
            or not self.declaration_query_path.endswith(".json")
        ):
            raise LeanModuleBuildError("module build spec is invalid")
        modules = tuple(item.module for item in self.dependency_receipts)
        if len(set(modules)) != len(modules):
            raise LeanModuleBuildError("dependency module receipts are duplicated")
        baseline_present = (
            self.baseline_receipt_sha256 is not None and self.baseline_receipt_artifact is not None
        )
        if (self.action == _REUSE) != baseline_present or (
            baseline_present
            and (
                _SHA256.fullmatch(cast(str, self.baseline_receipt_sha256)) is None
                or cast(ArtifactRef, self.baseline_receipt_artifact).digest
                != self.baseline_receipt_sha256
            )
        ):
            raise LeanModuleBuildError("module baseline receipt binding is invalid")

    def canonical_bytes(self) -> bytes:
        return _canonical_bytes(
            {
                "schema_version": MODULE_BUILD_SPEC_SCHEMA,
                "action": self.action,
                "module": self.module,
                "worker_input_sha256": self.worker_input_sha256,
                "worker_input_artifact": _artifact_document(self.worker_input_artifact),
                "execution_bundle_sha256": self.execution_bundle_sha256,
                "execution_bundle_artifact": _artifact_document(self.execution_bundle_artifact),
                "changed_source_witness_sha256": (self.changed_source_witness_sha256),
                "changed_source_witness_artifact": _artifact_document(
                    self.changed_source_witness_artifact
                ),
                "rebuild_plan_sha256": self.rebuild_plan_sha256,
                "rebuild_plan_artifact": _artifact_document(self.rebuild_plan_artifact),
                "source_tree_sha256": self.source_tree_sha256,
                "source_tree_artifact": _artifact_document(self.source_tree_artifact),
                "dependency_receipts": [item.document() for item in self.dependency_receipts],
                "lean_version": self.lean_version,
                "mathlib_revision": self.mathlib_revision,
                "lake_manifest_sha256": self.lake_manifest_sha256,
                "lake_manifest_artifact": _artifact_document(self.lake_manifest_artifact),
                "image_binding_sha256": self.image_binding_sha256,
                "image_binding_artifact": _artifact_document(self.image_binding_artifact),
                "expected_query_sha256": self.expected_query_sha256,
                "expected_query_artifact": _artifact_document(self.expected_query_artifact),
                "command_argv": list(self.command_argv),
                "working_directory": self.working_directory,
                "output_olean_path": self.output_olean_path,
                "declaration_query_path": self.declaration_query_path,
                "baseline_receipt_sha256": self.baseline_receipt_sha256,
                "baseline_receipt_artifact": (
                    None
                    if self.baseline_receipt_artifact is None
                    else _artifact_document(self.baseline_receipt_artifact)
                ),
            }
        )

    @property
    def content_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    @property
    def job_id(self) -> str:
        return f"t7-lean-module:{self.content_sha256}"


@dataclass(frozen=True, slots=True)
class FrozenLeanModuleBuildSpecV1:
    spec: LeanModuleBuildSpecV1
    artifact: ArtifactRef
    worker: FrozenRealLeanImmutableWorkerInputV1
    source_tree: FrozenLeanModuleSourceTreeV1
    image_binding: LeanModuleImageBindingV1
    image_binding_artifact: ArtifactRef
    expected_query: FrozenLeanDeclarationQueryManifestV1
    dependencies: tuple[CommittedLeanModuleBuildV1, ...]
    baseline: CommittedLeanModuleBuildV1 | None

    def __post_init__(self) -> None:
        _check_frozen(self.artifact, self.spec.canonical_bytes(), "module build spec")


@dataclass(frozen=True, slots=True)
class LeanModuleBuildRequestV1:
    spec_sha256: str
    spec_artifact: ArtifactRef
    lease_job_id: str
    lease_holder_id: str
    fencing_token: int
    worker_identity: str

    def __post_init__(self) -> None:
        if (
            _SHA256.fullmatch(self.spec_sha256) is None
            or self.spec_artifact.digest != self.spec_sha256
            or not self.lease_job_id
            or not self.lease_holder_id
            or type(self.fencing_token) is not int
            or self.fencing_token <= 0
            or _SAFE_NAME.fullmatch(self.worker_identity) is None
        ):
            raise LeanModuleBuildError("module build request authority is invalid")

    def canonical_bytes(self) -> bytes:
        return _canonical_bytes(
            {
                "schema_version": MODULE_BUILD_REQUEST_SCHEMA,
                "spec_sha256": self.spec_sha256,
                "spec_artifact": _artifact_document(self.spec_artifact),
                "lease_job_id": self.lease_job_id,
                "lease_holder_id": self.lease_holder_id,
                "fencing_token": self.fencing_token,
                "worker_identity": self.worker_identity,
            }
        )

    @property
    def content_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


@dataclass(frozen=True, slots=True)
class FrozenLeanModuleBuildRequestV1:
    request: LeanModuleBuildRequestV1
    artifact: ArtifactRef
    frozen_spec: FrozenLeanModuleBuildSpecV1
    lease: Lease

    def __post_init__(self) -> None:
        _check_frozen(
            self.artifact,
            self.request.canonical_bytes(),
            "module build request",
        )
        if (
            self.request.spec_sha256 != self.frozen_spec.spec.content_sha256
            or self.request.spec_artifact != self.frozen_spec.artifact
            or self.request.lease_job_id != self.frozen_spec.spec.job_id
            or self.request.lease_job_id != self.lease.job_id
            or self.request.lease_holder_id != self.lease.holder_id
            or self.request.fencing_token != self.lease.fencing_token
        ):
            raise LeanModuleBuildError("frozen module request binding is invalid")


@dataclass(frozen=True, slots=True)
class LeanModuleRuntimeObservationV1:
    runtime_kind: str
    runtime_engine: str
    runtime_engine_version: str
    oci_repo_digest: str
    oci_config_digest: str
    platform: OciPlatformV1
    runner_policy_sha256: str
    command_argv: tuple[str, ...]
    working_directory: str
    container_identity: str | None
    network_mode: str
    root_filesystem_read_only: bool
    started_at_utc: str
    finished_at_utc: str
    duration_ms: int
    exit_code: int | None
    timed_out: bool

    def __post_init__(self) -> None:
        start = _parse_utc(self.started_at_utc)
        finish = _parse_utc(self.finished_at_utc)
        if (
            self.runtime_kind not in {"synthetic_injected", "operator_local_oci"}
            or not self.runtime_engine
            or not self.runtime_engine_version
            or not _is_oci_repo_digest(self.oci_repo_digest)
            or _DIGEST.fullmatch(self.oci_config_digest) is None
            or _SHA256.fullmatch(self.runner_policy_sha256) is None
            or not _safe_argv(self.command_argv)
            or not _safe_absolute_posix_path(self.working_directory)
            or (
                self.container_identity is not None
                and _SAFE_NAME.fullmatch(self.container_identity) is None
            )
            or self.network_mode != "none"
            or type(self.root_filesystem_read_only) is not bool
            or not self.root_filesystem_read_only
            or type(self.duration_ms) is not int
            or self.duration_ms < 0
            or (self.exit_code is not None and type(self.exit_code) is not int)
            or type(self.timed_out) is not bool
            or finish < start
            or (self.timed_out and self.exit_code is not None)
        ):
            raise LeanModuleBuildError("module runtime observation is invalid")

    def canonical_bytes(self) -> bytes:
        return _canonical_bytes(
            {
                "schema_version": MODULE_RUNTIME_OBSERVATION_SCHEMA,
                "runtime_kind": self.runtime_kind,
                "runtime_engine": self.runtime_engine,
                "runtime_engine_version": self.runtime_engine_version,
                "oci_repo_digest": self.oci_repo_digest,
                "oci_config_digest": self.oci_config_digest,
                "platform": self.platform.document(),
                "runner_policy_sha256": self.runner_policy_sha256,
                "command_argv": list(self.command_argv),
                "working_directory": self.working_directory,
                "container_identity": self.container_identity,
                "network_mode": self.network_mode,
                "root_filesystem_read_only": self.root_filesystem_read_only,
                "started_at_utc": self.started_at_utc,
                "finished_at_utc": self.finished_at_utc,
                "duration_ms": self.duration_ms,
                "exit_code": self.exit_code,
                "timed_out": self.timed_out,
            }
        )

    @property
    def content_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


@dataclass(frozen=True, slots=True)
class RawLeanModuleRunObservationV1:
    """Runner-returned bytes; evidence class and promotion are intentionally absent."""

    runtime: LeanModuleRuntimeObservationV1
    stdout: bytes
    stderr: bytes
    output_olean: bytes | None
    declaration_query: bytes | None


@dataclass(frozen=True, slots=True)
class LeanModuleBuildReceiptV1:
    request_sha256: str
    request_artifact: ArtifactRef
    spec_sha256: str
    module: str
    runtime_observation_sha256: str
    runtime_observation_artifact: ArtifactRef
    stdout_artifact: ArtifactRef
    stderr_artifact: ArtifactRef
    output_olean_artifact: ArtifactRef | None
    declaration_query_artifact: ArtifactRef | None
    outcome: ModuleProcessOutcome
    evidence_class: ModuleEvidenceClass
    runner_identity: str
    gateway_attestation_class: str
    gateway_attestation_artifact: ArtifactRef | None
    promotion_eligible: bool = False
    kernel_acceptance_eligible: bool = False

    def __post_init__(self) -> None:
        success = self.outcome == _PROCESS_SUCCEEDED
        if (
            _SHA256.fullmatch(self.request_sha256) is None
            or self.request_artifact.digest != self.request_sha256
            or _SHA256.fullmatch(self.spec_sha256) is None
            or not self.module
            or _SHA256.fullmatch(self.runtime_observation_sha256) is None
            or self.runtime_observation_artifact.digest != self.runtime_observation_sha256
            or self.outcome not in {_PROCESS_SUCCEEDED, _PROCESS_FAILED, _PROCESS_TIMED_OUT}
            or self.evidence_class
            not in {
                SYNTHETIC_MODULE_EVIDENCE_CLASS,
                OPERATOR_LOCAL_MODULE_EVIDENCE_CLASS,
            }
            or _SAFE_NAME.fullmatch(self.runner_identity) is None
            or self.gateway_attestation_class != NO_TRUSTED_GATEWAY_ATTESTATION
            or self.gateway_attestation_artifact is not None
            or type(self.promotion_eligible) is not bool
            or self.promotion_eligible
            or type(self.kernel_acceptance_eligible) is not bool
            or self.kernel_acceptance_eligible
            or success
            != (
                self.output_olean_artifact is not None
                and self.declaration_query_artifact is not None
            )
        ):
            raise LeanModuleBuildError("module build receipt is invalid")

    def canonical_bytes(self) -> bytes:
        return _canonical_bytes(
            {
                "schema_version": MODULE_BUILD_RECEIPT_SCHEMA,
                "request_sha256": self.request_sha256,
                "request_artifact": _artifact_document(self.request_artifact),
                "spec_sha256": self.spec_sha256,
                "module": self.module,
                "runtime_observation_sha256": (self.runtime_observation_sha256),
                "runtime_observation_artifact": _artifact_document(
                    self.runtime_observation_artifact
                ),
                "stdout_artifact": _artifact_document(self.stdout_artifact),
                "stderr_artifact": _artifact_document(self.stderr_artifact),
                "output_olean_artifact": (
                    None
                    if self.output_olean_artifact is None
                    else _artifact_document(self.output_olean_artifact)
                ),
                "declaration_query_artifact": (
                    None
                    if self.declaration_query_artifact is None
                    else _artifact_document(self.declaration_query_artifact)
                ),
                "outcome": self.outcome,
                "evidence_class": self.evidence_class,
                "runner_identity": self.runner_identity,
                "gateway_attestation_class": (self.gateway_attestation_class),
                "gateway_attestation_artifact": None,
                "promotion_eligible": self.promotion_eligible,
                "kernel_acceptance_eligible": (self.kernel_acceptance_eligible),
            }
        )

    @property
    def content_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


@dataclass(frozen=True, slots=True)
class FrozenLeanModuleBuildReceiptV1:
    receipt: LeanModuleBuildReceiptV1
    artifact: ArtifactRef
    request: FrozenLeanModuleBuildRequestV1
    runtime: LeanModuleRuntimeObservationV1

    def __post_init__(self) -> None:
        _check_frozen(
            self.artifact,
            self.receipt.canonical_bytes(),
            "module build receipt",
        )
        if (
            self.receipt.request_sha256 != self.request.request.content_sha256
            or self.receipt.request_artifact != self.request.artifact
            or self.receipt.spec_sha256 != self.request.frozen_spec.spec.content_sha256
            or self.receipt.runtime_observation_sha256 != self.runtime.content_sha256
        ):
            raise LeanModuleBuildError("frozen module receipt binding is invalid")


@dataclass(frozen=True, slots=True)
class LeanDeclarationFanoutRecordV1:
    current_request_sha256: str
    current_request_artifact: ArtifactRef
    module_receipt_sha256: str
    module_receipt_artifact: ArtifactRef
    module: str
    node_id: str
    declaration: str
    planned_action: str
    elaborated_type_sha256: str
    axioms: tuple[str, ...]
    output_olean_artifact: ArtifactRef
    declaration_query_artifact: ArtifactRef
    evidence_class: ModuleEvidenceClass
    promotion_eligible: bool = False
    kernel_acceptance_eligible: bool = False

    def __post_init__(self) -> None:
        if (
            _SHA256.fullmatch(self.current_request_sha256) is None
            or self.current_request_artifact.digest != self.current_request_sha256
            or _SHA256.fullmatch(self.module_receipt_sha256) is None
            or self.module_receipt_artifact.digest != self.module_receipt_sha256
            or not self.module
            or not self.node_id
            or not self.declaration
            or self.planned_action not in {"rebuild", "reuse"}
            or _SHA256.fullmatch(self.elaborated_type_sha256) is None
            or tuple(sorted(set(self.axioms))) != self.axioms
            or self.evidence_class
            not in {
                SYNTHETIC_MODULE_EVIDENCE_CLASS,
                OPERATOR_LOCAL_MODULE_EVIDENCE_CLASS,
            }
            or type(self.promotion_eligible) is not bool
            or self.promotion_eligible
            or type(self.kernel_acceptance_eligible) is not bool
            or self.kernel_acceptance_eligible
        ):
            raise LeanModuleBuildError("declaration fanout record is invalid")

    def canonical_bytes(self) -> bytes:
        return _canonical_bytes(
            {
                "schema_version": DECLARATION_FANOUT_SCHEMA,
                "current_request_sha256": self.current_request_sha256,
                "current_request_artifact": _artifact_document(self.current_request_artifact),
                "module_receipt_sha256": self.module_receipt_sha256,
                "module_receipt_artifact": _artifact_document(self.module_receipt_artifact),
                "module": self.module,
                "node_id": self.node_id,
                "declaration": self.declaration,
                "planned_action": self.planned_action,
                "elaborated_type_sha256": self.elaborated_type_sha256,
                "axioms": list(self.axioms),
                "output_olean_artifact": _artifact_document(self.output_olean_artifact),
                "declaration_query_artifact": _artifact_document(self.declaration_query_artifact),
                "evidence_class": self.evidence_class,
                "promotion_eligible": self.promotion_eligible,
                "kernel_acceptance_eligible": (self.kernel_acceptance_eligible),
            }
        )

    @property
    def content_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


@dataclass(frozen=True, slots=True)
class FrozenLeanDeclarationFanoutRecordV1:
    record: LeanDeclarationFanoutRecordV1
    artifact: ArtifactRef

    def __post_init__(self) -> None:
        _check_frozen(
            self.artifact,
            self.record.canonical_bytes(),
            "declaration fanout record",
        )


@dataclass(frozen=True, slots=True)
class CommittedLeanModuleBuildV1:
    """A successful durable module receipt and its atomic declaration fanout."""

    request: FrozenLeanModuleBuildRequestV1
    receipt: FrozenLeanModuleBuildReceiptV1
    fanout: tuple[FrozenLeanDeclarationFanoutRecordV1, ...]
    receipt_event: StoredEvent

    def __post_init__(self) -> None:
        request_matches_receipt = (
            self.receipt.request == self.request
            if self.request.frozen_spec.spec.action == _BUILD
            else (
                self.request.frozen_spec.baseline is not None
                and self.receipt.artifact == self.request.frozen_spec.baseline.receipt.artifact
            )
        )
        if (
            self.receipt.receipt.outcome != _PROCESS_SUCCEEDED
            or not request_matches_receipt
            or not self.fanout
            or self.receipt_event.global_position <= 0
        ):
            raise LeanModuleBuildError("committed module build is invalid")


@dataclass(frozen=True, slots=True)
class LeanModuleExecutionStatusV1:
    state: ModuleExecutionState
    module: str
    request_sha256: str
    module_receipt_artifact: ArtifactRef | None
    fanout_count: int
    evidence_class: ModuleEvidenceClass | None
    promotion_eligible: bool = False
    kernel_acceptance_eligible: bool = False

    def __post_init__(self) -> None:
        if (
            self.state
            not in {
                "MODULE_PENDING",
                "MODULE_BUILD_SUCCEEDED_NONPROMOTABLE",
                "MODULE_BUILD_FAILED_NONPROMOTABLE",
                "MODULE_REUSED_NONPROMOTABLE",
            }
            or not self.module
            or _SHA256.fullmatch(self.request_sha256) is None
            or type(self.fanout_count) is not int
            or self.fanout_count < 0
            or type(self.promotion_eligible) is not bool
            or self.promotion_eligible
            or type(self.kernel_acceptance_eligible) is not bool
            or self.kernel_acceptance_eligible
        ):
            raise LeanModuleBuildError("module execution status is invalid")


class SyntheticLeanModuleRunner(ABC):
    """Injection point for tests; every subclass is always synthetic evidence."""

    @property
    @abstractmethod
    def runner_identity(self) -> str:
        """Return a bounded public test-runner identity."""

    @abstractmethod
    def run(
        self,
        request: FrozenLeanModuleBuildRequestV1,
    ) -> RawLeanModuleRunObservationV1:
        """Return deterministic fake process bytes without launching a subprocess."""


@dataclass(frozen=True, slots=True)
class OperatorLocalModuleRunnerCapabilityV1:
    """A T6-verified local capability; it is never a trusted gateway attestation."""

    image_binding: LeanModuleImageBindingV1
    preflight_artifact: ArtifactRef
    runtime_engine_version: str
    runner_identity: str
    _preflight_marker: object
    capability_class: str = OPERATOR_LOCAL_MODULE_EVIDENCE_CLASS
    promotion_eligible: bool = False

    def __post_init__(self) -> None:
        if (
            _SAFE_NAME.fullmatch(self.runtime_engine_version) is None
            or _SAFE_NAME.fullmatch(self.runner_identity) is None
            or self._preflight_marker is not _OPERATOR_PREFLIGHT_MARKER
            or self.capability_class != OPERATOR_LOCAL_MODULE_EVIDENCE_CLASS
            or type(self.promotion_eligible) is not bool
            or self.promotion_eligible
        ):
            raise LeanModuleBuildError("operator-local runner capability is invalid")


class OperatorLocalOciModuleRunner:
    """Exact-type marker for a future local OCI launch path.

    Construction requires a successful T6-backed preflight.  This class does not
    grant trusted-gateway status; the store always labels its observations as
    operator-local and non-promotable.
    """

    __slots__ = ("capability",)

    def __init__(
        self,
        capability: OperatorLocalModuleRunnerCapabilityV1,
    ) -> None:
        if capability._preflight_marker is not _OPERATOR_PREFLIGHT_MARKER:
            raise LeanModuleBuildError(
                "operator-local runner requires a verified preflight capability"
            )
        self.capability = capability

    def run(
        self,
        request: FrozenLeanModuleBuildRequestV1,
    ) -> RawLeanModuleRunObservationV1:
        if (
            request.frozen_spec.image_binding.content_sha256
            != self.capability.image_binding.content_sha256
        ):
            raise LeanModuleBuildError("operator-local capability belongs to another OCI image")
        return _execute_operator_local_module(request, self.capability)


def freeze_expected_declaration_query(
    fixture: RealLeanProjectDagV1,
    module: str,
    records: Sequence[LeanDeclarationQueryRecordV1],
    artifacts: ArtifactStore,
) -> FrozenLeanDeclarationQueryManifestV1:
    """Seal an independently captured query manifest; never parse Lean source."""

    expected = tuple(
        item for item in fixture.declaration_topological_order() if item.module == module
    )
    supplied = tuple(records)
    if tuple(item.node_id for item in supplied) != tuple(
        item.node_id for item in expected
    ) or tuple(item.declaration for item in supplied) != tuple(
        item.declaration for item in expected
    ):
        raise LeanModuleBuildError(
            "locked declaration query does not cover the exact fixture module"
        )
    manifest = LeanDeclarationQueryManifestV1(module=module, records=supplied)
    artifact = artifacts.put_bytes(manifest.canonical_bytes())
    return FrozenLeanDeclarationQueryManifestV1(
        manifest=manifest,
        artifact=artifact,
    )


def freeze_module_source_tree(
    worker: FrozenRealLeanImmutableWorkerInputV1,
    module: str,
    artifacts: ArtifactStore,
) -> FrozenLeanModuleSourceTreeV1:
    """Seal the target module plus every transitive fixture import and source byte."""

    verify_frozen_real_lean_worker(worker, artifacts)
    fixture_modules = worker.fixture.modules_by_name
    if module not in fixture_modules:
        raise LeanModuleBuildError("module source tree targets an unknown module")
    closure: set[str] = set()
    pending = [module]
    while pending:
        current = pending.pop()
        if current in closure:
            continue
        closure.add(current)
        pending.extend(fixture_modules[current].imports)
    entries: list[LeanModuleSourceEntryV1] = []
    for fixture_module in worker.fixture.module_topological_order():
        if fixture_module.module not in closure:
            continue
        source = worker.bundle.sources_by_module.get(fixture_module.module)
        if source is None:
            raise LeanModuleBuildError("worker source snapshot is incomplete")
        artifacts.verify(source.artifact)
        entries.append(
            LeanModuleSourceEntryV1(
                module=fixture_module.module,
                file=fixture_module.file,
                imports=fixture_module.imports,
                source_artifact=source.artifact,
            )
        )
    tree = LeanModuleSourceTreeV1(
        target_module=module,
        entries=tuple(entries),
    )
    artifact = artifacts.put_bytes(tree.canonical_bytes())
    return FrozenLeanModuleSourceTreeV1(tree=tree, artifact=artifact)


def freeze_module_image_binding(
    image_binding: LeanModuleImageBindingV1,
    artifacts: ArtifactStore,
) -> ArtifactRef:
    for reference in (
        image_binding.runner_policy_artifact,
        image_binding.image_verification_artifact,
    ):
        artifacts.verify(reference)
    if not artifacts.get_bytes(image_binding.runner_policy_artifact):
        raise LeanModuleBuildError("runner policy artifact must not be empty")
    return artifacts.put_bytes(image_binding.canonical_bytes())


def freeze_lean_module_build_spec(
    worker: FrozenRealLeanImmutableWorkerInputV1,
    *,
    module: str,
    action: ModuleAction,
    image_binding: LeanModuleImageBindingV1,
    lake_manifest_artifact: ArtifactRef,
    expected_query: FrozenLeanDeclarationQueryManifestV1,
    dependencies: Sequence[CommittedLeanModuleBuildV1],
    baseline: CommittedLeanModuleBuildV1 | None,
    command_argv: Sequence[str],
    working_directory: str,
    output_olean_path: str,
    declaration_query_path: str,
    artifacts: ArtifactStore,
) -> FrozenLeanModuleBuildSpecV1:
    """Freeze all authority-free module inputs before a lease is claimed."""

    verify_frozen_real_lean_worker(worker, artifacts)
    source_tree = freeze_module_source_tree(worker, module, artifacts)
    image_artifact = freeze_module_image_binding(image_binding, artifacts)
    artifacts.verify(lake_manifest_artifact)
    artifacts.verify(expected_query.artifact)
    if expected_query.manifest.module != module:
        raise LeanModuleBuildError("expected declaration query targets another module")
    _verify_query_against_fixture(worker.fixture, expected_query.manifest)
    environment = worker.environment
    if (
        image_binding.oci_repo_digest != environment.oci_repo_digest
        or image_binding.runner_policy_sha256 != environment.runner_policy_sha256
        or environment.lean_version == ""
        or environment.mathlib_revision == ""
    ):
        raise LeanModuleBuildError(
            "module image binding differs from the frozen worker environment"
        )
    direct_imports = worker.fixture.modules_by_name[module].imports
    ordered_dependencies = tuple(dependencies)
    if tuple(item.request.frozen_spec.spec.module for item in ordered_dependencies) != (
        direct_imports
    ):
        raise LeanModuleBuildError("module dependencies must cover direct imports in fixture order")
    for dependency in ordered_dependencies:
        _verify_dependency_for_spec(
            worker,
            image_binding,
            source_tree,
            dependency,
            artifacts,
            lake_manifest_sha256=lake_manifest_artifact.digest,
        )
    if action == _REUSE:
        if baseline is None:
            raise LeanModuleBuildError("module reuse requires an earlier receipt")
        _verify_baseline_for_spec(
            worker,
            image_binding,
            source_tree,
            expected_query,
            baseline,
            artifacts,
            lake_manifest_sha256=lake_manifest_artifact.digest,
        )
    elif baseline is not None:
        raise LeanModuleBuildError("module build cannot carry a reuse baseline")
    dependency_bindings = tuple(
        LeanDependencyModuleReceiptV1(
            module=item.request.frozen_spec.spec.module,
            request_sha256=item.receipt.request.request.content_sha256,
            request_artifact=item.receipt.request.artifact,
            receipt_sha256=item.receipt.receipt.content_sha256,
            receipt_artifact=item.receipt.artifact,
            output_olean_artifact=cast(
                ArtifactRef,
                item.receipt.receipt.output_olean_artifact,
            ),
        )
        for item in ordered_dependencies
    )
    baseline_receipt = None if baseline is None else baseline.receipt
    spec = LeanModuleBuildSpecV1(
        action=action,
        module=module,
        worker_input_sha256=worker.bundle.content_sha256,
        worker_input_artifact=worker.artifact,
        execution_bundle_sha256=worker.execution.bundle.content_sha256,
        execution_bundle_artifact=worker.execution.artifact,
        changed_source_witness_sha256=(worker.changed_source_witness.witness.content_sha256),
        changed_source_witness_artifact=worker.changed_source_witness.artifact,
        rebuild_plan_sha256=worker.rebuild_plan.content_sha256,
        rebuild_plan_artifact=worker.execution.bundle.rebuild_plan_artifact,
        source_tree_sha256=source_tree.tree.content_sha256,
        source_tree_artifact=source_tree.artifact,
        dependency_receipts=dependency_bindings,
        lean_version=environment.lean_version,
        mathlib_revision=environment.mathlib_revision,
        lake_manifest_sha256=lake_manifest_artifact.digest,
        lake_manifest_artifact=lake_manifest_artifact,
        image_binding_sha256=image_binding.content_sha256,
        image_binding_artifact=image_artifact,
        expected_query_sha256=expected_query.manifest.content_sha256,
        expected_query_artifact=expected_query.artifact,
        command_argv=tuple(command_argv),
        working_directory=working_directory,
        output_olean_path=output_olean_path,
        declaration_query_path=declaration_query_path,
        baseline_receipt_sha256=(
            None if baseline_receipt is None else baseline_receipt.receipt.content_sha256
        ),
        baseline_receipt_artifact=(None if baseline_receipt is None else baseline_receipt.artifact),
    )
    artifact = artifacts.put_bytes(spec.canonical_bytes())
    return FrozenLeanModuleBuildSpecV1(
        spec=spec,
        artifact=artifact,
        worker=worker,
        source_tree=source_tree,
        image_binding=image_binding,
        image_binding_artifact=image_artifact,
        expected_query=expected_query,
        dependencies=ordered_dependencies,
        baseline=baseline,
    )


def verify_frozen_lean_module_build_spec(
    frozen: FrozenLeanModuleBuildSpecV1,
    artifacts: ArtifactStore,
) -> None:
    """Recompute and verify every authority-free module input and nested CAS edge."""

    artifacts.verify(frozen.artifact)
    if artifacts.get_bytes(frozen.artifact) != frozen.spec.canonical_bytes():
        raise LeanModuleBuildError("module build spec artifact changed")
    verify_frozen_real_lean_worker(frozen.worker, artifacts)
    expected_tree = freeze_module_source_tree(
        frozen.worker,
        frozen.spec.module,
        artifacts,
    )
    if (
        expected_tree.tree.canonical_bytes() != frozen.source_tree.tree.canonical_bytes()
        or expected_tree.artifact != frozen.source_tree.artifact
        or frozen.spec.source_tree_sha256 != frozen.source_tree.tree.content_sha256
        or frozen.spec.source_tree_artifact != frozen.source_tree.artifact
    ):
        raise LeanModuleBuildError("module source tree differs from the frozen worker")
    for reference in (
        frozen.spec.worker_input_artifact,
        frozen.spec.execution_bundle_artifact,
        frozen.spec.changed_source_witness_artifact,
        frozen.spec.rebuild_plan_artifact,
        frozen.spec.lake_manifest_artifact,
        frozen.spec.image_binding_artifact,
        frozen.spec.expected_query_artifact,
        frozen.image_binding.runner_policy_artifact,
        frozen.image_binding.image_verification_artifact,
        *(item.source_artifact for item in frozen.source_tree.tree.entries),
    ):
        artifacts.verify(reference)
    environment = frozen.worker.environment
    if (
        frozen.spec.worker_input_sha256 != frozen.worker.bundle.content_sha256
        or frozen.spec.worker_input_artifact != frozen.worker.artifact
        or frozen.spec.execution_bundle_sha256 != frozen.worker.execution.bundle.content_sha256
        or frozen.spec.execution_bundle_artifact != frozen.worker.execution.artifact
        or frozen.spec.changed_source_witness_sha256
        != frozen.worker.changed_source_witness.witness.content_sha256
        or frozen.spec.changed_source_witness_artifact
        != frozen.worker.changed_source_witness.artifact
        or frozen.spec.rebuild_plan_sha256 != frozen.worker.rebuild_plan.content_sha256
        or frozen.spec.rebuild_plan_artifact != frozen.worker.execution.bundle.rebuild_plan_artifact
        or frozen.spec.lean_version != environment.lean_version
        or frozen.spec.mathlib_revision != environment.mathlib_revision
        or frozen.image_binding.oci_repo_digest != environment.oci_repo_digest
        or frozen.image_binding.runner_policy_sha256 != environment.runner_policy_sha256
        or frozen.spec.image_binding_sha256 != frozen.image_binding.content_sha256
        or frozen.spec.image_binding_artifact != frozen.image_binding_artifact
        or artifacts.get_bytes(frozen.image_binding_artifact)
        != frozen.image_binding.canonical_bytes()
        or frozen.spec.expected_query_sha256 != frozen.expected_query.manifest.content_sha256
        or frozen.spec.expected_query_artifact != frozen.expected_query.artifact
        or artifacts.get_bytes(frozen.expected_query.artifact)
        != frozen.expected_query.manifest.canonical_bytes()
    ):
        raise LeanModuleBuildError("module spec nested artifact binding changed")
    _verify_query_against_fixture(
        frozen.worker.fixture,
        frozen.expected_query.manifest,
    )
    expected_imports = frozen.worker.fixture.modules_by_name[frozen.spec.module].imports
    if (
        tuple(item.request.frozen_spec.spec.module for item in frozen.dependencies)
        != expected_imports
    ):
        raise LeanModuleBuildError("module spec dependencies drifted")
    expected_dependency_bindings = tuple(
        LeanDependencyModuleReceiptV1(
            module=item.request.frozen_spec.spec.module,
            request_sha256=item.receipt.request.request.content_sha256,
            request_artifact=item.receipt.request.artifact,
            receipt_sha256=item.receipt.receipt.content_sha256,
            receipt_artifact=item.receipt.artifact,
            output_olean_artifact=cast(
                ArtifactRef,
                item.receipt.receipt.output_olean_artifact,
            ),
        )
        for item in frozen.dependencies
    )
    if frozen.spec.dependency_receipts != expected_dependency_bindings:
        raise LeanModuleBuildError("module spec dependency receipt bindings changed")
    for dependency in frozen.dependencies:
        verify_frozen_lean_module_build_spec(
            dependency.request.frozen_spec,
            artifacts,
        )
        verify_frozen_lean_module_build_receipt(
            dependency.receipt,
            artifacts,
        )
        _verify_dependency_for_spec(
            frozen.worker,
            frozen.image_binding,
            frozen.source_tree,
            dependency,
            artifacts,
            lake_manifest_sha256=frozen.spec.lake_manifest_sha256,
        )
    if frozen.spec.action == _REUSE:
        if frozen.baseline is None:
            raise LeanModuleBuildError("module reuse baseline disappeared")
        verify_frozen_lean_module_build_spec(
            frozen.baseline.request.frozen_spec,
            artifacts,
        )
        verify_frozen_lean_module_build_receipt(
            frozen.baseline.receipt,
            artifacts,
        )
        _verify_baseline_for_spec(
            frozen.worker,
            frozen.image_binding,
            frozen.source_tree,
            frozen.expected_query,
            frozen.baseline,
            artifacts,
            lake_manifest_sha256=frozen.spec.lake_manifest_sha256,
        )
        if (
            frozen.spec.baseline_receipt_sha256 != frozen.baseline.receipt.receipt.content_sha256
            or frozen.spec.baseline_receipt_artifact != frozen.baseline.receipt.artifact
        ):
            raise LeanModuleBuildError("module reuse baseline binding changed")
    elif frozen.baseline is not None:
        raise LeanModuleBuildError("module build acquired a reuse baseline")


def verify_frozen_lean_module_build_receipt(
    frozen: FrozenLeanModuleBuildReceiptV1,
    artifacts: ArtifactStore,
) -> None:
    """Verify a receipt and all nested artifacts without granting acceptance.

    This verifier proves only that the immutable module process observation is
    internally consistent with its request and locked query artifact.  It does not
    turn fake or operator-local evidence into a trusted gateway attestation and it
    does not establish per-declaration kernel acceptance.
    """

    request = frozen.request
    spec = request.frozen_spec.spec
    image = request.frozen_spec.image_binding
    receipt = frozen.receipt
    runtime = frozen.runtime
    verify_frozen_lean_module_build_spec(request.frozen_spec, artifacts)
    for reference in (
        request.frozen_spec.artifact,
        request.artifact,
        request.frozen_spec.source_tree.artifact,
        request.frozen_spec.image_binding_artifact,
        request.frozen_spec.expected_query.artifact,
        receipt.runtime_observation_artifact,
        receipt.stdout_artifact,
        receipt.stderr_artifact,
        frozen.artifact,
    ):
        artifacts.verify(reference)
    for optional_reference in (
        receipt.output_olean_artifact,
        receipt.declaration_query_artifact,
    ):
        if optional_reference is not None:
            artifacts.verify(optional_reference)
    if (
        artifacts.get_bytes(request.frozen_spec.artifact) != spec.canonical_bytes()
        or artifacts.get_bytes(request.artifact) != request.request.canonical_bytes()
        or artifacts.get_bytes(request.frozen_spec.source_tree.artifact)
        != request.frozen_spec.source_tree.tree.canonical_bytes()
        or artifacts.get_bytes(request.frozen_spec.image_binding_artifact)
        != image.canonical_bytes()
        or artifacts.get_bytes(request.frozen_spec.expected_query.artifact)
        != request.frozen_spec.expected_query.manifest.canonical_bytes()
        or artifacts.get_bytes(receipt.runtime_observation_artifact) != runtime.canonical_bytes()
        or artifacts.get_bytes(frozen.artifact) != receipt.canonical_bytes()
        or request.request.lease_job_id != spec.job_id
        or request.request.lease_job_id != request.lease.job_id
        or receipt.request_sha256 != request.request.content_sha256
        or receipt.request_artifact != request.artifact
        or receipt.spec_sha256 != spec.content_sha256
        or receipt.module != spec.module
        or receipt.runtime_observation_sha256 != runtime.content_sha256
        or runtime.oci_repo_digest != image.oci_repo_digest
        or runtime.oci_config_digest != image.oci_config_digest
        or runtime.platform != image.platform
        or runtime.runner_policy_sha256 != image.runner_policy_sha256
        or runtime.command_argv != spec.command_argv
        or runtime.working_directory != spec.working_directory
        or (
            receipt.evidence_class == SYNTHETIC_MODULE_EVIDENCE_CLASS
            and runtime.runtime_kind != "synthetic_injected"
        )
        or (
            receipt.evidence_class == OPERATOR_LOCAL_MODULE_EVIDENCE_CLASS
            and runtime.runtime_kind != "operator_local_oci"
        )
        or receipt.promotion_eligible
        or receipt.kernel_acceptance_eligible
        or receipt.gateway_attestation_class != NO_TRUSTED_GATEWAY_ATTESTATION
        or receipt.gateway_attestation_artifact is not None
    ):
        raise LeanModuleBuildError("module receipt artifact binding changed")
    expected_outcome = (
        _PROCESS_TIMED_OUT
        if runtime.timed_out
        else (_PROCESS_SUCCEEDED if runtime.exit_code == 0 else _PROCESS_FAILED)
    )
    if receipt.outcome != expected_outcome:
        raise LeanModuleBuildError("module receipt outcome differs from process observation")
    if receipt.outcome == _PROCESS_SUCCEEDED:
        if (
            receipt.output_olean_artifact is None
            or receipt.declaration_query_artifact != request.frozen_spec.expected_query.artifact
        ):
            raise LeanModuleBuildError("successful module receipt omitted locked outputs")
        if (
            artifacts.get_bytes(receipt.declaration_query_artifact)
            != request.frozen_spec.expected_query.manifest.canonical_bytes()
        ):
            raise LeanModuleBuildError("successful module receipt query artifact changed")
    elif (
        receipt.output_olean_artifact is not None or receipt.declaration_query_artifact is not None
    ):
        raise LeanModuleBuildError("failed module receipt exposes accepted outputs")


def require_trusted_module_receipt_for_kernel_acceptance(
    frozen: FrozenLeanModuleBuildReceiptV1,
    artifacts: ArtifactStore,
) -> None:
    """Reject every current V1 receipt at the production kernel-acceptance boundary."""

    verify_frozen_lean_module_build_receipt(frozen, artifacts)
    raise LeanModuleBuildError(
        "V1 module receipts are execution observations, not kernel acceptance"
    )


class LeanModuleBuildStore:
    """Lease-fenced, at-most-once module receipt and atomic fanout store."""

    def __init__(
        self,
        *,
        events: EventStore,
        leases: LeaseStore,
        artifacts: ArtifactStore,
    ) -> None:
        if events.path.resolve() != leases.path.resolve():
            raise LeanModuleBuildError(
                "module event and lease stores must share one SQLite database"
            )
        self.events = events
        self.leases = leases
        self.artifacts = artifacts

    def claim(
        self,
        frozen_spec: FrozenLeanModuleBuildSpecV1,
        *,
        worker_id: str,
        ttl_seconds: float,
    ) -> Lease:
        self._verify_spec(frozen_spec)
        return self.leases.claim(
            frozen_spec.spec.job_id,
            worker_id,
            ttl_seconds=ttl_seconds,
        )

    def bind_request(
        self,
        frozen_spec: FrozenLeanModuleBuildSpecV1,
        *,
        lease: Lease,
        worker_identity: str,
    ) -> FrozenLeanModuleBuildRequestV1:
        self._verify_spec(frozen_spec)
        if lease.job_id != frozen_spec.spec.job_id:
            raise StaleFence("module lease belongs to another build spec")
        self.leases.assert_current(lease)
        request = LeanModuleBuildRequestV1(
            spec_sha256=frozen_spec.spec.content_sha256,
            spec_artifact=frozen_spec.artifact,
            lease_job_id=lease.job_id,
            lease_holder_id=lease.holder_id,
            fencing_token=lease.fencing_token,
            worker_identity=worker_identity,
        )
        artifact = self.artifacts.put_bytes(request.canonical_bytes())
        return FrozenLeanModuleBuildRequestV1(
            request=request,
            artifact=artifact,
            frozen_spec=frozen_spec,
            lease=lease,
        )

    def execute_and_commit(
        self,
        frozen_request: FrozenLeanModuleBuildRequestV1,
        *,
        runner: SyntheticLeanModuleRunner | OperatorLocalOciModuleRunner,
        idempotency_key: str,
    ) -> CommittedLeanModuleBuildV1 | FrozenLeanModuleBuildReceiptV1:
        """Run one module and atomically commit its receipt plus complete fanout.

        Failure returns a frozen receipt and emits no declaration records.  Success
        returns a durable ``CommittedLeanModuleBuildV1``.  No public method accepts a
        caller-constructed receipt.
        """

        self._verify_request(frozen_request, require_current_lease=False)
        spec = frozen_request.frozen_spec.spec
        if spec.action != _BUILD:
            raise LeanModuleBuildError("only build requests may invoke a runner")
        self._assert_prerequisites_committed(frozen_request.frozen_spec)
        existing = self.events.read_stream(
            MODULE_EVENT_ENTITY_TYPE,
            self._entity_id(frozen_request),
        )
        if existing:
            receipt, fanout, _ = self._validate_stream(
                frozen_request,
                existing,
            )
            if receipt.receipt.outcome != _PROCESS_SUCCEEDED:
                return receipt
            return CommittedLeanModuleBuildV1(
                request=frozen_request,
                receipt=receipt,
                fanout=fanout,
                receipt_event=existing[0],
            )
        self.leases.assert_current(frozen_request.lease)
        if isinstance(runner, SyntheticLeanModuleRunner):
            evidence_class: ModuleEvidenceClass = "synthetic_fake_module_v1"
            runtime_kind = "synthetic_injected"
            runner_identity = runner.runner_identity
        elif type(runner) is OperatorLocalOciModuleRunner:
            evidence_class = "operator_local_oci_without_trusted_gateway_v1"
            runtime_kind = "operator_local_oci"
            runner_identity = runner.capability.runner_identity
        else:
            raise LeanModuleBuildError("module runner type is not allowlisted")
        if _SAFE_NAME.fullmatch(runner_identity) is None:
            raise LeanModuleBuildError("module runner identity is invalid")
        observation = runner.run(frozen_request)
        receipt = self._freeze_observation(
            frozen_request,
            observation,
            evidence_class=evidence_class,
            required_runtime_kind=runtime_kind,
            runner_identity=runner_identity,
        )
        fanout = (
            self._derive_fanout(frozen_request, receipt)
            if receipt.receipt.outcome == _PROCESS_SUCCEEDED
            else ()
        )
        events = self._append_terminal_stream(
            frozen_request,
            receipt=receipt,
            fanout=fanout,
            idempotency_key=idempotency_key,
        )
        if receipt.receipt.outcome != _PROCESS_SUCCEEDED:
            if len(events) != 1:
                raise LeanModuleBuildError("failed module stream contains declaration fanout")
            return receipt
        committed = CommittedLeanModuleBuildV1(
            request=frozen_request,
            receipt=receipt,
            fanout=fanout,
            receipt_event=events[0],
        )
        self._verify_committed(committed)
        return committed

    def commit_reuse(
        self,
        frozen_request: FrozenLeanModuleBuildRequestV1,
        *,
        idempotency_key: str,
    ) -> CommittedLeanModuleBuildV1:
        """Atomically project an earlier same-source/environment successful receipt."""

        self._verify_request(frozen_request, require_current_lease=False)
        frozen_spec = frozen_request.frozen_spec
        if frozen_spec.spec.action != _REUSE or frozen_spec.baseline is None:
            raise LeanModuleBuildError("module reuse request has no baseline receipt")
        self._assert_prerequisites_committed(frozen_spec)
        existing = self.events.read_stream(
            MODULE_EVENT_ENTITY_TYPE,
            self._entity_id(frozen_request),
        )
        if existing:
            receipt, fanout, _ = self._validate_stream(
                frozen_request,
                existing,
            )
            return CommittedLeanModuleBuildV1(
                request=frozen_request,
                receipt=receipt,
                fanout=fanout,
                receipt_event=existing[0],
            )
        self._verify_committed(frozen_spec.baseline)
        self.leases.assert_current(frozen_request.lease)
        receipt = frozen_spec.baseline.receipt
        fanout = self._derive_fanout(frozen_request, receipt)
        events = self._append_terminal_stream(
            frozen_request,
            receipt=receipt,
            fanout=fanout,
            idempotency_key=idempotency_key,
        )
        committed = CommittedLeanModuleBuildV1(
            request=frozen_request,
            receipt=receipt,
            fanout=fanout,
            receipt_event=events[0],
        )
        self._verify_committed(committed)
        return committed

    def status(
        self,
        frozen_request: FrozenLeanModuleBuildRequestV1,
    ) -> LeanModuleExecutionStatusV1:
        """Replay and validate the complete module stream without returning VERIFIED."""

        self._verify_request(frozen_request, require_current_lease=False)
        stream = self.events.read_stream(
            MODULE_EVENT_ENTITY_TYPE,
            self._entity_id(frozen_request),
        )
        if not stream:
            return LeanModuleExecutionStatusV1(
                state="MODULE_PENDING",
                module=frozen_request.frozen_spec.spec.module,
                request_sha256=frozen_request.request.content_sha256,
                module_receipt_artifact=None,
                fanout_count=0,
                evidence_class=None,
            )
        receipt, fanout, action = self._validate_stream(frozen_request, stream)
        if receipt.receipt.outcome == _PROCESS_SUCCEEDED:
            state: ModuleExecutionState = (
                "MODULE_REUSED_NONPROMOTABLE"
                if action == _REUSE
                else "MODULE_BUILD_SUCCEEDED_NONPROMOTABLE"
            )
        else:
            state = "MODULE_BUILD_FAILED_NONPROMOTABLE"
        return LeanModuleExecutionStatusV1(
            state=state,
            module=frozen_request.frozen_spec.spec.module,
            request_sha256=frozen_request.request.content_sha256,
            module_receipt_artifact=receipt.artifact,
            fanout_count=len(fanout),
            evidence_class=receipt.receipt.evidence_class,
        )

    def _freeze_observation(
        self,
        frozen_request: FrozenLeanModuleBuildRequestV1,
        observation: RawLeanModuleRunObservationV1,
        *,
        evidence_class: ModuleEvidenceClass,
        required_runtime_kind: str,
        runner_identity: str,
    ) -> FrozenLeanModuleBuildReceiptV1:
        spec = frozen_request.frozen_spec.spec
        runtime = observation.runtime
        image = frozen_request.frozen_spec.image_binding
        if (
            runtime.runtime_kind != required_runtime_kind
            or runtime.oci_repo_digest != image.oci_repo_digest
            or runtime.oci_config_digest != image.oci_config_digest
            or runtime.platform != image.platform
            or runtime.runner_policy_sha256 != image.runner_policy_sha256
            or runtime.command_argv != spec.command_argv
            or runtime.working_directory != spec.working_directory
        ):
            raise LeanModuleBuildError("runner observation differs from the immutable request")
        if runtime.timed_out:
            outcome: ModuleProcessOutcome = "PROCESS_TIMED_OUT"
        elif runtime.exit_code == 0:
            outcome = "PROCESS_SUCCEEDED"
        else:
            outcome = "PROCESS_FAILED"
        success = outcome == _PROCESS_SUCCEEDED
        if success and (
            observation.output_olean is None
            or not observation.output_olean
            or observation.declaration_query is None
            or not observation.declaration_query
        ):
            raise LeanModuleBuildError(
                "successful module process omitted output or declaration query"
            )
        if not success and (
            observation.output_olean is not None or observation.declaration_query is not None
        ):
            raise LeanModuleBuildError("failed module process must not expose accepted outputs")
        stdout = self.artifacts.put_bytes(observation.stdout)
        stderr = self.artifacts.put_bytes(observation.stderr)
        runtime_artifact = self.artifacts.put_bytes(runtime.canonical_bytes())
        output = (
            None
            if observation.output_olean is None
            else self.artifacts.put_bytes(observation.output_olean)
        )
        query = (
            None
            if observation.declaration_query is None
            else self.artifacts.put_bytes(observation.declaration_query)
        )
        if success and (
            query != frozen_request.frozen_spec.expected_query.artifact
            or self.artifacts.get_bytes(query)
            != frozen_request.frozen_spec.expected_query.manifest.canonical_bytes()
        ):
            raise LeanModuleBuildError("module declaration query differs from the locked manifest")
        receipt = LeanModuleBuildReceiptV1(
            request_sha256=frozen_request.request.content_sha256,
            request_artifact=frozen_request.artifact,
            spec_sha256=spec.content_sha256,
            module=spec.module,
            runtime_observation_sha256=runtime.content_sha256,
            runtime_observation_artifact=runtime_artifact,
            stdout_artifact=stdout,
            stderr_artifact=stderr,
            output_olean_artifact=output,
            declaration_query_artifact=query,
            outcome=outcome,
            evidence_class=evidence_class,
            runner_identity=runner_identity,
            gateway_attestation_class=NO_TRUSTED_GATEWAY_ATTESTATION,
            gateway_attestation_artifact=None,
        )
        artifact = self.artifacts.put_bytes(receipt.canonical_bytes())
        return FrozenLeanModuleBuildReceiptV1(
            receipt=receipt,
            artifact=artifact,
            request=frozen_request,
            runtime=runtime,
        )

    def _derive_fanout(
        self,
        current_request: FrozenLeanModuleBuildRequestV1,
        successful_receipt: FrozenLeanModuleBuildReceiptV1,
    ) -> tuple[FrozenLeanDeclarationFanoutRecordV1, ...]:
        receipt = successful_receipt.receipt
        if (
            receipt.outcome != _PROCESS_SUCCEEDED
            or receipt.output_olean_artifact is None
            or receipt.declaration_query_artifact is None
        ):
            raise LeanModuleBuildError("declaration fanout requires a successful module receipt")
        self._verify_receipt(successful_receipt)
        expected = current_request.frozen_spec.expected_query
        if receipt.declaration_query_artifact != expected.artifact:
            raise LeanModuleBuildError("module receipt query differs from current locked query")
        fixture = current_request.frozen_spec.worker.fixture
        execution_nodes = current_request.frozen_spec.worker.execution.bundle.nodes_by_id
        records: list[FrozenLeanDeclarationFanoutRecordV1] = []
        for query_record in expected.manifest.records:
            declaration = fixture.declarations_by_id.get(query_record.node_id)
            execution = execution_nodes.get(query_record.node_id)
            if (
                declaration is None
                or execution is None
                or declaration.module != expected.manifest.module
                or declaration.declaration != query_record.declaration
            ):
                raise LeanModuleBuildError(
                    "query record cannot be projected to the execution graph"
                )
            record = LeanDeclarationFanoutRecordV1(
                current_request_sha256=current_request.request.content_sha256,
                current_request_artifact=current_request.artifact,
                module_receipt_sha256=receipt.content_sha256,
                module_receipt_artifact=successful_receipt.artifact,
                module=declaration.module,
                node_id=declaration.node_id,
                declaration=declaration.declaration,
                planned_action=execution.action,
                elaborated_type_sha256=query_record.elaborated_type_sha256,
                axioms=query_record.axioms,
                output_olean_artifact=receipt.output_olean_artifact,
                declaration_query_artifact=receipt.declaration_query_artifact,
                evidence_class=receipt.evidence_class,
            )
            artifact = self.artifacts.put_bytes(record.canonical_bytes())
            records.append(
                FrozenLeanDeclarationFanoutRecordV1(
                    record=record,
                    artifact=artifact,
                )
            )
        if len(records) != len(expected.manifest.records):
            raise LeanModuleBuildError("module declaration fanout is partial")
        return tuple(records)

    def _append_terminal_stream(
        self,
        frozen_request: FrozenLeanModuleBuildRequestV1,
        *,
        receipt: FrozenLeanModuleBuildReceiptV1,
        fanout: tuple[FrozenLeanDeclarationFanoutRecordV1, ...],
        idempotency_key: str,
    ) -> tuple[StoredEvent, ...]:
        action = frozen_request.frozen_spec.spec.action
        success = receipt.receipt.outcome == _PROCESS_SUCCEEDED
        if success != bool(fanout):
            raise LeanModuleBuildError(
                "module terminal stream fanout does not match process outcome"
            )
        event_payload: JsonObject = {
            "schema_version": MODULE_EVENT_SCHEMA,
            "bundle_id": frozen_request.lease.job_id,
            "request_sha256": frozen_request.request.content_sha256,
            "request_artifact": _artifact_document(frozen_request.artifact),
            "spec_sha256": frozen_request.frozen_spec.spec.content_sha256,
            "module": frozen_request.frozen_spec.spec.module,
            "action": action,
            "outcome": receipt.receipt.outcome,
            "receipt_sha256": receipt.receipt.content_sha256,
            "receipt_artifact": _artifact_document(receipt.artifact),
            "evidence_class": receipt.receipt.evidence_class,
            "promotion_eligible": False,
            "kernel_acceptance_eligible": False,
            "fanout_count": len(fanout),
            "lease_holder_id": frozen_request.lease.holder_id,
            "fencing_token": frozen_request.lease.fencing_token,
        }
        new_events: list[NewEvent] = [
            NewEvent(
                (
                    "t7_module.reused_nonpromotable"
                    if action == _REUSE
                    else (
                        "t7_module.build_succeeded_nonpromotable"
                        if success
                        else "t7_module.build_failed_nonpromotable"
                    )
                ),
                payload=event_payload,
            )
        ]
        for record in fanout:
            payload: JsonObject = {
                "schema_version": MODULE_FANOUT_EVENT_SCHEMA,
                "bundle_id": frozen_request.lease.job_id,
                "request_sha256": frozen_request.request.content_sha256,
                "request_artifact": _artifact_document(frozen_request.artifact),
                "module_receipt_sha256": receipt.receipt.content_sha256,
                "module_receipt_artifact": _artifact_document(receipt.artifact),
                "node_id": record.record.node_id,
                "fanout_record_sha256": record.record.content_sha256,
                "fanout_record_artifact": _artifact_document(record.artifact),
                "evidence_class": receipt.receipt.evidence_class,
                "promotion_eligible": False,
                "kernel_acceptance_eligible": False,
                "lease_holder_id": frozen_request.lease.holder_id,
                "fencing_token": frozen_request.lease.fencing_token,
            }
            new_events.append(NewEvent("t7_module.declaration_projected", payload=payload))
        idempotency = Idempotency(
            scope="t7_lean_module_terminal_commit",
            key=idempotency_key,
            request_hash=request_hash(
                {
                    "request_sha256": frozen_request.request.content_sha256,
                    "lease": {
                        "job_id": frozen_request.lease.job_id,
                        "holder_id": frozen_request.lease.holder_id,
                        "fencing_token": frozen_request.lease.fencing_token,
                    },
                    "receipt_sha256": receipt.receipt.content_sha256,
                    "fanout_sha256": [item.record.content_sha256 for item in fanout],
                }
            ),
        )
        replay = self.events.lookup_idempotency(idempotency)
        if replay is not None:
            expected_count = 1 + len(fanout)
            if len(replay) != expected_count:
                raise LeanModuleBuildError("module idempotency replay has incomplete fanout")
            return tuple(replay)
        stored = self.events.append_fenced(
            MODULE_EVENT_ENTITY_TYPE,
            self._entity_id(frozen_request),
            task_id=frozen_request.lease.job_id,
            lease=frozen_request.lease,
            expected_sequence=0,
            events=tuple(new_events),
            idempotency=idempotency,
        )
        return tuple(stored)

    def _verify_spec(self, frozen: FrozenLeanModuleBuildSpecV1) -> None:
        verify_frozen_lean_module_build_spec(frozen, self.artifacts)
        self.artifacts.verify(frozen.artifact)
        if self.artifacts.get_bytes(frozen.artifact) != frozen.spec.canonical_bytes():
            raise LeanModuleBuildError("module build spec artifact changed")
        verify_frozen_real_lean_worker(frozen.worker, self.artifacts)
        expected_tree = freeze_module_source_tree(
            frozen.worker,
            frozen.spec.module,
            self.artifacts,
        )
        if (
            expected_tree.tree.canonical_bytes() != frozen.source_tree.tree.canonical_bytes()
            or expected_tree.artifact != frozen.source_tree.artifact
            or frozen.spec.source_tree_sha256 != frozen.source_tree.tree.content_sha256
            or frozen.spec.source_tree_artifact != frozen.source_tree.artifact
        ):
            raise LeanModuleBuildError("module source tree differs from the frozen worker")
        for reference in (
            frozen.spec.worker_input_artifact,
            frozen.spec.execution_bundle_artifact,
            frozen.spec.changed_source_witness_artifact,
            frozen.spec.rebuild_plan_artifact,
            frozen.spec.lake_manifest_artifact,
            frozen.spec.image_binding_artifact,
            frozen.spec.expected_query_artifact,
            frozen.image_binding.runner_policy_artifact,
            frozen.image_binding.image_verification_artifact,
        ):
            self.artifacts.verify(reference)
        if (
            frozen.spec.worker_input_sha256 != frozen.worker.bundle.content_sha256
            or frozen.spec.worker_input_artifact != frozen.worker.artifact
            or frozen.spec.execution_bundle_sha256 != frozen.worker.execution.bundle.content_sha256
            or frozen.spec.execution_bundle_artifact != frozen.worker.execution.artifact
            or frozen.spec.changed_source_witness_sha256
            != frozen.worker.changed_source_witness.witness.content_sha256
            or frozen.spec.changed_source_witness_artifact
            != frozen.worker.changed_source_witness.artifact
            or frozen.spec.rebuild_plan_sha256 != frozen.worker.rebuild_plan.content_sha256
            or frozen.spec.rebuild_plan_artifact
            != frozen.worker.execution.bundle.rebuild_plan_artifact
            or frozen.spec.image_binding_sha256 != frozen.image_binding.content_sha256
            or frozen.spec.image_binding_artifact != frozen.image_binding_artifact
            or self.artifacts.get_bytes(frozen.image_binding_artifact)
            != frozen.image_binding.canonical_bytes()
            or frozen.spec.expected_query_sha256 != frozen.expected_query.manifest.content_sha256
            or frozen.spec.expected_query_artifact != frozen.expected_query.artifact
            or self.artifacts.get_bytes(frozen.expected_query.artifact)
            != frozen.expected_query.manifest.canonical_bytes()
        ):
            raise LeanModuleBuildError("module spec nested artifact binding changed")
        _verify_query_against_fixture(
            frozen.worker.fixture,
            frozen.expected_query.manifest,
        )
        expected_imports = frozen.worker.fixture.modules_by_name[frozen.spec.module].imports
        if (
            tuple(item.request.frozen_spec.spec.module for item in frozen.dependencies)
            != expected_imports
        ):
            raise LeanModuleBuildError("module spec dependencies drifted")
        expected_dependency_bindings = tuple(
            LeanDependencyModuleReceiptV1(
                module=item.request.frozen_spec.spec.module,
                request_sha256=item.receipt.request.request.content_sha256,
                request_artifact=item.receipt.request.artifact,
                receipt_sha256=item.receipt.receipt.content_sha256,
                receipt_artifact=item.receipt.artifact,
                output_olean_artifact=cast(
                    ArtifactRef,
                    item.receipt.receipt.output_olean_artifact,
                ),
            )
            for item in frozen.dependencies
        )
        if frozen.spec.dependency_receipts != expected_dependency_bindings:
            raise LeanModuleBuildError("module spec dependency receipt bindings changed")
        for dependency in frozen.dependencies:
            _verify_dependency_for_spec(
                frozen.worker,
                frozen.image_binding,
                frozen.source_tree,
                dependency,
                self.artifacts,
                lake_manifest_sha256=frozen.spec.lake_manifest_sha256,
            )
        if frozen.spec.action == _REUSE:
            if frozen.baseline is None:
                raise LeanModuleBuildError("module reuse baseline disappeared")
            _verify_baseline_for_spec(
                frozen.worker,
                frozen.image_binding,
                frozen.source_tree,
                frozen.expected_query,
                frozen.baseline,
                self.artifacts,
                lake_manifest_sha256=frozen.spec.lake_manifest_sha256,
            )
            if (
                frozen.spec.baseline_receipt_sha256
                != frozen.baseline.receipt.receipt.content_sha256
                or frozen.spec.baseline_receipt_artifact != frozen.baseline.receipt.artifact
            ):
                raise LeanModuleBuildError("module reuse baseline binding changed")
        elif frozen.baseline is not None:
            raise LeanModuleBuildError("module build acquired a reuse baseline")

    def _verify_request(
        self,
        frozen: FrozenLeanModuleBuildRequestV1,
        *,
        require_current_lease: bool = True,
    ) -> None:
        self._verify_spec(frozen.frozen_spec)
        self.artifacts.verify(frozen.artifact)
        if (
            self.artifacts.get_bytes(frozen.artifact) != frozen.request.canonical_bytes()
            or frozen.request.spec_sha256 != frozen.frozen_spec.spec.content_sha256
            or frozen.request.spec_artifact != frozen.frozen_spec.artifact
            or frozen.request.lease_job_id != frozen.frozen_spec.spec.job_id
            or frozen.request.lease_job_id != frozen.lease.job_id
            or frozen.request.lease_holder_id != frozen.lease.holder_id
            or frozen.request.fencing_token != frozen.lease.fencing_token
        ):
            raise LeanModuleBuildError("module request artifact binding changed")
        if require_current_lease:
            self.leases.assert_current(frozen.lease)

    def _assert_prerequisites_committed(
        self,
        frozen_spec: FrozenLeanModuleBuildSpecV1,
    ) -> None:
        for dependency in frozen_spec.dependencies:
            self._verify_committed(dependency)
        if frozen_spec.baseline is not None:
            self._verify_committed(frozen_spec.baseline)

    def _verify_committed(
        self,
        committed: CommittedLeanModuleBuildV1,
    ) -> None:
        self._verify_request(committed.request, require_current_lease=False)
        stream = self.events.read_stream(
            MODULE_EVENT_ENTITY_TYPE,
            self._entity_id(committed.request),
        )
        receipt, fanout, _ = self._validate_stream(committed.request, stream)
        if (
            receipt.artifact != committed.receipt.artifact
            or tuple(item.artifact for item in fanout)
            != tuple(item.artifact for item in committed.fanout)
            or not stream
            or stream[0].event_id != committed.receipt_event.event_id
            or stream[0].global_position != committed.receipt_event.global_position
        ):
            raise LeanModuleBuildError("committed module receipt is not durable")

    def _verify_receipt(
        self,
        frozen: FrozenLeanModuleBuildReceiptV1,
    ) -> None:
        verify_frozen_lean_module_build_receipt(frozen, self.artifacts)

    def _validate_stream(
        self,
        frozen_request: FrozenLeanModuleBuildRequestV1,
        stream: Sequence[StoredEvent],
    ) -> tuple[
        FrozenLeanModuleBuildReceiptV1,
        tuple[FrozenLeanDeclarationFanoutRecordV1, ...],
        ModuleAction,
    ]:
        if not stream:
            raise LeanModuleBuildError("module terminal stream is absent")
        first = stream[0]
        payload = first.payload
        spec = frozen_request.frozen_spec.spec
        if (
            set(payload) != _EVENT_FIELDS
            or payload.get("schema_version") != MODULE_EVENT_SCHEMA
            or payload.get("bundle_id") != frozen_request.lease.job_id
            or payload.get("request_sha256") != frozen_request.request.content_sha256
            or payload.get("spec_sha256") != spec.content_sha256
            or payload.get("module") != spec.module
            or payload.get("action") != spec.action
            or payload.get("promotion_eligible") is not False
            or payload.get("kernel_acceptance_eligible") is not False
            or payload.get("lease_holder_id") != frozen_request.lease.holder_id
            or payload.get("fencing_token") != frozen_request.lease.fencing_token
        ):
            raise LeanModuleBuildError("module terminal event is inconsistent")
        request_artifact = _artifact_reference(
            payload.get("request_artifact"),
            label="module event request",
        )
        receipt_artifact = _artifact_reference(
            payload.get("receipt_artifact"),
            label="module event receipt",
        )
        if (
            request_artifact != frozen_request.artifact
            or payload.get("receipt_sha256") != receipt_artifact.digest
        ):
            raise LeanModuleBuildError("module terminal event artifact changed")
        receipt_request = (
            frozen_request
            if spec.action == _BUILD
            else cast(
                CommittedLeanModuleBuildV1,
                frozen_request.frozen_spec.baseline,
            ).request
        )
        receipt = _load_frozen_receipt(
            receipt_artifact,
            receipt_request,
            self.artifacts,
        )
        self._verify_receipt(receipt)
        if (
            payload.get("outcome") != receipt.receipt.outcome
            or payload.get("evidence_class") != receipt.receipt.evidence_class
        ):
            raise LeanModuleBuildError("module terminal receipt metadata changed")
        success = receipt.receipt.outcome == _PROCESS_SUCCEEDED
        fanout_count = payload.get("fanout_count")
        expected_count = len(frozen_request.frozen_spec.expected_query.manifest.records)
        if (
            type(fanout_count) is not int
            or fanout_count < 0
            or (success and fanout_count != expected_count)
            or (not success and fanout_count != 0)
            or len(stream) != 1 + fanout_count
        ):
            raise LeanModuleBuildError("module terminal stream has partial fanout")
        expected_fanout = self._derive_fanout(frozen_request, receipt) if success else ()
        observed: list[FrozenLeanDeclarationFanoutRecordV1] = []
        for event, expected in zip(
            stream[1:],
            expected_fanout,
            strict=True,
        ):
            event_payload = event.payload
            if (
                event.event_type != "t7_module.declaration_projected"
                or set(event_payload) != _FANOUT_EVENT_FIELDS
                or event_payload.get("schema_version") != MODULE_FANOUT_EVENT_SCHEMA
                or event_payload.get("bundle_id") != frozen_request.lease.job_id
                or event_payload.get("request_sha256") != frozen_request.request.content_sha256
                or event_payload.get("module_receipt_sha256") != receipt.receipt.content_sha256
                or event_payload.get("node_id") != expected.record.node_id
                or event_payload.get("fanout_record_sha256") != expected.record.content_sha256
                or event_payload.get("evidence_class") != receipt.receipt.evidence_class
                or event_payload.get("promotion_eligible") is not False
                or event_payload.get("kernel_acceptance_eligible") is not False
                or event_payload.get("lease_holder_id") != frozen_request.lease.holder_id
                or event_payload.get("fencing_token") != frozen_request.lease.fencing_token
            ):
                raise LeanModuleBuildError("module fanout event is inconsistent")
            if (
                _artifact_reference(
                    event_payload.get("request_artifact"),
                    label="fanout request",
                )
                != frozen_request.artifact
                or _artifact_reference(
                    event_payload.get("module_receipt_artifact"),
                    label="fanout module receipt",
                )
                != receipt.artifact
                or _artifact_reference(
                    event_payload.get("fanout_record_artifact"),
                    label="fanout record",
                )
                != expected.artifact
            ):
                raise LeanModuleBuildError("module fanout artifact binding changed")
            self.artifacts.verify(expected.artifact)
            if self.artifacts.get_bytes(expected.artifact) != expected.record.canonical_bytes():
                raise LeanModuleBuildError("declaration fanout artifact changed")
            observed.append(expected)
        expected_event_type = (
            "t7_module.reused_nonpromotable"
            if spec.action == _REUSE
            else (
                "t7_module.build_succeeded_nonpromotable"
                if success
                else "t7_module.build_failed_nonpromotable"
            )
        )
        if first.event_type != expected_event_type:
            raise LeanModuleBuildError("module terminal event type changed")
        return receipt, tuple(observed), spec.action

    @staticmethod
    def _entity_id(
        frozen_request: FrozenLeanModuleBuildRequestV1,
    ) -> str:
        return frozen_request.frozen_spec.spec.content_sha256


def operator_local_module_runner_preflight(
    *,
    oci_repo_digest: str,
    runner_policy_image_path: str,
    artifacts: ArtifactStore,
    runner_identity: str,
    timeout_seconds: float = 300.0,
    run_command: CommandRunner | None = None,
) -> OperatorLocalModuleRunnerCapabilityV1:
    """Verify T6 image identity, platform, and image-owned policy bytes.

    The default path invokes the existing ``library_substrate_image.py verify``
    command.  On Windows that command delegates to the locked WSL distribution.
    The returned capability remains operator-local and cannot be promoted.
    """

    if (
        not _is_oci_repo_digest(oci_repo_digest)
        or not _safe_absolute_posix_path(runner_policy_image_path)
        or _SAFE_NAME.fullmatch(runner_identity) is None
        or timeout_seconds <= 0
    ):
        raise LeanModuleBuildError("operator module preflight input is invalid")
    command = run_command or _run_bytes
    script = (
        Path(__file__).resolve().parents[1] / "Library" / "scripts" / "library_substrate_image.py"
    )
    verified = command(
        (
            sys.executable,
            str(script),
            "verify",
            "--image",
            oci_repo_digest,
        ),
        timeout_seconds,
    )
    if verified.returncode != 0:
        raise LeanModuleBuildError("T6 library-substrate verification failed closed")
    verification = _load_unique_json_object(
        verified.stdout,
        label="T6 image verification",
    )
    if (
        verification.get("schema_version") != "autolean.library-substrate-image-verification.v1"
        or verification.get("image") != oci_repo_digest
    ):
        raise LeanModuleBuildError("T6 image verification returned another image")
    image_id = verification.get("image_id")
    if not isinstance(image_id, str) or _DIGEST.fullmatch(image_id) is None:
        raise LeanModuleBuildError("T6 image verification omitted config digest")
    docker_prefix: tuple[str, ...] = (
        ("wsl.exe", "-d", "Ubuntu-24.04", "--") if os.name == "nt" else ()
    )
    inspect = command(
        (
            *docker_prefix,
            "docker",
            "image",
            "inspect",
            oci_repo_digest,
            "--format",
            "{{json .Os}} {{json .Architecture}} {{json .Variant}}",
        ),
        min(timeout_seconds, 60.0),
    )
    if inspect.returncode != 0:
        raise LeanModuleBuildError("OCI image platform inspection failed")
    platform_values = _parse_docker_inspect_words(inspect.stdout)
    platform = OciPlatformV1(
        os=platform_values[0],
        architecture=platform_values[1],
        variant=platform_values[2] or None,
    )
    version = command(
        (
            *docker_prefix,
            "docker",
            "version",
            "--format",
            "{{json .Server.Version}}",
        ),
        min(timeout_seconds, 30.0),
    )
    if version.returncode != 0:
        raise LeanModuleBuildError("OCI runtime version inspection failed")
    try:
        engine_version_raw = json.loads(version.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LeanModuleBuildError("OCI runtime version output is invalid") from error
    if not isinstance(engine_version_raw, str) or _SAFE_NAME.fullmatch(engine_version_raw) is None:
        raise LeanModuleBuildError("OCI runtime version is invalid")
    engine_version = engine_version_raw
    policy = command(
        (
            *docker_prefix,
            "docker",
            "run",
            "--rm",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            oci_repo_digest,
            "/bin/cat",
            runner_policy_image_path,
        ),
        min(timeout_seconds, 60.0),
    )
    if policy.returncode != 0 or not policy.stdout:
        raise LeanModuleBuildError("runner policy is not readable from the exact OCI image")
    policy_artifact = artifacts.put_bytes(policy.stdout)
    verification_artifact = artifacts.put_bytes(_canonical_bytes(verification))
    image_binding = LeanModuleImageBindingV1(
        oci_repo_digest=oci_repo_digest,
        oci_config_digest=image_id,
        platform=platform,
        runner_policy_image_path=runner_policy_image_path,
        runner_policy_sha256=policy_artifact.digest,
        runner_policy_artifact=policy_artifact,
        image_verification_artifact=verification_artifact,
    )
    preflight_document = {
        "schema_version": OPERATOR_PREFLIGHT_SCHEMA,
        "image_binding_sha256": image_binding.content_sha256,
        "oci_repo_digest": oci_repo_digest,
        "oci_config_digest": image_id,
        "platform": platform.document(),
        "runner_policy_sha256": policy_artifact.digest,
        "runner_policy_image_path": runner_policy_image_path,
        "runtime_engine_version": engine_version,
        "runner_identity": runner_identity,
        "evidence_class": OPERATOR_LOCAL_MODULE_EVIDENCE_CLASS,
        "promotion_eligible": False,
    }
    preflight_artifact = artifacts.put_bytes(_canonical_bytes(preflight_document))
    return OperatorLocalModuleRunnerCapabilityV1(
        image_binding=image_binding,
        preflight_artifact=preflight_artifact,
        runtime_engine_version=engine_version,
        runner_identity=runner_identity,
        _preflight_marker=_OPERATOR_PREFLIGHT_MARKER,
    )


def _verify_dependency_for_spec(
    worker: FrozenRealLeanImmutableWorkerInputV1,
    image_binding: LeanModuleImageBindingV1,
    current_tree: FrozenLeanModuleSourceTreeV1,
    dependency: CommittedLeanModuleBuildV1,
    artifacts: ArtifactStore,
    *,
    lake_manifest_sha256: str,
) -> None:
    receipt = dependency.receipt.receipt
    dependency_spec = dependency.request.frozen_spec.spec
    imported_module = dependency_spec.module
    expected_tree = freeze_module_source_tree(worker, imported_module, artifacts)
    if (
        receipt.outcome != _PROCESS_SUCCEEDED
        or receipt.output_olean_artifact is None
        or dependency.request.frozen_spec.source_tree.tree.canonical_bytes()
        != expected_tree.tree.canonical_bytes()
        or expected_tree.tree.canonical_bytes()
        != LeanModuleSourceTreeV1(
            target_module=imported_module,
            entries=tuple(
                item
                for item in current_tree.tree.entries
                if item.module in {entry.module for entry in expected_tree.tree.entries}
            ),
        ).canonical_bytes()
        or dependency.request.frozen_spec.image_binding.content_sha256
        != image_binding.content_sha256
        or dependency_spec.lean_version != worker.environment.lean_version
        or dependency_spec.mathlib_revision != worker.environment.mathlib_revision
        or dependency_spec.lake_manifest_sha256 != lake_manifest_sha256
    ):
        raise LeanModuleBuildError("dependency module receipt has source or environment drift")
    for reference in (
        dependency.receipt.artifact,
        receipt.output_olean_artifact,
        receipt.declaration_query_artifact,
    ):
        if reference is not None:
            artifacts.verify(reference)


def _verify_baseline_for_spec(
    worker: FrozenRealLeanImmutableWorkerInputV1,
    image_binding: LeanModuleImageBindingV1,
    source_tree: FrozenLeanModuleSourceTreeV1,
    expected_query: FrozenLeanDeclarationQueryManifestV1,
    baseline: CommittedLeanModuleBuildV1,
    artifacts: ArtifactStore,
    *,
    lake_manifest_sha256: str,
) -> None:
    receipt = baseline.receipt.receipt
    baseline_spec = baseline.request.frozen_spec.spec
    if (
        receipt.outcome != _PROCESS_SUCCEEDED
        or receipt.output_olean_artifact is None
        or receipt.declaration_query_artifact is None
        or baseline_spec.module != source_tree.tree.target_module
        or baseline.request.frozen_spec.source_tree.tree.canonical_bytes()
        != source_tree.tree.canonical_bytes()
        or baseline.request.frozen_spec.image_binding.content_sha256 != image_binding.content_sha256
        or baseline_spec.lean_version != worker.environment.lean_version
        or baseline_spec.mathlib_revision != worker.environment.mathlib_revision
        or baseline_spec.lake_manifest_sha256 != lake_manifest_sha256
        or baseline.request.frozen_spec.expected_query.manifest.canonical_bytes()
        != expected_query.manifest.canonical_bytes()
        or receipt.declaration_query_artifact != expected_query.artifact
    ):
        raise LeanModuleBuildError("reuse baseline is not the same source and environment")
    for reference in (
        baseline.receipt.artifact,
        receipt.output_olean_artifact,
        receipt.declaration_query_artifact,
    ):
        artifacts.verify(reference)


def _verify_query_against_fixture(
    fixture: RealLeanProjectDagV1,
    manifest: LeanDeclarationQueryManifestV1,
) -> None:
    expected = tuple(
        item for item in fixture.declaration_topological_order() if item.module == manifest.module
    )
    if tuple(item.node_id for item in manifest.records) != tuple(
        item.node_id for item in expected
    ) or tuple(item.declaration for item in manifest.records) != tuple(
        item.declaration for item in expected
    ):
        raise LeanModuleBuildError("declaration query does not match the locked fixture manifest")


def _load_frozen_receipt(
    reference: ArtifactRef,
    request: FrozenLeanModuleBuildRequestV1,
    artifacts: ArtifactStore,
) -> FrozenLeanModuleBuildReceiptV1:
    artifacts.verify(reference)
    raw_bytes = artifacts.get_bytes(reference)
    raw = _load_unique_json_object(raw_bytes, label="module build receipt")
    expected_fields = {
        "schema_version",
        "request_sha256",
        "request_artifact",
        "spec_sha256",
        "module",
        "runtime_observation_sha256",
        "runtime_observation_artifact",
        "stdout_artifact",
        "stderr_artifact",
        "output_olean_artifact",
        "declaration_query_artifact",
        "outcome",
        "evidence_class",
        "runner_identity",
        "gateway_attestation_class",
        "gateway_attestation_artifact",
        "promotion_eligible",
        "kernel_acceptance_eligible",
    }
    if (
        set(raw) != expected_fields
        or raw.get("schema_version") != MODULE_BUILD_RECEIPT_SCHEMA
        or raw.get("gateway_attestation_artifact") is not None
    ):
        raise LeanModuleBuildError("module receipt artifact shape is invalid")
    runtime_reference = _artifact_reference(
        raw.get("runtime_observation_artifact"),
        label="runtime observation",
    )
    runtime = _load_runtime_observation(runtime_reference, artifacts)
    output_raw = raw.get("output_olean_artifact")
    query_raw = raw.get("declaration_query_artifact")
    outcome = raw.get("outcome")
    evidence = raw.get("evidence_class")
    if outcome not in {
        _PROCESS_SUCCEEDED,
        _PROCESS_FAILED,
        _PROCESS_TIMED_OUT,
    } or evidence not in {
        SYNTHETIC_MODULE_EVIDENCE_CLASS,
        OPERATOR_LOCAL_MODULE_EVIDENCE_CLASS,
    }:
        raise LeanModuleBuildError("module receipt enum is invalid")
    receipt = LeanModuleBuildReceiptV1(
        request_sha256=_required_string(
            raw.get("request_sha256"),
            "receipt request hash",
        ),
        request_artifact=_artifact_reference(
            raw.get("request_artifact"),
            label="receipt request",
        ),
        spec_sha256=_required_string(
            raw.get("spec_sha256"),
            "receipt spec hash",
        ),
        module=_required_string(raw.get("module"), "receipt module"),
        runtime_observation_sha256=_required_string(
            raw.get("runtime_observation_sha256"),
            "runtime observation hash",
        ),
        runtime_observation_artifact=runtime_reference,
        stdout_artifact=_artifact_reference(
            raw.get("stdout_artifact"),
            label="receipt stdout",
        ),
        stderr_artifact=_artifact_reference(
            raw.get("stderr_artifact"),
            label="receipt stderr",
        ),
        output_olean_artifact=(
            None if output_raw is None else _artifact_reference(output_raw, label="receipt OLean")
        ),
        declaration_query_artifact=(
            None if query_raw is None else _artifact_reference(query_raw, label="receipt query")
        ),
        outcome=cast(ModuleProcessOutcome, outcome),
        evidence_class=cast(ModuleEvidenceClass, evidence),
        runner_identity=_required_string(
            raw.get("runner_identity"),
            "receipt runner",
        ),
        gateway_attestation_class=_required_string(
            raw.get("gateway_attestation_class"),
            "gateway attestation class",
        ),
        gateway_attestation_artifact=None,
        promotion_eligible=_required_bool(
            raw.get("promotion_eligible"),
            "receipt promotion eligibility",
        ),
        kernel_acceptance_eligible=_required_bool(
            raw.get("kernel_acceptance_eligible"),
            "receipt kernel acceptance eligibility",
        ),
    )
    if receipt.canonical_bytes() != raw_bytes:
        raise LeanModuleBuildError("module receipt artifact is not canonical")
    return FrozenLeanModuleBuildReceiptV1(
        receipt=receipt,
        artifact=reference,
        request=request,
        runtime=runtime,
    )


def _load_runtime_observation(
    reference: ArtifactRef,
    artifacts: ArtifactStore,
) -> LeanModuleRuntimeObservationV1:
    artifacts.verify(reference)
    raw_bytes = artifacts.get_bytes(reference)
    raw = _load_unique_json_object(raw_bytes, label="runtime observation")
    expected_fields = {
        "schema_version",
        "runtime_kind",
        "runtime_engine",
        "runtime_engine_version",
        "oci_repo_digest",
        "oci_config_digest",
        "platform",
        "runner_policy_sha256",
        "command_argv",
        "working_directory",
        "container_identity",
        "network_mode",
        "root_filesystem_read_only",
        "started_at_utc",
        "finished_at_utc",
        "duration_ms",
        "exit_code",
        "timed_out",
    }
    if (
        set(raw) != expected_fields
        or raw.get("schema_version") != MODULE_RUNTIME_OBSERVATION_SCHEMA
    ):
        raise LeanModuleBuildError("runtime observation artifact shape is invalid")
    platform_raw = raw.get("platform")
    if not isinstance(platform_raw, dict) or set(platform_raw) != {
        "os",
        "architecture",
        "variant",
    }:
        raise LeanModuleBuildError("runtime platform is invalid")
    variant = platform_raw.get("variant")
    if variant is not None and not isinstance(variant, str):
        raise LeanModuleBuildError("runtime platform variant is invalid")
    argv_raw = raw.get("command_argv")
    if not isinstance(argv_raw, list) or any(not isinstance(item, str) for item in argv_raw):
        raise LeanModuleBuildError("runtime command argv is invalid")
    container = raw.get("container_identity")
    exit_code = raw.get("exit_code")
    if container is not None and not isinstance(container, str):
        raise LeanModuleBuildError("runtime container identity is invalid")
    if exit_code is not None and type(exit_code) is not int:
        raise LeanModuleBuildError("runtime exit code is invalid")
    runtime = LeanModuleRuntimeObservationV1(
        runtime_kind=_required_string(
            raw.get("runtime_kind"),
            "runtime kind",
        ),
        runtime_engine=_required_string(
            raw.get("runtime_engine"),
            "runtime engine",
        ),
        runtime_engine_version=_required_string(
            raw.get("runtime_engine_version"),
            "runtime engine version",
        ),
        oci_repo_digest=_required_string(
            raw.get("oci_repo_digest"),
            "runtime OCI RepoDigest",
        ),
        oci_config_digest=_required_string(
            raw.get("oci_config_digest"),
            "runtime OCI config digest",
        ),
        platform=OciPlatformV1(
            os=_required_string(platform_raw.get("os"), "runtime platform OS"),
            architecture=_required_string(
                platform_raw.get("architecture"),
                "runtime platform architecture",
            ),
            variant=variant,
        ),
        runner_policy_sha256=_required_string(
            raw.get("runner_policy_sha256"),
            "runtime runner policy",
        ),
        command_argv=tuple(cast(list[str], argv_raw)),
        working_directory=_required_string(
            raw.get("working_directory"),
            "runtime working directory",
        ),
        container_identity=container,
        network_mode=_required_string(
            raw.get("network_mode"),
            "runtime network mode",
        ),
        root_filesystem_read_only=_required_bool(
            raw.get("root_filesystem_read_only"),
            "runtime read-only root",
        ),
        started_at_utc=_required_string(
            raw.get("started_at_utc"),
            "runtime start",
        ),
        finished_at_utc=_required_string(
            raw.get("finished_at_utc"),
            "runtime finish",
        ),
        duration_ms=_required_int(raw.get("duration_ms"), "runtime duration"),
        exit_code=exit_code,
        timed_out=_required_bool(raw.get("timed_out"), "runtime timeout"),
    )
    if runtime.canonical_bytes() != raw_bytes:
        raise LeanModuleBuildError("runtime observation artifact is not canonical")
    return runtime


def _execute_operator_local_module(
    request: FrozenLeanModuleBuildRequestV1,
    capability: OperatorLocalModuleRunnerCapabilityV1,
) -> RawLeanModuleRunObservationV1:
    """Fail closed until T6 ships the image-owned T7 module wrapper.

    Preflight proves image and policy identity only.  Treating an arbitrary host
    callback as OCI evidence would let a caller self-assert real execution, so the
    operator runner stays disabled until the wrapper path and output protocol are
    part of the T6 receipt.
    """

    del request, capability
    raise LeanModuleBuildError("operator-local module execution requires an image-owned T7 wrapper")


def _run_bytes(
    argv: Sequence[str],
    timeout_seconds: float,
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            tuple(argv),
            check=False,
            capture_output=True,
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise LeanModuleBuildError("operator module preflight command failed") from error


def _parse_docker_inspect_words(value: bytes) -> tuple[str, str, str]:
    try:
        text = value.decode("utf-8").strip()
        decoder = json.JSONDecoder()
        items: list[str] = []
        position = 0
        while position < len(text):
            while position < len(text) and text[position].isspace():
                position += 1
            item, position = decoder.raw_decode(text, position)
            if not isinstance(item, str):
                raise ValueError("Docker inspect item is not a string")
            items.append(item)
        if len(items) != 3:
            raise ValueError("Docker inspect field count differs")
        return items[0], items[1], items[2]
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise LeanModuleBuildError("OCI image platform output is invalid") from error


def _load_unique_json_object(data: bytes, *, label: str) -> dict[str, object]:
    def reject_duplicates(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        output: dict[str, object] = {}
        for key, value in pairs:
            if key in output:
                raise ValueError("duplicate JSON key")
            output[key] = value
        return output

    try:
        raw = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise LeanModuleBuildError(f"{label} is not valid JSON") from error
    if not isinstance(raw, dict):
        raise LeanModuleBuildError(f"{label} must be a JSON object")
    return cast(dict[str, object], raw)


def _canonical_bytes(value: object) -> bytes:
    rendered = json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return (rendered + "\n").encode("utf-8")


def _artifact_document(reference: ArtifactRef) -> JsonObject:
    return {
        "algorithm": reference.algorithm,
        "digest": reference.digest,
        "size": reference.size,
    }


def _artifact_reference(value: object, *, label: str) -> ArtifactRef:
    if not isinstance(value, dict) or set(value) != {
        "algorithm",
        "digest",
        "size",
    }:
        raise LeanModuleBuildError(f"{label} artifact reference is invalid")
    algorithm = value.get("algorithm")
    digest = value.get("digest")
    size = value.get("size")
    if not isinstance(algorithm, str) or not isinstance(digest, str) or type(size) is not int:
        raise LeanModuleBuildError(f"{label} artifact reference is invalid")
    try:
        return ArtifactRef(algorithm=algorithm, digest=digest, size=size)
    except ValueError as error:
        raise LeanModuleBuildError(f"{label} artifact reference is invalid") from error


def _check_frozen(reference: ArtifactRef, value: bytes, label: str) -> None:
    if reference.digest != hashlib.sha256(value).hexdigest() or reference.size != len(value):
        raise LeanModuleBuildError(f"{label} artifact does not bind its bytes")


def _required_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise LeanModuleBuildError(f"{label} is invalid")
    return value


def _required_bool(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise LeanModuleBuildError(f"{label} is invalid")
    return value


def _required_int(value: object, label: str) -> int:
    if type(value) is not int:
        raise LeanModuleBuildError(f"{label} is invalid")
    return value


def _parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise LeanModuleBuildError("runtime timestamp is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise LeanModuleBuildError("runtime timestamp must be UTC")
    return parsed


def _safe_relative_file(value: str) -> bool:
    candidate = PurePosixPath(value)
    return (
        bool(value)
        and "\\" not in value
        and not candidate.is_absolute()
        and bool(candidate.parts)
        and all(part not in {"", ".", ".."} for part in candidate.parts)
    )


def _safe_absolute_posix_path(value: str) -> bool:
    candidate = PurePosixPath(value)
    return (
        bool(value)
        and "\\" not in value
        and candidate.is_absolute()
        and all(part not in {"", ".", ".."} for part in candidate.parts)
    )


def _safe_argv(value: tuple[str, ...]) -> bool:
    return (
        bool(value)
        and _safe_absolute_posix_path(value[0])
        and all(item and "\x00" not in item and "\r" not in item for item in value)
    )


def _is_oci_repo_digest(value: str) -> bool:
    if value.count("@") != 1:
        return False
    repository, digest = value.split("@", maxsplit=1)
    if _DIGEST.fullmatch(digest) is None or not repository or repository != repository.lower():
        return False
    parts = repository.split("/")
    if any(not part for part in parts):
        return False
    path_parts = parts
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        host = parts[0].split(":", maxsplit=1)[0]
        if _OCI_HOST.fullmatch(host) is None:
            return False
        path_parts = parts[1:]
    return bool(path_parts) and all(
        _OCI_COMPONENT.fullmatch(part) is not None for part in path_parts
    )
