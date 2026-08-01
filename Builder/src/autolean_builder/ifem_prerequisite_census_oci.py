"""Receipt-bound OCI execution for the frozen iFEM prerequisite census.

This module collects declaration metadata only.  A completed worker run remains
``Partial`` discovery evidence: it cannot classify a mathematical mapping,
freeze a Builder statement, or hand a task to Prover.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Final, Literal, cast

from autolean_contracts import canonical_json_bytes
from autolean_contracts.base import ContractModel
from pydantic import Field, model_validator

from .ifem_prerequisite_census import (
    DEFAULT_LANE_MANIFEST_PATH,
    DEFAULT_LIBRARY_ROOT,
    DEFAULT_PLAN_PATH,
    IFEMPrerequisiteCensusError,
    IFEMPrerequisiteCensusPlanV1,
    IFEMPrerequisiteCensusResultV1,
    IFEMPrerequisiteClassificationV1,
    IFEMQueryExecutionStateV1,
    IFEMQueryObservationV1,
    completed_unreviewed_result,
    load_ifem_prerequisite_census_plan,
    normalize_query_observation,
    validate_plan_bindings,
    validate_result_against_plan,
    write_model_once,
)

ROOT = Path(__file__).resolve().parents[3]
WORKER_ROOT = ROOT / "Prover" / "worker"

PARENT_IMAGE: Final = (
    "autolean/mathlib-worker@sha256:"
    "3237192cf627a05367c75d46e61ec9034fefe43a4fd0c06139e38c80358648d6"
)
BASE_IMAGE_ID: Final = "sha256:6c54c3600b2572ddcabae024a3a8b6c533c3defa6d4bda31c90408cb4c61f0ab"
BASE_IMAGE: Final = BASE_IMAGE_ID
PROTOCOL: Final = "autolean.ifem-prerequisite-census-query.v1"
RECEIPT_SCHEMA: Final = "autolean.ifem-prerequisite-census-worker-build-receipt.v1"
DOCKERFILE_NAME: Final = "Dockerfile.ifem-prerequisite-census-query"
HELPER_NAME: Final = "AutoleanIFEMPrerequisiteCensusQuery.lean"
WRAPPER_NAME: Final = "autolean-ifem-prerequisite-census-query"
BUILD_INPUTS: Final = (DOCKERFILE_NAME, HELPER_NAME, WRAPPER_NAME)

_SHA256 = r"^[0-9a-f]{64}$"
_CHILD_IMAGE = re.compile(r"^sha256:[0-9a-f]{64}$")
_RUN_MEMORY_LIMIT = "4g"
_RUN_PIDS_LIMIT = 128
_RUN_TMPFS = "/tmp:rw,noexec,nosuid,nodev,size=64m"
_LABEL_PREFIX = "org.autolean.ifem.census."


class IFEMPrerequisiteCensusOCIError(IFEMPrerequisiteCensusError):
    """The census worker recipe, receipt, image, or isolated execution drifted."""


class IFEMPrerequisiteCensusWorkerBuildReceiptV1(ContractModel):
    schema_version: Literal["autolean.ifem-prerequisite-census-worker-build-receipt.v1"] = (
        RECEIPT_SCHEMA
    )
    evidence_state: Literal["Partial"] = "Partial"
    plan_content_sha256: str = Field(pattern=_SHA256)
    parent_image: Literal[
        "autolean/mathlib-worker@sha256:3237192cf627a05367c75d46e61ec9034fefe43a4fd0c06139e38c80358648d6"
    ] = PARENT_IMAGE
    base_image: Literal[
        "sha256:6c54c3600b2572ddcabae024a3a8b6c533c3defa6d4bda31c90408cb4c61f0ab"
    ] = BASE_IMAGE
    base_image_id: Literal[
        "sha256:6c54c3600b2572ddcabae024a3a8b6c533c3defa6d4bda31c90408cb4c61f0ab"
    ] = BASE_IMAGE_ID
    child_image: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    staged_context_sha256: str = Field(pattern=_SHA256)
    dockerfile_sha256: str = Field(pattern=_SHA256)
    helper_sha256: str = Field(pattern=_SHA256)
    wrapper_sha256: str = Field(pattern=_SHA256)
    lean_toolchain: str = Field(min_length=1)
    mathlib_revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    lake_manifest_sha256: str = Field(pattern=_SHA256)
    docker_builder: Literal["classic"] = "classic"
    docker_engine_version: str = Field(pattern=r"^[0-9][0-9A-Za-z.+~-]*$")
    builder_freeze: Literal["forbidden"] = "forbidden"
    prover_handoff: Literal["forbidden"] = "forbidden"
    semantic_classification: Literal["not_authorized"] = "not_authorized"
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_content_hash(self) -> IFEMPrerequisiteCensusWorkerBuildReceiptV1:
        if self.content_sha256 != self.computed_content_sha256():
            raise ValueError("iFEM census worker receipt content hash does not match")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(
            dict[str, object],
            self.model_dump(mode="json", exclude={"content_sha256"}),
        )

    def computed_content_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.content_payload())).hexdigest()


class IFEMPrerequisiteCensusOCIExecutionEnvelopeV1(ContractModel):
    schema_version: Literal["autolean.ifem-prerequisite-census-oci-execution-envelope.v1"] = (
        "autolean.ifem-prerequisite-census-oci-execution-envelope.v1"
    )
    evidence_state: Literal["Partial"] = "Partial"
    worker_receipt_content_sha256: str = Field(pattern=_SHA256)
    child_image: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    query_argv_sha256: str = Field(pattern=_SHA256)
    raw_stdout_sha256: str = Field(pattern=_SHA256)
    observation_content_sha256: str = Field(pattern=_SHA256)
    result_content_sha256: str = Field(pattern=_SHA256)
    builder_freeze: Literal["forbidden"] = "forbidden"
    prover_handoff: Literal["forbidden"] = "forbidden"
    semantic_classification: Literal["not_authorized"] = "not_authorized"
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_content_hash(self) -> IFEMPrerequisiteCensusOCIExecutionEnvelopeV1:
        payload = self.model_dump(mode="json", exclude={"content_sha256"})
        expected = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
        if self.content_sha256 != expected:
            raise ValueError("iFEM census execution envelope content hash does not match")
        return self


def _sha256_path(path: Path, *, label: str) -> str:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not path.is_file() or metadata.st_size <= 0:
            raise IFEMPrerequisiteCensusOCIError(f"{label} is not a real non-empty file")
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise IFEMPrerequisiteCensusOCIError(f"cannot read {label}") from error


def worker_asset_hashes(worker_root: Path = WORKER_ROOT) -> dict[str, str]:
    return {
        "dockerfile_sha256": _sha256_path(worker_root / DOCKERFILE_NAME, label="worker Dockerfile"),
        "helper_sha256": _sha256_path(worker_root / HELPER_NAME, label="worker helper"),
        "wrapper_sha256": _sha256_path(worker_root / WRAPPER_NAME, label="worker wrapper"),
    }


def _staged_context_sha256(stage: Path) -> str:
    digest = hashlib.sha256()
    for name in BUILD_INPUTS:
        path = stage / name
        digest.update(name.encode("ascii"))
        digest.update(b"\x00")
        digest.update(path.read_bytes())
        digest.update(b"\x00")
    return digest.hexdigest()


def _run_docker(
    argv: Sequence[str],
    *,
    capture_output: bool = False,
    environment: dict[str, str] | None = None,
    timeout: int = 1800,
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            list(argv),
            check=False,
            capture_output=capture_output,
            text=True,
            encoding="utf-8",
            errors="strict",
            env={**os.environ, **(environment or {})},
            stdin=subprocess.DEVNULL,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError) as error:
        raise IFEMPrerequisiteCensusOCIError("iFEM census OCI command failed") from error
    if completed.returncode != 0:
        diagnostic = (completed.stderr or "")[:4096].replace("\x00", "")
        raise IFEMPrerequisiteCensusOCIError(
            f"iFEM census OCI command returned {completed.returncode}: {diagnostic}"
        )
    return completed


def _docker_engine_version() -> str:
    completed = _run_docker(
        ("docker", "version", "--format", "{{.Server.Version}}"),
        capture_output=True,
    )
    lines = completed.stdout.splitlines()
    if len(lines) != 1 or re.fullmatch(r"[0-9][0-9A-Za-z.+~-]*", lines[0]) is None:
        raise IFEMPrerequisiteCensusOCIError("Docker Engine version has an invalid shape")
    return lines[0]


def _read_image_id(path: Path) -> str:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not path.is_file() or not 1 <= metadata.st_size <= 256:
            raise IFEMPrerequisiteCensusOCIError("Docker iidfile is not a bounded real file")
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise IFEMPrerequisiteCensusOCIError("cannot read Docker iidfile") from error
    lines = raw.splitlines()
    if len(lines) != 1 or _CHILD_IMAGE.fullmatch(lines[0]) is None:
        raise IFEMPrerequisiteCensusOCIError("Docker iidfile lacks one exact image ID")
    return lines[0]


def _inspect_image(image: str) -> dict[str, object]:
    completed = _run_docker(("docker", "image", "inspect", image), capture_output=True)
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise IFEMPrerequisiteCensusOCIError("census image inspect is not JSON") from error
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
        raise IFEMPrerequisiteCensusOCIError("census image inspect has an invalid shape")
    return cast(dict[str, object], payload[0])


def _verify_base_environment(
    plan: IFEMPrerequisiteCensusPlanV1,
    inspected: dict[str, object],
) -> None:
    if inspected.get("Id") != BASE_IMAGE_ID:
        raise IFEMPrerequisiteCensusOCIError("fixed P2-07 census base image identity drifted")
    config = inspected.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    if (
        not isinstance(labels, dict)
        or labels.get("org.autolean.ifem.parent-image") != PARENT_IMAGE
        or labels.get("org.autolean.ifem.profile-protocol")
        != "autolean.ifem-pinned-profile-query.v1"
        or labels.get("org.autolean.mathlib.revision") != plan.environment.mathlib_revision
        or labels.get("org.autolean.mathlib.lake-manifest.sha256")
        != plan.environment.lake_manifest_sha256
    ):
        raise IFEMPrerequisiteCensusOCIError(
            "fixed P2-07 census base environment differs from the frozen plan"
        )


def _expected_labels(
    plan: IFEMPrerequisiteCensusPlanV1,
    assets: dict[str, str],
) -> dict[str, str]:
    return {
        f"{_LABEL_PREFIX}protocol": PROTOCOL,
        f"{_LABEL_PREFIX}plan-sha256": plan.content_sha256,
        f"{_LABEL_PREFIX}dockerfile-sha256": assets["dockerfile_sha256"],
        f"{_LABEL_PREFIX}helper-sha256": assets["helper_sha256"],
        f"{_LABEL_PREFIX}wrapper-sha256": assets["wrapper_sha256"],
        f"{_LABEL_PREFIX}lean-toolchain": plan.environment.lean_toolchain,
        f"{_LABEL_PREFIX}mathlib-revision": plan.environment.mathlib_revision,
        f"{_LABEL_PREFIX}lake-manifest-sha256": plan.environment.lake_manifest_sha256,
        f"{_LABEL_PREFIX}base-image-id": BASE_IMAGE_ID,
    }


def _docker_build_command(
    plan: IFEMPrerequisiteCensusPlanV1,
    assets: dict[str, str],
    *,
    stage: Path,
    iidfile: Path,
) -> tuple[str, ...]:
    return (
        "docker",
        "build",
        "--network=none",
        "--pull=false",
        "--iidfile",
        str(iidfile),
        "--file",
        str(stage / DOCKERFILE_NAME),
        "--build-arg",
        f"AUTOLEAN_CENSUS_PLAN_SHA256={plan.content_sha256}",
        "--build-arg",
        f"AUTOLEAN_CENSUS_DOCKERFILE_SHA256={assets['dockerfile_sha256']}",
        "--build-arg",
        f"AUTOLEAN_CENSUS_HELPER_SHA256={assets['helper_sha256']}",
        "--build-arg",
        f"AUTOLEAN_CENSUS_WRAPPER_SHA256={assets['wrapper_sha256']}",
        "--build-arg",
        f"AUTOLEAN_CENSUS_LEAN_TOOLCHAIN={plan.environment.lean_toolchain}",
        "--build-arg",
        f"AUTOLEAN_CENSUS_MATHLIB_REVISION={plan.environment.mathlib_revision}",
        "--build-arg",
        f"AUTOLEAN_CENSUS_LAKE_MANIFEST_SHA256={plan.environment.lake_manifest_sha256}",
        "--build-arg",
        f"AUTOLEAN_CENSUS_BASE_IMAGE_ID={BASE_IMAGE_ID}",
        str(stage),
    )


def _verify_image_configuration(
    inspected: dict[str, object],
    *,
    child_image: str,
    labels: dict[str, str],
) -> None:
    if inspected.get("Id") != child_image:
        raise IFEMPrerequisiteCensusOCIError("census image digest identity drifted")
    config = inspected.get("Config")
    if not isinstance(config, dict):
        raise IFEMPrerequisiteCensusOCIError("census image has no configuration")
    if config.get("User") != "65532:65532" or config.get("WorkingDir") != "/work":
        raise IFEMPrerequisiteCensusOCIError("census image runtime identity drifted")
    actual_labels = config.get("Labels")
    if not isinstance(actual_labels, dict) or any(
        actual_labels.get(key) != value for key, value in labels.items()
    ):
        raise IFEMPrerequisiteCensusOCIError("census image labels do not bind the worker recipe")


def _verify_base_layer_prefix(inspected: dict[str, object]) -> None:
    base = _inspect_image(BASE_IMAGE_ID)
    base_rootfs = base.get("RootFS")
    child_rootfs = inspected.get("RootFS")
    base_layers = base_rootfs.get("Layers") if isinstance(base_rootfs, dict) else None
    child_layers = child_rootfs.get("Layers") if isinstance(child_rootfs, dict) else None
    if (
        not isinstance(base_layers, list)
        or not base_layers
        or not all(isinstance(layer, str) for layer in base_layers)
        or not isinstance(child_layers, list)
        or child_layers[: len(base_layers)] != base_layers
    ):
        raise IFEMPrerequisiteCensusOCIError("census child image does not extend the fixed base")


def build_worker_image(
    plan: IFEMPrerequisiteCensusPlanV1,
    *,
    worker_root: Path = WORKER_ROOT,
) -> IFEMPrerequisiteCensusWorkerBuildReceiptV1:
    """Build the isolated worker from only its three hash-bound inputs."""

    validate_plan_bindings(plan)
    assets = worker_asset_hashes(worker_root)
    docker_engine_version = _docker_engine_version()
    base = _inspect_image(BASE_IMAGE)
    _verify_base_environment(plan, base)
    with tempfile.TemporaryDirectory(prefix="autolean-ifem-census-worker-") as raw_root:
        stage = Path(raw_root) / "context"
        iidfile = Path(raw_root) / "image.id"
        stage.mkdir()
        for name in BUILD_INPUTS:
            source = worker_root / name
            destination = stage / name
            if source.is_symlink():
                raise IFEMPrerequisiteCensusOCIError("worker build input must not be a symlink")
            shutil.copyfile(source, destination)
            if _sha256_path(source, label=name) != _sha256_path(destination, label=name):
                raise IFEMPrerequisiteCensusOCIError("staged worker input differs from source")
        if tuple(sorted(path.name for path in stage.iterdir())) != tuple(sorted(BUILD_INPUTS)):
            raise IFEMPrerequisiteCensusOCIError("worker build context allowlist drifted")
        staged_context_sha256 = _staged_context_sha256(stage)
        command = _docker_build_command(
            plan,
            assets,
            stage=stage,
            iidfile=iidfile,
        )
        _run_docker(command, environment={"DOCKER_BUILDKIT": "0"})
        child_image = _read_image_id(iidfile)

    inspected = _inspect_image(child_image)
    _verify_image_configuration(
        inspected,
        child_image=child_image,
        labels=_expected_labels(plan, assets),
    )
    _verify_base_layer_prefix(inspected)
    payload: dict[str, object] = {
        "builder_freeze": "forbidden",
        "base_image": BASE_IMAGE,
        "base_image_id": BASE_IMAGE_ID,
        "child_image": child_image,
        "dockerfile_sha256": assets["dockerfile_sha256"],
        "docker_builder": "classic",
        "docker_engine_version": docker_engine_version,
        "evidence_state": "Partial",
        "helper_sha256": assets["helper_sha256"],
        "lake_manifest_sha256": plan.environment.lake_manifest_sha256,
        "lean_toolchain": plan.environment.lean_toolchain,
        "mathlib_revision": plan.environment.mathlib_revision,
        "parent_image": PARENT_IMAGE,
        "plan_content_sha256": plan.content_sha256,
        "prover_handoff": "forbidden",
        "schema_version": RECEIPT_SCHEMA,
        "semantic_classification": "not_authorized",
        "staged_context_sha256": staged_context_sha256,
        "wrapper_sha256": assets["wrapper_sha256"],
    }
    payload["content_sha256"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    receipt = IFEMPrerequisiteCensusWorkerBuildReceiptV1.model_validate(payload)
    verify_worker_image(plan, receipt, worker_root=worker_root)
    return receipt


def verify_worker_image(
    plan: IFEMPrerequisiteCensusPlanV1,
    receipt: IFEMPrerequisiteCensusWorkerBuildReceiptV1,
    *,
    worker_root: Path = WORKER_ROOT,
) -> None:
    validate_plan_bindings(plan)
    assets = worker_asset_hashes(worker_root)
    if (
        receipt.plan_content_sha256 != plan.content_sha256
        or receipt.base_image != BASE_IMAGE
        or receipt.base_image_id != BASE_IMAGE_ID
        or receipt.dockerfile_sha256 != assets["dockerfile_sha256"]
        or receipt.helper_sha256 != assets["helper_sha256"]
        or receipt.wrapper_sha256 != assets["wrapper_sha256"]
        or receipt.lean_toolchain != plan.environment.lean_toolchain
        or receipt.mathlib_revision != plan.environment.mathlib_revision
        or receipt.lake_manifest_sha256 != plan.environment.lake_manifest_sha256
        or receipt.staged_context_sha256 != _staged_context_sha256(worker_root)
    ):
        raise IFEMPrerequisiteCensusOCIError("census worker receipt differs from the frozen plan")
    inspected = _inspect_image(receipt.child_image)
    _verify_image_configuration(
        inspected,
        child_image=receipt.child_image,
        labels=_expected_labels(plan, assets),
    )
    _verify_base_layer_prefix(inspected)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    payload: dict[str, object] = {}
    for key, value in pairs:
        if key in payload:
            raise IFEMPrerequisiteCensusOCIError(f"duplicate JSON key: {key}")
        payload[key] = value
    return payload


def _read_regular_bytes(path: Path, *, label: str, max_bytes: int) -> bytes:
    try:
        metadata = path.lstat()
        if (
            path.is_symlink()
            or not path.is_file()
            or metadata.st_size <= 0
            or metadata.st_size > max_bytes
        ):
            raise IFEMPrerequisiteCensusOCIError(f"{label} is not a bounded physical regular file")
        raw = path.read_bytes()
        after = path.lstat()
    except OSError as error:
        raise IFEMPrerequisiteCensusOCIError(f"cannot read {label}") from error
    if (
        path.is_symlink()
        or not path.is_file()
        or (metadata.st_dev, metadata.st_ino, metadata.st_size)
        != (after.st_dev, after.st_ino, after.st_size)
        or len(raw) != metadata.st_size
    ):
        raise IFEMPrerequisiteCensusOCIError(f"{label} changed while loading")
    return raw


def _load_canonical_model[ModelT: ContractModel](
    path: Path,
    model_type: type[ModelT],
    *,
    label: str,
    max_bytes: int = 16 * 1024 * 1024,
) -> ModelT:
    raw = _read_regular_bytes(path, label=label, max_bytes=max_bytes)
    try:
        payload = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IFEMPrerequisiteCensusOCIError(f"{label} is not strict UTF-8 JSON") from error
    if not isinstance(payload, dict):
        raise IFEMPrerequisiteCensusOCIError(f"{label} must be a JSON object")
    try:
        model = model_type.model_validate(payload)
    except ValueError as error:
        raise IFEMPrerequisiteCensusOCIError(f"{label} is invalid") from error
    if canonical_json_bytes(model) + b"\n" != raw:
        raise IFEMPrerequisiteCensusOCIError(f"{label} is not canonically rendered")
    return model


def _build_execution_envelope(
    plan: IFEMPrerequisiteCensusPlanV1,
    receipt: IFEMPrerequisiteCensusWorkerBuildReceiptV1,
    *,
    raw_stdout: bytes,
    observation: IFEMQueryObservationV1,
    result: IFEMPrerequisiteCensusResultV1,
) -> IFEMPrerequisiteCensusOCIExecutionEnvelopeV1:
    command = docker_query_command(plan, receipt)
    payload: dict[str, object] = {
        "builder_freeze": "forbidden",
        "child_image": receipt.child_image,
        "evidence_state": "Partial",
        "observation_content_sha256": observation.content_sha256,
        "prover_handoff": "forbidden",
        "query_argv_sha256": hashlib.sha256(canonical_json_bytes(list(command))).hexdigest(),
        "raw_stdout_sha256": hashlib.sha256(raw_stdout).hexdigest(),
        "result_content_sha256": result.content_sha256,
        "schema_version": "autolean.ifem-prerequisite-census-oci-execution-envelope.v1",
        "semantic_classification": "not_authorized",
        "worker_receipt_content_sha256": receipt.content_sha256,
    }
    payload["content_sha256"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    return IFEMPrerequisiteCensusOCIExecutionEnvelopeV1.model_validate(payload)


def verify_execution_artifacts(
    plan: IFEMPrerequisiteCensusPlanV1,
    receipt: IFEMPrerequisiteCensusWorkerBuildReceiptV1,
    *,
    plan_path: Path,
    raw_stdout_path: Path,
    observation_path: Path,
    result_path: Path,
    execution_path: Path,
    verify_image: bool = True,
) -> None:
    """Replay one receipt-bound execution and reject any cross-artifact drift.

    Image-backed verification also reruns the exact container command and
    requires byte-identical stdout.  ``verify_image=False`` exists only for
    deterministic unit tests that exercise the artifact-consistency layer.
    """

    validate_plan_bindings(plan)
    if verify_image:
        verify_worker_image(plan, receipt)
    raw_stdout = _read_regular_bytes(
        raw_stdout_path,
        label="census raw stdout",
        max_bytes=16 * 1024 * 1024,
    )
    try:
        raw_text = raw_stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise IFEMPrerequisiteCensusOCIError("census raw stdout is not UTF-8") from error
    lines = raw_text.splitlines()
    if len(lines) != 1 or not raw_stdout.endswith(b"\n"):
        raise IFEMPrerequisiteCensusOCIError("census raw stdout is not one complete JSON line")
    observation = _load_canonical_model(
        observation_path,
        IFEMQueryObservationV1,
        label="census observation",
    )
    result = _load_canonical_model(
        result_path,
        IFEMPrerequisiteCensusResultV1,
        label="census result",
    )
    execution = _load_canonical_model(
        execution_path,
        IFEMPrerequisiteCensusOCIExecutionEnvelopeV1,
        label="census execution envelope",
    )
    expected_observation = normalize_query_observation(
        lines[0],
        plan=plan,
        query_source_sha256=receipt.helper_sha256,
    )
    if observation != expected_observation:
        raise IFEMPrerequisiteCensusOCIError(
            "census observation differs from normalized raw stdout"
        )
    expected_result = completed_unreviewed_result(
        plan,
        observation,
        plan_path=plan_path,
    )
    validate_result_against_plan(result, plan)
    if (
        result != expected_result
        or result.execution_state is not IFEMQueryExecutionStateV1.COMPLETED
        or result.query_source_sha256 != receipt.helper_sha256
        or result.query_observation_sha256 != observation.content_sha256
        or any(
            item.evidence.classification is not IFEMPrerequisiteClassificationV1.UNKNOWN
            or item.evidence.explicit_unknown_reason != "builder_semantic_review_not_recorded"
            for item in result.node_results
        )
    ):
        raise IFEMPrerequisiteCensusOCIError(
            "OCI census result is not the exact completed unknown-only projection"
        )
    expected_execution = _build_execution_envelope(
        plan,
        receipt,
        raw_stdout=raw_stdout,
        observation=observation,
        result=result,
    )
    if execution != expected_execution:
        raise IFEMPrerequisiteCensusOCIError(
            "census execution envelope differs from exact artifact replay"
        )
    if verify_image:
        completed = _run_docker(
            docker_query_command(plan, receipt),
            capture_output=True,
            timeout=600,
        )
        rerun_stdout = completed.stdout.encode("utf-8")
        if completed.stderr or rerun_stdout != raw_stdout:
            raise IFEMPrerequisiteCensusOCIError(
                "census worker rerun does not reproduce retained raw stdout"
            )


def _queries_json(plan: IFEMPrerequisiteCensusPlanV1) -> str:
    payload = [
        {"declarations": list(query.candidate_declarations), "nodeId": query.node_id}
        for query in plan.queries
    ]
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def docker_query_command(
    plan: IFEMPrerequisiteCensusPlanV1,
    receipt: IFEMPrerequisiteCensusWorkerBuildReceiptV1,
) -> tuple[str, ...]:
    if receipt.plan_content_sha256 != plan.content_sha256:
        raise IFEMPrerequisiteCensusOCIError("census worker receipt binds another plan")
    return (
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        str(_RUN_PIDS_LIMIT),
        "--memory",
        _RUN_MEMORY_LIMIT,
        "--tmpfs",
        _RUN_TMPFS,
        "--user",
        "65532:65532",
        "--workdir",
        "/work",
        receipt.child_image,
        "/opt/autolean/bin/autolean-ifem-prerequisite-census-query",
        "--protocol",
        PROTOCOL,
        "--plan-content-sha256",
        plan.content_sha256,
        "--lean-toolchain",
        plan.environment.lean_toolchain,
        "--mathlib-revision",
        plan.environment.mathlib_revision,
        "--lake-manifest-sha256",
        plan.environment.lake_manifest_sha256,
        "--queries-json",
        _queries_json(plan),
    )


def run_worker_query(
    plan: IFEMPrerequisiteCensusPlanV1,
    receipt: IFEMPrerequisiteCensusWorkerBuildReceiptV1,
    *,
    plan_path: Path,
) -> tuple[
    bytes,
    IFEMQueryObservationV1,
    IFEMPrerequisiteCensusResultV1,
    IFEMPrerequisiteCensusOCIExecutionEnvelopeV1,
]:
    """Collect exact 21-node metadata; preserve all semantic authority gates."""

    verify_worker_image(plan, receipt)
    command = docker_query_command(plan, receipt)
    completed = _run_docker(
        command,
        capture_output=True,
        timeout=600,
    )
    lines = completed.stdout.splitlines()
    if len(lines) != 1 or completed.stderr:
        raise IFEMPrerequisiteCensusOCIError("census worker output was not one clean JSON line")
    raw_stdout = completed.stdout.encode("utf-8")
    observation = normalize_query_observation(
        lines[0],
        plan=plan,
        query_source_sha256=receipt.helper_sha256,
    )
    result = completed_unreviewed_result(plan, observation, plan_path=plan_path)
    envelope = _build_execution_envelope(
        plan,
        receipt,
        raw_stdout=raw_stdout,
        observation=observation,
        result=result,
    )
    return raw_stdout, observation, result, envelope


def load_worker_receipt(path: Path) -> IFEMPrerequisiteCensusWorkerBuildReceiptV1:
    return _load_canonical_model(
        path,
        IFEMPrerequisiteCensusWorkerBuildReceiptV1,
        label="iFEM census worker receipt",
    )


def _write_bytes_once(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError:
        existing = _read_regular_bytes(
            path,
            label="existing census raw stdout",
            max_bytes=16 * 1024 * 1024,
        )
        if existing != content:
            raise IFEMPrerequisiteCensusOCIError(
                "census raw stdout already exists with different bytes"
            ) from None


def parse_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN_PATH)
    parser.add_argument("--lane-manifest", type=Path, default=DEFAULT_LANE_MANIFEST_PATH)
    parser.add_argument("--library-root", type=Path, default=DEFAULT_LIBRARY_ROOT)
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build", help="build and receipt the isolated worker")
    build.add_argument("--receipt-out", type=Path, required=True)
    verify = subparsers.add_parser("verify", help="verify a worker receipt and local image")
    verify.add_argument("--receipt", type=Path, required=True)
    render = subparsers.add_parser("command", help="print the exact isolated query command")
    render.add_argument("--receipt", type=Path, required=True)
    run = subparsers.add_parser("run", help="run the receipt-bound diagnostic census")
    run.add_argument("--receipt", type=Path, required=True)
    run.add_argument("--raw-out", type=Path, required=True)
    run.add_argument("--observation-out", type=Path, required=True)
    run.add_argument("--result-out", type=Path, required=True)
    run.add_argument("--execution-out", type=Path, required=True)
    verify_execution = subparsers.add_parser(
        "verify-execution",
        help="cross-check one receipt, raw output, observation, result, and execution envelope",
    )
    verify_execution.add_argument("--receipt", type=Path, required=True)
    verify_execution.add_argument("--raw", type=Path, required=True)
    verify_execution.add_argument("--observation", type=Path, required=True)
    verify_execution.add_argument("--result", type=Path, required=True)
    verify_execution.add_argument("--execution", type=Path, required=True)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    namespace = parse_arguments(arguments)
    plan_path = namespace.plan.resolve()
    plan = load_ifem_prerequisite_census_plan(plan_path)
    validate_plan_bindings(
        plan,
        lane_manifest_path=namespace.lane_manifest.resolve(),
        library_root=namespace.library_root.resolve(),
    )
    if namespace.command == "build":
        receipt = build_worker_image(plan)
        write_model_once(namespace.receipt_out.resolve(), receipt)
        print(receipt.child_image)
        return 0
    receipt = load_worker_receipt(namespace.receipt.resolve())
    if namespace.command == "verify":
        verify_worker_image(plan, receipt)
        print(receipt.content_sha256)
        return 0
    if namespace.command == "command":
        verify_worker_image(plan, receipt)
        print(json.dumps(list(docker_query_command(plan, receipt)), ensure_ascii=True))
        return 0
    if namespace.command == "run":
        raw_stdout, observation, result, execution = run_worker_query(
            plan,
            receipt,
            plan_path=plan_path,
        )
        _write_bytes_once(namespace.raw_out.resolve(), raw_stdout)
        write_model_once(namespace.observation_out.resolve(), observation)
        write_model_once(namespace.result_out.resolve(), result)
        write_model_once(namespace.execution_out.resolve(), execution)
        print(result.content_sha256)
        return 0
    if namespace.command == "verify-execution":
        verify_execution_artifacts(
            plan,
            receipt,
            plan_path=plan_path,
            raw_stdout_path=namespace.raw.resolve(),
            observation_path=namespace.observation.resolve(),
            result_path=namespace.result.resolve(),
            execution_path=namespace.execution.resolve(),
        )
        print(receipt.content_sha256)
        return 0
    raise IFEMPrerequisiteCensusOCIError("unsupported iFEM census OCI command")


if __name__ == "__main__":
    raise SystemExit(main())
