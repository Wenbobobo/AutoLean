"""Credential-free provider readiness evidence for role benchmarks.

Capability probing is intentionally a separate phase from benchmark execution.  A readiness
report grants no model-execution authority and contains no endpoint URL, credential, prompt, or
probe error text.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal, Self

from autolean_contracts import ContractModel, DigestV1, HashKindV1, canonical_json_bytes
from autolean_prover.providers import (
    Capability,
    CapabilityProbe,
    FakeProvider,
    ModelProvider,
    ProviderCapabilities,
    StaticCapabilityProbe,
)
from pydantic import Field, model_validator

from benchmarks.role_benchmark import (
    RoleBenchmarkError,
    RoleBenchmarkExecutorDescriptorV1,
    RoleBenchmarkMatrixV1,
    RoleBenchmarkPreflightBindingV1,
    RoleModelTargetV1,
    scripted_fake_executor_descriptor,
)

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_IDENTIFIER_PATTERN = r"^[a-z0-9][a-z0-9_.:/-]{0,127}$"


class ProviderProbeStatusV1(StrEnum):
    NOT_RUN = "not_run"
    PASSED = "passed"
    FAILED = "failed"


class ProviderReadinessStatusV1(StrEnum):
    READY = "ready"
    BLOCKED = "blocked"


class ProviderReadinessBlockerV1(StrEnum):
    BINDING_MISSING = "provider_binding_missing_v1"
    BINDING_INVALID = "provider_binding_invalid_v1"
    IDENTITY_MISMATCH = "provider_identity_mismatch_v1"
    CONFIGURATION_MISMATCH = "provider_configuration_mismatch_v1"
    DECLARED_CAPABILITY_MISSING = "declared_capability_missing_v1"
    PROBE_FAILED = "provider_probe_failed_v1"
    PROBE_INVALID = "provider_probe_invalid_v1"
    OBSERVED_CAPABILITY_MISSING = "observed_capability_missing_v1"


class BackendReadinessBlockerV1(StrEnum):
    NON_FAKE_TARGET = "scripted_backend_non_fake_target_v1"
    TARGET_NOT_READY = "provider_target_not_ready_v1"
    EXTERNAL_EXECUTOR_UNAVAILABLE = "external_executor_unavailable_v1"
    EXECUTION_AUTHORIZATION_MISSING = "execution_authorization_missing_v1"
    PRODUCTION_EVALUATOR_MISSING = "production_role_evaluator_missing_v1"


class RoleProviderTargetReadinessV1(ContractModel):
    """One exact model target's declared and independently observed capabilities."""

    schema_version: Literal["autolean.role-provider-target-readiness.v3"] = (
        "autolean.role-provider-target-readiness.v3"
    )
    target: RoleModelTargetV1
    target_hash: str = Field(pattern=_SHA256_PATTERN)
    cell_ids: tuple[str, ...]
    required_capabilities: tuple[Capability, ...]
    declared_capabilities: tuple[Capability, ...] = ()
    observed_capabilities: tuple[Capability, ...] = ()
    probe_status: ProviderProbeStatusV1
    status: ProviderReadinessStatusV1
    blockers: tuple[ProviderReadinessBlockerV1, ...]

    @model_validator(mode="after")
    def validate_consistency(self) -> Self:
        if self.target_hash != hashlib.sha256(canonical_json_bytes(self.target)).hexdigest():
            raise ValueError("readiness target hash does not match its target")
        if not self.cell_ids or tuple(sorted(set(self.cell_ids))) != self.cell_ids:
            raise ValueError("readiness cell IDs must be non-empty, unique, and sorted")
        for values, label in (
            (self.required_capabilities, "required"),
            (self.declared_capabilities, "declared"),
            (self.observed_capabilities, "observed"),
            (self.blockers, "blocker"),
        ):
            if tuple(sorted(set(values), key=str)) != values:
                raise ValueError(f"readiness {label} values must be unique and sorted")
        required = set(self.required_capabilities)
        declared = set(self.declared_capabilities)
        observed = set(self.observed_capabilities)
        blockers = set(self.blockers)
        if self.status is ProviderReadinessStatusV1.READY:
            if (
                self.blockers
                or self.probe_status is not ProviderProbeStatusV1.PASSED
                or not required.issubset(declared)
                or not required.issubset(observed)
            ):
                raise ValueError("a ready provider target must have a successful probe")
        elif not blockers:
            raise ValueError("a blocked provider target must name at least one blocker")
        elif self.probe_status is ProviderProbeStatusV1.NOT_RUN:
            if ProviderReadinessBlockerV1.BINDING_MISSING in blockers:
                if blockers != {ProviderReadinessBlockerV1.BINDING_MISSING} or declared or observed:
                    raise ValueError("a missing provider binding cannot claim capability evidence")
                return self
            if ProviderReadinessBlockerV1.BINDING_INVALID in blockers:
                if blockers != {ProviderReadinessBlockerV1.BINDING_INVALID} or declared or observed:
                    raise ValueError("an invalid provider binding cannot claim capability evidence")
                return self
            invalid = {
                ProviderReadinessBlockerV1.PROBE_FAILED,
                ProviderReadinessBlockerV1.PROBE_INVALID,
                ProviderReadinessBlockerV1.OBSERVED_CAPABILITY_MISSING,
            }
            if observed or blockers & invalid:
                raise ValueError("a not-run provider probe cannot claim observed evidence")
            declared_gap = not required.issubset(declared)
            if (ProviderReadinessBlockerV1.DECLARED_CAPABILITY_MISSING in blockers) != declared_gap:
                raise ValueError("declared capability blockers do not match declared evidence")
        elif self.probe_status is ProviderProbeStatusV1.FAILED:
            allowed = {
                ProviderReadinessBlockerV1.PROBE_FAILED,
                ProviderReadinessBlockerV1.PROBE_INVALID,
            }
            if observed or not blockers.issubset(allowed):
                raise ValueError("a failed provider probe has inconsistent evidence")
        elif (
            blockers != {ProviderReadinessBlockerV1.OBSERVED_CAPABILITY_MISSING}
            or not required.issubset(declared)
            or required.issubset(observed)
        ):
            raise ValueError("a passed blocked probe must expose an observed capability gap")
        return self


class RoleBenchmarkBackendReadinessV1(ContractModel):
    """Execution-backend readiness, distinct from provider capability evidence."""

    schema_version: Literal["autolean.role-backend-readiness.v3"] = (
        "autolean.role-backend-readiness.v3"
    )
    backend: Literal["scripted_fake", "authorized_external"]
    status: ProviderReadinessStatusV1
    blockers: tuple[BackendReadinessBlockerV1, ...]

    @model_validator(mode="after")
    def validate_consistency(self) -> Self:
        if tuple(sorted(set(self.blockers), key=str)) != self.blockers:
            raise ValueError("backend blockers must be unique and sorted")
        if self.status is ProviderReadinessStatusV1.READY and self.blockers:
            raise ValueError("a ready backend cannot have blockers")
        if self.status is ProviderReadinessStatusV1.BLOCKED and not self.blockers:
            raise ValueError("a blocked backend must name at least one blocker")
        return self


class RoleBenchmarkReadinessReportV1(ContractModel):
    """Machine-readable preflight evidence; explicitly not an execution authorization."""

    schema_version: Literal["autolean.role-benchmark-readiness.v3"] = (
        "autolean.role-benchmark-readiness.v3"
    )
    matrix_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    matrix_revision: str = Field(min_length=1, max_length=128)
    matrix_hash: str = Field(pattern=_SHA256_PATTERN)
    authority_granted: Literal[False] = False
    targets: tuple[RoleProviderTargetReadinessV1, ...]
    backends: tuple[RoleBenchmarkBackendReadinessV1, ...]

    @model_validator(mode="after")
    def validate_index(self) -> Self:
        target_hashes = tuple(item.target_hash for item in self.targets)
        if not target_hashes or tuple(sorted(set(target_hashes))) != target_hashes:
            raise ValueError("readiness targets must be non-empty, unique, and sorted")
        backend_names = tuple(item.backend for item in self.backends)
        if backend_names != ("authorized_external", "scripted_fake"):
            raise ValueError("readiness report must contain both backends in canonical order")
        external = self.backends[0]
        required_external_blockers = {
            BackendReadinessBlockerV1.EXECUTION_AUTHORIZATION_MISSING,
            BackendReadinessBlockerV1.EXTERNAL_EXECUTOR_UNAVAILABLE,
            BackendReadinessBlockerV1.PRODUCTION_EVALUATOR_MISSING,
        }
        if (
            external.status is not ProviderReadinessStatusV1.BLOCKED
            or set(external.blockers) != required_external_blockers
        ):
            raise ValueError("V3 external benchmark execution must remain explicitly blocked")
        scripted = self.backends[1]
        expected_scripted_blockers: set[BackendReadinessBlockerV1] = set()
        if any(item.target.provider_id != "fake" for item in self.targets):
            expected_scripted_blockers.add(BackendReadinessBlockerV1.NON_FAKE_TARGET)
        if any(item.status is not ProviderReadinessStatusV1.READY for item in self.targets):
            expected_scripted_blockers.add(BackendReadinessBlockerV1.TARGET_NOT_READY)
        expected_status = (
            ProviderReadinessStatusV1.BLOCKED
            if expected_scripted_blockers
            else ProviderReadinessStatusV1.READY
        )
        if (
            scripted.status is not expected_status
            or set(scripted.blockers) != expected_scripted_blockers
        ):
            raise ValueError("scripted backend readiness is inconsistent with provider targets")
        return self

    def canonical_json_bytes(self) -> bytes:
        return canonical_json_bytes(self) + b"\n"

    def content_hash(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self)).hexdigest()


@dataclass(frozen=True, slots=True)
class RoleProviderProbeBinding:
    """Operator-supplied provider and probe bound to one exact matrix target."""

    target: RoleModelTargetV1
    provider: ModelProvider
    probe: CapabilityProbe


def _target_hash(target: RoleModelTargetV1) -> str:
    return hashlib.sha256(canonical_json_bytes(target)).hexdigest()


def _required_capabilities(
    matrix: RoleBenchmarkMatrixV1,
    target: RoleModelTargetV1,
) -> tuple[Capability, ...]:
    required = {
        capability
        for cell in matrix.cells
        if cell.model == target
        for capability in cell.required_capabilities
    }
    return tuple(sorted(required, key=str))


def _blocked_target(
    *,
    target: RoleModelTargetV1,
    cell_ids: tuple[str, ...],
    required: tuple[Capability, ...],
    declared: tuple[Capability, ...] = (),
    observed: tuple[Capability, ...] = (),
    probe_status: ProviderProbeStatusV1 = ProviderProbeStatusV1.NOT_RUN,
    blockers: Iterable[ProviderReadinessBlockerV1],
) -> RoleProviderTargetReadinessV1:
    return RoleProviderTargetReadinessV1(
        target=target,
        target_hash=_target_hash(target),
        cell_ids=cell_ids,
        required_capabilities=required,
        declared_capabilities=tuple(sorted(set(declared), key=str)),
        observed_capabilities=tuple(sorted(set(observed), key=str)),
        probe_status=probe_status,
        status=ProviderReadinessStatusV1.BLOCKED,
        blockers=tuple(sorted(set(blockers), key=str)),
    )


def assess_role_provider_readiness(
    matrix: RoleBenchmarkMatrixV1,
    *,
    bindings: Iterable[RoleProviderProbeBinding],
) -> RoleBenchmarkReadinessReportV1:
    """Probe exact targets without executing a benchmark trial or granting authority."""

    binding_by_hash: dict[str, RoleProviderProbeBinding] = {}
    for probe_binding in bindings:
        target_hash = _target_hash(probe_binding.target)
        if target_hash in binding_by_hash:
            raise RoleBenchmarkError("provider probe bindings contain a duplicate target")
        binding_by_hash[target_hash] = probe_binding

    targets_by_hash = {_target_hash(cell.model): cell.model for cell in matrix.cells}
    readiness: list[RoleProviderTargetReadinessV1] = []
    for target_hash, target in sorted(targets_by_hash.items()):
        required = _required_capabilities(matrix, target)
        cell_ids = tuple(sorted(cell.cell_id for cell in matrix.cells if cell.model == target))
        selected_binding = binding_by_hash.get(target_hash)
        if selected_binding is None:
            readiness.append(
                _blocked_target(
                    target=target,
                    cell_ids=cell_ids,
                    required=required,
                    blockers=(ProviderReadinessBlockerV1.BINDING_MISSING,),
                )
            )
            continue

        blockers: set[ProviderReadinessBlockerV1] = set()
        try:
            provider_id = selected_binding.provider.provider_id
            model_id = selected_binding.provider.model_id
            configuration_candidate: object = selected_binding.provider.configuration_hash
            declared_candidate: object = selected_binding.provider.capabilities
        except Exception:
            readiness.append(
                _blocked_target(
                    target=target,
                    cell_ids=cell_ids,
                    required=required,
                    blockers=(ProviderReadinessBlockerV1.BINDING_INVALID,),
                )
            )
            continue
        if not isinstance(
            configuration_candidate,
            DigestV1,
        ) or not isinstance(declared_candidate, ProviderCapabilities):
            readiness.append(
                _blocked_target(
                    target=target,
                    cell_ids=cell_ids,
                    required=required,
                    blockers=(ProviderReadinessBlockerV1.BINDING_INVALID,),
                )
            )
            continue
        configuration_hash = configuration_candidate
        declared_capabilities = declared_candidate
        declared = tuple(sorted(declared_capabilities.values, key=str))
        if provider_id != target.provider_id or model_id != target.model_id:
            blockers.add(ProviderReadinessBlockerV1.IDENTITY_MISMATCH)
        if (
            configuration_hash.kind is not HashKindV1.CONFIG
            or configuration_hash.value != target.provider_configuration_hash
        ):
            blockers.add(ProviderReadinessBlockerV1.CONFIGURATION_MISMATCH)
        if not set(required).issubset(declared_capabilities.values):
            blockers.add(ProviderReadinessBlockerV1.DECLARED_CAPABILITY_MISSING)
        if blockers:
            readiness.append(
                _blocked_target(
                    target=target,
                    cell_ids=cell_ids,
                    required=required,
                    declared=declared,
                    blockers=blockers,
                )
            )
            continue

        try:
            observed_candidate: object = selected_binding.probe.probe(selected_binding.provider)
        except Exception:
            readiness.append(
                _blocked_target(
                    target=target,
                    cell_ids=cell_ids,
                    required=required,
                    declared=declared,
                    probe_status=ProviderProbeStatusV1.FAILED,
                    blockers=(ProviderReadinessBlockerV1.PROBE_FAILED,),
                )
            )
            continue
        if not isinstance(observed_candidate, ProviderCapabilities):
            readiness.append(
                _blocked_target(
                    target=target,
                    cell_ids=cell_ids,
                    required=required,
                    declared=declared,
                    probe_status=ProviderProbeStatusV1.FAILED,
                    blockers=(ProviderReadinessBlockerV1.PROBE_INVALID,),
                )
            )
            continue
        observed_capabilities = observed_candidate
        observed = tuple(sorted(observed_capabilities.values, key=str))
        if not set(required).issubset(observed_capabilities.values):
            readiness.append(
                _blocked_target(
                    target=target,
                    cell_ids=cell_ids,
                    required=required,
                    declared=declared,
                    observed=observed,
                    probe_status=ProviderProbeStatusV1.PASSED,
                    blockers=(ProviderReadinessBlockerV1.OBSERVED_CAPABILITY_MISSING,),
                )
            )
            continue
        readiness.append(
            RoleProviderTargetReadinessV1(
                target=target,
                target_hash=target_hash,
                cell_ids=cell_ids,
                required_capabilities=required,
                declared_capabilities=declared,
                observed_capabilities=observed,
                probe_status=ProviderProbeStatusV1.PASSED,
                status=ProviderReadinessStatusV1.READY,
                blockers=(),
            )
        )

    scripted_blockers: set[BackendReadinessBlockerV1] = set()
    if any(item.target.provider_id != "fake" for item in readiness):
        scripted_blockers.add(BackendReadinessBlockerV1.NON_FAKE_TARGET)
    if any(item.status is not ProviderReadinessStatusV1.READY for item in readiness):
        scripted_blockers.add(BackendReadinessBlockerV1.TARGET_NOT_READY)
    scripted = RoleBenchmarkBackendReadinessV1(
        backend="scripted_fake",
        status=(
            ProviderReadinessStatusV1.BLOCKED
            if scripted_blockers
            else ProviderReadinessStatusV1.READY
        ),
        blockers=tuple(sorted(scripted_blockers, key=str)),
    )
    external = RoleBenchmarkBackendReadinessV1(
        backend="authorized_external",
        status=ProviderReadinessStatusV1.BLOCKED,
        blockers=tuple(
            sorted(
                (
                    BackendReadinessBlockerV1.EXECUTION_AUTHORIZATION_MISSING,
                    BackendReadinessBlockerV1.EXTERNAL_EXECUTOR_UNAVAILABLE,
                    BackendReadinessBlockerV1.PRODUCTION_EVALUATOR_MISSING,
                ),
                key=str,
            )
        ),
    )
    return RoleBenchmarkReadinessReportV1(
        matrix_id=matrix.matrix_id,
        matrix_revision=matrix.matrix_revision,
        matrix_hash=matrix.content_hash(),
        targets=tuple(readiness),
        backends=(external, scripted),
    )


def build_scripted_fake_readiness(
    matrix: RoleBenchmarkMatrixV1,
) -> RoleBenchmarkReadinessReportV1:
    """Build a network-free readiness report for the checked-in scripted backend."""

    targets = {
        _target_hash(cell.model): cell.model
        for cell in matrix.cells
        if cell.model.provider_id == "fake"
    }
    bindings: list[RoleProviderProbeBinding] = []
    for target in targets.values():
        capabilities = ProviderCapabilities(frozenset(_required_capabilities(matrix, target)))
        provider = FakeProvider((), model_id=target.model_id, capabilities=capabilities)
        bindings.append(
            RoleProviderProbeBinding(
                target=target,
                provider=provider,
                probe=StaticCapabilityProbe(capabilities),
            )
        )
    return assess_role_provider_readiness(matrix, bindings=bindings)


def require_scripted_fake_ready(
    matrix: RoleBenchmarkMatrixV1,
    report: RoleBenchmarkReadinessReportV1,
    *,
    executor_descriptor: RoleBenchmarkExecutorDescriptorV1 | None = None,
) -> RoleBenchmarkPreflightBindingV1:
    """Fail closed on stale, partial, blocked, or authority-confused readiness evidence."""

    if (
        report.matrix_id != matrix.matrix_id
        or report.matrix_revision != matrix.matrix_revision
        or report.matrix_hash != matrix.content_hash()
        or report.authority_granted
    ):
        raise RoleBenchmarkError("provider readiness report does not bind the benchmark matrix")
    expected_targets = tuple(sorted({_target_hash(cell.model) for cell in matrix.cells}))
    if tuple(item.target_hash for item in report.targets) != expected_targets:
        raise RoleBenchmarkError("provider readiness report does not cover every matrix target")
    matrix_targets = {_target_hash(cell.model): cell.model for cell in matrix.cells}
    for target_readiness in report.targets:
        expected_target = matrix_targets[target_readiness.target_hash]
        expected_cells = tuple(
            sorted(cell.cell_id for cell in matrix.cells if cell.model == expected_target)
        )
        if (
            target_readiness.target != expected_target
            or target_readiness.cell_ids != expected_cells
            or target_readiness.required_capabilities
            != _required_capabilities(matrix, expected_target)
        ):
            raise RoleBenchmarkError("provider readiness target binding is incomplete")
    scripted = tuple(item for item in report.backends if item.backend == "scripted_fake")
    if (
        len(scripted) != 1
        or scripted[0].status is not ProviderReadinessStatusV1.READY
        or any(item.status is not ProviderReadinessStatusV1.READY for item in report.targets)
    ):
        raise RoleBenchmarkError("scripted fake benchmark backend is not ready")
    external = tuple(item for item in report.backends if item.backend == "authorized_external")
    if (
        len(external) != 1
        or external[0].status is not ProviderReadinessStatusV1.BLOCKED
        or report.authority_granted
    ):
        raise RoleBenchmarkError("external benchmark execution is not fail-closed")
    descriptor = executor_descriptor or scripted_fake_executor_descriptor()
    expected_descriptor = scripted_fake_executor_descriptor()
    if descriptor != expected_descriptor or descriptor.authority_receipt_hash is not None:
        raise RoleBenchmarkError("V3 accepts only the typed scripted-fake executor")
    return RoleBenchmarkPreflightBindingV1(
        matrix_hash=matrix.content_hash(),
        provider_readiness_hash=report.content_hash(),
        executor_descriptor_hash=hashlib.sha256(canonical_json_bytes(descriptor)).hexdigest(),
        execution_class=descriptor.execution_class,
    )


def readiness_json(report: RoleBenchmarkReadinessReportV1) -> str:
    validated = RoleBenchmarkReadinessReportV1.model_validate(report.model_dump(mode="json"))
    return validated.canonical_json_bytes().decode("ascii")


def load_readiness_json(payload: str) -> RoleBenchmarkReadinessReportV1:
    try:
        report = RoleBenchmarkReadinessReportV1.model_validate_json(payload)
    except ValueError as error:
        raise RoleBenchmarkError("invalid role benchmark readiness JSON") from error
    if payload != report.canonical_json_bytes().decode("ascii"):
        raise RoleBenchmarkError("role benchmark readiness JSON is not canonical V3")
    return report
