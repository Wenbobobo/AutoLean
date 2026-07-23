from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest
from autolean_prover.providers import (
    Capability,
    FakeProvider,
    ModelProvider,
    ProviderCapabilities,
    StaticCapabilityProbe,
)

from benchmarks.provider_readiness import (
    BackendReadinessBlockerV1,
    ProviderProbeStatusV1,
    ProviderReadinessBlockerV1,
    ProviderReadinessStatusV1,
    RoleProviderProbeBinding,
    assess_role_provider_readiness,
    build_scripted_fake_readiness,
    load_readiness_json,
    readiness_json,
    require_scripted_fake_ready,
)
from benchmarks.role_benchmark import (
    RoleBenchmarkError,
    RoleBenchmarkMatrixV1,
    load_fake_fixture,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATH = PROJECT_ROOT / "benchmarks" / "roles" / "fake-smoke.v3.json"


def _matrix() -> RoleBenchmarkMatrixV1:
    return load_fake_fixture(FIXTURE_PATH).matrix


def _provider(*capabilities: Capability) -> FakeProvider:
    return FakeProvider(
        (),
        model_id="fake-model",
        capabilities=ProviderCapabilities.of(*capabilities),
    )


def test_scripted_readiness_is_replayable_and_external_api_is_explicitly_blocked() -> None:
    matrix = _matrix()
    first = build_scripted_fake_readiness(matrix)
    second = build_scripted_fake_readiness(matrix)

    assert readiness_json(first) == readiness_json(second)
    assert first.content_hash() == second.content_hash()
    assert load_readiness_json(readiness_json(first)) == first
    assert first.schema_version == "autolean.role-benchmark-readiness.v3"
    assert all(
        target.schema_version == "autolean.role-provider-target-readiness.v3"
        for target in first.targets
    )
    assert not first.authority_granted
    assert all(item.status is ProviderReadinessStatusV1.READY for item in first.targets)
    external = next(item for item in first.backends if item.backend == "authorized_external")
    assert external.status is ProviderReadinessStatusV1.BLOCKED
    assert set(external.blockers) == {
        BackendReadinessBlockerV1.EXECUTION_AUTHORIZATION_MISSING,
        BackendReadinessBlockerV1.EXTERNAL_EXECUTOR_UNAVAILABLE,
        BackendReadinessBlockerV1.PRODUCTION_EVALUATOR_MISSING,
    }
    preflight = require_scripted_fake_ready(matrix, first)
    assert not preflight.authority_granted
    assert preflight.provider_readiness_hash == first.content_hash()


def test_missing_binding_and_stale_matrix_fail_closed() -> None:
    matrix = _matrix()
    missing = assess_role_provider_readiness(matrix, bindings=())
    assert missing.targets[0].blockers == (ProviderReadinessBlockerV1.BINDING_MISSING,)
    assert missing.targets[0].probe_status is ProviderProbeStatusV1.NOT_RUN
    with pytest.raises(RoleBenchmarkError, match="not ready"):
        require_scripted_fake_ready(matrix, missing)

    stale = matrix.model_copy(update={"sampling_seed": "changed-seed"})
    with pytest.raises(RoleBenchmarkError, match="does not bind"):
        require_scripted_fake_ready(stale, build_scripted_fake_readiness(matrix))

    ready = build_scripted_fake_readiness(matrix)
    incomplete_target = ready.targets[0].model_copy(
        update={"required_capabilities": (Capability.TEXT_GENERATION,)}
    )
    incomplete = ready.model_copy(update={"targets": (incomplete_target,)})
    with pytest.raises(RoleBenchmarkError, match="binding is incomplete"):
        require_scripted_fake_ready(matrix, incomplete)


@dataclass
class _ExplodingProbe:
    marker: str

    def probe(self, _provider: ModelProvider) -> ProviderCapabilities:
        raise RuntimeError(self.marker)


def test_probe_failure_is_sanitized_and_never_executes_a_fallback() -> None:
    matrix = _matrix()
    target = matrix.cells[0].model
    provider = _provider(Capability.TEXT_GENERATION, Capability.USAGE_ACCOUNTING)
    marker = "credential-adjacent-probe-detail"
    report = assess_role_provider_readiness(
        matrix,
        bindings=(
            RoleProviderProbeBinding(
                target=target,
                provider=provider,
                probe=_ExplodingProbe(marker),
            ),
        ),
    )

    assert report.targets[0].blockers == (ProviderReadinessBlockerV1.PROBE_FAILED,)
    assert report.targets[0].probe_status is ProviderProbeStatusV1.FAILED
    assert marker not in readiness_json(report)


def test_declared_or_observed_capability_gaps_block_before_execution() -> None:
    matrix = _matrix()
    target = matrix.cells[0].model
    declared_gap = _provider(Capability.TEXT_GENERATION)
    declared_report = assess_role_provider_readiness(
        matrix,
        bindings=(
            RoleProviderProbeBinding(
                target=target,
                provider=declared_gap,
                probe=StaticCapabilityProbe(declared_gap.capabilities),
            ),
        ),
    )
    assert ProviderReadinessBlockerV1.CONFIGURATION_MISMATCH in declared_report.targets[0].blockers
    assert (
        ProviderReadinessBlockerV1.DECLARED_CAPABILITY_MISSING
        in declared_report.targets[0].blockers
    )
    assert declared_report.targets[0].probe_status is ProviderProbeStatusV1.NOT_RUN

    provider = _provider(Capability.TEXT_GENERATION, Capability.USAGE_ACCOUNTING)
    observed_gap = ProviderCapabilities.of(Capability.TEXT_GENERATION)
    observed_report = assess_role_provider_readiness(
        matrix,
        bindings=(
            RoleProviderProbeBinding(
                target=target,
                provider=provider,
                probe=StaticCapabilityProbe(observed_gap),
            ),
        ),
    )
    assert observed_report.targets[0].blockers == (
        ProviderReadinessBlockerV1.OBSERVED_CAPABILITY_MISSING,
    )
    assert observed_report.targets[0].probe_status is ProviderProbeStatusV1.PASSED


def test_schema_rejects_forged_ready_capabilities_and_external_backend() -> None:
    report = build_scripted_fake_readiness(_matrix())
    payload = report.model_dump(mode="json")
    first_target = payload["targets"][0]
    first_target["declared_capabilities"] = []
    first_target["observed_capabilities"] = []
    with pytest.raises(ValueError, match="successful probe"):
        type(report).model_validate(payload)

    payload = report.model_dump(mode="json")
    external = payload["backends"][0]
    external["status"] = "ready"
    external["blockers"] = []
    with pytest.raises(ValueError, match="external benchmark execution"):
        type(report).model_validate(payload)

    payload = report.model_dump(mode="json")
    first_target = payload["targets"][0]
    first_target["status"] = "blocked"
    first_target["blockers"] = ["observed_capability_missing_v1"]
    with pytest.raises(ValueError, match="passed blocked probe"):
        type(report).model_validate(payload)

    payload = report.model_dump(mode="json")
    scripted = payload["backends"][1]
    scripted["status"] = "blocked"
    scripted["blockers"] = ["provider_target_not_ready_v1"]
    with pytest.raises(ValueError, match="scripted backend readiness"):
        type(report).model_validate(payload)

    missing = assess_role_provider_readiness(_matrix(), bindings=())
    payload = missing.model_dump(mode="json")
    payload["targets"][0]["declared_capabilities"] = ["text_generation"]
    with pytest.raises(ValueError, match="missing provider binding"):
        type(missing).model_validate(payload)


def test_readiness_v1_v2_and_noncanonical_v3_fail_closed() -> None:
    canonical = readiness_json(build_scripted_fake_readiness(_matrix()))
    assert load_readiness_json(canonical)
    with pytest.raises(RoleBenchmarkError, match="not canonical V3"):
        load_readiness_json(canonical.replace(",", ", "))
    for version in ("v1", "v2"):
        payload = canonical.replace(
            "autolean.role-benchmark-readiness.v3",
            f"autolean.role-benchmark-readiness.{version}",
            1,
        )
        with pytest.raises(RoleBenchmarkError, match="invalid role benchmark readiness"):
            load_readiness_json(payload)
