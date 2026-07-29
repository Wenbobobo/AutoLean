from __future__ import annotations

import hashlib
import json
import os
import pickle
import sqlite3
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from autolean_contracts import (
    AttestationPurposeV1,
    AttestationV1,
    EndpointClassV1,
    HashKindV1,
    HmacAttestationKeyV1,
    HmacAttestationSignerV1,
    HmacAttestationVerifierV1,
    ModelExecutionAuthorizationError,
    ModelExecutionBudgetV1,
    ModelExecutionPricingV1,
    ModelExecutionProviderApprovalV1,
    ModelExecutionProviderBindingV1,
    ModelWorkBundleV2,
    PermissionDecisionV1,
    RightsRecordV1,
    SourceRecordV1,
    canonical_json_bytes,
    digest_text,
    model_work_admission_evidence_identity,
    model_work_admission_payload,
    model_work_rights_binding,
    model_work_source_binding,
    stable_identifier,
)
from autolean_control_plane import (
    ArtifactStore,
    ControlPlane,
    EventStore,
    LeaseStore,
    ModelExecutionAuthorizationService,
)
from autolean_prover.errors import CapabilityError
from autolean_prover.providers import (
    Capability,
    FakeProvider,
    ModelRequest,
    ModelResponse,
    ProviderCapabilities,
    ProviderRegistry,
    StaticCapabilityProbe,
    TokenUsage,
)

from benchmarks.authorized_role_bridge import (
    AuthorizedRoleBridgeError,
    AuthorizedRoleGenerationPolicyV1,
    AuthorizedRolePrivateManifestV1,
    AuthorizedRolePrivateOutputEntryV1,
    AuthorizedRolePrivateReconciliationV1,
    AuthorizedRoleRawOutputStore,
    AuthorizedRoleReconciliationRequired,
    AuthorizedRoleSuiteDefinition,
    PreparedAuthorizedRoleTrial,
    build_locked_calibration_floor_suite,
    execute_authorized_role_trial,
    prepare_authorized_role_trial,
    prepare_locked_floor_trials,
    run_authorized_role_floor_suite,
)
from benchmarks.authorized_role_bridge import (
    TestOnlyHmacPrivateManifestAuthenticator as PrivateManifestHmacFixture,
)
from benchmarks.role_benchmark import (
    BenchmarkRoleV1,
    RoleArtifactRefV1,
    RoleBenchmarkCellV1,
    RoleBenchmarkMatrixV1,
    RoleModelTargetV1,
)

_MODEL_KEY = HmacAttestationKeyV1(
    key_id="authorized-role-test-model-v1",
    secret=b"authorized-role-test-model-secret-material-0001",
    allowed_purposes=frozenset({AttestationPurposeV1.MODEL_EXECUTION}),
)
_ADMISSION_KEY = HmacAttestationKeyV1(
    key_id="authorized-role-test-only-admission-v1",
    secret=b"authorized-role-test-admission-secret-material-0001",
    allowed_purposes=frozenset({AttestationPurposeV1.MODEL_WORK_ADMISSION}),
)
_CAPABILITIES = ProviderCapabilities.of(
    Capability.TEXT_GENERATION,
    Capability.USAGE_ACCOUNTING,
    Capability.REASONING_EFFORT,
)
_GENERATION_POLICY = AuthorizedRoleGenerationPolicyV1(
    reasoning_effort="high",
    timeout_seconds=37,
)
_PRIVATE_ROOT_ENV = "AUTOLEAN_AUTHORIZED_ROLE_TEST_PRIVATE_ROOT"
_PRIVATE_AUTH_SECRET = b"authorized-role-private-test-secret-material-0001"


def _private_authenticator() -> PrivateManifestHmacFixture:
    return PrivateManifestHmacFixture(_PRIVATE_AUTH_SECRET)


class RecordingFakeProvider(FakeProvider):
    def __init__(
        self,
        responses: list[ModelResponse],
        *,
        capabilities: ProviderCapabilities = _CAPABILITIES,
        timeout_seconds: float = 3600.0,
    ) -> None:
        super().__init__(
            responses,
            model_id="role-floor-model",
            capabilities=capabilities,
            timeout_seconds=timeout_seconds,
        )
        self.requests: list[ModelRequest] = []

    def generate(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        return super().generate(request)


class RecordingRawOutputStore(AuthorizedRoleRawOutputStore):
    def __init__(self, root: Path) -> None:
        super().__init__(root, private_authenticator=_private_authenticator())
        self.events: list[str] = []
        self.private_output_hashes: list[str] = []

    def put_response(self, response: ModelResponse) -> str:
        output_hash = super().put_response(response)
        self.private_output_hashes.append(output_hash)
        self.events.append("response")
        return output_hash

    def put_manifest(self, manifest: AuthorizedRolePrivateManifestV1) -> str:
        self.events.append("manifest")
        return super().put_manifest(manifest)


class CrashAfterProviderResponseStore(AuthorizedRoleRawOutputStore):
    def persist_provider_response(
        self,
        state: AuthorizedRolePrivateReconciliationV1,
        response: ModelResponse,
        *,
        elapsed_ms: int,
    ) -> AuthorizedRolePrivateReconciliationV1:
        del state, response, elapsed_ms
        raise RuntimeError("simulated crash after provider response")


class AdvancingClock:
    def __init__(self) -> None:
        self.current = _clock()

    def __call__(self) -> datetime:
        return self.current

    def advance(self, seconds: float) -> None:
        self.current += timedelta(seconds=seconds)


class JitObservingProvider(RecordingFakeProvider):
    def __init__(
        self,
        responses: list[ModelResponse],
        *,
        database: Path,
        clock: AdvancingClock,
    ) -> None:
        super().__init__(responses)
        self._database = database
        self._clock = clock
        self.authorization_counts: list[int] = []

    def generate(self, request: ModelRequest) -> ModelResponse:
        with sqlite3.connect(self._database) as connection:
            count = connection.execute(
                "SELECT COUNT(*) FROM model_execution_authorizations"
            ).fetchone()
        assert count is not None
        self.authorization_counts.append(int(count[0]))
        self._clock.advance(30)
        return super().generate(request)


def _clock() -> datetime:
    return datetime(2026, 1, 1, tzinfo=UTC)


def _target(
    provider: FakeProvider,
    *,
    generation_policy: AuthorizedRoleGenerationPolicyV1 = _GENERATION_POLICY,
) -> RoleModelTargetV1:
    return RoleModelTargetV1(
        provider_id=provider.provider_id,
        model_id=provider.model_id,
        model_revision="role-floor-v1",
        provider_configuration_hash=provider.configuration_hash.value,
        generation_parameters_hash=generation_policy.content_hash(),
    )


def _suite(provider: FakeProvider) -> AuthorizedRoleSuiteDefinition:
    return build_locked_calibration_floor_suite(
        _target(provider),
        generation_policy=_GENERATION_POLICY,
        repetitions=1,
        max_cost_microusd_per_trial=0,
    )


def _service_and_registry(
    tmp_path: Path,
    provider: RecordingFakeProvider,
    *,
    clock: Callable[[], datetime] = _clock,
    max_ttl_seconds: float = 3600,
) -> tuple[
    ModelExecutionAuthorizationService,
    ProviderRegistry,
    ModelExecutionProviderApprovalV1,
]:
    database = tmp_path / "control.db"
    verifier = HmacAttestationVerifierV1(
        {
            _MODEL_KEY.key_id: _MODEL_KEY,
            _ADMISSION_KEY.key_id: _ADMISSION_KEY,
        },
        clock=clock,
    )
    plane = ControlPlane(
        events=EventStore(database, clock=clock),
        leases=LeaseStore(database, clock=clock),
        artifacts=ArtifactStore(tmp_path / "artifacts"),
        attestation_verifier=verifier,
    )
    service = ModelExecutionAuthorizationService(
        control_plane=plane,
        signer=HmacAttestationSignerV1(_MODEL_KEY, clock=clock),
        verifier=verifier,
        admission_verifier=verifier,
        clock=clock,
        max_ttl_seconds=max_ttl_seconds,
    )
    approval = ModelExecutionProviderApprovalV1(
        approval_id=stable_identifier("authorized-role-provider", "fake-floor"),
        binding=ModelExecutionProviderBindingV1(
            registry_name="fake",
            provider_id=provider.provider_id,
            model_id=provider.model_id,
            model_revision="role-floor-v1",
            endpoint_class=EndpointClassV1.LOCAL,
            configuration_hash=provider.configuration_hash,
        ),
        pricing=ModelExecutionPricingV1(),
        approved_by="test-operator",
        approved_at=clock(),
    )
    service.register_operator_approval(approval, idempotency_key="register-role-provider")
    registry = ProviderRegistry(authorization_gate=service)
    registry.register(
        "fake",
        provider=provider,
        probe=StaticCapabilityProbe(provider.capabilities),
        endpoint_class=EndpointClassV1.LOCAL,
        model_revision="role-floor-v1",
    )
    return service, registry, approval


def _budget(
    max_input_tokens: int,
    max_output_tokens: int,
    *,
    attempts: int = 1,
    max_cost_microusd: int = 0,
    extra_total_tokens: int = 0,
) -> ModelExecutionBudgetV1:
    return ModelExecutionBudgetV1(
        max_attempts=attempts,
        max_input_tokens=max_input_tokens,
        max_output_tokens=max_output_tokens,
        max_total_tokens=max_input_tokens + max_output_tokens + extra_total_tokens,
        max_cost_microusd=max_cost_microusd,
    )


def _budgets(suite: AuthorizedRoleSuiteDefinition) -> dict[str, ModelExecutionBudgetV1]:
    return {
        cell.cell_id: _budget(
            cell.budget.max_input_tokens,
            cell.budget.max_output_tokens,
        )
        for cell in suite.matrix.cells
    }


def _admission(
    work: ModelWorkBundleV2,
    *,
    clock: Callable[[], datetime] = _clock,
    ttl_seconds: float = 3600,
) -> AttestationV1:
    return HmacAttestationSignerV1(_ADMISSION_KEY, clock=clock).issue(
        purpose=AttestationPurposeV1.MODEL_WORK_ADMISSION,
        payload=model_work_admission_payload(work),
        evidence_identity=model_work_admission_evidence_identity(work),
        ttl_seconds=ttl_seconds,
    )


def _admissions(
    prepared: tuple[PreparedAuthorizedRoleTrial, ...],
    *,
    clock: Callable[[], datetime] = _clock,
    ttl_seconds: float = 3600,
) -> dict[str, AttestationV1]:
    return {
        item.work_bundle.bundle_id.value: _admission(
            item.work_bundle,
            clock=clock,
            ttl_seconds=ttl_seconds,
        )
        for item in prepared
    }


def _responses(count: int) -> list[ModelResponse]:
    return [
        ModelResponse(
            provider_id="fake",
            model_id="role-floor-model",
            text=json.dumps({"trial": index}, sort_keys=True),
            usage=TokenUsage(input_tokens=10, output_tokens=3),
        )
        for index in range(count)
    ]


def _raw_root(tmp_path: Path, suffix: str) -> Path:
    configured = os.environ.get(_PRIVATE_ROOT_ENV)
    root = Path(configured) if configured else tmp_path
    return root / f"{tmp_path.name}-{suffix}"


def _raw_store(tmp_path: Path, suffix: str) -> AuthorizedRoleRawOutputStore:
    return AuthorizedRoleRawOutputStore(
        _raw_root(tmp_path, suffix),
        private_authenticator=_private_authenticator(),
    )


_AUTHORIZATION_STATE_TABLES = (
    "model_execution_authorizations",
    "model_execution_work_bundles",
    "model_execution_work_idempotency",
    "model_execution_authorization_idempotency",
    "model_execution_authorization_ledger",
    "model_execution_provider_health_ledger",
    "worker_leases",
)


def _authorization_state_counts(database: Path) -> tuple[int, ...]:
    with sqlite3.connect(database) as connection:
        return tuple(
            int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in _AUTHORIZATION_STATE_TABLES
        )


def _private_manifest_fixture(
    store: AuthorizedRoleRawOutputStore,
    *,
    run_id: str,
    marker: str,
) -> AuthorizedRolePrivateManifestV1:
    output_hash = store.put_response(
        ModelResponse(
            provider_id="fake",
            model_id="role-floor-model",
            text=marker,
            usage=TokenUsage(input_tokens=1, output_tokens=1),
        )
    )
    return AuthorizedRolePrivateManifestV1(
        run_id=run_id,
        outputs=tuple(
            AuthorizedRolePrivateOutputEntryV1(
                cell_id=f"cell-{index:02d}",
                case_id=f"case-{index:02d}",
                repetition=1,
                private_reconciliation_handle=(
                    "private_" + hashlib.sha256(f"{marker}:reconcile:{index}".encode()).hexdigest()
                ),
                output_hash=output_hash,
                authorization_hash=hashlib.sha256(
                    f"{marker}:authorization:{index}".encode()
                ).hexdigest(),
                elapsed_ms=1,
                input_tokens=1,
                cached_input_tokens=0,
                output_tokens=1,
            )
            for index in range(10)
        ),
    )


def test_ten_case_suite_privately_retains_raw_outputs_before_public_sidecar(
    tmp_path: Path,
) -> None:
    provider = RecordingFakeProvider(_responses(10))
    suite = _suite(provider)
    service, registry, approval = _service_and_registry(tmp_path, provider)
    raw_store = RecordingRawOutputStore(_raw_root(tmp_path, "suite"))
    prepared = prepare_locked_floor_trials(suite, run_id="authorized-role-run-1")

    public = run_authorized_role_floor_suite(
        suite,
        run_id="authorized-role-run-1",
        authorization_service=service,
        admissions_by_bundle_id=_admissions(prepared),
        registry=registry,
        approval=approval,
        budgets_by_cell=_budgets(suite),
        raw_output_store=raw_store,
    )

    assert len(public.trials) == 10
    assert len(provider.requests) == 10
    assert {item.role.value for item in public.trials} == {role.value for role in BenchmarkRoleV1}
    assert raw_store.events == ["response"] * 10 + ["manifest"]
    assert len(set(raw_store.private_output_hashes)) == 10
    for output_hash in raw_store.private_output_hashes:
        raw_store.verify(output_hash)
    private_manifest_hash = raw_store.resolve_manifest_handle(public.private_manifest_handle)
    raw_store.verify(private_manifest_hash)
    assert public.private_manifest_handle.startswith("private_")
    assert public.private_manifest_handle != private_manifest_hash
    assert public.schema_version == "autolean.authorized-role-suite-sidecar.v2"
    assert public.usage_summary.aggregate_input_tokens_bucket == "1_255"
    assert public.usage_summary.aggregate_output_tokens_bucket == "1_255"
    assert public.usage_summary.aggregate_elapsed_ms_bucket == "under_1s"
    cases = {case.case_id: case for case in suite.matrix.cases}
    for trial, sidecar, request in zip(prepared, public.trials, provider.requests, strict=True):
        oracle = json.dumps(
            cases[trial.context.case_id].expected_output,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        context_json = trial.context.model_dump_json()
        work_json = trial.work_bundle.model_dump_json()
        sidecar_json = sidecar.model_dump_json()
        outbound_text = f"{request.system_prompt}\n{request.prompt}"
        assert oracle not in outbound_text
        assert oracle not in context_json
        assert oracle not in work_json
        assert oracle not in sidecar_json
        assert '"expected_output"' not in outbound_text
        assert '"output_hash"' not in sidecar_json
        assert '"input_tokens"' not in sidecar_json
        assert '"output_tokens"' not in sidecar_json
        assert '"cached_input_tokens"' not in sidecar_json
        assert '"passed"' not in sidecar_json
        assert '"score' not in sidecar_json
        assert sidecar.work_evidence_hash == suite.work_evidence.content_hash()
        assert sidecar.schema_version == "autolean.authorized-role-trial-sidecar.v2"
        assert sidecar.usage_summary.input_tokens_bucket == "1_255"
        assert sidecar.usage_summary.cached_input_tokens_bucket == "zero"
        assert sidecar.usage_summary.output_tokens_bucket == "1_255"
        assert sidecar.usage_summary.elapsed_ms_bucket == "under_1s"
        assert sidecar.production_evaluator is False
        assert sidecar.floor_claim_eligible is False
        assert sidecar.cross_role_aggregation_permitted is False
        assert trial.context.system_prompt not in work_json
        assert trial.context.prompt not in work_json
        assert request.reasoning_effort == _GENERATION_POLICY.reasoning_effort
        assert request.timeout_seconds == _GENERATION_POLICY.timeout_seconds
        assert Capability.REASONING_EFFORT in request.required_capabilities
        assert trial.cell.budget.timeout_ms == _GENERATION_POLICY.timeout_seconds * 1000
        source_projection_json = trial.work_bundle.source.model_dump_json()
        rights_projection_json = trial.work_bundle.rights.model_dump_json()
        for forbidden in (
            "metadata",
            "title",
            "locator",
            "permitted_excerpt",
        ):
            assert forbidden not in source_projection_json
        for forbidden in (
            "attribution",
            "restrictions",
            "reviewed_by",
        ):
            assert forbidden not in rights_projection_json
    with sqlite3.connect(tmp_path / "control.db") as connection:
        control_db_dump = "\n".join(connection.iterdump())
    assert all(
        trial.context.system_prompt not in control_db_dump
        and trial.context.prompt not in control_db_dump
        for trial in prepared
    )
    assert public.production_evaluator is False
    assert public.floor_claim_eligible is False
    assert public.cross_role_aggregation_permitted is False
    assert suite.work_evidence.production_trust_eligible is False
    assert suite.work_evidence.evidence_class == "local_software_root_of_trust_nonpromotable"
    assert suite.work_evidence.generation_policy_hash == _GENERATION_POLICY.content_hash()
    public_json = public.model_dump_json()
    assert "raw_artifact_manifest_hash" not in public_json
    assert private_manifest_hash not in public_json


def test_prompt_replacement_is_denied_before_provider_io_or_public_sidecar(
    tmp_path: Path,
) -> None:
    provider = RecordingFakeProvider(_responses(1))
    suite = _suite(provider)
    service, registry, approval = _service_and_registry(tmp_path, provider)
    cell = suite.matrix.cells[0]
    prepared = prepare_authorized_role_trial(
        suite,
        cell,
        case_id=cell.case_ids[0],
        repetition=1,
        run_id="authorized-role-run-2",
    )
    replaced = PreparedAuthorizedRoleTrial(
        context=prepared.context,
        request=replace(prepared.request, prompt=prepared.request.prompt + "\nREPLACED"),
        work_bundle=prepared.work_bundle,
        cell=prepared.cell,
        generation_policy=prepared.generation_policy,
        work_evidence=prepared.work_evidence,
    )

    with pytest.raises(AuthorizedRoleBridgeError, match="exact locked trial"):
        execute_authorized_role_trial(
            replaced,
            authorization_service=service,
            admission=_admission(prepared.work_bundle),
            registry=registry,
            approval=approval,
            budget=_budgets(suite)[cell.cell_id],
            raw_output_store=_raw_store(tmp_path, "prompt"),
        )
    assert provider.requests == []


def test_suite_rejects_cross_bundle_admission_reuse_before_provider_io(
    tmp_path: Path,
) -> None:
    provider = RecordingFakeProvider(_responses(10))
    suite = _suite(provider)
    service, registry, approval = _service_and_registry(tmp_path, provider)
    prepared = prepare_locked_floor_trials(suite, run_id="authorized-role-run-cross-admission")
    admissions = _admissions(prepared)
    bundle_ids = sorted(admissions)
    rotated = {
        bundle_id: admissions[bundle_ids[(index + 1) % len(bundle_ids)]]
        for index, bundle_id in enumerate(bundle_ids)
    }

    with pytest.raises(
        ModelExecutionAuthorizationError,
        match="does not bind the exact payload",
    ):
        run_authorized_role_floor_suite(
            suite,
            run_id="authorized-role-run-cross-admission",
            authorization_service=service,
            admissions_by_bundle_id=rotated,
            registry=registry,
            approval=approval,
            budgets_by_cell=_budgets(suite),
            raw_output_store=_raw_store(tmp_path, "cross-admission"),
        )
    assert provider.requests == []


def test_invalid_sixth_admission_causes_zero_provider_calls(tmp_path: Path) -> None:
    provider = RecordingFakeProvider(_responses(10))
    suite = _suite(provider)
    service, registry, approval = _service_and_registry(tmp_path, provider)
    prepared = prepare_locked_floor_trials(suite, run_id="authorized-role-run-sixth-admission")
    admissions = _admissions(prepared)
    sixth = prepared[5].work_bundle.bundle_id.value
    valid_sixth = admissions[sixth]
    admissions[sixth] = _admission(prepared[0].work_bundle)
    raw_store = _raw_store(tmp_path, "sixth-admission")
    state_before = _authorization_state_counts(tmp_path / "control.db")

    with pytest.raises(
        ModelExecutionAuthorizationError,
        match="does not bind the exact payload",
    ):
        run_authorized_role_floor_suite(
            suite,
            run_id="authorized-role-run-sixth-admission",
            authorization_service=service,
            admissions_by_bundle_id=admissions,
            registry=registry,
            approval=approval,
            budgets_by_cell=_budgets(suite),
            raw_output_store=raw_store,
        )

    assert provider.requests == []
    assert _authorization_state_counts(tmp_path / "control.db") == state_before

    admissions[sixth] = valid_sixth
    public = run_authorized_role_floor_suite(
        suite,
        run_id="authorized-role-run-sixth-admission",
        authorization_service=service,
        admissions_by_bundle_id=admissions,
        registry=registry,
        approval=approval,
        budgets_by_cell=_budgets(suite),
        raw_output_store=raw_store,
    )
    assert len(public.trials) == 10
    assert len(provider.requests) == 10


def test_suite_rejects_cumulative_admission_expiry_before_any_call_and_retries_cleanly(
    tmp_path: Path,
) -> None:
    clock = AdvancingClock()
    provider = JitObservingProvider(
        _responses(10),
        database=tmp_path / "control.db",
        clock=clock,
    )
    suite = _suite(provider)
    service, registry, approval = _service_and_registry(
        tmp_path,
        provider,
        clock=clock,
    )
    prepared = prepare_locked_floor_trials(
        suite,
        run_id="authorized-role-cumulative-admission",
    )
    private_root = _raw_root(tmp_path, "cumulative-admission")
    raw_store = AuthorizedRoleRawOutputStore(
        private_root,
        private_authenticator=_private_authenticator(),
    )
    private_files_before = tuple(
        sorted(
            path.relative_to(private_root).as_posix()
            for path in private_root.rglob("*")
            if path.is_file()
        )
    )
    state_before = _authorization_state_counts(tmp_path / "control.db")

    # A 200-second parent is enough for any one 67-second trial. Before the
    # cumulative gate, five 30-second calls completed before trial six failed
    # to mint its 67-second authorization under that same parent.
    with pytest.raises(
        ModelExecutionAuthorizationError,
        match="does not cover the required execution window",
    ):
        run_authorized_role_floor_suite(
            suite,
            run_id="authorized-role-cumulative-admission",
            authorization_service=service,
            admissions_by_bundle_id=_admissions(
                prepared,
                clock=clock,
                ttl_seconds=200,
            ),
            registry=registry,
            approval=approval,
            budgets_by_cell=_budgets(suite),
            raw_output_store=raw_store,
        )

    assert provider.requests == []
    assert _authorization_state_counts(tmp_path / "control.db") == state_before
    assert (
        tuple(
            sorted(
                path.relative_to(private_root).as_posix()
                for path in private_root.rglob("*")
                if path.is_file()
            )
        )
        == private_files_before
    )

    public = run_authorized_role_floor_suite(
        suite,
        run_id="authorized-role-cumulative-admission",
        authorization_service=service,
        admissions_by_bundle_id=_admissions(
            prepared,
            clock=clock,
            ttl_seconds=3600,
        ),
        registry=registry,
        approval=approval,
        budgets_by_cell=_budgets(suite),
        raw_output_store=raw_store,
    )
    assert len(public.trials) == 10
    assert len(provider.requests) == 10
    assert provider.authorization_counts == list(range(1, 11))


def test_real_clock_lease_outlives_authorization_and_reaches_provider(tmp_path: Path) -> None:
    def clock() -> datetime:
        return datetime.now(UTC)

    provider = RecordingFakeProvider(_responses(1))
    suite = _suite(provider)
    service, registry, approval = _service_and_registry(
        tmp_path,
        provider,
        clock=clock,
    )
    prepared = prepare_locked_floor_trials(
        suite,
        run_id="authorized-role-real-clock",
    )[0]

    execution = execute_authorized_role_trial(
        prepared,
        authorization_service=service,
        admission=_admission(prepared.work_bundle, clock=clock),
        registry=registry,
        approval=approval,
        budget=_budget(
            prepared.cell.budget.max_input_tokens,
            prepared.cell.budget.max_output_tokens,
        ),
        raw_output_store=_raw_store(tmp_path, "real-clock"),
    )

    assert len(provider.requests) == 1
    assert execution.authorization.expires_at < execution.authorization.lease.expires_at


def test_generation_policy_hash_timeout_and_reasoning_capability_are_frozen() -> None:
    provider = RecordingFakeProvider(_responses(1))
    mismatched = AuthorizedRoleGenerationPolicyV1(
        reasoning_effort="max",
        timeout_seconds=19,
    )
    with pytest.raises(AuthorizedRoleBridgeError, match="generation_parameters_hash"):
        build_locked_calibration_floor_suite(
            _target(provider),
            generation_policy=mismatched,
            repetitions=1,
            max_cost_microusd_per_trial=0,
        )

    suite = _suite(provider)
    assert all(
        cell.model.generation_parameters_hash == _GENERATION_POLICY.content_hash()
        and cell.budget.timeout_ms == 37_000
        and Capability.REASONING_EFFORT in cell.required_capabilities
        for cell in suite.matrix.cells
    )


def test_role_json_contract_is_frozen_without_outbound_oracle_values() -> None:
    policy = AuthorizedRoleGenerationPolicyV1(
        reasoning_effort="high",
        response_format="json_object",
        output_contract="role_json_v1",
        timeout_seconds=37,
    )
    provider = FakeProvider(
        [],
        model_id="role-floor-model",
        capabilities=ProviderCapabilities.of(
            Capability.TEXT_GENERATION,
            Capability.USAGE_ACCOUNTING,
            Capability.REASONING_EFFORT,
            Capability.STRUCTURED_JSON,
        ),
    )
    suite = build_locked_calibration_floor_suite(
        _target(provider, generation_policy=policy),
        generation_policy=policy,
        repetitions=1,
        max_cost_microusd_per_trial=0,
    )
    prepared = prepare_locked_floor_trials(suite, run_id="authorized-role-json-contract-v1")
    expected_outputs = {
        case.case_id: json.dumps(
            case.expected_output,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        for case in suite.matrix.cases
    }

    assert all(
        Capability.STRUCTURED_JSON in cell.required_capabilities for cell in suite.matrix.cells
    )
    assert all(
        "OUTPUT_JSON_CONTRACT_V1" in cell.prompt.system_prompt for cell in suite.matrix.cells
    )
    for trial in prepared:
        outbound = f"{trial.request.system_prompt}\n{trial.request.prompt}"
        assert trial.request.response_format == "json_object"
        assert Capability.STRUCTURED_JSON in trial.request.required_capabilities
        assert expected_outputs[trial.context.case_id] not in outbound
        assert '"expected_output"' not in outbound


def test_role_json_contract_requires_structured_json_response_format() -> None:
    with pytest.raises(ValueError, match="requires response_format"):
        AuthorizedRoleGenerationPolicyV1(output_contract="role_json_v1", timeout_seconds=37)


def test_provider_effective_timeout_must_equal_frozen_policy_before_state_or_io(
    tmp_path: Path,
) -> None:
    provider = RecordingFakeProvider(_responses(10), timeout_seconds=10)
    suite = _suite(provider)
    service, registry, approval = _service_and_registry(tmp_path, provider)
    prepared = prepare_locked_floor_trials(suite, run_id="authorized-role-low-timeout")
    state_before = _authorization_state_counts(tmp_path / "control.db")

    with pytest.raises(
        AuthorizedRoleBridgeError,
        match="effective timeout does not match",
    ):
        run_authorized_role_floor_suite(
            suite,
            run_id="authorized-role-low-timeout",
            authorization_service=service,
            admissions_by_bundle_id=_admissions(prepared),
            registry=registry,
            approval=approval,
            budgets_by_cell=_budgets(suite),
            raw_output_store=_raw_store(tmp_path, "low-timeout"),
        )

    assert provider.requests == []
    assert _authorization_state_counts(tmp_path / "control.db") == state_before


@pytest.mark.parametrize(
    "lifetime_overrides",
    (
        {"authorization_ttl_seconds": 66.0},
        {"lease_ttl_seconds": 66.0},
        {"authorization_ttl_seconds": 67.0, "lease_ttl_seconds": 67.0},
        {"authorization_ttl_seconds": 3601.0},
    ),
)
def test_role_lifetime_window_rejects_short_or_over_cap_before_state(
    tmp_path: Path,
    lifetime_overrides: dict[str, float],
) -> None:
    provider = RecordingFakeProvider(_responses(10))
    suite = _suite(provider)
    service, registry, approval = _service_and_registry(tmp_path, provider)
    prepared = prepare_locked_floor_trials(suite, run_id="authorized-role-bad-lifetime")
    private_root = _raw_root(tmp_path, "bad-lifetime")
    raw_store = AuthorizedRoleRawOutputStore(
        private_root,
        private_authenticator=_private_authenticator(),
    )
    state_before = _authorization_state_counts(tmp_path / "control.db")
    private_files_before = tuple(path for path in private_root.rglob("*") if path.is_file())

    with pytest.raises(AuthorizedRoleBridgeError, match="TTL"):
        run_authorized_role_floor_suite(
            suite,
            run_id="authorized-role-bad-lifetime",
            authorization_service=service,
            admissions_by_bundle_id=_admissions(prepared),
            registry=registry,
            approval=approval,
            budgets_by_cell=_budgets(suite),
            raw_output_store=raw_store,
            **lifetime_overrides,
        )

    assert provider.requests == []
    assert _authorization_state_counts(tmp_path / "control.db") == state_before
    assert tuple(path for path in private_root.rglob("*") if path.is_file()) == private_files_before


def test_configured_authorization_ttl_cap_is_checked_before_state(tmp_path: Path) -> None:
    provider = RecordingFakeProvider(_responses(10))
    suite = _suite(provider)
    service, registry, approval = _service_and_registry(
        tmp_path,
        provider,
        max_ttl_seconds=60,
    )
    prepared = prepare_locked_floor_trials(suite, run_id="authorized-role-configured-cap")
    state_before = _authorization_state_counts(tmp_path / "control.db")

    with pytest.raises(ModelExecutionAuthorizationError, match="exceeds the configured maximum"):
        run_authorized_role_floor_suite(
            suite,
            run_id="authorized-role-configured-cap",
            authorization_service=service,
            admissions_by_bundle_id=_admissions(prepared),
            registry=registry,
            approval=approval,
            budgets_by_cell=_budgets(suite),
            raw_output_store=_raw_store(tmp_path, "configured-cap"),
        )

    assert provider.requests == []
    assert _authorization_state_counts(tmp_path / "control.db") == state_before


def test_suite_issues_each_capability_just_in_time(tmp_path: Path) -> None:
    clock = AdvancingClock()
    provider = JitObservingProvider(
        _responses(10),
        database=tmp_path / "control.db",
        clock=clock,
    )
    suite = _suite(provider)
    service, registry, approval = _service_and_registry(
        tmp_path,
        provider,
        clock=clock,
    )
    prepared = prepare_locked_floor_trials(suite, run_id="authorized-role-jit")

    public = run_authorized_role_floor_suite(
        suite,
        run_id="authorized-role-jit",
        authorization_service=service,
        admissions_by_bundle_id=_admissions(prepared, clock=clock),
        registry=registry,
        approval=approval,
        budgets_by_cell=_budgets(suite),
        raw_output_store=_raw_store(tmp_path, "jit"),
    )

    assert len(public.trials) == 10
    assert provider.authorization_counts == list(range(1, 11))
    assert len(provider.requests) == 10


def test_private_manifest_handle_mapping_is_authenticated_and_key_is_not_persisted(
    tmp_path: Path,
) -> None:
    root = _raw_root(tmp_path, "authenticated-manifest")
    authenticator = _private_authenticator()
    store = AuthorizedRoleRawOutputStore(
        root,
        private_authenticator=authenticator,
    )
    handles = [
        store.put_manifest(
            _private_manifest_fixture(
                store,
                run_id=f"private-manifest-run-{index}",
                marker=f"manifest-{index}",
            )
        )
        for index in range(4)
    ]
    mapping_root = root / "authorized-role-manifest-handles"

    # Replacing A with an otherwise valid B mapping still fails because the MAC envelope binds
    # the opaque handle itself.
    (mapping_root / f"{handles[0]}.json").write_bytes(
        (mapping_root / f"{handles[1]}.json").read_bytes()
    )
    with pytest.raises(AuthorizedRoleReconciliationRequired, match="invalid"):
        store.resolve_manifest_handle(handles[0])

    # Canonical field substitution reaches the MAC check instead of relying on JSON formatting.
    binding_path = mapping_root / f"{handles[1]}.json"
    changed = json.loads(binding_path.read_bytes())
    changed["binding"]["coordinates"][0]["authorization_hash"] = "f" * 64
    binding_path.write_bytes(canonical_json_bytes(changed))
    with pytest.raises(AuthorizedRoleReconciliationRequired, match="authentication failed"):
        store.resolve_manifest_handle(handles[1])

    truncation_path = mapping_root / f"{handles[2]}.json"
    truncation_path.write_bytes(truncation_path.read_bytes()[:17])
    with pytest.raises(AuthorizedRoleReconciliationRequired, match="cannot be reconciled"):
        store.resolve_manifest_handle(handles[2])

    wrong_key_store = AuthorizedRoleRawOutputStore(
        root,
        private_authenticator=PrivateManifestHmacFixture(
            b"different-authorized-role-private-secret-material"
        ),
    )
    with pytest.raises(AuthorizedRoleReconciliationRequired, match="authentication failed"):
        wrong_key_store.resolve_manifest_handle(handles[3])

    with pytest.raises(TypeError, match="private_authenticator"):
        cast(Any, AuthorizedRoleRawOutputStore)(root)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(authenticator)
    assert all(
        _PRIVATE_AUTH_SECRET not in path.read_bytes() for path in root.rglob("*") if path.is_file()
    )


def test_private_run_index_is_authenticated_and_recovers_after_restart(tmp_path: Path) -> None:
    root = _raw_root(tmp_path, "authenticated-run-index")
    authenticator = _private_authenticator()
    store = AuthorizedRoleRawOutputStore(
        root,
        private_authenticator=authenticator,
    )
    run_id = "private-run-index-restart"
    private_handle = store.put_manifest(
        _private_manifest_fixture(
            store,
            run_id=run_id,
            marker="run-index",
        )
    )

    restarted = AuthorizedRoleRawOutputStore(
        root,
        private_authenticator=_private_authenticator(),
    )
    assert restarted.resolve_run_manifest_handle(run_id) == private_handle
    assert restarted.read_authenticated_manifest(private_handle).run_id == run_id

    wrong_key_store = AuthorizedRoleRawOutputStore(
        root,
        private_authenticator=PrivateManifestHmacFixture(
            b"different-authorized-role-private-secret-material"
        ),
    )
    with pytest.raises(AuthorizedRoleReconciliationRequired, match="authentication failed"):
        wrong_key_store.resolve_run_manifest_handle(run_id)

    run_key = hashlib.sha256(run_id.encode("utf-8")).hexdigest()
    run_index_path = root / "authorized-role-run-index" / f"{run_key}.json"
    index_payload = json.loads(run_index_path.read_bytes())
    index_payload["binding"]["manifest_hash"] = "f" * 64
    run_index_path.write_bytes(canonical_json_bytes(index_payload))
    with pytest.raises(AuthorizedRoleReconciliationRequired, match="authentication failed"):
        restarted.resolve_run_manifest_handle(run_id)


def test_reasoning_policy_requires_provider_capability_before_io(tmp_path: Path) -> None:
    capabilities = ProviderCapabilities.of(
        Capability.TEXT_GENERATION,
        Capability.USAGE_ACCOUNTING,
    )
    provider = RecordingFakeProvider(_responses(1), capabilities=capabilities)
    suite = _suite(provider)
    service, registry, approval = _service_and_registry(tmp_path, provider)
    prepared = prepare_authorized_role_trial(
        suite,
        suite.matrix.cells[0],
        case_id=suite.matrix.cells[0].case_ids[0],
        repetition=1,
        run_id="authorized-role-run-reasoning-capability",
    )

    with pytest.raises(CapabilityError, match="reasoning_effort"):
        execute_authorized_role_trial(
            prepared,
            authorization_service=service,
            admission=_admission(prepared.work_bundle),
            registry=registry,
            approval=approval,
            budget=_budgets(suite)[prepared.cell.cell_id],
            raw_output_store=_raw_store(tmp_path, "reasoning-capability"),
        )

    assert provider.requests == []


def test_crash_after_provider_response_requires_private_reconciliation(
    tmp_path: Path,
) -> None:
    provider = RecordingFakeProvider(_responses(1))
    suite = _suite(provider)
    service, registry, approval = _service_and_registry(tmp_path, provider)
    prepared = prepare_authorized_role_trial(
        suite,
        suite.matrix.cells[0],
        case_id=suite.matrix.cells[0].case_ids[0],
        repetition=1,
        run_id="authorized-role-run-private-reconciliation",
    )
    private_root = _raw_root(tmp_path, "private-reconciliation")
    raw_store = CrashAfterProviderResponseStore(
        private_root,
        private_authenticator=_private_authenticator(),
    )

    with pytest.raises(AuthorizedRoleReconciliationRequired, match="private reconciliation"):
        execute_authorized_role_trial(
            prepared,
            authorization_service=service,
            admission=_admission(prepared.work_bundle),
            registry=registry,
            approval=approval,
            budget=_budgets(suite)[prepared.cell.cell_id],
            raw_output_store=raw_store,
        )

    assert len(provider.requests) == 1
    state = raw_store.reconciliation_for_bundle(prepared.work_bundle.bundle_id.value)
    assert state is not None
    assert state.state == "provider_outcome_ambiguous"
    with pytest.raises(AuthorizedRoleReconciliationRequired, match="existing private"):
        raw_store.begin_provider_call(
            bundle_id=prepared.work_bundle.bundle_id.value,
            authorization_hash=state.authorization_hash,
        )
    assert len(provider.requests) == 1


def test_unrelated_allow_source_cannot_launder_locked_case_egress(tmp_path: Path) -> None:
    provider = RecordingFakeProvider(_responses(1))
    suite = _suite(provider)
    unrelated = SourceRecordV1(
        source_id=stable_identifier("authorized-role-source", "unrelated-cc0"),
        work_id="unrelated",
        title="Unrelated permissive source",
        version="1",
        locator="repo://unrelated",
        content_hash=digest_text(HashKindV1.SOURCE_BYTES, "unrelated"),
        spans=tuple(
            span.model_copy(update={"permitted_excerpt": None}) for span in suite.source.spans
        ),
    )
    unrelated_rights = RightsRecordV1(
        rights_id=stable_identifier("authorized-role-rights", "unrelated-cc0"),
        source_id=unrelated.source_id,
        source_license="CC0-1.0",
        overall_decision=PermissionDecisionV1.ALLOW,
        model_egress=PermissionDecisionV1.ALLOW,
        allowed_endpoint_classes=(EndpointClassV1.APPROVED_EXTERNAL,),
        reviewed_by="test-operator",
        reviewed_at=_clock(),
    )
    laundered = replace(suite, source=unrelated, rights=unrelated_rights)

    with pytest.raises(AuthorizedRoleBridgeError, match="exact locked fixture"):
        prepare_authorized_role_trial(
            laundered,
            suite.matrix.cells[0],
            case_id=suite.matrix.cells[0].case_ids[0],
            repetition=1,
            run_id="authorized-role-run-3",
        )

    prepared = prepare_authorized_role_trial(
        suite,
        suite.matrix.cells[0],
        case_id=suite.matrix.cells[0].case_ids[0],
        repetition=1,
        run_id="authorized-role-run-3",
    )
    laundered_bundle = ModelWorkBundleV2.model_validate(
        {
            **prepared.work_bundle.model_dump(mode="json"),
            "source": model_work_source_binding(unrelated).model_dump(mode="json"),
            "rights": model_work_rights_binding(unrelated_rights).model_dump(mode="json"),
        }
    )
    forged = PreparedAuthorizedRoleTrial(
        context=prepared.context,
        request=prepared.request,
        work_bundle=laundered_bundle,
        cell=prepared.cell,
        generation_policy=prepared.generation_policy,
        work_evidence=prepared.work_evidence,
    )
    service, registry, approval = _service_and_registry(tmp_path, provider)
    with pytest.raises(AuthorizedRoleBridgeError, match="exact locked trial"):
        execute_authorized_role_trial(
            forged,
            authorization_service=service,
            admission=_admission(forged.work_bundle),
            registry=registry,
            approval=approval,
            budget=_budgets(suite)[prepared.cell.cell_id],
            raw_output_store=_raw_store(tmp_path, "laundered"),
        )
    assert provider.requests == []


def test_locked_builder_rejects_tools_and_trial_budget_is_one_shot(tmp_path: Path) -> None:
    provider = RecordingFakeProvider(_responses(1))
    suite = _suite(provider)
    cell = suite.matrix.cells[0]
    tool = RoleArtifactRefV1(
        artifact_id=stable_identifier("authorized-role-tool", "forbidden").value,
        revision="1",
        content_hash="a" * 64,
    )
    changed_cell = RoleBenchmarkCellV1.model_validate(
        {
            **cell.model_dump(mode="python"),
            "tools": (tool,),
            "required_capabilities": tuple(
                sorted(
                    {
                        Capability.TEXT_GENERATION,
                        Capability.TOOL_CALLING,
                        Capability.USAGE_ACCOUNTING,
                    },
                    key=str,
                )
            ),
        }
    )
    changed_matrix = RoleBenchmarkMatrixV1.model_validate(
        {
            **suite.matrix.model_dump(mode="python"),
            "cells": (changed_cell, *suite.matrix.cells[1:]),
        }
    )
    with pytest.raises(AuthorizedRoleBridgeError, match="exact locked fixture"):
        prepare_authorized_role_trial(
            replace(suite, matrix=changed_matrix),
            changed_cell,
            case_id=changed_cell.case_ids[0],
            repetition=1,
            run_id="authorized-role-run-4",
        )

    service, registry, approval = _service_and_registry(tmp_path, provider)
    prepared = prepare_authorized_role_trial(
        suite,
        cell,
        case_id=cell.case_ids[0],
        repetition=1,
        run_id="authorized-role-run-5",
    )
    with pytest.raises(AuthorizedRoleBridgeError, match="exactly one attempt"):
        execute_authorized_role_trial(
            prepared,
            authorization_service=service,
            admission=_admission(prepared.work_bundle),
            registry=registry,
            approval=approval,
            budget=_budget(
                cell.budget.max_input_tokens,
                cell.budget.max_output_tokens,
                attempts=2,
            ),
            raw_output_store=_raw_store(tmp_path, "budget"),
        )
    for index, changed_budget in enumerate(
        (
            _budget(
                cell.budget.max_input_tokens + 1,
                cell.budget.max_output_tokens,
            ),
            _budget(
                cell.budget.max_input_tokens,
                cell.budget.max_output_tokens,
                max_cost_microusd=1,
            ),
            _budget(
                cell.budget.max_input_tokens,
                cell.budget.max_output_tokens,
                extra_total_tokens=1,
            ),
        )
    ):
        with pytest.raises(AuthorizedRoleBridgeError, match="exactly match"):
            execute_authorized_role_trial(
                prepared,
                authorization_service=service,
                admission=_admission(prepared.work_bundle),
                registry=registry,
                approval=approval,
                budget=changed_budget,
                raw_output_store=_raw_store(tmp_path, f"changed-budget-{index}"),
            )
    assert provider.requests == []
