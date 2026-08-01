from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

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
    ModelExecutionAuthorizationV1,
    ModelExecutionBudgetV1,
    ModelExecutionPricingV1,
    ModelExecutionProviderApprovalV1,
    ModelExecutionProviderBindingV1,
    ModelWorkBundleV2,
    SourceRecordV1,
    StableIdentifierV1,
    digest_bytes,
    model_work_admission_evidence_identity,
    model_work_admission_payload,
    stable_identifier,
)
from autolean_control_plane import (
    ArtifactStore,
    ControlPlane,
    DashboardProjection,
    EventStore,
    FixtureHmacIndependentExecutionReceiptAuthenticator,
    IndependentExecutionClassV1,
    IndependentExecutionReceiptV1,
    IndependentExecutionTrustPolicyV1,
    Lease,
    LeaseStore,
    ModelExecutionAuthorizationService,
    TrustedIndependentExecutionVerifierV1,
)
from autolean_prover.errors import ProviderResponseError
from autolean_prover.providers import (
    Capability,
    CapabilityProbe,
    FakeProvider,
    ModelProvider,
    ModelRequest,
    ModelResponse,
    ProviderCapabilities,
    ProviderRegistry,
    StaticCapabilityProbe,
)

from benchmarks.fate import TIER_COUNTS, FateProblemId, Tier
from benchmarks.fate_adapter import (
    FateAdapter,
    FateFixtureLockV1,
    FateFixtureManifestV1,
    FateFixtureTaskV1,
)
from benchmarks.fate_execution import (
    DeterministicFakeFateVerifier,
    FateAttemptAmbiguous,
    FateCandidateVerifier,
    FateExecutionEngineV1,
    FateExecutionError,
    FateExecutionSuiteV1,
    FateLiveExecutionBlocked,
    FateModelWorkAuthorityV1,
    FateRunPlanV1,
    FateTestOnlyEvaluationV1,
    FateVerificationReceiptV1,
    FateVerificationRequestV1,
    OperatorPrivateArtifactStore,
    build_fate_model_work_authority,
    prepare_fate_attempt,
    require_live_fate_dependencies,
    selected_fate_problems,
    validate_fate_egress_binding,
    verified_split_manifest_hash,
)

_ROOT = Path(__file__).resolve().parents[2]
_SPLITS = _ROOT / "benchmarks" / "fate-splits.v1.json"
_CAPABILITIES = ProviderCapabilities.of(
    Capability.TEXT_GENERATION,
    Capability.USAGE_ACCOUNTING,
)
_TIERS: tuple[Tier, ...] = ("M", "H", "X")
_MODEL_KEY = HmacAttestationKeyV1(
    key_id="fate-execution-test-model-v1",
    secret=b"fate-execution-test-model-secret-material-01",
    allowed_purposes=frozenset({AttestationPurposeV1.MODEL_EXECUTION}),
)
_ADMISSION_KEY = HmacAttestationKeyV1(
    key_id="fate-execution-test-model-work-admission-v1",
    secret=b"fate-execution-test-admission-secret-material-01",
    allowed_purposes=frozenset({AttestationPurposeV1.MODEL_WORK_ADMISSION}),
)
_RECEIPT_SECRET = b"fate-independent-receipt-test-secret-01"
_RECEIPT_KEY_ID = "fate-independent-receipt-test-v1"
_VERIFIER_ID = "fake-fate-verifier-v1"


def _clock() -> datetime:
    return datetime(2026, 1, 1, tzinfo=UTC)


@dataclass
class MutableClock:
    now: datetime

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


class DelayedClaimAuthorizationService:
    def __init__(
        self,
        delegate: ModelExecutionAuthorizationService,
        *,
        clock: MutableClock,
        delay_seconds: float,
    ) -> None:
        self._delegate = delegate
        self._clock = clock
        self._delay_seconds = delay_seconds

    def claim_model_work(
        self,
        bundle: ModelWorkBundleV2,
        *,
        ttl_seconds: float,
    ) -> Lease:
        lease = self._delegate.claim_model_work(bundle, ttl_seconds=ttl_seconds)
        self._clock.advance(self._delay_seconds)
        return lease

    def __getattr__(self, name: str) -> object:
        return getattr(self._delegate, name)


class DelayedIssueAuthorizationService:
    def __init__(
        self,
        delegate: ModelExecutionAuthorizationService,
        *,
        clock: MutableClock,
        delay_seconds: float,
    ) -> None:
        self._delegate = delegate
        self._clock = clock
        self._delay_seconds = delay_seconds

    def issue_model_work(
        self,
        bundle: ModelWorkBundleV2,
        *,
        approval_id: StableIdentifierV1,
        budget: ModelExecutionBudgetV1,
        lease: Lease,
        ttl_seconds: float,
    ) -> ModelExecutionAuthorizationV1:
        authorization = self._delegate.issue_model_work(
            bundle,
            approval_id=approval_id,
            budget=budget,
            lease=lease,
            ttl_seconds=ttl_seconds,
        )
        self._clock.advance(self._delay_seconds)
        return authorization

    def __getattr__(self, name: str) -> object:
        return getattr(self._delegate, name)


class AdjustableTtlPreflightAuthorizationService:
    def __init__(
        self,
        delegate: ModelExecutionAuthorizationService,
        *,
        max_ttl_seconds: float,
    ) -> None:
        self._delegate = delegate
        self.max_ttl_seconds = max_ttl_seconds

    def preflight_authorization_ttl(self, ttl_seconds: float) -> None:
        if ttl_seconds > self.max_ttl_seconds:
            raise ModelExecutionAuthorizationError(
                "authorization ttl_seconds exceeds the adjustable test policy"
            )
        self._delegate.preflight_authorization_ttl(ttl_seconds)

    def __getattr__(self, name: str) -> object:
        return getattr(self._delegate, name)


def _source(tier: str, number: int) -> bytes:
    return (f"import Mathlib\n\ntheorem target_{tier}_{number} : True := by\n  sorry\n").encode()


def _fixture(tmp_path: Path) -> tuple[FateAdapter, dict[str, bytes]]:
    lock = FateFixtureLockV1.load()
    tasks: list[FateFixtureTaskV1] = []
    canonical_sources: dict[str, bytes] = {}
    for tier in _TIERS:
        for number in range(1, TIER_COUNTS[tier] + 1):
            problem = FateProblemId(tier, number)
            source = _source(tier, number)
            task = FateFixtureTaskV1.from_source(
                problem,
                f"FATE-{tier}/FATE{tier}/{number}.lean",
                source,
            )
            tasks.append(task)
            canonical_sources[task.source_path] = source
    manifest = FateFixtureManifestV1(
        root_commit=lock.root_commit,
        submodules=dict(lock.submodules),
        toolchain=lock.toolchain,
        mathlib_commit=lock.mathlib_revision,
        lake_manifest_sha256=dict(lock.lake_manifest_sha256),
        metadata_json_sha256=dict(lock.metadata_json_sha256),
        tasks=tuple(tasks),
    )
    return (
        FateAdapter(
            tmp_path / "checkout",
            manifest,
            canonical_sources=canonical_sources,
        ),
        {task.task_id: canonical_sources[task.source_path] for task in tasks},
    )


class RecordingFakeProvider(FakeProvider):
    def __init__(
        self,
        responses: list[str | ModelResponse],
        *,
        timeout_seconds: float = 3600,
    ) -> None:
        super().__init__(
            responses,
            model_id="fate-test-model",
            capabilities=_CAPABILITIES,
            timeout_seconds=timeout_seconds,
        )
        self.requests: list[ModelRequest] = []

    def generate(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        return super().generate(request)


class CrashingProvider(RecordingFakeProvider):
    def __init__(self) -> None:
        super().__init__([])
        self.calls = 0

    def generate(self, request: ModelRequest) -> ModelResponse:
        self.calls += 1
        self.requests.append(request)
        raise ProviderResponseError("simulated provider crash")


class CountingFateProbe:
    def __init__(self) -> None:
        self.calls = 0

    def probe(self, provider: ModelProvider) -> ProviderCapabilities:
        del provider
        self.calls += 1
        return _CAPABILITIES


class ProductionReceiptAuthenticatorProbe:
    execution_class = IndependentExecutionClassV1.PRODUCTION

    def verify(self, receipt: IndependentExecutionReceiptV1) -> None:
        del receipt
        raise AssertionError("production authenticator was unexpectedly reached")


class ReachedProductionVerifier:
    execution_class = IndependentExecutionClassV1.PRODUCTION

    def __init__(self) -> None:
        self.requests: list[FateVerificationRequestV1] = []

    def verify(
        self,
        request: FateVerificationRequestV1,
    ) -> FateVerificationReceiptV1:
        self.requests.append(request)
        raise AssertionError("production verifier reached")


class NeverCalledTestVerifier:
    execution_class = IndependentExecutionClassV1.TEST_ONLY

    def __init__(self) -> None:
        self.calls = 0

    def verify(
        self,
        request: FateVerificationRequestV1,
    ) -> FateVerificationReceiptV1:
        del request
        self.calls += 1
        raise AssertionError("test verifier must not be called")


@dataclass
class StepMonotonic:
    value: float = 0.0

    def __call__(self) -> float:
        current = self.value
        self.value += 0.01
        return current


@dataclass(frozen=True)
class Runtime:
    adapter: FateAdapter
    all_sources: dict[str, bytes]
    plan: FateRunPlanV1
    authority: FateModelWorkAuthorityV1
    approval: ModelExecutionProviderApprovalV1
    service: ModelExecutionAuthorizationService
    registry: ProviderRegistry
    events: EventStore
    private: OperatorPrivateArtifactStore
    provider: RecordingFakeProvider
    admission_signer: HmacAttestationSignerV1
    receipt_issuer: FixtureHmacIndependentExecutionReceiptAuthenticator
    verifier_trust_policy: IndependentExecutionTrustPolicyV1
    clock: Callable[[], datetime]


def _runtime(
    tmp_path: Path,
    *,
    responses: list[str | ModelResponse],
    suite: FateExecutionSuiteV1 = "regression-48",
    attempts: int = 1,
    provider: RecordingFakeProvider | None = None,
    provider_probe: CapabilityProbe | None = None,
    clock: Callable[[], datetime] = _clock,
    max_authorization_ttl_seconds: float = 3600,
) -> Runtime:
    adapter, all_sources = _fixture(tmp_path)
    selected_provider = provider or RecordingFakeProvider(responses)
    database = tmp_path / "control.db"
    attestation_verifier = HmacAttestationVerifierV1(
        {_MODEL_KEY.key_id: _MODEL_KEY},
        clock=clock,
    )
    events = EventStore(database, clock=clock)
    plane = ControlPlane(
        events=events,
        leases=LeaseStore(database, clock=clock),
        artifacts=ArtifactStore(tmp_path / "public-artifacts"),
        attestation_verifier=attestation_verifier,
    )
    service = ModelExecutionAuthorizationService(
        control_plane=plane,
        signer=HmacAttestationSignerV1(_MODEL_KEY, clock=clock),
        verifier=attestation_verifier,
        admission_verifier=HmacAttestationVerifierV1(
            {_ADMISSION_KEY.key_id: _ADMISSION_KEY},
            clock=clock,
        ),
        clock=clock,
        max_ttl_seconds=max_authorization_ttl_seconds,
    )
    approval = ModelExecutionProviderApprovalV1(
        approval_id=stable_identifier("fate-test-provider", "fake"),
        binding=ModelExecutionProviderBindingV1(
            registry_name="fake",
            provider_id=selected_provider.provider_id,
            model_id=selected_provider.model_id,
            model_revision="fate-test-revision-v1",
            endpoint_class=EndpointClassV1.LOCAL,
            configuration_hash=selected_provider.configuration_hash,
        ),
        pricing=ModelExecutionPricingV1(
            input_microusd_per_token=1,
            cached_input_microusd_per_token=1,
            output_microusd_per_token=1,
        ),
        approved_by="test-operator",
        approved_at=clock(),
    )
    service.register_operator_approval(
        approval,
        idempotency_key="register-fate-test-provider",
    )
    registry = ProviderRegistry(authorization_gate=service)
    registry.register(
        "fake",
        provider=selected_provider,
        probe=(StaticCapabilityProbe(_CAPABILITIES) if provider_probe is None else provider_probe),
        endpoint_class=EndpointClassV1.LOCAL,
        model_revision="fate-test-revision-v1",
    )
    authority = build_fate_model_work_authority(
        adapter.manifest,
        endpoint_class=EndpointClassV1.LOCAL,
        reviewed_by="test-operator",
        reviewed_at=clock(),
    )
    plan = FateRunPlanV1(
        run_id="fate-test-run",
        suite=suite,
        fate_manifest_hash=adapter.manifest.content_hash,
        split_manifest_hash=verified_split_manifest_hash(_SPLITS),
        environment_hash="e" * 64,
        attempt_budget=attempts,
        model_request_timeout_seconds=20,
        verifier_timeout_seconds=30,
        settlement_margin_seconds=10,
        max_input_tokens=256,
        max_output_tokens=32,
        max_cost_microusd_per_attempt=288,
    )
    repository = tmp_path / "repository"
    repository.mkdir()
    private = OperatorPrivateArtifactStore(
        tmp_path / "operator-private",
        repository_root=repository,
    )
    receipt_issuer = FixtureHmacIndependentExecutionReceiptAuthenticator(
        key_id=_RECEIPT_KEY_ID,
        secret=_RECEIPT_SECRET,
    )
    trusted_verifier = TrustedIndependentExecutionVerifierV1(
        verifier_id=_VERIFIER_ID,
        authentication_key_id=_RECEIPT_KEY_ID,
        execution_class=IndependentExecutionClassV1.TEST_ONLY,
        authenticator=receipt_issuer,
    )
    verifier_trust_policy = IndependentExecutionTrustPolicyV1(
        gateway_signing_key_id="fate-gateway-test-key-v1",
        execution_class=IndependentExecutionClassV1.TEST_ONLY,
        trusted_verifiers={_VERIFIER_ID: trusted_verifier},
    )
    return Runtime(
        adapter=adapter,
        all_sources=all_sources,
        plan=plan,
        authority=authority,
        approval=approval,
        service=service,
        registry=registry,
        events=events,
        private=private,
        provider=selected_provider,
        admission_signer=HmacAttestationSignerV1(
            _ADMISSION_KEY,
            clock=clock,
        ),
        receipt_issuer=receipt_issuer,
        verifier_trust_policy=verifier_trust_policy,
        clock=clock,
    )


def _engine(
    runtime: Runtime,
    verifier: FateCandidateVerifier,
    *,
    nonce: str = "process-nonce-1",
    work_admissions: dict[str, AttestationV1] | None = None,
    verifier_trust_policy: IndependentExecutionTrustPolicyV1 | None = None,
    lease_ttl_seconds: float = 900,
    authorization_ttl_seconds: float = 600,
    authorization_service: ModelExecutionAuthorizationService | None = None,
) -> FateExecutionEngineV1:
    selected = selected_fate_problems(runtime.plan.suite)
    selected_admissions = _work_admissions(runtime) if work_admissions is None else work_admissions
    return FateExecutionEngineV1(
        plan=runtime.plan,
        adapter=runtime.adapter,
        prompt_sources={
            problem.canonical: runtime.all_sources[problem.canonical] for problem in selected
        },
        authority=runtime.authority,
        approval_id=runtime.approval.approval_id,
        authorization_service=(
            runtime.service if authorization_service is None else authorization_service
        ),
        registry=runtime.registry,
        events=runtime.events,
        private_artifacts=runtime.private,
        verifier=verifier,
        verifier_trust_policy=(
            runtime.verifier_trust_policy
            if verifier_trust_policy is None
            else verifier_trust_policy
        ),
        execution_nonce=nonce,
        work_admissions=selected_admissions,
        monotonic=StepMonotonic(),
        wall_clock=runtime.clock,
        lease_ttl_seconds=lease_ttl_seconds,
        authorization_ttl_seconds=authorization_ttl_seconds,
    )


def _work_admissions(
    runtime: Runtime,
    *,
    ttl_seconds: float = 3_600,
) -> dict[str, AttestationV1]:
    admissions: dict[str, AttestationV1] = {}
    selected = selected_fate_problems(runtime.plan.suite)
    for problem in selected:
        for attempt_number in range(1, runtime.plan.attempt_budget + 1):
            prepared = prepare_fate_attempt(
                adapter=runtime.adapter,
                source_bytes=runtime.all_sources[problem.canonical],
                problem_id=problem,
                attempt_number=attempt_number,
                plan=runtime.plan,
                authority=runtime.authority,
            )
            bundle = prepared.work_bundle
            admissions[bundle.bundle_id.value] = runtime.admission_signer.issue(
                purpose=AttestationPurposeV1.MODEL_WORK_ADMISSION,
                payload=model_work_admission_payload(bundle),
                evidence_identity=model_work_admission_evidence_identity(bundle),
                ttl_seconds=ttl_seconds,
            )
    return admissions


def _verifier(
    runtime: Runtime,
    *,
    accept_all_candidates: bool = False,
) -> DeterministicFakeFateVerifier:
    return DeterministicFakeFateVerifier(
        receipt_issuer=runtime.receipt_issuer,
        accept_all_candidates=accept_all_candidates,
        clock=_clock,
    )


def test_suite_selections_are_fixed_and_keep_tiers_addressable() -> None:
    regression = selected_fate_problems("regression-48")
    comparison = selected_fate_problems("model-compare-90")
    full = selected_fate_problems("FATE-350")

    assert len(regression) == 48
    assert len(comparison) == 90
    assert len(full) == 350
    assert {tier: sum(item.tier == tier for item in regression) for tier in _TIERS} == {
        "M": 24,
        "H": 12,
        "X": 12,
    }
    assert {tier: sum(item.tier == tier for item in comparison) for tier in _TIERS} == {
        "M": 30,
        "H": 30,
        "X": 30,
    }


def test_regression_48_runs_end_to_end_and_public_evidence_is_answer_free(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, responses=["trivial"] * 48)
    verifier = _verifier(runtime, accept_all_candidates=True)
    test_only = _engine(runtime, verifier).run_test_only()
    assert isinstance(test_only, FateTestOnlyEvaluationV1)
    assert test_only.production_evidence is False
    report = test_only.report

    metrics = {item.tier: item for item in report.metrics()}
    assert {tier: metrics[tier].problems for tier in _TIERS} == {
        "M": 24,
        "H": 12,
        "X": 12,
    }
    assert {tier: metrics[tier].pass_at_1 for tier in _TIERS} == {
        "M": 24,
        "H": 12,
        "X": 12,
    }
    assert len(runtime.provider.requests) == 48
    assert len(verifier.requests) == 48
    assert all(request.tools == () for request in runtime.provider.requests)
    assert all(request.working_directory is None for request in runtime.provider.requests)

    public_events = json.dumps(
        [
            {
                "event_type": event.event_type,
                "payload": event.payload,
            }
            for event in runtime.events.read_all()
        ],
        sort_keys=True,
    )
    public_report = report.canonical_json_bytes().decode("ascii")
    assert "trivial" not in public_events
    assert "trivial" not in public_report
    assert "LEAN_SOURCE" not in public_events
    assert "target_M_1" not in public_events
    assert '"tiers"' in public_report
    first_problem = selected_fate_problems(runtime.plan.suite)[0]
    private_record = runtime.private.get_attempt_record(
        runtime.plan.run_id,
        first_problem,
        1,
    )
    assert runtime.private.get_bytes(private_record.raw_output_sha256) == b"trivial"
    terminal = runtime.events.read_all()[1].payload
    assert "raw_output_sha256" not in terminal
    assert "candidate_sha256" not in terminal
    assert "verification_evidence_sha256" not in terminal
    assert private_record.raw_output_sha256 not in public_events
    assert private_record.candidate_sha256 is not None
    assert private_record.candidate_sha256 not in public_events
    assert private_record.verifier_receipt_artifact_sha256 not in public_events
    private_receipt = FateVerificationReceiptV1.from_private_bytes(
        runtime.private.get_bytes(private_record.verifier_receipt_artifact_sha256)
    )
    assert private_receipt.accepted is True
    assert private_receipt.independent_execution_receipt.authentication is not None


def test_test_only_verifier_cannot_emit_publishable_report(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path, responses=["trivial"] * 48)
    engine = _engine(
        runtime,
        _verifier(runtime, accept_all_candidates=True),
    )

    with pytest.raises(
        FateLiveExecutionBlocked,
        match="production_verifier_authority_required",
    ):
        engine.run()
    assert runtime.provider.requests == []


def test_production_execution_reaches_provider_with_bound_request_timeout(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, responses=["trivial"])
    verifier_id = "reached-production-verifier-v1"
    key_id = "production-receipt-key-v1"
    production_policy = IndependentExecutionTrustPolicyV1(
        gateway_signing_key_id="production-gateway-key-v1",
        execution_class=IndependentExecutionClassV1.PRODUCTION,
        trusted_verifiers={
            verifier_id: TrustedIndependentExecutionVerifierV1(
                verifier_id=verifier_id,
                authentication_key_id=key_id,
                execution_class=IndependentExecutionClassV1.PRODUCTION,
                authenticator=ProductionReceiptAuthenticatorProbe(),
            )
        },
    )
    verifier = ReachedProductionVerifier()
    engine = _engine(
        runtime,
        verifier,
        verifier_trust_policy=production_policy,
    )
    problem = selected_fate_problems(runtime.plan.suite)[0]

    with pytest.raises(
        FateAttemptAmbiguous,
        match="automatic provider replay is forbidden",
    ):
        engine.execute_attempt(problem, 1)

    assert len(runtime.provider.requests) == 1
    assert (
        runtime.provider.requests[0].timeout_seconds == runtime.plan.model_request_timeout_seconds
    )
    assert len(verifier.requests) == 1
    assert verifier.requests[0].timeout_seconds == runtime.plan.verifier_timeout_seconds


def test_model_request_timeout_is_distinct_and_bound_to_request_bundle_and_report(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, responses=["trivial"])
    problem = selected_fate_problems(runtime.plan.suite)[0]
    source = runtime.all_sources[problem.canonical]
    prepared = prepare_fate_attempt(
        adapter=runtime.adapter,
        source_bytes=source,
        problem_id=problem,
        attempt_number=1,
        plan=runtime.plan,
        authority=runtime.authority,
    )
    changed_plan = replace(
        runtime.plan,
        model_request_timeout_seconds=21,
    )
    changed = prepare_fate_attempt(
        adapter=runtime.adapter,
        source_bytes=source,
        problem_id=problem,
        attempt_number=1,
        plan=changed_plan,
        authority=runtime.authority,
    )
    changed_verifier_plan = replace(
        runtime.plan,
        verifier_timeout_seconds=31,
    )
    changed_verifier = prepare_fate_attempt(
        adapter=runtime.adapter,
        source_bytes=source,
        problem_id=problem,
        attempt_number=1,
        plan=changed_verifier_plan,
        authority=runtime.authority,
    )

    assert runtime.plan.model_request_timeout_seconds == 20
    assert runtime.plan.verifier_timeout_seconds == 30
    assert prepared.request.timeout_seconds == 20.0
    assert changed.request.timeout_seconds == 21.0
    assert prepared.request.outbound_request_hash() != changed.request.outbound_request_hash()
    assert prepared.work_bundle.request_hash != changed.work_bundle.request_hash
    assert prepared.work_bundle.cell_contract_hash != changed.work_bundle.cell_contract_hash
    assert prepared.work_bundle.handoff_hash() != changed.work_bundle.handoff_hash()
    assert (
        runtime.plan.reporting_config(
            runtime.approval,
            effective_model_timeout_seconds=20.0,
        ).timeout_seconds
        == 20.0
    )
    assert (
        changed_plan.reporting_config(
            runtime.approval,
            effective_model_timeout_seconds=21.0,
        ).timeout_seconds
        == 21.0
    )
    assert changed_verifier.request.timeout_seconds == prepared.request.timeout_seconds
    assert (
        changed_verifier.request.outbound_request_hash() == prepared.request.outbound_request_hash()
    )
    assert changed_verifier.work_bundle.request_hash == prepared.work_bundle.request_hash
    assert (
        changed_verifier.work_bundle.cell_contract_hash != prepared.work_bundle.cell_contract_hash
    )
    assert changed_verifier.work_bundle.handoff_hash() != prepared.work_bundle.handoff_hash()
    assert (
        changed_verifier_plan.reporting_config(
            runtime.approval,
            effective_model_timeout_seconds=20.0,
        ).timeout_seconds
        == 20.0
    )
    with pytest.raises(FateExecutionError, match="reported model timeout differs"):
        runtime.plan.reporting_config(
            runtime.approval,
            effective_model_timeout_seconds=19.0,
        )


@pytest.mark.parametrize("timeout_seconds", (0, 3601))
def test_model_request_timeout_rejects_out_of_range_values(
    tmp_path: Path,
    timeout_seconds: int,
) -> None:
    runtime = _runtime(tmp_path, responses=["trivial"])

    with pytest.raises(FateExecutionError, match="model_request_timeout_seconds"):
        replace(
            runtime.plan,
            model_request_timeout_seconds=timeout_seconds,
        )


def test_provider_ceiling_below_frozen_timeout_blocks_before_any_execution_io(
    tmp_path: Path,
) -> None:
    provider = RecordingFakeProvider(["trivial"], timeout_seconds=19)
    probe = CountingFateProbe()
    runtime = _runtime(
        tmp_path,
        responses=[],
        provider=provider,
        provider_probe=probe,
    )
    verifier = NeverCalledTestVerifier()
    problem = selected_fate_problems(runtime.plan.suite)[0]

    with pytest.raises(
        FateLiveExecutionBlocked,
        match="provider_timeout_ceiling_below_frozen_plan",
    ):
        _engine(runtime, verifier).execute_test_only_attempt(problem, 1)

    assert provider.requests == []
    assert probe.calls == 0
    assert verifier.calls == 0
    assert not any(
        event.event_type == "fate.attempt.started" for event in runtime.events.read_all()
    )


@pytest.mark.parametrize(
    ("lease_ttl_seconds", "authorization_ttl_seconds", "message"),
    (
        (59, 30, "lease TTL cannot cover"),
        (60, 29, "authorization TTL cannot cover"),
        (60, 60, "outlive authorization TTL"),
    ),
)
def test_attempt_ttls_fail_closed_before_io_when_static_windows_are_insufficient(
    tmp_path: Path,
    lease_ttl_seconds: float,
    authorization_ttl_seconds: float,
    message: str,
) -> None:
    runtime = _runtime(tmp_path, responses=["trivial"])
    verifier = NeverCalledTestVerifier()

    with pytest.raises(FateExecutionError, match=message):
        _engine(
            runtime,
            verifier,
            lease_ttl_seconds=lease_ttl_seconds,
            authorization_ttl_seconds=authorization_ttl_seconds,
        )

    assert runtime.provider.requests == []
    assert verifier.calls == 0


def test_service_ttl_policy_blocks_before_model_work_registration_or_claim(
    tmp_path: Path,
) -> None:
    probe = CountingFateProbe()
    runtime = _runtime(
        tmp_path,
        responses=["trivial"],
        provider_probe=probe,
        max_authorization_ttl_seconds=29,
    )
    verifier = NeverCalledTestVerifier()
    problem = selected_fate_problems(runtime.plan.suite)[0]

    with pytest.raises(
        ModelExecutionAuthorizationError,
        match="configured maximum of 29 seconds",
    ):
        _engine(
            runtime,
            verifier,
            lease_ttl_seconds=60,
            authorization_ttl_seconds=30,
        ).execute_test_only_attempt(problem, 1)

    with sqlite3.connect(tmp_path / "control.db") as connection:
        model_work_count = connection.execute(
            "SELECT COUNT(*) FROM model_execution_work_bundles"
        ).fetchone()
        lease_count = connection.execute("SELECT COUNT(*) FROM worker_leases").fetchone()
    assert model_work_count == (0,)
    assert lease_count == (0,)
    assert runtime.provider.requests == []
    assert probe.calls == 0
    assert verifier.calls == 0
    assert not any(
        event.event_type == "fate.attempt.started" for event in runtime.events.read_all()
    )


def test_static_ttl_preflight_failure_does_not_poison_same_engine_retry(
    tmp_path: Path,
) -> None:
    probe = CountingFateProbe()
    runtime = _runtime(
        tmp_path,
        responses=["trivial"],
        provider_probe=probe,
    )
    policy = AdjustableTtlPreflightAuthorizationService(
        runtime.service,
        max_ttl_seconds=29,
    )
    verifier = _verifier(runtime, accept_all_candidates=True)
    problem = selected_fate_problems(runtime.plan.suite)[0]
    engine = _engine(
        runtime,
        verifier,
        lease_ttl_seconds=60,
        authorization_ttl_seconds=30,
        authorization_service=cast(
            ModelExecutionAuthorizationService,
            policy,
        ),
    )

    with pytest.raises(
        ModelExecutionAuthorizationError,
        match="adjustable test policy",
    ):
        engine.execute_test_only_attempt(problem, 1)

    with sqlite3.connect(tmp_path / "control.db") as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM model_execution_work_bundles"
        ).fetchone() == (0,)
        assert connection.execute("SELECT COUNT(*) FROM worker_leases").fetchone() == (0,)
    assert runtime.provider.requests == []
    assert probe.calls == 0
    assert verifier.requests == []
    assert not any(
        event.event_type == "fate.attempt.started" for event in runtime.events.read_all()
    )

    policy.max_ttl_seconds = 30
    result = engine.execute_test_only_attempt(problem, 1)

    assert result.attempt.accepted is True
    assert len(runtime.provider.requests) == 1
    assert probe.calls == 1
    assert len(verifier.requests) == 1


def test_model_authorization_extreme_respects_one_hour_cap_without_covering_verifier(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, responses=["trivial"])
    valid_plan = replace(
        runtime.plan,
        model_request_timeout_seconds=3590,
        verifier_timeout_seconds=1,
        settlement_margin_seconds=10,
    )
    valid_runtime = replace(runtime, plan=valid_plan)

    _engine(
        valid_runtime,
        NeverCalledTestVerifier(),
        lease_ttl_seconds=3601,
        authorization_ttl_seconds=3600,
    )

    assert valid_plan.model_authorization_window_seconds == 3600
    assert valid_plan.attempt_lease_window_seconds == 3601
    with pytest.raises(FateExecutionError, match="authorization hard cap"):
        replace(
            runtime.plan,
            model_request_timeout_seconds=3591,
            settlement_margin_seconds=10,
        )


def test_short_parent_admission_blocks_before_provider_or_verifier_io(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, responses=["trivial"])
    verifier = NeverCalledTestVerifier()
    problem = selected_fate_problems(runtime.plan.suite)[0]

    with pytest.raises(
        FateLiveExecutionBlocked,
        match="model_work_admission_deadline_insufficient",
    ):
        _engine(
            runtime,
            verifier,
            work_admissions=_work_admissions(runtime, ttl_seconds=29),
            lease_ttl_seconds=60,
            authorization_ttl_seconds=30,
        ).execute_test_only_attempt(problem, 1)

    assert runtime.provider.requests == []
    assert verifier.calls == 0
    assert not any(
        event.event_type == "fate.attempt.started" for event in runtime.events.read_all()
    )


def test_elapsed_lease_setup_time_blocks_before_provider_or_verifier_io(
    tmp_path: Path,
) -> None:
    clock = MutableClock(_clock())
    runtime = _runtime(tmp_path, responses=["trivial"], clock=clock)
    delayed = DelayedClaimAuthorizationService(
        runtime.service,
        clock=clock,
        delay_seconds=1,
    )
    verifier = NeverCalledTestVerifier()
    problem = selected_fate_problems(runtime.plan.suite)[0]

    with pytest.raises(
        FateLiveExecutionBlocked,
        match="attempt_lease_deadline_insufficient",
    ):
        _engine(
            runtime,
            verifier,
            lease_ttl_seconds=60,
            authorization_ttl_seconds=30,
            authorization_service=cast(
                ModelExecutionAuthorizationService,
                delayed,
            ),
        ).execute_test_only_attempt(problem, 1)

    assert runtime.provider.requests == []
    assert verifier.calls == 0
    assert not any(
        event.event_type == "fate.attempt.started" for event in runtime.events.read_all()
    )


def test_elapsed_post_issue_time_blocks_before_provider_or_verifier_io(
    tmp_path: Path,
) -> None:
    clock = MutableClock(_clock())
    runtime = _runtime(tmp_path, responses=["trivial"], clock=clock)
    delayed = DelayedIssueAuthorizationService(
        runtime.service,
        clock=clock,
        delay_seconds=1,
    )
    verifier = NeverCalledTestVerifier()
    problem = selected_fate_problems(runtime.plan.suite)[0]

    with pytest.raises(
        FateLiveExecutionBlocked,
        match="model_authorization_deadline_insufficient",
    ):
        _engine(
            runtime,
            verifier,
            lease_ttl_seconds=60,
            authorization_ttl_seconds=30,
            authorization_service=cast(
                ModelExecutionAuthorizationService,
                delayed,
            ),
        ).execute_test_only_attempt(problem, 1)

    assert runtime.provider.requests == []
    assert verifier.calls == 0
    assert not any(
        event.event_type == "fate.attempt.started" for event in runtime.events.read_all()
    )


def test_untrusted_verifier_receipt_cannot_commit_terminal_event(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, responses=["trivial"])
    untrusted_issuer = FixtureHmacIndependentExecutionReceiptAuthenticator(
        key_id="untrusted-receipt-key-v1",
        secret=b"untrusted-independent-receipt-secret-01",
    )
    verifier = DeterministicFakeFateVerifier(
        receipt_issuer=untrusted_issuer,
        accept_all_candidates=True,
        clock=_clock,
    )
    problem = selected_fate_problems(runtime.plan.suite)[0]

    with pytest.raises(FateAttemptAmbiguous, match="automatic provider replay"):
        _engine(runtime, verifier).execute_test_only_attempt(problem, 1)

    assert len(runtime.provider.requests) == 1
    assert [event.event_type for event in runtime.events.read_all()] == ["fate.attempt.started"]


def test_report_identity_and_cost_use_signed_approval_snapshot(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, responses=["trivial"] * 48)
    forged_binding = runtime.approval.binding.model_copy(
        update={
            "model_id": "forged-model",
            "model_revision": "forged-revision",
        }
    )
    forged = runtime.approval.model_copy(
        update={
            "binding": forged_binding,
            "pricing": ModelExecutionPricingV1(
                input_microusd_per_token=0,
                cached_input_microusd_per_token=0,
                output_microusd_per_token=0,
            ),
        }
    )
    caller_view = replace(runtime, approval=forged)

    report = (
        _engine(
            caller_view,
            _verifier(caller_view, accept_all_candidates=True),
        )
        .run_test_only()
        .report
    )

    assert report.config.model_id == runtime.approval.binding.model_id
    assert report.config.model_revision == runtime.approval.binding.model_revision
    assert report.config.timeout_seconds == runtime.plan.model_request_timeout_seconds
    assert (
        sum(attempt.cost_microusd for result in report.results for attempt in result.attempts) > 0
    )
    terminal = runtime.events.read_all()[1].payload
    assert terminal["approval_hash"] == runtime.approval.approval_hash().value
    assert terminal["approval_hash"] != forged.approval_hash().value
    assert terminal["effective_model_timeout_seconds"] == runtime.plan.model_request_timeout_seconds


def test_each_work_bundle_rights_bind_the_exact_pinned_task_bytes(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path, responses=["trivial"])
    problem = selected_fate_problems(runtime.plan.suite)[0]
    source = runtime.all_sources[problem.canonical]

    prepared = prepare_fate_attempt(
        adapter=runtime.adapter,
        source_bytes=source,
        problem_id=problem,
        attempt_number=1,
        plan=runtime.plan,
        authority=runtime.authority,
    )

    assert prepared.work_bundle.source.source_content_hash == digest_bytes(
        HashKindV1.SOURCE_BYTES,
        source,
    )
    assert (
        prepared.work_bundle.rights.source_identity_hash
        == prepared.work_bundle.source.source_identity_hash
    )
    assert len(prepared.work_bundle.source.spans) == 1
    assert (
        prepared.work_bundle.egress_content_hash
        == prepared.work_bundle.source.spans[0].content_hash
    )
    public_bundle = prepared.work_bundle.model_dump_json()
    forbidden_free_text = (
        "LEAN_SOURCE",
        "target_M_1",
        "FATE problem M1",
        "FATE-M/FATEM/1.lean",
        "derived://autolean/fate-prover-egress/",
        "FATE, frenzymath, MIT license",
        '"work_id"',
        '"title"',
        '"version"',
        '"locator"',
        '"metadata"',
        '"attribution"',
        '"restrictions"',
        '"reviewed_by"',
        '"reviewed_at"',
    )
    assert all(canary not in public_bundle for canary in forbidden_free_text)
    public_admission = json.dumps(
        model_work_admission_payload(prepared.work_bundle),
        sort_keys=True,
    )
    assert all(canary not in public_admission for canary in forbidden_free_text)
    admission = runtime.admission_signer.issue(
        purpose=AttestationPurposeV1.MODEL_WORK_ADMISSION,
        payload=model_work_admission_payload(prepared.work_bundle),
        evidence_identity=model_work_admission_evidence_identity(prepared.work_bundle),
        ttl_seconds=3_600,
    )
    runtime.service.register_model_work(
        prepared.work_bundle,
        admission=admission,
    )
    with sqlite3.connect(tmp_path / "control.db") as connection:
        stored = connection.execute(
            """
            SELECT bundle_json, admission_attestation_json
            FROM model_execution_work_bundles
            WHERE bundle_id = ?
            """,
            (prepared.work_bundle.bundle_id.value,),
        ).fetchone()
    assert stored is not None
    stored_public_records = "\n".join(str(value) for value in stored)
    assert all(canary not in stored_public_records for canary in forbidden_free_text)
    validate_fate_egress_binding(prepared, expected_source_bytes=source)


def test_tampered_outbound_wrapper_is_rejected_before_provider_io(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path, responses=["trivial"])
    problem = selected_fate_problems(runtime.plan.suite)[0]
    source = runtime.all_sources[problem.canonical]
    prepared = prepare_fate_attempt(
        adapter=runtime.adapter,
        source_bytes=source,
        problem_id=problem,
        attempt_number=1,
        plan=runtime.plan,
        authority=runtime.authority,
    )
    tampered = replace(
        prepared,
        request=replace(
            prepared.request,
            prompt=prepared.request.prompt + "\nUNAUTHORIZED_WRAPPER",
        ),
    )

    with pytest.raises(FateExecutionError, match="outbound request differs"):
        validate_fate_egress_binding(tampered, expected_source_bytes=source)
    assert runtime.provider.requests == []


def test_shared_model_work_admission_rejects_another_bundle_signature(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, responses=["trivial"])
    problems = selected_fate_problems(runtime.plan.suite)
    first = prepare_fate_attempt(
        adapter=runtime.adapter,
        source_bytes=runtime.all_sources[problems[0].canonical],
        problem_id=problems[0],
        attempt_number=1,
        plan=runtime.plan,
        authority=runtime.authority,
    )
    second = prepare_fate_attempt(
        adapter=runtime.adapter,
        source_bytes=runtime.all_sources[problems[1].canonical],
        problem_id=problems[1],
        attempt_number=1,
        plan=runtime.plan,
        authority=runtime.authority,
    )
    admissions = _work_admissions(runtime)
    admissions[first.work_bundle.bundle_id.value] = admissions[second.work_bundle.bundle_id.value]
    engine = _engine(
        runtime,
        _verifier(runtime, accept_all_candidates=True),
        work_admissions=admissions,
    )

    with pytest.raises(
        ModelExecutionAuthorizationError,
        match="admission evidence identity",
    ):
        engine.execute_test_only_attempt(problems[0], 1)

    assert runtime.provider.requests == []
    assert not runtime.events.read_all()


def test_missing_model_work_admission_blocks_before_provider_io(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, responses=["trivial"])
    problem = selected_fate_problems(runtime.plan.suite)[0]
    prepared = prepare_fate_attempt(
        adapter=runtime.adapter,
        source_bytes=runtime.all_sources[problem.canonical],
        problem_id=problem,
        attempt_number=1,
        plan=runtime.plan,
        authority=runtime.authority,
    )
    admissions = _work_admissions(runtime)
    del admissions[prepared.work_bundle.bundle_id.value]
    engine = _engine(
        runtime,
        _verifier(runtime, accept_all_candidates=True),
        work_admissions=admissions,
    )

    with pytest.raises(FateLiveExecutionBlocked, match="model_work_admission_required"):
        engine.execute_test_only_attempt(problem, 1)

    assert runtime.provider.requests == []
    assert not runtime.events.read_all()


def test_unrelated_allow_source_cannot_replace_fate_authority(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path, responses=["trivial"])
    unrelated = SourceRecordV1(
        source_id=stable_identifier("unrelated", "source"),
        work_id="unrelated",
        title="Unrelated allowed source",
        version="1",
        locator="synthetic://unrelated",
        content_hash=digest_bytes(HashKindV1.SOURCE_BYTES, b"unrelated"),
        retrieved_at=_clock(),
    )
    wrong = FateModelWorkAuthorityV1(
        source=unrelated,
        rights=runtime.authority.rights.model_copy(update={"source_id": unrelated.source_id}),
        lock_sha256=runtime.authority.lock_sha256,
    )
    selected = selected_fate_problems(runtime.plan.suite)

    with pytest.raises(FateExecutionError, match="does not hash the adapter manifest"):
        FateExecutionEngineV1(
            plan=runtime.plan,
            adapter=runtime.adapter,
            prompt_sources={
                problem.canonical: runtime.all_sources[problem.canonical] for problem in selected
            },
            authority=wrong,
            approval_id=runtime.approval.approval_id,
            authorization_service=runtime.service,
            registry=runtime.registry,
            events=runtime.events,
            private_artifacts=runtime.private,
            verifier=_verifier(runtime, accept_all_candidates=True),
            verifier_trust_policy=runtime.verifier_trust_policy,
            execution_nonce="wrong-source-nonce",
            work_admissions={},
        )


def test_provider_success_cannot_bypass_independent_verifier(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path, responses=["trivial"] * 48)
    verifier = _verifier(runtime)

    report = _engine(runtime, verifier).run_test_only().report

    assert len(runtime.provider.requests) == 48
    assert len(verifier.requests) == 48
    assert all(result.terminal_status == "budget_exhausted" for result in report.results)
    assert all(not attempt.accepted for result in report.results for attempt in result.attempts)
    assert all(metric.success_at_budget == 0 for metric in report.metrics())


def test_invalid_model_output_is_boundary_rejected_then_verifier_recorded(
    tmp_path: Path,
) -> None:
    invalid = "theorem target_M_1 : True := by trivial"
    runtime = _runtime(tmp_path, responses=[invalid] * 48)
    verifier = _verifier(runtime, accept_all_candidates=True)

    report = _engine(runtime, verifier).run_test_only().report

    assert all(request.candidate is None for request in verifier.requests)
    assert all(
        request.boundary_failure == "proof_boundary_rejected" for request in verifier.requests
    )
    assert all(not attempt.accepted for result in report.results for attempt in result.attempts)
    public = report.canonical_json_bytes().decode("ascii")
    assert invalid not in public


def test_started_provider_failure_is_ambiguous_and_never_replayed(tmp_path: Path) -> None:
    provider = CrashingProvider()
    runtime = _runtime(tmp_path, responses=[], provider=provider)
    engine = _engine(
        runtime,
        _verifier(runtime, accept_all_candidates=True),
    )
    problem = selected_fate_problems(runtime.plan.suite)[0]

    with pytest.raises(FateAttemptAmbiguous, match="automatic provider replay"):
        engine.execute_test_only_attempt(problem, 1)
    assert provider.calls == 1
    with pytest.raises(FateAttemptAmbiguous, match="durable start"):
        engine.execute_test_only_attempt(problem, 1)
    assert provider.calls == 1
    stream = runtime.events.read_all()
    assert [event.event_type for event in stream] == ["fate.attempt.started"]


def test_terminal_attempt_is_reused_after_restart_without_provider_call(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, responses=["trivial"])
    problem = selected_fate_problems(runtime.plan.suite)[0]
    first = (
        _engine(
            runtime,
            _verifier(runtime, accept_all_candidates=True),
        )
        .execute_test_only_attempt(problem, 1)
        .attempt
    )
    restarted = _engine(
        runtime,
        _verifier(runtime),
        nonce="process-nonce-2",
    )

    second = restarted.execute_test_only_attempt(problem, 1).attempt

    assert second == first
    assert len(runtime.provider.requests) == 1
    assert [event.event_type for event in runtime.events.read_all()] == [
        "fate.attempt.started",
        "fate.attempt.verified",
    ]


def test_public_attempt_events_bind_the_same_deterministic_attempt_seed(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, responses=["trivial"])
    problem = selected_fate_problems(runtime.plan.suite)[0]

    _engine(
        runtime,
        _verifier(runtime, accept_all_candidates=True),
    ).execute_test_only_attempt(problem, 1)

    expected_seed = hashlib.sha256(
        json.dumps(
            {
                "schema_version": "autolean.fate-attempt-seed.v1",
                "run_id": runtime.plan.run_id,
                "problem_id": problem.canonical,
                "attempt_number": 1,
            },
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    stream = runtime.events.read_all()
    assert [event.payload["schema_version"] for event in stream] == [
        "autolean.fate-execution.v2",
        "autolean.fate-execution.v2",
    ]
    assert [event.payload["attempt_seed"] for event in stream] == [
        expected_seed,
        expected_seed,
    ]
    projection = DashboardProjection(stream).snapshot()
    runs = projection.get("runs")
    assert isinstance(runs, list)
    assert runs
    first_run = runs[0]
    assert isinstance(first_run, dict)
    assert first_run.get("status") == "benchmark_verified"
    assert "approval_snapshot" not in json.dumps(projection, sort_keys=True)


def test_restart_rechecks_verifier_trust_policy_before_reusing_terminal(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, responses=["trivial"])
    problem = selected_fate_problems(runtime.plan.suite)[0]
    _engine(
        runtime,
        _verifier(runtime, accept_all_candidates=True),
    ).execute_test_only_attempt(problem, 1)
    other_issuer = FixtureHmacIndependentExecutionReceiptAuthenticator(
        key_id="other-restart-receipt-key-v1",
        secret=b"other-restart-independent-receipt-secret-01",
    )
    other_policy = IndependentExecutionTrustPolicyV1(
        gateway_signing_key_id="other-restart-gateway-key-v1",
        execution_class=IndependentExecutionClassV1.TEST_ONLY,
        trusted_verifiers={
            _VERIFIER_ID: TrustedIndependentExecutionVerifierV1(
                verifier_id=_VERIFIER_ID,
                authentication_key_id=other_issuer.key_id,
                execution_class=IndependentExecutionClassV1.TEST_ONLY,
                authenticator=other_issuer,
            )
        },
    )
    restarted = _engine(
        runtime,
        _verifier(runtime),
        nonce="process-nonce-untrusted-restart",
        verifier_trust_policy=other_policy,
    )

    with pytest.raises(
        FateExecutionError,
        match="verifier authority is not allowlisted",
    ):
        restarted.execute_test_only_attempt(problem, 1)

    assert len(runtime.provider.requests) == 1


def test_operator_private_store_rejects_repository_descendant(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()

    with pytest.raises(FateExecutionError, match="outside the repository"):
        OperatorPrivateArtifactStore(
            repository / "artifacts",
            repository_root=repository,
        )


def test_split_manifest_rejects_semantic_drift(tmp_path: Path) -> None:
    raw = json.loads(_SPLITS.read_text(encoding="utf-8"))
    raw["contains_solutions"] = True
    changed = tmp_path / "fate-splits.json"
    changed.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(FateExecutionError, match="differs"):
        verified_split_manifest_hash(changed)


@pytest.mark.parametrize(
    (
        "operator",
        "provider_authority",
        "verifier",
        "production_verifier_authority",
        "work_admission_authority",
        "code",
    ),
    (
        (False, True, True, True, True, "operator_approval_required"),
        (True, False, True, True, True, "model_execution_authority_required"),
        (True, True, False, True, True, "wsl_oci_verifier_required"),
        (
            True,
            True,
            True,
            False,
            True,
            "production_verifier_authority_required",
        ),
        (
            True,
            True,
            True,
            True,
            False,
            "model_work_admission_authority_required",
        ),
    ),
)
def test_live_execution_wiring_fails_closed(
    operator: bool,
    provider_authority: bool,
    verifier: bool,
    production_verifier_authority: bool,
    work_admission_authority: bool,
    code: str,
) -> None:
    with pytest.raises(FateLiveExecutionBlocked, match=code):
        require_live_fate_dependencies(
            operator_approved=operator,
            provider_authority_injected=provider_authority,
            wsl_verifier_injected=verifier,
            production_verifier_authority_injected=(production_verifier_authority),
            work_admission_authority_injected=work_admission_authority,
        )


def test_live_execution_guard_accepts_only_all_authorities() -> None:
    require_live_fate_dependencies(
        operator_approved=True,
        provider_authority_injected=True,
        wsl_verifier_injected=True,
        production_verifier_authority_injected=True,
        work_admission_authority_injected=True,
    )
