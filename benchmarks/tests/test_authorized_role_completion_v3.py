"""Completion-backed role-floor evidence keeps model output private by construction."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from autolean_contracts import (
    AttestationPurposeV1,
    AttestationSignerV1,
    AttestationV1,
    EndpointClassV1,
    HmacAttestationKeyV1,
    HmacAttestationSignerV1,
    HmacAttestationVerifierV1,
    ModelExecutionBudgetV1,
    ModelExecutionPricingV1,
    ModelExecutionProviderApprovalV1,
    ModelExecutionProviderBindingV1,
    ModelResponseArtifactRefV1,
    ModelResponseArtifactV1,
    ModelResponseToolCallV1,
    ModelResponseUsageV1,
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
from autolean_prover.errors import PolicyViolation
from autolean_prover.providers import (
    Capability,
    FakeProvider,
    LocalPrivateModelOutputStore,
    ModelExecutionCompletionRecoveryRequired,
    ModelRequest,
    ModelResponse,
    ProviderCapabilities,
    ProviderRegistry,
    StaticCapabilityProbe,
    TokenUsage,
)
from pydantic import ValidationError

from benchmarks.authorized_role_bridge import (
    AuthorizedRoleCompletionEvidenceReaderV2,
    AuthorizedRoleCompletionManifestStoreV2,
    AuthorizedRoleGenerationPolicyV1,
    AuthorizedRoleReconciliationRequired,
    AuthorizedRoleSuiteDefinition,
    AuthorizedRoleSuiteSidecarV3,
    PreparedAuthorizedRoleTrial,
    build_locked_calibration_floor_suite,
    prepare_locked_floor_trials,
    run_completed_authorized_role_floor_suite,
)
from benchmarks.authorized_role_bridge import (
    TestOnlyHmacPrivateManifestAuthenticator as PrivateManifestHmacFixture,
)
from benchmarks.authorized_role_evaluation import (
    AuthorizedRoleEvaluationError,
    evaluate_completed_authorized_role_suite_exact_json,
)
from benchmarks.role_benchmark import RoleModelTargetV1

_MODEL_KEY = HmacAttestationKeyV1(
    key_id="authorized-role-v3-model",
    secret=b"authorized-role-v3-model-secret-material-0000001",
    allowed_purposes=frozenset({AttestationPurposeV1.MODEL_EXECUTION}),
)
_ADMISSION_KEY = HmacAttestationKeyV1(
    key_id="authorized-role-v3-admission",
    secret=b"authorized-role-v3-admission-secret-material-0001",
    allowed_purposes=frozenset({AttestationPurposeV1.MODEL_WORK_ADMISSION}),
)
_COMPLETION_KEY = HmacAttestationKeyV1(
    key_id="authorized-role-v3-completion",
    secret=b"authorized-role-v3-completion-secret-material-01",
    allowed_purposes=frozenset({AttestationPurposeV1.MODEL_EXECUTION_COMPLETION}),
)
_PRIVATE_AUTH_SECRET = b"authorized-role-v3-private-manifest-secret-00001"
_POLICY = AuthorizedRoleGenerationPolicyV1(reasoning_effort="high", timeout_seconds=30)
_CAPABILITIES = ProviderCapabilities.of(
    Capability.TEXT_GENERATION,
    Capability.USAGE_ACCOUNTING,
    Capability.REASONING_EFFORT,
)


def _clock() -> datetime:
    return datetime(2026, 7, 28, tzinfo=UTC)


class CountingProvider(FakeProvider):
    def __init__(self, responses: list[ModelResponse]) -> None:
        super().__init__(
            responses,
            model_id="role-v3-model",
            capabilities=_CAPABILITIES,
            timeout_seconds=3600,
        )
        self.calls = 0

    def generate(self, request: ModelRequest) -> ModelResponse:
        self.calls += 1
        return super().generate(request)


class CountingOutputStore(LocalPrivateModelOutputStore):
    def __init__(self, root: Path) -> None:
        super().__init__(root)
        self.artifact_reads = 0
        self.response_reads = 0

    def read_artifact(self, reference: ModelResponseArtifactRefV1) -> ModelResponseArtifactV1:
        self.artifact_reads += 1
        return super().read_artifact(reference)

    def read_response(self, reference: ModelResponseArtifactRefV1) -> ModelResponse:
        self.response_reads += 1
        return super().read_response(reference)


class SubstitutingStore(CountingOutputStore):
    """An independent injected store that attempts to swap response fields after receipt verify."""

    def __init__(self, root: Path, *, mutation: str) -> None:
        super().__init__(root)
        self._mutation = mutation

    def read_artifact(self, reference: ModelResponseArtifactRefV1) -> ModelResponseArtifactV1:
        artifact = super().read_artifact(reference)
        if self._mutation == "text":
            return artifact.model_copy(update={"text": "attacker-controlled-text"})
        if self._mutation == "tool":
            return artifact.model_copy(
                update={
                    "tool_calls": (
                        ModelResponseToolCallV1(
                            call_id="attacker-call",
                            name="attacker_tool",
                            arguments_json="{}",
                        ),
                    )
                }
            )
        if self._mutation == "response_id":
            return artifact.model_copy(update={"response_id": "attacker-response-id"})
        raise AssertionError(f"unexpected substitution mutation: {self._mutation}")

    def read_response(self, reference: ModelResponseArtifactRefV1) -> ModelResponse:
        self.response_reads += 1
        raise AssertionError("completion reader must not call substituted read_response")


class RejectingVerifier:
    def __init__(self) -> None:
        self.calls = 0

    def verify_completion(self, _receipt: object) -> None:
        self.calls += 1
        raise RuntimeError("test verifier rejects receipt")


class FailOnceCompletionSigner:
    def __init__(self, delegate: HmacAttestationSignerV1) -> None:
        self._delegate = delegate
        self._failed = False

    def issue(self, **kwargs: object) -> object:
        if not self._failed:
            self._failed = True
            raise RuntimeError("simulated completion signer interruption")
        return self._delegate.issue(**kwargs)  # type: ignore[arg-type]


@dataclass(frozen=True)
class CompletionHarness:
    suite: AuthorizedRoleSuiteDefinition
    prepared: tuple[PreparedAuthorizedRoleTrial, ...]
    service: ModelExecutionAuthorizationService
    registry: ProviderRegistry
    approval: ModelExecutionProviderApprovalV1
    admissions: dict[str, AttestationV1]
    budgets: dict[str, ModelExecutionBudgetV1]
    output_store: CountingOutputStore
    manifest_store: AuthorizedRoleCompletionManifestStoreV2
    provider: CountingProvider


def _responses(count: int) -> list[ModelResponse]:
    return [
        ModelResponse(
            provider_id="fake",
            model_id="role-v3-model",
            text=json.dumps({"private_response": f"PRIVATE_V3_RESPONSE_{index}"}),
            usage=TokenUsage(input_tokens=10, cached_input_tokens=2, output_tokens=3),
        )
        for index in range(count)
    ]


def _harness(
    tmp_path: Path,
    *,
    completion_configured: bool = True,
    completion_signer: object | None = None,
) -> CompletionHarness:
    provider = CountingProvider(_responses(10))
    target = RoleModelTargetV1(
        provider_id=provider.provider_id,
        model_id=provider.model_id,
        model_revision="role-v3-revision",
        provider_configuration_hash=provider.configuration_hash.value,
        generation_parameters_hash=_POLICY.content_hash(),
    )
    suite = build_locked_calibration_floor_suite(
        target,
        generation_policy=_POLICY,
        repetitions=1,
        max_cost_microusd_per_trial=0,
    )
    prepared = prepare_locked_floor_trials(suite, run_id="authorized-role-v3-run")
    verifier = HmacAttestationVerifierV1(
        {
            _MODEL_KEY.key_id: _MODEL_KEY,
            _ADMISSION_KEY.key_id: _ADMISSION_KEY,
        },
        clock=_clock,
    )
    completion_verifier = HmacAttestationVerifierV1(
        {_COMPLETION_KEY.key_id: _COMPLETION_KEY},
        clock=_clock,
    )
    database = tmp_path / "control.db"
    plane = ControlPlane(
        events=EventStore(database, clock=_clock),
        leases=LeaseStore(database, clock=_clock),
        artifacts=ArtifactStore(tmp_path / "artifacts"),
        attestation_verifier=verifier,
    )
    output_store = CountingOutputStore((tmp_path / "private-output").resolve())
    if completion_configured:
        service = ModelExecutionAuthorizationService(
            control_plane=plane,
            signer=HmacAttestationSignerV1(_MODEL_KEY, clock=_clock),
            verifier=verifier,
            admission_verifier=verifier,
            completion_signer=cast(
                AttestationSignerV1,
                completion_signer or HmacAttestationSignerV1(_COMPLETION_KEY, clock=_clock),
            ),
            completion_verifier=completion_verifier,
            private_output_verifier=output_store,
            clock=_clock,
        )
    else:
        service = ModelExecutionAuthorizationService(
            control_plane=plane,
            signer=HmacAttestationSignerV1(_MODEL_KEY, clock=_clock),
            verifier=verifier,
            admission_verifier=verifier,
            clock=_clock,
        )
    approval = ModelExecutionProviderApprovalV1(
        approval_id=stable_identifier("authorized-role-v3-provider", "fake"),
        binding=ModelExecutionProviderBindingV1(
            registry_name="fake",
            provider_id=provider.provider_id,
            model_id=provider.model_id,
            model_revision="role-v3-revision",
            endpoint_class=EndpointClassV1.LOCAL,
            configuration_hash=provider.configuration_hash,
        ),
        pricing=ModelExecutionPricingV1(),
        approved_by="test-operator",
        approved_at=_clock(),
    )
    service.register_operator_approval(approval, idempotency_key="v3-register-provider")
    registry = ProviderRegistry(authorization_gate=service)
    registry.register(
        "fake",
        provider=provider,
        probe=StaticCapabilityProbe(provider.capabilities),
        endpoint_class=EndpointClassV1.LOCAL,
        model_revision="role-v3-revision",
    )
    admission_signer = HmacAttestationSignerV1(_ADMISSION_KEY, clock=_clock)
    admissions = {
        trial.work_bundle.bundle_id.value: admission_signer.issue(
            purpose=AttestationPurposeV1.MODEL_WORK_ADMISSION,
            payload=model_work_admission_payload(trial.work_bundle),
            evidence_identity=model_work_admission_evidence_identity(trial.work_bundle),
            ttl_seconds=3600,
        )
        for trial in prepared
    }
    budgets = {
        cell.cell_id: ModelExecutionBudgetV1(
            max_attempts=1,
            max_input_tokens=cell.budget.max_input_tokens,
            max_output_tokens=cell.budget.max_output_tokens,
            max_total_tokens=cell.budget.max_input_tokens + cell.budget.max_output_tokens,
            max_cost_microusd=cell.budget.max_cost_microusd,
        )
        for cell in suite.matrix.cells
    }
    manifest_store = AuthorizedRoleCompletionManifestStoreV2(
        (tmp_path / "private-manifests").resolve(),
        private_authenticator=PrivateManifestHmacFixture(_PRIVATE_AUTH_SECRET),
    )
    return CompletionHarness(
        suite=suite,
        prepared=prepared,
        service=service,
        registry=registry,
        approval=approval,
        admissions=admissions,
        budgets=budgets,
        output_store=output_store,
        manifest_store=manifest_store,
        provider=provider,
    )


def _run(harness: CompletionHarness) -> AuthorizedRoleSuiteSidecarV3:
    return run_completed_authorized_role_floor_suite(
        harness.suite,
        run_id="authorized-role-v3-run",
        authorization_service=harness.service,
        admissions_by_bundle_id=harness.admissions,
        registry=harness.registry,
        approval=harness.approval,
        budgets_by_cell=harness.budgets,
        output_store=harness.output_store,
        completion_manifest_store=harness.manifest_store,
    )


def _reader(harness: CompletionHarness) -> AuthorizedRoleCompletionEvidenceReaderV2:
    return AuthorizedRoleCompletionEvidenceReaderV2(
        manifest_store=harness.manifest_store,
        output_store=harness.output_store,
        completion_verifier=harness.service,
    )


def test_v3_public_sidecar_has_fixed_denominator_and_no_private_response_data(
    tmp_path: Path,
) -> None:
    harness = _harness(tmp_path)
    sidecar = _run(harness)

    assert harness.provider.calls == 10
    assert len(sidecar.trials) == 10
    serialized = json.dumps(sidecar.model_dump(mode="json"), sort_keys=True)
    for forbidden in (
        "PRIVATE_V3_RESPONSE_",
        "artifact_digest",
        "response_id",
        "nonce",
        "actual_usage",
        "max_cost_microusd",
    ):
        assert forbidden not in serialized
    assert all(
        set(trial.completion.model_dump(mode="json"))
        == {
            "schema_version",
            "completion_id",
            "receipt_hash",
            "public_output_commitment",
        }
        for trial in sidecar.trials
    )

    manifest = harness.manifest_store.read_manifest(sidecar.private_manifest_handle)
    assert len(manifest.outputs) == 10
    assert b"PRIVATE_V3_RESPONSE_" in b"".join(
        path.read_bytes() for path in (tmp_path / "private-output").rglob("*") if path.is_file()
    )
    with pytest.raises(AuthorizedRoleReconciliationRequired):
        harness.manifest_store.put_manifest(manifest)


def test_completed_evaluator_rejects_tampering_and_cross_run_evidence(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    sidecar = _run(harness)
    report = evaluate_completed_authorized_role_suite_exact_json(
        harness.suite,
        sidecar,
        evidence_reader=_reader(harness),
    )
    assert len(report.trials) == 10

    first = sidecar.trials[0].model_copy(update={"authorization_hash": "0" * 64})
    tampered = sidecar.model_copy(update={"trials": (first, *sidecar.trials[1:])})
    with pytest.raises(AuthorizedRoleEvaluationError):
        evaluate_completed_authorized_role_suite_exact_json(
            harness.suite,
            tampered,
            evidence_reader=_reader(harness),
        )
    foreign_payload = sidecar.model_dump(mode="json")
    foreign_payload["run_id"] = "authorized-role-v3-foreign"
    for trial in foreign_payload["trials"]:
        trial["run_id"] = "authorized-role-v3-foreign"
    foreign_run = AuthorizedRoleSuiteSidecarV3.model_validate(foreign_payload)
    with pytest.raises(AuthorizedRoleEvaluationError):
        evaluate_completed_authorized_role_suite_exact_json(
            harness.suite,
            foreign_run,
            evidence_reader=_reader(harness),
        )


def test_v3_sidecar_rejects_short_long_and_duplicate_trial_sets(tmp_path: Path) -> None:
    sidecar = _run(_harness(tmp_path))
    payload = sidecar.model_dump(mode="json")
    for trials in (
        payload["trials"][:-1],
        [*payload["trials"], payload["trials"][0]],
        [payload["trials"][0], payload["trials"][0], *payload["trials"][2:]],
    ):
        with pytest.raises(ValidationError):
            AuthorizedRoleSuiteSidecarV3.model_validate({**payload, "trials": trials})


def test_receipt_verification_precedes_private_artifact_read(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    sidecar = _run(harness)
    manifest = harness.manifest_store.read_manifest(sidecar.private_manifest_handle)
    harness.output_store.artifact_reads = 0
    harness.output_store.response_reads = 0
    rejecting = RejectingVerifier()
    reader = AuthorizedRoleCompletionEvidenceReaderV2(
        manifest_store=harness.manifest_store,
        output_store=harness.output_store,
        completion_verifier=rejecting,
    )

    with pytest.raises(AuthorizedRoleReconciliationRequired):
        reader.read_response(
            manifest=manifest,
            entry=manifest.outputs[0],
            expected_bundle_id=harness.prepared[0].work_bundle.bundle_id.value,
        )
    assert rejecting.calls == 1
    assert harness.output_store.artifact_reads == 0
    assert harness.output_store.response_reads == 0


def test_reader_uses_one_verified_artifact_snapshot_not_store_read_response(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    sidecar = _run(harness)
    manifest = harness.manifest_store.read_manifest(sidecar.private_manifest_handle)
    harness.output_store.artifact_reads = 0
    harness.output_store.response_reads = 0
    reader = _reader(harness)

    response = reader.read_response(
        manifest=manifest,
        entry=manifest.outputs[0],
        expected_bundle_id=harness.prepared[0].work_bundle.bundle_id.value,
    )

    assert response.text == '{"private_response": "PRIVATE_V3_RESPONSE_0"}'
    # The service verifies its configured store first; the reader then snapshots the same ref.
    assert harness.output_store.artifact_reads == 2
    assert harness.output_store.response_reads == 0


@pytest.mark.parametrize("mutation", ("text", "tool", "response_id"))
def test_reader_rejects_substituted_artifact_fields_without_read_response(
    tmp_path: Path,
    mutation: str,
) -> None:
    harness = _harness(tmp_path)
    sidecar = _run(harness)
    manifest = harness.manifest_store.read_manifest(sidecar.private_manifest_handle)
    substituted = SubstitutingStore((tmp_path / "private-output").resolve(), mutation=mutation)
    reader = AuthorizedRoleCompletionEvidenceReaderV2(
        manifest_store=harness.manifest_store,
        output_store=substituted,
        completion_verifier=harness.service,
    )

    with pytest.raises(AuthorizedRoleReconciliationRequired):
        reader.read_response(
            manifest=manifest,
            entry=manifest.outputs[0],
            expected_bundle_id=harness.prepared[0].work_bundle.bundle_id.value,
        )
    assert substituted.artifact_reads == 1
    assert substituted.response_reads == 0


@pytest.mark.parametrize("replacement", ("digest", "size"))
def test_reader_rejects_receipt_artifact_reference_replacement(
    tmp_path: Path,
    replacement: str,
) -> None:
    harness = _harness(tmp_path)
    sidecar = _run(harness)
    manifest = harness.manifest_store.read_manifest(sidecar.private_manifest_handle)
    original = manifest.outputs[0]
    harness.output_store.artifact_reads = 0
    harness.output_store.response_reads = 0
    reference = original.receipt.record.private_output.artifact
    if replacement == "digest":
        altered_artifact = ModelResponseArtifactV1(
            provider_id="fake",
            model_id="role-v3-model",
            response_id="different-artifact",
            text="different-artifact",
            tool_calls=(),
            usage=ModelResponseUsageV1(
                input_tokens=10,
                cached_input_tokens=2,
                output_tokens=3,
            ),
        )
        altered_reference = reference.model_copy(
            update={"artifact_digest": altered_artifact.artifact_digest()}
        )
    else:
        altered_reference = reference.model_copy(update={"size_bytes": reference.size_bytes + 1})
    altered_private_output = original.receipt.record.private_output.model_copy(
        update={"artifact": altered_reference}
    )
    # A normal contract reconstruction rejects this by the public commitment validator.  Model
    # construction is not a trust boundary, so also emulate a privileged in-memory replacement.
    altered_record = copy.deepcopy(original.receipt.record)
    object.__setattr__(altered_record, "private_output", altered_private_output)
    altered_receipt = copy.deepcopy(original.receipt)
    object.__setattr__(altered_receipt, "record", altered_record)
    altered_entry = copy.deepcopy(original)
    object.__setattr__(altered_entry, "receipt", altered_receipt)
    altered_manifest = copy.deepcopy(manifest)
    object.__setattr__(
        altered_manifest,
        "outputs",
        (altered_entry, *altered_manifest.outputs[1:]),
    )

    with pytest.raises(AuthorizedRoleReconciliationRequired):
        _reader(harness).read_response(
            manifest=altered_manifest,
            entry=altered_entry,
            expected_bundle_id=harness.prepared[0].work_bundle.bundle_id.value,
        )
    assert harness.output_store.artifact_reads == 0
    assert harness.output_store.response_reads == 0


def test_missing_completion_configuration_blocks_provider_before_first_call(tmp_path: Path) -> None:
    harness = _harness(tmp_path, completion_configured=False)

    with pytest.raises(PolicyViolation):
        _run(harness)
    assert harness.provider.calls == 0


def test_recovery_settles_without_provider_rerun(tmp_path: Path) -> None:
    signer = FailOnceCompletionSigner(HmacAttestationSignerV1(_COMPLETION_KEY, clock=_clock))
    harness = _harness(tmp_path, completion_signer=signer)

    with pytest.raises(ModelExecutionCompletionRecoveryRequired) as captured:
        _run(harness)
    assert harness.provider.calls == 1
    completed = harness.registry.recover_completed(
        captured.value.recovery_handle,
        output_store=harness.output_store,
    )
    assert (
        completed.receipt.record.authorization.bundle_id
        == harness.prepared[0].work_bundle.bundle_id
    )
    assert harness.provider.calls == 1
