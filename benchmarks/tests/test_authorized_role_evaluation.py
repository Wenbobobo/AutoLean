from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest
from autolean_contracts import canonical_json_bytes
from autolean_prover.providers import ModelResponse, TokenUsage

from benchmarks.authorized_role_bridge import (
    AuthorizedRoleAuthenticatedManifestHandleV1,
    AuthorizedRoleBridgeError,
    AuthorizedRoleGenerationPolicyV1,
    AuthorizedRolePrivateManifestV1,
    AuthorizedRolePrivateOutputEntryV1,
    AuthorizedRolePrivateReconciliationV1,
    AuthorizedRolePublicUsageSummaryV1,
    AuthorizedRoleRawOutputStore,
    AuthorizedRoleReconciliationRequired,
    AuthorizedRoleSuiteDefinition,
    AuthorizedRoleSuiteSidecarV1,
    AuthorizedRoleSuiteSidecarV2,
    AuthorizedRoleTrialSidecarV1,
    AuthorizedRoleTrialSidecarV2,
    authorized_role_suite_usage_summary,
    authorized_role_trial_usage_summary,
    build_locked_calibration_floor_suite,
    prepare_locked_floor_trials,
)
from benchmarks.authorized_role_bridge import (
    TestOnlyHmacPrivateManifestAuthenticator as PrivateManifestHmacFixture,
)
from benchmarks.authorized_role_evaluation import (
    AuthorizedRoleEvaluationError,
    evaluate_authorized_role_suite_exact_json,
)
from benchmarks.role_benchmark import RoleModelTargetV1

_GENERATION_POLICY = AuthorizedRoleGenerationPolicyV1(
    reasoning_effort="high",
    timeout_seconds=37,
)
_PRIVATE_SECRET = b"authorized-role-evaluation-test-secret-v1"


@dataclass(frozen=True, slots=True)
class _EvaluationFixture:
    suite: AuthorizedRoleSuiteDefinition
    sidecar: AuthorizedRoleSuiteSidecarV2
    manifest: AuthorizedRolePrivateManifestV1
    store: AuthorizedRoleRawOutputStore
    root: Path


def _target(*, configuration_hash: str = "a" * 64) -> RoleModelTargetV1:
    return RoleModelTargetV1(
        provider_id="deepseek",
        model_id="deepseek-v4-pro",
        model_revision="operator-profile-v1",
        provider_configuration_hash=configuration_hash,
        generation_parameters_hash=_GENERATION_POLICY.content_hash(),
    )


def _suite(*, configuration_hash: str = "a" * 64) -> AuthorizedRoleSuiteDefinition:
    return build_locked_calibration_floor_suite(
        _target(configuration_hash=configuration_hash),
        generation_policy=_GENERATION_POLICY,
        repetitions=1,
        max_cost_microusd_per_trial=100_000,
    )


def _authenticator(
    secret: bytes = _PRIVATE_SECRET,
) -> PrivateManifestHmacFixture:
    return PrivateManifestHmacFixture(secret)


def _build_fixture(
    tmp_path: Path,
    *,
    run_id: str = "deepseek-local-evaluation-1",
    response_overrides: dict[int, str] | None = None,
    response_ids_none: bool = False,
) -> _EvaluationFixture:
    suite = _suite()
    root = tmp_path / "operator-private"
    store = AuthorizedRoleRawOutputStore(
        root,
        private_authenticator=_authenticator(),
    )
    prepared = prepare_locked_floor_trials(suite, run_id=run_id)
    cases = {case.case_id: case for case in suite.matrix.cases}
    overrides = {} if response_overrides is None else response_overrides
    public_trials: list[AuthorizedRoleTrialSidecarV2] = []
    private_outputs: list[AuthorizedRolePrivateOutputEntryV1] = []

    for index, trial in enumerate(prepared):
        authorization_hash = hashlib.sha256(f"{run_id}:authorization:{index}".encode()).hexdigest()
        response_text = overrides.get(
            index,
            canonical_json_bytes(cases[trial.context.case_id].expected_output).decode("ascii"),
        )
        pending = store.begin_provider_call(
            bundle_id=trial.work_bundle.bundle_id.value,
            authorization_hash=authorization_hash,
        )
        persisted = store.persist_provider_response(
            pending,
            ModelResponse(
                provider_id=trial.cell.model.provider_id,
                model_id=trial.cell.model.model_id,
                response_id=None if response_ids_none else f"private-response-{index}",
                text=response_text,
                usage=TokenUsage(
                    input_tokens=10,
                    cached_input_tokens=2,
                    output_tokens=3,
                ),
            ),
            elapsed_ms=index + 1,
        )
        assert persisted.output_hash is not None
        assert persisted.elapsed_ms is not None
        assert persisted.input_tokens is not None
        assert persisted.cached_input_tokens is not None
        assert persisted.output_tokens is not None
        public_trials.append(
            AuthorizedRoleTrialSidecarV2(
                run_id=run_id,
                cell_id=trial.context.cell_id,
                case_id=trial.context.case_id,
                repetition=trial.work_bundle.repetition,
                role=trial.work_bundle.role,
                work_item_hash=trial.context.work_item_hash,
                model_work_bundle_hash=trial.work_bundle.handoff_hash().value,
                authorization_hash=authorization_hash,
                provider_id=trial.cell.model.provider_id,
                model_id=trial.cell.model.model_id,
                model_revision=trial.cell.model.model_revision,
                provider_configuration_hash=trial.cell.model.provider_configuration_hash,
                context_pack_hash=trial.work_bundle.context_pack_hash.value,
                request_hash=trial.work_bundle.request_hash.value,
                work_evidence_hash=trial.work_evidence.content_hash(),
                usage_summary=authorized_role_trial_usage_summary(
                    input_tokens=persisted.input_tokens,
                    cached_input_tokens=persisted.cached_input_tokens,
                    output_tokens=persisted.output_tokens,
                    elapsed_ms=persisted.elapsed_ms,
                ),
            )
        )
        private_outputs.append(
            AuthorizedRolePrivateOutputEntryV1(
                cell_id=trial.context.cell_id,
                case_id=trial.context.case_id,
                repetition=trial.work_bundle.repetition,
                private_reconciliation_handle=persisted.private_handle,
                output_hash=persisted.output_hash,
                authorization_hash=authorization_hash,
                elapsed_ms=persisted.elapsed_ms,
                input_tokens=persisted.input_tokens,
                cached_input_tokens=persisted.cached_input_tokens,
                output_tokens=persisted.output_tokens,
            )
        )

    manifest = AuthorizedRolePrivateManifestV1(
        run_id=run_id,
        outputs=tuple(private_outputs),
    )
    private_manifest_handle = store.put_manifest(manifest)
    sidecar = AuthorizedRoleSuiteSidecarV2(
        run_id=run_id,
        private_manifest_handle=private_manifest_handle,
        usage_summary=authorized_role_suite_usage_summary(manifest.outputs),
        trials=tuple(public_trials),
    )
    return _EvaluationFixture(
        suite=suite,
        sidecar=sidecar,
        manifest=manifest,
        store=store,
        root=root,
    )


def _private_files(root: Path) -> tuple[tuple[str, str], ...]:
    return tuple(
        (
            path.relative_to(root).as_posix(),
            hashlib.sha256(path.read_bytes()).hexdigest(),
        )
        for path in sorted(root.rglob("*"))
        if path.is_file()
    )


def _coordinate_hash(sidecar: AuthorizedRoleTrialSidecarV2) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "schema_version": "autolean.authorized-role-evaluation-coordinate.v1",
                "run_id": sidecar.run_id,
                "cell_id": sidecar.cell_id,
                "case_id": sidecar.case_id,
                "repetition": sidecar.repetition,
                "role": sidecar.role.value,
            }
        )
    ).hexdigest()


def _legacy_unkeyed_output_commitment(
    sidecar: AuthorizedRoleTrialSidecarV2,
    private_output_hash: str,
) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "schema_version": "autolean.authorized-role-output-commitment.v1",
                "coordinate_hash": _coordinate_hash(sidecar),
                "private_output_hash": private_output_hash,
            }
        )
    ).hexdigest()


def test_exact_json_evaluation_is_read_only_role_separated_and_nonpromotable(
    tmp_path: Path,
) -> None:
    fixture = _build_fixture(tmp_path)
    before = _private_files(fixture.root)

    report = evaluate_authorized_role_suite_exact_json(
        fixture.suite,
        fixture.sidecar,
        raw_output_store=fixture.store,
    )

    assert _private_files(fixture.root) == before
    assert len(report.trials) == 10
    assert all(item.passed and item.score_micros == 1_000_000 for item in report.trials)
    assert len(report.role_metrics) == 5
    assert all(
        item.trials == 2
        and item.passed == 2
        and item.pass_rate_ppm == 1_000_000
        and item.mean_score_micros == 1_000_000
        for item in report.role_metrics
    )
    assert report.authority == "local_exact_json_nonproduction"
    assert report.promotion_eligible is False
    assert report.role_floor_admission == "forbidden"
    assert report.cross_role_aggregation_permitted is False
    output_commitments = {item.output_commitment for item in report.trials}
    private_output_hashes = {item.output_hash for item in fixture.manifest.outputs}
    assert len(output_commitments) == 10
    assert output_commitments.isdisjoint(private_output_hashes)


@pytest.mark.parametrize(
    "unsafe_run_id",
    [
        "run:private-marker",
        "run/private-marker",
        r"run\private-marker",
        r"C:\private-marker",
        r"\\server\private-marker",
        "..",
        "run..private-marker",
        ".run",
        "run.",
        "run private-marker",
    ],
)
def test_unsafe_run_ids_are_rejected_without_reflection(
    unsafe_run_id: str,
) -> None:
    with pytest.raises(AuthorizedRoleBridgeError) as captured:
        prepare_locked_floor_trials(_suite(), run_id=unsafe_run_id)

    assert unsafe_run_id not in str(captured.value)


def test_safe_run_id_accepts_portable_ascii_slug() -> None:
    prepared = prepare_locked_floor_trials(_suite(), run_id="Run_2026.alpha-1")

    assert len(prepared) == 10
    assert all(item.context.run_id == "Run_2026.alpha-1" for item in prepared)


def test_private_run_id_schema_hides_rejected_input(tmp_path: Path) -> None:
    fixture = _build_fixture(tmp_path)
    private_marker = r"C:\DO_NOT_REFLECT_PRIVATE_RUN"
    payload = fixture.manifest.model_dump(mode="json")
    payload["run_id"] = private_marker

    with pytest.raises(ValueError) as captured:
        AuthorizedRolePrivateManifestV1.model_validate(payload)

    assert private_marker not in str(captured.value)
    handle_path = (
        fixture.root
        / "authorized-role-manifest-handles"
        / f"{fixture.sidecar.private_manifest_handle}.json"
    )
    handle_payload = json.loads(handle_path.read_bytes())
    handle_payload["binding"]["run_id"] = private_marker
    with pytest.raises(ValueError) as nested:
        AuthorizedRoleAuthenticatedManifestHandleV1.model_validate(handle_payload)
    assert private_marker not in str(nested.value)


def test_suite_usage_summary_drift_is_rejected(tmp_path: Path) -> None:
    fixture = _build_fixture(tmp_path)
    drifted = fixture.sidecar.model_copy(
        update={
            "usage_summary": fixture.sidecar.usage_summary.model_copy(
                update={"aggregate_input_tokens_bucket": "zero"}
            )
        }
    )

    with pytest.raises(AuthorizedRoleEvaluationError, match="evidence is invalid"):
        evaluate_authorized_role_suite_exact_json(
            fixture.suite,
            drifted,
            raw_output_store=fixture.store,
        )


def test_trial_usage_summary_drift_is_rejected(tmp_path: Path) -> None:
    fixture = _build_fixture(tmp_path)
    trials = list(fixture.sidecar.trials)
    trials[0] = trials[0].model_copy(
        update={
            "usage_summary": trials[0].usage_summary.model_copy(
                update={"elapsed_ms_bucket": "300s_plus"}
            )
        }
    )
    drifted = fixture.sidecar.model_copy(update={"trials": tuple(trials)})

    with pytest.raises(AuthorizedRoleEvaluationError, match="evidence is invalid"):
        evaluate_authorized_role_suite_exact_json(
            fixture.suite,
            drifted,
            raw_output_store=fixture.store,
        )


def test_legacy_sidecar_without_trial_usage_is_rejected(tmp_path: Path) -> None:
    fixture = _build_fixture(tmp_path)
    legacy_trials = tuple(
        AuthorizedRoleTrialSidecarV1.model_validate(
            {
                key: value
                for key, value in trial.model_dump(mode="json").items()
                if key not in {"schema_version", "usage_summary"}
            }
        )
        for trial in fixture.sidecar.trials
    )
    legacy = AuthorizedRoleSuiteSidecarV1(
        run_id=fixture.sidecar.run_id,
        private_manifest_handle=fixture.sidecar.private_manifest_handle,
        usage_summary=AuthorizedRolePublicUsageSummaryV1(
            aggregate_input_tokens_bucket=(
                fixture.sidecar.usage_summary.aggregate_input_tokens_bucket
            ),
            aggregate_cached_input_tokens_bucket=(
                fixture.sidecar.usage_summary.aggregate_cached_input_tokens_bucket
            ),
            aggregate_output_tokens_bucket=(
                fixture.sidecar.usage_summary.aggregate_output_tokens_bucket
            ),
            aggregate_elapsed_ms_bucket=(fixture.sidecar.usage_summary.aggregate_elapsed_ms_bucket),
        ),
        trials=legacy_trials,
    )

    with pytest.raises(AuthorizedRoleEvaluationError, match="evidence is invalid"):
        evaluate_authorized_role_suite_exact_json(
            fixture.suite,
            cast(AuthorizedRoleSuiteSidecarV2, legacy),
            raw_output_store=fixture.store,
        )


def test_wrong_reconciliation_bundle_id_is_rejected(tmp_path: Path) -> None:
    fixture = _build_fixture(tmp_path)
    first = fixture.manifest.outputs[0]
    state_path = (
        fixture.root
        / "authorized-role-reconciliation"
        / f"{first.private_reconciliation_handle}.json"
    )
    state = AuthorizedRolePrivateReconciliationV1.model_validate_json(state_path.read_bytes())
    prepared = prepare_locked_floor_trials(fixture.suite, run_id=fixture.sidecar.run_id)
    wrong_bundle_id = prepared[1].work_bundle.bundle_id.value
    assert state.bundle_id != wrong_bundle_id
    state_path.write_bytes(
        canonical_json_bytes(state.model_copy(update={"bundle_id": wrong_bundle_id}))
    )

    with pytest.raises(AuthorizedRoleEvaluationError, match="evidence is invalid"):
        evaluate_authorized_role_suite_exact_json(
            fixture.suite,
            fixture.sidecar,
            raw_output_store=fixture.store,
        )


def test_keyed_commitment_is_stable_and_not_an_enumerable_cas_locator(
    tmp_path: Path,
) -> None:
    fixture = _build_fixture(tmp_path, response_ids_none=True)

    first = evaluate_authorized_role_suite_exact_json(
        fixture.suite,
        fixture.sidecar,
        raw_output_store=fixture.store,
    )
    second = evaluate_authorized_role_suite_exact_json(
        fixture.suite,
        fixture.sidecar,
        raw_output_store=fixture.store,
    )

    assert tuple(item.output_commitment for item in first.trials) == tuple(
        item.output_commitment for item in second.trials
    )
    by_coordinate = {item.coordinate_hash: item for item in first.trials}
    legacy_commitments: set[str] = set()
    for public, private in zip(
        fixture.sidecar.trials,
        fixture.manifest.outputs,
        strict=True,
    ):
        coordinate_hash = _coordinate_hash(public)
        old_commitment = _legacy_unkeyed_output_commitment(public, private.output_hash)
        legacy_commitments.add(old_commitment)
        assert by_coordinate[coordinate_hash].output_commitment not in {
            private.output_hash,
            old_commitment,
        }
    payload = first.canonical_json_bytes().decode("ascii")
    assert all(item.output_hash not in payload for item in fixture.manifest.outputs)
    assert all(item not in payload for item in legacy_commitments)


@pytest.mark.parametrize(
    "invalid_text",
    [
        '{"answer":1,"answer":1}',
        '{"answer":{"nested":1,"nested":2}}',
        '{"answer":NaN}',
        '{"answer":1e999}',
        "[]",
        '"object required"',
        '{"truncated":',
    ],
)
def test_invalid_or_ambiguous_json_scores_zero_without_leaking_parser_errors(
    tmp_path: Path,
    invalid_text: str,
) -> None:
    fixture = _build_fixture(tmp_path, response_overrides={0: invalid_text})

    report = evaluate_authorized_role_suite_exact_json(
        fixture.suite,
        fixture.sidecar,
        raw_output_store=fixture.store,
    )

    assert sum(item.passed for item in report.trials) == 9
    assert sorted(item.score_micros for item in report.trials).count(0) == 1
    assert invalid_text not in report.canonical_json_bytes().decode("ascii")


def test_sidecar_authorization_substitution_is_rejected(tmp_path: Path) -> None:
    fixture = _build_fixture(tmp_path)
    trials = list(fixture.sidecar.trials)
    trials[0] = trials[0].model_copy(update={"authorization_hash": trials[1].authorization_hash})
    substituted = fixture.sidecar.model_copy(update={"trials": tuple(trials)})

    with pytest.raises(AuthorizedRoleEvaluationError, match="evidence is invalid"):
        evaluate_authorized_role_suite_exact_json(
            fixture.suite,
            substituted,
            raw_output_store=fixture.store,
        )


def test_duplicate_run_manifest_is_rejected_by_private_run_index(
    tmp_path: Path,
) -> None:
    fixture = _build_fixture(tmp_path)
    outputs = list(fixture.manifest.outputs)
    outputs[0] = outputs[0].model_copy(update={"output_hash": outputs[1].output_hash})
    substituted_manifest = fixture.manifest.model_copy(update={"outputs": tuple(outputs)})

    with pytest.raises(AuthorizedRoleReconciliationRequired, match="run index already exists"):
        fixture.store.put_manifest(substituted_manifest)


def test_signed_output_substitution_is_rejected_by_reconciliation_binding(
    tmp_path: Path,
) -> None:
    fixture = _build_fixture(tmp_path)
    outputs = list(fixture.manifest.outputs)
    outputs[0] = outputs[0].model_copy(update={"output_hash": outputs[1].output_hash})
    substituted_manifest = fixture.manifest.model_copy(update={"outputs": tuple(outputs)})

    # Remove only the disposable test run index so this isolated fixture can exercise the
    # downstream response-to-reconciliation binding independently of the earlier no-clobber gate.
    run_key = hashlib.sha256(fixture.manifest.run_id.encode("utf-8")).hexdigest()
    (fixture.root / "authorized-role-run-index" / f"{run_key}.json").unlink()
    substituted_handle = fixture.store.put_manifest(substituted_manifest)
    substituted_sidecar = fixture.sidecar.model_copy(
        update={"private_manifest_handle": substituted_handle}
    )

    with pytest.raises(AuthorizedRoleEvaluationError, match="evidence is invalid"):
        evaluate_authorized_role_suite_exact_json(
            fixture.suite,
            substituted_sidecar,
            raw_output_store=fixture.store,
        )


def test_truncated_authenticated_handle_is_rejected(tmp_path: Path) -> None:
    fixture = _build_fixture(tmp_path)
    handle_path = (
        fixture.root
        / "authorized-role-manifest-handles"
        / f"{fixture.sidecar.private_manifest_handle}.json"
    )
    payload = handle_path.read_bytes()
    handle_path.write_bytes(payload[: len(payload) // 2])

    with pytest.raises(AuthorizedRoleEvaluationError, match="evidence is invalid"):
        evaluate_authorized_role_suite_exact_json(
            fixture.suite,
            fixture.sidecar,
            raw_output_store=fixture.store,
        )


def test_wrong_private_authenticator_is_rejected(tmp_path: Path) -> None:
    fixture = _build_fixture(tmp_path)
    wrong_store = AuthorizedRoleRawOutputStore(
        fixture.root,
        private_authenticator=_authenticator(b"wrong-private-authenticator-secret-v1"),
    )

    with pytest.raises(AuthorizedRoleEvaluationError, match="evidence is invalid"):
        evaluate_authorized_role_suite_exact_json(
            fixture.suite,
            fixture.sidecar,
            raw_output_store=wrong_store,
        )


def test_wrong_locked_suite_is_rejected(tmp_path: Path) -> None:
    fixture = _build_fixture(tmp_path)
    wrong_suite = _suite(configuration_hash="b" * 64)

    with pytest.raises(AuthorizedRoleEvaluationError, match="evidence is invalid"):
        evaluate_authorized_role_suite_exact_json(
            wrong_suite,
            fixture.sidecar,
            raw_output_store=fixture.store,
        )


def test_cross_run_sidecar_is_rejected(tmp_path: Path) -> None:
    fixture = _build_fixture(tmp_path)
    wrong_run_id = "deepseek-local-evaluation-other-run"
    cross_run = fixture.sidecar.model_copy(
        update={
            "run_id": wrong_run_id,
            "trials": tuple(
                item.model_copy(update={"run_id": wrong_run_id}) for item in fixture.sidecar.trials
            ),
        }
    )

    with pytest.raises(AuthorizedRoleEvaluationError, match="evidence is invalid"):
        evaluate_authorized_role_suite_exact_json(
            fixture.suite,
            cross_run,
            raw_output_store=fixture.store,
        )


def test_response_cas_corruption_is_rejected(tmp_path: Path) -> None:
    fixture = _build_fixture(tmp_path)
    output_hash = fixture.manifest.outputs[0].output_hash
    artifact_path = fixture.root / "sha256" / output_hash[:2] / output_hash[2:4] / output_hash
    artifact_path.write_bytes(b'{"corrupted":true}')

    with pytest.raises(AuthorizedRoleEvaluationError, match="evidence is invalid"):
        evaluate_authorized_role_suite_exact_json(
            fixture.suite,
            fixture.sidecar,
            raw_output_store=fixture.store,
        )


def test_public_report_persists_no_oracle_raw_secret_path_or_manifest_identity(
    tmp_path: Path,
) -> None:
    private_marker = "DO_NOT_PERSIST_PRIVATE_RESPONSE_MARKER"
    fixture = _build_fixture(
        tmp_path,
        response_overrides={0: f'{{"private":"{private_marker}"}}'},
    )
    manifest_hash = fixture.store.resolve_manifest_handle(fixture.sidecar.private_manifest_handle)

    report = evaluate_authorized_role_suite_exact_json(
        fixture.suite,
        fixture.sidecar,
        raw_output_store=fixture.store,
    )
    payload = report.canonical_json_bytes().decode("ascii")
    parsed = report.model_dump(mode="json")

    assert set(parsed) == {
        "schema_version",
        "run_id",
        "provider_id",
        "model_id",
        "model_revision",
        "provider_configuration_hash",
        "evaluator_hash",
        "authority",
        "promotion_eligible",
        "role_floor_admission",
        "cross_role_aggregation_permitted",
        "trials",
        "role_metrics",
    }
    assert all(
        set(item)
        == {
            "schema_version",
            "coordinate_hash",
            "role",
            "passed",
            "score_micros",
            "output_commitment",
        }
        for item in parsed["trials"]
    )
    for forbidden in (
        private_marker,
        fixture.sidecar.private_manifest_handle,
        manifest_hash,
        str(fixture.root),
        _PRIVATE_SECRET.decode(),
        '"expected_output"',
        '"private_reconciliation_handle"',
        '"manifest_hash"',
        '"response_id"',
        '"error"',
        *(item.output_hash for item in fixture.manifest.outputs),
    ):
        assert forbidden not in payload
