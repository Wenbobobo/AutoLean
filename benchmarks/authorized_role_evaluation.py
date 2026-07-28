"""Private exact-JSON evaluation for the authorized five-role operator suite.

This evaluator is deliberately independent of the scripted-fake V3 harness.  It consumes
authenticated operator-private responses only after the locked suite, public sidecar, and private
manifest have been joined exactly.  Its report is local, non-production evidence and cannot admit
a model to the role floor.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from typing import Literal, Never, Self

from autolean_contracts import (
    ContractModel,
    ModelWorkRoleV1,
    canonical_json_bytes,
    model_execution_completion_public,
)
from pydantic import ConfigDict, Field, model_validator

from benchmarks.authorized_role_bridge import (
    AuthorizedRoleCompletionEvidenceReaderV2,
    AuthorizedRoleCompletionPrivateManifestV2,
    AuthorizedRoleCompletionPrivateOutputEntryV2,
    AuthorizedRolePrivateManifestV1,
    AuthorizedRolePrivateOutputEntryV1,
    AuthorizedRoleRawOutputStore,
    AuthorizedRoleRunIdV1,
    AuthorizedRoleSuiteDefinition,
    AuthorizedRoleSuiteSidecarV2,
    AuthorizedRoleSuiteSidecarV3,
    AuthorizedRoleTrialSidecarV2,
    AuthorizedRoleTrialSidecarV3,
    PreparedAuthorizedRoleTrial,
    authorized_role_completion_suite_usage_summary,
    authorized_role_suite_usage_summary,
    authorized_role_trial_usage_summary,
    prepare_locked_floor_trials,
)

_IDENTIFIER_PATTERN = r"^[a-z0-9][a-z0-9_.:/-]{0,127}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_ONE_MILLION = 1_000_000
_INVALID_EVIDENCE = "authorized role evaluation evidence is invalid"


class AuthorizedRoleEvaluationError(ValueError):
    """Authenticated private evidence did not match the exact locked public suite."""


class AuthorizedRoleExactJsonTrialResultV1(ContractModel):
    """Public commitment and exact-JSON result for one opaque trial coordinate."""

    schema_version: Literal["autolean.authorized-role-exact-json-trial.v1"] = (
        "autolean.authorized-role-exact-json-trial.v1"
    )
    coordinate_hash: str = Field(pattern=_SHA256_PATTERN)
    role: ModelWorkRoleV1
    passed: bool
    score_micros: int = Field(ge=0, le=_ONE_MILLION)
    output_commitment: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_exact_score(self) -> Self:
        if self.score_micros != (_ONE_MILLION if self.passed else 0):
            raise ValueError("exact JSON score must match passed")
        return self


class AuthorizedRoleExactJsonRoleMetricsV1(ContractModel):
    """Metrics for one role; cross-role aggregation is intentionally absent."""

    schema_version: Literal["autolean.authorized-role-exact-json-role-metrics.v1"] = (
        "autolean.authorized-role-exact-json-role-metrics.v1"
    )
    role: ModelWorkRoleV1
    trials: Literal[2] = 2
    passed: int = Field(ge=0, le=2)
    pass_rate_ppm: int = Field(ge=0, le=_ONE_MILLION)
    mean_score_micros: int = Field(ge=0, le=_ONE_MILLION)

    @model_validator(mode="after")
    def validate_metrics(self) -> Self:
        expected = self.passed * _ONE_MILLION // self.trials
        if self.pass_rate_ppm != expected or self.mean_score_micros != expected:
            raise ValueError("role metrics do not match exact JSON pass count")
        return self


class AuthorizedRoleExactJsonEvaluationReportV1(ContractModel):
    """Sanitized local report that carries no oracle, raw response, path, or manifest digest."""

    schema_version: Literal["autolean.authorized-role-exact-json-evaluation.v1"] = (
        "autolean.authorized-role-exact-json-evaluation.v1"
    )
    model_config = ConfigDict(hide_input_in_errors=True)

    run_id: AuthorizedRoleRunIdV1
    provider_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    model_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    model_revision: str = Field(min_length=1, max_length=512)
    provider_configuration_hash: str = Field(pattern=_SHA256_PATTERN)
    evaluator_hash: str = Field(pattern=_SHA256_PATTERN)
    authority: Literal["local_exact_json_nonproduction"] = "local_exact_json_nonproduction"
    promotion_eligible: Literal[False] = False
    role_floor_admission: Literal["forbidden"] = "forbidden"
    cross_role_aggregation_permitted: Literal[False] = False
    trials: tuple[AuthorizedRoleExactJsonTrialResultV1, ...]
    role_metrics: tuple[AuthorizedRoleExactJsonRoleMetricsV1, ...]

    @model_validator(mode="after")
    def validate_report(self) -> Self:
        if (
            len(self.trials) != 10
            or self.trials != tuple(sorted(self.trials, key=lambda item: item.coordinate_hash))
            or len({item.coordinate_hash for item in self.trials}) != 10
        ):
            raise ValueError("evaluation report requires ten canonical opaque trials")
        expected_metrics = _role_metrics(self.trials)
        if self.role_metrics != expected_metrics:
            raise ValueError("evaluation report role metrics do not match its trials")
        return self

    def canonical_json_bytes(self) -> bytes:
        return canonical_json_bytes(self) + b"\n"


def evaluate_authorized_role_suite_exact_json(
    suite: AuthorizedRoleSuiteDefinition,
    sidecar: AuthorizedRoleSuiteSidecarV2,
    *,
    raw_output_store: AuthorizedRoleRawOutputStore,
) -> AuthorizedRoleExactJsonEvaluationReportV1:
    """Evaluate a locked suite through authenticated private reads without V3 persistence."""

    try:
        return _evaluate_authorized_role_suite_exact_json(
            suite,
            sidecar,
            raw_output_store=raw_output_store,
        )
    except AuthorizedRoleEvaluationError:
        raise
    except Exception:
        raise AuthorizedRoleEvaluationError(_INVALID_EVIDENCE) from None


def evaluate_completed_authorized_role_suite_exact_json(
    suite: AuthorizedRoleSuiteDefinition,
    sidecar: AuthorizedRoleSuiteSidecarV3,
    *,
    evidence_reader: AuthorizedRoleCompletionEvidenceReaderV2,
) -> AuthorizedRoleExactJsonEvaluationReportV1:
    """Score V3 output-bound completions through a read-only private evidence boundary."""

    try:
        return _evaluate_completed_authorized_role_suite_exact_json(
            suite,
            sidecar,
            evidence_reader=evidence_reader,
        )
    except AuthorizedRoleEvaluationError:
        raise
    except Exception:
        raise AuthorizedRoleEvaluationError(_INVALID_EVIDENCE) from None


def _evaluate_authorized_role_suite_exact_json(
    suite: AuthorizedRoleSuiteDefinition,
    sidecar: AuthorizedRoleSuiteSidecarV2,
    *,
    raw_output_store: AuthorizedRoleRawOutputStore,
) -> AuthorizedRoleExactJsonEvaluationReportV1:
    if not isinstance(sidecar, AuthorizedRoleSuiteSidecarV2):
        raise AuthorizedRoleEvaluationError(_INVALID_EVIDENCE)
    prepared = prepare_locked_floor_trials(suite, run_id=sidecar.run_id)
    manifest = raw_output_store.read_authenticated_manifest(sidecar.private_manifest_handle)
    joined = _validated_private_join(prepared, sidecar, manifest)
    evaluator_hash = _evaluator_hash(suite)
    cases = {case.case_id: case for case in suite.matrix.cases}

    results: list[AuthorizedRoleExactJsonTrialResultV1] = []
    for trial, public, private in joined:
        bundle_id = trial.work_bundle.bundle_id.value
        response = raw_output_store.read_authenticated_response(
            sidecar.private_manifest_handle,
            private,
            expected_bundle_id=bundle_id,
        )
        if (
            response.provider_id != public.provider_id
            or response.model_id != public.model_id
            or response.tool_calls
        ):
            raise AuthorizedRoleEvaluationError(_INVALID_EVIDENCE)
        expected_output = cases[trial.context.case_id].expected_output
        if not isinstance(expected_output, Mapping):
            raise AuthorizedRoleEvaluationError(_INVALID_EVIDENCE)
        candidate = _strict_json_object(response.text)
        passed = candidate is not None and canonical_json_bytes(candidate) == canonical_json_bytes(
            expected_output
        )
        coordinate_hash = _coordinate_hash(public)
        results.append(
            AuthorizedRoleExactJsonTrialResultV1(
                coordinate_hash=coordinate_hash,
                role=public.role,
                passed=passed,
                score_micros=_ONE_MILLION if passed else 0,
                output_commitment=raw_output_store.authenticated_output_commitment(
                    sidecar.private_manifest_handle,
                    private,
                    expected_bundle_id=bundle_id,
                    coordinate_hash=coordinate_hash,
                ),
            )
        )

    canonical_results = tuple(sorted(results, key=lambda item: item.coordinate_hash))
    first_target = suite.matrix.cells[0].model
    return AuthorizedRoleExactJsonEvaluationReportV1(
        run_id=sidecar.run_id,
        provider_id=first_target.provider_id,
        model_id=first_target.model_id,
        model_revision=first_target.model_revision,
        provider_configuration_hash=first_target.provider_configuration_hash,
        evaluator_hash=evaluator_hash,
        trials=canonical_results,
        role_metrics=_role_metrics(canonical_results),
    )


def _evaluate_completed_authorized_role_suite_exact_json(
    suite: AuthorizedRoleSuiteDefinition,
    sidecar: AuthorizedRoleSuiteSidecarV3,
    *,
    evidence_reader: AuthorizedRoleCompletionEvidenceReaderV2,
) -> AuthorizedRoleExactJsonEvaluationReportV1:
    if not isinstance(sidecar, AuthorizedRoleSuiteSidecarV3):
        raise AuthorizedRoleEvaluationError(_INVALID_EVIDENCE)
    if not isinstance(evidence_reader, AuthorizedRoleCompletionEvidenceReaderV2):
        raise AuthorizedRoleEvaluationError(_INVALID_EVIDENCE)
    prepared = prepare_locked_floor_trials(suite, run_id=sidecar.run_id)
    manifest = evidence_reader.read_manifest(sidecar.private_manifest_handle)
    joined = _validated_completed_private_join(prepared, sidecar, manifest)
    evaluator_hash = _evaluator_hash(suite)
    cases = {case.case_id: case for case in suite.matrix.cases}

    results: list[AuthorizedRoleExactJsonTrialResultV1] = []
    for trial, public, private in joined:
        response = evidence_reader.read_response(
            manifest=manifest,
            entry=private,
            expected_bundle_id=trial.work_bundle.bundle_id.value,
        )
        if (
            response.provider_id != public.provider_id
            or response.model_id != public.model_id
            or response.tool_calls
        ):
            raise AuthorizedRoleEvaluationError(_INVALID_EVIDENCE)
        expected_output = cases[trial.context.case_id].expected_output
        if not isinstance(expected_output, Mapping):
            raise AuthorizedRoleEvaluationError(_INVALID_EVIDENCE)
        candidate = _strict_json_object(response.text)
        passed = candidate is not None and canonical_json_bytes(candidate) == canonical_json_bytes(
            expected_output
        )
        results.append(
            AuthorizedRoleExactJsonTrialResultV1(
                coordinate_hash=_coordinate_hash(public),
                role=public.role,
                passed=passed,
                score_micros=_ONE_MILLION if passed else 0,
                output_commitment=public.completion.public_output_commitment.value,
            )
        )

    canonical_results = tuple(sorted(results, key=lambda item: item.coordinate_hash))
    first_target = suite.matrix.cells[0].model
    return AuthorizedRoleExactJsonEvaluationReportV1(
        run_id=sidecar.run_id,
        provider_id=first_target.provider_id,
        model_id=first_target.model_id,
        model_revision=first_target.model_revision,
        provider_configuration_hash=first_target.provider_configuration_hash,
        evaluator_hash=evaluator_hash,
        trials=canonical_results,
        role_metrics=_role_metrics(canonical_results),
    )


def _validated_private_join(
    prepared: tuple[PreparedAuthorizedRoleTrial, ...],
    sidecar: AuthorizedRoleSuiteSidecarV2,
    manifest: AuthorizedRolePrivateManifestV1,
) -> tuple[
    tuple[
        PreparedAuthorizedRoleTrial,
        AuthorizedRoleTrialSidecarV2,
        AuthorizedRolePrivateOutputEntryV1,
    ],
    ...,
]:
    if (
        manifest.run_id != sidecar.run_id
        or len(prepared) != 10
        or len(manifest.outputs) != 10
        or sidecar.usage_summary != authorized_role_suite_usage_summary(manifest.outputs)
    ):
        raise AuthorizedRoleEvaluationError(_INVALID_EVIDENCE)
    prepared_by_coordinate = {
        (
            item.context.cell_id,
            item.context.case_id,
            item.work_bundle.repetition,
        ): item
        for item in prepared
    }
    public_by_coordinate = {
        (item.cell_id, item.case_id, item.repetition): item for item in sidecar.trials
    }
    private_by_coordinate = {
        (item.cell_id, item.case_id, item.repetition): item for item in manifest.outputs
    }
    coordinates = set(prepared_by_coordinate)
    if (
        len(prepared_by_coordinate) != 10
        or set(public_by_coordinate) != coordinates
        or set(private_by_coordinate) != coordinates
    ):
        raise AuthorizedRoleEvaluationError(_INVALID_EVIDENCE)

    joined: list[
        tuple[
            PreparedAuthorizedRoleTrial,
            AuthorizedRoleTrialSidecarV2,
            AuthorizedRolePrivateOutputEntryV1,
        ]
    ] = []
    for coordinate in sorted(coordinates):
        trial = prepared_by_coordinate[coordinate]
        public = public_by_coordinate[coordinate]
        private = private_by_coordinate[coordinate]
        target = trial.cell.model
        bundle = trial.work_bundle
        if (
            public.run_id != sidecar.run_id
            or public.role != bundle.role
            or public.work_item_hash != trial.context.work_item_hash
            or public.model_work_bundle_hash != bundle.handoff_hash().value
            or public.provider_id != target.provider_id
            or public.model_id != target.model_id
            or public.model_revision != target.model_revision
            or public.provider_configuration_hash != target.provider_configuration_hash
            or public.context_pack_hash != bundle.context_pack_hash.value
            or public.request_hash != bundle.request_hash.value
            or public.work_evidence_hash != trial.work_evidence.content_hash()
            or private.authorization_hash != public.authorization_hash
            or public.usage_summary
            != authorized_role_trial_usage_summary(
                input_tokens=private.input_tokens,
                cached_input_tokens=private.cached_input_tokens,
                output_tokens=private.output_tokens,
                elapsed_ms=private.elapsed_ms,
            )
        ):
            raise AuthorizedRoleEvaluationError(_INVALID_EVIDENCE)
        joined.append((trial, public, private))
    return tuple(joined)


def _validated_completed_private_join(
    prepared: tuple[PreparedAuthorizedRoleTrial, ...],
    sidecar: AuthorizedRoleSuiteSidecarV3,
    manifest: AuthorizedRoleCompletionPrivateManifestV2,
) -> tuple[
    tuple[
        PreparedAuthorizedRoleTrial,
        AuthorizedRoleTrialSidecarV3,
        AuthorizedRoleCompletionPrivateOutputEntryV2,
    ],
    ...,
]:
    if (
        manifest.run_id != sidecar.run_id
        or len(prepared) != 10
        or len(manifest.outputs) != 10
        or sidecar.usage_summary != authorized_role_completion_suite_usage_summary(manifest.outputs)
    ):
        raise AuthorizedRoleEvaluationError(_INVALID_EVIDENCE)
    prepared_by_coordinate = {
        (
            item.context.cell_id,
            item.context.case_id,
            item.work_bundle.repetition,
        ): item
        for item in prepared
    }
    public_by_coordinate = {
        (item.cell_id, item.case_id, item.repetition): item for item in sidecar.trials
    }
    private_by_coordinate = {
        (item.cell_id, item.case_id, item.repetition): item for item in manifest.outputs
    }
    coordinates = set(prepared_by_coordinate)
    if (
        len(prepared_by_coordinate) != 10
        or set(public_by_coordinate) != coordinates
        or set(private_by_coordinate) != coordinates
    ):
        raise AuthorizedRoleEvaluationError(_INVALID_EVIDENCE)

    joined: list[
        tuple[
            PreparedAuthorizedRoleTrial,
            AuthorizedRoleTrialSidecarV3,
            AuthorizedRoleCompletionPrivateOutputEntryV2,
        ]
    ] = []
    for coordinate in sorted(coordinates):
        trial = prepared_by_coordinate[coordinate]
        public = public_by_coordinate[coordinate]
        private = private_by_coordinate[coordinate]
        target = trial.cell.model
        bundle = trial.work_bundle
        receipt = private.receipt
        authorization = receipt.record.authorization
        if (
            public.run_id != sidecar.run_id
            or public.role != bundle.role
            or public.work_item_hash != trial.context.work_item_hash
            or public.model_work_bundle_hash != bundle.handoff_hash().value
            or public.provider_id != target.provider_id
            or public.model_id != target.model_id
            or public.model_revision != target.model_revision
            or public.provider_configuration_hash != target.provider_configuration_hash
            or public.context_pack_hash != bundle.context_pack_hash.value
            or public.request_hash != bundle.request_hash.value
            or public.work_evidence_hash != trial.work_evidence.content_hash()
            or private.authorization_hash != public.authorization_hash
            or authorization.authorization_hash().value != private.authorization_hash
            or authorization.bundle_id != bundle.bundle_id
            or authorization.bundle_hash != bundle.handoff_hash()
            or public.completion != model_execution_completion_public(receipt)
            or public.usage_summary
            != authorized_role_trial_usage_summary(
                input_tokens=receipt.record.actual_usage.input_tokens,
                cached_input_tokens=receipt.record.actual_usage.cached_input_tokens,
                output_tokens=receipt.record.actual_usage.output_tokens,
                elapsed_ms=private.elapsed_ms,
            )
        ):
            raise AuthorizedRoleEvaluationError(_INVALID_EVIDENCE)
        joined.append((trial, public, private))
    return tuple(joined)


def _evaluator_hash(suite: AuthorizedRoleSuiteDefinition) -> str:
    cases = tuple(
        {
            "case_id": case.case_id,
            "role": case.role.value,
            "case_revision": case.case_revision,
            "scorer": case.scorer,
            "expected_output": case.expected_output,
        }
        for case in sorted(suite.matrix.cases, key=lambda item: item.case_id)
    )
    if len(cases) != 10 or any(
        not isinstance(case.expected_output, Mapping) for case in suite.matrix.cases
    ):
        raise AuthorizedRoleEvaluationError(_INVALID_EVIDENCE)
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "schema_version": "autolean.authorized-role-exact-json-evaluator.v1",
                "comparison": "strict-object-parse-canonical-json-exact-v1",
                "matrix_revision": suite.matrix.matrix_revision,
                "cases": cases,
            }
        )
    ).hexdigest()


def _coordinate_hash(sidecar: AuthorizedRoleTrialSidecarV2 | AuthorizedRoleTrialSidecarV3) -> str:
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


def _role_metrics(
    trials: tuple[AuthorizedRoleExactJsonTrialResultV1, ...],
) -> tuple[AuthorizedRoleExactJsonRoleMetricsV1, ...]:
    metrics: list[AuthorizedRoleExactJsonRoleMetricsV1] = []
    for role in sorted(ModelWorkRoleV1, key=lambda item: item.value):
        selected = tuple(item for item in trials if item.role is role)
        if len(selected) != 2:
            raise ValueError("each authorized role requires exactly two trials")
        passed = sum(item.passed for item in selected)
        score = passed * _ONE_MILLION // 2
        metrics.append(
            AuthorizedRoleExactJsonRoleMetricsV1(
                role=role,
                passed=passed,
                pass_rate_ppm=score,
                mean_score_micros=score,
            )
        )
    return tuple(metrics)


def _strict_json_object(text: str) -> dict[str, object] | None:
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_unique_object_pairs,
            parse_constant=_reject_nonfinite_constant,
        )
        _validate_finite_json(parsed)
    except (TypeError, ValueError):
        return None
    if not isinstance(parsed, dict):
        return None
    return parsed


def _unique_object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_nonfinite_constant(value: str) -> Never:
    del value
    raise ValueError("non-finite JSON number")


def _validate_finite_json(value: object) -> None:
    if value is None or isinstance(value, str | bool | int):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite JSON number")
        return
    if isinstance(value, list):
        for item in value:
            _validate_finite_json(item)
        return
    if isinstance(value, dict):
        for item in value.values():
            _validate_finite_json(item)
        return
    raise ValueError("unsupported JSON value")
