"""No-network checks for the first-case source-free three-role operator."""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest
from autolean_builder.ifem_source_free_case_authoring import SourceFreeReviewResponseV1
from autolean_builder.ifem_source_free_stage_ledger import (
    LocalSourceFreeStageLedger,
    SourceFreeStageCoordinateV1,
    SourceFreeStageLedgerStateV1,
)
from autolean_contracts import ModelWorkRoleV1, canonical_json_bytes

from benchmarks import ifem_source_free_model_work_sidecar as sidecar_module
from scripts import ifem_source_free_model_work as single
from scripts import ifem_source_free_role_chain as chain

_DEMO_CREDENTIAL = "source-free-role-chain-test-credential-0123456789"
_RAW_RESPONSE = "ROLE_CHAIN_RAW_RESPONSE_MUST_NOT_REACH_STDOUT"
_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class SimulatedProcessCrash(BaseException):
    pass


class RoleChainTransport:
    def __init__(self, *, invalid_role: str | None = None) -> None:
        self.calls: list[tuple[str, Mapping[str, str], bytes, float]] = []
        self.invalid_role = invalid_role

    def post_json_bytes(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        self.calls.append((url, dict(headers), body, timeout_seconds))
        request = json.loads(body)
        stage_input = json.loads(request["messages"][1]["content"])
        role = stage_input["role"]
        if role == self.invalid_role:
            response_text = '{"unexpected":true}'
        else:
            responses: dict[str, dict[str, object]] = {
                "statement_formalizer": {
                    "schema_version": "autolean.ifem-source-free-authoring-response.v1",
                    "disposition": "abstain",
                    "selected_slot": None,
                    "candidate": None,
                },
                "fidelity_reviewer": {
                    "schema_version": "autolean.ifem-source-free-review-response.v1",
                    "disposition": "abstain",
                    "observed_change_count": 0,
                },
                "cheating_supervisor": {
                    "schema_version": "autolean.ifem-source-free-supervisor-response.v1",
                    "disposition": "abstain",
                    "violation_detected": False,
                },
            }
            response_text = json.dumps(responses[role], sort_keys=True, separators=(",", ":"))
        return {
            "id": _RAW_RESPONSE,
            "model": "deepseek-v4-pro",
            "choices": [{"message": {"content": response_text}}],
            "usage": {
                "prompt_tokens": 12,
                "prompt_cache_hit_tokens": 0,
                "completion_tokens": 10,
            },
        }

    def post_json(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        payload: Mapping[str, object],
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        return self.post_json_bytes(
            url=url,
            headers=headers,
            body=json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"),
            timeout_seconds=timeout_seconds,
        )


class FailingTransport:
    def post_json_bytes(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        del url, headers, body, timeout_seconds
        raise AssertionError("a settled role-chain coordinate must not re-dispatch")

    def post_json(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        payload: Mapping[str, object],
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        del url, headers, payload, timeout_seconds
        raise AssertionError("a settled role-chain coordinate must not re-dispatch")


def _config(
    tmp_path: Path,
    mode: chain.RoleChainMode,
    *,
    approved: bool = False,
) -> chain.SourceFreeDeepSeekRoleChainConfig:
    operator_root = (tmp_path / "operator").resolve()
    operator_root.mkdir(exist_ok=True)
    return chain.SourceFreeDeepSeekRoleChainConfig(
        mode=mode,
        state_root=operator_root / "state",
        private_root=operator_root / "private",
        run_label="source-free-role-chain-test",
        operator_approved=approved,
    )


def _environment() -> dict[str, str]:
    return {"AUTOLEAN_DEEPSEEK_API_KEY": _DEMO_CREDENTIAL}


def test_plan_and_preflight_are_credential_free_and_hash_all_role_prompts(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path, "plan")

    planned = chain.execute_source_free_deepseek_role_chain(config, environment={})
    preflight = chain.execute_source_free_deepseek_role_chain(
        _config(tmp_path, "preflight"),
        environment={},
    )
    built = chain.build_source_free_deepseek_role_chain_plan()

    assert planned.status == "planned"
    assert preflight.status == "preflight_ready"
    assert planned.runtime_evidence_available is False
    assert planned.run_scope_binding_sha256 is None
    assert preflight.run_scope_binding_sha256 is None
    assert not config.state_root.exists()
    assert not config.private_root.exists()
    assert tuple(item.role for item in built.public.role_prompt_contracts) == (
        ModelWorkRoleV1.STATEMENT_FORMALIZER,
        ModelWorkRoleV1.FIDELITY_REVIEWER,
        ModelWorkRoleV1.CHEATING_SUPERVISOR,
    )
    assert built.public.aggregate_cost_bound_microusd == 184_320
    assert built.public.maximum_authorized_provider_attempts == 3
    assert built.public.authority.cross_role_independence_claimed is False


def test_role_chain_plan_binds_reviewer_prompt_without_changing_legacy_plan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    legacy_before = single.build_source_free_deepseek_plan()
    chain_before = chain.build_source_free_deepseek_role_chain_plan()
    original_prompt = sidecar_module._system_prompt

    def drifted_prompt(role: ModelWorkRoleV1) -> str:
        value = original_prompt(role)
        if role is ModelWorkRoleV1.FIDELITY_REVIEWER:
            return f"{value} deterministic-reviewer-drift"
        return value

    monkeypatch.setattr(sidecar_module, "_system_prompt", drifted_prompt)

    legacy_after = single.build_source_free_deepseek_plan()
    chain_after = chain.build_source_free_deepseek_role_chain_plan()

    assert legacy_after.content_sha256 == legacy_before.content_sha256
    assert legacy_after.prompt_contract_sha256 == legacy_before.prompt_contract_sha256
    assert chain_after.public.content_sha256 != chain_before.public.content_sha256
    assert (
        chain_after.public.role_prompt_contracts[1].prompt_contract_sha256
        != chain_before.public.role_prompt_contracts[1].prompt_contract_sha256
    )


def test_role_chain_plan_binds_actual_reviewer_response_schema(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = chain.build_source_free_deepseek_role_chain_plan()
    original_schema = SourceFreeReviewResponseV1.model_json_schema

    def drifted_schema(**_kwargs: object) -> dict[str, object]:
        schema = original_schema(mode="validation")
        return {**schema, "autolean_test_drift": True}

    monkeypatch.setattr(
        SourceFreeReviewResponseV1,
        "model_json_schema",
        staticmethod(drifted_schema),
    )

    after = chain.build_source_free_deepseek_role_chain_plan()

    assert after.public.content_sha256 != before.public.content_sha256
    assert (
        after.public.role_prompt_contracts[1].response_schema_sha256
        != before.public.role_prompt_contracts[1].response_schema_sha256
    )


def test_run_executes_exactly_three_roles_and_repeated_run_does_not_redispatch(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path, "run", approved=True)
    transport = RoleChainTransport()

    first = chain.execute_source_free_deepseek_role_chain(
        config,
        environment=_environment(),
        transport=transport,
    )
    second = chain.execute_source_free_deepseek_role_chain(
        config,
        environment=_environment(),
        transport=FailingTransport(),
    )

    assert first.status == second.status == "settled"
    assert first.runtime_evidence_available is True
    assert len(transport.calls) == 3
    requests = [json.loads(item[2]) for item in transport.calls]
    stage_inputs = [json.loads(item["messages"][1]["content"]) for item in requests]
    assert [item["role"] for item in stage_inputs] == [role.value for role in chain._ROLE_ORDER]
    assert all(sorted(item) == ["card", "role", "schema_version"] for item in stage_inputs)
    assert all(item["response_format"] == {"type": "json_object"} for item in requests)
    assert first.attempt_binding_count == 3
    assert first.completion_settlement_count == 3
    assert first.private_completion_verified_count == 3
    assert first.selected_completion_committed_count == 3
    assert first.selected_pending_count == 0
    assert first.outside_scope_pending_count == 24
    assert first.all_selected_completions_verified is True
    assert first.actual_provider_dispatch_count_claimed is False
    assert first.combined_score_claimed is False
    assert first.authority == sidecar_module.SourceFreeModelWorkAuthorityV1()
    assert first.run_scope_binding_sha256 is not None
    assert second.run_scope_binding_sha256 == first.run_scope_binding_sha256

    scope_path = config.state_root / chain._SCOPE_BINDING_FILENAME
    scope = chain.SourceFreeDeepSeekRoleChainScopeBindingV1.model_validate_json(
        scope_path.read_bytes()
    )
    assert scope.content_sha256 == first.run_scope_binding_sha256
    assert scope.plan_content_sha256 == first.plan_content_sha256

    plan = chain.build_source_free_deepseek_role_chain_plan()
    runtime = single._prepare_runtime(
        _config(tmp_path, "resume").single_config(),
        plan.runtime,
        mode="resume",
        environment={},
        transport=None,
    )
    selected = {item.coordinate_sha256 for item in chain._role_chain_coordinates(runtime)}
    outside = tuple(
        item for item in runtime.ledger.run.coordinates if item.coordinate_sha256 not in selected
    )
    assert len(outside) == 24
    assert all(
        runtime.ledger.state_for(item) is SourceFreeStageLedgerStateV1.PENDING
        and runtime.attempt_store.load(item) is None
        for item in outside
    )
    assert scope.private_stage_run_content_sha256 == runtime.ledger.run.run_content_sha256
    assert scope.selected_coordinate_sha256s == tuple(
        item.coordinate_sha256 for item in chain._role_chain_coordinates(runtime)
    )


def test_same_plan_with_different_private_seed_has_distinct_scope_commitment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entropy_counter = 0

    def deterministic_entropy(length: int) -> bytes:
        nonlocal entropy_counter
        entropy_counter += 1
        return bytes([entropy_counter]) * length

    monkeypatch.setattr(secrets, "token_bytes", deterministic_entropy)
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    first = chain.execute_source_free_deepseek_role_chain(
        _config(first_root, "run", approved=True),
        environment=_environment(),
        transport=RoleChainTransport(),
    )
    second = chain.execute_source_free_deepseek_role_chain(
        _config(second_root, "run", approved=True),
        environment=_environment(),
        transport=RoleChainTransport(),
    )

    assert first.status == second.status == "settled"
    assert first.plan_content_sha256 == second.plan_content_sha256
    assert first.run_scope_binding_sha256 is not None
    assert second.run_scope_binding_sha256 is not None
    assert first.run_scope_binding_sha256 != second.run_scope_binding_sha256


def test_scope_binding_is_persisted_before_every_selected_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path, "run", approved=True)
    observed_scope_hashes: list[str] = []
    original_execute = LocalSourceFreeStageLedger.execute_coordinate

    def execute_after_scope_readback(
        ledger: LocalSourceFreeStageLedger,
        coordinate: SourceFreeStageCoordinateV1,
        executor: object,
    ) -> object:
        scope_path = config.state_root / chain._SCOPE_BINDING_FILENAME
        scope = chain.SourceFreeDeepSeekRoleChainScopeBindingV1.model_validate_json(
            scope_path.read_bytes()
        )
        observed_scope_hashes.append(scope.content_sha256)
        return original_execute(ledger, coordinate, executor)  # type: ignore[arg-type]

    monkeypatch.setattr(
        LocalSourceFreeStageLedger,
        "execute_coordinate",
        execute_after_scope_readback,
    )
    report = chain.execute_source_free_deepseek_role_chain(
        config,
        environment=_environment(),
        transport=RoleChainTransport(),
    )

    assert report.status == "settled"
    assert observed_scope_hashes == [report.run_scope_binding_sha256] * 3


def test_scope_deletion_at_first_ledger_entry_prevents_provider_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path, "run", approved=True)
    transport = RoleChainTransport()
    original_execute = LocalSourceFreeStageLedger.execute_coordinate
    deleted = False

    def delete_scope_before_executor(
        ledger: LocalSourceFreeStageLedger,
        coordinate: SourceFreeStageCoordinateV1,
        executor: object,
    ) -> object:
        nonlocal deleted
        if not deleted:
            deleted = True
            (config.state_root / chain._SCOPE_BINDING_FILENAME).unlink()
        return original_execute(ledger, coordinate, executor)  # type: ignore[arg-type]

    monkeypatch.setattr(
        LocalSourceFreeStageLedger,
        "execute_coordinate",
        delete_scope_before_executor,
    )
    refused = chain.execute_source_free_deepseek_role_chain(
        config,
        environment=_environment(),
        transport=transport,
    )

    assert deleted is True
    assert len(transport.calls) == 0
    assert refused.status == "execution_refused"
    assert refused.failure_class == "private_state_unavailable"
    assert refused.runtime_evidence_available is False
    assert refused.run_scope_binding_sha256 is None


def test_scope_deletion_after_last_provider_return_cannot_report_settled(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path, "run", approved=True)
    scope_path = config.state_root / chain._SCOPE_BINDING_FILENAME

    class DeleteAfterThirdResponseTransport(RoleChainTransport):
        def post_json_bytes(
            self,
            *,
            url: str,
            headers: Mapping[str, str],
            body: bytes,
            timeout_seconds: float,
        ) -> Mapping[str, object]:
            response = super().post_json_bytes(
                url=url,
                headers=headers,
                body=body,
                timeout_seconds=timeout_seconds,
            )
            if len(self.calls) == 3:
                scope_path.unlink()
            return response

    transport = DeleteAfterThirdResponseTransport()
    refused = chain.execute_source_free_deepseek_role_chain(
        config,
        environment=_environment(),
        transport=transport,
    )

    assert len(transport.calls) == 3
    assert refused.status == "execution_refused"
    assert refused.failure_class == "private_state_unavailable"
    assert refused.runtime_evidence_available is False
    assert refused.run_scope_binding_sha256 is None


def test_resume_rejects_rehashed_scope_binding_from_another_coordinate(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path, "run", approved=True)
    settled = chain.execute_source_free_deepseek_role_chain(
        config,
        environment=_environment(),
        transport=RoleChainTransport(),
    )
    assert settled.status == "settled"

    scope_path = config.state_root / chain._SCOPE_BINDING_FILENAME
    payload = json.loads(scope_path.read_bytes())
    payload["selected_coordinate_sha256s"][0] = "0" * 64
    payload["selected_coordinate_commitment_sha256"] = chain._sha256_json(
        tuple(payload["selected_coordinate_sha256s"])
    )
    payload["content_sha256"] = chain._sha256_json(
        {key: value for key, value in payload.items() if key != "content_sha256"}
    )
    scope_path.write_bytes(canonical_json_bytes(payload))

    refused = chain.execute_source_free_deepseek_role_chain(
        _config(tmp_path, "resume"),
        environment={},
        transport=FailingTransport(),
    )

    assert refused.status == "execution_refused"
    assert refused.failure_class == "private_state_unavailable"
    assert refused.runtime_evidence_available is False
    assert refused.run_scope_binding_sha256 is None


def test_invalid_reviewer_blocks_supervisor_and_is_never_retried(tmp_path: Path) -> None:
    config = _config(tmp_path, "run", approved=True)
    transport = RoleChainTransport(invalid_role="fidelity_reviewer")

    failed = chain.execute_source_free_deepseek_role_chain(
        config,
        environment=_environment(),
        transport=transport,
    )
    resumed = chain.execute_source_free_deepseek_role_chain(
        _config(tmp_path, "resume"),
        environment={},
        transport=FailingTransport(),
    )

    assert len(transport.calls) == 2
    assert failed.status == resumed.status == "reconciliation_required"
    assert failed.failure_class == resumed.failure_class == "settled_completion_rejected"
    assert failed.attempt_binding_count == 2
    assert failed.completion_settlement_count == 2
    assert failed.private_completion_verified_count == 1
    assert failed.selected_completion_committed_count == 1
    assert failed.selected_reconciliation_required_count == 1
    assert failed.selected_pending_count == 1
    assert failed.outside_scope_pending_count == 24


def test_extra_control_plane_authorization_refuses_unknown_runtime_projection(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path, "run", approved=True)
    transport = RoleChainTransport()
    settled = chain.execute_source_free_deepseek_role_chain(
        config,
        environment=_environment(),
        transport=transport,
    )
    assert settled.status == "settled"
    database = config.state_root / "control-plane.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            INSERT INTO model_execution_authorizations (
                authorization_id, authorization_hash, authorization_json,
                issue_request_hash, issued_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                "outside-scope-authorization",
                "0" * 64,
                "{}",
                "1" * 64,
                "2026-08-01T00:00:00Z",
            ),
        )

    refused = chain.execute_source_free_deepseek_role_chain(
        config,
        environment=_environment(),
        transport=FailingTransport(),
    )

    assert len(transport.calls) == 3
    assert refused.status == "execution_refused"
    assert refused.runtime_evidence_available is False
    assert refused.selected_pending_count is None
    assert refused.attempt_binding_count is None
    assert refused.outside_scope_pending_count is None
    assert refused.private_stage_ledger_commitment_sha256 is None


def test_extra_control_plane_settlement_refuses_unknown_runtime_projection(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path, "run", approved=True)
    transport = RoleChainTransport()
    settled = chain.execute_source_free_deepseek_role_chain(
        config,
        environment=_environment(),
        transport=transport,
    )
    assert settled.status == "settled"
    database = config.state_root / "control-plane.sqlite3"
    with sqlite3.connect(database) as connection:
        authorization_id = str(
            connection.execute(
                "SELECT authorization_id FROM model_execution_authorizations "
                "ORDER BY authorization_id LIMIT 1"
            ).fetchone()[0]
        )
        connection.execute(
            """
            INSERT INTO model_execution_completion_settlements (
                reservation_id, authorization_id, completion_id,
                settlement_event_id, settlement_event_hash,
                completion_record_hash, completion_record_json, settled_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "outside-scope-reservation",
                authorization_id,
                "outside-scope-completion",
                "outside-scope-event",
                "2" * 64,
                "3" * 64,
                "{}",
                "2026-08-01T00:00:00Z",
            ),
        )

    refused = chain.execute_source_free_deepseek_role_chain(
        config,
        environment=_environment(),
        transport=FailingTransport(),
    )

    assert len(transport.calls) == 3
    assert refused.status == "execution_refused"
    assert refused.runtime_evidence_available is False
    assert refused.attempt_binding_count is None
    assert refused.completion_settlement_count is None


def test_orphan_control_plane_receipt_refuses_unknown_runtime_projection(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path, "run", approved=True)
    transport = RoleChainTransport()
    settled = chain.execute_source_free_deepseek_role_chain(
        config,
        environment=_environment(),
        transport=transport,
    )
    assert settled.status == "settled"
    database = config.state_root / "control-plane.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            INSERT INTO model_execution_completion_receipts (
                completion_id, reservation_id, receipt_hash, receipt_json, issued_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                "orphan-completion",
                "orphan-reservation",
                "4" * 64,
                "{}",
                "2026-08-01T00:00:00Z",
            ),
        )

    refused = chain.execute_source_free_deepseek_role_chain(
        config,
        environment=_environment(),
        transport=FailingTransport(),
    )

    assert len(transport.calls) == 3
    assert refused.status == "execution_refused"
    assert refused.runtime_evidence_available is False
    assert refused.private_completion_verified_count is None
    assert refused.private_completion_binding_commitment_sha256 is None


def test_config_and_executor_reject_unknown_programmatic_mode(tmp_path: Path) -> None:
    with pytest.raises(chain.SourceFreeDeepSeekRoleChainError, match="mode is invalid"):
        chain.SourceFreeDeepSeekRoleChainConfig(
            mode=cast(chain.RoleChainMode, "invalid"),
            state_root=(tmp_path / "state").resolve(),
            private_root=(tmp_path / "private").resolve(),
        )

    config = _config(tmp_path, "plan")
    object.__setattr__(config, "mode", cast(chain.RoleChainMode, "invalid"))
    with pytest.raises(chain.SourceFreeDeepSeekRoleChainError, match="mode is invalid"):
        chain.execute_source_free_deepseek_role_chain(config, environment={})


def test_post_dispatch_evidence_failure_never_fabricates_zero_runtime_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = RoleChainTransport()

    def unavailable(*_args: object, **_kwargs: object) -> chain._RoleChainEvidence:
        raise OSError("injected evidence read failure")

    monkeypatch.setattr(chain, "_collect_role_chain_evidence", unavailable)
    refused = chain.execute_source_free_deepseek_role_chain(
        _config(tmp_path, "run", approved=True),
        environment=_environment(),
        transport=transport,
    )

    assert len(transport.calls) == 3
    assert refused.status == "execution_refused"
    assert refused.runtime_evidence_available is False
    assert refused.selected_pending_count is None
    assert refused.selected_completion_committed_count is None
    assert refused.attempt_binding_count is None
    assert refused.completion_settlement_count is None
    assert refused.private_completion_verified_count is None
    assert refused.all_selected_completions_verified is None
    assert refused.private_stage_ledger_commitment_sha256 is None


def test_report_rejects_impossible_mode_status_and_missing_plan_hash(tmp_path: Path) -> None:
    report = chain.execute_source_free_deepseek_role_chain(
        _config(tmp_path, "run", approved=True),
        environment=_environment(),
        transport=RoleChainTransport(),
    )
    assert report.status == "settled"

    wrong_mode = report.model_dump(mode="json")
    wrong_mode["mode"] = "plan"
    wrong_mode["content_sha256"] = chain._sha256_json(
        {key: value for key, value in wrong_mode.items() if key != "content_sha256"}
    )
    with pytest.raises(ValueError, match="mode and status"):
        chain.SourceFreeDeepSeekRoleChainPublicReportV1.model_validate(wrong_mode)

    missing_plan = report.model_dump(mode="json")
    missing_plan["plan_content_sha256"] = None
    missing_plan["content_sha256"] = chain._sha256_json(
        {key: value for key, value in missing_plan.items() if key != "content_sha256"}
    )
    with pytest.raises(ValueError, match="plan hash"):
        chain.SourceFreeDeepSeekRoleChainPublicReportV1.model_validate(missing_plan)

    false_reconciliation = report.model_dump(mode="json")
    false_reconciliation["status"] = "reconciliation_required"
    false_reconciliation["failure_class"] = "private_reconciliation_required"
    false_reconciliation["content_sha256"] = chain._sha256_json(
        {key: value for key, value in false_reconciliation.items() if key != "content_sha256"}
    )
    with pytest.raises(ValueError, match="cannot claim a complete chain"):
        chain.SourceFreeDeepSeekRoleChainPublicReportV1.model_validate(false_reconciliation)


def test_resume_recovers_third_settlement_without_key_or_provider_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path, "run", approved=True)
    transport = RoleChainTransport()
    original_checkpoint = LocalSourceFreeStageLedger._checkpoint
    armed = True

    def crash_after_third_executor(
        ledger: LocalSourceFreeStageLedger,
        name: str,
        coordinate: SourceFreeStageCoordinateV1,
    ) -> None:
        nonlocal armed
        if armed and name == "executor_returned" and coordinate.ordinal == 3:
            armed = False
            raise SimulatedProcessCrash(coordinate.coordinate_sha256)
        original_checkpoint(ledger, name, coordinate)

    monkeypatch.setattr(
        LocalSourceFreeStageLedger,
        "_checkpoint",
        crash_after_third_executor,
    )
    with pytest.raises(SimulatedProcessCrash):
        chain.execute_source_free_deepseek_role_chain(
            config,
            environment=_environment(),
            transport=transport,
        )
    assert len(transport.calls) == 3

    monkeypatch.setattr(LocalSourceFreeStageLedger, "_checkpoint", original_checkpoint)
    monkeypatch.setattr(
        single,
        "_required_api_key",
        lambda _environment: (_ for _ in ()).throw(
            AssertionError("role-chain resume must not resolve the API key")
        ),
    )
    resumed = chain.execute_source_free_deepseek_role_chain(
        _config(tmp_path, "resume"),
        environment={},
        transport=FailingTransport(),
    )

    assert resumed.status == "recovered"
    assert resumed.private_completion_verified_count == 3
    assert resumed.all_selected_completions_verified is True
    assert len(transport.calls) == 3


def test_public_stdout_redacts_response_credential_paths_and_role_results(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = _config(tmp_path, "run", approved=True)
    transport = RoleChainTransport()
    monkeypatch.setenv("AUTOLEAN_DEEPSEEK_API_KEY", _DEMO_CREDENTIAL)
    monkeypatch.setattr(single, "HttpxResponsesTransport", lambda: transport)

    assert (
        chain.main(
            [
                "run",
                "--operator-approved",
                "--state-root",
                str(config.state_root),
                "--private-root",
                str(config.private_root),
                "--run-label",
                config.run_label,
            ]
        )
        == 0
    )
    rendered = capsys.readouterr().out.encode("ascii")

    assert _DEMO_CREDENTIAL.encode("ascii") not in rendered
    assert _RAW_RESPONSE.encode("ascii") not in rendered
    assert str(config.state_root).encode("utf-8") not in rendered
    assert str(config.private_root).encode("utf-8") not in rendered
    for forbidden in (
        b'"case_id"',
        b'"model_id"',
        b'"prompt"',
        b'"raw_response"',
        b'"response"',
        b'"secret"',
        b'"state_root"',
        b'"private_root"',
    ):
        assert forbidden not in rendered
    report = chain.SourceFreeDeepSeekRoleChainPublicReportV1.model_validate_json(rendered)
    assert report.machine_advisory_disposition == "abstain"
    assert report.per_role_result_disclosed is False
    assert report.builder_freeze == "forbidden"
    assert report.prover_handoff == "forbidden"


def test_direct_script_help_is_available() -> None:
    completed = subprocess.run(
        (
            sys.executable,
            str(_REPOSITORY_ROOT / "scripts" / "ifem_source_free_role_chain.py"),
            "--help",
        ),
        cwd=_REPOSITORY_ROOT,
        env={key: value for key, value in os.environ.items() if key != "AUTOLEAN_DEEPSEEK_API_KEY"},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert "source-free formalizer-reviewer-supervisor chain" in completed.stdout
