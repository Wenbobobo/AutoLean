from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from autolean_contracts import (
    AttestationError,
    AttestationPurposeV1,
    AttestationSignerV1,
    AttestationV1,
    HashKindV1,
    ModelExecutionAuthorizationError,
    ModelExecutionBudgetV1,
    digest_text,
)
from autolean_prover.errors import ConfigurationError, PolicyViolation, ProviderResponseError
from autolean_prover.providers import ModelExecutionCompletionRecoveryRequired

from scripts import deepseek_authorized_canary as canary

_BOOTSTRAP_ONLY_FIELDS: dict[str, object] = {
    "authority_status": "non-promotable-ephemeral-test-authority",
    "promotion_eligible": False,
    "capability_evidence_class": "static_declared_only",
    "independent_capability_probe_status": "not_independently_probed",
    "provider_approval_class": "operator_declared_bootstrap_only",
    "role_floor_admission": "forbidden",
}


@dataclass(slots=True)
class MutableClock:
    current: datetime

    def __call__(self) -> datetime:
        return self.current

    def advance(self, seconds: float) -> None:
        self.current += timedelta(seconds=seconds)


class CountingTransport:
    def __init__(self) -> None:
        self.calls = 0

    def post_json(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        payload: Mapping[str, object],
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        self.calls += 1
        assert url == "https://api.deepseek.com/chat/completions"
        assert headers["Authorization"].startswith("Bearer ")
        assert payload["model"] == "deepseek-v4-pro"
        assert payload["thinking"] == {"type": "enabled"}
        assert payload["reasoning_effort"] in {"high", "max"}
        assert "tools" not in payload
        messages = payload["messages"]
        assert isinstance(messages, list)
        assert messages[0] == {
            "role": "system",
            "content": "Submit only the proof body for the frozen Lean theorem.",
        }
        assert isinstance(messages[1], dict)
        assert "theorem deepseek_authorized_canary" in messages[1]["content"]
        assert timeout_seconds == 120
        return {
            "id": "synthetic-response-id",
            "model": "deepseek-v4-pro",
            "choices": [
                {
                    "message": {
                        "content": "by\n  rfl",
                    }
                }
            ],
            "usage": {
                "prompt_tokens": 23,
                "prompt_cache_hit_tokens": 3,
                "completion_tokens": 7,
            },
        }

    def post_json_bytes(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        payload = json.loads(body.decode("utf-8"))
        assert isinstance(payload, dict)
        return self.post_json(
            url=url,
            headers=headers,
            payload=payload,
            timeout_seconds=timeout_seconds,
        )


class RaisingTransport:
    def __init__(self, error: Exception) -> None:
        self._error = error

    def post_json(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        payload: Mapping[str, object],
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        del url, headers, payload, timeout_seconds
        raise self._error

    def post_json_bytes(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        del url, headers, body, timeout_seconds
        raise self._error


class ReturningTransport:
    def post_json(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        payload: Mapping[str, object],
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        del url, headers, payload, timeout_seconds
        return {"safe": True}

    def post_json_bytes(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        del url, headers, body, timeout_seconds
        return {"safe": True}


class FailOnceCompletionSigner:
    def __init__(self, delegate: AttestationSignerV1) -> None:
        self._delegate = delegate
        self.calls = 0

    def issue(
        self,
        *,
        purpose: AttestationPurposeV1,
        payload: Mapping[str, object],
        evidence_identity: str,
        ttl_seconds: float,
        nonce: str | None = None,
    ) -> AttestationV1:
        self.calls += 1
        if self.calls == 1:
            raise AttestationError("injected completion signer interruption")
        return self._delegate.issue(
            purpose=purpose,
            payload=payload,
            evidence_identity=evidence_identity,
            ttl_seconds=ttl_seconds,
            nonce=nonce,
        )


def _environment() -> dict[str, str]:
    return {"AUTOLEAN_DEEPSEEK_API_KEY": "x" * 32}


def _prepare(
    tmp_path: Path,
    transport: CountingTransport,
    *,
    clock: MutableClock,
    external_egress: bool = True,
) -> canary.PreparedCanary:
    return canary.prepare_canary(
        state_root=tmp_path,
        environment=_environment(),
        transport=transport,
        operator_approved=True,
        clock=clock,
        external_egress=external_egress,
    )


def test_canary_uses_full_authorization_chain_and_redacts_output(tmp_path: Path) -> None:
    clock = MutableClock(datetime(2026, 7, 27, tzinfo=UTC))
    transport = CountingTransport()
    prepared = _prepare(tmp_path, transport, clock=clock)
    assert prepared.request.context_pack_hash == prepared.context_pack.content_hash()
    assert prepared.request.prompt == prepared.context_pack.render()
    assert prepared.bundle.contract.formal.lean_statement_source in prepared.request.prompt
    authorization = canary.issue_canary_authorization(prepared)

    report = canary.execute_prepared_canary(prepared, authorization)

    assert transport.calls == 1
    assert report["status"] == "settled"
    for key, expected in _BOOTSTRAP_ONLY_FIELDS.items():
        assert report[key] == expected
    assert report["provider_id"] == "deepseek"
    assert report["model_id"] == "deepseek-v4-pro"
    assert report["hashes"] == {
        "authorization": authorization.authorization_hash().value,
        "bundle": prepared.bundle.handoff_hash().value,
        "contract": prepared.bundle.contract.semantic_hash().value,
        "context_pack": authorization.context_pack_hash.value,
        "outbound_request": authorization.request_hash.value,
    }
    completion = report["completion"]
    assert isinstance(completion, dict)
    assert completion["schema_version"] == "autolean.model-execution-completion-public.v1"
    assert set(completion) == {
        "schema_version",
        "completion_id",
        "receipt_hash",
        "public_output_commitment",
    }
    serialized = json.dumps(report, sort_keys=True)
    for forbidden in (
        "by\\n  rfl",
        "Acknowledge the AutoLean",
        "theorem deepseek_authorized_canary",
        "api.deepseek.com",
        "x" * 32,
        "Bearer",
        "synthetic-response-id",
        "artifact_digest",
        "nonce",
        '"usage"',
        '"input_tokens"',
        '"output_tokens"',
    ):
        assert forbidden not in serialized

    with sqlite3.connect(tmp_path / "control.db") as connection:
        ledger = connection.execute(
            """
            SELECT event_type, actual_input_tokens, actual_cached_input_tokens,
                   actual_output_tokens
            FROM model_execution_authorization_ledger
            ORDER BY event_sequence
            """
        ).fetchall()
        approvals = connection.execute(
            "SELECT approval_json FROM model_execution_provider_approvals"
        ).fetchall()
    assert [row[0] for row in ledger] == ["reserved", "settled"]
    assert ledger[-1][1:] == (23, 3, 7)
    assert len(approvals) == 1
    assert json.loads(approvals[0][0])["approved_by"] == "operator-declared-bootstrap-canary"


def test_canary_recovers_the_same_private_response_without_provider_rerun(tmp_path: Path) -> None:
    clock = MutableClock(datetime(2026, 7, 27, tzinfo=UTC))
    transport = CountingTransport()
    prepared = canary.prepare_canary(
        state_root=tmp_path,
        environment=_environment(),
        transport=transport,
        operator_approved=True,
        completion_signer_factory=FailOnceCompletionSigner,
        clock=clock,
    )
    authorization = canary.issue_canary_authorization(prepared)

    with pytest.raises(ModelExecutionCompletionRecoveryRequired) as captured:
        canary.execute_prepared_canary(prepared, authorization)

    assert transport.calls == 1
    recovered = canary.recover_prepared_canary(prepared, captured.value.recovery_handle)

    assert transport.calls == 1
    assert recovered["status"] == "settled"
    assert recovered["completion"] != {}


def test_canary_report_cannot_be_role_floor_capability_evidence(tmp_path: Path) -> None:
    clock = MutableClock(datetime(2026, 7, 27, tzinfo=UTC))
    transport = CountingTransport()
    prepared = _prepare(tmp_path, transport, clock=clock)
    authorization = canary.issue_canary_authorization(prepared)
    settled = canary.execute_prepared_canary(prepared, authorization)
    refused = canary._refusal("execution_refused", failure_class="http_429")

    for report in (settled, refused):
        for key, expected in _BOOTSTRAP_ONLY_FIELDS.items():
            assert report[key] == expected
        assert report["capability_evidence_class"] == "static_declared_only"
        assert report["independent_capability_probe_status"] == "not_independently_probed"
        assert report["provider_approval_class"] == "operator_declared_bootstrap_only"
        assert report["role_floor_admission"] == "forbidden"
        assert report["promotion_eligible"] is False


def test_tampered_authorization_is_rejected_before_transport(tmp_path: Path) -> None:
    clock = MutableClock(datetime(2026, 7, 27, tzinfo=UTC))
    transport = CountingTransport()
    prepared = _prepare(tmp_path, transport, clock=clock)
    authorization = canary.issue_canary_authorization(prepared)
    tampered = authorization.model_copy(
        update={"request_hash": digest_text(HashKindV1.PROMPT, "different-request")}
    )

    with pytest.raises(PolicyViolation, match="authorization was denied"):
        prepared.registry.generate_completed(
            tampered,
            prepared.request,
            output_store=prepared.output_store,
        )

    assert transport.calls == 0


def test_rights_denial_is_rejected_before_transport(tmp_path: Path) -> None:
    clock = MutableClock(datetime(2026, 7, 27, tzinfo=UTC))
    transport = CountingTransport()

    with pytest.raises(PolicyViolation, match="source rights do not permit"):
        _prepare(tmp_path, transport, clock=clock, external_egress=False)

    assert transport.calls == 0


def test_stale_lease_is_rejected_before_transport(tmp_path: Path) -> None:
    clock = MutableClock(datetime(2026, 7, 27, tzinfo=UTC))
    transport = CountingTransport()
    prepared = _prepare(tmp_path, transport, clock=clock)
    lease = prepared.control_plane.claim(
        prepared.bundle.bundle_id.value,
        worker_id="stale-canary-worker",
        ttl_seconds=600,
        idempotency_key="claim-stale-canary-worker",
    ).lease
    clock.advance(601)

    with pytest.raises(ModelExecutionAuthorizationError, match="stale or expired"):
        canary.issue_canary_authorization(prepared, lease=lease)

    assert transport.calls == 0


def test_budget_denial_is_rejected_before_transport(tmp_path: Path) -> None:
    clock = MutableClock(datetime(2026, 7, 27, tzinfo=UTC))
    transport = CountingTransport()
    prepared = _prepare(tmp_path, transport, clock=clock)
    budget = ModelExecutionBudgetV1(
        max_attempts=1,
        max_input_tokens=prepared.request.max_input_tokens - 1,
        max_output_tokens=prepared.request.max_output_tokens,
        max_total_tokens=prepared.request.max_input_tokens + prepared.request.max_output_tokens - 1,
        max_cost_microusd=1_000_000,
    )
    authorization = canary.issue_canary_authorization(prepared, budget=budget)

    with pytest.raises(PolicyViolation, match="authorization was denied"):
        prepared.registry.generate_completed(
            authorization,
            prepared.request,
            output_store=prepared.output_store,
        )

    assert transport.calls == 0


def test_low_reasoning_effort_is_rejected_without_transport(tmp_path: Path) -> None:
    transport = CountingTransport()

    with pytest.raises(ValueError, match="high or max"):
        canary.prepare_canary(
            state_root=tmp_path,
            environment=_environment(),
            transport=transport,
            operator_approved=True,
            reasoning_effort="low",  # type: ignore[arg-type]
        )

    assert transport.calls == 0


def test_preparation_requires_explicit_operator_approval_before_transport(
    tmp_path: Path,
) -> None:
    transport = CountingTransport()

    with pytest.raises(PolicyViolation, match="explicit operator approval"):
        canary.prepare_canary(
            state_root=tmp_path,
            environment=_environment(),
            transport=transport,
            operator_approved=False,
        )

    assert transport.calls == 0


def test_cli_requires_explicit_operator_approval(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = canary.main([])

    assert exit_code == 2
    assert json.loads(capsys.readouterr().out) == {
        "schema_version": "autolean.deepseek-authorized-canary.v2",
        "status": "operator_approval_required",
        **_BOOTSTRAP_ONLY_FIELDS,
    }


def test_cli_maps_failure_type_without_emitting_exception_text(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    marker = "raw-sensitive-exception-marker"

    def fail(**_kwargs: object) -> dict[str, object]:
        raise ConfigurationError(marker)

    monkeypatch.setattr(canary, "run_authorized_canary", fail)

    assert canary.main(["--operator-approved"]) == 1
    output = capsys.readouterr().out
    assert marker not in output
    assert json.loads(output) == {
        "schema_version": "autolean.deepseek-authorized-canary.v2",
        "status": "execution_refused",
        "failure_class": "configuration",
        **_BOOTSTRAP_ONLY_FIELDS,
    }


@pytest.mark.parametrize(
    ("status_code", "expected"),
    [
        (400, "http_400"),
        (401, "http_401"),
        (402, "http_402"),
        (403, "http_4xx_other"),
        (422, "http_422"),
        (429, "http_429"),
        (500, "http_5xx"),
        (599, "http_5xx"),
        (307, "http_3xx"),
    ],
)
def test_safe_diagnostic_transport_maps_http_status_without_retaining_details(
    status_code: int,
    expected: str,
) -> None:
    marker = "sensitive-http-detail"
    request = httpx.Request("POST", f"https://{marker}.invalid/private")
    response = httpx.Response(status_code, request=request, text=marker)
    error = httpx.HTTPStatusError(
        marker,
        request=request,
        response=response,
    )
    transport = canary.SafeDiagnosticTransport(RaisingTransport(error))

    with pytest.raises(httpx.HTTPStatusError):
        transport.post_json(
            url="https://unused.invalid",
            headers={"Authorization": f"Bearer {marker}"},
            payload={"private": marker},
            timeout_seconds=1,
        )

    diagnostic = transport.provider_response_failure_class
    assert diagnostic == expected
    assert marker not in diagnostic
    assert "invalid" not in diagnostic


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (
            httpx.ReadTimeout(
                "sensitive-timeout-detail",
                request=httpx.Request("POST", "https://sensitive-timeout.invalid"),
            ),
            "timeout",
        ),
        (
            httpx.ConnectError(
                "sensitive-network-detail",
                request=httpx.Request("POST", "https://sensitive-network.invalid"),
            ),
            "network",
        ),
        (
            json.JSONDecodeError(
                "sensitive-json-detail",
                "sensitive-json-body",
                0,
            ),
            "invalid_json",
        ),
        (
            ConfigurationError("sensitive-unclassified-detail"),
            "transport_unclassified",
        ),
    ],
)
def test_safe_diagnostic_transport_maps_non_http_failures(
    error: Exception,
    expected: str,
) -> None:
    transport = canary.SafeDiagnosticTransport(RaisingTransport(error))

    with pytest.raises(type(error)):
        transport.post_json(
            url="https://sensitive-url.invalid",
            headers={"Authorization": "Bearer sensitive-value"},
            payload={"private": "sensitive-body"},
            timeout_seconds=1,
        )

    diagnostic = transport.provider_response_failure_class
    assert diagnostic == expected
    assert "sensitive" not in diagnostic


def test_safe_diagnostic_transport_marks_http_ok_for_later_response_validation() -> None:
    transport = canary.SafeDiagnosticTransport(ReturningTransport())

    assert transport.post_json(
        url="https://unused.invalid",
        headers={},
        payload={},
        timeout_seconds=1,
    ) == {"safe": True}
    assert transport.provider_response_failure_class == "http_ok_response_invalid"


def test_cli_emits_http_category_without_body_url_or_exception_text(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    marker = "sensitive-provider-marker"
    request = httpx.Request("POST", f"https://{marker}.invalid/private")
    response = httpx.Response(402, request=request, text=marker)
    raw_error = httpx.HTTPStatusError(
        marker,
        request=request,
        response=response,
    )
    monkeypatch.setattr(
        canary,
        "HttpxResponsesTransport",
        lambda: RaisingTransport(raw_error),
    )

    def fail(**kwargs: object) -> dict[str, object]:
        transport = kwargs["transport"]
        assert isinstance(transport, canary.SafeDiagnosticTransport)
        try:
            transport.post_json(
                url=f"https://{marker}.invalid",
                headers={"Authorization": f"Bearer {marker}"},
                payload={"private": marker},
                timeout_seconds=1,
            )
        except httpx.HTTPStatusError:
            raise ProviderResponseError(marker) from None
        raise AssertionError("diagnostic transport did not raise")

    monkeypatch.setattr(canary, "run_authorized_canary", fail)

    assert canary.main(["--operator-approved"]) == 1
    output = capsys.readouterr().out
    assert marker not in output
    assert "https://" not in output
    assert json.loads(output) == {
        "schema_version": "autolean.deepseek-authorized-canary.v2",
        "status": "execution_refused",
        "failure_class": "http_402",
        **_BOOTSTRAP_ONLY_FIELDS,
    }
