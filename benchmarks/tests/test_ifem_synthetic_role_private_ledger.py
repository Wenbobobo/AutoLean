"""Focused recovery and confidentiality tests for the private iFEM output ledger."""

from __future__ import annotations

import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import cast

import pytest
from autolean_contracts import HashKindV1, canonical_json_bytes, digest_text
from autolean_prover.providers import LocalPrivateModelOutputStore, TokenUsage, ToolCall

from benchmarks.ifem_synthetic_role_bridge import (
    IFEMSyntheticRoleExecutionV1,
    IFEMSyntheticRoleFakeExecutor,
    IFEMSyntheticRoleModelOutputV1,
    IFEMSyntheticRolePreparedRequestV1,
    prepare,
)
from benchmarks.ifem_synthetic_role_fixture import (
    IFEMSyntheticRolePublicFixtureV1,
    build_ifem_synthetic_role_fixture,
)
from benchmarks.ifem_synthetic_role_private_ledger import (
    IFEMSyntheticRolePrivateLedgerError,
    IFEMSyntheticRoleReconciliationRequired,
    LocalIFEMSyntheticRolePrivateLedger,
    TestOnlyIFEMSyntheticRoleHmacAuthenticator,
    render_ifem_synthetic_role_public_ledger_projection,
)
from benchmarks.tests.test_ifem_synthetic_role_fixture import _corpus

_HMAC_SECRET = b"iFEM private-ledger test secret must be at least thirty-two bytes"
_RAW_OUTPUT = '{"selected_option":"option_a","reason":"private iFEM response"}'


def _fixture() -> IFEMSyntheticRolePublicFixtureV1:
    return build_ifem_synthetic_role_fixture(_corpus(), operator_seed="ledger-seed")


def _ledger(
    root: Path,
    output_store: LocalPrivateModelOutputStore | None = None,
) -> tuple[LocalIFEMSyntheticRolePrivateLedger, LocalPrivateModelOutputStore]:
    store = output_store or LocalPrivateModelOutputStore(root / "private-cas")
    return (
        LocalIFEMSyntheticRolePrivateLedger(
            root / "private-ledger",
            output_store=store,
            authenticator=TestOnlyIFEMSyntheticRoleHmacAuthenticator(_HMAC_SECRET),
        ),
        store,
    )


def _prepared_run(
    fixture: IFEMSyntheticRolePublicFixtureV1,
    executor: IFEMSyntheticRoleFakeExecutor,
) -> tuple[IFEMSyntheticRolePreparedRequestV1, ...]:
    return tuple(prepare(fixture, item.case_id, executor) for item in fixture.cases)


def test_private_ledger_commits_full_run_and_public_projection_is_opaque(tmp_path: Path) -> None:
    fixture = _fixture()
    executor = IFEMSyntheticRoleFakeExecutor([_RAW_OUTPUT] * 16)
    prepared = _prepared_run(fixture, executor)
    ledger, output_store = _ledger(tmp_path)

    for request in prepared:
        ledger.execute_once(request, executor)
    manifest = ledger.commit_manifest(fixture, prepared)
    recovered_manifest = ledger.read_manifest(fixture, prepared)
    projection = ledger.public_projection(fixture, prepared)
    rendered = render_ifem_synthetic_role_public_ledger_projection(
        projection,
        ledger=ledger,
        fixture=fixture,
        prepared_requests=prepared,
    )

    assert recovered_manifest == manifest
    assert len(manifest.entries) == 16
    assert len(projection.outputs) == 16
    assert all(
        item.output_commitment.kind is HashKindV1.MODEL_OUTPUT_COMMITMENT
        for item in projection.outputs
    )
    assert projection.authority.raw_output_public is False
    assert projection.authority.private_reference_public is False
    assert projection.authority.benchmark_authority is False
    assert projection.authority.freeze_allowed is False
    assert projection.authority.prover_handoff_allowed is False
    assert projection.authority.promotion_allowed is False
    assert projection.is_promotable is False
    assert _RAW_OUTPUT.encode("utf-8") not in rendered
    raw_digest = digest_text(HashKindV1.MODEL_OUTPUT_COMMITMENT, _RAW_OUTPUT).value
    assert raw_digest.encode("ascii") not in rendered
    assert manifest.entries[0].artifact.artifact_digest.value.encode("ascii") not in rendered
    response_id_digest = digest_text(
        HashKindV1.MODEL_OUTPUT_COMMITMENT,
        "synthetic-fake-response-1",
    ).value
    assert response_id_digest.encode("ascii") not in rendered
    assert str(tmp_path).encode("utf-8") not in rendered
    assert b"private-cas" not in rendered
    assert b"oracle" not in rendered.lower()
    assert b'"artifact":' not in rendered
    assert output_store.read_response(manifest.entries[0].artifact).text == _RAW_OUTPUT


def test_execute_once_is_idempotent_and_conflicting_replay_fails_closed(tmp_path: Path) -> None:
    fixture = _fixture()
    executor = IFEMSyntheticRoleFakeExecutor([_RAW_OUTPUT])
    prepared = prepare(fixture, fixture.cases[0].case_id, executor)
    ledger, _store = _ledger(tmp_path)

    first = ledger.execute_once(prepared, executor)
    replay_executor = IFEMSyntheticRoleFakeExecutor(['{"selected_option":"option_b"}'])
    replay = ledger.execute_once(prepared, replay_executor)

    assert first.output.text == replay.output.text == _RAW_OUTPUT
    assert executor.bodies == (prepared.body,)
    assert replay_executor.bodies == ()

    conflict = IFEMSyntheticRoleExecutionV1(
        prepared=prepared,
        output=IFEMSyntheticRoleModelOutputV1(
            text='{"selected_option":"option_b"}',
            body_binding=prepared.body_binding,
            provider_id=prepared.provider_id,
            model_id=prepared.model_id,
        ),
    )
    with pytest.raises(IFEMSyntheticRoleReconciliationRequired, match="conflicts"):
        ledger.persist_execution(conflict)


def test_private_cas_preserves_provider_usage(tmp_path: Path) -> None:
    fixture = _fixture()

    class UsageExecutor(IFEMSyntheticRoleFakeExecutor):
        def execute_prepared(self, *, request, body, binding):  # type: ignore[no-untyped-def]
            output = super().execute_prepared(request=request, body=body, binding=binding)
            return IFEMSyntheticRoleModelOutputV1(
                text=output.text,
                body_binding=output.body_binding,
                provider_id=output.provider_id,
                model_id=output.model_id,
                response_id=output.response_id,
                usage=TokenUsage(input_tokens=21, cached_input_tokens=5, output_tokens=8),
                tool_calls=(
                    ToolCall(
                        call_id="private-unexpected-call",
                        name="unavailable_tool",
                        arguments_json="{}",
                    ),
                ),
            )

    executor = UsageExecutor([_RAW_OUTPUT])
    prepared = prepare(fixture, fixture.cases[0].case_id, executor)
    ledger, _store = _ledger(tmp_path)

    execution = ledger.execute_once(prepared, executor)
    recovered = ledger.recover_execution(prepared)

    assert execution.output.usage == TokenUsage(
        input_tokens=21,
        cached_input_tokens=5,
        output_tokens=8,
    )
    assert recovered.output.usage == execution.output.usage
    assert recovered.output.tool_calls == execution.output.tool_calls


def test_private_ledger_rejects_a_static_journal_link_escape(tmp_path: Path) -> None:
    ledger_root = tmp_path / "private-ledger"
    outside = tmp_path / "outside"
    ledger_root.mkdir()
    outside.mkdir()
    journal = ledger_root / "journal-v1"
    try:
        journal.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable on this platform")

    with pytest.raises(IFEMSyntheticRolePrivateLedgerError, match="physical child"):
        LocalIFEMSyntheticRolePrivateLedger(
            ledger_root.resolve(),
            output_store=LocalPrivateModelOutputStore(tmp_path / "private-cas"),
            authenticator=TestOnlyIFEMSyntheticRoleHmacAuthenticator(_HMAC_SECRET),
        )

    assert tuple(outside.iterdir()) == ()


def test_cas_write_before_terminal_event_recovers_without_second_provider_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture()
    executor = IFEMSyntheticRoleFakeExecutor([_RAW_OUTPUT])
    prepared = prepare(fixture, fixture.cases[0].case_id, executor)
    ledger, output_store = _ledger(tmp_path)
    original_append = ledger._append_event

    def crash_before_terminal(
        *,
        transition: str,
        **kwargs: object,
    ) -> object:
        if transition == "response_persisted":
            raise OSError("injected crash after private CAS write")
        return original_append(transition=transition, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(ledger, "_append_event", crash_before_terminal)
    with pytest.raises(OSError, match="after private CAS"):
        ledger.execute_once(prepared, executor)
    assert executor.bodies == (prepared.body,)

    restarted, _same_store = _ledger(tmp_path, output_store)
    recovered = restarted.recover_execution(prepared)

    assert recovered.output.text == _RAW_OUTPUT
    assert executor.bodies == (prepared.body,)


def test_manifest_commit_failure_retries_without_executing_provider_twice(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture()
    executor = IFEMSyntheticRoleFakeExecutor([_RAW_OUTPUT] * 16)
    prepared = _prepared_run(fixture, executor)
    ledger, _store = _ledger(tmp_path)
    for request in prepared:
        ledger.execute_once(request, executor)
    original_write = ledger._write_manifest_record

    def fail_manifest_commit(_record: object) -> None:
        raise OSError("injected manifest commit failure")

    monkeypatch.setattr(ledger, "_write_manifest_record", fail_manifest_commit)
    with pytest.raises(OSError, match="manifest commit"):
        ledger.commit_manifest(fixture, prepared)
    assert len(executor.bodies) == 16

    monkeypatch.setattr(ledger, "_write_manifest_record", original_write)
    manifest = ledger.commit_manifest(fixture, prepared)
    assert len(manifest.entries) == 16
    assert len(executor.bodies) == 16


def test_public_render_revalidates_projection_and_private_dispatch_is_never_replayed(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    executor = IFEMSyntheticRoleFakeExecutor([_RAW_OUTPUT] * 16)
    prepared = _prepared_run(fixture, executor)
    ledger, _store = _ledger(tmp_path)

    # An executor failure leaves a durable dispatch-started event.  The response outcome is
    # unknowable, so the next caller must stop rather than issuing the same prompt again.
    first = prepared[0]

    class FailingExecutor(IFEMSyntheticRoleFakeExecutor):
        def execute_prepared(self, *, request, body, binding):  # type: ignore[no-untyped-def]
            del request, body, binding
            raise RuntimeError("transport interrupted")

    failing = FailingExecutor([_RAW_OUTPUT])
    with pytest.raises(Exception, match="executor failed"):
        ledger.execute_once(first, failing)
    with pytest.raises(IFEMSyntheticRoleReconciliationRequired, match="replay"):
        ledger.execute_once(first, executor)

    # Make a separately complete run to exercise public revalidation without publishing raw data.
    other_root = tmp_path / "complete"
    complete, _complete_store = _ledger(other_root)
    complete_executor = IFEMSyntheticRoleFakeExecutor([_RAW_OUTPUT] * 16)
    complete_prepared = _prepared_run(fixture, complete_executor)
    for request in complete_prepared:
        complete.execute_once(request, complete_executor)
    complete.commit_manifest(fixture, complete_prepared)
    projection = complete.public_projection(fixture, complete_prepared)
    payload = projection.model_dump(mode="python")
    payload["content_sha256"] = "0" * 64
    forged = type(projection).model_construct(**payload)
    with pytest.raises(IFEMSyntheticRolePrivateLedgerError, match="failed revalidation"):
        render_ifem_synthetic_role_public_ledger_projection(
            forged,
            ledger=complete,
            fixture=fixture,
            prepared_requests=complete_prepared,
        )
    assert canonical_json_bytes(projection.model_dump(mode="json")).endswith(b"}")


def test_concurrent_first_claim_dispatches_provider_at_most_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture()
    executor = IFEMSyntheticRoleFakeExecutor([_RAW_OUTPUT, _RAW_OUTPUT])
    prepared = prepare(fixture, fixture.cases[0].case_id, executor)
    ledger, _store = _ledger(tmp_path)
    original_read_state = ledger._read_state
    barrier = threading.Barrier(2)
    counter_lock = threading.Lock()
    initial_reads = 0

    def coordinated_read_state(coordinate):  # type: ignore[no-untyped-def]
        nonlocal initial_reads
        state = original_read_state(coordinate)
        with counter_lock:
            initial_reads += 1
            should_wait = initial_reads <= 2
        if should_wait:
            barrier.wait(timeout=5)
        return state

    monkeypatch.setattr(ledger, "_read_state", coordinated_read_state)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(ledger.execute_once, prepared, executor) for _ in range(2)]
        outcomes: list[object] = []
        for future in futures:
            try:
                outcomes.append(future.result())
            except IFEMSyntheticRoleReconciliationRequired as error:
                outcomes.append(error)

    assert len(executor.bodies) == 1
    assert sum(isinstance(item, IFEMSyntheticRoleExecutionV1) for item in outcomes) == 1
    assert sum(isinstance(item, IFEMSyntheticRoleReconciliationRequired) for item in outcomes) == 1


def test_self_hashed_public_projection_must_match_private_ledger(tmp_path: Path) -> None:
    fixture = _fixture()
    executor = IFEMSyntheticRoleFakeExecutor([_RAW_OUTPUT] * 16)
    prepared = _prepared_run(fixture, executor)
    ledger, _store = _ledger(tmp_path)
    for request in prepared:
        ledger.execute_once(request, executor)
    ledger.commit_manifest(fixture, prepared)
    projection = ledger.public_projection(fixture, prepared)
    payload = projection.model_dump(mode="json")
    outputs = cast(list[dict[str, object]], payload["outputs"])
    commitment = cast(dict[str, object], outputs[0]["output_commitment"])
    commitment["value"] = "f" * 64
    payload["content_sha256"] = hashlib.sha256(
        canonical_json_bytes(
            {key: value for key, value in payload.items() if key != "content_sha256"}
        )
    ).hexdigest()
    forged = type(projection).model_validate(payload)

    with pytest.raises(IFEMSyntheticRolePrivateLedgerError, match="authenticated private ledger"):
        render_ifem_synthetic_role_public_ledger_projection(
            forged,
            ledger=ledger,
            fixture=fixture,
            prepared_requests=prepared,
        )
