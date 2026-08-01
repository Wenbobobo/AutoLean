from __future__ import annotations

import json
import os
import shutil
import sqlite3
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import pytest
from autolean_contracts import ModelExecutionProviderApprovalV1
from autolean_control_plane import ModelExecutionAuthorizationService
from autolean_prover.errors import ConfigurationError

from benchmarks.authorized_role_bridge import (
    AuthorizedRoleBridgeError,
    AuthorizedRoleCompletionManifestStoreV2,
)
from benchmarks.authorized_role_bridge import (
    TestOnlyHmacPrivateManifestAuthenticator as PrivateManifestHmacFixture,
)
from scripts import deepseek_role_baseline as runner

_API_SECRET = "api-secret-marker-" + ("a" * 40)
_MANIFEST_SECRET = "manifest-secret-marker-" + ("b" * 40)
_PRIVATE_RESPONSE_MARKER = "PRIVATE_DEEPSEEK_ROLE_RESPONSE"


def _clock() -> datetime:
    return datetime(2026, 7, 27, 12, 0, tzinfo=UTC)


class CountingTransport:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def post_json(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        payload: Mapping[str, object],
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        self.calls.append(
            {
                "url": url,
                "headers": dict(headers),
                "payload": dict(payload),
                "timeout_seconds": timeout_seconds,
            }
        )
        assert url == "https://api.deepseek.com/chat/completions"
        assert headers["Authorization"] == f"Bearer {_API_SECRET}"
        assert payload["model"] == "deepseek-v4-pro"
        assert payload["thinking"] == {"type": "enabled"}
        assert payload["reasoning_effort"] == "high"
        assert "tools" not in payload
        assert timeout_seconds == 120
        return {
            "id": f"private-response-{len(self.calls)}",
            "model": "deepseek-v4-pro",
            "choices": [
                {
                    "message": {
                        "content": f"{_PRIVATE_RESPONSE_MARKER}_{len(self.calls)}",
                    }
                }
            ],
            "usage": {
                "prompt_tokens": 20,
                "prompt_cache_hit_tokens": 2,
                "completion_tokens": 5,
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
    def __init__(self, marker: str) -> None:
        self.marker = marker
        self.calls = 0

    def post_json(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        payload: Mapping[str, object],
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        del url, headers, payload, timeout_seconds
        self.calls += 1
        raise RuntimeError(self.marker)

    def post_json_bytes(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        del url, headers, body, timeout_seconds
        self.calls += 1
        raise RuntimeError(self.marker)


def _environment(
    *,
    api: str | None = _API_SECRET,
    manifest: str | None = _MANIFEST_SECRET,
) -> dict[str, str]:
    environment: dict[str, str] = {}
    if api is not None:
        environment["AUTOLEAN_DEEPSEEK_API_KEY"] = api
    if manifest is not None:
        environment["AUTOLEAN_ROLE_MANIFEST_HMAC_KEY"] = manifest
    return environment


def _config(
    tmp_path: Path,
    mode: Literal["plan", "preflight", "run"],
    *,
    operator_approved: bool = True,
) -> runner.DeepSeekRoleOperatorConfig:
    return runner.DeepSeekRoleOperatorConfig(
        mode=mode,
        run_id=f"deepseek-role-{mode}-v1",
        state_root=(tmp_path / f"{mode}-state").resolve(),
        private_root=(tmp_path / f"{mode}-private").resolve(),
        max_cost_microusd_per_trial=100_000,
        operator_approved=operator_approved,
    )


def _state_counts(database: Path) -> tuple[int, ...]:
    with sqlite3.connect(database) as connection:
        return tuple(
            int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in runner._MODEL_WORK_STATE_TABLES
        )


def _serialized(report: runner.DeepSeekRolePublicReportV2) -> str:
    return json.dumps(report.model_dump(mode="json"), sort_keys=True)


def test_plan_is_locked_answer_free_and_write_free(tmp_path: Path) -> None:
    transport = CountingTransport()
    config = _config(tmp_path, "plan")

    report = runner.execute_operator_mode(
        config,
        environment={},
        transport=transport,
        clock=_clock,
    )

    assert report.status == "planned"
    assert report.trial_count == 10
    assert len(report.roles) == 5
    assert {item.role.value for item in report.roles} == {
        "prover",
        "statement_formalizer",
        "fidelity_reviewer",
        "cheating_supervisor",
        "task_allocator",
    }
    assert all(item.trial_count == 2 for item in report.roles)
    assert all(item.trial_sidecar_hashes == () for item in report.roles)
    assert report.role_floor_admission == "forbidden"
    assert report.score_status == "not_computed"
    assert report.floor_claim_eligible is False
    assert report.production_authority is False
    assert transport.calls == []
    assert not config.state_root.exists()
    assert not config.private_root.exists()

    public = _serialized(report)
    for forbidden in (
        "api.deepseek.com",
        _API_SECRET,
        _MANIFEST_SECRET,
        "expected_output",
        "Return one JSON",
    ):
        assert forbidden not in public


def test_preflight_is_zero_io_and_zero_model_work_state(tmp_path: Path) -> None:
    transport = CountingTransport()
    config = _config(tmp_path, "preflight")

    report = runner.execute_operator_mode(
        config,
        environment=_environment(),
        transport=transport,
        clock=_clock,
    )

    assert report.status == "preflight_ready"
    assert report.private_evidence_committed is False
    assert transport.calls == []
    assert _state_counts(config.state_root / "control.db") == (0,) * len(
        runner._MODEL_WORK_STATE_TABLES
    )
    with sqlite3.connect(config.state_root / "control.db") as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM model_execution_provider_approvals"
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*) FROM model_execution_provider_approval_idempotency"
        ).fetchone() == (1,)
        for table in (
            "events",
            "entity_versions",
            "idempotency_records",
            "attestation_nonce_uses",
            "contract_revision_bindings",
            "lease_counters",
        ):
            assert connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone() == (0,)
    assert not any(path.is_file() for path in (config.state_root / "public-artifacts").rglob("*"))
    assert {path.name for path in config.private_root.rglob("*") if path.is_file()} == {
        runner._ROOT_READY_MARKER
    }
    assert not tuple(config.state_root.parent.glob(".*.autolean-quarantine-*"))
    assert all(item.trial_sidecar_hashes == () for item in report.roles)


def test_run_executes_ten_calls_and_exposes_only_role_separated_sidecars(
    tmp_path: Path,
) -> None:
    transport = CountingTransport()
    config = _config(tmp_path, "run")
    prepared = runner.preflight_deepseek_role_operator(
        config,
        environment=_environment(),
        transport=transport,
        clock=_clock,
    )
    assert transport.calls == []
    assert _state_counts(prepared.state_database) == (0,) * len(runner._MODEL_WORK_STATE_TABLES)

    report = runner.run_preflighted_deepseek_role_operator(prepared)

    assert report.status == "settled"
    assert len(transport.calls) == 10
    assert report.private_evidence_committed is True
    private_handle = prepared.completion_manifest_store.resolve_run_manifest_handle(config.run_id)
    manifest_hash = prepared.completion_manifest_store.read_manifest(private_handle).content_hash()
    assert len(manifest_hash) == 64
    assert len(report.roles) == 5
    assert all(len(item.trial_sidecar_hashes) == 2 for item in report.roles)
    assert all(item.usage.input_tokens == "1_255" for item in report.roles)
    assert all(item.usage.cached_input_tokens == "1_255" for item in report.roles)
    assert all(item.usage.output_tokens == "1_255" for item in report.roles)
    assert all(item.usage.elapsed_ms == "under_1s" for item in report.roles)

    with sqlite3.connect(prepared.state_database) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM model_execution_work_bundles"
        ).fetchone() == (10,)
        assert connection.execute(
            "SELECT COUNT(*) FROM model_execution_authorizations"
        ).fetchone() == (10,)
        assert connection.execute(
            "SELECT COUNT(*) FROM model_execution_authorization_ledger"
        ).fetchone() == (20,)

    public = _serialized(report)
    for forbidden in (
        _PRIVATE_RESPONSE_MARKER,
        _API_SECRET,
        _MANIFEST_SECRET,
        "api.deepseek.com",
        str(config.state_root),
        str(config.private_root),
        private_handle,
        "private_manifest_handle",
        "completion-manifest-handles-v2",
        "completion-manifest-run-index-v2",
        "expected_output",
    ):
        assert forbidden not in public
    private_payload = b"\n".join(
        path.read_bytes() for path in config.private_root.rglob("*") if path.is_file()
    )
    assert _PRIVATE_RESPONSE_MARKER.encode() in private_payload

    restarted_store = AuthorizedRoleCompletionManifestStoreV2(
        config.private_root,
        private_authenticator=PrivateManifestHmacFixture(_MANIFEST_SECRET.encode("utf-8")),
    )
    restarted_handle = restarted_store.resolve_run_manifest_handle(config.run_id)
    assert restarted_handle == private_handle
    assert restarted_store.read_manifest(restarted_handle).content_hash() == manifest_hash

    outbound = json.dumps(
        [call["payload"] for call in transport.calls],
        sort_keys=True,
    )
    assert "expected_output" not in outbound
    assert '"oracle"' not in outbound


def test_run_stdout_contains_no_private_locator_or_operator_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    transport = CountingTransport()
    state_root = (tmp_path / "stdout-state").resolve()
    private_root = (tmp_path / "stdout-private").resolve()
    run_id = "deepseek-role-stdout-v2"
    original_execute = runner.execute_operator_mode

    def execute_with_fake_transport(
        config: runner.DeepSeekRoleOperatorConfig,
    ) -> runner.DeepSeekRolePublicReportV2:
        return original_execute(
            config,
            environment=_environment(),
            transport=transport,
            clock=_clock,
        )

    monkeypatch.setattr(runner, "execute_operator_mode", execute_with_fake_transport)
    exit_code = runner.main(
        [
            "run",
            "--operator-approved",
            "--state-root",
            str(state_root),
            "--private-root",
            str(private_root),
            "--run-id",
            run_id,
            "--max-cost-microusd-per-trial",
            "100000",
        ]
    )
    stdout = capsys.readouterr().out.strip()
    report = json.loads(stdout)
    private_store = AuthorizedRoleCompletionManifestStoreV2(
        private_root,
        private_authenticator=PrivateManifestHmacFixture(_MANIFEST_SECRET.encode("utf-8")),
    )
    private_handle = private_store.resolve_run_manifest_handle(run_id)

    assert exit_code == 0
    assert report["schema_version"] == "autolean.deepseek-role-operator.v2"
    assert report["private_evidence_committed"] is True
    assert len(transport.calls) == 10
    for forbidden in (
        private_handle,
        "private_manifest_handle",
        "completion-manifest-handles-v2",
        "completion-manifest-run-index-v2",
        str(state_root),
        str(private_root),
        _PRIVATE_RESPONSE_MARKER,
        _API_SECRET,
        _MANIFEST_SECRET,
    ):
        assert forbidden not in stdout


@pytest.mark.parametrize(
    ("api", "manifest"),
    (
        (None, _MANIFEST_SECRET),
        (_API_SECRET, None),
        (_MANIFEST_SECRET, _MANIFEST_SECRET),
    ),
)
def test_missing_or_shared_secrets_fail_before_state_or_io(
    tmp_path: Path,
    api: str | None,
    manifest: str | None,
) -> None:
    transport = CountingTransport()
    config = _config(tmp_path, "preflight")

    report = runner.execute_operator_mode(
        config,
        environment=_environment(api=api, manifest=manifest),
        transport=transport,
        clock=_clock,
    )

    assert report.status == "execution_refused"
    assert report.failure_class == "secret_reference_unavailable"
    assert transport.calls == []
    assert not config.state_root.exists()
    assert not config.private_root.exists()
    assert _API_SECRET not in _serialized(report)
    assert _MANIFEST_SECRET not in _serialized(report)


def test_checkout_root_and_missing_operator_approval_are_redacted(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    checkout_root = runner._REPOSITORY_ROOT / ".codex-tmp" / f"forbidden-role-state-{tmp_path.name}"
    private_root = (tmp_path / "private").resolve()

    exit_code = runner.main(
        [
            "preflight",
            "--operator-approved",
            "--state-root",
            str(checkout_root),
            "--private-root",
            str(private_root),
            "--run-id",
            "deepseek-role-invalid-root-v1",
            "--max-cost-microusd-per-trial",
            "100000",
        ]
    )
    invalid_root = json.loads(capsys.readouterr().out)
    assert exit_code == 2
    assert invalid_root["failure_class"] == "root_policy_rejected"
    assert str(checkout_root) not in json.dumps(invalid_root)
    assert not checkout_root.exists()

    exit_code = runner.main(
        [
            "plan",
            "--state-root",
            str((tmp_path / "state").resolve()),
            "--private-root",
            str(private_root),
            "--run-id",
            "deepseek-role-no-approval-v1",
            "--max-cost-microusd-per-trial",
            "100000",
        ]
    )
    no_approval = json.loads(capsys.readouterr().out)
    assert exit_code == 2
    assert no_approval["failure_class"] == "operator_approval_required"


@pytest.mark.parametrize(
    "unsafe_run_id",
    (
        "c:/operator-private-leak",
        r"\\operator-host\private-share",
        "deepseek-role-../private",
    ),
)
def test_path_shaped_run_id_is_rejected_without_public_echo(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    unsafe_run_id: str,
) -> None:
    exit_code = runner.main(
        [
            "plan",
            "--operator-approved",
            "--state-root",
            str((tmp_path / "state").resolve()),
            "--private-root",
            str((tmp_path / "private").resolve()),
            "--run-id",
            unsafe_run_id,
            "--max-cost-microusd-per-trial",
            "100000",
        ]
    )

    public = capsys.readouterr().out
    report = json.loads(public)
    assert exit_code == 2
    assert report["run_id"] == "unavailable"
    assert report["failure_class"] == "operator_policy_rejected"
    assert unsafe_run_id not in public
    assert not (tmp_path / "state").exists()
    assert not (tmp_path / "private").exists()


def test_low_provider_timeout_fails_before_model_work_or_io(tmp_path: Path) -> None:
    transport = CountingTransport()
    config = _config(tmp_path, "preflight")

    report = runner.execute_operator_mode(
        config,
        environment=_environment(),
        transport=transport,
        clock=_clock,
        _provider_timeout_override_seconds=119,
    )

    assert report.status == "execution_refused"
    assert report.failure_class == "provider_timeout_policy_rejected"
    assert transport.calls == []
    assert not config.state_root.exists()
    assert not config.private_root.exists()

    retried = runner.execute_operator_mode(
        config,
        environment=_environment(),
        transport=transport,
        clock=_clock,
    )
    assert retried.status == "preflight_ready"
    assert transport.calls == []
    assert _state_counts(config.state_root / "control.db") == (0,) * len(
        runner._MODEL_WORK_STATE_TABLES
    )


def test_dirty_state_root_is_rejected_without_any_additional_state(tmp_path: Path) -> None:
    transport = CountingTransport()
    config = _config(tmp_path, "preflight")
    config.state_root.mkdir(parents=True)
    sentinel = config.state_root / "operator-owned-state.bin"
    sentinel.write_bytes(b"EXISTING_OPERATOR_STATE")
    before = tuple(
        (path.relative_to(config.state_root).as_posix(), path.read_bytes())
        for path in config.state_root.rglob("*")
        if path.is_file()
    )

    report = runner.execute_operator_mode(
        config,
        environment=_environment(),
        transport=transport,
        clock=_clock,
    )

    after = tuple(
        (path.relative_to(config.state_root).as_posix(), path.read_bytes())
        for path in config.state_root.rglob("*")
        if path.is_file()
    )
    assert report.status == "execution_refused"
    assert report.failure_class == "operator_state_not_clean"
    assert transport.calls == []
    assert after == before
    assert not (config.state_root / "control.db").exists()
    assert not config.private_root.exists()


def _assert_retryable_initialization_failure(
    *,
    config: runner.DeepSeekRoleOperatorConfig,
    transport: CountingTransport,
    report: runner.DeepSeekRolePublicReportV2,
    secret_marker: str,
) -> None:
    assert report.status == "execution_refused"
    assert report.failure_class == "operator_initialization_quarantined"
    assert transport.calls == []
    assert not config.state_root.exists()
    assert not config.private_root.exists()
    assert secret_marker not in _serialized(report)
    quarantines = tuple(sorted(config.state_root.parent.glob(".*.autolean-quarantine-*")))
    assert len(quarantines) == 2
    for quarantine in quarantines:
        markers = tuple(
            marker
            for marker in (
                quarantine / runner._ROOT_INITIALIZING_MARKER,
                quarantine / runner._ROOT_READY_MARKER,
            )
            if marker.is_file()
        )
        assert len(markers) == 1
        assert len(markers[0].read_bytes()) == 32

    retried = runner.execute_operator_mode(
        config,
        environment=_environment(),
        transport=transport,
        clock=_clock,
    )
    assert retried.status == "preflight_ready"
    assert transport.calls == []
    assert all(quarantine.is_dir() for quarantine in quarantines)


def test_artifact_store_initialization_failure_rolls_back_and_retries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = "SECRET_ARTIFACT_INITIALIZATION_FAILURE"
    transport = CountingTransport()
    config = _config(tmp_path, "preflight")

    def fail_artifact_store(root: str | Path) -> None:
        del root
        raise ConfigurationError(marker)

    with monkeypatch.context() as scoped:
        scoped.setattr(runner, "ArtifactStore", fail_artifact_store)
        report = runner.execute_operator_mode(
            config,
            environment=_environment(),
            transport=transport,
            clock=_clock,
        )

    _assert_retryable_initialization_failure(
        config=config,
        transport=transport,
        report=report,
        secret_marker=marker,
    )


def test_private_store_initialization_failure_rolls_back_approval_and_retries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = "SECRET_PRIVATE_STORE_INITIALIZATION_FAILURE"
    transport = CountingTransport()
    config = _config(tmp_path, "preflight")

    def fail_private_store(root: Path, *, private_authenticator: object) -> None:
        del root, private_authenticator
        raise AuthorizedRoleBridgeError(marker)

    with monkeypatch.context() as scoped:
        scoped.setattr(runner, "AuthorizedRoleCompletionManifestStoreV2", fail_private_store)
        report = runner.execute_operator_mode(
            config,
            environment=_environment(),
            transport=transport,
            clock=_clock,
        )

    _assert_retryable_initialization_failure(
        config=config,
        transport=transport,
        report=report,
        secret_marker=marker,
    )


def test_approval_registration_failure_after_write_rolls_back_and_retries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = "SECRET_APPROVAL_REGISTRATION_FAILURE"
    transport = CountingTransport()
    config = _config(tmp_path, "preflight")
    original_register = ModelExecutionAuthorizationService.register_operator_approval

    def fail_after_register(
        service: ModelExecutionAuthorizationService,
        approval: ModelExecutionProviderApprovalV1,
        *,
        idempotency_key: str,
    ) -> None:
        original_register(
            service,
            approval,
            idempotency_key=idempotency_key,
        )
        raise ConfigurationError(marker)

    with monkeypatch.context() as scoped:
        scoped.setattr(
            ModelExecutionAuthorizationService,
            "register_operator_approval",
            fail_after_register,
        )
        report = runner.execute_operator_mode(
            config,
            environment=_environment(),
            transport=transport,
            clock=_clock,
        )

    _assert_retryable_initialization_failure(
        config=config,
        transport=transport,
        report=report,
        secret_marker=marker,
    )


def test_partial_root_publication_failure_rolls_back_and_retries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = "SECRET_ROOT_PUBLICATION_FAILURE"
    transport = CountingTransport()
    config = _config(tmp_path, "preflight")
    publish_one = runner._publish_owned_root

    def fail_after_first_publish(roots: Sequence[runner._OwnedOperatorRoot]) -> None:
        publish_one(roots[0])
        raise OSError(marker)

    with monkeypatch.context() as scoped:
        scoped.setattr(runner, "_publish_initialized_roots", fail_after_first_publish)
        report = runner.execute_operator_mode(
            config,
            environment=_environment(),
            transport=transport,
            clock=_clock,
        )

    _assert_retryable_initialization_failure(
        config=config,
        transport=transport,
        report=report,
        secret_marker=marker,
    )


def test_quarantine_never_deletes_swapped_foreign_data(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent_identity = runner._physical_directory_identity(tmp_path)
    parent = runner._OperatorParentSnapshot(
        path=tmp_path,
        device=parent_identity[0],
        inode=parent_identity[1],
    )
    owned = runner._claim_operator_root(tmp_path / "owned-root", parent=parent)
    original_matches = runner._owned_root_matches_at
    swapped: dict[str, Path] = {}

    def swap_after_quarantine_verification(
        candidate: runner._OwnedOperatorRoot,
        path: Path,
    ) -> bool:
        valid = original_matches(candidate, path)
        if valid and path != candidate.path and not swapped:
            original = path.with_name(f"{path.name}-actual-owned")
            path.rename(original)
            path.mkdir()
            (path / "FOREIGN_OPERATOR_DATA").write_bytes(b"FOREIGN")
            swapped["foreign"] = path
            swapped["owned"] = original
        return valid

    try:
        with monkeypatch.context() as scoped:
            scoped.setattr(
                runner,
                "_owned_root_matches_at",
                swap_after_quarantine_verification,
            )
            quarantined = runner._quarantine_owned_roots((owned,))

        assert quarantined is not None
        assert (swapped["foreign"] / "FOREIGN_OPERATOR_DATA").read_bytes() == b"FOREIGN"
        assert swapped["owned"].is_dir()
    finally:
        for path in swapped.values():
            if path.exists():
                shutil.rmtree(path)
        if owned.path.exists():
            shutil.rmtree(owned.path)


def test_parent_identity_drift_fails_before_state_or_private_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    sentinel = foreign / "FOREIGN_OPERATOR_DATA"
    sentinel.write_bytes(b"FOREIGN")
    config = _config(tmp_path, "preflight")
    transport = CountingTransport()
    original_matches = runner._parent_snapshot_matches
    checks = 0

    def drift_after_state_mkdir(snapshot: runner._OperatorParentSnapshot) -> bool:
        nonlocal checks
        checks += 1
        return original_matches(snapshot) if checks < 6 else False

    with monkeypatch.context() as scoped:
        scoped.setattr(
            runner,
            "_parent_snapshot_matches",
            drift_after_state_mkdir,
        )
        report = runner.execute_operator_mode(
            config,
            environment=_environment(),
            transport=transport,
            clock=_clock,
        )

    assert report.status == "execution_refused"
    assert report.failure_class == "operator_initialization_manual_review"
    assert transport.calls == []
    assert sentinel.read_bytes() == b"FOREIGN"
    assert config.state_root.is_dir()
    assert not tuple(config.state_root.iterdir())
    assert not config.private_root.exists()
    assert not tuple(tmp_path.rglob("control.db"))


def test_parent_symlink_swap_fails_closed_when_supported(tmp_path: Path) -> None:
    operator_parent = tmp_path / "operator-parent"
    operator_parent.mkdir()
    foreign = tmp_path / "foreign-parent"
    foreign.mkdir()
    sentinel = foreign / "FOREIGN_OPERATOR_DATA"
    sentinel.write_bytes(b"FOREIGN")
    config = runner.DeepSeekRoleOperatorConfig(
        mode="preflight",
        run_id="deepseek-role-parent-swap-v1",
        state_root=operator_parent / "state",
        private_root=operator_parent / "private",
        max_cost_microusd_per_trial=100_000,
        operator_approved=True,
    )
    backup = tmp_path / "operator-parent-original"
    operator_parent.rename(backup)
    try:
        try:
            os.symlink(foreign, operator_parent, target_is_directory=True)
        except OSError:
            backup.rename(operator_parent)
            pytest.skip("directory symlink creation is not available")

        report = runner.execute_operator_mode(
            config,
            environment=_environment(),
            transport=CountingTransport(),
            clock=_clock,
        )
        assert report.status == "execution_refused"
        assert report.failure_class == "root_policy_rejected"
        assert sentinel.read_bytes() == b"FOREIGN"
        assert not (foreign / "state").exists()
        assert not (foreign / "private").exists()
    finally:
        if operator_parent.is_symlink():
            operator_parent.unlink()
        if backup.exists() and not operator_parent.exists():
            backup.rename(operator_parent)


def test_provider_exception_is_redacted_and_never_automatically_retried(
    tmp_path: Path,
) -> None:
    secret_exception = "SECRET_PROVIDER_EXCEPTION_MUST_NOT_ESCAPE"
    transport = RaisingTransport(secret_exception)
    config = _config(tmp_path, "run")
    prepared = runner.preflight_deepseek_role_operator(
        config,
        environment=_environment(),
        transport=transport,
        clock=_clock,
    )

    first = runner.run_preflighted_deepseek_role_operator(prepared)
    second = runner.run_preflighted_deepseek_role_operator(prepared)

    assert first.status == "reconciliation_required"
    assert first.failure_class == "transport_unclassified"
    assert second.status == "reconciliation_required"
    assert second.failure_class == "private_reconciliation_required"
    assert transport.calls == 1
    assert secret_exception not in _serialized(first)
    assert secret_exception not in _serialized(second)
    assert first.private_evidence_committed is False
    assert second.private_evidence_committed is False


def test_runner_never_reads_backup_or_dotenv_files() -> None:
    source = Path(runner.__file__).read_text(encoding="utf-8")
    assert "llm.txt" not in source
    assert "dotenv" not in source.casefold()
    assert 'Path(".env")' not in source
    assert "rmtree" not in source
    assert ".unlink(" not in source
    assert ".rmdir(" not in source
