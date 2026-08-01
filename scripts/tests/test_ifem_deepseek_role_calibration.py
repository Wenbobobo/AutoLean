"""Focused iFEM operator-runner checks; all provider calls use an injected recording transport."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path

import pytest
from autolean_contracts import canonical_json_bytes

from benchmarks.ifem_synthetic_role_bridge import (
    IFEMSyntheticRoleResponseContractV1,
    ifem_synthetic_role_system_prompt,
)
from benchmarks.ifem_synthetic_role_private_ledger import (
    IFEMSyntheticRolePrivateCoordinateV1,
    LocalIFEMSyntheticRolePrivateLedger,
)
from scripts import ifem_deepseek_role_calibration as runner
from scripts import ifem_private_evaluation as private_evaluator

_API_KEY = "d32-api-key-" + ("a" * 40)
_OPERATOR_SEED = "d32-operator-seed-" + ("b" * 48)
_LEDGER_KEY = "d32-ledger-key-" + ("c" * 48)
_RAW_OUTPUT = '{"selected_option":"option_a","reason":"D32_PRIVATE_RAW_OUTPUT"}'


def _create_directory_link(path: Path, target: Path) -> None:
    if os.name == "nt":
        completed = subprocess.run(
            ["cmd.exe", "/d", "/c", "mklink", "/J", str(path), str(target)],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            pytest.skip("directory junction creation is unavailable")
        return
    try:
        path.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink creation is unavailable")


def _remove_directory_link(path: Path) -> None:
    if bool(getattr(path, "is_junction", lambda: False)()):
        os.rmdir(path)
    elif path.is_symlink():
        path.unlink()


class RecordingTransport:
    def __init__(self) -> None:
        self.calls: list[bytes] = []

    def post_json(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        payload: Mapping[str, object],
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        del url, headers, payload, timeout_seconds
        raise AssertionError("the exact D32 executor must send canonical bytes")

    def post_json_bytes(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        assert url == "https://api.deepseek.com/chat/completions"
        assert headers["Authorization"] == f"Bearer {_API_KEY}"
        assert timeout_seconds == 120
        self.calls.append(body)
        return {
            "id": f"private-d32-response-{len(self.calls)}",
            "model": "deepseek-v4-pro",
            "choices": [{"message": {"content": _RAW_OUTPUT}}],
            "usage": {"prompt_tokens": 12, "completion_tokens": 4},
        }


def _environment() -> dict[str, str]:
    return {
        "AUTOLEAN_DEEPSEEK_API_KEY": _API_KEY,
        "AUTOLEAN_IFEM_OPERATOR_SEED": _OPERATOR_SEED,
        "AUTOLEAN_IFEM_LEDGER_HMAC_KEY": _LEDGER_KEY,
    }


def _config(
    tmp_path: Path,
    mode: str,
    *,
    approved: bool = False,
    protocol_id: str = "d32-v1",
) -> runner.IFEMDeepSeekRoleCalibrationConfig:
    tmp_path.mkdir(parents=True, exist_ok=True)
    return runner.IFEMDeepSeekRoleCalibrationConfig(
        mode=mode,  # type: ignore[arg-type]
        state_root=(tmp_path / "state").resolve(),
        private_root=(tmp_path / "private").resolve(),
        protocol_id=protocol_id,
        operator_approved=approved,
    )


def test_plan_and_preflight_are_read_only_and_do_not_resolve_secrets(tmp_path: Path) -> None:
    transport = RecordingTransport()
    plan_config = _config(tmp_path / "plan", "plan")
    preflight_config = _config(tmp_path / "preflight", "preflight")

    planned = runner.execute_ifem_deepseek_role_calibration(
        plan_config,
        environment={},
        transport=transport,
    )
    preflight = runner.execute_ifem_deepseek_role_calibration(
        preflight_config,
        environment={},
        transport=transport,
    )

    assert planned.status == "planned"
    assert preflight.status == "preflight_ready"
    assert planned.case_count == preflight.case_count == 16
    assert (
        planned.role_counts
        == preflight.role_counts
        == {
            "statement_formalizer": 8,
            "fidelity_reviewer": 4,
            "cheating_supervisor": 4,
        }
    )
    assert transport.calls == []
    assert not plan_config.state_root.exists()
    assert not plan_config.private_root.exists()
    assert not preflight_config.state_root.exists()
    assert not preflight_config.private_root.exists()


def test_run_prepares_exact_sixteen_coordinates_without_network(tmp_path: Path) -> None:
    plan = runner.build_ifem_deepseek_role_calibration_plan()
    transport = RecordingTransport()

    inputs = runner._prepare_run_inputs(plan, environment=_environment(), transport=transport)
    coordinates = tuple(
        IFEMSyntheticRolePrivateCoordinateV1.from_prepared(item)
        for item in inputs.preflight.prepared
    )

    assert len(inputs.preflight.prepared) == 16
    assert len({item.coordinate_hash() for item in coordinates}) == 16
    assert {item.case_id.value for item in coordinates} == {
        item.case_id.value for item in inputs.fixture.cases
    }
    assert {item.role.value for item in coordinates} == {
        "statement_formalizer",
        "fidelity_reviewer",
        "cheating_supervisor",
    }
    assert inputs.preflight.adapter.network_call_count == 0
    assert transport.calls == []


def test_run_refuses_missing_approval_or_secret_without_claiming_roots(tmp_path: Path) -> None:
    transport = RecordingTransport()
    denied_config = _config(tmp_path / "approval", "run")
    missing_config = _config(tmp_path / "secret", "run", approved=True)
    denied = runner.execute_ifem_deepseek_role_calibration(
        denied_config,
        environment=_environment(),
        transport=transport,
    )
    missing = runner.execute_ifem_deepseek_role_calibration(
        missing_config,
        environment={},
        transport=transport,
    )

    assert denied.status == "execution_refused"
    assert denied.failure_class == "operator_approval_required"
    assert missing.status == "execution_refused"
    assert missing.failure_class == "secret_reference_unavailable"
    assert transport.calls == []
    assert not denied_config.state_root.exists()
    assert not denied_config.private_root.exists()
    assert not missing_config.state_root.exists()
    assert not missing_config.private_root.exists()


def test_root_policy_rejects_checkout_and_foreign_root_without_network(tmp_path: Path) -> None:
    with pytest.raises(runner.OperatorRootRejected, match="outside the checkout"):
        runner.IFEMDeepSeekRoleCalibrationConfig(
            mode="plan",
            state_root=runner._REPOSITORY_ROOT / "d32-forbidden-state",
            private_root=(tmp_path / "private").resolve(),
            protocol_id="d32-v1",
        )

    state_root = (tmp_path / "foreign" / "state").resolve()
    private_root = (tmp_path / "foreign" / "private").resolve()
    state_root.mkdir(parents=True)
    private_root.mkdir()
    sentinel = private_root / "FOREIGN_OPERATOR_DATA"
    sentinel.write_text("FOREIGN", encoding="ascii")
    transport = RecordingTransport()
    preflight = runner.execute_ifem_deepseek_role_calibration(
        runner.IFEMDeepSeekRoleCalibrationConfig(
            mode="preflight",
            state_root=state_root,
            private_root=private_root,
            protocol_id="d32-v1",
        ),
        environment={},
        transport=transport,
    )
    report = runner.execute_ifem_deepseek_role_calibration(
        runner.IFEMDeepSeekRoleCalibrationConfig(
            mode="run",
            state_root=state_root,
            private_root=private_root,
            protocol_id="d32-v1",
            operator_approved=True,
        ),
        environment=_environment(),
        transport=transport,
    )

    assert preflight.status == "execution_refused"
    assert preflight.failure_class == "root_policy_rejected"
    assert report.status == "execution_refused"
    assert report.failure_class == "root_policy_rejected"
    assert transport.calls == []
    assert sentinel.read_text(encoding="ascii") == "FOREIGN"


def test_private_child_root_rejects_a_link_substitution_when_supported(tmp_path: Path) -> None:
    private_root = (tmp_path / "private").resolve()
    foreign = (tmp_path / "foreign").resolve()
    private_root.mkdir()
    foreign.mkdir()
    candidate = private_root / "responses-v1"
    try:
        _create_directory_link(candidate, foreign)
        with pytest.raises(runner.OperatorRootRejected, match="physical directory"):
            runner._private_child_root(private_root, "responses-v1")
    finally:
        _remove_directory_link(candidate)


def test_partial_cas_recovery_never_repeats_external_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path, "run", approved=True)
    transport = RecordingTransport()
    original_append = LocalIFEMSyntheticRolePrivateLedger._append_event
    failed = False

    def crash_after_private_cas(self, *, transition, **kwargs):  # type: ignore[no-untyped-def]
        nonlocal failed
        if transition == "response_persisted" and not failed:
            failed = True
            raise OSError("injected private terminal interruption")
        return original_append(self, transition=transition, **kwargs)

    monkeypatch.setattr(
        LocalIFEMSyntheticRolePrivateLedger,
        "_append_event",
        crash_after_private_cas,
    )
    interrupted = runner.execute_ifem_deepseek_role_calibration(
        config,
        environment=_environment(),
        transport=transport,
    )
    monkeypatch.setattr(
        LocalIFEMSyntheticRolePrivateLedger,
        "_append_event",
        original_append,
    )
    recovered = runner.execute_ifem_deepseek_role_calibration(
        config,
        environment=_environment(),
        transport=transport,
    )

    assert interrupted.status == "reconciliation_required"
    assert recovered.status == "settled"
    assert len(transport.calls) == 16


def test_stdout_is_redacted_and_complete_restart_reuses_private_ledger(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = _config(tmp_path, "run", approved=True)
    transport = RecordingTransport()
    first = runner.execute_ifem_deepseek_role_calibration(
        config,
        environment=_environment(),
        transport=transport,
    )
    second = runner.execute_ifem_deepseek_role_calibration(
        config,
        environment=_environment(),
        transport=transport,
    )
    monkeypatch.setattr(runner, "execute_ifem_deepseek_role_calibration", lambda _config: first)

    assert (
        runner.main(
            [
                "run",
                "--operator-approved",
                "--state-root",
                str(config.state_root),
                "--private-root",
                str(config.private_root),
                "--protocol",
                "d32-v1",
            ]
        )
        == 0
    )
    stdout = capsys.readouterr().out

    assert first.status == second.status == "settled"
    assert len(transport.calls) == 16
    assert json.loads(stdout)["private_evidence_committed"] is True
    for forbidden in (
        _API_KEY,
        _OPERATOR_SEED,
        _LEDGER_KEY,
        _RAW_OUTPUT,
        str(tmp_path),
        hashlib.sha256(_OPERATOR_SEED.encode("utf-8")).hexdigest(),
        "oracle",
        "expected_option",
        "response_id",
    ):
        assert forbidden not in stdout


def test_operator_material_is_initialized_once_and_reused(tmp_path: Path) -> None:
    root = (tmp_path / "operator-material").resolve()

    first = runner._load_or_initialize_operator_material(root)
    second = runner._load_or_initialize_operator_material(root)

    assert first == second
    assert first[0] != first[1]
    assert all(len(value.encode("utf-8")) >= 32 for value in first)
    assert {item.name for item in root.iterdir()} == {
        runner._MATERIAL_MARKER_NAME,
        runner._OPERATOR_SEED_FILE,
        runner._LEDGER_KEY_FILE,
    }


def test_operator_material_rejects_foreign_files(tmp_path: Path) -> None:
    root = (tmp_path / "operator-material").resolve()
    runner._load_or_initialize_operator_material(root)
    (root / "foreign.txt").write_text("foreign", encoding="ascii")

    with pytest.raises(runner.OperatorSecretUnavailable, match="incomplete or foreign"):
        runner._load_or_initialize_operator_material(root)


def test_operator_secret_file_accepts_an_external_physical_regular_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout = (tmp_path / "checkout").resolve()
    external = (tmp_path / "external").resolve()
    checkout.mkdir()
    external.mkdir()
    secret_file = external / "api-key.txt"
    secret_file.write_text(_API_KEY, encoding="ascii")
    monkeypatch.setattr(runner, "_REPOSITORY_ROOT", checkout)

    assert runner._read_operator_secret_file(secret_file, minimum_bytes=1) == _API_KEY


def test_operator_api_key_file_accepts_one_assignment_with_nonsecret_endpoint_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout = (tmp_path / "checkout").resolve()
    external = (tmp_path / "external").resolve()
    checkout.mkdir()
    external.mkdir()
    secret_file = external / "api-key.txt"
    secret_file.write_text(
        f"BASE_URL = https://api.deepseek.com\r\nAPI_KEY = {_API_KEY}",
        encoding="utf-8",
    )
    monkeypatch.setattr(runner, "_REPOSITORY_ROOT", checkout)

    assert runner._read_operator_api_key_file(secret_file) == _API_KEY


def test_operator_api_key_file_rejects_a_second_sensitive_assignment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout = (tmp_path / "checkout").resolve()
    external = (tmp_path / "external").resolve()
    checkout.mkdir()
    external.mkdir()
    secret_file = external / "api-key.txt"
    secret_file.write_text(
        f"API_KEY = {_API_KEY}\nPASSWORD = unrelated-sensitive-value",
        encoding="utf-8",
    )
    monkeypatch.setattr(runner, "_REPOSITORY_ROOT", checkout)

    with pytest.raises(runner.OperatorSecretUnavailable, match="contains another secret"):
        runner._read_operator_api_key_file(secret_file)


def test_cli_rejects_checkout_secret_file_before_read_material_roots_or_transport(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    checkout = (tmp_path / "checkout").resolve()
    external = (tmp_path / "external").resolve()
    checkout.mkdir()
    external.mkdir()
    checkout_secret = checkout / "llm.txt"
    checkout_secret.write_text(_API_KEY, encoding="ascii")
    state_root = external / "state"
    private_root = external / "private"
    operator_material_root = external / "operator-material"
    read_attempts: list[Path] = []
    material_attempts: list[Path] = []
    transport_instances: list[object] = []

    def unexpected_secret_read(path: Path) -> str:
        read_attempts.append(path)
        raise AssertionError("checkout-internal secret bytes must not be read")

    def unexpected_material_initialization(path: Path) -> tuple[str, str]:
        material_attempts.append(path)
        raise AssertionError("operator material must not be initialized")

    class UnexpectedTransport:
        def __init__(self) -> None:
            transport_instances.append(self)

    monkeypatch.setattr(runner, "_REPOSITORY_ROOT", checkout)
    monkeypatch.setattr(runner, "_read_operator_api_key_file", unexpected_secret_read)
    monkeypatch.setattr(
        runner,
        "_load_or_initialize_operator_material",
        unexpected_material_initialization,
    )
    monkeypatch.setattr(runner, "HttpxResponsesTransport", UnexpectedTransport)

    assert (
        runner.main(
            [
                "run",
                "--operator-approved",
                "--protocol",
                "d35-v3",
                "--state-root",
                str(state_root),
                "--private-root",
                str(private_root),
                "--api-key-file",
                str(checkout_secret),
                "--operator-material-root",
                str(operator_material_root),
            ]
        )
        == 2
    )
    report = json.loads(capsys.readouterr().out)

    assert report["status"] == "execution_refused"
    assert report["failure_class"] == "secret_reference_unavailable"
    assert report["protocol_id"] == "d35-v3"
    assert read_attempts == []
    assert material_attempts == []
    assert transport_instances == []
    assert not state_root.exists()
    assert not private_root.exists()
    assert not operator_material_root.exists()


@pytest.mark.parametrize("mode", ("plan", "preflight"))
def test_cli_rejects_secret_file_options_outside_run_before_read_or_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    mode: str,
) -> None:
    external = (tmp_path / "external").resolve()
    external.mkdir()
    secret_file = external / "api-key.txt"
    secret_file.write_text(_API_KEY, encoding="ascii")
    state_root = external / "state"
    private_root = external / "private"
    operator_material_root = external / "operator-material"
    read_attempts: list[Path] = []
    material_attempts: list[Path] = []
    transport_instances: list[object] = []

    def unexpected_secret_read(path: Path) -> str:
        read_attempts.append(path)
        raise AssertionError("plan and preflight must not read secret bytes")

    def unexpected_material_initialization(path: Path) -> tuple[str, str]:
        material_attempts.append(path)
        raise AssertionError("plan and preflight must not initialize operator material")

    class UnexpectedTransport:
        def __init__(self) -> None:
            transport_instances.append(self)

    monkeypatch.setattr(runner, "_read_operator_api_key_file", unexpected_secret_read)
    monkeypatch.setattr(
        runner,
        "_load_or_initialize_operator_material",
        unexpected_material_initialization,
    )
    monkeypatch.setattr(runner, "HttpxResponsesTransport", UnexpectedTransport)

    assert (
        runner.main(
            [
                mode,
                "--protocol",
                "d35-v3",
                "--state-root",
                str(state_root),
                "--private-root",
                str(private_root),
                "--api-key-file",
                str(secret_file),
                "--operator-material-root",
                str(operator_material_root),
            ]
        )
        == 2
    )
    report = json.loads(capsys.readouterr().out)

    assert report["status"] == "execution_refused"
    assert report["failure_class"] == "secret_reference_unavailable"
    assert read_attempts == []
    assert material_attempts == []
    assert transport_instances == []
    assert not state_root.exists()
    assert not private_root.exists()
    assert not operator_material_root.exists()


def test_operator_secret_file_rejects_parent_link_before_content_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout = (tmp_path / "checkout").resolve()
    physical_parent = (tmp_path / "physical").resolve()
    linked_parent = tmp_path / "linked"
    checkout.mkdir()
    physical_parent.mkdir()
    (physical_parent / "api-key.txt").write_text(_API_KEY, encoding="ascii")
    read_attempts: list[Path] = []

    def unexpected_physical_read(path: Path, **_kwargs: object) -> bytes:
        read_attempts.append(path)
        raise AssertionError("linked secret path must fail before content read")

    try:
        _create_directory_link(linked_parent, physical_parent)
        monkeypatch.setattr(runner, "_REPOSITORY_ROOT", checkout)
        monkeypatch.setattr(runner, "_read_physical_regular_file", unexpected_physical_read)

        with pytest.raises(runner.OperatorSecretUnavailable, match="external physical"):
            runner._read_operator_secret_file(
                linked_parent / "api-key.txt",
                minimum_bytes=1,
            )
    finally:
        _remove_directory_link(linked_parent)

    assert read_attempts == []


def test_legacy_d32_v1_root_pair_remains_readable_and_rebuildable(tmp_path: Path) -> None:
    config = _config(tmp_path, "run", approved=True)
    plan = runner.build_ifem_deepseek_role_calibration_plan()
    transport = RecordingTransport()
    inputs = runner._prepare_run_inputs(plan, environment=_environment(), transport=transport)
    config.state_root.mkdir()
    config.private_root.mkdir()
    nonce = "a" * 64
    for kind, root in (("state", config.state_root), ("private", config.private_root)):
        unsigned = {
            "schema_version": "autolean.ifem-deepseek-role-calibration-root.v1",
            "root_kind": kind,
            "run_nonce": nonce,
            "fixture_content_sha256": inputs.fixture.content_sha256,
            "provider_configuration_digest": inputs.executor.configuration_hash.value,
        }
        marker = runner._RootMarkerV1.model_validate(
            {
                **unsigned,
                "authentication_tag": inputs.authenticator.authenticate(
                    canonical_json_bytes(unsigned)
                ),
            }
        )
        runner._write_root_marker(root, marker)

    report = runner.execute_ifem_deepseek_role_calibration(
        config,
        environment=_environment(),
        transport=transport,
    )

    assert report.status == "settled"
    assert report.protocol_id == runner.IFEMDeepSeekRoleCalibrationProtocolIdV1.D32_V1
    assert len(transport.calls) == 16


def test_legacy_v2_root_is_limited_to_its_original_corpus_revision(tmp_path: Path) -> None:
    config = _config(tmp_path, "run", approved=True, protocol_id="d34-v2")
    plan = runner.build_ifem_deepseek_role_calibration_plan(protocol_id="d34-v2")
    transport = RecordingTransport()
    inputs = runner._prepare_run_inputs(plan, environment=_environment(), transport=transport)
    config.state_root.mkdir()
    config.private_root.mkdir()
    nonce = "b" * 64
    for kind, root in (("state", config.state_root), ("private", config.private_root)):
        unsigned = {
            "schema_version": "autolean.ifem-deepseek-role-calibration-root.v2",
            "root_kind": kind,
            "run_nonce": nonce,
            "fixture_content_sha256": inputs.fixture.content_sha256,
            "provider_configuration_digest": inputs.executor.configuration_hash.value,
            "protocol_id": plan.protocol.protocol_id.value,
            "profile_content_sha256": hashlib.sha256(plan.profile_bytes).hexdigest(),
            "request_policy_content_sha256": runner._request_policy_content_sha256(
                plan.request_policy
            ),
            "response_contract": plan.response_contract.value,
        }
        marker = runner._RootMarkerV2.model_validate(
            {
                **unsigned,
                "authentication_tag": inputs.authenticator.authenticate(
                    canonical_json_bytes(unsigned)
                ),
            }
        )
        runner._write_root_marker(root, marker)

    report = runner.execute_ifem_deepseek_role_calibration(
        config,
        environment=_environment(),
        transport=transport,
    )

    assert report.status == "settled"
    assert len(transport.calls) == 16

    successor_plan = replace(
        plan,
        protocol=replace(
            plan.protocol,
            expected_corpus_file_sha256="0" * 64,
        ),
    )
    with pytest.raises(runner.OperatorRootRejected, match="successor public inputs"):
        runner._verify_owned_root(
            config.private_root,
            kind="private",
            plan=successor_plan,
            fixture=inputs.fixture,
            executor=inputs.executor,
            authenticator=inputs.authenticator,
        )


def test_d34_v2_prepares_a_512_token_selected_option_only_contract() -> None:
    plan = runner.build_ifem_deepseek_role_calibration_plan(protocol_id="d34-v2")
    transport = RecordingTransport()
    inputs = runner._prepare_run_inputs(plan, environment=_environment(), transport=transport)

    assert plan.protocol.protocol_id == runner.IFEMDeepSeekRoleCalibrationProtocolIdV1.D34_V2
    assert plan.response_contract is IFEMSyntheticRoleResponseContractV1.SELECTED_OPTION_ONLY_V2
    assert plan.request_policy.max_output_tokens == 512
    assert inputs.executor.request_policy == plan.request_policy
    for prepared in inputs.preflight.prepared:
        body = json.loads(prepared.body)
        system = body["messages"][0]["content"]
        assert body["max_tokens"] == 512
        assert system == ifem_synthetic_role_system_prompt(
            prepared.role,
            response_contract=IFEMSyntheticRoleResponseContractV1.SELECTED_OPTION_ONLY_V2,
        )
        assert "exactly one selected_option field" in system
        assert "reason" not in system
    assert transport.calls == []


def test_d35_v3_is_a_1024_token_d34_successor_without_other_generation_changes(
    tmp_path: Path,
) -> None:
    d34_plan = runner.build_ifem_deepseek_role_calibration_plan(protocol_id="d34-v2")
    d35_plan = runner.build_ifem_deepseek_role_calibration_plan(protocol_id="d35-v3")
    transport = RecordingTransport()
    inputs = runner._prepare_run_inputs(d35_plan, environment=_environment(), transport=transport)

    assert d35_plan.protocol.protocol_id == runner.IFEMDeepSeekRoleCalibrationProtocolIdV1.D35_V3
    assert d35_plan.profile.profile_id == "deepseek-v4-pro-ifem-role-d35"
    assert d35_plan.profile.model_id == d34_plan.profile.model_id == "deepseek-v4-pro"
    assert d35_plan.graph == d34_plan.graph
    assert d35_plan.corpus == d34_plan.corpus
    assert d35_plan.case_count == d34_plan.case_count == 16
    assert d35_plan.role_counts == d34_plan.role_counts
    assert (
        d35_plan.request_policy.max_input_tokens == d34_plan.request_policy.max_input_tokens == 2048
    )
    assert (
        d35_plan.request_policy.reasoning_effort
        == d34_plan.request_policy.reasoning_effort
        == "high"
    )
    assert d35_plan.request_policy.max_output_tokens == 1024
    assert d34_plan.request_policy.max_output_tokens == 512
    assert d35_plan.response_contract is (
        IFEMSyntheticRoleResponseContractV1.SELECTED_OPTION_ONLY_V2
    )
    assert d35_plan.response_contract is d34_plan.response_contract

    d34_profile = json.loads(d34_plan.profile_bytes)
    d35_profile = json.loads(d35_plan.profile_bytes)
    assert {key for key in d34_profile if d34_profile[key] != d35_profile[key]} == {
        "profile_id",
        "canary_max_output_tokens",
    }
    assert set(d34_profile) == set(d35_profile)

    assert inputs.executor.request_policy == d35_plan.request_policy
    for prepared in inputs.preflight.prepared:
        body = json.loads(prepared.body)
        system = body["messages"][0]["content"]
        assert body["max_tokens"] == 1024
        assert system == ifem_synthetic_role_system_prompt(
            prepared.role,
            response_contract=IFEMSyntheticRoleResponseContractV1.SELECTED_OPTION_ONLY_V2,
        )
        assert "exactly one selected_option field" in system
        assert "reason" not in system
    assert transport.calls == []

    report = runner.execute_ifem_deepseek_role_calibration(
        _config(tmp_path, "plan", protocol_id="d35-v3"),
        environment={},
        transport=transport,
    )
    assert report.status == "planned"
    assert report.authority == runner.IFEMDeepSeekRoleCalibrationAuthorityV1()


@pytest.mark.parametrize(
    "protocol_id",
    ("d32-v1", "d34-v2", "d35-v3"),
)
def test_protocols_pin_their_current_profile_graph_and_corpus_bytes(protocol_id: str) -> None:
    plan = runner.build_ifem_deepseek_role_calibration_plan(protocol_id=protocol_id)

    assert hashlib.sha256(plan.profile_bytes).hexdigest() == (
        plan.protocol.expected_profile_content_sha256
    )
    assert runner._GRAPH_PATH == (
        runner._REPOSITORY_ROOT
        / "Builder"
        / "pilots"
        / "discovery"
        / "ifem-candidate-dependency-graph.v1.json"
    )
    assert hashlib.sha256(runner._GRAPH_PATH.read_bytes()).hexdigest() == (
        plan.protocol.expected_graph_file_sha256
    )
    assert plan.graph.content_sha256 == plan.protocol.expected_graph_content_sha256
    assert runner._CORPUS_PATH == (
        runner._REPOSITORY_ROOT
        / "Builder"
        / "pilots"
        / "discovery"
        / "ifem-structural-role-probe-corpus.v1.json"
    )
    assert hashlib.sha256(runner._CORPUS_PATH.read_bytes()).hexdigest() == (
        plan.protocol.expected_corpus_file_sha256
    )
    assert plan.corpus.content_sha256 == plan.protocol.expected_corpus_content_sha256


@pytest.mark.parametrize("input_kind", ("graph", "corpus", "profile"))
def test_plan_rejects_public_input_parent_directory_links(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    input_kind: str,
) -> None:
    protocol_id = runner.IFEMDeepSeekRoleCalibrationProtocolIdV1.D34_V2
    protocol = runner._PROTOCOLS[protocol_id]
    source = {
        "graph": runner._GRAPH_PATH,
        "corpus": runner._CORPUS_PATH,
        "profile": protocol.profile_path,
    }[input_kind]
    physical = tmp_path / f"physical-{input_kind}"
    physical.mkdir()
    target = physical / source.name
    target.write_bytes(source.read_bytes())
    linked_parent = tmp_path / f"linked-{input_kind}"
    try:
        _create_directory_link(linked_parent, physical)
        linked_input = linked_parent / source.name
        if input_kind == "graph":
            monkeypatch.setattr(runner, "_GRAPH_PATH", linked_input)
        elif input_kind == "corpus":
            monkeypatch.setattr(runner, "_CORPUS_PATH", linked_input)
        else:
            monkeypatch.setitem(
                runner._PROTOCOLS,
                protocol_id,
                replace(protocol, profile_path=linked_input),
            )

        with pytest.raises(runner.IFEMDeepSeekRoleCalibrationError):
            runner.build_ifem_deepseek_role_calibration_plan(protocol_id=protocol_id)
    finally:
        _remove_directory_link(linked_parent)


@pytest.mark.parametrize(
    "field",
    (
        "expected_graph_file_sha256",
        "expected_graph_content_sha256",
        "expected_corpus_file_sha256",
        "expected_corpus_content_sha256",
    ),
)
def test_public_input_hash_drift_is_refused_before_roots_or_transport(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    protocol_id = runner.IFEMDeepSeekRoleCalibrationProtocolIdV1.D34_V2
    protocol = runner._PROTOCOLS[protocol_id]
    if field == "expected_graph_file_sha256":
        drifted_protocol = replace(protocol, expected_graph_file_sha256="0" * 64)
    elif field == "expected_graph_content_sha256":
        drifted_protocol = replace(protocol, expected_graph_content_sha256="0" * 64)
    elif field == "expected_corpus_file_sha256":
        drifted_protocol = replace(protocol, expected_corpus_file_sha256="0" * 64)
    else:
        drifted_protocol = replace(protocol, expected_corpus_content_sha256="0" * 64)
    monkeypatch.setitem(
        runner._PROTOCOLS,
        protocol_id,
        drifted_protocol,
    )
    config = _config(tmp_path, "run", approved=True, protocol_id=protocol_id.value)
    transport = RecordingTransport()

    report = runner.execute_ifem_deepseek_role_calibration(
        config,
        environment=_environment(),
        transport=transport,
    )

    assert report.status == "execution_refused"
    assert report.failure_class == "operator_policy_rejected"
    assert transport.calls == []
    assert not config.state_root.exists()
    assert not config.private_root.exists()


def test_profile_sha_drift_is_refused_before_roots_or_transport(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    protocol_id = runner.IFEMDeepSeekRoleCalibrationProtocolIdV1.D34_V2
    monkeypatch.setitem(
        runner._PROTOCOLS,
        protocol_id,
        replace(
            runner._PROTOCOLS[protocol_id],
            expected_profile_content_sha256="0" * 64,
        ),
    )
    config = _config(tmp_path, "run", approved=True, protocol_id=protocol_id.value)
    transport = RecordingTransport()

    report = runner.execute_ifem_deepseek_role_calibration(
        config,
        environment=_environment(),
        transport=transport,
    )

    assert report.status == "execution_refused"
    assert report.failure_class == "operator_policy_rejected"
    assert transport.calls == []
    assert not config.state_root.exists()
    assert not config.private_root.exists()


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("graph_file_sha256", "4" * 64),
        ("graph_content_sha256", "5" * 64),
        ("corpus_file_sha256", "2" * 64),
        ("corpus_content_sha256", "3" * 64),
        ("profile_content_sha256", "0" * 64),
        ("request_policy_content_sha256", "1" * 64),
        ("response_contract", "selected_option_and_reason.v1"),
    ),
)
def test_d34_individual_root_binding_mutations_fail_before_recovery_transport_or_public_output(
    tmp_path: Path,
    field: str,
    replacement: str,
) -> None:
    operator_material = (tmp_path / "operator-material").resolve()
    seed, ledger_key = runner._load_or_initialize_operator_material(operator_material)
    environment = {
        "AUTOLEAN_DEEPSEEK_API_KEY": _API_KEY,
        "AUTOLEAN_IFEM_OPERATOR_SEED": seed,
        "AUTOLEAN_IFEM_LEDGER_HMAC_KEY": ledger_key,
    }
    config = _config(tmp_path / "run", "run", approved=True, protocol_id="d34-v2")
    initial_transport = RecordingTransport()
    settled = runner.execute_ifem_deepseek_role_calibration(
        config,
        environment=environment,
        transport=initial_transport,
    )
    assert settled.status == "settled"
    assert len(initial_transport.calls) == 16

    plan = runner.build_ifem_deepseek_role_calibration_plan(protocol_id="d34-v2")
    signing_inputs = runner._prepare_run_inputs(
        plan,
        environment=environment,
        transport=RecordingTransport(),
    )
    marker = runner._read_root_marker(config.private_root)
    assert isinstance(marker, runner._RootMarkerV3)
    assert marker.graph_file_sha256 == plan.protocol.expected_graph_file_sha256
    assert marker.graph_content_sha256 == plan.protocol.expected_graph_content_sha256
    assert marker.corpus_file_sha256 == plan.protocol.expected_corpus_file_sha256
    assert marker.corpus_content_sha256 == plan.protocol.expected_corpus_content_sha256
    payload = marker.model_dump(mode="json")
    payload[field] = replacement
    unsigned = {key: value for key, value in payload.items() if key != "authentication_tag"}
    payload["authentication_tag"] = signing_inputs.authenticator.authenticate(
        canonical_json_bytes(unsigned)
    )
    (config.private_root / runner._ROOT_MARKER_NAME).write_bytes(canonical_json_bytes(payload))

    recovery_transport = RecordingTransport()
    recovered = runner.execute_ifem_deepseek_role_calibration(
        config,
        environment=environment,
        transport=recovery_transport,
    )
    public_root = (tmp_path / "public").resolve()
    with pytest.raises(runner.OperatorRootRejected, match="does not match this protocol"):
        private_evaluator.evaluate_settled_ifem_private_run(
            private_root=config.private_root,
            operator_material_root=operator_material,
            public_output_root=public_root,
            protocol_id="d34-v2",
        )

    assert recovered.status == "execution_refused"
    assert recovered.failure_class == "root_policy_rejected"
    assert recovery_transport.calls == []
    assert not public_root.exists()


def test_protocol_root_mismatch_is_refused_before_any_v2_transport(tmp_path: Path) -> None:
    roots = tmp_path / "roots"
    d32_transport = RecordingTransport()
    d32_config = _config(roots, "run", approved=True)
    settled = runner.execute_ifem_deepseek_role_calibration(
        d32_config,
        environment=_environment(),
        transport=d32_transport,
    )
    d34_transport = RecordingTransport()
    d34 = runner.execute_ifem_deepseek_role_calibration(
        runner.IFEMDeepSeekRoleCalibrationConfig(
            mode="run",
            state_root=d32_config.state_root,
            private_root=d32_config.private_root,
            protocol_id="d34-v2",
            operator_approved=True,
        ),
        environment=_environment(),
        transport=d34_transport,
    )

    assert settled.status == "settled"
    assert d34.status == "execution_refused"
    assert d34.failure_class == "root_policy_rejected"
    assert len(d32_transport.calls) == 16
    assert d34_transport.calls == []


def test_d35_root_mismatch_is_refused_before_any_provider_transport(tmp_path: Path) -> None:
    roots = tmp_path / "roots"
    d34_transport = RecordingTransport()
    d34_config = _config(roots, "run", approved=True, protocol_id="d34-v2")
    settled = runner.execute_ifem_deepseek_role_calibration(
        d34_config,
        environment=_environment(),
        transport=d34_transport,
    )
    d35_transport = RecordingTransport()
    d35 = runner.execute_ifem_deepseek_role_calibration(
        runner.IFEMDeepSeekRoleCalibrationConfig(
            mode="run",
            state_root=d34_config.state_root,
            private_root=d34_config.private_root,
            protocol_id="d35-v3",
            operator_approved=True,
        ),
        environment=_environment(),
        transport=d35_transport,
    )

    assert settled.status == "settled"
    assert d35.status == "execution_refused"
    assert d35.failure_class == "root_policy_rejected"
    assert len(d34_transport.calls) == 16
    assert d35_transport.calls == []
