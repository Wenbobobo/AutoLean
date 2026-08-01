"""End-to-end local D32-to-D33 integration using an injected provider transport."""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import IO, Any, cast

import pytest

from benchmarks.ifem_private_evaluator import IFEM_PRIVATE_EVALUATOR_PUBLIC_REPORT_FILENAME
from scripts import ifem_deepseek_role_calibration as runner
from scripts import ifem_private_evaluation as evaluator


class _RecordingTransport:
    def __init__(self, selected_option: str = "option_a") -> None:
        self.calls: list[bytes] = []
        self.selected_option = selected_option

    def post_json(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        payload: Mapping[str, object],
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        del url, headers, payload, timeout_seconds
        raise AssertionError("D32 must use the exact-byte transport")

    def post_json_bytes(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        del url, headers, timeout_seconds
        self.calls.append(body)
        return {
            "id": f"private-d33-response-{len(self.calls)}",
            "model": "deepseek-v4-pro",
            "choices": [
                {"message": {"content": json.dumps({"selected_option": self.selected_option})}}
            ],
            "usage": {"prompt_tokens": 25, "completion_tokens": 4},
        }


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


def test_settled_d32_run_is_rebuilt_into_a_public_d33_aggregate(tmp_path: Path) -> None:
    operator_material = (tmp_path / "operator-material").resolve()
    seed, ledger_key = runner._load_or_initialize_operator_material(operator_material)
    state_root = (tmp_path / "state").resolve()
    private_root = (tmp_path / "private").resolve()
    public_root = (tmp_path / "public").resolve()
    transport = _RecordingTransport()
    report = runner.execute_ifem_deepseek_role_calibration(
        runner.IFEMDeepSeekRoleCalibrationConfig(
            mode="run",
            state_root=state_root,
            private_root=private_root,
            protocol_id="d32-v1",
            operator_approved=True,
        ),
        environment={
            "AUTOLEAN_DEEPSEEK_API_KEY": "test-api-key",
            "AUTOLEAN_IFEM_OPERATOR_SEED": seed,
            "AUTOLEAN_IFEM_LEDGER_HMAC_KEY": ledger_key,
        },
        transport=transport,
    )

    aggregate = evaluator.evaluate_settled_ifem_private_run(
        private_root=private_root,
        operator_material_root=operator_material,
        public_output_root=public_root,
        protocol_id="d32-v1",
    )

    assert report.status == "settled"
    assert len(transport.calls) == 16
    assert aggregate.case_count == 16
    assert sum(item.case_count for item in aggregate.role_aggregates) == 16
    assert len(aggregate.risk_aggregates) == 8
    assert all(item.case_count == 2 for item in aggregate.risk_aggregates)
    assert aggregate.token_usage.input_tokens_total == 400
    assert aggregate.token_usage.output_tokens_total == 64
    assert not aggregate.authority.promotion_allowed
    payload = json.loads(
        (public_root / IFEM_PRIVATE_EVALUATOR_PUBLIC_REPORT_FILENAME).read_text(encoding="utf-8")
    )
    assert payload["schema_version"] == "autolean.ifem-private-evaluator-public-report.v2"
    assert payload["protocol_binding"]["protocol_id"] == "d32-v1"
    assert payload["protocol_binding"]["response_contract"] == "selected_option_and_reason.v1"
    assert payload["content_sha256"] == aggregate.content_sha256
    rendered = json.dumps(payload, sort_keys=True)
    assert '"selected_option":' not in rendered
    assert "private-d33-response" not in rendered
    assert seed not in rendered
    assert ledger_key not in rendered


@pytest.mark.parametrize(
    ("protocol_id", "output_tokens", "expected_protocol"),
    (
        ("d34-v2", 512, runner.IFEMDeepSeekRoleCalibrationProtocolIdV1.D34_V2),
        ("d35-v3", 1024, runner.IFEMDeepSeekRoleCalibrationProtocolIdV1.D35_V3),
    ),
)
def test_selected_option_successor_run_is_rebuilt_by_the_matching_d33_protocol(
    tmp_path: Path,
    protocol_id: str,
    output_tokens: int,
    expected_protocol: runner.IFEMDeepSeekRoleCalibrationProtocolIdV1,
) -> None:
    operator_material = (tmp_path / "operator-material").resolve()
    seed, ledger_key = runner._load_or_initialize_operator_material(operator_material)
    state_root = (tmp_path / "state").resolve()
    private_root = (tmp_path / "private").resolve()
    public_root = (tmp_path / "public").resolve()
    transport = _RecordingTransport()
    report = runner.execute_ifem_deepseek_role_calibration(
        runner.IFEMDeepSeekRoleCalibrationConfig(
            mode="run",
            state_root=state_root,
            private_root=private_root,
            protocol_id=protocol_id,
            operator_approved=True,
        ),
        environment={
            "AUTOLEAN_DEEPSEEK_API_KEY": "test-api-key",
            "AUTOLEAN_IFEM_OPERATOR_SEED": seed,
            "AUTOLEAN_IFEM_LEDGER_HMAC_KEY": ledger_key,
        },
        transport=transport,
    )

    aggregate = evaluator.evaluate_settled_ifem_private_run(
        private_root=private_root,
        operator_material_root=operator_material,
        public_output_root=public_root,
        protocol_id=protocol_id,
    )

    assert report.status == "settled"
    assert report.protocol_id == expected_protocol
    assert len(transport.calls) == 16
    assert all(json.loads(body)["max_tokens"] == output_tokens for body in transport.calls)
    assert aggregate.case_count == 16
    assert not aggregate.authority.promotion_allowed
    payload = json.loads(
        (public_root / IFEM_PRIVATE_EVALUATOR_PUBLIC_REPORT_FILENAME).read_text(encoding="utf-8")
    )
    assert payload["schema_version"] == "autolean.ifem-private-evaluator-public-report.v2"
    assert payload["protocol_binding"]["protocol_id"] == protocol_id
    assert payload["protocol_binding"]["response_contract"] == "selected_option_only.v2"


def test_d33_refuses_a_private_root_from_the_wrong_protocol(tmp_path: Path) -> None:
    operator_material = (tmp_path / "operator-material").resolve()
    seed, ledger_key = runner._load_or_initialize_operator_material(operator_material)
    state_root = (tmp_path / "state").resolve()
    private_root = (tmp_path / "private").resolve()
    public_root = (tmp_path / "public").resolve()
    settled = runner.execute_ifem_deepseek_role_calibration(
        runner.IFEMDeepSeekRoleCalibrationConfig(
            mode="run",
            state_root=state_root,
            private_root=private_root,
            protocol_id="d34-v2",
            operator_approved=True,
        ),
        environment={
            "AUTOLEAN_DEEPSEEK_API_KEY": "test-api-key",
            "AUTOLEAN_IFEM_OPERATOR_SEED": seed,
            "AUTOLEAN_IFEM_LEDGER_HMAC_KEY": ledger_key,
        },
        transport=_RecordingTransport(),
    )

    with pytest.raises(runner.OperatorRootRejected, match="does not match this protocol"):
        evaluator.evaluate_settled_ifem_private_run(
            private_root=private_root,
            operator_material_root=operator_material,
            public_output_root=public_root,
            protocol_id="d32-v1",
        )

    assert settled.status == "settled"
    assert not public_root.exists()


@pytest.mark.parametrize("protocol_id", ("d32-v1", "d34-v2", "d35-v3"))
def test_settlement_and_evaluation_never_open_ignored_source_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    protocol_id: str,
) -> None:
    original_open = Path.open

    def reject_cache_open(path: Path, *args: Any, **kwargs: Any) -> IO[Any]:
        if ".cache" in path.parts:
            raise AssertionError(f"runtime attempted to open ignored cache path: {path.name}")
        return cast(IO[Any], original_open(path, *args, **kwargs))

    monkeypatch.setattr(Path, "open", reject_cache_open)
    operator_material = (tmp_path / f"{protocol_id}-operator-material").resolve()
    seed, ledger_key = runner._load_or_initialize_operator_material(operator_material)
    state_root = (tmp_path / f"{protocol_id}-state").resolve()
    private_root = (tmp_path / f"{protocol_id}-private").resolve()
    public_root = (tmp_path / f"{protocol_id}-public").resolve()
    transport = _RecordingTransport()

    settled = runner.execute_ifem_deepseek_role_calibration(
        runner.IFEMDeepSeekRoleCalibrationConfig(
            mode="run",
            state_root=state_root,
            private_root=private_root,
            protocol_id=protocol_id,
            operator_approved=True,
        ),
        environment={
            "AUTOLEAN_DEEPSEEK_API_KEY": "test-api-key",
            "AUTOLEAN_IFEM_OPERATOR_SEED": seed,
            "AUTOLEAN_IFEM_LEDGER_HMAC_KEY": ledger_key,
        },
        transport=transport,
    )
    aggregate = evaluator.evaluate_settled_ifem_private_run(
        private_root=private_root,
        operator_material_root=operator_material,
        public_output_root=public_root,
        protocol_id=protocol_id,
    )

    assert settled.status == "settled"
    assert aggregate.case_count == 16
    assert len(transport.calls) == 16


def test_d33_rejects_cross_run_private_child_junction_substitution(tmp_path: Path) -> None:
    operator_material = (tmp_path / "operator-material").resolve()
    seed, ledger_key = runner._load_or_initialize_operator_material(operator_material)
    environment = {
        "AUTOLEAN_DEEPSEEK_API_KEY": "test-api-key",
        "AUTOLEAN_IFEM_OPERATOR_SEED": seed,
        "AUTOLEAN_IFEM_LEDGER_HMAC_KEY": ledger_key,
    }
    private_a = (tmp_path / "private-a").resolve()
    private_b = (tmp_path / "private-b").resolve()
    for label, private_root, selected_option in (
        ("a", private_a, "option_a"),
        ("b", private_b, "option_b"),
    ):
        settled = runner.execute_ifem_deepseek_role_calibration(
            runner.IFEMDeepSeekRoleCalibrationConfig(
                mode="run",
                state_root=(tmp_path / f"state-{label}").resolve(),
                private_root=private_root,
                protocol_id="d34-v2",
                operator_approved=True,
            ),
            environment=environment,
            transport=_RecordingTransport(selected_option),
        )
        assert settled.status == "settled"

    replacements: list[tuple[Path, Path]] = []
    try:
        for name in ("ledger-v1", "responses-v1"):
            candidate = private_a / name
            original = private_a / f"{name}-original"
            candidate.rename(original)
            replacements.append((candidate, original))
            _create_directory_link(candidate, private_b / name)

        public_root = (tmp_path / "public").resolve()
        with pytest.raises(runner.OperatorRootRejected, match="physical directory"):
            evaluator.evaluate_settled_ifem_private_run(
                private_root=private_a,
                operator_material_root=operator_material,
                public_output_root=public_root,
                protocol_id="d34-v2",
            )
        assert not public_root.exists()
    finally:
        for candidate, original in reversed(replacements):
            _remove_directory_link(candidate)
            if not candidate.exists() and original.exists():
                original.rename(candidate)
