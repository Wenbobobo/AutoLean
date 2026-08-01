from __future__ import annotations

import inspect
import json
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import cast

import pytest

from Library.scripts import library_substrate_image as substrate
from scripts import operator_live_gate as gate


def _sha(character: str) -> str:
    return character * 64


def _deepseek_settled(*, extra: object | None = None) -> bytes:
    report: dict[str, object] = {
        "hashes": {
            "authorization": _sha("a"),
            "bundle": _sha("b"),
            "context_pack": _sha("c"),
            "contract": _sha("d"),
            "outbound_request": _sha("e"),
            "response_id_sha256": _sha("f"),
            "response_text_sha256": _sha("0"),
        },
        "status": "settled",
        "usage": {
            "cached_input_tokens": 1,
            "input_tokens": 2,
            "output_tokens": 3,
        },
    }
    if extra is not None:
        report["opaque"] = extra
    return (json.dumps(report) + "\n").encode("utf-8")


def _t6_all() -> bytes:
    report = {
        "build": {
            "build_input_sha256": _sha("1"),
            "context_inventory_sha256": _sha("2"),
            "image": "autolean/library-substrate@sha256:" + _sha("3"),
            "verification": {
                "image_receipt_sha256": _sha("4"),
                "parent_receipt_canonical_sha256": _sha("5"),
            },
        },
        "builder_query_canary": {
            "image": "autolean/library-substrate@sha256:" + _sha("3"),
            "schema_version": "autolean.library-substrate-builder-query-canary.v1",
        },
        "canary": {
            "image": "autolean/library-substrate@sha256:" + _sha("3"),
            "schema_version": "autolean.library-substrate-independent-canary.v1",
        },
        "v2_facade_canary": {
            "image": "autolean/library-substrate@sha256:" + _sha("3"),
            "schema_version": "autolean.library-substrate-v2-facade-canary.v2",
        },
        "schema_version": "autolean.library-substrate-image-all.v1",
    }
    return (json.dumps(report) + "\n").encode("ascii")


class FakeRunner:
    def __init__(self, results: dict[str, gate.ChildResult]) -> None:
        self.results = results
        self.calls: list[tuple[tuple[str, ...], Path, int]] = []

    def __call__(self, argv: Sequence[str], cwd: Path, timeout_seconds: int) -> gate.ChildResult:
        command = tuple(argv)
        self.calls.append((command, cwd, timeout_seconds))
        if any(item.endswith("deepseek_authorized_canary.py") for item in command):
            return self.results["deepseek"]
        return self.results["t6_oci"]


def test_deepseek_command_is_fixed_and_does_not_accept_secret_inputs() -> None:
    command = gate.deepseek_argv()

    assert command == (
        "uv",
        "run",
        "--frozen",
        "python",
        "scripts/deepseek_authorized_canary.py",
        "--operator-approved",
    )
    assert not any("llm" in item.casefold() or "key" in item.casefold() for item in command)


def test_subprocess_runner_inherits_environment_without_loading_secret_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    observed: dict[str, object] = {}

    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        observed["args"] = args
        observed.update(kwargs)
        return subprocess.CompletedProcess(args=["fake"], returncode=0, stdout=b"{}", stderr=b"")

    monkeypatch.setattr("scripts.operator_live_gate.subprocess.run", fake_run)

    result = gate._subprocess_runner(("fake",), tmp_path, 1)

    assert result == gate.ChildResult(returncode=0, stdout=b"{}", stderr=b"")
    assert observed["env"] is None
    assert observed["cwd"] == tmp_path
    assert observed["capture_output"] is True


@pytest.mark.parametrize(
    ("system", "release"),
    (
        ("Windows", ""),
        ("Linux", "6.6.87.2-microsoft-standard-WSL2"),
        ("Linux", "6.8.0-generic"),
    ),
)
def test_t6_argv_uses_library_owned_runtime_helper_on_every_supported_host(
    system: str, release: str
) -> None:
    host_kind = gate._host_kind(system, release)

    assert gate.t6_oci_argv(host_kind=host_kind) == (
        "uv",
        "run",
        "--frozen",
        "python",
        "-m",
        "Library.scripts.library_substrate_image",
        "all",
    )


def test_windows_t6_delegation_stays_in_library_while_deepseek_stays_on_host() -> None:
    library_main = inspect.getsource(substrate.main)
    library_delegate = inspect.getsource(substrate._delegate_to_wsl)

    assert 'if os.name == "nt" and not parsed.native:' in library_main
    assert "return _delegate_to_wsl(parsed)" in library_main
    assert '"wsl.exe"' in library_delegate
    assert not any("wsl" in part.casefold() for part in gate.deepseek_argv())


def test_t6_summary_schema_is_bound_to_current_library_result_constants() -> None:
    expected_fields = frozenset(
        {
            "build",
            "builder_query_canary",
            "canary",
            "schema_version",
            "v2_facade_canary",
        }
    )
    expected_schemas = {
        "builder_query_canary": substrate.BUILDER_QUERY_CANARY_SCHEMA,
        "canary": substrate.CANARY_SCHEMA,
        "v2_facade_canary": substrate.V2_FACADE_CANARY_SCHEMA,
    }
    assert expected_fields == gate._T6_ALL_FIELDS
    assert expected_schemas == gate._T6_COMPONENT_SCHEMAS
    all_source = inspect.getsource(substrate.main)
    assert '"v2_facade_canary": v2_facade_canary(' in all_source
    build_source = inspect.getsource(substrate.build)
    verification_source = inspect.getsource(substrate.verify)
    for field in ("build_input_sha256", "context_inventory_sha256", "image", "verification"):
        assert f'"{field}"' in build_source
    for field in ("image_receipt_sha256", "parent_receipt_canonical_sha256"):
        assert f'"{field}"' in verification_source


def test_all_summary_is_ascii_canonical_and_never_copies_child_secret_like_fields(
    tmp_path: Path,
) -> None:
    fake = FakeRunner(
        {
            "deepseek": gate.ChildResult(
                0,
                _deepseek_settled(
                    extra={
                        "api_key": "secret-value",
                        "endpoint": "https://operator.example.invalid",
                        "prompt": "hidden prompt",
                        "response": "hidden response",
                    }
                ),
                b"",
            ),
            "t6_oci": gate.ChildResult(0, _t6_all(), b""),
        }
    )

    summary = gate.run_live_gate(
        "all",
        root=tmp_path,
        runner=fake,
        host_system="Linux",
        host_release="6.8.0-generic",
    )
    rendered = gate._canonical_summary(summary)

    assert rendered.isascii()
    assert json.loads(rendered) == summary
    assert summary["status"] == "passed"
    assert summary["phase1_promotion_eligible"] is False
    gates = cast(dict[str, object], summary["gates"])
    assert gates["deepseek"] == {
        "evidence_hashes": {
            "authorization": _sha("a"),
            "bundle": _sha("b"),
            "context_pack": _sha("c"),
            "contract": _sha("d"),
            "outbound_request": _sha("e"),
            "response_id_sha256": _sha("f"),
            "response_text_sha256": _sha("0"),
        },
        "status": "passed",
        "usage": {
            "cached_input_tokens": 1,
            "input_tokens": 2,
            "output_tokens": 3,
        },
    }
    assert "secret-value" not in rendered.decode("ascii")
    assert "operator.example.invalid" not in rendered.decode("ascii")
    assert "hidden prompt" not in rendered.decode("ascii")
    assert fake.calls[0][1] == tmp_path.resolve()


def test_refused_deepseek_and_failed_t6_are_blocked_without_diagnostics(tmp_path: Path) -> None:
    refusal = {
        "failure_class": "network",
        "status": "execution_refused",
        "unexpected_detail": "https://do-not-copy.invalid secret=do-not-copy",
    }
    fake = FakeRunner(
        {
            "deepseek": gate.ChildResult(1, (json.dumps(refusal) + "\n").encode(), b"secret"),
            "t6_oci": gate.ChildResult(2, b"raw endpoint and prompt", b"raw secret"),
        }
    )

    summary = gate.run_live_gate(
        "all",
        root=tmp_path,
        runner=fake,
        host_system="Windows",
    )

    assert summary == {
        "gates": {
            "deepseek": {"stable_blocker": "network", "status": "blocked"},
            "t6_oci": {"stable_blocker": "child_failed", "status": "blocked"},
        },
        "phase1_promotion_eligible": False,
        "schema_version": gate.SUMMARY_SCHEMA,
        "status": "blocked",
    }
    rendered = gate._canonical_summary(summary).decode("ascii")
    assert "do-not-copy" not in rendered
    assert "raw secret" not in rendered


def test_invalid_child_output_fails_closed(tmp_path: Path) -> None:
    fake = FakeRunner(
        {
            "deepseek": gate.ChildResult(0, b'{"status":"settled"}\n', b""),
            "t6_oci": gate.ChildResult(0, _t6_all(), b""),
        }
    )

    summary = gate.run_live_gate(
        "deepseek",
        root=tmp_path,
        runner=fake,
        host_system="Linux",
        host_release="generic",
    )

    assert summary["status"] == "blocked"
    gates = cast(dict[str, object], summary["gates"])
    assert gates["deepseek"] == {
        "stable_blocker": "child_output_schema",
        "status": "blocked",
    }


def test_t6_summary_rejects_a_truncated_all_result(tmp_path: Path) -> None:
    truncated = json.loads(_t6_all())
    assert isinstance(truncated, dict)
    del truncated["v2_facade_canary"]
    fake = FakeRunner(
        {
            "deepseek": gate.ChildResult(0, _deepseek_settled(), b""),
            "t6_oci": gate.ChildResult(0, (json.dumps(truncated) + "\n").encode(), b""),
        }
    )

    summary = gate.run_live_gate(
        "t6-oci",
        root=tmp_path,
        runner=fake,
        host_system="Linux",
        host_release="generic",
    )

    gates = cast(dict[str, object], summary["gates"])
    assert gates["t6_oci"] == {
        "stable_blocker": "child_output_schema",
        "status": "blocked",
    }


def test_deepseek_response_without_optional_response_id_remains_usable(tmp_path: Path) -> None:
    report = json.loads(_deepseek_settled())
    assert isinstance(report["hashes"], dict)
    del report["hashes"]["response_id_sha256"]
    fake = FakeRunner(
        {
            "deepseek": gate.ChildResult(0, (json.dumps(report) + "\n").encode(), b""),
            "t6_oci": gate.ChildResult(0, _t6_all(), b""),
        }
    )

    summary = gate.run_live_gate(
        "deepseek",
        root=tmp_path,
        runner=fake,
        host_system="Linux",
        host_release="generic",
    )

    gates = cast(dict[str, object], summary["gates"])
    deepseek = cast(dict[str, object], gates["deepseek"])
    evidence = cast(dict[str, object], deepseek["evidence_hashes"])
    assert summary["status"] == "passed"
    assert "response_id_sha256" not in evidence


def test_output_must_be_new_absolute_path_outside_checkout(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    outside = tmp_path / "operator-summary.json"

    with pytest.raises(gate.OperatorLiveGateError, match="output_must_be_absolute"):
        gate._validate_output_path(Path("summary.json"), root=checkout)
    with pytest.raises(gate.OperatorLiveGateError, match="output_must_be_outside_checkout"):
        gate._validate_output_path(checkout / "summary.json", root=checkout)

    accepted = gate._validate_output_path(outside, root=checkout)
    payload = gate._canonical_summary(gate._refusal_summary("child_unavailable"))
    gate._write_exclusive(accepted, payload)

    assert outside.read_bytes() == payload
    with pytest.raises(gate.OperatorLiveGateError, match="output_must_not_exist"):
        gate._validate_output_path(outside, root=checkout)
