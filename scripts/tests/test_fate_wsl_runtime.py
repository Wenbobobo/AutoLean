from __future__ import annotations

import argparse
import json
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

from scripts.fate_wsl_runtime import (
    HOST_RESULT_SCHEMA,
    ProcessResult,
    RuntimePreparationError,
    _attributes_payload,
    _host_dispatch,
    _load_locked_dependencies,
    _pure_absolute_posix,
    _require_descendant,
    _runtime_paths,
    _write_exclusive,
)


class FakeHostRunner:
    def __init__(self, *, leaked_result: bool = False) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.leaked_result = leaked_result

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        timeout_seconds: int = 120,
        env: Mapping[str, str] | None = None,
    ) -> ProcessResult:
        del cwd, timeout_seconds, env
        command = tuple(argv)
        self.calls.append(command)
        if "/usr/bin/wslpath" in command:
            source = command[-1].replace("\\", "/")
            leaf = source.rsplit("/", 1)[-1]
            return ProcessResult(0, f"/mnt/c/AutoLean/{leaf}\n".encode(), b"")
        result: dict[str, object] = {
            "schema_version": HOST_RESULT_SCHEMA,
            "status": "verified",
            "runtime_state_sha256": "a" * 64,
            "audit_sha256": "b" * 64,
            "source_count": 350,
            "dependency_count": 9,
            "contains_absolute_paths": False,
        }
        if self.leaked_result:
            result["debug"] = "/home/operator/private"
        return ProcessResult(0, json.dumps(result).encode(), b"")


def _audit_args(tmp_path: Path) -> argparse.Namespace:
    checkout = tmp_path / "FATE"
    manifest = tmp_path / "manifest.json"
    checkout.mkdir()
    manifest.write_text("{}", encoding="utf-8")
    return argparse.Namespace(
        command="audit",
        checkout=checkout,
        manifest=manifest,
        cache_root="/home/operator/cache",
        packages_root="/home/operator/cache/packages",
        runtime_root="/home/operator/cache/runtime",
        distribution="Ubuntu-24.04",
    )


def test_host_dispatch_uses_no_shell_or_network_and_returns_path_free_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("scripts.fate_wsl_runtime.platform.system", lambda: "Windows")
    runner = FakeHostRunner()

    result, exit_code = _host_dispatch(_audit_args(tmp_path), runner)

    assert exit_code == 0
    assert result["source_count"] == 350
    native = runner.calls[-1]
    assert native[:4] == ("wsl.exe", "--distribution", "Ubuntu-24.04", "--exec")
    assert "/usr/bin/env" in native
    assert "/usr/bin/python3" in native
    assert not any(
        token in native
        for token in (
            "/bin/bash",
            "/bin/sh",
            "curl",
            "wget",
            "fetch",
            "pull",
        )
    )
    assert "/home/operator/cache" in native


def test_host_dispatch_rejects_absolute_path_in_native_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("scripts.fate_wsl_runtime.platform.system", lambda: "Windows")
    with pytest.raises(RuntimePreparationError, match="native_wsl_runtime_result_leaked_path"):
        _host_dispatch(_audit_args(tmp_path), FakeHostRunner(leaked_result=True))


def test_eol_policy_is_path_specific_and_deterministic() -> None:
    assert _attributes_payload("M") == (
        b"FATE-M.json text eol=crlf\nlake-manifest.json text eol=crlf\n"
    )
    assert b"*.lean" not in _attributes_payload("M")
    assert b"*" not in _attributes_payload("X")


def test_posix_boundaries_and_deterministic_layout_reject_escape(tmp_path: Path) -> None:
    assert _pure_absolute_posix("/home/operator/cache", "cache").as_posix() == (
        "/home/operator/cache"
    )
    with pytest.raises(RuntimePreparationError, match="unsafe_cache"):
        _pure_absolute_posix("../cache", "cache")
    with pytest.raises(RuntimePreparationError, match="unsafe_cache"):
        _pure_absolute_posix(r"C:\cache", "cache")

    root = tmp_path / "cache"
    root.mkdir()
    _require_descendant(root, root / "packages", "packages")
    with pytest.raises(RuntimePreparationError, match="packages_outside_cache_root"):
        _require_descendant(root, tmp_path / "outside", "packages")
    paths = _runtime_paths(root, root / "packages", "b" * 40)
    assert paths.layout_root.name == "fate-runtime-v1-bbbbbbbb"
    assert paths.runtime_root.relative_to(paths.cache_root).as_posix() == (
        "fate-runtime-v1-bbbbbbbb/runtime"
    )


def test_locked_dependency_parser_accepts_crlf_and_rejects_unlocked_entry(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "lake-manifest.json"
    manifest.write_bytes(
        b'{\r\n"packages":[{"name":"mathlib","rev":"' + b"8" * 40 + b'","type":"git"}]\r\n}\r\n'
    )
    assert _load_locked_dependencies(manifest)[0].name == "mathlib"

    manifest.write_text(
        json.dumps(
            {
                "packages": [
                    {
                        "name": "mathlib",
                        "rev": "main",
                        "type": "git",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(RuntimePreparationError, match="host_lake_manifest_invalid"):
        _load_locked_dependencies(manifest)


def test_state_write_is_exclusive_and_never_overwrites(tmp_path: Path) -> None:
    state = tmp_path / "state.json"
    _write_exclusive(state, b'{"version":1}\n', "state_conflict")
    with pytest.raises(RuntimePreparationError, match="state_conflict"):
        _write_exclusive(state, b'{"version":2}\n', "state_conflict")
    assert state.read_bytes() == b'{"version":1}\n'
