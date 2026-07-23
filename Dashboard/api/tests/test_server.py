from __future__ import annotations

import pytest
from autolean_dashboard.server import ServerConfig


def test_server_defaults_to_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AUTOLEAN_DASHBOARD_REMOTE", raising=False)
    monkeypatch.delenv("AUTOLEAN_DASHBOARD_HOST", raising=False)
    monkeypatch.delenv("AUTOLEAN_DASHBOARD_PORT", raising=False)

    assert ServerConfig.from_environment() == ServerConfig(
        host="127.0.0.1", port=8765, remote_mode=False
    )


def test_server_rejects_remote_bind_without_remote_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AUTOLEAN_DASHBOARD_REMOTE", raising=False)
    monkeypatch.setenv("AUTOLEAN_DASHBOARD_HOST", "0.0.0.0")

    with pytest.raises(RuntimeError, match=r"127\.0\.0\.1"):
        ServerConfig.from_environment()


def test_server_allows_remote_bind_only_in_remote_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUTOLEAN_DASHBOARD_REMOTE", "1")
    monkeypatch.setenv("AUTOLEAN_DASHBOARD_HOST", "0.0.0.0")
    monkeypatch.setenv("AUTOLEAN_DASHBOARD_PORT", "9876")

    assert ServerConfig.from_environment() == ServerConfig(
        host="0.0.0.0", port=9876, remote_mode=True
    )
