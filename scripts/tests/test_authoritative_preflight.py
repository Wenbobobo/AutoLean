from __future__ import annotations

from pathlib import Path

import pytest

from scripts import authoritative_preflight


def test_preflight_never_claims_authoritative_execution(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(authoritative_preflight, "_host_system", lambda: "Linux")
    observations = iter(
        (
            (True, b"0123456789abcdef0123456789abcdef01234567\n"),
            (True, b""),
            (True, b"26.1.0\n"),
        )
    )
    monkeypatch.setattr(
        authoritative_preflight,
        "_command_ok",
        lambda *_args, **_kwargs: next(observations),
    )

    payload, passed = authoritative_preflight.run_preflight(tmp_path, None)

    assert passed
    assert payload["status"] == "ready-for-authoritative-run"
    assert payload["authoritative_execution"] == "not-run"
    assert payload["scope"] == "readiness-preflight-only"


def test_missing_dependency_blocks_preflight(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(authoritative_preflight, "_host_system", lambda: "Linux")
    observations = iter(
        (
            (True, b"0123456789abcdef0123456789abcdef01234567\n"),
            (True, b""),
            (False, b""),
        )
    )
    monkeypatch.setattr(
        authoritative_preflight,
        "_command_ok",
        lambda *_args, **_kwargs: next(observations),
    )

    payload, passed = authoritative_preflight.run_preflight(tmp_path, None)

    assert not passed
    assert payload["status"] == "blocked"
    assert payload["authoritative_execution"] == "not-run"
