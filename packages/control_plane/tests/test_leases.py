from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from autolean_control_plane import LeaseStore
from autolean_control_plane.errors import LeaseUnavailable, StaleFence


def test_lease_uses_fencing_tokens_after_expiry(tmp_path: Path) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)

    def clock() -> datetime:
        return now

    store = LeaseStore(tmp_path / "control.db", clock=clock)
    first = store.claim("bundle-1", "worker-a", ttl_seconds=5)
    with pytest.raises(LeaseUnavailable):
        store.claim("bundle-1", "worker-b", ttl_seconds=5)

    now += timedelta(seconds=6)
    replacement = store.claim("bundle-1", "worker-b", ttl_seconds=5)
    assert replacement.fencing_token == first.fencing_token + 1
    with pytest.raises(StaleFence):
        store.assert_current(first)
    store.assert_current(replacement)


def test_same_worker_claim_is_idempotent_until_expiry(tmp_path: Path) -> None:
    store = LeaseStore(tmp_path / "control.db")
    first = store.claim("bundle-1", "worker-a", ttl_seconds=60)
    repeated = store.claim("bundle-1", "worker-a", ttl_seconds=60)
    assert repeated.fencing_token == first.fencing_token
    assert repeated.expires_at == first.expires_at
