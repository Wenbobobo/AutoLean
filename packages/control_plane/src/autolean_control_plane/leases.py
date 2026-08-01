"""Fenced leases for workers that may crash, restart, or retry commands."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .errors import LeaseUnavailable, StaleFence


@dataclass(frozen=True, slots=True)
class Lease:
    job_id: str
    holder_id: str
    fencing_token: int
    expires_at: datetime

    def __post_init__(self) -> None:
        if not self.job_id.strip() or not self.holder_id.strip():
            raise ValueError("job_id and holder_id must not be empty")
        if self.fencing_token <= 0:
            raise ValueError("fencing_token must be positive")
        if self.expires_at.tzinfo is None:
            raise ValueError("expires_at must be timezone-aware")


class LeaseStore:
    """SQLite CAS leases with monotonically increasing fencing tokens.

    The token is the authoritative guard: a worker that finishes after a replacement lease was
    issued cannot commit its output even if it still has a process running.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        timeout_seconds: float = 30.0,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.timeout_seconds = timeout_seconds
        self._clock = clock or (lambda: datetime.now(UTC))
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path,
            timeout=self.timeout_seconds,
            isolation_level=None,
            check_same_thread=False,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute(f"PRAGMA busy_timeout = {int(self.timeout_seconds * 1000)}")
        return connection

    @contextmanager
    def _write_transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except BaseException:
                connection.rollback()
                raise
            else:
                connection.commit()
        finally:
            connection.close()

    def _initialize(self) -> None:
        with closing(self._connect()) as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS worker_leases (
                    job_id TEXT PRIMARY KEY,
                    holder_id TEXT NOT NULL,
                    fencing_token INTEGER NOT NULL CHECK (fencing_token > 0),
                    expires_at_epoch REAL NOT NULL,
                    updated_at_epoch REAL NOT NULL
                ) WITHOUT ROWID;

                CREATE TABLE IF NOT EXISTS lease_counters (
                    job_id TEXT PRIMARY KEY,
                    last_fencing_token INTEGER NOT NULL CHECK (last_fencing_token >= 0)
                ) WITHOUT ROWID;
                """
            )

    def claim(self, job_id: str, holder_id: str, *, ttl_seconds: float) -> Lease:
        if not job_id.strip() or not holder_id.strip():
            raise ValueError("job_id and holder_id must not be empty")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        now = self._utc_now()
        now_epoch = now.timestamp()
        expires_at = now + timedelta(seconds=ttl_seconds)
        with self._write_transaction() as connection:
            row = connection.execute(
                "SELECT * FROM worker_leases WHERE job_id = ?", (job_id,)
            ).fetchone()
            if row is not None and float(row["expires_at_epoch"]) > now_epoch:
                if str(row["holder_id"]) != holder_id:
                    raise LeaseUnavailable(f"job {job_id!r} is leased by another worker")
                return self._row_to_lease(row)

            counter = connection.execute(
                "SELECT last_fencing_token FROM lease_counters WHERE job_id = ?", (job_id,)
            ).fetchone()
            token = 1 if counter is None else int(counter["last_fencing_token"]) + 1
            connection.execute(
                """
                INSERT INTO lease_counters (job_id, last_fencing_token) VALUES (?, ?)
                ON CONFLICT(job_id) DO UPDATE SET last_fencing_token = excluded.last_fencing_token
                """,
                (job_id, token),
            )
            connection.execute(
                """
                INSERT INTO worker_leases (
                    job_id, holder_id, fencing_token, expires_at_epoch, updated_at_epoch
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    holder_id = excluded.holder_id,
                    fencing_token = excluded.fencing_token,
                    expires_at_epoch = excluded.expires_at_epoch,
                    updated_at_epoch = excluded.updated_at_epoch
                """,
                (job_id, holder_id, token, expires_at.timestamp(), now_epoch),
            )
        return Lease(job_id, holder_id, token, expires_at)

    def renew(self, lease: Lease, *, ttl_seconds: float) -> Lease:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        now = self._utc_now()
        expires_at = now + timedelta(seconds=ttl_seconds)
        with self._write_transaction() as connection:
            updated = connection.execute(
                """
                UPDATE worker_leases
                SET expires_at_epoch = ?, updated_at_epoch = ?
                WHERE job_id = ? AND holder_id = ? AND fencing_token = ?
                    AND expires_at_epoch > ?
                """,
                (
                    expires_at.timestamp(),
                    now.timestamp(),
                    lease.job_id,
                    lease.holder_id,
                    lease.fencing_token,
                    now.timestamp(),
                ),
            )
            if updated.rowcount != 1:
                raise StaleFence("lease cannot be renewed because its fencing token is stale")
        return Lease(lease.job_id, lease.holder_id, lease.fencing_token, expires_at)

    def assert_current(self, lease: Lease) -> None:
        now_epoch = self._utc_now().timestamp()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM worker_leases WHERE job_id = ?", (lease.job_id,)
            ).fetchone()
        if row is None:
            raise StaleFence("lease no longer exists")
        if (
            str(row["holder_id"]) != lease.holder_id
            or int(row["fencing_token"]) != lease.fencing_token
            or float(row["expires_at_epoch"]) <= now_epoch
        ):
            raise StaleFence("lease fencing token is stale or expired")

    def current(self, job_id: str) -> Lease | None:
        """Return the exact live lease recorded for a job, including its authority expiry."""

        if not job_id.strip():
            raise ValueError("job_id must not be empty")
        now_epoch = self._utc_now().timestamp()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM worker_leases WHERE job_id = ?",
                (job_id,),
            ).fetchone()
        if row is None or float(row["expires_at_epoch"]) <= now_epoch:
            return None
        return self._row_to_lease(row)

    def release(self, lease: Lease) -> None:
        self.assert_current(lease)
        with self._write_transaction() as connection:
            deleted = connection.execute(
                """
                DELETE FROM worker_leases
                WHERE job_id = ? AND holder_id = ? AND fencing_token = ?
                """,
                (lease.job_id, lease.holder_id, lease.fencing_token),
            )
            if deleted.rowcount != 1:
                raise StaleFence("lease fencing token became stale before release")

    def _utc_now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise ValueError("lease clock must return a timezone-aware datetime")
        return value.astimezone(UTC)

    @staticmethod
    def _row_to_lease(row: sqlite3.Row) -> Lease:
        return Lease(
            job_id=str(row["job_id"]),
            holder_id=str(row["holder_id"]),
            fencing_token=int(row["fencing_token"]),
            expires_at=datetime.fromtimestamp(float(row["expires_at_epoch"]), tz=UTC),
        )
