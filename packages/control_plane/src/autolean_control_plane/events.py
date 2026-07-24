from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from .errors import (
    AttestationReplay,
    ConcurrencyError,
    ContractRevisionConflict,
    IdempotencyConflict,
    ProjectionError,
    StaleFence,
)
from .leases import Lease

type JsonValue = None | bool | int | float | str | list[JsonValue] | dict[str, JsonValue]
type JsonObject = dict[str, JsonValue]

_ATTESTATION_NONCE = re.compile(r"^[A-Za-z0-9._-]{16,256}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def canonical_json(value: object) -> str:
    """Encode a JSON value deterministically for hashing and durable storage."""

    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON object key")
        value[key] = item
    return value


def _load_canonical_json(value: str, *, label: str) -> object:
    try:
        decoded = json.loads(value, object_pairs_hook=_unique_json_object)
        if canonical_json(decoded) != value:
            raise ValueError("JSON is not canonical")
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise ProjectionError(f"{label} is not canonical JSON") from error
    return decoded


def _load_canonical_json_object(value: str, *, label: str) -> JsonObject:
    decoded = _load_canonical_json(value, label=label)
    if not isinstance(decoded, dict):
        raise ProjectionError(f"{label} must be a JSON object")
    return cast(JsonObject, decoded)


def request_hash(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def utc_now_text() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class NewEvent:
    event_type: str
    payload: Mapping[str, JsonValue] = field(default_factory=dict)
    metadata: Mapping[str, JsonValue] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class StoredEvent:
    global_position: int
    event_id: str
    entity_type: str
    entity_id: str
    entity_sequence: int
    event_type: str
    payload: JsonObject
    metadata: JsonObject
    recorded_at: str


@dataclass(frozen=True, slots=True)
class Idempotency:
    scope: str
    key: str
    request_hash: str

    def __post_init__(self) -> None:
        if not self.scope.strip():
            raise ValueError("idempotency scope must not be empty")
        if not self.key.strip():
            raise ValueError("idempotency key must not be empty")
        if len(self.request_hash) != 64:
            raise ValueError("request_hash must be a SHA-256 hex digest")


@dataclass(frozen=True, slots=True)
class AttestationNonce:
    """One public nonce consumed atomically with an append-only state transition.

    The nonce and payload hash are public replay-prevention metadata.  They are never secret key
    material, and the event store deliberately persists neither a signer secret nor a raw
    attestation payload.
    """

    purpose: str
    key_id: str
    nonce: str
    payload_hash: str

    def __post_init__(self) -> None:
        if not self.purpose.strip() or len(self.purpose) > 128:
            raise ValueError("attestation nonce purpose must be a bounded non-empty string")
        if not self.key_id.strip() or len(self.key_id) > 128:
            raise ValueError("attestation nonce key_id must be a bounded non-empty string")
        if not _ATTESTATION_NONCE.fullmatch(self.nonce):
            raise ValueError("attestation nonce must use the safe V1 nonce format")
        if not _SHA256.fullmatch(self.payload_hash):
            raise ValueError("attestation nonce payload_hash must be a SHA-256 digest")


@dataclass(frozen=True, slots=True)
class ContractRevisionBinding:
    """The immutable cross-stream identity of one Builder handoff."""

    contract_id: str
    revision: int
    bundle_id: str
    bundle_hash: str
    contract_hash: str

    def __post_init__(self) -> None:
        if not self.contract_id.strip() or not self.bundle_id.strip():
            raise ValueError("contract_id and bundle_id must not be empty")
        if self.revision < 1:
            raise ValueError("contract revision must be positive")
        if not _SHA256.fullmatch(self.bundle_hash):
            raise ValueError("bundle_hash must be a SHA-256 digest")
        if not _SHA256.fullmatch(self.contract_hash):
            raise ValueError("contract_hash must be a SHA-256 digest")


class EventStore:
    """SQLite event log with transactional entity CAS and command idempotency."""

    def __init__(
        self,
        path: str | Path,
        *,
        timeout_seconds: float = 30.0,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.path = Path(path)
        self.timeout_seconds = timeout_seconds
        self._clock = clock or (lambda: datetime.now(UTC))
        self.path.parent.mkdir(parents=True, exist_ok=True)
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
    def connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def write_transaction(self) -> Iterator[sqlite3.Connection]:
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except BaseException:
                connection.rollback()
                raise
            else:
                connection.commit()

    def _initialize(self) -> None:
        with self.connection() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    global_position INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    entity_type TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    entity_sequence INTEGER NOT NULL CHECK (entity_sequence > 0),
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    recorded_at TEXT NOT NULL,
                    UNIQUE (entity_type, entity_id, entity_sequence)
                );

                CREATE INDEX IF NOT EXISTS events_entity_stream
                    ON events (entity_type, entity_id, entity_sequence);

                CREATE TABLE IF NOT EXISTS entity_versions (
                    entity_type TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL CHECK (sequence >= 0),
                    PRIMARY KEY (entity_type, entity_id)
                ) WITHOUT ROWID;

                CREATE TABLE IF NOT EXISTS idempotency_records (
                    scope TEXT NOT NULL,
                    key TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    event_ids_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (scope, key)
                ) WITHOUT ROWID;

                CREATE TABLE IF NOT EXISTS attestation_nonce_uses (
                    purpose TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    consumed_at TEXT NOT NULL,
                    PRIMARY KEY (purpose, key_id, nonce)
                ) WITHOUT ROWID;

                CREATE TRIGGER IF NOT EXISTS events_forbid_update
                BEFORE UPDATE ON events
                BEGIN
                    SELECT RAISE(ABORT, 'events are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS events_forbid_delete
                BEFORE DELETE ON events
                BEGIN
                    SELECT RAISE(ABORT, 'events are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS attestation_nonce_uses_forbid_update
                BEFORE UPDATE ON attestation_nonce_uses
                BEGIN
                    SELECT RAISE(ABORT, 'attestation nonce uses are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS attestation_nonce_uses_forbid_delete
                BEFORE DELETE ON attestation_nonce_uses
                BEGIN
                    SELECT RAISE(ABORT, 'attestation nonce uses are append-only');
                END;
                """
            )
        self._initialize_contract_revision_bindings()

    def _initialize_contract_revision_bindings(self) -> None:
        """Create or verify the canonical contract-revision projection.

        Legacy databases are backfilled from the append-only registration events. Any duplicate
        contract revision, duplicate bundle ID, malformed event, or disagreement with an existing
        projection aborts initialization. DDL and backfill are one transaction, so a failed
        migration never leaves a partially accepted projection.
        """

        with self.write_transaction() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS contract_revision_bindings (
                    contract_id TEXT NOT NULL,
                    revision INTEGER NOT NULL CHECK (revision > 0),
                    bundle_id TEXT NOT NULL UNIQUE,
                    bundle_hash TEXT NOT NULL,
                    contract_hash TEXT NOT NULL,
                    registration_event_id TEXT NOT NULL UNIQUE
                        REFERENCES events (event_id),
                    PRIMARY KEY (contract_id, revision)
                ) WITHOUT ROWID
                """
            )
            connection.execute(
                """
                CREATE TRIGGER IF NOT EXISTS contract_revision_bindings_forbid_update
                BEFORE UPDATE ON contract_revision_bindings
                BEGIN
                    SELECT RAISE(ABORT, 'contract revision bindings are immutable');
                END
                """
            )
            connection.execute(
                """
                CREATE TRIGGER IF NOT EXISTS contract_revision_bindings_forbid_delete
                BEFORE DELETE ON contract_revision_bindings
                BEGIN
                    SELECT RAISE(ABORT, 'contract revision bindings are immutable');
                END
                """
            )

            event_rows = connection.execute(
                """
                SELECT *
                FROM events
                WHERE entity_type = 'task' AND event_type = 'task.registered'
                ORDER BY global_position
                """
            ).fetchall()
            expected: dict[tuple[str, int], tuple[ContractRevisionBinding, str]] = {}
            expected_bundle_ids: dict[str, tuple[str, int]] = {}
            for row in event_rows:
                binding = self._registration_binding_from_event_row(row)
                key = (binding.contract_id, binding.revision)
                if key in expected:
                    raise ProjectionError(
                        "legacy registration events contain a duplicate contract revision "
                        f"{binding.contract_id}@{binding.revision}"
                    )
                previous_key = expected_bundle_ids.get(binding.bundle_id)
                if previous_key is not None:
                    raise ProjectionError(
                        "legacy registration events bind one bundle ID to multiple contract "
                        f"revisions: {binding.bundle_id}"
                    )
                event_id = str(row["event_id"])
                expected[key] = (binding, event_id)
                expected_bundle_ids[binding.bundle_id] = key

            projected_rows = connection.execute(
                """
                SELECT contract_id, revision, bundle_id, bundle_hash, contract_hash,
                       registration_event_id
                FROM contract_revision_bindings
                """
            ).fetchall()
            projected: dict[tuple[str, int], tuple[ContractRevisionBinding, str]] = {}
            for row in projected_rows:
                binding = self._registration_binding_from_projection_row(row)
                projected[(binding.contract_id, binding.revision)] = (
                    binding,
                    str(row["registration_event_id"]),
                )
            unexpected = projected.keys() - expected.keys()
            if unexpected:
                contract_id, revision = sorted(unexpected)[0]
                raise ProjectionError(
                    "contract revision projection contains no canonical registration event for "
                    f"{contract_id}@{revision}"
                )

            for key, value in expected.items():
                existing = projected.get(key)
                if existing is not None:
                    if existing != value:
                        contract_id, revision = key
                        raise ProjectionError(
                            "contract revision projection disagrees with its canonical "
                            f"registration event for {contract_id}@{revision}"
                        )
                    continue
                binding, event_id = value
                try:
                    self._insert_contract_revision_binding(
                        connection,
                        binding=binding,
                        registration_event_id=event_id,
                    )
                except sqlite3.IntegrityError as error:
                    raise ProjectionError(
                        "legacy registration events violate the unique contract-revision or "
                        "bundle-ID binding"
                    ) from error

    def journal_mode(self) -> str:
        with self.connection() as connection:
            row = connection.execute("PRAGMA journal_mode").fetchone()
        if row is None:
            raise RuntimeError("SQLite journal_mode query returned no result")
        return str(row[0]).lower()

    def current_sequence(self, entity_type: str, entity_id: str) -> int:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT sequence FROM entity_versions WHERE entity_type = ? AND entity_id = ?",
                (entity_type, entity_id),
            ).fetchone()
        return 0 if row is None else int(row["sequence"])

    def lookup_idempotency(self, value: Idempotency) -> tuple[StoredEvent, ...] | None:
        with self.connection() as connection:
            row = connection.execute(
                """
                SELECT request_hash, event_ids_json
                FROM idempotency_records
                WHERE scope = ? AND key = ?
                """,
                (value.scope, value.key),
            ).fetchone()
            if row is None:
                return None
            return self._resolve_idempotency(connection, row, value)

    def append(
        self,
        entity_type: str,
        entity_id: str,
        *,
        expected_sequence: int,
        events: Sequence[NewEvent],
        idempotency: Idempotency | None = None,
        attestation_nonce: AttestationNonce | None = None,
    ) -> tuple[StoredEvent, ...]:
        self._validate_append_request(entity_type, entity_id, expected_sequence, events)
        if entity_type == "task" and any(event.event_type == "task.registered" for event in events):
            raise ValueError("task.registered must use append_contract_revision_registration")

        with self.write_transaction() as connection:
            return self._append_locked(
                connection,
                entity_type,
                entity_id,
                expected_sequence=expected_sequence,
                events=events,
                idempotency=idempotency,
                attestation_nonce=attestation_nonce,
            )

    def append_contract_revision_registration(
        self,
        binding: ContractRevisionBinding,
        *,
        event: NewEvent,
        idempotency: Idempotency,
        attestation_nonce: AttestationNonce,
    ) -> tuple[StoredEvent, ...]:
        """Atomically register one immutable bundle for a frozen contract revision.

        A byte-identical logical binding may be delivered again under a new idempotency key. That
        retry is linked to the original event without consuming the already-used authority nonce.
        Any different bundle ID, handoff hash, or contract hash for the revision fails closed.
        """

        if event.event_type != "task.registered":
            raise ValueError("registration event must have type task.registered")
        self._validate_append_request("task", binding.bundle_id, 0, (event,))

        with self.write_transaction() as connection:
            replayed = self._existing_idempotency(connection, idempotency)
            if replayed is not None:
                self._assert_registration_events_match(
                    connection,
                    binding=binding,
                    events=replayed,
                )
                return replayed

            existing = self._contract_revision_projection_row(
                connection,
                contract_id=binding.contract_id,
                revision=binding.revision,
            )
            existing_for_bundle = connection.execute(
                """
                SELECT contract_id, revision, bundle_id, bundle_hash, contract_hash,
                       registration_event_id
                FROM contract_revision_bindings
                WHERE bundle_id = ?
                """,
                (binding.bundle_id,),
            ).fetchone()
            if existing is not None or existing_for_bundle is not None:
                selected = existing if existing is not None else existing_for_bundle
                if selected is None:
                    raise RuntimeError("contract revision projection lookup was inconsistent")
                projected_binding = self._registration_binding_from_projection_row(selected)
                if projected_binding != binding:
                    # Preserve nonce-replay detection for a conflicting delivery. A fresh nonce is
                    # rolled back with the conflict; an already-used nonce fails at this point.
                    self._consume_attestation_nonce(
                        connection,
                        value=attestation_nonce,
                        entity_type="task",
                        entity_id=binding.bundle_id,
                    )
                    raise ContractRevisionConflict(
                        "contract revision or bundle ID is already bound to a different "
                        "immutable Builder handoff"
                    )
                event_id = str(selected["registration_event_id"])
                replayed = self._events_by_ids(connection, (event_id,))
                self._assert_registration_events_match(
                    connection,
                    binding=binding,
                    events=replayed,
                )
                self._record_idempotency(
                    connection,
                    value=idempotency,
                    event_ids=(event_id,),
                    recorded_at=self._utc_now_text(),
                )
                return replayed

            registered = self._append_locked(
                connection,
                "task",
                binding.bundle_id,
                expected_sequence=0,
                events=(event,),
                idempotency=idempotency,
                idempotency_checked=True,
                attestation_nonce=attestation_nonce,
            )
            try:
                self._insert_contract_revision_binding(
                    connection,
                    binding=binding,
                    registration_event_id=registered[0].event_id,
                )
            except sqlite3.IntegrityError as error:
                raise ContractRevisionConflict(
                    "contract revision or bundle ID is already bound to a different immutable "
                    "Builder handoff"
                ) from error
            return registered

    def append_fenced(
        self,
        entity_type: str,
        entity_id: str,
        *,
        task_id: str,
        lease: Lease,
        expected_sequence: int,
        events: Sequence[NewEvent],
        idempotency: Idempotency | None = None,
        attestation_nonce: AttestationNonce | None = None,
    ) -> tuple[StoredEvent, ...]:
        """Append only while the supplied task lease remains current.

        The idempotency lookup is deliberately first: replaying a command that already committed
        does not create a new state change and remains safe after its original lease has expired.
        New writes validate the lease row in the same SQLite transaction as the event append.
        """

        self._validate_append_request(entity_type, entity_id, expected_sequence, events)
        if not task_id.strip():
            raise ValueError("task_id must not be empty")
        self._validate_fenced_task_binding(task_id=task_id, events=events)

        with self.write_transaction() as connection:
            existing = self._existing_idempotency(connection, idempotency)
            if existing is not None:
                self._assert_fenced_replay_task_binding(task_id=task_id, events=existing)
                return existing
            self._assert_current_fence(connection, task_id=task_id, lease=lease)
            return self._append_locked(
                connection,
                entity_type,
                entity_id,
                expected_sequence=expected_sequence,
                events=events,
                idempotency=idempotency,
                idempotency_checked=True,
                attestation_nonce=attestation_nonce,
            )

    @staticmethod
    def _validate_append_request(
        entity_type: str,
        entity_id: str,
        expected_sequence: int,
        events: Sequence[NewEvent],
    ) -> None:
        if not entity_type.strip() or not entity_id.strip():
            raise ValueError("entity_type and entity_id must not be empty")
        if expected_sequence < 0:
            raise ValueError("expected_sequence must be non-negative")
        if not events:
            raise ValueError("at least one event is required")
        if any(not event.event_type.strip() for event in events):
            raise ValueError("event_type must not be empty")

    @staticmethod
    def _validate_fenced_task_binding(*, task_id: str, events: Sequence[NewEvent]) -> None:
        """Require the leased task identity in every immutable fenced-event payload.

        ``task_id`` is an authorization input, while ``bundle_id`` is preserved in the
        append-only payload read by downstream projections. Requiring equality before an
        idempotency lookup prevents a caller from replaying a valid command under another task.
        """

        for event in events:
            bundle_id = event.payload.get("bundle_id")
            if not isinstance(bundle_id, str) or not bundle_id:
                raise ValueError("fenced event payload must include a non-empty bundle_id")
            if bundle_id != task_id:
                raise ValueError("fenced event payload bundle_id must match task_id")

    @staticmethod
    def _assert_fenced_replay_task_binding(*, task_id: str, events: Sequence[StoredEvent]) -> None:
        """Fail closed when an idempotency record belongs to a different fenced task."""

        for event in events:
            bundle_id = event.payload.get("bundle_id")
            if not isinstance(bundle_id, str) or bundle_id != task_id:
                raise IdempotencyConflict(
                    "idempotency replay does not belong to the requested fenced task"
                )

    def _append_locked(
        self,
        connection: sqlite3.Connection,
        entity_type: str,
        entity_id: str,
        *,
        expected_sequence: int,
        events: Sequence[NewEvent],
        idempotency: Idempotency | None,
        idempotency_checked: bool = False,
        attestation_nonce: AttestationNonce | None = None,
    ) -> tuple[StoredEvent, ...]:
        if not idempotency_checked:
            existing = self._existing_idempotency(connection, idempotency)
            if existing is not None:
                return existing

        if attestation_nonce is not None:
            self._consume_attestation_nonce(
                connection,
                value=attestation_nonce,
                entity_type=entity_type,
                entity_id=entity_id,
            )

        row = connection.execute(
            "SELECT sequence FROM entity_versions WHERE entity_type = ? AND entity_id = ?",
            (entity_type, entity_id),
        ).fetchone()
        actual_sequence = 0 if row is None else int(row["sequence"])
        if actual_sequence != expected_sequence:
            raise ConcurrencyError(entity_type, entity_id, expected_sequence, actual_sequence)

        final_sequence = expected_sequence + len(events)
        if row is None:
            connection.execute(
                """
                INSERT INTO entity_versions (entity_type, entity_id, sequence)
                VALUES (?, ?, ?)
                """,
                (entity_type, entity_id, final_sequence),
            )
        else:
            cursor = connection.execute(
                """
                UPDATE entity_versions SET sequence = ?
                WHERE entity_type = ? AND entity_id = ? AND sequence = ?
                """,
                (final_sequence, entity_type, entity_id, expected_sequence),
            )
            if cursor.rowcount != 1:
                refreshed = connection.execute(
                    """
                    SELECT sequence FROM entity_versions
                    WHERE entity_type = ? AND entity_id = ?
                    """,
                    (entity_type, entity_id),
                ).fetchone()
                actual = 0 if refreshed is None else int(refreshed["sequence"])
                raise ConcurrencyError(entity_type, entity_id, expected_sequence, actual)

        recorded_at = self._utc_now_text()
        event_ids: list[str] = []
        for offset, event in enumerate(events, start=1):
            event_id = str(uuid.uuid4())
            event_ids.append(event_id)
            connection.execute(
                """
                INSERT INTO events (
                    event_id, entity_type, entity_id, entity_sequence,
                    event_type, payload_json, metadata_json, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    entity_type,
                    entity_id,
                    expected_sequence + offset,
                    event.event_type,
                    canonical_json(dict(event.payload)),
                    canonical_json(dict(event.metadata)),
                    recorded_at,
                ),
            )

        if idempotency is not None:
            self._record_idempotency(
                connection,
                value=idempotency,
                event_ids=event_ids,
                recorded_at=recorded_at,
            )

        return self._events_by_ids(connection, event_ids)

    @staticmethod
    def _record_idempotency(
        connection: sqlite3.Connection,
        *,
        value: Idempotency,
        event_ids: Sequence[str],
        recorded_at: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO idempotency_records (
                scope, key, request_hash, event_ids_json, created_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                value.scope,
                value.key,
                value.request_hash,
                canonical_json(list(event_ids)),
                recorded_at,
            ),
        )

    @staticmethod
    def _contract_revision_projection_row(
        connection: sqlite3.Connection,
        *,
        contract_id: str,
        revision: int,
    ) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            connection.execute(
                """
                SELECT contract_id, revision, bundle_id, bundle_hash, contract_hash,
                       registration_event_id
                FROM contract_revision_bindings
                WHERE contract_id = ? AND revision = ?
                """,
                (contract_id, revision),
            ).fetchone(),
        )

    @staticmethod
    def _insert_contract_revision_binding(
        connection: sqlite3.Connection,
        *,
        binding: ContractRevisionBinding,
        registration_event_id: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO contract_revision_bindings (
                contract_id, revision, bundle_id, bundle_hash, contract_hash,
                registration_event_id
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                binding.contract_id,
                binding.revision,
                binding.bundle_id,
                binding.bundle_hash,
                binding.contract_hash,
                registration_event_id,
            ),
        )

    @staticmethod
    def _registration_binding_from_projection_row(
        row: sqlite3.Row,
    ) -> ContractRevisionBinding:
        try:
            return ContractRevisionBinding(
                contract_id=str(row["contract_id"]),
                revision=int(row["revision"]),
                bundle_id=str(row["bundle_id"]),
                bundle_hash=str(row["bundle_hash"]),
                contract_hash=str(row["contract_hash"]),
            )
        except (TypeError, ValueError) as error:
            raise ProjectionError("contract revision projection contains invalid fields") from error

    @classmethod
    def _registration_binding_from_event_row(
        cls,
        row: sqlite3.Row,
    ) -> ContractRevisionBinding:
        payload = _load_canonical_json_object(
            str(row["payload_json"]),
            label="task.registered event payload",
        )
        binding = cls._registration_binding_from_payload(payload)
        if str(row["entity_id"]) != binding.bundle_id:
            raise ProjectionError("task.registered event stream ID does not match its bundle ID")
        return binding

    @staticmethod
    def _registration_binding_from_payload(payload: JsonObject) -> ContractRevisionBinding:
        def required_text(key: str) -> str:
            value = payload.get(key)
            if not isinstance(value, str) or not value:
                raise ProjectionError(f"task.registered event has invalid {key}")
            return value

        revision = payload.get("revision")
        if isinstance(revision, bool) or not isinstance(revision, int):
            raise ProjectionError("task.registered event has invalid revision")
        try:
            return ContractRevisionBinding(
                contract_id=required_text("contract_id"),
                revision=revision,
                bundle_id=required_text("bundle_id"),
                bundle_hash=required_text("bundle_hash"),
                contract_hash=required_text("contract_hash"),
            )
        except ValueError as error:
            raise ProjectionError("task.registered event has invalid binding fields") from error

    def _assert_registration_events_match(
        self,
        connection: sqlite3.Connection,
        *,
        binding: ContractRevisionBinding,
        events: Sequence[StoredEvent],
    ) -> None:
        if len(events) != 1:
            raise ProjectionError(
                "registration idempotency record must reference exactly one event"
            )
        event = events[0]
        if (
            event.entity_type != "task"
            or event.entity_id != binding.bundle_id
            or event.event_type != "task.registered"
            or self._registration_binding_from_payload(event.payload) != binding
        ):
            raise ProjectionError(
                "registration replay does not match the requested contract-revision binding"
            )
        projected = self._contract_revision_projection_row(
            connection,
            contract_id=binding.contract_id,
            revision=binding.revision,
        )
        if projected is None:
            raise ProjectionError(
                "registration replay has no canonical contract-revision projection"
            )
        if (
            self._registration_binding_from_projection_row(projected) != binding
            or str(projected["registration_event_id"]) != event.event_id
        ):
            raise ProjectionError(
                "registration replay disagrees with the canonical contract-revision projection"
            )

    def read_stream(
        self, entity_type: str, entity_id: str, *, after_sequence: int = 0
    ) -> tuple[StoredEvent, ...]:
        with self.connection() as connection:
            rows = connection.execute(
                """
                SELECT * FROM events
                WHERE entity_type = ? AND entity_id = ? AND entity_sequence > ?
                ORDER BY entity_sequence
                """,
                (entity_type, entity_id, after_sequence),
            ).fetchall()
        return tuple(self._row_to_event(row) for row in rows)

    def read_all(
        self, *, after_position: int = 0, limit: int | None = None
    ) -> tuple[StoredEvent, ...]:
        query = "SELECT * FROM events WHERE global_position > ? ORDER BY global_position"
        parameters: tuple[object, ...]
        if limit is None:
            parameters = (after_position,)
        else:
            if limit <= 0:
                raise ValueError("limit must be positive")
            query += " LIMIT ?"
            parameters = (after_position, limit)
        with self.connection() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return tuple(self._row_to_event(row) for row in rows)

    def count_events(self, *, entity_type: str | None = None) -> int:
        with self.connection() as connection:
            if entity_type is None:
                row = connection.execute("SELECT COUNT(*) AS count FROM events").fetchone()
            else:
                row = connection.execute(
                    "SELECT COUNT(*) AS count FROM events WHERE entity_type = ?",
                    (entity_type,),
                ).fetchone()
        if row is None:
            raise RuntimeError("SQLite event count query returned no result")
        return int(row["count"])

    def _existing_idempotency(
        self, connection: sqlite3.Connection, value: Idempotency | None
    ) -> tuple[StoredEvent, ...] | None:
        if value is None:
            return None
        row = connection.execute(
            """
            SELECT request_hash, event_ids_json
            FROM idempotency_records
            WHERE scope = ? AND key = ?
            """,
            (value.scope, value.key),
        ).fetchone()
        if row is None:
            return None
        return self._resolve_idempotency(connection, row, value)

    def _consume_attestation_nonce(
        self,
        connection: sqlite3.Connection,
        *,
        value: AttestationNonce,
        entity_type: str,
        entity_id: str,
    ) -> None:
        """Persist a one-time nonce in the same transaction as its state transition."""

        existing = connection.execute(
            """
            SELECT entity_type, entity_id
            FROM attestation_nonce_uses
            WHERE purpose = ? AND key_id = ? AND nonce = ?
            """,
            (value.purpose, value.key_id, value.nonce),
        ).fetchone()
        if existing is not None:
            raise AttestationReplay("attestation nonce was already consumed")
        connection.execute(
            """
            INSERT INTO attestation_nonce_uses (
                purpose, key_id, nonce, payload_hash, entity_type, entity_id, consumed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                value.purpose,
                value.key_id,
                value.nonce,
                value.payload_hash,
                entity_type,
                entity_id,
                self._utc_now_text(),
            ),
        )

    def _assert_current_fence(
        self, connection: sqlite3.Connection, *, task_id: str, lease: Lease
    ) -> None:
        if lease.job_id != task_id:
            raise StaleFence("lease belongs to a different task")
        row = connection.execute(
            """
            SELECT holder_id, fencing_token, expires_at_epoch
            FROM worker_leases
            WHERE job_id = ?
            """,
            (task_id,),
        ).fetchone()
        now_epoch = self._utc_now().timestamp()
        if row is None:
            raise StaleFence("lease no longer exists")
        if (
            str(row["holder_id"]) != lease.holder_id
            or int(row["fencing_token"]) != lease.fencing_token
            or float(row["expires_at_epoch"]) <= now_epoch
        ):
            raise StaleFence("lease fencing token is stale or expired")

    def _utc_now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise ValueError("event clock must return a timezone-aware datetime")
        return value.astimezone(UTC)

    def _utc_now_text(self) -> str:
        return self._utc_now().isoformat(timespec="microseconds").replace("+00:00", "Z")

    def _resolve_idempotency(
        self, connection: sqlite3.Connection, row: sqlite3.Row, value: Idempotency
    ) -> tuple[StoredEvent, ...]:
        existing_hash = str(row["request_hash"])
        if existing_hash != value.request_hash:
            raise IdempotencyConflict(
                f"idempotency key {value.scope}/{value.key} was reused for another request"
            )
        decoded = _load_canonical_json(
            str(row["event_ids_json"]),
            label="idempotency event IDs",
        )
        if (
            not isinstance(decoded, list)
            or not decoded
            or any(not isinstance(event_id, str) or not event_id for event_id in decoded)
            or len(set(decoded)) != len(decoded)
        ):
            raise ProjectionError("idempotency event IDs must be a unique non-empty string list")
        event_ids = cast(list[str], decoded)
        return self._events_by_ids(connection, event_ids)

    def _events_by_ids(
        self, connection: sqlite3.Connection, event_ids: Sequence[str]
    ) -> tuple[StoredEvent, ...]:
        events: list[StoredEvent] = []
        for event_id in event_ids:
            row = connection.execute(
                "SELECT * FROM events WHERE event_id = ?", (event_id,)
            ).fetchone()
            if row is None:
                raise RuntimeError(f"idempotency record references missing event {event_id}")
            events.append(self._row_to_event(row))
        return tuple(events)

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> StoredEvent:
        payload = _load_canonical_json_object(
            str(row["payload_json"]),
            label="event payload",
        )
        metadata = _load_canonical_json_object(
            str(row["metadata_json"]),
            label="event metadata",
        )
        return StoredEvent(
            global_position=int(row["global_position"]),
            event_id=str(row["event_id"]),
            entity_type=str(row["entity_type"]),
            entity_id=str(row["entity_id"]),
            entity_sequence=int(row["entity_sequence"]),
            event_type=str(row["event_type"]),
            payload=payload,
            metadata=metadata,
            recorded_at=str(row["recorded_at"]),
        )
