"""Durable compare-and-set authority for source-prepared statement drafts.

The ledger is deliberately narrower than a signing gateway. It prevents a caller from replacing
all mutually consistent fields of an in-memory packet after preparation and survives a local
process restart. Filesystem ownership and authenticated reviewer identity remain deployment
boundaries; a production signer must read this record from its own protected service.
"""

from __future__ import annotations

import hmac
import re
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path

from autolean_contracts import (
    DigestV1,
    HashKindV1,
    StableIdentifierV1,
    StatementContractV1,
    canonical_json_bytes,
    digest_bytes,
    digest_model,
)

_SCHEMA_VERSION = "autolean.source-preparation-ledger.v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class SourcePreparationError(ValueError):
    """A source-preparation record is absent, conflicting, or stored unsafely."""


@dataclass(frozen=True, slots=True)
class SourcePreparationRecordV1:
    preparation_id: StableIdentifierV1
    contract_id: StableIdentifierV1
    revision: int
    packet_sha256: str
    contract_sha256: str
    rights_sha256: str
    spans_sha256: str
    manifest_sha256: str
    artifact_sha256: str
    parent_artifact_sha256: str

    def __post_init__(self) -> None:
        if self.preparation_id.namespace != "source-preparation":
            raise SourcePreparationError("preparation_id must use the source-preparation namespace")
        if self.revision < 1:
            raise SourcePreparationError("source-preparation revision must be positive")
        for label, value in (
            ("packet_sha256", self.packet_sha256),
            ("contract_sha256", self.contract_sha256),
            ("rights_sha256", self.rights_sha256),
            ("spans_sha256", self.spans_sha256),
            ("manifest_sha256", self.manifest_sha256),
            ("artifact_sha256", self.artifact_sha256),
            ("parent_artifact_sha256", self.parent_artifact_sha256),
        ):
            if _SHA256.fullmatch(value) is None:
                raise SourcePreparationError(f"{label} must be a lowercase SHA-256 digest")

    def database_values(self) -> tuple[object, ...]:
        return (
            self.preparation_id.value,
            self.contract_id.value,
            self.revision,
            self.packet_sha256,
            self.contract_sha256,
            self.rights_sha256,
            self.spans_sha256,
            self.manifest_sha256,
            self.artifact_sha256,
            self.parent_artifact_sha256,
        )

    def canonical_json_bytes(self) -> bytes:
        return canonical_json_bytes(
            {
                "schema_version": "autolean.source-preparation-record.v1",
                "preparation_id": self.preparation_id.model_dump(mode="json"),
                "contract_id": self.contract_id.model_dump(mode="json"),
                "revision": self.revision,
                "packet_sha256": self.packet_sha256,
                "contract_sha256": self.contract_sha256,
                "rights_sha256": self.rights_sha256,
                "spans_sha256": self.spans_sha256,
                "manifest_sha256": self.manifest_sha256,
                "artifact_sha256": self.artifact_sha256,
                "parent_artifact_sha256": self.parent_artifact_sha256,
            }
        )

    def artifact_digest(self) -> DigestV1:
        return digest_bytes(HashKindV1.SOURCE_PREPARATION, self.canonical_json_bytes())

    def assert_binds_contract(self, contract: StatementContractV1) -> None:
        if self.contract_id != contract.contract_id:
            raise SourcePreparationError("source preparation binds another contract ID")
        if self.revision != contract.revision:
            raise SourcePreparationError("source preparation binds another contract revision")
        complete_draft_hash = digest_model(HashKindV1.CONTRACT, contract).value
        if not hmac.compare_digest(self.contract_sha256, complete_draft_hash):
            raise SourcePreparationError("source preparation binds another contract hash")


class SourcePreparationLedger:
    """Append-only SQLite CAS for one canonical record per contract revision."""

    def __init__(self, database_path: Path, *, confinement_root: Path) -> None:
        root = confinement_root.resolve(strict=True)
        path = database_path.resolve(strict=False)
        if not path.is_relative_to(root):
            raise SourcePreparationError("source-preparation ledger must stay within its root")
        _reject_link_or_reparse(root, path.parent)
        path.parent.mkdir(parents=True, exist_ok=True)
        _reject_link_or_reparse(root, path.parent)
        if path.exists() and not path.is_file():
            raise SourcePreparationError("source-preparation ledger path is not a regular file")
        if path.is_symlink() or _is_reparse(path):
            raise SourcePreparationError("source-preparation ledger cannot be a link or junction")
        self._path = path
        self._initialize()

    @property
    def database_path(self) -> Path:
        return self._path

    def record(self, record: SourcePreparationRecordV1) -> None:
        """Insert once, replay identically, and reject a conflicting contract revision."""

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """
                SELECT preparation_id, contract_id, revision, packet_sha256, contract_sha256,
                       rights_sha256, spans_sha256, manifest_sha256, artifact_sha256,
                       parent_artifact_sha256
                FROM source_preparations
                WHERE preparation_id = ?
                   OR (contract_id = ? AND revision = ?)
                ORDER BY preparation_id
                """,
                (
                    record.preparation_id.value,
                    record.contract_id.value,
                    record.revision,
                ),
            ).fetchall()
            if existing:
                if len(existing) != 1 or not _row_matches(existing[0], record):
                    raise SourcePreparationError(
                        "source preparation conflicts with the append-only contract revision"
                    )
            else:
                connection.execute(
                    """
                    INSERT INTO source_preparations (
                        preparation_id, contract_id, revision, packet_sha256, contract_sha256,
                        rights_sha256, spans_sha256, manifest_sha256, artifact_sha256,
                        parent_artifact_sha256
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    record.database_values(),
                )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def require(self, record: SourcePreparationRecordV1) -> None:
        """Reload the authority record instead of trusting packet-local duplicate fields."""

        connection = self._connect()
        try:
            rows = connection.execute(
                """
                SELECT preparation_id, contract_id, revision, packet_sha256, contract_sha256,
                       rights_sha256, spans_sha256, manifest_sha256, artifact_sha256,
                       parent_artifact_sha256
                FROM source_preparations
                WHERE preparation_id = ?
                """,
                (record.preparation_id.value,),
            ).fetchall()
        finally:
            connection.close()
        if len(rows) != 1:
            raise SourcePreparationError("source preparation is absent from the authority ledger")
        if not _row_matches(rows[0], record):
            raise SourcePreparationError("source preparation differs from the authority ledger")

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS ledger_metadata (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    schema_version TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS source_preparations (
                    preparation_id TEXT PRIMARY KEY,
                    contract_id TEXT NOT NULL,
                    revision INTEGER NOT NULL CHECK (revision >= 1),
                    packet_sha256 TEXT NOT NULL,
                    contract_sha256 TEXT NOT NULL,
                    rights_sha256 TEXT NOT NULL,
                    spans_sha256 TEXT NOT NULL,
                    manifest_sha256 TEXT NOT NULL,
                    artifact_sha256 TEXT NOT NULL,
                    parent_artifact_sha256 TEXT NOT NULL,
                    UNIQUE (contract_id, revision)
                )
                """
            )
            metadata = connection.execute(
                "SELECT schema_version FROM ledger_metadata WHERE singleton = 1"
            ).fetchone()
            if metadata is None:
                connection.execute(
                    "INSERT INTO ledger_metadata (singleton, schema_version) VALUES (1, ?)",
                    (_SCHEMA_VERSION,),
                )
            elif metadata[0] != _SCHEMA_VERSION:
                raise SourcePreparationError(
                    "source-preparation ledger schema version is unsupported"
                )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        if self._path.is_symlink() or _is_reparse(self._path):
            raise SourcePreparationError("source-preparation ledger cannot be a link or junction")
        connection = sqlite3.connect(self._path, isolation_level=None, timeout=10.0)
        connection.execute("PRAGMA busy_timeout = 10000")
        journal_mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()
        if journal_mode is None or str(journal_mode[0]).lower() != "wal":
            connection.close()
            raise SourcePreparationError("source-preparation ledger requires SQLite WAL mode")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA foreign_keys = ON")
        return connection


def _row_matches(row: sqlite3.Row | tuple[object, ...], record: SourcePreparationRecordV1) -> bool:
    actual = tuple(row)
    expected = record.database_values()
    return len(actual) == len(expected) and all(
        hmac.compare_digest(str(left), str(right))
        for left, right in zip(actual, expected, strict=True)
    )


def _reject_link_or_reparse(root: Path, target: Path) -> None:
    try:
        relative = target.resolve(strict=False).relative_to(root)
    except ValueError as error:
        raise SourcePreparationError("source-preparation path escapes its root") from error
    current = root
    for part in relative.parts:
        current = current / part
        if not current.exists():
            continue
        if current.is_symlink() or _is_reparse(current):
            raise SourcePreparationError(
                "source-preparation path cannot traverse a link or junction"
            )


def _is_reparse(path: Path) -> bool:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return False
    return bool(attributes & _REPARSE_POINT)
