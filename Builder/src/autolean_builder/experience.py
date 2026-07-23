"""Deterministic, rights-scoped experience retrieval for statement conversion.

Experience is untrusted advisory evidence. This module has no contract-freeze,
provider, control-plane, or Prover integration and cannot mutate a statement.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, cast

_IDENTIFIER: Final = re.compile(r"^[a-z0-9][a-z0-9._:/-]{0,255}$")
_SHA256: Final = re.compile(r"^[0-9a-f]{64}$")
_SECRET_PATTERNS: Final = (
    re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
    re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    re.compile(r"\bhf_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}\b"),
)
_INJECTION_MARKERS: Final = (
    "<|",
    "[inst]",
    "assistant:",
    "developer message",
    "ignore all previous",
    "ignore previous",
    "override instructions",
    "reveal secret",
    "system prompt",
    "system:",
    "tool_call",
)
_BIDI_CLASSES: Final = frozenset({"RLE", "LRE", "RLO", "LRO", "PDF", "RLI", "LRI", "FSI", "PDI"})
_PACK_SCHEMA: Final = "autolean.builder-experience-context.v1"
_RECORD_SCHEMA: Final = "autolean.builder-experience.v1"
_AUTHORITY: Final = "untrusted-advisory-only"
_TOKEN_ESTIMATOR: Final = "canonical-json-utf8-ceil-div-4.v1"


class ExperienceError(ValueError):
    """An experience record, query, or replay violated a trust boundary."""


class ExperienceBudgetError(ExperienceError):
    """The token budget cannot hold even the empty context envelope."""


class ExperienceOutcome(StrEnum):
    SUCCESS_PATTERN = "success_pattern"
    NEGATIVE_EVIDENCE = "negative_evidence"
    GAP = "gap"


class ExperienceEndpoint(StrEnum):
    LOCAL = "local"
    APPROVED_EXTERNAL = "approved_external"


class FailureEvidenceKind(StrEnum):
    GAP_REPORT = "gap_report"
    REJECTED_TRANSLATION = "rejected_translation"
    REVIEW_FAILURE = "review_failure"
    VERIFICATION_FAILURE = "verification_failure"


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _mapping(value: object, *, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ExperienceError(f"{label} must be a string-keyed mapping")
    return cast(dict[str, object], value)


def _list(value: object, *, label: str) -> list[object]:
    if not isinstance(value, list):
        raise ExperienceError(f"{label} must be a list")
    return cast(list[object], value)


def _string(value: object, *, label: str) -> str:
    if not isinstance(value, str):
        raise ExperienceError(f"{label} must be a string")
    return value


def _optional_string(value: object, *, label: str) -> str | None:
    if value is None:
        return None
    return _string(value, label=label)


def _integer(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ExperienceError(f"{label} must be an integer")
    return value


def _string_tuple(value: object, *, label: str) -> tuple[str, ...]:
    return tuple(_string(item, label=label) for item in _list(value, label=label))


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ExperienceError("experience ContextPack JSON contains a duplicate key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ExperienceError(f"experience ContextPack JSON contains invalid constant {value!r}")


def _validate_identifier(value: str, *, label: str) -> None:
    if _IDENTIFIER.fullmatch(value) is None:
        raise ExperienceError(f"{label} must be a canonical lower-case identifier")


def _validate_digest(value: str, *, label: str) -> None:
    if _SHA256.fullmatch(value) is None:
        raise ExperienceError(f"{label} must be a lower-case SHA-256 digest")


def _validate_unique(values: tuple[str, ...], *, label: str) -> None:
    if not values or len(values) != len(set(values)):
        raise ExperienceError(f"{label} must be non-empty and unique")
    for value in values:
        _validate_identifier(value, label=label)


def _validate_untrusted_text(value: str, *, label: str, maximum: int = 16_384) -> None:
    if not value.strip() or value != value.strip() or len(value) > maximum:
        raise ExperienceError(f"{label} must be non-empty, trimmed, and bounded")
    if "\r" in value or "\x00" in value:
        raise ExperienceError(f"{label} contains an unsafe control character")
    if any(unicodedata.bidirectional(character) in _BIDI_CLASSES for character in value):
        raise ExperienceError(f"{label} contains bidirectional control text")
    folded = unicodedata.normalize("NFKC", value).casefold()
    if any(marker in folded for marker in _INJECTION_MARKERS):
        raise ExperienceError(f"{label} contains a prompt-control marker")
    if any(pattern.search(value) is not None for pattern in _SECRET_PATTERNS):
        raise ExperienceError(f"{label} contains credential-shaped material")


@dataclass(frozen=True, slots=True)
class ExperienceSource:
    source_id: str
    source_version: str
    source_sha256: str
    span_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        _validate_identifier(self.source_id, label="source_id")
        _validate_identifier(self.source_version, label="source_version")
        _validate_digest(self.source_sha256, label="source_sha256")
        _validate_unique(self.span_ids, label="source span IDs")

    def payload(self) -> dict[str, object]:
        return {
            "source_id": self.source_id,
            "source_sha256": self.source_sha256,
            "source_version": self.source_version,
            "span_ids": sorted(self.span_ids),
        }


@dataclass(frozen=True, slots=True)
class RightsEgressPolicy:
    rights_scope_id: str
    policy_version: str
    allowed_endpoints: tuple[ExperienceEndpoint, ...] = (ExperienceEndpoint.LOCAL,)
    external_review_ref: str | None = None

    def __post_init__(self) -> None:
        _validate_identifier(self.rights_scope_id, label="rights_scope_id")
        _validate_identifier(self.policy_version, label="rights policy version")
        if not self.allowed_endpoints or len(self.allowed_endpoints) != len(
            set(self.allowed_endpoints)
        ):
            raise ExperienceError("allowed_endpoints must be non-empty and unique")
        if ExperienceEndpoint.LOCAL not in self.allowed_endpoints:
            raise ExperienceError("every experience record must remain available locally")
        if ExperienceEndpoint.APPROVED_EXTERNAL in self.allowed_endpoints:
            if self.external_review_ref is None:
                raise ExperienceError("external egress requires an explicit review reference")
            _validate_identifier(self.external_review_ref, label="external_review_ref")
        elif self.external_review_ref is not None:
            raise ExperienceError("local-only experience must not carry an external review")

    def payload(self) -> dict[str, object]:
        return {
            "allowed_endpoints": sorted(item.value for item in self.allowed_endpoints),
            "external_review_ref": self.external_review_ref,
            "policy_version": self.policy_version,
            "rights_scope_id": self.rights_scope_id,
        }


@dataclass(frozen=True, slots=True)
class ExperienceApplicability:
    roles: tuple[str, ...]
    domain_path: tuple[str, ...]
    required_graph_frontier: tuple[str, ...]
    conditions: tuple[str, ...]

    def __post_init__(self) -> None:
        _validate_unique(self.roles, label="experience roles")
        _validate_unique(self.domain_path, label="domain path")
        if len(self.required_graph_frontier) != len(set(self.required_graph_frontier)):
            raise ExperienceError("required_graph_frontier must not contain duplicates")
        for value in self.required_graph_frontier:
            _validate_identifier(value, label="graph frontier node")
        if not self.conditions or len(self.conditions) != len(set(self.conditions)):
            raise ExperienceError("applicability conditions must be non-empty and unique")
        for condition in self.conditions:
            _validate_untrusted_text(condition, label="applicability condition", maximum=1024)

    def payload(self) -> dict[str, object]:
        return {
            "conditions": sorted(self.conditions),
            "domain_path": list(self.domain_path),
            "required_graph_frontier": sorted(self.required_graph_frontier),
            "roles": sorted(self.roles),
        }


@dataclass(frozen=True, slots=True)
class FailureEvidence:
    kind: FailureEvidenceKind
    evidence_id: str
    evidence_version: str
    artifact_sha256: str
    summary: str

    def __post_init__(self) -> None:
        _validate_identifier(self.evidence_id, label="failure evidence ID")
        _validate_identifier(self.evidence_version, label="failure evidence version")
        _validate_digest(self.artifact_sha256, label="failure artifact digest")
        _validate_untrusted_text(self.summary, label="failure evidence summary", maximum=2048)

    def payload(self) -> dict[str, object]:
        return {
            "artifact_sha256": self.artifact_sha256,
            "evidence_id": self.evidence_id,
            "evidence_version": self.evidence_version,
            "kind": self.kind.value,
            "summary": self.summary,
        }


@dataclass(frozen=True, slots=True)
class ExperienceRecord:
    source: ExperienceSource
    record_version: str
    author_role: str
    applicability: ExperienceApplicability
    rights: RightsEgressPolicy
    outcome: ExperienceOutcome
    title: str
    observation: str
    failure_evidence: tuple[FailureEvidence, ...] = ()

    def __post_init__(self) -> None:
        _validate_identifier(self.record_version, label="record_version")
        _validate_identifier(self.author_role, label="author_role")
        _validate_untrusted_text(self.title, label="experience title", maximum=256)
        _validate_untrusted_text(self.observation, label="experience observation")
        evidence_keys = {
            (item.kind, item.evidence_id, item.evidence_version, item.artifact_sha256)
            for item in self.failure_evidence
        }
        if len(evidence_keys) != len(self.failure_evidence):
            raise ExperienceError("failure evidence references must be unique")
        if (
            self.outcome in {ExperienceOutcome.NEGATIVE_EVIDENCE, ExperienceOutcome.GAP}
            and not self.failure_evidence
        ):
            raise ExperienceError("negative and gap experiences require failure evidence")

    def payload(self) -> dict[str, object]:
        evidence = sorted(
            self.failure_evidence,
            key=lambda item: (
                item.kind.value,
                item.evidence_id,
                item.evidence_version,
                item.artifact_sha256,
            ),
        )
        return {
            "applicability": self.applicability.payload(),
            "author_role": self.author_role,
            "failure_evidence": [item.payload() for item in evidence],
            "observation": self.observation,
            "outcome": self.outcome.value,
            "record_version": self.record_version,
            "rights": self.rights.payload(),
            "schema_version": _RECORD_SCHEMA,
            "source": self.source.payload(),
            "title": self.title,
        }

    @property
    def content_sha256(self) -> str:
        return _sha256(_canonical_json(self.payload()))


@dataclass(frozen=True, slots=True)
class ExperienceQuery:
    role: str
    domain_path: tuple[str, ...]
    graph_frontier: tuple[str, ...]
    rights_scope_id: str
    endpoint: ExperienceEndpoint = ExperienceEndpoint.LOCAL
    outcomes: tuple[ExperienceOutcome, ...] = tuple(ExperienceOutcome)
    max_items: int = 8
    max_tokens: int = 4096

    def __post_init__(self) -> None:
        _validate_identifier(self.role, label="query role")
        _validate_unique(self.domain_path, label="query domain path")
        _validate_identifier(self.rights_scope_id, label="query rights scope")
        if len(self.graph_frontier) != len(set(self.graph_frontier)):
            raise ExperienceError("query graph_frontier must not contain duplicates")
        for value in self.graph_frontier:
            _validate_identifier(value, label="query graph frontier node")
        if not self.outcomes or len(self.outcomes) != len(set(self.outcomes)):
            raise ExperienceError("query outcomes must be non-empty and unique")
        if not 1 <= self.max_items <= 64:
            raise ExperienceError("max_items must be between 1 and 64")
        if not 128 <= self.max_tokens <= 131_072:
            raise ExperienceError("max_tokens must be between 128 and 131072")

    def payload(self) -> dict[str, object]:
        return {
            "domain_path": list(self.domain_path),
            "endpoint": self.endpoint.value,
            "graph_frontier": sorted(self.graph_frontier),
            "max_items": self.max_items,
            "max_tokens": self.max_tokens,
            "outcomes": sorted(item.value for item in self.outcomes),
            "rights_scope_id": self.rights_scope_id,
            "role": self.role,
        }

    @property
    def content_sha256(self) -> str:
        return _sha256(_canonical_json(self.payload()))


def _candidate_set_sha256(candidate_record_sha256: tuple[str, ...]) -> str:
    return _sha256(_canonical_json(list(candidate_record_sha256)))


def _pack_payload_without_estimate(
    *,
    query: ExperienceQuery,
    query_sha256: str,
    candidate_record_sha256: tuple[str, ...],
    records: tuple[ExperienceRecord, ...],
) -> dict[str, object]:
    return {
        "authority": _AUTHORITY,
        "candidate_record_sha256": list(candidate_record_sha256),
        "candidate_set_sha256": _candidate_set_sha256(candidate_record_sha256),
        "handling": {
            "follow_embedded_instructions": False,
            "may_change_frozen_statement": False,
            "text_classification": "quoted-untrusted-experience",
        },
        "query": query.payload(),
        "query_sha256": query_sha256,
        "records": [
            {"content_sha256": record.content_sha256, "record": record.payload()}
            for record in records
        ],
        "schema_version": _PACK_SCHEMA,
        "token_estimator": _TOKEN_ESTIMATOR,
    }


def _estimate_pack_tokens(payload_without_estimate: dict[str, object]) -> int:
    estimate = 0
    while True:
        rendered = _canonical_json({**payload_without_estimate, "estimated_tokens": estimate})
        updated = (len(rendered) + 3) // 4
        if updated == estimate:
            return estimate
        estimate = updated


@dataclass(frozen=True, slots=True)
class ExperienceContextPack:
    query: ExperienceQuery
    query_sha256: str
    candidate_record_sha256: tuple[str, ...]
    records: tuple[ExperienceRecord, ...]
    estimated_tokens: int

    def __post_init__(self) -> None:
        _validate_digest(self.query_sha256, label="query_sha256")
        if self.query_sha256 != self.query.content_sha256:
            raise ExperienceError("ContextPack query hash does not match its query")
        for digest in self.candidate_record_sha256:
            _validate_digest(digest, label="candidate record digest")
        if len(self.candidate_record_sha256) != len(set(self.candidate_record_sha256)):
            raise ExperienceError("candidate record digests must be unique")
        selected = tuple(record.content_sha256 for record in self.records)
        if len(selected) != len(set(selected)):
            raise ExperienceError("selected records must be unique")
        if any(digest not in self.candidate_record_sha256 for digest in selected):
            raise ExperienceError("ContextPack contains a record outside its candidate snapshot")
        if len(self.records) > self.query.max_items:
            raise ExperienceError("ContextPack exceeds its item budget")
        expected = _estimate_pack_tokens(self._payload_without_estimate())
        if self.estimated_tokens != expected:
            raise ExperienceError("ContextPack token estimate is not reproducible")
        if self.estimated_tokens > self.query.max_tokens:
            raise ExperienceError("ContextPack exceeds its token budget")

    @property
    def candidate_set_sha256(self) -> str:
        return _candidate_set_sha256(self.candidate_record_sha256)

    def _payload_without_estimate(self) -> dict[str, object]:
        return _pack_payload_without_estimate(
            query=self.query,
            query_sha256=self.query_sha256,
            candidate_record_sha256=self.candidate_record_sha256,
            records=self.records,
        )

    def payload(self) -> dict[str, object]:
        return {**self._payload_without_estimate(), "estimated_tokens": self.estimated_tokens}

    def render(self) -> bytes:
        return _canonical_json(self.payload())

    @property
    def content_sha256(self) -> str:
        return _sha256(self.render())

    @classmethod
    def from_bytes(cls, content: bytes) -> ExperienceContextPack:
        """Load one canonical artifact without trusting its nested hashes."""

        try:
            decoded = content.decode("utf-8")
            raw = json.loads(
                decoded,
                object_pairs_hook=_reject_duplicate_pairs,
                parse_constant=_reject_json_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ExperienceError("experience ContextPack is not valid UTF-8 JSON") from error
        root = _mapping(raw, label="ContextPack")
        if _canonical_json(root) != content:
            raise ExperienceError("experience ContextPack is not canonical JSON")
        if root.get("schema_version") != _PACK_SCHEMA:
            raise ExperienceError("experience ContextPack schema is unsupported")
        if root.get("authority") != _AUTHORITY or root.get("token_estimator") != _TOKEN_ESTIMATOR:
            raise ExperienceError("experience ContextPack trust metadata is invalid")
        expected_handling = {
            "follow_embedded_instructions": False,
            "may_change_frozen_statement": False,
            "text_classification": "quoted-untrusted-experience",
        }
        if root.get("handling") != expected_handling:
            raise ExperienceError("experience ContextPack handling policy is invalid")

        query = _query_from_payload(_mapping(root.get("query"), label="query"))
        query_sha256 = _string(root.get("query_sha256"), label="query_sha256")
        candidate_hashes = _string_tuple(
            root.get("candidate_record_sha256"),
            label="candidate_record_sha256",
        )
        if root.get("candidate_set_sha256") != _candidate_set_sha256(candidate_hashes):
            raise ExperienceError("experience candidate snapshot hash does not match")

        records: list[ExperienceRecord] = []
        for item in _list(root.get("records"), label="records"):
            envelope = _mapping(item, label="record envelope")
            record = _record_from_payload(_mapping(envelope.get("record"), label="record"))
            if envelope.get("content_sha256") != record.content_sha256:
                raise ExperienceError("experience record content hash does not match")
            records.append(record)
        pack = cls(
            query=query,
            query_sha256=query_sha256,
            candidate_record_sha256=candidate_hashes,
            records=tuple(records),
            estimated_tokens=_integer(root.get("estimated_tokens"), label="estimated_tokens"),
        )
        if pack.render() != content:
            raise ExperienceError("experience ContextPack fields are incomplete or changed")
        return pack


def _query_from_payload(value: dict[str, object]) -> ExperienceQuery:
    try:
        endpoint = ExperienceEndpoint(_string(value.get("endpoint"), label="query endpoint"))
        outcomes = tuple(
            ExperienceOutcome(item)
            for item in _string_tuple(value.get("outcomes"), label="query outcomes")
        )
    except ValueError as error:
        raise ExperienceError("experience query contains an unsupported enum value") from error
    return ExperienceQuery(
        role=_string(value.get("role"), label="query role"),
        domain_path=_string_tuple(value.get("domain_path"), label="query domain path"),
        graph_frontier=_string_tuple(value.get("graph_frontier"), label="query graph frontier"),
        rights_scope_id=_string(value.get("rights_scope_id"), label="query rights scope"),
        endpoint=endpoint,
        outcomes=outcomes,
        max_items=_integer(value.get("max_items"), label="query max_items"),
        max_tokens=_integer(value.get("max_tokens"), label="query max_tokens"),
    )


def _record_from_payload(value: dict[str, object]) -> ExperienceRecord:
    if value.get("schema_version") != _RECORD_SCHEMA:
        raise ExperienceError("experience record schema is unsupported")
    source_value = _mapping(value.get("source"), label="experience source")
    applicability_value = _mapping(value.get("applicability"), label="experience applicability")
    rights_value = _mapping(value.get("rights"), label="experience rights")
    try:
        outcome = ExperienceOutcome(_string(value.get("outcome"), label="experience outcome"))
        endpoints = tuple(
            ExperienceEndpoint(item)
            for item in _string_tuple(
                rights_value.get("allowed_endpoints"),
                label="allowed endpoints",
            )
        )
    except ValueError as error:
        raise ExperienceError("experience record contains an unsupported enum value") from error

    evidence: list[FailureEvidence] = []
    for item in _list(value.get("failure_evidence"), label="failure evidence"):
        evidence_value = _mapping(item, label="failure evidence item")
        try:
            kind = FailureEvidenceKind(
                _string(evidence_value.get("kind"), label="failure evidence kind")
            )
        except ValueError as error:
            raise ExperienceError("failure evidence kind is unsupported") from error
        evidence.append(
            FailureEvidence(
                kind=kind,
                evidence_id=_string(
                    evidence_value.get("evidence_id"),
                    label="failure evidence ID",
                ),
                evidence_version=_string(
                    evidence_value.get("evidence_version"),
                    label="failure evidence version",
                ),
                artifact_sha256=_string(
                    evidence_value.get("artifact_sha256"),
                    label="failure evidence digest",
                ),
                summary=_string(evidence_value.get("summary"), label="failure evidence summary"),
            )
        )

    return ExperienceRecord(
        source=ExperienceSource(
            source_id=_string(source_value.get("source_id"), label="source ID"),
            source_version=_string(source_value.get("source_version"), label="source version"),
            source_sha256=_string(source_value.get("source_sha256"), label="source hash"),
            span_ids=_string_tuple(source_value.get("span_ids"), label="source spans"),
        ),
        record_version=_string(value.get("record_version"), label="record version"),
        author_role=_string(value.get("author_role"), label="author role"),
        applicability=ExperienceApplicability(
            roles=_string_tuple(applicability_value.get("roles"), label="experience roles"),
            domain_path=_string_tuple(
                applicability_value.get("domain_path"),
                label="experience domain",
            ),
            required_graph_frontier=_string_tuple(
                applicability_value.get("required_graph_frontier"),
                label="required graph frontier",
            ),
            conditions=_string_tuple(
                applicability_value.get("conditions"),
                label="applicability conditions",
            ),
        ),
        rights=RightsEgressPolicy(
            rights_scope_id=_string(
                rights_value.get("rights_scope_id"),
                label="rights scope",
            ),
            policy_version=_string(
                rights_value.get("policy_version"),
                label="rights policy version",
            ),
            allowed_endpoints=endpoints,
            external_review_ref=_optional_string(
                rights_value.get("external_review_ref"),
                label="external review reference",
            ),
        ),
        outcome=outcome,
        title=_string(value.get("title"), label="experience title"),
        observation=_string(value.get("observation"), label="experience observation"),
        failure_evidence=tuple(evidence),
    )


class ExperienceCatalog:
    """A minimal content-addressed, read-only record collection."""

    def __init__(self, records: tuple[ExperienceRecord, ...]) -> None:
        by_digest: dict[str, ExperienceRecord] = {}
        for record in records:
            by_digest.setdefault(record.content_sha256, record)
        self._by_digest = by_digest

    def records(self) -> tuple[ExperienceRecord, ...]:
        return tuple(self._by_digest[digest] for digest in sorted(self._by_digest))


class ExperienceRetriever:
    """Filter, rank, budget, and replay advisory experience without semantic authority."""

    def __init__(self, catalog: ExperienceCatalog) -> None:
        self._catalog = catalog

    @staticmethod
    def _eligible(record: ExperienceRecord, query: ExperienceQuery) -> bool:
        applicability = record.applicability
        required_frontier = set(applicability.required_graph_frontier)
        return (
            query.role in applicability.roles
            and len(applicability.domain_path) <= len(query.domain_path)
            and query.domain_path[: len(applicability.domain_path)] == applicability.domain_path
            and required_frontier.issubset(query.graph_frontier)
            and record.rights.rights_scope_id == query.rights_scope_id
            and query.endpoint in record.rights.allowed_endpoints
            and record.outcome in query.outcomes
        )

    @staticmethod
    def _rank_key(record: ExperienceRecord) -> tuple[int, int, int, str]:
        return (
            -len(record.applicability.domain_path),
            -len(record.applicability.required_graph_frontier),
            -len(record.applicability.conditions),
            record.content_sha256,
        )

    def retrieve(self, query: ExperienceQuery) -> ExperienceContextPack:
        candidates = tuple(
            sorted(
                (record for record in self._catalog.records() if self._eligible(record, query)),
                key=self._rank_key,
            )
        )
        candidate_hashes = tuple(record.content_sha256 for record in candidates)

        selected: list[ExperienceRecord] = []
        empty_payload = _pack_payload_without_estimate(
            query=query,
            query_sha256=query.content_sha256,
            candidate_record_sha256=candidate_hashes,
            records=(),
        )
        if _estimate_pack_tokens(empty_payload) > query.max_tokens:
            raise ExperienceBudgetError("token budget cannot hold the empty experience envelope")

        for candidate in candidates:
            if len(selected) >= query.max_items:
                break
            trial = tuple((*selected, candidate))
            trial_payload = _pack_payload_without_estimate(
                query=query,
                query_sha256=query.content_sha256,
                candidate_record_sha256=candidate_hashes,
                records=trial,
            )
            if _estimate_pack_tokens(trial_payload) <= query.max_tokens:
                selected.append(candidate)

        selected_tuple = tuple(selected)
        final_payload = _pack_payload_without_estimate(
            query=query,
            query_sha256=query.content_sha256,
            candidate_record_sha256=candidate_hashes,
            records=selected_tuple,
        )
        return ExperienceContextPack(
            query=query,
            query_sha256=query.content_sha256,
            candidate_record_sha256=candidate_hashes,
            records=selected_tuple,
            estimated_tokens=_estimate_pack_tokens(final_payload),
        )

    def replay(self, previous: ExperienceContextPack) -> ExperienceContextPack:
        replayed = self.retrieve(previous.query)
        if replayed.render() != previous.render():
            raise ExperienceError("experience ContextPack replay does not match recorded bytes")
        return replayed
