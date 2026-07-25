"""Fail-closed validation for experimental Lean proof-dependency evidence.

The current frozen proof boundary and OCI evidence contracts do not carry this policy or evidence.
This module is therefore a validation spike, not an admission authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, NoReturn

PROOF_DEPENDENCY_QUERY_SCHEMA: Final[str] = "autolean.proof-dependency-query-spike.v1"
PROOF_DEPENDENCY_POLICY_SCHEMA: Final[str] = "autolean.proof-dependency-policy-spike.v1"
PROOF_DEPENDENCY_TRAVERSAL: Final[str] = (
    "target-proof-value-then-declaration-type-and-value-transitive.v1"
)
_MAX_DECLARATIONS: Final[int] = 100_000
_MAX_NAME_CHARS: Final[int] = 4_096
_TARGET = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$")
_EVIDENCE_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "candidate_declaration_count",
        "candidate_owned_dependencies",
        "declaration",
        "direct_proof_dependencies",
        "proof_dependency_closure",
        "schema_version",
        "traversal",
    }
)
_POLICY_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "allowed_dependencies",
        "denied_dependencies",
        "schema_version",
        "target_declaration",
    }
)


class ProofDependencyEvidenceError(ValueError):
    """The query record or frozen policy is malformed or incomplete."""


class ProofDependencyRejected(ValueError):
    """A well-formed query record violates the frozen dependency boundary."""


def _reject(message: str) -> NoReturn:
    raise ProofDependencyEvidenceError(message)


def _name(value: object, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > _MAX_NAME_CHARS
        or any(character in value for character in ("\x00", "\n", "\r"))
    ):
        _reject(f"{label} is not a canonical declaration name")
    return value


def _name_list(value: object, *, label: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        _reject(f"{label} must be a list")
    names = tuple(_name(item, label=label) for item in value)
    if len(names) > _MAX_DECLARATIONS:
        _reject(f"{label} exceeds the declaration limit")
    if names != tuple(sorted(names)) or len(names) != len(set(names)):
        _reject(f"{label} must be sorted and unique")
    return names


def _canonical_sha256(payload: Mapping[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class ProofDependencyEvidence:
    """Strictly parsed output from the experimental Lean dependency query."""

    declaration: str
    candidate_declaration_count: int
    direct_proof_dependencies: tuple[str, ...]
    proof_dependency_closure: tuple[str, ...]
    candidate_owned_dependencies: tuple[str, ...]
    schema_version: str = PROOF_DEPENDENCY_QUERY_SCHEMA
    traversal: str = PROOF_DEPENDENCY_TRAVERSAL

    @classmethod
    def from_mapping(cls, raw: Mapping[str, object]) -> ProofDependencyEvidence:
        if set(raw) != _EVIDENCE_FIELDS:
            _reject("proof dependency evidence has unexpected or missing fields")
        if raw.get("schema_version") != PROOF_DEPENDENCY_QUERY_SCHEMA:
            _reject("proof dependency evidence uses an unsupported schema")
        if raw.get("traversal") != PROOF_DEPENDENCY_TRAVERSAL:
            _reject("proof dependency evidence uses an unsupported traversal")
        count = raw.get("candidate_declaration_count")
        if (
            not isinstance(count, int)
            or isinstance(count, bool)
            or count <= 0
            or count > _MAX_DECLARATIONS
        ):
            _reject("candidate declaration count is invalid")
        declaration = _name(raw.get("declaration"), label="target declaration")
        if _TARGET.fullmatch(declaration) is None:
            _reject("target declaration is not a canonical dotted name")
        direct = _name_list(
            raw.get("direct_proof_dependencies"),
            label="direct proof dependencies",
        )
        closure = _name_list(
            raw.get("proof_dependency_closure"),
            label="proof dependency closure",
        )
        candidate_owned = _name_list(
            raw.get("candidate_owned_dependencies"),
            label="candidate-owned dependencies",
        )
        closure_set = set(closure)
        if not set(direct) <= closure_set:
            _reject("proof dependency closure omits a direct dependency")
        if not set(candidate_owned) <= closure_set:
            _reject("candidate-owned dependencies are outside the proof dependency closure")
        if len(candidate_owned) > count:
            _reject("candidate-owned dependency count exceeds the Candidate module")
        if declaration in closure_set:
            _reject("proof dependency closure refers to its own target declaration")
        return cls(
            declaration=declaration,
            candidate_declaration_count=count,
            direct_proof_dependencies=direct,
            proof_dependency_closure=closure,
            candidate_owned_dependencies=candidate_owned,
        )

    def to_mapping(self) -> dict[str, object]:
        return {
            "candidate_declaration_count": self.candidate_declaration_count,
            "candidate_owned_dependencies": list(self.candidate_owned_dependencies),
            "declaration": self.declaration,
            "direct_proof_dependencies": list(self.direct_proof_dependencies),
            "proof_dependency_closure": list(self.proof_dependency_closure),
            "schema_version": self.schema_version,
            "traversal": self.traversal,
        }

    def canonical_sha256(self) -> str:
        return _canonical_sha256(self.to_mapping())


@dataclass(frozen=True, slots=True)
class ProofDependencyPolicy:
    """Exact, frozen allow/deny boundary for one target declaration.

    Every declaration in the transitive closure must be explicitly allowed. Denials take
    precedence and the target itself must be denied, making accidental recursion or reuse explicit.
    """

    target_declaration: str
    allowed_dependencies: tuple[str, ...]
    denied_dependencies: tuple[str, ...]
    schema_version: str = PROOF_DEPENDENCY_POLICY_SCHEMA

    @classmethod
    def from_mapping(cls, raw: Mapping[str, object]) -> ProofDependencyPolicy:
        if set(raw) != _POLICY_FIELDS:
            _reject("proof dependency policy has unexpected or missing fields")
        if raw.get("schema_version") != PROOF_DEPENDENCY_POLICY_SCHEMA:
            _reject("proof dependency policy uses an unsupported schema")
        target = _name(raw.get("target_declaration"), label="policy target declaration")
        if _TARGET.fullmatch(target) is None:
            _reject("policy target declaration is not a canonical dotted name")
        allowed = _name_list(raw.get("allowed_dependencies"), label="allowed dependencies")
        denied = _name_list(raw.get("denied_dependencies"), label="denied dependencies")
        if set(allowed) & set(denied):
            _reject("proof dependency allowlist and denylist overlap")
        if target not in denied:
            _reject("proof dependency denylist must include the target declaration")
        return cls(
            target_declaration=target,
            allowed_dependencies=allowed,
            denied_dependencies=denied,
        )

    def to_mapping(self) -> dict[str, object]:
        return {
            "allowed_dependencies": list(self.allowed_dependencies),
            "denied_dependencies": list(self.denied_dependencies),
            "schema_version": self.schema_version,
            "target_declaration": self.target_declaration,
        }

    def canonical_sha256(self) -> str:
        return _canonical_sha256(self.to_mapping())


@dataclass(frozen=True, slots=True)
class ProofDependencyDecision:
    """A deterministic non-authoritative decision from the experimental gate."""

    accepted: bool
    target_declaration: str
    policy_sha256: str
    evidence_sha256: str
    direct_dependency_count: int
    closure_dependency_count: int

    def to_mapping(self) -> dict[str, object]:
        return {
            "accepted": self.accepted,
            "closure_dependency_count": self.closure_dependency_count,
            "direct_dependency_count": self.direct_dependency_count,
            "evidence_sha256": self.evidence_sha256,
            "policy_sha256": self.policy_sha256,
            "schema_version": "autolean.proof-dependency-decision-spike.v1",
            "target_declaration": self.target_declaration,
        }


def evaluate_proof_dependency_policy(
    evidence: ProofDependencyEvidence,
    policy: ProofDependencyPolicy,
) -> ProofDependencyDecision:
    """Accept only an exact, deny-free transitive dependency closure."""

    if evidence.declaration != policy.target_declaration:
        raise ProofDependencyRejected(
            "proof dependency evidence names a different target declaration"
        )
    observed = set(evidence.proof_dependency_closure)
    denied = observed & set(policy.denied_dependencies)
    if denied:
        raise ProofDependencyRejected(
            "proof dependency closure contains denied declarations: " + ", ".join(sorted(denied))
        )
    unapproved = observed - set(policy.allowed_dependencies)
    if unapproved:
        raise ProofDependencyRejected(
            "proof dependency closure contains unapproved declarations: "
            + ", ".join(sorted(unapproved))
        )
    return ProofDependencyDecision(
        accepted=True,
        target_declaration=evidence.declaration,
        policy_sha256=policy.canonical_sha256(),
        evidence_sha256=evidence.canonical_sha256(),
        direct_dependency_count=len(evidence.direct_proof_dependencies),
        closure_dependency_count=len(evidence.proof_dependency_closure),
    )
