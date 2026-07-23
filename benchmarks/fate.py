"""Deterministic FATE metadata validation and benchmark splits.

This module deliberately contains no downloader and no solution loader. Network access and
model execution belong to explicit operator commands, never to the default test suite.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

Tier = Literal["M", "H", "X"]

CANARY: Final[dict[Tier, frozenset[int]]] = {
    "M": frozenset({3, 15, 134}),
    "H": frozenset({31, 51, 93}),
    "X": frozenset({11, 15, 62, 72, 77, 86}),
}
SMOKE: Final[dict[Tier, frozenset[int]]] = {
    "M": frozenset({1, 3, 4, 7, 10, 40, 79, 150}),
    "H": frozenset(),
    "X": frozenset(),
}
TIER_COUNTS: Final[dict[Tier, int]] = {"M": 150, "H": 100, "X": 100}
SPLIT_SEED: Final = "autolean-fate-split-v1"


@dataclass(frozen=True, slots=True, order=True)
class FateProblemId:
    tier: Tier
    number: int

    def __post_init__(self) -> None:
        if not 1 <= self.number <= TIER_COUNTS[self.tier]:
            raise ValueError(f"FATE-{self.tier}-{self.number} is outside the pinned suite")

    @property
    def canonical(self) -> str:
        return f"FATE-{self.tier}-{self.number}"


@dataclass(frozen=True, slots=True)
class FateProblem:
    problem_id: FateProblemId
    informal_statement: str
    formal_statement: str
    version: str
    declarations: tuple[str, ...] = ()


def _stable_key(problem_id: FateProblemId) -> bytes:
    payload = f"{SPLIT_SEED}\0{problem_id.tier}:{problem_id.number}".encode()
    return hashlib.sha256(payload).digest()


def stable_sample(
    tier: Tier,
    count: int,
    *,
    excluded: frozenset[int] = frozenset(),
) -> tuple[int, ...]:
    """Select IDs without depending on source ordering or global RNG state."""

    if count < 0 or count > TIER_COUNTS[tier] - len(excluded):
        raise ValueError("requested sample does not fit the tier")
    candidates = (
        FateProblemId(tier, number)
        for number in range(1, TIER_COUNTS[tier] + 1)
        if number not in excluded
    )
    ordered = sorted(candidates, key=_stable_key)
    return tuple(sorted(item.number for item in ordered[:count]))


def benchmark_splits() -> dict[str, dict[Tier, tuple[int, ...]]]:
    regression: dict[Tier, tuple[int, ...]] = {}
    comparison: dict[Tier, tuple[int, ...]] = {}
    regression_quota: dict[Tier, int] = {"M": 24, "H": 12, "X": 12}

    for tier in ("M", "H", "X"):
        required = set(CANARY[tier])
        fill = stable_sample(
            tier,
            regression_quota[tier] - len(required),
            excluded=frozenset(required),
        )
        regression[tier] = tuple(sorted(required | set(fill)))
        comparison[tier] = stable_sample(
            tier,
            30,
            excluded=frozenset(regression[tier]),
        )

    return {
        "compile-canary-12": {tier: tuple(sorted(CANARY[tier])) for tier in CANARY},
        "agent-smoke-8": {tier: tuple(sorted(SMOKE[tier])) for tier in SMOKE},
        "regression-48": regression,
        "model-compare-90": comparison,
    }


def load_fate_json(path: Path, tier: Tier) -> tuple[FateProblem, ...]:
    """Load FATE's structured JSON and reject version or statement drift."""

    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("FATE JSON root must be a list")
    problems: list[FateProblem] = []
    seen: set[int] = set()
    for entry in raw:
        if not isinstance(entry, dict):
            raise ValueError("FATE entries must be objects")
        number = entry.get("id")
        if not isinstance(number, int) or number in seen:
            raise ValueError("FATE IDs must be unique integers")
        seen.add(number)
        version = entry.get("version")
        if version != "v4.28.0":
            raise ValueError(f"unexpected FATE version: {version!r}")
        source = entry.get("source")
        if source != f"FATE-{tier}":
            raise ValueError(f"unexpected FATE source: {source!r}")
        informal = entry.get("informal_statement")
        formal = entry.get("formal_statement")
        if not isinstance(informal, str) or not informal.strip():
            raise ValueError("informal statement is missing")
        if not isinstance(formal, str) or formal.count("sorry") != 1:
            raise ValueError("formal statement must contain exactly one proof hole")
        declarations = entry.get("declarations", ())
        if not isinstance(declarations, (list, tuple)):
            raise ValueError("declarations must be a list when present")
        problems.append(
            FateProblem(
                problem_id=FateProblemId(tier, number),
                informal_statement=informal,
                formal_statement=formal,
                version=version,
                declarations=tuple(str(item) for item in declarations),
            )
        )
    return tuple(sorted(problems, key=lambda problem: problem.problem_id.number))


def split_manifest() -> dict[str, object]:
    return {
        "schema_version": "autolean.fate-splits.v1",
        "seed": SPLIT_SEED,
        "suites": benchmark_splits(),
        "report_tiers_separately": True,
        "contains_solutions": False,
    }
