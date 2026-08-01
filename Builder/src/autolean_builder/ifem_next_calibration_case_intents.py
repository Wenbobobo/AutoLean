"""Project unknown-only iFEM risk routes into un-authored calibration intents.

The queue is deliberately narrower than a calibration case.  It contains no
source material, Lean surface, catalogue entry, model exchange, private state,
or graph/bundle payload.  It only gives a stable identifier and conservative
authoring order to each of the already-unknown iFEM nodes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from collections.abc import Sequence
from enum import StrEnum
from pathlib import Path
from typing import Final, Literal, Never, Self, cast

from autolean_contracts.base import ContractModel
from autolean_contracts.hashing import StableIdentifierV1, canonical_json_bytes, stable_identifier
from pydantic import Field, model_validator

from .ifem_calibration_risk_routing import (
    DEFAULT_D35_REPORT_PATH,
    IFEMCalibrationPriorityV1,
    IFEMCalibrationRiskRoutingError,
    IFEMCalibrationRiskRoutingV1,
    IFEMRequiredNextCalibrationV1,
    build_ifem_calibration_risk_routing_from_paths,
)

ROOT = Path(__file__).resolve().parents[3]
CASE_INTENT_SCHEMA: Final[Literal["autolean.ifem-next-calibration-case-intents.v1"]] = (
    "autolean.ifem-next-calibration-case-intents.v1"
)
CASE_INTENT_PROTOCOL: Final[Literal["autolean.builder-ifem-next-calibration-case-intents.v1"]] = (
    "autolean.builder-ifem-next-calibration-case-intents.v1"
)
CASE_INTENT_KIND: Final[Literal["unknown_only_next_calibration_case_intent_queue"]] = (
    "unknown_only_next_calibration_case_intent_queue"
)
CASE_INTENT_NAMESPACE: Final[Literal["ifem-next-calibration-case-intent"]] = (
    "ifem-next-calibration-case-intent"
)
CASE_INTENT_LANE: Final[Literal["ifem-unknown-only-next-calibration"]] = (
    "ifem-unknown-only-next-calibration"
)
DEFAULT_GRAPH_PATH = (
    ROOT / "Builder" / "pilots" / "discovery" / "ifem-candidate-dependency-graph.v1.json"
)
DEFAULT_CENSUS_PLAN_PATH = (
    ROOT / "Builder" / "pilots" / "discovery" / "ifem-coercive-prerequisite-census-plan.v1.json"
)
DEFAULT_CENSUS_RESULT_PATH = (
    ROOT / "docs" / "research" / "ifem-prerequisite-census-not-run-2026-07-31-graph-chain.json"
)
DEFAULT_PROFILE_SUMMARY_PATH = (
    ROOT / "docs" / "research" / "ifem-pinned-mathlib-profile-public-summary-2026-07-31.json"
)
DEFAULT_STRUCTURAL_CORPUS_PATH = (
    ROOT / "Builder" / "pilots" / "discovery" / "ifem-structural-role-probe-corpus.v1.json"
)
DEFAULT_READINESS_DECISION_PATH = (
    ROOT
    / "docs"
    / "research"
    / "ifem-pilot-readiness-decision-2026-07-31-graph-chain-successor.json"
)
_SHA256 = r"^[0-9a-f]{64}$"
_PRIORITY_RANK: Final[dict[IFEMCalibrationPriorityV1, int]] = {
    IFEMCalibrationPriorityV1.P0_INCORRECT: 0,
    IFEMCalibrationPriorityV1.P1_INVALID: 1,
    IFEMCalibrationPriorityV1.P2_INDEPENDENT_MACHINE_REVIEW: 2,
    IFEMCalibrationPriorityV1.P3_CREATE_CALIBRATION_CASE: 3,
}
_REQUIRED_ACTION_BY_PRIORITY: Final[
    dict[IFEMCalibrationPriorityV1, IFEMRequiredNextCalibrationV1]
] = {
    IFEMCalibrationPriorityV1.P0_INCORRECT: (
        IFEMRequiredNextCalibrationV1.DETERMINISTIC_OR_HIGHER_CAPABILITY_CALIBRATION
    ),
    IFEMCalibrationPriorityV1.P1_INVALID: (
        IFEMRequiredNextCalibrationV1.DETERMINISTIC_OR_HIGHER_CAPABILITY_CALIBRATION
    ),
    IFEMCalibrationPriorityV1.P2_INDEPENDENT_MACHINE_REVIEW: (
        IFEMRequiredNextCalibrationV1.INDEPENDENT_MACHINE_REVIEW
    ),
    IFEMCalibrationPriorityV1.P3_CREATE_CALIBRATION_CASE: (
        IFEMRequiredNextCalibrationV1.CREATE_CALIBRATION_CASE
    ),
}
_FORBIDDEN_RENDERED_FIELDS: Final[tuple[bytes, ...]] = (
    b'"candidate_declarations"',
    b'"catalog_case"',
    b'"canonical_type"',
    b'"declaration"',
    b'"expected_answer"',
    b'"formal_graph"',
    b'"lean_import"',
    b'"lean_statement"',
    b'"lean_type"',
    b'"mutation"',
    b'"oracle"',
    b'"private_cas"',
    b'"prompt"',
    b'"provider"',
    b'"raw_output"',
    b'"request"',
    b'"rights_text"',
    b'"source_path"',
    b'"source_span"',
    b'"source_text"',
    b'"statement_contract"',
    b'"execution_graph"',
    b'"bundle"',
)


class IFEMNextCalibrationCaseIntentError(ValueError):
    """A source-free, unknown-only intent queue crossed its closed boundary."""


class IFEMCalibrationCaseMaterializationStateV1(StrEnum):
    """The queue may request no case content; every V1 intent stays un-authored."""

    NOT_AUTHORED = "not_authored"


class IFEMNextCalibrationCaseIntentAuthorityV1(ContractModel):
    """Every authority relevant to this metadata-only projection is withheld."""

    schema_version: Literal["autolean.ifem-next-calibration-case-intent-authority.v1"] = (
        "autolean.ifem-next-calibration-case-intent-authority.v1"
    )
    semantic_authority: Literal[False] = False
    case_authoring_authority: Literal[False] = False
    materialization_authority: Literal[False] = False
    freeze_authority: Literal[False] = False
    prover_handoff_authority: Literal[False] = False
    promotion_authority: Literal[False] = False


class IFEMNextCalibrationCaseIntentEvidenceV1(ContractModel):
    """Digest-only binding to the already-replayable risk-routing artifact."""

    risk_routing_content_sha256: str = Field(pattern=_SHA256)


class IFEMNextCalibrationCaseIntentV1(ContractModel):
    """One stable, content-free instruction to keep a node in a later queue."""

    intent_id: StableIdentifierV1
    intent_lane: Literal["ifem-unknown-only-next-calibration"] = CASE_INTENT_LANE
    node_id: str = Field(pattern=r"^ifem-[a-z0-9-]+$")
    source_order: int = Field(ge=1)
    semantic_classification: Literal["unknown"] = "unknown"
    calibration_priority: IFEMCalibrationPriorityV1
    required_next_calibration: IFEMRequiredNextCalibrationV1
    structural_risk_discovery_required: bool
    materialization_state: IFEMCalibrationCaseMaterializationStateV1 = (
        IFEMCalibrationCaseMaterializationStateV1.NOT_AUTHORED
    )

    @model_validator(mode="after")
    def validate_intent(self) -> Self:
        expected_id = stable_identifier(
            CASE_INTENT_NAMESPACE,
            f"{CASE_INTENT_LANE}:{self.node_id}",
        )
        if self.intent_id != expected_id:
            raise ValueError("intent id must bind the fixed lane and node id")
        if (
            self.required_next_calibration
            is not _REQUIRED_ACTION_BY_PRIORITY[self.calibration_priority]
        ):
            raise ValueError("intent action does not match its calibration priority")
        if self.structural_risk_discovery_required is not (
            self.calibration_priority is IFEMCalibrationPriorityV1.P3_CREATE_CALIBRATION_CASE
        ):
            raise ValueError("only P3 intents may require structural risk discovery")
        return self


class IFEMNextCalibrationCaseIntentsV1(ContractModel):
    """Canonical queue of un-authored, source-free iFEM calibration intents."""

    schema_version: Literal["autolean.ifem-next-calibration-case-intents.v1"] = CASE_INTENT_SCHEMA
    protocol: Literal["autolean.builder-ifem-next-calibration-case-intents.v1"] = (
        CASE_INTENT_PROTOCOL
    )
    artifact_kind: Literal["unknown_only_next_calibration_case_intent_queue"] = CASE_INTENT_KIND
    intent_lane: Literal["ifem-unknown-only-next-calibration"] = CASE_INTENT_LANE
    denominator_node_count: Literal[21] = 21
    evidence: IFEMNextCalibrationCaseIntentEvidenceV1
    intents: tuple[IFEMNextCalibrationCaseIntentV1, ...] = Field(min_length=21, max_length=21)
    source_free: Literal[True] = True
    formalization_payload_present: Literal[False] = False
    model_payload_present: Literal[False] = False
    private_state_present: Literal[False] = False
    authority: IFEMNextCalibrationCaseIntentAuthorityV1 = Field(
        default_factory=IFEMNextCalibrationCaseIntentAuthorityV1
    )
    builder_freeze: Literal["forbidden"] = "forbidden"
    prover_handoff: Literal["forbidden"] = "forbidden"
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_queue(self) -> Self:
        expected_order = tuple(
            sorted(
                self.intents,
                key=lambda intent: (
                    _PRIORITY_RANK[intent.calibration_priority],
                    intent.source_order,
                ),
            )
        )
        if self.intents != expected_order:
            raise ValueError("intents must be ordered by priority and then source order")
        if len({intent.node_id for intent in self.intents}) != self.denominator_node_count:
            raise ValueError("intents must have unique node identifiers")
        if len({intent.intent_id.value for intent in self.intents}) != self.denominator_node_count:
            raise ValueError("intents must have unique stable identifiers")
        if any(intent.semantic_classification != "unknown" for intent in self.intents):
            raise ValueError("case intents cannot classify unknown-only nodes")
        if any(intent.materialization_state != "not_authored" for intent in self.intents):
            raise ValueError("case intents cannot contain authored materialization")
        if self.authority != IFEMNextCalibrationCaseIntentAuthorityV1():
            raise ValueError("case intent authority flags drifted")
        if self.content_sha256 != self.computed_content_sha256():
            raise ValueError("case intent content hash does not match its payload")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(dict[str, object], self.model_dump(mode="json", exclude={"content_sha256"}))

    def computed_content_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.content_payload())).hexdigest()

    def assert_not_authoritative(self) -> Never:
        raise IFEMNextCalibrationCaseIntentError(
            "iFEM next calibration case intents cannot author calibration material, "
            "freeze a statement, or hand work to Prover"
        )

    def freeze_statement(self) -> Never:
        self.assert_not_authoritative()

    def handoff_to_prover(self) -> Never:
        self.assert_not_authoritative()


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise IFEMNextCalibrationCaseIntentError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _is_link_or_reparse(path: Path, metadata: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return (
        stat.S_ISLNK(metadata.st_mode)
        or bool(getattr(metadata, "st_file_attributes", 0) & reparse_flag)
        or path.is_symlink()
    )


def _physical_parent_identities(path: Path) -> tuple[tuple[int, int], ...]:
    identities: list[tuple[int, int]] = []
    for parent in path.parents:
        metadata = parent.stat(follow_symlinks=False)
        if _is_link_or_reparse(parent, metadata) or not stat.S_ISDIR(metadata.st_mode):
            raise IFEMNextCalibrationCaseIntentError(
                "case intent path parent chain must contain only physical directories"
            )
        identities.append((metadata.st_dev, metadata.st_ino))
    return tuple(identities)


def _read_regular_file(path: Path, *, label: str) -> tuple[bytes, str]:
    if not isinstance(path, Path):
        raise IFEMNextCalibrationCaseIntentError(f"{label} path must be a Path")
    try:
        parents_before = _physical_parent_identities(path)
        before = path.lstat()
        if _is_link_or_reparse(path, before) or not stat.S_ISREG(before.st_mode):
            raise IFEMNextCalibrationCaseIntentError(f"{label} must be an unlinked regular file")
        raw = path.read_bytes()
        after = path.lstat()
        parents_after = _physical_parent_identities(path)
    except OSError as error:
        raise IFEMNextCalibrationCaseIntentError(f"cannot read {label}: {path}") from error
    if (
        _is_link_or_reparse(path, after)
        or not stat.S_ISREG(after.st_mode)
        or (before.st_dev, before.st_ino, before.st_size)
        != (after.st_dev, after.st_ino, after.st_size)
        or parents_before != parents_after
    ):
        raise IFEMNextCalibrationCaseIntentError(f"{label} changed while loading")
    return raw, hashlib.sha256(raw).hexdigest()


def build_ifem_next_calibration_case_intents_from_routing(
    routing: IFEMCalibrationRiskRoutingV1,
) -> IFEMNextCalibrationCaseIntentsV1:
    """Project one exact unknown-only risk route without exposing its internal facts."""

    if type(routing) is not IFEMCalibrationRiskRoutingV1:
        raise IFEMNextCalibrationCaseIntentError("case intents require the exact risk routing type")
    try:
        verified_routing = IFEMCalibrationRiskRoutingV1.model_validate(
            routing.model_dump(mode="json")
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise IFEMNextCalibrationCaseIntentError(
            "case intent input risk routing failed revalidation"
        ) from error

    intents = tuple(
        sorted(
            (
                IFEMNextCalibrationCaseIntentV1(
                    intent_id=stable_identifier(
                        CASE_INTENT_NAMESPACE,
                        f"{CASE_INTENT_LANE}:{node.node_id}",
                    ),
                    node_id=node.node_id,
                    source_order=node.source_order,
                    semantic_classification="unknown",
                    calibration_priority=node.calibration_priority,
                    required_next_calibration=node.required_next_calibration,
                    structural_risk_discovery_required=(
                        node.calibration_priority
                        is IFEMCalibrationPriorityV1.P3_CREATE_CALIBRATION_CASE
                    ),
                    materialization_state=IFEMCalibrationCaseMaterializationStateV1.NOT_AUTHORED,
                )
                for node in verified_routing.nodes
            ),
            key=lambda intent: (
                _PRIORITY_RANK[intent.calibration_priority],
                intent.source_order,
            ),
        )
    )
    payload: dict[str, object] = {
        "schema_version": CASE_INTENT_SCHEMA,
        "protocol": CASE_INTENT_PROTOCOL,
        "artifact_kind": CASE_INTENT_KIND,
        "intent_lane": CASE_INTENT_LANE,
        "denominator_node_count": 21,
        "evidence": IFEMNextCalibrationCaseIntentEvidenceV1(
            risk_routing_content_sha256=verified_routing.content_sha256
        ).model_dump(mode="json"),
        "intents": [intent.model_dump(mode="json") for intent in intents],
        "source_free": True,
        "formalization_payload_present": False,
        "model_payload_present": False,
        "private_state_present": False,
        "authority": IFEMNextCalibrationCaseIntentAuthorityV1().model_dump(mode="json"),
        "builder_freeze": "forbidden",
        "prover_handoff": "forbidden",
    }
    payload["content_sha256"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    try:
        return IFEMNextCalibrationCaseIntentsV1.model_validate(payload)
    except ValueError as error:
        raise IFEMNextCalibrationCaseIntentError(
            "generated case intent queue is invalid"
        ) from error


def build_ifem_next_calibration_case_intents_from_paths(
    *,
    d35_report_path: Path = DEFAULT_D35_REPORT_PATH,
    graph_path: Path = DEFAULT_GRAPH_PATH,
    census_plan_path: Path = DEFAULT_CENSUS_PLAN_PATH,
    census_result_path: Path = DEFAULT_CENSUS_RESULT_PATH,
    profile_summary_path: Path = DEFAULT_PROFILE_SUMMARY_PATH,
    structural_corpus_path: Path = DEFAULT_STRUCTURAL_CORPUS_PATH,
    readiness_decision_path: Path = DEFAULT_READINESS_DECISION_PATH,
) -> IFEMNextCalibrationCaseIntentsV1:
    """Replay public inputs through the risk router, then project only queue metadata."""

    try:
        routing = build_ifem_calibration_risk_routing_from_paths(
            d35_report_path=d35_report_path,
            graph_path=graph_path,
            census_plan_path=census_plan_path,
            census_result_path=census_result_path,
            profile_summary_path=profile_summary_path,
            structural_corpus_path=structural_corpus_path,
            readiness_decision_path=readiness_decision_path,
        )
    except IFEMCalibrationRiskRoutingError as error:
        raise IFEMNextCalibrationCaseIntentError(
            "cannot rebuild the exact unknown-only risk routing input"
        ) from error
    return build_ifem_next_calibration_case_intents_from_routing(routing)


def verify_ifem_next_calibration_case_intents_against_paths(
    intents: IFEMNextCalibrationCaseIntentsV1,
    **paths: Path,
) -> None:
    """Require one queue to equal a fresh strict replay of all public inputs."""

    if type(intents) is not IFEMNextCalibrationCaseIntentsV1:
        raise IFEMNextCalibrationCaseIntentError("case intents must use their exact typed model")
    try:
        actual = IFEMNextCalibrationCaseIntentsV1.model_validate(intents.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as error:
        raise IFEMNextCalibrationCaseIntentError(
            "case intent queue failed self-revalidation"
        ) from error
    expected = build_ifem_next_calibration_case_intents_from_paths(**paths)
    if actual != expected:
        raise IFEMNextCalibrationCaseIntentError(
            "case intent queue differs from exact input replay"
        )


def load_ifem_next_calibration_case_intents(path: Path) -> IFEMNextCalibrationCaseIntentsV1:
    """Load a canonical output; callers need exact replay to establish provenance."""

    raw, _file_sha256 = _read_regular_file(path, label="next calibration case intents")
    try:
        payload = json.loads(
            raw.decode("utf-8", errors="strict"), object_pairs_hook=_reject_duplicate_keys
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IFEMNextCalibrationCaseIntentError(
            "next calibration case intents are not strict UTF-8 JSON"
        ) from error
    if not isinstance(payload, dict):
        raise IFEMNextCalibrationCaseIntentError(
            "next calibration case intents must be a JSON object"
        )
    try:
        intents = IFEMNextCalibrationCaseIntentsV1.model_validate(payload)
    except ValueError as error:
        raise IFEMNextCalibrationCaseIntentError(
            "next calibration case intents are invalid"
        ) from error
    if render_ifem_next_calibration_case_intents(intents) != raw:
        raise IFEMNextCalibrationCaseIntentError(
            "next calibration case intents are not canonically rendered"
        )
    return intents


def render_ifem_next_calibration_case_intents(
    intents: IFEMNextCalibrationCaseIntentsV1,
) -> bytes:
    if type(intents) is not IFEMNextCalibrationCaseIntentsV1:
        raise IFEMNextCalibrationCaseIntentError("case intents must use their exact typed model")
    try:
        verified = IFEMNextCalibrationCaseIntentsV1.model_validate(intents.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as error:
        raise IFEMNextCalibrationCaseIntentError(
            "case intent queue failed self-revalidation"
        ) from error
    rendered = canonical_json_bytes(verified.model_dump(mode="json")) + b"\n"
    if any(field in rendered for field in _FORBIDDEN_RENDERED_FIELDS):
        raise IFEMNextCalibrationCaseIntentError(
            "case intent queue rendering leaked a forbidden field"
        )
    return rendered


def _write_once(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError:
        existing, _file_sha256 = _read_regular_file(path, label="existing case intent output")
        if existing != content:
            raise IFEMNextCalibrationCaseIntentError(
                "case intent output already exists with different bytes"
            ) from None


def materialize_ifem_next_calibration_case_intents_from_paths_once(
    output_path: Path,
    **paths: Path,
) -> IFEMNextCalibrationCaseIntentsV1:
    """Build and write one content-addressed queue without replacing any output."""

    intents = build_ifem_next_calibration_case_intents_from_paths(**paths)
    _write_once(output_path, render_ifem_next_calibration_case_intents(intents))
    return intents


def parse_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--d35-report", type=Path, default=DEFAULT_D35_REPORT_PATH)
    parser.add_argument("--graph", type=Path, default=DEFAULT_GRAPH_PATH)
    parser.add_argument("--census-plan", type=Path, default=DEFAULT_CENSUS_PLAN_PATH)
    parser.add_argument("--census-result", type=Path, default=DEFAULT_CENSUS_RESULT_PATH)
    parser.add_argument("--profile-summary", type=Path, default=DEFAULT_PROFILE_SUMMARY_PATH)
    parser.add_argument("--structural-corpus", type=Path, default=DEFAULT_STRUCTURAL_CORPUS_PATH)
    parser.add_argument("--readiness-decision", type=Path, default=DEFAULT_READINESS_DECISION_PATH)
    parser.add_argument("--out", type=Path, required=True)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    namespace = parse_arguments(arguments)
    intents = materialize_ifem_next_calibration_case_intents_from_paths_once(
        namespace.out,
        d35_report_path=namespace.d35_report,
        graph_path=namespace.graph,
        census_plan_path=namespace.census_plan,
        census_result_path=namespace.census_result,
        profile_summary_path=namespace.profile_summary,
        structural_corpus_path=namespace.structural_corpus,
        readiness_decision_path=namespace.readiness_decision,
    )
    print(intents.content_sha256)
    return 0


__all__ = [
    "CASE_INTENT_KIND",
    "CASE_INTENT_LANE",
    "CASE_INTENT_NAMESPACE",
    "CASE_INTENT_PROTOCOL",
    "CASE_INTENT_SCHEMA",
    "IFEMCalibrationCaseMaterializationStateV1",
    "IFEMNextCalibrationCaseIntentAuthorityV1",
    "IFEMNextCalibrationCaseIntentError",
    "IFEMNextCalibrationCaseIntentEvidenceV1",
    "IFEMNextCalibrationCaseIntentV1",
    "IFEMNextCalibrationCaseIntentsV1",
    "build_ifem_next_calibration_case_intents_from_paths",
    "build_ifem_next_calibration_case_intents_from_routing",
    "load_ifem_next_calibration_case_intents",
    "main",
    "materialize_ifem_next_calibration_case_intents_from_paths_once",
    "render_ifem_next_calibration_case_intents",
    "verify_ifem_next_calibration_case_intents_against_paths",
]
