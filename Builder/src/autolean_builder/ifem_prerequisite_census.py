"""Content-addressed iFEM prerequisite census planning and query protocol.

This module is Builder discovery infrastructure.  Its Lean runner observes
declaration metadata in the pinned ``Library/`` environment; it never turns a
name hit into a mathematical mapping, freezes a statement, or hands work to
Prover.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from collections.abc import Sequence
from enum import StrEnum
from pathlib import Path
from typing import Literal, cast

from autolean_contracts import canonical_json_bytes
from autolean_contracts.base import ContractModel
from pydantic import Field, model_validator

from .discovery_manifest import DiscoveryManifestError, load_discovery_lane_manifest

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_PLAN_PATH = (
    ROOT / "Builder" / "pilots" / "discovery" / "ifem-coercive-prerequisite-census-plan.v1.json"
)
DEFAULT_LANE_MANIFEST_PATH = (
    ROOT / "Builder" / "pilots" / "discovery" / "phase-2-active-lanes.v1.json"
)
DEFAULT_LIBRARY_ROOT = ROOT / "Library"

PLAN_SCHEMA = "autolean.ifem-prerequisite-census-plan.v1"
OBSERVATION_SCHEMA = "autolean.ifem-prerequisite-query-observation.v1"
RESULT_SCHEMA = "autolean.ifem-prerequisite-census-result.v1"
PROTOCOL = "autolean.builder-ifem-prerequisite-census.v1"
LANE_ID = "ifem-coercive-galerkin"

_ID = r"^[a-z][a-z0-9-]{2,95}$"
_SHA256 = r"^[0-9a-f]{64}$"
_REVISION = r"^[0-9a-f]{40}$"
_DECLARATION = re.compile(r"^[A-Za-z_][A-Za-z0-9_'.]*(?:\.[A-Za-z_][A-Za-z0-9_']*)*$")
_MODULE = re.compile(r"^[A-Z][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")


class IFEMPrerequisiteCensusError(ValueError):
    """The query plan, pinned environment, or evidence record drifted."""


class IFEMPrerequisiteClassificationV1(StrEnum):
    DIRECT = "direct"
    THIN_ADAPTER = "thin_adapter"
    MISSING = "missing"
    UNKNOWN = "unknown"


class IFEMQueryExecutionStateV1(StrEnum):
    NOT_RUN = "not_run"
    COMPLETED = "completed"


class IFEMDenominatorBindingV1(ContractModel):
    lane_id: Literal["ifem-coercive-galerkin"] = "ifem-coercive-galerkin"
    denominator_id: str = Field(pattern=_ID)
    denominator_revision: str = Field(min_length=1)
    denominator_content_sha256: str = Field(pattern=_SHA256)
    frozen_node_count: int = Field(ge=1)
    prerequisite_node_count: int = Field(ge=1)
    source_manifest: Literal["Builder/pilots/discovery/phase-2-active-lanes.v1.json"] = (
        "Builder/pilots/discovery/phase-2-active-lanes.v1.json"
    )


class IFEMEnvironmentBindingV1(ContractModel):
    library_root: Literal["Library"] = "Library"
    lean_toolchain: str = Field(min_length=1)
    mathlib_revision: str = Field(pattern=_REVISION)
    lake_manifest_sha256: str = Field(pattern=_SHA256)
    direct_imports: tuple[str, ...] = Field(min_length=1)
    lean_argv: tuple[str, ...] = (
        "lake",
        "env",
        "lean",
        "--run",
        "<generated-query.lean>",
    )

    @model_validator(mode="after")
    def validate_environment_binding(self) -> IFEMEnvironmentBindingV1:
        if self.direct_imports != tuple(sorted(set(self.direct_imports))):
            raise ValueError("direct imports must be sorted and unique")
        if any(_MODULE.fullmatch(module) is None for module in self.direct_imports):
            raise ValueError("direct import contains an invalid Lean module name")
        if self.lean_argv != (
            "lake",
            "env",
            "lean",
            "--run",
            "<generated-query.lean>",
        ):
            raise ValueError("Lean query argv drifted from the bounded runner")
        return self


class IFEMGraphBoundaryV1(ContractModel):
    mathematical_graph: Literal["frozen_prerequisite_denominator_only"] = (
        "frozen_prerequisite_denominator_only"
    )
    formal_graph: Literal["candidate_declarations_unclassified"] = (
        "candidate_declarations_unclassified"
    )
    execution_graph: Literal["pinned_library_declaration_observation"] = (
        "pinned_library_declaration_observation"
    )
    builder_freeze: Literal["forbidden"] = "forbidden"
    prover_handoff: Literal["forbidden"] = "forbidden"
    coverage_claim: Literal["forbidden_without_reviewed_result"] = (
        "forbidden_without_reviewed_result"
    )


class IFEMClassificationPolicyV1(ContractModel):
    classifications: tuple[IFEMPrerequisiteClassificationV1, ...]
    default_classification: Literal[IFEMPrerequisiteClassificationV1.UNKNOWN] = (
        IFEMPrerequisiteClassificationV1.UNKNOWN
    )
    direct_requires: tuple[str, ...]
    thin_adapter_requires: tuple[str, ...]
    missing_requires: tuple[str, ...]
    unknown_requires: tuple[str, ...]

    @model_validator(mode="after")
    def validate_policy(self) -> IFEMClassificationPolicyV1:
        if self.classifications != tuple(IFEMPrerequisiteClassificationV1):
            raise ValueError("classification vocabulary or order drifted")
        expected = {
            "direct_requires": (
                "canonical_type_sha256s",
                "mapped_declaration",
                "query_observation_sha256",
                "semantic_review_sha256",
            ),
            "thin_adapter_requires": (
                "adapter_compile_receipt_sha256",
                "adapter_source_sha256",
                "canonical_type_sha256s",
                "mapped_declaration",
                "query_observation_sha256",
                "semantic_review_sha256",
            ),
            "missing_requires": (
                "declaration_inventory_sha256",
                "negative_query_observation_sha256",
                "semantic_review_sha256",
            ),
            "unknown_requires": ("explicit_unknown_reason",),
        }
        for field, required in expected.items():
            if getattr(self, field) != required:
                raise ValueError(f"{field} drifted from the explicit-evidence policy")
        return self


class IFEMNodeQueryPlanV1(ContractModel):
    node_id: str = Field(pattern=_ID)
    probe_kind: Literal["environment_declaration_lookup"] = "environment_declaration_lookup"
    candidate_declarations: tuple[str, ...] = Field(min_length=1)
    source_hints: tuple[str, ...] = Field(min_length=1)
    initial_classification: Literal[IFEMPrerequisiteClassificationV1.UNKNOWN] = (
        IFEMPrerequisiteClassificationV1.UNKNOWN
    )
    classification_authority: Literal["post_query_builder_semantic_review"] = (
        "post_query_builder_semantic_review"
    )

    @model_validator(mode="after")
    def validate_query(self) -> IFEMNodeQueryPlanV1:
        if self.candidate_declarations != tuple(sorted(set(self.candidate_declarations))):
            raise ValueError("candidate declarations must be sorted and unique")
        if any(_DECLARATION.fullmatch(name) is None for name in self.candidate_declarations):
            raise ValueError("query contains an invalid Lean declaration name")
        if self.source_hints != tuple(sorted(set(self.source_hints))):
            raise ValueError("source hints must be sorted and unique")
        return self


class IFEMPrerequisiteCensusPlanV1(ContractModel):
    schema_version: Literal["autolean.ifem-prerequisite-census-plan.v1"] = (
        "autolean.ifem-prerequisite-census-plan.v1"
    )
    protocol: Literal["autolean.builder-ifem-prerequisite-census.v1"] = (
        "autolean.builder-ifem-prerequisite-census.v1"
    )
    state: Literal[IFEMQueryExecutionStateV1.NOT_RUN] = IFEMQueryExecutionStateV1.NOT_RUN
    denominator: IFEMDenominatorBindingV1
    environment: IFEMEnvironmentBindingV1
    graph_boundary: IFEMGraphBoundaryV1
    classification_policy: IFEMClassificationPolicyV1
    queries: tuple[IFEMNodeQueryPlanV1, ...] = Field(min_length=1)
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_plan(self) -> IFEMPrerequisiteCensusPlanV1:
        node_ids = tuple(query.node_id for query in self.queries)
        if len(node_ids) != len(set(node_ids)):
            raise ValueError("query node IDs must be unique")
        if len(node_ids) != self.denominator.prerequisite_node_count:
            raise ValueError("query count differs from the prerequisite denominator")
        if self.content_sha256 != self.computed_content_sha256():
            raise ValueError("iFEM census plan content hash does not match its payload")
        return self

    def content_payload(self) -> dict[str, object]:
        payload = self.model_dump(mode="json", exclude={"content_sha256"})
        return cast(dict[str, object], payload)

    def computed_content_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.content_payload())).hexdigest()


class IFEMDeclarationObservationV1(ContractModel):
    declaration: str = Field(min_length=1)
    present: bool
    declaration_kind: str | None = Field(default=None, min_length=1)
    canonical_type: str | None = Field(default=None, min_length=1)
    canonical_type_sha256: str | None = Field(default=None, pattern=_SHA256)
    observed_axioms: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_observation(self) -> IFEMDeclarationObservationV1:
        if _DECLARATION.fullmatch(self.declaration) is None:
            raise ValueError("observation contains an invalid declaration name")
        if self.observed_axioms != tuple(sorted(set(self.observed_axioms))):
            raise ValueError("observed axioms must be sorted and unique")
        if self.present:
            if self.declaration_kind is None or self.canonical_type is None:
                raise ValueError("present declaration lacks kind or canonical type")
            expected = hashlib.sha256(self.canonical_type.encode("utf-8")).hexdigest()
            if self.canonical_type_sha256 != expected:
                raise ValueError("canonical type hash does not match the observed type")
        elif (
            any(
                value is not None
                for value in (
                    self.declaration_kind,
                    self.canonical_type,
                    self.canonical_type_sha256,
                )
            )
            or self.observed_axioms
        ):
            raise ValueError("absent declaration carries fabricated metadata")
        return self


class IFEMNodeQueryObservationV1(ContractModel):
    node_id: str = Field(pattern=_ID)
    candidates: tuple[IFEMDeclarationObservationV1, ...] = Field(min_length=1)


class IFEMQueryObservationV1(ContractModel):
    schema_version: Literal["autolean.ifem-prerequisite-query-observation.v1"] = (
        "autolean.ifem-prerequisite-query-observation.v1"
    )
    protocol: Literal["autolean.builder-ifem-prerequisite-census.v1"] = (
        "autolean.builder-ifem-prerequisite-census.v1"
    )
    plan_content_sha256: str = Field(pattern=_SHA256)
    query_source_sha256: str = Field(pattern=_SHA256)
    lean_toolchain: str = Field(min_length=1)
    mathlib_revision: str = Field(pattern=_REVISION)
    lake_manifest_sha256: str = Field(pattern=_SHA256)
    direct_imports: tuple[str, ...] = Field(min_length=1)
    nodes: tuple[IFEMNodeQueryObservationV1, ...] = Field(min_length=1)
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_content_hash(self) -> IFEMQueryObservationV1:
        if self.content_sha256 != self.computed_content_sha256():
            raise ValueError("query observation content hash does not match its payload")
        return self

    def content_payload(self) -> dict[str, object]:
        payload = self.model_dump(mode="json", exclude={"content_sha256"})
        return cast(dict[str, object], payload)

    def computed_content_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.content_payload())).hexdigest()


class IFEMNodeClassificationEvidenceV1(ContractModel):
    classification: IFEMPrerequisiteClassificationV1
    mapped_declarations: tuple[str, ...] = ()
    canonical_type_sha256s: tuple[str, ...] = ()
    query_observation_sha256: str | None = Field(default=None, pattern=_SHA256)
    negative_query_observation_sha256: str | None = Field(default=None, pattern=_SHA256)
    adapter_source_sha256: str | None = Field(default=None, pattern=_SHA256)
    adapter_compile_receipt_sha256: str | None = Field(default=None, pattern=_SHA256)
    declaration_inventory_sha256: str | None = Field(default=None, pattern=_SHA256)
    semantic_review_sha256: str | None = Field(default=None, pattern=_SHA256)
    explicit_unknown_reason: str | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def validate_explicit_evidence(self) -> IFEMNodeClassificationEvidenceV1:
        if self.mapped_declarations != tuple(sorted(set(self.mapped_declarations))):
            raise ValueError("mapped declarations must be sorted and unique")
        if any(_DECLARATION.fullmatch(name) is None for name in self.mapped_declarations):
            raise ValueError("classification contains an invalid mapped declaration")
        if any(re.fullmatch(_SHA256, digest) is None for digest in self.canonical_type_sha256s):
            raise ValueError("classification contains an invalid canonical type hash")
        common = (
            self.query_observation_sha256,
            self.negative_query_observation_sha256,
            self.adapter_source_sha256,
            self.adapter_compile_receipt_sha256,
            self.declaration_inventory_sha256,
            self.semantic_review_sha256,
        )
        if self.classification is IFEMPrerequisiteClassificationV1.UNKNOWN:
            if (
                self.mapped_declarations
                or self.canonical_type_sha256s
                or any(value is not None for value in common)
            ):
                raise ValueError("unknown classification must not carry mapping evidence")
            if self.explicit_unknown_reason is None:
                raise ValueError("unknown classification needs an explicit reason")
        elif self.classification is IFEMPrerequisiteClassificationV1.DIRECT:
            if (
                not self.mapped_declarations
                or len(self.canonical_type_sha256s) != len(self.mapped_declarations)
                or self.query_observation_sha256 is None
                or self.semantic_review_sha256 is None
                or any(
                    value is not None
                    for value in (
                        self.adapter_source_sha256,
                        self.adapter_compile_receipt_sha256,
                        self.declaration_inventory_sha256,
                        self.negative_query_observation_sha256,
                        self.explicit_unknown_reason,
                    )
                )
            ):
                raise ValueError("direct classification lacks exact query and semantic evidence")
        elif self.classification is IFEMPrerequisiteClassificationV1.THIN_ADAPTER:
            if (
                not self.mapped_declarations
                or len(self.canonical_type_sha256s) != len(self.mapped_declarations)
                or self.query_observation_sha256 is None
                or self.adapter_source_sha256 is None
                or self.adapter_compile_receipt_sha256 is None
                or self.semantic_review_sha256 is None
                or self.declaration_inventory_sha256 is not None
                or self.negative_query_observation_sha256 is not None
                or self.explicit_unknown_reason is not None
            ):
                raise ValueError("thin adapter classification lacks compiled adapter evidence")
        elif (
            self.mapped_declarations
            or self.canonical_type_sha256s
            or self.query_observation_sha256 is not None
            or self.negative_query_observation_sha256 is None
            or self.declaration_inventory_sha256 is None
            or self.semantic_review_sha256 is None
            or any(
                value is not None
                for value in (
                    self.adapter_source_sha256,
                    self.adapter_compile_receipt_sha256,
                    self.explicit_unknown_reason,
                )
            )
        ):
            raise ValueError("missing classification lacks negative inventory and review evidence")
        return self


class IFEMNodeCensusResultV1(ContractModel):
    node_id: str = Field(pattern=_ID)
    evidence: IFEMNodeClassificationEvidenceV1


class IFEMPrerequisiteCensusResultV1(ContractModel):
    schema_version: Literal["autolean.ifem-prerequisite-census-result.v1"] = (
        "autolean.ifem-prerequisite-census-result.v1"
    )
    protocol: Literal["autolean.builder-ifem-prerequisite-census.v1"] = (
        "autolean.builder-ifem-prerequisite-census.v1"
    )
    execution_state: IFEMQueryExecutionStateV1
    plan_content_sha256: str = Field(pattern=_SHA256)
    denominator: IFEMDenominatorBindingV1
    environment: IFEMEnvironmentBindingV1
    query_source_sha256: str | None = Field(default=None, pattern=_SHA256)
    query_observation_sha256: str | None = Field(default=None, pattern=_SHA256)
    node_results: tuple[IFEMNodeCensusResultV1, ...] = Field(min_length=1)
    resume_command: tuple[str, ...] = Field(min_length=1)
    builder_freeze: Literal["forbidden"] = "forbidden"
    prover_handoff: Literal["forbidden"] = "forbidden"
    coverage_claim: Literal["not_authorized"] = "not_authorized"
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_result(self) -> IFEMPrerequisiteCensusResultV1:
        node_ids = tuple(result.node_id for result in self.node_results)
        if len(node_ids) != len(set(node_ids)):
            raise ValueError("census result node IDs must be unique")
        if len(node_ids) != self.denominator.prerequisite_node_count:
            raise ValueError("census result count differs from the denominator")
        if self.execution_state is IFEMQueryExecutionStateV1.NOT_RUN:
            if self.query_source_sha256 is not None or self.query_observation_sha256 is not None:
                raise ValueError("not-run result must not claim query artifacts")
            if any(
                result.evidence.classification is not IFEMPrerequisiteClassificationV1.UNKNOWN
                for result in self.node_results
            ):
                raise ValueError("not-run result may classify nodes only as unknown")
        elif self.query_source_sha256 is None or self.query_observation_sha256 is None:
            raise ValueError("completed query result lacks content-addressed execution evidence")
        if self.content_sha256 != self.computed_content_sha256():
            raise ValueError("census result content hash does not match its payload")
        return self

    def content_payload(self) -> dict[str, object]:
        payload = self.model_dump(mode="json", exclude={"content_sha256"})
        return cast(dict[str, object], payload)

    def computed_content_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.content_payload())).hexdigest()


def validate_result_against_plan(
    result: IFEMPrerequisiteCensusResultV1,
    plan: IFEMPrerequisiteCensusPlanV1,
) -> None:
    if (
        result.plan_content_sha256 != plan.content_sha256
        or result.denominator != plan.denominator
        or result.environment != plan.environment
        or tuple(item.node_id for item in result.node_results)
        != tuple(query.node_id for query in plan.queries)
    ):
        raise IFEMPrerequisiteCensusError("census result does not bind its query plan")
    for query, item in zip(plan.queries, result.node_results, strict=True):
        evidence = item.evidence
        if evidence.classification in {
            IFEMPrerequisiteClassificationV1.DIRECT,
            IFEMPrerequisiteClassificationV1.THIN_ADAPTER,
        }:
            if not set(evidence.mapped_declarations) <= set(query.candidate_declarations):
                raise IFEMPrerequisiteCensusError(
                    "reviewed mapping uses a declaration outside the content-addressed query plan"
                )
            if evidence.query_observation_sha256 != result.query_observation_sha256:
                raise IFEMPrerequisiteCensusError(
                    "reviewed mapping does not bind the result's Lean observation"
                )


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise IFEMPrerequisiteCensusError(f"duplicate JSON key: {key}")
        document[key] = value
    return document


def _read_json(path: Path, *, label: str) -> tuple[dict[str, object], bytes]:
    try:
        raw = path.read_bytes()
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IFEMPrerequisiteCensusError(f"cannot read {label}: {path}") from error
    if not isinstance(payload, dict):
        raise IFEMPrerequisiteCensusError(f"{label} must be a JSON object")
    return cast(dict[str, object], payload), raw


def load_ifem_prerequisite_census_plan(path: Path) -> IFEMPrerequisiteCensusPlanV1:
    payload, _ = _read_json(path, label="iFEM prerequisite census plan")
    try:
        return IFEMPrerequisiteCensusPlanV1.model_validate(payload)
    except ValueError as error:
        raise IFEMPrerequisiteCensusError(f"iFEM census plan is invalid: {error}") from error


def validate_plan_bindings(
    plan: IFEMPrerequisiteCensusPlanV1,
    *,
    lane_manifest_path: Path = DEFAULT_LANE_MANIFEST_PATH,
    library_root: Path = DEFAULT_LIBRARY_ROOT,
) -> None:
    try:
        lane_manifest = load_discovery_lane_manifest(lane_manifest_path)
    except DiscoveryManifestError as error:
        raise IFEMPrerequisiteCensusError("cannot validate the discovery lane manifest") from error
    lane = next((item for item in lane_manifest.lanes if item.lane_id == LANE_ID), None)
    if lane is None or lane.prerequisite_denominator is None or lane.precompile_census_plan is None:
        raise IFEMPrerequisiteCensusError("the iFEM lane lacks its frozen census denominator")
    denominator = lane.prerequisite_denominator
    binding = plan.denominator
    included_ids = tuple(
        node.node_id for node in denominator.nodes if node.included_in_prerequisite_denominator
    )
    if (
        binding.denominator_id != denominator.denominator_id
        or binding.denominator_revision != denominator.revision
        or binding.denominator_content_sha256 != denominator.content_sha256
        or binding.frozen_node_count != len(denominator.nodes)
        or binding.prerequisite_node_count != len(included_ids)
        or tuple(query.node_id for query in plan.queries) != included_ids
    ):
        raise IFEMPrerequisiteCensusError(
            "census plan does not bind the current frozen iFEM prerequisite denominator"
        )
    if plan.environment.mathlib_revision != lane.precompile_census_plan.mathlib_revision:
        raise IFEMPrerequisiteCensusError("census plan and discovery lane pin different mathlib")

    toolchain_path = library_root / "lean-toolchain"
    manifest_path = library_root / "lake-manifest.json"
    try:
        toolchain = toolchain_path.read_text(encoding="utf-8").strip()
    except OSError as error:
        raise IFEMPrerequisiteCensusError("cannot read the pinned Lean toolchain") from error
    lake_manifest, lake_bytes = _read_json(manifest_path, label="Library lake manifest")
    packages = lake_manifest.get("packages")
    if not isinstance(packages, list):
        raise IFEMPrerequisiteCensusError("Library lake manifest has no package list")
    mathlib_entries = [
        item for item in packages if isinstance(item, dict) and item.get("name") == "mathlib"
    ]
    if len(mathlib_entries) != 1:
        raise IFEMPrerequisiteCensusError("Library lake manifest has no unique mathlib input")
    mathlib_revision = mathlib_entries[0].get("rev")
    if (
        toolchain != plan.environment.lean_toolchain
        or mathlib_revision != plan.environment.mathlib_revision
        or hashlib.sha256(lake_bytes).hexdigest() != plan.environment.lake_manifest_sha256
    ):
        raise IFEMPrerequisiteCensusError("Library environment differs from the census plan")


def _require_real_directory(path: Path, *, label: str) -> None:
    try:
        path.lstat()
    except OSError as error:
        raise IFEMPrerequisiteCensusError(f"{label} is missing") from error
    if path.is_symlink() or not path.is_dir():
        raise IFEMPrerequisiteCensusError(f"{label} must be a real directory")


def _require_real_file(path: Path, *, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise IFEMPrerequisiteCensusError(f"{label} is missing") from error
    if path.is_symlink() or not path.is_file() or metadata.st_size <= 0:
        raise IFEMPrerequisiteCensusError(f"{label} must be a real non-empty file")


def _git_probe_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    environment["GIT_TERMINAL_PROMPT"] = "0"
    return environment


def _host_query_environment() -> dict[str, str]:
    """Disable Git-backed dependency network access in the diagnostic host runner."""

    environment = _git_probe_environment()
    environment.update(
        {
            "GIT_CONFIG_COUNT": "2",
            "GIT_CONFIG_KEY_0": "url.file:///__autolean_network_disabled__/.insteadOf",
            "GIT_CONFIG_VALUE_0": "https://",
            "GIT_CONFIG_KEY_1": "protocol.file.allow",
            "GIT_CONFIG_VALUE_1": "never",
        }
    )
    return environment


def validate_local_library_dependencies(
    plan: IFEMPrerequisiteCensusPlanV1,
    *,
    library_root: Path = DEFAULT_LIBRARY_ROOT,
) -> None:
    """Fail before Lake when a locked local Git package is absent or incomplete.

    ``lake env`` may otherwise populate ``.lake/packages`` from the network.  The
    host runner is diagnostic only, but it still must not turn an observation
    command into an implicit dependency installer.
    """

    manifest, _ = _read_json(library_root / "lake-manifest.json", label="Library lake manifest")
    packages = manifest.get("packages")
    if not isinstance(packages, list) or not packages:
        raise IFEMPrerequisiteCensusError("Library lake manifest has no package list")
    packages_root = library_root / ".lake" / "packages"
    _require_real_directory(packages_root, label="Library local package directory")
    seen: set[str] = set()
    mathlib_root: Path | None = None
    for index, raw_package in enumerate(packages):
        if not isinstance(raw_package, dict):
            raise IFEMPrerequisiteCensusError("Library package record is not an object")
        name = raw_package.get("name")
        revision = raw_package.get("rev")
        config_file = raw_package.get("configFile")
        manifest_file = raw_package.get("manifestFile")
        if (
            raw_package.get("type") != "git"
            or not isinstance(name, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}", name) is None
            or name.casefold() in seen
            or not isinstance(revision, str)
            or re.fullmatch(_REVISION, revision) is None
            or not isinstance(config_file, str)
            or Path(config_file).name != config_file
            or not isinstance(manifest_file, str)
            or Path(manifest_file).name != manifest_file
        ):
            raise IFEMPrerequisiteCensusError(
                f"Library package record {index} is not a bounded Git dependency"
            )
        seen.add(name.casefold())
        package_root = packages_root / name
        _require_real_directory(package_root, label=f"Library package {name}")
        _require_real_directory(package_root / ".git", label=f"Library package {name} Git metadata")
        _require_real_file(package_root / config_file, label=f"Library package {name} config")
        _require_real_file(package_root / manifest_file, label=f"Library package {name} manifest")
        try:
            completed = subprocess.run(
                ("git", "-C", str(package_root), "rev-parse", "--verify", "HEAD^{commit}"),
                check=False,
                capture_output=True,
                text=True,
                encoding="ascii",
                errors="strict",
                stdin=subprocess.DEVNULL,
                timeout=15,
                env=_git_probe_environment(),
            )
        except (OSError, subprocess.SubprocessError, UnicodeError) as error:
            raise IFEMPrerequisiteCensusError(
                f"cannot verify Library package {name} revision"
            ) from error
        if completed.returncode != 0 or completed.stdout.strip() != revision:
            raise IFEMPrerequisiteCensusError(
                f"Library package {name} does not match its locked revision"
            )
        if name == "mathlib":
            mathlib_root = package_root
    if mathlib_root is None:
        raise IFEMPrerequisiteCensusError("Library local packages omit mathlib")
    for module in plan.environment.direct_imports:
        source = mathlib_root.joinpath(*module.split(".")).with_suffix(".lean")
        _require_real_file(source, label=f"Mathlib direct import {module}")


def _lean_string(value: str) -> str:
    if not value.isascii() or any(character in value for character in ("\x00", "\n", "\r")):
        raise IFEMPrerequisiteCensusError("Lean query strings must be single-line ASCII")
    return json.dumps(value, ensure_ascii=True)


def render_lean_query(plan: IFEMPrerequisiteCensusPlanV1) -> str:
    """Render the exact environment-lookup program without assigning coverage classes."""

    imports = "\n".join(f"import {module}" for module in plan.environment.direct_imports)
    module_records = ", ".join(
        f"{{ module := `{module} }}" for module in plan.environment.direct_imports
    )
    query_records = ",\n  ".join(
        "("
        + _lean_string(query.node_id)
        + ", ["
        + ", ".join(_lean_string(name) for name in query.candidate_declarations)
        + "])"
        for query in plan.queries
    )
    direct_import_json = ", ".join(
        f"Json.str {_lean_string(module)}" for module in plan.environment.direct_imports
    )
    return f"""{imports}
import Lean.PrettyPrinter
import Lean.Util.CollectAxioms

open Lean

private def canonicalOptions : Options :=
  ((((({{}} : Options).setBool `pp.all true).setBool `pp.explicit true).setBool
        `pp.universes true).setBool `pp.notation false).set `pp.width (1000000 : Nat)

private def declarationKind (info : ConstantInfo) : String :=
  match info with
  | .axiomInfo _ => "axiom"
  | .defnInfo _ => "definition"
  | .thmInfo _ => "theorem"
  | .opaqueInfo _ => "opaque"
  | .quotInfo _ => "quotient"
  | .inductInfo _ => "inductive"
  | .ctorInfo _ => "constructor"
  | .recInfo _ => "recursor"

private def canonicalType (env : Environment) (info : ConstantInfo) : IO String := do
  if info.type.hasMVar then
    throw <| IO.userError "canonical declaration type contains a metavariable"
  let rendered :=
    (← PrettyPrinter.ppExprLegacy env {{}} {{}} canonicalOptions info.type).pretty 1000000
  if rendered.isEmpty || rendered.length > 1000000 then
    throw <| IO.userError "canonical declaration type has an invalid size"
  if rendered.any fun char => char == '\\x00' || char == '\\n' || char == '\\r' then
    throw <| IO.userError "canonical declaration type is not one line"
  return rendered

private def observedAxioms (env : Environment) (declaration : Name) : IO (Array Name) := do
  let context : Core.Context := {{
    fileName := "<AutoLeanIFEMPrerequisiteQuery>"
    fileMap := default
    options := canonicalOptions
  }}
  let state : Core.State := {{ env := env }}
  let axioms ← Core.CoreM.toIO' (collectAxioms declaration) context state
  return axioms.qsort fun left right => left.toString < right.toString

private def declarationRecord (env : Environment) (declarationText : String) : IO Json := do
  let declaration := declarationText.toName
  match env.checked.get.find? declaration with
  | none =>
      return Json.mkObj [
        ("canonical_type", Json.null),
        ("declaration", Json.str declarationText),
        ("declaration_kind", Json.null),
        ("observed_axioms", Json.arr #[]),
        ("present", Json.bool false)
      ]
  | some info =>
      let rendered ← canonicalType env info
      let axioms ← observedAxioms env declaration
      return Json.mkObj [
        ("canonical_type", Json.str rendered),
        ("declaration", Json.str declarationText),
        ("declaration_kind", Json.str (declarationKind info)),
        ("observed_axioms", Json.arr <| axioms.map fun name => Json.str name.toString),
        ("present", Json.bool true)
      ]

private def queries : List (String \u00d7 List String) := [
  {query_records}
]

private def nodeRecord (env : Environment) (query : String \u00d7 List String) : IO Json := do
  let candidates ← query.2.toArray.mapM (declarationRecord env)
  return Json.mkObj [
    ("candidates", Json.arr candidates),
    ("node_id", Json.str query.1)
  ]

private def executeQuery : IO Json := do
  let environment ← importModules #[{module_records}] canonicalOptions
  let nodes ← queries.toArray.mapM (nodeRecord environment)
  return Json.mkObj [
    ("direct_imports", Json.arr #[{direct_import_json}]),
    ("lake_manifest_sha256", Json.str {_lean_string(plan.environment.lake_manifest_sha256)}),
    ("lean_toolchain", Json.str {_lean_string(plan.environment.lean_toolchain)}),
    ("mathlib_revision", Json.str {_lean_string(plan.environment.mathlib_revision)}),
    ("nodes", Json.arr nodes),
    ("plan_content_sha256", Json.str {_lean_string(plan.content_sha256)}),
    ("protocol", Json.str {_lean_string(PROTOCOL)}),
    ("schema_version", Json.str "autolean.ifem-prerequisite-query-raw.v1"),
    ("type_format", Json.str "autolean.lean-pp-expr.v1")
  ]

def main (_arguments : List String) : IO UInt32 := do
  try
    IO.println (← executeQuery).compress
    return (0 : UInt32)
  catch error =>
    IO.eprintln s!"autolean-ifem-prerequisite-query: {{error}}"
    return (2 : UInt32)
"""


def _raw_string_list(value: object, *, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise IFEMPrerequisiteCensusError(f"raw query {label} must be a string list")
    return tuple(cast(list[str], value))


def normalize_query_observation(
    raw: str,
    *,
    plan: IFEMPrerequisiteCensusPlanV1,
    query_source_sha256: str,
) -> IFEMQueryObservationV1:
    try:
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as error:
        raise IFEMPrerequisiteCensusError("Lean query did not emit valid JSON") from error
    if not isinstance(payload, dict) or set(payload) != {
        "direct_imports",
        "lake_manifest_sha256",
        "lean_toolchain",
        "mathlib_revision",
        "nodes",
        "plan_content_sha256",
        "protocol",
        "schema_version",
        "type_format",
    }:
        raise IFEMPrerequisiteCensusError("Lean query record has unexpected fields")
    if (
        payload.get("schema_version") != "autolean.ifem-prerequisite-query-raw.v1"
        or payload.get("protocol") != PROTOCOL
        or payload.get("type_format") != "autolean.lean-pp-expr.v1"
        or payload.get("plan_content_sha256") != plan.content_sha256
        or payload.get("lean_toolchain") != plan.environment.lean_toolchain
        or payload.get("mathlib_revision") != plan.environment.mathlib_revision
        or payload.get("lake_manifest_sha256") != plan.environment.lake_manifest_sha256
        or _raw_string_list(payload.get("direct_imports"), label="direct imports")
        != plan.environment.direct_imports
    ):
        raise IFEMPrerequisiteCensusError("Lean query record differs from the pinned plan")

    raw_nodes = payload.get("nodes")
    if not isinstance(raw_nodes, list) or len(raw_nodes) != len(plan.queries):
        raise IFEMPrerequisiteCensusError("Lean query node count differs from the plan")
    normalized_nodes: list[dict[str, object]] = []
    for query, raw_node in zip(plan.queries, raw_nodes, strict=True):
        if not isinstance(raw_node, dict) or set(raw_node) != {"candidates", "node_id"}:
            raise IFEMPrerequisiteCensusError("Lean query node record is invalid")
        if raw_node.get("node_id") != query.node_id:
            raise IFEMPrerequisiteCensusError("Lean query node order differs from the plan")
        raw_candidates = raw_node.get("candidates")
        if not isinstance(raw_candidates, list) or len(raw_candidates) != len(
            query.candidate_declarations
        ):
            raise IFEMPrerequisiteCensusError("Lean query candidate count differs from the plan")
        normalized_candidates: list[dict[str, object]] = []
        for expected_name, candidate in zip(
            query.candidate_declarations, raw_candidates, strict=True
        ):
            if not isinstance(candidate, dict) or set(candidate) != {
                "canonical_type",
                "declaration",
                "declaration_kind",
                "observed_axioms",
                "present",
            }:
                raise IFEMPrerequisiteCensusError("Lean declaration observation is invalid")
            if candidate.get("declaration") != expected_name or not isinstance(
                candidate.get("present"), bool
            ):
                raise IFEMPrerequisiteCensusError("Lean declaration observation changed identity")
            present = cast(bool, candidate["present"])
            canonical_type = candidate.get("canonical_type")
            declaration_kind = candidate.get("declaration_kind")
            axioms = _raw_string_list(candidate.get("observed_axioms"), label="observed axioms")
            if axioms != tuple(sorted(set(axioms))):
                raise IFEMPrerequisiteCensusError("Lean observed axioms are not sorted and unique")
            if present:
                if (
                    not isinstance(canonical_type, str)
                    or not canonical_type
                    or not isinstance(declaration_kind, str)
                ):
                    raise IFEMPrerequisiteCensusError("present declaration lacks exact metadata")
                type_sha256 = hashlib.sha256(canonical_type.encode("utf-8")).hexdigest()
            else:
                if canonical_type is not None or declaration_kind is not None or axioms:
                    raise IFEMPrerequisiteCensusError("absent declaration carries metadata")
                type_sha256 = None
            normalized_candidates.append(
                {
                    "canonical_type": canonical_type,
                    "canonical_type_sha256": type_sha256,
                    "declaration": expected_name,
                    "declaration_kind": declaration_kind,
                    "observed_axioms": list(axioms),
                    "present": present,
                }
            )
        normalized_nodes.append({"candidates": normalized_candidates, "node_id": query.node_id})
    normalized: dict[str, object] = {
        "direct_imports": list(plan.environment.direct_imports),
        "lake_manifest_sha256": plan.environment.lake_manifest_sha256,
        "lean_toolchain": plan.environment.lean_toolchain,
        "mathlib_revision": plan.environment.mathlib_revision,
        "nodes": normalized_nodes,
        "plan_content_sha256": plan.content_sha256,
        "protocol": PROTOCOL,
        "query_source_sha256": query_source_sha256,
        "schema_version": OBSERVATION_SCHEMA,
    }
    normalized["content_sha256"] = hashlib.sha256(canonical_json_bytes(normalized)).hexdigest()
    return IFEMQueryObservationV1.model_validate(normalized)


def _resume_command(plan_path: Path) -> tuple[str, ...]:
    try:
        relative_plan = plan_path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError as error:
        raise IFEMPrerequisiteCensusError("plan path must remain inside the repository") from error
    return (
        "uv",
        "run",
        "--frozen",
        "python",
        "scripts/ifem_prerequisite_census.py",
        "--plan",
        relative_plan,
        "run",
        "--out",
        "<result-json>",
        "--observation-out",
        "<observation-json>",
    )


def _unknown_evidence_payload(reason: str) -> dict[str, object]:
    return {
        "adapter_compile_receipt_sha256": None,
        "adapter_source_sha256": None,
        "canonical_type_sha256s": [],
        "classification": "unknown",
        "declaration_inventory_sha256": None,
        "explicit_unknown_reason": reason,
        "mapped_declarations": [],
        "negative_query_observation_sha256": None,
        "query_observation_sha256": None,
        "semantic_review_sha256": None,
    }


def not_run_result(
    plan: IFEMPrerequisiteCensusPlanV1,
    *,
    plan_path: Path,
    reason: str,
) -> IFEMPrerequisiteCensusResultV1:
    if reason not in {
        "host_query_timeout",
        "operator_not_run",
        "pinned_runtime_unavailable",
        "wsl_unavailable",
    }:
        raise IFEMPrerequisiteCensusError("unsupported not-run reason")
    node_results = [
        {
            "evidence": _unknown_evidence_payload(reason),
            "node_id": query.node_id,
        }
        for query in plan.queries
    ]
    payload: dict[str, object] = {
        "builder_freeze": "forbidden",
        "coverage_claim": "not_authorized",
        "denominator": plan.denominator.model_dump(mode="json"),
        "environment": plan.environment.model_dump(mode="json"),
        "execution_state": "not_run",
        "node_results": node_results,
        "plan_content_sha256": plan.content_sha256,
        "protocol": PROTOCOL,
        "prover_handoff": "forbidden",
        "query_observation_sha256": None,
        "query_source_sha256": None,
        "resume_command": list(_resume_command(plan_path)),
        "schema_version": RESULT_SCHEMA,
    }
    payload["content_sha256"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    result = IFEMPrerequisiteCensusResultV1.model_validate(payload)
    validate_result_against_plan(result, plan)
    return result


def completed_unreviewed_result(
    plan: IFEMPrerequisiteCensusPlanV1,
    observation: IFEMQueryObservationV1,
    *,
    plan_path: Path,
) -> IFEMPrerequisiteCensusResultV1:
    node_results = [
        {
            "evidence": _unknown_evidence_payload("builder_semantic_review_not_recorded"),
            "node_id": query.node_id,
        }
        for query in plan.queries
    ]
    payload: dict[str, object] = {
        "builder_freeze": "forbidden",
        "coverage_claim": "not_authorized",
        "denominator": plan.denominator.model_dump(mode="json"),
        "environment": plan.environment.model_dump(mode="json"),
        "execution_state": "completed",
        "node_results": node_results,
        "plan_content_sha256": plan.content_sha256,
        "protocol": PROTOCOL,
        "prover_handoff": "forbidden",
        "query_observation_sha256": observation.content_sha256,
        "query_source_sha256": observation.query_source_sha256,
        "resume_command": list(_resume_command(plan_path)),
        "schema_version": RESULT_SCHEMA,
    }
    payload["content_sha256"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    result = IFEMPrerequisiteCensusResultV1.model_validate(payload)
    validate_result_against_plan(result, plan)
    return result


def _write_once(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError:
        try:
            if path.read_bytes() != content:
                raise IFEMPrerequisiteCensusError("output already exists with different bytes")
        except OSError as error:
            raise IFEMPrerequisiteCensusError("cannot inspect existing output") from error


def write_model_once(path: Path, model: ContractModel) -> None:
    _write_once(path, canonical_json_bytes(model) + b"\n")


def run_query(
    plan: IFEMPrerequisiteCensusPlanV1,
    *,
    plan_path: Path,
    lane_manifest_path: Path,
    library_root: Path,
) -> tuple[IFEMQueryObservationV1, IFEMPrerequisiteCensusResultV1]:
    """Run the bounded diagnostic query in a POSIX checkout with the pinned Lake lock."""

    validate_plan_bindings(plan, lane_manifest_path=lane_manifest_path, library_root=library_root)
    if os.name != "posix":
        raise IFEMPrerequisiteCensusError(
            "the pinned query must run from the repository's POSIX/WSL Library environment"
        )
    validate_local_library_dependencies(plan, library_root=library_root)
    source = render_lean_query(plan)
    source_bytes = source.encode("utf-8")
    source_sha256 = hashlib.sha256(source_bytes).hexdigest()
    with tempfile.TemporaryDirectory(
        prefix=".autolean-ifem-prerequisite-query-",
        dir=library_root,
    ) as raw_root:
        query_path = Path(raw_root) / "IFEMPrerequisiteQuery.lean"
        query_path.write_bytes(source_bytes)
        command = ["lake", "env", "lean", "--run", str(query_path)]
        try:
            completed = subprocess.run(
                command,
                cwd=library_root,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="strict",
                timeout=600,
                env=_host_query_environment(),
            )
        except (OSError, subprocess.SubprocessError, UnicodeError) as error:
            raise IFEMPrerequisiteCensusError("pinned Lean query execution failed") from error
    if completed.returncode != 0:
        diagnostic = completed.stderr[:4096].replace("\x00", "")
        raise IFEMPrerequisiteCensusError(
            f"pinned Lean query returned {completed.returncode}: {diagnostic}"
        )
    stdout_lines = completed.stdout.splitlines()
    if len(stdout_lines) != 1 or completed.stderr:
        raise IFEMPrerequisiteCensusError("pinned Lean query output was not one clean JSON line")
    observation = normalize_query_observation(
        stdout_lines[0], plan=plan, query_source_sha256=source_sha256
    )
    return observation, completed_unreviewed_result(plan, observation, plan_path=plan_path)


def parse_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN_PATH)
    parser.add_argument("--lane-manifest", type=Path, default=DEFAULT_LANE_MANIFEST_PATH)
    parser.add_argument("--library-root", type=Path, default=DEFAULT_LIBRARY_ROOT)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("check-plan", help="validate plan, denominator, and Library pins")
    render = subparsers.add_parser("render-query", help="render the exact Lean query source")
    render.add_argument("--out", type=Path, required=True)
    not_run = subparsers.add_parser("not-run", help="record an honest all-unknown result")
    not_run.add_argument("--out", type=Path, required=True)
    not_run.add_argument(
        "--reason",
        choices=(
            "host_query_timeout",
            "operator_not_run",
            "pinned_runtime_unavailable",
            "wsl_unavailable",
        ),
        required=True,
    )
    run = subparsers.add_parser("run", help="execute the query without classifying mappings")
    run.add_argument("--out", type=Path, required=True)
    run.add_argument("--observation-out", type=Path, required=True)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    namespace = parse_arguments(arguments)
    plan_path = namespace.plan.resolve()
    lane_manifest_path = namespace.lane_manifest.resolve()
    library_root = namespace.library_root.resolve()
    plan = load_ifem_prerequisite_census_plan(plan_path)
    validate_plan_bindings(plan, lane_manifest_path=lane_manifest_path, library_root=library_root)
    if namespace.command == "check-plan":
        print(plan.content_sha256)
        return 0
    if namespace.command == "render-query":
        _write_once(namespace.out, render_lean_query(plan).encode("utf-8"))
        return 0
    if namespace.command == "not-run":
        result = not_run_result(plan, plan_path=plan_path, reason=namespace.reason)
        write_model_once(namespace.out, result)
        return 0
    if namespace.command == "run":
        observation, result = run_query(
            plan,
            plan_path=plan_path,
            lane_manifest_path=lane_manifest_path,
            library_root=library_root,
        )
        write_model_once(namespace.observation_out, observation)
        write_model_once(namespace.out, result)
        return 0
    raise IFEMPrerequisiteCensusError("unsupported iFEM census command")


if __name__ == "__main__":
    raise SystemExit(main())
