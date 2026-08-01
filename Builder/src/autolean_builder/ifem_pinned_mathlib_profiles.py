"""Pinned singleton-import observations for the iFEM prerequisite denominator.

This is deliberately a fixed-profile execution lane separate from
``ifem_prerequisite_census``.  It determines which declarations are visible
under each fixed one-module *direct* import and records the complete loaded
module closure plus Lean metadata.  A singleton direct import does not imply a
small transitive closure.  The observer does not infer a mathematical mapping,
classify a prerequisite, accept closure breadth, freeze a Builder contract, or
hand work to Prover.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from enum import StrEnum
from pathlib import Path
from typing import Final, Literal, cast

from autolean_contracts import canonical_json_bytes
from autolean_contracts.base import ContractModel
from pydantic import Field, model_validator

from .ifem_prerequisite_census import (
    DEFAULT_PLAN_PATH as DEFAULT_CENSUS_PLAN_PATH,
)
from .ifem_prerequisite_census import (
    IFEMDenominatorBindingV1,
    IFEMPrerequisiteCensusPlanV1,
    load_ifem_prerequisite_census_plan,
    validate_plan_bindings,
)

ROOT = Path(__file__).resolve().parents[3]
WORKER_ROOT = ROOT / "Prover" / "worker"
DEFAULT_PLAN_PATH = (
    ROOT / "Builder" / "pilots" / "discovery" / "ifem-pinned-mathlib-profile-plan.v1.json"
)

PLAN_SCHEMA: Final = "autolean.ifem-pinned-mathlib-profile-plan.v1"
RAW_OBSERVATION_SCHEMA: Final = "autolean.ifem-pinned-profile-query-raw.v1"
OBSERVATION_SCHEMA: Final = "autolean.ifem-pinned-mathlib-profile-observation.v1"
MULTI_OBSERVATION_SCHEMA: Final = "autolean.ifem-pinned-mathlib-profile-observations.v1"
RESULT_SCHEMA: Final = "autolean.ifem-pinned-mathlib-profile-result.v1"
PUBLIC_SUMMARY_SCHEMA: Final = "autolean.ifem-pinned-mathlib-profile-public-summary.v1"
PROTOCOL: Final = "autolean.ifem-pinned-profile-query.v1"

PARENT_IMAGE: Final = (
    "autolean/mathlib-worker@sha256:"
    "3237192cf627a05367c75d46e61ec9034fefe43a4fd0c06139e38c80358648d6"
)
CHILD_IMAGE_REPOSITORY: Final = "autolean/ifem-pinned-profile-query"
CHILD_IMAGE_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

_SHA256 = r"^[0-9a-f]{64}$"
_REVISION = r"^[0-9a-f]{40}$"
_DECLARATION = re.compile(r"^[A-Za-z_][A-Za-z0-9_'.]*(?:\.[A-Za-z_][A-Za-z0-9_']*)*$")
_MODULE = re.compile(r"^[A-Z][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")

NEGATIVE_CONTROL: Final = "AutoLean.IFEM.PinnedProfileQuery.NegativeControl"
_CENSUS_PLAN_PATH: Final = "Builder/pilots/discovery/ifem-coercive-prerequisite-census-plan.v1.json"
_DOCKERFILE_PATH: Final = "Prover/worker/Dockerfile.ifem-pinned-profile-query"
_HELPER_PATH: Final = "Prover/worker/AutoleanIFEMPinnedProfileQuery.lean"
_WRAPPER_PATH: Final = "Prover/worker/autolean-ifem-pinned-profile-query"
_BUILT_OLEAN_MANIFEST_PATH: Final = (
    "/opt/autolean/attestations/ifem-pinned-profile-built-oleans.sha256"
)
_BUILT_OLEAN_PATHS: tuple[str, ...] = (
    "/opt/mathlib/.lake/build/lib/lean/AutoLean/AutoleanIFEMPinnedProfileQuery.olean",
    "/opt/mathlib/.lake/build/lib/lean/Mathlib/Analysis/InnerProductSpace/Defs.olean",
    "/opt/mathlib/.lake/build/lib/lean/Mathlib/Analysis/InnerProductSpace/Dual.olean",
    "/opt/mathlib/.lake/build/lib/lean/Mathlib/Analysis/InnerProductSpace/LaxMilgram.olean",
    "/opt/mathlib/.lake/build/lib/lean/Mathlib/Analysis/Normed/Operator/Basic.olean",
    "/opt/mathlib/.lake/build/lib/lean/Mathlib/Analysis/Normed/Operator/Bilinear.olean",
)

_PROFILE_IMPORTS: tuple[tuple[str, str], ...] = (
    ("ifem-singleton-defs", "Mathlib.Analysis.InnerProductSpace.Defs"),
    ("ifem-singleton-dual", "Mathlib.Analysis.InnerProductSpace.Dual"),
    ("ifem-singleton-lax-milgram", "Mathlib.Analysis.InnerProductSpace.LaxMilgram"),
    ("ifem-singleton-operator-basic", "Mathlib.Analysis.Normed.Operator.Basic"),
    ("ifem-singleton-operator-bilinear", "Mathlib.Analysis.Normed.Operator.Bilinear"),
)
_PROFILE_DIRECT_IMPORTS: Final = tuple(
    (profile_id, (direct_import,)) for profile_id, direct_import in _PROFILE_IMPORTS
)
_BUILD_CONTEXT_FILES: tuple[str, ...] = (
    "Dockerfile.ifem-pinned-profile-query",
    "AutoleanIFEMPinnedProfileQuery.lean",
    "autolean-ifem-pinned-profile-query",
)
_RUN_MEMORY_LIMIT = "2g"
_RUN_PIDS_LIMIT = 128
_RUN_TMPFS = "/tmp:rw,noexec,nosuid,nodev,size=64m"
_PUBLIC_SUMMARY_REPLAY_COMMAND: tuple[str, ...] = (
    "uv",
    "run",
    "--frozen",
    "python",
    "scripts/ifem_pinned_mathlib_profiles.py",
    "--plan",
    "<plan-json>",
    "public-summary",
    "--receipt",
    "<receipt-json>",
    "--observation",
    "<observation-json>",
    "--result",
    "<result-json>",
    "--out",
    "<public-summary-json>",
)


class IFEMPinnedProfileError(ValueError):
    """A singleton-profile plan or its observation drifted from the frozen boundary."""


class IFEMPinnedMathlibProfileExecutionStateV1(StrEnum):
    NOT_RUN = "not_run"
    COMPLETED = "completed"


# Retained for imports created while this isolated profile protocol was being introduced.
IFEMPinnedProfileExecutionStateV1 = IFEMPinnedMathlibProfileExecutionStateV1


class IFEMPinnedProfileAuthorityV1(ContractModel):
    """This observation lane has no Builder or Prover authority."""

    mathematical_mapping_authorized: Literal[False] = False
    semantic_classification_authorized: Literal[False] = False
    coverage_claim_authorized: Literal[False] = False
    builder_freeze_authorized: Literal[False] = False
    prover_handoff_authorized: Literal[False] = False
    proof_submission_authorized: Literal[False] = False


class IFEMPinnedProfileAssetBindingV1(ContractModel):
    dockerfile_path: Literal["Prover/worker/Dockerfile.ifem-pinned-profile-query"] = (
        _DOCKERFILE_PATH
    )
    dockerfile_sha256: str = Field(pattern=_SHA256)
    helper_path: Literal["Prover/worker/AutoleanIFEMPinnedProfileQuery.lean"] = _HELPER_PATH
    helper_sha256: str = Field(pattern=_SHA256)
    wrapper_path: Literal["Prover/worker/autolean-ifem-pinned-profile-query"] = _WRAPPER_PATH
    wrapper_sha256: str = Field(pattern=_SHA256)
    built_olean_manifest_path: Literal[
        "/opt/autolean/attestations/ifem-pinned-profile-built-oleans.sha256"
    ] = _BUILT_OLEAN_MANIFEST_PATH


class IFEMPinnedProfileEnvironmentV1(ContractModel):
    lean_toolchain: str = Field(min_length=1)
    mathlib_revision: str = Field(pattern=_REVISION)
    lake_manifest_sha256: str = Field(pattern=_SHA256)
    parent_image: Literal[
        "autolean/mathlib-worker@sha256:3237192cf627a05367c75d46e61ec9034fefe43a4fd0c06139e38c80358648d6"
    ] = PARENT_IMAGE


class IFEMPinnedProfileV1(ContractModel):
    profile_id: str = Field(pattern=r"^ifem-singleton-[a-z-]+$")
    direct_import: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_profile(self) -> IFEMPinnedProfileV1:
        if _MODULE.fullmatch(self.direct_import) is None:
            raise ValueError("profile direct import is not a valid Lean module")
        if self.direct_import == "Mathlib":
            raise ValueError("aggregate import Mathlib is forbidden")
        return self


class IFEMPinnedProfileObservationContractV1(ContractModel):
    """The exact environment facts a singleton query must record, not interpret."""

    declaration_origin: Literal["required_if_present"] = "required_if_present"
    canonical_type: Literal["required_if_present"] = "required_if_present"
    observed_axioms: Literal["required_if_present"] = "required_if_present"
    loaded_module_closure: Literal["required"] = "required"
    negative_control: Literal["required_and_must_be_absent"] = "required_and_must_be_absent"


class IFEMPinnedMathlibProfilePlanV1(ContractModel):
    schema_version: Literal["autolean.ifem-pinned-mathlib-profile-plan.v1"] = PLAN_SCHEMA
    protocol: Literal["autolean.ifem-pinned-profile-query.v1"] = PROTOCOL
    state: Literal[IFEMPinnedProfileExecutionStateV1.NOT_RUN] = (
        IFEMPinnedProfileExecutionStateV1.NOT_RUN
    )
    census_plan_path: Literal[
        "Builder/pilots/discovery/ifem-coercive-prerequisite-census-plan.v1.json"
    ] = _CENSUS_PLAN_PATH
    census_plan_content_sha256: str = Field(pattern=_SHA256)
    denominator: IFEMDenominatorBindingV1
    environment: IFEMPinnedProfileEnvironmentV1
    assets: IFEMPinnedProfileAssetBindingV1
    profiles: tuple[IFEMPinnedProfileV1, ...] = Field(min_length=1)
    candidate_declarations: tuple[str, ...] = Field(min_length=1)
    negative_control: Literal["AutoLean.IFEM.PinnedProfileQuery.NegativeControl"] = NEGATIVE_CONTROL
    observation_contract: IFEMPinnedProfileObservationContractV1 = (
        IFEMPinnedProfileObservationContractV1()
    )
    authority: IFEMPinnedProfileAuthorityV1 = IFEMPinnedProfileAuthorityV1()
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_plan(self) -> IFEMPinnedMathlibProfilePlanV1:
        profile_pairs = tuple(
            (profile.profile_id, profile.direct_import) for profile in self.profiles
        )
        if profile_pairs != _PROFILE_IMPORTS:
            raise ValueError("singleton profile vocabulary or order drifted")
        if self.candidate_declarations != tuple(sorted(set(self.candidate_declarations))):
            raise ValueError("candidate declarations must be sorted and unique")
        if any(_DECLARATION.fullmatch(name) is None for name in self.candidate_declarations):
            raise ValueError("candidate declaration is not a valid Lean name")
        if self.negative_control in self.candidate_declarations:
            raise ValueError("negative control must not enter the candidate declaration list")
        if self.observation_contract != IFEMPinnedProfileObservationContractV1():
            raise ValueError("pinned observation contract drifted")
        if self.content_sha256 != self.computed_content_sha256():
            raise ValueError("pinned profile plan content hash does not match its payload")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(dict[str, object], self.model_dump(mode="json", exclude={"content_sha256"}))

    def computed_content_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.content_payload())).hexdigest()


class IFEMPinnedProfileDeclarationObservationV1(ContractModel):
    declaration: str = Field(min_length=1)
    present: bool
    declaration_kind: str | None = Field(default=None, min_length=1)
    origin_module: str | None = Field(default=None, min_length=1)
    canonical_type: str | None = Field(default=None, min_length=1)
    canonical_type_sha256: str | None = Field(default=None, pattern=_SHA256)
    observed_axioms: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_observation(self) -> IFEMPinnedProfileDeclarationObservationV1:
        if _DECLARATION.fullmatch(self.declaration) is None:
            raise ValueError("observation has an invalid Lean declaration name")
        if self.observed_axioms != tuple(sorted(set(self.observed_axioms))):
            raise ValueError("observed axioms must be sorted and unique")
        if self.present:
            if (
                self.declaration_kind is None
                or self.origin_module is None
                or _MODULE.fullmatch(self.origin_module) is None
                or self.canonical_type is None
            ):
                raise ValueError("present declaration lacks exact kind, origin, or canonical type")
            expected = hashlib.sha256(self.canonical_type.encode("utf-8")).hexdigest()
            if self.canonical_type_sha256 != expected:
                raise ValueError("canonical type hash does not match the observed type")
        elif (
            self.declaration_kind is not None
            or self.origin_module is not None
            or self.canonical_type is not None
            or self.canonical_type_sha256 is not None
            or self.observed_axioms
        ):
            raise ValueError("absent declaration carries fabricated metadata")
        return self


class IFEMPinnedProfileObservationV1(ContractModel):
    profile_id: str = Field(pattern=r"^ifem-singleton-[a-z-]+$")
    direct_imports: tuple[str, ...] = Field(min_length=1)
    loaded_module_closure: tuple[str, ...] = Field(min_length=1)
    loaded_module_closure_sha256: str = Field(pattern=_SHA256)
    declarations: tuple[IFEMPinnedProfileDeclarationObservationV1, ...] = Field(min_length=1)
    negative_control: IFEMPinnedProfileDeclarationObservationV1

    @model_validator(mode="after")
    def validate_profile_observation(self) -> IFEMPinnedProfileObservationV1:
        if self.direct_imports != tuple(sorted(set(self.direct_imports))):
            raise ValueError("profile direct imports must be sorted and unique")
        if len(self.direct_imports) != 1 or self.direct_imports[0] == "Mathlib":
            raise ValueError("observation must contain one non-aggregate direct import")
        if any(_MODULE.fullmatch(module) is None for module in self.direct_imports):
            raise ValueError("observation has an invalid direct import")
        if self.loaded_module_closure != tuple(sorted(set(self.loaded_module_closure))):
            raise ValueError("loaded module closure must be sorted and unique")
        if any(_MODULE.fullmatch(module) is None for module in self.loaded_module_closure):
            raise ValueError("loaded module closure has an invalid module name")
        if self.direct_imports[0] not in self.loaded_module_closure:
            raise ValueError("loaded closure does not contain the singleton direct import")
        expected_closure = hashlib.sha256(
            canonical_json_bytes(list(self.loaded_module_closure))
        ).hexdigest()
        if self.loaded_module_closure_sha256 != expected_closure:
            raise ValueError("loaded module closure hash does not match its entries")
        declaration_names = tuple(record.declaration for record in self.declarations)
        if declaration_names != tuple(sorted(set(declaration_names))):
            raise ValueError("profile declaration observations must be sorted and unique")
        if self.negative_control.present:
            raise ValueError("negative control unexpectedly resolved in the profile environment")
        return self


class IFEMPinnedProfileBuiltOleanHashV1(ContractModel):
    """One image-built OLean identity, listed in the fixed child-image inventory."""

    path: str = Field(min_length=1)
    sha256: str = Field(pattern=_SHA256)


class IFEMPinnedMathlibProfileObservationsV1(ContractModel):
    schema_version: Literal["autolean.ifem-pinned-mathlib-profile-observations.v1"] = (
        MULTI_OBSERVATION_SCHEMA
    )
    protocol: Literal["autolean.ifem-pinned-profile-query.v1"] = PROTOCOL
    plan_content_sha256: str = Field(pattern=_SHA256)
    child_image: str = Field(min_length=1)
    parent_image: str = Field(min_length=1)
    lean_toolchain: str = Field(min_length=1)
    mathlib_revision: str = Field(pattern=_REVISION)
    lake_manifest_sha256: str = Field(pattern=_SHA256)
    helper_sha256: str = Field(pattern=_SHA256)
    wrapper_sha256: str = Field(pattern=_SHA256)
    built_olean_manifest_sha256: str = Field(pattern=_SHA256)
    built_olean_hashes: tuple[IFEMPinnedProfileBuiltOleanHashV1, ...] = Field(
        min_length=6,
        max_length=6,
    )
    profiles: tuple[IFEMPinnedProfileObservationV1, ...] = Field(min_length=1)
    authority: IFEMPinnedProfileAuthorityV1 = IFEMPinnedProfileAuthorityV1()
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_observations(self) -> IFEMPinnedMathlibProfileObservationsV1:
        if CHILD_IMAGE_RE.fullmatch(self.child_image) is None:
            raise ValueError("child image must use the fixed digest-pinned repository")
        profile_ids = tuple(profile.profile_id for profile in self.profiles)
        if profile_ids != tuple(profile_id for profile_id, _ in _PROFILE_IMPORTS):
            raise ValueError("observation profile vocabulary or order drifted")
        if (
            tuple((profile.profile_id, profile.direct_imports) for profile in self.profiles)
            != _PROFILE_DIRECT_IMPORTS
        ):
            raise ValueError("observation profile direct imports differ from the frozen plan")
        if tuple(item.path for item in self.built_olean_hashes) != _BUILT_OLEAN_PATHS:
            raise ValueError("image-built OLean inventory or order drifted")
        if self.content_sha256 != self.computed_content_sha256():
            raise ValueError("profile observations content hash does not match its payload")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(dict[str, object], self.model_dump(mode="json", exclude={"content_sha256"}))

    def computed_content_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.content_payload())).hexdigest()


class IFEMPinnedMathlibProfileResultV1(ContractModel):
    schema_version: Literal["autolean.ifem-pinned-mathlib-profile-result.v1"] = RESULT_SCHEMA
    protocol: Literal["autolean.ifem-pinned-profile-query.v1"] = PROTOCOL
    execution_state: IFEMPinnedProfileExecutionStateV1
    plan_content_sha256: str = Field(pattern=_SHA256)
    observation_content_sha256: str | None = Field(default=None, pattern=_SHA256)
    not_run_reason: str | None = Field(default=None, min_length=1)
    authority: IFEMPinnedProfileAuthorityV1 = IFEMPinnedProfileAuthorityV1()
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_result(self) -> IFEMPinnedMathlibProfileResultV1:
        if self.execution_state is IFEMPinnedProfileExecutionStateV1.NOT_RUN:
            if self.observation_content_sha256 is not None or self.not_run_reason is None:
                raise ValueError("not-run result must have only an explicit reason")
        elif self.observation_content_sha256 is None or self.not_run_reason is not None:
            raise ValueError("completed result must bind only a profile observation")
        if self.content_sha256 != self.computed_content_sha256():
            raise ValueError("profile result content hash does not match its payload")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(dict[str, object], self.model_dump(mode="json", exclude={"content_sha256"}))

    def computed_content_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.content_payload())).hexdigest()


class IFEMPinnedMathlibProfileBuildReceiptV1(ContractModel):
    """A plan-bound local child-image build identity; it has no semantic authority."""

    schema_version: Literal["autolean.ifem-pinned-mathlib-profile-build-receipt.v1"] = (
        "autolean.ifem-pinned-mathlib-profile-build-receipt.v1"
    )
    protocol: Literal["autolean.ifem-pinned-profile-query.v1"] = PROTOCOL
    plan_content_sha256: str = Field(pattern=_SHA256)
    parent_image: Literal[
        "autolean/mathlib-worker@sha256:3237192cf627a05367c75d46e61ec9034fefe43a4fd0c06139e38c80358648d6"
    ] = PARENT_IMAGE
    child_image: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    child_image_tag: str = Field(pattern=r"^autolean/ifem-pinned-profile-query:plan-[0-9a-f]{12}$")
    staged_context_sha256: str = Field(pattern=_SHA256)
    dockerfile_sha256: str = Field(pattern=_SHA256)
    helper_sha256: str = Field(pattern=_SHA256)
    wrapper_sha256: str = Field(pattern=_SHA256)
    build_network: Literal["none"] = "none"
    authority: IFEMPinnedProfileAuthorityV1 = IFEMPinnedProfileAuthorityV1()
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_build_receipt(self) -> IFEMPinnedMathlibProfileBuildReceiptV1:
        if self.authority != IFEMPinnedProfileAuthorityV1():
            raise ValueError("build receipt authority flags drifted")
        if self.content_sha256 != self.computed_content_sha256():
            raise ValueError("profile build receipt content hash does not match its payload")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(dict[str, object], self.model_dump(mode="json", exclude={"content_sha256"}))

    def computed_content_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.content_payload())).hexdigest()


class IFEMPinnedProfilePublicDeclarationObservationV1(ContractModel):
    """A declaration observation with the canonical type deliberately removed."""

    declaration: str = Field(min_length=1)
    present: bool
    declaration_kind: str | None = Field(default=None, min_length=1)
    origin_module: str | None = Field(default=None, min_length=1)
    canonical_type_sha256: str | None = Field(default=None, pattern=_SHA256)
    canonical_type_utf8_byte_count: int | None = Field(default=None, gt=0)
    observed_axioms: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_redacted_observation(self) -> IFEMPinnedProfilePublicDeclarationObservationV1:
        if _DECLARATION.fullmatch(self.declaration) is None:
            raise ValueError("public observation has an invalid Lean declaration name")
        if self.observed_axioms != tuple(sorted(set(self.observed_axioms))):
            raise ValueError("public observed axioms must be sorted and unique")
        if self.present:
            if (
                self.declaration_kind is None
                or self.origin_module is None
                or _MODULE.fullmatch(self.origin_module) is None
                or self.canonical_type_sha256 is None
                or self.canonical_type_utf8_byte_count is None
            ):
                raise ValueError("present public declaration lacks retained metadata")
        elif (
            self.declaration_kind is not None
            or self.origin_module is not None
            or self.canonical_type_sha256 is not None
            or self.canonical_type_utf8_byte_count is not None
            or self.observed_axioms
        ):
            raise ValueError("absent public declaration carries fabricated metadata")
        return self


class IFEMPinnedProfilePublicObservationV1(ContractModel):
    """One public-safe singleton profile; closure members never cross this boundary."""

    profile_id: str = Field(pattern=r"^ifem-singleton-[a-z-]+$")
    direct_import: str = Field(min_length=1)
    loaded_module_closure_count: int = Field(ge=1)
    loaded_module_closure_sha256: str = Field(pattern=_SHA256)
    declarations: tuple[IFEMPinnedProfilePublicDeclarationObservationV1, ...] = Field(min_length=1)
    negative_control: IFEMPinnedProfilePublicDeclarationObservationV1

    @model_validator(mode="after")
    def validate_public_profile(self) -> IFEMPinnedProfilePublicObservationV1:
        if _MODULE.fullmatch(self.direct_import) is None or self.direct_import == "Mathlib":
            raise ValueError("public profile direct import is invalid")
        declaration_names = tuple(record.declaration for record in self.declarations)
        if declaration_names != tuple(sorted(set(declaration_names))):
            raise ValueError("public profile declarations must be sorted and unique")
        if self.negative_control.present:
            raise ValueError("public negative control unexpectedly resolved")
        return self


class IFEMPinnedMathlibProfilePublicSummaryV1(ContractModel):
    """Content-addressed, public-safe projection of completed P2-07 evidence."""

    schema_version: Literal["autolean.ifem-pinned-mathlib-profile-public-summary.v1"] = (
        PUBLIC_SUMMARY_SCHEMA
    )
    protocol: Literal["autolean.ifem-pinned-profile-query.v1"] = PROTOCOL
    plan_content_sha256: str = Field(pattern=_SHA256)
    plan_file_sha256: str = Field(pattern=_SHA256)
    receipt_content_sha256: str = Field(pattern=_SHA256)
    receipt_file_sha256: str = Field(pattern=_SHA256)
    observation_content_sha256: str = Field(pattern=_SHA256)
    observation_file_sha256: str = Field(pattern=_SHA256)
    result_content_sha256: str = Field(pattern=_SHA256)
    result_file_sha256: str = Field(pattern=_SHA256)
    execution_state: Literal[IFEMPinnedMathlibProfileExecutionStateV1.COMPLETED] = (
        IFEMPinnedMathlibProfileExecutionStateV1.COMPLETED
    )
    environment: IFEMPinnedProfileEnvironmentV1
    assets: IFEMPinnedProfileAssetBindingV1
    child_image: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    built_olean_manifest_sha256: str = Field(pattern=_SHA256)
    built_olean_hashes: tuple[IFEMPinnedProfileBuiltOleanHashV1, ...] = Field(
        min_length=6,
        max_length=6,
    )
    profiles: tuple[IFEMPinnedProfilePublicObservationV1, ...] = Field(min_length=1)
    replay_command: tuple[str, ...] = _PUBLIC_SUMMARY_REPLAY_COMMAND
    replay_reloads_exact_source_artifacts: Literal[True] = True
    authority: IFEMPinnedProfileAuthorityV1 = IFEMPinnedProfileAuthorityV1()
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_public_summary(self) -> IFEMPinnedMathlibProfilePublicSummaryV1:
        profile_pairs = tuple(
            (profile.profile_id, profile.direct_import) for profile in self.profiles
        )
        if profile_pairs != _PROFILE_IMPORTS:
            raise ValueError("public summary profile vocabulary or order drifted")
        if tuple(item.path for item in self.built_olean_hashes) != _BUILT_OLEAN_PATHS:
            raise ValueError("public summary OLean inventory or order drifted")
        if self.replay_command != _PUBLIC_SUMMARY_REPLAY_COMMAND:
            raise ValueError("public summary replay command drifted")
        if self.authority != IFEMPinnedProfileAuthorityV1():
            raise ValueError("public summary authority flags drifted")
        if self.content_sha256 != self.computed_content_sha256():
            raise ValueError("public summary content hash does not match its payload")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(dict[str, object], self.model_dump(mode="json", exclude={"content_sha256"}))

    def computed_content_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.content_payload())).hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise IFEMPinnedProfileError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json_object(path: Path, *, label: str) -> dict[str, object]:
    payload, _ = _load_json_object_with_file_sha256(path, label=label)
    return payload


def _read_regular_file_bytes(path: Path, *, label: str) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        raise IFEMPinnedProfileError(f"cannot inspect {label}") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise IFEMPinnedProfileError(f"{label} must be an unlinked regular file")
    try:
        raw = path.read_bytes()
        after = path.lstat()
    except OSError as error:
        raise IFEMPinnedProfileError(f"cannot read {label}: {path}") from error
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise IFEMPinnedProfileError(f"{label} changed while it was read")
    return raw


def _load_json_object_with_file_sha256(
    path: Path,
    *,
    label: str,
) -> tuple[dict[str, object], str]:
    raw_bytes = _read_regular_file_bytes(path, label=label)
    try:
        raw = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise IFEMPinnedProfileError(f"{label} is not valid UTF-8 JSON") from error
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as error:
        raise IFEMPinnedProfileError(f"{label} is not valid JSON") from error
    if not isinstance(value, dict):
        raise IFEMPinnedProfileError(f"{label} must be a JSON object")
    return cast(dict[str, object], value), hashlib.sha256(raw_bytes).hexdigest()


def _regular_file_sha256(path: Path, *, label: str) -> str:
    return hashlib.sha256(_read_regular_file_bytes(path, label=label)).hexdigest()


def _candidate_declarations(census: IFEMPrerequisiteCensusPlanV1) -> tuple[str, ...]:
    return tuple(
        sorted({name for query in census.queries for name in query.candidate_declarations})
    )


def build_ifem_pinned_mathlib_profile_plan(
    *,
    census_plan_path: Path = DEFAULT_CENSUS_PLAN_PATH,
    worker_root: Path = WORKER_ROOT,
) -> IFEMPinnedMathlibProfilePlanV1:
    """Build the immutable no-run profile plan from the frozen prerequisite census."""

    census = load_ifem_prerequisite_census_plan(census_plan_path)
    validate_plan_bindings(census)
    asset_paths = {
        "dockerfile_sha256": (worker_root / "Dockerfile.ifem-pinned-profile-query", "Dockerfile"),
        "helper_sha256": (worker_root / "AutoleanIFEMPinnedProfileQuery.lean", "query helper"),
        "wrapper_sha256": (worker_root / "autolean-ifem-pinned-profile-query", "query wrapper"),
    }
    assets = {
        field: _regular_file_sha256(path, label=label)
        for field, (path, label) in asset_paths.items()
    }
    payload: dict[str, object] = {
        "authority": IFEMPinnedProfileAuthorityV1().model_dump(mode="json"),
        "assets": {
            "built_olean_manifest_path": _BUILT_OLEAN_MANIFEST_PATH,
            "dockerfile_path": _DOCKERFILE_PATH,
            "dockerfile_sha256": assets["dockerfile_sha256"],
            "helper_path": _HELPER_PATH,
            "helper_sha256": assets["helper_sha256"],
            "wrapper_path": _WRAPPER_PATH,
            "wrapper_sha256": assets["wrapper_sha256"],
        },
        "candidate_declarations": list(_candidate_declarations(census)),
        "census_plan_content_sha256": census.content_sha256,
        "census_plan_path": _CENSUS_PLAN_PATH,
        "denominator": census.denominator.model_dump(mode="json"),
        "environment": {
            "lake_manifest_sha256": census.environment.lake_manifest_sha256,
            "lean_toolchain": census.environment.lean_toolchain,
            "mathlib_revision": census.environment.mathlib_revision,
            "parent_image": PARENT_IMAGE,
        },
        "negative_control": NEGATIVE_CONTROL,
        "observation_contract": IFEMPinnedProfileObservationContractV1().model_dump(mode="json"),
        "profiles": [
            {"direct_import": direct_import, "profile_id": profile_id}
            for profile_id, direct_import in _PROFILE_IMPORTS
        ],
        "protocol": PROTOCOL,
        "schema_version": PLAN_SCHEMA,
        "state": IFEMPinnedProfileExecutionStateV1.NOT_RUN.value,
    }
    payload["content_sha256"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    try:
        return IFEMPinnedMathlibProfilePlanV1.model_validate(payload)
    except ValueError as error:
        raise IFEMPinnedProfileError("generated pinned profile plan is invalid") from error


def load_ifem_pinned_mathlib_profile_plan(
    path: Path = DEFAULT_PLAN_PATH,
) -> IFEMPinnedMathlibProfilePlanV1:
    payload = _load_json_object(path, label="iFEM pinned mathlib profile plan")
    try:
        return IFEMPinnedMathlibProfilePlanV1.model_validate(payload)
    except ValueError as error:
        raise IFEMPinnedProfileError(f"iFEM pinned profile plan is invalid: {error}") from error


def load_ifem_pinned_mathlib_profile_build_receipt(
    path: Path,
) -> IFEMPinnedMathlibProfileBuildReceiptV1:
    payload = _load_json_object(path, label="iFEM pinned profile build receipt")
    try:
        return IFEMPinnedMathlibProfileBuildReceiptV1.model_validate(payload)
    except ValueError as error:
        raise IFEMPinnedProfileError("iFEM pinned profile build receipt is invalid") from error


def load_ifem_pinned_mathlib_profile_observations(
    path: Path,
) -> IFEMPinnedMathlibProfileObservationsV1:
    payload = _load_json_object(path, label="iFEM pinned profile observations")
    try:
        return IFEMPinnedMathlibProfileObservationsV1.model_validate(payload)
    except ValueError as error:
        raise IFEMPinnedProfileError("iFEM pinned profile observations are invalid") from error


def load_ifem_pinned_mathlib_profile_result(
    path: Path,
) -> IFEMPinnedMathlibProfileResultV1:
    payload = _load_json_object(path, label="iFEM pinned profile result")
    try:
        return IFEMPinnedMathlibProfileResultV1.model_validate(payload)
    except ValueError as error:
        raise IFEMPinnedProfileError("iFEM pinned profile result is invalid") from error


def load_ifem_pinned_mathlib_profile_public_summary(
    path: Path,
) -> IFEMPinnedMathlibProfilePublicSummaryV1:
    payload = _load_json_object(path, label="iFEM pinned profile public summary")
    try:
        return IFEMPinnedMathlibProfilePublicSummaryV1.model_validate(payload)
    except ValueError as error:
        raise IFEMPinnedProfileError("iFEM pinned profile public summary is invalid") from error


def _load_public_summary_inputs(
    *,
    plan_path: Path,
    receipt_path: Path,
    observation_path: Path,
    result_path: Path,
) -> tuple[
    IFEMPinnedMathlibProfilePlanV1,
    IFEMPinnedMathlibProfileBuildReceiptV1,
    IFEMPinnedMathlibProfileObservationsV1,
    IFEMPinnedMathlibProfileResultV1,
    str,
    str,
    str,
    str,
]:
    plan_payload, plan_file_sha256 = _load_json_object_with_file_sha256(
        plan_path,
        label="iFEM pinned mathlib profile plan",
    )
    receipt_payload, receipt_file_sha256 = _load_json_object_with_file_sha256(
        receipt_path,
        label="iFEM pinned profile build receipt",
    )
    observation_payload, observation_file_sha256 = _load_json_object_with_file_sha256(
        observation_path,
        label="iFEM pinned profile observations",
    )
    result_payload, result_file_sha256 = _load_json_object_with_file_sha256(
        result_path,
        label="iFEM pinned profile result",
    )
    try:
        return (
            IFEMPinnedMathlibProfilePlanV1.model_validate(plan_payload),
            IFEMPinnedMathlibProfileBuildReceiptV1.model_validate(receipt_payload),
            IFEMPinnedMathlibProfileObservationsV1.model_validate(observation_payload),
            IFEMPinnedMathlibProfileResultV1.model_validate(result_payload),
            plan_file_sha256,
            receipt_file_sha256,
            observation_file_sha256,
            result_file_sha256,
        )
    except ValueError as error:
        raise IFEMPinnedProfileError("public summary source artifact is invalid") from error


def validate_profile_plan_bindings(
    plan: IFEMPinnedMathlibProfilePlanV1,
    *,
    census_plan_path: Path = DEFAULT_CENSUS_PLAN_PATH,
    worker_root: Path = WORKER_ROOT,
) -> None:
    """Verify that this profile plan remains tied to the frozen census and child inputs."""

    census = load_ifem_prerequisite_census_plan(census_plan_path)
    validate_plan_bindings(census)
    if plan.census_plan_content_sha256 != census.content_sha256:
        raise IFEMPinnedProfileError("profile plan does not bind the current frozen census plan")
    if plan.denominator != census.denominator:
        raise IFEMPinnedProfileError("profile plan denominator differs from the frozen census")
    if (
        plan.environment.lean_toolchain != census.environment.lean_toolchain
        or plan.environment.mathlib_revision != census.environment.mathlib_revision
        or plan.environment.lake_manifest_sha256 != census.environment.lake_manifest_sha256
    ):
        raise IFEMPinnedProfileError("profile plan environment differs from the frozen census")
    if plan.candidate_declarations != _candidate_declarations(census):
        raise IFEMPinnedProfileError("profile declaration inventory differs from the frozen census")
    assets = {
        "dockerfile_sha256": (worker_root / "Dockerfile.ifem-pinned-profile-query", "Dockerfile"),
        "helper_sha256": (worker_root / "AutoleanIFEMPinnedProfileQuery.lean", "query helper"),
        "wrapper_sha256": (worker_root / "autolean-ifem-pinned-profile-query", "query wrapper"),
    }
    for field, (path, label) in assets.items():
        if getattr(plan.assets, field) != _regular_file_sha256(path, label=label):
            raise IFEMPinnedProfileError(f"profile plan {field} differs from the child image input")


def _run_docker(
    argv: Sequence[str],
    *,
    capture_output: bool,
    check: bool = True,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            list(argv),
            check=check,
            shell=False,
            text=True,
            capture_output=capture_output,
            cwd=str(cwd) if cwd is not None else None,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise IFEMPinnedProfileError("pinned profile OCI command failed") from error


def _docker_image_inspect(image: str) -> dict[str, object]:
    completed = _run_docker(("docker", "image", "inspect", image), capture_output=True)
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise IFEMPinnedProfileError("pinned profile image inspect is not JSON") from error
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
        raise IFEMPinnedProfileError("pinned profile image inspect has an invalid shape")
    return cast(dict[str, object], payload[0])


def _docker_image_inspect_if_present(image: str) -> dict[str, object] | None:
    """Return ``None`` only for an absent local image, never for a Docker failure."""

    try:
        completed = _run_docker(
            ("docker", "image", "inspect", image),
            capture_output=True,
            check=False,
        )
    except IFEMPinnedProfileError:
        raise
    if completed.returncode == 1:
        if "No such image" in completed.stderr:
            return None
        raise IFEMPinnedProfileError("pinned profile image is not inspectable")
    if completed.returncode != 0:
        raise IFEMPinnedProfileError("pinned profile image inspection failed")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise IFEMPinnedProfileError("pinned profile image inspect is not JSON") from error
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
        raise IFEMPinnedProfileError("pinned profile image inspect has an invalid shape")
    return cast(dict[str, object], payload[0])


def _child_image_tag(plan: IFEMPinnedMathlibProfilePlanV1) -> str:
    return f"{CHILD_IMAGE_REPOSITORY}:plan-{plan.content_sha256[:12]}"


def _child_image_build_command(
    plan: IFEMPinnedMathlibProfilePlanV1,
    *,
    tag: str,
) -> tuple[str, ...]:
    """Build only the staged three-file context; network access is unavailable."""

    if tag != _child_image_tag(plan):
        raise IFEMPinnedProfileError("pinned profile child-image tag does not bind the plan")
    return (
        "docker",
        "build",
        "--network=none",
        "--pull=false",
        "--file",
        "Dockerfile.ifem-pinned-profile-query",
        "--tag",
        tag,
        ".",
    )


def _build_context_asset_bindings(
    plan: IFEMPinnedMathlibProfilePlanV1,
) -> tuple[tuple[str, str, str], ...]:
    return (
        (
            "Dockerfile.ifem-pinned-profile-query",
            plan.assets.dockerfile_sha256,
            "Dockerfile",
        ),
        (
            "AutoleanIFEMPinnedProfileQuery.lean",
            plan.assets.helper_sha256,
            "query helper",
        ),
        (
            "autolean-ifem-pinned-profile-query",
            plan.assets.wrapper_sha256,
            "query wrapper",
        ),
    )


def _expected_staged_context_sha256(plan: IFEMPinnedMathlibProfilePlanV1) -> str:
    inventory = [
        {"path": path, "sha256": sha256}
        for path, sha256, _label in _build_context_asset_bindings(plan)
    ]
    return hashlib.sha256(canonical_json_bytes(inventory)).hexdigest()


def _stage_child_build_context(
    plan: IFEMPinnedMathlibProfilePlanV1,
    *,
    worker_root: Path,
    stage: Path,
) -> str:
    """Copy the three plan-bound inputs into an otherwise empty temporary build context."""

    if stage.exists():
        raise IFEMPinnedProfileError("pinned profile build context must start absent")
    stage.mkdir(mode=0o700)
    assets = _build_context_asset_bindings(plan)
    inventory: list[dict[str, str]] = []
    for name, expected_sha256, label in assets:
        source = worker_root / name
        observed_sha256 = _regular_file_sha256(source, label=label)
        if observed_sha256 != expected_sha256:
            raise IFEMPinnedProfileError("pinned profile source differs from the frozen plan")
        destination = stage / name
        try:
            shutil.copyfile(source, destination)
            destination.chmod(0o444)
        except OSError as error:
            raise IFEMPinnedProfileError(
                "pinned profile build input could not be staged"
            ) from error
        if _regular_file_sha256(destination, label=f"staged {label}") != expected_sha256:
            raise IFEMPinnedProfileError("staged pinned profile input differs from its source")
        inventory.append({"path": name, "sha256": expected_sha256})
    if tuple(item["path"] for item in inventory) != _BUILD_CONTEXT_FILES:
        raise IFEMPinnedProfileError("pinned profile build context allowlist drifted")
    if tuple(sorted(path.name for path in stage.iterdir())) != tuple(sorted(_BUILD_CONTEXT_FILES)):
        raise IFEMPinnedProfileError("pinned profile build context contains an unplanned file")
    observed_context_sha256 = hashlib.sha256(canonical_json_bytes(inventory)).hexdigest()
    if observed_context_sha256 != _expected_staged_context_sha256(plan):
        raise IFEMPinnedProfileError("staged pinned profile context hash drifted")
    return observed_context_sha256


def build_ifem_pinned_mathlib_profile_child_image(
    plan: IFEMPinnedMathlibProfilePlanV1,
    *,
    worker_root: Path = WORKER_ROOT,
) -> IFEMPinnedMathlibProfileBuildReceiptV1:
    """Stage the exact three-file context and build a network-disabled local child image."""

    validate_profile_plan_bindings(plan, worker_root=worker_root)
    tag = _child_image_tag(plan)
    if _docker_image_inspect_if_present(tag) is not None:
        raise IFEMPinnedProfileError("pinned profile child-image tag already exists")
    with tempfile.TemporaryDirectory(prefix="autolean-ifem-pinned-profile-build-") as raw_parent:
        stage = Path(raw_parent) / "context"
        staged_context_sha256 = _stage_child_build_context(
            plan, worker_root=worker_root, stage=stage
        )
        _run_docker(
            _child_image_build_command(plan, tag=tag),
            capture_output=False,
            cwd=stage,
        )
    inspected = _docker_image_inspect(tag)
    image_id = inspected.get("Id")
    if not isinstance(image_id, str) or CHILD_IMAGE_RE.fullmatch(image_id) is None:
        raise IFEMPinnedProfileError("pinned profile child image has no digest identity")
    receipt_payload: dict[str, object] = {
        "authority": IFEMPinnedProfileAuthorityV1().model_dump(mode="json"),
        "build_network": "none",
        "child_image": image_id,
        "child_image_tag": tag,
        "dockerfile_sha256": plan.assets.dockerfile_sha256,
        "helper_sha256": plan.assets.helper_sha256,
        "parent_image": plan.environment.parent_image,
        "plan_content_sha256": plan.content_sha256,
        "protocol": PROTOCOL,
        "schema_version": "autolean.ifem-pinned-mathlib-profile-build-receipt.v1",
        "staged_context_sha256": staged_context_sha256,
        "wrapper_sha256": plan.assets.wrapper_sha256,
    }
    receipt_payload["content_sha256"] = hashlib.sha256(
        canonical_json_bytes(receipt_payload)
    ).hexdigest()
    try:
        receipt = IFEMPinnedMathlibProfileBuildReceiptV1.model_validate(receipt_payload)
    except ValueError as error:
        raise IFEMPinnedProfileError("pinned profile build receipt is invalid") from error
    verify_ifem_pinned_mathlib_profile_child_image(plan, receipt)
    return receipt


def verify_ifem_pinned_mathlib_profile_child_image(
    plan: IFEMPinnedMathlibProfilePlanV1,
    receipt: IFEMPinnedMathlibProfileBuildReceiptV1,
) -> None:
    """Verify a locally built child image against the frozen plan and image-owned labels."""

    if type(receipt) is not IFEMPinnedMathlibProfileBuildReceiptV1:
        raise IFEMPinnedProfileError("pinned profile build receipt has an invalid type")
    validate_profile_plan_bindings(plan)
    try:
        verified = IFEMPinnedMathlibProfileBuildReceiptV1.model_validate(
            receipt.model_dump(mode="json")
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise IFEMPinnedProfileError("pinned profile build receipt failed revalidation") from error
    if (
        verified.plan_content_sha256 != plan.content_sha256
        or verified.parent_image != plan.environment.parent_image
        or verified.dockerfile_sha256 != plan.assets.dockerfile_sha256
        or verified.helper_sha256 != plan.assets.helper_sha256
        or verified.wrapper_sha256 != plan.assets.wrapper_sha256
        or verified.child_image_tag != _child_image_tag(plan)
        or verified.staged_context_sha256 != _expected_staged_context_sha256(plan)
    ):
        raise IFEMPinnedProfileError("pinned profile build receipt differs from the frozen plan")
    inspected = _docker_image_inspect(verified.child_image)
    if inspected.get("Id") != verified.child_image:
        raise IFEMPinnedProfileError("pinned profile image digest changed after build")
    config = inspected.get("Config")
    if not isinstance(config, dict):
        raise IFEMPinnedProfileError("pinned profile image has no configuration")
    if config.get("User") != "65532:65532" or config.get("WorkingDir") != "/work":
        raise IFEMPinnedProfileError("pinned profile image runtime identity drifted")
    labels = config.get("Labels")
    if not isinstance(labels, dict) or (
        labels.get("org.autolean.ifem.parent-image") != plan.environment.parent_image
        or labels.get("org.autolean.ifem.profile-protocol") != PROTOCOL
    ):
        raise IFEMPinnedProfileError("pinned profile image labels do not bind the fixed parent")


def _pinned_profile_docker_command(
    plan: IFEMPinnedMathlibProfilePlanV1,
    *,
    child_image: str,
    profile: IFEMPinnedProfileV1,
) -> tuple[str, ...]:
    if CHILD_IMAGE_RE.fullmatch(child_image) is None:
        raise IFEMPinnedProfileError("child image must use a sha256 image identity")
    if profile not in plan.profiles:
        raise IFEMPinnedProfileError("query profile is not part of the fixed plan")
    return (
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        str(_RUN_PIDS_LIMIT),
        "--memory",
        _RUN_MEMORY_LIMIT,
        "--tmpfs",
        _RUN_TMPFS,
        "--user",
        "65532:65532",
        "--workdir",
        "/work",
        child_image,
        "/opt/autolean/bin/autolean-ifem-pinned-profile-query",
        "--protocol",
        PROTOCOL,
        "--profile",
        profile.profile_id,
        *tuple(
            argument
            for declaration in plan.candidate_declarations
            for argument in ("--declaration", declaration)
        ),
    )


def run_ifem_pinned_mathlib_profile_queries(
    plan: IFEMPinnedMathlibProfilePlanV1,
    receipt: IFEMPinnedMathlibProfileBuildReceiptV1,
) -> IFEMPinnedMathlibProfileObservationsV1:
    """Run all five isolated singleton profiles and normalize their image-owned records."""

    verify_ifem_pinned_mathlib_profile_child_image(plan, receipt)
    raw_by_profile: dict[str, str] = {}
    for profile in plan.profiles:
        completed = _run_docker(
            _pinned_profile_docker_command(
                plan,
                child_image=receipt.child_image,
                profile=profile,
            ),
            capture_output=True,
        )
        raw_by_profile[profile.profile_id] = completed.stdout
    observation = normalize_profile_observations(
        raw_by_profile,
        plan=plan,
        child_image=receipt.child_image,
    )
    validate_profile_observation_bindings(plan, receipt, observation)
    return observation


def _raw_string_list(value: object, *, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise IFEMPinnedProfileError(f"raw profile {label} must be a string list")
    return tuple(cast(list[str], value))


def _normalize_declaration(
    raw: object,
    *,
    expected_declaration: str,
) -> IFEMPinnedProfileDeclarationObservationV1:
    if not isinstance(raw, dict) or set(raw) != {
        "canonical_type",
        "declaration",
        "declaration_kind",
        "observed_axioms",
        "origin_module",
        "present",
    }:
        raise IFEMPinnedProfileError("raw declaration observation has unexpected fields")
    if raw.get("declaration") != expected_declaration or not isinstance(raw.get("present"), bool):
        raise IFEMPinnedProfileError("raw declaration observation changed its requested identity")
    present = cast(bool, raw["present"])
    canonical_type = raw.get("canonical_type")
    declaration_kind = raw.get("declaration_kind")
    origin_module = raw.get("origin_module")
    axioms = _raw_string_list(raw.get("observed_axioms"), label="observed axioms")
    if axioms != tuple(sorted(set(axioms))):
        raise IFEMPinnedProfileError("raw declaration observed axioms are not sorted and unique")
    if present:
        if (
            not isinstance(canonical_type, str)
            or not canonical_type
            or not isinstance(declaration_kind, str)
            or not declaration_kind
            or not isinstance(origin_module, str)
            or not origin_module
        ):
            raise IFEMPinnedProfileError("present declaration lacks exact kind, origin, or type")
        canonical_type_sha256: str | None = hashlib.sha256(
            canonical_type.encode("utf-8")
        ).hexdigest()
    else:
        if (
            canonical_type is not None
            or declaration_kind is not None
            or origin_module is not None
            or axioms
        ):
            raise IFEMPinnedProfileError("absent declaration carries fabricated metadata")
        canonical_type_sha256 = None
    try:
        return IFEMPinnedProfileDeclarationObservationV1.model_validate(
            {
                "canonical_type": canonical_type,
                "canonical_type_sha256": canonical_type_sha256,
                "declaration": expected_declaration,
                "declaration_kind": declaration_kind,
                "observed_axioms": list(axioms),
                "origin_module": origin_module,
                "present": present,
            }
        )
    except ValueError as error:
        raise IFEMPinnedProfileError("normalized declaration observation is invalid") from error


def _normalize_built_olean_hashes(
    raw: object,
) -> tuple[IFEMPinnedProfileBuiltOleanHashV1, ...]:
    if not isinstance(raw, list) or len(raw) != len(_BUILT_OLEAN_PATHS):
        raise IFEMPinnedProfileError("raw profile OLean inventory has an invalid size")
    normalized: list[IFEMPinnedProfileBuiltOleanHashV1] = []
    for expected_path, item in zip(_BUILT_OLEAN_PATHS, raw, strict=True):
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            raise IFEMPinnedProfileError("raw profile OLean inventory has unexpected fields")
        if item.get("path") != expected_path:
            raise IFEMPinnedProfileError("raw profile OLean inventory order drifted")
        try:
            normalized.append(IFEMPinnedProfileBuiltOleanHashV1.model_validate(item))
        except ValueError as error:
            raise IFEMPinnedProfileError("raw profile OLean hash is invalid") from error
    return tuple(normalized)


def normalize_profile_observation(
    raw: str,
    *,
    plan: IFEMPinnedMathlibProfilePlanV1,
    profile: IFEMPinnedProfileV1,
) -> tuple[IFEMPinnedProfileObservationV1, str, tuple[IFEMPinnedProfileBuiltOleanHashV1, ...]]:
    """Normalize one image-owned raw record without assigning semantic meaning."""

    try:
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as error:
        raise IFEMPinnedProfileError("raw profile query did not emit valid JSON") from error
    expected_fields = {
        "built_olean_hashes",
        "built_olean_manifest_sha256",
        "declarations",
        "direct_imports",
        "helper_sha256",
        "loaded_module_closure",
        "negative_control",
        "profile_id",
        "schema_version",
        "type_format",
        "wrapper_sha256",
    }
    if not isinstance(payload, dict) or set(payload) != expected_fields:
        raise IFEMPinnedProfileError("raw profile query record has unexpected fields")
    if (
        payload.get("schema_version") != RAW_OBSERVATION_SCHEMA
        or payload.get("type_format") != "autolean.lean-pp-expr.v1"
        or payload.get("profile_id") != profile.profile_id
        or payload.get("helper_sha256") != plan.assets.helper_sha256
        or payload.get("wrapper_sha256") != plan.assets.wrapper_sha256
    ):
        raise IFEMPinnedProfileError("raw profile query identity differs from the fixed plan")
    built_olean_manifest_sha256 = payload.get("built_olean_manifest_sha256")
    if (
        not isinstance(built_olean_manifest_sha256, str)
        or re.fullmatch(_SHA256, built_olean_manifest_sha256) is None
    ):
        raise IFEMPinnedProfileError("raw profile query lacks a valid built olean manifest hash")
    built_olean_hashes = _normalize_built_olean_hashes(payload.get("built_olean_hashes"))
    direct_imports = _raw_string_list(payload.get("direct_imports"), label="direct imports")
    if direct_imports != (profile.direct_import,):
        raise IFEMPinnedProfileError("raw profile query did not use the planned singleton import")
    closure = _raw_string_list(payload.get("loaded_module_closure"), label="loaded module closure")
    if closure != tuple(sorted(set(closure))):
        raise IFEMPinnedProfileError("raw profile loaded closure is not sorted and unique")
    raw_declarations = payload.get("declarations")
    if not isinstance(raw_declarations, list) or len(raw_declarations) != len(
        plan.candidate_declarations
    ):
        raise IFEMPinnedProfileError("raw profile declaration count differs from the fixed plan")
    declarations = tuple(
        _normalize_declaration(raw_record, expected_declaration=expected_declaration)
        for expected_declaration, raw_record in zip(
            plan.candidate_declarations, raw_declarations, strict=True
        )
    )
    negative = _normalize_declaration(
        payload.get("negative_control"), expected_declaration=plan.negative_control
    )
    try:
        normalized = IFEMPinnedProfileObservationV1.model_validate(
            {
                "declarations": [item.model_dump(mode="json") for item in declarations],
                "direct_imports": list(direct_imports),
                "loaded_module_closure": list(closure),
                "loaded_module_closure_sha256": hashlib.sha256(
                    canonical_json_bytes(list(closure))
                ).hexdigest(),
                "negative_control": negative.model_dump(mode="json"),
                "profile_id": profile.profile_id,
            }
        )
    except ValueError as error:
        raise IFEMPinnedProfileError(
            "normalized singleton profile observation is invalid"
        ) from error
    return normalized, built_olean_manifest_sha256, built_olean_hashes


def normalize_profile_observations(
    raw_by_profile: Mapping[str, str],
    *,
    plan: IFEMPinnedMathlibProfilePlanV1,
    child_image: str,
) -> IFEMPinnedMathlibProfileObservationsV1:
    """Bind all five raw singleton-profile records into one content-addressed observation."""

    if set(raw_by_profile) != {profile.profile_id for profile in plan.profiles}:
        raise IFEMPinnedProfileError("raw profile set differs from the fixed five-profile plan")
    if CHILD_IMAGE_RE.fullmatch(child_image) is None:
        raise IFEMPinnedProfileError("child image must use the fixed digest-pinned repository")
    normalized_profiles: list[IFEMPinnedProfileObservationV1] = []
    manifest_hashes: set[str] = set()
    built_olean_inventory: tuple[IFEMPinnedProfileBuiltOleanHashV1, ...] | None = None
    for profile in plan.profiles:
        normalized, built_olean_manifest_sha256, built_olean_hashes = normalize_profile_observation(
            raw_by_profile[profile.profile_id], plan=plan, profile=profile
        )
        normalized_profiles.append(normalized)
        manifest_hashes.add(built_olean_manifest_sha256)
        if built_olean_inventory is None:
            built_olean_inventory = built_olean_hashes
        elif built_olean_inventory != built_olean_hashes:
            raise IFEMPinnedProfileError("profiles disagree on the image-built OLean inventory")
    if len(manifest_hashes) != 1:
        raise IFEMPinnedProfileError("profiles disagree on the image-built olean manifest")
    if built_olean_inventory is None:
        raise IFEMPinnedProfileError("image-built OLean inventory is unavailable")
    payload: dict[str, object] = {
        "authority": IFEMPinnedProfileAuthorityV1().model_dump(mode="json"),
        "built_olean_hashes": [item.model_dump(mode="json") for item in built_olean_inventory],
        "built_olean_manifest_sha256": next(iter(manifest_hashes)),
        "child_image": child_image,
        "helper_sha256": plan.assets.helper_sha256,
        "lake_manifest_sha256": plan.environment.lake_manifest_sha256,
        "lean_toolchain": plan.environment.lean_toolchain,
        "mathlib_revision": plan.environment.mathlib_revision,
        "parent_image": plan.environment.parent_image,
        "plan_content_sha256": plan.content_sha256,
        "profiles": [profile.model_dump(mode="json") for profile in normalized_profiles],
        "protocol": PROTOCOL,
        "schema_version": MULTI_OBSERVATION_SCHEMA,
        "wrapper_sha256": plan.assets.wrapper_sha256,
    }
    payload["content_sha256"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    try:
        return IFEMPinnedMathlibProfileObservationsV1.model_validate(payload)
    except ValueError as error:
        raise IFEMPinnedProfileError("normalized multi-profile observation is invalid") from error


def validate_profile_observation_bindings(
    plan: IFEMPinnedMathlibProfilePlanV1,
    receipt: IFEMPinnedMathlibProfileBuildReceiptV1,
    observation: IFEMPinnedMathlibProfileObservationsV1,
) -> None:
    """Check that an observation is a receipt for exactly one verified child image."""

    if observation.plan_content_sha256 != plan.content_sha256:
        raise IFEMPinnedProfileError("profile observation does not bind the frozen plan")
    if observation.child_image != receipt.child_image:
        raise IFEMPinnedProfileError("profile observation does not bind the verified child image")
    if tuple(
        (profile.profile_id, profile.direct_imports) for profile in observation.profiles
    ) != tuple((profile.profile_id, (profile.direct_import,)) for profile in plan.profiles):
        raise IFEMPinnedProfileError(
            "profile observation direct imports differ from the frozen plan"
        )
    if (
        observation.parent_image != plan.environment.parent_image
        or observation.lean_toolchain != plan.environment.lean_toolchain
        or observation.mathlib_revision != plan.environment.mathlib_revision
        or observation.lake_manifest_sha256 != plan.environment.lake_manifest_sha256
        or observation.helper_sha256 != plan.assets.helper_sha256
        or observation.wrapper_sha256 != plan.assets.wrapper_sha256
    ):
        raise IFEMPinnedProfileError("profile observation environment differs from the frozen plan")
    if observation.authority != IFEMPinnedProfileAuthorityV1():
        raise IFEMPinnedProfileError("profile observation authority flags drifted")


def not_run_result(
    plan: IFEMPinnedMathlibProfilePlanV1,
    *,
    reason: Literal["operator_not_run", "child_image_unavailable", "pinned_runtime_unavailable"],
) -> IFEMPinnedMathlibProfileResultV1:
    payload: dict[str, object] = {
        "authority": IFEMPinnedProfileAuthorityV1().model_dump(mode="json"),
        "execution_state": IFEMPinnedProfileExecutionStateV1.NOT_RUN,
        "not_run_reason": reason,
        "observation_content_sha256": None,
        "plan_content_sha256": plan.content_sha256,
        "protocol": PROTOCOL,
        "schema_version": RESULT_SCHEMA,
    }
    payload["content_sha256"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    return IFEMPinnedMathlibProfileResultV1.model_validate(payload)


def completed_result(
    plan: IFEMPinnedMathlibProfilePlanV1,
    observation: IFEMPinnedMathlibProfileObservationsV1,
) -> IFEMPinnedMathlibProfileResultV1:
    if observation.plan_content_sha256 != plan.content_sha256:
        raise IFEMPinnedProfileError("completed observation does not bind this profile plan")
    payload: dict[str, object] = {
        "authority": IFEMPinnedProfileAuthorityV1().model_dump(mode="json"),
        "execution_state": IFEMPinnedProfileExecutionStateV1.COMPLETED,
        "not_run_reason": None,
        "observation_content_sha256": observation.content_sha256,
        "plan_content_sha256": plan.content_sha256,
        "protocol": PROTOCOL,
        "schema_version": RESULT_SCHEMA,
    }
    payload["content_sha256"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    return IFEMPinnedMathlibProfileResultV1.model_validate(payload)


def _validate_completed_profile_evidence_bindings(
    plan: IFEMPinnedMathlibProfilePlanV1,
    receipt: IFEMPinnedMathlibProfileBuildReceiptV1,
    observation: IFEMPinnedMathlibProfileObservationsV1,
    result: IFEMPinnedMathlibProfileResultV1,
) -> None:
    if (
        receipt.plan_content_sha256 != plan.content_sha256
        or receipt.parent_image != plan.environment.parent_image
        or receipt.child_image_tag != _child_image_tag(plan)
        or receipt.dockerfile_sha256 != plan.assets.dockerfile_sha256
        or receipt.helper_sha256 != plan.assets.helper_sha256
        or receipt.wrapper_sha256 != plan.assets.wrapper_sha256
        or receipt.authority != IFEMPinnedProfileAuthorityV1()
    ):
        raise IFEMPinnedProfileError("profile build receipt differs from the frozen plan")
    validate_profile_observation_bindings(plan, receipt, observation)
    if (
        result.execution_state is not IFEMPinnedProfileExecutionStateV1.COMPLETED
        or result.plan_content_sha256 != plan.content_sha256
        or result.observation_content_sha256 != observation.content_sha256
        or result.authority != IFEMPinnedProfileAuthorityV1()
    ):
        raise IFEMPinnedProfileError("profile result does not bind completed frozen observations")


def _public_declaration_observation(
    observation: IFEMPinnedProfileDeclarationObservationV1,
) -> IFEMPinnedProfilePublicDeclarationObservationV1:
    return IFEMPinnedProfilePublicDeclarationObservationV1(
        declaration=observation.declaration,
        present=observation.present,
        declaration_kind=observation.declaration_kind,
        origin_module=observation.origin_module,
        canonical_type_sha256=observation.canonical_type_sha256,
        canonical_type_utf8_byte_count=(
            len(observation.canonical_type.encode("utf-8"))
            if observation.canonical_type is not None
            else None
        ),
        observed_axioms=observation.observed_axioms,
    )


def _assert_public_summary_redacted(
    observation: IFEMPinnedMathlibProfileObservationsV1,
    rendered_summary: bytes,
) -> None:
    try:
        payload = json.loads(
            rendered_summary.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
        summary = IFEMPinnedMathlibProfilePublicSummaryV1.model_validate(payload)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise IFEMPinnedProfileError("public summary is not the strict redacted schema") from error
    if render_ifem_pinned_mathlib_profile_public_summary(summary) != rendered_summary:
        raise IFEMPinnedProfileError("public summary is not canonically rendered")
    if b'"canonical_type"' in rendered_summary or b'"loaded_module_closure"' in rendered_summary:
        raise IFEMPinnedProfileError("public summary contains a forbidden raw-observation field")
    if any(
        record.canonical_type is not None
        and record.canonical_type.encode("utf-8") in rendered_summary
        and record.canonical_type
        not in {record.declaration, record.origin_module, *record.observed_axioms}
        for profile in observation.profiles
        for record in (*profile.declarations, profile.negative_control)
    ):
        raise IFEMPinnedProfileError("canonical type text leaked into the public summary")


def build_ifem_pinned_mathlib_profile_public_summary(
    plan: IFEMPinnedMathlibProfilePlanV1,
    receipt: IFEMPinnedMathlibProfileBuildReceiptV1,
    observation: IFEMPinnedMathlibProfileObservationsV1,
    result: IFEMPinnedMathlibProfileResultV1,
    *,
    plan_file_sha256: str,
    receipt_file_sha256: str,
    observation_file_sha256: str,
    result_file_sha256: str,
) -> IFEMPinnedMathlibProfilePublicSummaryV1:
    """Project exactly-bound completed observations without copying their private text."""

    _validate_completed_profile_evidence_bindings(plan, receipt, observation, result)
    profiles = tuple(
        IFEMPinnedProfilePublicObservationV1(
            profile_id=profile.profile_id,
            direct_import=profile.direct_imports[0],
            loaded_module_closure_count=len(profile.loaded_module_closure),
            loaded_module_closure_sha256=profile.loaded_module_closure_sha256,
            declarations=tuple(
                _public_declaration_observation(record) for record in profile.declarations
            ),
            negative_control=_public_declaration_observation(profile.negative_control),
        )
        for profile in observation.profiles
    )
    payload: dict[str, object] = {
        "assets": plan.assets.model_dump(mode="json"),
        "authority": IFEMPinnedProfileAuthorityV1().model_dump(mode="json"),
        "built_olean_hashes": [
            item.model_dump(mode="json") for item in observation.built_olean_hashes
        ],
        "built_olean_manifest_sha256": observation.built_olean_manifest_sha256,
        "child_image": observation.child_image,
        "environment": plan.environment.model_dump(mode="json"),
        "execution_state": IFEMPinnedMathlibProfileExecutionStateV1.COMPLETED.value,
        "observation_content_sha256": observation.content_sha256,
        "observation_file_sha256": observation_file_sha256,
        "plan_content_sha256": plan.content_sha256,
        "plan_file_sha256": plan_file_sha256,
        "profiles": [profile.model_dump(mode="json") for profile in profiles],
        "protocol": PROTOCOL,
        "receipt_content_sha256": receipt.content_sha256,
        "receipt_file_sha256": receipt_file_sha256,
        "replay_command": list(_PUBLIC_SUMMARY_REPLAY_COMMAND),
        "replay_reloads_exact_source_artifacts": True,
        "result_content_sha256": result.content_sha256,
        "result_file_sha256": result_file_sha256,
        "schema_version": PUBLIC_SUMMARY_SCHEMA,
    }
    payload["content_sha256"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    try:
        summary = IFEMPinnedMathlibProfilePublicSummaryV1.model_validate(payload)
    except ValueError as error:
        raise IFEMPinnedProfileError("generated public summary is invalid") from error
    _assert_public_summary_redacted(
        observation,
        render_ifem_pinned_mathlib_profile_public_summary(summary),
    )
    return summary


def validate_ifem_pinned_mathlib_profile_public_summary_bindings(
    summary: IFEMPinnedMathlibProfilePublicSummaryV1,
    plan: IFEMPinnedMathlibProfilePlanV1,
    receipt: IFEMPinnedMathlibProfileBuildReceiptV1,
    observation: IFEMPinnedMathlibProfileObservationsV1,
    result: IFEMPinnedMathlibProfileResultV1,
    *,
    plan_file_sha256: str,
    receipt_file_sha256: str,
    observation_file_sha256: str,
    result_file_sha256: str,
) -> None:
    """Reject a public record that cannot be replayed from its exact four sources."""

    expected = build_ifem_pinned_mathlib_profile_public_summary(
        plan,
        receipt,
        observation,
        result,
        plan_file_sha256=plan_file_sha256,
        receipt_file_sha256=receipt_file_sha256,
        observation_file_sha256=observation_file_sha256,
        result_file_sha256=result_file_sha256,
    )
    if summary != expected:
        raise IFEMPinnedProfileError("public summary differs from the exact source projection")


def render_ifem_pinned_mathlib_profile_public_summary(
    summary: IFEMPinnedMathlibProfilePublicSummaryV1,
) -> bytes:
    return canonical_json_bytes(summary.model_dump(mode="json")) + b"\n"


def write_ifem_pinned_mathlib_profile_public_summary_once(
    path: Path,
    summary: IFEMPinnedMathlibProfilePublicSummaryV1,
) -> None:
    _write_once(path, render_ifem_pinned_mathlib_profile_public_summary(summary))


def docker_query_command(
    plan: IFEMPinnedMathlibProfilePlanV1,
    *,
    child_image: str,
    profile: IFEMPinnedProfileV1,
) -> tuple[str, ...]:
    """Render, but never execute, the exact isolated query command for one profile."""

    return _pinned_profile_docker_command(plan, child_image=child_image, profile=profile)


def _write_once(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError:
        try:
            if _read_regular_file_bytes(path, label="existing output") != content:
                raise IFEMPinnedProfileError("output already exists with different bytes")
        except OSError as error:
            raise IFEMPinnedProfileError("cannot inspect an existing output") from error


def write_model_once(path: Path, model: ContractModel) -> None:
    _write_once(path, canonical_json_bytes(model) + b"\n")


def parse_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN_PATH)
    subparsers = parser.add_subparsers(dest="command", required=True)
    materialize = subparsers.add_parser(
        "materialize-plan", help="write the immutable no-run plan from the frozen census"
    )
    materialize.add_argument("--out", type=Path, default=DEFAULT_PLAN_PATH)
    subparsers.add_parser("check-plan", help="validate the frozen census and child-image inputs")
    commands = subparsers.add_parser("render-commands", help="render isolated Docker commands only")
    commands.add_argument("--child-image", required=True)
    build = subparsers.add_parser(
        "build-child-image",
        help="build the staged local child image with Docker networking disabled",
    )
    build.add_argument("--receipt-out", type=Path, required=True)
    verify = subparsers.add_parser(
        "verify-child-image", help="verify one receipt-bound local child image"
    )
    verify.add_argument("--receipt", type=Path, required=True)
    run = subparsers.add_parser(
        "run", help="execute all five receipt-bound singleton profile observations"
    )
    run.add_argument("--receipt", type=Path, required=True)
    run.add_argument("--observation-out", type=Path, required=True)
    run.add_argument("--result-out", type=Path, required=True)
    not_run = subparsers.add_parser("not-run", help="write an honest non-execution result")
    not_run.add_argument("--out", type=Path, required=True)
    not_run.add_argument(
        "--reason",
        choices=("operator_not_run", "child_image_unavailable", "pinned_runtime_unavailable"),
        required=True,
    )
    normalize = subparsers.add_parser("normalize", help="normalize five pre-collected raw records")
    normalize.add_argument("--receipt", type=Path, required=True)
    normalize.add_argument(
        "--raw",
        action="append",
        required=True,
        metavar="PROFILE_ID=PATH",
        help="one raw image-owned record per fixed profile",
    )
    normalize.add_argument("--observation-out", type=Path, required=True)
    normalize.add_argument("--result-out", type=Path, required=True)
    public_summary = subparsers.add_parser(
        "public-summary",
        help="write a redacted, replay-bound summary of completed profile evidence",
    )
    public_summary.add_argument("--receipt", type=Path, required=True)
    public_summary.add_argument("--observation", type=Path, required=True)
    public_summary.add_argument("--result", type=Path, required=True)
    public_summary.add_argument("--out", type=Path, required=True)
    return parser.parse_args(arguments)


def _parse_raw_file_specs(specifications: Sequence[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for specification in specifications:
        profile_id, separator, path_text = specification.partition("=")
        if not separator or not profile_id or not path_text or profile_id in result:
            raise IFEMPinnedProfileError(
                "raw record arguments must be unique PROFILE_ID=PATH pairs"
            )
        try:
            result[profile_id] = Path(path_text).read_text(encoding="utf-8")
        except OSError as error:
            raise IFEMPinnedProfileError("cannot read raw profile record") from error
    return result


def main(arguments: Sequence[str] | None = None) -> int:
    namespace = parse_arguments(arguments)
    if namespace.command == "materialize-plan":
        plan = build_ifem_pinned_mathlib_profile_plan()
        write_model_once(namespace.out.resolve(), plan)
        print(plan.content_sha256)
        return 0
    if namespace.command == "public-summary":
        (
            plan,
            receipt,
            observation,
            result,
            plan_file_sha256,
            receipt_file_sha256,
            observation_file_sha256,
            result_file_sha256,
        ) = _load_public_summary_inputs(
            plan_path=namespace.plan.resolve(),
            receipt_path=namespace.receipt.resolve(),
            observation_path=namespace.observation.resolve(),
            result_path=namespace.result.resolve(),
        )
        summary = build_ifem_pinned_mathlib_profile_public_summary(
            plan,
            receipt,
            observation,
            result,
            plan_file_sha256=plan_file_sha256,
            receipt_file_sha256=receipt_file_sha256,
            observation_file_sha256=observation_file_sha256,
            result_file_sha256=result_file_sha256,
        )
        write_ifem_pinned_mathlib_profile_public_summary_once(namespace.out.resolve(), summary)
        print(summary.content_sha256)
        return 0
    plan = load_ifem_pinned_mathlib_profile_plan(namespace.plan.resolve())
    validate_profile_plan_bindings(plan)
    if namespace.command == "check-plan":
        print(plan.content_sha256)
        return 0
    if namespace.command == "render-commands":
        output = {
            "commands": [
                list(docker_query_command(plan, child_image=namespace.child_image, profile=profile))
                for profile in plan.profiles
            ],
            "plan_content_sha256": plan.content_sha256,
            "semantic_classification_authorized": False,
        }
        print(json.dumps(output, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if namespace.command == "build-child-image":
        receipt = build_ifem_pinned_mathlib_profile_child_image(plan)
        write_model_once(namespace.receipt_out.resolve(), receipt)
        print(receipt.content_sha256)
        return 0
    if namespace.command == "verify-child-image":
        receipt = load_ifem_pinned_mathlib_profile_build_receipt(namespace.receipt.resolve())
        verify_ifem_pinned_mathlib_profile_child_image(plan, receipt)
        print(receipt.content_sha256)
        return 0
    if namespace.command == "run":
        receipt = load_ifem_pinned_mathlib_profile_build_receipt(namespace.receipt.resolve())
        observation = run_ifem_pinned_mathlib_profile_queries(plan, receipt)
        write_model_once(namespace.observation_out.resolve(), observation)
        write_model_once(namespace.result_out.resolve(), completed_result(plan, observation))
        print(observation.content_sha256)
        return 0
    if namespace.command == "not-run":
        write_model_once(namespace.out, not_run_result(plan, reason=namespace.reason))
        return 0
    if namespace.command == "normalize":
        receipt = load_ifem_pinned_mathlib_profile_build_receipt(namespace.receipt.resolve())
        verify_ifem_pinned_mathlib_profile_child_image(plan, receipt)
        observation = normalize_profile_observations(
            _parse_raw_file_specs(namespace.raw), plan=plan, child_image=receipt.child_image
        )
        validate_profile_observation_bindings(plan, receipt, observation)
        write_model_once(namespace.observation_out, observation)
        write_model_once(namespace.result_out, completed_result(plan, observation))
        return 0
    raise IFEMPinnedProfileError("unsupported pinned mathlib profile command")


if __name__ == "__main__":
    raise SystemExit(main())
