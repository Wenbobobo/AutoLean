"""Render a narrow, non-authoritative local-use request for the locked iFEM lane.

This module deliberately creates a request for a later source-rights decision.
It does not create a ``RightsRecordV1``, approve local processing, read cached
source bytes, make a provider request, or create a Builder--Prover bridge.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from collections.abc import Sequence
from pathlib import Path
from typing import Final, Literal, Never, Self, cast

from autolean_contracts import StableIdentifierV1, canonical_json_bytes, stable_identifier
from autolean_contracts.base import ContractModel
from pydantic import Field, model_validator

from .discovery_manifest import (
    DiscoveryLaneManifestV1,
    DiscoveryLaneV1,
    DiscoveryManifestError,
    load_discovery_lane_manifest,
)

ROOT = Path(__file__).resolve().parents[3]
IFEM_LOCAL_USE_REQUEST_SCHEMA: Final[Literal["autolean.ifem-local-use-request.v1"]] = (
    "autolean.ifem-local-use-request.v1"
)
IFEM_LOCAL_USE_REQUEST_PROTOCOL: Final[Literal["autolean.builder-ifem-local-use-request.v1"]] = (
    "autolean.builder-ifem-local-use-request.v1"
)
IFEM_LOCAL_USE_REQUEST_KIND: Final[Literal["pending_source_rights_local_use_request"]] = (
    "pending_source_rights_local_use_request"
)
IFEM_LOCAL_USE_REQUEST_NAMESPACE: Final[Literal["ifem-local-use-request"]] = (
    "ifem-local-use-request"
)
IFEM_LANE_ID: Final[Literal["ifem-coercive-galerkin"]] = "ifem-coercive-galerkin"
DEFAULT_DISCOVERY_MANIFEST_PATH = (
    ROOT / "Builder" / "pilots" / "discovery" / "phase-2-active-lanes.v1.json"
)

_SHA256 = r"^[0-9a-f]{64}$"
_SHA1 = r"^[0-9a-f]{40}$"
_IFEM_SOURCE_ID: Final[Literal["ifem-chapters-01-10"]] = "ifem-chapters-01-10"
_IFEM_REPOSITORY_URL: Final[Literal["https://github.com/JSchoeberl/iFEM"]] = (
    "https://github.com/JSchoeberl/iFEM"
)
_IFEM_REVISION = "a4ab841c4e5ec726e9b7742c9dcb352cb9645736"
_IFEM_SOURCE_LOCK_RECEIPT_SHA256 = (
    "74eca6689fe69dcbf2f34ea524a99cacc2054c0a39cfecfb11887c29e13cf239"
)
_IFEM_REFERENCE_MANIFEST_CANDIDATE_SHA256 = (
    "4a5d859d77b606d6e485d98bd3e4afc41f6c566c6fb09f5e3dc2b2a539f18398"
)
_CC_BY_4_LICENSE_URL: Final[Literal["https://creativecommons.org/licenses/by/4.0/"]] = (
    "https://creativecommons.org/licenses/by/4.0/"
)
_IFEM_LICENSE_EVIDENCE_URL: Final[
    Literal[
        "https://github.com/JSchoeberl/iFEM/blob/a4ab841c4e5ec726e9b7742c9dcb352cb9645736/LICENSE"
    ]
] = "https://github.com/JSchoeberl/iFEM/blob/a4ab841c4e5ec726e9b7742c9dcb352cb9645736/LICENSE"
_IFEM_LICENSE_BLOB_SHA1 = "7aa2c7d055857957fc9464109c305df6916f3f30"
_IFEM_LICENSE_SHA256 = "91030ffc2d2f295670d43f67ac5c9f9ee7b9ace6609f5bcf6990fbd68f2665a0"
_FORBIDDEN_RENDERED_FIELDS: Final[tuple[bytes, ...]] = (
    b'"source_text"',
    b'"source_path"',
    b'"prompt"',
)


class IFEMLocalUseRequestError(ValueError):
    """The narrow iFEM local-use request crossed its pending-decision boundary."""


class IFEMLocalUseRequestLicenseV1(ContractModel):
    """Pinned CC BY 4.0 metadata, not a conclusion about a requested use."""

    expression: Literal["CC-BY-4.0"] = "CC-BY-4.0"
    license_url: Literal["https://creativecommons.org/licenses/by/4.0/"] = _CC_BY_4_LICENSE_URL
    evidence_url: Literal[
        "https://github.com/JSchoeberl/iFEM/blob/a4ab841c4e5ec726e9b7742c9dcb352cb9645736/LICENSE"
    ] = _IFEM_LICENSE_EVIDENCE_URL
    license_blob_sha1: str = Field(default=_IFEM_LICENSE_BLOB_SHA1, pattern=_SHA1)
    license_sha256: str = Field(default=_IFEM_LICENSE_SHA256, pattern=_SHA256)

    @model_validator(mode="after")
    def validate_license(self) -> Self:
        if self.license_blob_sha1 != _IFEM_LICENSE_BLOB_SHA1:
            raise ValueError("local-use request license blob does not bind the locked iFEM license")
        if self.license_sha256 != _IFEM_LICENSE_SHA256:
            raise ValueError("local-use request license hash does not bind the locked iFEM license")
        return self


class IFEMLocalUseRequestSourceBindingV1(ContractModel):
    """Digest-only binding to the exact current iFEM discovery lane."""

    lane_id: Literal["ifem-coercive-galerkin"] = IFEM_LANE_ID
    source_id: Literal["ifem-chapters-01-10"] = _IFEM_SOURCE_ID
    official_record_url: Literal["https://github.com/JSchoeberl/iFEM"] = _IFEM_REPOSITORY_URL
    resolved_revision: str = Field(default=_IFEM_REVISION, pattern=_SHA1)
    source_lock_receipt_sha256: str = Field(
        default=_IFEM_SOURCE_LOCK_RECEIPT_SHA256,
        pattern=_SHA256,
    )
    reference_manifest_candidate_sha256: str = Field(
        default=_IFEM_REFERENCE_MANIFEST_CANDIDATE_SHA256,
        pattern=_SHA256,
    )
    source_bytes_state: Literal["acquired_local_only"] = "acquired_local_only"
    rights_state: Literal["metadata_verified_egress_pending"] = "metadata_verified_egress_pending"
    license: IFEMLocalUseRequestLicenseV1 = Field(default_factory=IFEMLocalUseRequestLicenseV1)

    @model_validator(mode="after")
    def validate_source_binding(self) -> Self:
        if self.resolved_revision != _IFEM_REVISION:
            raise ValueError("local-use request revision does not bind the locked iFEM lane")
        if self.source_lock_receipt_sha256 != _IFEM_SOURCE_LOCK_RECEIPT_SHA256:
            raise ValueError("local-use request source-lock receipt does not bind the iFEM lane")
        if self.reference_manifest_candidate_sha256 != _IFEM_REFERENCE_MANIFEST_CANDIDATE_SHA256:
            raise ValueError(
                "local-use request reference-manifest candidate does not bind the iFEM lane"
            )
        return self


class IFEMLocalUseRequestScopeV1(ContractModel):
    """The only requested operation and all expressly excluded operations."""

    local_model_processing: Literal["requested_not_authorized"] = "requested_not_authorized"
    requested_endpoint_class: Literal["local"] = "local"
    external_source_text_egress: Literal["forbidden"] = "forbidden"
    source_redistribution: Literal["forbidden"] = "forbidden"
    source_training: Literal["forbidden"] = "forbidden"
    source_embedding: Literal["forbidden"] = "forbidden"


class IFEMLocalUseRequestAuthorityV1(ContractModel):
    """This request carries no rights, execution, semantic, or promotion authority."""

    schema_version: Literal["autolean.ifem-local-use-request-authority.v1"] = (
        "autolean.ifem-local-use-request-authority.v1"
    )
    rights_record_created: Literal[False] = False
    rights_decision_authorized: Literal[False] = False
    local_processing_authorized: Literal[False] = False
    external_egress_authorized: Literal[False] = False
    model_execution_authorized: Literal[False] = False
    semantic_review_authorized: Literal[False] = False
    builder_freeze_authorized: Literal[False] = False
    prover_handoff_authorized: Literal[False] = False
    promotion_authorized: Literal[False] = False


class IFEMLocalUseRequestV1(ContractModel):
    """A write-once request for later source-rights review, never an authorization."""

    schema_version: Literal["autolean.ifem-local-use-request.v1"] = IFEM_LOCAL_USE_REQUEST_SCHEMA
    protocol: Literal["autolean.builder-ifem-local-use-request.v1"] = (
        IFEM_LOCAL_USE_REQUEST_PROTOCOL
    )
    artifact_kind: Literal["pending_source_rights_local_use_request"] = IFEM_LOCAL_USE_REQUEST_KIND
    request_id: StableIdentifierV1
    discovery_manifest_content_sha256: str = Field(pattern=_SHA256)
    source: IFEMLocalUseRequestSourceBindingV1
    requested_scope: IFEMLocalUseRequestScopeV1 = Field(default_factory=IFEMLocalUseRequestScopeV1)
    request_status: Literal["pending_operator_rights_decision"] = "pending_operator_rights_decision"
    source_text_included: Literal[False] = False
    source_path_included: Literal[False] = False
    prompt_included: Literal[False] = False
    authority: IFEMLocalUseRequestAuthorityV1 = Field(
        default_factory=IFEMLocalUseRequestAuthorityV1
    )
    builder_freeze: Literal["forbidden"] = "forbidden"
    prover_handoff: Literal["forbidden"] = "forbidden"
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_request(self) -> Self:
        expected_id = _request_id(
            self.discovery_manifest_content_sha256,
            source_lock_receipt_sha256=self.source.source_lock_receipt_sha256,
            reference_manifest_candidate_sha256=self.source.reference_manifest_candidate_sha256,
        )
        if self.request_id != expected_id:
            raise ValueError(
                "local-use request id does not bind its manifest and source identities"
            )
        if self.requested_scope != IFEMLocalUseRequestScopeV1():
            raise ValueError(
                "local-use request scope widened or no longer requests local processing"
            )
        if self.authority != IFEMLocalUseRequestAuthorityV1():
            raise ValueError("local-use request authority flags drifted")
        if self.content_sha256 != self.computed_content_sha256():
            raise ValueError("local-use request content hash does not match its payload")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(dict[str, object], self.model_dump(mode="json", exclude={"content_sha256"}))

    def computed_content_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.content_payload())).hexdigest()

    def assert_not_authoritative(self) -> Never:
        raise IFEMLocalUseRequestError(
            "iFEM local-use request is pending a source-rights decision and cannot authorize "
            "processing, freeze a statement, or hand work to Prover"
        )

    def freeze_statement(self) -> Never:
        self.assert_not_authoritative()

    def handoff_to_prover(self) -> Never:
        self.assert_not_authoritative()


def _request_id(
    manifest_content_sha256: str,
    *,
    source_lock_receipt_sha256: str,
    reference_manifest_candidate_sha256: str,
) -> StableIdentifierV1:
    return stable_identifier(
        IFEM_LOCAL_USE_REQUEST_NAMESPACE,
        ":".join(
            (
                IFEM_LANE_ID,
                manifest_content_sha256,
                source_lock_receipt_sha256,
                reference_manifest_candidate_sha256,
            )
        ),
    )


def _canonical_manifest_sha256(manifest: DiscoveryLaneManifestV1) -> str:
    return hashlib.sha256(manifest.canonical_bytes()).hexdigest()


def _ifem_lane(manifest: DiscoveryLaneManifestV1) -> DiscoveryLaneV1:
    lanes = tuple(lane for lane in manifest.lanes if lane.lane_id == IFEM_LANE_ID)
    if len(lanes) != 1:
        raise IFEMLocalUseRequestError(
            "discovery manifest must contain exactly one locked iFEM lane"
        )
    return lanes[0]


def _source_binding_from_manifest(
    manifest: DiscoveryLaneManifestV1,
) -> IFEMLocalUseRequestSourceBindingV1:
    lane = _ifem_lane(manifest)
    source = lane.source
    if source.source_id != _IFEM_SOURCE_ID or source.official_record_url != _IFEM_REPOSITORY_URL:
        raise IFEMLocalUseRequestError("discovery manifest iFEM source identity drifted")
    if source.resolved_revision != _IFEM_REVISION:
        raise IFEMLocalUseRequestError("discovery manifest iFEM revision drifted")
    if source.source_bytes_state.value != "acquired_local_only":
        raise IFEMLocalUseRequestError("discovery manifest iFEM source is not acquired local-only")
    if source.rights_state.value != "metadata_verified_egress_pending":
        raise IFEMLocalUseRequestError("discovery manifest iFEM rights state is not pending")
    if (
        source.model_egress_ceiling != "local_only"
        or source.external_model_source_text != "forbidden"
    ):
        raise IFEMLocalUseRequestError("discovery manifest iFEM egress ceiling widened")
    if (
        source.license_expression != "CC-BY-4.0"
        or source.license_evidence_url != _IFEM_LICENSE_EVIDENCE_URL
    ):
        raise IFEMLocalUseRequestError("discovery manifest iFEM license metadata drifted")
    if source.source_lock_receipt_sha256 != _IFEM_SOURCE_LOCK_RECEIPT_SHA256:
        raise IFEMLocalUseRequestError("discovery manifest iFEM source-lock receipt drifted")
    if source.reference_manifest_candidate_sha256 != _IFEM_REFERENCE_MANIFEST_CANDIDATE_SHA256:
        raise IFEMLocalUseRequestError(
            "discovery manifest iFEM reference-manifest candidate drifted"
        )
    return IFEMLocalUseRequestSourceBindingV1(
        resolved_revision=source.resolved_revision,
        source_lock_receipt_sha256=source.source_lock_receipt_sha256,
        reference_manifest_candidate_sha256=source.reference_manifest_candidate_sha256,
    )


def build_ifem_local_use_request_from_manifest(
    manifest_path: Path = DEFAULT_DISCOVERY_MANIFEST_PATH,
) -> IFEMLocalUseRequestV1:
    """Build the pending request from one strict replay of the public discovery manifest."""

    try:
        manifest = load_discovery_lane_manifest(manifest_path)
    except DiscoveryManifestError as error:
        raise IFEMLocalUseRequestError("cannot load the iFEM discovery manifest") from error
    source = _source_binding_from_manifest(manifest)
    manifest_content_sha256 = _canonical_manifest_sha256(manifest)
    payload: dict[str, object] = {
        "schema_version": IFEM_LOCAL_USE_REQUEST_SCHEMA,
        "protocol": IFEM_LOCAL_USE_REQUEST_PROTOCOL,
        "artifact_kind": IFEM_LOCAL_USE_REQUEST_KIND,
        "request_id": _request_id(
            manifest_content_sha256,
            source_lock_receipt_sha256=source.source_lock_receipt_sha256,
            reference_manifest_candidate_sha256=source.reference_manifest_candidate_sha256,
        ).model_dump(mode="json"),
        "discovery_manifest_content_sha256": manifest_content_sha256,
        "source": source.model_dump(mode="json"),
        "requested_scope": IFEMLocalUseRequestScopeV1().model_dump(mode="json"),
        "request_status": "pending_operator_rights_decision",
        "source_text_included": False,
        "source_path_included": False,
        "prompt_included": False,
        "authority": IFEMLocalUseRequestAuthorityV1().model_dump(mode="json"),
        "builder_freeze": "forbidden",
        "prover_handoff": "forbidden",
    }
    payload["content_sha256"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    try:
        return IFEMLocalUseRequestV1.model_validate(payload)
    except ValueError as error:
        raise IFEMLocalUseRequestError("generated iFEM local-use request is invalid") from error


def verify_ifem_local_use_request_against_manifest(
    request: IFEMLocalUseRequestV1,
    manifest_path: Path = DEFAULT_DISCOVERY_MANIFEST_PATH,
) -> None:
    """Require exact replay of the current manifest, not merely matching source hashes."""

    if type(request) is not IFEMLocalUseRequestV1:
        raise IFEMLocalUseRequestError("local-use request must use its exact typed model")
    try:
        actual = IFEMLocalUseRequestV1.model_validate(request.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as error:
        raise IFEMLocalUseRequestError("local-use request failed self-revalidation") from error
    expected = build_ifem_local_use_request_from_manifest(manifest_path)
    if actual != expected:
        raise IFEMLocalUseRequestError(
            "local-use request differs from exact discovery manifest replay"
        )


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise IFEMLocalUseRequestError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_regular_file(path: Path, *, label: str) -> bytes:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise IFEMLocalUseRequestError(f"{label} must be an unlinked regular file")
        return path.read_bytes()
    except OSError as error:
        raise IFEMLocalUseRequestError(f"cannot read {label}") from error


def render_ifem_local_use_request(request: IFEMLocalUseRequestV1) -> bytes:
    """Render the request as strict canonical JSON with no source payload surface."""

    if type(request) is not IFEMLocalUseRequestV1:
        raise IFEMLocalUseRequestError("local-use request must use its exact typed model")
    try:
        verified = IFEMLocalUseRequestV1.model_validate(request.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as error:
        raise IFEMLocalUseRequestError("local-use request failed self-revalidation") from error
    rendered = canonical_json_bytes(verified.model_dump(mode="json")) + b"\n"
    if any(field in rendered for field in _FORBIDDEN_RENDERED_FIELDS):
        raise IFEMLocalUseRequestError("local-use request rendering leaked a source payload field")
    return rendered


def load_ifem_local_use_request(path: Path) -> IFEMLocalUseRequestV1:
    """Load only a strict canonical request; callers still need manifest replay."""

    raw = _read_regular_file(path, label="iFEM local-use request")
    try:
        payload = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IFEMLocalUseRequestError("iFEM local-use request is not strict UTF-8 JSON") from error
    if not isinstance(payload, dict):
        raise IFEMLocalUseRequestError("iFEM local-use request must be a JSON object")
    try:
        request = IFEMLocalUseRequestV1.model_validate(payload)
    except ValueError as error:
        raise IFEMLocalUseRequestError("iFEM local-use request is invalid") from error
    if render_ifem_local_use_request(request) != raw:
        raise IFEMLocalUseRequestError("iFEM local-use request is not canonically rendered")
    return request


def _write_once(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError:
        existing = _read_regular_file(path, label="existing iFEM local-use request")
        if existing != content:
            raise IFEMLocalUseRequestError(
                "iFEM local-use request output already exists with different bytes"
            ) from None


def materialize_ifem_local_use_request_from_manifest_once(
    output_path: Path,
    manifest_path: Path = DEFAULT_DISCOVERY_MANIFEST_PATH,
) -> IFEMLocalUseRequestV1:
    """Write one request exactly once, then read and replay it against the manifest."""

    request = build_ifem_local_use_request_from_manifest(manifest_path)
    _write_once(output_path, render_ifem_local_use_request(request))
    persisted = load_ifem_local_use_request(output_path)
    if persisted != request:
        raise IFEMLocalUseRequestError("persisted iFEM local-use request differs from its replay")
    verify_ifem_local_use_request_against_manifest(persisted, manifest_path)
    return persisted


def parse_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--discovery-manifest", type=Path, default=DEFAULT_DISCOVERY_MANIFEST_PATH)
    parser.add_argument("--out", type=Path, required=True)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    namespace = parse_arguments(arguments)
    request = materialize_ifem_local_use_request_from_manifest_once(
        namespace.out,
        namespace.discovery_manifest,
    )
    print(request.content_sha256)
    return 0


__all__ = [
    "DEFAULT_DISCOVERY_MANIFEST_PATH",
    "IFEM_LANE_ID",
    "IFEM_LOCAL_USE_REQUEST_KIND",
    "IFEM_LOCAL_USE_REQUEST_NAMESPACE",
    "IFEM_LOCAL_USE_REQUEST_PROTOCOL",
    "IFEM_LOCAL_USE_REQUEST_SCHEMA",
    "IFEMLocalUseRequestAuthorityV1",
    "IFEMLocalUseRequestError",
    "IFEMLocalUseRequestLicenseV1",
    "IFEMLocalUseRequestScopeV1",
    "IFEMLocalUseRequestSourceBindingV1",
    "IFEMLocalUseRequestV1",
    "build_ifem_local_use_request_from_manifest",
    "load_ifem_local_use_request",
    "main",
    "materialize_ifem_local_use_request_from_manifest_once",
    "render_ifem_local_use_request",
    "verify_ifem_local_use_request_against_manifest",
]
