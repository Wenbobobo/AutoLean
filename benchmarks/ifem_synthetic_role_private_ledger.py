"""Operator-private persistence for the sixteen-case iFEM synthetic-role run.

The public iFEM bridge intentionally treats an executor result as transient.  This module
adds the missing operator-side durability without changing the bridge, provider, or
control-plane interfaces:

* an exact request coordinate is journaled before a provider call can be made;
* an existing private response CAS stores the raw output; and
* immutable, authenticated journal events and a sixteen-case manifest make recovery
  possible without dispatching the same coordinate twice.

The ledger accepts no oracle and never renders one.  Its public projection has only
request bindings and a keyed output commitment.  It is calibration plumbing, not
benchmark, semantic, freezing, or Prover authority.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import stat
from abc import ABC, abstractmethod
from collections.abc import Iterable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, Never, Protocol, Self, SupportsIndex, cast, runtime_checkable

from autolean_builder.ifem_structural_role_probes import IFEMStructuralProbeRoleV1
from autolean_contracts import (
    DigestV1,
    HashKindV1,
    ModelResponseArtifactRefV1,
    OutboundRequestBodyV1,
    StableIdentifierV1,
    canonical_json_bytes,
    digest_model,
    digest_text,
)
from autolean_contracts.base import ContractModel
from autolean_contracts.hashing import require_digest_kind
from autolean_prover.providers import (
    ModelResponse,
    PrivateModelOutputStore,
    model_response_artifact,
)
from pydantic import ConfigDict, Field, model_validator

from benchmarks.ifem_synthetic_role_bridge import (
    IFEMSyntheticRoleExecutionV1,
    IFEMSyntheticRoleExecutor,
    IFEMSyntheticRoleModelOutputV1,
    IFEMSyntheticRolePreparedRequestV1,
    execute,
)
from benchmarks.ifem_synthetic_role_fixture import (
    IFEMSyntheticRolePublicFixtureV1,
    render_ifem_synthetic_role_fixture,
)

_SHA256 = r"^[0-9a-f]{64}$"
_IDENTIFIER = r"^[a-z][a-z0-9_.-]{0,127}$"
_AUTHENTICATION_TAG = r"^[A-Za-z0-9_-]{32,1024}$"
_FORBIDDEN_PUBLIC_MARKERS: Final[tuple[bytes, ...]] = (
    b'"text":',
    b'"response_id":',
    b'"artifact":',
    b'"oracle":',
    b"private-oracle",
    b'"path":',
    b'"secret":',
    b"secret-token",
)


class IFEMSyntheticRolePrivateLedgerError(ValueError):
    """A private iFEM ledger binding, state transition, or projection is invalid."""


class IFEMSyntheticRoleReconciliationRequired(IFEMSyntheticRolePrivateLedgerError):
    """A provider outcome may already exist, so automatic redispatch is forbidden."""


class IFEMSyntheticRolePrivateLedgerAuthenticator(ABC):
    """Injected operator-private authentication boundary for ledger events and commitments.

    A production deployment can back this interface with a non-exportable KMS/HSM key.  The
    authenticator never becomes part of a manifest, artifact, public projection, or log.
    """

    @property
    @abstractmethod
    def authenticator_id(self) -> str:
        """Return the non-secret key identifier."""

    @property
    @abstractmethod
    def authentication_scheme(self) -> str:
        """Return the non-secret implementation identifier."""

    @abstractmethod
    def authenticate(self, payload: bytes) -> str:
        """Return a deterministic authentication tag for private canonical bytes."""

    @abstractmethod
    def verify(self, payload: bytes, authentication_tag: str) -> bool:
        """Verify a tag without exposing key material."""

    def __getstate__(self) -> Never:
        raise TypeError("private ledger authenticator cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        del protocol
        raise TypeError("private ledger authenticator cannot be serialized")


class TestOnlyIFEMSyntheticRoleHmacAuthenticator(IFEMSyntheticRolePrivateLedgerAuthenticator):
    """Deterministic HMAC fixture for local tests, never a production key adapter."""

    __slots__ = ("_secret",)
    __test__ = False

    def __init__(self, secret: bytes) -> None:
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise IFEMSyntheticRolePrivateLedgerError(
                "test-only private ledger HMAC secret must contain at least 32 bytes"
            )
        self._secret = bytes(secret)

    @property
    def authenticator_id(self) -> str:
        return "test-only-ifem-private-ledger-hmac-v1"

    @property
    def authentication_scheme(self) -> str:
        return "test-only-hmac-sha256-nonproduction"

    def authenticate(self, payload: bytes) -> str:
        return hmac.new(self._secret, payload, hashlib.sha256).hexdigest()

    def verify(self, payload: bytes, authentication_tag: str) -> bool:
        return hmac.compare_digest(self.authenticate(payload), authentication_tag)


class IFEMSyntheticRolePrivateLedgerAuthorityV1(ContractModel):
    """Hard-negative authority boundary retained on every public projection."""

    schema_version: Literal["autolean.ifem-synthetic-role-private-ledger-authority.v1"] = (
        "autolean.ifem-synthetic-role-private-ledger-authority.v1"
    )
    raw_output_public: Literal[False] = False
    private_reference_public: Literal[False] = False
    semantic_equivalence_claimed: Literal[False] = False
    benchmark_authority: Literal[False] = False
    statement_contract_created: Literal[False] = False
    freeze_allowed: Literal[False] = False
    prover_handoff_allowed: Literal[False] = False
    promotion_allowed: Literal[False] = False


class IFEMSyntheticRolePrivateCoordinateV1(ContractModel):
    """The complete non-secret coordinate that must stay fixed across recovery."""

    schema_version: Literal["autolean.ifem-synthetic-role-private-coordinate.v1"] = (
        "autolean.ifem-synthetic-role-private-coordinate.v1"
    )
    fixture_content_sha256: str = Field(pattern=_SHA256)
    case_id: StableIdentifierV1
    role: IFEMStructuralProbeRoleV1
    request_body_binding: OutboundRequestBodyV1
    logical_request_digest: DigestV1
    provider_id: str = Field(pattern=_IDENTIFIER)
    model_id: str = Field(min_length=1, max_length=256)
    provider_configuration_digest: DigestV1

    @model_validator(mode="after")
    def validate_coordinate(self) -> Self:
        try:
            require_digest_kind(
                self.logical_request_digest,
                HashKindV1.PROMPT,
                "logical_request_digest",
            )
            require_digest_kind(
                self.provider_configuration_digest,
                HashKindV1.CONFIG,
                "provider_configuration_digest",
            )
            require_digest_kind(
                self.request_body_binding.body_hash,
                HashKindV1.OUTBOUND_REQUEST_BODY,
                "request_body_binding.body_hash",
            )
        except ValueError as error:
            raise ValueError(str(error)) from error
        return self

    def coordinate_hash(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.model_dump(mode="json"))).hexdigest()

    @classmethod
    def from_prepared(
        cls,
        prepared: IFEMSyntheticRolePreparedRequestV1,
    ) -> IFEMSyntheticRolePrivateCoordinateV1:
        if not isinstance(prepared, IFEMSyntheticRolePreparedRequestV1):
            raise IFEMSyntheticRolePrivateLedgerError(
                "private coordinate requires an exact prepared request"
            )
        return cls(
            fixture_content_sha256=prepared.fixture_content_sha256,
            case_id=prepared.case_id,
            role=prepared.role,
            request_body_binding=prepared.body_binding,
            logical_request_digest=prepared.logical_request_digest,
            provider_id=prepared.provider_id,
            model_id=prepared.model_id,
            provider_configuration_digest=prepared.provider_configuration_digest,
        )


class IFEMSyntheticRolePrivateLedgerEventV1(ContractModel):
    """One immutable private journal event; artifact references are never public."""

    model_config = ConfigDict(hide_input_in_errors=True)

    schema_version: Literal["autolean.ifem-synthetic-role-private-ledger-event.v1"] = (
        "autolean.ifem-synthetic-role-private-ledger-event.v1"
    )
    transition: Literal["dispatch_started", "cas_expected", "response_persisted"]
    coordinate: IFEMSyntheticRolePrivateCoordinateV1
    artifact: ModelResponseArtifactRefV1 | None = None
    commitment_nonce: str | None = Field(default=None, pattern=_SHA256)
    authenticator_id: str = Field(pattern=_IDENTIFIER)
    authentication_scheme: str = Field(pattern=_IDENTIFIER)
    authentication_tag: str = Field(pattern=_AUTHENTICATION_TAG)

    @model_validator(mode="after")
    def validate_transition(self) -> Self:
        has_private_output = self.artifact is not None or self.commitment_nonce is not None
        if self.transition == "dispatch_started" and has_private_output:
            raise ValueError("dispatch_started cannot contain a private output")
        if self.transition != "dispatch_started" and (
            self.artifact is None or self.commitment_nonce is None
        ):
            raise ValueError("private output transition requires artifact and commitment nonce")
        return self

    def unsigned_payload(self) -> dict[str, object]:
        return cast(
            dict[str, object],
            self.model_dump(mode="json", exclude={"authentication_tag"}),
        )


class IFEMSyntheticRolePrivateOutputEntryV1(ContractModel):
    """One terminal private output binding inside a sixteen-case immutable manifest."""

    schema_version: Literal["autolean.ifem-synthetic-role-private-output-entry.v1"] = (
        "autolean.ifem-synthetic-role-private-output-entry.v1"
    )
    coordinate: IFEMSyntheticRolePrivateCoordinateV1
    artifact: ModelResponseArtifactRefV1
    commitment_nonce: str = Field(pattern=_SHA256)


class IFEMSyntheticRolePrivateManifestV1(ContractModel):
    """Private full-run manifest; raw model output remains in the injected response CAS."""

    schema_version: Literal["autolean.ifem-synthetic-role-private-manifest.v1"] = (
        "autolean.ifem-synthetic-role-private-manifest.v1"
    )
    run_identity_sha256: str = Field(pattern=_SHA256)
    fixture_content_sha256: str = Field(pattern=_SHA256)
    entries: tuple[IFEMSyntheticRolePrivateOutputEntryV1, ...]

    @model_validator(mode="after")
    def validate_entries(self) -> Self:
        if len(self.entries) != 16:
            raise ValueError("private iFEM manifest requires exactly sixteen entries")
        coordinates = tuple(entry.coordinate.coordinate_hash() for entry in self.entries)
        if coordinates != tuple(sorted(coordinates)) or len(coordinates) != len(set(coordinates)):
            raise ValueError("private iFEM manifest coordinates must be canonical and unique")
        if any(
            entry.coordinate.fixture_content_sha256 != self.fixture_content_sha256
            for entry in self.entries
        ):
            raise ValueError("private iFEM manifest fixture binding is inconsistent")
        return self

    def content_hash(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.model_dump(mode="json"))).hexdigest()


class IFEMSyntheticRolePrivateManifestRecordV1(ContractModel):
    """Authenticated on-disk wrapper for one immutable private manifest."""

    model_config = ConfigDict(hide_input_in_errors=True)

    schema_version: Literal["autolean.ifem-synthetic-role-private-manifest-record.v1"] = (
        "autolean.ifem-synthetic-role-private-manifest-record.v1"
    )
    manifest: IFEMSyntheticRolePrivateManifestV1
    authenticator_id: str = Field(pattern=_IDENTIFIER)
    authentication_scheme: str = Field(pattern=_IDENTIFIER)
    authentication_tag: str = Field(pattern=_AUTHENTICATION_TAG)

    def unsigned_payload(self) -> dict[str, object]:
        return cast(
            dict[str, object],
            self.model_dump(mode="json", exclude={"authentication_tag"}),
        )


class IFEMSyntheticRolePublicOutputCommitmentV1(ContractModel):
    """Public request-bound opaque commitment, never a CAS locator or response digest."""

    schema_version: Literal["autolean.ifem-synthetic-role-public-output-commitment.v1"] = (
        "autolean.ifem-synthetic-role-public-output-commitment.v1"
    )
    case_id: StableIdentifierV1
    role: IFEMStructuralProbeRoleV1
    request_body_binding: OutboundRequestBodyV1
    logical_request_digest: DigestV1
    provider_id: str = Field(pattern=_IDENTIFIER)
    model_id: str = Field(min_length=1, max_length=256)
    provider_configuration_digest: DigestV1
    output_commitment: DigestV1

    @model_validator(mode="after")
    def validate_commitment(self) -> Self:
        try:
            require_digest_kind(
                self.logical_request_digest,
                HashKindV1.PROMPT,
                "logical_request_digest",
            )
            require_digest_kind(
                self.provider_configuration_digest,
                HashKindV1.CONFIG,
                "provider_configuration_digest",
            )
            require_digest_kind(
                self.output_commitment,
                HashKindV1.MODEL_OUTPUT_COMMITMENT,
                "output_commitment",
            )
        except ValueError as error:
            raise ValueError(str(error)) from error
        return self


class IFEMSyntheticRolePublicLedgerProjectionV1(ContractModel):
    """Sanitized non-authoritative projection of one committed iFEM run."""

    schema_version: Literal["autolean.ifem-synthetic-role-public-ledger-projection.v1"] = (
        "autolean.ifem-synthetic-role-public-ledger-projection.v1"
    )
    fixture_content_sha256: str = Field(pattern=_SHA256)
    outputs: tuple[IFEMSyntheticRolePublicOutputCommitmentV1, ...]
    authority: IFEMSyntheticRolePrivateLedgerAuthorityV1 = Field(
        default_factory=IFEMSyntheticRolePrivateLedgerAuthorityV1
    )
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_projection(self) -> Self:
        if len(self.outputs) != 16:
            raise ValueError("public iFEM ledger projection requires exactly sixteen outputs")
        coordinates = tuple(
            (
                item.case_id.value,
                item.role.value,
                item.request_body_binding.body_hash.value,
                item.provider_configuration_digest.value,
            )
            for item in self.outputs
        )
        if coordinates != tuple(sorted(coordinates)) or len(coordinates) != len(set(coordinates)):
            raise ValueError("public iFEM ledger outputs must be canonical and unique")
        if self.content_sha256 != self.computed_content_sha256():
            raise ValueError("public iFEM ledger projection content hash does not match payload")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(
            dict[str, object],
            self.model_dump(mode="json", exclude={"content_sha256"}),
        )

    def computed_content_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.content_payload())).hexdigest()

    @property
    def is_promotable(self) -> Literal[False]:
        return False


@dataclass(frozen=True, slots=True)
class _LedgerState:
    dispatch: IFEMSyntheticRolePrivateLedgerEventV1 | None
    cas_expected: IFEMSyntheticRolePrivateLedgerEventV1 | None
    response_persisted: IFEMSyntheticRolePrivateLedgerEventV1 | None


@runtime_checkable
class IFEMSyntheticRolePrivateLedger(Protocol):
    """Provider-neutral persistence surface used by the iFEM calibration harness."""

    def execute_once(
        self,
        prepared: IFEMSyntheticRolePreparedRequestV1,
        executor: IFEMSyntheticRoleExecutor,
    ) -> IFEMSyntheticRoleExecutionV1: ...

    def persist_execution(
        self,
        execution: IFEMSyntheticRoleExecutionV1,
    ) -> IFEMSyntheticRoleExecutionV1: ...

    def recover_execution(
        self,
        prepared: IFEMSyntheticRolePreparedRequestV1,
    ) -> IFEMSyntheticRoleExecutionV1: ...

    def commit_manifest(
        self,
        fixture: IFEMSyntheticRolePublicFixtureV1,
        prepared_requests: Iterable[IFEMSyntheticRolePreparedRequestV1],
    ) -> IFEMSyntheticRolePrivateManifestV1: ...

    def public_projection(
        self,
        fixture: IFEMSyntheticRolePublicFixtureV1,
        prepared_requests: Iterable[IFEMSyntheticRolePreparedRequestV1],
    ) -> IFEMSyntheticRolePublicLedgerProjectionV1: ...


class LocalIFEMSyntheticRolePrivateLedger:
    """Single-host append-only ledger over an injected private response CAS.

    The CAS must be operator-private.  This adapter stores only event/manifest metadata under
    ``root``; both locations are intentionally excluded from public rendering and artifacts.
    """

    def __init__(
        self,
        root: Path,
        *,
        output_store: PrivateModelOutputStore,
        authenticator: IFEMSyntheticRolePrivateLedgerAuthenticator,
    ) -> None:
        if not isinstance(root, Path) or not root.is_absolute():
            raise IFEMSyntheticRolePrivateLedgerError(
                "private ledger root must be an absolute Path"
            )
        if not isinstance(output_store, PrivateModelOutputStore):
            raise IFEMSyntheticRolePrivateLedgerError(
                "private ledger requires a PrivateModelOutputStore"
            )
        if not isinstance(authenticator, IFEMSyntheticRolePrivateLedgerAuthenticator):
            raise IFEMSyntheticRolePrivateLedgerError(
                "private ledger requires an injected authenticator"
            )
        for label, value in (
            ("authenticator_id", authenticator.authenticator_id),
            ("authentication_scheme", authenticator.authentication_scheme),
        ):
            if not isinstance(value, str) or re.fullmatch(_IDENTIFIER, value) is None:
                raise IFEMSyntheticRolePrivateLedgerError(f"private ledger {label} is invalid")
        root.mkdir(parents=True, exist_ok=True)
        self._root = root.resolve(strict=True)
        if not self._root.is_dir() or _is_link_or_reparse_point(root):
            raise IFEMSyntheticRolePrivateLedgerError("private ledger root must be a directory")
        self._journal_root = self._root / "journal-v1"
        self._manifest_root = self._root / "manifests-v1"
        self._require_physical_directory(self._journal_root)
        self._require_physical_directory(self._manifest_root)
        self._output_store = output_store
        self._authenticator = authenticator

    def execute_once(
        self,
        prepared: IFEMSyntheticRolePreparedRequestV1,
        executor: IFEMSyntheticRoleExecutor,
    ) -> IFEMSyntheticRoleExecutionV1:
        """Execute a coordinate only if no durable state could represent a prior dispatch."""

        coordinate = IFEMSyntheticRolePrivateCoordinateV1.from_prepared(prepared)
        state = self._read_state(coordinate)
        if state.response_persisted is not None or state.cas_expected is not None:
            return self.recover_execution(prepared)
        if state.dispatch is not None:
            raise IFEMSyntheticRoleReconciliationRequired(
                "private dispatch is incomplete; automatic provider replay is forbidden"
            )
        self._append_event(
            transition="dispatch_started",
            coordinate=coordinate,
            require_new=True,
        )
        # Any exception from the executor intentionally leaves dispatch_started durable.  A later
        # process cannot distinguish an interrupted call from a completed call without operator
        # reconciliation, so it must not send the request again.
        execution = execute(prepared, executor)
        return self.persist_execution(execution)

    def persist_execution(
        self,
        execution: IFEMSyntheticRoleExecutionV1,
    ) -> IFEMSyntheticRoleExecutionV1:
        """Write a response CAS intent, persist the CAS object, then close the event ledger."""

        if not isinstance(execution, IFEMSyntheticRoleExecutionV1):
            raise IFEMSyntheticRolePrivateLedgerError(
                "private ledger requires an exact iFEM execution"
            )
        coordinate = IFEMSyntheticRolePrivateCoordinateV1.from_prepared(execution.prepared)
        state = self._read_state(coordinate)
        if state.dispatch is None:
            raise IFEMSyntheticRoleReconciliationRequired(
                "private output has no prior dispatch journal"
            )
        response = _response_from_execution(execution)
        artifact = _expected_artifact_ref(response)
        if state.response_persisted is not None:
            self._require_terminal_matches(
                state.response_persisted,
                coordinate=coordinate,
                artifact=artifact,
            )
            return self._execution_from_terminal(execution.prepared, state.response_persisted)

        if state.cas_expected is None:
            nonce = secrets.token_hex(32)
            expected = self._append_event(
                transition="cas_expected",
                coordinate=coordinate,
                artifact=artifact,
                commitment_nonce=nonce,
            )
        else:
            expected = state.cas_expected
            self._require_terminal_matches(expected, coordinate=coordinate, artifact=artifact)

        # The expected artifact reference is journaled before the CAS write.  If this process
        # dies after put_response, recovery verifies that exact reference and finishes without
        # calling a provider.
        stored = self._output_store.put_response(response)
        if stored != artifact:
            raise IFEMSyntheticRolePrivateLedgerError(
                "private response CAS returned a reference different from the expected artifact"
            )
        self._output_store.verify(stored)
        terminal = self._append_event(
            transition="response_persisted",
            coordinate=coordinate,
            artifact=stored,
            commitment_nonce=expected.commitment_nonce,
        )
        return self._execution_from_terminal(execution.prepared, terminal)

    def recover_execution(
        self,
        prepared: IFEMSyntheticRolePreparedRequestV1,
    ) -> IFEMSyntheticRoleExecutionV1:
        """Recover a terminal result, or finish a verified CAS intent without provider I/O."""

        coordinate = IFEMSyntheticRolePrivateCoordinateV1.from_prepared(prepared)
        state = self._read_state(coordinate)
        if state.response_persisted is not None:
            return self._execution_from_terminal(prepared, state.response_persisted)
        if state.cas_expected is not None:
            event = state.cas_expected
            assert event.artifact is not None
            try:
                self._output_store.verify(event.artifact)
            except Exception:
                raise IFEMSyntheticRoleReconciliationRequired(
                    "private CAS intent is incomplete; automatic provider replay is forbidden"
                ) from None
            terminal = self._append_event(
                transition="response_persisted",
                coordinate=coordinate,
                artifact=event.artifact,
                commitment_nonce=event.commitment_nonce,
            )
            return self._execution_from_terminal(prepared, terminal)
        if state.dispatch is not None:
            raise IFEMSyntheticRoleReconciliationRequired(
                "private dispatch is incomplete; automatic provider replay is forbidden"
            )
        raise IFEMSyntheticRoleReconciliationRequired(
            "private ledger has no execution for this coordinate"
        )

    def commit_manifest(
        self,
        fixture: IFEMSyntheticRolePublicFixtureV1,
        prepared_requests: Iterable[IFEMSyntheticRolePreparedRequestV1],
    ) -> IFEMSyntheticRolePrivateManifestV1:
        """Commit or recover one private immutable full-run manifest after all sixteen outputs."""

        verified_fixture = _revalidate_fixture(fixture)
        prepared = _validated_full_run(verified_fixture, prepared_requests)
        entries: list[IFEMSyntheticRolePrivateOutputEntryV1] = []
        for item in prepared:
            execution = self.recover_execution(item)
            coordinate = IFEMSyntheticRolePrivateCoordinateV1.from_prepared(execution.prepared)
            terminal = self._read_state(coordinate).response_persisted
            if terminal is None or terminal.artifact is None or terminal.commitment_nonce is None:
                raise IFEMSyntheticRoleReconciliationRequired(
                    "private terminal event cannot be reconciled"
                )
            entries.append(
                IFEMSyntheticRolePrivateOutputEntryV1(
                    coordinate=coordinate,
                    artifact=terminal.artifact,
                    commitment_nonce=terminal.commitment_nonce,
                )
            )
        entries.sort(key=lambda entry: entry.coordinate.coordinate_hash())
        run_identity = _run_identity(prepared)
        manifest = IFEMSyntheticRolePrivateManifestV1(
            run_identity_sha256=run_identity,
            fixture_content_sha256=verified_fixture.content_sha256,
            entries=tuple(entries),
        )
        record = self._signed_manifest_record(manifest)
        self._write_manifest_record(record)
        return manifest

    def read_manifest(
        self,
        fixture: IFEMSyntheticRolePublicFixtureV1,
        prepared_requests: Iterable[IFEMSyntheticRolePreparedRequestV1],
    ) -> IFEMSyntheticRolePrivateManifestV1:
        """Read the authenticated immutable manifest for a completely specified run."""

        verified_fixture = _revalidate_fixture(fixture)
        prepared = _validated_full_run(verified_fixture, prepared_requests)
        run_identity = _run_identity(prepared)
        try:
            payload = self._manifest_path(run_identity).read_bytes()
            record = IFEMSyntheticRolePrivateManifestRecordV1.model_validate_json(payload)
        except (OSError, ValueError):
            raise IFEMSyntheticRoleReconciliationRequired(
                "private iFEM manifest cannot be reconciled"
            ) from None
        if canonical_json_bytes(record.model_dump(mode="json")) != payload:
            raise IFEMSyntheticRoleReconciliationRequired("private iFEM manifest is not canonical")
        self._verify_manifest_record(record)
        if (
            record.manifest.run_identity_sha256 != run_identity
            or record.manifest.fixture_content_sha256 != verified_fixture.content_sha256
        ):
            raise IFEMSyntheticRoleReconciliationRequired(
                "private iFEM manifest binding is inconsistent"
            )
        expected_coordinates = tuple(
            sorted(
                IFEMSyntheticRolePrivateCoordinateV1.from_prepared(item).coordinate_hash()
                for item in prepared
            )
        )
        actual_coordinates = tuple(
            entry.coordinate.coordinate_hash() for entry in record.manifest.entries
        )
        if actual_coordinates != expected_coordinates:
            raise IFEMSyntheticRoleReconciliationRequired(
                "private iFEM manifest coordinates are inconsistent"
            )
        for entry in record.manifest.entries:
            state = self._read_state(entry.coordinate)
            terminal = state.response_persisted
            if terminal is None:
                raise IFEMSyntheticRoleReconciliationRequired(
                    "private iFEM manifest has no terminal ledger event"
                )
            self._require_terminal_matches(
                terminal,
                coordinate=entry.coordinate,
                artifact=entry.artifact,
                commitment_nonce=entry.commitment_nonce,
            )
            try:
                self._output_store.verify(entry.artifact)
            except Exception:
                raise IFEMSyntheticRoleReconciliationRequired(
                    "private iFEM manifest references an unavailable response"
                ) from None
        return record.manifest

    def public_projection(
        self,
        fixture: IFEMSyntheticRolePublicFixtureV1,
        prepared_requests: Iterable[IFEMSyntheticRolePreparedRequestV1],
    ) -> IFEMSyntheticRolePublicLedgerProjectionV1:
        """Return the only public projection after re-reading the authenticated manifest."""

        manifest = self.read_manifest(fixture, prepared_requests)
        outputs = tuple(
            sorted(
                (_public_commitment(entry, self._authenticator) for entry in manifest.entries),
                key=lambda item: (
                    item.case_id.value,
                    item.role.value,
                    item.request_body_binding.body_hash.value,
                    item.provider_configuration_digest.value,
                ),
            )
        )
        payload: dict[str, object] = {
            "schema_version": "autolean.ifem-synthetic-role-public-ledger-projection.v1",
            "fixture_content_sha256": manifest.fixture_content_sha256,
            "outputs": [item.model_dump(mode="json") for item in outputs],
            "authority": IFEMSyntheticRolePrivateLedgerAuthorityV1().model_dump(mode="json"),
        }
        payload["content_sha256"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
        return IFEMSyntheticRolePublicLedgerProjectionV1.model_validate(payload)

    def _append_event(
        self,
        *,
        transition: Literal["dispatch_started", "cas_expected", "response_persisted"],
        coordinate: IFEMSyntheticRolePrivateCoordinateV1,
        artifact: ModelResponseArtifactRefV1 | None = None,
        commitment_nonce: str | None = None,
        require_new: bool = False,
    ) -> IFEMSyntheticRolePrivateLedgerEventV1:
        unsigned: dict[str, object] = {
            "schema_version": "autolean.ifem-synthetic-role-private-ledger-event.v1",
            "transition": transition,
            "coordinate": coordinate.model_dump(mode="json"),
            "artifact": None if artifact is None else artifact.model_dump(mode="json"),
            "commitment_nonce": commitment_nonce,
            "authenticator_id": self._authenticator.authenticator_id,
            "authentication_scheme": self._authenticator.authentication_scheme,
        }
        tag = self._authenticate(unsigned)
        event = IFEMSyntheticRolePrivateLedgerEventV1.model_validate(
            {**unsigned, "authentication_tag": tag}
        )
        path = self._event_path(coordinate, transition)
        payload = canonical_json_bytes(event.model_dump(mode="json"))
        try:
            _write_private_exclusive(path, payload)
        except FileExistsError:
            existing = self._read_event(path, coordinate, transition)
            if existing != event:
                raise IFEMSyntheticRoleReconciliationRequired(
                    "private ledger transition conflicts with an existing immutable event"
                ) from None
            if require_new:
                raise IFEMSyntheticRoleReconciliationRequired(
                    "private dispatch was claimed concurrently; provider execution is forbidden"
                ) from None
            return existing
        return event

    def _read_state(self, coordinate: IFEMSyntheticRolePrivateCoordinateV1) -> _LedgerState:
        dispatch_path = self._event_path(coordinate, "dispatch_started")
        cas_expected_path = self._event_path(coordinate, "cas_expected")
        terminal_path = self._event_path(coordinate, "response_persisted")
        dispatch = self._read_event_if_exists(dispatch_path, coordinate, "dispatch_started")
        cas_expected = self._read_event_if_exists(cas_expected_path, coordinate, "cas_expected")
        response_persisted = self._read_event_if_exists(
            terminal_path,
            coordinate,
            "response_persisted",
        )
        if dispatch is None and (cas_expected is not None or response_persisted is not None):
            raise IFEMSyntheticRoleReconciliationRequired(
                "private ledger transition history is incomplete"
            )
        if cas_expected is None and response_persisted is not None:
            raise IFEMSyntheticRoleReconciliationRequired(
                "private ledger terminal event has no CAS intent"
            )
        if cas_expected is not None and response_persisted is not None:
            self._require_terminal_matches(
                response_persisted,
                coordinate=coordinate,
                artifact=cas_expected.artifact,
                commitment_nonce=cas_expected.commitment_nonce,
            )
        return _LedgerState(
            dispatch=dispatch,
            cas_expected=cas_expected,
            response_persisted=response_persisted,
        )

    def _read_event_if_exists(
        self,
        path: Path,
        coordinate: IFEMSyntheticRolePrivateCoordinateV1,
        transition: Literal["dispatch_started", "cas_expected", "response_persisted"],
    ) -> IFEMSyntheticRolePrivateLedgerEventV1 | None:
        try:
            return self._read_event(path, coordinate, transition)
        except FileNotFoundError:
            return None

    def _read_event(
        self,
        path: Path,
        coordinate: IFEMSyntheticRolePrivateCoordinateV1,
        transition: Literal["dispatch_started", "cas_expected", "response_persisted"],
    ) -> IFEMSyntheticRolePrivateLedgerEventV1:
        try:
            payload = path.read_bytes()
            event = IFEMSyntheticRolePrivateLedgerEventV1.model_validate_json(payload)
        except FileNotFoundError:
            raise
        except (OSError, ValueError):
            raise IFEMSyntheticRoleReconciliationRequired(
                "private ledger event cannot be reconciled"
            ) from None
        if (
            canonical_json_bytes(event.model_dump(mode="json")) != payload
            or event.coordinate != coordinate
            or event.transition != transition
        ):
            raise IFEMSyntheticRoleReconciliationRequired("private ledger event is invalid")
        self._verify_event(event)
        return event

    def _execution_from_terminal(
        self,
        prepared: IFEMSyntheticRolePreparedRequestV1,
        terminal: IFEMSyntheticRolePrivateLedgerEventV1,
    ) -> IFEMSyntheticRoleExecutionV1:
        coordinate = IFEMSyntheticRolePrivateCoordinateV1.from_prepared(prepared)
        self._require_terminal_matches(terminal, coordinate=coordinate)
        assert terminal.artifact is not None
        try:
            response = self._output_store.read_response(terminal.artifact)
        except Exception:
            raise IFEMSyntheticRoleReconciliationRequired(
                "private ledger response cannot be recovered"
            ) from None
        if (
            response.provider_id != coordinate.provider_id
            or response.model_id != coordinate.model_id
        ):
            raise IFEMSyntheticRoleReconciliationRequired(
                "private ledger response identity differs from its coordinate"
            )
        output = IFEMSyntheticRoleModelOutputV1(
            text=response.text,
            body_binding=prepared.body_binding,
            provider_id=response.provider_id,
            model_id=response.model_id,
            response_id=response.response_id,
            usage=response.usage,
            tool_calls=response.tool_calls,
        )
        return IFEMSyntheticRoleExecutionV1(prepared=prepared, output=output)

    def _require_terminal_matches(
        self,
        event: IFEMSyntheticRolePrivateLedgerEventV1,
        *,
        coordinate: IFEMSyntheticRolePrivateCoordinateV1,
        artifact: ModelResponseArtifactRefV1 | None = None,
        commitment_nonce: str | None = None,
    ) -> None:
        if (
            event.transition not in {"cas_expected", "response_persisted"}
            or event.coordinate != coordinate
            or event.artifact is None
            or event.commitment_nonce is None
            or (artifact is not None and event.artifact != artifact)
            or (commitment_nonce is not None and event.commitment_nonce != commitment_nonce)
        ):
            raise IFEMSyntheticRoleReconciliationRequired(
                "private ledger terminal binding conflicts with this coordinate"
            )

    def _signed_manifest_record(
        self,
        manifest: IFEMSyntheticRolePrivateManifestV1,
    ) -> IFEMSyntheticRolePrivateManifestRecordV1:
        unsigned: dict[str, object] = {
            "schema_version": "autolean.ifem-synthetic-role-private-manifest-record.v1",
            "manifest": manifest.model_dump(mode="json"),
            "authenticator_id": self._authenticator.authenticator_id,
            "authentication_scheme": self._authenticator.authentication_scheme,
        }
        return IFEMSyntheticRolePrivateManifestRecordV1.model_validate(
            {**unsigned, "authentication_tag": self._authenticate(unsigned)}
        )

    def _write_manifest_record(self, record: IFEMSyntheticRolePrivateManifestRecordV1) -> None:
        path = self._manifest_path(record.manifest.run_identity_sha256)
        payload = canonical_json_bytes(record.model_dump(mode="json"))
        try:
            _write_private_exclusive(path, payload)
        except FileExistsError:
            try:
                existing = self._read_manifest_record(path)
            except IFEMSyntheticRoleReconciliationRequired:
                raise
            if existing != record:
                raise IFEMSyntheticRoleReconciliationRequired(
                    "private immutable manifest conflicts with an existing run"
                ) from None

    def _read_manifest_record(
        self,
        path: Path,
    ) -> IFEMSyntheticRolePrivateManifestRecordV1:
        try:
            payload = path.read_bytes()
            record = IFEMSyntheticRolePrivateManifestRecordV1.model_validate_json(payload)
        except (OSError, ValueError):
            raise IFEMSyntheticRoleReconciliationRequired(
                "private iFEM manifest cannot be reconciled"
            ) from None
        if canonical_json_bytes(record.model_dump(mode="json")) != payload:
            raise IFEMSyntheticRoleReconciliationRequired("private iFEM manifest is not canonical")
        self._verify_manifest_record(record)
        return record

    def _verify_event(self, event: IFEMSyntheticRolePrivateLedgerEventV1) -> None:
        if (
            event.authenticator_id != self._authenticator.authenticator_id
            or event.authentication_scheme != self._authenticator.authentication_scheme
            or not self._authenticator.verify(
                canonical_json_bytes(event.unsigned_payload()),
                event.authentication_tag,
            )
        ):
            raise IFEMSyntheticRoleReconciliationRequired(
                "private ledger event authentication failed"
            )

    def _verify_manifest_record(self, record: IFEMSyntheticRolePrivateManifestRecordV1) -> None:
        if (
            record.authenticator_id != self._authenticator.authenticator_id
            or record.authentication_scheme != self._authenticator.authentication_scheme
            or not self._authenticator.verify(
                canonical_json_bytes(record.unsigned_payload()),
                record.authentication_tag,
            )
        ):
            raise IFEMSyntheticRoleReconciliationRequired(
                "private iFEM manifest authentication failed"
            )

    def _authenticate(self, unsigned_payload: dict[str, object]) -> str:
        tag = self._authenticator.authenticate(canonical_json_bytes(unsigned_payload))
        if (
            not isinstance(tag, str)
            or re.fullmatch(_AUTHENTICATION_TAG, tag) is None
            or not self._authenticator.verify(canonical_json_bytes(unsigned_payload), tag)
        ):
            raise IFEMSyntheticRolePrivateLedgerError(
                "private ledger authenticator returned an invalid tag"
            )
        return tag

    def _event_path(
        self,
        coordinate: IFEMSyntheticRolePrivateCoordinateV1,
        transition: Literal["dispatch_started", "cas_expected", "response_persisted"],
    ) -> Path:
        ordinal = {
            "dispatch_started": "01-dispatch-started.json",
            "cas_expected": "02-cas-expected.json",
            "response_persisted": "03-response-persisted.json",
        }[transition]
        coordinate_root = self._journal_root / coordinate.coordinate_hash()
        self._require_physical_directory(self._journal_root)
        self._require_physical_directory(coordinate_root)
        return self._require_private_file_target(coordinate_root / ordinal)

    def _manifest_path(self, run_identity_sha256: str) -> Path:
        if re.fullmatch(_SHA256, run_identity_sha256) is None:
            raise IFEMSyntheticRolePrivateLedgerError("private manifest identity is invalid")
        self._require_physical_directory(self._manifest_root)
        return self._require_private_file_target(
            self._manifest_root / f"{run_identity_sha256}.json"
        )

    def _require_physical_directory(self, path: Path) -> None:
        """Create and re-check one ledger-owned directory without following reparse points."""

        try:
            path.relative_to(self._root)
        except ValueError as error:
            raise IFEMSyntheticRolePrivateLedgerError(
                "private ledger directory escaped its root"
            ) from error
        try:
            path.mkdir(exist_ok=True)
            metadata = path.stat(follow_symlinks=False)
            resolved = path.resolve(strict=True)
        except OSError as error:
            raise IFEMSyntheticRolePrivateLedgerError(
                "private ledger directory is unavailable"
            ) from error
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or _is_link_or_reparse_point(path)
            or (resolved != self._root and self._root not in resolved.parents)
        ):
            raise IFEMSyntheticRolePrivateLedgerError(
                "private ledger directory must be a physical child of its root"
            )

    def _require_private_file_target(self, path: Path) -> Path:
        try:
            path.relative_to(self._root)
        except ValueError as error:
            raise IFEMSyntheticRolePrivateLedgerError(
                "private ledger file escaped its root"
            ) from error
        try:
            resolved_parent = path.parent.resolve(strict=True)
        except OSError as error:
            raise IFEMSyntheticRolePrivateLedgerError(
                "private ledger file parent is unavailable"
            ) from error
        if self._root not in resolved_parent.parents:
            raise IFEMSyntheticRolePrivateLedgerError("private ledger file parent escaped its root")
        if path.exists() and _is_link_or_reparse_point(path):
            raise IFEMSyntheticRolePrivateLedgerError(
                "private ledger file must not be a link or reparse point"
            )
        return path


def render_ifem_synthetic_role_public_ledger_projection(
    projection: IFEMSyntheticRolePublicLedgerProjectionV1,
    *,
    ledger: IFEMSyntheticRolePrivateLedger,
    fixture: IFEMSyntheticRolePublicFixtureV1,
    prepared_requests: Iterable[IFEMSyntheticRolePreparedRequestV1],
) -> bytes:
    """Rebuild from the authenticated private ledger before rendering the public projection."""

    if type(projection) is not IFEMSyntheticRolePublicLedgerProjectionV1:
        raise IFEMSyntheticRolePrivateLedgerError(
            "public ledger projection must use the exact projection type"
        )
    try:
        verified = IFEMSyntheticRolePublicLedgerProjectionV1.model_validate(
            projection.model_dump(mode="json")
        )
    except (TypeError, ValueError) as error:
        raise IFEMSyntheticRolePrivateLedgerError(
            "public ledger projection failed revalidation"
        ) from error
    expected = ledger.public_projection(fixture, prepared_requests)
    if verified != expected:
        raise IFEMSyntheticRolePrivateLedgerError(
            "public ledger projection differs from the authenticated private ledger"
        )
    rendered = canonical_json_bytes(verified.model_dump(mode="json")) + b"\n"
    if any(marker in rendered.lower() for marker in _FORBIDDEN_PUBLIC_MARKERS):
        raise IFEMSyntheticRolePrivateLedgerError(
            "public ledger projection contains private material"
        )
    return rendered


def _response_from_execution(execution: IFEMSyntheticRoleExecutionV1) -> ModelResponse:
    """Normalize bridge output into the existing operator-private response CAS schema."""

    return ModelResponse(
        provider_id=execution.output.provider_id,
        model_id=execution.output.model_id,
        response_id=execution.output.response_id,
        text=execution.output.text,
        usage=execution.output.usage,
        tool_calls=execution.output.tool_calls,
    )


def _expected_artifact_ref(response: ModelResponse) -> ModelResponseArtifactRefV1:
    artifact = model_response_artifact(response)
    payload = artifact.canonical_bytes()
    return ModelResponseArtifactRefV1(
        artifact_digest=artifact.artifact_digest(),
        size_bytes=len(payload),
    )


def _revalidate_fixture(
    fixture: IFEMSyntheticRolePublicFixtureV1,
) -> IFEMSyntheticRolePublicFixtureV1:
    if type(fixture) is not IFEMSyntheticRolePublicFixtureV1:
        raise IFEMSyntheticRolePrivateLedgerError("fixture must use the exact public fixture type")
    try:
        return IFEMSyntheticRolePublicFixtureV1.model_validate_json(
            render_ifem_synthetic_role_fixture(fixture)
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise IFEMSyntheticRolePrivateLedgerError("public fixture failed revalidation") from error


def _validated_full_run(
    fixture: IFEMSyntheticRolePublicFixtureV1,
    prepared_requests: Iterable[IFEMSyntheticRolePreparedRequestV1],
) -> tuple[IFEMSyntheticRolePreparedRequestV1, ...]:
    try:
        prepared = tuple(prepared_requests)
    except TypeError as error:
        raise IFEMSyntheticRolePrivateLedgerError(
            "prepared requests must be an iterable"
        ) from error
    if len(prepared) != 16 or not all(
        isinstance(item, IFEMSyntheticRolePreparedRequestV1) for item in prepared
    ):
        raise IFEMSyntheticRolePrivateLedgerError(
            "private iFEM run requires exactly sixteen prepared requests"
        )
    expected_cases = {item.case_id.value: item for item in fixture.cases}
    coordinates = [IFEMSyntheticRolePrivateCoordinateV1.from_prepared(item) for item in prepared]
    if len({item.coordinate_hash() for item in coordinates}) != 16:
        raise IFEMSyntheticRolePrivateLedgerError("private iFEM run has duplicate coordinates")
    if {item.case_id.value for item in prepared} != set(expected_cases):
        raise IFEMSyntheticRolePrivateLedgerError("private iFEM run does not cover the fixture")
    provider_bindings = {
        (
            item.provider_id,
            item.model_id,
            item.provider_configuration_digest.value,
        )
        for item in prepared
    }
    if len(provider_bindings) != 1:
        raise IFEMSyntheticRolePrivateLedgerError(
            "private iFEM run must use one fixed provider configuration"
        )
    for item in prepared:
        case = expected_cases[item.case_id.value]
        if (
            item.fixture_content_sha256 != fixture.content_sha256
            or item.role is not case.role
            or item.prompt_digest != digest_text(HashKindV1.PROMPT, case.prompt)
        ):
            raise IFEMSyntheticRolePrivateLedgerError(
                "private iFEM request does not bind the public fixture case"
            )
    return tuple(sorted(prepared, key=lambda item: item.case_id.value))


def _run_identity(prepared: tuple[IFEMSyntheticRolePreparedRequestV1, ...]) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "schema_version": "autolean.ifem-synthetic-role-private-run-identity.v1",
                "coordinates": [
                    IFEMSyntheticRolePrivateCoordinateV1.from_prepared(item).model_dump(mode="json")
                    for item in prepared
                ],
            }
        )
    ).hexdigest()


def _public_commitment(
    entry: IFEMSyntheticRolePrivateOutputEntryV1,
    authenticator: IFEMSyntheticRolePrivateLedgerAuthenticator,
) -> IFEMSyntheticRolePublicOutputCommitmentV1:
    coordinate = entry.coordinate
    private_payload = canonical_json_bytes(
        {
            "schema_version": "autolean.ifem-synthetic-role-private-output-commitment.v1",
            "coordinate": coordinate.model_dump(mode="json"),
            "artifact": entry.artifact.model_dump(mode="json"),
            "commitment_nonce": entry.commitment_nonce,
        }
    )
    tag = authenticator.authenticate(private_payload)
    if (
        not isinstance(tag, str)
        or re.fullmatch(_AUTHENTICATION_TAG, tag) is None
        or not authenticator.verify(private_payload, tag)
    ):
        raise IFEMSyntheticRolePrivateLedgerError(
            "private ledger authenticator could not build an output commitment"
        )
    commitment = digest_model(
        HashKindV1.MODEL_OUTPUT_COMMITMENT,
        {
            "schema_version": "autolean.ifem-synthetic-role-public-output-commitment.v1",
            "authenticator_id": authenticator.authenticator_id,
            "authentication_scheme": authenticator.authentication_scheme,
            "authentication_tag": tag,
        },
    )
    return IFEMSyntheticRolePublicOutputCommitmentV1(
        case_id=coordinate.case_id,
        role=coordinate.role,
        request_body_binding=coordinate.request_body_binding,
        logical_request_digest=coordinate.logical_request_digest,
        provider_id=coordinate.provider_id,
        model_id=coordinate.model_id,
        provider_configuration_digest=coordinate.provider_configuration_digest,
        output_commitment=commitment,
    )


def _write_private_exclusive(path: Path, payload: bytes) -> None:
    if not path.parent.is_dir() or _is_link_or_reparse_point(path.parent):
        raise IFEMSyntheticRolePrivateLedgerError(
            "private ledger target parent must be a physical directory"
        )
    temporary = path.parent / f".{path.name}.{secrets.token_hex(16)}.tmp"
    descriptor: int | None = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        descriptor = os.open(temporary, flags, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = None
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        with suppress(FileNotFoundError):
            temporary.unlink()


def _is_link_or_reparse_point(path: Path) -> bool:
    """Return true for POSIX links and Windows junction/reparse-point paths."""

    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError:
        return True
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_attribute = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    is_junction = getattr(path, "is_junction", lambda: False)
    try:
        return bool(path.is_symlink() or is_junction() or attributes & reparse_attribute)
    except OSError:
        return True


__all__ = [
    "IFEMSyntheticRolePrivateCoordinateV1",
    "IFEMSyntheticRolePrivateLedger",
    "IFEMSyntheticRolePrivateLedgerAuthenticator",
    "IFEMSyntheticRolePrivateLedgerAuthorityV1",
    "IFEMSyntheticRolePrivateLedgerError",
    "IFEMSyntheticRolePrivateLedgerEventV1",
    "IFEMSyntheticRolePrivateManifestV1",
    "IFEMSyntheticRolePublicLedgerProjectionV1",
    "IFEMSyntheticRolePublicOutputCommitmentV1",
    "IFEMSyntheticRoleReconciliationRequired",
    "LocalIFEMSyntheticRolePrivateLedger",
    "TestOnlyIFEMSyntheticRoleHmacAuthenticator",
    "render_ifem_synthetic_role_public_ledger_projection",
]
