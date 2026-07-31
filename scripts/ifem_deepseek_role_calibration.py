"""Run the sixteen-case iFEM synthetic-role calibration as a private D32 operation.

This runner is intentionally an observation path only.  It loads the hash-pinned redacted iFEM
corpus, sends exactly the prepared DeepSeek bodies only in explicit ``run`` mode, and stores raw
responses exclusively in an operator-private authenticated ledger.  It creates no score, oracle
evaluation, statement contract, freeze, Prover handoff, or promotion authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import stat
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Final, Literal, Never

# Keep direct-file invocation usable for operator diagnostics without relying on PYTHONPATH.
_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(_REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPOSITORY_ROOT))

import httpx  # noqa: E402
from autolean_builder.ifem_candidate_dependency_graph import (  # noqa: E402
    IFEMCandidateDependencyGraphV1,
    load_ifem_candidate_dependency_graph,
)
from autolean_builder.ifem_structural_role_probes import (  # noqa: E402
    IFEMStructuralProbeRoleV1,
    IFEMStructuralRoleProbeCorpusV1,
    build_ifem_structural_role_probe_corpus,
    load_ifem_structural_role_probe_corpus,
)
from autolean_contracts import ContractModel, canonical_json_bytes  # noqa: E402
from autolean_prover.errors import ConfigurationError, ProviderResponseError  # noqa: E402
from autolean_prover.providers import (  # noqa: E402
    HttpxResponsesTransport,
    LocalPrivateModelOutputStore,
    ResponsesTransport,
)
from autolean_prover.providers.operator_profile import (  # noqa: E402
    ChatCompletionsOperatorProfileV1,
)

from benchmarks.ifem_deepseek_executor import IFEMDeepSeekExactExecutor  # noqa: E402
from benchmarks.ifem_deepseek_preflight import (  # noqa: E402
    IFEMDeepSeekPreflightBundleV1,
    build_ifem_deepseek_preflight,
)
from benchmarks.ifem_synthetic_role_bridge import (  # noqa: E402
    IFEMSyntheticRoleExecutor,
    IFEMSyntheticRoleRequestPolicyV1,
    IFEMSyntheticRoleResponseContractV1,
)
from benchmarks.ifem_synthetic_role_fixture import (  # noqa: E402
    IFEMSyntheticRolePublicFixtureV1,
    build_ifem_synthetic_role_fixture,
)
from benchmarks.ifem_synthetic_role_private_ledger import (  # noqa: E402
    IFEMSyntheticRoleReconciliationRequired,
    LocalIFEMSyntheticRolePrivateLedger,
    TestOnlyIFEMSyntheticRoleHmacAuthenticator,
)

_PROFILE_PATH: Final[Path] = (
    _REPOSITORY_ROOT / "Prover" / "operator-profiles" / "deepseek-v4-pro.chat-completions.v1.json"
)
_D34_PROFILE_PATH: Final[Path] = (
    _REPOSITORY_ROOT
    / "Prover"
    / "operator-profiles"
    / "deepseek-v4-pro.ifem-role-calibration.v2.json"
)
_GRAPH_PATH: Final[Path] = (
    _REPOSITORY_ROOT
    / "Builder"
    / "pilots"
    / "discovery"
    / "ifem-candidate-dependency-graph.v1.json"
)
_GRAPH_V1_FILE_SHA256: Final[str] = (
    "e6442bfe1cc5305a3d26972c23c70a08029f8cde387dc1b58088d918632cd3af"
)
_GRAPH_V1_CONTENT_SHA256: Final[str] = (
    "ba9b246805a4b94ea9f0b02898a772114e495fc8dc12c783b7388b519470a71d"
)
_CORPUS_PATH: Final[Path] = (
    _REPOSITORY_ROOT
    / "Builder"
    / "pilots"
    / "discovery"
    / "ifem-structural-role-probe-corpus.v1.json"
)
_CORPUS_V1_FILE_SHA256: Final[str] = (
    "b0b232a7cd062b47bf5b07efb3158bd068d1988e5285cd0fd964a5855856f617"
)
_CORPUS_V1_CONTENT_SHA256: Final[str] = (
    "a449b48f3544dc7dfe748eb76abe423e0a6c66372dd1f58c5cdb7221b1d59fb8"
)
_API_KEY_ENV: Final[str] = "AUTOLEAN_DEEPSEEK_API_KEY"
_OPERATOR_SEED_ENV: Final[str] = "AUTOLEAN_IFEM_OPERATOR_SEED"
_LEDGER_KEY_ENV: Final[str] = "AUTOLEAN_IFEM_LEDGER_HMAC_KEY"
_ROOT_MARKER_NAME: Final[str] = ".autolean-ifem-d32-root-v1.json"
_MATERIAL_MARKER_NAME: Final[str] = ".autolean-ifem-d32-operator-material-v1.json"
_OPERATOR_SEED_FILE: Final[str] = "operator-seed.txt"
_LEDGER_KEY_FILE: Final[str] = "ledger-hmac-key.txt"
_SHA256: Final[str] = r"^[0-9a-f]{64}$"
_SAFE_FAILURE: Final[str] = r"^[a-z][a-z0-9_]{0,63}$"
_ROLE_COUNTS: Final[dict[str, int]] = {
    IFEMStructuralProbeRoleV1.STATEMENT_FORMALIZER.value: 8,
    IFEMStructuralProbeRoleV1.FIDELITY_REVIEWER.value: 4,
    IFEMStructuralProbeRoleV1.CHEATING_SUPERVISOR.value: 4,
}


class IFEMDeepSeekRoleCalibrationProtocolIdV1(StrEnum):
    """Closed revision selection for the private iFEM calibration lane."""

    D32_V1 = "d32-v1"
    D34_V2 = "d34-v2"


@dataclass(frozen=True, slots=True)
class IFEMDeepSeekRoleCalibrationProtocolV1:
    """One fixed corpus, profile, request policy, and response contract revision."""

    protocol_id: IFEMDeepSeekRoleCalibrationProtocolIdV1
    profile_path: Path
    expected_profile_id: str
    expected_profile_content_sha256: str
    expected_graph_file_sha256: str
    expected_graph_content_sha256: str
    expected_corpus_file_sha256: str
    expected_corpus_content_sha256: str
    expected_max_output_tokens: int
    response_contract: IFEMSyntheticRoleResponseContractV1


_PROTOCOLS: Final[
    dict[IFEMDeepSeekRoleCalibrationProtocolIdV1, IFEMDeepSeekRoleCalibrationProtocolV1]
] = {
    IFEMDeepSeekRoleCalibrationProtocolIdV1.D32_V1: IFEMDeepSeekRoleCalibrationProtocolV1(
        protocol_id=IFEMDeepSeekRoleCalibrationProtocolIdV1.D32_V1,
        profile_path=_PROFILE_PATH,
        expected_profile_id="deepseek-v4-pro-canary",
        expected_profile_content_sha256=(
            "ebc5defa78e63d7db0eaa7ef98d3b3bf82b0221cc555bdbe696d8ae8959125fa"
        ),
        expected_graph_file_sha256=_GRAPH_V1_FILE_SHA256,
        expected_graph_content_sha256=_GRAPH_V1_CONTENT_SHA256,
        expected_corpus_file_sha256=_CORPUS_V1_FILE_SHA256,
        expected_corpus_content_sha256=_CORPUS_V1_CONTENT_SHA256,
        expected_max_output_tokens=256,
        response_contract=(IFEMSyntheticRoleResponseContractV1.SELECTED_OPTION_AND_REASON_V1),
    ),
    IFEMDeepSeekRoleCalibrationProtocolIdV1.D34_V2: IFEMDeepSeekRoleCalibrationProtocolV1(
        protocol_id=IFEMDeepSeekRoleCalibrationProtocolIdV1.D34_V2,
        profile_path=_D34_PROFILE_PATH,
        expected_profile_id="deepseek-v4-pro-ifem-role-d34",
        expected_profile_content_sha256=(
            "6bd8834a76f64d405c2755b067cf1bf19a40531b12cb06b6a5b3ccc32a69c817"
        ),
        expected_graph_file_sha256=_GRAPH_V1_FILE_SHA256,
        expected_graph_content_sha256=_GRAPH_V1_CONTENT_SHA256,
        expected_corpus_file_sha256=_CORPUS_V1_FILE_SHA256,
        expected_corpus_content_sha256=_CORPUS_V1_CONTENT_SHA256,
        expected_max_output_tokens=512,
        response_contract=IFEMSyntheticRoleResponseContractV1.SELECTED_OPTION_ONLY_V2,
    ),
}


class IFEMDeepSeekRoleCalibrationError(ValueError):
    """The D32 operator boundary was not satisfied."""


class OperatorApprovalRequired(IFEMDeepSeekRoleCalibrationError):
    """A live request was attempted without explicit operator approval."""


class OperatorRootRejected(IFEMDeepSeekRoleCalibrationError):
    """An operator root is unsafe, overlapping, or not a fresh D32 root pair."""


class OperatorSecretUnavailable(IFEMDeepSeekRoleCalibrationError):
    """A required operator-owned secret reference is absent or too short."""


def _resolve_protocol(
    value: IFEMDeepSeekRoleCalibrationProtocolIdV1 | str,
) -> IFEMDeepSeekRoleCalibrationProtocolV1:
    try:
        protocol_id = IFEMDeepSeekRoleCalibrationProtocolIdV1(value)
    except (TypeError, ValueError) as error:
        raise IFEMDeepSeekRoleCalibrationError(
            "iFEM calibration protocol is unsupported"
        ) from error
    return _PROTOCOLS[protocol_id]


class _RedactedTransport:
    """Classify transport failures without retaining endpoint, header, or exception detail."""

    def __init__(self, delegate: ResponsesTransport) -> None:
        self._delegate = delegate
        self._failure_class: str | None = None

    @property
    def failure_class(self) -> str:
        return self._failure_class or "provider_response_unclassified"

    def post_json(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        payload: Mapping[str, object],
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        return self._delegate.post_json(
            url=url,
            headers=headers,
            payload=payload,
            timeout_seconds=timeout_seconds,
        )

    def post_json_bytes(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        self._failure_class = None
        try:
            response = self._delegate.post_json_bytes(
                url=url,
                headers=headers,
                body=body,
                timeout_seconds=timeout_seconds,
            )
        except httpx.HTTPStatusError as error:
            self._failure_class = _http_failure_class(error.response.status_code)
            raise
        except httpx.TimeoutException:
            self._failure_class = "timeout"
            raise
        except httpx.RequestError:
            self._failure_class = "network"
            raise
        except (json.JSONDecodeError, UnicodeDecodeError, ProviderResponseError):
            self._failure_class = "provider_response_rejected"
            raise
        except Exception:
            self._failure_class = "transport_unclassified"
            raise
        self._failure_class = "http_ok"
        return response


class IFEMDeepSeekRoleCalibrationAuthorityV1(ContractModel):
    """Public hard-negative authority flags for this local HMAC observation."""

    schema_version: Literal["autolean.ifem-deepseek-role-calibration-authority.v1"] = (
        "autolean.ifem-deepseek-role-calibration-authority.v1"
    )
    local_hmac_evidence: Literal["non_promotable"] = "non_promotable"
    raw_output_public: Literal[False] = False
    benchmark_authority: Literal[False] = False
    semantic_equivalence_claimed: Literal[False] = False
    statement_contract_created: Literal[False] = False
    freeze_allowed: Literal[False] = False
    prover_handoff_allowed: Literal[False] = False
    promotion_allowed: Literal[False] = False


class IFEMDeepSeekRoleCalibrationReportV1(ContractModel):
    """Digest-free stdout projection for all D32 modes."""

    schema_version: Literal["autolean.ifem-deepseek-role-calibration.v1"] = (
        "autolean.ifem-deepseek-role-calibration.v1"
    )
    mode: Literal["plan", "preflight", "run"]
    status: Literal[
        "planned",
        "preflight_ready",
        "settled",
        "execution_refused",
        "reconciliation_required",
    ]
    protocol_id: IFEMDeepSeekRoleCalibrationProtocolIdV1 = (
        IFEMDeepSeekRoleCalibrationProtocolIdV1.D32_V1
    )
    provider_id: Literal["deepseek"] = "deepseek"
    model_id: Literal["deepseek-v4-pro"] = "deepseek-v4-pro"
    case_count: Literal[16] = 16
    role_counts: dict[str, int] = _ROLE_COUNTS
    authority: IFEMDeepSeekRoleCalibrationAuthorityV1 = IFEMDeepSeekRoleCalibrationAuthorityV1()
    private_evidence_committed: bool = False
    failure_class: str | None = None

    def model_post_init(self, __context: object) -> None:
        if self.role_counts != _ROLE_COUNTS:
            raise ValueError("D32 report role counts differ from the fixed 16-case corpus")
        if (
            self.failure_class is not None
            and re.fullmatch(_SAFE_FAILURE, self.failure_class) is None
        ):
            raise ValueError("D32 report failure class is invalid")
        successful = self.status in {"planned", "preflight_ready", "settled"}
        if successful != (self.failure_class is None):
            raise ValueError("D32 report status and failure class are inconsistent")
        if self.status == "settled" and not self.private_evidence_committed:
            raise ValueError("settled D32 report requires private evidence")
        if self.status != "settled" and self.private_evidence_committed:
            raise ValueError("unsettled D32 report cannot claim private evidence")


class _RootMarkerV1(ContractModel):
    """Private root ownership marker authenticated with the operator ledger key."""

    schema_version: Literal["autolean.ifem-deepseek-role-calibration-root.v1"] = (
        "autolean.ifem-deepseek-role-calibration-root.v1"
    )
    root_kind: Literal["state", "private"]
    run_nonce: str
    fixture_content_sha256: str
    provider_configuration_digest: str
    authentication_tag: str

    def model_post_init(self, __context: object) -> None:
        if re.fullmatch(_SHA256, self.run_nonce) is None:
            raise ValueError("D32 root nonce is invalid")
        if re.fullmatch(_SHA256, self.fixture_content_sha256) is None:
            raise ValueError("D32 root fixture binding is invalid")
        if re.fullmatch(_SHA256, self.provider_configuration_digest) is None:
            raise ValueError("D32 root provider binding is invalid")
        if re.fullmatch(_SHA256, self.authentication_tag) is None:
            raise ValueError("D32 root authentication tag is invalid")

    def unsigned_payload(self) -> dict[str, object]:
        return self.model_dump(mode="json", exclude={"authentication_tag"})


class _RootMarkerV2(ContractModel):
    """Revision-bound private root marker for a fresh D34-or-later run."""

    schema_version: Literal["autolean.ifem-deepseek-role-calibration-root.v2"] = (
        "autolean.ifem-deepseek-role-calibration-root.v2"
    )
    root_kind: Literal["state", "private"]
    run_nonce: str
    fixture_content_sha256: str
    provider_configuration_digest: str
    protocol_id: IFEMDeepSeekRoleCalibrationProtocolIdV1
    profile_content_sha256: str
    request_policy_content_sha256: str
    response_contract: IFEMSyntheticRoleResponseContractV1
    authentication_tag: str

    def model_post_init(self, __context: object) -> None:
        for label, value in (
            ("run nonce", self.run_nonce),
            ("fixture binding", self.fixture_content_sha256),
            ("provider binding", self.provider_configuration_digest),
            ("profile binding", self.profile_content_sha256),
            ("request-policy binding", self.request_policy_content_sha256),
            ("authentication tag", self.authentication_tag),
        ):
            if re.fullmatch(_SHA256, value) is None:
                raise ValueError(f"D34 root {label} is invalid")

    def unsigned_payload(self) -> dict[str, object]:
        return self.model_dump(mode="json", exclude={"authentication_tag"})


class _RootMarkerV3(ContractModel):
    """Protocol marker that also authenticates the exact public corpus revision."""

    schema_version: Literal["autolean.ifem-deepseek-role-calibration-root.v3"] = (
        "autolean.ifem-deepseek-role-calibration-root.v3"
    )
    root_kind: Literal["state", "private"]
    run_nonce: str
    fixture_content_sha256: str
    provider_configuration_digest: str
    protocol_id: IFEMDeepSeekRoleCalibrationProtocolIdV1
    graph_file_sha256: str
    graph_content_sha256: str
    corpus_file_sha256: str
    corpus_content_sha256: str
    profile_content_sha256: str
    request_policy_content_sha256: str
    response_contract: IFEMSyntheticRoleResponseContractV1
    authentication_tag: str

    def model_post_init(self, __context: object) -> None:
        for label, value in (
            ("run nonce", self.run_nonce),
            ("fixture binding", self.fixture_content_sha256),
            ("provider binding", self.provider_configuration_digest),
            ("graph-file binding", self.graph_file_sha256),
            ("graph-content binding", self.graph_content_sha256),
            ("corpus-file binding", self.corpus_file_sha256),
            ("corpus-content binding", self.corpus_content_sha256),
            ("profile binding", self.profile_content_sha256),
            ("request-policy binding", self.request_policy_content_sha256),
            ("authentication tag", self.authentication_tag),
        ):
            if re.fullmatch(_SHA256, value) is None:
                raise ValueError(f"D34 root {label} is invalid")

    def unsigned_payload(self) -> dict[str, object]:
        return self.model_dump(mode="json", exclude={"authentication_tag"})


@dataclass(frozen=True, slots=True)
class IFEMDeepSeekRoleCalibrationConfig:
    mode: Literal["plan", "preflight", "run"]
    state_root: Path
    private_root: Path
    protocol_id: IFEMDeepSeekRoleCalibrationProtocolIdV1 | str
    operator_approved: bool = False

    def __post_init__(self) -> None:
        state_root = _validated_operator_root(self.state_root, label="state")
        private_root = _validated_operator_root(self.private_root, label="private")
        if (
            state_root == private_root
            or _is_relative_to(state_root, private_root)
            or _is_relative_to(private_root, state_root)
        ):
            raise OperatorRootRejected("state and private roots must be disjoint")
        object.__setattr__(self, "state_root", state_root)
        object.__setattr__(self, "private_root", private_root)
        object.__setattr__(self, "protocol_id", _resolve_protocol(self.protocol_id).protocol_id)


@dataclass(frozen=True, slots=True)
class IFEMDeepSeekRoleCalibrationPlan:
    graph: IFEMCandidateDependencyGraphV1
    corpus: IFEMStructuralRoleProbeCorpusV1
    protocol: IFEMDeepSeekRoleCalibrationProtocolV1
    profile: ChatCompletionsOperatorProfileV1
    profile_bytes: bytes = field(repr=False)
    request_policy: IFEMSyntheticRoleRequestPolicyV1
    response_contract: IFEMSyntheticRoleResponseContractV1
    case_count: Literal[16]
    role_counts: dict[str, int]


@dataclass(frozen=True, slots=True)
class _RunInputs:
    fixture: IFEMSyntheticRolePublicFixtureV1
    preflight: IFEMDeepSeekPreflightBundleV1
    executor: IFEMDeepSeekExactExecutor
    authenticator: TestOnlyIFEMSyntheticRoleHmacAuthenticator
    diagnostic_transport: _RedactedTransport


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _is_link_or_reparse_point(path: Path) -> bool:
    try:
        return path.is_symlink() or bool(getattr(path, "is_junction", lambda: False)())
    except OSError:
        return True


def _is_link_or_reparse_metadata(path: Path, metadata: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    file_attributes = getattr(metadata, "st_file_attributes", 0)
    return (
        stat.S_ISLNK(metadata.st_mode)
        or bool(file_attributes & reparse_flag)
        or _is_link_or_reparse_point(path)
    )


def _physical_file_parent_identities(path: Path, *, label: str) -> tuple[tuple[int, int], ...]:
    identities: list[tuple[int, int]] = []
    for parent in path.parents:
        metadata = parent.stat(follow_symlinks=False)
        if _is_link_or_reparse_metadata(parent, metadata) or not stat.S_ISDIR(metadata.st_mode):
            raise IFEMDeepSeekRoleCalibrationError(
                f"{label} parent chain must contain only physical directories"
            )
        identities.append((metadata.st_dev, metadata.st_ino))
    return tuple(identities)


def _read_physical_regular_file(path: Path, *, label: str) -> bytes:
    try:
        parents_before = _physical_file_parent_identities(path, label=label)
        before = path.stat(follow_symlinks=False)
        if _is_link_or_reparse_metadata(path, before) or not stat.S_ISREG(before.st_mode):
            raise IFEMDeepSeekRoleCalibrationError(f"{label} must be an unlinked regular file")
        payload = path.read_bytes()
        after = path.stat(follow_symlinks=False)
        parents_after = _physical_file_parent_identities(path, label=label)
    except OSError as error:
        raise IFEMDeepSeekRoleCalibrationError(f"{label} is unavailable") from error
    if (
        _is_link_or_reparse_metadata(path, after)
        or not stat.S_ISREG(after.st_mode)
        or (before.st_dev, before.st_ino, before.st_size)
        != (after.st_dev, after.st_ino, after.st_size)
        or parents_before != parents_after
    ):
        raise IFEMDeepSeekRoleCalibrationError(f"{label} changed while loading")
    return payload


def _assert_physical_parent_chain(path: Path) -> None:
    current = path.anchor and Path(path.anchor)
    if current is None:
        raise OperatorRootRejected("operator root has no filesystem anchor")
    for component in path.parents:
        if component == current:
            break
        if component.exists() and _is_link_or_reparse_point(component):
            raise OperatorRootRejected("operator root parent contains a link or reparse point")


def _validated_operator_root(value: object, *, label: str) -> Path:
    if not isinstance(value, Path) or not value.is_absolute():
        raise OperatorRootRejected(f"{label} root must be an absolute path")
    if _is_link_or_reparse_point(value):
        raise OperatorRootRejected(f"{label} root must not be a link or reparse point")
    try:
        candidate = value.resolve(strict=False)
    except OSError as error:
        raise OperatorRootRejected(f"{label} root cannot be resolved") from error
    if _is_relative_to(candidate, _REPOSITORY_ROOT.resolve()):
        raise OperatorRootRejected(f"{label} root must be outside the checkout")
    parent = candidate.parent
    if not parent.exists() or not parent.is_dir() or _is_link_or_reparse_point(parent):
        raise OperatorRootRejected(f"{label} root parent must be an existing physical directory")
    _assert_physical_parent_chain(parent)
    return candidate


def _assert_fresh_or_owned_roots(
    config: IFEMDeepSeekRoleCalibrationConfig,
    *,
    plan: IFEMDeepSeekRoleCalibrationPlan,
    fixture: IFEMSyntheticRolePublicFixtureV1,
    executor: IFEMSyntheticRoleExecutor,
    authenticator: TestOnlyIFEMSyntheticRoleHmacAuthenticator,
) -> None:
    roots: tuple[tuple[Literal["state", "private"], Path], ...] = (
        ("state", config.state_root),
        ("private", config.private_root),
    )
    existence = tuple(path.exists() for _kind, path in roots)
    if not any(existence):
        nonce = secrets.token_hex(32)
        for kind, root in roots:
            _claim_fresh_root(
                root,
                kind=kind,
                run_nonce=nonce,
                plan=plan,
                fixture=fixture,
                executor=executor,
                authenticator=authenticator,
            )
        return
    if not all(existence):
        raise OperatorRootRejected("D32 roots are only usable as a complete owned pair")
    for kind, root in roots:
        _verify_owned_root(
            root,
            kind=kind,
            plan=plan,
            fixture=fixture,
            executor=executor,
            authenticator=authenticator,
        )
    state_marker = _read_root_marker(config.state_root)
    private_marker = _read_root_marker(config.private_root)
    if (
        type(state_marker) is not type(private_marker)
        or state_marker.run_nonce != private_marker.run_nonce
    ):
        raise OperatorRootRejected("D32 root pair has inconsistent ownership")


def _assert_preflight_roots_are_fresh(config: IFEMDeepSeekRoleCalibrationConfig) -> None:
    """Check the requested future run roots without creating or authenticating anything."""

    if config.state_root.exists() or config.private_root.exists():
        raise OperatorRootRejected("D32 preflight requires roots reserved for a fresh run")


def _request_policy_content_sha256(policy: IFEMSyntheticRoleRequestPolicyV1) -> str:
    if type(policy) is not IFEMSyntheticRoleRequestPolicyV1:
        raise IFEMDeepSeekRoleCalibrationError("iFEM request policy must use the exact type")
    payload = {
        "schema_version": "autolean.ifem-deepseek-role-request-policy.v1",
        "max_input_tokens": policy.max_input_tokens,
        "max_output_tokens": policy.max_output_tokens,
        "reasoning_effort": policy.reasoning_effort,
        "require_usage_accounting": policy.require_usage_accounting,
    }
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _uses_legacy_public_input_revision(
    protocol: IFEMDeepSeekRoleCalibrationProtocolV1,
) -> bool:
    """Limit marker v1/v2 recovery to the graph/corpus revision they omitted."""

    return (
        protocol.expected_graph_file_sha256 == _GRAPH_V1_FILE_SHA256
        and protocol.expected_graph_content_sha256 == _GRAPH_V1_CONTENT_SHA256
        and protocol.expected_corpus_file_sha256 == _CORPUS_V1_FILE_SHA256
        and protocol.expected_corpus_content_sha256 == _CORPUS_V1_CONTENT_SHA256
    )


def _claim_fresh_root(
    root: Path,
    *,
    kind: Literal["state", "private"],
    run_nonce: str,
    plan: IFEMDeepSeekRoleCalibrationPlan,
    fixture: IFEMSyntheticRolePublicFixtureV1,
    executor: IFEMSyntheticRoleExecutor,
    authenticator: TestOnlyIFEMSyntheticRoleHmacAuthenticator,
) -> None:
    if root.exists():
        raise OperatorRootRejected("D32 operator root is not fresh")
    parent_stat = root.parent.stat(follow_symlinks=False)
    if not stat.S_ISDIR(parent_stat.st_mode) or _is_link_or_reparse_point(root.parent):
        raise OperatorRootRejected("D32 operator root parent changed")
    try:
        os.mkdir(root)
    except FileExistsError as error:
        raise OperatorRootRejected("D32 operator root was claimed concurrently") from error
    except OSError as error:
        raise OperatorRootRejected("D32 operator root could not be claimed") from error
    current_parent = root.parent.stat(follow_symlinks=False)
    if (parent_stat.st_dev, parent_stat.st_ino) != (current_parent.st_dev, current_parent.st_ino):
        raise OperatorRootRejected("D32 operator root parent changed during claim")
    if _is_link_or_reparse_point(root) or not root.is_dir():
        raise OperatorRootRejected("D32 claimed root is not a physical directory")
    marker = _new_root_marker(
        kind=kind,
        run_nonce=run_nonce,
        plan=plan,
        fixture=fixture,
        executor=executor,
        authenticator=authenticator,
    )
    _write_root_marker(root, marker)


def _new_root_marker(
    *,
    kind: Literal["state", "private"],
    run_nonce: str,
    plan: IFEMDeepSeekRoleCalibrationPlan,
    fixture: IFEMSyntheticRolePublicFixtureV1,
    executor: IFEMSyntheticRoleExecutor,
    authenticator: TestOnlyIFEMSyntheticRoleHmacAuthenticator,
) -> _RootMarkerV3:
    unsigned: dict[str, object] = {
        "schema_version": "autolean.ifem-deepseek-role-calibration-root.v3",
        "root_kind": kind,
        "run_nonce": run_nonce,
        "fixture_content_sha256": fixture.content_sha256,
        "provider_configuration_digest": executor.configuration_hash.value,
        "protocol_id": plan.protocol.protocol_id.value,
        "graph_file_sha256": plan.protocol.expected_graph_file_sha256,
        "graph_content_sha256": plan.protocol.expected_graph_content_sha256,
        "corpus_file_sha256": plan.protocol.expected_corpus_file_sha256,
        "corpus_content_sha256": plan.protocol.expected_corpus_content_sha256,
        "profile_content_sha256": hashlib.sha256(plan.profile_bytes).hexdigest(),
        "request_policy_content_sha256": _request_policy_content_sha256(plan.request_policy),
        "response_contract": plan.response_contract.value,
    }
    tag = authenticator.authenticate(canonical_json_bytes(unsigned))
    return _RootMarkerV3.model_validate({**unsigned, "authentication_tag": tag})


def _root_marker_path(root: Path) -> Path:
    return root / _ROOT_MARKER_NAME


def _write_root_marker(
    root: Path,
    marker: _RootMarkerV1 | _RootMarkerV2 | _RootMarkerV3,
) -> None:
    payload = canonical_json_bytes(marker.model_dump(mode="json"))
    try:
        descriptor = os.open(
            _root_marker_path(root),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
    except OSError as error:
        raise OperatorRootRejected("D32 root marker could not be created") from error
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def _read_root_marker(root: Path) -> _RootMarkerV1 | _RootMarkerV2 | _RootMarkerV3:
    if _is_link_or_reparse_point(root) or not root.is_dir():
        raise OperatorRootRejected("D32 root is no longer a physical directory")
    marker_path = _root_marker_path(root)
    if _is_link_or_reparse_point(marker_path):
        raise OperatorRootRejected("D32 root marker must not be a link")
    try:
        payload = marker_path.read_bytes()
        decoded = json.loads(payload.decode("utf-8"))
        if not isinstance(decoded, dict):
            raise ValueError("root marker must be an object")
        schema_version = decoded.get("schema_version")
        if schema_version == "autolean.ifem-deepseek-role-calibration-root.v1":
            marker: _RootMarkerV1 | _RootMarkerV2 | _RootMarkerV3 = _RootMarkerV1.model_validate(
                decoded
            )
        elif schema_version == "autolean.ifem-deepseek-role-calibration-root.v2":
            marker = _RootMarkerV2.model_validate(decoded)
        elif schema_version == "autolean.ifem-deepseek-role-calibration-root.v3":
            marker = _RootMarkerV3.model_validate(decoded)
        else:
            raise ValueError("root marker schema is unsupported")
    except (OSError, ValueError) as error:
        raise OperatorRootRejected("D32 root ownership marker is unavailable") from error
    if canonical_json_bytes(marker.model_dump(mode="json")) != payload:
        raise OperatorRootRejected("D32 root ownership marker is not canonical")
    return marker


def _verify_owned_root(
    root: Path,
    *,
    kind: Literal["state", "private"],
    plan: IFEMDeepSeekRoleCalibrationPlan,
    fixture: IFEMSyntheticRolePublicFixtureV1,
    executor: IFEMSyntheticRoleExecutor,
    authenticator: TestOnlyIFEMSyntheticRoleHmacAuthenticator,
) -> None:
    marker = _read_root_marker(root)
    common_match = (
        marker.root_kind != kind
        or marker.fixture_content_sha256 != fixture.content_sha256
        or marker.provider_configuration_digest != executor.configuration_hash.value
        or not authenticator.verify(
            canonical_json_bytes(marker.unsigned_payload()), marker.authentication_tag
        )
    )
    if common_match:
        raise OperatorRootRejected("D32 root ownership binding does not match this run")
    if isinstance(marker, _RootMarkerV1):
        if plan.protocol.protocol_id is not IFEMDeepSeekRoleCalibrationProtocolIdV1.D32_V1:
            raise OperatorRootRejected("legacy D32 root cannot be resumed by another protocol")
        if not _uses_legacy_public_input_revision(plan.protocol):
            raise OperatorRootRejected("legacy D32 root cannot bind successor public inputs")
        return
    if (
        marker.protocol_id is not plan.protocol.protocol_id
        or marker.profile_content_sha256 != hashlib.sha256(plan.profile_bytes).hexdigest()
        or marker.request_policy_content_sha256
        != _request_policy_content_sha256(plan.request_policy)
        or marker.response_contract is not plan.response_contract
    ):
        raise OperatorRootRejected("D34 root ownership binding does not match this protocol")
    if isinstance(marker, _RootMarkerV2):
        if not _uses_legacy_public_input_revision(plan.protocol):
            raise OperatorRootRejected("legacy D34 root cannot bind successor public inputs")
        return
    if (
        marker.graph_file_sha256 != plan.protocol.expected_graph_file_sha256
        or marker.graph_content_sha256 != plan.protocol.expected_graph_content_sha256
        or marker.corpus_file_sha256 != plan.protocol.expected_corpus_file_sha256
        or marker.corpus_content_sha256 != plan.protocol.expected_corpus_content_sha256
    ):
        raise OperatorRootRejected("D34 root public-input binding does not match this protocol")


def verify_ifem_deepseek_private_root_protocol(
    *,
    private_root: Path,
    plan: IFEMDeepSeekRoleCalibrationPlan,
    fixture: IFEMSyntheticRolePublicFixtureV1,
    authenticator: TestOnlyIFEMSyntheticRoleHmacAuthenticator,
) -> None:
    """Verify a readable private root against the explicitly selected protocol revision."""

    # The D33 caller uses its exact preflight adapter rather than a credential-bearing executor.
    # Its provider configuration is equal to the selected profile's deterministic configuration.
    preflight = build_ifem_deepseek_preflight(
        fixture,
        profile_bytes=plan.profile_bytes,
        request_policy=plan.request_policy,
        response_contract=plan.response_contract,
    )
    root = _validated_operator_root(private_root, label="private")
    if not root.exists():
        raise OperatorRootRejected("D32 private root is unavailable")
    _verify_owned_root(
        root,
        kind="private",
        plan=plan,
        fixture=fixture,
        executor=preflight.adapter,
        authenticator=authenticator,
    )


def _private_child_root(private_root: Path, name: str) -> Path:
    """Return one direct physical private child, rejecting a resumed link substitution."""

    candidate = private_root / name
    if candidate.exists():
        if _is_link_or_reparse_point(candidate) or not candidate.is_dir():
            raise OperatorRootRejected("D32 private child root is not a physical directory")
        try:
            resolved = candidate.resolve(strict=True)
            private_resolved = private_root.resolve(strict=True)
        except OSError as error:
            raise OperatorRootRejected("D32 private child root cannot be resolved") from error
        if not _is_relative_to(resolved, private_resolved):
            raise OperatorRootRejected("D32 private child root escaped its operator root")
        return resolved
    return candidate


def _required_secret(
    environment: Mapping[str, str],
    name: str,
    *,
    minimum_bytes: int,
) -> bytes:
    value = environment.get(name)
    if (
        not isinstance(value, str)
        or not value
        or any(token in value for token in ("\r", "\n", "\x00"))
    ):
        raise OperatorSecretUnavailable("an operator secret reference is unavailable")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise OperatorSecretUnavailable("an operator secret reference is invalid") from error
    if len(encoded) < minimum_bytes:
        raise OperatorSecretUnavailable("an operator secret reference is too short")
    return encoded


def _read_operator_secret_file(path: Path, *, minimum_bytes: int) -> str:
    if not isinstance(path, Path) or not path.is_absolute():
        raise OperatorSecretUnavailable("operator secret file must be an absolute path")
    if _is_link_or_reparse_point(path) or not path.is_file():
        raise OperatorSecretUnavailable("operator secret file must be a physical file")
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise OperatorSecretUnavailable("operator secret file is unavailable") from error
    if len(payload) > 4096:
        raise OperatorSecretUnavailable("operator secret file is unexpectedly large")
    try:
        value = payload.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise OperatorSecretUnavailable("operator secret file is invalid") from error
    _required_secret({"value": value}, "value", minimum_bytes=minimum_bytes)
    return value


def _write_operator_secret(path: Path, value: str) -> None:
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
    except OSError as error:
        raise OperatorSecretUnavailable("operator material could not be initialized") from error
    with os.fdopen(descriptor, "wb") as output:
        output.write(value.encode("ascii"))
        output.flush()
        os.fsync(output.fileno())


def _load_operator_material(root: Path) -> tuple[str, str]:
    material_root = _validated_operator_root(root, label="operator material")
    marker_bytes = canonical_json_bytes(
        {"schema_version": "autolean.ifem-deepseek-role-operator-material.v1"}
    )
    if not material_root.exists():
        raise OperatorSecretUnavailable("operator material root is unavailable")
    if _is_link_or_reparse_point(material_root) or not material_root.is_dir():
        raise OperatorSecretUnavailable("operator material root must be a physical directory")
    expected_names = {
        _MATERIAL_MARKER_NAME,
        _OPERATOR_SEED_FILE,
        _LEDGER_KEY_FILE,
    }
    try:
        entries = {item.name for item in material_root.iterdir()}
        marker = (material_root / _MATERIAL_MARKER_NAME).read_bytes()
    except OSError as error:
        raise OperatorSecretUnavailable("operator material is unavailable") from error
    if entries != expected_names or marker != marker_bytes:
        raise OperatorSecretUnavailable("operator material root is incomplete or foreign")
    seed = _read_operator_secret_file(
        material_root / _OPERATOR_SEED_FILE,
        minimum_bytes=32,
    )
    ledger_key = _read_operator_secret_file(
        material_root / _LEDGER_KEY_FILE,
        minimum_bytes=32,
    )
    if seed == ledger_key:
        raise OperatorSecretUnavailable("operator material values must be independent")
    return seed, ledger_key


def _load_or_initialize_operator_material(root: Path) -> tuple[str, str]:
    material_root = _validated_operator_root(root, label="operator material")
    marker_bytes = canonical_json_bytes(
        {"schema_version": "autolean.ifem-deepseek-role-operator-material.v1"}
    )
    if not material_root.exists():
        try:
            os.mkdir(material_root, 0o700)
        except OSError as error:
            raise OperatorSecretUnavailable(
                "operator material root could not be initialized"
            ) from error
        _write_operator_secret(
            material_root / _OPERATOR_SEED_FILE,
            secrets.token_hex(48),
        )
        _write_operator_secret(
            material_root / _LEDGER_KEY_FILE,
            secrets.token_hex(48),
        )
        try:
            descriptor = os.open(
                material_root / _MATERIAL_MARKER_NAME,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
                0o600,
            )
        except OSError as error:
            raise OperatorSecretUnavailable(
                "operator material marker could not be initialized"
            ) from error
        with os.fdopen(descriptor, "wb") as output:
            output.write(marker_bytes)
            output.flush()
            os.fsync(output.fileno())
    return _load_operator_material(material_root)


def _load_locked_graph(
    protocol: IFEMDeepSeekRoleCalibrationProtocolV1,
) -> IFEMCandidateDependencyGraphV1:
    """Load the source-text-free graph projection bound by this protocol."""

    try:
        return load_ifem_candidate_dependency_graph(
            _GRAPH_PATH,
            expected_file_sha256=protocol.expected_graph_file_sha256,
            expected_content_sha256=protocol.expected_graph_content_sha256,
        )
    except ValueError as error:
        raise IFEMDeepSeekRoleCalibrationError(
            "fixed iFEM candidate dependency graph has drifted"
        ) from error


def _load_locked_corpus(
    protocol: IFEMDeepSeekRoleCalibrationProtocolV1,
    graph: IFEMCandidateDependencyGraphV1,
) -> IFEMStructuralRoleProbeCorpusV1:
    """Load the one hash-pinned redacted corpus without source-cache reconstruction."""

    try:
        corpus = load_ifem_structural_role_probe_corpus(
            _CORPUS_PATH,
            expected_file_sha256=protocol.expected_corpus_file_sha256,
            expected_content_sha256=protocol.expected_corpus_content_sha256,
        )
    except ValueError as error:
        raise IFEMDeepSeekRoleCalibrationError(
            "fixed iFEM structural role probe corpus has drifted"
        ) from error
    if len(corpus.pairs) != 16:
        raise IFEMDeepSeekRoleCalibrationError("locked iFEM corpus does not contain sixteen pairs")
    role_counts = dict(Counter(pair.probe_role.value for pair in corpus.pairs))
    if role_counts != _ROLE_COUNTS:
        raise IFEMDeepSeekRoleCalibrationError("locked iFEM corpus role projection has drifted")
    try:
        rebuilt = build_ifem_structural_role_probe_corpus(
            catalog=corpus.catalog,
            graph=graph,
        )
    except ValueError as error:
        raise IFEMDeepSeekRoleCalibrationError(
            "fixed iFEM corpus failed its graph-bound rebuild"
        ) from error
    if rebuilt != corpus:
        raise IFEMDeepSeekRoleCalibrationError(
            "fixed iFEM corpus differs from its graph-bound rebuild"
        )
    return corpus


def _load_profile(
    protocol: IFEMDeepSeekRoleCalibrationProtocolV1,
) -> tuple[ChatCompletionsOperatorProfileV1, bytes]:
    try:
        profile_bytes = _read_physical_regular_file(
            protocol.profile_path,
            label="fixed DeepSeek operator profile",
        )
        profile = ChatCompletionsOperatorProfileV1.from_json_bytes(profile_bytes)
    except (OSError, ConfigurationError) as error:
        raise IFEMDeepSeekRoleCalibrationError(
            "fixed DeepSeek operator profile is unavailable"
        ) from error
    profile_content_sha256 = hashlib.sha256(profile_bytes).hexdigest()
    if (
        profile.provider_id != "deepseek"
        or profile.model_id != "deepseek-v4-pro"
        or profile.api_key_env != _API_KEY_ENV
        or profile.profile_id != protocol.expected_profile_id
        or profile_content_sha256 != protocol.expected_profile_content_sha256
        or profile.canary_max_output_tokens != protocol.expected_max_output_tokens
    ):
        raise IFEMDeepSeekRoleCalibrationError("fixed DeepSeek operator profile has drifted")
    return profile, profile_bytes


def build_ifem_deepseek_role_calibration_plan(
    *,
    protocol_id: IFEMDeepSeekRoleCalibrationProtocolIdV1 | str = (
        IFEMDeepSeekRoleCalibrationProtocolIdV1.D32_V1
    ),
) -> IFEMDeepSeekRoleCalibrationPlan:
    """Perform the read-only, credential-free D32 corpus and profile validation."""

    protocol = _resolve_protocol(protocol_id)
    graph = _load_locked_graph(protocol)
    corpus = _load_locked_corpus(protocol, graph)
    profile, profile_bytes = _load_profile(protocol)
    request_policy = IFEMSyntheticRoleRequestPolicyV1(
        max_input_tokens=profile.canary_max_input_tokens,
        max_output_tokens=profile.canary_max_output_tokens,
        reasoning_effort=profile.default_reasoning_effort,
        require_usage_accounting=True,
    )
    return IFEMDeepSeekRoleCalibrationPlan(
        graph=graph,
        corpus=corpus,
        protocol=protocol,
        profile=profile,
        profile_bytes=profile_bytes,
        request_policy=request_policy,
        response_contract=protocol.response_contract,
        case_count=16,
        role_counts=dict(_ROLE_COUNTS),
    )


def _prepare_run_inputs(
    plan: IFEMDeepSeekRoleCalibrationPlan,
    *,
    environment: Mapping[str, str],
    transport: ResponsesTransport,
) -> _RunInputs:
    api_key = _required_secret(environment, _API_KEY_ENV, minimum_bytes=1)
    seed = _required_secret(environment, _OPERATOR_SEED_ENV, minimum_bytes=32)
    ledger_key = _required_secret(environment, _LEDGER_KEY_ENV, minimum_bytes=32)
    if len({api_key, seed, ledger_key}) != 3:
        raise OperatorSecretUnavailable("D32 operator secret references must be independent")
    fixture = build_ifem_synthetic_role_fixture(plan.corpus, operator_seed=seed)
    preflight = build_ifem_deepseek_preflight(
        fixture,
        profile_bytes=plan.profile_bytes,
        request_policy=plan.request_policy,
        response_contract=plan.response_contract,
    )
    diagnostic_transport = _RedactedTransport(transport)
    provider = plan.profile.create_provider(
        transport=diagnostic_transport,
        environment={_API_KEY_ENV: api_key.decode("utf-8")},
    )
    executor = IFEMDeepSeekExactExecutor(provider, profile_bytes=plan.profile_bytes)
    if executor.request_policy != plan.request_policy:
        raise IFEMDeepSeekRoleCalibrationError(
            "D32 exact executor differs from the selected request policy"
        )
    if any(
        item.provider_configuration_digest != executor.configuration_hash
        or item.provider_id != executor.provider_id
        or item.model_id != executor.model_id
        for item in preflight.prepared
    ):
        raise IFEMDeepSeekRoleCalibrationError("D32 exact preflight differs from the live executor")
    return _RunInputs(
        fixture=fixture,
        preflight=preflight,
        executor=executor,
        authenticator=TestOnlyIFEMSyntheticRoleHmacAuthenticator(ledger_key),
        diagnostic_transport=diagnostic_transport,
    )


def _report(
    mode: Literal["plan", "preflight", "run"],
    status: Literal[
        "planned",
        "preflight_ready",
        "settled",
        "execution_refused",
        "reconciliation_required",
    ],
    *,
    protocol_id: IFEMDeepSeekRoleCalibrationProtocolIdV1 = (
        IFEMDeepSeekRoleCalibrationProtocolIdV1.D32_V1
    ),
    failure_class: str | None = None,
    private_evidence_committed: bool = False,
) -> IFEMDeepSeekRoleCalibrationReportV1:
    return IFEMDeepSeekRoleCalibrationReportV1(
        mode=mode,
        status=status,
        protocol_id=protocol_id,
        failure_class=failure_class,
        private_evidence_committed=private_evidence_committed,
    )


def _failure_class(error: BaseException, transport: _RedactedTransport | None = None) -> str:
    if transport is not None and transport.failure_class not in {
        "provider_response_unclassified",
        "http_ok",
    }:
        return transport.failure_class
    if isinstance(error, IFEMSyntheticRoleReconciliationRequired):
        return "private_reconciliation_required"
    if isinstance(error, OperatorApprovalRequired):
        return "operator_approval_required"
    if isinstance(error, OperatorSecretUnavailable):
        return "secret_reference_unavailable"
    if isinstance(error, OperatorRootRejected):
        return "root_policy_rejected"
    if isinstance(error, ProviderResponseError):
        return "provider_response_rejected"
    if isinstance(error, ConfigurationError):
        return "configuration_rejected"
    if isinstance(error, IFEMDeepSeekRoleCalibrationError):
        return "operator_policy_rejected"
    return "internal_unclassified"


def _http_failure_class(status_code: int) -> str:
    if status_code == 429:
        return "http_429"
    if 500 <= status_code <= 599:
        return "http_5xx"
    if 400 <= status_code <= 499:
        return "http_4xx"
    return "http_status_other"


def execute_ifem_deepseek_role_calibration(
    config: IFEMDeepSeekRoleCalibrationConfig,
    *,
    environment: Mapping[str, str] | None = None,
    transport: ResponsesTransport | None = None,
) -> IFEMDeepSeekRoleCalibrationReportV1:
    """Run one D32 mode while returning only a redacted, digest-free report."""

    protocol_id = _resolve_protocol(config.protocol_id).protocol_id
    try:
        plan = build_ifem_deepseek_role_calibration_plan(protocol_id=config.protocol_id)
    except BaseException as error:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        return _report(
            config.mode,
            "execution_refused",
            protocol_id=protocol_id,
            failure_class=_failure_class(error),
        )
    if config.mode == "plan":
        return _report("plan", "planned", protocol_id=protocol_id)
    if config.mode == "preflight":
        try:
            _assert_preflight_roots_are_fresh(config)
        except BaseException as error:
            if isinstance(error, (KeyboardInterrupt, SystemExit)):
                raise
            return _report(
                "preflight",
                "execution_refused",
                protocol_id=protocol_id,
                failure_class=_failure_class(error),
            )
        return _report("preflight", "preflight_ready", protocol_id=protocol_id)
    if config.operator_approved is not True:
        return _report(
            "run",
            "execution_refused",
            protocol_id=protocol_id,
            failure_class="operator_approval_required",
        )

    source_environment = os.environ if environment is None else environment
    delegate = HttpxResponsesTransport() if transport is None else transport
    try:
        inputs = _prepare_run_inputs(plan, environment=source_environment, transport=delegate)
    except BaseException as error:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        return _report(
            "run",
            "execution_refused",
            protocol_id=protocol_id,
            failure_class=_failure_class(error),
        )

    try:
        _assert_fresh_or_owned_roots(
            config,
            plan=plan,
            fixture=inputs.fixture,
            executor=inputs.executor,
            authenticator=inputs.authenticator,
        )
        output_store = LocalPrivateModelOutputStore(
            _private_child_root(config.private_root, "responses-v1")
        )
        ledger = LocalIFEMSyntheticRolePrivateLedger(
            _private_child_root(config.private_root, "ledger-v1"),
            output_store=output_store,
            authenticator=inputs.authenticator,
        )
    except BaseException as error:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        return _report(
            "run",
            "execution_refused",
            protocol_id=protocol_id,
            failure_class=_failure_class(error),
        )

    provider_boundary_entered = False
    try:
        for prepared in inputs.preflight.prepared:
            provider_boundary_entered = True
            ledger.execute_once(prepared, inputs.executor)
        ledger.commit_manifest(inputs.fixture, inputs.preflight.prepared)
    except BaseException as error:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        failure = _failure_class(
            error,
            inputs.diagnostic_transport,
        )
        return _report(
            "run",
            "reconciliation_required" if provider_boundary_entered else "execution_refused",
            protocol_id=protocol_id,
            failure_class=failure,
        )
    return _report(
        "run",
        "settled",
        protocol_id=protocol_id,
        private_evidence_committed=True,
    )


class _RedactedArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        del message
        raise IFEMDeepSeekRoleCalibrationError("invalid CLI arguments")


def _parser() -> argparse.ArgumentParser:
    parser = _RedactedArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "preflight", "run"))
    parser.add_argument("--operator-approved", action="store_true")
    parser.add_argument("--state-root", required=True, type=Path)
    parser.add_argument("--private-root", required=True, type=Path)
    parser.add_argument(
        "--protocol",
        choices=tuple(item.value for item in IFEMDeepSeekRoleCalibrationProtocolIdV1),
        required=True,
    )
    parser.add_argument("--api-key-file", type=Path)
    parser.add_argument("--operator-material-root", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    mode: Literal["plan", "preflight", "run"] = "plan"
    try:
        arguments = _parser().parse_args(argv)
        mode = arguments.mode
        config = IFEMDeepSeekRoleCalibrationConfig(
            mode=mode,
            state_root=arguments.state_root,
            private_root=arguments.private_root,
            protocol_id=arguments.protocol,
            operator_approved=arguments.operator_approved,
        )
        file_references = (arguments.api_key_file, arguments.operator_material_root)
        if any(item is not None for item in file_references) and not all(
            item is not None for item in file_references
        ):
            raise OperatorSecretUnavailable("operator file references must be supplied together")
        environment: Mapping[str, str] | None = None
        if arguments.api_key_file is not None and arguments.operator_material_root is not None:
            api_key = _read_operator_secret_file(
                arguments.api_key_file,
                minimum_bytes=1,
            )
            seed, ledger_key = _load_or_initialize_operator_material(
                arguments.operator_material_root
            )
            environment = {
                _API_KEY_ENV: api_key,
                _OPERATOR_SEED_ENV: seed,
                _LEDGER_KEY_ENV: ledger_key,
            }
        report = (
            execute_ifem_deepseek_role_calibration(config)
            if environment is None
            else execute_ifem_deepseek_role_calibration(config, environment=environment)
        )
    except BaseException as error:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        report = _report(mode, "execution_refused", failure_class=_failure_class(error))
    print(canonical_json_bytes(report.model_dump(mode="json")).decode("ascii"))
    return 0 if report.status in {"planned", "preflight_ready", "settled"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
