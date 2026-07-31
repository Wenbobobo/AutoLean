"""Private-input reconciliation for the synthetic iFEM role calibration.

The public fixture and bridge receipts are useful transport artifacts, but their ordinary
content hashes are not semantic authentication.  This module is the evaluator-side join: it
rebuilds the fixture and oracle from the private corpus and operator seed, checks every public
receipt against that rebuilt fixture, and emits only bounded counts and public-fixture digests.
The private oracle is never represented by an unkeyed public digest: its expected-side payload
is small enough to recover by enumeration.  A future public oracle commitment requires a separate
authenticated operator-private sidecar.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from typing import Final, Literal, Self, cast

from autolean_builder.ifem_structural_role_probes import (
    IFEMStructuralProbeRoleV1,
    IFEMStructuralRoleProbeCorpusV1,
)
from autolean_contracts import (
    ContractModel,
    DigestV1,
    HashKindV1,
    canonical_json_bytes,
    digest_bytes,
)
from autolean_contracts.hashing import require_digest_kind
from pydantic import Field, model_validator

from benchmarks.ifem_synthetic_role_bridge import (
    IFEMSyntheticRoleExecutor,
    IFEMSyntheticRolePreparedRequestV1,
    IFEMSyntheticRoleReceiptV1,
    IFEMSyntheticRoleRequestPolicyV1,
    prepare,
)
from benchmarks.ifem_synthetic_role_fixture import (
    IFEMSyntheticRolePrivateOracleV1,
    IFEMSyntheticRolePublicFixtureV1,
    build_ifem_synthetic_role_fixture,
    build_ifem_synthetic_role_oracle,
    render_ifem_synthetic_role_fixture,
)

_SHA256 = r"^[0-9a-f]{64}$"
_ROLE_COUNTS: Final[dict[str, int]] = {
    IFEMStructuralProbeRoleV1.STATEMENT_FORMALIZER.value: 8,
    IFEMStructuralProbeRoleV1.FIDELITY_REVIEWER.value: 4,
    IFEMStructuralProbeRoleV1.CHEATING_SUPERVISOR.value: 4,
}


class IFEMRoleReconciliationError(ValueError):
    """Private reconciliation failed; no public calibration report is produced."""


class IFEMRoleReconciliationAuthorityV1(ContractModel):
    schema_version: Literal["autolean.ifem-role-reconciliation-authority.v1"] = (
        "autolean.ifem-role-reconciliation-authority.v1"
    )
    private_rebuild_verified: Literal[True] = True
    semantic_equivalence_claimed: Literal[False] = False
    benchmark_authority: Literal[False] = False
    statement_contract_created: Literal[False] = False
    freeze_allowed: Literal[False] = False
    prover_handoff_allowed: Literal[False] = False
    promotion_allowed: Literal[False] = False


class IFEMRoleReconciliationReportV1(ContractModel):
    """Public-fixture digest/count result of one private evaluator reconciliation."""

    schema_version: Literal["autolean.ifem-role-reconciliation.v1"] = (
        "autolean.ifem-role-reconciliation.v1"
    )
    fixture_content_sha256: str = Field(pattern=_SHA256)
    fixture_bundle_digest: DigestV1
    case_count: Literal[16] = 16
    role_counts: dict[str, int]
    oracle_record_count: Literal[16] = 16
    oracle_case_match_count: Literal[16] = 16
    receipt_count: int = Field(ge=0, le=16)
    receipt_case_match_count: int = Field(ge=0, le=16)
    receipt_role_match_count: int = Field(ge=0, le=16)
    receipt_body_binding_count: int = Field(ge=0, le=16)
    authority: IFEMRoleReconciliationAuthorityV1 = Field(
        default_factory=IFEMRoleReconciliationAuthorityV1
    )
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_report(self) -> Self:
        require_digest_kind(self.fixture_bundle_digest, HashKindV1.BUNDLE, "fixture_bundle_digest")
        if self.role_counts != _ROLE_COUNTS:
            raise ValueError("role counts differ from the fixed 16-case projection")
        if self.receipt_case_match_count != self.receipt_count:
            raise ValueError("every receipt must match one rebuilt case")
        if self.receipt_role_match_count != self.receipt_count:
            raise ValueError("every receipt must match its rebuilt role")
        if self.receipt_body_binding_count != self.receipt_count:
            raise ValueError("every receipt must match one rebuilt exact request body")
        if self.authority != IFEMRoleReconciliationAuthorityV1():
            raise ValueError("reconciliation authority flags are not fixed")
        if self.content_sha256 != self.computed_content_sha256():
            raise ValueError("reconciliation report content hash does not match its payload")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(dict[str, object], self.model_dump(mode="json", exclude={"content_sha256"}))

    def computed_content_sha256(self) -> str:
        return digest_bytes(
            HashKindV1.VERIFICATION_EVIDENCE, canonical_json_bytes(self.content_payload())
        ).value


def build_ifem_role_reconciliation(
    fixture: IFEMSyntheticRolePublicFixtureV1,
    oracle: IFEMSyntheticRolePrivateOracleV1,
    corpus: IFEMStructuralRoleProbeCorpusV1,
    *,
    operator_seed: bytes | str,
    receipts: Iterable[IFEMSyntheticRoleReceiptV1] = (),
    preparation_executor: IFEMSyntheticRoleExecutor | None = None,
    request_policy: IFEMSyntheticRoleRequestPolicyV1 | None = None,
) -> IFEMRoleReconciliationReportV1:
    """Rebuild private inputs and reconcile all public receipts."""

    verified_corpus = _revalidate_corpus(corpus)
    verified_fixture = _revalidate_fixture(fixture)
    verified_oracle = _revalidate_oracle(oracle)
    expected_fixture = build_ifem_synthetic_role_fixture(
        verified_corpus, operator_seed=operator_seed
    )
    expected_oracle = build_ifem_synthetic_role_oracle(verified_corpus, operator_seed=operator_seed)
    if verified_fixture != expected_fixture:
        raise IFEMRoleReconciliationError(
            "public fixture differs from the private corpus/seed rebuild"
        )
    if verified_oracle != expected_oracle:
        raise IFEMRoleReconciliationError("private oracle differs from the corpus/seed rebuild")
    rendered_fixture = render_ifem_synthetic_role_fixture(verified_fixture)
    verified_receipts = tuple(_revalidate_receipt(item) for item in receipts)
    case_by_id = {case.case_id: case for case in verified_fixture.cases}
    if len(verified_receipts) != len({item.case_id for item in verified_receipts}):
        raise IFEMRoleReconciliationError("receipt cases must be unique")
    if verified_receipts and preparation_executor is None:
        raise IFEMRoleReconciliationError(
            "receipt reconciliation requires the fixed preparation executor"
        )
    expected_prepared = (
        {
            case.case_id: prepare(
                verified_fixture,
                case.case_id,
                preparation_executor,
                request_policy=request_policy,
            )
            for case in verified_fixture.cases
        }
        if preparation_executor is not None
        else {}
    )
    case_matches = sum(item.case_id in case_by_id for item in verified_receipts)
    role_matches = sum(
        item.case_id in case_by_id and item.role is case_by_id[item.case_id].role
        for item in verified_receipts
    )
    exact_request_matches = sum(
        _receipt_matches_prepared(item, expected_prepared.get(item.case_id))
        for item in verified_receipts
    )
    if any(
        item.fixture_content_sha256 != verified_fixture.content_sha256 for item in verified_receipts
    ):
        raise IFEMRoleReconciliationError("a receipt binds another fixture")
    if case_matches != len(verified_receipts) or role_matches != len(verified_receipts):
        raise IFEMRoleReconciliationError("a receipt does not match the rebuilt fixture")
    if exact_request_matches != len(verified_receipts):
        raise IFEMRoleReconciliationError("a receipt does not match its rebuilt provider request")
    role_counts = dict(Counter(case.role.value for case in verified_fixture.cases))
    payload: dict[str, object] = {
        "schema_version": "autolean.ifem-role-reconciliation.v1",
        "fixture_content_sha256": verified_fixture.content_sha256,
        "fixture_bundle_digest": digest_bytes(HashKindV1.BUNDLE, rendered_fixture).model_dump(
            mode="json"
        ),
        "case_count": len(verified_fixture.cases),
        "role_counts": role_counts,
        "oracle_record_count": len(verified_oracle.records),
        "oracle_case_match_count": sum(
            record.public_case_id in case_by_id for record in verified_oracle.records
        ),
        "receipt_count": len(verified_receipts),
        "receipt_case_match_count": case_matches,
        "receipt_role_match_count": role_matches,
        "receipt_body_binding_count": exact_request_matches,
        "authority": IFEMRoleReconciliationAuthorityV1().model_dump(mode="json"),
    }
    payload["content_sha256"] = digest_bytes(
        HashKindV1.VERIFICATION_EVIDENCE, canonical_json_bytes(payload)
    ).value
    try:
        report = IFEMRoleReconciliationReportV1.model_validate(payload)
    except ValueError as error:
        raise IFEMRoleReconciliationError("reconciliation report did not validate") from error
    if report.oracle_case_match_count != report.oracle_record_count:
        raise IFEMRoleReconciliationError("private oracle contains an unknown case")
    return report


def render_ifem_role_reconciliation_report(
    report: IFEMRoleReconciliationReportV1,
    *,
    fixture: IFEMSyntheticRolePublicFixtureV1,
    oracle: IFEMSyntheticRolePrivateOracleV1,
    corpus: IFEMStructuralRoleProbeCorpusV1,
    operator_seed: bytes | str,
    receipts: Iterable[IFEMSyntheticRoleReceiptV1] = (),
    preparation_executor: IFEMSyntheticRoleExecutor | None = None,
    request_policy: IFEMSyntheticRoleRequestPolicyV1 | None = None,
) -> bytes:
    """Recompute the private reconciliation before serializing its public projection."""

    if type(report) is not IFEMRoleReconciliationReportV1:
        raise IFEMRoleReconciliationError("report must be the exact reconciliation type")
    expected = build_ifem_role_reconciliation(
        fixture,
        oracle,
        corpus,
        operator_seed=operator_seed,
        receipts=receipts,
        preparation_executor=preparation_executor,
        request_policy=request_policy,
    )
    try:
        verified = IFEMRoleReconciliationReportV1.model_validate(report.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as error:
        raise IFEMRoleReconciliationError("report requires revalidation") from error
    if verified != expected:
        raise IFEMRoleReconciliationError("report does not match the private reconciliation")
    return canonical_json_bytes(verified.model_dump(mode="json")) + b"\n"


def _revalidate_fixture(
    fixture: IFEMSyntheticRolePublicFixtureV1,
) -> IFEMSyntheticRolePublicFixtureV1:
    if type(fixture) is not IFEMSyntheticRolePublicFixtureV1:
        raise IFEMRoleReconciliationError("fixture must be the exact public fixture type")
    try:
        return IFEMSyntheticRolePublicFixtureV1.model_validate(fixture.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as error:
        raise IFEMRoleReconciliationError("fixture failed revalidation") from error


def _revalidate_oracle(
    oracle: IFEMSyntheticRolePrivateOracleV1,
) -> IFEMSyntheticRolePrivateOracleV1:
    if type(oracle) is not IFEMSyntheticRolePrivateOracleV1:
        raise IFEMRoleReconciliationError("oracle must be the exact private oracle type")
    try:
        return IFEMSyntheticRolePrivateOracleV1.model_validate(oracle.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as error:
        raise IFEMRoleReconciliationError("oracle failed revalidation") from error


def _revalidate_corpus(
    corpus: IFEMStructuralRoleProbeCorpusV1,
) -> IFEMStructuralRoleProbeCorpusV1:
    if type(corpus) is not IFEMStructuralRoleProbeCorpusV1:
        raise IFEMRoleReconciliationError("corpus must be the exact private corpus type")
    try:
        return IFEMStructuralRoleProbeCorpusV1.model_validate(corpus.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as error:
        raise IFEMRoleReconciliationError("corpus failed revalidation") from error


def _revalidate_receipt(receipt: IFEMSyntheticRoleReceiptV1) -> IFEMSyntheticRoleReceiptV1:
    if type(receipt) is not IFEMSyntheticRoleReceiptV1:
        raise IFEMRoleReconciliationError("receipt must be the exact bridge receipt type")
    try:
        return IFEMSyntheticRoleReceiptV1.model_validate(receipt.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as error:
        raise IFEMRoleReconciliationError("receipt failed revalidation") from error


def _receipt_matches_prepared(
    receipt: IFEMSyntheticRoleReceiptV1,
    prepared: IFEMSyntheticRolePreparedRequestV1 | None,
) -> bool:
    if prepared is None:
        return False
    return (
        receipt.fixture_content_sha256 == prepared.fixture_content_sha256
        and receipt.case_id == prepared.case_id
        and receipt.role is prepared.role
        and receipt.prompt_digest == prepared.prompt_digest
        and receipt.logical_request_digest == prepared.logical_request_digest
        and receipt.request_body_binding == prepared.body_binding
        and receipt.provider_id == prepared.provider_id
        and receipt.model_id == prepared.model_id
        and receipt.provider_configuration_digest == prepared.provider_configuration_digest
    )


__all__ = [
    "IFEMRoleReconciliationAuthorityV1",
    "IFEMRoleReconciliationError",
    "IFEMRoleReconciliationReportV1",
    "build_ifem_role_reconciliation",
    "render_ifem_role_reconciliation_report",
]
