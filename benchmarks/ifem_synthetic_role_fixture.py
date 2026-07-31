"""Independent public prompts for the source-text-free iFEM role calibration.

This module is deliberately a narrow bridge between the project-authored structural
probe corpus and a model endpoint.  It does not import textbook bytes, the catalog,
or the witness specifications into a public prompt.  The public fixture contains
only neutral option text plus exact source/span/rights records for that text.  The
operator seed and the expected side labels are returned through a separate private
oracle object and are never fields of the public fixture.

The fixture is calibration evidence, not a statement contract, a benchmark result,
or a Prover handoff.  In particular, ``RightsRecordV1.model_egress`` describes the
rights of the project-authored prompt text; it is not execution authorization.
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime
from enum import StrEnum
from typing import Final, Literal, Self, cast

from autolean_builder.ifem_structural_role_probes import (
    IFEMStructuralProbeRoleV1,
    IFEMStructuralProbeSignatureV1,
    IFEMStructuralRoleProbeCorpusV1,
    IFEMStructuralRoleProbePairV1,
)
from autolean_contracts import (
    EndpointClassV1,
    HashKindV1,
    PermissionDecisionV1,
    RightsRecordV1,
    SourceRecordV1,
    SourceSpanV1,
    StableIdentifierV1,
    canonical_json_bytes,
    digest_bytes,
    digest_text,
    stable_identifier,
)
from autolean_contracts.base import ContractModel
from pydantic import Field, model_validator

IFEM_SYNTHETIC_ROLE_FIXTURE_SCHEMA: Final[
    Literal["autolean.ifem-synthetic-role-public-fixture.v1"]
] = "autolean.ifem-synthetic-role-public-fixture.v1"
IFEM_SYNTHETIC_ROLE_FIXTURE_KIND: Final[Literal["project_synthetic_neutral_role_prompts"]] = (
    "project_synthetic_neutral_role_prompts"
)
_SHA256 = r"^[0-9a-f]{64}$"
_CASE_COUNT: Final[int] = 16
_REVIEWED_AT: Final[datetime] = datetime(2026, 7, 30, 0, 0, tzinfo=UTC)
_ORDER_DOMAIN: Final[bytes] = b"autolean.ifem-synthetic-role-order.v1\0"
_EXPECTED_ROLES: Final[tuple[IFEMStructuralProbeRoleV1, ...]] = (
    IFEMStructuralProbeRoleV1.STATEMENT_FORMALIZER,
    IFEMStructuralProbeRoleV1.FIDELITY_REVIEWER,
    IFEMStructuralProbeRoleV1.STATEMENT_FORMALIZER,
    IFEMStructuralProbeRoleV1.CHEATING_SUPERVISOR,
    IFEMStructuralProbeRoleV1.STATEMENT_FORMALIZER,
    IFEMStructuralProbeRoleV1.CHEATING_SUPERVISOR,
    IFEMStructuralProbeRoleV1.STATEMENT_FORMALIZER,
    IFEMStructuralProbeRoleV1.FIDELITY_REVIEWER,
    IFEMStructuralProbeRoleV1.STATEMENT_FORMALIZER,
    IFEMStructuralProbeRoleV1.CHEATING_SUPERVISOR,
    IFEMStructuralProbeRoleV1.STATEMENT_FORMALIZER,
    IFEMStructuralProbeRoleV1.FIDELITY_REVIEWER,
    IFEMStructuralProbeRoleV1.STATEMENT_FORMALIZER,
    IFEMStructuralProbeRoleV1.FIDELITY_REVIEWER,
    IFEMStructuralProbeRoleV1.STATEMENT_FORMALIZER,
    IFEMStructuralProbeRoleV1.CHEATING_SUPERVISOR,
)
_PUBLIC_FORBIDDEN_PROMPT_TERMS: Final[tuple[str, ...]] = (
    "ifem",
    "source",
    "catalog",
    "risk",
    "mutation",
    "witness",
    "oracle",
    "baseline",
    "mutant",
)


class IFEMSyntheticRoleFixtureError(ValueError):
    """A public synthetic fixture crossed its isolation or binding boundary."""


class IFEMSyntheticRoleOptionV1(StrEnum):
    """The only public side vocabulary; it has no semantic preferred side."""

    A = "option_a"
    B = "option_b"


class IFEMSyntheticRoleFixtureAuthorityV1(ContractModel):
    """Hard-negative authority boundary for public synthetic prompt evidence."""

    schema_version: Literal["autolean.ifem-synthetic-role-fixture-authority.v1"] = (
        "autolean.ifem-synthetic-role-fixture-authority.v1"
    )
    external_text_embedded: Literal[False] = False
    restricted_reference_embedded: Literal[False] = False
    structural_side_metadata_embedded: Literal[False] = False
    private_evaluator_data_embedded: Literal[False] = False
    paired_side_identity_embedded: Literal[False] = False
    provider_credentials_present: Literal[False] = False
    model_egress_authorized: Literal[False] = False
    benchmark_authority: Literal[False] = False
    semantic_equivalence_claimed: Literal[False] = False
    statement_contract_created: Literal[False] = False
    freeze_allowed: Literal[False] = False
    prover_handoff_allowed: Literal[False] = False
    promotion_allowed: Literal[False] = False


class IFEMSyntheticRolePublicCaseV1(ContractModel):
    """One neutral two-option prompt with exact source and rights bindings."""

    schema_version: Literal["autolean.ifem-synthetic-role-public-case.v1"] = (
        "autolean.ifem-synthetic-role-public-case.v1"
    )
    ordinal: int = Field(ge=1, le=_CASE_COUNT)
    case_id: StableIdentifierV1
    role: IFEMStructuralProbeRoleV1
    prompt: str = Field(min_length=80, max_length=4096)
    source: SourceRecordV1
    rights: RightsRecordV1
    authority: IFEMSyntheticRoleFixtureAuthorityV1 = Field(
        default_factory=IFEMSyntheticRoleFixtureAuthorityV1
    )
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_case(self) -> Self:
        if self.case_id.namespace != "ifem.synthetic-role-case":
            raise ValueError("synthetic role case has an unexpected public namespace")
        if self.role is not _EXPECTED_ROLES[self.ordinal - 1]:
            raise ValueError("synthetic role case role differs from the fixed ordinal projection")
        expected_case_id = stable_identifier("ifem.synthetic-role-case", f"v1:{self.ordinal}")
        if self.case_id != expected_case_id:
            raise ValueError("synthetic role case identifier differs from its ordinal")
        if self.source.source_id != self.rights.source_id:
            raise ValueError("synthetic role rights must bind the exact source record")
        if len(self.source.spans) != 1:
            raise ValueError("synthetic role case must have exactly one egress span")
        span = self.source.spans[0]
        expected_source_id = stable_identifier("ifem.synthetic-role-source", f"v1:{self.ordinal}")
        expected_span_id = stable_identifier("ifem.synthetic-role-span", f"v1:{self.ordinal}")
        expected_rights_id = stable_identifier("ifem.synthetic-role-rights", f"v1:{self.ordinal}")
        if self.source.source_id != expected_source_id:
            raise ValueError("synthetic role source identifier differs from its ordinal")
        if span.span_id != expected_span_id:
            raise ValueError("synthetic role span identifier differs from its ordinal")
        if self.rights.rights_id != expected_rights_id:
            raise ValueError("synthetic role rights identifier differs from its ordinal")
        if (
            self.source.work_id != "autolean-project-synthetic-role-calibration-v1"
            or self.source.title != "AutoLean project synthetic role calibration prompts"
            or self.source.version != "1"
            or self.source.locator != "repo://benchmarks/ifem_synthetic_role_fixture.py"
            or self.source.retrieved_at != _REVIEWED_AT
            or self.source.metadata
            != {
                "fixture_revision": "1",
                "egress_encoding": "utf-8",
                "authorship": "autolean_project_synthetic",
            }
        ):
            raise ValueError("synthetic role source provenance differs from the fixed projection")
        if span.locator != f"repo://benchmarks/ifem_synthetic_role_fixture.py#case-{self.ordinal}":
            raise ValueError("synthetic role span locator differs from the fixed projection")
        prompt_bytes = self.prompt.encode("utf-8")
        if span.permitted_excerpt != self.prompt:
            raise ValueError("permitted_excerpt must exactly equal the outbound prompt")
        if span.content_hash != digest_text(HashKindV1.SOURCE_SPAN, self.prompt):
            raise ValueError("source span hash does not match the outbound prompt")
        if self.source.content_hash != digest_bytes(HashKindV1.SOURCE_BYTES, prompt_bytes):
            raise ValueError("source hash does not match the outbound prompt bytes")
        if span.start_offset != 0 or span.end_offset != len(prompt_bytes):
            raise ValueError("source span offsets must cover the exact UTF-8 egress bytes")
        if self.rights.overall_decision is not PermissionDecisionV1.ALLOW:
            raise ValueError("the project-authored prompt rights must be allowed")
        if self.rights.redistribution is not PermissionDecisionV1.ALLOW:
            raise ValueError("the project-authored prompt must be redistributable")
        if self.rights.model_egress is not PermissionDecisionV1.ALLOW:
            raise ValueError("the project-authored prompt must permit model egress")
        if self.rights.allowed_endpoint_classes != (EndpointClassV1.APPROVED_EXTERNAL,):
            raise ValueError("synthetic role rights must name approved_external exactly")
        if (
            self.rights.source_license != "Apache-2.0"
            or self.rights.generated_code_license != "Apache-2.0"
            or self.rights.attribution != "AutoLean project synthetic role calibration; Apache-2.0"
            or self.rights.restrictions != ("project-authored calibration text only",)
            or self.rights.reviewed_by != "autolean-project-synthetic-rights-v1"
            or self.rights.reviewed_at != _REVIEWED_AT
        ):
            raise ValueError("synthetic role rights provenance differs from the fixed projection")
        lowered_prompt = self.prompt.lower()
        if any(term in lowered_prompt for term in _PUBLIC_FORBIDDEN_PROMPT_TERMS):
            raise ValueError("public prompt contains a forbidden private/source label")
        if self.content_sha256 != self.computed_content_sha256():
            raise ValueError("synthetic role case content hash does not match its payload")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(
            dict[str, object],
            self.model_dump(mode="json", exclude={"content_sha256"}),
        )

    def computed_content_sha256(self) -> str:
        return _sha256_json(self.content_payload())


class IFEMSyntheticRolePublicFixtureV1(ContractModel):
    """Public-only projection of exactly the 16 project-synthetic probe pairs."""

    schema_version: Literal["autolean.ifem-synthetic-role-public-fixture.v1"] = (
        IFEM_SYNTHETIC_ROLE_FIXTURE_SCHEMA
    )
    artifact_kind: Literal["project_synthetic_neutral_role_prompts"] = (
        IFEM_SYNTHETIC_ROLE_FIXTURE_KIND
    )
    fixture_revision: Literal["1"] = "1"
    case_count: Literal[16] = 16
    cases: tuple[IFEMSyntheticRolePublicCaseV1, ...] = Field(
        min_length=_CASE_COUNT,
        max_length=_CASE_COUNT,
    )
    contains_external_text: Literal[False] = False
    contains_restricted_reference: Literal[False] = False
    contains_structural_side_metadata: Literal[False] = False
    contains_private_evaluator_data: Literal[False] = False
    contains_paired_side_identity: Literal[False] = False
    authority: IFEMSyntheticRoleFixtureAuthorityV1 = Field(
        default_factory=IFEMSyntheticRoleFixtureAuthorityV1
    )
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_fixture(self) -> Self:
        if self.case_count != len(self.cases):
            raise ValueError("synthetic role case_count does not match the case tuple")
        if tuple(item.ordinal for item in self.cases) != tuple(range(1, _CASE_COUNT + 1)):
            raise ValueError("synthetic role cases must use canonical ordinal order")
        ids = tuple(item.case_id for item in self.cases)
        if len(set(ids)) != len(ids):
            raise ValueError("synthetic role public case identifiers must be unique")
        if self.content_sha256 != self.computed_content_sha256():
            raise ValueError("synthetic role fixture content hash does not match its payload")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(
            dict[str, object],
            self.model_dump(mode="json", exclude={"content_sha256"}),
        )

    def computed_content_sha256(self) -> str:
        return _sha256_json(self.content_payload())


class IFEMSyntheticRolePrivateOracleAuthorityV1(ContractModel):
    """Private evaluator authority; it never grants execution or promotion power."""

    schema_version: Literal["autolean.ifem-synthetic-role-private-oracle-authority.v1"] = (
        "autolean.ifem-synthetic-role-private-oracle-authority.v1"
    )
    public_projection_allowed: Literal[False] = False
    model_egress_authorized: Literal[False] = False
    benchmark_authority: Literal[False] = False
    statement_contract_created: Literal[False] = False
    freeze_allowed: Literal[False] = False
    prover_handoff_allowed: Literal[False] = False
    promotion_allowed: Literal[False] = False


class IFEMSyntheticRolePrivateOracleRecordV1(ContractModel):
    """One private side label retained independently of the public prompt."""

    schema_version: Literal["autolean.ifem-synthetic-role-private-oracle-record.v1"] = (
        "autolean.ifem-synthetic-role-private-oracle-record.v1"
    )
    public_case_id: StableIdentifierV1
    source_pair_id: StableIdentifierV1
    pair_sha256: str = Field(pattern=_SHA256)
    baseline_option: IFEMSyntheticRoleOptionV1
    role: IFEMStructuralProbeRoleV1
    risk: str = Field(min_length=1)
    mutation: str = Field(min_length=1)
    witness_commitment_sha256: str = Field(pattern=_SHA256)


class IFEMSyntheticRolePrivateOracleV1(ContractModel):
    """Separate operator-private expected-side projection for later evaluation."""

    schema_version: Literal["autolean.ifem-synthetic-role-private-oracle.v1"] = (
        "autolean.ifem-synthetic-role-private-oracle.v1"
    )
    fixture_revision: Literal["1"] = "1"
    seed_commitment: str = Field(pattern=_SHA256)
    records: tuple[IFEMSyntheticRolePrivateOracleRecordV1, ...] = Field(
        min_length=_CASE_COUNT,
        max_length=_CASE_COUNT,
    )
    authority: IFEMSyntheticRolePrivateOracleAuthorityV1 = Field(
        default_factory=IFEMSyntheticRolePrivateOracleAuthorityV1
    )

    @model_validator(mode="after")
    def validate_oracle(self) -> Self:
        if tuple(item.public_case_id for item in self.records) != tuple(
            sorted((item.public_case_id for item in self.records), key=lambda item: item.value)
        ):
            raise ValueError("private oracle records must use canonical public case order")
        if len({item.public_case_id for item in self.records}) != len(self.records):
            raise ValueError("private oracle public case identifiers must be unique")
        return self


def build_ifem_synthetic_role_fixture(
    corpus: IFEMStructuralRoleProbeCorpusV1,
    *,
    operator_seed: bytes | str,
) -> IFEMSyntheticRolePublicFixtureV1:
    """Build the public fixture without retaining the private side labels."""

    verified = _revalidate_corpus(corpus)
    seed = _seed_bytes(operator_seed)
    cases = tuple(
        _build_public_case(
            pair, ordinal=ordinal, baseline_option=_baseline_option(seed, ordinal, pair)
        )
        for ordinal, pair in enumerate(verified.pairs, start=1)
    )
    payload: dict[str, object] = {
        "schema_version": IFEM_SYNTHETIC_ROLE_FIXTURE_SCHEMA,
        "artifact_kind": IFEM_SYNTHETIC_ROLE_FIXTURE_KIND,
        "fixture_revision": "1",
        "case_count": _CASE_COUNT,
        "cases": [case.model_dump(mode="json") for case in cases],
        "contains_external_text": False,
        "contains_restricted_reference": False,
        "contains_structural_side_metadata": False,
        "contains_private_evaluator_data": False,
        "contains_paired_side_identity": False,
        "authority": IFEMSyntheticRoleFixtureAuthorityV1().model_dump(mode="json"),
    }
    payload["content_sha256"] = _sha256_json(payload)
    try:
        return IFEMSyntheticRolePublicFixtureV1.model_validate(payload)
    except ValueError as error:
        raise IFEMSyntheticRoleFixtureError("public synthetic fixture did not validate") from error


def build_ifem_synthetic_role_oracle(
    corpus: IFEMStructuralRoleProbeCorpusV1,
    *,
    operator_seed: bytes | str,
) -> IFEMSyntheticRolePrivateOracleV1:
    """Return the private expected-side object independently of public serialization."""

    verified = _revalidate_corpus(corpus)
    seed = _seed_bytes(operator_seed)
    records = tuple(
        _oracle_record(pair, ordinal=ordinal, baseline_option=_baseline_option(seed, ordinal, pair))
        for ordinal, pair in enumerate(verified.pairs, start=1)
    )
    return IFEMSyntheticRolePrivateOracleV1(
        seed_commitment=hashlib.sha256(seed).hexdigest(),
        records=tuple(sorted(records, key=lambda item: item.public_case_id.value)),
    )


def render_ifem_synthetic_role_fixture(
    fixture: IFEMSyntheticRolePublicFixtureV1,
) -> bytes:
    """Serialize only a fully revalidated public projection."""

    if type(fixture) is not IFEMSyntheticRolePublicFixtureV1:
        raise IFEMSyntheticRoleFixtureError("fixture must be the exact public fixture type")
    try:
        verified = IFEMSyntheticRolePublicFixtureV1.model_validate(fixture.model_dump(mode="json"))
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise IFEMSyntheticRoleFixtureError(
            "fixture serialization requires a revalidated public fixture"
        ) from error
    return canonical_json_bytes(verified.model_dump(mode="json")) + b"\n"


def ifem_synthetic_role_egress_bytes(case: IFEMSyntheticRolePublicCaseV1) -> bytes:
    """Return the exact bytes whose span and rights are bound by a public case."""

    if type(case) is not IFEMSyntheticRolePublicCaseV1:
        raise IFEMSyntheticRoleFixtureError("egress requires the exact public case type")
    verified = IFEMSyntheticRolePublicCaseV1.model_validate(case.model_dump(mode="json"))
    return verified.prompt.encode("utf-8")


def _build_public_case(
    pair: IFEMStructuralRoleProbePairV1,
    *,
    ordinal: int,
    baseline_option: IFEMSyntheticRoleOptionV1,
) -> IFEMSyntheticRolePublicCaseV1:
    case_id = stable_identifier("ifem.synthetic-role-case", f"v1:{ordinal}")
    baseline = pair.baseline
    mutant = pair.mutant
    if baseline_option is IFEMSyntheticRoleOptionV1.A:
        option_a, option_b = baseline, mutant
    else:
        option_a, option_b = mutant, baseline
    prompt = _neutral_prompt(option_a, option_b)
    egress_bytes = prompt.encode("utf-8")
    source_id = stable_identifier("ifem.synthetic-role-source", f"v1:{ordinal}")
    span_id = stable_identifier("ifem.synthetic-role-span", f"v1:{ordinal}")
    source = SourceRecordV1(
        source_id=source_id,
        work_id="autolean-project-synthetic-role-calibration-v1",
        title="AutoLean project synthetic role calibration prompts",
        version="1",
        locator="repo://benchmarks/ifem_synthetic_role_fixture.py",
        content_hash=digest_bytes(HashKindV1.SOURCE_BYTES, egress_bytes),
        retrieved_at=_REVIEWED_AT,
        spans=(
            SourceSpanV1(
                span_id=span_id,
                locator=f"repo://benchmarks/ifem_synthetic_role_fixture.py#case-{ordinal}",
                content_hash=digest_text(HashKindV1.SOURCE_SPAN, prompt),
                start_offset=0,
                end_offset=len(egress_bytes),
                permitted_excerpt=prompt,
            ),
        ),
        metadata={
            "fixture_revision": "1",
            "egress_encoding": "utf-8",
            "authorship": "autolean_project_synthetic",
        },
    )
    rights = RightsRecordV1(
        rights_id=stable_identifier("ifem.synthetic-role-rights", f"v1:{ordinal}"),
        source_id=source.source_id,
        source_license="Apache-2.0",
        generated_code_license="Apache-2.0",
        overall_decision=PermissionDecisionV1.ALLOW,
        redistribution=PermissionDecisionV1.ALLOW,
        model_egress=PermissionDecisionV1.ALLOW,
        training=PermissionDecisionV1.RESTRICTED,
        embedding=PermissionDecisionV1.RESTRICTED,
        allowed_endpoint_classes=(EndpointClassV1.APPROVED_EXTERNAL,),
        attribution="AutoLean project synthetic role calibration; Apache-2.0",
        restrictions=("project-authored calibration text only",),
        reviewed_by="autolean-project-synthetic-rights-v1",
        reviewed_at=_REVIEWED_AT,
    )
    case_payload: dict[str, object] = {
        "schema_version": "autolean.ifem-synthetic-role-public-case.v1",
        "ordinal": ordinal,
        "case_id": case_id.model_dump(mode="json"),
        "role": pair.probe_role,
        "prompt": prompt,
        "source": source.model_dump(mode="json"),
        "rights": rights.model_dump(mode="json"),
        "authority": IFEMSyntheticRoleFixtureAuthorityV1().model_dump(mode="json"),
    }
    case_payload["content_sha256"] = _sha256_json(case_payload)
    try:
        return IFEMSyntheticRolePublicCaseV1.model_validate(case_payload)
    except ValueError as error:
        raise IFEMSyntheticRoleFixtureError(
            f"public synthetic case {ordinal} did not validate"
        ) from error


def _oracle_record(
    pair: IFEMStructuralRoleProbePairV1,
    *,
    ordinal: int,
    baseline_option: IFEMSyntheticRoleOptionV1,
) -> IFEMSyntheticRolePrivateOracleRecordV1:
    return IFEMSyntheticRolePrivateOracleRecordV1(
        public_case_id=stable_identifier("ifem.synthetic-role-case", f"v1:{ordinal}"),
        source_pair_id=pair.pair_id,
        pair_sha256=pair.pair_sha256,
        baseline_option=baseline_option,
        role=pair.probe_role,
        risk=pair.risk.value,
        mutation=pair.mutation.value,
        witness_commitment_sha256=pair.witness.commitment_sha256,
    )


def _neutral_prompt(
    option_a: IFEMStructuralProbeSignatureV1,
    option_b: IFEMStructuralProbeSignatureV1,
) -> str:
    def render_option(signature: IFEMStructuralProbeSignatureV1) -> str:
        clauses = (
            _quantifier_clause(signature.quantifier_order),
            _coercivity_clause(signature.coercivity_constant),
            _continuity_clause(signature.continuity_magnitude),
            _subspace_clause(signature.subspace_topology),
            _restriction_clause(signature.restriction_scope),
            _approximation_clause(signature.approximation_target),
            _parameter_clause(signature.form_parameter_order),
            _antecedent_clause(signature.antecedent_status),
        )
        return "\n".join(f"- Clause {index}: {clause}" for index, clause in enumerate(clauses, 1))

    return (
        "AutoLean project-authored calibration task.\n"
        "Compare Option A and Option B in the same abstract mathematical setting.\n"
        "List the quantified obligations for each option, then state whether the two options "
        "can be treated as interchangeable. Check the wording directly; neither option is "
        "privileged.\n\n"
        "Option A:\n"
        f"{render_option(option_a)}\n\n"
        "Option B:\n"
        f"{render_option(option_b)}"
    )


def _baseline_option(
    seed: bytes,
    ordinal: int,
    pair: IFEMStructuralRoleProbePairV1,
) -> IFEMSyntheticRoleOptionV1:
    message = _ORDER_DOMAIN + ordinal.to_bytes(2, "big") + pair.pair_sha256.encode("ascii")
    bit = hmac.new(seed, message, hashlib.sha256).digest()[0] & 1
    return IFEMSyntheticRoleOptionV1.B if bit else IFEMSyntheticRoleOptionV1.A


def _seed_bytes(value: bytes | str) -> bytes:
    if isinstance(value, str):
        value = value.encode("utf-8")
    if not isinstance(value, bytes) or not value:
        raise IFEMSyntheticRoleFixtureError("operator_seed must be non-empty bytes or text")
    return value


def _revalidate_corpus(corpus: IFEMStructuralRoleProbeCorpusV1) -> IFEMStructuralRoleProbeCorpusV1:
    if type(corpus) is not IFEMStructuralRoleProbeCorpusV1:
        raise IFEMSyntheticRoleFixtureError("fixture requires the exact role probe corpus type")
    try:
        verified = IFEMStructuralRoleProbeCorpusV1.model_validate(corpus.model_dump(mode="json"))
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise IFEMSyntheticRoleFixtureError(
            "fixture requires a revalidated, non-model-constructed probe corpus"
        ) from error
    if len(verified.pairs) != _CASE_COUNT:
        raise IFEMSyntheticRoleFixtureError("fixture requires exactly the existing 16 role pairs")
    if verified.contains_source_text or verified.contains_source_excerpt:
        raise IFEMSyntheticRoleFixtureError("source-derived probe input cannot enter this fixture")
    if verified.authority.prover_handoff_allowed or verified.authority.freeze_allowed:
        raise IFEMSyntheticRoleFixtureError("non-authoritative probe corpus cannot be routed")
    return verified


def _sha256_json(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _quantifier_clause(value: str) -> str:
    return {
        "forall_exists": "For every input u, there exists a response v satisfying the relation.",
        "exists_forall": (
            "There exists a response v such that every input u satisfies the relation."
        ),
    }[value]


def _coercivity_clause(value: str) -> str:
    return {
        "strictly_positive": "The scalar c is strictly positive (c > 0).",
        "nonnegative_allowed": "The scalar c is allowed to be nonnegative (c >= 0).",
    }[value]


def _continuity_clause(value: str) -> str:
    return {
        "absolute_value": "The estimate uses the magnitude |q|.",
        "raw_value": "The estimate uses q without taking its magnitude.",
    }[value]


def _subspace_clause(value: str) -> str:
    return {
        "closed_required": "The admissible subspace is required to be closed.",
        "closedness_omitted": "No closedness requirement is stated for the admissible subspace.",
    }[value]


def _restriction_clause(value: str) -> str:
    return {
        "trial_subspace": "The restriction quantifies over the trial subspace.",
        "ambient_space": "The restriction quantifies over the ambient space.",
    }[value]


def _approximation_clause(value: str) -> str:
    return {
        "infimum": "The bound uses an infimum and does not assert attainment.",
        "attained_minimum": "The bound asserts that a minimum is attained.",
    }[value]


def _parameter_clause(value: str) -> str:
    return {
        "trial_test": "The form is written in trial-then-test order b(u,v).",
        "test_trial": "The form is written in test-then-trial order b(v,u).",
    }[value]


def _antecedent_clause(value: str) -> str:
    return {
        "satisfiable": "The assumptions admit at least one compatible instance.",
        "contradictory": "The assumptions require incompatible conditions.",
    }[value]
