"""Deterministic evaluator-side checks for project-synthetic iFEM witnesses.

The checks in this module establish that each synthetic baseline/mutant pair has
one concrete distinguishing observation.  They do not validate a textbook
interpretation, create a Lean theorem, or grant model, freeze, or Prover
authority.
"""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from collections.abc import Mapping
from contextlib import suppress
from enum import StrEnum
from fractions import Fraction
from pathlib import Path
from types import MappingProxyType
from typing import Final, Literal, Never, Self, cast

from autolean_contracts import canonical_json_bytes
from autolean_contracts.base import ContractModel
from pydantic import Field, model_validator

from .ifem_candidate_dependency_graph import IFEMCandidateDependencyGraphV1
from .ifem_structural_calibration import IFEMStructuralRiskV1
from .ifem_structural_role_probes import (
    _WITNESS_SPECIFICATIONS,
    IFEMStructuralRoleProbeCorpusV1,
    IFEMStructuralRoleProbeError,
    IFEMStructuralWitnessKindV1,
    build_ifem_structural_role_probe_corpus,
)

_SHA256 = r"^[0-9a-f]{64}$"
IFEM_STRUCTURAL_WITNESS_VALIDATION_REPORT_FILENAME: Final[
    Literal["ifem-structural-witness-validation-report.v1.json"]
] = "ifem-structural-witness-validation-report.v1.json"

# This evaluator-side registry is deliberately independent from the role-probe
# commitment goldens.  Updating both requires an explicit source review rather
# than allowing one mutable in-process specification to certify itself.
_WITNESS_SPECIFICATION_SHA256_GOLDENS: Final[Mapping[IFEMStructuralRiskV1, str]] = MappingProxyType(
    {
        IFEMStructuralRiskV1.ABSOLUTE_VALUE: (
            "c380e94e46a77f9521fec94ba7dd3d96d7144a566009148fd0d74c8e1982d3ae"
        ),
        IFEMStructuralRiskV1.CLOSED_SUBSPACE: (
            "b2d72d89f11e929604555348b7ac8b003ef6d055c40300a77366b6670f0d8444"
        ),
        IFEMStructuralRiskV1.INFIMUM_TO_ATTAINMENT: (
            "4d0a42870fb4f0db26325783c10220eea88801e47f82a0b03105db628416ea48"
        ),
        IFEMStructuralRiskV1.PARAMETER_REVERSAL: (
            "40b05a3fcbcbd97b89b54aa666ce119efdd6b44fc4deafa64acf9962b2e50764"
        ),
        IFEMStructuralRiskV1.POSITIVITY: (
            "12b5c431097939c0afb90bcf90779fb0a033e03670d01486fb2b6721112cb865"
        ),
        IFEMStructuralRiskV1.QUANTIFIER_ORDER: (
            "6bf4abf96537461ef29b0d5b0cd733c1e420767a15ead7a3c90571b1841518e1"
        ),
        IFEMStructuralRiskV1.RESTRICTION_DOMAIN: (
            "f0ed88def878901f459cdbfbb186671c8dec9af5c06cb91dc3ac827120f2ff67"
        ),
        IFEMStructuralRiskV1.VACUOUS_HYPOTHESIS: (
            "c381cee7d463a63fd2a314ddcee6b932a23afc5109eb030bc386685789b483fd"
        ),
    }
)


class IFEMStructuralWitnessValidationError(ValueError):
    """A witness audit is invalid, stale, or attempts an authority transition."""


class IFEMStructuralDistinguishingDimensionV1(StrEnum):
    """The exact observable on which a baseline and mutant differ."""

    PREDICATE_TRUTH = "predicate_truth"
    GUARD_SATISFIABILITY = "guard_satisfiability"


class IFEMStructuralWitnessValidationScopeV1(StrEnum):
    """How much of one counterexample is checked by the local evaluator."""

    EXACT_FINITE_COMPUTATION = "exact_finite_computation"
    EXACT_SYMBOLIC_RULE = "exact_symbolic_rule"
    SCHEMA_PLUS_STANDARD_LEMMA = "schema_plus_standard_lemma"


class IFEMStructuralWitnessValidationAuthorityV1(ContractModel):
    """Hard-negative authority for mathematical probe checks."""

    schema_version: Literal["autolean.ifem-structural-witness-validation-authority.v1"] = (
        "autolean.ifem-structural-witness-validation-authority.v1"
    )
    evidence_class: Literal["project_synthetic_counterexample_check_only"] = (
        "project_synthetic_counterexample_check_only"
    )
    textbook_fidelity_claimed: Literal[False] = False
    semantic_equivalence_claimed: Literal[False] = False
    lean_checked: Literal[False] = False
    kernel_verified: Literal[False] = False
    model_input_allowed: Literal[False] = False
    model_egress_allowed: Literal[False] = False
    benchmark_authority: Literal[False] = False
    statement_contract_created: Literal[False] = False
    freeze_allowed: Literal[False] = False
    prover_handoff_allowed: Literal[False] = False
    promotion_allowed: Literal[False] = False


class IFEMStructuralRiskWitnessValidationV1(ContractModel):
    """One risk-family check without the private witness specification."""

    schema_version: Literal["autolean.ifem-structural-risk-witness-validation.v1"] = (
        "autolean.ifem-structural-risk-witness-validation.v1"
    )
    risk: IFEMStructuralRiskV1
    witness_kind: IFEMStructuralWitnessKindV1
    witness_commitment_sha256: str = Field(pattern=_SHA256)
    pair_sha256: tuple[str, ...] = Field(min_length=2, max_length=2)
    distinguishing_dimension: IFEMStructuralDistinguishingDimensionV1
    baseline_dimension_value: bool
    mutant_dimension_value: bool
    scope: IFEMStructuralWitnessValidationScopeV1
    machine_check_ids: tuple[str, ...] = Field(min_length=1)
    standard_lemma_dependencies: tuple[str, ...] = ()
    validation_sha256: str = Field(pattern=_SHA256)
    authority: IFEMStructuralWitnessValidationAuthorityV1 = Field(
        default_factory=IFEMStructuralWitnessValidationAuthorityV1
    )

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        if self.baseline_dimension_value == self.mutant_dimension_value:
            raise ValueError("structural witness does not distinguish baseline from mutant")
        if self.pair_sha256 != tuple(sorted(set(self.pair_sha256))):
            raise ValueError("structural witness pair hashes must be canonical and unique")
        if any(re.fullmatch(_SHA256, value) is None for value in self.pair_sha256):
            raise ValueError("structural witness pair references must be SHA-256 digests")
        if self.machine_check_ids != tuple(sorted(set(self.machine_check_ids))):
            raise ValueError("structural witness check identifiers must be canonical and unique")
        if self.standard_lemma_dependencies != tuple(sorted(set(self.standard_lemma_dependencies))):
            raise ValueError("standard-lemma dependencies must be canonical and unique")
        if (
            self.scope is IFEMStructuralWitnessValidationScopeV1.SCHEMA_PLUS_STANDARD_LEMMA
            and not self.standard_lemma_dependencies
        ):
            raise ValueError("schema-level validation must name its standard-lemma dependencies")
        expected = _sha256_json(self.model_dump(mode="json", exclude={"validation_sha256"}))
        if self.validation_sha256 != expected:
            raise ValueError("structural witness validation hash differs")
        return self


class IFEMStructuralWitnessValidationReportV1(ContractModel):
    """Complete eight-risk audit bound to one exact probe corpus."""

    schema_version: Literal["autolean.ifem-structural-witness-validation-report.v1"] = (
        "autolean.ifem-structural-witness-validation-report.v1"
    )
    lane_id: Literal["ifem-coercive-galerkin"] = "ifem-coercive-galerkin"
    candidate_graph_content_sha256: str = Field(pattern=_SHA256)
    probe_corpus_content_sha256: str = Field(pattern=_SHA256)
    validation_count: Literal[8] = 8
    validations: tuple[IFEMStructuralRiskWitnessValidationV1, ...] = Field(
        min_length=8, max_length=8
    )
    private_witness_specifications_embedded: Literal[False] = False
    model_payload_created: Literal[False] = False
    content_sha256: str = Field(pattern=_SHA256)
    authority: IFEMStructuralWitnessValidationAuthorityV1 = Field(
        default_factory=IFEMStructuralWitnessValidationAuthorityV1
    )

    @model_validator(mode="after")
    def validate_report(self) -> Self:
        risks = tuple(item.risk for item in self.validations)
        if risks != tuple(sorted(IFEMStructuralRiskV1, key=str)):
            raise ValueError("witness validation report must cover every risk exactly once")
        pair_hashes = tuple(
            pair_hash for validation in self.validations for pair_hash in validation.pair_sha256
        )
        if len(pair_hashes) != 16 or len(set(pair_hashes)) != 16:
            raise ValueError("witness validation report must cover every probe pair exactly once")
        expected = _sha256_json(self.model_dump(mode="json", exclude={"content_sha256"}))
        if self.content_sha256 != expected:
            raise ValueError("witness validation report content hash differs")
        return self

    def assert_not_routable(self) -> Never:
        raise IFEMStructuralWitnessValidationError(
            "synthetic witness validation cannot create model input, authorize egress, freeze a "
            "statement, or hand work to Prover"
        )


def validate_ifem_structural_witnesses(
    *,
    corpus: IFEMStructuralRoleProbeCorpusV1,
    graph: IFEMCandidateDependencyGraphV1,
) -> IFEMStructuralWitnessValidationReportV1:
    """Rebuild ``corpus`` and evaluate all eight fixed counterexample schemas."""

    if type(corpus) is not IFEMStructuralRoleProbeCorpusV1:
        raise IFEMStructuralWitnessValidationError(
            "witness validation requires an IFEMStructuralRoleProbeCorpusV1 input"
        )
    try:
        verified_corpus = IFEMStructuralRoleProbeCorpusV1.model_validate(
            corpus.model_dump(mode="json")
        )
        expected_corpus = build_ifem_structural_role_probe_corpus(
            catalog=verified_corpus.catalog,
            graph=graph,
        )
    except (ValueError, IFEMStructuralRoleProbeError) as error:
        raise IFEMStructuralWitnessValidationError(
            "witness validation requires a revalidated graph-bound probe corpus"
        ) from error
    if verified_corpus != expected_corpus:
        raise IFEMStructuralWitnessValidationError(
            "witness validation corpus differs from the exact graph-bound projection"
        )

    validations = tuple(
        _validate_risk(verified_corpus, risk) for risk in sorted(IFEMStructuralRiskV1, key=str)
    )
    payload: dict[str, object] = {
        "schema_version": "autolean.ifem-structural-witness-validation-report.v1",
        "lane_id": "ifem-coercive-galerkin",
        "candidate_graph_content_sha256": verified_corpus.candidate_graph_content_sha256,
        "probe_corpus_content_sha256": verified_corpus.content_sha256,
        "validation_count": 8,
        "validations": [item.model_dump(mode="json") for item in validations],
        "private_witness_specifications_embedded": False,
        "model_payload_created": False,
        "authority": IFEMStructuralWitnessValidationAuthorityV1().model_dump(mode="json"),
    }
    payload["content_sha256"] = _sha256_json(payload)
    try:
        return IFEMStructuralWitnessValidationReportV1.model_validate(payload)
    except ValueError as error:
        raise IFEMStructuralWitnessValidationError(
            "structural witness validation report did not validate"
        ) from error


def render_ifem_structural_witness_validation_report(
    report: IFEMStructuralWitnessValidationReportV1,
    *,
    corpus: IFEMStructuralRoleProbeCorpusV1,
    graph: IFEMCandidateDependencyGraphV1,
) -> bytes:
    """Recompute and render the exact graph-bound public validation report."""

    verified = verify_ifem_structural_witness_validation_report(
        report,
        corpus=corpus,
        graph=graph,
    )
    return canonical_json_bytes(verified.model_dump(mode="json")) + b"\n"


def verify_ifem_structural_witness_validation_report(
    report: IFEMStructuralWitnessValidationReportV1,
    *,
    corpus: IFEMStructuralRoleProbeCorpusV1,
    graph: IFEMCandidateDependencyGraphV1,
) -> IFEMStructuralWitnessValidationReportV1:
    """Rebuild the evaluator result and compare it with an untrusted report."""

    if type(report) is not IFEMStructuralWitnessValidationReportV1:
        raise IFEMStructuralWitnessValidationError(
            "cannot verify an object that is not a witness validation report"
        )
    try:
        verified = IFEMStructuralWitnessValidationReportV1.model_validate(
            report.model_dump(mode="json")
        )
    except ValueError as error:
        raise IFEMStructuralWitnessValidationError(
            "cannot render an invalid or model-constructed witness validation report"
        ) from error
    expected = validate_ifem_structural_witnesses(corpus=corpus, graph=graph)
    if verified != expected:
        raise IFEMStructuralWitnessValidationError(
            "witness report differs from exact evaluator recomputation"
        )
    return verified


def write_ifem_structural_witness_validation_report(
    *,
    cache_root: Path,
    output_path: Path,
    report: IFEMStructuralWitnessValidationReportV1,
    corpus: IFEMStructuralRoleProbeCorpusV1,
    graph: IFEMCandidateDependencyGraphV1,
) -> None:
    """Atomically persist only an exact evaluator-recomputed report."""

    serialized = render_ifem_structural_witness_validation_report(
        report,
        corpus=corpus,
        graph=graph,
    )
    try:
        root = cache_root.resolve(strict=True)
    except OSError as error:
        raise IFEMStructuralWitnessValidationError(
            "witness validation cache root does not exist"
        ) from error
    if not root.is_dir():
        raise IFEMStructuralWitnessValidationError(
            "witness validation cache root must be a directory"
        )
    target = output_path.resolve(strict=False)
    try:
        target.relative_to(root)
    except ValueError as error:
        raise IFEMStructuralWitnessValidationError(
            "witness validation report output must stay below its cache root"
        ) from error
    if target.name != IFEM_STRUCTURAL_WITNESS_VALIDATION_REPORT_FILENAME:
        raise IFEMStructuralWitnessValidationError(
            "witness validation report output must use the canonical artifact filename"
        )

    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
    )
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(serialized)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_name, target)
    except OSError as error:
        with suppress(OSError):
            Path(temporary_name).unlink(missing_ok=True)
        raise IFEMStructuralWitnessValidationError(
            "cannot write witness validation report"
        ) from error


def _validate_risk(
    corpus: IFEMStructuralRoleProbeCorpusV1,
    risk: IFEMStructuralRiskV1,
) -> IFEMStructuralRiskWitnessValidationV1:
    pairs = tuple(pair for pair in corpus.pairs if pair.risk is risk)
    if len(pairs) != 2:
        raise IFEMStructuralWitnessValidationError(
            "each structural risk must bind exactly two probe pairs"
        )
    commitments = {pair.witness.commitment_sha256 for pair in pairs}
    witness_kinds = {pair.witness.witness_kind for pair in pairs}
    if len(commitments) != 1 or len(witness_kinds) != 1:
        raise IFEMStructuralWitnessValidationError(
            "role-specific pairs disagree on their risk witness"
        )
    dimension, baseline, mutant, scope, checks, lemmas = _evaluate_counterexample(risk)
    payload: dict[str, object] = {
        "schema_version": "autolean.ifem-structural-risk-witness-validation.v1",
        "risk": risk,
        "witness_kind": next(iter(witness_kinds)),
        "witness_commitment_sha256": next(iter(commitments)),
        "pair_sha256": sorted(pair.pair_sha256 for pair in pairs),
        "distinguishing_dimension": dimension,
        "baseline_dimension_value": baseline,
        "mutant_dimension_value": mutant,
        "scope": scope,
        "machine_check_ids": sorted(checks),
        "standard_lemma_dependencies": sorted(lemmas),
        "authority": IFEMStructuralWitnessValidationAuthorityV1().model_dump(mode="json"),
    }
    payload["validation_sha256"] = _sha256_json(payload)
    return IFEMStructuralRiskWitnessValidationV1.model_validate(payload)


def _evaluate_counterexample(
    risk: IFEMStructuralRiskV1,
) -> tuple[
    IFEMStructuralDistinguishingDimensionV1,
    bool,
    bool,
    IFEMStructuralWitnessValidationScopeV1,
    tuple[str, ...],
    tuple[str, ...],
]:
    spec = _validated_witness_specification(risk)
    if risk is IFEMStructuralRiskV1.QUANTIFIER_ORDER:
        domain = cast(tuple[int, ...], spec["universe"])
        baseline = all(any(y == x for y in domain) for x in domain)
        mutant = any(all(y == x for x in domain) for y in domain)
        return _finite_truth(baseline, mutant, "two-point-equality-enumeration")

    if risk is IFEMStructuralRiskV1.POSITIVITY:
        if spec["form"] != "zero_bilinear_form" or spec["nontrivial_witness"] != "one":
            raise IFEMStructuralWitnessValidationError("positivity witness specification drifted")
        # At x = 1, 0 >= alpha is false for every alpha > 0.  Alpha = 0
        # witnesses the nonnegative mutant.
        baseline = False
        mutant = Fraction(0) >= Fraction(0)
        return _symbolic_truth(
            baseline,
            mutant,
            ("positive-alpha-refuted-at-one", "zero-alpha-admits-zero-form"),
        )

    if risk is IFEMStructuralRiskV1.ABSOLUTE_VALUE:
        if (
            spec.get("evaluation_scope") != "singleton_pair_one_one"
            or spec.get("scope_closed_under_sign_change") is not False
        ):
            raise IFEMStructuralWitnessValidationError(
                "absolute-value probe is invalid unless its finite scope excludes sign closure"
            )
        raw_value = -Fraction(1)
        bound = Fraction(0)
        baseline = abs(raw_value) <= bound
        mutant = raw_value <= bound
        return _finite_truth(baseline, mutant, "singleton-signed-bound")

    if risk is IFEMStructuralRiskV1.CLOSED_SUBSPACE:
        if (
            spec["ambient"] != "square_summable_real_sequences"
            or spec["subspace"] != "finitely_supported_sequences"
            or spec["property"] != "dense_nonclosed"
            or spec["lost_structure"] != "completeness"
        ):
            raise IFEMStructuralWitnessValidationError("closed-subspace witness drifted")
        # For u_k = 2^-k, k >= 1, the squared l2 tail after n entries is
        # exactly 1 / (3 * 4^n), so finite truncations converge to an
        # infinitely supported point outside c00.
        for n in range(1, 13):
            expected_tail_squared = Fraction(1, 3 * (4**n))
            finite_geometric_tail = Fraction(1, 4 ** (n + 1)) / Fraction(3, 4)
            if (
                finite_geometric_tail != expected_tail_squared
                or expected_tail_squared <= 0
                or expected_tail_squared > Fraction(1, 4**n)
            ):
                raise IFEMStructuralWitnessValidationError("l2 tail identity failed")
        truncation_supports = tuple(tuple(range(1, n + 1)) for n in range(1, 13))
        if any(len(support) != n for n, support in enumerate(truncation_supports, start=1)):
            raise IFEMStructuralWitnessValidationError("c00 truncation support is not finite")
        return (
            IFEMStructuralDistinguishingDimensionV1.PREDICATE_TRUTH,
            True,
            False,
            IFEMStructuralWitnessValidationScopeV1.SCHEMA_PLUS_STANDARD_LEMMA,
            (
                "c00-finite-truncation-membership",
                "c00-infinite-support-limit",
                "exact-geometric-tail-identity",
            ),
            ("closed-subspace-of-complete-space-is-complete", "c00-is-not-complete-in-l2"),
        )

    if risk is IFEMStructuralRiskV1.RESTRICTION_DOMAIN:
        # With u = e1, v -> <u,v> has coefficients (1,0), while
        # ell(v) = v_1 + v_2 has coefficients (1,1).  Restriction to the
        # first-coordinate axis compares only coefficient zero.
        if (
            spec["ambient"] != "real_plane"
            or spec["subspace"] != "first_coordinate_axis"
            or spec["outside_witness"] != "second_basis_vector"
            or spec["property"] != "ambient_element_not_in_subspace"
        ):
            raise IFEMStructuralWitnessValidationError("restriction-domain witness drifted")
        represented_coefficients = (1, 0)
        functional_coefficients = (1, 1)

        def in_trial_subspace(vector: tuple[int, int]) -> bool:
            return vector[1] == 0

        def represented(vector: tuple[int, int]) -> int:
            return sum(
                coefficient * coordinate
                for coefficient, coordinate in zip(represented_coefficients, vector, strict=True)
            )

        def functional(vector: tuple[int, int]) -> int:
            return sum(
                coefficient * coordinate
                for coefficient, coordinate in zip(functional_coefficients, vector, strict=True)
            )

        e1 = (1, 0)
        e2 = (0, 1)
        trial_samples = tuple((coordinate, 0) for coordinate in range(-3, 4))
        if not in_trial_subspace(e1) or in_trial_subspace(e2):
            raise IFEMStructuralWitnessValidationError("subspace membership witness failed")
        baseline = all(represented(vector) == functional(vector) for vector in trial_samples)
        mutant = represented(e2) == functional(e2)
        return _symbolic_truth(
            baseline,
            mutant,
            (
                "r2-ambient-coefficient-mismatch",
                "r2-subspace-coefficient-equality",
                "r2-subspace-membership-and-outside-witness",
            ),
        )

    if risk is IFEMStructuralRiskV1.INFIMUM_TO_ATTAINMENT:
        if (
            spec["domain"] != "open_unit_interval"
            or spec["objective"] != "identity"
            or spec["infimum"] != "zero"
            or spec["attained"] is not False
        ):
            raise IFEMStructuralWitnessValidationError("infimum witness specification drifted")
        samples = tuple(Fraction(1, n) for n in range(2, 18))
        if not all(Fraction(0) < value < Fraction(1) for value in samples):
            raise IFEMStructuralWitnessValidationError("open-interval sample escaped its domain")
        if not all(Fraction(0) < value / 2 < value for value in samples):
            raise IFEMStructuralWitnessValidationError("halving rule failed")
        positive_lower_bound_candidates = tuple(Fraction(1, n) for n in range(1, 18))
        refuters = tuple(
            min(candidate / 2, Fraction(1, 2)) for candidate in positive_lower_bound_candidates
        )
        if not all(
            Fraction(0) < witness < Fraction(1) and witness < candidate
            for candidate, witness in zip(positive_lower_bound_candidates, refuters, strict=True)
        ):
            raise IFEMStructuralWitnessValidationError("positive lower-bound refuter failed")
        if not all(Fraction(0) <= value for value in samples):
            raise IFEMStructuralWitnessValidationError("zero lower-bound check failed")
        return (
            IFEMStructuralDistinguishingDimensionV1.PREDICATE_TRUTH,
            True,
            False,
            IFEMStructuralWitnessValidationScopeV1.EXACT_SYMBOLIC_RULE,
            (
                "open-interval-halving-has-no-minimizer",
                "positive-lower-bound-candidate-refuters",
                "zero-is-lower-bound",
            ),
            (),
        )

    if risk is IFEMStructuralRiskV1.PARAMETER_REVERSAL:
        if (
            spec["space"] != "real_plane"
            or spec["left_argument"] != "first_basis_vector"
            or spec["right_argument"] != "second_basis_vector"
            or spec["forward_value"] != "one"
            or spec["reverse_value"] != "zero"
            or spec["symmetric_part_positive_definite"] is not True
            or spec["symmetry_assumed"] is not False
        ):
            raise IFEMStructuralWitnessValidationError("parameter-reversal witness drifted")
        matrix = cast(tuple[tuple[int, int], tuple[int, int]], spec["matrix"])
        e1 = (1, 0)
        e2 = (0, 1)

        def form(left: tuple[int, int], right: tuple[int, int]) -> int:
            return sum(
                left[row] * matrix[row][column] * right[column]
                for row in range(2)
                for column in range(2)
            )

        if matrix[0][1] == matrix[1][0]:
            raise IFEMStructuralWitnessValidationError(
                "parameter-reversal matrix is accidentally symmetric"
            )
        # Sylvester's criterion on the symmetric part.
        symmetric_00 = Fraction(matrix[0][0])
        symmetric_11 = Fraction(matrix[1][1])
        symmetric_01 = Fraction(matrix[0][1] + matrix[1][0], 2)
        symmetric_part_det = symmetric_00 * symmetric_11 - symmetric_01 * symmetric_01
        if not (symmetric_00 > 0 and symmetric_part_det > 0):
            raise IFEMStructuralWitnessValidationError("symmetric part is not positive definite")
        forward = form(e1, e2)
        reverse = form(e2, e1)
        return _symbolic_truth(
            forward == 1,
            reverse == 1,
            (
                "nonsymmetric-parameter-order-values",
                "symmetric-part-sylvester-positive-definite",
            ),
        )

    if risk is IFEMStructuralRiskV1.VACUOUS_HYPOTHESIS:
        x = Fraction(0)
        baseline_guard = x == 0
        mutant_guard = x == 0 and x != 0
        baseline_theorem = (not baseline_guard) or x * x == 0
        mutant_theorem = (not mutant_guard) or x * x == 0
        if not baseline_theorem or not mutant_theorem:
            raise IFEMStructuralWitnessValidationError("vacuity theorem-truth check drifted")
        return (
            IFEMStructuralDistinguishingDimensionV1.GUARD_SATISFIABILITY,
            baseline_guard,
            mutant_guard,
            IFEMStructuralWitnessValidationScopeV1.EXACT_FINITE_COMPUTATION,
            ("both-implications-true", "guard-satisfiability-distinguishes"),
            (),
        )

    raise AssertionError(f"unhandled structural risk: {risk}")


def _validated_witness_specification(
    risk: IFEMStructuralRiskV1,
) -> Mapping[str, object]:
    if set(_WITNESS_SPECIFICATION_SHA256_GOLDENS) != set(IFEMStructuralRiskV1):
        raise IFEMStructuralWitnessValidationError(
            "evaluator witness golden registry is incomplete"
        )
    try:
        specification = _WITNESS_SPECIFICATIONS[risk]
    except (KeyError, TypeError) as error:
        raise IFEMStructuralWitnessValidationError(
            "witness specification registry is incomplete"
        ) from error
    if not isinstance(specification, Mapping):
        raise IFEMStructuralWitnessValidationError("witness specification must be a mapping")
    if _sha256_json(specification) != _WITNESS_SPECIFICATION_SHA256_GOLDENS[risk]:
        raise IFEMStructuralWitnessValidationError(
            "witness specification differs from the approved evaluator fixture"
        )
    return specification


def _finite_truth(
    baseline: bool,
    mutant: bool,
    check_id: str,
) -> tuple[
    IFEMStructuralDistinguishingDimensionV1,
    bool,
    bool,
    IFEMStructuralWitnessValidationScopeV1,
    tuple[str, ...],
    tuple[str, ...],
]:
    return (
        IFEMStructuralDistinguishingDimensionV1.PREDICATE_TRUTH,
        baseline,
        mutant,
        IFEMStructuralWitnessValidationScopeV1.EXACT_FINITE_COMPUTATION,
        (check_id,),
        (),
    )


def _symbolic_truth(
    baseline: bool,
    mutant: bool,
    check_ids: tuple[str, ...],
) -> tuple[
    IFEMStructuralDistinguishingDimensionV1,
    bool,
    bool,
    IFEMStructuralWitnessValidationScopeV1,
    tuple[str, ...],
    tuple[str, ...],
]:
    return (
        IFEMStructuralDistinguishingDimensionV1.PREDICATE_TRUTH,
        baseline,
        mutant,
        IFEMStructuralWitnessValidationScopeV1.EXACT_SYMBOLIC_RULE,
        check_ids,
        (),
    )


def _sha256_json(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()
