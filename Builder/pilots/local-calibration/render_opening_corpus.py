# ruff: noqa: E501, RUF001
"""Render the repository-synthetic pre-calibration opening fixture.

This is intentionally a deterministic fixture renderer, not a source-ingestion path.  The
statements below were generated for this repository and remain pending human content review.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from autolean_builder.local_calibration import (
    LocalCalibrationDifferenceKindV1,
    LocalCalibrationDomainV1,
    LocalCalibrationExampleV1,
    LocalCalibrationFixtureCorpusV1,
    LocalCalibrationIllustrativeLeanSnippetV1,
    LocalCalibrationMutationFixtureV1,
    LocalCalibrationNormalizedStatementV1,
    LocalCalibrationReviewStateV1,
    LocalCalibrationReviewV1,
    PreCalibrationFixtureRecordV1,
    ProjectSyntheticFixtureLicenseBindingV1,
    ProjectSyntheticFixtureReleaseManifestV1,
    project_synthetic_fixture_rights_record,
    project_synthetic_fixture_source_record,
)
from autolean_contracts import (
    AmbiguitySeverityV1,
    AmbiguityV1,
    MutationKindV1,
    MutationProbeV1,
    stable_identifier,
)

_ROOT = Path(__file__).resolve().parents[3]
_OUTPUT = Path(__file__).with_name("project-synthetic-opening-corpus.v1.json")
_MANIFEST_OUTPUT = Path(__file__).with_name(
    "project-synthetic-opening-corpus.release-manifest.v1.json"
)
_LICENSE_PATH = _ROOT / "LICENSE"


def _illustrative_snippet(
    *,
    sample_id: str,
    suffix: str,
    illustrative_text: str,
    reverse_rendering: str,
) -> LocalCalibrationIllustrativeLeanSnippetV1:
    path = "a" if suffix == "snippet-a" else "b"
    return LocalCalibrationIllustrativeLeanSnippetV1(
        snippet_id=f"{sample_id}-{suffix}",
        authoring_path=f"project-synthetic:pre-calibration-path-{path}",
        declared_independence_label=f"project-synthetic-path-{path}",
        illustrative_lean_snippet=illustrative_text,
        reverse_rendering=reverse_rendering,
    )


def _mutation(sample_id: str, payload: dict[str, str]) -> LocalCalibrationMutationFixtureV1:
    probe = MutationProbeV1(
        probe_id=stable_identifier(
            "pre-calibration-fixture-probe", f"{sample_id}:{payload['code']}"
        ),
        kind=MutationKindV1(payload["probe_kind"]),
        target_path="normalized_statement",
        expected_failure=payload["reason"],
        mutated_statement_source=(
            f"{payload['mutated']}; this is an adversarial pre-calibration synthetic mutation."
        ),
    )
    return LocalCalibrationMutationFixtureV1(
        difference_kind=LocalCalibrationDifferenceKindV1(payload["difference_kind"]),
        baseline_fragment=payload["baseline"],
        mutated_fragment=payload["mutated"],
        blocker_code=payload["code"],
        blocker_reason=payload["reason"],
        probe=probe,
    )


# Each item was generated as a synthetic repository fixture. Human content review is pending.
_SPECS: tuple[dict[str, Any], ...] = (
    {
        "sample_id": "pde-a-transport-sign",
        "domain": "pde-a",
        "source": "For a sufficiently differentiable profile u0 and constant c, define u(t, x) = u0(x - c t). This defined function satisfies u_t + c u_x = 0 and u(0, x) = u0(x).",
        "normalized": "For every sufficiently differentiable u0 and constant c, define u(t, x) = u0(x - c t); conclude u_t + c u_x = 0 and u(0, x) = u0(x).",
        "quantifiers": ("for every sufficiently differentiable u0 and constant c",),
        "assumptions": (
            "u0 is sufficiently differentiable",
            "u(t, x) = u0(x - c t)",
        ),
        "conclusion": "u_t + c u_x = 0 and u(0, x) = u0(x)",
        "illustrative_snippet_a": "theorem pde_a_transport_sign (u0 : ℝ → ℝ) (c : ℝ) (h : Differentiable ℝ u0) : SatisfiesTransportEquation (fun t x => u0 (x - c * t)) c ∧ HasInitialData (fun t x => u0 (x - c * t)) u0 := by exact transportProfile_satisfies u0 c h",
        "illustrative_snippet_b": "example (u0 : ℝ → ℝ) (c : ℝ) (h : Differentiable ℝ u0) : TransportProfileSatisfies u0 c := by exact transportProfile_satisfies' u0 c h",
        "reverse": "For the explicitly defined profile, the chain rule yields the stated PDE and substitution at t = 0 yields the initial data; no uniqueness claim is made.",
        "positive": "For u0(x) = x^2, direct differentiation of u0(x - c t) cancels u_t with c u_x.",
        "negative": "Replacing x - c t by x + c t changes transport direction.",
        "ambiguity": "The displayed PDE fixes the sign convention used in this sample.",
        "mutations": (
            {
                "code": "TRANSPORT_SIGN_FLIP",
                "difference_kind": "sign_flip",
                "probe_kind": "reverse_parameters",
                "baseline": "u(t, x) = u0(x - c t)",
                "mutated": "u(t, x) = u0(x + c t)",
                "reason": "Changing minus to plus reverses transport direction for the stated PDE.",
            },
        ),
    },
    {
        "sample_id": "pde-a-initial-trace",
        "domain": "pde-a",
        "source": "A weak heat-flow solution has an L2 initial trace when u(t) converges to u0 in L2 as t decreases to zero.",
        "normalized": "For every weak heat-flow solution u and datum u0, assuming u belongs to C([0, T]; L2) and u(0) = u0, conclude lim_{t ↓ 0} ||u(t) - u0||_L2 = 0.",
        "quantifiers": ("for every weak heat-flow solution u and datum u0",),
        "assumptions": ("u belongs to C([0, T]; L2)", "u(0) = u0"),
        "conclusion": "lim_{t ↓ 0} ||u(t) - u0||_L2 = 0",
        "illustrative_snippet_a": "theorem pde_a_initial_trace (u : ℝ → L2Space) (u0 : L2Space) : HasL2InitialTrace u u0 := by exact weakHeatFlow_initialTrace u u0",
        "illustrative_snippet_b": "example (u : ℝ → L2Space) (u0 : L2Space) : HasL2InitialTrace u u0 → limAtZeroL2 u = u0 := by exact initialTrace_limit",
        "reverse": "The trace uses the L2 norm topology, not pointwise convergence.",
        "positive": "A continuous L2 curve with u(0) = u0 has the stated L2 trace.",
        "negative": "Pointwise convergence is stronger and is not supplied by an L2 trace.",
        "ambiguity": "L2 names the norm topology used for the trace.",
        "mutations": (
            {
                "code": "TRACE_TO_POINTWISE",
                "difference_kind": "drop_regularity",
                "probe_kind": "remove_side_condition",
                "baseline": "lim_{t ↓ 0} ||u(t) - u0||_L2 = 0",
                "mutated": "for every x, lim_{t ↓ 0} u(t, x) = u0(x)",
                "reason": "An L2 trace does not entail pointwise convergence without extra regularity.",
            },
        ),
    },
    {
        "sample_id": "pde-a-parabolic-regularity",
        "domain": "pde-a",
        "source": "A bounded weak heat solution is smooth in the open positive-time interior, not automatically at the initial trace.",
        "normalized": "For every u, assuming u is a bounded weak solution of u_t - Δu = 0 on (0, T) × Ω, conclude u is smooth on every compact subset of (0, T) × Ω.",
        "quantifiers": ("for every u",),
        "assumptions": ("u is bounded", "u is a weak solution of u_t - Δu = 0 on (0, T) × Ω"),
        "conclusion": "u is smooth on every compact subset of (0, T) × Ω",
        "illustrative_snippet_a": "theorem pde_a_parabolic_regularity (u : ℝ → ΩType → ℝ) : BoundedWeakHeatSolution u → SmoothOnPositiveTimeInterior u := by exact heat_interior_smooth",
        "illustrative_snippet_b": "example (u : ℝ → ΩType → ℝ) : BoundedWeakHeatSolution u → ∀ K, CompactSubsetPositiveTime K → SmoothOn u K := by exact heat_compact_interior_smooth",
        "reverse": "The conclusion is interior regularity and excludes t = 0.",
        "positive": "Rough initial data can become smooth for every positive time.",
        "negative": "Dropping weak-solution regularity leaves the smoothness claim unsupported.",
        "ambiguity": "A compact positive-time subset stays a positive distance from t = 0.",
        "mutations": (
            {
                "code": "DROP_WEAK_REGULARITY",
                "difference_kind": "drop_regularity",
                "probe_kind": "drop_assumption",
                "baseline": "u is a bounded weak solution of u_t - Δu = 0 on (0, T) × Ω",
                "mutated": "u is a solution of u_t - Δu = 0",
                "reason": "The stated regularity conclusion needs the recorded weak-solution and boundedness hypotheses.",
            },
        ),
    },
    {
        "sample_id": "pde-a-weak-uniqueness",
        "domain": "pde-a",
        "source": "Within a specified weak-solution class, a heat-flow problem has at most one solution; this does not assert existence.",
        "normalized": "For every u and v, assuming u and v lie in the stated energy class, have the same initial trace, and solve the same heat equation, conclude u = v.",
        "quantifiers": ("for every u and v",),
        "assumptions": (
            "u and v lie in the stated energy class",
            "u and v have the same initial trace",
            "u and v solve the same heat equation",
        ),
        "conclusion": "u = v",
        "illustrative_snippet_a": "theorem pde_a_weak_uniqueness (u v : WeakHeatSolution) : SameData u v → u = v := by exact weakHeat_unique",
        "illustrative_snippet_b": "example (u v : WeakHeatSolution) : SameData u v → u = v := by exact weakHeat_unique",
        "reverse": "At-most-one means any two already-given admissible solutions are equal.",
        "positive": "Two supplied admissible solutions with the same data coincide.",
        "negative": "An empty class makes at-most-one vacuous and cannot yield existence.",
        "ambiguity": "The energy class belongs to uniqueness rather than an existence assertion.",
        "mutations": (
            {
                "code": "UNIQUENESS_TO_EXISTENCE",
                "difference_kind": "uniqueness_to_existence",
                "probe_kind": "vacuity",
                "baseline": "For every u and v",
                "mutated": "For every datum there exists a unique u",
                "reason": "At-most-one uniqueness permits an empty solution class and cannot supply existence.",
            },
        ),
    },
    {
        "sample_id": "pde-a-local-existence",
        "domain": "pde-a",
        "source": "For sufficiently regular initial data, a semilinear evolution has a solution on [0, T] for a strictly positive T.",
        "normalized": "For every admissible datum u0, assuming u0 has the stated regularity, there exists T > 0 and a solution u on [0, T] with u(0) = u0.",
        "quantifiers": ("for every admissible datum u0", "there exists T > 0 and a solution u"),
        "assumptions": ("u0 has the stated regularity",),
        "conclusion": "u is a solution on [0, T] and u(0) = u0",
        "illustrative_snippet_a": "theorem pde_a_local_existence (u0 : DataSpace) : AdmissibleData u0 → ∃ T : ℝ, T > 0 ∧ LocalSolution u0 T := by exact semilinear_local_exists",
        "illustrative_snippet_b": "example (u0 : DataSpace) : AdmissibleData u0 → ∃ T, 0 < T ∧ LocalSolution u0 T := by exact semilinear_local_exists",
        "reverse": "A zero-length interval is not local existence.",
        "positive": "A regular datum has a nontrivial positive-time solution interval.",
        "negative": "T = 0 permits a degenerate interval and weakens the assertion.",
        "ambiguity": "The exact regularity class is represented by the named admissibility predicate.",
        "mutations": (
            {
                "code": "POSITIVE_LIFESPAN_WEAKENED",
                "difference_kind": "strict_to_nonstrict",
                "probe_kind": "weaken_relation",
                "baseline": "there exists T > 0 and a solution u",
                "mutated": "there exists T ≥ 0 and a solution u",
                "reason": "Non-strict positivity admits a zero-time interval rather than local existence.",
            },
        ),
    },
    {
        "sample_id": "mg-a-infimum-attainment",
        "domain": "mg-a",
        "source": "A nonempty real set bounded below has an infimum; the statement does not assert that a member attains it.",
        "normalized": "For every nonempty set S of real numbers, assuming S is bounded below, conclude inf S is a lower bound and every lower bound is at most inf S.",
        "quantifiers": ("for every nonempty set S of real numbers",),
        "assumptions": ("S is bounded below",),
        "conclusion": "inf S is a lower bound and every lower bound is at most inf S",
        "illustrative_snippet_a": "theorem mg_a_infimum_attainment (S : Set ℝ) : S.Nonempty → BddBelow S → IsGreatest (lowerBounds S) (sInf S) := by exact real_sInf_spec",
        "illustrative_snippet_b": "example (S : Set ℝ) : S.Nonempty → BddBelow S → ∀ a ∈ lowerBounds S, a ≤ sInf S := by exact lowerBound_le_sInf",
        "reverse": "The lower-bound specification of an infimum is distinct from its membership in S.",
        "positive": "For S = {x | x > 0}, inf S is 0.",
        "negative": "For that same S, 0 is not a member, so the infimum is not attained.",
        "ambiguity": "This local sample uses real infimum and does not add compactness.",
        "mutations": (
            {
                "code": "INFIMUM_TO_ATTAINMENT",
                "difference_kind": "infimum_to_attainment",
                "probe_kind": "totalization_trap",
                "baseline": "inf S is a lower bound and every lower bound is at most inf S",
                "mutated": "there exists s ∈ S with s = inf S",
                "reason": "An infimum need not be attained; the open positive ray is a counterexample.",
            },
        ),
    },
    {
        "sample_id": "mg-a-length-geodesic",
        "domain": "mg-a",
        "source": "The equality d(x, y) = inf length(γ) in a length space does not itself produce a minimizing geodesic.",
        "normalized": "For every x and y in a length space, conclude d(x, y) is the infimum of lengths of admissible curves from x to y.",
        "quantifiers": ("for every x and y in a length space",),
        "assumptions": ("the space is a length space",),
        "conclusion": "d(x, y) is the infimum of lengths of admissible curves from x to y",
        "illustrative_snippet_a": "theorem mg_a_length_geodesic (X : Type) [LengthSpace X] (x y : X) : dist x y = sInf (curveLengths x y) := by exact lengthSpace_dist_eq_inf",
        "illustrative_snippet_b": "example (X : Type) [LengthSpace X] (x y : X) : ∀ ε : ℝ, ε > 0 → ∃ γ, CurveFromTo γ x y ∧ length γ < dist x y + ε := by exact lengthSpace_almost_minimizer",
        "reverse": "A length space provides arbitrarily short curves; a geodesic attains the minimum.",
        "positive": "For every positive epsilon, a curve may lie within epsilon of the distance.",
        "negative": "A nonproper length space can fail to contain a minimizing curve.",
        "ambiguity": "Geodesic here means a curve whose length equals the distance.",
        "mutations": (
            {
                "code": "LENGTH_TO_GEODESIC",
                "difference_kind": "length_to_geodesic",
                "probe_kind": "remove_side_condition",
                "baseline": "d(x, y) is the infimum of lengths of admissible curves from x to y",
                "mutated": "there exists a geodesic γ from x to y with length γ = d(x, y)",
                "reason": "The infimum statement lacks compactness or properness hypotheses needed for attainment.",
            },
        ),
    },
    {
        "sample_id": "mg-a-quantifier-order",
        "domain": "mg-a",
        "source": "In a length space, each positive epsilon may use its own curve whose length is within epsilon of the distance.",
        "normalized": "For every x, y, and ε > 0, assuming the space is a length space, there exists an admissible curve γ from x to y with length γ < d(x, y) + ε.",
        "quantifiers": ("for every x, y, and ε > 0", "there exists an admissible curve γ"),
        "assumptions": ("the space is a length space",),
        "conclusion": "length γ < d(x, y) + ε",
        "illustrative_snippet_a": "theorem mg_a_quantifier_order (x y : X) : ∀ ε : ℝ, ε > 0 → ∃ γ, CurveFromTo γ x y ∧ length γ < dist x y + ε := by exact lengthSpace_almost_minimizer",
        "illustrative_snippet_b": "example (x y : X) : ∀ ε : ℝ, 0 < ε → ∃ γ, CurveFromTo γ x y ∧ length γ < dist x y + ε := by exact lengthSpace_almost_minimizer",
        "reverse": "The approximating curve is allowed to depend on epsilon.",
        "positive": "For any chosen epsilon, an appropriate new curve may be selected.",
        "negative": "One curve for every epsilon would typically require a minimizer.",
        "ambiguity": "The curve variable is bound only after epsilon is fixed.",
        "mutations": (
            {
                "code": "EPSILON_CURVE_QUANTIFIER_SWAP",
                "difference_kind": "quantifier_swap",
                "probe_kind": "swap_quantifiers",
                "baseline": "For every x, y, and ε > 0, assuming the space is a length space, there exists an admissible curve γ",
                "mutated": "For every x and y, there exists an admissible curve γ such that for every ε > 0",
                "reason": "Swapping epsilon and curve quantifiers upgrades approximation to an attained minimum.",
            },
            {
                "code": "STRICT_LENGTH_BOUND_WEAKENED",
                "difference_kind": "strict_to_nonstrict",
                "probe_kind": "weaken_relation",
                "baseline": "length γ < d(x, y) + ε",
                "mutated": "length γ ≤ d(x, y) + ε",
                "reason": "The source snapshot says <; replacing it by ≤ creates a different contract that requires fidelity review, irrespective of either statement's provability.",
            },
        ),
    },
    {
        "sample_id": "mg-a-nonempty-vacuity",
        "domain": "mg-a",
        "source": "Every nonempty compact subset of the real line has a member at which the identity function reaches its maximum.",
        "normalized": "For every nonempty compact K ⊆ ℝ, there exists x ∈ K such that for every y ∈ K, y ≤ x.",
        "quantifiers": ("for every nonempty compact K ⊆ ℝ", "there exists x ∈ K"),
        "assumptions": ("K is compact", "K is nonempty"),
        "conclusion": "for every y ∈ K, y ≤ x",
        "illustrative_snippet_a": "theorem mg_a_nonempty_vacuity (K : Set ℝ) : IsCompact K → K.Nonempty → ∃ x ∈ K, ∀ y ∈ K, y ≤ x := by exact compact_exists_isGreatest",
        "illustrative_snippet_b": "example (K : Set ℝ) : IsCompact K → K.Nonempty → ∃ x ∈ K, ∀ y ∈ K, y ≤ x := by exact compact_exists_isGreatest",
        "reverse": "The maximum must be a member of K, so a witness requires nonemptiness.",
        "positive": "A nonempty compact interval has a maximum element.",
        "negative": "The empty compact set has no member witness even though comparisons are vacuous.",
        "ambiguity": "Maximum means a member of K, not merely an upper bound.",
        "mutations": (
            {
                "code": "DROP_NONEMPTY_MAXIMIZER",
                "difference_kind": "drop_nonempty",
                "probe_kind": "drop_nonempty",
                "baseline": "For every nonempty compact K ⊆ ℝ, there exists x ∈ K",
                "mutated": "For every compact K ⊆ ℝ, there exists x ∈ K",
                "reason": "The empty compact set has no witness, so nonemptiness cannot be dropped.",
            },
            {
                "code": "EMPTY_SET_VACUITY",
                "difference_kind": "vacuity",
                "probe_kind": "vacuity",
                "baseline": "For every nonempty compact K ⊆ ℝ, there exists x ∈ K",
                "mutated": "For every compact K ⊆ ℝ, for every y ∈ K, y ≤ x",
                "reason": "A vacuous comparison cannot replace the required member witness.",
            },
        ),
    },
    {
        "sample_id": "mg-a-endpoint-order",
        "domain": "mg-a",
        "source": "A path from x to y has γ(0) = x and γ(1) = y; reversing endpoints changes the directed path specification.",
        "normalized": "For every x, y, and path γ, assuming γ is continuous with γ(0) = x and γ(1) = y, conclude γ is an admissible path from x to y.",
        "quantifiers": ("for every x, y, and path γ",),
        "assumptions": ("γ is continuous", "γ(0) = x", "γ(1) = y"),
        "conclusion": "γ is an admissible path from x to y",
        "illustrative_snippet_a": "theorem mg_a_endpoint_order (γ : ℝ → X) (x y : X) : Continuous γ → γ 0 = x → γ 1 = y → PathFromTo γ x y := by exact pathFromTo_intro",
        "illustrative_snippet_b": "example (γ : ℝ → X) (x y : X) : Continuous γ → γ 0 = x → γ 1 = y → PathFromTo γ x y := by exact pathFromTo_intro",
        "reverse": "Endpoint order is part of directed path data even when the metric is symmetric.",
        "positive": "A path with those endpoint values is admitted from x to y.",
        "negative": "Reversed endpoints define a path from y to x unless x = y.",
        "ambiguity": "This sample fixes the parameter interval endpoints as 0 and 1.",
        "mutations": (
            {
                "code": "PATH_ENDPOINTS_REVERSED",
                "difference_kind": "reverse_parameters",
                "probe_kind": "reverse_parameters",
                "baseline": "γ(0) = x and γ(1) = y",
                "mutated": "γ(0) = y and γ(1) = x",
                "reason": "Reversing endpoint equations changes the directed path predicate.",
            },
        ),
    },
)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def build_corpus() -> LocalCalibrationFixtureCorpusV1:
    records: list[PreCalibrationFixtureRecordV1] = []
    for item in _SPECS:
        sample_id = item["sample_id"]
        normalized = LocalCalibrationNormalizedStatementV1(
            normalized_statement=item["normalized"],
            quantifiers=item["quantifiers"],
            assumptions=item["assumptions"],
            conclusion=item["conclusion"],
        )
        ambiguity = AmbiguityV1(
            ambiguity_id=stable_identifier("pre-calibration-fixture-ambiguity", sample_id),
            description=item["ambiguity"],
            severity=AmbiguitySeverityV1.INFORMATIONAL,
            resolution=(
                "The synthetic fixture declares this convention for testing; "
                "it is not a domain-expert signoff."
            ),
            resolved_by="project-synthetic fixture declaration, not human review",
        )
        records.append(
            PreCalibrationFixtureRecordV1(
                sample_id=sample_id,
                domain=LocalCalibrationDomainV1(item["domain"]),
                source_text=item["source"],
                source=project_synthetic_fixture_source_record(
                    sample_id=sample_id,
                    source_text=item["source"],
                    title=f"AutoLean project-synthetic pre-calibration fixture: {sample_id}",
                ),
                rights=project_synthetic_fixture_rights_record(
                    sample_id=sample_id,
                    source_text=item["source"],
                ),
                normalized=normalized,
                ambiguities=(ambiguity,),
                illustrative_lean_snippets=(
                    _illustrative_snippet(
                        sample_id=sample_id,
                        suffix="snippet-a",
                        illustrative_text=item["illustrative_snippet_a"],
                        reverse_rendering=item["reverse"],
                    ),
                    _illustrative_snippet(
                        sample_id=sample_id,
                        suffix="snippet-b",
                        illustrative_text=item["illustrative_snippet_b"],
                        reverse_rendering=item["reverse"],
                    ),
                ),
                positive_examples=(
                    LocalCalibrationExampleV1(
                        example_id=f"{sample_id}-positive",
                        description=item["positive"],
                        expected_outcome=(
                            "Declared positive fixture for later independent semantic review."
                        ),
                    ),
                ),
                negative_examples=(
                    LocalCalibrationExampleV1(
                        example_id=f"{sample_id}-negative",
                        description=item["negative"],
                        expected_outcome=(
                            "Declared negative fixture for later independent semantic review."
                        ),
                    ),
                ),
                mutation_fixtures=tuple(
                    _mutation(sample_id, mutation) for mutation in item["mutations"]
                ),
                review=LocalCalibrationReviewV1(
                    state=(
                        LocalCalibrationReviewStateV1.SYNTHETIC_FIXTURES_RECORDED_PENDING_INDEPENDENT_REVIEW
                    ),
                    notes=(
                        "Two illustrative unparsed text snapshots and declared synthetic mutation "
                        "fixtures are recorded; independent semantic review remains required."
                    ),
                ),
            )
        )
    corpus = LocalCalibrationFixtureCorpusV1(
        repository_license_binding=ProjectSyntheticFixtureLicenseBindingV1(
            repository_license_sha256=_sha256_bytes(_LICENSE_PATH.read_bytes()),
        ),
        samples=tuple(records),
    )
    corpus.assert_opening_coverage()
    return corpus


def render() -> str:
    return json.dumps(build_corpus().model_dump(mode="json"), ensure_ascii=True, indent=2) + "\n"


def render_release_manifest(rendered_corpus: str) -> str:
    manifest = ProjectSyntheticFixtureReleaseManifestV1(
        fixture_sha256=_sha256_bytes(rendered_corpus.encode("utf-8")),
        renderer_sha256=_sha256_bytes(Path(__file__).read_bytes()),
        repository_license_sha256=_sha256_bytes(_LICENSE_PATH.read_bytes()),
    )
    return json.dumps(manifest.model_dump(mode="json"), ensure_ascii=True, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rendered = render()
    rendered_manifest = render_release_manifest(rendered)
    rendered_bytes = rendered.encode("utf-8")
    rendered_manifest_bytes = rendered_manifest.encode("utf-8")
    if args.check:
        corpus_matches = _OUTPUT.exists() and _OUTPUT.read_bytes() == rendered_bytes
        manifest_matches = (
            _MANIFEST_OUTPUT.exists() and _MANIFEST_OUTPUT.read_bytes() == rendered_manifest_bytes
        )
        return 0 if corpus_matches and manifest_matches else 1
    _OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    _OUTPUT.write_bytes(rendered_bytes)
    _MANIFEST_OUTPUT.write_bytes(rendered_manifest_bytes)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
