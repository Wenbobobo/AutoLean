# Backup Pilot Audit: Cea Comparison and van Kampen

Status: read-only research audit; no backup selected

Audit date: 2026-07-25

## Conclusion

If the current model-theory pilot receives an authorized backup disposition, evaluate an
abstract Cea comparison slice first. Pause the van Kampen candidate.

This ordering is conditional. It does not admit either candidate, freeze a statement, authorize
source ingestion, prove API compatibility, or establish progress on an open problem. No expert
review, independent semantic review, pinned-Library compile spike, Builder admission, Prover
handoff, or promotion was performed by this audit.

The Cea boundary is deliberately the pointwise comparison estimate

```text
for every v_h in V_h,
  norm (u - u_h) <= (M / alpha) * norm (u - v_h),
```

under explicit positivity, continuity, coercivity, trial-subspace membership, and Galerkin
orthogonality hypotheses. It is not the textbook theorem with an infimum over `V_h`. Calling the
comparison lemma the full infimum theorem would silently strengthen the result and is forbidden.
A later source-backed corollary may add the infimum only after its order-theoretic hypotheses and
bridge have been stated and reviewed.

## Decision criteria

The audit uses the following minimum boundary:

1. 20--40 mathematical/formal dependency nodes, small enough for a first real Library slice;
2. a source and rights route that can be bound to exact bytes and exact spans;
3. approximately 70--80 percent of prerequisite infrastructure already available in the pinned
   public Mathlib API;
4. non-vacuity, positive and negative examples, and assumption/quantifier mutations that can
   falsify an overbroad statement;
5. a bounded route to reusable weak-field or open-problem dependencies without presenting the
   pilot itself as an open-problem result; and
6. no exact collision with active upstream work.

The percentages below are desk-audit estimates over the proposed graph. They count expected
source/API mappings, not compiled declarations or completed proofs.

## Evidence boundary

### Local records

The current [pilot manifest](../../Builder/pilots/self-calibration/pilot-manifest.v1.json)
records the Cea source as `pending_acquisition` and its license as unknown. It records the Hatcher
lead for van Kampen as `rights_restricted`. The current
[reference manifest](../../Builder/references/manifest.v2.json) contains only the McKay and Open
Logic source chains. Neither iFEM nor Hatcher has a manifest entry, cached artifact, verified
receipt, rights decision, or source span available to either candidate.

The [Library lock](../../Library/lake-manifest.json) pins Mathlib revision
`8f9d9cff6bd728b17a24e163c9402775d9e6a365`. The official Mathlib source at that revision contains
[Lax--Milgram infrastructure](https://github.com/leanprover-community/mathlib4/blob/8f9d9cff6bd728b17a24e163c9402775d9e6a365/Mathlib/Analysis/InnerProductSpace/LaxMilgram.lean),
including bounded real bilinear forms, `IsCoercive`, `continuousLinearMapOfBilin`, and
`continuousLinearEquivOfBilin`. That source inspection supports a mapping estimate only. This
audit did not materialize dependencies in `Library/.lake/packages`, compile a candidate, or query
the declarations in a pinned worker.

### Candidate textbook lead

The preferred Cea source lead is Joachim Schoberl, *Interactive Finite Elements*, Chapter 24,
["Finite element error analysis"](https://jschoeberl.github.io/iFEM/FEM/erroranalysis.html). The
chapter states the best-approximation Cea bound and identifies its constant as the ratio of the
continuity and coercivity bounds. For reproducibility, this audit inspected the
[chapter source at revision `a4ab841c4e5ec726e9b7742c9dcb352cb9645736`](https://github.com/JSchoeberl/iFEM/blob/a4ab841c4e5ec726e9b7742c9dcb352cb9645736/FEM/erroranalysis.ipynb)
and the repository's
[CC BY 4.0 license at the same revision](https://github.com/JSchoeberl/iFEM/blob/a4ab841c4e5ec726e9b7742c9dcb352cb9645736/LICENSE).
All three primary-source links were accessed on 2026-07-25.

This is a source lead, not a rights decision. Before source preparation, an operator must add a
manifest-bound parent artifact and derived text, verify their hashes, bind attribution and an
egress ceiling, and record a rights review. A source analyst must also identify the exact
preceding definitions of the variational problem, continuity, coercivity, and Galerkin
approximation; Chapter 24 alone does not authorize an inferred dependency boundary.

## Candidate 1: pointwise Cea comparison

### Exact first boundary

The candidate takes:

```text
V          a complete real inner-product space
B          a bundled continuous bilinear form on V
V_h        a linear subspace of V
u          the continuous solution value
u_h        a member of V_h
alpha, M   explicit real constants with 0 < alpha and 0 <= M

coercivity:             alpha * norm(v) * norm(v) <= B(v, v)
continuity:             abs(B(v, w)) <= M * norm(v) * norm(w)
Galerkin orthogonality: for every w in V_h, B(u - u_h, w) = 0
```

and concludes:

```text
for every v_h in V_h,
  norm(u - u_h) <= (M / alpha) * norm(u - v_h).
```

Existence and uniqueness of `u` can map to Lax--Milgram. Existence of `u_h`, finite-element
geometry, Sobolev regularity, interpolation estimates, convergence rates, and the infimum form
are outside the first boundary. In particular, the first theorem may assume a Galerkin solution;
it must not imply that Mathlib already supplies the discrete existence theorem.

### Estimated 28-node statement graph

| Node | Role | Expected disposition |
| --- | --- | --- |
| `cea-01-real-scalars` | Ordered scalar field | Existing Mathlib/core infrastructure |
| `cea-02-normed-add-group` | Normed additive structure on `V` | Existing Mathlib infrastructure |
| `cea-03-inner-product-space` | Real inner-product structure | Existing Mathlib infrastructure |
| `cea-04-complete-space` | Completeness required by Lax--Milgram | Existing Mathlib infrastructure |
| `cea-05-bundled-bilinear-form` | `V ->L[R] V ->L[R] R` representation | Existing Mathlib infrastructure |
| `cea-06-form-evaluation` | Evaluation and linearity in both arguments | Existing Mathlib infrastructure |
| `cea-07-continuity-bound` | Explicit operator bound with constant `M` | Expected generic API mapping |
| `cea-08-coercivity-predicate` | Coercivity with explicit `alpha` | Expected `IsCoercive` mapping |
| `cea-09-bilinear-to-linear-map` | `continuousLinearMapOfBilin` | Existing pinned Mathlib declaration |
| `cea-10-lax-milgram-equivalence` | Ambient solution equivalence | Existing pinned Mathlib declaration |
| `cea-11-trial-submodule` | Linear subspace `V_h` | Existing Mathlib infrastructure |
| `cea-12-submodule-membership` | Typed membership in `V_h` | Existing Mathlib infrastructure |
| `cea-13-submodule-zero` | Zero comparison member | Existing Mathlib infrastructure |
| `cea-14-submodule-add` | Addition closure | Existing Mathlib infrastructure |
| `cea-15-submodule-sub` | Negation/subtraction closure | Existing Mathlib infrastructure |
| `cea-16-error-term` | `e = u - u_h` | Existing additive infrastructure |
| `cea-17-norm-zero-case` | `norm e = 0` branch | Existing Mathlib infrastructure |
| `cea-18-norm-nonnegative` | Positivity of norms | Existing Mathlib infrastructure |
| `cea-19-positive-division` | `0 < alpha` and `M / alpha` order facts | Existing Mathlib infrastructure |
| `cea-20-real-cancellation` | Cancel the nonzero error norm | Existing Mathlib infrastructure |
| `cea-21-source-solution-spec` | Source-bound variational equation for `u` | New Builder-owned mapping |
| `cea-22-galerkin-solution-spec` | Source-bound discrete equation for `u_h` | New Builder-owned mapping |
| `cea-23-trial-membership-obligation` | Explicit proof that `u_h` is in `V_h` | New candidate obligation |
| `cea-24-galerkin-orthogonality` | Residual vanishes on every trial member | New candidate lemma |
| `cea-25-comparison-member` | Arbitrary `v_h` with membership proof | New quantifier boundary |
| `cea-26-residual-rewrite` | `B(e,e) = B(e,u-v_h)` | New candidate lemma |
| `cea-27-bound-chain` | Coercivity-to-continuity inequality chain | New candidate lemma |
| `cea-28-pointwise-comparison` | Final universally quantified estimate | New target statement |

Twenty of 28 nodes are expected to map to existing infrastructure, yielding a 71 percent point
estimate. Allowing for uncertainty in the explicit continuity/coercivity adapters gives the
reported 70--75 percent range. This estimate is not a compile result, API acceptance, proof, or
semantic-fidelity judgement.

### Controls and mutations

The following are proposed gates, not completed test results:

| Control | Witness or change | Required result |
| --- | --- | --- |
| Positive and non-vacuous | `V = R^2`, standard inner product, `V_h = span(e_1)`, `u = e_2`, `u_h = 0`, `alpha = M = 1`, compare with `v_h = 0` | The hypotheses hold and equality has nonzero error |
| Drop coercivity | Use the zero form with nonzero error and `M = 0` | Reject the mutated conclusion |
| Drop `u_h in V_h` | `V = R`, `V_h = {0}`, `u = 0`, `u_h = 1`; orthogonality on `V_h` is trivial at zero while the bound at `v_h = 0` is false | Reject the mutated statement |
| Weaken `forall v_h` to `exists v_h` | Replace the comparison quantifier | Reject as a semantic weakening even if provable |
| Remove comparison membership | Quantify over arbitrary `v_h : V` | Reject the overbroad statement |
| Remove `0 < alpha` | Permit zero or negative coercivity constant | Reject division/cancellation and the claimed estimate |
| Invert `M / alpha` | Mutate the constant to `alpha / M` | Reject with `B = diag(1,2)`, `V_h = span(e_1)`, `u = e_2`, and `u_h = 0` |
| Add the infimum silently | Replace the target with the textbook display without its order-theoretic bridge | Reject as an unreviewed stronger contract |

### Research leverage and limits

The slice could create reusable infrastructure for coercive variational problems, Galerkin
orthogonality, weak PDE formulations, numerical approximation, and later optimization/control
dependencies. That is dependency leverage, not novelty. The slice proves no convergence rate,
contains no concrete Sobolev space, and advances no named open problem.

Concrete Sobolev work remains outside this boundary. As of the access date,
[Mathlib PR #32305](https://github.com/leanprover-community/mathlib4/pull/32305) was open and
proposed Sobolev-space definitions. If a successor changes this candidate into a concrete PDE or
Sobolev theorem, the API and overlap audit must be repeated rather than inheriting the abstract
slice's estimate.

## Candidate 2: van Kampen slice

### Dependency estimate

At the pinned revision, Mathlib supplies paths, path homotopy, a fundamental groupoid, induced
maps, fundamental groups, and generic categorical colimit machinery. The pinned
[fundamental-groupoid module](https://github.com/leanprover-community/mathlib4/blob/8f9d9cff6bd728b17a24e163c9402775d9e6a365/Mathlib/AlgebraicTopology/FundamentalGroupoid/Basic.lean)
does not supply a topological van Kampen theorem. The pinned
[category-theory `VanKampen` module](https://github.com/leanprover-community/mathlib4/blob/8f9d9cff6bd728b17a24e163c9402775d9e6a365/Mathlib/CategoryTheory/Limits/VanKampen.lean)
defines van Kampen colimits in a general category; it is not the Seifert--van Kampen theorem for
fundamental groups or groupoids.

A minimum honest graph is approximately 31 nodes:

- 13 expected existing nodes: topological space, two open subspaces, union and intersection,
  basepoint, connectivity predicates, paths, path homotopy quotients, fundamental groupoid,
  induced functors, fundamental group, and generic pushout/colimit data;
- 18 missing bridge/theorem nodes: path subdivision subordinate to the cover, decomposition
  composition, common refinement, homotopy-grid refinement, invariance under decomposition,
  compatible local functors, a well-defined mediating functor, uniqueness, the canonical
  groupoid cocone, its colimit proof, basepoint automorphism extraction, induced group maps, and
  the final group pushout statement.

This is roughly 42 percent existing infrastructure, far below the target range. More
importantly, the missing nodes are the mathematical core rather than routine adapters.

### Active overlap and rights blockers

As of 2026-07-25, official Mathlib
[PR #41603](https://github.com/leanprover-community/mathlib4/pull/41603) was open and explicitly
proposed that the fundamental groupoid functor is a cosheaf, describing the work as
Seifert--van Kampen. Its changed-file list includes the top-level theorem and a large family of
path-decomposition, common-refinement, homotopy, universal-property, and colimit modules. This is
exact overlap with the hard part of the proposed slice, not merely adjacent topology work.

Official Mathlib [PR #41856](https://github.com/leanprover-community/mathlib4/pull/41856) was also
open and proposed the fundamental group of the circle. It increases API-motion risk around the
candidate's natural counterexample and non-vacuity examples. These links are primary upstream
records and were accessed on 2026-07-25; their future state is not predicted here.

Independently, the local pilot manifest marks the proposed Hatcher source as
`rights_restricted`. No Hatcher bytes, verified reference, rights review, or permitted source
span is present in the local reference cache. An alternative open source would fix only the
source blocker; it would not remove the upstream collision.

Therefore the current van Kampen candidate is paused. It is not a second immediately runnable
backup.

## Switching gates

### Main candidate to Cea evaluation

Evaluation may start only after all of:

1. an authorized successor T3 record keeps the current primary unselected and explicitly chooses
   a backup evaluation; delay or missing review is not itself a backup decision;
2. the iFEM source is added through a new immutable reference-manifest revision, cached and
   verified by the operator path, and bound to a rights decision and egress ceiling;
3. exact source spans and the preceding definition chain are retained for continuity,
   coercivity, the continuous problem, the Galerkin problem, and the comparison argument;
4. the 28-node graph and the pointwise target are versioned without presenting the infimum form
   as already proved;
5. a current overlap/API census and pinned-Library mapping spike retain their exact lock,
   imports, candidate revision, and failures; and
6. the proposed positive, negative, non-vacuity, assumption, constant, and quantifier controls
   are independently reviewed.

### Cea evaluation to selection

Selection additionally requires a clean pinned-Library compile spike without scope changes,
independent source interpretation, independent semantic review, ordinary library/domain review,
and authenticated Builder admission authority. Compilation alone cannot select the candidate.
Any mismatch produces a gap or Builder-owned contract-change request.

### Reconsidering van Kampen

van Kampen may be reconsidered only if:

1. a lawful, manifest-bound source and its full dependency boundary replace the restricted lead;
2. PR #41603 and related fundamental-group work reach a stable state;
3. a fresh API/overlap review identifies a genuinely disjoint contribution boundary; and
4. a revised 20--40 node graph demonstrates the target prerequisite-coverage range.

If upstream van Kampen work merges, AutoLean should map to or contribute through the stable
upstream API rather than duplicate its theorem. If it remains active or the hard bridge remains
mostly absent, the pause remains.

## Counter-argument and decision test

The strongest counter-argument is that the pointwise Cea comparison is too abstract: it assumes
the Galerkin solution and postpones the textbook infimum statement, so it may exercise less
domain structure than topology. That objection holds if the pilot's goal is already a concrete
finite-element convergence theorem. In that case neither candidate is ready: Cea must first
resolve discrete existence, infimum, and Sobolev dependencies, while van Kampen must resolve
rights and active upstream overlap.

For the narrower Phase 1 goal -- a faithful 20--40 node Builder--Prover boundary with strong
mutations and reusable dependency leverage -- the Cea comparison is the better first audit
target. The decision should change only on retained source, API, compile, and review evidence,
not on domain popularity or narrative ambition.
