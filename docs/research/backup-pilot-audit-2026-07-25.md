# Backup Pilot Audit: Cea Comparison and van Kampen

Status: read-only research audit; no backup selected

Audit date: 2026-07-25

## Conclusion

Use an abstract pointwise Cea comparison as the first **read-only backup audit lead**. It is not
a qualifying backup pilot: its reproducible pointwise-only mathematical graph has 8 nodes, below
the 20-node floor, and only 2 of 8 nodes map directly to exact generic pinned Mathlib/core
representations in this desk audit. Even an optimistic count that assumes two uncompiled
adapters gives 4 of 8 nodes, 50 percent, below the 70--80 percent target. Pause the van Kampen
candidate. The current decision is therefore that neither backup qualifies for selection.

This ordering is only for desk, source-lead, and API inspection. Those read-only checks may
continue under the current T3 `gap/not_selected` record; they do not require an authorized backup
disposition. They do not admit either candidate, authorize source ingestion or a rights decision,
freeze a statement, prove API compatibility, or establish progress on an open problem. No expert
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

1. a reviewed 20--40-node mathematical target closure, small enough for a first real Library
   slice; any compiled formal graph is reported separately and is never added to that count;
2. a source and rights route that can be bound to exact bytes and exact spans;
3. approximately 70--80 percent of prerequisite infrastructure already available in the pinned
   public Mathlib API;
4. non-vacuity, positive and negative examples, and assumption/quantifier mutations that can
   falsify an overbroad statement;
5. a bounded route to reusable weak-field or open-problem dependencies without presenting the
   pilot itself as an open-problem result; and
6. no exact collision with active upstream work.

These are admission criteria, not targets to recover by changing the node granularity or adding
future theorems. The percentages below are desk-audit estimates over the pointwise-only graph.
They count source/API mappings, not compiled declarations or completed proofs.

## Evidence boundary

### Local records

The current [pilot manifest](../../Builder/pilots/self-calibration/pilot-manifest.v1.json)
records the Cea source as `pending_acquisition` and its license as unknown. It records the Hatcher
lead for van Kampen as `rights_restricted`. The current
[reference manifest](../../Builder/references/manifest.v2.json) contains only the McKay and Open
Logic source chains. Neither iFEM nor Hatcher has a manifest entry, cached artifact, verified
receipt, rights decision, or source span available to either candidate.

The [Library lock](../../Library/lake-manifest.json) pins Mathlib revision
`8f9d9cff6bd728b17a24e163c9402775d9e6a365`. The official pinned
[Lax--Milgram source](https://github.com/leanprover-community/mathlib4/blob/8f9d9cff6bd728b17a24e163c9402775d9e6a365/Mathlib/Analysis/InnerProductSpace/LaxMilgram.lean)
represents a bounded real bilinear form as `V ->L[R] V ->L[R] R` and exposes an `IsCoercive`
predicate. This audit counts the exact continuous-linear-map representation, and treats an
explicit-constant coercivity bridge only as a possible adapter. It does not count completeness,
the Lax--Milgram equivalence, or any solution theorem.

The same source inspection supports desk mappings to generic real normed-space, submodule, norm,
and ordered-real infrastructure. This audit did not materialize dependencies in
`Library/.lake/packages`, compile a candidate, or query any proposed declaration in a pinned
worker.

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
egress ceiling, and record a rights review. A source analyst must identify the exact spans for
continuity, coercivity, Galerkin orthogonality, and the comparison argument. Definitions of the
continuous and discrete variational problems may be retained as source context for later work,
but they are not prerequisites of the pointwise contract below.

## Candidate 1: pointwise Cea comparison

### Exact first boundary

The candidate takes:

```text
V          a real normed vector space
B          a bundled continuous real bilinear form on V
V_h        a real linear subspace of V
u, u_h     arbitrary values in V
alpha, M   real constants

trial membership:       u_h in V_h
positivity:              0 < alpha and 0 <= M
coercivity:              forall v : V,
                           alpha * norm(v) * norm(v) <= B(v, v)
continuity:              forall v w : V,
                           abs(B(v, w)) <= M * norm(v) * norm(w)
Galerkin orthogonality:  forall w : V, w in V_h ->
                           B(u - u_h, w) = 0
```

and concludes:

```text
forall v_h : V, v_h in V_h ->
  norm(u - u_h) <= (M / alpha) * norm(u - v_h).
```

The universal quantifiers in coercivity, continuity, orthogonality, and the conclusion are part
of the contract. The theorem treats `u` and `u_h` as values satisfying explicit hypotheses, not
as continuous and discrete solutions. The proof uses only bilinearity and the displayed
pointwise bound; the continuous-linear-map bundle is an exact pinned API representation, not an
invocation of Lax--Milgram. Inner-product structure, completeness, and an existence theorem are
not prerequisites.

### Pointwise-only 8-node mathematical graph

The counting unit follows the repository's [graph separation](../architecture.md): a
mathematical node is a separately nameable definition or theorem with its own normalized claim
and dependency edges. The existing
[pilot manifest](../../Builder/pilots/self-calibration/pilot-manifest.v1.json) represents such
nodes with a `node_id`, kind, normalized claim, formalization target, dependencies, and review
state. Raw binders such as `u`, individual structure fields, uses of a hypothesis, algebraic
rewrites inside a proof, Lean imports, and execution tasks are not additional mathematical
nodes. Lean declarations, instances, and imports belong to a separate formal graph, which this
audit has not compiled and therefore cannot honestly count.

| Node | Normalized claim | Depends on | Mapping status |
| --- | --- | --- | --- |
| `cea-01-normed-bilinear-setting` | `V` is a real normed vector space and `B : V ->L[R] V ->L[R] R` | None | Direct pinned Mathlib/core representations |
| `cea-02-trial-data` | `V_h` is a real submodule and `u u_h : V` | `cea-01-normed-bilinear-setting` | Direct `Submodule` representation |
| `cea-03-coercivity-all-v` | `0 < alpha` and `forall v : V`, `alpha * norm(v) * norm(v) <= B(v,v)` | `cea-01-normed-bilinear-setting` | Possible coercivity adapter; uncompiled |
| `cea-04-continuity-all-v-w` | `0 <= M` and `forall v w : V`, `abs(B(v,w)) <= M * norm(v) * norm(w)` | `cea-01-normed-bilinear-setting` | Possible bounded-bilinear adapter; uncompiled |
| `cea-05-galerkin-admissibility` | `u_h in V_h` and `forall w : V`, `w in V_h -> B(u-u_h,w) = 0` | `cea-01-normed-bilinear-setting`, `cea-02-trial-data` | New candidate hypothesis node |
| `cea-06-residual-identity` | For every `v_h in V_h`, `B(u-u_h,u-u_h) = B(u-u_h,u-v_h)` | `cea-01-normed-bilinear-setting`, `cea-02-trial-data`, `cea-05-galerkin-admissibility` | New candidate lemma |
| `cea-07-pre-cancellation-bound` | For every `v_h in V_h`, `alpha * norm(u-u_h)^2 <= M * norm(u-u_h) * norm(u-v_h)` | `cea-03-coercivity-all-v`, `cea-04-continuity-all-v-w`, `cea-06-residual-identity` | New candidate lemma |
| `cea-08-pointwise-target` | For every `v_h in V_h`, `norm(u-u_h) <= (M/alpha) * norm(u-v_h)` | `cea-02-trial-data`, `cea-03-coercivity-all-v`, `cea-07-pre-cancellation-bound` | New target statement |

The frozen mapping rule distinguishes representations from claims. A representation node is
direct only when exact generic structures are identified in pinned source. A claim node is
direct only when an exact reusable predicate or theorem is identified; merely being writable
with `forall` and equality is not coverage. An adapter has an analogous pinned declaration but
its type, constants, or quantifiers have not compiled against this contract. Candidate-specific
hypotheses and lemmas are new. On that rule, 2 of 8 nodes map directly, giving 25 percent.
If both uncompiled adapters at `cea-03` and `cea-04` require no new bridge declaration, the
optimistic estimate is 4 of 8, or 50 percent. Neither estimate reaches the 70--80 percent gate.
The only auditable graph is also below the 20-node floor. A future formal graph may contain more
Lean declarations, but it must remain separate and cannot be predicted or added to this
mathematical denominator. Therefore this pointwise slice fails both the size and current
coverage gates. It must not be padded with future work to qualify. These estimates are not a
compile result, API acceptance, proof, or semantic-fidelity judgement.

### Future work not counted in the pointwise graph

Completeness, inner-product structure, continuous-solution and discrete-solution specifications,
existence or uniqueness, and derivation of Galerkin orthogonality from those specifications all
change the contract. A later source-backed candidate could investigate the pinned Lax--Milgram
infrastructure, but it would need a new graph and source review.

The infimum corollary, finite-element geometry, Sobolev regularity, interpolation estimates, and
convergence rates are also future work. None is a prerequisite of the displayed pointwise
comparison, and none contributes to the 8-node count or coverage estimate.

### Controls and mutations

The following are proposed gates, not completed test results:

| Control | Witness or change | Required result |
| --- | --- | --- |
| Positive and non-vacuous | `V = R^2`, standard inner product, `V_h = span(e_1)`, `u = e_2`, `u_h = 0`, `alpha = M = 1`, compare with `v_h = 0` | The hypotheses hold and equality has nonzero error |
| Drop coercivity | `V = R`, `V_h = {0}`, zero form, `u = 1`, `u_h = 0`, `alpha = 1`, and `M = 0` | Reject: orthogonality and continuity hold, but comparison with zero would require `1 <= 0` |
| Drop `u_h in V_h` | `V = R`, `V_h = {0}`, `u = 0`, `u_h = 1`; orthogonality on `V_h` is trivial at zero while the bound at `v_h = 0` is false | Reject the mutated statement |
| Weaken coercivity or continuity quantifiers | Replace `forall v` with one chosen value, or replace `forall v w` with a diagonal-only bound | Reject: the proof needs coercivity at the error and continuity at the error/comparison pair |
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

## Work lanes and switching gates

### Read-only audit permitted now

The current [Phase 1 progress ledger](../phase-1-progress.md) says that a backup may be evaluated
under T3 `gap/not_selected`, while T5 freeze and any Prover bundle remain blocked. In that narrow
sense, the following work may continue now without an authorized backup disposition:

1. inspect public source and license pages, pinned Mathlib source, and official upstream issue or
   pull-request metadata without changing source or reference state;
2. refine the semantic graph, statement quantifiers, controls, overlap census, and gap record;
3. draft acquisition, rights-review, compile-spike, and expert-review requests; and
4. retain URLs, immutable revisions, hashes, access dates, and negative findings in audit notes.

Here, "read-only" means no candidate, reference-cache, manifest, rights, freeze, or selection
state is changed; writing the audit record does not turn its source leads into admitted evidence.
This lane may not ingest source bytes, retain unapproved excerpts, edit the reference manifest,
decide rights, materialize a candidate workspace, freeze a contract, select a backup, or hand
anything to Prover. The current audit has completed only this lane.

### Authorized source preparation

If the project owner chooses to investigate a new Cea boundary despite the current gate failures,
source preparation requires separate authority:

1. the operator creates a new immutable reference-manifest revision, imports and verifies the
   exact parent and derived artifacts, and preserves receipts;
2. the rights reviewer records attribution, permitted use, and the egress ceiling;
3. the source analyst binds exact spans and the definition chain required by the proposed
   contract; and
4. any local dependency materialization or compile spike is explicitly scoped and records the
   exact Library lock, imports, candidate revision, and failures.

Those actions are not authorized by delay, by the existing T3 gap, or by this audit. Source
preparation also does not select a candidate.

### Admission, selection, and freeze

The present 8-node pointwise slice cannot advance because it misses both the size and coverage
gates. An authorized successor T3 record is required to select a backup or open admission of a
different source-backed boundary; it is not required for the read-only lane above. Any revised
boundary must freeze its counting rule before scoring and must not count future theorems merely
to reach 20 nodes.

Selection then requires source and rights readiness, a current overlap/API census, a clean
pinned-Library compile spike without scope changes, the proposed positive and negative controls,
independent source interpretation, independent semantic review, ordinary library/domain review,
and authenticated Builder admission authority. Compilation alone cannot select the candidate.
Any mismatch produces a gap or Builder-owned contract-change request. Only after selection may
source-to-contract calibration and T5 freeze begin; only an unchanged frozen bundle may pass to
Prover.

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
only Galerkin orthogonality and postpones the continuous/discrete solution equations, existence,
the textbook infimum statement, and concrete finite-element structure. One response would be to
add Lax--Milgram, solution specifications, or Sobolev dependencies until the graph reaches 20
nodes. That would produce a different theorem, not repair this audit, and would make the old
coverage denominator misleading.

Such a broader Cea candidate can be legitimate only when a retained source and an independently
reviewed contract actually require those nodes. Until then, the pointwise comparison remains the
better read-only audit lead because it has a bounded statement and strong mutations, while van
Kampen has a rights blocker and exact active-upstream overlap. Neither is a qualifying Phase 1
backup. The decision should change only on retained source, API, compile, and review evidence,
not on domain popularity or narrative ambition.
