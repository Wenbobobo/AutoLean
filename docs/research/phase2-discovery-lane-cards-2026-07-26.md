# Phase 2 discovery lane cards: PDE and metric geometry

**Date:** 2026-07-26

**PDE-A source refresh:** 2026-07-26. The PDE card now names an open,
author-hosted source candidate. This changes neither its discovery-only status
nor the independent semantic-authority gate.

**Status:** public-metadata `discovery`; neither card authorizes source ingestion,
a Builder `freeze`, a Prover handoff, or a claim of new mathematics.
`production_ingestion` must first pass the Phase 1 entry gates.

## Decision

Run two small, independent discovery lanes in parallel:

1. **PDE-A: classical transport by characteristics**, from Victor Ivrii's
   open *Partial Differential Equations* textbook, with a separate rigorous
   theorem authority still required before any statement is frozen.
2. **MG-A: intrinsic distance and length spaces**, from Burago--Burago--
   Ivanov's *A Course in Metric Geometry*.

They are deliberately not a second Riemannian-geometry lane and not an SDE
lane.  The public [Brownian-motion project](https://github.com/RemyDegenne/brownian-motion)
states that stochastic integrals and Ito's lemma are still in progress, so an
independent SDE pilot would duplicate a live upstream effort rather than test
the Builder--Prover boundary.  PDE-A also makes statement fidelity visible:
the sign and initial-trace convention have concrete counterexamples.  MG-A
exercises a different failure mode: an infimum need not be attained, so a
plausible Lean statement can silently confuse a length space with a geodesic
space.

The two lanes share no source text or Lean namespace.  They may share only
stable Mathlib primitives and the versioned Builder--Prover protocol below.

## Evidence and rights policy

All links below are discovery evidence, not source admission. PDE-A has a
separate author-hosted, CC BY-SA 4.0 source candidate documented in
[the acquisition note](pde-a-ivrii-source-acquisition-2026-07-26.md). Its
metadata is verified, but its local bytes, size, and SHA-256 are still
`metadata_verified_download_pending`. MG-A remains a copyrighted commercial
reference, not a dataset. Do not download, commit, send to a model, or expose
full text unless the operator has a licence that explicitly permits the
intended use. `SourceRecordV1` stores a version/section locator, a hash of the
operator-authorized extract, and a short factual normalization; `RightsRecordV1`
must set model egress explicitly. Public artifacts may contain independently
written statements, citations, theorem identifiers, and verification results,
but not scans or substantial quotations.

The mathlib observations are a discovery snapshot, not a claim that a symbol
is absent in every revision.  Before a contract is frozen, re-run premise
search against its pinned Mathlib commit and record the result in the contract.

## Card PDE-A: classical transport by characteristics

### Source, scope, and status

**Status: `metadata_verified_download_pending`.** Victor Ivrii's official
University of Toronto [textbook index](https://www.math.toronto.edu/ivrii/PDE-textbook/)
identifies the author and orders the material from preliminaries through
fourteen chapters. Its official [PDF](https://www.math.toronto.edu/ivrii/PDE-textbook/PDE-textbook.pdf)
is 415 pages, says it is licensed under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/),
and describes an APM346 junior course whose required preparation is
multivariable calculus and ordinary differential equations. It also says that
each rendered page has Markdown source and that the whole book, PDF, and TeX
source can be downloaded. These are strong reasons to make it the local-cache
candidate instead of a commercial source.

The version evidence is intentionally not collapsed into one date: the current
PDF title page says `© Victor Ivrii, 2026`, while its preface calls itself a
`June 7, 2021` snapshot and says PDFs are updated only once in a few years.
The lock must record the actual retrieved bytes and never infer a version or
SHA-256 from either statement.

* Primary source: Ivrii, *Partial Differential Equations*, University of
  Toronto, author-hosted online textbook and PDF; local cache is not populated
  yet. The exact future cache record is sketched in
  [`pde-a-ivrii-source-lock.v1.template.json`](templates/pde-a-ivrii-source-lock.v1.template.json).
* Exact opening path: begin the mathematical source graph with the Preface,
  `0.1 What one needs to know?`, and Chapter 1; the first proposed transport
  slice is Chapter 2, [§2.1 First order PDEs](https://www.math.toronto.edu/ivrii/PDE-textbook/Chapter2/S2.1.html).
  It introduces `a u_t + b u_x = 0`, constant-coefficient characteristics,
  the initial condition at `t = 0`, and `u(x,t) = f(x-c t)` with `c = b/a` and
  `a != 0`. The initially bounded target remains the scalar, constant-speed
  equation on the full plane with a classical initial trace. Discontinuous
  data, shocks, bounded domains, and weak/distributional solutions stay out
  of scope.
* Semantic-authority limitation: the prior
  [domain audit](domain-pilot-discovery-2026-07-26.md#pde-decision) remains
  binding. Ivrii explicitly frames the course as having few theorems and
  non-rigorous proofs, so this source alone cannot authorize autonomous
  theorem conversion. A rigorous, explicitly hypothesis-bearing theorem
  source must independently review every proposed frozen statement.
* Borthwick remains a **non-ingestible cross-reference**: its Springer edition
  can help a licensed human compare exposition, but it is neither a cache
  target nor a model input for this lane.

### First useful theorem family

For a real constant `c`, a `C^1` function `u : R -> R -> R`, and an initial
profile `g`, formalize the chain-rule bridge and then the characteristic
formula:

```text
(forall t x, partial_t u t x + c * partial_x u t x = 0)
and (forall x, u 0 x = g x)
implies
forall t x, u t x = g (x - c * t).
```

This is intentionally a uniqueness/representation theorem, not an
unqualified existence theorem. Its formal contract must state the coordinate
order (`u(x,t)` in Ivrii versus any Lean curried convention), the chosen
partial-derivative encoding, `a != 0` before defining `c = b/a`, and exactly
which differentiability hypotheses justify the chain rule. The open source
provides the transport notation; the independent theorem authority provides
the rigorous statement boundary.

### 30-node dependency sketch

The graph is a Builder mathematical graph, not an import graph.  Nodes 1--12
are reusable substrate; 13--30 are the pilot theorem path.

1. real scalar field and order
2. product domain `R x R`
3. one-variable derivative
4. continuous differentiability on `R`
5. two-variable function convention
6. partial derivative in time
7. partial derivative in space
8. affine characteristic `s |-> (s, x0 + c * s)`
9. differentiability of affine characteristic
10. derivative of a composition with a characteristic
11. derivative-zero-implies-constant on `R`
12. substitution at time zero
13. classical transport-solution predicate
14. initial-trace predicate
15. normalized transport equation
16. characteristic residual identity
17. residual-zero implies constant-on-characteristic
18. value along characteristic equals initial value
19. solve characteristic footpoint `x0 = x - c * t`
20. characteristic representation formula
21. uniqueness of classical solution with identical trace
22. zero-speed specialization
23. constant-profile specialization
24. affine-profile specialization
25. quadratic-profile specialization
26. explicit candidate `g (x - c*t)`
27. candidate satisfies initial trace
28. candidate satisfies PDE under stated regularity of `g`
29. representation plus candidate gives existence-and-uniqueness, conditional
30. bridge theorem suitable for a later variable-speed or conservation-law lane

### Current Mathlib fit and blind spots

Mathlib already contains substantial analytic substrate.  It has a formal
[Lax--Milgram theorem](https://leanprover-community.github.io/mathlib4_docs/Mathlib/Analysis/InnerProductSpace/LaxMilgram.html)
and defines Sobolev spaces through Fourier analysis in
[`Mathlib.Analysis.Distribution.Sobolev`](https://leanprover-community.github.io/mathlib4_docs/Mathlib/Analysis/Distribution/Sobolev.html).
Those are later-stage PDE ingredients, not a ready-made transport-equation
API.  For this lane, use existing calculus, topology, and linear-algebra
lemmas where the pinned premise search confirms them.

Likely new downstream concepts are a deliberately minimal classical PDE
predicate, named partial-derivative wrappers, characteristic composition, and
the representation/uniqueness lemmas.  Do **not** infer from the absence of a
discovery search result that Mathlib lacks a theorem; the exact overlap is a
pre-freeze deliverable, including symbol names, imports, and the pinned commit.

### Public-work conflict risk

**Medium.** The Lean community lists a
[sphere-eversion project](https://leanprover-community.github.io/sphere-eversion/)
whose scope includes first-order partial differential relations, and Mathlib
already has Lax--Milgram.  Neither is evidence of a competing formalization of
this constant-coefficient transport result.  The public project list is not
complete, so the admission owner must check Mathlib issues/PRs, the
[project-intentions registry](https://github.com/leanprover-community/project-intentions),
and relevant Zulip threads immediately before work starts.  If a live owner
has an overlapping transport API, switch this lane to an integration/adapter
pilot or stop; do not race it.

### Five statement-conversion hazards

1. **Sign of transport:** `u_t + c*u_x = 0` has `g (x - c*t)`; changing the
   sign changes the solution.  A proof of the opposite sign is a semantic bug,
   not a successful alternate theorem.
2. **Trace versus point evaluation:** `u 0 x = g x` is a global classical
   trace.  Do not silently replace it with an almost-everywhere equality or a
   boundary trace.
3. **Regularity strength:** the chain rule needs explicit regularity.  Do not
   promote a `C^1` theorem into a weak-solution claim by omitting it.
4. **Domain quantifiers:** all of `R x R` is not a strip, a half-line, or a
   periodic domain.  The contract must bind both `t` and `x` exactly.
5. **Existence versus uniqueness:** the representation implication proves
   uniqueness for an assumed solution.  Existence requires a separately
   verified regularity theorem for the candidate.

### Feedback artifacts

* A reverse-rendered contract reviewed against the hash-locked Ivrii source
  span **and** the independent rigorous theorem authority.
* A two-column sign ledger: PDE residual and characteristic formula.
* Lean proofs for `c = 0`, constant `g`, `g(x) = x`, and `g(x) = x^2`.
* Mutation tests that flip the sign, omit the trace, weaken `C^1`, restrict the
  domain, or convert uniqueness into existence; every mutation must be
  rejected or receive a distinct contract revision.
* A generated counterexample note: `u(t,x) = g(x + c*t)` is generally a
  solution of the opposite-sign equation, so it cannot validate the target.

### GO / NO-GO

**GO** only if: (a) the official Ivrii bytes have been acquired by an operator,
hashed, and admitted through a new reference-manifest revision; (b) a separate
rigorous theorem authority supplies explicit regularity, domain, and
well-posedness hypotheses; (c) every one of nodes 13--21 has a source locator
and a mathematical-graph parent set; (d) two independent formalizers agree on
the normalized theorem or the difference is resolved by a reviewer; (e) all
five mutation tests and the four concrete feedback cases are recorded; and
(f) a pinned clean Lean build accepts the frozen statement without `sorryAx`,
extra axioms, or imports outside its allowlist.

**NO-GO / stop** if download/rights verification remains pending, Ivrii is the
only proposed statement authority, the first usable result needs weak
solutions, regularity/trace semantics remain disputed, an active project
claims the same API, or a proof attempt requires changing a quantifier, sign,
hypothesis, or conclusion. The last case emits `ContractChangeRequestV1`; it
never edits the frozen contract in place.

## Card MG-A: intrinsic distance and length spaces

### Why this lane

*A Course in Metric Geometry* explicitly targets core material accessible to
first-year graduate students, introduces concepts through simple cases, and
opens with **Chapter 1. Metric Spaces** and **Chapter 2. Length Spaces**.
This is non-smooth metric geometry, not a duplicate of smooth Riemannian
geometry.  It is a strong Builder test because "every two points can be
joined by paths whose lengths approximate distance" and "a shortest path
exists" are different statements.

* Primary source and edition: [AMS product page](https://bookstore.ams.org/gsm-33/),
   Dmitri Burago, Yuri Burago, Sergei Ivanov, *Graduate Studies in Mathematics*
   33.  The AMS page supplies the target audience and chapter list.
* Rights/access: copyrighted AMS book, offered as paid print/eBook.  Use only
   an operator-authorized copy; record exact internal page/section locators in
   `SourceRecordV1`.  Do not mirror its text or use an unverified online PDF.
* Exact opening slice: all of Chapters 1--2, stopping before Chapter 3
   *Constructions*.  The first frozen sub-slice is narrower: curve length,
   intrinsic distance, length-space and geodesic-space predicates, then the
   implication “geodesic space -> length space”.  It excludes curvature bounds,
   Hopf--Rinow-style attainment, smooth length structures, and Riemannian
   metrics.

### First useful theorem family

Define the length of a continuous path by finite partitions, define intrinsic
distance as the infimum of path lengths, and formalize:

```text
if every pair x y has a constant-speed distance-realizing path,
then the intrinsic distance between x and y equals d(x,y).
```

The contract must separate an extended-valued intrinsic distance (needed when
there is no path) from ordinary `dist`, and must name the parameter interval,
endpoint conditions, and whether “geodesic” means constant-speed or merely
distance-realizing.

### 31-node dependency sketch

1. extended/pseudo metric space interface
2. ordinary distance and non-negativity
3. compact interval as path parameter domain
4. continuous path
5. endpoints of a path
6. finite ordered partition
7. partition includes endpoints
8. partition length
9. refinement monotonicity
10. curve length as supremum over partitions
11. finite/rectifiable curve predicate
12. zero length of constant path
13. reverse path
14. concatenated path
15. lower bound `dist(endpoints) <= length`
16. Lipschitz upper bound for length
17. path family from `x` to `y`
18. intrinsic extended distance as infimum of lengths
19. no-path convention
20. `dist <= intrinsicDist`
21. length-space predicate (arbitrary epsilon approximation)
22. distance-realizing path predicate
23. constant-speed geodesic predicate
24. geodesic path is rectifiable
25. geodesic path length equals endpoint distance
26. geodesic space predicate
27. geodesic space implies length space
28. real-line segment instance
29. normed-vector-space affine segment instance
30. discrete two-point counterexample / no-path boundary
31. isometry transports path length and intrinsic distance (bridge toward GH)

### Current Mathlib fit and blind spots

Mathlib already contains important metric infrastructure.  Its
[Gromov--Hausdorff module](https://leanprover-community.github.io/mathlib4_docs/Mathlib/Topology/MetricSpace/GromovHausdorff.html)
formalizes the metric on nonempty compact metric spaces up to isometry and
uses Hausdorff distance, compactness, and isometric embeddings.  Its
[Hausdorff-dimension module](https://leanprover-community.github.io/mathlib4_docs/Mathlib/Topology/MetricSpace/HausdorffDimension.html)
also exposes metric, Lipschitz, and isometry-facing results.

The pilot should reuse those primitives plus paths, interval topology, finite
sets, `iSup`/`iInf`, and Lipschitz facts where the pinned search confirms the
exact API.  The expected blind spots are a coherent path-length/intrinsic-
metric hierarchy, the distinction between approximate and attained distance,
and transport under isometry.  This is an **expected gap**, not proof of an
upstream absence: the pre-freeze audit must search the pinned Mathlib source
and attach a mapping table of reused versus new declarations.

### Public-work conflict risk

**Medium, but manageable.** Mathlib itself already owns nearby
Gromov--Hausdorff and Hausdorff-distance APIs.  The active
[Carleson project](https://github.com/fpvandoorn/carleson) formalizes results
on doubling metric measure spaces, so broad names such as `Length` or
`MetricSpace.Geodesic` must not be introduced casually.  This lane excludes
the current Riemannian work's smooth metrics and curvature material.  Before
admission, check the current project-intentions board and Mathlib discussions;
the registry explicitly says it is informational rather than a reservation.
If a compatible upstream API already exists, replace nodes 1--27 with an
adapter/coverage task and retain only the statement-fidelity fixture.

### Five statement-conversion hazards

1. **Infimum versus minimum:** a length space supplies arbitrarily good paths;
   it does not necessarily supply a distance-realizing one.
2. **Ordinary versus extended distance:** disconnected spaces need an explicit
   no-path convention.  Coercing an infinite intrinsic distance into `R`
   silently makes the theorem false or ill-typed.
3. **Parameterization:** `[0,1]`, a subtype interval, and an arbitrary compact
   interval have different endpoint and scaling obligations.
4. **Partition definition:** omitting endpoints or reversing the refinement
   relation changes curve length.  The supremum direction must be reviewable.
5. **Hidden compactness/completeness:** these are relevant to later geodesic-
   existence theorems, not to the first implication.  Do not add them merely
   to make proof search easier.

### Feedback artifacts

* A source-to-symbol glossary: length space, intrinsic metric, rectifiable,
  distance-realizing path, and constant-speed geodesic.
* Four hand-checkable examples: `R`, a normed vector space affine segment, a
  one-point space, and a two-point discrete space.  The last is the mandatory
  no-path/non-attainment check.
* Mutation tests that replace `inf` with `min`, collapse length space into
  geodesic space, drop endpoint conditions, change the partition order, or
  inject compactness.
* An isometry-transport theorem checked against Mathlib's existing
  Gromov--Hausdorff notions, without claiming a new GH theorem.
* A diagram that distinguishes the mathematical dependency graph from Lean
  imports and from execution attempts.

### GO / NO-GO

**GO** only if: (a) the source rights and source span are recorded; (b) the
definition choice for intrinsic distance is independently reviewed; (c) all
31 nodes are either mapped to a pinned Mathlib symbol or marked as a new
downstream declaration; (d) the discrete two-point example and all five
mutations reject false conflations; and (e) the first theorem has a stable
import/axiom allowlist and builds in the pinned environment.

**NO-GO / stop** if a reviewer cannot distinguish approximate from attained
distance in the normalized statement, if the no-path convention is unresolved,
if compatibility with an upstream metric API is unclear, or if a proof attempt
needs an unrecorded completeness/compactness assumption.  Those events produce
a gap or a new contract revision, never a silent weakening.

## Common Builder--Prover handoff

For either lane, the Builder owns source interpretation and stops at the
following immutable boundary:

1. `SourceRecordV1` identifies the licensed edition, exact span, and content
   hash; `RightsRecordV1` records local access and model-egress policy.
2. `StatementContractV1` records normalized mathematics, all quantifiers and
   hypotheses, ambiguity decisions, Lean statement, source and Lean hashes,
   toolchain/Mathlib commit, imports and axiom allowlists, the three graph
   links, editable fields, and full provenance.
3. An independent fidelity reviewer accepts the contract revision, and only
   then it becomes `frozen`.  A later correction creates a new revision; it
   never changes the theorem under an already submitted proof.
4. `FormalizationTaskBundleV1` carries only the frozen revision, manifest,
   immutable Lean snapshot, allowed workspace, and attempt budget to Prover.
   It must not contain raw copyrighted source text or Builder-private notes.
5. Prover returns `ProofSubmissionV1`, `GapReportV1`, or
   `ContractChangeRequestV1`.  The verifier emits `VerificationReportV1`, and
   the Builder/review path emits `ReviewDecisionV1`.  Prover cannot add an
   assumption, alter a quantifier, broaden imports, or replace the declaration
   to obtain a passing build.

The near-term success criterion is one faithfully frozen, independently
reviewed, cleanly verified bridge bundle per lane.  It is not theorem count,
FATE score, or a claim that either field has been formalized.

## Admission order and uncertainty

Start **PDE-A** and **MG-A** as paper-only/contract-only discovery in parallel.
Admit at most one to a frozen bundle after the source-rights, conflict, and
pre-freeze premise audits complete.  Prefer PDE-A if the domain/regularity
contract settles cleanly; prefer MG-A if `intrinsicDist` can be aligned with
the pinned Mathlib API without a large foundational fork.

Confidence is **high** that the sources, chapter slices, rights restrictions,
and Brownian-motion conflict status are correctly described from their primary
pages.  Confidence is **medium** on the exact Mathlib blind spots because the
documentation is a moving snapshot and source-level premise search must run
against the future pinned commit.  Confidence is **low** that any public
registry is exhaustive; the stated pre-admission conflict check is therefore
mandatory.
