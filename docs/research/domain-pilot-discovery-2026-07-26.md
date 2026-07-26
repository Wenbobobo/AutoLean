# Domain Pilot Discovery Gates

Status: read-only source and library audit; no domain pilot selected

Audit date: 2026-07-26 (Asia/Shanghai)

Repository baseline: `585a4fcc0dc7c1f2d04ea931198923a2fd743cba`

Pinned Mathlib baseline: `v4.28.0`,
`8f9d9cff6bd728b17a24e163c9402775d9e6a365`

## Conclusion

None of the four audited textbook routes qualifies as the first 20--40-node Builder domain
pilot.

| Direction | Source lead | Decision | Decisive gate |
| --- | --- | --- | --- |
| SDE | Sarkka--Solin, *Applied Stochastic Differential Equations* | **NO-GO** | The available PDF is personal-use-only and forbids adaptation and redistribution; active Lean work overlaps the intended Ito foundation |
| PDE | Ivrii, *Partial Differential Equations* | **NO-GO** | The author explicitly says the course has very few theorems and non-rigorous proofs; this is unsuitable as the semantic authority for theorem conversion |
| Riemannian geometry | Robbin--Salamon, *Introduction to Differential Geometry* | **NO-GO** | No open adaptation/redistribution license was found, and connections/geodesics/curvature are moving upstream |
| Metric algebraic geometry | Breiding--Kohn--Sturmfels, *Metric Algebraic Geometry* | **NO-GO as first textbook**; **retain as secondary calibration and roadmap** | It is a short graduate seminar text, and the opening polar-geometry core is mostly absent or requires substantive bridges |

These decisions reject a particular source-and-boundary pair, not the mathematical field. SDE,
PDE, Riemannian geometry, and metric algebraic geometry remain strategically useful weak-library
areas.

## What the 70--80 percent gate means

The earlier shorthand "70--80 percent exists in Mathlib" admits two incompatible readings. The
admission gate is the first reading below, not the second:

1. **Prerequisite-definition coverage** is the proportion of a frozen pilot's *prerequisite
   nodes* whose mathematical representation and basic API already exist in the pinned public
   Mathlib. The intended first-pilot range is approximately 70--80 percent. A new target theorem
   is not expected to exist already.
2. **Exact statement reuse** is the proportion of nodes for which an existing declaration has
   the same mathematical relation, quantifiers, assumptions, domain, and conclusion. It is a
   useful diagnostic, but 70--80 percent exact theorem reuse is not an admission requirement.
3. **Thin adapter coverage** is reported separately. A coordinate wrapper, notation bridge, or
   direct finite-sum specialization may be thin, but it is not exact until its type elaborates in
   the pinned environment without changing mathematical content.
4. **Missing** means that the audit found no matching public declaration in its stated scope. It
   does not mean that the result is impossible, globally absent, or absent from private work.

The denominator must be frozen before scoring. Mathematical nodes, Lean declarations, imports,
proof steps, and execution jobs are different graphs and cannot be mixed to improve a percentage.
A candidate may stop before node scoring when source fidelity, rights, or exact upstream
collision already makes it inadmissible.

### Route decision: start at the book, build at the frontier

"Start from the beginning of the textbook" means that discovery constructs the
`MathematicalGraph`, source chain, and definition mapping from Chapter 1 (or the book's explicit
first mathematical chapter). It does **not** mean re-proving prerequisites that already exist in
the pinned Library.

After that semantic chain is reviewed, the formal Builder frontier begins at the first
high-leverage missing node. Existing prerequisites are imported through exact, audited mappings;
thin adapters are compiled and reviewed; only genuinely missing nodes become new formal assets.
This preserves the textbook's meaning and dependency order without rebuilding Mathlib for its own
sake.

## Evidence boundary

This document is a discovery-only record. It creates no local source cache entry, chooses no
pilot, freezes no statement, and authorizes no Prover handoff.

The local source lock and `Library/lake-manifest.json` both pin Mathlib to
[`8f9d9cff...`](https://github.com/leanprover-community/mathlib4/tree/8f9d9cff6bd728b17a24e163c9402775d9e6a365).
The associated archive SHA-256 is
`e6d04f776a22f4159667589dec4b317605972e8d2c2b4a338324a372c56ee6a3`.

Library mappings below are desk audits of that frozen source archive. No candidate statement was
elaborated, no exact declaration type was queried, and no candidate was kernel-compiled. Current
upstream overlap was checked separately on 2026-07-26; an open pull request is not part of the
frozen baseline and is never counted as existing substrate.

No textbook PDF was downloaded into this worktree. No source span, rights record, statement
contract, Builder admission, Prover bundle, or open-problem result was created.

## SDE

### SDE source and rights

Simo Sarkka and Arno Solin's
[*Applied Stochastic Differential Equations*](https://users.aalto.fi/~ssarkka/pub/sde_book.pdf)
is a coherent applied introduction covering ODE background, Ito calculus, SDE distributions,
simulation, filtering, parameter estimation, and machine learning. The authors' publication
[page](https://users.aalto.fi/~asolin/publications/) says the practical treatment assumes only
ordinary differential equations.

The available PDF states that it is for personal use only and must not be adapted, sold, or
redistributed. The Cambridge
[copyright record](https://assets.cambridge.org/97813165/10087/copyright/9781316510087_copyright_info.pdf)
also reserves reproduction absent permission. Free access therefore does not supply the rights
needed for a public, model-assisted source-to-contract workflow. This gate fires before source
ingestion or a 20--40-node mapping.

### SDE frozen mapping and active overlap

The frozen Mathlib tree has substantial generic probability substrate, including
[`Probability/Process`](https://github.com/leanprover-community/mathlib4/tree/8f9d9cff6bd728b17a24e163c9402775d9e6a365/Mathlib/Probability/Process),
[`Probability/Martingale`](https://github.com/leanprover-community/mathlib4/tree/8f9d9cff6bd728b17a24e163c9402775d9e6a365/Mathlib/Probability/Martingale),
Gaussian-process definitions, filtrations, stopping times, and Bochner integration. A bounded
path census did not find a Brownian-motion, Ito-integral, or stochastic-integral module in the
frozen tree. That observation is not a declaration-level global absence proof.

Two current public projects overlap the missing core:

- [`stochasticpde-itocalculus`](https://github.com/xiyin137/stochasticpde-itocalculus) describes
  Brownian motion, simple and L2 stochastic integrals, Ito isometry, quadratic variation, and an
  Ito formula. Its README and Lean sources describe this scope; no date-sensitive branch metadata is used as evidence here.
- [`formal-mathfin`](https://github.com/raphaelrrcoelho/formal-mathfin) describes active
  Black--Scholes, Ito-calculus, Girsanov, and related work built on a Brownian-motion dependency.
  Its README describes active work in this area; no date-sensitive branch metadata is used as evidence here.

Repository README claims are overlap signals, not independently reproduced proof evidence.
AutoLean should first seek collaboration and API reuse instead of defining a competing Brownian
motion or Ito integral.

### SDE decision

**NO-GO for this source.** This is discovery-only; the PDF was not downloaded and no pilot was
selected. No node count is reported: the rights stop condition fired before a frozen graph was
constructed. A successor may proceed only with an adaptation-permitting source, an explicit
non-duplication plan for active Ito work, and a 20--40-node prerequisite graph scored against the
pinned revision.

## PDE

### PDE source and rights

Victor Ivrii's official
[*Partial Differential Equations*](https://www.math.toronto.edu/ivrii/PDE-textbook/) is a
substantial 415-page text that begins with motivation and classification, then treats
one-dimensional waves and heat, Fourier methods, Laplace and wave equations, variational
methods, distributions, weak solutions, and nonlinear equations. The
[PDF](https://www.math.toronto.edu/ivrii/PDE-textbook/PDE-textbook.pdf) is licensed CC BY-SA 4.0.

The source is accessible and systematic, but it fails the fidelity-source gate. In the opening
chapter the author says the class contains "very few theorems" and that proofs are "not very
rigorous", because accurate PDE existence and uniqueness statements require more advanced
analysis. That candor makes the book useful for intuition and examples, but not a reliable
semantic authority for autonomous theorem conversion. A proof assistant cannot reconstruct
unstated regularity or boundary hypotheses from exposition intended to omit them.

### PDE frozen mapping and active overlap

The frozen tree contains
[`LaxMilgram`](https://github.com/leanprover-community/mathlib4/blob/8f9d9cff6bd728b17a24e163c9402775d9e6a365/Mathlib/Analysis/InnerProductSpace/LaxMilgram.lean),
distributions, Schwartz spaces, Fourier analysis, and a Sobolev inequality. Its path inventory
does not contain a general `Mathlib/Analysis/PDE` hierarchy or the concrete early-wave/heat
theorem chain required by this book. This was not promoted to a node percentage because the
source-quality stop condition fired first.

Current adjacent work includes:

- Mathlib [PR #34134](https://github.com/leanprover-community/mathlib4/pull/34134), open on the
  audit date, for first-order quasilinear PDEs and the method of characteristics.
- Physlib's fixed
  [`WaveEquation/Basic.lean`](https://github.com/leanprover-community/physlib/blob/9b0e3feebcaa2627d632a31210f66644facca0f5/Physlib/ClassicalMechanics/WaveEquation/Basic.lean),
  which defines the Euclidean wave equation and proves plane waves are solutions.

These do not cover the textbook, but they make a broad "start from the wave equation" pilot a
poorly isolated contribution boundary. The separate
[Cea audit](backup-pilot-audit-2026-07-25.md) must not be reused as this book's score: it studied
another source and another eight-node contract.

### PDE decision

**NO-GO for Ivrii as the statement-fidelity textbook.** This is discovery-only; the PDF was not
downloaded and no pilot was selected. No exact 20--40-node score is claimed. A later PDE search
should prefer a rigorous theorem-proof text with explicit function spaces, regularity, domains,
initial/boundary conditions, and well-posedness hypotheses. Ivrii can remain an intuition and
counterexample source after independent theorem authority is selected.

## Riemannian geometry

### Riemannian source and rights

Joel Robbin and Dietmar Salamon's
[*Introduction to Differential Geometry*](https://people.math.ethz.ch/~salamon/PREPRINTS/diffgeo.pdf)
is a strong 439-page textbook candidate. Its preface gives a self-contained one-semester route
beginning with Euclidean submanifolds, tangent spaces, vector fields, flows, vector bundles, and
Frobenius before Levi-Civita connections, geodesics, distance, and curvature. The authors'
[publication page](https://people.math.ethz.ch/~salamon/publications.html) identifies the 2022
Springer book and the 2024 ETH lecture-note revision.

Neither the official PDF nor the authors' publication page states an open license permitting
adaptation and redistribution. This audit therefore records the rights status as **not
established**, not as a legal conclusion about every possible use. Public availability alone is
insufficient for Builder source preparation.

### Riemannian frozen mapping and active overlap

The frozen Mathlib tree makes this the technically strongest of the four directions. It includes
smooth-manifold foundations, tangent and vector bundles, Lie brackets, integral curves,
Riemannian structures, and path energy/length:

- [`Geometry/Manifold/Riemannian`](https://github.com/leanprover-community/mathlib4/tree/8f9d9cff6bd728b17a24e163c9402775d9e6a365/Mathlib/Geometry/Manifold/Riemannian)
- [`Geometry/Manifold/VectorBundle`](https://github.com/leanprover-community/mathlib4/tree/8f9d9cff6bd728b17a24e163c9402775d9e6a365/Mathlib/Geometry/Manifold/VectorBundle)
- [`Geometry/Manifold/IntegralCurve`](https://github.com/leanprover-community/mathlib4/tree/8f9d9cff6bd728b17a24e163c9402775d9e6a365/Mathlib/Geometry/Manifold/IntegralCurve)

No percentage is reported because rights and overlap stopped admission before a frozen
prerequisite graph. Technical promise is not permission and is not a score.

The API is also moving. Mathlib [PR #36036](https://github.com/leanprover-community/mathlib4/pull/36036)
is an open umbrella for connections and geodesics and includes curvature work. The merged
[`metric connections` commit](https://github.com/leanprover-community/mathlib4/commit/1ce228d453951997c60c821c7738e71fa0db0142)
shows that part of this surface has already entered current Mathlib after the frozen AutoLean
baseline. Building a first pilot around connections or curvature would either duplicate active
work or target an unstable API.

### Riemannian decision

**NO-GO now.** This is discovery-only; the PDF was not downloaded and no pilot was selected.
Reconsider only after an adaptation-permitting source or explicit permission is recorded and the
upstream connections/geodesics work stabilizes enough to define a maintainer-confirmed
non-overlap. A future discovery graph should begin at the textbook's foundations, while its
Builder frontier should begin at the first reviewed gap rather than re-proving those foundations.

## Metric algebraic geometry

### Metric AG source and rights

Breiding, Kohn, and Sturmfels'
[*Metric Algebraic Geometry*](https://link.springer.com/book/10.1007/978-3-031-51462-3) is an
open-access book published by Springer in 2024. The Springer book page identifies the title as
open access and the front matter / copyright page of the publisher PDF records a Creative Commons
Attribution 4.0 International License for the work, with the usual caveat that third-party
material credited differently may require separate permission. It has 15 chapters and XIV+215
pages. Its [author-hosted manuscript](https://kathlenkohn.github.io/Papers/MFO_Seminar_MAG.pdf)
says it grew from an Oberwolfach summer school for PhD students and postdocs and assumes a solid
undergraduate background in algebra and geometry.

The license is suitable in principle for discovery metadata, source-span records, and derivative
statement-contract work, subject to attribution, change notices, a separate model-egress decision,
and per-item review of third-party figures or credited material. The book is nevertheless a short
graduate survey of a new field rather than a foundational beginner textbook. Chapter 1 immediately
moves between real varieties, complex affine/projective Zariski closures, algebraic bilinear
forms, polars, and duality.

### Frozen 31-node mapping

This is the only direction in this round for which a 20--40-node opening graph was classified.
The 31 nodes come from the introductory metric setup and Section 1.1 on polars:

| Opening range | Subject | Direct exact | Thin adapter | Missing |
| --- | --- | ---: | ---: | ---: |
| 1--9 | Real Euclidean carrier, inner product, norm, and metric facts | 9 | 0 | 0 |
| 10--17 | Complex algebraic bilinear form and oriented-line distance | 0 | 8 | 0 |
| 18--20 | Cotes relation, conic tangent, and polar line | 0 | 0 | 3 |
| 21--23 | Denominator clearing and finite-sum centroid identities | 0 | 3 | 0 |
| 24--27 | Centroid locus and higher polar curves | 0 | 0 | 4 |
| 28 | Homogeneous polynomial representation | 0 | 1 | 0 |
| 29--31 | Iterated directional derivative, degree, and Salmon duality | 0 | 0 | 3 |
| **Total** |  | **9/31 (29.0%)** | **12/31 (38.7%)** | **10/31 (32.3%)** |

Direct plus thin is `21/31` (67.7 percent), but that number is **not** the formal
prerequisite-definition coverage score: this table mixes prerequisite representations and
candidate theorem nodes. The prerequisite subset was not separately frozen. It is an optimistic
whole-graph mapping diagnostic, and even then the actual polar/dual mathematical core has no
direct exact match.

Relevant frozen ingredients include
[`MvPolynomial.Homogeneous`](https://github.com/leanprover-community/mathlib4/blob/8f9d9cff6bd728b17a24e163c9402775d9e6a365/Mathlib/RingTheory/MvPolynomial/Homogeneous.lean),
[`MvPolynomial.Degrees`](https://github.com/leanprover-community/mathlib4/blob/8f9d9cff6bd728b17a24e163c9402775d9e6a365/Mathlib/Algebra/MvPolynomial/Degrees.lean),
and
[`Projectivization`](https://github.com/leanprover-community/mathlib4/tree/8f9d9cff6bd728b17a24e163c9402775d9e6a365/Mathlib/LinearAlgebra/Projectivization).
They do not by themselves define real algebraic varieties, polar curves, projective duality,
intersection multiplicity, genericity, or Voronoi degree in the book's sense.

Current adjacent work includes open Mathlib PRs for
[Groebner bases #29203](https://github.com/leanprover-community/mathlib4/pull/29203),
[polynomial remainder #34873](https://github.com/leanprover-community/mathlib4/pull/34873),
and
[generic determinantal ideals #40266](https://github.com/leanprover-community/mathlib4/pull/40266).
These are not frozen dependencies and should be collaboration boundaries, especially for later
computational and low-rank chapters.

### Secondary calibration and Open Problem roadmap

The book remains valuable after rejection as a first textbook:

- The complex algebraic form has the explicit witness `(1, i)`, whose self-pairing is zero. A
  mutation that silently substitutes the Hermitian inner product must be rejected.
- A circle polar gives a narrow, falsifiable bridge among Euclidean geometry, homogeneous
  polynomials, differentiation, and line equations without claiming the whole chapter.
- Externally computed Groebner or elimination output should enter as a polynomial certificate
  checked by Lean, not as trusted algorithm output.
- Chapter 8 records Conjectures 8.13 and 8.14 for generic inhomogeneous and homogeneous
  hypersurface Voronoi degrees. The book reports the `n <= 3` and `d = 2` cases as proved and
  `n >= 4, d >= 3` as open. These low-dimensional cases are useful calibration targets; the
  conjectures remain isolated until polar/dual varieties, degree, intersection, genericity, and
  elimination contracts exist.

The dependency route is:

```text
real/complex domain contracts
  -> polar and dual basics
  -> Euclidean-distance critical equations
  -> polar degree and elimination certificates
  -> reach/offset and Voronoi boundary
  -> low-dimensional degree calibration
  -> isolated Conjecture 8.13/8.14 track
```

This is Open Problem leverage, not evidence that AutoLean has advanced either conjecture.

### Metric AG decision

**NO-GO as the first Builder textbook.** **GO only as a secondary calibration and portfolio
roadmap** after a foundational source has supplied the missing substrate. This is discovery-only;
the PDF was not downloaded and no pilot was selected. Because the admission decision is NO-GO,
no local book asset or source cache entry is created in this round.

## Counter-argument and resolution

The strongest counter-argument is that a first pilot need not reuse existing theorems; its purpose
is to add missing ones. That is correct. Requiring 70--80 percent exact theorem reuse would select
low-value exercises and defeat the weak-domain objective.

It does not rescue these four source leads. The actual policy requires reusable *prerequisite
definitions*, a trustworthy and usable source, a bounded non-overlapping contribution, and
falsifiable semantic feedback. SDE and Riemannian stop on rights; PDE stops on theorem-source
rigor; Riemannian also collides with moving upstream work; Metric AG starts above the available
foundational substrate. The right response is a better source-and-boundary pair, not weaker
admission semantics.

## Next textbook search and stop conditions

For each new source, search from its beginning and stop at the first failed condition:

1. **Source identity:** official author, publisher, or institutional source with a stable edition
   and exact URL.
2. **Rights:** explicit permission for the intended local processing, derived statement work,
   attribution, public metadata, and any model egress. "Free PDF" is not sufficient.
3. **Textbook fit:** systematic definitions and theorem-proof development with all domain,
   quantifier, regularity, boundary, finiteness, and genericity hypotheses stated.
4. **Entry boundary:** the first 20--40 mathematical nodes can be traced from the book's beginning
   or from an explicitly reviewed prerequisite closure. Do not start mid-book merely because the
   target theorem is attractive.
5. **Frozen mapping:** separately report prerequisite-definition coverage, exact statement reuse,
   thin adapters, and missing nodes against the pinned Mathlib SHA. Stop below the approximately
   70--80 percent prerequisite target.
6. **Collision:** stop or narrow the boundary when an active Mathlib or domain-library project
   owns the same hard definitions or theorem chain; record a collaboration route instead.
7. **Feedback:** require a non-vacuous positive example, a negative example, assumption and
   quantifier mutations, and at least one known special case whose opposite or malformed
   translation fails.
8. **Leverage:** name the reusable dependency closure and an honest route toward an open-problem
   portfolio, without treating relevance as proof progress.

Only after a source passes these desk gates may an operator download it into the ignored,
content-addressed reference cache, record its hash and rights decision, bind exact spans, and run
a pinned-Library compile spike. Downloading first creates provenance and cleanup work without
improving the admission decision.

## Verification still required after a future GO

A desk-audit GO would authorize source preparation, not theorem freeze. Selection still requires:

- an immutable source and rights record with a model-egress ceiling;
- an independently reviewed 20--40-node mathematical graph;
- declaration-level mapping and elaborated-type checks in the pinned Library environment;
- positive, negative, non-vacuity, and mutation evidence;
- an independent semantic review that can reject the proposed representation;
- a clean kernel compile and axiom/import audit; and
- a frozen Builder contract before any Prover handoff.

Failure at any later gate yields a gap or contract-change request. It never authorizes silently
changing assumptions, domains, quantifiers, or conclusions.
