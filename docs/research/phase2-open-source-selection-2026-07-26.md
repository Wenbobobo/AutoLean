# Phase 2 open-source selection: a source route for the Builder--Prover boundary

**Status:** research-only recommendation; no source bytes acquired, no reference-manifest
entry added, no rights decision made, no contract frozen, and no Prover handoff authorized.

**Access date:** 2026-07-26 (Asia/Shanghai)

**Pinned AutoLean Library baseline:** Mathlib `v4.28.0`,
`8f9d9cff6bd728b17a24e163c9402775d9e6a365`.

## Decision

Select **Joachim Schoberl et al., _An Interactive Introduction to the Finite
Element Method_ (iFEM), Chapters 1--10** as the **one conditional primary
pilot**.  The prospective first contract family is the abstract coercive
variational / Galerkin quasi-optimality bridge, not a concrete PDE solution.
Its status is **conditional GO for source preparation and compile discovery
only**.  It is not a GO for Builder admission, freeze, or proof search.

Retain **Breiding--Kohn--Sturmfels, _Metric Algebraic Geometry_ (MAG),
Chapter 1** as the **one backup**, with status **NO-GO now**.  It is a valuable
long-horizon algebraic-geometry comparator and has unusually good licensing,
but its opening mathematical core is currently too far above the pinned
substrate for a first 20--40-node Builder pilot.

This is deliberately not a choice of a whole field.  It is a choice of the
first source-and-boundary pair that can test the Builder's statement-fidelity
machinery without falsely claiming that it formalizes PDE theory or advances an
open problem.

## Selection rules

A source must pass all of the following before it can be selected:

1. Its official author, institution, publisher, or version-controlled source
   gives an explicit license allowing adaptation and redistribution.  "Free
   PDF" is insufficient.  The eventual rights reviewer must also set the
   model-egress policy; an open license does not itself authorize sending bytes
   to a hosted model.
2. It begins a coherent dependency story and has theorem statements with
   explicit hypotheses.  The Builder must trace that story from the source's
   opening chapters even when formal work starts at a later missing frontier.
3. A prospective 20--40-node **mathematical** closure has about 70--80 percent
   of its prerequisite definitions and basic APIs available in the pinned
   Mathlib.  Mathematical nodes, Lean declarations, imports, and execution
   jobs remain separate graphs.  This is a future compile-and-review gate, not
   a percentage that can be recovered by counting proof steps.
4. The source admits positive cases, counterexamples, and mutation tests that
   expose swapped quantifiers, missing hypotheses, changed inequalities, and
   false attainability claims.
5. Its formal frontier is separated from active upstream work.  Source quality
   and open licensing do not excuse duplication of a moving Mathlib API.

## Primary: iFEM abstract Galerkin bridge

### Primary records and rights

* Official source repository: [JSchoeberl/iFEM](https://github.com/JSchoeberl/iFEM).
  It describes itself as an interactive introduction to finite-element theory
  prepared at TU Wien and links the rendered course.
* Official rendered book and chapter opening:
  [contents](https://jschoeberl.github.io/iFEM/intro.html) and
  [Chapter 10, *Coercive variational problems and their approximation*](https://jschoeberl.github.io/iFEM/abstracttheory/Coercive.html).
* Official license:
  [repository `LICENSE`](https://github.com/JSchoeberl/iFEM/blob/master/LICENSE),
  **CC BY 4.0**.  This grants the adaptation/distribution baseline required for
  a public source-to-contract workflow, conditional on attribution and a later
  policy decision on model egress.
* Official retrieval endpoints for a future operator action: the repository
  URL `https://github.com/JSchoeberl/iFEM.git`, its
  [archive endpoint](https://github.com/JSchoeberl/iFEM/archive/refs/heads/master.zip),
  and the rendered chapter URL above.  They are recorded as retrieval routes,
  not as acquired artifacts or immutable versions.

The source is systematic rather than a loose collection of notes.  Its table
of contents starts with Poisson/Galerkin examples, then develops basic Hilbert
space properties, projection, Riesz representation, coercive variational
problems, and only later begins Sobolev and concrete finite-element machinery.
That progression is an appropriate *source* path for an early modern-analysis
pilot.  It is also pedagogically useful: the text supplies geometric examples
before the abstraction, while Chapters 8--10 state projection, Lax--Milgram,
and quasi-optimality claims explicitly.  The rendered introduction also says
that the course was first offered in this form in 2024 and that many sections
were still draft; this increases the independent-review burden and rules out
treating the source as unquestionable theorem authority.

### Proposed source path and 27-node discovery closure

The source review must begin at Chapters 1--10, not jump directly to the
Cea display in Chapter 10.  The first formal frontier may be Chapters 8--10,
but its contracts must retain a provenance chain through the preceding
Galerkin and Hilbert-space terminology.

The following is a **proposed, unfrozen** 27-node mathematical graph.  It is
not a coverage score, a Lean declaration plan, or a promise that each node is
missing.  Its purpose is to make the forthcoming audit falsifiable.

| Group | Nodes in the prospective closure | Expected role |
| --- | --- | --- |
| Hilbert substrate | real scalar field; normed vector space; inner product; completeness; induced norm; continuous linear functional; dual norm | Existing generic Mathlib substrate, to be elaborated at the pinned revision |
| Bilinear setting | continuous bilinear form; continuity bound; coercivity predicate; induced operator into the dual; operator-norm bound | Mostly existing representations; the exact constant-bearing bridge requires a compile check |
| Subspace setting | submodule; closedness; inherited complete structure; restricted form; restricted functional; inherited continuity; inherited coercivity | Mix of existing representation and thin adapters; do not count an adapter as direct coverage before it elaborates |
| Solution data | full-space variational equation; subspace Galerkin equation; full solution; discrete solution; uniqueness | Source-to-contract nodes; full-space Lax--Milgram may map to existing API, subspace form is to be audited |
| Error bridge | Galerkin orthogonality; comparison membership; error decomposition; coercivity-at-error; continuity-at-comparison; cancellation/case split; pointwise quasi-optimality; infimum lifting | Candidate theorem/lemma frontier |

The current Mathlib documentation already has a real-Hilbert-space
[Lax--Milgram theorem](https://leanprover-community.github.io/mathlib4_docs/Mathlib/Analysis/InnerProductSpace/LaxMilgram.html)
for bounded bilinear forms and an `IsCoercive` predicate.  That is evidence
for prerequisite reuse, not evidence that the Galerkin statement, its closed
subspace restriction, or Cea's bound already exist in the exact source form.
The **pre-screen result is unscored**, because the table intentionally mixes
prerequisite definitions with the proposed theorem frontier.  The earlier
eight-node pointwise-Cea audit cannot be relabelled as 27-node prerequisite
coverage: it measured a different graph and was below the node-floor.  The
admission review must first freeze a prerequisite-only denominator, then
compile exact type queries and report direct mappings, thin adapters, and
missing nodes separately.  A score outside the 70--80 percent policy band, an
absent restriction API, or a broad import dependency is a **NO-GO**, not a
reason to change the denominator.

### Fidelity controls and semantic risk

The rendered Chapter 10 writes the continuity inequality without an absolute
value while subsequently using it as a bound.  The source is still useful, but
this is exactly why an open license is not synonymous with a frozen statement.
The source analyst and independent functional-analysis reviewer must resolve
the intended convention before any normalized theorem is created.  The
candidate is rejected if the contract silently changes that convention.

Required controls for the proposed slice:

* **Positive, non-vacuous instance:** a finite-dimensional real inner-product
  space with a proper subspace and a coercive bounded bilinear form; record a
  case with nonzero approximation error.
* **Drop coercivity:** use a zero form.  Galerkin equations can hold while a
  claimed quasi-optimal error bound does not.
* **Drop discrete membership:** let the purported approximation lie outside the
  trial subspace; the stated orthogonality alone must not imply the conclusion.
* **Mutate the binders:** replace universal coercivity/continuity or universal
  comparison quantifiers by a single witness, or replace `forall` comparison
  by `exists`; every such mutant must be rejected by fidelity review.
* **Mutate the boundary:** remove positivity of the coercivity constant, change
  `|A u v|` to a one-sided relation without an explicit convention, reverse the
  approximation constant, or replace an infimum with an attained minimum.

This provides a high-feedback Builder harness: reverse rendering, a finite
countermodel search for the linear-algebra instances, a sign/absolute-value
ledger, and independent review can all fail before the Prover ever sees a
bundle.  The initial expert burden is moderate rather than negligible: one
functional/numerical analyst must approve the statement family, and one Lean
reviewer must approve the concrete Mathlib mapping.  Neither role may be
replaced by model agreement.

### Overlap and long-term leverage

The current Mathlib
[method-of-characteristics PR](https://github.com/leanprover-community/mathlib4/pull/34134)
is open and concerns first-order quasilinear PDEs.  It is an adjacent signal,
not a reason to duplicate it.  The iFEM target is deliberately the abstract
variational/Galerkin bridge, not characteristics, transport, or a concrete
Sobolev/PDE theorem.  Any move from that abstraction to a concrete weak PDE
must repeat the overlap census.

The leverage is infrastructural: a verified coercive variational and
approximation boundary can later support weak formulations, finite elements,
and numerical-analysis dependencies.  It does **not** prove a convergence
rate, formalize a particular PDE, or advance an open problem.  That restraint
is a feature: it tests the Builder--Prover interface with theorem statements
that can be independently falsified.

### Primary GO / NO-GO gates

**GO for source preparation and compile discovery only** when all of the
following occur:

1. an operator obtains exact source bytes from an official endpoint, records
   their hash and resolved revision, and a rights reviewer records attribution
   plus a conservative `local_only` egress ceiling;
2. the 27-node closure is independently reconstructed from Chapters 1--10 and
   its direct-prerequisite score is in the stated range without counting future
   theorems or uncompiled adapters;
3. two reviewers resolve the continuity/sign convention, preserve every
   quantifier and boundary condition, and approve the control suite;
4. a clean pinned-Library compile spike establishes exact imports and no
   collision with active work; and
5. a Builder authority record explicitly selects the slice.

**NO-GO** if any of those fail.  In particular, no model may repair the
statement by adding assumptions, weakening it, or substituting the pointwise
bound for the source's infimum theorem without a new contract revision.

## Backup: Metric Algebraic Geometry, Chapter 1

### Primary records and rights

* Official publisher record: [Springer book page](https://link.springer.com/book/10.1007/978-3-031-51462-3).
* Official full-book PDF:
  [download endpoint](https://link.springer.com/content/pdf/10.1007/978-3-031-51462-3.pdf).
* The publisher PDF records **CC BY 4.0** for the book and warns that separately
  credited third-party material may have different rights.  That makes source
  acquisition plausible after per-item review; it does not authorize copying
  figures into a contract or dashboard.

MAG is a serious open source for a future algebraic-geometry track.  It is a
graduate-level one-semester text, however, not the first "beginner" source:
the authors explicitly assume a solid undergraduate base in algebra and
geometry, and the opening chapter moves quickly from plane polars to complex
algebraic bilinear forms and duality.

### Why it remains NO-GO now

The Chapter 1 desk graph in the existing AutoLean discovery record has 31
mathematical nodes: 9 direct mappings, 12 possible thin adapters, and 10
missing core nodes.  It therefore cannot honestly meet the first-pilot
prerequisite criterion.  The missing material is central, not cosmetic:
complex algebraic bilinear forms versus Hermitian forms, polar constructions,
projective duality, and related polynomial geometry must be made precise before
the later motivating claims have a faithful Lean meaning.

The live upstream landscape is also moving.  Mathlib's
[Groebner-basis PR #29203](https://github.com/leanprover-community/mathlib4/pull/29203)
and [generic determinantal-ideals PR #40266](https://github.com/leanprover-community/mathlib4/pull/40266)
were open when this report was checked.  They do not prove an exact collision
with the Chapter 1 polar slice, but they do make it irresponsible to establish
a parallel polynomial-algebra API without a fresh maintainer/overlap review.

MAG has strong open-problem leverage, especially for later polar-degree,
Voronoi, and elimination-certificate work.  That is precisely why it should
wait for a stable algebraic substrate rather than become a misleadingly small
first pilot.

### Backup GO / NO-GO gates

**NO-GO now.**  Reopen only after a new 20--40-node closure has at least the
required direct prerequisite coverage, distinguishes bilinear from Hermitian
forms using explicit counterexamples, contains a source span for every
definition, receives an algebraic-geometry review, and shows a non-duplicating
boundary against current Mathlib.  Until then it may be used for read-only
portfolio and mutation-design research only.

## Rejected source routes

These rejections are positive evidence that source selection is enforcing both
rights and semantic rigor rather than optimizing for convenient PDFs.

| Route | Result | Reason |
| --- | --- | --- |
| Victor Ivrii, [_Partial Differential Equations_](https://www.math.toronto.edu/ivrii/PDE-textbook/) | Keep only as intuition/examples | Its CC BY-SA 4.0 route is promising, but the opening material states that it contains very few theorems and non-rigorous proofs.  It cannot be the sole semantic authority for a frozen theorem. |
| Sarkka--Solin, [_Applied Stochastic Differential Equations_](https://users.aalto.fi/~ssarkka/pub/sde_book.pdf) | Reject | It is available online but its stated personal-use restriction does not grant the adaptation/redistribution rights needed for the Builder workflow. |
| Robbin--Salamon, [_Introduction to Differential Geometry_](https://people.math.ethz.ch/~salamon/PREPRINTS/diffgeo.pdf) | Reject for now | No adaptation-permitting license was established.  Independently, Mathlib's [connections/geodesics umbrella PR](https://github.com/leanprover-community/mathlib4/pull/36036) is still open, so a first Riemannian slice would sit on a moving API. |
| Stacks Project, [source repository](https://github.com/stacks/stacks-project) | Long-horizon comparator, not a first pilot | Its GFDL source is legally open but operationally more demanding for derivative delivery, and it is a research reference rather than a beginner-friendly bounded entrance to a 20--40-node slice.  It remains valuable once a specifically scoped algebraic-geometry frontier is independently mapped. |

No SDE source passing both the explicit adaptation/redistribution condition and
the desired systematic beginner-to-rigorous route was selected in this pass.
That is a genuine search result, not a reason to lower the source gate.

## Local cache and lock plan

No download is authorized by this report.  When a Builder authority does
authorize source preparation, create a new, uncommitted template under
`docs/research/templates/` and cache only through the existing
operator-owned reference workflow.  The template must initially keep all
observed fields null:

```json
{
  "schema_version": "autolean.phase2-source-lock-template.v1",
  "reference_id": "ifem-abstract-galerkin-official-source",
  "state": "metadata_verified_download_pending",
  "official_sources": {
    "record_url": "https://github.com/JSchoeberl/iFEM",
    "retrieval_url": "https://github.com/JSchoeberl/iFEM.git",
    "resolved_revision": null
  },
  "rights": {
    "license_expression": "CC-BY-4.0",
    "rights_review_status": "pending",
    "model_egress_policy": "pending_explicit_rights_review"
  },
  "acquisition": {
    "cache_root": ".cache/references/ifem-abstract-galerkin/",
    "retrieved_at": null,
    "final_url": null,
    "sha256": null,
    "download_verified": false
  },
  "scope": {
    "source_path": ["Chapters 1-10"],
    "candidate_family": "coercive variational Galerkin quasi-optimality",
    "semantic_authority_status": "independent_review_required"
  }
}
```

The operator must resolve a concrete source revision before retrieval; the
cache stays gitignored; the parent artifact and any locally extracted text get
separate hashes and derivation records; and the public reference manifest is
updated only after rights review.  Do not invent a SHA-256 from a URL, use a
branch name as a version, or send a source excerpt to a model before the
recorded egress policy permits it.

## Evidence boundary and next decision

This report used official author/repository, university, publisher, and Mathlib
records accessed on 2026-07-26.  Link accessibility was checked where the
source host allowed it.  It does not claim that every iFEM theorem is correct,
that current Mathlib lacks an exact Cea theorem, or that any future proof will
be novel.  The next action is the primary source-preparation gate above, not
bulk ingestion and not Prover execution.
