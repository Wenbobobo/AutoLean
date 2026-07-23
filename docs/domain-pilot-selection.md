# Builder Domain Pilot Selection

Status: discovery proposal, not a frozen Builder mission
Decision date: 2026-07-23
Primary candidate: Riemannian geometry, connections and the Levi-Civita connection

## Decision

The first chapter-scale Builder discovery should target the transition from a Riemannian
metric to connections, torsion, metric compatibility, and the Levi-Civita connection. The
preferred source is John M. Lee, *Introduction to Riemannian Manifolds*, second edition,
Chapters 4--6. The publisher describes it as a graduate introduction with explicit chapters
on connections and the Levi-Civita connection:

- <https://link.springer.com/book/10.1007/978-3-319-91755-9>

This is a proposal for source mapping and human review. It is not permission to redistribute
the book, not evidence that the source has been ingested, and not a claim that the resulting
statements are faithful.

## Why this slice

Current mathlib documentation exposes substantial prerequisites:

- manifold differentiability and tangent-space APIs;
- tangent and Riemannian vector bundles;
- smooth sections, local frames, and tensoriality;
- vector-field Lie brackets;
- a basic Riemannian manifold structure and path-length distance.

Primary module references:

- <https://leanprover-community.github.io/mathlib4_docs/Mathlib/Geometry/Manifold/Riemannian/Basic.html>
- <https://leanprover-community.github.io/mathlib4_docs/Mathlib/Geometry/Manifold/Riemannian/PathELength.html>
- <https://leanprover-community.github.io/mathlib4_docs/Mathlib/Geometry/Manifold/VectorBundle/LocalFrame.html>
- <https://leanprover-community.github.io/mathlib4_docs/Mathlib/Geometry/Manifold/VectorBundle/SmoothSection.html>
- <https://leanprover-community.github.io/mathlib4_docs/Mathlib/Geometry/Manifold/VectorBundle/Tensoriality.html>
- <https://leanprover-community.github.io/mathlib4_docs/Mathlib/Geometry/Manifold/VectorField/LieBracket.html>

The public module index currently lists `Riemannian.Basic` and `Riemannian.PathELength`, but
does not expose a corresponding connection, covariant-derivative, or curvature module. A
GitHub issue and code search on 2026-07-23 also returned no direct match for a Levi-Civita or
covariant-derivative implementation. Absence from those searches is only a lead: work may exist
in branches, Zulip discussions, private experiments, or unindexed pull requests. Mathlib
maintainer coordination is therefore a mandatory discovery gate.

This slice has unusually good leverage:

1. It exercises Builder translation on definitions, identities, uniqueness statements, local
   coordinate formulas, and side conditions.
2. Its prerequisites appear close enough to support a 20--40 node pilot without rebuilding all
   smooth-manifold foundations.
3. It opens a path toward geometric analysis, comparison geometry, and geometric PDE, which are
   relevant to the open-problem mission.

## Proposed 24-node discovery graph

The first eight nodes are mappings to existing library concepts, not new declarations. They must
be confirmed against the pinned mathlib revision before any downstream statement is frozen.

| ID | Kind | Proposed mathematical asset |
| --- | --- | --- |
| `RG-E01` | existing map | smooth manifold and model with corners |
| `RG-E02` | existing map | tangent bundle and tangent spaces |
| `RG-E03` | existing map | smooth vector-bundle sections |
| `RG-E04` | existing map | local frames |
| `RG-E05` | existing map | Riemannian vector bundle |
| `RG-E06` | existing map | Riemannian metric, path length, and induced distance |
| `RG-E07` | existing map | vector-field Lie bracket |
| `RG-E08` | existing map | tensoriality support |
| `RG-N01` | new candidate | connection data and laws |
| `RG-N02` | new candidate | connection extensionality |
| `RG-N03` | new candidate | zero, addition, and scalar rules |
| `RG-N04` | new candidate | difference of two connections |
| `RG-N05` | new candidate | tensoriality of the connection difference |
| `RG-N06` | new candidate | local connection coefficients |
| `RG-N07` | new candidate | change-of-frame law |
| `RG-N08` | new candidate | torsion |
| `RG-N09` | new candidate | tensoriality of torsion |
| `RG-N10` | new candidate | metric compatibility |
| `RG-N11` | new candidate | Koszul expression |
| `RG-N12` | new candidate | uniqueness of a torsion-free metric connection |
| `RG-N13` | new candidate | construction and existence of the Levi-Civita connection |
| `RG-N14` | new candidate | covariant acceleration and the geodesic equation |
| `RG-N15` | new candidate | Euclidean-space sanity model |
| `RG-N16` | new candidate | sphere or another existing manifold sanity model |

The graph is intentionally provisional. A node is removed or split if its source span contains
multiple independently meaningful claims, if a mathlib definition already covers it, or if its
semantic review cannot be made local and testable.

## Builder roles and evidence

Each source statement should pass through independent role surfaces:

1. `source_analyst`: records the lawful source span, definitions in scope, and cross references.
2. `normalizer`: produces an explicit quantifier/assumption/conclusion form.
3. `mathlib_mapper`: proposes existing definitions and import boundaries.
4. `statement_formalizer_a` and `statement_formalizer_b`: independently propose Lean statements.
5. `reverse_renderer`: renders each candidate back into mathematical language.
6. `fidelity_reviewer`: compares source, normalization, reverse renderings, and examples.
7. `mutation_supervisor`: challenges quantifiers, inequalities, nonempty conditions, parameter
   order, regularity, and vacuity.
8. `domain_expert`: supplies the semantic signoff that automation cannot establish.

Role independence is an operational policy backed by separate ContextPacks and artifacts. Merely
using different `actor_id` strings does not establish cognitive independence.

## Rights boundary

Lee's text is copyrighted. Until an operator supplies a lawfully held source and a
`RightsRecordV1` policy:

- no chapter text is stored in repository fixtures;
- no source prose is sent to an external model;
- no verbatim textbook statement is emitted in a public benchmark;
- discovery artifacts contain only citation metadata, hashes, locally authored normalization,
  and independently reviewed formal statements.

The source may remain local-only even if the derived Lean declaration is later contributed under
mathlib's terms. Source rights and code licensing are separate decisions.

## Alternatives

### Stochastic analysis and SDE

Bernt Oksendal, *Stochastic Differential Equations: An Introduction with Applications*, sixth
edition, is the preferred textbook candidate:

- <https://link.springer.com/book/10.1007/978-3-642-14394-6>

Mathlib now documents Brownian motion, martingales, stopping times, optional stopping, and
martingale convergence. The large missing bridge appears to be stochastic integration and Ito
calculus. This has high open-problem leverage, but an Ito-integral pilot may exceed the desired
20--40 node scope if foundational constructions are not already stable.

### PDE and modern analysis

Lawrence C. Evans, *Partial Differential Equations*, second edition, is the preferred textbook
candidate:

- <https://bookstore.ams.org/gsm-19-r>

Mathlib has substantial measure, functional-analysis, Fourier, and Sobolev infrastructure.
However, a PDE chapter often hides boundary regularity, weak derivatives, trace theory, and
function-space conventions inside apparently short statements. It remains a strong second pilot,
but the first slice needs a more detailed prerequisite census.

## Discovery gates

The primary choice is revoked or deferred if any of these gates fails:

1. Mathlib maintainers identify an active overlapping project or incompatible planned API.
2. Fewer than 70 percent of the eight prerequisite mappings are usable without redesign.
3. No qualified domain reviewer is available.
4. Source rights cannot support the intended model-egress policy.
5. Five trial statements cannot pass reverse rendering, mutation tests, non-vacuity review, and
   independent signoff.
6. The 24-node graph cannot be cut into reviewable contracts with local failure evidence.

## Feedback cadence

Discovery should produce an externally legible result every five accepted nodes:

- one frozen statement-contract packet with all fidelity evidence;
- one known theorem or example proved and independently recompiled by Prover;
- one gap report when the required library API is absent;
- one short comparison against the corresponding informal source and existing mathlib surface.

These feedback artifacts demonstrate useful formalization progress. They do not convert a known
theorem into an open-problem result and they do not waive semantic review.
