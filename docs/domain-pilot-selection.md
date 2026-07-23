# Builder Domain Pilot Selection

Status: discovery decision, not a frozen Builder mission

Decision date: 2026-07-23

Primary: curvature of vector-bundle connections and the first Bianchi boundary

Backup: abstract variational PDE, Galerkin orthogonality, and Cea-type error bounds

## Decision

The first 20--40 node Builder pilot should remain in Riemannian/geometric analysis, but the
original Levi-Civita target is revoked. Current mathlib already contains covariant derivatives,
metric compatibility, and torsion, while an active upstream pull request implements existence and
uniqueness of the Levi-Civita connection. Duplicating that work would give misleading progress.

The revised pilot begins one layer later: define curvature for a connection on a smooth vector
bundle, establish its tensorial and alternating laws, relate it to local connection forms, and
reach a sharply scoped Bianchi boundary. It uses the existing connection API without depending on
the open Levi-Civita pull request for its first accepted nodes.

The primary source is Benjamin McKay, *Lectures on Differential Geometry*, Chapters 59--60,
especially pages 505--520. University College Cork describes this 643-page published book as
peer-reviewed and licenses it under CC BY-SA 4.0:

- <https://cora.ucc.ie/items/274ec834-ca2e-4885-922f-e353d539ef18/full>

The exact PDF and repository-extracted text are pinned in
[`Builder/references/manifest.v1.json`](../Builder/references/manifest.v1.json). Their bytes remain
under the ignored local `.cache/references/` tree.

## Evidence snapshots

Two mathlib snapshots must not be conflated:

1. FATE v4.28.0 pins mathlib commit
   [`8f9d9cff`](https://github.com/leanprover-community/mathlib4/commit/8f9d9cff6bd728b17a24e163c9402775d9e6a365).
   In the locally verified checkout, `Geometry/Manifold/Riemannian` contains only `Basic.lean` and
   `PathELength.lean`; there is no manifold covariant-derivative module.
2. The original discovery census used the pinned snapshot
   [`e780b56e`](https://github.com/leanprover-community/mathlib4/commit/e780b56e9235c747285043b5cd5f2ebba300daad).
   It contains
   [`CovariantDerivative/Basic.lean`](https://github.com/leanprover-community/mathlib4/blob/e780b56e9235c747285043b5cd5f2ebba300daad/Mathlib/Geometry/Manifold/VectorBundle/CovariantDerivative/Basic.lean),
   [`Metric.lean`](https://github.com/leanprover-community/mathlib4/blob/e780b56e9235c747285043b5cd5f2ebba300daad/Mathlib/Geometry/Manifold/VectorBundle/CovariantDerivative/Metric.lean),
   and
   [`Torsion.lean`](https://github.com/leanprover-community/mathlib4/blob/e780b56e9235c747285043b5cd5f2ebba300daad/Mathlib/Geometry/Manifold/VectorBundle/CovariantDerivative/Torsion.lean).
3. During integration, `master` had advanced to
   [`bbc4475e`](https://github.com/leanprover-community/mathlib4/commit/bbc4475e9e8fd25fbc8e26d636dd8b37be8f105a).
   A second GitHub tree census found the same three covariant-derivative modules and no path
   containing curvature or parallel transport. PR #36845 was still open. This reduces snapshot
   drift; it does not replace maintainer coordination.

The observed modules explicitly provide bundled and local covariant derivatives, differences of
connections, metric compatibility, and torsion. A code census at `e780b56e`, repeated at
`bbc4475e`, found no
`CovariantDerivative.curvature`, Riemann-curvature, or manifold parallel-transport declaration.
Absence from one repository snapshot is not proof that no branch or downstream project exists.
Maintainer coordination remains an admission gate.

The overlap risk is concrete:

- [PR #36845](https://github.com/leanprover-community/mathlib4/pull/36845), updated 2026-07-22,
  implements the Levi-Civita connection.
- [PR #26221](https://github.com/leanprover-community/mathlib4/pull/26221) is the umbrella
  covariant-derivative project and lists Christoffel symbols and related follow-on work.

AutoLean therefore treats those declarations as upstream dependencies or mappings, never as pilot
deliverables.

## Three-domain comparison

| Candidate | Snapshot evidence | Why it fits | Blocking risk | Decision |
| --- | --- | --- | --- | --- |
| Connection curvature / geometric analysis | The two discovery snapshots have covariant derivative, metric, torsion, differential forms, Lie brackets, and tensoriality; no curvature module was found | A 24-node graph can reuse most structural prerequisites and exercises definitions, local/global equivalence, side conditions, and identities | Nearby upstream work can rapidly make the census stale; bundle-valued forms may require API design | Primary, conditional on maintainer check |
| Abstract weak PDE / modern analysis | Mathlib has [Lax--Milgram](https://github.com/leanprover-community/mathlib4/blob/e780b56e9235c747285043b5cd5f2ebba300daad/Mathlib/Analysis/InnerProductSpace/LaxMilgram.lean), distributions, and Fourier/Bessel [Sobolev spaces](https://github.com/leanprover-community/mathlib4/blob/e780b56e9235c747285043b5cd5f2ebba300daad/Mathlib/Analysis/Distribution/Sobolev.lean) | Galerkin orthogonality and a Cea-style bound can stay abstract, avoiding boundary regularity in the first slice | Weak-derivative Sobolev spaces remain under [PR #32305](https://github.com/leanprover-community/mathlib4/pull/32305); concrete domain PDE statements would overrun 40 nodes | Backup |
| Stochastic analysis / SDE | Current mathlib has [Brownian motion](https://github.com/leanprover-community/mathlib4/blob/e780b56e9235c747285043b5cd5f2ebba300daad/Mathlib/Probability/BrownianMotion/Basic.lean), martingales, stopping times, and convergence | Very high long-term leverage for SDE and stochastic PDE | No stochastic-integral or Ito-calculus module was found; Brownian work is active, and an earlier all-in-one attempt [PR #35571](https://github.com/leanprover-community/mathlib4/pull/35571) closed without merge | Defer until the integral boundary is designed with maintainers |

The comparison is architectural, not a theorem-count score. If the latest snapshot census is wrong
or an unindexed curvature project exists, the primary choice loses its non-overlap advantage and
the backup becomes first.

## Proposed 24-node graph

The first eight nodes are mappings to existing APIs at a newly pinned mathlib commit. They are not
new declarations and must compile in the pilot environment before downstream contracts are
frozen.

| ID | Kind | Mathematical asset |
| --- | --- | --- |
| `GC-E01` | existing map | smooth manifolds and smooth vector bundles |
| `GC-E02` | existing map | smooth sections and section extensionality |
| `GC-E03` | existing map | bundled and local covariant derivatives |
| `GC-E04` | existing map | adding an endomorphism-valued one-form and connection difference |
| `GC-E05` | existing map | tensoriality constructors |
| `GC-E06` | existing map | vector-field Lie bracket |
| `GC-E07` | existing map | differential forms, wedge products, and bundle homomorphisms |
| `GC-E08` | existing map | metric compatibility and torsion |
| `GC-N01` | new candidate | unbundled curvature expression |
| `GC-N02` | new candidate | additivity in the first vector field |
| `GC-N03` | new candidate | scalar tensoriality in the first vector field |
| `GC-N04` | new candidate | additivity in the second vector field |
| `GC-N05` | new candidate | scalar tensoriality in the second vector field |
| `GC-N06` | new candidate | dependence on the section value at a point |
| `GC-N07` | new candidate | bundled curvature endomorphism |
| `GC-N08` | new candidate | curvature application formula |
| `GC-N09` | new candidate | alternating law and repeated-vector zero |
| `GC-N10` | new candidate | flat connection predicate |
| `GC-N11` | new candidate | zero curvature of a trivial flat connection |
| `GC-N12` | new candidate | curvature after adding an endomorphism-valued one-form |
| `GC-N13` | new candidate | local connection form and frame-change statement |
| `GC-N14` | new candidate | local formula `dA + A wedge A` |
| `GC-N15` | new candidate | skew-adjoint curvature of a metric connection |
| `GC-N16` | boundary candidate | covariant exterior derivative and first Bianchi statement |

`GC-N13`--`GC-N16` are discovery boundaries, not promised declarations. If bundle-valued forms or
local-frame APIs require a foundational redesign, Prover must emit a `GapReportV1`; Builder must
not hide the gap by weakening the statement.

## Source-to-contract path

Each trial statement follows one route:

1. `reference_cache.py` independently verifies the parent PDF and its manifest-typed derived text.
2. A source analyst selects exact UTF-8 byte offsets in the derived text and separately declares
   the corresponding chapter/page locator in the parent PDF.
3. An operator records a rights decision no broader than the manifest egress policy.
4. `SourceToStatementHarness.prepare_draft` creates a `draft` `StatementContractV1` with source,
   span, rights, alignment, environment, and provenance bindings.
5. Normalization and mathlib mapping complete before independent candidates are produced.
6. `SourceToStatementHarness.run_fidelity` delegates to the existing
   `StatementFidelityHarness`.
7. Preparation commits the complete source, rights, span, and contract state to the append-only
   source-preparation ledger.
8. `SourceToStatementHarness.revalidate_freeze_and_bridge` reloads that record, revalidates both
   artifacts and every excerpt, freezes the reviewed statement with the preparation record ID and
   typed digest, and emits the signed bundle.

The local reference cache proves artifact and derived-text byte identity, not semantic fidelity.
The parent-PDF page locator is a human declaration. Page alignment, notation scope, quantifier
recovery, and mathematical equivalence still require independent review. Production release also
remains blocked on the Builder signing gateway because the local freeze authority is not yet
authenticated.

## Admission and revocation gates

The primary pilot starts only if all conditions hold:

1. Maintainers report no conflicting curvature project or agree on a collaboration boundary.
2. At least six of the eight existing mappings compile without API redesign.
3. Five trial claims can be cut into local source spans and pass reverse rendering, mutation,
   positive/negative example, non-vacuity, library review, and domain review.
4. At least one qualified differential geometer reviews semantic fidelity.
5. The first ten proposed nodes do not require a general theory of parallel transport.
6. Rights review permits the selected model endpoints; the initial cached source policy is
   local-only.

Failure of gates 1, 2, or 5 moves the pilot to the abstract variational PDE backup. Failure of
gates 3, 4, or 6 pauses Builder ingestion rather than changing the theorem.

## Feedback cadence

Every five accepted nodes must yield:

- a frozen statement contract and canonical fidelity artifact;
- one Prover result independently recompiled in the pinned environment;
- a `GapReportV1` for every missing API rather than an informal TODO;
- a source-to-normalization-to-Lean trace that a domain reviewer can inspect; and
- a current-main overlap check before proposing anything upstream.

These artifacts demonstrate the Builder--Prover interface. They do not establish research novelty
or progress on an open problem by themselves.
