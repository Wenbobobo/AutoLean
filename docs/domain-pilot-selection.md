# Builder Domain Pilot Selection

Status: conditional discovery decision, not a frozen Builder mission

Decision date: 2026-07-24

Primary: first-order model theory, sequent-calculus soundness

Backups: an abstract Cea-type variational-PDE bound; a van Kampen-style algebraic-topology slice

## Decision

The next Builder discovery pilot is a bounded first-order model-theory exercise: formulate a
small sequent calculus and establish soundness with respect to a stated semantics. It is
conditional on a compile spike in the pinned independent `Library/` project. This is a
calibration target for the Builder--Prover boundary and for reusable formal structure; it is not
an open-problem claim and it is not yet a frozen theorem portfolio.

Two independently produced candidate designs disagree about the right first boundary:

| Candidate | Strength | Cost and omitted evidence |
| --- | --- | --- |
| Closed-only conservative pilot | Restricts the first slice to closed formulas and closed sequents, minimizing substitution, alpha-renaming, and context transport | It may hide whether AutoLean can preserve structural side conditions and reason over open formulas |
| Structural/open-formula pilot | Makes finite variable contexts, open formulas, freshness, and context-sensitive substitution explicit | The representation and freshness obligations may dominate the slice before a soundness argument is reachable |

Neither candidate wins by narrative preference or by compiling first. The pinned `Library/`
spike described below supplies reproducible API-compatibility evidence, while source
interpretation, explicit freshness/capture-avoidance obligations, and independent review retain
selection authority. A failed spike is a gap report for its candidate, not a license to change a
theorem silently. If neither candidate reaches the required boundary, the pilot moves to the
Cea-type or van Kampen backup after the same selection process.

The [backup pilot audit](research/backup-pilot-audit-2026-07-25.md) conditionally ranks a
pointwise Cea comparison slice ahead of van Kampen and records the latter's source-rights and
active-upstream blockers. It is research input only: it selects, compiles, admits, and freezes no
candidate.

## Curvature reference boundary

The former curvature/first-Bianchi proposal is **reference only**. It is blocked by mathlib
[PR #36036](https://github.com/leanprover-community/mathlib4/pull/36036), an open work-in-progress
that unifies ongoing connections and geodesics work and includes a curvature module. AutoLean
will not fork, duplicate, or build a pilot on that moving upstream branch. The McKay reference
cache and prior overlap notes remain provenance/reference material only; they do not authorize
new curvature contracts, a new benchmark, or a promotion claim.

This decision does not assert that the upstream work will merge, that its final API will satisfy
AutoLean, or that the old census was complete. It only says that the dependency is too active for
curvature to be a responsible first pilot today.

## Pinned Library Compile Spike

`Library/` is the independent formal-work system of record and the staging surface for eventual
upstream contributions. It is neither a scratch checkout nor a substitute verifier. The spike
uses its committed Lake lock and public mathlib imports; it must not patch `.lake/packages`, move
the lock incidentally, or depend on a local mathlib branch.

Before choosing a candidate, record one immutable spike packet for each candidate containing:

1. the exact `Library` commit, `lake-manifest.json` digest, Lean toolchain, and candidate-design
   revision;
2. a compact signature/formula/sequent representation and the exact intended soundness statement;
3. the imports and mappings it relies on, including every explicit freshness or substitution
   premise;
4. a clean compile result for the mapping layer and a minimal soundness-rule skeleton in that
   pinned environment; and
5. any compiler failure, API gap, or statement ambiguity as a `GapReportV1` or contract-change
   request, without replacing it with a weaker statement.

The spike tests whether each candidate (a) preserves its advertised mathematical scope, (b)
compiles against the pinned public API without a foundation redesign, and (c) leaves a traceable
route to the full soundness statement. Candidate selection additionally requires independent
source and semantic review of the quantifier/freshness boundary. A compile alone establishes none
of semantic fidelity, mathematical novelty, proof validity in the production verifier, candidate
selection, or suitability for promotion. The independent verifier remains required for any
accepted proof.

## Self-calibration before manual calibration

The immediate work is the multi-agent self-calibration loop in
[the decision record](self-calibration-decision.md), coupled to textbook and open-problem
alignment. It compares candidate decompositions, source interpretation, formal boundaries, and
research relevance while preserving the Builder/Prover authority split.

Manual Builder calibration is deliberately later. It begins only after a separate selection
record binds the source interpretation, formal boundary, independent review, and compatible
pinned-Library evidence, and the ordinary rights and domain-review gates are satisfied. Human
review remains the authority for semantic fidelity; agents can surface disagreement and
counterexamples but cannot turn them into a freeze decision.

## Admission and revocation gates

The selected model-theory pilot starts only when all conditions hold:

1. the selected candidate has a retained pinned-Library spike packet and no unresolved statement
   weakening;
2. textbook interpretation and open-problem alignment have been independently reviewed and their
   disagreement is recorded rather than averaged away;
3. the source rights record permits the intended local use and any later endpoint class;
4. the formal plan states whether it covers closed formulas only or open formulas with explicit
   context/freshness semantics;
5. the first frozen contract has passed the normal reverse-rendering, mutation, positive/negative
   example, non-vacuity, library-review, and domain-review gates; and
6. Builder and verifier authority requirements for promotion are independently satisfied.

Failure of conditions 1, 2, or 4 returns the work to self-calibration or selects a backup.
Failure of conditions 3, 5, or 6 pauses ingestion or promotion. No failure changes the selected
theorem by implication.

## Feedback cadence

Each self-calibration round records a candidate revision, an adversarial critique, an explicit
agreement/disagreement table, and a decision of `continue`, `compile-spike`, `gap`, or `stop`.
Each compile spike records its pinned environment and outcome. After selection, each manual
calibration batch records the frozen contract/evidence chain or the corresponding gap.

`Library/records/` retains the safe, immutable pointers to the reviewed/promotion chain;
`Library/Staging/` is the work surface for candidate formal assets once they are bound to a
Builder draft-contract revision. A later upstream proposal is staged from that record only after
its AutoLean review path is complete. Upstream merge status never promotes an AutoLean claim.
