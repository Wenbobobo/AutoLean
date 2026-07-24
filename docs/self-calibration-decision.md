# Multi-Agent Self-Calibration Decision

Status: active discovery protocol; no calibration result has been accepted

Decision date: 2026-07-24

## Purpose

This protocol decides whether AutoLean's first Builder pilot has a faithful, useful formal
boundary before asking people to calibrate individual Builder statements. Its immediate target is
the conditional first-order model-theory/sequent-calculus soundness pilot described in
[the domain selection](domain-pilot-selection.md). It also aligns each proposed formal slice to
its textbook interpretation and to a clearly bounded open-problem research rationale.

Self-calibration is not a substitute for semantic review, Lean verification, or human authority.
It exists to make disagreements visible early and to select what a later human calibration should
test. It does not produce a score, a benchmark result, a frozen Builder contract, or a research
claim.

## Inputs and boundaries

Every round uses versioned, public-safe inputs only:

- the candidate-design revision and its stated closed-only or open-formula boundary;
- permitted textbook metadata, locators, and derived claims under the source rights record;
- a concise open-problem alignment note that names the intended research dependency without
  claiming the dependency has been solved; and
- the pinned `Library` environment when the round requests a compile spike.

Raw textbook passages, source-cache paths, prompts, credentials, model outputs, and recovered
archives do not enter the public record. A source may be locally available yet still be ineligible
for external-model use; the rights record controls that separately.

## Independent roles

The roles may be carried out by agents or people, but their written outputs must remain
independently attributable:

| Role | Required output | Must not decide |
| --- | --- | --- |
| Mathematical interpreter | Textbook claim, notation scope, hidden hypotheses, and counterexamples to overbroad readings | Whether the Lean representation is accepted |
| Formalization architect | Signature, formula/sequent representation, structural rules, and exact candidate soundness boundary | Whether the source semantics are faithful |
| Adversarial reviewer | Quantifier, substitution, freshness, weakening, exchange, and vacuity failure modes | Whether to weaken a contract to make it compile |
| Research-alignment reviewer | Dependency map from the pilot to a bounded open-problem direction and reasons the pilot may be too narrow | Whether a research direction is solved or novel |
| Library steward | Pinned-lock compile-spike packet, public-API boundary, staging record, and upstream-staging recommendation | Semantic fidelity or proof acceptance |

The interpreter and architect must produce their first candidate views without editing one
another's draft. Later reconciliation may cite both revisions but must preserve the disagreement
when it remains unresolved.

## Round protocol

1. Freeze a round input list, including candidate revision, source/rights identifiers, and the
   current `Library` lock identity.
2. Obtain two independent candidate reports: the conservative closed-only formulation and the
   structural formulation with explicit open-formula contexts/freshness.
3. Have the adversarial reviewer enumerate semantic and formal counterexamples. A reported
   mismatch becomes a gap or contract-change request; it is never repaired by deleting an
   antecedent or context condition.
4. Record textbook and open-problem alignment separately. Alignment explains relevance; it is not
   evidence that the candidate is true, formalizable, or novel.
5. When both candidates are sufficiently specified, ask the Library steward for the pinned
   preselection compile spike. It records replayable API compatibility and remaining gaps under
   the pinned lock; it cannot select or reject a Builder boundary.
6. Publish a public-safe round record with candidate hashes, role conclusions, unresolved
   disagreements, the spike state, and one next state: `continue`, `compile-spike`, `gap`, or
   `stop`.

No role may freeze a Builder statement, accept a proof, authorize model egress, or promote a
Library asset through this protocol.

## Decision rule

This protocol never chooses a candidate. A later Builder fidelity workflow may consider a
candidate only after a retained spike packet demonstrates compatible compilation in the pinned
`Library` environment without changing advertised scope, and after independent source,
formalization, mutation, non-vacuity, and semantic review. If the structural candidate exposes
freshness/context machinery that dominates the minimal soundness path, a closed-only follow-up
must retain that limitation explicitly. If closed-only syntax conceals required context, it is
rejected even if a small mapping layer compiles.

The current tracked spike is `partial_passed_with_gap`, not a selection. It names the missing
calculus-level quantifier/eigenvariable freshness bridge, therefore selects neither candidate.
No vote total, model preference, or FATE result can change that state.

## Human-calibration handoff

Manual Builder calibration begins after selection, not in parallel with this decision. Its first
batch uses the normal source-to-contract route and must pass reverse rendering, mutations,
positive/negative examples, non-vacuity, library review, and domain review. The humans retain the
right to reject the selected candidate or require a new Builder-owned contract revision.

## Record locations and cadence

`Library/Staging/` holds candidate formal assets under the pinned lock once they are bound to a
Builder draft-contract revision; an earlier spike packet contains only safe design identifiers and
its environment evidence. `Library/records/` holds safe identifiers, hashes, review decisions, and
immutable artifact pointers; it is the main formal-work record and the staging point for a later
upstream contribution. The Builder source ledger remains the source/contract record. These are
linked records, not interchangeable graphs.

Close each round with one durable note and a short update to
[the progress ledger](phase-1-progress.md). The current round already references a tracked,
revalidated `partial_passed_with_gap` preselection receipt; it remains `incomplete/gap` until the
quantifier/freshness bridge and the other recorded blockers are addressed. Start manual
calibration only after a separate Builder admission and selection record. This cadence is
deliberately evidence-first: a planned or partial compile, API benchmark, proof, or expert review
does not imply semantic acceptance.
