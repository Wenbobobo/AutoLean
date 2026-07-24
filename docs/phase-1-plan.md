# Phase 1 Current Route

Status: decision and sequencing record as of 2026-07-24

## Role of this document

This is the current sequencing record for Phase 1. It resolves the order of active work when an
older week-by-week forecast, a parallel package, or a domain proposal says something different.
It does not replace the mandatory acceptance gates in
[Phase 1 acceptance](phase-1-acceptance.md), the observed-evidence record in
[the progress ledger](phase-1-progress.md), or the package ownership in
[the parallel execution plan](phase-1-parallel-execution.md).

The north star remains open-problem research. Phase 1 instead establishes a trustworthy route
from mathematical source to frozen statement, proof attempt, independent verification, and a
reviewable Library record. FATE is a pinned Prover fixture and diagnostic; it is not the north
star, a pilot-selection oracle, or a substitute for a multi-file formal library.

## Current decisions

| Decision | Current disposition | What would change it |
| --- | --- | --- |
| Domain primary | Conditional first-order model-theory sequent-calculus soundness | A retained pinned-Library compile spike rejects both candidate boundaries |
| Candidate boundary | Closed-only conservative and structural/open-formula candidates remain unresolved | Source interpretation, freshness/capture-avoidance evidence, independent review, and a compatible spike jointly support a later selection, or retain a gap |
| Curvature | Reference only, blocked by upstream mathlib PR #36036 | Stable upstream state plus a fresh, independent overlap and API review; this does not automatically restore priority |
| Backups | Abstract Cea-type variational-PDE and van Kampen-style slices | The same rights, alignment, and pinned-Library selection gates |
| Calibration order | Multi-agent self-calibration and textbook/open-problem alignment first; manual Builder calibration later | A recorded candidate selection and normal rights/domain-review readiness |
| Formal work record | Independent `Library/` is the main formal-work record and upstream staging surface | Never replaced by benchmark files, worker logs, or a mutable local checkout |
| HF archive | Operator confirmed deletion; no archive is a migration source | Separate provider-side access and credential-rotation evidence is still required for incident closure |

## Gate order

```text
source and rights identifiers
  -> independent candidate reports
  -> textbook and open-problem alignment
  -> adversarial self-calibration record
  -> pinned Library compile spike
  -> selected pilot boundary or explicit gap/backup decision
  -> manual Builder calibration and contract freeze
  -> unchanged bundle to Prover
  -> independent OCI/kernel verification
  -> Library review/promoted record and optional upstream staging
```

The first five steps are discovery/selection gates. Passing any one of them does not establish
semantic fidelity, a valid proof, a human calibration, a model result, or a promotion. A failure
at any step produces a gap or a new Builder-owned revision; it may not silently weaken a theorem.

## Feedback rhythm

Each self-calibration round produces an independently attributable candidate report, adversarial
review, alignment note, disagreement table, and next-state decision. Each compile spike produces
a pinned environment packet and either a minimally scoped success or an explicit gap. The
progress ledger is updated only with observed evidence.

The usual Phase 1 safety work continues independently: authoritative OCI execution, verifier
authority, source/rights gates, control-plane resilience, and release evidence retain their
existing acceptance criteria. Benchmark work may support the Prover track, but cannot reorder the
source-to-contract or Library selection gates.

## Milestones

| Milestone | Target window | Builder result | Prover result | Exit evidence |
| --- | --- | --- | --- | --- |
| M0: evidence baseline | Weeks 1--4 | Source/reference Harness and the retained `partial_passed_with_gap` selection spike | Two-container pure-Lean canary, replay/fencing, and test-only receipt | Focused audit, full local CI, and green Draft PR; no production claim |
| M1: pilot boundary | Weeks 5--6 | Resolve the quantifier/eigenvariable freshness and capture-avoidance boundary, then select one model-theory candidate or an explicit backup | Freeze the bundle/profile interface needed by that candidate | Separate source, formal, Library, and decision records; compile success alone cannot select |
| M2: first frozen slice | Weeks 6--8 | Calibrate a small source-backed statement set and freeze the first accepted `StatementContractV1` revisions | Prove or return evidence-backed gaps against the unchanged bundles | At least one frozen-to-verified vertical result plus retained rejected/mutated controls |
| M3: mathlib authority | Weeks 6--9 | Keep source fidelity and contract revision ownership unchanged | Build mathlib and verifier helper into a digest-pinned OCI image; rerun the same handoff/adversarial canaries | Clean image-owned build, import/axiom/type checks, authenticated execution receipt, and explicit non-production/production authority class |
| M4: project-scale loop | Weeks 8--10 | Extend the selected slice into a real multi-file dependency frontier | Execute the 20-node Lean DAG fixture and fixed regression suites with recovery | Replayed dependency propagation, lease conflict, and clean integration evidence; one completed formalized problem as visible feedback |
| M5: Phase 1 decision | Weeks 11--12 | Publish the selected/gap state and review backlog without inflating it into a mathematical result | Run the registered benchmark/chaos/release gates that are actually authorized | RC or no-RC decision, SBOM, operations guide, interface specification, audit report, and all unrun gates named |

## Current implementation batch

The milestones above remain the release-level sequence. The following tasks are the current
implementation batch; they exist to make the critical path assignable and independently
verifiable without turning each local defect into a new subsystem. T1 and T4 are the only two
immediate work fronts.

| Task | Why now | Output and acceptance | Depends on | Explicitly out of scope |
| --- | --- | --- | --- | --- |
| T1: source and quantifier boundary | The two compiling adapters are not a calculus and cannot decide source fidelity | A source-hash-bound rule matrix for substitution, capture avoidance, eigenvariable freshness, weakening, and vacuity; independent source, adversarial, research-alignment, and Library records; the result is either implementable scope or a retained gap | Pinned source and rights records | Lean proof implementation, candidate selection, contract freeze, or an open-problem claim |
| T2: Lean freshness micro-slice | The active pilot cannot advance while its only named calculus-level gap is represented only in prose | Minimal syntax/context, renaming or substitution, quantifier rules, and soundness lemmas under the pinned Library lock; clean build without `sorry`; positive cases plus negative capture/freshness controls | T1 | A complete textbook calculus, `Promoted/`, or selecting a candidate merely because it compiles |
| T3: pilot admission | Mathematical selection must precede the Prover interface, not be inferred from proof-search success | One admission receipt or an immutable gap/backup decision; locked imports, axioms, environment, and proof-slot profile; every missing review must reject admission | T1 and T2 | Freezing a statement, issuing a Prover bundle, or treating Agent agreement as authority |
| T4: mathlib-in-image authority | The current cache receipt detects byte drift but cannot establish how its first `.olean` files were produced | A source-only package lock followed by a network-disabled, empty-build-directory OCI build of the import closure actually used by the pilot; a real mathlib-importing V2 canary must pass without reading the host `.lake` | Existing OCI V2 protocol and Library lock | New contract versions, a copied host cache, registry publication, KMS/mTLS, or a production claim |
| T5: first calibrated contract slice | A real Builder--Prover result requires source-backed frozen contracts rather than another synthetic fixture | A coherent three-node source slice with separate `StatementContractV1` revisions; reverse rendering, non-vacuity, positive/negative examples, mutations, Library review, and named semantic review all pass before freeze | T3 and reviewer/rights readiness | Phase 2 batch conversion or allowing Prover to alter a statement |
| T6: frozen-to-verified result | This is the first meaningful proof that the two engines preserve one immutable statement across their boundary | `claim -> submit_proof` or `report_gap -> verify_submission` using the T4 image; at least one accepted target and retained rejected controls; revision, type, imports, and axioms remain identical through the receipt | T4 and T5 | Silent repair of a failed contract; failures emit only a gap or change request |
| T7: real project-scale loop | The current 20-node fixture tests scheduling but does not compile a Lean library | At least four files and 20 real declarations with dependency-frontier, lease-conflict, API-revision propagation, clean integration, and per-node verification evidence | T3, T4, and T6 | Routing or throughput optimization before correctness |
| T8: repository and Phase 1 decisions | Code visibility and mathematical release are different decisions | Two decisions bound to one commit: repository visibility after complete reachable-history checks, and RC/no-RC after T1--T7 plus the registered release gates; failed and unrun gates remain explicit | History audit can run now; RC depends on T1--T7 | Publishing source caches, raw model output, recovered data, or treating public code as a promoted theorem |

External model evaluation is deliberately absent from this critical path until an operator-owned
authorization, endpoint, evaluator, and budget are ready. Once authorized it remains a registered
secondary diagnostic under T8; it cannot close T1--T7.

Capability-adaptive `direct`/`light`/`full` routing remains in shadow evaluation until M4. A
benchmark or Dashboard improvement cannot close M1--M3. External model runs start only after the
operator-owned authorization and endpoint evidence are ready; no API is required for the next
Builder-boundary and mathlib-image increments.

After M5, Phase 2 begins with a 4--6 week Builder discovery/calibration cycle. It selects a weak
field by current library overlap, source rights, expert access, and dependency leverage rather
than by a fixed topic label. Its first chapter-scale asset uses 50--100 reviewed statements and
the same frozen bundle interface. Builder supplies faithful, reusable dependencies; Prover turns
them into checked assets; the open-problem portfolio chooses subsequent work by dependency
leverage rather than benchmark score.

## Current evidence boundary

A pinned-Library preselection spike is now recorded as `partial_passed_with_gap` and
`not_selected`. It establishes API compatibility for two semantic adapters only; it does not
select a candidate or establish a calculus-level soundness boundary. No model/API benchmark,
manual Builder calibration batch, frozen model-theory contract, accepted soundness proof, or
upstream contribution is recorded by this plan. Those items require their own immutable evidence
and semantic review.
