# Phase 1 Current Route

Status: decision and sequencing record as of 2026-07-25

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
| Domain primary | Conditional first-order model-theory sequent-calculus soundness | Independent source-fidelity or Builder-admission review rejects the implemented fragment and records a backup decision |
| Candidate boundary | V2 records the level-indexed universal fragment as T3 `gap/not_selected`; separate non-authority attachments retain pending fine spans and exact source-v2 declaration evidence without changing it | Authorized span review, a successor formal profile consistent with the observed image/imports/axioms, independent semantic review, and authenticated admission authority accept its boundary, or a backup is evaluated and recorded |
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
| M1: pilot boundary | Weeks 5--6 | Admit the reviewed model-theory fragment or record an explicit backup after the technical freshness micro-slice | Freeze the bundle/profile interface needed by that candidate | Separate source, formal, Library, and decision records; compile success alone cannot select |
| M2: first frozen slice | Weeks 6--8 | Calibrate a small source-backed statement set and freeze the first accepted `StatementContractV1` revisions | Prove or return evidence-backed gaps against the unchanged bundles | At least one frozen-to-verified vertical result plus retained rejected/mutated controls |
| M3: mathlib authority | Weeks 6--9 | Keep source fidelity and contract revision ownership unchanged | Integrate the source-built digest with the frozen bundle, lease, verifier evidence, and signer; rerun the required adversarial cases | Existing clean image-owned build plus authenticated execution receipt and explicit non-production/production authority class |
| M4: project-scale loop | Weeks 8--10 | Extend the selected slice into a real multi-file dependency frontier | Execute the 20-node Lean DAG fixture and fixed regression suites with recovery | Replayed dependency propagation, lease conflict, and clean integration evidence; one completed formalized problem as visible feedback |
| M5: Phase 1 decision | Weeks 11--12 | Publish the selected/gap state and review backlog without inflating it into a mathematical result | Run the registered benchmark/chaos/release gates that are actually authorized | RC or no-RC decision, SBOM, operations guide, interface specification, audit report, and all unrun gates named |

## Current implementation batch

The milestones above remain the release-level sequence. The following tasks are the current
implementation batch; they exist to make the critical path assignable and independently
verifiable without turning each local defect into a new subsystem. T2 and the local test-only T4
profile are technically complete. T3 now has a replayable gap record rather than an admission;
the immediate frontier is resolving that boundary or evaluating a backup. T5 and therefore T6
remain blocked downstream.

| Task | Why now | Output and acceptance | Depends on | Explicitly out of scope |
| --- | --- | --- | --- | --- |
| T1: source and quantifier boundary | The two compiling adapters are not a calculus and cannot decide source fidelity | A source-hash-bound rule matrix for substitution, capture avoidance, eigenvariable freshness, weakening, and vacuity; independent source, adversarial, research-alignment, and Library records; the result is either implementable scope or a retained gap | Pinned source and rights records | Lean proof implementation, candidate selection, contract freeze, or an open-problem claim |
| T2: Lean freshness micro-slice | Technically complete for the bounded fragment | Kernel-checked level-indexed syntax/context, weakening, capture-avoiding instantiation, universal rules, soundness, level-zero bridge, and negative capture/freshness controls under the pinned Library lock | T1 | A complete textbook calculus, `Promoted/`, or selecting a candidate merely because it compiles |
| T3: pilot admission | V2 consistently records the current candidate as `gap/not_selected`; exact source-v2 technical evidence now exposes, rather than resolves, its formal-profile mismatch | Keep the V2 decision immutable. Review the fine spans and semantics, explicitly decide the image/`Init`/axiom policy in a successor profile, and obtain authenticated authority; otherwise record the selected backup | T1 and T2 | Freezing a statement, issuing a Prover bundle, silently rewriting the old decision, or treating local replay or Agent agreement as authority |
| T4: mathlib-in-image authority | Exact source-v2 build and declaration query complete, local test-only | The 889/889 network-disabled build produced digest `3237192cf627a05367c75d46e61ec9034fefe43a4fd0c06139e38c80358648d6`. Query artifact SHA `167d7a1ede245bfa631c46651b5eb0502d758b8d966d6f4c494fdcb2d75df42a` binds 46 declarations and a 2,744-module closure; 41 declarations have nonempty axiom sets, and `Deriv.closed_sound` uses `Classical.choice`, `Quot.sound`, and `propext` | Existing OCI V2 protocol and Library lock | Registry publication, production signer, KMS/mTLS, promotion attestation, admission, RC, a frozen-bundle/gateway run against this profile, or claiming the pure-worker adversarial V3 suite ran against it |
| T5: first calibrated contract slice | A real Builder--Prover result requires an admitted source boundary; the current T3 gap cannot be frozen | After T3 admission, a coherent three-node source slice with separate `StatementContractV1` revisions; reverse rendering, non-vacuity, positive/negative examples, mutations, Library review, and named semantic review all pass before freeze. Backup evaluation may run before admission, but freeze may not | T3 admission and reviewer/rights readiness | Phase 2 batch conversion, freezing the current gap, or allowing Prover to alter a statement |
| T6: frozen-to-verified result | This is the first meaningful proof that the two engines preserve one immutable statement across their boundary | After T5, bind the retained 2,744-module closure and exact declaration evidence into the frozen contract, then run `claim -> submit_proof` or `report_gap -> verify_submission` using the source-v2 image; retain at least one accepted target and rejected controls while revision, type, imports, and axioms remain identical | T4 and T5 | Silent repair of a failed contract; failures emit only a gap or change request |
| T7: real project-scale loop | The current 20-node fixture tests scheduling but does not compile a Lean library | At least four files and 20 real declarations with dependency-frontier, lease-conflict, API-revision propagation, clean integration, and per-node verification evidence | T3, T4, and T6 | Routing or throughput optimization before correctness |
| T8: repository and Phase 1 decisions | Code visibility and mathematical release are different decisions | Two decisions bound to one commit: repository visibility after complete reachable-history checks, and RC/no-RC after T1--T7 plus the registered release gates; failed and unrun gates remain explicit | History audit can run now; RC depends on T1--T7 | Publishing source caches, raw model output, recovered data, or treating public code as a promoted theorem |

External model evaluation is deliberately absent from this critical path until an operator-owned
authorization, endpoint, evaluator, and budget are ready. Once authorized it remains a registered
secondary diagnostic under T8; it cannot close T1--T7.

Capability-adaptive `direct`/`light`/`full` routing remains in shadow evaluation until M4. A
benchmark or Dashboard improvement cannot close M1--M3. External model runs start only after the
operator-owned authorization and endpoint evidence are ready; no API is required to resolve the
local T3 evidence gaps or assess a backup. T5 cannot begin while T3 remains `not_selected`.

After M5, Phase 2 begins with a 4--6 week Builder discovery/calibration cycle. It selects a weak
field by current library overlap, source rights, expert access, and dependency leverage rather
than by a fixed topic label. Its first chapter-scale asset uses 50--100 reviewed statements and
the same frozen bundle interface. Builder supplies faithful, reusable dependencies; Prover turns
them into checked assets; the open-problem portfolio chooses subsequent work by dependency
leverage rather than benchmark score.

## Current evidence boundary

The pinned-Library packet remains `partial_passed_with_gap` and `not_selected`, but includes a
kernel-checked soundness micro-slice for the `⊥`, `→`, and `∀` fragment. Its immutable V2 T3
decision replays locally against the current manifest and workspace and preserves the gap.
Separate attachments retain ten machine-located fine spans pending review and the exact source-v2
query for all 46 declarations and the 2,744-module closure. The latter shows that 41 declarations
use nonempty axiom sets and that `Deriv.closed_sound` depends on `Classical.choice`, `Quot.sound`,
and `propext`; it does not match the decision's old image/import/strict empty-axiom profile.
Independent semantic acceptance, a successor formal-profile decision, and authenticated admission
authority are still absent. The local image is not published to a registry and has no production
authority. T5 remains blocked; backup evaluation is the only downstream selection work that can
proceed without weakening this boundary. The open-problem north star is unchanged, and neither
result establishes progress on an open problem or an upstream contribution.
