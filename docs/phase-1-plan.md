# Phase 1 Current Route

Status: historical decision and sequencing snapshot as of 2026-07-25; superseded for live
ordering by [roadmap-next.md](roadmap-next.md)

## Role of this document

This was the sequencing record for Phase 1 at its stated historical snapshot. It no longer
resolves active ordering; when it differs from an older forecast or proposal, that difference is
historical context only. Current ordering is owned exclusively by `roadmap-next.md`.
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
| Candidate boundary | V2 records the level-indexed universal fragment as T3 `gap/not_selected`; separate non-authority attachments retain pending fine spans and exact source-v2 declaration evidence without changing it | Authorized span review, a successor formal profile consistent with the observed image/imports/axioms, independent semantic review, and authenticated admission authority accept its boundary, or a different backup passes its own audit |
| Curvature | Reference only, blocked by upstream mathlib PR #36036 | Stable upstream state plus a fresh, independent overlap and API review; this does not automatically restore priority |
| Backups | Read-only audit selected neither: pointwise Cea has 8 nodes with 25 percent strict or 50 percent optimistic reuse; van Kampen is paused | A materially different boundary or candidate must pass a new rights, overlap, alignment, and pinned-Library audit |
| Model-theory source egress | Current source and review packet are `local_only`; exact pages cannot be sent to external providers or model-backed subagents | A reviewed source-manifest/rights revision explicitly authorizes a permitted endpoint class; this is source policy, not a Provider/Harness capability gap |
| Calibration order | Multi-agent self-calibration and textbook/open-problem alignment first; manual Builder calibration later | A recorded candidate selection and normal rights/domain-review readiness |
| Formal work record | Independent `Library/` is the main formal-work record and upstream staging surface | Never replaced by benchmark files, worker logs, or a mutable local checkout |
| Prover Library substrate | Use a new side-by-side `library-substrate-v1` image with a target-free AutoLean declaration closure over the locked Semantics Mathlib closure; keep source-v2 and T4 immutable | A general `mathlib-substrate-v1` remains undecided until a measured default-target/closure preflight; external `/deps` waits for the V3 trigger |
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
| M4: project-scale loop | Weeks 8--10 | Extend the selected slice into a real multi-file dependency frontier | Bind the preflight's 20-node Lean content fixture to fixed regression suites and recovery | Replayed changed-source dependency propagation, lease conflict, bundle flow, clean integration, and per-node verification evidence; one completed formalized problem as visible feedback |
| M5: Phase 1 decision | Weeks 11--12 | Publish the selected/gap state and review backlog without inflating it into a mathematical result | Run the registered benchmark/chaos/release gates that are actually authorized | RC or no-RC decision, SBOM, operations guide, interface specification, audit report, and all unrun gates named |

## Current implementation batch

The milestones above remain the release-level sequence. The following tasks are the current
implementation batch; they exist to make the critical path assignable and independently
verifiable without turning each local defect into a new subsystem. T2 and the local test-only T4
profile are technically complete. T3 now has a replayable gap record rather than an admission;
the merged [human-review packet](../Builder/pilots/model-theory-admission/human-review/README.md)
makes the pending span review reproducible but contains no completed reviewer response and grants
no authority. The immediate frontier is completing the local review or auditing a materially
different backup. The target-free
[Library substrate decision](library-substrate-decision.md) fixes the execution design without
claiming admission. The read-only backup audit selected neither current alternative. The
executable ordinary-dependency spike replayed 4/4 fixtures against source-v2, but remains
host-mounted and outside the image/contract/gateway evidence chain. T5 and therefore T6 remain
blocked downstream. PR #20 adds a separate target-free staged split whose profile-selected source
snapshot can optionally be compiled and queried through an unretained operator-local, host-mounted diagnostic; it has
no image or content-addressed receipt, complete closure, module-origin/collision gate, contract,
or gateway evidence. PR #19 supplies only the Lean API boundary for an imported declaration's
module lookup: a current `Candidate` declaration normally yields `none`, and ownership remains a
separate sealed-module check. PR #18 keeps the synthetic DAG intact and adds a snapshot-first
four-module/twenty-node real-Lean input with an optional local source-v2 clean build. That is not
changed-source rebuild, lease, bundle, per-node verifier, or T7 acceptance evidence.

| Task | Why now | Output and acceptance | Depends on | Explicitly out of scope |
| --- | --- | --- | --- | --- |
| T1: source and quantifier boundary | The two compiling adapters are not a calculus and cannot decide source fidelity | A source-hash-bound rule matrix for substitution, capture avoidance, eigenvariable freshness, weakening, and vacuity; independent source, adversarial, research-alignment, and Library records; the result is either implementable scope or a retained gap | Pinned source and rights records | Lean proof implementation, candidate selection, contract freeze, or an open-problem claim |
| T2: Lean freshness micro-slice | Technically complete for the bounded fragment | Kernel-checked level-indexed syntax/context, weakening, capture-avoiding instantiation, universal rules, soundness, level-zero bridge, and negative capture/freshness controls under the pinned Library lock | T1 | A complete textbook calculus, `Promoted/`, or selecting a candidate merely because it compiles |
| T3: pilot admission | V2 consistently records the current candidate as `gap/not_selected`; exact source-v2 technical evidence now exposes, rather than resolves, its formal-profile mismatch. A versioned human-review packet is merged, but no independent response is accepted | Keep the V2 decision immutable. Complete independent review of the fine spans and semantics, explicitly decide the image/`Init`/axiom policy in a successor profile, and obtain authenticated authority; otherwise record the selected backup | T1 and T2 | Freezing a statement, issuing a Prover bundle, silently rewriting the old decision, or treating packet generation, local replay, or Agent agreement as authority |
| T4: mathlib-in-image authority | Exact source-v2 build and declaration query complete, local test-only | The 889/889 network-disabled build produced digest `3237192cf627a05367c75d46e61ec9034fefe43a4fd0c06139e38c80358648d6`. Query artifact SHA `167d7a1ede245bfa631c46651b5eb0502d758b8d966d6f4c494fdcb2d75df42a` binds 46 declarations and a 2,744-module closure; 41 declarations have nonempty axiom sets, and `Deriv.closed_sound` uses `Classical.choice`, `Quot.sound`, and `propext` | Existing OCI V2 protocol and Library lock | Registry publication, production signer, KMS/mTLS, promotion attestation, admission, RC, a frozen-bundle/gateway run against this profile, or claiming the pure-worker adversarial V3 suite ran against it |
| T5: first calibrated contract slice | A real Builder--Prover result requires an admitted source boundary; the current T3 gap cannot be frozen | After T3 admission, a coherent three-node source slice with separate `StatementContractV1` revisions; each node declares `independent_reproof` or `compositional_bridge`, exact formal-body dependencies, reverse rendering, non-vacuity, positive/negative examples, mutations, Library review, and named semantic review before freeze. A different backup audit may run before admission, but freeze may not | T3 admission, reviewer/rights readiness, and the target-free substrate interface | Phase 2 batch conversion, freezing the current gap, importing the full `UniversalLK` oracle, or allowing Prover to alter a statement |
| T6: frozen-to-verified result | This is the first meaningful proof that the two engines preserve one immutable statement across their boundary | After T5, use a new `library-substrate-v1` image/environment revision that contains only the manifest-bound target-free AutoLean closure over the locked Semantics Mathlib closure. Move the ordinary-dependency query into that image and bind canonical type hash, declaration kind, imported module origin, task mode, policy/closure artifact, contract, OCI evidence, and gateway replay. PR #20's profile/snapshot split and host-mounted direct-dependency/type/axiom diagnostic are implementation input only: they are not the new image, a content-addressed receipt, full closure, origin/collision gate, or T6 evidence. Run `claim -> submit_proof` or `report_gap -> verify_submission`; retain at least one accepted target plus target-leak, unknown same-type alias, dependency-drift, axiom-drift, and mutation rejections | T4, T5, and the substrate rejection gates | Reusing the host-mounted spike or source-v2/T4 evidence for the split closure, silently repairing a failed contract, enabling unbound `/deps`, or treating a compositional bridge as an independent reproof |
| T7: real project-scale loop | PR #18 supplies a separate real-Lean preflight: a snapshot-first, byte-bound four-file/twenty-node input and an optional source-v2 clean build. The synthetic fixture still owns scheduler/control-plane behavior | Bind that input to changed-source rebuild, dependency-frontier, lease-conflict, API-revision propagation, immutable bundle flow, clean integration, and per-node verification evidence | T3, T4, and T6 | Treating the preflight clean build or graph closure as T7 acceptance, or routing/throughput optimization before correctness |
| T8: repository and Phase 1 decisions | Code visibility and mathematical release are different decisions | Two decisions bound to one commit: repository visibility after complete reachable-history checks, and RC/no-RC after T1--T7 plus the registered release gates; failed and unrun gates remain explicit | History audit can run now; RC depends on T1--T7 | Publishing source caches, raw model output, recovered data, or treating public code as a promoted theorem |

External model evaluation is deliberately absent from this critical path until an operator-owned
authorization, endpoint, production evaluator, and budget are ready. The current model-theory
source is also `local_only`, so its pages cannot be used in an external or model-backed subagent
review without a new rights/manifest decision. No API is requested now. Once authorized,
answer-free or otherwise permitted evaluation remains a registered secondary diagnostic under
T8; it cannot close T1--T7.

Capability-adaptive `direct`/`light`/`full` routing remains in shadow evaluation until M4. A
benchmark or Dashboard improvement cannot close M1--M3. External model runs start only after the
operator-owned authorization and endpoint evidence are ready; no API is required to resolve the
local T3 evidence gaps or assess a backup. T5 cannot begin while T3 remains `not_selected`.

The focused `library-substrate-v1` does not decide how a future general
`mathlib-substrate-v1` is built. Before choosing Mathlib's full default target, run an isolated
preflight that records build time, module count, runtime size, and replay cost against reviewed
per-import closures. Do not enable external `/deps` until the V3 manifest, tree, evidence, and
gateway bindings in the substrate decision are implemented.

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
authority. The host-side proof-dependency spike is executable and replayed 4/4 source-v2 fixtures,
but it has no canonical type/module-origin binding or contract/gateway authority. T5 remains
blocked. The two audited backups are not selected; local T3 review or read-only audit of a
different backup may proceed without weakening this boundary. The open-problem north star is
unchanged, and none of these results establishes progress on an open problem or an upstream
contribution.

The new Library split preflight does not alter that state. It makes a profile-selected target-free
source snapshot and permits an operator-local host-mounted diagnostic to compare direct proof
dependencies, type, and axiom observations between two candidate modes. It does not create a
`library-substrate-v1` image, content-addressed receipt, complete closure, imported-origin check,
type-collision check, contract, or gateway replay. Likewise, the module-origin note is a design
constraint rather than a replayable probe: its early ad hoc probe was not retained, and Lean's
imported-only lookup normally returns `none` for the current Candidate, whose ownership must be
checked separately. The real Lean T7 preflight is
also separate evidence: four modules and twenty curated declarations can clean-build from a
snapshot in source-v2, while changed-source rebuild, leases, bundles, per-node verification, and
T7 acceptance remain open.
