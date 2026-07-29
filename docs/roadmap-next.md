# AutoLean Next Operating Plan

Status: the only active execution-order authority

This is the current root-agent control plan for continuing Phase 1 and preparing Phase 2 without
losing sight of the Open Problem north star. Acceptance rules remain in
[phase-1-acceptance.md](phase-1-acceptance.md), observed evidence remains in
[phase-1-progress.md](phase-1-progress.md), and every external action is consolidated in
[operator-and-authority-worklist.md](operator-and-authority-worklist.md).

## North-star invariant

AutoLean has two engines, not one:

- Builder converts mathematical sources into faithful, reviewed, versioned statement contracts.
- Prover searches for proofs of frozen contracts and returns verified proof evidence, gap reports,
  or contract-change requests.

The Open Problem route depends on both. A faster Prover without Builder fidelity can solve the
wrong theorem; a careful Builder without Prover throughput does not scale toward dependency
closures. All near-term milestones must therefore preserve the public protocol boundary.

## Current phase interpretation

The repository has a substantial Phase 1 skeleton: contracts, control-plane events, ModelWork V2,
an authorized ten-trial role bridge, a FATE common executor, a read-only Dashboard projection,
source/fidelity harnesses, typed T7 module receipts, synthetic chaos coverage, and downstream
Library workspace documentation. It also has a proposal-only ResearchScout event projection, a
complete non-authoritative T3 machine packet, and bounded synthetic Builder calibration protocols.
Remote facts checked on 2026-07-29: public draft
[PR #26](https://github.com/Wenbobobo/AutoLean/pull/26) is open and mergeable at
`cd42ba76473002cfff9eaf4b8710e90fa3877cd4`, and GitHub Actions
[CI run #64](https://github.com/Wenbobobo/AutoLean/actions/runs/30364517594) succeeded. Its updated
PR description records candidate-local validation of 1,438 passed, 15 explicit environment/cache/
OCI/WSL skips, and 0 failures, plus a retained local synthetic 1,000-job replay. CI success and a
project-authored PR description do not independently establish semantic fidelity, a Lean result, or
production authority.

An earlier local DeepSeek official-profile canary reached only a redacted network refusal. A later
ten-call role observation settled every request, but every completion saturated the fixed 256-token
output ceiling and remains non-promotable. A versioned 512-token ablation then passed zero-call
preflight but stopped after its first 256-token control request returned redacted `network`; it made
no retry and no comparison. An independent 2026-07-30 rerun again stopped after one control-arm
`network` failure and skipped the candidate arm. These are sandbox-route observations, not endpoint,
authentication, billing, or model-quality diagnoses, and none supports a competence conclusion.
A fresh 2026-07-30 WSL probe returned `Wsl/EnumerateDistros/Service/E_ACCESSDENIED`; no authoritative
Lean or OCI execution occurred. Fresh authority-host, gateway, and provider results must be retained
under their own exact execution identities.

The remaining work is not to invent another runtime. It is to close a narrow vertical path in which
one admitted Builder statement moves through the exact same interfaces that future textbook and
Open Problem dependency nodes will use.

## Active 60-step execution board

Status means:

- `Done`: the progress ledger names evidence within its stated scope;
- `Partial`: code or bounded evidence exists, but the listed acceptance boundary remains open;
- `Next`: agents can execute it without a new external decision;
- `In progress`: an active work package owns the next artifact; and
- `External`: agents must finish machine preparation, then the corresponding `AUTH-*` item must
  close. External work never blocks unrelated `Next` items.

The board is dependency ordered, not a claim that every row takes equal time. FATE rows are
diagnostic; they never outrank the first faithful contract or chapter closure.

### Phase 1: Weeks 1--2, contracts and repository frame

| ID | Status | Task and acceptance signal |
| --- | --- | --- |
| P1-01 | Done | Establish the document authority map: specifications, facts, execution, external actions, strategy, history, and research have one owner each. |
| P1-02 | Done | Establish the archive index without deleting or moving evidence-bearing files; future moves require a link/dependency scan and redirect. |
| P1-03 | Partial | Bind each progress-ledger snapshot to one exact commit or staged candidate; the historical baseline and working-tree addendum must remain distinguishable. |
| P1-04 | Done | Make this file the only active ordering authority; old Phase 1 plans are historical snapshots. |
| P1-05 | Done | Preserve Contract V1, stable revision/hash separation, immutable bundles, and the five public Builder--Prover commands. |
| P1-06 | Done | Preserve MathematicalGraph, FormalGraph, and ExecutionGraph as distinct structures. |
| P1-07 | Done | Preserve fake provider, FATE locks, threat model, `uv` workspace, and source/public policy gates. |

### Phase 1: Weeks 3--4, first vertical and authority boundary

| ID | Status | Task and acceptance signal |
| --- | --- | --- |
| P1-08 | Partial | Exercise `SourceRecordV1` and `RightsRecordV1` on a real, exact, explicitly licensed source; URL metadata alone is insufficient. |
| P1-09 | Done | Retain reverse rendering, non-vacuity controls, examples/counterexamples, and critical semantic mutations as hard Builder gates. |
| P1-10 | Done | Preserve the locally tested, non-promotable [machine-semantic-quorum](../Builder/src/autolean_builder/machine_semantic_quorum.py) sidecar with blinded roles, failure-domain accounting, hard vetoes, persistent dissent, and `may_freeze=false`. This closes quorum construction only; P1-12 has separate packet evidence, and this row cannot close `AUTH-T3-01`. |
| P1-11 | Done | Preserve the model-theory T3 V2 decision as immutable `gap/not_selected`; no machine vote may rewrite it. |
| P1-12 | Done | Preserve the complete, deterministic [T3 machine review packet](model-theory-t3-machine-review.md): all nine ambiguities remain unresolved, three mutation controls are retained, three successor profiles remain unselected, and every authority flag is false. This closes packet construction only; `AUTH-T3-01` remains open. |
| P1-13 | External | Close `AUTH-T3-01`, or explicitly retain the T3 gap and move the first real-contract attempt to a new source. |
| P1-14 | External | Obtain one rights-ready, semantically accountable boundary for the first real T5 contract. |
| P1-15 | Done | Preserve SQLite WAL, CAS artifacts, leases, fencing, append-only events, and deterministic projection. |
| P1-16 | Partial | Extend replay evidence from in-process/synthetic coverage to a retained, gateway-bound independent-execution receipt. A P1-33 process-chaos receipt cannot close this row; production signer custody remains a separate P1-20 requirement. |
| P1-17 | Partial | Keep the T6 Builder-only query `proof_eligible=false` and replay its rejection controls in local tests. |
| P1-18 | External | Close `AUTH-T6-01`: run the exact query through image-owned OCI/Lean and the independent gateway. |
| P1-19 | Partial | Preserve gateway replay/outage/fence tests while keeping local HMAC explicitly test-only. |
| P1-20 | External | Close `AUTH-SIGNER-01`: deploy independently controlled mTLS/ACL and signing custody. |

### Phase 1: Weeks 5--6, real worker and model path

| ID | Status | Task and acceptance signal |
| --- | --- | --- |
| P1-21 | Partial | Preserve the typed T7 module process receipt, complete source binding, atomic fanout, and injected-runner adversarial tests. Focused Python tests passed, but no OCI authority execution has run. |
| P1-22 | External | Close `AUTH-T7-01`: run a real leased image-owned build, stale-fence rejection, crash/restart, clean integration, and per-node verification. |
| P1-23 | External | Retain one real rights-cleared frozen contract through unchanged bundle, Prover, OCI, kernel query, and independent verifier. |
| P1-24 | Done | Preserve Fake, Codex CLI, OpenAI Responses, and custom-compatible providers; keep Claude/Anthropic absent and prohibit automatic fallback. |
| P1-25 | Partial | Preserve the DeepSeek official profile, redacted canary, authorized ten-trial role route, and output-budget ablation protocol. The ten-call observation settled at the fixed 256-token ceiling. Both the 2026-07-29 ablation and a fresh 2026-07-30 rerun stopped on their first redacted control-arm `network` failure, skipped the candidate arm, and emitted no comparison. Neither run is promotable or supports an endpoint, authentication, billing, or model-competence conclusion. |
| P1-26 | External | Close `AUTH-PROVIDER-01`: retain one successful real-provider run and independent evaluation without turning it into proof or fidelity evidence. |
| P1-27 | Partial | Preserve the canonical FATE lock, common executor, stable selections, answer exclusion, deterministic attempt seeds, and separate M/H/X reporting. The current compile canary has not rerun because a fresh 2026-07-30 probe returned `Wsl/EnumerateDistros/Service/E_ACCESSDENIED`; no current Lean/OCI authority result exists, and any earlier canary is historical and nonbinding. |
| P1-28 | Next | After P1-26, run `regression-48` pass@1 under one frozen model/tool/retrieval/budget contract. |

### Phase 1: Weeks 7--8, comparison and observation

| ID | Status | Task and acceptance signal |
| --- | --- | --- |
| P1-29 | Next | After P1-26, run compare-90 pass@1 and pass@4 plus model, retrieval, and specialist-role ablations; never merge role scores. |
| P1-30 | Next | Run FATE-350 only after the smaller frozen routes are stable; report M/H/X and failures separately. |
| P1-31 | Partial | Preserve the loopback read-only Dashboard, three graph lanes, evidence-state health semantics, sanitization, and event identity separation. The ResearchScout proposal-only event is now replayed as an advisory work-record summary without creating a graph node, run, task, contract, or authority state. |
| P1-32 | Next | Link real Builder revisions, proof/gap attempts, T7 receipts, and verifier evidence in the Dashboard projection without adding control actions. |
| P1-33 | Done | A fresh V2 1,000-job local synthetic receipt is bound to candidate `cd42ba76473002cfff9eaf4b8710e90fa3877cd4`, `uv.lock`, runtime, canonical argv, retained manifest, exact SQLite schema/event/lease/fence history, terminal projection, and typed cross-bound CAS artifacts. Its independent read-only replay verified 1,000 completed jobs, 5,000 contiguous events, 4,000 artifacts, and 4,000 duplicate deliveries with no loss or duplicate terminal verdict. This closes provenance-bound synthetic recovery only; it cannot close P1-16, T6/T7, production signer custody, or the release gate. |

### Phase 1: Weeks 9--12, authority stress and phase decision

| ID | Status | Task and acceptance signal |
| --- | --- | --- |
| P1-34 | External | Run real-worker kill/restart/replay through T7; synthetic chaos cannot close this row. |
| P1-35 | Done | Preserve Windows/Linux CI, Ruff, mypy, UI tests/build, source locks, secret scans, and public-readiness checks. |
| P1-36 | Partial | Keep SBOM, operations, protocol, audits, exact release manifest, and clean staged-candidate evidence current. |
| P1-37 | External | Close remaining authority-host, provider, signer, semantic, and release-owner actions; browser QA remains a separately disclosed UI gap where unavailable. |
| P1-38 | External | Close `AUTH-RELEASE-01` with an exact-commit RC or no-RC decision naming every unrun, failed, and waived gate. |

### Phase 2: discovery and source lock

| ID | Status | Task and acceptance signal |
| --- | --- | --- |
| P2-01 | Partial | Maintain two or three discovery lanes without presenting any as an admitted pilot. |
| P2-02 | Partial | Keep iFEM Chapters 1--10 as the conditional primary for source preparation and compile discovery only. |
| P2-03 | Partial | Retain PDE and metric/algebraic-geometry lane cards with explicit stop conditions and no production-ingestion claim. |
| P2-04 | Partial | Thirteen pinned iFEM source files are locally locked and independently replayed under `local_only`, with source-lock receipt SHA-256 `74eca6689fe69dcbf2f34ea524a99cacc2054c0a39cfecfb11887c29e13cf239`. Digest-only indexes bind 161 notebook cells and three `intro.md` heading sections. A deterministic [candidate-only dependency graph](ifem-candidate-dependency-graph.md) now records 25 nodes and 49 planning edges without source text. This closes source/locator and graph-skeleton construction only: there is no semantic source mapping, mathematical dependency claim, FormalGraph, ExecutionGraph, freeze, or Prover handoff. |
| P2-05 | Done | Preserve the [active discovery-lane manifest](../Builder/pilots/discovery/phase-2-active-lanes.v1.json) with source, rights, overlap, and stop gates for every active lane. This is discovery metadata only; egress remains `local_only` until `AUTH-RIGHTS-01` closes. |
| P2-06 | Done | Preserve the content-addressed iFEM prerequisite denominator and reject unrelated easy-node additions before any mathlib query. The bound coverage census remains `not_started`; no coverage result is claimed. |
| P2-07 | Next | Compile exact pinned-mathlib type/import queries and classify direct mappings, thin adapters, and missing nodes separately. |
| P2-08 | Next | Issue a falsifiable GO/NO-GO for iFEM at the unchanged 70--80 percent prerequisite band; an absent restriction API or broad import remains NO-GO evidence. |

### Phase 2: machine-first statement factory

| ID | Status | Task and acceptance signal |
| --- | --- | --- |
| P2-09 | Done | Preserve the eleven-sample repository-synthetic opening corpus as a schema fixture. It covers every required mutation family, but is not textbook calibration or semantic evidence. |
| P2-10 | Done | Keep the required mutation-family coverage locked to the eleven-sample synthetic corpus; source-specific calibration and measured detection performance remain separate next gates. |
| P2-11 | Partial | Preserve the deterministic [5/3/3 held-out structural protocol](builder-held-out-calibration.md) over the eleven project-synthetic samples, including cross-partition digest isolation and precommitted fake-provider budgets. It measures strict JSON and declared structural-drift detection only; harmful negatives, known formal references, real-model repetitions, false-acceptance/risk-coverage estimates, and semantic calibration remain open. |
| P2-12 | Partial | Preserve the [source-span synthetic self-calibration harness](builder-source-span-self-calibration.md): two proposers, reverse review, mutation critic, and adjudicator run over the canonical eleven-sample corpus with all authority false. No real textbook candidate, independent real agent execution, semantic-equivalence result, freeze, or Prover handoff has occurred. |
| P2-13 | Next | Treat any critical dissent, surviving mutation, counterexample, shared lineage, or stale calibration as abstention, not a majority-vote pass. |
| P2-14 | External | Close source-specific `AUTH-RIGHTS-01`; then create 50--100 real non-frozen `local_calibration` candidates starting from textbook definitions and openings. |
| P2-15 | Next | Keep machine-screened candidates in a non-promotable sandbox lane until the measured risk-coverage policy and accountable admission boundary are explicit. |

### Phase 2: chapter-scale Builder--Prover closure

| ID | Status | Task and acceptance signal |
| --- | --- | --- |
| P2-16 | External | Freeze only candidates that satisfy formal admission; hand unchanged bundles to Prover through the Phase 1 contract. |
| P2-17 | Next | Build one 20--40-node chapter slice with definitions, examples, counterexamples, reusable lemmas, and terminal theorem/gap coverage. The 25-node/49-edge iFEM candidate-only graph is a planning skeleton and does not satisfy this task because it has no semantic mapping, reviewed contracts, freeze, proofs, or gaps. |
| P2-18 | Partial | Preserve `Library/` staging, records, and review surfaces as the independent downstream workspace. |
| P2-19 | Partial | [Dependency Closure V2](dependency-closure-v2-design.md) has locally tested Stage A and implemented Stage B mechanics. A nonempty `accepted_dependencies` closure now fails registration until a gateway-owned `dependency.admitted` record binds the accepted verification to the exact exported module/OLean blob. That admission record, complete declaration inventory observation, and authoritative proof path remain open. |
| P2-20 | Next | End every cycle with one replayable mathematical feedback artifact: verified proof, mutation-blocked conversion, counterexample, or bounded gap. |

### Post-Phase 2 research queue

| ID | Status | Task and acceptance signal |
| --- | --- | --- |
| R-01 | Done | Audit Danus at exact commit `7e244865`; retain its fact-graph/context lessons only through the isolated, [proposal-only ResearchScout boundary](research/research-scout-adapter-v1.md). Its advisory events now replay append-only into the read-only Dashboard projection without creating a task, graph node, contract, proof, or promotion path. Reject the Danus runtime, Claude dependencies, shared-file authority, and LLM verifier as truth. |
| R-02 | Next | After at least three connected chapter slices, validate a dependency-leverage atlas against simple/random/degree baselines before it may steer the Open Problem portfolio. |

## Current parallel waves

1. **Wave A, no external wait:** preserve completed P1-10/P1-12, the bounded P2-04 through P2-06
   evidence, the synthetic P2-11/P2-12 protocols, and R-01; advance P2-07/P2-08/P2-13 with focused
   tests and no authority promotion.
2. **Wave B, authority execution:** prepare P1-18/P1-22/P1-26 so each requires one bounded
   operator action rather than an open-ended investigation.
3. **Wave C, first real closure:** close P1-14/P1-23, then start P2-14 through P2-20 without
   changing the Builder--Prover contract.
4. **Wave D, scale:** run P1-28 through P1-30 and later multi-chapter work only after the
   production-shaped vertical is retained.

## Canonical M0--M8 milestone ladder

The detailed Phase 2 design remains in [the fractal roadmap](phase-2-fractal-roadmap.md). This
ladder is the canonical long-horizon order. A milestone may contain many parallel tasks, but its
exit condition is never satisfied by a later milestone's evidence.

| Milestone | Horizon and task frontier | Current truth | Exit condition and non-substitutes |
| --- | --- | --- | --- |
| **M0 — Invariants and evidence hygiene** | Continuous: Contract V1, three graphs, immutable artifacts, source/rights policies, provider deny-list, and read-only Dashboard. | Maintained locally. | These are permanent constraints, not a one-time promotion. A passing test or agent consensus cannot weaken Builder -> frozen contract -> Prover. |
| **M1 — Reproducible Phase 1 architecture** | Weeks 1--12: control plane, fake/provider adapters, FATE boundary, dashboard, chaos receipt, release/public scans. | Substantially complete in local scope; PR #26 at `cd42ba7` is CI-green and records the exact candidate tests. | A no-RC/RC decision names every gate. Local/CI evidence alone is not a semantic, kernel, signer, or model result. |
| **M2 — Authority-bearing vertical** | First rights-cleared statement through unchanged bundle, T6 OCI/Lean, T7 lease/recovery, kernel query, and independent gateway. | Not closed. | Exact source rights, semantic admission, fixed environment, real image execution, gateway verification, and signer custody must all bind the same revision. Synthetic routes do not substitute. |
| **M3 — Controlled real Prover baseline** | Authorized DeepSeek/Codex/custom endpoint role runs, then regression-48, compare-90, and FATE-350 under frozen experimental contracts. | Harness ready; the ten-call DeepSeek observation settled but saturated its 256-token ceiling and is non-promotable, so no competence conclusion is available. | Provider/evaluator authority, source-egress policy, budget reconciliation, and role-separated reports. Benchmark score never establishes Builder fidelity. |
| **M4 — Builder calibration factory** | Rights-cleared textbook openings; 50--100 non-frozen candidates; independent extraction/formalization/critique/falsification and calibration measurement. | The eleven-sample synthetic opening corpus now has a source-span multi-role fake harness and a deterministic 5/3/3 held-out structural protocol. These are architecture regressions, not real textbook or semantic calibration. | Measured harmful-negative resistance, abstention behavior, and source-specific rights boundary. Machine output remains `machine_advisory`. |
| **M5 — First chapter closure** | One 20--40 node slice in downstream `Library/`: definitions, examples, counterexamples, reusable lemmas, terminal theorem/gap ledger. | A 25-node/49-edge iFEM candidate-only planning graph exists, and Dependency Closure V2 has Stage A plus fail-closed Stage B mechanics. No node is semantically mapped, reviewed, frozen, proved, or handed to Prover. | Reviewed frozen contracts route unchanged to Prover and verifier; every node has reproducible proof/gap/mutation evidence. Isolated FATE passes do not substitute. |
| **M6 — Connected downstream library** | Several coherent chapter slices, Dependency Closure V2 Stage B, stable APIs, multi-worker scheduling, and optional small mathlib packets. | Stage B mechanics exist, but nonempty accepted dependencies are blocked pending gateway-owned module/OLean admission binding. | Pinned clean builds, cross-slice dependency and axiom profiles, provenance, migration discipline, and demonstrable closure reduction per budget. |
| **M7 — Research atlas and untrusted scout** | Dependency-leverage portfolio, Danus-inspired proposal workers, experience retrieval, and blind reproof of held-out known results. | The proposal-only ResearchScout adapter and append-only read-only event projection exist; no scout runtime, atlas result, scheduling authority, or accepted artifact exists. | Beats simple/random/degree baselines on held-out closure while every accepted artifact still traverses M0--M6 boundaries. Fact count or model agreement does not substitute. |
| **M8 — Conjecture frontier and Open Problem claim** | Quarantined conjectures, diversified reduction/counterexample/lemma portfolios, exact proof-closure and novelty packets. | Long-range only. | Independent semantic, kernel, reproduction, and novelty review for one exact revision; only `AUTH-OPEN-PROBLEM-01` permits a public solution/novelty claim. |

Machine agents may independently choose a conservative operational route—retain a gap, abstain,
switch to public-metadata discovery, or reject a candidate—but cannot mark an authority exit as
complete. Their positive output is evidence for a later review or verifier, never the review or
verifier itself.

## Phase decomposition by horizon

The following detailed sections unpack the canonical ladder without replacing its exit conditions.

### Phase 1: architecture proof

**P1.a — Frozen contract path.** Complete one rights-cleared, independently reviewed Builder contract
without statement mutation; route the immutable bundle through independent Lean verification.

**P1.b — Real execution path.** Run T6 and T7 on the authority Linux/WSL OCI route with retained
image, lease, receipt, clean-integration, and failure/restart evidence.

**P1.c — Measured Prover path.** Run an authorized real provider through the frozen role protocol and
FATE executor. Report M/H/X separately, preserving unsuccessful and refused attempts. Do not use
the result as Builder fidelity evidence.

**Phase exit.** A no-RC or RC decision names every unrun gate. An RC additionally needs semantic
review, independent verification, production admission/signing custody, release scans/SBOM, and
the remaining controlled-browser/operations evidence.

### Phase 2: chapter-scale Builder--Prover closure

**P2.a — Discovery and calibration.** For two or three candidate domains, build public-metadata
dependency maps. For an explicitly rights-cleared lane, start at the textbook opening to calibrate
notation, retain independent conversion candidates, and use mutation, examples, and reverse
rendering to reject bad conversions. McKay is currently only a non-freezing opening discovery.

**P2.b — First chapter slice.** Select one 20--40 node slice with roughly 70--80 percent prerequisites
already present. Freeze only the reviewed contracts; send the unchanged bundles to Prover and keep
proof gaps distinct from contract-change requests.

**P2.c — Feedback loop.** Each cycle must yield one replayable artifact: a verified proof, a rejected
conversion with its mutation witness, or a bounded gap report. The downstream `Library/` tree is
the reviewable record; upstream mathlib contribution remains optional and later.

**Phase exit.** A cleanly buildable, source-reviewed chapter slice with contract-to-verifier links,
examples/counterexamples, and a reproducible gap/proof ledger. A collection of isolated benchmark
passes is insufficient.

### Phase 3: library scaling

**P3.a — Reusable substrate.** Promote only reviewed definitions and lemmas from several coherent
chapter slices into a downstream library namespace, with stable APIs, dependency/axiom profiles,
and migration notes.

**P3.b — Throughput with evidence.** Schedule frozen bundles across specialized Prover roles using
bounded ContextPacks; compare providers by role, fixed inputs, and cost/time budgets rather than a
single aggregate score.

**P3.c — Upstream readiness.** Prepare small, independently buildable mathlib-facing change packets
only after downstream stability and maintainability review. The project remains valuable even when
the correct outcome is to keep a result downstream.

**Phase exit.** Multiple connected slices build from a pinned environment, have reviewable source
provenance and receipts, and reduce a documented dependency frontier rather than merely increasing
the theorem count.

### Phase 4: dependency-leverage atlas

**P4.a — Portfolio graph.** Rank conjecture families by verified missing dependency closure, source
clarity, active-project overlap, and independently reproducible evidence. Keep conjecture nodes
separate from theorem nodes.

**P4.b — Scheduling validation.** Compare dependency-leverage scheduling against simple, random, and
degree-based baselines on held-out known-theorem closures. Promote it only when it improves
kernel-verified closure per budget without increasing semantic false accepts.

**P4.c — Experience retrieval.** Compress successful and failed routes into provenance-bound,
revisioned guidance artifacts. Retrieved experience may steer search but never become a proof
premise or statement authority.

**Phase exit.** The atlas improves held-out closure under a frozen protocol, and every scheduling
decision remains replayable to its graph and evidence revisions.

### Phase 5: automated research scout and blind reproof

**P5.a — Untrusted scout.** Add Danus-inspired fact-sized constructive, refutational, toy-example, and
literature workers as proposal generators only. Their outputs enter MathematicalGraph candidate
space, never FormalGraph truth.

**P5.b — Closure and invalidation.** Track exploration graph versus final supporting closure, and
propagate source or lemma invalidation through immutable revisions rather than shared-file edits.

**P5.c — Blind reproof.** Reprove held-out established results with original proofs excluded, exact
budgets, contamination caveats, and independent kernel replay. Measure closure gain, not generated
fact count.

**Phase exit.** The scout beats simpler search baselines on blind known results while all accepted
nodes still pass the unchanged Builder--Prover contract and verifier path.

### Phase 6: conjecture frontier sandbox

**P6.a — Quarantined conjecture track.** Admit a conjecture only after its definitions and prerequisite
lemmas have the same evidence standard as theorem nodes. Proof failure may create gaps or change
requests, never weaken the conjecture.

**P6.b — Route portfolio.** Run diversified reduction, counterexample, lemma-discovery, and proof
search portfolios with correlated-failure accounting and explicit abstention.

**P6.c — Research artifact boundary.** Keep promising reductions, conditional lemmas, and negative
results publishable as exact, reproducible artifacts without calling the conjecture solved.

**Phase exit.** At least one frontier portfolio produces independently replayed new dependency
assets or a materially sharper gap, with no promotion based on model consensus alone.

### Phase 7: Open Problem research and claim validation

**P7.a — Exact claim closure.** Bind the conjecture revision, complete proof dependency closure, axiom
profile, source provenance, and clean verifier replay.

**P7.b — Adversarial reproduction.** Use fresh environments and independent model families to attack
the statement, proof, novelty search, and hidden assumptions. Dissent is retained, not averaged
away.

**P7.c — Public research decision.** Only the external accountability item
`AUTH-OPEN-PROBLEM-01` can authorize a novelty or solution claim for the exact artifact. The
automated system prepares the evidence packet; it does not award itself authority.

**Phase exit.** There is no automatic "solved" label. A public research claim exists only for an
exact frozen statement and independently reproduced proof context, with the claim scope and
remaining uncertainty stated explicitly.

## Immediate work packages

| Package | Owner style | Next deliverable | Acceptance signal |
| --- | --- | --- | --- |
| T3 semantic/admission closure | Machine quorum plus external exception owner | Preserve the completed machine packet, resolve its nine pending ambiguities if authoritative source evidence permits, and select a successor profile or retain the gap | Packet construction is complete with three controls and three unselected profiles; only `AUTH-T3-01` can admit the old candidate, and choosing a new source is the preferred low-human bypass |
| T6 real Builder-query replay | Core/root | Run the implemented Builder-only query in the exact OCI/Lean environment and bind its receipt to the signing gateway | Query stays `proof_eligible=false`; real image, environment, and rejection controls replay without changing a theorem. The current session's WSL denial is an execution blocker, not a T6 conclusion. |
| T7 leased rebuild vertical | Focused subagent with core review | Attach the typed module-receipt path to the image-owned worker and real lease | Focused Python tests passed, but no OCI authority execution occurred. Exact declaration closure and conservative module rebuild remain distinct; the injected cross-job receipt rejection is local coverage, not an execution receipt. |
| Role benchmark execution | Subagent | Keep `calibration-pairs-v3` fake-only for harness regression; use a separately authorized, unsaturated run for any future competence comparison | The DeepSeek ten-call observation saturated the 256-token ceiling, while both ablation attempts stopped on a first control-arm `network` failure and skipped the candidate; none is a score or competence result. |
| Dashboard grid view | Subagent | Preserve the read-only graph-health surface and add only event-projection evidence links | UI keeps FATE, generic verification, and T7 receipt identities separate; browser visual QA and remote access remain separate gates. |
| Meeting/landscape research | Subagent | Extract Archon-talk and adjacent assistant lessons into scoped architecture proposals | Suggestions are mapped to existing gates instead of treated as benchmark proof |
| Library/Builder pilot discovery | Core/root with later reviewers | Pick 2-3 synchronized pilot threads only after source/rights and review constraints are explicit | Each candidate has a node graph, missing-library map, and clear rejection condition |

## Phase 2 planning pointer

Public-metadata `discovery` can run now. `local_calibration` needs explicit source rights and
remains non-freezing/non-egressing by default; `production_ingestion` remains subject to every
Phase 1 entry criterion. A Phase 1 no-RC decision records blockers; it does not waive a missing
admission, freeze, verification, substrate, or release gate.

## Execution notes

The active statuses and ordering are the 60-step board above. These notes explain the immediate
critical path; they do not form a second task list.

1. Preserve the completed T3 machine packet before attempting a first frozen Builder statement.
   - The packet remains intentionally fail-closed at `gap/not_selected/not_frozen`; all nine
     ambiguities remain unresolved and all three successor profiles remain unselected.
   - Either close `AUTH-T3-01` with accountable source evidence or retain the gap and choose a
     different source; no machine result may silently admit the old candidate.
   - T5 remains blocked unless that decision admits one exact boundary with rights readiness.

2. Move the implemented T6/T7 routes across their real execution boundaries.
   - Run the Builder-only T6 query in the exact OCI/Lean image, bind it to the gateway, and keep
     it `proof_eligible=false`.
   - Bind T7 planning to a control-plane lease and immutable source snapshot worker; retain clean
     integration and per-node verifier evidence.
   - Preserve exact statement and theorem type checks before accepting any proof.

3. Turn role benchmark work into a stable workflow.
   - Treat Prover, checker, allocator, formalizer, and contract-change reviewer as separate roles.
   - Keep the implemented five-role `calibration-pairs-v3` preset fake-only; require authorization,
     applicable source egress, production evaluation, and budget before a real model run.
   - Store matrix revisions rather than overwriting old results.

4. Move Dashboard toward graph operations visibility.
   - Render MathematicalGraph, FormalGraph, and ExecutionGraph as distinct but linked lanes.
   - Health colors should mean evidence state, not success optimism.
   - The panel remains read-only and local by default.

5. Prepare Builder pilots without freezing them.
   - Maintain multiple candidates in parallel when they are cheap: model theory, analysis/SDE/PDE,
     and Riemannian or metric/algebraic-geometry substrate leads.
   - Start from textbook openings when the goal is calibration and feedback; start from middle
     nodes only when they expose a known Library blind spot with enough existing prerequisites.
   - Record machine abstention and the exact external fact needed rather than blocking mechanical
     preparation behind a generic “expert required” label.

## What not to optimize yet

- Do not tune against FATE as the main objective; FATE remains a Prover diagnostic.
- Do not treat Archon, AutoArchon, or any external assistant as the control plane.
- Do not treat possession of an operator-owned API key as execution authority. The local DeepSeek
  configuration has bounded canaries, but the repeated sandbox-route `network` failures and skipped
  candidate arms do not diagnose the endpoint or make the role harness ready for scoring.
- Do not use Builder observations, canonical-type canaries, or host-mounted Library diagnostics as
  proof authority.
- Do not add broad publication gates that slow every small bug fix; use focused gates where they
  protect a real boundary.

## Git and repository hygiene

The main branch should stay reviewable: one coherent commit per verified increment. Temporary
worktrees and caches can be cleaned after evidence boundaries are retained, but meeting materials,
release evidence, Library evidence, quarantined recovery records, and local source caches are not
ordinary trash.

Commits should use the configured author identity 'CC <78262508+Wenbobobo@users.noreply.github.com>'
unless the operator requests otherwise.

## External action pointer

Do not maintain an operator list here. Every remaining human, host, account, rights, signer, and
release action is a checkbox with exact machine preparation and evidence requirements in
[operator-and-authority-worklist.md](operator-and-authority-worklist.md).
