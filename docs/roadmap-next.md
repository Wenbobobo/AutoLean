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
Library workspace documentation. A local DeepSeek official-profile canary reached only a redacted
network refusal; it is not a model result. The current task session cannot invoke WSL
(`Wsl/Service/E_ACCESSDENIED`), so it cannot create fresh Docker/Lean evidence.

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
| P1-10 | Done | Preserve the locally tested, non-promotable [machine-semantic-quorum](../Builder/src/autolean_builder/machine_semantic_quorum.py) sidecar with blinded roles, failure-domain accounting, hard vetoes, persistent dissent, and `may_freeze=false`. This closes software construction only, not P1-12 or `AUTH-T3-01`. |
| P1-11 | Done | Preserve the model-theory T3 V2 decision as immutable `gap/not_selected`; no machine vote may rewrite it. |
| P1-12 | Next | Produce the complete T3 machine review, ambiguity table, mutation results, and successor-profile alternatives without claiming admission. |
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
| P1-21 | Partial | Preserve the typed T7 module process receipt, complete source binding, atomic fanout, and injected-runner adversarial tests. |
| P1-22 | External | Close `AUTH-T7-01`: run a real leased image-owned build, stale-fence rejection, crash/restart, clean integration, and per-node verification. |
| P1-23 | External | Retain one real rights-cleared frozen contract through unchanged bundle, Prover, OCI, kernel query, and independent verifier. |
| P1-24 | Done | Preserve Fake, Codex CLI, OpenAI Responses, and custom-compatible providers; keep Claude/Anthropic absent and prohibit automatic fallback. |
| P1-25 | Partial | Preserve the DeepSeek official profile, redacted canary, authorized ten-trial role route, budget, and reconciliation boundary. |
| P1-26 | External | Close `AUTH-PROVIDER-01`: retain one successful real-provider run and independent evaluation without turning it into proof or fidelity evidence. |
| P1-27 | Partial | Preserve the FATE common executor, stable selections, answer exclusion, deterministic attempt seeds, and separate M/H/X reporting. |
| P1-28 | Next | After P1-26, run `regression-48` pass@1 under one frozen model/tool/retrieval/budget contract. |

### Phase 1: Weeks 7--8, comparison and observation

| ID | Status | Task and acceptance signal |
| --- | --- | --- |
| P1-29 | Next | After P1-26, run compare-90 pass@1 and pass@4 plus model, retrieval, and specialist-role ablations; never merge role scores. |
| P1-30 | Next | Run FATE-350 only after the smaller frozen routes are stable; report M/H/X and failures separately. |
| P1-31 | Partial | Preserve the loopback read-only Dashboard, three graph lanes, evidence-state health semantics, sanitization, and event identity separation. |
| P1-32 | Next | Link real Builder revisions, proof/gap attempts, T7 receipts, and verifier evidence in the Dashboard projection without adding control actions. |
| P1-33 | Partial | V2 provenance receipts bind bounded synthetic recovery runs to an exact candidate, `uv.lock`, runtime, canonical argv, and retained manifest. The verifier now read-only replays the exact SQLite schema, event/lease/fence history and terminal projection, parses and cross-binds canonical typed CAS artifacts, and rejects unreferenced artifacts. A historical V1 1,000-job summary is not a provenance-bound result. Run and independently verify a fresh V2 1,000-job receipt before closing this row. Even a successful receipt remains synthetic recovery evidence and cannot close P1-16, T6/T7, or the release gate. |

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
| P2-04 | Partial | The bounded adapter pins the iFEM revision, thirteen paths, reviewed CC BY 4.0 LICENSE digests, local-only policy, and manifest commitment; exact source bytes remain absent until `AUTH-IFEM-SOURCE-01` runs in a network-capable environment. |
| P2-05 | Done | Preserve the [active discovery-lane manifest](../Builder/pilots/discovery/phase-2-active-lanes.v1.json) with source, rights, overlap, and stop gates for every active lane. This is discovery metadata only; egress remains `local_only` until `AUTH-RIGHTS-01` closes. |
| P2-06 | Done | Preserve the content-addressed iFEM prerequisite denominator and reject unrelated easy-node additions before any mathlib query. The bound coverage census remains `not_started`; no coverage result is claimed. |
| P2-07 | Next | Compile exact pinned-mathlib type/import queries and classify direct mappings, thin adapters, and missing nodes separately. |
| P2-08 | Next | Issue a falsifiable GO/NO-GO for iFEM at the unchanged 70--80 percent prerequisite band; an absent restriction API or broad import remains NO-GO evidence. |

### Phase 2: machine-first statement factory

| ID | Status | Task and acceptance signal |
| --- | --- | --- |
| P2-09 | Partial | Preserve the ten-statement repository-synthetic pre-calibration corpus as a schema fixture, never as real textbook calibration. |
| P2-10 | Next | Extend the machine quorum with omission, `iff`, existence/uniqueness, maximum/upper-bound, equality, totalization, and coercion mutations. |
| P2-11 | Next | Build a held-out calibration set with harmful negatives and known formal references; report false acceptance, mutation recall, abstention, and correlated double faults. |
| P2-12 | Next | For each real candidate, run two blinded semantic-atom extractions, two blinded formalizations, de-correlated critics, and one adversarial falsifier. |
| P2-13 | Next | Treat any critical dissent, surviving mutation, counterexample, shared lineage, or stale calibration as abstention, not a majority-vote pass. |
| P2-14 | External | Close source-specific `AUTH-RIGHTS-01`; then create 50--100 real non-frozen `local_calibration` candidates starting from textbook definitions and openings. |
| P2-15 | Next | Keep machine-screened candidates in a non-promotable sandbox lane until the measured risk-coverage policy and accountable admission boundary are explicit. |

### Phase 2: chapter-scale Builder--Prover closure

| ID | Status | Task and acceptance signal |
| --- | --- | --- |
| P2-16 | External | Freeze only candidates that satisfy formal admission; hand unchanged bundles to Prover through the Phase 1 contract. |
| P2-17 | Next | Build one 20--40-node chapter slice with definitions, examples, counterexamples, reusable lemmas, and terminal theorem/gap coverage. |
| P2-18 | Partial | Preserve `Library/` staging, records, and review surfaces as the independent downstream workspace. |
| P2-19 | Partial | Stage A of [Dependency Closure V2](dependency-closure-v2-design.md) now has locally tested canonical contracts and a pure blob materializer, covered by [contract](../packages/contracts/tests/test_dependency_closure.py) and [materializer](../Prover/tests/test_dependency_closure_materializer.py) adversarial tests. Stage B must still bind the closure into Bundle V2, claim-scoped artifact reads, OCI execution, observed verification evidence, and the verifier gateway before any proof can be accepted. |
| P2-20 | Next | End every cycle with one replayable mathematical feedback artifact: verified proof, mutation-blocked conversion, counterexample, or bounded gap. |

### Post-Phase 2 research queue

| ID | Status | Task and acceptance signal |
| --- | --- | --- |
| R-01 | Done | Audit Danus at exact commit `7e244865`; retain its fact-graph/context lessons only for a future isolated research scout. Reject its runtime, Claude dependencies, shared-file authority, and LLM verifier as truth. |
| R-02 | Next | After at least three connected chapter slices, validate a dependency-leverage atlas against simple/random/degree baselines before it may steer the Open Problem portfolio. |

## Current parallel waves

1. **Wave A, no external wait:** preserve completed P1-10, P2-04 through P2-06, and R-01
   evidence; finish P1-12 and P2-07 through P2-13 with focused tests and no authority promotion.
2. **Wave B, authority execution:** prepare P1-18/P1-22/P1-26 so each requires one bounded
   operator action rather than an open-ended investigation.
3. **Wave C, first real closure:** close P1-14/P1-23, then start P2-14 through P2-20 without
   changing the Builder--Prover contract.
4. **Wave D, scale:** run P1-28 through P1-30 and later multi-chapter work only after the
   production-shaped vertical is retained.

## Layered milestone map

The detailed Phase 2 plan remains in [the fractal roadmap](phase-2-fractal-roadmap.md). This
shorter map fixes the dependency order and acceptance boundary for the next several horizons.

### Phase 1: architecture proof

**M1. Frozen contract path.** Complete one rights-cleared, independently reviewed Builder contract
without statement mutation; route the immutable bundle through independent Lean verification.

**M2. Real execution path.** Run T6 and T7 on the authority Linux/WSL OCI route with retained
image, lease, receipt, clean-integration, and failure/restart evidence.

**M3. Measured Prover path.** Run an authorized real provider through the frozen role protocol and
FATE executor. Report M/H/X separately, preserving unsuccessful and refused attempts. Do not use
the result as Builder fidelity evidence.

**Phase exit.** A no-RC or RC decision names every unrun gate. An RC additionally needs semantic
review, independent verification, production admission/signing custody, release scans/SBOM, and
the remaining controlled-browser/operations evidence.

### Phase 2: chapter-scale Builder--Prover closure

**M1. Discovery and calibration.** For two or three candidate domains, build public-metadata
dependency maps. For an explicitly rights-cleared lane, start at the textbook opening to calibrate
notation, retain independent conversion candidates, and use mutation, examples, and reverse
rendering to reject bad conversions. McKay is currently only a non-freezing opening discovery.

**M2. First chapter slice.** Select one 20--40 node slice with roughly 70--80 percent prerequisites
already present. Freeze only the reviewed contracts; send the unchanged bundles to Prover and keep
proof gaps distinct from contract-change requests.

**M3. Feedback loop.** Each cycle must yield one replayable artifact: a verified proof, a rejected
conversion with its mutation witness, or a bounded gap report. The downstream `Library/` tree is
the reviewable record; upstream mathlib contribution remains optional and later.

**Phase exit.** A cleanly buildable, source-reviewed chapter slice with contract-to-verifier links,
examples/counterexamples, and a reproducible gap/proof ledger. A collection of isolated benchmark
passes is insufficient.

### Phase 3: library scaling

**M1. Reusable substrate.** Promote only reviewed definitions and lemmas from several coherent
chapter slices into a downstream library namespace, with stable APIs, dependency/axiom profiles,
and migration notes.

**M2. Throughput with evidence.** Schedule frozen bundles across specialized Prover roles using
bounded ContextPacks; compare providers by role, fixed inputs, and cost/time budgets rather than a
single aggregate score.

**M3. Upstream readiness.** Prepare small, independently buildable mathlib-facing change packets
only after downstream stability and maintainability review. The project remains valuable even when
the correct outcome is to keep a result downstream.

**Phase exit.** Multiple connected slices build from a pinned environment, have reviewable source
provenance and receipts, and reduce a documented dependency frontier rather than merely increasing
the theorem count.

### Phase 4: dependency-leverage atlas

**M1. Portfolio graph.** Rank conjecture families by verified missing dependency closure, source
clarity, active-project overlap, and independently reproducible evidence. Keep conjecture nodes
separate from theorem nodes.

**M2. Scheduling validation.** Compare dependency-leverage scheduling against simple, random, and
degree-based baselines on held-out known-theorem closures. Promote it only when it improves
kernel-verified closure per budget without increasing semantic false accepts.

**M3. Experience retrieval.** Compress successful and failed routes into provenance-bound,
revisioned guidance artifacts. Retrieved experience may steer search but never become a proof
premise or statement authority.

**Phase exit.** The atlas improves held-out closure under a frozen protocol, and every scheduling
decision remains replayable to its graph and evidence revisions.

### Phase 5: automated research scout and blind reproof

**M1. Untrusted scout.** Add Danus-inspired fact-sized constructive, refutational, toy-example, and
literature workers as proposal generators only. Their outputs enter MathematicalGraph candidate
space, never FormalGraph truth.

**M2. Closure and invalidation.** Track exploration graph versus final supporting closure, and
propagate source or lemma invalidation through immutable revisions rather than shared-file edits.

**M3. Blind reproof.** Reprove held-out established results with original proofs excluded, exact
budgets, contamination caveats, and independent kernel replay. Measure closure gain, not generated
fact count.

**Phase exit.** The scout beats simpler search baselines on blind known results while all accepted
nodes still pass the unchanged Builder--Prover contract and verifier path.

### Phase 6: conjecture frontier sandbox

**M1. Quarantined conjecture track.** Admit a conjecture only after its definitions and prerequisite
lemmas have the same evidence standard as theorem nodes. Proof failure may create gaps or change
requests, never weaken the conjecture.

**M2. Route portfolio.** Run diversified reduction, counterexample, lemma-discovery, and proof
search portfolios with correlated-failure accounting and explicit abstention.

**M3. Research artifact boundary.** Keep promising reductions, conditional lemmas, and negative
results publishable as exact, reproducible artifacts without calling the conjecture solved.

**Phase exit.** At least one frontier portfolio produces independently replayed new dependency
assets or a materially sharper gap, with no promotion based on model consensus alone.

### Phase 7: Open Problem research and claim validation

**M1. Exact claim closure.** Bind the conjecture revision, complete proof dependency closure, axiom
profile, source provenance, and clean verifier replay.

**M2. Adversarial reproduction.** Use fresh environments and independent model families to attack
the statement, proof, novelty search, and hidden assumptions. Dissent is retained, not averaged
away.

**M3. Public research decision.** Only the external accountability item
`AUTH-OPEN-PROBLEM-01` can authorize a novelty or solution claim for the exact artifact. The
automated system prepares the evidence packet; it does not award itself authority.

**Phase exit.** There is no automatic "solved" label. A public research claim exists only for an
exact frozen statement and independently reproduced proof context, with the claim scope and
remaining uncertainty stated explicitly.

## Immediate work packages

| Package | Owner style | Next deliverable | Acceptance signal |
| --- | --- | --- | --- |
| T3 semantic/admission closure | Machine quorum plus external exception owner | Resolve the local review packet's pending spans and two locator ambiguities; decide the successor profile or retain the gap | Machine work produces an advisory/dissent packet; only `AUTH-T3-01` can admit the old candidate, and choosing a new source is the preferred low-human bypass |
| T6 real Builder-query replay | Core/root | Run the implemented Builder-only query in the exact OCI/Lean environment and bind its receipt to the signing gateway | Query stays `proof_eligible=false`; real image, environment, and rejection controls replay without changing a theorem. The current session's WSL denial is an execution blocker, not a T6 conclusion. |
| T7 leased rebuild vertical | Focused subagent with core review | Attach the typed module-receipt path to the image-owned worker and real lease | Exact declaration closure and conservative module rebuild remain distinct; the injected cross-job receipt rejection is local coverage, not an execution receipt. |
| Role benchmark execution | Subagent | Keep `calibration-pairs-v3` fake-only for harness regression; rerun the ten-trial suite only when a real provider and evaluator are independently authorized | The DeepSeek canary's network refusal proves only a classified failure path. A real run uses frozen prompts, evaluator, source-egress scope, budget, and timeout. |
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

1. Finish the T3 machine packet before attempting a first frozen Builder statement.
   - The local check is intentionally fail-closed at `gap/not_selected/not_frozen`.
   - Resolve the machine-located spans and two locator ambiguities as far as the source bytes
     permit, run blinded critics and mutations, then either close `AUTH-T3-01` or retain the gap and
     choose a different source.
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
  configuration has a bounded canary, but the failed network call does not make the role harness
  ready for scoring.
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
