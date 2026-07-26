# Phase 2 Fractal Roadmap

Status: planning record, not a release claim
Date: 2026-07-26

## Executive summary

Phase 1 is not yet complete as a release candidate. It has a credible architecture skeleton and
several verified local/synthetic surfaces, but the current critical path is still blocked by pilot
admission, first calibrated contract freeze, and the first frozen-to-verified Library result. The
right response is not to wait passively or chase FATE scores. We should run Phase 1 closure and
Phase 2 preparation in parallel, while keeping the authority boundary strict:

- Phase 1 closes the machine path: frozen Builder contract -> unchanged Prover bundle -> independent verifier result.
- Phase 2 opens the mathematical path: source-to-statement conversion at textbook scale, with
  reviewed dependency assets feeding the same Prover interface.
- The Open Problem portfolio governs topic selection by dependency leverage, not benchmark appeal.

This document is fractal: every level repeats the same pattern of mission, milestone, task,
evidence, and stop condition.

## Entry criteria from Phase 1

Phase 2 preparation may begin in discovery mode now. Use only these four status labels:

- `planned`: a proposed lane or dependency route with no completed source/library audit;
- `discovery`: public-metadata, rights, overlap, and dependency analysis with no source ingestion,
  contract freeze, or Prover handoff;
- `local_calibration`: a fixed, rights-cleared sample may be converted by humans or local tools to
  calibrate fidelity. It defaults to no external model egress and cannot freeze a contract, hand
  work to Prover, or support promotion; and
- `production_ingestion`: source-bound statement conversion and downstream execution.

Only `production_ingestion` waits for all Phase 1 gates below. Discovery may run now.
`local_calibration` additionally requires explicit source rights and a recorded local-use/egress
policy, but it remains non-production evidence. Neither state can be relabelled as an admitted
pilot, a frozen contract, or Phase 2 production evidence.

`local_calibration_fixture` / `pre_calibration_fixture` is an artifact class, not a fifth Phase-2
status. It remains in `discovery`: its repository-synthetic bytes may exercise schemas, reports,
and deterministic replay, but pending human content review, illustrative Lean-like text, and
synthetic mutation declarations do not satisfy the rights-cleared source, independent-candidate,
or semantic-review requirements of real `local_calibration`.

| Gate | Required before production ingestion | Can proceed in parallel now |
| --- | --- | --- |
| Pilot admission | One source/formal boundary selected or explicit backup selected | Candidate audits, textbook alignment, source-rights checks |
| First frozen slice | At least one reviewed StatementContractV1 revision frozen | Synthetic/golden mutation harness and conversion templates |
| Frozen-to-verified result | One unchanged bundle proves or gaps through independent verification | Prover fixture hardening and Dashboard projection |
| Library substrate | Image-owned declaration/type/dependency query bound to contract/gateway | Host-side diagnostics and API design notes |
| Release decision | RC or no-RC with named blockers | Long-range roadmap and downstream workspace standards |

## Layer 0: North star

Mission: make sustained progress toward Open Problems by building the missing formal dependency
substrate.

Milestones:

1. Portfolio map: choose target conjecture clusters by dependency leverage.
2. Builder pipeline: turn trusted sources into faithful, reviewed formal statements.
3. Prover engine: discharge frozen statements or return useful gaps at scale.
4. Library record: maintain an independent downstream formal-work tree with upstream-ready review
   surfaces.
5. Conjecture track: isolate open conjectures until semantic, axiom, reproduction, and expert
   reviews pass.

Stop condition: if any layer starts optimizing for benchmark success while bypassing statement
fidelity, freeze, or clean verification, pause that layer and return to the contract boundary.

## Layer 1: 2-3 year portfolio

### P2-M1. Dependency leverage atlas

Tasks:

- Build a graph of open-problem families, textbook prerequisites, mathlib coverage, active upstream
  efforts, and expert availability.
- Score nodes by leverage: number of downstream conjectures unlocked, missing-definition density,
  proof expectedness, source clarity, and formalization overlap.
- Keep conjecture nodes quarantined from theorem nodes.

Evidence:

- Versioned MathematicalGraph portfolio.
- Source/rights records for every candidate source.
- Overlap and duplication report against mathlib and active projects.

Stop condition:

- No source rights, active conflicting project, or too many missing foundations for a first pilot.

### P2-M2. Textbook-to-contract factory

Tasks:

- Select beginner-friendly, systematic, widely used textbooks for each candidate field.
- Start at chapter openings when calibrating notation and definitions; jump to middle nodes only
  when a specific Library blind spot is already isolated.
- During `local_calibration`, run normalize -> mathlib mapping -> independent candidates ->
  fidelity review, retaining candidate records without freezing them.
- In `production_ingestion`, freeze only statements that have passed the complete admission path.

Evidence:

- 50-100 reviewed statement candidates in `local_calibration`.
- Mutation gates for quantifiers, relation direction, missing side conditions, vacuity, and examples.
- Reverse-rendered statement packets and reviewer decisions.

Stop condition:

- Independent reviewers disagree on source meaning, or mutation tests admit a known wrong theorem.

### P2-M3. Prover scaling lane

Tasks:

- Run frozen bundles through direct/light/full Prover lanes with fixed budgets.
- Add specialist roles only as bounded ContextPack consumers.
- Compare models per role with role benchmark suites; do not merge roles into a single score.

Evidence:

- Verified proof submissions or GapReportV1 records.
- Cost/time/token reports by role and bundle.
- Reproducible pass@k and success@budget reports only on permitted benchmarks.

Stop condition:

- Provider egress is unauthorized, a model changes statement/imports, or verifier acceptance drifts.

### P2-M4. Downstream Library workspace

Tasks:

- Keep AutoLean work in Library or a sibling downstream repository with clear staging, promoted,
  and review folders.
- Store each theorem with contract revision, source span, proof dependency profile, axiom policy,
  and verifier receipt.
- Upstream to mathlib only when style, API stability, and maintainability are ready.

Evidence:

- Buildable downstream tree.
- Review checklist per file.
- Upstream-diff packet when appropriate.

Stop condition:

- Work cannot be independently reviewed without private caches, hidden prompts, or non-reproducible
  model output.

## Layer 2: Phase 2 first 4-6 weeks

Goal: public-metadata discovery followed, only where rights permit, by local calibration rather
than mass ingestion.

### P2-A. Select pilot lanes

Tasks:

- Maintain 2-3 lanes in parallel: current model-theory candidate or backup, one analysis/PDE/SDE
  route, and one geometry or metric/algebraic-geometry route.
- For each lane, produce a 20-40 node dependency sketch and identify the first five source-to-contract
  risks.
- Verify source rights and endpoint egress policy before any model-backed conversion.

Evidence:

- Lane cards with source, rights, mathlib overlap, dependency graph, review needs, and stop rules.
- Explicit GO/NO-GO decision.

Stop condition:

- No clear source rights, no review surface, or less than roughly 70 percent prerequisite coverage
  for the intended first slice.

### P2-B. Calibrate statement conversion

Tasks:

- After an explicit rights and local-use decision, convert 50-100 statements manually/with local
  agents in `local_calibration`.
- Include textbook opening definitions, early examples, and theorem statements before harder nodes.
- Use independent conversion candidates and adversarial checkers for every selected statement.
- Keep the resulting candidates non-frozen and out of Prover; external model egress remains off
  unless the source policy separately authorizes it.

Evidence:

- Calibration matrix: source span, normalized proposition, Lean statement, ambiguity notes, examples,
  mutation results, reviewer state.
- At least ten blocked or corrected cases retained as training signal for future agents.

Stop condition:

- Conversion disagreement remains unresolved for core definitions, or mutation tests repeatedly
  expose vacuous/over-strong/under-strong statements.

### P2-C. Bridge to Prover

Tasks:

- Enter `production_ingestion` only after all Phase 1 entry gates and the selected source rights
  are satisfied.
- Freeze only reviewed contracts.
- Route frozen bundles to Prover unchanged.
- Classify failures as proof gap, missing dependency, bad contract, bad import, or Library substrate
  issue.

Evidence:

- First pilot bundle set with verified proofs/gaps.
- Dashboard view linking Builder statement revisions, Prover attempts, gaps, and downstream files.

Stop condition:

- Prover needs to reinterpret source text or mutate statements to make progress.

## Layer 3: 3-6 month Builder pilot

Goal: produce a coherent chapter-scale formal asset, not a scattered benchmark score.

### B1. Chapter substrate

Tasks:

- Formalize a 20-40 node chapter slice with source-reviewed statement contracts.
- Separate definitions, reusable lemmas, local theorem bridges, and downstream-staging theorems.
- Keep examples and counterexamples as first-class tests.

Evidence:

- Buildable downstream tree.
- Contract bundle manifest.
- Review decisions and verifier receipts.

Stop condition:

- Dependency graph becomes mostly new foundations rather than the chosen pilot slice.

### B2. Prover throughput

Tasks:

- Run multiple frozen bundles with direct/light/full routing.
- Use role benchmarks to choose Prover/checker/allocator models per task type.
- Accumulate reusable gap patterns and successful proof tactics into experience retrieval.

Evidence:

- Success@budget by task class.
- Failure taxonomy trend.
- Reusable proof-pattern records with provenance.

Stop condition:

- Cost grows without reducing gap classes, or model ranking changes are not reproducible.

### B3. Feedback artifacts

Tasks:

- Produce one visible mathematical checkpoint each cycle: a compiled proof, a blocked wrong
  statement, or a reviewed gap that clarifies the next dependency.
- Keep reports short, hash-bound, and replayable.
- Prepare upstream issue/PR packets only after downstream stability.

Evidence:

- Monthly progress ledger.
- Dashboard snapshots.
- Downstream review packets.

Stop condition:

- Reports become narrative-only without reproducible artifacts.

## Layer 4: execution model

Root agent responsibilities:

- Maintain mission, milestone order, evidence definitions, and stop conditions.
- Assign narrow tasks to subagents with exact files, constraints, and test commands.
- Use separate validation subagents for non-trivial changes.
- Commit only coherent, verified increments.

Subagent task template:

    Role: <specific role>
    Scope: <files/dirs>
    Task: <one concrete deliverable>
    Do not: <authority/safety exclusions>
    Validation: <exact commands>
    Output: changed files, test results, unresolved risks

Recommended lane split:

| Lane | Model tier | Typical tasks |
| --- | --- | --- |
| Luna/Terra | low/medium | doc indexing, fixture inventory, CLI presets, UI polish, targeted tests |
| Terra | medium | benchmark harness increments, Dashboard projections, source manifest checks |
| Sol | high | contract boundary design, verifier/OCI semantics, Phase 2 field selection, proof-dependency gates |
| Root | high-level only | architecture decisions, task decomposition, final acceptance, release/stop decisions |

## Immediate next tasks

1. Close the Phase 1 vertical fixture gap: one frozen bundle through Prover verified/gap with retained
   rejection controls.
2. Add an authorized production evaluator and run the first preset-backed real-model role
   comparison without changing the frozen matrix, evaluator, or per-role reporting boundary.
3. Update Dashboard projection with real phase-feedback links for Builder observation, Prover attempts,
   and gaps.
4. Prepare two Phase 2 lane cards, but keep them discovery-only until Phase 1 freeze/verify closes.
5. Create a compact weekly progress ledger format: completed evidence, blocked gates, next task queue,
   operator asks.

## Operator asks

No API key is needed for the next dry-run and documentation work. Later, request only specific
operator-owned references:

- approved Codex/OpenAI or compatible endpoint;
- budget and timeout limits;
- source-egress permission class;
- reviewer availability for first contracts;
- repository visibility decision after public-readiness gates.
