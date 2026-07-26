# Meeting Archon Takeaways for AutoLean

Status: research synthesis; no runtime adoption; no performance claim promoted
Date: 2026-07-26

Primary local sources:
- docs/meeting/chat.txt
- docs/meeting/share_file.pdf and docs/meeting/share_file_zh-CN.pdf
- docs/meeting/photo_1_2026-07-24_11-36-54.jpg through photo_6_2026-07-24_11-36-54.jpg
- docs/audits/archon-audit.md
- docs/research/formal-assistant-landscape-2026-07-24.md

## Conclusion

AutoLean should absorb three lessons from the Archon/meeting materials and reject one tempting shortcut.

1. Adopt capability-adaptive orchestration, but only as scheduling over frozen bundles.
2. Add structured context packs and graph/cone UI, but feed them from immutable artifacts and read models.
3. Treat proof-search systems such as Reap as isolated candidate generators behind the independent verifier.
4. Do not adopt Archon/Danus/MMAT/ReasFlow runtime authority, credential routing, or proof acceptance semantics.

The useful external pattern is not simply more agents. It is separated responsibilities plus replayable evidence. AutoLean already has the right hard boundary: Builder owns statement fidelity, Prover owns search, and verifier-owned clean builds decide acceptance.

## First principles

The core decision is whether outside systems change AutoLean's authority model or only its implementation queue. They should not change authority: a model-visible graph, an agent summary, a fact-memory node, or an MCTS trace is not a theorem statement, not semantic review, and not a kernel-verification receipt.

AutoLean's constraints are stricter than the reviewed systems: frozen statement contracts, immutable artifacts, isolated workers, provider/secret boundaries, clean verification, and semantic review. Any borrowed mechanism must therefore be recast as advisory scheduling, context construction, or candidate generation.

## Archon report: highest-value architecture points

### 1. Blueprint plus Lean DAG extraction

The Archon audit identifies Blueprint plus LeanDag workflow as valuable because it extracts Lean declarations, blueprint nodes, gaps, dependency cones, and cached project graphs. For AutoLean, this should become an optional extractor feeding typed graph records with provenance and review state, not a replacement for MathematicalGraph, FormalGraph, or ExecutionGraph.

Recommended absorption:
- Build or extend a read-only FormalGraph projection showing declaration nodes, dependency cones, gaps, source links, diff links, attempt history, and verifier status.
- Keep graph edges typed: mathematical dependency, Lean import/declaration dependency, and execution lease/attempt edge must remain distinct.
- Use graph visualization for human review and scheduler routing, never proof acceptance.

### 2. Role-specialized agents with bounded context

The Archon audit calls plan/prover/review/focused subagents a useful specialization pattern. The transfer is a task-type taxonomy, not shared mutable worktrees.

Recommended absorption:
- Encode Planner, Builder, Prover, and Reviewer as attempt roles over immutable bundles and ContextPack inputs.
- Give roles different context surfaces and budgets, but the same final verifier boundary.
- Require every role output to be patch, gap, or contract-change evidence; never silent source mutation.

### 3. Event normalization and read-only UI

Archon's event normalization and dashboard patterns are reusable as UI ideas: DAG/diff/timeline/journal, cone focus, status glyphs, historical browsing, and source links.

Recommended absorption:
- Implement EventEnvelopeV1/projections natively, independent of Archon's provider configuration and retention behavior.
- Dashboard reads projected events and approved artifacts only.
- Never serve live workspaces, raw prompts, arbitrary local files, host secrets, or mutable worker state through the UI.

### 4. Competing lanes and deterministic comparison

Archon's worktree/competing-lane idea matches AutoLean's need for parallel proof attempts, but the mechanism must be replaced.

Recommended absorption:
- Use OCI workers, immutable snapshots, leases, patch-only submissions, and verifier-owned acceptance.
- Compare attempts by frozen bundle hash, environment digest, policy hash, budget, attempt lineage, patch digest, and clean verifier result.
- Treat best-lane selection as a verifier/control-plane decision, not an agent self-report.

### 5. Frozen-signature intent

Archon's prompt-level frozen-signature concept aligns with AutoLean's statement contract goal, but enforcement must be stronger.

Recommended absorption:
- Implement only as contract revision hash plus elaborated-type hash plus import/axiom verification.
- Include mutation tests and semantic review before a new contract revision is admitted.
- A prover failure may emit a gap or contract-change request; it must never weaken the theorem.

## External systems from chat/blogs

Evidence classes: Local observation means meeting material or existing project audit; Primary public source means paper/blog/repository inspected but not reproduced; Author/institution claim means reported result not independently reproduced; Decision means AutoLean-native recommendation.

| System | Open-source status | Target/task | Performance or benchmark claim | What AutoLean should borrow | What AutoLean should reject |
| --- | --- | --- | --- | --- | --- |
| Archon / Archon2 | Public FrenzyMath materials say Archon is open-sourced; local audit pinned Archon v0.3.3 at 5e9ae7615efa0aa2cff11edabd5fbc0d45308fd5. | Research-level Lean formalization; structured task decomposition; LeanSearch-backed proof synthesis. | FrenzyMath reports research-level formal proofs and conjecture formalization costs; not reproduced here. | Blueprint/DAG extraction, role-specialized attempts, event/UI projection, competing lanes, frozen-signature intent. | Runtime authority, live checkout mutation, default danger-full-access, workspace credentials, dashboard trust, proof acceptance semantics. |
| Danus | Public arXiv record says Danus is open source at github.com/frenzymath/Danus; local landscape records pinned audit 7aad41077147af7b8f2a697512075bb326ade992. | Research-level mathematical reasoning with fact-graph memory, planner, workers, verifier. | Paper reports six research-level case studies; not reproduced here. | Tiered memory, construction/counterexample parallelism, cascade revocation. | Fact graph as acceptance authority, short IDs/provenance, LLM verifier as proof authority, unbound provider/runtime policy. |
| Reap / Reaper | FrenzyMath public materials identify Reap as a Lean tactic/project; local landscape records pinned audit 19dff902126427fd82c28e03fbc66f76b4157743. | Lean tactic/proof search; saved states; AND/OR MCTS-style search; RL/value-guidance candidate. | Existing local landscape records author-reported miniF2F numbers: 77.5% pass@32 and 80.3% accumulated across RL steps; not reproduced here. | Future isolated ReapSearchEngine adapter as a candidate generator under fixed budgets. | Search trace as verifier, default fallback before T6/T7, state-key trust, unisolated network/provider access. |
| MechMath / MMAT | Public paper and CAS report inspected; implementation repository/commit/license not verified in this pass. | Full-cycle mathematical research co-pilot; Control/Execution/Augmentation planes; Knowledge Base Manager, Natural Language Prover, Formal Language Prover. | Paper reports a deployment and solved-problem count; CAS report claims all six IMO 2026 problems with Lean 4.29.0/mathlib and dependency/axiom checks; not reproduced. | Responsibility-plane vocabulary; stronger knowledge/provenance manager; offline/no-web run discipline as experiment requirement. | Performance ranking, runtime adoption, unverifiable result promotion, new authority domains. |
| ReasLab / ReasFlow | Public arXiv record says ReasFlow is publicly accessible via ReasLab and gives a GitHub URL; source tree/license/commit were not audited. | Applied-mathematics discovery via knowledge-based multi-agent workflow, internal verification, knowledge/procedural heuristic retrieval. | Paper claims autonomous paper generation and comparative LLM-based review results; not comparable to Lean clean-build proof. | discovery_evidence records attached to MathematicalGraph nodes; retrieval of declarative facts and procedural experience with source/rights/evidence state. | A fourth authority graph, LLM review as proof certificate, merged status for claims/conjectures/theorems. |
| Quokka | Unresolved from chat alone. A current public Quokka referent is LLM-based invariant synthesis for program verification, not necessarily the intended formal-math system. | Program verification/invariant synthesis if that referent is intended; otherwise unknown. | Not evaluated here. | No roadmap work until disambiguated. | Do not spend implementation time on a name-only reference. |
| Qiyuan Xu thesis / AoA / Minilang | Local thesis PDF, not a repo adoption target. | Program verification, separation logic VCG, Isabelle/HOL, Minilang proof language, Agent over AST. | Thesis reports Minilang SFT improves PISA pass@1 by 20/29 percentage points versus Isar variants, and AoA experiments in its own language/context; not Lean-reproduced here. | Structural context packs: AST/hole IDs, stable declaration IDs, local proof-state snapshots, dependency translation discipline, failure taxonomy. | Migrating language/runtime, assuming Isabelle/Minilang results transfer to Lean, using thesis claims as AutoLean benchmark results. |

## 1-12 week roadmap recommendations

### Week 1-2: schema and projections, no routing promotion

- Add a CapabilityPathDecisionV0 read-only projection with direct, light, and full path labels.
- Inputs: bundle hash, declaration complexity, dependency frontier size, available context pack, role, budget, policy hash.
- Output: route recommendation plus reason; no automatic dispatch yet.
- Acceptance: projection can be replayed from event log and cannot alter contract/proof state.

### Week 2-3: Builder conversion taxonomy

- Register the conversion error taxonomy already sketched in docs/research/formal-assistant-landscape-2026-07-24.md.
- Add golden mutations for source locator, definition boundary, binder/scope, hypothesis/side condition, relation/conclusion, dependency/import leakage, and vacuity/witness failure.
- Acceptance: mutation results become evidence in GapReportV1 or ContractChangeRequestV1; no silent theorem weakening.

### Week 3-5: StructuralContextPack experiment

- Define StructuralContextPackV0 with declaration IDs, imports, allowed write set, local context/proof-state snapshots, stable hole/node IDs, source spans, and rights-scoped retrieval records.
- Run three arms over frozen, disjoint bundles: current text context, line/span context, structural context.
- Measure clean verifier acceptance, type-preservation, stale-location errors, tool calls, tokens, wall time, and rejected-submission reasons.
- Reject if it broadens imports, changes undeclared files, bypasses OCI, or improves proxy success while reducing clean verification.

### Week 4-6: read-only graph/cone UI

- Build a graph projection that displays formal dependency cones, gap nodes, source links, attempt history, and verifier status.
- Use event/artifact projections only; no live filesystem serving.
- This absorbs Archon's strongest UI lesson without its trust-model weaknesses.

### Week 5-8: competing-lane scheduler canary

- Create deterministic lane comparison for multiple Prover attempts on the same frozen task.
- Required comparison keys: bundle digest, environment digest, policy digest, budget, attempt lineage, patch digest, verifier result.
- Add adversarial cases: wrong target, changed statement, hidden import, network attempt, budget overrun, duplicate lane, stale lease.
- Acceptance: only verifier-owned merge/acceptance can change result state.

### Week 7-10: Reap-style fallback as sealed experiment only

- Specify SearchEngineAdapterV0 for candidate generators.
- Start with fake-policy canaries before integrating real Reap or any external tactic model.
- Candidate output: proof patch plus trace digest; no authority over Builder state, contracts, or acceptance.
- Admission gate: reproducible in two clean digest-pinned worker runs and positive paired effect on a preregistered workload without integrity regression.

### Week 8-12: discovery/provenance layer

- Add discovery_evidence records to MathematicalGraph nodes for literature claims, heuristic notes, counterexample searches, and procedural retrieval.
- Keep status separate: literature claim, model suggestion, conjecture, reviewed statement, Lean declaration, kernel-checked theorem.
- This borrows ReasFlow/MMAT knowledge-management framing without inventing a new authority graph.

## Counter-argument

A reasonable counter-position is: Reap/Danus/MMAT are moving fast; AutoLean should adopt a strong external runtime now and optimize proof success first. This holds if the goal is benchmark demos under loose authority, or if theorem statements are already trusted and failures are low-risk.

It does not hold for AutoLean's north star. AutoLean's hardest failure mode is not a failed proof attempt; it is a successful proof of the wrong or weakened statement. External systems can improve search while weakening provenance. Therefore the correct strategy is to import search/context/UI ideas only after they are made subordinate to frozen contracts and verifier-owned clean builds.

## Uncertainties and verification required

- Public performance claims for Archon, Danus, Reap, MMAT, and ReasFlow were not reproduced.
- MMAT/ReasFlow source releases, licenses, exact commits, checker outputs, and retained run artifacts were not audited.
- Quokka remains ambiguous unless the operator confirms the intended URL/author/logo.
- Thesis AoA/Minilang claims are Isabelle/Minilang-specific and cannot be assumed to transfer to Lean.
- Reap integration requires source-level API review at a pinned commit plus a no-network OCI canary.
- Any public benchmark comparison must use equal budget, equal environment, disjoint tasks, retained artifacts, and clean verification.

## Next steps

1. Keep this document as roadmap input, not an architecture decision by itself.
2. Update docs/phase-1-plan.md only after choosing which schema proposals enter T6/T7/M4.
3. Do not implement Reap/MMAT/ReasFlow adapters before the core frozen-to-verified path is stable.
4. Ask the operator to disambiguate Quokka with a URL/author/logo before further work.
5. If external source is later audited, pin commit, license, lockfile/environment, exact commands, and verification transcript before promoting any claim.
