# AutoLean Next Operating Plan

This note is the current root-agent control plan for continuing Phase 1 without losing sight of the
Open Problem north star. It is intentionally shorter than the full acceptance documents: it records
what should move next, what can run in parallel, and what must not be promoted prematurely.

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

### Phase 4: isolated open-problem portfolio

**M1. Leverage atlas.** Rank conjecture families by the verified dependency closure still missing,
source clarity, overlap with active work, and expert availability. Keep conjecture nodes separate
from theorem nodes.

**M2. Quarantined conjecture track.** Allow a conjecture only after the surrounding definitions and
lemmas have the same Builder/Prover evidence as theorem nodes. No agent may weaken it in response
to proof failure.

**M3. Research review.** Before describing progress toward an open problem, require independent
semantic review, strict axiom audit, clean reproduction, and domain-expert assessment of novelty.

**Phase exit.** There is no automatic "solved" label. A result is a research claim only after the
separate mathematical review process accepts the exact formal statement and proof context.

## Immediate work packages

| Package | Owner style | Next deliverable | Acceptance signal |
| --- | --- | --- | --- |
| T3 semantic/admission closure | Core/root plus human authority | Resolve the local review packet's pending spans and two locator ambiguities; decide the successor profile | An independently attributable decision remains a gap or admits one exact source/formal boundary; agents cannot self-admit it |
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

## First 1-2 week execution plan

1. Close the T3 human boundary before attempting a first frozen Builder statement.
   - The local check is intentionally fail-closed at `gap/not_selected/not_frozen`.
   - Resolve the machine-located spans and two locator ambiguities locally, then obtain a
     separately attributable semantic/admission decision.
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
   - Record “human review required” explicitly rather than blocking all mechanical preparation.

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

## Operator help to request later

No additional API key is needed for local preflight. Later requests should be specific:

- one Codex/OpenAI or compatible custom endpoint reference;
- total budget and per-attempt timeout;
- permission class for each source/benchmark group;
- human semantic review for the first statement contracts; and
- final decision on repository visibility after public-readiness checks pass.
