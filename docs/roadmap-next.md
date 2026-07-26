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

The repository has a substantial Phase 1 skeleton: contracts, control-plane events, FATE adapters,
role benchmarks, read-only Dashboard projection, source/fidelity harnesses, OCI/Lean worker notes,
Library substrate experiments, and downstream Mathlib workspace documentation.

The remaining work is not to invent another runtime. It is to close a narrow vertical path in which
one admitted Builder statement moves through the exact same interfaces that future textbook and
Open Problem dependency nodes will use.

## Immediate work packages

| Package | Owner style | Next deliverable | Acceptance signal |
| --- | --- | --- | --- |
| Builder statement observation bridge | Core/root plus focused subagent | A Builder-only observation artifact that binds source hash, canonical type, environment, and contract revision without becoming proof evidence | Control plane and Builder tests reject promotion and Prover-submission misuse |
| Prover frozen-bundle vertical route | Core/root | One route from frozen bundle to verified proof or evidence-backed gap using immutable workspace and independent verification | Same theorem statement, source file, imports, and elaborated type remain unchanged |
| Role benchmark harness | Subagent | Repeatable dry-run/fake-provider matrix for specialist roles, with later API slots | Matrix is reproducible without secrets and separates roles from model claims |
| Dashboard grid view | Subagent | Read-only graph-health surface in the “power-grid health map” style | UI renders graph state without mutation endpoints or raw prompt/log exposure |
| Meeting/landscape research | Subagent | Extract Archon-talk and adjacent assistant lessons into scoped architecture proposals | Suggestions are mapped to existing gates instead of treated as benchmark proof |
| Library/Builder pilot discovery | Core/root with later reviewers | Pick 2-3 synchronized pilot threads only after source/rights and review constraints are explicit | Each candidate has a node graph, missing-library map, and clear rejection condition |

## First 1-2 week execution plan

1. Stabilize the Builder observation bridge.
   - Keep 'builder_statement_observation' internal to Builder/control-plane evidence.
   - It may help Prover prepare a bundle, but it may not satisfy 'submit_proof' or promotion gates.
   - Add negative tests for proof-like promotion, detached canonical type, and environment drift.

2. Close a small vertical fixture before broad benchmarks.
   - Use a synthetic or already-permitted Lean fixture with no source-egress issue.
   - Exercise 'claim -> submit_proof/report_gap -> verify_submission'.
   - Preserve exact statement and theorem type checks before accepting any proof.

3. Turn role benchmark work into a stable workflow.
   - Treat Prover, checker, allocator, formalizer, and contract-change reviewer as separate roles.
   - Run fake-provider/dry-run first; require operator API approval only once egress and budget are ready.
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
- Do not request API keys until the role harness can run with fake providers and source-egress
  permissions are clear.
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

No immediate API key is required for the next dry-run increment. Later requests should be specific:

- one Codex/OpenAI or compatible custom endpoint reference;
- total budget and per-attempt timeout;
- permission class for each source/benchmark group;
- human semantic review for the first statement contracts; and
- final decision on repository visibility after public-readiness checks pass.
