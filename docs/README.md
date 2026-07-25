# AutoLean Documentation

This directory is the engineering record for AutoLean Phase 1. The north star is
open-problem research, but Phase 1 is an architecture-validation program: a result is
not promoted merely because an agent produced Lean-looking text or because a benchmark
runner reports success.

## Reading order

1. [Architecture](architecture.md) defines the Builder--Prover authority split, the
   three graphs, and the contract lifecycle.
2. [Protocol](protocol.md) defines the only five commands that cross the Builder--Prover
   boundary and the immutable artifact rules behind them.
3. [Builder reference cache](builder-reference-cache.md),
   [Builder fidelity Harness](builder-fidelity-harness.md), and the
   [Builder--Prover evidence closure](builder-prover-evidence-closure.md) define the lawful
   source-to-contract entry, semantic freeze gate, and artifact root handed to Prover.
4. [Elaborated-type comparator](elaborated-type-comparator.md) defines how a frozen Lean
   declaration type is queried from the pinned runner and compared without trusting a model.
5. [Pinned Lean OCI workers](oci-lean-worker.md) records the pure-Lean adversarial profile and the
   separate test-only, source-built `Mathlib.ModelTheory.Semantics` profile with their distinct
   replay and evidence boundaries.
6. [Attestation trust root](attestation.md) defines separate Builder and verifier authority
   signatures, the lease-bound verifier gateway, replay semantics, and remaining mTLS/KMS gap.
7. [Threat model](threat-model.md) defines what agents, workers, providers, the control
   plane, and the read-only panel may trust.
8. [Builder experience retrieval](builder-experience-retrieval.md) defines deterministic,
   rights-scoped advisory context for statement-conversion specialists.
9. [Model provider policy](model-provider-policy.md) defines Codex, OpenAI Responses,
   and custom-compatible endpoint policy. Anthropic and Claude are intentionally excluded.
10. [Role benchmark protocol](role-benchmark-protocol.md) freezes repeatable specialist-role
   comparisons before any paid or external model execution.
11. [FATE compile canary](fate-compile-canary.md), the non-promotable
    [agent-smoke-8 vertical bridge](fate-agent-smoke.md), and the
    [process-chaos Harness](control-plane-process-chaos.md) define the current real-toolchain,
    proof-search, and recovery evidence.
12. [HF incident containment](hf-incident-containment.md) records the recovery boundary
   without including recovered data, archive names, prompts, sessions, or credentials.
13. [Phase 1 acceptance](phase-1-acceptance.md) defines the non-waivable gates,
    [the current route](phase-1-plan.md) resolves active sequencing,
    [the parallel execution plan](phase-1-parallel-execution.md) assigns work packages, and
    [the progress ledger](phase-1-progress.md) records observed evidence and unrun gates.
14. [Builder domain pilot](domain-pilot-selection.md) records the conditional model-theory
    primary, curvature's reference-only boundary, backups, and selection gates.
15. [Multi-agent self-calibration](self-calibration-decision.md) defines the independent
    candidate, textbook/open-problem alignment, adversarial-review, and pinned-Library-spike
    decision loop that precedes manual Builder calibration.
16. [Mathlib downstream workspace](mathlib-downstream.md) defines `Library/` as the independent
    formal-work record, review surface, and later upstream staging boundary.
17. [Target-free Library substrate](library-substrate-decision.md) separates the focused
    `library-substrate-v1` pilot profile from any future general Mathlib substrate, and defines
    independent versus compositional proof-dependency gates.
18. [Lock-input SPDX SBOM](sbom.md) defines the deterministic, offline SPDX 2.3 generator and its
    deliberately narrow evidence boundary.
19. [Operations and release](operations-release.md) defines evidence collection and the conditions
    that block a release candidate.
20. [Continuous integration](ci.md) defines the offline Windows/Linux gate and separates its
    manual readiness preflight from authoritative Lean/OCI evidence.
21. [Public repository release](public-release.md) defines the tracked-tree, license, and
    restricted-payload checks required before changing GitHub visibility.
22. [Open questions](open-questions.md) records decisions that require an operator,
    mathematical reviewer, or project owner.
23. [Formal-assistant landscape](research/formal-assistant-landscape-2026-07-24.md) records
    the local Archon-talk evidence, Danus/Reap audit boundaries, and the resulting isolated
    experiments without treating external performance claims as AutoLean results.
24. [Backup pilot audit](research/backup-pilot-audit-2026-07-25.md) keeps a pointwise Cea
    comparison as the first read-only audit lead but records that it misses the size and coverage
    gates; van Kampen remains paused and neither candidate is selected.

The source audits that informed these decisions live in [audits/](audits/):
[Archon](audits/archon-audit.md), [AutoArchon](audits/autoarchon-audit.md), and
[FATE/FATE-Eval](audits/fate-audit.md).

## Status vocabulary

- **Implemented** means a named source module exists in this checkout. It does not mean
  that the code has passed an end-to-end Lean, OCI, crash, or security test.
- **Required** is a release gate. It must be demonstrated by recorded evidence before
  the corresponding result can be accepted.
- **Planned** is deliberately not an implied capability. It appears in the acceptance
  route or open-question register so that it cannot be mistaken for a current guarantee.

No document in this directory is a proof certificate. The authoritative evidence for a
proof is a frozen statement contract, the matching proof submission, a clean-environment
verification report, and the associated immutable artifacts.
