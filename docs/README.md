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
3. [Builder fidelity Harness](builder-fidelity-harness.md) and the
   [Builder--Prover evidence closure](builder-prover-evidence-closure.md) define the semantic
   freeze gate and the artifact root handed to Prover.
4. [Elaborated-type comparator](elaborated-type-comparator.md) defines how a frozen Lean
   declaration type is queried from the pinned runner and compared without trusting a model.
5. [Pinned pure-Lean OCI worker](oci-lean-worker.md) records the real Linux image, replay command,
   adversarial canaries, and its deliberately non-mathlib evidence boundary.
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
11. [FATE compile canary](fate-compile-canary.md) and the
    [process-chaos Harness](control-plane-process-chaos.md) define the current real-toolchain and
    recovery evidence.
12. [HF incident containment](hf-incident-containment.md) records the recovery boundary
   without including recovered data, archive names, prompts, sessions, or credentials.
13. [Phase 1 acceptance](phase-1-acceptance.md) defines the 12-week route, while the
    [current progress ledger](phase-1-progress.md) records executed evidence and unrun gates.
14. [Builder domain pilot](domain-pilot-selection.md) records the proposed Riemannian-connections
    discovery graph, alternatives, rights boundary, and expert gates.
15. [Lock-input SPDX SBOM](sbom.md) defines the deterministic, offline SPDX 2.3 generator and its
   deliberately narrow evidence boundary.
16. [Operations and release](operations-release.md) defines evidence collection and the conditions
    that block a release candidate.
17. [Continuous integration](ci.md) defines the offline Windows/Linux gate and separates its
    manual readiness preflight from authoritative Lean/OCI evidence.
18. [Open questions](open-questions.md) records decisions that require an operator,
   mathematical reviewer, or project owner.

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
