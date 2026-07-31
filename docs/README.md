# AutoLean Documentation

This directory is the engineering record for AutoLean Phase 1. The north star is
open-problem research, but Phase 1 is an architecture-validation program: a result is
not promoted merely because an agent produced Lean-looking text or because a benchmark
runner reports success.

## Document authority

| Authority | Canonical document | What it alone decides |
| --- | --- | --- |
| Stable specification | [Architecture](architecture.md), [protocol](protocol.md), [threat model](threat-model.md), and [Phase 1 acceptance](phase-1-acceptance.md) | Non-waivable system and acceptance invariants |
| Observed facts | [Phase 1 progress ledger](phase-1-progress.md) | Evidence actually observed, bound to its stated commit or candidate tree |
| Active execution | [Next operating plan](roadmap-next.md) | Current ordering, parallel waves, and task status |
| External authority | [Operator and authority worklist](operator-and-authority-worklist.md) and its [Chinese operational copy](operator-and-authority-worklist.zh-CN.md) | Human, host, rights, account, signer, and release actions; the English file is canonical |
| Long-range strategy | [Phase 2 fractal roadmap](phase-2-fractal-roadmap.md) | Phase 2 and later milestones and stop conditions |
| Historical decisions | [Archive index](archive/README.md) | Superseded plans and their safe-retention policy |
| Research input | [Research](research/) and [audits](audits/) | Evidence and proposals that cannot change a gate by themselves |

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
    comparisons before any paid or external model execution. The
    [DeepSeek five-role operator run](deepseek-role-operator.md) provides a non-promotable
    ten-call path with whole-suite preflight, private reconciliation, and an optional local
    exact-JSON evaluation API that is forbidden from role-floor admission. The separate
    [2026-07-29 role observation](research/deepseek-role-json-contract-calibration-2026-07-29.md)
    settled ten calls but saturated every fixed 256-token output ceiling, so it supports no
    competence conclusion. The separately versioned
    [DeepSeek output-budget ablation](deepseek-output-budget-ablation.md) repeats a fresh 256
    control with one bounded larger-output arm and reports only receipt-bound saturation, never a
    score or competence conclusion. Its first tracked
    [2026-07-29 run report](research/deepseek-output-budget-ablation-2026-07-29.json) stopped after
    one redacted `network` failure. A fresh
    [2026-07-30 rerun](research/deepseek-output-budget-ablation-2026-07-30.json) did the same and
    skipped the candidate arm. A third, separately rooted
    [settled run](research/deepseek-output-budget-ablation-2026-07-30-settled-a.json) completed all
    20 calls: saturation fell from 4/10 at 256 tokens to 1/10 at 512. A subsequent
    [strict V2 512-token scored observation](research/deepseek-live-baseline-2026-07-30-512-b-v2.json) settled
    ten calls and passed 2/10 exact-JSON cases, both task-allocation cases. These observations select
    a less-truncated local budget but remain non-promotable and support no general competence,
    billing, proof, or Builder-fidelity conclusion.
    The repository-owned [benchmark skill](../skills/run-autolean-benchmarks/SKILL.md) and its
    [2026-07-30 offline forward test](research/role-benchmark-skill-forward-test-2026-07-30.json)
    preserve the repeatable V3 workflow without turning fake results into model evidence.
11. [FATE compile canary](fate-compile-canary.md), the non-promotable
    [agent-smoke-8 vertical bridge](fate-agent-smoke.md), and the
    [process-chaos Harness](control-plane-process-chaos.md) define the current real-toolchain,
    proof-search, and recovery evidence.
12. [HF incident containment](hf-incident-containment.md) records the recovery boundary
   without including recovered data, archive names, prompts, sessions, or credentials.
13. [Phase 1 acceptance](phase-1-acceptance.md) defines the non-waivable gates,
    [the active execution board](roadmap-next.md) owns current sequencing, and
    [the progress ledger](phase-1-progress.md) records observed evidence and unrun gates.
    [The Phase 1 assurance case](phase-1-assurance-case.md) maps each current safety claim to
    its replayable evidence, non-claim, and remaining acceptance gate.
     [The operator and authority worklist](operator-and-authority-worklist.md) is the only active
     checklist for external actions; its [Chinese operational copy](operator-and-authority-worklist.zh-CN.md)
     is for project operation and does not create a second authority source. The old [route](phase-1-plan.md) and
    [parallel plan](phase-1-parallel-execution.md) are retained historical snapshots indexed in
    [the archive](archive/README.md).
    [The Phase 2 fractal roadmap](phase-2-fractal-roadmap.md) is the longer-horizon planning
    record for Open Problem portfolio work, Builder discovery, Prover scaling, and downstream
    Library staging.
14. [Builder domain pilot](domain-pilot-selection.md) records the conditional model-theory
    primary, curvature's reference-only boundary, backups, and selection gates. The
    [T3 human-review packet](../Builder/pilots/model-theory-admission/human-review/README.md)
    provides the reproducible reviewer view without claiming that review or admission occurred.
    The [T3 machine-review packet](model-theory-t3-machine-review.md) binds nine unresolved
    ambiguities, three mutation controls, and three unselected successor profiles; its construction
    is complete, but `AUTH-T3-01` remains open and it cannot admit, freeze, or hand off a statement.
15. [Multi-agent self-calibration](self-calibration-decision.md) defines the independent
    candidate, textbook/open-problem alignment, adversarial-review, and pinned-Library-spike
    decision loop that precedes manual Builder calibration. The
    [source-span synthetic self-calibration harness](builder-source-span-self-calibration.md) and
    [deterministic 5/3/3 held-out protocol](builder-held-out-calibration.md) exercise proposal,
    review, mutation, abstention, split, and replay structure over eleven project-synthetic samples.
    They are fake-provider architecture regressions, not real-model or semantic calibration.
    The [iFEM structural calibration](builder-ifem-structural-calibration.md) separately freezes a
    source-text-free risk registry plus a hash-pinned, tracked public graph/corpus runtime pair;
    both are evaluator metadata, not a textbook statement or model input.
    The [iFEM role calibration boundary](builder-ifem-role-calibration-v1.md) records the
    graph-bound witness recomputation, pair leakage closure, private partition roots, and exact
    outbound-byte contract. The [independent synthetic-role bridge](ifem-synthetic-role-bridge.md)
    now supplies exact-byte execution acknowledgements, private-input reconciliation, and an
    [operator-private output ledger](ifem-synthetic-role-private-ledger.md). All three remain
    non-promotable calibration evidence rather than benchmark or semantic authority. The
    [D32/D34 DeepSeek iFEM operator runner](ifem-deepseek-role-calibration.md) applies that exact
    private-ledger path to a live local observation only after explicit operator approval; its
    selected revision is bound to both the root pair and the
    [D33 public aggregate](ifem-private-evaluation-operator.md). It is likewise non-promotable and
    does not score, evaluate the oracle, or create Builder--Prover authority.
16. [Mathlib downstream workspace](mathlib-downstream.md) defines `Library/` as the independent
    formal-work record, review surface, and later upstream staging boundary.
17. [Target-free Library substrate](library-substrate-decision.md) separates the focused
     `library-substrate-v1` pilot profile from any future general Mathlib substrate, and defines
     independent versus compositional proof-dependency gates. The
     [image-owned substrate preflight](library-substrate-image-preflight.md) records the exact
    child build, typed/IR inventory, sealed-Candidate query, and V2-compatible preflight facade
    without a contract, gateway, or T6 claim.
    The
    [executable proof-dependency spike](proof-dependency-gate-spike.md) records a host-mounted
     source-v2 replay and the remaining image, type, origin, contract, and gateway blockers.
     The [Lean 4.28 module-origin API note](lean-module-origin-spike.md) records the imported
     declaration boundary and the narrow image-owned test a successor manifest must implement.
     The [Dependency Closure V2 design](dependency-closure-v2-design.md) records a locally tested,
     non-authoritative Stage A contract/materializer and implemented fail-closed Stage B mechanics:
     nonempty accepted dependencies remain rejected pending a gateway-owned
     `dependency.admitted` module/OLean binding.
18. [Lock-input SPDX SBOM](sbom.md) defines the deterministic, offline SPDX 2.3 generator and its
    deliberately narrow evidence boundary.
19. [Operations and release](operations-release.md) defines evidence collection and the conditions
    that block a release candidate.
20. [Continuous integration](ci.md) defines the offline Windows/Linux gate and separates its
    manual readiness preflight from authoritative Lean/OCI evidence.
21. [Public repository release](public-release.md) defines the tracked-tree, license, and
    restricted-payload checks required before changing GitHub visibility.
22. [Open questions](open-questions.md) preserves stable historical OQ identifiers.
    Actionable operator, host, rights, reviewer, signer, and release tasks live only in the
    [operator and authority worklist](operator-and-authority-worklist.md). The
    [operator live gate](operator-live-gate.md) documents the bounded host command.
23. [Formal-assistant landscape](research/formal-assistant-landscape-2026-07-24.md) records
    the local Archon-talk evidence, Danus/Reap audit boundaries, and the resulting isolated
    experiments without treating external performance claims as AutoLean results. The
    [meeting Archon takeaways](research/meeting_archon_takeaways.md) keep the newer talk snippets,
    adjacent assistant landscape, and Dashboard/context-pack lessons as advisory roadmap input.
    The [pinned Danus code audit](research/danus-code-audit-2026-07-28.md) accepts its
    fact-graph/context lessons only for a future untrusted research-scout layer and rejects its
    runtime, LLM truth gate, provider policy, and shared-file authority boundary.
    The [integration decision](research/danus-integration-decision-2026-07-29.md) and
    [proposal-only adapter and event projection](research/research-scout-adapter-v1.md) implement
    only that advisory boundary. The control plane appends digest-only ResearchScout events and the
    read-only Dashboard renders a short work record without creating a task or graph node; scout
    output cannot freeze a contract, mutate a graph, schedule work, or reach Prover authority.
24. [Backup pilot audit](research/backup-pilot-audit-2026-07-25.md) keeps a pointwise Cea
    comparison as the first read-only audit lead but records that it misses the size and coverage
    gates; van Kampen remains paused and neither candidate is selected.
25. [Domain pilot discovery gates](research/domain-pilot-discovery-2026-07-26.md) distinguish
    prerequisite-definition coverage from exact theorem reuse and record the SDE, PDE,
    Riemannian, and metric-algebraic-geometry source decisions without selecting a pilot.
26. [Phase 2 discovery lane cards](research/phase2-discovery-lane-cards-2026-07-26.md) propose
    transport-PDE and intrinsic-metric discovery routes with explicit rights, overlap, conversion,
    and stop gates; neither card authorizes source ingestion or a frozen contract.
    The [Phase 2 open-source selection](research/phase2-open-source-selection-2026-07-26.md)
    records iFEM as a conditional source-preparation and compile-discovery primary, not a selected
    production pilot. The [iFEM source-lock preparation](research/ifem-source-lock-preparation-2026-07-28.md)
    pins the bounded acquisition protocol, and the
    [2026-07-29 source-lock evidence](research/ifem-source-lock-evidence-2026-07-29.md) records the
    exact local hashes and replay while retaining `local_only`, no-freeze, and no-Prover bounds.
    The [digest-only notebook index](research/ifem-notebook-source-span-index-2026-07-29.md)
    records the 10-notebook / 161-cell locator replay without source text, while the
    [prerequisite census protocol](research/ifem-prerequisite-census-protocol-2026-07-29.md)
    binds the actual 25-node / 21-prerequisite denominator and keeps every mapping `unknown`
    until the pinned Lean query and semantic classification evidence exist. The
    [P2-08 readiness gate](research/ifem-pilot-readiness-gate-v1.md) makes the
    fixed 15--16/21 pilot hypothesis falsifiable without converting missing
    evidence into a negative decision or granting any promotion authority. The
    [25-node/49-edge candidate dependency graph](ifem-candidate-dependency-graph.md) is a
    source-text-free planning projection only; it creates no semantic mapping, FormalGraph,
    ExecutionGraph, freeze, or Prover handoff.
27. [iFEM fixed Mathlib profile query](ifem-pinned-mathlib-profiles.md) freezes five
    singleton-import observation profiles and a digest-bound OCI evidence path. Its plan and
    receipts record only environment facts; they cannot classify a prerequisite, decide coverage,
    freeze a Builder contract, or hand work to Prover. The 2026-07-31
    [public profile projection](research/ifem-pinned-mathlib-profile-public-summary-2026-07-31.json)
    binds the real run without canonical type text or closure members, and the corresponding
    [P2-08 v2 decision](research/ifem-pilot-readiness-decision-2026-07-31.json) remains
    `incomplete` with every promotion authority false.
28. [T7 real Lean project-DAG preflight](t7-real-lean-project-dag-preflight.md) binds a small,
    side-by-side 20-declaration Lean fixture to a content graph and records its deliberately
    non-acceptance local source-v2 clean-build boundary.
28. [T7 real Lean changed-source preflight](t7-real-lean-changed-source-preflight.md) binds one
    `Arithmetic.score` API change to separate declaration-invalidation and module-rebuild plans,
    then records the non-acceptance failure/rebuild/reuse boundary.
29. [T7 OCI module receipt and declaration fanout](t7-oci-module-build-receipt.md) defines one
    lease-fenced process receipt per module, atomic locked-query fanout, same-source receipt reuse,
    and the explicit non-promotion/non-kernel-acceptance boundary.
30. [Pre-T6 Builder query route](pre-t6-builder-query-route.md) chooses a Builder-only
    statement/type observation endpoint over fake proof-carriers, keeping the Prover V2 facade
    and public protocol unchanged.

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
