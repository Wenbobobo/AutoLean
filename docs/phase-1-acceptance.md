# Phase 1: 12-Week Architecture Acceptance Plan

## Objective

The objective is to prove the architecture is correct enough to support future Builder work, not
to maximize a benchmark score. A result is acceptable only when its statement contract is frozen,
its proof is tied to that exact revision and environment, its verifier report passes every gate,
and its semantic review is recorded separately.

All milestones below are release gates, not claims of completed work. A passing FATE task is
proof-search evidence only; FATE is not AutoLean's research north star or a pilot-selection
mechanism. The 20-node project DAG fixture is the complementary evidence for multi-file,
dependency, and lease behavior. The active ordering of discovery work is maintained in
[the current operating plan](roadmap-next.md), which does not relax any acceptance gate here.

## Week-by-week route

| Weeks | Primary deliverable | Acceptance evidence |
| --- | --- | --- |
| 1--2 | uv workspace, contract V1, three graph models, threat model, FATE lock/adapter, fake provider, documentation frame | Contract schema and adversarial tests; immutable FATE lock verification; documented trust boundary |
| 3--4 | Event storage, artifact store, leases, immutable bundle, worker boundary, statement/verifier attack tests, canary/smoke vertical slice | SQLite WAL/CAS/idempotency/fencing tests; proof-slot and theorem-substitution attacks rejected; canary and smoke reports |
| 5--6 | Codex/OpenAI/custom-compatible providers, Archon concepts behind adapters, context packs, project DAG fixture, regression-48 pass@1 | No prohibited provider/fallback path; egress enforcement; recorded fixed-prompt/model/tool/retrieval/budget methodology |
| 7--8 | Read-only dashboard, budget/circuit-breaker policy, failure taxonomy, compare-90 pass@1, ablations | Projection contains no raw artifact contents; model/retrieval/specialist ablations reported separately |
| 9--10 | Crash/chaos/security tests, Windows path CI, Linux authoritative CI, compare-90 pass@4, replayable reports | 1,000-job restart/replay test; stale fence cannot submit; no duplicate acceptance; Linux clean build evidence |
| 11--12 | FATE-350 pass@1 attempt, paper-version subset review, SBOM, operations guide, API spec, audit report, release candidate | Separate M/H/X results; reproducible manifest/report; all mandatory safety gates pass or release is blocked |

## Fixed benchmark protocol

FATE is pinned by [benchmarks/fate.lock.json](../benchmarks/fate.lock.json) at FATE v4.28.0
and its three recorded submodule revisions. The adapter must operate from a verified clean
checkout and replace only the source-manifested proof slot. It must never use FATE-Eval's
statement checker, model layer, execution runtime, or answers; see [the FATE audit](audits/fate-audit.md).

Report M, H, and X separately. Do not merge them into one number.

| Suite | Fixed task selection | Purpose |
| --- | --- | --- |
| compile-canary-12 | M {3, 15, 134}; H {31, 51, 93}; X {11, 15, 62, 72, 77, 86} | Statement preservation, version migration, and pre-declaration checks |
| agent-smoke-8 | M {1, 3, 4, 7, 10, 40, 79, 150} | End-to-end flow only; never model ranking |
| regression-48 | 24 M, 12 H, 12 X | Fixed regression gate; separate from comparison data |
| model-compare-90 | 30 M, 30 H, 30 X, disjoint from regression | Controlled model comparison |
| FATE-350 | Full pinned suite, M/H/X reported separately | Late Phase 1 coverage attempt, not an architectural substitute |

All non-explicit selections use stable SHA-256 ordering, not task number. Model comparisons fix
prompt, tools, retrieval scope, attempt budget, timeout, environment, and answer-exclusion policy.
They report pass@1, pass@4, success@budget, elapsed time, tokens, and cost-to-proof. They may
not claim absence of training contamination.

Non-FATE specialist comparisons use the versioned
[role benchmark protocol](role-benchmark-protocol.md). Each role is reported separately, every
trial is bound to a frozen matrix cell plus a derived repetition seed, and repeated outcomes expose
instability. Capability readiness is probed before execution but grants no authority. Raw outputs
remain in a separate operator-private CAS while the aggregate report carries only their hashes. A
comparison with more than one changed dimension is labelled confounded rather than attributed to a
model, prompt, retrieval policy, tool set, budget, environment, or code change.
The pre-RC V3 wire format rejects populated V1/V2 stores rather than inventing missing evidence.

## Mandatory acceptance gates

### Statement and proof boundary

- Original file, declaration identity, theorem type, and pre-declarations remain unchanged.
- The fixed Lean/mathlib environment performs a clean build.
- sorryAx, sorry, admit, unapproved axioms, unapproved imports, and declaration replacement are
  rejected.
- Submissions bind stable contract ID, revision, contract hash, and environment hash.
- The verifier runs independently of the proof worker and records the result as an immutable
  artifact/event.
- Verifier authority signs only through the secret-free gateway contract. Its payload binds the
  exact live lease holder, fencing token and expiry; stale fence, substituted digest/context,
  expired request, replay and gateway outage all fail closed. Local HMAC proves tests only;
  promotion additionally requires isolated mTLS/ACL plus KMS/HSM deployment evidence.

### Builder semantic fidelity

- Golden tests inject swapped quantifiers, less-than versus less-than-or-equal, dropped
  nonempty/finite/Noetherian assumptions, parameter reversal, and vacuous hypotheses.
- Every injected incorrect contract is blocked before frozen.
- Freeze evidence includes reverse rendering, independent candidate(s), positive and negative
  examples, non-vacuity, mutation probes, and independent semantic signoff.
- L2 reusable APIs require library review; L3 research tasks require domain review; open
  conjectures stay in quarantine and require independent verifier review.

### Control plane and resilience

- The internal 20-node multi-file DAG fixture tests dependency frontier, concurrent writes,
  API-change propagation, and integration lease handling.
- At least 1,000 jobs cover **OS-process** kill/restart, duplicate delivery, expired lease, stale
  fencing token, and event replay. The bounded synthetic implementation is documented in
  [the process-chaos harness](control-plane-process-chaos.md). Required result: no task loss, no
  duplicate acceptance, and no stale-token submission. In-process service reconstruction is a
  regression test only and cannot close this gate.
- Artifact corruption, malformed event, and idempotency-key conflict paths are explicit failures,
  not best-effort recovery.

### Providers, workers, and panel

- Provider identity and configuration reject prohibited families and credential-bearing URLs.
- Every enabled endpoint has an immutable operator approval record, capability evidence,
  rights-egress policy, budget, revocation procedure, and an operator-authenticated authority
  boundary. A V1 approval snapshot alone is not evidence of an independent human approval.
- Every egressing model request is bound to the currently fenced worker lease and a
  content-addressed, role-scoped ContextPack. A stale worker or an arbitrary prompt must be
  rejected before endpoint I/O.
- Linux/WSL2 OCI execution is the authority: no network, immutable source/dependencies, and
  limited writable workspace. Windows support is compatibility coverage, not proof authority.
- The dashboard reads only event projections, binds to loopback by default, has no mutation API,
  and undergoes controlled-browser sanitizer/XSS, desktop/mobile rendering, authentication, and
  remote-access tests before any non-loopback use. API tests are not a substitute for those tests.

## Evidence package for a release candidate

The release candidate must contain:

- committed uv.lock, pinned benchmark/environment manifests, and a retained SPDX or CycloneDX
  SBOM;
- contract/protocol/API specifications and migration notes;
- reproducible benchmark and chaos reports with raw identifiers/hashes but no secrets or answers;
- source audits, dependency/license review, security tests, and operations/recovery runbooks;
- documented known limitations and open questions; and
- an explicit release decision that lists failed, waived, or unrun gates. A gate is never silently
  waived because a favorable FATE score exists.

Use the [operations and release runbook](operations-release.md) to generate the offline lock
inventory and collect the remaining evidence. A checkout without a verifiable source commit, or
without recorded pinned Lean/OCI execution, is blocked from RC status even when its Python tests
and inventory self-check pass.

## Phase 2 bridge

Phase 2 begins with a Builder discovery program, not mass ingestion. Its first step is
multi-agent self-calibration: independently align the candidate boundary with permitted textbook
interpretation and an open-problem dependency, adversarially review it, and choose between the
closed-only and structural/open-formula candidates through a pinned `Library/` compile spike.
Machine-first Builder calibration follows that selection; no fixed count, successful compile, or
agent agreement is claimed in advance. The current Phase 2 discovery primary is the opening
iFEM finite-element sequence. The earlier first-order model-theory route remains a historical T3
gap, while the PDE and metric/algebraic-geometry lanes remain conditional alternatives.

The first frozen pilot needs clear rights, accountable semantic admission, a scope that records
its mathematical boundary, non-vacuity tests, and no duplication of an active formalization
project. A machine quorum may prepare and challenge the admission packet, but may not manufacture
source intent or promotion authority. The independent `Library/` project holds the main formal-work
record and any later upstream staging; it does not replace the Builder source/contract ledger or
independent verifier.

Builder outputs frozen contracts and downstream-staging bundles only. Prover receives those same
standardized bundles; it does not reinterpret textbooks or repair statements. The open-problem
portfolio is prioritized by dependency leverage, while every conjecture remains isolated until
semantic review, strict axiom audit, clean reproduction, and independent expert review all pass.
