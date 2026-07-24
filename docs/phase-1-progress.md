# Phase 1 Progress Ledger

Snapshot: 2026-07-24

Decision: the local architecture has substantial adversarial evidence, but this branch is not a
Phase 1 release candidate. The remaining blockers are authoritative mathlib-in-image execution,
deployed authenticated Builder/verifier authorities, authorized external-model evaluation, fixed
regression/compare runs, the active model-theory quantifier/freshness gap, and later
human-calibrated Builder statements.

This ledger records observed evidence rather than estimated completion percentages. `Verified`
means the named check ran and its scope is stated. `Blocked` names a missing prerequisite.
Synthetic, fake, mounted-build, and local-HMAC evidence is never promoted by relabeling it.

## Current evidence

| Surface | Status | Recorded evidence | Boundary |
| --- | --- | --- | --- |
| Contract V1 and three graphs | Verified | Contract, hash, graph-separation, migration, and adversarial offline suites | Does not establish mathematical fidelity |
| Builder source-to-freeze path | Verified, local/synthetic | Official parent/text hashes, exact UTF-8 byte spans, append-only SQLite CAS preparation, two independent candidates, complete mutation suite, semantic/library review, and a real `prepare -> fidelity -> freeze` test | Reviewer and freezer IDs are unauthenticated strings; no production Builder signer |
| Public/private source boundary | Verified | Public source-backed contracts retain span IDs, locators, offsets, and typed hashes but no verbatim excerpt; exact text remains in the ignored source cache and private fidelity artifact; public-readiness rejects JSON with non-null `permitted_excerpt` | Not a forensic scanner and not protection from a hostile local administrator |
| Builder experience retrieval | Verified, synthetic | Content-addressed success/negative/gap records, rights/endpoint filters, deterministic ranking and budgets, poison-text rejection, and validated retrieval skill | Advisory context cannot satisfy a freeze gate |
| Builder--Prover closure | Verified, synthetic | Fidelity artifact through freeze, signed bridge, claim, gap/change request, new-revision re-review, fake proof, and synthetic acceptance | No Lean or OCI execution in this fixture |
| Event, lease, and artifact control plane | Verified, synthetic | SQLite WAL, command idempotency, fencing, append-only events, concurrent artifact create-if-absent, and immutable contract-revision projection | No power-loss or storage-device fault injection |
| OS-process recovery | Verified, synthetic | 1,000 jobs; 1,000 expired leases/stale-fence rejections; 4,000 duplicate-delivery replays; 5,000 contiguous events; 4,000 artifact checks; no loss or duplicate terminal verdict. Report SHA `d80c2c0dbcbab22bfcbd0bea13f41e07c5f337a4a93d82203ef060e7765a2847` | No Lean, OCI, network, model, physical power loss, or mid-transaction kill |
| Verifier evidence and signing gateway | Verified, local test-only | Lease/context/digest-bound request, evidence-artifact rehash and cross-binding, replay ledger, fail-closed outage, stale-fence rejection, and mandatory independently authenticated execution receipt before signing | Fixture HMAC proves the software boundary only; production mTLS/ACL and KMS/HSM custody are absent |
| FATE source boundary | Verified | FATE v4.28.0 root and three submodule commits; 350-task manifest hash `3187bac80d3aeb2dac8f5da878fe21580a4c11540a0c7db3c14a34c2e0bdc748` | FATE is a bounded Prover fixture, not the research north star, a pilot-selection oracle, or multi-file library evidence |
| `compile-canary-12` | Verified | Managed WSL runtime, Lean 4.28.0, mathlib `8f9d9cff6bd728b17a24e163c9402775d9e6a365`; M 3/3, H 3/3, X 6/6; report SHA `87208dfc6d30c485c5a1efa85113f14334d86dd0c8544a1f2ac463d3b7aa90aa` | Original files contain `sorry`; `proof_search=false` |
| `agent-smoke-8` | Verified, non-promotable | All eight fixed M cases attempted with one task-independent `aesop`; M-1 and M-3 compiled, type-queried, and passed the axiom policy; 2/8 total, no timeout; report SHA `c8c32f150562a9f4de9d6be84c812a6e7c6b760d624d43a1ad03b280144e5bb2` | No model Agent; mounted `.olean` tree is observed but not independently attested or image-built; no bundle/lease/signing request |
| Role benchmark V3 | Verified, fake-only | Five roles, three repetitions, strict matrix/readiness/evaluator commitments, private raw CAS, public aggregate, replay, and two byte-identical forward runs. Report file SHA `06766d98d82c6a5400765c60423d4b225ab0b12d314535e414d765ccbd414f13` | Scripted fake output is not a model score or Lean/fidelity evidence |
| External benchmark readiness | Blocked before egress | Refuses execution on `execution_authorization_missing_v1`, `external_executor_unavailable_v1`, and `production_role_evaluator_missing_v1` | API credentials are not yet requested |
| Project DAG | Verified, synthetic | Fixed 20-node multi-file frontier, conflict, propagation, API-change, and integration-lease fixture | Does not compile a real multi-file Lean library |
| Providers | Verified offline | Fake, Codex CLI, OpenAI Responses, and custom-compatible adapters; authorization/egress controls, stable failure taxonomy, and persistent circuit breaker | No paid/external run; no prohibited provider path |
| OCI verifier | Verified, pure Lean test-only canary | Non-root image `autolean/lean-worker@sha256:9a85f190bfaaf5cc79418abe3cee46cf5456b9aaaa0c78df5d3c1e380ee419e5`; protocol V2 uses separate compile/query containers and binds both argv hashes plus the host-sealed `Candidate.olean` digest; statement replacement, wrong declaration/profile, stdout spoof, trusted-module shadow injection, persistent compile-time writer, and axiom attacks were rejected; an independent rerun produced an authenticated test-only execution receipt. Image-owned identity hash `81099458f107fc5a179e1d308b09ff0189424d8b4341dd47026cfbf01c3828e0`; policy-V2 canary SHA `8aa49896f153b763d5887a88b7ee646f0842e72d61f8c0379442332e8eb324b2` | The image deliberately contains no mathlib; FATE's matching two-phase path was code-tested but not rerun; the receipt and gateway are fixture-only, `promotion_attestation_created=false`, and no production KMS/mTLS evidence exists |
| Mathlib source lock | Verified, source-input stage only | All nine Git dependencies in the pinned Lake manifest were acquired as source-only codeload archives, structurally validated, and rebound from the operator cache. The complete tracked lock SHA is `f9ef72acfebed52c6c7de1bacebe840fcd620568f7dc2875685771f363701448`; it binds Lake-manifest SHA `e2a93c904f51195d6740cd9abfb35ab155dc0157e0e46642dce0d364b68a9a89`, exact commits/URLs, and every archive SHA. Both lock-only and cache-byte verification passed after a real interrupted-download resume | No mathlib build or `.olean` provenance exists yet. The next gate must unpack only these locked inputs into a fresh Docker context, build the required import closure with network disabled and no host `.lake`, and rerun a real mathlib-importing OCI V2 canary |
| Dashboard | Verified, loopback | Projection/API tests, 15 UI tests, production build, controlled-browser desktop/mobile rendering, XSS/display sanitization, stable three-lane graph layout, and task/gap/verification drill-down | Remote mode remains unapproved; current JS bundle has a non-blocking 500 kB chunk warning |
| Independent Library workspace | Verified, local diagnostic | Pinned Lean 4.28.0 and mathlib `8f9d9cff6bd728b17a24e163c9402775d9e6a365`; WSL/ext4 build of public root plus the three-node DAG fixture passed in 11.3 s | A local Lake build is not a Builder freeze, semantic review, OCI verification, or promotion |
| Builder self-calibration and pilot selection | Partial, blocked | Both model-theory semantic adapters compiled in the pinned Library lock. The tracked receipt v2 and self-calibration record bind canonical build-input SHA `1bdc463299bc21d3836832c5c05755655d7450e9a3f91cef979e7c3c0aded795`, canonical report digest `9b9c75bd40d1ead093603f57f38b4c0d74ba317ca90ec63204125ca52f073769`, packet SHA `a94a45ec974d70888a327192ed9100351b87c90982be31681ed424ee9fb572c5`, receipt SHA `7d5867946a5ce3d0ff1472405fc572d0fcc1a2fe6e687bc01ad41c016dfc274f`, verifier SHA `7c6cf6ba9bed96d978238e27c0ab7bdd95464c7d1c6360da4f86df08e906ac29`, dependency-tree SHA `43f889366a4c5dc6daaed5b56cf3704e82e491ff90f2044602a187d7da2bfe62`, and dependency-manifest SHA `7f83b557c145abc56ec83619871c305f4bb6b5abff54b1d6fd52dd837c4f6423`; the packet state is `partial_passed_with_gap` and `not_selected` | The adapters and observed-cache binding establish local API compatibility and byte-level replay detection only, not trusted clean-build provenance. The Builder self-calibration round deliberately remains incomplete/gap; quantifier/eigenvariable freshness, capture avoidance, weakening, source interpretation, and independent review remain open. No candidate is selected, frozen, handed to Prover, or promoted |
| Builder reference cache | Verified offline | Four locked source/derived records, including locally extracted Open Logic Project *Sets, Logic, Computation*: source PDF SHA `39081a7e3cade6b9d6935e15448fd14279b44708c1a8da2abd30ff817c4a35d9`, extracted text SHA `285655b3e8937e37215bb51b69eff6eb10cd9a5d64c54d8f1f4ddfb5175fc584`, manifest SHA `9f6fc30c5bac7d3625938d6b4dae166270ef0f34c21db603be12c86d5bfd42ab` | Retained only as local reference/provenance material; no human-calibrated pilot statement is recorded and model egress remains forbidden |
| HF recovery boundary | Partially closed by operator confirmation | Operator confirmed deletion of the HF archive; no archive material is a migration source | This does not independently prove provider-side access state, credential rotation, or incident closure |
| Local and remote CI, inventory, and SBOM | Verified in the recorded scope | The staged source-lock/publication increment passed 570 Python and policy tests locally, with two documented Windows skips; current-tree and reachable-history scans, source-lock, inventory, and SPDX checks passed. Draft PR baseline head `76d2092` passed Ubuntu/Windows Python+policy and UI in [run 30082181435](https://github.com/Wenbobobo/AutoLean/actions/runs/30082181435) | The staged increment still requires its own remote run. GitHub Actions is compatibility and policy evidence, not the missing authoritative mathlib-in-image verifier |

## Current gated route

| Gate | State | What remains before the gate can close |
| --- | --- | --- |
| Local architecture baseline | Verified in the stated local/synthetic scopes | Retain the evidence boundaries; it does not close authoritative Lean/OCI, production authority, or semantic-fidelity gates |
| Pilot self-calibration | Partial, blocked | Reconcile the retained partial-pass spike with source-interpreter, research-alignment, Library-steward, source-entry, Mathlib-census, and later human-review records; agreement is never a freeze |
| Pinned Library selection spike | Partial passed with gap | Both adapter modules compiled under the committed lock, but implement and review the calculus-level quantifier/eigenvariable freshness bridge before selecting either boundary |
| Manual Builder calibration | Deferred | Begin only after candidate selection, rights readiness, and domain review; retain normal fidelity/non-vacuity evidence |
| Authoritative Prover path | Partially verified | Build mathlib and verifier helper inside one pinned image, then retain immutable bundle, lease, evidence, and signing observations |
| Controlled model/benchmark evaluation | Blocked before egress | Obtain operator authorization, then run fixed suites and ablations as secondary diagnostics; no FATE result closes a Builder or Library gate |
| Release decision | Not run | Satisfy all mandatory gates and record failed, waived, and unrun items explicitly |

## Pilot discovery

The conditional primary is first-order model-theory sequent-calculus soundness. Two independent
candidates disagree over a closed-only conservative formulation versus explicit structural
freshness and open-formula contexts. Both semantic adapters now compile in the pinned independent
`Library/` project, but their retained packet is deliberately `partial_passed_with_gap`: it does
not represent a calculus, a soundness theorem, a textbook-faithful statement, or a selection. The
selection authority remains the resolved quantifier/freshness bridge and its independent review,
not a model preference or a benchmark score. The backups are an abstract Cea-type variational-PDE
bound and a van Kampen-style topology slice.

Two later independent automated research inputs have refined the gap without closing it. The
textbook target is a closed, two-sided classical `LK` sequent, while substitution and eigenvariable
freshness still require an internal open layer. The next spike therefore uses level-indexed
`Formula (Fin n)` sequents internally and exposes soundness only through an explicit `n = 0`
sentence bridge. This reconciliation rejects both original candidates as sufficient in their
current form; it is neither a selected replacement nor a human semantic review.

Curvature is reference only: mathlib [PR #36036](https://github.com/leanprover-community/mathlib4/pull/36036)
is an active, open connection/geodesics work-in-progress that includes curvature. No curvature
mapping, source-to-contract calibration, or upstream duplication is current work.

Before manual Builder calibration, the active work requires:

- independent candidate, adversarial, textbook, and open-problem-alignment records;
- a pinned-Library compile spike that preserves the selected candidate's stated scope;
- a complete gap record if neither candidate compiles without a representation redesign; and
- an explicit rights decision before any non-local model egress.

Only after that selection may human source-to-contract calibration start. Failure of selection,
fidelity, expert, or rights gates creates a gap, pauses ingestion, or selects a backup; it never
weakens a theorem.

## Immediate execution order

1. Complete the multi-agent self-calibration records: source interpretation, research alignment,
   Library stewardship, source-entry review, and the bounded Mathlib API census.
2. Design and test a calculus-level quantifier/eigenvariable freshness bridge with capture
   avoidance and weakening. Retain its gap or review result; do not select a candidate merely
   because the two semantic adapters compile.
3. In parallel, build a source-clean, mathlib-containing OCI verifier image and repeat
   `agent-smoke-8` through bundle, lease, evidence artifact, and signing-gateway boundaries.
4. Implement the authorized online executor and production role evaluators. Request an
   operator-owned API secret reference only when readiness otherwise passes.
5. After selection and rights/domain readiness, begin expert-reviewed source-to-contract
   calibration; feed only frozen bundles to Prover.
6. Run fixed regression/comparison work as controlled secondary diagnostics, then deploy
   Builder/verifier authorities behind authenticated service boundaries before any result is
   called promotable.

Repository visibility and the historical HF incident are separate decisions. Visibility may be
changed only after all remote refs intended for publication are fetched, reachable history is
reviewed, Git-host secret scanning is enabled or independently substituted, and the current
public-readiness, history-secret, provider, and remote-CI gates pass. The history audit found no
recovered archive, session, prompt, passphrase, or credential material in AutoLean's reachable
objects. Provider-side incident state and credential rotation remain open for incident closure and
future external-model authorization, but do not by themselves contaminate this independently
constructed source repository. Public source code never authorizes source-document, recovered
archive, raw model output, or credential publication.
