# Phase 1 Progress Ledger

Snapshot: 2026-07-25

Decision: main baseline `faac4a3` plus this branch's local evidence has substantial adversarial
coverage, but is not a Phase 1 release candidate. Model-theory T3 now has a replayable V2 gap
record and nine requirements covered by ten machine-located spans, but remains `not_selected`;
T5 freeze is therefore blocked. Other remaining work includes visual and semantic review,
deployed Builder/verifier authorities, authorized external-model evaluation, fixed
regression/compare runs, and later calibrated Builder statements.

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
| Builder--Prover closure | Verified, local test-only | A synthetic source-backed statement passed the public Builder `prepare -> fidelity -> freeze -> bridge` path, register/claim, immutable workspace materialization, real pure-Lean exact-image OCI execution, independent gateway rerun, and terminal acceptance. Evidence SHA `a83e703add32f9c896b3dbcd5f81982dabcfe5d036799a70cf5b5f9cd500a62e`; handoff hash `770ad9dab1fabd15722aba6cdc938d2172de4fe7a9e166ff508aa219cbc71375`; source-preparation hash `312be270ddb575ce036a7b286199027a2995d867c3e31acd935d70d9911b685d` | The source and review identities are synthetic fixtures; execution is `test-only-local`, the result is `not_a_promotion`, and no production authority is established |
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
| OCI verifier | Verified, pure Lean test-only canary | Non-root exact image `autolean/lean-worker@sha256:9a85f190bfaaf5cc79418abe3cee46cf5456b9aaaa0c78df5d3c1e380ee419e5`; protocol V2 uses separate compile/query containers and binds both argv hashes plus the host-sealed `Candidate.olean` digest; statement replacement, wrong declaration/profile, stdout spoof, trusted-module shadow injection, persistent compile-time writer, and axiom attacks were rejected; an independent rerun produced an authenticated test-only execution receipt. Image-owned identity hash `81099458f107fc5a179e1d308b09ff0189424d8b4341dd47026cfbf01c3828e0`; current source-backed canary SHA `a83e703add32f9c896b3dbcd5f81982dabcfe5d036799a70cf5b5f9cd500a62e` | The image deliberately contains no mathlib; FATE's matching two-phase path was code-tested but not rerun; the receipt and gateway are fixture-only, `promotion_attestation_created=false`, and no production KMS/mTLS evidence exists |
| Mathlib source-built OCI profile | Verified, local test-only | All nine locked Git sources plus only the JS payload from the official ProofWidgets v0.0.87 release asset entered a fresh exact context; `--no-cache --pull=false --network=none` completed 889/889 targets for `+Mathlib.ModelTheory.Semantics:olean`. Image `autolean/mathlib-worker@sha256:83daaa542ee407c0fbb1ba93f2a0b40fde1621cc5ad2e689ab7d5392b76d03ff`; build evidence SHA `bd7576eb489c140704c691aadb80669ed462133b973848b4a49871c0cf5b4aab`; canonical receipt SHA `801959222c195e249e320a0568418d177022c8dbd925b70ad34ee28c0c2e2a90`; canary SHA `95505c212b7bf32b027766399322d3a4af96d2a30cf1b309a869d8f2f64971ce`. The canary observed `∀ (n : Nat), @Eq.{1} Nat n n`, zero axioms, and ignored an invalid `/deps` shadow | Local test-only evidence only: no registry, KMS/mTLS, production signer, promotion attestation, bundle/lease integration, full Mathlib build, FATE claim, or full rerun of the pure-worker adversarial V3 suite |
| Dashboard | Verified, loopback | Projection/API tests, 15 UI tests, production build, controlled-browser desktop/mobile rendering, XSS/display sanitization, stable three-lane graph layout, and task/gap/verification drill-down | Remote mode remains unapproved; current JS bundle has a non-blocking 500 kB chunk warning |
| Independent Library workspace | Verified, local diagnostic | Pinned Lean 4.28.0 and mathlib `8f9d9cff6bd728b17a24e163c9402775d9e6a365`; WSL/ext4 build of public root plus the three-node DAG fixture passed in 11.3 s | A local Lake build is not a Builder freeze, semantic review, OCI verification, or promotion |
| Builder self-calibration and pilot selection | T3 gap, `not_selected` | The pinned Library packet includes the kernel-checked `UniversalLK` micro-slice for the classical two-sided `⊥`, `→`, and `∀` fragment: level-indexed formulas, capture-avoiding instantiation, eigenvariable-safe universal rules, local/global soundness, the level-zero sentence bridge, and retained Bool rejection controls. The public-safe V2 decision and rule matrix bind the candidate, manifest/closure, four coarse source spans, compile packet/receipt, and local T4 profile. A separate digest-only attachment now covers all nine fine-anchor requirements with ten machine-located spans. Local replay confirms the bindings and that a gap decision cannot issue an admission receipt | Every fine span remains `machine_located_pending_review`; visual and semantic review is absent, and the Section 7.5 and universal-right (`∀R`) PDF/printed-page locators remain ambiguous. Declaration-specific type/axiom evidence and authenticated admission-authority verification are also missing. The fragment has no existential constructors or sequent-level structural rules; it is not frozen or handed to Prover |
| Builder reference cache | Verified offline | Five locked source/derived records. The manifest-v2 fifth record is the 437-page `pypdf 6.14.2` extraction of Open Logic Project *Sets, Logic, Computation*, text SHA `6184495568a4487848e747f25385cb4081be1cd87f77488c9de0046d600cfa6d`; manifest SHA `b947a08ef2455beb77d9481c4cbddc481ec6590f03746fd22affb03dd8b06f91` | Retained only as local reference/provenance material; no human-calibrated pilot statement is recorded and model egress remains forbidden |
| HF recovery boundary | Partially closed by operator confirmation | Operator confirmed deletion of the HF archive; no archive material is a migration source | This does not independently prove provider-side access state, credential rotation, or incident closure |
| Local and remote CI, inventory, and SBOM | Verified in the recorded main scope | Main baseline `faac4a3` passed all recorded Ubuntu and Windows workflow surfaces in [run 30140325921](https://github.com/Wenbobobo/AutoLean/actions/runs/30140325921); current-tree and reachable-history scans, source-lock, inventory, and SPDX checks remain part of the recorded gates | This branch's source-backed OCI evidence is local until its own remote run; GitHub Actions is compatibility and policy evidence, not production verifier authority |

## Current gated route

| Gate | State | What remains before the gate can close |
| --- | --- | --- |
| Local architecture baseline | Verified in the stated local/synthetic scopes | Retain the evidence boundaries; it does not close authoritative Lean/OCI, production authority, or semantic-fidelity gates |
| Pilot self-calibration | T3 gap, blocked | V2 records `gap/not_selected` and replays locally. Review the ten machine-located spans, resolve the Section 7.5 and universal-right (`∀R`) locator ambiguity, and close axiom, semantic-review, and admission-authority checks, or evaluate and record a backup |
| Pinned Library selection spike | Partial passed with gap | The universal fragment is kernel-checked, but local replay does not select it or establish source fidelity |
| First calibrated contract slice (T5) | Blocked by T3 | A backup may be evaluated now, but no model-theory statement may freeze until one boundary is admitted with rights and review readiness |
| Authoritative Prover path | Partially verified | One unchanged source-backed synthetic bundle passed the full local pure-Lean path through real OCI, an independent gateway rerun, and terminal acceptance. Preserve that contract while extending the same path to the exact mathlib profile and closing production-authority and full adversarial-suite gaps |
| Controlled model/benchmark evaluation | Blocked before egress | Obtain operator authorization, then run fixed suites and ablations as secondary diagnostics; no FATE result closes a Builder or Library gate |
| Release decision | Not run | Satisfy all mandatory gates and record failed, waived, and unrun items explicitly |

## Pilot discovery

The conditional primary is first-order model-theory sequent-calculus soundness. The two original
candidates disagreed over a closed-only conservative formulation versus explicit structural
freshness and open-formula contexts. The current `model-theory-closed-level-indexed-fragment`
revision records the result as a V2 T3 gap: the `⊥`, `→`, and `∀` micro-slice is kernel-checked,
but remains `not_selected`. Local replay establishes that the gap artifacts consistently bind the
current manifest, workspace, source anchors, and retained build evidence; it does not establish
source fidelity or admission authority. The backups remain an abstract Cea-type variational-PDE
bound and a van Kampen-style topology slice.

The technical spike uses level-indexed `Formula (Fin n)` sequents internally and exposes soundness
through an explicit `n = 0` sentence bridge. It implements only the `⊥`, `→`, and `∀` fragment and
retains capture/freshness rejection controls. Nine fine-anchor requirements now map to ten
machine-located spans, but none has visual or semantic acceptance; the Section 7.5 and
universal-right (`∀R`) page locators remain ambiguous. Exact source-rule variants, the
quantifier-encoding equivalence, declaration-specific axiom-query evidence, independent semantic
review, and authenticated admission authority remain open. The V2 record is therefore a durable
reason not to freeze this candidate.

Curvature is reference only: mathlib [PR #36036](https://github.com/leanprover-community/mathlib4/pull/36036)
is an active, open connection/geodesics work-in-progress that includes curvature. No curvature
mapping, source-to-contract calibration, or upstream duplication is current work.

Before T5 can begin, the active work requires:

- visual and semantic review of all ten machine-located source spans, including reconciliation of
  the Section 7.5 and universal-right (`∀R`) page locators;
- declaration-specific axiom evidence and authenticated verification of any admission decision;
- the retained pinned-Library receipt preserving its deliberately limited scope;
- an admitted candidate or a reviewed backup replacing the current `not_selected` state; and
- an explicit rights decision before any non-local model egress.

Only after that selection may source-to-contract calibration start. A failed selection, fidelity,
semantic-review, or rights gate retains the gap, pauses ingestion, or selects a backup; it never
weakens a theorem.

## Immediate execution order

1. Treat the replayable T3 V2 decision as a blocking `gap/not_selected` record. Resolve its named
   evidence gaps or evaluate the two backups and record which boundary, if any, can proceed.
2. Keep T5 blocked until one boundary is admitted. Backup source/rule evaluation may proceed, but
   no statement freeze or Prover bundle may be issued.
3. Preserve the completed source-backed pure-Lean vertical evidence. Separately complete the T4
   source-v2 draft and T6 against its exact digest: enumerate and bind the complete transitive
   import closure, then rerun the unchanged-bundle and rejected controls against that profile.
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
