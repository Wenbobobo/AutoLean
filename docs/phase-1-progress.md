# Phase 1 Progress Ledger

Snapshot: 2026-07-25

Baseline: `f8bf32915a3510a4d697bd09d4b11147078abd88` on `origin/main`, after merged PRs
[#11](https://github.com/Wenbobobo/AutoLean/pull/11),
[#12](https://github.com/Wenbobobo/AutoLean/pull/12),
[#13](https://github.com/Wenbobobo/AutoLean/pull/13),
[#14](https://github.com/Wenbobobo/AutoLean/pull/14), and
[#15](https://github.com/Wenbobobo/AutoLean/pull/15), through
[#20](https://github.com/Wenbobobo/AutoLean/pull/20).

Decision: the baseline has substantial offline, synthetic, and local test-only coverage, but is
not a Phase 1 release candidate. PR #11 adds a scripted-fake role calibration fixture, not a model
result. PR #12 records a target-free Library substrate design, not a built or admitted substrate.
PR #13 makes the pending T3 source review reproducible, but supplies no completed independent
review and no admission authority. PR #14 records that neither current backup qualifies. PR #15
adds a host-side ordinary-dependency query and exact source-v2 replay, not an image-owned
admission gate. Model-theory T3 therefore remains `gap/not_selected`, and T5 freeze remains
blocked. PR #18 adds a real-Lean T7 input preflight, not T7 acceptance. PR #19 records the
imported-declaration module-origin API boundary, not an executable probe; its early ad hoc probe
was not retained. PR #20 adds a
target-free split preflight, not a `library-substrate-v1` image or a T6 result. No real external
provider/model benchmark has run, and this baseline is not a Phase 1 release candidate.

This ledger records observed evidence rather than estimated completion percentages. `Verified`
means the named check ran and its scope is stated. `Blocked` names a missing prerequisite.
Synthetic, fake, mounted-build, and local-HMAC evidence is never promoted by relabeling it.

## Evidence classes

These labels are deliberately non-interchangeable:

| Evidence class | What it establishes | What it does not establish |
| --- | --- | --- |
| Green CI | The tracked checkout passed the named Windows/Linux unit, policy, and UI jobs | Semantic fidelity, a Lean proof in the authoritative worker, production authority, or model quality |
| Fake benchmark | Deterministic case selection, evaluator wiring, report commitments, replay, and failure detection against scripted outputs | Any capability of Codex, GPT, a custom endpoint, or any other real model |
| Host-side spike | A diagnostic algorithm or operator workflow can be exercised from the host checkout | An immutable image-owned implementation, gateway binding, admission gate, or promotion authority |
| Kernel compile | Lean elaborated the named declaration in the pinned toolchain; where stated, the queried type/axioms were also checked | That the formal statement faithfully represents its source, that imports are conceptually minimal, or that an authority admitted the result |
| Semantic or admission review | A separately attributable reviewer/authority accepted the bound source, formal profile, and decision record | A proof unless the unchanged contract also passes independent kernel verification |
| Real provider/model run | A named provider/model actually executed under a frozen prompt, tool, retrieval, budget, and evaluator contract | A proof, semantic fidelity, or fair cross-model comparison unless the corresponding independent gates also pass |

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
| Role benchmark V3 | Verified, fake-only | Ten oracle/mutant cells cover five roles and two cases per role with three repetitions, for 60 scripted trials. Strict matrix/readiness/evaluator commitments, private raw CAS, public aggregate, replay, and two byte-identical forward runs are recorded. Report file SHA `06766d98d82c6a5400765c60423d4b225ab0b12d314535e414d765ccbd414f13` | `provider_id=fake` and `exact_json_v1` exercise the harness only; this is not a model score or Lean/fidelity evidence |
| External benchmark readiness | Blocked before egress | Refuses execution on `execution_authorization_missing_v1`, `external_executor_unavailable_v1`, and `production_role_evaluator_missing_v1` | API credentials are not yet requested |
| Project DAG | Verified, synthetic | Fixed 20-node multi-file frontier, conflict, propagation, API-change, and integration-lease fixture | Does not compile a real multi-file Lean library |
| Real Lean project-DAG preflight | Verified, byte-bound input; operator-local clean-build path | PR #18 adds a separate snapshot-first fixture: four Lean modules, twenty curated declaration nodes, byte-bound source/import/content graph, and a clean-build runner for the pinned local source-v2 image | No changed-source invalidation/rebuild, lease exercise, immutable bundle, per-node verifier, or T7 acceptance evidence |
| Providers | Verified offline | Fake, Codex CLI, OpenAI Responses, and custom-compatible adapters; authorization/egress controls, stable failure taxonomy, and persistent circuit breaker | No paid/external run; no prohibited provider path |
| OCI verifier | Verified, pure Lean test-only canary | Non-root exact image `autolean/lean-worker@sha256:9a85f190bfaaf5cc79418abe3cee46cf5456b9aaaa0c78df5d3c1e380ee419e5`; protocol V2 uses separate compile/query containers and binds both argv hashes plus the host-sealed `Candidate.olean` digest; statement replacement, wrong declaration/profile, stdout spoof, trusted-module shadow injection, persistent compile-time writer, and axiom attacks were rejected; an independent rerun produced an authenticated test-only execution receipt. Image-owned identity hash `81099458f107fc5a179e1d308b09ff0189424d8b4341dd47026cfbf01c3828e0`; current source-backed canary SHA `a83e703add32f9c896b3dbcd5f81982dabcfe5d036799a70cf5b5f9cd500a62e` | The image deliberately contains no mathlib; FATE's matching two-phase path was code-tested but not rerun; the receipt and gateway are fixture-only, `promotion_attestation_created=false`, and no production KMS/mTLS evidence exists |
| Mathlib source-built OCI profile | Verified, local test-only | All nine locked Git sources plus only the JS payload from the official ProofWidgets v0.0.87 release asset entered a fresh exact context; `--no-cache --pull=false --network=none` completed 889/889 targets for `+Mathlib.ModelTheory.Semantics:olean`. The exact source-v2 image is `autolean/mathlib-worker@sha256:3237192cf627a05367c75d46e61ec9034fefe43a4fd0c06139e38c80358648d6`; build evidence SHA `3c340227a423ff5440aa67c63023f02e1468577eac317df8e2db2200e3212d7f`; canonical receipt SHA `40e15776cec80a03b9d5b0affd59a3f613b7f1855c48aa0c1e91f24ec0e1eed7`; canary SHA `0931e138fdc4bf67374dc1a42978c92e49f786bece95fcf812c425fc7fd8ad0e`. Query artifact SHA `167d7a1ede245bfa631c46651b5eb0502d758b8d966d6f4c494fdcb2d75df42a` binds all 46 retained declarations and the 2,744-module transitive closure; 41 declarations have nonempty axiom sets, and `Deriv.closed_sound` uses exactly `Classical.choice`, `Quot.sound`, and `propext` | Local test-only technical evidence only: the image has no registry publication, production signer, KMS/mTLS authority, promotion attestation, or frozen-bundle/gateway run. The source-v2 image, implicit `Init` import, and observed axioms do not match the immutable V2 decision's source-v1 strict empty-axiom profile; no admission or RC follows |
| Ordinary proof-dependency spike | Verified, host-side executable | The Lean 4.28 query walks proof values and ordinary declaration types/values. Four committed fixtures replayed 4/4 against the exact source-v2 image: a structurally non-alias proof passed, while an exact-type known alias, a wrapper hiding a denied theorem, and a quotient dependency were exposed and rejected by their policies. The operator-local replay record binds one candidate snapshot, one helper snapshot, four query-output hashes, and aggregate output SHA `b216956433b32b4f3473889565cfe27e415564b2d768eb21650bd1acfa221116` | The helper is host-mounted and absent from the image receipt. The spike does not report canonical type hash, declaration kind, trusted module origin, or task mode; an unknown same-type alias can still pass if allowlisted. Contracts, OCI evidence, and the signing gateway do not bind or rerun it. It is not an admission gate or `independent_reproof` evidence |
| Target-free Library split preflight | Verified static boundary; unretained operator-local diagnostic | PR #20 creates separate staged source trees and profile-selected snapshots. Its optional source-v2 canary can mount only the selected profile view and use a host-mounted diagnostic to observe Candidate ownership, direct proof dependencies, canonical type, and axioms for independent and compositional candidates | The diagnostic JSON was not retained. No new image or content-addressed receipt, complete dependency closure, imported module-origin verification, exact-type collision gate, contract/gateway binding, or T6 result |
| Imported-declaration module-origin API note | Design note, not replayable evidence | PR #19 documents Lean 4.28's imported-only lookup: an imported `ConstantInfo` may resolve through `getModuleIdxFor?`; a declaration in the current `Candidate` normally yields `none`, so Candidate ownership remains a separate sealed-`ModuleData` check | The early ad hoc probe was not retained and is not evidence. The note supplies no image-owned helper, module-origin observation, collision check, or admission result |
| Dashboard | Verified, loopback | Projection/API tests, 15 UI tests, production build, controlled-browser desktop/mobile rendering, XSS/display sanitization, stable three-lane graph layout, and task/gap/verification drill-down | Remote mode remains unapproved; current JS bundle has a non-blocking 500 kB chunk warning |
| Independent Library workspace | Verified, local diagnostic | Pinned Lean 4.28.0 and mathlib `8f9d9cff6bd728b17a24e163c9402775d9e6a365`; WSL/ext4 build of public root plus the three-node DAG fixture passed in 11.3 s | A local Lake build is not a Builder freeze, semantic review, OCI verification, or promotion |
| Target-free Library substrate | Operator-local image preflight verified | The exact source-v2 child build completed offline with Docker-recorded RepoDigest `autolean/library-substrate@sha256:5a71d357ce26e07a44bcce43dc26de06dd8470d2dda5f7341ffdfa2fe9e3dd2e`. Its dedicated runtime tree contains three target-free Library `.olean` files, a receipt-bound inventory of 77 typed declarations and 22 separately validated IR auxiliaries, and an image-owned sealed-Candidate query. The independent canary preserved the historical target type/axioms, rejected `Deriv.sound` as an ordinary dependency, replayed both inventories, and established Candidate/runtime kernel-plus-IR name disjointness. The fixed-digest verifier also recomputed each staged source and final `.olean` hash/size against the receipt-bound checksum manifests | Local preflight only: no registry publication, production signer, frozen contract/environment revision, formal-asset admission, provider run, V2 `OciLeanRunner` adapter/evidence, gateway receipt, or T6 result exists. The query's Lean source is embedded in its hashed wrapper; only the three Library runtime source files are absent from the dedicated final substrate tree. Receipt replay is not a claim that separate Docker builds have identical image metadata or RepoDigest |
| Builder self-calibration and pilot selection | T3 gap, `not_selected`; review tooling merged | The pinned Library packet includes the kernel-checked `UniversalLK` micro-slice for the classical two-sided `⊥`, `→`, and `∀` fragment: level-indexed formulas, capture-avoiding instantiation, eigenvariable-safe universal rules, local/global soundness, the level-zero sentence bridge, and retained Bool rejection controls. The immutable public-safe V2 decision records the gap; a digest-only attachment covers all nine fine-anchor requirements with ten machine-located spans, and a separate exact-image attachment binds the source-v2 query artifact, all 46 declaration types/axiom sets, and the 2,744-module closure without changing that decision. PR #13 adds a byte-bound, versioned human-review packet and reproducible page-rendering workflow for the two ambiguous page pairs | No independent reviewer response has been accepted. Every fine span remains `machine_located_pending_review`; generating or visually opening the packet is not semantic review. The source-v2 observation still conflicts with the old decision's image/import/strict empty-axiom profile and requires an explicit successor profile plus authenticated admission authority. The fragment has no existential constructors or sequent-level structural rules; it is not frozen or handed to Prover |
| Model-theory source egress | Enforced, source-specific `local_only` | The current reference manifest, source-rule matrix, and human-review packet all bind `model_egress_policy=local_only` | Exact textbook bytes or rendered pages may not be sent to an external provider or model-backed subagent. This is the current source record's rights/egress decision, not a missing Provider or Harness capability; changing it requires a reviewed manifest/rights revision |
| Builder reference cache | Verified offline | Five locked source/derived records. The manifest-v2 fifth record is the 437-page `pypdf 6.14.2` extraction of Open Logic Project *Sets, Logic, Computation*, text SHA `6184495568a4487848e747f25385cb4081be1cd87f77488c9de0046d600cfa6d`; manifest SHA `b947a08ef2455beb77d9481c4cbddc481ec6590f03746fd22affb03dd8b06f91` | Retained only as local reference/provenance material; no human-calibrated pilot statement is recorded and model egress remains forbidden |
| Backup pilot audit | Completed, read-only negative selection | The pointwise Cea lead has an 8-node mathematical graph: 2/8 nodes map directly under the strict count (25 percent), or 4/8 under the uncompiled optimistic-adapter count (50 percent), below both the 20-node floor and 70--80 percent reuse gate. van Kampen is paused for exact upstream overlap and source-rights blockers. Neither candidate is selected | This is desk/source/API inspection only: no source ingestion, rights decision, compile spike, semantic review, Builder admission, or Prover handoff occurred |
| HF recovery boundary | Partially closed by operator confirmation | Operator confirmed deletion of the HF archive; no archive material is a migration source | This does not independently prove provider-side access state, credential rotation, or incident closure |
| Local and remote CI, inventory, and SBOM | Verified at the current baseline | Historical baseline `3543b76` passed all four jobs in [run 30145353560](https://github.com/Wenbobobo/AutoLean/actions/runs/30145353560). Current baseline `f8bf329` passed all four Ubuntu and Windows Python/policy and Dashboard jobs in [run 30161312819](https://github.com/Wenbobobo/AutoLean/actions/runs/30161312819). Current-tree and reachable-history scans, source-lock, inventory, and SPDX checks remain part of the recorded gates | GitHub Actions is compatibility and policy evidence, not production verifier authority |

## Weeks 1--12: actual state

The week labels are acceptance buckets, not elapsed-time claims. `Closed in stated scope` means
the named code/document gate has evidence within its explicit boundary; it does not promote
downstream work.

| Weeks | Actual state at baseline | Evidence present | Missing minimum evidence |
| --- | --- | --- | --- |
| 1--2 | Closed in offline architecture scope | `uv` workspace and lock; Contract V1 records; separate mathematical/formal/execution graphs; threat model; pinned FATE lock/adapter; fake provider; documentation frame | Preserve these invariants while later real execution is added; no further Week 1--2 claim is needed |
| 3--4 | Partial | SQLite WAL/events, leases/fencing, content-addressed artifacts, immutable workspaces, pure-Lean OCI adversarial canary, compile-canary-12, non-promotable agent-smoke-8, source-backed local vertical tests, and a host-side ordinary-dependency spike with 4/4 source-v2 fixture replay | Exercise the fixed FATE smoke bundles through the same immutable OCI/query/evidence boundary. Move ordinary-dependency evidence into a new image/contract/gateway revision with type and origin bindings; production verifier authority remains separate |
| 5--6 | Partial | Offline Codex CLI/OpenAI Responses/custom-compatible adapters, capability/egress rejection, Archon adapter, specialist `ContextPack`, and synthetic 20-node DAG | Obtain explicit execution authorization and production role evaluators, then run registered `regression-48` pass@1. No such real-model run is recorded |
| 7--8 | Partial | Read-only loopback Dashboard, budget and durable circuit-breaker policy, failure taxonomy, and fake-only five-role calibration fixture | Run `model-compare-90` pass@1 and role/model/retrieval/specialist ablations under one frozen experiment contract; remote Dashboard access remains unapproved |
| 9--10 | Partial | Synthetic 1,000-job process recovery/replay evidence, Windows/Linux CI, local OCI evidence, replayable fake reports, and the separate four-module/twenty-node real-Lean T7 input preflight | Bind the real fixture to changed-source rebuild, leases, immutable bundles, clean integration, and per-node verification; record authoritative Linux execution and the remaining real worker crash/restart cases instead of treating compatibility CI or the preflight as authority |
| 11--12 | Not closed | SPDX SBOM, operations/release guide, protocol/interface documentation, audits, and explicit no-RC gates exist | Attempt FATE-350 pass@1 with separate M/H/X reports, review the registered paper-version subset, complete authorized production-authority evidence, and record an RC/no-RC decision. None of the benchmark/RC evidence is recorded |

## Recent merged evidence

All six rows are in the baseline. None establishes admission, freezes T5, completes T6 or T7, or
permits an RC.

| Work item at snapshot | Repository state | Permitted interpretation |
| --- | --- | --- |
| T3 human-review packet, PR #13 | Merged | Review preparation and reproducibility only. T3 remains `gap/not_selected`; no semantic or admission decision exists |
| Backup pilot audit, PR #14 | Merged | Read-only negative selection: pointwise Cea fails size/reuse gates, van Kampen is paused, and neither is selected |
| Proof-dependency closure spike, PR #15 | Merged | Executable host-side diagnostic with real 4/4 source-v2 fixture replay; not image-owned, contract-bound, gateway-enforced, or `independent_reproof` admission evidence |
| Real Lean T7 input preflight, PR #18 | Merged | Snapshot-first, byte-bound four-module/twenty-node content fixture with an optional local source-v2 clean build. It leaves changed-source rebuild, leases, bundles, per-node verification, and T7 acceptance open |
| Lean module-origin API note, PR #19 | Merged | Imported-only API design boundary. Current-`Candidate` `none` is expected and Candidate ownership is separately sealed-module based; the unretained early probe cannot support a claim |
| Target-free Library split preflight, PR #20 | Merged | Profile-bound staged split and unretained host-mounted direct-dependency/type/axiom diagnostic only. No image or content-addressed receipt, full closure, module-origin/collision gate, contract/gateway run, or T6 result |

## Current gated route

| Gate | State | What remains before the gate can close |
| --- | --- | --- |
| Local architecture baseline | Verified in the stated local/synthetic scopes | Retain the evidence boundaries; it does not close authoritative Lean/OCI, production authority, or semantic-fidelity gates |
| Pilot self-calibration | T3 gap, blocked | V2 records `gap/not_selected` and remains unchanged. Complete local review of the ten machine-located spans, resolve the Section 7.5 and universal-right (`∀R`) locator ambiguity, decide a successor formal profile consistent with the exact image/import/axiom observation, and close semantic-review and admission-authority checks. The two audited backups are not selected, so a different backup requires its own audit |
| Pinned Library selection spike | Partial passed with gap | The universal fragment is kernel-checked, but local replay does not select it or establish source fidelity |
| First calibrated contract slice (T5) | Blocked by T3 | A different backup may be audited, but no statement may freeze until one boundary is admitted with rights and review readiness |
| Target-free substrate and dependency gate (T6) | Image-owned preflight verified; blocked by T5 and integration | The focused child image now binds its parent/build/runtime receipts, complete typed and IR-owned declaration inventories, imported origins, collision checks, sealed Candidate ownership, and independent ordinary-dependency observation. T6 still needs an admitted immutable contract/environment revision, the V2 `OciLeanRunner` adapter and evidence, signing-gateway replay, adversarial integration rejections, and an accepted frozen-to-verified result |
| Real project-scale loop (T7) | Input preflight only | The synthetic scheduling fixture and real Lean content fixture are both retained, but acceptance still needs changed-source rebuild, lease/bundle flow, clean integration, and per-node verification evidence |
| Authoritative Prover path | Partially verified | One unchanged source-backed synthetic bundle passed the full local pure-Lean path through real OCI, an independent gateway rerun, and terminal acceptance. Preserve that contract while extending the same path to the exact mathlib profile and closing production-authority and full adversarial-suite gaps |
| Controlled model/benchmark evaluation | Blocked before egress | External execution authorization and production evaluators must exist before requesting an API secret. Once ready, fixed suites and ablations remain secondary diagnostics; no FATE result closes a Builder or Library gate |
| Release decision | Not run | Satisfy all mandatory gates and record failed, waived, and unrun items explicitly |

## Operator help required

The one current human action that can unlock T3 and therefore T5 is an independently attributable
review using the generated local review view:

1. decide all ten pending source spans;
2. resolve the two page-pair ambiguities; and
3. accept or reject a successor formal profile, including the observed import and axiom
   disposition.

Agent agreement is advisory and cannot act as this authority. Do not send the source pages to an
external provider or model-backed subagent: the current source record is `local_only`. No API
secret is requested now because external execution authorization, production role evaluators,
and applicable source-egress permission are not ready.

## Pilot discovery

The conditional primary is first-order model-theory sequent-calculus soundness. The two original
candidates disagreed over a closed-only conservative formulation versus explicit structural
freshness and open-formula contexts. The current `model-theory-closed-level-indexed-fragment`
revision records the result as a V2 T3 gap: the `⊥`, `→`, and `∀` micro-slice is kernel-checked,
but remains `not_selected`. Local replay establishes that the gap artifacts consistently bind the
current manifest, workspace, source anchors, and retained build evidence; it does not establish
source fidelity or admission authority. The read-only backup audit selected neither alternative:
the pointwise Cea graph has only 8 nodes and 25 percent strict or 50 percent optimistic reuse,
while van Kampen remains paused.

The technical spike uses level-indexed `Formula (Fin n)` sequents internally and exposes soundness
through an explicit `n = 0` sentence bridge. It implements only the `⊥`, `→`, and `∀` fragment and
retains capture/freshness rejection controls. Nine fine-anchor requirements now map to ten
machine-located spans, but none has visual or semantic acceptance; the Section 7.5 and
universal-right (`∀R`) page locators remain ambiguous. The exact source-v2 query now retains all
46 declaration types and axiom sets plus the 2,744-module closure. It also establishes that the
current candidate is incompatible with the immutable V2 decision's source-v1 image and strict
empty-axiom profile: 41 declarations have nonempty axiom sets, including all three of
`Classical.choice`, `Quot.sound`, and `propext` for `Deriv.closed_sound`. Exact source-rule
variants, the quantifier-encoding equivalence, a reviewed successor formal profile, independent
semantic review, and authenticated admission authority remain open. The V2 record is therefore a
durable reason not to freeze this candidate.

Curvature is reference only: mathlib [PR #36036](https://github.com/leanprover-community/mathlib4/pull/36036)
is an active, open connection/geodesics work-in-progress that includes curvature. No curvature
mapping, source-to-contract calibration, or upstream duplication is current work.

Before T5 can begin, the active work requires:

- visual and semantic review of all ten machine-located source spans, including reconciliation of
  the Section 7.5 and universal-right (`∀R`) page locators;
- an explicit successor formal profile resolving the source-v2 image, implicit `Init` import, and
  observed `Classical.choice`, `Quot.sound`, and `propext`, plus authenticated verification of any
  new admission decision;
- the retained pinned-Library receipt preserving its deliberately limited scope;
- an admitted candidate or a reviewed backup replacing the current `not_selected` state; and
- a reviewed source-manifest/rights revision before any non-local model egress; the current
  `local_only` decision remains binding.

Only after that selection may source-to-contract calibration start. A failed selection, fidelity,
semantic-review, or rights gate retains the gap, pauses ingestion, or selects a backup; it never
weakens a theorem.

## Immediate execution order

1. Treat the replayable T3 V2 decision as a blocking `gap/not_selected` record. Resolve its named
   evidence gaps locally. The two audited backups are not selected; a different backup would need
   a new read-only audit before any selection work.
2. Keep T5 blocked until one boundary is admitted. Further backup source/rule auditing may
   proceed, but no statement freeze or Prover bundle may be issued.
3. Preserve the completed source-backed pure-Lean vertical evidence and the exact source-v2 T4
   query attachment. PR #20's target-free split is a profile/snapshot and host-mounted diagnostic,
   while PR #19 is only an imported-origin API design note; neither changes the immutable V2
   decision. Build a new image-owned helper that binds canonical type, declaration kind, imported
   module origin, full closure, collision checks, task mode, contract evidence, and gateway replay.
   After T3 and T5 permit a frozen contract, rerun the unchanged bundle and rejected controls
   against the new substrate digest.
4. Keep the real Lean T7 fixture separate from the synthetic DAG: use it next for changed-source
   rebuild, bundle/lease flow, clean integration, and per-node verification rather than relabeling
   its source-v2 clean build as T7 acceptance.
5. Implement external execution authorization and production role evaluators. Request an
   operator-owned API secret reference only after those gates and the relevant source-egress
   policy are ready; no API is requested now.
6. After selection and rights/domain readiness, begin expert-reviewed source-to-contract
   calibration; feed only frozen bundles to Prover.
7. Run fixed regression/comparison work as controlled secondary diagnostics, then deploy
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
