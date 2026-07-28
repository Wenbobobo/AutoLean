# Phase 1 Progress Ledger

Snapshot: 2026-07-25 baseline, with a 2026-07-27 to 2026-07-28 working-tree addendum below

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

## 2026-07-27 to 2026-07-28 working-tree addendum

This addendum records source and test surfaces present in the working tree after the historical
baseline above.  It is deliberately **not** a replacement baseline or release record: the tree is
not yet a clean, committed candidate, and none of these rows upgrades the Phase 1 decision from
`no-RC`.

| Surface | Current evidence | Boundary that remains |
| --- | --- | --- |
| ModelWork V2 | `ModelWorkBundleV2` separates non-theorem model work from statement contracts. Its typed source/rights bindings, derived identifiers and hashes, parent-admission revalidation, control-plane lease, fenced authorization, revocation, and reservation paths have focused local/adversarial coverage. | Local test HMAC and process-local approval objects are not an independently operated `MODEL_WORK_ADMISSION` authority or a lawful rights decision for external source material. |
| Machine semantic quorum | The deterministic sidecar rederives blinded review tasks and scoring from the contract, packet, reviewer set, and seed; enforces reviewer/failure-domain floors, critical mutation vetoes, controls, persistent dissent, and exact report verification; and exposes only `machine_advisory` with `may_freeze=false`. Focused implementation and independent attack tests passed locally. | It neither authenticates reviewer execution nor grants semantic admission, source rights, freeze authority, proof authority, or a replacement for P1-12 and `AUTH-T3-01`. |
| Model completion and authorized role V3 | The local completion path binds the exact private response CAS, authorization, reservation, actual usage/cost, settlement event, recovery handle, and public salted commitment. The V3 role bridge/evaluator fixes ten trials, authenticates its private run index, revalidates receipts, and reads one locally rehashed artifact snapshot. A 127-test completion/bridge/evaluator/canary set passed on 2026-07-28. | Local filesystem CAS and HMAC remain single-host/test-only. No paid-provider result, production KMS signer, external evaluator, role-floor score, or permission to expose source text follows. |
| Dependency Closure V2 Stage A | Canonical manifest/reference/artifact contracts and a two-phase pure blob materializer enforce a closed theorem inventory, dependency reachability, tree/environment binding, and no-reader-callback writes. Contract/materializer attack tests passed 40/40 on 2026-07-28. | Bundle V2, claim-scoped reads, OCI-observed declaration evidence, gateway binding, and any proof-acceptance path are intentionally absent. |
| Authorized ten-trial role bridge V2 compatibility | The retained V2 path derives ten canonical trials (two for each of five roles), completes pure suite validation before registration, binds its authenticated private run index and exact private usage, and exposes only keyed, non-addressable public commitments with no private handle. Its evaluator accepts strict exact JSON and recomputes trial and suite usage before issuing a role-separated, explicitly non-promotable report. | V2 is retained compatibility evidence, not the current completion-backed route. It is not a production evaluator, role-floor score, or source of authority to send protected source text to a provider. |
| FATE common executor | The executor distinguishes `regression-48`, `model-compare-90`, and `FATE-350`; locks source selection, excludes answers, preflights authorization before state mutation, and records deterministic attempt seeds for restart-safe projection. | No authorized model/Lean/verifier run is recorded. There is no pass@1, pass@4, cost, ranking, or theorem result. |
| Dashboard event projection | The read-only projection now keeps FATE attempts, generic verification, and T7 module receipt events in separate identities; collisions and orphan/mismatched FATE terminals are rejected. API/UI tests and the production build are local software evidence. | Controlled-browser visual QA could not run in this session, and remote authentication/operation remains unapproved. The panel is not a promotion authority. |
| T7 module receipt | The typed module-build contract binds the frozen specification job to its lease job, source tree, environment, process receipt, and declaration fanout; injected-runner attack coverage rejects a forged cross-job receipt. | No image-owned T6 module wrapper has executed it in OCI/Lean, and it has no gateway attestation, real-worker recovery result, or theorem-level kernel acceptance. |
| Process-chaos provenance | The V2 receipt/verifier and bounded retained-workspace tests bind synthetic recovery to a candidate identity, `uv.lock`, runtime, argv, child-state files, a read-only replayed SQLite schema/event/lease history, the terminal projection, and canonical cross-bound CAS artifacts. The complete 16-test focused file passed on a static working tree on 2026-07-28. | A historical local V1 1,000-job summary is not a retained V2 provenance receipt. No fresh V2 1,000-job run and independent replay has been recorded. |
| McKay opening alignment | The Builder alignment harness verified cached parent/derived-text provenance and emitted a redacted, source-bound opening-page observation with status `textbook_alignment_discovery_nonfreeze`. It did not guess a proposition from a weak extraction. | No statement was extracted, normalized, mapped to mathlib, frozen, handed to Prover, or semantically reviewed. Source text was not sent to a model. |
| DeepSeek official-profile canary and five-role runner | The bootstrap canary returned redacted `execution_refused/network`. The V2 five-role runner then completed credential-free `plan` and authorization-aware `preflight` for ten trials; its single permitted live attempt reached redacted `reconciliation_required/network` without a model response. Private state remained outside the checkout and public output exposed no private handle. | These are failure-path and orchestration observations, not capability, role-floor, cost, or benchmark results. They grant no promotion or source-egress authority, and no automatic retry is authorized. |
| Authority environment availability | This session's WSL invocation returned `Wsl/Service/E_ACCESSDENIED`; it therefore cannot create a fresh Docker/Lean receipt here. | This is a session-environment block, not evidence that the operator host cannot run Docker/WSL. A retained authority-environment replay is still required. |
| Historical local software gates | Earlier development-tree observations recorded 1,304 passed with 9 environment-specific skips and 2 repository-release tests deselected, followed by an index-aligned staged observation of 1,300 passed with 15 explicit cache/Linux/OCI/WSL skips. This ledger does not bind those counts to an exact retained report, so they remain historical observations rather than current-candidate evidence. | Local software gates never replace T3 semantic admission, T6/T7 authority execution, a real model result, or independent kernel acceptance. A new exact staged candidate must rerun and bind its own gates. |

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
| Builder canonical-type pre-freeze | Verified, local non-authoritative canary | Three fresh reference/candidate compile-seal-query observations against `autolean/mathlib-worker@sha256:3237192cf627a05367c75d46e61ec9034fefe43a4fd0c06139e38c80358648d6` agreed on exact printer text `∀ (n : Nat), @Eq.{1} Nat n n`; gate hash `5bcc9657c0ae5d1ef4b545bb1803e5f76aed09f942f284ecf960798ad389aa3f`; elapsed 94.7 s | The raw output was not retained as a committed artifact. Assurance is `local_oci_prefreeze`, `promotion_authority=false`, and `proof_or_axiom_admission=false`; this is not semantic fidelity, T3/T5 admission, proof verification, or release evidence. Normal freeze and registration still reject this assurance. |
| Public/private source boundary | Verified | Public source-backed contracts retain span IDs, locators, offsets, and typed hashes but no verbatim excerpt; exact text remains in the ignored source cache and private fidelity artifact; public-readiness rejects JSON with non-null `permitted_excerpt` | Not a forensic scanner and not protection from a hostile local administrator |
| Builder experience retrieval | Verified, synthetic | Content-addressed success/negative/gap records, rights/endpoint filters, deterministic ranking and budgets, poison-text rejection, and validated retrieval skill | Advisory context cannot satisfy a freeze gate |
| Builder--Prover closure | Verified, local test-only | A post-cutoff WSL pure-Lean exact-image canary ran `prepare -> fidelity -> freeze -> bridge -> register -> claim -> OCI compile/query -> independent gateway -> terminal acceptance` with `builder_unreviewed_bypass=false`. Builder fidelity digest `d08a743f264db53c7a5b7c8c27e8a7387796559e218426883a17ed056cbe3b57`; handoff hash `2a7600baddfe5a2335b38ebdec5ee08a18261a3e6d3045c9055303fdfbe654c7`; verifier evidence SHA `55d53a7e92839badba32c4ef4287dd4895cfcfdcad73488bd96dec1ca77b50f8`; source-preparation hash `312be270ddb575ce036a7b286199027a2995d867c3e31acd935d70d9911b685d`; image `autolean/lean-worker@sha256:9a85f190bfaaf5cc79418abe3cee46cf5456b9aaaa0c78df5d3c1e380ee419e5`. Earlier V1 source-backed evidence without the generation projection remains historical only and cannot authorize new registration or promotion. | The source and review identities are synthetic fixtures; execution is `test-only-local`, the result is `not_a_promotion`, and no production authority is established. |
| Event, lease, and artifact control plane | Verified, synthetic | SQLite WAL, command idempotency, fencing, append-only events, concurrent artifact create-if-absent, and immutable contract-revision projection | No power-loss or storage-device fault injection |
| OS-process recovery | Partial, synthetic | V2 receipt/verifier with bounded retained-workspace coverage; it rejects source/lock/argv/count/manifest drift, extra workspace files, and V1 summary substitution. A local V1 summary with report SHA `d80c2c0dbcbab22bfcbd0bea13f41e07c5f337a4a93d82203ef060e7765a2847` is historical diagnostic output, not provenance-bound evidence. | Fresh 1,000-job V2 receipt plus retained workspace and independent replay are absent; no Lean, OCI, network, model, physical power loss, or mid-transaction kill is exercised |
| Verifier evidence and signing gateway | Verified, local test-only | Lease/context/digest-bound request, evidence-artifact rehash and cross-binding, replay ledger, fail-closed outage, stale-fence rejection, and mandatory independently authenticated execution receipt before signing | Fixture HMAC proves the software boundary only; production mTLS/ACL and KMS/HSM custody are absent |
| FATE source boundary | Verified | FATE v4.28.0 root and three submodule commits; 350-task manifest hash `3187bac80d3aeb2dac8f5da878fe21580a4c11540a0c7db3c14a34c2e0bdc748` | FATE is a bounded Prover fixture, not the research north star, a pilot-selection oracle, or multi-file library evidence |
| `compile-canary-12` | Verified | Managed WSL runtime, Lean 4.28.0, mathlib `8f9d9cff6bd728b17a24e163c9402775d9e6a365`; M 3/3, H 3/3, X 6/6; report SHA `87208dfc6d30c485c5a1efa85113f14334d86dd0c8544a1f2ac463d3b7aa90aa` | Original files contain `sorry`; `proof_search=false` |
| `agent-smoke-8` | Verified, non-promotable | All eight fixed M cases attempted with one task-independent `aesop`; M-1 and M-3 compiled, type-queried, and passed the axiom policy; 2/8 total, no timeout; report SHA `c8c32f150562a9f4de9d6be84c812a6e7c6b760d624d43a1ad03b280144e5bb2` | No model Agent; mounted `.olean` tree is observed but not independently attested or image-built; no bundle/lease/signing request |
| Role benchmark V3 | Verified, fake-only | Ten oracle/mutant cells cover five roles and two cases per role with three repetitions, for 60 scripted trials. Strict matrix/readiness/evaluator commitments, private raw CAS, public aggregate, replay, and two byte-identical forward runs are recorded. Report file SHA `06766d98d82c6a5400765c60423d4b225ab0b12d314535e414d765ccbd414f13` | `provider_id=fake` and `exact_json_v1` exercise the harness only; this is not a model score or Lean/fidelity evidence |
| External benchmark readiness | Blocked before egress | Refuses execution on `execution_authorization_missing_v1`, `external_executor_unavailable_v1`, and `production_role_evaluator_missing_v1` | At the 2026-07-25 baseline, API credentials had not been requested; the later DeepSeek credential does not by itself satisfy execution authorization or evaluator custody |
| Project DAG | Verified, synthetic | Fixed 20-node multi-file frontier, conflict, propagation, API-change, and integration-lease fixture | Does not compile a real multi-file Lean library |
| Real Lean project-DAG preflight | Verified, byte-bound input; operator-local clean-build path | PR #18 adds a separate snapshot-first fixture: four Lean modules, twenty curated declaration nodes, byte-bound source/import/content graph, and a clean-build runner for the pinned local source-v2 image | No changed-source invalidation/rebuild, lease exercise, immutable bundle, per-node verifier, or T7 acceptance evidence |
| Providers | Verified offline | Fake, Codex CLI, OpenAI Responses, and custom-compatible adapters; authorization/egress controls, stable failure taxonomy, and persistent circuit breaker | No paid/external run; no prohibited provider path |
| OCI verifier | Verified, pure Lean test-only canary | Non-root exact image `autolean/lean-worker@sha256:9a85f190bfaaf5cc79418abe3cee46cf5456b9aaaa0c78df5d3c1e380ee419e5`; protocol V2 uses separate compile/query containers and binds both argv hashes plus the host-sealed `Candidate.olean` digest; statement replacement, wrong declaration/profile, stdout spoof, trusted-module shadow injection, persistent compile-time writer, and axiom attacks were rejected; an independent rerun produced an authenticated test-only execution receipt. Image-owned identity hash `81099458f107fc5a179e1d308b09ff0189424d8b4341dd47026cfbf01c3828e0`; current source-backed canary SHA `a83e703add32f9c896b3dbcd5f81982dabcfe5d036799a70cf5b5f9cd500a62e` | The image deliberately contains no mathlib; FATE's matching two-phase path was code-tested but not rerun; the receipt and gateway are fixture-only, `promotion_attestation_created=false`, and no production KMS/mTLS evidence exists |
| Mathlib source-built OCI profile | Verified, local test-only | All nine locked Git sources plus only the JS payload from the official ProofWidgets v0.0.87 release asset entered a fresh exact context; `--no-cache --pull=false --network=none` completed 889/889 targets for `+Mathlib.ModelTheory.Semantics:olean`. The exact source-v2 image is `autolean/mathlib-worker@sha256:3237192cf627a05367c75d46e61ec9034fefe43a4fd0c06139e38c80358648d6`; build evidence SHA `3c340227a423ff5440aa67c63023f02e1468577eac317df8e2db2200e3212d7f`; canonical receipt SHA `40e15776cec80a03b9d5b0affd59a3f613b7f1855c48aa0c1e91f24ec0e1eed7`; canary SHA `0931e138fdc4bf67374dc1a42978c92e49f786bece95fcf812c425fc7fd8ad0e`. Query artifact SHA `167d7a1ede245bfa631c46651b5eb0502d758b8d966d6f4c494fdcb2d75df42a` binds all 46 retained declarations and the 2,744-module transitive closure; 41 declarations have nonempty axiom sets, and `Deriv.closed_sound` uses exactly `Classical.choice`, `Quot.sound`, and `propext` | Local test-only technical evidence only: the image has no registry publication, production signer, KMS/mTLS authority, promotion attestation, or frozen-bundle/gateway run. The source-v2 image, implicit `Init` import, and observed axioms do not match the immutable V2 decision's source-v1 strict empty-axiom profile; no admission or RC follows |
| Ordinary proof-dependency spike | Verified, host-side executable | The Lean 4.28 query walks proof values and ordinary declaration types/values. Four committed fixtures replayed 4/4 against the exact source-v2 image: a structurally non-alias proof passed, while an exact-type known alias, a wrapper hiding a denied theorem, and a quotient dependency were exposed and rejected by their policies. The operator-local replay record binds one candidate snapshot, one helper snapshot, four query-output hashes, and aggregate output SHA `b216956433b32b4f3473889565cfe27e415564b2d768eb21650bd1acfa221116` | The helper is host-mounted and absent from the image receipt. The spike does not report canonical type hash, declaration kind, trusted module origin, or task mode; an unknown same-type alias can still pass if allowlisted. Contracts, OCI evidence, and the signing gateway do not bind or rerun it. It is not an admission gate or `independent_reproof` evidence |
| Target-free Library split preflight | Verified static boundary; unretained operator-local diagnostic | PR #20 creates separate staged source trees and profile-selected snapshots. Its optional source-v2 canary can mount only the selected profile view and use a host-mounted diagnostic to observe Candidate ownership, direct proof dependencies, canonical type, and axioms for independent and compositional candidates | The diagnostic JSON was not retained. No new image or content-addressed receipt, complete dependency closure, imported module-origin verification, exact-type collision gate, contract/gateway binding, or T6 result |
| Imported-declaration module-origin API note | Design note, not replayable evidence | PR #19 documents Lean 4.28's imported-only lookup: an imported `ConstantInfo` may resolve through `getModuleIdxFor?`; a declaration in the current `Candidate` normally yields `none`, so Candidate ownership remains a separate sealed-`ModuleData` check | The early ad hoc probe was not retained and is not evidence. The note supplies no image-owned helper, module-origin observation, collision check, or admission result |
| Dashboard | Verified, local projection/UI scope | Projection/API tests, UI tests, production build, display sanitization, stable three-lane graph layout, and task/gap/verification drill-down are implemented. The current event model keeps FATE, generic verification, and T7 receipt identities distinct. | Controlled-browser desktop/mobile QA was unavailable in the current session; remote mode remains unapproved and the panel is never a promotion authority. |
| Independent Library workspace | Verified, local diagnostic | Pinned Lean 4.28.0 and mathlib `8f9d9cff6bd728b17a24e163c9402775d9e6a365`; WSL/ext4 build of public root plus the three-node DAG fixture passed in 11.3 s | A local Lake build is not a Builder freeze, semantic review, OCI verification, or promotion |
| Target-free Library substrate | Operator-local image preflight verified | The exact source-v2 child build completed offline at Docker RepoDigest `autolean/library-substrate@sha256:bc336196592536658395ff0867f3008fc256dc6a3fd9098f414e118f18d5d1ef`, with raw receipt SHA-256 `f98010e0c4efb3a43a06bb7782507aa74e799e10822c0cecba890a858e8590df`. Its dedicated runtime tree contains three target-free Library `.olean` files, a receipt-bound inventory of 77 typed declarations and 22 separately validated IR auxiliaries, an image-owned sealed-Candidate query, and a narrow facade accepting the existing V2 argv/result shape. The independent/facade canaries preserve the historical target type/axioms, reject direct `Deriv.sound`, replay both inventories, establish Candidate/runtime kernel-plus-IR name disjointness, and recompute staged-source and final-OLean hash/size facts against receipt-bound checksum manifests. Facade negatives bind source hash, exact phase, return code, and reason: the two forbidden target-module imports fail compilation, while a wrong-type replacement compiles and is rejected by the rich sealed query | Local V2-compatible preflight only: no registry publication, production signer, frozen contract/environment revision, formal-asset admission, provider run, V2 OCI evidence, gateway receipt, or T6 result exists. The facade does not change contracts, control plane, or gateway. The query's Lean source is embedded in its hashed wrapper; only the three Library runtime source files are absent from the dedicated final substrate tree. Receipt replay is not a claim that separate Docker builds have identical image metadata or RepoDigest |
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
| 9--10 | Partial | V2 process-chaos provenance and bounded semantic retained-workspace replay tests, Windows/Linux CI, local OCI evidence, replayable fake reports, and the separate four-module/twenty-node real-Lean T7 input preflight | Run and independently replay a fresh V2 1,000-job receipt; bind the real fixture to changed-source rebuild, leases, immutable bundles, clean integration, and per-node verification; record authoritative Linux execution and the remaining real worker crash/restart cases instead of treating compatibility CI or the preflight as authority |
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

## 2026-07-26 execution batch

This is post-baseline working-tree evidence. It records implemented local increments and their
validation boundary; it does not revise the historical baseline or imply a Phase 1 release
candidate.

| Work item | Current result | Boundary still open |
| --- | --- | --- |
| `calibration-pairs-v3` role preset | Implemented as a five-role, oracle/mutant fake-provider preset. It tests role separation and evaluator wiring without secrets. | No external model or cross-model comparison has run; a fake result is not a model capability claim. |
| T3 local review check | Implemented as a fail-closed local check. Its only non-error disposition is the existing `gap/not_selected/not_frozen` state. | It cannot decide source fidelity, resolve the two pending locator ambiguities, or substitute for independently attributable semantic review and admission authority. |
| T6 Builder-only statement query | The query route, negative tests, and static checks are implemented. It is explicitly `proof_eligible=false`, so it cannot become a proof submission or acceptance path. | The current Codex sandbox cannot invoke the required OCI/Lean build and gateway replay; operator-host availability is not retained execution evidence. T6 is not complete until an admitted frozen contract is exercised through that exact environment and verification boundary. |
| T7 changed-source rebuild and module-receipt contract | The reviewed witness now seals every source byte in CAS and recomputes the plan and execution graph. A typed module spec binds the complete transitive source tree, direct-import receipts/OLean, toolchain/lake/image/config/platform/policy/query identities, then atomically commits one process receipt plus complete deterministic declaration fanout under a lease fence. Same-source reuse requires an earlier durable successful module receipt. The focused injected-runner/preflight suite is non-promotable. | No module ran in OCI through this new contract. T6 does not yet contain a receipt-bound T7 module build/query wrapper; the operator preflight therefore reports `module_execution_enabled=false`. Trusted gateway attestation, crash/restart with a real worker, clean integration, and theorem-level kernel acceptance remain open. Module success and fanout are explicitly ineligible for kernel acceptance. |
| Phase 2 pilot lanes | PDE and metric-geometry lane cards are available for public-metadata `discovery`, with node sketches, stop conditions, and conversion hazards. | They are not selected production pilots and do not authorize textbook ingestion, model egress, statement freezing, or Prover handoff. |
| Repository visibility | A public repository can distribute the code and documentation. | Visibility is not release readiness and cannot waive secret/history, remote-CI, semantic-fidelity, authoritative Lean/OCI, or promotion gates. |
| External-model access | The operator has supplied an experimental DeepSeek credential through an ignored local secret file. A credential-free profile and a non-promotable, authorization-complete bootstrap canary are implemented. | Network access from the current task remains blocked, so no live canary has succeeded. The static declaration is not an independent capability probe, and the canary is forbidden from role-floor admission or production promotion. |

## Current gated route

| Gate | State | What remains before the gate can close |
| --- | --- | --- |
| Local architecture baseline | Verified in the stated local/synthetic scopes | Retain the evidence boundaries; it does not close authoritative Lean/OCI, production authority, or semantic-fidelity gates |
| Pilot self-calibration | T3 gap, blocked | V2 records `gap/not_selected` and remains unchanged. Complete local review of the ten machine-located spans, resolve the Section 7.5 and universal-right (`∀R`) locator ambiguity, decide a successor formal profile consistent with the exact image/import/axiom observation, and close semantic-review and admission-authority checks. The two audited backups are not selected, so a different backup requires its own audit |
| Pinned Library selection spike | Partial passed with gap | The universal fragment is kernel-checked, but local replay does not select it or establish source fidelity |
| First calibrated contract slice (T5) | Blocked by T3 | A different backup may be audited, but no statement may freeze until one boundary is admitted with rights and review readiness |
| Target-free substrate and dependency gate (T6) | Builder-only query implemented locally; blocked by T5 and real integration | The focused route is `proof_eligible=false` and its local negative/static coverage does not create proof evidence. T6 still needs an admitted immutable contract/environment revision, real OCI/Lean execution, signing-gateway replay, adversarial integration rejections, and an accepted frozen-to-verified result |
| Real project-scale loop (T7) | Immutable source/witness/environment input, a typed module process receipt, durable same-source reuse, and atomic declaration fanout are implemented and tested with an injected fake runner; real execution is not admitted | The contract rejects fake/operator-local evidence at the kernel-acceptance boundary. It still needs an image-owned T6 module build/query wrapper, operator-local OCI replay, trusted gateway attestation, real-worker recovery, clean integration, and theorem-level kernel verification |
| Prover authority-path canary | Partially verified | One unchanged source-backed synthetic bundle passed the full local pure-Lean path through real OCI, an independent gateway rerun, and terminal acceptance. Preserve that contract while extending the same path to the exact mathlib profile and closing production-authority and full adversarial-suite gaps |
| Controlled model/benchmark evaluation | Authorized bootstrap and ten-trial role paths are implemented; one DeepSeek canary reached only a redacted network refusal | A network refusal is not a model result. Independent capability evidence, production admission/evaluator custody, a retained successful provider run, and the frozen role protocol are still required; the bootstrap canary cannot enter role-floor results, and no FATE result closes a Builder or Library gate |
| Release decision | Not run | Satisfy all mandatory gates and record failed, waived, and unrun items explicitly |

## External-action pointer

This ledger records the T3/T5 blocker facts below; it does not assign work. The exact machine
preparation and accountable exception decision are maintained only as `AUTH-T3-01` in
[operator-and-authority-worklist.md](operator-and-authority-worklist.md). Current execution order
is maintained only in [roadmap-next.md](roadmap-next.md).

## Pilot discovery

The historical first-order model-theory candidate is not the current Phase 2 primary. Its two
original candidates disagreed over a closed-only conservative formulation versus explicit
structural freshness and open-formula contexts. The current
`model-theory-closed-level-indexed-fragment` revision records the result as a V2 T3 gap: the `⊥`,
`→`, and `∀` micro-slice is kernel-checked, but remains `not_selected`. Local replay establishes
that the gap artifacts consistently bind the current manifest, workspace, source anchors, and
retained build evidence; it does not establish source fidelity or admission authority. The
current conditional discovery primary is the iFEM opening sequence; PDE and
metric/algebraic-geometry remain alternatives. The earlier read-only backup audit selected
neither the pointwise Cea graph nor van Kampen.

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

The observed T5 blockers are therefore the unresolved source locators, successor formal profile,
rights/egress revision, and absence of an admitted replacement for `not_selected`. They remain
facts until a new immutable decision is recorded. Failed selection, fidelity, semantic-review, or
rights checks retain the gap; they never weaken a theorem.

## Execution-order pointer

This facts ledger intentionally contains no current task ordering. The dependency-ordered 60-step
board is [roadmap-next.md](roadmap-next.md); every host, account, rights, signer,
semantic-exception, and release action is in
[operator-and-authority-worklist.md](operator-and-authority-worklist.md).

Repository visibility and the historical HF incident are separate decisions. Visibility may be
changed only after all remote refs intended for publication are fetched, reachable history is
reviewed, Git-host secret scanning is enabled or independently substituted, and the current
public-readiness, history-secret, provider, and remote-CI gates pass. The history audit found no
recovered archive, session, prompt, passphrase, or credential material in AutoLean's reachable
objects. Provider-side incident state and credential rotation remain open for incident closure and
future external-model authorization, but do not by themselves contaminate this independently
constructed source repository. Public source code never authorizes source-document, recovered
archive, raw model output, or credential publication.
