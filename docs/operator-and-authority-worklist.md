# Operator and Authority Worklist

Status: active, canonical external-action register

Chinese operational copy: [operator-and-authority-worklist.zh-CN.md](operator-and-authority-worklist.zh-CN.md).
It is a faithful reader-oriented translation, not a second authority source.

Last cross-audit: 2026-07-31. The audit compared this file with every current `AUTH-*`
reference, the stable `OQ-*` register, the Phase 1 evidence ledger, the active roadmap, and the
Phase 2 roadmap. All eleven pre-existing `AUTH-*` identifiers are here. Two formerly implicit
decisions are now explicit: `AUTH-T5-01` (freeze one exact statement contract) and
`AUTH-DASHBOARD-REMOTE-01` (remote Dashboard access). No ordinary plan may keep a separate
operator checklist.

Latest remote fact, checked 2026-07-31: draft [PR #26](https://github.com/Wenbobobo/AutoLean/pull/26)
is open and `CLEAN` at `705f2c192865eae1dbe4151926f92ce61634fddc`; all four jobs in
[CI run 30612841190](https://github.com/Wenbobobo/AutoLean/actions/runs/30612841190) completed
successfully. The PR body separately records clean-stage local validation of 1,875 passes, 13
explicit skips, and zero failures. These are useful engineering records, not an RC, semantic
admission, signer deployment, provider authority, or mathematical result.

## What this file is for

AutoLean can write code, run deterministic checks, and use multiple blinded model roles. It cannot
silently obtain a license, decide that a Lean formula says the same thing as a textbook sentence,
prove a host action happened, control a provider's billing limit, or claim a new mathematical
result. This file is the one place where those remaining boundaries are visible.

An unchecked item blocks only the acceptance effect named in that item. It never blocks unrelated
offline implementation, discovery, fake tests, or quarantine work. Conversely, a green test,
model agreement, or self-authored report never checks an item by itself.

### Priority and support labels

Priority is based on the current critical path, not on personal importance.

| Priority | Count | Meaning now |
| --- | ---: | --- |
| P0 | 2 | Needed before the first real source can become a frozen Builder contract. |
| P1 | 2 | Needed before high-scale or fully closed public/security operation. Start in parallel. |
| P2 | 3 | Prepare now; execution becomes meaningful after a frozen contract exists. |
| P3 | 3 | Later Phase 1 exit or a dormant candidate; do not let it distract from P0. |
| P4 | 2 | Deferred product/research frontier decision. |
| Mechanical close | 1 | Deterministic evidence is sufficient; no human judgment is needed. |
| No human action now | 5 | Existing fail-closed policy or automated work is enough until its stated trigger occurs. |

`Human decision` means someone accountable must choose a scope or attest to meaning. `External
operation` means a separately controlled host, provider, or signer must perform and retain a
bounded action; it may be automated after setup. `No human action now` means agents should proceed
under the documented conservative default rather than wait for an unnecessary review.

## Immediate picture for a non-specialist

The shortest honest path is: decide how the iFEM source may be used, create one exact statement
contract, have its meaning checked, then run that unchanged contract in a separately controlled
Lean environment. A Lean proof only answers "does this formal sentence follow?"; it does not answer
"did we formalize the textbook correctly?" That is why rights and statement-fidelity gates occur
before Prover acceptance.

The current model-theory candidate is deliberately `gap/not_selected`. It is not the fastest path.
Keeping it as a negative fixture requires no mathematical expert; reviving it does.

## Engineering and operations

### [x] AUTH-IFEM-SOURCE-01 - retain the pinned iFEM opening bytes

- **Support type / priority:** mechanical close; no human review required.
- **Plain meaning:** keep an exact, repeatable copy of the selected introductory teaching material,
  so later work cannot accidentally refer to a changing web page.
- **Current state:** 13 selected files at iFEM commit
  `a4ab841c4e5ec726e9b7742c9dcb352cb9645736` were acquired and independently replayed as
  `local_only`. The receipt hash is
  `74eca6689fe69dcbf2f34ea524a99cacc2054c0a39cfecfb11887c29e13cf239`; details are in
  [the source-lock evidence](research/ifem-source-lock-evidence-2026-07-29.md).
- **Impact of this closure:** later local locator and prerequisite work has a stable input.
- **What remains blocked:** nothing is licensed for external model egress, no mathematical claim
  has been selected, and nothing may freeze or reach Prover. Those are separate items below.
- **Why no human is needed:** this is a byte-for-byte acquisition and hash replay, not a judgment
  about copyright or mathematics. The automated receipt supplies the required fact.
- **If the bytes change or a new source is added:** create a new source revision and rerun the
  deterministic lock; do not edit the old receipt.

### [ ] AUTH-T6-01 - bind a real frozen contract to the authority Lean/OCI and gateway path

- **Support type / priority:** external operation, P2; waiting on `AUTH-RIGHTS-01` and
  `AUTH-T5-01`.
- **Plain meaning:** run the exact frozen statement in a sealed Linux/Lean image and have a separate
  verifier service replay what happened. This prevents the proof-search worker from grading itself.
- **Current state:** the target-free Library substrate's local operator gate passed against
  `autolean/library-substrate@sha256:c28d05d12f8e5cbfba240a35987b33e1564c7cda72a2529ccf6255c28e5bf2a8`,
  but explicitly records `phase1_promotion_eligible=false`. It is preparation, not T6 authority.
- **Impact:** this is the first environment where an accepted proof could eventually be trusted as
  reproducible rather than merely a developer-machine result.
- **If incomplete:** a proof may be explored locally but cannot be accepted, published as verified,
  or used to close the Builder-to-Prover vertical.
- **Needed support:** once an admitted frozen bundle exists, an authority-host operator runs the
  bounded image command and a separately controlled verifier/gateway operator replays it. The two
  roles may automate their steps but must not share the proof worker's signing authority.
- **Close with:** image digest, immutable input/output hashes, gateway receipt, rejection controls,
  owner identities, and a statement that names the exact contract revision only.

### [ ] AUTH-T7-01 - retain a real leased multi-file run and recovery

- **Support type / priority:** external operation, P3; follows T6.
- **Plain meaning:** demonstrate that a project with many Lean files can survive a worker crash
  without accepting stale or duplicated results.
- **Current state:** typed source, lease/fence, process-receipt, fanout, and fake-runner rejection
  paths are tested. No image-owned multi-file run, independent recovery, or theorem-level verifier
  receipt exists.
- **Impact:** T7 is the bridge from a one-theorem demonstration to a maintainable mathematical
  library.
- **If incomplete:** local DAG tests remain useful, but no claim about project-scale worker
  recovery or changed-source propagation is justified.
- **Needed support:** later, a worker-farm operator runs a predeclared crash/recovery schedule and
  an independent verifier operator checks the final declarations. Do not run this before T5/T6;
  it would produce expensive non-promotable evidence.
- **Close with:** immutable source tree and environment, lease/fence event history, process and CAS
  roots, stale-fence rejection, clean integration build, and theorem-level verifier receipts.

### [ ] AUTH-SIGNER-01 - deploy an independent verifier trust root

- **Support type / priority:** external security operation, P2; deployment can be prepared now,
  but cannot promote anything before T5/T6.
- **Plain meaning:** the final approval key/service must be controlled separately from the agents
  that search for proofs, just as an examiner should not be the same person who writes the exam.
- **Current state:** protocol and local HMAC fixtures exist; they are deliberately test-only.
- **Impact:** separates "a worker says success" from "the verifier independently accepted it."
- **If incomplete:** no production admission or Phase 1 RC is honest, even if Lean checks pass on a
  development host.
- **Needed support:** security/verifier operator provisions mTLS/ACL isolation, a key owner,
  revocation/rotation procedure, and a proof that workers cannot call raw signing operations.
- **Close with:** deployment attestation, public key ID, policy hashes, isolation test, rotation
  drill, outage behavior, and named operational owner. Never put key material here.

### [ ] AUTH-PROVIDER-01 - retain one independently administered real-model experiment

- **Support type / priority:** external operation, P2; may run in parallel only on answer-free,
  rights-safe inputs.
- **Plain meaning:** show that a named model actually performed a fixed task under a fixed budget
  and evaluator, rather than confusing a local mock with model capability.
- **Current state:** one settled canary and a 20-call 256/512 output-budget observation are retained;
  saturation fell from 4/10 to 1/10. Two ten-call 512-token role observations each passed 2/10
  cases: 512a is a legacy V1 projection and 512b is the normative strict V2 envelope. A separate
  D35 iFEM role calibration settled 16 source-text-free synthetic cases at a 1,024-token ceiling;
  the local D33 evaluator reported 2 correct, 0 incorrect, 8 abstentions, and 6 invalid outputs.
  All records remain alias-unpinned, locally evaluated, public or lookup-recoverable, and
  non-promotable; no model ranking, capability floor, textbook fidelity, or provider-authority
  claim follows. See the [authorized canary record](deepseek-authorized-canary.md) and
  [D35 observation](research/ifem-deepseek-role-calibration-2026-07-31-1024-v3.md).
- **Impact:** enables trustworthy role and benchmark evidence, not Builder fidelity or proof
  acceptance.
- **If incomplete:** development may use fake providers and local observations, but cannot claim
  real-model performance, `regression-48`, `compare-90`, or FATE results.
- **Needed support:** an approved provider account/endpoint, frozen prompt/tool/retrieval contract,
  external evaluator administration, capability probe, no-retry policy, and source-egress check.
  The evaluator need not be a mathematician; it must be independently operated and reproducible.
- **Close with:** authorization/plan hashes, provider/model revision as far as available, settled
  usage, independent evaluator report, failure ledger, and redacted public commitment. Never store
  an API key or raw protected source text.

### [ ] AUTH-SPEND-01 - enforce an external hard-spend ceiling

- **Support type / priority:** operations decision, P1 before a large worker swarm.
- **Plain meaning:** client-side counters can notice overspending after a request; an account or
  proxy limit must stop spending before it exceeds the ceiling.
- **Current state:** reservations, circuit breaker, concurrency limits, and reconciliation tests are
  implemented locally.
- **Impact:** makes thousands of agents financially bounded rather than merely well-behaved in a
  simulation.
- **If incomplete:** do not run high-concurrency provider work or claim a hard budget guarantee.
- **Needed support:** provider/operations owner sets an account-level cap or egress-proxy policy,
  chooses a ceiling and review date, and performs one safe rejection test.
- **Close with:** policy/account identifier, numeric ceiling, effective date, rejection receipt,
  and owner. Do not record credentials.

### [ ] AUTH-RELEASE-01 - record the Phase 1 RC or no-RC decision

- **Support type / priority:** release decision, P3; intentionally last.
- **Plain meaning:** decide what one exact commit may honestly be called. "No-RC" is a valid,
  useful decision when the authority gates are still open.
- **Current state:** draft PR #26 at `705f2c192865eae1dbe4151926f92ce61634fddc` records 1,875
  clean-stage passes, 13 explicit environment/cache/OCI skips, zero failures, FATE canary
  preparation, local T6 preparation, scans, SBOM, and policy checks; its four-job GitHub Actions run
  is green. It remains `no-RC` because rights/T5, independently operated T6/signer, real T7, and
  independently administered provider evaluation are not closed.
- **Impact:** prevents a public code repository or green CI badge from being mistaken for a verified
  mathematical system.
- **If incomplete:** development continues; no release-candidate or production claim may be made.
- **Needed support:** release owner reviews a machine-prepared gate table and chooses RC or no-RC
  for the exact commit. A waiver cannot override statement fidelity, kernel verification, or signer
  separation.
- **Close with:** commit SHA, CI IDs, evidence digests, passed/failed/waived/unrun table, signed or
  otherwise independently retained decision, owner, and date.

### [ ] AUTH-DASHBOARD-REMOTE-01 - approve remote Dashboard access only if it is requested

- **Support type / priority:** product/security decision, P4; not needed for the present
  loopback-only Dashboard.
- **Plain meaning:** the Dashboard is a monitoring screen. If exposed remotely it could reveal
  source, proof, cost, or worker metadata, so someone must choose who may see it and for how long.
- **Current state:** local read-only event projection and UI are implemented; remote mode is not
  approved.
- **Impact:** protects evidence confidentiality without slowing local development.
- **If incomplete:** keep the default `127.0.0.1` read-only mode. No functionality required for
  Builder or Prover is blocked.
- **Needed support when triggered:** Dashboard/security owner selects authentication, access roles,
  retention/export rules, audit logging, and an incident contact; operator deploys that exact policy.
- **Close with:** approved policy, deployment/config hashes, authentication and sanitization tests,
  retention period, and owner. Until then, this item is deliberately dormant.

## Mathematics and statement fidelity

### [ ] AUTH-RIGHTS-01 - approve source-specific rights and model-egress scope

- **Support type / priority:** source/rights decision, P0.
- **Plain meaning:** decide what may be copied, stored, shown publicly, and sent to an external
  model. This is about permission and provenance, not whether the mathematics is true.
- **Current state:** iFEM bytes and CC BY 4.0 license identity are pinned; the current enforced
  policy is `local_only` with no external-model egress. That is evidence, not legal advice or a
  completed usage decision.
- **Impact:** unlocks the first real `local_calibration` sample only within the chosen scope.
- **If incomplete:** agents may inspect public metadata and use synthetic fixtures, but may not send
  text to external models, redistribute it, or start real source-backed conversion.
- **Needed support:** the project/source-rights owner selects one narrow scope. The recommended
  near-term choice is "local cached analysis, attribution retained, no external model egress, no
  public excerpt redistribution." Broader use needs an explicit rights/operational review.
- **Close with:** `SourceRecordV1`, `RightsRecordV1`, license and attribution hashes, allowed
  endpoint classes, accountable owner, and review date. This does not approve a statement's meaning.

### [ ] AUTH-T5-01 - admit and freeze one exact statement contract

- **Support type / priority:** mathematical semantic decision, P0 after rights scope.
- **Plain meaning:** confirm that one Lean sentence says what one source sentence means, including
  all conditions such as "for every," boundary assumptions, and exceptional cases. Freezing means
  the Prover may try to prove that exact sentence but may not quietly change it.
- **Current state:** no real source-backed statement is admitted or frozen. The system has machine
  candidates, reverse renderings, mutation tests, counterexamples, and dissent records, but these
  intentionally produce only `machine_advisory`.
- **Impact:** this is the actual Builder-to-Prover handoff gate. Without it, solving a Lean theorem
  might solve the wrong mathematical problem.
- **If incomplete:** continue discovery and non-frozen local calibration only. Never route the
  candidate to Prover acceptance or claim that it represents the textbook.
- **Needed support:** an independently accountable semantic reviewer (or a separately authorized,
  versioned future policy) checks a small review packet: source span, plain-language restatement,
  Lean statement, assumptions/quantifiers, examples/counterexamples, mutation results, imports and
  axioms. A mathematics specialist is valuable here because tiny wording changes can reverse a
  theorem.
- **Close with:** exact contract revision/hash, source/rights record, reviewed formal profile,
  independent decision, complete dissent disposition, freezer identity, and expiry/review date.
  The closure is only for that revision.

### [ ] AUTH-T3-01 - dispose of the dormant model-theory candidate

- **Support type / priority:** mathematical exception decision, P3; it is not the current primary
  path.
- **Plain meaning:** the older logic candidate contains ambiguous source locations and a mismatch
  between the intended logic fragment and observed image/import/axiom profile. It must not drift
  into a frozen theorem by accident.
- **Current state:** `gap/not_selected`; a reproducible packet binds ten spans, machine checks,
  mutations, and dissent. No independent reviewer has admitted it.
- **Impact:** protects the project from building a large proof effort on a possibly misread theorem.
- **If incomplete:** it blocks only this old candidate, not iFEM discovery or another rights-cleared
  source.
- **Lowest-human path (recommended):** no reviewer is needed to keep or archive a negative fixture.
  Leave it `gap/not_selected` and select a fresh source later. Human mathematical review is needed
  only if someone wants to revive this candidate.
- **Close with:** either a named admission of one exact successor profile, or an accountable
  rejection/archival decision that preserves the immutable gap and forbids reuse as a pilot.

### [ ] AUTH-OPEN-PROBLEM-01 - approve a novelty or open-problem claim

- **Support type / priority:** research-governance decision, P4; long-range only.
- **Plain meaning:** proving a Lean lemma is not the same as proving it is new or solves a famous
  unsolved problem. Someone must check that the claim is the right question and was not already
  solved elsewhere.
- **Current state:** no such claim exists; all future conjectures remain quarantined.
- **Impact:** protects the north-star research program from confusing benchmark progress with a
  research breakthrough.
- **If incomplete:** retain useful lemmas, reductions, counterexamples, and gap reports in
  `CONJECTURE_QUARANTINE`; do not make a public novelty statement.
- **Needed support when triggered:** independent domain reviewers examine the exact conjecture,
  literature/active-project search, semantic contract, axiom/dependency audit, kernel replay, and
  independent reproduction.
- **Close with:** frozen conjecture revision, verification/reproduction receipts, dated search
  record, reviewer decision, and the exact public wording allowed. It never covers nearby claims.

## Security, data, and incident support

### [ ] AUTH-INCIDENT-01 - close the historical Hugging Face credential incident

- **Support type / priority:** external security operation, P1.
- **Plain meaning:** deleting the archive stops one distribution path; it does not prove that old
  tokens cannot still be used elsewhere.
- **Current state:** the project owner confirmed deletion of the HF archive. Current and reachable
  history scans protect the candidate repository, but provider-side credential state has not been
  independently recorded.
- **Impact:** limits the chance that a historically exposed token is reused against public project
  infrastructure.
- **If incomplete:** local development can continue with fresh secret references, but the project
  cannot honestly claim full incident closure.
- **Needed support:** each credential owner checks the relevant provider account and revokes or
  rotates any potentially exposed HF, GitHub, OpenAI/Codex, or compatible-endpoint credential.
  This is an account operation, not a request to put secrets in the repository.
- **Close with:** provider, credential identifier or scope (never value), rotation/revocation date,
  owner, and evidence reference. Do not write session names, prompts, or raw archive facts here.

## Items that do not need human intervention now

These entries are intentional. They prevent a vague "please find an expert" request from blocking
machine work. If their trigger occurs, create a new `AUTH-*` item rather than retroactively
pretending the automated policy granted authority.

| ID and source register | Status and machine reasoning | Trigger for human/external support |
| --- | --- | --- |
| `AUTO-SCHEMA-01` / OQ-002 | **No human action now.** Unknown contract versions/fields are rejected; workers do not auto-migrate meanings. This is a deterministic compatibility rule. | A future public schema migration or external interoperability claim needs a versioned ADR and compatibility fixtures. |
| `AUTO-COMPARATOR-01` / OQ-006 | **No human action now.** V1 stays local and makes no lean-eval-style portable comparator claim. | Before claiming external comparator/workspace compatibility, build and independently exercise the exact bundle revision. |
| `AUTO-BENCHMARK-SPLIT-01` / OQ-013 | **No human action now; closed in code.** Stable SHA-based, answer-free split manifests prevent cherry-picking. | Only a deliberately new benchmark version needs a recorded benchmark-owner decision. |
| `AUTO-OVERRIDE-01` / OQ-014 | **No human action now.** There is no human override for a verifier or Builder rejection; create a new contract/evidence revision instead. | A request to weaken this rule is a new governance proposal and must never be handled as an ad hoc exception. |
| `AUTO-MIGRATION-01` / OQ-009 | **No human action now.** Reimplement public ideas only; do not import old sessions, prompts, workspaces, or runtime state. | Any proposed legacy-artifact import requires a fresh manifest, security review, and a new authority item. |

## Coverage map: historical decisions to this worklist

| Register item | Current handling |
| --- | --- |
| OQ-001, OQ-010, OQ-017 | `AUTH-T3-01`, `AUTH-T5-01`, and `AUTH-RIGHTS-01` distinguish a dormant candidate from freezing a real statement. |
| OQ-003 | `AUTH-RIGHTS-01`. |
| OQ-004 | `AUTH-PROVIDER-01`; prohibited providers and unapproved endpoints remain rejected. |
| OQ-005, OQ-015 | `AUTH-T6-01`, `AUTH-T7-01`, and `AUTH-SIGNER-01`. |
| OQ-007 | `AUTH-DASHBOARD-REMOTE-01`; loopback-only remains the no-action default. |
| OQ-008 | `AUTH-INCIDENT-01`. |
| OQ-011 | `AUTH-OPEN-PROBLEM-01`. |
| OQ-012, OQ-016 | `AUTH-SPEND-01`. |
| OQ-002, OQ-006, OQ-009, OQ-013, OQ-014 | The five `AUTO-*` entries above; they are not hidden human backlogs. |

## How to record a closure

For every checked authority item, append a dated decision record containing:

```text
Decision:
Accountable owner or separately controlled operator:
Priority and scope:
Evidence reference and SHA-256:
Acceptance effect:
What this does not establish:
Expiry or review date:
```

Never put a credential value, private source excerpt, raw model response, private path, session
archive, signing key, or unredacted prompt in this file. A closure authorizes exactly the stated
effect and must not be used to silently weaken the Builder -> frozen contract -> Prover boundary.
