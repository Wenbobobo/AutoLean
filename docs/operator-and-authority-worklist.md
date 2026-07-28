# Operator and Authority Worklist

Status: active external-action register

This is the only checklist for work that AutoLean agents cannot honestly close by writing code,
running local tests, or agreeing with one another. The active execution order lives in
[roadmap-next.md](roadmap-next.md); observed evidence lives in
[phase-1-progress.md](phase-1-progress.md). Do not duplicate these items in ordinary planning
documents.

An unchecked item does not block unrelated implementation or discovery. It blocks only the
acceptance effect named in that item. Agents must finish the machine preparation first and present
the smallest possible evidence packet to the named owner.

## How to close an item

For every checked item, append a dated decision record containing:

```text
Decision:
Owner:
Evidence reference and SHA-256:
Scope:
Acceptance effect:
What this does not establish:
Expiry or review date:
```

Never put a credential value, private source excerpt, raw model response, private path, session
archive, or signing key in this file.

## Semantic and source authority

- [ ] **AUTH-T3-01: Dispose of the current model-theory T3 candidate.**
  - Blocking: the current candidate remains `gap/not_selected`; it cannot produce the first T5
    frozen contract.
  - Machine preparation: bind all ten source spans, resolve the two locator candidates as far as
    the bytes permit, generate blinded semantic-atom and formal-profile comparisons, run the
    complete mutation/counterexample suite, and preserve every dissent.
  - Required external fact: choose exactly one outcome: (a) admit one source/formal boundary with
    a named accountable reviewer, or (b) retain the immutable gap and abandon this candidate in
    favor of a new rights-clear source. Model agreement alone cannot rewrite the old V2 decision.
  - Evidence to attach: bound review packet hash, machine-quorum report hash, chosen successor
    profile or rejection record, owner identity, and date.
  - Acceptance effect: closes only pilot disposition. Admission is still not a Lean proof.
  - Owner: project owner plus an independently accountable semantic reviewer.
  - Low-human alternative: select outcome (b); continue iFEM or another explicit-license lane and
    leave the model-theory packet as a permanent negative fixture.

- [ ] **AUTH-RIGHTS-01: Approve rights and model-egress policy for each real source.**
  - Blocking: real `local_calibration`, external model conversion, public redistribution, and
    production ingestion for that source.
  - Machine preparation: pin exact bytes and revision, hash the license and attribution files,
    classify third-party material, propose the most conservative rights/egress ceiling, and test
    that every provider request revalidates it.
  - Required external fact: an accountable owner accepts the legal/operational policy. Agents
    cannot grant a license or provider-side permission.
  - Evidence to attach: `SourceRecordV1`, `RightsRecordV1`, license hash, attribution text, allowed
    endpoint classes, decision owner, and review date.
  - Acceptance effect: authorizes only the stated use and endpoint classes; it says nothing about
    mathematical correctness.
  - Owner: source/rights owner.
  - Low-human alternative: use only sources with an explicit adaptation license and keep
    `model_egress=deny`; escalate only before public redistribution or external egress.

- [ ] **AUTH-IFEM-SOURCE-01: Retain the pinned iFEM opening-source bytes.**
  - Blocking: P2-04 exact-byte source lock and any real iFEM `local_calibration` sample.
  - Machine preparation: the adapter pins upstream commit
    `a4ab841c4e5ec726e9b7742c9dcb352cb9645736`, the reviewed LICENSE Git blob and SHA-256,
    thirteen exact opening paths, a no-redirect route, the `local_only`/no-freeze/no-Prover
    policy, candidate-manifest commitment, and replay/adversarial tests.
  - Required external fact: a network-capable operator environment performs the bounded fourteen
    raw-file requests and replays every cached digest. The CLI acknowledgement is not an authority
    boundary; untrusted workers must remain unable to acquire network content.
  - Evidence to attach: redacted source-lock summary, receipt SHA-256, thirteen source hashes and
    sizes, candidate-manifest SHA-256, LICENSE digests, and successful `verify` summary. Do not
    attach source text to this checklist.
  - Acceptance effect: closes only exact local source acquisition. It does not approve external
    model egress, source-span selection, statement fidelity, contract freeze, or Prover handoff.
  - Owner: source-cache operator.
  - Operator commands: `uv run --frozen python scripts/ifem_source_lock.py acquire
    --operator-acquire`, then `uv run --frozen python scripts/ifem_source_lock.py verify --receipt
    <receipt-path>`.

- [ ] **AUTH-OPEN-PROBLEM-01: Accept an open-problem research or novelty claim.**
  - Blocking: any public statement that a result is new, advances an open frontier, or solves an
    open problem.
  - Machine preparation: exact conjecture contract, literature and active-project search,
    dependency-leverage comparison, axiom/dependency audit, independent kernel replay, adversarial
    restatement, and reproducibility packet.
  - Required external fact: independent domain review of mathematical intent, literature novelty,
    and significance. A finite model search cannot prove that no prior result exists.
  - Evidence to attach: frozen conjecture revision, proof/verification receipts, search record,
    independent reproduction, reviewer decision, and publication scope.
  - Acceptance effect: authorizes only the exact claim reviewed. It does not generalize to nearby
    formulations.
  - Owner: project owner and independent research reviewers.
  - Low-human alternative: keep results in `CONJECTURE_QUARANTINE` as lemmas, counterexamples,
    reductions, or gap evidence without a novelty claim.

## Host and execution authority

- [ ] **AUTH-T6-01: Retain the real T6 OCI/Lean and gateway replay.**
  - Blocking: T6 authority and the first production-shaped frozen-to-verified vertical.
  - Machine preparation: build the immutable input, run all preflight checks, bind exact image and
    environment digests, and prepare expected rejection controls.
  - Required external fact: the authority Linux/WSL host actually executes the image-owned query
    and the separately operated gateway replays the evidence.
  - Evidence to attach: canonical operator-live-gate summary, image digest, input/output hashes,
    gateway receipt, and negative-control results.
  - Acceptance effect: closes only the named T6 execution for the exact bundle and image.
  - Owner: authority-host operator and verifier operator.
  - Operator command: `uv run --frozen python scripts/operator_live_gate.py t6-oci`

- [ ] **AUTH-T7-01: Retain a real leased multi-file T7 run and recovery.**
  - Blocking: project-scale execution, changed-source propagation, and real-worker recovery.
  - Machine preparation: immutable source snapshot, module plan, lease/fence, expected declaration
    fanout, crash injection schedule, clean integration plan, and per-node verifier requests.
  - Required external fact: image-owned workers execute the plan; an old fence is rejected after
    recovery; the independent verifier checks declarations. Module success alone is not proof
    acceptance.
  - Evidence to attach: process receipts, lease/fence events, CAS roots, recovery transcript,
    integration build, and theorem-level verifier receipts.
  - Acceptance effect: closes only T7 for the bound source graph and environment.
  - Owner: worker-farm and verifier operators.
  - Alternative: keep T7 `local_fake_runner_only`; do not relabel injected-runner tests.

- [ ] **AUTH-SIGNER-01: Deploy the independent verifier trust root.**
  - Blocking: production admission/signing authority and Phase 1 RC.
  - Machine preparation: gateway protocol, replay ledger, mTLS/ACL policy, key rotation/revocation
    runbook, outage behavior, and adversarial requests.
  - Required external fact: a deployment owner provisions independently controlled credentials and
    proves that proof workers cannot invoke raw signing operations.
  - Evidence to attach: deployment attestation, public key ID, policy/config hashes, isolation test,
    rotation drill, and owner.
  - Acceptance effect: upgrades only the named signer deployment. Local HMAC fixtures remain
    test-only.
  - Owner: verifier/security operator.

## Provider and benchmark authority

- [ ] **AUTH-PROVIDER-01: Retain one successful authorized real-model suite.**
  - Blocking: real role-performance evidence, regression-48, compare-90, and FATE model results.
  - Machine preparation: frozen prompts, answer-free cases, model/profile revision, capability
    probe, source-egress revalidation, budget reservation, strict evaluator, private output CAS,
    public redacted commitments, and no-retry policy.
  - Required external fact: the approved account/endpoint executes the requests and reports usage;
    an independently administered evaluator accepts the complete private run.
  - Evidence to attach: authorization and plan hashes, provider/model revision, settled usage,
    evaluator report, failure ledger, and public commitment. Never attach the API key.
  - Acceptance effect: establishes only the named model's result under that experiment. It is not a
    proof, a role floor, or Builder fidelity evidence.
  - Owner: provider/evaluator operator.
  - Current record: operator authorized experimental DeepSeek use. The 2026-07-28 single bounded
    attempt returned `blocked` with `provider_response_received=false`, no usage, and no score; a
    credential-free probe from the same sandbox could not establish an HTTPS connection. This is
    environment-path evidence, not an endpoint incident or a model result.

- [ ] **AUTH-SPEND-01: Enforce the external hard-spend ceiling.**
  - Blocking: claims that a large swarm cannot exceed its provider budget.
  - Machine preparation: client reservations, circuit breaker, concurrency limits, accounting
    reconciliation, and failure tests.
  - Required external fact: the provider account, proxy, or billing control enforces the ceiling
    independently of delayed usage reports.
  - Evidence to attach: account/proxy policy ID, ceiling, effective date, rejection test, and owner.
  - Acceptance effect: closes only hard-spend containment for the named account.
  - Owner: provider/operations owner.

## Incident and release authority

- [ ] **AUTH-INCIDENT-01: Close the historical HF credential incident.**
  - Blocking: a complete incident-closure claim.
  - Machine preparation: current/history secret scans, public-candidate inventory, and confirmation
    that no recovered sessions or configuration enter the repository.
  - Required external fact: every potentially exposed HF, GitHub, OpenAI/Codex, and custom-endpoint
    credential is revoked or rotated at its provider.
  - Evidence to attach: provider-side rotation/revocation dates and credential identifiers only,
    never values. The operator has already confirmed deletion of the HF archive.
  - Acceptance effect: closes incident containment only; it does not validate Phase 1.
  - Owner: credential owners.

- [ ] **AUTH-RELEASE-01: Record the Phase 1 RC or no-RC decision.**
  - Blocking: Phase 1 exit and any release-candidate claim.
  - Machine preparation: clean staged candidate, exact manifest, full tests, secret/current/history
    scans, public readiness, SBOM/inventory, source locks, Windows/Linux CI, and a gate table naming
    every passed, failed, waived, and unrun item.
  - Required external fact: the release owner accepts the exact commit and explicitly chooses RC or
    no-RC. Waivers cannot override statement fidelity, kernel verification, or signer authority.
  - Evidence to attach: commit SHA, CI run IDs, evidence hashes, gate table, decision, and date.
  - Acceptance effect: applies only to the exact candidate commit.
  - Owner: release owner.
  - Current remote record, checked 2026-07-28: draft
    [PR #26](https://github.com/Wenbobobo/AutoLean/pull/26) is open and mergeable at head
    `979584346a331e52c97b7fe9f1301592be18725c`. Its body records the earlier candidate checks. The
    present dirty working tree and later changes are not that candidate and require a new exact
    staged validation. Neither state is an RC because T3/T5, real T6/T7, signer, and real-provider
    evidence remain open.

## Machine-first reduction policy

The default review route is deterministic checks plus blinded, de-correlated model roles:
source binders, two claim atomizers, two formalizers, chain critics, an adversarial falsifier,
library critic, cheating supervisor, and a deterministic consensus engine. A critical mutation,
counterexample, unresolved dissent, shared model lineage, or stale calibration forces abstention.

The resulting artifact is `machine_advisory` evidence. It may drive discovery, local calibration,
proof search in quarantine, and preparation of the checklist above. It cannot make the
source-fidelity/admission decision, transition a real candidate to `frozen`, impersonate a human
identity, grant rights, provision a trust root, prove that a host action occurred, or make a public
novelty claim. Any future narrower exception requires a separately versioned authority policy and
an explicit accountable decision; model consensus cannot silently create that exception.
