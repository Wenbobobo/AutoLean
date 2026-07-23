# Phase 1 Progress Ledger

Snapshot: 2026-07-23
Decision: architecture evidence is substantial but the Phase 1 release candidate is not ready.

This ledger records observed evidence, not estimated completion percentages. `Verified` means the
named check ran and its scope is stated. `Implemented` means code exists but the authoritative
gate has not run. `Blocked` names a missing prerequisite. `Not run` is never treated as failure or
success.

## Current evidence

| Surface | Status | Recorded evidence | Boundary |
| --- | --- | --- | --- |
| Contract V1 and three graphs | Verified | Contract, hash, graph-separation, and adversarial tests in the full Python suite | Does not establish mathematical fidelity |
| Builder statement-fidelity Harness | Verified, synthetic | Two candidate groups, reverse render, semantic obligations, nine mutation families, independent actor checks, expert verdict binding, and freeze rejection tests; the canonical fidelity artifact is now a typed bundle reference and a default registration gate | Actor IDs are structural metadata; authenticated human identity is external |
| Builder experience retrieval | Verified, synthetic | Content-addressed success/negative/gap records, exact rights and endpoint filters, deterministic ranking/budgets, canonical ContextPack replay, poison-text rejection, validated skill, and independent forward-test | It is advisory only; item budgeting does not guarantee an outcome-diverse pack |
| Builder--Prover closure | Verified, synthetic | Canonical fidelity artifact through freeze, signed bridge, claim, gap/change request, new-revision re-review, fake proof, and synthetic independent acceptance | No Lean or OCI execution in this fixture |
| Contract-revision registration | Verified | Transactional unique `(contract_id, revision)` binding, concurrent registration, restart/backfill, immutable projection, strict canonical legacy JSON | Content-addressed orphan cleanup remains an operations concern |
| Event, lease, and artifact control plane | Verified, synthetic | SQLite WAL, command idempotency, fencing, append-only events, concurrent artifact create-if-absent | No power-loss or storage-device fault injection |
| Process recovery | Verified, synthetic | 1,000 jobs, process termination/restart, 1,000 expired leases, 4,000 idempotent replays, 5,000 replayed events, no lost or duplicate terminal task | No Lean, OCI, model, or physical power loss |
| Verifier evidence and signing gateway | Verified, synthetic | Lease/context/digest-bound signing request, replay ledger, fail-closed outage, stale-fence rejection; full-suite regression passed when introduced | Local HMAC is test-only; production mTLS and KMS/HSM custody are not deployed |
| FATE source boundary | Verified | FATE v4.28.0 root and three submodule commits, 350-task manifest hash `3187bac80d3aeb2dac8f5da878fe21580a4c11540a0c7db3c14a34c2e0bdc748` | FATE is single-theorem evidence only |
| `compile-canary-12` | Verified | Reproducible WSL mirror, Lean 4.28.0, mathlib `8f9d9cff6bd728b17a24e163c9402775d9e6a365`; M 3/3, H 3/3, X 6/6; wrapper report hash `ac7cdd9b1ab4c7be1834a433c2843b0246b87714eb15b131531384769ed4c2d8` | Originals contain `sorry`; `proof_search=false` |
| Role benchmark protocol | Verified, fake-only | Five roles, three repetitions, 15/15 scripted trials; skill forward-test plus a fresh-database rerun were byte-identical at `3486bc7edf249957ff7d7edf68f3a033dbbbcfd46bacb5e733a217cff8df835e` | Exact-output fake fixture is not a model score |
| Project DAG | Verified, synthetic | Fixed 20-node multi-file dependency, frontier, conflict, propagation, and integration-lease fixture | Does not compile a real multi-file Lean library |
| Providers | Verified offline | Fake, Codex CLI, OpenAI Responses, and custom-compatible adapters; authorization/egress controls; stable failure taxonomy; restart-persistent, binding-scoped circuit breaker | No paid or external model benchmark has run; no single fenced half-open probe |
| OCI verifier | Verified, pure Lean | Non-root, digest-pinned image `sha256:d69da80fa5c1b9f921cda33bb37376114e9e15e7238eff513d8b6a340e55bcc0`; real Lean 4.28.0 compile/query through `OciLeanRunner`; altered statement, candidate replacement, wrong declaration/profile, and stdout spoof rejected; latest canary evidence hash `83ca4bd156d383cc6dc703fc7901780d46c2601eadae6cf5621ebf895b2f76da` | No mathlib/FATE image, registry publication, or promotion attestation |
| Dashboard | Verified, loopback | API 15/15 and UI 6/6 checks; production build; controlled-browser desktop/mobile, navigation, refresh, XSS text rendering, canvas sizing, and no-overflow checks | Remote mode remains an operator policy; browser screenshot transport timed out, so validation used DOM and geometry evidence |
| HF recovery boundary | Verified locally, incident open | Four encrypted archives checksum-verified; three non-session archives decrypted but not extracted; session archive remains encrypted; strict aggregate JSON and header-only inventory | Provider access restriction, credential rotation, classification review, and sanitized export remain operator-owned |
| CI, inventory, and SBOM | Verified locally | Merged-tree gate: 270 Python tests, Ruff, all Mypy targets, 198-file secret scan, provider policy, 6 UI tests and production build; inventory `7f8b733958d7b1e505922f0b4eab778a0586383ca9cec10168a22aadbfbe7cb7`; SPDX `cda980bad6b43d907e9a2e703e12cce5076e61ef1485a594355cc970b520275b` | No canonical commit or remote Windows/Linux CI run yet |

## Week route

| Weeks | State | What remains before the milestone is closed |
| --- | --- | --- |
| 1--2 | Locally verified | Commit the canonical repository and retain a clean remote CI run from that commit |
| 3--4 | Partially verified | Extend the real pure-Lean OCI path to pinned mathlib/FATE and run `agent-smoke-8` through the same verifier boundary |
| 5--6 | Partially implemented | Add the authorized online role executor; run fixed `regression-48` pass@1; measure the Archon adapter instead of only testing its seam |
| 7--8 | Partially verified | Run compare-90 pass@1 and one-dimension model/retrieval/specialist ablations; deploy no remote Dashboard until its operator policy is approved |
| 9--10 | Partially verified | Add physical-process/transaction fault cases where practical; obtain authoritative Linux OCI CI; run compare-90 pass@4 |
| 11--12 | Not run | Run FATE-350 pass@1, review the paper-version subset, close license/dependency audit, and make an explicit RC decision |

## Builder discovery

The proposed first discovery slice is the 24-node Riemannian-connections and Levi-Civita graph in
[`domain-pilot-selection.md`](domain-pilot-selection.md). It remains gated on:

- mathlib maintainer coordination and a current overlap search;
- at least 70 percent usable prerequisite mappings;
- a lawful source plus endpoint-specific rights policy;
- a qualified domain reviewer; and
- five human-calibrated trial statements before expansion.

No textbook prose has been ingested. The checked-in pilot directory is a rights-safe staging
boundary, not a formalization claim.

## Immediate execution order

1. Run the final merged-tree offline gate, create the first canonical commit, and retain its
   Windows/Linux remote CI result.
2. Build a pinned mathlib/FATE OCI image from the reproducible WSL mirror and run
   `agent-smoke-8` through verifier evidence and the signing gateway.
3. Add the authorized online role executor and role-specific evaluators; only then request one
   operator-owned API secret reference and run `regression-48`.
4. Start the five-statement Riemannian-geometry Builder calibration after rights and expert gates
   are supplied; feed only frozen bundles to Prover.
5. Deploy the verifier signer behind mTLS/ACL and KMS/HSM custody before treating any local HMAC
   attestation as promotable.

API credentials are not currently a blocker. When an online run is ready, the operator should
configure a secret reference outside the repository; no key should be pasted into a task, fixture,
command line, report, or conversation.
