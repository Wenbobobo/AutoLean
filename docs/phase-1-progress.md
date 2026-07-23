# Phase 1 Progress Ledger

Snapshot: 2026-07-23

Decision: the local architecture has substantial adversarial evidence, but this branch is not a
Phase 1 release candidate. The remaining blockers are authoritative mathlib-in-image execution,
authenticated Builder/verifier authorities, authorized external-model evaluation, fixed
regression/compare runs, a human-calibrated Builder slice, and current-branch remote CI.

This ledger records observed evidence rather than estimated completion percentages. `Verified`
means the named check ran and its scope is stated. `Blocked` names a missing prerequisite.
Synthetic, fake, mounted-build, and local-HMAC evidence is never promoted by relabeling it.

## Current evidence

| Surface | Status | Recorded evidence | Boundary |
| --- | --- | --- | --- |
| Contract V1 and three graphs | Verified | Contract, hash, graph-separation, migration, and adversarial tests in the 415-test offline suite | Does not establish mathematical fidelity |
| Builder source-to-freeze path | Verified, local/synthetic | Official parent/text hashes, exact UTF-8 byte spans, append-only SQLite CAS preparation, two independent candidates, complete mutation suite, semantic/library review, and a real `prepare -> fidelity -> freeze` test | Reviewer and freezer IDs are unauthenticated strings; no production Builder signer |
| Public/private source boundary | Verified | Public source-backed contracts retain span IDs, locators, offsets, and typed hashes but no verbatim excerpt; exact text remains in the ignored source cache and private fidelity artifact; public-readiness rejects JSON with non-null `permitted_excerpt` | Not a forensic scanner and not protection from a hostile local administrator |
| Builder experience retrieval | Verified, synthetic | Content-addressed success/negative/gap records, rights/endpoint filters, deterministic ranking and budgets, poison-text rejection, and validated retrieval skill | Advisory context cannot satisfy a freeze gate |
| Builder--Prover closure | Verified, synthetic | Fidelity artifact through freeze, signed bridge, claim, gap/change request, new-revision re-review, fake proof, and synthetic acceptance | No Lean or OCI execution in this fixture |
| Event, lease, and artifact control plane | Verified, synthetic | SQLite WAL, command idempotency, fencing, append-only events, concurrent artifact create-if-absent, and immutable contract-revision projection | No power-loss or storage-device fault injection |
| OS-process recovery | Verified, synthetic | 1,000 jobs; 1,000 expired leases/stale-fence rejections; 4,000 duplicate-delivery replays; 5,000 contiguous events; 4,000 artifact checks; no loss or duplicate terminal verdict. Report SHA `d80c2c0dbcbab22bfcbd0bea13f41e07c5f337a4a93d82203ef060e7765a2847` | No Lean, OCI, network, model, physical power loss, or mid-transaction kill |
| Verifier evidence and signing gateway | Verified, synthetic | Lease/context/digest-bound request, evidence-artifact rehash and cross-binding, replay ledger, fail-closed outage, stale-fence rejection, and verifier execution-policy binding | Local HMAC is test-only; production mTLS/ACL and KMS/HSM custody are absent |
| FATE source boundary | Verified | FATE v4.28.0 root and three submodule commits; 350-task manifest hash `3187bac80d3aeb2dac8f5da878fe21580a4c11540a0c7db3c14a34c2e0bdc748` | FATE is single-theorem evidence only |
| `compile-canary-12` | Verified | Managed WSL runtime, Lean 4.28.0, mathlib `8f9d9cff6bd728b17a24e163c9402775d9e6a365`; M 3/3, H 3/3, X 6/6; report SHA `87208dfc6d30c485c5a1efa85113f14334d86dd0c8544a1f2ac463d3b7aa90aa` | Original files contain `sorry`; `proof_search=false` |
| `agent-smoke-8` | Verified, non-promotable | All eight fixed M cases attempted with one task-independent `aesop`; M-1 and M-3 compiled, type-queried, and passed the axiom policy; 2/8 total, no timeout; report SHA `c8c32f150562a9f4de9d6be84c812a6e7c6b760d624d43a1ad03b280144e5bb2` | No model Agent; mounted `.olean` tree is observed but not independently attested or image-built; no bundle/lease/signing request |
| Role benchmark V3 | Verified, fake-only | Five roles, three repetitions, strict matrix/readiness/evaluator commitments, private raw CAS, public aggregate, replay, and two byte-identical forward runs. Report file SHA `06766d98d82c6a5400765c60423d4b225ab0b12d314535e414d765ccbd414f13` | Scripted fake output is not a model score or Lean/fidelity evidence |
| External benchmark readiness | Blocked before egress | Refuses execution on `execution_authorization_missing_v1`, `external_executor_unavailable_v1`, and `production_role_evaluator_missing_v1` | API credentials are not yet requested |
| Project DAG | Verified, synthetic | Fixed 20-node multi-file frontier, conflict, propagation, API-change, and integration-lease fixture | Does not compile a real multi-file Lean library |
| Providers | Verified offline | Fake, Codex CLI, OpenAI Responses, and custom-compatible adapters; authorization/egress controls, stable failure taxonomy, and persistent circuit breaker | No paid/external run; no prohibited provider path |
| OCI verifier | Verified, pure Lean | Non-root, digest-pinned image `sha256:d69da80fa5c1b9f921cda33bb37376114e9e15e7238eff513d8b6a340e55bcc0`; real Lean compile/query; statement replacement, wrong declaration/profile, stdout spoof, and axiom attacks rejected | No clean mathlib rebuild owned by the image |
| Dashboard | Verified, loopback | Projection/API tests plus 11/11 UI tests, production build, desktop/mobile controlled-browser screenshots, XSS/display sanitization, stable three-lane graph layout, task/gap/verification drill-down | Remote mode remains unapproved; current JS bundle has a non-blocking 500 kB chunk warning |
| Builder reference cache | Verified offline | McKay PDF: 94,902,360 bytes, SHA `1cd1660be5e63bf2d5198e7a7f7e912d3179c9cf3b5f2d972db6283e0b483ea4`; official extracted text: 1,194,775 bytes, SHA `3fdfa27690ce473d8b84c322dbd12779ce5ba76aa12ef8d07608db768894bd25`; manifest SHA `881d535d62661ad496f8385964151830688a78d10123b59ff8326cb8a3a5a907` | Local-only egress; no human-calibrated pilot statement yet |
| HF recovery boundary | Incident open | Recovery work completed locally without migrating sessions, prompts, logs, or credentials | The API still reported `Garydesu/AutoArchon_Private` as `private=false`, `gated=false` on this snapshot; credential rotation is operator-owned |
| Local CI, inventory, and SBOM | Verified | 415 Python tests, Ruff format/check, all Mypy targets, 226-file secret/provider/public scans, 11 UI tests/build, reference replay, inventory SHA `4beb3113a106ccc687b0421e30feea6908f4a16bc406e765d970581831233039`, SPDX SHA `03d9645cf1c8e52f8a0acfb425ff9fa62a4653638fc5cd466030522fe0797917` | Current branch has not yet passed remote Windows/Linux CI |

## Week route

| Weeks | State | What remains before the milestone is closed |
| --- | --- | --- |
| 1--2 | Implemented and locally verified | Retain current-branch Windows/Linux CI; bootstrap `main` alone is not enough |
| 3--4 | Partially verified | Build mathlib and verifier helper inside one pinned image; route FATE smoke through immutable bundle, lease, evidence artifact, and signing gateway |
| 5--6 | Partially implemented | Add operator-authorized external executor and production role evaluators; measure Archon adapter; run fixed `regression-48` pass@1 |
| 7--8 | Partially verified | Run compare-90 pass@1 and one-factor model/retrieval/specialist ablations; complete five human-reviewed Builder calibration statements |
| 9--10 | Partially verified | Retain authoritative Linux OCI CI, add practical transaction/power-loss tests, and run compare-90 pass@4 |
| 11--12 | Not run | Attempt FATE-350 pass@1, review the paper-version subset, close dependency/license audit, and make an explicit RC decision |

## Builder discovery

The primary 24-node discovery slice is now curvature of vector-bundle connections through a
sharply bounded first Bianchi target. The earlier Levi-Civita proposal is revoked because current
mathlib already has the connection/torsion/metric groundwork and active upstream Levi-Civita work.
The backup remains abstract variational PDE and a Cea-type error bound.

The McKay textbook and repository-provided text are pinned and cached locally, never tracked.
Admission still requires:

- a current mathlib overlap/maintainer check;
- at least six of eight prerequisite mappings compiling at the pilot commit;
- five human-calibrated statements passing the full fidelity and non-vacuity gate;
- one qualified differential geometer; and
- an explicit rights decision before any non-local model egress.

Failure of the overlap or prerequisite gates moves the pilot to the PDE backup. Failure of
fidelity, expert, or rights gates pauses ingestion rather than weakening a theorem.

## Immediate execution order

1. Commit this evidence-bearing branch, push it, open a Draft PR, and retain its Windows/Linux CI.
2. Build a source-clean, mathlib-containing OCI verifier image and repeat `agent-smoke-8` through
   bundle, lease, evidence artifact, and signing-gateway boundaries.
3. Implement the authorized online executor and production role evaluators. Request an
   operator-owned API secret reference only when readiness otherwise passes.
4. Compile the eight existing curvature mappings and start five expert-reviewed source-to-contract
   calibration statements; feed only frozen bundles to Prover.
5. Run `regression-48` pass@1, then controlled role/model/retrieval ablations and compare-90.
6. Deploy Builder/verifier authorities behind authenticated service boundaries before any result
   is called promotable.

Repository visibility may be changed after the external HF/credential incident is closed, GitHub
history is reviewed, host secret scanning is enabled or independently substituted, and the
current public-readiness/secret/provider gates pass. Public source code never authorizes source
document, recovered archive, raw model output, or credential publication.
