# Phase 1 Parallel Execution Plan

Snapshot: 2026-07-23
Baseline commit: `48b129097773616a28534abfe833eb10b9779aac`

## Decision

Phase 1 proves that Builder and Prover can exchange a faithful, immutable statement and produce
replayable proof evidence without sharing authority. It does not optimize a headline benchmark
score and does not promote an open-problem claim. Work proceeds in parallel only where the
evidence roots remain independently reviewable.

The repository may become public after the public-release gate below passes. Downloaded source
documents, operator credentials, raw model traffic, benchmark answers, recovery archives, and
private workspaces remain outside Git regardless of repository visibility.

## Non-negotiable merge gate

Every work package must provide:

1. a versioned input or configuration;
2. a short script entry point under `scripts/` when execution is repeatable;
3. positive and adversarial tests proportional to the trust boundary;
4. a canonical report or content hash without restricted payloads;
5. documentation that states both the observed result and what it does not prove;
6. clean Ruff, Mypy, Pytest, provider-policy, secret-scan, UI test/build, and lock checks relevant
   to the changed surface; and
7. a branch commit and remote CI result before merge.

No passing score can waive a failed statement, verifier, rights, or provenance gate.

## Parallel work packages

| Package | Current objective | Exit evidence | Cannot claim |
| --- | --- | --- | --- |
| A. Public release and governance | Complete license metadata, scan the entire one-commit history, document contribution and disclosure boundaries, and make visibility an explicit operator action | Root license, package metadata, zero tracked restricted files, secret/provider scans, clean remote CI | Historical HF incident containment or credential rotation |
| B. Prover vertical slice | Extend the digest-pinned OCI path from pure Lean to the pinned FATE mathlib environment and run `agent-smoke-8` through the same verifier-evidence boundary | Immutable image/build inputs, clean statement/type comparison, eight separate task reports, signed-gateway observation | Model quality, project-scale library construction, or independent production attestation |
| C. Role and model benchmark | Freeze role-specific matrices, seeds, evaluators, provider readiness, private raw-output CAS, public aggregate report, and controlled comparison semantics | Deterministic fake forward test, readiness refusal tests, then a separately authorized online run | A fake score, cross-role ranking, contamination-free evaluation, or causal attribution from a confounded comparison |
| D. Builder source and fidelity | Cache lawful sources locally by manifest, select a 20--40 node pilot, and calibrate source-span-to-contract conversion with independent review and mutation tests | Verified source hash and rights record, five human-reviewed trial statements, fidelity artifacts, frozen bundles | That Lean truth establishes source fidelity or that a textbook license permits model egress |
| E. Read-only graph observability | Show mathematical, formal, and execution graphs as distinct but linked operational layers, with revision/attempt/gap/verification drill-down | Projection-only API tests, sanitizer/XSS tests, desktop/mobile screenshots and geometry checks | Control authority, remote-access approval, or completeness of hidden artifacts |
| F. Reliability and release evidence | Turn chaos, SBOM, inventory, attestation, Windows compatibility, and Linux authority checks into one replayable RC decision | Retained manifests/reports, 1,000-job recovery evidence, SBOM, clean Linux authority run, explicit pass/block table | Physical power-loss tolerance, KMS/HSM deployment, or a final RC while mandatory gates remain unrun |

## Critical path

```text
lawful source manifest
  -> rights and egress decision
  -> human calibration statements
  -> fidelity freeze
  -> standard task bundle
  -> Prover claim
  -> model execution authorization
  -> proof submission
  -> independent OCI verification
  -> immutable evidence and read-only projection
```

Provider integration is not on the critical path until the fake executor, evaluator, worker, and
verifier path can reject malformed and unauthorized work. An API credential is requested only
after the online readiness command passes without contacting an endpoint. The operator supplies a
secret reference through the approved host mechanism; a literal key never appears in Git, a
command line, a task, a report, or chat.

## Execution waves

### Wave 0: repository and evidence baseline

- Publish the canonical bootstrap commit and retain Windows/Linux CI.
- Add the actual software license and consistent package metadata.
- Add a public-readiness audit that rejects tracked caches, archives, sessions, prompts,
  credentials, benchmark answers, and source PDFs.
- Keep downloaded references under an ignored, content-addressed local cache.

Exit: the repository is safe and legally clear enough to make public; visibility itself is still
an explicit GitHub operation.

### Wave 1: close Weeks 3--4

- Build a pinned mathlib/FATE OCI profile from the verified source locks.
- Run `agent-smoke-8` through immutable bundle, claim, proof patch, comparator, verifier evidence,
  and signing-gateway interfaces.
- Add failure fixtures for altered declaration type, imports, axioms, source, image digest, and
  stale lease.
- Retain one small, independently recompiled Lean proof as the human-visible checkpoint.

Exit: eight smoke tasks have separate evidence states; failures remain failures rather than being
discarded or repaired by changing statements.

### Wave 2: close Weeks 5--6

- Complete the authorized online role executor and dry-run readiness probe.
- Measure the Archon adapter behind the same contracts; do not grant its runtime authority.
- Run `regression-48` pass@1 with frozen prompts, tools, retrieval, budgets, and exclusions.
- Record one proof or evidence-backed gap from the fixed suite as the checkpoint.

Exit: every online request is lease-bound and rights-authorized, and every accepted proof passes
the independent verifier. Missing API authority is reported as `blocked`, not score zero.

### Wave 3: close Weeks 7--8

- Run `model-compare-90` pass@1.
- Perform one-factor model, retrieval, and specialist-role ablations.
- Finish graph-state drill-down and cost/budget/circuit-breaker projections.
- Begin five-statement Builder calibration from a locally verified source.

Exit: comparisons label controlled versus confounded changes, roles and FATE tiers remain
separate, and the Dashboard exposes no mutation path.

### Wave 4: close Weeks 9--10

- Run pass@4 and success-at-budget on the fixed comparison suite.
- Add authoritative Linux CI evidence and practical process/transaction fault cases.
- Replay reports from immutable inputs and compare canonical bytes.
- Freeze the first reviewed Builder pilot bundles and hand them to Prover unchanged.

Exit: restart, duplicate delivery, stale fence, replay, and independent rebuild gates are retained
as release evidence.

### Wave 5: close Weeks 11--12

- Attempt FATE-350 pass@1 and report M/H/X independently.
- Review the paper-version subset and all license/dependency records.
- Generate SBOM, operations guide, interface specification, security audit, and explicit RC
  decision.
- Promote no result whose semantic, formal, or execution evidence chain is incomplete.

Exit: either a reproducible Phase 1 RC exists or the decision names every blocking gate.

## Builder source cache policy

Tracked files contain only a source manifest, provenance, rights/egress policy, expected digest,
and conversion evidence. Source bytes live in an ignored local cache. The downloader:

- accepts only manifest entries and HTTPS origins explicitly listed there;
- writes a partial file, verifies size and SHA-256, then atomically promotes it;
- refuses digest drift and preserves the mismatched file for audit;
- records retrieval time separately from immutable source identity;
- supports offline `verify` without network access; and
- never treats public download access as permission for redistribution or external-model egress.

Textbook prose is not copied into public fixtures. Public contracts cite source spans and hashes;
their normalized mathematical content and Lean declarations remain independently reviewed.

## Feedback cadence

Each wave ends with three artifacts:

1. a short progress-ledger update tied to a commit and CI run;
2. one replayable technical report with hashes and explicit evidence limits; and
3. one human-visible mathematical checkpoint: an independently compiled proof, a fidelity-blocked
   mutation, or an evidence-backed gap.

Benchmark changes are repeated at least three times for stochastic calls. Model or code upgrades
create a new matrix revision rather than overwriting old results.

## Immediate blockers and operator inputs

The current iteration does not require an API key. The first online regression requires:

- one approved Codex/OpenAI or custom-compatible endpoint;
- an operator-owned secret reference resolvable outside the workspace;
- a hard total budget and per-attempt timeout; and
- permission to send only cases whose rights record allows that endpoint class.

The Builder pilot additionally requires a qualified reviewer and an explicit source-use/egress
decision. Until then, source acquisition and synthetic fidelity tests can proceed, but no pilot
statement becomes `frozen`.
