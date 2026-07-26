# Phase 1 Assurance Case

**Decision: no-RC.**

This is an assurance case for the Phase 1 architecture, not a progress percentage and not a
benchmark report.  It records the strongest conclusion justified by the repository without
turning an implementation, a fake fixture, or an operator command into evidence that the command
was run.  The current repository can make narrowly testable safety claims; it does not yet carry
the authoritative evidence required for a Phase 1 release candidate.

The north-star invariant remains unchanged: Builder decides whether a mathematical source was
faithfully frozen into a contract; Prover searches only for a proof of that frozen revision.
Neither role may repair the other role's conclusion by silently changing a statement.

**Working-tree update, 2026-07-27.** The current tree adds local ModelWork V2, an authorized
ten-trial role bridge and V2 evaluator, the FATE common executor, hardened Dashboard event
projection, a typed T7 module receipt, a synthetic 1,000-job chaos result, and a McKay opening
alignment discovery. These are implementation/test or explicitly non-promotable local records.
The DeepSeek bootstrap canary reached redacted `execution_refused/network`; the five-role runner's
`plan` and `preflight` completed, but its single live attempt reached
`reconciliation_required/network` without a model response. These are failure-path observations,
not model results. The session cannot invoke WSL (`Wsl/Service/E_ACCESSDENIED`), so no fresh
Docker/Lean receipt exists for this revision. The `no-RC` decision remains unchanged.

## Evidence vocabulary

The labels below are deliberately ordered neither by convenience nor by optimism.  A later label
cannot be inferred from an earlier one.

| Label | Meaning in this case | Does not establish |
| --- | --- | --- |
| `unit` | Deterministic Python or TypeScript tests of a component's input, output, and rejection behaviour | A real Lean build, a real model request, or an independent human decision |
| `synthetic` | A controlled fake provider, fake verifier, test fixture, or scripted change case exercised an integration path | Capability of a model, semantic fidelity of a source, or authority of a production service |
| `operator-local` | A documented command can be run by an authorized operator in the specified host/WSL environment and retains a redacted local result | That it was run for this revision, that its result is independently authoritative, or that it admits a release |
| `authoritative` | A retained, independently authenticated result binds the pinned source, environment, lease, revision, and verifier or reviewer identity required by the relevant acceptance rule | Any separate Builder, Prover, rights, or research conclusion not bound by that result |

The commands below are **replay commands**.  Their presence is exact repository evidence; this
document does not claim that every command has run on the checkout that contains it.  A future
ledger entry may cite a command only with its pinned revision, result digest, execution class, and
the gate it closes.

## Assurance argument

### A1. Builder fidelity is structurally separated from proof search

**Claim.** The Builder path can bind source/rights preparation, candidate formalizations,
mutation obligations, and a fidelity decision to a draft contract before a freeze is attempted.
It is designed to reject a proposed formalization whose type, source binding, or required review
evidence does not match the draft.

**Exact evidence.**

- Implementation: [`Builder/src/autolean_builder/source_harness.py`](../Builder/src/autolean_builder/source_harness.py),
  [`Builder/src/autolean_builder/fidelity_harness.py`](../Builder/src/autolean_builder/fidelity_harness.py),
  and [`Builder/src/autolean_builder/workflow.py`](../Builder/src/autolean_builder/workflow.py).
- Replay command:

  ```text
  uv run --frozen pytest Builder/tests/test_source_harness.py Builder/tests/test_workflow.py Builder/tests/test_pilot_harness.py Builder/tests/test_local_calibration.py
  ```

- The committed local-calibration material is explicitly a project-synthetic fixture in
  [`Builder/pilots/local-calibration/`](../Builder/pilots/local-calibration/), with its public
  boundary checked by [`scripts/tests/test_public_readiness.py`](../scripts/tests/test_public_readiness.py).

**Evidence class.** `unit` plus `synthetic` fixture coverage.

**Non-claim.** This does not prove that any textbook proposition has been translated faithfully,
that a domain expert independently approved a contract, or that the fixture's illustrative Lean
text is a theorem admission.  Candidate agreement and mutation coverage are evidence obligations,
not semantic truth.

**Remaining acceptance gate.** A rights-cleared source must receive an independently attributable
semantic/admission decision, then produce a frozen `StatementContractV1` with retained fidelity
evidence.  The freeze must remain distinct from the subsequent kernel verification.

### A1a. Textbook opening alignment is a bounded discovery aid, not a conversion result

**Claim.** The Builder can bind a locally cached source document to a derived-text opening sample,
keep the excerpt private, and publish only redacted hashes/locators for a human-led alignment
worksheet.

**Exact evidence.** [`Builder/src/autolean_builder/textbook_alignment.py`](../Builder/src/autolean_builder/textbook_alignment.py),
[`scripts/textbook_alignment.py`](../scripts/textbook_alignment.py), and
[the McKay discovery record](research/mckay-opening-textbook-alignment-discovery-2026-07-27.md).
The produced status is exactly `textbook_alignment_discovery_nonfreeze`.

**Evidence class.** Local provenance and unit coverage.

**Non-claim.** The McKay opening observation did not extract or normalize a proposition, generate
a Lean statement, map to mathlib, freeze a contract, call a model, or send work to Prover. A
missing form-feed page boundary was retained as an extraction limitation rather than silently
inventing a theorem.

**Remaining acceptance gate.** A future calibration sample needs explicit source rights, a
reviewed extraction, independent formalization candidates, mutation/positive/negative evidence,
and human semantic review before it can enter the freeze path.

### A2. The Builder--Prover bridge is revision-bound and one-way

**Claim.** The public bridge is intended to hand Prover an immutable Builder-produced bundle,
rather than letting Prover read mutable Builder state or alter the selected statement.

**Exact evidence.**

- Protocol and contract implementation: [`docs/protocol.md`](protocol.md),
  [`packages/contracts/src/autolean_contracts/`](../packages/contracts/src/autolean_contracts/),
  and [`packages/control_plane/src/autolean_control_plane/`](../packages/control_plane/src/autolean_control_plane/).
- Integration test: [`benchmarks/tests/test_builder_prover_closed_loop.py`](../benchmarks/tests/test_builder_prover_closed_loop.py).
- Replay command:

  ```text
  uv run --frozen pytest packages/contracts/tests packages/control_plane/tests benchmarks/tests/test_builder_prover_closed_loop.py
  ```

**Evidence class.** `unit` and `synthetic` integration coverage.

**Non-claim.** A passing closed-loop fixture is not evidence that a real source was frozen,
that Lean was run in the authority environment, or that an accepted proof is semantically the
source proposition.  In particular, a control-plane event sequence cannot substitute for the
Builder review gate.

**Remaining acceptance gate.** One independently reviewed Builder contract must traverse the
same versioned bridge, preserve its revision/type/environment identity, and be verified by the
independent Lean worker without any statement rewrite.

### A3. Model work requires a rights-bound, prompt-free admission object

**Claim.** Benchmark and orchestration work are represented separately from theorem contracts.
The admission payload binds an immutable, role-specific model-work bundle with typed source and
rights projections, egress, context, request, and environment hashes; extraneous prompt or source
text fields are rejected by schema validation.

**Exact evidence.**

- Implementation: [`packages/contracts/src/autolean_contracts/model_work.py`](../packages/contracts/src/autolean_contracts/model_work.py) and
  [`packages/control_plane/src/autolean_control_plane/model_authorization.py`](../packages/control_plane/src/autolean_control_plane/model_authorization.py).
- Role execution bridge: [`benchmarks/authorized_role_bridge.py`](../benchmarks/authorized_role_bridge.py)
  derives ten canonical trials, performs the whole-suite pure preflight before state mutation,
  authenticates the private run index and exact private usage, and exposes only keyed,
  non-addressable public commitments with no private handle. The V2 evaluator at
  [`benchmarks/authorized_role_evaluation.py`](../benchmarks/authorized_role_evaluation.py)
  accepts strict exact JSON, recomputes trial and suite usage, and is explicitly non-production.
- Replay command:

  ```text
  uv run --frozen pytest packages/contracts/tests/test_model_work.py Prover/tests/test_model_execution_authorization.py benchmarks/tests/test_authorized_role_bridge.py benchmarks/tests/test_authorized_role_evaluation.py
  ```

**Evidence class.** `unit` and `synthetic` authorization coverage, plus a local software-root-of-
trust fixture for private-manifest binding. The bridge deliberately labels itself non-promotable.

**Non-claim.** Local HMAC fixtures and schema rejection do not constitute an independently
operated admission authority, a source-rights decision for a real external request, or a completed
model run. The ten canonical trials are not a role-floor score. Hashes also do not make an
unreviewed source lawful to export.

**Remaining acceptance gate.** Use an independently managed `MODEL_WORK_ADMISSION` signer for a
real, rights-cleared bundle and retain its attestation outside the model's writable workspace.

### A4. Provider requests have a bounded policy surface

**Claim.** Provider selection is separate from execution authorization.  The provider layer has
capability checks and request objects, while operator profiles constrain approved configuration;
the repository policy excludes Anthropic and Claude rather than providing them as fallbacks.

**Exact evidence.**

- Implementation: [`Prover/src/autolean_prover/providers/`](../Prover/src/autolean_prover/providers/),
  [`Prover/operator-profiles/`](../Prover/operator-profiles/),
  [`scripts/deepseek_authorized_canary.py`](../scripts/deepseek_authorized_canary.py), and
  [`scripts/deepseek_role_baseline.py`](../scripts/deepseek_role_baseline.py).
- Policy: [`docs/model-provider-policy.md`](model-provider-policy.md) and
  [`docs/deepseek-authorized-canary.md`](deepseek-authorized-canary.md), plus the
  [`docs/deepseek-role-operator.md`](deepseek-role-operator.md) procedure.
- Replay command:

  ```text
  uv run --frozen pytest Prover/tests/test_providers.py Prover/tests/test_operator_profiles.py Prover/tests/test_model_execution_authorization.py scripts/tests/test_deepseek_authorized_canary.py scripts/tests/test_deepseek_role_baseline.py
  ```

**Evidence class.** `unit` and `synthetic` policy coverage. The operator-local canary returned
redacted `execution_refused/network`. The five-role V2 runner completed credential-free `plan` and
authorization-aware `preflight`, while its single permitted live attempt reached
`reconciliation_required/network`. No invocation returned a model response or created a benchmark
result. The operator sequence is:

```text
uv run --frozen python -m scripts.deepseek_role_baseline plan --operator-approved --state-root <ABS_STATE> --private-root <ABS_PRIVATE> --run-id <RUN_ID> --max-cost-microusd-per-trial <LIMIT>
uv run --frozen python -m scripts.deepseek_role_baseline preflight --operator-approved --state-root <ABS_STATE> --private-root <ABS_PRIVATE> --run-id <RUN_ID> --max-cost-microusd-per-trial <LIMIT>
uv run --frozen python -m scripts.deepseek_role_baseline run --operator-approved --state-root <ABS_STATE> --private-root <ABS_PRIVATE> --run-id <RUN_ID> --max-cost-microusd-per-trial <LIMIT>
```

**Non-claim.** No provider capability, availability, cost, or model-quality result follows from
the static profile, fake provider tests, or the observed network refusal. A bootstrap canary is
explicitly neither a role-floor admission nor a benchmark score.

**Remaining acceptance gate.** Replay the bounded request only when the authority environment has
deliberate egress, with operator-owned environment credentials, independent admission and
execution authorization, redacted private retention, and a separately recorded result. A later
role comparison additionally needs an independently operated evaluator and the fixed repeated-run
protocol.

### A5. T6 OCI/library-substrate receipts are fail-closed at the design and test boundary

**Claim.** The Library substrate route distinguishes a Builder statement/type query from proof
submission and specifies a content-addressed image receipt rather than trusting an image tag or a
host-mounted result.

**Exact evidence.**

- Implementation: [`Library/scripts/library_substrate_image.py`](../Library/scripts/library_substrate_image.py),
  [`scripts/oci_mathlib_worker.py`](../scripts/oci_mathlib_worker.py), and
  [`Prover/worker/Dockerfile.library-substrate`](../Prover/worker/Dockerfile.library-substrate).
- Replay command:

  ```text
  uv run --frozen pytest scripts/tests/test_library_substrate_image.py scripts/tests/test_oci_mathlib_worker.py Prover/tests/test_authoritative_oci_execution.py
  ```
- Operator-local command:

  ```text
  uv run --frozen python -m Library.scripts.library_substrate_image all
  ```

**Evidence class.** Test coverage is `unit`/`synthetic`; the last command defines an
`operator-local` route only until it produces a new retained Docker `RepoDigest` receipt.

**Non-claim.** The Dockerfile, wrapper, and test records do not prove that Docker/WSL built the
current image, that the pinned Lean/mathlib environment compiled cleanly, or that a query receipt
may be used as a proof.  The Builder-only query remains proof-ineligible.

**Remaining acceptance gate.** Run the admitted frozen contract through the authority
environment's real OCI/Lean route; preserve the fresh Docker image digest, content-bound receipt,
gateway replay, and rejection controls, and retain a frozen-to-verified result without changing
the contract. The Builder-only query must remain proof-ineligible and separate from proof
verification.

### A6. T7 has a typed multi-file scheduling and result-recording path

**Claim.** The twenty-declaration fixture distinguishes declared API invalidation from the
conservative Lean module rebuild closure.  Its typed path binds changed-source witnesses,
successor manifests, terminal node states, artifact identity, and lease/fencing semantics instead
of accepting a self-declared success state.

**Exact evidence.**

- Implementation: [`benchmarks/real_lean_project_dag_rebuild.py`](../benchmarks/real_lean_project_dag_rebuild.py),
  [`benchmarks/real_lean_project_dag_execution.py`](../benchmarks/real_lean_project_dag_execution.py),
  [`benchmarks/real_lean_project_dag_worker_contract.py`](../benchmarks/real_lean_project_dag_worker_contract.py), and
  [`benchmarks/real_lean_project_dag_module_build.py`](../benchmarks/real_lean_project_dag_module_build.py).
- Replay command:

  ```text
  uv run --frozen pytest benchmarks/tests/test_real_lean_project_dag.py benchmarks/tests/test_real_lean_project_dag_rebuild.py benchmarks/tests/test_real_lean_project_dag_execution.py benchmarks/tests/test_real_lean_project_dag_worker_contract.py benchmarks/tests/test_real_lean_project_dag_module_build.py scripts/tests/test_real_lean_changed_source_preflight.py
  ```
- Operator-local preflight: [`docs/t7-real-lean-changed-source-preflight.md`](t7-real-lean-changed-source-preflight.md).
- The current module-receipt verifier also checks that the typed frozen specification and leased
  request name the same job; an injected cross-job receipt is rejected before public verification.

**Evidence class.** `synthetic` fixture and typed-control-plane coverage.  The real-Lean
preflight is an `operator-local` diagnostic until its WSL/OCI receipt is retained and authenticated.

**Non-claim.** This fixture is not cross-file theorem-library construction, an authoritative Lean
module build, a model-driven integration run, or evidence that an arbitrary declaration change is
semantics-preserving.

**Remaining acceptance gate.** Execute the immutable worker bundle in the authority OCI/Lean
environment under a live lease, then retain authenticated per-module results, clean integration,
and replay evidence.  The broader 1,000-job process-chaos gate remains separate.

### A7. FATE is a controlled Prover evaluation route, not architecture acceptance by score

**Claim.** FATE suite selection, source locking, answer exclusion, private response retention,
model-work admission, and verifier receipt interfaces are represented in the common execution
path.  Regression, comparison, and full-suite selections are distinct by construction.

**Exact evidence.**

- Lock and adapter: [`benchmarks/fate.lock.json`](../benchmarks/fate.lock.json),
  [`benchmarks/fate_adapter.py`](../benchmarks/fate_adapter.py), and
  [`benchmarks/fate_execution.py`](../benchmarks/fate_execution.py).
- Protocol: [`docs/fate-authorized-execution-v1.md`](fate-authorized-execution-v1.md).
- Replay command:

  ```text
  uv run --frozen pytest benchmarks/tests/test_fate.py benchmarks/tests/test_fate_adapter.py benchmarks/tests/test_fate_execution.py scripts/tests/test_fate_execution_preflight.py
  ```
- Credential-free operator preflight:

  ```text
  uv run --frozen python scripts/fate_execution_preflight.py --help
  ```

**Evidence class.** `unit` and `synthetic` fake-provider/fake-verifier coverage; the preflight is
an `operator-local` configuration check. The common executor has distinct `regression-48`,
`model-compare-90`, and `FATE-350` selections, preflights authorization before ModelWork state
mutation, and carries a deterministic attempt seed across restart projections.

**Non-claim.** No FATE model call, verified proof, pass@1/pass@4, cost, or ranking is established
here.  A test-only receipt authenticator is not a production independent verifier, and FATE cannot
prove Builder semantic fidelity or multi-file library scalability.

**Remaining acceptance gate.** Run the selected suites against the pinned checkout through a real
authorized provider and separately operated verifier in the authority environment, publishing
M/H/X results separately with fixed prompt, tools, retrieval, attempts, timeouts, and budgets.

### A8. Dashboard is an observation surface, not a control surface

**Claim.** The Dashboard API and UI are designed to render read-only projections of mathematical,
formal, and execution evidence.  It must not expose provider prompts, raw artifacts, or mutation
endpoints as a convenience path.

**Exact evidence.**

- Implementation: [`Dashboard/api/src/autolean_dashboard/`](../Dashboard/api/src/autolean_dashboard/) and
  [`Dashboard/ui/src/`](../Dashboard/ui/src/).
- Replay commands:

  ```text
  uv run --frozen pytest Dashboard/api/tests
  pnpm --dir Dashboard/ui test
  pnpm --dir Dashboard/ui build
  ```

**Evidence class.** API/UI test coverage is `unit`; fixture-driven graph rendering is
`synthetic`.

**Non-claim.** A successful API test or production bundle does not prove the panel is visually
correct at desktop/mobile sizes, safely authenticated for remote access, or safe against every
browser/XSS integration condition. Controlled-browser visual QA was unavailable in the current
session. The panel does not decide promotions.

**Remaining acceptance gate.** Perform controlled-browser desktop/mobile, sanitization/XSS, and
authenticated remote-access tests before any non-loopback deployment; retain their result as
operator or authoritative evidence according to the execution environment.

### A9. Synthetic control-plane chaos resists duplicate and stale work, within its stated scope

**Claim.** The process-chaos harness exercises the SQLite/CAS control-plane state machine under
large synthetic restart, replay, stale-fence, and duplicate-delivery pressure.

**Exact evidence.** A 1,000-job run recorded 1,000 expired-lease/stale-fence rejections, 4,000
duplicate-delivery replays, 5,000 contiguous/replay-consistent events, 4,000 CAS checks, no lost
job, and no duplicate terminal verdict. The harness and its boundary are documented in
[`docs/control-plane-process-chaos.md`](control-plane-process-chaos.md).

**Evidence class.** `synthetic` control-plane resilience.

**Non-claim.** This does not exercise Lean, OCI, provider egress, production signing, physical
power loss, or a real worker killed during a transaction. It does not authenticate a proof or
replace T6/T7 authority-environment evidence.

**Remaining acceptance gate.** Retain an authority-environment worker recovery result after the
T6 image-owned wrapper and T7 leased execution exist. Do not reclassify the synthetic result as
kernel or production evidence.

### A10. Public-release policy protects the source and operator boundary, but is not a release

**Claim.** The repository includes checks for candidate-tree secrets, restricted/operator-only
paths, source excerpts, license metadata, staged/worktree mismatch, and reachable-history
hazards.  It keeps operator credentials out of the tracked configuration surface.

**Exact evidence.**

- Implementation: [`scripts/public_readiness.py`](../scripts/public_readiness.py),
  [`scripts/secret_scan.py`](../scripts/secret_scan.py), and [`.env.example`](../.env.example).
- Replay command:

  ```text
  uv run --frozen pytest scripts/tests/test_public_readiness.py scripts/tests/test_secret_scan.py
  ```
- Release candidate command (run only from a clean, intentional staging checkout):

  ```text
  uv run --frozen python -m scripts.public_readiness
  ```

**Evidence class.** The test suite is `unit`; the final command is an `operator-local` release
preflight until a clean candidate tree and reachable history are actually scanned.

**Non-claim.** Passing the scanner would not prove that the public repository is usable, that
dependencies are secure, that historical credentials were rotated, or that Phase 1 has met its
Lean/model/review gates.

**Remaining acceptance gate.** Scan the exact staged release candidate and reachable history,
retain a redacted report, then combine it with SBOM, operations evidence, and every independent
technical acceptance gate.  Do not use a dirty development worktree as a release verdict.

## RC conclusion and evidence upgrades

The present conclusion is **no-RC**.  The repository has valuable structural and adversarial
coverage, but no row above is promoted to `authoritative` by code existence or by a passing fake
test.  At minimum, the following independent evidence is still required before an RC decision:

1. an independently reviewed, rights-cleared Builder statement frozen with full fidelity evidence;
2. an authority-environment Lean/OCI verification tied to that exact frozen revision;
3. a real T6 receipt and a leased, authenticated T7 multi-file worker result;
4. at least one actual authorized provider execution through the frozen role path with independent
   evaluation and production verifier evidence; a full FATE-350 or published model ranking is
   additionally required only when those benchmark claims are reported;
5. authority-environment T6/T7 recovery evidence beyond the completed synthetic chaos run, plus
   SBOM, operations, exact staged public-release, and controlled-browser evidence;
6. a release decision that names every remaining failed, waived, or unrun gate.

An evidence upgrade must add a result record, not edit this conclusion optimistically.  The record
must identify the source/contract revision, toolchain and image, relevant authority/reviewer,
execution class, immutable artifact or report digest, and the precise acceptance rule it closes.
It must also state what it still does **not** establish.
