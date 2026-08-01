# DeepSeek V4 Pro five-role operator run

## Status

The supported CLI entrypoint `python -m scripts.deepseek_role_baseline` runs the locked ten-trial,
five-role answer-free suite against the fixed `deepseek-v4-pro` operator profile. Do not invoke the
`scripts/deepseek_role_baseline.py` file path directly; the module entrypoint is the only documented
runner boundary. It is a
non-promotable observation path. The CLI does not score responses by default,
establish a model floor, admit the model to role benchmarks, or provide
production authority. An optional private exact-JSON API can score the synthetic
calibration answers locally; that report remains explicitly non-production and
is forbidden from role-floor admission.

The five roles are Prover, statement formalizer, fidelity reviewer, cheating
supervisor, and task allocator. Each role receives two synthetic locked cases.
The evaluator oracle is not included in any outbound request.

## Operator boundary

The command requires:

- `--operator-approved`;
- a dedicated absolute `--state-root` outside this checkout;
- a separate absolute `--private-root` outside this checkout; and
- an explicit `--max-cost-microusd-per-trial`.

Within each invocation the state and private roots must be disjoint, absent, and have existing
parent directories. `plan`, `preflight`, and `run` must each receive a different disposable
state/private root pair; do not reuse any root path between the three commands. `plan` writes
nothing, but its path pair is still invocation-specific operator input. `preflight` publishes
initialized state, so those roots are evidence from a zero-provider-call readiness check and are
never valid `run` roots.
Every parent component must be a physical directory rather than a symlink,
junction, or reparse point. Preflight snapshots the resolved parent path and its
filesystem identity, then rechecks both around claim, marker creation,
publication, and quarantine. It never opens, modifies, or deletes a pre-existing
root.

Two secrets are read only from the process environment:

- `AUTOLEAN_DEEPSEEK_API_KEY`;
- `AUTOLEAN_ROLE_MANIFEST_HMAC_KEY`.

The values must be distinct. The second value must contain at least 32 UTF-8
bytes. The runner does not read `llm.txt`, load dotenv files, create `.env`, copy
credentials into a workspace, or serialize secret values.

The model-execution and ModelWork-admission HMAC keys are generated in memory for
one process. They are explicitly ephemeral and non-production. The manifest HMAC
authenticates only the checkout-external private handle mapping; it is not a
production KMS/HSM authority.

## Commands

From the repository root:

```text
uv run --frozen python -m scripts.deepseek_role_baseline plan --operator-approved --state-root <ABS_PLAN_STATE> --private-root <ABS_PLAN_PRIVATE> --run-id deepseek-role-001 --max-cost-microusd-per-trial 100000
uv run --frozen python -m scripts.deepseek_role_baseline preflight --operator-approved --state-root <ABS_PREFLIGHT_STATE> --private-root <ABS_PREFLIGHT_PRIVATE> --run-id deepseek-role-001 --max-cost-microusd-per-trial 100000
uv run --frozen python -m scripts.deepseek_role_baseline run --operator-approved --state-root <ABS_RUN_STATE> --private-root <ABS_RUN_PRIVATE> --run-id deepseek-role-001 --max-cost-microusd-per-trial 100000
```

All six placeholders above name different paths. Treat the write-free `plan` pair as consumed by
that inspection, and retain any roots published or quarantined by `preflight` or `run` for
evidence/reconciliation rather than resuming another mode in them. Use a new run identity as well
when starting a genuinely new experiment rather than the three-step inspection of one frozen plan.

`plan` performs no state writes or provider I/O and needs no secret; it does read
the pinned profile, fixture, and license. `preflight` loads the two secret
references, validates all ten budgets, bindings, local capabilities, timeouts,
admission signatures, and cumulative validity windows, and checks both roots
before creating the operator database. It then registers only the operator
approval; the whole ten-trial gate leaves ModelWork state at zero and does not
probe or contact the provider. Initialization is published only after both roots
are complete. An earlier failure atomically moves each root still owned by this
invocation to a random marker-bound quarantine name beside the requested root.
Runtime never recursively deletes or cleans a quarantine. `run` repeats that
whole-suite gate and then delegates execution to
`run_completed_authorized_role_floor_suite`, which registers, mints, and
consumes one short-lived capability at a time.

The base operator CLI keeps its historical per-trial limits at one attempt, 512 input tokens,
256 output tokens, a 120-second provider timeout, a 30-second settlement margin, a 150-second
model authorization, and a 180-second lease. The CLI cost argument is copied exactly into each of
the ten cell budgets. Settlement uses a conservative local
10-microusd-per-token accounting coefficient; this is an authorization bound,
not a claim about the provider's current quoted price.

The scored wrapper `python -m scripts.deepseek_live_baseline` additionally accepts the frozen
`--max-output-tokens {256,512,1024}` option and binds it into every role cell, request,
authorization, and static cost check. This is not an adaptive per-role budget. A 512-token run
without another canary requires at least 102,400 microUSD of total local authorization and fresh
state/private roots:

```text
uv run --frozen python -m scripts.deepseek_live_baseline --operator-approved --secret-file llm.txt --state-root <ABS_NEW_STATE> --private-root <ABS_NEW_PRIVATE> --run-id <short-safe-id> --max-total-authorized-cost-microusd 102400 --max-output-tokens 512 --skip-canary --public-report docs/research/<unique-report>.json
```

The output-budget ablation selects an observation budget; it does not establish competence. The
wrapper's exact-JSON evaluator remains local, synthetic, role-separated, and non-promotable.

## Evidence and failure

Raw responses, response identifiers, exact usage, elapsed time, completion
nonces, and receipt bodies are written only to the private root. A successful
run stores each normalized response in `LocalPrivateModelOutputStore` and then
stores an authenticated private V2 completion manifest with the full ten
completion receipts plus a no-clobber authenticated run index. Its opaque handle
remains inside the trusted process and operator-private reconciliation path.
Public report V2 exposes only `private_evidence_committed: true`; neither the
handle nor a CAS locator is written to stdout.

The authorized bridge emits V3 suite/trial sidecars. Every public trial contains
the existing answer-free bindings, coarse token/time buckets, and exactly one
`ModelExecutionCompletionPublicV1`: completion ID, receipt hash, and salted
public output commitment. It does not contain a receipt body, nonce, private
artifact reference, response hash, response text, response ID, exact usage, or
cost. A V3 suite has exactly ten distinct completion IDs, receipt hashes, and
output commitments. V1/V2 sidecars remain historical contracts only; the
completion evaluator accepts V3.

Stdout is one canonical JSON object. It contains the non-promotion authority
class, frozen budget and plan hash, and five role-separated sidecars. Successful
role sidecars contain two public trial hashes plus coarse token/time buckets.
They contain no response text, prompt, endpoint URL, path, secret, exception
message, exact usage, score, private handle, manifest digest, or private-store
locator.

A provider or network failure emits only a stable redacted `failure_class`.
After a provider response, the control plane first persists an output-bound
completion settlement. If receipt signing or post-settlement persistence is
interrupted, it emits a credential-free recovery handle internally and the
provider must not be called again: `ProviderRegistry.recover_completed` settles
the same receipt from the private artifact. The runner never retries the
provider automatically. Any existing completion or authorization state turns a
later run invocation into `reconciliation_required`; the public failure record
is not replay permission.

Initialization failures that were moved aside report only
`operator_initialization_quarantined`; a parent or ownership drift that cannot
be moved safely reports `operator_initialization_manual_review`. Neither status
contains a path, marker, token, exception text, or the original failure detail.
The operator must inspect checkout-external sibling names matching
`.<requested-name>.autolean-quarantine-*`, verify the lifecycle marker and
contents, retain any evidence needed for diagnosis, and explicitly decide
whether disposal is appropriate. The runtime never makes that disposal
decision.

Parent identity checks narrow path-swap races but are not an operating-system
isolation boundary. A same-user process can still race individual filesystem
operations. Production use therefore requires operator-exclusive ACLs on both
parent chains and an authoritative WSL/Linux worker volume where untrusted
processes cannot rename or replace the selected parent directories. Detected
identity drift stops before provider work and reports manual review; quarantine
never recursively deletes or overwrites foreign bytes.

## Optional local exact-JSON evaluation

`benchmarks.authorized_role_evaluation.evaluate_completed_authorized_role_suite_exact_json`
is the integration point for a DeepSeek runner that elects to evaluate a
successfully settled suite. Call it while the exact `suite_sidecar` and the same
`PreparedDeepSeekRoleOperator` are still available:

```python
from benchmarks.authorized_role_evaluation import (
    evaluate_completed_authorized_role_suite_exact_json,
)
from benchmarks.authorized_role_bridge import AuthorizedRoleCompletionEvidenceReaderV2

evaluation = evaluate_completed_authorized_role_suite_exact_json(
    prepared.plan.suite,
    suite_sidecar,
    evidence_reader=AuthorizedRoleCompletionEvidenceReaderV2(
        manifest_store=prepared.completion_manifest_store,
        output_store=prepared.output_store,
        completion_verifier=prepared.authorization_service,
    ),
)
```

The private reader first authenticates the opaque manifest handle and checks its
MAC, run binding, canonical manifest hash, and ten coordinate/authorization
bindings. The evaluator then joins all ten entries to the locked suite and
answer-free V3 sidecars. For every entry, it verifies the completion receipt
before reading the one exact private artifact named by that receipt. It rejects a
receipt whose authorization or immutable work bundle is misbound. Before
scoring, it recomputes every trial bucket and the suite aggregate from the
receipt-bound exact usage and private elapsed values; any missing or altered
binding fails closed.

Candidate text must be one JSON object. Duplicate keys at any depth, `NaN`,
infinite values, arrays, scalars, and malformed JSON score zero. A valid object
is compared to the evaluator-owned oracle by canonical JSON bytes. Parse details
are not returned.

The resulting `AuthorizedRoleExactJsonEvaluationReportV1` contains only run and
model identity, an evaluator commitment, opaque coordinate hashes, per-trial
pass/score and receipt-derived public output commitments, and five separate role
metrics. The evaluator never constructs an unsalted output hash and does not
publish a private CAS address. Its fixed authority fields are:

```json
{
  "authority": "local_exact_json_nonproduction",
  "promotion_eligible": false,
  "role_floor_admission": "forbidden",
  "cross_role_aggregation_permitted": false
}
```

It contains no oracle, raw response, private handle or path, manifest digest,
reconciliation handle, or error text. Evaluation performs no provider call and
does not write the scripted-fake V3 benchmark store. A restart must reinject the
same operator-private authenticator and recover the opaque handle through the
authenticated private run index; it never depends on public stdout. Using a
different key fails closed. This
test-only HMAC boundary is not a substitute for KMS, remote attestation, Lean
verification, semantic fidelity review, or the role-specific production
evaluators.

## Local structural JSON grammar (V1)

`evaluate_completed_authorized_role_suite_structural_json` is a separate, receipt-bound,
read-only evaluator for the same settled V3 suite. It never sends a provider request or changes
provider behavior. Its fixed grammar version is `autolean.deepseek-role-json-grammar.v1` and
defines closed objects for all five roles: Prover, statement formalizer, fidelity reviewer,
cheating supervisor, and task allocator. Missing fields, extra fields, and wrong JSON types are
schema rejections; only a grammar-valid object proceeds to canonical exact-value comparison.

Each sanitized trial reports a completed `receipt_bound` transport outcome, strict-JSON outcome,
schema outcome, semantic-exact outcome, and whether its receipt-bound output-token count exactly
reached the frozen per-cell output ceiling. It publishes only the existing public output commitment
and role-local counts. It never publishes response text, parser diagnostics, endpoint data, a
private handle/path, receipt body, exact token count, or the evaluator-owned expected value.

A completed V3 receipt can establish only that a completion was bound and settled. It cannot
classify an absent, timed-out, or failed transport attempt because such an attempt has no
receipt-bound candidate artifact. Those states remain outside this evaluator rather than being
silently counted as JSON or schema failures. The structural report is local non-production
evidence, remains ineligible for promotion and role-floor admission, and must not be aggregated
across roles.

## Observed 2026-07-30 512-token scored run

After the separate output-budget experiment selected 512 for the next observation, the scored
wrapper used new external roots, skipped the already completed canary, and settled all ten role
requests with no retry. The local exact-JSON evaluator passed 2/10 cases, both task-allocation
cases. It recorded one schema rejection and seven semantic mismatches; Prover, statement
formalizer, fidelity reviewer, and cheating supervisor each passed 0/2.

The first public report is retained as
[`deepseek-live-baseline-2026-07-30-512-a.json`](research/deepseek-live-baseline-2026-07-30-512-a.json),
SHA-256 `ecac7ec0303ad2947a66c4b6d2b3a6eb74357269c2c2a29c66cc0e968febe3b2`.
It is a legacy V1 projection: its base role-report object carries scored extension fields that are
not declared by `DeepSeekRolePublicReportV2`, so it is preserved as historical JSON but is not the
normative machine-revalidation format. Its response-content-free ledger aggregate remains bound to
that exact file.

The corrected wrapper composes the unchanged base operator report inside
`DeepSeekRoleScoredObservationV1` and emits strict top-level
`autolean.deepseek-live-baseline.v2`. A second fresh 512-token run produced the same aggregate
outcome: 2/10 passes, one schema rejection, seven semantic mismatches, and one ceiling hit. The
normative V2 report is
[`deepseek-live-baseline-2026-07-30-512-b-v2.json`](research/deepseek-live-baseline-2026-07-30-512-b-v2.json),
SHA-256 `c8036e1283cb608ed17836eccdf8b075a71675965dee948b29ae97be4045e538`.
Its bound ledger aggregate records ten reservations/receipts/settlements and 47,940 microUSD of
local receipt-bound accounting:
[`deepseek-live-baseline-2026-07-30-512-b-v2-ledger-audit.json`](research/deepseek-live-baseline-2026-07-30-512-b-v2-ledger-audit.json),
SHA-256 `c2aab3f741030155d17228aacf0de0dd081935f1f473bc63523f87a15aa3fade`.
Neither local accounting value is a provider invoice.

The earlier 256-token observation and the two 512-token observations are different stochastic runs
against an unpinned API alias, not a paired causal comparison. The change from one passing case to
two therefore cannot be attributed to the token limit. Repeating the same 2/10 role distribution
improves confidence in this tiny fixture observation, but the total is still only four cases per
role across two non-independent runs. It is harness-calibration evidence, not a role floor or
competence claim.
