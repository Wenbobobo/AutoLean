# DeepSeek V4 Pro five-role operator run

## Status

`scripts/deepseek_role_baseline.py` runs the locked ten-trial, five-role
answer-free suite against the fixed `deepseek-v4-pro` operator profile. It is a
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

The roots must be disjoint, absent, and have existing parent directories.
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
uv run python -m scripts.deepseek_role_baseline plan --operator-approved --state-root <ABS_STATE> --private-root <ABS_PRIVATE> --run-id deepseek-role-001 --max-cost-microusd-per-trial 100000
uv run python -m scripts.deepseek_role_baseline preflight --operator-approved --state-root <ABS_STATE> --private-root <ABS_PRIVATE> --run-id deepseek-role-001 --max-cost-microusd-per-trial 100000
uv run python -m scripts.deepseek_role_baseline run --operator-approved --state-root <ABS_STATE> --private-root <ABS_PRIVATE> --run-id deepseek-role-001 --max-cost-microusd-per-trial 100000
```

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
`run_authorized_role_floor_suite`, which registers, mints, and consumes one
short-lived capability at a time.

The locked per-trial limits are one attempt, 512 input tokens, 256 output tokens,
a 120-second provider timeout, a 30-second settlement margin, a 150-second model
authorization, and a 180-second lease. The CLI cost argument is copied exactly
into each of the ten cell budgets. Settlement uses a conservative local
10-microusd-per-token accounting coefficient; this is an authorization bound,
not a claim about the provider's current quoted price.

## Evidence and failure

Raw responses, response identifiers, exact usage, elapsed time, and
reconciliation journals are written only to the private root. A successful run
stores an authenticated private manifest plus a no-clobber, authenticated run
index. Its opaque handle remains inside the trusted process and operator-private
reconciliation path. Public report V2 exposes only
`private_evidence_committed: true`; neither the handle nor a CAS locator is
written to stdout.
The authorized bridge emits V2 suite/trial sidecars: the suite contains aggregate
token/time buckets and every trial contains its own coarse buckets. V1 sidecars
remain parseable historical contracts but are not accepted by the evaluator
because they lack the per-trial usage binding.

Stdout is one canonical JSON object. It contains the non-promotion authority
class, frozen budget and plan hash, and five role-separated sidecars. Successful
role sidecars contain two public trial hashes plus coarse token/time buckets.
They contain no response text, prompt, endpoint URL, path, secret, exception
message, exact usage, score, private handle, manifest digest, or private-store
locator.

A provider or network failure emits only a stable redacted `failure_class`.
Because the private dispatch journal is written before provider entry, such a
failure is normally `reconciliation_required`. The runner never retries the
provider automatically. An operator must inspect the private state and choose a
new run deliberately; the public failure record is not replay permission.

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

`benchmarks.authorized_role_evaluation.evaluate_authorized_role_suite_exact_json`
is the integration point for a DeepSeek runner that elects to evaluate a
successfully settled suite. Call it while the exact `suite_sidecar` and the same
`PreparedDeepSeekRoleOperator.raw_output_store` are still available:

```python
from benchmarks.authorized_role_evaluation import (
    evaluate_authorized_role_suite_exact_json,
)

evaluation = evaluate_authorized_role_suite_exact_json(
    prepared.plan.suite,
    suite_sidecar,
    raw_output_store=prepared.raw_output_store,
)
```

The private store first authenticates the opaque manifest handle and checks its
MAC, run binding, canonical manifest hash, and ten coordinate/authorization
bindings. The evaluator then joins all ten entries to the locked suite and
answer-free sidecars. Only after that complete join does it request each
`ModelResponse`; every read reauthenticates the handle, requires the exact
manifest entry, checks reconciliation state and usage, and verifies the response
through its content-addressed hash. The reconciliation state's `bundle_id` must
also equal the exact prepared work bundle. Before scoring, the evaluator
recomputes every trial bucket and the suite aggregate from authenticated exact
usage and elapsed values; any missing or altered bucket fails closed.

Candidate text must be one JSON object. Duplicate keys at any depth, `NaN`,
infinite values, arrays, scalars, and malformed JSON score zero. A valid object
is compared to the evaluator-owned oracle by canonical JSON bytes. Parse details
are not returned.

The resulting
`AuthorizedRoleExactJsonEvaluationReportV1` contains only run and model identity,
an evaluator commitment, opaque coordinate hashes, per-trial pass/score and
keyed, domain-separated output commitments, and five separate role metrics. The
private store derives commitments through the already injected manifest
authenticator; the evaluator never constructs them from a public unsalted hash.
They bind the private response hash to its opaque coordinate and exact bundle,
remain stable for the same authenticated entry, and are not enumerable private
CAS addresses. Its fixed authority fields are:

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
