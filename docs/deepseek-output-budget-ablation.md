# DeepSeek output-budget ablation

The supported CLI entrypoint `python -m scripts.deepseek_output_budget_ablation` is the only
operator path for a bounded comparison between the locked five-role suite's 256-output-token
control and one larger output ceiling. Do not invoke the
`scripts/deepseek_output_budget_ablation.py` file path directly; the module entrypoint is required
for workspace package resolution. It
measures receipt-bound completion-budget saturation only. It is not a model benchmark, competence
claim, role-floor admission, proof result, semantic-fidelity result, or Builder calibration.

## Frozen protocol

Protocol version `deepseek-role-output-budget-ablation-v1` has exactly two arms:

| Arm | Output limit | Trials | Provider-call allowance |
| --- | ---: | ---: | ---: |
| Control | 256 | 10 | 10 |
| Candidate | 512 or 1024 | 10 | 10 |

The hard total is 20 provider calls. An arm has exactly one attempt per trial. The protocol never
retries a failed request, substitutes a model or provider, removes `response_format=json_object`,
or falls back from the existing DeepSeek-only profile. If the 256 arm is not fully settled, the
candidate arm is marked `skipped`; if the candidate fails, no saturation comparison is emitted.

The following are fixed across arms: provider/model/revision/configuration, roles, fixture and
license bytes, cases, prompts, response-format and role-JSON contract, reasoning effort, timeout,
input limit, cost limit, source and rights bindings, evaluator implementation, and trial count.
The runner locally rejects a plan if a role cell differs outside `max_output_tokens`. Each changed
limit is bound into the role-cell budget, `ModelRequest.max_output_tokens`, outbound request hash,
authorization, completion receipt, suite definition, and arm plan hash.

The historical 2026-07-29 256-token observation cannot be inserted into a new authenticated
comparison: its private process-local authenticator and completion reader are deliberately not
portable. A new ablation therefore executes a fresh 256 control arm, rather than attempting to
reuse or rescore the historical public record.

## Operator invocation

The runner accepts `plan`, `preflight`, and `run`. Use `uv` with the module under `scripts/`; keep
the command parameters in an operator-owned command file rather than copying secrets or long
shell history into the checkout. Each mode must use a distinct disposable state/private parent
pair:

```text
uv run --frozen python -m scripts.deepseek_output_budget_ablation plan --operator-approved --state-parent <ABS_PLAN_STATE_PARENT> --private-parent <ABS_PLAN_PRIVATE_PARENT> --run-id <short-safe-id> --candidate-output-tokens 512 --max-cost-microusd-per-trial <explicit-bound>
uv run --frozen python -m scripts.deepseek_output_budget_ablation preflight --operator-approved --state-parent <ABS_PREFLIGHT_STATE_PARENT> --private-parent <ABS_PREFLIGHT_PRIVATE_PARENT> --run-id <short-safe-id> --candidate-output-tokens 512 --max-cost-microusd-per-trial <explicit-bound>
uv run --frozen python -m scripts.deepseek_output_budget_ablation run --operator-approved --state-parent <ABS_RUN_STATE_PARENT> --private-parent <ABS_RUN_PRIVATE_PARENT> --run-id <short-safe-id> --candidate-output-tokens 512 --max-cost-microusd-per-trial <explicit-bound>
```

All six parent placeholders above name different existing physical directories. The runner derives
absent `<run-id>-b256` and `<run-id>-b<candidate>` children under each pair. The write-free `plan`
parents are still invocation-specific inputs; `preflight` publishes four disposable readiness
roots, and `run` must derive four fresh roots under its own parents. No mode may resume, overwrite,
or reinterpret another mode's roots.

For the existing ignored operator reference, add `--secret-file llm.txt`. The strict parser accepts
only the existing API-key assignment shape, rejects links/reparse points and ambiguous secret
material, and creates the private-manifest HMAC key ephemerally in memory. It does not copy either
secret into `.env`, a profile, stdout, a report, or an artifact. Omitting `--secret-file` preserves
the standard environment-variable path below; `plan` never reads the file even if supplied.

`run-id` is an ASCII slug of at most 48 characters. State and private parents must be separate,
existing physical directory trees outside the checkout; derived roots are subject to the same
identity, link/junction, ownership-marker, quarantine, and no-overwrite rules as the five-role
operator runner. A later experiment requires a new run identity and another fresh parent set.

The only secret references are unchanged from the role runner:

- `AUTOLEAN_DEEPSEEK_API_KEY` for the profile-selected endpoint;
- `AUTOLEAN_ROLE_MANIFEST_HMAC_KEY` for the private completion-manifest mapping.

They must be distinct, are read only from the process environment, and are never copied into a
workspace, report, fixture, command output, or custom endpoint configuration. The static local
authorization bound uses 10 microUSD per input or output token. The supplied per-trial limit must
cover the larger arm: at least 10,240 microUSD for 512 or 15,360 microUSD for 1024. This is only a
local reservation ceiling, not an assertion of provider billing.

`plan` performs no provider I/O or root write. `preflight` validates and initializes both arms but
performs zero provider calls; it consumes a dedicated root set that is retained rather than
automatically deleted. `run` preflights and settles the
256 arm first, then preflights and settles the larger arm only after the control settles. This
sequencing avoids treating a partial run as authorization to replay it.

The CLI returns zero only for `planned`, `preflight_ready`, or `settled`. It returns `2` for
`execution_refused` and `reconciliation_required`; orchestration must check both the exit code and
the JSON `status`, and must never retry an existing run/root after either failure status.

That fixed control-first order also creates a time/order confound: endpoint load or alias behavior
may drift between arms. Consequently even a complete 20-call report is a descriptive saturation
observation, not a causal estimate of the token limit. A future causal comparison would need a new
protocol version with counterbalanced or interleaved execution; V1 results cannot be relabelled.

## Public evidence and limits

Successful stdout is one canonical JSON object at
`autolean.deepseek-output-budget-ablation.v1`. It includes the two plan hashes, fixed protocol
identity, a hard call ceiling and observed call count, redacted per-arm status, and role-local
counts of receipts whose exact private `output_tokens` equal the arm ceiling. It includes no
response text, prompt, evaluator oracle, response ID, endpoint URL, secret, path, private handle,
CAS locator, receipt body, nonce, exact usage, exact cost, score, winner, or provider invoice.

The runner invokes the existing receipt-bound structural evaluator only inside the same private
process to revalidate completion binding and calculate saturation. It discards parse, schema, and
exact-value fields before constructing the ablation report. The public comparison is deliberately
limited to `candidate_minus_baseline_saturated_trials`; a decrease in saturation says only that
fewer completed responses exactly reached that arm's requested output limit. It does **not** show
that any response is correct, that the candidate is better, or that a role is competent.

Private output CAS and authenticated completion manifests remain under each operator-private arm
root. As with the base runner, a receipt interruption requires private reconciliation of the same
artifact and never authorizes another provider dispatch. Test-only local HMAC remains
non-promotable; it is not a KMS/HSM, independent provider evaluator, Lean kernel check, or
semantic review.

## Observed 2026-07-29 run

The 512-token protocol preflight completed with zero provider calls and both arms marked
`preflight_ready`. The subsequent fresh run dispatched exactly one 256-token control request; that
request ended as the redacted failure class `network`. The run therefore entered
`reconciliation_required`, made no automatic retry, skipped the 512-token arm, and emitted no
comparison. The content-addressed public report is
[deepseek-output-budget-ablation-2026-07-29.json](research/deepseek-output-budget-ablation-2026-07-29.json),
SHA-256 `d49f0fe94cfbd7cdc162c5bc9a4a49c6c3b2f3e907dbba6c82b9d6c206654a31`.

This is a transport interruption record, not evidence for or against DeepSeek capability. A later
attempt must use a new run identity and fresh roots; it cannot resume, overwrite, or combine this
partial run with another arm.

## Observed 2026-07-30 independent rerun

A new run identity and fresh state/private roots were used after the operator reported that the
network had recovered. The control arm again dispatched exactly one request and returned the
redacted failure class `network`; automatic retry remained disabled and the 512-token arm made zero
calls. No saturation comparison or competence claim was produced. The public report is
[`deepseek-output-budget-ablation-2026-07-30.json`](research/deepseek-output-budget-ablation-2026-07-30.json),
SHA-256 `43196ba6b4a466aea9a353f8e4b4f7aa42402afaed1e8bdebd239e51007ef219`.

The repeated result is evidence about this Codex sandbox route only. It is not an endpoint-outage,
authentication, billing, or model-quality diagnosis, and it must not be merged with the prior
partial run as though the two arms of one experiment had completed.

## Observed 2026-07-30 settled run

After the operator confirmed the credential and route, a third run used another identity and six
mode-specific parent directories. The write-free plan and zero-call preflight both matched
experiment binding `f1a562616d343193163b34be8b9c8c05c88b3f500982f04f122432ccd136ca6c`.
The fresh run then settled all 20 permitted requests with ten distinct reservations, receipts, and
settlements in each arm and no retry event.

The 256-token arm reached its ceiling in 4 of 10 trials: two cheating-supervisor trials, one
fidelity-reviewer trial, and one statement-formalizer trial. The 512-token arm reached its ceiling
in 1 of 10 trials, a statement-formalizer trial. Thus 512 is the better bounded choice for the next
scored observation, but one residual saturation remains and the fixed control-first order remains
a confound. The result does not establish that any output was correct.

The exact public contract is
[`deepseek-output-budget-ablation-2026-07-30-settled-a.json`](research/deepseek-output-budget-ablation-2026-07-30-settled-a.json),
SHA-256 `cea53c21348e896e0b0fefa6713505471f4ea7b94c43317df913f666d46f6c31`.
An independent aggregate ledger query, performed without reading private response content, found
20 reserved and 20 settled events, 20 receipts, and 20 settlements. Its local receipt-bound
accounting total is 85,990 microUSD; this is not a provider invoice. The redacted aggregate is
[`deepseek-output-budget-ablation-2026-07-30-settled-a-ledger-audit.json`](research/deepseek-output-budget-ablation-2026-07-30-settled-a-ledger-audit.json),
SHA-256 `c4de8fd7b5fd6180f8527129568e9c65dc50aef6418e461487052f368468e053`.

Both artifacts remain `non-promotable`: they select a local output budget and demonstrate bounded
settlement/accounting behavior only. They are not role-floor, Builder-fidelity, Prover, Lean, or
release evidence.
