# DeepSeek output-budget ablation

`scripts/deepseek_output_budget_ablation.py` is the only operator path for a bounded comparison
between the locked five-role suite's 256-output-token control and one larger output ceiling. It
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
shell history into the checkout:

```text
uv run python -m scripts.deepseek_output_budget_ablation run --operator-approved --state-parent <existing-absolute-directory> --private-parent <existing-absolute-directory> --run-id <short-safe-id> --candidate-output-tokens 512 --max-cost-microusd-per-trial <explicit-bound>
```

For the existing ignored operator reference, add `--secret-file llm.txt`. The strict parser accepts
only the existing API-key assignment shape, rejects links/reparse points and ambiguous secret
material, and creates the private-manifest HMAC key ephemerally in memory. It does not copy either
secret into `.env`, a profile, stdout, a report, or an artifact. Omitting `--secret-file` preserves
the standard environment-variable path below; `plan` never reads the file even if supplied.

`run-id` is an ASCII slug of at most 48 characters. The runner derives two absent children named
`<run-id>-b256` and `<run-id>-b<candidate>` below each parent. State and private parents must be
separate, existing physical directory trees outside the checkout; roots are subject to the same
identity, link/junction, ownership-marker, quarantine, and no-overwrite rules as the five-role
operator runner. Do not use a `preflight` root again for `run`; select fresh roots for the actual
execution.

The only secret references are unchanged from the role runner:

- `AUTOLEAN_DEEPSEEK_API_KEY` for the profile-selected endpoint;
- `AUTOLEAN_ROLE_MANIFEST_HMAC_KEY` for the private completion-manifest mapping.

They must be distinct, are read only from the process environment, and are never copied into a
workspace, report, fixture, command output, or custom endpoint configuration. The static local
authorization bound uses 10 microUSD per input or output token. The supplied per-trial limit must
cover the larger arm: at least 10,240 microUSD for 512 or 15,360 microUSD for 1024. This is only a
local reservation ceiling, not an assertion of provider billing.

`plan` performs no provider I/O or root write. `preflight` validates and initializes both arms but
performs zero provider calls; it is a disposable readiness action. `run` preflights and settles the
256 arm first, then preflights and settles the larger arm only after the control settles. This
sequencing avoids treating a partial run as authorization to replay it.

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
