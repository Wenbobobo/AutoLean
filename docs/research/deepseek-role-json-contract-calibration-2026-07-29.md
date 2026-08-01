# DeepSeek V4 Pro role JSON-contract calibration — 2026-07-29

## Status

This is a local, non-promotable operator observation. It is neither a model ranking, a role-floor
admission, a proof result, nor evidence of semantic fidelity. Builder remains responsible for
statement fidelity; this document concerns only the frozen Prover-side role-work interface.

The redacted machine record is
`docs/research/deepseek-role-json-contract-calibration-2026-07-29.json`. It contains no prompt,
candidate response, reasoning content, endpoint URL, secret, private handle, CAS address, receipt
body, or exact usage/cost.

## Locked run

- Provider/model: `deepseek` / `deepseek-v4-pro`; the authenticated `/models` catalog listed the
  exact model identifier before generation.
- Cases: five roles, two fixed synthetic calibration cases per role, ten trials total. No tools,
  Web access, FATE material, historical answer lookup, or retry were enabled.
- Budget: 512 input and 256 output tokens per trial; a ten-request role-only calibration has a
  local authorized static ceiling of 76,800 microUSD. Provider invoice cost is intentionally not
  inferred from this value.
- Request contract: `response_format=json_object` and `role_json_v1` were both included in the
  frozen generation-policy hash and each outbound-request hash. The policy describes object shape
  only; it does not include any case-specific expected output or evaluator oracle.
- Endpoint observation: all ten structured-output requests settled. This establishes that the
  request was accepted in this run; it is not independent certification of every structured-output
  behavior and cannot admit the capability to a production role floor.

## Result

The exact-JSON evaluator recorded one pass out of ten, in the task-allocation role. The remaining
nine failures split into five JSON-object parse rejections and four exact-value mismatches; there
were no transport failures after the catalog check. Per-role results remain separate:

| Role | Pass | Schema | Semantic |
| --- | ---: | ---: | ---: |
| Cheating supervisor | 0/2 | 2 | 0 |
| Fidelity reviewer | 0/2 | 1 | 1 |
| Prover | 0/2 | 0 | 2 |
| Statement formalizer | 0/2 | 1 | 1 |
| Task allocator | 1/2 | 1 | 0 |

The taxonomy is derived by a read-only, receipt-bound evaluator in the same private process. A
schema rejection means that the final candidate was not a strict JSON object. A semantic mismatch
means it was a strict JSON object but did not canonically equal the evaluator-owned answer. This
is deliberately a parse-level taxonomy, not a complete validator for every role-specific JSON
grammar: an object with extra or missing role fields is an exact-value mismatch in this V1
evaluator. Neither classification publishes candidate bytes or evaluator values.

All ten role sidecars report the `256_1023` output-token bucket while the frozen output ceiling is
256 tokens. The registry rejects a completion whose reported output usage exceeds that ceiling, so
each accepted trial reached the ceiling. The table is therefore not evidence that the model would
have produced the same final JSON with more room for private reasoning and its visible answer.

## Interpretation

The earlier prompt-only exact-JSON run produced 0/10 and is not a valid model-quality comparison
with this run: the request contract changed. The calibrated interface produced one exact match
under a fully saturated 256-token output ceiling. The observed parse/value split is useful
harness feedback, but it cannot distinguish an output-contract failure from a final answer crowded
out by the fixed reasoning/output budget. It is not evidence that the model is suitable for
autonomous proof, review, allocation, or statement conversion.

The separate bootstrap canary observation established a settled completion receipt and a locally
injected signer interruption recovered without a second provider call. It remains a connectivity
and completion-boundary check, not a capability or quality claim.

## Next controlled comparison

1. Keep the current ten-case suite and request budget fixed; repeat only after the code and prompt
   hashes are recorded, reporting a new run rather than overwriting this one.
2. Treat structured JSON as a request contract. Do not fall back to prompt-only JSON or silently
   remove `response_format` if a future endpoint rejects it.
3. Improve role APIs through versioned interface schemas and independently held-out cases, not by
   embedding case answers in prompts. The current grammar intentionally declares no case-specific
   reason code or expected proof.
4. Before interpreting JSON conformance, run a separately versioned budget-ablation with a larger
   output ceiling. Keep the cases, provider target, and evaluator fixed; record the changed policy
   hash and do not pool its scores with this saturated run.
5. Do not aggregate role scores into a single capability number. For Builder calibration, use the
   statement-formalizer and fidelity-reviewer slices only as non-promotable harness observations.
