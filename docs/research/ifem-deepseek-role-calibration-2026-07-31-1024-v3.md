# iFEM DeepSeek role calibration: 1,024-token protocol v3

Date: 2026-07-31

Status: retained local provider-path and response-budget observation; non-promotable

## Bound run

- Provider/model request identity: `deepseek` / `deepseek-v4-pro` through the fixed official
  Chat Completions profile.
- Corpus: the same 16 project-authored, source-text-free iFEM structural role cases used by D34:
  eight statement-formalizer, four fidelity-reviewer, and four cheating-supervisor cases.
- Generation policy: 2,048 input tokens, 1,024 output tokens, high reasoning effort, structured
  JSON, required usage accounting, one attempt per case, and no automatic retry.
- Single-variable boundary: compared with D34, only the output-token ceiling changed from 512 to
  1,024. The model, graph, corpus, input limit, reasoning effort, prompt contract, and
  `selected_option_only.v2` response contract remained fixed.
- Result: all 16 provider calls settled in 388 seconds, the authenticated private manifest
  committed, and D33 independently rebuilt the complete run from the private ledger.

Before the settled run, two fail-closed operator checks produced no provider call or run root. The
first rejected a checkout-internal key reference before reading it. After the original ignored
reference was moved to an operator-owned location outside the checkout, the second rejected its
legacy two-line assignment format. The runner now accepts exactly one recognized API-key
assignment plus non-sensitive endpoint metadata, rejects a second sensitive assignment, and keeps
the selected protocol ID in early refusal reports. Focused path, parser, Ruff, and strict-mypy
checks passed before the settled run.

## Public observation

The retained public aggregate is
[ifem-deepseek-role-calibration-2026-07-31-1024-v3.json](ifem-deepseek-role-calibration-2026-07-31-1024-v3.json).
Its file SHA-256 is
`205bdce0fa25b5b82199f11e498b19eb6f2a6cc15a7464479182c1b1335a5435`, and its internal content
SHA-256 is `097c016714bbde46cb37d99ab697c15f800c8cd7d795887941eca8194a7da2e1`.
The report binds profile SHA-256
`d8ee725c9dca99884c69a719e8b458d56163fb75e8b91458697c526b39e24a80`, request-policy SHA-256
`f39b0e104c5f8012fb2d023f50f5378e36a8eb7cac33b835ab1c34d8738587f8`, and fixture content
SHA-256 `a6acd9218d8a0e4b9ca5d7933b143172dab8aa851c00328c48a4a32ef97d9001`.

The run reported 6,072 input tokens, 2,816 cached input tokens, and 12,991 output tokens. D33
classified the sixteen strict outputs as:

| Role | Correct | Incorrect | Abstain | Invalid | Total |
| --- | ---: | ---: | ---: | ---: | ---: |
| Statement formalizer | 1 | 0 | 4 | 3 | 8 |
| Fidelity reviewer | 0 | 0 | 2 | 2 | 4 |
| Cheating supervisor | 1 | 0 | 2 | 1 | 4 |
| **All roles** | **2** | **0** | **8** | **6** | **16** |

At the risk-family level, positivity and vacuous-hypothesis each produced one correct result and
one abstention; restriction-domain produced two abstentions; absolute-value, closed-subspace,
parameter-reversal, and quantifier-order each produced one abstention and one invalid result;
infimum-to-attainment produced two invalid results. The public report contains no per-case
prediction, raw response, response identifier, private CAS reference, operator seed, HMAC key, API
key, prompt, or source text.

## Interpretation

Relative to the retained D34 observation, D35 changed the aggregate from 0 correct, 0 incorrect,
4 abstentions, and 12 invalid results to 2 correct, 0 incorrect, 8 abstentions, and 6 invalid
results. This is evidence that the larger completion budget reduced strict-output saturation for
this fixed open synthetic fixture. It is not a model ranking, capability floor, semantic
calibration, or accuracy estimate: the sample is tiny, public, lookup-recoverable, locally
evaluated, and uses an unpinned model alias.

The next useful experiment should not spend more tokens on the same open sixteen cases. It should
either test a separately frozen reasoning-policy arm or move to a private, rights-safe held-out
Builder calibration set with repeated seeds and a precommitted harmful-negative/risk-coverage
policy. D32, D34, and D35 remain immutable observations rather than adaptive retries.

## Authority boundary

The local HMAC ledger is single-host and non-production. Every benchmark, semantic, statement,
freeze, Prover-handoff, proof, promotion, provider-billing, release, and Open Problem authority flag
remains false. The result may prioritize future calibration work; it cannot classify an iFEM
prerequisite, admit a statement, or change a frozen contract.
