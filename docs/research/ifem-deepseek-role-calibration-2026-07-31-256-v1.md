# iFEM DeepSeek role calibration: 256-token protocol v1

Date: 2026-07-31

Status: retained local provider-path observation; non-promotable

## Bound run

- Provider/model request identity: `deepseek` / `deepseek-v4-pro` through the fixed official
  Chat Completions profile.
- Corpus: 16 project-authored, source-text-free iFEM structural role cases: eight statement-formalizer,
  four fidelity-reviewer, and four cheating-supervisor cases.
- Generation policy: 2,048 input tokens, 256 output tokens, high reasoning effort, structured JSON,
  and required usage accounting.
- Dispatch policy: one attempt per case and no automatic retry.
- Result: all 16 provider calls settled, the authenticated private manifest committed, and D33
  independently rebuilt the complete run from the private ledger.

The first CLI invocation stopped before root creation or provider dispatch because the supplied
operator file contained more than one line. A separate one-value reference outside the repository
was then derived from its unique key token, and the fresh run completed. This refusal is operator
input validation evidence, not a provider failure.

## Public observation

The retained public aggregate is
[ifem-deepseek-role-calibration-2026-07-31-256-v1.json](ifem-deepseek-role-calibration-2026-07-31-256-v1.json).
Its file SHA-256 is
`0472f3160118f54d95929f63c1fb229c19a535673c76c96bc51ff8bca247ea38`, and its internal content
SHA-256 is `491cfff6a307ad6b141227cf33d51634539efbaa916d7179878e4e0095691578`.

The run reported 5,816 input tokens, 1,024 cached input tokens, and 4,096 output tokens. Private
structural inspection, without exposing response text, found the same pattern in all 16 artifacts:

- output usage was exactly 256 tokens;
- final answer content was empty;
- no tool call was present.

D33 therefore classified all 16 cases as invalid. This is evidence that the v1 budget did not
leave room for a final answer from this thinking-enabled endpoint. It is not evidence that the
model chose the wrong mathematical option on 16 cases, and it must not be reported as a semantic
accuracy score.

## Protocol defect found

The v1 system prompt asks for JSON containing both `selected_option` and `reason`, while the D33
strict parser accepts only a single `selected_option` field. Empty final content prevented this
disagreement from affecting the observed counts, but it makes the v1 protocol unsuitable for a
capability comparison even at a larger budget.

The next run must use a new, explicitly bound protocol revision with a selected-option-only output
contract and a 512-token ceiling. The v1 profile, request bytes, private ledger, and public report
remain immutable historical evidence; the revised run must use a fresh root pair and must not
overwrite or reinterpret this result.

## Authority boundary

The model alias is not revision-pinned, evaluation is local, and the HMAC ledger is a single-host
adapter. The artifact establishes a real request/response/usage/persistence path only. It grants no
benchmark authority, statement fidelity, semantic equivalence, freeze, Prover handoff, proof,
provider billing reconciliation, production admission, release, or Open Problem claim.
