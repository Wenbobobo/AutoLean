# iFEM DeepSeek role calibration: 512-token protocol v2

Date: 2026-07-31

Status: retained local provider-path and response-budget observation; non-promotable

## Bound run

- Provider/model request identity: `deepseek` / `deepseek-v4-pro` through the fixed official
  Chat Completions profile.
- Corpus: the same 16 project-authored, source-text-free iFEM structural role cases used by protocol
  v1: eight statement-formalizer, four fidelity-reviewer, and four cheating-supervisor cases.
- Generation policy: 2,048 input tokens, 512 output tokens, high reasoning effort, structured JSON,
  and required usage accounting.
- Response contract: exactly one JSON field, `selected_option`; the profile bytes, request-policy
  bytes, and `selected_option_only.v2` contract are bound into the private root and public report.
- Dispatch policy: one attempt per case and no automatic retry.
- Result: all 16 provider calls settled in one run, the authenticated private manifest committed,
  and D33 independently rebuilt the complete run from the private ledger.

## Public observation

The retained public aggregate is
[ifem-deepseek-role-calibration-2026-07-31-512-v2.json](ifem-deepseek-role-calibration-2026-07-31-512-v2.json).
Its file SHA-256 is
`802979251c5c4d402f2104ad34830f3afcd04e44f2a139a8e0f36bd929fa7c22`, and its internal content
SHA-256 is `ee1f04d1c9a5bccfb43760c8836b30a429938eea7ba683b0b69fbe9886532423`.

The run reported 6,072 input tokens, 512 cached input tokens, and 7,871 output tokens. Private
structural inspection, without exposing response text, found:

- 12 artifacts used exactly the 512-token ceiling and had empty final answer content;
- four artifacts had non-empty final content of at most 30 characters;
- no artifact contained a tool call;
- output usage ranged from 404 to 512 tokens.

D33 accepted the four non-empty responses as `abstain` and classified the 12 empty responses as
invalid. No response was classified as correct or incorrect. The public report contains no raw
response, response identifier, private CAS reference, operator seed, HMAC key, or API key. A broad
`sk-*` lexical scan matches only the public schema term `risk-aggregate`; exact secret matching and
a credential-shaped hexadecimal scan do not match.

## Interpretation

Protocol v2 removes the v1 prompt/parser disagreement, and doubling the output ceiling allows four
strictly valid final answers to appear. It does not produce a scored semantic result: twelve calls
still exhaust the ceiling before emitting final content, while the remaining four abstain. This is
evidence that the current thinking-enabled endpoint and 512-token response budget are a poor fit
for this strict role probe. It is not evidence of zero mathematical ability and must not be used as
a model ranking.

The next protocol experiment, if justified, should change exactly one dimension. A 1,024-token arm
would test response-budget saturation; a lower-reasoning or non-reasoning arm would test whether
the endpoint can satisfy a short structured contract. Either requires a new protocol ID, fresh
private roots, and a separately bound request policy. Existing v1 and v2 evidence remains immutable.

## Authority boundary

The model alias is not revision-pinned, evaluation is local, and the HMAC ledger is a single-host
adapter. The artifact establishes a real request/response/usage/persistence path and a reproducible
protocol-level budget observation only. It grants no benchmark authority, statement fidelity,
semantic equivalence, freeze, Prover handoff, proof, provider billing reconciliation, production
admission, release, or Open Problem claim.
