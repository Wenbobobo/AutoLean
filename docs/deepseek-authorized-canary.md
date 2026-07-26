# DeepSeek V4 Pro authorized bootstrap canary

`scripts/deepseek_authorized_canary.py` performs one real, bounded
`deepseek-v4-pro` request through the same authorization boundary used by the
Prover. It is a connectivity and accounting check, not a model benchmark and
not release evidence. In particular, it does not independently probe endpoint
features and cannot admit the model to a role-floor benchmark.

The command requires the credential only through the environment-variable
reference fixed in
`Prover/operator-profiles/deepseek-v4-pro.chat-completions.v1.json`:

```powershell
$env:AUTOLEAN_DEEPSEEK_API_KEY = "<operator-owned value>"
uv run python scripts/deepseek_authorized_canary.py --operator-approved
```

Use `--reasoning-effort max` only when that larger canary is intentional. The
only supported endpoint, provider, and model are
`https://api.deepseek.com`, `deepseek`, and `deepseek-v4-pro`. The canary
declares exactly text generation, usage accounting, and reasoning effort; it
does not declare tool calling.

The full path is:

1. Create and Builder-attest a synthetic CC0 frozen bundle whose rights allow
   `approved_external`.
2. Register a credential-free, operator-declared bootstrap approval for the
   exact provider configuration. This authorizes the bootstrap call; it is not
   evidence that endpoint capabilities were independently observed.
3. Claim a fenced worker lease and mint a signed
   `ModelExecutionAuthorizationV1` bound to the exact ContextPack and outbound
   request hashes.
4. Reserve a one-attempt token/cost budget, call
   `ProviderRegistry.generate`, validate mandatory usage, and settle the
   control-plane ledger.

The Builder and model-execution HMAC keys are random, process-local test
fixtures. The SQLite state is transient. Consequently every report is marked
`non-promotable-ephemeral-test-authority` and `promotion_eligible: false`.
Every report also fixes:

- `capability_evidence_class: static_declared_only`
- `independent_capability_probe_status: not_independently_probed`
- `provider_approval_class: operator_declared_bootstrap_only`
- `role_floor_admission: forbidden`

The static Registry probe only checks that the operator-declared capability
list can satisfy this request. It is not independent endpoint evidence.

Stdout contains only status, provider/model identity, token usage, and
SHA-256 hashes. Prompt text, response text, response ID, endpoint, credential,
paths, and signing material are never emitted. A refusal is deliberately
restricted to a stable diagnostic category. Current network categories include
`http_400`, `http_401`, `http_402`, `http_422`, `http_429`, `http_5xx`,
`timeout`, `network`, `invalid_json`, and `http_ok_response_invalid`, with
coarser categories for other status codes. Response bodies, URLs, and exception
messages are never retained or emitted. These diagnostics are canary-local and
do not weaken `ProviderRegistry` failure sanitization.
