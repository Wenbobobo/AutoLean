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
uv run --frozen python scripts/deepseek_authorized_canary.py --operator-approved
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
   `ProviderRegistry.generate_completed`, write the normalized response only to
   a transient private output store, and settle an output-bound completion
   receipt in the control plane.

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

Stdout contains only status, provider/model identity, frozen authorization and
bundle hashes, and the public completion projection (completion ID, receipt hash,
and salted output commitment). It contains no response text, response ID,
private artifact digest, receipt body, nonce, exact token usage, cost, endpoint,
credential, path, or signing material. A refusal is deliberately
restricted to a stable diagnostic category. Current network categories include
`http_400`, `http_401`, `http_402`, `http_422`, `http_429`, `http_5xx`,
`timeout`, `network`, `invalid_json`, and `http_ok_response_invalid`, with
coarser categories for other status codes. Response bodies, URLs, and exception
messages are never retained or emitted. These diagnostics are canary-local and
do not weaken `ProviderRegistry` failure sanitization.

If receipt signing is interrupted after the provider response is safely stored,
the registry raises a credential-free recovery handle. The only permitted follow
up is `recover_prepared_canary`, which calls `ProviderRegistry.recover_completed`
against the same private store. It does not contact the provider again.

## 2026-07-28 working-session observation

One operator-approved, no-retry attempt sent only the fixed synthetic `n = n` canary under the
2,048-input/256-output-token ceiling. The outer live gate returned `blocked` with
`provider_response_received=false`; no response text, usage, settled cost, or model score exists.
The caller did not retain a more specific stable provider category, so this record does not infer
an HTTP or authentication failure.

A separate credential-free HTTPS reachability probe from the same Codex sandbox failed before a
connection was established. That narrows the observed blocker to this execution environment's
network path; it does not establish an endpoint outage and does not authorize an automatic retry.
`AUTH-PROVIDER-01` remains open.

## 2026-07-29 separate role observation

This does not revise the bootstrap-canary observation above. A separate frozen ten-call DeepSeek
role run settled all requests, but every accepted completion reached the fixed 256-token output
ceiling. Its redacted local record is explicitly non-promotable and cannot distinguish a poor final
answer from an answer crowded out by the fixed reasoning/output budget. It therefore supports no
competence, role-floor, proof, or Builder-fidelity conclusion; see
[the separate calibration record](research/deepseek-role-json-contract-calibration-2026-07-29.md).
