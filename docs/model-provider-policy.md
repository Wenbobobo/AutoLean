# Model Provider Policy

## Decision

AutoLean uses an explicit provider registry and an execution harness as separate seams. A provider
generates model output; an execution harness controls how a process or OCI worker runs. No provider
is selected implicitly, and a capability-probe failure rejects execution rather than falling back
to another model.

Registering a provider is not authority to send it context. Every registry call requires a
short-lived, control-plane-issued `ModelExecutionAuthorizationV1`; the legacy
`generate(name, request)` shape is rejected. The authorization binds the registered frozen bundle,
contract revision/hash, Lean environment, current worker lease holder/fencing token/expiry,
role-scoped ContextPack hash, complete outbound-request hash, provider registry name,
provider/model/revision, operator-approved endpoint class plus a credential-free
provider-configuration hash, source-rights egress facts, and token/cost/attempt budget.

Before issuance, an operator-side control-plane process must call
`ModelExecutionAuthorizationService.register_operator_approval(...)`. That writes one immutable,
credential-free approval record to the local SQLite registry. `issue(...)` accepts only that
record's `approval_id`; a Builder, Prover, task bundle, or model request cannot inject or replace
the approval snapshot. The default authorization TTL is capped at one hour. Deployment may set a
smaller `max_ttl_seconds`, but V1 rejects any configuration or individual capability over the
one-hour hard cap.

The approved Phase 1 families are:

| Family | Intended use | Current implementation surface |
| --- | --- | --- |
| Fake provider | Deterministic tests and protocol fixtures | FakeProvider |
| Codex CLI | Local/operator-managed proof attempts | CodexCliProvider with read-only sandbox only |
| OpenAI Responses | API-based proof attempts | ResponsesProvider configured for the official API endpoint |
| Custom Responses-compatible endpoint | Operator-approved alternative endpoint | ResponsesProvider with custom HTTPS endpoint policy |
| Custom Chat Completions-compatible endpoint | Operator-approved alternative endpoint | ChatCompletionsProvider with custom HTTPS endpoint policy |

Anthropic and Claude are not supported providers, models, dependencies, examples, or fallbacks.
The identity guard rejects those terms in provider and model identifiers; see
[policy.py](../Prover/src/autolean_prover/providers/policy.py#L1). That guard is defense in
depth, not a substitute for dependency review and operator approval.

## Configuration rules

1. Provider identity, model identity, endpoint class, capability declaration, timeout, and a
   **credential environment-variable name** may be configured.
2. Credential values may not be placed in repository files, task bundles, model requests,
   event payloads, artifacts, fixtures, dashboard projections, or logs.
3. A non-local endpoint must use HTTPS. Endpoint URLs may not contain user-info, query strings,
   fragments, or embedded credentials. The official OpenAI configuration must use the official
   endpoint.
4. A custom endpoint is operator-owned. Builder and Prover workers do not get to choose or edit
   it through task input, source text, or model output.
5. No automatic fallback crosses a provider, model, endpoint, or rights boundary. A failed
   capability probe is a failed attempt.
6. `ModelRequest.timeout_seconds` is optional for legacy callers, finite and positive when set,
   and capped at 3600 seconds. It is part of the outbound request hash. Chat-compatible HTTP,
   OpenAI Responses HTTP, and Codex CLI enforce
   `min(provider_configuration_timeout, request_timeout)` at the transport or subprocess boundary;
   omitting it retains the provider ceiling. A later elapsed-time comparison is reporting only and
   cannot substitute for this enforcement.
7. Every provider exposes an immutable, credential-free `ModelExecutionTimeoutPolicyV1`.
   `ProviderRegistry.execution_timeout_policy(binding)` and
   `effective_timeout_seconds(binding, request)` read only registered local state, recheck the
   exact provider binding and policy, and never run a capability probe or contact an endpoint.
   Benchmark harnesses must compare this effective deadline with their frozen plan before allowing
   probe or provider I/O, and must report the effective deadline rather than the request in
   isolation.

Provider adapter objects are operator-side implementation details. Workers receive only a
capability and registry gateway; exposing a raw adapter or credential-bearing transport to an
untrusted worker is a deployment-policy violation, not a supported API.

`register_operator_approval(...)` is deliberately named as an operator-only path, but Python code
alone cannot prove that a human approved a record. The local registry proves only that a process
with control-plane write access inserted the immutable public snapshot. Production must enforce a
separate ACL so Builder and worker identities cannot invoke that method, and must protect the
model-execution signing authority with KMS/HSM or an equivalent operator-owned boundary. The
`approved_by` field is audit attribution, not independent evidence of human authorization.

The endpoint and secret-reference validation functions are
[validate_secret_reference](../Prover/src/autolean_prover/providers/policy.py#L23) and
[validate_endpoint_url](../Prover/src/autolean_prover/providers/policy.py#L30).

## Operator profile templates

[DeepSeek V4 Pro's Chat Completions profile](../Prover/operator-profiles/deepseek-v4-pro.chat-completions.v1.json)
is an operator template, not a credential store or an enabled provider. It fixes
`https://api.deepseek.com`, `deepseek`, and `deepseek-v4-pro`; it refers only to
`AUTOLEAN_DEEPSEEK_API_KEY` as an environment-variable name. It fixes a small canary at 2048
input and 256 output tokens, allows only high or max reasoning effort, and sends the narrowly
typed Chat Completions extension `{"thinking":{"type":"enabled"}}`.

An operator must capability-probe the exact endpoint before granting production or role-floor
approval. A compatible endpoint may reject or ignore that extension; this is a failed probe, not
permission to retry with a different provider, model, or request shape. The one exception is the
ephemeral DeepSeek bootstrap canary: its process-local authority may authorize one bounded
connectivity/accounting call with `static_declared_only` capability evidence. That record is not an
independent probe or production approval, and its report fixes `role_floor_admission: forbidden`.
If a Chat Completions response names a model, the adapter rejects any value other than the
requested model. It also records DeepSeek's `prompt_cache_hit_tokens` as cached input usage and
rejects a value above `prompt_tokens`. The template is intentionally not a benchmark matrix,
production approval record, or spend limit.

## DeepSeek operator sequence

`llm.txt` is an ignored, operator-local temporary input. It is not a configuration format for the
repository: do not commit it, migrate its values into `.env`/YAML, copy it into an artifact, or
teach a runner to read it. The operator may use it only to place
`AUTOLEAN_DEEPSEEK_API_KEY` and a distinct `AUTOLEAN_ROLE_MANIFEST_HMAC_KEY` into the current
process environment. The runner reads environment references only; public files retain the fixed
official profile, never a credential or an alternate endpoint.

Use the existing role-runner in this order, with fresh, checkout-external empty state and private
roots, a safe run identifier, and an explicit per-trial cost ceiling:

```text
uv run python -m scripts.deepseek_role_baseline plan --operator-approved --state-root <ABS_STATE> --private-root <ABS_PRIVATE> --run-id deepseek-role-001 --max-cost-microusd-per-trial <LIMIT>
uv run python -m scripts.deepseek_role_baseline preflight --operator-approved --state-root <ABS_STATE> --private-root <ABS_PRIVATE> --run-id deepseek-role-001 --max-cost-microusd-per-trial <LIMIT>
uv run python -m scripts.deepseek_role_baseline run --operator-approved --state-root <ABS_STATE> --private-root <ABS_PRIVATE> --run-id deepseek-role-001 --max-cost-microusd-per-trial <LIMIT>
```

`plan` is credential-free and performs neither filesystem nor provider I/O. `preflight` validates
the frozen ten-trial suite, effective provider timeout, source/rights and admission bindings,
budgets, lifetimes, and empty-root boundary before a provider request; it must leave ModelWork
trial state at zero. Run `run` only when the host network is deliberately available and preflight
has returned `preflight_ready`. It is one non-promotable observation run, not a retry loop.

The public stdout/report is redacted, role-separated, and marked non-promotable. Raw responses,
exact usage, reconciliation journals, and the authenticated private manifest live only below the
operator-owned private root. A provider/network failure produces a stable public failure class; it
does not authorize automatic retry, model substitution, role-floor admission, or benchmark scoring.
See [the DeepSeek role operator procedure](deepseek-role-operator.md) for the fixed limits and
private-output boundary. The bootstrap canary is narrower still: its earlier observed outcome was a
redacted network refusal and is not evidence of provider capability. A separate 2026-07-29 ten-call
role observation settled every request, but every completion saturated the fixed 256-token output
ceiling. That local, non-promotable result is [recorded separately](research/deepseek-role-json-contract-calibration-2026-07-29.md)
and supports no competence, role-floor, proof, or Builder-fidelity conclusion.

## Capability and provenance policy

Every request declares the capabilities it needs. Before generation, the registry requires both
the provider's declared capability set and the operator-supplied observed/probed set to satisfy
the request. The current registry is
[ProviderRegistry](../Prover/src/autolean_prover/providers/registry.py#L40).

The registry preflights the signed capability before it runs a capability probe that could contact
an endpoint. That preflight rechecks the current lease and requires the exact ContextPack and full
outbound-request hashes; a replaced worker, missing ContextPack, or substituted prompt is rejected
before endpoint I/O. It then reserves the capability's worst-case input/output token and integer
micro-USD cost before it invokes a provider. It settles only a nonzero, reported input-usage
record; a provider without `usage_accounting`, or a response that omits usage by reporting zero
input tokens, fails closed rather than being treated as free. The authoritative reservation ledger
is the control-plane SQLite database, not process memory: a restarted worker cannot reset an
attempt budget. Expired, revoked, stale-lease, mismatched, or exhausted capabilities fail closed.
A provider approval snapshot (`approval_id`, binding, pricing, approver, timestamp, and enabled
state) is loaded only from the immutable operator registry, signed into and persisted with the
capability alongside its stable approval hash, and contains neither endpoint URLs nor credentials.
The registry persists only this public snapshot, its hash, a registration request hash, and
timestamps/idempotency data.

## Failure evidence and circuit breaker

`ProviderRegistry` classifies every failure after reservation with one credential-free V1 code.
The original exception text and exception chain are discarded at the registry boundary. The
authorization ledger records the code on its immutable `abandoned` event; it never stores an
endpoint response body, exception message, prompt, credential, or provider log.

| V1 code | Boundary | Advances circuit |
| --- | --- | --- |
| `probe_failed_v1` | Capability probe raised or was unavailable | yes |
| `probe_invalid_v1` | Probe returned an invalid evidence object | yes |
| `probe_capability_mismatch_v1` | Observed capabilities do not satisfy the authorized request | no |
| `generation_failed_v1` | Provider generation call failed | yes |
| `response_invalid_v1` | Returned identity, response type, or usage was invalid | yes |
| `settlement_rejected_v1` | Local authorization ledger rejected settlement | no |
| `local_policy_rejected_v1` | Provider mutation, configuration, or local policy rejected the call | no |

Provider health is an independent append-only SQLite ledger keyed by the canonical serialization
and hash of the complete `ModelExecutionProviderBindingV1`: registry name, provider/model/revision,
endpoint class, and credential-free configuration hash. Only the four provider-health codes above
write failure events. Authorization denial, exhausted budgets, stale leases, capability mismatch,
local policy rejection, and settlement rejection cannot open the circuit. A successful settlement
writes a success event in the same transaction as usage settlement and resets the consecutive
failure sequence for that exact binding.

`ModelExecutionAuthorizationService` defaults to three consecutive health failures and a 60-second
cooldown. Operators must configure `provider_failure_threshold` and
`provider_failure_cooldown_seconds` explicitly when defaults are unsuitable. V1 enforces hard
bounds of 1–100 failures and 1–86400 seconds. Both the read-only preflight before probe I/O and the
transactional reservation repeat the circuit check, so restart or a race between probe
authorization and token reservation cannot bypass an open circuit. Once cooldown expires, V1
allows a retry; a success resets the sequence and another health failure starts a new sequence.
There is no automatic provider or model fallback.

The V1 recovery window does not serialize a single half-open trial across workers. Concurrent
requests can pass preflight after cooldown, although each must still win its own transactional
attempt/token/cost reservation. A future distributed control-plane implementation should add a
fenced half-open lease before increasing external concurrency.

Provider-reported usage is the V1 accounting evidence, not an independent remote billing meter.
For a hard external-spend ceiling, deployment must additionally use an operator-controlled egress
proxy or provider-side account limit that rejects over-budget traffic before the remote endpoint
accepts it. This operational control is not replaced by a client-side token declaration.

An accepted experiment report should record, by hashes and identifiers rather than secret values:

- provider and model identifier/revision;
- endpoint class, not a credential-bearing URL;
- provider configuration hash, prompt hash, and tool hashes;
- requested and observed capabilities;
- attempt budget, distinct model-request and verifier timeouts where both exist, token counts, and
  cost accounting; and
- frozen contract, environment, toolchain, and benchmark-manifest identity.

ProvenanceTraceV1 already makes model provenance require provider, name, revision, and endpoint
class. It does not replace a signed operator attestation or a real remote capability probe.

## Rights-aware context egress

Specialist workers receive role-scoped ContextPack projections derived from a frozen bundle, not
the Builder database or a shared workspace. A deterministic ContextPack hash and a hash of every
outbound model payload are signed into the short-lived authorization; the raw prompt stays out of
the authorization, ledger, and events. External egress is denied when rights are unknown or denied;
otherwise it requires explicit model-egress permission and a permitted endpoint class. Local
endpoint use is a distinct policy case. The implementation is
[ContextPackBuilder](../Prover/src/autolean_prover/context.py#L42).

Roles currently isolate planner, retriever, tactic, and verifier context. This reduces context
pressure and limits what one specialist needs to see; it does not make model output trustworthy.
All proof acceptance still goes through the verifier and control plane.

## Required operational approval record

Before a provider is enabled beyond tests, an operator must record:

- provider registry name and immutable model/revision selection;
- ownership and approval of the endpoint;
- permitted endpoint class and data-egress rights coverage;
- credential reference owner and rotation procedure, without recording the value;
- capability probe implementation and evidence;
- maximum token, wall-clock, concurrency, and cost budget;
- retention/redaction policy for prompts, tool output, and model response artifacts; and
- revocation procedure for the endpoint and model.

The operator registration path does not replace external approval workflow, identity management,
or a signing-key custody policy. Those controls are deployment responsibilities and remain a
release blocker when an external provider is enabled.

The unresolved operator choices are tracked in [open-questions.md](open-questions.md). Until that
record exists, the fake provider is the only suitable default for architecture tests.
