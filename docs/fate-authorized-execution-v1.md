# FATE authorized execution V1

## Conclusion

Confidence: high for the offline execution semantics; low for live production
authority because that authority is intentionally not available in the local
Python composition.

The V1 engine now exercises the full answer-free path from a pinned FATE task to
proof-slot materialization, private artifact persistence, independent receipt
authentication, and tier-separated reporting. A fake provider and fake verifier
can test that path, but their result is returned only as an explicit test-only
wrapper. It cannot enter the production `run()` path.

No live DeepSeek request or WSL compilation is evidence of a FATE result until all
authority boundaries below are injected and the candidate passes the independent
Lean verifier.

`FateRunPlanV1.model_request_timeout_seconds` binds the provider request timeout
independently from `verifier_timeout_seconds`, which bounds Lean verification.
The model timeout is part of the request hash, work-bundle cell contract, and
reported evaluation config. Before any capability probe or provider I/O, FATE
reads the registered provider's local timeout policy and requires the effective
deadline to equal the frozen model timeout. A lower provider ceiling rejects the
attempt; the report records this observed effective value rather than relabelling
the requested value as actual.

## Irreducible boundaries

- The pinned source bytes and target signature define the task. A model may return
  only the text replacing the existing `sorry` slot.
- The actual outbound `system_prompt` and `prompt` are bound together as one
  derived egress packet and recomputed immediately before provider I/O.
- Model-request and Lean-verifier timeouts are separate frozen limits. Changing
  either limit changes the relevant immutable contract; one is never reported as
  the other.
- Model success is not proof success. Only an authenticated, allowlisted
  independent-verifier receipt may set `accepted=true`.
- Provider/model identity and cost come from the signed
  `authorization.approval_snapshot`, never from a caller-supplied approval object.
- Raw response, patched source, and verifier evidence digests remain in a mandatory
  repository-external private store. Public events do not expose proof-derived
  SHA-256 values that would make short proofs dictionary-enumerable.
- M, H, and X are preserved as separate populations in every report.

## Execution states

Each attempt has one durable public stream:

1. Register and claim the immutable `ModelWorkBundleV2`.
2. Issue a fenced, budgeted model capability.
3. Read the provider's frozen local timeout policy, require the exact effective
   model deadline, and verify the capability and lease windows.
4. Commit `fate.attempt.started`.
5. Revalidate exact source, request, egress admission, and lease-bound authority.
6. Call and settle the provider once.
7. Persist raw output and any candidate in the operator-private store.
8. Ask the independent verifier and authenticate its receipt against the configured
   verifier allowlist.
9. Persist the private coordinate record.
10. Commit `fate.attempt.verified`.

If the process fails after step 4 and before step 10, the attempt is ambiguous and
automatic replay is forbidden. This is provider-call at-most-once behavior, not a
claim of provider-side exactly-once delivery. An operator must reconcile an
ambiguous attempt.

The model-execution capability covers only
`effective model timeout + settlement margin`, because the registry settles that
capability before returning the provider response. It does not cover the later
Lean verifier. The shared fenced lease covers
`effective model timeout + verifier timeout + terminal settlement margin`, because
the terminal event still requires the original fence after verification. FATE
does not currently renew that lease mid-attempt, so both the configured TTLs and
the actual post-issuance expiry windows are checked before the durable start and
before provider or verifier I/O. Parent ModelWork admission validity must also
outlive the requested child capability plus a small issuance margin. The exact
registration admission and requested authorization TTL first pass the control
plane's read-only preflights; an operator TTL-cap mismatch therefore cannot register
work or strand a claimed lease.

## Test-only versus production

`run_test_only()` accepts only a `test-only` verifier trust policy and only a local
provider. It returns `FateTestOnlyEvaluationV1`, whose
`production_evidence` field is always `false`. The deterministic fake verifier and
the current process-local OCI compiler adapter are both permanently test-only.

`run()` accepts only a production verifier trust policy. A production verifier must
be a separately operated service that returns an authenticated execution receipt;
the local fake/HMAC fixtures cannot satisfy that policy.

Every model-work route additionally requires the shared `MODEL_WORK_ADMISSION`
authority. That dedicated-purpose admission must bind the exact prompt-free source/rights
projection and complete work bundle before registration and issuance. FATE's local manifest and egress
recomputation remain defense in depth; they are not a substitute for the shared
admission gate.

## Credential-free preflight

The preflight validates a pinned checkout and manifest, deterministic split file,
credential-free DeepSeek operator profile, repository-external private root, and a
successful redacted WSL runtime audit:

```text
uv run --frozen python scripts/fate_execution_preflight.py \
  --checkout <pinned-fate-checkout> \
  --manifest <fate-source-manifest.v1.json> \
  --expected-manifest-sha256 <sha256> \
  --environment-hash <sha256> \
  --private-state-root <absolute-path-outside-repository> \
  --wsl-audit <redacted-audit.json> \
  --operator-approved
```

The command never reads `llm.txt`, resolves an API key, invokes a provider, or
starts WSL. It always exits blocked and reports the still-missing live authorities:

- model execution authority;
- shared model-work admission;
- production independent-verifier authority;
- concrete WSL OCI verifier adapter.

This behavior is intentional. A clean profile and a WSL audit prove configuration
readiness, not permission to send FATE source externally or authority to publish a
benchmark score.

## Current verification

The focused suite covers regression-48 end to end with fake components, exact
source/egress binding, theorem-boundary rejection, untrusted verifier receipts,
signed approval identity and pricing, private-store placement, public
proof-digest non-disclosure, crash ambiguity, restart reuse, suite counts, and
preflight schema rejection.

Live work remains blocked until the production remote verifier and shared
`MODEL_WORK_ADMISSION` signer are deployed. The request-bound model timeout is now
implemented, but the M/H/X compiler behavior must still be rechecked in the pinned
WSL/OCI environment before any FATE number is published.

ModelWork V2 changes public bundle identities and the FATE attempt event schema is
now `autolean.fate-execution.v2`. Existing V1 events remain append-only evidence,
but this engine does not reinterpret or automatically resume them as V2 attempts.
Every V2 started and terminal event carries the same deterministic `attempt_seed`,
derived before model execution from the frozen run, problem, and attempt number.
Missing or mismatched seeds make the event stream invalid; they are never recovered
from model output or a later terminal event.
