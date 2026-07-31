# iFEM synthetic-role private ledger

`benchmarks.ifem_synthetic_role_private_ledger` is the D31 operator-private persistence
layer for the sixteen synthetic iFEM role requests. It is deliberately a small adapter around
the existing `PrivateModelOutputStore`; it does not modify a provider, add a second egress path,
or accept the evaluator oracle.

For each exact prepared request it atomically persists three authenticated, append-only events:

1. `dispatch_started` is written before a provider call. A restart at this point is
   indeterminate and refuses automatic redispatch.
2. `cas_expected` records the exact private response-CAS reference before the CAS write. If a
   process stops after `put_response`, a restart can verify that reference and append the
   terminal event without calling the provider again.
3. `response_persisted` closes the coordinate. Replays with the same response are idempotent;
   a different response, request body, provider configuration, or event sequence fails closed.

The initial event is also the single-host dispatch claim. Concurrent callers cannot both treat an
already-created identical event as a successful claim, so at most one reaches the executor. Event
and manifest files use write-fsync-link publication; an interrupted write cannot publish a partial
immutable record.

After all sixteen terminal coordinates are present, `commit_manifest` writes one immutable,
authenticated private manifest. A failure while writing that manifest can be retried from the
ledger and CAS alone; it never requires another model execution. The single-host implementation
uses local files and an injected operator-private authenticator. The test-only HMAC implementation
is not a production key-management design.

The iFEM bridge never executes tool calls. If a provider nevertheless returns one, the raw call and
normalized token usage are retained only inside the private output record and D33 classifies the
case as invalid. This layer therefore stores provider/model identity, response ID, text, tool calls,
and input/cached-input/output token counts in the common private response CAS. None of those values
are copied into the public receipt. The bridge has no reservation/authorization semantics,
therefore it does not fabricate a `ModelExecutionCompletionReceiptV1` to reuse the authorized-role
completion path.

`public_projection` re-reads the authenticated manifest and emits each public request binding plus
an opaque, keyed `MODEL_OUTPUT_COMMITMENT`. It excludes raw text, response ID, CAS reference,
nonce, oracle, file path, and secret. The projection explicitly has no benchmark, semantic,
freezing, Prover-handoff, promotion, or model-egress authority. Its renderer requires the private
ledger, fixture, and complete prepared run, rebuilds the projection, and rejects even a
self-consistent forged public hash.

Focused tests cover a full sixteen-case offline run, duplicate/replayed coordinates, concurrent
first claims, conflicting outputs, a crash after CAS write before terminal ledger commit, manifest
persistence failure and retry, and stale-hash plus self-hashed public-render tampering. They use
only `IFEMSyntheticRoleFakeExecutor`; no network or model API call is made.
