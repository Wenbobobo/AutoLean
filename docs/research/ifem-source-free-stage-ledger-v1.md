# iFEM Source-Free Stage Ledger V1

Status: internal, source-free execution-journal protocol. It has a counting-fake executor surface
and is not a provider harness, a ModelWork authorization, a held-out benchmark, or Builder
semantic evidence.

## Purpose

The ledger fixes and durably accounts for the next execution boundary after the
[operator-private seed V2](ifem-source-free-private-seed-v2.md): nine private project-synthetic
cases, each with the ordered roles
`statement_formalizer -> fidelity_reviewer -> cheating_supervisor`. This produces exactly 27
private coordinates and permits at most one durable executor-dispatch transition per coordinate.

V1 proves only journal, dependency-frontier, redaction, and restart mechanics. Its executor is an
injected callback. The ledger does not itself construct a `ModelWorkBundleV2`, obtain provider
approval, issue a lease or authorization, call a provider, persist raw output in CAS, recover a
completion receipt, parse a role response, evaluate a case, or publish a calibration score.

## Persisted input boundary

`LocalSourceFreeStageLedger` does not accept an in-memory seed manifest. It requires the exact
`LocalSourceFreePrivateSeedStore` plus the exact typed P3 intent queue, calls `load()`, and replays
the retained manifest against that queue before creating its run descriptor. A missing or corrupt
manifest, queue drift, a queue subclass, or a non-local store fails closed.

The private seed remains unchanged: the ledger creates a downstream journal and does not rewrite
the seed's `model_work_created=false`, authority, or `live_model_eligible=false` fields.

## Coordinates and dependency frontier

Coordinates are canonical and private. Each binds the seed-manifest hash, run ID, case ID, role,
ordinal, and its own content hash. The run descriptor requires:

- exactly nine distinct private case IDs;
- exactly three roles per case in the fixed order;
- ordinals 1 through 27 without gaps;
- one run and one retained seed-manifest hash across all coordinates.

A reviewer cannot dispatch until its case's formalizer has a committed completion binding. A
supervisor cannot dispatch until its reviewer has one. Failure or reconciliation in one case does
not block independent cases, but it leaves that case's downstream coordinates pending. This is a
dependency rule, not evidence that the later role has received a correct finite projection; card
construction and strict role parsing belong to the future execution sidecar.

## State machine

Each coordinate begins as `pending` and may append write-once canonical events:

```text
pending -> claimed -> dispatch_started -> completion_committed
                                  \----> reconciliation_required
```

`dispatch_started` is persisted before invoking the injected executor. A second resumer that sees
this state does nothing: the first executor may still be active. It neither invokes the executor
again nor declares the attempt dead. Only an explicit
`operator_confirmed_quiescent=true` call may convert unresolved dispatches to
`reconciliation_required`.

An executor exception or an invalid completion binding enters reconciliation. A completion
recovered elsewhere may be attached without another executor call, but only after the ledger's
operator-private binding verifier accepts it. Completion events and conflicting terminal bindings
are immutable.

Because the private plan contains 27 coordinates and each coordinate can create only one
`dispatch_started` file, the durable journal enforces:

```text
executor callback invocations <= dispatch_started coordinates <= 27
```

This is not yet the stronger claim `provider calls <= 27`. The future sidecar must make the
provider call occur only inside the one claimed executor callback and bind it to one-attempt
ModelWork authorization.

## Completion-binding boundary

The journal stores only an opaque reduced binding: ModelWork bundle ID/hash, completion ID/receipt
hash, and public output commitment. It has no field for raw response text, prompts, tool calls,
usage, endpoint, credentials, private CAS paths, or recovery handles.

`bind_verified_stage_completion` can reduce an exact `ModelWorkBundleV2` and independently
verified `ModelExecutionCompletionReceiptV1`. The ledger also requires an injected
`SourceFreeStageCompletionBindingVerifier` whenever a binding is committed or reconciled. The
current public projection nevertheless fixes `completion_verification_attested=false`: requiring
a callback is an API invariant, not an independent gateway attestation. Counting-fake tests use a
deterministic test-only verifier.

## Storage and recovery boundary

The journal root must be absolute, outside the repository and every Git checkout, and free of
checked symlink, junction, or reparse-point traversal. The run descriptor and events use
write-once temporary files plus hard-link publication and canonical readback. Existing different
bytes cause a conflict instead of overwrite.

This supports tested process-interruption and concurrent-resumer behavior. It does not establish
Windows operator-only ACLs, close path-check time-of-check/time-of-use races against a hostile
local administrator, or attest parent-directory durability across operating-system or storage
power loss.

## Public projection and authority

The renderer exposes only the seed-manifest hash, private run and ledger commitments, aggregate
state/event/dispatch counts, and boundary flags. It refuses case IDs, roles, coordinates, run ID,
completion IDs, ModelWork bundle IDs, raw output, and private paths.

The projection states:

- `provider_dispatch_performed_by_ledger=false`;
- `completion_verification_attested=false`;
- `live_model_eligible=false`;
- `automatic_dispatch_replay_allowed=false`;
- `heldout_worker_isolation_claimed=false`;
- every semantic, freeze, Prover handoff, and promotion authority is false or forbidden.

`complete=true` means only that all 27 opaque completion bindings are committed in this journal.
It is not proof of valid model transport, correct role parsing, semantic fidelity, mathematical
truth, Lean verification, held-out performance, or a successful Builder run.

## Required successor

The execution sidecar must remain a separate versioned component. It must construct each role card
only after the prior role's strictly parsed finite response exists, then bind the exact outbound
bytes to project-synthetic source/rights records, `ModelWorkBundleV2`, admission, a single-attempt
authorization, private CAS, and completion receipt. Recovery must use `recover_completed` or enter
reconciliation; it may never redispatch an unknown attempt.

The control plane still needs an authorization-to-settled-completion recovery lookup for the crash
window after settlement but before a sidecar retained its recovery handle. Until that interface and
the real binding resolver exist, V1 remains counting-fake-only and must not receive DeepSeek or any
other provider callback.

## Verification snapshot

The focused private-seed and stage-ledger suite currently passes 42 tests: 17 seed tests and 25
ledger tests. The ledger cases cover exact 27-coordinate construction, predecessor blocking,
write-once events, all durable crash checkpoints, explicit quiescence, reconciliation without
redispatch, concurrent resumers, completion-binding verification, persisted-seed replay, path
containment, tamper rejection, public redaction, and the global callback cap. Ruff and Builder mypy
also pass. These are local engineering results only.
