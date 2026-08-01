# iFEM Source-Free ModelWork Sidecar V1

Status: internal, project-synthetic execution protocol. The current implementation is validated
with a counting fake provider. It is not a DeepSeek result, a private held-out benchmark, iFEM
statement evidence, semantic review, Builder freeze, or Prover handoff.

## Purpose

The sidecar closes one narrow gap between the private 27-stage Builder ledger and the existing
ModelWork control plane. For each exact `(run, case, role)` coordinate it constructs a bounded role
request, obtains independent ModelWork admission, records one fenced authorization binding before
provider I/O, stores the response in private CAS, settles a completion receipt, and returns the
opaque binding expected by the Builder ledger.

The outer ledger remains the dispatch owner. The sidecar does not add another 27-stage state
machine and cannot create statement, graph, freeze, handoff, or promotion authority.

## State ownership

| State | Single owner | Sidecar use |
| --- | --- | --- |
| Pending, claimed, dispatched, completed, reconciliation | `LocalSourceFreeStageLedger` | Executes only inside the winning ledger callback and returns an opaque completion binding. |
| Lease and fencing token | control-plane `LeaseStore` | Claims one deterministic ModelWork worker identity and binds the attempt event with the current token. |
| Admission, approval, authorization, reservation, settlement, receipt | `ModelExecutionAuthorizationService` | Uses the normal ModelWork path with `max_attempts=1`. |
| One coordinate-to-authorization binding | the same control-plane `EventStore` | Appends one immutable event with `expected_sequence=0` before provider I/O. |
| Raw response bytes | injected `PrivateModelOutputStore` | Uses CAS through `ProviderRegistry.generate_completed`; never copies bytes into the ledger or public report. |

The attempt event contains the exact credential-free `ModelWorkBundleV2` and signed authorization.
It does not contain prompt text, permitted excerpts, response text, usage, response ID, CAS path,
artifact digest, recovery handle, or secret material. The EventStore must share the control-plane
lease database; a disconnected store cannot validate the lease and fails before provider I/O.

## Persisted input boundary

The sidecar does not accept an in-memory manifest. It requires the exact
`LocalSourceFreePrivateSeedStore` and exact `IFEMNextCalibrationCaseIntentsV1`, reloads the
repository-external canonical manifest, and replays it against the queue. Missing, changed,
non-canonical, or self-hashed-but-non-replayable input fails before request construction.

This seed remains project-synthetic. The finite cards contain no iFEM source text, Lean declaration,
node identifier, partition label, nonce, hidden-oracle field, retrieval result, or tool call.
Reviewer and supervisor cards are rebuilt only from strictly parsed, CAS-recovered predecessor
responses. They never receive authorization, provider, completion, usage, or raw-response wrappers.

## Execution order

For a coordinate with no prior attempt event, `execute_once` performs:

1. Reload and validate the exact coordinate and private seed item.
2. Recover and strictly parse required predecessor completions.
3. Build the finite role card, canonical request, exact egress span, project-synthetic source and
   rights records, and `ModelWorkBundleV2`.
4. Obtain a signed admission and preflight admission, operator approval, budget, timeout, provider
   capabilities, egress, and completion policy.
5. Register the work, claim its lease, and issue a short-lived authorization with one allowed
   attempt.
6. Append the unique fenced attempt event with `expected_sequence=0`.
7. Call `ProviderRegistry.generate_completed` once, which reserves the attempt, writes private CAS,
   settles the completion, and creates or recovers the receipt.
8. Strictly parse the response and reduce the independently verified receipt to the ledger binding.

If an attempt event already exists, `execute_once` enters recovery. It never calls the provider
again. Two callers that reach the attempt boundary concurrently produce one event and one provider
call; the losing caller can only reconcile or recover the winner's settled completion.

The admission resolver must return the same immutable admission for the same
`model_work_admission_evidence_identity`. A gateway that signs a new nonce on each duplicate request
causes the duplicate caller to fail safely before dispatch, but reduces availability. Production
integration therefore needs gateway-level idempotent admission replay or an equivalent controlled
cache; the sidecar does not weaken immutable registration to hide that issue.

## Recovery matrix

| Last durable boundary | Automatic action | Provider redispatch |
| --- | --- | --- |
| Before attempt event | Outer ledger retains an unknown dispatch and requires explicit reconciliation. | Forbidden |
| Attempt event, no settlement | Return `reconciliation_required`; the network outcome is unknown. | Forbidden |
| Settlement exists, receipt or caller state missing | Discover the unique settlement by exact authorization, recover CAS and receipt, then rebind. | Forbidden |
| Settlement is absent, duplicated, corrupt, or misbound | Fail closed into reconciliation. | Forbidden |
| CAS is missing, changed, or not strictly parseable | Fail closed into reconciliation; the settled output cannot be replaced. | Forbidden |
| Ledger completion is already committed | Independently recover and compare the exact binding. | Forbidden |

`completion_recovery_handle_for_authorization` is a read-only lookup. It uses one SQLite snapshot,
requires an exact persisted authorization, distinguishes zero, one, and multiple settlements, and
does not inspect CAS, issue a receipt, sign data, alter a lease, or call a provider.

## Public report

The aggregate report accepts only the exact persisted stage ledger, calls its canonical readback,
requires all 27 coordinates complete with no reconciliation, and independently recovers all 27
attempts and receipts. It publishes only private commitments, counts, one-attempt bounds, and
boundary flags. It does not publish model/provider identity, case or role results, prompts, raw
responses, authorization, completion IDs, or partition data.

`maximum_authorized_provider_attempts=27` follows from 27 exact authorization bindings with
`max_attempts=1`. The report deliberately fixes `actual_provider_dispatch_count_claimed=false`:
the fake test counter observes 27 calls, but an aggregate authorization bound is not a production
transport attestation.

Every semantic and lifecycle authority remains false. The report disposition is `abstain`, and
Builder freeze, Prover handoff, and promotion remain forbidden.

## Verification snapshot

The focused sidecar suite passes 15 tests. It covers a complete 27-coordinate counting-fake run,
restart without extra calls, crashes after authorization and settlement, malformed and duplicate-key
JSON, strict predecessor projection, concurrent callers, disconnected EventStore/lease databases,
persisted-seed replay, detached-projection refusal, attempt-event redaction, and aggregate public
redaction. The completion lookup suite separately passes 21 tests for zero, unique, multiple,
corrupt, changed, and misbound settlement paths.

These are local engineering results. No external provider was called by this test snapshot. A live
source-free canary still requires an operator-approved provider binding, stable admission service,
private output root, bounded budget, and a separately retained run receipt. Even a successful
canary will remain machine-advisory and cannot establish textbook fidelity or mathematical truth.
