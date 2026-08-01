# iFEM Source-Free DeepSeek Role Chain V1

## Status and purpose

`scripts/ifem_source_free_role_chain.py` is a project-synthetic successor to the retained
one-coordinate DeepSeek canary. It selects exactly one private synthetic case and advances its
canonical three roles in order:

1. `statement_formalizer`
2. `fidelity_reviewer`
3. `cheating_supervisor`

The chain tests finite predecessor projection, fenced one-attempt execution, private completion
recovery, and aggregate redaction. It does not read iFEM source text, classify a mathematical
node, evaluate statement fidelity, create a statement contract, freeze Builder work, publish a
combined role score, or hand work to Prover.

The historical one-coordinate runner, its V2 plan, and the retained D/E report bytes are not
modified or reinterpreted by this successor.

## Frozen plan boundary

`SourceFreeDeepSeekRoleChainPlanV1` binds:

- the exact hash-pinned DeepSeek operator profile, source-free intent queue, per-stage execution
  policy, and provider configuration;
- the three roles in canonical order;
- for each role, the exact prompt/input-envelope contract hash and the actual Pydantic response
  schema hash;
- the declared scope cardinality of one case, three coordinates, and 24 outside-scope
  coordinates, but not the identity of the CSPRNG-selected private case;
- one attempt per stage, a per-stage accounting ceiling of 61,440 micro-USD, and an aggregate
  accounting ceiling of 184,320 micro-USD.

The cost values are conservative authorization bounds, not provider prices, invoices, or a claim
that three dispatches occurred. The plan contains no source text or Lean statement, claims no
held-out isolation or semantic calibration, and keeps all authority false.

Plan and preflight construction use the existing no-I/O provider adapter only to reproduce the
fixed configuration hash. They do not resolve an API key, create state roots, or make a request.

## Private run-scope binding

The plan intentionally remains credential-free and zero-I/O, so it cannot bind a private seed
that does not exist yet. After the existing private seed and canonical 27-coordinate run are
loaded, and before any selected coordinate can dispatch, the operator persists a write-once
`SourceFreeDeepSeekRoleChainScopeBindingV1`. It binds:

- the exact public plan hash;
- the private seed-manifest and canonical stage-run hashes;
- the fixed `first_case_in_canonical_27_coordinate_run_v1` selection rule; and
- the three ordered coordinate hashes plus their aggregate commitment.

Repeated `run` must read back the same bytes. `resume` only loads the retained binding and refuses
if it is missing, non-canonical, rehashed with different coordinates, or inconsistent with the
current plan, private manifest, or stage run. Two private roots may therefore share a public plan
hash, but they cannot share a run-scope commitment unless their exact selected private run is the
same. The binding file remains operator-private; public output exposes only its content hash and
never the manifest hash, case ID, or coordinate hashes.

## Execution boundary

The operator reuses the existing nine-case, 27-coordinate private ledger. It does not invent a
separate three-coordinate identity. The selected chain is obtained by filtering the canonical
run for the first case ID and must contain exactly ordinals 1--3 in the fixed role order.
The write-once run-scope binding is verified before this chain is allowed to execute.

Every stage advances only through `LocalSourceFreeStageLedger.execute_coordinate` and the existing
`SourceFreeModelWorkExecutionSidecar.execute_once`. A stage that does not reach
`completion_committed` stops the chain immediately. Consequently:

- reviewer work cannot run before a verified formalizer completion;
- supervisor work cannot run before verified formalizer and reviewer completions;
- each selected coordinate can have at most one durable attempt binding;
- a settled but invalid response is retained and never replaced;
- all 24 outside-scope coordinates must remain `pending` and have no attempt binding before a
  runtime report can be produced.

The runtime also reads the control-plane database through a read-only connection. Every durable
authorization must correspond exactly to one selected attempt, every settlement must correspond
to one of those authorizations, and every completion receipt must remain within that selected
authorization set. A pending coordinate with a pre-attempt authorization is therefore treated as
contaminated state, not as untouched work. Orphan receipts are detected with a left-join audit and
also force refusal.

The underlying ledger's public projection may read the state of all 27 coordinates and create
empty journal directories as part of its existing storage protocol. "Outside scope untouched"
therefore means no event, attempt, authorization, settlement, or completion, not absence of an
empty directory.

## Modes and recovery

| Mode | Provider API key | Provider dispatch | State effect |
| --- | --- | --- | --- |
| `plan` | Not read | None | None |
| `preflight` | Not read | None | None |
| `run` | Reads `AUTOLEAN_DEEPSEEK_API_KEY` after explicit operator approval | At most one request for each still-eligible selected stage | Initializes or reopens the exact bounded run |
| `resume` | Not read | None | Recovers only already-settled selected stages |

`resume` never calls the ledger's full 27-coordinate `resume` method and never advances a pending
downstream role. It reconstructs and verifies only durable selected attempts with existing
settlements. "No key" here means no provider API key; the current local experiment still requires
the operator-private HMAC material created by the original run to verify local admission and
completion receipts. That material is test-only local authority, not production signer custody.

If the process stops after the third provider settlement but before its ledger terminal event,
credential-free `resume` can recover all three completions. If an earlier stage is recovered while
a later stage remains pending, the public result stays `reconciliation_required`; a provider-free
resume does not silently start the next role.

## Public report

`SourceFreeDeepSeekRoleChainPublicReportV1` exposes only:

- the plan hash, selected/outside-scope cardinalities, and fixed budget ceilings;
- aggregate selected ledger-state counts;
- counts of durable attempts, observed settlements, and privately verified completions;
- aggregate ledger, attempt-binding, and completion-binding commitments when available;
- the opaque run-scope-binding hash for runtime evidence, without its private fields;
- an always-`abstain` machine-advisory disposition and explicit negative authority flags.

If execution has started but the ledger, attempt store, or control-plane scope cannot be read and
cross-checked, the result is `execution_refused` with `runtime_evidence_available=false`. All
runtime counts and commitments are then `null`; the report never replaces unknown durable state
with fabricated zero attempts or three pending coordinates. Plan and preflight may show their
declared initial cardinalities, but those are explicitly not runtime evidence.

It does not disclose a case ID, role result, raw response, model/provider identity, credential,
operator path, or combined score. `actual_provider_dispatch_count_claimed=false` remains mandatory:
attempt/settlement evidence is reported without inferring a network dispatch count.

All three roles currently share one provider binding. The report therefore retains
`cross_role_independence_claimed=false`. Role separation is an execution/control experiment, not
an independence or expert-equivalence result.

## Local verification scope

The no-network tests cover:

- credential-free plan/preflight and three role-specific prompt plus response-schema bindings;
- exact three-call happy path and zero redispatch on a repeated run;
- write-once plan-to-private-run scope binding before dispatch, distinct commitments for distinct
  deterministic test seeds under one plan, and refusal of a rehashed coordinate substitution;
- strict role ordering, finite stage envelopes, three attempts/settlements/private completions,
  and 24 pending coordinates with no attempts;
- an invalid reviewer response stopping the supervisor, retaining reconciliation, and never
  retrying either stage;
- rejection of a control-plane authorization that is not represented by a selected durable
  attempt, extra settlements, orphan receipts, and a null-evidence refusal when post-dispatch
  evidence collection fails;
- fail-closed rejection of an unknown programmatic mode in both config construction and execution;
- validator rejection of impossible mode/status combinations and successful reports without an
  exact plan hash or ledger commitment;
- recovery after the third settled response without provider API-key lookup or provider dispatch;
- stdout redaction and direct-script invocation;
- continued execution of the historical D/E hash and renderer regression tests.

This is local fake-transport mechanics evidence. A real three-call operator observation must use
separate external roots and explicit approval, then be recovered without the provider API key and
recorded as a new observation. Even a successful real observation would remain project-synthetic,
non-independent, non-semantic, non-promotable evidence.

## Next decision

Run a real maximum-three-call observation only after the operator injects the named environment
reference into the executing process. Inspect response-contract failures and recovery first. Do
not expand to the full 27-coordinate campaign until this bounded chain is settled and replayable;
do not treat either experiment as a substitute for `AUTH-RIGHTS-01` or rights-cleared textbook
calibration.
