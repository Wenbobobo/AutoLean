# ResearchScoutAdapterV1

`autolean_builder.adapters.research_scout` implements the proposal-only boundary selected in the
Danus integration decision. It does not import or run an external scout runtime, call a provider,
read a host path, write a database/CAS, create or freeze a statement contract, mutate any graph, or
invoke Prover or verification code.

The adapter accepts canonical request/response JSON only after binding the request to immutable
goal, context, graph, rights, provider, source, and predecessor commitments. It returns a typed
`ResearchScoutProposalV1` with `authority=machine_advisory`, `promotion=false`, and a full SHA-256
for both the proposal payload and response-CAS bytes. `lemma`, `counterexample`, `toy_example`,
`decomposition`, `literature_lead`, and `proof_candidate` remain untrusted: only a later Builder
review may create a new draft revision, and normal Prover/Lean gates remain the only path to proof
acceptance.

The `custom` provider class is a capability seam, not a family bypass: provider snapshot and model
identifiers containing `claude` or `anthropic` are rejected during typed validation, before any
adapter response can be accepted. The adapter still does not perform endpoint capability discovery
or provider I/O; those remain control-plane responsibilities.

Request goals and response text reject secret-like values and host-path forms, including Windows,
UNC, and `file://` paths. This keeps operator-local locations out of proposal artifacts; it is an
input-hygiene boundary, not a substitute for the worker sandbox or the rights gate.

The request carries `input_artifacts_sha256`, a canonical commitment to the complete companion
artifact inventory. This closes a substitution found during root review: rights/provider IDs alone
did not distinguish two artifacts with the same ID but different bytes, and source/predecessor
hashes were previously outside the request identity. Tests now replace each of those commitments
independently and require fail-closed rejection.

## Append-only advisory record

`ResearchScoutProposalV1.control_plane_event()` derives a separate
`autolean.research-advisory-event.v1` envelope. Its two event types are exactly
`research_hypothesis` and `research_observation`; the latter is reserved for counterexamples and
literature leads. `ControlPlane.record_research_advisory()` appends the envelope to the dedicated
`research_advisory_v1` stream, keyed by the immutable proposal digest. Matching retries replay the
same event; a different envelope under the same proposal digest is rejected.

The envelope is intentionally not a Builder-Prover handoff. It contains only proposal/request and
context digests, source-span commitments, predecessor digest references, provider/model identity,
and the fixed `machine_advisory` / `promotion=false` boundary. It deliberately omits statement and
evidence text, prompts, source excerpts, declared token/cost usage, endpoints, credentials,
contract/bundle IDs, lease data, signatures, and proof/verification fields. Consequently it cannot
create or freeze a contract, alter any graph, schedule a worker, submit a proof, or affect release
state.

The Dashboard validates this V1 envelope during event replay and displays only a short timeline
summary plus the public proposal digest. It adds no node or run and does not associate the advisory
with a task. An extra payload field, mismatched event/entity identity, second entity event, or any
attempted authority escalation makes projection/export fail closed rather than silently showing a
benign record.
