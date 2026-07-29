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

The request carries `input_artifacts_sha256`, a canonical commitment to the complete companion
artifact inventory. This closes a substitution found during root review: rights/provider IDs alone
did not distinguish two artifacts with the same ID but different bytes, and source/predecessor
hashes were previously outside the request identity. Tests now replace each of those commitments
independently and require fail-closed rejection.
