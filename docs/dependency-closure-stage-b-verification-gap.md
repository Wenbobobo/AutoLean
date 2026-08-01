# Dependency Closure Stage B: verification-binding gap

Status: fail closed (2026-07-29)

This note covers only ordinary theorem dependencies carried by a
`FormalizationTaskBundleV2` closure. Manifests with no `accepted_dependencies` and V1 bundles are
unaffected by this increment; that compatibility does not make a V2 runtime closure authoritative.

## Decision

The control plane must reject every non-empty `accepted_dependencies` manifest until a durable,
gateway-owned admission record binds the verified theorem to the exported module and exact OLean
blob supplied by the closure. Merely storing a blob labelled as verification evidence is not
authority. A worker or Builder cannot sign this missing link for itself.

## What existing durable records prove

An accepted `VerificationReportV1`, its `VerificationEvidenceArtifactV2`, the registered frozen
bundle, and the associated `verification.accepted` event can jointly recover:

- the exact contract ID, revision and semantic hash;
- the frozen declaration name and elaborated-type hash;
- the verifier-observed axiom set;
- the proof submission, environment, OCI transcript and fenced execution identity;
- whether the recorded attestation payload was the lease-bound gateway payload, by comparing its
  durable payload hash with the reconstructed gateway context.

These records prove an exact theorem in the solver workspace. They do not prove that a particular
library module exports it.

## Irreducible missing bindings

No existing accepted event or evidence artifact records all of the following:

1. the exported Lean module name containing the accepted declaration;
2. the content identity of the exported OLean blob;
3. a verifier observation that loading that exact blob yields the same declaration, canonical
   type and axiom profile;
4. a gateway decision joining that export observation to the earlier accepted verification event.

`AcceptedDependencyV1.module_name` and `verification_evidence` are therefore self-declared manifest
fields today. CAS existence, media type, contract cross-binding and a real proof-verification event
cannot manufacture the missing export relationship.

## Minimum future authority record

A later protocol revision should add an append-only gateway event (working name
`dependency.admitted`) whose canonical artifact binds at least:

- source `verification.accepted` event ID and accepted report/evidence artifact digests;
- contract ID, revision, contract hash and environment hash;
- declaration name, canonical elaborated-type hash and observed axioms;
- exported module name, OLean artifact digest/size and closure tree hash;
- an independent load/query observation over that exact OLean blob;
- verifier gateway key identity, fenced execution identity and attested payload hash.

The event must be emitted only after the gateway revalidates the source accepted event and performs
the export load/query. The Builder may reference this admission artifact but may not create it.
Registration can then compare every `AcceptedDependencyV1` field against that durable event and
expose only the already-admitted OLean blob through the claim-scoped reader.

Until that event and gateway route exist, accepting a non-empty closure would silently promote a
Builder assertion into verifier authority. The implemented registration gate intentionally rejects
that state.

## Residual Stage B authority gap

This increment does not close declaration-inventory completeness. An OLean blob can contain more
declarations than its manifest reports, and `DependencyClosureObservationEvidenceV1` is currently a
report-only DTO with no durable admission event. In particular, a proposition-bearing declaration
could be misclassified or omitted instead of appearing in `accepted_dependencies`.

That is a separate P1 architecture gap for full Stage B promotion. Empty-accepted-dependency V2
fixtures remain useful for CAS, lease and materialization mechanics, but they are not evidence that
the runtime closure is safe for authoritative proof composition. The future export load/query gate
must also prove a complete declaration inventory before any V2 closure can be promoted.

## Verification

`packages/control_plane/tests/test_dependency_closure_stage_b.py` includes a regression showing
that a structurally valid dependency, complete frozen graph binding, and present
verification-evidence-labelled CAS blob still fail registration. Existing V1 and empty-V2 service
tests remain the compatibility guard.
