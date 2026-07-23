# Builder Statement-Fidelity Harness

## Decision

The V1 Harness treats statement translation as an evidence-producing review workflow, not as a
model prompt. It can prove that every artifact is bound to one draft contract and that all required
tests were performed. It cannot prove that the mathematics means the same thing; that judgement
remains an explicit independent-expert trust root.

The implementation is
[`fidelity_harness.py`](../Builder/src/autolean_builder/fidelity_harness.py). It does not import the
Prover, a model provider, or the control plane.

For textbook-backed work, [`SourceToStatementHarness`](../Builder/src/autolean_builder/source_harness.py)
is the policy-required entry layer. It verifies a parent PDF, a manifest-typed derived UTF-8 text
artifact, and exact byte offsets for each permitted excerpt, then binds an explicit rights review
into a draft contract. Parent-PDF page locators remain human declarations. The packet rejects any
later change against a durable source-preparation CAS record and rechecks the manifest's egress
ceiling. Its `revalidate_and_freeze` wrapper repeats all source and rights checks before calling
the local freeze gate. The resulting `FreezeRecordV1` binds the stable source-preparation ID and
typed record digest; a production signer must retrieve that record from its own protected
ledger. See [`builder-reference-cache.md`](builder-reference-cache.md).

The excerpt is private evidence, not public contract payload. `SourceToStatementHarness` places
only its typed hash, locator, and byte offsets in `StatementContractV1`; it passes the exact text
to `StatementFidelityHarness` through a hash-checked private `SourceClaimSpan`. The canonical
fidelity artifact remains rights-scoped, while the Builder-to-Prover bundle exposes only its
digest and byte length.

## Closed loop

1. `TranslationTask.from_contract` binds public source-span hashes to rights-scoped private
   excerpts, then snapshots the informal and normalized statements, selected Lean statement,
   contract revision, and semantic obligations.
2. At least two `TranslationAgent` implementations produce candidates under distinct actor IDs and
   independence groups. Each candidate binds the source, normalized text, contract revision,
   selected Lean bytes, reverse rendering, and obligation coverage.
3. A `MutationSuiteAgent` emits the required adversarial statement variants.
4. An independent `SemanticReviewAgent` receives the complete packet. It returns per-candidate,
   per-obligation, and per-mutation verdicts plus example and non-vacuity evidence.
5. `FidelityEvaluation` canonically serializes the task, candidates, mutations, structural checks,
   expert verdict, and extra signoffs. Its SHA-256 is a typed field of `FidelityReportV1` and is
   also embedded in every derived fidelity check, mutation result, and semantic signoff.
6. The internal freeze primitive accepts only a complete `FidelityEvaluation`. It recomputes its
   artifact hash, checks every derived report field against the expert verdict, applies the
   risk-tier freeze gate, and only then produces the frozen contract.

`FidelityEvaluation.render_artifact()` returns the canonical JSON bytes that an artifact store
must retain before bridging. `FidelityEvidenceArtifactRefV1` carries its typed digest and size in
the bundle. The Builder attestation covers that reference through the handoff hash; production
registration rehashes the bytes, checks their task/statement/source binding, and records the
reference in the append-only registration event.

## Decision boundary

| Check | Authority | What the Harness establishes |
| --- | --- | --- |
| Source, revision, normalized-text, statement, and candidate hashes | Automatic | Exact byte and revision identity |
| Candidate actor IDs and declared independence groups | Automatic | Distinct declared origins; not epistemic independence |
| Obligation coverage and source-span references | Automatic | Complete and well-formed trace declarations |
| Mutation suite shape | Automatic | Required unique kinds exist and change statement bytes |
| Source to normalized statement fidelity | Expert | Mathematical meaning and conditions were preserved |
| Reverse rendering | Expert | Lean candidate renders back to the intended mathematics |
| Semantic obligation correctness | Expert | Quantifiers, assumptions, conclusion, definitions, and edge cases agree |
| Mutation detection | Expert | A changed statement is a material semantic change, not merely different text |
| Positive/negative examples and non-vacuity | Expert | The statement has intended witnesses and counter-boundaries |
| Final admission | Freeze gate | All required automatic evidence and role-specific signoffs are present |

The Harness never converts a model's confidence score into expert approval. Authentication and
authorization of reviewer identity belong to the operator review service; the current local
`ReviewerSignoffV1` record is evidence, not a cryptographic proof that a human signed it.

Raw freeze and bridge primitives are not exported by `autolean_builder`; the source-backed public
path reloads its append-only preparation record before freeze and signed handoff. This is a
structural API boundary, not a Python security sandbox. `frozen_by` and reviewer identities remain
unauthenticated strings, and a local process that owns the ledger or attestation key is trusted.
A separate Builder signing gateway with authenticated reviewers, protected ledger access, and
KMS/HSM key custody remains a release blocker.

## Required mutation suite

V1 requires:

- dropped assumption;
- swapped quantifiers;
- `<` to `<=` or the corresponding relation-boundary change;
- removed side condition;
- dropped nonempty condition;
- dropped finite condition;
- dropped Noetherian condition;
- reversed parameters;
- vacuity introduced through an impossible premise.

The synthetic golden fixture is
[`statement_fidelity_golden.json`](../Builder/tests/fixtures/statement_fidelity_golden.json). The
tests run two fake translators, a fake mutation agent, and a fake expert reviewer. For every
required mutation, a deliberately false-negative reviewer verdict reaches the evidence report but
is rejected by the freeze gate. This tests plumbing and policy only; it is not human fidelity
calibration and is not Lean compilation evidence.

## Operational requirements

- Give independent translators separate ContextPacks and prohibit shared hidden state. Distinct
  strings in `actor_id` and `independence_group` are necessary audit metadata, not proof of
  independence. The Harness rejects reuse of one declared identity across translation, mutation,
  semantic-review, or independent-signoff roles, but authenticated operator identities are still
  required to establish that those strings name different authorities.
- Persist the canonical Harness artifact before bridging and retain it under its evidence hash;
  a production control plane rejects a missing, corrupt, noncanonical, or cross-bound artifact.
- Obtain expert verdicts through an authenticated review service. L2, L3, and open-conjecture
  contracts still require the additional library, domain, and independent-verifier signoffs
  enforced by `FreezeGate`.
- Elaborate the selected statement in the pinned Lean environment before review. The Harness checks
  the existing elaborated-type binding but does not execute Lean.
- A rejected run remains immutable evidence. Corrections create a new Harness run; statement
  changes create a new contract revision.

V1 intentionally requires both independent candidates to match the selected Lean statement bytes.
Supporting syntactically different but propositionally equivalent candidates needs a separately
audited equivalence certificate and is deferred rather than inferred from model agreement.
