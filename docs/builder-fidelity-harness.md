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

## Preformal evidence flow

1. `TranslationTask.from_contract` binds public source-span hashes to rights-scoped private
   excerpts, then snapshots the informal and normalized statements, selected Lean statement,
   contract revision, and complete semantic obligations for the Harness.
2. Before calling a `TranslationAgentV2`, the Harness derives a selected-formal-field-blind
   `CandidateGenerationTask`. It contains the rights-scoped source claims, the immutable
   `MathematicalSpecificationV1`, and an obligation projection containing only ID, kind, source
   span IDs, and a normalized-statement fragment. Caller-authored obligation descriptions and Lean
   fragments are not projected. A selected-formal-field-blind formalization envelope supplies task
   kind, declaration name, namespace, Lean and mathlib versions, import and axiom allowlists, and the fixed
   `autolean.full-declaration-exact.v1` rendering profile. The task excludes selected Lean bytes,
   selected-statement hashes, elaborated types, and the target-dependent draft-contract hash.
3. The Harness hashes the canonical agent-visible projection as `HashKindV1.PROMPT`. The agent
   returns only a `CandidateProposal` with an identifier, proposed Lean source, reverse rendering,
   and coverage. The Harness injects the generation-task hash plus the contract, revision, draft,
   source, normalized-text, actor, and independence bindings server-side to form
   `CandidateFormalization`.
4. A `MutationSuiteAgent` emits the required adversarial statement variants.
5. An independent `SemanticReviewAgent` receives the complete packet. It returns per-candidate,
   per-obligation, and per-mutation verdicts plus example and non-vacuity evidence.
6. `FidelityEvaluation` canonically serializes both task projections, candidates, mutations,
   structural checks, expert verdict, and extra signoffs. Its SHA-256 is a typed field of
   `FidelityReportV1` and is also embedded in every derived fidelity check, mutation result, and
   semantic signoff.
7. The internal freeze primitive accepts only a complete `FidelityEvaluation`. It recomputes its
   artifact hash, checks every derived report field against the expert verdict, applies the
   risk-tier freeze gate, and only then produces the frozen contract.

`FidelityEvaluation.render_artifact()` returns the canonical JSON bytes that an artifact store
must retain before bridging. `FidelityEvidenceArtifactRefV1` carries its typed digest and size in
the bundle. The Builder attestation covers that reference through the handoff hash; production
registration rehashes the bytes, checks their task/statement/source binding, and records the
reference in the append-only registration event.

The source claims, mathematical specification, and formalization envelope are the preformal trust
boundary: the Harness copies them from an already prepared draft and does not prove that their
contents were authored from the source without contamination. The generation-task hash proves
content identity only. It does not prove execution chronology, process isolation, or independence
of the declared translation role. Identity strings for all
translation, mutation, and review roles are snapshotted before the first untrusted role call; this
prevents later attribute mutation from rewriting evidence but does not authenticate the people or
processes behind those strings.

## Decision boundary

| Check | Authority | What the Harness establishes |
| --- | --- | --- |
| Source, revision, generation-task, statement, and candidate hashes | Automatic | Exact content and revision identity |
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
is rejected by the freeze gate. This tests plumbing and policy only; it is not independently
isolated selected-formal-blind model evidence, human fidelity calibration, or Lean compilation
evidence.

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

An exact-match mismatch fails before mutation or reviewer execution. V1 records no inferred
semantic reconciliation for such a mismatch: a versioned disagreement artifact and its review
workflow are deliberately deferred to a later contract revision. The deterministic test fixtures
carry fixed oracle Lean source when they are constructed solely to exercise the plumbing; their
successful equality is not evidence that an independent agent generated the statement.

This exact-byte rule is selected-formal-field-blind groundwork, not a usable blind-formalization
closed loop. It is deliberately low-liveness: a generator must reproduce the preselected full
declaration byte for byte, including formatting. No real model run currently establishes that
capability. Independently created preformal artifacts and chronology receipts remain separate
requirements. Acceptance by canonical elaborated-type identity, rather than selected source bytes,
is reserved for a separate audited change.

## Pre-RC artifact cutoff

`autolean.builder-fidelity-evidence.v1` remains the artifact schema before the first release
candidate; this is an intentional migration cutoff, not a silent `FormalizationTaskBundleV2`
union. New registration requires the V1 top-level shape to contain `generation_task`, its complete
typed `HashKindV1.PROMPT` digest, and the same typed digest on every candidate. The control plane
derives the only permitted generation projection from the retained task and frozen contract,
rebuilds every source claim from its frozen-span binding while preserving the already validated
claim order. The private excerpt remains artifact-resident for rights reasons, yet must rehash to
the frozen span's typed hash; its ID, locator, and hash cannot come from the artifact. Obligation
records remain private artifact evidence, but registration
requires their exact V1 shape, valid kind, unique nonempty IDs, references only to frozen spans,
and normalized fragments that occur in the frozen normalized statement. The generation projection
contains none of each obligation's description, Lean fragment, or authority. The control plane
rehashes the resulting projection with `canonical_json_bytes` and `digest_bytes`, and rejects any
shape, projection, kind, or value mismatch before recording `task.registered`.

Old V1 source-backed artifacts without these fields remain historical evidence only. They can be
read through existing event replay but cannot be newly registered or used for promotion. The
explicit `allow_test_only_unreviewed_bundles` switch remains limited to a bundle with neither a
fidelity report nor an artifact reference; it is not an exception for legacy or malformed reviewed
V1 evidence.

## Pre-RC API migration

The translator signature changed before the first release candidate. New implementations must use
`TranslationAgentV2.translate(CandidateGenerationTask) -> CandidateProposal`. The exported
`TranslationAgent` name is only a deprecated pre-RC type alias and will be removed; it does not
preserve the old full-`TranslationTask` return contract. Mutation and semantic-review signatures
remain unchanged and continue to receive the full task only after candidate exact matching.
