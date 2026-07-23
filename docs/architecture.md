# AutoLean Phase 1 Architecture

## Conclusion

AutoLean is a Builder--Prover system with independent semantic and formal correctness
boundaries. Builder decides whether a frozen Lean statement faithfully represents a cited
mathematical claim; Prover searches only for a proof of that frozen statement. Lean kernel
verification establishes the latter, not the former.

The first release target is therefore a replayable, auditable local architecture. It is not a
claim to solve an open problem, and a successful FATE run is not evidence that the system can
construct a coherent multi-file mathematical library.

## Authority and non-authority

| Component | Owns | Must not do |
| --- | --- | --- |
| Builder | Source provenance, rights, normalization, formalization candidates, semantic-fidelity gates, contract freezing, and new revisions | Search for proofs, accept proof output, or mutate a frozen revision |
| Prover | Role-scoped context, model calls, proof search, proof candidates, gap evidence, and change requests | Add hypotheses, reorder quantifiers, weaken a conclusion, replace a declaration, or apply a contract change |
| Independent verifier | Clean build, immutable statement boundary, environment binding, and axiom-policy checks | Decide that an informal source was faithfully formalized |
| Control plane | Durable commands, task binding, fencing, append-only events, content-addressed evidence, and read models | Infer mathematical meaning or silently repair a failed task |
| Dashboard | Read-only presentation of projected events and artifact references | Read raw workspaces, expose secrets or prompts, submit commands, or become a source of truth |

This split is enforced in the current code by the shared
[StatementContractV1](../packages/contracts/src/autolean_contracts/models.py#L521), the
Builder freeze/bridge functions
([freeze_contract](../Builder/src/autolean_builder/workflow.py#L273) and
[bridge_frozen_contract](../Builder/src/autolean_builder/workflow.py#L302)), and the
control-plane command gateway
([ControlPlane](../packages/control_plane/src/autolean_control_plane/service.py#L87)).

## Three graphs, not one DAG

The graphs have different meanings and must remain independently versioned. A visual edge in
one graph is never evidence for an edge in another graph.

| Graph | Question answered | Nodes and edges | Invalid shortcut |
| --- | --- | --- | --- |
| MathematicalGraphV1 | What does the mathematics require? | Definitions, theorems, examples, notation, conventions; uses/defines/specializes/equivalence/motivation | Treating an import or a scheduled task as a mathematical prerequisite |
| FormalGraphV1 | What does Lean require? | Lean declarations, instances, notation, imports; signature/body/import/instance dependencies | Treating an incidental import as source-level mathematical intent |
| ExecutionGraphV1 | What work is running and why? | Ingest, rights review, normalization, formalization, review, proof, verification, integration; blocked/produces/retry/supersedes edges | Treating a completed task or retry as a proved mathematical dependency |

The data models are separate in
[graphs.py](../packages/contracts/src/autolean_contracts/graphs.py#L1). Formal and execution
dependency graphs are acyclic; the mathematical graph permits only explicitly non-DAG relations
while still rejecting dangling endpoints and self-edges. The bundle hashes all three graphs
together as a snapshot, but does not merge their semantics.

    MathematicalGraph (source meaning) ------+
                                              |
    FormalGraph (Lean dependencies) ----------+--> StatementContract V1
                                              |           |
    ExecutionGraph (work and evidence) -------+           v
                                        FormalizationTaskBundle V1

## Versioned contract boundary

packages/contracts is the only shared Builder--Prover language. It deliberately contains no
provider SDK, database implementation, agent loop, or dashboard transport. The V1 models are
implemented in [models.py](../packages/contracts/src/autolean_contracts/models.py#L1).

| V1 record | Binding purpose |
| --- | --- |
| SourceRecordV1 and SourceSpanV1 | Source identity, version, locator, byte hash, reviewed spans, and permitted excerpts |
| RightsRecordV1 | License, redistribution/model-egress decisions, endpoint classes, restrictions, and reviewer evidence |
| StatementContractV1 | Stable contract ID/revision plus normalized mathematics, Lean source, imports, axioms, policy, fidelity, and provenance |
| FormalizationTaskBundleV1 | The only Builder-to-Prover handoff: frozen contract, typed fidelity-artifact reference, and hash-bound three-graph snapshot |
| ProofSubmissionV1 | Candidate proof source bound to contract ID, revision, contract hash, and environment hash |
| GapReportV1 | Evidence that proof work is blocked without changing a theorem |
| ContractChangeRequestV1 | A request Builder may review; it cannot change the current revision itself |
| VerificationReportV1 | Kernel/build/dependency/clean-environment/axiom observations bound to proof and contract hash |
| ReviewDecisionV1 and EventEnvelopeV1 | Independent review evidence and hash-bound portable event representation |

### Identity is not content

AutoLean stores stable IDs separately from content digests. Source bytes, statement source,
elaborated type, environment, graph snapshot, proof source, contract payload, configuration,
prompt, tool, and event each use a distinct digest kind. The implementation is in
[hashing.py](../packages/contracts/src/autolean_contracts/hashing.py#L1). This prevents a
caller from substituting a proof hash where a source hash is required, or claiming that a
declaration name alone identifies a theorem.

A semantic change produces a new revision with the same stable contract ID; it begins as a
draft and must re-enter the Builder workflow. Old frozen revisions, bundles, submissions, and
reports remain historical evidence. The revision-lineage guard is
[create_next_revision](../Builder/src/autolean_builder/workflow.py#L292).

### Freeze is a semantic gate, not a status label

The implemented Builder state machine is:

    ingested -> rights_reviewed -> normalized -> mathlib_mapped
             -> candidates_reviewed -> fidelity_reviewed -> frozen -> bridged

The gate requires reviewed rights, cited spans and alignments, resolved blocking ambiguity, an
elaborated Lean type, two independent candidate groups, matching candidate statement evidence,
source preservation, reverse rendering, independent translation, positive and negative examples,
non-vacuity, mutation probes, and independent signoff. Higher-risk tasks add library and domain
review; open conjectures remain in a quarantine release tier and need independent verifier
signoff. See [FreezeGate](../Builder/src/autolean_builder/workflow.py#L123).

The V1 contract layer also makes nested mapping payloads immutable and revalidates a model_copy
update, so callers cannot bypass a hash or state invariant by shallow mutation. This is a
code-level defense in [ContractModel](../packages/contracts/src/autolean_contracts/base.py#L68);
it still needs the adversarial and replay tests in the acceptance plan.

## End-to-end lifecycle

    cited source -> Builder semantic review -> frozen contract -> immutable bundle
                                                             |
                                                             v
                  Dashboard <- event projection <- Control plane <- fenced worker
                                                             |
                                          independent verifier <- proof candidate

The public protocol is intentionally only claim, submit_proof, report_gap,
request_contract_change, and verify_submission. Details are in [protocol.md](protocol.md).

## Current implementation boundary

The following are **implemented code surfaces**, not yet release evidence:

- contracts, graph validation, typed hashes, and freeze records;
- a Builder workflow and conservative freeze gate;
- SQLite WAL event storage, content-addressed artifacts, and fenced leases;
- a control-plane command gateway and lossy read-only dashboard projection;
- provider policy/registry, lease- and ContextPack-bound model authorization, role-scoped context
  packs, immutable attempt materialization, OCI command construction, and a Lean-facing verifier;
- frozen OCI verifier policy plus canonical, content-addressed verification evidence artifacts
  cross-bound to the bundle, proof, candidate, statement, and manifest;
- typed Builder fidelity evidence rooted in the signed handoff and append-only registration event,
  with retained bytes rehashed and cross-bound before production registration;
- a secret-free verifier signing request, durable anti-replay ledger, and gateway/control-plane
  checks binding each signature to the current lease holder, fencing token, expiry, and canonical
  verification context; this is a software boundary, not a deployed mTLS/KMS service;
- a 20-node multi-file project-DAG fixture plus in-process and synthetic OS-process control-plane
  replay harnesses; none runs Lean or OCI and none alone is release evidence; and
- a strict FATE source adapter that replaces only the pinned proof slot.

The following remain **required demonstrations**, rather than current guarantees:

- clean Lean builds in the pinned Linux OCI environment, including elaborated-type and import
  boundary checks;
- 1,000-job kill/restart, duplicate-delivery, expiry, fencing, and event-replay evidence;
- browser security tests for the panel and an authenticated remote-access policy;
- concrete provider capability probes and operator endpoint approval, rather than merely a
  registry interface;
- a bundle-level trusted solver-workspace/comparator manifest compatible with external
  evaluation boundaries such as lean-eval; and
- calibrated Builder fidelity evidence on human-reviewed source material.

The exact gate matrix is maintained in [phase-1-acceptance.md](phase-1-acceptance.md).

## Design consequences

1. A proof failure is information, not permission to modify a theorem. It yields a typed gap or
   a typed change request and leaves the frozen revision untouched.
2. A green benchmark cell is not a semantic review. FATE is useful proof-search evidence, while
   multi-file construction is tested separately by the project DAG fixture.
3. An open-problem task is permitted in the type system from the start but is isolated in
   conjecture_quarantine. Promotion requires the complete semantic and formal evidence chain,
   not an agent narrative.
