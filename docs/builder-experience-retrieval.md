# Builder Experience Retrieval

## Decision

Builder experience is versioned, content-addressed, untrusted advisory evidence for a
statement-conversion role. It is not mathematical truth, a tactic rule, reviewer approval, or
permission to edit a frozen statement. The implementation is internal to Builder in
[`experience.py`](../Builder/src/autolean_builder/experience.py); it does not change the
Builder-Prover contracts.

Each `ExperienceRecord` binds:

- source ID, source version, source hash, and source-span IDs;
- record version, author role, intended roles, and a hierarchical domain path;
- required formal-graph frontier nodes and human-readable applicability conditions;
- a rights scope, policy revision, and allowed endpoint classes;
- either a successful pattern, negative evidence, or a gap; and
- content-addressed failure evidence for every negative or gap record.

The record hash covers every field. Source excerpts, prompts, credentials, raw logs, and proof
answers do not belong in a record.

## Retrieval

`ExperienceRetriever` first applies hard filters:

1. the requested role must be explicitly listed;
2. the record domain must be a prefix of the query domain;
3. every required graph-frontier node must already be present;
4. the rights scope must match exactly;
5. the requested endpoint must be allowed; and
6. the outcome must be requested.

It then ranks by domain specificity, frontier specificity, applicability specificity, and record
hash. No stochastic component, embedding, vector database, model score, or wall-clock time enters
the ranking. Greedy selection respects both item and deterministic canonical-JSON token budgets.

The resulting `ExperienceContextPack` records the exact query, ordered candidate hashes, selected
record snapshots, estimator version, and byte-derived token estimate. Replay reruns filtering,
ranking, and budgeting from the content-addressed catalog and requires byte-identical output.

## Trust and rights boundaries

Rights default to local-only. External retrieval requires an explicit external review reference
on every selected record. Scope matching has no wildcard, so one textbook, license, client, or
private project cannot leak into another scope merely because its domain labels match.

All free text is JSON-quoted and labelled `quoted-untrusted-experience`. Ingestion rejects control
characters, bidirectional controls, common prompt-control markers, private-key headers, and
credential-shaped tokens. This is defense in depth, not a proof that arbitrary natural language
is safe; the receiving statement-conversion agent must treat record text as data and retain the
system and contract instructions as authority.

Successes, rejected translations, review failures, verification failures, and gaps remain equally
eligible after filtering. A retrieved record may inform a new draft candidate or test selection.
It cannot satisfy a fidelity check, sign a review, alter a contract revision, or bypass
`StatementFidelityHarness`.
