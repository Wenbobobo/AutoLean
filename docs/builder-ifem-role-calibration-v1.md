# iFEM role calibration boundary

Status: implemented local protocol and fake end-to-end bridge; non-promotable synthetic evidence only

## Scope

The iFEM structural lane now has sixteen project-authored baseline/mutant pairs: two pairs for
each of eight structural risks. The pair corpus is evaluator-side metadata, not a source
formalization. It creates no `StatementContractV1`, `FormalGraph`, `ExecutionGraph`, frozen
revision, model authorization, or Prover task.

The three role labels are deliberately local:

| Role | Pairs | Intended observation |
| --- | ---: | --- |
| `statement_formalizer` | 8 | abstain when a source-text-free structural description is insufficient |
| `fidelity_reviewer` | 4 | distinguish a surface-matched baseline from a harmful local mutation |
| `cheating_supervisor` | 4 | detect a change to the declared structural boundary |

These counts are a coverage denominator, not a role score and not a claim about theorem
formalization ability.

## Mathematical witness layer

`ifem_structural_witness_validation.py` recomputes all eight local observations from the exact
graph-bound corpus. It checks finite arithmetic, symbolic rules, and named standard-lemma
dependencies, and it publishes no private witness specification. A fixed golden commitment for
each specification rejects metadata drift before a corpus can be rebuilt.

Two boundaries are intentional:

- The absolute-value pair is a non-sign-closed singleton observation. For a usual all-vector,
  sign-closed bilinear continuity theorem, a one-sided bound may imply the absolute-value bound;
  this pair must not be interpreted as a theorem-level counterexample.
- The vacuity pair distinguishes guard satisfiability, not theorem truth: both implications are
  true while one antecedent is impossible.

The `schema_plus_standard_lemma` entries for the `l2/c00` examples are not Lean proofs. The
authority flags remain false and the report cannot be rendered unless the corpus and candidate
graph are supplied for evaluator recomputation. A self-consistent forged report is rejected.

## Pair split and private roots

`PairLevelSplitCommitmentV1` contains keyed commitments for both durable source/span identifiers
and their content hashes. The private builder uses a transitive leakage closure over scenario,
source ID/content, span ID/content, mutation, and witness. Component ranking is based on the
complete identity projection rather than mutable pair IDs, so renaming records cannot change the
partition. The local fixture accepts only the verified HMAC implementation; a future KMS/HSM
adapter must be added as a separately attested implementation before production use.

Public split JSON is an opaque projection and explicitly requires private re-verification. It is
not a signed partition authority. Private manifest labels and key labels are projected as keyed
opaque identifiers; raw source, oracle, prompt, and workspace values remain private.

`private_pair_partition_store.py` materializes train/dev in one local CAS root and
`private_heldout` in a disjoint root. A tuning store capability rejects the held-out reference
before reading the filesystem. This is a local capability boundary, not production isolation:
the authority flag requires disjoint OCI mounts for an actual model run.

The public synthetic fixture additionally binds each ordinal to its fixed role, identifier
namespace, repository locator, source metadata, rights record, and egress span locator. Its
ordinary content hash is still an integrity check rather than authentication; a private corpus
or oracle revalidation is required before a run. The renderer therefore rejects a recomputed-hash
fixture that changes the role or provenance fields.

## Exact egress bytes

Chat Completions and Responses providers now serialize a credential-free canonical JSON object once,
bind its `OUTBOUND_REQUEST_BODY` digest, and send those exact bytes with `httpx.content`. The
Authorization header is injected separately and is never in the body or digest. Fake transports
capture the bytes, and a mock HTTP transport checks byte-for-byte identity.

The existing model authorization still binds the logical `ModelRequest` hash. The independent
iFEM bridge in `benchmarks/ifem_synthetic_role_bridge.py` keeps the logical hash and exact body
binding side by side in an in-memory prepared request, applies a fixed role-specific system
prompt, requires an executor to acknowledge the same bytes at execution time, and projects a
request/body-only `IFEMSyntheticRoleReceiptV1`. The public receipt omits model-output and
response-ID digests because those values are low entropy. D31 now supplies an authenticated,
operator-private CAS/append-only ledger and immutable sixteen-case manifest; its public projection
uses only a keyed output commitment. Its private-oracle evaluator is transient and does not create
a benchmark authority, statement contract, freeze, or Prover handoff. Any future evaluator adapter
must use this exact-byte protocol rather than creating a second provider path.

## Current verification

The local focused checks cover the role corpus, witness recomputation, pair commitments, private
store separation, exact-body transport, and seven provider-neutral fake bridge tests. They are
architecture regressions only. No DeepSeek call, textbook fidelity result, Lean kernel result,
model ranking, or Builder-to-Prover handoff is claimed by this lane.

The D29 reconciliation verifies the exact 8/4/4 role counts, private-oracle case coverage, and
receipt-to-fixture bindings. For every receipt it invokes a fixed preparation executor over the
rebuilt fixture and compares the prompt digest, logical request, provider/model/configuration, and
exact request-body binding. Rehashed prompts, reports, and arbitrary self-hashed request bindings
are rejected. The public report contains counts and public-fixture digests only; it omits an oracle
digest because the expected-side vector is enumerable. The corpus, seed, expected side, witness,
response text, and response identifier remain private. D31 provides an opaque keyed commitment
backed by an authenticated operator-private sidecar, but that commitment remains non-authoritative.
