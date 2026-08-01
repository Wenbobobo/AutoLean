# iFEM Source-Free Private Seed V2

Status: internal protocol specification for the next calibration experiment. It is
not a benchmark result, a heldout-worker design, a mathematical classification,
or a Builder-to-Prover handoff.

## Purpose and boundary

V2 turns the exact, unknown-only iFEM P3 calibration-intent queue into nine
project-synthetic cases whose identities, partition mapping, finite oracle, and
per-run nonce remain operator-private. Its narrow purpose is to commit that
private material before exposing a public aggregate commitment, so a later
27-stage authoring experiment has a stable input and can recover after an
interruption without silently changing its cases.

The protocol does not read textbooks or other source material, produce a Lean
statement, call a provider, create ModelWork, classify mathematics, establish
semantic fidelity, or create any FormalGraph or ExecutionGraph edge. A private
seed is therefore not a statement contract and cannot be sent to Prover.

## Inputs and outputs

`LocalSourceFreePrivateSeedStore.commit_for_queue` accepts only the exact typed
`IFEMNextCalibrationCaseIntentsV1` queue. Revalidation requires it to be
source-free and to contain no formalization, model, or private payload. Exactly
nine intents must be P3 `create_calibration_case` intents; each must remain
unknown, structurally risk-marked, and `not_authored`. A different queue is not
an equivalent input merely because it has a similar shape.

The operator supplies an absolute local storage root outside every Git checkout
and a valid run label. The returned pair is:

1. A canonical, operator-private manifest containing the nonce, intent-to-case
   mapping, 3/3/3 partition, bounded synthetic baseline, selector, increment,
   hidden oracle, and content hashes.
2. A public commitment that can be canonically rendered only after the manifest
   has been persisted and re-read.

The manifest is deliberately project-synthetic: its finite signatures and
oracle test process mechanics, not an iFEM proposition or a textbook claim.

## Construction and persistence order

For normal execution the store obtains a fresh 32-byte nonce from
`secrets.token_bytes`. It uses `HMAC-SHA256(nonce, canonical-json(payload))`
to derive the run identity, rank each intent, and derive each synthetic case.
The sorted rank assigns exactly three `train`, three `dev`, and three
`private_heldout` cases. Case IDs and all content hashes are independently
validated, while exact replay from the retained nonce and queue rejects a
self-rehashed but altered manifest.

The order is binding:

1. Build the private manifest.
2. Atomically create it without overwriting an existing manifest, flush it, and
   read it back in canonical form.
3. Revalidate it against the exact queue.
4. Derive the public commitment.

If a process stops after step 2 or 3, a retry loads and replays the retained
manifest. It does not request fresh entropy. If a concurrent retained manifest
does not equal the candidate, the operation fails rather than replacing it.

The root is rejected unless it is absolute, outside the specified repository,
outside every ancestor containing `.git`, and free of symlink, junction, and
other reparse-point traversal at the checked root and manifest path. This is a
local containment check, not encryption, access control, or remote attestation.

## Entropy provenance

There are exactly two labels:

- `default_store_csprng_path`: used only by the normal store path after it
  obtains 32 bytes from the operating-system CSPRNG. Its public commitment
  marks only `default_csprng_path_claimed=true`.
- `test_injected_path`: used by the public deterministic test-builder or an
  explicitly injected test entropy callback. It marks
  `default_csprng_path_claimed=false`.

The public test builder cannot label a caller-supplied fixed nonce as the
default CSPRNG path. The path label is nevertheless self-declared artifact
metadata: a caller that can rewrite the private manifest can rewrite and
rehash that label. Consequently every public commitment fixes
`entropy_provenance_verified=false` and `unpredictability_verified=false`.
Future live dispatch requires an independently trusted generation receipt;
the V2 commitment cannot supply one.

## Public projection and non-disclosure

The public commitment contains the run ID, input-queue hash, private-manifest
content hash and size, entropy-path label, aggregate 9/3/3 counts, and explicit
boundary flags. Its persistence field is a supported-store-path observation,
not an attestation: `store_persist_before_projection_observed=true` and
`store_persistence_attested=false`. The renderer rejects the prescribed
private field names. It must not render any of the following:

- case IDs, intent IDs, node IDs, or an intent-to-partition mapping;
- partition values for individual cases;
- the nonce or its hexadecimal representation;
- baseline, selector, increment, expected candidate, hidden oracle, or any raw
  private-manifest bytes.

The manifest hash is a commitment to the private bytes, not a substitute for
private storage. The field-name check is a narrow regression guard; it is not a
general data-loss-prevention system. Callers must separately ensure that private
manifest bytes, model prompts, raw outputs, and operator storage locations are
not copied into repositories, logs, public reports, or artifacts.

## Authority and isolation claims

Every V2 object carries the all-false
`SourceFreeCaseAuthoringAuthorityV1` capability record. In particular, it
does not authorize semantic classification, semantic fidelity, statement
contract creation, FormalGraph or ExecutionGraph creation, model egress,
machine advisory, heldout isolation, freezing, Prover handoff, or promotion.
The public commitment fixes `live_model_eligible=false`,
`builder_freeze="forbidden"`, and `prover_handoff="forbidden"`; its freeze and
handoff methods fail closed.

The current materialization is explicitly `same_process_materialization=true`
and `heldout_worker_isolation_claimed=false`. `private_heldout` is therefore a
private partition label and count, not proof that a separate worker, model,
identity, filesystem, process, or network boundary protects it. It must not be
used to make heldout-performance, anti-contamination, or model-comparison
claims.

## Threat model and non-claims

V2 is designed to detect ordinary malformed input, accidental corruption,
unintended replacement of a retained run, simple path redirection, and private
manifest changes that no longer replay against the queue. It also makes a later
accidental case-set change observable through the retained hash and replay
check.

It does not defend against a compromised operator host, a reader of the private
store or process memory, compromised entropy, malicious local administrators,
private-output exfiltration, hash or metadata side channels, or an attacker who
already knows the nonce. It does not prove that HMAC-derived cases are fair,
representative, independent, semantically faithful, non-contaminated, or
unseen by a model. It makes no claim about Lean kernel verification, rights,
source fidelity, mathematical truth, benchmark ranking, or open-problem
progress. File flush plus atomic hard-link publication supports the tested
process-interruption boundary; without a parent-directory durability receipt,
V2 does not claim persistence across operating-system or storage power loss.

## Implemented downstream interfaces

The protocol intentionally stops before model dispatch. The downstream
[private stage ledger](ifem-source-free-stage-ledger-v1.md) and
[ModelWork sidecar](ifem-source-free-model-work-sidecar-v1.md) consume this
persisted-and-revalidated manifest rather than an in-memory pre-persistence
candidate. The ledger is keyed by one exact stage coordinate per
`(run_id, case_id, role)` for the fixed role order:

`statement_formalizer -> fidelity_reviewer -> cheating_supervisor`.

There are exactly nine cases times three roles: 27 coordinates. State ownership
is deliberately split rather than duplicated: the ledger owns dispatch state,
the shared control plane owns lease/authorization/reservation/settlement, one
fenced EventStore event binds the coordinate to its exact authorization, and
private CAS owns response bytes. Recovery discovers a settled completion by
authorization and never redispatches an unknown attempt. The one-attempt bound
is enforced by the authorization plus the unique attempt event, not a caller
loop.

Its public summary may bind only the V2 commitment and aggregate counts. It
must not reveal private coordinate mapping, raw model output, oracle, nonce,
or private storage information. Before any live execution, the composed stack
still needs a real operator approval, idempotent admission gateway,
private-output retention policy, worker-isolation decision, and independent
evaluation protocol. Those mechanisms are not provided by V2 and cannot be
inferred from the 3/3/3 split.
