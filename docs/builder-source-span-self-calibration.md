# Builder source-span self-calibration

Status: offline architecture harness; no semantic, rights, kernel, freeze, or release result

`SourceSpanSelfCalibrationHarness` fills the gap before the normal Builder fidelity workflow. It
starts from a path-bound, runtime-reverified corpus handle and one unfrozen
`PreCalibrationFixtureRecordV1` source span in that corpus. It runs this fixed proposal-only
sequence with five actor executions across four role kinds:

1. two conversion proposers with distinct declared identities, independence groups, and role
   environments;
2. one independent reverse-render reviewer over both proposals;
3. one critic that must produce a quantifier mutation and a boundary mutation for each proposal;
4. one adjudicator that preserves both candidate findings and at least one unresolved issue.

V1 accepts only the repository's 11 project-synthetic opening samples through
`load_source_span_calibration_corpus`. That loader verifies the canonical corpus path, release
manifest, renderer, repository license, and exact corpus bytes before returning a handle containing
only the resolved path and its binding. The handle is not a Python security capability. Every
`run()` and input-binding build reloads the path through the same verifier and rejects any fresh
binding mismatch; no admitted corpus model or forgeable same-process token is retained. The corpus
and manifest digests are retained in every input binding. V1 also accepts
only exact deterministic local `fake` provider objects. It deliberately does not create a provider
authorization artifact or support a real endpoint. A future real-model route must pass through
the existing rights-bound model-work authorization and settlement boundary; replacing `fake` with
an arbitrary provider is rejected.

## Evidence contract

The result binds the complete fixture snapshot, `SourceRecordV1`, `RightsRecordV1`, exact source
span, local normalization baseline, mutation fixtures, fixed role protocols, provider/model
configuration, role environment, input/output token/byte limits and a declared timeout ceiling,
private-input hashes, raw
response hashes, parsed-output hashes, dependency hashes, and all five execution hashes. The
canonical result has a stable SHA-256. Its input binding contains no source excerpt, prompt,
credential, or operator path. Model outputs are retained as evidence and may repeat source text;
that is another reason V1 is restricted to the public project-synthetic corpus.

Proposers do not receive the synthetic normalization baseline. After each response, the harness
computes added and removed assumptions and quantifiers, quantifier sequence changes, plus
normalized-statement and conclusion changes, against that hidden fixture baseline. Therefore a
structural change is recorded even when the proposer omits it. This is a string-structural
detector, not a proof of semantic equivalence; a paraphrase may be flagged and an
equivalent-looking string may still be wrong. A reverse reviewer cannot simultaneously mark a
candidate equivalent and report assumption, quantifier, or boundary drift, and a non-equivalence
claim must identify at least one structured drift. The equivalence boolean is therefore constrained
to be the inverse of structured drift rather than treated as a second reviewer signal. Only the
structured drift fields are machine-interpreted. The reconstructed statement, rationale, and other
prose are untrusted model output: the harness stores and hashes them but performs no heuristic NLP
and derives no semantic authority from them.

Mutation proposals carry an explicit anchor category, baseline fragment, replacement fragment, and
applied statement. A quantifier-family mutation must use a `quantifier` anchor; a boundary-family
mutation must use a `conclusion` or `boundary_condition` anchor. The harness replays the single
local replacement and requires quantifier probes to bind an explicit candidate quantifier. A
conclusion probe binds the separately hashed source conclusion or a declared conclusion-impacting
fixture (`sign_flip`, `strict_to_nonstrict`, attainment/existence/geodesic strengthening, or
parameter reversal). A boundary-condition probe binds a separately hashed declared condition
fixture (regularity, nonempty/vacuity, finite, or Noetherian). `quantifier_swap` fixtures are not
admitted as boundary anchors. These hash classes are disjoint. Quantifier and boundary probes
for one proposal must use distinct baselines, and the exact fragment must occur once in the
candidate text. Control/format codepoints, including zero-width changes, and Unicode
normalization-equivalent replacements are rejected before replay. This proves a visible,
replayable structural mutation, not that its expected semantic failure is correct.

The residual trust assumption is ordinary local process and filesystem integrity while one call is
running: Python monkeypatching could replace the verifier itself, and a hostile process with write
access could race local files. A handle forged with `object.__new__`, a Pydantic
`model_construct` corpus, or a modified stored binding cannot admit extra samples because `run()`
reloads the canonical bytes and compares the fresh binding. This is an application invariant, not
an operating-system sandbox claim.

The fake provider is synchronous, so V1 binds but does not independently enforce or attest the
declared timeout ceiling. Its token counts are scripted declarations rather than independently
tokenized measurements; the verified constraint is the raw response-byte limit. JSON responses
use exact schemas and reject duplicate keys, missing proposal coverage, duplicate
actor identities, shared declared independence groups, unchanged mutations, missing
quantifier/boundary families, provider drift, and budget overruns. True process, organization, or
failure-domain independence is not established by those checks.

## Authority boundary

Every actor, execution, proposal, and result carries
`evidence_class=machine_advisory_proposal_only` with all authority fields fixed to `false`. Even a
fully consistent fake run retains blockers for machine-only evidence, unverified independence,
and absent rights, semantic-review, kernel, and freeze authority. `machine_advisory_continue`
means only that the artifact can inform another Builder round. `freeze_statement()` and
`handoff_to_prover()` always fail.

The focused test suite replays the five-actor/four-role loop across all 11 synthetic samples and
checks stable hashes, visible assumption drift, mandatory quantifier/boundary coverage,
duplicate-key rejection, runtime-reverified corpus admission, forged-object/model-construct
rejection, quantifier-order drift, explicit anchor-family matching, distinct mutation baselines,
Unicode-safe replayable mutation diffs, declared actor separation, declared provider budgets, and
non-promotability. This is repeatable architecture evidence only; the scripted outputs are not
Builder calibration scores or evidence that any sample was translated faithfully.
