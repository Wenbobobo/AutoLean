# Formal Assistant Landscape: Adoption Boundaries

Status: active architecture decision; no engine was adopted and no performance claim is made

Decision date: 2026-07-24

## Decision

AutoLean will take four bounded lessons from the material reviewed here:

1. dispatch proof work through capability-adaptive `direct`, `light`, and `full` paths, rather
   than treating multi-agent orchestration as a universal improvement;
2. make definition and statement conversion an explicit Builder risk surface, with a typed error
   taxonomy and a structural-context experiment;
3. borrow from Danus only the *ideas* of tiered exploration memory, construction/counterexample
   parallelism, and cascade revocation; and
4. keep Reap as a future, non-authoritative fallback-search candidate behind a frozen bundle and
   AutoLean's existing independent verifier.

Neither external project supplies an authority boundary for AutoLean. A successful search trace,
an accepted graph node, or an LLM judgement never freezes a statement, accepts a proof, grants
model egress, or promotes a Library asset. Those operations remain governed by the versioned
Builder--Prover contract and the verifier-owned clean build.

## Evidence and confidence labels

This record deliberately separates what was directly inspected from what an author or presenter
reported. It is not a reproduction study.

| Label | Meaning in this record |
| --- | --- |
| **Local observation** | Read from the checked-out local meeting material or its extracted text. |
| **Source audit** | A code-level conclusion from the named, pinned public revision, checked during this project review. |
| **Author claim** | A result, performance number, or positioning asserted by a talk, blog, or paper; not independently reproduced here. |
| **Decision** | AutoLean's design choice, not a claim about the referenced work. |

The preserved local material is intentionally not copied into the tracked documentation tree:

- `docs/meeting/photo_1_...jpg` through `photo_6_...jpg` are photographs of the Archon talk;
- `docs/meeting/chat.txt` identifies the projects to investigate and preserves the original
  prompts for the inquiry;
- `docs/meeting/share_file.pdf` is a local thesis copy. Its derived text and rendered key pages
  live under ignored `tmp/pdfs/meeting-evidence-20260724/`.

The thesis is Qiyuan Xu, *Automating Separation Logic-based Program Verification by Algebraic
Rule Generation and Neural Theorem Proving*. Page references below are locators into that local
copy, not quotations. Rights, distribution, and model-egress policy for the original material are
separate from this decision record.

## Meeting evidence: what transfers and what does not

### Capability-adaptive orchestration

**Local observation.** The photographed slides describe a simple-task comparison (slide 22), an
informal rule that orchestration benefit grows with task difficulty relative to model ability
(slide 24), and role-specific model allocation (slide 25). The same deck distinguishes a
repository/theory-scale formalization task from a clearly stated single theorem. Its displayed
elapsed-time bars and model comparisons are presentation claims: their workloads, repetitions,
prompts, budgets, environments, and acceptance checks are not available in the screenshots.

**Decision.** AutoLean adopts the *dispatch principle*, not the numbers or the specific routes in
the slides. A future dispatcher must select from:

| Path | Appropriate boundary | Required record | Escalation rule |
| --- | --- | --- | --- |
| `direct` | One frozen statement and a bounded, isolated proof attempt | bundle hash, pinned environment, prompt/tool policy hash, budget, verifier result | Move to `light` only after a classified proof gap or exhausted registered budget. |
| `light` | One statement or a small local prerequisite closure needing bounded repair/retrieval | all `direct` fields plus context-pack and attempt lineage | Move to `full` only when the registered dependency/frontier criterion is met. |
| `full` | Multi-file or multi-node dependency work, Builder conversion, or an explicit project-level gap | all `light` fields plus execution-graph lease, frontier, immutable artifacts, and recovery events | It may return a gap or contract-change request; it may not mutate a frozen statement. |

The path is selected from declared bundle complexity and calibrated role evidence, not a provider
name. Every path retains the same final acceptance boundary: the original declaration type,
allowed imports/axioms, fixed Lean environment, and independent verifier. An orchestration gain
that disappears under equal budget or changes the statement is not a gain.

**Verification experiment.** On a preregistered, disjoint slice of the existing fixed benchmark
and the internal multi-file DAG fixture, compare the three paths with identical statement bundles,
model capability policy, retrieval scope, wall-clock/token budgets, and clean verifier. Report
`success@budget`, type-preserving verification rate, time, token/cost, retries, and rejected
submission reasons. Do not compare only raw theorem pass rate. No routing policy is promoted
until it also preserves the recovery, lease, and no-network invariants.

### Definitions and statement conversion

**Local observation.** Slide 23 explicitly argues that definitions are often more fragile than
filling an already specified proof: a narrow or mis-specified definition propagates downstream.
This is consistent with AutoLean's current Builder ownership boundary. The thesis also treats
translation and dependency handling as first-class work (pp. 84--85 and 91--92), rather than an
unobservable pre-processing step.

**Decision.** The Builder will extend its existing fidelity Harness with a conversion error
taxonomy. A finding is recorded as a `GapReportV1` or `ContractChangeRequestV1`; no category
permits silent theorem weakening.

| Error class | Typical symptom | Required evidence before a new revision can proceed |
| --- | --- | --- |
| Source locator or terminology | Claim tied to the wrong theorem, edition, notation, or scope | source span/hash, reverse rendering, independent source review |
| Definition boundary | Representation, equivalence, coercion, or abstraction level differs from the source | definition map, positive/negative examples, downstream dependency impact |
| Binder and parameter scope | Quantifier order, implicit parameter, universe/typeclass, or free-variable context changes | binder diff, mutation result, elaborated-type check |
| Hypothesis and side condition | Nonempty, finite, regularity, finiteness, or admissibility condition is dropped or strengthened | condition mutation, counterexample/known-special-case review |
| Relation and conclusion | Equality versus isomorphism, strict versus weak bound, direction, or conclusion changes | relation mutation, reverse rendering, independent semantic review |
| Dependency or import leakage | Accidental theorem/import supplies an unadvertised premise | pinned-import audit, axiom report, mathematical-graph comparison |
| Vacuity and witness failure | Premise is contradictory or intended examples do not inhabit the claim | non-vacuity test, positive and negative examples |

The taxonomy is a review and measurement interface, not a substitute for expert judgement. It
will be added to mutation results, semantic review, and dashboard projections only after a schema
revision and backwards-compatibility decision.

### Structured context rather than shifting text locations

**Local observation.** The thesis' AoA discussion represents proof construction as edits over an
abstract syntax tree and reports direct access to local proof-state feedback (pp. 127 and
130--137). It also warns that the result is tied to its small proof language and that its measured
benefits do not automatically transfer to another assistant (p. 143). Its evaluation and
discussion cover data/licensing boundaries, benchmark corrections, recursive dependency
translation, failure modes, and the complementarity of neural and classical automation
(pp. 145--156). A separate failure analysis identifies syntax, semantic/pragmatic confusion, and
hallucinated entities as distinct problems (pp. 93--94 in the local page numbering).

**Decision.** Do not migrate AoA's language, agent runtime, or reported efficiency figures. Run a
small `StructuralContextPackV0` experiment instead. It will give a proof worker an immutable,
rights-scoped view containing a pinned source snapshot, declaration identifiers, imports, local
context/proof-state snapshots where available, stable hole/node identifiers, and structured
diagnostics. It must never expose a writable repository root or become a semantic authority.

The experiment has three arms over the same frozen bundles: current bounded textual context,
line/span-addressed context, and structural context. Hold provider capability, prompt template,
tools, retrieval range, seed policy, and budgets fixed. Measure elaboration/type-preservation,
successful verifier acceptance, recovery after an edit, stale-location errors, tool calls,
tokens, wall time, and conversion-error classes. The structural arm is rejected if it broadens
imports, changes declarations outside the declared write set, bypasses the OCI worker, or merely
improves a model-visible proxy while degrading clean verification.

## Danus: concepts retained, runtime rejected

### Pinned sources and audit status

- Public blog: <https://frenzymath.com/blog/danus/>.
- Paper version reviewed for orientation: <https://arxiv.org/abs/2607.06447v2>.
- Source revision audited: `7aad41077147af7b8f2a697512075bb326ade992` (Danus v0.1.0).

**Source audit.** The audited revision has a useful conceptual separation of exploratory and
accepted fact memory and supports construction/counterexample-style exploration. It does not
provide AutoLean's contract/authority semantics. In particular, the reviewed `fact_submit` path
does not bind a fact to a frozen mission, statement revision, and validated predecessors; its
LLM-verifier route is not an independent proof authority; graph predecessor validation is
insufficient at the insertion boundary; and its short identifiers/metadata handling are not
adequate immutable provenance. The revision also lacks the transactional lease, reproducible
attempt-artifact, and provider-policy boundaries required here.

**Decision.** Retain only these design ideas, implemented natively against AutoLean contracts:

| Idea | AutoLean interpretation | Non-negotiable boundary |
| --- | --- | --- |
| Tiered exploration memory | Keep scratch hypotheses, reusable but unaccepted observations, and accepted verifier-backed facts in distinct stores. | Only a frozen contract plus clean verification can produce an accepted fact. |
| Construction/counterexample parallelism | Schedule constructive proof and counterexample/assumption-testing tasks as separate leased attempts. | A counterexample is evidence for a gap/revision request, never permission to edit the claim in place. |
| Cascade revocation | Record downstream impact when a source, definition, or contract revision is invalidated. | Revocation is append-only and revision-scoped; it cannot erase historical attempts or mutate old proofs. |

**Rejected.** Do not fork or import Danus runtime, graph acceptance, verifier, identifier scheme,
or provider configuration. This decision is architectural, not a negative judgement on its
research contribution: a system intended for exploratory conjecture management may rationally
choose different trade-offs. It is incompatible with AutoLean's stricter promotion boundary.

## Reap: isolated fallback-search candidate only

### Pinned sources and audit status

- Public announcement: <https://frenzymath.com/blog/reaper-1/>.
- Source revision audited: `19dff902126427fd82c28e03fbc66f76b4157743`
  (Reap v4.28.0-rc1).

**Author claim.** The announcement reports miniF2F results, including `77.5%` pass@32 for a
current checkpoint and `80.3%` accumulated across reinforcement-learning steps. These are not the
same experimental object and have not been reproduced in AutoLean. Treat them as motivation for a
carefully controlled candidate experiment, not a model ranking or an expected result.

**Source audit.** The reviewed code uses Lean-native saved states and an AND/OR MCTS-style search,
then replays a final candidate in Lean. This is directionally compatible with a proof-search
*engine*. It is not sufficient as a verification architecture: state keys are based on rendered
form, merging is limited, resource accounting has edge cases, and the search code does not supply
AutoLean's import/axiom policy, immutable bundle binding, endpoint policy, artifact receipt, or
network-isolated execution guarantee.

**Decision.** Define a future `ReapSearchEngine` adapter only after the core proof and Library
authority path is stable. It receives a `FormalizationTaskBundleV1` that is already frozen and
executes inside an attempt-specific, default-no-network OCI worker. It may emit tactic/proof-patch
candidates and a raw search trace. It has no authority over Builder state, contracts, review,
verification reports, or promotion. All candidates still pass the existing elaborated-type,
import/axiom, clean-build, and receipt checks.

Admission requires all of the following before any default fallback is enabled:

1. a deterministic fake-policy canary and adversarial invariant suite pass `90/90`, including
   wrong-target, altered-statement, network, budget, and trace-binding attacks;
2. every accepted candidate reproduces in two clean, digest-pinned worker runs;
3. a three-arm, preregistered comparison on the disjoint `compare-90` workload compares direct
   search, Reap with uniform selection, and Reap with value guidance under identical budgets; and
4. the paired analysis shows a positive effect with uncertainty reported, without a policy,
   isolation, cost, or statement-integrity regression.

This is deliberately deferred. A proof-search fallback is valuable only after its output is less
trusted than the verifier, not more trusted than the frozen task.

## External ecosystem: first-pass primary-source review

The local chat record named MechMath, Quokka, and reaslab. This pass replaces the generic
placeholder with two primary-source reviews and one explicit disambiguation boundary. It remains
strictly weaker than a source audit: no verified repository revision, license, release artifact,
benchmark harness, or security review is inferred from a paper, institutional article, or public
web page.

| Project | Evidence state | AutoLean status |
| --- | --- | --- |
| MechMath Agent Team (MMAT) | Public paper and institutional report inspected; implementation assets not audited | Concepts only; no runtime adoption or performance endorsement |
| ReasLab / ReasFlow | Public paper and historical workshop material inspected; implementation assets not audited | Research-provenance and retrieval ideas only |
| Quokka | Referent unresolved | No conclusion and no roadmap effect |

### MechMath Agent Team (MMAT)

**Primary sources.** The [MMAT paper](https://arxiv.org/abs/2607.04394) was submitted on 2026-07-05.
The [Chinese Academy of Sciences report](https://amss.cas.cn/kyjz1/202607/t20260719_8251739.html)
was published on 2026-07-19. Both links were reachable during this review.

**Facts about the public record.** The paper describes an agent system for mathematical research
and names a three-part Harness Architecture: Control, Execution, and Augmentation. It names a
Knowledge Base Manager, Natural Language Prover, and Formal Language Prover. The institutional
page contains an account of an IMO 2026 run and identifies a Lean 4.29.0/mathlib environment.
These facts establish what the documents say, not that the described system or results have been
independently reproduced.

**Author and institution claims, not independently reproduced here.** The paper reports a
two-month deployment and eleven solved problems. The institutional report says the system solved
all six IMO 2026 problems, generated natural-language and Lean proofs, used an offline/no-web
environment, and that the submitted Lean files have no placeholder proofs, use only Lean's
standard axioms, and pass its dependency/axiom checks. Its description of the three planes and
three specialist roles is likewise a project claim until the cited source tree, exact commits,
inputs, and checker outputs are independently examined.

**Evidence gap.** No official implementation repository, license, source commit, package lock,
Lean files, command transcript, immutable run artifact, or benchmark protocol was verified in
this review. Therefore neither the eleven-problem count nor the IMO result can be entered in an
AutoLean comparison table, used to rank models, or treated as evidence that a particular Harness
is correct.

**Decision.** Adopt only two architectural prompts for an AutoLean-native design:

| MMAT idea | AutoLean interpretation | Boundary |
| --- | --- | --- |
| Control / Execution / Augmentation planes | Treat planning, isolated workers, and advisory retrieval/knowledge management as distinct responsibilities. | These are responsibility planes, not new authority domains or new graph types. |
| Knowledge Base Manager | Improve rights-scoped, content-addressed retrieval and maintain source/provenance summaries for Builder and Prover ContextPacks. | It cannot certify a fact, alter a frozen contract, select a proof, or grant egress. |

Cross-plane communication remains the existing versioned-contract and immutable-artifact
protocol. Control may schedule an attempt; Execution may submit a patch; Augmentation may return
advisory records; only the appropriate Builder or verifier gate may change lifecycle state. No
MMAT component, prompt, model route, performance number, or unreviewed code is adopted.

### ReasLab / ReasFlow

**Primary sources.** The [ReasFlow paper](https://arxiv.org/abs/2607.14178) was submitted on
2026-07-15. The provided [NUS workshop abstracts](https://ims.nus.edu.sg/wp-content/uploads/2024/04/15-Apr-Abstract.pdf)
are historical 2024 Lean/retrieval context; they predate ReasFlow and do not establish a current
ReasLab source release. Both links were reachable during this review.

**Facts about the public record.** The ReasFlow paper presents itself as a knowledge-based
multi-agent system for applied-mathematics discovery, with internal verification and automated
knowledge/procedural-heuristic retrieval. The NUS material documents earlier work on integrated
Lean environments and semantic retrieval for mathlib4. These sources motivate a provenance and
retrieval review, but they do not constitute a kernel-verification or benchmark artifact for
AutoLean.

**Author claims, not independently reproduced here.** The ReasFlow paper claims autonomous
research-paper generation, a human-principal-investigator workflow, internal logical auditing,
and comparative results under a curated LLM-based review rubric. Those claims are not Lean proof
certificates and are not comparable to a frozen-statement, clean-build measurement without the
exact task set, reviewer protocol, model configuration, source code, and retained outputs.

**Evidence gap.** The core ReasLab/ReasFlow source tree, license, fixed commit, release artifact,
benchmark inputs, provenance schema, retrieval index, verification implementation, and evaluation
harness were not verified. It must remain in the public-claims-only class until those materials
can be audited.

**Decision.** Borrow the problem framing, not the claimed system behavior. In particular,
AutoLean may add research-provenance records and retrieval of declarative facts plus procedural
experience, but each record must keep its source/rights identifier, scope, contract revision,
artifact digest, and evidence state. Retrieval is advisory and cannot collapse a literature
assertion, a model suggestion, a mathematical conjecture, and a kernel-checked theorem into one
status.

This does **not** create a fourth `DiscoveryGraph`. Discovery material is a typed
`discovery_evidence` layer attached to a `MathematicalGraph` node: it records source locators,
research claims, counterexamples, heuristic notes, and their review state without becoming a
mathematical-dependency edge. `FormalGraph` still records Lean-level dependencies and
`ExecutionGraph` still records leases, attempts, and scheduling. A discovery record can motivate a
new draft contract, but it cannot mutate or validate one.

### Quokka: explicit disambiguation boundary

`Quokka` is not sufficiently identified by the local chat record. One known referent,
[UST-QuAntiL/Quokka](https://github.com/UST-QuAntiL/Quokka), is a quantum resource-management
project and is excluded as unrelated to this formal-mathematics inquiry. That exclusion says
nothing about any other project with the same name. No architectural conclusion is recorded until
the intended project is disambiguated by an author, logo, or primary URL supplied by the operator;
only then may its public status, license, source revision, target assistant, and evaluation
protocol be reviewed.

## Why this is not a proof of architecture correctness

The materials support plausible design hypotheses, not the desired conclusion. A counterexample
is straightforward: an adaptive dispatcher can improve aggregate throughput while repeatedly
routing semantically hard statement conversions through a path that has weaker review evidence.
Likewise, AST-shaped context can lower syntactic errors while preserving a wrong definition.
AutoLean's three-graph separation, frozen contracts, mutation tests, independent semantic review,
and clean verification exist precisely to catch those failures.

The decision holds only if the experiments above record their full bundle, environment, prompt and
tool policy, budgets, attempts, verifier results, and exclusions. If an experiment cannot be made
replayable or comparable, it remains a research observation and cannot change default scheduling
or Builder admission policy.

## Near-term execution order

1. Add the capability-path schema and a read-only route-decision projection without enabling
   automatic routing.
2. Register the Builder conversion taxonomy as a versioned proposal, then add golden mutations
   for each error class before using it in a pilot.
3. Specify and run the small structural-context experiment against frozen, disjoint bundles.
4. Finish the core mathlib/OCI/independent-verifier gates before implementing a Reap adapter.
5. Turn the MMAT and ReasFlow ideas into small, versioned schema proposals only after defining
   their contract/rights/authority boundaries; do not import a runtime or cite their performance.
6. Audit any future MMAT or ReasLab source release from a pinned commit and reproduce a declared
   checker before it can graduate from public claims to source-audited evidence.
7. Disambiguate Quokka through an operator-provided author, logo, or primary URL before spending
   research or implementation time on it.

These steps advance the open-problem mission by reducing the two real bottlenecks: faithfully
constructing formal mathematical objects and proving frozen objects under a reproducible trust
boundary. They do not claim that a currently open problem is closer to resolution.
