# iFEM P2-08 Pilot Readiness Gate V2

Status: v2 implementation and focused rule tests complete; no iFEM pilot has
been admitted and no real prerequisite classification has been recorded. The
filename is retained while this pre-release documentation set is reconciled.

## Conclusion

P2-08 now has a deterministic, content-addressed v2 decision function for the
unchanged iFEM coercive/Galerkin discovery slice. It distinguishes an exact
singleton direct import from the transitive module closure loaded by that
import. Until a closure-acceptance policy is frozen, v2 can return only
`incomplete` or a falsifying `no_go`; it cannot return `go`.

The current state remains `incomplete`. The frozen 21-node census is still
unclassified. The five fixed direct-import observations have run, but their
loaded closures contain 3,666--4,199 modules. Those closure facts have not been
accepted by any precommitted policy. This is intentionally not a `no_go`
conclusion.

## Decision boundary

The gate consumes three separate evidence lanes:

- The Builder-owned prerequisite census result bound to
  `ifem-coercive-prerequisites-r01-f9d1f2d4717a`.
- The five-profile fixed-direct-import observation result, each recorded
  transitive closure, and the exact child-image build receipt.
- The precommitted P2-08 v2 rule. It has a denominator of 21, a 15--16
  direct-or-thin-adapter band, and four critical restriction nodes:
  `restricted-bilinear-form`, `restricted-functional`,
  `restricted-continuity`, and `restricted-coercivity`.

It validates identity and policy bindings.  It does not inspect textbook
source text, invent mappings, check the content behind a semantic-review hash,
or derive a Lean theorem.  The prior semantic-review gate remains the only
place that can classify a node as `direct`, `thin_adapter`, or `missing`.

## Rules

P2-08 v2 deliberately has no `go` path. A future successor may add one only
after it freezes a closure-acceptance rule and requires every one of the
following:

- A completed census with zero `unknown` nodes.
- Exactly 15 or 16 `direct` plus `thin_adapter` nodes in the frozen denominator.
- No critical restriction node classified `missing`.
- All five image-owned profiles, bound to their frozen singleton direct imports
  and child-image receipt.
- Every declaration used by a mapped critical restriction node is actually
  visible under one of those exact direct-import profiles.
- An explicit assessment of the observed transitive closures that addresses
  target-module circularity and import provenance. A raw module-count threshold
  has not been selected and must not be invented after seeing the result.

`no_go` is reserved for falsifying facts in the current slice: a reviewed
critical restriction API is missing, its mapped declarations are not visible
under the exact direct-import profiles, or a fully reviewed count lies outside the
precommitted 15--16 band.  The normal P2-07 collector rejects a raw broad or
wrong direct import before it becomes a normalized observation; that collection
attempt cannot be promoted or treated as profile evidence. P2-08 also rejects
such a mismatch defensively if an in-memory caller bypasses P2-07 normalization.
`incomplete` means an observation, semantic classification, profile run, or
closure-acceptance rule has not yet supplied enough evidence. It must not be
re-labelled as a negative scientific conclusion.

The upper bound is deliberate: more than 16 reviewed reusable prerequisites
is not a failure of iFEM or mathlib, but it does fall outside this frozen
70--80 percent pilot hypothesis.  It requires a successor pilot decision
rather than silently changing the scope after observing results.

## Current evidence

The earlier v1 synthetic decision SHA is retired by the v2 schema and protocol
bump; a v1 document cannot be loaded as a v2 decision. Focused v2 tests cover
both a one-module synthetic closure and an intentionally broader closure. Even
with a completed 15-of-21 semantic fixture and all critical declarations
visible, both remain `incomplete` with
`transitive_import_closure_acceptance_policy_unresolved`.

The fixed five-profile plan presently validates with content SHA-256
`21bd18f7f8522470247852ef8281f1e4c7016f6415771e4fc0c05ab433247619`.
The real P2-07 child image is
`sha256:6c54c3600b2572ddcabae024a3a8b6c533c3defa6d4bda31c90408cb4c61f0ab`;
its build-receipt file/content SHA-256 values are
`c859ec69ec46a2344f42a4e42f17b6922ade51c92d1bb22c674c7a4885185f26` /
`80659121feb8a831c6255879f7cf6d1230d1cd64e8272559523ef99aeab68251`.
All five queries ran twice with byte-identical normalized artifacts: observation
file/content SHA-256 `1900a11003a78ecaa681ad76ab5660762d4f5ca81e28b0b9525a95998131d736` /
`0dee6c5b7e4c0db81fb20e9821e2fd2eede727d9552d7fe4a7def7b6b6b1a348`, and
result file/content SHA-256 `ba9ca42865fd385fbf94b922e4111dd76ab9dec4386f28bbba778779dfc52298` /
`55e9c0f95d9634dc39fb37cd1b00a97575cbc91090c15701d39f8e3868110238`.

The `Defs`, `Dual`, `LaxMilgram`, `Operator.Basic`, and `Operator.Bilinear`
profiles respectively observed closure sizes 3,685, 4,198, 4,199, 3,666, and
3,667, with candidate presence 13/25, 23/25, 25/25, 14/25, and 19/25. Exact
direct-import binding is therefore verified; closure breadth and circularity
remain unreviewed. The profile evidence remains non-authoritative for semantic
mapping, coverage, Builder freeze, and Prover handoff.

The generic-host WSL P2-06 census under `/mnt/c` reached its 600-second internal
bound, wrote no observation or result, and cleaned its temporary query. The
frozen census manifest remains historically `not_started`; no 21-node
classification exists. An honest `host_query_timeout` census record was then
combined with the completed P2-07 evidence to produce the public
[P2-08 v2 decision](ifem-pilot-readiness-decision-2026-07-31.json). Its
file/content SHA-256 values are
`aa925bb186f4fdc6a0fe9eef7543f0c3ad5f3d5078856758da10cbd4ae9e176c` /
`c45cbff7a5efed34e59efbe922729f30f6d25cbe2120bd5cc1825325cb851b90`.
The outcome is `incomplete`, with 21 unknown nodes, verified direct imports,
and unresolved transitive-closure policy. It forbids Builder freeze and Prover
handoff; it is not a semantic, coverage, or pilot-admission result.

## Reproducible route

Use the short scripts rather than platform-specific commands.  First record a
real P2-07 census and profile observation/receipt in an operator-controlled
evidence directory.  Then evaluate them without any model call:

```text
uv run --frozen python scripts/ifem_pilot_readiness.py \
  --census-result <census-result.json> \
  --profile-plan Builder/pilots/discovery/ifem-pinned-mathlib-profile-plan.v1.json \
  --profile-result <profile-result.json> \
  --profile-observations <profile-observations.json> \
  --profile-build-receipt <profile-build-receipt.json> \
  --out <p2-08-decision.json>
```

The evaluator writes once: reusing a path is allowed only for byte-identical
content.  Its output binds all supplied artifact hashes, rejects partial
completed-profile evidence, and preserves `builder_freeze: forbidden` and
`prover_handoff: forbidden` in every outcome.

A consumer that has the source evidence must call
`verify_ifem_pilot_readiness_decision(...)`, which re-evaluates the exact
census/profile objects and requires byte-for-byte agreement.  The decision
model also rejects internally inconsistent outcomes, such as a rehashed `go`
with `unknown` nodes or without singleton-import evidence.

## Next evidence

1. Preserve and independently replay the completed P2-07 receipt and
   byte-identical observation/result pair without reinterpreting visibility as
   semantic mapping.
2. Run the P2-06 census in a viable pinned POSIX/WSL environment; the `/mnt/c`
   timeout produced no reusable evidence.
3. Provide independent semantic-review artifacts
   through the existing census classification boundary.
4. Define a successor closure policy before re-enabling `go`. It must distinguish
   ordinary Mathlib transitive dependencies from circular reliance on a target
   theorem/module; raw closure size alone is not yet an accepted criterion.
5. Re-run this gate under a new version. Any future `go` remains conditional on
   `AUTH-RIGHTS-01` before real textbook conversion and cannot authorize freeze
   or Prover work.
