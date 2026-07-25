# Proof Dependency Gate Spike

## Conclusion

`collectAxioms` is necessary but cannot show whether a submitted proof used an existing target or
stronger theorem. It recursively follows ordinary declarations and reports only the axioms at the
leaves. Two proofs with different ordinary theorem dependencies can therefore have the same axiom
observation.

This spike adds a separate query and validator without changing the frozen source-v2 Dockerfile,
wrapper, helper, receipt, or T4 evidence. It is executable technical evidence, not an admission
gate and not the ordinary-theorem policy accepted by `library-substrate-decision.md`.

## Query Semantics

`Prover/worker/spikes/AutoleanProofDependencyQuery.lean`:

1. imports the sealed `Candidate.olean`;
2. requires the target to be a Candidate-owned theorem;
3. seeds the graph from constants in the target theorem's kernel proof value;
4. recursively uses Lean 4.28's `ConstantInfo.getUsedConstantsAsSet`, including every declaration
   type and available theorem, definition, or opaque value;
5. fails if a referenced declaration is absent or the closure exceeds 100,000 names; and
6. emits sorted direct and transitive lists plus `candidate_module_dependencies`.

The traversal deliberately starts from the proof value rather than merely scanning source text.
It sees declarations introduced by elaboration and follows an allowed wrapper to a denied theorem.
`candidate_module_dependencies` is only the intersection of the closure with
`Candidate.olean.constNames`. It is a Candidate-module diagnostic, not an AutoLean ownership
inventory, and the Python decision does not treat it as one.

The exact Lean 4.28/source-v2 image produced these fixture results:

| Target | Direct dependencies | Transitive closure | Spike decision |
| --- | ---: | ---: | --- |
| `nonalias` | 2 | 5 | allowed by the exact closure fixture |
| `exactTypeAlias` | 1 (`nonalias`) | 6 | rejected because `nonalias` is explicitly denied |
| `disguised` | 1 (`allowedWrapper`) | 2, including `forbiddenStrong` | rejected |
| `quotientProbe` | 1 (`Quot.ind`) | 3, including `Quot.mk` | rejected when `Quot.mk` is denied |
| `Deriv.closed_sound` | 17 | 1,885 | observation only |

The `nonalias` target and `allowedHelper` have structurally different types: the helper consumes a
conjunction, while the target consumes the antecedent and implication separately.
`exactTypeAlias` deliberately has the same type as `nonalias`; the current policy catches only this
known alias by name. For `Deriv.closed_sound`, `Deriv.sound` is a direct proof dependency and the
Candidate-module diagnostic contains 41 declarations. These are facts the existing three-axiom
observation does not retain.

## Validator Semantics

`autolean_prover.proof_dependencies` parses both records with exact schemas and rejects missing,
unknown, duplicate, unsorted, self-referential, or internally inconsistent data. A policy:

- is bound to one target;
- must deny the target itself;
- carries disjoint exact allow and deny lists; and
- accepts only when every transitive dependency is allowed and none is denied.

Denials take precedence for explicit security diagnostics. Exact allowlisting also rejects a new
ordinary dependency even when it is not on the denylist. The decision binds canonical SHA-256
digests of both the policy and evidence.

This full-closure policy is intentionally conservative: it exact-allows every observed Lean,
Mathlib, and Candidate declaration. It is not the ADR policy, which requires declaration kind,
canonical type hash, module origin, task mode, and exact handling of AutoLean-owned external
theorems against a trusted substrate manifest.

Run the local spike through the repository script:

```text
uv run python scripts/proof_dependency_gate.py query --image <digest-pinned-image> \
  --candidate <Candidate.lean> --declaration <Target.Name>
uv run python scripts/proof_dependency_gate.py validate --policy <policy.json> \
  --evidence <evidence.json>
uv run python scripts/proof_dependency_gate.py observe-fixtures --image <digest-pinned-image> \
  --output release-evidence/proof-dependency/source-v2-fixture-replay.v1.json
```

Windows query execution delegates to the pinned WSL distribution. Compilation still uses the
frozen source-v2 wrapper; only the subsequent experimental query helper is host-mounted.

## Operator-Local Observation

The replay command above was run against:

```text
autolean/mathlib-worker@sha256:3237192cf627a05367c75d46e61ec9034fefe43a4fd0c06139e38c80358648d6
```

The ignored record is
`release-evidence/proof-dependency/source-v2-fixture-replay.v1.json`. It records the canonical
command, image digest, candidate SHA
`8906eb196909fc859b69745e5ebacb3a22403c48437f51dde174a6bba8f3427a`, host-mounted helper SHA
`b8f70dd46400460a0c70db225137be738e0d161639845a53792f465426508ae9`, four query-output
hashes, and aggregate outputs SHA
`b216956433b32b4f3473889565cfe27e415564b2d768eb21650bd1acfa221116`.
Candidate and helper are each snapshotted once before the first target; all four queries reuse
those paths, the record hashes those executed snapshots, and their hashes are rechecked after the
last target.
The ignored record's byte SHA-256 is
`51d02e527358681ca89f53f236ab397d9f82ad8feb8514fe88a0f8a0e72c9f64`.

The conditional integration test executes the real helper and requires all four outputs to equal
the committed fixtures. It passed locally under WSL/source-v2. The record is explicitly
`operator-local-observation-only`, `host-mounted`, and `not-admission-evidence`; it is ignored and
has no release or signing authority.

## Why This Is Not an Admission Gate

The current immutable contracts cannot safely carry this result:

- `FormalSpecificationV1` has import and axiom allowlists but no ordinary-declaration dependency
  policy or policy-artifact digest.
- `ProofBoundaryV1` has no dependency-policy binding.
- the OCI wrapper schema, image identity, execution artifact, verification report, and gateway
  request have no proof-dependency fields.
- the query helper is host-mounted and is not covered by the source-v2 image receipt or runtime
  file manifest.
- the query does not report dependency declaration kind, trusted module origin, task mode, or
  canonical type hash.

Consequently, a caller could fabricate or truncate spike JSON and the current signing gateway
would have no image-owned field to recheck. Structural parsing cannot prove that a reported closure
is complete. No result from this script may be presented as admission, promotion, or source-v2 T4
evidence.

There is also a hard alias blocker. An explicitly denied known alias such as `nonalias` is caught,
but an unknown differently named theorem with the exact target type is not detected by name
closure alone. If an operator placed that unknown alias on this spike's allowlist, the spike could
accept it. A successor image-owned query must report canonical type hashes and enforce the frozen
task mode before any `independent_reproof` claim is possible.

## Production Path

A successor protocol should:

1. freeze a reviewed dependency-policy artifact and bind its digest into a new proof boundary;
2. bind declaration kind, trusted module origin, canonical type hash, and task mode to the
   target-free substrate manifest;
3. add the query to a new image-owned helper and wrapper version, producing a new image and receipt
   rather than rewriting source-v2 history;
4. bind the closure artifact digest, traversal ID, helper identity, sealed candidate hash, and
   target into a new OCI evidence schema;
5. make the signing gateway rerun the query and compare the complete policy decision; and
6. add negative canaries for direct target reuse, unknown exact-type aliases, direct stronger
   theorem reuse, allowed-wrapper indirection, truncated output, and helper-identity substitution.

The 1,885-name `Deriv.closed_sound` result also argues for a content-addressed allowlist artifact
instead of thousands of inline contract fields. Semantic review remains separate: this closure
proves syntactic kernel dependencies, not mathematical independence.
