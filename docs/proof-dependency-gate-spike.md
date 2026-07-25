# Proof Dependency Gate Spike

## Conclusion

`collectAxioms` is necessary but cannot establish that a submitted proof is independent of an
existing target or stronger theorem. It recursively follows ordinary declarations and reports only
the axioms at the leaves. A proof that directly applies an existing theorem can therefore have the
same empty axiom set as an independently constructed proof.

This spike adds a separate query and validator without changing the frozen source-v2 Dockerfile,
wrapper, helper, receipt, or T4 evidence. It is executable technical evidence, not an admission
gate.

## Query Semantics

`Prover/worker/spikes/AutoleanProofDependencyQuery.lean`:

1. imports the sealed `Candidate.olean`;
2. requires the target to be a Candidate-owned theorem;
3. seeds the graph from constants in the target theorem's kernel proof value;
4. recursively visits the type and value of every referenced declaration;
5. fails if a referenced declaration is absent or the closure exceeds 100,000 names; and
6. emits sorted direct, transitive, and Candidate-owned dependency lists.

The traversal deliberately starts from the proof value rather than merely scanning source text.
It sees declarations introduced by elaboration and follows an allowed wrapper to a denied theorem.

The exact Lean 4.28/source-v2 image produced these fixture results:

| Target | Direct dependencies | Transitive closure |
| --- | ---: | ---: |
| `AutoLean.ProofDependencyFixture.independent` | 1 (`allowedHelper`) | 1 |
| `AutoLean.ProofDependencyFixture.disguised` | 1 (`allowedWrapper`) | 2, including `forbiddenStrong` |
| `AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Deriv.closed_sound` | 17 | 1,885 |

For `Deriv.closed_sound`, `Deriv.sound` is a direct proof dependency. The closure contains 41
Candidate-owned declarations. This is information the existing three-axiom observation does not
retain.

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

Run the local spike through the repository script:

```text
uv run python scripts/proof_dependency_gate.py query --image <digest-pinned-image> \
  --candidate <Candidate.lean> --declaration <Target.Name>
uv run python scripts/proof_dependency_gate.py validate --policy <policy.json> \
  --evidence <evidence.json>
```

Windows query execution delegates to the pinned WSL distribution. Compilation still uses the
frozen source-v2 wrapper; only the subsequent experimental query helper is host-mounted.

## Why This Is Not an Admission Gate

The current immutable contracts cannot safely carry this result:

- `FormalSpecificationV1` has import and axiom allowlists but no ordinary-declaration dependency
  policy or policy-artifact digest.
- `ProofBoundaryV1` has no dependency-policy binding.
- the OCI wrapper schema, image identity, execution artifact, verification report, and gateway
  request have no proof-dependency fields.
- the query helper is host-mounted and is not covered by the source-v2 image receipt or runtime
  file manifest.

Consequently, a caller could fabricate or truncate spike JSON and the current independent gateway
would have no image-owned field to recheck. Structural parsing cannot prove that a reported closure
is complete. No result from this script may be presented as admission, promotion, or source-v2 T4
evidence.

## Production Path

A successor protocol should:

1. freeze a reviewed dependency-policy artifact and bind its digest into a new proof boundary;
2. add this query to a new image-owned helper and wrapper version, producing a new image and
   receipt rather than rewriting source-v2 history;
3. bind the closure artifact digest, traversal ID, helper identity, sealed candidate hash, and
   target into a new OCI evidence schema;
4. make the independent gateway rerun the query and compare the complete policy decision; and
5. add negative canaries for direct target reuse, direct stronger-theorem reuse, allowed-wrapper
   indirection, truncated output, and helper-identity substitution.

The 1,885-name `Deriv.closed_sound` result also argues for a content-addressed allowlist artifact
instead of thousands of inline contract fields. Semantic review remains separate: this closure
proves syntactic kernel dependencies, not that two mathematically similar proofs are independent.
