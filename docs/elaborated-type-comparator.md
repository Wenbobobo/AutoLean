# Elaborated-Type Comparator V1

## Purpose

Lean accepting a candidate file is insufficient if the declaration it compiled is not the
declaration frozen by Builder. `ProofBoundaryV1.expected_elaborated_type_hash` is therefore an
acceptance gate, not diagnostic metadata. The verifier recomputes an
`elaborated_type` digest from an authoritative Lean rendering and rejects an absent, wrong-name,
or mismatching result.

This is deliberately narrower than the upstream
[Lean comparator](https://github.com/leanprover/comparator): it protects AutoLean's single
frozen declaration boundary. It does not replace the external comparator's environment replay,
dependency equivalence, or sandboxing model.

Builder uses the same canonical printer-text identity rule at an earlier and strictly separate
boundary. After selected-formal-field-blind candidates are returned, but before mutation or
semantic review, `StatementFidelityHarness` freshly queries the contract-selected reference and
each candidate through `scripts.oci_mathlib_worker.query_declarations`. Exact canonical text and
hash equality is required. This pre-freeze observation does not claim definitional equivalence,
mathematical fidelity, a valid proof, allowed axioms, or Prover verification; the Prover comparator
below still runs independently against the frozen proof boundary. Both currently implemented
Builder query assurances are non-authoritative, so this observation is accepted only by explicit
test-only freeze and registration modes.

## Evidence Contract

`LeanRunEvidence.elaborated_type_evidence` has this logical record:

```json
{
  "format_id": "autolean.lean-pp-expr.v1",
  "declaration": "Exact.Namespace.target",
  "canonical_type": "one single-line Lean expression"
}
```

The runner, not a model or a solver workspace, owns this record. It must create it only after the
candidate compiles in the pinned OCI image. The helper must look up `declaration` in the resulting
Lean environment and render that constant's elaborated `ConstantInfo.type`; it must not hash the
source declaration, parse `#check` display output, or reuse the expected hash. Lean's environment
API explicitly exposes typed constant information, and its documented printer options expose
implicit arguments, universes, and notation controls.

For `autolean.lean-pp-expr.v1`, the pinned helper must use one immutable rendering profile:

1. start from the compiled candidate environment and query the expected fully qualified constant;
2. render the elaborated type with `pp.all = true`, `pp.explicit = true`,
   `pp.universes = true`, and `pp.notation = false`;
3. use a fixed non-wrapping printer width and emit UTF-8 text without a final newline;
4. reject a missing declaration, unresolved metavariable, control character, multiline result, or
   helper/profile version mismatch; and
5. emit exactly one typed evidence record through a verifier-owned channel.

The formal statement's `elaborated_type` and its frozen hash must be generated using the same
format/profile in the same pinned Lean/mathlib environment. A printer or helper semantic change
requires a new format identifier and a new Builder contract revision; changing only the runner is
not a compatible migration.

The relevant Lean output options are documented in the official
[Theorem Proving in Lean 4 guide](https://lean-lang.org/theorem_proving_in_lean4/Interacting-with-Lean/)
and `pp.notation = false` prevents user notation/unexpander output from being used as the
canonical representation, as described in the
[Lean language reference](https://lean-lang.org/doc/reference/latest/Notations-and-Macros/Extending-Lean___s-Output/).

## Acceptance Algorithm

`ElaboratedTypeComparator.verify` performs all of the following in Python, after receiving typed
evidence from the authoritative runner:

1. require the exact `format_id`;
2. require `evidence.declaration == ProofBoundaryV1.expected_declaration`;
3. calculate `digest_text(HashKindV1.ELABORATED_TYPE, evidence.canonical_type)` itself; and
4. require equality with `ProofBoundaryV1.expected_elaborated_type_hash`, which the bundle
   validator already binds to the frozen contract's elaborated-type hash.

Any failure makes `kernel_passed`, `build_passed`, and `dependency_check_passed` false in the
report. This avoids a clean Lean exit code being promoted when the evidence does not establish the
frozen declaration.

## OCI Runner Requirement

`OciLeanRunner` is the concrete protocol boundary. It invokes only the fixed executable
`/opt/autolean/bin/autolean-lean-wrapper` in two fresh containers from one digest-pinned image.
The compile phase receives `/input/Candidate.lean` read-only and a dedicated writable `/output`;
its stdout is untrusted. After that container is confirmed absent, the host copies one bounded,
regular, non-link `Candidate.olean` into a private directory. The query phase receives only that
file at `/compiled/Candidate.olean` read-only, has no writable host bind, and emits
one JSON object with exactly these fields:

```json
{
  "schema_version": "autolean.oci-lean-wrapper.v2",
  "declaration": "Exact.Namespace.target",
  "canonical_type": "one single-line Lean expression",
  "lean_version": "pinned Lean version",
  "mathlib_revision": "pinned revision",
  "lake_manifest_hash": "optional frozen SHA-256",
  "observed_axioms": []
}
```

The host rejects duplicate fields, non-standard JSON constants, fields outside this set (including
a model-supplied `type_hash`), a declaration/type/environment mismatch, malformed axioms, and
truncated output. It hashes the verifier-rendered candidate and binds every protected frozen file
in the read-only source snapshot to the workspace hashes both before and after OCI execution. The
resulting `LeanRunEvidence` carries the recomputed type evidence and non-secret execution facts
(image digest, environment, separate compile/query argv hashes, sealed `.olean` hash, handoff
protocol, aggregate command-transcript hash, candidate, trusted-statement, and manifest hashes)
for later artifact storage and attestation; it is not itself a promotion artifact.
`TrustedLeanVerifier.observe` passes only those non-secret OCI facts to the Prover-side evidence
adapter. Production flow then uses
[`attest_oci_observation_via_gateway`](../Prover/src/autolean_prover/verification_gateway.py),
which binds them to the submitted proof bytes, frozen bundle, and current fenced lease before a
dedicated gateway authority can sign. The direct signer adapter remains a test-only fixture.

The repository now has an exercised [pure-Lean OCI worker](oci-lean-worker.md). One container
compiles the candidate, the host seals its output only after proving that container is gone, and a
second container's image-owned helper imports the sealed `Candidate.olean`. The explicit canary
has run this image through `OciLeanRunner` and the transient
verifier on Lean 4.28.0. This closes the real-execution protocol gap only for a theorem with no
mathlib dependency; it is not yet the pinned mathlib/FATE production image.

Required pinned-OCI canaries:

- unchanged theorem: helper type equals the frozen type and is accepted;
- same declaration name with its type changed to `True`: helper returns a different type hash and
  is rejected;
- correct type text reported under another declaration: rejected;
- missing, malformed, multiline, or unknown-profile helper output: rejected; and
- candidate-created shadows of trusted query modules and a persistent compile-time writer cannot
  cross the container handoff; and
- a helper/profile change without a new frozen contract revision: rejected.

These canaries now run explicitly through `scripts/oci_worker.py`. Normal unit tests still validate
only the protocol and fail-closed comparison logic; authoritative execution evidence must name the
exact image digest from the explicit canary. Lean 4.28.0 has been exercised, while mathlib has not.
