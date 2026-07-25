# Target-Free Library Substrate Decision

Status: accepted Phase 1 architecture; implementation and pilot admission remain open

Decision date: 2026-07-25

## Scope

This record defines the runtime dependency boundary needed after T4 and before a real T5/T6
Builder--Prover result. It does not select the current model-theory candidate, revise the immutable
T3 decision, freeze a statement, or authorize a proof result.

The immediate problem is narrower than a general Mathlib image. The retained
`UniversalLK.lean` fixture contains definitions, rule constructors, local and global soundness,
the closed bridge, target proofs, and rejection controls in one module. Importing that module, or
the `Packet` module that imports it, would make the target proof or a stronger theorem available to
the solver. Conversely, the source-v2 Mathlib worker contains the required
`Mathlib.ModelTheory.Semantics` closure but deliberately ignores the host `/deps` mount.

## Decision

Phase 1 will implement a side-by-side `library-substrate-v1` profile for the model-theory pilot:

- retain the existing source-v2 image, T3 decision, `UniversalLK.lean`, and T4 attachments as
  immutable historical inputs;
- build new, versioned target-free Library modules against the already locked
  `Mathlib.ModelTheory.Semantics` source closure;
- place only the resulting reviewed `.olean` closure and its manifest in a new image-owned
  runtime root;
- keep the original aggregate module, target proof modules, source files, host Library cache, and
  unbound `/deps` content out of the runtime closure;
- keep `TrustedStatement.lean` and `Proof.lean` as the only materialized solver files; and
- require a new image digest, environment hash, and statement-contract revision for every real
  task that uses the profile.

The initial profile is not `mathlib-substrate-v1`. That name is reserved for a possible future
general Mathlib runtime profile. Whether that profile should build Mathlib's full default target
or a set of reviewed import closures remains undecided until an isolated preflight measures build
time, module count, runtime size, and replay cost. A future full-Mathlib decision must not be
presented as the implementation or evidence for the focused Library profile.

| Profile | Immediate purpose | Mathlib scope | Decision state |
| --- | --- | --- | --- |
| `library-substrate-v1` | Target-free AutoLean definitions for the first T5/T6 pilot | Reuse the locked `Mathlib.ModelTheory.Semantics` closure | Accepted architecture; not implemented |
| `mathlib-substrate-v1` | Possible general upstream Mathlib basis for later domains | Full default target or reviewed closures, as preflight determines | Deferred; no build choice accepted |
| external `/deps` V3 | Dynamic accepted AutoLean theorem dependencies across project frontiers | Image-owned Mathlib plus a sealed external capsule | Deferred until the multi-file trigger below |

## Task modes

Every task using ordinary theorem dependencies must declare one of two modes before freeze.

### `independent_reproof`

The imported AutoLean closure may contain definitions, inductive constructors, and explicitly
reviewed non-target helper lemmas. It must not contain:

- the target declaration under any name;
- another theorem with the exact canonical target type;
- a stronger pilot theorem that Builder has not declared as a formal-body dependency; or
- any target or oracle module retained only for testing.

For example, an independent `Deriv.closed_sound` task may not import `Deriv.sound`. If proving the
target reasonably requires that theorem, the task is either reclassified as a compositional
bridge or given a different proof boundary; the verifier does not silently change the mode.

### `compositional_bridge`

The task may consume an earlier theorem only when the frozen dependency record names its stable
contract ID, exact revision and contract hash, verified proof artifact, declaration, canonical
type hash, and axiom observation. Using `Deriv.sound` to prove `Deriv.closed_sound` is then a valid
Library composition, but the result must be reported as a bridge verification rather than an
independent soundness proof search.

Task mode changes the allowed proof environment and the claim that may be made about a result.
It therefore requires a new contract/environment revision even when the target theorem text is
unchanged.

## Target-free module boundary

The selected candidate revision should use a new staging source root. The old monolithic fixture
must remain unchanged while its T3/T4 records still bind that path and content.

The minimum source split is:

| Module class | Permitted content | Initial runtime |
| --- | --- | --- |
| Core | Formula/term aliases, variable operations, semantic predicates, `Deriv` constructors, and closed-side definitions | Included |
| Semantic prelude | Non-target realization and context-lifting lemmas required to state or prove the selected nodes | Included when declared |
| Rule prelude | Reviewed non-target local rule lemmas | Included only when declared |
| Accepted dependency | A previously frozen and independently verified theorem plus its integration receipt | Compositional mode only |
| Controls | Countermodels, mutation witnesses, capture/freshness controls | Offline review only |
| Target/oracle | Known proof of the current target or an exact-type alias | Never included |
| Aggregate | The retained full `UniversalLK` or `Packet` import surface | Never included |

The new source root may retain the existing declaration namespace only if the original aggregate
root is absent from the build and runtime search paths. Dual visibility is a build failure.

## Runtime manifest and build receipt

`library-substrate-v1` is source-built. "Proof-erased" means that the final runtime omits source
and compiles modules which never declared the target. Removing a theorem body, changing it to
`opaque`, or retaining only an `.olean` that still exports the theorem is not target erasure: the
constant remains usable as a proof.

The canonical runtime manifest must bind at least:

- the parent Mathlib image/source receipt, Lean version, Mathlib revision, and Lake-manifest hash;
- the exact source-tree hash and fixed build command/tool hashes;
- ordered entry modules and their complete transitive import closure;
- every runtime file's safe relative path, SHA-256, and size;
- every AutoLean declaration's name, kind, canonical type hash, and observed axiom set; and
- the compiled-tree hash, declaration-inventory hash, and runtime-manifest hash.

The final image contains the compiled target-free tree, the image-owned verifier, and the
manifest/receipt only. The image digest is the runtime content boundary for this first profile.
The manifest is its reviewable explanation and the migration boundary for a future external
capsule; it is not an authority or admission receipt.

## Ordinary theorem dependency gate

Kernel checking and `collectAxioms` do not show that a proof avoided an imported theorem oracle.
Before T6 acceptance, the verifier must additionally:

1. confirm that the expected target declaration is owned by the sealed `Candidate.olean`;
2. compare the candidate's direct imports and complete loaded module closure with the frozen
   profile;
3. reject a dependency declaration whose name or canonical type collides with the target;
4. report the AutoLean-owned theorem constants referenced by the target proof expression; and
5. require every such external theorem to match an allowed formal-body dependency in the frozen
   contract and substrate manifest.

Mathlib theorem use remains controlled at module-import and axiom-policy boundaries; this first
gate does not attempt a theorem-by-theorem allowlist for all of Mathlib. AutoLean-owned ordinary
theorem dependencies are exact because they are the assets being built and composed.

`ProofSubmissionV1.dependency_manifest` is model-submitted evidence and cannot select or
materialize the trusted runtime substrate. Builder and verifier-owned records remain authoritative.

## Image and workspace consequences

A new image digest is mandatory. The current wrapper reads only its image-owned `LEAN_PATH`, and
the current `/deps` tree is not content-bound. A side-by-side image may reuse the exact source-v2
Mathlib layers or rebuild from the same locked inputs, but it must produce a new receipt and
digest. It may not overwrite, retag as, or rewrite source-v2.

The V2 two-container compile/query shape and the narrow `WorkspaceMaterializer` can remain for the
initial image-owned profile. The frozen header supplies the only direct imports, the agent can
write only the proof slot, and the final image contains no target module to discover dynamically.
Registration must allowlist the new image only after its manifest and build receipt pass the
release checks.

## Required rejection tests

The profile is not usable for a real T5/T6 contract until all of the following fail closed:

- direct import of the retained `UniversalLK` module and transitive import through `Packet`;
- target declaration present in any dependency module;
- differently named theorem with the exact canonical target type;
- undeclared use of `Deriv.sound` or another AutoLean theorem in `independent_reproof`;
- Candidate query where the expected declaration is imported rather than Candidate-owned;
- changed, missing, additional, linked, or path-escaping source, `.olean`, or manifest file;
- dependency source tree, compiled tree, module closure, or declaration inventory drift;
- simultaneous visibility of the old aggregate root and the new target-free root;
- `Mathlib`, `Lean`, `Init`, worker-helper, or `Candidate` namespace/path shadowing;
- old contract with the new image, or new contract with the source-v2 image;
- compile and query evidence bound to different image/runtime-manifest identities;
- `sorryAx`, a custom or extra axiom, a missing allowlist entry, or strict-profile nonempty axioms;
  and
- reuse of T4 declaration evidence as if it described the split source or new image.

The current observed target axiom sets are diagnostic baselines only. The split modules and exact
new image must be queried again before a successor profile can be reviewed.

## V3 `/deps` trigger

Do not enable host-mounted `/deps` merely to avoid rebuilding the pilot image. Implement
`OciVerifierExecutionPolicyV3` and a sealed external dependency capsule only when at least one of
these is true:

- an accepted multi-file Library frontier must combine independently verified assets without
  rebuilding an image per frontier;
- the T7 project fixture needs content-addressed dependency reuse across workers; or
- measured rebuild cost, not an assumption, makes the image-owned profile operationally
  unsuitable.

Before that switch, V3 must bind a verifier-owned `DependencySubstrateRefV1` into the frozen
bundle, verify the same regular non-link tree before both compile and query, place image-owned
Mathlib paths before the allowed AutoLean root, reject reserved namespace shadows, and carry the
manifest/tree hashes through OCI evidence and the signing gateway. The agent or proof submission
must never choose the mounted tree.

## Consequences and review point

This decision accepts one new image build in exchange for a small, auditable T5/T6 boundary. It
does not yet optimize thousands of workers. The image-owned choice becomes the wrong tradeoff
when accepted theorem frontiers change often enough to trigger the V3 criteria above; at that
point the same source, declaration, and runtime manifests become the external capsule interface.

T3 semantic admission, the successor image/import/axiom profile, and authenticated Builder
authority remain independent blockers. A successful substrate canary proves only that the target
was absent from the allowed runtime closure and that the frozen environment was reproduced.
