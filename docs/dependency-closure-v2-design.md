# Dependency Closure V2 Design

Status: **Stage A implemented and locally tested / Stage B mechanics implemented but nonempty accepted dependencies fail closed pending a gateway-owned `dependency.admitted` module/OLean binding / no acceptance authority**

This document specifies the smallest contract and execution change needed for a Phase 2
multi-file Library task to consume previously verified AutoLean assets without relying on a
mutable or preinstalled worker directory. Stage A now provides the isolated contract records and
local materializer described below. It does not change a frozen task bundle, admit a dependency,
authorize a proof, close a Phase 1 or Phase 2 task, or establish a release result.

## Conclusion

`DependencyClosureRefV1` should be a typed, content-addressed reference used only by a new
`StatementContractV2`, `FormalizationTaskBundleV2`, and `ProofBoundaryV2`. Existing V1 records
must remain byte- and meaning-stable. In particular, `FormalizationTaskBundleV1` must not gain an
optional dependency field whose absence could silently fall back to an operator-supplied
dependency directory.

The closure is a reviewed executable projection of the `FormalGraph`; it is not a fourth graph.
The `MathematicalGraph`, `FormalGraph`, and `ExecutionGraph` remain independently versioned and
retain their existing authority boundaries.

## Implementation boundary

Stage A is implemented:

- `autolean_contracts.dependency_closure` defines the canonical manifest, artifact reference,
  accepted-dependency and declaration-inventory records, plus their content bindings;
- the manifest treats its theorem inventory as closed: every `THEOREM` has exactly one accepted
  dependency binding. The only unbound runtime inventory kind is `DEFINITION`; ambiguous
  `INSTANCE` and `NOTATION` rows are rejected. Stage B must independently confirm the actual
  OLean declaration kind and that an unbound definition is not proposition-bearing;
- the Prover dependency-closure materializer first reads every size-bounded blob exactly once into
  a local snapshot without touching the destination. Only after all reader callbacks return does
  it require a nonexistent target with a regular parent chain, create the tree, and write without
  further reader calls. It rejects unsafe paths, missing or extra files, links, reparse points,
  noncanonical manifests, target-path mutation, and content drift;
- contract and materializer tests reuse a three-module
  `Foundation -> Bridge -> Certificate` fixture and cover positive and adversarial cases.

Stage A is deliberately local and non-authoritative. It is not connected to control-plane
registration or claims, leases, OCI execution, verification evidence, the verifier gateway, or
proof admission.

Stage B mechanics now exist, including the V2 registration path and its rejection controls. They
are deliberately fail closed: every manifest with nonempty `accepted_dependencies` is rejected
until a durable, gateway-owned `dependency.admitted` record binds the earlier accepted verification
to the exact exported module and OLean blob supplied by the closure. That record and its gateway
load/query route do not yet exist. Empty-accepted-dependency V2 fixtures remain local mechanics
evidence only; they do not make a runtime closure authoritative. V1 task bundles remain unchanged.

## Current findings

### P0: conditional execution blocker

There is no current P0 claim against an accepted multi-file result because no such result has been
accepted. However, using the current host-selected dependency directory for a dynamic Phase 2
Library result would be a P0 design failure:

- [`OciWorkerSpec.dependency_root`](../Prover/src/autolean_prover/execution/oci.py#L88-L113) is a
  host path selected outside the bundle;
- [`OciWorkerHarness.build_request`](../Prover/src/autolean_prover/execution/oci.py#L135-L225)
  mounts that directory read-only at `/deps`, but read-only does not establish content identity;
- neither the current
  [`FrozenTaskBundleInput`](../Prover/src/autolean_prover/execution/authority.py#L30-L86) nor
  [`OciExecutionEvidence`](../Prover/src/autolean_prover/execution/lean_runner.py#L65-L98) binds
  the dependency tree.

Therefore the current dynamic `/deps` path must not participate in Phase 2 proof acceptance.

### P1: missing authoritative bindings

1. [`DependencyReferenceV1`](../packages/contracts/src/autolean_contracts/models.py#L434-L447)
   records an ID, kind, and textual target, but not the depended-on contract revision/hash,
   declaration type, verified proof evidence, module, or axiom observation.
2. [`FormalizationTaskBundleV1`](../packages/contracts/src/autolean_contracts/models.py#L909-L976)
   binds a contract, graph snapshot, proof boundary, and fidelity evidence, but no materializable
   dependency closure.
3. [`GraphBundleV1`](../packages/contracts/src/autolean_contracts/graphs.py#L208-L227) validates
   graph structure and cross-graph mathematical/formal alignments, but it does not identify the
   target formal node or bind formal predecessors to runtime files.
4. [`WorkspaceMaterializer`](../Prover/src/autolean_prover/execution/workspace.py#L155-L196)
   materializes only the trusted statement, solver manifest, and proof slot.
5. The current verification artifacts bind the model-submitted dependency-manifest hash but not
   the materialized dependency tree; see
   [`VerificationEvidenceArtifactV2`](../packages/contracts/src/autolean_contracts/models.py#L1308-L1348).

### P2: useful but non-authoritative evidence

- [`ProofSubmissionV1.dependency_manifest`](../packages/contracts/src/autolean_contracts/models.py#L1024-L1065)
  is submitter-provided evidence. It cannot choose trusted runtime contents.
- [`proof_dependencies.py`](../Prover/src/autolean_prover/proof_dependencies.py#L1-L5) is
  explicitly an experimental validation spike and is not bound into the frozen proof boundary or
  verifier gateway.
- The existing
  [three-module Library fixture](mathlib-downstream.md#fixture-boundary) and
  [real Lean project-DAG preflight](t7-real-lean-project-dag-preflight.md) demonstrate bounded
  import/build properties, not a claimed-bundle-to-verifier closure.
- The accepted
  [target-free substrate decision](library-substrate-decision.md#v3-deps-trigger) already states
  that a sealed external capsule and a successor OCI policy are required once a real multi-file
  frontier consumes independently verified assets.

## Threat model

The proposal assumes an untrusted proof model, an untrusted attempt workspace, a fallible worker
host, and a content-addressed store that must revalidate every read. It addresses these attacks:

1. A worker or operator substitutes a host dependency tree containing the target theorem.
2. A dependency file changes between materialization, candidate compilation, and trusted query.
3. A differently named theorem with the target's canonical type is exposed as an oracle.
4. A bundle names the correct declaration but the wrong contract revision, environment, proof,
   module, axiom observation, or verification evidence.
5. A submitter reports an incomplete dependency manifest while Lean loads additional modules or
   declarations.
6. The FormalGraph omits a prerequisite or a runtime manifest contains an undeclared prerequisite.
7. A materialized artifact uses an absolute path, `..`, duplicate path, symbolic link, reparse
   point, reserved namespace, or unexpected extra file.
8. A stale or cross-bundle lease fetches closure artifacts or submits evidence.

This proposal does not establish source-statement fidelity. Builder semantic review remains a
separate gate.

## Proposed contract surface

### Narrow Statement Contract V2 extension

The new contract revision should add only the semantic bindings needed to make dependency mode
explicit:

```text
formal_target_node_id
dependency_mode: independent_reproof | compositional_bridge
formal_dependency_bindings:
  dependency_id -> formal_node_id -> supply: image_owned | closure
```

The target node must identify the formal declaration frozen by the contract. A closure-backed
binding means that the exact dependency must appear in the external closure. An image-owned
binding means it belongs to the independently pinned base environment and may not be supplied by
the external closure.

### DependencyClosureRefV1

This small object is embedded in `FormalizationTaskBundleV2` and therefore covered by the Builder
handoff hash and attestation.

| Field | Minimum rule |
| --- | --- |
| `schema_version` | Literal `1.0` |
| `closure_id` | Stable ID in the `dependency-closure` namespace |
| `closure_manifest_ref` | Content SHA-256, byte size, and fixed manifest media type |
| `closure_manifest_hash` | New typed digest kind `dependency_closure`; value equals the manifest artifact SHA-256 |
| `environment_hash` | Exactly equals the frozen contract environment hash |
| `tree_hash` | New typed digest kind `dependency_tree`; computed from the sorted runtime-file index |
| `entry_modules` | Sorted, unique AutoLean module roots permitted as direct imports |
| `formal_body_dependency_ids` | Sorted, unique IDs of every closure-backed formal-body dependency |

The ref intentionally contains no host path, storage URL, prompt, credential, or mutable cache
identity.

### DependencyClosureManifestV1

The canonical manifest is a content-addressed JSON artifact. It contains the larger materializable
record:

```text
schema_version
closure_id
environment_hash
tree_hash
files:
  relative_path, sha256, size, role
modules:
  module_name, olean_path, direct_imports
declaration_inventory:
  declaration_name, kind, canonical_type_hash, observed_axioms, module_name
accepted_dependencies:
  dependency_id, formal_node_id
  contract_id, revision, contract_hash
  declaration_name, canonical_type_hash, observed_axioms, module_name
  verification_evidence_artifact_sha256
```

Every runtime file is a separate CAS blob. Stage A does not use a tar or zip capsule. Writing
verified blobs to safe relative paths is sufficient for the first 20--40-node chapter slice and
removes archive extraction from the trusted path.

### Bundle, boundary, and evidence versions

- `FormalizationTaskBundleV2` requires one `DependencyClosureRefV1`.
- `ProofBoundaryV2` includes `closure_manifest_hash` in the solver manifest and boundary hash.
- The successor OCI policy binds the per-attempt materialized dependency root and rejects the
  current unbound `OciWorkerSpec.dependency_root` route for V2 bundles.
- OCI execution evidence and verification evidence require the closure manifest hash, tree hash,
  and verifier-observed loaded-module/declaration closure.
- `ProofSubmissionV1.dependency_manifest`, if retained in a successor submission, remains
  diagnostic and must not select files or override verifier observations.

## Invariants

1. The closure-backed formal-body dependency IDs exactly equal the applicable formal dependency
   bindings reachable from the declared target node. No closure is inferred from a proof
   submission, dashboard projection, or worker directory.
2. Every accepted ordinary theorem dependency binds its contract ID, exact revision and contract
   hash, declaration, canonical type hash, observed axioms, module, and verification evidence.
3. Every theorem-like runtime declaration is represented as `THEOREM` and appears exactly once in
   accepted dependencies. An unbound `DEFINITION` is limited to a non-proposition-bearing
   computational helper; Stage B verifier observation, not the manifest label, must establish
   that fact before acceptance.
4. Manifest and file lists are canonical, sorted, duplicate-free, path-safe, and content-addressed.
5. The runtime tree is rehashed before execution, after compile, and after query. Missing,
   additional, changed, linked, or reparse-point files fail closed.
6. The target declaration, any differently named declaration with the exact target canonical
   type, target/oracle modules, controls, and undeclared stronger AutoLean theorems are absent.
7. `independent_reproof` contains no closure-backed ordinary AutoLean theorem.
   `compositional_bridge` lists every such theorem explicitly.
8. Contract environment, closure environment, proof boundary, execution claim, worker policy,
   compile evidence, query evidence, and verifier gateway all bind the same closure hashes.
9. The verifier's loaded-module and proof-declaration observations, not a model declaration,
   determine dependency-check success.
10. A closure or dependency-mode change creates a new contract/environment revision and bundle.
   No old Builder or verifier attestation is reused.
11. Mathematical, formal, and execution graph meanings remain separate. A closure can be checked
    against FormalGraph identities but cannot establish source fidelity or scheduling completion.

## Data flow

```text
Builder freezes StatementContractV2
  -> bridge publishes immutable runtime blobs and canonical closure manifest
  -> Builder signs FormalizationTaskBundleV2, including DependencyClosureRefV1
  -> control-plane registration verifies artifacts, environment, graph bindings,
     and accepted-dependency evidence
  -> claim returns a fenced receipt for the immutable bundle
  -> fetch_claimed_bundle returns the exact canonical V2 bundle
  -> claim-scoped artifact retrieval returns only the registered closure manifest/blobs
  -> per-attempt materializer creates and rehashes a fresh read-only dependency root
  -> OCI compile and query consume only that root
  -> verifier observes modules, declarations, types, axioms, and closure hashes
  -> verification evidence and gateway check the same lease, bundle, and closure
```

Claim-scoped artifact retrieval is data retrieval under an existing lease, not a sixth
Builder--Prover command. It must authorize only artifact references reachable from the registered
bundle and must not expose arbitrary `ArtifactStore` reads.

## V1 to V2 migration

1. Leave `StatementContractV1`, `FormalizationTaskBundleV1`, `ProofBoundaryV1`, their hashes, and
   existing attestations unchanged.
2. Use a discriminated V1/V2 bundle union. A V1 payload containing V2 closure fields remains an
   extra-field validation failure.
3. Continue using V1 only with a digest-pinned, image-owned, target-free base substrate. If a task
   requires a closure-backed dependency, fail with a specific
   `dynamic_dependency_closure_requires_bundle_v2` capability error.
4. Create a new contract revision for dependency mode, closure, or environment changes. Re-run
   Builder review and issue a new handoff attestation.
5. Do not automatically repackage a V1 proof or local Library build as an accepted dependency.
   First produce a clean integration receipt, sealed module manifest, declaration inventory,
   verifier evidence, and V2 Builder attestation.
6. Preserve the five public commands. Extend claim-bound retrieval and materialization without
   allowing Builder or Prover to read the other component's internal state.

## Required tests

### Positive tests

1. Build `Foundation -> Bridge -> Certificate` as a canonical V2 closure and compile the terminal
   target in a fresh worker using only claim-fetched artifacts.
2. Restart the control plane, replay the claim, and reproduce byte-identical bundle, manifest,
   tree, and evidence hashes.
3. Run a `compositional_bridge` target whose verifier-observed declaration closure exactly matches
   the allowed accepted dependency.
4. Run an `independent_reproof` with no external ordinary AutoLean theorem and a pinned image-owned
   base environment.
5. Deduplicate an identical CAS blob across two bundles while preserving claim-scoped artifact
   authorization.

### Negative contract and registration tests

1. Reject one missing or additional closure-backed reachable formal-body predecessor.
2. Reject an unknown target node, dangling dependency binding, wrong edge direction, or graph
   cycle.
3. Reject a dependency whose contract revision/hash, declaration, canonical type, axioms, module,
   or verification evidence differs from the accepted record.
4. Reject environment, manifest hash, manifest size, tree hash, entry-module, and closure-ID
   mismatches.
5. Reject non-canonical manifest JSON, duplicate or unsorted entries, and an unavailable or corrupt
   CAS blob.
6. Reject a target, exact-type alias, undeclared stronger theorem, control module, fixture, old
   aggregate module, or reserved namespace in the closure inventory.
7. Reject a V1 bundle requesting a dynamic closure and a V2 bundle missing its required closure.

### Negative claim and materialization tests

1. Reject an expired/stale lease, wrong fencing token, forged receipt, cross-bundle reference, or
   claim event that differs from its persisted event.
2. Reject an absolute path, `..`, duplicate path, alternate path spelling, symbolic link, Windows
   reparse point, non-regular file, missing file, extra file, changed blob, or size mismatch.
3. Reject materialization into a non-empty root and reject any fallback to the worker spec's
   preinstalled dependency directory.
4. Detect a dependency-tree change after materialization, during compile, or before/after query.

### Negative verifier and gateway tests

1. Reject a compile or query whose actual dependency mount differs from the claim-bound
   materialized root.
2. Reject a wrapper-observed loaded-module closure, direct import set, declaration inventory,
   proof-dependency closure, or tree hash that differs from the manifest.
3. Reject Candidate ownership by an imported dependency and any target/canonical-type collision.
4. Reject evidence whose compile and query closure identities differ.
5. Reject verification evidence or a gateway attestation that omits or changes the closure hash.
6. Reject a model-submitted dependency manifest that attempts to add, remove, or replace trusted
   runtime dependencies.

## Explicit non-goals

The first implementation must not add:

- a general package manager, remote object-store protocol, multi-repository federation, or
  cross-organization trust system;
- tar/zip extraction, delta closures, incremental binary patching, or distributed cache coherence;
- theorem-by-theorem policy for the entire Mathlib closure;
- automatic conversion of a MathematicalGraph, FormalGraph, scheduler DAG, model output, or
  Dashboard projection into an accepted runtime closure;
- automatic authority for a local build, old proof, model vote, or experimental dependency query;
- a redesigned database or provider interface unrelated to claim-scoped immutable artifact
  retrieval; or
- scale optimizations for thousands of workers before the 20--40-node closure has measured blob
  count, bytes, materialization latency, and replay cost.

## Implementation order

1. Add the V2 contract models, typed hashes, exact graph/dependency validators, and canonical
   manifest validator.
2. Add claim-scoped artifact retrieval and a pure-Python per-file CAS materializer.
3. Exercise the existing three-module Library fixture through bundle, claim, restart, and
   materialization tests.
4. Add the successor OCI policy, pre/post tree rehash, wrapper observations, evidence schema, and
   gateway cross-binding.
5. Only after the adversarial suite passes, run a local test-only OCI vertical and record it in the
   progress ledger with its exact non-authority boundary.
