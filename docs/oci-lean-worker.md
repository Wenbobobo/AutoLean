# Pinned Lean OCI Workers

## Scope

`Prover/worker` contains two exercised AutoLean OCI verifier profiles. The original pure-Lean
profile closes the earlier gap between the host-side `OciLeanRunner` protocol and a real Linux
worker:

- Ubuntu 24.04 base image is pinned by digest;
- the official Lean 4.28.0 Linux archive is pinned and verified by SHA-256 in both the build driver
  and a Docker build stage;
- `/opt/autolean/bin/autolean-lean-wrapper` is the only accepted runner entry point;
- the candidate compiles in a container that can write only a dedicated output bind;
- after that container is confirmed stopped, the host accepts only a bounded regular non-link
  `Candidate.olean`, copies its bytes into a private directory, and mounts only that file read-only
  into a new query container;
- the image-owned helper resolves trusted Lean modules before the directory containing the single
  sealed `Candidate.olean`, then reads `ConstantInfo.type` plus `collectAxioms`;
- candidate compiler stdout is never parsed as verifier evidence; and
- both phases use the invoking host's numeric non-root identity so candidate-owned output can be
  removed without granting either container a writable dependency or attempt-workspace mount.

This image intentionally contains no mathlib. Its environment identifier is
`none-pure-lean-v4.28.0`; it proves the OCI/Lean protocol works on a real theorem, not that the
FATE or mathlib environment has been containerized.

The currently observed local pure-Lean image is
`autolean/lean-worker@sha256:9a85f190bfaaf5cc79418abe3cee46cf5456b9aaaa0c78df5d3c1e380ee419e5`.
It is a local Docker identity, not a registry publication or a transferable environment
attestation.

## Frozen Inputs

| Input | Binding |
| --- | --- |
| Base | `ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90` |
| Lean archive | `lean-4.28.0-linux.tar.zst` |
| Lean archive SHA-256 | `ceb3a3f844f7aebf63245e2b51c28d5b0ed38942c19f93cf3febd520302160bd` |
| Wrapper protocol | `autolean.oci-lean-wrapper.v2` |
| Image-owned verifier identity | `autolean.image-owned-verifier-identity.v2`, SHA-256 `81099458f107fc5a179e1d308b09ff0189424d8b4341dd47026cfbf01c3828e0` |
| Type format | `autolean.lean-pp-expr.v1` |

The build driver stages exactly the archive, Dockerfile, query helper, and wrapper in a fresh
temporary directory. It does not send the repository root, user home, environment files, or
credentials to Docker.

## Mathlib Source-Lock Precondition

The first M3 increment now locks source-only archives for all nine Git packages in
`Library/lake-manifest.json`. The tracked
`Prover/worker/mathlib-source-lock.v1.json` is complete and has SHA-256
`f9ef72acfebed52c6c7de1bacebe840fcd620568f7dc2875685771f363701448`. It binds:

- the raw Lake manifest SHA-256
  `e2a93c904f51195d6740cd9abfb35ab155dc0157e0e46642dce0d364b68a9a89`;
- the exact GitHub URL and 40-hex commit of each package;
- the canonical credential-free `codeload.github.com` archive URL; and
- the observed SHA-256 of each validated archive.

The nine archives total 22,224,408 bytes and remain in the operator-owned
`~/.cache/autolean/mathlib-sources` cache. They are not repository artifacts. Archive validation
rejects path escape, Git metadata, generated Lake state, Lean build output, hard links, devices,
and unsafe symlinks. Acquisition is resumable: each completed package is atomically bound into an
incomplete lock, and a later run reuses it only after the recorded hash and full archive structure
are revalidated. An unbound cache entry is never accepted as the first source observation.

Run the read-only lock and cache checks with:

```text
uv run --frozen python scripts/mathlib_source_lock.py
uv run --frozen python scripts/mathlib_source_lock.py --verify-cache
```

Only an explicit `--update` may download archives and rewrite the lock. This source lock closes
neither the clean-build nor image-authority gate, and the pure-Lean image above remains unchanged.

The separate `Dockerfile.mathlib` profile now proves more of the offline path without changing the
pure-Lean image. Its fresh context contains only the pinned Lean archive, all nine hash-checked
source archives, the source lock and manifests, and image-owned verifier files. The build uses
`--no-cache --pull=false --network=none`, verifies every input before extraction, converts the
locked Git dependency records to local-path records, and targets
`+Mathlib.ModelTheory.Semantics:olean`. The conversion retains and attests mathlib's original Lake
manifest.

An earlier clean attempt stopped at `ProofWidgets.Component.Basic`, whose source embeds
`.lake/build/js/interactiveExpr.js`. Removing the library's `widgetJsAll` dependency was therefore
not valid and has been removed from this profile: the original `lakefile.lean` and default target
are preserved.

ProofWidgets revision `be3b2e63b1bbf496c478cef98b86972a37c1417d` is tag `v0.0.87`.
`mathlib-build-resource-lock.v1.json` separately pins its official `ProofWidgets4.tar.gz` release
asset by URL, size, and SHA-256. The original 13,772,162-byte archive remains only in the
operator-owned `~/.cache/autolean/mathlib-build-resources` cache. A strict tar validator rejects
traversal, duplicate paths, links, and special files, then writes only the 20 regular `js/**`
files (6,902,528 bytes) into the fresh Docker context. The release archive and its `lib`, `ir`,
`.olean`, and native payloads never enter that context. This follows mathlib's own
`Cache/Requests.lean` policy, which fetches the ProofWidgets release for JavaScript and prunes
`lib` and `ir`.

The normal resource commands are read-only:

```text
uv run --frozen python scripts/mathlib_build_resources.py
uv run --frozen python scripts/mathlib_build_resources.py --verify-cache
```

Only an explicit `--update` downloads or replaces the cached release asset. In-image checks require
the complete JS manifest to be unchanged before and after `lake build widgetJsAll`, require
`lake build --no-build widgetJsAll` to report the release trace up-to-date, and reject a generated
`node_modules`. The runtime receipt also rejects extra or non-regular JS entries and recomputes its
helper OLean, direct-import dependency manifest/count, target OLean, and runtime-file-manifest
claims before emitting JSON. The receipt retains its existing `import_closure` field names for
schema compatibility; those fields do not claim a transitive closure.

The source-v2 profile completed all 889 build targets and produced the local test-only image
`autolean/mathlib-worker@sha256:3237192cf627a05367c75d46e61ec9034fefe43a4fd0c06139e38c80358648d6`.
The canonical in-image receipt SHA-256 is
`40e15776cec80a03b9d5b0affd59a3f613b7f1855c48aa0c1e91f24ec0e1eed7`; it binds the image-owned
single-declaration and multi-declaration helpers, the latter's wrapper, the same four-file direct
mathlib import dependency set with SHA-256
`2983d74fceb7bd025939793e1a9690653cf113f89d547f5e33bdcefc9fa8d44e`, and target OLean SHA-256
`6ecddc1bdec0ef5e871cac0feb5880a9b4048067bed154b95e0ba8f0c8e49297`. The ignored build evidence
file has SHA-256 `3c340227a423ff5440aa67c63023f02e1468577eac317df8e2db2200e3212d7f`.

The earlier source-v1 image
`sha256:83daaa542ee407c0fbb1ba93f2a0b40fde1621cc5ad2e689ab7d5392b76d03ff`
remains the historical image binding in the immutable model-theory V2 gap decision. The source-v2
image and query evidence do not rewrite or upgrade that decision in place.

## Replay

Build and exercise the mathlib profile from Windows or Linux:

```text
uv run --frozen python -m scripts.oci_mathlib_worker all
```

Replay the pure-Lean profile separately with:

```text
uv run python scripts/oci_worker.py all
```

On Windows both scripts delegate to WSL distribution `Ubuntu-24.04`. The Lean archive is retained
under the WSL user's `~/.cache/autolean/oci-worker-sources`; a digest mismatch fails closed and
leaves the unexpected file in place for audit. The Python environment used for the integrated
canary is outside the repository at `~/.cache/autolean/oci-worker-python`. Initial setup may use
the network to download the official Lean archive and locked Python packages. The subsequent
Docker build itself uses `--network=none`, and every verifier container separately runs with
`--network none`; the whole setup command must therefore not be described as offline.

To replay already-built exact images:

```text
uv run python scripts/oci_worker.py canary --image autolean/lean-worker@sha256:<digest>
uv run --frozen python -m scripts.oci_mathlib_worker verify --image autolean/mathlib-worker@sha256:<digest>
uv run --frozen python -m scripts.oci_mathlib_worker canary --image autolean/mathlib-worker@sha256:<digest>
```

Do not replace `<digest>` with the mutable tag. `build.v1.json` records the pure image and
`mathlib-build.v1.json` records the mathlib image. A local digest is not a published registry
artifact; another machine must rebuild or consume a separately attested registry image.

## Pure-Lean Canary Gates

The explicit canary runs a real Lean compile under `--network none`, `--read-only`,
`--cap-drop ALL`, `--security-opt no-new-privileges`, fixed pids/memory limits, and a no-exec
temporary filesystem. Its public source-backed fixture follows
`Builder prepare -> fidelity -> freeze -> bridge -> register -> claim`, materializes the immutable
solver workspace, and then exercises
`OciLeanRunner -> TrustedLeanVerifier.observe -> test-only signing gateway -> terminal accepted`.
Before the fixture gateway may attest, its independent canary verifier performs a second
digest-pinned Docker-wrapper execution and returns an authenticated test-only execution receipt
bound to the signing request and execution evidence.

The current fixture requires:

- exact declaration `AutoLean.OCI.fixture`;
- canonical type `forall` rendered as `∀ (n : Nat), @Eq.{1} Nat n n`;
- empty observed axiom set;
- a public Builder handoff produced without the unreviewed-bundle bypass, with source preparation
  hash `312be270ddb575ce036a7b286199027a2995d867c3e31acd935d70d9911b685d` and bundle handoff hash
  `770ad9dab1fabd15722aba6cdc938d2172de4fe7a9e166ff508aa219cbc71375`;
- kernel, build, dependency, and clean-environment gates all true;
- a changed-to-`True` declaration produces a different authoritative type;
- host-side candidate replacement is rejected before OCI execution;
- a missing declaration and unknown type profile fail without wrapper stdout; and
- a candidate `#eval` JSON spoof remains only in captured compiler output and cannot become the
  wrapper record;
- candidate-created `Lean/PrettyPrinter.olean` and `Lean/Util/CollectAxioms.olean` shadows remain
  outside the query container;
- a compile-time child that continuously writes to the output bind is dead and the output tree is
  stable before the host copies `Candidate.olean`; and
- the independently rerun wrapper evidence must agree with the gateway request before the
  test-only fixture attestation is created.

The generated `release-evidence/oci-worker/build.v1.json` and `canary.v2.json` files are
deliberately ignored by Git. They bind the actual image, command policy, command, candidate,
trusted statement, bundle manifest, and public test-only receipt binding without retaining
source, proof text, diagnostics, host paths, or credentials. The current policy-V2 canary file
has SHA-256 `a83e703add32f9c896b3dbcd5f81982dabcfe5d036799a70cf5b5f9cd500a62e`.
The V2 execution record separately binds the compile argv hash, query argv hash, sealed
`Candidate.olean` SHA-256, and `autolean.oci-compile-query-handoff.v1`; its aggregate command hash
is the canonical transcript hash of those fields. The phase hashes remain attempt-specific because
the OCI argv include fresh bind-source paths and container names. Compare the stable command-policy
hash for replay equivalence;
do not expect the entire canary file hash or command hash to be identical across attempts. A
re-run that overwrites this ignored file must record its new hash rather than presenting this
test-only run hash as a stable protocol or image identity.

## Mathlib Profile Canary

The mathlib canary imports `Mathlib.ModelTheory.Semantics` from the image-owned dependency set and
compiles `AutoLean.OCI.fixture`, observing the exact type
`∀ (n : Nat), @Eq.{1} Nat n n` with an empty axiom set. A deliberately invalid
`/deps/Mathlib/ModelTheory/Semantics.olean` bind does not influence compilation, demonstrating that
this profile uses its image-owned dependency path rather than the host dependency mount. The
canary evidence SHA-256 is
`0931e138fdc4bf67374dc1a42978c92e49f786bece95fcf812c425fc7fd8ad0e`.
The ignored evidence files are
`release-evidence/oci-worker/mathlib-build.v1.json` and
`release-evidence/oci-worker/mathlib-canary.v1.json`.

The source-v2 multi-declaration query separately compiled the retained `UniversalLK` source once,
sealed `Candidate.olean`, and queried all 46 Candidate-owned declarations in a second read-only
container. Artifact SHA-256
`167d7a1ede245bfa631c46651b5eb0502d758b8d966d6f4c494fdcb2d75df42a`
binds the canonical types, axiom lists, two direct imports (`Init` and
`Mathlib.ModelTheory.Semantics`), and the complete 2,744-module transitive import closure. Of the
46 declarations, 41 have nonempty axiom sets; `Deriv.closed_sound` uses exactly
`Classical.choice`, `Quot.sound`, and `propext`. The operator-local file is
`release-evidence/oci-worker/mathlib-declarations.v1.json`; its byte-exact public attachment and
non-authority binding live under `Builder/pilots/model-theory-admission/`.

This is a focused import/type/axiom/path canary. The complete pure-worker adversarial V3 suite,
including every statement-replacement, wrong-profile, stdout-spoof, persistent-writer, and
handoff case listed above, has not been rerun against the mathlib profile. Evidence from the pure
profile is not inherited by relabeling the mathlib image.

## Evidence Boundary

The pure-Lean source-backed canary uses synthetic fixture source but a real digest-pinned Lean
execution. The unchanged frozen bundle passes the public Builder handoff, claim and lease,
immutable workspace, OCI verifier, independently rerun gateway receipt, and terminal control-plane
acceptance. It produces verifier-owned execution evidence and uses the lease-bound signing gateway
only with a local, authenticated **test-only** receipt authority. It records
`test_gateway_attestation_created=true` and
`control_plane_accepted_test_fixture=true`, but also records
`execution_authority_class=test-only-local`, `promotion_state=not_a_promotion`, and
`promotion_attestation_created=false`. It grants no production authority and does not establish
reproducible registry publication, mathlib compatibility, FATE success, real-source semantic
statement fidelity, or model proof-search quality.
The second Docker execution establishes an important anti-spoofing software boundary; it does not
make two processes operated by one local fixture authority independent in the production sense.
The pure profile establishes its two-container boundary, while the mathlib profile adds a
source-built, image-owned dependency set, focused V2 canary, and a complete transitive-closure
enumeration for the retained candidate. It still has no frozen-contract or signing-gateway
observation against the source-v2 image.
FATE's mounted mathlib smoke wrapper has not been rerun here and remains explicitly
non-promotable.

Neither local image is a registry publication or promotion attestation. Promotion requires clean
registry/SBOM provenance, the signing gateway under an operator-authenticated mTLS/ACL boundary,
non-exportable KMS/HSM custody, lease- and bundle-bound integration, and the required adversarial
canaries rerun against the exact mathlib digest. The source-v2 evidence is local test-only and
does not match the immutable V2 decision's source-v1 image, import policy, or strict empty-axiom
profile. Resolving that mismatch requires an explicit successor formal profile, semantic review,
and authenticated Builder authority; it is not an admission, Prover handoff, promotion, or Phase
1 release-candidate result.
