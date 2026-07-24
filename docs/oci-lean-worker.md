# Pinned Pure-Lean OCI Worker

## Scope

`Prover/worker` is the first exercised AutoLean OCI verifier image. It closes the earlier gap
between the host-side `OciLeanRunner` protocol and a real Linux worker:

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

The currently observed local image is
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

## Replay

From Windows or Linux:

```text
uv run python scripts/oci_worker.py all
```

On Windows the script delegates to WSL distribution `Ubuntu-24.04`. The Lean archive is retained
under the WSL user's `~/.cache/autolean/oci-worker-sources`; a digest mismatch fails closed and
leaves the unexpected file in place for audit. The Python environment used for the integrated
canary is outside the repository at `~/.cache/autolean/oci-worker-python`. Initial setup may use
the network to download the official Lean archive and locked Python packages. The subsequent
Docker build itself uses `--network=none`, and every verifier container separately runs with
`--network none`; the whole setup command must therefore not be described as offline.

To replay an already-built exact image:

```text
uv run python scripts/oci_worker.py canary --image autolean/lean-worker@sha256:<digest>
```

Do not replace `<digest>` with the mutable tag. `build.v1.json` records the local Docker
repository digest after every build. A local digest is not a published registry artifact; another
machine must rebuild or consume a separately attested registry image.

## Canary Gates

The explicit canary runs a real Lean compile under `--network none`, `--read-only`,
`--cap-drop ALL`, `--security-opt no-new-privileges`, fixed pids/memory limits, and a no-exec
temporary filesystem. It then exercises the repository path
`OciLeanRunner -> TrustedLeanVerifier.observe -> test-only signing gateway`. Before the fixture
gateway may attest, its independent canary verifier performs a second digest-pinned
Docker-wrapper execution and returns an authenticated test-only execution receipt bound to the
signing request and execution evidence.

The current fixture requires:

- exact declaration `AutoLean.OCI.fixture`;
- canonical type `forall` rendered as `∀ (n : Nat), @Eq.{1} Nat n n`;
- empty observed axiom set;
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
has SHA-256 `8aa49896f153b763d5887a88b7ee646f0842e72d61f8c0379442332e8eb324b2`.
The V2 execution record separately binds the compile argv hash, query argv hash, sealed
`Candidate.olean` SHA-256, and `autolean.oci-compile-query-handoff.v1`; its aggregate command hash
is the canonical transcript hash of those fields. The phase hashes remain attempt-specific because
the OCI argv include fresh bind-source paths and container names. Compare the stable command-policy
hash for replay equivalence;
do not expect the entire canary file hash or command hash to be identical across attempts. A
re-run that overwrites this ignored file must record its new hash rather than presenting this
test-only run hash as a stable protocol or image identity.

## Evidence Boundary

The canary produces verifier-owned execution evidence and uses the lease-bound signing gateway
only with a local, authenticated **test-only** receipt authority. It records
`test_gateway_attestation_created=true` and
`control_plane_accepted_test_fixture=true`, but also records
`promotion_attestation_created=false`. It does not establish reproducible registry publication,
mathlib compatibility, FATE success, semantic statement fidelity, or model proof-search quality.
The second Docker execution establishes an important anti-spoofing software boundary; it does not
make two processes operated by one local fixture authority independent in the production sense.
The canary establishes the two-container boundary for the pure-Lean image only. FATE's mounted
mathlib smoke wrapper now follows the same two-phase handoff, but it has not been rerun here and
remains explicitly non-promotable.

Promoting this worker beyond the pure-Lean architecture canary requires a separately pinned
mathlib image, clean registry/SBOM provenance, the signing gateway under an
operator-authenticated mTLS/ACL boundary, non-exportable KMS/HSM custody, and the same adversarial
canaries rerun against that exact image digest. None of those production deployment requirements is
satisfied by the local HMAC receipt fixture.
