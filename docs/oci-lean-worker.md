# Pinned Pure-Lean OCI Worker

## Scope

`Prover/worker` is the first exercised AutoLean OCI verifier image. It closes the earlier gap
between the host-side `OciLeanRunner` protocol and a real Linux worker:

- Ubuntu 24.04 base image is pinned by digest;
- the official Lean 4.28.0 Linux archive is pinned and verified by SHA-256 in both the build driver
  and a Docker build stage;
- `/opt/autolean/bin/autolean-lean-wrapper` is the only accepted runner entry point;
- the candidate compiles before a separate, image-owned Lean helper imports its generated
  environment and reads `ConstantInfo.type` plus `collectAxioms`;
- candidate compiler stdout is captured and never copied to wrapper stdout; and
- the final process uses numeric user `65532:65532`.

This image intentionally contains no mathlib. Its environment identifier is
`none-pure-lean-v4.28.0`; it proves the OCI/Lean protocol works on a real theorem, not that the
FATE or mathlib environment has been containerized.

## Frozen Inputs

| Input | Binding |
| --- | --- |
| Base | `ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90` |
| Lean archive | `lean-4.28.0-linux.tar.zst` |
| Lean archive SHA-256 | `ceb3a3f844f7aebf63245e2b51c28d5b0ed38942c19f93cf3febd520302160bd` |
| Wrapper protocol | `autolean.oci-lean-wrapper.v1` |
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
`OciLeanRunner -> TrustedLeanVerifier.observe`.

The current fixture requires:

- exact declaration `AutoLean.OCI.fixture`;
- canonical type `forall` rendered as `∀ (n : Nat), @Eq.{1} Nat n n`;
- empty observed axiom set;
- kernel, build, dependency, and clean-environment gates all true;
- a changed-to-`True` declaration produces a different authoritative type;
- host-side candidate replacement is rejected before OCI execution;
- a missing declaration and unknown type profile fail without wrapper stdout; and
- a candidate `#eval` JSON spoof remains only in captured compiler output and cannot become the
  wrapper record.

The generated `release-evidence/oci-worker/{build,canary}.v1.json` files are deliberately ignored
by Git. They bind the actual image, command policy, command, candidate, trusted statement, and
bundle manifest without retaining source, proof text, diagnostics, host paths, or credentials.
The command hash is attempt-specific because the current host runner hashes the full OCI argv,
including fresh bind-source paths. Compare the stable command-policy hash for replay equivalence;
do not expect the entire canary file hash or command hash to be identical across attempts.

## Evidence Boundary

The canary produces verifier-owned execution evidence and an unsigned transient
`VerificationReportV1`. It does not use the lease-bound signing gateway and therefore creates no
promotable proof attestation. It also does not establish reproducible registry publication,
mathlib compatibility, FATE success, semantic statement fidelity, or model proof-search quality.

Promoting this worker beyond the pure-Lean architecture canary requires a separately pinned
mathlib image, clean registry/SBOM provenance, the signing gateway, and the same adversarial
canaries rerun against that exact image digest.
