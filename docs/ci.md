# Continuous Integration Boundaries

## Ordinary pull requests and pushes

`.github/workflows/ci.yml` runs the same offline gate on Ubuntu 24.04 and Windows
Server 2022. The Python job installs the committed `uv.lock`, checks that the lock
is current, checks Ruff formatting and lint, runs strict Mypy, runs Pytest, applies
the repository secret and prohibited-provider policies, and checks deterministic
release-inventory and SPDX generation. A separate matrix installs the committed
pnpm lock and runs the Dashboard UI tests and production build.

The ordinary workflow deliberately does not:

- fetch FATE or any benchmark task source;
- invoke a model, use an API credential, or enable networked benchmark execution;
- install or run Lean, Lake, Docker, an OCI proof worker, or a signing gateway; or
- generate benchmark scores or release-candidate evidence.

Run the corresponding Python gate locally with:

```powershell
uv run python scripts/dev.py bootstrap
uv run python scripts/dev.py ci
```

Run the locked UI checks with:

```powershell
pnpm --dir Dashboard/ui install --frozen-lockfile
pnpm --dir Dashboard/ui test
pnpm --dir Dashboard/ui build
```

## Repository policies

`scripts/secret_scan.py` reads only Git-tracked or non-ignored candidate files.
It explicitly refuses to scan `.git`, `.quarantine`, `.venv`, any
`node_modules`, `benchmarks/vendor`, or `benchmarks/results`. Findings contain
only a relative path and rule identifier; matching text and line contents are
never printed. This is a lightweight regression guard, not a substitute for
credential rotation, Git-host secret scanning, or history rewriting.

`scripts/provider_policy_guard.py` blocks prohibited provider dependencies and
production references while verifying that both runtime deny lists remain
present. Tests and policy/audit documentation may name rejected providers so
that the exclusion itself remains testable. Adding a model route requires an
allowed provider adapter, an operator approval, capability evidence, egress
policy, and the existing request-bound authorization flow.

## Manual readiness preflight

`.github/workflows/authoritative-preflight.yml` is manually dispatched. It checks
Linux, a real source commit, a clean tracked tree, and an available Docker daemon.
The operator may additionally request a public FATE checkout at the exact locked
root revision; the strict local adapter then verifies its root, submodules, and
source manifest without running a proof.

The workflow always records `authoritative_execution: not-run`. It does not run
Lean, the digest-pinned OCI verifier, KMS-backed signing, a model, or an Open
Problem workload. Therefore a green preflight means only that the named
prerequisites were observed on that ephemeral runner. Authoritative CI remains
blocked until a separately controlled Linux worker, immutable image, verifier
authority, and retained evidence path are configured.
