# Contributing to AutoLean

Changes must preserve the Builder-Prover authority split: Builder owns statement
fidelity, Prover owns proof search, and their only shared language is the
versioned contract package. Mathematical, formal, and execution dependencies
remain distinct. A proof failure may produce a gap or contract-change request,
but it may not silently change a frozen theorem.

Before opening a pull request, run:

```powershell
uv run python scripts/dev.py bootstrap
uv run python scripts/dev.py public-ready
uv run python scripts/dev.py ci
pnpm --dir Dashboard/ui install --frozen-lockfile
pnpm --dir Dashboard/ui test
pnpm --dir Dashboard/ui build
```

Do not commit credentials, recovered archives, sessions, prompts, benchmark
answers, generated result directories, local databases, or release evidence.
Provider changes may add Codex, OpenAI, or explicitly approved compatible
endpoints; they must not add prohibited providers, dependencies, examples, or
fallbacks.

Every pull request should state which contract or authority boundary it affects,
which tests demonstrate the change, and which Lean/OCI/FATE checks were not run.
Passing ordinary CI is not evidence of theorem correctness, statement fidelity,
authoritative execution, or release readiness. See
[`docs/ci.md`](docs/ci.md) and
[`docs/operations-release.md`](docs/operations-release.md).

Report security-boundary failures through the private process in
[`SECURITY.md`](SECURITY.md), not through a public issue.
