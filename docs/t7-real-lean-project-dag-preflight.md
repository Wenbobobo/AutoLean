# T7 Real Lean Project-DAG Preflight

## Purpose

`benchmarks/project_dag/graph.json` remains the existing synthetic v1 fixture for
control-plane scheduling, leases, event replay, and API-change propagation. This document
describes a side-by-side fixture with a different job: it binds a real four-module Lean source
tree to twenty named declaration identities and an explicit declaration content graph.

The fixture is intentionally small. Its role is to make the first later project-DAG acceptance
test executable against actual Lean imports without silently treating a scheduler label as a Lean
declaration. It is **T7 preflight only**. A successful local run is not a T7 acceptance result,
Builder freeze, semantic review, provider result, OCI verifier result, lease result, contract
binding, gateway replay, or promotion evidence.

## Bound inputs

`benchmarks/project_dag/real-lean-content-manifest.v1.json` binds:

- four modules beneath `benchmarks/project_dag/lean/`;
- exact file-to-module mappings and direct fixture imports;
- SHA-256 of every Lean source file;
- twenty unique fully-qualified declaration identities; and
- a directed declaration dependency graph.

The validator rejects a source hash change, file/module mismatch, changed source import list,
duplicate declaration identity, unknown dependency, cyclic module/declaration graph, an import
that does not correspond to a cross-module content edge, or a cross-module edge without its Lean
import. It exposes deterministic forward dependency closure and reverse API-change closure for
focused tests. That reverse closure is graph validation only: this preflight does **not** modify a
source declaration and recompile the affected modules. Changed-source invalidation/rebuild remains
scope for the later project-level acceptance harness. It also does not infer mathematical meaning
from syntax; Builder still owns that work.

Run the offline structural check with:

```text
uv run --frozen python -m scripts.real_lean_project_dag_preflight validate --json
```

## Operator-local source-v2 clean build

The optional command below runs only on an operator machine with the previously built pinned
source-v2 image available locally. On Windows it delegates Docker to WSL `Ubuntu-24.04`; on Linux
it calls the local Docker CLI. It passes Docker `--pull=never`: a missing local exact image fails
closed instead of fetching from a registry. The container has no network, receives the
fixture source as a read-only mount, and writes compiled OLeans only to a fresh temporary output
mount.

```text
uv run --frozen python -m scripts.real_lean_project_dag_preflight clean-build
```

The matching test is deliberately skipped by normal cross-platform CI. An operator may opt in:

```text
AUTOLEAN_RUN_T7_PREFLIGHT=1 uv run --frozen pytest scripts/tests/test_real_lean_project_dag_preflight.py -q
```

On PowerShell, set the environment variable for the current process before invoking the same
short command. The emitted JSON records only the fixture manifest hash, fixed image identity, and
compiled OLean hashes. It explicitly records that no acceptance, provider, OCI-verifier, or lease
evidence was created.

## What this unlocks, and what it does not

This preflight supplies a measured real-Lean input for the eventual 20-node project-level loop.
It does not replace the existing synthetic fixture: the latter is still needed to exercise
concurrent scheduling and control-plane events. It also does not exercise an agent, Builder
contract, task bundle, proof submission, target-free Library substrate, image-owned ordinary
dependency query, verifier gateway, or human statement-fidelity review.

Those boundaries are deliberate. The next project-level acceptance work must bind this content
fixture (or a reviewed successor) to immutable task bundles and the new substrate/verifier path;
only then can a real multi-file proof attempt become relevant to a Builder--Prover result.
