# AutoLean

AutoLean is a Builder-Prover system for turning cited mathematical sources into frozen Lean
statement contracts and then searching for independently verified proofs. Its long-term north
star is open-problem research; its first milestone is a replayable, auditable local architecture.

The repository is intentionally split:

- `Builder/` owns source provenance, rights, formalization candidates, semantic-fidelity gates,
  and contract freezing.
- `Prover/` owns model providers, execution harnesses, proof attempts, gap evidence, and proof
  verification.
- `packages/contracts/` is the only shared Builder-Prover language.
- `packages/control_plane/` stores append-only events, leases, projections, and artifacts.
- `Dashboard/` is a read-only projection of those records.
- `benchmarks/` contains pinned benchmark manifests and adapters, never hidden answers.

## Development

Install Python 3.12 and `uv`, then use the short task script:

```powershell
uv run python scripts/dev.py bootstrap
uv run python scripts/dev.py test
uv run python scripts/dev.py check
uv run python scripts/dev.py ci
uv run python scripts/release_evidence.py check
```

Lean and mathlib are pinned in each task bundle, and FATE revisions are pinned in a verified
manifest. Model routing is instead bound to a separate, short-lived, operator-issued
authorization; endpoint URLs and credentials never enter bundles. Paid model calls and networked
benchmark downloads are never part of the default test suite.

See `docs/architecture.md`, `docs/protocol.md`, and `docs/threat-model.md` before changing a
public contract or verifier gate.

Contribution rules and the exact offline CI boundary are documented in
`CONTRIBUTING.md` and `docs/ci.md`. Ordinary CI never downloads FATE, invokes a
model, or claims Lean/OCI authority.

The executed Phase 1 evidence and remaining gates are tracked in
[`docs/phase-1-progress.md`](docs/phase-1-progress.md). The only active execution order is
[`docs/roadmap-next.md`](docs/roadmap-next.md), and all operator, host, rights, reviewer, signer,
and release actions are consolidated in
[`docs/operator-and-authority-worklist.md`](docs/operator-and-authority-worklist.md). Historical
plans remain available through [`docs/archive/README.md`](docs/archive/README.md). The first Builder
discovery proposal is the rights-gated
[`docs/domain-pilot-selection.md`](docs/domain-pilot-selection.md).

The software in this repository is licensed under
the [Apache License 2.0](LICENSE). Source documents and benchmark data retain their own rights and
are never relicensed merely because their manifests or provenance records appear here.
