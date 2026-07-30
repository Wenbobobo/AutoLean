# FATE agent-smoke-8 vertical bridge

## Current result

The current `agent-smoke-8` execution completed on 2026-07-30 against the audited LF
`fate-runtime-v2-bb646ecb` layout and the split compile/query OCI wrapper V2. The earlier
2026-07-23 single-container V1 report remains historical only. The current run is a transparent,
task-independent `aesop` baseline, not a model comparison and not evidence that an Agent ran.
Lean proof search did execute inside each candidate; the report therefore records
`proof_search_executed=true` and `model_or_agent_executed=false`.

| Tier | Selected | Compiled, queried, and passed the axiom policy | Not verified |
| --- | ---: | ---: | ---: |
| M | 8 | 2 | 6 |
| H | 0 | 0 | 0 |
| X | 0 | 0 | 0 |

`FATE-M-1` and `FATE-M-3` completed. `FATE-M-{4,7,10,40,79,150}` returned wrapper exit
code 20 because the fixed tactic did not close the goal. No case timed out. Failure diagnostics
are retained only as byte counts and SHA-256 commitments.

The operator-local evidence file is
`benchmarks/results/fate-agent-smoke-8-static-wsl-v2-2026-07-30.json`:

- report SHA-256:
  `820fe89baaecfa4d0deedbe841c052662f754618b292db2016ba88b97071c6ee`;
- envelope file SHA-256:
  `5a07f4b239b29b7e68d0a88765e8858907d0a8f78ad2043d1920f9d3880254ae`;
- observed dependency build-tree SHA-256:
  `096a51f662104eca6ce73c6c9c7d436fe0e6d467e766c2736ab20c20a65539c7`;
- observed build-tree file count: 88,140.

The report binds runtime-state SHA-256
`7f1ce2ef67c150a04d146d562facca5f8c52b2fdd4bbfb0b27ed076a6739492f` and runtime-audit
SHA-256 `12fbd86dae4c0067df0602a90c0fe2c5217482371475024e1cc5311a79892dd0`.
It contains no proof body, source text, diagnostic text, absolute path, environment value, or
credential.

## What the bridge proves

The runner re-audits the managed ext4 FATE runtime before any attempt. It binds FATE v4.28.0,
the three split revisions, Lean 4.28.0, mathlib commit
`8f9d9cff6bd728b17a24e163c9402775d9e6a365`, all 350 source hashes, the nine dependency
commits, and the answer-free split manifest.

For each selected task:

1. `FateAdapter` replaces only the source-manifested `sorry` byte range.
2. The candidate, dependency tree, and verifier files are mounted read-only.
3. Docker runs with `--network none`, a read-only root filesystem, all capabilities dropped,
   no-new-privileges, a numeric non-root user, and bounded CPU, memory, pids, and time.
4. Under current V2, candidate compilation writes only to a dedicated output bind. After that
   container is confirmed stopped, the host copies one regular non-link `Candidate.olean`.
5. A new query container receives only that sealed file read-only; candidate stdout and sibling
   shadow modules are not part of its filesystem.
6. The Lean query returns the elaborated declaration type and `collectAxioms` result.
7. The public report retains hashes of the type and wrapper record, not their source text.
8. `sorryAx` and any axiom outside `Classical.choice`, `Quot.sound`, and `propext` are rejected.

The protected prefix and suffix remain byte-identical, so neither the declaration name nor its
type can be replaced with `True`. M, H, and X are always emitted as separate report sections.

## Why it is not promotable

The bridge intentionally forces `promotable=false` and makes no signing-gateway request:

- the base image contains pinned Lean but not mathlib;
- the mounted mathlib build tree is fully observed and re-hashed before and after the run, but it
  was not rebuilt from source inside a pinned image or independently attested;
- the query helper and wrapper are read-only and hash-bound, but host-mounted rather than owned
  by the image digest;
- no immutable `FormalizationTaskBundleV1`, control-plane lease, verifier evidence artifact, or
  lease-bound signing request is produced;
- the candidate policy is a fixed tactic probe, not a real model Agent.

The counterfactual matters: mounting existing `.olean` files is fast and sufficient to test the
vertical mechanics, but blessing those files as production verifier inputs would let a
pre-existing modified build artifact sit below the theorem check. Only a clean in-image rebuild
or an independently authenticated build-tree attestation closes that gap.

## Replay

Use an unused output path. The managed runtime and package roots must already pass
`scripts/fate_wsl_runtime.py audit`; the command does not download anything.

```powershell
uv run python scripts/fate_agent_smoke.py `
  --cache-root <wsl-cache-root> `
  --packages-root <wsl-packages-root> `
  --runtime-root <wsl-runtime-root> `
  --output release-evidence/fate-agent-smoke-static-aesop.replay.v1.json
```

Each case has a 600-second default hard timeout. A timeout kills only the unique container name
allocated to that attempt. The report is created exclusively after all eight cases and a second
dependency/verifier commitment match; it is never overwritten.

## Promotion path

1. Build mathlib from the locked Git sources inside a digest-pinned OCI image with network
   disabled during the build and publish its SBOM/provenance.
2. Move the FATE wrapper and query helper into that image, retain the V2 compile/query container
   split, then rerun altered-statement, stdout spoof, trusted-module-shadow, persistent-writer,
   missing-declaration, unknown-axiom, and dependency-drift canaries.
3. Express each task as an immutable bundle and route the observation through the existing
   verifier-evidence and lease/fencing boundary.
4. Ask the signing gateway to attest only the resulting canonical evidence artifact.
5. Replace the static tactic policy with provider-generated proof-body patches while retaining
   the same source, execution, comparator, budget, and report contracts.
