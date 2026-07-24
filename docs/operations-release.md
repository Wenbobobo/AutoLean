# Phase 1 Operations and Release Runbook

## Scope and authority

This runbook collects and reviews release evidence. It does not authorize a Builder freeze, accept
a proof, approve a model endpoint, or waive a failed acceptance gate. The authoritative proof
record remains the frozen statement contract, its matching immutable bundle and submission, and
an independent verification report from the pinned environment.

The release inventory is deliberately an **offline lock inventory**, not an installed-host scan.
It reads only `pyproject.toml`, `uv.lock`, `Dashboard/ui/pnpm-lock.yaml`, and
`benchmarks/fate.lock.json`, plus the answer-free `benchmarks/fate-splits.v1.json`. It contains
relative input paths, bytes, SHA-256 digests, package identities, package artifact/integrity
hashes, and the pinned FATE facts. It intentionally contains no timestamps, absolute paths,
environment variables, endpoint configuration, Git configuration, credentials, prompts, sessions,
logs, solutions, or recovered archive contents.

## Non-negotiable RC blockers

An existing `.git/` directory is not by itself source provenance. The bootstrap baseline is commit
`48b129097773616a28534abfe833eb10b9779aac`, whose Windows/Linux GitHub CI run completed
successfully. Every later release candidate must record its own resolved commit, clean status,
remote CI URL, and exact evidence hashes; it may not inherit the bootstrap result after source or
lock inputs change.

Likewise, Python unit tests and source manifests do not establish the required Lean/OCI boundary.
Until there are recorded clean builds in the pinned Linux/WSL2 OCI environment, including the
verifier-owned elaborated-type comparison and required canaries, this checkout is not a Phase 1
release candidate. A host Lean installation, a static adapter test, or a successful FATE-Eval run
cannot substitute for that evidence.

Ignored local observations, including `Library/evidence/` compile reports and
`release-evidence/oci-worker/` test-only canaries, are useful diagnostics but are not committed
release evidence or production attestations. A later release decision must bind a clean source
commit, canonical build inputs, immutable artifact references, an authoritative mathlib-capable
OCI verification record, and the required deployed authority evidence. A partial Library spike or
test-only gateway receipt never closes a Builder semantic gate or a promotion gate.

Other hard blockers are:

- no retained 1,000-job **OS-process** kill/restart/replay report proving no loss, duplicate
  acceptance, or stale-fence submission. The bounded synthetic harness in
  [`scripts/control_plane_process_chaos.py`](../scripts/control_plane_process_chaos.py) exercises
  this control-plane protocol boundary; its small smoke default and the older in-process
  reconstruction harness are useful regressions but do not satisfy this gate;
- no verified FATE source manifest plus separately reported M/H/X benchmark result;
- no controlled-browser dashboard evidence covering rendered sanitizer/XSS payloads, desktop and
  mobile layouts, and authenticated non-loopback access;
- no SPDX or CycloneDX SBOM generated from an identified tool, with the exact generated artifact
  retained as release evidence;
- no deployment evidence that provider approval and verifier signing are isolated behind an
  operator-authenticated authority or KMS/service boundary; and
- no explicit release decision listing every passed, failed, waived, and unrun gate. A favorable
  benchmark score never waives a semantic, worker, security, or provenance gate.

## Evidence collection

Run the short project scripts from the intended immutable checkout. The first three commands are
offline after dependencies have been bootstrapped; none starts a model or downloads FATE tasks.

```powershell
uv run python scripts/dev.py bootstrap
uv run python scripts/dev.py check
uv run python scripts/release_evidence.py check
uv run python scripts/release_evidence.py generate --output release-evidence/inventory.v1.json
uv run python scripts/dev.py sbom
uv run python -m scripts.generate_sbom generate --output release-evidence/autolean-phase1.spdx.json
```

`release_evidence.py check` builds the inventory twice in memory, checks byte-for-byte equality,
checks that exactly the five declared lock inputs were used, and rejects an absolute workspace path
in the generated JSON. `generate` atomically writes the exact same canonical JSON. It refuses
protected recovery and agent-work directories as output locations. Review the generated file before
including it in a release evidence package; its source hashes must match the files supplied for the
release decision.

`scripts/dev.py sbom` verifies deterministic SPDX generation without writing an artifact. The
explicit `generate` command writes a canonical SPDX 2.3 **lock-input SBOM** beside the inventory;
the output must be retained and hashed in the release decision. See [the SBOM boundary](sbom.md).
It does not scan the host, fetch packages, establish a source commit, clear licenses, or establish
installed-binary provenance.

For FATE, an operator must separately provide a clean checkout at the lock's actual revisions and
create a content-addressed source manifest with the strict adapter documented in
[the benchmark guide](../benchmarks/README.md). Never substitute FATE-Eval code, task JSON, or
verification output. Store only the adapter's manifest hash and redacted result metadata in release
evidence, never answer files or model prompts.

## Promotion checklist

1. Record a real source commit and clean-tree evidence from a non-empty Git repository. If either
   is unavailable, stop with `blocked: source-provenance`.
2. Record the `scripts/dev.py check` result and the deterministic inventory digest. If either fails,
   stop with `blocked: static-quality` or `blocked: inventory`.
3. Record the pinned FATE manifest digest, canary/smoke/regression selection manifests, and M/H/X
   reports separately. If source, theorem boundary, or environment provenance is missing, stop with
   `blocked: benchmark-provenance`.
4. Record clean Lean and elaborated-type verification in the pinned Linux/WSL2 OCI environment.
   The report must bind the contract, proof boundary, toolchain/mathlib, imported axioms, and
   immutable artifact hashes. Otherwise stop with `blocked: authoritative-execution`.
5. Record the required 1,000-job OS-process chaos/replay report, worker isolation,
   controlled-browser dashboard sanitizer/authentication/remote-access tests, and provider policy
   tests. The process-chaos report is limited to synthetic SQLite/artifact recovery and cannot
   substitute for Lean/OCI, power-loss, or mid-transaction crash evidence. Otherwise stop with
   `blocked: operational-safety`.
6. Generate and retain an SPDX or CycloneDX SBOM using a documented generator and policy. The
   offline lock inventory is an input, not a substitute. Otherwise stop with `blocked: sbom`.
7. Have the release owner publish a signed or otherwise independently retained release decision that
   enumerates the evidence digests and every unrun, failed, or explicitly waived gate. Do not use the
   word `RC` unless all non-waivable gates passed.

The inventory is a release-input inventory. The SPDX artifact is derived from it, but neither file
asserts vulnerability status, license clearance beyond the lock metadata, or installed-binary
provenance. Add those claims only after the corresponding scanner, policy, and evidence source have
been separately introduced and reviewed.
