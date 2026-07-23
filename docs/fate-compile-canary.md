# FATE compile-canary-12

`scripts/fate_compile_canary.py` performs one bounded compatibility check: WSL 2 runs
`lake env lean` against the twelve original, pinned FATE source files. Those sources still
contain their benchmark `sorry`; therefore exit code zero means only that the locked statement
and its pre-declarations elaborate in the selected Lean environment. It is not a proof, a model
score, or evidence that any FATE task was solved.

The runner fails closed before Lean starts when any of these inputs drift:

- `fate.lock.json`, the root FATE commit, or any of its three submodule commits;
- the repository-pinned SHA-256 of `fate-source-manifest.v1.json`;
- any tracked FATE worktree file or any of the twelve source byte hashes;
- the three separately pinned Lake manifest hashes or the locked Lean/mathlib revisions;
- Ubuntu 24.04 under WSL, Lean 4.28.0, Lake 5.0.0, or any installed Lake package Git revision;
- a tracked modification in an installed Lake package.

Run it from the repository root with an unused output path:

```powershell
uv run python scripts/fate_compile_canary.py `
  --output release-evidence/fate-compile-canary-12.wsl.v1.json
```

The output is created exclusively and is never overwritten. M, H, and X retain separate case
lists and summaries. Each case records only stable identifiers, source/signature hashes, the
normalized command, elapsed time, exit/result, and hashes plus byte counts of stdout/stderr.
Source text, proof answers, diagnostics, and environment values are not written.

The child process begins from an empty environment and receives only `HOME`, `PATH`, `LANG`, and
`LC_ALL`; their values are not reported. The script itself does not request writes or network
access, but it does **not** provide kernel-enforced filesystem or network isolation. The
authoritative proof-verification path remains the digest-pinned OCI worker. This canary closes
only the WSL baseline-compilation portion of the Phase 1 environment gate.

The run also compares each canary file before and after compilation. That detects ordinary
concurrent drift but is not a substitute for an immutable mount against a hostile local actor.

## Reproducible ext4 runtime

Windows and ext4 checkouts do not materialize this fixture identically. The 350 task sources and
other tracked Lean inputs are bound to LF Git blobs, while the repository lock intentionally
binds each split's metadata JSON and `lake-manifest.json` to CRLF worktree bytes. A plain WSL
checkout therefore cannot satisfy both boundaries.

`scripts/fate_wsl_runtime.py` provides three bounded commands:

- `prepare` creates an isolated local object database and detached worktrees below an explicit
  ext4 cache root. It uses `git clone --local --no-hardlinks`; it neither fetches nor retains a
  remote. Split-specific Git `info/attributes` name only the two CRLF paths.
- `audit` is read-only. It verifies all commits, all 350 task hashes, both locked JSON hashes per
  split, LF source policy, clean tracked worktrees, nine dependency commits, and every symbolic
  link boundary.
- `run` performs the same audit and only then invokes the canary runner natively in WSL.

The shared packages directory must already exist and must be a real directory below the explicit
cache root. The three runtime `.lake/packages` links must resolve exactly to it. No command
downloads dependencies.

Example audit of an existing runtime:

```powershell
uv run python scripts/fate_wsl_runtime.py audit `
  --cache-root /home/operator/.cache/autolean `
  --packages-root /home/operator/.cache/autolean/fate-cache/FATE-M/.lake/packages `
  --runtime-root /home/operator/.cache/autolean/fate-runtime-v1-bb646ecb/runtime
```

For a new managed layout, replace `audit` with `prepare` and omit `--runtime-root`. The layout
name is derived from the locked root commit. A second `prepare` reuses it only when its canonical,
path-free state file and complete audit still match. Existing partial layouts, unknown targets,
state drift, or output files are never deleted or overwritten. The prepare result returns a
`runtime_path_relative_to_cache` such as `fate-runtime-v1-bb646ecb/runtime`; pass the cache root
joined to that relative path as `--runtime-root`. The enclosing deterministic layout directory is
not itself a Git worktree and must not be passed as the runtime root.

Run with a new output path:

```powershell
uv run python scripts/fate_wsl_runtime.py run `
  --cache-root /home/operator/.cache/autolean `
  --packages-root /home/operator/.cache/autolean/fate-cache/FATE-M/.lake/packages `
  --runtime-root /home/operator/.cache/autolean/fate-runtime-v1-bb646ecb/runtime `
  --output benchmarks/results/fate-compile-canary-ext4.v1.json
```

Runtime state, audit output, and the canary report contain hashes and stable identifiers, not
absolute paths, source text, proof answers, environment values, or subprocess/network logs. Git
worktree administrative files necessarily point to a verified local object database inside the
cache root; all symbolic links are separately confined to that root.
