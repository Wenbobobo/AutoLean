# Operator Live Gate

`scripts/operator_live_gate.py` is the short operator-facing bridge for the two
live checks that cannot run inside every development sandbox:

- `deepseek` invokes only `scripts/deepseek_authorized_canary.py --operator-approved`.
  Its credential is inherited only as `AUTOLEAN_DEEPSEEK_API_KEY`; the runner never
  reads `llm.txt`, a dotenv file, or a credential argument.
- `t6-oci` invokes only `python -m Library.scripts.library_substrate_image all`.
  On Windows, that existing Library command owns delegation to the fixed WSL runtime;
  Linux and WSL execute it natively.
- `deepseek` remains a Windows-host process on Windows. It does not traverse the
  WSL delegate, so it uses the host's normal operator network path.
- `all` executes both gates even when the first one is blocked.

Run one selected gate or both from the checkout:

```powershell
uv run --frozen python scripts/operator_live_gate.py all
```

The process writes one ASCII, canonical JSON summary to stdout. It retains only a
gate status, stable blocker, SHA-256 evidence hashes, the T6 Docker-recorded
`RepoDigest`, and DeepSeek usage counters. It deliberately drops command lines,
paths, prompts, responses, endpoints, credentials, and raw child diagnostics.

By default it creates no file. To preserve a result, use `--output` with a new
absolute path outside the checkout. The command refuses relative, in-checkout,
existing, or unavailable-parent output paths.

Neither a successful provider connectivity check nor a successful T6 OCI
preflight is Phase 1 promotion evidence. The emitted summary always sets
`phase1_promotion_eligible` to `false`.
