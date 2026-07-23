# Public Repository Release Gate

Repository visibility is separate from proof promotion and from containment of the historical
AutoArchon backup incident. A public AutoLean source tree does not imply that recovered data,
credentials, private prompts, model output, or source documents are cleared for publication.

Run:

```powershell
uv run python scripts/dev.py public-ready
uv run python -m scripts.secret_scan
uv run python -m scripts.provider_policy_guard
```

The public-readiness command inventories Git-tracked and non-ignored candidate files. It rejects
local caches, quarantine or result directories, source PDFs and office documents, archives,
databases, raw JSONL/logs, key material, symlinks, files above 5 MiB, and environment files other
than `.env.example`. It explicitly rejects role-benchmark raw-output CAS directories and private
raw-artifact manifests, even when a file is force-added outside the normal ignored paths. JSON
containing a non-null `permitted_excerpt` is also rejected because fidelity artifacts with
verbatim source text are private evidence. It also
requires the root Apache-2.0 license and matching metadata in every Python workspace package and
the Dashboard UI.

This is a repository-tree policy, not a forensic content scanner. The secret scanner and provider
policy run separately, and an operator must still inspect the reachable Git history and Git-host
secret-scanning result before changing visibility. A passing result does not close external
credential rotation, dataset access control, license review for third-party sources, or model
egress authorization.

Downloaded references live only under an ignored cache and are verified against a tracked
manifest. Public access to a document is not automatically permission to redistribute it or send
its text to an external model.
