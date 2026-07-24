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
verbatim source text are private evidence. It also rejects the exact repository path prefixes
`docs/meeting/` and `tmp/`, including force-added files. Prefix matching is case-insensitive and
normalizes `/` and `\\` separators, but is component-bounded: `docs/meetingsafe/`,
`docs/meeting-notes/`, and `tmpfile/` are not blocked by this rule. It also
requires the root Apache-2.0 license and matching metadata in every Python workspace package and
the Dashboard UI.

These two boundaries are enforced from the Git candidate inventory, not merely through
`.git/info/exclude` or `.gitignore`; `git add -f` cannot make their contents release-ready.
Before reading any tracked candidate from the worktree, both public-readiness and secret scans
require the Git index and worktree to agree. Run the release audit after staging the intended
tree. This prevents a staged blob or symlink from being hidden behind different worktree bytes.

This is a repository-tree policy, not a forensic content scanner. The secret scanner and provider
policy run separately, and an operator must still inspect the reachable Git history and Git-host
secret-scanning result before changing visibility. A passing result does not close external
credential rotation, dataset access control, license review for third-party sources, or model
egress authorization.

Downloaded references live only under an ignored cache and are verified against a tracked
manifest. Public access to a document is not automatically permission to redistribute it or send
its text to an external model.
