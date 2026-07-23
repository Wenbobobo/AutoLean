# Archon v0.3.3 adoption audit

## Conclusion (confidence: high)

Audit target: frenzymath/Archon at SHA
5e9ae7615efa0aa2cff11edabd5fbc0d45308fd5. I cloned this exact commit,
checked it out detached, and verified that its package version is 0.3.3.

Archon contains useful project-formalization ideas and several strong dashboard
interaction patterns. It must not be adopted as AutoLean's runtime, control
plane, worker sandbox, credential layer, or proof-acceptance verifier. Selective
Apache-2.0 source/component reuse is possible only behind AutoLean's new
contracts, event store, and isolated verifier.

The fundamental mismatch is that Archon is a trusted-user agent loop operating
in a live project worktree. AutoLean needs a multi-worker system where Builder
owns statement fidelity, Prover receives frozen contracts, and only a verifier
outside the agent workspace can accept a result.

## Reusable assets

| Asset | Why it is valuable | Required AutoLean boundary |
| --- | --- | --- |
| Blueprint plus LeanDag workflow | It extracts Lean declarations, blueprint nodes, gaps, dependency cones, and a cached project graph. | Use only as an optional graph extractor. It cannot replace MathematicalGraph, FormalGraph, or ExecutionGraph; extracted edges need provenance and review status. |
| Plan, prover, review, and focused subagents | It demonstrates useful specialization and bounded context windows. | Re-express as independent task types and ContextPacks over immutable bundles, never a shared checkout. |
| Codex event normalization | It maps Codex JSON events into structured session records suitable for a live UI. | Implement EventEnvelopeV1 independently; do not inherit its provider configuration, sandbox policy, or retention behavior. |
| DAG, diff, timeline, journal UI | Force/layered graph layout, cone focus, status glyphs, historical browsing, and source/diff links are good read-only-panel patterns. | Feed a read model projected from events and approved artifacts only. Never serve a live workspace, raw prompts, or arbitrary local files. |
| Worktree and competing-lane concepts | Multiple independent attempts and deterministic comparison are the right high-level direction. | Replace shared inner-Git worktrees with OCI workers, immutable snapshots, patch-only submissions, leases, and verifier-owned merge/acceptance. |
| Frozen-signature intent | A mathematician-owned protected surface aligns with statement contracts. | Replace prompt-level protection with contract revision hashes plus elaborated-type and import/axiom verification. |

Archon is Apache-2.0. Its notices also identify modified MIT components
lean4-skills and lean-lsp-mcp. Any copied source must retain the required
notices. License compatibility is not a security approval.

## Blocking findings

### Critical: default execution has host authority

The shipped Codex descriptor sets sandbox to danger-full-access. The descriptor
type and loader use the same default. The argv builder passes it straight to
Codex and then appends project-configured extra arguments without an allowlist.

Evidence:
[default descriptor](https://github.com/frenzymath/Archon/blob/5e9ae7615efa0aa2cff11edabd5fbc0d45308fd5/src/archon/commands/tooling/project_config.py#L223),
[descriptor defaults](https://github.com/frenzymath/Archon/blob/5e9ae7615efa0aa2cff11edabd5fbc0d45308fd5/src/archon/commands/tooling/project_config.py#L546),
[Codex argv construction](https://github.com/frenzymath/Archon/blob/5e9ae7615efa0aa2cff11edabd5fbc0d45308fd5/src/archon/agents/codex.py#L585).

The main prover runs with its current directory equal to the project directory
after only a best-effort baseline copy; it does not submit a patch to a separate
verifier. See
[prover runners](https://github.com/frenzymath/Archon/blob/5e9ae7615efa0aa2cff11edabd5fbc0d45308fd5/src/archon/commands/loop/prover/runners.py#L68).

Impact: a model, prompt injection, or modified workspace configuration can
alter the authority that later judges it. AutoLean must use default-deny OCI
workers, no network by default, read-only dependencies, immutable bundles, and
a verifier which applies a validated patch in a fresh workspace.

### Critical: credentials are copied into project state and endpoint routing is workspace-configured

The environment template writes matching host-shell credential values into the
project .archon/.env file, including OpenAI and alternative-provider keys.
Git-ignore does not prevent an agent in the workspace, a log, a backup, or a
dashboard process from reading that file.

Evidence:
[environment template](https://github.com/frenzymath/Archon/blob/5e9ae7615efa0aa2cff11edabd5fbc0d45308fd5/src/archon/commands/tooling/env_loader.py#L114)
and [initialization](https://github.com/frenzymath/Archon/blob/5e9ae7615efa0aa2cff11edabd5fbc0d45308fd5/src/archon/commands/init/steps/env_config.py#L20).

The Codex harness reads base_url_env and key_env from project config, copies the
named host value into CODEX_GATEWAY_API_KEY, and configures Codex to use the
chosen endpoint. There is no operator-owned endpoint/key allowlist.

Evidence:
[credential resolution](https://github.com/frenzymath/Archon/blob/5e9ae7615efa0aa2cff11edabd5fbc0d45308fd5/src/archon/agents/codex.py#L544)
and [child environment construction](https://github.com/frenzymath/Archon/blob/5e9ae7615efa0aa2cff11edabd5fbc0d45308fd5/src/archon/agents/codex.py#L799).

Impact: an agent-editable project configuration can become a credential-routing
or exfiltration primitive. In AutoLean, provider endpoint and credential
references must be operator-owned and outside Builder/Prover workspaces.

### Critical: Dashboard is unauthenticated and binds a non-loopback address

The Fastify server registers CORS without authentication and binds to the
wildcard/dual-stack address :: on native systems or 0.0.0.0 on WSL, while the
printed URL says 127.0.0.1. It serves source, task results, logs, and live log
WebSockets.

Evidence:
[server startup](https://github.com/frenzymath/Archon/blob/5e9ae7615efa0aa2cff11edabd5fbc0d45308fd5/src/archon/ui/server/src/index.ts#L63)
and [log routes](https://github.com/frenzymath/Archon/blob/5e9ae7615efa0aa2cff11edabd5fbc0d45308fd5/src/archon/ui/server/src/routes/logs.ts#L542).

Impact: any client that reaches the listener can read mathematical work,
execution metadata, and retained log content. AutoLean must bind 127.0.0.1 by
default, expose no write route, and require authentication plus explicit remote
policy before leaving loopback.

### High: statement protection and proof verification are advisory/non-blocking

Archon's own code says declaration- and label-level protection remains advisory
and prompt-enforced. Its deterministic check only rejects a subagent-declared
write domain that overlaps a wholly protected file; it does not inspect the
resulting diff, and the main prover path does not use that subagent gate.

Evidence:
[subagent protection](https://github.com/frenzymath/Archon/blob/5e9ae7615efa0aa2cff11edabd5fbc0d45308fd5/src/archon/subagents/base.py#L207)
and [protected-set semantics](https://github.com/frenzymath/Archon/blob/5e9ae7615efa0aa2cff11edabd5fbc0d45308fd5/src/archon/commands/tooling/protect.py#L120).

Lake build failures are recorded but the loop continues. The sorryAx sweep is
opt-in and non-blocking.

Evidence:
[finalization](https://github.com/frenzymath/Archon/blob/5e9ae7615efa0aa2cff11edabd5fbc0d45308fd5/src/archon/commands/tooling/iteration.py#L94)
and [axiom sweep](https://github.com/frenzymath/Archon/blob/5e9ae7615efa0aa2cff11edabd5fbc0d45308fd5/src/archon/commands/loop/axiom_sweep.py#L1).

Impact: neither a leanok marker nor a completed-looking Archon node is an
AutoLean proof-acceptance certificate. AutoLean acceptance must preserve
theorem type and contract revision, require a clean build in the pinned
environment, and reject sorryAx, unapproved axioms, forbidden imports, and
declaration replacement.

### High: state semantics cannot support large-scale workers

Archon has useful local slot-file coordination, but iteration metadata is a
plain read-modify-write JSON file with no transaction, compare-and-swap
revision, fencing token, or durable task claim. Its inner Git deliberately
shares the mathematician's live worktree, including branch operations that
rewrite live files.

Evidence:
[metadata update](https://github.com/frenzymath/Archon/blob/5e9ae7615efa0aa2cff11edabd5fbc0d45308fd5/src/archon/state/iteration.py#L274)
and [inner Git design](https://github.com/frenzymath/Archon/blob/5e9ae7615efa0aa2cff11edabd5fbc0d45308fd5/src/archon/commands/tooling/inner_git.py#L1).

Impact: this cannot establish at-most-once acceptance, reject stale workers, or
safely replay duplicate delivery at the proposed scale. Retain the audit-history
idea but use SQLite WAL transactions, append-only events, content-addressed
artifacts, leases, and fencing tokens.

### High: runtime conflicts with the no-Claude policy and lacks a reproducible lock

The default runner is Claude Code, the package depends on claude-p, and the
configuration includes Anthropic-compatible lanes. This conflicts with
AutoLean's explicit ban on Claude/Anthropic providers. The project also points
to Git tags for dependencies and explicitly ignores uv.lock.

Evidence:
[package metadata](https://github.com/frenzymath/Archon/blob/5e9ae7615efa0aa2cff11edabd5fbc0d45308fd5/pyproject.toml#L5)
and [ignored lockfile](https://github.com/frenzymath/Archon/blob/5e9ae7615efa0aa2cff11edabd5fbc0d45308fd5/.gitignore#L13).

AutoLean must have its own uv workspace and committed lockfile with SHA-pinned,
audited dependencies. Do not import Archon packages, Claude providers,
Anthropic environment conventions, examples, or fallbacks.

### Medium: UI rendering and static export require separate content-security review

The UI renders generated Markdown through dangerouslySetInnerHTML, while
link/image URLs have no protocol allowlist. It can therefore preserve
click-triggered javascript URL payloads in model-controlled content.

Evidence:
[Markdown renderer](https://github.com/frenzymath/Archon/blob/5e9ae7615efa0aa2cff11edabd5fbc0d45308fd5/src/archon/ui/client/src/components/MarkdownBlock.tsx#L21).

Static export aliases known absolute paths but does not classify or redact
general secret-bearing content before writing a GitHub Pages artifact.

Evidence:
[static export redaction](https://github.com/frenzymath/Archon/blob/5e9ae7615efa0aa2cff11edabd5fbc0d45308fd5/src/archon/commands/dashboard/static_export.py#L232).

Use a sanitizer and strict http/https allowlist, or render untrusted content as
text. Make any public export a separately authorized, scrubbed release pipeline.

## Recommended adoption boundary

1. Do not fork the runtime. Keep Archon outside the dependency graph and use it
   as a design/reference source only.
2. Audit LeanDag separately before use, pin its exact SHA, and hide it behind an
   adapter. Its scan output is evidence, not statement-fidelity proof.
3. Rebuild the provider seam around FakeProvider, Codex CLI, OpenAI Responses,
   and operator-configured Responses/Chat-compatible endpoints. Capability
   probing and provider allowlisting happen before task claim.
4. Rebuild execution and acceptance. A worker returns a patch and
   ProofSubmissionV1; a verifier owns the clean checkout and emits
   VerificationReportV1.
5. Reuse UI selectively. The first candidates are DAG layout, cone navigation,
   diff playback, and timeline interaction patterns, all fed only from a
   read-only event projection.

## Verification and limits

- The stated SHA was verified by detached checkout; package metadata reports
  version 0.3.3.
- I read the Python runtime, Codex harness, protection, state, DAG, dashboard,
  static export, and package metadata. Python byte-compilation passed; it
  emitted one existing SyntaxWarning in project.py line 389.
- The repository has 55 Python test modules, including Codex, protection, and
  multilane tests. No TypeScript UI test suite or browser-test configuration
  was found. npm is unavailable in this audit environment, so no npm advisory
  scan was run.
- This is a source/configuration audit, not a full dynamic penetration test of
  an installed Archon stack. Before copying any UI or parser code, test the
  resulting AutoLean component for dependencies, SAST, path traversal, XSS,
  authenticated browser access, and sandbox escape.
