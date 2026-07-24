# AutoArchon Migration and Security Audit

## Scope

This audit covers the public `main` snapshot of
[Wenbobobo/AutoArchon](https://github.com/Wenbobobo/AutoArchon/tree/6a401ff552080bdfdd1e1f53bc6dc418379bf0ec)
at commit `6a401ff552080bdfdd1e1f53bc6dc418379bf0ec`, plus metadata returned by the
public Hugging Face dataset APIs for
[Garydesu/AutoArchon_Public](https://huggingface.co/api/datasets/Garydesu/AutoArchon_Public)
and
[Garydesu/AutoArchon_Private](https://huggingface.co/api/datasets/Garydesu/AutoArchon_Private).

No HF archive was downloaded, decrypted, extracted, or inspected **during this source audit**.
No session, prompt, credential, `helper.env`, or workspace content was copied into this
repository. A later operator-authorized, quarantine-only recovery is recorded separately in
[the containment record](../hf-incident-containment.md); it does not change this audit's source
or migration conclusions.

## Conclusion (confidence: high)

AutoArchon contains useful product and operational ideas, but its runtime must not be
migrated into AutoLean. It is a file-oriented, host-trusting campaign runner rather
than a durable Builder--Prover control plane. Reusing it as the execution substrate
would violate the required statement-fidelity boundary, immutable-artifact model,
concurrent lease semantics, secret policy, model allowlist, and read-only dashboard
boundary.

The usable migration rule is therefore:

> Preserve selected ideas and independently reimplement their semantics. Do not fork,
> vendor, or run AutoArchon's runtime, helper transport, recovery scripts, or dashboard
> in an AutoLean deployment.

At the time of this audit, the HF dataset named `AutoArchon_Private` was publicly enumerable and
reported `private: false`, `gated: false`. Its public tree metadata listed encrypted config,
workspace, campaign-metadata, and Codex-session archives, including a 1,624,079,559-byte
session archive. This is an active security incident even though the payloads are
encrypted; the audit did not inspect any passphrase or archive contents. It must be
made private or removed, then all potentially exposed credentials must be rotated before
any migration work.

## First Principles

A Lean kernel can establish that a frozen formal statement has a proof in a specified
environment. It cannot establish that an informal mathematical source was faithfully
translated. Builder and Prover must therefore have separate authority, communicate only
through revisioned contracts, and never share mutable workspace state as their protocol.

Thousands of workers make crashes, duplicate delivery, stale owners, and partial writes
normal events rather than edge cases. The system of record must make those events
unambiguous through transactional claims, fencing tokens, append-only events, and
content-addressed artifacts. A filesystem convention plus best-effort PID checks cannot
provide that property.

## Evidence and Findings

| Severity | Finding | Why it blocks runtime reuse |
| --- | --- | --- |
| Critical | Public "private" HF migration dataset | Access control is absent for data whose declared purpose includes config and Codex-session recovery. Treat all referenced credentials and session-derived data as potentially exposed. |
| Critical | Host-trusting agent execution and broad log capture | Codex is launched with `danger-full-access`, inherited host environment, optional search, and logging of tool inputs/outputs. This defeats an isolated, default-no-network worker boundary and can persist sensitive material. |
| High | File-backed state and non-fencing leases | Read/modify/write JSON files and JSONL append are not transactional. A stale worker can clobber a newer owner; event replay cannot establish exactly-once acceptance. |
| High | Dashboard is network-exposed and has XSS risk | It binds to `0.0.0.0`, enables permissive CORS, has no authentication, reads full logs directly, and inserts unescaped Markdown-derived HTML. |
| High | Statement fidelity is syntactic and task-specific | Header text comparison and regular-expression checks cannot establish semantic preservation, source provenance, revision binding, or theorem-type identity. |
| Medium | Source snapshots and artifacts are mutable copies | No source/content/type hash, immutable mount, artifact digest, or clean-environment verifier is bound to acceptance. Shared Lake packages are symlinked into workers. |
| Medium | Provider and credential model conflict | The helper supports Gemini/OpenRouter and accepts literal transport values. It also falls back to a local Codex auth file. AutoLean requires an explicit non-Anthropic allowlist and operator-owned secret references only. |

### 1. Public HF archive exposure

On 2026-07-23, the HF API reported the dataset named `AutoArchon_Private` as public and
ungated. Its [public tree metadata](https://huggingface.co/api/datasets/Garydesu/AutoArchon_Private/tree/main?recursive=true&expand=true)
listed encrypted archives for private config, campaign metadata/workspaces, and Codex
sessions. The checked-in recovery guide explicitly treats that dataset as the recovery
source for `helper.env`, curated campaign state, and sessions
([migration guide](https://github.com/Wenbobobo/AutoArchon/blob/6a401ff552080bdfdd1e1f53bc6dc418379bf0ec/docs/migration-recovery.md#L22-L35)).

Facts:

- Public metadata proves the dataset is accessible without HF authorization.
- Archive encryption is not a substitute for access control or credential lifecycle.
- The stated weak-passphrase premise was not independently verified here because doing
  so would require reading restoration material or decrypting an archive, both outside
  the safe audit scope.

Required containment:

1. Restrict or remove the public `AutoArchon_Private` dataset immediately.
2. Rotate OpenAI/Codex, HF, GitHub, custom-endpoint, and any helper credentials that
   could have existed in the archived configuration or sessions.
3. Preserve current dataset/repository SHAs and access logs for incident tracking, but
   do not use the archives as a migration source.
4. Create a fresh, separately reviewed public export containing only redacted schemas,
   manifests, independently rebuilt fixtures, and verification reports.

### 2. Execution and secret boundary failures

The Codex runner constructs `codex exec` with `--sandbox danger-full-access` and
`approval_policy=never`
([runner](https://github.com/Wenbobobo/AutoArchon/blob/6a401ff552080bdfdd1e1f53bc6dc418379bf0ec/archonlib/codex_logs.py#L201-L238)).
It copies the whole host environment into the child process and persists normalized and
optional raw logs ([same file](https://github.com/Wenbobobo/AutoArchon/blob/6a401ff552080bdfdd1e1f53bc6dc418379bf0ec/archonlib/codex_logs.py#L279-L373)).
The normalized log format records shell/MCP tool inputs and tool result content
([event normalization](https://github.com/Wenbobobo/AutoArchon/blob/6a401ff552080bdfdd1e1f53bc6dc418379bf0ec/archonlib/codex_logs.py#L111-L174)).

The helper path has three incompatible properties:

- it accepts OpenAI, Gemini, and OpenRouter providers
  ([provider list](https://github.com/Wenbobobo/AutoArchon/blob/6a401ff552080bdfdd1e1f53bc6dc418379bf0ec/archonlib/helper_models.py#L7-L35));
- it supports literal credential/base-URL material by injecting it into process
  environment variables
  ([transport binding](https://github.com/Wenbobobo/AutoArchon/blob/6a401ff552080bdfdd1e1f53bc6dc418379bf0ec/.archon-src/tools/helper_prover_agent.py#L167-L197));
- when an environment variable is absent, it reads the local Codex authentication file
  ([credential fallback](https://github.com/Wenbobobo/AutoArchon/blob/6a401ff552080bdfdd1e1f53bc6dc418379bf0ec/.archon-src/tools/informal_agent.py#L70-L83)).

Its test suite intentionally verifies inline transport-value support. That is useful
evidence of intended behavior, not a safe compatibility feature. AutoLean must reject
inline credential values at parsing time and provide workers only short-lived,
operator-resolved secret references.

### 3. Recovery is useful operationally but not correct under concurrency

AutoArchon has a real operational model: campaign operator, watchdog, run lease,
source/workspace/artifacts split, postmortem output, and replay-oriented summaries.
Those are valuable design inputs. The implementation, however, persists state with plain
`write_text` JSON files and plain JSONL append
([state writers](https://github.com/Wenbobobo/AutoArchon/blob/6a401ff552080bdfdd1e1f53bc6dc418379bf0ec/archonlib/campaign.py#L42-L65)).

`claim_owner_lease` performs a read/check/write sequence with no lock, compare-and-swap,
or fencing token ([lease claim](https://github.com/Wenbobobo/AutoArchon/blob/6a401ff552080bdfdd1e1f53bc6dc418379bf0ec/archonlib/campaign.py#L239-L286)).
`release_owner_lease` overwrites the file without validating that the releasing owner
still owns the current lease ([lease release](https://github.com/Wenbobobo/AutoArchon/blob/6a401ff552080bdfdd1e1f53bc6dc418379bf0ec/archonlib/campaign.py#L313-L347)).

Concrete failure case: worker A times out, worker B claims the lease, then delayed worker
A writes its release record. The current lease becomes inactive although B is running.
Two simultaneous claimers can likewise both observe an expired lease and both write a
successful claim. Neither event can be rejected later because submissions have no
monotonic fencing token.

AutoLean must replace this with SQLite WAL transactions locally, CAS lease operations,
monotonic fencing tokens on every state-changing API, append-only events with IDs, and
idempotency keys. PostgreSQL/object-store migration can then preserve the same semantics.

### 4. Artifact and environment isolation are insufficient

`create_isolated_run` copies the source and workspace, but records an origin path rather
than source/content/toolchain/type identities and does not make the source snapshot
read-only ([run creation](https://github.com/Wenbobobo/AutoArchon/blob/6a401ff552080bdfdd1e1f53bc6dc418379bf0ec/archonlib/run_workspace.py#L108-L161)).
It can symlink shared Lake packages into the workspace
([cache reuse](https://github.com/Wenbobobo/AutoArchon/blob/6a401ff552080bdfdd1e1f53bc6dc418379bf0ec/archonlib/run_workspace.py#L75-L105)).
Artifact export overwrites file-oriented proof/diff snapshots and an artifact index rather
than publishing immutable content-addressed objects
([export path](https://github.com/Wenbobobo/AutoArchon/blob/6a401ff552080bdfdd1e1f53bc6dc418379bf0ec/archonlib/run_workspace.py#L281-L379)).

For AutoLean, a `FormalizationTaskBundleV1` must include pinned source and environment
hashes, imports/axioms policy, a read-only input tree, a separate writable patch area,
and a full artifact manifest. The verifier must build the submitted patch in a clean,
network-disabled Linux/WSL2 worker and produce a `VerificationReportV1`; no workspace
file can itself be acceptance evidence.

### 5. The old formalization/validation layer cannot serve as Builder

The supervisor protects theorem headers by parsing source text with regular expressions
([header parser](https://github.com/Wenbobobo/AutoArchon/blob/6a401ff552080bdfdd1e1f53bc6dc418379bf0ec/archonlib/supervisor.py#L52-L199)).
Acceptance is then based on a clean loop status plus a changed file or a durable textual
task result ([acceptance rule](https://github.com/Wenbobobo/AutoArchon/blob/6a401ff552080bdfdd1e1f53bc6dc418379bf0ec/archonlib/validation.py#L58-L86)).
The validation payload has no trusted statement hash, elaborated-type hash, source span
hash, revision parent, axioms/import policy, or independent semantic reviewer.

For comment-only inputs, its formalization contract derives a handful of requirements
from regex matches over local files
([derivation](https://github.com/Wenbobobo/AutoArchon/blob/6a401ff552080bdfdd1e1f53bc6dc418379bf0ec/archonlib/formalization.py#L403-L463)).
It explicitly allows statement-stage placeholders and assesses fidelity through textual
patterns ([autoformalization policy](https://github.com/Wenbobobo/AutoArchon/blob/6a401ff552080bdfdd1e1f53bc6dc418379bf0ec/archonlib/formalization.py#L165-L189),
[assessment](https://github.com/Wenbobobo/AutoArchon/blob/6a401ff552080bdfdd1e1f53bc6dc418379bf0ec/archonlib/formalization.py#L550-L628)).

This is a useful warning set for one benchmark family, not a general fidelity system. It
cannot distinguish quantifier exchange, dropped non-emptiness/Noetherian hypotheses,
parameter reversal, or definition replacement when the token patterns still match. New
Builder contracts need independent candidate generation, reverse rendering, mutation
tests, examples/counterexamples, rights/provenance, and explicit human/expert review
before `frozen`.

The audited acceptance path also does not wire an axiom audit, `sorryAx` check,
import allowlist, or elaborated-theorem-type comparison into `validation.py`. A standalone
Lean skill script is not equivalent to an enforced verifier. AutoLean must make those
checks mandatory and machine-recorded before accepting a proof.

### 6. Existing dashboard contains good interaction ideas but is unsafe to reuse

The UI has worthwhile interaction patterns: file snapshot playback, unified diffs,
iteration/attempt log grouping, journal/milestone views, and aggregate cost/token data.
Those can inform AutoLean's read-only Dashboard.

Its implementation is not an acceptable starting point. The server registers unrestricted
CORS and listens on all interfaces without authentication
([server](https://github.com/Wenbobobo/AutoArchon/blob/6a401ff552080bdfdd1e1f53bc6dc418379bf0ec/ui/server/src/index.ts#L38-L70)).
It reads logs directly from the project tree, and its Markdown renderer interpolates
unescaped input before passing it to `dangerouslySetInnerHTML`
([renderer](https://github.com/Wenbobobo/AutoArchon/blob/6a401ff552080bdfdd1e1f53bc6dc418379bf0ec/ui/client/src/utils/markdown.ts#L1-L54),
[sink](https://github.com/Wenbobobo/AutoArchon/blob/6a401ff552080bdfdd1e1f53bc6dc418379bf0ec/ui/client/src/components/MarkdownBlock.tsx#L1-L8)).
Agent-produced text and logs are attacker-controlled for this purpose.

AutoLean's Dashboard should instead query a redacted event projection API, default to
`127.0.0.1`, require authentication for remote access, use a strict Content Security
Policy, and render Markdown only through a sanitizer with no raw HTML. It should expose
statement revision, three graphs, attempts, gaps, patches, verifier reports, model/cost,
and provenance without exposing raw secrets or host paths.

## What to Reimplement, Not Migrate

| AutoArchon idea | AutoLean replacement | Constraint |
| --- | --- | --- |
| `source/`, `workspace/`, `artifacts/` run layout | Immutable bundle inputs, isolated patch workspace, content-addressed artifacts | Inputs and outputs carry hashes and write-domain policy. |
| Campaign watchdog, cooldown, restart budget | Scheduler policy over durable event/state records | Lease ownership is transactional and fenced. |
| Final vs postmortem artifacts | `ReviewDecisionV1` and immutable verification evidence | A failed or blocked task is never silently promoted. |
| Lesson records/clusters | Secondary retrieval/diagnostic artifacts | Retrieval is advice, never proof or contract authority. |
| Snapshot/diff/attempt dashboard | Read-only event-projection UI | Redaction, auth, sanitized rich text, no direct workspace filesystem API. |
| Helper call budgets and failure categories | ModelProvider quota, circuit-breaker, and cost accounting | Provider is capability-probed, allowlisted, and secret-isolated. |
| Narrow run scopes | Graph-derived `ContextPack` | Scope comes from a frozen statement revision and dependency frontier, not regex file selection. |

## Contract Compatibility Matrix

| Required AutoLean property | AutoArchon equivalent | Decision |
| --- | --- | --- |
| `StatementContractV1` with source span/hash, rights, revision, Lean statement, environment, policies, and three graphs | Local JSON formalization note with regex-derived fields | Reimplement from scratch. |
| Builder/Prover communicate only by immutable public protocol | Agents share workspace, `.archon` files, and launch scripts | Incompatible. |
| Stable IDs plus separate source/Lean/elaborated-type hashes | Path/name and source header text | Incompatible. |
| `claim`, `submit_proof`, `report_gap`, `request_contract_change`, `verify_submission` | Shell/script lifecycle and mutable filesystem records | Reimplement APIs. |
| SQLite WAL/CAS/fencing/event replay | Plain JSON/JSONL and PID heuristics | Incompatible. |
| OCI worker, default no network, patch-only writes | Host `danger-full-access` Codex process | Incompatible. |
| Codex/OpenAI/custom compatible endpoints with explicit non-Anthropic policy | OpenAI/Gemini/OpenRouter helper surface and loose fallback | Reimplement ModelProvider. |
| Read-only authenticated dashboard | Direct workspace reader bound to all interfaces | Reimplement UI/API boundary. |

## Counterargument

For a disposable, single-machine FATE demo run by one trusted operator, a pinned
AutoArchon fork could produce a visible result faster. Its tests and documentation show
substantial work on campaign lifecycle, UI playback, and operational recovery.

That argument stops holding once the target is a many-agent mathematical system. The
failure modes above are architectural: a syntactic header fence is not semantic fidelity;
a mutable workspace is not a contract boundary; a PID lease is not a fencing protocol;
and a host-wide agent process is not a worker sandbox. The decision criterion is simple:
if a result must remain trustworthy after retries, operator changes, worker crashes, or
later mathematical review, it must use the new control plane.

## Uncertainties and Verification Status

- The audit did not decrypt or download HF archives, inspect any session/config payload,
  or test a passphrase. The public-access finding is independently verified from API
  metadata; the contents are intentionally unknown.
- The checkout was scanned for common cleartext credential signatures without printing
  matches. No apparent live credential was found in the audited current source tree;
  this does not clear historical Git objects, ignored files, HF archives, external
  services, or endpoint logs.
- `pytest --collect-only -q` completed and collected 299 tests. A full-suite run was not
  accepted as audit evidence because the local host closed its test-process output before
  a result could be recovered. In any case, the current tests do not establish the
  required distributed correctness or semantic-fidelity properties.
- Before importing even selected files, run a full-history secret scan in an isolated
  incident-response environment and review licenses/provenance of each copied idea.

## Next Steps

1. Complete containment and credential rotation before touching HF artifacts.
2. Keep AutoArchon only as a pinned read-only research reference; do not add it as a
   git submodule, runtime dependency, or deployment template.
3. Encode the compatibility matrix as ADRs and tests in AutoLean: contract revision
   immutability, stale-fencing rejection, clean verifier, `sorryAx`/axiom/import policy,
   redacted events, and dashboard security defaults.
4. Recreate the high-value operational ideas behind the new interfaces, beginning with
   immutable task bundles, event store/lease semantics, proof verification, and an
   event-projection dashboard.
