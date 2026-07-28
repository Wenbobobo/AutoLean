# Danus code audit: research scout, not a truth layer

Status: completed read-only source audit; no Danus runtime or dependency imported

Audit date: 2026-07-28

Pinned repository revision:
[`7e244865968d3268b21c96b898c7af1f55d2f7c5`](https://github.com/frenzymath/Danus/commit/7e244865968d3268b21c96b898c7af1f55d2f7c5)
(2026-07-22 02:56:31 UTC).

Primary records:

- [repository](https://github.com/frenzymath/Danus);
- [Apache-2.0 code license](https://github.com/frenzymath/Danus/blob/7e244865968d3268b21c96b898c7af1f55d2f7c5/LICENSE);
- [architecture](https://github.com/frenzymath/Danus/blob/7e244865968d3268b21c96b898c7af1f55d2f7c5/ARCHITECTURE.md);
- [arXiv:2607.06447v2](https://arxiv.org/abs/2607.06447), dated 2026-07-08 and
  licensed CC BY 4.0.

The Python package declares version `0.1.0`, but the audit found no evidence for a corresponding
release or tag. All references in this report therefore use the commit SHA.

## Decision

Do not fork Danus and do not place it in the AutoLean control plane, FormalGraph, or verification
authority.

Use selected Danus ideas later as an isolated, provider-neutral **research scout**. Its outputs are
untrusted proposed lemmas, counterexamples, decompositions, and literature leads. Every useful
output must still pass:

```text
research scout
  -> Builder source binding, machine review, and statement freeze
  -> unchanged Prover bundle
  -> Lean kernel and independent replay
  -> trusted formal asset
```

This placement is not a minor integration detail. Danus verifies informal natural-language proofs
with another model, while AutoLean's north-star work requires a separate statement-fidelity system
and kernel-checkable proof authority.

## Evidence that matters

The paper reports six research-level case studies and a largest run with 3,157 admitted facts,
8,616 edges, depth 54, and a final supporting closure of 664 facts. These are useful case-study
observations, not a benchmark:

- there is no fixed token/cost/timeout protocol;
- there are no repeated Danus trials or confidence intervals;
- verifier false positives have no reported denominator or confusion matrix;
- human input and final review vary by case; and
- no repository benchmark runner reproduces the claims.

The paper's own counterexamples are more important than the raw scale. In its matroid case, the
system completed a manuscript for the rational version before human reviewers noticed that the
original problem required an integral class. In another case, an erroneous literature definition
propagated until human review forced revocation and repair. The authors also state that a verifier
can accept skipped steps or bad cited references. These are direct demonstrations that a fact graph
does not solve statement fidelity or reference trust by itself.

## Ideas to absorb by reimplementation

1. **Fact-sized exploration.** Give one worker one lemma, counterexample, or toy instance rather
   than a whole proof. This fits bounded ContextPacks and parallel ownership.
2. **Exploration graph versus supporting closure.** Report the full search separately from the
   minimal closure supporting a final result. Fact count alone is not progress.
3. **Three memory tiers.** Local work is private scratch; global memory is shared awareness; only
   frozen, independently verified AutoLean artifacts can become formal truth.
4. **Constructive and refutational diversity.** Schedule constructive proofs, counterexamples,
   boundary cases, and toy models as different worker portfolios rather than identical replicas.
5. **Low-frequency strategy compression.** Periodically compress evidence into a guidance artifact
   for a strong planner. Guidance may allocate work; it may not create mathematical dependencies.
6. **Cascade invalidation.** When a source, contract, or dependency is invalidated, mark all
   descendants stale and require new immutable revisions and re-verification.
7. **Fresh critic context.** A new reviewer context reduces self-review bias. It remains advisory
   for semantics and cannot replace Lean for proof acceptance.
8. **Artifact seam verification.** A correct graph can be rendered into an incorrect paper,
   textbook explanation, or PR description. Recheck the assembled artifact as written.
9. **Isolated authoring context.** Give the writer only selected, reviewed material; do not expose
   orchestration logs, private prompts, or irrelevant internal vocabulary.

## Code-level reasons not to reuse the runtime

### Verdict-only truth admission

The [fact submission gate](https://github.com/frenzymath/Danus/blob/7e244865968d3268b21c96b898c7af1f55d2f7c5/danus/gateway/server.py#L151-L247)
sets `accepted` from `result.get("verdict") == "correct"`. It does not validate a report schema,
reject a `correct` verdict paired with critical errors or gaps, bind model/config/run identity,
bind the submission hash, or require independent replay. A top-level model string therefore owns
the truth transition.

### Dependency input is not closed

The verifier service receives only statement and proof. It is not passed the project, predecessor
IDs and contents, bibliography revision, or their hashes. The verifier contract says it may read a
project fact graph, but the launcher does not provide a project binding in its prompt.

The [fact add path](https://github.com/frenzymath/Danus/blob/7e244865968d3268b21c96b898c7af1f55d2f7c5/danus/core/factgraph.py#L124-L174)
rejects a revoked predecessor but does not require every predecessor to exist. A phantom ID can
therefore enter the graph.

### Tool visibility is not OS authority

The [role table](https://github.com/frenzymath/Danus/blob/7e244865968d3268b21c96b898c7af1f55d2f7c5/danus/gateway/roles.py#L23-L45)
is good capability-oriented UX: the main role lacks `fact_submit`, and an unknown role fails to a
read-only set. It is not an adversarial boundary. Workers and verifiers run Codex with sandbox and
approval bypass on a shared host. A process with shell access can edit fact files, import the
FactGraph directly, launch a gateway with `DANUS_ROLE=all`, or change verifier inputs. AutoLean must
retain OCI isolation, read-only dependencies, patch write scopes, leases, fencing, and separately
operated verification.

### Untrusted proof text shares the verifier instruction layer

The [verifier launcher](https://github.com/frenzymath/Danus/blob/7e244865968d3268b21c96b898c7af1f55d2f7c5/danus/verify/launcher.py#L145-L213)
interpolates untrusted statement and proof text into one natural-language command, then runs with
sandbox bypass. This creates prompt-injection and host-action risk. AutoLean model reviewers need
typed inputs, strict output schemas, no raw authority, and deterministic gates that override model
text.

### Accepted can mean state commit failed

Fact write and glossary update are separate file writes with no transaction or lock. If the second
write fails, the gateway can return `accepted=True`, `fact_id=None`, and a write error. Verification
success and durable state commit are different facts and must never share a terminal status.
AutoLean's WAL/CAS/lease/fence design already has the correct direction.

### Revocation is non-transactional

Cascade revocation repeatedly moves files and appends JSONL entries. A crash can leave a partially
revoked graph. AutoLean should derive stale descendants from append-only invalidation events and
create new revisions; it should not mutate or move accepted evidence in place.

### Content identity is too short and provenance is mutable

The [fact ID](https://github.com/frenzymath/Danus/blob/7e244865968d3268b21c96b898c7af1f55d2f7c5/danus/core/schema.py#L104-L130)
is only the first 16 hexadecimal characters of SHA-256. At the envisioned AutoLean scale, a full
digest is required and a short ID may only be a display alias.

The [external-reference update](https://github.com/frenzymath/Danus/blob/7e244865968d3268b21c96b898c7af1f55d2f7c5/danus/core/factgraph.py#L231-L252)
edits citations in place while leaving the fact ID unchanged. AutoLean should keep separate
mathematical-content and provenance/bibliography hashes, but every public artifact must bind both
revisions.

### Dashboard content is not safely rendered

The [Dashboard renderer](https://github.com/frenzymath/Danus/blob/7e244865968d3268b21c96b898c7af1f55d2f7c5/danus/observability/static/app.js#L4-L42)
defines `esc` as `String`, then uses Markdown/KaTeX output and `innerHTML`. The graph tooltip also
interpolates agent-controlled fields into HTML. Combined with CDN assets without a recorded
integrity policy, this is an operator-browser attack surface. AutoLean may borrow graph-depth and
supporting-closure visual language, but not the implementation.

## Absorb, isolate, reject

| Danus component | Decision | AutoLean location |
| --- | --- | --- |
| Fact-sized exploration and supporting closure | Reimplement | MathematicalGraph/FormalGraph candidate and closure projections |
| Local/global/verified memory discipline | Reimplement with a stronger truth definition | ContextPack and ExecutionGraph; global memory never becomes a proof premise |
| Strategy compression and work allocation | Reimplement as policy | Control-plane guidance artifact, no admission authority |
| Constructive/refutational/toy portfolios | Reimplement | Builder adversarial lane and conjecture quarantine |
| Cascade revocation | Reimplement as immutable invalidation | Contract revisions, append-only events, descendant re-verification |
| Fresh verifier and isolated writer | Reimplement as advisory roles | Machine semantic quorum and report/PR artifact checks |
| Matlas/theorem search | Isolated adapter only | Source-hash/rights/egress-bound retrieval evidence |
| Danus fact import | Isolated adapter only | `untrusted_research_hypothesis`, never FormalGraph truth |
| Worker skills | Role-by-role benchmark before use | Provider-neutral RoleSpec/ContextPack; no Claude dependency |
| Dashboard graph idiom | Design reference only | AutoLean read-only sanitized event projection |
| LLM verifier as sole write gate | Reject | Lean kernel plus independent replay |
| MCP role table as security boundary | Reject | OCI, capabilities, leases, fencing, and signing authority |
| Shared files, PID coordination, mutable revocation | Reject | SQLite WAL, CAS artifacts, immutable workspaces |
| 16-hex IDs and mutable citation identity | Reject | Full SHA-256 and separate provenance revision |
| Claude/Anthropic main, transport, or fallback | Reject | Violates AutoLean provider policy |
| Six case studies as a benchmark | Reject | Qualitative evidence only |

## Milestone placement

1. **Phase 1:** import no runtime. The audit findings are candidate adversarial fixtures for a
   later hardening increment after the first vertical closes; they are not a second active Phase 1
   task list. Any implementation must first be scheduled in
   [roadmap-next.md](../roadmap-next.md).
2. **Phase 2:** use constructive/refutational/toy roles only to propose non-frozen chapter
   candidates. Every candidate traverses the existing Builder fidelity path.
3. **Phase 3:** add supporting-closure projections, failure-route compression, and immutable
   descendant invalidation after several connected chapter slices exist.
4. **Phase 4:** compare ordinary scheduling with a strategy-compression worker portfolio on held-out
   known-theorem closures. Continue only if Lean-verified closure gain improves under fixed budget.
5. **Phase 5:** add an isolated informal research-scout adapter for blind reproof. Reject
   alias/original-proof contamination.
6. **Phase 6:** permit the scout to propose lemmas, counterexamples, and reductions in conjecture
   quarantine. Its outputs remain untrusted until Builder freeze and kernel verification.
7. **Phase 7:** use the scout for route discovery inside the Open Problem portfolio; use AutoLean
   Builder--Prover for every trusted mathematical asset.

## Verification boundary

The root agent independently read the pinned truth write gate, fact add/revoke paths, verifier
launcher and contract, role table, security document, content-ID function, mutable-reference path,
Dashboard rendering code, and the paper's methodology, matroid scope mismatch, verification, and
limitations sections.

This was a static source audit. The repository was not imported, installed, or executed. Its CI
only runs offline package tests, its optional dependencies are not locked, and no standard
benchmark or real long-running swarm receipt was found. Those limits do not affect the rejection of
Danus as an AutoLean authority: the cited code paths and the paper's own reported semantic failures
are sufficient.
