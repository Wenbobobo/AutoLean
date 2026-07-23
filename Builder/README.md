# AutoLean Builder

`autolean-builder` owns statement fidelity. It turns reviewed source records into a frozen
`StatementContractV1` and an immutable `FormalizationTaskBundleV1`; it never invokes a model,
executes Lean, or accepts proof output.

The freeze gate requires source and rights review, resolved blocking ambiguity, independent
formalization candidates, reverse rendering, mutation evidence, and role-appropriate signoff.
A later statement change produces a new revision, never mutates a bundle already handed to the
Prover.

`ExperienceRetriever` supplies statement-conversion roles with deterministic, content-addressed
advisory context. It filters by role, domain, formal-graph frontier, exact rights scope, endpoint,
item budget, and token budget. Retrieved successes, failures, and gaps remain untrusted evidence;
they cannot edit a contract or satisfy a freeze gate. See
[`builder-experience-retrieval.md`](../docs/builder-experience-retrieval.md).

`StatementFidelityHarness` is the reviewed statement-conversion Harness. It binds private,
rights-scoped source excerpts, normalized mathematics, two or more independent candidates, reverse renderings,
semantic obligations, the required mutation suite, and an independent expert verdict into one
canonical evidence artifact. The internal freeze primitive accepts that complete evaluation
rather than caller-assembled Boolean checks.

`SourceToStatementHarness` is the provenance-safe textbook entrance to that path. It accepts only
manifest-typed derived UTF-8 text, an independently verified parent PDF, and exact byte spans
whose bytes equal each permitted excerpt. Parent-PDF page locators remain explicitly human
declarations. It creates a draft, delegates fidelity evaluation, and offers
`revalidate_and_freeze` so all source and complete rights-record bindings are checked immediately
before the local freeze gate. Every prepared revision is also inserted into a durable,
append-only SQLite CAS ledger; fidelity, freeze, and signed bridge operations reload that record
instead of trusting packet-local copies. `FreezeRecordV1` carries the preparation record's stable
ID and typed content digest, so the signed bundle commits the exact source-preparation evidence
that a protected signing service must reopen. The reference acquisition and offline replay
protocol are documented in
[`builder-reference-cache.md`](../docs/builder-reference-cache.md).

The public draft and frozen contract store only each span ID, locator, byte offsets, and excerpt
hash. Verbatim excerpts remain in the private preparation packet and fidelity artifact; the
Builder-to-Prover bundle carries only the typed fidelity-artifact reference.

Raw freeze and bridge primitives are no longer exported by `autolean_builder`; the supported
source-backed handoff is `SourceToStatementHarness.revalidate_freeze_and_bridge`. Python module
privacy and a writable local SQLite file are not authentication boundaries. A separate Builder
signing service must reopen the protected ledger, authenticate reviewer identities, and retain
KMS/HSM custody before a release can be promoted.

For V1 replay compatibility, an old standalone freeze record without a source-preparation pair
can still be parsed. The supported bridge and control-plane admission gate reject it; every new
handoff must carry both the preparation ID and digest.

See [the Harness protocol](../docs/builder-fidelity-harness.md) for the automatic-versus-expert
decision boundary and the remaining reviewer-authentication requirement. The proposed first
chapter-scale calibration is the rights-gated
[connection-curvature pilot](../docs/domain-pilot-selection.md). Source bytes remain in the ignored
local cache; only provenance and hash metadata are tracked.
