# AutoLean Builder

`autolean-builder` owns statement fidelity. It turns reviewed source records into a frozen
`StatementContractV1` and an immutable `FormalizationTaskBundleV1`. Before freeze, its fidelity
Harness may ask an injected, fixed-environment Lean query adapter to elaborate the selected
statement and independently generated candidates, but it never accepts proof output or treats
that type observation as proof verification. The current scripted and local-OCI query assurances
are both non-authoritative; the supported source-backed freeze path rejects them unless an
explicit test-only switch is enabled.

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
rights-scoped source excerpts, normalized mathematics, two or more independent candidates,
fresh canonical-type observations, reverse renderings, semantic obligations, the required
mutation suite, and an independent expert verdict into one canonical evidence artifact. Canonical
type identity here means exact printer-text identity in one pinned environment; it is not a claim
of definitional or semantic equivalence. The internal freeze primitive accepts that complete
evaluation rather than caller-assembled Boolean checks.

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
The companion BuilderStatementObservationEvidence record standardizes the selected-statement
canonical-type observation for Builder/Prover audits, but it is deliberately marked non-proof and
ineligible for ProofSubmissionV1.

The textbook-alignment discovery writer is intentionally narrower than a general artifact store.
It accepts only the repository root, requires a real `.git` marker and an active root
`/.cache/` ignore rule, and requires `.cache` plus each output parent to exist as real confined
directories before the run. It records directory identities around each write, treats identical
existing bytes as an idempotent replay, and refuses a different-content conflict without
overwriting either output. This protects against accidental publication and path substitution; it
is not an isolation boundary against a malicious process running as the same local user.
Production private packets belong on a separate operator-owned volume with access control and
retention policy outside this discovery harness.

Raw freeze and bridge primitives are no longer exported by `autolean_builder`; the supported
source-backed handoff is `SourceToStatementHarness.revalidate_freeze_and_bridge`. Python module
privacy and a writable local SQLite file are not authentication boundaries. A separate Builder
signing service must reopen the protected ledger, authenticate reviewer identities, and retain
KMS/HSM custody before a release can be promoted.

For V1 replay compatibility, an old standalone freeze record without a source-preparation pair
can still be parsed. The supported bridge and control-plane admission gate reject it; every new
handoff must carry both the preparation ID and digest.

See [the Harness protocol](../docs/builder-fidelity-harness.md) for the automatic-versus-expert
decision boundary and the remaining reviewer-authentication requirement. The versioned
[`self-calibration pilot manifest`](pilots/self-calibration/pilot-manifest.v1.json) keeps source,
current-mathlib, counterexample, and human-review gates separate from statement contracts. The
connection-curvature graph is reference-only because an active upstream overlap blocks admission;
its three alternatives remain conditional until their individual gates pass. Source bytes remain
in the ignored local cache; only provenance and hash metadata are tracked.

The adjacent [`self-calibration rounds`](pilots/self-calibration/README.md) are a narrower,
public-safe design record: they bind candidate revisions, source anchors, rights-evidence
metadata, role reports, blockers, and the pinned Library lock. Self-reported role independence
and SHA-256 checksums are explicitly untrusted until a future external identity/run verifier
accepts them. They cannot issue a pilot-admission receipt, freeze a Builder contract, authorize
model egress, hand off work to Prover, or promote a Library asset.

The [`project-synthetic pre-calibration fixture`](pilots/local-calibration/README.md) is an even
earlier, deliberately non-authoritative Phase-2 preparation surface. Its ten PDE-A and MG-A
fixtures were generated for this repository and bind exact source spans to the root Apache-2.0
license and an adjacent corpus/renderer hash manifest. Human content review remains pending; no
human authorship or legal-review claim is made. Each `pre_calibration_fixture` record contains
normalization sketches, unparsed illustrative Lean-like text, reverse renderings, examples, and
declared synthetic mutation fixtures. It neither binds normalized mathematics to Lean nor claims
that a semantic checker executed. Real candidates are reserved for `StatementFidelityHarness`.
The fixture permits redistribution only of its exact bound bytes, denies model egress, and sets
production ingestion, rights clearance, promotion, freeze, and Prover handoff to `false`. It does
not satisfy the roadmap's rights-cleared `local_calibration` state.

When a round records a `partial_passed_with_gap` Library preselection spike, it references the
tracked public-safe packet and compile receipt by repository-relative path and content digest.
Loading that round revalidates the exact Library v2 build-input closure, pinned environment,
targets, canonical build report, packet backlink, open gap, and `not_selected` state. This is API
compatibility evidence only; it cannot select a candidate or replace Builder fidelity review.
