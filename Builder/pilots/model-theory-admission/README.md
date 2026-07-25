# Model Theory T3 Boundary Record

## Disposition

This directory is a public-safe record of an unresolved Builder boundary. It does not admit or
select a candidate.

- Candidate: `model-theory-closed-level-indexed-fragment`
- Candidate revision: `t3-boundary-v2`
- T3 disposition: `gap`
- Selection disposition: `not_selected`

The implementation evidence covers a level-indexed, two-sided fragment with bottom, implication,
and universal quantification. It does not cover full `LK`, structural rules, or existential rule
constructors. Lean compilation and soundness establish properties of the implemented inductive
calculus only; they do not establish fidelity to the source calculus.

## Public-Safe Contents

[`decision.v2.json`](decision.v2.json) is the replayable V2 gap decision. It binds the current
pilot manifest, graph and target closure; the inline candidate revision; the retained T2 source,
packet, receipt and build evidence; and the test-only T4 mathlib worker profile. Its strict axiom
profile deliberately has no declaration-specific axiom evidence. The V2 schema is internal,
replay-only, and represents `gap` or `backup`; it exposes no admission receipt or statement-drafting
capability.

[`review-evidence.v2.json`](review-evidence.v2.json) retains only public-safe structured
subobjects for the source-interpreter and adversarial automated-agent reports. The decision binds
canonical hashes of each report's context, output and untrusted run receipt. Neither record claims
human or expert identity, authenticated independence, or operator authority.

[`source-rule-matrix.v2.json`](source-rule-matrix.v2.json) contains:

- whole-artifact hashes for the locked PDF, derived text, and reference manifest;
- the four previously retained coarse source spans;
- fine-grained locators whose offsets and hashes remain explicitly missing;
- declaration-level mappings to `UniversalLK`; and
- the current gap and non-authority boundaries.

It contains no textbook excerpt, local cache path, prompt, model output, or private review
material. The locators paraphrase the purpose of a source location; they are not quotations.

[`fine-source-spans.v2.json`](fine-source-spans.v2.json) is a separate, digest-only attachment to
the unchanged gap decision and source-rule matrix. It records ten machine-located byte spans
against the manifest-v2 `pypdf 6.14.2` text revision, covering all nine fine-anchor requirements;
the soundness requirement is split between its statement and universal-right proof case. Every
span remains `machine_located_pending_review`. The attachment explicitly preserves unresolved
PDF/printed-page ambiguity for Section 7.5 and the universal-right case, contains no source
excerpt or cache path, and has no authority to change the decision, freeze a statement, or hand
work to Prover.

[`t4-declaration-query.v1.json`](t4-declaration-query.v1.json) is the byte-exact public copy of
the image-owned query result for the retained `UniversalLK` source. It retains all 46 canonical
declaration types and `collectAxioms` results, the two direct imports, and the complete 2,744-module
import closure. [`t4-exact-image-attachment.v1.json`](t4-exact-image-attachment.v1.json) binds that
artifact to the unchanged gap decision, source snapshot, sealed `Candidate.olean`, exact source-v2
image, canonical image receipt, and operator-local build and canary digests.

The query is technical evidence for keeping the gap open, not a replacement decision. The exact
source-v2 image differs from the source-v1 image recorded in `decision.v2.json`; the observed
direct imports include `Init`; and 41 declarations use at least one axiom while the decision's
formal profile is strict with an empty allowlist. In particular, `Deriv.closed_sound` uses
`Classical.choice`, `Quot.sound`, and `propext`. Those differences require an explicit future
formal-profile revision and cannot be normalized away by this attachment.
The attachment closes only the earlier absence of declaration-specific technical evidence; it
does not close any semantic, authority, formal-profile, or admission blocker.

[`pending-review.md`](pending-review.md) lists only the confirmations still required from
authorized reviewers. None of these records is a human or expert review, a Builder admission
receipt, a statement contract, a freeze, a Prover handoff, a promotion record, or evidence of
progress on an open problem.

## Verification

The matrix is bound to these observed values:

| Artifact | SHA-256 |
| --- | --- |
| Open Logic Project source PDF | `39081a7e3cade6b9d6935e15448fd14279b44708c1a8da2abd30ff817c4a35d9` |
| Manifest-bound derived text | `285655b3e8937e37215bb51b69eff6eb10cd9a5d64c54d8f1f4ddfb5175fc584` |
| Reference manifest | `9f6fc30c5bac7d3625938d6b4dae166270ef0f34c21db603be12c86d5bfd42ab` |
| Manifest-v2 derived text (`pypdf 6.14.2`) | `6184495568a4487848e747f25385cb4081be1cd87f77488c9de0046d600cfa6d` |
| Reference manifest v2 | `b947a08ef2455beb77d9481c4cbddc481ec6590f03746fd22affb03dd8b06f91` |
| Gap decision canonical payload | `f55db634b51ef31871fdbd3e1002979d09c610bcf5dc7540ffef9d26c9f0f2a5` |
| T4 declaration-query artifact | `167d7a1ede245bfa631c46651b5eb0502d758b8d966d6f4c494fdcb2d75df42a` |
| Exact source-v2 image digest | `3237192cf627a05367c75d46e61ec9034fefe43a4fd0c06139e38c80358648d6` |
| Canonical source-v2 image receipt | `40e15776cec80a03b9d5b0affd59a3f613b7f1855c48aa0c1e91f24ec0e1eed7` |

The four coarse span bindings are copied from the tracked self-calibration pilot manifest. A
coarse span does not supply an offset or hash for a narrower rule locator. Every such narrower
binding remains `span_binding_state: missing` in the immutable matrix projection. The separate
fine-span attachment supplies machine candidates for review; it does not retroactively reinterpret
that matrix or close the decision's blocker.

The tracked T4 replay rehashes the complete query artifact, every canonical type and axiom list,
the direct imports and import closure, and the retained implementation source. It also proves that
the 46 queried names exactly equal the decision's declaration set. The raw build and canary files
remain ignored operator-local diagnostics; their bound digests are not public build artifacts or
production attestations. The attachment does not make the exact image publicly retrievable,
independently rerun the build, or recompute the complete Library input tree.

## Conditions To Close The Gap

T3 remains blocked until all of the following are recorded through the Builder authority path:

1. authorized visual and semantic review of every attached machine-located span, including
   reconciliation of the Section 7.5 and universal-right PDF/printed-page locators;
2. a rule-by-rule source review covering context shape, all side conditions, structural rules,
   cut, and the intentionally absent existential constructors;
3. an accepted account of the closed-sentence boundary, internal free-variable levels, fresh
   source constants, and capture-avoiding term instantiation;
4. an exact fragment name and scope that cannot be mistaken for full `LK`; and
5. an explicit successor formal profile that binds its exact image, resolves how `Init` is treated,
   selects an axiom policy consistent with its declarations, and replays the complete Library
   input tree; and
6. an authenticated Builder decision that either admits this revision or records an immutable
   gap/backup decision.

Until then, this directory is evidence for keeping the gap open.
