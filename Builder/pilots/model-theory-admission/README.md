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

The four coarse span bindings are copied from the tracked self-calibration pilot manifest. A
coarse span does not supply an offset or hash for a narrower rule locator. Every such narrower
binding remains `span_binding_state: missing` in the immutable matrix projection. The separate
fine-span attachment supplies machine candidates for review; it does not retroactively reinterpret
that matrix or close the decision's blocker.

The local V2 replay rehashes the retained implementation source, packet, and receipt and checks
their internal backlinks. It does not independently recompute the complete Library input tree or
query the claimed declarations inside the T4 image. A future versioned admission capability must
bind those checks before any candidate can enter statement drafting.

## Conditions To Close The Gap

T3 remains blocked until all of the following are recorded through the Builder authority path:

1. authorized visual and semantic review of every attached machine-located span, including
   reconciliation of the Section 7.5 and universal-right PDF/printed-page locators;
2. a rule-by-rule source review covering context shape, all side conditions, structural rules,
   cut, and the intentionally absent existential constructors;
3. an accepted account of the closed-sentence boundary, internal free-variable levels, fresh
   source constants, and capture-avoiding term instantiation;
4. an exact fragment name and scope that cannot be mistaken for full `LK`; and
5. a replay of the complete Library input tree plus T4 image queries binding every admitted
   declaration, canonical type, import closure, and `collectAxioms` result; and
6. an authenticated Builder decision that either admits this revision or records an immutable
   gap/backup decision.

Until then, this directory is evidence for keeping the gap open.
