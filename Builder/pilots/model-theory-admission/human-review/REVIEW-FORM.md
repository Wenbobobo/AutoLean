# T3 Model-Theory Advisory Review Form

This form records an advisory technical and semantic review. Completing it does not change
`decision.v2.json`, admit a candidate, freeze a statement, hand work to Prover, or authorize a
promotion.

## Bound Packet

- Packet ID: `model-theory-t3-human-review-v1`
- Packet SHA-256: `53eea20e92971ad6e47f1f244649604480d818f3645e97ab0d71a0afef19da6b`
- Decision canonical SHA-256:
  `f55db634b51ef31871fdbd3e1002979d09c610bcf5dc7540ffef9d26c9f0f2a5`
- Review effect: `advisory_only`

Use `response.template.v1.json` as the machine-readable response shape. Do not paste textbook
excerpts, screenshots, local paths, prompts, credentials, or raw model output into a tracked
response. Record page numbers, verdicts, concise paraphrases, and artifact identifiers only.

## Verdict Vocabulary

Visual locator:

- `confirmed`
- `needs_correction`
- `rejected`
- `insufficient_context`

Semantic fidelity:

- `supports`
- `supports_with_scope_change`
- `contradicts`
- `insufficient_evidence`

Use `pending` only for an unanswered item. A visual `confirmed` verdict never implies semantic
`supports`. `insufficient_context` and `insufficient_evidence` mean that the item was reviewed but
the retained evidence was not sufficient.

## Span Review

Give both verdicts for every row.

| Span ID | Visual locator verdict | Semantic fidelity verdict | Notes |
| --- | --- | --- | --- |
| `free-bound-occurrences-and-sentences` |  |  |  |
| `capture-avoiding-substitution-and-free-for` |  |  |  |
| `open-formula-satisfaction-and-assignment-update` |  |  |  |
| `sentence-satisfaction-assignment-independence` |  |  |  |
| `semantic-substitution` |  |  |  |
| `closed-term-quantifier-instances` |  |  |  |
| `closed-sequent-boundary` |  |  |  |
| `lk-rule-inventory-and-side-conditions` |  |  |  |
| `lk-validity-and-soundness-statement` |  |  |  |
| `lk-validity-and-soundness-universal-right-case` |  |  |  |

When a locator needs correction, fill the structured `locator_correction` object in the JSON
response: corrected UTF-8 start/end offsets and raw SHA-256, PDF page in both one-based and
zero-based coordinates, printed page label, and the local view's page-render SHA-256. Leave these
fields null when no correction is proposed.

## Page-Pair Ambiguities

Allowed verdicts are `page_pair_confirmed`, `page_pair_corrected`, and `unresolved`.

The packet records the unconfirmed source claims separately from the reviewer response. The
derived-text spans map across PDF pages 147-148 and 207-208 respectively; the local view binds
the render hash of the claimed page while retaining the full range.

| Ambiguity ID | Unconfirmed claim | Verdict | PDF page, 1-based | PDF page, 0-based | Printed label | Render SHA-256 | Label-region SHA-256 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `section-7-5-page-pair-unreconciled` | PDF 148 / printed 127 |  |  |  |  |  |  |
| `universal-right-page-pair-unreconciled` | PDF 208 / printed 187 |  |  |  |  |  |  |

## Fragment Name And Scope

Choose one:

- `accept_exact_scope`
- `revise_name_or_scope`
- `reject_candidate_scope`

Record an exact proposed name. Confirm whether it excludes existential constructors,
sequent-level structural rules and cut, connectives outside bottom/implication/universal
quantification, full LK, and completeness.

## Fin n And Freshness

For each question choose `supports`, `supports_with_scope_change`, `contradicts`, or
`insufficient_evidence`.

1. Does the internal `Fin n` representation preserve the intended closed-term and free-for
   boundary?
2. Does the fresh `Fin.last` level preserve the intended fresh-symbol side condition for
   universal-right?

These are separate verdicts. Agreement on one does not imply agreement on the other.

## Init And Axiom Policy

For `Init`, choose one:

- `treat_init_as_implicit`
- `require_init_in_allowlist`
- `reject_profile`

For the observed axiom set, choose one:

- `accept_exact_observed_set`
- `require_axiom_reduction`
- `reject_profile`

The observed set is `Classical.choice`, `Quot.sound`, and `propext`. Accepting it recommends a
new formal-profile revision; it does not rewrite the immutable V2 decision.

## Overall Recommendation

Choose one:

- `retain_gap`
- `revise_candidate`
- `select_backup`
- `recommend_admission_review`

State the remaining blockers and a concise rationale. `recommend_admission_review` means that a
separate authenticated Builder authority process may begin; it is not an admission.

## Public-Safety Confirmation

Before returning a tracked response, confirm that it contains no textbook excerpt, source image,
local path, prompt, raw model output, or credential. All authority fields remain `false`.
