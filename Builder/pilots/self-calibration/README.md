# Builder Self-Calibration Records

This directory holds public-safe, immutable decision records for early Builder design work.
They are intentionally not statement contracts, rights decisions, model prompts, proof tasks, or
Library promotion records. Free-text findings are context only: they are not evidence of human or
expert review, an open-problem result, model permission, or promotion.

`round-01.v1.json` binds two first-order soundness boundary candidates to the current pilot
manifest, target closure, textbook-anchor identifiers, rights-evidence identifiers, and pinned
`Library` lock and the tracked reference manifest. Its four retained role reports are from
automated agents: the closed-only and the structural/open-formula candidates each have one
formal-architect report and one adversarial report, from separately declared but untrusted
independence groups. No human or domain-expert review is recorded.

The round is deliberately `incomplete`. It records its unresolved source-interpreter,
research-alignment, and Library-steward reports; a locally self-reported
`partial_passed_with_gap` Library spike; the source-entry and Mathlib-census reviews; and the
absence of human/expert review as machine-readable blockers. The spike binds the recorded build
input tree, lock, toolchain, targets, exit status, and public-safe build-report checksum through the
tracked `Library/records/staging/round-01-model-theory-compile-spike/` packet and receipt. Loading
the record recomputes the Library v2 input closure and cross-checks both raw-record and canonical
content digests. `UniversalLK` is the technical implementation of the existing
structural/open-formula candidate, not a third candidate. Its bounded `⊥`, `→`, and `∀`
micro-slice implements the quantifier-freshness bridge with weakening, capture-avoiding
instantiation, eigenvariable-safe rules, and soundness. That technical micro-slice is complete;
independent source-fidelity review and Builder admission remain active gaps. The round therefore
remains `partial_passed_with_gap` and `incomplete`; neither candidate is selected or frozen.

The public-safe
[quantifier-boundary reconciliation](quantifier-boundary-2026-07-24.md) records a later pair of
independent automated research inputs. It resolves one design ambiguity: the textbook theorem
boundary is closed, while a level-indexed open layer is still required internally to encode
substitution and eigenvariable freshness. `UniversalLK` implements that refinement for the
existing structural/open-formula candidate, but it does not fill the round's authenticated role
reports, establish source fidelity, issue Builder admission, select or freeze a candidate, or
remove the human-review blocker.

Every candidate, role report, compile-spike packet, and round has a canonical SHA-256 integrity
checksum. A checksum detects accidental or unsynchronized edits; it is not a signature, an
identity proof, independence evidence, or authority. `load_self_calibration_round` rebinds the
record to both `pilot-manifest.v1.json` and `Builder/references/manifest.v1.json`, including the
source derivation and rights metadata, before exposing it.

A `complete` round is fail-closed. It needs every role report in `verified` state, no active
blocker, a passed compile spike with structured Library input/lock/toolchain/target/exit evidence,
and external identity and run-receipt verifiers. The current round is only `incomplete`, so its
self-reported independence groups and partial Library spike cannot be promoted by changing text or
state fields.

The schema hard-codes a forbidden authority boundary. A self-calibration record cannot issue a
pilot admission receipt, freeze a Builder statement, hand work to Prover, authorize model egress,
or promote a Library asset. Those operations remain available only through their dedicated,
rights-aware and kernel-verification workflows.
