# Quantifier Boundary Reconciliation

Status: automated research input; no candidate selected

Date: 2026-07-24

## Decision

The original binary choice is underspecified. A closed theorem boundary is faithful to the
textbook's classical `LK` sequents, but it does not remove the open-formula substitution and
eigenvariable machinery used to justify the quantifier rules. Conversely, an open-formula
calculus is useful implementation machinery, but it is not the textbook's stated object-level
sequent system.

The next implementation spike therefore evaluates one refined candidate:

> **Closed theorem boundary with level-indexed internal sequents.** Derivations use
> `Formula (Fin n)` internally so that an eigenvariable occupies the new level
> `Fin.last n`; both old sequent sides are lifted through `Fin.castSucc`. The public soundness
> theorem is stated only at `n = 0` and explicitly bridges `Formula (Fin 0)` to
> `Language.Sentence`.

This is a direction for T2, not a Builder admission, contract freeze, fidelity decision, or human
review. The existing `model-theory-closed-only` candidate omits required quantifier hygiene. The
existing `model-theory-structural-open-formula` candidate does not yet bridge its internal open
semantics back to the textbook's closed sequents. Neither is selected.

## Source identity

- Source: Open Logic Project, *Sets, Logic, Computation*, screen version 2026-07-12,
  CC BY 4.0.
- Source record: `openlogic-sets-logic-computation-2026-07-12-pdf`.
- PDF SHA-256:
  `39081a7e3cade6b9d6935e15448fd14279b44708c1a8da2abd30ff817c4a35d9`.
- Derived-text record: `openlogic-sets-logic-computation-2026-07-12-text`.
- Derived-text SHA-256:
  `285655b3e8937e37215bb51b69eff6eb10cd9a5d64c54d8f1f4ddfb5175fc584`.
- Reference-manifest SHA-256:
  `9f6fc30c5bac7d3625938d6b4dae166270ef0f34c21db603be12c86d5bfd42ab`.
- Egress policy: local only.

No source passage or local cache path is retained in this record.

## Source anchors

The pilot starts from the definitions needed by the theorem, not only from the later soundness
statement. Physical PDF pages and printed pages are both retained so another reviewer can
reproduce the interpretation.

| Requirement | Textbook anchor |
| --- | --- |
| Free and bound occurrences; sentences | Section 6.8, Definitions 6.33--6.37, PDF 128--129 / printed 107--108 |
| Capture-avoiding substitution and free-for condition | Section 6.9, Definitions 6.38--6.41, PDF 130--131 / printed 109--110 |
| Open-formula satisfaction and assignment update | Section 7.4, Definitions 7.7--7.11, PDF 139--141 / printed 118--120 |
| Sentence satisfaction is assignment-independent | Section 7.5, Corollary 7.15 and Definitions 7.16--7.17, PDF 148 / printed 127 |
| Semantic substitution | Proposition 7.23, PDF 150 / printed 129 |
| Closed-term quantifier instances | Proposition 7.31, PDF 153 / printed 132 |
| Sequents are sequences of sentences | Section 10.1, Definition 10.1, PDF 183 / printed 162 |
| `LK` quantifier rules and side conditions | Section 10.3, PDF 185--186 / printed 164--165 |
| `LK` validity and soundness | Definition 10.27 and Theorem 10.28, PDF 204 / printed 183; universal-right case at PDF 208 / printed 187 |

## Mathematical boundary

The source supports all of the following simultaneously:

1. The object-level `LK` antecedent and succedent contain closed sentences.
2. Substitution replaces only free occurrences and must avoid capture.
3. The witness in universal-left and existential-right is a closed term.
4. The eigenconstant in universal-right and existential-left is absent from the entire lower
   sequent, not merely from the principal formula.
5. The soundness proof for an eigenvariable rule depends on reinterpreting a genuinely fresh
   symbol; sentence semantics alone does not make that obligation disappear.

The refined representation preserves the closed external boundary while making freshness
structural:

```lean
abbrev Fml (L : Language) (n : Nat) := L.Formula (Fin n)
abbrev Body (L : Language) (n : Nat) := L.BoundedFormula (Fin n) 1
abbrev Side (L : Language) (n : Nat) := List (Fml L n)

inductive Deriv (L : Language) :
    (n : Nat) -> Side L n -> Side L n -> Prop
```

For universal-right, the premise has level `n + 1`. Both old sides are relabelled through
`Fin.castSucc`, and the opened body uses `Fin.last n`. Therefore the new variable cannot occur in
either old side by construction. Universal-left instantiates the body through mathlib's
capture-avoiding substitution. The first spike is the classical `LK` fragment with falsity,
implication, and universal quantification; it must be named as a fragment rather than as complete
`LK`. Existential rules may follow using the same hygiene layer.

## Required Lean evidence

The implementation spike is accepted only if all of the following hold under the pinned Library
lock:

1. `wk_realize` and two-sided `wkCtx_realize`.
2. `openLast_realize`, with `Fin.last n` denoting the opened binder.
3. `inst0_realize`, using capture-avoiding substitution rather than textual replacement.
4. Two-sided sequent semantics: all antecedents true implies at least one succedent true.
5. Local soundness for identity, falsity-left, implication-left/right, and
   universal-left/right.
6. `Deriv.sound` for arbitrary `n`.
7. An explicit realization-preserving bridge from `Formula (Fin 0)` to `Language.Sentence`.
8. A clean build with no `sorry`, new axiom, or default assignment in the open layer.

The three highest-risk API points are binder direction in `toFormula`/`subst`, the non-definitional
`Fin 0` to `Empty` bridge, and consistent relabelling of both sequent sides.

## Rejection controls

At minimum, the spike must retain controls for:

- replacing bound occurrences as though they were free;
- capture during substitution;
- universal-right when the eigenvariable remains in the antecedent;
- existential-left when the eigenvariable remains in the lower sequent;
- interpreting an open formula without an explicit assignment;
- accepting an arbitrary `Formula (Fin (n + 1))`, rather than the precise opened body, as the
  universal-right premise; and
- applying a non-injective relabelling that merges an old variable with `Fin.last n`.

The universal-right and existential-left controls require a concrete two-element countermodel or
an equivalent kernel-checked unsoundness witness. A failed control is a retained gap, never a
reason to weaken the advertised theorem.

## Remaining authority gap

The source interpretation and Lean architecture inputs were produced by independent automated
roles. They are attributable research notes, not authenticated independence, a named semantic
reviewer, or domain-expert approval. Before T3 admission, an independent reviewer must confirm the
source anchors, the closed/open bridge, the exact fragment name, and every rule side condition.

This pilot is useful to the open-problem north star because quantifier hygiene and faithful
statement boundaries recur across future domains. It does not establish progress on an open
problem, and that relevance cannot substitute for source fidelity or kernel verification.
