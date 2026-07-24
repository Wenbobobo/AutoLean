import Mathlib.ModelTheory.Semantics

/-!
Compile-only boundary probe for the closed-sentence candidate in the first-order
model-theory Builder pilot.

This module deliberately uses Mathlib's `Language.Sentence` API.  It does not
define a calculus, claim soundness, or introduce an assignment parameter: a
sentence has no free-variable assignment at this boundary.
-/
namespace AutoLeanLibrary.Fixtures.ModelTheory

open FirstOrder
open FirstOrder.Language

variable {L L' : FirstOrder.Language} {M : Type*} [L.Structure M] [L'.Structure M]

/--
Semantic transport for a closed sentence along a language expansion.  This is
an adapter to Mathlib's public sentence-realization theorem, not a new
mathematical result.
-/
theorem closed_sentence_expansion_boundary (hom : L →ᴸ L') [hom.IsExpansionOn M]
    (sentence : L.Sentence) : M ⊨ hom.onSentence sentence ↔ M ⊨ sentence :=
  hom.realize_onSentence M sentence

/-- A closed sentence's negation is evaluated without a free-variable valuation. -/
theorem closed_sentence_negation_boundary (sentence : L.Sentence) :
    M ⊨ sentence.not ↔ ¬M ⊨ sentence :=
  Sentence.realize_not M

end AutoLeanLibrary.Fixtures.ModelTheory
