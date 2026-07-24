import Mathlib.ModelTheory.Semantics

/-!
Compile-only boundary probe for the structural/open-formula candidate in the
first-order model-theory Builder pilot.

The explicit `assignment` argument is intentional.  Unlike a sentence,
`Language.Formula` may have free variables; dropping this argument would
silently change the candidate's semantic boundary.
-/
namespace AutoLeanLibrary.Fixtures.ModelTheory

open FirstOrder
open FirstOrder.Language

variable {L : FirstOrder.Language} {M : Type*} [L.Structure M]
variable {α β : Type*}

/--
Free-variable substitution commutes with realization under the induced
assignment.  The target assignment is kept explicit, so the fixture cannot be
mistaken for a closed-sentence semantics adapter.
-/
theorem open_formula_substitution_boundary (formula : L.Formula α)
    (substitution : α → L.Term β) (assignment : β → M) :
    Formula.Realize (formula.subst substitution) assignment ↔
      Formula.Realize formula (fun freeVar => (substitution freeVar).realize assignment) := by
  simpa only [Formula.Realize] using
    (BoundedFormula.realize_subst (φ := formula) (tf := substitution) (v := assignment)
      (xs := default))

/-- Renaming free variables changes the assignment by precomposition. -/
theorem open_formula_relabel_assignment_boundary (formula : L.Formula α)
    (rename : α → β) (assignment : β → M) :
    (formula.relabel rename).Realize assignment ↔ formula.Realize (assignment ∘ rename) :=
  Formula.realize_relabel

end AutoLeanLibrary.Fixtures.ModelTheory
