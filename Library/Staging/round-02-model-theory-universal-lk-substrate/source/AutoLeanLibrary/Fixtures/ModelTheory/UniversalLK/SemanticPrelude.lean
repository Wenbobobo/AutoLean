import AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Core

/-!
# Target-free UniversalLK semantic prelude

This module preserves the historical declaration surface for realization,
explicit open assignments, and closed-side adapters.  It contains no global
derivation soundness theorem.
-/
namespace AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK

open FirstOrder
open FirstOrder.Language

universe u v

section Semantics

variable {L : FirstOrder.Language} {M : Type u} [L.Structure M]
variable {n : Nat}

theorem wk_realize (φ : Fml L n) (assignment : Fin (n + 1) → M) :
    (wk φ).Realize assignment ↔ φ.Realize (assignment ∘ Fin.castSucc) := by
  simp [wk]

theorem openLast_realize (body : Body L n) (assignment : Fin (n + 1) → M) :
    (openLast body).Realize assignment ↔
      body.Realize (assignment ∘ Fin.castSucc) (fun _ => assignment (Fin.last n)) := by
  simp [openLast, eigenExtend, Function.comp_def, BoundedFormula.realize_toFormula]

theorem inst0_realize (body : Body L n) (term : L.Term (Fin n))
    (assignment : Fin n → M) :
    Formula.Realize (inst0 body term) assignment ↔
      body.Realize assignment (fun _ => term.realize assignment) := by
  calc
    Formula.Realize (inst0 body term) assignment ↔
        Formula.Realize body.toFormula
          (fun freeVar =>
            (Sum.elim Term.var (fun _ => term) freeVar).realize assignment) := by
      change
        BoundedFormula.Realize
            (body.toFormula.subst (Sum.elim Term.var fun _ => term))
            assignment default ↔
          BoundedFormula.Realize body.toFormula
            (fun freeVar =>
              (Sum.elim Term.var (fun _ => term) freeVar).realize assignment)
            default
      exact BoundedFormula.realize_subst
    _ ↔ body.Realize assignment (fun _ => term.realize assignment) := by
      rw [BoundedFormula.realize_toFormula]
      simp [Function.comp_def]

theorem all_realize (body : Body L n) (assignment : Fin n → M) :
    Formula.Realize body.all assignment ↔
      ∀ value : M, body.Realize assignment (fun _ => value) := by
  rw [Formula.Realize, BoundedFormula.realize_all]
  apply forall_congr'
  intro value
  have bound_assignment :
      Fin.snoc (default : Fin 0 → M) value = (fun _ : Fin 1 => value) := by
    funext i
    rw [show i = 0 from Fin.eq_zero i]
    exact Fin.snoc_last _ _
  rw [bound_assignment]

namespace Side

/-- Every antecedent formula is true under the explicit open assignment. -/
def AllRealize (assignment : Fin n → M) : Side L n → Prop
  | [] => True
  | φ :: Γ => φ.Realize assignment ∧ AllRealize assignment Γ

/-- At least one succedent formula is true under the explicit open assignment. -/
def AnyRealize (assignment : Fin n → M) : Side L n → Prop
  | [] => False
  | φ :: Δ => φ.Realize assignment ∨ AnyRealize assignment Δ

@[simp]
theorem allRealize_nil (assignment : Fin n → M) : AllRealize assignment ([] : Side L n) :=
  trivial

@[simp]
theorem allRealize_cons (assignment : Fin n → M) (φ : Fml L n) (Γ : Side L n) :
    AllRealize assignment (φ :: Γ) ↔
      φ.Realize assignment ∧ AllRealize assignment Γ :=
  Iff.rfl

@[simp]
theorem anyRealize_nil (assignment : Fin n → M) :
    ¬AnyRealize assignment ([] : Side L n) :=
  not_false

@[simp]
theorem anyRealize_cons (assignment : Fin n → M) (φ : Fml L n) (Δ : Side L n) :
    AnyRealize assignment (φ :: Δ) ↔
      φ.Realize assignment ∨ AnyRealize assignment Δ :=
  Iff.rfl

theorem wkCtx_allRealize (Γ : Side L n) (assignment : Fin (n + 1) → M) :
    AllRealize assignment (wkCtx Γ) ↔
      AllRealize (assignment ∘ Fin.castSucc) Γ := by
  induction Γ with
  | nil => rfl
  | cons φ Γ ih =>
      change
        (wk φ).Realize assignment ∧ AllRealize assignment (wkCtx Γ) ↔
          φ.Realize (assignment ∘ Fin.castSucc) ∧
            AllRealize (assignment ∘ Fin.castSucc) Γ
      rw [wk_realize, ih]

theorem wkCtx_anyRealize (Δ : Side L n) (assignment : Fin (n + 1) → M) :
    AnyRealize assignment (wkCtx Δ) ↔
      AnyRealize (assignment ∘ Fin.castSucc) Δ := by
  induction Δ with
  | nil => rfl
  | cons φ Δ ih =>
      change
        (wk φ).Realize assignment ∨ AnyRealize assignment (wkCtx Δ) ↔
          φ.Realize (assignment ∘ Fin.castSucc) ∨
            AnyRealize (assignment ∘ Fin.castSucc) Δ
      rw [wk_realize, ih]

end Side

/-- Two-sided sequent semantics in a fixed structure, with no default open assignment. -/
def ValidIn (M : Type u) [L.Structure M] (Γ Δ : Side L n) : Prop :=
  ∀ assignment : Fin n → M,
    Side.AllRealize assignment Γ → Side.AnyRealize assignment Δ

end Semantics

section ClosedBridge

variable {L : FirstOrder.Language} {M : Type u} [L.Structure M]

/-- The only public statement adapter in this spike: level-zero formulas become sentences. -/
def close (φ : Fml L 0) : L.Sentence :=
  φ.relabel Fin.elim0

theorem close_realize (φ : Fml L 0) (assignment : Fin 0 → M) :
    M ⊨ close φ ↔ φ.Realize assignment := by
  rw [close, Sentence.Realize, Formula.realize_relabel]
  have assignments_equal : (default : Empty → M) ∘ Fin.elim0 = assignment :=
    Subsingleton.elim _ _
  rw [assignments_equal]

theorem close_sequent_realize (Γ Δ : Side L 0) :
    ValidIn M Γ Δ ↔
      (Side.AllRealize (Fin.elim0 : Fin 0 → M) Γ →
        Side.AnyRealize (Fin.elim0 : Fin 0 → M) Δ) := by
  constructor
  · intro valid
    exact valid (Fin.elim0 : Fin 0 → M)
  · intro valid assignment
    have assignments_equal : assignment = (Fin.elim0 : Fin 0 → M) :=
      Subsingleton.elim _ _
    simpa [assignments_equal] using valid

/-- Every source-boundary antecedent is realized as a closed sentence. -/
def ClosedAll (M : Type u) [L.Structure M] : Side L 0 → Prop
  | [] => True
  | φ :: Γ => M ⊨ close φ ∧ ClosedAll M Γ

/-- Some source-boundary succedent is realized as a closed sentence. -/
def ClosedAny (M : Type u) [L.Structure M] : Side L 0 → Prop
  | [] => False
  | φ :: Δ => M ⊨ close φ ∨ ClosedAny M Δ

theorem closedAll_iff (Γ : Side L 0) :
    ClosedAll M Γ ↔ Side.AllRealize (Fin.elim0 : Fin 0 → M) Γ := by
  induction Γ with
  | nil => rfl
  | cons φ Γ ih =>
      change
        (M ⊨ close φ ∧ ClosedAll M Γ) ↔
          Formula.Realize φ Fin.elim0 ∧
            Side.AllRealize (Fin.elim0 : Fin 0 → M) Γ
      rw [close_realize φ Fin.elim0, ih]

theorem closedAny_iff (Δ : Side L 0) :
    ClosedAny M Δ ↔ Side.AnyRealize (Fin.elim0 : Fin 0 → M) Δ := by
  induction Δ with
  | nil => rfl
  | cons φ Δ ih =>
      change
        (M ⊨ close φ ∨ ClosedAny M Δ) ↔
          Formula.Realize φ Fin.elim0 ∨
            Side.AnyRealize (Fin.elim0 : Fin 0 → M) Δ
      rw [close_realize φ Fin.elim0, ih]

end ClosedBridge

end AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK
