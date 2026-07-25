import Mathlib.ModelTheory.Semantics

/-!
# Target-free UniversalLK substrate core

This is a staged source split of the retained historical fixture.  Declaration
names, namespaces, and parameter names intentionally match that fixture so a
later isolated declaration query can compare canonical types without source
renaming.  The old aggregate module is not imported and is not part of either
runtime profile.

This core has representation, variable operations, and rule constructors only.
It contains neither `Deriv.sound` nor `Deriv.closed_sound`.
-/
namespace AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK

open FirstOrder
open FirstOrder.Language

universe u v

abbrev Fml (L : FirstOrder.Language) (n : Nat) := L.Formula (Fin n)

abbrev Body (L : FirstOrder.Language) (n : Nat) := L.BoundedFormula (Fin n) 1

abbrev Side (L : FirstOrder.Language) (n : Nat) := List (Fml L n)

/-- The disjoint old/new variable map used by universal-right. -/
def eigenExtend {n : Nat} : Fin n ⊕ Fin 1 → Fin (n + 1) :=
  Sum.elim Fin.castSucc fun _ => Fin.last n

@[simp]
theorem eigenExtend_inl {n : Nat} (i : Fin n) :
    eigenExtend (Sum.inl i) = Fin.castSucc i :=
  rfl

@[simp]
theorem eigenExtend_inr {n : Nat} (i : Fin 1) :
    eigenExtend (Sum.inr i) = Fin.last n :=
  rfl

/-- The fixed opening map cannot merge an old variable with the new one. -/
theorem eigenExtend_injective {n : Nat} : Function.Injective (@eigenExtend n) := by
  intro a b equality
  rcases a with a | a <;> rcases b with b | b
  · change Fin.castSucc a = Fin.castSucc b at equality
    exact congrArg Sum.inl (Fin.castSucc_injective n equality)
  · change Fin.castSucc a = Fin.last n at equality
    exact (Fin.castSucc_ne_last a equality).elim
  · change Fin.last n = Fin.castSucc b at equality
    exact (Fin.castSucc_ne_last b equality.symm).elim
  · exact congrArg Sum.inr (Subsingleton.elim a b)

/-- Lift an old free variable into the next level. -/
def wk {L : FirstOrder.Language} {n : Nat} (φ : Fml L n) : Fml L (n + 1) :=
  φ.relabel Fin.castSucc

/-- Both sides of a universal-right premise use this same structural lift. -/
def wkCtx {L : FirstOrder.Language} {n : Nat} (Γ : Side L n) : Side L (n + 1) :=
  Γ.map wk

/--
Turn the single in-scope bound variable into the new last free variable.
Old free variables remain in the image of `Fin.castSucc`.
-/
def openLast {L : FirstOrder.Language} {n : Nat} (body : Body L n) : Fml L (n + 1) :=
  body.toFormula.relabel eigenExtend

/--
Instantiate the single in-scope bound variable with a term.  This goes through
mathlib's capture-avoiding `BoundedFormula.subst`; it is not textual replacement.
-/
def inst0 {L : FirstOrder.Language} {n : Nat} (body : Body L n)
    (term : L.Term (Fin n)) : Fml L n :=
  body.toFormula.subst (Sum.elim Term.var fun _ => term)

/-- No old variable is confused with the eigenvariable introduced by `openLast`. -/
theorem castSucc_ne_last {n : Nat} (i : Fin n) : Fin.castSucc i ≠ Fin.last n :=
  Fin.castSucc_ne_last i

/-- The rule vocabulary; constructors are data rather than soundness proofs. -/
inductive Deriv (L : FirstOrder.Language) :
    (n : Nat) → Side L n → Side L n → Prop
  | identity {n Γ Δ} (φ : Fml L n) :
      Deriv L n (φ :: Γ) (φ :: Δ)
  | falsumLeft {n Γ Δ} :
      Deriv L n ((⊥ : Fml L n) :: Γ) Δ
  | impLeft {n Γ Δ} {φ ψ : Fml L n}
      (left : Deriv L n Γ (φ :: Δ))
      (right : Deriv L n (ψ :: Γ) Δ) :
      Deriv L n (φ.imp ψ :: Γ) Δ
  | impRight {n Γ Δ} {φ ψ : Fml L n}
      (premise : Deriv L n (φ :: Γ) (ψ :: Δ)) :
      Deriv L n Γ (φ.imp ψ :: Δ)
  | allLeft {n Γ Δ} {body : Body L n} {term : L.Term (Fin n)}
      (premise : Deriv L n (inst0 body term :: Γ) Δ) :
      Deriv L n (body.all :: Γ) Δ
  | allRight {n Γ Δ} {body : Body L n}
      (premise :
        Deriv L (n + 1) (wkCtx Γ) (openLast body :: wkCtx Δ)) :
      Deriv L n Γ (body.all :: Δ)

end AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK
