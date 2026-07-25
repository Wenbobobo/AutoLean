import AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.SemanticPrelude

/-!
# Target-free UniversalLK rule prelude

This holds individually reviewed rule lemmas.  It deliberately omits the
global `Deriv.sound` and `Deriv.closed_sound` targets so the independent
profile can use the same prelude without importing either target theorem.
-/
namespace AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK

open FirstOrder
open FirstOrder.Language

universe u v

namespace Deriv

section Soundness

variable {L : FirstOrder.Language} {M : Type u} [L.Structure M]
variable {n : Nat} {Γ Δ : Side L n}

theorem identity_sound (φ : Fml L n) :
    ValidIn M (φ :: Γ) (φ :: Δ) := by
  intro assignment antecedent
  exact Or.inl antecedent.1

theorem falsumLeft_sound :
    ValidIn M ((⊥ : Fml L n) :: Γ) Δ := by
  intro assignment antecedent
  exact (by simpa using antecedent.1)

theorem impLeft_sound {φ ψ : Fml L n}
    (left : ValidIn M Γ (φ :: Δ))
    (right : ValidIn M (ψ :: Γ) Δ) :
    ValidIn M (φ.imp ψ :: Γ) Δ := by
  intro assignment antecedent
  rcases antecedent with ⟨implication, antecedent⟩
  rcases left assignment antecedent with formula | succedent
  · exact right assignment ⟨implication formula, antecedent⟩
  · exact succedent

theorem impRight_sound {φ ψ : Fml L n}
    (premise : ValidIn M (φ :: Γ) (ψ :: Δ)) :
    ValidIn M Γ (φ.imp ψ :: Δ) := by
  intro assignment antecedent
  classical
  by_cases formula : φ.Realize assignment
  · rcases premise assignment ⟨formula, antecedent⟩ with consequent | succedent
    · exact Or.inl (fun _ => consequent)
    · exact Or.inr succedent
  · exact Or.inl (fun impossible => (formula impossible).elim)

theorem allLeft_sound {body : Body L n} {term : L.Term (Fin n)}
    (premise : ValidIn M (inst0 body term :: Γ) Δ) :
    ValidIn M (body.all :: Γ) Δ := by
  intro assignment antecedent
  apply premise assignment
  refine ⟨(inst0_realize body term assignment).2 ?_, antecedent.2⟩
  exact (all_realize body assignment).1 antecedent.1 (term.realize assignment)

theorem allRight_sound {body : Body L n}
    (premise :
      ValidIn M (wkCtx Γ) (openLast body :: wkCtx Δ)) :
    ValidIn M Γ (body.all :: Δ) := by
  intro assignment antecedent
  classical
  by_cases oldSuccedent : Side.AnyRealize assignment Δ
  · exact Or.inr oldSuccedent
  · apply Or.inl
    apply (all_realize body assignment).2
    intro value
    let extended : Fin (n + 1) → M := Fin.snoc assignment value
    have liftedAntecedent : Side.AllRealize extended (wkCtx Γ) := by
      apply (Side.wkCtx_allRealize Γ extended).2
      simpa [extended] using antecedent
    rcases premise extended liftedAntecedent with opened | liftedSuccedent
    · have openedBody := (openLast_realize body extended).1 opened
      have extended_old : extended ∘ Fin.castSucc = assignment := by
        funext i
        simp [extended]
      rw [extended_old] at openedBody
      simpa [extended] using openedBody
    · exfalso
      apply oldSuccedent
      have oldBody := (Side.wkCtx_anyRealize Δ extended).1 liftedSuccedent
      have extended_old : extended ∘ Fin.castSucc = assignment := by
        funext i
        simp [extended]
      rwa [extended_old] at oldBody

end Soundness

end Deriv

end AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK
