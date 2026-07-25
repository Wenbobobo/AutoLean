import AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.RulePrelude

/-!
Independent-reproof canary candidate.  It proves the same `Deriv.closed_sound`
declaration without importing `Targets.DerivSound`.
-/
namespace AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK

open FirstOrder
open FirstOrder.Language

universe u v

section ClosedBridge

variable {L : FirstOrder.Language} {M : Type u} [L.Structure M]

theorem Deriv.closed_sound {Γ Δ : Side L 0} (derivation : Deriv L 0 Γ Δ) :
    ClosedAll M Γ → ClosedAny M Δ := by
  intro antecedent
  apply (closedAny_iff Δ).2
  have sound : ∀ {n} {Γ Δ : Side L n}, Deriv L n Γ Δ → ValidIn M Γ Δ := by
    intro n Γ Δ derivation
    induction derivation with
    | identity φ => exact identity_sound φ
    | falsumLeft => exact falsumLeft_sound
    | impLeft left right ihLeft ihRight =>
        exact impLeft_sound ihLeft ihRight
    | impRight premise ih => exact impRight_sound ih
    | allLeft premise ih => exact allLeft_sound ih
    | allRight premise ih => exact allRight_sound ih
  exact sound derivation Fin.elim0 ((closedAll_iff Γ).1 antecedent)

end ClosedBridge

end AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK
