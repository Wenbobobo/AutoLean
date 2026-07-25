import AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Targets.DerivSound

/-!
# Historical target module: `Deriv.closed_sound`

This is a reference target module for the source split.  Neither profile
imports it: both canaries instead materialize the same declaration in their
own `Candidate.lean` file.
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
  exact derivation.sound (M := M) Fin.elim0 ((closedAll_iff Γ).1 antecedent)

end ClosedBridge

end AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK
