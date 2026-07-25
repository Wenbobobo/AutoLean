import AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.RulePrelude

/-!
# Historical target module: `Deriv.sound`

This module exists to make the target split explicit.  It is not visible to
the independent-reproof profile.  The compositional-bridge profile treats it
only as an unadmitted dependency fixture, never as a frozen Library result.
-/
namespace AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK

open FirstOrder
open FirstOrder.Language

universe u v

namespace Deriv

section Soundness

variable {L : FirstOrder.Language} {M : Type u} [L.Structure M]
variable {n : Nat} {Γ Δ : Side L n}

theorem sound (derivation : Deriv L n Γ Δ) : ValidIn M Γ Δ := by
  induction derivation with
  | identity φ => exact identity_sound φ
  | falsumLeft => exact falsumLeft_sound
  | impLeft left right ihLeft ihRight =>
      exact impLeft_sound ihLeft ihRight
  | impRight premise ih => exact impRight_sound ih
  | allLeft premise ih => exact allLeft_sound ih
  | allRight premise ih => exact allRight_sound ih

end Soundness

end Deriv

end AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK
