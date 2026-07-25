import AutoLean.ProjectDagPreflight.Foundations
import AutoLean.ProjectDagPreflight.Arithmetic

namespace AutoLean.ProjectDagPreflight.Relations

theorem exactScore : AutoLean.ProjectDagPreflight.Arithmetic.score = 13 := rfl

theorem positiveScore : 0 < AutoLean.ProjectDagPreflight.Arithmetic.score := by
  decide

theorem scoreCertificate :
    AutoLean.ProjectDagPreflight.Arithmetic.score = 13 ∧
      0 < AutoLean.ProjectDagPreflight.Arithmetic.score :=
  ⟨exactScore, positiveScore⟩

theorem scoreIsNonzero : AutoLean.ProjectDagPreflight.Arithmetic.score ≠ 0 :=
  Nat.ne_of_gt positiveScore

theorem seedIsBounded :
    AutoLean.ProjectDagPreflight.Foundations.seed ≤
      AutoLean.ProjectDagPreflight.Arithmetic.score := by
  decide

end AutoLean.ProjectDagPreflight.Relations
