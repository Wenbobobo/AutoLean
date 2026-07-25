import AutoLean.ProjectDagPreflight.Foundations
import AutoLean.ProjectDagPreflight.Arithmetic
import AutoLean.ProjectDagPreflight.Relations

namespace AutoLean.ProjectDagPreflight.Capstone

def targetNat : Nat :=
  AutoLean.ProjectDagPreflight.Arithmetic.score +
    AutoLean.ProjectDagPreflight.Foundations.seed

theorem targetNatIsFifteen : targetNat = 15 := rfl

theorem targetNatIsPositive : 0 < targetNat := by
  decide

theorem finalCertificate :
    And (targetNat = 15)
      (And (0 < targetNat)
        (And (AutoLean.ProjectDagPreflight.Arithmetic.score = 13)
          (0 < AutoLean.ProjectDagPreflight.Arithmetic.score))) :=
  And.intro targetNatIsFifteen
    (And.intro targetNatIsPositive AutoLean.ProjectDagPreflight.Relations.scoreCertificate)

theorem capstone : targetNat = 15 := finalCertificate.1

end AutoLean.ProjectDagPreflight.Capstone
