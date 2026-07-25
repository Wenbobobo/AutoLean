import AutoLean.ProjectDagPreflight.Foundations

namespace AutoLean.ProjectDagPreflight.Arithmetic

def sumSeeds : Nat :=
  AutoLean.ProjectDagPreflight.Foundations.nextSeed +
    AutoLean.ProjectDagPreflight.Foundations.twiceSeed

theorem sumSeedsIsSeven : sumSeeds = 7 := rfl

def tripleSeed : Nat :=
  AutoLean.ProjectDagPreflight.Foundations.seed +
    AutoLean.ProjectDagPreflight.Foundations.twiceSeed

theorem tripleSeedIsSix : tripleSeed = 6 := rfl

def score : Nat := sumSeeds + tripleSeed

end AutoLean.ProjectDagPreflight.Arithmetic
