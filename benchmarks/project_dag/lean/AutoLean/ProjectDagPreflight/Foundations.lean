namespace AutoLean.ProjectDagPreflight.Foundations

def seed : Nat := 2

def nextSeed : Nat := seed + 1

def twiceSeed : Nat := seed + seed

theorem nextSeedIsThree : nextSeed = 3 := rfl

theorem twiceSeedIsFour : twiceSeed = 4 := rfl

end AutoLean.ProjectDagPreflight.Foundations
