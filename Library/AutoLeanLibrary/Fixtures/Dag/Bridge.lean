import AutoLeanLibrary.Fixtures.Dag.Foundation

namespace AutoLeanLibrary.Fixtures.Dag

/-- Second node: consumes a theorem exported by the foundation node. -/
theorem bridge_normalize (n : Nat) : (n + 0) + 0 = n := by
  rw [foundation_add_zero]

end AutoLeanLibrary.Fixtures.Dag
