import Mathlib.Data.Nat.Basic

namespace AutoLeanLibrary.Fixtures.Dag

/-- First node in the downstream multi-file DAG fixture. -/
theorem foundation_add_zero (n : Nat) : n + 0 = n := Nat.add_zero n

end AutoLeanLibrary.Fixtures.Dag
