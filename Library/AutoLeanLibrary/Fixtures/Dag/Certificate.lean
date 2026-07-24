import AutoLeanLibrary.Fixtures.Dag.Bridge

namespace AutoLeanLibrary.Fixtures.Dag

/-- Terminal node: proves a result through the imported bridge theorem. -/
theorem certificate_normalize (n : Nat) : (n + 0) + 0 = n :=
  bridge_normalize n

end AutoLeanLibrary.Fixtures.Dag
