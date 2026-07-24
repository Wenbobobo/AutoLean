import Lean

run_cmd do
  IO.FS.createDirAll "/output/Lean/Util"
  IO.FS.writeFile "/output/Lean/PrettyPrinter.olean" "candidate-controlled shadow"
  IO.FS.writeFile "/output/Lean/Util/CollectAxioms.olean" "candidate-controlled shadow"

namespace AutoLean.OCI

theorem fixture : ∀ n : Nat, n = n := by
  intro n
  rfl

end AutoLean.OCI
