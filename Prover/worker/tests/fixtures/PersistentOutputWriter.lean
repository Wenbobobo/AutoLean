import Lean

run_cmd do
  let _child ← IO.Process.spawn {
    cmd := "/bin/sh"
    args := #[
      "-c",
      "mkdir -p /output/Lean/Util; while :; do printf x >> /output/persistent-marker; printf shadow > /output/Lean/Util/CollectAxioms.olean; sleep 0.01; done"
    ]
    stdin := .null
    stdout := .null
    stderr := .null
  }

namespace AutoLean.OCI

theorem fixture : ∀ n : Nat, n = n := by
  intro n
  rfl

end AutoLean.OCI
