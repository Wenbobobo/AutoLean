import Lake

open Lake DSL

/--
Independent downstream package for AutoLean-owned mathematical assets.

This project consumes released mathlib APIs. It is not a mathlib fork and must
not carry patches to Mathlib internals.
-/
package AutoLeanLibrary

require mathlib from git
  "https://github.com/leanprover-community/mathlib4.git" @ "v4.28.0"

@[default_target]
lean_lib AutoLeanLibrary
