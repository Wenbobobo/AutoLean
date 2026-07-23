import Lean.PrettyPrinter
import Lean.Util.CollectAxioms

open Lean

private def canonicalOptions : Options :=
  ((((({} : Options).setBool `pp.all true).setBool `pp.explicit true).setBool
        `pp.universes true).setBool `pp.notation false).set `pp.width (1000000 : Nat)

private def canonicalType (env : Environment) (declaration : Name) : IO String := do
  let some info := env.checked.get.find? declaration
    | throw <| IO.userError s!"declaration not found: {declaration}"
  if info.type.hasMVar then
    throw <| IO.userError "declaration type contains a metavariable"
  let rendered :=
    (← PrettyPrinter.ppExprLegacy env {} {} canonicalOptions info.type).pretty 1000000
  if rendered.isEmpty then
    throw <| IO.userError "canonical declaration type is empty"
  if rendered.length > 1000000 then
    throw <| IO.userError "canonical declaration type exceeds the verifier limit"
  if rendered.any fun char => char == '\x00' || char == '\n' || char == '\r' then
    throw <| IO.userError "canonical declaration type is not one line"
  return rendered

private def observedAxioms (env : Environment) (declaration : Name) : IO (Array Name) := do
  let context : Core.Context := {
    fileName := "<AutoLeanFateQuery>"
    fileMap := default
    options := canonicalOptions
  }
  let state : Core.State := { env := env }
  let axioms ← Core.CoreM.toIO' (collectAxioms declaration) context state
  return Array.qsort axioms fun left right => left.toString < right.toString

private def query (declarationText : String) : IO Json := do
  let environment ← importModules #[{ module := `Candidate }] canonicalOptions
  let declaration := declarationText.toName
  let renderedType ← canonicalType environment declaration
  let axioms ← observedAxioms environment declaration
  return Json.mkObj [
    ("schema_version", Json.str "autolean.fate-oci-lean-wrapper.v1"),
    ("declaration", Json.str declarationText),
    ("canonical_type", Json.str renderedType),
    ("lean_version", Json.str "v4.28.0"),
    ("mathlib_revision", Json.str "8f9d9cff6bd728b17a24e163c9402775d9e6a365"),
    ("lake_manifest_hash",
      Json.str "8403899ad037e733385ed21746c79c772b918a1ce4a6d291fddadb8899ee9e24"),
    ("observed_axioms", Json.arr <| axioms.map fun name => Json.str name.toString)
  ]

def main (arguments : List String) : IO UInt32 := do
  try
    let [declaration] := arguments
      | throw <| IO.userError "expected exactly one declaration argument"
    IO.println (← query declaration).compress
    return (0 : UInt32)
  catch error =>
    IO.eprintln s!"autolean-fate-query: {error}"
    return (2 : UInt32)
