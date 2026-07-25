import Mathlib.ModelTheory.Semantics
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
  if rendered.isEmpty || rendered.length > 1000000 then
    throw <| IO.userError "canonical declaration type is outside the verifier limit"
  if rendered.any fun char => char == '\x00' || char == '\n' || char == '\r' then
    throw <| IO.userError "canonical declaration type is not one line"
  return rendered

private def observedAxioms (env : Environment) (declaration : Name) : IO (Array Name) := do
  let context : Core.Context := {
    fileName := "<AutoLeanLibrarySubstrateV2Query>"
    fileMap := default
    options := canonicalOptions
  }
  let state : Core.State := { env := env }
  let axioms ← Core.CoreM.toIO' (collectAxioms declaration) context state
  return Array.qsort axioms fun left right => left.toString < right.toString

private def query (declarationText wrapperSha256 queryHelperSha256 : String) : IO Json := do
  let environment ← importModules #[{ module := `Candidate }] canonicalOptions
  let declaration := declarationText.toName
  return Json.mkObj [
    ("schema_version", Json.str "autolean.oci-lean-wrapper.v2"),
    ("declaration", Json.str declarationText),
    ("canonical_type", Json.str (← canonicalType environment declaration)),
    ("lean_version", Json.str "v4.28.0"),
    ("mathlib_revision", Json.str "8f9d9cff6bd728b17a24e163c9402775d9e6a365"),
    ("lake_manifest_hash",
      Json.str "e2a93c904f51195d6740cd9abfb35ab155dc0157e0e46642dce0d364b68a9a89"),
    ("observed_axioms", Json.arr <| (← observedAxioms environment declaration).map fun name =>
      Json.str name.toString),
    ("image_identity", Json.mkObj [
      ("schema_version", Json.str "autolean.image-owned-verifier-identity.v2"),
      ("wrapper_path", Json.str "/opt/autolean/bin/autolean-lean-wrapper"),
      ("wrapper_sha256", Json.str wrapperSha256),
      ("query_helper_path", Json.str "/opt/autolean/lib/AutoleanLeanQuery.lean"),
      ("query_helper_sha256", Json.str queryHelperSha256)
    ])
  ]

def main (arguments : List String) : IO UInt32 := do
  try
    let [declaration, wrapperSha256, queryHelperSha256] := arguments
      | throw <| IO.userError "expected declaration and image-owned identity arguments"
    IO.println (← query declaration wrapperSha256 queryHelperSha256).compress
    return (0 : UInt32)
  catch error =>
    IO.eprintln s!"autolean-library-substrate-v2-query: {error}"
    return (2 : UInt32)
