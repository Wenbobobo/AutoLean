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
    throw <| IO.userError "canonical declaration type contains a metavariable"
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
    fileName := "<AutoLeanMathlibDeclarationQuery>"
    fileMap := default
    options := canonicalOptions
  }
  let state : Core.State := { env := env }
  let axioms ← Core.CoreM.toIO' (collectAxioms declaration) context state
  return axioms.qsort fun left right => left.toString < right.toString

private def sortedNames (names : Array Name) : Array Name :=
  names.qsort fun left right => left.toString < right.toString

private def candidateModuleData : IO ModuleData := do
  let (candidate, _) ← readModuleData "/compiled/Candidate.olean"
  return candidate

private def directImports (candidate : ModuleData) : Array Name :=
  sortedNames <| candidate.imports.map (·.module)

private def declarationRecord
    (env : Environment) (candidate : ModuleData) (declarationText : String) : IO Json := do
  let declaration := declarationText.toName
  if !candidate.constNames.any (· == declaration) then
    throw <| IO.userError s!"declaration is not defined by Candidate: {declarationText}"
  let renderedType ← canonicalType env declaration
  let axioms ← observedAxioms env declaration
  return Json.mkObj [
    ("canonical_type", Json.str renderedType),
    ("declaration", Json.str declarationText),
    ("observed_axioms", Json.arr <| axioms.map fun name => Json.str name.toString)
  ]

private def query
    (wrapperSha256 helperSha256 : String) (declarationTexts : List String) : IO Json := do
  if declarationTexts.isEmpty then
    throw <| IO.userError "at least one declaration is required"
  let environment ← importModules #[{ module := `Candidate }] canonicalOptions
  let candidate ← candidateModuleData
  let direct := directImports candidate
  let declarations ← declarationTexts.toArray.mapM (declarationRecord environment candidate)
  let closure := sortedNames environment.allImportedModuleNames
  return Json.mkObj [
    ("candidate_direct_imports", Json.arr <| direct.map fun name => Json.str name.toString),
    ("declarations", Json.arr declarations),
    ("image_identity", Json.mkObj [
      ("query_helper_path", Json.str "/opt/autolean/lib/AutoleanMathlibDeclarationQuery.lean"),
      ("query_helper_sha256", Json.str helperSha256),
      ("schema_version", Json.str "autolean.image-owned-declaration-query-identity.v1"),
      ("wrapper_path", Json.str "/opt/autolean/bin/autolean-mathlib-declaration-query"),
      ("wrapper_sha256", Json.str wrapperSha256)
    ]),
    ("lake_manifest_hash",
      Json.str "e2a93c904f51195d6740cd9abfb35ab155dc0157e0e46642dce0d364b68a9a89"),
    ("lean_version", Json.str "v4.28.0"),
    ("mathlib_revision", Json.str "8f9d9cff6bd728b17a24e163c9402775d9e6a365"),
    ("module_import_closure", Json.arr <| closure.map fun name => Json.str name.toString),
    ("schema_version", Json.str "autolean.mathlib-declaration-query.v1"),
    ("type_format", Json.str "autolean.lean-pp-expr.v1")
  ]

def main (arguments : List String) : IO UInt32 := do
  try
    let wrapperSha256 :: helperSha256 :: declarations := arguments
      | throw <| IO.userError "expected image-owned identity and declarations"
    IO.println (← query wrapperSha256 helperSha256 declarations).compress
    return (0 : UInt32)
  catch error =>
    IO.eprintln s!"autolean-mathlib-declaration-query: {error}"
    return (2 : UInt32)
