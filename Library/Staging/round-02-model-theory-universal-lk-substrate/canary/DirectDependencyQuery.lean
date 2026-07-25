import Mathlib.ModelTheory.Semantics
import Lean.PrettyPrinter
import Lean.Util.CollectAxioms
import Lean.Util.FoldConsts

open Lean

private def sortedNames (names : Array Name) : Array Name :=
  names.qsort fun left right => left.toString < right.toString

private def uniqueSortedNames (names : Array Name) : Array Name := Id.run do
  let mut seen : NameSet := {}
  let mut result := #[]
  for name in sortedNames names do
    unless seen.contains name do
      seen := seen.insert name
      result := result.push name
  return result

private def namesJson (names : Array Name) : Json :=
  Json.arr <| names.map fun name => Json.str name.toString

private def canonicalOptions : Options :=
  ((((({} : Options).setBool `pp.all true).setBool `pp.explicit true).setBool
        `pp.universes true).setBool `pp.notation false).set `pp.width (1000000 : Nat)

private def canonicalType (environment : Environment) (name : Name) : IO String := do
  let some info := environment.checked.get.find? name
    | throw <| IO.userError s!"target declaration not found: {name}"
  if info.type.hasMVar then
    throw <| IO.userError "target type contains a metavariable"
  let rendered :=
    (← PrettyPrinter.ppExprLegacy environment {} {} canonicalOptions info.type).pretty 1000000
  if rendered.isEmpty || rendered.length > 1000000 then
    throw <| IO.userError "canonical target type has invalid size"
  if rendered.any fun char => char == '\x00' || char == '\n' || char == '\r' then
    throw <| IO.userError "canonical target type is not one line"
  return rendered

private def observedAxioms (environment : Environment) (name : Name) : IO (Array Name) := do
  let context : Core.Context := {
    fileName := "<AutoLeanLibrarySubstrateCanary>"
    fileMap := default
    options := canonicalOptions
  }
  let state : Core.State := { env := environment }
  let axioms ← Core.CoreM.toIO' (collectAxioms name) context state
  return sortedNames axioms

private def theoremProofValue (environment : Environment) (name : Name) : IO Expr := do
  let some info := environment.checked.get.find? name
    | throw <| IO.userError s!"target declaration not found: {name}"
  match info with
  | .thmInfo value => return value.value
  | _ => throw <| IO.userError s!"target declaration is not a theorem: {name}"

private def query : IO Json := do
  let environment ← importModules #[{ module := `Candidate }] canonicalOptions
  let target := `AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Deriv.closed_sound
  let (candidate, _) ← readModuleData "/compiled/Candidate.olean"
  if !candidate.constNames.any (· == target) then
    throw <| IO.userError s!"target declaration is not owned by Candidate: {target}"
  let direct := uniqueSortedNames (← theoremProofValue environment target).getUsedConstants
  let renderedType ← canonicalType environment target
  let axioms ← observedAxioms environment target
  return Json.mkObj [
    ("authority", Json.str "diagnostic-host-mounted-preflight-only"),
    ("candidate_owns_target", Json.bool true),
    ("canonical_type", Json.str renderedType),
    ("declaration", Json.str target.toString),
    ("direct_proof_dependencies", namesJson direct),
    ("observed_axioms", namesJson axioms),
    ("schema_version", Json.str "autolean.library-substrate-direct-dependency-query.v2"),
  ]

def main (_arguments : List String) : IO UInt32 := do
  try
    IO.println (← query).compress
    return 0
  catch error =>
    IO.eprintln s!"autolean-library-substrate-query: {error}"
    return 2
