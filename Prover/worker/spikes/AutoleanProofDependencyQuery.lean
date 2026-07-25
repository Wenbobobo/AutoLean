import Mathlib.ModelTheory.Semantics
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

private def declarationDependencies : ConstantInfo → Array Name
  | .axiomInfo value => value.type.getUsedConstants
  | .defnInfo value => value.type.getUsedConstants ++ value.value.getUsedConstants
  | .thmInfo value => value.type.getUsedConstants ++ value.value.getUsedConstants
  | .opaqueInfo value => value.type.getUsedConstants ++ value.value.getUsedConstants
  | .quotInfo _ => #[]
  | .ctorInfo value => value.type.getUsedConstants
  | .recInfo value => value.type.getUsedConstants ++ value.all.toArray
  | .inductInfo value => value.type.getUsedConstants ++ value.ctors

private def checkedDeclaration (environment : Environment) (name : Name) : IO ConstantInfo := do
  let some info := environment.checked.get.find? name
    | throw <| IO.userError s!"dependency declaration not found: {name}"
  return info

private def theoremProofValue (environment : Environment) (name : Name) : IO Expr := do
  match ← checkedDeclaration environment name with
  | .thmInfo value => return value.value
  | _ => throw <| IO.userError s!"target declaration is not a theorem: {name}"

private partial def dependencyClosure
    (environment : Environment) (direct : Array Name) : IO (Array Name) := do
  let rec visit
      (pending : List Name) (seen : NameSet) (result : Array Name) :
      IO (Array Name) := do
    match pending with
    | [] => return result
    | name :: rest =>
        if seen.contains name then
          visit rest seen result
        else
          if result.size >= 100000 then
            throw <| IO.userError "proof dependency closure exceeds the query limit"
          let info ← checkedDeclaration environment name
          let dependencies := declarationDependencies info
          visit (dependencies.toList ++ rest) (seen.insert name) (result.push name)
  return uniqueSortedNames (← visit direct.toList {} #[])

private def candidateModuleData : IO ModuleData := do
  let (candidate, _) ← readModuleData "/compiled/Candidate.olean"
  return candidate

private def query (declarationText : String) : IO Json := do
  let environment ← importModules #[{ module := `Candidate }] {}
  let candidate ← candidateModuleData
  let declaration := declarationText.toName
  if !candidate.constNames.any (· == declaration) then
    throw <| IO.userError s!"declaration is not defined by Candidate: {declarationText}"
  let proofValue ← theoremProofValue environment declaration
  let direct := uniqueSortedNames proofValue.getUsedConstants
  let closure ← dependencyClosure environment direct
  let candidateOwned := closure.filter fun dependency =>
    candidate.constNames.any (· == dependency)
  return Json.mkObj [
    ("candidate_declaration_count", Json.num candidate.constNames.size),
    ("candidate_owned_dependencies", namesJson candidateOwned),
    ("declaration", Json.str declarationText),
    ("direct_proof_dependencies", namesJson direct),
    ("proof_dependency_closure", namesJson closure),
    ("schema_version", Json.str "autolean.proof-dependency-query-spike.v1"),
    ("traversal",
      Json.str "target-proof-value-then-declaration-type-and-value-transitive.v1")
  ]

def main (arguments : List String) : IO UInt32 := do
  try
    let [declaration] := arguments
      | throw <| IO.userError "expected exactly one target declaration"
    IO.println (← query declaration).compress
    return (0 : UInt32)
  catch error =>
    IO.eprintln s!"autolean-proof-dependency-query-spike: {error}"
    return (2 : UInt32)
