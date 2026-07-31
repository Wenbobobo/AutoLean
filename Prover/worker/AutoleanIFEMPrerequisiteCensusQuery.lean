import Lean.PrettyPrinter
import Lean.Util.CollectAxioms

open Lean

structure CensusNodeInput where
  nodeId : String
  declarations : Array String
deriving FromJson

private def canonicalOptions : Options :=
  ((((({} : Options).setBool `pp.all true).setBool `pp.explicit true).setBool
        `pp.universes true).setBool `pp.notation false).set `pp.width (1000000 : Nat)

private def declarationKind (info : ConstantInfo) : String :=
  match info with
  | .axiomInfo _ => "axiom"
  | .defnInfo _ => "definition"
  | .thmInfo _ => "theorem"
  | .opaqueInfo _ => "opaque"
  | .quotInfo _ => "quotient"
  | .inductInfo _ => "inductive"
  | .ctorInfo _ => "constructor"
  | .recInfo _ => "recursor"

private def canonicalType (env : Environment) (info : ConstantInfo) : IO String := do
  if info.type.hasMVar then
    throw <| IO.userError "canonical declaration type contains a metavariable"
  let rendered :=
    (← PrettyPrinter.ppExprLegacy env {} {} canonicalOptions info.type).pretty 1000000
  if rendered.isEmpty || rendered.length > 1000000 then
    throw <| IO.userError "canonical declaration type has an invalid size"
  if rendered.any fun char => char == '\x00' || char == '\n' || char == '\r' then
    throw <| IO.userError "canonical declaration type is not one line"
  return rendered

private def observedAxioms (env : Environment) (declaration : Name) : IO (Array Name) := do
  let context : Core.Context := {
    fileName := "<AutoLeanIFEMPrerequisiteCensusQuery>"
    fileMap := default
    options := canonicalOptions
  }
  let state : Core.State := { env := env }
  let axioms ← Core.CoreM.toIO' (collectAxioms declaration) context state
  return axioms.qsort fun left right => left.toString < right.toString

private def declarationRecord (env : Environment) (declarationText : String) : IO Json := do
  let declaration := declarationText.toName
  match env.checked.get.find? declaration with
  | none =>
      return Json.mkObj [
        ("canonical_type", Json.null),
        ("declaration", Json.str declarationText),
        ("declaration_kind", Json.null),
        ("observed_axioms", Json.arr #[]),
        ("present", Json.bool false)
      ]
  | some info =>
      let rendered ← canonicalType env info
      let axioms ← observedAxioms env declaration
      return Json.mkObj [
        ("canonical_type", Json.str rendered),
        ("declaration", Json.str declarationText),
        ("declaration_kind", Json.str (declarationKind info)),
        ("observed_axioms", Json.arr <| axioms.map fun name => Json.str name.toString),
        ("present", Json.bool true)
      ]

private def nodeRecord (env : Environment) (node : CensusNodeInput) : IO Json := do
  let candidates ← node.declarations.mapM (declarationRecord env)
  return Json.mkObj [
    ("candidates", Json.arr candidates),
    ("node_id", Json.str node.nodeId)
  ]

private def decodeNodes (raw : String) : IO (Array CensusNodeInput) := do
  let payload ← IO.ofExcept (Json.parse raw)
  let nodes : Array CensusNodeInput ← IO.ofExcept (fromJson? payload)
  if nodes.isEmpty || nodes.size > 64 then
    throw <| IO.userError "census node count is outside the bounded range"
  for node in nodes do
    if node.nodeId.isEmpty || node.nodeId.length > 96 || node.declarations.isEmpty ||
        node.declarations.size > 128 then
      throw <| IO.userError "census node input is outside the bounded range"
  return nodes

private def executeQuery
    (planContentSha256 leanToolchain mathlibRevision lakeManifestSha256 queriesJson : String) :
    IO Json := do
  let nodes ← decodeNodes queriesJson
  let environment ← importModules #[
    { module := `Mathlib.Analysis.InnerProductSpace.LaxMilgram },
    { module := `Mathlib.Analysis.Normed.Operator.Bilinear }
  ] canonicalOptions
  let records ← nodes.mapM (nodeRecord environment)
  return Json.mkObj [
    ("direct_imports", Json.arr #[
      Json.str "Mathlib.Analysis.InnerProductSpace.LaxMilgram",
      Json.str "Mathlib.Analysis.Normed.Operator.Bilinear"
    ]),
    ("lake_manifest_sha256", Json.str lakeManifestSha256),
    ("lean_toolchain", Json.str leanToolchain),
    ("mathlib_revision", Json.str mathlibRevision),
    ("nodes", Json.arr records),
    ("plan_content_sha256", Json.str planContentSha256),
    ("protocol", Json.str "autolean.builder-ifem-prerequisite-census.v1"),
    ("schema_version", Json.str "autolean.ifem-prerequisite-query-raw.v1"),
    ("type_format", Json.str "autolean.lean-pp-expr.v1")
  ]

def main (arguments : List String) : IO UInt32 := do
  try
    let [planContentSha256, leanToolchain, mathlibRevision, lakeManifestSha256, queriesJson] :=
        arguments
      | throw <| IO.userError "expected the image-bound census argument shape"
    initSearchPath (← findSysroot)
    IO.println (← executeQuery planContentSha256 leanToolchain mathlibRevision
      lakeManifestSha256 queriesJson).compress
    return (0 : UInt32)
  catch error =>
    IO.eprintln s!"autolean-ifem-prerequisite-census-query: {error}"
    return (2 : UInt32)
