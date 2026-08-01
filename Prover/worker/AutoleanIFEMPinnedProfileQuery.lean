import Lean.PrettyPrinter
import Lean.Util.CollectAxioms

open Lean

private def canonicalOptions : Options :=
  ((((({} : Options).setBool `pp.all true).setBool `pp.explicit true).setBool
        `pp.universes true).setBool `pp.notation false).set `pp.width (1000000 : Nat)

private def profileModule (profileId : String) : IO Name :=
  match profileId with
  | "ifem-singleton-defs" => pure `Mathlib.Analysis.InnerProductSpace.Defs
  | "ifem-singleton-dual" => pure `Mathlib.Analysis.InnerProductSpace.Dual
  | "ifem-singleton-lax-milgram" => pure `Mathlib.Analysis.InnerProductSpace.LaxMilgram
  | "ifem-singleton-operator-basic" => pure `Mathlib.Analysis.Normed.Operator.Basic
  | "ifem-singleton-operator-bilinear" => pure `Mathlib.Analysis.Normed.Operator.Bilinear
  | _ => throw <| IO.userError "unsupported singleton iFEM import profile"

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
    fileName := "<AutoLeanIFEMPinnedProfileQuery>"
    fileMap := default
    options := canonicalOptions
  }
  let state : Core.State := { env := env }
  let axioms ← Core.CoreM.toIO' (collectAxioms declaration) context state
  return axioms.qsort fun left right => left.toString < right.toString

private def originModule (env : Environment) (declaration : Name) : IO Name := do
  let some moduleIdx := env.getModuleIdxFor? declaration
    | throw <| IO.userError "declaration has no imported-module origin"
  let some moduleName := env.header.moduleNames[moduleIdx.toNat]?
    | throw <| IO.userError "declaration origin module index is unavailable"
  return moduleName

private def declarationRecord (env : Environment) (declarationText : String) : IO Json := do
  let declaration := declarationText.toName
  match env.checked.get.find? declaration with
  | none =>
      return Json.mkObj [
        ("canonical_type", Json.null),
        ("declaration", Json.str declarationText),
        ("declaration_kind", Json.null),
        ("observed_axioms", Json.arr #[]),
        ("origin_module", Json.null),
        ("present", Json.bool false)
      ]
  | some info =>
      let rendered ← canonicalType env info
      let axioms ← observedAxioms env declaration
      let origin ← originModule env declaration
      return Json.mkObj [
        ("canonical_type", Json.str rendered),
        ("declaration", Json.str declarationText),
        ("declaration_kind", Json.str (declarationKind info)),
        ("observed_axioms", Json.arr <| axioms.map fun name => Json.str name.toString),
        ("origin_module", Json.str origin.toString),
        ("present", Json.bool true)
      ]

private def sortedNames (names : Array Name) : Array Name :=
  names.qsort fun left right => left.toString < right.toString

private def query
    (helperSha256 wrapperSha256 builtOleanManifestSha256 profileId negativeControl : String)
    (declarationTexts : List String) : IO Json := do
  if declarationTexts.isEmpty then
    throw <| IO.userError "at least one declaration is required"
  if declarationTexts.any (· == negativeControl) then
    throw <| IO.userError "negative control must be supplied separately"
  let module ← profileModule profileId
  let environment ← importModules #[{ module := module }] canonicalOptions
  let declarations ← declarationTexts.toArray.mapM (declarationRecord environment)
  let negative ← declarationRecord environment negativeControl
  let closure := sortedNames environment.allImportedModuleNames
  return Json.mkObj [
    ("built_olean_manifest_sha256", Json.str builtOleanManifestSha256),
    ("declarations", Json.arr declarations),
    ("direct_imports", Json.arr #[Json.str module.toString]),
    ("helper_sha256", Json.str helperSha256),
    ("loaded_module_closure", Json.arr <| closure.map fun name => Json.str name.toString),
    ("negative_control", negative),
    ("profile_id", Json.str profileId),
    ("schema_version", Json.str "autolean.ifem-pinned-profile-query-raw.v1"),
    ("type_format", Json.str "autolean.lean-pp-expr.v1"),
    ("wrapper_sha256", Json.str wrapperSha256)
  ]

def main (arguments : List String) : IO UInt32 := do
  try
    let helperSha256 :: wrapperSha256 :: builtOleanManifestSha256 :: profileId :: negativeControl ::
        declarations := arguments
      | throw <| IO.userError "expected image identity, profile, negative control, and declarations"
    IO.println (← query helperSha256 wrapperSha256 builtOleanManifestSha256 profileId negativeControl
      declarations).compress
    return (0 : UInt32)
  catch error =>
    IO.eprintln s!"autolean-ifem-pinned-profile-query: {error}"
    return (2 : UInt32)
