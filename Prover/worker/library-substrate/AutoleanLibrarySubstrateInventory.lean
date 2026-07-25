import AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.RulePrelude
import Lean.Compiler.IR.CompilerM
import Lean.PrettyPrinter
import Lean.Util.CollectAxioms

open Lean

private def coreModule :=
  `AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Core

private def semanticModule :=
  `AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.SemanticPrelude

private def ruleModule :=
  `AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.RulePrelude

private def moduleRecords : Array (Name × System.FilePath) := #[
  (coreModule,
    "/build/compiled/AutoLeanLibrary/Fixtures/ModelTheory/UniversalLK/Core.olean"),
  (semanticModule,
    "/build/compiled/AutoLeanLibrary/Fixtures/ModelTheory/UniversalLK/SemanticPrelude.olean"),
  (ruleModule,
    "/build/compiled/AutoLeanLibrary/Fixtures/ModelTheory/UniversalLK/RulePrelude.olean")
]

private def canonicalOptions : Options :=
  ((((({} : Options).setBool `pp.all true).setBool `pp.explicit true).setBool
        `pp.universes true).setBool `pp.notation false).set `pp.width (1000000 : Nat)

private def sortedNames (names : Array Name) : Array Name :=
  names.qsort fun left right => left.toString < right.toString

private def namesJson (names : Array Name) : Json :=
  Json.arr <| sortedNames names |>.map fun name => Json.str name.toString

private def canonicalType (environment : Environment) (info : ConstantInfo) : IO String := do
  if info.type.hasMVar then
    throw <| IO.userError s!"declaration type contains a metavariable: {info.name}"
  let rendered :=
    (← PrettyPrinter.ppExprLegacy environment {} {} canonicalOptions info.type).pretty 1000000
  if rendered.isEmpty || rendered.length > 1000000 then
    throw <| IO.userError s!"canonical type has invalid size: {info.name}"
  if rendered.any fun char => char == '\x00' || char == '\n' || char == '\r' then
    throw <| IO.userError s!"canonical type is not one line: {info.name}"
  return rendered

private def sha256Text (value : String) : IO String := do
  let path : System.FilePath := "/tmp/autolean-library-substrate-type.txt"
  IO.FS.writeFile path value
  let output ← IO.Process.output { cmd := "sha256sum", args := #[path.toString] }
  if output.exitCode != 0 then
    throw <| IO.userError "sha256sum failed while hashing a canonical type"
  let digest := (output.stdout.trimAscii.take 64).toString
  if digest.length != 64 || !digest.all fun char => char.isDigit || ('a' ≤ char && char ≤ 'f') then
    throw <| IO.userError "sha256sum emitted an invalid digest"
  return digest

private def observedAxioms (environment : Environment) (name : Name) : IO (Array Name) := do
  let context : Core.Context := {
    fileName := "<AutoLeanLibrarySubstrateInventory>"
    fileMap := default
    options := canonicalOptions
  }
  let state : Core.State := { env := environment }
  let axioms ← Core.CoreM.toIO' (collectAxioms name) context state
  return sortedNames axioms

private def constantKind : ConstantInfo → String
  | .axiomInfo _ => "axiom"
  | .defnInfo _ => "definition"
  | .thmInfo _ => "theorem"
  | .opaqueInfo _ => "opaque"
  | .quotInfo _ => "quotient"
  | .inductInfo _ => "inductive"
  | .ctorInfo _ => "constructor"
  | .recInfo _ => "recursor"

private def originModule (environment : Environment) (name : Name) : IO Name := do
  let some index := environment.getModuleIdxFor? name
    | throw <| IO.userError s!"imported declaration has no module mapping: {name}"
  let some moduleName := environment.header.moduleNames[index.toNat]?
    | throw <| IO.userError s!"module index is outside the loaded header: {name}"
  return moduleName

private def originOleanSha256
    (origin : Name) (coreSha semanticSha ruleSha : String) : IO String := do
  if origin == coreModule then
    return coreSha
  if origin == semanticModule then
    return semanticSha
  if origin == ruleModule then
    return ruleSha
  throw <| IO.userError s!"AutoLean declaration resolved outside the runtime closure: {origin}"

private def declarationRecord
    (environment : Environment)
    (expectedOrigin name : Name)
    (coreSha semanticSha ruleSha : String) : IO Json := do
  let some info := environment.checked.get.find? name
    | throw <| IO.userError s!"runtime declaration has no ConstantInfo: {name}"
  let origin ← originModule environment name
  if origin != expectedOrigin then
    throw <| IO.userError s!"runtime declaration origin mismatch: {name}"
  let renderedType ← canonicalType environment info
  let typeSha ← sha256Text renderedType
  let axioms ← observedAxioms environment name
  return Json.mkObj [
    ("canonical_type", Json.str renderedType),
    ("canonical_type_sha256", Json.str typeSha),
    ("declaration_kind", Json.str (constantKind info)),
    ("name", Json.str name.toString),
    ("observed_axioms", namesJson axioms),
    ("origin_module", Json.str origin.toString),
    ("origin_olean_sha256",
      Json.str (← originOleanSha256 origin coreSha semanticSha ruleSha))
  ]

private def auxiliaryRecord
    (environment : Environment)
    (expectedOrigin name : Name)
    (coreSha semanticSha ruleSha : String) : IO Json := do
  if (environment.checked.get.find? name).isSome then
    throw <| IO.userError s!"IR auxiliary name overlaps a kernel declaration: {name}"
  let some declaration := Lean.IR.findEnvDecl environment name
    | throw <| IO.userError s!"IR auxiliary has no IR declaration: {name}"
  if declaration.name != name then
    throw <| IO.userError s!"IR auxiliary declaration name mismatch: {name}"
  let declarationKind :=
    match declaration with
    | .fdecl .. => "fdecl"
    | .extern .. => "extern"
  let origin ← originModule environment name
  if origin != expectedOrigin then
    throw <| IO.userError s!"IR auxiliary origin mismatch: {name}"
  return Json.mkObj [
    ("ir_decl_kind", Json.str declarationKind),
    ("name", Json.str name.toString),
    ("origin_module", Json.str origin.toString),
    ("origin_olean_sha256",
      Json.str (← originOleanSha256 origin coreSha semanticSha ruleSha))
  ]

private def inventory (coreSha semanticSha ruleSha : String) : IO Json := do
  let environment ← importModules #[{ module := ruleModule }] canonicalOptions
  let mut records : Array (String × Json) := #[]
  let mut auxiliary : Array (String × Json) := #[]
  let mut seen : NameSet := {}
  let mut seenAuxiliary : NameSet := {}
  for (moduleName, path) in moduleRecords do
    let (moduleData, _) ← readModuleData path
    for name in moduleData.extraConstNames do
      if seenAuxiliary.contains name then
        throw <| IO.userError s!"duplicate IR auxiliary name: {name}"
      seenAuxiliary := seenAuxiliary.insert name
      auxiliary := auxiliary.push (
        name.toString,
        ← auxiliaryRecord environment moduleName name coreSha semanticSha ruleSha
      )
    for name in moduleData.constNames do
      if name.toString.startsWith "AutoLeanLibrary." then
        if seen.contains name then
          throw <| IO.userError s!"duplicate runtime declaration: {name}"
        seen := seen.insert name
        records := records.push (
          name.toString,
          ← declarationRecord environment moduleName name coreSha semanticSha ruleSha
        )
  records := records.qsort fun left right => left.1 < right.1
  auxiliary := auxiliary.qsort fun left right => left.1 < right.1
  let auxiliaryJson := Json.arr <| auxiliary.map (·.2)
  return Json.mkObj [
    ("declarations", Json.arr <| records.map (·.2)),
    ("ir_auxiliary_names", auxiliaryJson),
    ("ir_auxiliary_names_sha256", Json.str (← sha256Text auxiliaryJson.compress)),
    ("schema_version", Json.str "autolean.library-substrate-declaration-inventory.v1")
  ]

def main (arguments : List String) : IO UInt32 := do
  try
    let [coreSha, semanticSha, ruleSha] := arguments
      | throw <| IO.userError "expected the three runtime OLean SHA-256 values"
    for digest in #[coreSha, semanticSha, ruleSha] do
      if digest.length != 64 then
        throw <| IO.userError "runtime OLean SHA-256 has invalid length"
    IO.println (← inventory coreSha semanticSha ruleSha).compress
    return (0 : UInt32)
  catch error =>
    IO.eprintln s!"autolean-library-substrate-inventory: {error}"
    return (2 : UInt32)
