import Candidate
import Lean.PrettyPrinter
import Lean.Util.CollectAxioms
import Lean.Util.FoldConsts

open Lean

private def allowedDirectImports : Array Name := #[
  `AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.RulePrelude,
  `Init
]

private def forbiddenLoadedModules : Array Name := #[
  `AutoLeanLibrary.Fixtures.ModelTheory.Packet,
  `AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK,
  `AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Controls,
  `AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Targets.ClosedSound,
  `AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Targets.DerivSound
]

private def canonicalOptions : Options :=
  ((((({} : Options).setBool `pp.all true).setBool `pp.explicit true).setBool
        `pp.universes true).setBool `pp.notation false).set `pp.width (1000000 : Nat)

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
  let path : System.FilePath := "/tmp/autolean-library-substrate-builder-query-type.txt"
  IO.FS.writeFile path value
  let output ← IO.Process.output { cmd := "sha256sum", args := #[path.toString] }
  if output.exitCode != 0 then
    throw <| IO.userError "sha256sum failed while hashing the carrier type"
  let digest := (output.stdout.trimAscii.take 64).toString
  if digest.length != 64 || !digest.all fun char => char.isDigit || ('a' ≤ char && char ≤ 'f') then
    throw <| IO.userError "sha256sum emitted an invalid carrier type digest"
  return digest

private def observedAxioms (environment : Environment) (name : Name) : IO (Array Name) := do
  let context : Core.Context := {
    fileName := "<AutoLeanLibrarySubstrateBuilderQuery>"
    fileMap := default
    options := canonicalOptions
  }
  let state : Core.State := { env := environment }
  let axioms ← Core.CoreM.toIO' (collectAxioms name) context state
  return uniqueSortedNames axioms

private def typeObservedAxioms
    (environment : Environment) (info : ConstantInfo) : IO (Array Name) := do
  let mut axioms := #[]
  for dependency in uniqueSortedNames info.type.getUsedConstants do
    axioms := axioms ++ (← observedAxioms environment dependency)
  return uniqueSortedNames axioms

private def originModule (environment : Environment) (name : Name) : IO Name := do
  let some index := environment.getModuleIdxFor? name
    | throw <| IO.userError s!"candidate declaration has no module mapping: {name}"
  let some moduleName := environment.header.moduleNames[index.toNat]?
    | throw <| IO.userError s!"candidate module index is outside the loaded header: {name}"
  return moduleName

private def query
    (targetText sourceSha image expectedTypeSha imageReceiptSha buildInputSha
      runtimeManifestSha helperSha wrapperSha profileId profileSha parentImage
      mathlibRevision : String) : IO Json := do
  let target := targetText.toName
  if target.toString != targetText || !targetText.startsWith "Candidate." then
    throw <| IO.userError "target declaration is outside the Candidate namespace"
  let environment ← importModules #[{ module := `Candidate }] canonicalOptions
  let (candidate, _) ← readModuleData "/tmp/autolean-library-substrate-builder-query/Candidate.olean"
  let candidateKernelNames := uniqueSortedNames candidate.constNames
  let candidateAuxiliaryNames := uniqueSortedNames candidate.extraConstNames
  if candidateKernelNames.size != candidate.constNames.size ||
      candidateAuxiliaryNames.size != candidate.extraConstNames.size then
    throw <| IO.userError "Candidate repeats an owned declaration name"
  if candidateKernelNames != #[target] then
    if !candidateKernelNames.any (· == target) then
      throw <| IO.userError s!"requested target is not owned by Candidate: {target}"
    throw <| IO.userError "Candidate owns declarations other than the requested carrier"
  if !candidateAuxiliaryNames.isEmpty then
    throw <| IO.userError "Candidate owns IR declarations in addition to the carrier"
  let candidateImports := uniqueSortedNames (candidate.imports.map (·.module))
  if candidateImports != allowedDirectImports then
    throw <| IO.userError "Candidate direct imports differ from the Builder statement profile"
  let loadedModules := uniqueSortedNames environment.header.moduleNames
  if forbiddenLoadedModules.any fun forbidden => loadedModules.any (· == forbidden) then
    throw <| IO.userError "loaded module closure contains a target or oracle module"
  let some targetInfo := environment.checked.get.find? target
    | throw <| IO.userError s!"requested target has no ConstantInfo: {target}"
  match targetInfo with
  | .axiomInfo _ => pure ()
  | _ => throw <| IO.userError "target declaration is not an axiom carrier"
  if (← originModule environment target) != `Candidate then
    throw <| IO.userError "requested target is not owned by the Candidate module"
  let renderedType ← canonicalType environment targetInfo
  let renderedTypeSha ← sha256Text renderedType
  let replayMode := expectedTypeSha != "-"
  if replayMode && renderedTypeSha != expectedTypeSha then
    throw <| IO.userError "observed carrier type differs from the replay expectation"
  let typeAxioms ← typeObservedAxioms environment targetInfo
  if typeAxioms.any (· == target) then
    throw <| IO.userError "carrier axiom leaked into type-level axioms"
  return Json.mkObj [
    ("candidate_direct_imports", namesJson candidateImports),
    ("candidate_ir_auxiliary_names", namesJson candidateAuxiliaryNames),
    ("candidate_kernel_names", namesJson candidateKernelNames),
    ("candidate_owns_target", Json.bool true),
    ("candidate_source_sha256", Json.str sourceSha),
    ("canonical_type", Json.str renderedType),
    ("canonical_type_sha256", Json.str renderedTypeSha),
    ("carrier_axiom_excluded_from_type_axioms", Json.bool true),
    ("carrier_kind", Json.str "builder_statement_carrier"),
    ("declaration", Json.str target.toString),
    ("declaration_kind", Json.str "axiom"),
    ("lean_version", Json.str "v4.28.0"),
    ("loaded_module_closure", namesJson loadedModules),
    ("mathlib_revision", Json.str mathlibRevision),
    ("proof_eligible", Json.bool false),
    ("replay_expected_type_sha256",
      if replayMode then Json.str expectedTypeSha else Json.null),
    ("replay_mode", Json.bool replayMode),
    ("replay_verified", Json.bool replayMode),
    ("schema_version", Json.str "autolean.library-substrate-builder-query.v1"),
    ("substrate_identity", Json.mkObj [
      ("build_input_sha256", Json.str buildInputSha),
      ("builder_query_helper_sha256", Json.str helperSha),
      ("builder_query_wrapper_sha256", Json.str wrapperSha),
      ("image", Json.str image),
      ("image_receipt_sha256", Json.str imageReceiptSha),
      ("parent_image", Json.str parentImage),
      ("profile_id", Json.str profileId),
      ("profile_sha256", Json.str profileSha),
      ("runtime_manifest_sha256", Json.str runtimeManifestSha)
    ]),
    ("type_observed_axioms", namesJson typeAxioms)
  ]

def main (arguments : List String) : IO UInt32 := do
  try
    let [target, sourceSha, image, expectedTypeSha, imageReceiptSha, buildInputSha,
      runtimeManifestSha, helperSha, wrapperSha, profileId, profileSha, parentImage,
      mathlibRevision] := arguments
      | throw <| IO.userError "expected Builder statement and substrate identity arguments"
    IO.println
      (← query target sourceSha image expectedTypeSha imageReceiptSha buildInputSha
        runtimeManifestSha helperSha wrapperSha profileId profileSha parentImage
        mathlibRevision).compress
    return (0 : UInt32)
  catch error =>
    IO.eprintln s!"autolean-library-substrate-builder-query: {error}"
    return (2 : UInt32)
