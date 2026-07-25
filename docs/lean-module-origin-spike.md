# Lean 4.28 Imported-Declaration Module-Origin API Note

## Status and conclusion

This is an API design note, not a replayable spike result. An early ad hoc source-v2
observation prompted the API investigation, but its probe source, inputs, output, and digest
were not retained. It must therefore not be cited as evidence that particular declarations,
generated forms, or the source-v2 image were tested.

Lean 4.28 exposes a diagnostic lookup for an *imported* declaration in a loaded environment:

```text
env.getModuleIdxFor? info.name -> env.header.moduleNames[idx.toNat]?
```

`getModuleIdxFor?` is the lookup used by Lean's `isImportedConst`; its `none` branch is the
normal branch for a declaration in the current module. The future substrate may use this lookup
only as a fresh, image-owned diagnostic after the executable test below. It does not make module
origin trusted admission evidence, and it does not establish source provenance.

## API boundary

| Field | Value |
| --- | --- |
| Lean API version | Lean 4.28 |
| Query subject | an imported declaration's `ConstantInfo` and its `info.name` |
| Lookup | `env.getModuleIdxFor? info.name`, followed by `env.header.moduleNames[idx.toNat]?` |
| `some idx` result | A module name in the current loaded import closure |
| `none` result | Current-module declaration or another name without an imported-module mapping |

The [Lean 4.28 implementation](https://github.com/leanprover/lean4/blob/v4.28.0/src/Lean/Environment.lean#L1168-L1173)
defines `getModuleIdxFor?` through the environment's imported-constant map and defines
`isImportedConst` using its presence. Its
[persistent-extension guidance](https://github.com/leanprover/lean4/blob/v4.28.0/src/Lean/Environment.lean#L1567-L1578)
directs callers to current-module state when the lookup returns `none`.

`ModuleIdx` is an index into the loaded environment's ordered module array. It is useful for the
immediate lookup only and is not stable across changed import closures or toolchain/runtime
rebuilds. It must never be a manifest identity, a cache key, or a reviewed dependency identity.

## Fail-closed interpretation

For an imported runtime declaration, the successor verifier must treat both absent stages as
insufficient origin evidence:

- `env.getModuleIdxFor? info.name = none`; or
- a returned index has no corresponding `env.header.moduleNames[idx.toNat]?` entry.

It must not infer an imported origin from a declaration's namespace, source-path convention,
import order, or current workspace. A `none` result is normal while compiling the current
`Candidate` module; it cannot establish Candidate ownership or satisfy an imported-runtime
origin check. Candidate ownership instead requires the sealed `Candidate.olean`'s
`ModuleData.constNames` (and the compiled-file record) to name the expected declaration. In a
separate query environment that imports `Candidate`, this API may report `Candidate`, but that
diagnostic does not replace the sealed-module ownership check. Any missing or mismatched evidence
rejects the ordinary-dependency decision.

## What this does not establish

- Neither the unretained ad hoc observation nor this API note supplies an image-owned runtime
  helper or OCI image receipt.
- A module name is not source provenance: it does not bind source bytes, a compiled file, import closure, build command, or runtime tree.
- It does not establish Candidate ownership, declaration kind, canonical type identity, axiom policy, target absence, or complete ordinary-dependency closure.
- It does not change a statement contract, prove a theorem, authorize a proof submission, or satisfy the `independent_reproof` gate.

## Successor manifest shape

The initial `library-substrate-v1` manifest should include one record for every AutoLean
declaration with a `ConstantInfo` in the target-free runtime. The minimum proposed fields are:

- declaration name and declaration kind;
- resolved declaring module name;
- canonical elaborated-type hash and observed axiom set;
- the resolved module's exact `.olean` SHA-256 and the complete runtime-manifest identity; and
- the profile image, Lean/toolchain, Mathlib revision, and ordered import-closure identities that make the module-name lookup meaningful.

The verifier compares its fresh lookup against this frozen record. A module name alone is never
sufficient: the record binds that name to its exact `.olean` identity and the sealed runtime
manifest, then applies the ordinary-dependency policy.

Lean's `ModuleData.extraConstNames` may contain code-generator auxiliary names that are mapped to
a module but have no `ConstantInfo`. Initial `library-substrate-v1` rejects an AutoLean-owned
extra name that cannot be matched to the typed declaration inventory; it does not fabricate a
kind, canonical type, or axiom record. A later profile may admit such names only with a separate,
reviewed schema and verification path.

## Next executable test

Build a small target-free `library-substrate-v1` fixture with at least two AutoLean modules. An
image-owned helper should enumerate the typed declaration inventory, emit the imported-origin
lookup plus declaration kind/type/axiom data for each record, and compare it to a
content-addressed manifest. Candidate ownership remains a separate sealed-`ModuleData` check.
The test passes only when every required imported origin is known and exact. Fixtures with a
missing mapping, a module-name/`.olean` mismatch, an unexpected untyped AutoLean extra name, a
target in the runtime, or reserved-module shadowing must reject. This is a preflight for later
image/contract/gateway work, not an admission result.
