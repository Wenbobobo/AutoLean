# Lean 4.28 Declaration Module-Origin Spike

## Conclusion

Lean 4.28 exposes a usable *diagnostic* declaration-to-module lookup for a loaded environment. In the fixed source-v2 environment, the probe resolved the declarations it covered through:

```text
env.getModuleIdxFor? info.name -> env.header.moduleNames[idx.toNat]?
```

This closes one API-discovery question for the future target-free substrate. It does not make module origin trusted admission evidence: the probe was not image-owned, is not bound to a contract or manifest, and does not establish source provenance.

## Fixed observation boundary

| Field | Value |
| --- | --- |
| Lean environment | Lean 4.28 source-v2 worker environment |
| Fixed image | `autolean/mathlib-worker@sha256:3237192cf627a05367c75d46e61ec9034fefe43a4fd0c06139e38c80358648d6` |
| Query subject | a loaded declaration's `ConstantInfo` and its `info.name` |
| Lookup | `env.getModuleIdxFor? info.name`, followed by `env.header.moduleNames[idx.toNat]?` |
| Result class | observed module name, or `unknown` |

The probe covered declarations from different namespace/module combinations, generated and equation declarations, an imported `Candidate` declaration, and `Init`. Those cases show that the lookup is useful across the specific declaration forms relevant to the first substrate split. They do **not** establish coverage for every Lean declaration kind, generated name, or future toolchain revision.

## Fail-closed interpretation

The successor verifier must treat both absent stages as `unknown`:

- `env.getModuleIdxFor? info.name = none`; or
- a returned index has no corresponding `env.header.moduleNames[idx.toNat]?` entry.

It must not infer an origin from the declaration's namespace, source-path convention, import order, or the current workspace. A declaration from the current module is accepted as such only when this exact lookup resolves to the expected current module name; it is not a fallback for an unresolved declaration. Any `unknown` or mismatch against the frozen manifest rejects the ordinary-dependency decision.

## What this does not establish

- The probe is not an image-owned runtime helper and is not covered by an OCI image receipt.
- A module name is not source provenance: it does not bind source bytes, a compiled file, import closure, build command, or runtime tree.
- It does not establish Candidate ownership, declaration kind, canonical type identity, axiom policy, target absence, or complete ordinary-dependency closure.
- It does not change a statement contract, prove a theorem, authorize a proof submission, or satisfy the `independent_reproof` gate.

## Successor manifest shape

The `library-substrate-v1` manifest should include one declaration record for every AutoLean declaration in the target-free runtime. The minimum proposed fields are:

- declaration name and declaration kind;
- resolved declaring module name (and, if retained for diagnostics, its module index);
- canonical elaborated-type hash and observed axiom set;
- the module's exact compiled-file identity and the complete runtime-manifest identity; and
- the profile image, Lean/toolchain, Mathlib revision, and ordered import-closure identities that make the module-name lookup meaningful.

The verifier compares its fresh lookup against this frozen record. The module name alone is never sufficient: the record is reviewed together with the sealed runtime manifest and the ordinary-dependency policy.

## Next executable test

Build a small target-free `library-substrate-v1` fixture with at least two AutoLean modules and one generated/equation declaration. An image-owned helper should enumerate its complete AutoLean declaration inventory, emit the lookup result and declaration kind/type/axiom data for each entry, and compare it to a content-addressed manifest. The test passes only when every origin is known and exact; fixtures with a missing mapping, manifest/module mismatch, target in the runtime, or reserved-module shadowing must reject. That is a preflight for the later image/contract/gateway work, not an admission result.
