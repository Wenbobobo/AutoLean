# Mathlib Downstream Build Boundary

`Library/` consumes a frozen public mathlib release. It is a separate Lake
project, not a mathlib fork, and no build or review step may patch
`.lake/packages/mathlib`.

## Reproducible local build

`uv run python Library/scripts/verify.py check` validates the committed Lean
toolchain, direct mathlib request, complete package closure, every resolved
commit, and the tracked model-theory compile receipt without touching Lake.
`verify-receipt` additionally dispatches to WSL and rehashes the current ext4
dependency cache. A missing cache or any changed cache path, byte, link,
manifest, or identity fails closed.

`uv run python Library/scripts/verify.py build` runs Lake only in WSL on an
ext4 cache. It creates a new copy of the authoritative build inputs for every
build and a new local Lake build directory. That allowlist is exactly
`lean-toolchain`, `lakefile.lean`, `lake-manifest.json`,
`AutoLeanLibrary.lean`, and `AutoLeanLibrary/**/*.lean`. Relative paths are
normalized to POSIX form and sorted by UTF-8 bytes before hashing and copying.
Docs, records, receipts, and ignored evidence are not Lake inputs and cannot
create a self-referential source digest. The receipt binds its packet and
verifier-script digests separately.

The cache has one dependency seed per cache/tree schema and hash of
`lean-toolchain`, `lakefile.lean`, and `lake-manifest.json`. The first run may
download the exact locked package sources and mathlib olean cache. A canonical
manifest stored outside the linked package tree records every directory,
regular-file SHA-256 and byte count, and permitted relative source symlink in
UTF-8 byte order. Git metadata is excluded, but all package source bytes and
generated `.lake/config` and `.lake/build` bytes are included. Generated
build/config symlinks, escaping links, junctions, and unsupported file types are
rejected. The build report and tracked receipt bind both the raw manifest
SHA-256 and canonical tree SHA-256 plus entry/file/link counts and total bytes.
The tree is rehashed before reuse and after the build.

This byte manifest makes the observed cache replayable and detects ordinary
pollution, including a locally rewritten cache manifest because the tracked
receipt retains the prior digests. It is not proof that the initially observed
bytes were produced by a trusted clean build, and it cannot defend against a
same-user attacker modifying the verifier during its run. This remains local
diagnostic evidence. Promotion requires a separately attested, digest-pinned
mathlib-capable OCI verifier.

The build targets are deliberately limited to `AutoLeanLibrary`, the three-node
fixture terminal `AutoLeanLibrary.Fixtures.Dag.Certificate`, and the
non-promotable semantic-boundary terminal
`AutoLeanLibrary.Fixtures.ModelTheory.Packet`. A passing result establishes
that those pinned local inputs built in that WSL environment. It does not
establish source fidelity, theorem acceptance, independent verification, or an
authoritative OCI result.

The model-theory packet is an API compatibility probe for two deliberately
different Builder candidates: closed sentences without a free-variable
assignment and open formulas with an explicit assignment. Its staged record
retains the missing quantifier/freshness bridge. It does not select either
candidate, formalize a calculus, or prove soundness.

For a durable local replay record, pass a fresh path below `Library/evidence/`:

```text
uv run python Library/scripts/verify.py build --evidence-out Library/evidence/<run-id>.json
```

Evidence files contain hashes and version strings only. They omit absolute
paths and raw Lake stdout/stderr. Do not overwrite an evidence file; a repeat
run uses a new name.

The tracked staged v2 compile receipt embeds the corresponding public-safe report
and its canonical digest. The packet references the receipt file digest, while
the receipt hashes packet content without that backlink. This one-way content
hashing rule avoids a packet/receipt hash cycle. Any change to a Lean input,
packet claim, verifier script, environment pin, dependency-tree digest, target,
report, or receipt makes `check` fail closed. `verify-receipt` additionally
requires the current WSL cache and rehashes its bytes against that tracked
dependency-tree binding.

## Promotion boundary

The fixture is wiring coverage only and must never be exported by the public
root or used as theorem evidence. A promoted module may import mathlib public
APIs and other promoted modules only. It must not import `Staging/`, a fixture,
or implementation-private files below `.lake/`.

Promotion still requires a frozen `StatementContractV1`, semantic review,
proof-boundary fidelity, a pinned environment, and independent verifier
evidence. A local WSL build cannot replace any of those gates. Proof failure
remains a gap or a Builder-owned contract-change request; it does not authorize
a weaker public theorem.
