# Library Substrate Image Preflight

Status: operator-local image-owned preflight verified; not admitted and not V2-integrated

Observed date: 2026-07-25

## Result and authority boundary

The focused `library-substrate-v1` implementation now has one real, offline build and
independent-reproof canary:

| Evidence | Observed value |
| --- | --- |
| Exact parent | `autolean/mathlib-worker@sha256:3237192cf627a05367c75d46e61ec9034fefe43a4fd0c06139e38c80358648d6` |
| Docker-recorded child RepoDigest | `autolean/library-substrate@sha256:5a71d357ce26e07a44bcce43dc26de06dd8470d2dda5f7341ffdfa2fe9e3dd2e` |
| Child image ID | `sha256:5a71d357ce26e07a44bcce43dc26de06dd8470d2dda5f7341ffdfa2fe9e3dd2e` |
| Build-input SHA-256 | `858b1dafb9150e117eb0886fd53cf5d4707b5c42880e5374ebab7c9a94066883` |
| Raw child receipt SHA-256 | `02f7fd99edbc29f817e2f87477fb6f4b69364b160a5659e5b2ccb8eab8e59fa9` |
| Runtime-manifest SHA-256 | `923914c53d499eb21d405035ecc0df7ee145eda570bd476b799c7011ba287817` |
| Runtime-source checksum-manifest SHA-256 | `e6638ec0117dcb0b700e695b760bb32c87bb7290b38ed98329d158e92e2ed2f3` |
| Query-wrapper SHA-256 | `f1c09f0002af1b0729305534433286659e4af343c78a01b2d9873b368348d8d3` |
| Runtime closure | 3 Library `.olean` files, 77 typed AutoLean declarations, 22 IR auxiliaries |

The RepoDigest above came from Docker's `RepoDigests` inspection field. The runner refuses to
invent a `repo@sha256:...` reference from an image ID. This is local technical evidence only:
the image has not been pushed to a registry, signed by the production verifier authority,
admitted into a frozen contract, or exercised through the OCI V2 evidence and signing gateway.

## Exact build boundary

[`library_substrate_image.py`](../Library/scripts/library_substrate_image.py) creates a fresh,
exact build context. It contains:

- the child Dockerfile and one canonical build-input record;
- four image-owned helper assets; and
- exactly the `Core`, `SemanticPrelude`, and `RulePrelude` Library sources selected by the
  `independent_reproof` profile.

The build command fixes `--no-cache --pull=false --network=none`; Dockerfile syntax uses only
the standard builder instructions and does not require a floating Dockerfile frontend. Both stages
use the exact source-v2 digest. The builder compiles only those three profile modules. The child layer adds
only their `.olean` files, the build input, inventory/manifest/receipt records, and the two
image-owned helper programs under `/opt/autolean/library-substrate`.

The three Library runtime module source files and their `.ilean` files are absent from that
dedicated final tree. This is deliberately not a claim that every parent-image source or every
piece of Lean text is absent from the whole child image. In particular, the independent query's
Lean program is embedded in a here-document inside the hashed query wrapper and materialized
only in a temporary, read-only-container run.

The source-v2 Dockerfile, receipt, and historical `UniversalLK.lean` inputs remain unchanged.
The fresh context never includes the aggregate module, target modules, controls, Candidate
source, or any host `/deps` tree.

## Receipt and inventory semantics

The build input lists each of the three source paths, sizes, and SHA-256 values, plus the
canonical source-record tree hash. Staging writes an exact `runtime-sources.sha256` checksum
manifest. The image build verifies that manifest with `sha256sum --check`, rechecks every staged
source hash and size against the build input, and recomputes the tree hash before compiling. The
source-manifest hash is carried by a build argument, build input, runtime manifest, and image
receipt. The host verifier retrieves the image-owned build input and source manifest from the
fixed Docker RepoDigest, then independently rereads the current three profile sources and
recomputes all per-file hashes, sizes, manifest bytes, and the tree hash. A source change between
input capture and context staging is therefore rejected instead of silently changing compilation.

`runtime-files.sha256` has a separate role: it is the exact three-line checksum manifest for the
final `.olean` files. The image-owned receipt command validates it, parses the runtime manifest,
and recomputes the hash and size of each fixed runtime path before emitting the receipt. The host
verifier repeats those hash and size calculations from the fixed Docker RepoDigest, reconstructs
the checksum-manifest bytes, and requires the reconstructed hash to agree with both runtime
manifest and receipt. Typed and IR inventory origins are accepted only after this actual-file
closure; a fresh query that omits the origin `.olean` hash is supplemented only from that closed
fact.

The child binds two distinct observations of the parent receipt:

- `parent_receipt_file_sha256` is the hash of the exact in-image receipt file bytes:
  `ce2a2a6f0dbaf7eb8e873ec952ee5ee04bbd8d5cafe214bac08fa8c114c3e356`;
- `parent_receipt_canonical_sha256` is the host-derived hash of the parsed record rendered as
  canonical JSON:
  `40e15776cec80a03b9d5b0affd59a3f613b7f1855c48aa0c1e91f24ec0e1eed7`.

The image-owned receipt command emits the raw child receipt file, and its reported receipt hash
binds those bytes. Canonical record hashes reported by the host are derived comparisons; they
are not represented as a second hash implicitly bound by the same raw byte stream.

For each typed AutoLean declaration, the inventory records its name, declaration kind,
canonical type and type hash, observed axioms, imported module name, and origin `.olean` hash.
`ModuleIdx` is used only to resolve the module name and is never treated as stable identity.

Lean's module data also lists code-generation/IR auxiliaries in `extraConstNames`. These names
are intentionally absent from kernel `ConstantInfo`; suffix-based filtering would be incorrect.
The preflight records every one in a separate, sorted `ir_auxiliary_names` inventory and requires:

- no overlap with any kernel declaration or reserved target/module identity;
- a matching `Lean.IR.findEnvDecl` entry whose declaration name is exact;
- an `fdecl` or `extern` IR declaration kind;
- exact imported-module origin and origin `.olean` hash; and
- global uniqueness plus a receipt-bound aggregate hash.

The image canary regenerates both inventories from the runtime `.olean` files and requires exact
replay against the manifest.

The content receipts above are replayable for the observed image. Two measured no-cache builds
produced different image identities (`bb271a4362f4b3a7fc7e858f9d8349790cbdf8191a53085c95e3d9b1fa860903`
and the recorded final digest above), while their build input, both checksum manifests, runtime
manifest, raw receipt, and all three `.olean` hashes matched. This is not a claim that two Docker
builds are byte-identical or will always have the same content: Docker image/config metadata can
vary between builds. Every verify or canary invocation therefore requires the specific
Docker-recorded RepoDigest it is evaluating.

## Independent Candidate query

The image-owned query compiles the fixed independent Candidate in one container, copies only the
resulting regular `Candidate.olean` into a separately sealed read-only mount, and queries it in a
fresh container. The query proves that:

- the target is owned by sealed `Candidate.olean`, not imported from the runtime;
- Candidate kernel and IR-owned names are mutually unique and disjoint from the complete runtime
  kernel-plus-IR ownership sets;
- Candidate IR auxiliaries have real IR declarations and `Candidate` module origin;
- direct imports and the loaded closure match the independent profile;
- the target canonical type and observed axioms match the historical diagnostic;
- the proof expression does not directly use `Deriv.sound`; and
- the query is bound to the runtime manifest, raw image receipt, query wrapper, and profile hash.

The helper lives at
`/opt/autolean/library-substrate/bin/autolean-library-substrate-independent-query`. It does not
occupy `/opt/autolean/bin/autolean-lean-wrapper`, does not implement
`autolean.oci-lean-wrapper.v2`, and is not a drop-in `OciLeanRunner` adapter. It emits neither V2
OCI evidence nor a gateway receipt. A separate integration change must adapt this verified
runtime/query boundary to the existing V2 compile/query and evidence protocol.

## Operator commands

From the repository root:

```text
uv run --frozen python -m Library.scripts.library_substrate_image build
uv run --frozen python -m Library.scripts.library_substrate_image verify --image <recorded-repodigest>
uv run --frozen python -m Library.scripts.library_substrate_image canary --image <recorded-repodigest>
uv run --frozen python -m Library.scripts.library_substrate_image all
```

Windows delegates the Docker work to WSL `Ubuntu-24.04`; Linux runs it natively. `verify` and
`canary` require the exact Docker-recorded child RepoDigest.

Focused negative tests cover context leakage, missing offline flags, fabricated child references,
source-to-context TOCTOU, source checksum-manifest drift, synchronized runtime
manifest/inventory/checksum forgery against unchanged actual `.olean` bytes, typed/IR inventory
drift, invalid IR kind and origin, kernel/IR/target collisions, forbidden pilot theorems, exact
target-type collision, and accidental V2-wrapper claims.

## Non-claims and next gate

This preflight does not implement a contract, the signing gateway, a provider run, an external
dependency capsule, formal-asset admission, or T6. It is limited to `independent_reproof`;
`compositional_bridge` and external `/deps` remain deferred.

The next Prover step is a narrow V2 adapter and adversarial integration suite that carries the
verified child digest, runtime-manifest identity, task mode, type/origin inventory, Candidate
ownership, and ordinary-dependency observation through OCI evidence and gateway replay. Builder
admission and semantic review remain separate prerequisites.
