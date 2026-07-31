# iFEM Fixed Mathlib Profile Query

This is a fixed-profile discovery observation lane for the frozen iFEM prerequisite
denominator. It answers one operational question: which candidate declaration metadata is
visible under each of five deliberately singleton Mathlib *direct-import* profiles in one
pinned environment. It does not map a declaration to a textbook concept, classify coverage,
accept the breadth of the resulting transitive module closure, freeze a Builder contract, or
submit a Prover task.

"Singleton" describes only the source-level direct-import list. Every observation also records
the complete loaded-module closure; the term does not claim that this closure is small, minimal,
or free of circular dependencies relative to the intended iFEM construction.

## Frozen boundary

[`Builder/pilots/discovery/ifem-pinned-mathlib-profile-plan.v1.json`](../Builder/pilots/discovery/ifem-pinned-mathlib-profile-plan.v1.json)
is the frozen plan. Its `state` field remains historically `not_run`; completed evidence is recorded
in separate receipt-bound artifacts and must not rewrite that manifest status. It binds:

- the current iFEM census plan and its 21-node prerequisite denominator;
- the exact parent image identity, Lean toolchain, Mathlib revision, and Lake manifest;
- one five-profile vocabulary: `Defs`, `Dual`, `LaxMilgram`, `Operator.Basic`, and
  `Operator.Bilinear`;
- the sorted 25-declaration census-derived candidate inventory and one negative control;
- the Dockerfile, Lean helper, and wrapper bytes; and
- the required observation fields: declaration origin, canonical type, observed axioms, loaded
  module closure, and an absent negative control.

The plan can only be regenerated from the frozen census and current three image inputs. The
writer is create-once: it accepts identical bytes on replay and refuses a different plan at the
same path.

```text
uv run --frozen python scripts/ifem_pinned_mathlib_profiles.py materialize-plan
uv run --frozen python scripts/ifem_pinned_mathlib_profiles.py check-plan
```

## Child image and receipt

`Prover/worker/Dockerfile.ifem-pinned-profile-query` starts from the exact parent-image digest
and builds only the fixed helper plus the five imported module OLeans. The orchestrator copies
only the Dockerfile, helper, and wrapper into a newly created temporary context, verifies every
hash against the plan, and invokes Docker with `--network=none` and `--pull=false`. The builder
does not build from the checkout root.

On success, `build-child-image` writes a content-addressed build receipt. Its `child_image` is a
local Docker image ID (`sha256:...`), not a claim that a registry image was published. The
receipt binds the plan, fixed parent, staged-context hash, image ID, and all three source hashes.
The verifier then checks the image ID, non-root user, working directory, and image labels before
any query can run.

```text
uv run --frozen python scripts/ifem_pinned_mathlib_profiles.py build-child-image --receipt-out <receipt-json>
uv run --frozen python scripts/ifem_pinned_mathlib_profiles.py verify-child-image --receipt <receipt-json>
```

No Docker build was run to create the tracked plan or this document. The active plan has now been
executed as evidence collection: its content SHA-256 is
`21bd18f7f8522470247852ef8281f1e4c7016f6415771e4fc0c05ab433247619`, its local child image is
`sha256:6c54c3600b2572ddcabae024a3a8b6c533c3defa6d4bda31c90408cb4c61f0ab`, and its
build-receipt file/content SHA-256 values are respectively
`c859ec69ec46a2344f42a4e42f17b6922ade51c92d1bb22c674c7a4885185f26` and
`80659121feb8a831c6255879f7cf6d1230d1cd64e8272559523ef99aeab68251`.

## Isolated observation

Each query starts a separate container by image ID. Its default runtime policy is network none,
read-only root filesystem, all Linux capabilities dropped, `no-new-privileges`, unprivileged
UID/GID `65532:65532`, PID limit `128`, memory limit `2g`, and an explicitly bounded temporary
filesystem. No checkout, source cache, Docker socket, host home directory, or arbitrary mount is
provided.

The wrapper verifies its own helper and wrapper hashes plus the image-owned OLean manifest before
running Lean. The raw record contains the hashes of all six built OLeans: the helper and five
profile modules. The normalizer requires every profile to report the same manifest and OLean
inventory. It produces a content-addressed observation receipt with plan hash, child image ID,
environment pins, helper/wrapper hashes, per-profile records, loaded closures, declaration
origin/type/axiom observations, and the negative-control result.

```text
uv run --frozen python scripts/ifem_pinned_mathlib_profiles.py run --receipt <receipt-json> --observation-out <observation-json> --result-out <result-json>
```

`normalize` supports an interrupted collection only when supplied with the verified build
receipt as well as all five image-owned raw records. It cannot attach raw output to an arbitrary
image ID.

`public-summary` reloads the exact plan, receipt, observation, and result, verifies their
relationships, and emits a write-once public projection. It keeps file/content hashes, environment,
image and OLean identities, exact direct imports, closure hashes/counts, declaration visibility,
origins, axioms, and non-authority flags. It omits canonical type text and closure members.

```text
uv run --frozen python scripts/ifem_pinned_mathlib_profiles.py public-summary \
  --receipt <receipt-json> --observation <observation-json> \
  --result <result-json> --out <public-summary-json>
```

The real 2026-07-31 projection is retained as
[`research/ifem-pinned-mathlib-profile-public-summary-2026-07-31.json`](research/ifem-pinned-mathlib-profile-public-summary-2026-07-31.json),
with file/content SHA-256
`0be217308b3476224830c2f3ce7e763501d86f448d30498d17542a69e6efd460` /
`e17550cedca856cad4becfa706a927399157f9037a412a3cc0445b846f83989e`.

The collector completed all five fixed profiles twice with byte-identical normalized outputs. The
observation file/content SHA-256 values are respectively
`1900a11003a78ecaa681ad76ab5660762d4f5ca81e28b0b9525a95998131d736` and
`0dee6c5b7e4c0db81fb20e9821e2fd2eede727d9552d7fe4a7def7b6b6b1a348`; the result file/content
SHA-256 values are respectively
`ba9ca42865fd385fbf94b922e4111dd76ab9dec4386f28bbba778779dfc52298` and
`55e9c0f95d9634dc39fb37cd1b00a97575cbc91090c15701d39f8e3868110238`.

| Exact direct import profile | Loaded-module closure | Present candidates |
| --- | ---: | ---: |
| `Defs` | 3,685 | 13/25 |
| `Dual` | 4,198 | 23/25 |
| `LaxMilgram` | 4,199 | 25/25 |
| `Operator.Basic` | 3,666 | 14/25 |
| `Operator.Bilinear` | 3,667 | 19/25 |

## Non-claims and next boundary

The plan, build receipt, observation receipt, and result set all authority flags for
mathematical mapping, semantic classification, coverage claims, Builder freeze, Prover handoff,
and proof submission to `false`. A name hit, a type match, or a zero-axiom declaration remains an
environment fact. The later iFEM readiness gate may consume a completed receipt as evidence that
the direct imports match the frozen profiles. P2-08 v2 keeps transitive-closure acceptance as a
separate unresolved policy, so these observations alone cannot authorize a `go`, even after
independent semantic classification evidence arrives.
