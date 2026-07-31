# iFEM pinned-profile child-image build observation

Date: 2026-07-31

Status: two bounded OCI build failures retained as history; the corrected active plan subsequently
built a receipt-bound child image and produced two byte-identical five-profile observation/result
pairs. This is pinned-environment visibility evidence only.

## Bound attempt

The first WSL2/Docker execution used profile-plan content SHA-256
`8e4aa8b23a7196104c786fe1fa4779eaed56e7193d2afb06c8017f274bf4bd18` and fixed parent image
`autolean/mathlib-worker@sha256:3237192cf627a05367c75d46e61ec9034fefe43a4fd0c06139e38c80358648d6`.
The staged build context contained only the plan-bound Dockerfile, Lean helper, and wrapper. Docker
used `--network=none --pull=false`; the parent image was already present locally.

The `lake build` step completed all 2,339 dependency jobs, including the five requested target
OLeans. The next command failed before the helper OLean, image-owned manifest, child image, or build
receipt could be created. Lean 4.28 rejected the helper source because
`/opt/autolean/lib/AutoleanIFEMPinnedProfileQuery.lean` was outside the Lake root
`/opt/mathlib`.

This is a build-path failure, not a declaration observation, coverage result, semantic mapping, or
Lean theorem result. The failed attempt produced no normalized P2-07 input and cannot affect a
P2-08 decision.

## Successor correction

The first successor plan had content SHA-256
`bea57f16f0300eb820eaec9c10cdc7ebe4c8afcdcd9285a93dcc76ca281452e3`. It made two bounded changes:

- the helper source and OLean now live below `/opt/mathlib`; and
- the expensive five-module `lake build` is a separate Docker layer before helper/wrapper copies,
  so query-source changes do not invalidate the pinned Mathlib closure cache.

Its real build committed the separate 2,339-job closure layer, then failed while compiling the
helper: Lean 4.28 inferred bare `return 0` / `return 2` literals as `Nat` where `main` requires
`UInt32`. No final image tag or receipt was created. The active successor explicitly types those
two exit-code literals and has content SHA-256
`21bd18f7f8522470247852ef8281f1e4c7016f6415771e4fc0c05ab433247619`; the expensive closure layer
remains reusable.

Across all revisions, the denominator, parent image, Lean/mathlib environment, candidate
declarations, five singleton imports, negative control, observation schema, and all non-authority
flags are unchanged. At the point of the second failure, the active plan still had to build,
verify, and run from a fresh content-addressed child-image tag before any observation could be
claimed. That requirement was subsequently met by the evidence recorded below.

## Completed active-plan evidence

The active profile plan has content SHA-256
`21bd18f7f8522470247852ef8281f1e4c7016f6415771e4fc0c05ab433247619`.
It successfully produced the local child image
`sha256:6c54c3600b2572ddcabae024a3a8b6c533c3defa6d4bda31c90408cb4c61f0ab`.
The persisted child-image build-receipt file SHA-256 is
`c859ec69ec46a2344f42a4e42f17b6922ade51c92d1bb22c674c7a4885185f26`; its
embedded `content_sha256` is
`80659121feb8a831c6255879f7cf6d1230d1cd64e8272559523ef99aeab68251`.

The five-profile collector was run twice against that receipt-bound child image. Both runs wrote
byte-identical normalized artifacts:

| Artifact | File SHA-256 | Embedded `content_sha256` |
| --- | --- | --- |
| Observation | `1900a11003a78ecaa681ad76ab5660762d4f5ca81e28b0b9525a95998131d736` | `0dee6c5b7e4c0db81fb20e9821e2fd2eede727d9552d7fe4a7def7b6b6b1a348` |
| Result | `ba9ca42865fd385fbf94b922e4111dd76ab9dec4386f28bbba778779dfc52298` | `55e9c0f95d9634dc39fb37cd1b00a97575cbc91090c15701d39f8e3868110238` |

Each query ran with network disabled, a read-only root filesystem, all Linux capabilities dropped,
`no-new-privileges`, UID/GID `65532:65532`, and no host checkout, cache, socket, home directory,
or bind mount. The collector used the five exact singleton direct imports and observed the
following loaded-module closure sizes and present-candidate counts out of the fixed 25 candidates:

| Profile | Exact direct import | Closure modules | Present candidates |
| --- | --- | ---: | ---: |
| `Defs` | `Mathlib.Analysis.InnerProductSpace.Defs` | 3,685 | 13/25 |
| `Dual` | `Mathlib.Analysis.InnerProductSpace.Dual` | 4,198 | 23/25 |
| `LaxMilgram` | `Mathlib.Analysis.InnerProductSpace.LaxMilgram` | 4,199 | 25/25 |
| `Operator.Basic` | `Mathlib.Analysis.Normed.Operator.Basic` | 3,666 | 14/25 |
| `Operator.Bilinear` | `Mathlib.Analysis.Normed.Operator.Bilinear` | 3,667 | 19/25 |

## Boundary and remaining census gap

An exact direct import is an input-identity fact, not a proof that its transitive closure is narrow.
The measured closures are in the thousands of modules. No closure-width acceptance policy has been
approved; whether any of these closures is sufficiently narrow remains pending independent review.
The observations establish only declaration metadata visibility in the pinned environment. They do
not establish a mathematical mapping, semantic classification, 21-node coverage, source rights,
Builder freeze, Prover handoff, or proof result.

Separately, the generic-host WSL census run against the checkout under `/mnt/c` reached its internal
600-second bound. It wrote neither a census observation nor a census result, and its temporary query
was cleaned up. The frozen census manifest therefore remains historically `not_started`; this failed
execution does not create a P2-06 classification or a P2-08 input or decision.

The tracked
[public projection](ifem-pinned-mathlib-profile-public-summary-2026-07-31.json)
retains the environment, image, artifact hashes, exact direct imports, closure
hashes/counts, declaration visibility metadata, and all non-authority flags,
while omitting canonical type text and closure members. Its file/content
SHA-256 values are
`0be217308b3476224830c2f3ce7e763501d86f448d30498d17542a69e6efd460` /
`e17550cedca856cad4becfa706a927399157f9037a412a3cc0445b846f83989e`.
The full receipt and raw observation remain outside the repository and are
required to reproduce this projection.
