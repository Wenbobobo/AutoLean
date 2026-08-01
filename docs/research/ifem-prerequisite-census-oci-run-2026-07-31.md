# iFEM Prerequisite Census OCI Run, 2026-07-31

Status: audit-fixed local diagnostic; completed execution, 21 unknown classifications, no
semantic, coverage, freeze, promotion, or Prover-handoff authority

## Bound execution

- Plan content SHA-256: `b24081ac1de564189ea10804665224cbdead963af3f737852e2de4d610cf8de8`
- Lean toolchain: `leanprover/lean4:v4.28.0`
- Mathlib revision: `8f9d9cff6bd728b17a24e163c9402775d9e6a365`
- Lake manifest SHA-256: `e2a93c904f51195d6740cd9abfb35ab155dc0157e0e46642dce0d364b68a9a89`
- Docker Engine: `29.1.3`, classic builder, build pull disabled
- Base image: `sha256:6c54c3600b2572ddcabae024a3a8b6c533c3defa6d4bda31c90408cb4c61f0ab`
- Audit-fixed child image: `sha256:56cc9cf71af30ceede1f7feec3ff2e410007372c5300bd8d995b991517229156`

The child has the base image's exact nine-layer RootFS prefix plus three child layers. Its runtime
identity is `65532:65532` at `/work`. The build checks the base Mathlib revision, manifest hash and
Lean toolchain; runtime uses a read-only root, no network, dropped capabilities,
`no-new-privileges`, bounded processes/memory, and a restricted temporary filesystem.

## Public projections

| Artifact | File SHA-256 | Content SHA-256 |
| --- | --- | --- |
| [Build receipt](ifem-prerequisite-census-oci-receipt-2026-07-31.json) | `1d4dbf90dad157814c557ddc65016ddb79de094b027c498778e2f3f17d5d8e22` | `91e79e29ff827b0cf53d7318200c1402cafef964ad330bc42329898d1231328a` |
| [Normalized observation](ifem-prerequisite-census-oci-observation-2026-07-31.json) | `f04e27a183e2ced5e16df7bb7f5e0bca29b9ff3e44532147062672228c2c9488` | `4ba2944578c1e59cb83d362c90384a3b1b5fb8ea05ec38f3893a5c38e5007aed` |
| [Unknown-only result](ifem-prerequisite-census-oci-result-2026-07-31.json) | `fd1111a91234755ae1308b2d4bfe0b329a000c3449e48abe80ccef5ad6a326b7` | `fbaf12b9f9979131f1ce2f7075808c0141e4a5933046b6a369a2f75818016165` |
| [Execution envelope](ifem-prerequisite-census-oci-execution-2026-07-31.json) | `204d70dc7fd7cde3987410a8ad3e53c634bd89ba32409e11caae5af5fe2f07c1` | `5b04fca9492a113a9e69060aa58d62f7004a2e5f9b36c7934d6dcbbc4482be32` |

These projections contain fixed plan/environment data and public Mathlib declaration metadata;
they contain no textbook source text, prompts, credentials, or model responses. The raw stdout is
retained only under the operator evidence root because public-release policy rejects raw JSONL.
Its committed hash is
`ae69a80ba23bdfef619f1129e8f7c5a7b4ceeac0cebb6dccf33eae8f69cf0b49`.

## Replay result

Two fresh isolated runs produced byte-identical raw stdout, observation, result, and envelope.
The audit-fixed `verify-execution` command then loaded all five artifacts with duplicate-key
rejection, revalidated the current child and base environment, rebuilt the normalized observation
and exact unknown-only result, recomputed the envelope, reran the exact container command, and
required byte-identical stdout. It returned receipt content SHA-256
`91e79e29ff827b0cf53d7318200c1402cafef964ad330bc42329898d1231328a`.

The corresponding immutable [P2-08 successor](ifem-pilot-readiness-decision-2026-07-31-oci-successor.json)
binds the completed result and remains `incomplete`: 21 unknown, no supplied profile evidence,
unresolved closure policy, Builder freeze forbidden, and Prover handoff forbidden.

## Boundary

This run proves that the pinned execution and evidence-replay path works for the fixed query. It
does not prove that an observed Mathlib declaration faithfully implements any textbook node. A
semantic reviewer or future machine-advisory quorum must still produce the evidence required by
the Builder classification contract; until then the only valid classification is `unknown`.
