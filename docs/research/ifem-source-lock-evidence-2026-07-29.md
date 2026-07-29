# iFEM opening-source lock evidence — 2026-07-29

Status: acquired and independently replayed as `local_only`; this is source-byte and rights
evidence only. It does not authorize model egress, statement extraction, semantic admission,
contract freeze, Prover handoff, Mathlib coverage, or a mathematical claim.

## Bound source

- Repository: `JSchoeberl/iFEM`
- Revision: `a4ab841c4e5ec726e9b7742c9dcb352cb9645736`
- License: CC BY 4.0
- LICENSE Git blob: `7aa2c7d055857957fc9464109c305df6916f3f30`
- LICENSE SHA-256: `91030ffc2d2f295670d43f67ac5c9f9ee7b9ace6609f5bcf6990fbd68f2665a0`

The fixed files were fetched as exact base64 repository objects through the GitHub connector,
then imported with `scripts/ifem_source_lock.py import-staged`. The staging boundary rejects
links, junctions, missing files, and unexpected files, and then reuses the same license, UTF-8,
notebook, size, content-addressed cache, and receipt checks as the direct downloader.

## Retained identities

- Connector staging manifest SHA-256:
  `95d615bddb3052ed9889ae195aeb23853276c3a2871637f67415cbf7793f8f79`
- Connector file count and size, including LICENSE: 14 files, 94,690 bytes
- Source-lock receipt SHA-256:
  `74eca6689fe69dcbf2f34ea524a99cacc2054c0a39cfecfb11887c29e13cf239`
- Reference-manifest candidate SHA-256:
  `4a5d859d77b606d6e485d98bd3e4afc41f6c566c6fb09f5e3dc2b2a539f18398`
- Selected source count and size: 13 files, 94,391 bytes
- Retrieval time recorded by the receipt: `2026-07-29T11:47:23.423056Z`

| Source path | Bytes | SHA-256 |
| --- | ---: | --- |
| `README.md` | 1,492 | `62aa66f193108b7d283586d14f2849767565680e2c76d3dfb5b46fc0b2bb1ba6` |
| `_toc.yml` | 5,949 | `8ab222e417632a3d91734dc74befbbd2363cdb0f1ea6c56ab9e750688610f9f6` |
| `intro.md` | 4,063 | `050ca6a5f175c9f813d19b5185c8e6a8edbf78607da7f9c91ee5516486d94eec` |
| `primal/first_example.ipynb` | 16,575 | `e6541ed4074229c9026393617d093fc9b1b85386bc3b459a56c9541caae7e74e` |
| `primal/boundary_conditions.ipynb` | 10,355 | `43e7b5bff828ee4612841717bdca00227104e6b97289d78b2aba98883b55766d` |
| `primal/subdomains.ipynb` | 5,999 | `4d40026cbe5672cd1a8ab93bc5602cdeabcfb7b91f065c4c86ad5d43100ff148` |
| `primal/solvers.ipynb` | 4,149 | `050376fcca020ef60c602db7420d5e47fe0da53be4bf1b8d69b33de3ca149228` |
| `primal/elasticity3D.ipynb` | 6,592 | `41069d45da4dd8940b977d207900a38ae548098b487312e791f8171778be2864` |
| `primal/exercises.ipynb` | 4,483 | `fc407a09e90f748211da610e8663c1bd918396133d26fa770f05055b99a7df60` |
| `abstracttheory/BasicProperties.ipynb` | 11,659 | `7b20840c2ff59190cb7382112393d2915eb36027d7c5a44e677e603626f77dc0` |
| `abstracttheory/subspaceprojection.ipynb` | 5,095 | `5a7f65cba4aaeac216b708122c8531768b9e345418b0710c9b29edb2107e20f5` |
| `abstracttheory/RieszRepresentation.ipynb` | 5,366 | `a648426db404e4ef9395c8f975adf0265b32a0459e8b30c5bfb13372ec3e4c8f` |
| `abstracttheory/Coercive.ipynb` | 12,614 | `7cf7b9fa8a9252bd4d799264059fd009c0d07e13fdb8bf12221c62c49bd899f9` |

## Replay

The cached bytes were independently re-read and rehashed with:

```text
uv run --frozen python scripts/ifem_source_lock.py verify --receipt \
  .cache/references/ifem-interactive-fem-chapters-01-10-git-a4ab841-lock/source-lock.v1.json
```

The verifier returned 13 manifest entries and `state=acquired_local_only`. No source text is
stored in this document or in the receipt. Exact source bytes remain in the ignored local
content-addressed cache.

## Next gate

The next machine step is a local-only source-span and prerequisite extraction from the opening
sequence, followed by a pinned-Mathlib census that reports direct mappings, thin adapters, and
missing nodes separately. A source hash is not a proposition and cannot enter Builder freeze or
Prover routing on its own.
