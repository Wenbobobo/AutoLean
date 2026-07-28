# iFEM source-lock preparation receipt

**Status:** `discovery`; source metadata and rights are verified, but no iFEM
source file has been acquired in this checkout.  This record does not authorize a
Builder freeze, model egress, Prover handoff, or a claim about Mathlib coverage.

## Fixed source identity

The selected official source is [JSchoeberl/iFEM](https://github.com/JSchoeberl/iFEM),
prepared by Joachim Schoberl and colleagues at TU Wien.  The first candidate is
the source path through Chapters 1--10, ending at the abstract coercive
variational / Galerkin chapter rather than a concrete PDE proof.

The acquisition tool pins this immutable upstream commit:

- revision: `a4ab841c4e5ec726e9b7742c9dcb352cb9645736`;
- upstream commit date: 2026-06-09T15:31:07Z;
- upstream change: `Add LICENSE file for Creative Commons Attribution 4.0`;
- official license blob SHA-1: `7aa2c7d055857957fc9464109c305df6916f3f30`;
- official license SHA-256: `91030ffc2d2f295670d43f67ac5c9f9ee7b9ace6609f5bcf6990fbd68f2665a0`;
- license: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), evidenced by
  the pinned [LICENSE](https://github.com/JSchoeberl/iFEM/blob/a4ab841c4e5ec726e9b7742c9dcb352cb9645736/LICENSE).

This repairs a potentially confusing historical fact: the public iFEM
repository did not always show a license, but the selected revision does.  The
license supports attribution-preserving adaptation and redistribution; it does
not by itself authorize sending source text to a hosted model.  AutoLean keeps
the ceiling at `local_only` until a later, separate policy change.

## Implemented local boundary

`scripts/ifem_source_lock.py` is deliberately narrower than a textbook
ingestion pipeline.

1. It contacts only the fourteen official raw GitHub files pinned to the
   commit: `LICENSE` plus the thirteen selected source files below.  This
   avoids a multi-gigabyte whole-repository archive whose unrelated notebook
   outputs are outside the first pilot's source boundary.
2. It rejects redirects before following them, unexpected media types, byte-limit violations,
   non-UTF-8 content, invalid notebooks, blank opening metadata, a missing CC
   BY notice, a LICENSE that differs from the pinned Git blob, and source bytes
   that differ from a prior local receipt.
3. It writes each selected file by SHA-256 to the gitignored
   `.cache/references/<reference-id>/<sha256>.<extension>` cache path.  The
   adjacent receipt records only IDs, URLs, hashes, and sizes.  It contains no
   textbook source text.
4. It emits thirteen candidate `ReferenceManifestV1` entries only after their
   actual file digests are known, and the receipt binds the canonical candidate
   projection hash plus the exact `local_only`/no-freeze/no-Prover policy. No
   digest is guessed from a URL or commit ID.

The intentionally short operator-local invocation is:

```text
uv run --frozen python scripts/ifem_source_lock.py acquire --operator-acquire
```

That command is a mechanical retrieval, not semantic or professional review.
The `--operator-acquire` flag is an explicit acknowledgement, not an OS
capability: the control plane or worker sandbox must still ensure that
untrusted workers cannot run network acquisition. It is idempotent after a
valid local receipt exists. The normal success output is redacted to the
receipt path and selected-file count. To revalidate its local bytes later:

```text
uv run --frozen python scripts/ifem_source_lock.py verify --receipt <receipt-path>
```

The current Codex sandbox cannot directly reach `api.github.com` or raw GitHub,
so it could verify the public metadata through GitHub's repository connector
but could not produce the source-file SHA-256 values in this session.  Consequently the
tracked reference manifest remains unchanged and the state remains
`discovery`, not `local_calibration`.

## Source selection recorded by the receipt

The local receipt checks the repository's opening Chapter 1--10 chapter order,
not just Chapter 10:

- `primal/first_example.ipynb`, `boundary_conditions.ipynb`, `subdomains.ipynb`,
  `solvers.ipynb`, `elasticity3D.ipynb`, and `exercises.ipynb`;
- `abstracttheory/BasicProperties.ipynb`, `subspaceprojection.ipynb`,
  `RieszRepresentation.ipynb`, and `Coercive.ipynb`.

It additionally binds `README.md`, `_toc.yml`, and `intro.md`; the separately
downloaded `LICENSE` is checked for its CC BY notice and hash.  The receipt is
therefore a source-lock prerequisite for the 27-node Galerkin discovery graph,
not proof that the notebooks form a mathematical dependency path or a frozen
theorem slice.

## Next machine gates

1. Acquire and reverify the thirteen selected source files with the fixed tool;
   append its emitted manifest entries to a new reference-manifest revision
   only after every exact hash is independently replayed.
2. Send no source text to external agents.  A local-only notebook span selector
   must preserve the existing per-file hashes and add span hashes before any
   Builder candidate exists.
3. Use the pinned Library environment to query exact Mathlib representations
   for the prerequisite-only denominator.  Report direct mappings, thin
   adapters, and missing nodes separately; do not count future theorems as
   coverage.
4. Enter `local_calibration` only when the source-file receipt, source-span
   lock, and zero-egress conversion harness all agree.  A source-record success
   does not close the separate semantic-fidelity, frozen-bundle, or
   authoritative OCI-verification gates.
