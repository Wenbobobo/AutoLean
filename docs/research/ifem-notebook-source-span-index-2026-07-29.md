# iFEM notebook source-span index — 2026-07-29

Status: local-only source alignment. This index is a replayable locator layer over the already
verified iFEM source lock. It is not a semantic review, statement extraction, frozen contract,
Builder admission receipt, Mathlib mapping, kernel verification, or Prover handoff.

## Binding and scope

`Builder/src/autolean_builder/ifem_notebook_source_span_index.py` reads the exact
`autolean.ifem-source-lock.v1` receipt and re-hashes each content-addressed notebook before
parsing it. The receipt must remain `acquired_local_only`, `model_egress_policy=local_only`,
`contract_freeze=not_authorized`, and `prover_handoff=not_authorized`.

For every notebook cell, the projection contains only:

- locked relative source path and source reference ID;
- locked notebook SHA-256;
- source-lock file order, zero-based cell index, and Jupyter cell type;
- SHA-256 and character count of the logical cell source; and
- a deterministic `ifem.notebook-source-span` UUIDv5 locator.

The notebook is parsed with Python's JSON parser and duplicate JSON keys fail closed. The source
field accepts only the Jupyter string form or an array of strings, joined exactly in source order.
No regular-expression notebook parsing is used. Notebook outputs and metadata are read only as
untrusted JSON structure and are never projected.

## Storage boundary

The generated index is installed idempotently below the ignored local source cache, by default at:

```text
.cache/references/ifem-interactive-fem-chapters-01-10-git-a4ab841-lock/notebook-source-span-index.v1.json
```

The tracked [schema template](../../Builder/pilots/ifem-source-alignment/notebook-source-span-index.template.v1.json)
contains field names and placeholders only. Neither it nor the generated projection includes
notebook body text, headings, formula text, code, outputs, local cache paths, or model input.

## Observed local replay

The locked 13-file source receipt was replayed twice through the CLI on 2026-07-29. The
text-free result bound 10 notebooks and 161 cells:

- source-lock SHA-256:
  `74eca6689fe69dcbf2f34ea524a99cacc2054c0a39cfecfb11887c29e13cf239`;
- canonical index SHA-256:
  `3a0d39527481170a647cc8dc23917577e156f9ac42cb126f73759d784f8b03a7`;
- rendered index-file SHA-256, including its final newline:
  `afc4ae97a9d5ac79a044195712e2a0591d93132d233bb1f6e2f8abb745dd7204`.

Both replays returned the same canonical index hash. The generated file remains ignored and
contains no exact `source`, `text`, or `content` payload field.

## Builder use and authority limit

`IFEMNotebookSourceSpanIndexV1.source_records()` projects the digest-only cells into existing
`SourceRecordV1` / `SourceSpanV1` values in memory. This lets a later Builder alignment worksheet
cite a stable location and hashes without treating the locator as a source interpretation.

The local generation command is:

```text
uv run --frozen python scripts/ifem_notebook_source_span_index.py
```

Its stdout is a text-free count/hash summary. Running it does not create a candidate statement,
authorize any model egress, perform semantic review, alter the source lock, or advance any
lifecycle state. A later human semantic review and the independent frozen-contract gates remain
required before any Builder or Prover authority can change.

This first index covers Jupyter cells only. The separately locked `intro.md`, `README.md`, and
`_toc.yml` have file hashes but no selected logical span yet. In particular, the notebook index
does not by itself prove that Builder calibration starts at the textbook introduction.
