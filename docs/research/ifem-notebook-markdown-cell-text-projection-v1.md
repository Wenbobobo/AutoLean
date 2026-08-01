# iFEM notebook Markdown-cell text projection V1

Status: implemented local-only preparation boundary. On 2026-08-01, four opening Markdown cells
were materialized and independently replayed in the ignored operator cache. They remain coarse
cell containers, not selected mathematical-claim spans. The contract exposes exact logical source
text only to a private, ignored cache artifact; it does not create a source span, model input,
semantic decision, statement contract, freeze, FormalGraph, ExecutionGraph, or Prover handoff.

## Purpose and binding

The existing digest-only notebook index identifies 161 locked Jupyter cells without retaining
their source text. Later real source-span calibration needs the exact logical Markdown text for one
explicitly selected cell. V1 projects exactly one nonempty Markdown cell and binds it to all of:

- source-lock receipt SHA-256
  `74eca6689fe69dcbf2f34ea524a99cacc2054c0a39cfecfb11887c29e13cf239`;
- unchanged thirteen-entry reference-manifest candidate SHA-256
  `4a5d859d77b606d6e485d98bd3e4afc41f6c566c6fb09f5e3dc2b2a539f18398`;
- digest-only notebook-index canonical SHA-256
  `3a0d39527481170a647cc8dc23917577e156f9ac42cb126f73759d784f8b03a7`;
- locked notebook path, reference ID, file order, and notebook SHA-256; and
- stable cell span ID, zero-based index, Markdown locator, character count, and logical-source
  SHA-256.

The source lock and digest-only index are inputs only. V1 creates no reference-manifest entry and
does not rewrite either artifact, so their schemas and hashes remain unchanged.

## Logical-source rule

`jupyter-nbformat-v4-logical-source-v1` parses strict UTF-8 JSON with duplicate keys and non-finite
numbers rejected. A Jupyter `source` string is retained exactly. A `source` array must contain only
strings and is concatenated in array order without a separator. No newline, Unicode, whitespace, or
Markdown normalization is performed. The resulting string must encode as strict UTF-8, remain
nonempty, and match the digest-only index's character count and SHA-256.

This logical text is not a raw `.ipynb` byte range. A later source-span contract must define byte
offsets relative to this projection's UTF-8 cell text and must not claim that those offsets locate
the JSON-escaped notebook bytes.

## Private and public surfaces

The private schema is
`autolean.ifem-notebook-markdown-cell-text-projection.v1`. It carries `cell_text`, declares
`contains_source_text=true`, and fixes all authority fields to local-only, not-performed, or
not-authorized. Its default location is derived from the stable span UUID and cell digest below:

```text
.cache/references/ifem-interactive-fem-chapters-01-10-git-a4ab841-lock/
  notebook-markdown-cell-text-projections.v1/<span-uuid>.<cell-sha256>.private.json
```

There is no public receipt file. CLI stdout uses the separate redacted schema
`autolean.ifem-notebook-markdown-cell-text-summary.v1`; it contains only source-lock/index/cell and
private-file hashes, the stable span ID and logical locator, plus explicit negative authority
fields. It declares `private_artifact_contains_source_text=true` and
`summary_contains_source_text=false`. It never prints source text, source paths, cache paths, or
the private filename.

## Filesystem and replay boundary

Every input and output path is lexically confined below the local reference cache. The reader walks
every existing directory component with `lstat`, rejects symlinks, junctions, and Windows reparse
points, opens leaf files with `O_NOFOLLOW` where available, compares `lstat`/`fstat` identities, and
checks the directory identities again after reading. Source-lock, index, and private-projection
artifacts must be canonical JSON with one final newline. The upstream notebook need not be
canonically formatted, but it must be strict JSON and match its locked file size and digest.

Materialization writes a same-directory temporary, flushes and synchronizes it, and installs it
without replacing an existing target. An identical target is an idempotent replay; different bytes
are a conflict. Verification performs no write. These checks defend the artifact boundary but do
not constitute an operating-system sandbox against a hostile process running as the same user.

## Operator command

The operator must copy one path/index/hash selector from the already verified digest-only index.
There is deliberately no arbitrary cache-root, source-lock, index, or output-path option.

```text
uv run --frozen python scripts/ifem_notebook_markdown_cell_text_projection.py materialize \
  --source-path <locked-notebook.ipynb> \
  --cell-index <zero-based-markdown-cell-index> \
  --expected-cell-sha256 <digest-only-cell-sha256>

uv run --frozen python scripts/ifem_notebook_markdown_cell_text_projection.py verify \
  --source-path <locked-notebook.ipynb> \
  --cell-index <zero-based-markdown-cell-index> \
  --expected-cell-sha256 <digest-only-cell-sha256>
```

Choosing an atomic mathematical claim within any coarse cell remains a separate Builder
source-selection decision. Materializing a projection proves only byte and locator consistency;
it does not authorize model egress or advance the source into calibration, admission, freeze, or
proof search.

## 2026-08-01 local replay

The first four Markdown cells of the opening `primal/first_example.ipynb` notebook were chosen in
source order solely as bounded coarse containers for exercising this projection boundary. Each
private artifact was installed once and then rebuilt from the locked notebook and verified without
writing. The public-safe commitments were:

| Cell | Stable span UUID | Cell-content SHA-256 | Private-artifact file SHA-256 |
| --- | --- | --- | --- |
| 0 | `3c998eb4-e0b0-57cc-a90e-502a35941954` | `42267c3ee93d76f87949e4960df2448f1db3cbdbd78e9d37e8ace2719f04aa4e` | `ff7565e24bda91be707038c06c0b3593d611d86390b647b681aff83a9108c011` |
| 1 | `6da8868b-ab7e-54f2-9023-3d9137946cf8` | `5bfeb6229159207d76c6967d9cc6fa25c0adc9a30079cce99454c29006b13857` | `1fdd356d177e42d055ced3dca73806596038984129a95ced7040b032161e2ed2` |
| 2 | `85a2cbde-32e1-540b-8e54-bf92266a51c3` | `c79742c5a34510d0c4b93bd751adcdaebf64ab0edc5c45ba5e9f952e175e878a` | `4cecd07f5f7c03d59254c823d006ac80b57e19d9727ff036f9708218cda8a4d4` |
| 3 | `f680f603-519e-5145-a323-98744255d946` | `546a972e09c6bf66ce1ac92af5a2fdef3eed93fce96243e5822487215965098b` | `0bb1b4565fe06f82ad84f73f5073074683e50953260aae36e2f294f84aec1cfb` |

All eight redacted materialize/verify summaries bound source-lock SHA-256
`74eca6689fe69dcbf2f34ea524a99cacc2054c0a39cfecfb11887c29e13cf239` and notebook-index
canonical SHA-256 `3a0d39527481170a647cc8dc23917577e156f9ac42cb126f73759d784f8b03a7`.
They contained no source text or local path and retained `local_only`, `not_performed`, no-freeze,
and no-handoff states. This replay closes M4.6 source-text preparation only. Atomic proposition
selection and any semantic conversion remain later Builder work.

## Focused validation

```text
uv run --frozen pytest -q \
  Builder/tests/test_ifem_notebook_markdown_cell_text_projection.py \
  scripts/tests/test_ifem_notebook_markdown_cell_text_projection_script.py
uv run --frozen ruff check \
  Builder/src/autolean_builder/ifem_notebook_markdown_cell_text_projection.py \
  Builder/tests/test_ifem_notebook_markdown_cell_text_projection.py \
  scripts/ifem_notebook_markdown_cell_text_projection.py \
  scripts/tests/test_ifem_notebook_markdown_cell_text_projection_script.py
uv run --frozen mypy \
  -m autolean_builder.ifem_notebook_markdown_cell_text_projection \
  -m scripts.ifem_notebook_markdown_cell_text_projection
```

The tests use a synthetic replay of the fixed thirteen-entry source-lock shape. They cover raw
whitespace and Unicode preservation, string-array concatenation, canonical JSON, duplicate keys,
`NaN`, invalid UTF-8, isolated surrogates, selection and binding drift, link/reparse rejection,
open-time identity drift, write-once conflicts, CLI redaction, and immutable negative authority.
They are implementation evidence, not a real iFEM source-span calibration result.
