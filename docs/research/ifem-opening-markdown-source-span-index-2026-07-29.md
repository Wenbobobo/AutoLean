# iFEM opening Markdown source-span index — 2026-07-29

Status: local-only source alignment. This is a digest-only locator layer over
the already verified iFEM source lock; it is not a semantic review, statement
extraction, frozen contract, Builder admission receipt, Mathlib mapping,
kernel verification, or Prover handoff.

## Scope and binding

`Builder/src/autolean_builder/ifem_markdown_source_span_index.py` replays only
the locked `intro.md` record. The current source-lock receipt binds that path
at revision `a4ab841c4e5ec726e9b7742c9dcb352cb9645736`, source SHA-256
`050ca6a5f175c9f813d19b5185c8e6a8edbf78607da7f9c91ee5516486d94eec`, and
source-lock SHA-256
`74eca6689fe69dcbf2f34ea524a99cacc2054c0a39cfecfb11887c29e13cf239`.

The reader fails closed unless the lock remains `acquired_local_only` with
`model_egress_policy=local_only`, `contract_freeze=not_authorized`, and
`prover_handoff=not_authorized`. The rendered index repeats those boundaries as
literal `local_only`, `not_performed`, and `not_authorized` fields. They deny
authority; they do not grant it. The index never carries model input.

## Logical sections

Each ATX heading outside fenced code blocks creates one section span. The span
starts at that heading and ends immediately before the next heading at the
same or higher level, or at end of file. It retains only the locked relative
path and reference ID, raw file hash, source-lock order, heading ordinal and
level, inclusive line range, SHA-256 and character count of the normalized
heading and section, and a deterministic
`ifem.markdown-source-span` UUIDv5 locator.

Duplicate heading text is intentionally not a selector. It is disambiguated
by the structural heading ordinal and line range, so a repeated title cannot
overwrite or redirect a previous span. Source bytes remain raw-hash-bound;
logical text normalizes `CRLF` and lone `CR` to `LF` before section hashing,
making logical-section digests independent of line-ending representation while
the source-file hash still detects byte drift.

## Storage and authority boundary

The index is atomically installed below the ignored local source cache by:

```text
uv run --frozen python scripts/ifem_markdown_source_span_index.py
```

Its default location is
`.cache/references/ifem-interactive-fem-chapters-01-10-git-a4ab841-lock/opening-markdown-source-span-index.v1.json`.
The tracked
[schema template](../../Builder/pilots/ifem-source-alignment/opening-markdown-source-span-index.template.v1.json)
contains field names and placeholders only. Neither template nor generated
index contains Markdown text, cache paths, headings, formula text, model input,
freeze authority, or Prover-handoff authority. It does contain explicit negative
authority states so downstream readers cannot reinterpret an omitted policy.

`IFEMMarkdownSourceSpanIndexV1.source_records()` provides an in-memory
`SourceRecordV1` / `SourceSpanV1` projection with the same digest-only
locations. A later Builder process may use it as a locator, but it remains
unable to infer mathematical meaning or cross the frozen-statement boundary.

## Observed local replay

On the current locked source, two consecutive local replays produced three
spans and the same canonical index SHA-256:

`5c11e96dde220158fb1705413472d7f20fd341374c8e56a8e9e3e0d7f7b0c35a`.

The rendered file, including its final newline, has SHA-256:

`6fffc7d70e2ad3accc4e22802de9ac84848acfbf568d8695570bdc2251941103`.

This is replay evidence for source alignment only. It does not establish a
mathematical interpretation, semantic review, a statement contract, or a
proof result.
