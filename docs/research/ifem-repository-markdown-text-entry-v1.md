# iFEM repository Markdown text entry V1

Status: implemented as a local cache adapter. It is source-byte provenance and a text-interface
preparation step only. It is not rights authorization, model execution, semantic review, a
statement contract, a frozen Builder artifact, a FormalGraph, an ExecutionGraph, or Prover input.

## Purpose

The iFEM source lock already proves the identity of the fixed, local `intro.md` object. Some
local Builder tools require a `text/plain` artifact type, but Markdown parsing would create a new
semantic or normalization surface. V1 instead creates a distinct content-addressed `.txt` object
whose bytes are exactly the locked Markdown bytes.

The derivation record is intentionally narrow:

- kind: `repository_text_extraction`;
- method: `utf8-markdown-byte-identity-v1`;
- parent type: `text/markdown` with `.md` extension;
- child type: `text/plain` with `.txt` extension;
- parent and child SHA-256 and byte count: identical;
- tool name and version: `null`; and
- parent locator authority: `human_declared`.

Both records remain `local_only`. The child is `local_derivation_only` with no download URL.
The adapter rejects any non-UTF-8 byte sequence, different hash or size, policy widening, tool
claim, method change, source-lock drift, or noncanonical cached receipt.

## Lifecycle

```text
verified iFEM source-lock receipt
        |
        v
fixed local Markdown parent (reverified)
        |
        v
byte-identical local text cache object + overlay manifest + overlay receipt
        |
        +--> local source-alignment consumers only
        +--> no model execution, freeze, or Prover handoff
```

The adapter does not modify the source-lock's thirteen-entry candidate manifest, its candidate
hash, or its receipt. It writes its own two-entry overlay and receipt below the ignored local
reference cache, accepting an existing file only when the bytes are exactly equal to the current
source-lock replay. It performs no network request.

## Operator commands

```text
uv run --frozen python scripts/ifem_repository_text.py materialize
uv run --frozen python scripts/ifem_repository_text.py verify
```

The only printed artifact is a redacted summary containing hashes, `local_only`, and false
freeze/Prover-handoff flags. It excludes source text, source paths, and cache paths. The local
overlay manifest and receipt likewise contain no source body; they are not tracked or published.

## 2026-08-01 local replay observation

The retained local iFEM cache was materialized and then verified through two separate CLI
invocations. Both emitted the same redacted summary:

- source-lock receipt SHA-256:
  `74eca6689fe69dcbf2f34ea524a99cacc2054c0a39cfecfb11887c29e13cf239`;
- unchanged thirteen-entry manifest-candidate SHA-256:
  `4a5d859d77b606d6e485d98bd3e4afc41f6c566c6fb09f5e3dc2b2a539f18398`;
- byte-identical derived text SHA-256:
  `050ca6a5f175c9f813d19b5185c8e6a8edbf78607da7f9c91ee5516486d94eec`;
- derived byte count: `4063`;
- overlay-manifest SHA-256:
  `5597beeabe757723ba16b63ecfc1d7ca1adbeb0f3dfd1378262e082a5380deb2`;
- overlay-receipt SHA-256:
  `fa8e28b5ebf45293022e7f3f9854d9dd8643287db9ec34608da844c841c49d52`.

The overlay bytes and receipt remain in the ignored local cache. This observation establishes
local byte identity and replay only; `model_egress_policy` stayed `local_only`, while contract
freeze and Prover handoff remained unauthorized.

## Boundary

Byte identity establishes that the text object is the same source bytes under a different typed
cache entry. It does not establish a theorem boundary, a Markdown interpretation, a proposition
translation, source rights for model input, mathematical correctness, or Lean proof validity.
Those remain Builder fidelity and Prover verification gates respectively.
