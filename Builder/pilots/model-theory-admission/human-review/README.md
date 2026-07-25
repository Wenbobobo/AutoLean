# T3 Human-Review Packet

This directory packages the unresolved model-theory pilot for a human advisory review. It binds
the immutable T3 gap decision, ten machine-located source spans, two page-pair ambiguities, the
manifest-v2 source identities, the retained Lean implementation, and the exact-image T4 query.
It contains no textbook excerpt, rendered page, local cache path, prompt, or raw model output.

## Files

- `packet.v1.json` is the immutable public-safe review context and verdict vocabulary.
- `REVIEW-FORM.md` is the readable checklist.
- `response.template.v1.json` is the strict unfilled response shape.
- `README.md` describes the local review workflow and authority boundary.

Every review item has `review_effect: advisory_only`. Every authority field is `false`. A
completed response cannot itself modify `decision.v2.json`, issue an admission receipt, freeze a
statement, hand a bundle to Prover, or promote a result.

## Local Review View

Materialize the two manifest-v2 artifacts in an operator-owned reference cache, then run:

```powershell
uv run python scripts/model_theory_review.py build `
  --cache-root <operator-reference-cache> `
  --pdftoppm <pdftoppm>
```

The script verifies the manifest, PDF, derived text, all ten span byte digests, and tracked packet
bindings before invoking `pdftoppm`. It maps UTF-8 byte offsets to PDF pages through the derived
text's form-feed page boundaries.

Generated files are confined to:

```text
tmp/pdfs/model-theory-t3-review/
  <review-view-manifest-sha256>/
    pages/
    index.html
    review-view-manifest.v1.json
```

This directory is ignored by Git. The CLI returns the versioned `output` path, the
`review_view_manifest` path, and its `review_view_manifest_sha256`. Repeating an identical build
reuses that immutable version; a renderer or view change produces a different version without
deleting prior versions or unknown files. The generator never writes page images or textbook text
into the public packet, never uses the network, and refuses to overwrite a different existing
generated file.

## Completing A Review

Use the generated HTML only as a local visual aid. Record both the visual locator and semantic
fidelity verdict for each span, resolve both page-pair ambiguities, and answer the fragment,
representation, freshness, import, axiom, and overall questions.

Keep any completed response advisory until an independent process authenticates reviewer identity,
qualification, and Builder authority. Any accepted change to the image, import policy, axiom
policy, candidate boundary, or statement requires a new versioned decision or contract; the
current V2 decision remains unchanged.
