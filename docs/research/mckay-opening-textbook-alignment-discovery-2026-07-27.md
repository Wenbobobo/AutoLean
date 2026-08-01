# McKay opening textbook-alignment discovery

**Status:** `textbook_alignment_discovery_nonfreeze`; local calibration side lane only.
No model received source text, no statement was extracted, no contract was frozen, and no
Prover handoff or semantic-review claim was created.

## Result

The operator-only harness verified the pinned `ReferenceManifestV1`, the cached
`mckay-lectures-differential-geometry-2022-text` artifact, and its exact parent PDF:

- parent SHA-256:
  `1cd1660be5e63bf2d5198e7a7f7e912d3179c9cf3b5f2d972db6283e0b483ea4`;
- selected locator: `form-feed-page:0001#utf8-bytes:0-8192`;
- pending worksheet count: 1;
- domain-separated candidate hash:
  `7c832a6da08a9c8d1f5027209ecd5c8a928eca5c1c0ac4eb3764ff650d43a441`.

The verified derived text contains zero form-feed delimiters. Therefore “page 1” here means
the first logical segment before any form feed, bounded by the recorded UTF-8 byte range; it
does **not** claim correspondence with printed PDF page 1. Automatic theorem extraction would
be unreliable at this boundary, so the private worksheet deliberately leaves the normalized
candidate, Lean-like draft, ambiguities, examples, mutations, and Mathlib mapping pending for
human review.

Private source and worksheet text remain under
`.cache/builder/textbook-alignment/mckay-opening/packet.private.json`. The adjacent public
summary contains only the reference ID, parent hash, locator, candidate count, candidate hash,
and non-freezing status.

The same fail-closed run can be reproduced with
`uv run python -m scripts.textbook_alignment`; stdout is the redacted summary only.
The checkout must have a real `.git` marker, the root `.gitignore` must contain the active
`/.cache/` rule, and the cache and output-parent directories must already exist as real confined
directories. An identical rerun is idempotent; different existing bytes are a conflict and are
never overwritten. These checks do not isolate the packet from another process running as the
same local user. A production deployment must place private packets on a separate
operator-controlled volume.

## Portfolio boundary

This run calibrates the Builder's source-binding and redaction path from the beginning of a
locally verified textbook. It does not change the Phase 2 source decision:

- iFEM Chapters 1--10 remains the one **conditional primary** pilot for source preparation
  and compile discovery;
- McKay remains a calibration/reference source;
- the active connections/curvature upstream-overlap blocker still prevents the McKay
  connection-curvature graph from becoming a new declaration track.

Any future extraction from this packet must re-enter the normal Builder fidelity workflow
with independent semantic review. It cannot inherit authority from this discovery record.
