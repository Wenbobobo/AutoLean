# PDE-A Ivrii Source Acquisition

Recorded: 2026-07-26

## Conclusion

**State: `metadata_verified_download_pending`.** Victor Ivrii's official,
University of Toronto-hosted *Partial Differential Equations* is the PDE-A
local-cache candidate. Its author, open licence, online structure, and
transport section are verified from first-party material. No PDF, Markdown, or
TeX bytes have been downloaded into this checkout, so no byte count, SHA-256,
source span, `SourceRecordV1`, or `RightsRecordV1` exists yet.

This is a replacement for PDE-A's commercial Borthwick source *as the cache
candidate only*. It does not select a Builder pilot or overrule the prior
[PDE source-quality decision](domain-pilot-discovery-2026-07-26.md#pde-decision):
Ivrii is not by itself the semantic authority for an autonomous formal theorem
contract.

## First-Party Metadata

| Field | Verified value | Evidence |
| --- | --- | --- |
| Author and host | Victor Ivrii; Department of Mathematics, University of Toronto | [official textbook index](https://www.math.toronto.edu/ivrii/PDE-textbook/) and [PDF title page](https://www.math.toronto.edu/ivrii/PDE-textbook/PDE-textbook.pdf) |
| Title and course position | *Partial Differential Equations*; online textbook for APM346 | [official textbook index](https://www.math.toronto.edu/ivrii/PDE-textbook/) |
| Licence | CC BY-SA 4.0 | [official PDF preface](https://www.math.toronto.edu/ivrii/PDE-textbook/PDE-textbook.pdf) and [licence deed](https://creativecommons.org/licenses/by-sa/4.0/) |
| Available forms | rendered HTML, official PDF, author-declared per-page Markdown, whole-book source and TeX | [official PDF preface](https://www.math.toronto.edu/ivrii/PDE-textbook/PDE-textbook.pdf) |
| PDF extent | 415 pages | [official PDF](https://www.math.toronto.edu/ivrii/PDE-textbook/PDE-textbook.pdf) |
| Opening pathway | Preface, `0.1`, Chapter 1, then Chapter 2 `§2.1 First order PDEs` | [index](https://www.math.toronto.edu/ivrii/PDE-textbook/) and [§2.1](https://www.math.toronto.edu/ivrii/PDE-textbook/Chapter2/S2.1.html) |
| Entry prerequisites | multivariable calculus and ODE required; complex variables and real analysis useful but not required | [official PDF preface](https://www.math.toronto.edu/ivrii/PDE-textbook/PDE-textbook.pdf) |

The author describes APM346 as a junior class except for mathematics specialists.
Together with the ordered table of contents and explicit prerequisites, this
supports beginner-oriented, systematic discovery. It does **not** establish
that every displayed result has sufficient hypotheses for formalization.

## Version and Markdown Boundary

The current official PDF contains two different temporal signals:

- its title page says `© by Victor Ivrii, 2026`;
- its preface calls the text a `snapshot of June 7, 2021` and says the PDF is
  updated once in a few years.

Neither signal alone identifies a reproducible release. The future lock must
use the observed byte SHA-256, retrieval time, and page count; it must not
invent a revision date. The preface declares the Markdown convention by showing
that a rendered page such as `Chapter2/S2.1.html` has the corresponding
`Chapter2/S2.1.md` source. This run verified the rendered official §2.1 page;
it did not download or hash its Markdown source.

§2.1 is an appropriate narrow starting check, not a frozen theorem source. It
introduces `a u_t + b u_x = 0`, constant-coefficient characteristic lines, the
initial condition at `t = 0`, the formula `u(x,t) = f(x-c t)`, and the explicit
assumption `a != 0`. Its same section also demonstrates why source text alone
is insufficient: variable-coefficient and initial-boundary examples carry
domain and well-posedness qualifications that a Builder must not elide.

## Acquisition Protocol

1. An operator, not a Builder or Prover worker, obtains unmodified bytes from
   the official HTTPS PDF URL. Redirects, final media type, retrieval time,
   byte count, and SHA-256 are recorded locally.
2. The operator places the bytes under
   `.cache/references/ivrii-pde-official-pdf/`; `.cache/` is already ignored.
   The PDF is never added to Git, an artifact fixture, a prompt, or a public
   report.
3. Only after the observed size and SHA-256 are available may a new,
   intentionally reviewed Builder reference-manifest revision be proposed.
   The tracked [lock template](templates/pde-a-ivrii-source-lock.v1.template.json)
   is documentation, not an acquisition allowlist and not executable input.
4. Derive local text only under the resulting pinned parent identity. Preserve
   separate page locators and byte offsets; do not use a PDF extractor to
   manufacture theorem hypotheses.
5. A rights reviewer decides model-egress scope. CC BY-SA creates a different
   source-rights path from the prior commercial text, but it does not itself
   approve a specific external model endpoint or replace attribution/share-alike
   review.

If the official download becomes unavailable, changes bytes unexpectedly, or
cannot be validated under the stated rights boundary, retain
`metadata_verified_download_pending`. Do not fill any SHA-256 field with a
guess and do not substitute an unofficial mirror.

## Cross-Reference Boundary

David Borthwick's *Introduction to Partial Differential Equations* remains a
copyrighted, non-ingestible cross-reference for a licensed human reviewer. It
is not a PDE-A cache target, source span, model input, or replacement PDF.
