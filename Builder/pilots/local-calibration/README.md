# Project-Synthetic Pre-calibration Fixture

`project-synthetic-opening-corpus.v1.json` is an eleven-statement fixture generated specifically
for this repository to inspect the future Builder conversion path. It contains five PDE-A and six
MG-A opening samples. Its provenance class is `project_synthetic_fixture`; its authorship claim is
`generated_for_repository_pending_human_content_review`. Those labels do not claim a human author,
legal review, completed content review, or textbook alignment.

The exact synthetic fixture bytes are covered by the repository's existing Apache-2.0 contribution
boundary. The corpus binds the SHA-256 of the root `LICENSE`; its adjacent release manifest binds
the exact corpus and renderer bytes. Redistribution is allowed only for those bound fixture bytes.
Model egress, training, and embedding remain denied, and this is not production rights clearance.

Each sample binds exact local source bytes and one exact source span to the repository license. It
also records a local normalization sketch, two declared-independence labels attached to
illustrative Lean-like text, reverse-rendering notes, informational ambiguities, examples, and
declared synthetic mutation fixtures. The illustrative text is not parsed or elaborated, has no
normalized-to-Lean semantic binding, and is not a formalization candidate. Real candidates exist
only after the normal `StatementFidelityHarness` workflow creates and evaluates them.

This artifact is a `local_calibration_fixture` containing `pre_calibration_fixture` records. It
does not satisfy the Phase-2 roadmap's real `local_calibration` state, which still requires a
rights-cleared source and independently generated formalization candidates.

The corpus names intended transport-sign and trace distinctions, PDE regularity, uniqueness
versus existence, strict versus non-strict bounds, infimum versus attainment, length-space versus
geodesic statements, quantifier order, nonemptiness, finiteness, Noetherian hypotheses, vacuity,
and endpoint order. These are
synthetic fixtures for a future checker; this artifact does not claim that a checker executed or
detected any of them. In particular, changing `<` to `<=` records an exact contract-fidelity
difference, irrespective of either statement's mathematical truth.

## Authority boundary

Every record fixes all of the following to `false`:

- `production_ingestion`
- `freeze_allowed`
- `prover_handoff_allowed`
- `model_egress_allowed`
- `production_rights_cleared`
- `promotion_allowed`

The machine-readable report includes a Builder-Prover interface preview only to make the future
handoff shape reviewable. The preview is not routable. The only executable assertion in this
local module checks whether an illustrative text snapshot changed byte-for-byte; passing that
check establishes no syntax or semantic property. A normal source ingestion, independent human
content and semantic review, `StatementFidelityHarness`, and `FreezeGate` run are required before
an actual `StatementContractV1` can enter Prover.

## Maintenance

The corpus and release manifest are deterministically rendered from the project-synthetic fixture
definitions in `render_opening_corpus.py`:

```powershell
uv run python Builder/pilots/local-calibration/render_opening_corpus.py --check
```

Use the same script without `--check` only when intentionally changing a project-synthetic
fixture. It performs no network, model, Lean, reference-cache, source-ingestion, freeze, or Prover
operation. The released corpus SHA-256 is also pinned in the Builder loader and
`scripts/public_readiness.py`; an intentional fixture change must update those pins in the same
reviewed change. Rewriting only the corpus and manifest remains invalid. Any fixture change
remains subject to human content review.
