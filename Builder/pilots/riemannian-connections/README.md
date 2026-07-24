# Connection Curvature Pilot

This directory is a source-alignment staging area for the vector-bundle connection-curvature
graph. It is not an admitted discovery pilot: active upstream PR #36036 overlaps the curvature
API surface, so the graph remains reference-only until a maintainer-confirmed non-overlap exists.

It intentionally contains no textbook bytes and no frozen statement contracts. Reference bytes
live under the ignored `.cache/references/` tree. Source records, rights policy, mathlib mappings,
independent formalization candidates, mutation evidence, and expert signoff must be created through
the Builder source and fidelity harnesses before any downstream bundle is emitted to Prover.

The executable [self-calibration manifest](../self-calibration/pilot-manifest.v1.json) records
this blocker along with independent-review and counterexample gates. It also holds the three
conditional alternatives; no node can become a Builder statement draft, and no artifact may cross
to Prover, until its own source, mathlib-census, and human-review gates all pass.
