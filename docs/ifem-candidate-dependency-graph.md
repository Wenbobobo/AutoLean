# iFEM Candidate Dependency Graph

`scripts/ifem_candidate_dependency_graph.py` produces a source-text-free planning projection for
the `ifem-coercive-galerkin` discovery lane. It is not a formalization, coverage result, or proof
input.

## Inputs and replay

The command verifies, without exporting source bytes:

- the pinned local source staging tree and its staging manifest;
- the iFEM source lock, opening Markdown heading index, and notebook-cell index;
- the discovery lane manifest, its prerequisite denominator, and the census plan/result;
- the current `not_run` census state.

The output retains only hashes, stable heading/cell identifiers, node kinds, source order,
redacted candidate-declaration-set hashes, and edge metadata.  It contains neither source text
nor model input.  The source remains `local_only`; the command has no model or network interface.
The v1 node, ambiguity, and gap vocabularies are closed.  Serialization revalidates the complete
graph, so a nested Pydantic `model_construct` object cannot add arbitrary text while retaining the
`contains_source_text: false` declaration.

Run the project script through `uv`:

```text
uv run python scripts/ifem_candidate_dependency_graph.py
```

The default artifact is written under the local reference cache with the canonical filename
`ifem-candidate-dependency-graph.v1.json`. A byte-identical canonical copy is also tracked at
`Builder/pilots/discovery/ifem-candidate-dependency-graph.v1.json` as a D32/D34 runtime input. Its
file SHA-256 is `e6442bfe1cc5305a3d26972c23c70a08029f8cde387dc1b58088d918632cd3af`;
its content SHA-256 is
`ba9b246805a4b94ea9f0b02898a772114e495fc8dc12c783b7388b519470a71d`.
Each protocol pins both values, revalidates the graph, and rebuilds the paired corpus against it.
The tracked copy remains source-metadata-bound and non-authoritative; publishing hashes, stable
identifiers, and candidate edges does not authorize source-text or model egress.

## Edge meanings

The graph has 25 candidate nodes in the current locked denominator.  Its two edge classes must
remain visibly distinct:

- `declared_candidate_dependency`: copied from the discovery denominator as an unreviewed
  planning declaration.
- `heuristic_candidate_declaration_overlap`: a low-confidence signal from an exact overlap of
  already-declared census candidate names.  The names themselves are replaced by a count and a
  SHA-256 digest.

Neither class asserts a mathematical dependency, a faithful reading of the source, or a Mathlib
mapping.  Source anchors are assigned by deterministic index position only and explicitly do not
mean that a node has been semantically located in that span or cell.

## Boundary

The artifact declares a candidate-only MathematicalGraph layer.  It does not create a
FormalGraph or ExecutionGraph, a `StatementContractV1`, a semantic review, a freeze, or a Prover
task.  Calls attempting to freeze or hand off the graph fail unconditionally.  A future Builder
candidate must instead pass the normal source, rights, normalization, independent review, and
fidelity gates before a frozen statement can cross the Builder–Prover boundary.
