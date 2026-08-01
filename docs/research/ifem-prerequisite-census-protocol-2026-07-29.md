# iFEM Coercive Prerequisite Census Protocol

Status: bounded P2-06/P2-07 query plan implemented; the generic-host run produced no observation,
and the audit-fixed receipt-bound OCI diagnostic completed with all 21 classifications unknown

## Conclusion

The authoritative denominator is the current content-addressed iFEM lane:
25 retained mathematical nodes, of which 21 definitions or prerequisite
theorems are scored. The older request text saying "27-node denominator" has
drifted and must not rewrite that frozen object. The query plan binds revision
`ifem-coercive-prerequisites-r01-f9d1f2d4717a`, denominator SHA-256
`f9d1f2d4717aaaed9f10c6c82deae083985f643089b17c424de4e61e9845bcc5`,
and plan SHA-256
`b24081ac1de564189ea10804665224cbdead963af3f737852e2de4d610cf8de8`.

## First principles

The denominator must be fixed before observation so easy nodes cannot be added
after a query. A Lean name hit establishes only that a declaration with a
canonical type exists in the pinned environment; it does not establish that
the declaration is mathematically equivalent to an iFEM prerequisite.
Therefore execution evidence and Builder semantic-review evidence are separate
inputs, and neither grants freeze or Prover-handoff authority.

## Three graphs

- Mathematical graph: the 25-node textbook dependency graph in
  `phase-2-active-lanes.v1.json`; only its 21 included nodes form the score
  denominator.
- Formal graph: candidate declaration names and possible adapter boundaries.
  These are unclassified probes, not accepted mappings.
- Execution graph: one generated Lean program imports the two fixed modules,
  looks up every candidate in the checked environment, and records declaration
  kind, canonical type, and observed axioms. It does not construct a proof or a
  `StatementContractV1`.

## Classification evidence

`direct` requires mapped declarations, their aligned canonical type hashes, the query
observation hash, and a Builder semantic-review hash. `thin_adapter` additionally
requires content-addressed adapter source and a compile receipt. `missing`
requires a negative query observation, a bounded declaration-inventory hash,
and semantic review; failure to find one guessed name is insufficient.
Anything lacking the exact evidence remains `unknown`.

This asymmetry is intentional. False positives inflate a coverage score and
can misdirect the pilot. A false negative also matters, but the protocol avoids
calling a node `missing` until the bounded inventory and review evidence exist.

## Pinned inputs

- Lean toolchain: `leanprover/lean4:v4.28.0`
- Mathlib revision: `8f9d9cff6bd728b17a24e163c9402775d9e6a365`
- `Library/lake-manifest.json` SHA-256:
  `e2a93c904f51195d6740cd9abfb35ab155dc0157e0e46642dce0d364b68a9a89`
- Direct imports: `Mathlib.Analysis.InnerProductSpace.LaxMilgram` and
  `Mathlib.Analysis.Normed.Operator.Bilinear`

The source hints in the plan were derived from the pinned mathlib source tree
and are search seeds only. They are not current Lean observations and do not
classify any node.

## Exact commands

Validate the denominator and environment bindings:

```text
uv run --frozen python scripts/ifem_prerequisite_census.py check-plan
```

Record the current honest result when the pinned POSIX/WSL runner is not
available:

```text
uv run --frozen python scripts/ifem_prerequisite_census.py not-run --reason wsl_unavailable --out .cache/ifem-prerequisite-census-not-run.v1.json
```

Run later from a POSIX/WSL checkout whose `Library/` files match the plan:

```text
uv run --frozen python scripts/ifem_prerequisite_census.py run --out .cache/ifem-prerequisite-census-unreviewed.v1.json --observation-out .cache/ifem-prerequisite-query-observation.v1.json
```

The wrapper renders a temporary query and invokes exactly:

```text
lake env lean --run <generated-query.lean>
```

This fallback now checks all locked local Git packages and exact revisions before Lake starts, and
passes a Git configuration that disables HTTPS dependency acquisition. It refuses the current
checkout when `.lake/packages/mathlib` or another dependency is absent instead of silently cloning.
The preferred route is the separate native OCI worker documented in
`docs/ifem-prerequisite-census-oci.md`; it does not alter the immutable five-profile P2-07 image.

Successful execution still emits 21 `unknown` classifications with reason
`builder_semantic_review_not_recorded`. The observation must be reviewed and a
separate evidence-complete result constructed before any coverage arithmetic.

## 2026-07-31 execution boundary

The generic-host WSL attempt from the checkout under `/mnt/c` reached the wrapper's internal
600-second timeout. It wrote no observation file and no result file, and its generated temporary
Lean query was cleaned up. The frozen census manifest keeps its historical `not_started` status;
this timeout is not a completed census, a negative query, or a reason to rewrite the manifest.
Accordingly, all 21 nodes remain unclassified. A later `host_query_timeout` record represents the
absence of completed census evidence without inventing an observation; P2-08 may bind that record
only to conclude `incomplete`.

The separate receipt-bound five-profile run is real pinned-environment visibility evidence, but it
does not substitute for this two-import, 21-node census. Fixed exact direct imports identify the
query roots only; they do not establish a narrow transitive import closure. A closure-width
acceptance policy remains unresolved pending independent review.

The dedicated two-import OCI census subsequently completed in the fixed Lean/Mathlib environment.
Its result content SHA-256 is
`fbaf12b9f9979131f1ce2f7075808c0141e4a5933046b6a369a2f75818016165`; the audit-fixed execution
envelope content SHA-256 is
`5b04fca9492a113a9e69060aa58d62f7004a2e5f9b36c7934d6dcbbc4482be32`. Two runs produced
byte-identical raw, observation, result, and envelope artifacts, and the receipt-bound replay
verifier passed in WSL against Docker Engine `29.1.3`. This closes only the missing local execution
record. It does not turn any candidate-name observation into a semantic mapping: every node remains
`unknown`, coverage is not authorized, and Builder freeze and Prover handoff remain forbidden.

## Counter-argument

A declaration such as `IsCoercive` may look like an obvious direct match from
its name and documentation. That shortcut is valid only if its quantifiers,
scalar field, positivity convention, absolute-value convention, and bilinear
form representation match the frozen mathematical node. If any differs but a
small compiled bridge preserves the intended statement, the right class is
`thin_adapter`; if review is absent, the right class is `unknown`.

## Remaining authority gap

The earlier host attempt did not produce a census observation. No node was classified and no
percentage was computed from that attempt. The later OCI diagnostic retained its build receipt and
passed cross-artifact replay, replacing only this execution gap. Builder semantic review and, for `missing`, a bounded
inventory protocol remain open. Source-span admission, statement freeze,
Library promotion, proof search, kernel verification, and Prover handoff are
outside this census and remain forbidden here.
