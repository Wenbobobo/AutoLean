# Phase 2 Discovery Manifests

`phase-2-active-lanes.v1.json` is public-metadata planning evidence for the
active iFEM, PDE-A, and MG-A lanes. It is deliberately below `PilotManifestV1`:
it has no source bytes, source spans, Mathlib census result, Lean declaration,
rights admission, frozen statement, Library record, or Prover handoff.

The iFEM object fixes one prerequisite-only overlap denominator before the
first compiler query. Its hash is copied into the `not_started` census plan.
A future census must bind that hash; changing the nodes changes the hash suffix
of the required revision and requires a successor denominator revision and a
fresh census plan. Every scored prerequisite must be in the selected terminal
node's transitive dependency closure. Examples and terminal targets are retained
for alignment but cannot inflate the score.

Do not put source caches, notebook text, prompts, credentials, compiler
output, or coverage results in this directory.

## P2-07 blockers

The iFEM thirteen-file source lock is now locally acquired and independently replayed under
`local_only`; its receipt SHA-256 is
`74eca6689fe69dcbf2f34ea524a99cacc2054c0a39cfecfb11887c29e13cf239`.
The first exact type/import census remains blocked by the unrevised tracked reference manifest and
local span lock, plus execution and review evidence. The query plan binds this denominator, the
pinned Mathlib/Lake environment, and imports. Until explicit evidence supports `direct`,
`thin_adapter`, or `missing`, the classification remains `unknown`.
The source lock is not rights/egress authority, semantic admission, a freeze, a coverage result,
a Library record, or a Prover handoff.

## P2-07 census query plan

`ifem-coercive-prerequisite-census-plan.v1.json` is the bounded query plan.
The current frozen lane has 25 retained mathematical nodes and 21 scored
prerequisites; the older "27-node" description is stale and has no authority
over the content-addressed lane revision. Candidate declaration names and
module hints are probes only. Even a successful Lean lookup remains `unknown`
until Builder semantic review supplies the exact evidence required for
`direct`, `thin_adapter`, or `missing`.

Use the short wrapper from a pinned checkout:

```text
uv run --frozen python scripts/ifem_prerequisite_census.py check-plan
uv run --frozen python scripts/ifem_prerequisite_census.py render-query --out <query.lean>
uv run --frozen python scripts/ifem_prerequisite_census.py not-run --reason wsl_unavailable --out <result.json>
```

The executable query is POSIX/WSL-only and produces observation evidence, not
a mapping verdict:

```text
uv run --frozen python scripts/ifem_prerequisite_census.py run --out <result.json> --observation-out <observation.json>
```
