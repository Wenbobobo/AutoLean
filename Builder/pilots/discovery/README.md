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
output, or coverage results in this directory. The tracked
`ifem-candidate-dependency-graph.v1.json` and
`ifem-structural-role-probe-corpus.v1.json` are exceptions only in form, not
content: they are canonical, source-text-free but source-metadata-bound public
project-synthetic runtime inputs. Their exact file/content hashes are pinned
separately by each D32/D34 protocol, and the corpus is rebuilt against the graph
before use.
Regeneration is an explicit source-cache-bound operator action; routine
plan/preflight/run/evaluation never falls back to that cache.

## P2-06/P2-07 evidence boundary

The iFEM thirteen-file source lock is now locally acquired and independently replayed under
`local_only`; its receipt SHA-256 is
`74eca6689fe69dcbf2f34ea524a99cacc2054c0a39cfecfb11887c29e13cf239`.
The frozen census manifest remains historically `not_started`. A generic-host WSL census attempt
under `/mnt/c` reached its internal 600-second bound, wrote no observation/result, and cleaned its
temporary query. It does not change the manifest and it does not classify a node. Until explicit
evidence supports `direct`, `thin_adapter`, or `missing`, all 21 scored prerequisites remain
`unknown`.

The separate fixed five-profile plan has content SHA-256
`21bd18f7f8522470247852ef8281f1e4c7016f6415771e4fc0c05ab433247619`. It built local child image
`sha256:6c54c3600b2572ddcabae024a3a8b6c533c3defa6d4bda31c90408cb4c61f0ab` with build-receipt
file/content SHA-256
`c859ec69ec46a2344f42a4e42f17b6922ade51c92d1bb22c674c7a4885185f26` /
`80659121feb8a831c6255879f7cf6d1230d1cd64e8272559523ef99aeab68251`. Two runs wrote
byte-identical observation/result artifacts: file SHA-256
`1900a11003a78ecaa681ad76ab5660762d4f5ca81e28b0b9525a95998131d736` /
`ba9ca42865fd385fbf94b922e4111dd76ab9dec4386f28bbba778779dfc52298`; embedded content SHA-256
`0dee6c5b7e4c0db81fb20e9821e2fd2eede727d9552d7fe4a7def7b6b6b1a348` /
`55e9c0f95d9634dc39fb37cd1b00a97575cbc91090c15701d39f8e3868110238`.

| Exact direct-import profile | Loaded-module closure | Present candidates |
| --- | ---: | ---: |
| `Defs` | 3,685 | 13/25 |
| `Dual` | 4,198 | 23/25 |
| `LaxMilgram` | 4,199 | 25/25 |
| `Operator.Basic` | 3,666 | 14/25 |
| `Operator.Bilinear` | 3,667 | 19/25 |

These are receipt-bound pinned-environment visibility facts. The runtime used network none,
read-only root, dropped capabilities, `no-new-privileges`, UID/GID `65532:65532`, and no host bind
mounts. An exact direct import is not the same thing as a narrow transitive closure; no
closure-width acceptance policy has been accepted, and independent review remains required.
The source lock is not rights/egress authority, semantic admission, a freeze, a coverage result,
a Library record, or a Prover handoff.

## P2-06 census query plan

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

## P2-08 readiness gate

`scripts/ifem_pilot_readiness.py` consumes completed, content-addressed P2-06
census and P2-07 singleton-import evidence. The v2 gate applies the unchanged
21-node 15--16 direct/thin-adapter feasibility rule but cannot issue `go`
until a separate closure-acceptance policy is frozen; missing execution,
semantic-review, or closure-policy evidence remains `incomplete`. A different
or broad direct import is rejected by the P2-07 collector before it can become
a readiness input. It never creates a source-rights decision, frozen statement,
Library record, or Prover handoff. See
[`docs/research/ifem-pilot-readiness-gate-v1.md`](../../../docs/research/ifem-pilot-readiness-gate-v1.md).

The completed profile pair supplies one required visibility input only. Because the P2-06 census
has no observation/result and no independent semantic classifications, P2-08 remains
`incomplete`. The public
[`2026-07-31` v2 decision](../../../docs/research/ifem-pilot-readiness-decision-2026-07-31.json)
binds the exact profile evidence and an honest `host_query_timeout` census record; its content
SHA-256 is `c45cbff7a5efed34e59efbe922729f30f6d25cbe2120bd5cc1825325cb851b90`.
It records 21 unknown nodes and unresolved closure policy, with freeze and handoff forbidden.
