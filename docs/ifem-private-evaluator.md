# iFEM private evaluator (D33)

Status: local project-synthetic aggregation only; explicitly non-promotional.

`benchmarks.ifem_private_evaluator` evaluates the existing sixteen-case iFEM
synthetic role lane after responses have been committed to the D31 private
ledger. It is not an executor, a retry mechanism, or a new model-provider
path. It performs no network or model API call.

## Private evaluation boundary

Before examining a response, D33 reloads the exact protocol-pinned
source-text-free candidate graph and structural probe corpus, rebuilds the
corpus against that graph, and rebuilds the public fixture and private oracle
from the corpus and operator seed. It repeats the eight-risk witness validation
and invokes the D29 reconciliation. Both loaders reject file/content hash
drift, duplicate JSON keys, non-canonical rendering, links, and non-regular
files. It then re-prepares
all sixteen exact requests with the supplied fixed preparation executor and
requires the authenticated private ledger to recover the complete manifest and
each private CAS-backed response. A fixture, oracle, witness report, body
binding, manifest, or response that is only self-consistent is insufficient.
The ignored source cache is needed only to regenerate a successor graph/corpus
pair, not to run or evaluate an already frozen protocol.

"Private oracle" refers only to the seed-dependent option orientation and the
per-run expected option. The baseline/mutant structural semantics are public in
the tracked project-synthetic corpus. A model or agent with repository access
can therefore recover the intended side by lookup; D33 is a calibration
diagnostic, not a held-out, contamination-resistant, or model-ranking benchmark.

The evaluator accepts only one strict response shape:

```json
{"selected_option":"option_a"}
```

`option_b` and explicit `abstain` are the only other accepted values. Bare
strings, the legacy `option` alias, extra fields, duplicate JSON keys, unknown
values, and malformed JSON are invalid. Explicit abstentions and invalid
responses are counted separately. The response text, expected side, selected
side, seed, oracle record, source pair, witness commitment, CAS artifact,
response ID, and any per-case token usage remain private.

## Public projection

The legacy v1 projection contains only the public fixture content hash, the
complete 16-case denominator, aggregate outcome counts for the three roles and
eight risk/mutation families, and full-run token totals with coarse buckets.
The revision-bound v2 projection additionally carries the selected protocol,
SHA-256 of the exact profile bytes, SHA-256 of the request policy, and response
contract. That makes D32 and D34 reports distinguishable after export without
exposing a secret, oracle, raw response, or per-case result. Usage is emitted
only after all sixteen authenticated private responses have been recovered; it
is never emitted per case, per role, or per risk family. The report contains no
oracle or output digest, including no enumerable digest of either low-entropy
value.

The report explicitly keeps raw-output, oracle, seed, CAS-reference, response
identifier, semantic-equivalence, benchmark, statement-contract, freeze,
Prover-handoff, and promotion flags false. Correctness counts are observations
about the project-synthetic lane, not a model ranking, source fidelity result,
Lean result, or release gate.

`render_ifem_private_evaluator_public_report` rebuilds the private evaluation
and compares the result before serialization. The writer repeats that process,
checks that its canonical filename stays beneath its caller-supplied cache
root, and atomically replaces the target. A report with recomputed internal
hashes but changed aggregate counts or token totals is rejected.

## Verification

```text
uv run --frozen pytest -q benchmarks/tests/test_ifem_private_evaluator.py
uv run --frozen ruff check benchmarks/ifem_private_evaluator.py benchmarks/tests/test_ifem_private_evaluator.py
uv run --frozen mypy benchmarks/ifem_private_evaluator.py benchmarks/tests/test_ifem_private_evaluator.py
```

The focused tests use `IFEMSyntheticRoleFakeExecutor` and a local private CAS.
They do not call any external provider and do not establish execution,
benchmark, semantic, kernel, or production authority.
