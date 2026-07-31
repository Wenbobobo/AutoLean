# D33 iFEM private evaluation operator

Status: implemented local evaluator; no model, semantic, freeze, Prover, or promotion authority

After a selected D32/D34 run reaches `settled`, the D33 command reloads the protocol-pinned,
source-text-free graph/corpus pair, rebuilds the corpus against the graph, then rebuilds the
fixture, private oracle, DeepSeek request policy, witness checks, and authenticated private
manifest. It performs no provider call and does not require the ignored source cache. The required
`--protocol` must exactly match the runner's fixed graph/corpus hashes, profile, request policy,
and response contract. The
operator-material and private-run roots remain outside the repository; only the role/risk
aggregate may be written to a public output root.

```text
uv run --frozen python -m scripts.ifem_private_evaluation --protocol d34-v2 --private-root <ABS_PRIVATE> --operator-material-root <ABS_MATERIAL> --public-output-root <ABS_PUBLIC>
```

For archived D32 roots, use `--protocol d32-v1`. A mismatched protocol is rejected before private
manifest evaluation and cannot turn one revision's responses into another revision's report.

The output contains complete role and risk-family counts plus full-run token totals/buckets. Its
v2 public projection also binds the chosen protocol, exact-profile hash, request-policy hash, and
response contract, so a D32 aggregate cannot be confused with a D34 aggregate after export. It
contains no per-case prediction, expected option, raw response, tool call, response identifier,
private CAS reference, seed, HMAC value, or enumerable oracle/output digest. Every semantic,
benchmark, statement, freeze, Prover-handoff, and promotion authority flag remains false.

Only the seed-dependent option orientation and per-run expected option remain private. The
baseline/mutant semantics are published in the project-synthetic corpus, so this mechanism is not
a held-out or contamination-resistant benchmark and its aggregate cannot rank models.
