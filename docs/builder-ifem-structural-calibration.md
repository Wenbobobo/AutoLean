# iFEM structural calibration

Status: source-free discovery calibration; not textbook alignment, semantic admission, or proof
authority

## Purpose

`Builder/src/autolean_builder/ifem_structural_calibration.py` binds the verified iFEM candidate
dependency graph to a closed project-authored registry of structural conversion risks. The
registry gives later synthetic model probes and mutation tests a stable denominator; it is not a
model prompt or a source-to-statement conversion.

The v1 registry contains sixteen cases across three roles and eight risk/mutation families:
quantifier order, positivity, absolute-value preservation, closed-subspace assumptions, restricted
versus ambient domains, infimum versus attainment, parameter order, and vacuous hypotheses. Each
family has two fixed cases. Cases reference only closed iFEM candidate-node identifiers. The
catalog binds the complete node set, candidate-graph content hash, and graph's digest-only source
binding.

## Authority boundary

The catalog contains no source text, excerpt, Lean statement, or model input. It creates neither a
FormalGraph nor an ExecutionGraph, and every semantic, freeze, handoff, egress, and promotion flag
is false. `freeze_statement()` and `handoff_to_prover()` always fail.

The candidate graph is still only a planning graph. Its node anchors are deterministic index
positions, and its edges are unreviewed dependency hypotheses. The catalog therefore cannot
establish that a mutation is mathematically harmful for a particular textbook statement.

## Benchmark bridge rule

The catalog remains evaluator-side metadata. It must not be sent to a model: its risk, mutation,
role, and required-disposition fields disclose the oracle, and its egress contract is explicitly
false.

A later role Benchmark bridge must create a separate Apache-2.0 project-synthetic probe corpus and
an exact `SourceRecordV1`/`RightsRecordV1` for the actual outbound bytes. Each harmful mutant must
have a surface-matched baseline and a falsifying witness or counterexample. Outbound prompts must
omit catalog IDs, control labels, risk names, mutation names, required dispositions, source
locators, graph bytes, and iFEM source bytes. The current ten-case authorized floor suite remains
unchanged; iFEM probes require a separately locked bridge and evaluator.

| Catalog role | Benchmark role | Measurement boundary |
| --- | --- | --- |
| `conversion_proposer` | `statement_formalizer` | Requests a semantic gap when source-free structure is insufficient |
| `fidelity_reviewer` | `fidelity_reviewer` | Accepts a baseline and rejects its harmful mutant |
| `mutation_critic` | `cheating_supervisor` | Detects a change to the frozen structural boundary |

The first row measures abstention and guardrail behavior, not formalization competence. Results
remain role-local; cross-role aggregation is forbidden.

## Verification

```text
uv run --frozen pytest -q \
  Builder/tests/test_ifem_candidate_dependency_graph.py \
  Builder/tests/test_ifem_structural_calibration.py
```

Acceptance requires deterministic rebuild, complete risk coverage, exact graph binding, rejection
of `model_construct` authority or case tampering, and preserved no-freeze/no-handoff behavior.
Every downstream consumer must call
`verify_ifem_structural_calibration_catalog_against_graph()` with the exact candidate graph; a
standalone catalog hash is not proof of provenance.
