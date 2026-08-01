# iFEM structural calibration

Status: source-text-free discovery calibration; not textbook alignment, semantic admission, or proof
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

The implemented role bridge derives a separate Apache-2.0 project-synthetic prompt fixture and an
exact `SourceRecordV1`/`RightsRecordV1` for the actual outbound bytes. The catalog and role-probe
corpus do not themselves authorize egress. Each harmful mutant must have a surface-matched
baseline and a falsifying witness or counterexample. Outbound prompts must
omit catalog IDs, control labels, risk names, mutation names, required dispositions, source
locators, graph bytes, and iFEM source bytes. The current ten-case authorized floor suite remains
unchanged; iFEM probes require a separately locked bridge and evaluator.

| Catalog role | Benchmark role | Measurement boundary |
| --- | --- | --- |
| `conversion_proposer` | `statement_formalizer` | Requests a semantic gap when source-text-free structure is insufficient |
| `fidelity_reviewer` | `fidelity_reviewer` | Accepts a baseline and rejects its harmful mutant |
| `mutation_critic` | `cheating_supervisor` | Detects a change to the frozen structural boundary |

The first row measures abstention and guardrail behavior, not formalization competence. Results
remain role-local; cross-role aggregation is forbidden. Because the paired corpus and construction
code are public, this lane is open calibration rather than a held-out or contamination-resistant
benchmark; repository-aware lookup can recover the intended baseline.

## Project-synthetic witness boundary

The eight local witness specifications are independently pinned twice: the role-probe corpus
commits each complete specification, while the evaluator checks a separate immutable golden digest
before interpreting any field. Field addition, removal, or mutation therefore fails even if an
in-process caller also rewrites the role-probe commitment table. These digests detect code or
fixture drift; they are neither signatures nor mathematical proofs.

A witness report's internal hashes establish only payload integrity. Verification, rendering, and
atomic writing rebuild the exact role-probe corpus from the supplied candidate graph, rerun all
eight evaluator checks, and require byte-for-byte contract equality with the proposed report. A
self-hashed or normally `model_validate`-constructed report cannot certify its own semantic fields.

The checks remain project-synthetic observations. In particular, the absolute-value case is a
singleton observation on a deliberately non-sign-closed scope. It is not a counterexample to the
usual globally quantified bilinear continuity bound on a real vector space, where sign closure can
make the one-sided and absolute formulations equivalent. The strengthened finite evaluator checks
finite-support truncations and exact geometric tails for `c00`/`l2`; subspace membership,
restriction equality, and an ambient outside witness in `R^2`; zero lower-bound and positive
candidate refuters on `(0,1)`; and the nonsymmetric matrix values plus positive-definite symmetric
part for parameter reversal. These remain executable observations with named standard-lemma
dependencies, not Lean/kernel evidence. None of these artifacts can establish textbook fidelity,
freeze a statement, enter Prover, or authorize promotion.

The executable role-pair, witness, pair-split, private-root, and exact-wire boundary is recorded
in [iFEM role calibration v1](builder-ifem-role-calibration-v1.md). That document is the current
implementation boundary for D16-D24; this catalog document remains the source-text-free registry
description.

## Verification

```text
uv run --frozen pytest -q \
  Builder/tests/test_ifem_candidate_dependency_graph.py \
  Builder/tests/test_ifem_structural_calibration.py \
  Builder/tests/test_ifem_structural_witness_validation.py
```

Acceptance requires deterministic rebuild, complete risk coverage, exact graph binding, rejection
of `model_construct` authority or case tampering, and preserved no-freeze/no-handoff behavior.
A consumer of an independently supplied catalog must call
`verify_ifem_structural_calibration_catalog_against_graph()` with the exact candidate graph; a
standalone catalog hash is not proof of provenance. D32/D34 instead consumes the deliberately
published, canonical role-probe corpus through a loader that pins both file and content hashes.
Only `scripts/ifem_structural_role_corpus.py materialize` may rebuild a successor corpus from the
locked source graph; there is no automatic source-cache fallback in plan, preflight, run, or
evaluation.
