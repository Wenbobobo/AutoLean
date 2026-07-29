# Builder held-out structural calibration

Status: deterministic offline protocol; structural-only evidence, not a fidelity or proof result

`autolean_builder.held_out_calibration` provides a bounded calibration protocol before normal
Builder fidelity review. Its sole input is the canonical
`Builder/pilots/local-calibration/project-synthetic-opening-corpus.v1.json` fixture. Loading first
uses the existing local corpus loader, which verifies the canonical path, corpus bytes, release
manifest, renderer, and repository license. The protocol retains only digest bindings after that
point: it does not copy source text, normalized propositions, mutation fragments, prompts, or raw
responses into its result.

## Split boundary

V1 takes a recorded `split_seed` and ranks the exact eleven manifest-bound samples with a
domain-separated SHA-256 function. It produces exactly five `train`, three `dev`, and three
`held_out` samples. The `HeldOutCalibrationSplitV1` validator rejects any repeated sample ID,
source hash, or derived mutation hash across the three partitions. Before a run, the split is
reconstructed from the repository's canonical corpus path and seed; a rehashed but manually
rearranged allocation is rejected. The run re-loads that canonical manifest rather than trusting an
in-process capability object, so a plugin cannot substitute altered sample bindings merely by
reusing private module state. Every structural case is bound to one partition, one sample binding,
and one declared
synthetic-mutation digest, so results cannot mix a held-out mutation into development evidence.

The V1 run deliberately does not tune a configuration. Its provider, budget, repeat count, and
base repeat seed are precommitted before the held-out partition is evaluated, and every repetition
records its derived seed, provider descriptor, provider configuration hash, and full token/byte/
time budget. This makes the protocol useful for checking split and reporting discipline now; it is
not evidence that a model generalizes from `train` or `dev` to `held_out`.

## What is measured

For each declared synthetic mutation, the report records only:

- strict JSON compliance, including rejection of duplicate keys;
- whether the response reported the fixture's declared structural delta;
- whether its advisory disposition agrees with its own structural-drift flag.

There is no semantic-equivalence label, theorem-correctness score, proof success field, human or
expert signoff, or release decision. A response can be internally consistent and still miss a
structural mutation; conversely, a structural hit says nothing about whether the original
mathematical proposition was formalized faithfully.

## Current execution boundary

V1 accepts only `ScriptedFakeHeldOutCalibrationProvider`, an exact synchronous local fake. Its
requests are text-free and its descriptor fixes `provider_id=fake`, a local endpoint class, an
offline execution mode, and denied external egress. Any shape-compatible provider is rejected
before it is asked to run. The project's synthetic fixture rights also deny model egress, so a
future real-provider experiment must use a separate rights-bound authorization and a newly reviewed
protocol; it cannot replace the fake in this module.

All protocol artifacts carry an authority object whose rights, semantic-review, kernel,
freeze, Prover-handoff, and release fields are false. `HeldOutCalibrationResultV1.freeze_statement`
and `handoff_to_prover` always raise. Passing structural scores can inform a later Builder design
round only; it cannot create a `StatementContractV1` or `FormalizationTaskBundleV1`.

## Current limits

The corpus contains only eleven project-synthetic fixtures and has pending human content review. Its
fixed 5/3/3 allocation is a regression harness, not a statistically meaningful model benchmark.
The fake's declared token counts and timeout are configuration receipts, not independent runtime
attestations. Real textbook calibration, independence of competing agents, semantic review, clean
Lean compilation, and frozen Builder-to-Prover transfer remain separate gates.
