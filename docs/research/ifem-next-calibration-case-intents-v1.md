# iFEM next calibration case intents v1

Status: local, source-free, non-authoritative queue metadata.

This projection consumes the replayable unknown-only iFEM calibration risk routing artifact and
emits exactly one intent for each of its 21 nodes. An intent is not a calibration case: it has no
source or rights material, no Lean surface, no catalogue entry, no mutation, no answer or oracle,
no provider exchange, no private state, and no statement, graph, or bundle payload.

Each intent is permanently bound to the fixed lane
`ifem-unknown-only-next-calibration` and its public node identifier. Its stable identifier is
therefore independent of content changes. It contains only the existing non-semantic priority,
the corresponding conservative next action, source order, `unknown` status, and
`not_authored` materialization state.

The queue is sorted by `P0`, `P1`, `P2`, then `P3`, with source order as the only tie-breaker.
The present D35-derived route yields `0/10/2/9` intents respectively. `P3` is special only in
that `structural_risk_discovery_required` is true: no structural-risk details or calibration case
content are created by this artifact.

The retained canonical queue is
[`ifem-next-calibration-case-intents-2026-07-31.json`](ifem-next-calibration-case-intents-2026-07-31.json).
Its content SHA-256 is
`cd0101db7a0f5b99c9a8311ce01540a24faba3f97881bc31d9a652b2cb19cbc8`; its file SHA-256 is
`cb86f9d67faddda54c2fea8a3d0698dd2711df579d0275bfd0b2a52ae404dd38`.

All authority flags are false. No intent may author material, classify a node, freeze a statement,
hand work to Prover, or promote a result. `freeze_statement()` and `handoff_to_prover()` always
raise. The artifact is canonical JSON, content-addressed, loadable only from strict UTF-8 JSON,
and write-once. A load verifies format and self-hash; provenance requires a fresh exact replay via
`verify_ifem_next_calibration_case_intents_against_paths()`.

## Verification

```text
uv run --frozen pytest -q Builder/tests/test_ifem_next_calibration_case_intents.py scripts/tests/test_ifem_next_calibration_case_intents_script.py
uv run --frozen ruff check Builder/src/autolean_builder/ifem_next_calibration_case_intents.py Builder/tests/test_ifem_next_calibration_case_intents.py scripts/ifem_next_calibration_case_intents.py scripts/tests/test_ifem_next_calibration_case_intents_script.py
uv run --frozen ruff format --check Builder/src/autolean_builder/ifem_next_calibration_case_intents.py Builder/tests/test_ifem_next_calibration_case_intents.py scripts/ifem_next_calibration_case_intents.py scripts/tests/test_ifem_next_calibration_case_intents_script.py
uv run --frozen mypy -p autolean_builder
uv run --frozen mypy scripts
```
