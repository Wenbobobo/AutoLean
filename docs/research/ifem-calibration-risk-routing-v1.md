# iFEM calibration risk routing v1

Status: local, source-free, non-authoritative advisory projection.

This artifact rebuilds the existing 21-node unknown-only iFEM classification triage and reads only
the public aggregate in `ifem-deepseek-role-calibration-2026-07-31-1024-v3.json`. It does not
read the private ledger, raw model output, oracle, source text, Lean names, Lean types, or any
`benchmarks` runtime state. The D35 input is accepted only as canonical JSON with its self-hash,
v2 schema, `d35-v3` protocol binding, sixteen-case denominator, complete eight-risk aggregate,
all-false authority object, and the exact frozen fixture/profile/request-policy hashes. This
prevents a rehashed report from relabelling another fixture or generation policy as the same D35
experiment while still allowing separately retained outcomes under that fixed protocol.

Every output node remains `unknown`. A route is an action priority, not a semantic classification:

| Observed aggregate for any risk already attached to the node | Priority | Required next calibration |
| --- | --- | --- |
| One or more `incorrect` observations | `p0_incorrect` | `deterministic_or_higher_capability_calibration` |
| No incorrect observations, at least one `invalid` observation | `p1_invalid` | `deterministic_or_higher_capability_calibration` |
| Only correct or abstain observations | `p2_independent_machine_review` | `independent_machine_review` |
| No attached structural risk | `p3_create_calibration_case` | `create_calibration_case` |

An incorrect result is deliberately the highest priority but still has no semantic consequence:
it does not prove a node missing, direct, or thin-adapter, and cannot authorize a statement change.
The projection has all semantic, freeze, Prover-handoff, and promotion authority flags false;
`freeze_statement()` and `handoff_to_prover()` always fail.

The module is content-addressed and supports canonical write-once materialization. Loading checks
only canonical format and the output self-hash; provenance requires replaying the exact public
inputs with `verify_ifem_calibration_risk_routing_against_paths()`.

## Verification

```text
uv run --frozen pytest -q \
  Builder/tests/test_ifem_calibration_risk_routing.py \
  scripts/tests/test_ifem_calibration_risk_routing_script.py
uv run --frozen ruff check \
  Builder/src/autolean_builder/ifem_calibration_risk_routing.py \
  Builder/tests/test_ifem_calibration_risk_routing.py \
  scripts/ifem_calibration_risk_routing.py \
  scripts/tests/test_ifem_calibration_risk_routing_script.py
uv run --frozen ruff format --check \
  Builder/src/autolean_builder/ifem_calibration_risk_routing.py \
  Builder/tests/test_ifem_calibration_risk_routing.py \
  scripts/ifem_calibration_risk_routing.py \
  scripts/tests/test_ifem_calibration_risk_routing_script.py
uv run --frozen mypy --strict \
  Builder/src/autolean_builder/ifem_calibration_risk_routing.py \
  Builder/tests/test_ifem_calibration_risk_routing.py \
  scripts/ifem_calibration_risk_routing.py \
  scripts/tests/test_ifem_calibration_risk_routing_script.py
```
