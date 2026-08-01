# Builder machine-advisory admission

Status: implemented fail-closed P2-13 negative route; positive continuation intentionally blocked

## Purpose

`autolean_builder.machine_advisory_admission` consumes an already
`VerifiedMachineQuorumReport` and adds the risks that the quorum v2 artifact intentionally did not
encode:

- complete, response-bound per-reviewer risk assessments with typed critical dissent and
  counterexample signals;
- the quorum's declared failure-domain correlation plus public provider, model revision,
  configuration, role-environment, runtime, and model failure-domain lineage;
- per-reviewer calibration protocol, scope, lineage, and validity-window declarations;
- an explicit fail-closed route whose only dispositions are
  `continue_machine_advisory_review` and `abstain`.

The layer is a sidecar. It does not change the historical quorum v2 serialization or fingerprint,
and it is not connected to `workflow.FreezeGate`.

## Versioned artifacts

`MachineAdvisoryExecutionLineageV1` derives two fingerprints. The model-lineage fingerprint omits
provider route, endpoint, role prompt, and configuration differences so that aliases of the same
model ID and revision remain one correlated failure domain. A separately supplied model
failure-domain fingerprint catches known aliases beyond those public identifiers. It cannot erase a
repeated `declared_failure_domain_id` in the verified quorum: that independently records
`shared_declared_failure_domain`. The execution-lineage fingerprint additionally binds provider
configuration, the exact reviewer role environment, and the runtime environment. These identities
are declared and structurally checked, not operator-attested, so V1 records
`lineage_evidence_unverified` and abstains even when they are otherwise consistent.

`MachineAdvisoryCalibrationBindingV1` binds one reviewer to a declared calibration artifact, input,
protocol, scope, execution lineage, `calibrated_at`, and `valid_until`. The evaluator receives an
explicit timezone-aware `evaluated_at`; it never reads the wall clock, so replay is deterministic.
Equality with `valid_until` is stale. A digest declaration is not a verified calibration report, so
V1 records `calibration_evidence_unverified` and abstains. A future positive route must consume the
typed calibration result plus signed model-completion receipts under a new schema; arbitrary
digests cannot clear the current gate.

`MachineReviewerRiskAssessmentV1` is mandatory for every reviewer and contains zero or more
`MachineReviewerRiskSignalV1` values. Each assessment binds the exact subject, reviewer task, and
verdict fingerprint, so omitting an entire reviewer's risk declaration produces abstention rather
than an implicit clean result. Signals contain no raw mathematical text; a detached assessment or
signal is rejected rather than counted.

`MachineAdvisoryAdmissionDecisionV1` binds the verified quorum fingerprint, underlying quorum
report fingerprint, contract revision and hash, subject, every sidecar, the expected calibration
protocol and scope, the explicit evaluation time, and the earliest calibration expiry. Its
fingerprint uses canonical JSON bytes. Consumers must call the time-aware freshness check again;
the serialized historical disposition is not a perpetual capability.

## Abstention rules

The decision is `abstain` when any of these conditions holds:

- the verified quorum requires semantic escalation, reviewers disagree, a mutation survives, a
  semantic control is rejected, or a declared semantic check fails;
- a reviewer risk assessment is missing, or any bound critical-dissent or counterexample signal
  exists;
- the verified quorum declares a shared failure domain, a reviewer lineage is missing, its role
  environment is detached, or multiple reviewers share a model identity or sidecar failure domain;
- a calibration is missing, for another protocol, scope, or execution lineage, from the future, or
  stale;
- current quorum execution, lineage, or calibration evidence remains unverified.

No majority threshold can override these conditions. Unknown reviewers, duplicate sidecars, and
sidecars detached from exact reviewer evidence are structural errors.

The enum reserves `continue_machine_advisory_review` for a future versioned positive route, but the
current quorum and sidecar types cannot produce it: quorum execution, declared lineage, and
digest-only calibration are explicitly unverified. This avoids turning locally self-consistent
declarations into a clean result. Every current decision is `abstain`, with precise additional
risks preserved. The decision always has `authority = machine_advisory`, `may_freeze = false`, and
`prover_handoff = forbidden`; direct freeze and handoff methods fail.

## Evidence boundary

The focused test matrix covers mandatory baseline abstention, reviewer disagreement, surviving
mutation, explicit dissent, counterexample reporting, provider-alias and shared-failure-domain
detection, missing risk/lineage/calibration coverage, protocol/scope/lineage drift, future and
boundary-stale timestamps, detached assessments, input-order invariance, consumption-time
freshness, and preserved quorum bytes.

```text
uv run --frozen pytest -q \
  Builder/tests/test_machine_advisory_admission.py \
  Builder/tests/test_machine_semantic_quorum.py
```

Passing these tests proves the deterministic P2-13 negative routing mechanics only. It does not
prove that a lineage declaration is true, a calibration benchmark is representative, a reported
counterexample is mathematically valid, or a statement is faithful to its source. A signed
completion-bound calibration verifier remains required before P2-13 can be complete. Current
same-model multi-role runs correctly abstain under V1 even when providers, prompts, seeds, or role
names differ.
