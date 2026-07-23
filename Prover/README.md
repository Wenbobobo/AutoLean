# AutoLean Prover

`autolean-prover` owns proof search without owning or weakening theorem statements. Its public
boundaries are deliberately small:

- `ModelProvider` generates model output and declares its capabilities.
- `ExecutionHarness` runs an explicit argv under a clean environment policy.
- `ProofRunRequest` and `ProofRunResult` are versioned, JSON-safe run records.
- validation gates compare immutable source bytes, not theorem names or model claims.
- `TrustedLeanVerifier.observe` exposes only a transient report and non-secret OCI facts;
  `attest_oci_observation` turns that observation into a content-addressed evidence artifact and
  verifier-attested report for the control plane.

Provider configuration contains environment-variable names only. Secret values are resolved at
call time and are never included in requests, results, or serialized configuration. Network calls
are absent from the default test suite.
