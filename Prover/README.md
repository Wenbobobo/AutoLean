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

For lease-bound OCI execution, `FrozenTaskBundleInput` captures the Builder handoff hashes and
`OciExecutionClaim` binds them to a verifier worker/fencing token and an image-owned wrapper
identity. `OciLeanRunner` requires an injected live-lease validator before using that mode, checks
the fence before and after OCI execution, and rejects host mounts over image-owned verifier paths.
The wrapper self-reports the hashes of its own executable and Lean query helper. This produces
`lease-bound-pending-gateway` evidence, not a production signature. Gateway promotion requires a
separate `IndependentExecutionVerifier` to receive the exact request plus canonical V2 evidence,
rerun the approved verifier path, and return a hash-bound public receipt before any signature is
reserved or minted. The receipt is accepted only through an explicit verifier-ID/key trust policy;
its authentication key must be distinct from the gateway signing key. Exact retries use the
ledgered, authenticated receipt and do not rerun it. The OCI canary
performs that second digest-pinned wrapper execution with local test HMAC and still reports
`promotion_attestation_created: false`; a separately deployed signing gateway and
runtime/image-publish attestation remain required for production authority. The local gateway
rejects every `PRODUCTION` construction or issue with `ProductionAuthorityUnavailable`; only a
future independent remote client may implement that interface. Legacy or test runners remain
explicitly `non-production`.

Provider configuration contains environment-variable names only. Secret values are resolved at
call time and are never included in requests, results, or serialized configuration. Network calls
are absent from the default test suite.
