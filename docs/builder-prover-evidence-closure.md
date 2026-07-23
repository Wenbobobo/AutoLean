# Builder-Prover evidence closure

The offline integration fixture in
`benchmarks/tests/test_builder_prover_closed_loop.py` exercises the public boundary end to end:

1. two declared-independent translators, a separate mutation agent, and an independent semantic
   reviewer produce one canonical `autolean.builder-fidelity-evidence.v1` artifact;
2. the artifact's SHA-256 is verified against `FidelityEvaluation.evidence_hash`, persisted in
   the content-addressed artifact store, and carried as a typed
   `FidelityEvidenceArtifactRefV1`;
3. only the reviewed draft can freeze, and only that frozen revision can produce a signed
   `FormalizationTaskBundleV1`;
4. the control plane rehashes and minimally cross-binds the canonical fidelity artifact, roots
   its reference in `task.registered`, and only then permits a fenced claim;
5. a Prover-side failure can append a revision-bound `GapReportV1` and
   `ContractChangeRequestV1`, but neither command can mutate the registered bundle;
6. the next revision begins as a draft, rejects the old fidelity evaluation, and must run the
   Builder harness again before it can cross the bridge;
7. an offline `FakeProvider` receives a role-scoped `ContextPack` projected only from the bundle,
   submits a proof candidate, and a separately signed synthetic verifier report reaches the
   acceptance transition.

The final step is architecture evidence, not theorem-proving evidence. It deliberately runs no
Lean command and no OCI worker; the report states that fact. Kernel correctness remains gated by
the authoritative Linux/OCI verifier path.

## Residual boundaries

- `FidelityReportV1.evidence_hash`, the typed bundle reference, Builder handoff hash, retained
  bytes, and `task.registered` reference now form one content chain. Production registration
  requires it. Synthetic legacy fixtures must opt into the conspicuously named
  `allow_test_only_unreviewed_bundles` switch; that switch is not a migration or release mode.
- Registration now commits the `task.registered` event, Builder-attestation nonce, idempotency
  record, and immutable `(contract_id, revision) -> (bundle_id, handoff_hash)` projection in one
  SQLite transaction. Exact retries reuse the original event; conflicting legacy events make
  projection backfill abort rather than selecting a winner.
- Fixture actor names and HMAC keys are public test data. Production semantic reviewer identity and
  signing authority require authenticated operator-owned gateways.
