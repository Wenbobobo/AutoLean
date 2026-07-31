# iFEM Source-Free DeepSeek Operator V1

## Scope

`scripts/ifem_source_free_model_work.py` is the smallest live-model path for the iFEM
source-free calibration fixture. It operates exactly one coordinate: the first
`statement_formalizer` node in the persisted nine-case seed manifest. It does not classify a
domain, create a statement contract, freeze Builder work, hand work to Prover, publish a score,
or create promotion authority.

The coordinate is advanced only through `LocalSourceFreeStageLedger.execute_coordinate`. The
runner never calls the sidecar directly. Full `resume` and the one-coordinate canary therefore
share the same claim, durable-dispatch, completion-verification, and reconciliation state
machine. The other 26 source-free coordinates remain pending.

## Fixed Boundary

- The only model route is the hash-pinned `deepseek-v4-pro.ifem-role-calibration.v4.json` profile.
- The policy is fixed at 2048 input tokens, 4096 output tokens, 120 seconds, JSON object output,
  `high` reasoning effort, and `max_attempts=1`. Authorization reserves a conservative
  10 micro-USD-per-token upper bound, so the one-attempt ceiling is 61,440 micro-USD. This is an
  accounting bound, not a claim about the provider's billed price.
- One SQLite file is both the `EventStore` and lease/control-plane database. The raw model output
  is written only to a separate operator-private content-addressed store.
- The stage ledger records its dispatch before the sidecar can call the provider. The sidecar
  records its fenced authorization binding before that call.
- A durable attempt without a settled completion can only yield reconciliation. Neither `run`
  nor `resume` dispatches it again.

The local HMAC material is generated once under the operator-private root so a settled receipt
can be verified after a process restart. It is not a provider credential copy, it is never placed
in the checkout or stdout, and it is explicitly test-only local authority. Replacing it with a
signing gateway is required before this path can support any stronger claim.

## Modes

All roots must be absolute, physical paths outside every Git checkout and must have existing
physical parents. `state-root` and `private-root` must be disjoint.

| Mode | Egress | API-key environment read | State effect |
| --- | --- | --- | --- |
| `plan` | No | No | None |
| `preflight` | No | No | None |
| `run` | At most one request | `AUTOLEAN_DEEPSEEK_API_KEY` only | Initializes or reopens the exact run and advances one coordinate |
| `resume` | No | No | Recovers a previously settled receipt only |
| `report` | No | No | Reads row presence only; it does not claim CAS verification |

`run` additionally requires `--operator-approved`. It obtains the API key only from the named
process environment variable; there is no API-key file option. The public JSON output contains
neither raw response text, a credential, an operator path, run label, model identifier, nor a
provider-dispatch count claim.

For a first operator invocation, use the repository script through `uv`; choose two external
operator-owned roots. The `plan` and `preflight` commands are safe checks before supplying an
API environment variable. A later `resume` must use the same roots and run label but has no API
key requirement.

## Failure and Recovery

The stable admission resolver persists one exact attestation per
`model_work_admission_evidence_identity`; a restarted process obtains the same admission rather
than minting a competing record. If a process dies after provider settlement but before the
ledger terminal event, `resume` reconstructs the frozen work bundle, recovers the completion
receipt from the control plane, verifies its private CAS artifact, and appends the original
ledger completion. It does not construct or call a provider.

If the attempt binding exists but no settlement exists, the public result is
`reconciliation_required`. The system deliberately does not infer whether a provider request
occurred. An operator can inspect private evidence, but no result from this fixture may cross the
Builder freeze or Prover handoff boundary.

If settlement exists but the recovered response cannot satisfy the finite role schema, both
`run` and `resume` report `settled_completion_rejected`. They retain the receipt and never issue a
replacement request. This distinguishes a provider/network ambiguity from an observed response
contract failure without disclosing the response.

A successful `run` or `resume` report re-reads the private CAS receipt, exact attempt binding,
and already-terminal ledger binding. It publishes only their three SHA-256 commitments. The
read-only `report` mode exposes only whether one attempt and one settlement row were observed; it
keeps `private_completion_verified=false` rather than treating row counts as CAS or ledger
verification.

## Verified Local Evidence

The zero-network tests cover:

- credential-free `plan` and `preflight` with no root creation;
- exactly one fake-provider call and no call on a repeated `run`;
- crash after a settled completion and `resume` without API-key lookup or transport construction;
- recovery in a fresh Python subprocess using persisted verifier material, again without an API
  key or provider construction;
- byte-identical replay of a persisted admission;
- exact nonzero pricing reservation and public ledger/attempt/completion commitments;
- redacted stdout, including an injected raw response identifier and operator paths;
- read-only aggregate `report`.

These tests are local fake-transport evidence only. A separate bounded operator observation
completed one strict real-provider coordinate and credential-free recovery; see
[the retained canary record](ifem-source-free-deepseek-canary-2026-08-01.md). Neither observation
is a DeepSeek benchmark result, model comparison, semantic fidelity result, or proof that a real
provider request is recoverable in production.
