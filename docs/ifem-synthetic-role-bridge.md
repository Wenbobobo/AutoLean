# iFEM synthetic-role bridge

`benchmarks.ifem_synthetic_role_bridge` is the independent D25 bridge for the sixteen
project-authored synthetic iFEM role prompts. It is deliberately separate from
`authorized_role_bridge.py` and does not reuse its fixed ten-trial authorization or any
Builder/Prover contract.

The four-step API is `prepare`, `execute`, `evaluate`, and `receipt`:

1. `prepare` revalidates the public fixture, applies the fixed role-specific system prompt and
   JSON response policy, and asks an injected executor for one `CanonicalJsonRequestBody`. The
   returned `OutboundRequestBodyV1` is bound to the exact in-memory bytes; credentials and
   private-field markers are rejected.
2. `execute` passes those exact bytes to the executor. The executor must acknowledge the same
   body binding, so an adapter cannot silently rebuild a different payload.
3. `evaluate` joins the private oracle only in evaluator memory. Callers should pass the public
   fixture too, so its content/case/prompt digests are rebound before the oracle is read. The
   expected side is not part of the execution receipt.
4. `receipt` emits only fixture/case identity, prompt and logical-request digests, provider
   configuration digest, and the exact body binding. It contains no prompt, model output,
   response identifier, credential, or private-oracle data. Model output and response identifiers
   are deliberately not published even as ordinary SHA-256 values: both are commonly low entropy
   and recoverable by enumeration. The separate
   [private ledger](ifem-synthetic-role-private-ledger.md) now provides an authenticated
   operator-private CAS/manifest sidecar and its public projection uses only a domain-separated
   keyed commitment.

`IFEMSyntheticRoleFakeExecutor` is deterministic and captures the exact bodies for offline
re-verification. A real adapter must implement the same explicit exact-byte executor protocol;
`render_receipt` revalidates the digest-only projection before persistence. This module does not
grant model execution, benchmark, semantic, freeze, Prover, or promotion authority. Passing the
focused tests is synthetic calibration plumbing evidence only.

`benchmarks.ifem_role_reconciliation` is the private evaluator-side join. It rebuilds the public
fixture and private oracle from the exact corpus and operator seed. When receipts are present, it
also requires a fixed preparation executor and independently regenerates every logical request,
provider configuration digest, and exact body binding before comparing the receipt. Counting a
self-hashed body digest is not verification. The public projection emits only fixed role counts and
public-fixture digests. It does not publish an oracle digest: the sixteen expected-side labels are
low entropy and an unkeyed digest would disclose them to enumeration. Its renderer repeats the
private rebuild, so a self-consistent forged report, a legal clause rewrite, or an arbitrary
self-hashed request binding is rejected. This is still calibration integrity, not transport,
semantic, or benchmark authority.

Fixture hashes are integrity bindings, not independent proof of source semantics. The private
oracle and raw model output remain non-public; D31 adds only a keyed output commitment after
private CAS/manifest recovery. This lane still has no benchmark score, semantic admission, freeze,
Prover handoff, or production isolation authority.
