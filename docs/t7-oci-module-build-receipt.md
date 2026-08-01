# T7 OCI Module Receipt and Declaration Fanout

## Status

`benchmarks.real_lean_project_dag_module_build` defines the module-level T7
contract above the synthetic declaration-node V2 layer. Its focused tests run
only an injected fake runner. They do not invoke Lean, Docker, WSL, or the
network.

The current implementation proves contract and recovery semantics:

- one immutable module spec binds the changed-source witness, rebuild plan,
  execution bundle, complete transitive source-tree CAS, direct-import module
  receipts and OLean artifacts, Lean version, full mathlib commit, lake
  manifest, exact OCI RepoDigest/config/platform, image-policy bytes and hash,
  expected declaration query, argv, paths, and optional reuse baseline;
- a live lease produces a separate request binding holder, fencing token, and
  worker identity without making authority part of the stable job ID;
- one runner call yields one process receipt. The caller cannot pass an
  evidence class or a preconstructed receipt to the store;
- a successful receipt and every declaration projection are appended in one
  `EventStore.append_fenced` transaction on one module stream. A crash cannot
  durably leave a successful module event with partial fanout;
- every declaration record is derived from the same successful module receipt
  and the exact locked query artifact. It has no per-node stdout, subprocess,
  or invented result artifact; and
- reuse requires an earlier successful receipt already present in the same
  store with the same module source tree, image/environment, lake manifest, and
  declaration query. An opaque OLean blob is insufficient.

`verify_frozen_lean_module_build_receipt` is the public read-only verifier. It
rechecks the request, worker, source tree, image, runtime observation, stdout,
stderr, OLean, query, and receipt CAS objects. It establishes internal
consistency only.

## Acceptance boundary

Both supported evidence classes are mechanically non-promotable:

| Evidence | Meaning | Promotion | Kernel acceptance |
| --- | --- | --- | --- |
| `synthetic_fake_module_v1` | Injected test runner, no process claim | false | false |
| `operator_local_oci_without_trusted_gateway_v1` | Local OCI observation after T6 preflight | false | false |

Every receipt, event, declaration record, and aggregate status carries
`promotion_eligible: false` and `kernel_acceptance_eligible: false`. Aggregate
states are `MODULE_PENDING`, `MODULE_BUILD_SUCCEEDED_NONPROMOTABLE`,
`MODULE_BUILD_FAILED_NONPROMOTABLE`, or `MODULE_REUSED_NONPROMOTABLE`; this
stream never returns naked `VERIFIED`.

Module success means only that one process exited successfully and emitted the
exact locked declaration/type/axiom query. It is not a per-declaration kernel
acceptance decision. `require_trusted_module_receipt_for_kernel_acceptance`
therefore rejects every V1 module receipt after verifying it. A later trusted
gateway must use a new attested verifier path; it must not reinterpret this
schema.

## Operator preflight

Run the preflight only on an operator machine with the exact T6 image already
present:

```text
uv run --frozen python scripts/real_lean_module_build_preflight.py --image <repository@sha256:digest> --runner-policy-path /opt/autolean/policies/t7-module-runner-policy.v1.json --artifact-root <absolute-operator-cas> --runner-identity <public-id>
```

The command first calls the existing
`Library/scripts/library_substrate_image.py verify` path. On Windows, that path
delegates to the locked WSL distribution. It then checks Docker's exact config
digest and Linux platform and reads the policy bytes from that same RepoDigest
under a network-disabled, read-only container.

The report deliberately says `module_execution_enabled: false`,
`trusted_gateway_attestation: false`, `promotion_eligible: false`, and
`kernel_acceptance_eligible: false`. T6 does not yet ship an image-owned T7
multi-module build/query wrapper. Accepting an arbitrary host callback as OCI
evidence would let the caller self-assert real execution, so
`OperatorLocalOciModuleRunner` fails closed until that wrapper and output
protocol are part of the T6 image receipt.

## Focused verification

```text
uv run --frozen pytest benchmarks/tests/test_real_lean_project_dag_module_build.py scripts/tests/test_real_lean_module_build_preflight.py -q
```

The suite covers forged/partial streams, output and query deletion or
substitution, missing declarations, changed type or axiom records, wrong
image/platform/policy, fake promotion, stale fences, dependency drift,
same-source reuse, and complete atomic fanout.

## Next boundary

The next real T7 increment belongs in T6: add and receipt-bind an image-owned
module build wrapper plus declaration/type/axiom query wrapper. After that,
operator-local runs can populate this V1 observation schema, still
non-promotably. Production acceptance additionally requires a trusted gateway
attestation and the existing theorem-level verifier; module fanout alone must
never satisfy that gate.
