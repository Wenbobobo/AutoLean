# Phase 1 Threat Model and Trust Boundaries

## Security objective

AutoLean must ensure that an untrusted model or stale worker cannot alter the theorem that later
gets accepted, gain host authority through a proof workspace, route operator credentials through
an agent-controlled endpoint, or turn the dashboard into a data-exfiltration path. It must also
make duplicate delivery and crash recovery unambiguous at the control-plane boundary.

This is a local-first threat model. It is not a claim that the current workstation, container
runtime, model endpoint, source corpus, or browser deployment has received a complete security
assessment.

## Protected assets

| Asset | Failure to prevent |
| --- | --- |
| Mathematical intent and source provenance | A valid Lean proof for the wrong informal proposition |
| Frozen Lean declaration and elaborated type | A proof accepted after a worker changes the statement, imports, namespace, or axioms |
| Operator credentials and provider routing | A task, prompt, workspace, log, or custom endpoint obtaining secret values |
| Event and artifact history | A stale worker, replay, or mutable file creating a second accepted result |
| Isolated worker authority | A proof attempt modifying host files, network state, dependencies, or trusted source bytes |
| Dashboard confidentiality | Raw artifacts, source, prompts, or browser-executable content escaping through the panel |

## Trust-boundary map

    operator-owned secrets and endpoint approval
                     |
                     | credential reference only
                     v
    Builder -> frozen bundle -> Control plane -> fenced model worker
                                      |                  |
                                      |                  +-> proof / gap / change evidence
                                      v
                             independent verifier
                                      |
                                      v
                         read-only dashboard projection

The worker is the least trusted participant. It never gets a mutable Builder checkout or a
credential value as an artifact. The verifier is separate because a worker cannot be the
authority that judges its own statement boundary.

## Threats, implemented mitigations, and required proof

| Threat | Current code-level mitigation | Required validation before release |
| --- | --- | --- |
| Worker changes theorem to True, adds an axiom, or edits imports | Protected header/manifest hashes; proof-slot-only materializer; placeholder rejection; verifier axiom checks | Compile-canary substitution attacks and clean Lean build in the pinned OCI environment |
| Caller invents a syntactically frozen bundle | Builder-freeze attestation binds bundle/contract/proof-boundary/freeze evidence; control plane checks an allowlisted non-expired key | Forged, revoked-key, expired, and replayed bundle-attestation tests plus operator key-rotation drill |
| Worker invents an all-true verifier report | Independent verifier attestation binds proof artifact, report hash, typed environment evidence, and a one-time nonce | Forged, changed-report, missing-evidence-artifact, expiry, and replay tests against the authoritative verifier path |
| Worker writes outside its task | Patch-path allowlist, immutable input snapshot, no-network/read-only OCI command construction | Runtime container escape and write-domain tests on Linux/WSL2 |
| Stale worker submits after replacement | SQLite lease TTL plus monotonic fencing token; each command asserts current lease | Expiry, renewal, replacement, and late-submit tests under concurrency |
| Retry duplicates an accepted result | Per-entity CAS sequence plus scoped request-hash idempotency | Duplicate-delivery and event-replay chaos tests |
| Artifact changes after event reference | SHA-256 content-addressed store verifies bytes and size | Corruption, concurrent-write, and backup/restore tests |
| Source is not permitted for a model endpoint | Rights record plus endpoint-class enforcement in ContextPackBuilder | Rights-review fixtures and egress policy integration tests |
| Provider name/model secretly selects a prohibited family | Identity policy rejects forbidden provider/model terms and registry has no fallback | Configuration fuzzing and operator allowlist review |
| Custom endpoint downgrades transport or embeds credentials | URL validator requires HTTP(S), TLS for non-local endpoints, and rejects query/fragment/user-info | Network proxy/redirect tests and production endpoint registration process |
| Dashboard leaks raw data or writes state | Projection is deliberately lossy and does not expose artifact contents | Browser auth, sanitizer, CSP, and remote-access tests |
| Recovery archive contaminates the workspace | Quarantine-only recovery tooling and default exclusion of session material | Human-reviewed sanitization manifest and secret-scanner evidence |

Relevant code paths are the immutable workspace materializer
([workspace.py](../Prover/src/autolean_prover/execution/workspace.py#L1)), OCI command builder
([oci.py](../Prover/src/autolean_prover/execution/oci.py#L1)), fenced leases
([leases.py](../packages/control_plane/src/autolean_control_plane/leases.py#L1)), artifact store
([artifacts.py](../packages/control_plane/src/autolean_control_plane/artifacts.py#L1)), and
read-only projection
([projection.py](../packages/control_plane/src/autolean_control_plane/projection.py#L1)).

## Worker policy

The authoritative execution target is Linux/WSL2 OCI. A promoted worker must use:

- an image pinned by immutable SHA-256 digest;
- a no-network container with read-only root filesystem;
- read-only source and dependency mounts;
- a fresh writable attempt directory only;
- dropped Linux capabilities, no-new-privileges, PID/memory/time/output limits; and
- a verifier-owned clean re-materialization rather than the agent's working directory.

`OciWorkerHarness` constructs this command line and `OciLeanRunner` binds the mounted frozen source
files to workspace hashes before and after execution, but this remains protocol-level defense, not
sandbox proof. The release gate requires an actual runtime test on the intended Linux/WSL2 host
with the pinned Lean image, wrapper, toolchain, and clean-build canaries; none has run yet.

## Explicit non-goals and residual risks

1. Lean's kernel cannot prove that a formal statement is the intended informal mathematics. This
   is why Builder has separate fidelity and review gates.
2. A successful container run does not prove that the container image, host kernel, OCI runtime,
   or endpoint service is uncompromised.
3. Source rights review does not resolve copyright, licensing, or data-protection questions on
   its own; it records an accountable decision and restricts model egress.
4. SQLite WAL is appropriate for the local control plane. It is not yet a multi-region,
   multi-primary distributed transaction system. A PostgreSQL/object-store/remote-worker port
   must preserve protocol semantics, lease fencing, idempotency, and artifact identity.
5. Sanitizing the dashboard projection does not validate the browser UI. Rendering,
   authentication, content-security policy, and remote binding remain separate release work.
6. The lease-bound verifier-gateway protocol is implemented, but its current tests use an
   in-process HMAC fixture. HMAC shares a secret with its verifier and proves neither host nor
   process isolation. Promotion requires authenticated mTLS/ACL transport and a non-exportable
   KMS/HSM sign/verify authority. An asymmetric scheme additionally requires a versioned V2
   contract, as described in [Attestation Trust Root V1](attestation.md).

## Security review triggers

Trigger a new review before any of the following:

- adding a provider, tool transport, custom endpoint class, or credential source;
- allowing outbound network access from a worker;
- adding a writable mount, executable, import source, or axiom to a trusted environment;
- exposing the dashboard beyond loopback or exporting a static report;
- importing any content from a backup, session archive, unreviewed workspace, or licensed source;
- changing contract hashing, event persistence, lease semantics, or the verifier acceptance gate.
