# Pre-T6 Builder Query Route

Status: design decision for the next Builder--Prover vertical; no public protocol change.

## Conclusion

Use route **B** for the real pre-T6 vertical slice: add a separate Builder-only statement/type query endpoint to the `library-substrate` image, bind it to a new image digest and receipt, and keep the Prover V2 facade plus public control-plane protocol unchanged.

Route **A** (`scripted_fake` registration plus separately retained source-v2 or local OCI evidence) remains useful as a control-plane rehearsal, but it should not be called the pre-T6 vertical. It proves that events and artifacts can be wired together; it does not prove that Builder can freeze an unknown statement against the same runtime substrate that Prover later uses.

## First principles

Builder is allowed to ask, "what Lean statement did this text produce, in this environment?" It is not allowed to submit a proof-like carrier or to cause Prover acceptance.

Prover is allowed to ask, "does this proof establish the frozen statement?" It must not expose a statement-elaboration loophole that can be mistaken for a proof attempt.

Therefore the next vertical must create an **observation endpoint**, not a new proof endpoint. The observation endpoint may use an axiom/constant carrier only to elaborate a statement; its receipt must say that the carrier is not proof evidence and is ineligible for `submit_proof`.

## Route comparison

| Dimension | Route A: scripted fake + separate evidence | Route B: Builder-only image endpoint |
| --- | --- | --- |
| Time to demo | Fastest; mostly orchestration and retained evidence | Moderate; one wrapper/helper, receipt fields, and canaries |
| Architectural evidence | Shows control-plane wiring only | Shows Builder can query the runtime statement boundary without abusing Prover |
| Risk | Easy to overclaim; evidence can split across source-v2/local runs | New image digest and endpoint must be kept narrow |
| Contract impact | Tempting to smuggle query facts through fake proof records | No public protocol change; query receipt is Builder evidence only |
| Prover boundary | Not exercised for Builder-origin statements | Preserved: V2 facade remains proof-only |
| Failure mode | "Looks vertical" while bypassing the hard Builder question | Scope creep if the endpoint becomes a general oracle |

Decision: Route B is worth doing because it is the smallest path that tests the actual Builder--Prover seam we care about: a faithful statement is frozen before proof search, and proof search cannot rewrite it.

## Minimal endpoint

Working name:

    /opt/autolean/library-substrate/bin/autolean-library-substrate-builder-query

Protocol:

    autolean.library-substrate-builder-query.v1

Inputs:

- immutable candidate statement source;
- expected declaration name;
- allowed imports/profile identifier;
- expected environment/toolchain/mathlib/library-substrate image digest;
- optional expected type hash when replaying a frozen revision;
- output path for canonical JSON.

The source may contain a dedicated statement carrier such as a `constant` or `axiom` declaration, but no theorem body and no proof script. The endpoint records the carrier kind explicitly and marks it as `builder_statement_carrier`, not proof evidence.

Outputs:

- schema/version and endpoint helper hashes;
- child image digest, parent source-v2 digest, runtime manifest hash, and receipt hash;
- candidate source hash and normalized import list;
- declaration name, declaration kind, canonical elaborated type, and type hash;
- type-level observed axioms, if any, separate from the carrier axiom itself;
- imported AutoLean declaration origins and allowed profile id;
- rejection reason when compilation or policy fails.

The receipt must be content-addressed and replayable from the fixed image. It must not be accepted by `claim`, `submit_proof`, `verify_submission`, or the Prover V2 facade.

The container cannot discover its own registry RepoDigest. Therefore `--image` is not trusted
caller testimony: the host canary must first verify that the requested reference equals Docker's
recorded child RepoDigest, then use that exact same string both as the image executed by
`docker run` and as the endpoint identity argument. A raw direct wrapper invocation is not
receipt-bound evidence.

Successful endpoint stdout is exactly one compact JSON line and successful stderr is empty.
Compile/query failures expose only a fixed 4096-byte diagnostic prefix plus a stable phase marker;
unbounded Lean diagnostics are never streamed into retained evidence.

## Required fail-closed tests

The Builder endpoint must reject or clearly mark as non-promotable:

1. a theorem/proof-body carrier;
2. a `sorry`, `admit`, `by exact` proof, or any proof-script token in the statement carrier file;
3. importing the target theorem module instead of only the profile/runtime substrate;
4. replacing the intended statement with `True` while keeping the same declaration name;
5. adding local axioms other than the single declared statement carrier;
6. changing the image, runtime manifest, helper hash, or source checksum after a receipt was produced;
7. passing the query receipt to any Prover `submit_proof` or verifier acceptance path;
8. using the old source-v2 image or the current proof-only library-substrate facade for a Builder query.

The Prover V2 facade must continue to reject the same negative proof candidates as before, and its stdout schema must not change.

## Pre-T6 vertical acceptance

The next vertical slice is accepted only if all of the following are true:

1. A Builder candidate statement is elaborated through the Builder-only endpoint in a fixed `library-substrate` image and produces a retained query receipt.
2. The frozen `StatementContractV1` or adjacent Builder evidence stores the source hash, type hash, environment digest, endpoint receipt digest, and carrier-non-proof marker.
3. The Prover receives only the frozen theorem statement/bundle and submits an actual theorem proof through the existing V2 facade.
4. The verifier checks the proof against the frozen statement type and the same image/runtime profile, then emits a normal verification report.
5. A control test with the same declaration name and `True` statement is rejected before Prover work begins.
6. A control test that tries to reuse the Builder query carrier as a proof is rejected by protocol, not merely by convention.

This is still **not T6**. It is a real pre-T6 vertical because it closes the Builder statement-observation seam and the Prover proof-verification seam in one trace, but it still lacks production signer/gateway admission and human semantic authority.

## Implementation split

1. **Image helper**: add the Builder-query Lean helper and shell wrapper beside the existing independent-query and V2 facade assets.
2. **Receipt binding**: extend the library-substrate build input and image receipt with the two new helper hashes; produce a new child RepoDigest.
3. **Host canary**: add `builder-query-canary` to compile/query one good statement carrier and the required negatives.
4. **Builder adapter**: add a narrow internal function that stores the query receipt digest as Builder evidence; do not add a public control-plane method.
5. **Vertical fixture**: run `prepare -> fidelity -> freeze -> builder-query receipt -> bridge -> claim -> proof -> verify` on the UniversalLK staged candidate.
6. **Docs/evidence**: update the progress ledger only after the retained receipt, canary output, and verification artifact hashes exist.

Current working-tree status: items 1--3 are implemented and locally unit/static tested. A real
receipt-v2 child image has not been built in this checkout. Item 4 remains open because
`builder-query-canary` validates fresh, replay, and seven negative cases but only prints a summary;
it does not persist the raw validated query record as immutable Builder evidence. Items 5--6
remain blocked by T3/T5 and real OCI execution.

The operator preflight, once a new Docker-recorded RepoDigest exists, is:

```text
uv run --frozen python -m Library.scripts.library_substrate_image verify --image <recorded-repodigest>
uv run --frozen python -m Library.scripts.library_substrate_image builder-query-canary --image <recorded-repodigest>
```

## Non-goals

- Do not add a new model role, provider, or public API.
- Do not change `claim`, `submit_proof`, `report_gap`, `request_contract_change`, or `verify_submission`.
- Do not treat the carrier axiom as a permitted proof axiom.
- Do not use a fixed proof-carrier theorem or a fake proof to extract a type.
- Do not claim promotion, T6, or mathematical success from the query receipt.
