# iFEM local-use request V1

Status: implemented as a pending, non-authoritative request. It is not a source-rights decision,
`RightsRecordV1`, model-execution authorization, source-text artifact, statement contract, or
Builder--Prover handoff.

## Purpose

The current iFEM discovery lane has a pinned local source lock, a candidate reference-manifest
digest, and CC BY 4.0 metadata. Those facts establish byte identity and a conservative ceiling;
they do not independently decide whether a particular processing workflow is lawful or operated
under an approved local boundary. V1 records one narrow request for a later source-rights decision:
local model processing only.

The request binds the canonical current discovery manifest, including the exact iFEM lane values:

- source-lock receipt SHA-256:
  `74eca6689fe69dcbf2f34ea524a99cacc2054c0a39cfecfb11887c29e13cf239`;
- reference-manifest candidate SHA-256:
  `4a5d859d77b606d6e485d98bd3e4afc41f6c566c6fb09f5e3dc2b2a539f18398`;
- pinned Git revision, iFEM record URL, and CC BY 4.0 expression, canonical license URL, evidence
  URL, Git blob SHA-1, and license SHA-256.

It serializes neither source content, source-file locations, cache locations, nor a prompt. The
request does carry explicit prohibitions: external source-text egress, redistribution, training,
embeddings, Builder freeze, and Prover handoff are all `forbidden`.

## Lifecycle

```text
discovery manifest + source-lock metadata
        |
        v
pending IFEMLocalUseRequestV1
        |
        +--> remains pending: no processing or handoff
        |
        +--> separate source-rights decision: may create a new, separately reviewed record
```

The right branch is intentionally not implemented by this request. A later decision must bind
attribution, the actual local execution boundary, retention, and any source-record scope. It must
not mutate or reinterpret the V1 request.

## Operator use

The wrapper performs no provider or network call. It builds, writes once, reloads canonical JSON,
and replays against the exact current discovery manifest:

```text
uv run --frozen python scripts/ifem_local_use_request.py --out <operator-output>.json
```

An existing output is accepted only when its bytes are identical. A changed manifest produces a
different request and cannot overwrite the prior output. Loading validates strict UTF-8 JSON,
rejects duplicate keys, checks the content hash, and rejects noncanonical bytes.

## Residual boundary

This artifact does not determine that CC BY 4.0 permits any contemplated processing, prove that a
local worker is isolated, or authorize local model execution. It cannot create a `RightsRecordV1`,
override the discovery lane's external-egress prohibition, freeze a statement, or route anything to
Prover. Those transitions remain separate, versioned gates.
