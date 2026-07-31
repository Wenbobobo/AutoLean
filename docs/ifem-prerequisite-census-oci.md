# iFEM Prerequisite Census OCI Worker

Status: audit-fixed local 21-node diagnostic completed; normalized public projections and the
operator-private raw record grant no semantic, freeze, coverage, or handoff authority

## Conclusion

The designated reproducible local execution route for the frozen 21-node prerequisite census is a dedicated,
image-owned native Lean helper. It imports exactly
`Mathlib.Analysis.InnerProductSpace.LaxMilgram` and
`Mathlib.Analysis.Normed.Operator.Bilinear` inside a network-disabled, read-only OCI container.
The worker is separate from the immutable five-profile P2-07 image, so adding it does not rewrite
that evidence chain.

Even a successful run is `Partial` discovery evidence. It records declaration kind, canonical
type, and observed axioms while every node remains `unknown` until independent Builder semantic
review. Builder freeze, coverage claims, and Prover handoff remain forbidden.

## Image and receipt

The build context contains exactly:

- `Prover/worker/Dockerfile.ifem-prerequisite-census-query`;
- `Prover/worker/AutoleanIFEMPrerequisiteCensusQuery.lean`; and
- `Prover/worker/autolean-ifem-prerequisite-census-query`.

The Dockerfile derives directly from the already receipt-bound P2-07 local image ID
`sha256:6c54c3600b2572ddcabae024a3a8b6c533c3defa6d4bda31c90408cb4c61f0ab`; it does not resolve a
mutable tag. The build uses the daemon's built-in classic frontend, disables networking for every
`RUN`, disables pulls, and records the Docker Engine version. This is receipt-bound build
provenance, not independent proof that the host daemon had no other egress. The builder reads the
resulting image ID from a private `--iidfile`, never resolves a result tag, and verifies that the
child root-filesystem layers start with the exact base layer sequence. This reuses the built import closure without
mutating the P2-07 image. It
compiles the Lean helper to a native executable, hashes the helper source, executable, wrapper,
identity record, and exact imported OLeans, and records the child image ID in a self-hashing build
receipt. Runtime verification recomputes the exact three-file staged-context hash and rechecks the
current recipe hashes, image ID, base-layer prefix, non-root identity, working directory, and all
plan/environment labels before starting the query.

Run these commands in Linux or WSL where the `docker` CLI resolves to the audited local daemon.
The Windows Python environment is not an OCI authority boundary by itself.

```text
uv run --frozen python scripts/ifem_prerequisite_census_oci.py build \
  --receipt-out <operator-private-receipt.json>

uv run --frozen python scripts/ifem_prerequisite_census_oci.py verify \
  --receipt <operator-private-receipt.json>

uv run --frozen python scripts/ifem_prerequisite_census_oci.py run \
  --receipt <operator-private-receipt.json> \
  --raw-out <operator-private-raw-stdout.jsonl> \
  --observation-out <observation.json> --result-out <result.json> \
  --execution-out <execution-envelope.json>

uv run --frozen python scripts/ifem_prerequisite_census_oci.py verify-execution \
  --receipt <operator-private-receipt.json> \
  --raw <operator-private-raw-stdout.jsonl> \
  --observation <observation.json> --result <result.json> \
  --execution <execution-envelope.json>
```

The execution envelope binds the worker receipt content hash, child image ID, exact argv hash, raw
stdout hash, normalized observation hash, and result hash. The query container has no checkout
mount, source cache, Docker socket, host home directory, or
credential path. It receives only a canonical JSON projection of the frozen plan's 21 node IDs
and candidate declaration lists. The normalizer then requires the returned nodes, candidates,
direct imports, plan hash, and environment pins to match that plan exactly. The execution verifier
rejects duplicate JSON keys, rechecks the receipt and current image, rebuilds the observation,
requires the exact 21-node `unknown` result, and recomputes the envelope. It cannot validate the
raw-output binding without the operator-private raw record. With that record present it reruns the
exact container argv and requires byte-identical stdout.

The normalized receipt, observation, result, and execution envelope are public because they
contain only fixed environment/plan metadata and public Mathlib declaration metadata. The raw
JSONL remains below the public-release boundary and is retained under the operator evidence root;
the repository records its SHA-256 commitment rather than bypassing the raw-output policy.

## Host fallback

The older POSIX/WSL `lake env lean` path remains diagnostic-only. Before invoking Lake it now
requires every locked Git package to exist as a real local checkout at the exact manifest revision,
requires the two Mathlib import source files, and installs a subprocess Git configuration that
rewrites HTTPS dependency URLs to a forbidden local protocol. A missing `Library/.lake/packages`
tree therefore fails closed instead of causing Lake to clone Mathlib implicitly.

This host guard does not make a generic checkout authoritative. The receipt-bound OCI route is the
reproducible execution boundary, and neither route grants semantic or proof authority.

## Local execution snapshot

On 2026-07-31, Docker Engine `29.1.3` built audit-fixed child image
`sha256:56cc9cf71af30ceede1f7feec3ff2e410007372c5300bd8d995b991517229156` from exact base
`sha256:6c54c3600b2572ddcabae024a3a8b6c533c3defa6d4bda31c90408cb4c61f0ab`. The receipt content hash
is `91e79e29ff827b0cf53d7318200c1402cafef964ad330bc42329898d1231328a` and its file SHA-256 is
`1d4dbf90dad157814c557ddc65016ddb79de094b027c498778e2f3f17d5d8e22`.

Two isolated executions produced byte-identical artifacts:

- operator-private raw stdout: file SHA-256
  `ae69a80ba23bdfef619f1129e8f7c5a7b4ceeac0cebb6dccf33eae8f69cf0b49`;
- observation: 21 nodes, content hash
  `4ba2944578c1e59cb83d362c90384a3b1b5fb8ea05ec38f3893a5c38e5007aed`, file SHA-256
  `f04e27a183e2ced5e16df7bb7f5e0bca29b9ff3e44532147062672228c2c9488`;
- diagnostic result: `completed`, `unknown=21`, content hash
  `fbaf12b9f9979131f1ce2f7075808c0141e4a5933046b6a369a2f75818016165`, file SHA-256
  `fd1111a91234755ae1308b2d4bfe0b329a000c3449e48abe80ccef5ad6a326b7`;
- execution envelope: content hash
  `5b04fca9492a113a9e69060aa58d62f7004a2e5f9b36c7934d6dcbbc4482be32`, file SHA-256
  `204d70dc7fd7cde3987410a8ad3e53c634bd89ba32409e11caae5af5fe2f07c1`.

The earlier child `sha256:7b311538...` is retained only as pre-audit history. It was superseded
after the base-environment and cross-artifact verification findings were fixed. The current run
and its public projections are catalogued in
`docs/research/ifem-prerequisite-census-oci-run-2026-07-31.md`.

The result is deliberately not a library-coverage conclusion. All 21 mappings await independent
Builder semantic evidence, so `builder_freeze=forbidden`, `prover_handoff=forbidden`, and
`coverage_claim=not_authorized` remain binding.
