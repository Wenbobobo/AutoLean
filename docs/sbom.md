# Lock-Input SPDX SBOM

`scripts/generate_sbom.py` emits a deterministic SPDX 2.3 JSON document for the declared Phase 1
lock inputs. It is intentionally a **lock-input SBOM**, not an installed-host inventory or a source
provenance record.

Run the no-write validation through the short task wrapper:

```powershell
uv run python scripts/dev.py sbom
```

Write a release-evidence artifact from the intended immutable checkout:

```powershell
uv run python -m scripts.generate_sbom generate --output release-evidence/autolean-phase1.spdx.json
```

The generator obtains all package data by calling the canonical release inventory generator. That
inventory is restricted to these four versioned inputs:

1. `pyproject.toml`
2. `uv.lock`
3. `Dashboard/ui/pnpm-lock.yaml`
4. `benchmarks/fate.lock.json`

The SPDX document carries the canonical inventory SHA-256 and each declared input's relative path,
byte count, and SHA-256 in its document comment. Python artifact hashes are emitted as SPDX SHA-256
checksums. pnpm SRI values are decoded to SPDX checksum values without preserving registry URLs.
The FATE lock is retained as a hashed declared input; it is not represented as a downloaded FATE
source package because this generator never fetches or inventories that source tree.

The fixed `1970-01-01T00:00:00Z` creation timestamp is a reproducibility marker. It is explicitly
not evidence of package installation, source creation, or release time. Output is canonical JSON,
uses only relative declared paths, and rejects output outside the workspace or under `.agents` and
`.quarantine`.

Every emitted package uses `NOASSERTION` for download location, concluded license, declared license,
and copyright. The generator performs no host scan, network access, credential discovery, license
clearance, vulnerability scan, installed-binary attestation, or source-provenance verification.
Those are independent release gates and must not be inferred from this SBOM.
