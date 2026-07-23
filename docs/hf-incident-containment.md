# AutoArchon HF Incident Containment and Recovery Boundary

## Scope and status

The AutoArchon audit recorded that the dataset named AutoArchon_Private was publicly enumerable
and ungated at the time of the audit. That is an incident record, not a current access-control
assertion: this document does not re-query the service and must not be used as proof that the
dataset is now private or deleted.

The relevant source evidence is [the AutoArchon audit](audits/autoarchon-audit.md). This document
contains no itemized recovered inventory, decrypted content, prompt, session, passphrase,
endpoint, credential, or checksum. It is deliberately safe to keep in the AutoLean repository.

After that source audit, the operator explicitly authorized a quarantine-only recovery. The
aggregate local reports record four verified encrypted archives, three decrypted non-session
archives, and one session archive deliberately left encrypted. No decrypted archive was
extracted. Header-only inspection counted 4,523 regular members totalling 230,761,442 bytes and
280 symbolic links, so the material is explicitly unsafe for automatic extraction. These counts
are recovery-boundary evidence only; they reveal no member paths or contents and authorize no
migration.

## Non-negotiable containment rule

Treat every credential that could have appeared in archived configuration, workspace state, or
session history as potentially exposed. Encryption does not negate the need to restrict access,
rotate relevant credentials, preserve incident evidence, and prohibit raw archival content from
entering the engineering repository or model context.

## Recovery boundary

Recovery utilities live under [scripts/](../scripts/) and are archival tools, not migration
tools. Their required behavior is:

1. Retrieve only a fixed remote revision into an ignored local quarantine and verify published
   integrity metadata before any decryption.
2. Keep encrypted inputs, decrypted outputs, reports, and any derived staging material below the
   quarantine boundary.
3. Never execute recovered code, load recovered environments, send recovered content to a model,
   or add raw material to the repository, control-plane artifact store, fixtures, or dashboard.
4. Exclude session-derived material by default. It is neither required source code nor safe
   migration input.
5. Treat any recovery hint or passphrase directive as process-local secret input. Do not copy it
   into a command line, checked-in configuration, report, terminal transcript, or this document.
6. Fail closed when recovery instructions are ambiguous, integrity checks fail, a path escapes
   quarantine, or a candidate item cannot be classified safely.

The recovery scripts should emit only aggregate completion/integrity information. A successful
decryption is not a migration approval.

## Required containment checklist

| Gate | Completion evidence | Owner |
| --- | --- | --- |
| Restrict or remove public dataset access | Provider-side access state and incident timestamp, retained outside public repo docs | Dataset owner |
| Rotate potentially exposed credentials | Rotation record for OpenAI/Codex, HF, GitHub, custom endpoints, and any helper/service credential that could be present | Credential owners |
| Preserve incident evidence | Immutable dataset/repository revision and platform audit/access records, stored in the incident system | Incident owner |
| Verify quarantine acquisition | Fixed revision, hash/size verification report, and no import/execution evidence | Recovery operator |
| Classify content | Inventory classified as allowable schema/fixture/report versus prohibited sessions, secrets, prompts, logs, and unreviewed workspaces | Security reviewer |
| Create proposed sanitized export | New clean repository or staging area, independently rebuilt fixtures, redacted schemas/reports only | Migration owner |
| Review export | Secret scan, license/rights review, reproducible rebuild, and independent approval | Security and Builder reviewers |
| Dispose or retain originals | Explicit retention/deletion decision with recoverability and access record | Dataset/incident owner |

The first two rows require an operator action outside this workspace. They must not be inferred
from the existence of a downloaded backup or a successful script run.

## What may cross into AutoLean

Only a reviewed, reproducible, sanitized subset may cross the boundary. Permitted categories are
limited to redacted schemas, documentation that contains no operational secrets, independent
verification reports, and fixtures rebuilt from public or otherwise approved sources. Every item
needs provenance, rights review, a content hash, and a reviewer decision.

The following never cross directly: raw sessions, prompts, tool transcripts, environment files,
credential-bearing configuration, logs, unreviewed workspaces, opaque binary archives, or source
with unresolved rights. The old AutoArchon runtime, helper transport, recovery logic, and dashboard
are reference material for audits, not dependencies or migration targets.

## Recovery completion criterion

Recovery is complete only when the incident owner can demonstrate that public access has been
restricted or the dataset has been removed, applicable credentials have been rotated, the original
archive remains quarantined or is deliberately disposed of, and any new public export is a fresh
sanitized artifact with independent review. It is not complete merely because data was downloaded,
decrypted, or readable. The local quarantine acquisition and no-extract inventory are complete;
provider-side access restriction, credential rotation, classification review, and any sanitized
export remain operator-owned gates.
