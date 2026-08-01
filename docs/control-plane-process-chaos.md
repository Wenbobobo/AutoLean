# OS-Process Control-Plane Chaos Harness

## Purpose

`scripts/control_plane_process_chaos.py` is a deliberately narrow, test-only resilience campaign
for the local SQLite control plane. It is separate from
[`control_plane_chaos.py`](../scripts/control_plane_chaos.py), whose service reconstruction stays
inside one Python process.

The process harness starts a dedicated synthetic child worker. That worker registers frozen
synthetic bundles, acquires SQLite WAL-backed leases, writes a durable checkpoint, and then waits.
The parent terminates exactly that direct child process. Two newly started child processes reopen
the same SQLite database and content-addressed artifact root: one performs recovery, and one
replays events and verifies artifact hashes.

## Boundaries

The harness exercises these facts for every synthetic job:

- an OS-process termination after durable task registration and lease acquisition, before proof
  submission;
- replacement claims after a deliberately expired lease, with monotonic fencing tokens;
- rejection of a stale-token proof submission;
- idempotent duplicate delivery for registration, replacement claim, proof submission, and
  verification;
- one terminal verification verdict per proof after recovery;
- fresh-process replay of the SQLite event sequence, dashboard projection, and
  content-addressed bundle/proof/report/evidence artifacts.

It does **not** run Lean, an OCI container, a model provider, a network endpoint, or a real
attestation authority. It also does not simulate a host reboot, power loss, filesystem corruption,
or termination while SQLite has an active write transaction. Those are separate acceptance and
deployment tests; passing this harness does not establish authoritative execution or a release
candidate.

The static HMAC authorities are synthetic fixtures. Their material is never emitted in the JSON
summary, state files, or documentation command output. A supplied `--workspace` must be empty and
is retained untouched after the run; without it, only a private temporary run directory is created
and cleaned up by the parent.

## Commands

Use the short project task for smoke coverage:

```powershell
uv run python scripts/dev.py chaos-process
```

Run the bounded 1,000-job control-plane target explicitly and retain its synthetic workspace plus
a new V2 receipt below the existing `release-evidence/` directory. Use fresh paths and verify them
in place: the receipt binds the exact Git commit or dirty-candidate fingerprint, `uv.lock`, Python
and `uv` versions, canonical argv, timing/run ID, state/SQLite file hashes, and content-addressed
artifact hashes. Relative output paths are resolved from the repository root; the writer refuses
links, junctions, overwrite, and paths outside that evidence subtree:

```powershell
$runId = [guid]::NewGuid().ToString("N")
$workspace = "release-evidence/control-plane-process-chaos-$runId.workspace"
$receipt = "release-evidence/control-plane-process-chaos-$runId.v2.json"
uv run --frozen python scripts/control_plane_process_chaos.py --jobs 1000 `
  --workspace $workspace --provenance-output $receipt
uv run --frozen python scripts/control_plane_process_chaos.py `
  --verify-provenance $receipt --workspace $workspace
```

The job count is capped at 1,000. V2 uses exclusive creation and fsync, and its independent verifier
re-reads the receipt and workspace with strict duplicate-key JSON parsing. The retained database
must be the single checkpointed SQLite file: sidecar WAL/SHM files are rejected, and verification
opens the database read-only and immutable so verification cannot change the manifest it checks.
The verifier checks the expected schema, replays every registration/claim/recovery/proof/terminal
event and lease/fence transition, rebuilds the Dashboard terminal projection, and validates the
auxiliary idempotency, contract-binding, nonce, and lease tables. It then traverses every event
artifact reference through the content-addressed store, parses canonical typed bundle, proof,
verification-report, and verifier-evidence artifacts, checks their cross-bindings, and rejects
unreferenced manifest artifacts.

Path and manifest validation rejects changed, missing, extra, linked, or reparse-point evidence.
Retain the workspace with the exact source/environment evidence used for an operational review; do
not treat a small smoke result, a hand-written V1 summary, or a V2 receipt without a
retained/reverified workspace as completion of the 1,000-job acceptance gate.

The path checks reject existing links and junctions, but cannot make a hostile concurrently
modified filesystem trustworthy. The release-evidence directory must be operator-owned and not
writable by untrusted processes. If a process or filesystem fails during exclusive creation, an
incomplete file may remain intentionally non-overwritable; inspect it as invalid evidence and have
an operator remove it before rerunning.
