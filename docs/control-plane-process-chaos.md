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

Run the bounded 1,000-job control-plane target explicitly and retain only synthetic evidence in an
empty operator-selected directory:

```powershell
uv run python scripts/dev.py chaos-process --jobs 1000
```

The job count is capped at 1,000. The result is one deterministic, redacted JSON line. Retain that
line with the exact source/environment evidence used for an operational review; do not treat a
small smoke result as completion of the 1,000-job acceptance gate.
