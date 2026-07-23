# AutoLean control plane

This package provides the durable local control-plane primitives used by Builder and Prover:

- an append-only SQLite WAL event store with per-entity compare-and-swap sequences;
- idempotent task commands, explicit lifecycle transitions, leases, and fencing tokens;
- transactionally fenced lease-guarded writes, requiring the event store and lease store to share
  one SQLite database; and
- disposable task projections rebuilt from the canonical event stream; and
- an immutable SHA-256 content-addressed artifact store.

The event log and artifact bytes are canonical. Projection tables are caches and may be deleted
and replayed at any time. Credentials and provider secrets must never be placed in task payloads,
events, or artifacts.
