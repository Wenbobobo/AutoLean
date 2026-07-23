# AutoLean Dashboard

The Dashboard is a read-only observer of the control plane. It receives an exported
JSON projection, never an event-store connection, source tree, prompt, proof body, or
artifact body. The API presents only graph metadata, statement revisions, attempt
metadata, gap and contract-change records, verification state, immutable artifact
references, and model cost/token summaries.

The primary topology view renders the three authoritative projections as one operational
surface: Builder/Mathematical, Bridge/Formal, and Prover/Execution. Shape identifies the
graph, color identifies the projected status, dependency edge style identifies degraded
targets, and pulses are limited to active or critical projected states. This is a display
projection only; it does not infer a healthy lease from a running node.

The topology workbench focuses the highest-risk visible node by default. A focused node
highlights only its direct upstream and downstream dependency frontier, and the adjacent
observer pane shows its revision and task-level attempts, model/token/cost totals, gaps,
contract changes, and verification events. Every public node ID is the stable composite
`bundle_id + graph + source_node_id`; dependencies use the same identity. The projection
also exposes the already-public bundle ID as `task_id` on nodes, runs, and events. Joins
use only that explicit key and never infer an association across graph boundaries.
Snapshots produced before these identity fields were introduced must be re-exported; the
reader intentionally rejects ambiguous legacy node identities.

The current public projection does not include cross-graph alignment edges, lease expiry,
worker fencing tokens, or heartbeat timestamps. Consequently, the UI neither draws
mathematical-to-formal-to-execution links nor claims lease freshness. Adding those signals
requires an explicitly reviewed projection-schema revision, not a UI-side heuristic.

The current canvas is an operational slice, not an unbounded graph browser. It flags views
above 96 visible nodes as dense; large portfolios should export reviewed aggregates or
bounded dependency neighborhoods until zooming, clustering, and virtualization have their
own acceptance tests.

## Local operation

The supported local API launcher is `uv run python scripts/dev.py dashboard`. It binds
to `127.0.0.1:8765`. The React UI is in `Dashboard/ui`; its Vite development server is
also pinned to `127.0.0.1` and proxies `/api` to the local API.

For deterministic UI development, set `AUTOLEAN_DASHBOARD_PROJECTION` to
`Dashboard/api/tests/fixtures/grid-demo.v1.json` before launching the API. The fixture is
synthetic, schema-validated, answer-free, and deliberately labels its model runs as `fake`; it is
not runtime or proof evidence.

`AUTOLEAN_DASHBOARD_PROJECTION` may point only to the control plane's atomically
exported projection file. The reader rejects symlinks, non-regular files, malformed
data, and projections larger than 16 MiB. It exposes a generic `503` instead of a path,
parser failure, or any file content.

## Remote operation

Remote binding is an explicit operator action. Set `AUTOLEAN_DASHBOARD_REMOTE=1`, a
trimmed `AUTOLEAN_DASHBOARD_TOKEN` of at least 32 characters, and an intentional
`AUTOLEAN_DASHBOARD_HOST`; then use `python -m autolean_dashboard.server`. In local
mode, any host other than `127.0.0.1` is rejected. Remote API routes require a bearer
token and disable API schema endpoints and browser CORS.

Do not put `AUTOLEAN_DASHBOARD_TOKEN` in `VITE_*`, a dashboard bundle, a URL, a log, or
the projection. The included SPA deliberately does not carry remote credentials. A
remote deployment needs an authenticated reverse proxy or another server-side client
that keeps the bearer token outside browser assets.

## Safety properties

- Every API route is `GET`/`HEAD`/`OPTIONS` only; all other methods return `405`.
- API responses are `no-store`, unframeable, non-indexable, and use a restrictive CSP.
- The event stream is bounded to 200 events per observation and honors `Last-Event-ID`.
- React renders projection strings as text. ECharts uses a canvas rich-text tooltip, not
  an HTML tooltip, and strips ECharts formatting control characters from labels.
- Artifact rows expose a digest and metadata only. Diffs, proof source, prompts, and
  logs stay outside the Dashboard projection.
- Graph nodes are reconstructed from an explicit public-field allowlist. Unknown or
  nested event fields are never copied into the projection, even when they arrive inside
  a registered graph node.
- A public `task_id` comes from an explicit `bundle_id`, or from the entity ID only when
  the event belongs to a `task` stream. Other entity streams are never guessed to be tasks.
- Verification acceptance must be a JSON boolean whose value agrees with
  `verification.accepted` or `verification.rejected`. A malformed flag or conflicting
  event type aborts projection/export instead of displaying a false success.

## Verification

Run the Dashboard API tests with `uv run pytest Dashboard/api/tests -q`. The package
type check is `uv run mypy -p autolean_dashboard`. Run the pinned UI checks from the
repository root with `pnpm --dir Dashboard/ui test` and
`pnpm --dir Dashboard/ui build`.
