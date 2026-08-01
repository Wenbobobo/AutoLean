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

The projection recognizes three additional public event families through fixed allowlists.
`autolean.t7-synthetic-node-result.v2` becomes an execution node whose status is explicitly
synthetic and non-promotable; a completed fixture never appears as a verified proof. Its private
node ID is replaced by a domain-separated SHA-256 public reference before entering any snapshot
field. FATE's
`autolean.fate-execution.v1` and `autolean.fate-execution.v2` started/terminal events become a
redacted benchmark run with coarse usage and verifier state only. A terminal event is visible only
after deterministic replay finds exactly one prior started event with the same schema, entity,
run, problem, attempt number, and attempt seed. V2 requires an explicit deterministic seed in both
events; V1 remains readable as historical evidence. Neither path exports lease holders, fencing tokens,
source modules, approval snapshots, raw model output, candidate source, private CAS handles,
or private digests. ResearchScout's `research_hypothesis` and `research_observation` records are
a third, non-execution family: a strict advisory-only envelope yields a timeline/work-record item,
but never a graph node, run, task ID, phase-feedback milestone, contract revision, or verification
state. It contains no statement/evidence text, prompt, source excerpt, endpoint, credential, or
declared usage. Builder pre-calibration records and ModelWork/authorized-role sidecars remain
outside Dashboard input: they are not registered control-plane public event schemas, so the
Dashboard deliberately leaves them out rather than inferring a state from files or private stores.

`GET /api/phase-feedback` exposes replay-derived milestone and evidence feedback for current
frozen bundles. It keeps Builder fidelity, proof-candidate verification, unresolved
human-review inputs, and within-bundle mathematical dependent reachability separate. The
contract has no scalar progress score and carries `promotion_state=not_a_promotion`.
Its freshness fields bind the task observation to exact relevant event sequences and the
export's replay head; they do not prove that an exported file is caught up to a live event store.

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

If the default API port is already occupied, set
`AUTOLEAN_DASHBOARD_API_URL=http://127.0.0.1:<port>` for the Vite process. The
browser continues to use the same-origin `/api` proxy.

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
- Unknown event types retain the existing minimal event-view compatibility surface, including
  their producer-supplied entity ID. Payload and metadata are never copied, but event producers
  must still treat entity IDs as public. A family with private entity identities needs a reviewed
  projection adapter before its events can enter the Dashboard source.

## Verification

Run the Dashboard API tests with `uv run pytest Dashboard/api/tests -q`. The package
type check is `uv run mypy -p autolean_dashboard`. Run the pinned UI checks from the
repository root with `pnpm --dir Dashboard/ui test` and
`pnpm --dir Dashboard/ui build`.
