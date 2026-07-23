import {
  Activity,
  Archive,
  Boxes,
  CircleDot,
  ClipboardCheck,
  FileCheck2,
  GitBranch,
  RefreshCw,
  Search,
  ShieldCheck
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";

import { api } from "./api";
import { displayText } from "./display";
import { GraphView } from "./GraphView";
import { summarizeGrid, type GraphScope } from "./gridModel";
import {
  buildNodeInspection,
  classifyWorkRecord,
  focusNode
} from "./inspectionModel";
import { NodeInspector } from "./NodeInspector";
import type {
  ArtifactSummary,
  EventView,
  GraphNode,
  Overview,
  RunSummary,
  WorkRecordCategory
} from "./types";

type View = "overview" | "graph" | "runs" | "evidence" | "artifacts";

const graphFilterLabel: Record<GraphScope, string> = {
  all: "All",
  mathematical: "Math",
  formal: "Formal",
  execution: "Exec"
};

const nav: Array<{ id: View; label: string; icon: typeof Activity }> = [
  { id: "overview", label: "Overview", icon: Activity },
  { id: "graph", label: "Graphs", icon: GitBranch },
  { id: "runs", label: "Runs", icon: Boxes },
  { id: "evidence", label: "Evidence", icon: ClipboardCheck },
  { id: "artifacts", label: "Artifacts", icon: Archive }
];

const emptyOverview: Overview = {
  generated_at: new Date().toISOString(),
  mission: "Open problem portfolio",
  metrics: [],
  active_runs: 0,
  blocked_nodes: 0
};

function formatNumber(value: number) {
  return new Intl.NumberFormat("en-US").format(value);
}

function formatTime(value: string | null | undefined) {
  if (!value) return "-";
  const parsed = new Date(value);
  return Number.isNaN(parsed.valueOf()) ? "Unknown" : parsed.toLocaleString();
}

function statusClass(status: string) {
  const normalized = status.toLowerCase().replace(/[^a-z0-9]+/g, "-");
  return `status status-${normalized || "unknown"}`;
}

function categoryLabel(category: WorkRecordCategory) {
  return category.replaceAll("_", " ");
}

export default function App() {
  const [view, setView] = useState<View>("overview");
  const [graph, setGraph] = useState<GraphScope>("all");
  const [overview, setOverview] = useState<Overview>(emptyOverview);
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [artifacts, setArtifacts] = useState<ArtifactSummary[]>([]);
  const [events, setEvents] = useState<EventView[]>([]);
  const [query, setQuery] = useState("");
  const [focusedNodeId, setFocusedNodeId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      // One immutable snapshot prevents a refresh from combining multiple event positions.
      const snapshot = await api.snapshot();
      setOverview(snapshot.overview);
      setNodes(snapshot.nodes);
      setRuns(snapshot.runs);
      setArtifacts(snapshot.artifacts);
      setEvents(snapshot.events);
      setError(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Projection unavailable");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const filteredRuns = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return needle
      ? runs.filter((run) => `${run.task_id} ${run.provider} ${run.model}`.toLowerCase().includes(needle))
      : runs;
  }, [query, runs]);

  const workRecords = useMemo(
    () => events.map(classifyWorkRecord).sort((left, right) => right.sequence - left.sequence),
    [events]
  );
  const revisions = useMemo(
    () =>
      nodes
        .filter((node) => node.kind !== "mission")
        .sort((left, right) => right.revision - left.revision || left.label.localeCompare(right.label)),
    [nodes]
  );

  const verified = nodes.filter((node) => node.status === "verified").length;
  const frozen = nodes.filter((node) => node.status === "frozen").length;
  const cost = runs.reduce((total, run) => total + run.cost_usd, 0);
  const tokenTotal = runs.reduce((total, run) => total + run.input_tokens + run.output_tokens, 0);
  const gridSummary = useMemo(() => summarizeGrid(nodes), [nodes]);
  const visibleGraphNodes =
    graph === "all" ? nodes : nodes.filter((node) => node.graph === graph);
  const focusedNode = useMemo(
    () => focusNode(visibleGraphNodes, focusedNodeId),
    [focusedNodeId, visibleGraphNodes]
  );
  const nodeInspection = useMemo(
    () => buildNodeInspection(nodes, runs, events, focusedNode?.id ?? null),
    [events, focusedNode?.id, nodes, runs]
  );

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand"><CircleDot size={20} /><span>AutoLean</span></div>
        <nav aria-label="Primary navigation">
          {nav.map((item) => {
            const Icon = item.icon;
            return (
              <button
                type="button"
                className={view === item.id ? "nav-item active" : "nav-item"}
                aria-current={view === item.id ? "page" : undefined}
                aria-label={item.label}
                title={item.label}
                key={item.id}
                onClick={() => setView(item.id)}
              >
                <Icon size={17} /><span>{item.label}</span>
              </button>
            );
          })}
        </nav>
        <div className="sidebar-state"><ShieldCheck size={16} /><span>Read-only</span></div>
      </aside>

      <main>
        <header className="topbar">
          <div><p className="eyebrow">Mission</p><h1>{displayText(overview.mission, 256)}</h1></div>
          <div className="topbar-actions">
            <span className={error ? "connection error" : "connection"}>{error ? "Offline" : "Live projection"}</span>
            <button
              type="button"
              className="icon-button"
              aria-label="Refresh projection"
              title="Refresh projection"
              onClick={() => void refresh()}
              disabled={loading}
            >
              <RefreshCw size={17} className={loading ? "spin" : ""} />
            </button>
          </div>
        </header>

        {error && <div className="alert-band">Projection API: {displayText(error, 192)}</div>}

        {view === "overview" && (
          <div className="overview-command">
            <section className="status-rail" aria-label="System metrics">
              <div className="overall-health">
                <span className={`health-signal tone-${gridSummary.overallTone}`} aria-hidden="true" />
                <div><span>Grid state</span><strong>{gridSummary.overallTone}</strong></div>
              </div>
              <div><span>Frozen</span><strong>{formatNumber(frozen)}</strong></div>
              <div><span>Verified</span><strong>{formatNumber(verified)}</strong></div>
              <div><span>Active</span><strong>{formatNumber(overview.active_runs)}</strong></div>
              <div><span>Blocked</span><strong>{formatNumber(overview.blocked_nodes)}</strong></div>
              <div><span>Tokens</span><strong>{formatNumber(tokenTotal)}</strong></div>
              <div><span>Spend</span><strong>${cost.toFixed(2)}</strong></div>
            </section>
            <section className="command-surface">
              <div className="command-header">
                <div><p className="eyebrow">System topology</p><h2>Builder–Prover grid</h2></div>
                <button type="button" className="text-button on-dark" onClick={() => setView("graph")}>Open topology</button>
              </div>
              <div className="command-layout">
                <GraphView nodes={nodes} graph="all" compact />
                <aside className="grid-journal">
                  <div className="journal-heading">
                    <p className="eyebrow">Event journal</p>
                    <span>#{events.at(-1)?.sequence ?? 0}</span>
                  </div>
                  <div className="event-list">
                    {workRecords.slice(0, 9).map((record) => (
                      <div className="event-row" key={record.sequence}>
                        <FileCheck2 size={15} />
                        <div><strong>{displayText(record.event.summary)}</strong><span>{record.category} · {displayText(record.event.entity_id, 128)}</span></div>
                        <time>{formatTime(record.event.occurred_at)}</time>
                      </div>
                    ))}
                    {workRecords.length === 0 && <div className="empty-state">No events recorded</div>}
                  </div>
                </aside>
              </div>
            </section>
          </div>
        )}

        {view === "graph" && (
          <section className="section-band full-height">
            <div className="section-heading">
              <div><p className="eyebrow">Dependency model</p><h2>Three-graph topology</h2></div>
              <div className="segmented" role="group" aria-label="Graph type">
                {(["all", "mathematical", "formal", "execution"] as GraphScope[]).map((kind) => (
                  <button
                    type="button"
                    className={graph === kind ? "selected" : ""}
                    onClick={() => setGraph(kind)}
                    aria-pressed={graph === kind}
                    aria-label={kind}
                    key={kind}
                  >
                    {graphFilterLabel[kind]}
                  </button>
                ))}
              </div>
            </div>
            <div className="topology-workbench">
              <GraphView
                nodes={nodes}
                graph={graph}
                selectedNodeId={focusedNode?.id}
                onSelectNode={setFocusedNodeId}
              />
              <NodeInspector inspection={nodeInspection} />
            </div>
            <div className="node-ledger table-wrap">
              <table>
                <thead><tr><th>Node</th><th>Kind</th><th>Revision</th><th>Status</th><th>Dependencies</th><th>Updated</th></tr></thead>
                <tbody>
                  {visibleGraphNodes.map((node) => (
                    <tr className={node.id === focusedNode?.id ? "is-selected" : ""} key={node.id}>
                      <td>
                        <button
                          type="button"
                          className="node-focus-button"
                          aria-pressed={node.id === focusedNode?.id}
                          onClick={() => setFocusedNodeId(node.id)}
                        >
                          <strong>{displayText(node.label)}</strong>
                          <span className="subtle">{displayText(node.source_node_id, 128)}</span>
                        </button>
                      </td>
                      <td>{displayText(node.kind, 64)}</td>
                      <td>r{node.revision}</td>
                      <td><span className={statusClass(node.status)}>{displayText(node.status, 64)}</span></td>
                      <td>{node.dependencies.length}</td>
                      <td>{formatTime(node.updated_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {visibleGraphNodes.length === 0 && <div className="empty-state">No nodes recorded</div>}
            </div>
          </section>
        )}

        {view === "runs" && (
          <section className="section-band">
            <div className="section-heading">
              <div><p className="eyebrow">Attempts</p><h2>Proof runs</h2></div>
              <label className="search"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Filter runs" /></label>
            </div>
            <div className="table-wrap">
              <table>
                <thead><tr><th>Task</th><th>Provider</th><th>Status</th><th>Verification</th><th>Duration</th><th>Tokens</th><th>Cost</th></tr></thead>
                <tbody>
                  {filteredRuns.map((run) => (
                    <tr key={run.id}>
                      <td><strong>{displayText(run.task_id, 128)}</strong><span className="subtle">{displayText(run.id, 128)}</span></td>
                      <td>{displayText(run.provider, 96)}<span className="subtle">{displayText(run.model, 160)}</span></td>
                      <td><span className={statusClass(run.status)}>{displayText(run.status, 64)}</span></td>
                      <td><span className={statusClass(run.verification)}>{displayText(run.verification, 64)}</span></td>
                      <td>{run.duration_ms === null || run.duration_ms === undefined ? "-" : `${formatNumber(run.duration_ms)} ms`}</td>
                      <td>{formatNumber(run.input_tokens + run.output_tokens)}</td>
                      <td>${run.cost_usd.toFixed(3)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {filteredRuns.length === 0 && <div className="empty-state">No runs match this view</div>}
            </div>
          </section>
        )}

        {view === "evidence" && (
          <div className="content-stack">
            <section className="section-band">
              <div className="section-heading"><div><p className="eyebrow">Contract state</p><h2>Statement revisions</h2></div></div>
              <div className="table-wrap">
                <table>
                  <thead><tr><th>Statement</th><th>Graph</th><th>Revision</th><th>State</th><th>Updated</th></tr></thead>
                  <tbody>
                    {revisions.map((node) => (
                      <tr key={`${node.graph}:${node.id}`}>
                        <td><strong>{displayText(node.label)}</strong><span className="subtle">{displayText(node.id, 128)}</span></td>
                        <td>{displayText(node.graph, 64)}</td>
                        <td>r{node.revision}</td>
                        <td><span className={statusClass(node.status)}>{displayText(node.status, 64)}</span></td>
                        <td>{formatTime(node.updated_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {revisions.length === 0 && <div className="empty-state">No statement revisions recorded</div>}
              </div>
            </section>
            <section className="section-band">
              <div className="section-heading"><div><p className="eyebrow">Review trail</p><h2>Gaps, contract changes, and verification</h2></div></div>
              <div className="table-wrap">
                <table>
                  <thead><tr><th>Record</th><th>Event</th><th>Entity</th><th>Time</th></tr></thead>
                  <tbody>
                    {workRecords.map((record) => (
                      <tr key={record.sequence}>
                        <td><span className={`record-kind record-${record.category}`}>{categoryLabel(record.category)}</span></td>
                        <td><strong>{displayText(record.event.summary)}</strong><span className="subtle">{displayText(record.event.event_type, 128)}</span></td>
                        <td>{displayText(record.event.entity_id, 128)}</td>
                        <td>{formatTime(record.event.occurred_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {workRecords.length === 0 && <div className="empty-state">No work records</div>}
              </div>
            </section>
          </div>
        )}

        {view === "artifacts" && (
          <section className="section-band">
            <div className="section-heading"><div><p className="eyebrow">Immutable outputs</p><h2>Artifact references</h2></div></div>
            <div className="artifact-list">
              {artifacts.map((artifact) => (
                <div className="artifact-row" key={artifact.digest}>
                  <Archive size={17} />
                  <div><strong>{displayText(artifact.kind, 64)}</strong><span>{displayText(artifact.media_type, 128)}</span></div>
                  <code>{displayText(artifact.digest, 64).slice(0, 16)}</code>
                  <span>{formatNumber(artifact.size)} B</span>
                </div>
              ))}
              {artifacts.length === 0 && <div className="empty-state">No artifacts recorded</div>}
            </div>
          </section>
        )}
      </main>
    </div>
  );
}
