import { displayText } from "./display";
import { buildDagHealthMap, type DagEventState, type GraphScope, type HealthTone } from "./gridModel";
import type { EventView, GraphNode } from "./types";

const eventStateLabel: Record<Exclude<DagEventState, null>, string> = {
  attempt: "Attempt",
  gap: "Gap",
  contract_change: "Contract change",
  verification: "Verification",
  other: "Other"
};

const toneLabel: Record<HealthTone, string> = {
  nominal: "Nominal",
  active: "Active",
  attention: "Attention",
  critical: "Critical",
  unknown: "Unknown"
};

export function DagHealthMap({
  nodes,
  events,
  graph = "all",
  compact = false
}: {
  nodes: GraphNode[];
  events: EventView[];
  graph?: GraphScope;
  compact?: boolean;
}) {
  const map = buildDagHealthMap(nodes, events, graph, compact ? 24 : 48);
  const maxRows = Math.max(1, ...map.columns.map((column) => column.cells.length));

  return (
    <section
      className={compact ? "dag-health-map dag-health-map-compact" : "dag-health-map"}
      aria-label="Read-only DAG health map"
    >
      <div className="dag-health-heading">
        <div>
          <p className="eyebrow">Grid health map</p>
          <h3>Builder / Prover DAG pressure</h3>
        </div>
        <div className="dag-health-totals">
          <span>{map.totalNodes} nodes</span>
          <span>{map.totalEdges} edges</span>
          <span>{map.totalAttempts} attempts</span>
          <span>{map.totalGaps} gaps</span>
        </div>
      </div>
      <div
        className="dag-health-columns"
        style={{ gridTemplateColumns: "repeat(" + map.columns.length + ", minmax(0, 1fr))" }}
      >
        {map.columns.map((column) => (
          <article className={"dag-health-column dag-health-column-" + column.graph} key={column.graph}>
            <header>
              <span className={"health-signal tone-" + column.tone} aria-hidden="true" />
              <div>
                <strong>{column.label}</strong>
                <small>
                  {column.nodeCount} node{column.nodeCount === 1 ? "" : "s"} · {column.attempts} attempt{column.attempts === 1 ? "" : "s"} · {column.gaps} gap{column.gaps === 1 ? "" : "s"}
                </small>
              </div>
            </header>
            <div
              className="dag-cell-grid"
              style={{ gridTemplateRows: "repeat(" + maxRows + ", minmax(9px, 1fr))" }}
            >
              {column.cells.map((cell) => (
                <button
                  type="button"
                  className={"dag-cell tone-" + cell.tone + " " + (cell.eventState ? "event-" + cell.eventState : "")}
                  key={cell.id}
                  title={displayText(cell.label, 96) + " · " + toneLabel[cell.tone] + " · r" + cell.revision + " · " + cell.dependencies + " in / " + cell.dependents + " out · " + cell.attempts + " attempts · " + cell.gaps + " gaps"}
                  aria-label={displayText(cell.label, 96) + ": " + toneLabel[cell.tone] + ", " + cell.attempts + " attempts, " + cell.gaps + " gaps"}
                  disabled
                >
                  <span />
                </button>
              ))}
              {column.omitted > 0 && (
                <span className="dag-cell-overflow" title={column.omitted + " additional nodes omitted"}>
                  +{column.omitted}
                </span>
              )}
            </div>
          </article>
        ))}
      </div>
      <footer className="dag-health-legend">
        {(["nominal", "active", "attention", "critical", "unknown"] as HealthTone[]).map((tone) => (
          <span key={tone}><i className={"health-signal tone-" + tone} />{toneLabel[tone]}</span>
        ))}
        {(["attempt", "gap", "contract_change", "verification"] as Exclude<DagEventState, null>[]).map((state) => (
          <span className={"event-key event-" + state} key={state}><i />{eventStateLabel[state]}</span>
        ))}
        {map.unresolvedDependencies > 0 && (
          <span className="boundary-count">{map.unresolvedDependencies} external dependencies</span>
        )}
        <span className="dag-health-note">Read-only projection from immutable events</span>
      </footer>
    </section>
  );
}

