import { Activity, CircleDollarSign, FileCheck2, GitBranch } from "lucide-react";

import { displayText } from "./display";
import { graphPresentation, healthForStatus } from "./gridModel";
import type { NodeInspection } from "./inspectionModel";
import type { WorkRecordCategory } from "./types";

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

export function NodeInspector({ inspection }: { inspection: NodeInspection | null }) {
  if (!inspection) {
    return (
      <aside className="node-inspector" aria-label="Focused node details">
        <div className="inspector-empty">No projected node</div>
      </aside>
    );
  }

  const { node } = inspection;
  const health = healthForStatus(node.status);

  return (
    <aside className="node-inspector" aria-label="Focused node details" aria-live="polite">
      <header className="inspector-header">
        <div className="inspector-kicker">
          <span className={`health-signal tone-${health.tone}`} aria-hidden="true" />
          <span>{graphPresentation[node.graph].label}</span>
        </div>
        <h3>{displayText(node.label)}</h3>
        <code title={displayText(node.id, 256)}>{displayText(node.source_node_id, 128)}</code>
      </header>

      <dl className="inspector-facts">
        <div><dt>Revision</dt><dd>r{node.revision}</dd></div>
        <div><dt>Kind</dt><dd>{displayText(node.kind, 64)}</dd></div>
        <div><dt>State</dt><dd><span className={statusClass(node.status)}>{displayText(node.status, 64)}</span></dd></div>
        <div><dt>Updated</dt><dd>{formatTime(node.updated_at)}</dd></div>
        <div className="inspector-task-fact"><dt>Task</dt><dd><code>{displayText(node.task_id, 96)}</code></dd></div>
      </dl>

      <section className="inspector-section">
        <div className="inspector-section-heading">
          <GitBranch size={15} />
          <h4>Dependency frontier</h4>
          <span>{inspection.upstream.length + inspection.downstream.length}</span>
        </div>
        <div className="frontier-columns">
          <div>
            <p>Upstream</p>
            {inspection.upstream.map((dependency) => (
              <div className="frontier-row" key={dependency.id}>
                <span
                  className={`health-signal tone-${
                    dependency.node
                      ? healthForStatus(dependency.node.status).tone
                      : "unknown"
                  }`}
                  aria-hidden="true"
                />
                <span>{displayText(dependency.node?.label ?? dependency.id, 96)}</span>
                <small>{dependency.node ? displayText(dependency.node.status, 32) : "external"}</small>
              </div>
            ))}
            {inspection.upstream.length === 0 && <div className="inspector-none">Root</div>}
          </div>
          <div>
            <p>Downstream</p>
            {inspection.downstream.map((dependent) => (
              <div className="frontier-row" key={dependent.id}>
                <span
                  className={`health-signal tone-${healthForStatus(dependent.status).tone}`}
                  aria-hidden="true"
                />
                <span>{displayText(dependent.label, 96)}</span>
                <small>{displayText(dependent.status, 32)}</small>
              </div>
            ))}
            {inspection.downstream.length === 0 && <div className="inspector-none">Leaf</div>}
          </div>
        </div>
      </section>

      <section className="inspector-section">
        <div className="inspector-section-heading">
          <CircleDollarSign size={15} />
          <h4>Task attempts</h4>
          <span>{inspection.runs.length}</span>
        </div>
        {inspection.runs.length > 0 && (
          <div className="attempt-totals">
            <span>{formatNumber(inspection.totalTokens)} tokens</span>
            <span>${inspection.totalCostUsd.toFixed(3)}</span>
          </div>
        )}
        {inspection.runs.slice(0, 4).map((run) => (
          <div className="inspector-record" key={run.id}>
            <Activity size={14} />
            <div>
              <strong>{displayText(run.model, 128)}</strong>
              <span>{displayText(run.provider, 96)} · {displayText(run.verification, 64)}</span>
            </div>
            <span className={statusClass(run.status)}>{displayText(run.status, 64)}</span>
          </div>
        ))}
        {inspection.runs.length === 0 && (
          <div className="inspector-none">No task attempts</div>
        )}
      </section>

      <section className="inspector-section">
        <div className="inspector-section-heading">
          <FileCheck2 size={15} />
          <h4>Task evidence</h4>
          <span>{inspection.workRecords.length}</span>
        </div>
        {inspection.workRecords.slice(0, 5).map((record) => (
          <div className="inspector-record evidence-record" key={record.sequence}>
            <span className={`record-kind record-${record.category}`}>
              {categoryLabel(record.category)}
            </span>
            <div>
              <strong>{displayText(record.event.summary, 160)}</strong>
              <span>#{record.sequence} · {formatTime(record.event.occurred_at)}</span>
            </div>
          </div>
        ))}
        {inspection.workRecords.length === 0 && (
          <div className="inspector-none">No task evidence</div>
        )}
      </section>
    </aside>
  );
}
