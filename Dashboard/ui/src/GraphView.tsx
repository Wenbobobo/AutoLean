import { EffectScatterChart, LinesChart, ScatterChart } from "echarts/charts";
import { GridComponent, TooltipComponent } from "echarts/components";
import { init, use } from "echarts/core";
import { CanvasRenderer } from "echarts/renderers";
import { useEffect, useMemo, useRef } from "react";

import { displayText, graphText } from "./display";
import {
  buildGridModel,
  graphPresentation,
  healthForStatus,
  type GraphScope,
  type HealthTone
} from "./gridModel";
import type { GraphNode } from "./types";

use([ScatterChart, EffectScatterChart, LinesChart, GridComponent, TooltipComponent, CanvasRenderer]);

type GraphDatum = {
  dependencies: number;
  graphLabel: string;
  kind: string;
  rawLabel: string;
  revision: number;
  shortLabel: string;
  status: string;
  updatedAt: string;
};

const toneLabel: Record<HealthTone, string> = {
  nominal: "Nominal",
  active: "Active",
  attention: "Attention",
  critical: "Critical",
  unknown: "Unknown"
};

export function GraphView({
  nodes,
  graph = "all",
  compact = false
}: {
  nodes: GraphNode[];
  graph?: GraphScope;
  compact?: boolean;
}) {
  const element = useRef<HTMLDivElement>(null);
  const model = useMemo(() => buildGridModel(nodes, graph), [graph, nodes]);

  useEffect(() => {
    if (!element.current) return;
    const chart = init(element.current, undefined, { renderer: "canvas" });
    chart.setOption({
      animationDuration: 360,
      animationEasing: "cubicOut",
      grid: { left: "3%", right: "3%", top: "6%", bottom: "7%", containLabel: false },
      tooltip: {
        renderMode: "richText",
        formatter: (item: { data?: Partial<GraphDatum> }) => {
          const datum = item.data;
          if (!datum) return "";
          return [
            graphText(datum.graphLabel ?? "", 48),
            graphText(datum.rawLabel ?? "", 96),
            `${graphText(datum.status ?? "", 48)} · ${graphText(datum.kind ?? "", 48)} · r${datum.revision ?? 1}`,
            `${datum.dependencies ?? 0} dependencies`,
            graphText(datum.updatedAt ?? "No update timestamp", 72)
          ].join("\n");
        }
      },
      xAxis: {
        type: "value",
        min: 0,
        max: 100,
        show: false
      },
      yAxis: {
        type: "value",
        min: 0,
        max: 100,
        inverse: true,
        show: false
      },
      series: [
        {
          type: "lines",
          coordinateSystem: "cartesian2d",
          silent: true,
          symbol: ["none", "arrow"],
          symbolSize: [0, 6],
          z: 1,
          data: model.links.map((link) => ({
            coords: [
              [link.source.x, link.source.y],
              [link.target.x, link.target.y]
            ],
            lineStyle: {
              color: link.health.edgeColor,
              curveness: 0.08,
              opacity: link.health.tone === "unknown" ? 0.42 : 0.72,
              type: link.health.edgeType,
              width: link.health.tone === "critical" ? 1.7 : 1.1
            }
          }))
        },
        {
          type: "lines",
          coordinateSystem: "cartesian2d",
          silent: true,
          symbol: ["none", "none"],
          z: 2,
          effect: {
            show: true,
            constantSpeed: 22,
            trailLength: 0.18,
            symbol: "circle",
            symbolSize: 3
          },
          lineStyle: { color: healthForStatus("running").edgeColor, opacity: 0.32, width: 1.2 },
          data: model.links
            .filter((link) => link.health.tone === "active")
            .map((link) => ({
              coords: [
                [link.source.x, link.source.y],
                [link.target.x, link.target.y]
              ]
            }))
        },
        {
          type: "effectScatter",
          coordinateSystem: "cartesian2d",
          silent: true,
          showEffectOn: "render",
          rippleEffect: { brushType: "stroke", number: 2, period: 3.2, scale: 2.2 },
          z: 3,
          data: model.nodes
            .filter((node) => node.health.pulse)
            .map((node) => ({
              value: [node.x, node.y],
              symbol: node.symbol,
              symbolSize: node.size,
              itemStyle: { color: node.health.color, opacity: 0.72 }
            }))
        },
        {
          type: "scatter",
          coordinateSystem: "cartesian2d",
          z: 4,
          label: {
            show: model.nodes.length <= (compact ? 24 : 40),
            position: "bottom",
            distance: 7,
            color: "#dce6e2",
            fontSize: compact ? 9 : 10,
            formatter: (item: { data?: Partial<GraphDatum> }) =>
              graphText(item.data?.shortLabel ?? "", compact ? 20 : 28)
          },
          emphasis: {
            scale: 1.3,
            itemStyle: { borderColor: "#ffffff", borderWidth: 2 }
          },
          data: model.nodes.map((node) => ({
            value: [node.x, node.y],
            symbol: node.symbol,
            symbolSize: node.size,
            graphLabel: graphPresentation[node.graph].label,
            rawLabel: node.label,
            shortLabel: graphText(node.label, compact ? 20 : 28),
            status: node.status,
            revision: node.revision,
            dependencies: node.dependencies.length,
            kind: node.kind,
            updatedAt: node.updated_at ? displayText(node.updated_at, 72) : "No update timestamp",
            itemStyle: {
              color: node.health.color,
              borderColor: node.health.tone === "unknown" ? "#c5ceca" : "#eff8f4",
              borderWidth: node.kind === "mission" ? 2.5 : 1.25,
              shadowBlur: node.health.tone === "active" ? 9 : 3,
              shadowColor: node.health.color
            }
          }))
        }
      ]
    });
    const observer = new ResizeObserver(() => chart.resize());
    observer.observe(element.current);
    return () => {
      observer.disconnect();
      chart.dispose();
    };
  }, [compact, model]);

  return (
    <div className={compact ? "graph-view graph-view-compact" : "graph-view"}>
      <div
        className="grid-lane-heads"
        style={{ gridTemplateColumns: `repeat(${model.lanes.length}, minmax(0, 1fr))` }}
      >
        {model.lanes.map((lane) => (
          <div className="grid-lane-head" key={lane.graph}>
            <span className={`health-signal tone-${lane.tone}`} aria-hidden="true" />
            <strong>{lane.label}</strong>
            <span>{lane.count}</span>
          </div>
        ))}
      </div>
      <div className="grid-plot">
        <div
          className="grid-lane-backdrop"
          style={{ gridTemplateColumns: `repeat(${model.lanes.length}, minmax(0, 1fr))` }}
          aria-hidden="true"
        >
          {model.lanes.map((lane) => <span key={lane.graph} />)}
        </div>
        <div
          className="graph-canvas"
          ref={element}
          role="img"
          aria-label={`${graph === "all" ? "Three-graph" : graph} system topology`}
        />
        {model.nodes.length === 0 && <div className="graph-empty">No nodes recorded</div>}
      </div>
      <div className="grid-legend" aria-label="Topology legend">
        {(["nominal", "active", "attention", "critical", "unknown"] as HealthTone[]).map((tone) => (
          <span key={tone}><i className={`health-signal tone-${tone}`} />{toneLabel[tone]}</span>
        ))}
        <span className="dependency-legend">→ Dependency</span>
        {model.unresolvedDependencies > 0 && (
          <span className="boundary-count">{model.unresolvedDependencies} external edges</span>
        )}
      </div>
    </div>
  );
}
