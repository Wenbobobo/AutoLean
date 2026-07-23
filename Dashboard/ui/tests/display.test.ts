import assert from "node:assert/strict";
import test from "node:test";

import { resolveApiBase } from "../src/api.ts";
import { displayText, graphText } from "../src/display.ts";
import { buildGridModel, graphPresentation, healthForStatus, summarizeGrid } from "../src/gridModel.ts";
import {
  buildNodeInspection,
  classifyWorkRecord,
  focusNode
} from "../src/inspectionModel.ts";
import type { GraphNode } from "../src/types.ts";

test("display text removes spoofing controls while retaining ordinary literal text", () => {
  const rendered = displayText("<img src=x onerror=alert(1)>\u202e\nsummary", 96);

  assert.equal(rendered, "<img src=x onerror=alert(1)> summary");
  assert.doesNotMatch(rendered, /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/);
});

test("graph text removes ECharts formatter syntax and stays bounded", () => {
  const rendered = graphText("{a|unsafe}\\label\u0000", 12);

  assert.equal(rendered, "a unsafe ...");
  assert.doesNotMatch(rendered, /[{}|\\]/);
  assert.equal(rendered.length, 12);
});

test("display limits reject values that cannot carry an ellipsis safely", () => {
  assert.throws(() => displayText("text", 3), RangeError);
});

test("API base only permits the local credential-free boundary", () => {
  assert.equal(resolveApiBase(undefined), "");
  assert.equal(resolveApiBase("http://127.0.0.1:8765/"), "http://127.0.0.1:8765");
  assert.equal(resolveApiBase("https://localhost:9443"), "https://localhost:9443");
  assert.throws(() => resolveApiBase("https://example.invalid"));
  assert.throws(() => resolveApiBase("http://user@127.0.0.1:8765"));
  assert.throws(() => resolveApiBase("http://127.0.0.1:8765/api"));
});

const topologyFixture: GraphNode[] = [
  {
    id: "math-a",
    source_node_id: "math-a",
    task_id: "task-math",
    label: "Mathematical source",
    graph: "mathematical",
    status: "frozen",
    revision: 1,
    kind: "statement",
    dependencies: []
  },
  {
    id: "formal-a",
    source_node_id: "formal-a",
    task_id: "task-formal",
    label: "Formal contract",
    graph: "formal",
    status: "blocked",
    revision: 2,
    kind: "statement",
    dependencies: ["missing-boundary"]
  },
  {
    id: "exec-a",
    source_node_id: "exec-a",
    task_id: "task-exec",
    label: "Worker attempt",
    graph: "execution",
    status: "running",
    revision: 1,
    kind: "attempt",
    dependencies: []
  },
  {
    id: "exec-b",
    source_node_id: "exec-b",
    task_id: "task-exec",
    label: "Verifier",
    graph: "execution",
    status: "queued",
    revision: 1,
    kind: "verification",
    dependencies: ["exec-a"]
  }
];

test("grid model preserves three graph lanes and encodes graph kind as shape", () => {
  const model = buildGridModel(topologyFixture);

  assert.deepEqual(model.lanes.map((lane) => lane.graph), ["mathematical", "formal", "execution"]);
  assert.equal(model.nodes.find((node) => node.id === "math-a")?.symbol, "circle");
  assert.equal(model.nodes.find((node) => node.id === "formal-a")?.symbol, "diamond");
  assert.equal(model.nodes.find((node) => node.id === "exec-a")?.symbol, "roundRect");
  assert.equal(graphPresentation.formal.shortLabel, "Contract");
});

test("single-graph layout keeps nodes inside the label-safe horizontal band", () => {
  const formalNodes: GraphNode[] = ["a", "b", "c", "d"].map((id, index) => ({
    id: `formal-${id}`,
    source_node_id: `formal-${id}`,
    task_id: "task-layout",
    label: `Formal node ${id}`,
    graph: "formal",
    status: "frozen",
    revision: 1,
    kind: "statement",
    dependencies: index === 0 ? [] : [`formal-${String.fromCharCode(96 + index)}`]
  }));
  const model = buildGridModel(formalNodes, "formal");

  assert.ok(model.nodes.length > 0);
  assert.ok(model.nodes.every((node) => node.x >= 25 && node.x <= 75));
});

test("grid health and edge state remain evidence-based projections", () => {
  const model = buildGridModel(topologyFixture);
  const summary = summarizeGrid(topologyFixture);

  assert.equal(summary.overallTone, "critical");
  assert.equal(summary.active, 1);
  assert.equal(summary.critical, 1);
  assert.equal(model.links.length, 1);
  assert.equal(model.links[0]?.source.id, "exec-a");
  assert.equal(model.links[0]?.target.id, "exec-b");
  assert.equal(model.unresolvedDependencies, 1);
  assert.equal(healthForStatus("running").pulse, true);
  assert.equal(healthForStatus("blocked").edgeType, "dashed");
  assert.equal(healthForStatus("critical").tone, "critical");
  assert.equal(healthForStatus("attention").tone, "attention");
  assert.equal(healthForStatus("nominal").tone, "nominal");
});

test("unknown node health conservatively prevents a nominal aggregate", () => {
  const unknown = {
    ...topologyFixture[0]!,
    id: "math-unknown",
    source_node_id: "math-unknown",
    status: "unrecognized-state"
  };
  const summary = summarizeGrid([topologyFixture[0]!, unknown]);

  assert.equal(summary.nominal, 1);
  assert.equal(summary.unknown, 1);
  assert.equal(summary.overallTone, "unknown");
  assert.equal(buildGridModel([topologyFixture[0]!]).lanes[0]?.tone, "nominal");
  assert.equal(buildGridModel([topologyFixture[0]!, unknown]).lanes[0]?.tone, "unknown");
});

test("node focus prefers projected operational risk and preserves an explicit selection", () => {
  assert.equal(focusNode(topologyFixture, null)?.id, "formal-a");
  assert.equal(focusNode(topologyFixture, "math-a")?.id, "math-a");
  assert.equal(focusNode(topologyFixture.slice(0, 1), "missing")?.id, "math-a");
});

test("node inspection joins task-keyed work and preserves factual dependency neighbors", () => {
  const inspection = buildNodeInspection(
    topologyFixture,
    [
      {
        id: "run-direct",
        task_id: "task-formal",
        provider: "openai-responses",
        model: "gpt-series",
        status: "blocked",
        input_tokens: 20,
        output_tokens: 5,
        cost_usd: 0.25,
        verification: "gap"
      },
      {
        id: "run-unrelated",
        task_id: "task-exec",
        provider: "custom-responses",
        model: "open-model",
        status: "running",
        input_tokens: 100,
        output_tokens: 0,
        cost_usd: 1,
        verification: "pending"
      }
    ],
    [
      {
        sequence: 2,
        event_type: "gap.reported",
        entity_id: "formal-a",
        task_id: "task-formal",
        occurred_at: "2026-07-23T12:00:00Z",
        summary: "Direct gap"
      },
      {
        sequence: 1,
        event_type: "verification.accepted",
        entity_id: "exec-a",
        task_id: "task-exec",
        occurred_at: "2026-07-23T11:00:00Z",
        summary: "Unrelated verification"
      }
    ],
    "formal-a"
  );

  assert.equal(inspection?.upstream[0]?.id, "missing-boundary");
  assert.equal(inspection?.upstream[0]?.node, null);
  assert.deepEqual(inspection?.downstream, []);
  assert.deepEqual(inspection?.runs.map((run) => run.id), ["run-direct"]);
  assert.equal(inspection?.totalTokens, 25);
  assert.equal(inspection?.totalCostUsd, 0.25);
  assert.deepEqual(inspection?.workRecords.map((record) => record.category), ["gap"]);
});

test("work record classification distinguishes semantic and verification evidence", () => {
  const event = {
    sequence: 1,
    event_type: "contract_change.requested",
    entity_id: "formal-a",
    task_id: "task-formal",
    occurred_at: "2026-07-23T12:00:00Z",
    summary: "Review requested"
  };

  assert.equal(classifyWorkRecord(event).category, "contract_change");
});
