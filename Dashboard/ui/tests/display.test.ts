import assert from "node:assert/strict";
import test from "node:test";

import { resolveApiBase } from "../src/api.ts";
import { displayText, graphText } from "../src/display.ts";
import { buildGridModel, graphPresentation, healthForStatus, summarizeGrid } from "../src/gridModel.ts";
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
    label: "Mathematical source",
    graph: "mathematical",
    status: "frozen",
    revision: 1,
    kind: "statement",
    dependencies: []
  },
  {
    id: "formal-a",
    label: "Formal contract",
    graph: "formal",
    status: "blocked",
    revision: 2,
    kind: "statement",
    dependencies: ["missing-boundary"]
  },
  {
    id: "exec-a",
    label: "Worker attempt",
    graph: "execution",
    status: "running",
    revision: 1,
    kind: "attempt",
    dependencies: []
  },
  {
    id: "exec-b",
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
});
