import assert from "node:assert/strict";
import test from "node:test";

import { resolveApiBase } from "../src/api.ts";
import { displayText, graphText, phaseStateLabel } from "../src/display.ts";
import {
  feedbackTone,
  LEVERAGE_DISPLAY_LIMIT,
  leverageMetric,
  leverageWindow
} from "../src/feedbackModel.ts";
import {
  buildDagHealthMap,
  buildGridModel,
  graphPresentation,
  healthForStatus,
  summarizeGrid
} from "../src/gridModel.ts";
import {
  buildNodeInspection,
  classifyWorkRecord,
  focusNode
} from "../src/inspectionModel.ts";
import type { GraphNode, PhaseFeedback } from "../src/types.ts";

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

test("phase states render as bounded human-readable labels", () => {
  assert.equal(phaseStateLabel("frozen_attested_with_evidence"), "frozen attested with evidence");
  assert.equal(phaseStateLabel("verified_candidate_available"), "verified candidate available");
  assert.equal(phaseStateLabel("contract_change"), "contract change");
  assert.equal(phaseStateLabel("unsafe_\u202elabel"), "unsafe label");
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

test("leverage rendering has a fixed degradation threshold for dense mathematical graphs", () => {
  const rows: PhaseFeedback["mathematical_dependency_leverage"] = Array.from(
    { length: LEVERAGE_DISPLAY_LIMIT + 3 },
    (_, index) => ({
      node_id: `node-${index}`,
      source_node_id: `source-${index}`,
      label: `Node ${index}`,
      direct_dependents: index,
      transitive_dependents: index + 1
    })
  );

  const window = leverageWindow(rows);
  assert.equal(window.rows.length, LEVERAGE_DISPLAY_LIMIT);
  assert.equal(window.omittedCount, 3);
  assert.equal(window.isDegraded, true);
  assert.throws(() => leverageWindow(rows, 0), RangeError);
});

test("direct-only leverage cannot be rendered as transitive reach", () => {
  const row: PhaseFeedback["mathematical_dependency_leverage"][number] = {
    node_id: "node-direct",
    source_node_id: "direct",
    label: "Direct dependency",
    direct_dependents: 3,
    transitive_dependents: null
  };

  assert.deepEqual(leverageMetric(row, "direct_only_over_limit"), {
    value: 3,
    label: "direct"
  });
  assert.throws(() => leverageMetric(row, "exact_transitive"));
});

test("phase feedback tone preserves failed verification and unresolved review semantics", () => {
  const base = {
    prover_verification: { state: "verified_candidate_available" },
    unresolved_human_review_assumptions: []
  } as PhaseFeedback;
  assert.equal(feedbackTone(base), "nominal");
  assert.equal(
    feedbackTone({
      ...base,
      unresolved_human_review_assumptions: [{ id: "gap-1" }]
    } as PhaseFeedback),
    "attention"
  );
  assert.equal(
    feedbackTone({
      ...base,
      prover_verification: { state: "all_candidates_rejected" }
    } as PhaseFeedback),
    "critical"
  );
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

test("T7 and FATE public execution events remain distinct from proof verification", () => {
  const t7Event = {
    sequence: 1,
    event_type: "t7_synthetic_node_v2.synthetic_complete",
    entity_id: "t7-bundle",
    task_id: "t7-bundle",
    occurred_at: "2026-07-27T12:00:00Z",
    summary: "T7 synthetic complete"
  };
  const fateEvent = {
    sequence: 2,
    event_type: "fate.attempt.verified",
    entity_id: "fate-bundle",
    task_id: "fate-bundle",
    occurred_at: "2026-07-27T12:00:01Z",
    summary: "FATE benchmark verifier accepted"
  };

  assert.equal(classifyWorkRecord(t7Event).category, "synthetic_execution");
  assert.equal(classifyWorkRecord(fateEvent).category, "benchmark");
  assert.notEqual(classifyWorkRecord(fateEvent).category, "verification");
});

test("research advisory events remain a non-authoritative work-record category", () => {
  const advisoryEvent = {
    sequence: 3,
    event_type: "research_hypothesis",
    entity_id: "a".repeat(64),
    task_id: null,
    occurred_at: "2026-07-29T12:00:02Z",
    summary: "Research advisory hypothesis: lemma"
  };

  assert.equal(classifyWorkRecord(advisoryEvent).category, "research_advisory");
  assert.notEqual(classifyWorkRecord(advisoryEvent).category, "task");
  assert.notEqual(classifyWorkRecord(advisoryEvent).category, "verification");
});

test("synthetic execution is visually explicit and cannot become a nominal proof state", () => {
  const node: GraphNode = {
    id: "dashboard-node|t7-bundle|execution|t7:node-a",
    source_node_id: "t7:node-a",
    task_id: "t7-bundle",
    label: "T7 synthetic node node-a",
    graph: "execution",
    status: "synthetic_complete",
    revision: 1,
    kind: "synthetic_execution",
    dependencies: []
  };
  const events = [
    {
      sequence: 1,
      event_type: "t7_synthetic_node_v2.synthetic_complete",
      entity_id: "t7-bundle",
      task_id: "t7-bundle",
      occurred_at: "2026-07-27T12:00:00Z",
      summary: "T7 synthetic complete"
    },
    {
      sequence: 2,
      event_type: "verification.accepted",
      entity_id: "unrelated-proof",
      task_id: "t7-bundle",
      occurred_at: "2026-07-27T12:00:01Z",
      summary: "Unrelated proof verification accepted"
    }
  ];
  const map = buildDagHealthMap([node], events, "execution");
  const inspection = buildNodeInspection(
    [node],
    [
      {
        id: "unrelated-proof",
        task_id: "t7-bundle",
        provider: "fake",
        model: "fake",
        status: "succeeded",
        input_tokens: 1,
        output_tokens: 1,
        cost_usd: 0,
        verification: "accepted"
      }
    ],
    events,
    node.id
  );

  assert.equal(healthForStatus("synthetic_complete").tone, "attention");
  assert.equal(healthForStatus("synthetic_failed").tone, "critical");
  assert.equal(map.columns[0]?.cells[0]?.eventState, "synthetic_execution");
  assert.deepEqual(inspection?.runs, []);
  assert.deepEqual(
    inspection?.workRecords.map((record) => record.category),
    ["synthetic_execution"]
  );
});
