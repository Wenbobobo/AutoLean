# Danus 集成决策：隔离研究侦察器，而非 AutoLean 真相层

状态：完成精确版本源码审计；本文件只记录研究判断和隔离实验设计，不引入 Danus 运行时。

审计日期：2026-07-29
审计范围：官方仓库源码、许可证和论文；AutoLean 当前 Builder--Prover 合同、三图、ContextPack、事件/CAS/lease 与 provider 边界。

## 1. 结论

**决策：不 fork、不 import、不把 Danus 放入 AutoLean control plane、FormalGraph 或任何证明接纳路径。** 只吸收经过重实现的设计思想，并在未来以 provider-neutral、无权限的 `research scout` 适配器隔离运行。

Danus 适合解决“很多自然语言数学代理如何把长搜索组织起来”的问题；AutoLean 还必须解决一个更强的问题：“Builder 产生的命题是否忠实，以及 Prover 是否在固定 Lean 环境中证明了同一个冻结命题”。两者的正确性对象不同：Danus 的 `fact` 是另一个 LLM 返回 `correct` 后的自然语言证明记录，AutoLean 的最终事实必须是冻结合同、受限写域、Lean kernel、独立 replay 和公理/依赖门共同产生的证据。

推荐的长期数据流是：

```text
Danus-inspired scout (untrusted proposal only)
  -> canonical proposal CAS / research_hypothesis event
  -> Builder source/rights/normalization/fidelity gates
  -> new frozen StatementContract revision
  -> FormalizationTaskBundleV1
  -> Prover claim -> proof candidate -> Lean verifier -> accepted evidence
```

侦察器永远不能写 `FormalGraph`，不能创建或冻结 `StatementContract`，不能修改已有 revision，不能发放模型授权、lease 或 verifier 签名，也不能把自然语言 `correct` 当作证明。

## 2. 精确来源、许可证和依赖

### 2.1 源码锁定

- 仓库：[frenzymath/Danus](https://github.com/frenzymath/Danus)。
- 审计提交：[`7e244865968d3268b21c96b898c7af1f55d2f7c5`](https://github.com/frenzymath/Danus/commit/7e244865968d3268b21c96b898c7af1f55d2f7c5)。本地 `git ls-remote` 在 2026-07-29 返回同一 SHA 为 `refs/heads/main`。
- 提交时间：2026-07-22 02:56:31 UTC；提交主题是 `readme: note to settle the stopping condition with the main agent up front`。
- `pyproject.toml` 声明版本 `0.1.0`、Python `>=3.10`、Apache-2.0，见 [`pyproject.toml#L5-L23`](https://github.com/frenzymath/Danus/blob/7e244865968d3268b21c96b898c7af1f55d2f7c5/pyproject.toml#L5-L23)。仓库存在 `v0.1.0` tag，但其 peeled commit 是较早的 `7aad41077147af7b8f2a697512075bb326ade992`；本审计针对更新的 `main` SHA `7e244865…`，所以复现必须记录完整 SHA，而不能只写版本号。
- 根许可证是 Apache License 2.0，见 [`LICENSE`](https://github.com/frenzymath/Danus/blob/7e244865968d3268b21c96b898c7af1f55d2f7c5/LICENSE)。论文 HTML/元数据是 CC BY 4.0，见 [arXiv 2607.06447v2](https://arxiv.org/abs/2607.06447)；代码许可和论文许可不能混写。

### 2.2 依赖与 provider 政策

源码基础包 `dependencies=[]`；可选依赖为 `mcp`、`fastapi/uvicorn/pydantic`、`openai` 和 `anthropic`，见 [`pyproject.toml#L26-L41`](https://github.com/frenzymath/Danus/blob/7e244865968d3268b21c96b898c7af1f55d2f7c5/pyproject.toml#L26-L41)。`strategy` 明确提供 `gpt_pro`、`claude_api`、`claude_code`、`off`，并把 Claude/Anthropic 作为一等 transport；这直接违反 AutoLean 的 provider allowlist，因此不能复用配置、依赖或 fallback。

### 2.3 论文证据的正确解读

论文声称六个 research-level case studies，最大案例达到 3,157 个事实、8,616 条边、深度 54、最终支撑闭包 664 个事实；方法、工作流和限制见 [论文方法部分](https://arxiv.org/html/2607.06447v2#S2) 与 [结果/讨论](https://arxiv.org/html/2607.06447v2#S3)。这些是有价值的案例材料，不是可直接横向比较的 benchmark：论文说明人类提供的初始问题、路线提示、最终逐项检查和后处理在不同案例中不同（[§3](https://arxiv.org/html/2607.06447v2#S3)），没有固定 token/cost/timeout、重复试验、验证器混淆矩阵或公开可复现的统一 runner。

论文自身也报告了两类必须保留的反例：matroid 案例最初只解决了 rational 而非原问题要求的 integral 版本，直到人类指出范围错误；另一个案例中错误的文献定义沿依赖传播，最终由专家发现并触发撤销（[§3.6](https://arxiv.org/html/2607.06447v2#S3.6)、[§4.5](https://arxiv.org/html/2607.06447v2#S4.5)）。这正说明“事实图”不能替代 Builder 的命题保真或来源审计。

## 3. 源码审计证据

风险等级按 AutoLean 语义使用场景标注：P0 = 若直接接纳会破坏核心正确性边界；P1 = 会造成可重放性、依赖或权限缺口；P2 = 可隔离借鉴但不阻断研究试验。

### 3.1 值得吸收的设计

| 机制 | Danus 证据 | 判断 |
|---|---|---|
| 事实大小的工作单元 | README 将 worker 的基本单位设为 lemma、counterexample 或 toy example，而不是整篇证明（[`README#L224-L227`](https://github.com/frenzymath/Danus/blob/7e244865968d3268b21c96b898c7af1f55d2f7c5/README.md#L224-L227)）。 | 吸收。映射为 Builder/Prover 的 role-scoped ContextPack 和小粒度 candidate；不改变冻结合同。 |
| 三层记忆 | `local`、`global`、`fact graph` 的分层与“只有事实图是 truth”写在 [`ARCHITECTURE#L73-L89`](https://github.com/frenzymath/Danus/blob/7e244865968d3268b21c96b898c7af1f55d2f7c5/ARCHITECTURE.md#L73-L89)。 | 吸收为 AutoLean 的 advisory experience/context 和 ExecutionGraph 投影；global memory 永远不能成为 Lean 证明前提。 |
| 建设性/反例/玩具例多样性 | 论文描述 workers 并行探索 constructive 与 refutational routes（[§2.1](https://arxiv.org/html/2607.06447v2#S2.SS1)）。 | 吸收为独立角色和 mutation lanes；counterexample 只能产生 gap 或 Builder draft，不得自动弱化命题。 |
| 低频策略压缩 | `elaboration -> consult -> master_guidance -> assign` 的固定流程见 [`elaboration/SKILL.md#L8-L16`](https://github.com/frenzymath/Danus/blob/7e244865968d3268b21c96b898c7af1f55d2f7c5/.claude/skills/elaboration/SKILL.md#L8-L16) 和 [`main_agent.md#L71-L120`](https://github.com/frenzymath/Danus/blob/7e244865968d3268b21c96b898c7af1f55d2f7c5/agents/contracts/main_agent.md#L71-L120)。 | 吸收为控制平面 advisory guidance artifact；guidance 只能分配工作，不能新增数学依赖或改合同。 |
| 支撑闭包与探索图分离 | 论文最大案例明确区分全量搜索图和最终 theorem 的 664 节点 supporting closure（[§3.6](https://arxiv.org/html/2607.06447v2#S3.SS6)）。 | 吸收为 Dashboard/benchmark 的两个投影；KPI 用 Lean-verified closure 与证据质量，不用 fact count。 |
| 组装后重新检查 | 论文指出从图到论文的压缩会引入新的 seam errors，并要求完整稿再次过 verifier（[§2.7](https://arxiv.org/html/2607.06447v2#S2.SS7)）。 | 吸收为 Builder 反向渲染、Prover submission replay 和最终 artifact recheck；检查器仍不能取代 kernel。 |
| 级联失效 | `revoke` 的意图是让错误节点及其后代一起失效（[`factgraph.py#L295-L316`](https://github.com/frenzymath/Danus/blob/7e244865968d3268b21c96b898c7af1f55d2f7c5/danus/core/factgraph.py#L295-L316)）。 | 只吸收语义，不吸收移动文件的实现；AutoLean 使用新 revision + append-only invalidation + descendant re-verification。 |

### 3.2 必须重写的机制

| 机制 | 审计发现 | AutoLean 重写要求 |
|---|---|---|
| 事实身份 | `compute_fact_id` 只保留 SHA-256 前 16 个 hex，见 [`schema.py#L104-L130`](https://github.com/frenzymath/Danus/blob/7e244865968d3268b21c96b898c7af1f55d2f7c5/danus/core/schema.py#L104-L130)。 | 使用完整 SHA-256；显示短 ID 只能是 alias。合同、Lean 源、elaborated type、provenance 各自保留独立 digest。 |
| 依赖闭包 | `FactGraph.add` 只检查 predecessor 是否已撤销，不要求 predecessor 文件存在（[`factgraph.py#L124-L166`](https://github.com/frenzymath/Danus/blob/7e244865968d3268b21c96b898c7af1f55d2f7c5/danus/core/factgraph.py#L124-L166)）。 | 每个依赖必须来自同一冻结 bundle/图快照并通过 CAS、revision、source hash 校验；未知或跨项目 ID fail closed。 |
| 写入一致性 | fact 文件和 glossary 是两个普通文件写入；`fact_submit` 还可能返回 `accepted=True` 但 `fact_id=None`/`write_error`（[`server.py#L207-L247`](https://github.com/frenzymath/Danus/blob/7e244865968d3268b21c96b898c7af1f55d2f7c5/danus/gateway/server.py#L207-L247)）。 | 采用 AutoLean SQLite WAL + CAS + idempotency + lease/fencing；“verifier 判断正确”和“证据已原子提交”必须是不同状态。 |
| 事实/引用 provenance | `external_refs` 可在事实文件上原地修改而不改变 fact ID（[`factgraph.py#L231-L252`](https://github.com/frenzymath/Danus/blob/7e244865968d3268b21c96b898c7af1f55d2f7c5/danus/core/factgraph.py#L231-L252)）。 | 数学内容 hash、来源/许可/provenance hash、声明 revision 分离保存；任何公开 artifact 同时绑定它们。 |
| 上下文构建 | Danus verifier HTTP 输入只有 `statement` 和 `proof`（[`service.py#L25-L50`](https://github.com/frenzymath/Danus/blob/7e244865968d3268b21c96b898c7af1f55d2f7c5/danus/verify/service.py#L25-L50)），项目、前置事实内容及其 hash 不在请求合同中。 | ContextPack 必须由冻结 bundle 投影，绑定 contract/revision/environment/proof-boundary/rights/context hash；模型请求先通过 operator authorization。 |
| 记忆写入 | `GlobalMemory.append` 是普通 JSONL append，状态转换只追加记录，允许额外自由字段（[`global_memory.py#L26-L91`](https://github.com/frenzymath/Danus/blob/7e244865968d3268b21c96b898c7af1f55d2f7c5/danus/core/global_memory.py#L26-L91)）。 | 只写 typed event/artifact refs；replay 必须从事件重建投影，不能把自由文本或未验证 finding 当控制状态。 |
| 失败/撤销恢复 | revoke 逐个移动文件并逐个 append 日志，崩溃可留下半撤销状态（[`factgraph.py#L295-L316`](https://github.com/frenzymath/Danus/blob/7e244865968d3268b21c96b898c7af1f55d2f7c5/danus/core/factgraph.py#L295-L316)）。 | 仅产生不可变 invalidation event；旧证据保留，后代在投影中 stale，新的合同 revision 重新走 Builder/Prover。 |
| 角色授权 | `ROLE_TOOLS` 的 main/verifier/worker 隔离和未知 role fail-closed 是好设计（[`roles.py#L21-L45`](https://github.com/frenzymath/Danus/blob/7e244865968d3268b21c96b898c7af1f55d2f7c5/danus/gateway/roles.py#L21-L45)），但 server 也明确允许 `DANUS_ROLE=all`（[`server.py#L56-L60`](https://github.com/frenzymath/Danus/blob/7e244865968d3268b21c96b898c7af1f55d2f7c5/danus/gateway/server.py#L288-L305)）。 | 角色表只能是应用层 capability；真正边界使用 OCI、只读依赖、受限写域、lease/fence、signing gateway 和 provider allowlist。 |

### 3.3 明确拒绝的运行时机制（P0/P1）

1. **LLM `correct` 作为真相写入门（P0）。** `fact_submit` 以 `result.get("verdict") == "correct"` 决定 `accepted`，不校验 report schema、critical errors/gaps、提交 hash、模型/运行身份或独立 replay（[`server.py#L190-L247`](https://github.com/frenzymath/Danus/blob/7e244865968d3268b21c96b898c7af1f55d2f7c5/danus/gateway/server.py#L190-L247)）。AutoLean 只能把它当 advisory proposal；最终接纳必须由固定 Lean 环境及独立 verifier evidence 决定。
2. **自然语言输入与 verifier 指令同层（P0/P1）。** launcher 把 statement/proof 直接插入 prompt，并用 `--dangerously-bypass-approvals-and-sandbox` 启动 codex（[`launcher.py#L145-L166`](https://github.com/frenzymath/Danus/blob/7e244865968d3268b21c96b898c7af1f55d2f7c5/danus/verify/launcher.py#L145-L166)）。恶意证明文本可尝试改变 verifier 行为或写越权文件。AutoLean 适配器只接受 typed canonical bytes，不让外部文本进入 authority prompt；worker 运行在 OCI 隔离环境。
3. **共享文件和 PID 作为恢复协议（P1）。** execution loop 以 detached subprocess、`.pid`、`.stop`、POSIX `flock` 协调（[`execution/loop.py#L121-L166`](https://github.com/frenzymath/Danus/blob/7e244865968d3268b21c96b898c7af1f55d2f7c5/danus/execution/loop.py#L180-L245)、[`orchestration/cli.py#L166-L197`](https://github.com/frenzymath/Danus/blob/7e244865968d3268b21c96b898c7af1f55d2f7c5/danus/orchestration/cli.py#L166-L197)）；没有 AutoLean 的 durable lease、fencing token、CAS event、幂等回放语义。
4. **直接 import/fork Danus runtime（P0）。** 这会把两个 truth model、生命周期和 secrets/host 假设混在一个控制平面，破坏 Builder → frozen contract → Prover 单向边界。只可复制思想或通过下文 adapter 交换未信任 proposal。
5. **Claude/Anthropic transport（P0，策略违规）。** `pyproject.toml` 和 strategy CLI 将 Anthropic 作为正式依赖/transport（[`pyproject.toml#L34-L41`](https://github.com/frenzymath/Danus/blob/7e244865968d3268b21c96b898c7af1f55d2f7c5/pyproject.toml#L34-L41)、[`strategy/cli.py#L22-L41`](https://github.com/frenzymath/Danus/blob/7e244865968d3268b21c96b898c7af1f55d2f7c5/danus/strategy/cli.py#L22-L41)）。AutoLean 只允许 Codex/GPT、DeepSeek 和经能力探测的自定义兼容端点。
6. **Danus Dashboard 代码（P2）。** 其静态 renderer 使用 agent-controlled 字段拼接 HTML/KaTeX，已有 prior audit 记录的 XSS/CDN integrity 风险；只借鉴 graph depth/closure 的视觉语言，使用 AutoLean 已有的只读、消毒投影。

## 4. 与 AutoLean 三图和 Builder--Prover 合同的映射

AutoLean 的协议已明确：Builder 创建/冻结合同，Prover 只提交 proof slot，失败只能是 gap 或 contract-change request，且五个 public commands 不允许替换声明（[`docs/protocol.md#L1-L12`](https://github.com/Wenbobobo/AutoLean/blob/main/docs/protocol.md#L1-L12)、[`docs/protocol.md#L111-L122`](https://github.com/Wenbobobo/AutoLean/blob/main/docs/protocol.md#L111-L122)）。Danus 的 fact graph 不能代替三图：

| AutoLean 对象 | Danus 对应概念 | 允许的关系 | 不允许的关系 |
|---|---|---|---|
| MathematicalGraph | problem/global-memory 的数学候选 | scout 可提出 lemma、反例、定义候选 | scout 不得直接添加节点、改变量词或改变原文来源 |
| FormalGraph | fact graph 中自然语言依赖的近似物 | 可把 proposal 的“建议依赖”作为 untrusted metadata | 不得当作 Lean declaration/import/axiom 事实 |
| ExecutionGraph | worker round/project status 的近似物 | 可把 run、attempt、proposal CAS 投影为 observability evidence | 不得用 PID/status 推导 proof acceptance |
| StatementContract/Bundle | Danus `statement`/`proof` | adapter 可绑定现有 contract digest 供上下文使用 | Danus 不能创建、冻结、替换 revision |
| Lean proof candidate | Danus fact proof 文本 | 可映射到普通 `ProofSubmissionV1` candidate | Danus verdict 不能直接变成 `VerificationReportV1` 或签名 |

AutoLean 已提供足够强的 ContextPack 和 provider seam：`ContextPack` 包含 role、contract/revision/hash、proof boundary 和可渲染 items（[`Prover/context.py#L20-L63`](https://github.com/Wenbobobo/AutoLean/blob/main/Prover/src/autolean_prover/context.py#L20-L63)）；`ArchonProofAdapter` 已示范 proof-term-only 外部引擎桥接，并明确“不 import/start/vendor runtime、普通 verifier 仍是 sole acceptance authority”（[`archon.py#L1-L7`](https://github.com/Wenbobobo/AutoLean/blob/main/Prover/src/autolean_prover/adapters/archon.py#L1-L7)）。Danus adapter 应复用这个原则，而非引入新 authority。

## 5. 最小 Danus-inspired 隔离实验

### 5.1 实验定位

先做一个不依赖 Danus 包的 `ResearchScoutAdapterV1`（建议路径：`Builder/src/autolean_builder/adapters/research_scout.py`；本轮不写实现）。它可以由 DeepSeek 或 fake provider 驱动，也可以未来接入一个单独容器中的 Danus-inspired worker；但 control plane 只看协议，不知道外部 runtime。

### 5.2 请求合同（建议）

适配器通过 canonical UTF-8 JSON/stdio 或 loopback RPC 交换以下 typed envelope；未知字段拒绝，所有 hash 使用完整 SHA-256：

```json
{
  "schema_version": "autolean.research-scout-request.v1",
  "request_id": "stable-id",
  "mission_id": "open-problem-or-textbook-lane",
  "contract_id": "optional-existing-contract-id",
  "revision": 1,
  "contract_hash": "sha256-or-null",
  "graph_snapshot_hash": "sha256",
  "context_pack_hash": "sha256",
  "role": "constructive|refutational|toy_example|decomposition|literature",
  "goal": "quoted, immutable objective",
  "context_artifact_sha256": "sha256",
  "rights_scope_id": "rights-record-id",
  "provider_snapshot_id": "deepseek-or-fake-snapshot",
  "attempt_budget": {"max_attempts": 1, "max_output_tokens": 4096},
  "egress_class": "local|approved-custom",
  "provenance": {"source_ids": [], "source_span_ids": [], "retrieval_hash": null}
}
```

约束：

- `goal` 和 context 只能来自 immutable artifact；不能从 Danus 工作目录或 Builder 私有数据库自行读取。
- `contract_hash` 为空只允许 Builder discovery draft lane；进入 Prover lane 时必须绑定冻结 revision。
- `rights_scope_id`、`egress_class` 和 `provider_snapshot_id` 由 AutoLean 控制平面提供，外部模型不能自行声明。
- 请求不包含 signing key、数据库句柄、lease 写权限、原始 host path 或 secrets。

### 5.3 响应合同（永远是不可信）

```json
{
  "schema_version": "autolean.research-scout-response.v1",
  "request_id": "same-request-id",
  "proposal_id": "full-sha256-derived-id",
  "kind": "lemma|counterexample|toy_example|decomposition|literature_lead|proof_candidate",
  "statement": "candidate text",
  "evidence": "candidate proof/construction/argument",
  "dependency_refs": ["stable-id-or-null"],
  "source_refs": [{"source_id": "...", "span_id": "...", "hash": "..."}],
  "context_pack_hash": "must-match-request",
  "provider": {"provider_id": "deepseek|fake|custom", "model_id": "..."},
  "usage": {"input_tokens": 0, "output_tokens": 0, "cost_micro_usd": 0},
  "output_sha256": "sha256(canonical proposal payload)",
  "status": "untrusted_proposal"
}
```

Adapter 必须：

1. 验证 request/response ID、schema、contract/revision/hash、context hash、source hash、provider allowlist 和预算；拒绝 Claude/Anthropic。
2. 重新计算 canonical `output_sha256`，拒绝重复 key、非 UTF-8、未知字段、超预算、空 proposal、`sorry/admit/sorryAx`（若是 proof_candidate）。
3. 将 proposal 写入独立 CAS staging，并仅发出 `research_hypothesis`/`research_observation` evidence；不调用 `task.registered`、`verify_submission`、签名 gateway 或 model authorization 的接纳路径。
4. 对 `proof_candidate` 只能调用类似 `ArchonProofAdapter.submission` 的转换，得到普通 candidate；必须再次经过当前 lease、Proof.lean 写域和 Lean kernel。
5. 对 `lemma`/`counterexample`/`decomposition` 只能投递 Builder review queue：Builder 负责 source span、量词、假设、反向渲染、mutation tests 和新 revision；原 revision 永不修改。

### 5.4 端到端实验序列

```text
1. 固定 textbook/internal fixture 的 mission 与 source/rights manifest。
2. Control plane 生成 role-scoped ContextPack + snapshot hash。
3. FakeProvider 先生成可重放 proposal；再用 DeepSeek 做相同请求的 live attempt。
4. Adapter 只收/验 CAS response，写 research_hypothesis 事件。
5. Builder 将 proposal 作为 draft evidence，执行 normalize、mapping、semantic quorum、反例/mutation tests。
6. 只有新的 frozen revision 才能 bridge 成 FormalizationTaskBundleV1。
7. Prover 通过 claim/submit_proof/verify_submission 处理 proof_candidate；Lean verifier 是唯一 acceptance authority。
8. 独立 replay 只凭 request/response CAS、bundle 和固定环境重建，不重新调用模型。
9. Dashboard 只显示 proposal、revision、attempt、gap、verification 的事件投影。
```

### 5.5 最小消融矩阵

第一轮不追求大规模模型排名，只问“Danus-inspired 机制是否提高可信 Lean 资产产出”：

| 消融 | A | B | C | D |
|---|---|---|---|---|
| 搜索宽度 | 单 scout | 3 个独立 role | 7 个独立 role | 同预算串行 |
| 记忆 | 无历史 | private scratch | advisory proposal index | 仅冻结 FormalGraph frontier |
| 角色组合 | constructive | constructive + refutational | + toy/counterexample | + literature |
| 策略压缩 | 无 guidance | 固定 deterministic summary | model-generated advisory guidance | summary + independent critic |

固定 provider/model（首轮 DeepSeek）、prompt、tool surface、retrieval snapshot、attempt/token/time/cost budget 和 held-out seed；不允许跨组共享隐藏上下文。报告：

- `valid_envelope_rate`、replay equality、proposal hash 完整率；
- Builder draft→frozen 通过率及被 mutation/反例拦截率；
- frozen bundle→Lean candidate 的 clean-build pass@1/pass@4；
- 从 proposal 到 accepted Lean artifact 的 time/token/cost-to-proof；
- gap 类型、contract-change 请求数、重复/污染率；
- supporting closure 与探索 proposal 数分开统计。

绝不把“fact 数量”“模型一致率”或自然语言 `correct` 计为证明成功。

## 6. 验收测试清单

### 6.1 协议和安全测试（本地可自动完成）

- canonical JSON：重复键、额外字段、错误 schema、非 UTF-8、hash/ID/context mismatch 全部 fail closed。
- 权限：proposal 尝试写 SQLite、发 lease、调用签名 gateway、注册 bundle、改 revision、访问 Builder 私有路径均被隔离 harness 阻断并留下 evidence。
- Provider：`claude`、`anthropic`、未探测 endpoint 和能力声明伪造均在 endpoint I/O 前拒绝。
- 语义：量词交换、`<`/`≤`、删非空/有限/Noetherian 条件、参数反转、真空假设、声明替换必须不能进入 `frozen`。
- Proof boundary：proposal patch 只能落在 `Proof.lean`；`sorry`、`admit`、`sorryAx`、import/axiom 越权均拒绝。
- replay：同一 response CAS 在断电/重启模拟后得到相同 proposal digest；重复投递不产生第二个 terminal verdict。
- negative path：错误 proposal 只产生 gap 或新 draft revision，不得自动修复、弱化或替换旧合同。

### 6.2 真实 DeepSeek 试验的可复现要求

真实 API 试验使用操作员提供的 endpoint reference，不把 key 写入 workspace、日志或 artifact；先运行 fake/replay 再运行 live。每次报告必须绑定：git SHA、adapter schema、provider snapshot、model ID、ContextPack hash、retrieval/fixture hash、attempt/time/token/cost budget 和完整 response CAS hash。API 失败或 usage 缺失时报告 `inconclusive`，不能折算为 pass 或失败证明。

### 6.3 当前本地源码审计复现记录

- 在精确 SHA 上运行 `python -m compileall -q danus`：通过。
- `pytest -q danus/core/tests`：15 passed。
- gateway 测试在当前 AutoLean Python 环境收集时因 Danus optional `mcp` 未安装而失败；这不是安装成功或全套 CI 通过的证据。
- core + execution 测试首先通过 19 项，随后在 Windows 的 `test_do_new_scaffolds_project` 因测试把 TOML 转义后的 Windows path 与未转义 `str(Path)` 直接比较而失败；说明 Danus 当前测试/平台合同尚未成为可直接移植的执行基础。

## 7. 分阶段落位

1. **当前 Phase 1：** 不引入任何 Danus runtime。保留本文件与既有审计，先完成真实 DeepSeek provider/Lean/OCI 证据链。
2. **Phase 2 discovery：** 在 Builder 非冻结区使用 proposal-only scout，优先 textbook opening slices 和内部 20-node DAG fixture；所有 proposal 走 source/rights/fidelity gates。
3. **Phase 2 后段：** 当多个章节切片已有稳定 FormalGraph 后，加入 supporting-closure projection、failure-route compression 和 immutable descendant invalidation。
4. **后续研究阶段：** 在 held-out known-theorem closures 上比较普通 scheduling 与 Danus-inspired portfolio；只有 Lean-verified closure 在固定预算下有增益，才扩大到 Open Problem portfolio。
5. **长期：** Danus-inspired scout 可以提出 lemma、反例、路线和文献线索，但永远不能从 proposal 直接成为数学资产；Open Problem 的可信产物仍由 Builder--Prover 双引擎生成。

## 8. 最终决定表

| Danus 部件 | 决定 | AutoLean 落点 |
|---|---|---|
| Fact-sized workers | 重实现 | role-scoped ContextPack / proposal CAS |
| Local/global/verified memory | 重实现并加强 | advisory experience + 三图/事件投影 |
| Strategy compression | 重实现 | advisory guidance artifact |
| Constructive/refutational/toy/literature lanes | 重实现 | Builder discovery lanes、mutation/counterexample tests |
| Supporting closure visual language | 借鉴设计 | 只读 Dashboard projection |
| Cascade revocation idea | 重实现 | immutable invalidation/revision/replay |
| Matlas/arXiv search | 隔离 adapter | rights/source-hash bound retrieval only |
| Danus fact import | 隔离 adapter | `research_hypothesis`，不进入 FormalGraph truth |
| Danus verifier / `correct` verdict | 拒绝 | Lean kernel + independent verifier evidence |
| Danus gateway role table as security | 拒绝 | OCI/capability/lease/fence/signing gateway |
| Shared files/PID/revoke move | 拒绝 | SQLite WAL/CAS/append-only events |
| 16-hex IDs / mutable refs | 拒绝 | full SHA-256 + separate provenance revisions |
| Claude/Anthropic runtime | 拒绝 | Codex/GPT/DeepSeek/custom allowlist |

**风险结论：** 直接集成 Danus runtime 为 P0；按本文件实现隔离 scout 为 P2 研究增强，且不会扩大 AutoLean 的语义、权限或发布边界。下一步不是 fork Danus，而是把上述 `ResearchScoutAdapterV1` 写成最小 typed seam，并用 fake → DeepSeek → Builder → Lean 的闭环证明它只能贡献候选、不能贡献真相。
