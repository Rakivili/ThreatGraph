# ThreatGraph 检测原理（当前分支）

本文基于当前代码路径（`feature/incident-subgraph-clickhouse-svg`）总结 ThreatGraph 的检测链路，重点描述实际运行逻辑，而不是历史设计目标。

---

## 1. 总体思路

当前实现采用 5 层流水：

1. **事件证据层**：从离线 EDR 事件抽取 IOA 标签。
2. **图建模层**：映射为时序有向邻接边。
3. **IIP 层**：构建初始感染点相关子图。
4. **TPG 层**：将告警事件提升为战术图并建立序列边。
5. **评分与输出层**：做 kill-chain 序列评分并输出 incident。

入口命令对应关系：

- `produce`：完成第 1~2 层并落地邻接数据。
- `analyze`：完成第 3~5 层（离线）。

---

## 2. 事件证据层（IOA 生成）

当前主链路下，`produce` worker 会调用 `offlineEDRIOATags(...)`（`internal/pipeline/adjacency_redis_pipeline.go`）生成 IOA 标签。

### 字段映射

- `IoaTag.ID <- ext_process_rule_id`
- `IoaTag.Name <- alert_name`（空则 `name_key`，再空则 `offline-edr-ioa`）
- `IoaTag.Severity <- risk_level`
- `IoaTag.Tactic <- attack.tactic`
- `IoaTag.Technique <- attack.technique`

### 过滤逻辑

- `risk_level` 为空或 `notice`：不生成 IOA 标签。
- 只有带 IOA 的 `edge` 行会成为后续“告警事件”。

这决定了后续 IIP/TPG 的召回上限：如果 IOA 标签缺失或质量差，分析层无法恢复攻击链。

---

## 3. 图建模层（Adjacency）

事件经 mapper 转为邻接行（`models.AdjacencyRow`）：

- 关键字段：`ts / record_type / type / vertex_id / adjacent_id / host / record_id / ioa_tags`
- 统一方向：`vertex_id -> adjacent_id`
- 时间序：`ts + record_id` 形成稳定时序键

对于大规模离线数据，推荐最小化落盘：

- `graph.write_vertex_rows=false`
- `graph.include_edge_data=false`

分析链路主要依赖 edge + ioa_tags，不依赖富顶点行。

---

## 4. IIP 构建原理

核心函数：`BuildIIPGraphsWithStats(...)`（`internal/analyzer/tactical.go`）。

### 4.1 告警事件抽取

- 从邻接行中抽取 `record_type=edge && ioa_tags非空` 的边，形成 `AlertEvent`。

### 4.2 同边同规则去重

- 对同一 `host + from + to + edge_type + rule_id` 的重复告警做压缩。
- 重复项仍保留边，但会清空 `ioa_tags`，避免同规则对评分链造成夸大。

### 4.3 IIP seed 分配

- 在同 host 告警时间流上，为每个告警找到“最近可达的更早告警”。
- 找不到早期可达告警的事件，视为 IIP seed（root）。

### 4.4 子图扩展与裁剪

- 从 seed 顶点前向遍历，只保留：
  - 告警边；
  - 或能到达告警的必要路径（`can_reach_alert`）。
- 这一步用于去噪，减少与告警无关的扩散边。

---

## 5. TPG 构建原理

核心函数：`BuildTPG(...)`（`internal/analyzer/tactical.go`）。

### 5.1 顶点

- 顶点来自 IIP 中的 `AlertEvent`。
- 对同一来源进程 `from` 的同 technique 做去重，减少战术图冗余。

### 5.2 序列边

序列边来源有两类：

1. **同主机时间链**：相邻时间告警直接连边。
2. **因果可达链**：若告警 A 的 `to` 在 IIP 路径上可达告警 B 的 `from`，且时间满足先后，则建立 A->B。

该机制是当前分支对 happens-before 的工程近似实现。

---

## 6. 战术评分原理

核心函数：`ScoreTPG(...)`（`internal/analyzer/tactical_score.go`）。

### 6.1 单告警基础分

- 基础公式：`TS = 2 * severity + likelihood`
- `severity` 由级别映射（`informational/low/medium/high/critical`）
- `likelihood` 默认与 severity 同级；若 technique 缺失会降级

### 6.2 tactic 顺序约束

- tactic 映射到有序等级（支持名称与 TA 编号）。
- 序列扩展时要求 tactic rank 非递减。

### 6.3 DAG DP 优化目标

在 TPG 序列边上做 DP，优化优先级：

1. 最大化 `SequenceLength`
2. 在长度相同下最大化风险（对数空间累计）

### 6.4 重复规则抑制

- 同规则多次命中采用 `1 + log(hit_count)` 增益，而非线性倍增。
- 目的是保留“重复命中增加风险”的信号，同时避免指数膨胀。

---

## 7. Incident 生成

核心函数：`BuildIncidents(...)`（`internal/analyzer/incident.go`）。

- 输入：`ScoredTPG`
- 过滤：`sequence_length >= incident_min_seq`
- 输出字段：`host/root/iip_ts/sequence_length/risk_product/risk_sum/tactic_coverage/alert_count/severity`

默认严重级别阈值：

- `critical`：`seq >= 4` 或 `risk_product >= 100`
- `high`：`seq >= 3` 或 `risk_product >= 25`
- `medium`：`seq >= 2` 或 `risk_product >= 9`
- 其余 `low`

---

## 8. 当前边界与注意事项

1. 当前 `produce` 主链路 IOA 来自离线 EDR 字段，不是 Sigma 在线匹配。
2. 检测效果高度依赖 `ioa_tags` 的召回和质量。
3. happens-before 仍以同 host 时序与图可达为主，跨主机关联能力有限。
4. `run_once` 对 ES 输入更多是兼容字段，ES 消费本身读完即结束。
