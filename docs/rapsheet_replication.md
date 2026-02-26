# ThreatGraph 复刻 RapSheet 方法说明

本文用于说明 ThreatGraph 如何复刻 RapSheet（USENIX Security/Oakland 2020）的方法论，以及当前实现进度与后续计划。

论文来源（当前工作目录）：`../Hassan_Oakland20.pdf`（文本提取版：`../extracted_text/Hassan_Oakland20.txt`）。

## 1. RapSheet 解决的问题

RapSheet 面向 EDR 场景的三个核心问题：

1. 告警量巨大，单条 MITRE 规则告警误报高，人工无法及时筛查。
2. 低层系统日志体量大，人工拼接攻击上下文成本高。
3. 长期日志保留成本高，导致跨天/跨周攻击链上下文丢失。

RapSheet 的关键思想：

- 在 provenance graph 的**事件边**上标注告警（alert events）。
- 从原始图中抽取 IIP graph（初始感染点相关子图），聚合上下文。
- 将告警事件提升为 TPG 顶点，基于 happens-before 建立 sequence edges。
- 在 TPG 上做 kill-chain 有序序列评分，用于告警优先级排序。
- 用 skeleton graph 降低存储成本并保留未来关联能力。

## 2. ThreatGraph 的复刻架构

ThreatGraph 采用与 RapSheet 对齐的分层思路：

1. 采集层：从 Redis 消费 Sysmon JSON（`winlog.event_data`）。
2. 规则层：使用 Sigma 规则引擎给事件打 IOA 标签。
3. 图层：将 Sysmon 映射为时序有向邻接表（process/file/net/domain 与边关系）。
4. 战术层：从图中抽取 IIP/TPG 结构（新增库能力）。
5. 评估层：在 TPG 上做威胁评分并输出优先级（规划中）。

## 3. 与论文对齐的实现点

### 3.1 事件边告警标注（已实现）

- ThreatGraph 现在将 IOA 标签附着在 edge rows，不再回退到 vertex。
- 这与 RapSheet 的“alert events are edge-backed”语义一致。

对应代码：

- `internal/graph/adjacency/mapper.go`

### 3.2 Sysmon + Sigma 规则标注（已实现）

- 接入 `sigma-go` 进行单事件匹配，命中后写入 `IoaTag`。
- 启动时会过滤复杂规则（聚合/timeframe/复杂 condition），确保在线路径稳定。

对应代码：

- `internal/rules/sigma_engine.go`
- `cmd/threatgraph/main.go`

### 3.3 IIP/TPG 构建能力（已实现为库模块）

- 新增战术图构建模块，提供：
  - `CollectAlertEvents`：从 edge + IOA 标签提取 alert events
  - `BuildIIPGraphs`：按告警时间流执行“反向早期告警判定 + 前向告警可达裁剪”构建 IIP 子图
  - `BuildTPG`：构建 alert-event 顶点与时序 sequence edges

对应代码：

- `internal/analyzer/tactical.go`
- `internal/analyzer/tactical_test.go`

### 3.4 Kill-chain 序列评分（已实现）

- 基于 TPG 顶点（alert events）执行“最长有序子序列”评分。
- 使用 sequence edge 上的 DAG DP（长度优先、分数次优）与 tactic 顺序约束输出排序分数。
- `analyze` 可通过 `--tactical-output` 生成战术评分结果。

对应代码：

- `internal/analyzer/tactical_score.go`
- `cmd/threatgraph/main.go`

## 4. 当前与 RapSheet 的差距

以下能力尚未完全对齐论文，需要继续推进：

1. **跨主机 happens-before 不完整**：当前重点是同主机时序序关系，跨主机关联仍需补齐。
2. **IIP 仍有工程近似**：已加入时间约束反向判定，但尚未引入跨主机 connect/accept 的完整 happens-before 约束。
3. **风险权重仍是工程近似**：当前用 severity/technique 权重，尚未完整接入 CAPEC 双指标体系。
4. **skeleton graph 未实现**：尚未上线论文中的长期保留约简规则。

## 5. 复刻路线图（建议）

建议按以下顺序推进，保证每一步可验证：

1. 校准 kill-chain 评分参数与阈值（结合真实环境回放样本）。
2. 增强跨主机 sequence edge（connect/accept 语义关联）。
3. 接入 CAPEC 风险映射，替换当前简化权重。
4. 实现 skeleton graph 约简与长期重放验证。

## 6. 为什么这条路线适合 ThreatGraph

- ThreatGraph 已有高吞吐的时序邻接表基础，适合战术图增量构建。
- 已支持 raw replay capture，可用于离线回放和回归评估。
- 通过“先结构、后评分”的路径，可以在不破坏生产采集链路的前提下逐步复刻论文方法。

---

如果你在项目评审中使用本文，建议同步提供两组指标：

- 工程指标：吞吐、内存、P95 延迟、落盘成本。
- 检测指标：Top-K 命中率、误报率变化、人工排查量下降比例。
