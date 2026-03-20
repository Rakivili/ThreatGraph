# ThreatGraph Implementation Owner Review

这份文档不是产品介绍，而是给实现 owner 用的复习提纲。目标是 20 到 30 分钟内重新建立对当前仓库关键路径的掌控感，知道：

- 现在真正还在跑的主链路是什么
- `produce` 和 `analyze` 分别从哪里进、到哪里出
- 哪些文件值得读，哪些先不用管
- 接入 MDR 时，这个仓库应当承担什么，不应当承担什么

---

## 1. 当前边界

先把边界钉死。当前项目不是一个“全功能安全平台”，而是一个新的 incident generation engine。

当前明确成立的约束：

- 只解决单终端问题，不做跨主机关联。
- 主链路只有 `produce` 和 `analyze`，`serve` 已经不是当前设计中心。
- `produce` 的输入当前只有 `elasticsearch`。
- `analyze` 的输入当前是 `file` 或 `clickhouse`，离线主路径是 `clickhouse`。
- 图是一种分析模型，不要求使用图数据库。
- 当前默认策略是：先筛感染主机，再按主机回拉日志，再在内存里做局部图分析。

这几个边界对后续所有设计判断都很重要。只要边界不变，这套系统的复杂度就是可控的。

---

## 2. 建议阅读顺序

### 第一轮：只看入口和数据流

1. `config/config.go`
2. `cmd/threatgraph/main.go`
3. `cmd/threatgraph/produce_hosts.go`
4. `internal/input/elasticsearch/consumer.go`
5. `internal/pipeline/adjacency_pipeline.go`
6. `internal/graph/adjacency/mapper.go`
7. `internal/output/adjacencyclickhouse/writer.go`
8. `internal/input/clickhouse/reader.go`
9. `internal/analyzer/tactical.go`
10. `internal/analyzer/tactical_score.go`
11. `internal/analyzer/incident.go`
12. `internal/analyzer/subgraph.go`

### 第二轮：只看契约和映射说明

1. `docs/adjacency_table_schema.md`
2. `docs/detection_principles.md`
3. `docs/es_offline_edr_to_adjacency_mapping.md`
4. `README.md`

### 可以先不看的部分

- `tools/make_viewer.py` 之外的大多数 Python 工具
- `serve` 相关历史思路
- 非离线主路径的细枝末节优化
- 不是当前输出契约的一次性实验代码

---

## 3. Produce 主链路

### 3.1 入口

`produce` 的入口在 `cmd/threatgraph/main.go` 的 `runProducer(...)`。

这个函数做的事很固定：

1. 读取配置并补默认值。
2. 如果 ES 没给完整查询，自动生成默认查询。
3. 初始化日志和 metrics。
4. 根据配置选择：
   - `host_prefilter`
   - `time_shards`
   - 普通 producer
5. 构建 pipeline 并执行。

你只要记住：`runProducer(...)` 本身不做分析逻辑，它主要是调度器。

### 3.2 两阶段 host prefilter

离线主路径最重要的是 `cmd/threatgraph/produce_hosts.go` 里的 `runHostPrefilteredProducer(...)`。

当前逻辑是：

1. 调 `DiscoverNonNoticeHosts(...)` 从 ES 找到感染主机集合。
2. 对主机列表排序、分 batch。
3. 每个 worker 拿一个 host batch。
4. 每个 batch 启一个 producer pipeline，只拉这一批 host 的日志。

这就是为什么你当前的 `produce` 不是“对全索引全量扫描后再过滤”，而是：

- 第一次查询：发现感染主机
- 第二次查询：只回拉这些主机的日志来构图

这是当前性能边界最关键的设计点。

### 3.3 ES Consumer 在做什么

`internal/input/elasticsearch/consumer.go` 负责：

- 解析 ES 查询模板
- 注入 `size` / `sort`
- 注入 host filter
- 处理 scroll
- 发现感染主机的 composite aggregation

要点：

- `DiscoverNonNoticeHosts(...)` 不是直接扫全量命中，而是走聚合。
- `NewConsumer(...)` 会把 host 过滤条件注入原查询中。
- `Pop(...)` 负责把 ES `_source` 一条条吐给 pipeline。

如果后面 `produce` 很慢，第一检查点通常不是 Go 算法，而是这里的查询形态、字段数量和网络往返。

### 3.4 Pipeline 在做什么

核心文件：`internal/pipeline/adjacency_pipeline.go`

这是一条通用的数据处理流水线：

1. `readLoop`
   从 consumer 读原始消息。
2. `workerLoop`
   解析原始消息，转成内部 `Event`。
3. `batchLoop`
   把 adjacency row / IOA event 聚合成批次。
4. `writeLoop`
   把邻接表写到目标存储。

这层最值得记住的事情有两件：

- `produce` 的并发主要发生在这里。
- 这里既承担解析，也承担写库前的批量化。

### 3.5 Mapper 在做什么

核心文件：`internal/graph/adjacency/mapper.go`

这是把单条日志转换成邻接表行的地方。它决定了：

- 生成哪些 vertex / edge
- 顶点 ID 和边类型怎么编码
- 旧字段和离线 EDR flatten 字段如何兼容

当前如果你怀疑“为什么某个事件没进图”或“为什么 incident 链路怪”，多半最终会落回这个文件。

### 3.6 IOA 标签来源

IOA 标签当前是在 pipeline 里挂到事件上的，而不是 analyzer 里事后推断。

关键函数：

- `internal/pipeline/adjacency_pipeline.go`
- `offlineEDRIOATags(...)`

这一步决定了后面：

- 哪条 edge 被视为 alert edge
- `BuildIIPGraphs(...)` 能不能正确找到 seed
- `BuildIncidents(...)` 会不会有足够的战术信号

---

## 4. Analyze 主链路

### 4.1 入口

入口在 `cmd/threatgraph/main.go` 的 `runAnalyzer(...)`。

`analyze` 只做两件事：

- 从 `file` 或 `clickhouse` 读邻接表
- 生成 `iip`、`tpg`、`incident`、`subgraph`

### 4.2 ClickHouse 路径

当前离线主路径走 `--source clickhouse`。

核心行为：

1. 读取配置和时间范围。
2. 通过 `internal/input/clickhouse/reader.go` 连接 ClickHouse。
3. 如果没显式指定 host，则先用 `ReadAlertHostsFromAdjacency(...)` 找有告警的主机。
4. 对每个 host 执行：
   - `ReadRows(host, since, until)`
   - `BuildIIPGraphs(hostRows)`
   - `BuildScoredTPGs(hostIIPs)`
   - `BuildIncidents(hostScored, minSeq)`
   - `WriteIncidentSubgraphs(...)`

你现在的分析模型是典型的“按 host 拉全量边到内存，再做局部图分析”。

这也是为什么：

- 单 host 分析内存是可控的
- 多 host 高并发 analyze 要谨慎
- 不需要图数据库也能成立

### 4.3 IIP / TPG / Incident

这三层分别在：

- `internal/analyzer/tactical.go`
- `internal/analyzer/tactical_score.go`
- `internal/analyzer/incident.go`

最短理解路径是：

1. `BuildIIPGraphs(...)`
   从带 IOA 标签的 edge 中找 IIP seed，并裁出与告警可达相关的局部图。
2. `BuildTPG(...)`
   把 IIP 图转成 tactical provenance graph。
3. `ScoreTPG(...)`
   给战术路径打分。
4. `BuildIncidents(...)`
   把高价值 TPG 收敛成 incident。

如果你要理解“为什么一条 incident 会生成出来”，从这四步往回看就够了。

### 4.4 Incident Subgraph

当前 incident 子图已经从 Python 后处理搬进 Go。

核心文件：`internal/analyzer/subgraph.go`

当前逻辑是：

1. 对 incident 按 `(host, root)` 去重。
2. 从 `root + iip_ts` 做前向时序遍历。
3. 只保留带 IOA 路径相关的边：
   - IOA edge 本身
   - 通向 IOA 的前置路径
   - IOA 之后的后置路径
4. 输出：
   - `subgraph_*.jsonl`
   - `summary.jsonl`

现在 `make offline` 的 HTML 视图就是基于这个产物，而不是再去跑单独的 Python 子图构建器。

---

## 5. 当前核心数据契约

### 5.1 输入契约：ES

当前 `produce` 真正依赖的是一批最小字段，不是整条原始日志。后续任何性能优化或接 MDR，都应该优先保住这份最小字段集。

参考：

- `threatgraph.offline.vm.yml`
- `docs/es_offline_edr_to_adjacency_mapping.md`
- `docs/produce_min_metadata_checklist.md`

### 5.2 存储契约：邻接表

当前 ClickHouse adjacency 表的持久化列只有 10 个：

- `ts`
- `record_type`
- `type`
- `vertex_id`
- `adjacent_id`
- `event_id`
- `host`
- `agent_id`
- `record_id`
- `ioa_tags`

参考：

- `docs/adjacency_table_schema.md`
- `internal/output/adjacencyclickhouse/writer.go`
- `internal/input/clickhouse/reader.go`

这张表是 append-only 的时序边表，不是通用业务表。

### 5.3 输出契约：incident 生成器

这个仓库对 MDR 最终应该输出的，不是 HTML，而是：

- incident 候选
- supporting subgraph
- 相关 `processuuid`
- 风险分数和优先级
- 最小可解释证据链

HTML 只是当前验证手段，不是最终契约。

---

## 6. 性能与内存的正确观察点

### 6.1 现在最可能的瓶颈

当前阶段通常优先怀疑：

1. ES 拉取和网络往返
2. `_source` 过大
3. JSON 解析与字段抽取
4. mapper 里的对象分配
5. ClickHouse 写入

不是先怀疑语言本身。

### 6.2 为什么不要急着重写 Rust

除非你已经证明 CPU 主要耗在：

- parser
- mapper
- analyzer 核心遍历

否则先重写 Rust 的收益大概率不如：

- 缩字段
- 减请求次数
- 让程序靠近 ES / ClickHouse
- 调整 batch / worker
- 减少 Go 侧分配

### 6.3 Analyze 并发要保守

你已经测到单 host `analyze` 峰值大约 `130 MB`。这意味着：

- 单 host 分析是健康的
- 多 host 并发分析不能盲目拉高

默认思路应该是：

- `produce` 并发可以偏高
- `analyze` 按低并发甚至串行执行
- 如需并发，按内存预算而不是固定 worker 数去做

---

## 7. 接 MDR 时的边界

后面接 MDR 中台时，这个仓库建议只承担：

- 对接 ES
- 生成新的 incident
- 生成 supporting subgraph / evidence

不建议继续在这个仓库里重复做：

- 进程树构造
- 富化上下文
- 资产信息
- 老 viewer 之外的平台交互逻辑

这些既然 MDR 中台已有，就让它们继续留在中台。

更准确地说，ThreatGraph 的定位应该是：

> 一个新的、基于时序图的 incident generation engine。

不是“一个完整的安全运营平台”。

---

## 8. 你最需要掌握的 8 个函数

如果只背 8 个函数，先背这 8 个：

1. `runProducer(...)`
2. `runHostPrefilteredProducer(...)`
3. `inputelasticsearch.DiscoverNonNoticeHosts(...)`
4. `newProducerPipeline(...)`
5. `analyzer.BuildIIPGraphs(...)`
6. `analyzer.BuildScoredTPGs(...)`
7. `analyzer.BuildIncidents(...)`
8. `analyzer.WriteIncidentSubgraphs(...)`

只要这 8 个函数的输入、输出和调用顺序你心里清楚，这个仓库的主链路就不会丢。

---

## 9. 最后的判断标准

后续这个项目是不是成立，不取决于代码写得多花，而取决于这几个问题：

- incident 数量是否明显下降
- 关键主机是否仍然被覆盖
- 每条 incident 是否更容易解释
- 分析师是否更快进入处置
- 跑一个月后是否仍然稳定

如果这些成立，这个仓库就是产品级核心能力；如果不成立，问题也应该优先从数据契约、分析边界和输出适配里找，而不是先怪“没上图数据库”或者“不是 Rust”。
