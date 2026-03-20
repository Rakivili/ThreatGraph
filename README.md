# ThreatGraph

ThreatGraph 是一个面向 Sysmon / 离线 EDR 事件的图分析引擎，提供四个主命令：

- `produce`：把输入事件转换为邻接表（`JSONL` / `HTTP` / `ClickHouse`）。
- `analyze`：离线批量分析，输出 `IIP / TPG / Incident`。
- `serve`：从 ClickHouse 的 `ioa_events` 增量轮询，做准实时分析。
- `explain-incident`：对单个 incident 回溯窗口并重建 IIP/TPG 细节。

---

## 当前分支状态（重要）

本 README 以当前代码行为为准（`feature/incident-subgraph-clickhouse-svg`）：

- `produce` 主链路当前**不走 Sigma 引擎**，IOA 标签来自离线 EDR 字段映射。
- ES 查询语句有固定配置入口：`threatgraph.input.elasticsearch.query`（JSON 字符串）。
- `host_prefilter=true` 时，会先发现主机，再按主机批次回拉事件（见下文查询机制）。
- `run_once` 对 ES 输入目前主要是兼容字段；ES 消费本身是 scroll 读完即结束。

---

## 架构总览

### 1) 离线批处理（推荐 v10）

`Elasticsearch -> produce -> ClickHouse(adjacency) -> analyze -> incidents`

适合离线数据回放与全量分析。

### 2) 准实时增量

`produce -> ClickHouse(adjacency + ioa_events) -> serve -> incidents`

`serve` 会维护 `ioa_processed` 去重标记，避免重复计算。

---

## 检测原理（简版）

ThreatGraph 当前主线是“事件证据 -> 时序因果图 -> 战术序列评分 -> incident”：

1. **证据提取（IOA）**
   - 在 `produce` 中，从离线 EDR 字段生成 `ioa_tags`（`risk_level/alert_name/name_key/ext_process_rule_id/attack.*`）。
   - 仅 `record_type=edge` 且 `ioa_tags` 非空的边会进入后续告警事件集合。

2. **图建模（Adjacency）**
   - 统一有向边：`vertex_id -> adjacent_id`，按 `ts + record_id` 排序。
   - 运行时可只落最小元信息（`write_vertex_rows=false` + `include_edge_data=false`），降低 I/O。

3. **IIP 构建（初始感染点子图）**
   - 对每个 host 的告警边按时间排序。
   - 通过“最近可达早期告警”分配 seed，得到每个 IIP root。
   - 从 seed 前向扩展，只保留能到达告警的路径（`can_reach_alert`），裁剪噪声边。

4. **TPG 构建（战术图）**
   - 顶点 = IIP 内告警事件。
   - 序列边 = 同主机时间链 + IIP 路径上的因果告警对（happens-before 近似）。

5. **战术评分与优先级**
   - 在 TPG 上执行 DAG DP：先最大化 `sequence_length`，再最大化风险得分。
   - 评分融合 `severity`、`tactic`、`technique`，并对重复规则命中做对数抑制。
   - `incident-min-seq` 用于过滤过短序列，输出 `incident` 供 SOC 分诊。

更详细说明见：`docs/detection_principles.md`。

---

## 快速开始（v10）

### 前置条件

- Go 1.24+（见 `go.mod`）
- 可访问的 ClickHouse HTTP 端口（默认 `8123`）
- （可选）Elasticsearch（离线 EDR 回放时需要）

### 构建

```bash
make
```

二进制输出：`bin/threatgraph`（Windows 下为 `bin/threatgraph.exe`）。

---

## 配置文件

默认会按以下顺序查找配置：

1. 命令行传入路径（如 `./bin/threatgraph produce xxx.yml`）
2. 当前目录 `threatgraph.yml`
3. 可执行文件同目录 `threatgraph.yml`

配置根结构在 `config/config.go`，核心段如下：

- `threatgraph.input`：输入（`redis` / `elasticsearch`）
- `threatgraph.pipeline`：并发与批量参数
- `threatgraph.graph`：邻接行精简开关
- `threatgraph.output`：邻接输出
- `threatgraph.ioa`：IOA 事件输出
- `threatgraph.serve`：增量分析参数

### v10 推荐配置片段（离线 ES -> ClickHouse）

```yaml
threatgraph:
  input:
    mode: elasticsearch
    elasticsearch:
      url: https://127.0.0.1:9200
      index: edr-offline-ls-*
      query: '{"query":{"bool":{"filter":[{"range":{"@timestamp":{"gte":"2026-03-04T00:00:00Z","lt":"2026-03-05T00:00:00Z"}}}],"should":[{"bool":{"must":[{"term":{"risk_level":"notice"}},{"term":{"operation":"CreateProcess"}},{"term":{"fltrname.keyword":"CommonCreateProcess"}}]}},{"bool":{"must":[{"term":{"risk_level":"notice"}},{"term":{"operation":"WriteComplete"}},{"term":{"fltrname.keyword":"WriteNewFile.ExcuteFile"}}]}},{"bool":{"must":[{"exists":{"field":"risk_level"}}],"must_not":[{"term":{"risk_level":"notice"}}]}}],"minimum_should_match":1}}}'
      host_prefilter: true
      host_batch_size: 50
      host_batch_workers: 4
      batch_size: 2000
      scroll: 5m
      timeout: 60s
      run_once: true
  pipeline:
    workers: 8
    write_workers: 2
    batch_size: 20000
    flush_interval: 5s
  graph:
    write_vertex_rows: false
    include_edge_data: false
  output:
    mode: clickhouse
    clickhouse:
      url: http://127.0.0.1:8123
      database: threatgraph
      table: adjacency_offline_full_20260304_v10
      format: row_binary
  ioa:
    enabled: false
```

---

## Elasticsearch 查询机制（回答“是否有固定配置文件”）

有。主查询模板来自：

- `threatgraph.input.elasticsearch.query`

实现细节（`internal/input/elasticsearch/consumer.go`）：

1. 若 `query` 为空，默认使用 `match_all`。
2. 若缺少 `size/sort`，自动注入：
   - `size = batch_size`
   - `sort = ["_doc"]`
3. 若设置 `slices > 1`，自动注入 ES slice 参数。
4. 若 `host_prefilter=true`：
   - Phase 1：基于你的 `query.bool.filter` 发现候选 host，并附加：
     - `exists risk_level`
     - `must_not risk_level=notice`
     - `must_not operation=PortAttack`
     - `cardinality(ext_process_rule_id.keyword) > 1`
   - Phase 2：在原始查询模板上注入 `terms client_id.keyword in [host batch]`
   - 对 non-notice 分支额外注入 `must_not operation=PortAttack`

所以：查询“骨架”在配置里，程序只做必要注入，不是完全硬编码。

---

## ClickHouse 表

### 必需表（离线 analyze）

```bash
clickhouse-client --query "CREATE DATABASE IF NOT EXISTS threatgraph"
clickhouse-client < migrations/001_adjacency.sql
```

### 必需表（serve 增量）

```bash
clickhouse-client --query "
CREATE TABLE IF NOT EXISTS threatgraph.ioa_events (
  ts DateTime64(3),
  host String,
  agent_id String,
  record_id String,
  event_id UInt16,
  edge_type String,
  vertex_id String,
  adjacent_id String,
  name String
)
ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (host, ts, name, record_id)
TTL ts + INTERVAL 14 DAY
"

clickhouse-client < migrations/002_ioa_processed.sql
```

---

## 命令说明

### `produce`

```bash
./bin/threatgraph produce threatgraph.yml
```

兼容旧调用方式（不写子命令）：

```bash
./bin/threatgraph threatgraph.yml
```

说明：

- `input.mode=elasticsearch` + `host_prefilter=true`：优先走 host 预筛选模式。
- 若启用 `time_shards` / `time_shard_minutes`，会分片生成子配置并并发子进程执行。
- 两者同时开时，当前代码优先 `host_prefilter`。

### `analyze`

文件输入：

```bash
./bin/threatgraph analyze \
  --source file \
  --input output/adjacency.jsonl \
  --output output/iip_graphs.jsonl \
  --tactical-output output/scored_tpg.jsonl \
  --incident-output output/incidents.min2.jsonl \
  --incident-min-seq 2
```

ClickHouse 输入（v10 常用）：

```bash
./bin/threatgraph analyze \
  --source clickhouse \
  --config threatgraph.yml \
  --adjacency-table adjacency_offline_full_20260304_v10 \
  --since 2026-03-04T00:00:00Z \
  --until 2026-03-05T00:00:00Z \
  --output output/iip_ch_full_20260304_v10.jsonl \
  --tactical-output output/tpg_ch_full_20260304_v10.jsonl \
  --incident-output output/incidents_ch_full_20260304_v10.jsonl \
  --incident-min-seq 2
```

注意：

- `--source=clickhouse` 必须提供 `--config --since --until`。
- 至少要给 `--tactical-output` 或 `--incident-output` 之一。

### `serve`

```bash
./bin/threatgraph serve threatgraph.yml
```

`serve` 读取 `threatgraph.serve.analyze` 配置，循环：

- 拉取未处理 IOA 批次（`ioa_events` - `ioa_processed`）
- 按 host 取邻接窗口（`adjacency_table`）
- 执行 IIP/TPG/Incident
- 写 incident 输出并标记 processed

当 `serve.incident.mode=file` 时，会额外维护两个兼容快照：

- `incidents.latest.min2.jsonl`
- `scored_tpg.latest.jsonl`

### `explain-incident`

```bash
./bin/threatgraph explain-incident \
  --config threatgraph.yml \
  --incident-file output/incidents_ch_full_20260304_v10.jsonl \
  --index -1 \
  --out output/incident_explain.latest.json
```

输出包含：

- 原始 incident
- 选中窗口
- 匹配 IIP
- 重建 TPG
- 评分摘要
- 时间线（包含 IOA 名称/战术/技术）

---

## IOA 标签来源（当前实现）

`produce` worker 中使用 `offlineEDRIOATags(...)` 生成 IOA 标签（`internal/pipeline/adjacency_redis_pipeline.go`）：

- `risk_level` 为空或 `notice` 时不生成 IOA 标签
- `name` 优先 `alert_name`，其次 `name_key`，再退化为 `offline-edr-ioa`
- `id` 来自 `ext_process_rule_id`
- `tactic/technique` 来自 `attack.tactic` / `attack.technique`

---

## 已知限制与兼容性说明

- `rules.enabled/path` 配置仍在，但当前 `produce` 主链路未接入 Sigma 引擎。
- `run_once` 在 ES 输入下目前主要是兼容字段，实际结束条件是 scroll EOF。
- `serve` 依赖 `ioa_events + ioa_processed`，若 `ioa.enabled=false` 则不能直接做增量链路。
- `output.clickhouse.format` 仅邻接写入支持 `json_each_row` / `row_binary`；IOA 写入固定 `JSONEachRow`。

---

## 相关文档

- `docs/detection_principles.md`
- `docs/rapsheet_replication.md`
- `docs/produce_min_metadata_checklist.md`
- `docs/offline_edr_adjacency_mapping.md`
- `docs/es_offline_edr_to_adjacency_mapping.md`
- `docs/adjacency_table_schema.md`
