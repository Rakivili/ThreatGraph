# ThreatGraph

ThreatGraph 是一个面向 Sysmon / 离线 EDR 事件的图分析引擎，当前提供两个主命令：

- `produce`：把输入事件转换为邻接表（`JSONL` / `HTTP` / `ClickHouse`）。
- `analyze`：离线批量分析，输出 `IIP / TPG / Incident`。

---

## 当前分支状态（重要）

本 README 以当前代码行为为准（`feature/incident-subgraph-clickhouse-svg`）：

- `produce` 主链路当前**不走 Sigma 引擎**，IOA 标签来自离线 EDR 字段映射。
- ES 查询支持两种方式：
  - 显式提供 `threatgraph.input.elasticsearch.query`（JSON 字符串）
  - 仅提供 `threatgraph.input.elasticsearch.since/until`，程序自动生成默认筛选查询
- `host_prefilter=true` 时，会先发现主机，再按主机批次回拉事件（见下文查询机制）。
- `run_once` 对 ES 输入目前主要是兼容字段；ES 消费本身是 scroll 读完即结束。
- Metrics 默认关闭；如需开启可设置 `threatgraph.metrics.enabled: true`（`/metrics`，默认监听 `:9091`）。

---

## 架构总览

### 1) 离线批处理（推荐 v10）

`Elasticsearch -> produce -> ClickHouse(adjacency) -> analyze -> incidents`

适合离线数据回放与全量分析。

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

### 一键离线流程（produce + analyze + subgraph + viewer）

```bash
make offline
```

默认读取 `example/threatgraph.clickhouse.example.yml`，输出：

- `output/offline/iip.jsonl`
- `output/offline/tpg.jsonl`
- `output/offline/incidents.jsonl`
- `output/offline/incident_subgraphs/subgraph_*.jsonl`
- `output/offline/incident_subgraphs/summary.jsonl`
- `output/offline/report.html`

`report.html` 由以下两步生成（与 Ubuntu 侧流程一致）：

1. `python3 tools/build_incident_subgraphs.py`（按 incident 构建子图 JSON）
2. `python3 tools/make_viewer.py`（将子图打包为自包含 HTML）

兼容别名脚本：

- `tools/buildincidentsubgraph.py` -> `tools/build_incident_subgraphs.py`
- `tools/makeviewer.py` -> `tools/make_viewer.py`

常用覆盖参数（按需传入）：

```bash
make offline \
  OFFLINE_CONFIG=threatgraph.yml \
  OFFLINE_OUT_DIR=output/offline_20260320 \
  OFFLINE_INCIDENT_MIN_SEQ=2
```

说明：

- `make offline` 会自动从 `OFFLINE_CONFIG` 读取
  - `threatgraph.output.clickhouse.(url/database/table)`（用于 subgraph 构建）
  - `threatgraph.input.elasticsearch.(url/username/password/index/ca_cert_path)`（用于 viewer 进程元数据补全）

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

离线最小必填只需要两段：

- `threatgraph.input.elasticsearch.since/until`
- `threatgraph.output.clickhouse.(url/database/table)`

### 最小配置片段（离线 ES -> ClickHouse）

只保留必填：`ES 查询范围 + ClickHouse 连接`（`host_prefilter` 建议保持 `true`）。

```yaml
threatgraph:
  input:
    mode: elasticsearch
    elasticsearch:
      url: https://127.0.0.1:9200
      index: edr-offline-ls-*
      since: 2026-03-04T00:00:00Z
      until: 2026-03-05T00:00:00Z
      host_prefilter: true
  output:
    mode: clickhouse
    clickhouse:
      url: http://127.0.0.1:8123
      database: threatgraph
      table: adjacency
```

---

## Elasticsearch 查询机制（回答“是否有固定配置文件”）

有。`produce` 支持两种入口：

1. `threatgraph.input.elasticsearch.query`：直接使用你提供的完整查询模板
2. `threatgraph.input.elasticsearch.since/until`：程序自动生成默认查询模板（包含 notice/non-notice 三段 should 逻辑）

实现细节（`internal/input/elasticsearch/consumer.go`）：

1. 若查询缺少 `size/sort`，自动注入：
   - `size = batch_size`
   - `sort = ["_doc"]`
2. 若设置 `slices > 1`，自动注入 ES slice 参数。
3. 若 `host_prefilter=true`：
   - Phase 1：基于你的 `query.bool.filter` 发现候选 host，并附加：
     - `exists risk_level`
     - `must_not risk_level=notice`
     - `must_not operation=PortAttack`
     - `cardinality(ext_process_rule_id.keyword) > 1`
   - Phase 2：在原始查询模板上注入 `terms client_id.keyword in [host batch]`
   - 对 non-notice 分支额外注入 `must_not operation=PortAttack`

所以：你可以只配置时间范围；程序会自动补默认查询骨架并做必要注入。

查询骨架示意：

- Phase 1（主机发现）：`query.bool.filter` 继承你的时间范围，并附加 `exists/must_not`，然后做 `composite(client_id.keyword)` 聚合，要求 `distinct_rules > 1`
- Phase 2（主机回拉）：在原始查询 `query.bool.filter` 追加 `terms client_id.keyword`

---

## ClickHouse 表

### 必需表（离线 analyze）

```bash
clickhouse-client --query "CREATE DATABASE IF NOT EXISTS threatgraph"
clickhouse-client < migrations/001_adjacency.sql
```

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
  --adjacency-table adjacency \
  --output output/offline/iip.jsonl \
  --tactical-output output/offline/tpg.jsonl \
  --incident-output output/offline/incidents.jsonl \
  --incident-min-seq 2
```

注意：

- `--source=clickhouse` 必须提供 `--config`。
- `--since/--until` 可选；未传时会回退读取 `input.elasticsearch.since/until`。
- 至少要给 `--tactical-output` 或 `--incident-output` 之一。

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
- `output.clickhouse.format` 仅邻接写入支持 `json_each_row` / `row_binary`；IOA 写入固定 `JSONEachRow`。

---

## 相关文档

- `docs/detection_principles.md`
- `docs/rapsheet_replication.md`
- `docs/produce_min_metadata_checklist.md`
- `docs/offline_edr_adjacency_mapping.md`
- `docs/es_offline_edr_to_adjacency_mapping.md`
- `docs/adjacency_table_schema.md`
