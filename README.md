# ThreatGraph

ThreatGraph 是一个面向 Sysmon / 离线 EDR 数据集的图安全分析引擎，支持三种运行模式：

- `produce`：并发消费日志、规则打标、写入原始邻接图（JSONL / HTTP / ClickHouse）
- `analyze`：基于本地 JSONL 或 ClickHouse 邻接表执行一次性批量分析 `IIP -> TPG -> Killchain 评分 -> Incident`
- `serve`：准实时增量分析——轮询 ClickHouse IOA 表发现活跃主机，按需拉取邻接数据做增量分析并输出 incident

## 项目介绍

ThreatGraph 的设计参考了 RapSheet 论文中的分析思路，并结合实际工程场景实现为可持续运行的检测系统。

核心能力：

- 以 Sysmon 事件构建时序图
- 基于 IOA 证据提取 IIP，并进一步构建 TPG
- 对攻击阶段链路进行评分，输出可追溯的 incident

## 检测思路

ThreatGraph 采用“规则命中 + 图时序分析”联合判断：

- 规则层：IOA 标签用于标记证据边（兼容路径可来自 Sigma 或离线 EDR 告警字段）
- 图层：在时间约束和可达关系下还原攻击路径
- 输出层：以 root、关键 IOA、TPG 序列为核心给出 incident 结果

核心原则：

- 证据优先：先保留规则命中证据，再做图级关联与裁剪
- 时序约束：仅保留满足时间一致性的传播路径
- 因果约束：关注可达关系与阶段衔接，避免孤立事件误判
- 可解释性优先：Incident 必须能回溯到 root、关键 IOA 与关键路径
- 工程可运行：允许规则层存在一定噪声，但通过路径裁剪、阶段评分与上下文聚合控制误报，并在吞吐与存储受限场景下保持持续分析能力

简而言之：规则回答“看到了什么”，图分析回答“这些行为是否构成同一条攻击链”。

论文复刻说明：`docs/rapsheet_replication.md`

Produce 压缩清单：`docs/produce_min_metadata_checklist.md`

## 运行模型

### produce

`produce` 负责基础构图，不做最终 incident 判定。当前主路径已经不是 Redis 实时流，而是**离线 ES 数据集回扫**。

数据流：

1) 从 Redis 或 Elasticsearch 取消息（当前离线主路径通常是 Elasticsearch）
2) 解析事件并规范化为 `Event`
3) 对离线 EDR 优先走固定字段 envelope + `Lookup map[string]string` 快路径
4) 对离线 EDR 直接使用事件自带的告警字段生成 IOA 标签
5) 映射为邻接表行（append-only）
6) 输出邻接表（JSONL / HTTP / ClickHouse）
7) 可选输出 IOA 事件（JSONL 或 ClickHouse）
8) 可选落盘原始消息（重放用）

说明：

- `SameParentDir` 由 `dirname(Image)` 与 `dirname(ImageLoaded)` 比较得到（忽略大小写）
- 在保留的兼容路径里，仍可使用 `SameParentDir: true` 约束同目录侧加载场景
- 对离线 ES 数据集，当前推荐固定主键来源：
  - `ts = @timestamp`
  - `host = client_id`
  - `agent_id = client_id`
  - `record_id = ext_detection_id`
- 当前 `v9` 离线 ES 主路径默认**不再经过 Sigma 引擎**。IOA 标签直接来自事件字段：
  - `risk_level`
  - `alert_name` / `name_key`
  - `ext_process_rule_id`
  - `attack.tactic`
  - `attack.technique`

#### v9 固定查询规则

当前 `v9` 的 `produce` 已经固定为两阶段：

1. **发现 infected hosts**
   - 时间窗内
   - `risk_level != notice`
   - `operation != PortAttack`
   - `uniq(ext_process_rule_id.keyword) > 1`
   - 聚合 `unique client_id.keyword`

2. **按 host batch 回拉事件构图**
   - 只对第一阶段发现的 host 回拉
   - 事件条件固定为：
     - `notice + CreateProcess + CommonCreateProcess`
     - `notice + WriteComplete + WriteNewFile.ExcuteFile`
     - `non-notice + operation != PortAttack`
     - 再叠加 `terms client_id.keyword in [host batch]`

### analyze（批量离线）

`analyze` 从本地 JSONL 或 ClickHouse 执行一次性分析：

1) 从邻接表 JSONL 或 ClickHouse 表读取图数据
2) 构建 IIP 子图（时间约束反向判定 + `can_reach_alert` 裁剪）
3) 从 IIP 子图构建 TPG（时间链 + 同路径因果补边）
4) 在 TPG 上做 DAG DP 评分（长度优先、分数次优）
5) 生成 incident 输出

### serve（准实时增量）

`serve` 以常驻进程方式做 IOA 微批处理（micro-batch），并按需拉取邻接窗口数据做验证分析：

```
[produce --output=clickhouse]  常驻写入
    ├→ ClickHouse adjacency 表
    └→ ClickHouse ioa_events 表

[serve]  每 interval 触发一次
    ① 读取一批未处理 IOA（按 ts + record_id 游标）
    ② 按 host 聚合本批 IOA，计算每个 host 的分析窗口
    ③ SELECT * FROM adjacency WHERE host = ? AND ts BETWEEN host_min_ts-window AND now()
    ④ BuildIIPGraphs → BuildScoredTPGs → BuildIncidents（复用现有分析链路）
    ⑤ 若某个 IIP 子图覆盖了同批其他 IOA，则这些 IOA 直接视为已处理（不再重复计算）
    ⑥ 将已覆盖 IOA 写入 ioa_processed（避免后续批次重复计算）
    ⑦ 输出 incidents（JSONL 或 Webhook），推进游标
```

关键参数（均可配置）：

- `window`：邻接数据回看窗口，默认 2h
- `interval`：处理周期，默认 30s
- `batch_size`：每批 IOA 数量，默认 1000
- `workers`：并发主机分析数，默认 4
- `min_seq`：最小 kill-chain 序列长度，默认 2
- `adjacency_table` / `ioa_table` / `processed_table`：ClickHouse 表名

同一 host 的同一批 IOA 会做“子图覆盖去重”：某个 IOA 已被先前计算出的 IIP 子图覆盖时，本批内后续不再重复作为 seed 计算。

`serve` 日志中的关键批次指标：

- `batch_ioa`：该 host 在当前微批内的 IOA 条数
- `covered_ioa` / `coverage`：本批 IOA 被 IIP 覆盖并标记 processed 的条数/比例
- `batch_iips`：本批 IOA 实际映射到的 IIP root 数
- `window_iips`：当前分析窗口（`window`）内构建出的 IIP 总数（历史上下文）
- `backward` / `forward`：IIP 构建阶段的回溯/前向遍历次数

注意：`window_iips` 不是“本批次 IIP 数”，它通常会大于 `batch_ioa`。

IIP 回溯的核心加速来自分析运行时从原始边派生的反向邻接索引。
事实来源始终是 append-only 邻接表。

## 图模型

顶点（`vertex_id` 前缀）：

- `proc:` 进程实例
- `path:` 文件路径
- `net:` 网络端点（ip:port）
- `domain:` 域名

边为有向边，带 `ts`。分析时按时间约束构造 time-respecting paths。

## 快速开始

```bash
make
```

### 离线模式（JSONL）

```bash
# 实时构图
./bin/threatgraph produce threatgraph.yml

# 一次性分析
./bin/threatgraph analyze \
  --input output/adjacency.min.jsonl \
  --output output/iip_graphs.latest.jsonl \
  --tactical-output output/scored_tpg.latest.jsonl \
  --incident-output output/incidents.latest.min2.jsonl \
  --incident-min-seq 2
```

### 准实时模式（ClickHouse，推荐）

```bash
# 进程 1：produce 写入 ClickHouse
./bin/threatgraph produce example/threatgraph.serve.example.yml

# 进程 2：serve 按 IOA 微批增量分析
./bin/threatgraph serve example/threatgraph.serve.example.yml
```

`serve` 启动后按 interval 拉取一批未处理 IOA（`ts+record_id` 游标），按 host 聚合后拉邻接窗口并运行分析链路，最后写入 incident 与已处理标记。

当 `serve.incident.mode=file` 时，会在同目录额外维护两份 analyze 兼容快照：

- `incidents.latest.min2.jsonl`（当前增量状态下的 incident 快照）
- `scored_tpg.latest.jsonl`（当前增量状态下的 scored TPG 快照）

这样 Flask 等消费端可以直接复用 analyze 时代的文件名，不需要再额外跑一次离线 analyze。

示例配置：

- `example/threatgraph.example.yml` — 纯 JSONL 模式
- `example/threatgraph.clickhouse.example.yml` — IOA 写 ClickHouse
- `example/threatgraph.serve.example.yml` — produce + serve 全 ClickHouse 模式

## Sigma 规则说明（历史/兼容路径）

启用示例：

```yaml
threatgraph:
  rules:
    enabled: true
    path: ./rules/sigma
```

当前仅在保留的兼容路径中加载“单事件 + 简单条件”规则；离线 ES `v9` 主路径默认不再依赖 Sigma。以下规则会跳过：

- 聚合（count/max/min/sum/avg）
- timeframe 相关
- 复杂条件（超出 `and/or/not + 简单标识符` 的表达式）
- 非 windows/sysmon 数据源

另外，当前引擎不支持在规则条件里做“字段对字段计算比较”（例如直接比较 `dirname(Image)` 与 `dirname(ImageLoaded)`）。
这类需求应在 `produce` 阶段先补充派生字段，再由规则匹配该派生字段。

## Analyze 用法（批量离线）

```bash
./bin/threatgraph analyze \
  --input output/adjacency.min.jsonl \
  --output output/iip_graphs.latest.jsonl \
  --tactical-output output/scored_tpg.latest.jsonl \
  --incident-output output/incidents.latest.min2.jsonl \
  --incident-min-seq 2
```

注意：`analyze` 运行时至少需要指定 `--tactical-output` 或 `--incident-output` 之一。

常用参数：

- `--output`：IIP graph JSONL 输出
- `--tactical-output`：TPG + 评分输出
- `--incident-output`：incident 输出
- `--incident-min-seq`：incident 最小序列长度阈值（默认 `2`）

对于万级主机或需要持续运行的场景，推荐使用 `serve` 子命令替代手动循环调用 `analyze`。

## Incident 深度提取（TPG 详情）

`serve` 输出的 incident 是 SOC 归并摘要，不包含完整 TPG 顶点/时间线。可使用内置命令按 incident 反查邻接窗口并重建 IIP/TPG：

```bash
./bin/threatgraph explain-incident \
  --config threatgraph.ubuntu.yml \
  --incident-file output/incidents.serve.jsonl \
  --index -1 \
  --out output/incident_explain.latest.json
```

输出文件包含：

- `incident`：原始 incident 摘要
- `iip`：匹配到的 IIP 子图（`alert_events` + `edges`）
- `tpg`：重建后的 TPG（`vertices` + `sequence_edges`）
- `score`：当前评分结果（sequence/risk/tactic coverage）
- `timeline`：按时间展开的 IOA 顶点序列（含规则名、tactic、technique）

## 关键配置片段

### IOA 输出

```yaml
threatgraph:
  ioa:
    enabled: true
    output:
      mode: file # file | clickhouse
      file:
        path: output/ioa_events.jsonl
```

### 原始消息重放落盘

```yaml
threatgraph:
  replay_capture:
    enabled: true
    file:
      path: output/raw_events.jsonl
    batch_size: 1000
  flush_interval: 2s
```

### 低成本原始图模式（推荐）

```yaml
threatgraph:
  graph:
    write_vertex_rows: true
    include_edge_data: false
```

- `write_vertex_rows=true`：保留顶点基础元信息（用于 incident root 与子图详情展示）。
- `include_edge_data=false`：不在边上写入完整 Sysmon 字段，显著降低落盘体积。
- 建议保留边级 `ioa_tags`（无论来源于 Sigma 兼容路径或离线 EDR 告警字段）用于后续 `analyze` 的 IIP/TPG 构建与评分。

### Serve 模式配置

```yaml
threatgraph:
  serve:
    analyze:
      window: 2h
      interval: 30s
      batch_size: 1000
      min_seq: 2
      workers: 4
      adjacency_table: adjacency
      ioa_table: ioa_events
      processed_table: ioa_processed
      clickhouse:
        url: http://127.0.0.1:8123
        database: threatgraph
    incident:
      mode: file   # file | http
      file:
        path: output/incidents.jsonl
```

### 邻接表输出到 ClickHouse

```yaml
threatgraph:
  output:
    mode: clickhouse
    clickhouse:
      url: http://127.0.0.1:8123
      database: threatgraph
      table: adjacency
      format: row_binary
      username: default
      password: ""
      timeout: 5s
```

`format` 支持：

- `json_each_row`：兼容模式，直观但较慢
- `row_binary`：当前推荐，吞吐更高

### 离线 ES -> ClickHouse（当前主路径）

当前离线回放推荐配置：

```yaml
threatgraph:
  input:
    mode: elasticsearch
    elasticsearch:
      host_prefilter: true
      host_batch_size: 50
      host_batch_workers: 4
      run_once: true
  pipeline:
    write_workers: 2
    batch_size: 20000
    flush_interval: 5s
  graph:
    write_vertex_rows: false
    include_edge_data: false
  output:
    clickhouse:
      format: row_binary
```

含义：

- `host_prefilter=true`：先发现 infected host，再按 host batch 回拉事件
- `host_batch_size=50`：每批最多 50 台 host
- `host_batch_workers=4`：最多 4 个 batch 并发
- `write_vertex_rows=false`：只写 edge 行，减少邻接表膨胀
- `format=row_binary`：ClickHouse 写入使用 `RowBinary`

## 傻瓜版：produce / analyze / HTML 怎么跑

下面假设你已经有：

- Elasticsearch 离线数据集：`edr-offline-ls-*`
- ClickHouse：`http://127.0.0.1:8123`
- 配置文件：`config_full_v9.yml`

### 1. 先跑 produce

```bash
./bin/threatgraph produce config_full_v9.yml
```

它会做两阶段处理：

1. 先找 infected host
2. 再按 host batch 回拉事件并写入 ClickHouse 邻接表

默认输出表：

- `threatgraph.adjacency_offline_full_20260304_v9`

### 2. 再跑 analyze

```bash
./bin/threatgraph analyze \
  --source clickhouse \
  --config threatgraph.ubuntu.yml \
  --adjacency-table adjacency_offline_full_20260304_v9 \
  --since 2026-03-04T00:00:00Z \
  --until 2026-03-05T00:00:00Z \
  --output output/iip_ch_full_20260304_v9.jsonl \
  --tactical-output output/tpg_ch_full_20260304_v9.jsonl \
  --incident-output output/incidents_ch_full_20260304_v9.jsonl \
  --incident-min-seq 2
```

会生成：

- `output/iip_ch_full_20260304_v9.jsonl`
- `output/tpg_ch_full_20260304_v9.jsonl`
- `output/incidents_ch_full_20260304_v9.jsonl`

### 3. 最后生成 HTML viewer

先生成每个 incident 的子图：

```bash
python3 tools/build_incident_subgraphs.py \
  --incidents output/incidents_ch_full_20260304_v9.jsonl \
  --iip output/iip_ch_full_20260304_v9.jsonl \
  --ch-url http://127.0.0.1:8123 \
  --ch-db threatgraph \
  --ch-table adjacency_offline_full_20260304_v9 \
  --out-dir output/incident_subgraphs_v9
```

再生成 HTML：

```bash
python3 tools/make_viewer.py \
  --all-in-dir output/incident_subgraphs_v9 \
  --out output/viewer_v9.html \
  --es-url https://127.0.0.1:9200 \
  --es-user elastic \
  --es-pass <PASSWORD> \
  --es-ca /home/ubuntu/elasticsearch-8.15.0/config/certs/http_ca.crt \
  --es-index edr-offline-ls-*
```

最终产物：

- `output/viewer_v9.html`

如果在本地打开，建议用简单 HTTP 服务，不要直接双击 `file://`：

```bash
python -m http.server 8000
```

然后浏览器打开：

- `http://127.0.0.1:8000/viewer_v9.html`

## ClickHouse 建表

```bash
clickhouse-client --query "CREATE DATABASE IF NOT EXISTS threatgraph"

# IOA 事件表
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

# 邻接表（serve 模式必需）
clickhouse-client < migrations/001_adjacency.sql

# 已处理 IOA 映射表（serve 去重与增量必需）
clickhouse-client --query "
CREATE TABLE IF NOT EXISTS threatgraph.ioa_processed (
  ts DateTime64(3),
  host String,
  record_id String,
  name String,
  iip_root String,
  iip_ts DateTime64(3),
  processed_at DateTime64(3)
)
ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (host, ts, name, record_id)
TTL ts + INTERVAL 14 DAY
"
```

## 可视化

脚本：`tools/visualize_adjacency.py`

```bash
python tools/visualize_adjacency.py \
  --input output/adjacency.min.jsonl \
  --render simple-svg \
  --layout tree \
  --rankdir TB \
  --focus 'proc:host:{guid}' \
  --start-ts '2026-02-27T15:43:02.066Z'
```

## Incident 页面（Flask）

```bash
TG_PORT=5050 python3 tools/incident_viewer_flask.py
```

默认读取以下文件（可用环境变量覆盖）：

- `output/incidents.latest.min2.jsonl`
- `output/scored_tpg.latest.jsonl`
- `output/adjacency.min.jsonl`

访问：`http://127.0.0.1:5050/`

页面支持：

- Incident 详情（Root + IOA 顶点上下文）
- TPG 规则/ATT&CK 聚合、TPG 顶点与序列边
- 基于 root 的 IIP 子图 SVG（可强制刷新）

## 离线 ES 主路径（当前推荐）

当前离线回放推荐路径如下：

1. `produce` 从 `edr-offline-ls-*` 读取离线 EDR 数据集
2. 使用 `time_shard_minutes + time_shard_workers` 按时间窗口切任务
3. 并发写入 ClickHouse adjacency 表
4. 再使用 `analyze --source clickhouse` 从邻接表读取并生成 `IIP / TPG / incident`

对离线 ES 数据集，当前推荐固定主键来源：

- `ts = @timestamp`
- `host = client_id`
- `agent_id = client_id`
- `record_id = ext_detection_id`

推荐配置片段：

```yaml
threatgraph:
  input:
    mode: elasticsearch
    elasticsearch:
      run_once: true
      time_shard_minutes: 30
      time_shard_workers: 4
  pipeline:
    write_workers: 2
    batch_size: 20000
    flush_interval: 5s
  graph:
    write_vertex_rows: false
    include_edge_data: false
  output:
    mode: clickhouse
    clickhouse:
      format: row_binary
```

说明：

- `time_shard_minutes=30`：把大时间范围切成 30 分钟窗口任务
- `time_shard_workers=4`：父进程最多同时拉起 4 个子进程抢占窗口任务
- `write_workers=2`：单个 produce 进程内部开启多个写协程
- `write_vertex_rows=false`：仅写 edge 行，减少邻接表膨胀
- `format=row_binary`：ClickHouse 写入采用 `RowBinary`

## 离线数据集已测性能（当前基线）

以下数字来自 `192.168.120.134` 上对 `2026-03-04` 离线 EDR 数据集的实测。

### produce 基线（v5）

- ES 命中：`10,291,175` 条
- 邻接表行数：`49,223,796` 条
- 总耗时：`3254s`（约 `54.2 分钟`）

### produce 优化试验（2 分钟采样）

- `v7`（4 slices，同表，`write_workers=1`）
  - `789,696 rows / 2 min`
  - `95,895 uniq(record_id) / 2 min`
- `v7`（4 slices，同表，`write_workers=2`）
  - `864,722 rows / 2 min`
  - `105,356 uniq(record_id) / 2 min`
- `v8`（4 个 6 小时时间分片，同表）
  - `1,094,823 rows / 2 min`
  - `148,350 uniq(record_id) / 2 min`
- `v8`（30 分钟窗口任务队列，4 worker，同表）
  - `1,581,494 rows / 2 min`
  - `282,927 uniq(record_id) / 2 min`

### analyze 基线（v5）

- 输入表：`adjacency_offline_full_20260304_v5`
- 表总行数：`49,223,796`
- 表磁盘占用：`348.72 MiB`
- 实际参与 analyze 的 host：`85`
- 总耗时：`25.84s`
- 平均每台 host：`0.304s`
- 峰值 RSS：`130,064 KB`（约 `127 MiB`）
