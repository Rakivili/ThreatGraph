# ThreatGraph

ThreatGraph 是一个面向 Sysmon 的图安全分析引擎，支持三种运行模式：

- `produce`：并发消费日志、规则打标、写入原始邻接图（JSONL / HTTP / ClickHouse）
- `analyze`：基于本地 JSONL 执行一次性批量分析 `IIP -> TPG -> Killchain 评分 -> Incident`
- `serve`：准实时增量分析——轮询 ClickHouse IOA 表发现活跃主机，按需拉取邻接数据做增量分析并输出 incident

## 项目介绍

ThreatGraph 的设计参考了 RapSheet 论文中的分析思路，并结合实际工程场景实现为可持续运行的检测系统。

核心能力：

- 以 Sysmon 事件构建时序图
- 基于 IOA 证据提取 IIP，并进一步构建 TPG
- 对攻击阶段链路进行评分，输出可追溯的 incident

## 检测思路

ThreatGraph 采用“规则命中 + 图时序分析”联合判断：

- 规则层：Sigma 命中用于标记 IOA 证据边
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

`produce` 负责实时数据入口与基础构图，不做最终 incident 判定。

数据流：

1) Redis list (`BLPOP`) 取消息
2) 解析 Sysmon JSON（主要使用 `winlog.event_data`）
3) Sigma 规则匹配，命中后给边打 IOA 标签
4) 映射为邻接表行（append-only）
5) 输出邻接表（JSONL / HTTP / ClickHouse）
6) 可选输出 IOA 事件（JSONL 或 ClickHouse）
7) 可选落盘原始消息（重放用）

### analyze（批量离线）

`analyze` 从本地 JSONL 执行一次性分析：

1) 从邻接表 JSONL 读取图数据
2) 构建 IIP 子图（时间约束反向判定 + `can_reach_alert` 裁剪）
3) 从 IIP 子图构建 TPG（时间链 + 同路径因果补边）
4) 在 TPG 上做 DAG DP 评分（长度优先、分数次优）
5) 生成 incident 输出

### serve（准实时增量）

`serve` 以常驻进程方式周期性轮询 ClickHouse，实现万级主机规模下的准实时增量分析：

```
[produce --output=clickhouse]  常驻写入
    ├→ ClickHouse adjacency 表
    └→ ClickHouse ioa_events 表

[serve]  每 30s 轮询
    ① SELECT DISTINCT host FROM ioa_events WHERE ts > checkpoint
    ② 对每个 host:
       SELECT * FROM adjacency WHERE host = ? AND ts BETWEEN now()-window AND now()
    ③ BuildIIPGraphs → BuildScoredTPGs → BuildIncidents（复用现有分析链路）
    ④ 输出 incidents（JSONL 或 Webhook）
    ⑤ 更新 checkpoint
```

关键参数（均可配置）：

- `window`：邻接数据回看窗口，默认 15m
- `interval`：轮询间隔，默认 30s
- `workers`：并发主机分析数，默认 4
- `min_seq`：最小 kill-chain 序列长度，默认 2

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

# 进程 2：serve 轮询 ClickHouse 做增量分析
./bin/threatgraph serve example/threatgraph.serve.example.yml
```

`serve` 启动后自动每 30s 轮询一次 IOA 表，发现活跃主机后拉取邻接数据、运行分析链路、输出 incident。

示例配置：

- `example/threatgraph.example.yml` — 纯 JSONL 模式
- `example/threatgraph.clickhouse.example.yml` — IOA 写 ClickHouse
- `example/threatgraph.serve.example.yml` — produce + serve 全 ClickHouse 模式

## Sigma 规则说明

启用示例：

```yaml
threatgraph:
  rules:
    enabled: true
    path: ./rules/sigma
```

当前仅加载“单事件 + 简单条件”规则；以下规则会跳过：

- 聚合（count/max/min/sum/avg）
- timeframe 相关
- 复杂条件（超出 `and/or/not + 简单标识符` 的表达式）
- 非 windows/sysmon 数据源

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
- 建议保留 Sigma 的 `ioa_tags`（边级）用于后续 `analyze` 的 IIP/TPG 构建与评分。

### Serve 模式配置

```yaml
threatgraph:
  serve:
    analyze:
      window: 15m
      interval: 30s
      min_seq: 2
      workers: 4
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
      username: default
      password: ""
      timeout: 5s
```

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
