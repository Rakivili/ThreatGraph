# ThreatGraph

ThreatGraph 是一个面向 Sysmon 的图安全分析引擎，采用双进程职责拆分：

- `produce`：并发消费日志，规则打标，写原始邻接图与状态索引
- `analyze`：基于原始图做 `IIP -> TPG -> Killchain 评分 -> Incident`

论文复刻说明：`docs/rapsheet_replication.md`

## 运行模型

### Process 1: produce

`produce` 负责实时数据入口和基础构图，不做最终 incident 判定。

数据流：

1) Redis list (`BLPOP`) 取消息
2) 解析 Sysmon JSON（主要使用 `winlog.event_data`）
3) Sigma 规则匹配，命中后给边打 IOA 标签
4) 映射为邻接表行（append-only）
5) 输出邻接表（JSONL 或 HTTP）
6) 可选输出 IOA 事件（JSONL 或 ClickHouse）
7) 可选落盘原始消息（重放用）
8) 可选更新 Redis `vertex_state`（给 analyze 增量分析用）

### Process 2: analyze

`analyze` 统一执行分析链路：

1) 从邻接表读取图数据（可按 state-mode 做 host/time window 裁剪）
2) 构建 IIP 子图（时间约束反向判定 + `can_reach_alert` 裁剪）
3) 从 IIP 子图构建 TPG（时间链 + 同路径因果补边）
4) 在 TPG 上做 DAG DP 评分（长度优先、分数次优）
5) 生成 incident 输出

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

# 进程1：实时构图
./bin/threatgraph produce

# 进程2：离线/一次性分析
./bin/threatgraph analyze \
  --input output/adjacency.jsonl \
  --output output/iip_graphs.jsonl \
  --tactical-output output/tactical_scored_tpg.jsonl \
  --incident-output output/incidents.jsonl
```

`produce` 默认读取 `threatgraph.yml`（当前目录或可执行文件目录），也可显式传入配置路径：

```bash
./bin/threatgraph produce path/to/threatgraph.yml
```

示例配置：

- `example/threatgraph.example.yml`
- `example/threatgraph.clickhouse.example.yml`

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
- 复杂条件（如 `1 of` / `all of` / pattern 扩展）
- 非 windows/sysmon 数据源

## Analyze 用法

### 一次性分析

```bash
./bin/threatgraph analyze \
  --input output/adjacency.jsonl \
  --output output/iip_graphs.jsonl \
  --tactical-output output/tactical_scored_tpg.jsonl \
  --incident-output output/incidents.jsonl
```

### 周期增量分析（state-mode）

```bash
./bin/threatgraph analyze --state-mode \
  --input output/adjacency.jsonl \
  --output output/iip_graphs.jsonl \
  --tactical-output output/tactical_scored_tpg.jsonl \
  --incident-output output/incidents.jsonl \
  --state-redis-addr 127.0.0.1:6379 \
  --state-key-prefix threatgraph:vertex_state \
  --poll-interval 30s \
  --lookback 5m
```

注意：`analyze` 运行时至少需要指定 `--tactical-output` 或 `--incident-output` 之一。

常用参数：

- `--output`：IIP graph JSONL 输出
- `--tactical-output`：TPG + 评分输出
- `--incident-output`：incident 输出
- `--incident-min-seq`：incident 最小序列长度阈值（默认 `2`）
- `--state-mode`：启用 Redis 顶点状态轮询
- `--state-redis-addr` / `--state-redis-db` / `--state-key-prefix`
- `--poll-interval` / `--lookback` / `--once`

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

### vertex_state（analyze 增量入口）

```yaml
threatgraph:
  vertex_state:
    enabled: true
    redis:
      addr: 127.0.0.1:6379
      password: ""
      db: 0
    key_prefix: threatgraph:vertex_state
    scan_interval: 30s
    lookback: 5m
```

## ClickHouse 建表（IOA）

```bash
clickhouse-client --query "CREATE DATABASE IF NOT EXISTS threatgraph"

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
```

## 可视化

脚本：`tools/visualize_adjacency.py`

```bash
python tools/visualize_adjacency.py \
  --input output/adjacency.jsonl \
  --render simple-svg \
  --layout tree \
  --rankdir TB \
  --proc-name TelegramInstaller.exe
```
