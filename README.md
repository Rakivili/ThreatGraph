# ThreatGraph

ThreatGraph 是一个云端图构建器。它从 Redis 队列消费 Sysmon 事件（Winlogbeat -> Logstash），将事件转换为可追加写入（append-only）的邻接表行，便于存储与检测。

论文复刻说明文档：`docs/rapsheet_replication.md`

## 数据流

1) Redis list 队列（BLPOP）取消息
2) 解析 JSON -> 标准化事件（**仅使用 `winlog.event_data`**）
3) Sigma 规则引擎给事件打 IOA 标签
4) 映射为邻接表行（有向 + 带时间）
5) 输出邻接表（JSONL 或 HTTP）
6) （可选）输出 IOA 时序事件（JSONL 或 ClickHouse）
7) （可选）落盘原始队列消息用于重放测试

## 图模型（有向）

节点（vertex_id 前缀）：

- `proc:` 进程实例（ProcessGuid）
- `path:` 文件路径
- `net:` 网络端点（ip:port）
- `domain:` 域名

边是有向且带时间戳（`ts`）。整体是一个“时间有向无环图”（time-respecting paths），便于做序列检测。

邻接表 JSONL（每行一条）：

```
{
  "ts": "2026-02-07T16:52:53.853Z",
  "record_type": "vertex",
  "type": "ProcessVertex",
  "vertex_id": "proc:host:{guid}",
  "event_id": 1,
  "host": "host",
  "agent_id": "agent",
  "record_id": "13075",
  "data": {"image": "C:\\Path\\proc.exe"},
  "ioa_tags": [{"id": "IOA-001", "name": "sample"}]
}
```

## 事件 -> 图 映射

只使用 `winlog.event_data` 字段。若缺失会记录告警并跳过。

`ts` 仅使用 Sysmon `UtcTime`（事件真实发生时间）；若 `UtcTime` 缺失或解析失败，则该事件不写入邻接表并记录 ERROR 日志。

- **Event ID 1 (ProcessCreate)**
  - `ProcessVertex(proc)`
  - `ParentOfEdge(parent -> child)`
  - `ImageOfEdge(path -> proc)`（只写边，不创建文件节点）

- **Event ID 11 (FileCreate)**
  - `FilePathVertex(path)`
  - `CreatedFileEdge(proc -> path)`
  - 当前不生成哈希节点（Sysmon 文件事件无哈希）

- **Event ID 7 (ImageLoad)**
  - `ImageLoadEdge(path -> proc)`（仅写边，不创建文件节点）

- **Event ID 3 (NetworkConnect)**
  - `NetworkVertex(net:ip:port)`
  - `ConnectEdge(proc -> net)`

- **Event ID 22 (DNSQuery)**
  - `DomainVertex(domain)`
  - `DNSQueryEdge(proc -> domain)`

- **Event ID 8/10 (CreateRemoteThread/ProcessAccess)**
  - `RemoteThreadEdge(SourceProc -> TargetProc)`
  - `ProcessAccessEdge(SourceProc -> TargetProc)`

> 说明：未列出的事件 **不生成边**。

## 检测逻辑（当前方向）

IOA 标签仅挂在**边**上（edge），未生成边的事件不会产生 IOA 标签。

当前推荐方案（用于大规模环境）不是全图遍历，而是：

- 在线维护 `vertex_state`（按 `host + vertex_id`）
- 状态里维护 `earliest_upstream_alert_ts`、`ioa_count` 等可增量更新字段
- 周期性任务只处理新增告警相关顶点，从原始图中产出 IIP 子图

这是一种“状态索引 + 局部回溯”的工程实现，用于避免全量遍历图。

## 设计要点

- Redis list 消费（BLPOP）
- Sigma 规则驱动的 IOA 标注
- 邻接表 append-only 输出（JSONL/HTTP）
- 顶点状态索引（用于 IIP 裁剪）
- 周期性 IIP 子图产出

## 项目结构

```
threatgraph/
  cmd/threatgraph/          # CLI 入口
  config/                   # YAML 配置
  internal/input/redis/     # Redis list 消费
  internal/graph/adjacency/ # 事件 -> 邻接表映射
  internal/output/          # 邻接表 JSON/HTTP 输出
  internal/pipeline/        # Redis -> IOA -> 邻接表 -> 输出
  pkg/models/               # Event + adjacency 模型
```

## 运行

```
make
./bin/threatgraph produce
```

启用 Sigma 规则（单事件）示例：

```yaml
threatgraph:
  rules:
    enabled: true
    path: ./rules/sigma
```

说明：启动时会预加载并校验规则，只加载“单事件 + 简单条件”规则；以下规则会被自动跳过：

- 使用聚合（count/max/min/sum/avg）
- 使用 timeframe 的相关规则
- 复杂条件（如 `1 of ...` / `all of ...` / pattern 展开）
- 非 Sysmon/Windows 数据源规则

默认读取 `threatgraph.yml`（当前目录或可执行文件目录）。可传入路径参数指定配置文件：`./bin/threatgraph produce path/to/threatgraph.yml`。

示例配置：

- 本地文件输出：`example/threatgraph.example.yml`
- ClickHouse 输出：`example/threatgraph.clickhouse.example.yml`

## 低成本 10w 终端模式

推荐开启两阶段：

1) `produce` 阶段输出轻量 IOA 时序事件（`name/ts/host/src/dst`）
2) `analyze` 阶段先做序列候选，再做图连通验证

可选地，`analyze` 可以输出战术评分结果（IIP/TPG + kill-chain 序列评分）用于优先级排序。

这比直接全图遍历更省 CPU 和内存。

### IOA 输出配置

`threatgraph.yml` 中新增：

```yaml
threatgraph:
  ioa:
    enabled: true
    output:
      mode: file # file | clickhouse
      file:
        path: output/ioa_events.jsonl
      clickhouse:
        url: http://127.0.0.1:8123
        database: threatgraph
        table: ioa_events
        username: default
        password: ""
        timeout: 5s
```

### 原始消息重放落盘配置

如果你要做基于历史 Sysmon JSON 的重放测试，可开启原始消息捕获：

```yaml
threatgraph:
  replay_capture:
    enabled: true
    file:
      path: output/raw_events.jsonl
    batch_size: 1000
    flush_interval: 2s
```

说明：

- 写入内容是从消息队列取出的原始 JSON（一行一条）
- 该文件可直接作为后续 replay 输入
- 默认使用追加写入，便于长期采样与回放

### ClickHouse（非 Docker）建库建表

先确保 ClickHouse 服务已启动（HTTP 默认端口 `8123`）。

方式 A：使用 `clickhouse-client`（推荐）

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

方式 B：使用 HTTP API（`curl`）

```bash
curl -sS "http://127.0.0.1:8123/?query=CREATE%20DATABASE%20IF%20NOT%20EXISTS%20threatgraph"

curl -sS "http://127.0.0.1:8123/" --data-binary @- <<'SQL'
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
TTL ts + INTERVAL 14 DAY;
SQL
```

建好后可用下面命令快速验证：

```bash
curl -sS "http://127.0.0.1:8123/?query=SELECT%20count()%20FROM%20threatgraph.ioa_events"
```

## IIP 产出（推荐）

生产环境推荐流程：

1) `produce` 持续写入 append-only 邻接边
2) 同步维护顶点状态表（`vertex_state`）
3) 周期任务按“新增告警相关顶点”产出 IIP 子图

其中 IIP 判定依赖 `vertex_state` 的最早上游告警时间索引，避免对原始图做全量回溯。

建议状态字段：

- `host`
- `vertex_id`
- `earliest_upstream_alert_ts`
- `ioa_count`
- `updated_at`

## 离线 analyze（实验/过渡）

`analyze` 仍保留，主要用于离线实验与回放验证，不建议作为 10w 端规模的主路径。

能力包括：

- 两阶段候选 + 连通验证
- 基于 IIP/TPG 的战术评分输出（`--tactical-output`）
- 按边 `name` 的有序序列匹配

```bash
./bin/threatgraph analyze --input output/adjacency.jsonl --output output/ioa_findings.jsonl

# 输出战术评分结果（TPG 排序，实验）
./bin/threatgraph analyze --input output/adjacency.jsonl --output output/ioa_findings.jsonl --tactical-output output/tactical_scored_tpg.jsonl

# 按边 name 做序列匹配（示例）
./bin/threatgraph analyze --input output/adjacency.jsonl --output output/ioa_findings.jsonl --name-seq "SuspiciousTool,NetworkConnect.SuspiciousPath"

# 使用规则文件做两阶段（候选+连通验证）检测
./bin/threatgraph analyze --input output/adjacency.jsonl --rules-file example/sequence_rules.yml --candidates-output output/ioa_candidates.jsonl --output output/ioa_findings.jsonl
```

可选参数：

- `--max-depth`：每个根进程的最大遍历深度（默认 `64`）
- `--max-findings`：最多输出命中条数（默认 `10000`）
- `--name-seq`：按顺序匹配边 name 的逗号序列（例如 `A,B,C`）
- `--rules-file`：规则 YAML 文件（两阶段检测）
- `--candidates-output`：候选序列输出路径（可选）
- `--tactical-output`：输出 IIP/TPG 战术评分 JSONL（可选）

规则文件支持 `composites`：可把多个小序列规则按时间顺序组合成一条更长攻击链，再做图连通验证。`composites.max_depth` 可设为 `-1` 表示不限制跳数。

## 可视化工具（Python）

脚本位置：`tools/visualize_adjacency.py`

常用用法：

```
python tools/visualize_adjacency.py --input output/adjacency.jsonl --render simple-svg --layout tree --rankdir TB --proc-name TelegramInstaller.exe

# 绘制 analyze 输出的已验证子图（finding JSONL）
python tools/visualize_adjacency.py --input output/ioa_findings.jsonl --input-kind finding --finding-index 0 --render simple-svg --image output/finding_0.svg --layout tree --rankdir TB
```

常见参数：

- `--proc-name <name>`：以指定进程为根构建子图
- `--input-kind auto|adjacency|finding`：输入类型（默认 auto 自动识别）
- `--finding-index <n>`：仅绘制第 n 条 finding（默认 -1，绘制全部）
- `--layout tree`：树形布局（根在上，向下生长）
- `--edge-label text|hover|none`：边标签显示方式（默认 text）
- `--edge-curve <n>`：曲线强度，0 表示直线
- `--no-legend`：关闭图例
