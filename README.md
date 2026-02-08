# ThreatGraph

ThreatGraph 是一个云端图构建器。它从 Redis 队列消费 Sysmon 事件（Winlogbeat -> Logstash），将事件转换为可追加写入（append-only）的邻接表行，便于存储与检测。

## 数据流

1) Redis list 队列（BLPOP）取消息
2) 解析 JSON -> 标准化事件（**仅使用 `winlog.event_data`**）
3) IOA 标注钩子（当前为空）
4) 映射为邻接表行（有向 + 带时间）
5) 输出 JSONL 或 HTTP

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

- **Event ID 1 (ProcessCreate)**
  - `ProcessVertex(proc)`
  - `ParentOfEdge(parent -> child)`
  - `ImageOfEdge(path -> proc)`（只写边，不创建文件节点）

- **Event ID 11 (FileCreate)**
  - `FilePathVertex(path)`
  - `CreatedFileEdge(proc -> path)`
  - 当前不生成哈希节点（Sysmon 文件事件无哈希）

- **Event ID 7 (ImageLoad)**
  - `ImageLoadEdge(proc -> path)`（仅写边，不创建文件节点）

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

## 检测逻辑

IOA 标签挂在**进程节点**上（ProcessVertex 的追加记录），核心检测模型为：

- 从根进程出发遍历有向图
- 以 `ts` 为序（用 `record_id` 作为同刻度的 tie-break）
- 在“时间一致路径”上匹配 IOA 标签序列（以节点序列为主）

这相当于 **DAG 上的标签路径匹配**，并带时间约束。可选的“告警评分”会对时间窗内的 IOA 密度进行聚合。

## 设计要点

- Redis list 消费（BLPOP）
- IOA 引擎钩子（当前为空）
- 邻接表 append-only 输出（JSONL/HTTP）
- 可选子图告警（IOA 密度评分）

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
./bin/threatgraph
```

默认读取 `threatgraph.yml`（当前目录或可执行文件目录）。可传入路径参数指定配置文件。

示例配置：`example/threatgraph.yml`

## 可视化工具（Python）

脚本位置：`tools/visualize_adjacency.py`

常用用法：

```
python tools/visualize_adjacency.py --input output/adjacency.jsonl --render simple-svg --layout tree --rankdir TB --proc-name TelegramInstaller.exe
```

常见参数：

- `--proc-name <name>`：以指定进程为根构建子图
- `--layout tree`：树形布局（根在上，向下生长）
- `--edge-label text|hover|none`：边标签显示方式（默认 text）
- `--edge-curve <n>`：曲线强度，0 表示直线
- `--no-legend`：关闭图例
