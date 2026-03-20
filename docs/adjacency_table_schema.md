# Adjacency 邻接表结构说明

本文档说明 ThreatGraph 当前邻接表的两层结构：

1. **逻辑模型**：代码中的 `models.AdjacencyRow`
2. **ClickHouse 落表结构**：当前 writer/reader 实际持久化的列

适用代码路径：

- 逻辑模型：`pkg/models/adjacency.go`
- ClickHouse writer：`internal/output/adjacencyclickhouse/writer.go`
- ClickHouse reader：`internal/input/clickhouse/reader.go`

---

## 1. 逻辑模型：`models.AdjacencyRow`

当前代码中的邻接行结构为：

| 字段 | 类型 | 含义 |
|---|---|---|
| `ts` | `time.Time` | 事件时间 |
| `record_type` | `string` | 记录类型，当前主要是 `vertex` / `edge` |
| `type` | `string` | 顶点类型或边类型 |
| `vertex_id` | `string` | 起点顶点 ID |
| `adjacent_id` | `string` | 终点顶点 ID（仅 `edge` 有意义） |
| `event_id` | `int` | 原始事件 ID |
| `host` | `string` | 主机标识（当前字段名为 `Hostname`，落表列名为 `host`） |
| `agent_id` | `string` | 终端/Agent 标识 |
| `record_id` | `string` | 原始日志记录 ID |
| `data` | `map[string]interface{}` | 顶点/边附加属性（逻辑层） |
| `ioa_tags` | `[]IoaTag` | 挂载在边上的 IOA 标签 |

注意：

- `data` 字段存在于逻辑模型中，但**当前 ClickHouse adjacency writer 不落这个字段**。
- 当 `graph.write_vertex_rows=false` 时，produce 不会输出顶点行，实际落表主要都是 `record_type=edge`。

### 1.1 `models.AdjacencyRow` 与 ClickHouse 列对应关系

当前可以把 `models.AdjacencyRow` 理解成 **ClickHouse adjacency 表的逻辑行模型**。  
实际上一一对应关系如下：

| Go 模型字段 | Go 类型 | ClickHouse 列 | 说明 |
|---|---|---|---|
| `Timestamp` | `time.Time` | `ts` | 事件时间 |
| `RecordType` | `string` | `record_type` | `vertex` / `edge` |
| `Type` | `string` | `type` | 顶点/边类型 |
| `VertexID` | `string` | `vertex_id` | 起点顶点 ID |
| `AdjacentID` | `string` | `adjacent_id` | 终点顶点 ID |
| `EventID` | `int` | `event_id` | 原始事件 ID |
| `Hostname` | `string` | `host` | 主机标识 |
| `AgentID` | `string` | `agent_id` | Agent 标识 |
| `RecordID` | `string` | `record_id` | 原始记录 ID |
| `IoaTags` | `[]IoaTag` | `ioa_tags` | 以 JSON 字符串形式落表 |

唯一的例外是：

| Go 模型字段 | 当前是否落表 | 说明 |
|---|---|---|
| `Data` | 否 | 逻辑层保留，当前 ClickHouse adjacency writer 不写该列 |

所以更准确地说：

- `models.AdjacencyRow` **基本就是** ClickHouse adjacency 表的逻辑模型
- 当前持久化层是 **10 列一一对应**
- 只有 `Data` 还停留在逻辑层，没有进入当前 ClickHouse 表结构

---

## 2. 当前 ClickHouse 实际落表列

当前 `adjacencyclickhouse.Writer` 明确写入以下 10 列：

```sql
INSERT INTO <db>.<table>
  (ts, record_type, type, vertex_id, adjacent_id, event_id, host, agent_id, record_id, ioa_tags)
FORMAT JSONEachRow | RowBinary
```

也就是说，当前邻接表的**持久化列**只有这 10 个，和上面的 `AdjacencyRow` 主字段一一对应：

| 列名 | 含义 | 来源 |
|---|---|---|
| `ts` | 事件时间 | `AdjacencyRow.Timestamp` |
| `record_type` | `vertex` / `edge` | `AdjacencyRow.RecordType` |
| `type` | 顶点/边类型 | `AdjacencyRow.Type` |
| `vertex_id` | 起点顶点 ID | `AdjacencyRow.VertexID` |
| `adjacent_id` | 终点顶点 ID | `AdjacencyRow.AdjacentID` |
| `event_id` | 原始事件 ID | `AdjacencyRow.EventID` |
| `host` | 主机标识 | `AdjacencyRow.Hostname` |
| `agent_id` | Agent 标识 | `AdjacencyRow.AgentID` |
| `record_id` | 原始记录 ID | `AdjacencyRow.RecordID` |
| `ioa_tags` | IOA 标签 JSON 字符串 | `AdjacencyRow.IoaTags` |

### 2.1 `ioa_tags` 的存储形式

当前 ClickHouse 中，`ioa_tags` 以 **JSON 字符串** 形式落表，例如：

```json
[]
```

或：

```json
[{"id":"...","name":"...","severity":"high","tactic":"execution","technique":"..."}]
```

Reader 读取时会把这个 JSON 字符串再反序列化回 `[]models.IoaTag`。

---

## 3. 顶点/边语义

### 3.1 统一方向

邻接表统一按下面的方向理解：

```text
vertex_id -> adjacent_id
```

### 3.2 `record_type`

| 值 | 含义 |
|---|---|
| `vertex` | 顶点行 |
| `edge` | 边行 |

当前生产推荐配置通常为：

```yaml
graph:
  write_vertex_rows: false
```

因此在线上/离线批处理里，ClickHouse 表里大多数记录会是 `edge`。

补充说明：

- `v5` 早期基线配置使用 `write_vertex_rows: true`，因此会把 `ProcessVertex`、`FilePathVertex`、`NetworkVertex` 等顶点也一起落表。
- `v9` 当前稳定基线使用 `write_vertex_rows: false`，因此邻接表主要由 `record_type=edge` 构成。
- 所以 `v5` 与 `v9` 不能直接按“总行数”横比；更公平的比较口径是：
  - 只比较 `edge rows`
  - 或比较 `incident/root/score`

---

## 4. 常见顶点类型

当前文档与实现中常见的顶点 ID 形式如下：

| 顶点类型 | 示例 |
|---|---|
| 进程 | `proc:{host}:{guid}` |
| 文件路径 | `path:{host}:{path}` |
| 注册表键 | `regkey:{host}:{key}` |
| 注册表值 | `regval:{host}:{key}|{value}` |
| 网络 | `net:{ip}` / `net:{ip}:{port}` |
| 域名 | `domain:{domain}` |

---

## 5. 常见边类型

当前实现里常见的边包括但不限于：

- `ParentOfEdge`
- `ProcessCPEdge`
- `RPCTriggerEdge`
- `FileWriteEdge`
- `FileAccessEdge`
- `ImageLoadEdge`
- `TargetProcessEdge`
- `RegistryKeyEdge`
- `RegistrySetValueEdge`
- `ConnectEdge`
- `DNSQueryEdge`

这些边的字段来源和语义，请结合：

- `docs/offline_edr_adjacency_mapping.md`
- `docs/es_offline_edr_to_adjacency_mapping.md`

一起看。

---

## 6. 当前与历史实现的区别

### 6.1 `data` 不落 ClickHouse

虽然 `models.AdjacencyRow` 仍保留 `Data` 字段，但当前 ClickHouse writer 没有写这一列。

这意味着：

- 逻辑层仍然可以构造 `Data`
- 但落到 ClickHouse adjacency 表后，当前 `analyze` 依赖的是：
  - `ts`
  - `record_type`
  - `type`
  - `vertex_id`
  - `adjacent_id`
  - `host`
  - `record_id`
  - `ioa_tags`

### 6.2 writer 支持两种格式

当前 ClickHouse writer 支持：

- `json_each_row`
- `row_binary`

推荐生产配置：

```yaml
output:
  clickhouse:
    format: row_binary
```

这是为了降低 produce 写入开销；**不会影响 analyze 读取兼容性**，因为 analyze 读的是落表后的列，而不是当初的写入格式。

---

## 7. 与 analyze 的关系

当前 `analyze --source clickhouse` 读取邻接表时，实际只依赖以下落表列：

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

因此：

- 只要这 10 列语义不变
- produce 的写入格式（`JSONEachRow` / `RowBinary`）可以自由替换
- analyze 不需要同步修改逻辑
