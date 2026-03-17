# ES Offline EDR -> Adjacency 映射说明

本文档记录当前 `produce` 在 `input.mode=elasticsearch` 下，如何将 ES 中的离线 EDR 日志映射为 ThreatGraph 邻接表。

适用场景：

- 输入索引：`edr-offline-ls-*`
- 输入来源：离线 EDR 导出日志导入 Elasticsearch 后的 `_source`
- 使用目标：`threatgraph produce` 直接从 ES 读取并写入邻接表

---

## 1. 输入过滤口径

当前离线 EDR 映射只处理两类日志：

1. `risk_level = notice AND operation = CreateProcess AND fltrname = CommonCreateProcess`
2. `risk_level = notice AND operation = WriteComplete AND fltrname = WriteNewFile.ExcuteFile`
3. `risk_level != notice`

额外规则：

- `risk_level != notice` 且 `operation = PortAttack`：直接忽略，不产邻接

---

## 2. Host 维度（顶点命名）

顶点 ID 中的 host key 使用优先级如下：

1. `client_id`
2. `agent.id / agent_id`
3. `hostname`

因此进程/文件路径等顶点默认按 `client_id` 分桶。

---

## 3. 邻接表语义

- 每条 `record_type = edge` 的邻接记录，**一定有两个顶点**：
  - `vertex_id`
  - `adjacent_id`
- 统一按 `vertex_id -> adjacent_id` 理解边方向。

当前 ES -> adjacency 路径下会实际产出的顶点类型有：

- `ProcessVertex`
- `FilePathVertex`
- `RegistryKeyVertex`
- `RegistryValueVertex`
- `NetworkVertex`
- `DomainVertex`

### 3.1 顶点 key 生成规则

| 顶点类型 | key 生成规则 |
|---|---|
| `ProcessVertex` | `proc:{host_key}:{guid}` |
| `FilePathVertex` | `path:{host_key}:{path}` |
| `RegistryKeyVertex` | `regkey:{host_key}:{keyname}` |
| `RegistryValueVertex` | `regval:{host_key}:{keyname}|{valuename}` |
| `NetworkVertex` | `net:{ip}` 或 `net:{ip}:{port}` |
| `DomainVertex` | `domain:{domain}` |

其中：

- `host_key` = `client_id`（优先） / `AgentID` / `Hostname`
- `guid / path / keyname / valuename / domain / ip` 都按当前 mapper 的规则转为小写后入 key

---

## 4. 时间与基础字段映射

| ES 字段 | ThreatGraph 字段 |
|---|---|
| `@timestamp` | `event.Timestamp` |
| `client_id` | `event.AgentID`（兜底输入身份） |
| `ext_detection_id` / `@hash` / `rm_log_uuid` | `event.RecordID` |
| `_source` 原文 | `event.Raw` |

离线 EDR 生成 `IoaTag` 时：

| ES 字段 | IoaTag 字段 |
|---|---|
| `ext_process_rule_id` | `IoaTag.ID` |
| `alert_name`（空则 `name_key`） | `IoaTag.Name` |
| `risk_level` | `IoaTag.Severity` |
| `attack.tactic` | `IoaTag.Tactic` |
| `attack.technique` | `IoaTag.Technique` |

---

## 5. notice 事件映射

### 4.1 notice + CreateProcess

只处理 `operation = CreateProcess AND fltrname = CommonCreateProcess`。

#### 字段映射

| ES 字段 | 含义 | 邻接用途 |
|---|---|---|
| `processuuid` / `parent_processuuid` | 创建者进程 GUID | 父进程 |
| `newprocessuuid` | 新进程 GUID | 子进程 |
| `process` / `parent_process` | 创建者进程镜像路径 | 父进程 data |
| `newprocess` / `new_process` | 子进程镜像路径 | 子进程 image |
| `command_line` | 创建者命令行 | 父进程 data |
| `new_command_line` | 子进程命令行 | 子进程 data |

#### 产出边/顶点

- `ParentOfEdge`: `creator_proc -> child_proc`
- `ProcessCPEdge`: `processcpuuid -> child_proc`（仅当 `processcpuuid` 存在）
- `RPCTriggerEdge`: `rpcprocessuuid -> creator_proc`（仅当 `rpcprocessuuid` 存在且与主体不同）

### 4.2 notice + WriteNewFile.ExcuteFile

只处理 `operation = WriteComplete AND fltrname.keyword = WriteNewFile.ExcuteFile`。

#### 固定字段

| ES 字段 | 邻接用途 |
|---|---|
| `processuuid` | 主体进程 |
| `process` | 主体镜像路径 |
| `file` | 目标文件路径 |
| `processcpuuid` | 可选 ProcessCP 因果来源 |
| `rpcprocessuuid` | 可选 RPC 因果来源 |

#### 产出边

- `FileWriteEdge`: `subject_proc -> file_path`
- `ProcessCPEdge`: `processcpuuid -> subject_proc`（仅当 `processcpuuid` 存在）
- `RPCTriggerEdge`: `rpcprocessuuid -> subject_proc`（仅当 `rpcprocessuuid` 存在且与主体不同）

---

## 6. non-notice 事件映射

non-notice 事件默认以：

- `processuuid` 作为主体进程 GUID
- `process` 作为主体镜像路径

然后按 object 字段补充 subject->object 建模。

### 5.1 因果边（额外进程）

| 字段 | 条件 | 边 |
|---|---|---|
| `processcpuuid` | 存在时 | `ProcessCPEdge`: `cp_proc -> subject_proc` |
| `rpcprocessuuid` | 存在且不等于 `processuuid` | `RPCTriggerEdge`: `rpc_proc -> subject_proc` |

约束：

- `processcp/rpcprocess` **无 UUID 不关联**
- 若 `processuuid == rpcprocessuuid`（忽略大小写和 `{}`），则不建 `RPCTriggerEdge`
- `ProcessCPEdge` / `RPCTriggerEdge` 的 `ts` 始终取自当前这条原始日志本身的时间（即当前 event 的 `@timestamp`）

### 5.2 subject -> subject

| ES 字段 | 边 |
|---|---|
| `targetprocessuuid` / `TargetProcessGuid` | `TargetProcessEdge`: `subject_proc -> target_proc` |

`targetprocess` 仅用于目标进程顶点 data。

对于 `DS0009.Process.Modification` 中的特殊检测：

- `fltrname = ObOpenProcess`
- `fltrname = ShellcodeExecute`
- `fltrname = Hollowing`

固定规则：

- `ObOpenProcess`：无论日志里是否存在 `targetprocessuuid`，都强制使用 `objectuuid` 作为 `targetprocessuuid`，并使用 `object` 作为目标进程镜像路径
- `fltrname = ShellcodeExecute`
- `fltrname = Hollowing`

无论日志里是否存在 `targetprocessuuid`，都强制使用 `processuuid` 作为 `targetprocessuuid`。

对于 `DS0009.Process.Modification` 中的：

- `fltrname = CreateRemoteThread`

当前按固定规则处理：

- `targetprocessuuid` 视为必有字段
- 若缺失，则按脏数据跳过，不做 fallback

### 5.3 subject -> file

| ES 字段 | 边 |
|---|---|
| `file` / `filepath` / `filename` | `FileAccessEdge`: `subject_proc -> file_path` |

### 5.4 module -> subject

模块类对象按你的约束使用：

- `ImageLoadEdge`: `module_path -> subject_proc`

字段来源：

| ES 字段 |
|---|
| `newimage` |
| `moduleilpath` |
| `modulename` |

### 5.5 subject -> registry

| 条件 | 边 |
|---|---|
| `keyname` 存在，且 `valuename` 存在 | `RegistrySetValueEdge`: `subject_proc -> reg_value` |
| 仅 `keyname` 存在 | `RegistryKeyEdge`: `subject_proc -> reg_key` |

#### 顶点规则

- `RegistryKeyVertex`: `regkey:{host}:{keyname}`
- `RegistryValueVertex`: `regval:{host}:{keyname}|{valuename}`

#### 相关字段

| ES 字段 | 用途 |
|---|---|
| `keyname` / `registry_path` / `reg_path` | 注册表键 |
| `valuename` / `value_name` | 注册表值名 |
| `valuetype` | 值类型（写入 data） |

### 5.6 subject -> network

| ES 字段 | 边 |
|---|---|
| `remoteip` / `DestinationIp` / `dstip` + `remoteport` / `DestinationPort` / `dstport` | `ConnectEdge`: `subject_proc -> net:ip:port` |

---

## 7. 不挂 IOA 的边类型

以下边类型不会继承 `event.IoaTags`：

- `RPC*`
- `ProcessCP*`

也就是：

- `rpc` 类边
- `processcp` 类边

都不挂 IOA 信息。

---

## 8. 当前已忽略或未建模项

- `PortAttack`（non-notice）直接忽略
- 其它 notice 事件（除 `CreateProcess`）当前不建模
- 当前 `IOAEvent` 落表仍偏少，因为很多告警边本身不挂 IOA，后续可再讨论是否需要对 object 边补策略

---

## 9. 主要代码位置

- `config/config.go`
- `cmd/threatgraph/main.go`
- `internal/input/elasticsearch/consumer.go`
- `internal/transform/sysmon/parser.go`
- `internal/graph/adjacency/mapper.go`
- `internal/pipeline/adjacency_redis_pipeline.go`
