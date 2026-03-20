# Offline EDR 邻接表映射说明（当前实现）

本文档记录当前 `ThreatGraph/internal/graph/adjacency/mapper.go` 的已实现事件类型与字段映射。

> 适用范围：离线 EDR 数据（当前优先走 `event.Lookup`，必要时 fallback 到 `event.Fields/event.Raw`）与 Sysmon 事件（`event.EventID`）

---

## 1. Host Key（顶点命名中的 host 维度）

当前 `pickHost(event)` 规则：

1. 优先 `Raw["client_id"]`
2. 其次 `event.AgentID`
3. 最后 `event.Hostname`

因此 `proc:/path:` 顶点 ID 默认会按 `client_id` 分桶（若存在）。

---

## 2. 邻接表语义

- 每条 `record_type = edge` 的邻接记录，**一定有两个顶点**：
  - `vertex_id`
  - `adjacent_id`
- 语义上统一读作：
  - `vertex_id -> adjacent_id`

当前 mapper 里实际会产出的顶点类型有：

- `ProcessVertex`
- `FilePathVertex`
- `RegistryKeyVertex`
- `RegistryValueVertex`
- `NetworkVertex`
- `DomainVertex`

### 2.1 顶点 key 生成规则

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

## 3. 离线 EDR 路径判定

若 `event.Lookup["risk_level"]`（或 fallback 字段）存在，则进入离线 EDR 映射：

- `risk_level == notice`
  - 仅处理 `operation == CreateProcess AND fltrname == CommonCreateProcess`
  - 以及 `operation == WriteComplete AND fltrname == WriteNewFile.ExcuteFile`
  - 其它 notice 事件直接忽略（不产邻接）
- `risk_level != notice`
  - 走 non-notice 映射

---

## 4. notice + CreateProcess 映射

处理以下 notice 子类型：

- `operation = CreateProcess AND fltrname = CommonCreateProcess`
- `operation = WriteComplete AND fltrname = WriteNewFile.ExcuteFile`

### 3.1 主进程链

- 子进程 GUID：`ProcessGuid` / `newprocessuuid` / `new_process_uuid`
- 父（创建者）进程 GUID：`ParentProcessGuid` / `processuuid` / `parent_processuuid`

### 3.2 字段到顶点/边

- 子进程路径：`Image` / `newprocess` / `new_process`
- 子进程命令行：`CommandLine` / `new_command_line` / `newcommandline`
- 父进程路径：`ParentImage` / `process` / `parent_process`
- 父进程命令行：`ParentCommandLine` / `command_line`

### 3.3 产出

- `ParentOfEdge`: `parent_proc -> child_proc`
- `ProcessCPEdge`（若有 `processcpuuid`）: `cp_proc -> creator_proc`
- `RPCTriggerEdge`（若有 `rpcprocessuuid`）: `rpc_proc -> creator_proc`

### 4. notice + WriteNewFile.ExcuteFile

固定字段：

- 主体进程：`processuuid`
- 主体镜像：`process`
- 目标文件：`file`

产出：

- `FileWriteEdge`: `subject_proc -> file_path`
- `ProcessCPEdge`（若有 `processcpuuid`）: `cp_proc -> subject_proc`
- `RPCTriggerEdge`（若有 `rpcprocessuuid`）: `rpc_proc -> subject_proc`

---

## 5. non-notice 映射

### 4.1 主体（subject）

- 主体 GUID：`ProcessGuid` / `processuuid`
- 主体路径：`Image` / `process`
- 主体命令行：`CommandLine` / `command_line`

### 4.2 产出

- `ProcessCPEdge`（仅当 `processcpuuid` 存在）: `cp_proc -> subject_proc`
- `RPCTriggerEdge`（仅当 `rpcprocessuuid` 存在）: `rpc_proc -> subject_proc`

### 4.3 额外约束

- `processcp` / `rpcprocess` **无 UUID 不关联**（不会建 image fallback 边）
- 若 `processuuid == rpcprocessuuid`（忽略大小写、忽略 `{}`）
  - 认为是同一进程
  - **不建立 `RPCTriggerEdge`**

---

## 6. Sysmon EventID 映射（当前）

`Map(event)` 中已支持：

- `1`  -> `mapProcessCreate`
- `3`  -> `mapNetworkConnect`
- `7`  -> `mapImageLoad`
- `8`  -> `mapRemoteThread`
- `10` -> `mapProcessAccess`
- `11` -> `mapFileCreate`
- `22` -> `mapDNSQuery`

> 当前未实现 Sysmon 12/13/14 注册表 EventID 的专门映射。

---

## 7. IOA 标签挂载规则（当前）

默认边会继承 `event.IoaTags`，但以下边类型明确排除：

- 所有 `RPC*` 边（如 `RPCTriggerEdge`）
- 所有 `ProcessCP*` 边（如 `ProcessCPEdge`）

即：`rpc / processcp` 这两类边不挂 IOA。

---

## 8. 备注

- 上述顶点 key 规则适用于当前已实现 mapper。
- 如果后续新增 `NamedPipeVertex` / `ThreadVertex` 等类型，需要同步更新本文档。
- 当前 offline parser 已改为固定字段 envelope + `Lookup map[string]string` 快路径，不再为离线 EDR 主路径构建完整 `Raw map[string]interface{}`；只有 `winlog.event_data` 仍会进入 `event.Fields` 供兼容逻辑使用。
