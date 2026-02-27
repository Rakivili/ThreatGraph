# Produce 最小元信息清单

目标：只在 `produce` 阶段保留 IIP/TPG 所需最小信息，降低落盘、I/O 与内存压力。

## 必保字段（edge）

- `ts`
- `record_type=edge`
- `type`
- `vertex_id`
- `adjacent_id`
- `host` / `agent_id`
- `record_id`
- `ioa_tags`（尤其 `name`, `severity`, `tactic`, `technique`）

## 可去除字段（默认建议）

- edge 上完整 Sysmon `fields`（`data.fields`）
- vertex 富属性（image/path/user/command_line/hashes...）
- 非必要的 replay 原始消息

## 配置建议（低成本模式）

```yaml
threatgraph:
  graph:
    write_vertex_rows: false
    include_edge_data: false
```

说明：

- `write_vertex_rows=false`：仅输出边行，顶点通过 `vertex_id/adjacent_id` 隐式重建。
- `include_edge_data=false`：边上不写整包 Sysmon 字段。

## 与 analyze 兼容性

- `analyze` 的 IIP/TPG 主链路按当前实现仅依赖 edge 行与 `ioa_tags`。
- `adjacency-analyzer` 的 `name-seq` 已兼容优先读取 `ioa_tags.name`。

## 上线前检查

- [ ] Sigma 规则命中时，边上 `ioa_tags` 不丢失。
- [ ] `output/adjacency.jsonl` 单行大小显著下降。
- [ ] 同样输入下，`analyze` 仍能产出 IIP/TPG/incident。
- [ ] IOA ClickHouse 行数与命中规则数一致。

## 回退策略

若需调试详情，可临时打开：

```yaml
threatgraph:
  graph:
    write_vertex_rows: true
    include_edge_data: true
```

建议仅在短时间排障窗口启用，避免持续高成本。
