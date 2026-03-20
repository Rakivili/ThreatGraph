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

## 配置建议（低成本模式 / v9 当前推荐）

```yaml
threatgraph:
  input:
    elasticsearch:
      host_prefilter: true
      host_batch_size: 50
      host_batch_workers: 4
      run_once: true
  graph:
    write_vertex_rows: false
    include_edge_data: false
  pipeline:
    write_workers: 2
    batch_size: 20000
    flush_interval: 5s
  output:
    clickhouse:
      format: row_binary
```

说明：

- `host_prefilter=true`：先发现 infected host，再按 host batch 回拉事件。
- `host_batch_size=50`：每批最多 50 台 host。
- `host_batch_workers=4`：最多 4 个 host batch 并发。
- `run_once=true`：ES 离线回放消费完当前批次后自动退出。
- `write_vertex_rows=false`：仅输出边行，顶点通过 `vertex_id/adjacent_id` 隐式重建。
- `include_edge_data=false`：边上不写整包 Sysmon 字段。
- `write_workers=2`：单个 produce 进程内部开启多个写协程。
- `format=row_binary`：ClickHouse 写入使用 `RowBinary`，替代较慢的 `JSONEachRow`。

当前 `v9` 的 host prefilter 固定规则：

- Phase 1（发现 infected host）
  - `risk_level != notice`
  - `operation != PortAttack`
  - `uniq(ext_process_rule_id.keyword) > 1`

- Phase 2（按 host batch 回拉事件构图）
  - `notice + CreateProcess + CommonCreateProcess`
  - `notice + WriteComplete + WriteNewFile.ExcuteFile`
  - `non-notice + operation != PortAttack`
  - 再叠加 `terms client_id.keyword in [host batch]`

## 与 analyze 兼容性

- `analyze` 的 IIP/TPG 主链路按当前实现仅依赖 edge 行与 `ioa_tags`。

## 上线前检查

- [ ] IOA 标签写入边后不丢失（兼容 Sigma 路径或离线 EDR 告警字段）。
- [ ] `output/adjacency.jsonl` 单行大小显著下降。
- [ ] 同样输入下，`analyze` 仍能产出 IIP/TPG/incident。
- [ ] IOA ClickHouse 行数与命中规则数一致。
- [ ] 若启用 `time_shard_minutes`，确认所有子窗口使用 `[start, end)`，无重叠无漏数。

## 回退策略

若需调试详情，可临时打开：

```yaml
threatgraph:
  graph:
    write_vertex_rows: true
    include_edge_data: true
```

建议仅在短时间排障窗口启用，避免持续高成本。
