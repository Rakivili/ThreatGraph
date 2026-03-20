#!/usr/bin/env python3
"""
Build temporal subgraphs for each incident from ClickHouse adjacency data.

For each incident:
  1. Start from the IIP root vertex at iip_ts
  2. Forward temporal BFS to expand the subgraph
  3. Prune: keep only edges/paths that have at least one IOA edge on the path

Input:
  --incidents  Path to incidents JSONL (default: output/incidents_ch_full_20260304_v4.jsonl)
  --iip        Path to IIP JSONL (default: output/iip_ch_full_20260304_v4.jsonl)
  --ch-url     ClickHouse HTTP URL (default: http://127.0.0.1:8123)
  --ch-db      ClickHouse database (default: threatgraph)
  --ch-table   ClickHouse adjacency table (default: adjacency_offline_full_20260304)
  --out-dir    Output directory (default: output/incident_subgraphs)

Output:
  <out-dir>/subgraph_<host>_<root_hash>.jsonl  - adjacency JSONL per incident (visualize_adjacency.py compatible)
  <out-dir>/summary.jsonl                       - summary of all incidents
"""

import argparse
import hashlib
import json
import os
import sys
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--incidents", default="output/incidents_ch_full_20260304_v5.jsonl")
    p.add_argument("--iip", default="output/iip_ch_full_20260304_v5.jsonl")
    p.add_argument("--ch-url", default="http://127.0.0.1:8123")
    p.add_argument("--ch-db", default="threatgraph")
    p.add_argument("--ch-table", default="adjacency_offline_full_20260304_v5")
    p.add_argument("--out-dir", default="output/incident_subgraphs")
    return p.parse_args()


# ---------------------------------------------------------------------------
# ClickHouse query helper
# ---------------------------------------------------------------------------

def ch_query(url, sql):
    """Execute SQL against ClickHouse HTTP API, return list of dicts (JSONEachRow)."""
    encoded = urllib.parse.quote(sql)
    req_url = f"{url}/?query={encoded}"
    with urllib.request.urlopen(req_url, timeout=120) as resp:
        body = resp.read().decode("utf-8")
    rows = []
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        rows.append(json.loads(line))
    return rows


# ---------------------------------------------------------------------------
# Timestamp helpers (ClickHouse returns "YYYY-MM-DD HH:MM:SS.mmm")
# ---------------------------------------------------------------------------

def parse_ts(ts_str):
    """Return float epoch. Returns None on failure."""
    if ts_str is None:
        return None
    if isinstance(ts_str, (int, float)):
        return float(ts_str)
    s = str(ts_str).strip()
    # Try ClickHouse format: "2026-03-04 15:08:57.924"
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            pass
    # Try ISO8601
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except ValueError:
        pass
    return None


def parse_iip_ts(ts_str):
    """Parse iip_ts from incident JSONL (ISO8601 with offset like +08:00)."""
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# IOA helpers
# ---------------------------------------------------------------------------

def normalize_ioa_tags(row):
    tags = row.get("ioa_tags")
    if isinstance(tags, list):
        return row
    if isinstance(tags, str):
        raw = tags.strip()
        if not raw or raw == "[]":
            row["ioa_tags"] = []
        else:
            try:
                decoded = json.loads(raw)
                row["ioa_tags"] = decoded if isinstance(decoded, list) else []
            except Exception:
                row["ioa_tags"] = []
    else:
        row["ioa_tags"] = []
    return row


def edge_has_ioa(row):
    tags = row.get("ioa_tags")
    return isinstance(tags, list) and len(tags) > 0


# ---------------------------------------------------------------------------
# Edge key / time key helpers
# ---------------------------------------------------------------------------

def edge_key(row):
    return (row.get("vertex_id"), row.get("adjacent_id"), row.get("type"))


def edge_time_key(row):
    ts = parse_ts(row.get("ts"))
    try:
        rid = int(row.get("record_id", "").split("-{")[-1].rstrip("}"), 16) if row.get("record_id") else None
    except Exception:
        rid = None
    if ts is None and rid is None:
        return None
    return (ts, rid)


def time_ge(edge_time, ref_time):
    """edge_time >= ref_time (temporally)."""
    if ref_time is None or edge_time is None:
        return True
    et, _ = edge_time
    rt, _ = ref_time
    if et is None or rt is None:
        return True
    return et >= rt


def time_le(edge_time, ref_time):
    """edge_time <= ref_time (temporally)."""
    if ref_time is None or edge_time is None:
        return True
    et, _ = edge_time
    rt, _ = ref_time
    if et is None or rt is None:
        return True
    return et <= rt


def should_update_forward(old_time, new_time):
    """Return True if new_time is earlier than old_time (better arrival)."""
    if old_time is None:
        return False
    if new_time is None:
        return True
    ot = old_time[0]
    nt = new_time[0]
    if nt is None or ot is None:
        return False
    return nt < ot


def should_update_reverse(old_time, new_time):
    """Return True if new_time is later than old_time."""
    if old_time is None:
        return False
    if new_time is None:
        return True
    ot = old_time[0]
    nt = new_time[0]
    if nt is None or ot is None:
        return False
    return nt > ot


# ---------------------------------------------------------------------------
# Temporal traversal (ported from visualize_adjacency.py)
# ---------------------------------------------------------------------------

def traverse_forward(edges_by_src, seeds):
    """BFS forward in time from seed nodes. Returns (visited_nodes, selected_edge_keys)."""
    visited = set()
    best_time = {}
    selected = set()
    queue = list(seeds)

    for node, t in seeds:
        if node:
            visited.add(node)
            best_time[node] = t

    while queue:
        src, src_time = queue.pop(0)
        for row in edges_by_src.get(src, []):
            dst = row.get("adjacent_id")
            if not dst:
                continue
            edge_time = edge_time_key(row)
            if not time_ge(edge_time, src_time):
                continue
            selected.add(edge_key(row))
            next_time = edge_time if edge_time is not None else src_time
            if dst not in best_time:
                best_time[dst] = next_time
                visited.add(dst)
                queue.append((dst, next_time))
            elif should_update_forward(best_time[dst], next_time):
                best_time[dst] = next_time
                queue.append((dst, next_time))

    return visited, selected


def traverse_reverse(edges_by_dst, seeds):
    """BFS backward in time from seed nodes. Returns (visited_nodes, selected_edge_keys)."""
    visited = set()
    best_time = {}
    selected = set()
    queue = list(seeds)

    for node, t in seeds:
        if node:
            visited.add(node)
            best_time[node] = t

    while queue:
        dst, dst_time = queue.pop(0)
        for row in edges_by_dst.get(dst, []):
            src = row.get("vertex_id")
            if not src:
                continue
            edge_time = edge_time_key(row)
            if not time_le(edge_time, dst_time):
                continue
            selected.add(edge_key(row))
            next_time = edge_time if edge_time is not None else dst_time
            if src not in best_time:
                best_time[src] = next_time
                visited.add(src)
                queue.append((src, next_time))
            elif should_update_reverse(best_time[src], next_time):
                best_time[src] = next_time
                queue.append((src, next_time))

    return visited, selected


# ---------------------------------------------------------------------------
# Subgraph building and IOA pruning
# ---------------------------------------------------------------------------

def build_subgraph_from_root(all_edges, all_edges_by_key, root, start_ts_epoch):
    """
    Forward temporal BFS from root, starting at start_ts_epoch.
    Returns list of edge dicts in the subgraph.
    """
    edges_by_src = defaultdict(list)
    for row in all_edges:
        src = row.get("vertex_id")
        if src:
            edges_by_src[src].append(row)

    # Sort edges by time for determinism
    for src in edges_by_src:
        edges_by_src[src].sort(key=lambda r: (parse_ts(r.get("ts")) or 0,))

    seed_time = (start_ts_epoch, None) if start_ts_epoch is not None else None
    _, selected_keys = traverse_forward(edges_by_src, [(root, seed_time)])

    return [row for row in all_edges if edge_key(row) in selected_keys]


def prune_ioa_paths(subgraph_edges):
    """
    Keep only edges that lie on a path with at least one IOA edge.

    Algorithm:
      1. Identify IOA edges
      2. From each IOA edge's src, reverse BFS (back toward root) → pre_keys
      3. From each IOA edge's dst, forward BFS → post_keys
      4. Keep: pre_keys ∪ ioa_keys ∪ post_keys
    """
    ioa_edges = [row for row in subgraph_edges if edge_has_ioa(row)]
    if not ioa_edges:
        return []  # no IOA edges → prune everything

    edges_by_src = defaultdict(list)
    edges_by_dst = defaultdict(list)
    for row in subgraph_edges:
        src = row.get("vertex_id")
        dst = row.get("adjacent_id")
        if src:
            edges_by_src[src].append(row)
        if dst:
            edges_by_dst[dst].append(row)

    pre_seeds = []
    post_seeds = []
    ioa_keys = set()
    for row in ioa_edges:
        t = edge_time_key(row)
        ioa_keys.add(edge_key(row))
        if row.get("vertex_id"):
            pre_seeds.append((row["vertex_id"], t))
        if row.get("adjacent_id"):
            post_seeds.append((row["adjacent_id"], t))

    _, pre_keys = traverse_reverse(edges_by_dst, pre_seeds)
    _, post_keys = traverse_forward(edges_by_src, post_seeds)

    keep_keys = pre_keys | post_keys | ioa_keys

    seen = set()
    result = []
    for row in subgraph_edges:
        k = edge_key(row)
        if k in keep_keys and k not in seen:
            seen.add(k)
            result.append(row)
    return result


# ---------------------------------------------------------------------------
# Load incidents (deduplicated)
# ---------------------------------------------------------------------------

def load_incidents(path):
    """Load and deduplicate incidents by (host, root). Returns list of dicts."""
    seen = set()
    incidents = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            key = (row.get("host"), row.get("root"))
            if key in seen:
                continue
            seen.add(key)
            incidents.append(row)
    return incidents


# ---------------------------------------------------------------------------
# Load per-host adjacency data from ClickHouse
# ---------------------------------------------------------------------------

def load_host_adjacency(ch_url, ch_db, ch_table, hosts):
    """
    Query ClickHouse for all adjacency rows (vertices + edges) for the given hosts.
    Returns dict: host -> {"vertices": {vertex_id: row}, "edges": [row, ...]}
    """
    host_list = ", ".join(f"'{h}'" for h in hosts)
    sql = (
        f"SELECT ts, record_type, type, vertex_id, adjacent_id, "
        f"event_id, host, agent_id, record_id, ioa_tags "
        f"FROM {ch_db}.{ch_table} "
        f"WHERE agent_id IN ({host_list}) "
        f"ORDER BY agent_id, ts "
        f"FORMAT JSONEachRow"
    )
    print(f"[*] Querying ClickHouse: {ch_db}.{ch_table} for {len(hosts)} hosts...", flush=True)
    rows = ch_query(ch_url, sql)
    print(f"[*] Received {len(rows)} rows", flush=True)

    result = defaultdict(lambda: {"vertices": {}, "edges": []})
    for row in rows:
        normalize_ioa_tags(row)
        host = row.get("agent_id") or row.get("host")
        if not host:
            continue
        if row.get("record_type") == "vertex":
            vid = row.get("vertex_id")
            if vid:
                result[host]["vertices"][vid] = row
        elif row.get("record_type") == "edge":
            result[host]["edges"].append(row)

    return result


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def safe_filename(s, max_len=40):
    """Make a string safe for use as a filename component."""
    out = []
    for c in s:
        if c.isalnum() or c in "-_":
            out.append(c)
        else:
            out.append("_")
    result = "".join(out)
    if len(result) > max_len:
        result = result[:max_len]
    return result


def incident_out_path(out_dir, incident):
    host = incident.get("host", "unknown")
    root = incident.get("root", "")
    root_hash = hashlib.md5(root.encode()).hexdigest()[:8]
    fname = f"subgraph_{host[:16]}_{root_hash}.jsonl"
    return os.path.join(out_dir, fname)


def write_subgraph(path, incident, pruned_edges, vertex_meta):
    """Write adjacency JSONL compatible with visualize_adjacency.py."""
    # Collect all vertex IDs referenced
    vertex_ids = set()
    for row in pruned_edges:
        if row.get("vertex_id"):
            vertex_ids.add(row["vertex_id"])
        if row.get("adjacent_id"):
            vertex_ids.add(row["adjacent_id"])

    with open(path, "w", encoding="utf-8") as f:
        # Write a comment-style header as a JSON record
        header = {
            "record_type": "_incident_meta",
            "host": incident.get("host"),
            "root": incident.get("root"),
            "iip_ts": incident.get("iip_ts"),
            "severity": incident.get("severity"),
            "risk_product": incident.get("risk_product"),
            "alert_count": incident.get("alert_count"),
            "tactic_coverage": incident.get("tactic_coverage"),
            "subgraph_edge_count": len(pruned_edges),
            "ioa_edge_count": sum(1 for e in pruned_edges if edge_has_ioa(e)),
        }
        f.write(json.dumps(header, ensure_ascii=False) + "\n")

        # Write vertex rows (from ClickHouse meta, or synthetic)
        for vid in sorted(vertex_ids):
            if vid in vertex_meta:
                f.write(json.dumps(vertex_meta[vid], ensure_ascii=False) + "\n")
            else:
                f.write(json.dumps({
                    "record_type": "vertex",
                    "vertex_id": vid,
                    "type": vid.split(":", 1)[0] if ":" in vid else "unknown",
                }, ensure_ascii=False) + "\n")

        # Write edge rows (ioa_tags as list, not string)
        for row in pruned_edges:
            out_row = dict(row)
            # Ensure ioa_tags is a list for output
            if isinstance(out_row.get("ioa_tags"), str):
                try:
                    out_row["ioa_tags"] = json.loads(out_row["ioa_tags"])
                except Exception:
                    out_row["ioa_tags"] = []
            f.write(json.dumps(out_row, ensure_ascii=False) + "\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    # 1. Load incidents (deduplicated)
    print(f"[*] Loading incidents from {args.incidents}", flush=True)
    incidents = load_incidents(args.incidents)
    print(f"[*] {len(incidents)} unique incidents", flush=True)
    for inc in incidents:
        print(f"    host={inc['host'][:16]}  root={inc['root'][:60]}  severity={inc.get('severity')}", flush=True)

    # 2. Get unique hosts
    hosts = list({inc["host"] for inc in incidents})
    print(f"[*] Unique hosts: {hosts}", flush=True)

    # 3. Load adjacency data for all hosts
    host_data = load_host_adjacency(args.ch_url, args.ch_db, args.ch_table, hosts)

    # 4. Process each incident
    summary = []
    for inc in incidents:
        host = inc["host"]
        root = inc["root"]
        iip_ts = inc.get("iip_ts")
        start_ts = parse_iip_ts(iip_ts)

        data = host_data.get(host, {"vertices": {}, "edges": []})
        all_edges = data["edges"]
        vertex_meta = data["vertices"]

        print(f"\n[*] Incident: host={host[:16]}  root={root[:60]}", flush=True)
        print(f"    iip_ts={iip_ts}  all_edges={len(all_edges)}  vertices={len(vertex_meta)}", flush=True)

        # 4a. Build temporal subgraph from root
        subgraph = build_subgraph_from_root(all_edges, {}, root, start_ts)
        print(f"    subgraph edges after forward BFS: {len(subgraph)}", flush=True)

        # 4b. Prune: keep only paths with at least one IOA edge
        pruned = prune_ioa_paths(subgraph)
        ioa_count = sum(1 for e in pruned if edge_has_ioa(e))
        print(f"    pruned edges: {len(pruned)}  (IOA edges: {ioa_count})", flush=True)

        # 4c. Write output
        out_path = incident_out_path(args.out_dir, inc)
        write_subgraph(out_path, inc, pruned, vertex_meta)
        print(f"    -> {out_path}", flush=True)

        summary.append({
            "host": host,
            "root": root,
            "iip_ts": iip_ts,
            "severity": inc.get("severity"),
            "risk_product": inc.get("risk_product"),
            "alert_count": inc.get("alert_count"),
            "total_host_edges": len(all_edges),
            "subgraph_edges_raw": len(subgraph),
            "subgraph_edges_pruned": len(pruned),
            "ioa_edges": ioa_count,
            "output_file": os.path.basename(out_path),
        })

    # 5. Write summary
    summary_path = os.path.join(args.out_dir, "summary.jsonl")
    with open(summary_path, "w", encoding="utf-8") as f:
        for row in summary:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"\n[*] Summary written to {summary_path}", flush=True)
    print("[*] Done.", flush=True)


if __name__ == "__main__":
    main()
