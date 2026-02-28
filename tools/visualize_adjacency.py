import argparse
import json
import os
import subprocess
import sys
import math
import random
from datetime import datetime
from typing import Dict, Optional


def parse_args():
    parser = argparse.ArgumentParser(
        description="Visualize adjacency JSONL as Graphviz DOT"
    )
    parser.add_argument(
        "--input",
        default="output/adjacency.jsonl",
        help="Path to adjacency JSONL (default: output/adjacency.jsonl)",
    )
    parser.add_argument(
        "--input-kind",
        choices=["auto", "adjacency", "finding"],
        default="auto",
        help="Input record kind (default: auto)",
    )
    parser.add_argument(
        "--finding-index",
        type=int,
        default=-1,
        help="Use only the Nth finding from finding JSONL (default: -1, all)",
    )
    parser.add_argument(
        "--finding-input",
        default="",
        help="Findings JSONL to seed roots (e.g. output/ioa_findings.jsonl)",
    )
    parser.add_argument(
        "--dot",
        default="output/adjacency.dot",
        help="Path to output DOT file (default: output/adjacency.dot)",
    )
    parser.add_argument(
        "--json-out",
        default="",
        help="Optional path to write structured subgraph JSON",
    )
    parser.add_argument(
        "--render",
        choices=["none", "svg", "png", "simple-svg"],
        default="none",
        help="Render DOT with graphviz (default: none)",
    )
    parser.add_argument(
        "--image",
        default="",
        help="Output image path when --render is set",
    )
    parser.add_argument(
        "--layout",
        choices=["force", "circle", "layered", "tree", "time"],
        default="force",
        help="Layout for simple-svg (default: force)",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=200,
        help="Force layout iterations (default: 200)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=7,
        help="Random seed for layouts (default: 7)",
    )
    parser.add_argument(
        "--layer-edge",
        default="ParentOfEdge",
        help="Comma-separated edge types for layered layout (default: ParentOfEdge)",
    )
    parser.add_argument(
        "--rankdir",
        choices=["TB", "LR"],
        default="TB",
        help="Layer direction for layered layout (default: TB)",
    )
    parser.add_argument(
        "--layer-gap",
        type=int,
        default=180,
        help="Layer gap for layered layout (default: 180)",
    )
    parser.add_argument(
        "--node-gap",
        type=int,
        default=200,
        help="Node gap within a layer (default: 200)",
    )
    parser.add_argument(
        "--node-padding",
        type=int,
        default=28,
        help="Minimum padding between nodes (default: 28)",
    )
    parser.add_argument(
        "--edge-types",
        default="",
        help="Comma-separated edge types to include (default: all)",
    )
    parser.add_argument(
        "--through-edge",
        default="",
        help=(
            "Comma-separated edge types; keep edges on paths that pass through these types"
        ),
    )
    parser.add_argument(
        "--vertex-types",
        default="proc,file,net",
        help="Comma-separated vertex types to include (default: proc,file,net)",
    )
    parser.add_argument(
        "--proc-name",
        default="",
        help="Root process image name (substring match)",
    )
    parser.add_argument(
        "--edge-label",
        choices=["none", "hover", "text"],
        default="text",
        help="Edge labels in SVG (default: text)",
    )
    parser.add_argument(
        "--edge-curve",
        type=int,
        default=40,
        help="Curve strength for edges (default: 40, 0 for straight)",
    )
    parser.add_argument(
        "--max-size",
        type=int,
        default=2400,
        help="Max SVG width/height in pixels (default: 2400)",
    )
    legend = parser.add_mutually_exclusive_group()
    legend.add_argument(
        "--legend",
        action="store_true",
        default=True,
        help="Show legend (default: on)",
    )
    legend.add_argument(
        "--no-legend",
        action="store_false",
        dest="legend",
        help="Hide legend",
    )
    parser.add_argument(
        "--focus",
        default="",
        help="Root vertex_id for subgraph expansion",
    )
    parser.add_argument(
        "--match",
        default="",
        help="Only include edges with vertex_id/adjacent_id containing substring",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=2000,
        help="Max edges to include (default: 2000, 0 for no limit)",
    )
    parser.add_argument(
        "--start-ts",
        default="",
        help="Lower bound timestamp (ISO8601). Keep only edges at/after this time.",
    )
    return parser.parse_args()


def shorten(value, max_len=60):
    if value is None:
        return ""
    value = str(value)
    if len(value) <= max_len:
        return value
    return value[: max_len - 3] + "..."


def vertex_kind(vertex_id):
    if ":" not in vertex_id:
        return "unknown"
    return vertex_id.split(":", 1)[0]


def node_style(kind):
    styles = {
        "proc": ("box", "#c6e2ff"),
        "path": ("note", "#e8e8e8"),
        "file": ("ellipse", "#ffe4b5"),
        "net": ("diamond", "#d5f5e3"),
        "domain": ("hexagon", "#f9e79f"),
        "event": ("oval", "#f5f5f5"),
    }
    return styles.get(kind, ("ellipse", "#ffffff"))


def build_label(vertex_id, meta):
    kind = vertex_kind(vertex_id)
    data = meta.get("data", {}) if meta else {}
    if kind == "proc":
        image = data.get("image") or data.get("Image")
        if image:
            filename = os.path.basename(str(image).replace("\\", "/"))
            if filename.lower() == "svchost.exe":
                cmdline = proc_command_line(meta)
                if cmdline:
                    return "proc\n" + shorten(cmdline)
            return "proc\n" + shorten(filename)
        cmdline = proc_command_line(meta)
        if cmdline:
            return "proc\n" + shorten(cmdline)
        return "proc"
    if kind == "path":
        value = data.get("path") or vertex_id
        filename = os.path.basename(str(value).replace("\\", "/"))
        return "path\n" + shorten(filename)
    if kind == "file":
        sha = data.get("sha256") or vertex_id
        return "file\n" + shorten(sha)
    if kind == "net":
        ip = data.get("ip")
        port = data.get("port")
        if ip and port:
            return "net\n{}:{}".format(ip, port)
        return "net\n" + shorten(ip or vertex_id)
    if kind == "domain":
        return "domain\n" + shorten(data.get("domain") or vertex_id)
    return shorten(vertex_id)


def edge_color(edge_type):
    if edge_type in ("ProcessAccessEdge", "RemoteThreadEdge"):
        return "#e74c3c"
    if edge_type in ("ConnectEdge", "DNSQueryEdge"):
        return "#27ae60"
    if edge_type == "ImageOfEdge":
        return "#f1c40f"
    if edge_type in ("CreatedFileEdge", "ImageLoadEdge"):
        return "#2980b9"
    return "#7f8c8d"


def edge_key(row):
    return (row.get("vertex_id"), row.get("adjacent_id"), row.get("type"))


def parse_record_id(row):
    rid = row.get("record_id")
    if rid is None:
        return None
    try:
        return int(rid)
    except (TypeError, ValueError):
        return None


def edge_label_text(edge_type):
    if edge_type == "ParentOfEdge":
        return "创建进程"
    if edge_type == "CreatedFileEdge":
        return "创建文件"
    if edge_type == "ImageOfEdge":
        return "可执行文件启动"
    if edge_type == "ConnectEdge":
        return "网络访问"
    return edge_type or "edge"


def ioa_label_text(row):
    tags = row.get("ioa_tags") if isinstance(row, dict) else None
    if not isinstance(tags, list) or not tags:
        return ""
    names = []
    for tag in tags:
        if not isinstance(tag, dict):
            continue
        name = str(tag.get("name") or "").strip()
        if name:
            names.append(name)
    if not names:
        return ""
    seen = []
    seen_set = set()
    for name in names:
        if name in seen_set:
            continue
        seen_set.add(name)
        seen.append(name)
    return " | ".join(seen)


def parse_ts(row):
    ts = row.get("ts") if isinstance(row, dict) else None
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        return float(ts)
    if isinstance(ts, str):
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None


def edge_time_key(row):
    ts = parse_ts(row)
    rid = parse_record_id(row)
    if ts is None and rid is None:
        return None
    return (ts, rid)


def time_cmp(left, right):
    if left is None or right is None:
        return None
    left_ts, left_rid = left
    right_ts, right_rid = right
    if left_ts is None or right_ts is None:
        return None
    if left_ts < right_ts:
        return -1
    if left_ts > right_ts:
        return 1
    if left_rid is None or right_rid is None:
        return 0
    if left_rid < right_rid:
        return -1
    if left_rid > right_rid:
        return 1
    return 0


def time_ge(edge_time, node_time):
    if node_time is None or edge_time is None:
        return True
    edge_ts, edge_rid = edge_time
    node_ts, node_rid = node_time
    if edge_ts is None or node_ts is None:
        return True
    if edge_ts > node_ts:
        return True
    if edge_ts < node_ts:
        return False
    if edge_rid is None or node_rid is None:
        return True
    return edge_rid >= node_rid


def time_le(edge_time, node_time):
    if node_time is None or edge_time is None:
        return True
    edge_ts, edge_rid = edge_time
    node_ts, node_rid = node_time
    if edge_ts is None or node_ts is None:
        return True
    if edge_ts < node_ts:
        return True
    if edge_ts > node_ts:
        return False
    if edge_rid is None or node_rid is None:
        return True
    return edge_rid <= node_rid


def edge_sort_key(row):
    ts = parse_ts(row)
    rid = parse_record_id(row)
    return (ts is None, ts or 0, rid is None, rid or 0)


def parse_iso_to_epoch(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def filter_edges_from_start_time(edges, start_ts):
    if start_ts is None:
        return edges
    filtered = []
    for row in edges:
        ts = parse_ts(row)
        if ts is None:
            continue
        if ts >= start_ts:
            filtered.append(row)
    return filtered


def should_update_forward(old_time, new_time):
    if old_time is None:
        return False
    if new_time is None:
        return True
    cmp_value = time_cmp(new_time, old_time)
    if cmp_value is None:
        return False
    return cmp_value < 0


def should_update_reverse(old_time, new_time):
    if old_time is None:
        return False
    if new_time is None:
        return True
    cmp_value = time_cmp(new_time, old_time)
    if cmp_value is None:
        return False
    return cmp_value > 0


def traverse_forward_time(edges_by_src, seeds):
    visited = set()
    best_time = {}
    selected_edges = set()
    queue = []

    for node, time_key in seeds:
        if not node:
            continue
        visited.add(node)
        best_time[node] = time_key
        queue.append((node, time_key))

    while queue:
        src, src_time = queue.pop(0)
        for row in edges_by_src.get(src, []):
            dst = row.get("adjacent_id")
            if not dst:
                continue
            edge_time = edge_time_key(row)
            if not time_ge(edge_time, src_time):
                continue
            selected_edges.add(edge_key(row))
            next_time = edge_time if edge_time is not None else src_time
            if dst not in best_time:
                best_time[dst] = next_time
                visited.add(dst)
                queue.append((dst, next_time))
            elif should_update_forward(best_time[dst], next_time):
                best_time[dst] = next_time
                queue.append((dst, next_time))

    return visited, selected_edges


def traverse_reverse_time(edges_by_dst, seeds):
    visited = set()
    best_time = {}
    selected_edges = set()
    queue = []

    for node, time_key in seeds:
        if not node:
            continue
        visited.add(node)
        best_time[node] = time_key
        queue.append((node, time_key))

    while queue:
        dst, dst_time = queue.pop(0)
        for row in edges_by_dst.get(dst, []):
            src = row.get("vertex_id")
            if not src:
                continue
            edge_time = edge_time_key(row)
            if not time_le(edge_time, dst_time):
                continue
            selected_edges.add(edge_key(row))
            next_time = edge_time if edge_time is not None else dst_time
            if src not in best_time:
                best_time[src] = next_time
                visited.add(src)
                queue.append((src, next_time))
            elif should_update_reverse(best_time[src], next_time):
                best_time[src] = next_time
                queue.append((src, next_time))

    return visited, selected_edges


def detect_input_kind(path):
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                if row.get("record_type") in ("vertex", "edge"):
                    return "adjacency"
                if isinstance(row.get("sequence"), list):
                    return "finding"
    return "adjacency"


def finding_to_edges(row):
    sequence = row.get("sequence")
    if not isinstance(sequence, list):
        return []
    edges = []
    for item in sequence:
        if not isinstance(item, dict):
            continue
        src = item.get("from")
        dst = item.get("to")
        if not src or not dst:
            continue
        data = {}
        name = item.get("name")
        if name:
            data["name"] = name
        edges.append(
            {
                "record_type": "edge",
                "vertex_id": src,
                "adjacent_id": dst,
                "type": item.get("type") or "edge",
                "ts": item.get("ts"),
                "record_id": item.get("record_id"),
                "event_id": row.get("rule_id"),
                "data": data,
            }
        )
    return edges


def load_rows(path, match, limit, edge_types, allowed_kinds, input_kind, finding_index):
    if input_kind == "auto":
        input_kind = detect_input_kind(path)

    if input_kind == "finding":
        return load_rows_from_findings(path, match, limit, edge_types, allowed_kinds, finding_index)

    return load_rows_from_adjacency(path, match, limit, edge_types, allowed_kinds)


def load_finding_roots(path, finding_index):
    if not path:
        return []
    roots = []
    finding_idx = -1
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(row, dict) or not isinstance(row.get("sequence"), list):
                continue
            finding_idx += 1
            if finding_index >= 0 and finding_idx != finding_index:
                continue
            root = row.get("root")
            if root:
                roots.append(root)
            if finding_index >= 0 and finding_idx == finding_index:
                break
    return roots


def load_rows_from_findings(path, match, limit, edge_types, allowed_kinds, finding_index):
    nodes = set()
    edges = []
    edge_keys = set()
    meta = {}

    finding_idx = -1
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue

            if not isinstance(row, dict) or not isinstance(row.get("sequence"), list):
                continue

            finding_idx += 1
            if finding_index >= 0 and finding_idx != finding_index:
                continue

            for edge in finding_to_edges(row):
                vertex_id = edge.get("vertex_id")
                adjacent_id = edge.get("adjacent_id")
                if not vertex_id or not adjacent_id:
                    continue

                if match and match not in vertex_id and match not in adjacent_id:
                    continue

                if edge_types and (edge.get("type") or "") not in edge_types:
                    continue

                if allowed_kinds and (vertex_kind(vertex_id) not in allowed_kinds or vertex_kind(adjacent_id) not in allowed_kinds):
                    continue

                key = edge_key(edge)
                if key in edge_keys:
                    continue
                edge_keys.add(key)

                nodes.add(vertex_id)
                nodes.add(adjacent_id)
                edges.append(edge)

                if limit and len(edges) >= limit:
                    break

            if limit and len(edges) >= limit:
                break
            if finding_index >= 0 and finding_idx == finding_index:
                break

    return nodes, edges, meta


def load_rows_from_adjacency(path, match, limit, edge_types, allowed_kinds):
    meta = {}
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("record_type") == "vertex" and row.get("vertex_id"):
                meta[row["vertex_id"]] = row

    nodes = set()
    edges = []
    edge_keys = set()

    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue

            record_type = row.get("record_type")
            vertex_id = row.get("vertex_id")
            adjacent_id = row.get("adjacent_id")

            if record_type != "edge" or not vertex_id or not adjacent_id:
                continue

            if match and match not in vertex_id and match not in adjacent_id:
                continue

            if edge_types and (row.get("type") or "") not in edge_types:
                continue

            if allowed_kinds and (vertex_kind(vertex_id) not in allowed_kinds or vertex_kind(adjacent_id) not in allowed_kinds):
                continue

            maybe_fill_proc_meta(meta, vertex_id, row)
            maybe_fill_proc_meta(meta, adjacent_id, row)
            maybe_fill_proc_meta_from_image_edge(meta, row)

            if should_skip_file_edge(vertex_id, adjacent_id, meta):
                continue

            edge_key = (vertex_id, adjacent_id, row.get("type"))
            if edge_key in edge_keys:
                continue
            edge_keys.add(edge_key)

            nodes.add(vertex_id)
            nodes.add(adjacent_id)
            edges.append(row)

            if limit and len(edges) >= limit:
                break

    return nodes, edges, meta


def filter_paths_through(edges, through_types):
    if not through_types:
        nodes = set()
        for row in edges:
            src = row.get("vertex_id")
            dst = row.get("adjacent_id")
            if src:
                nodes.add(src)
            if dst:
                nodes.add(dst)
        return nodes, edges

    special_edges = [
        row for row in edges if (row.get("type") or "") in through_types
    ]
    if not special_edges:
        return set(), []

    forward = {}
    reverse = {}
    for row in edges:
        src = row.get("vertex_id")
        dst = row.get("adjacent_id")
        if not src or not dst:
            continue
        forward.setdefault(src, []).append(row)
        reverse.setdefault(dst, []).append(row)

    for src in list(forward.keys()):
        forward[src].sort(key=edge_sort_key)
    for dst in list(reverse.keys()):
        reverse[dst].sort(key=edge_sort_key)

    pre_seeds = []
    post_seeds = []
    for row in special_edges:
        time_key = edge_time_key(row)
        src = row.get("vertex_id")
        dst = row.get("adjacent_id")
        if src:
            pre_seeds.append((src, time_key))
        if dst:
            post_seeds.append((dst, time_key))

    _, pre_edges = traverse_reverse_time(reverse, pre_seeds)
    _, post_edges = traverse_forward_time(forward, post_seeds)

    special_keys = {edge_key(row) for row in special_edges}
    keep_keys = pre_edges | post_edges | special_keys

    selected_edges = []
    nodes = set()
    seen = set()
    for row in edges:
        key = edge_key(row)
        if key not in keep_keys or key in seen:
            continue
        seen.add(key)
        selected_edges.append(row)
        src = row.get("vertex_id")
        dst = row.get("adjacent_id")
        if src:
            nodes.add(src)
        if dst:
            nodes.add(dst)
    return nodes, selected_edges


def should_skip_file_edge(vertex_id, adjacent_id, meta):
    vk = vertex_kind(vertex_id)
    ak = vertex_kind(adjacent_id)
    if vk == "proc" and ak in ("path", "file"):
        return is_system_process(meta.get(vertex_id))
    if ak == "proc" and vk in ("path", "file"):
        return is_system_process(meta.get(adjacent_id))
    return False


def is_system_process(meta_row):
    if not meta_row:
        return False
    data = meta_row.get("data", {}) if isinstance(meta_row, dict) else {}
    image = str(data.get("image") or data.get("Image") or "").lower()
    return image.startswith("c:\\windows\\system32\\") or image.startswith("c:\\windows\\syswow64\\")


def proc_name_match(meta, vertex_id, name):
    image = proc_image_name(meta.get(vertex_id))
    if not image:
        return False
    return name in image


def proc_image_name(meta_row):
    if not meta_row:
        return ""
    data = meta_row.get("data", {}) if isinstance(meta_row, dict) else {}
    image = data.get("image") or data.get("Image") or ""
    if not image:
        return ""
    filename = os.path.basename(str(image).replace("\\", "/")).lower()
    return filename


def proc_command_line(meta_row):
    if not meta_row:
        return ""
    data = meta_row.get("data", {}) if isinstance(meta_row, dict) else {}
    for key in ("command_line", "CommandLine", "cmdline", "Cmdline", "cmd"):
        value = data.get(key)
        if value:
            return str(value)
    fields = data.get("fields", {}) if isinstance(data, dict) else {}
    for key in ("CommandLine", "command_line", "cmdline", "Cmdline", "cmd"):
        value = fields.get(key)
        if value:
            return str(value)
    return ""


def maybe_fill_proc_meta(meta, vertex_id, row):
    if not vertex_id or vertex_kind(vertex_id) != "proc":
        return
    existing = meta.get(vertex_id)
    existing_data = existing.get("data", {}) if existing else {}
    if not isinstance(existing_data, dict):
        existing_data = {}
    if existing is not None and "data" not in existing:
        existing["data"] = existing_data
    has_image = bool(existing_data.get("image") or existing_data.get("Image"))
    has_cmd = bool(existing_data.get("command_line") or existing_data.get("CommandLine"))
    row_data = row.get("data", {}) if isinstance(row, dict) else {}
    fields = row_data.get("fields", {}) if isinstance(row_data, dict) else {}
    image = fields.get("Image") or fields.get("image")
    cmdline = (
        fields.get("CommandLine")
        or fields.get("command_line")
        or fields.get("cmdline")
        or fields.get("Cmdline")
        or fields.get("cmd")
    )
    if not image and not cmdline:
        return
    if not existing:
        meta[vertex_id] = {
            "record_type": "vertex",
            "vertex_id": vertex_id,
            "data": {},
        }
        existing_data = meta[vertex_id]["data"]
        has_image = False
        has_cmd = False
    if image and not has_image:
        existing_data["image"] = image
    if cmdline and not has_cmd:
        existing_data["command_line"] = cmdline


def maybe_fill_proc_meta_from_image_edge(meta, row):
    if not isinstance(row, dict):
        return
    if (row.get("type") or "") != "ImageOfEdge":
        return

    src = row.get("vertex_id")
    dst = row.get("adjacent_id")
    if vertex_kind(src) != "path" or vertex_kind(dst) != "proc":
        return

    image = extract_path_from_path_vertex_id(src)
    if not image:
        return

    existing = meta.get(dst)
    if not existing:
        meta[dst] = {
            "record_type": "vertex",
            "vertex_id": dst,
            "data": {"image": image},
        }
        return

    data = existing.get("data", {}) if isinstance(existing, dict) else {}
    if not isinstance(data, dict):
        data = {}
    if isinstance(existing, dict) and "data" not in existing:
        existing["data"] = data
    if not (data.get("image") or data.get("Image")):
        data["image"] = image


def extract_path_from_path_vertex_id(vertex_id):
    if not isinstance(vertex_id, str) or not vertex_id.startswith("path:"):
        return ""
    parts = vertex_id.split(":", 2)
    if len(parts) < 3:
        return ""
    return parts[2]


def write_dot(path, nodes, edges, meta):
    node_ids = {}

    def node_id(key):
        if key not in node_ids:
            node_ids[key] = "n{}".format(len(node_ids) + 1)
        return node_ids[key]

    with open(path, "w", encoding="utf-8") as handle:
        handle.write("digraph G {\n")
        handle.write("  rankdir=LR;\n")
        handle.write("  node [style=filled,fontname=Helvetica];\n")

        for vertex_id in sorted(nodes):
            kind = vertex_kind(vertex_id)
            shape, color = node_style(kind)
            label = build_label(vertex_id, meta.get(vertex_id))
            handle.write(
                "  {} [label=\"{}\", shape={}, fillcolor=\"{}\"];\n".format(
                    node_id(vertex_id), label.replace("\"", "'"), shape, color
                )
            )

        for row in edges:
            src = node_id(row.get("vertex_id"))
            dst = node_id(row.get("adjacent_id"))
            edge_type = row.get("type") or "edge"
            event_id = row.get("event_id")
            label = edge_label_text(edge_type)
            if event_id is not None:
                label = "{} ({})".format(label, event_id)
            ioa_text = ioa_label_text(row)
            if ioa_text:
                label = "{}\\nIOA".format(label)
            color = edge_color(edge_type)
            handle.write(
                "  {} -> {} [label=\"{}\", color=\"{}\"];\n".format(
                    src, dst, label.replace("\"", "'"), color
                )
            )

        handle.write("}\n")


def write_subgraph_json(path, nodes, edges, meta, seeds):
    node_items = []
    for vertex_id in sorted(nodes):
        node_items.append(
            {
                "id": vertex_id,
                "kind": vertex_kind(vertex_id),
                "label": build_label(vertex_id, meta.get(vertex_id)),
            }
        )

    edge_items = []
    for row in edges:
        edge_items.append(
            {
                "from": row.get("vertex_id"),
                "to": row.get("adjacent_id"),
                "type": row.get("type") or "edge",
                "ts": row.get("ts"),
                "record_id": row.get("record_id"),
                "ioa_tags": row.get("ioa_tags") or [],
            }
        )

    payload = {
        "seeds": sorted(list(seeds)) if seeds else [],
        "nodes": node_items,
        "edges": edge_items,
    }

    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False)


def write_simple_svg(path, nodes, edges, meta, layout, iterations, seed, layer_edges, rankdir, layer_gap, node_gap, edge_label, legend_enabled, max_size, node_padding, seeds, edge_curve, tree_edge_keys):
    nodes = list(sorted(nodes))
    if not nodes:
        return

    labels = {}
    sizes = {}
    max_w = 0
    max_h = 0
    for vertex_id in nodes:
        label = build_label(vertex_id, meta.get(vertex_id))
        labels[vertex_id] = label
        w, h = label_size(label)
        sizes[vertex_id] = (w, h)
        if w > max_w:
            max_w = w
        if h > max_h:
            max_h = h

    effective_node_gap = max(node_gap, max_w + node_padding * 2)
    effective_layer_gap = max(layer_gap, max_h + node_padding * 2)

    positions, width, height = layout_positions(
        nodes,
        edges,
        layout,
        iterations,
        seed,
        layer_edges,
        rankdir,
        effective_layer_gap,
        effective_node_gap,
        seeds,
        sizes,
        tree_edge_keys,
    )

    if layout != "tree":
        apply_overlap_separation(positions, sizes, node_padding)
    positions, width, height = normalize_positions(positions, sizes, 40)

    if legend_enabled:
        width += 260

    svg_width = width
    svg_height = height
    if max_size and (width > max_size or height > max_size):
        scale = min(max_size / width, max_size / height)
        svg_width = width * scale
        svg_height = height * scale

    with open(path, "w", encoding="utf-8") as handle:
        handle.write(
            "<svg xmlns='http://www.w3.org/2000/svg' width='{0}' height='{1}' viewBox='0 0 {2} {3}'>\n".format(
                int(svg_width), int(svg_height), int(width), int(height)
            )
        )
        handle.write("<defs>\n")
        handle.write(
            "<marker id='arrow' viewBox='0 0 10 10' refX='9' refY='5' markerWidth='6' markerHeight='6' orient='auto-start-reverse'>\n"
        )
        handle.write("<path d='M 0 0 L 10 5 L 0 10 z' fill='currentColor'/>\n")
        handle.write("</marker>\n")
        handle.write("</defs>\n")

        node_boxes = {}
        for vertex_id in nodes:
            x, y = positions[vertex_id]
            box_w, box_h = sizes[vertex_id]
            node_boxes[vertex_id] = (
                x - box_w / 2 - node_padding,
                y - box_h / 2 - node_padding,
                x + box_w / 2 + node_padding,
                y + box_h / 2 + node_padding,
            )

        routed_edge_samples = []

        # edges
        for row in edges:
            src = row.get("vertex_id")
            dst = row.get("adjacent_id")
            if src not in positions or dst not in positions:
                continue
            x1, y1 = positions[src]
            x2, y2 = positions[dst]
            edge_type = row.get("type") or "edge"
            color = edge_color(edge_type)
            event_id = row.get("event_id")
            label_text = edge_label_text(edge_type)
            ioa_text = ioa_label_text(row)
            if ioa_text:
                label_text = "{} | IOA".format(label_text)
            label_hover = label_text
            if event_id is not None:
                label_hover = "{} ({})".format(label_text, event_id)
            if ioa_text:
                label_hover = "{}\\nIOA: {}".format(label_hover, ioa_text)
            write_edge(
                handle,
                x1,
                y1,
                x2,
                y2,
                color,
                label_text,
                label_hover,
                edge_label,
                sizes.get(src, (80, 24)),
                sizes.get(dst, (80, 24)),
                node_padding,
                edge_curve,
                layout,
                src,
                dst,
                node_boxes,
                routed_edge_samples,
            )

        # nodes
        for vertex_id in nodes:
            kind = vertex_kind(vertex_id)
            shape, color = node_style(kind)
            label = labels[vertex_id]
            x, y = positions[vertex_id]
            box_w, box_h = sizes[vertex_id]
            draw_node(handle, x, y, box_w, box_h, shape, color)
            draw_label(handle, x, y, label)

        if legend_enabled:
            draw_legend(handle, edges, width, height)

        handle.write("</svg>\n")


def layout_circle(nodes):
    count = len(nodes)
    radius = 80 + 20 * math.sqrt(count)
    margin = 120
    cx = radius + margin
    cy = radius + margin
    positions = {}
    for i, node in enumerate(nodes):
        angle = 2 * math.pi * i / count
        positions[node] = (cx + radius * math.cos(angle), cy + radius * math.sin(angle))
    size = (radius + margin) * 2
    return positions, size, size


def layout_force(nodes, edges, iterations, seed):
    count = len(nodes)
    size = max(600.0, 200.0 + 30.0 * math.sqrt(count))
    area = size * size
    k = math.sqrt(area / max(1, count))
    rng = random.Random(seed)

    positions = {}
    for node in nodes:
        positions[node] = (rng.uniform(0.0, size), rng.uniform(0.0, size))

    edge_pairs = []
    seen = set()
    for row in edges:
        src = row.get("vertex_id")
        dst = row.get("adjacent_id")
        if not src or not dst:
            continue
        key = (src, dst) if src <= dst else (dst, src)
        if key in seen:
            continue
        seen.add(key)
        edge_pairs.append((src, dst))

    t = size / 10.0
    iters = max(50, iterations)
    if count > 600:
        iters = 60
    elif count > 300:
        iters = min(iters, 120)

    for _ in range(iters):
        disp = {node: [0.0, 0.0] for node in nodes}

        for i in range(count):
            v = nodes[i]
            vx, vy = positions[v]
            for j in range(i + 1, count):
                u = nodes[j]
                ux, uy = positions[u]
                dx = vx - ux
                dy = vy - uy
                dist = math.hypot(dx, dy) + 0.01
                force = (k * k) / dist
                disp[v][0] += (dx / dist) * force
                disp[v][1] += (dy / dist) * force
                disp[u][0] -= (dx / dist) * force
                disp[u][1] -= (dy / dist) * force

        for src, dst in edge_pairs:
            sx, sy = positions[src]
            dx, dy = positions[dst]
            vx = sx - dx
            vy = sy - dy
            dist = math.hypot(vx, vy) + 0.01
            force = (dist * dist) / k
            disp[src][0] -= (vx / dist) * force
            disp[src][1] -= (vy / dist) * force
            disp[dst][0] += (vx / dist) * force
            disp[dst][1] += (vy / dist) * force

        cx = size / 2.0
        cy = size / 2.0
        for node in nodes:
            dx = positions[node][0] - cx
            dy = positions[node][1] - cy
            disp[node][0] -= dx * 0.01
            disp[node][1] -= dy * 0.01

        for node in nodes:
            dx, dy = disp[node]
            disp_len = math.hypot(dx, dy)
            if disp_len > 0:
                scale = min(disp_len, t) / disp_len
                nx = positions[node][0] + dx * scale
                ny = positions[node][1] + dy * scale
                nx = min(size, max(0.0, nx))
                ny = min(size, max(0.0, ny))
                positions[node] = (nx, ny)

        t *= 0.92

    return positions, size, size


def layout_positions(nodes, edges, layout, iterations, seed, layer_edges, rankdir, layer_gap, node_gap, seeds, sizes, tree_edge_keys):
    if layout == "force":
        return layout_force(nodes, edges, iterations, seed)
    if layout == "tree":
        return layout_tree(nodes, edges, seeds, rankdir, layer_gap, node_gap, tree_edge_keys)
    if layout == "time":
        return layout_time(nodes, edges, rankdir, layer_gap, node_gap)
    if layout == "layered":
        return layout_layered(nodes, edges, layer_edges, rankdir, layer_gap, node_gap)
    return layout_circle(nodes)


def layout_tree(nodes, edges, seeds, rankdir, layer_gap, node_gap, tree_edge_keys):
    nodes = list(sorted(nodes))
    if not seeds:
        return layout_layered(nodes, edges, "", rankdir, layer_gap, node_gap)
    node_time = {}
    for row in edges:
        t = parse_ts(row)
        if t is None:
            continue
        for node in (row.get("vertex_id"), row.get("adjacent_id")):
            if not node:
                continue
            prev = node_time.get(node)
            if prev is None or t < prev:
                node_time[node] = t

    adjacency = {node: [] for node in nodes}
    used_edges = 0
    for row in edges:
        src = row.get("vertex_id")
        dst = row.get("adjacent_id")
        if not src or not dst:
            continue
        if tree_edge_keys and edge_key(row) not in tree_edge_keys:
            continue
        if src not in adjacency or dst not in adjacency:
            continue
        adjacency[src].append((dst, parse_ts(row)))
        used_edges += 1

    if used_edges == 0:
        for row in edges:
            src = row.get("vertex_id")
            dst = row.get("adjacent_id")
            if not src or not dst:
                continue
            if src not in adjacency or dst not in adjacency:
                continue
            adjacency[src].append((dst, parse_ts(row)))

    for src, entries in adjacency.items():
        entries.sort(key=lambda item: (item[1] is None, item[1] or 0))

    depth = {}
    queue = []
    for seed in seeds:
        if seed in adjacency:
            depth[seed] = 0
            queue.append(seed)

    while queue:
        src = queue.pop(0)
        for dst, _ in adjacency.get(src, []):
            if dst in depth:
                continue
            depth[dst] = depth[src] + 1
            queue.append(dst)

    # Attach non-proc nodes under their nearest proc parent.
    for row in edges:
        src = row.get("vertex_id")
        dst = row.get("adjacent_id")
        if not src or not dst:
            continue
        src_kind = vertex_kind(src)
        dst_kind = vertex_kind(dst)
        if src_kind == "proc" and dst_kind != "proc" and src in depth:
            candidate = depth[src] + 1
            if dst not in depth or depth[dst] > candidate:
                depth[dst] = candidate
        if dst_kind == "proc" and src_kind != "proc" and dst in depth:
            candidate = depth[dst] + 1
            if src not in depth or depth[src] > candidate:
                depth[src] = candidate

    for node in nodes:
        if node not in depth:
            depth[node] = 0

    max_level = max(depth.values()) if depth else 0
    layers = [[] for _ in range(max_level + 1)]
    for node in nodes:
        layers[depth[node]].append(node)

    for layer in layers:
        layer.sort(key=lambda n: (node_time.get(n) is None, node_time.get(n) or 0, n))

    layers = reorder_layers_to_reduce_crossings(layers, adjacency)

    max_nodes = max(len(layer) for layer in layers) if layers else 1
    width = max(600.0, node_gap * max_nodes + 200)
    height = max(400.0, layer_gap * (max_level + 1) + 200)

    positions = {}
    for level, layer in enumerate(layers):
        count = len(layer)
        if count == 0:
            continue
        total_width = (count - 1) * node_gap
        start_x = (width - total_width) / 2.0
        y = 100.0 + level * layer_gap
        for idx, node in enumerate(layer):
            x = start_x + idx * node_gap
            if rankdir == "LR":
                positions[node] = (y, x)
            else:
                positions[node] = (x, y)

    if rankdir == "LR":
        width, height = height, width

    return positions, width, height


def reorder_layers_to_reduce_crossings(layers, adjacency):
    if not layers:
        return layers

    layer_of = {}
    for idx, layer in enumerate(layers):
        for node in layer:
            layer_of[node] = idx

    parents = {}
    children = {}
    for src, entries in adjacency.items():
        src_layer = layer_of.get(src)
        if src_layer is None:
            continue
        for dst, _ in entries:
            dst_layer = layer_of.get(dst)
            if dst_layer is None:
                continue
            if dst_layer <= src_layer:
                continue
            parents.setdefault(dst, []).append(src)
            children.setdefault(src, []).append(dst)

    for _ in range(6):
        for li in range(1, len(layers)):
            prev_pos = {n: i for i, n in enumerate(layers[li - 1])}
            current_pos = {n: i for i, n in enumerate(layers[li])}

            def up_key(node):
                ps = [prev_pos[p] for p in parents.get(node, []) if p in prev_pos]
                if not ps:
                    return (10**9, current_pos[node], node)
                return (sum(ps) / len(ps), current_pos[node], node)

            layers[li].sort(key=up_key)

        for li in range(len(layers) - 2, -1, -1):
            next_pos = {n: i for i, n in enumerate(layers[li + 1])}
            current_pos = {n: i for i, n in enumerate(layers[li])}

            def down_key(node):
                cs = [next_pos[c] for c in children.get(node, []) if c in next_pos]
                if not cs:
                    return (10**9, current_pos[node], node)
                return (sum(cs) / len(cs), current_pos[node], node)

            layers[li].sort(key=down_key)

    return layers


def layout_layered(nodes, edges, layer_edges, rankdir, layer_gap, node_gap):
    nodes = list(sorted(nodes))
    layer_types = {t.strip() for t in layer_edges.split(",") if t.strip()}

    adjacency = {node: [] for node in nodes}
    indegree = {node: 0 for node in nodes}
    used_edges = 0

    for row in edges:
        src = row.get("vertex_id")
        dst = row.get("adjacent_id")
        if not src or not dst:
            continue
        edge_type = row.get("type") or ""
        if layer_types and edge_type not in layer_types:
            continue
        if src not in adjacency or dst not in adjacency:
            continue
        adjacency[src].append(dst)
        indegree[dst] += 1
        used_edges += 1

    if used_edges == 0:
        for row in edges:
            src = row.get("vertex_id")
            dst = row.get("adjacent_id")
            if not src or not dst:
                continue
            if src not in adjacency or dst not in adjacency:
                continue
            adjacency[src].append(dst)
            indegree[dst] += 1

    queue = [node for node in nodes if indegree[node] == 0]
    levels = {node: 0 for node in queue}

    idx = 0
    while idx < len(queue):
        node = queue[idx]
        idx += 1
        for child in adjacency[node]:
            next_level = levels[node] + 1
            if child not in levels or levels[child] < next_level:
                levels[child] = next_level
            indegree[child] -= 1
            if indegree[child] == 0:
                queue.append(child)

    max_level = 0
    for node in nodes:
        if node not in levels:
            levels[node] = 0
        max_level = max(max_level, levels[node])

    layers = [[] for _ in range(max_level + 1)]
    for node in nodes:
        layers[levels[node]].append(node)

    max_nodes = max(len(layer) for layer in layers) if layers else 1
    width = max(600.0, node_gap * max_nodes + 200)
    height = max(400.0, layer_gap * (max_level + 1) + 200)

    positions = {}
    for level, layer in enumerate(layers):
        count = len(layer)
        if count == 0:
            continue
        total_width = (count - 1) * node_gap
        start_x = (width - total_width) / 2.0
        y = 100.0 + level * layer_gap
        for idx, node in enumerate(layer):
            x = start_x + idx * node_gap
            if rankdir == "LR":
                positions[node] = (y, x)
            else:
                positions[node] = (x, y)

    if rankdir == "LR":
        width, height = height, width

    return positions, width, height


def layout_time(nodes, edges, rankdir, layer_gap, node_gap):
    nodes = list(sorted(nodes))
    if not nodes:
        return {}, 0, 0

    node_time: Dict[str, Optional[float]] = {node: None for node in nodes}
    node_rid: Dict[str, Optional[int]] = {node: None for node in nodes}

    for row in edges:
        ts = parse_ts(row)
        if ts is None:
            continue
        rid = parse_record_id(row)
        for node in (row.get("vertex_id"), row.get("adjacent_id")):
            if not node or node not in node_time:
                continue
            prev_ts = node_time.get(node)
            prev_rid = node_rid.get(node)
            if prev_ts is None or ts < prev_ts:
                node_time[node] = ts
                node_rid[node] = rid
            elif ts == prev_ts and rid is not None and (prev_rid is None or rid < prev_rid):
                node_rid[node] = rid

    timed_nodes = [node for node in nodes if node_time.get(node) is not None]
    unknown_nodes = [node for node in nodes if node_time.get(node) is None]

    layers = []
    if timed_nodes:
        times: list[float] = []
        for node in timed_nodes:
            value = node_time.get(node)
            if value is not None:
                times.append(value)
        min_t = min(times)
        max_t = max(times)
        unique_times = sorted(set(times))
        max_layers = 120

        if len(unique_times) > max_layers and max_t > min_t:
            bucket = (max_t - min_t) / float(max_layers - 1)

            def layer_index(value):
                return int((value - min_t) / bucket) if bucket > 0 else 0

        else:
            time_to_layer = {t: idx for idx, t in enumerate(unique_times)}

            def layer_index(value):
                return time_to_layer[value]

        layer_map = {}
        for node in timed_nodes:
            time_value = node_time.get(node)
            if time_value is None:
                continue
            idx = layer_index(time_value)
            layer_map.setdefault(idx, []).append(node)

        for idx in sorted(layer_map.keys()):
            layer = layer_map[idx]
            layer.sort(
                key=lambda n: (
                    node_time[n],
                    node_rid[n] is None,
                    node_rid[n] or 0,
                    n,
                )
            )
            layers.append(layer)

    if unknown_nodes:
        unknown_nodes.sort()
        layers.append(unknown_nodes)

    if not layers:
        layers = [nodes]

    max_nodes = max(len(layer) for layer in layers) if layers else 1
    width = max(600.0, node_gap * max_nodes + 200)
    height = max(400.0, layer_gap * (len(layers) + 1) + 200)

    positions = {}
    for level, layer in enumerate(layers):
        count = len(layer)
        if count == 0:
            continue
        total_width = (count - 1) * node_gap
        start_x = (width - total_width) / 2.0
        y = 100.0 + level * layer_gap
        for idx, node in enumerate(layer):
            x = start_x + idx * node_gap
            if rankdir == "LR":
                positions[node] = (y, x)
            else:
                positions[node] = (x, y)

    if rankdir == "LR":
        width, height = height, width

    return positions, width, height


def label_size(label):
    lines = label.split("\n")
    max_len = max(len(line) for line in lines)
    width = max(100, min(240, max_len * 7 + 20))
    height = max(30, 18 * len(lines) + 16)
    return width, height


def draw_node(handle, x, y, w, h, shape, color):
    x0 = x - w / 2
    y0 = y - h / 2
    if shape == "box" or shape == "note":
        handle.write(
            "<rect x='{:.1f}' y='{:.1f}' width='{:.1f}' height='{:.1f}' rx='6' ry='6' fill='{}' stroke='#333' stroke-width='0.8' />\n".format(
                x0, y0, w, h, color
            )
        )
    elif shape == "diamond":
        points = [
            (x, y0),
            (x0 + w, y),
            (x, y0 + h),
            (x0, y),
        ]
        handle.write(svg_polygon(points, color))
    elif shape == "hexagon":
        dx = w * 0.25
        points = [
            (x0 + dx, y0),
            (x0 + w - dx, y0),
            (x0 + w, y),
            (x0 + w - dx, y0 + h),
            (x0 + dx, y0 + h),
            (x0, y),
        ]
        handle.write(svg_polygon(points, color))
    else:
        handle.write(
            "<ellipse cx='{:.1f}' cy='{:.1f}' rx='{:.1f}' ry='{:.1f}' fill='{}' stroke='#333' stroke-width='0.8' />\n".format(
                x, y, w / 2, h / 2, color
            )
        )


def svg_polygon(points, color):
    points_str = " ".join(["{:.1f},{:.1f}".format(px, py) for px, py in points])
    return "<polygon points='{}' fill='{}' stroke='#333' stroke-width='0.8' />\n".format(points_str, color)


def draw_label(handle, x, y, label):
    lines = label.split("\n")
    start_y = y - (len(lines) - 1) * 8
    for i, line in enumerate(lines):
        handle.write(
            "<text x='{:.1f}' y='{:.1f}' text-anchor='middle' font-size='11' font-family='Helvetica' fill='#111'>{}</text>\n".format(
                x, start_y + i * 16, escape_xml(line)
            )
        )


def escape_xml(text):
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def write_edge(handle, x1, y1, x2, y2, color, label_text, label_hover, label_mode, size1, size2, padding, curve, layout, src_node, dst_node, node_boxes, routed_edge_samples):
    sx, sy = shrink_point(x1, y1, x2, y2, size1, padding)
    tx, ty = shrink_point(x2, y2, x1, y1, size2, padding)
    path, samples = build_edge_path_with_avoidance(
        sx,
        sy,
        tx,
        ty,
        curve,
        layout,
        src_node,
        dst_node,
        node_boxes,
        routed_edge_samples,
    )
    routed_edge_samples.append(samples)
    if label_mode in ("hover", "text") and label_hover:
        handle.write(
            "<path d='{}' fill='none' stroke='{}' stroke-width='1.2' stroke-opacity='0.7' marker-end='url(#arrow)'>\n".format(
                path, color
            )
        )
        handle.write("<title>{}</title>\n".format(escape_xml(label_hover)))
        handle.write("</path>\n")
    else:
        handle.write(
            "<path d='{}' fill='none' stroke='{}' stroke-width='1.2' stroke-opacity='0.7' marker-end='url(#arrow)' />\n".format(
                path, color
            )
        )

    if label_mode == "text" and label_text:
        lx, ly = label_position(sx, sy, tx, ty, curve)
        handle.write(
            "<text x='{:.1f}' y='{:.1f}' text-anchor='middle' font-size='10' font-family='Helvetica' fill='#333' pointer-events='none'>{}</text>\n".format(
                lx, ly, escape_xml(label_text)
            )
        )


def label_position(x1, y1, x2, y2, curve):
    mx = (x1 + x2) / 2
    my = (y1 + y2) / 2
    dx = x2 - x1
    dy = y2 - y1
    length = math.hypot(dx, dy)
    if length == 0:
        return mx, my - 6
    nx = -dy / length
    ny = dx / length
    offset = min(20.0, max(8.0, curve * 0.25))
    return mx + nx * offset, my + ny * offset


def shrink_point(x1, y1, x2, y2, size, padding):
    dx = x2 - x1
    dy = y2 - y1
    if dx == 0 and dy == 0:
        return x1, y1
    hw = size[0] / 2
    hh = size[1] / 2
    if dx == 0:
        scale = hh / abs(dy)
    elif dy == 0:
        scale = hw / abs(dx)
    else:
        scale = min(hw / abs(dx), hh / abs(dy))
    scale = min(scale, 1.0)
    nx = x1 + dx * scale
    ny = y1 + dy * scale
    length = math.hypot(dx, dy)
    if length > 0:
        nx += (dx / length) * padding
        ny += (dy / length) * padding
    return nx, ny


def build_curve_path(x1, y1, x2, y2, curve):
    if curve <= 0:
        return "M {:.1f},{:.1f} L {:.1f},{:.1f}".format(x1, y1, x2, y2)
    dx = x2 - x1
    dy = y2 - y1
    length = math.hypot(dx, dy)
    if length == 0:
        return "M {:.1f},{:.1f} L {:.1f},{:.1f}".format(x1, y1, x2, y2)
    abs_dx = abs(dx)
    abs_dy = abs(dy)
    if abs_dy >= abs_dx:
        offset = min(abs_dy * 0.5, curve)
        sign = 1 if dy >= 0 else -1
        c1x, c1y = x1, y1 + sign * offset
        c2x, c2y = x2, y2 - sign * offset
    else:
        offset = min(abs_dx * 0.5, curve)
        sign = 1 if dx >= 0 else -1
        c1x, c1y = x1 + sign * offset, y1
        c2x, c2y = x2 - sign * offset, y2
    return "M {:.1f},{:.1f} C {:.1f},{:.1f} {:.1f},{:.1f} {:.1f},{:.1f}".format(
        x1, y1, c1x, c1y, c2x, c2y, x2, y2
    )


def curve_control_points(x1, y1, x2, y2, curve):
    if curve <= 0:
        return x1, y1, x2, y2
    dx = x2 - x1
    dy = y2 - y1
    length = math.hypot(dx, dy)
    if length == 0:
        return x1, y1, x2, y2
    abs_dx = abs(dx)
    abs_dy = abs(dy)
    if abs_dy >= abs_dx:
        offset = min(abs_dy * 0.5, curve)
        sign = 1 if dy >= 0 else -1
        c1x, c1y = x1, y1 + sign * offset
        c2x, c2y = x2, y2 - sign * offset
    else:
        offset = min(abs_dx * 0.5, curve)
        sign = 1 if dx >= 0 else -1
        c1x, c1y = x1 + sign * offset, y1
        c2x, c2y = x2 - sign * offset, y2
    return c1x, c1y, c2x, c2y


def cubic_point(x1, y1, c1x, c1y, c2x, c2y, x2, y2, t):
    u = 1.0 - t
    tt = t * t
    uu = u * u
    uuu = uu * u
    ttt = tt * t
    x = uuu * x1 + 3 * uu * t * c1x + 3 * u * tt * c2x + ttt * x2
    y = uuu * y1 + 3 * uu * t * c1y + 3 * u * tt * c2y + ttt * y2
    return x, y


def sample_cubic(x1, y1, c1x, c1y, c2x, c2y, x2, y2, steps=18):
    points = []
    for i in range(steps + 1):
        t = i / float(steps)
        points.append(cubic_point(x1, y1, c1x, c1y, c2x, c2y, x2, y2, t))
    return points


def point_in_box(x, y, box):
    x0, y0, x1, y1 = box
    return x0 <= x <= x1 and y0 <= y <= y1


def min_distance_to_samples(points, other_points):
    best = None
    for x, y in points:
        for ox, oy in other_points:
            d = math.hypot(x - ox, y - oy)
            if best is None or d < best:
                best = d
    return best if best is not None else 1e9


def path_penalty(points, src_node, dst_node, node_boxes, routed_edge_samples):
    penalty = 0.0
    for node_id, box in node_boxes.items():
        if node_id == src_node or node_id == dst_node:
            continue
        for x, y in points:
            if point_in_box(x, y, box):
                penalty += 500.0
                break

    for other in routed_edge_samples:
        d = min_distance_to_samples(points, other)
        if d < 14:
            penalty += (14 - d) * 60.0

    return penalty


def build_edge_path_with_avoidance(x1, y1, x2, y2, curve, layout, src_node, dst_node, node_boxes, routed_edge_samples):
    if layout == "tree":
        path = build_tree_curve_path(x1, y1, x2, y2)
        c1x, c1y, c2x, c2y = curve_control_points(x1, y1, x2, y2, max(40.0, abs(y2 - y1) * 0.4))
        return path, sample_cubic(x1, y1, c1x, c1y, c2x, c2y, x2, y2)

    if curve <= 0:
        path = "M {:.1f},{:.1f} L {:.1f},{:.1f}".format(x1, y1, x2, y2)
        return path, [(x1, y1), (x2, y2)]

    factors = [1.0, -1.0, 1.6, -1.6, 2.3, -2.3, 3.0, -3.0]
    best = None
    for f in factors:
        cc = abs(curve) * abs(f)
        c1x, c1y, c2x, c2y = curve_control_points(x1, y1, x2, y2, cc)
        if f < 0:
            c1x, c1y = x1 + (x1 - c1x), y1 + (y1 - c1y)
            c2x, c2y = x2 + (x2 - c2x), y2 + (y2 - c2y)
        points = sample_cubic(x1, y1, c1x, c1y, c2x, c2y, x2, y2)
        penalty = path_penalty(points, src_node, dst_node, node_boxes, routed_edge_samples)
        if best is None or penalty < best[0]:
            path = "M {:.1f},{:.1f} C {:.1f},{:.1f} {:.1f},{:.1f} {:.1f},{:.1f}".format(
                x1, y1, c1x, c1y, c2x, c2y, x2, y2
            )
            best = (penalty, path, points)

    if best is None:
        path = build_curve_path(x1, y1, x2, y2, curve)
        c1x, c1y, c2x, c2y = curve_control_points(x1, y1, x2, y2, curve)
        return path, sample_cubic(x1, y1, c1x, c1y, c2x, c2y, x2, y2)
    return best[1], best[2]


def build_edge_path(x1, y1, x2, y2, curve, layout):
    if layout == "tree":
        return build_tree_curve_path(x1, y1, x2, y2)
    if curve <= 0:
        return "M {:.1f},{:.1f} L {:.1f},{:.1f}".format(x1, y1, x2, y2)
    return build_curve_path(x1, y1, x2, y2, curve)


def build_tree_curve_path(x1, y1, x2, y2):
    dy = y2 - y1
    ctrl = max(40.0, abs(dy) * 0.4)
    c1x, c1y = x1, y1 + ctrl
    c2x, c2y = x2, y2 - ctrl
    return "M {:.1f},{:.1f} C {:.1f},{:.1f} {:.1f},{:.1f} {:.1f},{:.1f}".format(
        x1, y1, c1x, c1y, c2x, c2y, x2, y2
    )


def draw_legend(handle, edges, width, height):
    seen = []
    for row in edges:
        edge_type = row.get("type") or "edge"
        if edge_type not in seen:
            seen.append(edge_type)
    if not seen:
        return
    max_items = 8
    items = seen[:max_items]
    x = width - 260
    y = 40
    handle.write(
        "<rect x='{:.1f}' y='{:.1f}' width='230' height='{}' rx='6' ry='6' fill='#ffffff' stroke='#ccc' stroke-width='0.8'/>\n".format(
            x - 10, y - 20, 24 + len(items) * 22
        )
    )
    handle.write("<text x='{:.1f}' y='{:.1f}' font-size='12' font-family='Helvetica' fill='#333'>Legend</text>\n".format(x, y - 4))
    for idx, edge_type in enumerate(items):
        color = edge_color(edge_type)
        label = edge_type
        y0 = y + idx * 22
        handle.write(
            "<line x1='{:.1f}' y1='{:.1f}' x2='{:.1f}' y2='{:.1f}' stroke='{}' stroke-width='3'/>\n".format(
                x, y0, x + 20, y0, color
            )
        )
        handle.write(
            "<text x='{:.1f}' y='{:.1f}' font-size='11' font-family='Helvetica' fill='#333'>{}</text>\n".format(
                x + 28, y0 + 4, escape_xml(label)
            )
        )


def apply_overlap_separation(positions, sizes, padding):
    nodes = list(positions.keys())
    count = len(nodes)
    if count <= 1:
        return
    iterations = 40
    if count > 400:
        iterations = 12
    elif count > 200:
        iterations = 20

    for _ in range(iterations):
        moved = False
        for i in range(count):
            v = nodes[i]
            vx, vy = positions[v]
            vw, vh = sizes[v]
            for j in range(i + 1, count):
                u = nodes[j]
                ux, uy = positions[u]
                uw, uh = sizes[u]

                dx = vx - ux
                dy = vy - uy
                overlap_x = (vw / 2 + uw / 2 + padding) - abs(dx)
                overlap_y = (vh / 2 + uh / 2 + padding) - abs(dy)
                if overlap_x <= 0 or overlap_y <= 0:
                    continue

                moved = True
                if overlap_x < overlap_y:
                    shift = overlap_x / 2 + 1
                    sign = 1 if dx >= 0 else -1
                    vx += sign * shift
                    ux -= sign * shift
                else:
                    shift = overlap_y / 2 + 1
                    sign = 1 if dy >= 0 else -1
                    vy += sign * shift
                    uy -= sign * shift

                positions[v] = (vx, vy)
                positions[u] = (ux, uy)
        if not moved:
            break


def normalize_positions(positions, sizes, margin):
    min_x = None
    min_y = None
    max_x = None
    max_y = None
    for node, (x, y) in positions.items():
        w, h = sizes[node]
        left = x - w / 2
        right = x + w / 2
        top = y - h / 2
        bottom = y + h / 2
        min_x = left if min_x is None else min(min_x, left)
        max_x = right if max_x is None else max(max_x, right)
        min_y = top if min_y is None else min(min_y, top)
        max_y = bottom if max_y is None else max(max_y, bottom)

    if min_x is None or min_y is None or max_x is None or max_y is None:
        return positions, 0, 0

    width = (max_x - min_x) + margin * 2
    height = (max_y - min_y) + margin * 2

    for node, (x, y) in list(positions.items()):
        positions[node] = (x - min_x + margin, y - min_y + margin)

    return positions, width, height


def build_subgraph(edges, seeds):
    edges_by_src = {}
    for row in edges:
        src = row.get("vertex_id")
        if not src:
            continue
        edges_by_src.setdefault(src, []).append(row)

    for src in list(edges_by_src.keys()):
        edges_by_src[src].sort(key=edge_sort_key)

    selected_edges = []
    seen_edges = set()
    tree_edge_keys = set()
    visited = set()
    best_time = {}
    queue = []

    for seed in seeds:
        if seed:
            visited.add(seed)
            best_time[seed] = None
            queue.append((seed, None))

    while queue:
        src, src_time = queue.pop(0)
        for row in edges_by_src.get(src, []):
            dst = row.get("adjacent_id")
            if not dst:
                continue
            edge_time = edge_time_key(row)
            if not time_ge(edge_time, src_time):
                continue
            key = edge_key(row)
            if key not in seen_edges:
                seen_edges.add(key)
                selected_edges.append(row)
            next_time = edge_time if edge_time is not None else src_time
            if dst not in best_time:
                best_time[dst] = next_time
                visited.add(dst)
                queue.append((dst, next_time))
                tree_edge_keys.add(key)
            elif should_update_forward(best_time[dst], next_time):
                best_time[dst] = next_time
                queue.append((dst, next_time))
                tree_edge_keys.add(key)

    nodes = set(visited)
    return nodes, selected_edges, tree_edge_keys


def edge_has_ioa(row):
    tags = row.get("ioa_tags") if isinstance(row, dict) else None
    return isinstance(tags, list) and len(tags) > 0


def prune_paths_without_ioa(edges, tree_edge_keys=None):
    if tree_edge_keys is None:
        tree_edge_keys = set()

    ioa_edges = [row for row in edges if edge_has_ioa(row)]
    if not ioa_edges:
        return set(), [], set(), 0

    edges_by_src = {}
    edges_by_dst = {}
    edge_map = {}
    for row in edges:
        src = row.get("vertex_id")
        dst = row.get("adjacent_id")
        if not src or not dst:
            continue
        key = edge_key(row)
        edge_map[key] = row
        edges_by_src.setdefault(src, []).append(row)
        edges_by_dst.setdefault(dst, []).append(row)

    keep_keys = {edge_key(row) for row in ioa_edges}
    queue = [row.get("vertex_id") for row in ioa_edges if row.get("vertex_id")]
    seen_nodes = set(queue)
    while queue:
        node = queue.pop(0)
        for prev in edges_by_dst.get(node, []):
            pkey = edge_key(prev)
            keep_keys.add(pkey)
            prev_src = prev.get("vertex_id")
            if prev_src and prev_src not in seen_nodes:
                seen_nodes.add(prev_src)
                queue.append(prev_src)

    queue = [row.get("adjacent_id") for row in ioa_edges if row.get("adjacent_id")]
    seen_nodes = set(queue)
    while queue:
        node = queue.pop(0)
        for nxt in edges_by_src.get(node, []):
            nkey = edge_key(nxt)
            keep_keys.add(nkey)
            nxt_dst = nxt.get("adjacent_id")
            if nxt_dst and nxt_dst not in seen_nodes:
                seen_nodes.add(nxt_dst)
                queue.append(nxt_dst)

    selected_edges = []
    selected_nodes = set()
    seen = set()
    for row in edges:
        key = edge_key(row)
        if key not in keep_keys or key in seen:
            continue
        seen.add(key)
        selected_edges.append(row)
        src = row.get("vertex_id")
        dst = row.get("adjacent_id")
        if src:
            selected_nodes.add(src)
        if dst:
            selected_nodes.add(dst)

    selected_tree_keys = {k for k in tree_edge_keys if k in keep_keys}
    return selected_nodes, selected_edges, selected_tree_keys, len(ioa_edges)


def render(dot_path, fmt, image_path, nodes, edges, meta, layout, iterations, seed, layer_edges, rankdir, layer_gap, node_gap, edge_label, legend_enabled, max_size, node_padding, seeds, edge_curve, tree_edge_keys):
    if fmt == "none":
        return
    if fmt == "simple-svg":
        if not image_path:
            base, _ = os.path.splitext(dot_path)
            image_path = base + ".simple.svg"
        write_simple_svg(
            image_path,
            nodes,
            edges,
            meta,
            layout,
            iterations,
            seed,
            layer_edges,
            rankdir,
            layer_gap,
            node_gap,
            edge_label,
            legend_enabled,
            max_size,
            node_padding,
            seeds,
            edge_curve,
            tree_edge_keys,
        )
        return image_path

    if not image_path:
        base, _ = os.path.splitext(dot_path)
        image_path = base + "." + fmt
    cmd = ["dot", "-T{}".format(fmt), dot_path, "-o", image_path]
    try:
        subprocess.check_call(cmd)
        return image_path
    except FileNotFoundError:
        if fmt == "svg":
            write_simple_svg(
                image_path,
                nodes,
                edges,
                meta,
                layout,
                iterations,
                seed,
                layer_edges,
                rankdir,
                layer_gap,
                node_gap,
                edge_label,
                legend_enabled,
                max_size,
                node_padding,
                seeds,
                edge_curve,
                tree_edge_keys,
            )
            return image_path
        raise RuntimeError("graphviz 'dot' not found in PATH")


def main():
    args = parse_args()
    if not os.path.exists(args.input):
        print("Input not found: {}".format(args.input))
        return 1
    if args.finding_input and not os.path.exists(args.finding_input):
        print("Finding input not found: {}".format(args.finding_input))
        return 1

    edge_types = {t.strip() for t in args.edge_types.split(",") if t.strip()}
    through_types = {t.strip() for t in args.through_edge.split(",") if t.strip()}
    allowed_kinds = {t.strip() for t in args.vertex_types.split(",") if t.strip()}
    if "file" in allowed_kinds:
        allowed_kinds.add("path")
    nodes, edges, meta = load_rows(
        args.input,
        args.match,
        args.limit,
        edge_types,
        allowed_kinds,
        args.input_kind,
        args.finding_index,
    )
    if through_types:
        nodes, edges = filter_paths_through(edges, through_types)
    if not edges:
        print("No edges found for the given filters.")
        return 1

    start_ts = parse_iso_to_epoch(args.start_ts)
    if args.start_ts and start_ts is None:
        print("Invalid --start-ts: {}".format(args.start_ts))
        return 2
    if start_ts is not None:
        edges = filter_edges_from_start_time(edges, start_ts)
        if not edges:
            print("No edges remain after start-ts filter.")
            return 1

    seeds = set()
    if args.focus:
        seeds.add(args.focus)
    if args.finding_input:
        seeds.update(load_finding_roots(args.finding_input, args.finding_index))
    if args.proc_name:
        name = args.proc_name.lower()
        for vertex_id in list(meta.keys()) + list(nodes):
            if vertex_kind(vertex_id) != "proc":
                continue
            if proc_name_match(meta, vertex_id, name):
                seeds.add(vertex_id)

    tree_edge_keys = set()
    if seeds:
        nodes, edges, tree_edge_keys = build_subgraph(edges, seeds)
        if not edges:
            print("No edges found after subgraph expansion.")
            return 1

    nodes, edges, tree_edge_keys, ioa_count = prune_paths_without_ioa(edges, tree_edge_keys)
    if not edges:
        print("No edges remain after IOA path pruning.")
        return 1
    print("IOA path pruning kept {} edge(s) with {} IOA seed edge(s).".format(len(edges), ioa_count))

    os.makedirs(os.path.dirname(args.dot) or ".", exist_ok=True)
    write_dot(args.dot, nodes, edges, meta)
    print("DOT written to {}".format(args.dot))

    if args.json_out:
        os.makedirs(os.path.dirname(args.json_out) or ".", exist_ok=True)
        write_subgraph_json(args.json_out, nodes, edges, meta, seeds)
        print("JSON written to {}".format(args.json_out))

    if args.render != "none":
        try:
            image_path = render(
                args.dot,
                args.render,
                args.image,
                nodes,
                edges,
                meta,
                args.layout,
                args.iterations,
                args.seed,
                args.layer_edge,
                args.rankdir,
                args.layer_gap,
                args.node_gap,
                args.edge_label,
                args.legend,
                args.max_size,
                args.node_padding,
                seeds,
                args.edge_curve,
                tree_edge_keys,
            )
            print("Image written to {}".format(image_path))
        except RuntimeError as exc:
            print(str(exc))
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
