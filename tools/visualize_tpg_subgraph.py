import argparse
import json
from pathlib import Path

import visualize_adjacency as va


def parse_args():
    parser = argparse.ArgumentParser(description="Render a TPG-seeded subgraph SVG from adjacency JSONL")
    parser.add_argument("--input", required=True, help="Adjacency JSONL path")
    parser.add_argument("--scored", required=True, help="Scored TPG JSONL path")
    parser.add_argument("--root", required=True, help="TPG root to render")
    parser.add_argument("--host", default="", help="Optional host filter for choosing the scored TPG row")
    parser.add_argument("--json-out", default="", help="Optional structured subgraph JSON output")
    parser.add_argument("--image", required=True, help="SVG output path")
    parser.add_argument("--layout", default="tree", choices=["force", "circle", "layered", "tree", "time"])
    parser.add_argument("--max-size", type=int, default=2400)
    parser.add_argument("--edge-label", default="text", choices=["none", "hover", "text"])
    parser.add_argument("--edge-curve", type=int, default=40)
    parser.add_argument("--legend", action="store_true", default=True)
    parser.add_argument("--limit", type=int, default=5000)
    return parser.parse_args()


def read_jsonl(path: Path):
    rows = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except Exception:
            continue
    return rows


def find_target(scored_rows, host: str, root: str):
    for row in scored_rows:
        if row.get("root") == root and row.get("host") == host:
            return row
    for row in scored_rows:
        if row.get("root") == root:
            return row
    return None


def seed_nodes_from_tpg(row):
    seeds = {str(row.get("root") or "").strip()}
    tpg = row.get("tpg") or {}
    for v in tpg.get("vertices") or []:
        for key in ("from", "to"):
            value = str(v.get(key) or "").strip()
            if value:
                seeds.add(value)
    return {s for s in seeds if s}


def main():
    args = parse_args()
    input_path = Path(args.input)
    scored_path = Path(args.scored)
    rows = read_jsonl(scored_path)
    target = find_target(rows, args.host, args.root)
    if not isinstance(target, dict):
        raise SystemExit("target scored TPG not found")

    allowed_kinds = {"proc", "path", "file", "net", "domain", "regkey", "regval"}
    nodes, edges, meta = va.load_rows_from_adjacency(str(input_path), "", 0, set(), allowed_kinds)
    seed_nodes = seed_nodes_from_tpg(target)
    if not seed_nodes:
        raise SystemExit("no seed vertices found in target TPG")

    sub_nodes, sub_edges, tree_edge_keys = va.build_subgraph(edges, seed_nodes)
    sub_nodes, sub_edges, tree_edge_keys, _ = va.prune_paths_without_ioa(sub_edges, tree_edge_keys)
    if args.limit and len(sub_edges) > args.limit:
        sub_edges = sub_edges[: args.limit]
        keep = set()
        for row in sub_edges:
            if row.get("vertex_id"):
                keep.add(row["vertex_id"])
            if row.get("adjacent_id"):
                keep.add(row["adjacent_id"])
        sub_nodes = keep

    if args.json_out:
        va.write_subgraph_json(args.json_out, sub_nodes, sub_edges, meta, seed_nodes)
    va.write_simple_svg(
        args.image,
        sub_nodes,
        sub_edges,
        meta,
        args.layout,
        200,
        7,
        "ParentOfEdge",
        "TB",
        180,
        200,
        args.edge_label,
        args.legend,
        args.max_size,
        28,
        seed_nodes,
        args.edge_curve,
        tree_edge_keys,
    )


if __name__ == "__main__":
    main()
