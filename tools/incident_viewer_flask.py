from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template_string, send_file


APP_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>ThreatGraph Incident Dashboard</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 16px; background: #0f172a; color: #e2e8f0; }
    .card { background: #111827; border: 1px solid #334155; border-radius: 10px; padding: 12px; margin-bottom: 12px; }
    h1, h2, h3 { margin: 0 0 8px 0; }
    .muted { color: #94a3b8; }
    table { width: 100%; border-collapse: collapse; font-size: 12px; }
    th, td { border-bottom: 1px solid #334155; text-align: left; padding: 8px; vertical-align: top; }
    tr:hover { background: #1e293b; cursor: pointer; }
    .mono { font-family: Consolas, monospace; word-break: break-all; }
    .pill { border: 1px solid #475569; border-radius: 999px; padding: 2px 8px; font-size: 12px; white-space: nowrap; }
    .critical { color: #fda4af; border-color: #7f1d1d; }
    .high { color: #fdba74; border-color: #9a3412; }
    .medium { color: #fde047; border-color: #854d0e; }
    .low { color: #86efac; border-color: #166534; }
    button { padding: 6px 10px; border: none; border-radius: 6px; background: #2563eb; color: #fff; }
    #svgWrap { margin-top: 6px; }
    #svgWrap img { max-width: 100%; border: 1px solid #334155; border-radius: 6px; background: #fff; }
    .kvs { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 8px; margin-bottom: 10px; }
    .kv { background: #0b1220; border: 1px solid #233047; border-radius: 8px; padding: 8px; }
    .kv .k { color: #94a3b8; font-size: 11px; margin-bottom: 4px; }
    .kv .v { font-size: 13px; }
    .detail-grid { display: grid; grid-template-columns: 1.3fr 1fr; gap: 12px; }
    .priority-grid { display: grid; grid-template-columns: 1.4fr 1fr; gap: 12px; margin-bottom: 12px; align-items: stretch; }
    .svg-card { margin: 0; padding: 10px; display: flex; flex-direction: column; min-height: 0; }
    .svg-title { margin-bottom: 8px; }
    .priority-side { display: grid; grid-template-rows: minmax(0, 0.4fr) minmax(0, 1.6fr); gap: 6px; min-height: 0; height: 100%; }
    .panel-block { background: #0b1220; border: 1px solid #233047; border-radius: 8px; min-height: 0; display: flex; flex-direction: column; }
    .panel-block { padding: 6px 8px; }
    .panel-block > summary { margin: 0; }
    .panel-body { margin-top: 4px; flex: 1 1 auto; min-height: 0; overflow: auto; }
    .panel-body .table-scroll { max-height: none; height: 100%; margin: 0; }
    .table-scroll { max-height: 260px; overflow: auto; border: 1px solid #253247; border-radius: 8px; }
    details { background: #0b1220; border: 1px solid #233047; border-radius: 8px; padding: 8px; margin-top: 8px; }
    summary { cursor: pointer; font-weight: 600; color: #cbd5e1; }
    @media (max-width: 1200px) { .kvs { grid-template-columns: repeat(2, minmax(0, 1fr)); } .detail-grid { grid-template-columns: 1fr; } .priority-grid { grid-template-columns: 1fr; } .priority-side { grid-template-rows: auto auto; } }
  </style>
</head>
<body>
  <div class="card">
    <h1>ThreatGraph Incident Dashboard</h1>
    <div class="muted">Data source: <span id="source"></span></div>
    <div style="margin-top:8px;"><button onclick="loadData()">Refresh</button></div>
  </div>

  <div class="card">
    <h2>Summary</h2>
    <div id="summary" class="muted">Loading...</div>
  </div>

  <div class="card">
    <h2>Incidents</h2>
    <table>
      <thead>
        <tr><th>#</th><th>Host</th><th>Severity</th><th>Seq</th><th>Alerts</th><th>Risk</th><th>Root</th></tr>
      </thead>
      <tbody id="rows"></tbody>
    </table>
  </div>

  <div class="card">
    <h2>Incident Detail</h2>
    <div id="detail" class="muted">Click an incident row.</div>
  </div>

<script>
let incidents = [];
let scored = [];

function sevClass(sev) {
  const s = (sev || '').toLowerCase();
  if (s === 'critical') return 'critical';
  if (s === 'high') return 'high';
  if (s === 'medium') return 'medium';
  return 'low';
}

function renderTable() {
  const tbody = document.getElementById('rows');
  tbody.innerHTML = '';
  incidents.forEach((x, i) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${i+1}</td>
      <td class="mono">${x.host||''}</td>
      <td><span class="pill ${sevClass(x.severity)}">${x.severity||'unknown'}</span></td>
      <td>${x.sequence_length||0}</td>
      <td>${x.alert_count||0}</td>
      <td>${x.risk_product||0}</td>
      <td class="mono">${x.root||''}</td>`;
    tr.onclick = () => showDetail(x);
    tbody.appendChild(tr);
  });
}

function showDetail(inc) {
  const match = scored.find(s => s.host === inc.host && s.root === inc.root);
  const verts = (((match||{}).tpg||{}).vertices||[]);
  const counts = {};
  for (const v of verts) {
    for (const t of (v.ioa_tags||[])) {
      const n = t.name || 'unknown';
      counts[n] = (counts[n] || 0) + 1;
    }
  }
  const lines = Object.entries(counts).sort((a,b)=>b[1]-a[1]).map(([k,v]) => `<li>${k}: ${v}</li>`).join('');
  const sample = verts.slice(0, 15).map(v => `<li><span class="mono">${v.ts||''}</span> | ${v.type||''} | record=${v.record_id||''}</li>`).join('');
  document.getElementById('detail').innerHTML = `
    <div class="kvs">
      <div class="kv"><div class="k">Host</div><div class="v mono">${inc.host||''}</div></div>
      <div class="kv"><div class="k">Root</div><div class="v mono">${inc.root||''}</div></div>
      <div class="kv"><div class="k">IIP Time</div><div class="v">${inc.iip_ts||''}</div></div>
      <div class="kv"><div class="k">Seq / Alerts / Risk</div><div class="v">${inc.sequence_length||0} / ${inc.alert_count||0} / ${inc.risk_product||0}</div></div>
    </div>
    <div class="priority-grid">
      <div class="card svg-card">
        <h3 class="svg-title">Focused IIP Subgraph</h3>
        <div id="svgWrap" class="muted">Loading SVG...</div>
      </div>
      <div class="priority-side">
        <details open class="panel-block">
          <summary>IIP Root (Start Vertex)</summary>
          <div id="rootInfo" class="muted panel-body">Loading...</div>
        </details>
        <details open class="panel-block">
          <summary>IOA With Vertex Context</summary>
          <div id="ioaContext" class="muted panel-body">Loading...</div>
        </details>
      </div>
    </div>
    <div class="detail-grid">
      <div>
        <details open>
          <summary>Rule Distribution</summary>
          <ul style="margin:8px 0 0 16px;">${lines || '<li>None</li>'}</ul>
        </details>
      </div>
      <div>
        <details>
          <summary>TPG Vertices (first 15)</summary>
          <ul style="margin:8px 0 0 16px;">${sample || '<li>None</li>'}</ul>
        </details>
      </div>
    </div>
    <details>
      <summary>TPG Rule & ATT&CK Context</summary>
      <div id="tpgContext" class="muted" style="margin-top:8px;">Loading...</div>
    </details>
    <details>
      <summary>TPG Alert Vertices</summary>
      <div id="tpgVertices" class="muted" style="margin-top:8px;">Loading...</div>
    </details>
    <details>
      <summary>TPG Sequence Edges</summary>
      <div id="tpgSequence" class="muted" style="margin-top:8px;">Loading...</div>
    </details>
  `;

  loadIncidentDetail(inc);

  const svgUrl = `/api/svg?root=${encodeURIComponent(inc.root || '')}&host=${encodeURIComponent(inc.host || '')}&force=1&_ts=${Date.now()}`;
  document.getElementById('svgWrap').innerHTML = `<img src="${svgUrl}" alt="IIP subgraph" />`;
}

function valueOrDash(v) {
  if (v === null || v === undefined || v === '') return '-';
  return String(v);
}

async function loadIncidentDetail(inc) {
  try {
    const u = `/api/detail?root=${encodeURIComponent(inc.root || '')}&host=${encodeURIComponent(inc.host || '')}`;
    const res = await fetch(u);
    const data = await res.json();
    if (!res.ok) {
      document.getElementById('rootInfo').innerHTML = `failed: ${data.error || res.status}`;
      document.getElementById('ioaContext').innerHTML = 'failed to load';
      document.getElementById('tpgContext').innerHTML = 'failed to load';
      document.getElementById('tpgVertices').innerHTML = 'failed to load';
      document.getElementById('tpgSequence').innerHTML = 'failed to load';
      return;
    }

    const r = data.root || {};
    document.getElementById('rootInfo').innerHTML = `
      <div><b>id:</b> <span class="mono">${valueOrDash(r.id)}</span></div>
      <div><b>kind:</b> ${valueOrDash(r.kind)}</div>
      <div><b>image/path:</b> <span class="mono">${valueOrDash(r.image_or_path)}</span></div>
      <div><b>parent path:</b> <span class="mono">${valueOrDash(r.parent_process_path)}</span></div>
      <div><b>command line:</b> <span class="mono">${valueOrDash(r.command_line)}</span></div>
    `;

    const rows = data.ioa_context || [];
    if (!rows.length) {
      document.getElementById('ioaContext').innerHTML = 'none';
    } else {
      let html = '<div class="table-scroll"><table><thead><tr><th>Time</th><th>IOA</th><th>From Vertex</th><th>To Vertex</th><th>Record</th></tr></thead><tbody>';
      for (const r of rows) {
        const fromText = `${valueOrDash(r.from.id)} [${valueOrDash(r.from.kind)}] ${valueOrDash(r.from.image_or_path)}`;
        const toText = `${valueOrDash(r.to.id)} [${valueOrDash(r.to.kind)}] ${valueOrDash(r.to.image_or_path)}`;
        html += `<tr><td>${valueOrDash(r.ts)}</td><td>${valueOrDash(r.ioa_name)}</td><td class="mono">${fromText}</td><td class="mono">${toText}</td><td class="mono">${valueOrDash(r.record_id)}</td></tr>`;
      }
      html += '</tbody></table></div>';
      document.getElementById('ioaContext').innerHTML = html;
    }

    const tpgRows = data.tpg_context || [];
    if (!tpgRows.length) {
      document.getElementById('tpgContext').innerHTML = 'none';
    } else {
      let tpgHtml = '<div class="table-scroll"><table><thead><tr><th>Rule</th><th>Severity</th><th>Tactic</th><th>Technique</th><th>Count</th></tr></thead><tbody>';
      for (const r of tpgRows) {
        tpgHtml += `<tr><td>${valueOrDash(r.rule_name)}</td><td>${valueOrDash(r.severity)}</td><td>${valueOrDash(r.tactic)}</td><td>${valueOrDash(r.technique)}</td><td>${valueOrDash(r.count)}</td></tr>`;
      }
      tpgHtml += '</tbody></table></div>';
      document.getElementById('tpgContext').innerHTML = tpgHtml;
    }

    const tpgVertices = data.tpg_vertices || [];
    if (!tpgVertices.length) {
      document.getElementById('tpgVertices').innerHTML = 'none';
    } else {
      let vHtml = '<div class="table-scroll"><table><thead><tr><th>#</th><th>Time</th><th>EdgeType</th><th>From</th><th>To</th><th>Rule/ATT&CK</th><th>Record</th><th>BestPath</th></tr></thead><tbody>';
      for (const v of tpgVertices) {
        const fromText = `${valueOrDash(v.from.id)} [${valueOrDash(v.from.kind)}] ${valueOrDash(v.from.image_or_path)}`;
        const toText = `${valueOrDash(v.to.id)} [${valueOrDash(v.to.kind)}] ${valueOrDash(v.to.image_or_path)}`;
        const tagText = (v.tags || []).map(t => `${valueOrDash(t.name)} | ${valueOrDash(t.severity)} | ${valueOrDash(t.tactic)} | ${valueOrDash(t.technique)}`).join('<br/>');
        vHtml += `<tr><td>${valueOrDash(v.index)}</td><td>${valueOrDash(v.ts)}</td><td>${valueOrDash(v.type)}</td><td class="mono">${fromText}</td><td class="mono">${toText}</td><td>${tagText || '-'}</td><td class="mono">${valueOrDash(v.record_id)}</td><td>${v.is_best_path ? 'yes' : 'no'}</td></tr>`;
      }
      vHtml += '</tbody></table></div>';
      document.getElementById('tpgVertices').innerHTML = vHtml;
    }

    const tpgSeq = data.tpg_sequence || [];
    if (!tpgSeq.length) {
      document.getElementById('tpgSequence').innerHTML = 'none';
    } else {
      let sHtml = '<div class="table-scroll"><table><thead><tr><th>FromIdx</th><th>ToIdx</th><th>FromRecord</th><th>ToRecord</th><th>FromTime</th><th>ToTime</th><th>BestPathEdge</th></tr></thead><tbody>';
      for (const s of tpgSeq) {
        sHtml += `<tr><td>${valueOrDash(s.from_index)}</td><td>${valueOrDash(s.to_index)}</td><td class="mono">${valueOrDash(s.from_record_id)}</td><td class="mono">${valueOrDash(s.to_record_id)}</td><td>${valueOrDash(s.from_ts)}</td><td>${valueOrDash(s.to_ts)}</td><td>${s.is_best_path_edge ? 'yes' : 'no'}</td></tr>`;
      }
      sHtml += '</tbody></table></div>';
      document.getElementById('tpgSequence').innerHTML = sHtml;
    }
  } catch (e) {
    document.getElementById('rootInfo').innerHTML = `error: ${String(e)}`;
    document.getElementById('ioaContext').innerHTML = 'error';
    document.getElementById('tpgContext').innerHTML = 'error';
    document.getElementById('tpgVertices').innerHTML = 'error';
    document.getElementById('tpgSequence').innerHTML = 'error';
  }
}

async function loadData() {
  const res = await fetch('/api/data');
  const data = await res.json();
  document.getElementById('source').textContent = `${data.paths.incidents} | ${data.paths.scored_tpg}`;
  incidents = data.incidents || [];
  scored = data.scored_tpg || [];
  document.getElementById('summary').textContent = `incidents=${incidents.length}, scored_tpg=${scored.length}`;
  renderTable();
}

loadData();
</script>
</body>
</html>
"""


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out


def create_app() -> Flask:
    app = Flask(__name__)
    output_dir = Path(os.environ.get("TG_OUTPUT_DIR", "output")).resolve()
    incidents_path = Path(os.environ.get("TG_INCIDENTS_FILE", str(output_dir / "incidents.latest.min2.jsonl")))
    scored_path = Path(os.environ.get("TG_SCORED_FILE", str(output_dir / "scored_tpg.latest.jsonl")))
    adjacency_path = Path(os.environ.get("TG_ADJACENCY_FILE", str(output_dir / "adjacency.min.jsonl")))
    svg_cache_dir = output_dir / "svg_cache"
    json_cache_dir = output_dir / "json_cache"
    svg_cache_dir.mkdir(parents=True, exist_ok=True)
    json_cache_dir.mkdir(parents=True, exist_ok=True)

    adjacency_cache: dict[str, Any] = {"mtime": None, "meta": {}}

    def _vertex_kind(vertex_id: str) -> str:
        if not isinstance(vertex_id, str) or ":" not in vertex_id:
            return "unknown"
        return vertex_id.split(":", 1)[0]

    def _extract_path_from_path_vertex(vertex_id: str) -> str:
        if not isinstance(vertex_id, str):
            return ""
        if not (vertex_id.startswith("path:") or vertex_id.startswith("file:")):
            return ""
        parts = vertex_id.split(":", 2)
        return parts[2] if len(parts) >= 3 else ""

    def _load_adjacency_meta() -> dict[str, dict[str, Any]]:
        if not adjacency_path.exists():
            return {}
        mtime = adjacency_path.stat().st_mtime
        if adjacency_cache["mtime"] == mtime and adjacency_cache["meta"]:
            return adjacency_cache["meta"]

        meta: dict[str, dict[str, Any]] = {}
        for line in adjacency_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except Exception:
                continue

            rtype = row.get("record_type")
            if rtype == "vertex" and row.get("vertex_id"):
                vid = row["vertex_id"]
                data = row.get("data") if isinstance(row.get("data"), dict) else {}
                meta[vid] = {"id": vid, "kind": _vertex_kind(vid), "data": data}
                continue

            if rtype == "edge" and row.get("type") == "ImageOfEdge":
                src = row.get("vertex_id")
                dst = row.get("adjacent_id")
                if _vertex_kind(src) in {"path", "file"} and _vertex_kind(dst) == "proc":
                    image = _extract_path_from_path_vertex(src)
                    if image:
                        item = meta.setdefault(dst, {"id": dst, "kind": "proc", "data": {}})
                        d = item.setdefault("data", {})
                        if not (d.get("image") or d.get("Image")):
                            d["image"] = image

        adjacency_cache["mtime"] = mtime
        adjacency_cache["meta"] = meta
        return meta

    def _vertex_info(vertex_id: str, meta_map: dict[str, dict[str, Any]]) -> dict[str, Any]:
        base = meta_map.get(vertex_id)
        if not isinstance(base, dict):
            base = {"id": vertex_id, "kind": _vertex_kind(vertex_id), "data": {}}
        kind = base.get("kind") or _vertex_kind(vertex_id)
        raw_data = base.get("data")
        data = raw_data if isinstance(raw_data, dict) else {}

        image_or_path = ""
        extra = ""
        if kind == "proc":
            image_or_path = str(data.get("process_path") or data.get("image") or data.get("Image") or "")
            extra = str(data.get("command_line") or data.get("CommandLine") or "")
        elif kind in {"path", "file"}:
            image_or_path = str(data.get("path") or _extract_path_from_path_vertex(vertex_id) or "")
        elif kind == "net":
            ip = str(data.get("ip") or "")
            port = str(data.get("port") or "")
            image_or_path = f"{ip}:{port}" if ip or port else ""
        elif kind == "domain":
            image_or_path = str(data.get("domain") or "")

        return {
            "id": vertex_id,
            "kind": kind,
            "image_or_path": image_or_path,
            "command_line": str(data.get("command_line") or data.get("CommandLine") or ""),
            "parent_process_path": str(data.get("parent_process_path") or data.get("parent_image") or ""),
            "extra": extra,
        }

    def _collect_proc_path_hints_from_subgraph(subgraph: dict[str, Any]) -> dict[str, str]:
        hints: dict[str, str] = {}
        edges = subgraph.get("edges") or []
        if not isinstance(edges, list):
            return hints

        for edge in edges:
            if not isinstance(edge, dict):
                continue
            src = str(edge.get("from") or edge.get("source") or "")
            dst = str(edge.get("to") or edge.get("target") or "")
            if _vertex_kind(src) not in {"path", "file"} or _vertex_kind(dst) != "proc":
                continue

            etype = str(edge.get("type") or "")
            if etype and etype != "ImageOfEdge":
                continue

            image_path = _extract_path_from_path_vertex(src)
            if image_path and ("\\" in image_path or "/" in image_path):
                hints[dst] = image_path

        return hints

    def _svg_cache_file(root: str, host: str) -> Path:
        key = f"{host}::{root}".encode("utf-8", errors="ignore")
        digest = hashlib.sha1(key).hexdigest()[:16]
        return svg_cache_dir / f"iip_{digest}.svg"

    def _json_cache_file(root: str, host: str) -> Path:
        key = f"{host}::{root}".encode("utf-8", errors="ignore")
        digest = hashlib.sha1(key).hexdigest()[:16]
        return json_cache_dir / f"iip_{digest}.json"

    def _build_svg(root: str, target: Path, start_ts: str = "") -> None:
        cmd = [
            "python3",
            "tools/visualize_adjacency.py",
            "--input",
            str(adjacency_path),
            "--focus",
            root,
            "--render",
            "simple-svg",
            "--image",
            str(target),
            "--layout",
            "tree",
            "--limit",
            "5000",
            "--edge-label",
            "text",
            "--max-size",
            "2400",
        ]
        if start_ts:
            cmd.extend(["--start-ts", start_ts])
        subprocess.run(cmd, cwd=Path(__file__).resolve().parents[1], check=True, capture_output=True, text=True)

    def _build_json(root: str, target: Path) -> None:
        cmd = [
            "python3",
            "tools/visualize_adjacency.py",
            "--input",
            str(adjacency_path),
            "--focus",
            root,
            "--json-out",
            str(target),
            "--render",
            "none",
            "--limit",
            "5000",
        ]
        subprocess.run(cmd, cwd=Path(__file__).resolve().parents[1], check=True, capture_output=True, text=True)

    def _load_or_build_subgraph_json(root: str, host: str, force: bool = False) -> dict[str, Any]:
        path = _json_cache_file(root, host)
        should_rebuild = force or (not path.exists())
        if not should_rebuild and adjacency_path.exists() and path.exists():
            should_rebuild = adjacency_path.stat().st_mtime > path.stat().st_mtime
        if should_rebuild:
            _build_json(root, path)
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))

    @app.get("/")
    def index() -> str:
        return render_template_string(APP_HTML)

    @app.get("/api/data")
    def api_data():
        incidents = _read_jsonl(incidents_path)
        incidents.sort(key=lambda x: (x.get("risk_product", 0), x.get("sequence_length", 0)), reverse=True)
        scored = _read_jsonl(scored_path)
        return jsonify(
            {
                "paths": {
                    "incidents": str(incidents_path),
                    "scored_tpg": str(scored_path),
                    "adjacency": str(adjacency_path),
                },
                "incidents": incidents,
                "scored_tpg": scored,
            }
        )

    @app.get("/api/svg")
    def api_svg():
        from flask import request

        root = (request.args.get("root") or "").strip()
        host = (request.args.get("host") or "").strip()
        if not root:
            return jsonify({"error": "missing root"}), 400
        if not adjacency_path.exists() or adjacency_path.stat().st_size == 0:
            return jsonify({"error": "adjacency file missing or empty"}), 404

        svg_path = _svg_cache_file(root, host)
        force = (request.args.get("force") or "").strip() in {"1", "true", "yes"}
        start_ts = ""
        scored = _read_jsonl(scored_path)
        target = None
        for row in scored:
            if row.get("root") == root and row.get("host") == host:
                target = row
                break
        if target is None:
            for row in scored:
                if row.get("root") == root:
                    target = row
                    break
        if isinstance(target, dict):
            vertices = ((target.get("tpg") or {}).get("vertices") or [])
            ts_list = [str(v.get("ts") or "") for v in vertices if isinstance(v, dict) and v.get("ts")]
            if ts_list:
                ts_list.sort()
                start_ts = ts_list[0]
        try:
            should_rebuild = force or (not svg_path.exists())
            if not should_rebuild and adjacency_path.exists() and svg_path.exists():
                should_rebuild = adjacency_path.stat().st_mtime > svg_path.stat().st_mtime
            if should_rebuild:
                _build_svg(root, svg_path, start_ts=start_ts)
            return send_file(svg_path, mimetype="image/svg+xml")
        except subprocess.CalledProcessError as exc:
            return jsonify({"error": "svg generation failed", "stderr": exc.stderr[-1200:] if exc.stderr else ""}), 500
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    @app.get("/api/detail")
    def api_detail():
        from flask import request

        root = (request.args.get("root") or "").strip()
        host = (request.args.get("host") or "").strip()
        if not root:
            return jsonify({"error": "missing root"}), 400

        scored = _read_jsonl(scored_path)
        target = None
        for row in scored:
            if row.get("root") == root and row.get("host") == host:
                target = row
                break
        if target is None:
            for row in scored:
                if row.get("root") == root:
                    target = row
                    break
        if target is None:
            return jsonify({"error": "incident not found in scored_tpg"}), 404

        meta_map = _load_adjacency_meta()
        subgraph = _load_or_build_subgraph_json(root, host, force=False)
        label_map: dict[str, str] = {}
        for n in (subgraph.get("nodes") or []):
            if isinstance(n, dict) and n.get("id"):
                label_map[str(n.get("id"))] = str(n.get("label") or "")

        def merge_label_info(info: dict[str, Any]) -> dict[str, Any]:
            if not isinstance(info, dict):
                return info
            if info.get("image_or_path"):
                return info
            label = label_map.get(str(info.get("id") or ""), "")
            if "\n" in label:
                parts = label.split("\n", 1)
                maybe = parts[1].strip()
                if maybe and maybe.lower() != "proc" and ("\\" in maybe or "/" in maybe):
                    info["image_or_path"] = maybe
            return info
        ioa_context = []
        tpg_context_counter: dict[tuple[str, str, str, str], int] = {}
        tpg_vertices_raw = ((target.get("tpg") or {}).get("vertices") or [])
        best_indexes_raw = ((target.get("score") or {}).get("best_vertex_indexes") or [])
        best_index_set = {int(x) for x in best_indexes_raw if isinstance(x, int)}
        best_path_edges = {
            (best_indexes_raw[i], best_indexes_raw[i + 1])
            for i in range(len(best_indexes_raw) - 1)
            if isinstance(best_indexes_raw[i], int) and isinstance(best_indexes_raw[i + 1], int)
        }
        tpg_vertices = []

        for idx, v in enumerate(tpg_vertices_raw):
            tags = v.get("ioa_tags") or []
            names = []
            norm_tags = []
            for t in tags:
                if isinstance(t, dict):
                    n = str(t.get("name") or "").strip()
                    severity = str(t.get("severity") or "").strip()
                    tactic = str(t.get("tactic") or "").strip()
                    technique = str(t.get("technique") or "").strip()
                    norm_tags.append(
                        {
                            "name": n,
                            "severity": severity,
                            "tactic": tactic,
                            "technique": technique,
                        }
                    )
                    if n:
                        names.append(n)
                        key = (
                            n,
                            severity,
                            tactic,
                            technique,
                        )
                        tpg_context_counter[key] = tpg_context_counter.get(key, 0) + 1
            if not names:
                names = [""]

            from_v = merge_label_info(_vertex_info(v.get("from") or "", meta_map))
            to_v = merge_label_info(_vertex_info(v.get("to") or "", meta_map))
            tpg_vertices.append(
                {
                    "index": idx,
                    "ts": v.get("ts"),
                    "type": v.get("type"),
                    "record_id": v.get("record_id"),
                    "from": from_v,
                    "to": to_v,
                    "tags": norm_tags,
                    "is_best_path": idx in best_index_set,
                }
            )
            for name in names:
                ioa_context.append(
                    {
                        "ioa_name": name,
                        "ts": v.get("ts"),
                        "record_id": v.get("record_id"),
                        "from": from_v,
                        "to": to_v,
                    }
                )

        proc_path_hint = _collect_proc_path_hints_from_subgraph(subgraph)
        for row in ioa_context:
            from_v = row.get("from") if isinstance(row, dict) else None
            to_v = row.get("to") if isinstance(row, dict) else None
            if not isinstance(from_v, dict) or not isinstance(to_v, dict):
                continue
            if str(from_v.get("kind")) not in {"path", "file"}:
                continue
            if str(to_v.get("kind")) != "proc":
                continue
            p = str(from_v.get("image_or_path") or "")
            pid = str(to_v.get("id") or "")
            if pid and p and ("\\" in p or "/" in p):
                proc_path_hint[pid] = p

        for row in ioa_context:
            for side in ("from", "to"):
                v = row.get(side) if isinstance(row, dict) else None
                if not isinstance(v, dict):
                    continue
                if str(v.get("kind")) != "proc":
                    continue
                vid = str(v.get("id") or "")
                cur = str(v.get("image_or_path") or "")
                hint = proc_path_hint.get(vid, "")
                if hint and (not cur or ("\\" not in cur and "/" not in cur)):
                    v["image_or_path"] = hint

        for row in tpg_vertices:
            if not isinstance(row, dict):
                continue
            for side in ("from", "to"):
                v = row.get(side)
                if not isinstance(v, dict):
                    continue
                if str(v.get("kind")) != "proc":
                    continue
                vid = str(v.get("id") or "")
                cur = str(v.get("image_or_path") or "")
                hint = proc_path_hint.get(vid, "")
                if hint and (not cur or ("\\" not in cur and "/" not in cur)):
                    v["image_or_path"] = hint

        root_info = merge_label_info(_vertex_info(root, meta_map))
        root_hint = proc_path_hint.get(str(root_info.get("id") or ""), "")
        root_cur = str(root_info.get("image_or_path") or "")
        if root_hint and (not root_cur or ("\\" not in root_cur and "/" not in root_cur)):
            root_info["image_or_path"] = root_hint

        tpg_context = [
            {
                "rule_name": key[0],
                "severity": key[1],
                "tactic": key[2],
                "technique": key[3],
                "count": count,
            }
            for key, count in sorted(tpg_context_counter.items(), key=lambda item: item[1], reverse=True)
        ]

        tpg_sequence = []
        tpg_vertices_map = {
            v.get("index"): v
            for v in tpg_vertices
            if isinstance(v, dict) and isinstance(v.get("index"), int)
        }
        for edge in ((target.get("tpg") or {}).get("sequence_edges") or []):
            if not isinstance(edge, dict):
                continue
            from_idx = edge.get("from")
            to_idx = edge.get("to")
            if not isinstance(from_idx, int) or not isinstance(to_idx, int):
                continue
            from_v = tpg_vertices_map.get(from_idx, {})
            to_v = tpg_vertices_map.get(to_idx, {})
            tpg_sequence.append(
                {
                    "from_index": from_idx,
                    "to_index": to_idx,
                    "from_record_id": from_v.get("record_id") if isinstance(from_v, dict) else "",
                    "to_record_id": to_v.get("record_id") if isinstance(to_v, dict) else "",
                    "from_ts": from_v.get("ts") if isinstance(from_v, dict) else "",
                    "to_ts": to_v.get("ts") if isinstance(to_v, dict) else "",
                    "is_best_path_edge": (from_idx, to_idx) in best_path_edges,
                }
            )

        return jsonify(
            {
                "root": root_info,
                "ioa_context": ioa_context,
                "tpg_context": tpg_context,
                "tpg_vertices": tpg_vertices,
                "tpg_sequence": tpg_sequence,
            }
        )

    return app


if __name__ == "__main__":
    app = create_app()
    host = os.environ.get("TG_HOST", "0.0.0.0")
    port = int(os.environ.get("TG_PORT", "5000"))
    app.run(host=host, port=port, debug=False)
