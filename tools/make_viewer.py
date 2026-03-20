#!/usr/bin/env python3
"""
make_viewer.py  –  生成自包含 HTML incident viewer (D3.js 进程树图)

用法:
  python3 make_viewer.py --all-in-dir DIR [options]
"""

import argparse, datetime, json, os, ssl, sys, urllib.request
from collections import defaultdict

# ──────────────────────────────────────────────────────────────
_FILETIME_EPOCH_DIFF = 11644473600

_EXEC_EXTS = {'.exe','.dll','.sys','.bat','.cmd','.ps1','.vbs',
              '.js','.hta','.scr','.pif','.com','.msi','.cpl','.ocx'}

def filetime_to_str(ft):
    try:
        ft = int(ft)
        if ft <= 0: return ""
        secs = ft / 10_000_000 - _FILETIME_EPOCH_DIFF
        dt = (datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
              + datetime.timedelta(seconds=secs))
        return dt.strftime("%Y-%m-%dT%H:%M:%S")
    except Exception:
        return ""

def get_proc_ts(meta):
    ft = meta.get("time")
    if ft:
        ts = filetime_to_str(ft)
        if ts: return ts
    return (meta.get("@timestamp") or "")[:19]

def normalize_tags(raw):
    if not raw: return []
    if isinstance(raw, str):
        try: raw = json.loads(raw)
        except Exception: return [raw] if raw else []
    if isinstance(raw, list):
        out = []
        for item in raw:
            if isinstance(item, str): out.append(item)
            elif isinstance(item, dict):
                out.append(item.get("name") or item.get("tag") or str(item))
            else: out.append(str(item))
        return out
    return [str(raw)]

# ── ES ─────────────────────────────────────────────────────────

def make_ssl_ctx(ca_path):
    ctx = ssl.create_default_context()
    if ca_path and os.path.exists(ca_path):
        ctx.load_verify_locations(ca_path)
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx

def es_search(cfg, body):
    url = f"{cfg['url']}/{cfg['index']}/_search"
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers={
        "Content-Type": "application/json",
        "Authorization": "Basic " + __import__("base64").b64encode(
            f"{cfg['user']}:{cfg['passwd']}".encode()).decode(),
    })
    with urllib.request.urlopen(req, context=cfg["ssl"], timeout=60) as r:
        return json.loads(r.read())

def fetch_proc_meta(cfg, uuid_list, agent_list):
    if not uuid_list: return {}
    result = es_search(cfg, {
        "size": 10000,
        "_source": ["newprocessuuid","newprocess","new_process_name",
                    "new_command_line","command_line","processuuid",
                    "process","process_name","@timestamp","time"],
        "query": {"bool": {"filter": [
            {"term": {"fltrid": 1}},
            {"terms": {"newprocessuuid": uuid_list}},
            {"terms": {"client_id.keyword": agent_list}},
        ]}},
    })
    meta = {}
    for hit in result.get("hits", {}).get("hits", []):
        src = hit["_source"]
        u = src.get("newprocessuuid")
        if u: meta[u] = src
    return meta

def build_parent_name_map(proc_meta):
    out = {}
    for meta in proc_meta.values():
        p = meta.get("processuuid")
        if not p or p in proc_meta: continue
        name = meta.get("process_name") or os.path.basename(
            (meta.get("process") or "").replace("\\", "/"))
        if name and p not in out:
            out[p] = name
    return out

# ── Subgraph load ───────────────────────────────────────────────

def load_subgraph(path):
    incident_meta = {}
    parent_edges  = []
    all_edges     = []
    proc_uuids    = set()
    ioa_proc_uuids = set()
    agent_id      = ""

    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try: row = json.loads(line)
            except: continue

            rt = row.get("record_type", "")
            if rt == "_incident_meta":
                incident_meta = row
                continue

            vid = row.get("vertex_id", "")
            if vid.startswith("proc:"):
                parts = vid.split(":", 2)
                if len(parts) == 3:
                    if not agent_id: agent_id = parts[1]
                    proc_uuids.add(parts[2])

            if rt == "edge":
                etype = row.get("type", "")
                dst   = row.get("adjacent_id", "")
                tags  = normalize_tags(row.get("ioa_tags"))
                all_edges.append({"type": etype, "src": vid, "dst": dst,
                                   "ioa": tags, "ts": row.get("ts", "")})
                if etype == "ParentOfEdge":
                    if vid.startswith("proc:") and dst.startswith("proc:"):
                        pu = vid.split(":", 2)[2]
                        cu = dst.split(":", 2)[2]
                        parent_edges.append((pu, cu, tags))
                        if tags:
                            ioa_proc_uuids.add(pu)
                            ioa_proc_uuids.add(cu)
                if tags:
                    for fld in ("vertex_id", "adjacent_id"):
                        v = row.get(fld, "")
                        if v.startswith("proc:"):
                            p2 = v.split(":", 2)
                            if len(p2) == 3: ioa_proc_uuids.add(p2[2])

    return incident_meta, proc_uuids, parent_edges, all_edges, ioa_proc_uuids, agent_id

# ── Build JSON ──────────────────────────────────────────────────

def _root_short(root_label):
    """Return a human-readable short label for an IIP root vertex."""
    if not root_label:
        return ""
    parts = root_label.split(":", 2)
    vtype = parts[0] if parts else ""
    payload = parts[2] if len(parts) == 3 else root_label
    if vtype == "proc":
        # proc:host:{uuid} → {uuid}
        return payload
    elif vtype == "path":
        # path:host:C:\...\file.exe → file.exe
        return os.path.basename(payload.replace("\\", "/"))
    return payload

def _root_info(root_label, proc_meta, parent_names):
    if not root_label:
        return {"name": "", "detail": "", "icon": "other", "type": ""}
    parts = root_label.split(":", 2)
    vtype = parts[0] if parts else ""
    payload = parts[2] if len(parts) == 3 else root_label
    if vtype == "proc":
        meta = proc_meta.get(payload)
        name = ""
        detail = ""
        if meta:
            name = meta.get("new_process_name") or os.path.basename((meta.get("newprocess") or "").replace("\\", "/"))
            detail = meta.get("newprocess") or payload
        else:
            name = parent_names.get(payload, "") or payload
            detail = payload
        return {"name": name or payload, "detail": detail, "icon": "proc", "type": vtype}
    if vtype == "path":
        path = payload
        name = os.path.basename(path.replace("\\", "/")) or path
        return {"name": name, "detail": path, "icon": "file", "type": vtype}
    if vtype == "net":
        return {"name": payload, "detail": payload, "icon": "net", "type": vtype}
    if vtype in ("regkey", "regval"):
        return {"name": payload.split("\\")[-1] or payload, "detail": payload, "icon": "reg", "type": vtype}
    if vtype == "domain":
        return {"name": payload, "detail": payload, "icon": "domain", "type": vtype}
    return {"name": payload, "detail": payload, "icon": "other", "type": vtype}

def _pname(uuid, proc_meta, parent_names):
    m = proc_meta.get(uuid)
    if m:
        n = m.get("new_process_name") or os.path.basename(
            (m.get("newprocess") or "").replace("\\", "/"))
        return n or ""
    return parent_names.get(uuid, "")

def build_incident_json(path, cfg):
    fname = os.path.basename(path)
    print(f"  {fname} ...", flush=True)

    incident_meta, proc_uuids, parent_edges, all_edges, ioa_proc_uuids, agent_id = \
        load_subgraph(path)

    proc_meta    = fetch_proc_meta(cfg, list(proc_uuids),
                                   [agent_id] if agent_id else [])
    parent_names = build_parent_name_map(proc_meta)
    print(f"    ES {len(proc_meta)}/{len(proc_uuids)}", flush=True)

    # children map
    ch_map  = defaultdict(list)
    parent_of = {}
    has_par = set()
    for pu, cu, _ in parent_edges:
        if pu in proc_uuids and cu in proc_uuids:
            ch_map[pu].append(cu)
            has_par.add(cu)
            parent_of[cu] = pu

    # IOA tag map per proc
    ioa_tag_map = defaultdict(set)
    for e in all_edges:
        if not e["ioa"]: continue
        for fld in ("src", "dst"):
            v = e[fld]
            if v.startswith("proc:"):
                p = v.split(":", 2)
                if len(p) == 3: ioa_tag_map[p[2]].update(e["ioa"])

    # extra edges (non-ParentOf) for overlay visualization
    extra_edges = []
    net_connections = {}  # uuid -> [{ip_port, ioa}]

    for e in all_edges:
        etype, src, dst, tags = e["type"], e["src"], e["dst"], e["ioa"]
        if etype == "ParentOfEdge": continue

        if src.startswith("proc:") and dst.startswith("proc:"):
            su = src.split(":", 2)[2]
            du = dst.split(":", 2)[2]
            if su in proc_uuids and du in proc_uuids and su != du:
                extra_edges.append({"src": su, "dst": du,
                                     "type": etype, "ioa": bool(tags)})

        elif etype == "ConnectEdge" and src.startswith("proc:") and dst.startswith("net:"):
            su = src.split(":", 2)[2]
            if su in proc_uuids:
                ip_port = dst[4:]  # strip "net:"
                if su not in net_connections:
                    net_connections[su] = []
                net_connections[su].append({"ip": ip_port, "ioa": bool(tags)})

    rpc_path_procs = set()
    for e in extra_edges:
        if e["type"] not in ("RPCTriggerEdge", "ProcessCPEdge"):
            continue
        for u in (e["src"], e["dst"]):
            cur = u
            while cur and cur not in rpc_path_procs:
                rpc_path_procs.add(cur)
                cur = parent_of.get(cur)

    file_map = {}  # path_str → {name, ioa, edges:[{uuid,type,ioa}]}
    for e in all_edges:
        etype, src, dst, tags = e["type"], e["src"], e["dst"], e["ioa"]
        path_str = proc_uuid = None
        if etype == "ImageLoadEdge" and src.startswith("path:") and dst.startswith("proc:"):
            dp = dst.split(":", 2)
            if len(dp) == 3 and dp[2] in proc_uuids:
                sp2 = src.split(":", 2)
                path_str = sp2[2] if len(sp2) == 3 else ""
                proc_uuid = dp[2]
        elif etype in ("CreatedFileEdge", "FileWriteEdge", "FileAccessEdge") \
                and src.startswith("proc:") and dst.startswith("path:"):
            sp2 = src.split(":", 2)
            if len(sp2) == 3 and sp2[2] in proc_uuids:
                dp = dst.split(":", 2)
                path_str = dp[2] if len(dp) == 3 else ""
                proc_uuid = sp2[2]
        if path_str and proc_uuid:
            ext = os.path.splitext(path_str.lower())[1]
            if ext in _EXEC_EXTS:
                if path_str not in file_map:
                    file_map[path_str] = {
                        "name": os.path.basename(path_str.replace("\\", "/")),
                        "ioa": False, "edges": []}
                file_map[path_str]["edges"].append(
                    {"uuid": proc_uuid, "type": etype, "ioa": bool(tags)})
                if tags:
                    file_map[path_str]["ioa"] = True

    file_nodes = [{"path": p, "name": v["name"], "ioa": v["ioa"], "edges": v["edges"]}
                  for p, v in file_map.items()]

    # per-proc file lookup for detail panel
    file_per_proc = defaultdict(list)
    for fn in file_nodes:
        for fe in fn["edges"]:
            file_per_proc[fe["uuid"]].append(
                {"path": fn["path"], "name": fn["name"],
                 "type": fe["type"], "ioa": fe["ioa"]})

    # count descendants
    def desc_count(u, vis=None):
        if vis is None: vis = set()
        if u in vis: return 0
        vis.add(u)
        return sum(1 + desc_count(c, vis) for c in ch_map.get(u, []))

    def make_file_child(item):
        label = item["name"]
        prefix = {
            "ImageLoadEdge": "[L] ",
            "CreatedFileEdge": "[C] ",
            "FileWriteEdge": "[W] ",
            "FileAccessEdge": "[A] ",
        }.get(item.get("type"), "[F] ")
        return {
            "_id": nid(),
            "uuid": None,
            "name": prefix + label,
            "full_path": item.get("path", ""),
            "cmd": "",
            "ts": "",
            "ts_end": "",
            "pre_obs": False,
            "is_ioa": item.get("ioa", False),
            "ioa_tags": [],
            "group": False,
            "group_count": None,
            "net": [],
            "files": [],
            "children": [],
            "node_type": "file",
            "edge_type": item.get("type", ""),
            "_open": True,
        }

    def node_signature(node):
        return (
            node.get("node_type", "proc"),
            node.get("name"),
            node.get("is_ioa"),
            tuple(sorted((c.get("node_type", "proc"), c.get("name"), c.get("is_ioa"), c.get("group", False), c.get("group_count")) for c in node.get("children", []))),
        )

    def aggregate_collapsed_children(children):
        buckets = defaultdict(list)
        ordered = []
        for child in children:
            if child.get("node_type", "proc") != "proc" or child.get("group") or child.get("_open", True) or child.get("is_ioa") or child.get("uuid") in rpc_path_procs:
                ordered.append(child)
                continue
            buckets[node_signature(child)].append(child)
        out = list(ordered)
        for grp in buckets.values():
            if len(grp) == 1:
                out.append(grp[0])
                continue
            first = grp[0]
            out.append({
                "_id": nid(),
                "uuid": None,
                "name": first.get("name"),
                "full_path": "",
                "cmd": "",
                "ts": first.get("ts", ""),
                "ts_end": grp[-1].get("ts", first.get("ts", "")),
                "pre_obs": False,
                "is_ioa": False,
                "ioa_tags": [],
                "group": True,
                "group_count": len(grp),
                "net": [],
                "files": [],
                "children": first.get("children", []),
                "node_type": "proc",
                "edge_type": "ParentOfEdge",
                "_open": False,
            })
        return out

    def make_net_child(item):
        return {
            "_id": nid(),
            "uuid": None,
            "name": "[N] " + item.get("ip", ""),
            "full_path": item.get("ip", ""),
            "cmd": "",
            "ts": "",
            "ts_end": "",
            "pre_obs": False,
            "is_ioa": item.get("ioa", False),
            "ioa_tags": [],
            "group": False,
            "group_count": None,
            "net": [],
            "files": [],
            "children": [],
            "node_type": "net",
            "edge_type": "ConnectEdge",
            "_open": True,
        }

    # Determine which proc nodes are actually visible (have at least one drawn edge).
    # Procs with zero visible connections are zombie vertex records left over from
    # IOA pruning — exclude them so they don't appear as isolated floating circles.
    visible_procs = set(ch_map.keys()) | has_par          # ParentOfEdge endpoints
    visible_procs.update(net_connections.keys())           # ConnectEdge endpoints
    visible_procs.update(rpc_path_procs)                   # Keep RPC/CodePath endpoints visible

    # find roots
    inc_root = incident_meta.get("root", "")
    explicit = []
    if inc_root.startswith("proc:"):
        p = inc_root.split(":", 2)
        if len(p) == 3: explicit.append(p[2])
    orphans = [u for u in proc_uuids if u not in has_par and u in visible_procs]
    if explicit:
        explicit_visible = [r for r in explicit if r in proc_uuids and r in visible_procs]
        explicit_orphans = [r for r in explicit_visible if r not in has_par]
        if orphans:
            roots = orphans
        else:
            roots = explicit_orphans or explicit_visible
    else:
        roots = orphans

    _id_seq = [0]
    def nid():
        _id_seq[0] += 1
        return _id_seq[0]

    def make_node(uuid, depth=0):
        meta = proc_meta.get(uuid)
        if meta:
            name  = meta.get("new_process_name") or os.path.basename(
                        (meta.get("newprocess") or "").replace("\\", "/")) or uuid
            fpath = meta.get("newprocess") or ""
            cmd   = (meta.get("new_command_line") or
                     meta.get("command_line") or "").strip()
            ts    = get_proc_ts(meta)
            preob = False
        else:
            name  = parent_names.get(uuid) or f"<{uuid[:8]}…>"
            fpath = ""
            cmd   = ""
            ts    = ""
            preob = bool(parent_names.get(uuid))

        kids = ch_map.get(uuid, [])

        # Group same-name childless siblings
        name_cnt = defaultdict(int)
        for kid in kids:
            if not ch_map.get(kid) and kid not in rpc_path_procs:
                name_cnt[_pname(kid, proc_meta, parent_names) or kid] += 1

        children_json = []
        child_signals = []
        done_groups   = set()
        for kid in kids:
            if ch_map.get(kid):
                child_node, child_signal = make_node(kid, depth + 1)
                children_json.append(child_node)
                child_signals.append(child_signal)
            else:
                kn = _pname(kid, proc_meta, parent_names) or kid
                if kid not in rpc_path_procs and name_cnt[kn] > 1:
                    if kn not in done_groups:
                        done_groups.add(kn)
                        grp = [k for k in kids if not ch_map.get(k)
                               and (_pname(k, proc_meta, parent_names) or k) == kn]
                        tss = sorted(filter(None,
                            [get_proc_ts(proc_meta[k]) for k in grp if k in proc_meta]))
                        grp_ioa = any(k in ioa_proc_uuids for k in grp)
                        children_json.append({
                            "_id": nid(), "uuid": None,
                            "name": kn, "full_path": "", "cmd": "",
                            "ts": tss[0] if tss else "",
                            "ts_end": tss[-1] if len(tss) > 1 else "",
                            "pre_obs": False,
                            "is_ioa": grp_ioa,
                            "ioa_tags": [],
                            "group": True, "group_count": len(grp),
                            "net": [],
                            "children": [],
                        })
                        child_signals.append(grp_ioa)
                else:
                    child_node, child_signal = make_node(kid, depth + 1)
                    children_json.append(child_node)
                    child_signals.append(child_signal)

        file_children = {}
        for item in file_per_proc.get(uuid, []):
            if item.get("type") not in ("CreatedFileEdge", "FileWriteEdge", "FileAccessEdge", "ImageLoadEdge"):
                continue
            key = item.get("path", "")
            if not key:
                continue
            cur = file_children.get(key)
            if cur is None:
                file_children[key] = dict(item)
            else:
                cur["ioa"] = cur.get("ioa", False) or item.get("ioa", False)
                cur["type"] = cur.get("type") or item.get("type")
        for key in sorted(file_children):
            item = file_children[key]
            children_json.append(make_file_child(item))
            child_signals.append(item.get("ioa", False) or True)

        net_children = {}
        for item in net_connections.get(uuid, []):
            key = item.get("ip", "")
            if not key:
                continue
            cur = net_children.get(key)
            if cur is None:
                net_children[key] = dict(item)
            else:
                cur["ioa"] = cur.get("ioa", False) or item.get("ioa", False)
        for key in sorted(net_children):
            item = net_children[key]
            children_json.append(make_net_child(item))
            child_signals.append(item.get("ioa", False) or True)

        children_json = aggregate_collapsed_children(children_json)

        dc = desc_count(uuid)
        subtree_signal = (uuid in ioa_proc_uuids) or (uuid in rpc_path_procs) or any(child_signals)
        node = {
            "_id":      nid(),
            "uuid":     uuid,
            "name":     name,
            "full_path": fpath,
            "cmd":      cmd,
            "ts":       ts,
            "ts_end":   "",
            "pre_obs":  preob,
            "is_ioa":   uuid in ioa_proc_uuids,
            "ioa_tags": sorted(ioa_tag_map.get(uuid, [])),
            "group":    False,
            "group_count": None,
            "net":      net_connections.get(uuid, []),
            "files":    [f for f in file_per_proc.get(uuid, []) if f.get("type") in ("CreatedFileEdge", "FileWriteEdge")],
            "children": children_json,
            # auto-collapse big subtrees beyond depth 2
            "_open":    not (dc > 40 and depth > 1),
        }
        if depth > 0 and children_json and not subtree_signal:
            node["_open"] = False
        return node, subtree_signal

    root_nodes = [make_node(r)[0] for r in roots]
    root_info = _root_info(inc_root, proc_meta, parent_names)

    return {
        "id":             fname.replace(".jsonl", ""),
        "file":           fname,
        "host":           incident_meta.get("host", agent_id),
        "host_short":     incident_meta.get("host", agent_id),
        "severity":       incident_meta.get("severity", "unknown"),
        "iip_ts":         incident_meta.get("iip_ts", ""),
        "root_label":     inc_root,
        "alert_count":    incident_meta.get("alert_count", 0),
        "tactic_coverage":incident_meta.get("tactic_coverage", 0),
        "proc_count":     len(proc_uuids),
        "ioa_count":      len(ioa_proc_uuids),
        "ioa_edge_count": incident_meta.get("ioa_edge_count", 0),
        "roots":          root_nodes,
        "extra_edges":    extra_edges,
        "file_nodes":     file_nodes,
        "root_short":     _root_short(inc_root),
        "root_type":      inc_root.split(":")[0] if inc_root else "",
        "root_name":      root_info["name"],
        "root_detail":    root_info["detail"],
        "root_icon":      root_info["icon"],
    }

# ── HTML template ───────────────────────────────────────────────

HTML = r"""<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ThreatGraph · Process Tree</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0d1117;--surf:#161b22;--surf2:#1c2128;
  --bd:#30363d;--bd2:#21262d;
  --tx:#e6edf3;--tx2:#848d97;--tx3:#6e7681;
  --ioa:#f85149;--ioa-bg:rgba(248,81,73,.12);
  --crit:#f85149;--high:#e3b341;--med:#3fb950;--low:#58a6ff;
  --acc:#2f81f7;
  --mono:'Cascadia Code','JetBrains Mono',Consolas,monospace;
}
html,body{height:100%;overflow:hidden;background:var(--bg);color:var(--tx);
  font:13px/1.5 'Segoe UI',system-ui,sans-serif}

/* ── Layout ── */
#app{display:grid;height:100vh;
  grid-template:"hdr hdr hdr" 48px "sb  cvs det" 1fr / 240px 1fr 340px}
header{grid-area:hdr;display:flex;align-items:center;gap:14px;padding:0 16px;
  background:var(--surf);border-bottom:1px solid var(--bd);z-index:20}
#sidebar{grid-area:sb;overflow-y:auto;background:var(--surf);
  border-right:1px solid var(--bd)}
#canvas-wrap{grid-area:cvs;position:relative;overflow:hidden;background:var(--bg)}
#detail{grid-area:det;overflow-y:auto;background:var(--surf);
  border-left:1px solid var(--bd)}
#canvas{width:100%;height:100%;display:block}

/* ── Header ── */
.logo{display:flex;align-items:center;gap:8px;font-weight:600;font-size:14px}
.logo-dot{width:7px;height:7px;border-radius:50%;background:var(--crit);
  box-shadow:0 0 8px var(--crit)}
.hdr-stat{margin-left:auto;font-size:11px;color:var(--tx2)}
.hdr-btn{background:none;border:1px solid var(--bd);color:var(--tx2);
  border-radius:5px;padding:3px 10px;cursor:pointer;font-size:11px;
  transition:all .15s}
.hdr-btn:hover{border-color:var(--tx2);color:var(--tx)}
.hdr-btn.on{border-color:var(--acc);color:var(--acc);background:rgba(47,129,247,.08)}

/* ── Sidebar ── */
.sb-hdr{padding:10px 14px 6px;font-size:10px;font-weight:600;
  letter-spacing:.1em;color:var(--tx3);text-transform:uppercase}
.ic{padding:9px 14px;border-bottom:1px solid var(--bd2);cursor:pointer;
  transition:background .1s;user-select:none}
.ic:hover{background:rgba(255,255,255,.04)}
.ic.active{background:rgba(47,129,247,.1);border-left:2px solid var(--acc);
  padding-left:12px}
.ic-r1{display:flex;align-items:center;gap:6px;margin-bottom:2px}
.sev-dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.sev-dot.critical{background:var(--crit);box-shadow:0 0 5px var(--crit)}
.sev-dot.high{background:var(--high);box-shadow:0 0 5px var(--high)}
.sev-dot.medium{background:var(--med)}
.sev-dot.low{background:var(--low)}
.ic-host{font-weight:600;font-size:10.5px;font-family:var(--mono);word-break:break-all}
.ic-sev{margin-left:auto;font-size:10px;font-weight:600;padding:1px 6px;
  border-radius:8px}
.ic-sev.critical{background:rgba(248,81,73,.2);color:var(--crit)}
.ic-sev.high{background:rgba(227,179,65,.15);color:var(--high)}
.ic-sev.medium{background:rgba(63,185,80,.12);color:var(--med)}
.ic-sev.low{background:rgba(88,166,255,.12);color:var(--low)}
.ic-ts{font-size:11px;color:var(--tx2);font-family:var(--mono)}
.ic-root{font-size:10.5px;color:var(--tx3);font-family:var(--mono);
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
  margin-top:2px;display:flex;align-items:center;gap:4px}
.ic-root-wrap{margin-top:2px}
.ic-root-main{font-size:10.5px;color:var(--tx);font-family:var(--mono);display:flex;align-items:center;gap:4px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ic-root-detail{font-size:10px;color:var(--tx3);font-family:var(--mono);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;padding-left:16px}
.ic-root-proc{color:#58a6ff}.ic-root-path{color:#a855f7}
.ic-stats{display:flex;gap:10px;margin-top:4px;font-size:11px;color:var(--tx3)}
.ioa-c{color:var(--ioa)}

/* ── Zoom controls ── */
#zoom-ctrl{position:absolute;bottom:20px;right:20px;display:flex;flex-direction:column;
  gap:4px;z-index:10}
.zb{width:28px;height:28px;background:var(--surf);border:1px solid var(--bd);
  border-radius:5px;color:var(--tx2);cursor:pointer;font-size:14px;
  display:flex;align-items:center;justify-content:center;
  transition:all .15s}
.zb:hover{background:var(--surf2);border-color:var(--acc);color:var(--tx)}

/* ── Legend ── */
#legend{position:absolute;bottom:20px;left:14px;background:rgba(22,27,34,.88);
  border:1px solid var(--bd2);border-radius:6px;padding:8px 10px;
  font-size:10.5px;color:var(--tx3);z-index:10;backdrop-filter:blur(4px)}
.leg-title{font-size:9px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;
  color:var(--tx3);margin-bottom:5px}
.leg-row{display:flex;align-items:center;gap:6px;margin-bottom:3px}
.leg-circ{width:9px;height:9px;border-radius:50%;flex-shrink:0}
.leg-line{width:22px;height:2px;flex-shrink:0;border-radius:1px}
.leg-label{color:var(--tx2)}

/* ── SVG tree styles ── */
.link{fill:none;stroke:#1e3a5f;stroke-width:1;opacity:.65}
.nd-circle{cursor:pointer;transition:r .15s}
.nc-normal{fill:#162032;stroke:#3b5e8a;stroke-width:1.5}
.nc-ioa{fill:#4a0f0d;stroke:var(--ioa);stroke-width:2}
.nc-preobs{fill:#1a2230;stroke:#3d4f63;stroke-width:1.5;stroke-dasharray:3,2}
.nc-group{fill:none;stroke:#4b5563;stroke-width:1.5;stroke-dasharray:4,2}
.nc-leaf{fill:#162032;stroke:#2d4460;stroke-width:1.2}
.nc-root{fill:#0d2644;stroke:var(--acc);stroke-width:2}
.nc-file{fill:#2b1625;stroke:#f97316;stroke-width:1.4}
.nc-net{fill:#0f1f38;stroke:#3b82f6;stroke-width:1.4}
.nd-name{font:600 11px var(--mono);fill:var(--tx);dominant-baseline:middle;
  pointer-events:none}
.nd-name-ioa{fill:var(--ioa)}
.nd-name-preobs{fill:var(--tx3);font-style:italic}
.nd-ts{font:10px var(--mono);fill:var(--tx3);dominant-baseline:middle;
  pointer-events:none}
.nd-star{font:bold 9px sans-serif;fill:var(--ioa);dominant-baseline:middle;
  pointer-events:none}
.nd-badge{font:bold 9px var(--mono);dominant-baseline:middle;
  text-anchor:middle;fill:#6b7280;pointer-events:none}
.nd-grp-cnt{font:bold 8px var(--mono);fill:var(--acc);dominant-baseline:middle;
  text-anchor:middle;pointer-events:none}
.nd-caret{font:9px sans-serif;fill:var(--tx3);dominant-baseline:middle;
  cursor:pointer}
.nd-hover rect{fill:transparent;pointer-events:fill}
.nd-hover:hover rect{fill:rgba(255,255,255,.04)}
.nd-sel rect{fill:rgba(47,129,247,.08)!important}
/* extra edge types */
.ex-TargetProcessEdge{stroke:#f85149;stroke-width:2;stroke-dasharray:none;opacity:.8}
.ex-ProcessCPEdge{stroke:#e3b341;stroke-width:1.5;stroke-dasharray:5,3;opacity:.7}
.ex-RPCTriggerEdge{stroke:#06b6d4;stroke-width:1.5;stroke-dasharray:6,3;opacity:.7}
.ex-ConnectEdge{stroke:#3b82f6;stroke-width:1.2;stroke-dasharray:4,3;opacity:.6}
/* net endpoint node */
.net-node circle{fill:#0f1f38;stroke:#3b82f6;stroke-width:1.2}
.net-label{font:9.5px var(--mono);fill:#3b82f6;dominant-baseline:middle}
/* file endpoint node */
.file-node polygon{stroke-width:1.5}
.file-label{font:9.5px var(--mono);dominant-baseline:middle;pointer-events:none}
.ex-ImageLoadEdge{stroke:#a855f7;stroke-width:1.2;stroke-dasharray:5,3;opacity:.65}
.ex-CreatedFileEdge{stroke:#f97316;stroke-width:1.3;opacity:.65}
.ex-FileWriteEdge{stroke:#fb923c;stroke-width:1.3;opacity:.65}
.ex-FileAccessEdge{stroke:#84cc16;stroke-width:1;stroke-dasharray:4,3;opacity:.6}

/* ── Detail panel ── */
.det-ph{display:flex;flex-direction:column;align-items:center;justify-content:center;
  height:100%;gap:8px;opacity:.4;color:var(--tx3);font-size:12px}
.det-ph svg{opacity:.5}
.det-hdr{padding:14px 16px 10px;border-bottom:1px solid var(--bd)}
.det-name{font:600 15px var(--mono);color:var(--tx);word-break:break-all}
.det-name.ioa{color:#ff7b72}
.det-badges{display:flex;gap:5px;flex-wrap:wrap;margin-top:6px}
.badge{font-size:10px;padding:2px 7px;border-radius:4px;font-weight:500}
.badge-ioa{background:var(--ioa-bg);color:var(--ioa);border:1px solid rgba(248,81,73,.25)}
.badge-preobs{background:rgba(255,255,255,.06);color:var(--tx2)}
.badge-group{background:rgba(47,129,247,.12);color:var(--acc)}
.det-sec{padding:10px 16px;border-bottom:1px solid var(--bd2)}
.det-sec-t{font:600 10px sans-serif;letter-spacing:.08em;text-transform:uppercase;
  color:var(--tx3);margin-bottom:6px}
.det-kv{display:grid;grid-template-columns:90px 1fr;gap:3px 6px;font-size:11.5px}
.det-k{color:var(--tx2)}
.det-v{color:var(--tx);font-family:var(--mono);word-break:break-all}
.det-cmd{font:11.5px var(--mono);color:var(--tx);background:var(--bg);
  border:1px solid var(--bd2);border-radius:5px;padding:7px 9px;
  word-break:break-all;line-height:1.65;margin-top:4px}
.ioa-tag{display:inline-block;font-size:10.5px;padding:2px 7px;border-radius:10px;
  background:var(--ioa-bg);color:var(--ioa);border:1px solid rgba(248,81,73,.2);
  margin:2px 3px 2px 0}
.edge-list{display:flex;flex-direction:column;gap:3px}
.edge-item{background:var(--bg);border:1px solid var(--bd2);border-radius:4px;
  padding:4px 8px;font-size:11px}
.edge-item.hot{border-color:rgba(248,81,73,.35);background:var(--ioa-bg)}
.edge-dst{font-family:var(--mono);color:var(--tx);word-break:break-all}
.edge-ts{font-size:10px;color:var(--tx3);margin-top:1px}

/* scrollbar */
::-webkit-scrollbar{width:5px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--bd);border-radius:3px}
</style>
</head>
<body>
<div id="app">

<header>
  <div class="logo"><span class="logo-dot"></span>ThreatGraph</div>
  <span style="color:var(--tx3);font-size:12px">Incident Process Tree</span>
  <span class="hdr-stat" id="hdr-stat"></span>
  <button class="hdr-btn" onclick="toggleAll(true)">Expand All</button>
  <button class="hdr-btn" onclick="toggleAll(false)">Collapse All</button>
  <button class="hdr-btn" onclick="fitView()">Fit</button>
</header>

<aside id="sidebar">
  <div class="sb-hdr">Incidents</div>
  <div id="ilist"></div>
</aside>

<div id="canvas-wrap">
  <svg id="canvas"></svg>
  <div id="zoom-ctrl">
    <button class="zb" onclick="doZoom(1.3)" title="Zoom in">+</button>
    <button class="zb" onclick="doZoom(0.77)" title="Zoom out">−</button>
    <button class="zb" onclick="fitView()" title="Fit to screen" style="font-size:11px">⊡</button>
  </div>
  <div id="legend">
    <div class="leg-title">Nodes</div>
    <div class="leg-row"><span class="leg-circ" style="background:#162032;border:1.5px solid #3b5e8a"></span><span class="leg-label">Process</span></div>
    <div class="leg-row"><span class="leg-circ" style="background:#4a0f0d;border:2px solid #f85149;box-shadow:0 0 4px #f85149"></span><span class="leg-label">IOA Process</span></div>
    <div class="leg-row"><span class="leg-circ" style="background:#0d2644;border:2px solid #2f81f7"></span><span class="leg-label">Root</span></div>
    <div class="leg-row"><span class="leg-circ" style="background:none;border:1.5px dashed #4b5563"></span><span class="leg-label">Grouped ×N</span></div>
    <div class="leg-title" style="margin-top:6px">Tree Trunk</div>
    <div class="leg-row"><div class="leg-line" style="background:#1e3a5f;opacity:.9"></div><span class="leg-label">Parent → Child</span></div>
    <div class="leg-row"><span class="leg-label">N = Network</span></div>
    <div class="leg-row"><span class="leg-label">L = LoadImage</span></div>
    <div class="leg-row"><span class="leg-label">W = Write / Create / Access</span></div>
    <div class="leg-title" style="margin-top:6px">Overlay Edges</div>
    <div class="leg-row"><button class="hdr-btn on" id="edge-toggle-TargetProcessEdge" onclick="toggleEdgeType('TargetProcessEdge')">Inject/Target</button></div>
    <div class="leg-row"><button class="hdr-btn on" id="edge-toggle-ProcessCPEdge" onclick="toggleEdgeType('ProcessCPEdge')">Code Path</button></div>
    <div class="leg-row"><button class="hdr-btn on" id="edge-toggle-RPCTriggerEdge" onclick="toggleEdgeType('RPCTriggerEdge')">RPC Trigger</button></div>
  </div>
</div>

<aside id="detail">
  <div class="det-ph" id="det-ph">
    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><path d="M12 8v4l2 2"/></svg>
    <span>Click a node to inspect</span>
  </div>
  <div id="det-body" style="display:none"></div>
</aside>

</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.9.0/d3.min.js" crossorigin="anonymous"></script>
<script>
'use strict';
const DATA = __DATA__;

// ── constants ─────────────────────────────────────────────────
const NODE_DY = 22;   // vertical spacing between siblings
const NODE_DX = 210;  // horizontal spacing between levels

const EDGE_STYLE = {
  TargetProcessEdge: {stroke:'#f85149', sw:2,   dash:'none', label:'Inject/Target'},
  RPCTriggerEdge:    {stroke:'#06b6d4', sw:1.5, dash:'6,3',  label:'RPC Trigger'},
  ProcessCPEdge:     {stroke:'#e3b341', sw:1.5, dash:'5,3',  label:'Code Path'},
  ConnectEdge:       {stroke:'#3b82f6', sw:1.2, dash:'4,3',  label:'Network'},
  ImageLoadEdge:     {stroke:'#a855f7', sw:1.2, dash:'5,3',  label:'DLL Load'},
  CreatedFileEdge:   {stroke:'#f97316', sw:1.3, dash:'none', label:'Create File'},
  FileWriteEdge:     {stroke:'#fb923c', sw:1.3, dash:'none', label:'Write File'},
  FileAccessEdge:    {stroke:'#84cc16', sw:1.0, dash:'4,3',  label:'File Access'},
};

const OVERLAY_EDGE_TYPES = ['TargetProcessEdge', 'ProcessCPEdge', 'RPCTriggerEdge'];

// ── state ─────────────────────────────────────────────────────
let svg, mainG, linkG, extraG, nodeG, netG, fileG;
let zoomBeh, currentInc = null, selEl = null, selNode = null;
let currentPosMap = {};
const edgeVisibility = Object.fromEntries(OVERLAY_EDGE_TYPES.map(t => [t, true]));

// ── sidebar ───────────────────────────────────────────────────
function initSidebar() {
  const list = document.getElementById('ilist');
  DATA.incidents.forEach((inc, i) => {
    const ts = inc.iip_ts.slice(0, 16).replace('T', ' ');
    const rootName = inc.root_name || inc.root_short;
    const rootDetail = inc.root_detail || inc.root_label || '';
    const div = document.createElement('div');
    div.className = 'ic';
    div.innerHTML = `
      <div class="ic-r1">
        <span class="sev-dot ${inc.severity}"></span>
        <span class="ic-host">${inc.host_short}</span>
        <span class="ic-sev ${inc.severity}">${inc.severity.toUpperCase()}</span>
      </div>
      <div class="ic-root-wrap" title="${inc.root_label}">
        <div class="ic-root-main ic-root-${inc.root_type}">
          <span style="opacity:.7">${rootGlyph(inc.root_icon)}</span>
          <span>${rootName}</span>
        </div>
        <div class="ic-root-detail">${rootDetail}</div>
      </div>
      <div class="ic-ts">${ts}</div>
      <div class="ic-stats">
        <span>⬡ ${inc.proc_count}</span>
        ${inc.ioa_count > 0 ? `<span class="ioa-c">★ ${inc.ioa_count} IOA</span>` : ''}
        ${inc.alert_count > 0 ? `<span>⚑ ${inc.alert_count}</span>` : ''}
      </div>`;
    div.addEventListener('click', () => {
      document.querySelectorAll('.ic').forEach(c => c.classList.remove('active'));
      div.classList.add('active');
      loadIncident(inc);
    });
    list.appendChild(div);
    if (i === 0) { div.classList.add('active'); }
  });
}

function rootGlyph(kind) {
  switch (kind) {
    case 'proc': return '⬢';
    case 'file': return '🗎';
    case 'net': return '◎';
    case 'reg': return '⌘';
    case 'domain': return '◌';
    default: return '◆';
  }
}

// ── SVG init ──────────────────────────────────────────────────
function initSVG() {
  svg = d3.select('#canvas');
  zoomBeh = d3.zoom().scaleExtent([0.03, 4])
    .on('zoom', e => mainG.attr('transform', e.transform));
  svg.call(zoomBeh)
     .on('dblclick.zoom', null);

  const defs = svg.append('defs');

  // Glow filter for IOA nodes
  const f = defs.append('filter').attr('id','glow-ioa')
    .attr('x','-80%').attr('y','-80%').attr('width','260%').attr('height','260%');
  f.append('feGaussianBlur').attr('in','SourceGraphic').attr('stdDeviation',3).attr('result','b');
  const fm = f.append('feMerge');
  fm.append('feMergeNode').attr('in','b');
  fm.append('feMergeNode').attr('in','SourceGraphic');

  mainG = svg.append('g').attr('class','main-g');
  linkG  = mainG.append('g').attr('class','link-layer');
  extraG = mainG.append('g').attr('class','extra-layer');
  netG   = mainG.append('g').attr('class','net-layer');
  fileG  = mainG.append('g').attr('class','file-layer');
  nodeG  = mainG.append('g').attr('class','node-layer');
}

// ── Load incident ─────────────────────────────────────────────
function loadIncident(inc) {
  currentInc = inc;
  selEl = null; selNode = null;
  document.getElementById('det-ph').style.display = 'flex';
  document.getElementById('det-body').style.display = 'none';
  document.getElementById('hdr-stat').textContent =
    `${inc.proc_count} processes · ${inc.ioa_count} IOA · IIP: ${inc.root_short}`;

  // Clear layers and restore toggle visibility
  linkG.selectAll('*').remove();
  extraG.selectAll('*').remove();
  netG.selectAll('*').remove();
  fileG.selectAll('*').remove();
  nodeG.selectAll('*').remove();

  // Build data: if multiple roots, wrap in synthetic
  const rootData = inc.roots.length === 1
    ? prep(inc.roots[0], 0)
    : {_id:-1, _synth:true, name:'', uuid:null, children: inc.roots.map(r=>prep(r,0))};

  const hier = d3.hierarchy(rootData, d => d._open !== false ? (d.children || null) : null);
  renderTree(hier, inc);
}

let _idSeq = 0;
function prep(node, depth) {
  node._depth = depth;
  if (!node._id) node._id = ++_idSeq;
  if (node.children) node.children.forEach(c => prep(c, depth+1));
  return node;
}

function hexagonPoints(r) {
  const top = Math.round(r * 1.02);
  const sideX = Math.round(r * 0.88);
  const midY = Math.round(r * 0.52);
  return `0,${-top} ${sideX},${-midY} ${sideX},${midY} 0,${top} ${-sideX},${midY} ${-sideX},${-midY}`;
}

function fileIconPath(r) {
  const w = r * 1.7;
  const h = r * 2.0;
  const x = -w / 2;
  const y = -h / 2;
  const fold = r * 0.55;
  return `M${x},${y} H${x + w - fold} L${x + w},${y + fold} V${y + h} H${x} Z M${x + w - fold},${y} V${y + fold} H${x + w}`;
}

function networkIconPath(r) {
  const globe = r * 0.88;
  const meridian = r * 0.42;
  const latMajor = r * 0.38;
  const latMinor = r * 0.22;
  return [
    `M0,${-globe} A${globe},${globe} 0 1 0 0,${globe} A${globe},${globe} 0 1 0 0,${-globe}`,
    `M0,${-globe} A${meridian},${globe} 0 1 1 0,${globe} A${meridian},${globe} 0 1 1 0,${-globe}`,
    `M${-globe},0 A${globe},${latMajor} 0 1 0 ${globe},0 A${globe},${latMajor} 0 1 0 ${-globe},0`,
    `M${-globe * 0.72},${-globe * 0.42} A${globe * 0.72},${latMinor} 0 1 0 ${globe * 0.72},${-globe * 0.42}`,
    `M${-globe * 0.72},${globe * 0.42} A${globe * 0.72},${latMinor} 0 1 0 ${globe * 0.72},${globe * 0.42}`,
  ].join(' ');
}

function rerenderCurrentIncident(preserveSelectionUuid=null) {
  if (!currentInc) return;
  const rootData = currentInc.roots.length === 1
    ? currentInc.roots[0]
    : {_id:-1, _synth:true, name:'', uuid:null, children: currentInc.roots};
  const hier = d3.hierarchy(rootData, d => d._open !== false ? (d.children || null) : null);
  linkG.selectAll('*').remove();
  extraG.selectAll('*').remove();
  netG.selectAll('*').remove();
  fileG.selectAll('*').remove();
  nodeG.selectAll('*').remove();
  renderTree(hier, currentInc);
  if (preserveSelectionUuid) {
    setTimeout(() => {
      const found = nodeG.selectAll('.nd').filter(n => n.data.uuid === preserveSelectionUuid);
      if (!found.empty()) selectNode(found.node(), found.datum().data);
    }, 20);
  }
}

function toggleCaret(nd, event) {
  event.stopPropagation();
  if (!nd.children) return;
  nd._open = (nd._open === false) ? true : false;
  rerenderCurrentIncident(nd.uuid || null);
}

// ── Render tree ───────────────────────────────────────────────
function renderTree(hier, inc) {
  const layout = d3.tree().nodeSize([NODE_DY, NODE_DX]);
  layout(hier);

  const nodes = hier.descendants().filter(d => !d.data._synth);
  const links = hier.links().filter(l => !l.source.data._synth);

  // Build position map: uuid → {x (horizontal), y (vertical)}
  const posMap = {};
  nodes.forEach(d => { if (d.data.uuid) posMap[d.data.uuid] = {x: d.y, y: d.x}; });
  currentPosMap = posMap;

  // ── draw links ──
  linkG.selectAll('.link').data(links, d => d.target.data._id)
    .join('path')
    .attr('class','link')
    .attr('d', d3.linkHorizontal().x(d => d.y).y(d => d.x));

  // ── draw extra edges (non-parent arcs) ──
  drawExtraEdges(inc.extra_edges, posMap);

  // ── draw overlay file edges (ImageLoad / FileAccess) ──
  drawFileNodes(inc.file_nodes, posMap);

  // ── draw process nodes ──
  const nodeEl = nodeG.selectAll('.nd').data(nodes, d => d.data._id)
    .join('g')
    .attr('class','nd')
    .attr('transform', d => `translate(${d.y},${d.x})`);

  nodeEl.each(function(d) { buildNode(d3.select(this), d, hier, inc); });

  // Fit after first render
  setTimeout(fitView, 50);
}

// ── Build a single node ───────────────────────────────────────
function buildNode(g, d, hier, inc) {
  const nd   = d.data;
  const nodeType = nd.node_type || 'proc';
  const isIoa  = nd.is_ioa && !nd.group;
  const isRoot = d.depth === 0 || (d.depth === 1 && d.parent && d.parent.data._synth);
  const isGroup = nd.group;
  const hasKids = d.children && d.children.length > 0;
  const hasColl = nd._open === false || (!nd._open && nd.children && nd.children.length);

  const r = isGroup ? 7 : isRoot ? 7 : isIoa ? 6 : 5;

  // Hover hit rect (wide, for easier clicking)
  const hitW = Math.min(nd.name.length * 7 + 60, 240);
  g.append('rect').attr('class','nd-hover')
   .attr('x', -r - 2).attr('y', -10)
   .attr('width', r + hitW).attr('height', 20)
   .attr('fill','transparent').attr('rx', 3);

  // Main circle
  let cls = 'nd-circle ';
  if (isGroup) cls += 'nc-group';
  else if (isIoa) cls += 'nc-ioa';
  else if (isRoot) cls += 'nc-root';
  else if (nd.pre_obs) cls += 'nc-preobs';
  else if (nodeType === 'file') cls += 'nc-file';
  else if (nodeType === 'net') cls += 'nc-net';
  else if (!hasKids && !hasColl) cls += 'nc-leaf';
  else cls += 'nc-normal';

  let mainShape;
  if (nodeType === 'file') {
    mainShape = g.append('path')
      .attr('d', fileIconPath(r))
      .attr('class', cls);
  } else if (nodeType === 'net') {
    mainShape = g.append('path')
      .attr('d', networkIconPath(r))
      .attr('class', cls)
      .attr('fill', 'none');
  } else {
    mainShape = g.append('polygon')
      .attr('points', hexagonPoints(r))
      .attr('class', cls);
  }
  if (isIoa) mainShape.attr('filter','url(#glow-ioa)');

  // Group count inside circle
  if (isGroup) {
    g.append('text').attr('class','nd-grp-cnt').attr('y', 0)
     .text(`×${nd.group_count}`);
  }

  // IOA star above circle
  if (isIoa) {
    g.append('text').attr('class','nd-star')
     .attr('x', r + 1).attr('y', -r - 2).text('★');
  }

  // Collapse caret (left of circle)
  if (!isGroup) {
    const caret = g.append('text').attr('class','nd-caret')
      .attr('x', -r - 6).attr('y', 1).attr('text-anchor','end');
    if (hasKids) caret.text('▼');
    else if (nd._open === false && nd.children) caret.text('▶');
    else caret.text('');
    if (nd.children) caret.style('cursor','pointer').on('click', (event) => toggleCaret(nd, event));
  }

  // Process name label
  const nameCls = 'nd-name' + (isIoa ? ' nd-name-ioa' : nd.pre_obs ? ' nd-name-preobs' : '');
  const maxNameLen = isGroup ? 0 : 24;
  const labelX = isGroup ? r + 4 : r + 8;
  if (!isGroup) {
    g.append('text').attr('class', nameCls)
     .attr('x', labelX).attr('y', nd.ts ? -4 : 1)
     .text(trunc(nd.name, maxNameLen || 24));
  } else {
    // Group: show name to the right of circle
    g.append('text').attr('class', 'nd-name')
     .attr('x', r + 5).attr('y', nd.ts ? -4 : 1)
     .text(trunc(nd.name, 22));
  }

  // Timestamp
  const showTs = nd._open === false && !!nd.ts;
  if (showTs) {
    const tsText = nd.ts_end && nd.ts_end !== nd.ts
      ? nd.ts.slice(11,19) + '–' + nd.ts_end.slice(11,19)
      : nd.ts.slice(11,19);
    g.append('text').attr('class','nd-ts')
     .attr('x', labelX).attr('y', 9)
     .text(tsText);
  }

  // Tooltip
  g.append('title').text(
    nd.name + (nd.cmd ? '\n' + nd.cmd.slice(0, 120) : '')
    + (nd.ts ? '\n' + nd.ts : '')
    + (isGroup ? `\n×${nd.group_count} instances` : '')
  );

  // Click: select only
  g.on('click', (event) => {
    event.stopPropagation();
    selectNode(g.node(), nd);
  });
}

// ── Extra edge arcs ───────────────────────────────────────────
function drawExtraEdges(edges, posMap) {
  if (!edges || !edges.length) return;
  edges.forEach(e => {
    if (!edgeVisibility[e.type]) return;
    const sp = posMap[e.src], dp = posMap[e.dst];
    if (!sp || !dp) return;
    const style = EDGE_STYLE[e.type] || EDGE_STYLE.ProcessCPEdge;

    // Control point: bow left / above to avoid overlapping tree
    const bow = Math.max(60, Math.abs(dp.y - sp.y) * 0.25);
    const cx = Math.min(sp.x, dp.x) - bow;
    const cy = (sp.y + dp.y) / 2;

    const path = extraG.append('path')
      .attr('fill','none')
      .attr('class', `ex-${e.type}`)
      .attr('d', `M${sp.x},${sp.y} Q${cx},${cy} ${dp.x},${dp.y}`);
    if (style.dash !== 'none') path.attr('stroke-dasharray', style.dash);

    path.append('title').text(`${style.label}: ${e.src.slice(0,8)} → ${e.dst.slice(0,8)}`);
  });
}

// ── Network endpoint nodes ────────────────────────────────────
function drawNetNodes(nodes, posMap) {
  // Collect all unique net connections
  const netMap = {}; // ip_port → [{uuid, ioa}]
  nodes.forEach(d => {
    const nd = d.data;
    if (nd.net && nd.net.length && nd.uuid) {
      nd.net.forEach(n => {
        if (!netMap[n.ip]) netMap[n.ip] = [];
        netMap[n.ip].push({uuid: nd.uuid, ioa: n.ioa});
      });
    }
  });

  if (!Object.keys(netMap).length) return;

  // Find rightmost x
  const maxX = d3.max(nodes, d => d.y) + NODE_DX * 0.6;

  // Stack net nodes vertically centered
  const ips = Object.keys(netMap);
  const totalH = ips.length * 30;
  const startY = -totalH / 2;

  ips.forEach((ip, i) => {
    const nx = maxX + 40;
    const ny = startY + i * 30;
    const isIoa = netMap[ip].some(n => n.ioa);

    const ng = netG.append('g').attr('class','net-node')
      .attr('transform', `translate(${nx},${ny})`);
    ng.append('circle').attr('r', 5)
      .style('stroke', isIoa ? '#f85149' : '#3b82f6')
      .style('fill', isIoa ? 'rgba(248,81,73,.1)' : '#0f1f38');
    ng.append('text').attr('class','net-label')
      .attr('x', 9).attr('y', 1).text(ip)
      .style('fill', isIoa ? '#f85149' : '#3b82f6');
    if (isIoa) ng.select('circle').attr('filter','url(#glow-ioa)');

    // Draw lines from source procs to this net node (kept in netG so they hide together)
    netMap[ip].forEach(({uuid, ioa}) => {
      const sp = posMap[uuid];
      if (!sp) return;
      const cx = (sp.x + nx) / 2 + 20;
      const cy = (sp.y + ny) / 2;
      netG.append('path')
        .attr('fill','none')
        .attr('class','ex-ConnectEdge')
        .attr('d', `M${sp.x},${sp.y} Q${cx},${cy} ${nx},${ny}`);
    });
  });
}

// ── File endpoint nodes ───────────────────────────────────────
function drawFileNodes(fileNodes, posMap) {
  fileG.selectAll('*').remove();
  if (!fileNodes || !fileNodes.length) return;

  const visible = fileNodes
    .map(fn => ({
      ...fn,
      edges: fn.edges.filter(e => edgeVisibility[e.type])
    }))
    .filter(fn => fn.edges.length > 0);
  if (!visible.length) return;

  // Position: right column, separate from net nodes
  const maxX = d3.max(Object.values(posMap), d => d.x) || 0;
  const fileColX = maxX + NODE_DX * 0.65;
  const spacing = 26;
  const totalH = visible.length * spacing;
  const startY = -totalH / 2;

  visible.forEach((fn, i) => {
    const fx = fileColX;
    const fy = startY + i * spacing;
    const isIoa = fn.ioa;

    const fg = fileG.append('g')
      .attr('class', 'file-node')
      .attr('transform', `translate(${fx},${fy})`);

    fg.append('polygon')
      .attr('points', '0,-6 7,0 0,6 -7,0')
      .attr('fill', isIoa ? 'rgba(248,81,73,.12)' : '#110f1c')
      .attr('stroke', isIoa ? '#f85149' : '#a855f7')
      .attr('stroke-width', isIoa ? 2 : 1.5);
    if (isIoa) fg.select('polygon').attr('filter', 'url(#glow-ioa)');

    fg.append('text').attr('class', 'file-label')
      .attr('x', 11).attr('y', 1)
      .style('fill', isIoa ? '#f85149' : '#a855f7')
      .text(trunc(fn.name, 30));

    fg.append('title').text(fn.path);

    // Click: show detail
    fg.style('cursor', 'pointer')
      .on('click', (event) => {
        event.stopPropagation();
        showFileDetail(fn);
      });

    // Draw arcs to connected procs
    fn.edges.forEach(({uuid, type, ioa}) => {
      const sp = posMap[uuid];
      if (!sp) return;
      const style = EDGE_STYLE[type] || EDGE_STYLE.ImageLoadEdge;
      const isLoad = type === 'ImageLoadEdge'; // direction: file → proc

      const bow = Math.max(40, Math.abs(fx - sp.x) * 0.18);
      const cx = (sp.x + fx) / 2;
      const cy = Math.min(sp.y, fy) - bow;

      // ImageLoadEdge: arc from file to proc; others: proc to file
      const [x1, y1, x2, y2] = isLoad
        ? [fx, fy, sp.x, sp.y]
        : [sp.x, sp.y, fx, fy];

      const arc = fileG.append('path')
        .attr('fill', 'none')
        .attr('stroke', (ioa || isIoa) ? '#f85149' : style.stroke)
        .attr('stroke-width', style.sw)
        .attr('opacity', 0.62)
        .attr('d', `M${x1},${y1} Q${cx},${cy} ${x2},${y2}`);
      if (style.dash && style.dash !== 'none') arc.attr('stroke-dasharray', style.dash);
      arc.append('title').text(`${style.label}: ${fn.name}`);
    });
  });
}

function toggleEdgeType(type) {
  edgeVisibility[type] = !edgeVisibility[type];
  const btn = document.getElementById(`edge-toggle-${type}`);
  if (btn) btn.classList.toggle('on', edgeVisibility[type]);
  if (currentInc) {
    const rootData = currentInc.roots.length === 1
      ? currentInc.roots[0]
      : {_id:-1, _synth:true, name:'', uuid:null, children: currentInc.roots};
    const hier = d3.hierarchy(rootData, d => d._open !== false ? (d.children || null) : null);
    linkG.selectAll('*').remove();
    extraG.selectAll('*').remove();
    netG.selectAll('*').remove();
    fileG.selectAll('*').remove();
    nodeG.selectAll('*').remove();
    renderTree(hier, currentInc);
  }
}

function showFileDetail(fn) {
  document.getElementById('det-ph').style.display = 'none';
  const body = document.getElementById('det-body');
  body.style.display = 'block';
  body.innerHTML = '';

  const hdr = el('div', 'det-hdr', body);
  el('div', 'det-name' + (fn.ioa ? ' ioa' : ''), hdr).textContent = fn.name;
  const badges = el('div', 'det-badges', hdr);
  if (fn.ioa) el('span', 'badge badge-ioa', badges).textContent = '★ IOA';

  const sec = mkSec('File Path', body);
  el('div', 'det-cmd', sec).textContent = fn.path;

  if (fn.edges.length) {
    const esec = mkSec(`Process Connections (${fn.edges.length})`, body);
    const lst = el('div', 'edge-list', esec);
    fn.edges.forEach(({uuid, type, ioa}) => {
      const item = el('div', 'edge-item' + (ioa ? ' hot' : ''), lst);
      const style = EDGE_STYLE[type] || {};
      el('div', 'edge-dst', item).textContent = (style.label || type) + ' ← ' + uuid.slice(0, 16) + '…';
    });
  }
}

// ── Select node ───────────────────────────────────────────────
function selectNode(el, nd) {
  if (selEl) d3.select(selEl).classed('nd-sel', false);
  selEl = el;
  selNode = nd;
  d3.select(el).classed('nd-sel', true);
  showDetail(nd);
}

// ── Detail panel ──────────────────────────────────────────────
function showDetail(nd) {
  document.getElementById('det-ph').style.display = 'none';
  const body = document.getElementById('det-body');
  body.style.display = 'block';
  body.innerHTML = '';

  // Header
  const hdr = el('div', 'det-hdr', body);
  el('div', 'det-name' + (nd.is_ioa ? ' ioa' : ''), hdr).textContent = nd.name;
  const badges = el('div', 'det-badges', hdr);
  if (nd.is_ioa) el('span','badge badge-ioa', badges).textContent = '★ IOA';
  if (nd.group) el('span','badge badge-group', badges).textContent = `×${nd.group_count} instances`;
  if (nd.pre_obs) el('span','badge badge-preobs', badges).textContent = 'pre-observation';

  // Info
  if (nd.uuid || nd.ts) {
    const sec = mkSec('Process Info', body);
    const kv = el('div','det-kv', sec);
    if (nd.uuid)      addKV(kv, 'UUID',  nd.uuid);
    if (nd.full_path) addKV(kv, 'Image', nd.full_path);
    if (nd.ts) {
      const tv = nd.ts_end && nd.ts_end !== nd.ts ? `${nd.ts}  →  ${nd.ts_end}` : nd.ts;
      addKV(kv, 'Time (UTC)', tv);
    }
  }
  if (nd.node_type === 'file' || nd.node_type === 'net') {
    const sec = mkSec('Node Info', body);
    const kv = el('div','det-kv', sec);
    addKV(kv, 'Type', nd.node_type);
    addKV(kv, 'Edge', nd.edge_type || '');
    if (nd.full_path) addKV(kv, nd.node_type === 'net' ? 'Endpoint' : 'Path', nd.full_path);
  }
  if (nd.cmd) {
    const sec = mkSec('Command Line', body);
    el('div','det-cmd', sec).textContent = nd.cmd;
  }
  if (nd.ioa_tags && nd.ioa_tags.length) {
    const sec = mkSec('IOA Tags', body);
    nd.ioa_tags.forEach(t => el('span','ioa-tag', sec).textContent = t);
  }
  if (nd.net && nd.net.length) {
    const sec = mkSec(`Network Connections (${nd.net.length})`, body);
    const lst = el('div','edge-list', sec);
    nd.net.slice(0, 20).forEach(n => {
      const item = el('div', 'edge-item' + (n.ioa ? ' hot' : ''), lst);
      el('div','edge-dst', item).textContent = '→ ' + n.ip;
    });
  }
  if (nd.files && nd.files.length) {
    const sec = mkSec(`File Connections (${nd.files.length})`, body);
    const lst = el('div', 'edge-list', sec);
    nd.files.slice(0, 20).forEach(f => {
      const item = el('div', 'edge-item' + (f.ioa ? ' hot' : ''), lst);
      const lbl = {ImageLoadEdge:'↙ Load', CreatedFileEdge:'→ Create',
                   FileWriteEdge:'→ Write', FileAccessEdge:'→ Access'}[f.type] || f.type;
      el('div', 'edge-dst', item).textContent = lbl + ' ' + f.name;
      el('div', 'edge-ts',  item).textContent = f.path;
    });
  }
}

// ── Zoom & fit ────────────────────────────────────────────────
function fitView() {
  const bb = mainG.node().getBBox();
  if (!bb.width) return;
  const cvs = document.getElementById('canvas');
  const w = cvs.clientWidth, h = cvs.clientHeight;
  const pad = 60;
  const sc = Math.min((w - pad*2) / bb.width, (h - pad*2) / bb.height, 1.5);
  const tx = w/2 - sc*(bb.x + bb.width/2);
  const ty = h/2 - sc*(bb.y + bb.height/2);
  svg.transition().duration(450)
     .call(zoomBeh.transform, d3.zoomIdentity.translate(tx, ty).scale(sc));
}
function doZoom(factor) {
  svg.transition().duration(200).call(zoomBeh.scaleBy, factor);
}

// ── Toggle all ────────────────────────────────────────────────
function toggleAll(open) {
  function walk(node) {
    if (node.children) {
      node._open = open;
      node.children.forEach(walk);
    }
  }
  if (!currentInc) return;
  currentInc.roots.forEach(walk);
  const rootData = currentInc.roots.length === 1
    ? currentInc.roots[0]
    : {_id:-1, _synth:true, name:'', uuid:null, children: currentInc.roots};
  const hier = d3.hierarchy(rootData,
    d => d._open !== false ? (d.children || null) : null);
  linkG.selectAll('*').remove();
  extraG.selectAll('*').remove();
  netG.selectAll('*').remove();
  fileG.selectAll('*').remove();
  nodeG.selectAll('*').remove();
  renderTree(hier, currentInc);
  setTimeout(fitView, 100);
}

// ── Helpers ───────────────────────────────────────────────────
function el(tag, cls, parent) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (parent) parent.appendChild(e);
  return e;
}
function mkSec(title, parent) {
  const sec = el('div','det-sec', parent);
  el('div','det-sec-t', sec).textContent = title;
  return sec;
}
function addKV(container, k, v) {
  el('span','det-k', container).textContent = k;
  el('span','det-v', container).textContent = v;
}
function trunc(s, n) {
  return s && s.length > n ? s.slice(0, n-1) + '…' : (s || '');
}

// ── Init ──────────────────────────────────────────────────────
initSVG();
initSidebar();
if (DATA.incidents.length > 0) loadIncident(DATA.incidents[0]);
</script>
</body>
</html>
"""

# ── CLI & main ──────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("subgraphs", nargs="*", metavar="subgraph.jsonl")
    p.add_argument("--all-in-dir", default="")
    p.add_argument("--out", default="viewer.html")
    p.add_argument("--es-url",  default="https://127.0.0.1:9200")
    p.add_argument("--es-user", default="elastic")
    p.add_argument("--es-pass", default="__nmRSxBG2Hzr15uWCoI")
    p.add_argument("--es-ca",   default=os.path.expanduser(
        "~/elasticsearch-8.15.0/config/certs/http_ca.crt"))
    p.add_argument("--es-index", default="edr-offline-ls-2026.03.04")
    return p.parse_args()

def main():
    args = parse_args()
    files = list(args.subgraphs)
    if args.all_in_dir:
        d = args.all_in_dir
        for fname in sorted(os.listdir(d)):
            if fname.startswith("subgraph_") and fname.endswith(".jsonl"):
                files.append(os.path.join(d, fname))
    if not files:
        print("No subgraph files."); sys.exit(1)

    cfg = {"url": args.es_url, "index": args.es_index,
           "user": args.es_user, "passwd": args.es_pass,
           "ssl": make_ssl_ctx(args.es_ca)}

    print(f"Processing {len(files)} subgraph(s)…")
    incidents = []
    for path in files:
        try:
            incidents.append(build_incident_json(path, cfg))
        except Exception as e:
            import traceback
            print(f"  ERROR {path}: {e}", file=sys.stderr)
            traceback.print_exc()

    html = HTML.replace("__DATA__", json.dumps(
        {"incidents": incidents}, ensure_ascii=False, separators=(",", ":")))
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"\n→ {args.out}  ({os.path.getsize(args.out)//1024} KB, {len(incidents)} incidents)")

if __name__ == "__main__":
    main()
