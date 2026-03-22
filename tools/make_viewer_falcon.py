#!/usr/bin/env python3
"""
Falcon-inspired incident viewer generator.

This script reuses the incident extraction/data shaping logic from
`make_viewer.py`, but emits a denser, more responsive SOC-style viewer with:

- preserved zoom state across rerenders
- compact, keyboard-accessible controls
- responsive sidebar/detail panels
- restrained enterprise dark styling with Falcon-inspired visual language
- optional local D3 bundling for fully offline HTML output
"""

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path


_BASE_PATH = Path(__file__).with_name("make_viewer.py")
_SPEC = importlib.util.spec_from_file_location("make_viewer_base", _BASE_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError(f"Unable to load base viewer module: {_BASE_PATH}")
_BASE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_BASE)


make_ssl_ctx = _BASE.make_ssl_ctx
fetch_proc_meta = _BASE.fetch_proc_meta
PROCESS_OVERLAY_EDGE_TYPES = (
    "TargetProcessEdge",
    "ProcessCPEdge",
    "RPCTriggerEdge",
)


def _normalize_node_times(node):
    ts = node.get("ts") or ""
    ts_end = node.get("ts_end") or ""
    if ts and ts_end and ts_end < ts:
        node["ts"], node["ts_end"] = ts_end, ts
    for child in node.get("children", []) or []:
        _normalize_node_times(child)


def _dedupe_process_overlay_edges(edges):
    ordered = []
    seen = {}
    for edge in edges or []:
        edge_type = edge.get("type")
        if edge_type not in PROCESS_OVERLAY_EDGE_TYPES:
            continue
        key = (edge.get("src"), edge.get("dst"), edge_type)
        current = seen.get(key)
        if current is None:
            current = {
                "src": edge.get("src"),
                "dst": edge.get("dst"),
                "type": edge_type,
                "ioa": bool(edge.get("ioa")),
                "count": 1,
            }
            seen[key] = current
            ordered.append(current)
            continue
        current["ioa"] = current["ioa"] or bool(edge.get("ioa"))
        current["count"] += 1
    return ordered


def build_incident_json(path, cfg):
    original = _BASE.fetch_proc_meta
    _BASE.fetch_proc_meta = fetch_proc_meta
    try:
        incident = _BASE.build_incident_json(path, cfg)
    finally:
        _BASE.fetch_proc_meta = original
    for root in incident.get("roots", []) or []:
        _normalize_node_times(root)
    incident["extra_edges"] = _dedupe_process_overlay_edges(incident.get("extra_edges", []))
    incident["file_nodes"] = []
    return incident


HTML = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>ThreatGraph · SOC Viewer</title>
<style>
*,
*::before,
*::after{box-sizing:border-box}

:root{
  --bg:#2f2e34;
  --bg-elev:#26252a;
  --bg-panel:#323136;
  --bg-panel-2:#37353b;
  --bg-canvas:#2f2e34;
  --line:#3f3e45;
  --line-2:#55535c;
  --line-soft:rgba(255,255,255,.04);
  --text:#eceef1;
  --text-2:#d4d8dd;
  --text-3:#a9afb7;
  --text-4:#737983;
  --accent:#df5a5e;
  --accent-2:#c74d50;
  --accent-soft:rgba(223,90,94,.12);
  --accent-text:#ffe0e1;
  --focus:#8796bb;
  --deep-sea:#a1a7af;
  --surf:#8c9ca8;
  --warm:#eb9049;
  --warm-text:#ffd1a5;
  --storm:#747a84;
  --cloud:#3b3a40;
  --proc-edge:#a7adb5;
  --rpc-edge:#8797a3;
  --node-fill:#d7dbe0;
  --node-fill-2:#c9ced4;
  --node-root-fill:#eef1f4;
  --node-root-stroke:#ffffff;
  --node-ioa-fill:#eb9049;
  --select-ring:#ff8f92;
  --crit:#dd575b;
  --attack:#d4ae36;
  --shadow:none;
  --panel-shadow:none;
  --radius:8px;
  --radius-sm:5px;
  --font-sans:'Segoe UI','Helvetica Neue',Arial,sans-serif;
  --font-mono:'SFMono-Regular',Consolas,'Liberation Mono',monospace;
}

html,body{
  height:100%;
  margin:0;
}

body{
  overflow:hidden;
  color:var(--text);
  background:var(--bg);
  font:14px/1.5 var(--font-sans);
}

button,
input,
select{
  font:inherit;
}

button{
  border:0;
  background:none;
  color:inherit;
}

button,
input,
select{
  outline:none;
}

button:focus-visible,
input:focus-visible,
select:focus-visible{
  box-shadow:0 0 0 2px rgba(31,32,36,.96), 0 0 0 4px rgba(236,0,0,.34);
}

.sr-only{
  position:absolute;
  width:1px;
  height:1px;
  padding:0;
  margin:-1px;
  overflow:hidden;
  clip:rect(0,0,0,0);
  white-space:nowrap;
  border:0;
}

#app{
  position:relative;
  height:100vh;
  display:grid;
  --sidebar-width:clamp(300px,24vw,348px);
  --detail-width:clamp(340px,27vw,408px);
  grid-template:
    "hdr hdr hdr" 64px
    "sb canvas det" minmax(0,1fr)
    / var(--sidebar-width) minmax(0,1fr) var(--detail-width);
  transition:grid-template-columns .2s ease;
}

body.sidebar-collapsed #app{
  --sidebar-width:0px;
}

.panel{
  min-height:0;
  background:var(--bg-panel);
  border:1px solid var(--line-soft);
  box-shadow:var(--panel-shadow);
}

#sidebar{
  grid-area:sb;
  background:#2b2c32;
  border-left:0;
  border-top:0;
  border-bottom:0;
  border-right:1px solid #4b4d56;
  display:flex;
  flex-direction:column;
  min-width:0;
  transition:transform .2s ease, opacity .2s ease, border-color .2s ease;
}

@media (min-width: 1121px){
  body.sidebar-collapsed #sidebar{
    transform:translateX(-16px);
    opacity:0;
    pointer-events:none;
    border-right-color:transparent;
  }
}

#detail{
  grid-area:det;
  border-right:0;
  border-top:0;
  border-bottom:0;
  border-left:1px solid var(--line);
  display:flex;
  flex-direction:column;
  min-width:0;
}

#canvas-wrap{
  grid-area:canvas;
  position:relative;
  min-width:0;
  overflow:hidden;
  background:var(--bg-canvas);
}

#canvas-wrap::before{
  content:"";
  position:absolute;
  inset:0;
  background-image:none;
  opacity:0;
  pointer-events:none;
}

#canvas-wrap::after{
  content:"";
  position:absolute;
  inset:0;
  background:none;
  pointer-events:none;
}

#canvas{
  position:relative;
  z-index:1;
  width:100%;
  height:100%;
  display:block;
}

#panel-scrim{
  position:fixed;
  inset:64px 0 0 0;
  background:rgba(0,0,0,.42);
  backdrop-filter:blur(2px);
  opacity:0;
  pointer-events:none;
  transition:opacity .18s ease;
  z-index:48;
}

body.show-sidebar #panel-scrim,
body.show-detail #panel-scrim{
  opacity:1;
  pointer-events:auto;
}

.topbar{
  grid-area:hdr;
  display:flex;
  align-items:center;
  gap:14px;
  min-width:0;
  padding:0 16px;
  border-bottom:1px solid var(--line);
  background:#212124;
  box-shadow:none;
  z-index:50;
}

.brand{
  display:flex;
  align-items:center;
  gap:12px;
  min-width:0;
}

.brand-mark{
  width:10px;
  height:10px;
  border-radius:2px;
  background:var(--accent);
  box-shadow:none;
  transform:none;
  flex:0 0 auto;
}

.brand-copy{
  display:flex;
  flex-direction:column;
  gap:1px;
  line-height:1.1;
}

.brand-title{
  font:600 13px/1 var(--font-sans);
  letter-spacing:.015em;
}

.brand-sub{
  font:10px/1.15 var(--font-mono);
  color:var(--text-3);
  text-transform:uppercase;
  letter-spacing:.08em;
}

.topbar-summary{
  display:flex;
  gap:10px;
  min-width:0;
  flex:1 1 auto;
  overflow:hidden;
}

.summary-pill{
  display:inline-flex;
  align-items:center;
  gap:8px;
  min-width:0;
  max-width:280px;
  padding:5px 0;
  border-radius:0;
  border:0;
  background:none;
  color:var(--text-2);
  font-size:12px;
}

.summary-pill strong{
  color:var(--text);
  font-weight:600;
}

.summary-pill.severity-pill strong{
  text-transform:uppercase;
  letter-spacing:.06em;
  font-size:11px;
}

.summary-pill .truncate{
  overflow:hidden;
  text-overflow:ellipsis;
  white-space:nowrap;
}

.topbar-actions{
  display:flex;
  align-items:center;
  gap:8px;
  flex:0 0 auto;
}

.toolbar-btn.only-detail{
  display:none;
}

.toolbar-btn{
  display:inline-flex;
  align-items:center;
  justify-content:center;
  gap:8px;
  min-height:34px;
  padding:0 11px;
  border:1px solid rgba(255,255,255,.08);
  border-radius:5px;
  background:#2b2a2f;
  color:var(--text-2);
  cursor:pointer;
  transition:background .18s ease, border-color .18s ease, color .18s ease;
}

.toolbar-btn:hover{
  border-color:rgba(255,255,255,.12);
  color:var(--text);
  background:#313036;
}

.toolbar-btn.active{
  border-color:rgba(135,150,187,.32);
  background:#303038;
  color:var(--text);
}

.toolbar-btn .toolbar-meta{
  color:var(--text-4);
  font:600 10px/1 var(--font-mono);
  letter-spacing:.08em;
}

.panel-head{
  display:flex;
  align-items:flex-start;
  justify-content:space-between;
  gap:12px;
  padding:14px 16px 10px;
  border-bottom:1px solid rgba(255,255,255,.04);
}

#sidebar .panel-head{
  background:#2d2e35;
  border-bottom:1px solid rgba(166,173,184,.2);
}

.panel-eyebrow{
  display:block;
  margin-bottom:4px;
  color:var(--text-4);
  font:600 10px/1 var(--font-mono);
  letter-spacing:.12em;
  text-transform:uppercase;
}

#sidebar .panel-eyebrow{
  color:#818a96;
}

.panel-title{
  font:600 14px/1.15 var(--font-sans);
}

#sidebar .panel-title{
  color:#e6eaee;
}

.panel-subtitle{
  margin-top:4px;
  color:var(--text-3);
  font-size:12px;
}

#sidebar .panel-subtitle{
  color:#9ba3ae;
}

.panel-action{
  flex:0 0 auto;
  font:600 11px/1 var(--font-mono);
  color:var(--text-3);
  text-transform:uppercase;
  letter-spacing:.08em;
}

.sidebar-tools{
  display:grid;
  grid-template-columns:minmax(0,1fr) 124px;
  gap:10px;
  padding:12px 16px 10px;
}

.field{
  display:flex;
  flex-direction:column;
  gap:6px;
  min-width:0;
}

.field span{
  color:var(--text-4);
  font:600 10px/1 var(--font-mono);
  letter-spacing:.12em;
  text-transform:uppercase;
}

#sidebar .field span{
  color:#858e9a;
}

.input-control,
.select-control{
  width:100%;
  min-width:0;
  min-height:36px;
  padding:0 11px;
  border:1px solid rgba(168,175,186,.28);
  border-radius:5px;
  background:#26272d;
  color:#dfe3e8;
}

.input-control::placeholder{
  color:#838c98;
}

.select-control{
  appearance:none;
  background-image:
    linear-gradient(45deg, transparent 50%, var(--text-3) 50%),
    linear-gradient(135deg, var(--text-3) 50%, transparent 50%);
  background-position:
    calc(100% - 18px) calc(50% - 2px),
    calc(100% - 12px) calc(50% - 2px);
  background-size:6px 6px, 6px 6px;
  background-repeat:no-repeat;
}

.queue-meta{
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:10px;
  padding:0 16px 10px;
  color:#9ba3ae;
  font-size:12px;
}

.queue-meta strong{
  color:#e3e7ec;
}

.incident-list{
  flex:1 1 auto;
  overflow:auto;
  padding:0 8px 10px;
}

.incident-empty{
  margin:8px;
  padding:16px 14px;
  border:1px dashed rgba(168,175,186,.22);
  border-radius:7px;
  background:#303139;
  color:#9da5b0;
  font-size:13px;
}

.incident-card{
  display:flex;
  flex-direction:column;
  gap:8px;
  width:100%;
  margin:0 0 8px;
  padding:10px 11px 9px;
  border:1px solid rgba(169,176,187,.24);
  border-radius:6px;
  background:#34363e;
  color:#e0e4e9;
  cursor:pointer;
  text-align:left;
  transition:border-color .18s ease, background .18s ease, box-shadow .18s ease;
}

.incident-card:hover{
  border-color:rgba(197,204,214,.44);
  background:#3b3e47;
  box-shadow:none;
}

.incident-card.active{
  border-color:rgba(134,145,164,.62);
  background:#40444d;
  box-shadow:none;
}

.incident-card:focus-visible{
  box-shadow:0 0 0 2px rgba(31,32,36,.96), 0 0 0 4px rgba(143,156,179,.34);
}

.incident-row{
  display:flex;
  align-items:center;
  gap:8px;
  min-width:0;
}

.severity-dot{
  width:10px;
  height:10px;
  border-radius:50%;
  box-shadow:0 0 0 4px rgba(236,0,0,.03);
  flex:0 0 auto;
}

.sev-critical{background:var(--crit);box-shadow:0 0 0 4px rgba(236,0,0,.08), 0 0 0 1px rgba(236,0,0,.14)}
.sev-high{background:#8a0000;box-shadow:0 0 0 4px rgba(138,0,0,.07)}
.sev-medium{background:var(--deep-sea);box-shadow:0 0 0 4px rgba(61,71,79,.07)}
.sev-low{background:var(--storm);box-shadow:0 0 0 4px rgba(167,169,172,.11)}
.sev-unknown{background:#c6c8ca;box-shadow:0 0 0 4px rgba(198,200,202,.16)}

.incident-host{
  min-width:0;
  font:600 11px/1.2 var(--font-mono);
  color:#dbe0e6;
  overflow:hidden;
  text-overflow:ellipsis;
  white-space:nowrap;
}

.severity-chip{
  margin-left:auto;
  padding:3px 8px;
  border-radius:999px;
  border:1px solid transparent;
  font:600 9px/1 var(--font-mono);
  text-transform:uppercase;
  letter-spacing:.08em;
}

.severity-chip.critical{background:rgba(236,0,0,.11);border-color:rgba(236,0,0,.2);color:var(--accent-text)}
.severity-chip.high{background:rgba(152,39,39,.14);border-color:rgba(255,120,120,.16);color:#f1b4b4}
.severity-chip.medium{background:rgba(61,71,79,.08);border-color:rgba(61,71,79,.14);color:var(--deep-sea)}
.severity-chip.low{background:rgba(167,169,172,.14);border-color:rgba(167,169,172,.18);color:#5f666d}
.severity-chip.unknown{background:rgba(198,200,202,.18);border-color:rgba(198,200,202,.2);color:#83898f}

.incident-root{
  display:grid;
  grid-template-columns:22px minmax(0,1fr);
  gap:8px;
  align-items:flex-start;
}

.incident-root-icon{
  display:flex;
  align-items:center;
  justify-content:center;
  width:22px;
  height:22px;
  border-radius:8px;
  border:1px solid rgba(171,178,189,.34);
  background:#2b2d34;
  color:#d7dce2;
}

.incident-root-icon svg{
  width:12px;
  height:12px;
  display:block;
}

.incident-root-copy{
  min-width:0;
}

.incident-root-name{
  font:600 12px/1.15 var(--font-sans);
  color:var(--text);
  overflow:hidden;
  text-overflow:ellipsis;
  white-space:nowrap;
}

.incident-root-detail{
  margin-top:2px;
  color:var(--text-3);
  font:10px/1.25 var(--font-mono);
  overflow:hidden;
  text-overflow:ellipsis;
  white-space:nowrap;
}

.incident-footer{
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:8px;
}

.incident-ts{
  color:var(--text-4);
  font:10px/1 var(--font-mono);
}

.incident-metrics{
  display:flex;
  flex-wrap:wrap;
  justify-content:flex-end;
  gap:6px;
}

.stat-pill{
  display:inline-flex;
  align-items:center;
  gap:6px;
  padding:3px 7px;
  border-radius:999px;
  background:rgba(255,255,255,.05);
  border:1px solid rgba(255,255,255,.06);
  color:var(--text-2);
  font:600 9px/1 var(--font-mono);
  letter-spacing:.04em;
}

.stat-pill.hot{
  color:var(--accent-text);
  background:rgba(236,0,0,.12);
  border-color:rgba(236,0,0,.2);
}

.canvas-status{
  position:absolute;
  top:12px;
  left:14px;
  right:auto;
  z-index:3;
  display:flex;
  pointer-events:none;
}

body:not(.display-collapsed) .canvas-status{
  right:auto;
}

.focus-hud{
  min-width:0;
  max-width:min(560px, calc(100vw - 140px));
  padding:6px 8px;
  border:1px solid rgba(255,255,255,.07);
  border-radius:5px;
  background:rgba(41,40,46,.9);
  backdrop-filter:none;
  box-shadow:var(--shadow);
}

.kicker{
  display:none;
  margin:0;
  color:var(--text-4);
  font:600 10px/1 var(--font-mono);
  letter-spacing:.14em;
  text-transform:uppercase;
}

.focus-main{
  display:flex;
  align-items:center;
  justify-content:flex-start;
  gap:8px;
  min-width:0;
}

.focus-copy{
  min-width:0;
  display:flex;
  align-items:center;
}

.focus-title{
  font:600 11px/1.1 var(--font-sans);
  color:var(--text);
  overflow:hidden;
  text-overflow:ellipsis;
  white-space:nowrap;
  max-width:min(260px, 46vw);
}

.focus-subtitle{
  display:none;
  margin:0;
  color:var(--text-3);
  font:10px/1.25 var(--font-mono);
  overflow:hidden;
  text-overflow:ellipsis;
  white-space:nowrap;
}

.focus-stat-row{
  display:flex;
  flex-wrap:nowrap;
  justify-content:flex-start;
  gap:4px;
  min-width:0;
}

.focus-stat{
  display:inline-flex;
  align-items:center;
  gap:5px;
  min-height:20px;
  padding:0 6px;
  border-radius:4px;
  border:1px solid rgba(255,255,255,.06);
  background:rgba(255,255,255,.02);
}

.focus-stat-label{
  color:var(--text-4);
  font:600 9px/1 var(--font-mono);
  letter-spacing:.06em;
  text-transform:uppercase;
}

.focus-stat-value{
  font:600 10px/1 var(--font-mono);
  color:var(--text);
}

.focus-stat.hot{
  border-color:rgba(223,90,93,.18);
  background:rgba(223,90,93,.08);
}

.focus-stat.hot .focus-stat-label,
.focus-stat.hot .focus-stat-value{
  color:var(--accent-text);
}

.floating-panel{
  position:absolute;
  z-index:4;
  border:1px solid rgba(255,255,255,.08);
  border-radius:6px;
  background:rgba(38,37,42,.96);
  backdrop-filter:none;
  box-shadow:var(--shadow);
}

#display-panel{
  top:18px;
  right:18px;
  width:min(330px, calc(100vw - 36px));
  max-height:calc(100% - 112px);
  overflow:auto;
  transition:opacity .18s ease, transform .18s ease;
}

body.display-collapsed #display-panel{
  opacity:0;
  pointer-events:none;
  transform:translateY(-8px);
}

.floating-head{
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:12px;
  padding:13px 14px 9px;
  border-bottom:1px solid rgba(255,255,255,.06);
}

.floating-title{
  font:600 13px/1 var(--font-sans);
}

.floating-sub{
  margin-top:4px;
  color:var(--text-4);
  font:11px/1.3 var(--font-mono);
}

.floating-body{
  padding:12px 14px 14px;
}

.action-row{
  display:grid;
  grid-template-columns:repeat(3, minmax(0,1fr));
  gap:8px;
}

.toggle-section + .toggle-section{
  margin-top:14px;
}

.toggle-section-title,
.legend-title{
  margin-bottom:8px;
  color:var(--text-4);
  font:600 10px/1 var(--font-mono);
  letter-spacing:.12em;
  text-transform:uppercase;
}

.toggle-grid{
  display:grid;
  grid-template-columns:minmax(0,1fr);
  gap:8px;
}

.toggle-btn{
  min-height:34px;
  padding:0 10px;
  border:1px solid rgba(255,255,255,.08);
  border-radius:5px;
  background:#302f34;
  color:var(--text-2);
  cursor:pointer;
  text-align:left;
  transition:background .16s ease, border-color .16s ease, color .16s ease;
}

.toggle-btn:hover{
  background:#36343a;
  color:var(--text);
}

.toggle-btn[aria-pressed="true"]{
  border-color:rgba(223,90,93,.2);
  background:#392f33;
  color:var(--text);
}

.toggle-btn[data-edge="TargetProcessEdge"]{
  box-shadow:inset 3px 0 0 var(--attack);
}

.toggle-btn[data-edge="ProcessCPEdge"]{
  box-shadow:inset 3px 0 0 #76a9c4;
}

.toggle-btn[data-edge="RPCTriggerEdge"]{
  box-shadow:inset 3px 0 0 #8f98a5;
}

.toggle-btn:disabled{
  opacity:.38;
  cursor:default;
}

.legend-grid{
  display:grid;
  grid-template-columns:minmax(0,1fr);
  gap:8px;
}

.legend-row{
  display:flex;
  align-items:center;
  gap:10px;
  color:var(--text-2);
  font-size:12px;
}

.legend-node,
.legend-shape{
  flex:0 0 auto;
  display:inline-flex;
  align-items:center;
  justify-content:center;
  width:18px;
  height:18px;
}

.legend-shape svg,
.legend-node svg{
  width:18px;
  height:18px;
  display:block;
}

.legend-edge{
  width:28px;
  height:14px;
}

.legend-edge svg{
  width:28px;
  height:14px;
  overflow:visible;
}

.legend-line{
  width:24px;
  height:0;
  border-top:2px solid var(--storm);
  opacity:1;
}

#zoom-ctrl{
  right:18px;
  bottom:18px;
  display:flex;
  align-items:center;
  gap:8px;
  padding:8px;
}

.zoom-btn{
  width:38px;
  height:38px;
  border:1px solid rgba(255,255,255,.08);
  border-radius:5px;
  background:#302f34;
  color:var(--text-2);
  cursor:pointer;
  transition:background .16s ease, border-color .16s ease, color .16s ease;
}

.zoom-btn:hover{
  background:#36343a;
  border-color:rgba(255,255,255,.16);
  color:var(--text);
}

.detail-empty{
  display:flex;
  flex:1 1 auto;
  align-items:center;
  justify-content:center;
  padding:32px;
  color:var(--text-3);
  text-align:center;
}

.detail-empty-card{
  max-width:280px;
  padding:20px 18px;
  border:1px dashed rgba(255,255,255,.08);
  border-radius:8px;
  background:#302f34;
}

.detail-empty-icon{
  display:inline-flex;
  align-items:center;
  justify-content:center;
  width:44px;
  height:44px;
  margin-bottom:12px;
  border-radius:10px;
  border:1px solid rgba(255,255,255,.08);
  background:#37353c;
}

.detail-empty-icon svg{
  width:20px;
  height:20px;
}

#det-body{
  display:none;
  flex:1 1 auto;
  overflow:auto;
}

.det-header{
  padding:18px 18px 14px;
  border-bottom:1px solid rgba(255,255,255,.06);
}

.det-title{
  font:600 18px/1.2 var(--font-sans);
  color:var(--text);
  word-break:break-word;
}

.det-title.ioa{
  color:var(--accent-text);
}

.det-badges{
  display:flex;
  flex-wrap:wrap;
  gap:8px;
  margin-top:10px;
}

.badge{
  display:inline-flex;
  align-items:center;
  min-height:26px;
  padding:0 10px;
  border-radius:999px;
  border:1px solid rgba(255,255,255,.08);
  background:rgba(255,255,255,.04);
  color:var(--text-2);
  font:600 11px/1 var(--font-mono);
}

.badge-ioa{
  color:var(--accent-text);
  border-color:rgba(236,0,0,.2);
  background:rgba(236,0,0,.11);
}

.badge-group{
  color:var(--text-2);
  border-color:rgba(143,152,165,.16);
  background:rgba(143,152,165,.08);
}

.badge-preobs{
  color:var(--text-2);
}

.detail-section{
  padding:14px 18px 16px;
  border-bottom:1px solid rgba(255,255,255,.05);
}

.detail-section-title{
  margin-bottom:10px;
  color:var(--text-4);
  font:600 10px/1 var(--font-mono);
  letter-spacing:.12em;
  text-transform:uppercase;
}

.detail-kv{
  display:grid;
  grid-template-columns:96px minmax(0,1fr);
  gap:8px 10px;
}

.detail-key{
  color:var(--text-4);
  font:600 11px/1.35 var(--font-mono);
}

.detail-val{
  color:var(--text);
  font:12px/1.5 var(--font-mono);
  word-break:break-word;
}

.detail-code{
  padding:12px 13px;
  border:1px solid rgba(255,255,255,.08);
  border-radius:14px;
  background:rgba(255,255,255,.03);
  color:var(--text);
  font:12px/1.6 var(--font-mono);
  word-break:break-word;
}

.tag-list{
  display:flex;
  flex-wrap:wrap;
  gap:8px;
}

.ioa-tag{
  display:inline-flex;
  align-items:center;
  min-height:28px;
  padding:0 10px;
  border-radius:999px;
  border:1px solid rgba(236,0,0,.2);
  background:rgba(236,0,0,.1);
  color:var(--accent-text);
  font:600 11px/1 var(--font-mono);
}

.edge-list{
  display:flex;
  flex-direction:column;
  gap:8px;
}

.edge-item{
  padding:10px 12px;
  border:1px solid rgba(255,255,255,.08);
  border-radius:14px;
  background:rgba(255,255,255,.03);
}

.edge-item.hot{
  border-color:rgba(236,0,0,.22);
  background:rgba(73,31,36,.78);
}

.edge-primary{
  color:var(--text);
  font:600 12px/1.4 var(--font-sans);
  word-break:break-word;
}

.edge-secondary{
  margin-top:4px;
  color:var(--text-3);
  font:11px/1.45 var(--font-mono);
  word-break:break-word;
}

.tree-link{
  fill:none;
  stroke:rgba(220,223,227,.24);
  stroke-width:.84;
  stroke-linecap:square;
  stroke-linejoin:miter;
  opacity:.96;
}

.tree-node{
  cursor:pointer;
  outline:none;
}

.hit-area{
  fill:transparent;
  stroke:transparent;
}

.node-shape{
  transition:stroke .16s ease, fill .16s ease, opacity .16s ease;
}

.tree-node:focus-visible .node-shape{
  stroke:#b7c2d5;
}

.tree-node:focus-visible .node-proc-glyph{
  stroke:#f7fafc;
}

.node-proc{
  fill:#d7dbe0;
  stroke:#c1c7cf;
  stroke-width:.74;
}

.node-leaf{
  fill:#d7dbe0;
  stroke:#c1c7cf;
  stroke-width:.74;
}

.node-root{
  fill:#eef1f4;
  stroke:#ffffff;
  stroke-width:.82;
}

.node-ioa{
  fill:#d84b50;
  stroke:#ffb4b7;
  stroke-width:.82;
}

.node-preobs{
  fill:#44484f;
  stroke:#a2a8b0;
  stroke-width:.82;
  stroke-dasharray:2.8,2.6;
}

.node-group-shadow{
  fill:#a0a6ae;
  stroke:#c0c7d0;
  stroke-width:.64;
  opacity:.36;
  pointer-events:none;
}

.node-group{
  fill:#d4d8dd;
  stroke:#bcc3cb;
  stroke-width:.76;
}

.node-file{
  fill:#262b31;
  stroke:#c4cbd2;
  stroke-width:.84;
}

.node-net{
  fill:#283039;
  stroke:#b2c4cf;
  stroke-width:.84;
}

.node-proc-glyph{
  fill:none;
  stroke:#6f7780;
  stroke-width:.74;
  stroke-linecap:round;
  stroke-linejoin:round;
  pointer-events:none;
  transition:stroke .16s ease;
}

.node-proc-glyph.ioa{
  stroke:#f7f9fc;
  stroke-width:.72;
}

.node-label{
  fill:#d7dbe0;
  font:600 9.4px/1.08 var(--font-sans);
  text-anchor:start;
  dominant-baseline:middle;
  pointer-events:none;
}

.node-label.ioa{
  fill:#f3f5f7;
}

.node-label.preobs{
  fill:#adb3bb;
}

.node-meta{
  fill:#888f98;
  font:600 7.9px/1 var(--font-sans);
  text-anchor:start;
  dominant-baseline:middle;
  pointer-events:none;
}

.node-toggle-chip{
  fill:#37363c;
  stroke:rgba(198,204,211,.48);
  stroke-width:.72;
  transition:stroke .16s ease, fill .16s ease, opacity .16s ease;
}

.node-toggle-glyph{
  fill:none;
  stroke:#ccd1d7;
  stroke-width:.9;
  stroke-linecap:round;
  stroke-linejoin:round;
  pointer-events:none;
}

.tree-node:hover .node-shape{
  stroke:#d8dde3;
}

.tree-node:hover .node-proc-glyph{
  stroke:#f7fafc;
}

.tree-node:hover .node-toggle-chip{
  stroke:rgba(255,255,255,.28);
}

.tree-node.is-collapsed-branch .node-shape,
.tree-node.is-group-branch .node-shape{
  stroke:#d9dde1;
}

.tree-node.is-collapsed-branch .node-meta,
.tree-node.is-group-leaf .node-meta,
.tree-node.is-group-branch .node-meta{
  fill:#969ca4;
}

.tree-node.is-collapsed-branch .node-toggle-chip,
.tree-node.is-group-branch .node-toggle-chip{
  fill:#3b3940;
  stroke:rgba(224,228,233,.42);
}

.tree-node.is-collapsed-branch .node-toggle-glyph,
.tree-node.is-group-branch .node-toggle-glyph{
  stroke:#e3e7eb;
}

.tree-node.nd-selected .node-proc{
  fill:#df5a5e;
  stroke:#ffd8d9;
}

.tree-node.nd-selected .node-leaf{
  fill:#df5a5e;
  stroke:#ffd8d9;
}

.tree-node.nd-selected .node-root{
  fill:#e46a6d;
  stroke:#ffe9ea;
}

.tree-node.nd-selected .node-ioa{
  fill:#f8646b;
  stroke:#ffe7e8;
}

.tree-node.nd-selected .node-preobs{
  fill:#565d67;
  stroke:#d9e0e8;
}

.tree-node.nd-selected .node-group{
  fill:#df5a5e;
  stroke:#ffd8d9;
}

.tree-node.nd-selected .node-group-shadow{
  fill:#b5bcc5;
  stroke:#dde3eb;
  opacity:.48;
}

.tree-node.nd-selected .node-file{
  fill:#3a3f46;
  stroke:#ffd8d9;
}

.tree-node.nd-selected .node-net{
  fill:#32414a;
  stroke:#d5e4ed;
}

.tree-node.nd-selected .node-proc-glyph{
  stroke:#fffaf6;
}

.tree-node.nd-selected .node-label{
  fill:#fff8f8;
}

.tree-node.nd-selected .node-meta{
  fill:#f1c7c9;
}

.tree-node.nd-selected .node-toggle-chip{
  fill:#413237;
  stroke:rgba(255,216,217,.54);
}

.tree-node.nd-selected .node-toggle-glyph{
  stroke:#fff4f5;
}

.node-mark{
  fill:var(--accent-text);
  font:700 8px/1 var(--font-mono);
  dominant-baseline:middle;
  text-anchor:middle;
  pointer-events:none;
}

.overlay-TargetProcessEdge{stroke:var(--attack);stroke-width:1.28;stroke-linecap:round;opacity:.95}
.overlay-ProcessCPEdge{stroke:#76a9c4;stroke-width:1.04;stroke-dasharray:4.6,3.4;stroke-linecap:round;opacity:.92}
.overlay-RPCTriggerEdge{stroke:#8f98a5;stroke-width:1;stroke-dasharray:1.8,4.2;stroke-linecap:round;opacity:.9}

::-webkit-scrollbar{width:10px;height:10px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{
  background:rgba(61,71,79,.16);
  border-radius:999px;
  border:2px solid transparent;
  background-clip:padding-box;
}

@media (max-width: 1360px){
  #app{
    --sidebar-width:clamp(292px,32vw,348px);
    grid-template:
      "hdr hdr" 64px
      "sb canvas" minmax(0,1fr)
      / var(--sidebar-width) minmax(0,1fr);
  }

  #detail{
    position:fixed;
    top:64px;
    right:0;
    bottom:0;
    width:min(400px, calc(100vw - 28px));
    transform:translateX(100%);
    transition:transform .18s ease;
    z-index:49;
    border-left:1px solid var(--line);
  }

  body.show-detail #detail{
    transform:translateX(0);
  }

  .toolbar-btn.only-detail{
    display:inline-flex;
  }

  .canvas-status{
    right:auto;
  }

  .focus-hud{
    max-width:min(500px, calc(100vw - 72px));
  }
}

@media (max-width: 1120px){
  #app{
    grid-template:
      "hdr" 64px
      "canvas" minmax(0,1fr)
      / minmax(0,1fr);
  }

  #sidebar{
    position:fixed;
    top:64px;
    left:0;
    bottom:0;
    width:min(360px, calc(100vw - 28px));
    transform:translateX(-100%);
    transition:transform .18s ease;
    z-index:49;
    border-right:1px solid var(--line);
  }

  body.show-sidebar #sidebar{
    transform:translateX(0);
  }

  .toolbar-btn.only-detail{
    display:inline-flex;
  }

  .canvas-status{
    right:auto;
  }
}

@media (max-width: 860px){
  .topbar{
    flex-wrap:wrap;
    align-content:center;
    padding:10px 14px;
    height:auto;
    min-height:64px;
  }

  #app{
    grid-template:
      "hdr" auto
      "canvas" minmax(0,1fr)
      / minmax(0,1fr);
  }

  #panel-scrim{
    top:74px;
  }

  #sidebar,
  #detail{
    top:74px;
  }

  .topbar-summary{
    order:3;
    width:100%;
    overflow:auto;
    padding-bottom:2px;
  }

  .summary-pill{
    flex:0 0 auto;
    max-width:none;
  }

  .canvas-status{
    top:14px;
    left:14px;
    right:14px;
  }

  .focus-hud{
    max-width:none;
  }

  .focus-main{
    flex-wrap:wrap;
    align-items:flex-start;
  }

  .focus-stat-row{
    justify-content:flex-start;
    flex-wrap:wrap;
  }

  #display-panel{
    top:auto;
    bottom:72px;
    right:14px;
    left:14px;
    width:auto;
    max-height:40vh;
  }

  #zoom-ctrl{
    right:14px;
    bottom:14px;
  }

  .toggle-grid{
    grid-template-columns:minmax(0,1fr);
  }

  .action-row{
    grid-template-columns:repeat(3, minmax(0,1fr));
  }
}

@media (prefers-reduced-motion: reduce){
  *,
  *::before,
  *::after{
    animation:none !important;
    transition:none !important;
    scroll-behavior:auto !important;
  }
}
</style>
</head>
<body class="display-collapsed">
<div id="app">
  <header class="topbar">
    <div class="brand">
      <span class="brand-mark" aria-hidden="true"></span>
      <div class="brand-copy">
        <div class="brand-title">ThreatGraph</div>
        <div class="brand-sub">SOC incident viewer</div>
      </div>
    </div>

    <div class="topbar-summary" aria-live="polite">
      <div class="summary-pill"><strong>Host</strong><span class="truncate" id="summary-host">No incident</span></div>
      <div class="summary-pill severity-pill"><strong>Severity</strong><span class="truncate" id="summary-severity">N/A</span></div>
      <div class="summary-pill"><strong>Root</strong><span class="truncate" id="summary-root">No root selected</span></div>
    </div>

    <div class="topbar-actions">
      <button type="button" class="toolbar-btn only-sidebar" id="sidebar-toggle-btn" aria-controls="sidebar" aria-expanded="false">Incidents <span class="toolbar-meta" id="sidebar-toggle-meta">Pinned</span></button>
      <button type="button" class="toolbar-btn only-detail" id="detail-toggle-btn" aria-controls="detail" aria-expanded="false">Details</button>
      <button type="button" class="toolbar-btn" id="display-toggle-btn" aria-controls="display-panel" aria-expanded="false">Display <span class="toolbar-meta" id="display-active-count">3 on</span></button>
    </div>
  </header>

  <aside id="sidebar" class="panel" aria-label="Incident queue">
    <div class="panel-head">
      <div>
        <span class="panel-eyebrow">Queue</span>
        <div class="panel-title">Investigations</div>
        <div class="panel-subtitle">Filter incidents by host, root, or severity.</div>
      </div>
    </div>

    <div class="sidebar-tools">
      <label class="field">
        <span>Filter</span>
        <input id="incident-search" class="input-control" type="search" placeholder="Host, root, UUID…" aria-label="Filter incidents">
      </label>
      <label class="field">
        <span>Severity</span>
        <select id="severity-filter" class="select-control" aria-label="Filter by severity">
          <option value="all">All</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="unknown">Unknown</option>
        </select>
      </label>
    </div>

    <div class="queue-meta">
      <span id="queue-count"><strong>0</strong> incidents</span>
      <span id="queue-hint">Press <strong>/</strong> to search</span>
    </div>

    <div class="incident-list" id="ilist" role="listbox" aria-label="Incident list"></div>
  </aside>

  <main id="canvas-wrap">
    <svg id="canvas" aria-label="Threat graph canvas"></svg>

    <div class="canvas-status" aria-live="polite">
      <div class="focus-hud">
        <div class="focus-main">
          <div class="focus-copy">
            <div class="focus-title" id="focus-title">No incident loaded</div>
            <div class="focus-subtitle" id="focus-subtitle">Select an incident from the queue to render the tree.</div>
          </div>
          <div class="focus-stat-row">
            <span class="focus-stat"><span class="focus-stat-label">Proc</span><span class="focus-stat-value" id="metric-proc">0</span></span>
            <span class="focus-stat hot"><span class="focus-stat-label">IOA</span><span class="focus-stat-value" id="metric-ioa">0</span></span>
            <span class="focus-stat"><span class="focus-stat-label">Alerts</span><span class="focus-stat-value" id="metric-alerts">0</span></span>
            <span class="focus-stat"><span class="focus-stat-label">Coverage</span><span class="focus-stat-value" id="metric-coverage">0</span></span>
          </div>
        </div>
      </div>
    </div>

    <section id="display-panel" class="floating-panel" aria-labelledby="display-title">
      <div class="floating-head">
        <div>
          <div class="floating-title" id="display-title">Display</div>
          <div class="floating-sub">Toggle process overlays and interpret node semantics.</div>
        </div>
      </div>
      <div class="floating-body">
        <div class="toggle-section">
          <div class="toggle-section-title">Graph actions</div>
          <div class="action-row">
            <button type="button" class="toggle-btn" id="btn-expand-all">Expand</button>
            <button type="button" class="toggle-btn" id="btn-collapse-all">Collapse</button>
            <button type="button" class="toggle-btn" id="btn-fit">Fit View</button>
          </div>
        </div>

        <div class="toggle-section">
          <div class="toggle-section-title">Process overlays</div>
          <div class="toggle-grid">
            <button type="button" class="toggle-btn" id="edge-toggle-TargetProcessEdge" data-edge="TargetProcessEdge" aria-pressed="true">Inject / Target</button>
            <button type="button" class="toggle-btn" id="edge-toggle-ProcessCPEdge" data-edge="ProcessCPEdge" aria-pressed="true">Code Path</button>
            <button type="button" class="toggle-btn" id="edge-toggle-RPCTriggerEdge" data-edge="RPCTriggerEdge" aria-pressed="true">RPC Trigger</button>
          </div>
        </div>

        <div class="toggle-section">
          <div class="legend-title">Nodes</div>
          <div class="legend-grid">
            <div class="legend-row"><span class="legend-node" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="6.8" fill="#d7dbe0" stroke="#c1c7cf" stroke-width="1"/></svg></span><span>Process</span></div>
            <div class="legend-row"><span class="legend-node" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5.2L17.89 8.6V15.4L12 18.8L6.11 15.4V8.6Z" fill="#d84b50" stroke="#ffb4b7" stroke-width="1"/></svg></span><span>IOA process</span></div>
            <div class="legend-row"><span class="legend-node" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="6.8" fill="#eef1f4" stroke="#ffffff" stroke-width="1.05"/></svg></span><span>Root process</span></div>
            <div class="legend-row"><span class="legend-node" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke-linecap="round" stroke-linejoin="round"><circle cx="7.9" cy="12.4" r="4.5" fill="#9fa5ad" stroke="#c0c7d0" stroke-width=".85" opacity=".38"/><circle cx="10.1" cy="12.1" r="5.4" fill="#aab0b8" stroke="#c0c7d0" stroke-width=".85" opacity=".58"/><circle cx="12.5" cy="11.8" r="6.1" fill="#d4d8dd" stroke="#bcc3cb" stroke-width=".95"/></svg></span><span>Grouped summary</span></div>
            <div class="legend-row"><span class="legend-node" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="#c4cbd2" stroke-width="1.1" stroke-linecap="round" stroke-linejoin="round"><path d="M7.2 4.1h6l3.6 3.6v12.1H7.2z" fill="#262b31"/><path d="M13.2 4.1v3.8h3.6"/><path d="M9.2 12h5.4"/><path d="M9.2 14.9h3.9"/></svg></span><span>File node</span></div>
            <div class="legend-row"><span class="legend-node" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="#b2c4cf" stroke-width="1.05" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="6.8" fill="#283039"/><circle cx="12" cy="12" r="1.7" fill="#b2c4cf" stroke="none"/><path d="M12 5.6v2"/><path d="M18.4 12h-2"/><path d="M12 18.4v-2"/><path d="M5.6 12h2"/></svg></span><span>Network node</span></div>
          </div>
        </div>

        <div class="toggle-section">
          <div class="legend-title">Edges</div>
          <div class="legend-grid">
            <div class="legend-row"><span class="legend-shape legend-edge" aria-hidden="true"><svg viewBox="0 0 28 12" fill="none" stroke-linecap="square" stroke-linejoin="miter"><path d="M2 6H25" stroke="#7a808a" stroke-width="1.35"/></svg></span><span>Parent → child</span></div>
            <div class="legend-row"><span class="legend-shape legend-edge" aria-hidden="true"><svg viewBox="0 0 28 12" fill="none" stroke-linecap="round" stroke-linejoin="round"><path d="M2 6H22.2" stroke="#d4ae36" stroke-width="1.45"/><path d="M22.2 2.9L26.1 6 22.2 9.1Z" fill="#d4ae36"/></svg></span><span>Inject / target</span></div>
            <div class="legend-row"><span class="legend-shape legend-edge" aria-hidden="true"><svg viewBox="0 0 28 12" fill="none" stroke-linecap="round" stroke-linejoin="round"><path d="M2 6H21.8" stroke="#76a9c4" stroke-width="1.2" stroke-dasharray="4.6 3.4"/><path d="M21.8 3.2L25.9 6 21.8 8.8Z" fill="#76a9c4"/></svg></span><span>Code path</span></div>
            <div class="legend-row"><span class="legend-shape legend-edge" aria-hidden="true"><svg viewBox="0 0 28 12" fill="none" stroke-linecap="round" stroke-linejoin="round"><path d="M2 6H20.1" stroke="#8f98a5" stroke-width="1.1" stroke-dasharray="1.8 4.2"/><circle cx="23" cy="6" r="1.75" fill="#8f98a5"/></svg></span><span>RPC trigger</span></div>
          </div>
        </div>
      </div>
    </section>

    <div id="zoom-ctrl" class="floating-panel" aria-label="Zoom controls">
      <button type="button" class="zoom-btn" id="zoom-in-btn" aria-label="Zoom in">+</button>
      <button type="button" class="zoom-btn" id="zoom-out-btn" aria-label="Zoom out">−</button>
      <button type="button" class="zoom-btn" id="zoom-fit-btn" aria-label="Fit graph to viewport">⊡</button>
    </div>
  </main>

  <aside id="detail" class="panel" aria-label="Evidence detail">
    <div class="panel-head">
      <div>
        <span class="panel-eyebrow">Evidence</span>
        <div class="panel-title">Details</div>
        <div class="panel-subtitle">Node metadata and related evidence appear here.</div>
      </div>
    </div>

    <div class="detail-empty" id="det-ph">
      <div class="detail-empty-card">
        <div class="detail-empty-icon" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7">
            <circle cx="12" cy="12" r="9"></circle>
            <path d="M12 8v4l2.5 2.5"></path>
          </svg>
        </div>
        <div>Select a process, file, or network node to inspect evidence.</div>
      </div>
    </div>
    <div id="det-body"></div>
  </aside>
</div>

<div id="panel-scrim" aria-hidden="true"></div>

__D3_SCRIPT__
<script>
'use strict';

if (!window.d3) {
  const canvasWrap = document.getElementById('canvas-wrap');
  if (canvasWrap) {
    canvasWrap.innerHTML = `
      <div class="detail-empty" style="position:absolute;inset:0;z-index:6;">
        <div class="detail-empty-card" role="alert">
          <div class="detail-empty-icon" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7">
              <path d="M12 3 2.5 20.5h19z"></path>
              <path d="M12 9v5"></path>
              <circle cx="12" cy="17" r="1"></circle>
            </svg>
          </div>
          <div>D3.js failed to load. Regenerate with <code>--d3-local /path/to/d3.min.js</code> for fully offline output.</div>
        </div>
      </div>`;
  }
  throw new Error('D3.js failed to load');
}

const DATA = __DATA__;
const REDUCED_MOTION = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
const NODE_DY = 60;
const NODE_DX = 340;
const PATH_TAIL_CHARS = 20;
const DETAIL_BREAKPOINT = 1360;
const SIDEBAR_BREAKPOINT = 1120;
const OVERLAY_EDGE_TYPES = Object.freeze(['TargetProcessEdge', 'ProcessCPEdge', 'RPCTriggerEdge']);

const EDGE_STYLE = {
  TargetProcessEdge: {stroke:'#d4ae36', sw:1.28, dash:'none', label:'Inject / Target', marker:'arrow'},
  RPCTriggerEdge: {stroke:'#8f98a5', sw:1, dash:'1.8,4.2', label:'RPC Trigger', marker:'dot'},
  ProcessCPEdge: {stroke:'#76a9c4', sw:1.04, dash:'4.6,3.4', label:'Code Path', marker:'arrow'},
};

const EDGE_DEFAULTS = Object.fromEntries(OVERLAY_EDGE_TYPES.map(type => [type, true]));

let svg;
let mainG;
let linkG;
let extraG;
let nodeG;
let zoomBeh;
let currentInc = null;
let filteredIncidents = [];
let selEl = null;
let selNode = null;
let sidebarReframeTimer = null;
let fitTimer = null;
const edgeVisibility = {...EDGE_DEFAULTS};

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function trunc(value, maxLen) {
  const text = value || '';
  return text.length > maxLen ? text.slice(0, maxLen - 1) + '…' : text;
}

function tailFixed(value, tailChars = PATH_TAIL_CHARS) {
  const text = String(value || '').trim();
  if (!text) return '';
  if (text.length <= tailChars) return text;
  return `…${text.slice(-tailChars)}`;
}

function compactCount(value) {
  const count = Number(value || 0);
  if (!Number.isFinite(count) || count <= 0) return '0';
  if (count >= 1000) {
    const compact = count >= 10000 ? (count / 1000).toFixed(0) : (count / 1000).toFixed(1);
    return compact.replace(/\.0$/, '') + 'k';
  }
  return String(count);
}

function normalizeTimeRange(ts, tsEnd) {
  let start = ts || '';
  let end = tsEnd || '';
  if (start && end && end < start) [start, end] = [end, start];
  return {start, end};
}

function timeRangeLabel(ts, tsEnd, compact = false) {
  const range = normalizeTimeRange(ts, tsEnd);
  if (!range.start) return '';
  if (!compact) return range.end && range.end !== range.start ? `${range.start}  →  ${range.end}` : range.start;
  const start = range.start.slice(11, 19);
  if (!range.end || range.end === range.start) return start;
  return `${start}-${range.end.slice(11, 19)}`;
}

function nodeSummaryKind(nd) {
  const childCount = Array.isArray(nd.children) ? nd.children.length : 0;
  if (nd.group && childCount > 0) return 'group-branch';
  if (nd.group) return 'group-leaf';
  if (childCount > 0 && nd._open === false) return 'collapsed-branch';
  return 'node';
}

function nodeSummaryLabel(nd) {
  switch (nodeSummaryKind(nd)) {
    case 'group-branch':
      return 'Grouped branch summary';
    case 'group-leaf':
      return 'Grouped leaf summary';
    case 'collapsed-branch':
      return 'Collapsed branch';
    default:
      return '';
  }
}

function nodeSummaryText(nd) {
  const childCount = Array.isArray(nd.children) ? nd.children.length : 0;
  switch (nodeSummaryKind(nd)) {
    case 'group-branch':
      return `${compactCount(nd.group_count || 0)} grouped instances · ${compactCount(childCount)} child patterns`;
    case 'group-leaf':
      return `${compactCount(nd.group_count || 0)} grouped instances`;
    case 'collapsed-branch':
      return `${compactCount(childCount)} child nodes hidden`;
    default:
      if (nd.node_type === 'proc' && nd.cmd) {
        const cmd = String(nd.cmd || '').trim();
        if (cmd && cmd.toLowerCase() !== String(nd.name || '').trim().toLowerCase()) {
          if (cmd.includes('\\') || cmd.includes('/')) return tailFixed(cmd);
          return trunc(cmd, 28);
        }
      }
      if ((nd.node_type === 'file' || nd.node_type === 'net') && nd.full_path) return tailFixed(nd.full_path);
      return '';
  }
}

function severityClass(raw) {
  return ['critical', 'high', 'medium', 'low'].includes(raw) ? raw : 'unknown';
}

function rootIconSVG(kind) {
  switch (kind) {
    case 'proc':
      return '<svg viewBox="0 0 24 24" fill="none" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="6.8" fill="#d7dbe0" stroke="#c1c7cf" stroke-width="1"/></svg>';
    case 'file':
      return '<svg viewBox="0 0 24 24" fill="none" stroke="#c4cbd2" stroke-width="1.1" stroke-linecap="round" stroke-linejoin="round"><path d="M7.2 4.1h6l3.6 3.6v12.1H7.2z" fill="#262b31"/><path d="M13.2 4.1v3.8h3.6"/><path d="M9.2 12h5.4"/><path d="M9.2 14.9h3.9"/></svg>';
    case 'net':
      return '<svg viewBox="0 0 24 24" fill="none" stroke="#b2c4cf" stroke-width="1.05" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="6.8" fill="#283039"/><circle cx="12" cy="12" r="1.7" fill="#b2c4cf" stroke="none"/><path d="M12 5.6v2"/><path d="M18.4 12h-2"/><path d="M12 18.4v-2"/><path d="M5.6 12h2"/></svg>';
    case 'reg':
      return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M7 4h4v4H7zM13 8h4v4h-4zM7 12h4v4H7zM13 16h4v4h-4z"/></svg>';
    case 'domain':
      return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><circle cx="12" cy="12" r="8"/><path d="M8 9.5a13 13 0 0 0 8 0"/><path d="M8 14.5a13 13 0 0 1 8 0"/></svg>';
    default:
      return '<svg viewBox="0 0 24 24" fill="none" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5.2L17.89 8.6V15.4L12 18.8L6.11 15.4V8.6Z" fill="#d84b50" stroke="#ffb4b7" stroke-width="1"/></svg>';
  }
}

function setSummary(host, severity, root) {
  document.getElementById('summary-host').textContent = host || 'Unknown host';
  document.getElementById('summary-severity').textContent = (severity || 'unknown').toUpperCase();
  document.getElementById('summary-root').textContent = root || 'No root selected';
}

function setCanvasMeta(inc) {
  document.getElementById('focus-title').textContent = inc ? (inc.root_name || inc.root_short || 'Unnamed root') : 'No incident loaded';
  document.getElementById('focus-subtitle').textContent = inc
    ? `${inc.host_short || inc.host || 'Unknown host'} · ${inc.file}`
    : 'Select an incident from the queue to render the tree.';
  document.getElementById('metric-proc').textContent = inc ? String(inc.proc_count || 0) : '0';
  document.getElementById('metric-ioa').textContent = inc ? String(inc.ioa_count || 0) : '0';
  document.getElementById('metric-alerts').textContent = inc ? String(inc.alert_count || 0) : '0';
  document.getElementById('metric-coverage').textContent = inc ? String(inc.tactic_coverage || 0) : '0';
}

function updateDisplayToggleMeta() {
  const activeCount = Object.values(edgeVisibility).filter(Boolean).length;
  const meta = document.getElementById('display-active-count');
  if (meta) meta.textContent = `${activeCount} on`;
}

function updateToolbarState() {
  const detailBtn = document.getElementById('detail-toggle-btn');
  const sidebarBtn = document.getElementById('sidebar-toggle-btn');
  const sidebarMeta = document.getElementById('sidebar-toggle-meta');
  const displayBtn = document.getElementById('display-toggle-btn');
  const isCompactSidebar = window.innerWidth <= SIDEBAR_BREAKPOINT;
  const sidebarVisible = isCompactSidebar
    ? document.body.classList.contains('show-sidebar')
    : !document.body.classList.contains('sidebar-collapsed');
  if (detailBtn) detailBtn.setAttribute('aria-expanded', String(document.body.classList.contains('show-detail')));
  if (sidebarBtn) {
    sidebarBtn.setAttribute('aria-expanded', String(sidebarVisible));
    sidebarBtn.classList.toggle('active', sidebarVisible);
  }
  if (sidebarMeta) {
    sidebarMeta.textContent = isCompactSidebar
      ? (sidebarVisible ? 'Open' : 'Closed')
      : (sidebarVisible ? 'Pinned' : 'Hidden');
  }
  if (displayBtn) {
    const expanded = !document.body.classList.contains('display-collapsed');
    displayBtn.setAttribute('aria-expanded', String(expanded));
    displayBtn.classList.toggle('active', expanded);
  }
  updateDisplayToggleMeta();
}

function syncResponsiveState() {
  if (window.innerWidth > DETAIL_BREAKPOINT) document.body.classList.remove('show-detail');
  if (window.innerWidth > SIDEBAR_BREAKPOINT) {
    document.body.classList.remove('show-sidebar');
  }
  updateToolbarState();
}

function openDetailIfCompact() {
  if (window.innerWidth <= DETAIL_BREAKPOINT) {
    document.body.classList.add('show-detail');
    updateToolbarState();
  }
}

function closeTransientPanels() {
  document.body.classList.remove('show-sidebar');
  document.body.classList.remove('show-detail');
  updateToolbarState();
}

function recenterViewportAfterSidebarChange(prevWidth, prevHeight) {
  if (!svg || !zoomBeh) return;
  if (sidebarReframeTimer) {
    window.clearTimeout(sidebarReframeTimer);
    sidebarReframeTimer = null;
  }
  const wait = REDUCED_MOTION ? 0 : 220;
  sidebarReframeTimer = window.setTimeout(() => {
    const canvas = document.getElementById('canvas');
    if (!canvas) return;
    const nextWidth = canvas.clientWidth;
    const nextHeight = canvas.clientHeight;
    if (!nextWidth || !nextHeight || !prevWidth || !prevHeight) return;
    const dx = (nextWidth - prevWidth) / 2;
    const dy = (nextHeight - prevHeight) / 2;
    if (Math.abs(dx) < 0.25 && Math.abs(dy) < 0.25) return;
    const current = d3.zoomTransform(svg.node());
    const transform = d3.zoomIdentity
      .translate(current.x + dx, current.y + dy)
      .scale(current.k);
    if (REDUCED_MOTION) {
      svg.call(zoomBeh.transform, transform);
    } else {
      svg.transition().duration(220).call(zoomBeh.transform, transform);
    }
  }, wait);
}

function toggleSidebarDrawer() {
  if (window.innerWidth <= SIDEBAR_BREAKPOINT) {
    document.body.classList.toggle('show-sidebar');
    document.body.classList.remove('show-detail');
  } else {
    const canvas = document.getElementById('canvas');
    const prevWidth = canvas ? canvas.clientWidth : 0;
    const prevHeight = canvas ? canvas.clientHeight : 0;
    document.body.classList.toggle('sidebar-collapsed');
    recenterViewportAfterSidebarChange(prevWidth, prevHeight);
  }
  updateToolbarState();
}

function toggleDetailDrawer() {
  if (window.innerWidth > DETAIL_BREAKPOINT) return;
  document.body.classList.toggle('show-detail');
  document.body.classList.remove('show-sidebar');
  updateToolbarState();
}

function toggleDisplayPanel() {
  document.body.classList.toggle('display-collapsed');
  updateToolbarState();
}

function initSVG() {
  svg = d3.select('#canvas');
  zoomBeh = d3.zoom()
    .scaleExtent([0.03, 4])
    .on('zoom', event => mainG.attr('transform', event.transform));
  svg.call(zoomBeh).on('dblclick.zoom', null);

  const defs = svg.append('defs');
  Object.entries(EDGE_STYLE).forEach(([type, style]) => {
    const marker = defs.append('marker')
      .attr('id', `edge-marker-${type}`)
      .attr('viewBox', '0 0 10 10')
      .attr('markerUnits', 'userSpaceOnUse')
      .attr('markerWidth', 8.8)
      .attr('markerHeight', 8.8)
      .attr('refX', 8.2)
      .attr('refY', 5)
      .attr('orient', 'auto');
    if (style.marker === 'arrow') {
      marker.append('path')
        .attr('d', 'M0,1.1 L8.2,5 L0,8.9 Z')
        .attr('fill', style.stroke);
    } else if (style.marker === 'diamond') {
      marker.append('path')
        .attr('d', 'M1.1,5 L5,1.2 L8.9,5 L5,8.8 Z')
        .attr('fill', style.stroke);
    } else {
      marker.append('circle')
        .attr('cx', 5)
        .attr('cy', 5)
        .attr('r', 2.1)
        .attr('fill', style.stroke);
    }
  });

  mainG = svg.append('g').attr('class', 'main-layer');
  linkG = mainG.append('g').attr('class', 'link-layer');
  extraG = mainG.append('g').attr('class', 'overlay-layer');
  nodeG = mainG.append('g').attr('class', 'node-layer');
}

function buildIncidentCard(inc) {
  const button = document.createElement('button');
  const severity = severityClass(inc.severity);
  const rootName = inc.root_name || inc.root_short || inc.root_label || 'Unknown root';
  const rootDetail = inc.root_detail || inc.root_label || '';
  const ts = (inc.iip_ts || '').slice(0, 16).replace('T', ' ');
  button.type = 'button';
  button.className = 'incident-card';
  button.setAttribute('role', 'option');
  button.setAttribute('aria-selected', String(currentInc && currentInc.id === inc.id));
  button.dataset.incidentId = inc.id;
  button.innerHTML = `
    <div class="incident-row">
      <span class="severity-dot sev-${severity}" aria-hidden="true"></span>
      <span class="incident-host">${escapeHtml(inc.host_short || inc.host || 'unknown-host')}</span>
      <span class="severity-chip ${severity}">${escapeHtml(severity)}</span>
    </div>
    <div class="incident-root">
      <span class="incident-root-icon" aria-hidden="true">${rootIconSVG(inc.root_icon)}</span>
      <div class="incident-root-copy">
        <div class="incident-root-name">${escapeHtml(rootName)}</div>
        <div class="incident-root-detail">${escapeHtml(rootDetail)}</div>
      </div>
    </div>
    <div class="incident-footer">
      <span class="incident-ts">${escapeHtml(ts)}</span>
      <div class="incident-metrics">
        <span class="stat-pill">PROC ${escapeHtml(String(inc.proc_count || 0))}</span>
        ${inc.ioa_count > 0 ? `<span class="stat-pill hot">IOA ${escapeHtml(String(inc.ioa_count))}</span>` : ''}
        ${inc.alert_count > 0 ? `<span class="stat-pill">ALRT ${escapeHtml(String(inc.alert_count))}</span>` : ''}
      </div>
    </div>`;
  if (currentInc && currentInc.id === inc.id) button.classList.add('active');
  button.addEventListener('click', () => activateIncident(inc));
  return button;
}

function renderIncidentList() {
  const list = document.getElementById('ilist');
  list.innerHTML = '';
  if (!filteredIncidents.length) {
    const empty = document.createElement('div');
    empty.className = 'incident-empty';
    empty.textContent = 'No incidents match the current filters.';
    list.appendChild(empty);
    return;
  }

  const frag = document.createDocumentFragment();
  filteredIncidents.forEach(inc => frag.appendChild(buildIncidentCard(inc)));
  list.appendChild(frag);
}

function refreshQueueMeta() {
  const total = DATA.incidents.length;
  const shown = filteredIncidents.length;
  document.getElementById('queue-count').innerHTML = `<strong>${shown}</strong> of ${total} incidents`;
}

function clearCanvasAndDetail() {
  linkG.selectAll('*').remove();
  extraG.selectAll('*').remove();
  nodeG.selectAll('*').remove();
  document.getElementById('det-ph').style.display = 'flex';
  document.getElementById('det-body').style.display = 'none';
  document.getElementById('det-body').innerHTML = '';
  setSummary('No incident', 'N/A', 'No root selected');
  setCanvasMeta(null);
}

function applyIncidentFilters() {
  const query = document.getElementById('incident-search').value.trim().toLowerCase();
  const sev = document.getElementById('severity-filter').value;
  filteredIncidents = DATA.incidents.filter(inc => {
    const hay = [
      inc.id,
      inc.file,
      inc.host,
      inc.host_short,
      inc.root_label,
      inc.root_name,
      inc.root_detail,
      inc.root_short,
    ].join(' ').toLowerCase();
    if (sev !== 'all' && severityClass(inc.severity) !== sev) return false;
    return !query || hay.includes(query);
  });
  refreshQueueMeta();
  renderIncidentList();

  if (!filteredIncidents.length) {
    currentInc = null;
    clearCanvasAndDetail();
    return;
  }

  if (!currentInc || !filteredIncidents.some(inc => inc.id === currentInc.id)) {
    activateIncident(filteredIncidents[0], {closePanels:false});
  } else {
    updateToolbarState();
  }
}

function activateIncident(inc, options = {}) {
  currentInc = inc;
  selEl = null;
  selNode = null;
  renderIncidentList();
  syncEdgeButtons(inc);
  updateSummaryForIncident(inc);
  loadIncident(inc, {fit: true});
  if (options.closePanels !== false && window.innerWidth <= SIDEBAR_BREAKPOINT) {
    document.body.classList.remove('show-sidebar');
  }
  updateToolbarState();
}

function updateSummaryForIncident(inc) {
  setSummary(
    inc.host_short || inc.host || 'Unknown host',
    inc.severity || 'unknown',
    inc.root_name || inc.root_short || 'Unknown root'
  );
  setCanvasMeta(inc);
}

function syncEdgeButtons(inc) {
  const counts = {};
  OVERLAY_EDGE_TYPES.forEach(key => { counts[key] = 0; });
  (inc.extra_edges || []).forEach(edge => {
    if (edge.type in counts) counts[edge.type] += 1;
  });

  OVERLAY_EDGE_TYPES.forEach(type => {
    const btn = document.getElementById(`edge-toggle-${type}`);
    if (!btn) return;
    btn.disabled = counts[type] === 0;
    btn.setAttribute('aria-pressed', String(Boolean(edgeVisibility[type])));
  });
  updateDisplayToggleMeta();
}

function scheduleFit() {
  clearTimeout(fitTimer);
  fitTimer = setTimeout(() => fitView(true), REDUCED_MOTION ? 0 : 40);
}

function loadIncident(inc, options = {}) {
  document.getElementById('det-ph').style.display = 'flex';
  document.getElementById('det-body').style.display = 'none';
  document.getElementById('det-body').innerHTML = '';

  linkG.selectAll('*').remove();
  extraG.selectAll('*').remove();
  nodeG.selectAll('*').remove();

  const rootData = inc.roots.length === 1
    ? prep(inc.roots[0], 0)
    : {_id: -1, _synth: true, name: '', uuid: null, children: inc.roots.map(r => prep(r, 0))};

  const hier = d3.hierarchy(rootData, d => d._open !== false ? (d.children || null) : null);
  renderTree(hier, inc);
  if (options.fit) scheduleFit();
}

let _idSeq = 0;
function prep(node, depth) {
  node._depth = depth;
  if (!node._id) node._id = ++_idSeq;
  if (node.children) node.children.forEach(child => prep(child, depth + 1));
  return node;
}

function hexagonPoints(r) {
  const top = Math.round(r * 1.02);
  const sideX = Math.round(r * 0.88);
  const midY = Math.round(r * 0.52);
  return `0,${-top} ${sideX},${-midY} ${sideX},${midY} 0,${top} ${-sideX},${midY} ${-sideX},${-midY}`;
}

function hexagonPath(r) {
  const points = [];
  for (let i = 0; i < 6; i += 1) {
    const angle = Math.PI / 6 + i * (Math.PI / 3);
    const x = Math.cos(angle) * r;
    const y = Math.sin(angle) * r;
    points.push(`${i === 0 ? 'M' : 'L'}${x},${y}`);
  }
  return points.join(' ') + ' Z';
}

function roundedRectPath(x, y, w, h, radius) {
  const r = Math.min(radius, w / 2, h / 2);
  return [
    `M${x + r},${y}`,
    `H${x + w - r}`,
    `Q${x + w},${y} ${x + w},${y + r}`,
    `V${y + h - r}`,
    `Q${x + w},${y + h} ${x + w - r},${y + h}`,
    `H${x + r}`,
    `Q${x},${y + h} ${x},${y + h - r}`,
    `V${y + r}`,
    `Q${x},${y} ${x + r},${y}`,
    'Z',
  ].join(' ');
}

function processIconPath(r) {
  const top = r;
  const sideX = r * 0.8660254;
  const upperY = r * 0.5;
  const lowerY = r * 0.5;
  const bottom = r;
  return `M0,${-top} L${sideX},${-upperY} L${sideX},${lowerY} L0,${bottom} L${-sideX},${lowerY} L${-sideX},${-upperY} Z`;
}

function processGlyphPath(r) {
  const skull = r * 0.56;
  const jaw = r * 0.24;
  return [
    `M0,${-skull}`,
    `C${skull * 0.55},${-skull} ${skull},${-skull * 0.58} ${skull},${-skull * 0.06}`,
    `C${skull},${skull * 0.38} ${skull * 0.68},${skull * 0.7} ${skull * 0.24},${skull * 0.82}`,
    `V${skull + jaw}`,
    `H${-skull * 0.24}`,
    `V${skull * 0.82}`,
    `C${-skull * 0.68},${skull * 0.7} ${-skull},${skull * 0.38} ${-skull},${-skull * 0.06}`,
    `C${-skull},${-skull * 0.58} ${-skull * 0.55},${-skull} 0,${-skull}`,
    `M${-skull * 0.5},${-skull * 0.02} L${-skull * 0.2},${-skull * 0.24} L${-skull * 0.04},${-skull * 0.02}`,
    `M${skull * 0.5},${-skull * 0.02} L${skull * 0.2},${-skull * 0.24} L${skull * 0.04},${-skull * 0.02}`,
    `M${-skull * 0.24},${skull + jaw * 0.26} H${skull * 0.24}`,
    `M0,${skull * 0.84} V${skull + jaw * 0.24}`,
  ].join(' ');
}

function fileIconPath(r) {
  const w = r * 1.72;
  const h = r * 2.02;
  const x = -w / 2;
  const y = -h / 2;
  const fold = r * 0.56;
  return [
    `M${x},${y} H${x + w - fold} L${x + w},${y + fold} V${y + h} H${x} Z`,
    `M${x + w - fold},${y} V${y + fold} H${x + w}`,
    `M${x + r * 0.18},${y + h * 0.34} H${x + w - r * 0.28}`,
    `M${x + r * 0.18},${y + h * 0.56} H${x + w - r * 0.5}`,
  ].join(' ');
}

function networkIconPath(r) {
  const outer = r * 0.92;
  const inner = r * 0.28;
  return [
    `M0,${-outer} A${outer},${outer} 0 1 0 0,${outer} A${outer},${outer} 0 1 0 0,${-outer}`,
    `M0,${-inner} A${inner},${inner} 0 1 0 0,${inner} A${inner},${inner} 0 1 0 0,${-inner}`,
    `M0,${-outer} V${-outer + r * 0.34}`,
    `M${outer},0 H${outer - r * 0.34}`,
    `M0,${outer} V${outer - r * 0.34}`,
    `M${-outer},0 H${-outer + r * 0.34}`,
  ].join(' ');
}

function toggleGlyphPath(collapsed) {
  return collapsed
    ? 'M-1.45,0 H1.45 M0,-1.45 V1.45'
    : 'M-1.45,0 H1.45';
}

function treeLinkPath(link) {
  const sx = link.source.y;
  const sy = link.source.x;
  const tx = link.target.y;
  const ty = link.target.x;
  const mid = sx + Math.max(18, (tx - sx) * 0.42);
  return `M${sx},${sy} H${mid} V${ty} H${tx}`;
}

function dedupeOverlayEdges(edges) {
  const seen = new Map();
  const ordered = [];
  (edges || []).forEach(edge => {
    if (!edge || !edge.src || !edge.dst || !edge.type) return;
    const key = `${edge.type}\u0000${edge.src}\u0000${edge.dst}`;
    const current = seen.get(key);
    if (current) {
      current.count = (current.count || 1) + Math.max(1, Number(edge.count) || 1);
      current.ioa = Boolean(current.ioa || edge.ioa);
      return;
    }
    const normalized = {
      ...edge,
      ioa: Boolean(edge.ioa),
      count: Math.max(1, Number(edge.count) || 1),
    };
    seen.set(key, normalized);
    ordered.push(normalized);
  });
  return ordered;
}

function currentSelectionDescriptor() {
  if (selNode && (selNode.uuid || selNode._id != null)) return {kind: 'node', uuid: selNode.uuid || null, id: selNode._id ?? null};
  return null;
}

function restoreSelection(descriptor) {
  if (!descriptor) return;
  const found = nodeG.selectAll('.tree-node').filter(d =>
    (descriptor.uuid && d.data.uuid === descriptor.uuid)
    || (descriptor.id != null && d.data._id === descriptor.id)
  );
  if (!found.empty()) selectNode(found.node(), found.datum().data, {openDetail: false});
}

function rerenderCurrentIncident() {
  if (!currentInc) return;
  const descriptor = currentSelectionDescriptor();
  const rootData = currentInc.roots.length === 1
    ? currentInc.roots[0]
    : {_id: -1, _synth: true, name: '', uuid: null, children: currentInc.roots};
  const hier = d3.hierarchy(rootData, d => d._open !== false ? (d.children || null) : null);
  linkG.selectAll('*').remove();
  extraG.selectAll('*').remove();
  nodeG.selectAll('*').remove();
  renderTree(hier, currentInc);
  restoreSelection(descriptor);
}

function toggleNodeOpen(nd) {
  if (!nd.children) return;
  nd._open = nd._open === false ? true : false;
  rerenderCurrentIncident();
}

function renderTree(hier, inc) {
  const layout = d3.tree().nodeSize([NODE_DY, NODE_DX]);
  layout(hier);

  const nodes = hier.descendants().filter(d => !d.data._synth);
  const links = hier.links().filter(link => !link.source.data._synth);
  const posMap = {};
  nodes.forEach(d => {
    if (d.data.uuid) posMap[d.data.uuid] = {x: d.y, y: d.x};
  });

  linkG.selectAll('.tree-link').data(links, d => d.target.data._id)
    .join('path')
    .attr('class', 'tree-link')
    .attr('d', d => treeLinkPath(d));

  drawExtraEdges(inc.extra_edges, posMap);

  const nodeEl = nodeG.selectAll('.tree-node').data(nodes, d => d.data._id)
    .join('g')
    .attr('class', 'tree-node')
    .attr('transform', d => `translate(${d.y},${d.x})`);

  nodeEl.each(function(d) {
    buildNode(d3.select(this), d);
  });
}

function buildNodeAriaLabel(nd) {
  const type = nd.node_type || 'process';
  const pieces = [nd.name || 'Unnamed node', type];
  const summaryLabel = nodeSummaryLabel(nd);
  if (summaryLabel) pieces.push(summaryLabel);
  if (nd.is_ioa) pieces.push('IOA');
  if (nd.group && nd.group_count) pieces.push(`${nd.group_count} grouped instances`);
  if (nd.ts) pieces.push(`time ${timeRangeLabel(nd.ts, nd.ts_end, false)}`);
  return pieces.join(', ');
}

function buildNode(g, d) {
  g.selectAll('*').remove();
  const nd = d.data;
  const nodeType = nd.node_type || 'proc';
  const summaryKind = nodeSummaryKind(nd);
  const isGroup = summaryKind === 'group-leaf' || summaryKind === 'group-branch';
  const isGroupLeaf = summaryKind === 'group-leaf';
  const isGroupBranch = summaryKind === 'group-branch';
  const isIoa = Boolean(nd.is_ioa && nodeType === 'proc');
  const isRoot = d.depth === 0 || (d.depth === 1 && d.parent && d.parent.data._synth);
  const childCount = Array.isArray(nd.children) ? nd.children.length : 0;
  const hasKids = childCount > 0;
  const isCollapsed = summaryKind === 'collapsed-branch';
  const hasLeafState = !hasKids;
  const r = nodeType === 'file' || nodeType === 'net'
    ? 5.15
    : isIoa
      ? 6.05
      : isRoot
        ? 5.6
        : 5.05;
  const labelText = trunc(nd.name || '', isGroup ? 20 : (nodeType === 'proc' ? 22 : 24));
  const metaText = nodeSummaryText(nd);
  const showMeta = Boolean(metaText);
  const labelX = r + 10.9;
  const labelY = showMeta ? -12.8 : -6.8;
  const metaY = labelY + 10.2;
  const labelWidth = Math.max(labelText.length * 6.15, metaText.length * 5.2) + labelX + 16;
  const hitLeft = -r - 9;
  const hitTop = -r - 8;
  const hitRight = Math.min(Math.max(labelWidth, 70), 236);
  const hitBottom = showMeta ? metaY + 5.5 : labelY + 5.8;

  g.attr('tabindex', 0)
    .attr('role', 'button')
    .attr('aria-label', buildNodeAriaLabel(nd))
    .classed('nd-selected', Boolean(selNode && (
      (selNode.uuid && nd.uuid === selNode.uuid)
      || (selNode._id != null && nd._id === selNode._id)
    )))
    .classed('has-kids', hasKids)
    .classed('is-collapsed', isCollapsed)
    .classed('is-collapsed-branch', isCollapsed)
    .classed('is-group-leaf', isGroupLeaf)
    .classed('is-group-branch', isGroupBranch);

  g.append('rect')
    .attr('class', 'hit-area')
    .attr('x', hitLeft)
    .attr('y', hitTop)
    .attr('width', hitRight - hitLeft)
    .attr('height', hitBottom - hitTop)
    .attr('rx', 10);

  let shapeClass = 'node-shape ';
  if (isIoa) shapeClass += 'node-ioa';
  else if (isGroup) shapeClass += 'node-group';
  else if (isRoot) shapeClass += 'node-root';
  else if (nd.pre_obs) shapeClass += 'node-preobs';
  else if (nodeType === 'file') shapeClass += 'node-file';
  else if (nodeType === 'net') shapeClass += 'node-net';
  else if (hasLeafState) shapeClass += 'node-leaf';
  else shapeClass += 'node-proc';

  if (isGroup) {
    [-3.9, -1.95].forEach((offset, index) => {
      if (isIoa) {
        g.append('path')
          .attr('d', processIconPath(r * (0.91 - index * 0.04)))
          .attr('transform', `translate(${offset},${index * 0.18})`)
          .attr('class', 'node-group-shadow');
      } else {
        g.append('circle')
          .attr('r', Math.max(3.8, r - 0.34 + index * 0.08))
          .attr('cx', offset)
          .attr('cy', index * 0.16)
          .attr('class', 'node-group-shadow');
      }
    });
  }

  let shape;
  if (nodeType === 'file') {
    shape = g.append('path').attr('d', fileIconPath(r)).attr('class', shapeClass);
  } else if (nodeType === 'net') {
    shape = g.append('path').attr('d', networkIconPath(r)).attr('class', shapeClass);
    g.append('circle')
      .attr('r', Math.max(1.15, r * 0.24))
      .attr('class', 'node-proc-glyph');
  } else if (isIoa) {
    shape = g.append('path').attr('d', processIconPath(r * 1.01)).attr('class', shapeClass);
  } else {
    shape = g.append('circle')
      .attr('r', r)
      .attr('class', shapeClass);
  }

  if (hasKids) {
    const chipX = 0;
    const chipY = r + 6.2;
    const toggle = g.append('g')
      .attr('transform', `translate(${chipX},${chipY})`);
    toggle.append('circle')
      .attr('class', 'node-toggle-chip')
      .attr('r', 3);
    toggle.append('path')
      .attr('class', 'node-toggle-glyph')
      .attr('d', toggleGlyphPath(isCollapsed));
    toggle.style('cursor', 'pointer')
      .on('click', event => {
        event.stopPropagation();
        toggleNodeOpen(nd);
      });
  }

  const labelClass = ['node-label'];
  if (isIoa) labelClass.push('ioa');
  if (nd.pre_obs) labelClass.push('preobs');
  g.append('text')
    .attr('class', labelClass.join(' '))
    .attr('x', labelX)
    .attr('y', labelY)
    .text(labelText);

  if (showMeta) {
    g.append('text')
      .attr('class', 'node-meta')
      .attr('x', labelX)
      .attr('y', metaY)
      .text(metaText);
  }

  const titleLines = [nd.name || ''];
  if (isGroup && nd.group_count) titleLines.push(`${nd.group_count} grouped instances`);
  if (metaText) titleLines.push(metaText);
  if (nodeSummaryLabel(nd)) titleLines.push(nodeSummaryLabel(nd));
  if (nd.ts) titleLines.push(timeRangeLabel(nd.ts, nd.ts_end, false));
  if (nd.cmd) titleLines.push(nd.cmd.slice(0, 180));
  g.append('title').text(titleLines.filter(Boolean).join('\n'));

  g.on('click', event => {
    event.stopPropagation();
    selectNode(g.node(), nd);
  });

  g.on('keydown', event => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      selectNode(g.node(), nd);
      return;
    }
    if (event.key === 'ArrowRight' && nd.children && nd._open === false) {
      event.preventDefault();
      toggleNodeOpen(nd);
      return;
    }
    if (event.key === 'ArrowLeft' && nd.children && nd._open !== false) {
      event.preventDefault();
      toggleNodeOpen(nd);
    }
  });
}

function drawExtraEdges(edges, posMap) {
  if (!edges || !edges.length) return;
  const pullPoint = (from, to, distance) => {
    const dx = to.x - from.x;
    const dy = to.y - from.y;
    const len = Math.hypot(dx, dy);
    if (!len) return {x: from.x, y: from.y};
    const scale = distance / len;
    return {x: from.x + dx * scale, y: from.y + dy * scale};
  };
  dedupeOverlayEdges(edges).forEach(edge => {
    if (!edgeVisibility[edge.type]) return;
    const sp = posMap[edge.src];
    const dp = posMap[edge.dst];
    if (!sp || !dp) return;
    const style = EDGE_STYLE[edge.type] || EDGE_STYLE.ProcessCPEdge;
    const dx = dp.x - sp.x;
    const dy = dp.y - sp.y;
    const isCodePath = edge.type === 'ProcessCPEdge';
    const bowMin = isCodePath ? 84 : 56;
    const bowMax = isCodePath ? 192 : 146;
    const bowFactorY = isCodePath ? 0.62 : 0.46;
    const bow = Math.max(
      bowMin,
      Math.min(bowMax, Math.abs(dy) * bowFactorY + Math.abs(dx) * 0.22)
    );
    const cx = Math.min(sp.x, dp.x) - bow;
    const cy = (sp.y + dp.y) / 2;
    const control = {x: cx, y: cy};
    const start = pullPoint(sp, control, 6.2);
    const end = pullPoint(dp, control, 11.8);
    const path = extraG.append('path')
      .attr('fill', 'none')
      .attr('class', `overlay-${edge.type}`)
      .attr('d', `M${start.x},${start.y} Q${cx},${cy} ${end.x},${end.y}`)
      .attr('stroke-width', style.sw)
      .attr('stroke', style.stroke)
      .attr('marker-end', `url(#edge-marker-${edge.type})`);
    if (style.dash !== 'none') path.attr('stroke-dasharray', style.dash);
    const edgeCountLabel = edge.count > 1 ? ` (${edge.count} events)` : '';
    path.append('title').text(`${style.label}: ${edge.src.slice(0, 8)} → ${edge.dst.slice(0, 8)}${edgeCountLabel}`);
  });
}

function toggleEdgeType(type) {
  if (!(type in edgeVisibility)) return;
  edgeVisibility[type] = !edgeVisibility[type];
  const btn = document.getElementById(`edge-toggle-${type}`);
  if (btn) btn.setAttribute('aria-pressed', String(Boolean(edgeVisibility[type])));
  updateDisplayToggleMeta();
  rerenderCurrentIncident();
}

function clearSelections() {
  if (selEl) d3.select(selEl).classed('nd-selected', false);
  selEl = null;
  selNode = null;
}

function selectNode(el, nd, options = {}) {
  if (selEl) d3.select(selEl).classed('nd-selected', false);
  selEl = el;
  selNode = nd;
  d3.select(el).classed('nd-selected', true);
  showDetail(nd);
  if (options.openDetail !== false) openDetailIfCompact();
}

function el(tag, cls, parent) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (parent) parent.appendChild(node);
  return node;
}

function mkSection(title, parent) {
  const section = el('section', 'detail-section', parent);
  el('div', 'detail-section-title', section).textContent = title;
  return section;
}

function addKV(container, key, value) {
  el('div', 'detail-key', container).textContent = key;
  el('div', 'detail-val', container).textContent = value;
}

function showDetail(nd) {
  document.getElementById('det-ph').style.display = 'none';
  const body = document.getElementById('det-body');
  body.style.display = 'block';
  body.innerHTML = '';
  const childCount = Array.isArray(nd.children) ? nd.children.length : 0;
  const summaryLabel = nodeSummaryLabel(nd);
  const summaryText = nodeSummaryText(nd);
  const timeLabel = timeRangeLabel(nd.ts, nd.ts_end, false);
  const infoTitle = nd.node_type === 'file'
    ? 'File Info'
    : nd.node_type === 'net'
      ? 'Network Info'
      : 'Process Info';

  const header = el('div', 'det-header', body);
  el('div', `det-title${nd.is_ioa ? ' ioa' : ''}`, header).textContent = nd.name || '';
  const badges = el('div', 'det-badges', header);
  if (nd.is_ioa) el('span', 'badge badge-ioa', badges).textContent = 'IOA';
  if (nd.group) el('span', 'badge badge-group', badges).textContent = `Grouped ×${nd.group_count || 0}`;
  if (summaryLabel && !nd.group) el('span', 'badge badge-group', badges).textContent = summaryLabel;
  if (nd.pre_obs) el('span', 'badge badge-preobs', badges).textContent = 'Pre-observation';
  if (nd.node_type) el('span', 'badge', badges).textContent = nd.node_type;

  if (summaryLabel || (nd.group && nd.group_count)) {
    const section = mkSection('Summary', body);
    const kv = el('div', 'detail-kv', section);
    if (summaryLabel) addKV(kv, 'Kind', summaryLabel);
    if (nd.group && nd.group_count) addKV(kv, 'Instances', String(nd.group_count));
    if (childCount) addKV(kv, 'Child patterns', String(childCount));
    if (summaryText) addKV(kv, 'Display', summaryText);
    if (timeLabel) addKV(kv, 'Observed (UTC)', timeLabel);
  }

  if (nd.uuid || nd.ts || nd.full_path || nd.edge_type) {
    const section = mkSection(infoTitle, body);
    const kv = el('div', 'detail-kv', section);
    if (nd.uuid) addKV(kv, 'UUID', nd.uuid);
    if (nd.full_path) addKV(kv, nd.node_type === 'file' ? 'Path' : 'Image', nd.full_path);
    if (nd.ts) addKV(kv, 'Time (UTC)', timeLabel);
    if (nd.edge_type) addKV(kv, 'Edge', nd.edge_type);
  }

  if (nd.cmd) {
    const section = mkSection('Command Line', body);
    el('div', 'detail-code', section).textContent = nd.cmd;
  }

  if (nd.ioa_tags && nd.ioa_tags.length) {
    const section = mkSection('IOA Tags', body);
    const tags = el('div', 'tag-list', section);
    nd.ioa_tags.forEach(tag => el('span', 'ioa-tag', tags).textContent = tag);
  }

  if (nd.net && nd.net.length) {
    const section = mkSection(`Network Connections (${nd.net.length})`, body);
    const list = el('div', 'edge-list', section);
    nd.net.slice(0, 24).forEach(item => {
      const row = el('div', `edge-item${item.ioa ? ' hot' : ''}`, list);
      el('div', 'edge-primary', row).textContent = item.ip;
      el('div', 'edge-secondary', row).textContent = item.ioa ? 'Flagged by IOA relationship' : 'Observed network endpoint';
    });
  }

  if (nd.files && nd.files.length) {
    const section = mkSection(`File Connections (${nd.files.length})`, body);
    const list = el('div', 'edge-list', section);
    nd.files.slice(0, 24).forEach(file => {
      const row = el('div', `edge-item${file.ioa ? ' hot' : ''}`, list);
      const label = {
        ImageLoadEdge: 'Image Load',
        CreatedFileEdge: 'Create File',
        FileWriteEdge: 'Write File',
        FileAccessEdge: 'Access File',
      }[file.type] || file.type || 'File';
      el('div', 'edge-primary', row).textContent = `${label} · ${file.name}`;
      el('div', 'edge-secondary', row).textContent = file.path || '';
    });
  }
}

function fitView(force) {
  const bbox = mainG.node().getBBox();
  if (!bbox.width || !bbox.height) return;
  const canvas = document.getElementById('canvas');
  const width = canvas.clientWidth;
  const height = canvas.clientHeight;
  const pad = 72;
  const scale = Math.min((width - pad * 2) / bbox.width, (height - pad * 2) / bbox.height, 1.45);
  const tx = width / 2 - scale * (bbox.x + bbox.width / 2);
  const ty = height / 2 - scale * (bbox.y + bbox.height / 2);
  const transform = d3.zoomIdentity.translate(tx, ty).scale(scale);
  if (REDUCED_MOTION || !force) {
    svg.call(zoomBeh.transform, transform);
  } else {
    svg.transition().duration(320).call(zoomBeh.transform, transform);
  }
}

function doZoom(factor) {
  if (REDUCED_MOTION) {
    svg.call(zoomBeh.scaleBy, factor);
  } else {
    svg.transition().duration(160).call(zoomBeh.scaleBy, factor);
  }
}

function toggleAll(open) {
  if (!currentInc) return;
  function walk(node) {
    if (node.children) {
      node._open = open;
      node.children.forEach(walk);
    }
  }
  currentInc.roots.forEach(walk);
  rerenderCurrentIncident();
}

function wireControls() {
  document.getElementById('incident-search').addEventListener('input', applyIncidentFilters);
  document.getElementById('severity-filter').addEventListener('change', applyIncidentFilters);
  document.getElementById('btn-expand-all').addEventListener('click', () => toggleAll(true));
  document.getElementById('btn-collapse-all').addEventListener('click', () => toggleAll(false));
  document.getElementById('btn-fit').addEventListener('click', () => fitView(true));
  document.getElementById('zoom-in-btn').addEventListener('click', () => doZoom(1.24));
  document.getElementById('zoom-out-btn').addEventListener('click', () => doZoom(0.8));
  document.getElementById('zoom-fit-btn').addEventListener('click', () => fitView(true));
  document.getElementById('sidebar-toggle-btn').addEventListener('click', toggleSidebarDrawer);
  document.getElementById('detail-toggle-btn').addEventListener('click', toggleDetailDrawer);
  document.getElementById('display-toggle-btn').addEventListener('click', toggleDisplayPanel);
  document.getElementById('panel-scrim').addEventListener('click', closeTransientPanels);
  window.addEventListener('resize', syncResponsiveState);
  document.querySelectorAll('[data-edge]').forEach(btn => {
    btn.addEventListener('click', () => {
      if (btn.disabled) return;
      toggleEdgeType(btn.dataset.edge);
    });
  });

  document.addEventListener('keydown', event => {
    const activeTag = (document.activeElement && document.activeElement.tagName) || '';
    const isTyping = ['INPUT', 'TEXTAREA', 'SELECT'].includes(activeTag);
    if (event.key === '/' && !isTyping) {
      event.preventDefault();
      document.getElementById('incident-search').focus();
      document.getElementById('incident-search').select();
      return;
    }
    if (event.key === 'Escape') {
      closeTransientPanels();
      return;
    }
    if (event.key.toLowerCase() === 'f' && !isTyping) {
      event.preventDefault();
      fitView(true);
    }
  });
}

function init() {
  initSVG();
  wireControls();
  syncResponsiveState();
  filteredIncidents = DATA.incidents.slice();
  refreshQueueMeta();
  renderIncidentList();
  if (filteredIncidents.length) {
    activateIncident(filteredIncidents[0], {closePanels: false});
  } else {
    clearCanvasAndDetail();
  }
  updateToolbarState();
}

init();
</script>
</body>
</html>
'''


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate a Falcon-inspired ThreatGraph incident viewer.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("subgraphs", nargs="*", metavar="subgraph.jsonl")
    parser.add_argument("--all-in-dir", default="")
    parser.add_argument("--out", default="viewer_falcon.html")
    parser.add_argument("--es-url", default="https://127.0.0.1:9200")
    parser.add_argument("--es-user", default="elastic")
    parser.add_argument("--es-pass", default="__nmRSxBG2Hzr15uWCoI")
    parser.add_argument("--es-ca", default=os.path.expanduser(
        "~/elasticsearch-8.15.0/config/certs/http_ca.crt"))
    parser.add_argument("--es-index", default="edr-offline-ls-2026.03.04")
    parser.add_argument(
        "--d3-local",
        default="",
        help="Optional path to a local d3.min.js bundle to inline for fully offline HTML output.",
    )
    return parser.parse_args()


def iter_input_files(args):
    files = list(args.subgraphs)
    if args.all_in_dir:
        for fname in sorted(os.listdir(args.all_in_dir)):
            if fname.startswith("subgraph_") and fname.endswith(".jsonl"):
                files.append(os.path.join(args.all_in_dir, fname))
    return files


def build_d3_script(path_str):
    if path_str:
        js = Path(path_str).read_text(encoding="utf-8")
        return f"<script>\n{js}\n</script>"
    return (
        '<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.9.0/d3.min.js" '
        'crossorigin="anonymous" referrerpolicy="no-referrer"></script>'
    )


def main():
    args = parse_args()
    files = iter_input_files(args)
    if not files:
        print("No subgraph files.")
        sys.exit(1)

    cfg = {
        "url": args.es_url,
        "index": args.es_index,
        "user": args.es_user,
        "passwd": args.es_pass,
        "ssl": make_ssl_ctx(args.es_ca),
    }

    print(f"Processing {len(files)} subgraph(s)…")
    incidents = []
    for path in files:
        try:
            incidents.append(build_incident_json(path, cfg))
        except Exception as exc:  # pragma: no cover - keep parity with base script
            import traceback
            print(f"  ERROR {path}: {exc}", file=sys.stderr)
            traceback.print_exc()

    html = HTML.replace(
        "__DATA__",
        json.dumps({"incidents": incidents}, ensure_ascii=False, separators=(",", ":")),
    ).replace(
        "__D3_SCRIPT__",
        build_d3_script(args.d3_local),
    )

    with open(args.out, "w", encoding="utf-8") as handle:
        handle.write(html)
    print(f"\n→ {args.out}  ({os.path.getsize(args.out)//1024} KB, {len(incidents)} incidents)")


if __name__ == "__main__":
    main()
