import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from typing import cast


MODULE_PATH = Path(__file__).with_name("make_viewer_falcon.py")
spec = importlib.util.spec_from_file_location("make_viewer_falcon", MODULE_PATH)
assert spec is not None
make_viewer_falcon = cast(ModuleType, importlib.util.module_from_spec(spec))
assert spec.loader is not None
spec.loader.exec_module(make_viewer_falcon)


class MakeViewerFalconTests(unittest.TestCase):
    def test_connected_parent_tree_has_single_root(self):
        proc_root = "proc:host:{services}"
        proc_child = "proc:host:{svchost}"
        rows = [
            {"record_type": "_incident_meta", "host": "host", "root": proc_child, "iip_ts": "2026-03-04T12:00:00Z", "severity": "critical", "alert_count": 1, "tactic_coverage": 1, "ioa_edge_count": 1},
            {"record_type": "vertex", "vertex_id": proc_root, "type": "proc"},
            {"record_type": "vertex", "vertex_id": proc_child, "type": "proc"},
            {"record_type": "edge", "vertex_id": proc_root, "adjacent_id": proc_child, "type": "ParentOfEdge", "ioa_tags": []},
        ]
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "subgraph.jsonl"
            path.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")

            original_fetch = getattr(make_viewer_falcon, "fetch_proc_meta")
            try:
                setattr(make_viewer_falcon, "fetch_proc_meta", lambda cfg, uuids, agents: {
                    "{services}": {"new_process_name": "services.exe", "newprocess": r"C:\Windows\System32\services.exe", "new_command_line": "services.exe", "@timestamp": "2026-03-04T11:59:58"},
                    "{svchost}": {"new_process_name": "svchost.exe", "newprocess": r"C:\Windows\System32\svchost.exe", "new_command_line": "svchost.exe -k netsvcs", "processuuid": "{services}", "@timestamp": "2026-03-04T12:00:00"},
                })
                incident = make_viewer_falcon.build_incident_json(str(path), {"url": "", "index": "", "user": "", "passwd": "", "ssl": None})
            finally:
                setattr(make_viewer_falcon, "fetch_proc_meta", original_fetch)

        self.assertEqual(len(incident["roots"]), 1)
        self.assertEqual(incident["roots"][0]["uuid"], "{services}")
        self.assertEqual(incident["root_name"], "svchost.exe")
        self.assertEqual(incident["root_detail"], r"C:\Windows\System32\svchost.exe")
        self.assertEqual(incident["root_icon"], "proc")

    def test_html_uses_accessible_controls_and_preserves_zoom_on_rerender(self):
        html = make_viewer_falcon.HTML
        self.assertIn('aria-label="Filter incidents"', html)
        self.assertIn('button:focus-visible', html)
        self.assertIn('document.getElementById(\'display-toggle-btn\')', html)
        self.assertIn('<body class="display-collapsed">', html)
        self.assertIn('id="display-active-count"', html)
        self.assertIn('scheduleFit();', html)
        self.assertNotIn('setTimeout(fitView, 50);', html)
        self.assertNotIn('onclick="', html)
        self.assertIn('updateDisplayToggleMeta()', html)

    def test_html_replaces_character_icons_and_uses_compact_focus_hud(self):
        html = make_viewer_falcon.HTML
        self.assertIn('function rootIconSVG(kind)', html)
        self.assertIn('function compactCount(value)', html)
        self.assertIn('function nodeSummaryKind(nd)', html)
        self.assertIn('function processIconPath(r)', html)
        self.assertIn('function processGlyphPath(r)', html)
        self.assertIn('function toggleGlyphPath(collapsed)', html)
        self.assertIn('.node-proc-glyph{', html)
        self.assertIn('.node-meta{', html)
        self.assertIn('.node-group-shadow{', html)
        self.assertIn('.node-toggle-chip{', html)
        self.assertIn('PROC ${escapeHtml(String(inc.proc_count || 0))}', html)
        self.assertIn('class="focus-hud"', html)
        self.assertIn('class="focus-stat hot"', html)
        self.assertNotIn('class="metric-box"', html)
        self.assertIn('--bg:#2f2e34;', html)
        self.assertIn('--accent:#df5a5e;', html)
        self.assertIn('--accent-text:#ffe0e1;', html)
        self.assertIn('--focus:#8796bb;', html)
        self.assertIn('--warm:#eb9049;', html)
        self.assertIn('--proc-edge:#a7adb5;', html)
        self.assertIn('.overlay-TargetProcessEdge{stroke:var(--attack);stroke-width:1.28;', html)
        self.assertIn('.overlay-ProcessCPEdge{stroke:#76a9c4;stroke-width:1.04;', html)
        self.assertIn('.overlay-RPCTriggerEdge{stroke:#8f98a5;stroke-width:1;', html)
        self.assertIn('const NODE_DY = 60;', html)
        self.assertIn('const NODE_DX = 340;', html)
        self.assertIn('const PATH_TAIL_CHARS = 20;', html)
        self.assertIn("const metaText = nodeSummaryText(nd);", html)
        self.assertIn("const labelX = r + 10.9;", html)
        self.assertIn("const labelY = showMeta ? -12.8 : -6.8;", html)
        self.assertIn("const pullPoint = (from, to, distance) => {", html)
        self.assertIn(".attr('markerUnits', 'userSpaceOnUse')", html)
        self.assertIn("function tailFixed(value, tailChars = PATH_TAIL_CHARS) {", html)
        self.assertIn("if (cmd.includes('\\\\') || cmd.includes('/')) return tailFixed(cmd);", html)
        self.assertIn("if ((nd.node_type === 'file' || nd.node_type === 'net') && nd.full_path) return tailFixed(nd.full_path);", html)
        self.assertIn("return `${compactCount(childCount)} child nodes hidden`;", html)
        self.assertIn("return `${compactCount(nd.group_count || 0)} grouped instances`;", html)
        self.assertIn("dedupeOverlayEdges(edges).forEach(edge => {", html)
        self.assertIn('text-anchor:start;', html)
        self.assertIn('<circle cx="12" cy="12" r="6.8" fill="#d7dbe0"', html)
        self.assertIn('Grouped summary</span>', html)
        self.assertIn('class="legend-shape legend-edge"', html)
        self.assertIn('stroke-dasharray="4.6 3.4"', html)
        self.assertIn('stroke-dasharray="1.8 4.2"', html)
        self.assertIn('fill="#d84b50"', html)
        self.assertIn('fill="#eef1f4"', html)
        self.assertIn('fill="#262b31"', html)
        self.assertNotIn('.node-caret{', html)
        self.assertNotIn('.node-select-ring{', html)
        self.assertNotIn('.node-count-pill{', html)
        self.assertNotIn('.node-proc-eye{', html)
        self.assertNotIn('glow-ioa', html)
        self.assertNotIn('const badgeText = isGroup && nd.group_count', html)
        self.assertNotIn('--bg:#f8f8f8;', html)
        self.assertNotIn('#6ea7ff', html)
        self.assertNotIn('#9ec3ff', html)
        self.assertNotIn('#bd74ff', html)
        self.assertNotIn('#c999ff', html)
        self.assertNotIn('🗎', html)
        self.assertNotIn('⬡', html)
        self.assertNotIn('⚑', html)

    def test_build_incident_json_dedupes_overlay_edges_and_normalizes_group_ranges(self):
        original_build = make_viewer_falcon._BASE.build_incident_json
        try:
            make_viewer_falcon._BASE.build_incident_json = lambda path, cfg: {
                "roots": [
                    {
                        "_id": 1,
                        "uuid": "{root}",
                        "name": "root.exe",
                        "ts": "",
                        "ts_end": "",
                        "group": False,
                        "children": [
                            {
                                "_id": 2,
                                "uuid": None,
                                "name": "cmd.exe",
                                "ts": "2026-03-04T07:57:27",
                                "ts_end": "2026-03-04T07:56:50",
                                "group": True,
                                "group_count": 2,
                                "children": [],
                            }
                        ],
                    }
                ],
                "extra_edges": [
                    {"src": "{a}", "dst": "{b}", "type": "RPCTriggerEdge", "ioa": False},
                    {"src": "{a}", "dst": "{b}", "type": "RPCTriggerEdge", "ioa": True},
                    {"src": "{a}", "dst": "{c}", "type": "TargetProcessEdge", "ioa": False},
                    {"src": "{a}", "dst": "{z}", "type": "UnexpectedOverlayEdge", "ioa": False},
                ],
                "file_nodes": [{"name": "unused"}],
            }
            incident = make_viewer_falcon.build_incident_json("unused.jsonl", {"url": "", "index": "", "user": "", "passwd": "", "ssl": None})
        finally:
            make_viewer_falcon._BASE.build_incident_json = original_build

        self.assertEqual(len(incident["extra_edges"]), 2)
        self.assertEqual(incident["extra_edges"][0]["type"], "RPCTriggerEdge")
        self.assertEqual(incident["extra_edges"][0]["count"], 2)
        self.assertTrue(incident["extra_edges"][0]["ioa"])
        child = incident["roots"][0]["children"][0]
        self.assertEqual(child["ts"], "2026-03-04T07:56:50")
        self.assertEqual(child["ts_end"], "2026-03-04T07:57:27")
        self.assertEqual(incident["file_nodes"], [])

    def test_overlay_controls_are_limited_to_process_relationships(self):
        html = make_viewer_falcon.HTML
        self.assertIn("const OVERLAY_EDGE_TYPES = Object.freeze(['TargetProcessEdge', 'ProcessCPEdge', 'RPCTriggerEdge']);", html)
        self.assertIn("const EDGE_DEFAULTS = Object.fromEntries(OVERLAY_EDGE_TYPES.map(type => [type, true]));", html)
        self.assertIn("marker:'arrow'", html)
        self.assertIn("marker:'dot'", html)
        self.assertIn("edge-marker-${type}", html)
        self.assertIn("marker-end', `url(#edge-marker-${edge.type})`", html)
        self.assertIn('id="edge-toggle-TargetProcessEdge"', html)
        self.assertIn('id="edge-toggle-ProcessCPEdge"', html)
        self.assertIn('id="edge-toggle-RPCTriggerEdge"', html)
        self.assertIn('id="btn-expand-all"', html)
        self.assertIn('id="btn-collapse-all"', html)
        self.assertIn('id="btn-fit"', html)
        self.assertNotIn('ImageLoadEdge: false', html)
        self.assertNotIn('CreatedFileEdge: false', html)
        self.assertNotIn('FileWriteEdge: false', html)
        self.assertNotIn('FileAccessEdge: false', html)
        self.assertNotIn('id="edge-toggle-ImageLoadEdge"', html)
        self.assertNotIn('id="edge-toggle-CreatedFileEdge"', html)
        self.assertNotIn('id="edge-toggle-FileWriteEdge"', html)
        self.assertNotIn('id="edge-toggle-FileAccessEdge"', html)
        self.assertNotIn('drawArtifactOverlays', html)
        self.assertNotIn('selectArtifact', html)
        self.assertNotIn('artifact-node', html)
        self.assertNotIn('file-overlay-layer', html)

    def test_build_incident_json_strips_non_process_overlay_payload_but_keeps_file_tree(self):
        proc_root = "proc:host:{services}"
        proc_child = "proc:host:{svchost}"
        rows = [
            {"record_type": "_incident_meta", "host": "host", "root": proc_child, "iip_ts": "2026-03-04T12:00:00Z", "severity": "critical", "alert_count": 1, "tactic_coverage": 1, "ioa_edge_count": 1},
            {"record_type": "vertex", "vertex_id": proc_root, "type": "proc"},
            {"record_type": "vertex", "vertex_id": proc_child, "type": "proc"},
            {"record_type": "edge", "vertex_id": proc_root, "adjacent_id": proc_child, "type": "ParentOfEdge", "ioa_tags": []},
            {"record_type": "edge", "vertex_id": proc_root, "adjacent_id": proc_child, "type": "TargetProcessEdge", "ioa_tags": ["ioa:test"]},
            {"record_type": "edge", "vertex_id": proc_child, "adjacent_id": proc_root, "type": "UnexpectedOverlayEdge", "ioa_tags": []},
            {"record_type": "edge", "vertex_id": proc_child, "adjacent_id": "path:host:/tmp/evil.dll", "type": "CreatedFileEdge", "ioa_tags": []},
        ]
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "subgraph.jsonl"
            path.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")

            original_fetch = getattr(make_viewer_falcon, "fetch_proc_meta")
            try:
                setattr(make_viewer_falcon, "fetch_proc_meta", lambda cfg, uuids, agents: {
                    "{services}": {"new_process_name": "services.exe", "newprocess": r"C:\Windows\System32\services.exe", "new_command_line": "services.exe", "@timestamp": "2026-03-04T11:59:58"},
                    "{svchost}": {"new_process_name": "svchost.exe", "newprocess": r"C:\Windows\System32\svchost.exe", "new_command_line": "svchost.exe -k netsvcs", "processuuid": "{services}", "@timestamp": "2026-03-04T12:00:00"},
                })
                incident = make_viewer_falcon.build_incident_json(str(path), {"url": "", "index": "", "user": "", "passwd": "", "ssl": None})
            finally:
                setattr(make_viewer_falcon, "fetch_proc_meta", original_fetch)

        self.assertEqual([edge["type"] for edge in incident["extra_edges"]], ["TargetProcessEdge"])
        self.assertEqual(incident["file_nodes"], [])
        child = incident["roots"][0]["children"][0]
        self.assertEqual(child["uuid"], "{svchost}")
        file_children = [node for node in child["children"] if node["node_type"] == "file"]
        self.assertEqual(len(file_children), 1)
        self.assertEqual(file_children[0]["edge_type"], "CreatedFileEdge")
        self.assertIn("evil.dll", file_children[0]["name"])

    def test_build_d3_script_can_inline_local_bundle(self):
        with tempfile.TemporaryDirectory() as td:
            bundle = Path(td) / "d3.min.js"
            bundle.write_text("window.d3 = {version: 'test'};", encoding="utf-8")
            tag = make_viewer_falcon.build_d3_script(str(bundle))
        self.assertIn("<script>", tag)
        self.assertIn("window.d3 = {version: 'test'};", tag)
        self.assertIn("</script>", tag)


if __name__ == "__main__":
    unittest.main()
