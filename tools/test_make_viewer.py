import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from typing import cast


MODULE_PATH = Path(__file__).with_name("make_viewer.py")
spec = importlib.util.spec_from_file_location("make_viewer", MODULE_PATH)
assert spec is not None
make_viewer = cast(ModuleType, importlib.util.module_from_spec(spec))
assert spec.loader is not None
spec.loader.exec_module(make_viewer)


class MakeViewerTests(unittest.TestCase):
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
            p = Path(td) / "subgraph.jsonl"
            p.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")

            old_fetch = getattr(make_viewer, "fetch_proc_meta")
            try:
                setattr(make_viewer, "fetch_proc_meta", lambda cfg, uuids, agents: {
                    "{services}": {"new_process_name": "services.exe", "newprocess": r"C:\Windows\System32\services.exe", "new_command_line": "services.exe", "@timestamp": "2026-03-04T11:59:58"},
                    "{svchost}": {"new_process_name": "svchost.exe", "newprocess": r"C:\Windows\System32\svchost.exe", "new_command_line": "svchost.exe -k netsvcs", "processuuid": "{services}", "@timestamp": "2026-03-04T12:00:00"},
                })
                incident = make_viewer.build_incident_json(str(p), {"url": "", "index": "", "user": "", "passwd": "", "ssl": None})
            finally:
                setattr(make_viewer, "fetch_proc_meta", old_fetch)

        self.assertEqual(len(incident["roots"]), 1)
        self.assertEqual(incident["roots"][0]["uuid"], "{services}")
        self.assertEqual(incident["root_name"], "svchost.exe")
        self.assertEqual(incident["root_detail"], r"C:\Windows\System32\svchost.exe")
        self.assertEqual(incident["root_icon"], "proc")

    def test_overlay_edge_types_are_limited_to_non_tree_edges(self):
        self.assertIn("const OVERLAY_EDGE_TYPES = ['TargetProcessEdge', 'ProcessCPEdge', 'RPCTriggerEdge'];", make_viewer.HTML)

    def test_html_uses_distinct_shapes_and_directional_markers(self):
        self.assertIn("hexagonPoints(", make_viewer.HTML)
        self.assertIn("fileIconPath(", make_viewer.HTML)
        self.assertIn("networkIconPath(", make_viewer.HTML)
        self.assertNotIn("id=\"procarc-toggle\"", make_viewer.HTML)
        self.assertNotIn("id=\"file-toggle\"", make_viewer.HTML)
        self.assertNotIn("showProcArcs", make_viewer.HTML)
        self.assertNotIn("fileMode", make_viewer.HTML)
        self.assertNotIn("toggleProcArcs(", make_viewer.HTML)
        self.assertNotIn("cycleFiles(", make_viewer.HTML)
        self.assertNotIn("marker-start", make_viewer.HTML)
        self.assertNotIn("marker-end", make_viewer.HTML)
        self.assertNotIn("midArrowPath(", make_viewer.HTML)
        self.assertIn("toggleCaret", make_viewer.HTML)
        self.assertIn("const showTs = nd._open === false", make_viewer.HTML)
        self.assertIn(".nd-caret{font:9px sans-serif;fill:var(--tx3);dominant-baseline:middle;", make_viewer.HTML)
        self.assertIn("cursor:pointer", make_viewer.HTML)

    def test_rpc_path_keeps_endpoint_branch_open(self):
        rows = [
            {"record_type": "_incident_meta", "host": "host", "root": "proc:host:{root}", "iip_ts": "2026-03-04T12:00:00Z", "severity": "critical", "alert_count": 1, "tactic_coverage": 1, "ioa_edge_count": 1},
            {"record_type": "vertex", "vertex_id": "proc:host:{root}", "type": "proc"},
            {"record_type": "vertex", "vertex_id": "proc:host:{mid}", "type": "proc"},
            {"record_type": "vertex", "vertex_id": "proc:host:{leaf}", "type": "proc"},
            {"record_type": "vertex", "vertex_id": "proc:host:{rpcdst}", "type": "proc"},
            {"record_type": "edge", "vertex_id": "proc:host:{root}", "adjacent_id": "proc:host:{mid}", "type": "ParentOfEdge", "ioa_tags": []},
            {"record_type": "edge", "vertex_id": "proc:host:{mid}", "adjacent_id": "proc:host:{leaf}", "type": "ParentOfEdge", "ioa_tags": []},
            {"record_type": "edge", "vertex_id": "proc:host:{leaf}", "adjacent_id": "proc:host:{rpcdst}", "type": "RPCTriggerEdge", "ioa_tags": []},
        ]
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "subgraph.jsonl"
            p.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
            old_fetch = getattr(make_viewer, "fetch_proc_meta")
            try:
                setattr(make_viewer, "fetch_proc_meta", lambda cfg, uuids, agents: {
                    "{root}": {"new_process_name": "root.exe", "newprocess": r"C:\\root.exe", "@timestamp": "2026-03-04T11:59:58"},
                    "{mid}": {"new_process_name": "mid.exe", "newprocess": r"C:\\mid.exe", "processuuid": "{root}", "@timestamp": "2026-03-04T12:00:00"},
                    "{leaf}": {"new_process_name": "leaf.exe", "newprocess": r"C:\\leaf.exe", "processuuid": "{mid}", "@timestamp": "2026-03-04T12:00:01"},
                    "{rpcdst}": {"new_process_name": "rpcdst.exe", "newprocess": r"C:\\rpcdst.exe", "@timestamp": "2026-03-04T12:00:02"},
                })
                incident = make_viewer.build_incident_json(str(p), {"url": "", "index": "", "user": "", "passwd": "", "ssl": None})
            finally:
                setattr(make_viewer, "fetch_proc_meta", old_fetch)
        roots_by_uuid = {node.get("uuid"): node for node in incident["roots"]}
        root = roots_by_uuid["{root}"]
        child = root["children"][0]
        grandchild = child["children"][0]
        self.assertIn("{rpcdst}", roots_by_uuid)
        self.assertTrue(root["_open"])
        self.assertTrue(child["_open"])
        self.assertTrue(grandchild["_open"])

    def test_rpc_only_endpoint_remains_visible(self):
        rows = [
            {"record_type": "_incident_meta", "host": "host", "root": "proc:host:{svchost}", "iip_ts": "2026-03-04T12:00:00Z", "severity": "critical", "alert_count": 1, "tactic_coverage": 1, "ioa_edge_count": 1},
            {"record_type": "vertex", "vertex_id": "proc:host:{svchost}", "type": "proc"},
            {"record_type": "vertex", "vertex_id": "proc:host:{caller}", "type": "proc"},
            {"record_type": "vertex", "vertex_id": "proc:host:{services}", "type": "proc"},
            {"record_type": "edge", "vertex_id": "proc:host:{svchost}", "adjacent_id": "proc:host:{caller}", "type": "ParentOfEdge", "ioa_tags": []},
            {"record_type": "edge", "vertex_id": "proc:host:{caller}", "adjacent_id": "proc:host:{services}", "type": "RPCTriggerEdge", "ioa_tags": []},
        ]
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "subgraph.jsonl"
            p.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
            old_fetch = getattr(make_viewer, "fetch_proc_meta")
            try:
                setattr(make_viewer, "fetch_proc_meta", lambda cfg, uuids, agents: {
                    "{svchost}": {"new_process_name": "svchost.exe", "newprocess": r"C:\\svchost.exe", "@timestamp": "2026-03-04T12:00:00"},
                    "{caller}": {"new_process_name": "sc.exe", "newprocess": r"C:\\sc.exe", "processuuid": "{svchost}", "@timestamp": "2026-03-04T12:00:01"},
                    "{services}": {"new_process_name": "services.exe", "newprocess": r"C:\\services.exe", "@timestamp": "2026-03-04T12:00:02"},
                })
                incident = make_viewer.build_incident_json(str(p), {"url": "", "index": "", "user": "", "passwd": "", "ssl": None})
            finally:
                setattr(make_viewer, "fetch_proc_meta", old_fetch)

        root_uuids = {r.get("uuid") for r in incident["roots"]}
        self.assertIn("{services}", root_uuids)

    def test_rpc_path_leaf_nodes_are_not_grouped_into_multiplicity(self):
        rows = [
            {"record_type": "_incident_meta", "host": "host", "root": "proc:host:{root}", "iip_ts": "2026-03-04T12:00:00Z", "severity": "critical", "alert_count": 1, "tactic_coverage": 1, "ioa_edge_count": 1},
            {"record_type": "vertex", "vertex_id": "proc:host:{root}", "type": "proc"},
            {"record_type": "vertex", "vertex_id": "proc:host:{a}", "type": "proc"},
            {"record_type": "vertex", "vertex_id": "proc:host:{b}", "type": "proc"},
            {"record_type": "vertex", "vertex_id": "proc:host:{rpcdst}", "type": "proc"},
            {"record_type": "edge", "vertex_id": "proc:host:{root}", "adjacent_id": "proc:host:{a}", "type": "ParentOfEdge", "ioa_tags": []},
            {"record_type": "edge", "vertex_id": "proc:host:{root}", "adjacent_id": "proc:host:{b}", "type": "ParentOfEdge", "ioa_tags": []},
            {"record_type": "edge", "vertex_id": "proc:host:{a}", "adjacent_id": "proc:host:{rpcdst}", "type": "RPCTriggerEdge", "ioa_tags": []},
            {"record_type": "edge", "vertex_id": "proc:host:{b}", "adjacent_id": "proc:host:{rpcdst}", "type": "RPCTriggerEdge", "ioa_tags": []},
        ]
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "subgraph.jsonl"
            p.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
            old_fetch = getattr(make_viewer, "fetch_proc_meta")
            try:
                setattr(make_viewer, "fetch_proc_meta", lambda cfg, uuids, agents: {
                    "{root}": {"new_process_name": "root.exe", "newprocess": r"C:\\root.exe", "@timestamp": "2026-03-04T11:59:58"},
                    "{a}": {"new_process_name": "dup.exe", "newprocess": r"C:\\dup.exe", "processuuid": "{root}", "@timestamp": "2026-03-04T12:00:00"},
                    "{b}": {"new_process_name": "dup.exe", "newprocess": r"C:\\dup.exe", "processuuid": "{root}", "@timestamp": "2026-03-04T12:00:01"},
                    "{rpcdst}": {"new_process_name": "rpcdst.exe", "newprocess": r"C:\\rpcdst.exe", "@timestamp": "2026-03-04T12:00:02"},
                })
                incident = make_viewer.build_incident_json(str(p), {"url": "", "index": "", "user": "", "passwd": "", "ssl": None})
            finally:
                setattr(make_viewer, "fetch_proc_meta", old_fetch)
        def walk(node):
            out = [node]
            for ch in node.get("children", []) or []:
                out.extend(walk(ch))
            return out

        nodes = []
        for r in incident["roots"]:
            nodes.extend(walk(r))
        dup_nodes = [n for n in nodes if n.get("name") == "dup.exe" and not n.get("group")]
        self.assertEqual(len(dup_nodes), 2)


if __name__ == "__main__":
    unittest.main()
