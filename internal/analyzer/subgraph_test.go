package analyzer

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"threatgraph/pkg/models"
)

func TestWriteIncidentSubgraphsPrunesAndDedupes(t *testing.T) {
	host := "host-1"
	base := time.Date(2026, 3, 21, 0, 0, 0, 0, time.UTC)
	rows := []*models.AdjacencyRow{
		vertex(host, "proc:host-1:root"),
		vertex(host, "proc:host-1:a"),
		vertex(host, "proc:host-1:b"),
		vertex(host, "proc:host-1:c"),
		edge(host, "1", base.Add(1*time.Second), "ParentOfEdge", "proc:host-1:root", "proc:host-1:a", false),
		edge(host, "2", base.Add(2*time.Second), "RemoteThreadEdge", "proc:host-1:a", "proc:host-1:b", true),
		edge(host, "3", base.Add(3*time.Second), "ParentOfEdge", "proc:host-1:b", "proc:host-1:c", false),
		edge(host, "4", base.Add(4*time.Second), "ParentOfEdge", "proc:host-1:c", "proc:host-1:d", false),
		edge(host, "5", base.Add(5*time.Second), "ParentOfEdge", "proc:host-1:x", "proc:host-1:y", false),
	}
	incidents := []Incident{
		{Host: host, Root: "proc:host-1:root", IIPTS: base.Add(1 * time.Second), Severity: "high", RiskProduct: 64, AlertCount: 1, TacticCoverage: 1},
		{Host: host, Root: "proc:host-1:root", IIPTS: base.Add(1 * time.Second), Severity: "high", RiskProduct: 64, AlertCount: 1, TacticCoverage: 1},
	}

	outDir := t.TempDir()
	summaries, err := WriteIncidentSubgraphs(outDir, host, rows, incidents)
	if err != nil {
		t.Fatalf("WriteIncidentSubgraphs failed: %v", err)
	}
	if got, want := len(summaries), 1; got != want {
		t.Fatalf("unexpected summary count: got %d want %d", got, want)
	}

	s := summaries[0]
	if s.TotalHostEdges != 5 {
		t.Fatalf("unexpected total_host_edges: got %d want 5", s.TotalHostEdges)
	}
	if s.SubgraphEdgesRaw != 4 {
		t.Fatalf("unexpected subgraph_edges_raw: got %d want 4", s.SubgraphEdgesRaw)
	}
	if s.SubgraphEdgesPruned != 4 {
		t.Fatalf("unexpected subgraph_edges_pruned: got %d want 4", s.SubgraphEdgesPruned)
	}
	if s.IOAEdges != 1 {
		t.Fatalf("unexpected ioa_edges: got %d want 1", s.IOAEdges)
	}

	path := filepath.Join(outDir, s.OutputFile)
	lines := readJSONLines(t, path)
	if got, want := len(lines), 10; got != want {
		t.Fatalf("unexpected jsonl line count: got %d want %d", got, want)
	}

	meta := lines[0]
	if meta["record_type"] != "_incident_meta" {
		t.Fatalf("first line is not _incident_meta: %#v", meta)
	}
	if meta["subgraph_edge_count"].(float64) != 4 {
		t.Fatalf("unexpected meta subgraph_edge_count: %#v", meta["subgraph_edge_count"])
	}
	if meta["ioa_edge_count"].(float64) != 1 {
		t.Fatalf("unexpected meta ioa_edge_count: %#v", meta["ioa_edge_count"])
	}

	edgeCount := 0
	for _, row := range lines[1:] {
		if row["record_type"] == "edge" {
			edgeCount++
		}
	}
	if edgeCount != 4 {
		t.Fatalf("unexpected edge rows in subgraph file: got %d want 4", edgeCount)
	}
}

func TestWriteIncidentSubgraphsWithoutIOAStillWritesMeta(t *testing.T) {
	host := "host-2"
	base := time.Date(2026, 3, 21, 0, 0, 0, 0, time.UTC)
	rows := []*models.AdjacencyRow{
		edge(host, "1", base.Add(1*time.Second), "ParentOfEdge", "proc:host-2:r", "proc:host-2:a", false),
		edge(host, "2", base.Add(2*time.Second), "ParentOfEdge", "proc:host-2:a", "proc:host-2:b", false),
	}
	incidents := []Incident{{Host: host, Root: "proc:host-2:r", IIPTS: base.Add(1 * time.Second), Severity: "medium"}}

	outDir := t.TempDir()
	summaries, err := WriteIncidentSubgraphs(outDir, host, rows, incidents)
	if err != nil {
		t.Fatalf("WriteIncidentSubgraphs failed: %v", err)
	}
	if got, want := len(summaries), 1; got != want {
		t.Fatalf("unexpected summary count: got %d want %d", got, want)
	}
	if summaries[0].SubgraphEdgesPruned != 0 {
		t.Fatalf("expected zero pruned edges, got %d", summaries[0].SubgraphEdgesPruned)
	}

	lines := readJSONLines(t, filepath.Join(outDir, summaries[0].OutputFile))
	if got, want := len(lines), 1; got != want {
		t.Fatalf("expected meta-only file when no IOA edges, got %d lines", got)
	}
	if lines[0]["record_type"] != "_incident_meta" {
		t.Fatalf("unexpected first record: %#v", lines[0])
	}
}

func vertex(host, id string) *models.AdjacencyRow {
	return &models.AdjacencyRow{
		RecordType: "vertex",
		Type:       "ProcessVertex",
		VertexID:   id,
		Hostname:   host,
		AgentID:    host,
	}
}

func edge(host, rid string, ts time.Time, typ, from, to string, ioa bool) *models.AdjacencyRow {
	row := &models.AdjacencyRow{
		Timestamp:  ts,
		RecordType: "edge",
		Type:       typ,
		VertexID:   from,
		AdjacentID: to,
		RecordID:   rid,
		Hostname:   host,
		AgentID:    host,
	}
	if ioa {
		row.IoaTags = []models.IoaTag{{Name: "test-rule", Severity: "high", Tactic: "execution", Technique: "T1055"}}
	}
	return row
}

func readJSONLines(t *testing.T, path string) []map[string]interface{} {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()

	out := make([]map[string]interface{}, 0, 16)
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		var row map[string]interface{}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatalf("decode line %q: %v", line, err)
		}
		out = append(out, row)
	}
	if err := s.Err(); err != nil {
		t.Fatalf("scan %s: %v", path, err)
	}
	return out
}
