package analyzer

import (
	"testing"
	"time"

	"threatgraph/pkg/models"
)

func TestCollectAlertEventsOnlyUsesEdgeRowsWithIoaTags(t *testing.T) {
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	rows := []*models.AdjacencyRow{
		{Timestamp: base, RecordType: "vertex", VertexID: "proc:a", IoaTags: []models.IoaTag{{Name: "ignore"}}},
		{Timestamp: base, RecordType: "edge", VertexID: "proc:a", AdjacentID: "proc:b"},
		{Timestamp: base, RecordType: "edge", VertexID: "proc:a", AdjacentID: "proc:b", IoaTags: []models.IoaTag{{Name: "alert"}}, Hostname: "h1", RecordID: "2"},
	}

	got := CollectAlertEvents(rows)
	if len(got) != 1 {
		t.Fatalf("expected 1 alert event, got %d", len(got))
	}
	if got[0].From != "proc:a" || got[0].To != "proc:b" {
		t.Fatalf("unexpected alert edge: %+v", got[0])
	}
}

func TestBuildIIPGraphsGroupsAndFiltersEdges(t *testing.T) {
	t0 := time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(1 * time.Minute)
	t2 := t0.Add(2 * time.Minute)
	t3 := t0.Add(3 * time.Minute)
	t4 := t0.Add(4 * time.Minute)

	rows := []*models.AdjacencyRow{
		{Timestamp: t0, RecordType: "edge", Type: "CreateProcessEdge", VertexID: "proc:pre", AdjacentID: "proc:p1", Hostname: "host-a", RecordID: "1"},
		{Timestamp: t1, RecordType: "edge", Type: "ProcessAccessEdge", VertexID: "proc:p1", AdjacentID: "proc:p2", Hostname: "host-a", RecordID: "2", IoaTags: []models.IoaTag{{Name: "A", Technique: "T1055"}}},
		{Timestamp: t2, RecordType: "edge", Type: "NetworkConnectEdge", VertexID: "proc:p2", AdjacentID: "net:n1", Hostname: "host-a", RecordID: "3"},
		{Timestamp: t3, RecordType: "edge", Type: "WriteFileEdge", VertexID: "proc:x", AdjacentID: "file:f1", Hostname: "host-a", RecordID: "4"},
		{Timestamp: t4, RecordType: "edge", Type: "RemoteThreadEdge", VertexID: "proc:q1", AdjacentID: "proc:q2", Hostname: "host-b", RecordID: "10", IoaTags: []models.IoaTag{{Name: "B", Technique: "T1106"}}},
	}

	graphs := BuildIIPGraphs(rows)
	if len(graphs) != 2 {
		t.Fatalf("expected 2 graphs, got %d", len(graphs))
	}

	var hostA *IIPGraph
	for i := range graphs {
		if graphs[i].Host == "host-a" {
			hostA = &graphs[i]
			break
		}
	}
	if hostA == nil {
		t.Fatalf("expected host-a graph")
	}
	if hostA.Root != "proc:p1" {
		t.Fatalf("expected root proc:p1, got %s", hostA.Root)
	}
	if !hostA.IIPTS.Equal(t1) {
		t.Fatalf("unexpected iip ts: %v", hostA.IIPTS)
	}
	if len(hostA.AlertEvents) != 1 {
		t.Fatalf("expected 1 alert event in host-a, got %d", len(hostA.AlertEvents))
	}

	edgeIDs := make(map[string]struct{}, len(hostA.Edges))
	for _, e := range hostA.Edges {
		edgeIDs[e.RecordID] = struct{}{}
	}
	if _, ok := edgeIDs["2"]; !ok {
		t.Fatalf("expected alert edge record 2 to be included")
	}
	if _, ok := edgeIDs["3"]; ok {
		t.Fatalf("did not expect post-alert edge record 3 without downstream alert")
	}
	if _, ok := edgeIDs["1"]; ok {
		t.Fatalf("did not expect pre-IIP edge record 1")
	}
	if _, ok := edgeIDs["4"]; ok {
		t.Fatalf("did not expect unrelated edge record 4")
	}
}

func TestBuildIIPGraphsSkipsLaterAlertWhenEarlierAlertExistsInBackwardTrace(t *testing.T) {
	t0 := time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(1 * time.Minute)

	rows := []*models.AdjacencyRow{
		{Timestamp: t0, RecordType: "edge", Type: "ProcessAccessEdge", VertexID: "proc:p1", AdjacentID: "proc:p2", Hostname: "host-a", RecordID: "1", IoaTags: []models.IoaTag{{Name: "A", Technique: "T1001"}}},
		{Timestamp: t1, RecordType: "edge", Type: "CreateProcessEdge", VertexID: "proc:p2", AdjacentID: "proc:p3", Hostname: "host-a", RecordID: "2", IoaTags: []models.IoaTag{{Name: "B", Technique: "T1002"}}},
	}

	graphs := BuildIIPGraphs(rows)
	if len(graphs) != 1 {
		t.Fatalf("expected 1 graph, got %d", len(graphs))
	}
	if graphs[0].Root != "proc:p1" {
		t.Fatalf("expected earliest root proc:p1, got %s", graphs[0].Root)
	}
	if len(graphs[0].AlertEvents) != 2 {
		t.Fatalf("expected both alerts to be grouped into first IIP graph, got %d", len(graphs[0].AlertEvents))
	}
}

func TestBuildTPGDeduplicatesTechniqueNamePerSourceAndOrdersByTime(t *testing.T) {
	t0 := time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(1 * time.Minute)

	iip := IIPGraph{
		Host: "host-a",
		Root: "proc:a",
		AlertEvents: []AlertEvent{
			{Host: "host-a", From: "proc:a", To: "proc:b", TS: t0, RecordID: "1", IoaTags: []models.IoaTag{{Technique: "T1000", Name: "Alpha"}}},
			{Host: "host-a", From: "proc:a", To: "proc:c", TS: t1, RecordID: "2", IoaTags: []models.IoaTag{{Technique: "T1000", Name: "Alpha"}}},
			{Host: "host-a", From: "proc:a", To: "proc:d", TS: t1, RecordID: "3", IoaTags: []models.IoaTag{{Technique: "T2000", Name: "Beta"}}},
			{Host: "host-a", From: "proc:x", To: "proc:y", TS: t1, RecordID: "4", IoaTags: []models.IoaTag{{Technique: "T1000", Name: "Alpha"}}},
		},
	}

	tpg := BuildTPG(iip)
	if len(tpg.Vertices) != 3 {
		t.Fatalf("expected 3 vertices after dedupe, got %d", len(tpg.Vertices))
	}
	if tpg.Vertices[0].RecordID != "1" || tpg.Vertices[1].RecordID != "3" || tpg.Vertices[2].RecordID != "4" {
		t.Fatalf("unexpected temporal order: %+v", tpg.Vertices)
	}
	if len(tpg.SequenceEdges) != 2 {
		t.Fatalf("expected 2 sequence edges, got %d", len(tpg.SequenceEdges))
	}
	if tpg.SequenceEdges[0].From != 0 || tpg.SequenceEdges[0].To != 1 {
		t.Fatalf("unexpected first sequence edge: %+v", tpg.SequenceEdges[0])
	}
	if tpg.SequenceEdges[1].From != 1 || tpg.SequenceEdges[1].To != 2 {
		t.Fatalf("unexpected second sequence edge: %+v", tpg.SequenceEdges[1])
	}
}

func TestBuildTPGAddsCausalSequenceEdgesFromIIPPaths(t *testing.T) {
	t0 := time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(1 * time.Minute)
	t2 := t0.Add(2 * time.Minute)

	iip := IIPGraph{
		Host: "host-a",
		Root: "proc:a",
		AlertEvents: []AlertEvent{
			{Host: "host-a", From: "proc:a", To: "proc:b", TS: t0, RecordID: "1", IoaTags: []models.IoaTag{{Technique: "T1000", Name: "A"}}},
			{Host: "host-a", From: "proc:c", To: "proc:d", TS: t2, RecordID: "3", IoaTags: []models.IoaTag{{Technique: "T2000", Name: "B"}}},
		},
		Edges: []*models.AdjacencyRow{
			{Timestamp: t1, RecordType: "edge", VertexID: "proc:b", AdjacentID: "proc:c", Type: "CreateProcessEdge", RecordID: "2", Hostname: "host-a"},
		},
	}

	tpg := BuildTPG(iip)
	foundCausal := false
	for _, e := range tpg.SequenceEdges {
		if e.From == 0 && e.To == 1 {
			foundCausal = true
			break
		}
	}
	if !foundCausal {
		t.Fatalf("expected causal sequence edge 0->1")
	}
}

func TestScoreTPGPrefersLongestKillChainOrderedSubsequence(t *testing.T) {
	t0 := time.Date(2026, 2, 2, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(1 * time.Minute)
	t2 := t0.Add(2 * time.Minute)
	t3 := t0.Add(3 * time.Minute)

	tpg := TPG{
		Host: "host-a",
		Root: "proc:a",
		Vertices: []AlertEvent{
			{TS: t0, RecordID: "1", IoaTags: []models.IoaTag{{Tactic: "execution", Severity: "medium", Technique: "T1059"}}},
			{TS: t1, RecordID: "2", IoaTags: []models.IoaTag{{Tactic: "discovery", Severity: "medium", Technique: "T1082"}}},
			{TS: t2, RecordID: "3", IoaTags: []models.IoaTag{{Tactic: "initial-access", Severity: "critical", Technique: "T1190"}}},
			{TS: t3, RecordID: "4", IoaTags: []models.IoaTag{{Tactic: "lateral-movement", Severity: "high", Technique: "T1021"}}},
		},
		SequenceEdges: []TPGSequenceEdge{{From: 0, To: 1}, {From: 1, To: 2}, {From: 2, To: 3}},
	}

	score := ScoreTPG(tpg)
	if score.SequenceLength != 3 {
		t.Fatalf("expected sequence length 3, got %d", score.SequenceLength)
	}
	if score.TacticCoverage != 3 {
		t.Fatalf("expected tactic coverage 3, got %d", score.TacticCoverage)
	}
	if score.RiskProduct <= 0 || score.RiskSum <= 0 {
		t.Fatalf("expected positive risk values, got product=%f sum=%f", score.RiskProduct, score.RiskSum)
	}
	if len(score.BestVertexIndexes) != 3 {
		t.Fatalf("expected best path length 3, got %d", len(score.BestVertexIndexes))
	}
}

func TestBuildScoredTPGsSortsByLengthThenRisk(t *testing.T) {
	t0 := time.Date(2026, 2, 3, 10, 0, 0, 0, time.UTC)
	iips := []IIPGraph{
		{
			Host: "h2",
			Root: "proc:z",
			AlertEvents: []AlertEvent{
				{Host: "h2", From: "proc:z", TS: t0, RecordID: "1", IoaTags: []models.IoaTag{{Tactic: "execution", Severity: "low", Technique: "T1059"}}},
			},
		},
		{
			Host: "h1",
			Root: "proc:a",
			AlertEvents: []AlertEvent{
				{Host: "h1", From: "proc:a", TS: t0, RecordID: "1", IoaTags: []models.IoaTag{{Tactic: "execution", Severity: "high", Technique: "T1059"}}},
				{Host: "h1", From: "proc:a", TS: t0.Add(1 * time.Minute), RecordID: "2", IoaTags: []models.IoaTag{{Tactic: "discovery", Severity: "high", Technique: "T1082"}}},
			},
		},
	}

	scored := BuildScoredTPGs(iips)
	if len(scored) != 2 {
		t.Fatalf("expected 2 scored graphs, got %d", len(scored))
	}
	if scored[0].Host != "h1" {
		t.Fatalf("expected h1 first due to longer sequence, got %s", scored[0].Host)
	}
}

func TestBuildIncidentsFiltersBySequenceLength(t *testing.T) {
	t0 := time.Date(2026, 2, 4, 10, 0, 0, 0, time.UTC)
	scored := []ScoredTPG{
		{
			Host: "h1",
			Root: "proc:a",
			Score: TacticalScore{
				SequenceLength: 3,
				RiskProduct:    64,
				RiskSum:        12,
				TacticCoverage: 3,
			},
			TPG: TPG{Vertices: []AlertEvent{{TS: t0}, {TS: t0.Add(1 * time.Minute)}}},
		},
		{
			Host: "h2",
			Root: "proc:b",
			Score: TacticalScore{
				SequenceLength: 1,
				RiskProduct:    4,
				RiskSum:        4,
				TacticCoverage: 1,
			},
			TPG: TPG{Vertices: []AlertEvent{{TS: t0}}},
		},
	}

	incidents := BuildIncidents(scored, 2)
	if len(incidents) != 1 {
		t.Fatalf("expected 1 incident, got %d", len(incidents))
	}
	if incidents[0].Host != "h1" {
		t.Fatalf("expected host h1, got %s", incidents[0].Host)
	}
	if incidents[0].Severity != "high" && incidents[0].Severity != "critical" {
		t.Fatalf("expected high/critical severity, got %s", incidents[0].Severity)
	}
}
