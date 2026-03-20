package main

import (
	"encoding/json"
	"testing"

	"threatgraph/config"
)

func TestSplitCSVDedupTrimAndSkipEmpty(t *testing.T) {
	got := splitCSV(" host-a,host-b,host-a , ,host-c")
	want := []string{"host-a", "host-b", "host-c"}
	if len(got) != len(want) {
		t.Fatalf("splitCSV len=%d want=%d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("splitCSV[%d]=%q want=%q", i, got[i], want[i])
		}
	}
	if out := splitCSV("   "); len(out) != 0 {
		t.Fatalf("splitCSV on empty input got=%v want=nil", out)
	}
}

func TestRunAnalyzerUnknownSource(t *testing.T) {
	code := runAnalyzer([]string{
		"--source", "postgres",
		"--tactical-output", "output/test.scored.jsonl",
	})
	if code != 2 {
		t.Fatalf("runAnalyzer exit code=%d want=2", code)
	}
}

func TestEnsureDefaultElasticsearchQueryBuildsFromRange(t *testing.T) {
	cfg := &config.Config{
		ThreatGraph: config.ThreatGraphConfig{
			Input: config.InputConfig{
				Mode: "elasticsearch",
				Elasticsearch: config.ElasticsearchConfig{
					Since: "2026-03-04T00:00:00Z",
					Until: "2026-03-05T00:00:00Z",
				},
			},
		},
	}
	if err := ensureDefaultElasticsearchQuery(cfg); err != nil {
		t.Fatalf("ensureDefaultElasticsearchQuery returned err: %v", err)
	}
	if cfg.ThreatGraph.Input.Elasticsearch.Query == "" {
		t.Fatalf("query was not generated")
	}
	var q map[string]any
	if err := json.Unmarshal([]byte(cfg.ThreatGraph.Input.Elasticsearch.Query), &q); err != nil {
		t.Fatalf("generated query is not valid json: %v", err)
	}
}

func TestEnsureDefaultElasticsearchQueryKeepsCustomQuery(t *testing.T) {
	cfg := &config.Config{
		ThreatGraph: config.ThreatGraphConfig{
			Input: config.InputConfig{
				Mode: "elasticsearch",
				Elasticsearch: config.ElasticsearchConfig{
					Query: `{"query":{"match_all":{}}}`,
					Since: "2026-03-04T00:00:00Z",
					Until: "2026-03-05T00:00:00Z",
				},
			},
		},
	}
	if err := ensureDefaultElasticsearchQuery(cfg); err != nil {
		t.Fatalf("ensureDefaultElasticsearchQuery returned err: %v", err)
	}
	if got := cfg.ThreatGraph.Input.Elasticsearch.Query; got != `{"query":{"match_all":{}}}` {
		t.Fatalf("custom query changed: %s", got)
	}
}
