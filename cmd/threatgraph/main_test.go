package main

import (
	"testing"
	"time"

	"threatgraph/internal/analyzer"
)

func TestSelectIncidentLatestWithFilter(t *testing.T) {
	base := time.Date(2026, 3, 4, 14, 0, 0, 0, time.UTC)
	incidents := []analyzer.Incident{
		{Host: "h1", Root: "r1", IIPTS: base},
		{Host: "h1", Root: "r2", IIPTS: base.Add(1 * time.Minute)},
		{Host: "h2", Root: "r3", IIPTS: base.Add(2 * time.Minute)},
	}

	got, err := selectIncident(incidents, -1, "h1", "", time.Time{})
	if err != nil {
		t.Fatalf("selectIncident returned err: %v", err)
	}
	if got.Root != "r2" {
		t.Fatalf("expected latest filtered root=r2, got=%s", got.Root)
	}
}

func TestPickIncidentIIPPrefersHostRootClosestTime(t *testing.T) {
	base := time.Date(2026, 3, 4, 14, 0, 0, 0, time.UTC)
	incident := analyzer.Incident{Host: "h1", Root: "root-a", IIPTS: base.Add(10 * time.Second)}
	iips := []analyzer.IIPGraph{
		{Host: "h1", Root: "root-a", IIPTS: base.Add(30 * time.Second)},
		{Host: "h1", Root: "root-a", IIPTS: base.Add(11 * time.Second)},
		{Host: "h1", Root: "root-b", IIPTS: base.Add(9 * time.Second)},
	}

	got, err := pickIncidentIIP(iips, incident)
	if err != nil {
		t.Fatalf("pickIncidentIIP returned err: %v", err)
	}
	if !got.IIPTS.Equal(base.Add(11 * time.Second)) {
		t.Fatalf("expected closest matching iip ts, got=%s", got.IIPTS)
	}
}
