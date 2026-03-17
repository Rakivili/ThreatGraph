package clickhouse

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestParseTimestampLocalNaiveString(t *testing.T) {
	v := "2026-03-05 01:15:01.159"
	got, err := parseTimestamp(v)
	if err != nil {
		t.Fatalf("parseTimestamp returned error: %v", err)
	}

	wantLocal, err := time.ParseInLocation("2006-01-02 15:04:05.000", v, time.Local)
	if err != nil {
		t.Fatalf("failed to parse expected local time: %v", err)
	}
	if !got.Equal(wantLocal) {
		t.Fatalf("unexpected parsed timestamp: got=%s want=%s", got.Format(time.RFC3339Nano), wantLocal.Format(time.RFC3339Nano))
	}
}

func TestParseTimestampRFC3339Z(t *testing.T) {
	v := "2026-03-04T17:15:01.159Z"
	got, err := parseTimestamp(v)
	if err != nil {
		t.Fatalf("parseTimestamp returned error: %v", err)
	}
	want := time.Date(2026, 3, 4, 17, 15, 1, 159000000, time.UTC).In(time.Local)
	if !got.Equal(want) {
		t.Fatalf("unexpected parsed timestamp: got=%s want=%s", got.Format(time.RFC3339Nano), want.Format(time.RFC3339Nano))
	}
}

func TestReadAlertHostsFromAdjacency(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"host":"host-a"}`+"\n"+`{"host":"host-b"}`+"\n")
	}))
	defer ts.Close()

	r, err := NewReader(Config{URL: ts.URL, Database: "threatgraph", AdjacencyTable: "adjacency", Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewReader failed: %v", err)
	}

	hosts, err := r.ReadAlertHostsFromAdjacency(time.Date(2026, 3, 4, 0, 0, 0, 0, time.UTC), time.Date(2026, 3, 5, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("ReadAlertHostsFromAdjacency failed: %v", err)
	}
	if len(hosts) != 2 || hosts[0] != "host-a" || hosts[1] != "host-b" {
		t.Fatalf("unexpected hosts: %#v", hosts)
	}
}
