package elasticsearch

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestConsumerPopSearchAndScroll(t *testing.T) {
	searchCalls := 0
	scrollCalls := 0

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/_search"):
			searchCalls++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"_scroll_id": "scroll-1",
				"hits": map[string]interface{}{
					"hits": []map[string]interface{}{
						{"_source": map[string]interface{}{"@timestamp": "2026-03-04T00:00:00Z", "risk_level": "notice", "operation": "CreateProcess"}},
						{"_source": map[string]interface{}{"@timestamp": "2026-03-04T00:00:01Z", "risk_level": "high", "operation": "SetValueKey"}},
					},
				},
			})
		case r.URL.Path == "/_search/scroll":
			scrollCalls++
			if scrollCalls == 1 {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"_scroll_id": "scroll-2",
					"hits": map[string]interface{}{
						"hits": []map[string]interface{}{
							{"_source": map[string]interface{}{"@timestamp": "2026-03-04T00:00:02Z", "risk_level": "high", "operation": "OpenProcess"}},
						},
					},
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"_scroll_id": "scroll-2",
				"hits":       map[string]interface{}{"hits": []map[string]interface{}{}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	c, err := NewConsumer(Config{
		URL:       ts.URL,
		Index:     "edr-offline-*",
		BatchSize: 2,
		Scroll:    time.Minute,
		Timeout:   5 * time.Second,
		Insecure:  true,
	})
	if err != nil {
		t.Fatalf("NewConsumer failed: %v", err)
	}
	defer c.Close()

	for i := 0; i < 3; i++ {
		payload, err := c.Pop(context.Background())
		if err != nil {
			t.Fatalf("Pop %d failed: %v", i, err)
		}
		if len(payload) == 0 {
			t.Fatalf("Pop %d returned empty payload", i)
		}
	}

	payload, err := c.Pop(context.Background())
	if err != io.EOF {
		t.Fatalf("expected io.EOF after exhausting hits, got %v", err)
	}
	if payload != nil {
		t.Fatalf("expected nil after exhausting hits")
	}
	if searchCalls != 1 {
		t.Fatalf("expected 1 initial search, got %d", searchCalls)
	}
	if scrollCalls == 0 {
		t.Fatalf("expected scroll to be used")
	}
}

func TestNewConsumerInjectsSliceIntoQuery(t *testing.T) {
	c, err := NewConsumer(Config{
		URL:      "https://example.local:9200",
		Index:    "edr-offline-*",
		Query:    `{"query":{"match_all":{}}}`,
		SliceID:  2,
		SliceMax: 4,
		Insecure: true,
	})
	if err != nil {
		t.Fatalf("NewConsumer failed: %v", err)
	}
	defer c.Close()
	slice, ok := c.query["slice"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected slice query to be injected")
	}
	if slice["id"] != 2 || slice["max"] != 4 {
		t.Fatalf("unexpected slice payload: %#v", slice)
	}
}
