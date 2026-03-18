package sysmon

import "testing"

func TestParseOfflineEDRFallbacks(t *testing.T) {
	ResetStats()
	payload := []byte(`{
  "@timestamp": "2026-03-04T12:34:56.789Z",
  "client_id": "AA0000119100000427",
  "ext_detection_id": "det-1",
  "risk_level": "high",
  "operation": "SetValueKey",
  "processuuid": "{GUID}"
}`)

	e, err := Parse(payload)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if e.AgentID != "AA0000119100000427" {
		t.Fatalf("expected AgentID from client_id, got %q", e.AgentID)
	}
	if e.RecordID != "det-1" {
		t.Fatalf("expected RecordID fallback ext_detection_id, got %q", e.RecordID)
	}
	if e.Timestamp.IsZero() {
		t.Fatalf("expected @timestamp fallback to populate Timestamp")
	}
	if got := MissingWinlogEventDataCount(); got != 1 {
		t.Fatalf("expected missing winlog.event_data count 1, got %d", got)
	}
}
